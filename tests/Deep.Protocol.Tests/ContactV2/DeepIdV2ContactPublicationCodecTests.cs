using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2ContactPublicationCodecTests
{
    [Fact]
    public void ExactMinimumV2PairBindsOneBodyWithoutGrantingAuthority()
    {
        var pair = Pair(DeepIdV2ContactPublicationCodec.MinimumCiphertextLength,
            4_143, 2);
        var parsed = DeepIdV2ContactPublicationCodec.DecodeXpu1(pair.Xpu);

        Assert.False(DeepIdV2ContactPublicationCodec.RuntimeActivation);
        Assert.Equal(DeepIdV2ContactPublicationCodec.MinimumXpuLength,
            pair.Xpu.Length);
        Assert.Equal(DeepIdV2ContactPublicationCodec.MinimumXpaLength,
            pair.Xpa.Length);
        Assert.Equal(pair.Xpu, parsed.CanonicalBytes.ToArray());
        Assert.Equal(pair.Xpa, parsed.Authorization.CanonicalBytes.ToArray());
        Assert.Equal(pair.BodyHash,
            DeepIdV2ContactPublicationCodec.ComputeAuthorizedBodyHash(pair.Xpu));
        Assert.Equal(ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V2/request", pair.Xpu),
            parsed.RequestHash.ToArray());
        Assert.Equal(Bytes(32, 0x31), parsed.Field(16).ToArray());
        Assert.Throws<ArgumentOutOfRangeException>(() => parsed.Field(15));
    }

    [Fact]
    public void ExactMaximumV2PairIsBounded()
    {
        var pair = Pair(DeepIdV2ContactPublicationCodec.MaximumCiphertextLength,
            23_295, 32);
        var parsed = DeepIdV2ContactPublicationCodec.DecodeXpu1(pair.Xpu);
        Assert.Equal(DeepIdV2ContactPublicationCodec.MaximumXpuLength,
            parsed.CanonicalBytes.Length);
        Assert.Equal(DeepIdV2ContactPublicationCodec.MaximumXpaLength,
            parsed.Authorization.CanonicalBytes.Length);
    }

    [Fact]
    public void RetiredHeaderHashAndInnerAuthorizationCannotCrossFeed()
    {
        var pair = Pair(DeepIdV2ContactPublicationCodec.MinimumCiphertextLength,
            4_143, 2);
        var oldVersion = pair.Xpu.ToArray();
        oldVersion[5] = 1;
        RejectXpu(oldVersion);
        var oldSuite = pair.Xpu.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(oldSuite.AsSpan(6), 0x0201);
        RejectXpu(oldSuite);
        var oldXpa = pair.Xpa.ToArray();
        oldXpa[5] = 1;
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2ContactPublicationCodec.DecodeXpa1(oldXpa));
        var trailing = pair.Xpu.Concat(new byte[] { 0 }).ToArray();
        RejectXpu(trailing);
        var truncated = pair.Xpu[..^1];
        RejectXpu(truncated);
        var changedCipher = pair.Fields.Select(static value => value.ToArray()).ToArray();
        changedCipher[11][^1] ^= 1;
        RejectXpu(Build("XPU1", DeepIdV2ContactPublicationCodec.XpuTags,
            changedCipher));
        var changedRoute = pair.Fields.Select(static value => value.ToArray()).ToArray();
        changedRoute[15][^1] ^= 1;
        RejectXpu(Build("XPU1", DeepIdV2ContactPublicationCodec.XpuTags,
            changedRoute));
        var changedOperation = pair.Fields.Select(static value => value.ToArray()).ToArray();
        changedOperation[1][^1] ^= 1;
        RejectXpu(Build("XPU1", DeepIdV2ContactPublicationCodec.XpuTags,
            changedOperation));
        var shortCipher = pair.Fields.Select(static value => value.ToArray()).ToArray();
        shortCipher[11] = shortCipher[11][1..];
        RejectXpu(Build("XPU1", DeepIdV2ContactPublicationCodec.XpuTags,
            shortCipher));
        var wrongTag = pair.Xpu.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(wrongTag.AsSpan(12), 2);
        RejectXpu(wrongTag);
    }

    [Fact]
    public void XpaWitnessRowsAndAuthorizationIdRejectTampering()
    {
        var pair = Pair(DeepIdV2ContactPublicationCodec.MinimumCiphertextLength,
            4_143, 2);
        var wrongId = pair.XpaFields.Select(static value => value.ToArray()).ToArray();
        wrongId[1][0] ^= 1;
        RejectXpa(wrongId);
        var duplicate = pair.XpaFields.Select(static value => value.ToArray()).ToArray();
        duplicate[20].AsSpan(0, 32).CopyTo(duplicate[20].AsSpan(96, 32));
        RejectXpa(duplicate);
        var zeroSignature = pair.XpaFields.Select(static value => value.ToArray()).ToArray();
        zeroSignature[20].AsSpan(32, 64).Clear();
        RejectXpa(zeroSignature);
        var bodyMismatch = pair.XpaFields.Select(static value => value.ToArray()).ToArray();
        bodyMismatch[18][0] ^= 1;
        RejectXpa(bodyMismatch);
        var wrongKind = pair.XpaFields.Select(static value => value.ToArray()).ToArray();
        wrongKind[4][0] = 2;
        RejectXpa(wrongKind);
    }

    private static void RejectXpu(byte[] value) =>
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2ContactPublicationCodec.DecodeXpu1(value));

    private static void RejectXpa(byte[][] fields)
    {
        var pair = Pair(DeepIdV2ContactPublicationCodec.MinimumCiphertextLength,
            4_143, 2);
        var xpuFields = pair.Fields.Select(static value => value.ToArray()).ToArray();
        xpuFields[16] = Build("XPA1", DeepIdV2ContactPublicationCodec.XpaTags,
            fields);
        RejectXpu(Build("XPU1", DeepIdV2ContactPublicationCodec.XpuTags,
            xpuFields));
    }

    private static (byte[] Xpu, byte[] Xpa, byte[] BodyHash,
        byte[][] Fields, byte[][] XpaFields) Pair(
        int ciphertextLength, int routeLength, int witnesses)
    {
        var network = Bytes(16, 0x11);
        var operation = Bytes(32, 0x21);
        var ciphertext = Bytes(ciphertextLength, 0x41);
        var route = Bytes(routeLength, 0x51);
        var witnessRows = new byte[witnesses * 96];
        for (var index = 0; index < witnesses; index++)
        {
            witnessRows[index * 96] = checked((byte)(index + 1));
            witnessRows[index * 96 + 32] = 0x71;
        }
        var xpu = new byte[][]
        {
            network, operation, Bytes(32, 0x22), Bytes(32, 0x23),
            U64(10), U64(100), Bytes(32, 0x31), Bytes(32, 0x32),
            U64(0), new byte[32], SHA256.HashData(ciphertext), ciphertext,
            U32(0), U64(200), SHA256.HashData(route), route,
            new byte[594 + witnessRows.Length], Bytes(32, 0x33),
        };
        var skeleton = Build("XPU1", DeepIdV2ContactPublicationCodec.XpuTags,
            xpu);
        var bodyHash = DeepIdV2ContactPublicationCodec
            .ComputeAuthorizedBodyHash(skeleton);
        var head = Bytes(32, 0x61);
        var authorizationInput = operation.Concat(bodyHash).Concat(head).ToArray();
        var authorizationId = ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V2/publication-authorization-id",
            authorizationInput);
        var xpa = new byte[][]
        {
            network, authorizationId, operation, xpu[6], new byte[] { 1 },
            Bytes(32, 0x34), Bytes(32, 0x35), xpu[7], U64(0), new byte[32],
            xpu[10], U32(0), U64(200), Bytes(32, 0x36), U64(10), U64(10),
            U64(100), head, bodyHash, new byte[] { (byte)witnesses }, witnessRows,
        };
        var exactXpa = Build("XPA1", DeepIdV2ContactPublicationCodec.XpaTags,
            xpa);
        xpu[16] = exactXpa;
        return (Build("XPU1", DeepIdV2ContactPublicationCodec.XpuTags,
            xpu), exactXpa, bodyHash, xpu, xpa);
    }

    private static byte[] Build(string magic, ReadOnlySpan<ushort> tags,
        byte[][] fields)
    {
        var size = 12 + fields.Sum(static value => 8 + value.Length);
        var bytes = new byte[size];
        var writer = new ApplicationRecordWriter(bytes,
            Encoding.ASCII.GetBytes(magic), checked((ushort)fields.Length),
            2, DeepIdV2Codec.Suite);
        for (var index = 0; index < fields.Length; index++)
            writer.Write(tags[index], fields[index]);
        writer.Complete();
        return bytes;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static byte[] U32(uint value)
    {
        var result = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(result, value);
        return result;
    }

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();
}
