using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2Xpa1WitnessThresholdVerifierTests
{
    [Fact]
    public void ExactV2WitnessThresholdMintsOnlySignatureEvidence()
    {
        var signers = Signers();
        var authority = Authority(signers, 2);
        var request = SignedRequest(signers.Take(2).ToArray());

        var verified = DeepIdV2Xpa1WitnessThresholdVerifier.Verify(
            request.Authorization, authority);

        Assert.False(DeepIdV2Xpa1WitnessThresholdVerifier.RuntimeActivation);
        Assert.Equal(request.Authorization.CanonicalBytes.ToArray(),
            verified.ExactXpa1.ToArray());
        Assert.Equal(authority.AuthorityCoreReference.ToArray(),
            verified.AuthorityCoreReference.ToArray());
        Assert.Equal(authority.DirectoryWitnessPolicyHash.ToArray(),
            verified.WitnessPolicyHash.ToArray());
        Assert.Empty(typeof(VerifiedXpa1V2WitnessThreshold).GetConstructors());
    }

    [Fact]
    public void ChangedSignatureOldDomainUnknownWitnessAndThresholdReject()
    {
        var signers = Signers();
        var authority = Authority(signers, 2);
        var request = SignedRequest(signers.Take(2).ToArray());
        var fields = DeepIdV2ContactPublicationCodecTests
            .Pair(DeepIdV2ContactPublicationCodec.MinimumCiphertextLength,
                4_143, 2).XpaFields;
        fields[20] = request.Authorization.Field(21).ToArray();
        fields[20][^1] ^= 1;
        var changed = DeepIdV2ContactPublicationCodec.DecodeXpa1(
            DeepIdV2ContactPublicationCodecTests.Build("XPA1",
                DeepIdV2ContactPublicationCodec.XpaTags, fields));
        Assert.Throws<CryptographicException>(() =>
            DeepIdV2Xpa1WitnessThresholdVerifier.Verify(changed, authority));

        var oldInputRequest = SignedRequest(signers.Take(2).ToArray(), oldDomain: true);
        Assert.Throws<CryptographicException>(() =>
            DeepIdV2Xpa1WitnessThresholdVerifier.Verify(
                oldInputRequest.Authorization, authority));

        var unknown = Signers()[2] with { Id = Bytes(32, 0x7e) };
        var unknownRequest = SignedRequest([signers[0], unknown]);
        Assert.Throws<CryptographicException>(() =>
            DeepIdV2Xpa1WitnessThresholdVerifier.Verify(
                unknownRequest.Authorization, authority));

        var higherThreshold = Authority(signers, 3);
        Assert.Throws<CryptographicException>(() =>
            DeepIdV2Xpa1WitnessThresholdVerifier.Verify(
                request.Authorization, higherThreshold));
        var otherNetwork = Authority(signers, 2, Bytes(16, 0x19));
        Assert.Throws<CryptographicException>(() =>
            DeepIdV2Xpa1WitnessThresholdVerifier.Verify(
                request.Authorization, otherNetwork));
        Assert.Throws<XPointValidationException>(() =>
            Authority(signers.Select(signer => signer with
                { FailureDomain = Bytes(32, 0x61) }).ToArray(), 2));
    }

    private static ParsedXpu1V2 SignedRequest(
        IReadOnlyList<Signer> signers, bool oldDomain = false)
    {
        var pair = DeepIdV2ContactPublicationCodecTests.Pair(
            DeepIdV2ContactPublicationCodec.MinimumCiphertextLength,
            4_143, signers.Count);
        var xpa = DeepIdV2ContactPublicationCodec.DecodeXpa1(pair.Xpa);
        Assert.Equal(ApplicationCoreFormat.SignatureInput(
            "Deep/ContactResolver/V2/publication-authorization",
            UnsignedXpa(pair.XpaFields), DeepIdV2Codec.Suite),
            xpa.WitnessSigningInput.ToArray());
        var input = oldDomain
            ? ApplicationCoreFormat.SignatureInput(
                "Deep/ContactResolver/V1/publication-authorization",
                UnsignedXpa(pair.XpaFields), 0x0201)
            : xpa.WitnessSigningInput.ToArray();
        var fields = pair.XpaFields.Select(static value => value.ToArray()).ToArray();
        var rows = new byte[96 * signers.Count];
        foreach (var item in signers.OrderBy(static signer => signer.Id[0])
            .Select((signer, index) => (signer, index)))
        {
            var offset = item.index * 96;
            item.signer.Id.CopyTo(rows, offset);
            PublicKeyAuth.SignDetached(input, item.signer.Key.PrivateKey)
                .CopyTo(rows, offset + 32);
        }
        fields[20] = rows;
        var exactXpa = DeepIdV2ContactPublicationCodecTests.Build(
            "XPA1", DeepIdV2ContactPublicationCodec.XpaTags, fields);
        var xpu = pair.Fields.Select(static value => value.ToArray()).ToArray();
        xpu[16] = exactXpa;
        return DeepIdV2ContactPublicationCodec.DecodeXpu1(
            DeepIdV2ContactPublicationCodecTests.Build(
                "XPU1", DeepIdV2ContactPublicationCodec.XpuTags, xpu));
    }

    private static byte[] UnsignedXpa(byte[][] fields)
    {
        var unsigned = fields.Take(20).ToArray();
        return DeepIdV2ContactPublicationCodecTests.Build(
            "XPA1", DeepIdV2ContactPublicationCodec.XpaTags[..20], unsigned);
    }

    private static Signer[] Signers() => Enumerable.Range(1, 3).Select(index =>
        new Signer(Bytes(32, (byte)index),
            PublicKeyAuth.GenerateKeyPair(Bytes(32, (byte)(0x50 + index))),
            Bytes(32, (byte)(0x60 + index)))).ToArray();

    private static VerifiedXPointNetworkAuthority Authority(
        IReadOnlyList<Signer> signers, byte threshold, byte[]? network = null)
    {
        network ??= Bytes(16, 0x11);
        var root = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x20));
        var rootId = Bytes(32, 0x21);
        var sources = new[]
        {
            new AccountDirectoryDts1Source(
                Bytes(32, 0x22), Bytes(32, 0x23), 1,
                "time-a.example", 443, Bytes(32, 0x24), 1),
            new AccountDirectoryDts1Source(
                Bytes(32, 0x25), Bytes(32, 0x26), 1,
                "time-b.example", 443, Bytes(32, 0x27), 1),
        };
        var dts = new AccountDirectoryDts1(network, 0, new byte[32],
            sources, 2, 2, 30, 1, 1, 1_000, 1, 0,
            [new AccountDirectoryDts1RootReceipt(rootId, Bytes(64, 0x28))]);
        var dtsHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(dts);
        ReadOnlyMemory<byte>[] fields = new ReadOnlyMemory<byte>[20];
        fields[0] = network;
        fields[1] = U64(0);
        fields[2] = new byte[32];
        fields[3] = new byte[] { 1 };
        fields[4] = Join(rootId, U64(0), root.PublicKey);
        fields[5] = new byte[] { 1 };
        fields[6] = U64(0);
        fields[7] = U16(1);
        fields[8] = new byte[] { checked((byte)signers.Count) };
        fields[9] = Join(signers.OrderBy(static signer => signer.Id[0])
            .Select(static signer => Join(signer.Id, U64(0),
                signer.Key.PublicKey, signer.FailureDomain)).ToArray());
        fields[10] = new byte[] { threshold };
        fields[11] = Reference("DTS1", dtsHash);
        fields[12] = dtsHash;
        fields[13] = U32(30);
        fields[14] = U64(1);
        fields[15] = U64(1);
        fields[16] = U64(1);
        fields[17] = U64(1_000);
        fields[18] = new byte[] { 1 };
        fields[19] = Join(rootId, Bytes(64, 0x29));
        var unsigned = XPointNetworkCodec.Parse<Xna1Record>(
            XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
        fields[19] = Join(rootId, PublicKeyAuth.SignDetached(
            XPointNetworkCrypto.ComputeSigningInput(unsigned),
            root.PrivateKey));
        var xna = XPointNetworkCodec.Parse<Xna1Record>(
            XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
        return new VerifiedXPointNetworkAuthority(xna, dts, [xna]);
    }

    private sealed record Signer(byte[] Id, KeyPair Key, byte[] FailureDomain);

    private static byte[] Reference(string magic, byte[] hash)
    {
        var result = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result, 6);
        return result;
    }

    private static byte[] Join(params byte[][] values) =>
        values.SelectMany(static value => value).ToArray();

    private static byte[] U16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    private static byte[] U32(uint value)
    {
        var result = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static byte[] Bytes(int length, byte marker)
        => Enumerable.Repeat(marker, length).ToArray();
}
