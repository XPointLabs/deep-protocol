using System.Buffers.Binary;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class DeepIdV2AccountDirectoryLookupCodecTests
{
    [Fact]
    public void AuthorDecodeVerify_BindsExactDid2AndNetworkWithoutLegacyAcceptance()
    {
        var did = Did(0x10);
        var network = Bytes(16, 0x20);
        var capability = DeepIdV2AccountDirectoryLookupCodec.Author(did, network,
            17, Bytes(32, 0x30), 1, new byte[38], new byte[32]);
        var encoded = capability.CanonicalBytes.ToArray();
        var decoded = DeepIdV2AccountDirectoryLookupCodec.Decode(encoded);

        Assert.Equal(228, encoded.Length);
        Assert.Equal((ushort)2, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(4)));
        Assert.Equal(DeepIdV2Codec.Suite,
            BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(6)));
        Assert.Equal(DeepIdV2AccountDirectoryCodec.ComputeDirectoryLookupKey(network, did),
            decoded.DirectoryLookupKey.ToArray());
        Assert.Equal(DeepIdV2AccountDirectoryCodec.ComputeDirectoryLeafKey(network, did),
            DeepIdV2AccountDirectoryLookupCodec.MatchExactDid2(decoded, did));
        Assert.Throws<AccountDirectoryAdl1FormatException>(() =>
            AccountDirectoryAdl1Codec.Decode(encoded));

        var changed = decoded.DirectoryLookupKey.ToArray();
        changed[0] ^= 0xff;
        Assert.NotEqual(changed, decoded.DirectoryLookupKey.ToArray());
        Assert.Throws<AccountDirectoryAdl1FormatException>(() =>
            DeepIdV2AccountDirectoryLookupCodec.MatchExactDid2(
                decoded, Did(0x11)));
        var changedNetwork = encoded.ToArray();
        changedNetwork[20] ^= 1;
        Assert.Throws<AccountDirectoryAdl1FormatException>(() =>
            DeepIdV2AccountDirectoryLookupCodec.MatchExactDid2(
                DeepIdV2AccountDirectoryLookupCodec.Decode(changedNetwork), did));
    }

    [Fact]
    public void Decode_RejectsWrongVersionSuiteAndNonCanonicalFields()
    {
        var did = Did(0x10);
        var valid = DeepIdV2AccountDirectoryLookupCodec.Author(did, Bytes(16, 0x20),
            17, Bytes(32, 0x30), 3, XodReference(Bytes(32, 0x40)),
            Bytes(32, 0x40)).CanonicalBytes.ToArray();
        Action<byte[]>[] mutations =
        [
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), 6),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(12), 2),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(16), 15),
            bytes => Array.Clear(bytes, 20, 16),
            bytes => Array.Clear(bytes, 44, 32),
            bytes => Array.Clear(bytes, 100, 32),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(140), 4),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(140), 1),
            bytes => bytes[150] = (byte)'Y',
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(154), 2),
            bytes => bytes[156] ^= 1
        ];
        foreach (var mutate in mutations)
        {
            var candidate = valid.ToArray();
            mutate(candidate);
            Assert.ThrowsAny<FormatException>(() =>
                DeepIdV2AccountDirectoryLookupCodec.Decode(candidate));
        }
        Assert.ThrowsAny<FormatException>(() =>
            DeepIdV2AccountDirectoryLookupCodec.Decode(valid[..^1]));
        Assert.ThrowsAny<FormatException>(() =>
            DeepIdV2AccountDirectoryLookupCodec.Decode([.. valid, 0]));
    }

    private static ParsedDid2 Did(byte seed) => DeepIdV2Codec.AuthorDid2(
        Bytes(32, seed), Bytes(1952, (byte)(seed + 1)),
        Bytes(16, (byte)(seed + 2)));

    private static byte[] XodReference(byte[] hash)
    {
        var reference = new byte[38];
        "XOD1"u8.CopyTo(reference);
        BinaryPrimitives.WriteUInt16BigEndian(reference.AsSpan(4), 1);
        hash.CopyTo(reference, 6);
        return reference;
    }

    private static byte[] Bytes(int length, byte first) =>
        Enumerable.Range(0, length).Select(index =>
            unchecked((byte)(first + index))).ToArray();
}
