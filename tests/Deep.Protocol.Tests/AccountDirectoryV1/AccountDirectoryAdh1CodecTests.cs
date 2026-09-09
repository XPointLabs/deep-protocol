using System.Buffers.Binary;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryAdh1CodecTests
{
    [Fact]
    public void EncodeDecode_RoundTripsWithExactSizeAndDefensiveCopies()
    {
        var network = Bytes(16, 1);
        var value = Fixture(network);
        network[0] = 0xff;
        var encoded = AccountDirectoryAdh1Codec.Encode(value);
        var decoded = AccountDirectoryAdh1Codec.Decode(encoded);

        Assert.Equal(525, encoded.Length);
        Assert.Equal(2, decoded.WitnessCount);
        Assert.Equal(17UL, decoded.LogGeneration);
        Assert.Equal(value.NetworkId.ToArray(), decoded.NetworkId.ToArray());
        var witnessId = decoded.Witnesses[0].WitnessId.ToArray();
        witnessId[0] ^= 0xff;
        Assert.NotEqual(witnessId, decoded.Witnesses[0].WitnessId.ToArray());
    }

    [Fact]
    public void EncodeUnsigned_ContainsOnlyTagsOneThroughEleven()
    {
        var unsigned = AccountDirectoryAdh1Codec.EncodeUnsigned(Fixture(Bytes(16, 1)));

        Assert.Equal(11, BinaryPrimitives.ReadUInt16BigEndian(unsigned.AsSpan(8)));
        Assert.Equal(316, unsigned.Length);
        var offset = 12;
        for (var tag = 1; tag <= 11; tag++)
        {
            Assert.Equal((ushort)tag, BinaryPrimitives.ReadUInt16BigEndian(unsigned.AsSpan(offset)));
            offset += 8 + BinaryPrimitives.ReadInt32BigEndian(unsigned.AsSpan(offset + 4));
        }
        Assert.Equal(unsigned.Length, offset);
    }

    [Fact]
    public void Decode_RejectsEnvelopeTagsLengthsTruncationAndTrailingBytes()
    {
        var encoded = AccountDirectoryAdh1Codec.Encode(Fixture(Bytes(16, 1)));
        var mutations = new Action<byte[]>[]
        {
            bytes => bytes[0] = (byte)'X',
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 2),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0202),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), 12),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10), 1),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(12), 2),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(14), 1),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(16), 15),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(325), 95)
        };
        foreach (var mutate in mutations)
        {
            var candidate = encoded.ToArray();
            mutate(candidate);
            Assert.Throws<AccountDirectoryAdh1FormatException>(() => AccountDirectoryAdh1Codec.Decode(candidate));
        }
        Assert.Throws<AccountDirectoryAdh1FormatException>(() => AccountDirectoryAdh1Codec.Decode(encoded[..11]));
        Assert.Throws<AccountDirectoryAdh1FormatException>(() => AccountDirectoryAdh1Codec.Decode(encoded[..^1]));
        Assert.Throws<AccountDirectoryAdh1FormatException>(() => AccountDirectoryAdh1Codec.Decode(encoded.Concat(new byte[] { 0 }).ToArray()));
    }

    [Fact]
    public void Decode_RejectsPredecessorValidityCountAndWitnessOrderingViolations()
    {
        var encoded = AccountDirectoryAdh1Codec.Encode(Fixture(Bytes(16, 1)));
        var cases = new Action<byte[]>[]
        {
            bytes => { BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(44), 0); bytes[60] = 1; },
            bytes => { BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(44), 1); Array.Clear(bytes, 60, 32); },
            bytes => BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(298), 1_700_086_401),
            bytes => bytes[324] = 3,
            bytes => Array.Copy(bytes, 333, bytes, 429, 32),
            bytes => bytes[333] = 0xff
        };
        foreach (var mutate in cases)
        {
            var candidate = encoded.ToArray();
            mutate(candidate);
            Assert.Throws<AccountDirectoryAdh1FormatException>(() => AccountDirectoryAdh1Codec.Decode(candidate));
        }
    }

    [Fact]
    public void Constructor_RejectsInvalidArguments()
    {
        var witness = new AccountDirectoryAdh1WitnessEntry(Bytes(32, 1), Bytes(64, 2));
        Assert.Throws<ArgumentException>(() => new AccountDirectoryAdh1(
            new byte[15], 0, new byte[32], 0, new byte[32], new byte[32], Reference("XNA1", 5), new byte[32],
            1, 0, 1, new[] { witness }));
        Assert.Throws<ArgumentException>(() => new AccountDirectoryAdh1(
            Bytes(16, 1), 0, Bytes(32, 2), 0, Bytes(32, 3), Bytes(32, 4), Reference("XNA1", 5), Bytes(32, 6),
            10, 10 + 86_401, 1, new[] { witness }));
        Assert.Throws<ArgumentException>(() => new AccountDirectoryAdh1(
            Bytes(16, 1), 1, new byte[32], 0, Bytes(32, 3), Bytes(32, 4), Reference("XNA1", 5), Bytes(32, 6),
            10, 10, 1, new[] { witness }));
        Assert.Throws<ArgumentException>(() => new AccountDirectoryAdh1(
            Bytes(16, 1), 1, Bytes(32, 2), 0, Bytes(32, 3), Bytes(32, 4), Bytes(38, 5), Bytes(32, 6),
            10, 10, 1, new[] { witness }));
    }

    private static AccountDirectoryAdh1 Fixture(byte[] network) => new(
        network, 17, Bytes(32, 2), 21, Bytes(32, 3), Bytes(32, 4), Reference("XNA1", 5), Bytes(32, 6),
        1_700_000_000, 1_700_000_100, 0x0201,
        new[]
        {
            new AccountDirectoryAdh1WitnessEntry(Bytes(32, 0x10), Bytes(64, 0x20)),
            new AccountDirectoryAdh1WitnessEntry(Bytes(32, 0x11), Bytes(64, 0x30))
        });

    private static byte[] Reference(string magic, byte first)
    {
        var value = Bytes(38, first);
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        return value;
    }

    private static byte[] Bytes(int length, byte first)
    {
        var value = new byte[length];
        for (var index = 0; index < value.Length; index++)
            value[index] = unchecked((byte)(first + index));
        return value;
    }
}
