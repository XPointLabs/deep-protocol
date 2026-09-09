using System.Buffers.Binary;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryDtt1CodecTests
{
    [Fact]
    public void RoundTrip_AndUnsignedProjection_AreExact()
    {
        var value = Fixture();
        var encoded = AccountDirectoryDtt1Codec.Encode(value);
        var decoded = AccountDirectoryDtt1Codec.Decode(encoded);
        var unsigned = AccountDirectoryDtt1Codec.EncodeUnsigned(value);
        Assert.Equal(583, encoded.Length);
        Assert.Equal(374, unsigned.Length);
        Assert.Equal((ushort)13, BinaryPrimitives.ReadUInt16BigEndian(unsigned.AsSpan(8)));
        Assert.Equal(2, decoded.Witnesses.Count);
        Assert.Equal(value.ClientNonce.ToArray(), decoded.ClientNonce.ToArray());
        var copy = decoded.Witnesses[0].Signature.ToArray();
        copy[0] ^= 1;
        Assert.NotEqual(copy, decoded.Witnesses[0].Signature.ToArray());
    }

    [Fact]
    public void Decode_RejectsEnvelopeLengthTruncationAndTrailingData()
    {
        var encoded = AccountDirectoryDtt1Codec.Encode(Fixture());
        Action<byte[]>[] mutations =
        [
            bytes => bytes[0] = (byte)'X',
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 2),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0001),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), 14),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10), 1),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(12), 2),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(14), 1),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(16), 15),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(387), 95)
        ];
        foreach (var mutation in mutations)
        {
            var candidate = encoded.ToArray();
            mutation(candidate);
            Assert.Throws<AccountDirectoryDtt1FormatException>(() => AccountDirectoryDtt1Codec.Decode(candidate));
        }
        Assert.Throws<AccountDirectoryDtt1FormatException>(() => AccountDirectoryDtt1Codec.Decode(encoded[..^1]));
        Assert.Throws<AccountDirectoryDtt1FormatException>(() => AccountDirectoryDtt1Codec.Decode(encoded.Concat(new byte[] { 0 }).ToArray()));
    }

    [Fact]
    public void Decode_RejectsTimeNonceReferenceCountAndReceiptViolations()
    {
        var encoded = AccountDirectoryDtt1Codec.Encode(Fixture());
        Action<byte[]>[] mutations =
        [
            bytes => Array.Clear(bytes, 44, 32),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(100), 31),
            bytes => BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(310), 1_699_999_960),
            bytes => BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(326), 1_700_000_071),
            bytes => bytes[224] = (byte)'Y',
            bytes => Array.Clear(bytes, 342, 32),
            bytes => bytes[382] = 3,
            bytes => Array.Copy(bytes, 391, bytes, 487, 32),
            bytes => bytes[391] = 0xff,
            bytes => Array.Clear(bytes, 423, 64)
        ];
        foreach (var mutation in mutations)
        {
            var candidate = encoded.ToArray();
            mutation(candidate);
            Assert.Throws<AccountDirectoryDtt1FormatException>(() => AccountDirectoryDtt1Codec.Decode(candidate));
        }
    }

    private static AccountDirectoryDtt1 Fixture() => new(
        Bytes(16, 1), Bytes(32, 2), 1_700_000_000, 30, Bytes(32, 3), 4, Bytes(32, 4), 5,
        Reference("XNA1", 5), Bytes(32, 6), 1_700_000_010, 1_700_000_060,
        Bytes(32, 7),
        [
            new AccountDirectoryDtt1WitnessReceipt(Bytes(32, 0x10), Bytes(64, 0x20)),
            new AccountDirectoryDtt1WitnessReceipt(Bytes(32, 0x11), Bytes(64, 0x30))
        ]);

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
        for (var index = 0; index < length; index++)
            value[index] = unchecked((byte)(first + index));
        return value;
    }
}
