using System.Buffers.Binary;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryAdl1CodecTests
{
    [Fact]
    public void EncodeDecode_RoundTripsAndUsesDefensiveCopies()
    {
        var network = Bytes(16, 0x10);
        var value = new AccountDirectoryAdl1(network, Bytes(32, 0x20), 17, Bytes(32, 0x30),
            3, XodReference(Bytes(32, 0x40)), Bytes(32, 0x40));
        network[0] = 0xff;

        var encoded = AccountDirectoryAdl1Codec.Encode(value);
        var decoded = AccountDirectoryAdl1Codec.Decode(encoded);
        var copy = decoded.NetworkId.ToArray();
        copy[0] ^= 0xff;

        Assert.Equal(228, encoded.Length);
        Assert.Equal((ushort)7, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(8)));
        Assert.Equal(17UL, decoded.MinimumAdhGeneration);
        Assert.Equal((ushort)3, decoded.ServiceProfile);
        Assert.NotEqual(copy, decoded.NetworkId.ToArray());
        Assert.Equal(value.ExactOhttpXod1CoreHash.ToArray(), decoded.ExactOhttpXod1CoreHash.ToArray());
    }

    [Fact]
    public void ProfileOne_EncodesZeroOhttpFields()
    {
        var value = new AccountDirectoryAdl1(Bytes(16, 1), Bytes(32, 2), 0, Bytes(32, 3), 1, new byte[38], new byte[32]);
        var decoded = AccountDirectoryAdl1Codec.Decode(AccountDirectoryAdl1Codec.Encode(value));

        Assert.All(decoded.ExactOhttpXod1CoreReference.ToArray(), item => Assert.Equal(0, item));
        Assert.All(decoded.ExactOhttpXod1CoreHash.ToArray(), item => Assert.Equal(0, item));
    }

    [Fact]
    public void Decode_RejectsEnvelopeFieldAndProfileViolations()
    {
        var encoded = AccountDirectoryAdl1Codec.Encode(new AccountDirectoryAdl1(
            Bytes(16, 1), Bytes(32, 2), 4, Bytes(32, 3), 3, XodReference(Bytes(32, 4)), Bytes(32, 4)));
        var mutations = new Action<byte[]>[]
        {
            bytes => bytes[0] = (byte)'X',
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 2),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0202),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), 6),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10), 1),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(12), 2),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(14), 1),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(16), 15),
            bytes => bytes[encoded.Length - 1] ^= 1,
            bytes => bytes[encoded.Length - 1] = 0
        };
        foreach (var mutate in mutations)
        {
            var candidate = encoded.ToArray();
            mutate(candidate);
            Assert.Throws<AccountDirectoryAdl1FormatException>(() => AccountDirectoryAdl1Codec.Decode(candidate));
        }

        Assert.Throws<AccountDirectoryAdl1FormatException>(() => AccountDirectoryAdl1Codec.Decode(encoded[..^1]));
        Assert.Throws<AccountDirectoryAdl1FormatException>(() => AccountDirectoryAdl1Codec.Decode(encoded.Concat(new byte[] { 0 }).ToArray()));
    }

    [Fact]
    public void Decode_RejectsProfileAndXodConsistencyViolations()
    {
        var valid = AccountDirectoryAdl1Codec.Encode(new AccountDirectoryAdl1(
            Bytes(16, 1), Bytes(32, 2), 4, Bytes(32, 3), 3, XodReference(Bytes(32, 4)), Bytes(32, 4)));
        const int profileOffset = 140;
        const int xodOffset = 150;
        const int xodHashOffset = 196;
        var cases = new Action<byte[]>[]
        {
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(profileOffset), 4),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(profileOffset), 1),
            bytes => Array.Clear(bytes, xodOffset, 38),
            bytes => bytes[xodOffset] = (byte)'Y',
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(xodOffset + 4), 2),
            bytes => bytes[xodOffset + 6] ^= 1,
            bytes => bytes[xodHashOffset + 6] ^= 1
        };
        foreach (var mutate in cases)
        {
            var candidate = valid.ToArray();
            mutate(candidate);
            Assert.Throws<AccountDirectoryAdl1FormatException>(() => AccountDirectoryAdl1Codec.Decode(candidate));
        }
    }

    [Fact]
    public void Decode_RejectsZeroRequiredIdentityAndFloorValues()
    {
        var encoded = AccountDirectoryAdl1Codec.Encode(new AccountDirectoryAdl1(
            Bytes(16, 1), Bytes(32, 2), 4, Bytes(32, 3), 3, XodReference(Bytes(32, 4)), Bytes(32, 4)));
        foreach (var range in new[] { (Offset: 20, Length: 16), (Offset: 44, Length: 32), (Offset: 100, Length: 32) })
        {
            var candidate = encoded.ToArray();
            Array.Clear(candidate, range.Offset, range.Length);
            Assert.Throws<AccountDirectoryAdl1FormatException>(() => AccountDirectoryAdl1Codec.Decode(candidate));
        }
    }

    private static byte[] XodReference(byte[] hash)
    {
        var reference = new byte[38];
        "XOD1"u8.CopyTo(reference);
        BinaryPrimitives.WriteUInt16BigEndian(reference.AsSpan(4), 1);
        hash.CopyTo(reference, 6);
        return reference;
    }

    private static byte[] Bytes(int length, byte first)
    {
        var value = new byte[length];
        for (var index = 0; index < value.Length; index++)
            value[index] = unchecked((byte)(first + index));
        return value;
    }
}
