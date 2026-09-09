using System.Buffers.Binary;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryAdf1CodecTests
{
    [Fact]
    public void RoundTripAndUnsignedProjection_AreExactAndDefensive()
    {
        var value = Fixture();
        var encoded = AccountDirectoryAdf1Codec.Encode(value);
        var unsigned = AccountDirectoryAdf1Codec.EncodeUnsigned(value);
        var decoded = AccountDirectoryAdf1Codec.Decode(encoded);

        Assert.Equal(603, encoded.Length);
        Assert.Equal(394, unsigned.Length);
        Assert.Equal((ushort)14, BinaryPrimitives.ReadUInt16BigEndian(unsigned.AsSpan(8)));
        Assert.Equal((ulong)7, decoded.CheckpointGeneration);
        Assert.Equal(2, decoded.Receipts.Count);
        var copy = decoded.NetworkId.ToArray();
        copy[0] ^= 1;
        Assert.NotEqual(copy, decoded.NetworkId.ToArray());
    }

    [Fact]
    public void Decode_RejectsEnvelopeLengthAndTrailingViolations()
    {
        var encoded = AccountDirectoryAdf1Codec.Encode(Fixture());
        Action<byte[]>[] mutations =
        [
            bytes => bytes[0] = (byte)'X',
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 2),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), 15),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10), 1),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(12), 2),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(FieldHeader(bytes, 8) + 4), 37),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(FieldHeader(bytes, 16) + 4), 191)
        ];
        for (var index = 0; index < mutations.Length; index++)
        {
            var candidate = encoded.ToArray();
            mutations[index](candidate);
            var error = Record.Exception(() => AccountDirectoryAdf1Codec.Decode(candidate));
            Assert.True(error is AccountDirectoryAdf1FormatException,
                $"Mutation {index} was not rejected as ADF1 format: {error?.GetType().Name ?? "no exception"}.");
        }
        Assert.Throws<AccountDirectoryAdf1FormatException>(() => AccountDirectoryAdf1Codec.Decode(encoded[..^1]));
        Assert.Throws<AccountDirectoryAdf1FormatException>(() => AccountDirectoryAdf1Codec.Decode(encoded.Concat(new byte[] { 0 }).ToArray()));
    }

    [Fact]
    public void Decode_RejectsInvalidGenerationRangeReferencesAndReceiptOrder()
    {
        var encoded = AccountDirectoryAdf1Codec.Encode(Fixture());
        Action<byte[]>[] mutations =
        [
            bytes => { BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(Value(bytes, 2)), 0); bytes[Value(bytes, 3)] = 1; },
            bytes => { BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(Value(bytes, 2)), 1); Array.Clear(bytes, Value(bytes, 3), 32); },
            bytes => BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(Value(bytes, 5)), 2),
            bytes => Array.Clear(bytes, Value(bytes, 6), 8),
            bytes => bytes[Value(bytes, 8)] = (byte)'X',
            bytes => Array.Clear(bytes, Value(bytes, 10), 32),
            bytes => bytes[Value(bytes, 12)] = (byte)'Z',
            bytes => bytes[Value(bytes, 15)] = 0,
            bytes => Array.Copy(bytes, Value(bytes, 16), bytes, Value(bytes, 16) + 96, 32)
        ];
        for (var index = 0; index < mutations.Length; index++)
        {
            var candidate = encoded.ToArray();
            mutations[index](candidate);
            var error = Record.Exception(() => AccountDirectoryAdf1Codec.Decode(candidate));
            Assert.True(error is AccountDirectoryAdf1FormatException,
                $"Mutation {index} was not rejected as ADF1 format: {error?.GetType().Name ?? "no exception"}.");
        }
    }

    [Fact]
    public void CryptoFraming_BindsUnsignedRecordAndReceiptsDoNotChangeCore()
    {
        var value = Fixture();
        var other = Create([new(Bytes(32, 0x10), Bytes(64, 0x55)), new(Bytes(32, 0x11), Bytes(64, 0x66))]);
        Assert.Equal(AccountDirectoryCrypto.ComputeAdf1CoreHash(value), AccountDirectoryCrypto.ComputeAdf1CoreHash(other));
        Assert.Equal(AccountDirectoryCrypto.ComputeAdf1SigningInput(value), AccountDirectoryCrypto.ComputeAdf1SigningInput(other));
        Assert.NotEqual(AccountDirectoryAdf1Codec.Encode(value), AccountDirectoryAdf1Codec.Encode(other));
    }

    private static AccountDirectoryAdf1 Fixture() => Create(
        [new(Bytes(32, 0x10), Bytes(64, 0x20)), new(Bytes(32, 0x11), Bytes(64, 0x30))]);

    private static AccountDirectoryAdf1 Create(IReadOnlyList<AccountDirectoryAdf1RootReceipt> receipts) =>
        new(Bytes(16, 1), 7, Bytes(32, 2), 10, 20, 11, Bytes(32, 3), Ref("ADH1", 4),
            42, Bytes(32, 5), Bytes(32, 6), Ref("XNA1", 7), 1234, 1, receipts);

    private static byte[] Ref(string magic, byte seed)
    {
        var result = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        Bytes(32, seed).CopyTo(result, 6);
        return result;
    }

    private static int FieldHeader(ReadOnlySpan<byte> record, int tag)
    {
        var offset = 12;
        for (var current = 1; current < tag; current++)
            offset += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(record[(offset + 4)..]));
        return offset;
    }

    private static int Value(ReadOnlySpan<byte> record, int tag) => FieldHeader(record, tag) + 8;

    private static byte[] Bytes(int length, byte seed)
    {
        var result = new byte[length];
        for (var index = 0; index < result.Length; index++) result[index] = unchecked((byte)(seed + index));
        return result;
    }
}
