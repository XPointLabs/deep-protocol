using System.Buffers.Binary;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryDts1CodecTests
{
    [Fact]
    public void RoundTripAndUnsignedProjection_AreCanonicalAndDefensive()
    {
        var value = Fixture();
        var encoded = AccountDirectoryDts1Codec.Encode(value);
        var decoded = AccountDirectoryDts1Codec.Decode(encoded);
        var unsigned = AccountDirectoryDts1Codec.EncodeUnsigned(value);
        Assert.Equal(654, encoded.Length);
        Assert.Equal(445, unsigned.Length);
        Assert.Equal((ushort)13, BinaryPrimitives.ReadUInt16BigEndian(unsigned.AsSpan(8)));
        Assert.Equal(2, decoded.Sources.Count);
        Assert.Equal("time-a.example", decoded.Sources[0].HostAscii);
        var copy = decoded.Sources[0].SourceId.ToArray();
        copy[0] ^= 1;
        Assert.NotEqual(copy, decoded.Sources[0].SourceId.ToArray());
    }

    [Fact]
    public void Decode_RejectsEnvelopeAndExactLengthViolations()
    {
        var encoded = AccountDirectoryDts1Codec.Encode(Fixture());
        Action<byte[]>[] mutations =
        [
            bytes => bytes[0] = (byte)'X',
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 2),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), 14),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10), 1),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(12), 2),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(14), 1),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(16), 15),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(FieldHeaderOffset(bytes, 5) + 4), 4097),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(FieldHeaderOffset(bytes, 15) + 4), 95)
        ];
        foreach (var mutation in mutations)
        {
            var candidate = encoded.ToArray();
            mutation(candidate);
            Assert.Throws<AccountDirectoryDts1FormatException>(() => AccountDirectoryDts1Codec.Decode(candidate));
        }
        Assert.Throws<AccountDirectoryDts1FormatException>(() => AccountDirectoryDts1Codec.Decode(encoded[..^1]));
        Assert.Throws<AccountDirectoryDts1FormatException>(() => AccountDirectoryDts1Codec.Decode(encoded.Concat(new byte[] { 0 }).ToArray()));
    }

    [Fact]
    public void Decode_RejectsGenerationPolicyTimeAndOrderingViolations()
    {
        var encoded = AccountDirectoryDts1Codec.Encode(Fixture());
        Action<byte[]>[] mutations =
        [
            bytes => { BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(FieldValueOffset(bytes, 2)), 0); bytes[FieldValueOffset(bytes, 3)] = 1; },
            bytes => { BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(FieldValueOffset(bytes, 2)), 1); Array.Clear(bytes, FieldValueOffset(bytes, 3), 32); },
            bytes => bytes[FieldValueOffset(bytes, 4)] = 1,
            bytes => bytes[FieldValueOffset(bytes, 6)] = 3,
            bytes => bytes[FieldValueOffset(bytes, 7)] = 1,
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(FieldValueOffset(bytes, 8)), 31),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(FieldValueOffset(bytes, 9)), 31),
            bytes => BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(FieldValueOffset(bytes, 11)), 2_592_001),
            bytes => bytes[FieldValueOffset(bytes, 14)] = 3,
            bytes => Array.Copy(bytes, FieldValueOffset(bytes, 15), bytes, FieldValueOffset(bytes, 15) + 96, 32),
            bytes => bytes[FieldValueOffset(bytes, 15)] = 0xff
        ];
        foreach (var mutation in mutations)
        {
            var candidate = encoded.ToArray();
            mutation(candidate);
            Assert.Throws<AccountDirectoryDts1FormatException>(() => AccountDirectoryDts1Codec.Decode(candidate));
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("UPPER.example")]
    [InlineData("bad_.example")]
    [InlineData("-bad.example")]
    [InlineData("bad-.example")]
    [InlineData("bad..example")]
    [InlineData("bad.example.")]
    [InlineData("192.0.2.1")]
    [InlineData("[2001:db8::1]")]
    [InlineData("пример.example")]
    public void Source_RejectsNonCanonicalOrLiteralHosts(string host) =>
        Assert.Throws<ArgumentException>(() => Source(1, 1, host, 1));

    [Fact]
    public void Policy_RejectsDuplicateEndpointFamilyCollapseAndUnsortedIds()
    {
        var receipts = Receipts();
        Assert.Throws<ArgumentException>(() => CreatePolicy(
            [Source(1, 1, "time.example", 1), Source(2, 2, "time.example", 1)], receipts));
        Assert.Throws<ArgumentException>(() => CreatePolicy(
            [Source(1, 1, "time-a.example", 1), Source(2, 1, "time-b.example", 2)], receipts));
        Assert.Throws<ArgumentException>(() => CreatePolicy(
            [Source(2, 1, "time-a.example", 1), Source(1, 2, "time-b.example", 2)], receipts));
        Assert.Throws<ArgumentException>(() => CreatePolicy(
            [Source(1, 1, "time-a.example", 1), Source(2, 2, "time-b.example", 2)],
            [receipts[1], receipts[0]]));
    }

    private static AccountDirectoryDts1 Fixture() => CreatePolicy(
        [Source(1, 1, "time-a.example", 1), Source(2, 2, "time-b.example", 2)], Receipts());

    private static AccountDirectoryDts1 CreatePolicy(
        IReadOnlyList<AccountDirectoryDts1Source> sources,
        IReadOnlyList<AccountDirectoryDts1RootReceipt> receipts) =>
        new(Bytes(16, 1), 1, Bytes(32, 2), sources, 2, 2, 30, 15, 0, 2_592_000, 1, 1, receipts);

    private static AccountDirectoryDts1Source Source(byte id, byte family, string host, ushort port) =>
        new(Bytes(32, id), Bytes(32, family), 1, host, port, Bytes(32, 0x40), 5);

    private static AccountDirectoryDts1RootReceipt[] Receipts() =>
    [
        new AccountDirectoryDts1RootReceipt(Bytes(32, 0x10), Bytes(64, 0x20)),
        new AccountDirectoryDts1RootReceipt(Bytes(32, 0x11), Bytes(64, 0x30))
    ];

    private static int FieldHeaderOffset(ReadOnlySpan<byte> record, int targetTag)
    {
        var offset = 12;
        for (var tag = 1; tag < targetTag; tag++)
            offset += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(record[(offset + 4)..]));
        return offset;
    }

    private static int FieldValueOffset(ReadOnlySpan<byte> record, int tag) => FieldHeaderOffset(record, tag) + 8;

    private static byte[] Bytes(int length, byte first)
    {
        var value = new byte[length];
        for (var index = 0; index < length; index++)
            value[index] = unchecked((byte)(first + index));
        return value;
    }
}
