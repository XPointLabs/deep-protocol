using System.Buffers.Binary;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.Tests.XPointNetworkV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryAfp1CodecTests
{
    [Fact]
    public void RoundTrip_IsCanonicalAndDefensive()
    {
        var value = Fixture();
        var encoded = AccountDirectoryAfp1Codec.Encode(value);
        var decoded = AccountDirectoryAfp1Codec.Decode(encoded);

        Assert.Equal(encoded, AccountDirectoryAfp1Codec.Encode(decoded));
        Assert.Equal((ulong)11, decoded.SourceAdhGeneration);
        Assert.Single(decoded.AuthorityChain);
        Assert.Single(decoded.CheckpointChain);
        Assert.Single(decoded.TargetHeadChain);
        Assert.Equal(2, decoded.MembershipNodes.Count);
        var copy = decoded.CheckpointChain[0].ToArray();
        copy[0] ^= 1;
        Assert.NotEqual(copy, decoded.CheckpointChain[0].ToArray());
    }

    [Fact]
    public void Decode_RejectsEnvelopeAndListFramingViolations()
    {
        var encoded = AccountDirectoryAfp1Codec.Encode(Fixture());
        Action<byte[]>[] mutations =
        [
            bytes => bytes[0] = (byte)'X',
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 2),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 1),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), 10),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10), 1),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(12), 2),
            bytes => bytes[Value(bytes, 4)] = 0,
            bytes => bytes[Value(bytes, 6)] = 0,
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(Value(bytes, 5)), 11),
            bytes => bytes[Value(bytes, 9)] = 3
        ];
        foreach (var mutation in mutations)
        {
            var candidate = encoded.ToArray();
            mutation(candidate);
            Assert.Throws<AccountDirectoryAfp1FormatException>(() => AccountDirectoryAfp1Codec.Decode(candidate));
        }
        Assert.Throws<AccountDirectoryAfp1FormatException>(() => AccountDirectoryAfp1Codec.Decode(encoded[..^1]));
        Assert.Throws<AccountDirectoryAfp1FormatException>(() => AccountDirectoryAfp1Codec.Decode(encoded.Concat(new byte[] { 0 }).ToArray()));
    }

    [Fact]
    public void Constructor_RejectsCoverageTargetAndCheckpointChainMismatch()
    {
        var fixture = Fixture();
        Assert.Throws<ArgumentException>(() => Create(sourceGeneration: 9));
        Assert.Throws<ArgumentException>(() => Create(sourceLeafIndex: 3));
        Assert.Throws<ArgumentException>(() => Create(targetHash: Bytes(32, 0x77)));

        var firstHead = TargetHead(13, 0x30);
        var secondHead = TargetHead(14, 0x40);
        var first = Checkpoint(3, Bytes(32, 0x21), firstHead);
        var wrongSecond = Checkpoint(4, Bytes(32, 0x70), secondHead);
        Assert.Throws<ArgumentException>(() => new AccountDirectoryAfp1(
            fixture.NetworkId.Span, 11, 25, fixture.SourceAdh1CoreHash.Span,
            AccountDirectoryCrypto.ComputeAdh1CoreHash(secondHead),
            fixture.AuthorityChain, [first, wrongSecond],
            [AccountDirectoryAdh1Codec.Encode(firstHead), AccountDirectoryAdh1Codec.Encode(secondHead)],
            0, fixture.MembershipNodes, fixture.LiveDtt1CoreHash.Span));
    }

    private static AccountDirectoryAfp1 Fixture() => Create();

    private static AccountDirectoryAfp1 Create(
        ulong sourceGeneration = 11,
        ulong sourceLeafIndex = 1,
        byte[]? targetHash = null)
    {
        var targetHead = TargetHead(13, 0x30);
        targetHash ??= AccountDirectoryCrypto.ComputeAdh1CoreHash(targetHead);
        return new AccountDirectoryAfp1(Network(), sourceGeneration, 25, Bytes(32, 0x20), targetHash,
            [XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xna1)], [Checkpoint(3, Bytes(32, 0x21), targetHead)],
            [AccountDirectoryAdh1Codec.Encode(targetHead)], sourceLeafIndex,
            [Bytes(32, 0x40), Bytes(32, 0x50)], Bytes(32, 0x60));
    }

    private static ReadOnlyMemory<byte> Checkpoint(
        ulong generation,
        byte[] predecessor,
        AccountDirectoryAdh1 target)
    {
        var targetHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(target);
        var value = new AccountDirectoryAdf1(Network(), generation, predecessor, 10, 12, 3,
            Bytes(32, 0x22), Ref("ADH1", targetHash), target.TreeSize,
            target.AppendLogMerkleRoot.Span, target.CurrentValueMapRoot.Span,
            target.ExactXnaAuthorityCoreReference.Span, 900, 1,
            [new(Bytes(32, 0x10), Bytes(64, 0x11))]);
        return AccountDirectoryAdf1Codec.Encode(value);
    }

    private static AccountDirectoryAdh1 TargetHead(ulong generation, byte seed) => new(
        Network(), generation, Bytes(32, unchecked((byte)(seed + 1))), 30,
        Bytes(32, 0x31), Bytes(32, 0x32), Ref("XNA1", Bytes(32, 0x33)), Bytes(32, 0x34),
        800, 1_000, 1,
        [new AccountDirectoryAdh1WitnessEntry(Bytes(32, 0x35), Bytes(64, 0x36))]);

    private static byte[] Ref(string magic, byte[] hash)
    {
        var result = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result, 6);
        return result;
    }

    private static byte[] Network() => XPointNetworkTestRecords.Id(1, 16);

    private static int Header(ReadOnlySpan<byte> record, int tag)
    {
        var offset = 12;
        for (var current = 1; current < tag; current++)
            offset += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(record[(offset + 4)..]));
        return offset;
    }

    private static int Value(ReadOnlySpan<byte> record, int tag) => Header(record, tag) + 8;

    private static byte[] Bytes(int length, byte seed)
    {
        var result = new byte[length];
        for (var index = 0; index < result.Length; index++) result[index] = unchecked((byte)(seed + index));
        return result;
    }
}
