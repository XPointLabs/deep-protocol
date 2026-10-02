using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.XPointNetworkV1;

// Deliberately shape-only transport fixtures, not signed network/freshness evidence.
public sealed class XPointNetworkClosureWireCodecTests
{
    private static byte[] Network => Enumerable.Repeat((byte)7, 16).ToArray();
    private static readonly string[] Magics = ["XNA1", "DTS1", "XVP1", "XNV1", "XNH1", "XND1", "PMT2", "PMA2"];

    [Fact]
    public void RequestIsClosedIdentityNeutralAndOwned()
    {
        var network = Network;
        var bytes = XPointNetworkClosureWireCodec.EncodeRequest(network);
        Assert.Equal(28, bytes.Length);
        Assert.Equal("NCQ2", Encoding.ASCII.GetString(bytes, 0, 4));
        Assert.Equal(new byte[] { 0, 2, 2, 1, 0, 0, 0, 0 }, bytes[4..12]);
        var decoded = XPointNetworkClosureWireCodec.DecodeRequest(bytes);
        bytes[12] ^= 1;
        network[0] ^= 1;
        Assert.Equal(Network, decoded);
        Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.EncodeRequest(new byte[16]));
        Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.EncodeRequest(new byte[15]));
    }

    [Fact]
    public void ResponsePreservesEveryExactChainAndCannotExportMutableState()
    {
        var chains = Chains();
        chains[3] = [Record(3), Record(3, 32)];
        chains[4] = [Record(4), Record(4, 48)];
        var bytes = Encode(chains);
        var response = XPointNetworkClosureWireCodec.DecodeResponse(bytes);
        Assert.Equal("NCP2", Encoding.ASCII.GetString(bytes, 0, 4));
        Assert.Equal(2, response.ExactViewChain.Count);
        Assert.Equal(chains[7][0].ToArray(), response.ExactMailboxAuthorityChain[0].ToArray());
        var mailboxAuthority = response.ExactMailboxAuthorityChain[0];
        Assert.True(MemoryMarshal.TryGetArray(mailboxAuthority, out var mailboxSegment));
        mailboxSegment.Array![mailboxSegment.Offset] ^= 1;
        Assert.Equal(chains[7][0].ToArray(), response.ExactMailboxAuthorityChain[0].ToArray());
        var exported = response.ExactAuthorityChain[0];
        Assert.True(MemoryMarshal.TryGetArray(exported, out var segment));
        segment.Array![segment.Offset] ^= 1;
        Array.Fill(bytes, (byte)0);
        Assert.Equal(chains[0][0].ToArray(), response.ExactAuthorityChain[0].ToArray());
        Assert.Equal(chains[4][1].ToArray(), response.ExactHeadChain[1].ToArray());
        var network = response.NetworkId;
        Assert.True(MemoryMarshal.TryGetArray(network, out segment));
        segment.Array![segment.Offset] ^= 1;
        Assert.Equal(Network, response.NetworkId.ToArray());
    }

    [Theory]
    [InlineData(0)] [InlineData(4)] [InlineData(5)] [InlineData(6)]
    [InlineData(7)] [InlineData(8)] [InlineData(9)] [InlineData(10)] [InlineData(11)]
    public void UnknownHeadersReject(int offset)
    {
        var request = XPointNetworkClosureWireCodec.EncodeRequest(Network);
        request[offset] ^= 0x80;
        Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.DecodeRequest(request));
        var response = Encode(Chains());
        response[offset] ^= 0x80;
        Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.DecodeResponse(response));
    }

    [Fact]
    public void TruncationTrailingBytesZeroScopeAndWrongChainMagicReject()
    {
        var bytes = Encode(Chains());
        for (var length = 0; length < bytes.Length; length++)
            Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.DecodeResponse(bytes[..length]));
        Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.DecodeResponse([.. bytes, 0]));
        var zeroScope = bytes.ToArray();
        zeroScope.AsSpan(12, 16).Clear();
        Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.DecodeResponse(zeroScope));
        // Last-chain failure must be checked before ownership, not just first-chain shape.
        var wrong = bytes.ToArray();
        "ADP1"u8.CopyTo(wrong.AsSpan(wrong.Length - 12));
        Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.DecodeResponse(wrong));
        var request = XPointNetworkClosureWireCodec.EncodeRequest(Network);
        Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.DecodeRequest([.. request, 0]));
        Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.DecodeRequest(bytes));
        Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.DecodeResponse(request));
    }

    [Theory]
    [InlineData(0u)] [InlineData(4097u)] [InlineData(uint.MaxValue)]
    public void HostileCountsReject(uint value)
    {
        var bytes = Encode(Chains());
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(28), value);
        Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.DecodeResponse(bytes));
    }

    [Theory]
    [InlineData(0u)] [InlineData(11u)] [InlineData(65536u)] [InlineData(uint.MaxValue)]
    public void HostileRecordLengthsReject(uint value)
    {
        var bytes = Encode(Chains());
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(32), value);
        Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.DecodeResponse(bytes));
    }

    [Fact]
    public void WriterChecksPairsAndBoundariesWithoutInventingSignedRecords()
    {
        var chains = Chains();
        chains[1] = [Record(1), Record(1)];
        Assert.Throws<FormatException>(() => Encode(chains));
        chains = Chains();
        chains[4] = [Record(4), Record(4)];
        Assert.Throws<FormatException>(() => Encode(chains));
        chains = Chains();
        chains[5] = [];
        Assert.Throws<FormatException>(() => Encode(chains));
        chains[5] = Enumerable.Repeat((ReadOnlyMemory<byte>)Record(5), 4096).ToArray();
        Assert.Equal(4096, XPointNetworkClosureWireCodec.DecodeResponse(Encode(chains)).ExactActiveNodeDescriptors.Count);
        chains[5] = Enumerable.Repeat((ReadOnlyMemory<byte>)Record(5), 4097).ToArray();
        Assert.Throws<FormatException>(() => Encode(chains));
        chains[5] = [Record(5, 65_535)];
        Assert.Equal(65_535, XPointNetworkClosureWireCodec.DecodeResponse(Encode(chains)).ExactActiveNodeDescriptors[0].Length);
        chains[5] = [Record(5, 65_536)];
        Assert.Throws<FormatException>(() => Encode(chains));
        chains[5] = Enumerable.Repeat((ReadOnlyMemory<byte>)Record(5, 65_535), 257).ToArray();
        Assert.Throws<FormatException>(() => Encode(chains));
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>>[] Chains() =>
        Enumerable.Range(0, 8).Select(index =>
            (IReadOnlyList<ReadOnlyMemory<byte>>)new ReadOnlyMemory<byte>[] { Record(index) }).ToArray();

    private static byte[] Record(int chain, int size = 12)
    {
        var bytes = new byte[size];
        Encoding.ASCII.GetBytes(Magics[chain]).CopyTo(bytes, 0);
        return bytes;
    }

    private static byte[] Encode(IReadOnlyList<ReadOnlyMemory<byte>>[] chains) =>
        XPointNetworkClosureWireCodec.EncodeResponse(Network,
            chains[0], chains[1], chains[2], chains[3], chains[4], chains[5], chains[6], chains[7]);

    [Fact]
    public void RetiredSevenChainAndMissingOrWrongMailboxAuthorityReject()
    {
        var bytes = Encode(Chains());
        var retired = bytes[..^20]; // shape-only final chain: count + length + 12 bytes
        BinaryPrimitives.WriteUInt16BigEndian(retired.AsSpan(8), 7);
        Assert.Throws<FormatException>(() => XPointNetworkClosureWireCodec.DecodeResponse(retired));
        var chains = Chains();
        chains[7] = [];
        Assert.Throws<FormatException>(() => Encode(chains));
        chains[7] = [Record(6)];
        Assert.Throws<FormatException>(() => Encode(chains));
    }
}
