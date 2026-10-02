using System.Buffers.Binary;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>Owned untrusted distribution bytes, never network/time/account/route authority.</summary>
public sealed class XPointNetworkClosureWireArtifacts
{
    private readonly byte[] networkId;
    private readonly byte[][][] chains;

    internal XPointNetworkClosureWireArtifacts(ReadOnlySpan<byte> networkId, byte[][][] chains)
    {
        this.networkId = networkId.ToArray();
        this.chains = chains;
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactAuthorityChain => Copy(0);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactTimePolicyChain => Copy(1);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactNetworkPolicyChain => Copy(2);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactViewChain => Copy(3);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactHeadChain => Copy(4);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactActiveNodeDescriptors => Copy(5);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactPlacementTopologyChain => Copy(6);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactMailboxAuthorityChain => Copy(7);

    private IReadOnlyList<ReadOnlyMemory<byte>> Copy(int index) =>
        Array.AsReadOnly(chains[index].Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
}

/// <summary>
/// Identity-neutral NCQ2/NCP2 framing only: no proof, nonce, private locator,
/// selected route, authority mint or rewritten signed NETCODEC record.
/// </summary>
public static class XPointNetworkClosureWireCodec
{
    public const ushort Version = 2;
    public const int RequestLength = 28;
    public const int MaximumResponseLength = 68 * 1024 * 1024;
    public const int MaximumChainLength = 16 * 1024 * 1024;
    public const int MaximumRecordLength = 65_535;
    public const int MaximumChainCount = 4096;
    public const string RequestMediaType = "application/vnd.deep.network-closure-request.v2+octet-stream";
    public const string ResponseMediaType = "application/vnd.deep.network-closure.v2+octet-stream";
    private const int ChainCount = 8;
    private const ushort Suite = 0x0201;

    public static byte[] EncodeRequest(ReadOnlySpan<byte> networkId)
    {
        RequireNetwork(networkId);
        var bytes = new byte[RequestLength];
        WriteHeader(bytes, ProtocolMagicBytes.NCQ2, 0);
        networkId.CopyTo(bytes.AsSpan(12));
        return bytes;
    }

    public static byte[] DecodeRequest(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != RequestLength)
            throw new FormatException("Network closure request length is invalid.");
        RequireHeader(bytes, ProtocolMagicBytes.NCQ2, 0);
        RequireNetwork(bytes[12..]);
        return bytes[12..].ToArray();
    }

    public static byte[] EncodeResponse(ReadOnlySpan<byte> networkId,
        IReadOnlyList<ReadOnlyMemory<byte>> exactAuthorityChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactTimePolicyChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactNetworkPolicyChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactViewChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactHeadChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactActiveNodeDescriptors,
        IReadOnlyList<ReadOnlyMemory<byte>> exactPlacementTopologyChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactMailboxAuthorityChain)
    {
        RequireNetwork(networkId);
        IReadOnlyList<ReadOnlyMemory<byte>>[] chains =
        [exactAuthorityChain, exactTimePolicyChain, exactNetworkPolicyChain,
            exactViewChain, exactHeadChain, exactActiveNodeDescriptors, exactPlacementTopologyChain,
            exactMailboxAuthorityChain];
        var length = RequestLength + ChainCount * 4;
        for (var index = 0; index < ChainCount; index++)
        {
            var chain = chains[index];
            ArgumentNullException.ThrowIfNull(chain);
            if (chain.Count is < 1 or > MaximumChainCount)
                throw new FormatException("Network closure chain count is invalid.");
            var chainLength = 0;
            foreach (var value in chain)
            {
                RequireRecord(value.Span, index);
                chainLength = checked(chainLength + value.Length);
                if (chainLength > MaximumChainLength)
                    throw new FormatException("Network closure chain length is invalid.");
                length = checked(length + 4 + value.Length);
                if (length > MaximumResponseLength)
                    throw new FormatException("Network closure response length is invalid.");
            }
        }
        RequirePairedCounts(chains[0].Count, chains[1].Count, chains[3].Count, chains[4].Count);
        var bytes = new byte[length];
        WriteHeader(bytes, ProtocolMagicBytes.NCP2, ChainCount);
        networkId.CopyTo(bytes.AsSpan(12));
        var offset = RequestLength;
        foreach (var chain in chains)
        {
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset), (uint)chain.Count);
            offset += 4;
            foreach (var value in chain)
            {
                BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset), (uint)value.Length);
                offset += 4;
                value.Span.CopyTo(bytes.AsSpan(offset));
                offset += value.Length;
            }
        }
        Preflight(bytes);
        return bytes;
    }

    public static XPointNetworkClosureWireArtifacts DecodeResponse(ReadOnlySpan<byte> bytes)
    {
        // Check every chain and trailing byte before copying any record.
        Preflight(bytes);
        var chains = new byte[ChainCount][][];
        var offset = RequestLength;
        for (var index = 0; index < ChainCount; index++)
        {
            var count = (int)ReadLength(bytes, ref offset);
            chains[index] = new byte[count][];
            for (var record = 0; record < count; record++)
            {
                var length = (int)ReadLength(bytes, ref offset);
                chains[index][record] = bytes.Slice(offset, length).ToArray();
                offset += length;
            }
        }
        return new XPointNetworkClosureWireArtifacts(bytes.Slice(12, 16), chains);
    }

    private static void Preflight(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < RequestLength + ChainCount * (4 + 4 + 12) ||
            bytes.Length > MaximumResponseLength)
            throw new FormatException("Network closure response length is invalid.");
        RequireHeader(bytes, ProtocolMagicBytes.NCP2, ChainCount);
        RequireNetwork(bytes.Slice(12, 16));
        Span<int> counts = stackalloc int[ChainCount];
        var offset = RequestLength;
        for (var index = 0; index < ChainCount; index++)
        {
            var count = ReadLength(bytes, ref offset);
            if (count is < 1 or > MaximumChainCount)
                throw new FormatException("Network closure chain count is invalid.");
            counts[index] = (int)count;
            var chainLength = 0;
            for (var record = 0; record < count; record++)
            {
                var length = ReadLength(bytes, ref offset);
                if (length is < 12 or > MaximumRecordLength || length > bytes.Length - offset)
                    throw new FormatException("Network closure record length is invalid.");
                chainLength = checked(chainLength + (int)length);
                if (chainLength > MaximumChainLength)
                    throw new FormatException("Network closure chain length is invalid.");
                RequireRecord(bytes.Slice(offset, (int)length), index);
                offset += (int)length;
            }
        }
        RequirePairedCounts(counts[0], counts[1], counts[3], counts[4]);
        if (offset != bytes.Length)
            throw new FormatException("Network closure response has trailing bytes.");
    }

    private static uint ReadLength(ReadOnlySpan<byte> bytes, ref int offset)
    {
        if (offset > bytes.Length - 4)
            throw new FormatException("Network closure response is truncated.");
        var value = BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset, 4));
        offset += 4;
        return value;
    }

    private static void RequireRecord(ReadOnlySpan<byte> value, int chain)
    {
        ReadOnlySpan<byte> magic = chain switch
        {
            0 => ProtocolMagicBytes.XNA1, 1 => ProtocolMagicBytes.DTS1,
            2 => ProtocolMagicBytes.XVP1, 3 => ProtocolMagicBytes.XNV1,
            4 => ProtocolMagicBytes.XNH1, 5 => ProtocolMagicBytes.XND1,
            6 => ProtocolMagicBytes.PMT2, 7 => ProtocolMagicBytes.PMA2,
            _ => throw new InvalidOperationException("Unknown network closure chain.")
        };
        if (value.Length is < 12 or > MaximumRecordLength || !value[..4].SequenceEqual(magic))
            throw new FormatException("Network closure record shape is invalid.");
    }

    private static void RequirePairedCounts(int authority, int time, int views, int heads)
    {
        if (authority != time || views != heads)
            throw new FormatException("Network closure paired chain counts differ.");
    }

    private static void RequireNetwork(ReadOnlySpan<byte> networkId)
    {
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("Network closure network scope is invalid.");
    }

    private static void WriteHeader(Span<byte> bytes, ReadOnlySpan<byte> magic, ushort count)
    {
        magic.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes[4..], Version);
        BinaryPrimitives.WriteUInt16BigEndian(bytes[6..], Suite);
        BinaryPrimitives.WriteUInt16BigEndian(bytes[8..], count);
    }

    private static void RequireHeader(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> magic, ushort count)
    {
        if (!bytes[..4].SequenceEqual(magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]) != Version ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]) != Suite ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes[8..]) != count ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes[10..]) != 0)
            throw new FormatException("Network closure frame header is invalid.");
    }
}
