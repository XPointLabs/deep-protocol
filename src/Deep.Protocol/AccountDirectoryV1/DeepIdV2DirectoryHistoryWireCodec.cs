using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>Shape-only source-bound history page, not a freshness capability.</summary>
public sealed class DeepIdV2DirectoryHistoryPage
{
    private readonly byte[][] heads;
    private readonly byte[] nodes;
    internal DeepIdV2DirectoryHistoryPage(byte[][] heads, byte[] nodes)
    { this.heads = heads; this.nodes = nodes; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactSuccessors =>
        heads.Select(static h => (ReadOnlyMemory<byte>)h.ToArray()).ToArray();
    public ReadOnlyMemory<byte> ConsistencyNodes => nodes.ToArray();
}

public static class DeepIdV2DirectoryHistoryWireCodec
{
    public const int RequestLength = 68;
    public const int MaximumResponseLength = 264_519;
    public const string RequestMediaType = "application/vnd.deep.directory-history-request.v2+octet-stream";
    public const string ResponseMediaType = "application/vnd.deep.directory-history.v2+octet-stream";

    public static byte[] EncodeRequest(AccountDirectoryProtectedLkg source)
    {
        ArgumentNullException.ThrowIfNull(source);
        var bytes = new byte[RequestLength];
        Header(bytes, ProtocolMagicBytes.DHQ2);
        source.Head.NetworkId.Span.CopyTo(bytes.AsSpan(12));
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(28), source.LogGeneration);
        source.CoreHash.Span.CopyTo(bytes.AsSpan(36));
        ValidateRequest(bytes);
        return bytes;
    }

    public static void ValidateRequest(ReadOnlySpan<byte> request)
    {
        if (request.Length != RequestLength) throw new FormatException("History request length is invalid.");
        CheckHeader(request, ProtocolMagicBytes.DHQ2);
        if (request.Slice(12, 16).IndexOfAnyExcept((byte)0) < 0 ||
            request.Slice(36, 32).IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("History request source is invalid.");
    }

    public static byte[] AuthorResponse(VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> exactRequest,
        IReadOnlyList<AccountDirectoryProtectedLkg> protectedHistory,
        IReadOnlyList<ReadOnlyMemory<byte>> exactTransitions)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(protectedHistory);
        ArgumentNullException.ThrowIfNull(exactTransitions);
        var request = exactRequest.ToArray();
        ValidateRequest(request);
        if (!request.AsSpan(12, 16).SequenceEqual(authority.NetworkId.Span) ||
            protectedHistory.Count is < 1 or > 1_000_000 || exactTransitions.Count > 1_000_000)
            throw new CryptographicException("History authority is out of scope or unbounded.");
        var generation = BinaryPrimitives.ReadUInt64BigEndian(request.AsSpan(28));
        var sourceIndex = -1;
        for (var i = 0; i < protectedHistory.Count; i++)
            if (protectedHistory[i].LogGeneration == generation &&
                CryptographicOperations.FixedTimeEquals(protectedHistory[i].CoreHash.Span, request.AsSpan(36)))
            { sourceIndex = i; break; }
        if (sourceIndex < 0) throw new ArgumentException("History source is absent.", nameof(exactRequest));
        var source = protectedHistory[sourceIndex];
        var successors = protectedHistory.Skip(sourceIndex + 1).Take(64)
            .Select(static h => h.ExactAdh1).ToArray();
        var nodes = Array.Empty<byte>();
        if (successors.Length > 0)
        {
            var target = protectedHistory[sourceIndex + successors.Length];
            if (target.TreeSize > (ulong)exactTransitions.Count)
                throw new CryptographicException("History journal is incomplete.");
            var journal = exactTransitions.Take(checked((int)target.TreeSize)).ToArray();
            var leaves = journal.Select(static b => DeepIdV2DirectoryTransitionCodec.Decode(b.Span).AppendLogLeafHash.ToArray()).ToArray();
            nodes = AccountDirectoryProofMaterialAuthor.BuildConsistencyProof(source, target, leaves)
                .SelectMany(static b => b.ToArray()).ToArray();
            _ = DeepIdV2DirectoryCatchupVerifier.Verify(authority, source, successors, nodes);
        }
        else _ = AccountDirectoryProtectedLkgFactory.Restore(authority, source.ExactAdh1, source.CoreHash.Span);
        var bytes = new byte[checked(RequestLength + 3 + successors.Sum(static h => 4 + h.Length) + nodes.Length)];
        Header(bytes, ProtocolMagicBytes.DHR2);
        request.AsSpan(12).CopyTo(bytes.AsSpan(12));
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(68), checked((ushort)successors.Length));
        var offset = 70;
        foreach (var head in successors)
        {
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset), checked((uint)head.Length));
            offset += 4; head.Span.CopyTo(bytes.AsSpan(offset)); offset += head.Length;
        }
        bytes[offset++] = checked((byte)(nodes.Length / 32));
        nodes.CopyTo(bytes, offset);
        _ = DecodeResponse(bytes, request);
        return bytes;
    }

    public static DeepIdV2DirectoryHistoryPage DecodeResponse(ReadOnlySpan<byte> bytes,
        ReadOnlySpan<byte> exactRequest)
    {
        ValidateRequest(exactRequest);
        if (bytes.Length is < 71 or > MaximumResponseLength)
            throw new FormatException("History response length is invalid.");
        CheckHeader(bytes, ProtocolMagicBytes.DHR2);
        if (!CryptographicOperations.FixedTimeEquals(bytes.Slice(12, 56), exactRequest[12..]))
            throw new CryptographicException("History response does not consume the requested source.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(bytes[68..]);
        if (count > 64) throw new FormatException("History page is unbounded.");
        var heads = new byte[count][];
        var offset = 70;
        for (var i = 0; i < count; i++)
        {
            var length = BinaryPrimitives.ReadUInt32BigEndian(Read(bytes, ref offset, 4));
            if (length is < 1 or > 4096) throw new FormatException("History head is unbounded.");
            heads[i] = Read(bytes, ref offset, checked((int)length)).ToArray();
            _ = AccountDirectoryAdh1Codec.Decode(heads[i]);
        }
        var nodeCount = Read(bytes, ref offset, 1)[0];
        if (nodeCount > 64 || count == 0 && nodeCount != 0)
            throw new FormatException("History consistency proof is unbounded.");
        var nodes = Read(bytes, ref offset, nodeCount * 32).ToArray();
        if (offset != bytes.Length) throw new FormatException("History response has trailing bytes.");
        return new DeepIdV2DirectoryHistoryPage(heads, nodes);
    }

    private static ReadOnlySpan<byte> Read(ReadOnlySpan<byte> bytes, ref int offset, int length)
    {
        if (bytes.Length - offset < length) throw new FormatException("History response is truncated.");
        var result = bytes.Slice(offset, length); offset += length; return result;
    }
    private static void Header(Span<byte> bytes, ReadOnlySpan<byte> magic)
    { magic.CopyTo(bytes); BinaryPrimitives.WriteUInt16BigEndian(bytes[4..], 2); BinaryPrimitives.WriteUInt32BigEndian(bytes[8..], checked((uint)bytes.Length)); }
    private static void CheckHeader(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> magic)
    {
        if (bytes.Length < 12 || !bytes[..4].SequenceEqual(magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]) != 2 || BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]) != 0 ||
            BinaryPrimitives.ReadUInt32BigEndian(bytes[8..]) != bytes.Length)
            throw new FormatException("History header is invalid.");
    }
}
