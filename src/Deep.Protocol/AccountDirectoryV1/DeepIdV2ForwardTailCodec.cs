using System.Buffers.Binary;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// ADP1 V2 mode-2 tag-14 framing. The embedded AFP1 root proof terminates at
/// a historical anchor; the following exact ADH1 envelopes lead to the one
/// current DTT1-bound head. This framing never crosses into V1 ADP1.
/// </summary>
internal static class DeepIdV2ForwardTailCodec
{
    internal const byte HistoryMode = 2;
    internal const int MaximumTailHeads = 64;

    internal sealed class Parsed(
        ReadOnlyMemory<byte> exactAnchorAfp1,
        AccountDirectoryAfp1 anchorProof,
        AccountDirectoryAdh1 anchorHead,
        ReadOnlyMemory<byte> exactChainSourceHead,
        byte sourceCheckpointIndex,
        ulong sourceLeafIndex,
        IReadOnlyList<ReadOnlyMemory<byte>> sourceMembershipNodes,
        IReadOnlyList<ReadOnlyMemory<byte>> exactTailHeads)
    {
        internal ReadOnlyMemory<byte> ExactAnchorAfp1 { get; } =
            exactAnchorAfp1.ToArray();
        internal AccountDirectoryAfp1 AnchorProof { get; } = anchorProof;
        internal AccountDirectoryAdh1 AnchorHead { get; } = anchorHead;
        internal ReadOnlyMemory<byte> ExactChainSourceHead { get; } =
            exactChainSourceHead.ToArray();
        internal byte SourceCheckpointIndex { get; } = sourceCheckpointIndex;
        internal ulong SourceLeafIndex { get; } = sourceLeafIndex;
        internal IReadOnlyList<ReadOnlyMemory<byte>> SourceMembershipNodes { get; } =
            sourceMembershipNodes.Select(static value =>
                (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
        internal IReadOnlyList<ReadOnlyMemory<byte>> ExactTailHeads { get; } =
            exactTailHeads.Select(static value =>
                (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
    }

    internal static byte[] Encode(ReadOnlySpan<byte> exactAnchorAfp1,
        ReadOnlySpan<byte> exactChainSourceHead,
        byte sourceCheckpointIndex, ulong sourceLeafIndex,
        IReadOnlyList<ReadOnlyMemory<byte>> sourceMembershipNodes,
        IReadOnlyList<ReadOnlyMemory<byte>> exactTailHeads)
    {
        ArgumentNullException.ThrowIfNull(sourceMembershipNodes);
        ArgumentNullException.ThrowIfNull(exactTailHeads);
        if (exactAnchorAfp1.Length is < 12 or > DeepIdV2Adp1Codec.MaximumLength ||
            exactChainSourceHead.Length is < 12 or > 4096 ||
            sourceMembershipNodes.Count > 64 ||
            exactTailHeads.Count > MaximumTailHeads)
            throw new AccountDirectoryAdp1FormatException(
                "DID2 forward-tail framing exceeds its bounds.");
        if (sourceMembershipNodes.Any(static value => value.Length != 32) ||
            exactTailHeads.Any(static value => value.Length is < 12 or > 4096))
            throw new AccountDirectoryAdp1FormatException(
                "DID2 successor-tail head exceeds its bounds.");
        var length = checked(4 + exactAnchorAfp1.Length +
            4 + exactChainSourceHead.Length + 1 + 8 + 1 +
            sourceMembershipNodes.Count * 32 + 1 +
            exactTailHeads.Sum(static value => 4 + value.Length));
        if (length > DeepIdV2Adp1Codec.MaximumLength)
            throw new AccountDirectoryAdp1FormatException(
                "DID2 forward-tail framing exceeds ADP1 V2.");
        var output = new byte[length];
        BinaryPrimitives.WriteUInt32BigEndian(output, (uint)exactAnchorAfp1.Length);
        exactAnchorAfp1.CopyTo(output.AsSpan(4));
        var offset = 4 + exactAnchorAfp1.Length;
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset),
            checked((uint)exactChainSourceHead.Length));
        offset += 4;
        exactChainSourceHead.CopyTo(output.AsSpan(offset));
        offset += exactChainSourceHead.Length;
        output[offset++] = sourceCheckpointIndex;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset),
            sourceLeafIndex);
        offset += 8;
        output[offset++] = checked((byte)sourceMembershipNodes.Count);
        foreach (var node in sourceMembershipNodes)
        {
            node.Span.CopyTo(output.AsSpan(offset));
            offset += 32;
        }
        output[offset++] = checked((byte)exactTailHeads.Count);
        foreach (var head in exactTailHeads)
        {
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset),
                checked((uint)head.Length));
            offset += 4;
            head.Span.CopyTo(output.AsSpan(offset));
            offset += head.Length;
        }
        _ = Decode(output);
        return output;
    }

    internal static Parsed Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is < 43 or > DeepIdV2Adp1Codec.MaximumLength)
            throw new AccountDirectoryAdp1FormatException(
                "DID2 forward-tail framing length is invalid.");
        var afpLength = BinaryPrimitives.ReadUInt32BigEndian(encoded);
        if (afpLength < 12 || afpLength > encoded.Length - 31)
            throw new AccountDirectoryAdp1FormatException(
                "DID2 anchor AFP1 length is invalid.");
        var exactAfp = encoded.Slice(4, checked((int)afpLength));
        AccountDirectoryAfp1 afp;
        try { afp = AccountDirectoryAfp1Codec.Decode(exactAfp); }
        catch (Exception exception) when (exception is FormatException or
            ArgumentException)
        {
            throw new AccountDirectoryAdp1FormatException(
                $"DID2 anchor AFP1 is invalid: {exception.Message}");
        }
        var anchorBytes = afp.TargetHeadChain[^1];
        var anchor = AccountDirectoryAdh1Codec.Decode(anchorBytes.Span);
        var offset = 4 + checked((int)afpLength);
        if (encoded.Length - offset < 4)
            throw new AccountDirectoryAdp1FormatException(
                "DID2 chain-source head length is truncated.");
        var sourceLength = BinaryPrimitives.ReadUInt32BigEndian(
            encoded.Slice(offset, 4));
        offset += 4;
        if (sourceLength is < 12 or > 4096 ||
            sourceLength > encoded.Length - offset)
            throw new AccountDirectoryAdp1FormatException(
                "DID2 chain-source head length is invalid.");
        var exactSource = encoded.Slice(offset, checked((int)sourceLength));
        AccountDirectoryAdh1 sourceHead;
        try { sourceHead = AccountDirectoryAdh1Codec.Decode(exactSource); }
        catch (Exception exception) when (exception is FormatException or
            ArgumentException)
        {
            throw new AccountDirectoryAdp1FormatException(
                $"DID2 chain-source head is invalid: {exception.Message}");
        }
        offset += checked((int)sourceLength);
        if (encoded.Length - offset < 11 ||
            sourceHead.MinimumReader < 2 ||
            sourceHead.LogGeneration != afp.SourceAdhGeneration ||
            sourceHead.TreeSize != afp.SourceTreeSize ||
            !AccountDirectoryCrypto.ComputeAdh1CoreHash(sourceHead)
                .AsSpan().SequenceEqual(afp.SourceAdh1CoreHash.Span))
            throw new AccountDirectoryAdp1FormatException(
                "DID2 chain-source head differs from the embedded AFP1.");
        var sourceCheckpointIndex = encoded[offset++];
        if (sourceCheckpointIndex >= afp.CheckpointChain.Count)
            throw new AccountDirectoryAdp1FormatException(
                "DID2 source checkpoint index is outside the signed chain.");
        var sourceLeafIndex = BinaryPrimitives.ReadUInt64BigEndian(
            encoded.Slice(offset, 8));
        offset += 8;
        var membershipCount = encoded[offset++];
        if (membershipCount > 64 ||
            encoded.Length - offset < membershipCount * 32 + 1)
            throw new AccountDirectoryAdp1FormatException(
                "DID2 source membership path is invalid.");
        var membership = new ReadOnlyMemory<byte>[membershipCount];
        for (var index = 0; index < membershipCount; index++)
        {
            membership[index] = encoded.Slice(offset, 32).ToArray();
            offset += 32;
        }
        var count = encoded[offset++];
        if (count > MaximumTailHeads)
            throw new AccountDirectoryAdp1FormatException(
                "DID2 successor-tail count is invalid.");
        var exactHeads = new ReadOnlyMemory<byte>[count];
        for (var index = 0; index < count; index++)
        {
            if (encoded.Length - offset < 4)
                throw new AccountDirectoryAdp1FormatException(
                    "DID2 successor-tail head length is truncated.");
            var headLength = BinaryPrimitives.ReadUInt32BigEndian(
                encoded.Slice(offset, 4));
            offset += 4;
            if (headLength is < 12 or > 4096 ||
                headLength > encoded.Length - offset)
                throw new AccountDirectoryAdp1FormatException(
                    "DID2 successor-tail head length is invalid.");
            var exact = encoded.Slice(offset, checked((int)headLength));
            try { _ = AccountDirectoryAdh1Codec.Decode(exact); }
            catch (Exception exception) when (exception is FormatException or
                ArgumentException)
            {
                throw new AccountDirectoryAdp1FormatException(
                    $"DID2 successor-tail head is invalid: {exception.Message}");
            }
            exactHeads[index] = exact.ToArray();
            offset += checked((int)headLength);
        }
        if (offset != encoded.Length)
            throw new AccountDirectoryAdp1FormatException(
                "DID2 successor-tail contains trailing bytes.");
        return new Parsed(exactAfp.ToArray(), afp, anchor,
            exactSource.ToArray(), sourceCheckpointIndex, sourceLeafIndex,
            membership, exactHeads);
    }
}
