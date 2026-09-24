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
        IReadOnlyList<ReadOnlyMemory<byte>> exactTailHeads)
    {
        internal ReadOnlyMemory<byte> ExactAnchorAfp1 { get; } =
            exactAnchorAfp1.ToArray();
        internal AccountDirectoryAfp1 AnchorProof { get; } = anchorProof;
        internal AccountDirectoryAdh1 AnchorHead { get; } = anchorHead;
        internal IReadOnlyList<ReadOnlyMemory<byte>> ExactTailHeads { get; } =
            exactTailHeads.Select(static value =>
                (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
    }

    internal static byte[] Encode(ReadOnlySpan<byte> exactAnchorAfp1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactTailHeads)
    {
        ArgumentNullException.ThrowIfNull(exactTailHeads);
        if (exactAnchorAfp1.Length is < 12 or > DeepIdV2Adp1Codec.MaximumLength ||
            exactTailHeads.Count is < 1 or > MaximumTailHeads)
            throw new AccountDirectoryAdp1FormatException(
                "DID2 forward-tail framing exceeds its bounds.");
        if (exactTailHeads.Any(static value => value.Length is < 12 or > 4096))
            throw new AccountDirectoryAdp1FormatException(
                "DID2 successor-tail head exceeds its bounds.");
        var length = checked(4 + exactAnchorAfp1.Length + 1 +
            exactTailHeads.Sum(static value => 4 + value.Length));
        if (length > DeepIdV2Adp1Codec.MaximumLength)
            throw new AccountDirectoryAdp1FormatException(
                "DID2 forward-tail framing exceeds ADP1 V2.");
        var output = new byte[length];
        BinaryPrimitives.WriteUInt32BigEndian(output, (uint)exactAnchorAfp1.Length);
        exactAnchorAfp1.CopyTo(output.AsSpan(4));
        var offset = 4 + exactAnchorAfp1.Length;
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
        if (encoded.Length is < 17 or > DeepIdV2Adp1Codec.MaximumLength)
            throw new AccountDirectoryAdp1FormatException(
                "DID2 forward-tail framing length is invalid.");
        var afpLength = BinaryPrimitives.ReadUInt32BigEndian(encoded);
        if (afpLength < 12 || afpLength > encoded.Length - 5)
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
        var count = encoded[offset++];
        if (count is < 1 or > MaximumTailHeads)
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
        return new Parsed(exactAfp.ToArray(), afp, anchor, exactHeads);
    }
}
