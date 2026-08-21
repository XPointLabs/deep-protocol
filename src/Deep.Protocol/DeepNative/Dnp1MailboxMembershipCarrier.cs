using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.DeepNative;

internal static class MailboxMembershipCarrier
{
    internal const int FixedOuterLength = 120;
    internal const int MinimumRip2Length = 573;
    internal const int MaximumRip2Length = 957;

    internal static MailboxReplicaMembershipProof DecodeOwned(ReadOnlySpan<byte> canonicalMailboxMip1)
    {
        Preflight(canonicalMailboxMip1);
        var owned = canonicalMailboxMip1.ToArray();
        Preflight(owned);
        return MailboxPeerReplicationCodec.DecodeMembershipProof(owned);
    }

    internal static void Preflight(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is < FixedOuterLength + MinimumRip2Length or
            > FixedOuterLength + MaximumRip2Length)
            Invalid("The native mailbox MIP1 length is invalid.");
        if (!encoded[..4].SequenceEqual("MIP1"u8) || encoded[4] != 1 ||
            encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(114, 6).IndexOfAnyExcept((byte)0) >= 0)
            Invalid("The native mailbox MIP1 header is invalid.");
        var innerLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(112, 2));
        if (innerLength is < MinimumRip2Length or > MaximumRip2Length ||
            encoded.Length != FixedOuterLength + innerLength)
            Invalid("The native mailbox MIP1 inner length is invalid.");
        var inner = encoded[FixedOuterLength..];
        if (!inner[..4].SequenceEqual("RIP2"u8))
            Invalid("Only RIP2 is accepted by the native mailbox MIP1 boundary.");
        CanonicalGrammar.Preflight(inner, RecordDefinitions.Rip2);
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
