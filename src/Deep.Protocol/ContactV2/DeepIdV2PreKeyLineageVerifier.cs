using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Checks the exact XPI1 predecessor link before a replica admits a new
/// inventory epoch. The predecessor must come from the replica's own durable,
/// already-authorized state; caller-supplied predecessor bytes are not authority.
/// </summary>
public static class DeepIdV2PreKeyLineageVerifier
{
    public static bool RuntimeActivation => false;

    public static void VerifySuccessor(ParsedXpi1V2 candidate,
        ParsedXpi1V2? durablePredecessor)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        var epoch = U64(candidate.Field(7).Span);
        if (durablePredecessor is null)
        {
            if (epoch != 1 || !IsZero(candidate.Field(8).Span))
                Reject("The first DID2 inventory must start at epoch one without a predecessor.");
            return;
        }

        var previousEpoch = U64(durablePredecessor.Field(7).Span);
        if (previousEpoch == 14 || epoch != previousEpoch + 1 ||
            !Fixed(candidate.Field(8).Span,
                durablePredecessor.ExactHash.Span))
            Reject("The DID2 inventory does not extend the exact durable predecessor.");

        // An XPS1 service generation has one account-owned responder device.
        // A new DMD1/DRS1 head may be witnessed by a successor, but the
        // service's identity and its signed policy cannot silently change.
        foreach (var tag in new[] { 1, 2, 3, 4, 5, 6 })
            if (!Fixed(candidate.Field(tag).Span,
                    durablePredecessor.Field(tag).Span))
                Reject("The DID2 inventory successor changed its service identity.");
    }

    private static ulong U64(ReadOnlySpan<byte> bytes) =>
        BinaryPrimitives.ReadUInt64BigEndian(bytes);

    private static bool IsZero(ReadOnlySpan<byte> bytes) =>
        bytes.IndexOfAnyExcept((byte)0) < 0;

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static void Reject(string message) => throw ApplicationCoreFormat.Error(
        ApplicationCoreValidationStage.CryptographicVerification,
        ApplicationCoreRejection.InvalidLineage, message);
}
