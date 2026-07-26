using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxCapabilityReplayStateMachine
{
    public static byte[] ComputeScopeKey(MailboxCapabilityAtomicReplayClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        ValidateClaim(claim);
        Span<byte> fixedFields = stackalloc byte[32 + 16 + 8 + 8 + 1];
        claim.IssuerPublicKey.Span.CopyTo(fixedFields);
        claim.Serial.Span.CopyTo(fixedFields[32..]);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
            fixedFields[48..],
            claim.Epoch);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
            fixedFields[56..],
            claim.Generation);
        fixedFields[64] = (byte)claim.Operation;
        return SHA256.HashData([
            .. "deep.mailbox.replay-scope.v2"u8,
            .. fixedFields
        ]);
    }

    public static (
        MailboxCapabilityAtomicReplayEvaluation Evaluation,
        MailboxCapabilityReplaySnapshot? NextSnapshot) EvaluateAndReserve(
        MailboxCapabilityReplaySnapshot? current,
        MailboxCapabilityAtomicReplayClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        ValidateClaim(claim);
        if (current is null || claim.ReplayCounter > current.HighestCounter)
        {
            return (
                new MailboxCapabilityAtomicReplayEvaluation
                {
                    State = MailboxCapabilityAtomicReplayState.NewReserved,
                    CachedOutcome = ReadOnlyMemory<byte>.Empty
                },
                new MailboxCapabilityReplaySnapshot
                {
                    HighestCounter = claim.ReplayCounter,
                    ClaimDigest = claim.ClaimDigest.ToArray(),
                    Status = MailboxCapabilityReplayRecordStatus.Pending,
                    CanonicalOutcome = ReadOnlyMemory<byte>.Empty
                });
        }
        if (claim.ReplayCounter < current.HighestCounter)
            return (Evaluation(MailboxCapabilityAtomicReplayState.StaleReplay), current);
        if (!CryptographicOperations.FixedTimeEquals(
                claim.ClaimDigest.Span,
                current.ClaimDigest.Span))
            return (Evaluation(MailboxCapabilityAtomicReplayState.Conflict), current);
        return current.Status switch
        {
            MailboxCapabilityReplayRecordStatus.Pending when current.CanonicalOutcome.IsEmpty =>
                (Evaluation(MailboxCapabilityAtomicReplayState.PendingSame), current),
            MailboxCapabilityReplayRecordStatus.Completed
                when current.CanonicalOutcome.Length is
                    > 0 and <= MailboxAuthenticatedCapabilityLimits.MaximumCachedOutcomeLength =>
                (new MailboxCapabilityAtomicReplayEvaluation
                {
                    State = MailboxCapabilityAtomicReplayState.CompletedSame,
                    CachedOutcome = current.CanonicalOutcome.ToArray()
                }, current),
            _ => throw new MailboxAuthenticatedCapabilityException(
                MailboxAuthenticatedCapabilityError.InvalidReplayEvaluation,
                "Persisted replay snapshot is inconsistent.")
        };
    }

    public static MailboxCapabilityReplaySnapshot Complete(
        MailboxCapabilityReplaySnapshot current,
        MailboxCapabilityAtomicReplayClaim claim,
        ReadOnlySpan<byte> canonicalOutcome)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(claim);
        ValidateClaim(claim);
        if (current.Status != MailboxCapabilityReplayRecordStatus.Pending ||
            current.HighestCounter != claim.ReplayCounter ||
            !CryptographicOperations.FixedTimeEquals(current.ClaimDigest.Span, claim.ClaimDigest.Span) ||
            canonicalOutcome.Length is 0 or > MailboxAuthenticatedCapabilityLimits.MaximumCachedOutcomeLength)
            throw new MailboxAuthenticatedCapabilityException(
                MailboxAuthenticatedCapabilityError.InvalidReplayEvaluation,
                "Only the exact pending replay claim can be completed with a bounded outcome.");
        return current with
        {
            Status = MailboxCapabilityReplayRecordStatus.Completed,
            CanonicalOutcome = canonicalOutcome.ToArray()
        };
    }

    private static MailboxCapabilityAtomicReplayEvaluation Evaluation(
        MailboxCapabilityAtomicReplayState state) =>
        new()
        {
            State = state,
            CachedOutcome = ReadOnlyMemory<byte>.Empty
        };

    private static void ValidateClaim(MailboxCapabilityAtomicReplayClaim claim)
    {
        if (claim.ClaimDigest.Length != 32 ||
            claim.IssuerPublicKey.Length != 32 ||
            claim.Serial.Length != 16 ||
            claim.OperationId.Length != 16 ||
            claim.RequestDigest.Length != 32 ||
            claim.Epoch == 0 ||
            claim.Generation == 0 ||
            claim.ReplayCounter == 0)
            throw new MailboxAuthenticatedCapabilityException(
                MailboxAuthenticatedCapabilityError.InvalidReplayEvaluation,
                "Replay claim is malformed.");
    }
}
