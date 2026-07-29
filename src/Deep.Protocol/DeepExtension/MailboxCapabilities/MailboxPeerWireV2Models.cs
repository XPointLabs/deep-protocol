namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxPeerWireV2Limits
{
    public const int RouterIdLength = 32;
    public const int ReplayNonceLength = 32;
    public const int RequestHeaderLength = 296;
    public const ulong MaximumPastAgeSeconds = 120;
    public const ulong MaximumFutureSkewSeconds = 0;
    public const ulong MaximumEpochLifetimeSeconds = 7 * 24 * 60 * 60;
    public const ulong MaximumTombstoneLifetimeSeconds = 7 * 24 * 60 * 60;
    public const ulong ReplayRetentionSeconds = 7 * 24 * 60 * 60;
    public const int MaximumReplayCollectionBatch = 1024;
    public const int MaximumReplayRecordsPerRouterPairPerEpoch =
        120 * 60 * 24 * 7;
    public const int MinimumMembershipProofLength =
        MailboxPeerReplicationLimits.MembershipProofFixedLength + 1;
    public const int MaximumMembershipProofLength =
        MailboxPeerReplicationLimits.MembershipProofFixedLength +
        MailboxPeerReplicationLimits.MaximumInclusionProofLength;
    public const int MinimumStoreRequestLength =
        RequestHeaderLength +
        MailboxClientLimits.EncryptedEnvelopeHeaderLength +
        MailboxClientLimits.MinimumCiphertextLength +
        (2 * MinimumMembershipProofLength) +
        MailboxPeerReplicationLimits.SignatureLength;
    public const int MinimumTombstoneRequestLength =
        RequestHeaderLength +
        MailboxClientLimits.DigestLength +
        (2 * MinimumMembershipProofLength) +
        MailboxPeerReplicationLimits.SignatureLength;
    public const int MaximumRequestLength =
        RequestHeaderLength +
        MailboxClientLimits.MaximumEncryptedEnvelopeLength +
        (2 * MaximumMembershipProofLength) +
        MailboxPeerReplicationLimits.SignatureLength;
    public const int MaximumTombstoneRequestLength =
        RequestHeaderLength +
        MailboxClientLimits.DigestLength +
        (2 * MaximumMembershipProofLength) +
        MailboxPeerReplicationLimits.SignatureLength;
    public const int Ed25519ReplicaResponseLength =
        MailboxReceiptV2Limits.ReplicaFixedHeaderLength +
        MailboxPeerReplicationLimits.SignatureLength;
}

public sealed record MailboxPeerWireRequestV2
{
    public required MailboxPeerReplicationOperation Operation { get; init; }
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ReadOnlyMemory<byte> SenderRouterId { get; init; }
    public required ReadOnlyMemory<byte> RecipientRouterId { get; init; }
    public required ReadOnlyMemory<byte> MembershipCommitment { get; init; }
    public required ReadOnlyMemory<byte> PlacementCommitment { get; init; }
    public required ReadOnlyMemory<byte> BlindedMailboxId { get; init; }
    public required ulong Cursor { get; init; }
    public required ulong CreatedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> ReplayNonce { get; init; }
    public required ReadOnlyMemory<byte> PayloadDigest { get; init; }
    public required ReadOnlyMemory<byte> Payload { get; init; }
    public required MailboxReplicaMembershipProof SenderMembershipProof { get; init; }
    public required MailboxReplicaMembershipProof RecipientMembershipProof { get; init; }
    public required ReadOnlyMemory<byte> Signature { get; init; }
}

public sealed record MailboxPeerWireVerificationPolicyV2
{
    public required MailboxPeerReplicationOperation ExpectedOperation { get; init; }
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ReadOnlyMemory<byte> SenderRouterId { get; init; }
    public required ReadOnlyMemory<byte> RecipientRouterId { get; init; }
    public required ReadOnlyMemory<byte> MembershipCommitment { get; init; }
    public required ReadOnlyMemory<byte> PlacementCommitment { get; init; }
    public required BlindedPlacementId PlacementId { get; init; }
    public required ulong NowUnixSeconds { get; init; }
    public required ulong EpochExpiresAtUnixSeconds { get; init; }
}

public enum MailboxPeerReplayRecordStatus : byte
{
    Pending = 1,
    Completed = 2
}

public sealed record MailboxPeerReplayClaim
{
    public required ReadOnlyMemory<byte> ScopeKey { get; init; }
    public required ReadOnlyMemory<byte> RequestDigest { get; init; }
    public required ReadOnlyMemory<byte> SenderRouterId { get; init; }
    public required ReadOnlyMemory<byte> RecipientRouterId { get; init; }
    public required ReadOnlyMemory<byte> ReplayNonce { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required MailboxPeerReplicationOperation Operation { get; init; }
    public required ulong Epoch { get; init; }
    public required ulong CreatedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ulong ReservedAtUnixSeconds { get; init; }
    public required ulong EpochExpiresAtUnixSeconds { get; init; }
    public required ulong RetainUntilUnixSeconds { get; init; }
}

public sealed record MailboxPeerReplaySnapshot
{
    public required ReadOnlyMemory<byte> ScopeKey { get; init; }
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> RequestDigest { get; init; }
    public required MailboxPeerReplayRecordStatus Status { get; init; }
    public required ReadOnlyMemory<byte> CanonicalResponse { get; init; }
    public required ulong CreatedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ulong ReservedAtUnixSeconds { get; init; }
    public required ulong EpochExpiresAtUnixSeconds { get; init; }
    public required ulong RetainUntilUnixSeconds { get; init; }
}

public enum MailboxPeerReplayState
{
    NewReserved = 1,
    PendingSame = 2,
    CompletedSame = 3,
    Conflict = 4
}

public sealed record MailboxPeerReplayEvaluation
{
    public required MailboxPeerReplayState State { get; init; }
    public required ReadOnlyMemory<byte> CachedResponse { get; init; }
    public required ulong EffectiveReservedAtUnixSeconds { get; init; }
}

/// <summary>
/// Implementations must atomically partition by <see cref="MailboxPeerReplayClaim.ScopeKey"/>,
/// persist the pending reservation before storage work, and retain pending state across crashes.
/// The response may be completed only after the Store or Tombstone mutation is durable.
/// A sender/recipient/epoch partition must fail closed before exceeding
/// MailboxPeerWireV2Limits.MaximumReplayRecordsPerRouterPairPerEpoch.
/// </summary>
public interface IMailboxPeerReplayJournal
{
    MailboxPeerReplayEvaluation EvaluateAndReserve(MailboxPeerReplayClaim claim);

    /// <summary>
    /// Evaluates an already persisted replay scope without creating a reservation when the
    /// scope is absent. This permits an exact retry to outlive the admission freshness window
    /// without allowing an unknown stale request to consume replay capacity.
    /// </summary>
    MailboxPeerReplayEvaluation? EvaluateExisting(MailboxPeerReplayClaim claim);

    void CompleteAtomically(
        MailboxPeerReplayClaim claim,
        ReadOnlyMemory<byte> canonicalMrr2Response);

    /// <summary>
    /// Deletes at most <paramref name="maximumRecords"/> snapshots for which
    /// MailboxPeerReplayStateMachine.IsCollectable returns true. Implementations must use a
    /// bounded transaction and return the number removed.
    /// </summary>
    int CollectExpired(ulong nowUnixSeconds, int maximumRecords);
}

public enum MailboxPeerReplayDisposition
{
    NewReserved = 1,
    InFlight = 2,
    IdempotentCompleted = 3
}

public enum MailboxPeerWireResponseReplicaV2 : byte
{
    Sender = 1,
    Recipient = 2
}

public sealed record VerifiedMailboxPeerWireRequestV2
{
    public required MailboxPeerWireRequestV2 Request { get; init; }
    public required MailboxEncryptedEnvelope? Envelope { get; init; }
    public required MailboxPeerReplayClaim ReplayClaim { get; init; }
    public required MailboxPeerReplayDisposition ReplayDisposition { get; init; }
    public required ReadOnlyMemory<byte> CachedResponse { get; init; }
}
