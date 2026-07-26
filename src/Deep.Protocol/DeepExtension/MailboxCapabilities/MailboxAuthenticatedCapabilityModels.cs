namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxAuthenticatedCapabilityLimits
{
    public const int NetworkIdLength = 16;
    public const int SerialLength = 16;
    public const int OperationIdLength = 16;
    public const int DigestLength = 32;
    public const int PublicKeyLength = 32;
    public const int SignatureLength = 64;
    public const int GrantLength = 272;
    public const int PresentationLength = 408;
    public const int MaximumCachedOutcomeLength = 64 * 1024;
}

public enum MailboxAuthenticatedOperation : byte
{
    Store = 1,
    Retrieve = 2,
    Ack = 3
}

public enum MailboxAuthenticatedCapabilityError
{
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    InvalidEnum,
    ReservedFieldNotZero,
    InvalidField,
    InvalidDomainForOperation,
    InvalidIssuerSignature,
    InvalidHolderSignature,
    UntrustedIssuer,
    Revoked,
    GenerationRejected,
    OutsideValidityWindow,
    BindingMismatch,
    ReplayRejected,
    ReplayConflict,
    InvalidReplayEvaluation
}

public sealed record MailboxAuthenticatedGrant
{
    public required MailboxCapabilityDomain Domain { get; init; }
    public required MailboxCapabilityLifecycle Lifecycle { get; init; }
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong Epoch { get; init; }
    public required ulong Generation { get; init; }
    public required ReadOnlyMemory<byte> Serial { get; init; }
    public required ulong NotBeforeUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ulong OverlapUntilUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> PlacementCommitment { get; init; }
    public required ReadOnlyMemory<byte> MembershipCommitment { get; init; }
    public required ReadOnlyMemory<byte> IssuerPublicKey { get; init; }
    public required ReadOnlyMemory<byte> HolderPublicKey { get; init; }
    public required ReadOnlyMemory<byte> IssuerSignature { get; init; }
}

public sealed record MailboxAuthenticatedRequestBinding
{
    public required MailboxAuthenticatedOperation Operation { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ReadOnlyMemory<byte> RequestDigest { get; init; }
}

public sealed record MailboxAuthenticatedPresentation
{
    public required MailboxAuthenticatedOperation Operation { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ulong ReplayCounter { get; init; }
    public required ReadOnlyMemory<byte> RequestDigest { get; init; }
    public required MailboxAuthenticatedGrant Grant { get; init; }
    public required ReadOnlyMemory<byte> HolderSignature { get; init; }
}

public sealed record MailboxAuthenticatedVerificationPolicy
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> PlacementCommitment { get; init; }
    public required ReadOnlyMemory<byte> MembershipCommitment { get; init; }
    public required ulong NowUnixSeconds { get; init; }
    public required ulong MinimumGeneration { get; init; }
    public required IReadOnlyList<ReadOnlyMemory<byte>> TrustedIssuerPublicKeys { get; init; }
}

public sealed record MailboxCapabilityRevocationQuery
{
    public required ReadOnlyMemory<byte> IssuerPublicKey { get; init; }
    public required ReadOnlyMemory<byte> Serial { get; init; }
    public required MailboxCapabilityDomain Domain { get; init; }
    public required ulong Generation { get; init; }
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> MembershipCommitment { get; init; }
}

public interface IMailboxCapabilityRevocationSource
{
    bool IsRevoked(MailboxCapabilityRevocationQuery query);
}

public sealed record MailboxCapabilityAtomicReplayClaim
{
    public required ReadOnlyMemory<byte> ClaimDigest { get; init; }
    public required ReadOnlyMemory<byte> IssuerPublicKey { get; init; }
    public required ReadOnlyMemory<byte> Serial { get; init; }
    public required MailboxAuthenticatedOperation Operation { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ulong ReplayCounter { get; init; }
    public required ReadOnlyMemory<byte> RequestDigest { get; init; }
}

public enum MailboxCapabilityAtomicReplayState
{
    NewReserved = 1,
    PendingSame = 2,
    CompletedSame = 3,
    StaleReplay = 4,
    Conflict = 5
}

public sealed record MailboxCapabilityAtomicReplayEvaluation
{
    public required MailboxCapabilityAtomicReplayState State { get; init; }
    public required ReadOnlyMemory<byte> CachedOutcome { get; init; }
}

/// <summary>
/// Host implementations must make each method durable and atomic. EvaluateAndReserve must never
/// return NewReserved twice for the same issuer/serial/operation/replay tuple, including after a
/// crash. An unfinished reservation remains PendingSame until explicit host recovery.
/// </summary>
public interface IMailboxCapabilityReplayJournal
{
    MailboxCapabilityAtomicReplayEvaluation EvaluateAndReserve(
        MailboxCapabilityAtomicReplayClaim claim);

    void CompleteAtomically(
        MailboxCapabilityAtomicReplayClaim claim,
        ReadOnlyMemory<byte> canonicalOutcome);
}

public enum MailboxAuthenticatedReplayDisposition
{
    NewReserved = 1,
    InFlight = 2,
    IdempotentCompleted = 3
}

public sealed record VerifiedMailboxAuthenticatedCapability
{
    public required MailboxAuthenticatedGrant Grant { get; init; }
    public required MailboxAuthenticatedRequestBinding Binding { get; init; }
    public required MailboxAuthenticatedReplayDisposition ReplayDisposition { get; init; }
    public required MailboxCapabilityAtomicReplayClaim ReplayClaim { get; init; }
    public required ReadOnlyMemory<byte> CachedOutcome { get; init; }
}

public interface IMailboxAuthenticatedCapabilityCrypto
{
    bool VerifyIssuer(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature);

    bool VerifyHolder(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature);

    byte[] Digest(ReadOnlySpan<byte> canonicalBytes);
}

public sealed class MailboxAuthenticatedCapabilityException(
    MailboxAuthenticatedCapabilityError error,
    string message) : Exception(message)
{
    public MailboxAuthenticatedCapabilityError Error { get; } = error;
}

