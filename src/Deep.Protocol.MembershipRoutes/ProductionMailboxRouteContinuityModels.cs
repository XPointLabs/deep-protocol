namespace Deep.Protocol.DeepExtension.MailboxTopology;

public static class ProductionMailboxRouteContinuityConstants
{
    public const byte Version = 1;
    public const int NetworkIdLength = 16;
    public const int DelegationSerialLength = 16;
    public const int HashLength = 32;
    public const int Ed25519PublicKeyLength = 32;
    public const int Ed25519SignatureLength = 64;
    public const int CanonicalDelegationLength = 552;
    public const int CanonicalDelegationAcceptanceLength = 320;
    public const int CanonicalRevocationLength = 224;
    public const int CanonicalRevocationCheckpointLength = 320;
    public const int CanonicalRouteOriginLkgLength = 224;
    public const int CanonicalRouteHistoryCheckpointLength = 464;
    public const ulong MaximumDelegationLifetimeSeconds = 365UL * 24 * 60 * 60;
    public const ulong DefaultDelegationLifetimeSeconds = 30UL * 24 * 60 * 60;
    public const ulong MaximumCheckpointLifetimeSeconds = 24UL * 60 * 60;
    public const ulong MaximumAuthorityGenerationAdvance = 512;
    public const ulong MaximumActivationSequenceCount = 512;
    public const ulong MaximumHistoryBatchCount = 32;
    public const ulong MaximumHistoryRouteLinkCount = 512;
    public const ulong MaximumHistoryPayloadBytes = 268_435_456;
    public const int MaximumClockSkewSeconds = 300;
}

public enum ProductionMailboxRouteAuthorizationKind : byte
{
    None = 0,
    OwnerPRA2 = 1,
    DelegatedRCA1 = 2
}

public enum ProductionMailboxRouteContinuityCapability : byte
{
    RouteContinuityOnly = 1
}

public enum ProductionMailboxRouteContinuityRevocationReason : byte
{
    OwnerRevoked = 1,
    OwnerKeyRotated = 2,
    RouteReset = 3
}

public enum ProductionMailboxRouteRevocationStatus : byte
{
    Active = 1,
    Revoked = 2
}

public enum ProductionMailboxRouteContinuityError
{
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    ReservedFieldNotZero,
    InvalidField,
    InvalidValidityWindow,
    InvalidAuthorizationKind,
    NonCanonical
}

public sealed class ProductionMailboxRouteContinuityException(
    ProductionMailboxRouteContinuityError error,
    string message) : Exception(message)
{
    public ProductionMailboxRouteContinuityError Error { get; } = error;
}

/// <summary>RCD1 owner delegation of only the bounded, unchanged route-continuity capability.</summary>
public sealed record ProductionMailboxRouteContinuityDelegation
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ReadOnlyMemory<byte> PinnedMrXPublicKeySha256 { get; init; }
    public required ReadOnlyMemory<byte> RouteDomainHash { get; init; }
    public required ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey { get; init; }
    public required ReadOnlyMemory<byte> BlindedMailboxId { get; init; }
    public required ReadOnlyMemory<byte> BlindedPlacementId { get; init; }
    public required ReadOnlyMemory<byte> SelectionInputCommitment { get; init; }
    public required ulong AnchorAuthorityGeneration { get; init; }
    public required ReadOnlyMemory<byte> AnchorCanonicalAuthorityHash { get; init; }
    public required ReadOnlyMemory<byte> AnchorCanonicalRouteCertificateHash { get; init; }
    public required ProductionMailboxRouteAuthorizationKind AnchorAuthorizationKind { get; init; }
    public required ReadOnlyMemory<byte> AnchorCanonicalRouteAuthorizationHash { get; init; }
    public required ulong AnchorRouteAuthorizationSequence { get; init; }
    public required ReadOnlyMemory<byte> PreDelegationRouteOriginLkgHash { get; init; }
    public required ulong RouteVerifiedAtUnixSeconds { get; init; }
    public required ProductionMailboxRouteContinuityCapability Capability { get; init; }
    public required ReadOnlyMemory<byte> DelegationSerial { get; init; }
    public required ulong DelegationSequence { get; init; }
    public required ReadOnlyMemory<byte> PreviousCanonicalDelegationHash { get; init; }
    public required ulong MaximumAuthorityGeneration { get; init; }
    public required ulong FirstActivationSequence { get; init; }
    public required ulong LastActivationSequence { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong NotBeforeUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> OwnerSignature { get; init; }
}

/// <summary>RDA1 immutable receipt proving live old-issuer acceptance of an exact RCD1.</summary>
public sealed record ProductionMailboxRouteDelegationAcceptance
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ReadOnlyMemory<byte> RouteDomainHash { get; init; }
    public required ReadOnlyMemory<byte> CanonicalDelegationHash { get; init; }
    public required ulong AnchorAuthorityGeneration { get; init; }
    public required ReadOnlyMemory<byte> AnchorCanonicalAuthorityHash { get; init; }
    public required ReadOnlyMemory<byte> AnchorCanonicalRouteCertificateHash { get; init; }
    public required ProductionMailboxRouteAuthorizationKind AnchorAuthorizationKind { get; init; }
    public required ReadOnlyMemory<byte> AnchorCanonicalRouteAuthorizationHash { get; init; }
    public required ulong AnchorRouteAuthorizationSequence { get; init; }
    public required ReadOnlyMemory<byte> PreDelegationRouteOriginLkgHash { get; init; }
    public required ulong RouteVerifiedAtUnixSeconds { get; init; }
    public required ulong AcceptedAtUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> AnchorIssuerSignature { get; init; }
}

/// <summary>RCR1 owner-signed terminal revocation of one exact route-continuity delegation.</summary>
public sealed record ProductionMailboxRouteContinuityRevocation
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ReadOnlyMemory<byte> RouteDomainHash { get; init; }
    public required ReadOnlyMemory<byte> TargetDelegationSerial { get; init; }
    public required ReadOnlyMemory<byte> TargetCanonicalDelegationHash { get; init; }
    public required ulong RevocationGeneration { get; init; }
    public required ReadOnlyMemory<byte> PreviousCanonicalRevocationHash { get; init; }
    public required ulong RevokedAtUnixSeconds { get; init; }
    public required ProductionMailboxRouteContinuityRevocationReason Reason { get; init; }
    public required ReadOnlyMemory<byte> OwnerSignature { get; init; }
}

/// <summary>RCH1 short-lived current-issuer checkpoint of the exact owner revocation state.</summary>
public sealed record ProductionMailboxRouteRevocationCheckpoint
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ReadOnlyMemory<byte> RouteDomainHash { get; init; }
    public required ulong CurrentAuthorityGeneration { get; init; }
    public required ReadOnlyMemory<byte> CurrentCanonicalAuthorityHash { get; init; }
    public required ReadOnlyMemory<byte> CurrentIssuerEd25519PublicKey { get; init; }
    public required ulong CurrentOwnerRevocationGeneration { get; init; }
    public required ReadOnlyMemory<byte> CurrentOwnerRevocationHeadHash { get; init; }
    public required ReadOnlyMemory<byte> TransitionSalt { get; init; }
    public required ReadOnlyMemory<byte> ContinuityTransitionCommitment { get; init; }
    public required ProductionMailboxRouteRevocationStatus Status { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> CurrentIssuerSignature { get; init; }
}

/// <summary>Canonical ROL1 durable route-origin transcript. It is not a caller-forgeable capability.</summary>
internal sealed record ProductionMailboxRouteOriginLkg
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ReadOnlyMemory<byte> RouteDomainHash { get; init; }
    public required ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; init; }
    public required ReadOnlyMemory<byte> CanonicalAuthorizationHash { get; init; }
    public required ulong AuthorizationSequence { get; init; }
    public required ReadOnlyMemory<byte> CanonicalDelegationHash { get; init; }
    public required ReadOnlyMemory<byte> CanonicalDelegationAcceptanceHash { get; init; }
    public required ulong OwnerRevocationGeneration { get; init; }
    public required ReadOnlyMemory<byte> OwnerRevocationHeadHash { get; init; }
    public required ulong RouteVerifiedAtUnixSeconds { get; init; }
    public required ulong LocalCommitGeneration { get; init; }
}

/// <summary>Canonical RHC1 resumable history state retained only behind the history verifier.</summary>
internal sealed record ProductionMailboxRouteHistoryCheckpoint
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ReadOnlyMemory<byte> RouteDomainHash { get; init; }
    public required ReadOnlyMemory<byte> DelegationHistoryBinding { get; init; }
    public required ProductionMailboxRouteAuthorizationKind CurrentAuthorizationKind { get; init; }
    public required ReadOnlyMemory<byte> CurrentCanonicalAuthorizationHash { get; init; }
    public required ulong CurrentAuthorizationSequence { get; init; }
    public required ulong OwnerRevocationGeneration { get; init; }
    public required ReadOnlyMemory<byte> OwnerRevocationHeadHash { get; init; }
    public required ReadOnlyMemory<byte> CurrentRouteOriginLkgHash { get; init; }
    public required ulong RouteVerifiedAtUnixSeconds { get; init; }
    public required ulong CurrentLocalCommitGeneration { get; init; }
    public required ReadOnlyMemory<byte> PinnedMrXPublicKeySha256 { get; init; }
    public required ulong CurrentAuthorityGeneration { get; init; }
    public required ReadOnlyMemory<byte> CurrentCanonicalAuthorityHash { get; init; }
    public required ulong CurrentRevocationGeneration { get; init; }
    public required ReadOnlyMemory<byte> CurrentRevocationHeadHash { get; init; }
    public required ReadOnlyMemory<byte> CurrentRevocationSnapshotHash { get; init; }
    public required ulong LastCommittedBatchSequence { get; init; }
    public required ulong CumulativeCommittedBatchCount { get; init; }
    public required ulong CumulativeVerifiedRouteLinkCount { get; init; }
    public required ulong CumulativeCanonicalPayloadBytes { get; init; }
    public required ReadOnlyMemory<byte> HistoryTranscriptHead { get; init; }
    public required ReadOnlyMemory<byte> LastCommittedBatchHash { get; init; }
}

internal static class ProductionMailboxRouteContinuityCopy
{
    public static ProductionMailboxRouteContinuityDelegation Clone(
        ProductionMailboxRouteContinuityDelegation value) => new()
    {
        NetworkId = value.NetworkId.ToArray(),
        PinnedMrXPublicKeySha256 = value.PinnedMrXPublicKeySha256.ToArray(),
        RouteDomainHash = value.RouteDomainHash.ToArray(),
        MailboxOwnerEd25519PublicKey = value.MailboxOwnerEd25519PublicKey.ToArray(),
        BlindedMailboxId = value.BlindedMailboxId.ToArray(),
        BlindedPlacementId = value.BlindedPlacementId.ToArray(),
        SelectionInputCommitment = value.SelectionInputCommitment.ToArray(),
        AnchorAuthorityGeneration = value.AnchorAuthorityGeneration,
        AnchorCanonicalAuthorityHash = value.AnchorCanonicalAuthorityHash.ToArray(),
        AnchorCanonicalRouteCertificateHash = value.AnchorCanonicalRouteCertificateHash.ToArray(),
        AnchorAuthorizationKind = value.AnchorAuthorizationKind,
        AnchorCanonicalRouteAuthorizationHash = value.AnchorCanonicalRouteAuthorizationHash.ToArray(),
        AnchorRouteAuthorizationSequence = value.AnchorRouteAuthorizationSequence,
        PreDelegationRouteOriginLkgHash = value.PreDelegationRouteOriginLkgHash.ToArray(),
        RouteVerifiedAtUnixSeconds = value.RouteVerifiedAtUnixSeconds,
        Capability = value.Capability,
        DelegationSerial = value.DelegationSerial.ToArray(),
        DelegationSequence = value.DelegationSequence,
        PreviousCanonicalDelegationHash = value.PreviousCanonicalDelegationHash.ToArray(),
        MaximumAuthorityGeneration = value.MaximumAuthorityGeneration,
        FirstActivationSequence = value.FirstActivationSequence,
        LastActivationSequence = value.LastActivationSequence,
        IssuedAtUnixSeconds = value.IssuedAtUnixSeconds,
        NotBeforeUnixSeconds = value.NotBeforeUnixSeconds,
        ExpiresAtUnixSeconds = value.ExpiresAtUnixSeconds,
        OwnerSignature = value.OwnerSignature.ToArray()
    };

    public static ProductionMailboxRouteDelegationAcceptance Clone(
        ProductionMailboxRouteDelegationAcceptance value) => new()
    {
        NetworkId = value.NetworkId.ToArray(),
        RouteDomainHash = value.RouteDomainHash.ToArray(),
        CanonicalDelegationHash = value.CanonicalDelegationHash.ToArray(),
        AnchorAuthorityGeneration = value.AnchorAuthorityGeneration,
        AnchorCanonicalAuthorityHash = value.AnchorCanonicalAuthorityHash.ToArray(),
        AnchorCanonicalRouteCertificateHash = value.AnchorCanonicalRouteCertificateHash.ToArray(),
        AnchorAuthorizationKind = value.AnchorAuthorizationKind,
        AnchorCanonicalRouteAuthorizationHash = value.AnchorCanonicalRouteAuthorizationHash.ToArray(),
        AnchorRouteAuthorizationSequence = value.AnchorRouteAuthorizationSequence,
        PreDelegationRouteOriginLkgHash = value.PreDelegationRouteOriginLkgHash.ToArray(),
        RouteVerifiedAtUnixSeconds = value.RouteVerifiedAtUnixSeconds,
        AcceptedAtUnixSeconds = value.AcceptedAtUnixSeconds,
        AnchorIssuerSignature = value.AnchorIssuerSignature.ToArray()
    };

    public static ProductionMailboxRouteContinuityRevocation Clone(
        ProductionMailboxRouteContinuityRevocation value) => new()
    {
        NetworkId = value.NetworkId.ToArray(),
        RouteDomainHash = value.RouteDomainHash.ToArray(),
        TargetDelegationSerial = value.TargetDelegationSerial.ToArray(),
        TargetCanonicalDelegationHash = value.TargetCanonicalDelegationHash.ToArray(),
        RevocationGeneration = value.RevocationGeneration,
        PreviousCanonicalRevocationHash = value.PreviousCanonicalRevocationHash.ToArray(),
        RevokedAtUnixSeconds = value.RevokedAtUnixSeconds,
        Reason = value.Reason,
        OwnerSignature = value.OwnerSignature.ToArray()
    };

    public static ProductionMailboxRouteRevocationCheckpoint Clone(
        ProductionMailboxRouteRevocationCheckpoint value) => new()
    {
        NetworkId = value.NetworkId.ToArray(),
        RouteDomainHash = value.RouteDomainHash.ToArray(),
        CurrentAuthorityGeneration = value.CurrentAuthorityGeneration,
        CurrentCanonicalAuthorityHash = value.CurrentCanonicalAuthorityHash.ToArray(),
        CurrentIssuerEd25519PublicKey = value.CurrentIssuerEd25519PublicKey.ToArray(),
        CurrentOwnerRevocationGeneration = value.CurrentOwnerRevocationGeneration,
        CurrentOwnerRevocationHeadHash = value.CurrentOwnerRevocationHeadHash.ToArray(),
        TransitionSalt = value.TransitionSalt.ToArray(),
        ContinuityTransitionCommitment = value.ContinuityTransitionCommitment.ToArray(),
        Status = value.Status,
        IssuedAtUnixSeconds = value.IssuedAtUnixSeconds,
        ExpiresAtUnixSeconds = value.ExpiresAtUnixSeconds,
        CurrentIssuerSignature = value.CurrentIssuerSignature.ToArray()
    };

    public static ProductionMailboxRouteOriginLkg Clone(ProductionMailboxRouteOriginLkg value) => new()
    {
        NetworkId = value.NetworkId.ToArray(),
        RouteDomainHash = value.RouteDomainHash.ToArray(),
        AuthorizationKind = value.AuthorizationKind,
        CanonicalAuthorizationHash = value.CanonicalAuthorizationHash.ToArray(),
        AuthorizationSequence = value.AuthorizationSequence,
        CanonicalDelegationHash = value.CanonicalDelegationHash.ToArray(),
        CanonicalDelegationAcceptanceHash = value.CanonicalDelegationAcceptanceHash.ToArray(),
        OwnerRevocationGeneration = value.OwnerRevocationGeneration,
        OwnerRevocationHeadHash = value.OwnerRevocationHeadHash.ToArray(),
        RouteVerifiedAtUnixSeconds = value.RouteVerifiedAtUnixSeconds,
        LocalCommitGeneration = value.LocalCommitGeneration
    };

    public static ProductionMailboxRouteHistoryCheckpoint Clone(
        ProductionMailboxRouteHistoryCheckpoint value) => new()
    {
        NetworkId = value.NetworkId.ToArray(),
        RouteDomainHash = value.RouteDomainHash.ToArray(),
        DelegationHistoryBinding = value.DelegationHistoryBinding.ToArray(),
        CurrentAuthorizationKind = value.CurrentAuthorizationKind,
        CurrentCanonicalAuthorizationHash = value.CurrentCanonicalAuthorizationHash.ToArray(),
        CurrentAuthorizationSequence = value.CurrentAuthorizationSequence,
        OwnerRevocationGeneration = value.OwnerRevocationGeneration,
        OwnerRevocationHeadHash = value.OwnerRevocationHeadHash.ToArray(),
        CurrentRouteOriginLkgHash = value.CurrentRouteOriginLkgHash.ToArray(),
        RouteVerifiedAtUnixSeconds = value.RouteVerifiedAtUnixSeconds,
        CurrentLocalCommitGeneration = value.CurrentLocalCommitGeneration,
        PinnedMrXPublicKeySha256 = value.PinnedMrXPublicKeySha256.ToArray(),
        CurrentAuthorityGeneration = value.CurrentAuthorityGeneration,
        CurrentCanonicalAuthorityHash = value.CurrentCanonicalAuthorityHash.ToArray(),
        CurrentRevocationGeneration = value.CurrentRevocationGeneration,
        CurrentRevocationHeadHash = value.CurrentRevocationHeadHash.ToArray(),
        CurrentRevocationSnapshotHash = value.CurrentRevocationSnapshotHash.ToArray(),
        LastCommittedBatchSequence = value.LastCommittedBatchSequence,
        CumulativeCommittedBatchCount = value.CumulativeCommittedBatchCount,
        CumulativeVerifiedRouteLinkCount = value.CumulativeVerifiedRouteLinkCount,
        CumulativeCanonicalPayloadBytes = value.CumulativeCanonicalPayloadBytes,
        HistoryTranscriptHead = value.HistoryTranscriptHead.ToArray(),
        LastCommittedBatchHash = value.LastCommittedBatchHash.ToArray()
    };
}
