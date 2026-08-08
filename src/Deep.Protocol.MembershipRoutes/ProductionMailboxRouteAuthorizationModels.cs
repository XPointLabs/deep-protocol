namespace Deep.Protocol.DeepExtension.MailboxTopology;

public static class ProductionMailboxRouteAuthorizationConstants
{
    public const byte Version = 1;
    public const byte AdvertisementVersion = 2;
    public const int HashLength = 32;
    public const int NetworkIdLength = 16;
    public const int Ed25519PublicKeyLength = 32;
    public const int Ed25519SignatureLength = 64;
    public const int CanonicalTransitionContextLength = 408;
    public const int CanonicalContinuityActivationLength = 496;
    public const int CanonicalAdvertisementV2Length = 448;
    public const ulong MaximumLifetimeSeconds = 24UL * 60 * 60;
}

public enum ProductionMailboxRouteAuthorizationError
{
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    ReservedFieldNotZero,
    InvalidField,
    InvalidValidityWindow,
    InvalidTransitionMode,
    InvalidAuthorizationKind,
    NonCanonical
}

public sealed class ProductionMailboxRouteAuthorizationException(
    ProductionMailboxRouteAuthorizationError error,
    string message) : Exception(message)
{
    public ProductionMailboxRouteAuthorizationError Error { get; } = error;
}

/// <summary>RTC1 canonical unsigned context jointly bound by route and selection authorization.</summary>
public sealed record ProductionMailboxRouteTransitionContext
{
    public required ProductionMailboxSelectionSuccessorMode Mode { get; init; }
    public required ProductionMailboxRouteAuthorizationKind PredecessorAuthorizationKind { get; init; }
    public required ProductionMailboxRouteAuthorizationKind NewAuthorizationKind { get; init; }
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ReadOnlyMemory<byte> RouteDomainHash { get; init; }
    public required ReadOnlyMemory<byte> OldCanonicalSelectionHash { get; init; }
    public required ReadOnlyMemory<byte> NewCanonicalSelectionHash { get; init; }
    public required ReadOnlyMemory<byte> PredecessorCanonicalRouteAuthorizationHash { get; init; }
    public required ulong PredecessorRouteAuthorizationSequence { get; init; }
    public required ReadOnlyMemory<byte> FreshCanonicalRouteCertificateHash { get; init; }
    public required ulong NewRouteAuthorizationSequence { get; init; }
    public required ReadOnlyMemory<byte> TransitionSalt { get; init; }
    public required ReadOnlyMemory<byte> ContinuityTransitionCommitment { get; init; }
    public required ReadOnlyMemory<byte> CanonicalRevocationCheckpointHash { get; init; }
    public required ReadOnlyMemory<byte> CurrentCanonicalAuthorityHash { get; init; }
    public required ulong CurrentAuthorityGeneration { get; init; }
    public required ReadOnlyMemory<byte> SealedOldRouteOriginLkgHash { get; init; }
    public required ulong OldRouteVerifiedAtUnixSeconds { get; init; }
    public required ulong OldLocalRouteCommitGeneration { get; init; }
    public required ulong NotBeforeUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
}

/// <summary>RCA1 delegated current-issuer activation for one exact RTC1 and fresh PRC1.</summary>
public sealed record ProductionMailboxRouteContinuityActivation
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ReadOnlyMemory<byte> RouteDomainHash { get; init; }
    public required ulong CurrentAuthorityGeneration { get; init; }
    public required ReadOnlyMemory<byte> CurrentCanonicalAuthorityHash { get; init; }
    public required ReadOnlyMemory<byte> CurrentIssuerEd25519PublicKey { get; init; }
    public required ulong CurrentRevocationGeneration { get; init; }
    public required ReadOnlyMemory<byte> CurrentRevocationHeadHash { get; init; }
    public required ReadOnlyMemory<byte> CurrentRevocationSnapshotHash { get; init; }
    public required ReadOnlyMemory<byte> TransitionSalt { get; init; }
    public required ReadOnlyMemory<byte> ContinuityTransitionCommitment { get; init; }
    public required ReadOnlyMemory<byte> CanonicalRevocationCheckpointHash { get; init; }
    public required ReadOnlyMemory<byte> FreshCanonicalRouteCertificateHash { get; init; }
    public required ReadOnlyMemory<byte> CanonicalTransitionContextHash { get; init; }
    public required ProductionMailboxRouteAuthorizationKind PredecessorAuthorizationKind { get; init; }
    public required ReadOnlyMemory<byte> PredecessorCanonicalRouteAuthorizationHash { get; init; }
    public required ulong PredecessorRouteAuthorizationSequence { get; init; }
    public required ulong ActivationSequence { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> CurrentIssuerSignature { get; init; }
}

/// <summary>PRA2 owner-online authorization sharing the tagged predecessor chain with RCA1.</summary>
public sealed record ProductionMailboxRouteAdvertisementV2
{
    public required ProductionMailboxRouteCertificate Certificate { get; init; }
    public required ProductionMailboxRouteAuthorizationKind PredecessorAuthorizationKind { get; init; }
    public required ReadOnlyMemory<byte> PredecessorCanonicalRouteAuthorizationHash { get; init; }
    public required ulong PredecessorRouteAuthorizationSequence { get; init; }
    public required ulong Sequence { get; init; }
    public required ulong PublishedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> OwnerSignature { get; init; }
}

internal static class ProductionMailboxRouteAuthorizationCopy
{
    public static ProductionMailboxRouteTransitionContext Clone(
        ProductionMailboxRouteTransitionContext value) => new()
    {
        Mode = value.Mode,
        PredecessorAuthorizationKind = value.PredecessorAuthorizationKind,
        NewAuthorizationKind = value.NewAuthorizationKind,
        NetworkId = value.NetworkId.ToArray(),
        RouteDomainHash = value.RouteDomainHash.ToArray(),
        OldCanonicalSelectionHash = value.OldCanonicalSelectionHash.ToArray(),
        NewCanonicalSelectionHash = value.NewCanonicalSelectionHash.ToArray(),
        PredecessorCanonicalRouteAuthorizationHash = value.PredecessorCanonicalRouteAuthorizationHash.ToArray(),
        PredecessorRouteAuthorizationSequence = value.PredecessorRouteAuthorizationSequence,
        FreshCanonicalRouteCertificateHash = value.FreshCanonicalRouteCertificateHash.ToArray(),
        NewRouteAuthorizationSequence = value.NewRouteAuthorizationSequence,
        TransitionSalt = value.TransitionSalt.ToArray(),
        ContinuityTransitionCommitment = value.ContinuityTransitionCommitment.ToArray(),
        CanonicalRevocationCheckpointHash = value.CanonicalRevocationCheckpointHash.ToArray(),
        CurrentCanonicalAuthorityHash = value.CurrentCanonicalAuthorityHash.ToArray(),
        CurrentAuthorityGeneration = value.CurrentAuthorityGeneration,
        SealedOldRouteOriginLkgHash = value.SealedOldRouteOriginLkgHash.ToArray(),
        OldRouteVerifiedAtUnixSeconds = value.OldRouteVerifiedAtUnixSeconds,
        OldLocalRouteCommitGeneration = value.OldLocalRouteCommitGeneration,
        NotBeforeUnixSeconds = value.NotBeforeUnixSeconds,
        ExpiresAtUnixSeconds = value.ExpiresAtUnixSeconds
    };

    public static ProductionMailboxRouteContinuityActivation Clone(
        ProductionMailboxRouteContinuityActivation value) => new()
    {
        NetworkId = value.NetworkId.ToArray(),
        RouteDomainHash = value.RouteDomainHash.ToArray(),
        CurrentAuthorityGeneration = value.CurrentAuthorityGeneration,
        CurrentCanonicalAuthorityHash = value.CurrentCanonicalAuthorityHash.ToArray(),
        CurrentIssuerEd25519PublicKey = value.CurrentIssuerEd25519PublicKey.ToArray(),
        CurrentRevocationGeneration = value.CurrentRevocationGeneration,
        CurrentRevocationHeadHash = value.CurrentRevocationHeadHash.ToArray(),
        CurrentRevocationSnapshotHash = value.CurrentRevocationSnapshotHash.ToArray(),
        TransitionSalt = value.TransitionSalt.ToArray(),
        ContinuityTransitionCommitment = value.ContinuityTransitionCommitment.ToArray(),
        CanonicalRevocationCheckpointHash = value.CanonicalRevocationCheckpointHash.ToArray(),
        FreshCanonicalRouteCertificateHash = value.FreshCanonicalRouteCertificateHash.ToArray(),
        CanonicalTransitionContextHash = value.CanonicalTransitionContextHash.ToArray(),
        PredecessorAuthorizationKind = value.PredecessorAuthorizationKind,
        PredecessorCanonicalRouteAuthorizationHash = value.PredecessorCanonicalRouteAuthorizationHash.ToArray(),
        PredecessorRouteAuthorizationSequence = value.PredecessorRouteAuthorizationSequence,
        ActivationSequence = value.ActivationSequence,
        IssuedAtUnixSeconds = value.IssuedAtUnixSeconds,
        ExpiresAtUnixSeconds = value.ExpiresAtUnixSeconds,
        CurrentIssuerSignature = value.CurrentIssuerSignature.ToArray()
    };

    public static ProductionMailboxRouteAdvertisementV2 Clone(
        ProductionMailboxRouteAdvertisementV2 value) => new()
    {
        Certificate = ProductionMailboxRouteAdvertisementCopy.Clone(value.Certificate),
        PredecessorAuthorizationKind = value.PredecessorAuthorizationKind,
        PredecessorCanonicalRouteAuthorizationHash = value.PredecessorCanonicalRouteAuthorizationHash.ToArray(),
        PredecessorRouteAuthorizationSequence = value.PredecessorRouteAuthorizationSequence,
        Sequence = value.Sequence,
        PublishedAtUnixSeconds = value.PublishedAtUnixSeconds,
        ExpiresAtUnixSeconds = value.ExpiresAtUnixSeconds,
        OwnerSignature = value.OwnerSignature.ToArray()
    };
}
