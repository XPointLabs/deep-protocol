using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

public static class ProductionMailboxSelectionSuccessorConstants
{
    public const string Schema = "production-mailbox-selection-successor.v1";
    public const byte Version = 1;
    public const int HashLength = 32;
    public const int NetworkIdLength = 16;
    public const int Ed25519PublicKeyLength = 32;
    public const int Ed25519SignatureLength = 64;
    public const int FixedCoreLength = 416;
    public const int SignatureBytes = 128;
    public const int MaximumArtifactBytes = FixedCoreLength +
        ProductionMailboxAuthorityConstants.MaximumArtifactBytes +
        (2 * ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes) + SignatureBytes;
    public const ulong MaximumLifetimeSeconds = 86_400;
    public const ulong MaximumOfflineCheckpointAgeSeconds = 365UL * 24 * 60 * 60;
    public const int MaximumClockSkewSeconds = 300;
}

public enum ProductionMailboxSelectionSuccessorMode : byte
{
    DirectPromotion = 1,
    OfflineCheckpoint = 2
}

public enum ProductionMailboxSelectionSuccessorError
{
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    ReservedFieldNotZero,
    InvalidField,
    InvalidValidityWindow,
    InvalidTransitionMode,
    NonCanonical,
    NetworkMismatch,
    OwnerMismatch,
    RouteMismatch,
    AuthorityNotSuccessor,
    TopologyNotSuccessor,
    CheckpointAnchorExpired,
    EpochMismatch,
    SelectionMismatch,
    ReplicaRouteMismatch,
    InvalidOldIssuerSignature,
    InvalidNewIssuerSignature,
    NotYetValid,
    Expired
}

public sealed class ProductionMailboxSelectionSuccessorException(
    ProductionMailboxSelectionSuccessorError error,
    string message) : Exception(message)
{
    public ProductionMailboxSelectionSuccessorError Error { get; } = error;
}

/// <summary>
/// Dual-closure bridge from an exact old PMT1/PMS1 selection to its exact new PMT1/PMS1 successor.
/// The old and new issuer signatures use different domains even when both PMA1 documents name the
/// same Ed25519 issuer key.
/// </summary>
public sealed record ProductionMailboxSelectionSuccessorProof
{
    public required ProductionMailboxSelectionSuccessorMode Mode { get; init; }
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong OldEpoch { get; init; }
    public required ulong OldEpochGeneration { get; init; }
    public required ulong NewEpoch { get; init; }
    public required ulong NewEpochGeneration { get; init; }
    public required ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey { get; init; }
    public required ReadOnlyMemory<byte> BlindedMailboxId { get; init; }
    public required ReadOnlyMemory<byte> BlindedPlacementId { get; init; }
    public required ReadOnlyMemory<byte> SelectionInputCommitment { get; init; }
    public required ReadOnlyMemory<byte> OldCanonicalAuthorityHash { get; init; }
    public required ReadOnlyMemory<byte> NewCanonicalAuthorityHash { get; init; }
    public required ulong OldTopologyGeneration { get; init; }
    public required ReadOnlyMemory<byte> OldCanonicalTopologyHash { get; init; }
    public required ulong NewTopologyGeneration { get; init; }
    public required ReadOnlyMemory<byte> NewCanonicalTopologyHash { get; init; }
    public required ReadOnlyMemory<byte> OldCanonicalSelectionHash { get; init; }
    public required ReadOnlyMemory<byte> NewCanonicalSelectionHash { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    /// <summary>Exact canonical, live PMA1 carrying the pinned-Mr. X signature for the new closure.</summary>
    public required ReadOnlyMemory<byte> CanonicalNewAuthority { get; init; }
    public required ReadOnlyMemory<byte> OldCanonicalSelection { get; init; }
    public required ReadOnlyMemory<byte> NewCanonicalSelection { get; init; }
    public required ReadOnlyMemory<byte> OldIssuerSignature { get; init; }
    public required ReadOnlyMemory<byte> NewIssuerSignature { get; init; }
}

public sealed record ProductionMailboxSelectionSuccessorVerificationContext
{
    public required ReadOnlyMemory<byte> ExpectedNetworkId { get; init; }
    public required ReadOnlyMemory<byte> ExpectedMailboxOwnerEd25519PublicKey { get; init; }
    public required ReadOnlyMemory<byte> ExpectedBlindedMailboxId { get; init; }
    public required ReadOnlyMemory<byte> ExpectedBlindedPlacementId { get; init; }
    public required ReadOnlyMemory<byte> PinnedMrXPublicKeySha256 { get; init; }
    /// <summary>Exact durable old-next PMS1 hash. A valid bridge may not substitute another issuance.</summary>
    public required ReadOnlyMemory<byte> ExpectedOldCanonicalSelectionHash { get; init; }
    public required ulong NowUnixSeconds { get; init; }
    public uint ClockSkewSeconds { get; init; }
}

public interface IProductionMailboxSelectionSuccessorSignatureVerifier
{
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature);
}

/// <summary>Verify-only Ed25519 adapter. It contains no private-key or signing API.</summary>
public sealed class SodiumProductionMailboxSelectionSuccessorSignatureVerifier
    : IProductionMailboxSelectionSuccessorSignatureVerifier
{
    private readonly SodiumProductionMailboxTopologySignatureVerifier _inner = new();

    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature) =>
        _inner.Verify(publicKey, signingBytes, signature);
}

public sealed class VerifiedProductionMailboxSelectionSuccessor
{
    private readonly ProductionMailboxSelectionSuccessorProof _proof;
    private readonly byte[] _canonicalHash;
    private readonly VerifiedProductionMailboxSelection _oldSelection;
    private readonly VerifiedProductionMailboxSelection _newSelection;

    internal VerifiedProductionMailboxSelectionSuccessor(
        ProductionMailboxSelectionSuccessorProof proof,
        ReadOnlySpan<byte> canonicalHash,
        VerifiedProductionMailboxSelection oldSelection,
        VerifiedProductionMailboxSelection newSelection)
    {
        _proof = ProductionMailboxSelectionSuccessorCopy.Clone(proof);
        _canonicalHash = canonicalHash.ToArray();
        _oldSelection = oldSelection;
        _newSelection = newSelection;
    }

    public ProductionMailboxSelectionSuccessorProof Proof =>
        ProductionMailboxSelectionSuccessorCopy.Clone(_proof);
    public ReadOnlyMemory<byte> CanonicalSuccessorHash => _canonicalHash.ToArray();
    public VerifiedProductionMailboxSelection OldSelection => _oldSelection;
    public VerifiedProductionMailboxSelection NewSelection => _newSelection;
}

internal static class ProductionMailboxSelectionSuccessorCopy
{
    public static ProductionMailboxSelectionSuccessorProof Clone(
        ProductionMailboxSelectionSuccessorProof value) => new()
    {
        Mode = value.Mode,
        NetworkId = value.NetworkId.ToArray(),
        OldEpoch = value.OldEpoch,
        OldEpochGeneration = value.OldEpochGeneration,
        NewEpoch = value.NewEpoch,
        NewEpochGeneration = value.NewEpochGeneration,
        MailboxOwnerEd25519PublicKey = value.MailboxOwnerEd25519PublicKey.ToArray(),
        BlindedMailboxId = value.BlindedMailboxId.ToArray(),
        BlindedPlacementId = value.BlindedPlacementId.ToArray(),
        SelectionInputCommitment = value.SelectionInputCommitment.ToArray(),
        OldCanonicalAuthorityHash = value.OldCanonicalAuthorityHash.ToArray(),
        NewCanonicalAuthorityHash = value.NewCanonicalAuthorityHash.ToArray(),
        OldTopologyGeneration = value.OldTopologyGeneration,
        OldCanonicalTopologyHash = value.OldCanonicalTopologyHash.ToArray(),
        NewTopologyGeneration = value.NewTopologyGeneration,
        NewCanonicalTopologyHash = value.NewCanonicalTopologyHash.ToArray(),
        OldCanonicalSelectionHash = value.OldCanonicalSelectionHash.ToArray(),
        NewCanonicalSelectionHash = value.NewCanonicalSelectionHash.ToArray(),
        IssuedAtUnixSeconds = value.IssuedAtUnixSeconds,
        ExpiresAtUnixSeconds = value.ExpiresAtUnixSeconds,
        CanonicalNewAuthority = value.CanonicalNewAuthority.ToArray(),
        OldCanonicalSelection = value.OldCanonicalSelection.ToArray(),
        NewCanonicalSelection = value.NewCanonicalSelection.ToArray(),
        OldIssuerSignature = value.OldIssuerSignature.ToArray(),
        NewIssuerSignature = value.NewIssuerSignature.ToArray()
    };
}
