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

/// <summary>
/// Exact durable recovery context for a complete offline-checkpoint closure.  Every old trust
/// component is supplied by the caller's protected LKG; downloaded artifacts cannot choose their
/// own predecessor.
/// </summary>
public sealed record ProductionMailboxOfflineCheckpointClosureVerificationContext
{
    public required ReadOnlyMemory<byte> ExpectedNetworkId { get; init; }
    public required ReadOnlyMemory<byte> ExpectedMailboxOwnerEd25519PublicKey { get; init; }
    public required ReadOnlyMemory<byte> ExpectedBlindedMailboxId { get; init; }
    public required ReadOnlyMemory<byte> ExpectedBlindedPlacementId { get; init; }
    public required ReadOnlyMemory<byte> ExpectedSelectionInputCommitment { get; init; }
    public required ReadOnlyMemory<byte> PinnedMrXPublicKeySha256 { get; init; }
    public required ulong ExpectedOldAuthorityGeneration { get; init; }
    public required ReadOnlyMemory<byte> ExpectedOldCanonicalAuthorityHash { get; init; }
    public required ulong ExpectedOldRevocationGeneration { get; init; }
    public required ReadOnlyMemory<byte> ExpectedOldRevocationHeadHash { get; init; }
    public required ReadOnlyMemory<byte> ExpectedOldRevocationSnapshotHash { get; init; }
    public required ulong ExpectedOldTopologyGeneration { get; init; }
    public required ReadOnlyMemory<byte> ExpectedOldCanonicalTopologyHash { get; init; }
    public required ReadOnlyMemory<byte> ExpectedOldCanonicalSelectionHash { get; init; }
    public required ulong VerifiedAtUnixSeconds { get; init; }
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

/// <summary>
/// Immutable commit observation produced only after a complete offline checkpoint has verified.
/// It is suitable for constructing a caller-owned atomic LKG update but is not itself a storage
/// capability.
/// </summary>
public sealed class ProductionMailboxOfflineCheckpointCommitAnchor
{
    private readonly byte[] _mrXPublicKeySha256;
    private readonly byte[] _networkId;
    private readonly byte[] _authorityHash;
    private readonly byte[] _revocationHeadHash;
    private readonly byte[] _revocationSnapshotHash;
    private readonly byte[] _topologyHash;
    private readonly byte[] _currentSelectionHash;
    private readonly byte[] _nextSelectionHash;

    internal ProductionMailboxOfflineCheckpointCommitAnchor(
        ReadOnlySpan<byte> mrXPublicKeySha256,
        ReadOnlySpan<byte> networkId,
        ulong authorityGeneration,
        ReadOnlySpan<byte> authorityHash,
        ulong revocationGeneration,
        ReadOnlySpan<byte> revocationHeadHash,
        ReadOnlySpan<byte> revocationSnapshotHash,
        ulong topologyGeneration,
        ReadOnlySpan<byte> topologyHash,
        ReadOnlySpan<byte> currentSelectionHash,
        ReadOnlySpan<byte> nextSelectionHash,
        ulong verifiedAtUnixSeconds)
    {
        _mrXPublicKeySha256 = mrXPublicKeySha256.ToArray();
        _networkId = networkId.ToArray();
        AuthorityGeneration = authorityGeneration;
        _authorityHash = authorityHash.ToArray();
        RevocationGeneration = revocationGeneration;
        _revocationHeadHash = revocationHeadHash.ToArray();
        _revocationSnapshotHash = revocationSnapshotHash.ToArray();
        TopologyGeneration = topologyGeneration;
        _topologyHash = topologyHash.ToArray();
        _currentSelectionHash = currentSelectionHash.ToArray();
        _nextSelectionHash = nextSelectionHash.ToArray();
        VerifiedAtUnixSeconds = verifiedAtUnixSeconds;
    }

    public ReadOnlyMemory<byte> MrXPublicKeySha256 => _mrXPublicKeySha256.ToArray();
    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ulong AuthorityGeneration { get; }
    public ReadOnlyMemory<byte> AuthorityHash => _authorityHash.ToArray();
    public ulong RevocationGeneration { get; }
    public ReadOnlyMemory<byte> RevocationHeadHash => _revocationHeadHash.ToArray();
    public ReadOnlyMemory<byte> RevocationSnapshotHash => _revocationSnapshotHash.ToArray();
    public ulong TopologyGeneration { get; }
    public ReadOnlyMemory<byte> TopologyHash => _topologyHash.ToArray();
    public ReadOnlyMemory<byte> CurrentSelectionHash => _currentSelectionHash.ToArray();
    public ReadOnlyMemory<byte> NextSelectionHash => _nextSelectionHash.ToArray();
    public ulong VerifiedAtUnixSeconds { get; }
}

/// <summary>
/// Non-forgeable complete offline-checkpoint result. Exact canonical bytes are retained so a
/// caller can atomically bind the same closure that was verified, without rereading mutable input.
/// </summary>
public sealed class VerifiedProductionMailboxOfflineCheckpointClosure
{
    private readonly byte[] _canonicalSuccessor;
    private readonly byte[] _canonicalNewAuthority;
    private readonly byte[] _canonicalNewRevocationSnapshot;
    private readonly byte[] _canonicalNewTopology;
    private readonly byte[] _canonicalOldSelection;
    private readonly byte[] _canonicalNewCurrentSelection;
    private readonly byte[] _canonicalNewNextSelection;
    private readonly byte[] _canonicalTranscript;
    private readonly byte[] _transcriptSha256;

    internal VerifiedProductionMailboxOfflineCheckpointClosure(
        VerifiedProductionMailboxSelectionSuccessor successor,
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxRevocationSnapshot revocations,
        VerifiedProductionMailboxTopology topology,
        VerifiedProductionMailboxSelection currentSelection,
        VerifiedProductionMailboxSelection nextSelection,
        ProductionMailboxOfflineCheckpointCommitAnchor nextCommitAnchor,
        ReadOnlySpan<byte> canonicalSuccessor,
        ReadOnlySpan<byte> canonicalNewAuthority,
        ReadOnlySpan<byte> canonicalNewRevocationSnapshot,
        ReadOnlySpan<byte> canonicalNewTopology,
        ReadOnlySpan<byte> canonicalOldSelection,
        ReadOnlySpan<byte> canonicalNewCurrentSelection,
        ReadOnlySpan<byte> canonicalNewNextSelection,
        ReadOnlySpan<byte> canonicalTranscript,
        ReadOnlySpan<byte> transcriptSha256)
    {
        Successor = successor ?? throw new ArgumentNullException(nameof(successor));
        Authority = authority ?? throw new ArgumentNullException(nameof(authority));
        Revocations = revocations ?? throw new ArgumentNullException(nameof(revocations));
        Topology = topology ?? throw new ArgumentNullException(nameof(topology));
        CurrentSelection = currentSelection ?? throw new ArgumentNullException(nameof(currentSelection));
        NextSelection = nextSelection ?? throw new ArgumentNullException(nameof(nextSelection));
        NextCommitAnchor = nextCommitAnchor ?? throw new ArgumentNullException(nameof(nextCommitAnchor));
        _canonicalSuccessor = canonicalSuccessor.ToArray();
        _canonicalNewAuthority = canonicalNewAuthority.ToArray();
        _canonicalNewRevocationSnapshot = canonicalNewRevocationSnapshot.ToArray();
        _canonicalNewTopology = canonicalNewTopology.ToArray();
        _canonicalOldSelection = canonicalOldSelection.ToArray();
        _canonicalNewCurrentSelection = canonicalNewCurrentSelection.ToArray();
        _canonicalNewNextSelection = canonicalNewNextSelection.ToArray();
        _canonicalTranscript = canonicalTranscript.ToArray();
        _transcriptSha256 = transcriptSha256.ToArray();
    }

    public VerifiedProductionMailboxSelectionSuccessor Successor { get; }
    public VerifiedProductionMailboxAuthority Authority { get; }
    public VerifiedProductionMailboxRevocationSnapshot Revocations { get; }
    public VerifiedProductionMailboxTopology Topology { get; }
    public VerifiedProductionMailboxSelection CurrentSelection { get; }
    public VerifiedProductionMailboxSelection NextSelection { get; }
    public ProductionMailboxOfflineCheckpointCommitAnchor NextCommitAnchor { get; }
    public ReadOnlyMemory<byte> CanonicalSuccessor => _canonicalSuccessor.ToArray();
    public ReadOnlyMemory<byte> CanonicalNewAuthority => _canonicalNewAuthority.ToArray();
    public ReadOnlyMemory<byte> CanonicalNewRevocationSnapshot =>
        _canonicalNewRevocationSnapshot.ToArray();
    public ReadOnlyMemory<byte> CanonicalNewTopology => _canonicalNewTopology.ToArray();
    public ReadOnlyMemory<byte> CanonicalOldSelection => _canonicalOldSelection.ToArray();
    public ReadOnlyMemory<byte> CanonicalNewCurrentSelection =>
        _canonicalNewCurrentSelection.ToArray();
    public ReadOnlyMemory<byte> CanonicalNewNextSelection => _canonicalNewNextSelection.ToArray();
    public ReadOnlyMemory<byte> CanonicalTranscript => _canonicalTranscript.ToArray();
    public ReadOnlyMemory<byte> TranscriptSha256 => _transcriptSha256.ToArray();
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
