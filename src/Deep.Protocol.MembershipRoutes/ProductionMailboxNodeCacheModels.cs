namespace Deep.Protocol.DeepExtension.MailboxTopology;

/// <summary>
/// Exact PMC2 cache inputs. This is an in-process aggregate, not a new wire artifact. The
/// revocation checkpoint is forbidden for OwnerPRA2 and mandatory for DelegatedRCA1.
/// </summary>
public sealed record ProductionMailboxNodeCacheArtifacts
{
    public required ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; init; }
    public required ReadOnlyMemory<byte> CanonicalAuthority { get; init; }
    public required ReadOnlyMemory<byte> CanonicalRevocations { get; init; }
    public required ReadOnlyMemory<byte> CanonicalTopology { get; init; }
    public required ReadOnlyMemory<byte> CanonicalCurrentSelection { get; init; }
    public required ReadOnlyMemory<byte> CanonicalNextSelection { get; init; }
    public required ReadOnlyMemory<byte> CanonicalSelectionSuccessorV2 { get; init; }
    public required ReadOnlyMemory<byte> CanonicalRouteCertificate { get; init; }
    public required ReadOnlyMemory<byte> CanonicalTransitionContext { get; init; }
    public required ReadOnlyMemory<byte> CanonicalRouteAuthorization { get; init; }
    public ReadOnlyMemory<byte> CanonicalRevocationCheckpoint { get; init; }
}

/// <summary>
/// Protected predecessor and expected route bindings needed to authenticate a node cache. This
/// deliberately contains no RCD1, RDA1, RCR1 or sealed ROL1 material.
/// </summary>
public sealed record ProductionMailboxNodeCacheVerificationContext
{
    public required ReadOnlyMemory<byte> ExpectedRouteDomainHash { get; init; }
    public required ProductionMailboxNodeCacheControlPlaneContext ControlPlane { get; init; }
}

/// <summary>Protected scalar/hash predecessor state for either Direct or Offline PMC2.</summary>
public sealed record ProductionMailboxNodeCacheControlPlaneContext
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

/// <summary>
/// Non-forgeable node-cache-only PMC2 observation. It proves that the exact cache aggregate is a
/// live, internally consistent offline distribution closure. It is intentionally not, and cannot
/// be converted by this assembly into, a client route/selection activation capability.
/// </summary>
public sealed class VerifiedProductionMailboxNodeCacheClosure
{
    private readonly ProductionMailboxNodeCacheArtifacts _artifacts;
    private readonly byte[] _cacheTranscriptHash;

    internal VerifiedProductionMailboxNodeCacheClosure(
        ProductionMailboxNodeCacheArtifacts artifacts,
        ulong cacheExpiresAtUnixSeconds,
        ReadOnlySpan<byte> cacheTranscriptHash)
    {
        _artifacts = ProductionMailboxNodeCacheCopy.Clone(artifacts);
        CacheExpiresAtUnixSeconds = cacheExpiresAtUnixSeconds;
        _cacheTranscriptHash = cacheTranscriptHash.ToArray();
    }

    public ProductionMailboxRouteAuthorizationKind AuthorizationKind => _artifacts.AuthorizationKind;
    public ProductionMailboxSelectionSuccessorMode Mode { get; internal init; }
    public ulong CacheExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> CacheTranscriptHash => _cacheTranscriptHash.ToArray();
    public ProductionMailboxNodeCacheArtifacts CanonicalArtifacts =>
        ProductionMailboxNodeCacheCopy.Clone(_artifacts);
}

internal static class ProductionMailboxNodeCacheCopy
{
    internal static ProductionMailboxNodeCacheArtifacts Clone(
        ProductionMailboxNodeCacheArtifacts value) => new()
    {
        AuthorizationKind = value.AuthorizationKind,
        CanonicalAuthority = value.CanonicalAuthority.ToArray(),
        CanonicalRevocations = value.CanonicalRevocations.ToArray(),
        CanonicalTopology = value.CanonicalTopology.ToArray(),
        CanonicalCurrentSelection = value.CanonicalCurrentSelection.ToArray(),
        CanonicalNextSelection = value.CanonicalNextSelection.ToArray(),
        CanonicalSelectionSuccessorV2 = value.CanonicalSelectionSuccessorV2.ToArray(),
        CanonicalRouteCertificate = value.CanonicalRouteCertificate.ToArray(),
        CanonicalTransitionContext = value.CanonicalTransitionContext.ToArray(),
        CanonicalRouteAuthorization = value.CanonicalRouteAuthorization.ToArray(),
        CanonicalRevocationCheckpoint = value.CanonicalRevocationCheckpoint.ToArray()
    };
}
