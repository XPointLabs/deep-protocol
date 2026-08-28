using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Protocol.DeepExtension.MembershipRoutes;

/// <summary>
/// Pinned trust inputs used when a client binary reaches the managed mailbox control plane for
/// the first time after more than one publication rotation. The downloaded artifacts remain
/// untrusted until this verifier returns.
/// </summary>
public sealed record ProductionMailboxInitialCheckpointVerificationContext
{
    public required ReadOnlyMemory<byte> PinnedMrXPublicKeySha256 { get; init; }
    public required ReadOnlyMemory<byte> ExpectedNetworkId { get; init; }
    public required ulong LastCommittedAuthorityGeneration { get; init; }
    public required ulong LastCommittedRevocationGeneration { get; init; }
    public required ReadOnlyMemory<byte> LastCommittedRevocationHeadHash { get; init; }
    public required ReadOnlyMemory<byte> LastCommittedRevocationSnapshotHash { get; init; }
    public required ulong LastCommittedTopologyGeneration { get; init; }
    public required ulong NowUnixSeconds { get; init; }
    public uint ClockSkewSeconds { get; init; }
}

/// <summary>Immutable verified handles for one fresh initial forward checkpoint.</summary>
public sealed class VerifiedProductionMailboxInitialCheckpoint
{
    internal VerifiedProductionMailboxInitialCheckpoint(
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxRevocationSnapshot revocations,
        VerifiedProductionMailboxTopology topology)
    {
        Authority = authority ?? throw new ArgumentNullException(nameof(authority));
        Revocations = revocations ?? throw new ArgumentNullException(nameof(revocations));
        Topology = topology ?? throw new ArgumentNullException(nameof(topology));
    }

    public VerifiedProductionMailboxAuthority Authority { get; }
    public VerifiedProductionMailboxRevocationSnapshot Revocations { get; }
    public VerifiedProductionMailboxTopology Topology { get; }
}

/// <summary>
/// Verifies a fresh Mr. X-signed PMA1 checkpoint and its issuer-bound PMR1/PMT1 closure without
/// requiring an unlaunched client to download every expired intermediate publication.
/// </summary>
public static class ProductionMailboxInitialCheckpointVerifier
{
    public static VerifiedProductionMailboxInitialCheckpoint Verify(
        ReadOnlySpan<byte> canonicalAuthority,
        ReadOnlySpan<byte> canonicalRevocations,
        ReadOnlySpan<byte> canonicalTopology,
        ProductionMailboxInitialCheckpointVerificationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (canonicalAuthority.Length is 0 or > ProductionMailboxAuthorityConstants.MaximumArtifactBytes ||
            canonicalRevocations.Length is 0 or > ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes ||
            canonicalTopology.Length is 0 or > ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes)
            throw new InvalidDataException(
                "Initial production mailbox checkpoint artifact length is outside strict bounds.");

        var frozen = context with
        {
            PinnedMrXPublicKeySha256 = context.PinnedMrXPublicKeySha256.ToArray(),
            ExpectedNetworkId = context.ExpectedNetworkId.ToArray(),
            LastCommittedRevocationHeadHash = context.LastCommittedRevocationHeadHash.ToArray(),
            LastCommittedRevocationSnapshotHash = context.LastCommittedRevocationSnapshotHash.ToArray()
        };
        if (frozen.LastCommittedTopologyGeneration == 0)
            throw new InvalidDataException(
                "Initial production mailbox checkpoint topology anchor is invalid.");

        var authority = ProductionMailboxAuthorityVerifier.VerifyForwardCheckpoint(
            canonicalAuthority,
            new ProductionMailboxAuthorityCheckpointVerificationContext
            {
                PinnedMrXPublicKeySha256 = frozen.PinnedMrXPublicKeySha256,
                ExpectedNetworkId = frozen.ExpectedNetworkId,
                LastCommittedGeneration = frozen.LastCommittedAuthorityGeneration,
                LastCommittedRevocationGeneration = frozen.LastCommittedRevocationGeneration,
                LastCommittedRevocationHeadHash = frozen.LastCommittedRevocationHeadHash,
                LastCommittedRevocationSnapshotHash = frozen.LastCommittedRevocationSnapshotHash,
                NowUnixSeconds = frozen.NowUnixSeconds,
                ClockSkewSeconds = frozen.ClockSkewSeconds
            },
            new SodiumProductionMailboxAuthoritySignatureVerifier());
        var revocations = ProductionMailboxRevocationSnapshotVerifier.Verify(
            canonicalRevocations,
            authority,
            frozen.NowUnixSeconds,
            frozen.ClockSkewSeconds,
            new SodiumProductionMailboxRevocationSnapshotSignatureVerifier());
        var topology = ProductionMailboxTopologyVerifier.VerifyForwardCheckpoint(
            canonicalTopology,
            authority,
            new ProductionMailboxTopologyCheckpointVerificationContext
            {
                LastCommittedTopologyGeneration = frozen.LastCommittedTopologyGeneration,
                NowUnixSeconds = frozen.NowUnixSeconds,
                ClockSkewSeconds = frozen.ClockSkewSeconds
            },
            new SodiumProductionMailboxTopologySignatureVerifier());
        return new VerifiedProductionMailboxInitialCheckpoint(
            authority, revocations, topology);
    }
}
