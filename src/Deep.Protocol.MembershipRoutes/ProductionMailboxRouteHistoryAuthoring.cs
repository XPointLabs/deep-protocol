using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

public sealed record ProductionMailboxRouteHistoryAuthoringLink
{
    public required ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; init; }
    public required ReadOnlyMemory<byte> CanonicalAuthority { get; init; }
    public required ReadOnlyMemory<byte> CanonicalRevocations { get; init; }
    public required ReadOnlyMemory<byte> CanonicalRouteCertificate { get; init; }
    public required ReadOnlyMemory<byte> CanonicalRevocationCheckpoint { get; init; }
    public required ReadOnlyMemory<byte> CanonicalTransitionContext { get; init; }
    public required ReadOnlyMemory<byte> CanonicalAuthorization { get; init; }
}

public sealed class VerifiedProductionMailboxRouteHistoryCursor
{
    private readonly VerifiedProductionMailboxRouteHistoryCheckpoint _checkpoint;

    internal VerifiedProductionMailboxRouteHistoryCursor(
        VerifiedProductionMailboxRouteHistoryCheckpoint checkpoint,
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment)
    {
        _checkpoint = checkpoint ?? throw new ArgumentNullException(nameof(checkpoint));
        Enrollment = enrollment ?? throw new ArgumentNullException(nameof(enrollment));
    }

    internal VerifiedProductionMailboxRouteHistoryCheckpoint Checkpoint => _checkpoint;
    internal VerifiedProductionMailboxRouteContinuityEnrollment Enrollment { get; }
    internal byte[] CanonicalCurrentRouteOriginLkg()
    {
        var value = _checkpoint.TrustedCheckpoint;
        return ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(new ProductionMailboxRouteOriginLkg
        {
            NetworkId = value.NetworkId.ToArray(), RouteDomainHash = value.RouteDomainHash.ToArray(),
            AuthorizationKind = value.CurrentAuthorizationKind,
            CanonicalAuthorizationHash = value.CurrentCanonicalAuthorizationHash.ToArray(),
            AuthorizationSequence = value.CurrentAuthorizationSequence,
            CanonicalDelegationHash = Enrollment.CanonicalDelegationHash.ToArray(),
            CanonicalDelegationAcceptanceHash = Enrollment.CanonicalAcceptanceHash.ToArray(),
            OwnerRevocationGeneration = value.OwnerRevocationGeneration,
            OwnerRevocationHeadHash = value.OwnerRevocationHeadHash.ToArray(),
            RouteVerifiedAtUnixSeconds = value.RouteVerifiedAtUnixSeconds,
            LocalCommitGeneration = value.CurrentLocalCommitGeneration
        });
    }
    public ReadOnlyMemory<byte> CanonicalCheckpoint => _checkpoint.CanonicalBytes.ToArray();
    public ReadOnlyMemory<byte> CanonicalCheckpointHash => _checkpoint.CanonicalHash.ToArray();
    public ulong LastCommittedBatchSequence => _checkpoint.TrustedCheckpoint.LastCommittedBatchSequence;
    public ulong CumulativeVerifiedRouteLinkCount =>
        _checkpoint.TrustedCheckpoint.CumulativeVerifiedRouteLinkCount;

    /// <summary>
    /// Exports one defensively snapshotted durable restore tuple. Callers never parse RHC1 to
    /// recover its CAS, enrollment, PMA1 or PMR1 bindings.
    /// </summary>
    public ProductionMailboxRouteHistoryProtectedRestoreContext ToProtectedRestoreContext() =>
        ProductionMailboxRouteHistoryProtectedRestoreContext.From(this);
}

public sealed class ProductionMailboxRouteHistoryBatchCommitPlan
{
    private readonly byte[] _canonicalBatch;
    private readonly byte[] _canonicalBatchHash;
    private readonly byte[] _expectedCurrentCheckpoint;
    private readonly byte[] _expectedCurrentCheckpointHash;
    private readonly byte[] _expectedCurrentRouteOriginLkgHash;

    internal ProductionMailboxRouteHistoryBatchCommitPlan(
        ReadOnlySpan<byte> canonicalBatch,
        VerifiedProductionMailboxRouteHistoryCursor currentCursor,
        VerifiedProductionMailboxRouteHistoryCursor nextCursor)
    {
        _canonicalBatch = canonicalBatch.ToArray();
        _canonicalBatchHash = SHA256.HashData(_canonicalBatch);
        _expectedCurrentCheckpoint = currentCursor.CanonicalCheckpoint.ToArray();
        _expectedCurrentCheckpointHash = currentCursor.CanonicalCheckpointHash.ToArray();
        _expectedCurrentRouteOriginLkgHash = currentCursor.Checkpoint.TrustedCheckpoint
            .CurrentRouteOriginLkgHash.ToArray();
        ExpectedCurrentBatchSequence = currentCursor.LastCommittedBatchSequence;
        NextCursor = nextCursor ?? throw new ArgumentNullException(nameof(nextCursor));
    }

    public ReadOnlyMemory<byte> CanonicalBatch => _canonicalBatch.ToArray();
    public ReadOnlyMemory<byte> CanonicalBatchHash => _canonicalBatchHash.ToArray();
    public ReadOnlyMemory<byte> ExpectedCurrentCheckpoint => _expectedCurrentCheckpoint.ToArray();
    public ReadOnlyMemory<byte> ExpectedCurrentCheckpointHash => _expectedCurrentCheckpointHash.ToArray();
    public ReadOnlyMemory<byte> ExpectedCurrentRouteOriginLkgHash =>
        _expectedCurrentRouteOriginLkgHash.ToArray();
    public ulong ExpectedCurrentBatchSequence { get; }
    public VerifiedProductionMailboxRouteHistoryCursor NextCursor { get; }

    /// <summary>Exports the exact post-commit durable restore tuple.</summary>
    public ProductionMailboxRouteHistoryProtectedRestoreContext ToProtectedRestoreContext() =>
        NextCursor.ToProtectedRestoreContext();
}

/// <summary>
/// Exact fields retained by the authenticated durable CAS alongside RHC1. Network-fetched values
/// must never be used to populate this context.
/// </summary>
public sealed class ProductionMailboxRouteHistoryProtectedRestoreContext
{
    private readonly byte[] _canonicalCheckpoint;
    private readonly byte[] _canonicalCheckpointHash;
    private readonly byte[] _lastCommittedBatchHash;
    private readonly byte[] _currentRouteOriginLkgHash;
    private readonly byte[] _enrollmentCanonicalDelegationHash;
    private readonly byte[] _enrollmentCanonicalAcceptanceHash;
    private readonly byte[] _networkId;
    private readonly byte[] _routeDomainHash;
    private readonly byte[] _delegationHistoryBinding;
    private readonly byte[] _pinnedMrXPublicKeySha256;
    private readonly byte[] _currentCanonicalAuthorityHash;
    private readonly byte[] _currentRevocationHeadHash;
    private readonly byte[] _currentRevocationSnapshotHash;

    public ProductionMailboxRouteHistoryProtectedRestoreContext(
        ReadOnlyMemory<byte> canonicalCheckpoint,
        ReadOnlyMemory<byte> canonicalCheckpointHash,
        ulong lastCommittedBatchSequence,
        ReadOnlyMemory<byte> lastCommittedBatchHash,
        ReadOnlyMemory<byte> currentRouteOriginLkgHash,
        ReadOnlyMemory<byte> enrollmentCanonicalDelegationHash,
        ReadOnlyMemory<byte> enrollmentCanonicalAcceptanceHash,
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> routeDomainHash,
        ReadOnlyMemory<byte> delegationHistoryBinding,
        ReadOnlyMemory<byte> pinnedMrXPublicKeySha256,
        ulong currentAuthorityGeneration,
        ReadOnlyMemory<byte> currentCanonicalAuthorityHash,
        ulong currentRevocationGeneration,
        ReadOnlyMemory<byte> currentRevocationHeadHash,
        ReadOnlyMemory<byte> currentRevocationSnapshotHash)
    {
        PreflightInputs(canonicalCheckpoint, canonicalCheckpointHash,
            lastCommittedBatchSequence, lastCommittedBatchHash, currentRouteOriginLkgHash,
            enrollmentCanonicalDelegationHash, enrollmentCanonicalAcceptanceHash, networkId,
            routeDomainHash, delegationHistoryBinding, pinnedMrXPublicKeySha256,
            currentAuthorityGeneration, currentCanonicalAuthorityHash,
            currentRevocationGeneration, currentRevocationHeadHash,
            currentRevocationSnapshotHash);
        _canonicalCheckpoint = canonicalCheckpoint.ToArray();
        _canonicalCheckpointHash = canonicalCheckpointHash.ToArray();
        LastCommittedBatchSequence = lastCommittedBatchSequence;
        _lastCommittedBatchHash = lastCommittedBatchHash.ToArray();
        _currentRouteOriginLkgHash = currentRouteOriginLkgHash.ToArray();
        _enrollmentCanonicalDelegationHash = enrollmentCanonicalDelegationHash.ToArray();
        _enrollmentCanonicalAcceptanceHash = enrollmentCanonicalAcceptanceHash.ToArray();
        _networkId = networkId.ToArray();
        _routeDomainHash = routeDomainHash.ToArray();
        _delegationHistoryBinding = delegationHistoryBinding.ToArray();
        _pinnedMrXPublicKeySha256 = pinnedMrXPublicKeySha256.ToArray();
        CurrentAuthorityGeneration = currentAuthorityGeneration;
        _currentCanonicalAuthorityHash = currentCanonicalAuthorityHash.ToArray();
        CurrentRevocationGeneration = currentRevocationGeneration;
        _currentRevocationHeadHash = currentRevocationHeadHash.ToArray();
        _currentRevocationSnapshotHash = currentRevocationSnapshotHash.ToArray();
        Validate();
    }

    private static void PreflightInputs(
        ReadOnlyMemory<byte> canonicalCheckpoint,
        ReadOnlyMemory<byte> canonicalCheckpointHash,
        ulong lastCommittedBatchSequence,
        ReadOnlyMemory<byte> lastCommittedBatchHash,
        ReadOnlyMemory<byte> currentRouteOriginLkgHash,
        ReadOnlyMemory<byte> enrollmentCanonicalDelegationHash,
        ReadOnlyMemory<byte> enrollmentCanonicalAcceptanceHash,
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> routeDomainHash,
        ReadOnlyMemory<byte> delegationHistoryBinding,
        ReadOnlyMemory<byte> pinnedMrXPublicKeySha256,
        ulong currentAuthorityGeneration,
        ReadOnlyMemory<byte> currentCanonicalAuthorityHash,
        ulong currentRevocationGeneration,
        ReadOnlyMemory<byte> currentRevocationHeadHash,
        ReadOnlyMemory<byte> currentRevocationSnapshotHash)
    {
        static void Exact(ReadOnlyMemory<byte> value, int length, string name)
        {
            if (value.Length != length)
                throw new FormatException($"Protected RHC1 {name} length is invalid.");
        }
        Exact(canonicalCheckpoint,
            ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength,
            "checkpoint");
        Exact(canonicalCheckpointHash, 32, "checkpoint hash");
        Exact(lastCommittedBatchHash, 32, "last batch hash");
        Exact(currentRouteOriginLkgHash, 32, "ROL1 hash");
        Exact(enrollmentCanonicalDelegationHash, 32, "RCD1 hash");
        Exact(enrollmentCanonicalAcceptanceHash, 32, "RDA1 hash");
        Exact(networkId, 16, "network");
        Exact(routeDomainHash, 32, "route domain");
        Exact(delegationHistoryBinding, 32, "delegation binding");
        Exact(pinnedMrXPublicKeySha256, 32, "Mr. X pin");
        Exact(currentCanonicalAuthorityHash, 32, "PMA1 hash");
        Exact(currentRevocationHeadHash, 32, "PMR1 head");
        Exact(currentRevocationSnapshotHash, 32, "PMR1 snapshot");
        if (lastCommittedBatchSequence >
                ProductionMailboxRouteContinuityConstants.MaximumHistoryBatchCount ||
            currentAuthorityGeneration is 0 or ulong.MaxValue ||
            currentRevocationGeneration is 0 or ulong.MaxValue)
            throw new FormatException("Protected RHC1 scalar state is invalid.");
    }

    public ReadOnlyMemory<byte> CanonicalCheckpoint => _canonicalCheckpoint.ToArray();
    public ReadOnlyMemory<byte> CanonicalCheckpointHash => _canonicalCheckpointHash.ToArray();
    public ulong LastCommittedBatchSequence { get; }
    public ReadOnlyMemory<byte> LastCommittedBatchHash => _lastCommittedBatchHash.ToArray();
    public ReadOnlyMemory<byte> CurrentRouteOriginLkgHash => _currentRouteOriginLkgHash.ToArray();
    public ReadOnlyMemory<byte> EnrollmentCanonicalDelegationHash =>
        _enrollmentCanonicalDelegationHash.ToArray();
    public ReadOnlyMemory<byte> EnrollmentCanonicalAcceptanceHash =>
        _enrollmentCanonicalAcceptanceHash.ToArray();
    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> RouteDomainHash => _routeDomainHash.ToArray();
    public ReadOnlyMemory<byte> DelegationHistoryBinding => _delegationHistoryBinding.ToArray();
    public ReadOnlyMemory<byte> PinnedMrXPublicKeySha256 => _pinnedMrXPublicKeySha256.ToArray();
    public ulong CurrentAuthorityGeneration { get; }
    public ReadOnlyMemory<byte> CurrentCanonicalAuthorityHash =>
        _currentCanonicalAuthorityHash.ToArray();
    public ulong CurrentRevocationGeneration { get; }
    public ReadOnlyMemory<byte> CurrentRevocationHeadHash => _currentRevocationHeadHash.ToArray();
    public ReadOnlyMemory<byte> CurrentRevocationSnapshotHash =>
        _currentRevocationSnapshotHash.ToArray();

    internal static ProductionMailboxRouteHistoryProtectedRestoreContext From(
        VerifiedProductionMailboxRouteHistoryCursor cursor)
    {
        var checkpoint = cursor.Checkpoint.TrustedCheckpoint;
        var enrollment = cursor.Enrollment;
        return new(cursor.CanonicalCheckpoint, cursor.CanonicalCheckpointHash,
            checkpoint.LastCommittedBatchSequence, checkpoint.LastCommittedBatchHash,
            checkpoint.CurrentRouteOriginLkgHash, enrollment.CanonicalDelegationHash,
            enrollment.CanonicalAcceptanceHash, checkpoint.NetworkId, checkpoint.RouteDomainHash,
            checkpoint.DelegationHistoryBinding, checkpoint.PinnedMrXPublicKeySha256,
            checkpoint.CurrentAuthorityGeneration, checkpoint.CurrentCanonicalAuthorityHash,
            checkpoint.CurrentRevocationGeneration, checkpoint.CurrentRevocationHeadHash,
            checkpoint.CurrentRevocationSnapshotHash);
    }

    internal void Validate()
    {
        static void Fixed(ReadOnlySpan<byte> value, int length, bool nonzero, string name)
        {
            if (value.Length != length || (nonzero && value.IndexOfAnyExcept((byte)0) < 0))
                throw new FormatException($"Protected RHC1 {name} is invalid.");
        }
        Fixed(_canonicalCheckpoint, ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength,
            true, "checkpoint");
        Fixed(_canonicalCheckpointHash, 32, true, "checkpoint hash");
        Fixed(_lastCommittedBatchHash, 32, LastCommittedBatchSequence != 0, "last batch hash");
        if (LastCommittedBatchSequence == 0 && _lastCommittedBatchHash.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException("Protected initial RHC1 last batch hash is non-zero.");
        Fixed(_currentRouteOriginLkgHash, 32, true, "ROL1 hash");
        Fixed(_enrollmentCanonicalDelegationHash, 32, true, "RCD1 hash");
        Fixed(_enrollmentCanonicalAcceptanceHash, 32, true, "RDA1 hash");
        Fixed(_networkId, 16, false, "network");
        Fixed(_routeDomainHash, 32, true, "route domain");
        Fixed(_delegationHistoryBinding, 32, true, "delegation binding");
        Fixed(_pinnedMrXPublicKeySha256, 32, true, "Mr. X pin");
        Fixed(_currentCanonicalAuthorityHash, 32, true, "PMA1 hash");
        Fixed(_currentRevocationHeadHash, 32, true, "PMR1 head");
        Fixed(_currentRevocationSnapshotHash, 32, true, "PMR1 snapshot");
        if (CurrentAuthorityGeneration == 0 || CurrentAuthorityGeneration == ulong.MaxValue ||
            CurrentRevocationGeneration == 0 || CurrentRevocationGeneration == ulong.MaxValue)
            throw new FormatException("Protected RHC1 PMA1/PMR1 generations are invalid.");
    }
}

/// <summary>
/// Bounded canonical RHB1 authoring backed by the same cryptographic link verifier used for
/// recovery. A batch becomes a commit plan only after every exact artifact and route link advances
/// the sealed RHC1 cursor.
/// </summary>
public static class ProductionMailboxRouteHistoryAuthoring
{
    public static VerifiedProductionMailboxRouteHistoryCursor CreateInitialCursor(
        VerifiedProductionMailboxRouteContinuityEnrollmentState enrollmentState,
        VerifiedProductionMailboxAuthority anchorAuthority,
        VerifiedProductionMailboxRevocationSnapshot anchorRevocations)
    {
        ArgumentNullException.ThrowIfNull(enrollmentState);
        ArgumentNullException.ThrowIfNull(anchorAuthority);
        ArgumentNullException.ThrowIfNull(anchorRevocations);
        var enrollment = enrollmentState.Enrollment;
        var rol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(
            enrollmentState.CanonicalEnrolledRouteOriginLkg.Span);
        var authority = anchorAuthority.Authority;
        var delegation = enrollment.Delegation;
        if (!CryptographicOperations.FixedTimeEquals(rol.NetworkId.Span, authority.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(rol.NetworkId.Span, delegation.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(rol.RouteDomainHash.Span,
                delegation.RouteDomainHash.Span) ||
            authority.AuthorityGeneration != delegation.AnchorAuthorityGeneration ||
            !CryptographicOperations.FixedTimeEquals(anchorAuthority.CanonicalAuthorityHash.Span,
                delegation.AnchorCanonicalAuthorityHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(authority.MrXApprovalEd25519PublicKey.Span),
                delegation.PinnedMrXPublicKeySha256.Span))
            throw new FormatException("Initial route-history control plane differs from enrollment.");
        if (!CryptographicOperations.FixedTimeEquals(rol.CanonicalDelegationHash.Span,
                enrollment.CanonicalDelegationHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(rol.CanonicalDelegationAcceptanceHash.Span,
                enrollment.CanonicalAcceptanceHash.Span) ||
            rol.AuthorizationKind != delegation.AnchorAuthorizationKind ||
            !CryptographicOperations.FixedTimeEquals(rol.CanonicalAuthorizationHash.Span,
                delegation.AnchorCanonicalRouteAuthorizationHash.Span) ||
            rol.AuthorizationSequence != delegation.AnchorRouteAuthorizationSequence ||
            rol.OwnerRevocationGeneration != 0 ||
            rol.OwnerRevocationHeadHash.Span.IndexOfAnyExcept((byte)0) >= 0 ||
            !CryptographicOperations.FixedTimeEquals(
                ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(rol),
                enrollmentState.EnrolledRouteOriginLkgHash.Span))
            throw new FormatException("Initial route-history ROL1 differs from enrolled continuity state.");
        var revocations = anchorRevocations.Snapshot;
        var checkpoint = new ProductionMailboxRouteHistoryCheckpoint
        {
            NetworkId = rol.NetworkId.ToArray(),
            RouteDomainHash = rol.RouteDomainHash.ToArray(),
            DelegationHistoryBinding = ProductionMailboxRouteContinuityCodec.ComputeDelegationHistoryBinding(
                enrollment.CanonicalDelegationHash.Span, enrollment.CanonicalAcceptanceHash.Span),
            CurrentAuthorizationKind = rol.AuthorizationKind,
            CurrentCanonicalAuthorizationHash = rol.CanonicalAuthorizationHash.ToArray(),
            CurrentAuthorizationSequence = rol.AuthorizationSequence,
            OwnerRevocationGeneration = rol.OwnerRevocationGeneration,
            OwnerRevocationHeadHash = rol.OwnerRevocationHeadHash.ToArray(),
            CurrentRouteOriginLkgHash = enrollmentState.EnrolledRouteOriginLkgHash.ToArray(),
            RouteVerifiedAtUnixSeconds = rol.RouteVerifiedAtUnixSeconds,
            CurrentLocalCommitGeneration = rol.LocalCommitGeneration,
            PinnedMrXPublicKeySha256 = SHA256.HashData(authority.MrXApprovalEd25519PublicKey.Span),
            CurrentAuthorityGeneration = authority.AuthorityGeneration,
            CurrentCanonicalAuthorityHash = anchorAuthority.CanonicalAuthorityHash.ToArray(),
            CurrentRevocationGeneration = revocations.RevocationGeneration,
            CurrentRevocationHeadHash = revocations.RevocationHeadHash.ToArray(),
            CurrentRevocationSnapshotHash = anchorRevocations.CanonicalSnapshotHash.ToArray(),
            LastCommittedBatchSequence = 0,
            CumulativeCommittedBatchCount = 0,
            CumulativeVerifiedRouteLinkCount = 0,
            CumulativeCanonicalPayloadBytes = 0,
            HistoryTranscriptHead = new byte[32],
            LastCommittedBatchHash = new byte[32]
        };
        VerifyCheckpointClosure(checkpoint, enrollment, anchorAuthority, anchorRevocations);
        return new(ProductionMailboxRouteHistoryVerifier.CreateInitial(checkpoint), enrollment);
    }

    public static ProductionMailboxRouteHistoryBatchCommitPlan AuthorNextBatch(
        VerifiedProductionMailboxRouteHistoryCursor current,
        IReadOnlyList<ProductionMailboxRouteHistoryAuthoringLink> links)
    {
        ArgumentNullException.ThrowIfNull(current);
        var frozenLinks = Freeze(links);
        var batch = BuildBatch(current, frozenLinks);
        var canonical = ProductionMailboxRouteHistoryCodec.Encode(batch);
        var next = VerifyCore(current, canonical);
        return new(canonical, current, next);
    }

    public static VerifiedProductionMailboxRouteHistoryCursor VerifyBatch(
        VerifiedProductionMailboxRouteHistoryCursor current,
        ReadOnlySpan<byte> canonicalBatch)
    {
        ArgumentNullException.ThrowIfNull(current);
        if (canonicalBatch.Length < ProductionMailboxRouteHistoryConstants.HeaderLength ||
            canonicalBatch.Length > ProductionMailboxRouteHistoryConstants.MaximumEncodedBytes)
            throw new FormatException("RHB1 length is outside its strict bound.");
        return VerifyCore(current, canonicalBatch);
    }

    public static VerifiedProductionMailboxRouteHistoryCursor RestoreCursor(
        ReadOnlySpan<byte> canonicalCheckpoint,
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment,
        VerifiedProductionMailboxAuthority currentAuthority,
        VerifiedProductionMailboxRevocationSnapshot currentRevocations,
        ProductionMailboxRouteHistoryProtectedRestoreContext protectedState)
    {
        ArgumentNullException.ThrowIfNull(enrollment);
        ArgumentNullException.ThrowIfNull(currentAuthority);
        ArgumentNullException.ThrowIfNull(currentRevocations);
        ArgumentNullException.ThrowIfNull(protectedState);
        protectedState.Validate();
        var protectedCheckpoint = protectedState.CanonicalCheckpoint.ToArray();
        var protectedCheckpointHash = protectedState.CanonicalCheckpointHash.ToArray();
        var protectedLastBatchHash = protectedState.LastCommittedBatchHash.ToArray();
        var protectedRolHash = protectedState.CurrentRouteOriginLkgHash.ToArray();
        if (canonicalCheckpoint.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength ||
            !canonicalCheckpoint.SequenceEqual(protectedCheckpoint))
            throw new FormatException("RHC1 differs from the exact protected checkpoint bytes.");
        var frozen = canonicalCheckpoint.ToArray();
        var checkpoint = ProductionMailboxRouteContinuityCodec.DecodeRouteHistoryCheckpoint(frozen);
        var canonicalHash = ProductionMailboxRouteContinuityCodec.ComputeRouteHistoryCheckpointHash(
            checkpoint);
        if (!CryptographicOperations.FixedTimeEquals(canonicalHash,
                protectedCheckpointHash) ||
            checkpoint.LastCommittedBatchSequence !=
                protectedState.LastCommittedBatchSequence ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.LastCommittedBatchHash.Span,
                protectedLastBatchHash) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRouteOriginLkgHash.Span,
                protectedRolHash) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.NetworkId.Span,
                protectedState.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.RouteDomainHash.Span,
                protectedState.RouteDomainHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.DelegationHistoryBinding.Span,
                protectedState.DelegationHistoryBinding.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.PinnedMrXPublicKeySha256.Span,
                protectedState.PinnedMrXPublicKeySha256.Span) ||
            checkpoint.CurrentAuthorityGeneration != protectedState.CurrentAuthorityGeneration ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentCanonicalAuthorityHash.Span,
                protectedState.CurrentCanonicalAuthorityHash.Span) ||
            checkpoint.CurrentRevocationGeneration != protectedState.CurrentRevocationGeneration ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRevocationHeadHash.Span,
                protectedState.CurrentRevocationHeadHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRevocationSnapshotHash.Span,
                protectedState.CurrentRevocationSnapshotHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(enrollment.CanonicalDelegationHash.Span,
                protectedState.EnrollmentCanonicalDelegationHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(enrollment.CanonicalAcceptanceHash.Span,
                protectedState.EnrollmentCanonicalAcceptanceHash.Span))
            throw new FormatException("RHC1 differs from the protected durable CAS state.");
        VerifyCheckpointClosure(checkpoint, enrollment, currentAuthority, currentRevocations);
        return new(new VerifiedProductionMailboxRouteHistoryCheckpoint(checkpoint, frozen), enrollment);
    }

    private static VerifiedProductionMailboxRouteHistoryCursor VerifyCore(
        VerifiedProductionMailboxRouteHistoryCursor current,
        ReadOnlySpan<byte> canonicalBatch)
    {
        var old = current.Checkpoint.TrustedCheckpoint;
        var verifier = new ProductionMailboxRouteHistoryCryptographicLinkVerifier(
            old.NetworkId, old.RouteDomainHash, old.PinnedMrXPublicKeySha256, current.Enrollment);
        var next = ProductionMailboxRouteHistoryVerifier.Advance(
            canonicalBatch, current.Checkpoint, verifier);
        return ReferenceEquals(next, current.Checkpoint) ? current : new(next, current.Enrollment);
    }

    private static void VerifyCheckpointClosure(
        ProductionMailboxRouteHistoryCheckpoint checkpoint,
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment,
        VerifiedProductionMailboxAuthority currentAuthority,
        VerifiedProductionMailboxRevocationSnapshot currentRevocations)
    {
        var delegation = enrollment.Delegation;
        var authority = currentAuthority.Authority;
        var revocations = currentRevocations.Snapshot;
        var expectedBinding = ProductionMailboxRouteContinuityCodec.ComputeDelegationHistoryBinding(
            enrollment.CanonicalDelegationHash.Span, enrollment.CanonicalAcceptanceHash.Span);
        if (!CryptographicOperations.FixedTimeEquals(checkpoint.NetworkId.Span,
                delegation.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.RouteDomainHash.Span,
                delegation.RouteDomainHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.DelegationHistoryBinding.Span,
                expectedBinding) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.PinnedMrXPublicKeySha256.Span,
                delegation.PinnedMrXPublicKeySha256.Span) ||
            authority.AuthorityGeneration > delegation.MaximumAuthorityGeneration ||
            checkpoint.CurrentAuthorityGeneration != authority.AuthorityGeneration ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentCanonicalAuthorityHash.Span,
                currentAuthority.CanonicalAuthorityHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(authority.NetworkId.Span,
                checkpoint.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(authority.MrXApprovalEd25519PublicKey.Span),
                checkpoint.PinnedMrXPublicKeySha256.Span) ||
            revocations.AuthorityGeneration != authority.AuthorityGeneration ||
            !CryptographicOperations.FixedTimeEquals(revocations.NetworkId.Span,
                checkpoint.NetworkId.Span) ||
            checkpoint.CurrentRevocationGeneration != revocations.RevocationGeneration ||
            revocations.RevocationGeneration != authority.Revocation.Generation ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRevocationHeadHash.Span,
                revocations.RevocationHeadHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(revocations.RevocationHeadHash.Span,
                authority.Revocation.HeadHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRevocationSnapshotHash.Span,
                currentRevocations.CanonicalSnapshotHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(currentRevocations.CanonicalSnapshotHash.Span,
                authority.Revocation.SnapshotHash.Span))
            throw new FormatException("RHC1 closure differs from enrollment or current control plane.");
    }

    private static ProductionMailboxRouteHistoryBatch BuildBatch(
        VerifiedProductionMailboxRouteHistoryCursor current,
        IReadOnlyList<ProductionMailboxRouteHistoryAuthoringLink> links)
    {
        var artifacts = new List<(ProductionMailboxRouteHistoryArtifactKind Kind, byte[] Bytes, byte[] Hash)>();
        var linkKeys = new List<(ProductionMailboxRouteHistoryAuthoringLink Link,
            (ProductionMailboxRouteHistoryArtifactKind Kind, byte[] Hash)[] Keys)>();
        foreach (var link in links)
        {
            var values = new List<(ProductionMailboxRouteHistoryArtifactKind, ReadOnlyMemory<byte>)>
            {
                (ProductionMailboxRouteHistoryArtifactKind.Authority, link.CanonicalAuthority),
                (ProductionMailboxRouteHistoryArtifactKind.Revocations, link.CanonicalRevocations),
                (ProductionMailboxRouteHistoryArtifactKind.RouteCertificate,
                    link.CanonicalRouteCertificate),
                (link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                    ? ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement
                    : ProductionMailboxRouteHistoryArtifactKind.ContinuityActivation,
                    link.CanonicalAuthorization)
            };
            if (link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            {
                values.Add((ProductionMailboxRouteHistoryArtifactKind.RevocationCheckpoint,
                    link.CanonicalRevocationCheckpoint));
                values.Add((ProductionMailboxRouteHistoryArtifactKind.TransitionContext,
                    link.CanonicalTransitionContext));
            }
            var keys = new (ProductionMailboxRouteHistoryArtifactKind, byte[])[values.Count];
            for (var i = 0; i < values.Count; i++)
            {
                var hash = SHA256.HashData(values[i].Item2.Span);
                if (artifacts.Any(item => item.Kind != values[i].Item1 &&
                        CryptographicOperations.FixedTimeEquals(item.Hash, hash)))
                    throw new FormatException("RHB1 cross-type artifact hash aliases are forbidden.");
                keys[i] = (values[i].Item1, hash);
                if (!artifacts.Any(item => item.Kind == values[i].Item1 &&
                        CryptographicOperations.FixedTimeEquals(item.Hash, hash)))
                    artifacts.Add((values[i].Item1, values[i].Item2.ToArray(), hash));
            }
            linkKeys.Add((link, keys));
        }
        var sorted = artifacts.OrderBy(static item => (byte)item.Kind)
            .ThenBy(static item => item.Hash, ByteArrayComparer.Instance).ToArray();
        if (sorted.Length > ProductionMailboxRouteHistoryConstants.MaximumArtifacts)
            throw new FormatException("RHB1 authoring artifact count exceeds its bound.");
        ushort Index(ProductionMailboxRouteHistoryArtifactKind kind, byte[] hash) => checked((ushort)
            Array.FindIndex(sorted, item => item.Kind == kind &&
                CryptographicOperations.FixedTimeEquals(item.Hash, hash)));
        var predecessor = current.Checkpoint.TrustedCheckpoint.CurrentAuthorizationSequence;
        var builtLinks = new ProductionMailboxRouteHistoryLink[linkKeys.Count];
        for (var i = 0; i < linkKeys.Count; i++)
        {
            var item = linkKeys[i];
            var authorization = item.Link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                ? ProductionMailboxRouteAuthorizationCodec.DecodeAdvertisementV2(
                    item.Link.CanonicalAuthorization.Span).Sequence
                : ProductionMailboxRouteAuthorizationCodec.DecodeContinuityActivation(
                    item.Link.CanonicalAuthorization.Span).ActivationSequence;
            var expected = checked(predecessor + 1);
            if (authorization != expected)
                throw new FormatException("RHB1 authoring route sequence is not exact +1.");
            byte[] FindHash(ProductionMailboxRouteHistoryArtifactKind kind) =>
                item.Keys.Single(key => key.Kind == kind).Hash;
            builtLinks[i] = new()
            {
                AuthorizationKind = item.Link.AuthorizationKind,
                AuthorityIndex = Index(ProductionMailboxRouteHistoryArtifactKind.Authority,
                    FindHash(ProductionMailboxRouteHistoryArtifactKind.Authority)),
                RevocationsIndex = Index(ProductionMailboxRouteHistoryArtifactKind.Revocations,
                    FindHash(ProductionMailboxRouteHistoryArtifactKind.Revocations)),
                RouteCertificateIndex = Index(ProductionMailboxRouteHistoryArtifactKind.RouteCertificate,
                    FindHash(ProductionMailboxRouteHistoryArtifactKind.RouteCertificate)),
                RevocationCheckpointIndex = item.Link.AuthorizationKind ==
                    ProductionMailboxRouteAuthorizationKind.OwnerPRA2 ? ushort.MaxValue :
                    Index(ProductionMailboxRouteHistoryArtifactKind.RevocationCheckpoint,
                        FindHash(ProductionMailboxRouteHistoryArtifactKind.RevocationCheckpoint)),
                TransitionContextIndex = item.Link.AuthorizationKind ==
                    ProductionMailboxRouteAuthorizationKind.OwnerPRA2 ? ushort.MaxValue :
                    Index(ProductionMailboxRouteHistoryArtifactKind.TransitionContext,
                        FindHash(ProductionMailboxRouteHistoryArtifactKind.TransitionContext)),
                AuthorizationIndex = Index(
                    item.Link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                        ? ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement
                        : ProductionMailboxRouteHistoryArtifactKind.ContinuityActivation,
                    FindHash(item.Link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                        ? ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement
                        : ProductionMailboxRouteHistoryArtifactKind.ContinuityActivation)),
                PredecessorSequence = predecessor,
                NewSequence = authorization
            };
            predecessor = authorization;
        }
        return new()
        {
            BatchSequence = checked(current.LastCommittedBatchSequence + 1),
            PreviousCheckpointHash = current.CanonicalCheckpointHash.ToArray(),
            Artifacts = sorted.Select(static item => new ProductionMailboxRouteHistoryArtifact
            {
                Kind = item.Kind,
                CanonicalBytes = item.Bytes
            }).ToArray(),
            Links = builtLinks
        };
    }

    private static ProductionMailboxRouteHistoryAuthoringLink[] Freeze(
        IReadOnlyList<ProductionMailboxRouteHistoryAuthoringLink> links)
    {
        ArgumentNullException.ThrowIfNull(links);
        var count = links.Count;
        if (count is < 1 or > ProductionMailboxRouteHistoryConstants.MaximumLinks)
            throw new FormatException("RHB1 authoring link count is outside its bound.");
        var payloadBytes = 0;
        var uniquePayloads = new List<(ProductionMailboxRouteHistoryArtifactKind Kind, byte[] Hash)>();
        var expectedHashes = new byte[count][][];
        var sourceItems = new ProductionMailboxRouteHistoryAuthoringLink[count];
        for (var i = 0; i < count; i++)
        {
            var item = links[i] ?? throw new FormatException("RHB1 authoring link is null.");
            sourceItems[i] = item;
            Preflight(item);
            expectedHashes[i] = new byte[6][];
            expectedHashes[i][0] = AddUniquePayload(ProductionMailboxRouteHistoryArtifactKind.Authority,
                item.CanonicalAuthority.Span);
            expectedHashes[i][1] = AddUniquePayload(ProductionMailboxRouteHistoryArtifactKind.Revocations,
                item.CanonicalRevocations.Span);
            expectedHashes[i][2] = AddUniquePayload(ProductionMailboxRouteHistoryArtifactKind.RouteCertificate,
                item.CanonicalRouteCertificate.Span);
            if (item.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            {
                expectedHashes[i][3] = AddUniquePayload(ProductionMailboxRouteHistoryArtifactKind.RevocationCheckpoint,
                    item.CanonicalRevocationCheckpoint.Span);
                expectedHashes[i][4] = AddUniquePayload(ProductionMailboxRouteHistoryArtifactKind.TransitionContext,
                    item.CanonicalTransitionContext.Span);
            }
            else
            {
                expectedHashes[i][3] = [];
                expectedHashes[i][4] = [];
            }
            expectedHashes[i][5] = AddUniquePayload(item.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                    ? ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement
                    : ProductionMailboxRouteHistoryArtifactKind.ContinuityActivation,
                item.CanonicalAuthorization.Span);
        }
        if (links.Count != count)
            throw new FormatException("RHB1 authoring link collection mutated during preflight.");
        var ownedPayloads = new List<(ProductionMailboxRouteHistoryArtifactKind Kind, byte[] Hash, byte[] Bytes)>();
        var result = new ProductionMailboxRouteHistoryAuthoringLink[count];
        for (var i = 0; i < count; i++)
        {
            var item = sourceItems[i];
            result[i] = item with
            {
                CanonicalAuthority = FreezePayload(ProductionMailboxRouteHistoryArtifactKind.Authority,
                    item.CanonicalAuthority, expectedHashes[i][0]),
                CanonicalRevocations = FreezePayload(ProductionMailboxRouteHistoryArtifactKind.Revocations,
                    item.CanonicalRevocations, expectedHashes[i][1]),
                CanonicalRouteCertificate = FreezePayload(ProductionMailboxRouteHistoryArtifactKind.RouteCertificate,
                    item.CanonicalRouteCertificate, expectedHashes[i][2]),
                CanonicalRevocationCheckpoint = item.AuthorizationKind ==
                    ProductionMailboxRouteAuthorizationKind.DelegatedRCA1
                    ? FreezePayload(ProductionMailboxRouteHistoryArtifactKind.RevocationCheckpoint,
                        item.CanonicalRevocationCheckpoint, expectedHashes[i][3]) : ReadOnlyMemory<byte>.Empty,
                CanonicalTransitionContext = item.AuthorizationKind ==
                    ProductionMailboxRouteAuthorizationKind.DelegatedRCA1
                    ? FreezePayload(ProductionMailboxRouteHistoryArtifactKind.TransitionContext,
                        item.CanonicalTransitionContext, expectedHashes[i][4]) : ReadOnlyMemory<byte>.Empty,
                CanonicalAuthorization = FreezePayload(item.AuthorizationKind ==
                        ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                        ? ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement
                        : ProductionMailboxRouteHistoryArtifactKind.ContinuityActivation,
                    item.CanonicalAuthorization, expectedHashes[i][5])
            };
        }
        if (links.Count != count)
            throw new FormatException("RHB1 authoring link collection mutated.");
        return result;

        byte[] AddUniquePayload(ProductionMailboxRouteHistoryArtifactKind kind, ReadOnlySpan<byte> payload)
        {
            var hash = SHA256.HashData(payload);
            foreach (var existing in uniquePayloads)
            {
                if (!CryptographicOperations.FixedTimeEquals(existing.Hash, hash))
                    continue;
                if (existing.Kind != kind)
                    throw new FormatException("RHB1 cross-type artifact hash aliases are forbidden.");
                return hash;
            }
            payloadBytes = checked(payloadBytes + payload.Length);
            if (payloadBytes > ProductionMailboxRouteHistoryConstants.MaximumPayloadBytes)
                throw new FormatException("RHB1 authoring payload exceeds its aggregate bound.");
            uniquePayloads.Add((kind, hash));
            return hash;
        }

        ReadOnlyMemory<byte> FreezePayload(ProductionMailboxRouteHistoryArtifactKind kind,
            ReadOnlyMemory<byte> payload, byte[] expectedHash)
        {
            var owned = payload.ToArray();
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(owned), expectedHash))
                throw new FormatException("RHB1 authoring input mutated while it was frozen.");
            foreach (var existing in ownedPayloads)
            {
                if (!CryptographicOperations.FixedTimeEquals(existing.Hash, expectedHash))
                    continue;
                if (existing.Kind != kind)
                    throw new FormatException("RHB1 cross-type artifact hash aliases are forbidden.");
                CryptographicOperations.ZeroMemory(owned);
                return existing.Bytes;
            }
            ownedPayloads.Add((kind, expectedHash, owned));
            return owned;
        }
    }

    private static void Preflight(ProductionMailboxRouteHistoryAuthoringLink value)
    {
        static void Bounded(ReadOnlyMemory<byte> bytes, int maximum, string name)
        {
            if (bytes.Length is <= 0 || bytes.Length > maximum)
                throw new FormatException($"RHB1 {name} length is outside its bound.");
        }
        Bounded(value.CanonicalAuthority, ProductionMailboxAuthorityConstants.MaximumArtifactBytes, "PMA1");
        Bounded(value.CanonicalRevocations, ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes, "PMR1");
        if (value.CanonicalRouteCertificate.Length != ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength)
            throw new FormatException("RHB1 PRC1 length is invalid.");
        if (value.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
        {
            if (!value.CanonicalRevocationCheckpoint.IsEmpty || !value.CanonicalTransitionContext.IsEmpty ||
                value.CanonicalAuthorization.Length != ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length)
                throw new FormatException("RHB1 owner link shape is invalid.");
        }
        else if (value.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
        {
            if (value.CanonicalRevocationCheckpoint.Length != ProductionMailboxRouteContinuityConstants.CanonicalRevocationCheckpointLength ||
                value.CanonicalTransitionContext.Length != ProductionMailboxRouteAuthorizationConstants.CanonicalTransitionContextLength ||
                value.CanonicalAuthorization.Length != ProductionMailboxRouteAuthorizationConstants.CanonicalContinuityActivationLength)
                throw new FormatException("RHB1 delegated link shape is invalid.");
        }
        else
            throw new FormatException("RHB1 authorization kind is invalid.");
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static ByteArrayComparer Instance { get; } = new();
        public int Compare(byte[]? x, byte[]? y) => x is null ? (y is null ? 0 : -1) :
            y is null ? 1 : x.AsSpan().SequenceCompareTo(y);
    }
}
