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

internal sealed class ProductionMailboxRouteHistoryArtifactBindings
{
    private readonly byte[] _certificateHash;
    private readonly byte[] _authorizationHash;
    private readonly byte[] _revocationCheckpointHash;
    private readonly byte[] _transitionContextHash;

    internal ProductionMailboxRouteHistoryArtifactBindings(
        ProductionMailboxRouteAuthorizationKind authorizationKind,
        ReadOnlySpan<byte> certificateHash,
        ReadOnlySpan<byte> authorizationHash,
        ReadOnlySpan<byte> revocationCheckpointHash,
        ReadOnlySpan<byte> transitionContextHash)
    {
        AuthorizationKind = authorizationKind;
        _certificateHash = Fixed(certificateHash, false, "PRC1 hash");
        _authorizationHash = Fixed(authorizationHash, false, "authorization hash");
        var delegated = authorizationKind ==
            ProductionMailboxRouteAuthorizationKind.DelegatedRCA1;
        if (authorizationKind is not ProductionMailboxRouteAuthorizationKind.OwnerPRA2 and
            not ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            throw new FormatException("Route-history artifact binding kind is invalid.");
        _revocationCheckpointHash = Fixed(revocationCheckpointHash, !delegated, "RCH1 hash");
        _transitionContextHash = Fixed(transitionContextHash, !delegated, "RTC1 hash");
    }

    internal ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; }
    internal ReadOnlySpan<byte> CertificateHash => _certificateHash;
    internal ReadOnlySpan<byte> AuthorizationHash => _authorizationHash;
    internal ReadOnlySpan<byte> RevocationCheckpointHash => _revocationCheckpointHash;
    internal ReadOnlySpan<byte> TransitionContextHash => _transitionContextHash;

    internal static ProductionMailboxRouteHistoryArtifactBindings Initial(
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment)
    {
        var delegation = enrollment.Delegation;
        if (delegation.AnchorAuthorizationKind !=
            ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
            throw new FormatException("The route-history genesis authorization must be Owner PRA2.");
        return new(delegation.AnchorAuthorizationKind,
            delegation.AnchorCanonicalRouteCertificateHash.Span,
            delegation.AnchorCanonicalRouteAuthorizationHash.Span,
            ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
    }

    internal static ProductionMailboxRouteHistoryArtifactBindings FromBatch(
        ProductionMailboxRouteHistoryBatch batch)
    {
        ArgumentNullException.ThrowIfNull(batch);
        var link = batch.Links[^1];
        var certificateHash = SHA256.HashData(
            batch.Artifacts[link.RouteCertificateIndex].CanonicalBytes.Span);
        var authorizationHash = SHA256.HashData(
            batch.Artifacts[link.AuthorizationIndex].CanonicalBytes.Span);
        if (link.AuthorizationKind ==
            ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
            return new(link.AuthorizationKind, certificateHash, authorizationHash,
                ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
        var checkpointHash = SHA256.HashData(
            batch.Artifacts[link.RevocationCheckpointIndex].CanonicalBytes.Span);
        var transitionBytes =
            batch.Artifacts[link.TransitionContextIndex].CanonicalBytes.Span;
        var transition = ProductionMailboxRouteAuthorizationCodec
            .DecodeTransitionContext(transitionBytes);
        var transitionHash = ProductionMailboxRouteAuthorizationCodec
            .ComputeTransitionContextHash(transition);
        return new(link.AuthorizationKind, certificateHash, authorizationHash,
            checkpointHash, transitionHash);
    }

    private static byte[] Fixed(ReadOnlySpan<byte> value, bool empty, string name)
    {
        if (empty)
        {
            if (!value.IsEmpty)
                throw new FormatException($"Route-history {name} must be absent.");
            return [];
        }
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException($"Route-history {name} is invalid.");
        return value.ToArray();
    }
}

public sealed class VerifiedProductionMailboxRouteHistoryCursor
{
    private readonly VerifiedProductionMailboxRouteHistoryCheckpoint _checkpoint;

    internal VerifiedProductionMailboxRouteHistoryCursor(
        VerifiedProductionMailboxRouteHistoryCheckpoint checkpoint,
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment,
        ProductionMailboxRouteHistoryArtifactBindings artifactBindings)
    {
        _checkpoint = checkpoint ?? throw new ArgumentNullException(nameof(checkpoint));
        Enrollment = enrollment ?? throw new ArgumentNullException(nameof(enrollment));
        ArtifactBindings = artifactBindings ??
            throw new ArgumentNullException(nameof(artifactBindings));
    }

    internal VerifiedProductionMailboxRouteHistoryCursor(
        VerifiedProductionMailboxRouteHistoryCheckpoint checkpoint,
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment)
        : this(checkpoint, enrollment,
            ProductionMailboxRouteHistoryArtifactBindings.Initial(enrollment))
    {
    }

    internal VerifiedProductionMailboxRouteHistoryCheckpoint Checkpoint => _checkpoint;
    internal VerifiedProductionMailboxRouteContinuityEnrollment Enrollment { get; }
    internal ProductionMailboxRouteHistoryArtifactBindings ArtifactBindings { get; }
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

/// <summary>
/// Defensive data-only authorization substate for one exact route-history CAS side. It is not a
/// storage, durability, publication, or activation capability.
/// </summary>
public sealed class ProductionMailboxRouteHistoryDurableRouteState
{
    private readonly byte[] _canonicalRol;
    private readonly byte[] _rolHash;
    private readonly byte[] _network;
    private readonly byte[] _route;
    private readonly byte[] _delegationHash;
    private readonly byte[] _acceptanceHash;
    private readonly byte[] _authorizationHash;
    private readonly byte[] _ownerRevocationHead;
    private readonly byte[] _authorityHash;
    private readonly byte[] _revocationHead;
    private readonly byte[] _revocationSnapshotHash;
    private readonly byte[] _certificateHash;
    private readonly byte[] _revocationCheckpointHash;
    private readonly byte[] _transitionContextHash;

    internal ProductionMailboxRouteHistoryDurableRouteState(
        VerifiedProductionMailboxRouteHistoryCursor cursor)
    {
        var checkpoint = cursor.Checkpoint.TrustedCheckpoint;
        var canonicalRol = cursor.CanonicalCurrentRouteOriginLkg();
        var rol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(canonicalRol);
        var computedHash = ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(rol);
        if (!CryptographicOperations.FixedTimeEquals(computedHash,
                checkpoint.CurrentRouteOriginLkgHash.Span) ||
            rol.AuthorizationKind != checkpoint.CurrentAuthorizationKind ||
            rol.AuthorizationKind != cursor.ArtifactBindings.AuthorizationKind ||
            !CryptographicOperations.FixedTimeEquals(rol.CanonicalAuthorizationHash.Span,
                checkpoint.CurrentCanonicalAuthorizationHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(rol.CanonicalAuthorizationHash.Span,
                cursor.ArtifactBindings.AuthorizationHash) ||
            rol.AuthorizationSequence != checkpoint.CurrentAuthorizationSequence)
            throw new FormatException("Route-history durable ROL1 state is inconsistent.");
        _canonicalRol = canonicalRol;
        _rolHash = computedHash;
        _network = rol.NetworkId.ToArray();
        _route = rol.RouteDomainHash.ToArray();
        _delegationHash = rol.CanonicalDelegationHash.ToArray();
        _acceptanceHash = rol.CanonicalDelegationAcceptanceHash.ToArray();
        AuthorizationKind = rol.AuthorizationKind;
        _authorizationHash = rol.CanonicalAuthorizationHash.ToArray();
        AuthorizationSequence = rol.AuthorizationSequence;
        RouteVerifiedAtUnixSeconds = rol.RouteVerifiedAtUnixSeconds;
        LocalCommitGeneration = rol.LocalCommitGeneration;
        OwnerRevocationGeneration = rol.OwnerRevocationGeneration;
        _ownerRevocationHead = rol.OwnerRevocationHeadHash.ToArray();
        AuthorityGeneration = checkpoint.CurrentAuthorityGeneration;
        _authorityHash = checkpoint.CurrentCanonicalAuthorityHash.ToArray();
        RevocationGeneration = checkpoint.CurrentRevocationGeneration;
        _revocationHead = checkpoint.CurrentRevocationHeadHash.ToArray();
        _revocationSnapshotHash = checkpoint.CurrentRevocationSnapshotHash.ToArray();
        _certificateHash = cursor.ArtifactBindings.CertificateHash.ToArray();
        _revocationCheckpointHash =
            cursor.ArtifactBindings.RevocationCheckpointHash.ToArray();
        _transitionContextHash = cursor.ArtifactBindings.TransitionContextHash.ToArray();
    }

    public ReadOnlyMemory<byte> CanonicalRouteOriginLkg => _canonicalRol.ToArray();
    public ReadOnlyMemory<byte> CanonicalRouteOriginLkgHash => _rolHash.ToArray();
    public ReadOnlyMemory<byte> NetworkId => _network.ToArray();
    public ReadOnlyMemory<byte> RouteDomainHash => _route.ToArray();
    public ReadOnlyMemory<byte> CanonicalDelegationHash => _delegationHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalDelegationAcceptanceHash => _acceptanceHash.ToArray();
    public ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; }
    public ReadOnlyMemory<byte> CanonicalAuthorizationHash => _authorizationHash.ToArray();
    public ulong AuthorizationSequence { get; }
    public ulong RouteVerifiedAtUnixSeconds { get; }
    public ulong LocalCommitGeneration { get; }
    public ulong OwnerRevocationGeneration { get; }
    public ReadOnlyMemory<byte> OwnerRevocationHeadHash => _ownerRevocationHead.ToArray();
    public ulong AuthorityGeneration { get; }
    public ReadOnlyMemory<byte> CanonicalAuthorityHash => _authorityHash.ToArray();
    public ulong RevocationGeneration { get; }
    public ReadOnlyMemory<byte> RevocationHeadHash => _revocationHead.ToArray();
    public ReadOnlyMemory<byte> RevocationSnapshotHash => _revocationSnapshotHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalRouteCertificateHash => _certificateHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalOwnerAdvertisementHash =>
        AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
            ? _authorizationHash.ToArray() : ReadOnlyMemory<byte>.Empty;
    public ReadOnlyMemory<byte> CanonicalRevocationCheckpointHash =>
        _revocationCheckpointHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalTransitionContextHash =>
        _transitionContextHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalContinuityActivationHash =>
        AuthorizationKind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1
            ? _authorizationHash.ToArray() : ReadOnlyMemory<byte>.Empty;
}

/// <summary>Defensive cumulative RHB1 state for one exact side of a caller-owned CAS.</summary>
public sealed class ProductionMailboxRouteHistoryCumulativeState
{
    private readonly byte[] _transcriptHead;
    private readonly byte[] _lastBatchHash;

    internal ProductionMailboxRouteHistoryCumulativeState(
        VerifiedProductionMailboxRouteHistoryCursor cursor)
    {
        var checkpoint = cursor.Checkpoint.TrustedCheckpoint;
        LastCommittedBatchSequence = checkpoint.LastCommittedBatchSequence;
        CumulativeCommittedBatchCount = checkpoint.CumulativeCommittedBatchCount;
        CumulativeVerifiedRouteLinkCount = checkpoint.CumulativeVerifiedRouteLinkCount;
        CumulativeCanonicalPayloadBytes = checkpoint.CumulativeCanonicalPayloadBytes;
        _transcriptHead = checkpoint.HistoryTranscriptHead.ToArray();
        _lastBatchHash = checkpoint.LastCommittedBatchHash.ToArray();
    }

    public ulong LastCommittedBatchSequence { get; }
    public ulong CumulativeCommittedBatchCount { get; }
    public ulong CumulativeVerifiedRouteLinkCount { get; }
    public ulong CumulativeCanonicalPayloadBytes { get; }
    public ReadOnlyMemory<byte> HistoryTranscriptHead => _transcriptHead.ToArray();
    public ReadOnlyMemory<byte> LastCommittedBatchHash => _lastBatchHash.ToArray();
}

/// <summary>
/// Exact verified artifact tuple selected by the final link of one canonical RHB1.
/// </summary>
public sealed class ProductionMailboxRouteHistoryFinalArtifacts
{
    private readonly byte[] _authority;
    private readonly byte[] _revocations;
    private readonly byte[] _certificate;
    private readonly byte[] _ownerAdvertisement;
    private readonly byte[] _revocationCheckpoint;
    private readonly byte[] _transitionContext;
    private readonly byte[] _continuityActivation;
    private readonly byte[] _authorityHash;
    private readonly byte[] _revocationsHash;
    private readonly byte[] _certificateHash;
    private readonly byte[] _ownerAdvertisementHash;
    private readonly byte[] _revocationCheckpointHash;
    private readonly byte[] _transitionContextSha256;
    private readonly byte[] _transitionContextHash;
    private readonly byte[] _continuityActivationHash;

    internal ProductionMailboxRouteHistoryFinalArtifacts(
        ProductionMailboxRouteHistoryBatch batch,
        ProductionMailboxRouteHistoryDurableRouteState nextState)
    {
        var link = batch.Links[^1];
        AuthorizationKind = link.AuthorizationKind;
        _authority = batch.Artifacts[link.AuthorityIndex].CanonicalBytes.ToArray();
        _revocations = batch.Artifacts[link.RevocationsIndex].CanonicalBytes.ToArray();
        _certificate = batch.Artifacts[link.RouteCertificateIndex].CanonicalBytes.ToArray();
        _authorityHash = SHA256.HashData(_authority);
        _revocationsHash = SHA256.HashData(_revocations);
        _certificateHash = SHA256.HashData(_certificate);
        if (AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
        {
            _ownerAdvertisement =
                batch.Artifacts[link.AuthorizationIndex].CanonicalBytes.ToArray();
            _ownerAdvertisementHash = SHA256.HashData(_ownerAdvertisement);
            _revocationCheckpoint = [];
            _transitionContext = [];
            _continuityActivation = [];
            _revocationCheckpointHash = [];
            _transitionContextSha256 = [];
            _transitionContextHash = [];
            _continuityActivationHash = [];
        }
        else
        {
            _ownerAdvertisement = [];
            _ownerAdvertisementHash = [];
            _revocationCheckpoint =
                batch.Artifacts[link.RevocationCheckpointIndex].CanonicalBytes.ToArray();
            _transitionContext =
                batch.Artifacts[link.TransitionContextIndex].CanonicalBytes.ToArray();
            _continuityActivation =
                batch.Artifacts[link.AuthorizationIndex].CanonicalBytes.ToArray();
            _revocationCheckpointHash = SHA256.HashData(_revocationCheckpoint);
            _transitionContextSha256 = SHA256.HashData(_transitionContext);
            var rtc = ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(
                _transitionContext);
            _transitionContextHash =
                ProductionMailboxRouteAuthorizationCodec.ComputeTransitionContextHash(rtc);
            _continuityActivationHash = SHA256.HashData(_continuityActivation);
        }
        if (!CryptographicOperations.FixedTimeEquals(_authorityHash,
                nextState.CanonicalAuthorityHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(_revocationsHash,
                nextState.RevocationSnapshotHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(_certificateHash,
                nextState.CanonicalRouteCertificateHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                    ? _ownerAdvertisementHash : _continuityActivationHash,
                nextState.CanonicalAuthorizationHash.Span) ||
            !OptionalEqual(_revocationCheckpointHash,
                nextState.CanonicalRevocationCheckpointHash.Span) ||
            !OptionalEqual(_transitionContextHash,
                nextState.CanonicalTransitionContextHash.Span))
            throw new FormatException("RHB1 final artifacts differ from the next durable state.");
    }

    public ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; }
    public ReadOnlyMemory<byte> CanonicalAuthority => _authority.ToArray();
    public ReadOnlyMemory<byte> CanonicalAuthorityHash => _authorityHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalRevocations => _revocations.ToArray();
    public ReadOnlyMemory<byte> CanonicalRevocationsHash => _revocationsHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalRouteCertificate => _certificate.ToArray();
    public ReadOnlyMemory<byte> CanonicalRouteCertificateHash => _certificateHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalOwnerAdvertisement => _ownerAdvertisement.ToArray();
    public ReadOnlyMemory<byte> CanonicalOwnerAdvertisementHash =>
        _ownerAdvertisementHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalRevocationCheckpoint =>
        _revocationCheckpoint.ToArray();
    public ReadOnlyMemory<byte> CanonicalRevocationCheckpointHash =>
        _revocationCheckpointHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalTransitionContext => _transitionContext.ToArray();
    public ReadOnlyMemory<byte> CanonicalTransitionContextSha256 =>
        _transitionContextSha256.ToArray();
    public ReadOnlyMemory<byte> CanonicalTransitionContextHash =>
        _transitionContextHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalContinuityActivation =>
        _continuityActivation.ToArray();
    public ReadOnlyMemory<byte> CanonicalContinuityActivationHash =>
        _continuityActivationHash.ToArray();

    internal ReadOnlySpan<byte> TrustedCanonicalAuthority => _authority;
    internal ReadOnlySpan<byte> TrustedCanonicalRevocations => _revocations;
    internal ReadOnlySpan<byte> TrustedCanonicalRouteCertificate => _certificate;
    internal ReadOnlySpan<byte> TrustedCanonicalOwnerAdvertisement => _ownerAdvertisement;
    internal ReadOnlySpan<byte> TrustedCanonicalRevocationCheckpoint => _revocationCheckpoint;
    internal ReadOnlySpan<byte> TrustedCanonicalTransitionContext => _transitionContext;
    internal ReadOnlySpan<byte> TrustedCanonicalContinuityActivation => _continuityActivation;
    internal ReadOnlySpan<byte> TrustedCanonicalTransitionContextHash => _transitionContextHash;

    private static bool OptionalEqual(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        (left.IsEmpty || CryptographicOperations.FixedTimeEquals(left, right));
}

public sealed class ProductionMailboxRouteHistoryBatchCommitPlan
{
    private readonly byte[] _canonicalBatch;
    private readonly byte[] _canonicalBatchHash;
    private readonly byte[] _expectedCurrentCheckpoint;
    private readonly byte[] _expectedCurrentCheckpointHash;
    private readonly byte[] _expectedCurrentRouteOriginLkgHash;
    private readonly byte[] _nextCheckpoint;
    private readonly byte[] _nextCheckpointHash;
    private readonly byte[] _planHash;
    private readonly ProductionMailboxRouteHistoryProtectedRestoreContext _currentContext;
    private readonly ProductionMailboxRouteHistoryProtectedRestoreContext _nextContext;

    internal ProductionMailboxRouteHistoryBatchCommitPlan(
        byte[] canonicalBatch,
        ProductionMailboxRouteHistoryBatch decodedBatch,
        VerifiedProductionMailboxRouteHistoryCursor currentCursor,
        VerifiedProductionMailboxRouteHistoryCursor nextCursor)
    {
        _canonicalBatch = canonicalBatch ??
            throw new ArgumentNullException(nameof(canonicalBatch));
        _canonicalBatchHash = SHA256.HashData(_canonicalBatch);
        _expectedCurrentCheckpoint = currentCursor.CanonicalCheckpoint.ToArray();
        _expectedCurrentCheckpointHash = currentCursor.CanonicalCheckpointHash.ToArray();
        _expectedCurrentRouteOriginLkgHash = currentCursor.Checkpoint.TrustedCheckpoint
            .CurrentRouteOriginLkgHash.ToArray();
        ExpectedCurrentBatchSequence = currentCursor.LastCommittedBatchSequence;
        NextCursor = nextCursor ?? throw new ArgumentNullException(nameof(nextCursor));
        _nextCheckpoint = nextCursor.CanonicalCheckpoint.ToArray();
        _nextCheckpointHash = nextCursor.CanonicalCheckpointHash.ToArray();
        NextBatchSequence = nextCursor.LastCommittedBatchSequence;
        CurrentDurableRouteState = new(currentCursor);
        NextDurableRouteState = new(nextCursor);
        CurrentCumulativeState = new(currentCursor);
        NextCumulativeState = new(nextCursor);
        FinalArtifacts = new(decodedBatch ??
            throw new ArgumentNullException(nameof(decodedBatch)), NextDurableRouteState);
        _currentContext = currentCursor.ToProtectedRestoreContext();
        _nextContext = nextCursor.ToProtectedRestoreContext();
        _planHash = ComputePlanHash();
    }

    public ReadOnlyMemory<byte> CanonicalBatch => _canonicalBatch.ToArray();
    public ReadOnlyMemory<byte> CanonicalBatchHash => _canonicalBatchHash.ToArray();
    public ReadOnlyMemory<byte> ExpectedCurrentCheckpoint => _expectedCurrentCheckpoint.ToArray();
    public ReadOnlyMemory<byte> ExpectedCurrentCheckpointHash => _expectedCurrentCheckpointHash.ToArray();
    public ReadOnlyMemory<byte> ExpectedCurrentRouteOriginLkgHash =>
        _expectedCurrentRouteOriginLkgHash.ToArray();
    public ReadOnlyMemory<byte> ExpectedCurrentRouteOriginLkg =>
        CurrentDurableRouteState.CanonicalRouteOriginLkg;
    public ulong ExpectedCurrentBatchSequence { get; }
    public ulong NextBatchSequence { get; }
    public VerifiedProductionMailboxRouteHistoryCursor NextCursor { get; }
    public ProductionMailboxRouteHistoryDurableRouteState CurrentDurableRouteState { get; }
    public ProductionMailboxRouteHistoryDurableRouteState NextDurableRouteState { get; }
    public ProductionMailboxRouteHistoryCumulativeState CurrentCumulativeState { get; }
    public ProductionMailboxRouteHistoryCumulativeState NextCumulativeState { get; }
    public ProductionMailboxRouteHistoryFinalArtifacts FinalArtifacts { get; }
    public ReadOnlyMemory<byte> PlanHash => _planHash.ToArray();

    internal ReadOnlySpan<byte> TrustedCanonicalBatch => _canonicalBatch;
    internal ReadOnlySpan<byte> TrustedCanonicalBatchHash => _canonicalBatchHash;
    internal ReadOnlySpan<byte> TrustedExpectedCurrentCheckpoint => _expectedCurrentCheckpoint;
    internal ReadOnlySpan<byte> TrustedExpectedCurrentCheckpointHash =>
        _expectedCurrentCheckpointHash;
    internal ReadOnlySpan<byte> TrustedExpectedCurrentRouteOriginLkgHash =>
        _expectedCurrentRouteOriginLkgHash;
    internal ReadOnlySpan<byte> TrustedNextCheckpoint => _nextCheckpoint;
    internal ReadOnlySpan<byte> TrustedNextCheckpointHash => _nextCheckpointHash;
    internal ReadOnlySpan<byte> TrustedPlanHash => _planHash;
    internal ProductionMailboxRouteHistoryProtectedRestoreContext TrustedCurrentContext =>
        _currentContext;

    internal void RevalidateOwnedForHistoryTransport()
    {
        if (_canonicalBatch.Length < ProductionMailboxRouteHistoryConstants.HeaderLength ||
            _canonicalBatch.Length > ProductionMailboxRouteHistoryConstants.MaximumEncodedBytes ||
            _expectedCurrentCheckpoint.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength ||
            _expectedCurrentCheckpointHash.Length != 32 ||
            _expectedCurrentRouteOriginLkgHash.Length != 32 ||
            _nextCheckpoint.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength ||
            _nextCheckpointHash.Length != 32 ||
            _planHash.Length != 32 || ExpectedCurrentBatchSequence == ulong.MaxValue ||
            NextBatchSequence != checked(ExpectedCurrentBatchSequence + 1))
            throw new FormatException("History transport plan framing or sequence is invalid.");
        ProductionMailboxRouteHistoryCodec.PreflightCanonical(_canonicalBatch,
            validateNestedFraming: true,
            CurrentDurableRouteState.AuthorizationSequence);
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(_canonicalBatch),
                _canonicalBatchHash))
            throw new FormatException("History transport batch hash is invalid.");
        var checkpoint = ProductionMailboxRouteContinuityCodec.DecodeRouteHistoryCheckpoint(
            _nextCheckpoint);
        if (!CryptographicOperations.FixedTimeEquals(
                ProductionMailboxRouteContinuityCodec.ComputeRouteHistoryCheckpointHash(checkpoint),
                _nextCheckpointHash) ||
            checkpoint.LastCommittedBatchSequence != NextBatchSequence ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.LastCommittedBatchHash.Span,
                _canonicalBatchHash) ||
            !CryptographicOperations.FixedTimeEquals(ComputePlanHash(), _planHash))
            throw new FormatException("History transport plan owned state is inconsistent.");
    }

    public ProductionMailboxRouteHistoryProtectedRestoreContext
        ToExpectedCurrentProtectedRestoreContext() => Clone(_currentContext);

    /// <summary>Exports the exact post-commit durable restore tuple.</summary>
    public ProductionMailboxRouteHistoryProtectedRestoreContext ToProtectedRestoreContext() =>
        Clone(_nextContext);

    private byte[] ComputePlanHash()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(
            "Deep/production-mailbox/route-history-batch-commit-plan/v1"u8);
        AppendBlob(hash, _canonicalBatch);
        AppendBlob(hash, _expectedCurrentCheckpoint);
        AppendContext(hash, _currentContext);
        AppendRouteState(hash, CurrentDurableRouteState);
        AppendCumulativeState(hash, CurrentCumulativeState);
        AppendBlob(hash, _nextCheckpoint);
        AppendContext(hash, _nextContext);
        AppendRouteState(hash, NextDurableRouteState);
        AppendCumulativeState(hash, NextCumulativeState);
        hash.AppendData([(byte)FinalArtifacts.AuthorizationKind]);
        AppendBlob(hash, FinalArtifacts.TrustedCanonicalAuthority);
        AppendBlob(hash, FinalArtifacts.TrustedCanonicalRevocations);
        AppendBlob(hash, FinalArtifacts.TrustedCanonicalRouteCertificate);
        AppendBlob(hash, FinalArtifacts.TrustedCanonicalOwnerAdvertisement);
        AppendBlob(hash, FinalArtifacts.TrustedCanonicalRevocationCheckpoint);
        AppendBlob(hash, FinalArtifacts.TrustedCanonicalTransitionContext);
        AppendBlob(hash, FinalArtifacts.TrustedCanonicalContinuityActivation);
        AppendBlob(hash, FinalArtifacts.TrustedCanonicalTransitionContextHash);
        return hash.GetHashAndReset();
    }

    private static void AppendContext(IncrementalHash hash,
        ProductionMailboxRouteHistoryProtectedRestoreContext value)
    {
        AppendBlob(hash, value.CanonicalCheckpoint.Span);
        AppendBlob(hash, value.CanonicalCheckpointHash.Span);
        AppendU64(hash, value.LastCommittedBatchSequence);
        AppendBlob(hash, value.LastCommittedBatchHash.Span);
        AppendBlob(hash, value.CurrentRouteOriginLkgHash.Span);
        AppendBlob(hash, value.EnrollmentCanonicalDelegationHash.Span);
        AppendBlob(hash, value.EnrollmentCanonicalAcceptanceHash.Span);
        AppendBlob(hash, value.NetworkId.Span);
        AppendBlob(hash, value.RouteDomainHash.Span);
        AppendBlob(hash, value.DelegationHistoryBinding.Span);
        AppendBlob(hash, value.PinnedMrXPublicKeySha256.Span);
        AppendU64(hash, value.CurrentAuthorityGeneration);
        AppendBlob(hash, value.CurrentCanonicalAuthorityHash.Span);
        AppendU64(hash, value.CurrentRevocationGeneration);
        AppendBlob(hash, value.CurrentRevocationHeadHash.Span);
        AppendBlob(hash, value.CurrentRevocationSnapshotHash.Span);
    }

    private static void AppendRouteState(IncrementalHash hash,
        ProductionMailboxRouteHistoryDurableRouteState value)
    {
        AppendBlob(hash, value.CanonicalRouteOriginLkg.Span);
        AppendBlob(hash, value.CanonicalRouteOriginLkgHash.Span);
        hash.AppendData([(byte)value.AuthorizationKind]);
        AppendBlob(hash, value.CanonicalAuthorizationHash.Span);
        AppendU64(hash, value.AuthorizationSequence);
        AppendU64(hash, value.RouteVerifiedAtUnixSeconds);
        AppendU64(hash, value.LocalCommitGeneration);
        AppendU64(hash, value.OwnerRevocationGeneration);
        AppendBlob(hash, value.OwnerRevocationHeadHash.Span);
        AppendU64(hash, value.AuthorityGeneration);
        AppendBlob(hash, value.CanonicalAuthorityHash.Span);
        AppendU64(hash, value.RevocationGeneration);
        AppendBlob(hash, value.RevocationHeadHash.Span);
        AppendBlob(hash, value.RevocationSnapshotHash.Span);
        AppendBlob(hash, value.CanonicalRouteCertificateHash.Span);
        AppendBlob(hash, value.CanonicalRevocationCheckpointHash.Span);
        AppendBlob(hash, value.CanonicalTransitionContextHash.Span);
    }

    private static void AppendCumulativeState(IncrementalHash hash,
        ProductionMailboxRouteHistoryCumulativeState value)
    {
        AppendU64(hash, value.LastCommittedBatchSequence);
        AppendU64(hash, value.CumulativeCommittedBatchCount);
        AppendU64(hash, value.CumulativeVerifiedRouteLinkCount);
        AppendU64(hash, value.CumulativeCanonicalPayloadBytes);
        AppendBlob(hash, value.HistoryTranscriptHead.Span);
        AppendBlob(hash, value.LastCommittedBatchHash.Span);
    }

    private static void AppendBlob(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(
            length, checked((uint)value.Length));
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static void AppendU64(IncrementalHash hash, ulong value)
    {
        Span<byte> encoded = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        hash.AppendData(encoded);
    }

    private static ProductionMailboxRouteHistoryProtectedRestoreContext Clone(
        ProductionMailboxRouteHistoryProtectedRestoreContext value) => new(
        value.CanonicalCheckpoint, value.CanonicalCheckpointHash,
        value.LastCommittedBatchSequence, value.LastCommittedBatchHash,
        value.CurrentRouteOriginLkgHash, value.EnrollmentCanonicalDelegationHash,
        value.EnrollmentCanonicalAcceptanceHash, value.NetworkId, value.RouteDomainHash,
        value.DelegationHistoryBinding, value.PinnedMrXPublicKeySha256,
        value.CurrentAuthorityGeneration, value.CurrentCanonicalAuthorityHash,
        value.CurrentRevocationGeneration, value.CurrentRevocationHeadHash,
        value.CurrentRevocationSnapshotHash);
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
    internal static VerifiedProductionMailboxRouteHistoryCursor CreateInitialCursor(
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
        var verified = VerifyCore(current, canonical, requireNext: true);
        return new(verified.Advance.CanonicalBatch,
            verified.Advance.Batch!, current, verified.Cursor);
    }

    /// <summary>
    /// Verifies one exact next canonical RHB1 against a sealed predecessor and returns the complete
    /// defensive cryptographic data required by a caller-owned atomic history/route-state CAS.
    /// This method does not attest storage, durability, replay handling, or publication.
    /// </summary>
    public static ProductionMailboxRouteHistoryBatchCommitPlan VerifyNextBatchForCommit(
        VerifiedProductionMailboxRouteHistoryCursor current,
        ReadOnlySpan<byte> canonicalBatch)
    {
        ArgumentNullException.ThrowIfNull(current);
        var verified = VerifyCore(current, canonicalBatch, requireNext: true);
        return new(verified.Advance.CanonicalBatch,
            verified.Advance.Batch!, current, verified.Cursor);
    }

    internal static VerifiedProductionMailboxRouteHistoryCursor VerifyBatch(
        VerifiedProductionMailboxRouteHistoryCursor current,
        ReadOnlySpan<byte> canonicalBatch)
    {
        ArgumentNullException.ThrowIfNull(current);
        return VerifyCore(current, canonicalBatch, requireNext: false).Cursor;
    }

    /// <summary>
    /// Restores a cursor only from the one sealed historical anchor committed with the RHC1.
    /// Independent enrollment/control-plane handles are not accepted at the public boundary.
    /// </summary>
    public static VerifiedProductionMailboxRouteHistoryCursor RestoreCursor(
        ReadOnlySpan<byte> canonicalCheckpoint,
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        ProductionMailboxRouteHistoryProtectedRestoreContext protectedState)
    {
        ArgumentNullException.ThrowIfNull(anchor);
        var restored = RestoreCursor(canonicalCheckpoint, anchor.EnrollmentState.Enrollment,
            anchor.AnchorAuthority, anchor.AnchorRevocations, protectedState);
        var checkpoint = restored.Checkpoint.TrustedCheckpoint;
        var delegation = restored.Enrollment.Delegation;
        if (checkpoint.LastCommittedBatchSequence != 0 ||
            checkpoint.CurrentAuthorizationKind != delegation.AnchorAuthorizationKind ||
            checkpoint.CurrentAuthorizationSequence !=
                delegation.AnchorRouteAuthorizationSequence ||
            !CryptographicOperations.FixedTimeEquals(
                checkpoint.CurrentCanonicalAuthorizationHash.Span,
                delegation.AnchorCanonicalRouteAuthorizationHash.Span))
            throw new FormatException(
                "Public RHC1 restore accepts only the exact genesis checkpoint; replay later batches sequentially.");
        return restored;
    }

    internal static VerifiedProductionMailboxRouteHistoryCursor RestoreCursor(
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

    private static (VerifiedProductionMailboxRouteHistoryCursor Cursor,
        ProductionMailboxRouteHistoryAdvanceResult Advance) VerifyCore(
        VerifiedProductionMailboxRouteHistoryCursor current,
        ReadOnlySpan<byte> canonicalBatch,
        bool requireNext)
    {
        var old = current.Checkpoint.TrustedCheckpoint;
        var verifier = new ProductionMailboxRouteHistoryCryptographicLinkVerifier(
            old.NetworkId, old.RouteDomainHash, old.PinnedMrXPublicKeySha256, current.Enrollment);
        var advance = requireNext
            ? ProductionMailboxRouteHistoryVerifier.AdvanceNextForCommit(
                canonicalBatch, current.Checkpoint, verifier)
            : ProductionMailboxRouteHistoryVerifier.AdvanceWithReplay(
                canonicalBatch, current.Checkpoint, verifier);
        if (!advance.Advanced)
            return (current, advance);
        var bindings = ProductionMailboxRouteHistoryArtifactBindings.FromBatch(
            advance.Batch!);
        return (new(advance.Checkpoint, current.Enrollment, bindings), advance);
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
        Bounded(value.CanonicalAuthority, ProductionMailboxAuthorityConstants.MaximumArtifactBytes, ProtocolMagic.PMA1);
        Bounded(value.CanonicalRevocations, ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes, ProtocolMagic.PMR1);
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
