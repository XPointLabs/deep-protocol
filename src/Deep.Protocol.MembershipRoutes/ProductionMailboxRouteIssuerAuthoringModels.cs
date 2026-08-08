using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

/// <summary>Capability-scoped RDA1 request. Only the protocol authoring flow can create it.</summary>
public sealed class ProductionMailboxRda1SigningRequest
{
    private readonly byte[] _signingBytes;

    internal ProductionMailboxRda1SigningRequest(ReadOnlySpan<byte> signingBytes) =>
        _signingBytes = signingBytes.ToArray();

    public ReadOnlyMemory<byte> SigningBytes => _signingBytes.ToArray();

    internal void Clear() => CryptographicOperations.ZeroMemory(_signingBytes);
}

/// <summary>Capability-scoped RCH1 request. Only the protocol authoring flow can create it.</summary>
public sealed class ProductionMailboxRch1SigningRequest
{
    private readonly byte[] _signingBytes;

    internal ProductionMailboxRch1SigningRequest(ReadOnlySpan<byte> signingBytes) =>
        _signingBytes = signingBytes.ToArray();

    public ReadOnlyMemory<byte> SigningBytes => _signingBytes.ToArray();

    internal void Clear() => CryptographicOperations.ZeroMemory(_signingBytes);
}

/// <summary>Capability-scoped RCA1 request. Only the protocol authoring flow can create it.</summary>
public sealed class ProductionMailboxRca1SigningRequest
{
    private readonly byte[] _signingBytes;

    internal ProductionMailboxRca1SigningRequest(ReadOnlySpan<byte> signingBytes) =>
        _signingBytes = signingBytes.ToArray();

    public ReadOnlyMemory<byte> SigningBytes => _signingBytes.ToArray();

    internal void Clear() => CryptographicOperations.ZeroMemory(_signingBytes);
}

public delegate ValueTask<int> ProductionMailboxRda1Signer(
    ProductionMailboxRda1SigningRequest request,
    Memory<byte> signatureDestination,
    CancellationToken cancellationToken);

public delegate ValueTask<int> ProductionMailboxRch1Signer(
    ProductionMailboxRch1SigningRequest request,
    Memory<byte> signatureDestination,
    CancellationToken cancellationToken);

public delegate ValueTask<int> ProductionMailboxRca1Signer(
    ProductionMailboxRca1SigningRequest request,
    Memory<byte> signatureDestination,
    CancellationToken cancellationToken);

/// <summary>
/// Exact one-shot CAS plan for the caller's protected enrollment store. The committer must compare
/// every expected predecessor field and atomically publish the exact RCD1/RDA1/post-RDA ROL1 set.
/// </summary>
public sealed class ProductionMailboxRouteContinuityEnrollmentCommitPlan
{
    private readonly byte[] _expectedOldRouteOriginLkg;
    private readonly byte[] _expectedOldRouteOriginLkgHash;
    private readonly byte[] _expectedPreviousDelegationHash;
    private readonly byte[] _canonicalDelegation;
    private readonly byte[] _canonicalDelegationHash;
    private readonly byte[] _canonicalAcceptance;
    private readonly byte[] _canonicalAcceptanceHash;
    private readonly byte[] _canonicalEnrolledRouteOriginLkg;
    private readonly byte[] _enrolledRouteOriginLkgHash;

    internal ProductionMailboxRouteContinuityEnrollmentCommitPlan(
        ReadOnlySpan<byte> expectedOldRouteOriginLkg,
        ReadOnlySpan<byte> expectedOldRouteOriginLkgHash,
        ulong expectedOldLocalCommitGeneration,
        ulong expectedPreviousDelegationSequence,
        ReadOnlySpan<byte> expectedPreviousDelegationHash,
        ReadOnlySpan<byte> canonicalDelegation,
        ReadOnlySpan<byte> canonicalDelegationHash,
        ReadOnlySpan<byte> canonicalAcceptance,
        ReadOnlySpan<byte> canonicalAcceptanceHash,
        ReadOnlySpan<byte> canonicalEnrolledRouteOriginLkg,
        ReadOnlySpan<byte> enrolledRouteOriginLkgHash)
    {
        _expectedOldRouteOriginLkg = expectedOldRouteOriginLkg.ToArray();
        _expectedOldRouteOriginLkgHash = expectedOldRouteOriginLkgHash.ToArray();
        ExpectedOldLocalCommitGeneration = expectedOldLocalCommitGeneration;
        ExpectedPreviousDelegationSequence = expectedPreviousDelegationSequence;
        _expectedPreviousDelegationHash = expectedPreviousDelegationHash.ToArray();
        _canonicalDelegation = canonicalDelegation.ToArray();
        _canonicalDelegationHash = canonicalDelegationHash.ToArray();
        _canonicalAcceptance = canonicalAcceptance.ToArray();
        _canonicalAcceptanceHash = canonicalAcceptanceHash.ToArray();
        _canonicalEnrolledRouteOriginLkg = canonicalEnrolledRouteOriginLkg.ToArray();
        _enrolledRouteOriginLkgHash = enrolledRouteOriginLkgHash.ToArray();
    }

    public ReadOnlyMemory<byte> ExpectedOldRouteOriginLkg =>
        _expectedOldRouteOriginLkg.ToArray();
    public ReadOnlyMemory<byte> ExpectedOldRouteOriginLkgHash =>
        _expectedOldRouteOriginLkgHash.ToArray();
    public ulong ExpectedOldLocalCommitGeneration { get; }
    public ulong ExpectedPreviousDelegationSequence { get; }
    public ReadOnlyMemory<byte> ExpectedPreviousDelegationHash =>
        _expectedPreviousDelegationHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalDelegation => _canonicalDelegation.ToArray();
    public ReadOnlyMemory<byte> CanonicalDelegationHash => _canonicalDelegationHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalAcceptance => _canonicalAcceptance.ToArray();
    public ReadOnlyMemory<byte> CanonicalAcceptanceHash => _canonicalAcceptanceHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalEnrolledRouteOriginLkg =>
        _canonicalEnrolledRouteOriginLkg.ToArray();
    public ReadOnlyMemory<byte> EnrolledRouteOriginLkgHash =>
        _enrolledRouteOriginLkgHash.ToArray();
}

public delegate ValueTask<bool> ProductionMailboxRouteContinuityEnrollmentCommitter(
    ProductionMailboxRouteContinuityEnrollmentCommitPlan plan,
    CancellationToken cancellationToken);

/// <summary>
/// Non-forgeable completion of the two-phase continuity enrollment. It owns the verified RCD/RDA
/// closure and both exact protected ROL1 snapshots needed for the caller's atomic CAS commit.
/// </summary>
public sealed class VerifiedProductionMailboxRouteContinuityEnrollmentState
{
    private readonly byte[] _preDelegationRouteOriginLkg;
    private readonly byte[] _preDelegationRouteOriginLkgHash;
    private readonly byte[] _enrolledRouteOriginLkg;
    private readonly byte[] _enrolledRouteOriginLkgHash;

    internal VerifiedProductionMailboxRouteContinuityEnrollmentState(
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment,
        ProductionMailboxRouteOriginLkg preDelegationRouteOrigin,
        ProductionMailboxRouteOriginLkg enrolledRouteOrigin)
    {
        Enrollment = enrollment ?? throw new ArgumentNullException(nameof(enrollment));
        PreDelegationRouteOrigin = ProductionMailboxRouteContinuityCopy.Clone(
            preDelegationRouteOrigin ?? throw new ArgumentNullException(nameof(preDelegationRouteOrigin)));
        EnrolledRouteOrigin = ProductionMailboxRouteContinuityCopy.Clone(
            enrolledRouteOrigin ?? throw new ArgumentNullException(nameof(enrolledRouteOrigin)));
        _preDelegationRouteOriginLkg = ProductionMailboxRouteContinuityCodec
            .EncodeRouteOriginLkg(PreDelegationRouteOrigin);
        _preDelegationRouteOriginLkgHash = ProductionMailboxRouteContinuityCodec
            .ComputeRouteOriginLkgHash(PreDelegationRouteOrigin);
        _enrolledRouteOriginLkg = ProductionMailboxRouteContinuityCodec
            .EncodeRouteOriginLkg(EnrolledRouteOrigin);
        _enrolledRouteOriginLkgHash = ProductionMailboxRouteContinuityCodec
            .ComputeRouteOriginLkgHash(EnrolledRouteOrigin);
    }

    public VerifiedProductionMailboxRouteContinuityEnrollment Enrollment { get; }
    internal ProductionMailboxRouteOriginLkg PreDelegationRouteOrigin { get; }
    internal ProductionMailboxRouteOriginLkg EnrolledRouteOrigin { get; }
    public ReadOnlyMemory<byte> CanonicalPreDelegationRouteOriginLkg =>
        _preDelegationRouteOriginLkg.ToArray();
    public ReadOnlyMemory<byte> PreDelegationRouteOriginLkgHash =>
        _preDelegationRouteOriginLkgHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalEnrolledRouteOriginLkg =>
        _enrolledRouteOriginLkg.ToArray();
    public ReadOnlyMemory<byte> EnrolledRouteOriginLkgHash => _enrolledRouteOriginLkgHash.ToArray();
}

/// <summary>
/// Non-forgeable, fully preflighted selection intent. It binds exact verified PMS1 selections to
/// their old/current PMA1+PMT1 closure and the exact current PMR1 before issuer callbacks run.
/// </summary>
public sealed class VerifiedProductionMailboxSelectionTransitionIntent
{
    private readonly byte[] _networkId;
    private readonly byte[] _selectionInputCommitment;
    private readonly byte[] _oldSelectionHash;
    private readonly byte[] _currentSelectionHash;
    private readonly byte[] _currentAuthorityHash;
    private readonly byte[] _currentRevocationHash;
    private readonly byte[] _currentTopologyHash;
    private readonly byte[] _routeCertificateHash;

    internal VerifiedProductionMailboxSelectionTransitionIntent(
        ProductionMailboxSelectionSuccessorMode mode,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> selectionInputCommitment,
        ReadOnlySpan<byte> oldSelectionHash,
        ReadOnlySpan<byte> currentSelectionHash,
        ReadOnlySpan<byte> currentAuthorityHash,
        ReadOnlySpan<byte> currentRevocationHash,
        ReadOnlySpan<byte> currentTopologyHash,
        ReadOnlySpan<byte> routeCertificateHash,
        ulong liveNotBeforeUnixSeconds,
        ulong liveExpiresAtUnixSeconds)
    {
        Mode = mode;
        _networkId = networkId.ToArray();
        _selectionInputCommitment = selectionInputCommitment.ToArray();
        _oldSelectionHash = oldSelectionHash.ToArray();
        _currentSelectionHash = currentSelectionHash.ToArray();
        _currentAuthorityHash = currentAuthorityHash.ToArray();
        _currentRevocationHash = currentRevocationHash.ToArray();
        _currentTopologyHash = currentTopologyHash.ToArray();
        _routeCertificateHash = routeCertificateHash.ToArray();
        LiveNotBeforeUnixSeconds = liveNotBeforeUnixSeconds;
        LiveExpiresAtUnixSeconds = liveExpiresAtUnixSeconds;
    }

    public ProductionMailboxSelectionSuccessorMode Mode { get; }
    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> SelectionInputCommitment => _selectionInputCommitment.ToArray();
    public ReadOnlyMemory<byte> OldCanonicalSelectionHash => _oldSelectionHash.ToArray();
    public ReadOnlyMemory<byte> CurrentCanonicalSelectionHash => _currentSelectionHash.ToArray();
    public ReadOnlyMemory<byte> CurrentCanonicalAuthorityHash => _currentAuthorityHash.ToArray();
    public ReadOnlyMemory<byte> CurrentCanonicalRevocationHash => _currentRevocationHash.ToArray();
    public ReadOnlyMemory<byte> CurrentCanonicalTopologyHash => _currentTopologyHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalRouteCertificateHash => _routeCertificateHash.ToArray();
    public ulong LiveNotBeforeUnixSeconds { get; }
    public ulong LiveExpiresAtUnixSeconds { get; }

    internal ReadOnlySpan<byte> TrustedNetworkId => _networkId;
    internal ReadOnlySpan<byte> TrustedSelectionInputCommitment => _selectionInputCommitment;
    internal ReadOnlySpan<byte> TrustedOldSelectionHash => _oldSelectionHash;
    internal ReadOnlySpan<byte> TrustedCurrentSelectionHash => _currentSelectionHash;
    internal ReadOnlySpan<byte> TrustedCurrentAuthorityHash => _currentAuthorityHash;
    internal ReadOnlySpan<byte> TrustedCurrentRevocationHash => _currentRevocationHash;
    internal ReadOnlySpan<byte> TrustedRouteCertificateHash => _routeCertificateHash;
}

/// <summary>
/// Non-forgeable, fully verified RCH1/RTC1/RCA1 authoring result. Public observations are
/// defensive exact canonical snapshots; trusted components remain assembly-internal.
/// </summary>
public sealed class VerifiedProductionMailboxDelegatedRouteAuthorization
{
    private readonly byte[] _checkpointBytes;
    private readonly byte[] _transitionContextBytes;
    private readonly byte[] _activationBytes;
    private readonly byte[] _checkpointHash;
    private readonly byte[] _transitionContextHash;
    private readonly byte[] _activationHash;

    internal VerifiedProductionMailboxDelegatedRouteAuthorization(
        VerifiedProductionMailboxRouteRevocationCheckpoint checkpoint,
        VerifiedProductionMailboxRouteTransitionContext transitionContext,
        VerifiedProductionMailboxRouteContinuityActivation activation)
    {
        VerifiedCheckpoint = checkpoint ?? throw new ArgumentNullException(nameof(checkpoint));
        VerifiedTransitionContext = transitionContext ??
            throw new ArgumentNullException(nameof(transitionContext));
        VerifiedActivation = activation ?? throw new ArgumentNullException(nameof(activation));
        _checkpointBytes = ProductionMailboxRouteContinuityCodec.EncodeRevocationCheckpoint(
            checkpoint.Checkpoint);
        _transitionContextBytes = transitionContext.CanonicalBytes.ToArray();
        _activationBytes = activation.CanonicalBytes.ToArray();
        _checkpointHash = checkpoint.CanonicalHash.ToArray();
        _transitionContextHash = transitionContext.CanonicalHash.ToArray();
        _activationHash = activation.CanonicalHash.ToArray();
    }

    internal VerifiedProductionMailboxRouteRevocationCheckpoint VerifiedCheckpoint { get; }
    internal VerifiedProductionMailboxRouteTransitionContext VerifiedTransitionContext { get; }
    internal VerifiedProductionMailboxRouteContinuityActivation VerifiedActivation { get; }

    public ReadOnlyMemory<byte> CanonicalCheckpointBytes => _checkpointBytes.ToArray();
    public ReadOnlyMemory<byte> CanonicalTransitionContextBytes => _transitionContextBytes.ToArray();
    public ReadOnlyMemory<byte> CanonicalActivationBytes => _activationBytes.ToArray();
    public ReadOnlyMemory<byte> CanonicalCheckpointHash => _checkpointHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalTransitionContextHash => _transitionContextHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalActivationHash => _activationHash.ToArray();
}
