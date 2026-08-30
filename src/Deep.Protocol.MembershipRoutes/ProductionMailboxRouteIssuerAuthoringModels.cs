using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

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

/// <summary>Capability-scoped PRC1 request. Only a sealed route intent can create it.</summary>
public sealed class ProductionMailboxPrc1SigningRequest
{
    private readonly byte[] _signingBytes;
    private readonly byte[] _expectedIssuerPublicKey;

    internal ProductionMailboxPrc1SigningRequest(ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> expectedIssuerPublicKey)
    {
        _signingBytes = signingBytes.ToArray();
        _expectedIssuerPublicKey = expectedIssuerPublicKey.ToArray();
    }

    public ReadOnlyMemory<byte> SigningBytes => _signingBytes.ToArray();
    public ReadOnlyMemory<byte> ExpectedIssuerEd25519PublicKey => _expectedIssuerPublicKey.ToArray();
    internal void Clear()
    {
        CryptographicOperations.ZeroMemory(_signingBytes);
        CryptographicOperations.ZeroMemory(_expectedIssuerPublicKey);
    }
}

public delegate ValueTask<int> ProductionMailboxPrc1Signer(
    ProductionMailboxPrc1SigningRequest request,
    Memory<byte> signatureDestination,
    CancellationToken cancellationToken);

/// <summary>
/// Sealed owner/anchor enrollment preflight. It contains only defensively frozen, production-
/// verified cryptographic input; transaction time and responder-key material are supplied later.
/// </summary>
public sealed class VerifiedProductionMailboxRouteContinuityGenesisIntent
{
    private readonly byte[] _canonicalDelegation;
    private readonly byte[] _canonicalPreRouteOriginLkg;
    private readonly byte[] _canonicalAuthority;
    private readonly byte[] _canonicalRevocations;
    private readonly byte[] _canonicalRouteCertificate;
    private readonly byte[] _canonicalRouteAuthorization;
    private readonly byte[] _delegationHash;
    private readonly byte[] _preRouteOriginLkgHash;
    private readonly byte[] _intentHash;
    private readonly byte[] _networkId;
    private readonly byte[] _mailboxOwner;
    private readonly byte[] _routeDomain;
    private readonly byte[] _selectionInputCommitment;

    internal VerifiedProductionMailboxRouteContinuityGenesisIntent(
        ReadOnlySpan<byte> canonicalDelegation,
        ReadOnlySpan<byte> canonicalPreRouteOriginLkg,
        ReadOnlySpan<byte> canonicalAuthority,
        ReadOnlySpan<byte> canonicalRevocations,
        ReadOnlySpan<byte> canonicalRouteCertificate,
        ReadOnlySpan<byte> canonicalRouteAuthorization,
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxRevocationSnapshot revocations,
        VerifiedProductionMailboxRouteCertificate routeCertificate,
        VerifiedProductionMailboxRouteAdvertisementV2 routeAuthorization,
        ulong verifiedAtUnixSeconds,
        uint clockSkewSeconds)
    {
        _canonicalDelegation = canonicalDelegation.ToArray();
        _canonicalPreRouteOriginLkg = canonicalPreRouteOriginLkg.ToArray();
        _canonicalAuthority = canonicalAuthority.ToArray();
        _canonicalRevocations = canonicalRevocations.ToArray();
        _canonicalRouteCertificate = canonicalRouteCertificate.ToArray();
        _canonicalRouteAuthorization = canonicalRouteAuthorization.ToArray();
        var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(
            _canonicalDelegation);
        _networkId = delegation.NetworkId.ToArray();
        _mailboxOwner = delegation.MailboxOwnerEd25519PublicKey.ToArray();
        _routeDomain = delegation.RouteDomainHash.ToArray();
        _selectionInputCommitment = delegation.SelectionInputCommitment.ToArray();
        _delegationHash = SHA256.HashData(_canonicalDelegation);
        _preRouteOriginLkgHash = ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(
            ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(_canonicalPreRouteOriginLkg));
        _intentHash = HashItems("Deep/production-mailbox/continuity-genesis-intent/v1"u8,
            _canonicalAuthority, _canonicalRevocations, _canonicalRouteCertificate,
            _canonicalRouteAuthorization, _canonicalDelegation, _canonicalPreRouteOriginLkg);
        Authority = authority; Revocations = revocations; RouteCertificate = routeCertificate;
        RouteAuthorization = routeAuthorization;
        VerifiedAtUnixSeconds = verifiedAtUnixSeconds; ClockSkewSeconds = clockSkewSeconds;
    }

    public ReadOnlyMemory<byte> CanonicalDelegation => _canonicalDelegation.ToArray();
    public ReadOnlyMemory<byte> CanonicalDelegationHash => _delegationHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalPreDelegationRouteOriginLkg =>
        _canonicalPreRouteOriginLkg.ToArray();
    public ReadOnlyMemory<byte> PreDelegationRouteOriginLkgHash =>
        _preRouteOriginLkgHash.ToArray();
    public ReadOnlyMemory<byte> IntentHash => _intentHash.ToArray();
    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey => _mailboxOwner.ToArray();
    public ReadOnlyMemory<byte> RouteDomainHash => _routeDomain.ToArray();
    public ReadOnlyMemory<byte> SelectionInputCommitment =>
        _selectionInputCommitment.ToArray();
    internal ReadOnlyMemory<byte> CanonicalAuthority => _canonicalAuthority;
    internal ReadOnlyMemory<byte> CanonicalRevocations => _canonicalRevocations;
    internal ReadOnlyMemory<byte> CanonicalRouteCertificate => _canonicalRouteCertificate;
    internal ReadOnlyMemory<byte> CanonicalRouteAuthorization => _canonicalRouteAuthorization;
    internal VerifiedProductionMailboxAuthority Authority { get; }
    internal VerifiedProductionMailboxRevocationSnapshot Revocations { get; }
    internal VerifiedProductionMailboxRouteCertificate RouteCertificate { get; }
    internal VerifiedProductionMailboxRouteAdvertisementV2 RouteAuthorization { get; }
    internal ulong VerifiedAtUnixSeconds { get; }
    internal uint ClockSkewSeconds { get; }

    private static byte[] HashItems(ReadOnlySpan<byte> domain, params byte[][] items)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domain);
        Span<byte> length = stackalloc byte[4];
        foreach (var item in items)
        {
            BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)item.Length));
            hash.AppendData(length); hash.AppendData(item);
        }
        return hash.GetHashAndReset();
    }
}

/// <summary>
/// Authenticated durable fields which bind an exact historical continuity enrollment and OCR1.
/// This is data for a protected store, not a verification capability.
/// </summary>
public sealed class ProductionMailboxRouteContinuityProtectedEnrollmentContext
{
    private readonly byte[] _networkId;
    private readonly byte[] _owner;
    private readonly byte[] _pinnedMrX;
    private readonly byte[] _mailbox;
    private readonly byte[] _placement;
    private readonly byte[] _routeDomain;
    private readonly byte[] _selection;
    private readonly byte[] _delegationHash;
    private readonly byte[] _acceptanceHash;
    private readonly byte[] _preRolHash;
    private readonly byte[] _enrolledRolHash;
    private readonly byte[] _ocrBytes;
    private readonly byte[] _ocrHash;
    private readonly byte[] _anchorAuthorityHash;
    private readonly byte[] _anchorCertificateHash;
    private readonly byte[] _anchorAuthorizationHash;
    private readonly byte[] _previousDelegationHash;

    public ProductionMailboxRouteContinuityProtectedEnrollmentContext(
        ReadOnlyMemory<byte> networkId, ReadOnlyMemory<byte> mailboxOwnerEd25519PublicKey,
        ReadOnlyMemory<byte> pinnedMrXPublicKeySha256, ReadOnlyMemory<byte> blindedMailboxId,
        ReadOnlyMemory<byte> blindedPlacementId, ReadOnlyMemory<byte> routeDomainHash,
        ReadOnlyMemory<byte> selectionInputCommitment,
        ulong anchorAuthorityGeneration, ReadOnlyMemory<byte> anchorCanonicalAuthorityHash,
        ReadOnlyMemory<byte> anchorCanonicalRouteCertificateHash,
        ProductionMailboxRouteAuthorizationKind anchorAuthorizationKind,
        ReadOnlyMemory<byte> anchorCanonicalRouteAuthorizationHash,
        ulong anchorRouteAuthorizationSequence, ulong routeVerifiedAtUnixSeconds,
        ulong acceptedAtUnixSeconds, ulong previousDelegationSequence,
        ReadOnlyMemory<byte> previousCanonicalDelegationHash,
        ReadOnlyMemory<byte> canonicalDelegationHash, ReadOnlyMemory<byte> canonicalAcceptanceHash,
        ReadOnlyMemory<byte> preDelegationRouteOriginLkgHash,
        ReadOnlyMemory<byte> enrolledRouteOriginLkgHash,
        ReadOnlyMemory<byte> canonicalOwnerControlResponderCertificate,
        ReadOnlyMemory<byte> canonicalOwnerControlResponderCertificateHash)
    {
        Exact(networkId, 16, "network"); Exact(mailboxOwnerEd25519PublicKey, 32, "owner");
        Exact(pinnedMrXPublicKeySha256, 32, "Mr. X pin"); Exact(blindedMailboxId, 32, "mailbox");
        Exact(blindedPlacementId, 32, "placement");
        Exact(routeDomainHash, 32, "route domain"); Exact(selectionInputCommitment, 32, "selection");
        Exact(anchorCanonicalAuthorityHash, 32, "anchor PMA1 hash");
        Exact(anchorCanonicalRouteCertificateHash, 32, "anchor PRC1 hash");
        Exact(anchorCanonicalRouteAuthorizationHash, 32, "anchor PRA2 hash");
        Exact(previousCanonicalDelegationHash, 32, "previous RCD1 hash");
        if (anchorAuthorityGeneration is 0 or ulong.MaxValue ||
            anchorAuthorizationKind != ProductionMailboxRouteAuthorizationKind.OwnerPRA2 ||
            anchorRouteAuthorizationSequence is 0 or ulong.MaxValue ||
            routeVerifiedAtUnixSeconds is 0 or ulong.MaxValue || acceptedAtUnixSeconds is 0 or ulong.MaxValue ||
            acceptedAtUnixSeconds < routeVerifiedAtUnixSeconds || previousDelegationSequence == ulong.MaxValue)
            throw new FormatException("Protected enrollment anchor scalars are invalid.");
        Exact(canonicalDelegationHash, 32, "RCD1 hash"); Exact(canonicalAcceptanceHash, 32, "RDA1 hash");
        Exact(preDelegationRouteOriginLkgHash, 32, "pre ROL1 hash");
        Exact(enrolledRouteOriginLkgHash, 32, "enrolled ROL1 hash");
        Exact(canonicalOwnerControlResponderCertificate,
            ProductionMailboxOwnerControlConstants.ResponderCertificateLength, ProtocolMagic.OCR1);
        Exact(canonicalOwnerControlResponderCertificateHash, 32, "OCR1 hash");
        _networkId = networkId.ToArray(); _owner = mailboxOwnerEd25519PublicKey.ToArray();
        _pinnedMrX = pinnedMrXPublicKeySha256.ToArray(); _mailbox = blindedMailboxId.ToArray();
        _placement = blindedPlacementId.ToArray();
        _routeDomain = routeDomainHash.ToArray(); _selection = selectionInputCommitment.ToArray();
        AnchorAuthorityGeneration = anchorAuthorityGeneration;
        _anchorAuthorityHash = anchorCanonicalAuthorityHash.ToArray();
        _anchorCertificateHash = anchorCanonicalRouteCertificateHash.ToArray();
        AnchorAuthorizationKind = anchorAuthorizationKind;
        _anchorAuthorizationHash = anchorCanonicalRouteAuthorizationHash.ToArray();
        AnchorRouteAuthorizationSequence = anchorRouteAuthorizationSequence;
        RouteVerifiedAtUnixSeconds = routeVerifiedAtUnixSeconds; AcceptedAtUnixSeconds = acceptedAtUnixSeconds;
        PreviousDelegationSequence = previousDelegationSequence;
        _previousDelegationHash = previousCanonicalDelegationHash.ToArray();
        _delegationHash = canonicalDelegationHash.ToArray(); _acceptanceHash = canonicalAcceptanceHash.ToArray();
        _preRolHash = preDelegationRouteOriginLkgHash.ToArray(); _enrolledRolHash = enrolledRouteOriginLkgHash.ToArray();
        _ocrBytes = canonicalOwnerControlResponderCertificate.ToArray();
        _ocrHash = canonicalOwnerControlResponderCertificateHash.ToArray();
        ValidateOwned();
    }

    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey => _owner.ToArray();
    public ReadOnlyMemory<byte> PinnedMrXPublicKeySha256 => _pinnedMrX.ToArray();
    public ReadOnlyMemory<byte> BlindedMailboxId => _mailbox.ToArray();
    public ReadOnlyMemory<byte> BlindedPlacementId => _placement.ToArray();
    public ReadOnlyMemory<byte> RouteDomainHash => _routeDomain.ToArray();
    public ReadOnlyMemory<byte> SelectionInputCommitment => _selection.ToArray();
    public ReadOnlyMemory<byte> CanonicalDelegationHash => _delegationHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalAcceptanceHash => _acceptanceHash.ToArray();
    public ReadOnlyMemory<byte> PreDelegationRouteOriginLkgHash => _preRolHash.ToArray();
    public ReadOnlyMemory<byte> EnrolledRouteOriginLkgHash => _enrolledRolHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalOwnerControlResponderCertificate => _ocrBytes.ToArray();
    public ReadOnlyMemory<byte> CanonicalOwnerControlResponderCertificateHash => _ocrHash.ToArray();
    public ulong AnchorAuthorityGeneration { get; }
    public ReadOnlyMemory<byte> AnchorCanonicalAuthorityHash => _anchorAuthorityHash.ToArray();
    public ReadOnlyMemory<byte> AnchorCanonicalRouteCertificateHash => _anchorCertificateHash.ToArray();
    public ProductionMailboxRouteAuthorizationKind AnchorAuthorizationKind { get; }
    public ReadOnlyMemory<byte> AnchorCanonicalRouteAuthorizationHash => _anchorAuthorizationHash.ToArray();
    public ulong AnchorRouteAuthorizationSequence { get; }
    public ulong RouteVerifiedAtUnixSeconds { get; }
    public ulong AcceptedAtUnixSeconds { get; }
    public ulong PreviousDelegationSequence { get; }
    public ReadOnlyMemory<byte> PreviousCanonicalDelegationHash => _previousDelegationHash.ToArray();

    internal void ValidateOwned()
    {
        Exact(_networkId, 16, "network"); Exact(_owner, 32, "owner"); Exact(_pinnedMrX, 32, "Mr. X pin");
        Exact(_mailbox, 32, "mailbox"); Exact(_placement, 32, "placement"); Exact(_routeDomain, 32, "route");
        Exact(_selection, 32, "selection"); Exact(_delegationHash, 32, "RCD1 hash");
        Exact(_anchorAuthorityHash, 32, "anchor PMA1 hash"); Exact(_anchorCertificateHash, 32, "anchor PRC1 hash");
        Exact(_anchorAuthorizationHash, 32, "anchor PRA2 hash"); Exact(_previousDelegationHash, 32, "previous RCD1 hash");
        Exact(_acceptanceHash, 32, "RDA1 hash"); Exact(_preRolHash, 32, "pre ROL1 hash");
        Exact(_enrolledRolHash, 32, "enrolled ROL1 hash"); Exact(_ocrBytes, 272, ProtocolMagic.OCR1);
        Exact(_ocrHash, 32, "OCR1 hash");
        if (_networkId.AsSpan().IndexOfAnyExcept((byte)0) < 0 || _owner.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            _pinnedMrX.AsSpan().IndexOfAnyExcept((byte)0) < 0 || _mailbox.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            _placement.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            _routeDomain.AsSpan().IndexOfAnyExcept((byte)0) < 0 || _selection.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            _delegationHash.AsSpan().IndexOfAnyExcept((byte)0) < 0 || _acceptanceHash.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            _preRolHash.AsSpan().IndexOfAnyExcept((byte)0) < 0 || _enrolledRolHash.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            _ocrHash.AsSpan().IndexOfAnyExcept((byte)0) < 0 || _anchorAuthorityHash.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            _anchorCertificateHash.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            _anchorAuthorizationHash.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            AnchorAuthorityGeneration is 0 or ulong.MaxValue || AnchorAuthorizationKind != ProductionMailboxRouteAuthorizationKind.OwnerPRA2 ||
            AnchorRouteAuthorizationSequence is 0 or ulong.MaxValue || RouteVerifiedAtUnixSeconds is 0 or ulong.MaxValue ||
            AcceptedAtUnixSeconds is 0 or ulong.MaxValue || AcceptedAtUnixSeconds < RouteVerifiedAtUnixSeconds ||
            PreviousDelegationSequence == ulong.MaxValue)
            throw new FormatException("Protected enrollment contains an all-zero binding.");
    }

    private static void Exact(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length) throw new FormatException($"Protected enrollment {name} length is invalid.");
    }
}

/// <summary>
/// One non-forgeable historical enrollment/identity/OCR anchor. Independent verified handles
/// cannot be mixed at later authoring or owner-control boundaries.
/// </summary>
public sealed class VerifiedProductionMailboxHistoricalRouteAnchor
{
    private readonly byte[] _canonicalOcr;
    private readonly byte[] _ocrHash;
    private readonly byte[] _responderKeyHash;

    internal VerifiedProductionMailboxHistoricalRouteAnchor(
        VerifiedProductionMailboxRouteContinuityEnrollmentState enrollmentState,
        VerifiedProductionMailboxAuthority anchorAuthority,
        VerifiedProductionMailboxRevocationSnapshot anchorRevocations,
        VerifiedProductionMailboxRouteCertificate anchorCertificate,
        VerifiedProductionMailboxRouteAdvertisementV2 anchorAuthorization,
        ProductionMailboxOwnerControlResponderCertificate ocr,
        ReadOnlySpan<byte> canonicalOcr,
        ReadOnlySpan<byte> ocrHash)
    {
        EnrollmentState = enrollmentState; AnchorAuthority = anchorAuthority;
        AnchorRevocations = anchorRevocations; AnchorCertificate = anchorCertificate;
        AnchorAuthorization = anchorAuthorization; OwnerControlResponderCertificate = ocr;
        _canonicalOcr = canonicalOcr.ToArray(); _ocrHash = ocrHash.ToArray();
        _responderKeyHash = SHA256.HashData(ocr.ResponderEd25519PublicKey.Span);
    }

    internal VerifiedProductionMailboxRouteContinuityEnrollmentState EnrollmentState { get; }
    internal VerifiedProductionMailboxAuthority AnchorAuthority { get; }
    internal VerifiedProductionMailboxRevocationSnapshot AnchorRevocations { get; }
    internal VerifiedProductionMailboxRouteCertificate AnchorCertificate { get; }
    internal VerifiedProductionMailboxRouteAdvertisementV2 AnchorAuthorization { get; }
    internal ProductionMailboxOwnerControlResponderCertificate OwnerControlResponderCertificate { get; }
    public ReadOnlyMemory<byte> CanonicalOwnerControlResponderCertificate => _canonicalOcr.ToArray();
    public ReadOnlyMemory<byte> CanonicalOwnerControlResponderCertificateHash => _ocrHash.ToArray();
    public ReadOnlyMemory<byte> ResponderEd25519PublicKeyHash => _responderKeyHash.ToArray();
    public ProductionMailboxRouteContinuityProtectedEnrollmentContext ToProtectedRestoreContext()
    {
        var delegation = EnrollmentState.Enrollment.Delegation;
        var acceptance = EnrollmentState.Enrollment.Acceptance;
        return new(delegation.NetworkId, delegation.MailboxOwnerEd25519PublicKey,
            delegation.PinnedMrXPublicKeySha256, delegation.BlindedMailboxId,
            delegation.BlindedPlacementId, delegation.RouteDomainHash, delegation.SelectionInputCommitment,
            delegation.AnchorAuthorityGeneration, delegation.AnchorCanonicalAuthorityHash,
            delegation.AnchorCanonicalRouteCertificateHash, delegation.AnchorAuthorizationKind,
            delegation.AnchorCanonicalRouteAuthorizationHash, delegation.AnchorRouteAuthorizationSequence,
            delegation.RouteVerifiedAtUnixSeconds, acceptance.AcceptedAtUnixSeconds,
            delegation.DelegationSequence - 1, delegation.PreviousCanonicalDelegationHash,
            EnrollmentState.Enrollment.CanonicalDelegationHash,
            EnrollmentState.Enrollment.CanonicalAcceptanceHash,
            EnrollmentState.PreDelegationRouteOriginLkgHash,
            EnrollmentState.EnrolledRouteOriginLkgHash, _canonicalOcr, _ocrHash);
    }
}

/// <summary>Sealed current-control-plane route identity from which a fresh PRC1 may be authored.</summary>
public sealed class VerifiedProductionMailboxRouteCertificateIntent
{
    internal VerifiedProductionMailboxRouteCertificateIntent(
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor currentRoute,
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxRevocationSnapshot revocations,
        ulong issuedAt, ulong expiresAt)
    { Anchor = anchor; CurrentRoute = currentRoute; Authority = authority; Revocations = revocations; IssuedAt = issuedAt; ExpiresAt = expiresAt; }
    internal VerifiedProductionMailboxHistoricalRouteAnchor Anchor { get; }
    internal VerifiedProductionMailboxRouteHistoryCursor CurrentRoute { get; }
    internal VerifiedProductionMailboxAuthority Authority { get; }
    internal VerifiedProductionMailboxRevocationSnapshot Revocations { get; }
    internal ulong IssuedAt { get; }
    internal ulong ExpiresAt { get; }
}

/// <summary>
/// Defensive cryptographic data for one caller-owned atomic genesis CAS. This plan does not attest
/// storage, durability, replay handling, publication, or a successful commit.
/// </summary>
public sealed class ProductionMailboxRouteContinuityGenesisCommitPlan
{
    private readonly byte[] _expectedPreRol;
    private readonly byte[] _expectedPreRolHash;
    private readonly byte[] _expectedPreviousDelegationHash;
    private readonly byte[] _intentHash;
    private readonly byte[] _authority;
    private readonly byte[] _authorityHash;
    private readonly byte[] _revocations;
    private readonly byte[] _revocationsHash;
    private readonly byte[] _certificate;
    private readonly byte[] _certificateHash;
    private readonly byte[] _authorization;
    private readonly byte[] _authorizationHash;
    private readonly byte[] _delegation;
    private readonly byte[] _delegationHash;
    private readonly byte[] _acceptance;
    private readonly byte[] _acceptanceHash;
    private readonly byte[] _enrolledRol;
    private readonly byte[] _enrolledRolHash;
    private readonly byte[] _ocr;
    private readonly byte[] _ocrHash;
    private readonly byte[] _initialRhc;
    private readonly byte[] _initialRhcHash;
    private readonly byte[] _planHash;
    private readonly ProductionMailboxRouteContinuityProtectedEnrollmentContext _enrollmentContext;
    private readonly ProductionMailboxRouteHistoryProtectedRestoreContext _historyContext;

    internal ProductionMailboxRouteContinuityGenesisCommitPlan(
        VerifiedProductionMailboxRouteContinuityGenesisIntent intent,
        VerifiedProductionMailboxRouteContinuityEnrollmentState enrollmentState,
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor initialCursor,
        ReadOnlySpan<byte> canonicalAcceptance,
        ReadOnlySpan<byte> canonicalOcr)
    {
        var delegation = enrollmentState.Enrollment.Delegation;
        var preRol = enrollmentState.PreDelegationRouteOrigin;
        _expectedPreRol = intent.CanonicalPreDelegationRouteOriginLkg.ToArray();
        _expectedPreRolHash = enrollmentState.PreDelegationRouteOriginLkgHash.ToArray();
        ExpectedPreDelegationLocalCommitGeneration = preRol.LocalCommitGeneration;
        ExpectedPreviousDelegationSequence = delegation.DelegationSequence - 1;
        _expectedPreviousDelegationHash = delegation.PreviousCanonicalDelegationHash.ToArray();
        _intentHash = intent.IntentHash.ToArray();
        _authority = intent.CanonicalAuthority.ToArray();
        _authorityHash = intent.Authority.CanonicalAuthorityHash.ToArray();
        _revocations = intent.CanonicalRevocations.ToArray();
        _revocationsHash = intent.Revocations.CanonicalSnapshotHash.ToArray();
        _certificate = intent.CanonicalRouteCertificate.ToArray();
        _certificateHash = intent.RouteCertificate.CanonicalCertificateHash.ToArray();
        _authorization = intent.CanonicalRouteAuthorization.ToArray();
        _authorizationHash = intent.RouteAuthorization.CanonicalHash.ToArray();
        _delegation = intent.CanonicalDelegation.ToArray();
        _delegationHash = enrollmentState.Enrollment.CanonicalDelegationHash.ToArray();
        _acceptance = canonicalAcceptance.ToArray();
        _acceptanceHash = enrollmentState.Enrollment.CanonicalAcceptanceHash.ToArray();
        _enrolledRol = enrollmentState.CanonicalEnrolledRouteOriginLkg.ToArray();
        _enrolledRolHash = enrollmentState.EnrolledRouteOriginLkgHash.ToArray();
        _ocr = canonicalOcr.ToArray();
        _ocrHash = anchor.CanonicalOwnerControlResponderCertificateHash.ToArray();
        _initialRhc = initialCursor.CanonicalCheckpoint.ToArray();
        _initialRhcHash = initialCursor.CanonicalCheckpointHash.ToArray();
        _enrollmentContext = anchor.ToProtectedRestoreContext();
        _historyContext = initialCursor.ToProtectedRestoreContext();
        AcceptedAtUnixSeconds = enrollmentState.Enrollment.Acceptance.AcceptedAtUnixSeconds;
        InternalEnrollmentState = enrollmentState; InternalAnchor = anchor;
        InternalInitialCursor = initialCursor;
        _planHash = ComputePlanHash();
    }

    public ReadOnlyMemory<byte> ExpectedPreDelegationRouteOriginLkg => _expectedPreRol.ToArray();
    public ReadOnlyMemory<byte> ExpectedPreDelegationRouteOriginLkgHash => _expectedPreRolHash.ToArray();
    public ulong ExpectedPreDelegationLocalCommitGeneration { get; }
    public ulong ExpectedPreviousDelegationSequence { get; }
    public ReadOnlyMemory<byte> ExpectedPreviousDelegationHash =>
        _expectedPreviousDelegationHash.ToArray();
    public ReadOnlyMemory<byte> GenesisIntentHash => _intentHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalAnchorAuthority => _authority.ToArray();
    public ReadOnlyMemory<byte> CanonicalAnchorAuthorityHash => _authorityHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalAnchorRevocations => _revocations.ToArray();
    public ReadOnlyMemory<byte> CanonicalAnchorRevocationsHash => _revocationsHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalAnchorRouteCertificate => _certificate.ToArray();
    public ReadOnlyMemory<byte> CanonicalAnchorRouteCertificateHash => _certificateHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalAnchorRouteAuthorization => _authorization.ToArray();
    public ReadOnlyMemory<byte> CanonicalAnchorRouteAuthorizationHash => _authorizationHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalDelegation => _delegation.ToArray();
    public ReadOnlyMemory<byte> CanonicalDelegationHash => _delegationHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalAcceptance => _acceptance.ToArray();
    public ReadOnlyMemory<byte> CanonicalAcceptanceHash => _acceptanceHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalEnrolledRouteOriginLkg => _enrolledRol.ToArray();
    public ReadOnlyMemory<byte> EnrolledRouteOriginLkgHash => _enrolledRolHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalOwnerControlResponderCertificate => _ocr.ToArray();
    public ReadOnlyMemory<byte> CanonicalOwnerControlResponderCertificateHash => _ocrHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalInitialRouteHistoryCheckpoint => _initialRhc.ToArray();
    public ReadOnlyMemory<byte> CanonicalInitialRouteHistoryCheckpointHash => _initialRhcHash.ToArray();
    public ulong AcceptedAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> PlanHash => _planHash.ToArray();

    public ProductionMailboxRouteContinuityProtectedEnrollmentContext
        ToProtectedEnrollmentRestoreContext() => Clone(_enrollmentContext);
    public ProductionMailboxRouteHistoryProtectedRestoreContext
        ToProtectedRouteHistoryRestoreContext() => Clone(_historyContext);

    internal VerifiedProductionMailboxRouteContinuityEnrollmentState InternalEnrollmentState { get; }
    internal VerifiedProductionMailboxHistoricalRouteAnchor InternalAnchor { get; }
    internal VerifiedProductionMailboxRouteHistoryCursor InternalInitialCursor { get; }

    private byte[] ComputePlanHash()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/production-mailbox/continuity-genesis-commit-plan/v1"u8);
        Append(hash, U64(ExpectedPreDelegationLocalCommitGeneration));
        Append(hash, U64(ExpectedPreviousDelegationSequence));
        foreach (var item in new[]
                 {
                     _expectedPreRol, _expectedPreRolHash, _expectedPreviousDelegationHash,
                     _intentHash,
                     _authority, _authorityHash, _revocations, _revocationsHash,
                     _certificate, _certificateHash, _authorization, _authorizationHash,
                     _delegation, _delegationHash, _acceptance, _acceptanceHash,
                     _enrolledRol, _enrolledRolHash, _ocr, _ocrHash, _initialRhc, _initialRhcHash
                 })
            Append(hash, item);
        AppendEnrollmentContext(hash, _enrollmentContext);
        AppendHistoryContext(hash, _historyContext);
        return hash.GetHashAndReset();
    }

    private static void AppendEnrollmentContext(IncrementalHash hash,
        ProductionMailboxRouteContinuityProtectedEnrollmentContext value)
    {
        foreach (var item in new[]
                 {
                     value.NetworkId, value.MailboxOwnerEd25519PublicKey,
                     value.PinnedMrXPublicKeySha256, value.BlindedMailboxId,
                     value.BlindedPlacementId, value.RouteDomainHash,
                     value.SelectionInputCommitment, value.AnchorCanonicalAuthorityHash,
                     value.AnchorCanonicalRouteCertificateHash,
                     value.AnchorCanonicalRouteAuthorizationHash,
                     value.PreviousCanonicalDelegationHash, value.CanonicalDelegationHash,
                     value.CanonicalAcceptanceHash, value.PreDelegationRouteOriginLkgHash,
                     value.EnrolledRouteOriginLkgHash,
                     value.CanonicalOwnerControlResponderCertificate,
                     value.CanonicalOwnerControlResponderCertificateHash
                 })
            Append(hash, item.Span);
        Append(hash, U64(value.AnchorAuthorityGeneration));
        Append(hash, [(byte)value.AnchorAuthorizationKind]);
        Append(hash, U64(value.AnchorRouteAuthorizationSequence));
        Append(hash, U64(value.RouteVerifiedAtUnixSeconds));
        Append(hash, U64(value.AcceptedAtUnixSeconds));
        Append(hash, U64(value.PreviousDelegationSequence));
    }

    private static void AppendHistoryContext(IncrementalHash hash,
        ProductionMailboxRouteHistoryProtectedRestoreContext value)
    {
        foreach (var item in new[]
                 {
                     value.CanonicalCheckpoint, value.CanonicalCheckpointHash,
                     value.LastCommittedBatchHash, value.CurrentRouteOriginLkgHash,
                     value.EnrollmentCanonicalDelegationHash,
                     value.EnrollmentCanonicalAcceptanceHash, value.NetworkId,
                     value.RouteDomainHash, value.DelegationHistoryBinding,
                     value.PinnedMrXPublicKeySha256, value.CurrentCanonicalAuthorityHash,
                     value.CurrentRevocationHeadHash, value.CurrentRevocationSnapshotHash
                 })
            Append(hash, item.Span);
        Append(hash, U64(value.LastCommittedBatchSequence));
        Append(hash, U64(value.CurrentAuthorityGeneration));
        Append(hash, U64(value.CurrentRevocationGeneration));
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> item)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)item.Length));
        hash.AppendData(length); hash.AppendData(item);
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static ProductionMailboxRouteContinuityProtectedEnrollmentContext Clone(
        ProductionMailboxRouteContinuityProtectedEnrollmentContext value) => new(
        value.NetworkId, value.MailboxOwnerEd25519PublicKey, value.PinnedMrXPublicKeySha256,
        value.BlindedMailboxId, value.BlindedPlacementId, value.RouteDomainHash,
        value.SelectionInputCommitment, value.AnchorAuthorityGeneration,
        value.AnchorCanonicalAuthorityHash, value.AnchorCanonicalRouteCertificateHash,
        value.AnchorAuthorizationKind, value.AnchorCanonicalRouteAuthorizationHash,
        value.AnchorRouteAuthorizationSequence, value.RouteVerifiedAtUnixSeconds,
        value.AcceptedAtUnixSeconds, value.PreviousDelegationSequence,
        value.PreviousCanonicalDelegationHash, value.CanonicalDelegationHash,
        value.CanonicalAcceptanceHash, value.PreDelegationRouteOriginLkgHash,
        value.EnrolledRouteOriginLkgHash, value.CanonicalOwnerControlResponderCertificate,
        value.CanonicalOwnerControlResponderCertificateHash);

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
/// Exact one-shot CAS plan for the caller's protected enrollment store. The committer must compare
/// every expected predecessor field and atomically publish the exact RCD1/RDA1/post-RDA ROL1 set.
/// </summary>
internal sealed class ProductionMailboxRouteContinuityEnrollmentCommitPlan
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

internal delegate ValueTask<bool> ProductionMailboxRouteContinuityEnrollmentCommitter(
    ProductionMailboxRouteContinuityEnrollmentCommitPlan plan,
    CancellationToken cancellationToken);

/// <summary>
/// Non-forgeable completion of the two-phase continuity enrollment. It owns the verified RCD/RDA
/// closure and both exact protected ROL1 snapshots needed for the caller's atomic CAS commit.
/// </summary>
internal sealed class VerifiedProductionMailboxRouteContinuityEnrollmentState
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
        ulong liveExpiresAtUnixSeconds,
        VerifiedProductionMailboxAuthority oldAuthority,
        VerifiedProductionMailboxTopology oldTopology,
        VerifiedProductionMailboxSelection oldSelection,
        VerifiedProductionMailboxAuthority currentAuthority,
        VerifiedProductionMailboxRevocationSnapshot currentRevocations,
        VerifiedProductionMailboxTopology currentTopology,
        VerifiedProductionMailboxSelection currentSelection,
        VerifiedProductionMailboxRouteCertificate routeCertificate,
        VerifiedProductionMailboxSelection? nextSelection = null,
        VerifiedProductionMailboxRouteHistoryCursor? currentRoute = null)
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
        OldAuthority = oldAuthority; OldTopology = oldTopology; OldSelection = oldSelection;
        CurrentAuthority = currentAuthority; CurrentRevocations = currentRevocations;
        CurrentTopology = currentTopology; CurrentSelection = currentSelection;
        RouteCertificate = routeCertificate;
        NextSelection = nextSelection;
        CurrentRoute = currentRoute;
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
    internal VerifiedProductionMailboxAuthority OldAuthority { get; }
    internal VerifiedProductionMailboxTopology OldTopology { get; }
    internal VerifiedProductionMailboxSelection OldSelection { get; }
    internal VerifiedProductionMailboxAuthority CurrentAuthority { get; }
    internal VerifiedProductionMailboxRevocationSnapshot CurrentRevocations { get; }
    internal VerifiedProductionMailboxTopology CurrentTopology { get; }
    internal VerifiedProductionMailboxSelection CurrentSelection { get; }
    internal VerifiedProductionMailboxRouteCertificate RouteCertificate { get; }
    internal VerifiedProductionMailboxSelection? NextSelection { get; }
    internal VerifiedProductionMailboxRouteHistoryCursor? CurrentRoute { get; }

    internal VerifiedProductionMailboxSelectionTransitionIntent WithNextSelection(
        VerifiedProductionMailboxSelection next,
        VerifiedProductionMailboxRouteHistoryCursor currentRoute) => new(Mode, _networkId, _selectionInputCommitment,
        _oldSelectionHash, _currentSelectionHash, _currentAuthorityHash, _currentRevocationHash,
        _currentTopologyHash, _routeCertificateHash, LiveNotBeforeUnixSeconds, LiveExpiresAtUnixSeconds,
        OldAuthority, OldTopology, OldSelection, CurrentAuthority, CurrentRevocations,
        CurrentTopology, CurrentSelection, RouteCertificate, next, currentRoute);
}

/// <summary>Owner-only route signer request; no caller-built PRA2 draft is accepted.</summary>
public sealed class ProductionMailboxPra2SigningRequest
{
    private readonly byte[] _bytes;
    private readonly byte[] _key;
    internal ProductionMailboxPra2SigningRequest(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> key)
    { _bytes = bytes.ToArray(); _key = key.ToArray(); }
    public ReadOnlyMemory<byte> SigningBytes => _bytes.ToArray();
    public ReadOnlyMemory<byte> ExpectedOwnerEd25519PublicKey => _key.ToArray();
    internal void Clear() { CryptographicOperations.ZeroMemory(_bytes); CryptographicOperations.ZeroMemory(_key); }
}

public delegate ValueTask<int> ProductionMailboxPra2Signer(
    ProductionMailboxPra2SigningRequest request, Memory<byte> signatureDestination,
    CancellationToken cancellationToken);

public sealed record ProductionMailboxLiveTransitionWindow
{
    public required ulong RouteNotBeforeUnixSeconds { get; init; }
    public required ulong RouteExpiresAtUnixSeconds { get; init; }
    public required ulong CheckpointIssuedAtUnixSeconds { get; init; }
    public required ulong CheckpointExpiresAtUnixSeconds { get; init; }
    public required ulong AuthorizationIssuedAtUnixSeconds { get; init; }
    public required ulong AuthorizationExpiresAtUnixSeconds { get; init; }
    public required ulong NowUnixSeconds { get; init; }
    public uint ClockSkewSeconds { get; init; }
}

/// <summary>Exact crypto-only transition plan. It makes no persistence/publication claim.</summary>
public sealed class ProductionMailboxLiveTransitionCommitPlan
{
    private readonly byte[] _expectedPredecessorRol;
    private readonly byte[] _expectedSelectionHash;
    private readonly byte[] _expectedRhc;
    private readonly byte[] _canonicalBatch;
    private readonly byte[] _nextRhc;
    private readonly byte[] _nextRol;
    private readonly byte[] _successor;
    private readonly byte[] _certificate;
    private readonly byte[] _rtc;
    private readonly byte[] _authorization;
    private readonly byte[] _rch;
    private readonly byte[] _transcript;
    private readonly byte[] _planHash;

    internal ProductionMailboxLiveTransitionCommitPlan(
        ReadOnlySpan<byte> expectedPredecessorRol, ReadOnlySpan<byte> expectedSelectionHash,
        ReadOnlySpan<byte> expectedRhc, ReadOnlySpan<byte> canonicalBatch,
        ReadOnlySpan<byte> nextRhc, ReadOnlySpan<byte> nextRol,
        VerifiedProductionMailboxRouteSelectionTransition transition)
    {
        _expectedPredecessorRol = expectedPredecessorRol.ToArray();
        _expectedSelectionHash = expectedSelectionHash.ToArray(); _expectedRhc = expectedRhc.ToArray();
        _canonicalBatch = canonicalBatch.ToArray(); _nextRhc = nextRhc.ToArray(); _nextRol = nextRol.ToArray();
        _successor = transition.CanonicalSuccessor.ToArray(); _certificate = transition.CanonicalRouteCertificate.ToArray();
        _rtc = transition.CanonicalTransitionContext.ToArray(); _authorization = transition.CanonicalRouteAuthorization.ToArray();
        _rch = transition.CanonicalRevocationCheckpoint.ToArray(); _transcript = transition.CanonicalTranscript.ToArray();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/production-mailbox/live-transition-commit-plan/v1"u8);
        Span<byte> length = stackalloc byte[4];
        foreach (var item in new[] { _expectedPredecessorRol, _expectedSelectionHash, _expectedRhc,
            _canonicalBatch, _nextRhc, _nextRol, _successor, _certificate, _rtc, _authorization, _rch, _transcript })
        { System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)item.Length)); hash.AppendData(length); hash.AppendData(item); }
        _planHash = hash.GetHashAndReset();
    }
    public ReadOnlyMemory<byte> ExpectedPredecessorRouteOriginLkg => _expectedPredecessorRol.ToArray();
    public ReadOnlyMemory<byte> ExpectedOldSelectionHash => _expectedSelectionHash.ToArray();
    public ReadOnlyMemory<byte> ExpectedRouteHistoryCheckpoint => _expectedRhc.ToArray();
    public ReadOnlyMemory<byte> CanonicalRouteHistoryBatch => _canonicalBatch.ToArray();
    public ReadOnlyMemory<byte> NextRouteHistoryCheckpoint => _nextRhc.ToArray();
    public ReadOnlyMemory<byte> CanonicalNextRouteOriginLkg => _nextRol.ToArray();
    public ReadOnlyMemory<byte> CanonicalSelectionSuccessorV2 => _successor.ToArray();
    public ReadOnlyMemory<byte> CanonicalRouteCertificate => _certificate.ToArray();
    public ReadOnlyMemory<byte> CanonicalTransitionContext => _rtc.ToArray();
    public ReadOnlyMemory<byte> CanonicalRouteAuthorization => _authorization.ToArray();
    public ReadOnlyMemory<byte> CanonicalRevocationCheckpoint => _rch.ToArray();
    public ReadOnlyMemory<byte> CanonicalTranscript => _transcript.ToArray();
    public ReadOnlyMemory<byte> PlanHash => _planHash.ToArray();
}

/// <summary>Sealed cryptographic result only; the consumer must perform and attest its own CAS.</summary>
public sealed class VerifiedProductionMailboxLiveTransition
{
    internal VerifiedProductionMailboxLiveTransition(
        VerifiedProductionMailboxRouteSelectionTransition transition,
        ProductionMailboxLiveTransitionCommitPlan plan,
        VerifiedProductionMailboxSelectionTransitionIntent intent)
    { Transition = transition; CommitPlan = plan; Intent = intent; }
    internal VerifiedProductionMailboxRouteSelectionTransition Transition { get; }
    internal VerifiedProductionMailboxSelectionTransitionIntent Intent { get; }
    public ProductionMailboxLiveTransitionCommitPlan CommitPlan { get; }
    public ProductionMailboxRouteAuthorizationKind AuthorizationKind => Transition.AuthorizationKind;
    public ProductionMailboxSelectionSuccessorMode Mode => Transition.SelectionSuccessor.Proof.Mode;
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
