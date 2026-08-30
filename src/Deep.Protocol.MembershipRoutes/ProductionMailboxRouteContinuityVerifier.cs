using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

public sealed record ProductionMailboxRouteContinuityEnrollmentVerificationContext
{
    public required ReadOnlyMemory<byte> ExpectedNetworkId { get; init; }
    public required ReadOnlyMemory<byte> ExpectedPinnedMrXPublicKeySha256 { get; init; }
    public required ReadOnlyMemory<byte> ExpectedRouteDomainHash { get; init; }
    public required ReadOnlyMemory<byte> ExpectedMailboxOwnerEd25519PublicKey { get; init; }
    public required ReadOnlyMemory<byte> ExpectedBlindedMailboxId { get; init; }
    public required ReadOnlyMemory<byte> ExpectedBlindedPlacementId { get; init; }
    public required ReadOnlyMemory<byte> ExpectedSelectionInputCommitment { get; init; }
    public required ReadOnlyMemory<byte> ExpectedPreDelegationRouteOriginLkgHash { get; init; }
    public required ulong ExpectedRouteVerifiedAtUnixSeconds { get; init; }
    public required ulong LastDelegationSequence { get; init; }
    public required ReadOnlyMemory<byte> LastCanonicalDelegationHash { get; init; }
    public required ulong NowUnixSeconds { get; init; }
    public required uint ClockSkewSeconds { get; init; }
}

internal sealed class VerifiedProductionMailboxRouteContinuityDelegation
{
    private readonly ProductionMailboxRouteContinuityDelegation _delegation;
    private readonly byte[] _canonicalBytes;
    private readonly byte[] _canonicalHash;

    internal VerifiedProductionMailboxRouteContinuityDelegation(
        ProductionMailboxRouteContinuityDelegation delegation,
        ReadOnlySpan<byte> canonicalBytes,
        ReadOnlySpan<byte> canonicalHash)
    {
        _delegation = ProductionMailboxRouteContinuityCopy.Clone(delegation);
        _canonicalBytes = canonicalBytes.ToArray();
        _canonicalHash = canonicalHash.ToArray();
    }

    internal ProductionMailboxRouteContinuityDelegation Delegation =>
        ProductionMailboxRouteContinuityCopy.Clone(_delegation);
    internal ReadOnlyMemory<byte> CanonicalBytes => _canonicalBytes.ToArray();
    internal ReadOnlyMemory<byte> CanonicalHash => _canonicalHash.ToArray();
}

public sealed class VerifiedProductionMailboxRouteContinuityEnrollment
{
    private readonly VerifiedProductionMailboxRouteContinuityDelegation _delegation;
    private readonly ProductionMailboxRouteDelegationAcceptance _acceptance;
    private readonly byte[] _acceptanceBytes;
    private readonly byte[] _acceptanceHash;

    internal VerifiedProductionMailboxRouteContinuityEnrollment(
        VerifiedProductionMailboxRouteContinuityDelegation delegation,
        ProductionMailboxRouteDelegationAcceptance acceptance,
        ReadOnlySpan<byte> acceptanceBytes,
        ReadOnlySpan<byte> acceptanceHash)
    {
        _delegation = delegation;
        _acceptance = ProductionMailboxRouteContinuityCopy.Clone(acceptance);
        _acceptanceBytes = acceptanceBytes.ToArray();
        _acceptanceHash = acceptanceHash.ToArray();
    }

    internal VerifiedProductionMailboxRouteContinuityDelegation VerifiedDelegation => _delegation;
    public ProductionMailboxRouteContinuityDelegation Delegation => _delegation.Delegation;
    public ProductionMailboxRouteDelegationAcceptance Acceptance =>
        ProductionMailboxRouteContinuityCopy.Clone(_acceptance);
    public ReadOnlyMemory<byte> CanonicalDelegationBytes => _delegation.CanonicalBytes.ToArray();
    public ReadOnlyMemory<byte> CanonicalDelegationHash => _delegation.CanonicalHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalAcceptanceBytes => _acceptanceBytes.ToArray();
    public ReadOnlyMemory<byte> CanonicalAcceptanceHash => _acceptanceHash.ToArray();
}

/// <summary>
/// Non-forgeable observation of one exact owner-signed terminal RCR1. The constructor and
/// signature-policy seam remain internal; callers can persist the exact canonical bytes/hash but
/// cannot manufacture a verified revocation from a decoded model.
/// </summary>
public sealed class VerifiedProductionMailboxRouteContinuityRevocation
{
    private readonly ProductionMailboxRouteContinuityRevocation _revocation;
    private readonly byte[] _canonicalBytes;
    private readonly byte[] _canonicalHash;

    internal VerifiedProductionMailboxRouteContinuityRevocation(
        ProductionMailboxRouteContinuityRevocation revocation,
        ReadOnlySpan<byte> canonicalBytes,
        ReadOnlySpan<byte> canonicalHash)
    {
        _revocation = ProductionMailboxRouteContinuityCopy.Clone(revocation);
        _canonicalBytes = canonicalBytes.ToArray();
        _canonicalHash = canonicalHash.ToArray();
    }

    public ProductionMailboxRouteContinuityRevocation Revocation =>
        ProductionMailboxRouteContinuityCopy.Clone(_revocation);
    public ReadOnlyMemory<byte> CanonicalBytes => _canonicalBytes.ToArray();
    public ReadOnlyMemory<byte> CanonicalHash => _canonicalHash.ToArray();
}

internal sealed class VerifiedProductionMailboxRouteRevocationCheckpoint
{
    private readonly ProductionMailboxRouteRevocationCheckpoint _checkpoint;
    private readonly byte[] _canonicalHash;

    internal VerifiedProductionMailboxRouteRevocationCheckpoint(
        ProductionMailboxRouteRevocationCheckpoint checkpoint,
        ReadOnlySpan<byte> canonicalHash)
    {
        _checkpoint = ProductionMailboxRouteContinuityCopy.Clone(checkpoint);
        _canonicalHash = canonicalHash.ToArray();
    }

    internal ProductionMailboxRouteRevocationCheckpoint Checkpoint =>
        ProductionMailboxRouteContinuityCopy.Clone(_checkpoint);
    internal ReadOnlyMemory<byte> CanonicalHash => _canonicalHash.ToArray();
}

public static class ProductionMailboxRouteContinuityVerifier
{
    /// <summary>
    /// Verifies an exact canonical owner-signed terminal RCR1 against an already verified
    /// continuity enrollment using the production sodium verifier.
    /// </summary>
    public static VerifiedProductionMailboxRouteContinuityRevocation VerifyOwnerRevocation(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment,
        ulong nowUnixSeconds,
        uint clockSkewSeconds) => VerifyTerminalRevocation(encoded,
            (enrollment ?? throw new ArgumentNullException(nameof(enrollment))).VerifiedDelegation,
            nowUnixSeconds, clockSkewSeconds, new SodiumProductionMailboxRouteSignatureVerifier());

    /// <summary>
    /// Verifies the complete owner-delegation plus live old-issuer acceptance closure using the
    /// production sodium verifier. No generic forward-route capability is returned.
    /// </summary>
    public static VerifiedProductionMailboxRouteContinuityEnrollment VerifyEnrollment(
        ReadOnlySpan<byte> delegationBytes,
        ReadOnlySpan<byte> acceptanceBytes,
        VerifiedProductionMailboxAuthority anchorAuthority,
        VerifiedProductionMailboxRevocationSnapshot anchorRevocations,
        VerifiedProductionMailboxRouteCertificate anchorCertificate,
        VerifiedProductionMailboxRouteAdvertisementV2 anchorAuthorization,
        ProductionMailboxRouteContinuityEnrollmentVerificationContext context) =>
        VerifyEnrollment(delegationBytes, acceptanceBytes, anchorAuthority, anchorRevocations, anchorCertificate,
            anchorAuthorization, context, new SodiumProductionMailboxRouteSignatureVerifier());

    internal static VerifiedProductionMailboxRouteContinuityEnrollment VerifyEnrollment(
        ReadOnlySpan<byte> delegationBytes,
        ReadOnlySpan<byte> acceptanceBytes,
        VerifiedProductionMailboxAuthority anchorAuthority,
        VerifiedProductionMailboxRevocationSnapshot anchorRevocations,
        VerifiedProductionMailboxRouteCertificate anchorCertificate,
        VerifiedProductionMailboxRouteAdvertisementV2 anchorAuthorization,
        ProductionMailboxRouteContinuityEnrollmentVerificationContext context,
        IProductionMailboxRouteSignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(anchorAuthority);
        ArgumentNullException.ThrowIfNull(anchorRevocations);
        ArgumentNullException.ThrowIfNull(anchorCertificate);
        ArgumentNullException.ThrowIfNull(anchorAuthorization);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (delegationBytes.Length != ProductionMailboxRouteContinuityConstants.CanonicalDelegationLength ||
            acceptanceBytes.Length != ProductionMailboxRouteContinuityConstants.CanonicalDelegationAcceptanceLength)
            throw Error(ProductionMailboxRouteContinuityError.InvalidLength,
                "RCD1/RDA1 enrollment artifacts have invalid fixed lengths.");
        ValidateContext(context);
        context = context with
        {
            ExpectedNetworkId = context.ExpectedNetworkId.ToArray(),
            ExpectedPinnedMrXPublicKeySha256 = context.ExpectedPinnedMrXPublicKeySha256.ToArray(),
            ExpectedRouteDomainHash = context.ExpectedRouteDomainHash.ToArray(),
            ExpectedMailboxOwnerEd25519PublicKey = context.ExpectedMailboxOwnerEd25519PublicKey.ToArray(),
            ExpectedBlindedMailboxId = context.ExpectedBlindedMailboxId.ToArray(),
            ExpectedBlindedPlacementId = context.ExpectedBlindedPlacementId.ToArray(),
            ExpectedSelectionInputCommitment = context.ExpectedSelectionInputCommitment.ToArray(),
            ExpectedPreDelegationRouteOriginLkgHash =
                context.ExpectedPreDelegationRouteOriginLkgHash.ToArray(),
            LastCanonicalDelegationHash = context.LastCanonicalDelegationHash.ToArray()
        };
        ValidateContext(context);
        var frozenDelegation = delegationBytes.ToArray();
        var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(frozenDelegation);
        var delegationHash = SHA256.HashData(frozenDelegation);
        BindDelegationToContext(delegation, context);
        var authority = anchorAuthority.Authority;
        var revocations = anchorRevocations.Snapshot;
        var certificate = anchorCertificate.Certificate;
        var authorization = anchorAuthorization.Advertisement;
        Equal(revocations.NetworkId.Span, authority.NetworkId.Span,
            "Enrollment PMR1 network does not match the supplied PMA1.");
        Equal(anchorRevocations.CanonicalSnapshotHash.Span, authority.Revocation.SnapshotHash.Span,
            "Enrollment PMR1 hash does not match the supplied PMA1.");
        Equal(revocations.RevocationHeadHash.Span, authority.Revocation.HeadHash.Span,
            "Enrollment PMR1 head does not match the supplied PMA1.");
        if (revocations.AuthorityGeneration != authority.AuthorityGeneration ||
            revocations.RevocationGeneration != authority.Revocation.Generation)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "Enrollment PMR1 generation does not match the supplied PMA1.");
        Equal(certificate.NetworkId.Span, authority.NetworkId.Span,
            "Enrollment PRC1 network does not match the supplied PMA1.");
        Equal(certificate.CanonicalAuthorityHash.Span, anchorAuthority.CanonicalAuthorityHash.Span,
            "Enrollment PRC1 authority hash does not match the supplied PMA1.");
        Equal(certificate.IssuerEd25519PublicKey.Span, authority.MailboxIssuerEd25519PublicKey.Span,
            "Enrollment PRC1 issuer does not match the supplied PMA1.");
        if (certificate.AuthorityGeneration != authority.AuthorityGeneration)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "Enrollment PRC1 authority generation does not match the supplied PMA1.");
        Equal(ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
                authorization.Certificate),
            ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(certificate),
            "Enrollment PRA2 does not embed the exact supplied PRC1.");
        Equal(anchorAuthorization.RouteDomainHash.Span, delegation.RouteDomainHash.Span,
            "Enrollment PRA2 route domain does not match RCD1.");
        Equal(ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(certificate),
            delegation.RouteDomainHash.Span,
            "Enrollment PRC1 route domain does not match RCD1.");
        Equal(delegation.PinnedMrXPublicKeySha256.Span,
            SHA256.HashData(authority.MrXApprovalEd25519PublicKey.Span),
            "RCD1 pinned Mr. X key does not match the anchor PMA1.");
        Equal(delegation.AnchorCanonicalAuthorityHash.Span,
            anchorAuthority.CanonicalAuthorityHash.Span, "RCD1 anchor PMA1 hash mismatch.");
        Equal(delegation.AnchorCanonicalRouteCertificateHash.Span,
            anchorCertificate.CanonicalCertificateHash.Span, "RCD1 anchor PRC1 hash mismatch.");
        Equal(delegation.AnchorCanonicalRouteAuthorizationHash.Span,
            anchorAuthorization.CanonicalHash.Span, "RCD1 anchor PRA2 hash mismatch.");
        if (delegation.AnchorAuthorityGeneration != authority.AuthorityGeneration ||
            delegation.AnchorRouteAuthorizationSequence != authorization.Sequence)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCD1 anchor generation/sequence mismatch.");
        Equal(certificate.MailboxOwnerEd25519PublicKey.Span,
            delegation.MailboxOwnerEd25519PublicKey.Span, "RCD1 owner mismatch.");
        Equal(certificate.BlindedMailboxId.Span, delegation.BlindedMailboxId.Span,
            "RCD1 mailbox route mismatch.");
        Equal(certificate.BlindedPlacementId.Span, delegation.BlindedPlacementId.Span,
            "RCD1 placement route mismatch.");
        Equal(certificate.SelectionInputCommitment.Span, delegation.SelectionInputCommitment.Span,
            "RCD1 selection input mismatch.");
        if (!signatureVerifier.Verify(delegation.MailboxOwnerEd25519PublicKey.Span,
                ProductionMailboxRouteContinuityCodec.GetDelegationSigningBytes(delegation),
                delegation.OwnerSignature.Span))
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCD1 owner signature is invalid.");
        VerifyLive(delegation.NotBeforeUnixSeconds, delegation.ExpiresAtUnixSeconds,
            context.NowUnixSeconds, context.ClockSkewSeconds, ProtocolMagic.RCD1);
        var frozenAcceptance = acceptanceBytes.ToArray();
        var acceptance = ProductionMailboxRouteContinuityCodec.DecodeDelegationAcceptance(
            frozenAcceptance);
        Equal(acceptance.NetworkId.Span, delegation.NetworkId.Span, "RDA1 network mismatch.");
        Equal(acceptance.RouteDomainHash.Span, delegation.RouteDomainHash.Span,
            "RDA1 route-domain mismatch.");
        Equal(acceptance.CanonicalDelegationHash.Span, delegationHash, "RDA1 RCD1 hash mismatch.");
        Equal(acceptance.AnchorCanonicalAuthorityHash.Span,
            delegation.AnchorCanonicalAuthorityHash.Span, "RDA1 anchor PMA1 hash mismatch.");
        Equal(acceptance.AnchorCanonicalRouteCertificateHash.Span,
            delegation.AnchorCanonicalRouteCertificateHash.Span, "RDA1 anchor PRC1 hash mismatch.");
        Equal(acceptance.AnchorCanonicalRouteAuthorizationHash.Span,
            delegation.AnchorCanonicalRouteAuthorizationHash.Span, "RDA1 anchor PRA2 hash mismatch.");
        Equal(acceptance.PreDelegationRouteOriginLkgHash.Span,
            delegation.PreDelegationRouteOriginLkgHash.Span, "RDA1 pre-delegation ROL1 mismatch.");
        if (acceptance.AnchorAuthorityGeneration != delegation.AnchorAuthorityGeneration ||
            acceptance.AnchorAuthorizationKind != delegation.AnchorAuthorizationKind ||
            acceptance.AnchorRouteAuthorizationSequence != delegation.AnchorRouteAuthorizationSequence ||
            acceptance.RouteVerifiedAtUnixSeconds != delegation.RouteVerifiedAtUnixSeconds)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RDA1 anchor scalar fields differ from RCD1.");
        VerifyAcceptanceTime(acceptance.AcceptedAtUnixSeconds, delegation, authority, revocations,
            certificate, authorization, context.NowUnixSeconds, context.ClockSkewSeconds);
        if (!signatureVerifier.Verify(authority.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxRouteContinuityCodec.GetDelegationAcceptanceSigningBytes(acceptance),
                acceptance.AnchorIssuerSignature.Span))
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RDA1 anchor issuer signature is invalid.");
        return new VerifiedProductionMailboxRouteContinuityEnrollment(
            new VerifiedProductionMailboxRouteContinuityDelegation(
                delegation, frozenDelegation, delegationHash),
            acceptance, frozenAcceptance, SHA256.HashData(frozenAcceptance));
    }

    internal static VerifiedProductionMailboxRouteContinuityRevocation VerifyTerminalRevocation(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxRouteContinuityDelegation verifiedDelegation,
        ulong nowUnixSeconds,
        uint clockSkewSeconds,
        IProductionMailboxRouteSignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(verifiedDelegation);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (encoded.Length != ProductionMailboxRouteContinuityConstants.CanonicalRevocationLength)
            throw Error(ProductionMailboxRouteContinuityError.InvalidLength,
                "RCR1 canonical length is invalid.");
        ProductionMailboxRouteAuthorizationVerifier.ValidateClock(nowUnixSeconds, clockSkewSeconds);
        var frozen = encoded.ToArray();
        var revocation = ProductionMailboxRouteContinuityCodec.DecodeRevocation(frozen);
        var delegation = verifiedDelegation.Delegation;
        Equal(revocation.NetworkId.Span, delegation.NetworkId.Span, "RCR1 network mismatch.");
        Equal(revocation.RouteDomainHash.Span, delegation.RouteDomainHash.Span,
            "RCR1 route-domain mismatch.");
        Equal(revocation.TargetDelegationSerial.Span, delegation.DelegationSerial.Span,
            "RCR1 delegation serial mismatch.");
        Equal(revocation.TargetCanonicalDelegationHash.Span,
            verifiedDelegation.CanonicalHash.Span, "RCR1 target RCD1 hash mismatch.");
        if (revocation.RevokedAtUnixSeconds < delegation.IssuedAtUnixSeconds ||
            revocation.RevokedAtUnixSeconds > AddSkew(nowUnixSeconds, clockSkewSeconds))
            throw Error(ProductionMailboxRouteContinuityError.InvalidValidityWindow,
                "RCR1 revoked-at is outside the accepted verification interval.");
        if (!signatureVerifier.Verify(delegation.MailboxOwnerEd25519PublicKey.Span,
                ProductionMailboxRouteContinuityCodec.GetRevocationSigningBytes(revocation),
                revocation.OwnerSignature.Span))
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCR1 owner signature is invalid.");
        return new VerifiedProductionMailboxRouteContinuityRevocation(
            revocation, frozen, SHA256.HashData(frozen));
    }

    internal static VerifiedProductionMailboxRouteRevocationCheckpoint VerifyRevocationCheckpoint(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority currentAuthority,
        VerifiedProductionMailboxRevocationSnapshot currentRevocation,
        VerifiedProductionMailboxRouteContinuityDelegation delegation,
        ReadOnlySpan<byte> expectedTransitionSalt,
        ReadOnlySpan<byte> expectedContinuityCommitment,
        ulong durableOwnerRevocationGeneration,
        ReadOnlySpan<byte> durableOwnerRevocationHeadHash,
        ulong nowUnixSeconds,
        uint clockSkewSeconds,
        IProductionMailboxRouteSignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(currentAuthority);
        ArgumentNullException.ThrowIfNull(currentRevocation);
        ArgumentNullException.ThrowIfNull(delegation);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (encoded.Length != ProductionMailboxRouteContinuityConstants.CanonicalRevocationCheckpointLength ||
            expectedTransitionSalt.Length != 32 || expectedContinuityCommitment.Length != 32 ||
            durableOwnerRevocationHeadHash.Length != 32)
            throw Error(ProductionMailboxRouteContinuityError.InvalidLength,
                "RCH1 artifact or exact verification inputs have invalid fixed lengths.");
        ProductionMailboxRouteAuthorizationVerifier.ValidateClock(nowUnixSeconds, clockSkewSeconds);
        var frozen = encoded.ToArray();
        var checkpoint = ProductionMailboxRouteContinuityCodec.DecodeRevocationCheckpoint(frozen);
        var authority = currentAuthority.Authority;
        var revocation = currentRevocation.Snapshot;
        var delegationArtifact = delegation.Delegation;
        Equal(revocation.NetworkId.Span, authority.NetworkId.Span, "RCH1 PMR1 network mismatch.");
        Equal(currentRevocation.CanonicalSnapshotHash.Span, authority.Revocation.SnapshotHash.Span,
            "RCH1 PMR1 snapshot does not match PMA1.");
        Equal(revocation.RevocationHeadHash.Span, authority.Revocation.HeadHash.Span,
            "RCH1 PMR1 head does not match PMA1.");
        if (revocation.AuthorityGeneration != authority.AuthorityGeneration ||
            revocation.RevocationGeneration != authority.Revocation.Generation)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCH1 PMR1 generation does not match PMA1.");
        Equal(checkpoint.NetworkId.Span, delegationArtifact.NetworkId.Span, "RCH1 network mismatch.");
        Equal(checkpoint.RouteDomainHash.Span, delegationArtifact.RouteDomainHash.Span,
            "RCH1 route-domain mismatch.");
        Equal(checkpoint.CurrentCanonicalAuthorityHash.Span,
            currentAuthority.CanonicalAuthorityHash.Span, "RCH1 PMA1 hash mismatch.");
        Equal(checkpoint.CurrentIssuerEd25519PublicKey.Span,
            authority.MailboxIssuerEd25519PublicKey.Span, "RCH1 issuer mismatch.");
        Equal(checkpoint.TransitionSalt.Span, expectedTransitionSalt, "RCH1 salt mismatch.");
        Equal(checkpoint.ContinuityTransitionCommitment.Span, expectedContinuityCommitment,
            "RCH1 continuity commitment mismatch.");
        if (checkpoint.CurrentAuthorityGeneration != authority.AuthorityGeneration ||
            checkpoint.CurrentAuthorityGeneration > delegationArtifact.MaximumAuthorityGeneration)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCH1 authority generation is outside the delegated ceiling.");
        if (durableOwnerRevocationGeneration == 1)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "A known exact owner revocation forbids every later RCH1 activation.");
        if (durableOwnerRevocationGeneration != 0 ||
            durableOwnerRevocationHeadHash.IndexOfAnyExcept((byte)0) >= 0 ||
            checkpoint.Status != ProductionMailboxRouteRevocationStatus.Active ||
            checkpoint.CurrentOwnerRevocationGeneration != 0 ||
            checkpoint.CurrentOwnerRevocationHeadHash.Span.IndexOfAnyExcept((byte)0) >= 0)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "Only exact durable Active 0/zero state may yield an activation checkpoint.");
        VerifyLive(checkpoint.IssuedAtUnixSeconds, checkpoint.ExpiresAtUnixSeconds,
            nowUnixSeconds, clockSkewSeconds, ProtocolMagic.RCH1);
        if (checkpoint.IssuedAtUnixSeconds < authority.MrXApproval.RolloutNotBeforeUnixSeconds ||
            checkpoint.ExpiresAtUnixSeconds > authority.MrXApproval.RolloutNotAfterUnixSeconds ||
            checkpoint.IssuedAtUnixSeconds < revocation.IssuedAtUnixSeconds ||
            checkpoint.ExpiresAtUnixSeconds > revocation.ExpiresAtUnixSeconds)
            throw Error(ProductionMailboxRouteContinuityError.InvalidValidityWindow,
                "RCH1 lifetime escapes PMA1/PMR1.");
        if (!signatureVerifier.Verify(authority.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxRouteContinuityCodec.GetRevocationCheckpointSigningBytes(checkpoint),
                checkpoint.CurrentIssuerSignature.Span))
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCH1 current-issuer signature is invalid.");
        return new VerifiedProductionMailboxRouteRevocationCheckpoint(
            checkpoint, SHA256.HashData(frozen));
    }

    private static void ValidateContext(ProductionMailboxRouteContinuityEnrollmentVerificationContext context)
    {
        if (context.ExpectedNetworkId.Length != 16 ||
            context.ExpectedPinnedMrXPublicKeySha256.Length != 32 ||
            context.ExpectedRouteDomainHash.Length != 32 ||
            context.ExpectedMailboxOwnerEd25519PublicKey.Length != 32 ||
            context.ExpectedBlindedMailboxId.Length != 32 ||
            context.ExpectedBlindedPlacementId.Length != 32 ||
            context.ExpectedSelectionInputCommitment.Length != 32 ||
            context.ExpectedPreDelegationRouteOriginLkgHash.Length != 32 ||
            context.LastCanonicalDelegationHash.Length != 32)
            throw Error(ProductionMailboxRouteContinuityError.InvalidLength,
                "RCD1 enrollment context fixed field length is invalid.");
        ProductionMailboxRouteAuthorizationVerifier.ValidateClock(
            context.NowUnixSeconds, context.ClockSkewSeconds);
        var lastIsZero = context.LastCanonicalDelegationHash.Span.IndexOfAnyExcept((byte)0) < 0;
        if ((context.LastDelegationSequence == 0) != lastIsZero ||
            context.ExpectedRouteVerifiedAtUnixSeconds == 0 ||
            context.ExpectedRouteVerifiedAtUnixSeconds == ulong.MaxValue)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCD1 enrollment CAS/origin context is inconsistent.");
    }

    private static void BindDelegationToContext(
        ProductionMailboxRouteContinuityDelegation delegation,
        ProductionMailboxRouteContinuityEnrollmentVerificationContext context)
    {
        Equal(delegation.NetworkId.Span, context.ExpectedNetworkId.Span, "RCD1 network mismatch.");
        Equal(delegation.PinnedMrXPublicKeySha256.Span,
            context.ExpectedPinnedMrXPublicKeySha256.Span, "RCD1 Mr. X pin mismatch.");
        Equal(delegation.RouteDomainHash.Span, context.ExpectedRouteDomainHash.Span,
            "RCD1 route-domain mismatch.");
        Equal(delegation.MailboxOwnerEd25519PublicKey.Span,
            context.ExpectedMailboxOwnerEd25519PublicKey.Span, "RCD1 owner mismatch.");
        Equal(delegation.BlindedMailboxId.Span, context.ExpectedBlindedMailboxId.Span,
            "RCD1 mailbox ID mismatch.");
        Equal(delegation.BlindedPlacementId.Span, context.ExpectedBlindedPlacementId.Span,
            "RCD1 placement ID mismatch.");
        Equal(delegation.SelectionInputCommitment.Span,
            context.ExpectedSelectionInputCommitment.Span, "RCD1 selection input mismatch.");
        Equal(delegation.PreDelegationRouteOriginLkgHash.Span,
            context.ExpectedPreDelegationRouteOriginLkgHash.Span,
            "RCD1 pre-delegation ROL1 mismatch.");
        Equal(delegation.PreviousCanonicalDelegationHash.Span,
            context.LastCanonicalDelegationHash.Span, "RCD1 predecessor hash mismatch.");
        if (delegation.RouteVerifiedAtUnixSeconds != context.ExpectedRouteVerifiedAtUnixSeconds ||
            context.LastDelegationSequence == ulong.MaxValue ||
            delegation.DelegationSequence != context.LastDelegationSequence + 1)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCD1 RouteVerifiedAt or delegation sequence CAS mismatch.");
    }

    private static void VerifyAcceptanceTime(
        ulong acceptedAt,
        ProductionMailboxRouteContinuityDelegation delegation,
        ProductionMailboxAuthority authority,
        ProductionMailboxRevocationSnapshot revocations,
        ProductionMailboxRouteCertificate certificate,
        ProductionMailboxRouteAdvertisementV2 authorization,
        ulong now,
        uint skew)
    {
        if (acceptedAt < delegation.IssuedAtUnixSeconds ||
            acceptedAt < delegation.NotBeforeUnixSeconds || acceptedAt >= delegation.ExpiresAtUnixSeconds ||
            acceptedAt < authority.CurrentEpoch.NotBeforeUnixSeconds ||
            acceptedAt >= authority.CurrentEpoch.NotAfterUnixSeconds ||
            acceptedAt < authority.MrXApproval.RolloutNotBeforeUnixSeconds ||
            acceptedAt >= authority.MrXApproval.RolloutNotAfterUnixSeconds ||
            acceptedAt < authority.Revocation.IssuedAtUnixSeconds ||
            acceptedAt >= authority.Revocation.ExpiresAtUnixSeconds ||
            acceptedAt < revocations.IssuedAtUnixSeconds ||
            acceptedAt >= revocations.ExpiresAtUnixSeconds ||
            acceptedAt < certificate.IssuedAtUnixSeconds || acceptedAt >= certificate.ExpiresAtUnixSeconds ||
            acceptedAt < authorization.PublishedAtUnixSeconds || acceptedAt >= authorization.ExpiresAtUnixSeconds ||
            acceptedAt > AddSkew(now, skew) ||
            (now > acceptedAt && now - acceptedAt > skew))
            throw Error(ProductionMailboxRouteContinuityError.InvalidValidityWindow,
                "RDA1 accepted-at is not inside the exact live anchor closure/transaction skew.");
    }

    private static void VerifyLive(ulong from, ulong until, ulong now, uint skew, string name) =>
        ProductionMailboxRouteAuthorizationVerifier.VerifyLive(from, until, now, skew, name);

    private static ulong AddSkew(ulong value, uint skew) =>
        value > ulong.MaxValue - skew ? ulong.MaxValue : value + skew;

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string message)
    {
        if (actual.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw Error(ProductionMailboxRouteContinuityError.InvalidField, message);
    }

    private static ProductionMailboxRouteContinuityException Error(
        ProductionMailboxRouteContinuityError error, string message) => new(error, message);
}
