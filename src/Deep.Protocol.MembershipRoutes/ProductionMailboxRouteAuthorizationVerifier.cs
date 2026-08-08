using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

public sealed record ProductionMailboxOwnerRouteAuthorizationVerificationContext
{
    public required ReadOnlyMemory<byte> ExpectedNetworkId { get; init; }
    public required ReadOnlyMemory<byte> ExpectedRouteDomainHash { get; init; }
    public required ProductionMailboxRouteAuthorizationKind ExpectedPredecessorKind { get; init; }
    public required ReadOnlyMemory<byte> ExpectedPredecessorHash { get; init; }
    public required ulong ExpectedPredecessorSequence { get; init; }
    public required ulong NowUnixSeconds { get; init; }
    public required uint ClockSkewSeconds { get; init; }
}

public sealed class VerifiedProductionMailboxRouteAdvertisementV2
{
    private readonly ProductionMailboxRouteAdvertisementV2 _advertisement;
    private readonly byte[] _canonicalBytes;
    private readonly byte[] _canonicalHash;
    private readonly byte[] _routeDomainHash;

    internal VerifiedProductionMailboxRouteAdvertisementV2(
        ProductionMailboxRouteAdvertisementV2 advertisement,
        ReadOnlySpan<byte> canonicalBytes,
        ReadOnlySpan<byte> canonicalHash,
        ReadOnlySpan<byte> routeDomainHash)
    {
        _advertisement = ProductionMailboxRouteAuthorizationCopy.Clone(advertisement);
        _canonicalBytes = canonicalBytes.ToArray();
        _canonicalHash = canonicalHash.ToArray();
        _routeDomainHash = routeDomainHash.ToArray();
    }

    public ProductionMailboxRouteAdvertisementV2 Advertisement =>
        ProductionMailboxRouteAuthorizationCopy.Clone(_advertisement);
    public ReadOnlyMemory<byte> CanonicalBytes => _canonicalBytes.ToArray();
    public ReadOnlyMemory<byte> CanonicalHash => _canonicalHash.ToArray();
    public ReadOnlyMemory<byte> RouteDomainHash => _routeDomainHash.ToArray();
}

internal sealed class VerifiedProductionMailboxRouteTransitionContext
{
    private readonly ProductionMailboxRouteTransitionContext _context;
    private readonly byte[] _canonicalBytes;
    private readonly byte[] _canonicalHash;

    internal VerifiedProductionMailboxRouteTransitionContext(
        ProductionMailboxRouteTransitionContext context,
        ReadOnlySpan<byte> canonicalBytes,
        ReadOnlySpan<byte> canonicalHash)
    {
        _context = ProductionMailboxRouteAuthorizationCopy.Clone(context);
        _canonicalBytes = canonicalBytes.ToArray();
        _canonicalHash = canonicalHash.ToArray();
    }

    internal ProductionMailboxRouteTransitionContext Context =>
        ProductionMailboxRouteAuthorizationCopy.Clone(_context);
    internal ReadOnlyMemory<byte> CanonicalBytes => _canonicalBytes.ToArray();
    internal ReadOnlyMemory<byte> CanonicalHash => _canonicalHash.ToArray();
}

internal sealed class VerifiedProductionMailboxRouteContinuityActivation
{
    private readonly ProductionMailboxRouteContinuityActivation _activation;
    private readonly byte[] _canonicalBytes;
    private readonly byte[] _canonicalHash;

    internal VerifiedProductionMailboxRouteContinuityActivation(
        ProductionMailboxRouteContinuityActivation activation,
        ReadOnlySpan<byte> canonicalBytes,
        ReadOnlySpan<byte> canonicalHash)
    {
        _activation = ProductionMailboxRouteAuthorizationCopy.Clone(activation);
        _canonicalBytes = canonicalBytes.ToArray();
        _canonicalHash = canonicalHash.ToArray();
    }

    internal ProductionMailboxRouteContinuityActivation Activation =>
        ProductionMailboxRouteAuthorizationCopy.Clone(_activation);
    internal ReadOnlyMemory<byte> CanonicalBytes => _canonicalBytes.ToArray();
    internal ReadOnlyMemory<byte> CanonicalHash => _canonicalHash.ToArray();
}

public static class ProductionMailboxRouteAuthorizationVerifier
{
    /// <summary>
    /// Verifies a live owner-online PRA2 using the production sodium verifier. The injectable core
    /// remains assembly-internal so callers cannot substitute production signature policy.
    /// </summary>
    public static VerifiedProductionMailboxRouteAdvertisementV2 VerifyOwnerAuthorization(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority verifiedAuthority,
        ProductionMailboxOwnerRouteAuthorizationVerificationContext context) =>
        VerifyOwnerAuthorization(encoded, verifiedAuthority, context,
            new SodiumProductionMailboxRouteSignatureVerifier());

    internal static VerifiedProductionMailboxRouteAdvertisementV2 VerifyOwnerAuthorization(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority verifiedAuthority,
        ProductionMailboxOwnerRouteAuthorizationVerificationContext context,
        IProductionMailboxRouteSignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(verifiedAuthority);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (encoded.Length != ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length ||
            context.ExpectedNetworkId.Length != 16 || context.ExpectedRouteDomainHash.Length != 32 ||
            context.ExpectedPredecessorHash.Length != 32)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidLength,
                "PRA2 artifact or verification context has an invalid fixed length.");
        ValidateClock(context.NowUnixSeconds, context.ClockSkewSeconds);
        var expectedNetwork = context.ExpectedNetworkId.ToArray();
        var expectedRoute = context.ExpectedRouteDomainHash.ToArray();
        var expectedPredecessor = context.ExpectedPredecessorHash.ToArray();
        var frozen = encoded.ToArray();
        var advertisement = ProductionMailboxRouteAuthorizationCodec.DecodeAdvertisementV2(frozen);
        var authority = verifiedAuthority.Authority;
        Equal(advertisement.Certificate.NetworkId.Span, expectedNetwork, "PRA2 network mismatch.");
        Equal(advertisement.Certificate.NetworkId.Span, authority.NetworkId.Span,
            "PRA2 authority network mismatch.");
        Equal(advertisement.Certificate.CanonicalAuthorityHash.Span,
            verifiedAuthority.CanonicalAuthorityHash.Span, "PRA2 authority hash mismatch.");
        if (advertisement.Certificate.AuthorityGeneration != authority.AuthorityGeneration)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "PRA2 authority generation mismatch.");
        var routeDomain = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(
            advertisement.Certificate);
        Equal(routeDomain, expectedRoute, "PRA2 route-domain mismatch.");
        if (advertisement.PredecessorAuthorizationKind != context.ExpectedPredecessorKind ||
            advertisement.PredecessorRouteAuthorizationSequence != context.ExpectedPredecessorSequence)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "PRA2 predecessor kind or sequence does not match durable CAS state.");
        Equal(advertisement.PredecessorCanonicalRouteAuthorizationHash.Span, expectedPredecessor,
            "PRA2 predecessor hash mismatch.");
        VerifyLive(advertisement.PublishedAtUnixSeconds, advertisement.ExpiresAtUnixSeconds,
            context.NowUnixSeconds, context.ClockSkewSeconds, "PRA2");
        VerifyLiveAuthority(authority, context.NowUnixSeconds, context.ClockSkewSeconds);
        var certificateBytes = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
            advertisement.Certificate);
        _ = ProductionMailboxRouteCertificateVerifier.Verify(certificateBytes, verifiedAuthority,
            context.NowUnixSeconds, context.ClockSkewSeconds, signatureVerifier);
        EnsureContained(advertisement.PublishedAtUnixSeconds, advertisement.ExpiresAtUnixSeconds,
            advertisement.Certificate.IssuedAtUnixSeconds, advertisement.Certificate.ExpiresAtUnixSeconds,
            "PRA2 within PRC1");
        EnsureContained(advertisement.PublishedAtUnixSeconds, advertisement.ExpiresAtUnixSeconds,
            authority.CurrentEpoch.NotBeforeUnixSeconds, authority.CurrentEpoch.NotAfterUnixSeconds,
            "PRA2 within PMA1 current epoch");
        EnsureContained(advertisement.PublishedAtUnixSeconds, advertisement.ExpiresAtUnixSeconds,
            authority.MrXApproval.RolloutNotBeforeUnixSeconds,
            authority.MrXApproval.RolloutNotAfterUnixSeconds, "PRA2 within PMA1 rollout");
        EnsureContained(advertisement.PublishedAtUnixSeconds, advertisement.ExpiresAtUnixSeconds,
            authority.Revocation.IssuedAtUnixSeconds, authority.Revocation.ExpiresAtUnixSeconds,
            "PRA2 within PMA1/PMR1 revocation window");
        var ownerKey = advertisement.Certificate.MailboxOwnerEd25519PublicKey.ToArray();
        var signature = advertisement.OwnerSignature.ToArray();
        if (!signatureVerifier.Verify(ownerKey,
                ProductionMailboxRouteAuthorizationCodec.GetAdvertisementV2SigningBytes(advertisement),
                signature))
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "PRA2 owner signature is invalid.");
        return new VerifiedProductionMailboxRouteAdvertisementV2(
            advertisement, frozen, SHA256.HashData(frozen), routeDomain);
    }

    internal static VerifiedProductionMailboxRouteTransitionContext VerifyTransitionContext(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> expectedNetworkId,
        ReadOnlySpan<byte> expectedRouteDomainHash,
        ReadOnlySpan<byte> expectedOldSelectionHash,
        ReadOnlySpan<byte> expectedNewSelectionHash,
        ReadOnlySpan<byte> expectedOldRouteOriginLkgHash,
        ulong expectedRouteVerifiedAt,
        ulong expectedLocalCommitGeneration)
    {
        if (encoded.Length != ProductionMailboxRouteAuthorizationConstants.CanonicalTransitionContextLength ||
            expectedNetworkId.Length != 16 || expectedRouteDomainHash.Length != 32 ||
            expectedOldSelectionHash.Length != 32 || expectedNewSelectionHash.Length != 32 ||
            expectedOldRouteOriginLkgHash.Length != 32)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidLength,
                "RTC1 artifact or exact sealed inputs have invalid fixed lengths.");
        var frozen = encoded.ToArray();
        var context = ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(frozen);
        Equal(context.NetworkId.Span, expectedNetworkId, "RTC1 network mismatch.");
        Equal(context.RouteDomainHash.Span, expectedRouteDomainHash, "RTC1 route-domain mismatch.");
        Equal(context.OldCanonicalSelectionHash.Span, expectedOldSelectionHash,
            "RTC1 old PMS1 hash mismatch.");
        Equal(context.NewCanonicalSelectionHash.Span, expectedNewSelectionHash,
            "RTC1 new PMS1 hash mismatch.");
        Equal(context.SealedOldRouteOriginLkgHash.Span, expectedOldRouteOriginLkgHash,
            "RTC1 sealed ROL1 hash mismatch.");
        if (context.OldRouteVerifiedAtUnixSeconds != expectedRouteVerifiedAt ||
            context.OldLocalRouteCommitGeneration != expectedLocalCommitGeneration)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "RTC1 sealed route time/generation mismatch.");
        return new VerifiedProductionMailboxRouteTransitionContext(context, frozen,
            ProductionMailboxRouteAuthorizationCodec.ComputeTransitionContextHash(context));
    }

    internal static VerifiedProductionMailboxRouteContinuityActivation VerifyDelegatedActivation(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority verifiedAuthority,
        VerifiedProductionMailboxRevocationSnapshot verifiedRevocation,
        VerifiedProductionMailboxRouteCertificate verifiedCertificate,
        VerifiedProductionMailboxRouteRevocationCheckpoint verifiedCheckpoint,
        VerifiedProductionMailboxRouteTransitionContext verifiedTransition,
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment,
        ulong nowUnixSeconds,
        uint clockSkewSeconds,
        IProductionMailboxRouteSignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(verifiedAuthority);
        ArgumentNullException.ThrowIfNull(verifiedRevocation);
        ArgumentNullException.ThrowIfNull(verifiedCertificate);
        ArgumentNullException.ThrowIfNull(verifiedCheckpoint);
        ArgumentNullException.ThrowIfNull(verifiedTransition);
        ArgumentNullException.ThrowIfNull(enrollment);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (encoded.Length != ProductionMailboxRouteAuthorizationConstants.CanonicalContinuityActivationLength)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidLength,
                "RCA1 canonical length is invalid.");
        ValidateClock(nowUnixSeconds, clockSkewSeconds);
        var frozen = encoded.ToArray();
        var activation = ProductionMailboxRouteAuthorizationCodec.DecodeContinuityActivation(frozen);
        var authority = verifiedAuthority.Authority;
        var revocation = verifiedRevocation.Snapshot;
        var certificate = verifiedCertificate.Certificate;
        var checkpoint = verifiedCheckpoint.Checkpoint;
        var transition = verifiedTransition.Context;
        var delegation = enrollment.Delegation;
        var acceptance = enrollment.Acceptance;
        Equal(revocation.NetworkId.Span, authority.NetworkId.Span, "RCA1 PMR1 network mismatch.");
        Equal(verifiedRevocation.CanonicalSnapshotHash.Span, authority.Revocation.SnapshotHash.Span,
            "RCA1 PMR1 snapshot does not match PMA1.");
        if (revocation.AuthorityGeneration != authority.AuthorityGeneration ||
            revocation.RevocationGeneration != authority.Revocation.Generation)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "RCA1 PMR1 generation does not match PMA1.");
        Equal(activation.NetworkId.Span, authority.NetworkId.Span, "RCA1 network mismatch.");
        Equal(activation.RouteDomainHash.Span, delegation.RouteDomainHash.Span,
            "RCA1 route-domain mismatch.");
        Equal(activation.CurrentCanonicalAuthorityHash.Span,
            verifiedAuthority.CanonicalAuthorityHash.Span, "RCA1 PMA1 hash mismatch.");
        Equal(activation.CurrentIssuerEd25519PublicKey.Span,
            authority.MailboxIssuerEd25519PublicKey.Span, "RCA1 issuer mismatch.");
        if (activation.CurrentAuthorityGeneration != authority.AuthorityGeneration ||
            activation.CurrentAuthorityGeneration > delegation.MaximumAuthorityGeneration)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "RCA1 authority generation is outside the delegated ceiling.");
        if (activation.CurrentRevocationGeneration != revocation.RevocationGeneration)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "RCA1 PMR1 generation mismatch.");
        Equal(activation.CurrentRevocationHeadHash.Span, revocation.RevocationHeadHash.Span,
            "RCA1 PMR1 head mismatch.");
        Equal(activation.CurrentRevocationSnapshotHash.Span,
            verifiedRevocation.CanonicalSnapshotHash.Span, "RCA1 PMR1 snapshot mismatch.");
        Equal(activation.TransitionSalt.Span, checkpoint.TransitionSalt.Span,
            "RCA1 transition salt mismatch.");
        Equal(activation.ContinuityTransitionCommitment.Span,
            checkpoint.ContinuityTransitionCommitment.Span, "RCA1 continuity commitment mismatch.");
        Equal(activation.CanonicalRevocationCheckpointHash.Span,
            verifiedCheckpoint.CanonicalHash.Span, "RCA1 RCH1 hash mismatch.");
        Equal(activation.FreshCanonicalRouteCertificateHash.Span,
            verifiedCertificate.CanonicalCertificateHash.Span, "RCA1 PRC1 hash mismatch.");
        Equal(activation.CanonicalTransitionContextHash.Span,
            verifiedTransition.CanonicalHash.Span, "RCA1 RTC1 hash mismatch.");
        Equal(transition.NetworkId.Span, activation.NetworkId.Span, "RTC1/RCA1 network mismatch.");
        Equal(transition.RouteDomainHash.Span, activation.RouteDomainHash.Span,
            "RTC1/RCA1 route-domain mismatch.");
        Equal(transition.TransitionSalt.Span, activation.TransitionSalt.Span,
            "RTC1/RCA1 salt mismatch.");
        Equal(transition.ContinuityTransitionCommitment.Span,
            activation.ContinuityTransitionCommitment.Span, "RTC1/RCA1 commitment mismatch.");
        Equal(transition.CanonicalRevocationCheckpointHash.Span,
            activation.CanonicalRevocationCheckpointHash.Span, "RTC1/RCA1 RCH1 mismatch.");
        Equal(transition.CurrentCanonicalAuthorityHash.Span,
            activation.CurrentCanonicalAuthorityHash.Span, "RTC1/RCA1 PMA1 mismatch.");
        Equal(transition.FreshCanonicalRouteCertificateHash.Span,
            activation.FreshCanonicalRouteCertificateHash.Span, "RTC1/RCA1 PRC1 mismatch.");
        if (transition.NewAuthorizationKind != ProductionMailboxRouteAuthorizationKind.DelegatedRCA1 ||
            transition.CurrentAuthorityGeneration != activation.CurrentAuthorityGeneration)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "RTC1 mode or authority generation does not authorize RCA1.");
        if (activation.PredecessorAuthorizationKind != transition.PredecessorAuthorizationKind ||
            activation.PredecessorRouteAuthorizationSequence != transition.PredecessorRouteAuthorizationSequence ||
            activation.ActivationSequence != transition.NewRouteAuthorizationSequence)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "RCA1 predecessor/new sequence differs from RTC1.");
        Equal(activation.PredecessorCanonicalRouteAuthorizationHash.Span,
            transition.PredecessorCanonicalRouteAuthorizationHash.Span,
            "RCA1 predecessor hash differs from RTC1.");
        if (activation.ActivationSequence < delegation.FirstActivationSequence ||
            activation.ActivationSequence > delegation.LastActivationSequence)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "RCA1 activation sequence is outside the delegated range.");
        if (!certificate.NetworkId.Span.SequenceEqual(activation.NetworkId.Span) ||
            !certificate.CanonicalAuthorityHash.Span.SequenceEqual(activation.CurrentCanonicalAuthorityHash.Span) ||
            !certificate.MailboxOwnerEd25519PublicKey.Span.SequenceEqual(
                delegation.MailboxOwnerEd25519PublicKey.Span) ||
            !certificate.BlindedMailboxId.Span.SequenceEqual(delegation.BlindedMailboxId.Span) ||
            !certificate.BlindedPlacementId.Span.SequenceEqual(delegation.BlindedPlacementId.Span) ||
            !certificate.SelectionInputCommitment.Span.SequenceEqual(delegation.SelectionInputCommitment.Span))
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "RCA1 fresh PRC1 does not preserve the exact delegated owner route.");
        var expectedCommitment = ProductionMailboxRouteContinuityCodec.ComputeContinuityTransitionCommitment(
            transition.TransitionSalt.Span, transition.NetworkId.Span, transition.RouteDomainHash.Span,
            enrollment.CanonicalDelegationHash.Span, enrollment.CanonicalAcceptanceHash.Span,
            transition.SealedOldRouteOriginLkgHash.Span, checkpoint.CurrentOwnerRevocationGeneration,
            checkpoint.CurrentOwnerRevocationHeadHash.Span, transition.CurrentCanonicalAuthorityHash.Span,
            transition.FreshCanonicalRouteCertificateHash.Span, transition.PredecessorAuthorizationKind,
            transition.PredecessorCanonicalRouteAuthorizationHash.Span,
            transition.PredecessorRouteAuthorizationSequence, transition.NewRouteAuthorizationSequence);
        Equal(transition.ContinuityTransitionCommitment.Span, expectedCommitment,
            "RTC1 continuity commitment does not bind the exact sealed enrollment.");
        VerifyLive(transition.NotBeforeUnixSeconds, transition.ExpiresAtUnixSeconds,
            nowUnixSeconds, clockSkewSeconds, "RTC1");
        VerifyLive(activation.IssuedAtUnixSeconds, activation.ExpiresAtUnixSeconds,
            nowUnixSeconds, clockSkewSeconds, "RCA1");
        if (activation.IssuedAtUnixSeconds < acceptance.AcceptedAtUnixSeconds ||
            activation.IssuedAtUnixSeconds < delegation.NotBeforeUnixSeconds ||
            activation.IssuedAtUnixSeconds < checkpoint.IssuedAtUnixSeconds ||
            activation.IssuedAtUnixSeconds < certificate.IssuedAtUnixSeconds ||
            activation.ExpiresAtUnixSeconds > delegation.ExpiresAtUnixSeconds ||
            activation.ExpiresAtUnixSeconds > checkpoint.ExpiresAtUnixSeconds ||
            activation.ExpiresAtUnixSeconds > certificate.ExpiresAtUnixSeconds ||
            activation.IssuedAtUnixSeconds < authority.CurrentEpoch.NotBeforeUnixSeconds ||
            activation.ExpiresAtUnixSeconds > authority.CurrentEpoch.NotAfterUnixSeconds ||
            activation.IssuedAtUnixSeconds < authority.MrXApproval.RolloutNotBeforeUnixSeconds ||
            activation.ExpiresAtUnixSeconds > authority.MrXApproval.RolloutNotAfterUnixSeconds ||
            activation.IssuedAtUnixSeconds < authority.Revocation.IssuedAtUnixSeconds ||
            activation.ExpiresAtUnixSeconds > authority.Revocation.ExpiresAtUnixSeconds ||
            activation.IssuedAtUnixSeconds < revocation.IssuedAtUnixSeconds ||
            activation.ExpiresAtUnixSeconds > revocation.ExpiresAtUnixSeconds)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidValidityWindow,
                "RCA1 lifetime escapes a delegated parent window.");
        EnsureContained(transition.NotBeforeUnixSeconds, transition.ExpiresAtUnixSeconds,
            delegation.NotBeforeUnixSeconds, delegation.ExpiresAtUnixSeconds, "RTC1 within RCD1");
        EnsureContained(transition.NotBeforeUnixSeconds, transition.ExpiresAtUnixSeconds,
            checkpoint.IssuedAtUnixSeconds, checkpoint.ExpiresAtUnixSeconds, "RTC1 within RCH1");
        EnsureContained(transition.NotBeforeUnixSeconds, transition.ExpiresAtUnixSeconds,
            certificate.IssuedAtUnixSeconds, certificate.ExpiresAtUnixSeconds, "RTC1 within PRC1");
        EnsureContained(transition.NotBeforeUnixSeconds, transition.ExpiresAtUnixSeconds,
            activation.IssuedAtUnixSeconds, activation.ExpiresAtUnixSeconds, "RTC1 within RCA1");
        EnsureContained(transition.NotBeforeUnixSeconds, transition.ExpiresAtUnixSeconds,
            authority.CurrentEpoch.NotBeforeUnixSeconds, authority.CurrentEpoch.NotAfterUnixSeconds,
            "RTC1 within PMA1 current epoch");
        EnsureContained(transition.NotBeforeUnixSeconds, transition.ExpiresAtUnixSeconds,
            authority.MrXApproval.RolloutNotBeforeUnixSeconds,
            authority.MrXApproval.RolloutNotAfterUnixSeconds, "RTC1 within PMA1 rollout");
        EnsureContained(transition.NotBeforeUnixSeconds, transition.ExpiresAtUnixSeconds,
            authority.Revocation.IssuedAtUnixSeconds, authority.Revocation.ExpiresAtUnixSeconds,
            "RTC1 within PMA1 revocation window");
        EnsureContained(transition.NotBeforeUnixSeconds, transition.ExpiresAtUnixSeconds,
            revocation.IssuedAtUnixSeconds, revocation.ExpiresAtUnixSeconds, "RTC1 within PMR1");
        if (!signatureVerifier.Verify(authority.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxRouteAuthorizationCodec.GetContinuityActivationSigningBytes(activation),
                activation.CurrentIssuerSignature.Span))
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "RCA1 current-issuer signature is invalid.");
        return new VerifiedProductionMailboxRouteContinuityActivation(
            activation, frozen, SHA256.HashData(frozen));
    }

    internal static void ValidateClock(ulong now, uint skew)
    {
        if (now == 0 || now == ulong.MaxValue ||
            skew > ProductionMailboxRouteContinuityConstants.MaximumClockSkewSeconds)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "Route authorization verification clock is unsafe.");
    }

    internal static void VerifyLive(ulong from, ulong until, ulong now, uint skew, string name)
    {
        if (now < from && from - now > skew)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidValidityWindow,
                $"{name} is not yet valid.");
        if (now > until && now - until > skew)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidValidityWindow,
                $"{name} has expired.");
    }

    internal static void VerifyLiveAuthority(ProductionMailboxAuthority authority, ulong now, uint skew)
    {
        if (authority.DevelopmentOnly || authority.Environment != ProductionMailboxAuthorityEnvironment.Production)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "Development mailbox authority is forbidden.");
        VerifyLive(authority.CurrentEpoch.NotBeforeUnixSeconds, authority.CurrentEpoch.NotAfterUnixSeconds,
            now, skew, "PMA1 current epoch");
        VerifyLive(authority.MrXApproval.RolloutNotBeforeUnixSeconds,
            authority.MrXApproval.RolloutNotAfterUnixSeconds, now, skew, "PMA1 rollout");
        VerifyLive(authority.Revocation.IssuedAtUnixSeconds, authority.Revocation.ExpiresAtUnixSeconds,
            now, skew, "PMA1 revocation state");
    }

    private static void EnsureContained(
        ulong childFrom, ulong childUntil, ulong parentFrom, ulong parentUntil, string name)
    {
        if (childFrom < parentFrom || childUntil > parentUntil)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidValidityWindow,
                $"{name} escapes its parent validity window.");
    }

    internal static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string message)
    {
        if (actual.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField, message);
    }

    internal static ProductionMailboxRouteAuthorizationException Error(
        ProductionMailboxRouteAuthorizationError error, string message) => new(error, message);
}
