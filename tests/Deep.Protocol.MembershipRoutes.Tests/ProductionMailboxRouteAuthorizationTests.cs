using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class ProductionMailboxRouteAuthorizationTests
{
    [Fact]
    public void PraRtcRca_CodecsRoundTripExactFixedLayouts()
    {
        var f = RouteV2TestFixture.Create();
        var rtc = Transition(f);
        var rca = Activation(f, rtc);

        var praBytes = ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(f.Pra);
        var rtcBytes = ProductionMailboxRouteAuthorizationCodec.EncodeTransitionContext(rtc);
        var rcaBytes = ProductionMailboxRouteAuthorizationCodec.EncodeContinuityActivation(rca);
        Assert.Equal(448, praBytes.Length);
        Assert.Equal(408, rtcBytes.Length);
        Assert.Equal(496, rcaBytes.Length);
        Assert.Equal(praBytes, ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(
            ProductionMailboxRouteAuthorizationCodec.DecodeAdvertisementV2(praBytes)));
        Assert.Equal(rtcBytes, ProductionMailboxRouteAuthorizationCodec.EncodeTransitionContext(
            ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(rtcBytes)));
        Assert.Equal(rcaBytes, ProductionMailboxRouteAuthorizationCodec.EncodeContinuityActivation(
            ProductionMailboxRouteAuthorizationCodec.DecodeContinuityActivation(rcaBytes)));
    }

    [Fact]
    public void OwnerAndDelegatedAuthorization_VerifyExactCrossBindings_AndRejectTamper()
    {
        var f = RouteV2TestFixture.Create();
        var verifiedPra = ProductionMailboxRouteAuthorizationVerifier.VerifyOwnerAuthorization(
            ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(f.Pra), f.Authority,
            new ProductionMailboxOwnerRouteAuthorizationVerificationContext
            {
                ExpectedNetworkId = f.NetworkId,
                ExpectedRouteDomainHash = f.RouteDomainHash,
                ExpectedPredecessorKind = f.Pra.PredecessorAuthorizationKind,
                ExpectedPredecessorHash = f.Pra.PredecessorCanonicalRouteAuthorizationHash,
                ExpectedPredecessorSequence = f.Pra.PredecessorRouteAuthorizationSequence,
                NowUnixSeconds = RouteV2TestFixture.Now,
                ClockSkewSeconds = 0
            }, new SodiumProductionMailboxRouteSignatureVerifier());
        Assert.Equal(f.Pra.Sequence, verifiedPra.Advertisement.Sequence);

        var rtc = Transition(f);
        var rtcBytes = ProductionMailboxRouteAuthorizationCodec.EncodeTransitionContext(rtc);
        var verifiedRtc = ProductionMailboxRouteAuthorizationVerifier.VerifyTransitionContext(
            rtcBytes, f.NetworkId, f.RouteDomainHash, rtc.OldCanonicalSelectionHash.Span,
            rtc.NewCanonicalSelectionHash.Span, rtc.SealedOldRouteOriginLkgHash.Span,
            rtc.OldRouteVerifiedAtUnixSeconds, rtc.OldLocalRouteCommitGeneration);
        var enrollment = ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(
            ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation),
            ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(f.Acceptance),
            f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra, f.EnrollmentContext,
            new SodiumProductionMailboxRouteSignatureVerifier());
        var verifiedRch = ProductionMailboxRouteContinuityVerifier.VerifyRevocationCheckpoint(
            ProductionMailboxRouteContinuityCodec.EncodeRevocationCheckpoint(f.Checkpoint),
            f.Authority, f.RevocationSnapshot, enrollment.VerifiedDelegation,
            f.Salt, f.Commitment, 0, new byte[32], RouteV2TestFixture.Now, 0,
            new SodiumProductionMailboxRouteSignatureVerifier());
        var rca = Activation(f, rtc);
        var verifiedRca = ProductionMailboxRouteAuthorizationVerifier.VerifyDelegatedActivation(
            ProductionMailboxRouteAuthorizationCodec.EncodeContinuityActivation(rca),
            f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, verifiedRch, verifiedRtc,
            enrollment, RouteV2TestFixture.Now, 0,
            new SodiumProductionMailboxRouteSignatureVerifier());
        Assert.Equal(rca.ActivationSequence, verifiedRca.Activation.ActivationSequence);

        var changed = rca with
        {
            CanonicalTransitionContextHash = RouteV2TestFixture.Bytes(220, 32),
            CurrentIssuerSignature = new byte[64]
        };
        changed = RouteV2TestFixture.SignActivation(changed, f.IssuerPrivateKey);
        Assert.Throws<ProductionMailboxRouteAuthorizationException>(() =>
            ProductionMailboxRouteAuthorizationVerifier.VerifyDelegatedActivation(
                ProductionMailboxRouteAuthorizationCodec.EncodeContinuityActivation(changed),
                f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, verifiedRch, verifiedRtc,
                enrollment, RouteV2TestFixture.Now, 0,
                new SodiumProductionMailboxRouteSignatureVerifier()));

        var tamperedPra = ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(f.Pra);
        tamperedPra[^1] ^= 1;
        Assert.Throws<ProductionMailboxRouteAuthorizationException>(() =>
            ProductionMailboxRouteAuthorizationVerifier.VerifyOwnerAuthorization(tamperedPra, f.Authority,
                new ProductionMailboxOwnerRouteAuthorizationVerificationContext
                {
                    ExpectedNetworkId = f.NetworkId,
                    ExpectedRouteDomainHash = f.RouteDomainHash,
                    ExpectedPredecessorKind = f.Pra.PredecessorAuthorizationKind,
                    ExpectedPredecessorHash = f.Pra.PredecessorCanonicalRouteAuthorizationHash,
                    ExpectedPredecessorSequence = f.Pra.PredecessorRouteAuthorizationSequence,
                    NowUnixSeconds = RouteV2TestFixture.Now,
                    ClockSkewSeconds = 0
                }, new SodiumProductionMailboxRouteSignatureVerifier()));
    }

    [Fact]
    public void DefensiveCopiesAndPublicSurface_DoNotExposeRawSigningOrGenericForwardVerifier()
    {
        var f = RouteV2TestFixture.Create();
        var exposed = f.VerifiedPra.CanonicalHash.ToArray();
        exposed[0] ^= 1;
        Assert.NotEqual(exposed, f.VerifiedPra.CanonicalHash.ToArray());
        Assert.DoesNotContain(typeof(ProductionMailboxRouteAuthorizationCodec).GetMethods(
            BindingFlags.Public | BindingFlags.Static), static method =>
            method.Name.Contains("SigningBytes", StringComparison.Ordinal));
        Assert.True(typeof(ProductionMailboxRouteAuthorizationVerifier).IsPublic);
        Assert.DoesNotContain(typeof(ProductionMailboxRouteAuthorizationVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static), static method =>
            method.GetParameters().Any(parameter =>
                typeof(IProductionMailboxRouteSignatureVerifier).IsAssignableFrom(parameter.ParameterType)));
        Assert.Empty(typeof(VerifiedProductionMailboxRouteAdvertisementV2).GetConstructors());
    }

    [Fact]
    public void PraRtcAndRca_RejectValidityEscapesFromParentClosures()
    {
        var f = RouteV2TestFixture.Create();
        var escapedPra = f.Pra with
        {
            PublishedAtUnixSeconds = f.Pra.Certificate.IssuedAtUnixSeconds - 1,
            OwnerSignature = new byte[64]
        };
        Assert.Throws<ProductionMailboxRouteAuthorizationException>(() =>
            RouteV2TestFixture.SignPra(escapedPra, f.OwnerPrivateKey));

        var enrollment = ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(
            ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation),
            ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(f.Acceptance),
            f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra, f.EnrollmentContext,
            new SodiumProductionMailboxRouteSignatureVerifier());
        var verifiedRch = ProductionMailboxRouteContinuityVerifier.VerifyRevocationCheckpoint(
            ProductionMailboxRouteContinuityCodec.EncodeRevocationCheckpoint(f.Checkpoint),
            f.Authority, f.RevocationSnapshot, enrollment.VerifiedDelegation,
            f.Salt, f.Commitment, 0, new byte[32], RouteV2TestFixture.Now, 0,
            new SodiumProductionMailboxRouteSignatureVerifier());
        var escapedRtc = Transition(f) with
        {
            NotBeforeUnixSeconds = f.Delegation.NotBeforeUnixSeconds - 1
        };
        var verifiedRtc = ProductionMailboxRouteAuthorizationVerifier.VerifyTransitionContext(
            ProductionMailboxRouteAuthorizationCodec.EncodeTransitionContext(escapedRtc),
            f.NetworkId, f.RouteDomainHash, escapedRtc.OldCanonicalSelectionHash.Span,
            escapedRtc.NewCanonicalSelectionHash.Span, escapedRtc.SealedOldRouteOriginLkgHash.Span,
            escapedRtc.OldRouteVerifiedAtUnixSeconds, escapedRtc.OldLocalRouteCommitGeneration);
        var rca = Activation(f, escapedRtc);
        Assert.Throws<ProductionMailboxRouteAuthorizationException>(() =>
            ProductionMailboxRouteAuthorizationVerifier.VerifyDelegatedActivation(
                ProductionMailboxRouteAuthorizationCodec.EncodeContinuityActivation(rca),
                f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, verifiedRch, verifiedRtc,
                enrollment, RouteV2TestFixture.Now, 0,
                new SodiumProductionMailboxRouteSignatureVerifier()));
    }

    private static ProductionMailboxRouteTransitionContext Transition(RouteV2TestFixture f) => new()
    {
        Mode = ProductionMailboxSelectionSuccessorMode.DirectPromotion,
        PredecessorAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
        NewAuthorizationKind = ProductionMailboxRouteAuthorizationKind.DelegatedRCA1,
        NetworkId = f.NetworkId,
        RouteDomainHash = f.RouteDomainHash,
        OldCanonicalSelectionHash = RouteV2TestFixture.Bytes(170, 32),
        NewCanonicalSelectionHash = RouteV2TestFixture.Bytes(171, 32),
        PredecessorCanonicalRouteAuthorizationHash = f.VerifiedPra.CanonicalHash,
        PredecessorRouteAuthorizationSequence = f.Pra.Sequence,
        FreshCanonicalRouteCertificateHash = f.VerifiedCertificate.CanonicalCertificateHash,
        NewRouteAuthorizationSequence = 5,
        TransitionSalt = f.Salt,
        ContinuityTransitionCommitment = f.Commitment,
        CanonicalRevocationCheckpointHash = SHA256.HashData(
            ProductionMailboxRouteContinuityCodec.EncodeRevocationCheckpoint(f.Checkpoint)),
        CurrentCanonicalAuthorityHash = f.Authority.CanonicalAuthorityHash,
        CurrentAuthorityGeneration = f.Authority.Authority.AuthorityGeneration,
        SealedOldRouteOriginLkgHash = f.Delegation.PreDelegationRouteOriginLkgHash,
        OldRouteVerifiedAtUnixSeconds = f.Delegation.RouteVerifiedAtUnixSeconds,
        OldLocalRouteCommitGeneration = 1,
        NotBeforeUnixSeconds = RouteV2TestFixture.Now,
        ExpiresAtUnixSeconds = RouteV2TestFixture.Now + 90
    };

    private static ProductionMailboxRouteContinuityActivation Activation(
        RouteV2TestFixture f, ProductionMailboxRouteTransitionContext rtc)
    {
        var pmr = f.RevocationSnapshot.Snapshot;
        var unsigned = new ProductionMailboxRouteContinuityActivation
        {
            NetworkId = f.NetworkId,
            RouteDomainHash = f.RouteDomainHash,
            CurrentAuthorityGeneration = f.Authority.Authority.AuthorityGeneration,
            CurrentCanonicalAuthorityHash = f.Authority.CanonicalAuthorityHash,
            CurrentIssuerEd25519PublicKey = f.Authority.Authority.MailboxIssuerEd25519PublicKey,
            CurrentRevocationGeneration = pmr.RevocationGeneration,
            CurrentRevocationHeadHash = pmr.RevocationHeadHash,
            CurrentRevocationSnapshotHash = f.RevocationSnapshot.CanonicalSnapshotHash,
            TransitionSalt = f.Salt,
            ContinuityTransitionCommitment = f.Commitment,
            CanonicalRevocationCheckpointHash = SHA256.HashData(
                ProductionMailboxRouteContinuityCodec.EncodeRevocationCheckpoint(f.Checkpoint)),
            FreshCanonicalRouteCertificateHash = f.VerifiedCertificate.CanonicalCertificateHash,
            CanonicalTransitionContextHash = ProductionMailboxRouteAuthorizationCodec.ComputeTransitionContextHash(rtc),
            PredecessorAuthorizationKind = rtc.PredecessorAuthorizationKind,
            PredecessorCanonicalRouteAuthorizationHash = rtc.PredecessorCanonicalRouteAuthorizationHash,
            PredecessorRouteAuthorizationSequence = rtc.PredecessorRouteAuthorizationSequence,
            ActivationSequence = rtc.NewRouteAuthorizationSequence,
            IssuedAtUnixSeconds = RouteV2TestFixture.Now,
            ExpiresAtUnixSeconds = RouteV2TestFixture.Now + 95,
            CurrentIssuerSignature = new byte[64]
        };
        return RouteV2TestFixture.SignActivation(unsigned, f.IssuerPrivateKey);
    }
}
