using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class ProductionMailboxRouteContinuityTests
{
    [Fact]
    public void FixedCodecs_RoundTripExactLayouts_WithRealSignatures()
    {
        var f = RouteV2TestFixture.Create();

        AssertRoundTrip(f.Delegation, 552,
            ProductionMailboxRouteContinuityCodec.EncodeDelegation,
            ProductionMailboxRouteContinuityCodec.DecodeDelegation);
        AssertRoundTrip(f.Acceptance, 320,
            ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance,
            ProductionMailboxRouteContinuityCodec.DecodeDelegationAcceptance);
        AssertRoundTrip(f.Revocation, 224,
            ProductionMailboxRouteContinuityCodec.EncodeRevocation,
            ProductionMailboxRouteContinuityCodec.DecodeRevocation);
        AssertRoundTrip(f.Checkpoint, 320,
            ProductionMailboxRouteContinuityCodec.EncodeRevocationCheckpoint,
            ProductionMailboxRouteContinuityCodec.DecodeRevocationCheckpoint);

        var rol = new ProductionMailboxRouteOriginLkg
        {
            NetworkId = f.NetworkId,
            RouteDomainHash = f.RouteDomainHash,
            AuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            CanonicalAuthorizationHash = f.VerifiedPra.CanonicalHash,
            AuthorizationSequence = f.Pra.Sequence,
            CanonicalDelegationHash = SHA256.HashData(
                ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation)),
            CanonicalDelegationAcceptanceHash = SHA256.HashData(
                ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(f.Acceptance)),
            OwnerRevocationGeneration = 0,
            OwnerRevocationHeadHash = new byte[32],
            RouteVerifiedAtUnixSeconds = RouteV2TestFixture.Now - 20,
            LocalCommitGeneration = 2
        };
        var rolBytes = ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(rol);
        Assert.Equal(224, rolBytes.Length);
        Assert.Equal(rolBytes, ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(
            ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(rolBytes)));

        var rhc = RouteV2TestFixture.InitialHistoryCheckpoint(f, rol);
        var rhcBytes = ProductionMailboxRouteContinuityCodec.EncodeRouteHistoryCheckpoint(rhc);
        Assert.Equal(464, rhcBytes.Length);
        Assert.Equal(rhcBytes, ProductionMailboxRouteContinuityCodec.EncodeRouteHistoryCheckpoint(
            ProductionMailboxRouteContinuityCodec.DecodeRouteHistoryCheckpoint(rhcBytes)));
    }

    [Fact]
    public void Enrollment_Revocation_AndCheckpoint_EnforceSignatureCasAndTime()
    {
        var f = RouteV2TestFixture.Create();
        var enrollment = ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(
            ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation),
            ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(f.Acceptance),
            f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra, f.EnrollmentContext,
            new SodiumProductionMailboxRouteSignatureVerifier());
        Assert.Equal(f.Delegation.DelegationSequence,
            enrollment.VerifiedDelegation.Delegation.DelegationSequence);

        var badCas = f.EnrollmentContext with
        {
            LastDelegationSequence = 1,
            LastCanonicalDelegationHash = RouteV2TestFixture.Bytes(201, 32)
        };
        Assert.Throws<ProductionMailboxRouteContinuityException>(() =>
            ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(
                ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation),
                ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(f.Acceptance),
                f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra, badCas,
                new SodiumProductionMailboxRouteSignatureVerifier()));

        var tamperedDelegation = ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation);
        tamperedDelegation[^1] ^= 1;
        Assert.Throws<ProductionMailboxRouteContinuityException>(() =>
            ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(tamperedDelegation,
                ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(f.Acceptance),
                f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra, f.EnrollmentContext,
                new SodiumProductionMailboxRouteSignatureVerifier()));

        var verifiedRcr = ProductionMailboxRouteContinuityVerifier.VerifyTerminalRevocation(
            ProductionMailboxRouteContinuityCodec.EncodeRevocation(f.Revocation),
            enrollment.VerifiedDelegation, RouteV2TestFixture.Now, 0,
            new SodiumProductionMailboxRouteSignatureVerifier());
        Assert.Equal(1UL, verifiedRcr.Revocation.RevocationGeneration);

        var verifiedRch = ProductionMailboxRouteContinuityVerifier.VerifyRevocationCheckpoint(
            ProductionMailboxRouteContinuityCodec.EncodeRevocationCheckpoint(f.Checkpoint),
            f.Authority, f.RevocationSnapshot, enrollment.VerifiedDelegation,
            f.Salt, f.Commitment, 0, new byte[32], RouteV2TestFixture.Now, 0,
            new SodiumProductionMailboxRouteSignatureVerifier());
        Assert.Equal(ProductionMailboxRouteRevocationStatus.Active, verifiedRch.Checkpoint.Status);
        Assert.Throws<ProductionMailboxRouteContinuityException>(() =>
            ProductionMailboxRouteContinuityVerifier.VerifyRevocationCheckpoint(
                ProductionMailboxRouteContinuityCodec.EncodeRevocationCheckpoint(f.Checkpoint),
                f.Authority, f.RevocationSnapshot, enrollment.VerifiedDelegation,
                f.Salt, f.Commitment, 1, verifiedRcr.CanonicalHash.Span,
                RouteV2TestFixture.Now, 0, new SodiumProductionMailboxRouteSignatureVerifier()));
    }

    [Fact]
    public void CapabilityCopiesAreDefensive_AndRawSigningIsNotPublic()
    {
        var f = RouteV2TestFixture.Create();
        var enrollment = ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(
            ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation),
            ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(f.Acceptance),
            f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra, f.EnrollmentContext,
            new SodiumProductionMailboxRouteSignatureVerifier());
        var exposed = enrollment.CanonicalAcceptanceHash.ToArray();
        exposed[0] ^= 1;
        Assert.NotEqual(exposed, enrollment.CanonicalAcceptanceHash.ToArray());

        var publicMethods = typeof(ProductionMailboxRouteContinuityCodec).GetMethods(
            BindingFlags.Public | BindingFlags.Static);
        Assert.DoesNotContain(publicMethods, static method => method.Name.Contains("SigningBytes",
            StringComparison.Ordinal));
        Assert.True(typeof(ProductionMailboxRouteContinuityVerifier).IsPublic);
        Assert.DoesNotContain(typeof(ProductionMailboxRouteContinuityVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static), static method =>
            method.GetParameters().Any(parameter =>
                typeof(IProductionMailboxRouteSignatureVerifier).IsAssignableFrom(parameter.ParameterType)));
        Assert.Empty(typeof(VerifiedProductionMailboxRouteContinuityEnrollment).GetConstructors());
    }

    [Fact]
    public void Enrollment_RejectsMixAndMatchPmaPrcAndPraClosures()
    {
        var first = RouteV2TestFixture.Create();
        var second = RouteV2TestFixture.Create(17);
        var rcd = ProductionMailboxRouteContinuityCodec.EncodeDelegation(first.Delegation);
        var rda = ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(first.Acceptance);
        var verifier = new SodiumProductionMailboxRouteSignatureVerifier();

        Assert.Throws<ProductionMailboxRouteContinuityException>(() =>
            ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(rcd, rda,
                second.Authority, first.RevocationSnapshot, first.VerifiedCertificate, first.VerifiedPra,
                first.EnrollmentContext, verifier));
        Assert.Throws<ProductionMailboxRouteContinuityException>(() =>
            ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(rcd, rda,
                first.Authority, first.RevocationSnapshot, second.VerifiedCertificate, first.VerifiedPra,
                first.EnrollmentContext, verifier));
        Assert.Throws<ProductionMailboxRouteContinuityException>(() =>
            ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(rcd, rda,
                first.Authority, first.RevocationSnapshot, first.VerifiedCertificate, second.VerifiedPra,
                first.EnrollmentContext, verifier));
    }

    private static void AssertRoundTrip<T>(T value, int length,
        Func<T, byte[]> encode, Func<ReadOnlySpan<byte>, T> decode)
    {
        var bytes = encode(value);
        Assert.Equal(length, bytes.Length);
        Assert.Equal(bytes, encode(decode(bytes)));
    }
}

internal sealed record RouteV2TestFixture(
    byte[] NetworkId,
    byte[] RouteDomainHash,
    byte[] Salt,
    byte[] Commitment,
    byte[] IssuerPrivateKey,
    byte[] OwnerPrivateKey,
    VerifiedProductionMailboxAuthority Authority,
    VerifiedProductionMailboxRevocationSnapshot RevocationSnapshot,
    VerifiedProductionMailboxRouteCertificate VerifiedCertificate,
    ProductionMailboxRouteAdvertisementV2 Pra,
    VerifiedProductionMailboxRouteAdvertisementV2 VerifiedPra,
    ProductionMailboxRouteContinuityDelegation Delegation,
    ProductionMailboxRouteDelegationAcceptance Acceptance,
    ProductionMailboxRouteContinuityRevocation Revocation,
    ProductionMailboxRouteRevocationCheckpoint Checkpoint,
    ProductionMailboxRouteContinuityEnrollmentVerificationContext EnrollmentContext)
{
    internal const ulong Now = 1_800_000_000;

    internal static RouteV2TestFixture Create(byte variant = 0)
    {
        var issuer = PublicKeyAuth.GenerateKeyPair(Bytes((byte)(30 + variant), 32));
        var mrX = PublicKeyAuth.GenerateKeyPair(Bytes((byte)(60 + variant), 32));
        var owner = PublicKeyAuth.GenerateKeyPair(Bytes((byte)(90 + variant), 32));
        var authorityValue = AuthorityValue(issuer.PublicKey, mrX.PublicKey, variant);
        var unsignedPmr = new ProductionMailboxRevocationSnapshot
        {
            NetworkId = authorityValue.NetworkId,
            AuthorityGeneration = authorityValue.AuthorityGeneration,
            AuthorityBindingHash = ProductionMailboxRevocationSnapshotCodec.ComputeAuthorityBindingHash(authorityValue),
            RevocationGeneration = authorityValue.Revocation.Generation,
            RevocationHeadHash = authorityValue.Revocation.HeadHash,
            PreviousRevocationHeadHash = authorityValue.Revocation.PreviousHeadHash,
            IssuedAtUnixSeconds = authorityValue.Revocation.IssuedAtUnixSeconds,
            ExpiresAtUnixSeconds = authorityValue.Revocation.ExpiresAtUnixSeconds,
            RevokedGrantSerials = [],
            IssuerSignature = new byte[64]
        };
        var pmr = unsignedPmr with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(unsignedPmr), issuer.PrivateKey)
        };
        var pmrBytes = ProductionMailboxRevocationSnapshotCodec.Encode(pmr);
        authorityValue = authorityValue with
        {
            Revocation = authorityValue.Revocation with { SnapshotHash = SHA256.HashData(pmrBytes) }
        };
        authorityValue = SignAuthority(authorityValue, mrX.PrivateKey);
        var authority = ProductionMailboxAuthorityVerifier.Verify(authorityValue,
            new ProductionMailboxAuthorityVerificationContext
            {
                PinnedMrXPublicKeySha256 = SHA256.HashData(mrX.PublicKey),
                ExpectedNetworkId = authorityValue.NetworkId,
                LastCommittedGeneration = 6,
                LastCommittedAuthorityHash = authorityValue.PreviousAuthorityHash,
                LastCommittedRevocationGeneration = 5,
                LastCommittedRevocationHeadHash = authorityValue.Revocation.PreviousHeadHash,
                LastCommittedRevocationSnapshotHash = Bytes(23, 32),
                NowUnixSeconds = Now,
                ClockSkewSeconds = 0
            }, new SodiumProductionMailboxAuthoritySignatureVerifier());
        var verifiedPmr = ProductionMailboxRevocationSnapshotVerifier.Verify(pmrBytes, authority, Now, 0,
            new SodiumProductionMailboxRevocationSnapshotSignatureVerifier());
        var placement = new Deep.Protocol.DeepExtension.MailboxCapabilities.BlindedPlacementId(Bytes(121, 32));
        var certificate = new ProductionMailboxRouteCertificate
        {
            NetworkId = authorityValue.NetworkId,
            AuthorityGeneration = authorityValue.AuthorityGeneration,
            CanonicalAuthorityHash = authority.CanonicalAuthorityHash,
            IssuerEd25519PublicKey = issuer.PublicKey,
            MailboxOwnerEd25519PublicKey = owner.PublicKey,
            BlindedMailboxId = Bytes(111, 32),
            BlindedPlacementId = placement.Bytes,
            SelectionInputCommitment = ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(placement),
            IssuedAtUnixSeconds = Now - 10,
            ExpiresAtUnixSeconds = Now + 300,
            IssuerSignature = new byte[64]
        };
        certificate = SignCertificate(certificate, issuer.PrivateKey);
        var verifiedCertificate = ProductionMailboxRouteCertificateVerifier.Verify(
            ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(certificate), authority, Now, 0,
            new SodiumProductionMailboxRouteSignatureVerifier());
        var routeDomain = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(certificate);
        var pra = new ProductionMailboxRouteAdvertisementV2
        {
            Certificate = certificate,
            PredecessorAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            PredecessorCanonicalRouteAuthorizationHash = Bytes(140, 32),
            PredecessorRouteAuthorizationSequence = 3,
            Sequence = 4,
            PublishedAtUnixSeconds = Now - 5,
            ExpiresAtUnixSeconds = Now + 200,
            OwnerSignature = new byte[64]
        };
        pra = SignPra(pra, owner.PrivateKey);
        var verifiedPra = ProductionMailboxRouteAuthorizationVerifier.VerifyOwnerAuthorization(
            ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(pra), authority,
            new ProductionMailboxOwnerRouteAuthorizationVerificationContext
            {
                ExpectedNetworkId = authorityValue.NetworkId,
                ExpectedRouteDomainHash = routeDomain,
                ExpectedPredecessorKind = pra.PredecessorAuthorizationKind,
                ExpectedPredecessorHash = pra.PredecessorCanonicalRouteAuthorizationHash,
                ExpectedPredecessorSequence = pra.PredecessorRouteAuthorizationSequence,
                NowUnixSeconds = Now,
                ClockSkewSeconds = 0
            }, new SodiumProductionMailboxRouteSignatureVerifier());
        var delegation = new ProductionMailboxRouteContinuityDelegation
        {
            NetworkId = authorityValue.NetworkId,
            PinnedMrXPublicKeySha256 = SHA256.HashData(mrX.PublicKey),
            RouteDomainHash = routeDomain,
            MailboxOwnerEd25519PublicKey = owner.PublicKey,
            BlindedMailboxId = certificate.BlindedMailboxId,
            BlindedPlacementId = certificate.BlindedPlacementId,
            SelectionInputCommitment = certificate.SelectionInputCommitment,
            AnchorAuthorityGeneration = authorityValue.AuthorityGeneration,
            AnchorCanonicalAuthorityHash = authority.CanonicalAuthorityHash,
            AnchorCanonicalRouteCertificateHash = verifiedCertificate.CanonicalCertificateHash,
            AnchorAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            AnchorCanonicalRouteAuthorizationHash = verifiedPra.CanonicalHash,
            AnchorRouteAuthorizationSequence = pra.Sequence,
            PreDelegationRouteOriginLkgHash = Bytes(150, 32),
            RouteVerifiedAtUnixSeconds = Now - 20,
            Capability = ProductionMailboxRouteContinuityCapability.RouteContinuityOnly,
            DelegationSerial = Bytes(151, 16),
            DelegationSequence = 1,
            PreviousCanonicalDelegationHash = new byte[32],
            MaximumAuthorityGeneration = 8,
            FirstActivationSequence = 5,
            LastActivationSequence = 6,
            IssuedAtUnixSeconds = Now - 4,
            NotBeforeUnixSeconds = Now - 3,
            ExpiresAtUnixSeconds = Now + 180,
            OwnerSignature = new byte[64]
        };
        delegation = SignDelegation(delegation, owner.PrivateKey);
        var acceptance = new ProductionMailboxRouteDelegationAcceptance
        {
            NetworkId = delegation.NetworkId,
            RouteDomainHash = delegation.RouteDomainHash,
            CanonicalDelegationHash = SHA256.HashData(
                ProductionMailboxRouteContinuityCodec.EncodeDelegation(delegation)),
            AnchorAuthorityGeneration = delegation.AnchorAuthorityGeneration,
            AnchorCanonicalAuthorityHash = delegation.AnchorCanonicalAuthorityHash,
            AnchorCanonicalRouteCertificateHash = delegation.AnchorCanonicalRouteCertificateHash,
            AnchorAuthorizationKind = delegation.AnchorAuthorizationKind,
            AnchorCanonicalRouteAuthorizationHash = delegation.AnchorCanonicalRouteAuthorizationHash,
            AnchorRouteAuthorizationSequence = delegation.AnchorRouteAuthorizationSequence,
            PreDelegationRouteOriginLkgHash = delegation.PreDelegationRouteOriginLkgHash,
            RouteVerifiedAtUnixSeconds = delegation.RouteVerifiedAtUnixSeconds,
            AcceptedAtUnixSeconds = Now,
            AnchorIssuerSignature = new byte[64]
        };
        acceptance = SignAcceptance(acceptance, issuer.PrivateKey);
        var revocation = new ProductionMailboxRouteContinuityRevocation
        {
            NetworkId = delegation.NetworkId,
            RouteDomainHash = delegation.RouteDomainHash,
            TargetDelegationSerial = delegation.DelegationSerial,
            TargetCanonicalDelegationHash = acceptance.CanonicalDelegationHash,
            RevocationGeneration = 1,
            PreviousCanonicalRevocationHash = new byte[32],
            RevokedAtUnixSeconds = Now,
            Reason = ProductionMailboxRouteContinuityRevocationReason.OwnerRevoked,
            OwnerSignature = new byte[64]
        };
        revocation = SignRevocation(revocation, owner.PrivateKey);
        var salt = Bytes(160, 32);
        var commitment = ProductionMailboxRouteContinuityCodec.ComputeContinuityTransitionCommitment(
            salt, delegation.NetworkId.Span, delegation.RouteDomainHash.Span,
            acceptance.CanonicalDelegationHash.Span,
            SHA256.HashData(ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(acceptance)),
            delegation.PreDelegationRouteOriginLkgHash.Span, 0, new byte[32],
            authority.CanonicalAuthorityHash.Span, verifiedCertificate.CanonicalCertificateHash.Span,
            ProductionMailboxRouteAuthorizationKind.OwnerPRA2, verifiedPra.CanonicalHash.Span,
            pra.Sequence, pra.Sequence + 1);
        var checkpoint = new ProductionMailboxRouteRevocationCheckpoint
        {
            NetworkId = delegation.NetworkId,
            RouteDomainHash = delegation.RouteDomainHash,
            CurrentAuthorityGeneration = authorityValue.AuthorityGeneration,
            CurrentCanonicalAuthorityHash = authority.CanonicalAuthorityHash,
            CurrentIssuerEd25519PublicKey = issuer.PublicKey,
            CurrentOwnerRevocationGeneration = 0,
            CurrentOwnerRevocationHeadHash = new byte[32],
            TransitionSalt = salt,
            ContinuityTransitionCommitment = commitment,
            Status = ProductionMailboxRouteRevocationStatus.Active,
            IssuedAtUnixSeconds = Now - 1,
            ExpiresAtUnixSeconds = Now + 100,
            CurrentIssuerSignature = new byte[64]
        };
        checkpoint = SignCheckpoint(checkpoint, issuer.PrivateKey);
        var enrollmentContext = new ProductionMailboxRouteContinuityEnrollmentVerificationContext
        {
            ExpectedNetworkId = delegation.NetworkId,
            ExpectedPinnedMrXPublicKeySha256 = delegation.PinnedMrXPublicKeySha256,
            ExpectedRouteDomainHash = delegation.RouteDomainHash,
            ExpectedMailboxOwnerEd25519PublicKey = delegation.MailboxOwnerEd25519PublicKey,
            ExpectedBlindedMailboxId = delegation.BlindedMailboxId,
            ExpectedBlindedPlacementId = delegation.BlindedPlacementId,
            ExpectedSelectionInputCommitment = delegation.SelectionInputCommitment,
            ExpectedPreDelegationRouteOriginLkgHash = delegation.PreDelegationRouteOriginLkgHash,
            ExpectedRouteVerifiedAtUnixSeconds = delegation.RouteVerifiedAtUnixSeconds,
            LastDelegationSequence = 0,
            LastCanonicalDelegationHash = new byte[32],
            NowUnixSeconds = Now,
            ClockSkewSeconds = 0
        };
        return new RouteV2TestFixture(authorityValue.NetworkId.ToArray(), routeDomain, salt, commitment,
            issuer.PrivateKey, owner.PrivateKey, authority, verifiedPmr, verifiedCertificate, pra,
            verifiedPra, delegation, acceptance, revocation, checkpoint, enrollmentContext);
    }

    internal static ProductionMailboxRouteHistoryCheckpoint InitialHistoryCheckpoint(
        RouteV2TestFixture f, ProductionMailboxRouteOriginLkg rol) => new()
    {
        NetworkId = f.NetworkId,
        RouteDomainHash = f.RouteDomainHash,
        DelegationHistoryBinding = ProductionMailboxRouteContinuityCodec.ComputeDelegationHistoryBinding(
            SHA256.HashData(ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation)),
            SHA256.HashData(ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(f.Acceptance))),
        CurrentAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
        CurrentCanonicalAuthorizationHash = f.VerifiedPra.CanonicalHash,
        CurrentAuthorizationSequence = f.Pra.Sequence,
        OwnerRevocationGeneration = 0,
        OwnerRevocationHeadHash = new byte[32],
        CurrentRouteOriginLkgHash = ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(rol),
        RouteVerifiedAtUnixSeconds = rol.RouteVerifiedAtUnixSeconds,
        CurrentLocalCommitGeneration = rol.LocalCommitGeneration,
        PinnedMrXPublicKeySha256 = f.Delegation.PinnedMrXPublicKeySha256,
        CurrentAuthorityGeneration = f.Authority.Authority.AuthorityGeneration,
        CurrentCanonicalAuthorityHash = f.Authority.CanonicalAuthorityHash,
        CurrentRevocationGeneration = f.RevocationSnapshot.Snapshot.RevocationGeneration,
        CurrentRevocationHeadHash = f.RevocationSnapshot.Snapshot.RevocationHeadHash,
        CurrentRevocationSnapshotHash = f.RevocationSnapshot.CanonicalSnapshotHash,
        LastCommittedBatchSequence = 0,
        CumulativeCommittedBatchCount = 0,
        CumulativeVerifiedRouteLinkCount = 0,
        CumulativeCanonicalPayloadBytes = 0,
        HistoryTranscriptHead = new byte[32],
        LastCommittedBatchHash = new byte[32]
    };

    internal static byte[] Bytes(byte seed, int length) =>
        Enumerable.Range(0, length).Select(index => (byte)(seed + index)).ToArray();

    internal static ProductionMailboxRouteAdvertisementV2 SignPra(
        ProductionMailboxRouteAdvertisementV2 value, byte[] key)
    {
        var unsigned = value with { OwnerSignature = new byte[64] };
        return unsigned with { OwnerSignature = PublicKeyAuth.SignDetached(
            ProductionMailboxRouteAuthorizationCodec.GetAdvertisementV2SigningBytes(unsigned), key) };
    }

    internal static ProductionMailboxRouteContinuityActivation SignActivation(
        ProductionMailboxRouteContinuityActivation value, byte[] key)
    {
        var unsigned = value with { CurrentIssuerSignature = new byte[64] };
        return unsigned with { CurrentIssuerSignature = PublicKeyAuth.SignDetached(
            ProductionMailboxRouteAuthorizationCodec.GetContinuityActivationSigningBytes(unsigned), key) };
    }

    private static ProductionMailboxAuthority AuthorityValue(byte[] issuer, byte[] mrX, byte variant) => new()
    {
        DevelopmentOnly = false,
        Environment = ProductionMailboxAuthorityEnvironment.Production,
        Transport = ProductionMailboxAuthorityTransport.AuthenticatedMau2,
        Ownership = ProductionMailboxAuthorityOwnership.OfficialManaged,
        EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
        NetworkId = Bytes((byte)(1 + variant), 16), AuthorityGeneration = 7,
        PreviousAuthorityHash = Bytes((byte)(2 + variant), 32),
        MailboxIssuerEd25519PublicKey = issuer, MrXApprovalEd25519PublicKey = mrX,
        Coordinator = Endpoint("https://coord.example.net/", 4),
        NodeIngress = Endpoint("https://ingress.example.net/mau2/", 6),
        CurrentEpoch = Epoch(9, 70, Now - 100, Now + 1_000, 8),
        NextEpoch = Epoch(10, 71, Now + 100, Now + 2_000, 10),
        Revocation = new ProductionMailboxAuthorityRevocation
        {
            SnapshotHash = Bytes(12, 32), HeadHash = Bytes(13, 32), PreviousHeadHash = Bytes(22, 32),
            Generation = 6, IssuedAtUnixSeconds = Now - 20, ExpiresAtUnixSeconds = Now + 500
        },
        MrXApproval = new ProductionMailboxAuthorityApproval
        {
            AuthorityPayloadHash = Bytes(14, 32),
            AllowedAndroidSigningCertificateSha256 = [Bytes(15, 32)],
            AllowedWindowsSigningCertificateSha256 = [Bytes(16, 32)],
            AndroidReleaseBuildArtifactSha256 = [Bytes(17, 32)],
            WindowsReleaseBuildArtifactSha256 = [Bytes(18, 32)],
            RolloutNotBeforeUnixSeconds = Now - 30, RolloutNotAfterUnixSeconds = Now + 500
        },
        Signature = new byte[64]
    };

    private static ProductionMailboxAuthorityEpoch Epoch(ulong epoch, ulong generation,
        ulong from, ulong until, byte seed) => new()
    {
        Epoch = epoch, Generation = generation, MembershipCommitment = Bytes(seed, 32),
        TopologyPlacementCommitment = Bytes((byte)(seed + 1), 32),
        NotBeforeUnixSeconds = from, NotAfterUnixSeconds = until
    };

    private static ProductionMailboxAuthorityEndpoint Endpoint(string uri, byte seed) => new()
    {
        Uri = uri, CurrentSpkiSha256 = Bytes(seed, 32), NextSpkiSha256 = Bytes((byte)(seed + 1), 32)
    };

    private static ProductionMailboxAuthority SignAuthority(ProductionMailboxAuthority value, byte[] key)
    {
        var bound = value with
        {
            MrXApproval = value.MrXApproval with
            { AuthorityPayloadHash = ProductionMailboxAuthorityCodec.ComputePayloadHash(value) },
            Signature = new byte[64]
        };
        return bound with { Signature = PublicKeyAuth.SignDetached(
            ProductionMailboxAuthorityCodec.GetSigningBytes(bound), key) };
    }

    internal static ProductionMailboxRouteCertificate SignCertificate(
        ProductionMailboxRouteCertificate value, byte[] key)
    {
        var unsigned = value with { IssuerSignature = new byte[64] };
        return unsigned with { IssuerSignature = PublicKeyAuth.SignDetached(
            ProductionMailboxRouteAdvertisementCodec.GetCertificateSigningBytes(unsigned), key) };
    }

    private static ProductionMailboxRouteContinuityDelegation SignDelegation(
        ProductionMailboxRouteContinuityDelegation value, byte[] key)
    {
        var unsigned = value with { OwnerSignature = new byte[64] };
        return unsigned with { OwnerSignature = PublicKeyAuth.SignDetached(
            ProductionMailboxRouteContinuityCodec.GetDelegationSigningBytes(unsigned), key) };
    }

    private static ProductionMailboxRouteDelegationAcceptance SignAcceptance(
        ProductionMailboxRouteDelegationAcceptance value, byte[] key)
    {
        var unsigned = value with { AnchorIssuerSignature = new byte[64] };
        return unsigned with { AnchorIssuerSignature = PublicKeyAuth.SignDetached(
            ProductionMailboxRouteContinuityCodec.GetDelegationAcceptanceSigningBytes(unsigned), key) };
    }

    private static ProductionMailboxRouteContinuityRevocation SignRevocation(
        ProductionMailboxRouteContinuityRevocation value, byte[] key)
    {
        var unsigned = value with { OwnerSignature = new byte[64] };
        return unsigned with { OwnerSignature = PublicKeyAuth.SignDetached(
            ProductionMailboxRouteContinuityCodec.GetRevocationSigningBytes(unsigned), key) };
    }

    private static ProductionMailboxRouteRevocationCheckpoint SignCheckpoint(
        ProductionMailboxRouteRevocationCheckpoint value, byte[] key)
    {
        var unsigned = value with { CurrentIssuerSignature = new byte[64] };
        return unsigned with { CurrentIssuerSignature = PublicKeyAuth.SignDetached(
            ProductionMailboxRouteContinuityCodec.GetRevocationCheckpointSigningBytes(unsigned), key) };
    }
}
