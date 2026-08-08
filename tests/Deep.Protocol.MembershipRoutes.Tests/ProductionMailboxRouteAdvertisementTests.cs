using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class ProductionMailboxRouteAdvertisementTests
{
    private const ulong Now = 1_800_000_000;

    [Fact]
    public void CanonicalCodecs_MatchIndependentEncodersAndGoldenDigests()
    {
        var fixture = CreateFixture();
        var certificateBytes = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(fixture.Certificate);
        var advertisementBytes = ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(fixture.Advertisement);

        Assert.Equal(ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength, certificateBytes.Length);
        Assert.Equal(ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength, advertisementBytes.Length);
        Assert.Equal(IndependentCertificate(fixture.Certificate, true), certificateBytes);
        Assert.Equal(IndependentAdvertisement(fixture.Advertisement, true), advertisementBytes);
        Assert.Equal(IndependentCertificateSigningBytes(fixture.Certificate),
            ProductionMailboxRouteAdvertisementCodec.GetCertificateSigningBytes(fixture.Certificate));
        Assert.Equal(IndependentAdvertisementSigningBytes(fixture.Advertisement),
            ProductionMailboxRouteAdvertisementCodec.GetAdvertisementSigningBytes(fixture.Advertisement));
        Assert.Equal("B940B0FB4EDB0A256F1A4A28AD6219EE3C0978C6F98A95C96036D0C511022A9F",
            Convert.ToHexString(SHA256.HashData(certificateBytes)));
        Assert.Equal("C90B8556366E35097C9F8D9DDD8BECD1D96A9E39F173EB37B5D18B48BAA49CBB",
            Convert.ToHexString(SHA256.HashData(advertisementBytes)));
        Assert.Equal(certificateBytes,
            ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
                ProductionMailboxRouteAdvertisementCodec.DecodeCertificate(certificateBytes)));
        Assert.Equal(advertisementBytes,
            ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(
                ProductionMailboxRouteAdvertisementCodec.DecodeAdvertisement(advertisementBytes)));
    }

    [Fact]
    public void Verifiers_AcceptIssuerAndOwnerAuthorization_AndAreStableAcrossHolderRotation()
    {
        var fixture = CreateFixture();
        var verifier = new SodiumProductionMailboxRouteSignatureVerifier();
        var certificate = ProductionMailboxRouteCertificateVerifier.Verify(
            ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(fixture.Certificate),
            fixture.Authority, Now, 0, verifier);
        var advertisement = ProductionMailboxRouteAdvertisementVerifier.Verify(
            ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(fixture.Advertisement),
            fixture.Authority, InitialContext(fixture.Certificate), verifier);

        Assert.Equal(fixture.Certificate.BlindedMailboxId, certificate.Certificate.BlindedMailboxId);
        Assert.Equal(fixture.Advertisement.Sequence, advertisement.NextAcceptedSequence);

        var before = ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(fixture.Advertisement);
        var holderA = PublicKeyAuth.GenerateKeyPair(Bytes(101, 32));
        var holderB = PublicKeyAuth.GenerateKeyPair(Bytes(102, 32));
        Assert.NotEqual(holderA.PublicKey, holderB.PublicKey);
        Assert.Equal(before, ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(fixture.Advertisement));
        Assert.Equal(-1, before.AsSpan().IndexOf(holderA.PublicKey));
        Assert.Equal(-1, before.AsSpan().IndexOf(holderB.PublicKey));
    }

    [Fact]
    public void RouteDomain_IsStableAcrossAuthorityRenewal_ButChangesWithOwnerOrRoute()
    {
        var fixture = CreateFixture();
        var expected = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(fixture.Certificate);
        var renewed = fixture.Certificate with
        {
            AuthorityGeneration = fixture.Certificate.AuthorityGeneration + 1,
            CanonicalAuthorityHash = Bytes(220, 32),
            IssuerEd25519PublicKey = Bytes(221, 32),
            IssuedAtUnixSeconds = fixture.Certificate.IssuedAtUnixSeconds + 100,
            ExpiresAtUnixSeconds = fixture.Certificate.ExpiresAtUnixSeconds + 100,
            IssuerSignature = Bytes(222, 64)
        };
        Assert.Equal(expected,
            ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(renewed));
        Assert.NotEqual(expected,
            ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(
                fixture.Certificate with { MailboxOwnerEd25519PublicKey = Bytes(223, 32) }));
        Assert.NotEqual(expected,
            ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(
                fixture.Certificate with { BlindedMailboxId = Bytes(224, 32) }));
    }

    [Fact]
    public void CertificateVerification_FailsOnAuthorityRouteSignatureAndTimeTampering()
    {
        var fixture = CreateFixture();
        var encoded = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(fixture.Certificate);
        foreach (var offset in new[] { 8, 24, 32, 64, 96, 128, 160, 192, 224, 232, 240 })
        {
            var changed = encoded.ToArray(); changed[offset] ^= 1;
            Assert.Throws<ProductionMailboxRouteAdvertisementException>(() =>
                ProductionMailboxRouteCertificateVerifier.Verify(
                    changed, fixture.Authority, Now, 0, new SodiumProductionMailboxRouteSignatureVerifier()));
        }
        AssertError(ProductionMailboxRouteAdvertisementError.Expired, () =>
            ProductionMailboxRouteCertificateVerifier.Verify(encoded, fixture.Authority,
                fixture.Certificate.ExpiresAtUnixSeconds + 1, 0, new SodiumProductionMailboxRouteSignatureVerifier()));
        AssertError(ProductionMailboxRouteAdvertisementError.NotYetValid, () =>
            ProductionMailboxRouteCertificateVerifier.Verify(encoded, fixture.Authority,
                fixture.Certificate.IssuedAtUnixSeconds - 1, 0, new SodiumProductionMailboxRouteSignatureVerifier()));

        var wrongSelection = fixture.Certificate with { SelectionInputCommitment = Bytes(190, 32) };
        wrongSelection = SignCertificate(wrongSelection, fixture.IssuerPrivateKey);
        AssertError(ProductionMailboxRouteAdvertisementError.InvalidRoute, () =>
            ProductionMailboxRouteCertificateVerifier.Verify(
                ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(wrongSelection),
                fixture.Authority, Now, 0, new SodiumProductionMailboxRouteSignatureVerifier()));
    }

    [Fact]
    public void AdvertisementVerification_FailsOnOwnerSignatureValidityRollbackAndConflict()
    {
        var fixture = CreateFixture();
        var encoded = ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(fixture.Advertisement);
        var verifier = new SodiumProductionMailboxRouteSignatureVerifier();
        var verified = ProductionMailboxRouteAdvertisementVerifier.Verify(
            encoded, fixture.Authority, InitialContext(fixture.Certificate), verifier);
        var accepted = new ProductionMailboxRouteAdvertisementVerificationContext
        {
            NowUnixSeconds = Now,
            ClockSkewSeconds = 0,
            ExpectedRouteDomainHash = verified.RouteDomainHash,
            LastAcceptedSequence = verified.NextAcceptedSequence,
            LastAcceptedAdvertisementHash = verified.CanonicalAdvertisementHash
        };
        _ = ProductionMailboxRouteAdvertisementVerifier.Verify(encoded, fixture.Authority, accepted, verifier);

        var conflicting = fixture.Advertisement with
        {
            PublishedAtUnixSeconds = fixture.Advertisement.PublishedAtUnixSeconds + 1,
            OwnerSignature = new byte[64]
        };
        conflicting = SignAdvertisement(conflicting, fixture.OwnerPrivateKey);
        AssertError(ProductionMailboxRouteAdvertisementError.AdvertisementConflict, () =>
            ProductionMailboxRouteAdvertisementVerifier.Verify(
                ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(conflicting),
                fixture.Authority, accepted, verifier));

        var later = fixture.Advertisement with { Sequence = fixture.Advertisement.Sequence + 1, OwnerSignature = new byte[64] };
        later = SignAdvertisement(later, fixture.OwnerPrivateKey);
        var laterVerified = ProductionMailboxRouteAdvertisementVerifier.Verify(
            ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(later), fixture.Authority, accepted, verifier);
        var laterContext = accepted with
        {
            LastAcceptedSequence = laterVerified.NextAcceptedSequence,
            LastAcceptedAdvertisementHash = laterVerified.CanonicalAdvertisementHash
        };
        AssertError(ProductionMailboxRouteAdvertisementError.AdvertisementRollback, () =>
            ProductionMailboxRouteAdvertisementVerifier.Verify(encoded, fixture.Authority, laterContext, verifier));

        var skipped = later with { Sequence = later.Sequence + 2, OwnerSignature = new byte[64] };
        skipped = SignAdvertisement(skipped, fixture.OwnerPrivateKey);
        var skippedVerified = ProductionMailboxRouteAdvertisementVerifier.Verify(
            ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(skipped),
            fixture.Authority, laterContext, verifier);
        Assert.Equal(skipped.Sequence, skippedVerified.NextAcceptedSequence);

        var signatureTamper = encoded.ToArray(); signatureTamper[^1] ^= 1;
        AssertError(ProductionMailboxRouteAdvertisementError.InvalidOwnerSignature, () =>
            ProductionMailboxRouteAdvertisementVerifier.Verify(signatureTamper, fixture.Authority,
                InitialContext(fixture.Certificate), verifier));
        AssertError(ProductionMailboxRouteAdvertisementError.Expired, () =>
            ProductionMailboxRouteAdvertisementVerifier.Verify(encoded, fixture.Authority,
                InitialContext(fixture.Certificate) with
                { NowUnixSeconds = fixture.Advertisement.ExpiresAtUnixSeconds + 1 }, verifier));
        AssertError(ProductionMailboxRouteAdvertisementError.InvalidRoute, () =>
            ProductionMailboxRouteAdvertisementVerifier.Verify(encoded, fixture.Authority,
                InitialContext(fixture.Certificate) with { ExpectedRouteDomainHash = Bytes(199, 32) }, verifier));
    }

    [Fact]
    public void StrictDecodersAndValidation_RejectMalformedArtifacts()
    {
        var fixture = CreateFixture();
        var certificate = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(fixture.Certificate);
        var advertisement = ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(fixture.Advertisement);
        foreach (var malformed in new[]
        {
            certificate[..^1], [.. certificate, (byte)0], certificate.Select((b, i) => i == 0 ? (byte)(b ^ 1) : b).ToArray(),
            certificate.Select((b, i) => i == 4 ? (byte)2 : b).ToArray(),
            certificate.Select((b, i) => i == 5 ? (byte)1 : b).ToArray()
        })
            Assert.Throws<ProductionMailboxRouteAdvertisementException>(() =>
                ProductionMailboxRouteAdvertisementCodec.DecodeCertificate(malformed));
        foreach (var malformed in new[]
        {
            advertisement[..^1], [.. advertisement, (byte)0],
            advertisement.Select((b, i) => i == 0 ? (byte)(b ^ 1) : b).ToArray(),
            advertisement.Select((b, i) => i == 4 ? (byte)2 : b).ToArray(),
            advertisement.Select((b, i) => i == 5 ? (byte)1 : b).ToArray()
        })
            Assert.Throws<ProductionMailboxRouteAdvertisementException>(() =>
                ProductionMailboxRouteAdvertisementCodec.DecodeAdvertisement(malformed));

        Assert.Throws<ProductionMailboxRouteAdvertisementException>(() =>
            ProductionMailboxRouteAdvertisementCodec.GetCertificateSigningBytes(
                fixture.Certificate with { BlindedMailboxId = new byte[32] }));
        Assert.Throws<ProductionMailboxRouteAdvertisementException>(() =>
            ProductionMailboxRouteAdvertisementCodec.GetAdvertisementSigningBytes(
                fixture.Advertisement with { Sequence = 0 }));
        Assert.Throws<ProductionMailboxRouteAdvertisementException>(() =>
            ProductionMailboxRouteAdvertisementCodec.GetAdvertisementSigningBytes(
                fixture.Advertisement with { ExpiresAtUnixSeconds = fixture.Certificate.ExpiresAtUnixSeconds + 1 }));
    }

    [Fact]
    public void PublicVerifiers_PreflightEncodedAndContextBoundsBeforeCopyOrCallback()
    {
        var fixture = CreateFixture();
        var verifier = new CountingVerifier();
        var oversized = new byte[8 * 1024 * 1024];
        var before = GC.GetAllocatedBytesForCurrentThread();

        AssertError(ProductionMailboxRouteAdvertisementError.InvalidLength, () =>
            ProductionMailboxRouteCertificateVerifier.Verify(
                oversized, fixture.Authority, Now, 0, verifier));
        AssertError(ProductionMailboxRouteAdvertisementError.InvalidLength, () =>
            ProductionMailboxRouteAdvertisementVerifier.Verify(
                oversized, fixture.Authority, InitialContext(fixture.Certificate), verifier));

        var advertisement = ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(
            fixture.Advertisement);
        AssertError(ProductionMailboxRouteAdvertisementError.InvalidField, () =>
            ProductionMailboxRouteAdvertisementVerifier.Verify(
                advertisement, fixture.Authority,
                InitialContext(fixture.Certificate) with
                {
                    ExpectedRouteDomainHash = oversized,
                    LastAcceptedAdvertisementHash = oversized
                }, verifier));

        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - before, 0, 128 * 1024);
        Assert.Equal(0, verifier.Callbacks);
    }

    [Fact]
    public void CallerOwnedBuffers_AreFrozenBeforeSignatureCallbacksAndVerifiedOutputsAreDefensive()
    {
        var fixture = CreateFixture();
        var certificateBytes = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(fixture.Certificate);
        var mutableCertificate = certificateBytes.ToArray();
        var verifiedCertificate = ProductionMailboxRouteCertificateVerifier.Verify(
            mutableCertificate, fixture.Authority, Now, 0,
            new MutatingVerifier(() => mutableCertificate[128] ^= 1));
        var exposedCertificate = verifiedCertificate.Certificate.BlindedMailboxId.ToArray();
        exposedCertificate[0] ^= 1;
        Assert.NotEqual(exposedCertificate, verifiedCertificate.Certificate.BlindedMailboxId.ToArray());

        var advertisementBytes = ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(fixture.Advertisement);
        var mutableAdvertisement = advertisementBytes.ToArray();
        var verifiedAdvertisement = ProductionMailboxRouteAdvertisementVerifier.Verify(
            mutableAdvertisement, fixture.Authority, InitialContext(fixture.Certificate),
            new MutatingVerifier(() => mutableAdvertisement[128] ^= 1));
        var exposedAdvertisement = verifiedAdvertisement.Advertisement.Certificate.BlindedMailboxId.ToArray();
        exposedAdvertisement[0] ^= 1;
        Assert.NotEqual(exposedAdvertisement,
            verifiedAdvertisement.Advertisement.Certificate.BlindedMailboxId.ToArray());
    }

    private static Fixture CreateFixture()
    {
        var issuer = PublicKeyAuth.GenerateKeyPair(Bytes(30, 32));
        var mrX = PublicKeyAuth.GenerateKeyPair(Bytes(60, 32));
        var owner = PublicKeyAuth.GenerateKeyPair(Bytes(90, 32));
        var authority = new ProductionMailboxAuthority
        {
            DevelopmentOnly = false,
            Environment = ProductionMailboxAuthorityEnvironment.Production,
            Transport = ProductionMailboxAuthorityTransport.AuthenticatedMau2,
            Ownership = ProductionMailboxAuthorityOwnership.OfficialManaged,
            EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
            NetworkId = Bytes(1, 16),
            AuthorityGeneration = 7,
            PreviousAuthorityHash = Bytes(2, 32),
            MailboxIssuerEd25519PublicKey = issuer.PublicKey,
            MrXApprovalEd25519PublicKey = mrX.PublicKey,
            Coordinator = Endpoint("https://coord.example.net/", 4),
            NodeIngress = Endpoint("https://ingress.example.net/mau2/", 6),
            CurrentEpoch = Epoch(9, 70, Now - 100, Now + 1_000, 8),
            NextEpoch = Epoch(10, 71, Now + 100, Now + 2_000, 10),
            Revocation = new ProductionMailboxAuthorityRevocation
            {
                SnapshotHash = Bytes(12, 32), HeadHash = Bytes(13, 32),
                PreviousHeadHash = Bytes(22, 32), Generation = 6,
                IssuedAtUnixSeconds = Now - 20, ExpiresAtUnixSeconds = Now + 500
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
        authority = SignAuthority(authority, mrX.PrivateKey);
        var verifiedAuthority = ProductionMailboxAuthorityVerifier.Verify(authority,
            new ProductionMailboxAuthorityVerificationContext
            {
                PinnedMrXPublicKeySha256 = SHA256.HashData(mrX.PublicKey),
                ExpectedNetworkId = authority.NetworkId,
                LastCommittedGeneration = 6,
                LastCommittedAuthorityHash = authority.PreviousAuthorityHash,
                LastCommittedRevocationGeneration = 5,
                LastCommittedRevocationHeadHash = authority.Revocation.PreviousHeadHash,
                LastCommittedRevocationSnapshotHash = Bytes(23, 32),
                NowUnixSeconds = Now,
                ClockSkewSeconds = 0
            }, new SodiumProductionMailboxAuthoritySignatureVerifier());
        var placement = new BlindedPlacementId(Bytes(121, 32));
        var certificate = new ProductionMailboxRouteCertificate
        {
            NetworkId = authority.NetworkId,
            AuthorityGeneration = authority.AuthorityGeneration,
            CanonicalAuthorityHash = verifiedAuthority.CanonicalAuthorityHash,
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
        var advertisement = new ProductionMailboxRouteAdvertisement
        {
            Certificate = certificate,
            Sequence = 4,
            PublishedAtUnixSeconds = Now - 5,
            ExpiresAtUnixSeconds = Now + 200,
            OwnerSignature = new byte[64]
        };
        advertisement = SignAdvertisement(advertisement, owner.PrivateKey);
        return new Fixture(verifiedAuthority, certificate, advertisement,
            issuer.PrivateKey, owner.PrivateKey);
    }

    private static ProductionMailboxRouteAdvertisementVerificationContext InitialContext(
        ProductionMailboxRouteCertificate certificate) => new()
    {
        NowUnixSeconds = Now,
        ClockSkewSeconds = 0,
        ExpectedRouteDomainHash = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(certificate),
        LastAcceptedSequence = 0,
        LastAcceptedAdvertisementHash = new byte[32]
    };

    private static ProductionMailboxAuthorityEpoch Epoch(ulong epoch, ulong generation,
        ulong from, ulong until, byte seed) => new()
    {
        Epoch = epoch, Generation = generation,
        MembershipCommitment = Bytes(seed, 32),
        TopologyPlacementCommitment = Bytes((byte)(seed + 1), 32),
        NotBeforeUnixSeconds = from, NotAfterUnixSeconds = until
    };

    private static ProductionMailboxAuthorityEndpoint Endpoint(string uri, byte seed) => new()
    {
        Uri = uri,
        CurrentSpkiSha256 = Bytes(seed, 32),
        NextSpkiSha256 = Bytes((byte)(seed + 1), 32)
    };

    private static ProductionMailboxAuthority SignAuthority(ProductionMailboxAuthority value, byte[] key)
    {
        var bound = value with
        {
            MrXApproval = value.MrXApproval with
            {
                AuthorityPayloadHash = ProductionMailboxAuthorityCodec.ComputePayloadHash(value)
            },
            Signature = new byte[64]
        };
        return bound with
        {
            Signature = PublicKeyAuth.SignDetached(
                ProductionMailboxAuthorityCodec.GetSigningBytes(bound), key)
        };
    }

    private static ProductionMailboxRouteCertificate SignCertificate(
        ProductionMailboxRouteCertificate value, byte[] key)
    {
        var unsigned = value with { IssuerSignature = new byte[64] };
        return unsigned with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteAdvertisementCodec.GetCertificateSigningBytes(unsigned), key)
        };
    }

    private static ProductionMailboxRouteAdvertisement SignAdvertisement(
        ProductionMailboxRouteAdvertisement value, byte[] key)
    {
        var unsigned = value with { OwnerSignature = new byte[64] };
        return unsigned with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteAdvertisementCodec.GetAdvertisementSigningBytes(unsigned), key)
        };
    }

    private static byte[] IndependentCertificateSigningBytes(ProductionMailboxRouteCertificate value) =>
        [.. "Deep/production-mailbox/route-certificate/v1"u8, .. IndependentCertificate(value, false)];

    private static byte[] IndependentAdvertisementSigningBytes(ProductionMailboxRouteAdvertisement value) =>
        [.. "Deep/production-mailbox/route-advertisement/v1"u8, .. IndependentAdvertisement(value, false)];

    private static byte[] IndependentCertificate(ProductionMailboxRouteCertificate value, bool signature)
    {
        using var stream = new MemoryStream();
        stream.Write("PRC1"u8); stream.WriteByte(1); stream.Write(new byte[3]);
        stream.Write(value.NetworkId.Span); WriteUInt64(stream, value.AuthorityGeneration);
        stream.Write(value.CanonicalAuthorityHash.Span); stream.Write(value.IssuerEd25519PublicKey.Span);
        stream.Write(value.MailboxOwnerEd25519PublicKey.Span); stream.Write(value.BlindedMailboxId.Span);
        stream.Write(value.BlindedPlacementId.Span); stream.Write(value.SelectionInputCommitment.Span);
        WriteUInt64(stream, value.IssuedAtUnixSeconds); WriteUInt64(stream, value.ExpiresAtUnixSeconds);
        if (signature) stream.Write(value.IssuerSignature.Span);
        return stream.ToArray();
    }

    private static byte[] IndependentAdvertisement(ProductionMailboxRouteAdvertisement value, bool signature)
    {
        using var stream = new MemoryStream();
        stream.Write("PRA1"u8); stream.WriteByte(1); stream.Write(new byte[3]);
        stream.Write(IndependentCertificate(value.Certificate, true));
        WriteUInt64(stream, value.Sequence); WriteUInt64(stream, value.PublishedAtUnixSeconds);
        WriteUInt64(stream, value.ExpiresAtUnixSeconds);
        if (signature) stream.Write(value.OwnerSignature.Span);
        return stream.ToArray();
    }

    private static void WriteUInt64(Stream stream, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value); stream.Write(bytes);
    }

    private static void AssertError(ProductionMailboxRouteAdvertisementError error, Action action) =>
        Assert.Equal(error,
            Assert.Throws<ProductionMailboxRouteAdvertisementException>(action).Error);

    private static byte[] Bytes(byte seed, int length) =>
        Enumerable.Range(0, length).Select(i => unchecked((byte)(seed + i))).ToArray();

    private sealed class MutatingVerifier(Action mutate) : IProductionMailboxRouteSignatureVerifier
    {
        private readonly SodiumProductionMailboxRouteSignatureVerifier _inner = new();
        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            mutate(); return _inner.Verify(publicKey, signingBytes, signature);
        }
    }

    private sealed class CountingVerifier : IProductionMailboxRouteSignatureVerifier
    {
        public int Callbacks { get; private set; }

        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            Callbacks++;
            return false;
        }
    }

    private sealed record Fixture(
        VerifiedProductionMailboxAuthority Authority,
        ProductionMailboxRouteCertificate Certificate,
        ProductionMailboxRouteAdvertisement Advertisement,
        byte[] IssuerPrivateKey,
        byte[] OwnerPrivateKey);
}
