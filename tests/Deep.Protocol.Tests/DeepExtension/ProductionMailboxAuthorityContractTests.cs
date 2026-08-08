using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Sodium;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class ProductionMailboxAuthorityContractTests
{
    private const ulong Now = 1_800_000_000;

    [Fact]
    public void CanonicalRoundTripAndPinnedSignatureVerificationSucceed()
    {
        var fixture = CreateFixture();
        var encoded = ProductionMailboxAuthorityCodec.Encode(fixture.Authority);
        var decoded = ProductionMailboxAuthorityCodec.Decode(encoded);

        Assert.Equal(encoded, ProductionMailboxAuthorityCodec.Encode(decoded));
        var verified = ProductionMailboxAuthorityVerifier.Verify(decoded, fixture.Context, new SodiumProductionMailboxAuthoritySignatureVerifier());
        Assert.Equal((ulong)7, verified.NextCommittedGeneration);
        Assert.Equal(ProductionMailboxAuthorityCodec.ComputeCanonicalHash(decoded), verified.CanonicalAuthorityHash.ToArray());
    }

    [Fact]
    public void VerificationFreezesCallerOwnedAuthorityBeforeSignatureCallbackMutation()
    {
        var fixture = CreateFixture();
        var sourceNetwork = Writable(fixture.Authority.NetworkId);
        var expectedNetwork = sourceNetwork.ToArray();
        var verified = ProductionMailboxAuthorityVerifier.Verify(
            fixture.Authority,
            fixture.Context,
            new MutatingVerifier(() => sourceNetwork[0] ^= 0xff));

        Assert.NotEqual(expectedNetwork[0], sourceNetwork[0]);
        Assert.Equal(expectedNetwork, verified.Authority.NetworkId.ToArray());
    }

    [Fact]
    public void PayloadHashBindsEveryAuthorityPayloadField()
    {
        var fixture = CreateFixture();
        var altered = fixture.Authority with { NodeIngress = fixture.Authority.NodeIngress with { Uri = "https://ingress.example.net/mau2/v2" } };

        var exception = Assert.Throws<ProductionMailboxAuthorityException>(() => ProductionMailboxAuthorityCodec.Encode(altered));
        Assert.Equal(ProductionMailboxAuthorityError.InvalidApprovalBinding, exception.Error);
    }

    [Fact]
    public void RejectsHttpPrivateOfficialAndSubstitutedEndpointRoles()
    {
        var fixture = CreateFixture();
        AssertInvalid(fixture.Authority with { Coordinator = fixture.Authority.Coordinator with { Uri = "http://coord.example.net/" } }, ProductionMailboxAuthorityError.InvalidEndpoint);
        AssertInvalid(fixture.Authority with { Coordinator = fixture.Authority.Coordinator with { Uri = "https://127.0.0.1/" } }, ProductionMailboxAuthorityError.InvalidEndpoint);
        AssertInvalid(fixture.Authority with { Coordinator = fixture.Authority.Coordinator with { Uri = "https://[fc00::1]/" } }, ProductionMailboxAuthorityError.InvalidEndpoint);
        AssertInvalid(fixture.Authority with { NodeIngress = fixture.Authority.Coordinator }, ProductionMailboxAuthorityError.InvalidEndpoint);
    }

    [Fact]
    public void ExplicitUserManagedPrivateHttpsIsTheOnlyPrivateEndpointException()
    {
        var fixture = CreateFixture();
        var authority = fixture.Authority with
        {
            Ownership = ProductionMailboxAuthorityOwnership.UserManaged,
            EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy.UserManagedPrivateHttps,
            Coordinator = fixture.Authority.Coordinator with { Uri = "https://127.0.0.1/" },
            NodeIngress = fixture.Authority.NodeIngress with { Uri = "https://192.168.1.9/" }
        };
        var signed = ReSign(authority, fixture.PrivateKey);

        Assert.NotEmpty(ProductionMailboxAuthorityCodec.Encode(signed));
        Assert.NotEmpty(ProductionMailboxAuthorityCodec.Encode(ReSign(authority with { Coordinator = authority.Coordinator with { Uri = "https://[fc00::1]/" } }, fixture.PrivateKey)));
        AssertInvalid(signed with { Coordinator = signed.Coordinator with { Uri = "http://127.0.0.1/" } }, ProductionMailboxAuthorityError.InvalidEndpoint);
    }

    [Fact]
    public void RejectsMissingOrDuplicatePinsAndDevMarkers()
    {
        var fixture = CreateFixture();
        AssertInvalid(fixture.Authority with
        {
            Coordinator = fixture.Authority.Coordinator with { NextSpkiSha256 = fixture.Authority.Coordinator.CurrentSpkiSha256 }
        }, ProductionMailboxAuthorityError.InvalidPinSet);
        AssertInvalid(fixture.Authority with
        {
            Coordinator = fixture.Authority.Coordinator with { NextSpkiSha256 = new byte[32] }
        }, ProductionMailboxAuthorityError.InvalidField);
        AssertInvalid(fixture.Authority with
        {
            Coordinator = fixture.Authority.Coordinator with { Uri = "https://mailbox.dev.example.net/" }
        }, ProductionMailboxAuthorityError.InvalidEndpoint);
        AssertInvalid(fixture.Authority with
        {
            MailboxIssuerEd25519PublicKey = fixture.Authority.MrXApprovalEd25519PublicKey
        }, ProductionMailboxAuthorityError.InvalidField);
        AssertInvalid(fixture.Authority with
        {
            MrXApproval = fixture.Authority.MrXApproval with
            {
                AllowedAndroidSigningCertificateSha256 = [Bytes(99, 32), Bytes(1, 32)]
            }
        }, ProductionMailboxAuthorityError.NonCanonical);
    }

    [Fact]
    public void RejectsEpochRollbackMissingOverlapAndInvalidRollout()
    {
        var fixture = CreateFixture();
        AssertInvalid(fixture.Authority with
        {
            NextEpoch = fixture.Authority.NextEpoch with { Epoch = fixture.Authority.CurrentEpoch.Epoch }
        }, ProductionMailboxAuthorityError.InvalidEpochOrder);
        AssertInvalid(fixture.Authority with
        {
            NextEpoch = fixture.Authority.NextEpoch with { NotBeforeUnixSeconds = fixture.Authority.CurrentEpoch.NotAfterUnixSeconds + 1 }
        }, ProductionMailboxAuthorityError.InvalidEpochOrder);
        AssertInvalid(fixture.Authority with
        {
            MrXApproval = fixture.Authority.MrXApproval with { RolloutNotAfterUnixSeconds = fixture.Authority.MrXApproval.RolloutNotBeforeUnixSeconds }
        }, ProductionMailboxAuthorityError.InvalidValidityWindow);
    }

    [Fact]
    public void DecodeRejectsHeaderMutationAndTrailingUnknownData()
    {
        var fixture = CreateFixture();
        var encoded = ProductionMailboxAuthorityCodec.Encode(fixture.Authority);
        var wrongVersion = encoded.ToArray();
        wrongVersion[4]++;
        Assert.Equal(ProductionMailboxAuthorityError.UnsupportedVersion, Assert.Throws<ProductionMailboxAuthorityException>(() => ProductionMailboxAuthorityCodec.Decode(wrongVersion)).Error);
        var reserved = encoded.ToArray();
        reserved[5] = 1;
        Assert.Equal(ProductionMailboxAuthorityError.ReservedFieldNotZero, Assert.Throws<ProductionMailboxAuthorityException>(() => ProductionMailboxAuthorityCodec.Decode(reserved)).Error);
        Assert.Equal(ProductionMailboxAuthorityError.NonCanonical, Assert.Throws<ProductionMailboxAuthorityException>(() => ProductionMailboxAuthorityCodec.Decode([.. encoded, 0])).Error);
    }

    [Fact]
    public void VerifierRejectsWrongMrXPinSignatureAndAuthorityRollback()
    {
        var fixture = CreateFixture();
        var verifier = new SodiumProductionMailboxAuthoritySignatureVerifier();
        Assert.Equal(ProductionMailboxAuthorityError.UntrustedMrXKey, Assert.Throws<ProductionMailboxAuthorityException>(() =>
            ProductionMailboxAuthorityVerifier.Verify(fixture.Authority, fixture.Context with { PinnedMrXPublicKeySha256 = Bytes(77, 32) }, verifier)).Error);
        Assert.Equal(ProductionMailboxAuthorityError.AuthorityRollback, Assert.Throws<ProductionMailboxAuthorityException>(() =>
            ProductionMailboxAuthorityVerifier.Verify(fixture.Authority, fixture.Context with { LastCommittedGeneration = 7 }, verifier)).Error);
        Assert.Equal(ProductionMailboxAuthorityError.InvalidField, Assert.Throws<ProductionMailboxAuthorityException>(() =>
            ProductionMailboxAuthorityVerifier.Verify(fixture.Authority, fixture.Context with { ExpectedNetworkId = Bytes(76, 16) }, verifier)).Error);
        var tampered = fixture.Authority with { Signature = Bytes(99, 64) };
        Assert.Equal(ProductionMailboxAuthorityError.InvalidSignature, Assert.Throws<ProductionMailboxAuthorityException>(() =>
            ProductionMailboxAuthorityVerifier.Verify(tampered, fixture.Context, verifier)).Error);
    }

    [Fact]
    public void ForwardCheckpointAuthenticatesPinnedRootAndAllowsLargeNonterminalAdvance()
    {
        var fixture = CreateFixture();
        var context = new ProductionMailboxAuthorityCheckpointVerificationContext
        {
            PinnedMrXPublicKeySha256 = fixture.Context.PinnedMrXPublicKeySha256,
            ExpectedNetworkId = fixture.Context.ExpectedNetworkId,
            LastCommittedGeneration = 2,
            LastCommittedRevocationGeneration = fixture.Authority.Revocation.Generation,
            LastCommittedRevocationHeadHash = fixture.Authority.Revocation.HeadHash,
            LastCommittedRevocationSnapshotHash = fixture.Authority.Revocation.SnapshotHash,
            NowUnixSeconds = Now,
            ClockSkewSeconds = 0
        };
        var verifier = new SodiumProductionMailboxAuthoritySignatureVerifier();
        var encoded = ProductionMailboxAuthorityCodec.Encode(fixture.Authority);

        Assert.Equal(fixture.Authority.AuthorityGeneration,
            ProductionMailboxAuthorityVerifier.VerifyForwardCheckpoint(
                encoded, context, verifier).Authority.AuthorityGeneration);
        Assert.Equal(ProductionMailboxAuthorityError.UntrustedMrXKey,
            Assert.Throws<ProductionMailboxAuthorityException>(() =>
                ProductionMailboxAuthorityVerifier.VerifyForwardCheckpoint(encoded,
                    context with { PinnedMrXPublicKeySha256 = Bytes(90, 32) }, verifier)).Error);

        var generation65 = ReSign(fixture.Authority with
        { AuthorityGeneration = context.LastCommittedGeneration + 65 }, fixture.PrivateKey);
        Assert.Equal(context.LastCommittedGeneration + 65,
            ProductionMailboxAuthorityVerifier.VerifyForwardCheckpoint(
                ProductionMailboxAuthorityCodec.Encode(generation65), context, verifier)
                .Authority.AuthorityGeneration);
        var terminal = ReSign(fixture.Authority with
        { AuthorityGeneration = ulong.MaxValue }, fixture.PrivateKey);
        Assert.Equal(ProductionMailboxAuthorityError.AuthorityRollback,
            Assert.Throws<ProductionMailboxAuthorityException>(() =>
                ProductionMailboxAuthorityVerifier.VerifyForwardCheckpoint(
                    ProductionMailboxAuthorityCodec.Encode(terminal), context, verifier)).Error);
        var terminalRevocation = ReSign(fixture.Authority with
        {
            Revocation = fixture.Authority.Revocation with { Generation = ulong.MaxValue }
        }, fixture.PrivateKey);
        Assert.Equal(ProductionMailboxAuthorityError.AuthorityRollback,
            Assert.Throws<ProductionMailboxAuthorityException>(() =>
                ProductionMailboxAuthorityVerifier.VerifyForwardCheckpoint(
                    ProductionMailboxAuthorityCodec.Encode(terminalRevocation), context, verifier)).Error);
    }

    [Fact]
    public void VerifierRejectsTimeAndRevocationExpiry()
    {
        var fixture = CreateFixture();
        var verifier = new SodiumProductionMailboxAuthoritySignatureVerifier();
        Assert.Equal(ProductionMailboxAuthorityError.NotYetValid, Assert.Throws<ProductionMailboxAuthorityException>(() =>
            ProductionMailboxAuthorityVerifier.Verify(fixture.Authority, fixture.Context with { NowUnixSeconds = fixture.Authority.CurrentEpoch.NotBeforeUnixSeconds - 301 }, verifier)).Error);
        Assert.Equal(ProductionMailboxAuthorityError.Expired, Assert.Throws<ProductionMailboxAuthorityException>(() =>
            ProductionMailboxAuthorityVerifier.Verify(fixture.Authority, fixture.Context with { NowUnixSeconds = fixture.Authority.Revocation.ExpiresAtUnixSeconds + 301 }, verifier)).Error);
    }

    [Fact]
    public void VerifierRejectsRevocationRollbackAndForkAndBoundsSnapshotLifetime()
    {
        var fixture = CreateFixture();
        var verifier = new SodiumProductionMailboxAuthoritySignatureVerifier();
        Assert.Equal(ProductionMailboxAuthorityError.AuthorityRollback, Assert.Throws<ProductionMailboxAuthorityException>(() =>
            ProductionMailboxAuthorityVerifier.Verify(fixture.Authority, fixture.Context with { LastCommittedRevocationGeneration = 7 }, verifier)).Error);
        Assert.Equal(ProductionMailboxAuthorityError.PreviousHashMismatch, Assert.Throws<ProductionMailboxAuthorityException>(() =>
            ProductionMailboxAuthorityVerifier.Verify(fixture.Authority, fixture.Context with { LastCommittedRevocationHeadHash = Bytes(70, 32) }, verifier)).Error);
        AssertInvalid(fixture.Authority with
        {
            Revocation = fixture.Authority.Revocation with { ExpiresAtUnixSeconds = fixture.Authority.Revocation.IssuedAtUnixSeconds + ProductionMailboxAuthorityConstants.MaximumRevocationSnapshotLifetimeSeconds + 1 }
        }, ProductionMailboxAuthorityError.InvalidValidityWindow);
    }

    [Fact]
    public void VerifierRejectsFutureIssuedRevocationSnapshot()
    {
        var fixture = CreateFixture();
        var future = ReSign(fixture.Authority with
        {
            Revocation = fixture.Authority.Revocation with
            {
                IssuedAtUnixSeconds = Now + 301,
                ExpiresAtUnixSeconds = Now + 401
            }
        }, fixture.PrivateKey);

        var exception = Assert.Throws<ProductionMailboxAuthorityException>(() =>
            ProductionMailboxAuthorityVerifier.Verify(future, fixture.Context, new SodiumProductionMailboxAuthoritySignatureVerifier()));
        Assert.Equal(ProductionMailboxAuthorityError.NotYetValid, exception.Error);
    }

    [Fact]
    public void DecoderFailsClosedForSingleByteMutations()
    {
        var fixture = CreateFixture();
        var encoded = ProductionMailboxAuthorityCodec.Encode(fixture.Authority);
        for (var index = 0; index < encoded.Length; index += Math.Max(1, encoded.Length / 19))
        {
            var mutation = encoded.ToArray();
            mutation[index] ^= 0x80;
            try
            {
                var decoded = ProductionMailboxAuthorityCodec.Decode(mutation);
                Assert.False(ProductionMailboxAuthorityVerifier.Verify(decoded, fixture.Context, new SodiumProductionMailboxAuthoritySignatureVerifier()).CanonicalAuthorityHash.IsEmpty);
                Assert.Fail("A signed byte mutation unexpectedly verified.");
            }
            catch (ProductionMailboxAuthorityException)
            {
                // Expected: parse, canonicality, policy, pin, chain or signature validation failed closed.
            }
        }
    }

    private static void AssertInvalid(ProductionMailboxAuthority authority, ProductionMailboxAuthorityError expected) =>
        Assert.Equal(expected, Assert.Throws<ProductionMailboxAuthorityException>(() => ProductionMailboxAuthorityCodec.Encode(authority)).Error);

    private static Fixture CreateFixture()
    {
        var pair = PublicKeyAuth.GenerateKeyPair(Bytes(19, 32));
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
            MailboxIssuerEd25519PublicKey = Bytes(3, 32),
            MrXApprovalEd25519PublicKey = pair.PublicKey,
            Coordinator = Endpoint("https://coord.example.net/", 4),
            NodeIngress = Endpoint("https://ingress.example.net/mau2/", 6),
            CurrentEpoch = Epoch(9, 70, Now - 60, Now + 90, 8),
            NextEpoch = Epoch(10, 71, Now + 30, Now + 600, 10),
            Revocation = new ProductionMailboxAuthorityRevocation
            {
                SnapshotHash = Bytes(12, 32), HeadHash = Bytes(13, 32), PreviousHeadHash = Bytes(22, 32), Generation = 6,
                IssuedAtUnixSeconds = Now - 20, ExpiresAtUnixSeconds = Now + 100
            },
            MrXApproval = new ProductionMailboxAuthorityApproval
            {
                AuthorityPayloadHash = Bytes(14, 32),
                AllowedAndroidSigningCertificateSha256 = [Bytes(15, 32)],
                AllowedWindowsSigningCertificateSha256 = [Bytes(16, 32)],
                AndroidReleaseBuildArtifactSha256 = [Bytes(17, 32)],
                WindowsReleaseBuildArtifactSha256 = [Bytes(18, 32)],
                RolloutNotBeforeUnixSeconds = Now - 30,
                RolloutNotAfterUnixSeconds = Now + 80
            },
            Signature = Bytes(20, 64)
        };
        var signed = ReSign(authority, pair.PrivateKey);
        return new Fixture(signed, pair.PrivateKey, new ProductionMailboxAuthorityVerificationContext
        {
            PinnedMrXPublicKeySha256 = SHA256.HashData(pair.PublicKey),
            ExpectedNetworkId = Bytes(1, 16),
            LastCommittedGeneration = 6,
            LastCommittedAuthorityHash = Bytes(2, 32),
            LastCommittedRevocationGeneration = 5,
            LastCommittedRevocationHeadHash = Bytes(22, 32),
            LastCommittedRevocationSnapshotHash = Bytes(23, 32),
            NowUnixSeconds = Now,
            ClockSkewSeconds = 0
        });
    }

    private static ProductionMailboxAuthority ReSign(ProductionMailboxAuthority authority, byte[] privateKey)
    {
        var withBinding = authority with
        {
            MrXApproval = authority.MrXApproval with { AuthorityPayloadHash = ProductionMailboxAuthorityCodec.ComputePayloadHash(authority) },
            Signature = new byte[64]
        };
        return withBinding with { Signature = PublicKeyAuth.SignDetached(ProductionMailboxAuthorityCodec.GetSigningBytes(withBinding), privateKey) };
    }

    private static ProductionMailboxAuthorityEndpoint Endpoint(string uri, byte seed) => new()
    {
        Uri = uri, CurrentSpkiSha256 = Bytes(seed, 32), NextSpkiSha256 = Bytes((byte)(seed + 1), 32)
    };

    private static ProductionMailboxAuthorityEpoch Epoch(ulong epoch, ulong generation, ulong from, ulong until, byte seed) => new()
    {
        Epoch = epoch, Generation = generation, MembershipCommitment = Bytes(seed, 32), TopologyPlacementCommitment = Bytes((byte)(seed + 1), 32),
        NotBeforeUnixSeconds = from, NotAfterUnixSeconds = until
    };

    private static byte[] Bytes(byte seed, int length) => Enumerable.Range(0, length).Select(index => unchecked((byte)(seed + index))).ToArray();

    private static byte[] Writable(ReadOnlyMemory<byte> value)
    {
        Assert.True(MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment));
        Assert.Equal(0, segment.Offset);
        Assert.NotNull(segment.Array);
        return segment.Array!;
    }

    private sealed class MutatingVerifier(Action mutate) : IProductionMailboxAuthoritySignatureVerifier
    {
        private readonly SodiumProductionMailboxAuthoritySignatureVerifier _inner = new();

        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature)
        {
            mutate();
            return _inner.Verify(publicKey, signingBytes, signature);
        }
    }

    private sealed record Fixture(ProductionMailboxAuthority Authority, byte[] PrivateKey, ProductionMailboxAuthorityVerificationContext Context);
}
