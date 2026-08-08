using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class ProductionMailboxRevocationSnapshotContractTests
{
    private const ulong Now = 1_800_000_000;

    [Fact]
    public void PreApprovalWorkflowRoundTripsAndProducesFailClosedRevocationSource()
    {
        var fixture = CreateFixture([Serial(1), Serial(9)]);
        var decoded = ProductionMailboxRevocationSnapshotCodec.Decode(fixture.EncodedSnapshot);

        Assert.Equal(fixture.EncodedSnapshot, ProductionMailboxRevocationSnapshotCodec.Encode(decoded));
        var verified = VerifySnapshot(fixture);
        Assert.Equal(2, verified.RevokedGrantSerialCount);
        Assert.True(verified.IsRevokedSerial(Serial(1)));
        Assert.False(verified.IsRevokedSerial(Serial(2)));
        Assert.True(verified.IsRevoked(Query(fixture.IssuerPublicKey, Serial(9))));
        Assert.False(verified.IsRevoked(Query(fixture.IssuerPublicKey, Serial(10))));
        Assert.Equal(SHA256.HashData(fixture.EncodedSnapshot), verified.CanonicalSnapshotHash.ToArray());
    }

    [Fact]
    public void EmptySnapshotAndMaximumBoundAreCanonical()
    {
        var empty = CreateFixture([]);
        Assert.Empty(VerifySnapshot(empty).Snapshot.RevokedGrantSerials);

        var maximum = Enumerable.Range(1, ProductionMailboxRevocationSnapshotConstants.MaximumRevokedGrantSerials)
            .Select(Serial)
            .Select(static serial => (ReadOnlyMemory<byte>)serial)
            .ToArray();
        var full = CreateFixture(maximum);
        Assert.Equal(ProductionMailboxRevocationSnapshotConstants.MaximumRevokedGrantSerials, VerifySnapshot(full).RevokedGrantSerialCount);
    }

    [Fact]
    public void SerialSetMustBeExactNonzeroSortedDistinctAndBounded()
    {
        var fixture = CreateFixture([Serial(1), Serial(2)]);
        AssertError(fixture.Snapshot with { RevokedGrantSerials = [Serial(2), Serial(1)] }, ProductionMailboxRevocationSnapshotError.InvalidSerialOrder);
        AssertError(fixture.Snapshot with { RevokedGrantSerials = [Serial(1), Serial(1)] }, ProductionMailboxRevocationSnapshotError.InvalidSerialOrder);
        AssertError(fixture.Snapshot with { RevokedGrantSerials = [new byte[16]] }, ProductionMailboxRevocationSnapshotError.InvalidField);
        AssertError(fixture.Snapshot with { RevokedGrantSerials = [new byte[15]] }, ProductionMailboxRevocationSnapshotError.InvalidField);
        var tooMany = Enumerable.Range(1, ProductionMailboxRevocationSnapshotConstants.MaximumRevokedGrantSerials + 1)
            .Select(Serial).Select(static value => (ReadOnlyMemory<byte>)value).ToArray();
        AssertError(fixture.Snapshot with { RevokedGrantSerials = tooMany }, ProductionMailboxRevocationSnapshotError.InvalidLength);
    }

    [Fact]
    public void DecoderRejectsUnknownVersionReservedTrailingTruncatedAndOversizedCount()
    {
        var fixture = CreateFixture([Serial(1)]);
        var wrongMagic = fixture.EncodedSnapshot.ToArray();
        wrongMagic[0] ^= 1;
        AssertDecodeError(wrongMagic, ProductionMailboxRevocationSnapshotError.InvalidMagic);
        var wrongVersion = fixture.EncodedSnapshot.ToArray();
        wrongVersion[4]++;
        AssertDecodeError(wrongVersion, ProductionMailboxRevocationSnapshotError.UnsupportedVersion);
        var reserved = fixture.EncodedSnapshot.ToArray();
        reserved[5] = 1;
        AssertDecodeError(reserved, ProductionMailboxRevocationSnapshotError.ReservedFieldNotZero);
        var countReserved = fixture.EncodedSnapshot.ToArray();
        countReserved[154] = 1;
        AssertDecodeError(countReserved, ProductionMailboxRevocationSnapshotError.ReservedFieldNotZero);
        AssertDecodeError([.. fixture.EncodedSnapshot, 0], ProductionMailboxRevocationSnapshotError.NonCanonical);
        AssertDecodeError(fixture.EncodedSnapshot[..^1], ProductionMailboxRevocationSnapshotError.InvalidLength);
        var oversized = fixture.EncodedSnapshot.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(oversized.AsSpan(152, 2),
            ProductionMailboxRevocationSnapshotConstants.MaximumRevokedGrantSerials + 1);
        AssertDecodeError(oversized, ProductionMailboxRevocationSnapshotError.InvalidLength);
    }

    [Fact]
    public void VerifierRejectsHashSignatureAndEveryAuthorityBoundFieldMismatch()
    {
        var fixture = CreateFixture([Serial(1), Serial(9)]);
        var changedSerial = fixture.EncodedSnapshot.ToArray();
        changedSerial[156 + 15] ^= 2;
        AssertVerifyError(changedSerial, fixture.VerifiedAuthority, ProductionMailboxRevocationSnapshotError.SnapshotHashMismatch);

        var invalidSignature = CreateFixture([Serial(1)], validIssuerSignature: false);
        AssertVerifyError(invalidSignature.EncodedSnapshot, invalidSignature.VerifiedAuthority, ProductionMailboxRevocationSnapshotError.InvalidSignature);

        AssertBoundFieldError(fixture, fixture.Snapshot with { NetworkId = Bytes(80, 16) }, ProductionMailboxRevocationSnapshotError.AuthorityFieldMismatch);
        AssertBoundFieldError(fixture, fixture.Snapshot with { AuthorityGeneration = fixture.Snapshot.AuthorityGeneration + 1 }, ProductionMailboxRevocationSnapshotError.AuthorityFieldMismatch);
        AssertBoundFieldError(fixture, fixture.Snapshot with { AuthorityBindingHash = Bytes(81, 32) }, ProductionMailboxRevocationSnapshotError.AuthorityBindingMismatch);
        AssertBoundFieldError(fixture, fixture.Snapshot with { RevocationGeneration = fixture.Snapshot.RevocationGeneration + 1 }, ProductionMailboxRevocationSnapshotError.AuthorityFieldMismatch);
        AssertBoundFieldError(fixture, fixture.Snapshot with { RevocationHeadHash = Bytes(82, 32) }, ProductionMailboxRevocationSnapshotError.AuthorityFieldMismatch);
        AssertBoundFieldError(fixture, fixture.Snapshot with { PreviousRevocationHeadHash = Bytes(83, 32) }, ProductionMailboxRevocationSnapshotError.AuthorityFieldMismatch);
        AssertBoundFieldError(fixture, fixture.Snapshot with { IssuedAtUnixSeconds = fixture.Snapshot.IssuedAtUnixSeconds + 1 }, ProductionMailboxRevocationSnapshotError.AuthorityFieldMismatch);
        AssertBoundFieldError(fixture, fixture.Snapshot with { ExpiresAtUnixSeconds = fixture.Snapshot.ExpiresAtUnixSeconds + 1 }, ProductionMailboxRevocationSnapshotError.AuthorityFieldMismatch);
    }

    [Fact]
    public void Pmb1BindingPreventsReleasePolicySubstitutionAndHasNoSelfReference()
    {
        var fixture = CreateFixture([Serial(1)]);
        var originalBinding = ProductionMailboxAuthorityCodec.ComputeRevocationBindingHash(fixture.Authority);
        var finalWithDifferentCircularFields = fixture.Authority with
        {
            Revocation = fixture.Authority.Revocation with { SnapshotHash = Bytes(90, 32) },
            MrXApproval = fixture.Authority.MrXApproval with { AuthorityPayloadHash = Bytes(91, 32) },
            Signature = Bytes(92, 64)
        };
        Assert.Equal(originalBinding, ProductionMailboxAuthorityCodec.ComputeRevocationBindingHash(finalWithDifferentCircularFields));

        var substituted = SignAuthority(fixture.Authority with
        {
            Coordinator = fixture.Authority.Coordinator with { Uri = "https://other.example.net/" }
        }, fixture.MrXPrivateKey);
        var substitutedVerified = VerifyAuthority(substituted, fixture.MrXPublicKey);
        AssertVerifyError(fixture.EncodedSnapshot, substitutedVerified, ProductionMailboxRevocationSnapshotError.AuthorityBindingMismatch);
    }

    [Fact]
    public void VerifierRejectsFutureExpiredAndUnsafeClockContexts()
    {
        var fixture = CreateFixture([Serial(1)]);
        AssertVerifyError(fixture.EncodedSnapshot, fixture.VerifiedAuthority, ProductionMailboxRevocationSnapshotError.NotYetValid,
            fixture.Snapshot.IssuedAtUnixSeconds - 301);
        AssertVerifyError(fixture.EncodedSnapshot, fixture.VerifiedAuthority, ProductionMailboxRevocationSnapshotError.Expired,
            fixture.Snapshot.ExpiresAtUnixSeconds + 301);
        var exception = Assert.Throws<ProductionMailboxRevocationSnapshotException>(() =>
            ProductionMailboxRevocationSnapshotVerifier.Verify(
                fixture.EncodedSnapshot, fixture.VerifiedAuthority, Now,
                ProductionMailboxAuthorityConstants.MaximumClockSkewSeconds + 1,
                new SodiumProductionMailboxRevocationSnapshotSignatureVerifier()));
        Assert.Equal(ProductionMailboxRevocationSnapshotError.InvalidField, exception.Error);
    }

    [Fact]
    public void VerifierPreflightsEncodedLengthBeforeCopyOrSignatureCallback()
    {
        var fixture = CreateFixture([Serial(1)]);
        var oversized = new byte[8 * 1024 * 1024];
        var verifier = new CountingVerifier();

        var before = GC.GetAllocatedBytesForCurrentThread();
        var exception = Assert.Throws<ProductionMailboxRevocationSnapshotException>(() =>
            ProductionMailboxRevocationSnapshotVerifier.Verify(
                oversized, fixture.VerifiedAuthority, Now, 0, verifier));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(ProductionMailboxRevocationSnapshotError.InvalidLength, exception.Error);
        Assert.True(allocated < 128 * 1024,
            $"Revocation verifier allocated {allocated} bytes for an oversized PMR1.");
        Assert.Equal(0, verifier.CallbackCount);
    }

    [Fact]
    public void VerifierUsesOneEncodedSnapshotAcrossSignatureCallbackMutation()
    {
        var fixture = CreateFixture([Serial(1)]);
        var mutable = fixture.EncodedSnapshot.ToArray();
        var expectedHash = SHA256.HashData(mutable);

        var verified = ProductionMailboxRevocationSnapshotVerifier.Verify(
            mutable, fixture.VerifiedAuthority, Now, 0,
            new MutatingVerifier(() => mutable[40] ^= 0xff));

        Assert.Equal(expectedHash, verified.CanonicalSnapshotHash.ToArray());
        Assert.NotEqual(expectedHash, SHA256.HashData(mutable));
    }

    [Fact]
    public void VerifierRechecksStaleVerifiedAuthorityEpochAndRollout()
    {
        var rolloutExpiresFirst = CreateFixture([Serial(1)]);
        AssertVerifyError(
            rolloutExpiresFirst.EncodedSnapshot,
            rolloutExpiresFirst.VerifiedAuthority,
            ProductionMailboxRevocationSnapshotError.Expired,
            Now + 81);

        var epochExpiresFirst = CreateFixture(
            [Serial(1)],
            currentNotAfter: Now + 90,
            rolloutNotAfter: Now + 200,
            revocationExpiresAt: Now + 300);
        AssertVerifyError(
            epochExpiresFirst.EncodedSnapshot,
            epochExpiresFirst.VerifiedAuthority,
            ProductionMailboxRevocationSnapshotError.Expired,
            Now + 91);
    }

    [Fact]
    public void VerifiedHandlesDefensivelyCopyAndRejectAnotherIssuer()
    {
        var fixture = CreateFixture([Serial(1)]);
        var verified = VerifySnapshot(fixture);
        Assert.Throws<ProductionMailboxRevocationSnapshotException>(() => verified.IsRevoked(Query(Bytes(77, 32), Serial(1))));

        var sourceAuthorityNetwork = GetWritableArray(fixture.Authority.NetworkId);
        sourceAuthorityNetwork[0] ^= 0xff;
        Assert.Equal(Bytes(1, 16), fixture.VerifiedAuthority.Authority.NetworkId.ToArray());
        var exposed = fixture.VerifiedAuthority.Authority;
        GetWritableArray(exposed.NetworkId)[0] ^= 0xff;
        Assert.Equal(Bytes(1, 16), fixture.VerifiedAuthority.Authority.NetworkId.ToArray());

        var exposedSnapshot = verified.Snapshot;
        GetWritableArray(exposedSnapshot.RevokedGrantSerials[0])[15] ^= 0xff;
        Assert.True(verified.IsRevokedSerial(Serial(1)));
    }

    [Fact]
    public void MutationsNeverVerifyAgainstHashBoundAuthority()
    {
        var fixture = CreateFixture([Serial(1), Serial(9)]);
        for (var index = 0; index < fixture.EncodedSnapshot.Length; index += Math.Max(1, fixture.EncodedSnapshot.Length / 23))
        {
            var mutation = fixture.EncodedSnapshot.ToArray();
            mutation[index] ^= 0x40;
            try
            {
                _ = ProductionMailboxRevocationSnapshotVerifier.Verify(
                    mutation, fixture.VerifiedAuthority, Now, 0,
                    new SodiumProductionMailboxRevocationSnapshotSignatureVerifier());
                Assert.Fail("Mutated PMR1 unexpectedly verified.");
            }
            catch (ProductionMailboxRevocationSnapshotException)
            {
                // Strict parser, authority binding, canonical hash, time, or signature failed closed.
            }
        }
    }

    private static Fixture CreateFixture(
        IReadOnlyList<ReadOnlyMemory<byte>> serials,
        bool validIssuerSignature = true,
        ulong currentNotAfter = Now + 90,
        ulong rolloutNotAfter = Now + 80,
        ulong revocationExpiresAt = Now + 100)
    {
        var issuer = PublicKeyAuth.GenerateKeyPair(Bytes(30, 32));
        var mrX = PublicKeyAuth.GenerateKeyPair(Bytes(60, 32));
        var draftAuthority = CreateDraftAuthority(
            issuer.PublicKey, mrX.PublicKey, currentNotAfter, rolloutNotAfter, revocationExpiresAt);
        var unsigned = new ProductionMailboxRevocationSnapshot
        {
            NetworkId = draftAuthority.NetworkId.ToArray(),
            AuthorityGeneration = draftAuthority.AuthorityGeneration,
            AuthorityBindingHash = ProductionMailboxRevocationSnapshotCodec.ComputeAuthorityBindingHash(draftAuthority),
            RevocationGeneration = draftAuthority.Revocation.Generation,
            RevocationHeadHash = draftAuthority.Revocation.HeadHash.ToArray(),
            PreviousRevocationHeadHash = draftAuthority.Revocation.PreviousHeadHash.ToArray(),
            IssuedAtUnixSeconds = draftAuthority.Revocation.IssuedAtUnixSeconds,
            ExpiresAtUnixSeconds = draftAuthority.Revocation.ExpiresAtUnixSeconds,
            RevokedGrantSerials = serials,
            IssuerSignature = Bytes(99, 64)
        };
        var snapshot = unsigned with
        {
            IssuerSignature = validIssuerSignature
                ? PublicKeyAuth.SignDetached(ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(unsigned), issuer.PrivateKey)
                : Bytes(98, 64)
        };
        var encoded = ProductionMailboxRevocationSnapshotCodec.Encode(snapshot);
        var authority = SignAuthority(draftAuthority with
        {
            Revocation = draftAuthority.Revocation with { SnapshotHash = SHA256.HashData(encoded) }
        }, mrX.PrivateKey);
        return new Fixture(
            authority,
            VerifyAuthority(authority, mrX.PublicKey),
            snapshot,
            encoded,
            issuer.PublicKey,
            issuer.PrivateKey,
            mrX.PublicKey,
            mrX.PrivateKey);
    }

    private static ProductionMailboxAuthority CreateDraftAuthority(
        byte[] issuerPublicKey,
        byte[] mrXPublicKey,
        ulong currentNotAfter,
        ulong rolloutNotAfter,
        ulong revocationExpiresAt) => new()
    {
        DevelopmentOnly = false,
        Environment = ProductionMailboxAuthorityEnvironment.Production,
        Transport = ProductionMailboxAuthorityTransport.AuthenticatedMau2,
        Ownership = ProductionMailboxAuthorityOwnership.OfficialManaged,
        EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
        NetworkId = Bytes(1, 16),
        AuthorityGeneration = 7,
        PreviousAuthorityHash = Bytes(2, 32),
        MailboxIssuerEd25519PublicKey = issuerPublicKey,
        MrXApprovalEd25519PublicKey = mrXPublicKey,
        Coordinator = Endpoint("https://coord.example.net/", 4),
        NodeIngress = Endpoint("https://ingress.example.net/mau2/", 6),
        CurrentEpoch = Epoch(9, 70, Now - 60, currentNotAfter, 8),
        NextEpoch = Epoch(10, 71, Now + 30, Now + 600, 10),
        Revocation = new ProductionMailboxAuthorityRevocation
        {
            SnapshotHash = Bytes(12, 32),
            HeadHash = Bytes(13, 32),
            PreviousHeadHash = Bytes(22, 32),
            Generation = 6,
            IssuedAtUnixSeconds = Now - 20,
            ExpiresAtUnixSeconds = revocationExpiresAt
        },
        MrXApproval = new ProductionMailboxAuthorityApproval
        {
            AuthorityPayloadHash = Bytes(14, 32),
            AllowedAndroidSigningCertificateSha256 = [Bytes(15, 32)],
            AllowedWindowsSigningCertificateSha256 = [Bytes(16, 32)],
            AndroidReleaseBuildArtifactSha256 = [Bytes(17, 32)],
            WindowsReleaseBuildArtifactSha256 = [Bytes(18, 32)],
            RolloutNotBeforeUnixSeconds = Now - 30,
            RolloutNotAfterUnixSeconds = rolloutNotAfter
        },
        Signature = Bytes(20, 64)
    };

    private static ProductionMailboxAuthority SignAuthority(ProductionMailboxAuthority authority, byte[] privateKey)
    {
        var bound = authority with
        {
            MrXApproval = authority.MrXApproval with
            {
                AuthorityPayloadHash = ProductionMailboxAuthorityCodec.ComputePayloadHash(authority)
            },
            Signature = new byte[64]
        };
        return bound with { Signature = PublicKeyAuth.SignDetached(ProductionMailboxAuthorityCodec.GetSigningBytes(bound), privateKey) };
    }

    private static VerifiedProductionMailboxAuthority VerifyAuthority(ProductionMailboxAuthority authority, byte[] mrXPublicKey) =>
        ProductionMailboxAuthorityVerifier.Verify(
            authority,
            new ProductionMailboxAuthorityVerificationContext
            {
                PinnedMrXPublicKeySha256 = SHA256.HashData(mrXPublicKey),
                ExpectedNetworkId = Bytes(1, 16),
                LastCommittedGeneration = 6,
                LastCommittedAuthorityHash = Bytes(2, 32),
                LastCommittedRevocationGeneration = 5,
                LastCommittedRevocationHeadHash = Bytes(22, 32),
                LastCommittedRevocationSnapshotHash = Bytes(23, 32),
                NowUnixSeconds = Now,
                ClockSkewSeconds = 0
            },
            new SodiumProductionMailboxAuthoritySignatureVerifier());

    private static VerifiedProductionMailboxRevocationSnapshot VerifySnapshot(Fixture fixture) =>
        ProductionMailboxRevocationSnapshotVerifier.Verify(
            fixture.EncodedSnapshot,
            fixture.VerifiedAuthority,
            Now,
            0,
            new SodiumProductionMailboxRevocationSnapshotSignatureVerifier());

    private static void AssertBoundFieldError(
        Fixture fixture,
        ProductionMailboxRevocationSnapshot mutated,
        ProductionMailboxRevocationSnapshotError expected)
    {
        var signed = mutated with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(mutated), fixture.IssuerPrivateKey)
        };
        AssertVerifyError(ProductionMailboxRevocationSnapshotCodec.Encode(signed), fixture.VerifiedAuthority, expected);
    }

    private static void AssertVerifyError(
        byte[] encoded,
        VerifiedProductionMailboxAuthority authority,
        ProductionMailboxRevocationSnapshotError expected,
        ulong now = Now)
    {
        var exception = Assert.Throws<ProductionMailboxRevocationSnapshotException>(() =>
            ProductionMailboxRevocationSnapshotVerifier.Verify(
                encoded, authority, now, 0,
                new SodiumProductionMailboxRevocationSnapshotSignatureVerifier()));
        Assert.Equal(expected, exception.Error);
    }

    private static void AssertError(ProductionMailboxRevocationSnapshot snapshot, ProductionMailboxRevocationSnapshotError expected) =>
        Assert.Equal(expected, Assert.Throws<ProductionMailboxRevocationSnapshotException>(() =>
            ProductionMailboxRevocationSnapshotCodec.Encode(snapshot)).Error);

    private static void AssertDecodeError(byte[] encoded, ProductionMailboxRevocationSnapshotError expected) =>
        Assert.Equal(expected, Assert.Throws<ProductionMailboxRevocationSnapshotException>(() =>
            ProductionMailboxRevocationSnapshotCodec.Decode(encoded)).Error);

    private static MailboxCapabilityRevocationQuery Query(ReadOnlyMemory<byte> issuer, ReadOnlyMemory<byte> serial) => new()
    {
        IssuerPublicKey = issuer,
        Serial = serial,
        Domain = MailboxCapabilityDomain.Deposit,
        Generation = 70,
        Epoch = 9,
        MembershipCommitment = Bytes(8, 32)
    };

    private static ProductionMailboxAuthorityEndpoint Endpoint(string uri, byte seed) => new()
    {
        Uri = uri,
        CurrentSpkiSha256 = Bytes(seed, 32),
        NextSpkiSha256 = Bytes((byte)(seed + 1), 32)
    };

    private static ProductionMailboxAuthorityEpoch Epoch(ulong epoch, ulong generation, ulong from, ulong until, byte seed) => new()
    {
        Epoch = epoch,
        Generation = generation,
        MembershipCommitment = Bytes(seed, 32),
        TopologyPlacementCommitment = Bytes((byte)(seed + 1), 32),
        NotBeforeUnixSeconds = from,
        NotAfterUnixSeconds = until
    };

    private static byte[] Serial(int value)
    {
        var result = new byte[MailboxAuthenticatedCapabilityLimits.SerialLength];
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(12), checked((uint)value));
        return result;
    }

    private static byte[] GetWritableArray(ReadOnlyMemory<byte> value)
    {
        Assert.True(MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment));
        Assert.Equal(0, segment.Offset);
        Assert.NotNull(segment.Array);
        return segment.Array!;
    }

    private static byte[] Bytes(byte seed, int length) =>
        Enumerable.Range(0, length).Select(index => unchecked((byte)(seed + index))).ToArray();

    private sealed class CountingVerifier : IProductionMailboxRevocationSnapshotSignatureVerifier
    {
        public int CallbackCount { get; private set; }

        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            CallbackCount++;
            return false;
        }
    }

    private sealed class MutatingVerifier(Action mutate) : IProductionMailboxRevocationSnapshotSignatureVerifier
    {
        private readonly SodiumProductionMailboxRevocationSnapshotSignatureVerifier _inner = new();

        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            mutate();
            return _inner.Verify(publicKey, signingBytes, signature);
        }
    }

    private sealed record Fixture(
        ProductionMailboxAuthority Authority,
        VerifiedProductionMailboxAuthority VerifiedAuthority,
        ProductionMailboxRevocationSnapshot Snapshot,
        byte[] EncodedSnapshot,
        byte[] IssuerPublicKey,
        byte[] IssuerPrivateKey,
        byte[] MrXPublicKey,
        byte[] MrXPrivateKey);
}
