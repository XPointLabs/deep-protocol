using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class ProductionMailboxRouteHistoryAuthoringTests
{
    [Fact]
    public async Task InitialCursorConsumesCompositePostRdaState()
    {
        var fixture = RouteV2TestFixture.Create();
        var state = await ProductionMailboxRouteIssuerAuthoring.AcceptDelegationAsync(
            ProductionMailboxRouteContinuityCodec.EncodeDelegation(fixture.Delegation),
            ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(
                fixture.PreDelegationRouteOriginLkg),
            fixture.Authority, fixture.RevocationSnapshot, fixture.VerifiedCertificate,
            fixture.VerifiedPra, RouteV2TestFixture.Now, RouteV2TestFixture.Now, 0,
            (request, destination, _) =>
            {
                PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(), fixture.IssuerPrivateKey)
                    .CopyTo(destination.Span);
                return ValueTask.FromResult(64);
            }, (_, _) => ValueTask.FromResult(true));

        var cursor = ProductionMailboxRouteHistoryAuthoring.CreateInitialCursor(
            state, fixture.Authority, fixture.RevocationSnapshot);

        Assert.Equal(0UL, cursor.LastCommittedBatchSequence);
        var checkpoint = ProductionMailboxRouteContinuityCodec.DecodeRouteHistoryCheckpoint(
            cursor.CanonicalCheckpoint.Span);
        Assert.Equal(state.EnrolledRouteOriginLkgHash.ToArray(),
            checkpoint.CurrentRouteOriginLkgHash.ToArray());
        Assert.Equal(ProductionMailboxRouteContinuityCodec.ComputeDelegationHistoryBinding(
                state.Enrollment.CanonicalDelegationHash.Span,
                state.Enrollment.CanonicalAcceptanceHash.Span),
            checkpoint.DelegationHistoryBinding.ToArray());
    }

    [Fact]
    public void AuthorAndReverifyBatch_AdvanceSealedCursor_AndReplayExactly()
    {
        var (fixture, cursor) = CreateCursor();
        var next = fixture.Pra with
        {
            PredecessorAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            PredecessorCanonicalRouteAuthorizationHash = fixture.VerifiedPra.CanonicalHash,
            PredecessorRouteAuthorizationSequence = fixture.Pra.Sequence,
            Sequence = fixture.Pra.Sequence + 1,
            PublishedAtUnixSeconds = RouteV2TestFixture.Now,
            ExpiresAtUnixSeconds = RouteV2TestFixture.Now + 100,
            OwnerSignature = new byte[64]
        };
        next = RouteV2TestFixture.SignPra(next, fixture.OwnerPrivateKey);
        var link = OwnerLink(fixture, next);

        var plan = ProductionMailboxRouteHistoryAuthoring.AuthorNextBatch(cursor, [link]);

        Assert.Equal(1UL, plan.NextCursor.LastCommittedBatchSequence);
        Assert.Equal(1UL, plan.NextCursor.CumulativeVerifiedRouteLinkCount);
        Assert.Equal(SHA256.HashData(plan.CanonicalBatch.Span), plan.CanonicalBatchHash.ToArray());
        Assert.Same(plan.NextCursor, ProductionMailboxRouteHistoryAuthoring.VerifyBatch(
            plan.NextCursor, plan.CanonicalBatch.Span));
        var persistedCheckpoint = plan.NextCursor.CanonicalCheckpoint.ToArray();
        var persistedValue = ProductionMailboxRouteContinuityCodec.DecodeRouteHistoryCheckpoint(
            persistedCheckpoint);
        var restored = ProductionMailboxRouteHistoryAuthoring.RestoreCursor(
            persistedCheckpoint, cursor.Enrollment, fixture.Authority, fixture.RevocationSnapshot,
            new ProductionMailboxRouteHistoryProtectedRestoreContext
            {
                ExpectedCanonicalCheckpointHash = plan.NextCursor.CanonicalCheckpointHash,
                ExpectedLastCommittedBatchSequence = 1,
                ExpectedLastCommittedBatchHash = plan.CanonicalBatchHash,
                ExpectedCurrentRouteOriginLkgHash = persistedValue.CurrentRouteOriginLkgHash
            });
        Assert.Equal(1UL, restored.LastCommittedBatchSequence);
        Assert.Same(restored, ProductionMailboxRouteHistoryAuthoring.VerifyBatch(
            restored, plan.CanonicalBatch.Span));
        var exposed = plan.CanonicalBatch.ToArray();
        exposed[^1] ^= 1;
        Assert.NotEqual(exposed, plan.CanonicalBatch.ToArray());
        Assert.Throws<FormatException>(() => ProductionMailboxRouteHistoryAuthoring.VerifyBatch(
            restored, exposed));

        var tamperedCheckpoint = persistedCheckpoint.ToArray();
        tamperedCheckpoint[100] ^= 1;
        Assert.ThrowsAny<Exception>(() => ProductionMailboxRouteHistoryAuthoring.RestoreCursor(
            tamperedCheckpoint, cursor.Enrollment, fixture.Authority, fixture.RevocationSnapshot,
            new ProductionMailboxRouteHistoryProtectedRestoreContext
            {
                ExpectedCanonicalCheckpointHash = plan.NextCursor.CanonicalCheckpointHash,
                ExpectedLastCommittedBatchSequence = 1,
                ExpectedLastCommittedBatchHash = plan.CanonicalBatchHash,
                ExpectedCurrentRouteOriginLkgHash = persistedValue.CurrentRouteOriginLkgHash
            }));
    }

    [Fact]
    public void AuthoringRejectsGapMutationAndOversizedArtifactBeforeCommitPlan()
    {
        var (fixture, cursor) = CreateCursor();
        var valid = fixture.Pra with
        {
            PredecessorAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            PredecessorCanonicalRouteAuthorizationHash = fixture.VerifiedPra.CanonicalHash,
            PredecessorRouteAuthorizationSequence = fixture.Pra.Sequence,
            Sequence = fixture.Pra.Sequence + 1,
            PublishedAtUnixSeconds = RouteV2TestFixture.Now,
            ExpiresAtUnixSeconds = RouteV2TestFixture.Now + 100,
            OwnerSignature = new byte[64]
        };
        valid = RouteV2TestFixture.SignPra(valid, fixture.OwnerPrivateKey);
        var old = cursor.Checkpoint.TrustedCheckpoint;
        var gapCursor = new VerifiedProductionMailboxRouteHistoryCursor(
            ProductionMailboxRouteHistoryVerifier.CreateInitial(old with
            {
                CurrentAuthorizationSequence = fixture.Pra.Sequence - 1
            }), cursor.Enrollment);
        Assert.Throws<FormatException>(() => ProductionMailboxRouteHistoryAuthoring.AuthorNextBatch(
            gapCursor, [OwnerLink(fixture, valid)]));
        var changing = new CountChangingList(OwnerLink(fixture, valid));
        Assert.Throws<FormatException>(() => ProductionMailboxRouteHistoryAuthoring.AuthorNextBatch(
            cursor, changing));

        var huge = OwnerLink(fixture, valid) with
        {
            CanonicalAuthority = new byte[ProductionMailboxAuthorityConstants.MaximumArtifactBytes + 1]
        };
        Assert.Throws<FormatException>(() => ProductionMailboxRouteHistoryAuthoring.AuthorNextBatch(
            cursor, [huge]));

        var otherCertificate = RouteV2TestFixture.SignCertificate(
            fixture.VerifiedCertificate.Certificate with
            {
                IssuedAtUnixSeconds = fixture.VerifiedCertificate.Certificate.IssuedAtUnixSeconds + 1,
                IssuerSignature = new byte[64]
            }, fixture.IssuerPrivateKey);
        var mismatchedCertificate = OwnerLink(fixture, valid) with
        {
            CanonicalRouteCertificate = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
                otherCertificate)
        };
        Assert.Throws<FormatException>(() => ProductionMailboxRouteHistoryAuthoring.AuthorNextBatch(
            cursor, [mismatchedCertificate]));
    }

    [Fact]
    public void RestoredTerminalOwnerRevocationAllowsOnlyExactReplayBeforeAnyLinkCallback()
    {
        var (fixture, cursor) = CreateCursor();
        var firstAuthorization = fixture.Pra with
        {
            PredecessorAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            PredecessorCanonicalRouteAuthorizationHash = fixture.VerifiedPra.CanonicalHash,
            PredecessorRouteAuthorizationSequence = fixture.Pra.Sequence,
            Sequence = fixture.Pra.Sequence + 1,
            PublishedAtUnixSeconds = RouteV2TestFixture.Now,
            ExpiresAtUnixSeconds = RouteV2TestFixture.Now + 100,
            OwnerSignature = new byte[64]
        };
        firstAuthorization = RouteV2TestFixture.SignPra(
            firstAuthorization, fixture.OwnerPrivateKey);
        var firstPlan = ProductionMailboxRouteHistoryAuthoring.AuthorNextBatch(
            cursor, [OwnerLink(fixture, firstAuthorization)]);

        var secondAuthorization = firstAuthorization with
        {
            PredecessorCanonicalRouteAuthorizationHash = SHA256.HashData(
                ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(firstAuthorization)),
            PredecessorRouteAuthorizationSequence = firstAuthorization.Sequence,
            Sequence = firstAuthorization.Sequence + 1,
            PublishedAtUnixSeconds = RouteV2TestFixture.Now + 1,
            ExpiresAtUnixSeconds = RouteV2TestFixture.Now + 100,
            OwnerSignature = new byte[64]
        };
        secondAuthorization = RouteV2TestFixture.SignPra(
            secondAuthorization, fixture.OwnerPrivateKey);
        var secondPlan = ProductionMailboxRouteHistoryAuthoring.AuthorNextBatch(
            firstPlan.NextCursor, [OwnerLink(fixture, secondAuthorization)]);

        var nonterminal = ProductionMailboxRouteContinuityCodec.DecodeRouteHistoryCheckpoint(
            firstPlan.NextCursor.CanonicalCheckpoint.Span);
        var terminalHead = RouteV2TestFixture.Bytes(252, 32);
        var terminalRol = new ProductionMailboxRouteOriginLkg
        {
            NetworkId = nonterminal.NetworkId,
            RouteDomainHash = nonterminal.RouteDomainHash,
            AuthorizationKind = nonterminal.CurrentAuthorizationKind,
            CanonicalAuthorizationHash = nonterminal.CurrentCanonicalAuthorizationHash,
            AuthorizationSequence = nonterminal.CurrentAuthorizationSequence,
            CanonicalDelegationHash = cursor.Enrollment.CanonicalDelegationHash,
            CanonicalDelegationAcceptanceHash = cursor.Enrollment.CanonicalAcceptanceHash,
            OwnerRevocationGeneration = 1,
            OwnerRevocationHeadHash = terminalHead,
            RouteVerifiedAtUnixSeconds = nonterminal.RouteVerifiedAtUnixSeconds,
            LocalCommitGeneration = nonterminal.CurrentLocalCommitGeneration
        };
        var terminalValue = nonterminal with
        {
            OwnerRevocationGeneration = 1,
            OwnerRevocationHeadHash = terminalHead,
            CurrentRouteOriginLkgHash = ProductionMailboxRouteContinuityCodec
                .ComputeRouteOriginLkgHash(terminalRol)
        };
        var terminalBytes = ProductionMailboxRouteContinuityCodec.EncodeRouteHistoryCheckpoint(
            terminalValue);
        var restored = ProductionMailboxRouteHistoryAuthoring.RestoreCursor(
            terminalBytes, cursor.Enrollment, fixture.Authority, fixture.RevocationSnapshot,
            new ProductionMailboxRouteHistoryProtectedRestoreContext
            {
                ExpectedCanonicalCheckpointHash = ProductionMailboxRouteContinuityCodec
                    .ComputeRouteHistoryCheckpointHash(terminalValue),
                ExpectedLastCommittedBatchSequence = terminalValue.LastCommittedBatchSequence,
                ExpectedLastCommittedBatchHash = terminalValue.LastCommittedBatchHash,
                ExpectedCurrentRouteOriginLkgHash = terminalValue.CurrentRouteOriginLkgHash
            });
        var verifier = new CountingHistoryLinkVerifier();

        Assert.Same(restored.Checkpoint, ProductionMailboxRouteHistoryVerifier.Advance(
            firstPlan.CanonicalBatch.Span, restored.Checkpoint, verifier));
        Assert.Equal(0, verifier.CallbackCount);

        var sameSequenceFork = firstPlan.CanonicalBatch.ToArray();
        sameSequenceFork[^1] ^= 1;
        Assert.Throws<FormatException>(() => ProductionMailboxRouteHistoryVerifier.Advance(
            sameSequenceFork, restored.Checkpoint, verifier));
        Assert.Equal(0, verifier.CallbackCount);

        Assert.Equal(2UL, BinaryPrimitives.ReadUInt64BigEndian(
            secondPlan.CanonicalBatch.Span[8..16]));
        Assert.Throws<FormatException>(() => ProductionMailboxRouteHistoryVerifier.Advance(
            secondPlan.CanonicalBatch.Span, restored.Checkpoint, verifier));
        Assert.Equal(0, verifier.CallbackCount);
    }

    [Fact]
    public void PublicHistorySurfaceRequiresNonForgeableCursorAndReturnsSealedPlan()
    {
        Assert.Empty(typeof(VerifiedProductionMailboxRouteHistoryCursor).GetConstructors());
        Assert.Empty(typeof(ProductionMailboxRouteHistoryBatchCommitPlan).GetConstructors());
        Assert.DoesNotContain(typeof(ProductionMailboxRouteHistoryAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static), static method =>
            method.GetParameters().Any(parameter =>
                typeof(IProductionMailboxRouteHistoryLinkVerifier)
                    .IsAssignableFrom(parameter.ParameterType)));
    }

    private static (RouteV2TestFixture Fixture, VerifiedProductionMailboxRouteHistoryCursor Cursor)
        CreateCursor()
    {
        var fixture = RouteV2TestFixture.Create();
        var enrollment = ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(
            ProductionMailboxRouteContinuityCodec.EncodeDelegation(fixture.Delegation),
            ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(fixture.Acceptance),
            fixture.Authority, fixture.RevocationSnapshot, fixture.VerifiedCertificate,
            fixture.VerifiedPra, fixture.EnrollmentContext);
        var rol = new ProductionMailboxRouteOriginLkg
        {
            NetworkId = fixture.NetworkId,
            RouteDomainHash = fixture.RouteDomainHash,
            AuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            CanonicalAuthorizationHash = fixture.VerifiedPra.CanonicalHash,
            AuthorizationSequence = fixture.Pra.Sequence,
            CanonicalDelegationHash = enrollment.CanonicalDelegationHash,
            CanonicalDelegationAcceptanceHash = enrollment.CanonicalAcceptanceHash,
            OwnerRevocationGeneration = 0,
            OwnerRevocationHeadHash = new byte[32],
            RouteVerifiedAtUnixSeconds = fixture.Delegation.RouteVerifiedAtUnixSeconds,
            LocalCommitGeneration = 2
        };
        var checkpoint = RouteV2TestFixture.InitialHistoryCheckpoint(fixture, rol);
        return (fixture, new VerifiedProductionMailboxRouteHistoryCursor(
            ProductionMailboxRouteHistoryVerifier.CreateInitial(checkpoint), enrollment));
    }

    private static ProductionMailboxRouteHistoryAuthoringLink OwnerLink(
        RouteV2TestFixture fixture,
        ProductionMailboxRouteAdvertisementV2 authorization) => new()
        {
            AuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            CanonicalAuthority = ProductionMailboxAuthorityCodec.Encode(fixture.Authority.Authority),
            CanonicalRevocations = ProductionMailboxRevocationSnapshotCodec.Encode(
                fixture.RevocationSnapshot.Snapshot),
            CanonicalRouteCertificate = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
                fixture.VerifiedCertificate.Certificate),
            CanonicalRevocationCheckpoint = ReadOnlyMemory<byte>.Empty,
            CanonicalTransitionContext = ReadOnlyMemory<byte>.Empty,
            CanonicalAuthorization = ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(
                authorization)
        };

    private sealed class CountChangingList(ProductionMailboxRouteHistoryAuthoringLink item)
        : IReadOnlyList<ProductionMailboxRouteHistoryAuthoringLink>
    {
        private int _reads;
        public int Count => ++_reads == 1 ? 1 : 2;
        public ProductionMailboxRouteHistoryAuthoringLink this[int index] => index == 0
            ? item : throw new ArgumentOutOfRangeException(nameof(index));
        public IEnumerator<ProductionMailboxRouteHistoryAuthoringLink> GetEnumerator() =>
            throw new InvalidOperationException("Enumeration is forbidden.");
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class CountingHistoryLinkVerifier : IProductionMailboxRouteHistoryLinkVerifier
    {
        internal int CallbackCount { get; private set; }

        public ProductionMailboxRouteHistoryLinkVerificationState Verify(
            ProductionMailboxRouteHistoryLink link,
            IReadOnlyList<ProductionMailboxRouteHistoryArtifact> artifacts,
            ProductionMailboxRouteHistoryLinkVerificationState predecessor)
        {
            CallbackCount++;
            throw new InvalidOperationException("Terminal RHC1 must reject before link verification.");
        }
    }
}
