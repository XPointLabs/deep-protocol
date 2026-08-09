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
        var verifiedPlan = ProductionMailboxRouteHistoryAuthoring.VerifyNextBatchForCommit(
            cursor, plan.CanonicalBatch.Span);

        Assert.Equal(1UL, plan.NextCursor.LastCommittedBatchSequence);
        Assert.Equal(1UL, plan.NextCursor.CumulativeVerifiedRouteLinkCount);
        Assert.Equal(SHA256.HashData(plan.CanonicalBatch.Span), plan.CanonicalBatchHash.ToArray());
        Assert.Equal(plan.CanonicalBatch.ToArray(), verifiedPlan.CanonicalBatch.ToArray());
        Assert.Equal(plan.PlanHash.ToArray(), verifiedPlan.PlanHash.ToArray());
        Assert.Equal(cursor.CanonicalCheckpoint.ToArray(),
            plan.ExpectedCurrentCheckpoint.ToArray());
        Assert.Equal(cursor.CanonicalCheckpointHash.ToArray(),
            plan.ExpectedCurrentCheckpointHash.ToArray());
        Assert.Equal(cursor.LastCommittedBatchSequence,
            plan.CurrentCumulativeState.LastCommittedBatchSequence);
        Assert.Equal(plan.NextCursor.LastCommittedBatchSequence,
            plan.NextCumulativeState.LastCommittedBatchSequence);
        Assert.Equal(ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            plan.FinalArtifacts.AuthorizationKind);
        Assert.Equal(ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(next),
            plan.FinalArtifacts.CanonicalOwnerAdvertisement.ToArray());
        Assert.Empty(plan.FinalArtifacts.CanonicalRevocationCheckpoint.ToArray());
        Assert.Empty(plan.FinalArtifacts.CanonicalTransitionContext.ToArray());
        Assert.Empty(plan.FinalArtifacts.CanonicalContinuityActivation.ToArray());
        Assert.Equal(plan.FinalArtifacts.CanonicalRouteCertificateHash.ToArray(),
            plan.NextDurableRouteState.CanonicalRouteCertificateHash.ToArray());
        Assert.Equal(plan.FinalArtifacts.CanonicalOwnerAdvertisementHash.ToArray(),
            plan.NextDurableRouteState.CanonicalOwnerAdvertisementHash.ToArray());
        Assert.Same(plan.NextCursor, ProductionMailboxRouteHistoryAuthoring.VerifyBatch(
            plan.NextCursor, plan.CanonicalBatch.Span));
        Assert.Throws<FormatException>(() =>
            ProductionMailboxRouteHistoryAuthoring.VerifyNextBatchForCommit(
                plan.NextCursor, plan.CanonicalBatch.Span));
        var persistedCheckpoint = plan.NextCursor.CanonicalCheckpoint.ToArray();
        var persistedValue = ProductionMailboxRouteContinuityCodec.DecodeRouteHistoryCheckpoint(
            persistedCheckpoint);
        var protectedRestore = plan.ToProtectedRestoreContext();
        Assert.Equal(plan.NextCursor.CanonicalCheckpoint.ToArray(),
            protectedRestore.CanonicalCheckpoint.ToArray());
        Assert.Equal(cursor.Enrollment.CanonicalDelegationHash.ToArray(),
            protectedRestore.EnrollmentCanonicalDelegationHash.ToArray());
        Assert.Equal(fixture.Authority.CanonicalAuthorityHash.ToArray(),
            protectedRestore.CurrentCanonicalAuthorityHash.ToArray());
        Assert.Equal(fixture.RevocationSnapshot.CanonicalSnapshotHash.ToArray(),
            protectedRestore.CurrentRevocationSnapshotHash.ToArray());
        var exposedProtected = protectedRestore.CanonicalCheckpoint.ToArray();
        exposedProtected[0] ^= 1;
        Assert.NotEqual(exposedProtected, protectedRestore.CanonicalCheckpoint.ToArray());
        var oversizedCheckpoint = new byte[8 * 1024 * 1024];
        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        Assert.Throws<FormatException>(() =>
            new ProductionMailboxRouteHistoryProtectedRestoreContext(
                oversizedCheckpoint,
                protectedRestore.CanonicalCheckpointHash,
                protectedRestore.LastCommittedBatchSequence,
                protectedRestore.LastCommittedBatchHash,
                protectedRestore.CurrentRouteOriginLkgHash,
                protectedRestore.EnrollmentCanonicalDelegationHash,
                protectedRestore.EnrollmentCanonicalAcceptanceHash,
                protectedRestore.NetworkId,
                protectedRestore.RouteDomainHash,
                protectedRestore.DelegationHistoryBinding,
                protectedRestore.PinnedMrXPublicKeySha256,
                protectedRestore.CurrentAuthorityGeneration,
                protectedRestore.CurrentCanonicalAuthorityHash,
                protectedRestore.CurrentRevocationGeneration,
                protectedRestore.CurrentRevocationHeadHash,
                protectedRestore.CurrentRevocationSnapshotHash));
        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - allocatedBefore, 0, 512 * 1024);
        var restored = ProductionMailboxRouteHistoryAuthoring.RestoreCursor(
            persistedCheckpoint, cursor.Enrollment, fixture.Authority, fixture.RevocationSnapshot,
            protectedRestore);
        Assert.Equal(1UL, restored.LastCommittedBatchSequence);
        Assert.Throws<FormatException>(() => ProductionMailboxRouteHistoryAuthoring.RestoreCursor(
            persistedCheckpoint, CreateTestHistoricalAnchor(fixture, cursor), protectedRestore));
        Assert.Same(restored, ProductionMailboxRouteHistoryAuthoring.VerifyBatch(
            restored, plan.CanonicalBatch.Span));
        var exposed = plan.CanonicalBatch.ToArray();
        exposed[^1] ^= 1;
        Assert.NotEqual(exposed, plan.CanonicalBatch.ToArray());
        var exposedPlanHash = plan.PlanHash.ToArray();
        exposedPlanHash[0] ^= 1;
        Assert.NotEqual(exposedPlanHash, plan.PlanHash.ToArray());
        Assert.Throws<FormatException>(() => ProductionMailboxRouteHistoryAuthoring.VerifyBatch(
            restored, exposed));

        var tamperedCheckpoint = persistedCheckpoint.ToArray();
        tamperedCheckpoint[100] ^= 1;
        Assert.ThrowsAny<Exception>(() => ProductionMailboxRouteHistoryAuthoring.RestoreCursor(
            tamperedCheckpoint, cursor.Enrollment, fixture.Authority, fixture.RevocationSnapshot,
            plan.NextCursor.ToProtectedRestoreContext()));
    }

    [Fact]
    public void VerifyNextBatchForCommitReturnsExactDelegatedFinalTuple()
    {
        var (fixture, cursor) = CreateCursor();
        var current = cursor.Checkpoint.TrustedCheckpoint;
        var salt = RouteV2TestFixture.Bytes(211, 32);
        var newSequence = checked(current.CurrentAuthorizationSequence + 1);
        var commitment = ProductionMailboxRouteContinuityCodec
            .ComputeContinuityTransitionCommitment(
                salt, fixture.NetworkId, fixture.RouteDomainHash,
                cursor.Enrollment.CanonicalDelegationHash.Span,
                cursor.Enrollment.CanonicalAcceptanceHash.Span,
                current.CurrentRouteOriginLkgHash.Span,
                current.OwnerRevocationGeneration,
                current.OwnerRevocationHeadHash.Span,
                fixture.Authority.CanonicalAuthorityHash.Span,
                fixture.VerifiedCertificate.CanonicalCertificateHash.Span,
                current.CurrentAuthorizationKind,
                current.CurrentCanonicalAuthorizationHash.Span,
                current.CurrentAuthorizationSequence, newSequence);
        var checkpoint = fixture.Checkpoint with
        {
            TransitionSalt = salt,
            ContinuityTransitionCommitment = commitment,
            CurrentIssuerSignature = new byte[64]
        };
        checkpoint = SignCheckpoint(checkpoint, fixture.IssuerPrivateKey);
        var checkpointBytes = ProductionMailboxRouteContinuityCodec
            .EncodeRevocationCheckpoint(checkpoint);
        var transition = new ProductionMailboxRouteTransitionContext
        {
            Mode = ProductionMailboxSelectionSuccessorMode.DirectPromotion,
            PredecessorAuthorizationKind = current.CurrentAuthorizationKind,
            NewAuthorizationKind = ProductionMailboxRouteAuthorizationKind.DelegatedRCA1,
            NetworkId = fixture.NetworkId,
            RouteDomainHash = fixture.RouteDomainHash,
            OldCanonicalSelectionHash = RouteV2TestFixture.Bytes(212, 32),
            NewCanonicalSelectionHash = RouteV2TestFixture.Bytes(213, 32),
            PredecessorCanonicalRouteAuthorizationHash =
                current.CurrentCanonicalAuthorizationHash,
            PredecessorRouteAuthorizationSequence = current.CurrentAuthorizationSequence,
            FreshCanonicalRouteCertificateHash =
                fixture.VerifiedCertificate.CanonicalCertificateHash,
            NewRouteAuthorizationSequence = newSequence,
            TransitionSalt = salt,
            ContinuityTransitionCommitment = commitment,
            CanonicalRevocationCheckpointHash = SHA256.HashData(checkpointBytes),
            CurrentCanonicalAuthorityHash = fixture.Authority.CanonicalAuthorityHash,
            CurrentAuthorityGeneration = fixture.Authority.Authority.AuthorityGeneration,
            SealedOldRouteOriginLkgHash = current.CurrentRouteOriginLkgHash,
            OldRouteVerifiedAtUnixSeconds = current.RouteVerifiedAtUnixSeconds,
            OldLocalRouteCommitGeneration = current.CurrentLocalCommitGeneration,
            NotBeforeUnixSeconds = RouteV2TestFixture.Now,
            ExpiresAtUnixSeconds = RouteV2TestFixture.Now + 90
        };
        var transitionBytes = ProductionMailboxRouteAuthorizationCodec
            .EncodeTransitionContext(transition);
        var activation = SignActivation(fixture, transition, checkpointBytes);
        var activationBytes = ProductionMailboxRouteAuthorizationCodec
            .EncodeContinuityActivation(activation);
        var link = new ProductionMailboxRouteHistoryAuthoringLink
        {
            AuthorizationKind = ProductionMailboxRouteAuthorizationKind.DelegatedRCA1,
            CanonicalAuthority = ProductionMailboxAuthorityCodec.Encode(
                fixture.Authority.Authority),
            CanonicalRevocations = ProductionMailboxRevocationSnapshotCodec.Encode(
                fixture.RevocationSnapshot.Snapshot),
            CanonicalRouteCertificate = ProductionMailboxRouteAdvertisementCodec
                .EncodeCertificate(fixture.VerifiedCertificate.Certificate),
            CanonicalRevocationCheckpoint = checkpointBytes,
            CanonicalTransitionContext = transitionBytes,
            CanonicalAuthorization = activationBytes
        };

        var authored = ProductionMailboxRouteHistoryAuthoring.AuthorNextBatch(cursor, [link]);
        var plan = ProductionMailboxRouteHistoryAuthoring.VerifyNextBatchForCommit(
            cursor, authored.CanonicalBatch.Span);

        Assert.Equal(ProductionMailboxRouteAuthorizationKind.DelegatedRCA1,
            plan.FinalArtifacts.AuthorizationKind);
        Assert.Empty(plan.FinalArtifacts.CanonicalOwnerAdvertisement.ToArray());
        Assert.Equal(checkpointBytes,
            plan.FinalArtifacts.CanonicalRevocationCheckpoint.ToArray());
        Assert.Equal(transitionBytes,
            plan.FinalArtifacts.CanonicalTransitionContext.ToArray());
        Assert.Equal(activationBytes,
            plan.FinalArtifacts.CanonicalContinuityActivation.ToArray());
        Assert.Equal(SHA256.HashData(checkpointBytes),
            plan.NextDurableRouteState.CanonicalRevocationCheckpointHash.ToArray());
        Assert.Equal(ProductionMailboxRouteAuthorizationCodec
                .ComputeTransitionContextHash(transition),
            plan.NextDurableRouteState.CanonicalTransitionContextHash.ToArray());
        Assert.Equal(SHA256.HashData(activationBytes),
            plan.NextDurableRouteState.CanonicalContinuityActivationHash.ToArray());
        Assert.Equal(authored.PlanHash.ToArray(), plan.PlanHash.ToArray());
    }

    [Fact]
    public void NextCommitPreflightRejectsOuterValidLateMaximumArtifactWithoutCopyOrCallback()
    {
        var (_, cursor) = CreateCursor();
        var encoded = new byte[ProductionMailboxRouteHistoryConstants.HeaderLength +
            ProductionMailboxRouteHistoryConstants.ArtifactItemLength +
            ProductionMailboxRouteHistoryConstants.LinkItemLength +
            ProductionMailboxRouteHistoryConstants.MaximumPayloadBytes];
        "RHB1"u8.CopyTo(encoded);
        encoded[4] = ProductionMailboxRouteHistoryConstants.Version;
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(8, 8), 1);
        cursor.CanonicalCheckpointHash.Span.CopyTo(encoded.AsSpan(16, 32));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(48, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(50, 2), 1);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(52, 4),
            ProductionMailboxRouteHistoryConstants.ArtifactItemLength +
            ProductionMailboxRouteHistoryConstants.LinkItemLength);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(56, 4),
            ProductionMailboxRouteHistoryConstants.MaximumPayloadBytes);
        var artifact = encoded.AsSpan(ProductionMailboxRouteHistoryConstants.HeaderLength,
            ProductionMailboxRouteHistoryConstants.ArtifactItemLength);
        artifact[0] = (byte)ProductionMailboxRouteHistoryArtifactKind.Authority;
        BinaryPrimitives.WriteUInt32BigEndian(artifact[4..8],
            ProductionMailboxRouteHistoryConstants.MaximumPayloadBytes);
        var verifier = new CountingHistoryLinkVerifier();
        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();

        Assert.Throws<FormatException>(() =>
            ProductionMailboxRouteHistoryVerifier.AdvanceNextForCommit(
                encoded, cursor.Checkpoint, verifier));

        Assert.Equal(0, verifier.CallbackCount);
        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - allocatedBefore,
            0, 512 * 1024);
    }

    [Fact]
    public void NextCommitPreflightRejectsLateNonAdjacentHashAliasWithoutCopyOrCallback()
    {
        var (fixture, cursor) = CreateCursor();
        var encoded = BuildLateNonAdjacentAliasBatch(fixture, cursor);
        Assert.True(encoded.Length >
            ProductionMailboxRouteHistoryConstants.MaximumEncodedBytes - 128 * 1024);
        var verifier = new CountingHistoryLinkVerifier();
        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();

        Assert.Throws<FormatException>(() =>
            ProductionMailboxRouteHistoryVerifier.AdvanceNextForCommit(
                encoded, cursor.Checkpoint, verifier));

        Assert.Equal(0, verifier.CallbackCount);
        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - allocatedBefore,
            0, 512 * 1024);
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
        var firstColdReplayPlan = ProductionMailboxRouteHistoryAuthoring
            .VerifyNextBatchForCommit(cursor, firstPlan.CanonicalBatch.Span);

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
        var secondColdReplayPlan = ProductionMailboxRouteHistoryAuthoring
            .VerifyNextBatchForCommit(firstColdReplayPlan.NextCursor,
                secondPlan.CanonicalBatch.Span);
        Assert.Equal(secondPlan.PlanHash.ToArray(), secondColdReplayPlan.PlanHash.ToArray());
        Assert.Equal(secondPlan.NextCursor.CanonicalCheckpoint.ToArray(),
            secondColdReplayPlan.NextCursor.CanonicalCheckpoint.ToArray());

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
            new ProductionMailboxRouteHistoryProtectedRestoreContext(
                terminalBytes,
                ProductionMailboxRouteContinuityCodec.ComputeRouteHistoryCheckpointHash(terminalValue),
                terminalValue.LastCommittedBatchSequence,
                terminalValue.LastCommittedBatchHash,
                terminalValue.CurrentRouteOriginLkgHash,
                cursor.Enrollment.CanonicalDelegationHash,
                cursor.Enrollment.CanonicalAcceptanceHash,
                terminalValue.NetworkId,
                terminalValue.RouteDomainHash,
                terminalValue.DelegationHistoryBinding,
                terminalValue.PinnedMrXPublicKeySha256,
                terminalValue.CurrentAuthorityGeneration,
                terminalValue.CurrentCanonicalAuthorityHash,
                terminalValue.CurrentRevocationGeneration,
                terminalValue.CurrentRevocationHeadHash,
                terminalValue.CurrentRevocationSnapshotHash));
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
    public void NextCommitRejectsGapInvalidLinkTagAndMalformedPmrBeforeAnyCallback()
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
        var plan = ProductionMailboxRouteHistoryAuthoring.AuthorNextBatch(
            cursor, [OwnerLink(fixture, next)]);
        var verifier = new CountingHistoryLinkVerifier();

        var gap = plan.CanonicalBatch.ToArray();
        BinaryPrimitives.WriteUInt64BigEndian(gap.AsSpan(8, 8), 2);
        Assert.Throws<FormatException>(() =>
            ProductionMailboxRouteHistoryVerifier.AdvanceNextForCommit(
                gap, cursor.Checkpoint, verifier));

        var invalidTag = plan.CanonicalBatch.ToArray();
        var artifactCount = BinaryPrimitives.ReadUInt16BigEndian(
            invalidTag.AsSpan(50, 2));
        var linkOffset = ProductionMailboxRouteHistoryConstants.HeaderLength +
            artifactCount * ProductionMailboxRouteHistoryConstants.ArtifactItemLength;
        invalidTag[linkOffset] = byte.MaxValue;
        Assert.Throws<FormatException>(() =>
            ProductionMailboxRouteHistoryVerifier.AdvanceNextForCommit(
                invalidTag, cursor.Checkpoint, verifier));

        var malformedPmr = plan.CanonicalBatch.ToArray();
        var tableBytes = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
            malformedPmr.AsSpan(52, 4)));
        var payloadOffset = ProductionMailboxRouteHistoryConstants.HeaderLength + tableBytes;
        for (var index = 0; index < artifactCount; index++)
        {
            var rowOffset = ProductionMailboxRouteHistoryConstants.HeaderLength +
                index * ProductionMailboxRouteHistoryConstants.ArtifactItemLength;
            var artifactLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                malformedPmr.AsSpan(rowOffset + 4, 4)));
            if (malformedPmr[rowOffset] ==
                (byte)ProductionMailboxRouteHistoryArtifactKind.Revocations)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(
                    malformedPmr.AsSpan(payloadOffset + 152, 2), ushort.MaxValue);
                SHA256.HashData(malformedPmr.AsSpan(payloadOffset, artifactLength))
                    .CopyTo(malformedPmr.AsSpan(rowOffset + 8, 32));
                break;
            }
            payloadOffset += artifactLength;
        }
        Assert.ThrowsAny<Exception>(() =>
            ProductionMailboxRouteHistoryVerifier.AdvanceNextForCommit(
                malformedPmr, cursor.Checkpoint, verifier));

        var firstPredecessorMismatch = BuildLinkChainBatch(
            plan.CanonicalBatch.Span, currentAuthorizationSequence: fixture.Pra.Sequence,
            linkCount: 1, mismatchIndex: 0);
        Assert.Throws<FormatException>(() =>
            ProductionMailboxRouteHistoryVerifier.AdvanceNextForCommit(
                firstPredecessorMismatch, cursor.Checkpoint, verifier));

        var lateMaximumLinkMismatch = BuildLinkChainBatch(
            plan.CanonicalBatch.Span, currentAuthorizationSequence: fixture.Pra.Sequence,
            linkCount: ProductionMailboxRouteHistoryConstants.MaximumLinks,
            mismatchIndex: ProductionMailboxRouteHistoryConstants.MaximumLinks - 1);
        Assert.Throws<FormatException>(() =>
            ProductionMailboxRouteHistoryVerifier.AdvanceNextForCommit(
                lateMaximumLinkMismatch, cursor.Checkpoint, verifier));

        var mutatedBetweenPreflightAndSnapshot = plan.CanonicalBatch.ToArray();
        Assert.Throws<FormatException>(() =>
            ProductionMailboxRouteHistoryVerifier.AdvanceNextForCommit(
                mutatedBetweenPreflightAndSnapshot, cursor.Checkpoint, verifier, () =>
                    BinaryPrimitives.WriteUInt64BigEndian(
                        mutatedBetweenPreflightAndSnapshot.AsSpan(8, 8), 2)));
        Assert.Equal(0, verifier.CallbackCount);
    }

    [Fact]
    public void PublicHistorySurfaceRequiresNonForgeableCursorAndReturnsSealedPlan()
    {
        Assert.Empty(typeof(VerifiedProductionMailboxRouteHistoryCursor).GetConstructors());
        Assert.Empty(typeof(ProductionMailboxRouteHistoryBatchCommitPlan).GetConstructors());
        Assert.Empty(typeof(ProductionMailboxRouteHistoryDurableRouteState).GetConstructors());
        Assert.Empty(typeof(ProductionMailboxRouteHistoryCumulativeState).GetConstructors());
        Assert.Empty(typeof(ProductionMailboxRouteHistoryFinalArtifacts).GetConstructors());
        var publicMethods = typeof(ProductionMailboxRouteHistoryAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static);
        Assert.Contains(publicMethods, static method =>
            method.Name == nameof(ProductionMailboxRouteHistoryAuthoring
                .VerifyNextBatchForCommit));
        Assert.DoesNotContain(publicMethods, static method => method.Name == "VerifyBatch");
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

    private static VerifiedProductionMailboxHistoricalRouteAnchor CreateTestHistoricalAnchor(
        RouteV2TestFixture fixture,
        VerifiedProductionMailboxRouteHistoryCursor cursor)
    {
        var enrolledRol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(
            cursor.CanonicalCurrentRouteOriginLkg());
        var enrollmentState = new VerifiedProductionMailboxRouteContinuityEnrollmentState(
            cursor.Enrollment, fixture.PreDelegationRouteOriginLkg, enrolledRol);
        var responderKey = RouteV2TestFixture.Bytes(221, 32);
        var ocr = new ProductionMailboxOwnerControlResponderCertificate
        {
            NetworkId = fixture.NetworkId,
            MailboxOwnerEd25519PublicKey = fixture.Delegation.MailboxOwnerEd25519PublicKey,
            RouteDomainHash = fixture.RouteDomainHash,
            AnchorCanonicalAuthorityHash = fixture.Authority.CanonicalAuthorityHash,
            ResponderEd25519PublicKey = responderKey,
            IssuedAtUnixSeconds = fixture.Acceptance.AcceptedAtUnixSeconds,
            ExpiresAtUnixSeconds = fixture.Delegation.ExpiresAtUnixSeconds,
            KeyGeneration = 1,
            PreviousCanonicalCertificateHash = new byte[32],
            AnchorIssuerSignature = RouteV2TestFixture.Bytes(222, 64)
        };
        var canonicalOcr = new byte[ProductionMailboxOwnerControlConstants
            .ResponderCertificateLength];
        return new VerifiedProductionMailboxHistoricalRouteAnchor(
            enrollmentState, fixture.Authority, fixture.RevocationSnapshot,
            fixture.VerifiedCertificate, fixture.VerifiedPra, ocr, canonicalOcr,
            SHA256.HashData(canonicalOcr));
    }

    private static byte[] BuildLinkChainBatch(
        ReadOnlySpan<byte> source,
        ulong currentAuthorizationSequence,
        int linkCount,
        int mismatchIndex)
    {
        var artifactCount = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(50, 2));
        var artifactTableBytes = checked(artifactCount *
            ProductionMailboxRouteHistoryConstants.ArtifactItemLength);
        var oldTableBytes = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
            source.Slice(52, 4)));
        var payloadBytes = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
            source.Slice(56, 4)));
        var newTableBytes = checked(artifactTableBytes +
            linkCount * ProductionMailboxRouteHistoryConstants.LinkItemLength);
        var output = new byte[checked(ProductionMailboxRouteHistoryConstants.HeaderLength +
            newTableBytes + payloadBytes)];
        source[..ProductionMailboxRouteHistoryConstants.HeaderLength].CopyTo(output);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(48, 2),
            checked((ushort)linkCount));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(52, 4),
            checked((uint)newTableBytes));
        source.Slice(ProductionMailboxRouteHistoryConstants.HeaderLength,
            artifactTableBytes).CopyTo(output.AsSpan(
                ProductionMailboxRouteHistoryConstants.HeaderLength));
        var sourceLinkOffset = ProductionMailboxRouteHistoryConstants.HeaderLength +
            artifactTableBytes;
        for (var index = 0; index < linkCount; index++)
        {
            var target = output.AsSpan(sourceLinkOffset +
                index * ProductionMailboxRouteHistoryConstants.LinkItemLength,
                ProductionMailboxRouteHistoryConstants.LinkItemLength);
            source.Slice(sourceLinkOffset,
                ProductionMailboxRouteHistoryConstants.LinkItemLength).CopyTo(target);
            var predecessor = checked(currentAuthorizationSequence + (ulong)index +
                (index == mismatchIndex ? 1UL : 0UL));
            BinaryPrimitives.WriteUInt64BigEndian(target[16..24], predecessor);
            BinaryPrimitives.WriteUInt64BigEndian(target[24..32], predecessor + 1);
        }
        source.Slice(ProductionMailboxRouteHistoryConstants.HeaderLength + oldTableBytes,
            payloadBytes).CopyTo(output.AsSpan(
                ProductionMailboxRouteHistoryConstants.HeaderLength + newTableBytes));
        return output;
    }

    private static byte[] BuildLateNonAdjacentAliasBatch(
        RouteV2TestFixture fixture,
        VerifiedProductionMailboxRouteHistoryCursor cursor)
    {
        const int pmrCount = ProductionMailboxRouteHistoryConstants.MaximumArtifacts - 2;
        var certificate = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
            fixture.VerifiedCertificate.Certificate);
        var pmrs = new List<(byte[] Payload, byte[] Hash)>(pmrCount);
        for (var index = 0; index < pmrCount; index++)
        {
            var payload = new byte[ProductionMailboxRevocationSnapshotConstants
                .MaximumArtifactBytes];
            "PMR1"u8.CopyTo(payload);
            payload[4] = ProductionMailboxRevocationSnapshotConstants.Version;
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(8, 4),
                checked((uint)(index + 1)));
            BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(152, 2),
                ProductionMailboxRevocationSnapshotConstants.MaximumRevokedGrantSerials);
            pmrs.Add((payload, SHA256.HashData(payload)));
        }
        pmrs.Sort(static (left, right) =>
            left.Hash.AsSpan().SequenceCompareTo(right.Hash));
        var artifactCount = ProductionMailboxRouteHistoryConstants.MaximumArtifacts;
        var tableBytes = checked(artifactCount *
            ProductionMailboxRouteHistoryConstants.ArtifactItemLength +
            ProductionMailboxRouteHistoryConstants.LinkItemLength);
        var payloadBytes = checked(2 * certificate.Length +
            pmrs.Sum(static item => item.Payload.Length));
        var output = new byte[checked(ProductionMailboxRouteHistoryConstants.HeaderLength +
            tableBytes + payloadBytes)];
        "RHB1"u8.CopyTo(output);
        output[4] = ProductionMailboxRouteHistoryConstants.Version;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8, 8), 1);
        cursor.CanonicalCheckpointHash.Span.CopyTo(output.AsSpan(16, 32));
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(48, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(50, 2),
            checked((ushort)artifactCount));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(52, 4),
            checked((uint)tableBytes));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(56, 4),
            checked((uint)payloadBytes));
        var rowOffset = ProductionMailboxRouteHistoryConstants.HeaderLength;
        var payloadOffset = ProductionMailboxRouteHistoryConstants.HeaderLength + tableBytes;
        WriteArtifact(ProductionMailboxRouteHistoryArtifactKind.Authority,
            certificate, output, ref rowOffset, ref payloadOffset);
        foreach (var item in pmrs)
            WriteArtifact(ProductionMailboxRouteHistoryArtifactKind.Revocations,
                item.Payload, output, ref rowOffset, ref payloadOffset);
        WriteArtifact(ProductionMailboxRouteHistoryArtifactKind.RouteCertificate,
            certificate, output, ref rowOffset, ref payloadOffset);
        return output;
    }

    private static void WriteArtifact(
        ProductionMailboxRouteHistoryArtifactKind kind,
        ReadOnlySpan<byte> payload,
        byte[] output,
        ref int rowOffset,
        ref int payloadOffset)
    {
        output[rowOffset] = (byte)kind;
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(rowOffset + 4, 4),
            checked((uint)payload.Length));
        SHA256.HashData(payload).CopyTo(output.AsSpan(rowOffset + 8, 32));
        payload.CopyTo(output.AsSpan(payloadOffset));
        rowOffset += ProductionMailboxRouteHistoryConstants.ArtifactItemLength;
        payloadOffset += payload.Length;
    }

    private static ProductionMailboxRouteRevocationCheckpoint SignCheckpoint(
        ProductionMailboxRouteRevocationCheckpoint value, byte[] key)
    {
        var unsigned = value with { CurrentIssuerSignature = new byte[64] };
        return unsigned with
        {
            CurrentIssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteContinuityCodec
                    .GetRevocationCheckpointSigningBytes(unsigned), key)
        };
    }

    private static ProductionMailboxRouteContinuityActivation SignActivation(
        RouteV2TestFixture fixture, ProductionMailboxRouteTransitionContext transition,
        byte[] checkpointBytes)
    {
        var revocations = fixture.RevocationSnapshot.Snapshot;
        return RouteV2TestFixture.SignActivation(new ProductionMailboxRouteContinuityActivation
        {
            NetworkId = fixture.NetworkId,
            RouteDomainHash = fixture.RouteDomainHash,
            CurrentAuthorityGeneration = fixture.Authority.Authority.AuthorityGeneration,
            CurrentCanonicalAuthorityHash = fixture.Authority.CanonicalAuthorityHash,
            CurrentIssuerEd25519PublicKey =
                fixture.Authority.Authority.MailboxIssuerEd25519PublicKey,
            CurrentRevocationGeneration = revocations.RevocationGeneration,
            CurrentRevocationHeadHash = revocations.RevocationHeadHash,
            CurrentRevocationSnapshotHash = fixture.RevocationSnapshot.CanonicalSnapshotHash,
            TransitionSalt = transition.TransitionSalt,
            ContinuityTransitionCommitment = transition.ContinuityTransitionCommitment,
            CanonicalRevocationCheckpointHash = SHA256.HashData(checkpointBytes),
            FreshCanonicalRouteCertificateHash =
                fixture.VerifiedCertificate.CanonicalCertificateHash,
            CanonicalTransitionContextHash = ProductionMailboxRouteAuthorizationCodec
                .ComputeTransitionContextHash(transition),
            PredecessorAuthorizationKind = transition.PredecessorAuthorizationKind,
            PredecessorCanonicalRouteAuthorizationHash =
                transition.PredecessorCanonicalRouteAuthorizationHash,
            PredecessorRouteAuthorizationSequence =
                transition.PredecessorRouteAuthorizationSequence,
            ActivationSequence = transition.NewRouteAuthorizationSequence,
            IssuedAtUnixSeconds = RouteV2TestFixture.Now,
            ExpiresAtUnixSeconds = RouteV2TestFixture.Now + 90,
            CurrentIssuerSignature = new byte[64]
        }, fixture.IssuerPrivateKey);
    }

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
