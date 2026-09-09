using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class PreKeyInventoryPublicationTests
{
    [Fact]
    public async Task CanonicalCodecsExactHashesTwoReceiptsAndVerifiedHandoffAreClosed()
    {
        var fixture = await Fixture.CreateAsync();
        var verified = await fixture.VerifyAsync();

        Assert.Equal(Xpi1Codec.TotalBytes, fixture.Manifest.CanonicalBytes.Length);
        Assert.Equal(Xpp1Codec.MinimumTotalBytes, fixture.Publication.CanonicalBytes.Length);
        Assert.All(fixture.Receipts, receipt => Assert.Equal(Xic1Codec.TotalBytes, receipt.CanonicalBytes.Length));
        Assert.Equal(
            ContactCodec.Sha256Domain(Xpi1Codec.ExactHashDomain, fixture.Manifest.CanonicalBytes.Span),
            fixture.Manifest.Xpi1Hash.ToArray());
        Assert.Equal(fixture.Manifest.CanonicalBytes.ToArray(), verified.ExactXpi1.ToArray());
        Assert.Equal(fixture.Manifest.Xpi1Hash.ToArray(), verified.Xpi1Hash.ToArray());
        Assert.Equal(fixture.Manifest.PredecessorXpi1Hash.ToArray(), verified.PredecessorXpi1Hash.ToArray());
        Assert.Equal(32, verified.OneTimeMembers.Count);
        Assert.Equal(Dpk2PrekeyKind.OneTime, verified.OneTimeMembers[0].Kind);
        Assert.Equal(fixture.OneTimeExact[0], verified.OneTimeMembers[0].ExactDpk2.ToArray());
        Assert.Equal(
            ContactCodec.Sha256Domain("Deep/Messaging/V2/exact-dpk2", fixture.OneTimeExact[0]),
            verified.OneTimeMembers[0].ExactDpk2Hash.ToArray());
        Assert.Equal(Dpk2PrekeyKind.LastResort, verified.LastResortMember.Kind);
        Assert.Equal(new byte[32], verified.LastResortMember.ClaimPreKeyId.ToArray());
        Assert.Equal(fixture.Xps1.LastResortReuseLimit, verified.LastResortMember.ReuseLimit);

        var exact = verified.OneTimeMembers[0].ExactDpk2.ToArray();
        exact[0] ^= 0xff;
        Assert.NotEqual(exact, verified.OneTimeMembers[0].ExactDpk2.ToArray());
        Assert.Empty(typeof(VerifiedPreKeyInventoryPublication).GetConstructors());
        Assert.Empty(typeof(VerifiedPreKeyInventoryMember).GetConstructors());
        Assert.DoesNotContain(typeof(VerifiedPreKeyInventoryMember).GetProperties(), property =>
            property.Name.Contains("Private", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("Authority", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("Secret", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task InventoryOrderAndCommitmentSubstitutionReject()
    {
        var fixture = await Fixture.CreateAsync();
        var swapped = fixture.OneTimeExact.Select(static value => (ReadOnlyMemory<byte>)value).ToArray();
        (swapped[0], swapped[1]) = (swapped[1], swapped[0]);
        var publication = Xpp1Codec.Decode(Xpp1Codec.Encode(
            fixture.Core.Network, fixture.OperationId, fixture.Placement.PlacementHash.Span,
            fixture.Manifest, swapped, fixture.LastResortExact));

        await AssertCodeAsync("InventoryOrderInvalid", () => fixture.VerifyAsync(publication: publication));

        var changed = fixture.OneTimes.ToArray();
        changed[0] = fixture.BuildDpk2(0, Dpk2PrekeyKind.OneTime, notBefore: 21);
        var changedExact = changed.Select(Dpk2Codec.Encode).Select(static value => (ReadOnlyMemory<byte>)value).ToArray();
        publication = Xpp1Codec.Decode(Xpp1Codec.Encode(
            fixture.Core.Network, fixture.OperationId, fixture.Placement.PlacementHash.Span,
            fixture.Manifest, changedExact, fixture.LastResortExact));
        await AssertCodeAsync("Dpk2InventoryBindingMismatch", () => fixture.VerifyAsync(publication: publication));
    }

    [Fact]
    public async Task LineageAndTwoExactReplicaReceiptsAreMandatory()
    {
        var fixture = await Fixture.CreateAsync();
        await AssertCodeAsync("ReplicaSetMismatch", () => fixture.VerifyAsync(receipts: [fixture.Receipts[0]]));

        var fakeReceipts = fixture.BuildReceipts(fakeSignature: true);
        await AssertCodeAsync("InventoryReceiptSignatureInvalid", () => fixture.VerifyAsync(receipts: fakeReceipts));

        var epochTwo = await Fixture.CreateAsync(inventoryEpoch: 2, predecessorHash: fixture.Manifest.Xpi1Hash.ToArray());
        await AssertCodeAsync("InventoryLineageMismatch", () => epochTwo.VerifyAsync(predecessor: null));
    }

    [Fact]
    public async Task ManifestSignaturePlacementAndReceiptBindingSubstitutionReject()
    {
        var fixture = await Fixture.CreateAsync();
        var fakeManifest = fixture.BuildManifest(fakeSignature: true);
        var publication = fixture.BuildPublication(fakeManifest);
        await AssertCodeAsync("InventorySignatureInvalid", () => fixture.VerifyAsync(publication: publication));

        var changedReceipt = fixture.BuildReceipts(xpi1Hash: Enumerable.Repeat((byte)0xe1, 32).ToArray());
        await AssertCodeAsync("InventoryReceiptBindingMismatch", () => fixture.VerifyAsync(receipts: changedReceipt));

        var changedPlacementPublication = Xpp1Codec.Decode(Xpp1Codec.Encode(
            fixture.Core.Network, fixture.OperationId, Enumerable.Repeat((byte)0xe2, 32).ToArray(),
            fixture.Manifest, fixture.OneTimeExact.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
            fixture.LastResortExact));
        await AssertCodeAsync("PlacementMismatch", () => fixture.VerifyAsync(publication: changedPlacementPublication));
    }

    [Fact]
    public async Task CanonicalBoundsRejectBeforeVerification()
    {
        var fixture = await Fixture.CreateAsync();
        Assert.Throws<ArgumentOutOfRangeException>(() => Xpp1Codec.Encode(
            fixture.Core.Network, fixture.OperationId, fixture.Placement.PlacementHash.Span,
            fixture.Manifest,
            fixture.OneTimeExact.Take(31).Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
            fixture.LastResortExact));

        var changed = fixture.Manifest.CanonicalBytes.ToArray();
        changed[10] = 1;
        Assert.Equal("NonCanonicalReserved", Assert.Throws<ContactFormatException>(() => Xpi1Codec.Decode(changed)).Code);

        changed = fixture.Receipts[0].CanonicalBytes.ToArray();
        changed[FieldHeaderOffset(changed, 7) + 2] = 1;
        Assert.Equal("NonCanonicalReserved", Assert.Throws<ContactFormatException>(() => Xic1Codec.Decode(changed)).Code);
    }

    [Fact]
    public async Task BoundedPublication_IsCanonicalOrderedAndActivatesOnlyAfterVerifiedFinalReceipts()
    {
        var fixture = await Fixture.CreateAsync();
        var bounded = BoundedPreKeyInventoryPublication.Create(
            fixture.Publication, fixture.Placement.ViewHash.Span, 20, 70);

        Assert.Equal(Xpp1BoundedPhase.Manifest, bounded.OrderedRequests[0].Phase);
        Assert.Equal(Xpp1BoundedPhase.Commit, bounded.OrderedRequests[^1].Phase);
        Assert.All(bounded.OrderedRequests, request =>
            Assert.True(request.CanonicalBytes.Length < OnionLimits.MaximumCanonicalRequestBytes));
        Assert.All(bounded.OrderedRequests, request =>
            Assert.True(request.CanonicalBytes.Length < 70_400));
        Assert.True(Xpp1BoundedCodec.MaximumCanonicalRequestBytes < 70_400);
        Assert.Equal(
            Enumerable.Range(0, bounded.ChunkRequests.Count),
            bounded.ChunkRequests.Select(static chunk => (int)chunk.ChunkIndex));
        Assert.Equal(
            bounded.ManifestRequest.InventoryTotalLength,
            (ulong)bounded.ChunkRequests.Sum(static chunk => chunk.Payload.Length));

        var manifest = PreKeyPublicationReplicaState.Empty.Apply(bounded.ManifestRequest);
        Assert.Equal(PreKeyPublicationReplicaDisposition.ManifestAccepted, manifest.Disposition);
        Assert.False(manifest.ActivatesInventory);
        var incomplete = manifest.NextState.Apply(bounded.CommitRequest);
        Assert.Equal(PreKeyPublicationReplicaDisposition.Incomplete, incomplete.Disposition);
        Assert.False(incomplete.NextState.IsActivated);

        var state = manifest.NextState;
        foreach (var chunk in bounded.ChunkRequests)
        {
            var transition = state.Apply(chunk);
            Assert.Equal(PreKeyPublicationReplicaDisposition.ChunkAccepted, transition.Disposition);
            Assert.False(transition.ActivatesInventory);
            state = transition.NextState;
        }
        var ready = state.Apply(bounded.CommitRequest);
        Assert.Equal(PreKeyPublicationReplicaDisposition.ReadyToVerify, ready.Disposition);
        Assert.False(ready.ActivatesInventory);
        Assert.False(ready.NextState.IsActivated);

        var candidate = await PreKeyInventoryPublicationVerifier.VerifyCandidateAsync(
            ready, fixture.Placement, fixture.Authority, fixture.Bundle,
            new OnionTrustedTimeAuthority(new FixedClock(
                new OnionMonotonicReading(fixture.Core.BootId, 1_003))),
            null, default);
        var installation = PreKeyPublicationReplicaState.PrepareActivation(ready, candidate);
        Assert.True(installation.NextState.IsActivated);
        Assert.Equal(fixture.OperationId, installation.PublicationOperationId.ToArray());
        Assert.Equal(fixture.Manifest.Xpi1Hash.ToArray(), installation.Xpi1Hash.ToArray());
        Assert.Equal(fixture.Manifest.CanonicalBytes.ToArray(), installation.ExactXpi1.ToArray());
        Assert.Equal(fixture.OneTimeExact, installation.OneTimeMembers
            .Select(static member => member.ExactDpk2.ToArray()).ToArray());
        Assert.Equal(fixture.LastResortExact, installation.LastResortMember.ExactDpk2.ToArray());
        Assert.Empty(typeof(VerifiedPreKeyInventoryInstallationPlan).GetConstructors());

        var receipts = fixture.BuildBoundedReceipts(bounded.CommitRequest);
        var verified = await PreKeyInventoryPublicationVerifier.VerifyBoundedAsync(
            bounded, receipts, fixture.Placement, fixture.Authority, fixture.Bundle,
            new OnionTrustedTimeAuthority(new FixedClock(
                new OnionMonotonicReading(fixture.Core.BootId, 1_003))),
            null, default);
        Assert.Equal(fixture.Manifest.Xpi1Hash.ToArray(), verified.Xpi1Hash.ToArray());
    }

    [Fact]
    public async Task BoundedPublication_OnionBoundaryAcceptsOnlyCanonicalPhaseMatchedXpp1AndXic1()
    {
        var fixture = await Fixture.CreateAsync();
        var bounded = BoundedPreKeyInventoryPublication.Create(
            fixture.Publication, fixture.Placement.ViewHash.Span, 20, 70);
        var requests = new Xpp1BoundedRequest[]
        {
            bounded.ManifestRequest,
            bounded.ChunkRequests[0],
            bounded.CommitRequest,
        };

        Xic1BoundedReceipt Receipt(Xpp1BoundedRequest request)
        {
            var status = request.Phase switch
            {
                Xpp1BoundedPhase.Manifest => Xic1BoundedStatus.ManifestStaged,
                Xpp1BoundedPhase.Chunk => Xic1BoundedStatus.ChunkStaged,
                Xpp1BoundedPhase.Commit => Xic1BoundedStatus.Committed,
                _ => throw new InvalidOperationException(),
            };
            var outcome = request.Phase == Xpp1BoundedPhase.Commit
                ? Xic1BoundedMutationOutcome.DurablyActivated
                : Xic1BoundedMutationOutcome.DurablyStaged;
            var acceptedCount = request.Phase switch
            {
                Xpp1BoundedPhase.Manifest => (ushort)0,
                Xpp1BoundedPhase.Chunk => checked((ushort)(request.ChunkIndex + 1)),
                Xpp1BoundedPhase.Commit => request.ChunkCount,
                _ => throw new InvalidOperationException(),
            };
            var acceptedLength = request.Phase switch
            {
                Xpp1BoundedPhase.Manifest => 0UL,
                Xpp1BoundedPhase.Chunk => Math.Min(
                    request.InventoryTotalLength,
                    checked((ulong)acceptedCount * Xpp1BoundedCodec.MaximumChunkPayloadBytes)),
                Xpp1BoundedPhase.Commit => request.InventoryTotalLength,
                _ => throw new InvalidOperationException(),
            };
            var stateHash = request is Xpp1CommitRequest commit
                ? Xic1BoundedCodec.ComputeActivatedStateHash(commit)
                : Bytes(32, 0xc1);
            var fields = new Xic1BoundedUnsignedFields(
                request, status, outcome, acceptedCount, acceptedLength,
                Bytes(32, 0xb1), 30, stateHash);
            return Xic1BoundedCodec.Decode(Xic1BoundedCodec.Encode(fields, Bytes(64, 0xd1)));
        }

        foreach (var request in requests)
        {
            var verifiedRequest = OnionTerminalPayloadVerifierV1.VerifyRequest(
                fixture.Placement.Network, OnionOperation.ContactResolve, request.CanonicalBytes);
            var receipt = Receipt(request);
            var verifiedResult = OnionTerminalPayloadVerifierV1.VerifySuccess(
                verifiedRequest, receipt.CanonicalBytes);

            Assert.Equal(request.CanonicalBytes.ToArray(), verifiedRequest.CanonicalBytes.ToArray());
            Assert.Equal(receipt.CanonicalBytes.ToArray(), verifiedResult.Body.ToArray());
        }

        Assert.Throws<PrivacyRoutingProtocolException>(() => OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Placement.Network, OnionOperation.GroupControl,
            bounded.ManifestRequest.CanonicalBytes));
        Assert.Throws<PrivacyRoutingProtocolException>(() => OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Placement.Network, OnionOperation.ContactResolve,
            fixture.Publication.CanonicalBytes));

        var oversized = bounded.ChunkRequests[0].CanonicalBytes.ToArray();
        Array.Resize(ref oversized, Xpp1BoundedCodec.MaximumCanonicalRequestBytes + 1);
        Assert.Throws<PrivacyRoutingProtocolException>(() => OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Placement.Network, OnionOperation.ContactResolve, oversized));

        var manifestRequest = OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Placement.Network, OnionOperation.ContactResolve,
            bounded.ManifestRequest.CanonicalBytes);
        Assert.Throws<PrivacyRoutingProtocolException>(() => OnionTerminalPayloadVerifierV1.VerifySuccess(
            manifestRequest, Receipt(bounded.ChunkRequests[0]).CanonicalBytes));
        Assert.Throws<PrivacyRoutingProtocolException>(() => OnionTerminalPayloadVerifierV1.VerifySuccess(
            manifestRequest, fixture.Receipts[0].CanonicalBytes));

        var phaseStatusMismatch = Receipt(bounded.ManifestRequest).CanonicalBytes.ToArray();
        phaseStatusMismatch[FieldHeaderOffset(phaseStatusMismatch, 8) + 9] =
            (byte)Xic1BoundedStatus.ChunkStaged;
        Assert.Throws<PrivacyRoutingProtocolException>(() => OnionTerminalPayloadVerifierV1.VerifySuccess(
            manifestRequest, phaseStatusMismatch));
    }

    [Fact]
    public async Task BoundedPublication_ExactReplayDriftAndReceiptCoverageAreClosed()
    {
        var fixture = await Fixture.CreateAsync();
        var bounded = BoundedPreKeyInventoryPublication.Create(
            fixture.Publication, fixture.Placement.ViewHash.Span, 20, 70);
        var staged = PreKeyPublicationReplicaState.Empty.Apply(bounded.ManifestRequest).NextState;

        var replay = staged.Apply(Xpp1BoundedCodec.Decode(
            bounded.ManifestRequest.CanonicalBytes.Span));
        Assert.Equal(PreKeyPublicationReplicaDisposition.ExactReplay, replay.Disposition);
        Assert.True(replay.RequiresStoredReceipt);

        var chunk = bounded.ChunkRequests[0];
        var changedView = chunk.ViewHash.ToArray();
        changedView[0] ^= 0x80;
        var drifted = Xpp1BoundedCodec.Decode(Xpp1BoundedCodec.Encode(
            Xpp1BoundedPhase.Chunk,
            chunk.NetworkId.Span,
            chunk.PublicationOperationId.Span,
            changedView,
            chunk.PlacementHash.Span,
            chunk.IssuedAtUnixSeconds,
            chunk.ExpiresAtUnixSeconds,
            chunk.PublicationHash.Span,
            [],
            chunk.Xpi1Hash.Span,
            chunk.InventoryTotalLength,
            chunk.InventoryHash.Span,
            chunk.ChunkCount,
            chunk.ChunkIndex,
            chunk.ChunkHash.Span,
            chunk.Payload.Span));
        Assert.Equal(
            PreKeyPublicationReplicaDisposition.ForkLatched,
            staged.Apply(drifted).Disposition);

        Assert.Throws<ContactFormatException>(() => new Xic1BoundedUnsignedFields(
            bounded.ManifestRequest,
            Xic1BoundedStatus.ManifestStaged,
            Xic1BoundedMutationOutcome.DurablyStaged,
            1,
            0,
            Bytes(32, 0xb1),
            30,
            Bytes(32, 0xc1)));
        Assert.Throws<ContactFormatException>(() => new Xic1BoundedUnsignedFields(
            chunk,
            Xic1BoundedStatus.ChunkStaged,
            Xic1BoundedMutationOutcome.DurablyStaged,
            0,
            0,
            Bytes(32, 0xb2),
            30,
            Bytes(32, 0xc2)));
    }

    [Fact]
    public async Task ReplicaCandidateBridge_RejectsWrongDispositionAndCrossPublicationSubstitution()
    {
        var fixture = await Fixture.CreateAsync();
        var first = BoundedPreKeyInventoryPublication.Create(
            fixture.Publication, fixture.Placement.ViewHash.Span, 20, 70);
        var time = new OnionTrustedTimeAuthority(new FixedClock(
            new OnionMonotonicReading(fixture.Core.BootId, 1_003)));
        var manifestOnly = PreKeyPublicationReplicaState.Empty.Apply(first.ManifestRequest);

        var wrongDisposition = await Assert.ThrowsAsync<PreKeyInventoryPublicationVerificationException>(
            () => PreKeyInventoryPublicationVerifier.VerifyCandidateAsync(
                manifestOnly, fixture.Placement, fixture.Authority, fixture.Bundle,
                time, null, default).AsTask());
        Assert.Equal("BoundedCommitNotReady", wrongDisposition.Code);
        Assert.DoesNotContain(
            typeof(PreKeyPublicationReplicaTransition).GetProperties(
                BindingFlags.Public | BindingFlags.Instance),
            static property => property.PropertyType == typeof(Xpp1Record));

        static PreKeyPublicationReplicaTransition Ready(BoundedPreKeyInventoryPublication publication)
        {
            var state = PreKeyPublicationReplicaState.Empty.Apply(publication.ManifestRequest).NextState;
            foreach (var chunk in publication.ChunkRequests)
                state = state.Apply(chunk).NextState;
            return state.Apply(publication.CommitRequest);
        }

        var firstReady = Ready(first);
        var changedOperation = fixture.OperationId.ToArray();
        changedOperation[0] ^= 0x80;
        var substitutedLogical = Xpp1Codec.Decode(Xpp1Codec.Encode(
            fixture.Core.Network,
            changedOperation,
            fixture.Placement.PlacementHash.Span,
            fixture.Manifest,
            fixture.OneTimeExact.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
            fixture.LastResortExact));
        var second = BoundedPreKeyInventoryPublication.Create(
            substitutedLogical, fixture.Placement.ViewHash.Span, 20, 70);
        var secondReady = Ready(second);
        var substitutedCandidate = await PreKeyInventoryPublicationVerifier.VerifyCandidateAsync(
            secondReady, fixture.Placement, fixture.Authority, fixture.Bundle,
            time, null, default);

        Assert.Throws<InvalidOperationException>(() =>
            PreKeyPublicationReplicaState.PrepareActivation(firstReady, substitutedCandidate));
    }

    [Fact]
    public async Task ReplicaLineage_RestartsAdvancesAndRejectsRollbackOrSameEpochFork()
    {
        static PreKeyPublicationReplicaTransition Ready(BoundedPreKeyInventoryPublication publication)
        {
            var state = PreKeyPublicationReplicaState.Empty.Apply(publication.ManifestRequest).NextState;
            foreach (var chunk in publication.ChunkRequests)
                state = state.Apply(chunk).NextState;
            return state.Apply(publication.CommitRequest);
        }

        var first = await Fixture.CreateAsync();
        var firstBounded = BoundedPreKeyInventoryPublication.Create(
            first.Publication, first.Placement.ViewHash.Span, 20, 70);
        var firstReady = Ready(firstBounded);
        var firstCandidate = await PreKeyInventoryPublicationVerifier.VerifyCandidateAsync(
            firstReady, first.Placement, first.Authority, first.Bundle,
            new OnionTrustedTimeAuthority(new FixedClock(
                new OnionMonotonicReading(first.Core.BootId, 1_003))),
            null, default);
        var installed = PreKeyPublicationReplicaState.PrepareActivation(firstReady, firstCandidate);
        var restored = PreKeyInventoryPublicationVerifier.RestoreReplicaLineage(
            installed.ReplicaLineage.ExactXpi1.Span,
            installed.ReplicaLineage.Xpi1Hash.Span,
            first.Authority,
            first.Bundle);
        Assert.Equal(installed.ReplicaLineage.Xpi1Hash.ToArray(), restored.Xpi1Hash.ToArray());
        Assert.Equal(1UL, restored.InventoryEpoch);
        Assert.Equal(first.Manifest.ServiceCapability.ToArray(), restored.ServiceCapability.ToArray());
        Assert.Equal(first.Manifest.ResponderDeviceId.ToArray(), restored.ResponderDeviceId.ToArray());
        Assert.Empty(typeof(VerifiedPreKeyInventoryReplicaLineage).GetConstructors());
        var changedExact = restored.ExactXpi1.ToArray();
        changedExact[0] ^= 0x80;
        Assert.NotEqual(changedExact, restored.ExactXpi1.ToArray());
        var wrongPersistedHash = restored.Xpi1Hash.ToArray();
        wrongPersistedHash[0] ^= 0x80;
        Assert.Equal("ReplicaLineageHashMismatch", Assert.Throws<PreKeyInventoryPublicationVerificationException>(() =>
            PreKeyInventoryPublicationVerifier.RestoreReplicaLineage(
                restored.ExactXpi1.Span, wrongPersistedHash, first.Authority, first.Bundle)).Code);

        var successor = await Fixture.CreateAsync(
            inventoryEpoch: 2,
            predecessorHash: restored.Xpi1Hash.ToArray(),
            issuedAtUnixSeconds: 70,
            expiresAtUnixSeconds: 79);
        var successorBounded = BoundedPreKeyInventoryPublication.Create(
            successor.Publication, successor.Placement.ViewHash.Span, 70, 79);
        var successorReady = Ready(successorBounded);
        var currentTime = new OnionTrustedTimeAuthority(new FixedClock(
            new OnionMonotonicReading(successor.Core.BootId, 1_044)));
        var successorCandidate = await PreKeyInventoryPublicationVerifier.VerifyCandidateAsync(
            successorReady,
            restored,
            successor.Placement,
            successor.Authority,
            successor.Bundle,
            currentTime,
            default);
        var successorInstalled = PreKeyPublicationReplicaState.PrepareActivation(
            successorReady, successorCandidate);
        Assert.Equal(2UL, successorInstalled.ReplicaLineage.InventoryEpoch);
        Assert.Equal(restored.Xpi1Hash.ToArray(),
            successor.Manifest.PredecessorXpi1Hash.ToArray());

        var rollback = await Assert.ThrowsAsync<PreKeyInventoryPublicationVerificationException>(() =>
            PreKeyInventoryPublicationVerifier.VerifyCandidateAsync(
                successorReady,
                successorInstalled.ReplicaLineage,
                successor.Placement,
                successor.Authority,
                successor.Bundle,
                currentTime,
                default).AsTask());
        Assert.Equal("InventoryLineageRollback", rollback.Code);

        var forkFixture = await Fixture.CreateAsync(
            inventoryEpoch: 2,
            predecessorHash: Bytes(32, 0xe1),
            issuedAtUnixSeconds: 70,
            expiresAtUnixSeconds: 79);
        var forkBounded = BoundedPreKeyInventoryPublication.Create(
            forkFixture.Publication, forkFixture.Placement.ViewHash.Span, 70, 79);
        var fork = await Assert.ThrowsAsync<PreKeyInventoryPublicationVerificationException>(() =>
            PreKeyInventoryPublicationVerifier.VerifyCandidateAsync(
                Ready(forkBounded),
                successorInstalled.ReplicaLineage,
                forkFixture.Placement,
                forkFixture.Authority,
                forkFixture.Bundle,
                new OnionTrustedTimeAuthority(new FixedClock(
                    new OnionMonotonicReading(forkFixture.Core.BootId, 1_044))),
                default).AsTask());
        Assert.Equal("InventoryLineageFork", fork.Code);
    }

    [Fact]
    public async Task ClaimMembershipProofClosesOneTimeAndLastResortShapes()
    {
        var fixture = await Fixture.CreateAsync();
        var hashes = fixture.OneTimeExact.Select(exact =>
            ContactCodec.Sha256Domain("Deep/Messaging/V2/exact-dpk2", exact)).ToArray();
        var proof = PreKeyInventoryTestData.BuildProof(hashes, 0);

        PreKeyInventoryPublicationVerifier.VerifyClaimMembership(
            fixture.Manifest, fixture.OneTimeExact[0], 0, proof);
        PreKeyInventoryPublicationVerifier.VerifyClaimMembership(
            fixture.Manifest, fixture.LastResortExact, ushort.MaxValue, []);

        var changedProof = proof.ToArray();
        changedProof[0] ^= 0xff;
        var oneTimeError = Assert.Throws<PreKeyInventoryPublicationVerificationException>(() =>
            PreKeyInventoryPublicationVerifier.VerifyClaimMembership(
                fixture.Manifest, fixture.OneTimeExact[0], 0, changedProof));
        Assert.Equal("InventoryMembershipMismatch", oneTimeError.Code);
        var lastResortError = Assert.Throws<PreKeyInventoryPublicationVerificationException>(() =>
            PreKeyInventoryPublicationVerifier.VerifyClaimMembership(
                fixture.Manifest, fixture.LastResortExact, 0, []));
        Assert.Equal("InventoryMembershipMismatch", lastResortError.Code);
    }

    private static async Task AssertCodeAsync(
        string expected,
        Func<ValueTask<VerifiedPreKeyInventoryPublication>> action)
    {
        var error = await Assert.ThrowsAsync<PreKeyInventoryPublicationVerificationException>(() => action().AsTask());
        Assert.Equal(expected, error.Code);
    }

    private sealed class Fixture
    {
        private Fixture(
            ContactNetworkAuthorityVerifierTests.Fixture core,
            ulong inventoryEpoch,
            byte[] predecessorHash,
            ulong issuedAtUnixSeconds,
            ulong expiresAtUnixSeconds)
        {
            Core = core;
            Bundle = core.Identity.Promote(core.Identity.Dcr);
            Xps1 = ContactCodec.DecodeXps1(Bundle.Bundle.FieldSpan(12).Slice(5, 352));
            InventoryEpoch = inventoryEpoch;
            PredecessorHash = predecessorHash;
            IssuedAtUnixSeconds = issuedAtUnixSeconds;
            ExpiresAtUnixSeconds = expiresAtUnixSeconds;
            OperationId = Bytes(32, 0x31);
        }

        internal ContactNetworkAuthorityVerifierTests.Fixture Core { get; }
        internal VerifiedContactNetworkAuthority Authority { get; private set; } = null!;
        internal VerifiedContactBundleClosure Bundle { get; }
        internal ContactCodec.Xps1Record Xps1 { get; }
        internal VerifiedContactServicePlacement Placement { get; private set; } = null!;
        internal ulong InventoryEpoch { get; }
        internal byte[] PredecessorHash { get; }
        internal ulong IssuedAtUnixSeconds { get; }
        internal ulong ExpiresAtUnixSeconds { get; }
        internal byte[] OperationId { get; }
        internal Dpk2Record[] OneTimes { get; private set; } = [];
        internal byte[][] OneTimeExact { get; private set; } = [];
        internal Dpk2Record LastResort { get; private set; } = null!;
        internal byte[] LastResortExact { get; private set; } = [];
        internal Xpi1Record Manifest { get; private set; } = null!;
        internal Xpp1Record Publication { get; private set; } = null!;
        internal Xic1Record[] Receipts { get; private set; } = [];

        internal static async Task<Fixture> CreateAsync(
            ulong inventoryEpoch = 1,
            byte[]? predecessorHash = null,
            ulong issuedAtUnixSeconds = 20,
            ulong expiresAtUnixSeconds = 70)
        {
            var fixture = new Fixture(
                ContactNetworkAuthorityVerifierTests.Fixture.Create(), inventoryEpoch,
                predecessorHash ?? new byte[32], issuedAtUnixSeconds, expiresAtUnixSeconds);
            fixture.Authority = await fixture.Core.VerifyAsync();
            fixture.Placement = ContactServicePlacementFactory.Create(
                fixture.Core.CurrentNetwork, ContactServiceRequestKind.PublishPreKeyInventory,
                fixture.Xps1.ServiceCapability);
            fixture.OneTimes = Enumerable.Range(0, 32)
                .Select(index => fixture.BuildDpk2(
                    index, Dpk2PrekeyKind.OneTime,
                    issuedAtUnixSeconds, issuedAtUnixSeconds, expiresAtUnixSeconds)).ToArray();
            fixture.OneTimeExact = fixture.OneTimes.Select(Dpk2Codec.Encode).ToArray();
            fixture.LastResort = fixture.BuildDpk2(
                32, Dpk2PrekeyKind.LastResort,
                issuedAtUnixSeconds, issuedAtUnixSeconds, expiresAtUnixSeconds);
            fixture.LastResortExact = Dpk2Codec.Encode(fixture.LastResort);
            fixture.Manifest = fixture.BuildManifest();
            fixture.Publication = fixture.BuildPublication(fixture.Manifest);
            fixture.Receipts = fixture.BuildReceipts();
            return fixture;
        }

        internal ValueTask<VerifiedPreKeyInventoryPublication> VerifyAsync(
            Xpp1Record? publication = null,
            IReadOnlyList<Xic1Record>? receipts = null,
            VerifiedPreKeyInventoryPublication? predecessor = null) =>
            PreKeyInventoryPublicationVerifier.VerifyAsync(
                publication ?? Publication, receipts ?? Receipts, Placement, Authority, Bundle,
                new OnionTrustedTimeAuthority(new FixedClock(new OnionMonotonicReading(Core.BootId, 1_003))),
                predecessor, default);

        internal Xpi1Record BuildManifest(bool fakeSignature = false)
        {
            var hashes = OneTimeExact.Select(exact =>
                ContactCodec.Sha256Domain("Deep/Messaging/V2/exact-dpk2", exact)).ToArray();
            var lastHash = ContactCodec.Sha256Domain("Deep/Messaging/V2/exact-dpk2", LastResortExact);
            var xpsReference = PreKeyInventoryTestData.Reference("XPS1", SHA256.HashData(Xps1.CanonicalBytes));
            var drsReference = PreKeyInventoryTestData.Reference("DRS1", Authority.RecipientDrs1ReferenceSpan[6..]);
            var fields = new Xpi1UnsignedFields(
                Core.Network, Xps1.ServiceCapability, Authority.RecipientDeviceId.Span,
                Authority.RecipientDpd1Reference.Span, Xps1.ServiceGeneration, xpsReference,
                InventoryEpoch, PredecessorHash, 32,
                PreKeyInventoryPublicationVerifier.ComputeMerkleRoot(hashes), lastHash,
                Authority.RecipientDmd1HashSpan, drsReference,
                IssuedAtUnixSeconds, ExpiresAtUnixSeconds);
            var signature = PublicKeyAuth.SignDetached(
                Xpi1Codec.CreateSignatureInput(fields), Core.Identity.Device.PrivateKey);
            if (fakeSignature) signature[0] ^= 0xff;
            return Xpi1Codec.Decode(Xpi1Codec.Encode(fields, signature));
        }

        internal Xpp1Record BuildPublication(Xpi1Record manifest) =>
            Xpp1Codec.Decode(Xpp1Codec.Encode(
                Core.Network, OperationId, Placement.PlacementHash.Span, manifest,
                OneTimeExact.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(), LastResortExact));

        internal Xic1Record[] BuildReceipts(byte[]? xpi1Hash = null, bool fakeSignature = false)
        {
            xpi1Hash ??= Manifest.Xpi1Hash.ToArray();
            return Placement.ResolveSelectedReplicas()
                .OrderBy(static replica => replica.NodeId, ByteArrayComparer.Instance)
                .Select((replica, index) =>
                {
                    var identity = Core.ReplicaIdentities.Single(candidate =>
                        candidate.NodeId.AsSpan().SequenceEqual(replica.NodeId));
                    var fields = new Xic1UnsignedFields(
                        Core.Network, OperationId, xpi1Hash, Placement.PlacementHash.Span,
                        replica.NodeId, 30);
                    var signature = PublicKeyAuth.SignDetached(
                        Xic1Codec.CreateSignatureInput(fields), identity.Key.PrivateKey);
                    if (fakeSignature && index == 0) signature[0] ^= 0xff;
                    return Xic1Codec.Decode(Xic1Codec.Encode(fields, signature));
                }).ToArray();
        }

        internal Xic1BoundedReceipt[] BuildBoundedReceipts(Xpp1CommitRequest request)
        {
            var stateHash = Xic1BoundedCodec.ComputeActivatedStateHash(request);
            return Placement.ResolveSelectedReplicas()
                .OrderBy(static replica => replica.NodeId, ByteArrayComparer.Instance)
                .Select(replica =>
                {
                    var identity = Core.ReplicaIdentities.Single(candidate =>
                        candidate.NodeId.AsSpan().SequenceEqual(replica.NodeId));
                    var fields = new Xic1BoundedUnsignedFields(
                        request,
                        Xic1BoundedStatus.Committed,
                        Xic1BoundedMutationOutcome.DurablyActivated,
                        request.ChunkCount,
                        request.InventoryTotalLength,
                        replica.NodeId,
                        30,
                        stateHash);
                    var signature = PublicKeyAuth.SignDetached(
                        Xic1BoundedCodec.CreateSignatureInput(fields), identity.Key.PrivateKey);
                    return Xic1BoundedCodec.Decode(Xic1BoundedCodec.Encode(fields, signature));
                }).ToArray();
        }

        internal Dpk2Record BuildDpk2(
            int index,
            Dpk2PrekeyKind kind,
            ulong notBefore = 20,
            ulong issuedAt = 20,
            ulong expiresAt = 70)
        {
            var certificate = Core.Identity.VerifiedRecipient.Certificate;
            var oneTimeId = kind == Dpk2PrekeyKind.OneTime ? Id(index + 1) : [];
            var oneTimePublic = kind == Dpk2PrekeyKind.OneTime ? Bytes(32, checked((byte)(0x40 + index))) : [];
            Dpk2Record Create(ReadOnlySpan<byte> xSignature, ReadOnlySpan<byte> kemSignature, ReadOnlySpan<byte> bundleSignature) => new(
                Core.Network, certificate.AccountHash.Span, certificate.DeviceId.Span,
                certificate.DeviceGeneration, Authority.RecipientDpd1Reference.Span,
                Core.Identity.Directory.Record.DirectoryGeneration, Core.Identity.Directory.Record.RecordHash.Span,
                Xps1.ServiceGeneration, InventoryEpoch, Id(index + 101), 1,
                notBefore, issuedAt, expiresAt, certificate.DeviceX25519PublicKey.Span,
                Bytes(32, 0x61), Bytes(32, 0x62), xSignature,
                oneTimeId, oneTimePublic, Id(index + 201),
                Bytes(1184, checked((byte)(0x70 + index))), kind,
                kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : Xps1.LastResortReuseLimit,
                kemSignature, bundleSignature);
            var unsigned = Create(new byte[64], new byte[64], new byte[64]);
            var xSignature = PublicKeyAuth.SignDetached(
                MessagingWireCryptographicInputs.GetX25519SignedPrekeySignatureInput(unsigned),
                Core.Identity.Device.PrivateKey);
            var kemSignature = PublicKeyAuth.SignDetached(
                MessagingWireCryptographicInputs.GetMlKemPrekeySignatureInput(unsigned),
                Core.Identity.Device.PrivateKey);
            var partial = Create(xSignature, kemSignature, new byte[64]);
            var bundleSignature = PublicKeyAuth.SignDetached(
                MessagingWireCryptographicInputs.GetPrekeyBundleSignatureInput(partial),
                Core.Identity.Device.PrivateKey);
            return Create(xSignature, kemSignature, bundleSignature);
        }
    }

    private sealed class FixedClock(OnionMonotonicReading reading) : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(reading);
        }
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }

    private static byte[] Id(int value)
    {
        var result = new byte[32];
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(28), value);
        return result;
    }

    private static byte[] Bytes(int length, byte seed)
    {
        var result = new byte[length];
        for (var index = 0; index < result.Length; index++) result[index] = (byte)(seed + (index % 17));
        return result;
    }

    private static int FieldHeaderOffset(byte[] encoded, ushort wanted)
    {
        var count = BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(8, 2));
        var offset = 12;
        for (var index = 0; index < count; index++)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(offset, 2));
            if (tag == wanted) return offset;
            offset += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(offset + 4, 4)));
        }
        throw new InvalidOperationException();
    }
}
