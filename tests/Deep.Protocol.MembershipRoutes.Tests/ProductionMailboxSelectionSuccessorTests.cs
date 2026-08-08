using System.Security.Cryptography;
using System.Reflection;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Sodium;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class ProductionMailboxSelectionSuccessorTests
{
    private const ulong Now = 1_800_000_000;

    [Fact]
    public void ForwardCheckpointPrimitivesAreNotPublicConsumerApis()
    {
        Assert.Null(typeof(ProductionMailboxAuthorityVerifier).GetMethod(
            "VerifyForwardCheckpoint", BindingFlags.Public | BindingFlags.Static));
        Assert.Null(typeof(ProductionMailboxTopologyVerifier).GetMethod(
            "VerifyForwardCheckpoint", BindingFlags.Public | BindingFlags.Static));
        Assert.Null(typeof(ProductionMailboxSelectionSuccessorVerifier).GetMethod(
            "VerifyOfflineCheckpoint", BindingFlags.Public | BindingFlags.Static));
        Assert.NotNull(typeof(ProductionMailboxSelectionSuccessorVerifier).GetMethod(
            "VerifyOfflineCheckpointClosure", BindingFlags.Public | BindingFlags.Static));
        Assert.Null(typeof(ProductionMailboxSelectionSuccessorVerifier).GetMethod(
            "VerifyOfflineCheckpointClosureCore", BindingFlags.Public | BindingFlags.Static));
        Assert.DoesNotContain(typeof(ProductionMailboxSelectionSuccessorVerifier).GetMethod(
                "VerifyOfflineCheckpointClosure", BindingFlags.Public | BindingFlags.Static)!
            .GetParameters(), parameter =>
                typeof(IProductionMailboxAuthoritySignatureVerifier).IsAssignableFrom(parameter.ParameterType) ||
                typeof(IProductionMailboxRevocationSnapshotSignatureVerifier).IsAssignableFrom(parameter.ParameterType) ||
                typeof(IProductionMailboxTopologySignatureVerifier).IsAssignableFrom(parameter.ParameterType) ||
                typeof(IProductionMailboxSelectionSuccessorSignatureVerifier).IsAssignableFrom(parameter.ParameterType));
        Assert.True(typeof(VerifiedProductionMailboxOfflineCheckpointClosure).IsSealed);
        Assert.Empty(typeof(VerifiedProductionMailboxOfflineCheckpointClosure)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.True(typeof(ProductionMailboxOfflineCheckpointCommitAnchor).IsSealed);
        Assert.Empty(typeof(ProductionMailboxOfflineCheckpointCommitAnchor)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public void DualClosureSuccessor_VerifiesExactOldNextAndNewCurrent()
    {
        var f = CreateFixture();
        var verified = Verify(f);
        Assert.Equal(f.Proof.OldEpoch, verified.OldSelection.Proof.Epoch);
        Assert.Equal(f.Proof.NewEpoch, verified.NewSelection.Proof.Epoch);
        Assert.Equal(f.Proof.OldCanonicalSelectionHash.ToArray(),
            verified.OldSelection.CanonicalSelectionHash.ToArray());
        Assert.Equal(f.Proof.NewCanonicalSelectionHash.ToArray(),
            verified.NewSelection.CanonicalSelectionHash.ToArray());
        Assert.Equal(
            verified.OldSelection.Replicas.Select(r => Convert.ToHexString(r.ReplicaId.Span)),
            verified.NewSelection.Replicas.Select(r => Convert.ToHexString(r.ReplicaId.Span)));
        Assert.NotEqual(f.Proof.OldCanonicalSelection.ToArray(), f.Proof.NewCanonicalSelection.ToArray());
    }

    [Fact]
    public void CompleteOfflineCheckpointOwnsExactClosureAndNextCommitAnchor()
    {
        var f = CreateFixture(
            mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 65, topologyAdvance: 10_000);
        var verified = VerifyComplete(f);

        Assert.Equal(ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            verified.Successor.Proof.Mode);
        Assert.Equal(ProductionMailboxAuthorityCodec.Encode(f.NewAuthority.Authority),
            verified.CanonicalNewAuthority.ToArray());
        Assert.Equal(f.NewRevocationSnapshot, verified.CanonicalNewRevocationSnapshot.ToArray());
        Assert.Equal(ProductionMailboxTopologyCodec.Encode(f.NewTopology.Snapshot),
            verified.CanonicalNewTopology.ToArray());
        Assert.Equal(f.Proof.OldCanonicalSelection.ToArray(),
            verified.CanonicalOldSelection.ToArray());
        Assert.Equal(f.Proof.NewCanonicalSelection.ToArray(),
            verified.CanonicalNewCurrentSelection.ToArray());
        Assert.Equal(f.NewNextSelection, verified.CanonicalNewNextSelection.ToArray());
        Assert.Equal(SHA256.HashData(verified.CanonicalTranscript.Span),
            verified.TranscriptSha256.ToArray());
        Assert.Equal(f.NewAuthority.Authority.AuthorityGeneration,
            verified.NextCommitAnchor.AuthorityGeneration);
        Assert.Equal(f.NewTopology.Snapshot.TopologyGeneration,
            verified.NextCommitAnchor.TopologyGeneration);
        Assert.Equal(Now, verified.NextCommitAnchor.VerifiedAtUnixSeconds);

        var authorityCopy = verified.CanonicalNewAuthority.ToArray();
        authorityCopy[0] ^= 0xff;
        var anchorCopy = verified.NextCommitAnchor.AuthorityHash.ToArray();
        anchorCopy[0] ^= 0xff;
        Assert.Equal(ProductionMailboxAuthorityCodec.Encode(f.NewAuthority.Authority),
            verified.CanonicalNewAuthority.ToArray());
        Assert.Equal(f.NewAuthority.CanonicalAuthorityHash.ToArray(),
            verified.NextCommitAnchor.AuthorityHash.ToArray());
    }

    [Fact]
    public void CompleteOfflineCheckpointBindsEveryOldLkgAndExactHistoricalSelection()
    {
        var f = CreateFixture(mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 65, topologyAdvance: 65);
        var context = CompleteContext(f);
        var mutations = new ProductionMailboxOfflineCheckpointClosureVerificationContext[]
        {
            context with { ExpectedNetworkId = Bytes(240, 16) },
            context with { PinnedMrXPublicKeySha256 = Bytes(241, 32) },
            context with { ExpectedOldAuthorityGeneration = context.ExpectedOldAuthorityGeneration + 1 },
            context with { ExpectedOldCanonicalAuthorityHash = Bytes(242, 32) },
            context with { ExpectedOldRevocationGeneration = context.ExpectedOldRevocationGeneration + 1 },
            context with { ExpectedOldRevocationHeadHash = Bytes(243, 32) },
            context with { ExpectedOldRevocationSnapshotHash = Bytes(244, 32) },
            context with { ExpectedOldTopologyGeneration = context.ExpectedOldTopologyGeneration + 1 },
            context with { ExpectedOldCanonicalTopologyHash = Bytes(245, 32) },
            context with { ExpectedOldCanonicalSelectionHash = Bytes(246, 32) },
            context with { ExpectedSelectionInputCommitment = Bytes(247, 32) }
        };
        foreach (var mutation in mutations)
            Assert.Throws<ProductionMailboxSelectionSuccessorException>(() =>
                VerifyComplete(f, context: mutation));

        var changedOld = f.Proof.OldCanonicalSelection.ToArray();
        changedOld[^1] ^= 1;
        AssertError(ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            () => VerifyComplete(f, oldSelection: changedOld));
    }

    [Fact]
    public void CompleteOfflineCheckpointRejectsSplitClosureAndCrossMode()
    {
        var f = CreateFixture(mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 65, topologyAdvance: 65);
        var changedAuthority = ProductionMailboxAuthorityCodec.Encode(f.NewAuthority.Authority);
        changedAuthority[^1] ^= 1;
        AssertError(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            () => VerifyComplete(f, authority: changedAuthority));
        var changedCurrent = f.Proof.NewCanonicalSelection.ToArray();
        changedCurrent[^1] ^= 1;
        AssertError(ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            () => VerifyComplete(f, currentSelection: changedCurrent));
        var changedRevocations = f.NewRevocationSnapshot.ToArray();
        changedRevocations[^1] ^= 1;
        AssertError(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            () => VerifyComplete(f, revocations: changedRevocations));
        var changedNext = f.NewNextSelection.ToArray();
        changedNext[^1] ^= 1;
        AssertError(ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            () => VerifyComplete(f, nextSelection: changedNext));

        var direct = CreateFixture();
        var offline = CreateFixture(mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 65, topologyAdvance: 65);
        AssertError(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
            () => VerifyComplete(direct, revocations: offline.NewRevocationSnapshot));
    }

    [Fact]
    public void CompleteOfflineCheckpointPreflightsAllInputsBeforeCallbacks()
    {
        var f = CreateFixture(mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 65, topologyAdvance: 65);
        var verifier = new CountingSignatureVerifier();
        var huge = new byte[8 * 1024 * 1024];
        AssertError(ProductionMailboxSelectionSuccessorError.InvalidLength, () =>
            ProductionMailboxSelectionSuccessorVerifier.VerifyOfflineCheckpointClosureCore(
                ProductionMailboxSelectionSuccessorCodec.Encode(f.Proof), huge,
                f.NewRevocationSnapshot, ProductionMailboxTopologyCodec.Encode(f.NewTopology.Snapshot),
                f.Proof.OldCanonicalSelection.Span, f.Proof.NewCanonicalSelection.Span,
                f.NewNextSelection, f.OldAuthority, f.OldTopology, CompleteContext(f),
                verifier, verifier, verifier, verifier));
        Assert.Equal(0, verifier.CallbackCount);

        var malformed = CompleteContext(f) with { ExpectedOldCanonicalAuthorityHash = huge };
        AssertError(ProductionMailboxSelectionSuccessorError.InvalidField,
            () => VerifyComplete(f, context: malformed));
        Assert.Equal(0, verifier.CallbackCount);
    }

    [Fact]
    public void CompleteOfflineCheckpointFreezesEveryInputBeforeFirstCallback()
    {
        var f = CreateFixture(mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 65, topologyAdvance: 65);
        var successor = ProductionMailboxSelectionSuccessorCodec.Encode(f.Proof);
        var authority = ProductionMailboxAuthorityCodec.Encode(f.NewAuthority.Authority);
        var revocations = f.NewRevocationSnapshot.ToArray();
        var topology = ProductionMailboxTopologyCodec.Encode(f.NewTopology.Snapshot);
        var oldSelection = f.Proof.OldCanonicalSelection.ToArray();
        var currentSelection = f.Proof.NewCanonicalSelection.ToArray();
        var nextSelection = f.NewNextSelection.ToArray();
        var expectedAuthority = authority.ToArray();
        var expectedTranscriptInputs = new[]
        {
            successor.ToArray(), authority.ToArray(), revocations.ToArray(), topology.ToArray(),
            oldSelection.ToArray(), currentSelection.ToArray(), nextSelection.ToArray()
        };
        var verifier = new MutatingAllSignatureVerifier(() =>
        {
            successor[0] ^= 1;
            authority[0] ^= 1;
            revocations[0] ^= 1;
            topology[0] ^= 1;
            oldSelection[0] ^= 1;
            currentSelection[0] ^= 1;
            nextSelection[0] ^= 1;
        });

        var verified = ProductionMailboxSelectionSuccessorVerifier
            .VerifyOfflineCheckpointClosureCore(
                successor, authority, revocations, topology, oldSelection, currentSelection,
                nextSelection, f.OldAuthority, f.OldTopology, CompleteContext(f),
                verifier, verifier, verifier, verifier);

        Assert.Equal(expectedAuthority, verified.CanonicalNewAuthority.ToArray());
        Assert.Equal(expectedTranscriptInputs[0], verified.CanonicalSuccessor.ToArray());
        Assert.Equal(expectedTranscriptInputs[2], verified.CanonicalNewRevocationSnapshot.ToArray());
        Assert.Equal(expectedTranscriptInputs[3], verified.CanonicalNewTopology.ToArray());
        Assert.Equal(expectedTranscriptInputs[4], verified.CanonicalOldSelection.ToArray());
        Assert.Equal(expectedTranscriptInputs[5], verified.CanonicalNewCurrentSelection.ToArray());
        Assert.Equal(expectedTranscriptInputs[6], verified.CanonicalNewNextSelection.ToArray());
    }

    [Fact]
    public void CompleteOfflineCheckpointRejectsEveryOversizedArtifactWithoutCallback()
    {
        var f = CreateFixture(mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 65, topologyAdvance: 65);
        var valid = new[]
        {
            ProductionMailboxSelectionSuccessorCodec.Encode(f.Proof),
            ProductionMailboxAuthorityCodec.Encode(f.NewAuthority.Authority),
            f.NewRevocationSnapshot,
            ProductionMailboxTopologyCodec.Encode(f.NewTopology.Snapshot),
            f.Proof.OldCanonicalSelection.ToArray(),
            f.Proof.NewCanonicalSelection.ToArray(),
            f.NewNextSelection
        };
        for (var field = 0; field < valid.Length; field++)
        {
            var fields = valid.Select(static value => value.ToArray()).ToArray();
            fields[field] = new byte[8 * 1024 * 1024];
            var verifier = new CountingSignatureVerifier();
            var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
            AssertError(ProductionMailboxSelectionSuccessorError.InvalidLength, () =>
                ProductionMailboxSelectionSuccessorVerifier.VerifyOfflineCheckpointClosureCore(
                    fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6],
                    f.OldAuthority, f.OldTopology, CompleteContext(f), verifier, verifier,
                    verifier, verifier));
            var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
            Assert.Equal(0, verifier.CallbackCount);
            Assert.True(allocated < 1024 * 1024,
                $"Oversized complete-closure field {field} allocated {allocated} bytes.");
        }
    }

    [Fact]
    public void CompleteOfflineCheckpointRejectsMalformedBoundedPmrAndPmtBeforeCopy()
    {
        var f = CreateFixture(mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 65, topologyAdvance: 65);
        var successor = ProductionMailboxSelectionSuccessorCodec.Encode(f.Proof);
        var authority = ProductionMailboxAuthorityCodec.Encode(f.NewAuthority.Authority);
        var topology = ProductionMailboxTopologyCodec.Encode(f.NewTopology.Snapshot);
        var oldSelection = f.Proof.OldCanonicalSelection.ToArray();
        var currentSelection = f.Proof.NewCanonicalSelection.ToArray();
        var nextSelection = f.NewNextSelection.ToArray();
        var malformedPmr = new byte[
            ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes];
        var malformedMaxPmt = new byte[
            ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes];
        var malformedNodeCount = topology.ToArray();
        malformedNodeCount[216] = 0;
        malformedNodeCount[217] = 0;
        var malformedEndpointLength = topology.ToArray();
        malformedEndpointLength[252] = 0;
        malformedEndpointLength[253] = 0;
        var cases = new (byte[] Pmr, byte[] Pmt)[]
        {
            (malformedPmr, topology),
            (f.NewRevocationSnapshot, malformedMaxPmt),
            (f.NewRevocationSnapshot, malformedNodeCount),
            (f.NewRevocationSnapshot, malformedEndpointLength),
            (f.NewRevocationSnapshot, topology[..^1]),
            (f.NewRevocationSnapshot, [.. topology, 0])
        };

        foreach (var item in cases)
        {
            var verifier = new CountingSignatureVerifier();
            var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
            AssertError(ProductionMailboxSelectionSuccessorError.InvalidLength, () =>
                ProductionMailboxSelectionSuccessorVerifier.VerifyOfflineCheckpointClosureCore(
                    successor, authority, item.Pmr, item.Pmt, oldSelection, currentSelection,
                    nextSelection, f.OldAuthority, f.OldTopology, CompleteContext(f), verifier,
                    verifier, verifier, verifier));
            var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
            Assert.Equal(0, verifier.CallbackCount);
            Assert.True(allocated < 1024 * 1024,
                $"Malformed bounded closure allocated {allocated} bytes before rejection.");
        }
    }

    [Fact]
    public void CompleteOfflineCheckpointTranscriptBindsVerificationPolicy()
    {
        var f = CreateFixture(mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 65, topologyAdvance: 65);
        var exact = VerifyComplete(f);
        var skewed = VerifyComplete(f, context: CompleteContext(f) with { ClockSkewSeconds = 1 });
        Assert.NotEqual(exact.CanonicalTranscript.ToArray(), skewed.CanonicalTranscript.ToArray());
        Assert.NotEqual(exact.TranscriptSha256.ToArray(), skewed.TranscriptSha256.ToArray());
    }

    [Fact]
    public void Codec_IsCanonicalBoundedAndUsesIndependentDualSignatureDomains()
    {
        var f = CreateFixture(sameIssuerKey: true);
        var encoded = ProductionMailboxSelectionSuccessorCodec.Encode(f.Proof);
        Assert.Equal(ProductionMailboxSelectionSuccessorConstants.FixedCoreLength +
            f.Proof.CanonicalNewAuthority.Length +
            f.Proof.OldCanonicalSelection.Length + f.Proof.NewCanonicalSelection.Length +
            ProductionMailboxSelectionSuccessorConstants.SignatureBytes, encoded.Length);
        Assert.Equal(encoded, ProductionMailboxSelectionSuccessorCodec.Encode(
            ProductionMailboxSelectionSuccessorCodec.Decode(encoded)));
        Assert.NotEqual(
            ProductionMailboxSelectionSuccessorCodec.GetOldIssuerSigningBytes(f.Proof),
            ProductionMailboxSelectionSuccessorCodec.GetNewIssuerSigningBytes(f.Proof));
        Assert.NotEqual(f.Proof.OldIssuerSignature.ToArray(), f.Proof.NewIssuerSignature.ToArray());
        _ = Verify(f);
        Assert.Equal("416368A12E6F617FDFCA9951D6BB7709B356A4350CF522ADC16BCA57D3B69B24",
            Convert.ToHexString(SHA256.HashData(encoded)));
        AssertError(ProductionMailboxSelectionSuccessorError.InvalidLength,
            () => ProductionMailboxSelectionSuccessorCodec.Decode(encoded[..^1]));
        AssertError(ProductionMailboxSelectionSuccessorError.InvalidLength,
            () => ProductionMailboxSelectionSuccessorCodec.Decode([.. encoded, 0]));
        var unsupportedMode = encoded.ToArray(); unsupportedMode[5] = 3;
        AssertError(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
            () => ProductionMailboxSelectionSuccessorCodec.Decode(unsupportedMode));
        var reserved = encoded.ToArray(); reserved[6] = 1;
        AssertError(ProductionMailboxSelectionSuccessorError.ReservedFieldNotZero,
            () => ProductionMailboxSelectionSuccessorCodec.Decode(reserved));
    }

    [Fact]
    public void PublicEntrypointsRejectOutOfBoundsBeforeSignatureCallbacks()
    {
        var f = CreateFixture();
        var verifier = new CountingSignatureVerifier();
        var undersized = new byte[
            ProductionMailboxSelectionSuccessorConstants.FixedCoreLength +
            ProductionMailboxSelectionSuccessorConstants.SignatureBytes - 1];
        var oversized = new byte[
            ProductionMailboxSelectionSuccessorConstants.MaximumArtifactBytes + 1];

        foreach (var invalid in new[] { undersized, oversized })
        {
            AssertError(ProductionMailboxSelectionSuccessorError.InvalidLength,
                () => ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(
                    invalid, f.OldAuthority, f.OldTopology, f.NewAuthority, f.NewTopology,
                    f.Context, verifier, verifier, verifier));
            AssertError(ProductionMailboxSelectionSuccessorError.InvalidLength,
                () => ProductionMailboxSelectionSuccessorVerifier.VerifyOfflineCheckpoint(
                    invalid, f.OldAuthority, f.OldTopology,
                    ProductionMailboxTopologyCodec.Encode(f.NewTopology.Snapshot), f.Context,
                    verifier, verifier, verifier));
        }

        var multiMegabyte = new byte[8 * 1024 * 1024];
        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        AssertError(ProductionMailboxSelectionSuccessorError.InvalidLength,
            () => ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(
                multiMegabyte, f.OldAuthority, f.OldTopology, f.NewAuthority, f.NewTopology,
                f.Context, verifier, verifier, verifier));
        var directAllocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
        Assert.True(directAllocated < 1024 * 1024,
            $"Direct verifier allocated {directAllocated} bytes for an oversized PSS1.");

        allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        AssertError(ProductionMailboxSelectionSuccessorError.InvalidLength,
            () => ProductionMailboxSelectionSuccessorVerifier.VerifyOfflineCheckpoint(
                multiMegabyte, f.OldAuthority, f.OldTopology,
                ProductionMailboxTopologyCodec.Encode(f.NewTopology.Snapshot), f.Context,
                verifier, verifier, verifier));
        var offlineAllocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
        Assert.True(offlineAllocated < 1024 * 1024,
            $"Offline verifier allocated {offlineAllocated} bytes for an oversized PSS1.");

        var valid = ProductionMailboxSelectionSuccessorCodec.Encode(f.Proof);
        var hugeContextField = new byte[8 * 1024 * 1024];
        var malformedContexts = new[]
        {
            f.Context with { ExpectedNetworkId = hugeContextField },
            f.Context with { ExpectedMailboxOwnerEd25519PublicKey = hugeContextField },
            f.Context with { ExpectedBlindedMailboxId = hugeContextField },
            f.Context with { ExpectedBlindedPlacementId = hugeContextField },
            f.Context with { PinnedMrXPublicKeySha256 = hugeContextField },
            f.Context with { ExpectedOldCanonicalSelectionHash = hugeContextField }
        };
        foreach (var malformedContext in malformedContexts)
        {
            allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
            AssertError(ProductionMailboxSelectionSuccessorError.InvalidField,
                () => ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(
                    valid, f.OldAuthority, f.OldTopology, f.NewAuthority, f.NewTopology,
                    malformedContext, verifier, verifier, verifier));
            var contextAllocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
            Assert.True(contextAllocated < 128 * 1024,
                $"Direct verifier allocated {contextAllocated} bytes for an oversized context field.");

            allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
            AssertError(ProductionMailboxSelectionSuccessorError.InvalidField,
                () => ProductionMailboxSelectionSuccessorVerifier.VerifyOfflineCheckpoint(
                    valid, f.OldAuthority, f.OldTopology,
                    ProductionMailboxTopologyCodec.Encode(f.NewTopology.Snapshot),
                    malformedContext, verifier, verifier, verifier));
            contextAllocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
            Assert.True(contextAllocated < 128 * 1024,
                $"Offline verifier allocated {contextAllocated} bytes for an oversized context field.");
        }

        Assert.Equal(0, verifier.CallbackCount);
    }

    [Fact]
    public void Verifier_RejectsTamperWrongContextForkAndRollback()
    {
        var f = CreateFixture();
        var encoded = ProductionMailboxSelectionSuccessorCodec.Encode(f.Proof);
        foreach (var offset in new[] { 8, 24, 40, 72, 104, 136, 168, 200, 232, 240, 272, 280,
            312, 344, 376, 384, 400, encoded.Length - 128, encoded.Length - 1 })
        {
            var changed = encoded.ToArray(); changed[offset] ^= 1;
            Assert.ThrowsAny<Exception>(() => Verify(f, changed));
        }
        AssertError(ProductionMailboxSelectionSuccessorError.NetworkMismatch,
            () => Verify(f, context: f.Context with { ExpectedNetworkId = Bytes(240, 16) }));
        AssertError(ProductionMailboxSelectionSuccessorError.OwnerMismatch,
            () => Verify(f, context: f.Context with
            { ExpectedMailboxOwnerEd25519PublicKey = Bytes(241, 32) }));
        AssertError(ProductionMailboxSelectionSuccessorError.RouteMismatch,
            () => Verify(f, context: f.Context with { ExpectedBlindedMailboxId = Bytes(242, 32) }));
        AssertError(ProductionMailboxSelectionSuccessorError.RouteMismatch,
            () => Verify(f, context: f.Context with { ExpectedBlindedPlacementId = Bytes(243, 32) }));
        AssertError(ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            () => Verify(f, context: f.Context with
            { ExpectedOldCanonicalSelectionHash = Bytes(244, 32) }));
        AssertError(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            () => ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(encoded,
                f.OldAuthority, f.OldTopology, f.OldAuthority, f.NewTopology, f.Context,
                new SodiumProductionMailboxAuthoritySignatureVerifier(),
                new SodiumProductionMailboxTopologySignatureVerifier(),
                new SodiumProductionMailboxSelectionSuccessorSignatureVerifier()));
        AssertError(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
            () => ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(encoded,
                f.OldAuthority, f.OldTopology, f.NewAuthority, f.OldTopology, f.Context,
                new SodiumProductionMailboxAuthoritySignatureVerifier(),
                new SodiumProductionMailboxTopologySignatureVerifier(),
                new SodiumProductionMailboxSelectionSuccessorSignatureVerifier()));
    }

    [Fact]
    public void Verifier_RejectsExpiredInvalidSignaturesAndMutableCallerRaces()
    {
        var f = CreateFixture();
        AssertError(ProductionMailboxSelectionSuccessorError.Expired,
            () => Verify(f, context: f.Context with { NowUnixSeconds = f.Proof.ExpiresAtUnixSeconds + 1 }));
        var oldBad = f.Proof with { OldIssuerSignature = Bytes(244, 64) };
        AssertError(ProductionMailboxSelectionSuccessorError.InvalidOldIssuerSignature,
            () => Verify(f, ProductionMailboxSelectionSuccessorCodec.Encode(oldBad)));
        var newBad = f.Proof with { NewIssuerSignature = Bytes(245, 64) };
        AssertError(ProductionMailboxSelectionSuccessorError.InvalidNewIssuerSignature,
            () => Verify(f, ProductionMailboxSelectionSuccessorCodec.Encode(newBad)));

        var mutable = ProductionMailboxSelectionSuccessorCodec.Encode(f.Proof);
        var verified = ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(mutable,
            f.OldAuthority, f.OldTopology, f.NewAuthority, f.NewTopology, f.Context,
            new SodiumProductionMailboxAuthoritySignatureVerifier(),
            new SodiumProductionMailboxTopologySignatureVerifier(),
            new MutatingVerifier(() => mutable[40] ^= 1));
        var exposed = verified.Proof.MailboxOwnerEd25519PublicKey.ToArray(); exposed[0] ^= 1;
        Assert.NotEqual(exposed, verified.Proof.MailboxOwnerEd25519PublicKey.ToArray());

        var mutableOwner = f.Context.ExpectedMailboxOwnerEd25519PublicKey.ToArray();
        var mutableContext = f.Context with
        {
            ExpectedMailboxOwnerEd25519PublicKey = mutableOwner
        };
        var contextVerified = ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(
            ProductionMailboxSelectionSuccessorCodec.Encode(f.Proof),
            f.OldAuthority, f.OldTopology, f.NewAuthority, f.NewTopology, mutableContext,
            new MutatingAuthorityVerifier(() => mutableOwner[0] ^= 1),
            new SodiumProductionMailboxTopologySignatureVerifier(),
            new SodiumProductionMailboxSelectionSuccessorSignatureVerifier());
        Assert.Equal(f.Proof.MailboxOwnerEd25519PublicKey.ToArray(),
            contextVerified.Proof.MailboxOwnerEd25519PublicKey.ToArray());
    }

    [Fact]
    public async Task SplitEntrypointsUseOneSnapshotAcrossConcurrentModeReplacement()
    {
        var direct = CreateFixture();
        var offline = CreateFixture(
            mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 2,
            topologyAdvance: 2);
        var directBytes = ProductionMailboxSelectionSuccessorCodec.Encode(direct.Proof);
        var offlineBytes = ProductionMailboxSelectionSuccessorCodec.Encode(offline.Proof);
        Assert.Equal(directBytes.Length, offlineBytes.Length);
        var shared = directBytes.ToArray();
        using var cancellation = new CancellationTokenSource();
        var swapper = Task.Run(() =>
        {
            while (!cancellation.IsCancellationRequested)
            {
                Buffer.BlockCopy(offlineBytes, 0, shared, 0, shared.Length);
                Buffer.BlockCopy(directBytes, 0, shared, 0, shared.Length);
            }
        });
        var offlineBypasses = 0;
        for (var attempt = 0; attempt < 5_000; attempt++)
        {
            try
            {
                var verified = ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(
                    shared, offline.OldAuthority, offline.OldTopology,
                    offline.NewAuthority, offline.NewTopology, offline.Context,
                    new SodiumProductionMailboxAuthoritySignatureVerifier(),
                    new SodiumProductionMailboxTopologySignatureVerifier(),
                    new SodiumProductionMailboxSelectionSuccessorSignatureVerifier());
                if (verified.Proof.Mode ==
                    ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint)
                    Interlocked.Increment(ref offlineBypasses);
            }
            catch (ProductionMailboxSelectionSuccessorException)
            {
                // A torn or wrong-mode attacker snapshot must fail closed.
            }
            catch (ProductionMailboxAuthorityException) { }
            catch (ProductionMailboxTopologyException) { }
        }
        cancellation.Cancel();
        await swapper.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, offlineBypasses);

        var callbackSource = directBytes.ToArray();
        var callbackVerified = ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(
            callbackSource, direct.OldAuthority, direct.OldTopology,
            direct.NewAuthority, direct.NewTopology, direct.Context,
            new MutatingAuthorityVerifier(() => callbackSource[5] =
                (byte)ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint),
            new SodiumProductionMailboxTopologySignatureVerifier(),
            new SodiumProductionMailboxSelectionSuccessorSignatureVerifier());
        Assert.Equal(ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            (ProductionMailboxSelectionSuccessorMode)callbackSource[5]);
        Assert.Equal(ProductionMailboxSelectionSuccessorMode.DirectPromotion,
            callbackVerified.Proof.Mode);
    }

    [Fact]
    public void Verifier_RejectsIssuerSignedReplicaEndpointFork()
    {
        var f = CreateFixture();
        var selectedId = ProductionMailboxTopologyCodec.DecodeSelection(
            f.Proof.NewCanonicalSelection.Span).Replicas[0].ReplicaId;
        var forkValue = f.NewTopology.Snapshot with
        {
            CurrentEpoch = f.NewTopology.Snapshot.CurrentEpoch with
            {
                Nodes = f.NewTopology.Snapshot.CurrentEpoch.Nodes.Select(node =>
                    node.NodeId.Span.SequenceEqual(selectedId.Span)
                        ? node with { HttpsEndpoint = "https://forked-route.example.net/" }
                        : node).ToArray()
            },
            IssuerSignature = new byte[64]
        };
        forkValue = SignTopology(forkValue, f.NewIssuerPrivateKey);
        var forkTopology = ProductionMailboxTopologyVerifier.Verify(
            ProductionMailboxTopologyCodec.Encode(forkValue), f.NewAuthority,
            new ProductionMailboxTopologyVerificationContext
            {
                LastCommittedTopologyGeneration = f.OldTopology.Snapshot.TopologyGeneration,
                LastCommittedTopologyHash = f.OldTopology.CanonicalTopologyHash,
                NowUnixSeconds = Now,
                ClockSkewSeconds = 0
            }, new SodiumProductionMailboxTopologySignatureVerifier());
        var forkSelection = Selection(f.NewAuthority, forkTopology, forkValue.CurrentEpoch,
            f.PromotedDescriptors, f.Placement, f.NewIssuerPrivateKey, Now - 5, Now + 200);
        var forkSelectionBytes = ProductionMailboxTopologyCodec.EncodeSelection(forkSelection);
        var forkProof = f.Proof with
        {
            NewCanonicalTopologyHash = forkTopology.CanonicalTopologyHash,
            NewCanonicalSelectionHash = SHA256.HashData(forkSelectionBytes),
            NewCanonicalSelection = forkSelectionBytes,
            OldIssuerSignature = new byte[64],
            NewIssuerSignature = new byte[64]
        };
        forkProof = SignSuccessor(forkProof, f.OldIssuerPrivateKey, f.NewIssuerPrivateKey);
        AssertError(ProductionMailboxSelectionSuccessorError.ReplicaRouteMismatch, () =>
            ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(
                ProductionMailboxSelectionSuccessorCodec.Encode(forkProof),
                f.OldAuthority, f.OldTopology, f.NewAuthority, forkTopology, f.Context,
                new SodiumProductionMailboxAuthoritySignatureVerifier(),
                new SodiumProductionMailboxTopologySignatureVerifier(),
                new SodiumProductionMailboxSelectionSuccessorSignatureVerifier()));

        var oldNodes = f.OldTopology.Snapshot.NextEpoch.Nodes.ToDictionary(
            node => Convert.ToHexString(node.NodeId.Span), StringComparer.Ordinal);
        var abbaValue = f.NewTopology.Snapshot with
        {
            CurrentEpoch = f.NewTopology.Snapshot.CurrentEpoch with
            {
                Nodes = f.NewTopology.Snapshot.CurrentEpoch.Nodes.Select(node =>
                {
                    var oldNode = oldNodes[Convert.ToHexString(node.NodeId.Span)];
                    return node with
                    {
                        CurrentSpkiSha256 = oldNode.NextSpkiSha256,
                        NextSpkiSha256 = oldNode.CurrentSpkiSha256
                    };
                }).ToArray()
            },
            IssuerSignature = new byte[64]
        };
        abbaValue = SignTopology(abbaValue, f.NewIssuerPrivateKey);
        var abbaTopology = ProductionMailboxTopologyVerifier.Verify(
            ProductionMailboxTopologyCodec.Encode(abbaValue), f.NewAuthority,
            new ProductionMailboxTopologyVerificationContext
            {
                LastCommittedTopologyGeneration = f.OldTopology.Snapshot.TopologyGeneration,
                LastCommittedTopologyHash = f.OldTopology.CanonicalTopologyHash,
                NowUnixSeconds = Now,
                ClockSkewSeconds = 0
            }, new SodiumProductionMailboxTopologySignatureVerifier());
        var abbaSelection = Selection(f.NewAuthority, abbaTopology, abbaValue.CurrentEpoch,
            f.PromotedDescriptors, f.Placement, f.NewIssuerPrivateKey, Now - 5, Now + 200);
        var abbaSelectionBytes = ProductionMailboxTopologyCodec.EncodeSelection(abbaSelection);
        var abbaProof = SignSuccessor(f.Proof with
        {
            NewCanonicalTopologyHash = abbaTopology.CanonicalTopologyHash,
            NewCanonicalSelectionHash = SHA256.HashData(abbaSelectionBytes),
            NewCanonicalSelection = abbaSelectionBytes,
            OldIssuerSignature = new byte[64],
            NewIssuerSignature = new byte[64]
        }, f.OldIssuerPrivateKey, f.NewIssuerPrivateKey);
        AssertError(ProductionMailboxSelectionSuccessorError.ReplicaRouteMismatch, () =>
            ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(
                ProductionMailboxSelectionSuccessorCodec.Encode(abbaProof),
                f.OldAuthority, f.OldTopology, f.NewAuthority, abbaTopology, f.Context,
                new SodiumProductionMailboxAuthoritySignatureVerifier(),
                new SodiumProductionMailboxTopologySignatureVerifier(),
                new SodiumProductionMailboxSelectionSuccessorSignatureVerifier()));
    }

    [Fact]
    public void DirectPromotion_AcceptsOldNextPinPromotionAndRejectsUnrelatedPins()
    {
        _ = Verify(CreateFixture(promoteSpkiPins: true));

        var f = CreateFixture();
        var forkValue = f.NewTopology.Snapshot with
        {
            CurrentEpoch = f.NewTopology.Snapshot.CurrentEpoch with
            {
                Nodes = f.NewTopology.Snapshot.CurrentEpoch.Nodes.Select((node, i) => node with
                {
                    CurrentSpkiSha256 = Bytes((byte)(230 + i * 2), 32),
                    NextSpkiSha256 = Bytes((byte)(231 + i * 2), 32)
                }).ToArray()
            },
            IssuerSignature = new byte[64]
        };
        forkValue = SignTopology(forkValue, f.NewIssuerPrivateKey);
        var forkTopology = ProductionMailboxTopologyVerifier.Verify(
            ProductionMailboxTopologyCodec.Encode(forkValue), f.NewAuthority,
            new ProductionMailboxTopologyVerificationContext
            {
                LastCommittedTopologyGeneration = f.OldTopology.Snapshot.TopologyGeneration,
                LastCommittedTopologyHash = f.OldTopology.CanonicalTopologyHash,
                NowUnixSeconds = Now,
                ClockSkewSeconds = 0
            }, new SodiumProductionMailboxTopologySignatureVerifier());
        var forkSelection = Selection(f.NewAuthority, forkTopology, forkValue.CurrentEpoch,
            f.PromotedDescriptors, f.Placement, f.NewIssuerPrivateKey, Now - 5, Now + 200);
        var forkSelectionBytes = ProductionMailboxTopologyCodec.EncodeSelection(forkSelection);
        var forkProof = SignSuccessor(f.Proof with
        {
            NewCanonicalTopologyHash = forkTopology.CanonicalTopologyHash,
            NewCanonicalSelectionHash = SHA256.HashData(forkSelectionBytes),
            NewCanonicalSelection = forkSelectionBytes,
            OldIssuerSignature = new byte[64],
            NewIssuerSignature = new byte[64]
        }, f.OldIssuerPrivateKey, f.NewIssuerPrivateKey);
        AssertError(ProductionMailboxSelectionSuccessorError.ReplicaRouteMismatch, () =>
            ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(
                ProductionMailboxSelectionSuccessorCodec.Encode(forkProof),
                f.OldAuthority, f.OldTopology, f.NewAuthority, forkTopology, f.Context,
                new SodiumProductionMailboxAuthoritySignatureVerifier(),
                new SodiumProductionMailboxTopologySignatureVerifier(),
                new SodiumProductionMailboxSelectionSuccessorSignatureVerifier()));
    }

    [Fact]
    public void DirectPromotionRejectsMaxMinusOneToTerminalRevocationAndTopology()
    {
        var f = CreateFixture();
        var encoded = ProductionMailboxSelectionSuccessorCodec.Encode(f.Proof);

        var oldTerminalRevocationAuthority = SignAuthority(f.OldAuthority.Authority with
        {
            Revocation = f.OldAuthority.Authority.Revocation with
            { Generation = ulong.MaxValue - 1 }
        }, f.MrXPrivateKey);
        var newTerminalRevocationAuthority = SignAuthority(f.NewAuthority.Authority with
        {
            Revocation = f.NewAuthority.Authority.Revocation with
            { Generation = ulong.MaxValue }
        }, f.MrXPrivateKey);
        var forgedOldAuthority = new VerifiedProductionMailboxAuthority(
            oldTerminalRevocationAuthority,
            SHA256.HashData(ProductionMailboxAuthorityCodec.Encode(oldTerminalRevocationAuthority)),
            oldTerminalRevocationAuthority.AuthorityGeneration);
        var forgedNewAuthority = new VerifiedProductionMailboxAuthority(
            newTerminalRevocationAuthority,
            SHA256.HashData(ProductionMailboxAuthorityCodec.Encode(newTerminalRevocationAuthority)),
            newTerminalRevocationAuthority.AuthorityGeneration);
        AssertError(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            () => ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(
                encoded, forgedOldAuthority, f.OldTopology, forgedNewAuthority, f.NewTopology,
                f.Context, new SodiumProductionMailboxAuthoritySignatureVerifier(),
                new SodiumProductionMailboxTopologySignatureVerifier(),
                new SodiumProductionMailboxSelectionSuccessorSignatureVerifier()));

        var oldTerminalTopology = SignTopology(f.OldTopology.Snapshot with
        { TopologyGeneration = ulong.MaxValue - 1 }, f.OldIssuerPrivateKey);
        var oldTerminalTopologyBytes = ProductionMailboxTopologyCodec.Encode(oldTerminalTopology);
        var newTerminalTopology = SignTopology(f.NewTopology.Snapshot with
        {
            TopologyGeneration = ulong.MaxValue,
            PreviousTopologyHash = SHA256.HashData(oldTerminalTopologyBytes)
        }, f.NewIssuerPrivateKey);
        var forgedOldTopology = new VerifiedProductionMailboxTopology(
            oldTerminalTopology, SHA256.HashData(oldTerminalTopologyBytes));
        var forgedNewTopology = new VerifiedProductionMailboxTopology(newTerminalTopology,
            SHA256.HashData(ProductionMailboxTopologyCodec.Encode(newTerminalTopology)));
        AssertError(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
            () => ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(
                encoded, f.OldAuthority, forgedOldTopology, f.NewAuthority, forgedNewTopology,
                f.Context, new SodiumProductionMailboxAuthoritySignatureVerifier(),
                new SodiumProductionMailboxTopologySignatureVerifier(),
                new SodiumProductionMailboxSelectionSuccessorSignatureVerifier()));
    }

    [Fact]
    public void OfflineCheckpoint_AcceptsExact365DayAndLargeGenerationDelta()
    {
        var f = CreateFixture(
            mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 10_000,
            topologyAdvance: 10_000,
            oldAnchorAgeSeconds:
                ProductionMailboxSelectionSuccessorConstants.MaximumOfflineCheckpointAgeSeconds);
        var verified = Verify(f);
        Assert.Equal(ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            verified.Proof.Mode);
        Assert.All(verified.Proof.OldIssuerSignature.ToArray(), value => Assert.Equal(0, value));
        Assert.Equal(f.Proof.NewCanonicalAuthorityHash.ToArray(),
            SHA256.HashData(f.Proof.CanonicalNewAuthority.Span));
    }

    [Fact]
    public void OfflineCheckpoint_RejectsExpiredAnchorDowngradeCrossOwnerAndCrossNetwork()
    {
        var expired = CreateFixture(
            mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 2,
            topologyAdvance: 2,
            oldAnchorAgeSeconds:
                ProductionMailboxSelectionSuccessorConstants.MaximumOfflineCheckpointAgeSeconds + 1);
        AssertError(ProductionMailboxSelectionSuccessorError.CheckpointAnchorExpired,
            () => Verify(expired));

        var downgrade = CreateFixture(
            mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 1,
            topologyAdvance: 1);
        AssertError(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
            () => Verify(downgrade));

        var f = CreateFixture(
            mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 2,
            topologyAdvance: 2);
        AssertError(ProductionMailboxSelectionSuccessorError.OwnerMismatch,
            () => Verify(f, context: f.Context with
            { ExpectedMailboxOwnerEd25519PublicKey = Bytes(247, 32) }));
        AssertError(ProductionMailboxSelectionSuccessorError.NetworkMismatch,
            () => Verify(f, context: f.Context with { ExpectedNetworkId = Bytes(248, 16) }));
    }

    [Fact]
    public void OfflineCheckpoint_Accepts65GenerationsButRejectsInvalidRootAndTerminalState()
    {
        var f = CreateFixture(
            mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 65,
            topologyAdvance: 65);
        _ = Verify(f);

        var invalidRootAuthority = f.NewAuthority.Authority with
        { Signature = Bytes(249, 64) };
        var invalidRootBytes = ProductionMailboxAuthorityCodec.Encode(invalidRootAuthority);
        var invalidRootProof = SignSuccessor(f.Proof with
        {
            CanonicalNewAuthority = invalidRootBytes,
            NewCanonicalAuthorityHash = SHA256.HashData(invalidRootBytes),
            OldIssuerSignature = new byte[64],
            NewIssuerSignature = new byte[64]
        }, f.OldIssuerPrivateKey, f.NewIssuerPrivateKey);
        AssertError(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            () => Verify(f, ProductionMailboxSelectionSuccessorCodec.Encode(invalidRootProof)));

        var checkpointContext = new ProductionMailboxAuthorityCheckpointVerificationContext
        {
            PinnedMrXPublicKeySha256 = f.Context.PinnedMrXPublicKeySha256,
            ExpectedNetworkId = f.Context.ExpectedNetworkId,
            LastCommittedGeneration = f.OldAuthority.Authority.AuthorityGeneration,
            LastCommittedRevocationGeneration =
                f.OldAuthority.Authority.Revocation.Generation,
            LastCommittedRevocationHeadHash = f.OldAuthority.Authority.Revocation.HeadHash,
            LastCommittedRevocationSnapshotHash =
                f.OldAuthority.Authority.Revocation.SnapshotHash,
            NowUnixSeconds = Now,
            ClockSkewSeconds = 0
        };
        var terminalAuthority = SignAuthority(f.NewAuthority.Authority with
        { AuthorityGeneration = ulong.MaxValue, Signature = new byte[64] }, f.MrXPrivateKey);
        Assert.Equal(ProductionMailboxAuthorityError.AuthorityRollback,
            Assert.Throws<ProductionMailboxAuthorityException>(() =>
                ProductionMailboxAuthorityVerifier.VerifyForwardCheckpoint(
                    ProductionMailboxAuthorityCodec.Encode(terminalAuthority), checkpointContext,
                    new SodiumProductionMailboxAuthoritySignatureVerifier())).Error);
        var terminalRevocation = SignAuthority(f.NewAuthority.Authority with
        {
            Revocation = f.NewAuthority.Authority.Revocation with
            { Generation = ulong.MaxValue },
            Signature = new byte[64]
        }, f.MrXPrivateKey);
        Assert.Equal(ProductionMailboxAuthorityError.AuthorityRollback,
            Assert.Throws<ProductionMailboxAuthorityException>(() =>
                ProductionMailboxAuthorityVerifier.VerifyForwardCheckpoint(
                    ProductionMailboxAuthorityCodec.Encode(terminalRevocation), checkpointContext,
                    new SodiumProductionMailboxAuthoritySignatureVerifier())).Error);
        var terminalTopology = SignTopology(f.NewTopology.Snapshot with
        { TopologyGeneration = ulong.MaxValue, IssuerSignature = new byte[64] },
            f.NewIssuerPrivateKey);
        Assert.Equal(ProductionMailboxTopologyError.TopologyRollback,
            Assert.Throws<ProductionMailboxTopologyException>(() =>
                ProductionMailboxTopologyVerifier.VerifyForwardCheckpoint(
                    ProductionMailboxTopologyCodec.Encode(terminalTopology), f.NewAuthority,
                    new ProductionMailboxTopologyCheckpointVerificationContext
                    {
                        LastCommittedTopologyGeneration =
                            f.OldTopology.Snapshot.TopologyGeneration,
                        NowUnixSeconds = Now,
                        ClockSkewSeconds = 0
                    }, new SodiumProductionMailboxTopologySignatureVerifier())).Error);
    }

    [Fact]
    public void OfflineCheckpoint_RejectsReplicaSubstitutionAndNonCanonicalSignatureSlots()
    {
        var f = CreateFixture(
            mode: ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            authorityAdvance: 2,
            topologyAdvance: 2);
        var decoded = ProductionMailboxTopologyCodec.DecodeSelection(
            f.Proof.NewCanonicalSelection.Span);
        var substituted = decoded with
        {
            Replicas = decoded.Replicas.Reverse().ToArray(),
            IssuerSignature = new byte[64]
        };
        substituted = SignSelection(substituted, f.NewIssuerPrivateKey);
        var substitutedBytes = ProductionMailboxTopologyCodec.EncodeSelection(substituted);
        var substitutedProof = SignSuccessor(f.Proof with
        {
            NewCanonicalSelection = substitutedBytes,
            NewCanonicalSelectionHash = SHA256.HashData(substitutedBytes),
            OldIssuerSignature = new byte[64],
            NewIssuerSignature = new byte[64]
        }, f.OldIssuerPrivateKey, f.NewIssuerPrivateKey);
        Assert.ThrowsAny<Exception>(() =>
            Verify(f, ProductionMailboxSelectionSuccessorCodec.Encode(substitutedProof)));

        var illegalOldSignature = f.Proof with { OldIssuerSignature = Bytes(250, 64) };
        AssertError(ProductionMailboxSelectionSuccessorError.InvalidField,
            () => ProductionMailboxSelectionSuccessorCodec.Encode(illegalOldSignature));

        var encoded = ProductionMailboxSelectionSuccessorCodec.Encode(f.Proof);
        for (var i = 0; i < encoded.Length; i += Math.Max(1, encoded.Length / 47))
        {
            var tampered = encoded.ToArray();
            tampered[i] ^= 0x80;
            Assert.ThrowsAny<Exception>(() => Verify(f, tampered));
        }
    }

    private static VerifiedProductionMailboxSelectionSuccessor Verify(
        Fixture f,
        byte[]? encoded = null,
        ProductionMailboxSelectionSuccessorVerificationContext? context = null)
    {
        var bytes = encoded ?? ProductionMailboxSelectionSuccessorCodec.Encode(f.Proof);
        var frozenContext = context ?? f.Context;
        return f.Proof.Mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion
            ? ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(
                bytes, f.OldAuthority, f.OldTopology, f.NewAuthority, f.NewTopology,
                frozenContext, new SodiumProductionMailboxAuthoritySignatureVerifier(),
                new SodiumProductionMailboxTopologySignatureVerifier(),
                new SodiumProductionMailboxSelectionSuccessorSignatureVerifier())
            : ProductionMailboxSelectionSuccessorVerifier.VerifyOfflineCheckpoint(
                bytes, f.OldAuthority, f.OldTopology,
                ProductionMailboxTopologyCodec.Encode(f.NewTopology.Snapshot), frozenContext,
                new SodiumProductionMailboxAuthoritySignatureVerifier(),
                new SodiumProductionMailboxTopologySignatureVerifier(),
                new SodiumProductionMailboxSelectionSuccessorSignatureVerifier());
    }

    private static VerifiedProductionMailboxOfflineCheckpointClosure VerifyComplete(
        Fixture f,
        byte[]? successor = null,
        byte[]? authority = null,
        byte[]? revocations = null,
        byte[]? topology = null,
        byte[]? oldSelection = null,
        byte[]? currentSelection = null,
        byte[]? nextSelection = null,
        ProductionMailboxOfflineCheckpointClosureVerificationContext? context = null)
        => ProductionMailboxSelectionSuccessorVerifier.VerifyOfflineCheckpointClosure(
            successor ?? ProductionMailboxSelectionSuccessorCodec.Encode(f.Proof),
            authority ?? ProductionMailboxAuthorityCodec.Encode(f.NewAuthority.Authority),
            revocations ?? f.NewRevocationSnapshot,
            topology ?? ProductionMailboxTopologyCodec.Encode(f.NewTopology.Snapshot),
            oldSelection ?? f.Proof.OldCanonicalSelection.ToArray(),
            currentSelection ?? f.Proof.NewCanonicalSelection.ToArray(),
            nextSelection ?? f.NewNextSelection,
            f.OldAuthority,
            f.OldTopology,
            context ?? CompleteContext(f));

    private static ProductionMailboxOfflineCheckpointClosureVerificationContext CompleteContext(
        Fixture f)
    {
        var authority = f.OldAuthority.Authority;
        var topology = f.OldTopology.Snapshot;
        return new ProductionMailboxOfflineCheckpointClosureVerificationContext
        {
            ExpectedNetworkId = f.Context.ExpectedNetworkId,
            ExpectedMailboxOwnerEd25519PublicKey =
                f.Context.ExpectedMailboxOwnerEd25519PublicKey,
            ExpectedBlindedMailboxId = f.Context.ExpectedBlindedMailboxId,
            ExpectedBlindedPlacementId = f.Context.ExpectedBlindedPlacementId,
            ExpectedSelectionInputCommitment = f.Proof.SelectionInputCommitment,
            PinnedMrXPublicKeySha256 = f.Context.PinnedMrXPublicKeySha256,
            ExpectedOldAuthorityGeneration = authority.AuthorityGeneration,
            ExpectedOldCanonicalAuthorityHash = f.OldAuthority.CanonicalAuthorityHash,
            ExpectedOldRevocationGeneration = authority.Revocation.Generation,
            ExpectedOldRevocationHeadHash = authority.Revocation.HeadHash,
            ExpectedOldRevocationSnapshotHash = authority.Revocation.SnapshotHash,
            ExpectedOldTopologyGeneration = topology.TopologyGeneration,
            ExpectedOldCanonicalTopologyHash = f.OldTopology.CanonicalTopologyHash,
            ExpectedOldCanonicalSelectionHash = f.Proof.OldCanonicalSelectionHash,
            VerifiedAtUnixSeconds = Now,
            ClockSkewSeconds = 0
        };
    }

    private static Fixture CreateFixture(
        bool sameIssuerKey = false,
        ProductionMailboxSelectionSuccessorMode mode =
            ProductionMailboxSelectionSuccessorMode.DirectPromotion,
        ulong authorityAdvance = 1,
        ulong topologyAdvance = 1,
        ulong oldAnchorAgeSeconds = 5,
        bool promoteSpkiPins = false)
    {
        var oldNow = Now - oldAnchorAgeSeconds;
        var oldIssuer = PublicKeyAuth.GenerateKeyPair(Bytes(30, 32));
        var newIssuer = sameIssuerKey ? oldIssuer : PublicKeyAuth.GenerateKeyPair(Bytes(31, 32));
        var mrX = PublicKeyAuth.GenerateKeyPair(Bytes(60, 32));
        var owner = PublicKeyAuth.GenerateKeyPair(Bytes(90, 32));
        var oldCurrentDescriptors = Descriptors(0x10, 9, oldNow - 200, oldNow + 100);
        var promotedDescriptors = Descriptors(0x30, 10, oldNow - 50, oldNow + 500);
        var checkpointCurrentDescriptors = Descriptors(0x31, 20, Now - 50, Now + 500);
        var directNextDescriptors = Descriptors(0x50, 11, Now + 400, Now + 900);
        var checkpointNextDescriptors = Descriptors(0x11, 21, Now - 50, Now + 900);
        var oldCurrentEpoch = AuthorityEpoch(9, 70,
            MembershipRouteDescriptorCodec.ComputeRoot(oldCurrentDescriptors), Bytes(8, 32),
            oldNow - 200, oldNow + 100);
        var promotedEpoch = AuthorityEpoch(10, 71,
            MembershipRouteDescriptorCodec.ComputeRoot(promotedDescriptors), Bytes(10, 32),
            oldNow - 50, oldNow + 500);
        var checkpointCurrentEpoch = AuthorityEpoch(20, 81,
            MembershipRouteDescriptorCodec.ComputeRoot(checkpointCurrentDescriptors), Bytes(22, 32),
            Now - 50, Now + 500);
        var directNextEpoch = AuthorityEpoch(11, 72,
            MembershipRouteDescriptorCodec.ComputeRoot(directNextDescriptors), Bytes(12, 32),
            Now + 400, Now + 900);
        var checkpointNextEpoch = AuthorityEpoch(21, 82,
            MembershipRouteDescriptorCodec.ComputeRoot(checkpointNextDescriptors), Bytes(24, 32),
            Now - 40, Now + 900);
        var newCurrentEpoch = mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion
            ? promotedEpoch : checkpointCurrentEpoch;
        var newCurrentDescriptors = mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion
            ? promotedDescriptors : checkpointCurrentDescriptors;
        var newNextEpoch = mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion
            ? directNextEpoch : checkpointNextEpoch;
        var newNextDescriptors = mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion
            ? directNextDescriptors : checkpointNextDescriptors;

        var oldAuthorityValue = Authority(oldIssuer.PublicKey, mrX.PublicKey,
            generation: 7, previousHash: Bytes(2, 32), oldCurrentEpoch, promotedEpoch, oldNow);
        oldAuthorityValue = SignAuthority(oldAuthorityValue, mrX.PrivateKey);
        var oldAuthority = ProductionMailboxAuthorityVerifier.Verify(oldAuthorityValue,
            AuthorityContext(oldAuthorityValue, mrX.PublicKey, lastGeneration: 6,
                lastAuthorityHash: oldAuthorityValue.PreviousAuthorityHash, now: oldNow),
            new SodiumProductionMailboxAuthoritySignatureVerifier());
        var oldAuthorityHash = oldAuthority.CanonicalAuthorityHash.ToArray();

        var newAuthorityValue = Authority(newIssuer.PublicKey, mrX.PublicKey,
            generation: 7 + authorityAdvance,
            previousHash: mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion
                ? oldAuthorityHash : Bytes(211, 32),
            newCurrentEpoch, newNextEpoch, Now);
        byte[] newRevocationSnapshot = [];
        if (mode == ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint)
        {
            newAuthorityValue = newAuthorityValue with
            {
                Revocation = newAuthorityValue.Revocation with
                {
                    Generation = oldAuthorityValue.Revocation.Generation + 1,
                    PreviousHeadHash = oldAuthorityValue.Revocation.HeadHash,
                    HeadHash = Bytes(26, 32)
                }
            };
            var unsignedRevocations = new ProductionMailboxRevocationSnapshot
            {
                NetworkId = newAuthorityValue.NetworkId,
                AuthorityGeneration = newAuthorityValue.AuthorityGeneration,
                AuthorityBindingHash = ProductionMailboxRevocationSnapshotCodec
                    .ComputeAuthorityBindingHash(newAuthorityValue),
                RevocationGeneration = newAuthorityValue.Revocation.Generation,
                RevocationHeadHash = newAuthorityValue.Revocation.HeadHash,
                PreviousRevocationHeadHash = newAuthorityValue.Revocation.PreviousHeadHash,
                IssuedAtUnixSeconds = newAuthorityValue.Revocation.IssuedAtUnixSeconds,
                ExpiresAtUnixSeconds = newAuthorityValue.Revocation.ExpiresAtUnixSeconds,
                RevokedGrantSerials = [],
                IssuerSignature = new byte[64]
            };
            var signedRevocations = unsignedRevocations with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(unsignedRevocations),
                    newIssuer.PrivateKey)
            };
            newRevocationSnapshot = ProductionMailboxRevocationSnapshotCodec.Encode(
                signedRevocations);
            newAuthorityValue = newAuthorityValue with
            {
                Revocation = newAuthorityValue.Revocation with
                { SnapshotHash = SHA256.HashData(newRevocationSnapshot) }
            };
        }
        newAuthorityValue = SignAuthority(newAuthorityValue, mrX.PrivateKey);
        var newAuthority = mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion
            ? ProductionMailboxAuthorityVerifier.Verify(newAuthorityValue,
                AuthorityContext(newAuthorityValue, mrX.PublicKey, lastGeneration: 7,
                    lastAuthorityHash: oldAuthorityHash, now: Now),
                new SodiumProductionMailboxAuthoritySignatureVerifier())
            : ProductionMailboxAuthorityVerifier.VerifyForwardCheckpoint(
                ProductionMailboxAuthorityCodec.Encode(newAuthorityValue),
                new ProductionMailboxAuthorityCheckpointVerificationContext
                {
                    PinnedMrXPublicKeySha256 = SHA256.HashData(mrX.PublicKey),
                    ExpectedNetworkId = newAuthorityValue.NetworkId,
                    LastCommittedGeneration = oldAuthorityValue.AuthorityGeneration,
                    LastCommittedRevocationGeneration = oldAuthorityValue.Revocation.Generation,
                    LastCommittedRevocationHeadHash = oldAuthorityValue.Revocation.HeadHash,
                    LastCommittedRevocationSnapshotHash = oldAuthorityValue.Revocation.SnapshotHash,
                    NowUnixSeconds = Now,
                    ClockSkewSeconds = 0
                }, new SodiumProductionMailboxAuthoritySignatureVerifier());

        var oldTopologyValue = new ProductionMailboxTopologySnapshot
        {
            NetworkId = oldAuthorityValue.NetworkId,
            AuthorityGeneration = oldAuthorityValue.AuthorityGeneration,
            CanonicalAuthorityHash = oldAuthorityHash,
            TopologyGeneration = 3,
            PreviousTopologyHash = Bytes(130, 32),
            IssuedAtUnixSeconds = oldNow - 20,
            ExpiresAtUnixSeconds = oldNow + 300,
            CurrentEpoch = TopologyEpoch(oldCurrentEpoch, oldCurrentDescriptors, endpointSeed: 1),
            NextEpoch = TopologyEpoch(promotedEpoch, promotedDescriptors, endpointSeed: 10),
            IssuerSignature = new byte[64]
        };
        oldTopologyValue = SignTopology(oldTopologyValue, oldIssuer.PrivateKey);
        var oldTopology = ProductionMailboxTopologyVerifier.Verify(
            ProductionMailboxTopologyCodec.Encode(oldTopologyValue), oldAuthority,
            new ProductionMailboxTopologyVerificationContext
            {
                LastCommittedTopologyGeneration = 2,
                LastCommittedTopologyHash = oldTopologyValue.PreviousTopologyHash,
                NowUnixSeconds = oldNow,
                ClockSkewSeconds = 0
            }, new SodiumProductionMailboxTopologySignatureVerifier());
        var oldTopologyHash = oldTopology.CanonicalTopologyHash.ToArray();

        var newTopologyValue = new ProductionMailboxTopologySnapshot
        {
            NetworkId = newAuthorityValue.NetworkId,
            AuthorityGeneration = newAuthorityValue.AuthorityGeneration,
            CanonicalAuthorityHash = newAuthority.CanonicalAuthorityHash,
            TopologyGeneration = 3 + topologyAdvance,
            PreviousTopologyHash = mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion
                ? oldTopologyHash : Bytes(212, 32),
            IssuedAtUnixSeconds = Now - 10,
            ExpiresAtUnixSeconds = Now + 300,
            CurrentEpoch = TopologyEpoch(newCurrentEpoch, newCurrentDescriptors, endpointSeed: 10),
            NextEpoch = TopologyEpoch(newNextEpoch, newNextDescriptors, endpointSeed: 20),
            IssuerSignature = new byte[64]
        };
        if (promoteSpkiPins)
            newTopologyValue = newTopologyValue with
            {
                CurrentEpoch = newTopologyValue.CurrentEpoch with
                {
                    Nodes = newTopologyValue.CurrentEpoch.Nodes.Select((node, i) => node with
                    {
                        CurrentSpkiSha256 = node.NextSpkiSha256,
                        NextSpkiSha256 = Bytes((byte)(220 + i), 32)
                    }).ToArray()
                }
            };
        newTopologyValue = SignTopology(newTopologyValue, newIssuer.PrivateKey);
        var newTopologyBytes = ProductionMailboxTopologyCodec.Encode(newTopologyValue);
        var newTopology = mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion
            ? ProductionMailboxTopologyVerifier.Verify(newTopologyBytes, newAuthority,
                new ProductionMailboxTopologyVerificationContext
                {
                    LastCommittedTopologyGeneration = 3,
                    LastCommittedTopologyHash = oldTopologyHash,
                    NowUnixSeconds = Now,
                    ClockSkewSeconds = 0
                }, new SodiumProductionMailboxTopologySignatureVerifier())
            : ProductionMailboxTopologyVerifier.VerifyForwardCheckpoint(newTopologyBytes, newAuthority,
                new ProductionMailboxTopologyCheckpointVerificationContext
                {
                    LastCommittedTopologyGeneration = 3,
                    NowUnixSeconds = Now,
                    ClockSkewSeconds = 0
                }, new SodiumProductionMailboxTopologySignatureVerifier());

        var placement = new BlindedPlacementId(Bytes(201, 32));
        var oldSelection = Selection(oldAuthority, oldTopology, oldTopologyValue.NextEpoch,
            promotedDescriptors, placement, oldIssuer.PrivateKey, oldNow, oldNow + 90);
        var newSelection = Selection(newAuthority, newTopology, newTopologyValue.CurrentEpoch,
            newCurrentDescriptors, placement, newIssuer.PrivateKey, Now - 5, Now + 200);
        var newNextSelection = Selection(newAuthority, newTopology, newTopologyValue.NextEpoch,
            newNextDescriptors, placement, newIssuer.PrivateKey, Now - 5, Now + 200);
        var oldSelectionBytes = ProductionMailboxTopologyCodec.EncodeSelection(oldSelection);
        var newSelectionBytes = ProductionMailboxTopologyCodec.EncodeSelection(newSelection);
        var newNextSelectionBytes = ProductionMailboxTopologyCodec.EncodeSelection(newNextSelection);
        var proof = new ProductionMailboxSelectionSuccessorProof
        {
            Mode = mode,
            NetworkId = oldAuthorityValue.NetworkId,
            OldEpoch = promotedEpoch.Epoch,
            OldEpochGeneration = promotedEpoch.Generation,
            NewEpoch = newCurrentEpoch.Epoch,
            NewEpochGeneration = newCurrentEpoch.Generation,
            MailboxOwnerEd25519PublicKey = owner.PublicKey,
            BlindedMailboxId = Bytes(111, 32),
            BlindedPlacementId = placement.Bytes,
            SelectionInputCommitment = ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(placement),
            OldCanonicalAuthorityHash = oldAuthorityHash,
            NewCanonicalAuthorityHash = newAuthority.CanonicalAuthorityHash,
            OldTopologyGeneration = oldTopologyValue.TopologyGeneration,
            OldCanonicalTopologyHash = oldTopologyHash,
            NewTopologyGeneration = newTopologyValue.TopologyGeneration,
            NewCanonicalTopologyHash = newTopology.CanonicalTopologyHash,
            OldCanonicalSelectionHash = SHA256.HashData(oldSelectionBytes),
            NewCanonicalSelectionHash = SHA256.HashData(newSelectionBytes),
            IssuedAtUnixSeconds = Now,
            ExpiresAtUnixSeconds = Now + 90,
            CanonicalNewAuthority = ProductionMailboxAuthorityCodec.Encode(newAuthority.Authority),
            OldCanonicalSelection = oldSelectionBytes,
            NewCanonicalSelection = newSelectionBytes,
            OldIssuerSignature = new byte[64],
            NewIssuerSignature = new byte[64]
        };
        proof = SignSuccessor(proof, oldIssuer.PrivateKey, newIssuer.PrivateKey);
        var context = new ProductionMailboxSelectionSuccessorVerificationContext
        {
            ExpectedNetworkId = proof.NetworkId,
            ExpectedMailboxOwnerEd25519PublicKey = proof.MailboxOwnerEd25519PublicKey,
            ExpectedBlindedMailboxId = proof.BlindedMailboxId,
            ExpectedBlindedPlacementId = proof.BlindedPlacementId,
            PinnedMrXPublicKeySha256 = SHA256.HashData(mrX.PublicKey),
            ExpectedOldCanonicalSelectionHash = proof.OldCanonicalSelectionHash,
            NowUnixSeconds = Now,
            ClockSkewSeconds = 0
        };
        return new Fixture(oldAuthority, oldTopology, newAuthority, newTopology, proof, context,
            oldIssuer.PrivateKey, newIssuer.PrivateKey, mrX.PrivateKey,
            newCurrentDescriptors, placement, newRevocationSnapshot, newNextSelectionBytes);
    }

    private static ProductionMailboxAuthority Authority(byte[] issuerPublicKey, byte[] mrXPublicKey,
        ulong generation, ReadOnlyMemory<byte> previousHash,
        ProductionMailboxAuthorityEpoch current, ProductionMailboxAuthorityEpoch next,
        ulong referenceNow) => new()
    {
        DevelopmentOnly = false,
        Environment = ProductionMailboxAuthorityEnvironment.Production,
        Transport = ProductionMailboxAuthorityTransport.AuthenticatedMau2,
        Ownership = ProductionMailboxAuthorityOwnership.OfficialManaged,
        EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
        NetworkId = Bytes(1, 16),
        AuthorityGeneration = generation,
        PreviousAuthorityHash = previousHash,
        MailboxIssuerEd25519PublicKey = issuerPublicKey,
        MrXApprovalEd25519PublicKey = mrXPublicKey,
        Coordinator = Endpoint("https://coord.example.net/", 4),
        NodeIngress = Endpoint("https://ingress.example.net/mau2/", 6),
        CurrentEpoch = current,
        NextEpoch = next,
        Revocation = new ProductionMailboxAuthorityRevocation
        {
            SnapshotHash = Bytes(14, 32), HeadHash = Bytes(15, 32),
            PreviousHeadHash = Bytes(16, 32), Generation = 6,
            IssuedAtUnixSeconds = referenceNow - 100, ExpiresAtUnixSeconds = referenceNow + 400
        },
        MrXApproval = new ProductionMailboxAuthorityApproval
        {
            AuthorityPayloadHash = Bytes(17, 32),
            AllowedAndroidSigningCertificateSha256 = [Bytes(18, 32)],
            AllowedWindowsSigningCertificateSha256 = [Bytes(19, 32)],
            AndroidReleaseBuildArtifactSha256 = [Bytes(20, 32)],
            WindowsReleaseBuildArtifactSha256 = [Bytes(21, 32)],
            RolloutNotBeforeUnixSeconds = current.NotBeforeUnixSeconds,
            RolloutNotAfterUnixSeconds = referenceNow + 400
        },
        Signature = new byte[64]
    };

    private static ProductionMailboxAuthorityVerificationContext AuthorityContext(
        ProductionMailboxAuthority authority, byte[] mrXPublicKey, ulong lastGeneration,
        ReadOnlyMemory<byte> lastAuthorityHash, ulong now) => new()
    {
        PinnedMrXPublicKeySha256 = SHA256.HashData(mrXPublicKey),
        ExpectedNetworkId = authority.NetworkId,
        LastCommittedGeneration = lastGeneration,
        LastCommittedAuthorityHash = lastAuthorityHash,
        LastCommittedRevocationGeneration = authority.Revocation.Generation,
        LastCommittedRevocationHeadHash = authority.Revocation.HeadHash,
        LastCommittedRevocationSnapshotHash = authority.Revocation.SnapshotHash,
        NowUnixSeconds = now,
        ClockSkewSeconds = 0
    };

    private static ProductionMailboxSelectionProof Selection(
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxTopology topology,
        ProductionMailboxTopologyEpoch epoch,
        MembershipRouteDescriptor[] descriptors,
        BlindedPlacementId placement,
        byte[] issuerPrivateKey,
        ulong issued,
        ulong expires)
    {
        var input = ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(placement);
        var selected = ProductionMailboxReplicaSelection.Select(
            authority.Authority.NetworkId.Span, epoch, input);
        var proofs = MembershipRouteDescriptorCodec.BuildProofs(descriptors);
        var replicas = selected.Select(id =>
        {
            var index = Array.FindIndex(descriptors, d => d.RouterId.Span.SequenceEqual(id.Span));
            var descriptor = descriptors[index];
            return new ProductionMailboxSelectionReplica
            {
                ReplicaId = descriptor.RouterId,
                CanonicalMIP1Proof = MailboxPeerReplicationCodec.EncodeMembershipProof(
                    new MailboxReplicaMembershipProof
                    {
                        ReplicaId = descriptor.RouterId,
                        SigningPublicKey = descriptor.Ed25519PublicKey,
                        Epoch = descriptor.Epoch,
                        MembershipCommitment = epoch.MembershipCommitment,
                        CanonicalInclusionProof = MailboxReplicaRouteProofCodec.Encode(descriptor, proofs[index])
                    })
            };
        }).ToArray();
        var unsigned = new ProductionMailboxSelectionProof
        {
            Algorithm = ProductionMailboxSelectionAlgorithm.RendezvousSha256V2,
            NetworkId = authority.Authority.NetworkId,
            AuthorityGeneration = authority.Authority.AuthorityGeneration,
            CanonicalAuthorityHash = authority.CanonicalAuthorityHash,
            TopologyGeneration = topology.Snapshot.TopologyGeneration,
            CanonicalTopologyHash = topology.CanonicalTopologyHash,
            Epoch = epoch.Epoch,
            Generation = epoch.Generation,
            MembershipCommitment = epoch.MembershipCommitment,
            TopologyPlacementCommitment = epoch.TopologyPlacementCommitment,
            MailboxPlacementCommitment = MailboxPlacementCommitment.Compute(placement),
            SelectionInputCommitment = input,
            IssuedAtUnixSeconds = issued,
            ExpiresAtUnixSeconds = expires,
            Replicas = replicas,
            IssuerSignature = new byte[64]
        };
        return unsigned with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxTopologyCodec.GetSelectionSigningBytes(unsigned), issuerPrivateKey)
        };
    }

    private static ProductionMailboxAuthority SignAuthority(ProductionMailboxAuthority value, byte[] key)
    {
        var bound = value with
        {
            MrXApproval = value.MrXApproval with
            { AuthorityPayloadHash = ProductionMailboxAuthorityCodec.ComputePayloadHash(value) },
            Signature = new byte[64]
        };
        return bound with
        {
            Signature = PublicKeyAuth.SignDetached(
                ProductionMailboxAuthorityCodec.GetSigningBytes(bound), key)
        };
    }

    private static ProductionMailboxSelectionProof SignSelection(
        ProductionMailboxSelectionProof value, byte[] key)
    {
        var unsigned = value with { IssuerSignature = new byte[64] };
        return unsigned with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxTopologyCodec.GetSelectionSigningBytes(unsigned), key)
        };
    }

    private static ProductionMailboxTopologySnapshot SignTopology(
        ProductionMailboxTopologySnapshot value, byte[] key)
    {
        var unsigned = value with { IssuerSignature = new byte[64] };
        return unsigned with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxTopologyCodec.GetSigningBytes(unsigned), key)
        };
    }

    private static ProductionMailboxSelectionSuccessorProof SignSuccessor(
        ProductionMailboxSelectionSuccessorProof value, byte[] oldKey, byte[] newKey)
    {
        var unsigned = value with { OldIssuerSignature = new byte[64], NewIssuerSignature = new byte[64] };
        return unsigned with
        {
            OldIssuerSignature = unsigned.Mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion
                ? PublicKeyAuth.SignDetached(
                    ProductionMailboxSelectionSuccessorCodec.GetOldIssuerSigningBytes(unsigned), oldKey)
                : new byte[64],
            NewIssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxSelectionSuccessorCodec.GetNewIssuerSigningBytes(unsigned), newKey)
        };
    }

    private static MembershipRouteDescriptor[] Descriptors(int start, ulong epoch, ulong from, ulong until) =>
        [Descriptor(start, epoch, from, until), Descriptor(start + 0x40, epoch, from, until),
            Descriptor(start + 0x80, epoch, from, until)];

    private static MembershipRouteDescriptor Descriptor(int start, ulong epoch, ulong from, ulong until) => new()
    {
        RouterId = Range(start, 32), Ed25519PublicKey = Range(start + 32, 32),
        X25519PublicKey = Range(start + 64, 32), RpcEndpoint = $"https://route-{start:D3}.example.net/",
        Roles = MembershipRouteRole.Storage, Capabilities = MembershipRouteCapability.Storage,
        Epoch = epoch, ValidFromUnixSeconds = from, ValidUntilUnixSeconds = until
    };

    private static ProductionMailboxTopologyEpoch TopologyEpoch(
        ProductionMailboxAuthorityEpoch epoch, MembershipRouteDescriptor[] descriptors, int endpointSeed) => new()
    {
        Epoch = epoch.Epoch, Generation = epoch.Generation,
        MembershipCommitment = epoch.MembershipCommitment,
        TopologyPlacementCommitment = epoch.TopologyPlacementCommitment,
        NotBeforeUnixSeconds = epoch.NotBeforeUnixSeconds, NotAfterUnixSeconds = epoch.NotAfterUnixSeconds,
        Nodes = descriptors.Select((d, i) => new ProductionMailboxTopologyNode
        {
            NodeId = d.RouterId, HttpsEndpoint = $"https://promoted-{endpointSeed + i}.example.net/",
            CurrentSpkiSha256 = Bytes((byte)(100 + endpointSeed + i * 2), 32),
            NextSpkiSha256 = Bytes((byte)(101 + endpointSeed + i * 2), 32)
        }).ToArray()
    };

    private static ProductionMailboxAuthorityEpoch AuthorityEpoch(ulong epoch, ulong generation,
        byte[] membership, byte[] placement, ulong from, ulong until) => new()
    {
        Epoch = epoch, Generation = generation, MembershipCommitment = membership,
        TopologyPlacementCommitment = placement,
        NotBeforeUnixSeconds = from, NotAfterUnixSeconds = until
    };

    private static ProductionMailboxAuthorityEndpoint Endpoint(string uri, byte seed) => new()
    {
        Uri = uri, CurrentSpkiSha256 = Bytes(seed, 32),
        NextSpkiSha256 = Bytes((byte)(seed + 1), 32)
    };

    private static void AssertError(ProductionMailboxSelectionSuccessorError error, Action action) =>
        Assert.Equal(error, Assert.Throws<ProductionMailboxSelectionSuccessorException>(action).Error);

    private static byte[] Bytes(byte seed, int length) =>
        Enumerable.Range(0, length).Select(i => unchecked((byte)(seed + i))).ToArray();
    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(i => unchecked((byte)i)).ToArray();

    private sealed class MutatingVerifier(Action mutate)
        : IProductionMailboxSelectionSuccessorSignatureVerifier
    {
        private readonly SodiumProductionMailboxSelectionSuccessorSignatureVerifier _inner = new();
        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            mutate(); return _inner.Verify(publicKey, signingBytes, signature);
        }
    }

    private sealed class MutatingAuthorityVerifier(Action mutate)
        : IProductionMailboxAuthoritySignatureVerifier
    {
        private readonly SodiumProductionMailboxAuthoritySignatureVerifier _inner = new();

        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            mutate();
            return _inner.Verify(publicKey, signingBytes, signature);
        }
    }

    private sealed class MutatingAllSignatureVerifier(Action mutate) :
        IProductionMailboxAuthoritySignatureVerifier,
        IProductionMailboxRevocationSnapshotSignatureVerifier,
        IProductionMailboxTopologySignatureVerifier,
        IProductionMailboxSelectionSuccessorSignatureVerifier
    {
        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            mutate();
            return PublicKeyAuth.VerifyDetached(signature.ToArray(), signingBytes.ToArray(),
                publicKey.ToArray());
        }
    }

    private sealed class CountingSignatureVerifier :
        IProductionMailboxAuthoritySignatureVerifier,
        IProductionMailboxRevocationSnapshotSignatureVerifier,
        IProductionMailboxTopologySignatureVerifier,
        IProductionMailboxSelectionSuccessorSignatureVerifier
    {
        public int CallbackCount { get; private set; }

        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            CallbackCount++;
            return false;
        }
    }

    private sealed record Fixture(
        VerifiedProductionMailboxAuthority OldAuthority,
        VerifiedProductionMailboxTopology OldTopology,
        VerifiedProductionMailboxAuthority NewAuthority,
        VerifiedProductionMailboxTopology NewTopology,
        ProductionMailboxSelectionSuccessorProof Proof,
        ProductionMailboxSelectionSuccessorVerificationContext Context,
        byte[] OldIssuerPrivateKey,
        byte[] NewIssuerPrivateKey,
        byte[] MrXPrivateKey,
        MembershipRouteDescriptor[] PromotedDescriptors,
        BlindedPlacementId Placement,
        byte[] NewRevocationSnapshot,
        byte[] NewNextSelection);
}
