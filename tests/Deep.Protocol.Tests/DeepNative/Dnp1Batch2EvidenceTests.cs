using System.Buffers.Binary;
using Deep.Protocol.Tests.DeepNative;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// Independently discoverable evidence cases split from broader contract suites.
/// Each fact below executes the complete existing production path needed by its
/// single normative semantic ID; deliberately partial structural cases are not
/// represented here.
/// </summary>
public sealed class Batch2EvidenceTests
{
    [Fact]
    public async Task ResetResult_Exact381HmacHashAndReflectionRejectRawAuthority()
    {
        await new GenesisProtectedRecordsExact15Tests()
            .ResetReservationResult_VerifiesExact381ShapeAndHasNoPublicRawIdsOrAuthorityConversion();
    }

    [Fact]
    public async Task SealIntent_IsDurablyLatchedBeforeOneAeadAndForkRetryIsClosed()
    {
        var suite = new GenesisRecoverySealerExact15Tests();
        await suite.SealIntent_UsesExactV5TranscriptAndDurableLatchBeforeAead();
        await suite.ForkLatch_RejectsBeforeSealOrOpen();
        await suite.LatchPrecedesExactlyOneSealAndSelfOpen_AndExactRetryIsByteIdentical();
    }

    [Fact]
    public async Task SealCandidate_SelfChecksCancelsAndZeroesOwnedSecrets()
    {
        var suite = new GenesisRecoverySealerExact15Tests();
        await suite.SealCandidate_SelfChecksExactRetryAndZeroesOnSuccessMutationOrCancellation();
        await suite.CancellationAfterDurableLatch_RejectsBeforeSealAndPreservesExactIntent();
        await suite.MutableOrIncorrectSelfOpen_FailsClosedAndZeroesProviderPlaintext();
    }

    [Fact]
    public async Task ArtifactReceipt_Exact285SevenRowsBoundsHmacAndStableReread()
    {
        new GenesisProtectedRecordsExact15Tests()
            .ArtifactReceipt_EnforcesExactSevenAndMax33558991();
        await new GenesisForwardStateExact15Tests()
            .ArtifactStore_UsesExactTransactionScopeAndVerifiesGasHmacAndReread();
    }

    [Fact]
    public async Task KeySetAxisCrossFeed_RejectsEachAxisBeforeSource492()
    {
        var sealing = new GenesisRecoverySealerExact15Tests.SealingProvider([]);
        using var fixture = await GenesisRecoverySealerExact15Tests.SealerFixture.CreateAsync(
            sealing);
        var identity = fixture.Identity;
        var intent = fixture.Intent;
        var canonicalNetwork = identity.BaseIdentity.Network.ToArray();
        var canonicalReset = identity.BaseIdentity.ResetId.ToArray();
        var canonicalSubject = intent.ComponentSubject.ToArray();
        var canonicalKind = intent.ComponentKind;
        var canonicalGeneration = identity.BaseIdentity.AccountGeneration;
        var cases = new[]
        {
            (Change(canonicalNetwork), canonicalReset, canonicalKind, canonicalSubject,
                canonicalGeneration),
            (canonicalNetwork, Change(canonicalReset), canonicalKind, canonicalSubject,
                canonicalGeneration),
            (canonicalNetwork, canonicalReset,
                canonicalKind == ComponentKind.Registry ? ComponentKind.XNode : ComponentKind.Registry,
                canonicalSubject, canonicalGeneration),
            (canonicalNetwork, canonicalReset, canonicalKind, Change(canonicalSubject),
                canonicalGeneration),
            (canonicalNetwork, canonicalReset, canonicalKind, canonicalSubject,
                checked(canonicalGeneration + 1))
        };

        foreach (var test in cases)
        {
            var request = new GenesisProtectedKeySetRequest(
                test.Item1, test.Item2, test.Item3, test.Item4, test.Item5);
            var registry = new OneKeySetRead(KeySetScope(request));
            var keySet = await GenesisProtectedKeySetContext.ReadAsync(
                registry, request, identity.ProtectedStateHmacKeyId.ToArray(),
                fixture.Protector.RecoveryNonceLatchKeyId.ToArray(),
                fixture.Protector.ProtectorKeyId.ToArray(), default);

            Assert.Throws<RecordException>(() =>
            {
                _ = new GenesisCutoverSourceContext(
                    identity, intent, fixture.Release, keySet, fixture.Protector);
            });
            Assert.Equal(1, registry.Calls);
        }
    }

    [Fact]
    public async Task RfcHash_TrustsFullTaggedContainerOnlyAfterItsHmac()
    {
        var cold = new RecoveryColdProtectedPayloadTests();
        await cold.ColdPayload_ReturnsCandidateOnlyAfterAllFourProtectedHmacsVerify();
        await cold.ColdPayload_WrongSharedHsmKeyFailsClosedAfterOneAeadAndBeforeCandidate();
        new RecoverySchemaProfileTests().RfcHash_IsLengthFramedAndIncludesVerifiedTagBytes();

        var tagged = new byte[232];
        "RFC1"u8.CopyTo(tagged);
        tagged[4] = 1;
        tagged.AsSpan(200, 32).Fill(0x5a);
        var trustedHash = RecoveryShadow.ComputeFrontierCheckpointHash(tagged);

        var omittedTag = tagged.ToArray();
        omittedTag.AsSpan(200, 32).Clear();
        Assert.NotEqual(trustedHash,
            RecoveryShadow.ComputeFrontierCheckpointHash(omittedTag));

        var frame = new byte[4 + tagged.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame, checked((uint)tagged.Length));
        tagged.CopyTo(frame, 4);
        Assert.NotEqual(trustedHash, CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-authority-history-hash", frame));
    }

    [Fact]
    public async Task ExpectedContextPostOpen_BindsFourHmacIdsAndOldSourceBeforeAuthority()
    {
        var registry = new RecoveryProviderRegistryAmendmentTests();
        await registry.ColdPath_OrdersPreReadAeadHmacAndPostReadWithExactLatchReplay();
        await registry.ColdPath_Row1CrossFeedRejectsAfterOpenBeforeProtectedHmacCallback();
        await new GenesisAuthorReplayOpenExact15Tests()
            .CrossFedAnchorSourceOrOldSource_RejectsOnlyAfterCryptoOpenAndFourHmacs();
    }

    [Fact]
    public async Task ExpectedContextToctou_RejectsSelectorRegistryHealthAndLatchMovement()
    {
        var registry = new RecoveryProviderRegistryAmendmentTests();
        foreach (var mutation in Enum.GetValues<
                     RecoveryProviderRegistryAmendmentTests.ScopeMutation>())
            await registry.ScopeSubstitution_RejectsBeforeAContextExists(mutation);
        foreach (var mutation in Enum.GetValues<
                     RecoveryProviderRegistryAmendmentTests.RereadMutation>())
            await registry.ColdPath_PostOpenRegistryMovementStopsBeforeLatchRereadOrAuthority(
                mutation);
        await registry.LatchReread_RequiresExactReplay(RecoveryNonceLatchDecision.Stored);
        await registry.LatchReread_RequiresExactReplay(RecoveryNonceLatchDecision.ForkLatched);

        var cold = new RecoveryColdProtectedPayloadTests();
        for (var tag = 1; tag <= 8; tag++)
            await cold.ColdPayload_DrcRsmCrossFeedRejectsBeforeEveryProviderCallback(tag);
    }

    [Fact]
    public async Task ExpectedContextPreOpen_RejectsEveryDrcRsmAndProtectorAxisBeforeProvider()
    {
        var cold = new RecoveryColdProtectedPayloadTests();
        for (var tag = 1; tag <= 8; tag++)
            await cold.ColdPayload_DrcRsmCrossFeedRejectsBeforeEveryProviderCallback(tag);
        await cold.ColdPayload_ProtectorSelectorCrossFeedRejectsBeforeEveryProviderCallback();
    }

    [Fact]
    public async Task ShadowManifest723_BindsTypedPredecessorInventoryAndEveryProtectedHash()
    {
        var schema = new RecoverySchemaProfileTests();
        schema.Rsm723_WrongSchemaOrOldLengthRejects();
        schema.Rsm723_PredecessorUnionAcceptsOnlyExactExistingOrGenesisShape();
        schema.CapsuleSource_V2IncludesPredecessorKindAndTypedRsmOffsets();

        var cold = new RecoveryColdProtectedPayloadTests();
        await cold.ColdPayload_ReturnsCandidateOnlyAfterAllFourProtectedHmacsVerify();
        await cold.ColdPayload_ChangedRsmInventoryBindingFailsAfterOneAeadBeforeHmac();
    }

    private static byte[] Change(byte[] value)
    {
        var changed = value.ToArray();
        changed[0] ^= 0x80;
        return changed;
    }

    private static byte[] KeySetScope(GenesisProtectedKeySetRequest request)
    {
        var scope = new byte[GenesisProtectedKeySetContext.ExactScopeLength];
        request.ExactScopeAxes.Span.CopyTo(scope);
        BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(90, 2), 6);
        for (var index = 0; index < 6; index++)
        {
            var offset = 92 + index * 34;
            BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(offset, 2),
                checked((ushort)(index + 1)));
            scope.AsSpan(offset + 2, 32).Fill(checked((byte)(0xa1 + index)));
        }
        return scope;
    }

    private sealed class OneKeySetRead(byte[] scope) : GenesisProtectedKeySetRegistry
    {
        internal int Calls { get; private set; }

        public override ValueTask<GenesisProtectedKeySetReadResult> ReadAsync(
            GenesisProtectedKeySetRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(new GenesisProtectedKeySetReadResult(
                scope, 1, Enumerable.Repeat(true, 6).ToArray()));
        }
    }
}
