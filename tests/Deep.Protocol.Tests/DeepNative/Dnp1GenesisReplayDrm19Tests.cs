using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisReplayDrm19Tests
{
    [Fact]
    public void Provider_CarriesSealedScopeInsteadOfRawScopeBytes()
    {
        var scopeType = typeof(GenesisReplayScopeV1);
        var callback = typeof(GenesisReplayHeadProvider).GetMethod("ReadLockedAsync");

        Assert.True(scopeType.IsSealed);
        Assert.Empty(scopeType.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Equal(new[] { "AttemptNumber", "DeadlineUnixSeconds", "NoAuthorityClaim" },
            scopeType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Select(static property => property.Name).OrderBy(static name => name));
        Assert.NotNull(callback);
        Assert.Equal(scopeType, callback!.GetParameters()[0].ParameterType);
    }

    [Fact]
    public void HeadDto_IsBoundedAndDefensivelyOwned()
    {
        var artifacts = MinimumArtifactTuple(0x11);
        var artifact = artifacts[0].ToArray();
        artifacts[0] = artifact;
        var dplReference = Bytes(0x22, 38);
        var source = Bytes(0x33, 32);
        var head = new GenesisReplayExternalHeadData(
            1, artifacts, dplReference, source, 4, 50);

        artifact[0] ^= 0xff;
        dplReference[0] ^= 0xff;
        source[0] ^= 0xff;
        var returnedArtifact = head.CanonicalArtifacts[0].ToArray();
        var returnedReference = head.DplReference.ToArray();
        var returnedSource = head.SourceFingerprint.ToArray();
        returnedArtifact[0] ^= 0xff;
        returnedReference[0] ^= 0xff;
        returnedSource[0] ^= 0xff;

        Assert.Equal(0x11, head.CanonicalArtifacts[0].Span[0]);
        Assert.Equal(0x22, head.DplReference.Span[0]);
        Assert.Equal(0x33, head.SourceFingerprint.Span[0]);
        Assert.Throws<RecordException>(() => new GenesisReplayExternalHeadData(
            1,
            Enumerable.Range(0, 9).Select(_ => (ReadOnlyMemory<byte>)Array.Empty<byte>())
                .ToArray(),
            Bytes(1, 38), Bytes(2, 32), 1, 2));
    }

    [Fact]
    public void HeadDto_PreflightsEveryPositionalAndAggregateBoundBeforeCopy()
    {
        var maximum = ArtifactTuple(33_554_914, 8_805);
        var head = new GenesisReplayExternalHeadData(
            1, maximum, Bytes(1, 38), Bytes(2, 32), 1, 10);
        Assert.Equal(33_567_796,
            head.CanonicalArtifacts.Sum(static artifact => artifact.Length));

        Assert.Throws<RecordException>(() => new GenesisReplayExternalHeadData(
            1, ArtifactTuple(481, 375), Bytes(1, 38), Bytes(2, 32), 1, 10));
        Assert.Throws<RecordException>(() => new GenesisReplayExternalHeadData(
            1, ArtifactTuple(33_554_915, 375),
            Bytes(1, 38), Bytes(2, 32), 1, 10));
        Assert.Throws<RecordException>(() => new GenesisReplayExternalHeadData(
            1, ArtifactTuple(482, 8_806), Bytes(1, 38), Bytes(2, 32), 1, 10));

        var crossSlot = MinimumArtifactTuple(0x21);
        (crossSlot[1], crossSlot[5]) = (crossSlot[5], crossSlot[1]);
        Assert.Throws<RecordException>(() => new GenesisReplayExternalHeadData(
            1, crossSlot, Bytes(1, 38), Bytes(2, 32), 1, 10));
    }

    [Fact]
    public void StableHead_AllowsOnlyRevisionAndLeaseRenewal()
    {
        var artifacts = MinimumArtifactTuple(0x41);
        var reference = Bytes(0x42, 38);
        var source = Bytes(0x43, 32);
        var preliminary = Head(artifacts, reference, source, revision: 7, lease: 100);
        var renewed = Head(artifacts, reference, source, revision: 8, lease: 101);
        var revisionRollback = Head(artifacts, reference, source, revision: 6, lease: 101);
        var leaseRollback = Head(artifacts, reference, source, revision: 8, lease: 99);
        var moved = Head(artifacts, Bytes(0x44, 38), source, revision: 8, lease: 101);

        Assert.True(GenesisReplayPrimitives.SameStableHead(preliminary, renewed));
        Assert.True(GenesisReplayPrimitives.StableForUse(preliminary, renewed));
        Assert.False(GenesisReplayPrimitives.StableForUse(preliminary, revisionRollback));
        Assert.False(GenesisReplayPrimitives.StableForUse(preliminary, leaseRollback));
        Assert.False(GenesisReplayPrimitives.SameStableHead(preliminary, moved));
        Assert.False(GenesisReplayPrimitives.StableForUse(preliminary, moved));
    }

    [Fact]
    public async Task LeaseRenewal_UsesAuthoritativeReadBWithOneNetworkCallbackAndNoMutation()
    {
        var artifacts = MinimumArtifactTuple(0x45);
        var reference = Bytes(0x46, 38);
        var source = Bytes(0x47, 32);
        var provider = new StableRenewalHeadProvider(
            Head(artifacts, reference, source, revision: 7, lease: 100),
            Head(artifacts, reference, source, revision: 8, lease: 101));
        var scope = new GenesisReplayScopeV1(Bytes(0x48, 122), 1, 110);

        var stable = await GenesisReplayVerifier.ReadStableAttemptAsync(
            scope, provider, default);

        Assert.NotNull(stable);
        Assert.Equal(1, provider.Calls);
        Assert.Equal(8UL, stable!.AuthoritativeExternal.SourceRevision);
        Assert.Equal(101UL, stable.AuthoritativeExternal.LeaseExpiryUnixSeconds);
        Assert.Equal(GenesisReplayMatrixCase.ExternalCatchUp,
            GenesisReplayMatrix.Classify(phase: 0, externalKind: 1, localKind: 0));
        Assert.Equal(0, provider.MutationCalls);
    }

    [Fact]
    public void JournalHash_IsExactV9LengthFramedGaj880()
    {
        var journal = Bytes(0x51, GenesisProtectedRecords.GajLength);
        var framed = new byte[4 + journal.Length];
        BinaryPrimitives.WriteUInt32BigEndian(framed, 880);
        journal.CopyTo(framed, 4);

        var expected = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V9/genesis-author-journal-hash", framed);

        Assert.Equal(expected, GenesisReplayPrimitives.JournalHash(journal));
    }

    [Fact]
    public void EvidenceHash_IsExactV8LengthFramedTranscript1056()
    {
        var transcript = Bytes(0x61, 1056);
        var framed = new byte[4 + transcript.Length];
        BinaryPrimitives.WriteUInt32BigEndian(framed, 1056);
        transcript.CopyTo(framed, 4);

        var expected = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V8/genesis-replay-fork-evidence", framed);

        Assert.Equal(expected, GenesisReplayPrimitives.EvidenceHash(transcript));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Gfl_PreflightAcceptsOnlyClosedReasonsAndExact1176(byte reason)
    {
        var gfl = Gfl(reason);

        GenesisProtectedRecords.PreflightGfl(gfl);

        Assert.Equal(1176, gfl.Length);
        gfl[130] = 0;
        Assert.Throws<RecordException>(() => GenesisProtectedRecords.PreflightGfl(gfl));
        gfl[130] = 4;
        Assert.Throws<RecordException>(() => GenesisProtectedRecords.PreflightGfl(gfl));
        Assert.Throws<RecordException>(() =>
            GenesisProtectedRecords.PreflightGfl(Gfl(reason).AsSpan(1)));
    }

    [Fact]
    public void Dispositions_AreClosedSealedAndHaveNoPublicConstructors()
    {
        var baseType = typeof(GenesisReplayDisposition);
        var exact = new[]
        {
            typeof(CreatedContinue), typeof(ExternalCatchUp), typeof(LocalCatchUp),
            typeof(NormalCurrentRequired), typeof(ExternalCheckpointAhead)
        };

        Assert.True(baseType.IsAbstract);
        Assert.Empty(baseType.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Equal(exact.OrderBy(static type => type.FullName),
            baseType.Assembly.GetTypes()
                .Where(type => type.BaseType == baseType)
                .OrderBy(static type => type.FullName));
        Assert.All(exact, type =>
        {
            Assert.True(type.IsSealed);
            Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
            Assert.NotNull(type.GetProperty(nameof(GenesisReplayDisposition.NoAuthorityClaim)));
        });
    }

    [Fact]
    public void FinalStableTupleMatrix_IsExhaustiveAcrossAllTwentySevenStates()
    {
        var counts = Enum.GetValues<GenesisReplayMatrixCase>()
            .ToDictionary(value => value, _ => 0);

        for (byte phase = 0; phase <= 2; phase++)
        for (var externalKind = 0; externalKind <= 2; externalKind++)
        for (var localKind = 0; localKind <= 2; localKind++)
        {
            var expected = (phase, externalKind, localKind) switch
            {
                (0, 0, 0) => GenesisReplayMatrixCase.CreatedContinue,
                (0, 1, 0) => GenesisReplayMatrixCase.ExternalCatchUp,
                (1, 1, 0 or 1) => GenesisReplayMatrixCase.LocalCatchUp,
                (2, 1, 1) => GenesisReplayMatrixCase.NormalCurrentRequired,
                _ => GenesisReplayMatrixCase.ExternalCheckpointAhead
            };

            var actual = GenesisReplayMatrix.Classify(phase, externalKind, localKind);

            Assert.Equal(expected, actual);
            counts[actual]++;
        }

        Assert.Equal(1, counts[GenesisReplayMatrixCase.CreatedContinue]);
        Assert.Equal(1, counts[GenesisReplayMatrixCase.ExternalCatchUp]);
        Assert.Equal(2, counts[GenesisReplayMatrixCase.LocalCatchUp]);
        Assert.Equal(1, counts[GenesisReplayMatrixCase.NormalCurrentRequired]);
        Assert.Equal(22, counts[GenesisReplayMatrixCase.ExternalCheckpointAhead]);
    }

    [Fact]
    public void ExternalCatchUp_OwnsSealedKeySetContextAndNoRawDplKey()
    {
        var fields = typeof(ExternalCatchUp).GetFields(
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        var properties = typeof(ExternalCatchUp).GetProperties(
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

        Assert.Contains(fields, field =>
            field.FieldType == typeof(GenesisProtectedKeySetContext));
        Assert.DoesNotContain(properties, property =>
            property.Name.Contains("KeyId", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("DplKey", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void UntrustedHeadTagsOrPartialSlots_RejectBeforeVerifiedSnapshotMint()
    {
        var local = new GenesisReplayLocalHeadData(
            [], new byte[38], new byte[32], 1, new byte[880], 1);
        var nonzeroZeroHead = new GenesisReplayExternalHeadData(
            0, [], Bytes(1, 38), new byte[32], 1, 0);
        Assert.Throws<RecordException>(() =>
            GenesisReplayVerifier.ValidateClosedHeadShape(nonzeroZeroHead, local));
        Assert.Throws<RecordException>(() =>
            new GenesisReplayExternalHeadData(
                1, new ReadOnlyMemory<byte>[] { Bytes(2, 8) },
                Bytes(3, 38), Bytes(4, 32), 1, 10));
        Assert.Empty(typeof(VerifiedGenesisReplayHeadSnapshot)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(typeof(GenesisReplayScopeV1).GetProperties(), property =>
            property.PropertyType == typeof(ReadOnlyMemory<byte>) ||
            property.PropertyType == typeof(byte[]));
    }

    [Fact]
    public async Task GajHashAndPhaseSlots_AreExactAndRejectCrossPhaseSlotsWithoutCallbacks()
    {
        var sealing = new GenesisRecoverySealerExact15Tests.SealingProvider([]);
        using var fixture = await GenesisRecoverySealerExact15Tests.SealerFixture.CreateAsync(
            sealing);
        for (byte phase = 0; phase <= 2; phase++)
        {
            var journal = Journal(fixture.Identity, phase, revision: 9);
            var slots = GenesisReplayVerifier.ExpectedSlots(journal);
            Assert.Equal(journal.AsSpan(227, 266).ToArray(), slots.AsSpan(0, 266).ToArray());
            Assert.Equal(phase == 0 ? new byte[108] : journal.AsSpan(597, 108).ToArray(),
                slots.AsSpan(266, 108).ToArray());
            var framed = new byte[884];
            BinaryPrimitives.WriteUInt32BigEndian(framed, 880);
            journal.CopyTo(framed, 4);
            Assert.Equal(CanonicalGrammar.Sha256Domain(
                    "Deep/Cutover/V9/genesis-author-journal-hash", framed),
                GenesisReplayPrimitives.JournalHash(journal));
        }

        var createdWithDcq = Journal(fixture.Identity, phase: 0, revision: 9);
        createdWithDcq.AsSpan(597, 38).Fill(0xa1);
        Assert.Throws<RecordException>(() =>
            GenesisProtectedRecords.PreflightGaj(createdWithDcq));
        var externalWithoutDcq = Journal(fixture.Identity, phase: 1, revision: 9);
        externalWithoutDcq.AsSpan(597, 38).Clear();
        Assert.Throws<RecordException>(() =>
            GenesisProtectedRecords.PreflightGaj(externalWithoutDcq));
    }

    [Fact]
    public async Task ThreeMovingAttempts_ExhaustWithoutFourthCallbackOrMutation()
    {
        using var harness = await ReplayHarness.CreateAsync();
        var heads = new MovingHeadProvider();

        var error = await Assert.ThrowsAsync<RecordException>(() =>
            harness.RestoreAsync(heads, new FixedTimePolicy(100, 10)).AsTask());

        Assert.Equal(RecordError.Expired, error.Error);
        Assert.Equal(new[] { 1, 2, 3 },
            heads.Requests.Select(request => request.AttemptNumber));
        Assert.All(heads.Requests, request => Assert.Equal(110UL,
            request.DeadlineUnixSeconds));
        Assert.Equal(3, heads.Requests.Count);
        Assert.Equal(0, harness.DownstreamCalls);
    }

    [Fact]
    public async Task LaterInvocation_StartsFreshThreeAttemptBudget()
    {
        using var harness = await ReplayHarness.CreateAsync();
        var heads = new MovingHeadProvider();

        for (var invocation = 0; invocation < 2; invocation++)
            await Assert.ThrowsAsync<RecordException>(() =>
                harness.RestoreAsync(heads, new FixedTimePolicy(100, 10)).AsTask());

        Assert.Equal(new[] { 1, 2, 3, 1, 2, 3 },
            heads.Requests.Select(request => request.AttemptNumber));
        Assert.Equal(0, harness.DownstreamCalls);
    }

    [Fact]
    public async Task DeadlineBeforeFirstAttempt_ReturnsNoDispositionAndMakesNoCallback()
    {
        using var harness = await ReplayHarness.CreateAsync();
        var heads = new MovingHeadProvider();
        var time = new SequenceTimePolicy(10, 1, 11);

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            harness.RestoreAsync(heads, time).AsTask());

        Assert.Empty(heads.Requests);
        Assert.Equal(0, harness.DownstreamCalls);
    }

    [Fact]
    public async Task CancellationAfterLockedRead_ReturnsNoDispositionAndStopsImmediately()
    {
        using var harness = await ReplayHarness.CreateAsync();
        using var cancellation = new CancellationTokenSource();
        var heads = new MovingHeadProvider(() => cancellation.Cancel());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            harness.RestoreAsync(heads, new FixedTimePolicy(100, 10),
                cancellation.Token).AsTask());

        Assert.Single(heads.Requests);
        Assert.Equal(0, harness.DownstreamCalls);
    }

    [Fact]
    public async Task BlockingHeadProvider_IsCancelledByProtocolOwnedAbsoluteDeadline()
    {
        using var harness = await ReplayHarness.CreateAsync();
        var heads = new BlockingHeadProvider();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            harness.RestoreAsync(heads, new FixedTimePolicy(100, 1)).AsTask());

        Assert.Equal(1, heads.Calls);
        Assert.Equal(0, harness.DownstreamCalls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ForkLatch_UsesPhaseRelativeSlotsAndExactAtomicReplay(byte phase)
    {
        var sealing = new GenesisRecoverySealerExact15Tests.SealingProvider([]);
        using var fixture = await GenesisRecoverySealerExact15Tests.SealerFixture.CreateAsync(
            sealing);
        var journalBytes = Journal(fixture.Identity, phase, revision: 9);
        var journal = new GenesisAuthorJournalSnapshot(journalBytes);
        var observed = Bytes(0xb1, 519);
        var snapshot = new VerifiedGenesisReplayHeadSnapshot(observed, 0);
        var keyRequest = KeyRequest(fixture);
        var keyRegistry = new StableKeyRegistry();
        var hmac = new DeterministicHmac();
        var provider = new AtomicLatchJournal();

        await GenesisReplayVerifier.LatchForkAsync(
            fixture.Identity, journal, snapshot, 3, provider, fixture.KeySet,
            keyRegistry, keyRequest, new FixedTimePolicy(7, 93), 7, 100,
            hmac, default);
        await GenesisReplayVerifier.LatchForkAsync(
            fixture.Identity, journal, snapshot, 3, provider, fixture.KeySet,
            keyRegistry, keyRequest, new FixedTimePolicy(7, 93), 7, 100,
            hmac, default);

        Assert.Equal(2, provider.Requests.Count);
        Assert.Equal(provider.Requests[0].EvidenceTranscript.ToArray(),
            provider.Requests[1].EvidenceTranscript.ToArray());
        var transcript = provider.Requests[0].EvidenceTranscript.Span;
        Assert.Equal(1056, transcript.Length);
        Assert.Equal(GenesisReplayPrimitives.Scope(fixture.Identity),
            transcript[..122].ToArray());
        Assert.Equal((byte)3, transcript[122]);
        Assert.Equal(GenesisReplayPrimitives.JournalHash(journalBytes),
            transcript.Slice(123, 32).ToArray());
        Assert.Equal(9UL, BinaryPrimitives.ReadUInt64BigEndian(
            transcript.Slice(155, 8)));

        var expectedSlots = new byte[374];
        journalBytes.AsSpan(227, 266).CopyTo(expectedSlots);
        if (phase != 0)
            journalBytes.AsSpan(597, 108).CopyTo(expectedSlots.AsSpan(266));
        Assert.Equal(expectedSlots, transcript.Slice(163, 374).ToArray());
        Assert.Equal(observed, transcript.Slice(537, 519).ToArray());
        Assert.Equal(GenesisReplayPrimitives.EvidenceHash(transcript),
            provider.Requests[0].EvidenceHash.ToArray());

        Assert.NotNull(provider.StoredGfl);
        Assert.NotNull(provider.StoredJournal);
        Assert.Equal(1176, provider.StoredGfl!.Length);
        Assert.Equal(10UL, BinaryPrimitives.ReadUInt64BigEndian(
            provider.StoredGfl.AsSpan(1096, 8)));
        Assert.Equal(10UL, BinaryPrimitives.ReadUInt64BigEndian(
            provider.StoredJournal!.AsSpan(807, 8)));
        Assert.Equal((byte)1, provider.StoredJournal[815]);
        Assert.Equal(journalBytes.AsSpan(0, 807).ToArray(),
            provider.StoredJournal.AsSpan(0, 807).ToArray());
        Assert.Equal(journalBytes.AsSpan(816, 32).ToArray(),
            provider.StoredJournal.AsSpan(816, 32).ToArray());
        Assert.NotEqual(journalBytes.AsSpan(848, 32).ToArray(),
            provider.StoredJournal.AsSpan(848, 32).ToArray());
        Assert.Equal(4, keyRegistry.Calls);
        Assert.Equal(new[]
        {
            "Deep/ProtectedState/V1/GFL1", "Deep/ProtectedState/V1/GAJ1",
            "Deep/ProtectedState/V1/GFL1", "Deep/ProtectedState/V1/GAJ1"
        }, hmac.Domains);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ForkLatch_HalfWriteReturnsNoVerifiedReceipt(bool gflOnly)
    {
        var sealing = new GenesisRecoverySealerExact15Tests.SealingProvider([]);
        using var fixture = await GenesisRecoverySealerExact15Tests.SealerFixture.CreateAsync(
            sealing);
        var journal = new GenesisAuthorJournalSnapshot(
            Journal(fixture.Identity, phase: 1, revision: 9));
        var keyRequest = KeyRequest(fixture);
        var keyRegistry = new StableKeyRegistry();
        var hmac = new DeterministicHmac();
        var provider = new AtomicLatchJournal
        {
            ReturnGflOnlyHalfWrite = gflOnly,
            ReturnJournalOnlyHalfWrite = !gflOnly
        };

        await Assert.ThrowsAsync<RecordException>(() =>
            GenesisReplayVerifier.LatchForkAsync(
                fixture.Identity, journal,
                new VerifiedGenesisReplayHeadSnapshot(Bytes(0xb2, 519), 0),
                1, provider, fixture.KeySet, keyRegistry, keyRequest,
                new FixedTimePolicy(7, 93), 7, 100, hmac, default)
                .AsTask());

        Assert.Single(provider.Requests);
    }

    [Fact]
    public async Task ForkLatch_LostResponseRestoresExactPriorJournalAndReceipt()
    {
        var sealing = new GenesisRecoverySealerExact15Tests.SealingProvider([]);
        using var fixture = await GenesisRecoverySealerExact15Tests.SealerFixture.CreateAsync(
            sealing);
        var journalBytes = Journal(fixture.Identity, phase: 1, revision: 9);
        var journal = new GenesisAuthorJournalSnapshot(journalBytes);
        var observed = new byte[519];
        observed[454] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(observed.AsSpan(455, 8), 9);
        GenesisReplayPrimitives.JournalHash(journalBytes).CopyTo(observed, 463);
        BinaryPrimitives.WriteUInt64BigEndian(observed.AsSpan(495, 8), 1);
        BinaryPrimitives.WriteUInt64BigEndian(observed.AsSpan(511, 8), 1);
        var snapshot = new VerifiedGenesisReplayHeadSnapshot(observed, 0);
        var keyRequest = KeyRequest(fixture);
        var keyRegistry = new StableKeyRegistry();
        var hmac = new DeterministicHmac();
        var provider = new AtomicLatchJournal();

        await GenesisReplayVerifier.LatchForkAsync(
            fixture.Identity, journal, snapshot, 3, provider, fixture.KeySet,
            keyRegistry, keyRequest, new FixedTimePolicy(7, 93), 7, 100,
            hmac, default);

        var local = new GenesisReplayLocalHeadData(
            [], new byte[38], new byte[32], 1, provider.StoredJournal!, 10);
        var latched = new GenesisAuthorJournalSnapshot(
            provider.StoredJournal!, requireUnlatched: false);
        await GenesisReplayVerifier.VerifyRestoredForkLatchAsync(
            fixture.Identity, latched, local,
            new GenesisReplayScopeV1(GenesisReplayPrimitives.Scope(fixture.Identity), 1, 99),
            provider, fixture.KeySet, keyRegistry, keyRequest, hmac, default);

        Assert.Equal(5, hmac.Domains.Count(domain =>
            domain is "Deep/ProtectedState/V1/GFL1" or "Deep/ProtectedState/V1/GAJ1"));
        Assert.Equal(4, keyRegistry.Calls);
    }

    [Fact]
    public async Task ForkLatch_ExpiryRejectsBeforeOrInsideAtomicMutationWithoutWrites()
    {
        var sealing = new GenesisRecoverySealerExact15Tests.SealingProvider([]);
        using var fixture = await GenesisRecoverySealerExact15Tests.SealerFixture.CreateAsync(
            sealing);
        var journal = new GenesisAuthorJournalSnapshot(
            Journal(fixture.Identity, phase: 1, revision: 9));
        var snapshot = new VerifiedGenesisReplayHeadSnapshot(Bytes(0xb2, 519), 20);
        var keyRequest = KeyRequest(fixture);
        var keyRegistry = new StableKeyRegistry();
        var hmac = new DeterministicHmac();
        var beforeMutation = new AtomicLatchJournal();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            GenesisReplayVerifier.LatchForkAsync(
                fixture.Identity, journal, snapshot, 1, beforeMutation,
                fixture.KeySet, keyRegistry, keyRequest,
                new FixedTimePolicy(10, 1), 9, 10, hmac, default).AsTask());
        Assert.Empty(beforeMutation.Requests);
        Assert.Null(beforeMutation.StoredGfl);
        Assert.Null(beforeMutation.StoredJournal);

        var atomicPredicate = new AtomicLatchJournal { ObservedAt = 10 };
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            GenesisReplayVerifier.LatchForkAsync(
                fixture.Identity, journal, snapshot, 1, atomicPredicate,
                fixture.KeySet, keyRegistry, keyRequest,
                new FixedTimePolicy(9, 1), 9, 10, hmac, default).AsTask());
        Assert.Single(atomicPredicate.Requests);
        Assert.Equal(10UL, atomicPredicate.Requests[0].MutationDeadlineUnixSeconds);
        Assert.Null(atomicPredicate.StoredGfl);
        Assert.Null(atomicPredicate.StoredJournal);
    }

    private static GenesisReplayExternalHeadData Head(
        IReadOnlyList<ReadOnlyMemory<byte>> artifacts,
        byte[] dplReference,
        byte[] source,
        ulong revision,
        ulong lease) =>
        new(1, artifacts, dplReference, source, revision, lease);

    private static ReadOnlyMemory<byte>[] MinimumArtifactTuple(byte seed) =>
    [
        Bytes(seed, 482),
        Bytes(checked((byte)(seed + 1)), 706),
        Bytes(checked((byte)(seed + 2)), 706),
        Bytes(checked((byte)(seed + 3)), 706),
        Bytes(checked((byte)(seed + 4)), 706),
        Bytes(checked((byte)(seed + 5)), 839),
        Bytes(checked((byte)(seed + 6)), 414),
        Bytes(checked((byte)(seed + 7)), 375)
    ];

    private static ReadOnlyMemory<byte>[] ArtifactTuple(int drcLength, int dcqLength) =>
    [
        new byte[drcLength], new byte[706], new byte[706], new byte[706],
        new byte[706], new byte[839], new byte[414], new byte[dcqLength]
    ];

    private static byte[] Gfl(byte reason)
    {
        var value = new byte[GenesisProtectedRecords.GflLength];
        "GFL1"u8.CopyTo(value);
        value[4] = 1;
        value.AsSpan(8, 122).Fill(0x71);
        value[130] = reason;
        value.AsSpan(131, 32).Fill(0x72);
        BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(163, 8), 4);
        value.AsSpan(1064, 32).Fill(0x73);
        BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(1096, 8), 5);
        BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(1104, 8), 6);
        value.AsSpan(1112, 32).Fill(0x74);
        value.AsSpan(1144, 32).Fill(0x75);
        return value;
    }

    private static byte[] Journal(
        GenesisIdentityContext identity,
        byte phase,
        ulong revision)
    {
        var value = new byte[GenesisProtectedRecords.GajLength];
        "GAJ1"u8.CopyTo(value); value[4] = 1;
        GenesisReplayPrimitives.Scope(identity).CopyTo(value, 8);
        value.AsSpan(130, 32).Fill(0x81);
        value.AsSpan(162, 32).Fill(0x82);
        value[194] = phase;
        value.AsSpan(195, 32).Fill(0x83);
        value.AsSpan(227, 38).Fill(0x84);
        for (var index = 0; index < 4; index++)
            value.AsSpan(265 + index * 38, 38).Fill(checked((byte)(0x85 + index)));
        value.AsSpan(417, 38).Fill(0x89);
        value.AsSpan(455, 38).Fill(0x8a);
        value.AsSpan(493, 32).Fill(0x8b);
        value.AsSpan(525, 32).Fill(0x8c);
        BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(557, 8), 2);
        value.AsSpan(775, 32).Fill(0x8d);
        BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(807, 8), revision);
        identity.ProtectedStateHmacKeyId.CopyTo(value.AsSpan(816));
        if (phase != 0)
        {
            value.AsSpan(565, 32).Fill(0x8e);
            value.AsSpan(597, 38).Fill(0x8f);
            value.AsSpan(635, 38).Fill(0x90);
            value.AsSpan(673, 32).Fill(0x91);
        }
        if (phase == 2)
        {
            value.AsSpan(635, 38).CopyTo(value.AsSpan(705));
            value.AsSpan(673, 32).CopyTo(value.AsSpan(743));
        }
        DeterministicHmac.Tag("Deep/ProtectedState/V1/GAJ1", value.AsSpan(0, 848))
            .CopyTo(value, 848);
        return value;
    }

    private static GenesisProtectedKeySetRequest KeyRequest(
        GenesisRecoverySealerExact15Tests.SealerFixture fixture) =>
        new(fixture.Identity.BaseIdentity.Network, fixture.Identity.BaseIdentity.ResetId,
            fixture.Intent.ComponentKind, fixture.Intent.ComponentSubject.Span,
            fixture.Identity.BaseIdentity.AccountGeneration);

    private static byte[] Bytes(byte value, int length)
    {
        var output = new byte[length];
        output.AsSpan().Fill(value);
        return output;
    }

    private sealed class ReplayHarness : IDisposable
    {
        private readonly GenesisRecoverySealerExact15Tests.SealerFixture _fixture;
        private readonly CallCounter _calls = new();

        private ReplayHarness(GenesisRecoverySealerExact15Tests.SealerFixture fixture) =>
            _fixture = fixture;

        internal int DownstreamCalls => _calls.Count;

        internal static async ValueTask<ReplayHarness> CreateAsync()
        {
            var sealing = new GenesisRecoverySealerExact15Tests.SealingProvider([]);
            return new ReplayHarness(
                await GenesisRecoverySealerExact15Tests.SealerFixture.CreateAsync(sealing));
        }

        internal ValueTask<GenesisReplayDisposition> RestoreAsync(
            GenesisReplayHeadProvider heads,
            GenesisReplayTimePolicy time,
            CancellationToken cancellationToken = default) =>
            RecoveryVerifier.RestoreGenesisAuthorReplayAsync(
                _fixture.Identity,
                _fixture.Intent,
                _fixture.Release,
                Uninitialized<GenesisResetReservationResult>(),
                _fixture.KeySet,
                new NeverKeyRegistry(_calls),
                _fixture.Protector,
                new NeverSealingProvider(_calls),
                _fixture.Source,
                new NeverArtifactStore(_calls),
                new NeverQuorumProvider(_calls),
                new NeverJournal(_calls),
                heads,
                time,
                new NeverRecoveryProvider(_calls),
                new NeverNonceLatch(_calls),
                new NeverHmacProvider(_calls),
                cancellationToken);

        public void Dispose() => _fixture.Dispose();
    }

    private sealed class MovingHeadProvider(Action? afterRead = null)
        : GenesisReplayHeadProvider
    {
        internal List<GenesisReplayScopeV1> Requests { get; } = [];

        public override ValueTask<GenesisReplayHeadReadResult> ReadLockedAsync(
            GenesisReplayScopeV1 request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            var local = new GenesisReplayLocalHeadData(
                [], new byte[38], new byte[32], 1, new byte[880], 1);
            var preliminary = new GenesisReplayExternalHeadData(
                0, [], new byte[38], new byte[32], 1, 0);
            var authoritative = new GenesisReplayExternalHeadData(
                1, MinimumArtifactTuple(0x91),
                Bytes(0x91, 38), Bytes(0x92, 32), 2, 200);
            afterRead?.Invoke();
            return ValueTask.FromResult(new GenesisReplayHeadReadResult(
                preliminary, local, authoritative));
        }
    }

    private sealed class BlockingHeadProvider : GenesisReplayHeadProvider
    {
        internal int Calls { get; private set; }
        public override async ValueTask<GenesisReplayHeadReadResult> ReadLockedAsync(
            GenesisReplayScopeV1 request,
            CancellationToken cancellationToken)
        {
            Calls++;
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("A cancelled head read resumed unexpectedly.");
        }
    }

    private sealed class StableRenewalHeadProvider(
        GenesisReplayExternalHeadData preliminary,
        GenesisReplayExternalHeadData authoritative) : GenesisReplayHeadProvider
    {
        internal int Calls { get; private set; }
        internal int MutationCalls { get; private set; }

        public override ValueTask<GenesisReplayHeadReadResult> ReadLockedAsync(
            GenesisReplayScopeV1 request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            var local = new GenesisReplayLocalHeadData(
                [], new byte[38], new byte[32], 1, new byte[880], 1);
            return ValueTask.FromResult(new GenesisReplayHeadReadResult(
                preliminary, local, authoritative));
        }
    }

    private sealed class FixedTimePolicy(ulong now, ulong timeout)
        : GenesisReplayTimePolicy
    {
        public override ulong GetUnixTimeSeconds() => now;
        public override ulong ReplayTimeoutSeconds => timeout;
    }

    private sealed class SequenceTimePolicy(
        ulong started,
        ulong timeout,
        params ulong[] later) : GenesisReplayTimePolicy
    {
        private readonly Queue<ulong> _times = new(new[] { started }.Concat(later));
        public override ulong GetUnixTimeSeconds() => _times.Dequeue();
        public override ulong ReplayTimeoutSeconds => timeout;
    }

    private sealed class CallCounter
    {
        internal int Count { get; private set; }
        internal T Unexpected<T>()
        {
            Count++;
            throw new InvalidOperationException("A movement-only replay called downstream state.");
        }
    }

    private sealed class NeverKeyRegistry(CallCounter calls)
        : GenesisProtectedKeySetRegistry
    {
        public override ValueTask<GenesisProtectedKeySetReadResult> ReadAsync(
            GenesisProtectedKeySetRequest request, CancellationToken cancellationToken) =>
            calls.Unexpected<ValueTask<GenesisProtectedKeySetReadResult>>();
    }

    private sealed class NeverSealingProvider(CallCounter calls) : RecoverySealingProvider
    {
        public override ValueTask<GenesisRecoveryProtectorReadResult> ReadAsync(
            GenesisRecoveryProtectorRequest request, CancellationToken cancellationToken) =>
            calls.Unexpected<ValueTask<GenesisRecoveryProtectorReadResult>>();
        public override ValueTask DeriveNonceAsync(
            RecoverySealRequest request, Memory<byte> derivedNonce24,
            CancellationToken cancellationToken) => calls.Unexpected<ValueTask>();
        public override ValueTask SealAsync(
            RecoverySealRequest request, ReadOnlyMemory<byte> plaintext,
            Memory<byte> ciphertextDestination, Memory<byte> authenticationTag16,
            CancellationToken cancellationToken) => calls.Unexpected<ValueTask>();
        public override ValueTask OpenAsync(
            RecoverySealRequest request, ReadOnlyMemory<byte> ciphertext,
            ReadOnlyMemory<byte> authenticationTag16, Memory<byte> plaintextDestination,
            CancellationToken cancellationToken) => calls.Unexpected<ValueTask>();
    }

    private sealed class NeverArtifactStore(CallCounter calls) : GenesisArtifactStore
    {
        public override ValueTask<GenesisArtifactStoreReadResult> StoreOrRestoreAsync(
            GenesisArtifactStoreRequest request, CancellationToken cancellationToken) =>
            calls.Unexpected<ValueTask<GenesisArtifactStoreReadResult>>();
    }

    private sealed class NeverQuorumProvider(CallCounter calls) : GenesisQuorumStateProvider
    {
        public override ValueTask<GenesisQuorumPendingReadResult> RestoreOrCreatePendingAsync(
            GenesisQuorumPendingRequest request, CancellationToken cancellationToken) =>
            calls.Unexpected<ValueTask<GenesisQuorumPendingReadResult>>();
    }

    private sealed class NeverJournal(CallCounter calls) : GenesisAuthorJournal
    {
        public override ValueTask<GenesisAuthorJournalReadResult> RestoreOrCreateCreatedAsync(
            GenesisAuthorJournalCreatedRequest request, CancellationToken cancellationToken) =>
            calls.Unexpected<ValueTask<GenesisAuthorJournalReadResult>>();
    }

    private sealed class NeverRecoveryProvider(CallCounter calls) : RecoveryProtectorProvider
    {
        public override ValueTask DeriveNonceAsync(
            RecoveryProviderRequest request, Memory<byte> derivedNonce24,
            CancellationToken cancellationToken) => calls.Unexpected<ValueTask>();
        public override ValueTask OpenAsync(
            RecoveryProviderRequest request, Memory<byte> plaintextDestination,
            CancellationToken cancellationToken) => calls.Unexpected<ValueTask>();
    }

    private sealed class NeverNonceLatch(CallCounter calls) : RecoveryNonceLatch
    {
        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request, CancellationToken cancellationToken) =>
            calls.Unexpected<ValueTask<RecoveryNonceLatchDecision>>();
    }

    private sealed class NeverHmacProvider(CallCounter calls) : IProtectedHmacProvider
    {
        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request, CancellationToken cancellationToken) =>
            calls.Unexpected<ValueTask<ReadOnlyMemory<byte>>>();
    }

    private sealed class StableKeyRegistry : GenesisProtectedKeySetRegistry
    {
        internal int Calls { get; private set; }
        public override ValueTask<GenesisProtectedKeySetReadResult> ReadAsync(
            GenesisProtectedKeySetRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            var scope = new byte[GenesisProtectedKeySetContext.ExactScopeLength];
            request.ExactScopeAxes.Span.CopyTo(scope);
            BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(90, 2), 6);
            for (var index = 0; index < 6; index++)
            {
                var offset = 92 + index * 34;
                BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(offset, 2),
                    checked((ushort)(index + 1)));
                scope.AsSpan(offset + 2, 32).Fill(checked((byte)(0x61 + index)));
            }
            return ValueTask.FromResult(new GenesisProtectedKeySetReadResult(
                scope, 1, Enumerable.Repeat(true, 6).ToArray()));
        }
    }

    private sealed class DeterministicHmac : IProtectedHmacProvider
    {
        internal List<string> Domains { get; } = [];
        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request,
            CancellationToken cancellationToken)
        {
            Domains.Add(request.Domain);
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                Tag(request.Domain, request.UnsignedCanonical.Span));
        }

        internal static byte[] Tag(string domain, ReadOnlySpan<byte> unsigned) =>
            CanonicalGrammar.Sha256Domain($"Test/DRM19/{domain}", unsigned);
    }

    private sealed class AtomicLatchJournal : GenesisAuthorJournal
    {
        internal List<GenesisReplayForkLatchRequest> Requests { get; } = [];
        internal byte[]? StoredGfl { get; private set; }
        internal byte[]? StoredJournal { get; private set; }
        internal bool ReturnGflOnlyHalfWrite { get; init; }
        internal bool ReturnJournalOnlyHalfWrite { get; init; }
        internal ulong ObservedAt { get; init; } = 7;

        public override ValueTask<GenesisAuthorJournalReadResult> RestoreOrCreateCreatedAsync(
            GenesisAuthorJournalCreatedRequest request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Created authoring is outside this latch test.");

        public override ValueTask<GenesisReplayForkLatchReadResult> LatchReplayForkAsync(
            GenesisReplayForkLatchRequest request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (ObservedAt >= request.MutationDeadlineUnixSeconds)
                throw new OperationCanceledException(
                    "The atomic replay latch deadline expired before mutation.");
            if (StoredGfl is null)
            {
                var expected = request.ExpectedJournal.ToArray();
                var revision = checked(BinaryPrimitives.ReadUInt64BigEndian(
                    expected.AsSpan(807, 8)) + 1);
                StoredJournal = expected.ToArray();
                BinaryPrimitives.WriteUInt64BigEndian(
                    StoredJournal.AsSpan(807, 8), revision);
                StoredJournal[815] = 1;
                DeterministicHmac.Tag("Deep/ProtectedState/V1/GAJ1",
                    StoredJournal.AsSpan(0, 848)).CopyTo(StoredJournal, 848);

                StoredGfl = new byte[GenesisProtectedRecords.GflLength];
                "GFL1"u8.CopyTo(StoredGfl); StoredGfl[4] = 1;
                request.EvidenceTranscript.Span.CopyTo(StoredGfl.AsSpan(8));
                request.EvidenceHash.Span.CopyTo(StoredGfl.AsSpan(1064));
                BinaryPrimitives.WriteUInt64BigEndian(
                    StoredGfl.AsSpan(1096, 8), revision);
                BinaryPrimitives.WriteUInt64BigEndian(
                    StoredGfl.AsSpan(1104, 8), ObservedAt);
                expected.AsSpan(816, 32).CopyTo(StoredGfl.AsSpan(1112));
                DeterministicHmac.Tag("Deep/ProtectedState/V1/GFL1",
                    StoredGfl.AsSpan(0, 1144)).CopyTo(StoredGfl, 1144);
            }

            var gfl = ReturnJournalOnlyHalfWrite
                ? new byte[GenesisProtectedRecords.GflLength]
                : StoredGfl;
            var journal = ReturnGflOnlyHalfWrite
                ? request.ExpectedJournal.ToArray()
                : StoredJournal;
            return ValueTask.FromResult(new GenesisReplayForkLatchReadResult(
                gfl!, journal!, healthy: true));
        }

        public override ValueTask<GenesisReplayForkLatchReadResult> RestoreReplayForkAsync(
            GenesisReplayScopeV1 scope,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(new GenesisReplayForkLatchReadResult(
                StoredGfl!, StoredJournal!, healthy: true));
    }

    private static T Uninitialized<T>() where T : class =>
        (T)RuntimeHelpers.GetUninitializedObject(typeof(T));
}
