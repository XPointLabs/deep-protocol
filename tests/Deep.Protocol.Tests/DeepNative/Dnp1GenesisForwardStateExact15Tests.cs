using System.Buffers.Binary;
using Drm3Fixture = Deep.Protocol.Tests.DeepNative.Drm3Fixture;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisForwardStateExact15Tests
{
    [Fact]
    public async Task ArtifactStore_UsesExactTransactionScopeAndVerifiesGasHmacAndReread()
    {
        using var state = await ForwardFixture.CreateAsync();
        var hmac = new FixedHmac();
        var store = new ArtifactStoreProvider(state.Plan, state.Identity);

        var verified = await RecoveryVerifier.StoreGenesisArtifactSetAsync(
            state.Plan, state.Identity, store, hmac);

        Assert.Equal(1, store.Calls);
        Assert.NotNull(store.Request);
        Assert.Equal(122, store.Request!.ExactScope.Length);
        Assert.Equal(state.Identity.Transaction.TransactionId.ToArray(),
            store.Request.ExactScope.Span.Slice(90, 32).ToArray());
        Assert.NotEqual(state.Identity.Scope.ExactScope.Slice(90, 32).ToArray(),
            store.Request.ExactScope.Span.Slice(90, 32).ToArray());
        Assert.Equal(7, store.Request.CanonicalArtifacts.Count);
        Assert.Equal(GenesisProtectedRecords.GasLength,
            verified.Receipt.CanonicalReceipt.Length);
        Assert.Equal(state.Plan.CandidateCoreFingerprint.ToArray(),
            verified.Receipt.CanonicalReceipt.Span.Slice(164, 32).ToArray());
        Assert.Equal((ushort)7, BinaryPrimitives.ReadUInt16BigEndian(
            verified.Receipt.CanonicalReceipt.Span.Slice(130, 2)));
        Assert.Equal(state.Plan.TotalBytes, BinaryPrimitives.ReadUInt64BigEndian(
            verified.Receipt.CanonicalReceipt.Span.Slice(196, 8)));
        Assert.Equal(1UL, verified.SourceRevision);
        Assert.True(verified.GetType().IsSealed);
        Assert.Empty(verified.GetType().GetConstructors());
        Assert.Equal(new[] { "Deep/ProtectedState/V1/GAS1" }, hmac.Domains);
        Assert.True(verified.NoAuthorityClaim);
    }

    [Fact]
    public async Task QuorumPending_UsesExactStableScopeOperationAndGqpHmac()
    {
        using var state = await ForwardFixture.CreateAsync();
        var hmac = new FixedHmac();
        var provider = new QuorumProvider(state.Identity);
        var selected = WitnessIds();

        var pending = await RecoveryVerifier.RestoreOrCreateGenesisQuorumPendingAsync(
            state.Plan, state.Release, selected, provider, hmac);

        Assert.Equal(1, provider.PendingCalls);
        Assert.NotNull(provider.PendingRequest);
        Assert.Equal(150, provider.PendingRequest!.ExactStableScope.Length);
        Assert.Equal(339, provider.PendingRequest.ExactOperation.Length);
        Assert.Equal(state.Identity.Transaction.TransactionId.ToArray(),
            provider.PendingRequest.ExactStableScope.Span.Slice(118, 32).ToArray());
        Assert.Equal(selected.Select(value => value.ToArray()),
            Enumerable.Range(0, 3).Select(index =>
                provider.PendingRequest.ExactOperation.Span
                    .Slice(243 + index * 32, 32).ToArray()));
        Assert.Equal(provider.PendingRequest.OperationHash.ToArray(),
            pending.CanonicalPending.Span.Slice(347, 32).ToArray());
        Assert.Equal(new[] { "Deep/ProtectedState/V1/GQP1" }, hmac.Domains);
    }

    [Fact]
    public async Task QuorumSelectionRequest_BindsGqsHeaderPendingIdsDcnRefsAndDcq()
    {
        using var state = await ForwardFixture.CreateAsync();
        var hmac = new FixedHmac();
        var provider = new QuorumProvider(state.Identity);
        var pending = await RecoveryVerifier.RestoreOrCreateGenesisQuorumPendingAsync(
            state.Plan, state.Release, WitnessIds(), provider, hmac);
        var dcqReference = Reference(ArtifactType.Dcq1, new byte[375]);
        var unsigned = UnsignedSelection(
            pending, state.Identity, dcqReference);

        var request = new GenesisQuorumSelectionRequest(pending.PendingHash.Span, unsigned);

        Assert.Equal("GQS1"u8.ToArray(), request.UnsignedSelection.Span[..4].ToArray());
        Assert.Equal((byte)1, request.UnsignedSelection.Span[4]);
        Assert.Equal(new byte[3], request.UnsignedSelection.Span.Slice(5, 3).ToArray());
        Assert.Equal(pending.PendingHash.ToArray(), request.PendingHash.ToArray());
        for (var index = 0; index < 3; index++)
        {
            Assert.Equal(pending.CanonicalPending.Span.Slice(251 + index * 32, 32).ToArray(),
                request.UnsignedSelection.Span.Slice(251 + index * 70, 32).ToArray());
            Assert.Equal(Drm3Fixture.Fill(checked((byte)(0xa1 + index)), 38),
                request.UnsignedSelection.Span.Slice(283 + index * 70, 38).ToArray());
        }
        Assert.Equal(dcqReference,
            request.UnsignedSelection.Span.Slice(461, 38).ToArray());

        var exposed = request.UnsignedSelection.ToArray();
        exposed[0] ^= 1;
        Assert.Equal((byte)'G', request.UnsignedSelection.Span[0]);
    }

    [Fact]
    public async Task AuthorJournal_AdvancesCreatedExternalLocalByOneExactRevisionAndHmac()
    {
        using var state = await ForwardFixture.CreateAsync();
        var hmac = new FixedHmac();
        var store = new ArtifactStoreProvider(state.Plan, state.Identity);
        var artifactSet = await RecoveryVerifier.StoreGenesisArtifactSetAsync(
            state.Plan, state.Identity, store, hmac);
        var quorumProvider = new QuorumProvider(state.Identity);
        var pending = await RecoveryVerifier.RestoreOrCreateGenesisQuorumPendingAsync(
            state.Plan, state.Release, WitnessIds(), quorumProvider, hmac);
        var reservation = Reservation(state.Identity);
        var journal = new JournalProvider(state.Identity);
        var created = await RecoveryVerifier.RestoreOrCreateGenesisAuthorCreatedAsync(
            state.Plan, artifactSet, pending, reservation, journal, hmac);

        var dcq = Canonical(RecordDefinitions.Dct1, 0xb1);
        var dcqRef = Reference(ArtifactType.Dcq1, dcq);
        var selection = new GenesisQuorumSelection(
            CompleteSelection(pending, state.Identity, dcqRef));
        var quorum = new GenesisVerifiedQuorumPlan(
            new QuorumReceipt(CanonicalGrammar.DecodeOwned(dcq, RecordDefinitions.Dct1)),
            selection);
        var dpl = Drm3Fixture.Fill(0xb2, 576);
        var dplRef = Reference(ArtifactType.Dpl1, dpl);
        var materialization = new RecoveryMaterializationPlan(
            dpl, new byte[70], dplRef);
        var coordinator = new CommitCoordinator(dplRef, state.Source.SourceFingerprint.ToArray());

        var external = await GenesisCutoverCommitVerifier.CommitExternalStructuralTestAsync(
            created, quorum, materialization, state.Source, coordinator, journal, hmac);
        var local = await GenesisCutoverCommitVerifier.CommitLocalStructuralTestAsync(
            external, coordinator, journal, hmac);

        Assert.Equal((byte)0, created.Journal.CanonicalJournal.Span[194]);
        Assert.Equal((byte)1, external.Journal.CanonicalJournal.Span[194]);
        Assert.Equal((byte)2, local.Journal.CanonicalJournal.Span[194]);
        Assert.Equal(new ulong[] { 1, 2, 3 },
            new[] { created.JournalRevision, external.JournalRevision, local.JournalRevision });
        Assert.Equal(2, journal.TransitionCalls);
        Assert.Equal(new byte[] { 1, 2 }, journal.NextPhases);
        Assert.Equal(3, hmac.Domains.Count(domain =>
            domain == "Deep/ProtectedState/V1/GAJ1"));
        Assert.Equal(dplRef,
            local.Journal.CanonicalJournal.Span.Slice(705, 38).ToArray());
        Assert.Equal(state.Source.SourceFingerprint.ToArray(),
            local.Journal.CanonicalJournal.Span.Slice(743, 32).ToArray());
        Assert.True(created.NoAuthorityClaim);
        Assert.True(external.NoAuthorityClaim);
        Assert.True(local.NoAuthorityClaim);

        var skippedPrefix = created.Journal.CanonicalJournal.Span[..807].ToArray();
        skippedPrefix[194] = 2;
        Assert.Throws<RecordException>(() => new GenesisAuthorJournalTransitionRequest(
            created.Journal.CanonicalJournal.Span, skippedPrefix));

        var mutatedJournal = new JournalProvider(state.Identity)
        {
            MutateUnchangedAxisOnTransition = true
        };
        await Assert.ThrowsAsync<RecordException>(() =>
            GenesisCutoverCommitVerifier.CommitExternalStructuralTestAsync(
                created, quorum, materialization, state.Source, coordinator,
                mutatedJournal, hmac).AsTask());
        Assert.Equal(3, hmac.Domains.Count(domain =>
            domain == "Deep/ProtectedState/V1/GAJ1"));
    }

    private sealed class ForwardFixture : IDisposable
    {
        private readonly GenesisRecoverySealerExact15Tests.SealerFixture _sealer;
        private ForwardFixture(
            GenesisRecoverySealerExact15Tests.SealerFixture sealer,
            SealedGenesisRecoveryCandidate candidate,
            GenesisPreExternalCandidatePlan plan)
        { _sealer = sealer; Candidate = candidate; Plan = plan; }

        internal SealedGenesisRecoveryCandidate Candidate { get; }
        internal GenesisPreExternalCandidatePlan Plan { get; }
        internal GenesisIdentityContext Identity => _sealer.Identity;
        internal GenesisReleaseContext Release => _sealer.Release;
        internal GenesisCutoverSourceContext Source => _sealer.Source;

        internal static async ValueTask<ForwardFixture> CreateAsync()
        {
            var sealing = new GenesisRecoverySealerExact15Tests.SealingProvider([]);
            var sealer = await GenesisRecoverySealerExact15Tests.SealerFixture.CreateAsync(sealing);
            var candidate = await sealer.SealAsync(sealing,
                new StoredLatch());
            var checkpoints = Enumerable.Range(1, 4).Select(index =>
                new ComponentCheckpoint(CanonicalGrammar.DecodeOwned(
                    CanonicalDcp(index, checked((byte)(0x41 + index))),
                    RecordDefinitions.Dcp1))).ToArray();
            var deployment = new DeploymentSet(CanonicalGrammar.DecodeOwned(
                Canonical(RecordDefinitions.Dcs1, 0x51), RecordDefinitions.Dcs1));
            var transaction = new CasTranscript(CanonicalGrammar.DecodeOwned(
                Canonical(RecordDefinitions.Dct1, 0x52), RecordDefinitions.Dct1));
            var total = checked((ulong)(candidate.Capsule.CanonicalBytes.Length +
                checkpoints.Sum(value => value.CanonicalBytes.Length) +
                deployment.CanonicalBytes.Length + transaction.CanonicalBytes.Length));
            var plan = new GenesisPreExternalCandidatePlan(candidate, sealer.Identity,
                checkpoints, deployment, transaction, Drm3Fixture.Fill(0x53, 32),
                Drm3Fixture.Fill(0x54, 32), Drm3Fixture.Fill(0x55, 32), total);
            return new ForwardFixture(sealer, candidate, plan);
        }

        public void Dispose()
        {
            Candidate.Dispose();
            _sealer.Dispose();
        }
    }

    private sealed class ArtifactStoreProvider(
        GenesisPreExternalCandidatePlan plan,
        GenesisIdentityContext identity) : GenesisArtifactStore
    {
        internal int Calls { get; private set; }
        internal GenesisArtifactStoreRequest? Request { get; private set; }
        public override ValueTask<GenesisArtifactStoreReadResult> StoreOrRestoreAsync(
            GenesisArtifactStoreRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            Request = request;
            var gas = new byte[GenesisProtectedRecords.GasLength];
            "GAS1"u8.CopyTo(gas); gas[4] = 1;
            request.ExactScope.Span.CopyTo(gas.AsSpan(8));
            BinaryPrimitives.WriteUInt16BigEndian(gas.AsSpan(130, 2), 7);
            plan.ArtifactInventoryHash.Span.CopyTo(gas.AsSpan(132));
            plan.CandidateCoreFingerprint.Span.CopyTo(gas.AsSpan(164));
            U64(gas, 196, plan.TotalBytes); U64(gas, 204, 1); U64(gas, 212, 2);
            gas[220] = 1;
            identity.ProtectedStateHmacKeyId.CopyTo(gas.AsSpan(221));
            gas.AsSpan(253, 32).Fill(FixedHmac.Marker);
            return ValueTask.FromResult(new GenesisArtifactStoreReadResult(
                gas, request.CanonicalArtifacts, 1, healthy: true));
        }
    }

    private sealed class QuorumProvider(GenesisIdentityContext identity)
        : GenesisQuorumStateProvider
    {
        internal int PendingCalls { get; private set; }
        internal GenesisQuorumPendingRequest? PendingRequest { get; private set; }
        public override ValueTask<GenesisQuorumPendingReadResult> RestoreOrCreatePendingAsync(
            GenesisQuorumPendingRequest request,
            CancellationToken cancellationToken)
        {
            PendingCalls++;
            PendingRequest = request;
            var gqp = new byte[GenesisProtectedRecords.GqpLength];
            "GQP1"u8.CopyTo(gqp); gqp[4] = 1;
            request.ExactOperation.Span.CopyTo(gqp.AsSpan(8));
            request.OperationHash.Span.CopyTo(gqp.AsSpan(347));
            U64(gqp, 379, 1); U64(gqp, 387, 2); gqp[395] = 1;
            identity.ProtectedStateHmacKeyId.CopyTo(gqp.AsSpan(397));
            gqp.AsSpan(429, 32).Fill(FixedHmac.Marker);
            return ValueTask.FromResult(
                new GenesisQuorumPendingReadResult(gqp, 1, healthy: true));
        }
    }

    private sealed class JournalProvider(GenesisIdentityContext identity)
        : GenesisAuthorJournal
    {
        internal bool MutateUnchangedAxisOnTransition { get; init; }
        internal int TransitionCalls { get; private set; }
        internal List<byte> NextPhases { get; } = [];
        public override ValueTask<GenesisAuthorJournalReadResult> RestoreOrCreateCreatedAsync(
            GenesisAuthorJournalCreatedRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(Result(request.ImmutableCreatedTranscript.Span, 1));

        public override ValueTask<GenesisAuthorJournalReadResult> CompareExchangeAsync(
            GenesisAuthorJournalTransitionRequest request,
            CancellationToken cancellationToken)
        {
            TransitionCalls++;
            NextPhases.Add(request.NextImmutableTranscript.Span[194]);
            var revision = checked(BinaryPrimitives.ReadUInt64BigEndian(
                request.ExpectedJournal.Span.Slice(807, 8)) + 1);
            return ValueTask.FromResult(Result(request.NextImmutableTranscript.Span, revision));
        }

        private GenesisAuthorJournalReadResult Result(ReadOnlySpan<byte> prefix, ulong revision)
        {
            var gaj = new byte[GenesisProtectedRecords.GajLength];
            prefix.CopyTo(gaj);
            if (MutateUnchangedAxisOnTransition && prefix[194] != 0)
                gaj[8] ^= 1;
            U64(gaj, 807, revision);
            identity.ProtectedStateHmacKeyId.CopyTo(gaj.AsSpan(816));
            gaj.AsSpan(848, 32).Fill(FixedHmac.Marker);
            return new GenesisAuthorJournalReadResult(gaj, revision, healthy: true);
        }
    }

    private sealed class CommitCoordinator(byte[] dplReference, byte[] source)
        : GenesisCutoverCommitCoordinator
    {
        public override ValueTask<GenesisCutoverCommitReadResult> CompareExternalZeroToOneAsync(
            GenesisExternalCutoverCommitRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(new GenesisCutoverCommitReadResult(
                true, dplReference, source, 1));
        public override ValueTask<GenesisCutoverCommitReadResult> CompareLocalEmptyToCandidateAsync(
            GenesisLocalCutoverCommitRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(new GenesisCutoverCommitReadResult(
                true, dplReference, source, 2));
    }

    private sealed class FixedHmac : IProtectedHmacProvider
    {
        internal const byte Marker = 0xa5;
        internal List<string> Domains { get; } = [];
        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request,
            CancellationToken cancellationToken)
        {
            Domains.Add(request.Domain);
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                Drm3Fixture.Fill(Marker, 32));
        }
    }

    private sealed class StoredLatch : RecoveryNonceLatch
    {
        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(RecoveryNonceLatchDecision.Stored);
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> WitnessIds() =>
    [
        Drm3Fixture.Fill(0x81, 32),
        Drm3Fixture.Fill(0x82, 32),
        Drm3Fixture.Fill(0x83, 32)
    ];

    private static GenesisResetReservationResult Reservation(GenesisIdentityContext identity)
    {
        var grr = new byte[GenesisProtectedRecords.GrrLength];
        "GRR1"u8.CopyTo(grr); grr[4] = 1; grr[8] = 1;
        identity.BaseIdentity.Network.CopyTo(grr.AsSpan(9));
        grr.AsSpan(57, 32).Fill(0xc1); U64(grr, 89, 1);
        grr.AsSpan(135, 38).Fill(0xc2); grr.AsSpan(243, 32).Fill(0xc3);
        identity.BaseIdentity.ResetId.CopyTo(grr.AsSpan(275));
        grr[307] = 1; U64(grr, 308, 1);
        identity.ProtectedStateHmacKeyId.CopyTo(grr.AsSpan(317));
        grr.AsSpan(349, 32).Fill(FixedHmac.Marker);
        var gri = new byte[GenesisProtectedRecords.GriLength];
        "GRI1"u8.CopyTo(gri); gri[4] = 1;
        gri.AsSpan(8, 64).Fill(0xc4); grr.AsSpan(243, 32).CopyTo(gri.AsSpan(72));
        GenesisProtectedRecords.ReservationHash(grr).CopyTo(gri, 104);
        U64(gri, 136, 1); U64(gri, 144, 2);
        identity.ProtectedStateHmacKeyId.CopyTo(gri.AsSpan(153));
        gri.AsSpan(185, 32).Fill(FixedHmac.Marker);
        return new GenesisResetReservationResult(gri, grr);
    }

    private static byte[] CompleteSelection(
        GenesisQuorumPending pending,
        GenesisIdentityContext identity,
        ReadOnlySpan<byte> dcqReference)
    {
        var canonical = new byte[GenesisProtectedRecords.GqsLength];
        UnsignedSelection(pending, identity, dcqReference).CopyTo(canonical, 0);
        canonical.AsSpan(548, 32).Fill(FixedHmac.Marker);
        return canonical;
    }

    private static byte[] UnsignedSelection(
        GenesisQuorumPending pending,
        GenesisIdentityContext identity,
        ReadOnlySpan<byte> dcqReference)
    {
        var pendingBytes = pending.CanonicalPending.Span;
        var unsigned = new byte[GenesisProtectedRecords.GqsLength - 32];
        "GQS1"u8.CopyTo(unsigned); unsigned[4] = 1;
        pendingBytes.Slice(8, 243).CopyTo(unsigned.AsSpan(8));
        for (var index = 0; index < 3; index++)
        {
            pendingBytes.Slice(251 + index * 32, 32)
                .CopyTo(unsigned.AsSpan(251 + index * 70));
            unsigned.AsSpan(283 + index * 70, 38)
                .Fill(checked((byte)(0xa1 + index)));
        }
        dcqReference.CopyTo(unsigned.AsSpan(461));
        U64(unsigned, 499, 2); U64(unsigned, 507, 3);
        identity.ProtectedStateHmacKeyId.CopyTo(unsigned.AsSpan(516));
        return unsigned;
    }

    private static byte[] Canonical(RecordDefinition definition, byte marker)
    {
        var fields = definition.Fields.Select(field =>
            (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        if (fields.Length > 0 && fields[0].Length > 0)
            fields[0] = Drm3Fixture.Fill(marker, fields[0].Length);
        if (definition.Magic == "DCS1")
        {
            fields[9] = new byte[] { 4 };
            var rows = new byte[416];
            for (var index = 0; index < 4; index++)
                BinaryPrimitives.WriteUInt16BigEndian(rows.AsSpan(index * 104, 2),
                    checked((ushort)(index + 1)));
            fields[10] = rows;
        }
        return CanonicalGrammar.Encode(definition, fields);
    }

    private static byte[] CanonicalDcp(int kind, byte marker)
    {
        var fields = RecordDefinitions.Dcp1.Fields.Select(field =>
            (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        fields[0] = Drm3Fixture.Fill(marker, fields[0].Length);
        fields[1] = Drm3Fixture.Fill(marker, fields[1].Length);
        fields[2] = U16(checked((ushort)kind));
        return CanonicalGrammar.Encode(RecordDefinitions.Dcp1, fields);
    }

    private static byte[] Reference(ArtifactType type, ReadOnlySpan<byte> canonical) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, canonical));

    private static void U64(byte[] destination, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64BigEndian(destination.AsSpan(offset, 8), value);

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }
}
