using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Drm3Fixture = Deep.Protocol.Tests.DeepNative.Drm3Fixture;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisRecoverySealerExact15Tests
{
    [Fact]
    public async Task SealCandidate_SelfChecksExactRetryAndZeroesOnSuccessMutationOrCancellation()
    {
        await LatchPrecedesExactlyOneSealAndSelfOpen_AndExactRetryIsByteIdentical();
        await CancellationAfterDurableLatch_RejectsBeforeSealAndPreservesExactIntent();
        await MutableOrIncorrectSelfOpen_FailsClosedAndZeroesProviderPlaintext();
    }

    [Fact]
    public async Task LatchPrecedesExactlyOneSealAndSelfOpen_AndExactRetryIsByteIdentical()
    {
        var events = new List<string>();
        var provider = new SealingProvider(events);
        using var fixture = await SealerFixture.CreateAsync(provider);
        var latch = new Latch(events,
            RecoveryNonceLatchDecision.Stored,
            RecoveryNonceLatchDecision.ExactReplay);

        using var first = await fixture.SealAsync(provider, latch);
        var firstCanonical = first.Capsule.CanonicalBytes.ToArray();
        using var replay = await fixture.SealAsync(provider, latch);

        Assert.Equal(new[]
        {
            "derive", "latch", "seal", "open",
            "derive", "latch", "seal", "open"
        }, events);
        Assert.Equal(2, provider.SealCalls);
        Assert.Equal(2, provider.OpenCalls);
        Assert.Equal(firstCanonical, replay.Capsule.CanonicalBytes.ToArray());
        Assert.Equal(latch.Requests[0], latch.Requests[1]);
        Assert.All(provider.CapturedPlaintexts, plaintext =>
            Assert.All(plaintext.ToArray(), value => Assert.Equal((byte)0, value)));

        Assert.True(first.NoAuthorityClaim);
        Assert.Equal(fixture.PlaintextHash, first.ManifestHash.ToArray());
        var returnedHash = first.ManifestHash;
        Assert.True(MemoryMarshal.TryGetArray(returnedHash, out var returnedHashArray));
        returnedHashArray.Array![returnedHashArray.Offset] ^= 1;
        Assert.Equal(fixture.PlaintextHash, first.ManifestHash.ToArray());

        var frozenCapsule = first.Capsule.CanonicalBytes.ToArray();
        provider.CapturedCiphertexts[0].Span.Fill(0xee);
        Assert.Equal(frozenCapsule, first.Capsule.CanonicalBytes.ToArray());

        first.Dispose();
        Assert.Throws<ObjectDisposedException>(() => first.Manifest.ToArray());
    }

    [Fact]
    public async Task ForkLatch_RejectsBeforeSealOrOpen()
    {
        var events = new List<string>();
        var provider = new SealingProvider(events);
        using var fixture = await SealerFixture.CreateAsync(provider);
        var latch = new Latch(events, RecoveryNonceLatchDecision.ForkLatched);

        await Assert.ThrowsAsync<RecordException>(() =>
            fixture.SealAsync(provider, latch).AsTask());

        Assert.Equal(new[] { "derive", "latch" }, events);
        Assert.Equal(0, provider.SealCalls);
        Assert.Equal(0, provider.OpenCalls);
        Assert.Single(latch.Requests);
    }

    [Fact]
    public async Task SealIntent_UsesExactV5TranscriptAndDurableLatchBeforeAead()
    {
        var events = new List<string>();
        var provider = new SealingProvider(events);
        using var fixture = await SealerFixture.CreateAsync(provider);
        var latch = new Latch(events, RecoveryNonceLatchDecision.Stored);

        using var candidate = await fixture.SealAsync(provider, latch);

        Assert.Equal(new[] { "derive", "latch", "seal", "open" }, events);
        Assert.Single(latch.Requests);
        Assert.Single(provider.SealRequests);
        Assert.Equal(ExpectedSealIntent(
                fixture.Plaintext, provider.SealRequests[0], Drm3Fixture.Fill(0x73, 24)),
            latch.Requests[0][88..120]);
    }

    [Fact]
    public async Task CancellationAfterDurableLatch_RejectsBeforeSealAndPreservesExactIntent()
    {
        var events = new List<string>();
        var provider = new SealingProvider(events);
        using var fixture = await SealerFixture.CreateAsync(provider);
        using var cancellation = new CancellationTokenSource();
        var latch = new Latch(events, RecoveryNonceLatchDecision.Stored)
        {
            CancelAfterStore = cancellation
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            fixture.SealAsync(provider, latch, cancellation.Token).AsTask());

        Assert.Equal(new[] { "derive", "latch" }, events);
        Assert.Equal(0, provider.SealCalls);
        Assert.Equal(0, provider.OpenCalls);
        Assert.Single(latch.Requests);
        Assert.Equal(RecoveryNonceLatchRequest.ExactLength, latch.Requests[0].Length);
        Assert.Equal(Drm3Fixture.Fill(0x72, 32), latch.Requests[0][..32]);
        Assert.Equal(Drm3Fixture.Fill(0x71, 32), latch.Requests[0][32..64]);
        Assert.Equal(Drm3Fixture.Fill(0x73, 24), latch.Requests[0][64..88]);
        Assert.Contains(latch.Requests[0][88..], static value => value != 0);
    }

    [Fact]
    public async Task MutableOrIncorrectSelfOpen_FailsClosedAndZeroesProviderPlaintext()
    {
        var events = new List<string>();
        var provider = new SealingProvider(events) { CorruptSelfOpen = true };
        using var fixture = await SealerFixture.CreateAsync(provider);
        var latch = new Latch(events, RecoveryNonceLatchDecision.Stored);

        var error = await Assert.ThrowsAsync<RecordException>(() =>
            fixture.SealAsync(provider, latch).AsTask());

        Assert.Equal(RecordError.InvalidSignature, error.Error);
        Assert.Equal(new[] { "derive", "latch", "seal", "open" }, events);
        Assert.Equal(1, provider.SealCalls);
        Assert.Equal(1, provider.OpenCalls);
        Assert.Single(provider.CapturedPlaintexts);
        Assert.All(provider.CapturedPlaintexts[0].ToArray(), value =>
            Assert.Equal((byte)0, value));
        Assert.All(provider.CapturedCiphertexts[0].ToArray(), value =>
            Assert.Equal((byte)0, value));
    }

    [Fact]
    public async Task ProtectorRead_RejectsShortIdsAndOwnsPostReturnMutation()
    {
        var shortProvider = new SealingProvider([], protectorLength: 31);
        await Assert.ThrowsAsync<RecordException>(() =>
            SealerFixture.CreateAsync(shortProvider).AsTask());

        var mutableProvider = new SealingProvider([])
        {
            MutateReadInputsAfterSnapshot = true
        };
        using var fixture = await SealerFixture.CreateAsync(mutableProvider);

        Assert.Equal(Drm3Fixture.Fill(0x71, 32),
            fixture.Protector.ProtectorKeyId.ToArray());
        Assert.Equal(Drm3Fixture.Fill(0x72, 32),
            fixture.Protector.RecoveryNonceLatchKeyId.ToArray());
    }

    internal sealed class SealerFixture : IDisposable
    {
        private const ulong CreatedAt = 1_000;
        private const ulong RetainUntil = 2_000;

        private SealerFixture(
            OwnedGenesisRecoveryManifest manifest,
            GenesisIdentityContext identity,
            GenesisComponentIntent intent,
            GenesisReleaseContext release,
            GenesisCutoverSourceContext source,
            GenesisRecoveryProtectorContext protector,
            GenesisProtectedKeySetContext keySet)
        {
            Manifest = manifest;
            Identity = identity;
            Intent = intent;
            Release = release;
            Source = source;
            Protector = protector;
            KeySet = keySet;
            PlaintextHash = CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-drm-hash", manifest.Plaintext);
        }

        private OwnedGenesisRecoveryManifest Manifest { get; }
        internal GenesisIdentityContext Identity { get; }
        internal GenesisComponentIntent Intent { get; }
        internal GenesisReleaseContext Release { get; }
        internal GenesisCutoverSourceContext Source { get; }
        internal GenesisRecoveryProtectorContext Protector { get; }
        internal GenesisProtectedKeySetContext KeySet { get; }
        internal byte[] PlaintextHash { get; }
        internal ReadOnlySpan<byte> Plaintext => Manifest.Plaintext;

        internal static async ValueTask<SealerFixture> CreateAsync(
            SealingProvider protectorProvider)
        {
            var drm = Drm3Fixture.Create();
            using var decoded = RecoveryManifestParser.DecodeOwned(drm, 6);
            var dpa = Row(decoded, ArtifactType.Dpa1, RecordDefinitions.Dpa1);
            var dcm = Row(decoded, ArtifactType.Dcm1, RecordDefinitions.Dcm1);
            var drs = Row(decoded, ArtifactType.Drs1, RecordDefinitions.Drs1);
            var dwdRow = decoded.Rows.Single(row => row.Reference.Type == ArtifactType.Dwd1);

            var account = new VerifiedAccount(new AccountCertificate(dpa), drs.FieldSpan(2));
            var revocations = new VerifiedRevocationState(account,
                new RevocationSnapshot(drs), new RevocationCatalog([]));
            var relativeIdentity = new VerifiedIdentityRelative(
                new VerifiedIdentityAuthority(account, revocations, []));
            var manifest = new CutoverManifest(dcm);
            var baseIdentity = Uninitialized<VerifiedGenesisBaseIdentityContext>();
            Set(baseIdentity, "<Identity>k__BackingField", relativeIdentity);
            Set(baseIdentity, "<Manifest>k__BackingField", manifest);

            var componentSubject = Drm3Fixture.Fill(0x33, 32);
            var exactScope = new byte[122];
            manifest.NetworkId.Span.CopyTo(exactScope);
            manifest.ResetId.Span.CopyTo(exactScope.AsSpan(16));
            BinaryPrimitives.WriteUInt16BigEndian(exactScope.AsSpan(48, 2),
                (ushort)ComponentKind.Shared);
            componentSubject.CopyTo(exactScope, 50);
            BinaryPrimitives.WriteUInt64BigEndian(exactScope.AsSpan(82, 8), 1);
            exactScope.AsSpan(90, 32).Fill(0x34);
            var scope = Uninitialized<GenesisTransactionScopeContext>();
            Set(scope, "_scope", exactScope);

            var gti = new byte[GenesisProtectedRecords.GtiLength];
            "GTI1"u8.CopyTo(gti); gti[4] = 1;
            exactScope.CopyTo(gti, 8);
            gti.AsSpan(130, 32).Fill(0x35);
            BinaryPrimitives.WriteUInt64BigEndian(gti.AsSpan(162, 8), 1);
            BinaryPrimitives.WriteUInt64BigEndian(gti.AsSpan(170, 8), 2);
            decoded.DtcProtectedKeyId.CopyTo(gti.AsSpan(179, 32));
            gti.AsSpan(211, 32).Fill(0x36);
            var transaction = new GenesisTransactionReservation(gti);
            var identity = new GenesisIdentityContext(baseIdentity, scope, transaction,
                decoded.DrtCatalog, Drm3Fixture.Fill(0x37, 32));

            var intent = Uninitialized<GenesisComponentIntent>();
            Set(intent, "<Identity>k__BackingField", identity);
            Set(intent, "<ComponentKind>k__BackingField", ComponentKind.Shared);
            Set(intent, "<SchemaGeneration>k__BackingField", 1UL);
            Set(intent, "_schemaFingerprint", Drm3Fixture.Fill(0x38, 32));
            Set(intent, "<ComponentSubject>k__BackingField",
                (ReadOnlyMemory<byte>)componentSubject);

            var keySetRequest = new GenesisProtectedKeySetRequest(
                manifest.NetworkId.Span, manifest.ResetId.Span, ComponentKind.Shared,
                componentSubject, 1);
            var keySet = await GenesisProtectedKeySetContext.ReadAsync(
                new KeySetRegistry(KeySetScope(keySetRequest)), keySetRequest,
                decoded.DtcProtectedKeyId.ToArray(), Drm3Fixture.Fill(0x72, 32),
                Drm3Fixture.Fill(0x71, 32), default);

            var protectorRequest = new GenesisRecoveryProtectorRequest(identity, intent);
            var protector = await GenesisRecoveryProtectorContext.ReadAsync(
                protectorProvider, protectorRequest, decoded.DtcProtectedKeyId.ToArray(),
                keySet, default);

            var release = Uninitialized<GenesisReleaseContext>();
            Set(release, "_fingerprint", Drm3Fixture.Fill(0x52, 32));
            Set(release, "_network", manifest.NetworkId.ToArray());
            Set(release, "_resetId", manifest.ResetId.ToArray());
            Set(release, "_protectedStateKeyId", decoded.DtcProtectedKeyId.ToArray());
            Set(release, "_latestDwdReference",
                CanonicalGrammar.EncodeReference(dwdRow.Reference));
            Set(release, "_latestWitnessEpoch", 15UL);
            Set(release, "_latestWitnessIds", new[]
            {
                Drm3Fixture.Fill(0x81, 32),
                Drm3Fixture.Fill(0x82, 32),
                Drm3Fixture.Fill(0x83, 32),
                Drm3Fixture.Fill(0x84, 32)
            });
            var source = new GenesisCutoverSourceContext(
                identity, intent, release, keySet, protector);

            var rsm = GenesisRsm(decoded, identity, intent, release, source,
                CanonicalGrammar.EncodeReference(
                    decoded.Rows.Single(row => row.Reference.Type == ArtifactType.Dcm1).Reference),
                CanonicalGrammar.EncodeReference(
                    decoded.Rows.Single(row => row.Reference.Type == ArtifactType.Drs1).Reference));
            return new SealerFixture(new OwnedGenesisRecoveryManifest(drm, rsm),
                identity, intent, release, source, protector, keySet);
        }

        internal ValueTask<SealedGenesisRecoveryCandidate> SealAsync(
            SealingProvider provider,
            RecoveryNonceLatch latch,
            CancellationToken cancellationToken = default) =>
            GenesisRecoverySealer.SealCandidateAsync(
                Manifest, Identity, Intent, Source, Protector, provider, latch,
                CreatedAt, RetainUntil, cancellationToken);

        public void Dispose() => Manifest.Dispose();

        private static OwnedRecord Row(
            OwnedRecoveryManifest manifest,
            ArtifactType type,
            RecordDefinition definition)
        {
            var row = manifest.Rows.Single(value => value.Reference.Type == type);
            return CanonicalGrammar.DecodeOwned(
                manifest.CanonicalSpan.Slice(row.CanonicalOffset, row.CanonicalLength),
                definition);
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
                scope.AsSpan(offset + 2, 32).Fill(checked((byte)(0x61 + index)));
            }
            return scope;
        }

        private static byte[] GenesisRsm(
            OwnedRecoveryManifest manifest,
            GenesisIdentityContext identity,
            GenesisComponentIntent intent,
            GenesisReleaseContext release,
            GenesisCutoverSourceContext source,
            ReadOnlySpan<byte> dcmReference,
            ReadOnlySpan<byte> drsReference)
        {
            var rsm = new byte[RecoveryShadow.Length];
            "RSM2"u8.CopyTo(rsm); rsm[4] = 1;
            identity.BaseIdentity.Network.CopyTo(rsm.AsSpan(6));
            BinaryPrimitives.WriteUInt16BigEndian(rsm.AsSpan(22, 2),
                (ushort)intent.ComponentKind);
            intent.ComponentSubject.Span.CopyTo(rsm.AsSpan(24));
            identity.Transaction.TransactionId.CopyTo(rsm.AsSpan(56));
            BinaryPrimitives.WriteUInt64BigEndian(rsm.AsSpan(88, 8),
                identity.BaseIdentity.AccountGeneration);
            rsm[RecoveryShadow.PredecessorKindOffset] = 2;
            source.GenesisAnchorHash.Span.CopyTo(
                rsm.AsSpan(RecoveryShadow.GenesisAnchorHashOffset));
            dcmReference.CopyTo(rsm.AsSpan(RecoveryShadow.DcmReferenceOffset));
            drsReference.CopyTo(rsm.AsSpan(RecoveryShadow.DrsReferenceOffset));
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-pin-core", manifest.PinCoreProjection)
                .CopyTo(rsm, RecoveryShadow.PinCoreHashOffset);
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-drm-hash", manifest.CanonicalSpan)
                .CopyTo(rsm, RecoveryShadow.DrmHashOffset);
            RecoveryShadow.ComputeInventoryHash(manifest)
                .CopyTo(rsm, RecoveryShadow.ArtifactInventoryHashOffset);
            RecoveryShadow.ComputeFrontierCheckpointHash(manifest.FrontierCheckpoint)
                .CopyTo(rsm, RecoveryShadow.RfcHashOffset);
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-predecessor-frontier",
                manifest.PredecessorFrontier).CopyTo(rsm, RecoveryShadow.RpfHashOffset);
            RecoveryShadow.ComputeResetAuthorityHeadHash(manifest.ResetAuthorityHead)
                .CopyTo(rsm, RecoveryShadow.RahHashOffset);
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-drt-catalog", manifest.DrtCatalog)
                .CopyTo(rsm, RecoveryShadow.DtcHashOffset);
            RecoveryShadow.ComputeWitnessHeadHistoryHash(manifest.WitnessHeadHistory)
                .CopyTo(rsm, RecoveryShadow.DwhHashOffset);
            manifest.RfcProtectedKeyId.CopyTo(rsm.AsSpan(RecoveryShadow.RfcKeyIdOffset));
            manifest.DtcProtectedKeyId.CopyTo(rsm.AsSpan(RecoveryShadow.DtcKeyIdOffset));
            RecoveryShadow.ComputeSchemaFingerprint()
                .CopyTo(rsm, RecoveryShadow.SchemaFingerprintOffset);
            release.Fingerprint.Span.CopyTo(
                rsm.AsSpan(RecoveryShadow.ReleaseContextFingerprintOffset));
            identity.Fingerprint.Span.CopyTo(
                rsm.AsSpan(RecoveryShadow.IdentityContextFingerprintOffset));
            source.SourceFingerprint.Span.CopyTo(
                rsm.AsSpan(RecoveryShadow.CutoverOrGenesisSourceFingerprintOffset));
            source.OldProtectedSource.CopyTo(
                rsm.AsSpan(RecoveryShadow.OldProtectedSourceFingerprintOffset));
            RecoveryShadow.Preflight(rsm);
            return rsm;
        }
    }

    private sealed class KeySetRegistry(byte[] exactScope)
        : GenesisProtectedKeySetRegistry
    {
        public override ValueTask<GenesisProtectedKeySetReadResult> ReadAsync(
            GenesisProtectedKeySetRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(new GenesisProtectedKeySetReadResult(
                exactScope, 1, Enumerable.Repeat(true, 6).ToArray()));
    }

    internal sealed class SealingProvider : RecoverySealingProvider
    {
        private readonly List<string> _events;
        private readonly byte[] _protector;
        private readonly byte[] _latch;

        internal SealingProvider(List<string> events, int protectorLength = 32)
        {
            _events = events;
            _protector = Drm3Fixture.Fill(0x71, protectorLength);
            _latch = Drm3Fixture.Fill(0x72, 32);
        }

        internal bool CorruptSelfOpen { get; init; }
        internal bool MutateReadInputsAfterSnapshot { get; init; }
        internal int SealCalls { get; private set; }
        internal int OpenCalls { get; private set; }
        internal List<ReadOnlyMemory<byte>> CapturedPlaintexts { get; } = [];
        internal List<Memory<byte>> CapturedCiphertexts { get; } = [];
        internal List<RecoverySealRequest> SealRequests { get; } = [];

        public override ValueTask<GenesisRecoveryProtectorReadResult> ReadAsync(
            GenesisRecoveryProtectorRequest request,
            CancellationToken cancellationToken)
        {
            var result = new GenesisRecoveryProtectorReadResult(
                _protector, _latch, 1, protectorHealthy: true, latchHealthy: true);
            if (MutateReadInputsAfterSnapshot)
            {
                _protector.AsSpan().Clear();
                _latch.AsSpan().Clear();
            }
            return ValueTask.FromResult(result);
        }

        public override ValueTask DeriveNonceAsync(
            RecoverySealRequest request,
            Memory<byte> derivedNonce24,
            CancellationToken cancellationToken)
        {
            _events.Add("derive");
            derivedNonce24.Span.Fill(0x73);
            return ValueTask.CompletedTask;
        }

        public override ValueTask SealAsync(
            RecoverySealRequest request,
            ReadOnlyMemory<byte> plaintext,
            Memory<byte> ciphertextDestination,
            Memory<byte> authenticationTag16,
            CancellationToken cancellationToken)
        {
            _events.Add("seal");
            SealCalls++;
            SealRequests.Add(request);
            CapturedPlaintexts.Add(plaintext);
            CapturedCiphertexts.Add(ciphertextDestination);
            plaintext.CopyTo(ciphertextDestination);
            authenticationTag16.Span.Fill(0x74);
            return ValueTask.CompletedTask;
        }

        public override ValueTask OpenAsync(
            RecoverySealRequest request,
            ReadOnlyMemory<byte> ciphertext,
            ReadOnlyMemory<byte> authenticationTag16,
            Memory<byte> plaintextDestination,
            CancellationToken cancellationToken)
        {
            _events.Add("open");
            OpenCalls++;
            ciphertext.CopyTo(plaintextDestination);
            if (CorruptSelfOpen) plaintextDestination.Span[0] ^= 1;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class Latch(
        List<string> events,
        params RecoveryNonceLatchDecision[] decisions) : RecoveryNonceLatch
    {
        private int _call;
        internal CancellationTokenSource? CancelAfterStore { get; init; }
        internal List<byte[]> Requests { get; } = [];

        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,
            CancellationToken cancellationToken)
        {
            events.Add("latch");
            Requests.Add(request.ExactRequest.ToArray());
            var decision = decisions[Math.Min(_call++, decisions.Length - 1)];
            if (decision == RecoveryNonceLatchDecision.Stored)
                CancelAfterStore?.Cancel();
            return ValueTask.FromResult(decision);
        }
    }

    private static T Uninitialized<T>() where T : class =>
        (T)RuntimeHelpers.GetUninitializedObject(typeof(T));

    private static void Set(object target, string fieldName, object value)
    {
        var field = target.GetType().GetField(fieldName,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        Assert.NotNull(field);
        field!.SetValue(target, value);
    }

    private static byte[] ExpectedSealIntent(
        ReadOnlySpan<byte> plaintext,
        RecoverySealRequest request,
        ReadOnlySpan<byte> nonce)
    {
        var hashInput = new byte[8 + plaintext.Length];
        BinaryPrimitives.WriteUInt64BigEndian(hashInput, checked((ulong)plaintext.Length));
        plaintext.CopyTo(hashInput.AsSpan(8));
        var plaintextHash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V5/recovery-seal-plaintext", hashInput);
        var associatedData = request.AssociatedData.Span;
        var transcript = new byte[2 + 32 + 24 + 32 + 4 + associatedData.Length + 8 + 32];
        var offset = 0;
        BinaryPrimitives.WriteUInt16BigEndian(transcript.AsSpan(offset, 2), request.Suite);
        offset += 2;
        request.ProtectorKeyId.Span.CopyTo(transcript.AsSpan(offset)); offset += 32;
        nonce.CopyTo(transcript.AsSpan(offset)); offset += 24;
        request.TransactionId.Span.CopyTo(transcript.AsSpan(offset)); offset += 32;
        BinaryPrimitives.WriteUInt32BigEndian(transcript.AsSpan(offset, 4),
            checked((uint)associatedData.Length)); offset += 4;
        associatedData.CopyTo(transcript.AsSpan(offset)); offset += associatedData.Length;
        BinaryPrimitives.WriteUInt64BigEndian(transcript.AsSpan(offset, 8),
            checked((ulong)plaintext.Length)); offset += 8;
        plaintextHash.CopyTo(transcript, offset);
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V5/recovery-seal-intent", transcript);
    }
}
