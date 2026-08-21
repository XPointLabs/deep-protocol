using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.CompilerServices;
using Drm3Fixture = Deep.Protocol.Tests.DeepNative.Drm3Fixture;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisAuthorReplayOpenExact15Tests
{
    [Fact]
    public async Task ProcessLossReplay_CryptoOpensExactlyOnceAndVerifiesFourContainers()
    {
        using var fixture = await ReplayFixture.CreateAsync();
        var callbacks = new CallbackRecorder();

        using var opened = await fixture.OpenAsync(
            fixture.ArtifactSet, fixture.Journal, fixture.Source, callbacks);

        Assert.True(opened.ExactReplay);
        Assert.True(opened.NoAuthorityClaim);
        Assert.Equal(fixture.Sealed.ManifestHash.ToArray(), opened.DrmHash.ToArray());
        Assert.Equal(new[]
        {
            "derive", "latch", "open",
            "hmac:RFC1", "hmac:RAH1", "hmac:DTC2", "hmac:DWH1"
        }, callbacks.Events);
        Assert.Equal(1, callbacks.DeriveCalls);
        Assert.Equal(1, callbacks.LatchCalls);
        Assert.Equal(1, callbacks.OpenCalls);
        Assert.Equal(4, callbacks.HmacCalls);
    }

    [Fact]
    public async Task CrossFedGasGajOrDrc_RejectsBeforeAnyProviderCallback()
    {
        using var fixture = await ReplayFixture.CreateAsync();

        var gas = fixture.Gas.ToArray();
        gas[164] ^= 1;
        await AssertPreProviderRejectedAsync(fixture,
            fixture.ArtifactSetWith(gas: gas), fixture.Journal);

        var gaj = fixture.Gaj.ToArray();
        gaj[227] ^= 1;
        await AssertPreProviderRejectedAsync(fixture,
            fixture.ArtifactSet, new GenesisAuthorJournalSnapshot(gaj));

        var drc = CrossFeedSubject(fixture.Sealed.Capsule.CanonicalBytes.Span);
        await AssertPreProviderRejectedAsync(fixture,
            fixture.ArtifactSetWith(drc: drc), fixture.Journal);
    }

    [Fact]
    public async Task CrossFedAnchorSourceOrOldSource_RejectsOnlyAfterCryptoOpenAndFourHmacs()
    {
        using var fixture = await ReplayFixture.CreateAsync();
        foreach (var field in new[] { "_anchorHash", "_sourceFingerprint", "_oldProtectedSource" })
        {
            var callbacks = new CallbackRecorder();
            var source = CrossFeedSource(fixture.Source, field);

            await Assert.ThrowsAsync<RecordException>(() => fixture.OpenAsync(
                fixture.ArtifactSet, fixture.Journal, source, callbacks).AsTask());

            Assert.Equal(new[]
            {
                "derive", "latch", "open",
                "hmac:RFC1", "hmac:RAH1", "hmac:DTC2", "hmac:DWH1"
            }, callbacks.Events);
            Assert.Equal(1, callbacks.DeriveCalls);
            Assert.Equal(1, callbacks.LatchCalls);
            Assert.Equal(1, callbacks.OpenCalls);
            Assert.Equal(4, callbacks.HmacCalls);
        }
    }

    private static async Task AssertPreProviderRejectedAsync(
        ReplayFixture fixture,
        VerifiedGenesisArtifactSet artifactSet,
        GenesisAuthorJournalSnapshot journal)
    {
        var callbacks = new CallbackRecorder();
        await Assert.ThrowsAsync<RecordException>(() => fixture.OpenAsync(
            artifactSet, journal, fixture.Source, callbacks).AsTask());
        Assert.Empty(callbacks.Events);
        Assert.Equal(0, callbacks.DeriveCalls);
        Assert.Equal(0, callbacks.LatchCalls);
        Assert.Equal(0, callbacks.OpenCalls);
        Assert.Equal(0, callbacks.HmacCalls);
    }

    private sealed class ReplayFixture : IDisposable
    {
        private readonly GenesisRecoverySealerExact15Tests.SealerFixture _sealer;

        private ReplayFixture(
            GenesisRecoverySealerExact15Tests.SealerFixture sealer,
            SealedGenesisRecoveryCandidate sealedCandidate,
            byte[] gas,
            byte[] gaj)
        {
            _sealer = sealer;
            Sealed = sealedCandidate;
            Gas = gas;
            Gaj = gaj;
            ArtifactSet = ArtifactSetWith();
            Journal = new GenesisAuthorJournalSnapshot(gaj);
        }

        internal SealedGenesisRecoveryCandidate Sealed { get; }
        internal byte[] Gas { get; }
        internal byte[] Gaj { get; }
        internal VerifiedGenesisArtifactSet ArtifactSet { get; }
        internal GenesisAuthorJournalSnapshot Journal { get; }
        internal GenesisCutoverSourceContext Source => _sealer.Source;

        internal static async ValueTask<ReplayFixture> CreateAsync()
        {
            var sealing = new GenesisRecoverySealerExact15Tests.SealingProvider([]);
            var sealer = await GenesisRecoverySealerExact15Tests.SealerFixture.CreateAsync(sealing);
            var sealedCandidate = await sealer.SealAsync(sealing, new StoredLatch());
            var gas = GasBytes(sealer.Identity);
            var receipt = new GenesisArtifactSetReceipt(gas);
            var gaj = GajBytes(sealer.Identity, sealedCandidate, receipt);
            return new ReplayFixture(sealer, sealedCandidate, gas, gaj);
        }

        internal VerifiedGenesisArtifactSet ArtifactSetWith(
            byte[]? gas = null,
            byte[]? drc = null)
        {
            var artifacts = new ReadOnlyMemory<byte>[7];
            artifacts[0] = drc ?? Sealed.Capsule.CanonicalBytes.ToArray();
            for (var index = 1; index < artifacts.Length; index++)
                artifacts[index] = Drm3Fixture.Fill(checked((byte)(0xc0 + index)), index);
            var request = new GenesisArtifactStoreRequest(
                GenesisArtifactSetVerifier.AuthorScope(_sealer.Identity), artifacts);
            return new VerifiedGenesisArtifactSet(
                new GenesisArtifactSetReceipt(gas ?? Gas), request, 1);
        }

        internal ValueTask<RecoveryCandidatePlan> OpenAsync(
            VerifiedGenesisArtifactSet artifactSet,
            GenesisAuthorJournalSnapshot journal,
            GenesisCutoverSourceContext source,
            CallbackRecorder callbacks) =>
            RecoveryVerifier.OpenGenesisAuthorReplayCandidateAsync(
                artifactSet, journal, _sealer.Identity, _sealer.Intent,
                _sealer.Release, _sealer.KeySet, _sealer.Protector, source,
                callbacks, callbacks.NonceLatch, callbacks);

        public void Dispose()
        {
            Sealed.Dispose();
            _sealer.Dispose();
        }

        private static byte[] GasBytes(GenesisIdentityContext identity)
        {
            var gas = new byte[GenesisProtectedRecords.GasLength];
            "GAS1"u8.CopyTo(gas); gas[4] = 1;
            GenesisArtifactSetVerifier.AuthorScope(identity).CopyTo(gas, 8);
            BinaryPrimitives.WriteUInt16BigEndian(gas.AsSpan(130, 2), 7);
            gas.AsSpan(132, 32).Fill(0x91);
            gas.AsSpan(164, 32).Fill(0x92);
            U64(gas, 196, 1); U64(gas, 204, 1); U64(gas, 212, 2);
            gas[220] = 1;
            identity.ProtectedStateHmacKeyId.CopyTo(gas.AsSpan(221));
            gas.AsSpan(253, 32).Fill(0xa5);
            return gas;
        }

        private static byte[] GajBytes(
            GenesisIdentityContext identity,
            SealedGenesisRecoveryCandidate candidate,
            GenesisArtifactSetReceipt receipt)
        {
            var gaj = new byte[GenesisProtectedRecords.GajLength];
            "GAJ1"u8.CopyTo(gaj); gaj[4] = 1;
            GenesisArtifactSetVerifier.AuthorScope(identity).CopyTo(gaj, 8);
            gaj.AsSpan(130, 32).Fill(0x93);
            gaj.AsSpan(162, 32).Fill(0x94);
            gaj[194] = 0;
            candidate.ShadowStateHash.Span.CopyTo(gaj.AsSpan(195));
            Reference(ArtifactType.Drc1, candidate.Capsule.CanonicalBytes.Span)
                .CopyTo(gaj, 227);
            for (var index = 0; index < 4; index++)
                Drm3Fixture.Fill(checked((byte)(0xa1 + index)), 38)
                    .CopyTo(gaj, 265 + index * 38);
            gaj.AsSpan(417, 38).Fill(0xa6);
            gaj.AsSpan(455, 38).Fill(0xa7);
            receipt.ReceiptHash.Span.CopyTo(gaj.AsSpan(493));
            gaj.AsSpan(525, 32).Fill(0xa8);
            U64(gaj, 557, 1);
            gaj.AsSpan(775, 32).Fill(0x92);
            U64(gaj, 807, 1);
            identity.ProtectedStateHmacKeyId.CopyTo(gaj.AsSpan(816));
            gaj.AsSpan(848, 32).Fill(0xa5);
            return gaj;
        }
    }

    private sealed class CallbackRecorder : RecoveryProtectorProvider,
        IProtectedHmacProvider
    {
        internal CallbackRecorder() => NonceLatch = new ExactReplayLatch(this);
        internal List<string> Events { get; } = [];
        internal RecoveryNonceLatch NonceLatch { get; }
        internal int DeriveCalls { get; private set; }
        internal int LatchCalls { get; private set; }
        internal int OpenCalls { get; private set; }
        internal int HmacCalls { get; private set; }

        public override ValueTask DeriveNonceAsync(
            RecoveryProviderRequest request,
            Memory<byte> derivedNonce24,
            CancellationToken cancellationToken)
        {
            Events.Add("derive"); DeriveCalls++;
            derivedNonce24.Span.Fill(0x73);
            return ValueTask.CompletedTask;
        }

        public override ValueTask OpenAsync(
            RecoveryProviderRequest request,
            Memory<byte> plaintextDestination,
            CancellationToken cancellationToken)
        {
            Events.Add("open"); OpenCalls++;
            request.Ciphertext.CopyTo(plaintextDestination);
            return ValueTask.CompletedTask;
        }

        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request,
            CancellationToken cancellationToken)
        {
            HmacCalls++;
            Events.Add($"hmac:{request.Domain[^4..]}");
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(new byte[32]);
        }

        private sealed class ExactReplayLatch(CallbackRecorder owner) : RecoveryNonceLatch
        {
            public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
                RecoveryNonceLatchRequest request,
                CancellationToken cancellationToken)
            {
                owner.Events.Add("latch"); owner.LatchCalls++;
                return ValueTask.FromResult(RecoveryNonceLatchDecision.ExactReplay);
            }
        }
    }

    private sealed class StoredLatch : RecoveryNonceLatch
    {
        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(RecoveryNonceLatchDecision.Stored);
    }

    private static byte[] CrossFeedSubject(ReadOnlySpan<byte> canonicalDrc)
    {
        var drc = CanonicalGrammar.DecodeOwned(canonicalDrc, RecordDefinitions.Drc1);
        var fields = RecordDefinitions.Drc1.Fields.Select((_, index) =>
            (ReadOnlyMemory<byte>)drc.FieldCopy(index + 1)).ToArray();
        fields[1] = Drm3Fixture.Fill(0xee, 32);
        return CanonicalGrammar.Encode(RecordDefinitions.Drc1, fields);
    }

    private static GenesisCutoverSourceContext CrossFeedSource(
        GenesisCutoverSourceContext source,
        string changedField)
    {
        var clone = (GenesisCutoverSourceContext)RuntimeHelpers.GetUninitializedObject(
            typeof(GenesisCutoverSourceContext));
        Set(clone, "_source", source.Source.ToArray());
        Set(clone, "_sourceFingerprint", source.SourceFingerprint.ToArray());
        Set(clone, "_anchor", source.Anchor.ToArray());
        Set(clone, "_anchorHash", source.GenesisAnchorHash.ToArray());
        Set(clone, "_oldProtectedSource", source.OldProtectedSource.ToArray());
        Set(clone, changedField, Drm3Fixture.Fill(0xef, 32));
        return clone;
    }

    private static void Set(object target, string fieldName, object value)
    {
        var field = target.GetType().GetField(fieldName,
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(field);
        field!.SetValue(target, value);
    }

    private static byte[] Reference(ArtifactType type, ReadOnlySpan<byte> canonical) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, canonical));

    private static void U64(byte[] destination, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64BigEndian(destination.AsSpan(offset, 8), value);
}
