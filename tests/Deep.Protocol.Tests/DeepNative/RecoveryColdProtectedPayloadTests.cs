using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class RecoveryColdProtectedPayloadTests
{
    internal static (
        ReleaseRootManifestPin Pin,
        byte[] Dcp,
        byte[] Dcs,
        byte[] Dcq,
        byte[] Dcl,
        byte[] Drc,
        byte[] Rsm,
        byte[] HmacKey,
        byte[] ResetId) CreateTaggedInputFixture()
    {
        var fixture = Fixture.Create();
        using var manifest = RecoveryManifestParser.DecodeOwned(fixture.Manifest, 6);
        var dcmIndex = Enumerable.Range(0,manifest.Rows.Count)
            .Single(index => manifest.Rows[index].Reference.Type == ArtifactType.Dcm1);
        var dcm = CanonicalGrammar.DecodeOwned(manifest.RowBytes(dcmIndex),RecordDefinitions.Dcm1);
        return (
            fixture.Input.Pin,
            fixture.Input.Dcp.ToArray(),
            fixture.Input.Dcs.ToArray(),
            fixture.Input.Dcq.ToArray(),
            fixture.Input.Dcl.ToArray(),
            fixture.Input.Drc.ToArray(),
            fixture.Input.Rsm.ToArray(),
            fixture.HmacKey.ToArray(),
            dcm.FieldCopy(2));
    }

    [Fact]
    public async Task ColdPayload_ReturnsCandidateOnlyAfterAllFourProtectedHmacsVerify()
    {
        var fixture = Fixture.Create();
        var hmac = new StoredContainerHmacProvider(fixture.HmacKey);
        var aead = new PlaintextProvider(fixture.Nonce, fixture.Manifest);
        var providerContext = await CreateProviderContextAsync(fixture);

        using var candidate = await RecoveryEngine.OpenColdPayloadAsync(
            fixture.Input,
            providerContext,
            aead,
            new StoredLatch(),
            hmac,
            default);

        Assert.Equal(1, aead.DeriveCalls);
        Assert.Equal(1, aead.OpenCalls);
        Assert.Equal(4, hmac.Calls);
        Assert.Equal(new[]
        {
            "Deep/ProtectedState/V1/RFC1",
            "Deep/ProtectedState/V1/RAH1",
            "Deep/ProtectedState/V1/DTC2",
            "Deep/ProtectedState/V1/DWH1"
        }, hmac.Domains);
        Assert.Equal(6, candidate.Artifacts.Count);
        Assert.True(candidate.NoAuthorityClaim);
    }

    [Fact]
    public async Task ColdPayload_WrongFinalProtectedHmacReturnsNoCandidate()
    {
        var fixture = Fixture.Create();
        var hmac = new StoredContainerHmacProvider(fixture.HmacKey, failCall: 4);
        var aead = new PlaintextProvider(fixture.Nonce, fixture.Manifest);
        var providerContext = await CreateProviderContextAsync(fixture);

        var error = await Assert.ThrowsAsync<RecordException>(() => RecoveryEngine.OpenColdPayloadAsync(
            fixture.Input,
            providerContext,
            aead,
            new StoredLatch(),
            hmac,
            default).AsTask());

        Assert.Equal(RecordError.InvalidSignature, error.Error);
        Assert.Equal(1, aead.DeriveCalls);
        Assert.Equal(1, aead.OpenCalls);
        Assert.Equal(4, hmac.Calls);
    }

    [Fact]
    public async Task ColdPayload_WrongSharedHsmKeyFailsClosedAfterOneAeadAndBeforeCandidate()
    {
        var fixture = Fixture.Create();
        var wrongKey = fixture.HmacKey.ToArray();
        wrongKey[0] ^= 0xff;
        var hmac = new StoredContainerHmacProvider(wrongKey);
        var aead = new PlaintextProvider(fixture.Nonce, fixture.Manifest);
        var providerContext = await CreateProviderContextAsync(fixture);

        var error = await Assert.ThrowsAsync<RecordException>(() => RecoveryEngine.OpenColdPayloadAsync(
            fixture.Input,
            providerContext,
            aead,
            new StoredLatch(),
            hmac,
            default).AsTask());

        Assert.Equal(RecordError.InvalidSignature, error.Error);
        Assert.Equal(1, aead.DeriveCalls);
        Assert.Equal(1, aead.OpenCalls);
        Assert.Equal(1, hmac.Calls);
        Assert.Equal("Deep/ProtectedState/V1/RFC1", hmac.Domains.Single());
    }

    [Fact]
    public async Task ColdPayload_ChangedRsmInventoryBindingFailsAfterOneAeadBeforeHmac()
    {
        var fixture = Fixture.Create();
        var changedRsm = fixture.Input.Rsm.ToArray();
        changedRsm[307] ^= 1;
        var changedDrc = ReplaceField(
            fixture.Input.Drc.ToArray(),
            RecordDefinitions.Drc1,
            8,
            RecoveryShadow.ComputeShadowHash(changedRsm));
        var changedInput = ColdRecoveryInput.CreateNonterminal(
            fixture.Input.Pin,
            fixture.Input.Dcp.Span,
            fixture.Input.Dcs.Span,
            fixture.Input.Dcq.Span,
            fixture.Input.Dcl.Span,
            changedDrc,
            changedRsm);
        var hmac = new StoredContainerHmacProvider(fixture.HmacKey);
        var aead = new PlaintextProvider(fixture.Nonce, fixture.Manifest);
        var providerContext = await CreateProviderContextAsync(changedInput, fixture.Manifest, fixture.HmacKey);

        var error = await Assert.ThrowsAsync<RecordException>(() => RecoveryEngine.OpenColdPayloadAsync(
            changedInput,
            providerContext,
            aead,
            new StoredLatch(),
            hmac,
            default).AsTask());

        Assert.Equal(RecordError.InvalidField, error.Error);
        Assert.Equal(1, aead.DeriveCalls);
        Assert.Equal(1, aead.OpenCalls);
        Assert.Equal(0, hmac.Calls);
    }

    [Fact]
    public async Task Dtc1OrMixedDtc20_RejectsAfterOneAeadWithExactReplayLatchAndNoMutation()
    {
        var fixture = Fixture.Create();
        var dtcOffset = fixture.Manifest.AsSpan().IndexOf("DTC2"u8);
        Assert.True(dtcOffset >= 0);
        var targetCount = BinaryPrimitives.ReadUInt16BigEndian(
            fixture.Manifest.AsSpan(dtcOffset + 166, 2));
        var historyCount = BinaryPrimitives.ReadUInt16BigEndian(
            fixture.Manifest.AsSpan(dtcOffset + 168, 2));
        var dtcLength = checked(RecoveryManifestParser.DtcFixedLength +
            targetCount * RecoveryManifestParser.DrtEntryLength +
            historyCount * RecoveryManifestParser.DrtHistoryEntryLength);

        var variants = new List<byte[]>();
        var legacyMagic = fixture.Manifest.ToArray();
        legacyMagic[dtcOffset + 3] = (byte)'1';
        variants.Add(legacyMagic);
        var mixedVersion = fixture.Manifest.ToArray();
        mixedVersion[dtcOffset + 4] = 1;
        variants.Add(mixedVersion);
        var legacyDomain = fixture.Manifest.ToArray();
        ComputeTag(fixture.HmacKey, "Deep/ProtectedState/V1/DTC1",
            legacyDomain.AsSpan(dtcOffset, dtcLength - 32))
            .CopyTo(legacyDomain, dtcOffset + dtcLength - 32);
        variants.Add(legacyDomain);

        foreach (var variant in variants)
        {
            var aead = new PlaintextProvider(fixture.Nonce, variant);
            var hmac = new StoredContainerHmacProvider(fixture.HmacKey);
            var providerContext = await CreateProviderContextAsync(fixture);

            await Assert.ThrowsAsync<RecordException>(() => RecoveryEngine.OpenColdPayloadAsync(
                fixture.Input, providerContext, aead, new ExactReplayLatch(), hmac, default).AsTask());

            Assert.Equal(1, aead.DeriveCalls);
            Assert.Equal(1, aead.OpenCalls);
            Assert.InRange(hmac.Calls, 0, 3);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    public async Task ColdPayload_DrcRsmCrossFeedRejectsBeforeEveryProviderCallback(int fieldTag)
    {
        var fixture = Fixture.Create();
        var changedDrc = MutateField(fixture.Input.Drc.ToArray(), RecordDefinitions.Drc1, fieldTag);
        var changedInput = ColdRecoveryInput.CreateNonterminal(
            fixture.Input.Pin,
            fixture.Input.Dcp.Span,
            fixture.Input.Dcs.Span,
            fixture.Input.Dcq.Span,
            fixture.Input.Dcl.Span,
            changedDrc,
            fixture.Input.Rsm.Span);
        var hmac = new StoredContainerHmacProvider(fixture.HmacKey);
        var aead = new PlaintextProvider(fixture.Nonce, fixture.Manifest);
        RecoveryProviderRegistryContext? providerContext = null;
        try
        {
            providerContext = await CreateProviderContextAsync(changedInput, fixture.Manifest, fixture.HmacKey);
        }
        catch (RecordException)
        {
            Assert.Equal(0, aead.DeriveCalls);
            Assert.Equal(0, aead.OpenCalls);
            Assert.Equal(0, hmac.Calls);
            return;
        }

        await Assert.ThrowsAsync<RecordException>(() => RecoveryEngine.OpenColdPayloadAsync(
            changedInput, providerContext, aead, new StoredLatch(), hmac, default).AsTask());

        Assert.Equal(0, aead.DeriveCalls);
        Assert.Equal(0, aead.OpenCalls);
        Assert.Equal(0, hmac.Calls);
    }

    internal async Task ColdPayload_ProtectorSelectorCrossFeedRejectsBeforeEveryProviderCallback()
    {
        var fixture = Fixture.Create();
        var changedDrc = MutateField(fixture.Input.Drc.ToArray(), RecordDefinitions.Drc1, 13);
        var changedInput = ColdRecoveryInput.CreateNonterminal(
            fixture.Input.Pin,
            fixture.Input.Dcp.Span,
            fixture.Input.Dcs.Span,
            fixture.Input.Dcq.Span,
            fixture.Input.Dcl.Span,
            changedDrc,
            fixture.Input.Rsm.Span);
        var hmac = new StoredContainerHmacProvider(fixture.HmacKey);
        var aead = new PlaintextProvider(fixture.Nonce, fixture.Manifest);
        var providerContext = await CreateProviderContextAsync(fixture);

        await Assert.ThrowsAsync<RecordException>(() => RecoveryEngine.OpenColdPayloadAsync(
            changedInput, providerContext, aead, new ExactReplayLatch(), hmac, default).AsTask());

        Assert.Equal(0, aead.DeriveCalls);
        Assert.Equal(0, aead.OpenCalls);
        Assert.Equal(0, hmac.Calls);
    }

    private static ValueTask<RecoveryProviderRegistryContext> CreateProviderContextAsync(Fixture fixture) =>
        CreateProviderContextAsync(fixture.Input, fixture.Manifest, fixture.HmacKey);

    private static async ValueTask<RecoveryProviderRegistryContext> CreateProviderContextAsync(
        ColdRecoveryInput input, byte[] manifestBytes, byte[] hmacKeyId)
    {
        using var manifest = RecoveryManifestParser.DecodeOwned(manifestBytes, 6);
        var dcmIndex = Enumerable.Range(0,manifest.Rows.Count)
            .Single(index => manifest.Rows[index].Reference.Type == ArtifactType.Dcm1);
        var dcm = CanonicalGrammar.DecodeOwned(manifest.RowBytes(dcmIndex), RecordDefinitions.Dcm1);
        var drc = CanonicalGrammar.DecodeOwned(input.Drc.Span, RecordDefinitions.Drc1);
        var request = new RecoveryProviderRegistryRequest(drc);
        var scope = new byte[RecoveryProviderRegistryContext.ExactScopeLength];
        drc.FieldSpan(1).CopyTo(scope);
        dcm.FieldSpan(2).CopyTo(scope.AsSpan(16));
        drc.FieldSpan(2).CopyTo(scope.AsSpan(48));
        drc.FieldSpan(4).CopyTo(scope.AsSpan(80));
        BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(88, 2), 2);
        BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(90, 2),
            (ushort)RecoveryProtectedKeyKind.ProtectedStateHmac);
        manifest.RfcProtectedKeyId.CopyTo(scope.AsSpan(92));
        BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(124, 2),
            (ushort)RecoveryProtectedKeyKind.RecoveryNonceLatch);
        Enumerable.Repeat((byte)0x6a, 32).ToArray().CopyTo(scope.AsSpan(126));
        return await RecoveryProviderRegistryContext.ReadAsync(
            new FixedRegistry(scope), request, default);
    }

    private sealed record Fixture(
        ColdRecoveryInput Input,
        byte[] Manifest,
        byte[] Nonce,
        byte[] HmacKey)
    {
        internal static Fixture Create()
        {
            var manifestBytes = Drm3Fixture.Create();
            var hmacKey = Enumerable.Repeat((byte)0x5a, 32).ToArray();
            SealContainer(manifestBytes, "RFC1", "Deep/ProtectedState/V1/RFC1", hmacKey);
            SealContainer(manifestBytes, "RAH1", "Deep/ProtectedState/V1/RAH1", hmacKey);
            SealContainer(manifestBytes, "DTC2", "Deep/ProtectedState/V1/DTC2", hmacKey);
            SealContainer(manifestBytes, "DWH1", "Deep/ProtectedState/V1/DWH1", hmacKey);
            using var manifest = RecoveryManifestParser.DecodeOwned(manifestBytes, 6);
            var nonce = Enumerable.Repeat((byte)7, 24).ToArray();
            var drc = Drm3Fixture.CreateCapsule(manifestBytes, nonce);
            drc = ReplaceField(drc, RecordDefinitions.Drc1, 3,
                manifest.RfcSourceTuple.Slice(128, 32).ToArray());
            var rsm = CreateRsm(manifest, drc);
            drc = ReplaceField(drc, RecordDefinitions.Drc1, 8,
                RecoveryShadow.ComputeShadowHash(rsm));

            var pin = new ReleaseRootManifestPin(
                Enumerable.Repeat((byte)0x11, 16).ToArray(),
                Enumerable.Repeat((byte)0x91, 32).ToArray(),
                Enumerable.Repeat((byte)0x92, 32).ToArray(),
                0,
                new ArtifactReference(
                    ArtifactType.Rrm1,
                    332,
                    Enumerable.Repeat((byte)0x93, 32).ToArray()));
            var dcp = Canonical(RecordDefinitions.Dcp1, fields =>
            {
                fields[2] = U16((ushort)ComponentKind.Shared);
            });
            var dcs = Canonical(RecordDefinitions.Dcs1, fields =>
            {
                fields[9] = new byte[] { 4 };
                var rows = new byte[416];
                for (ushort index = 0; index < 4; index++)
                    BinaryPrimitives.WriteUInt16BigEndian(
                        rows.AsSpan(index * 104, 2), checked((ushort)(index + 1)));
                fields[10] = rows;
            });
            var dcq = Canonical(RecordDefinitions.Dcq1, fields =>
            {
                fields[8] = new byte[] { 3 };
                fields[9] = FramedRows(3, 758);
            });
            var dcl = Canonical(RecordDefinitions.Dcl1, fields =>
            {
                fields[9] = new byte[] { 3 };
                fields[10] = FramedRows(3, 710);
            });
            return new Fixture(
                ColdRecoveryInput.CreateNonterminal(pin, dcp, dcs, dcq, dcl, drc, rsm),
                manifestBytes,
                nonce,
                hmacKey);
        }

        private static byte[] CreateRsm(OwnedRecoveryManifest manifest, byte[] drcCanonical)
        {
            var drc = CanonicalGrammar.DecodeOwned(drcCanonical, RecordDefinitions.Drc1);
            var rsm = new byte[RecoveryShadow.Length];
            "RSM2"u8.CopyTo(rsm);
            rsm[4] = 1;
            drc.FieldSpan(1).CopyTo(rsm.AsSpan(6));
            BinaryPrimitives.WriteUInt16BigEndian(rsm.AsSpan(22, 2), (ushort)ComponentKind.Shared);
            drc.FieldSpan(2).CopyTo(rsm.AsSpan(24));
            drc.FieldSpan(3).CopyTo(rsm.AsSpan(56));
            drc.FieldSpan(4).CopyTo(rsm.AsSpan(88));
            BinaryPrimitives.WriteUInt64BigEndian(rsm.AsSpan(88, 8), 1);
            rsm[96] = 1;
            manifest.RfcSourceTuple.Slice(58, 38).CopyTo(rsm.AsSpan(97));
            drc.FieldSpan(5).CopyTo(rsm.AsSpan(167));
            drc.FieldSpan(6).CopyTo(rsm.AsSpan(205));
            drc.FieldSpan(7).CopyTo(rsm.AsSpan(243));
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-drm-hash", manifest.CanonicalSpan).CopyTo(rsm, 275);
            RecoveryShadow.ComputeInventoryHash(manifest).CopyTo(rsm, 307);
            RecoveryShadow.ComputeFrontierCheckpointHash(manifest.FrontierCheckpoint).CopyTo(rsm, 339);
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-predecessor-frontier", manifest.PredecessorFrontier).CopyTo(rsm, 371);
            RecoveryShadow.ComputeResetAuthorityHeadHash(manifest.ResetAuthorityHead).CopyTo(rsm, 403);
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-drt-catalog", manifest.DrtCatalog).CopyTo(rsm, 435);
            RecoveryShadow.ComputeWitnessHeadHistoryHash(manifest.WitnessHeadHistory).CopyTo(rsm, 467);
            manifest.RfcProtectedKeyId.CopyTo(rsm.AsSpan(499));
            manifest.DtcProtectedKeyId.CopyTo(rsm.AsSpan(531));
            RecoveryShadow.ComputeSchemaFingerprint().CopyTo(rsm, 563);
            rsm.AsSpan(595, 32).Fill(0x35);
            rsm.AsSpan(627, 32).Fill(0x36);
            rsm.AsSpan(659, 32).Fill(0x37);
            manifest.RfcSourceTuple.Slice(96, 32).CopyTo(rsm.AsSpan(691));
            RecoveryShadow.Preflight(rsm);
            return rsm;
        }

        private static void SealContainer(
            byte[] manifest,
            string magic,
            string domain,
            byte[] hmacKey)
        {
            var offset = manifest.AsSpan().IndexOf(Encoding.ASCII.GetBytes(magic));
            if (offset < 0) throw new InvalidOperationException($"Missing {magic} fixture container.");
            var count = magic == "RAH1" ? 0 :
                BinaryPrimitives.ReadUInt16BigEndian(manifest.AsSpan(offset + 166, 2));
            var historyCount = magic == "DTC2"
                ? BinaryPrimitives.ReadUInt16BigEndian(manifest.AsSpan(offset + 168, 2)) : 0;
            var entryLength = magic switch
            {
                "RFC1" => RecoveryManifestParser.RfcEntryLength,
                "RAH1" => 0,
                "DTC2" => RecoveryManifestParser.DrtEntryLength,
                "DWH1" => RecoveryManifestParser.DwhEntryLength,
                _ => throw new ArgumentOutOfRangeException(nameof(magic))
            };
            var length = magic switch
            {
                "RAH1" => RecoveryManifestParser.RahFixedLength,
                "DTC2" => checked(RecoveryManifestParser.DtcFixedLength +
                    count * entryLength + historyCount * RecoveryManifestParser.DrtHistoryEntryLength),
                "DWH1" => checked(RecoveryManifestParser.DwhFixedLength + count * entryLength),
                _ => checked(RecoveryManifestParser.RfcFixedLength + count * entryLength)
            };
            ComputeTag(hmacKey, domain, manifest.AsSpan(offset, length - 32))
                .CopyTo(manifest, offset + length - 32);
        }
    }

    private sealed class PlaintextProvider(byte[] nonce, byte[] plaintext) : RecoveryProtectorProvider
    {
        internal int DeriveCalls { get; private set; }
        internal int OpenCalls { get; private set; }

        public override ValueTask DeriveNonceAsync(
            RecoveryProviderRequest request,
            Memory<byte> derivedNonce24,
            CancellationToken cancellationToken)
        {
            DeriveCalls++;
            nonce.CopyTo(derivedNonce24);
            return ValueTask.CompletedTask;
        }

        public override ValueTask OpenAsync(
            RecoveryProviderRequest request,
            Memory<byte> plaintextDestination,
            CancellationToken cancellationToken)
        {
            OpenCalls++;
            plaintext.CopyTo(plaintextDestination);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class StoredLatch : RecoveryNonceLatch
    {
        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(RecoveryNonceLatchDecision.Stored);
    }

    private sealed class ExactReplayLatch : RecoveryNonceLatch
    {
        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(RecoveryNonceLatchDecision.ExactReplay);
    }

    private sealed class FixedRegistry(byte[] scope) : RecoveryProviderRegistry
    {
        public override ValueTask<RecoveryProviderRegistryReadResult> ReadAsync(
            RecoveryProviderRegistryRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(new RecoveryProviderRegistryReadResult(
                scope, 1, protectedStateHmacHealthy: true, recoveryNonceLatchHealthy: true));
    }

    private sealed class StoredContainerHmacProvider(byte[] hmacKey, int failCall = 0)
        : IProtectedHmacProvider
    {
        internal int Calls { get; private set; }
        internal List<string> Domains { get; } = [];

        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            Domains.Add(request.Domain);
            var result = ComputeTag(hmacKey, request.Domain, request.UnsignedCanonical.Span);
            if (Calls == failCall) result[0] ^= 1;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(result);
        }
    }

    private static byte[] ComputeTag(
        ReadOnlySpan<byte> key,
        string domain,
        ReadOnlySpan<byte> unsigned)
    {
        var domainBytes = Encoding.ASCII.GetBytes(domain);
        var input = new byte[2 + domainBytes.Length + 2 + 4 + unsigned.Length];
        BinaryPrimitives.WriteUInt16BigEndian(input, checked((ushort)domainBytes.Length));
        domainBytes.CopyTo(input, 2);
        var offset = 2 + domainBytes.Length;
        BinaryPrimitives.WriteUInt16BigEndian(
            input.AsSpan(offset), ArtifactRegistry.ProtectedHmacSha256);
        BinaryPrimitives.WriteUInt32BigEndian(
            input.AsSpan(offset + 2), checked((uint)unsigned.Length));
        unsigned.CopyTo(input.AsSpan(offset + 6));
        return HMACSHA256.HashData(key, input);
    }

    private static byte[] Canonical(
        RecordDefinition definition,
        Action<ReadOnlyMemory<byte>[]>? update = null)
    {
        var fields = definition.Fields.Select(static field =>
            (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        update?.Invoke(fields);
        return CanonicalGrammar.Encode(definition, fields);
    }

    private static byte[] FramedRows(int count, int length)
    {
        var output = new byte[count * (4 + length)];
        var offset = 0;
        for (var index = 0; index < count; index++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset, 4), checked((uint)length));
            offset += 4 + length;
        }
        return output;
    }

    private static byte[] Reference(ArtifactType type, uint length, byte marker)
    {
        var output = new byte[ArtifactReference.Length];
        BinaryPrimitives.WriteUInt16BigEndian(output, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(2), length);
        output.AsSpan(6).Fill(marker);
        return output;
    }

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] ReplaceField(
        byte[] canonical,
        RecordDefinition definition,
        int tag,
        byte[] replacement)
    {
        var record = CanonicalGrammar.DecodeOwned(canonical, definition);
        var fields = definition.Fields.Select((_, index) =>
            (ReadOnlyMemory<byte>)(index + 1 == tag ? replacement : record.FieldCopy(index + 1)))
            .ToArray();
        return CanonicalGrammar.Encode(definition, fields);
    }

    private static byte[] MutateField(
        byte[] canonical, RecordDefinition definition, int tag)
    {
        var record = CanonicalGrammar.DecodeOwned(canonical, definition);
        var replacement = record.FieldCopy(tag);
        replacement[0] ^= 1;
        return ReplaceField(canonical, definition, tag, replacement);
    }
}
