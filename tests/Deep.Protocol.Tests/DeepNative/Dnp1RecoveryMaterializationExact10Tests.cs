using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.Tests.DeepNative;

namespace Deep.Protocol.DeepNative;

public sealed class RecoveryMaterializationExact10Tests
{
    [Fact]
    public async Task CanonicalExternalCheckpoint_AuthorsOneDataOnlyCandidateDpl()
    {
        using var candidate = await OpenCandidateAsync();
        var checkpoint = Checkpoint(candidate);
        var hmac = new RecordingHmacProvider(Bytes(0xa1, 32));

        var plan = await RecoveryVerifier.MaterializeCandidateDplAsync(
            candidate, checkpoint.Input, hmac);

        Assert.True(plan.NoAuthorityClaim);
        Assert.Equal(1, hmac.Calls);
        Assert.Equal("Deep/ProtectedState/V1/DPL1", hmac.Domain);
        Assert.Equal(ArtifactRegistry.ProtectedHmacSha256, hmac.Suite);
        Assert.Equal(candidate.FrontierCheckpoint.Slice(
            candidate.FrontierCheckpoint.Length - 64, 32).ToArray(), hmac.KeyId);

        var dpl = CanonicalGrammar.DecodeOwned(
            plan.CanonicalCandidateDpl.Span, RecordDefinitions.Dpl1);
        var projection = candidate.PinCoreProjection.Span;
        Assert.Equal(projection[..16].ToArray(), dpl.FieldCopy(1));
        Assert.Equal(projection.Slice(16, 2).ToArray(), dpl.FieldCopy(2));
        Assert.Equal(projection.Slice(18, 8).ToArray(), dpl.FieldCopy(3));
        Assert.Equal(projection.Slice(26, 38).ToArray(), dpl.FieldCopy(4));
        Assert.Equal(projection.Slice(64, 8).ToArray(), dpl.FieldCopy(5));
        Assert.Equal(projection.Slice(72, 38).ToArray(), dpl.FieldCopy(6));
        Assert.Equal(projection.Slice(110, 32).ToArray(), dpl.FieldCopy(7));
        Assert.Equal(projection.Slice(142, 8).ToArray(), dpl.FieldCopy(8));
        Assert.Equal(projection.Slice(150, 8).ToArray(), dpl.FieldCopy(9));
        Assert.Equal(projection.Slice(158, 32).ToArray(), dpl.FieldCopy(10));
        Assert.Equal(projection.Slice(190, 38).ToArray(), dpl.FieldCopy(11));
        Assert.Equal(Reference(ArtifactType.Dcp1, checkpoint.Dcp), dpl.FieldCopy(12));
        Assert.Equal(Reference(ArtifactType.Dcs1, checkpoint.Dcs), dpl.FieldCopy(13));
        Assert.Equal(Reference(ArtifactType.Dcq1, checkpoint.Dcq), dpl.FieldCopy(14));
        Assert.Equal(projection.Slice(228, 38).ToArray(), dpl.FieldCopy(15));
        Assert.Equal(projection.Slice(266, 1).ToArray(), dpl.FieldCopy(16));
        Assert.Equal(projection.Slice(267, 7).ToArray(), dpl.FieldCopy(17));
        Assert.Equal(Bytes(0xa1, 32), dpl.FieldCopy(18));
        Assert.Equal(576, plan.CanonicalCandidateDpl.Length);
        Assert.Equal(Reference(ArtifactType.Dpl1, dpl.CanonicalSpan),
            plan.CandidateDplArtifactReference.ToArray());

        var rfc = candidate.FrontierCheckpoint.Span;
        Assert.Equal(rfc.Slice(64, 70).ToArray(),
            plan.ExpectedOldDplAndProtectedSourceTuple.ToArray());
    }

    [Fact]
    public async Task ReturnedPlan_IsDefensivelyOwnedAndDoesNotRequeryHmac()
    {
        using var candidate = await OpenCandidateAsync();
        var checkpoint = Checkpoint(candidate);
        var tag = Bytes(0xb1, 32);
        var hmac = new RecordingHmacProvider(tag);

        var plan = await RecoveryVerifier.MaterializeCandidateDplAsync(
            candidate, checkpoint.Input, hmac);
        var canonical = plan.CanonicalCandidateDpl.ToArray();
        var oldSource = plan.ExpectedOldDplAndProtectedSourceTuple.ToArray();
        var reference = plan.CandidateDplArtifactReference.ToArray();

        tag.AsSpan().Fill(0xff);
        canonical.AsSpan().Fill(0xff);
        oldSource.AsSpan().Fill(0xff);
        reference.AsSpan().Fill(0xff);

        Assert.Equal(1, hmac.Calls);
        Assert.NotEqual(canonical, plan.CanonicalCandidateDpl.ToArray());
        Assert.NotEqual(oldSource, plan.ExpectedOldDplAndProtectedSourceTuple.ToArray());
        Assert.NotEqual(reference, plan.CandidateDplArtifactReference.ToArray());
        Assert.Equal(Bytes(0xb1, 32), CanonicalGrammar.DecodeOwned(
            plan.CanonicalCandidateDpl.Span, RecordDefinitions.Dpl1).FieldCopy(18));
    }

    [Fact]
    public async Task ExternalCheckpointInput_DefensivelyOwnsExactArtifacts()
    {
        using var candidate = await OpenCandidateAsync();
        var checkpoint = Checkpoint(candidate);
        var input = checkpoint.Input;
        checkpoint.Dcp.AsSpan().Fill(0xff);
        checkpoint.Dcs.AsSpan().Fill(0xff);
        checkpoint.Dcq.AsSpan().Fill(0xff);
        var hmac = new RecordingHmacProvider(Bytes(0xb2, 32));

        var plan = await RecoveryVerifier.MaterializeCandidateDplAsync(
            candidate, input, hmac);

        Assert.True(input.NoAuthorityClaim);
        Assert.True(plan.NoAuthorityClaim);
        Assert.Equal(1, hmac.Calls);
        Assert.Equal(576, plan.CanonicalCandidateDpl.Length);
    }

    [Fact]
    public async Task ExternalTupleMutation_RejectsBeforeHmacCallback()
    {
        using var candidate = await OpenCandidateAsync();
        var checkpoint = Checkpoint(candidate);
        var badDcp = MutateField(checkpoint.Dcp, RecordDefinitions.Dcp1, 1);
        var input = SealedCheckpoint(
            badDcp, checkpoint.Dcs, checkpoint.Dcq, checkpoint.Dcl, checkpoint.Drc);
        var hmac = new RecordingHmacProvider(Bytes(0xc1, 32));

        await Assert.ThrowsAsync<RecordException>(() =>
            RecoveryVerifier.MaterializeCandidateDplAsync(
                candidate, input, hmac).AsTask());

        Assert.Equal(0, hmac.Calls);
    }

    [Fact]
    public async Task DcpDcsTransactionMismatch_RejectsBeforeHmacCallback()
    {
        using var candidate = await OpenCandidateAsync();
        var checkpoint = Checkpoint(candidate);
        var badDcs = MutateField(checkpoint.Dcs, RecordDefinitions.Dcs1, 7);
        var badDcsRef = Reference(ArtifactType.Dcs1, badDcs);
        var dcq = ReplaceField(checkpoint.Dcq, RecordDefinitions.Dcq1, 4, badDcsRef);
        var input = SealedCheckpoint(
            checkpoint.Dcp, badDcs, dcq, checkpoint.Dcl, checkpoint.Drc);
        var hmac = new RecordingHmacProvider(Bytes(0xd1, 32));

        await Assert.ThrowsAsync<RecordException>(() =>
            RecoveryVerifier.MaterializeCandidateDplAsync(
                candidate, input, hmac).AsTask());

        Assert.Equal(0, hmac.Calls);
    }

    [Fact]
    public async Task WrongLengthHmacResult_RejectsAfterExactlyOneCallback()
    {
        using var candidate = await OpenCandidateAsync();
        var checkpoint = Checkpoint(candidate);
        var hmac = new RecordingHmacProvider(Bytes(0xe1, 31));

        await Assert.ThrowsAsync<RecordException>(() =>
            RecoveryVerifier.MaterializeCandidateDplAsync(
                candidate, checkpoint.Input, hmac).AsTask());

        Assert.Equal(1, hmac.Calls);
    }

    [Fact]
    public async Task CancellationBeforeMaterialization_YieldsZeroCallbacks()
    {
        using var candidate = await OpenCandidateAsync();
        var checkpoint = Checkpoint(candidate);
        var hmac = new RecordingHmacProvider(Bytes(0xf1, 32));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            RecoveryVerifier.MaterializeCandidateDplAsync(
                candidate, checkpoint.Input, hmac, cancellation.Token).AsTask());

        Assert.Equal(0, hmac.Calls);
    }

    [Fact]
    public async Task CancellationByHmacProvider_YieldsNoPlanAfterOneCallback()
    {
        using var candidate = await OpenCandidateAsync();
        var checkpoint = Checkpoint(candidate);
        using var cancellation = new CancellationTokenSource();
        var hmac = new RecordingHmacProvider(Bytes(0x91, 32), cancellation);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            RecoveryVerifier.MaterializeCandidateDplAsync(
                candidate, checkpoint.Input, hmac, cancellation.Token).AsTask());

        Assert.Equal(1, hmac.Calls);
    }

    private static async ValueTask<RecoveryCandidatePlan> OpenCandidateAsync()
    {
        var drm = Drm3Fixture.Create();
        var nonce = Bytes(7, 24);
        using var manifest = RecoveryManifestParser.DecodeOwned(drm, 6);
        var capsule = Drm3Fixture.CreateCapsule(drm, nonce);
        capsule = ReplaceField(capsule, RecordDefinitions.Drc1, 3,
            manifest.RfcSourceTuple.Slice(128, 32).ToArray());
        return await RecoveryTestAccess.OpenUnverifiedCandidateAsync(
            capsule, new PlaintextProvider(nonce, drm), new StoredLatch(), default);
    }

    private static CheckpointFixture Checkpoint(RecoveryCandidatePlan candidate)
    {
        var projection = candidate.PinCoreProjection.Span;
        var drc = candidate.Capsule.CanonicalBytes.ToArray();
        var drcRecord = CanonicalGrammar.DecodeOwned(drc, RecordDefinitions.Drc1);
        var transaction = drcRecord.FieldCopy(3);
        var dcpFields = Minimum(RecordDefinitions.Dcp1);
        dcpFields[0] = projection[..16].ToArray();
        dcpFields[1] = drcRecord.FieldCopy(2);
        dcpFields[2] = projection.Slice(16, 2).ToArray();
        dcpFields[5] = projection.Slice(18, 8).ToArray();
        dcpFields[6] = projection.Slice(72, 38).ToArray();
        dcpFields[10] = projection.Slice(190, 38).ToArray();
        dcpFields[11] = transaction;
        dcpFields[19] = Reference(ArtifactType.Drc1, drc);
        var dcp = CanonicalGrammar.Encode(RecordDefinitions.Dcp1, dcpFields);

        var dcsFields = Minimum(RecordDefinitions.Dcs1);
        dcsFields[0] = projection[..16].ToArray();
        dcsFields[5] = projection.Slice(72, 38).ToArray();
        dcsFields[6] = transaction;
        dcsFields[9] = new byte[] { 4 };
        var componentRows = new byte[416];
        for (var index = 0; index < 4; index++)
            BinaryPrimitives.WriteUInt16BigEndian(
                componentRows.AsSpan(index * 104, 2), checked((ushort)(index + 1)));
        dcsFields[10] = componentRows;
        var dcs = CanonicalGrammar.Encode(RecordDefinitions.Dcs1, dcsFields);

        var dcqFields = Minimum(RecordDefinitions.Dcq1);
        dcqFields[0] = projection[..16].ToArray();
        dcqFields[3] = Reference(ArtifactType.Dcs1, dcs);
        dcqFields[4] = Reference(ArtifactType.Dct1, 414, 0x73);
        dcqFields[8] = new byte[] { 3 };
        dcqFields[9] = ReceiptBlob(758);
        var dcq = CanonicalGrammar.Encode(RecordDefinitions.Dcq1, dcqFields);
        var dcqRecord = CanonicalGrammar.DecodeOwned(dcq, RecordDefinitions.Dcq1);
        var dclFields = Minimum(RecordDefinitions.Dcl1);
        dclFields[0] = dcqRecord.FieldCopy(1);
        dclFields[1] = dcqRecord.FieldCopy(2);
        dclFields[2] = dcqRecord.FieldCopy(3);
        dclFields[3] = Reference(ArtifactType.Dcs1, dcs);
        dclFields[4] = dcqRecord.FieldCopy(6);
        dclFields[6] = dcqRecord.FieldCopy(7);
        dclFields[7] = dcqRecord.FieldCopy(8);
        dclFields[9] = new byte[] { 3 };
        dclFields[10] = ReceiptBlob(710);
        var dcl = CanonicalGrammar.Encode(RecordDefinitions.Dcl1, dclFields);
        return new CheckpointFixture(dcp, dcs, dcq, dcl, drc,
            SealedCheckpoint(dcp, dcs, dcq, dcl, drc));
    }

    private static VerifiedRecoveredCutoverCheckpoint SealedCheckpoint(
        byte[] dcp, byte[] dcs, byte[] dcq, byte[] dcl, byte[] drc) => new(
            CanonicalGrammar.DecodeOwned(dcp, RecordDefinitions.Dcp1),
            CanonicalGrammar.DecodeOwned(dcs, RecordDefinitions.Dcs1),
            CanonicalGrammar.DecodeOwned(dcq, RecordDefinitions.Dcq1),
            CanonicalGrammar.DecodeOwned(dcl, RecordDefinitions.Dcl1),
            CanonicalGrammar.DecodeOwned(drc, RecordDefinitions.Drc1),
            SHA256.HashData("cutover"u8),
            SHA256.HashData("old-source"u8));

    private static byte[] MutateField(
        byte[] canonical, RecordDefinition definition, int tag)
    {
        var record = CanonicalGrammar.DecodeOwned(canonical, definition);
        var replacement = record.FieldCopy(tag);
        replacement[0] ^= 1;
        return ReplaceField(canonical, definition, tag, replacement);
    }

    private static byte[] ReplaceField(
        byte[] canonical, RecordDefinition definition, int tag, byte[] replacement)
    {
        var record = CanonicalGrammar.DecodeOwned(canonical, definition);
        var fields = definition.Fields.Select((_, index) =>
            (ReadOnlyMemory<byte>)(index + 1 == tag ? replacement : record.FieldCopy(index + 1)))
            .ToArray();
        return CanonicalGrammar.Encode(definition, fields);
    }

    private static ReadOnlyMemory<byte>[] Minimum(RecordDefinition definition) =>
        definition.Fields.Select(static field =>
            (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();

    private static byte[] Reference(ArtifactType type, ReadOnlySpan<byte> canonical) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, canonical));

    private static byte[] Reference(ArtifactType type, uint length, byte marker)
    {
        var output = new byte[38];
        BinaryPrimitives.WriteUInt16BigEndian(output, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(2), length);
        output.AsSpan(6).Fill(marker);
        return output;
    }

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private static byte[] ReceiptBlob(int receiptLength)
    {
        var output = new byte[3 * (4 + receiptLength)];
        for (var index = 0; index < 3; index++)
            BinaryPrimitives.WriteUInt32BigEndian(
                output.AsSpan(index * (4 + receiptLength), 4), checked((uint)receiptLength));
        return output;
    }

    private sealed record CheckpointFixture(
        byte[] Dcp, byte[] Dcs, byte[] Dcq, byte[] Dcl, byte[] Drc,
        VerifiedRecoveredCutoverCheckpoint Input);

    private sealed class PlaintextProvider(byte[] nonce, byte[] plaintext)
        : RecoveryProtectorProvider
    {
        public override ValueTask DeriveNonceAsync(
            RecoveryProviderRequest request,
            Memory<byte> derivedNonce24,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            nonce.CopyTo(derivedNonce24);
            return ValueTask.CompletedTask;
        }

        public override ValueTask OpenAsync(
            RecoveryProviderRequest request,
            Memory<byte> plaintextDestination,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            plaintext.CopyTo(plaintextDestination);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class StoredLatch : RecoveryNonceLatch
    {
        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(RecoveryNonceLatchDecision.Stored);
        }
    }

    private sealed class RecordingHmacProvider(
        byte[] tag, CancellationTokenSource? cancellation = null) : IProtectedHmacProvider
    {
        public int Calls { get; private set; }
        public string? Domain { get; private set; }
        public ushort Suite { get; private set; }
        public byte[]? KeyId { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            Domain = request.Domain;
            Suite = request.Suite;
            KeyId = request.ProtectedStateKeyId.ToArray();
            cancellation?.Cancel();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(tag);
        }
    }
}
