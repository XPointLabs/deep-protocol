using System.Buffers.Binary;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class WitnessHeadHistoryContainerTests
{
    [Fact]
    public void CountZero_IsExactOwnedDwh1AndHashUsesLengthFraming()
    {
        var plaintext = Drm3Fixture.Create();
        using var manifest = RecoveryManifestParser.DecodeOwned(plaintext, 6);
        var exact = manifest.WitnessHeadHistory.ToArray();

        Assert.Equal(RecoveryManifestParser.DwhFixedLength, exact.Length);
        Assert.Equal("DWH1"u8.ToArray(), exact[..4]);
        Assert.Equal((byte)1, exact[4]);
        Assert.Equal((byte)0, exact[5]);
        Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(exact.AsSpan(166, 2)));

        var framed = new byte[4 + exact.Length];
        BinaryPrimitives.WriteUInt32BigEndian(framed, checked((uint)exact.Length));
        exact.CopyTo(framed, 4);
        Assert.Equal(
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-witness-head-history", framed),
            RecoveryShadow.ComputeWitnessHeadHistoryHash(exact));

        plaintext.AsSpan().Fill(0xff);
        Assert.Equal("DWH1"u8.ToArray(), manifest.WitnessHeadHistory[..4].ToArray());
    }

    [Fact]
    public void Maximum64_IsExact22120ByteStructuralContainer()
    {
        var entries = Enumerable.Range(0, 64)
            .Select(index => Drm3Fixture.DwhEntry(
                checked((ulong)index + 1), checked((byte)(0x40 + index)),
                checked((ulong)index + 1)))
            .ToArray();

        using var manifest = RecoveryManifestParser.DecodeOwned(
            Drm3Fixture.CreateWithDwhEntries(entries), 6);

        Assert.Equal(64, BinaryPrimitives.ReadUInt16BigEndian(
            manifest.WitnessHeadHistory.Slice(166, 2)));
        Assert.Equal(22_120, manifest.WitnessHeadHistory.Length);
    }

    [Fact]
    public void Count65_RejectsDuringStructuralPreflight()
    {
        var bytes = Drm3Fixture.Create();
        var dwh = Drm3Fixture.Find(bytes, "DWH1");
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(dwh + 166, 2), 65);

        var error = Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.Preflight(bytes, 6));

        Assert.Equal(RecordError.InvalidLength, error.Error);
    }

    [Fact]
    public void NonConsecutiveGenerationRejectsButRandomReferenceHashOrderIsAccepted()
    {
        var first = Drm3Fixture.DwhEntry(1, 0x51, 1);
        var skipped = Drm3Fixture.DwhEntry(3, 0x52, 2);
        var error = Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.Preflight(
                Drm3Fixture.CreateWithDwhEntries(first, skipped), 6));
        Assert.Equal(RecordError.InvalidField, error.Error);

        var reversed = Drm3Fixture.DwhEntry(2, 0x50, 2);
        RecoveryManifestParser.Preflight(
            Drm3Fixture.CreateWithDwhEntries(first, reversed), 6);
    }

    [Fact]
    public void DuplicateWitnessIdAndNonemptyZeroRoot_RejectStructurally()
    {
        var duplicate = Drm3Fixture.DwhEntry(1, 0x51, 1);
        duplicate.AsSpan(54, 32).CopyTo(duplicate.AsSpan(126, 32));
        var error = Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.Preflight(
                Drm3Fixture.CreateWithDwhEntries(duplicate), 6));
        Assert.Equal(RecordError.InvalidField, error.Error);

        var zeroRoot = Drm3Fixture.DwhEntry(1, 0x51, 1);
        BinaryPrimitives.WriteUInt64BigEndian(zeroRoot.AsSpan(86, 8), 1);
        error = Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.Preflight(
                Drm3Fixture.CreateWithDwhEntries(zeroRoot), 6));
        Assert.Equal(RecordError.InvalidField, error.Error);
    }

    [Fact]
    public void SourceTupleAndProtectedKeyIdCrossFeed_RejectStructurally()
    {
        var sourceMismatch = Drm3Fixture.Create();
        var dwh = Drm3Fixture.Find(sourceMismatch, "DWH1");
        sourceMismatch[dwh + 22] ^= 1;
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.Preflight(sourceMismatch, 6));

        var zeroKeyId = Drm3Fixture.Create();
        dwh = Drm3Fixture.Find(zeroKeyId, "DWH1");
        zeroKeyId.AsSpan(dwh + 168, 32).Clear();
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.Preflight(zeroKeyId, 6));
    }

    [Fact]
    public void NormalStoreInput_PreflightsAllLengthsBeforeCopyAndOwnsDwh()
    {
        using var manifest = RecoveryManifestParser.DecodeOwned(Drm3Fixture.Create(), 6);
        var rfc = manifest.FrontierCheckpoint.ToArray();
        var rah = manifest.ResetAuthorityHead.ToArray();
        var dtc = manifest.DrtCatalog.ToArray();
        var dwh = manifest.WitnessHeadHistory.ToArray();

        var input = new NormalRecoveryStoreInput(rfc, rah, dtc, dwh);
        rfc.AsSpan().Fill(0xff);
        rah.AsSpan().Fill(0xff);
        dtc.AsSpan().Fill(0xff);
        dwh.AsSpan().Fill(0xff);

        Assert.True(input.NoAuthorityClaim);
        Assert.Equal("RAH1"u8.ToArray(), input.Rah[..4].ToArray());
        Assert.Equal("DWH1"u8.ToArray(), input.Dwh[..4].ToArray());

        var malformed = manifest.WitnessHeadHistory.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(malformed.AsSpan(166, 2), 64);
        var error = Assert.Throws<RecordException>(() =>
            new NormalRecoveryStoreInput(
                manifest.FrontierCheckpoint, manifest.ResetAuthorityHead,
                manifest.DrtCatalog, malformed));
        Assert.Equal(RecordError.InvalidField, error.Error);
    }

    [Fact]
    public void MissingLegacyOrHeadOnlyHistoryCannotBeSynthesizedIntoNormalStoreInput()
    {
        using var manifest = RecoveryManifestParser.DecodeOwned(Drm3Fixture.Create(), 6);
        var substitutes = new[]
        {
            Array.Empty<byte>(),
            new byte[RecoveryManifestParser.DwhFixedLength],
            Drm3Fixture.Fill(0x61, 32),
            "DWL1"u8.ToArray().Concat(
                new byte[RecoveryManifestParser.DwhFixedLength - 4]).ToArray()
        };

        foreach (var substitute in substitutes)
        {
            var error = Assert.Throws<RecordException>(() =>
                new NormalRecoveryStoreInput(
                    manifest.FrontierCheckpoint,
                    manifest.ResetAuthorityHead,
                    manifest.DrtCatalog,
                    substitute));
            Assert.True(error.Error is RecordError.InvalidField or RecordError.InvalidLength);
        }

        var coldPlaintext = Drm3Fixture.Create();
        var coldHistory = Drm3Fixture.Find(coldPlaintext, "DWH1");
        "DWL1"u8.CopyTo(coldPlaintext.AsSpan(coldHistory, 4));
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(coldPlaintext, 6));

        var constructor = Assert.Single(typeof(NormalRecoveryStoreInput).GetConstructors());
        var parameters = constructor.GetParameters();
        Assert.Equal(4, parameters.Length);
        Assert.Equal("exactDwh1", parameters[3].Name);
        Assert.True(new NormalRecoveryStoreInput(
            manifest.FrontierCheckpoint,
            manifest.ResetAuthorityHead,
            manifest.DrtCatalog,
            manifest.WitnessHeadHistory).NoAuthorityClaim);
    }
}
