using System.Buffers.Binary;
using System.Reflection;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class Drm3ContainerContractTests
{
    [Fact]
    public async Task RecoveryDrm3PinCoreCycleFree_OpensOnceAndRejectsLegacyVersions()
    {
        var drm3 = Drm3Fixture.Create();
        var nonce = Drm3Fixture.Fill(7, 24);
        var provider = new PlaintextProvider(nonce);
        using var candidate = await RecoveryTestAccess.OpenUnverifiedCandidateAsync(
            Drm3Fixture.CreateCapsule(drm3, nonce), provider, new StoredLatch(), default);

        Assert.Equal(1, provider.DeriveCalls);
        Assert.Equal(1, provider.OpenCalls);
        Assert.Equal(274, candidate.PinCoreProjection.Length);
        Assert.DoesNotContain(candidate.Artifacts, row => row.ArtifactType is
            ArtifactType.Dpl1 or ArtifactType.Dcp1 or ArtifactType.Drc1);

        foreach (var (magic, version) in new[] { ("DRM1", (byte)1), ("DRM2", (byte)2) })
        {
            var legacy = drm3.ToArray();
            System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(legacy, 0);
            legacy[4] = version;
            Assert.Throws<RecordException>(() =>
                RecoveryManifestParser.DecodeOwned(legacy, 6));
        }
    }

    [Fact]
    public void ExactPrefix_OwnsNonArtifactPinCoreAndExcludesCycleRows()
    {
        var bytes = Drm3Fixture.Create();

        using var manifest = RecoveryManifestParser.DecodeOwned(bytes, 6);

        Assert.Equal(284, RecoveryManifestParser.PrefixLength);
        Assert.Equal(274, manifest.PinCoreProjection.Length);
        Assert.Equal("DRMV"u8.ToArray(), manifest.CanonicalSpan[..4].ToArray());
        Assert.Equal((byte)20, manifest.CanonicalSpan[4]);
        Assert.Equal((byte)1, manifest.CanonicalSpan[5]);
        Assert.DoesNotContain(manifest.Rows, row => row.Reference.Type is
            ArtifactType.Dpl1 or ArtifactType.Dcp1 or ArtifactType.Drc1);
    }

    [Fact]
    public void FrozenDrm3Bounds_MatchNormativeMachineProfile()
    {
        Assert.Equal(284, RecoveryManifestParser.PrefixLength);
        Assert.Equal(274, RecoveryManifestParser.PinCoreLength);
        Assert.Equal(66, RecoveryManifestParser.MaximumFrontierCount);
        Assert.Equal(426, RecoveryManifestParser.RahFixedLength);
        Assert.Equal(1_024, RecoveryManifestParser.MaximumDrtCount);
        Assert.Equal(452, RecoveryManifestParser.MaximumArtifactCount);
        Assert.Equal(33_554_432, RecoveryManifestParser.MaximumPlaintextLength);
    }

    [Fact]
    public void Dtc2MaximumTargetAndHistoryTables_AcceptExact1024AndRejectMaxPlusOne()
    {
        var manifest = Drm3Fixture.Create();
        var dtcOffset = Drm3Fixture.Find(manifest, "DTC2");
        var empty = manifest.AsSpan(
            dtcOffset, RecoveryManifestParser.DtcFixedLength).ToArray();
        const int count = RecoveryManifestParser.MaximumDrtCount;
        var exactLength = checked(RecoveryManifestParser.DtcFixedLength +
            count * RecoveryManifestParser.DrtEntryLength +
            count * RecoveryManifestParser.DrtHistoryEntryLength);
        var maximum = new byte[exactLength];
        empty.AsSpan(0, 170).CopyTo(maximum);
        BinaryPrimitives.WriteUInt16BigEndian(maximum.AsSpan(166, 2), count);
        BinaryPrimitives.WriteUInt16BigEndian(maximum.AsSpan(168, 2), count);

        for (var index = 0; index < count; index++)
        {
            var target = maximum.AsSpan(
                170 + index * RecoveryManifestParser.DrtEntryLength,
                RecoveryManifestParser.DrtEntryLength);
            Drm3Fixture.WriteReference(target[..38], ArtifactType.Drt1, 179, 0x41);
            BinaryPrimitives.WriteUInt32BigEndian(target.Slice(34, 4),
                checked((uint)index));
            Drm3Fixture.WriteReference(target.Slice(217, 38),
                ArtifactType.Dpd1, 776, 0x51);
            BinaryPrimitives.WriteUInt32BigEndian(target.Slice(251, 4),
                checked((uint)index));
            target[255] = 1;
            target.Slice(256, 32).Fill(0x61);
            target.Slice(288, 32).Fill(0x62);
            BinaryPrimitives.WriteUInt16BigEndian(target.Slice(368, 2),
                checked((ushort)(index + 1)));

            var history = maximum.AsSpan(
                170 + count * RecoveryManifestParser.DrtEntryLength +
                index * RecoveryManifestParser.DrtHistoryEntryLength,
                RecoveryManifestParser.DrtHistoryEntryLength);
            Drm3Fixture.WriteReference(history[..38], ArtifactType.Drs1, 356, 0x71);
            BinaryPrimitives.WriteUInt32BigEndian(history.Slice(34, 4),
                checked((uint)index));
            BinaryPrimitives.WriteUInt64BigEndian(history.Slice(38, 8), 1);
            BinaryPrimitives.WriteUInt64BigEndian(history.Slice(86, 8), 1);
            history.Slice(140, 32).Fill(0x72);
        }

        empty.AsSpan(170, 64).CopyTo(maximum.AsSpan(exactLength - 64));

        Assert.Equal(555_242, maximum.Length);
        Assert.Equal(count, RecoveryManifestParser.PreflightDtcContainer(maximum));
        Assert.Equal(32_854_723,
            RecoveryManifestParser.MaximumPlaintextLength - 111_781 - 4_984 -
            5_156 - 426 - maximum.Length - 22_120);

        var targetMaxPlusOne = empty.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(targetMaxPlusOne.AsSpan(166, 2),
            count + 1);
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.PreflightDtcContainer(targetMaxPlusOne));

        var historyMaxPlusOne = empty.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(historyMaxPlusOne.AsSpan(166, 2), count);
        BinaryPrimitives.WriteUInt16BigEndian(historyMaxPlusOne.AsSpan(168, 2),
            count + 1);
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.PreflightDtcContainer(historyMaxPlusOne));
    }

    [Theory]
    [InlineData("DRM1", 1)]
    [InlineData("DRM2", 2)]
    public void LegacyManifestVersions_RejectWithoutReinterpretation(string magic, byte version)
    {
        var bytes = Drm3Fixture.Create();
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        bytes[4] = version;

        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(bytes, 6));
    }

    [Theory]
    [InlineData(4, 1)]
    [InlineData(5, 0)]
    [InlineData(8, 0)]
    [InlineData(9, 0)]
    public void PrefixClosedScalars_RejectBeforeOwnedManifest(int offset, byte value)
    {
        var bytes = Drm3Fixture.Create();
        bytes[offset] = value;

        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(bytes, 5));
    }

    [Fact]
    public void Containers_ExposeExactBoundedOwnedSlices()
    {
        using var manifest = RecoveryManifestParser.DecodeOwned(Drm3Fixture.Create(), 6);

        Assert.Equal(232, manifest.FrontierCheckpoint.Length);
        Assert.Equal(8, manifest.PredecessorFrontier.Length);
        Assert.Equal(426, manifest.ResetAuthorityHead.Length);
        Assert.Equal(234, manifest.DrtCatalog.Length);
        Assert.Equal(232, manifest.WitnessHeadHistory.Length);
        Assert.Equal("RFC1"u8.ToArray(), manifest.FrontierCheckpoint[..4].ToArray());
        Assert.Equal("RPF1"u8.ToArray(), manifest.PredecessorFrontier[..4].ToArray());
        Assert.Equal("RAH1"u8.ToArray(), manifest.ResetAuthorityHead[..4].ToArray());
        Assert.Equal("DTC2"u8.ToArray(), manifest.DrtCatalog[..4].ToArray());
        Assert.Equal("DWH1"u8.ToArray(), manifest.WitnessHeadHistory[..4].ToArray());
        Assert.Empty(manifest.FrontierEntries);
        Assert.Empty(manifest.PredecessorEntries);
        Assert.Empty(manifest.DrtEntries);
    }

    [Theory]
    [InlineData("RFC1", 166, 67)]
    [InlineData("RPF1", 6, 67)]
    [InlineData("DTC2", 166, 1025)]
    [InlineData("DTC2", 168, 1025)]
    public void ContainerMaximumPlusOne_RejectsBeforeRowDecode(
        string magic,
        int countOffset,
        ushort count)
    {
        var bytes = Drm3Fixture.Create();
        var container = Drm3Fixture.Find(bytes, magic);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(container + countOffset, 2), count);

        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(bytes, 6));
    }

    [Fact]
    public void RahAbsent_RequiresZeroFactTupleAndSharedProtectedKey()
    {
        var canonical = Drm3Fixture.Create();
        using var manifest = RecoveryManifestParser.DecodeOwned(canonical, 6);
        Assert.Equal((byte)0, manifest.ResetAuthorityHead[166]);
        Assert.True(manifest.ResetAuthorityHead.Slice(167, 195).IndexOfAnyExcept((byte)0) < 0);
        Assert.Equal(manifest.RfcProtectedKeyId.ToArray(), manifest.RahProtectedKeyId.ToArray());
        Assert.Equal(manifest.RfcProtectedKeyId.ToArray(), manifest.DtcProtectedKeyId.ToArray());
        Assert.Equal(manifest.RfcProtectedKeyId.ToArray(), manifest.DwhProtectedKeyId.ToArray());

        var factWhenAbsent = canonical.ToArray();
        factWhenAbsent[Drm3Fixture.Find(factWhenAbsent, "RAH1") + 167] = 1;
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(factWhenAbsent, 6));

        var crossFedKey = canonical.ToArray();
        crossFedKey[Drm3Fixture.Find(crossFedKey, "RAH1") + 362] ^= 1;
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(crossFedKey, 6));
    }

    [Fact]
    public void RahPresent_RejectsIncompleteHistoricalAuthorityBeforeRows()
    {
        var bytes = Drm3Fixture.Create();
        bytes[Drm3Fixture.Find(bytes, "RAH1") + 166] = 1;

        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(bytes, 6));
    }

    [Fact]
    public void RahHash_IsLengthFramedAndIncludesProtectedTagBytes()
    {
        using var manifest = RecoveryManifestParser.DecodeOwned(Drm3Fixture.Create(), 6);
        var rah = manifest.ResetAuthorityHead.ToArray();
        var first = RecoveryShadow.ComputeResetAuthorityHeadHash(rah);
        rah[^1] ^= 1;
        var changedTag = RecoveryShadow.ComputeResetAuthorityHeadHash(rah);
        Assert.NotEqual(first, changedTag);

        var framed = new byte[4 + rah.Length];
        BinaryPrimitives.WriteUInt32BigEndian(framed, checked((uint)rah.Length));
        rah.CopyTo(framed, 4);
        Assert.Equal(
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-reset-authority-head-fact", framed),
            changedTag);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(22)]
    [InlineData(54)]
    [InlineData(56)]
    [InlineData(64)]
    [InlineData(102)]
    [InlineData(134)]
    public void RahSourceTupleCrossFeed_RejectsBeforeRowDecode(int relativeOffset)
    {
        var bytes = Drm3Fixture.Create();
        bytes[Drm3Fixture.Find(bytes, "RAH1") + relativeOffset] ^= 1;

        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(bytes, 6));
    }

    [Fact]
    public void RfcAndRpf_RejectUnknownAndCrossFedKinds()
    {
        var bytes = Drm3Fixture.CreateOneDpaFrontier();

        var rfcUnknown = bytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(
            rfcUnknown.AsSpan(Drm3Fixture.Find(rfcUnknown, "RFC1") + 168, 2), 11);
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(rfcUnknown, 6));

        var rpfCrossKind = bytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(
            rpfCrossKind.AsSpan(Drm3Fixture.Find(rpfCrossKind, "RPF1") + 46, 2), 2);
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(rpfCrossKind, 6));
    }

    [Fact]
    public void RfcAndRpf_ExactTypedDpaFrontier_RoundTrips()
    {
        using var manifest = RecoveryManifestParser.DecodeOwned(
            Drm3Fixture.CreateOneDpaFrontier(), 6);

        Assert.Single(manifest.FrontierEntries);
        Assert.Single(manifest.PredecessorEntries);
        Assert.Equal((ushort)1, manifest.FrontierEntries[0].FieldKind);
        Assert.Equal(
            manifest.RfcPredecessor(0).ToArray(),
            manifest.RpfPredecessor(0).ToArray());
    }

    [Fact]
    public void DraFrontierKinds_AreThreeDistinctClosedSlots()
    {
        Assert.Equal(ArtifactType.Dpa1, Drm3Fixture.PredecessorType(3));
        Assert.Equal(ArtifactType.Dcm1, Drm3Fixture.PredecessorType(4));
        Assert.Equal(ArtifactType.Drs1, Drm3Fixture.PredecessorType(5));

        var bytes = Drm3Fixture.CreateOneDpaFrontier();
        var rfc = Drm3Fixture.Find(bytes, "RFC1");
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(rfc + 168, 2), 3);
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(bytes, 6));
    }

    [Fact]
    public void DtcTargetKind_RejectsArtifactTypeCrossFeedDuringStructuralPreflight()
    {
        var bytes = Drm3Fixture.CreateOneDtcEntry();
        var dtc = Drm3Fixture.Find(bytes, "DTC2");
        var entry = bytes.AsSpan(dtc + 170, RecoveryManifestParser.DrtEntryLength);
        entry[255] = (byte)RevocationTargetKind.AccountTerminal;
        Drm3Fixture.WriteReference(entry.Slice(217, 38), ArtifactType.Dpd1, 776, 0x91);

        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(bytes, 6));
    }

    [Fact]
    public void DtcProtectedFact_NoActiveRowOrCapabilitySurface()
    {
        var bytes = Drm3Fixture.CreateOneProtectedDtcEntry();

        using var manifest = RecoveryManifestParser.DecodeOwned(bytes, 6);

        Assert.Single(manifest.DrtEntries);
        Assert.DoesNotContain(manifest.Rows, row => row.Reference.Type is
            ArtifactType.Dpd1 or ArtifactType.Dpm1);
        Assert.Equal((ushort)1,
            BinaryPrimitives.ReadUInt16BigEndian(manifest.DrtCatalog.Slice(168, 2)));
        Assert.Equal((ushort)1,
            BinaryPrimitives.ReadUInt16BigEndian(manifest.DrtCatalog.Slice(170 + 368, 2)));
        Assert.True(manifest.DrtCatalog.Slice(170 + 370 + 102, 38)
            .IndexOfAnyExcept((byte)0) < 0);
        Assert.False(typeof(OwnedRecoveryManifest).IsPublic);
        Assert.False(typeof(RecoveryDrtEntry).IsPublic);
        Assert.DoesNotContain(typeof(RecoveryVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static), method =>
            method.ReturnType == typeof(OwnedRecoveryManifest) ||
            method.ReturnType == typeof(RecoveryDrtEntry) ||
            method.GetParameters().Any(parameter =>
                parameter.ParameterType == typeof(OwnedRecoveryManifest) ||
                parameter.ParameterType == typeof(RecoveryDrtEntry)));
    }

    [Fact]
    public void DtcProtectedHistory_OrdinalClosureRejectsMissingDuplicateUnusedAndOutOfRange()
    {
        var valid = Drm3Fixture.CreateOneProtectedDtcEntry();
        var dtc = Drm3Fixture.Find(valid, "DTC2");
        var ordinalOffset = dtc + 170 + 368;

        foreach (var ordinal in new ushort[] { 0, 2 })
        {
            var malformed = valid.ToArray();
            BinaryPrimitives.WriteUInt16BigEndian(malformed.AsSpan(ordinalOffset, 2), ordinal);
            Assert.Throws<RecordException>(() =>
                RecoveryManifestParser.DecodeOwned(malformed, 6));
        }

        var historyOffset = dtc + 170 + RecoveryManifestParser.DrtEntryLength;
        var historyEnd = historyOffset + RecoveryManifestParser.DrtHistoryEntryLength;
        var missing = new byte[valid.Length - RecoveryManifestParser.DrtHistoryEntryLength];
        valid.AsSpan(0, historyOffset).CopyTo(missing);
        valid.AsSpan(historyEnd).CopyTo(missing.AsSpan(historyOffset));
        BinaryPrimitives.WriteUInt16BigEndian(missing.AsSpan(dtc + 168, 2), 0);
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(missing, 6));

        var duplicate = InsertSecondHistory(valid, makeUnique: false);
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(duplicate, 6));

        var unused = InsertSecondHistory(valid, makeUnique: true);
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(unused, 6));
    }

    [Fact]
    public void DtcProtectedTarget_ActiveArtifactReferenceCollisionRejectsBeforeGraphValidation()
    {
        var bytes = Drm3Fixture.CreateOneProtectedDtcEntry(activeTargetCollision: true);

        var error = Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(bytes, 7));

        Assert.Contains("collides with an active DRM20 row", error.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void DtcProtectedHistory_StructuralAxisCrossFeedsRejectBeforeFactAcceptance()
    {
        var valid = Drm3Fixture.CreateOneProtectedDtcEntry();
        using var manifest = RecoveryManifestParser.DecodeOwned(valid, 6);
        var dtc = manifest.DtcOffset;
        var target = dtc + 170;
        var history = target + RecoveryManifestParser.DrtEntryLength;
        var drsRow = manifest.Rows.Single(row => row.Reference.Type == ArtifactType.Drs1);
        var dpaRow = manifest.Rows.Single(row => row.Reference.Type == ArtifactType.Dpa1);
        var dpa = CanonicalGrammar.DecodeOwned(
            valid.AsSpan(dpaRow.CanonicalOffset, dpaRow.CanonicalLength), RecordDefinitions.Dpa1);
        var wrongNetworkKeyPayload = new byte[89];
        dpa.FieldSpan(1).CopyTo(wrongNetworkKeyPayload); wrongNetworkKeyPayload[0] ^= 1;
        wrongNetworkKeyPayload[16] = (byte)KeyScope.AccountRevocation;
        manifest.DrtCatalog.Slice(170 + 256, 32).CopyTo(wrongNetworkKeyPayload.AsSpan(17));
        dpa.FieldSpan(2).CopyTo(wrongNetworkKeyPayload.AsSpan(49));
        dpa.FieldSpan(7).CopyTo(wrongNetworkKeyPayload.AsSpan(57));
        var wrongNetworkKeyHash = CanonicalGrammar.Sha256Domain(
            "Deep/IdentityAuth/V1/key-hash", wrongNetworkKeyPayload);
        var currentDrsReference = CanonicalGrammar.EncodeReference(drsRow.Reference);

        var mutations = new Action<byte[]>[]
        {
            bytes => wrongNetworkKeyHash.CopyTo(bytes, history + 140),
            bytes => bytes[target + 256] ^= 1,
            bytes => bytes[history + 140] ^= 1,
            bytes => bytes[target + 320] ^= 1,
            bytes => bytes[history + 54] ^= 1,
            bytes => currentDrsReference.CopyTo(bytes, history),
            bytes =>
            {
                BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(history + 94, 8), 1);
                var reference = bytes.AsSpan(history + 102, ArtifactReference.Length);
                BinaryPrimitives.WriteUInt16BigEndian(reference, (ushort)ArtifactType.Krt1);
                BinaryPrimitives.WriteUInt32BigEndian(reference[2..], 368);
                reference[6..].Fill(0x97);
            }
        };

        for (var index = 0; index < mutations.Length; index++)
        {
            var changed = valid.ToArray();
            mutations[index](changed);
            var error = Xunit.Record.Exception(() =>
            {
                using var decoded = RecoveryManifestParser.DecodeOwned(changed, 6);
                decoded.VerifyAuthenticatedAuthorityPartitions();
            });
            Assert.True(error is RecordException, $"Cross-feed mutation {index} was accepted.");
        }
    }

    [Fact]
    public void DtcPredecessorBranch_RejectsMixedExistingAndGenesisSourceTuples()
    {
        var genesis = Drm3Fixture.Create();
        foreach (var magic in new[] { "RFC1", "RAH1", "DWH1" })
            genesis.AsSpan(Drm3Fixture.Find(genesis, magic) + 64, 38).Clear();
        var dtc = Drm3Fixture.Find(genesis, "DTC2");
        genesis.AsSpan(dtc + 64, 70).Clear();

        using (RecoveryManifestParser.DecodeOwned(genesis,
                   BinaryPrimitives.ReadUInt16BigEndian(genesis.AsSpan(6, 2))))
        {
        }

        var mutations = new Action<byte[]>[]
        {
            value => value[Drm3Fixture.Find(value, "DTC2") + 102] = 1,
            value =>
            {
                var offset = Drm3Fixture.Find(value, "DTC2") + 64;
                Drm3Fixture.WriteReference(value.AsSpan(offset, 38),
                    ArtifactType.Dpl1, 576, 0xa1);
            },
            value =>
            {
                var offset = Drm3Fixture.Find(value, "RFC1") + 64;
                Drm3Fixture.WriteReference(value.AsSpan(offset, 38),
                    ArtifactType.Dpl1, 576, 0xa2);
            },
            value => value[Drm3Fixture.Find(value, "RAH1") + 102] = 0,
            value => value[Drm3Fixture.Find(value, "DTC2") + 134] ^= 1
        };
        foreach (var mutate in mutations)
        {
            var crossed = genesis.ToArray();
            mutate(crossed);
            Assert.Throws<RecordException>(() => RecoveryManifestParser.DecodeOwned(
                crossed, BinaryPrimitives.ReadUInt16BigEndian(crossed.AsSpan(6, 2))));
        }
    }

    private static byte[] InsertSecondHistory(byte[] valid, bool makeUnique)
    {
        var dtc = Drm3Fixture.Find(valid, "DTC2");
        var historyOffset = dtc + 170 + RecoveryManifestParser.DrtEntryLength;
        var historyLength = RecoveryManifestParser.DrtHistoryEntryLength;
        var historyEnd = historyOffset + historyLength;
        var first = valid.AsSpan(historyOffset, historyLength).ToArray();
        var second = first.ToArray();
        if (makeUnique) second[6] ^= 1;
        var histories = new[] { first, second };
        Array.Sort(histories, static (left, right) => left.AsSpan().SequenceCompareTo(right));
        var output = new byte[valid.Length + historyLength];
        valid.AsSpan(0, historyOffset).CopyTo(output);
        histories[0].CopyTo(output, historyOffset);
        histories[1].CopyTo(output, historyOffset + historyLength);
        valid.AsSpan(historyEnd).CopyTo(output.AsSpan(historyOffset + 2 * historyLength));
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(dtc + 168, 2), 2);
        var originalIndex = histories[0].AsSpan().SequenceEqual(first) ? 1 : 2;
        BinaryPrimitives.WriteUInt16BigEndian(
            output.AsSpan(dtc + 170 + RecoveryManifestParser.DrtEntryLength - 2, 2),
            checked((ushort)originalIndex));
        return output;
    }

    [Fact]
    public void DtcTargetSubject_DomainOrPreimageSubstitutionChangesTheExactSubject()
    {
        var network = Drm3Fixture.Fill(0x31, 16);
        var account = Drm3Fixture.Fill(0x32, 32);
        var generation = Drm3Fixture.U64(7);
        var device = Drm3Fixture.Fill(0x33, 32);
        var deviceGeneration = Drm3Fixture.U64(8);
        var dpaPayload = network.Concat(account).Concat(generation).ToArray();
        var dpdPayload = dpaPayload.Concat(device).Concat(deviceGeneration).ToArray();

        var dpa = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-target-subject/DPA", dpaPayload);
        var dpd = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-target-subject/DPD", dpdPayload);
        var wrongDomain = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-target-subject/DPA", dpdPayload);

        Assert.NotEqual(dpa, dpd);
        Assert.NotEqual(dpd, wrongDomain);
    }

    [Fact]
    public void ClosedProfile_RejectsForbiddenCandidateAndFuturePhaseRows()
    {
        foreach (var type in new[]
        {
            ArtifactType.Dpl1,
            ArtifactType.Dcp1,
            ArtifactType.Drc1,
            ArtifactType.Dpj1
        })
        {
            var bytes = Drm3Fixture.CreateWithReplacementRow(type);
            Assert.Throws<RecordException>(() =>
                RecoveryManifestParser.DecodeOwned(bytes, 6));
        }
    }

    [Fact]
    public void OwnedManifest_DisposalClosesAllInternalContainers()
    {
        var manifest = RecoveryManifestParser.DecodeOwned(Drm3Fixture.Create(), 6);
        manifest.Dispose();

        Assert.Throws<ObjectDisposedException>(() => manifest.CanonicalSpan.ToArray());
        Assert.Throws<ObjectDisposedException>(() => manifest.PinCoreProjection.ToArray());
        Assert.Throws<ObjectDisposedException>(() => manifest.FrontierCheckpoint.ToArray());
        Assert.Throws<ObjectDisposedException>(() => manifest.PredecessorFrontier.ToArray());
        Assert.Throws<ObjectDisposedException>(() => manifest.ResetAuthorityHead.ToArray());
        Assert.Throws<ObjectDisposedException>(() => manifest.DrtCatalog.ToArray());
        Assert.Throws<ObjectDisposedException>(() => manifest.WitnessHeadHistory.ToArray());
    }

    private sealed class PlaintextProvider(byte[] nonce) : RecoveryProtectorProvider
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
            request.Ciphertext.CopyTo(plaintextDestination);
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
}

internal static class Drm3Fixture
{
    /// <summary>
    /// Reusable canonical DRM20 fixture for recovery-engine tests. The returned arrays are fresh
    /// and caller-owned so provider, mutation, cancellation, and one-shot-zeroing tests can safely
    /// modify them without sharing state.
    /// </summary>
    internal static byte[] Create()
    {
        var rows = RequiredRows();
        return Assemble(rows, Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>());
    }

    internal static byte[] CreateWithDwhEntries(params byte[][] entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        if (entries.Length > 64 || entries.Any(entry =>
                entry is null || entry.Length != RecoveryManifestParser.DwhEntryLength))
            throw new ArgumentException("DWH1 entries must be exact 342-byte values.", nameof(entries));
        var flattened = new byte[checked(entries.Length * RecoveryManifestParser.DwhEntryLength)];
        for (var index = 0; index < entries.Length; index++)
            entries[index].CopyTo(flattened, index * RecoveryManifestParser.DwhEntryLength);
        return Assemble(RequiredRows(), Array.Empty<byte>(), Array.Empty<byte>(),
            Array.Empty<byte>(), flattened);
    }

    internal static byte[] DwhEntry(ulong generation, byte referenceMarker, ulong predecessorEpoch)
    {
        var output = new byte[RecoveryManifestParser.DwhEntryLength];
        Reference(ArtifactType.Dwd1, 776, referenceMarker).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(38, 8), generation);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(46, 8), predecessorEpoch);
        for (var head = 0; head < 4; head++)
        {
            output.AsSpan(54 + head * 72, 32).Fill(checked((byte)(0x80 + head)));
            // A zero-size root is checked against the predecessor descriptor during ancestry
            // restoration; structural framing deliberately leaves it opaque here.
        }
        return output;
    }

    internal static byte[] CreateCapsule(byte[] drm3, byte[] nonce24)
    {
        ArgumentNullException.ThrowIfNull(drm3);
        ArgumentNullException.ThrowIfNull(nonce24);
        if (nonce24.Length != 24) throw new ArgumentException("The nonce must be 24 bytes.", nameof(nonce24));
        _ = RecoveryManifestParser.Preflight(
            drm3,
            BinaryPrimitives.ReadUInt16BigEndian(drm3.AsSpan(6, 2)));
        var fields = Minimum(RecordDefinitions.Drc1);
        fields[0] = Fill(0x11, 16);
        fields[1] = Fill(0x12, 32);
        fields[2] = Fill(0x13, 32);
        fields[3] = U64(1);
        fields[4] = Reference(ArtifactType.Dcm1, 812, 0x14);
        fields[5] = Reference(ArtifactType.Drs1, 356, 0x15);
        fields[6] = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-pin-core", drm3.AsSpan(10, 274));
        fields[7] = Fill(0x16, 32);
        fields[8] = U16(BinaryPrimitives.ReadUInt16BigEndian(drm3.AsSpan(6, 2)));
        fields[9] = U64(checked((ulong)drm3.Length));
        fields[10] = U64(checked((ulong)drm3.Length));
        fields[11] = nonce24.ToArray();
        fields[12] = Fill(0x17, 32);
        fields[13] = U64(1);
        fields[14] = U64(100);
        fields[15] = drm3.ToArray();
        fields[16] = Fill(0x18, 16);
        return CanonicalGrammar.Encode(RecordDefinitions.Drc1, fields);
    }

    internal static byte[] CreateOneDpaFrontier()
    {
        var rows = RequiredRows(dpaPredecessor: Reference(ArtifactType.Dpa1, 644, 0xa1));
        var successor = rows.Single(row => row.Type == ArtifactType.Dpa1).Reference;
        var predecessor = Reference(ArtifactType.Dpa1, 644, 0xa1);
        var dpa = CanonicalGrammar.DecodeOwned(
            rows.Single(row => row.Type == ArtifactType.Dpa1).Canonical,
            RecordDefinitions.Dpa1);
        var subject = DpaFrontierSubject(dpa);
        var rfcEntry = new byte[72];
        BinaryPrimitives.WriteUInt16BigEndian(rfcEntry, 1);
        subject.CopyTo(rfcEntry, 2);
        predecessor.CopyTo(rfcEntry, 34);
        var rpfEntry = new byte[78];
        successor.CopyTo(rpfEntry, 0);
        BinaryPrimitives.WriteUInt16BigEndian(rpfEntry.AsSpan(38, 2), 1);
        predecessor.CopyTo(rpfEntry, 40);
        return Assemble(rows, rfcEntry, rpfEntry, Array.Empty<byte>());
    }

    private static byte[] DpaFrontierSubject(OwnedRecord dpa)
    {
        using var stream = new MemoryStream();
        stream.Write(dpa.FieldSpan(1));
        Span<byte> accountInput = stackalloc byte[56];
        dpa.FieldSpan(1).CopyTo(accountInput);
        dpa.FieldSpan(2).CopyTo(accountInput[16..]);
        dpa.FieldSpan(5).CopyTo(accountInput[24..]);
        stream.Write(CanonicalGrammar.Sha256Domain(
            "Deep/IdentityAuth/V1/account-id", accountInput));
        stream.Write(dpa.FieldSpan(2));
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-frontier-subject/DPA", stream.ToArray());
    }

    internal static byte[] CreateOneDtcEntry()
    {
        var rows = RequiredRows();
        var drtFields = Minimum(RecordDefinitions.Drt1);
        drtFields[0] = Fill(0x62, 32);
        drtFields[1] = new byte[] { (byte)RevocationTargetKind.DeviceCertificate };
        drtFields[2] = Fill(0x63, 32);
        drtFields[3] = U64(2);
        drtFields[4] = Reference(ArtifactType.Dpd1, 776, 0x64);
        drtFields[5] = U64(100);
        var drt = CanonicalGrammar.Encode(RecordDefinitions.Drt1, drtFields);
        var drtRef = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Drt1, drt));
        var entry = new byte[RecoveryManifestParser.DrtEntryLength];
        drtRef.CopyTo(entry, 0);
        drt.CopyTo(entry, 38);
        drtFields[4].Span.CopyTo(entry.AsSpan(217));
        entry[255] = (byte)RevocationTargetKind.DeviceCertificate;
        drtFields[0].Span.CopyTo(entry.AsSpan(256));
        Fill(0x65, 32).CopyTo(entry, 288);
        drtFields[3].Span.CopyTo(entry.AsSpan(320));
        drtFields[2].Span.CopyTo(entry.AsSpan(328));
        drtFields[5].Span.CopyTo(entry.AsSpan(360));

        // Keep the DRS row reference canonical after installing its one ordered DRT entry.
        var drsIndex = rows.FindIndex(row => row.Type == ArtifactType.Drs1);
        var drsFields = Minimum(RecordDefinitions.Drs1);
        drsFields[0] = Fill(0x11, 16);
        drsFields[1] = drtFields[0];
        drsFields[2] = U64(1);
        drsFields[8] = U16(1);
        var drsEntry = new byte[62];
        drsEntry[0] = (byte)RevocationTargetKind.DeviceCertificate;
        drtRef.CopyTo(drsEntry, 1);
        drsEntry[39] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(drsEntry.AsSpan(55, 2), 1);
        drsFields[9] = drsEntry;
        rows[drsIndex] = Row(ArtifactType.Drs1,
            CanonicalGrammar.Encode(RecordDefinitions.Drs1, drsFields));
        return Assemble(rows, Array.Empty<byte>(), Array.Empty<byte>(), entry);
    }

    internal static byte[] CreateOneProtectedDtcEntry(bool activeTargetCollision = false)
    {
        var rows = RequiredRows();
        var dpa = rows.Single(row => row.Type == ArtifactType.Dpa1);
        var dpaRecord = CanonicalGrammar.DecodeOwned(dpa.Canonical, RecordDefinitions.Dpa1);
        Span<byte> accountPayload = stackalloc byte[56];
        dpaRecord.FieldSpan(1).CopyTo(accountPayload);
        dpaRecord.FieldSpan(2).CopyTo(accountPayload[16..]);
        dpaRecord.FieldSpan(5).CopyTo(accountPayload[24..]);
        var accountHash = CanonicalGrammar.Sha256Domain(
            "Deep/IdentityAuth/V1/account-id", accountPayload);

        var targetReference = Reference(ArtifactType.Dpd1, 776, 0x84);
        var drtFields = Minimum(RecordDefinitions.Drt1);
        drtFields[0] = accountHash;
        drtFields[1] = new byte[] { (byte)RevocationTargetKind.DeviceCertificate };
        drtFields[2] = Fill(0x85, 32);
        drtFields[3] = U64(1);
        drtFields[4] = targetReference;
        drtFields[5] = U64(90);
        var drt = CanonicalGrammar.Encode(RecordDefinitions.Drt1, drtFields);
        var drtReference = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Drt1, drt));

        var target = new byte[RecoveryManifestParser.DrtEntryLength];
        drtReference.CopyTo(target, 0);
        drt.CopyTo(target, 38);
        targetReference.CopyTo(target, 217);
        target[255] = (byte)RevocationTargetKind.DeviceCertificate;
        accountHash.CopyTo(target, 256);
        Fill(0x86, 32).CopyTo(target, 288);
        U64(1).CopyTo(target, 320);
        drtFields[2].Span.CopyTo(target.AsSpan(328));
        U64(90).CopyTo(target, 360);
        BinaryPrimitives.WriteUInt16BigEndian(target.AsSpan(368, 2), 1);

        var drsEntry = new byte[62];
        drsEntry[0] = (byte)RevocationTargetKind.DeviceCertificate;
        drtReference.CopyTo(drsEntry, 1);
        U64(1).CopyTo(drsEntry, 39);
        U64(50).CopyTo(drsEntry, 47);
        BinaryPrimitives.WriteUInt16BigEndian(drsEntry.AsSpan(55, 2), 1);

        var drsFields = Minimum(RecordDefinitions.Drs1);
        drsFields[0] = dpaRecord.FieldCopy(1);
        drsFields[1] = accountHash;
        drsFields[2] = dpaRecord.FieldCopy(2);
        drsFields[3] = U64(2);
        drsFields[4] = U64(100);
        drsFields[8] = U16(1);
        drsFields[9] = drsEntry;
        var headPayload = new byte[158];
        drsFields[0].Span.CopyTo(headPayload);
        accountHash.CopyTo(headPayload, 16);
        drsFields[2].Span.CopyTo(headPayload.AsSpan(48));
        drsEntry.CopyTo(headPayload, 96);
        drsFields[10] = CanonicalGrammar.Sha256Domain(
            "Deep/IdentityAuth/V1/revocation-entry-head", headPayload);
        var drsIndex = rows.FindIndex(row => row.Type == ArtifactType.Drs1);
        rows[drsIndex] = Row(ArtifactType.Drs1,
            CanonicalGrammar.Encode(RecordDefinitions.Drs1, drsFields));

        var dcmIndex = rows.FindIndex(row => row.Type == ArtifactType.Dcm1);
        var dcm = CanonicalGrammar.DecodeOwned(rows[dcmIndex].Canonical, RecordDefinitions.Dcm1);
        var dcmFields = RecordDefinitions.Dcm1.Fields.Select((_, index) =>
            (ReadOnlyMemory<byte>)dcm.FieldCopy(index + 1)).ToArray();
        dcmFields[8] = rows[drsIndex].Reference;
        rows[dcmIndex] = Row(ArtifactType.Dcm1,
            CanonicalGrammar.Encode(RecordDefinitions.Dcm1, dcmFields));

        if (activeTargetCollision)
        {
            var dpdFields = Minimum(RecordDefinitions.Dpd1);
            dpdFields[0] = dpaRecord.FieldCopy(1);
            dpdFields[1] = accountHash;
            dpdFields[2] = dpaRecord.FieldCopy(2);
            dpdFields[3] = Fill(0x89, 32);
            dpdFields[4] = U64(1);
            dpdFields[5] = Fill(0x8A, 32);
            dpdFields[6] = Fill(0x8B, 32);
            dpdFields[7] = drtFields[2];
            dpdFields[8] = U64(0);
            dpdFields[9] = new byte[ArtifactReference.Length];
            dpdFields[10] = Fill(0x8C, 32);
            dpdFields[11] = U64(2);
            dpdFields[12] = rows[drsIndex].Reference;
            dpdFields[13] = U64(1);
            dpdFields[14] = drsFields[10];
            dpdFields[15] = U64(10);
            dpdFields[16] = U64(90);
            dpdFields[17] = U64(1);
            dpdFields[18] = U16(1);
            dpdFields[20] = Fill(0x8D, 32);
            rows.Add(new FixtureRow(ArtifactType.Dpd1, targetReference,
                CanonicalGrammar.Encode(RecordDefinitions.Dpd1, dpdFields)));
        }

        Span<byte> keyPayload = stackalloc byte[89];
        dpaRecord.FieldSpan(1).CopyTo(keyPayload);
        keyPayload[16] = (byte)KeyScope.AccountRevocation;
        accountHash.CopyTo(keyPayload[17..49]);
        dpaRecord.FieldSpan(2).CopyTo(keyPayload[49..57]);
        dpaRecord.FieldSpan(7).CopyTo(keyPayload[57..89]);
        var history = new byte[RecoveryManifestParser.DrtHistoryEntryLength];
        Reference(ArtifactType.Drs1, 256, 0x88).CopyTo(history, 0);
        U64(1).CopyTo(history, 38);
        U64(0).CopyTo(history, 46);
        U64(10).CopyTo(history, 86);
        U64(0).CopyTo(history, 94);
        CanonicalGrammar.Sha256Domain("Deep/IdentityAuth/V1/key-hash", keyPayload)
            .CopyTo(history, 140);

        return Assemble(rows, Array.Empty<byte>(), Array.Empty<byte>(), target,
            dtcHistoryEntries: history);
    }

    internal static byte[] CreateDtcTargetSubjectCrossKind(bool crossKind = true)
    {
        var rows = RequiredRows();
        var dpa = rows.Single(row => row.Type == ArtifactType.Dpa1);
        var dpaRecord = CanonicalGrammar.DecodeOwned(dpa.Canonical, RecordDefinitions.Dpa1);
        Span<byte> accountPayload = stackalloc byte[56];
        dpaRecord.FieldSpan(1).CopyTo(accountPayload);
        dpaRecord.FieldSpan(2).CopyTo(accountPayload[16..]);
        dpaRecord.FieldSpan(5).CopyTo(accountPayload[24..]);
        var accountHash = CanonicalGrammar.Sha256Domain(
            "Deep/IdentityAuth/V1/account-id", accountPayload);

        var drtFields = Minimum(RecordDefinitions.Drt1);
        drtFields[0] = accountHash;
        drtFields[1] = new byte[] { (byte)RevocationTargetKind.AccountTerminal };
        drtFields[2] = dpaRecord.FieldCopy(9);
        drtFields[3] = dpaRecord.FieldCopy(2);
        drtFields[4] = dpa.Reference;
        drtFields[5] = U64(0);
        var drt = CanonicalGrammar.Encode(RecordDefinitions.Drt1, drtFields);
        var drtRef = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Drt1, drt));

        var entry = new byte[RecoveryManifestParser.DrtEntryLength];
        drtRef.CopyTo(entry, 0);
        drt.CopyTo(entry, 38);
        dpa.Reference.CopyTo(entry, 217);
        entry[255] = (byte)RevocationTargetKind.AccountTerminal;
        accountHash.CopyTo(entry, 256);

        // Deliberately compute the target subject under the DPD domain and DPD-width
        // preimage. The artifact type and all other target facts still identify the exact
        // DPA1 row, so the authenticated semantic verifier must reject the cross-kind
        // subject instead of a structural/reference mismatch doing so earlier.
        if (crossKind)
        {
            var wrongSubjectPayload = new byte[96];
            dpaRecord.FieldSpan(1).CopyTo(wrongSubjectPayload);
            accountHash.CopyTo(wrongSubjectPayload, 16);
            dpaRecord.FieldSpan(2).CopyTo(wrongSubjectPayload.AsSpan(48));
            Fill(0x67, 32).CopyTo(wrongSubjectPayload, 56);
            U64(1).CopyTo(wrongSubjectPayload, 88);
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-target-subject/DPD", wrongSubjectPayload)
                .CopyTo(entry, 288);
        }
        else
        {
            var subjectPayload = new byte[56];
            dpaRecord.FieldSpan(1).CopyTo(subjectPayload);
            accountHash.CopyTo(subjectPayload, 16);
            dpaRecord.FieldSpan(2).CopyTo(subjectPayload.AsSpan(48));
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-target-subject/DPA", subjectPayload)
                .CopyTo(entry, 288);
        }
        dpaRecord.FieldSpan(2).CopyTo(entry.AsSpan(320));
        dpaRecord.FieldSpan(9).CopyTo(entry.AsSpan(328));
        U64(0).CopyTo(entry, 360);

        var drsIndex = rows.FindIndex(row => row.Type == ArtifactType.Drs1);
        var drsFields = Minimum(RecordDefinitions.Drs1);
        drsFields[0] = Fill(0x11, 16);
        drsFields[1] = accountHash;
        drsFields[2] = U64(1);
        drsFields[3] = U64(1);
        drsFields[8] = U16(1);
        var drsEntry = new byte[62];
        drsEntry[0] = (byte)RevocationTargetKind.AccountTerminal;
        drtRef.CopyTo(drsEntry, 1);
        U64(1).CopyTo(drsEntry, 39);
        U64(50).CopyTo(drsEntry, 47);
        BinaryPrimitives.WriteUInt16BigEndian(drsEntry.AsSpan(55, 2), 4);
        drsFields[9] = drsEntry;
        drsFields[10] = Fill(0x66, 32);
        rows[drsIndex] = Row(ArtifactType.Drs1,
            CanonicalGrammar.Encode(RecordDefinitions.Drs1, drsFields));

        var dcmIndex = rows.FindIndex(row => row.Type == ArtifactType.Dcm1);
        var dcm = CanonicalGrammar.DecodeOwned(rows[dcmIndex].Canonical, RecordDefinitions.Dcm1);
        var dcmFields = RecordDefinitions.Dcm1.Fields.Select((_, index) =>
            (ReadOnlyMemory<byte>)dcm.FieldCopy(index + 1)).ToArray();
        dcmFields[8] = rows[drsIndex].Reference;
        rows[dcmIndex] = Row(ArtifactType.Dcm1,
            CanonicalGrammar.Encode(RecordDefinitions.Dcm1, dcmFields));
        return Assemble(rows, Array.Empty<byte>(), Array.Empty<byte>(), entry);
    }

    internal static byte[] CreateWithReplacementRow(ArtifactType forbidden)
    {
        var rows = RequiredRows();
        rows.Add(Row(forbidden, Canonical(forbidden)));
        return Assemble(rows, Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>());
    }

    internal static int Find(byte[] bytes, string magic)
    {
        var needle = System.Text.Encoding.ASCII.GetBytes(magic);
        return bytes.AsSpan().IndexOf(needle);
    }

    internal static ArtifactType PredecessorType(ushort kind) => kind switch
    {
        3 => ArtifactType.Dpa1,
        4 => ArtifactType.Dcm1,
        5 => ArtifactType.Drs1,
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    internal static void WriteReference(
        Span<byte> destination,
        ArtifactType type,
        uint length,
        byte marker) => Reference(type, length, marker).CopyTo(destination);

    internal static byte[] Fill(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    internal static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static List<FixtureRow> RequiredRows(
        byte[]? dpaPredecessor = null,
        ushort drsEntryCount = 0)
    {
        var dpaFields = Minimum(RecordDefinitions.Dpa1);
        dpaFields[0] = Fill(0x11, 16);
        dpaFields[1] = U64(1);
        dpaFields[2] = U64(1);
        dpaFields[3] = dpaPredecessor ?? new byte[38];
        dpaFields[11] = U16(1);
        var dpa = Row(ArtifactType.Dpa1,
            CanonicalGrammar.Encode(RecordDefinitions.Dpa1, dpaFields));

        var drsFields = Minimum(RecordDefinitions.Drs1);
        drsFields[0] = Fill(0x11, 16);
        drsFields[1] = Fill(0x62, 32);
        drsFields[2] = U64(1);
        drsFields[8] = U16(drsEntryCount);
        drsFields[9] = drsEntryCount == 0 ? Array.Empty<byte>() : new byte[62 * drsEntryCount];
        var drs = Row(ArtifactType.Drs1,
            CanonicalGrammar.Encode(RecordDefinitions.Drs1, drsFields));

        var dcmFields = Minimum(RecordDefinitions.Dcm1);
        dcmFields[0] = Fill(0x11, 16);
        dcmFields[1] = Fill(0x21, 32);
        dcmFields[2] = U64(1);
        dcmFields[3] = U64(1);
        var dcm = Row(ArtifactType.Dcm1,
            CanonicalGrammar.Encode(RecordDefinitions.Dcm1, dcmFields));

        var rrmFields = Minimum(RecordDefinitions.Rrm1);
        rrmFields[0] = Fill(0x11, 16);
        rrmFields[2] = Fill(0x71, 32);
        rrmFields[4] = Fill(0x72, 32);
        rrmFields[6] = U64(15);
        rrmFields[7] = Fill(0x73, 32);
        rrmFields[8] = Fill(0x74, 32);
        var rrm = Row(ArtifactType.Rrm1,
            CanonicalGrammar.Encode(RecordDefinitions.Rrm1, rrmFields));

        var krtFields = Minimum(RecordDefinitions.Krt1);
        krtFields[0] = Fill(0x11, 16);
        krtFields[1] = new byte[] { (byte)KeyScope.ReleaseRoot };
        krtFields[4] = U64(1);
        krtFields[5] = rrm.Reference;
        krtFields[7] = Fill(0x75, 32);
        krtFields[9] = new byte[] { (byte)KeyAction.Rotate };
        var krt = Row(ArtifactType.Krt1,
            CanonicalGrammar.Encode(RecordDefinitions.Krt1, krtFields));

        var dwdFields = Minimum(RecordDefinitions.Dwd1);
        dwdFields[0] = Fill(0x11, 16);
        dwdFields[9] = U64(15);
        dwdFields[12] = new byte[] { 4 };
        var descriptors = new byte[464];
        for (var index = 0; index < 4; index++)
        {
            descriptors[index * 116 + 64] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(
                descriptors.AsSpan(index * 116 + 82, 2), checked((ushort)(9000 + index)));
        }
        dwdFields[13] = descriptors;
        dwdFields[15] = krt.Reference;
        var dwd = Row(ArtifactType.Dwd1,
            CanonicalGrammar.Encode(RecordDefinitions.Dwd1, dwdFields));

        var dcmRecord = CanonicalGrammar.DecodeOwned(dcm.Canonical, RecordDefinitions.Dcm1);
        var updatedDcm = dcmRecord.Definition.Fields
            .Select((_, index) => (ReadOnlyMemory<byte>)dcmRecord.FieldCopy(index + 1)).ToArray();
        updatedDcm[4] = dpa.Reference;
        updatedDcm[8] = drs.Reference;
        dcm = Row(ArtifactType.Dcm1,
            CanonicalGrammar.Encode(RecordDefinitions.Dcm1, updatedDcm));

        return new List<FixtureRow> { dpa, drs, dcm, dwd, rrm, krt };
    }

    private static byte[] Assemble(
        List<FixtureRow> rows,
        byte[] rfcEntries,
        byte[] rpfEntries,
        byte[] dtcEntries,
        byte[]? dwhEntries = null,
        byte[]? dtcHistoryEntries = null)
    {
        rows.Sort(static (left, right) => left.Reference.AsSpan().SequenceCompareTo(right.Reference));
        var projection = Projection(rows);
        var rfc = ProtectedContainer("RFC1", checked((ushort)(rfcEntries.Length / 72)), rfcEntries);
        var rpf = new byte[8 + rpfEntries.Length];
        "RPF1"u8.CopyTo(rpf);
        rpf[4] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(rpf.AsSpan(6, 2),
            checked((ushort)(rpfEntries.Length / 78)));
        rpfEntries.CopyTo(rpf, 8);
        var rah = ResetAuthorityHead();
        var dtc = ProtectedContainer("DTC2", checked((ushort)(dtcEntries.Length / 370)),
            dtcEntries, dtcHistoryEntries);
        dwhEntries ??= Array.Empty<byte>();
        var dwh = ProtectedContainer("DWH1", checked((ushort)(dwhEntries.Length / 342)), dwhEntries);
        var length = 284 + rfc.Length + rpf.Length + rah.Length + dtc.Length + dwh.Length +
            rows.Sum(row => 38 + row.Canonical.Length);
        var output = new byte[length];
        "DRMV"u8.CopyTo(output);
        output[4] = 20;
        output[5] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6, 2), checked((ushort)rows.Count));
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8, 2), 274);
        projection.CopyTo(output, 10);
        var offset = 284;
        rfc.CopyTo(output, offset); offset += rfc.Length;
        rpf.CopyTo(output, offset); offset += rpf.Length;
        rah.CopyTo(output, offset); offset += rah.Length;
        dtc.CopyTo(output, offset); offset += dtc.Length;
        dwh.CopyTo(output, offset); offset += dwh.Length;
        foreach (var row in rows)
        {
            row.Reference.CopyTo(output, offset); offset += 38;
            row.Canonical.CopyTo(output, offset); offset += row.Canonical.Length;
        }
        return output;
    }

    private static byte[] ResetAuthorityHead()
    {
        var output = new byte[RecoveryManifestParser.RahFixedLength];
        "RAH1"u8.CopyTo(output);
        output[4] = 1;
        Fill(0x11, 16).CopyTo(output, 6);
        Fill(0x21, 32).CopyTo(output, 22);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(54, 2), (ushort)ComponentKind.Shared);
        U64(1).CopyTo(output, 56);
        Reference(ArtifactType.Dpl1, 576, 0x41).CopyTo(output, 64);
        Fill(0x42, 32).CopyTo(output, 102);
        Fill(0x43, 32).CopyTo(output, 134);
        // present=0 requires the complete DRA/head fact range [167..362) to remain zero.
        Fill(0x44, 32).CopyTo(output, 362);
        return output;
    }

    private static byte[] Projection(List<FixtureRow> rows)
    {
        var output = new byte[274];
        Fill(0x11, 16).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(16, 2), (ushort)ComponentKind.Shared);
        U64(1).CopyTo(output, 18);
        rows.Single(row => row.Type == ArtifactType.Dpa1).Reference.CopyTo(output, 26);
        U64(1).CopyTo(output, 64);
        rows.Single(row => row.Type == ArtifactType.Dcm1).Reference.CopyTo(output, 72);
        Fill(0x51, 32).CopyTo(output, 110);
        rows.Single(row => row.Type == ArtifactType.Drs1).Reference.CopyTo(output, 190);
        return output;
    }

    private static byte[] ProtectedContainer(
        string magic,
        ushort count,
        byte[] entries,
        byte[]? historyEntries = null)
    {
        var entryLength = magic switch
        {
            "RFC1" => 72,
            "DTC2" => 370,
            "DWH1" => 342,
            _ => throw new ArgumentOutOfRangeException(nameof(magic))
        };
        var fixedLength = magic == "DTC2" ? 234 : 232;
        var entriesOffset = magic == "DTC2" ? 170 : 168;
        historyEntries ??= Array.Empty<byte>();
        if (magic != "DTC2" && historyEntries.Length != 0)
            throw new ArgumentException("Only DTC2 has a protected history table.", nameof(historyEntries));
        if (historyEntries.Length % RecoveryManifestParser.DrtHistoryEntryLength != 0)
            throw new ArgumentException("The DTC2 history table is not exact172.", nameof(historyEntries));
        var output = new byte[fixedLength + count * entryLength + historyEntries.Length];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        output[4] = magic == "DTC2" ? (byte)2 : (byte)1;
        Fill(0x11, 16).CopyTo(output, 6);
        Fill(0x21, 32).CopyTo(output, 22);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(54, 2), (ushort)ComponentKind.Shared);
        U64(1).CopyTo(output, 56);
        Reference(ArtifactType.Dpl1, 576, 0x41).CopyTo(output, 64);
        Fill(0x42, 32).CopyTo(output, 102);
        Fill(0x43, 32).CopyTo(output, 134);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(166, 2), count);
        if (magic == "DTC2")
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(168, 2),
                checked((ushort)(historyEntries.Length / RecoveryManifestParser.DrtHistoryEntryLength)));
        entries.CopyTo(output, entriesOffset);
        historyEntries.CopyTo(output, entriesOffset + entries.Length);
        Fill(0x44, 32).CopyTo(output, entriesOffset + entries.Length + historyEntries.Length);
        return output;
    }

    private static byte[] Canonical(ArtifactType type)
    {
        var definition = type switch
        {
            ArtifactType.Dpl1 => RecordDefinitions.Dpl1,
            ArtifactType.Dcp1 => RecordDefinitions.Dcp1,
            ArtifactType.Drc1 => RecordDefinitions.Drc1,
            ArtifactType.Dcl1 => RecordDefinitions.Dcl1,
            ArtifactType.Dhl1 => RecordDefinitions.Dhl1,
            ArtifactType.Dpj1 => RecordDefinitions.Dpj1,
            _ => throw new ArgumentOutOfRangeException(nameof(type))
        };
        var fields = Minimum(definition);
        switch (type)
        {
            case ArtifactType.Dpl1:
                fields[0] = Fill(1, 16); fields[1] = U16(1); fields[2] = U64(1); break;
            case ArtifactType.Dcp1:
                fields[2] = U16(1); break;
            case ArtifactType.Drc1:
                fields[8] = U16(1); break;
            case ArtifactType.Dcl1:
                fields[9] = new byte[] { 0 }; fields[10] = Array.Empty<byte>(); break;
            case ArtifactType.Dhl1:
                fields[10] = new byte[] { 0 }; fields[17] = new byte[] { 0 }; fields[18] = Array.Empty<byte>(); break;
            case ArtifactType.Dpj1:
                fields[7] = U16(1); break;
        }
        return CanonicalGrammar.Encode(definition, fields);
    }

    private static ReadOnlyMemory<byte>[] Minimum(RecordDefinition definition) =>
        definition.Fields.Select(static field =>
            (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();

    private static FixtureRow Row(ArtifactType type, byte[] canonical) => new(
        type,
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, canonical)),
        canonical);

    private static byte[] Reference(ArtifactType type, uint length, byte marker)
    {
        var output = new byte[38];
        WriteReferenceCore(output, type, length, marker);
        return output;
    }

    private static void WriteReferenceCore(byte[] output, ArtifactType type, uint length, byte marker)
    {
        BinaryPrimitives.WriteUInt16BigEndian(output, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(2, 4), length);
        output.AsSpan(6).Fill(marker);
    }

    private readonly record struct FixtureRow(ArtifactType Type, byte[] Reference, byte[] Canonical);
}
