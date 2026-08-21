using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class RecoverySchemaProfileTests
{
    [Fact]
    public void ExactTwentySixDrm20Lines_ProducePinnedFingerprint()
    {
        Assert.Equal(26, RecoverySchemaProfile.SourceLines.Length);
        var payload = Encoding.UTF8.GetBytes(
            string.Join('\n', RecoverySchemaProfile.SourceLines) + '\n');
        Assert.Equal(72_345, payload.Length);
        Assert.Equal(
            "0728ac6fd910831c935077012a9a90284f343ae8e3642ebced7072a45debac11",
            RecoveryShadow.ExpectedSchemaFingerprintHex);
        Assert.Equal(
            RecoveryShadow.ExpectedSchemaFingerprintHex,
            Convert.ToHexString(RecoveryShadow.ComputeSchemaFingerprint()).ToLowerInvariant());
    }

    [Fact]
    public void Rsm723_WrongSchemaOrOldLengthRejects()
    {
        var rsm = CanonicalRsm();
        RecoveryShadow.Preflight(rsm);
        var wrong = rsm.ToArray();
        wrong[RecoveryShadow.SchemaFingerprintOffset] ^= 1;
        Assert.Throws<RecordException>(() => RecoveryShadow.Preflight(wrong));
        Assert.Throws<RecordException>(() => RecoveryShadow.Preflight(rsm[..690]));
    }

    [Fact]
    public void Rsm723_PredecessorUnionAcceptsOnlyExactExistingOrGenesisShape()
    {
        RecoveryShadow.Preflight(CanonicalRsm(predecessorKind: 1));
        RecoveryShadow.Preflight(CanonicalRsm(predecessorKind: 2));

        foreach (var malformed in new[]
                 {
                     CanonicalRsm(predecessorKind: 0),
                     CanonicalRsm(predecessorKind: 3),
                     CanonicalRsm(predecessorKind: 1, includeOldDpl: false),
                     CanonicalRsm(predecessorKind: 1, includeAnchor: true),
                     CanonicalRsm(predecessorKind: 2, includeOldDpl: true),
                     CanonicalRsm(predecessorKind: 2, includeAnchor: false)
                 })
            Assert.Throws<RecordException>(() => RecoveryShadow.Preflight(malformed));
    }

    [Fact]
    public void CapsuleSource_V2IncludesPredecessorKindAndTypedRsmOffsets()
    {
        var rsm = CanonicalRsm(predecessorKind: 2);
        Span<byte> payload = stackalloc byte[289];
        payload[0] = 2;
        rsm.AsSpan(RecoveryShadow.OldProtectedSourceFingerprintOffset, 32)
            .CopyTo(payload[1..33]);
        RecoveryShadow.ComputeShadowHash(rsm).CopyTo(payload[33..65]);
        rsm.AsSpan(RecoveryShadow.RfcHashOffset, 32).CopyTo(payload[65..97]);
        rsm.AsSpan(RecoveryShadow.RfcKeyIdOffset, 32).CopyTo(payload[97..129]);
        rsm.AsSpan(RecoveryShadow.RpfHashOffset, 32).CopyTo(payload[129..161]);
        rsm.AsSpan(RecoveryShadow.RahHashOffset, 32).CopyTo(payload[161..193]);
        rsm.AsSpan(RecoveryShadow.DtcHashOffset, 32).CopyTo(payload[193..225]);
        rsm.AsSpan(RecoveryShadow.DtcKeyIdOffset, 32).CopyTo(payload[225..257]);
        rsm.AsSpan(RecoveryShadow.DwhHashOffset, 32).CopyTo(payload[257..289]);

        Assert.Equal(
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V2/recovery-capsule-source", payload),
            RecoveryShadow.ComputeCapsuleSource(rsm));
    }

    [Fact]
    public void SchemaProfile_ReorderAndSemanticSubstitutionCannotMatchPinnedFingerprint()
    {
        var expected = RecoveryShadow.ComputeSchemaFingerprint();
        var reordered = RecoverySchemaProfile.SourceLines.ToArray();
        (reordered[1], reordered[2]) = (reordered[2], reordered[1]);

        var semanticSubstitutions = new[]
        {
            (Old: "maximumPlaintextBytes=33554432", New: "maximumPlaintextBytes=33554431"),
            (Old: "Deep/ProtectedState/V1/RFC1", New: "Deep/ProtectedState/V1/RFC2"),
            (Old: "3,DRA1,oldDPACRef38", New: "4,DRA1,oldDPACRef38"),
            (Old: "target-kind3-DPA", New: "target-kind3-DPD"),
            (Old: "terminalRows=452", New: "terminalRows=451"),
            (Old: "DCM1.DPACRef38=row|DPA1", New: "DCM1.DPACRef38=row|DPD1"),
            (Old: "DCM1:DPACRef38->current-DPA1", New: "DCM1:DPACRef38->current-DPD1"),
            (Old: "RAH1 exact426", New: "RAH1 exact425")
        };

        Assert.NotEqual(expected, ComputeFingerprint(reordered));
        foreach (var substitution in semanticSubstitutions)
        {
            var changed = RecoverySchemaProfile.SourceLines.ToArray();
            var line = Array.FindIndex(changed,
                value => value.Contains(substitution.Old, StringComparison.Ordinal));
            Assert.True(line >= 0, $"Profile source does not contain '{substitution.Old}'.");
            changed[line] = changed[line].Replace(
                substitution.Old,
                substitution.New,
                StringComparison.Ordinal);
            Assert.NotEqual(expected, ComputeFingerprint(changed));
        }
    }

    [Fact]
    public void RfcHash_IsLengthFramedAndIncludesVerifiedTagBytes()
    {
        var rfc = new byte[232];
        "RFC1"u8.CopyTo(rfc); rfc[4] = 1;
        var first = RecoveryShadow.ComputeFrontierCheckpointHash(rfc);
        rfc[^1] = 1;
        var changedTag = RecoveryShadow.ComputeFrontierCheckpointHash(rfc);
        Assert.NotEqual(first, changedTag);

        var manuallyFramed = new byte[4 + rfc.Length];
        BinaryPrimitives.WriteUInt32BigEndian(manuallyFramed, (uint)rfc.Length);
        rfc.CopyTo(manuallyFramed, 4);
        Assert.Equal(CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-frontier-checkpoint-hash", manuallyFramed), changedTag);
    }

    private static byte[] CanonicalRsm(
        byte predecessorKind = 1,
        bool? includeOldDpl = null,
        bool? includeAnchor = null)
    {
        var rsm = Enumerable.Repeat((byte)1, RecoveryShadow.Length).ToArray();
        "RSM2"u8.CopyTo(rsm); rsm[4] = 1; rsm[5] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(rsm.AsSpan(22,2),(ushort)ComponentKind.Registry);
        BinaryPrimitives.WriteUInt64BigEndian(rsm.AsSpan(88,8),1);
        rsm[RecoveryShadow.PredecessorKindOffset] = predecessorKind;
        var hasOldDpl = includeOldDpl ?? predecessorKind == 1;
        var hasAnchor = includeAnchor ?? predecessorKind == 2;
        rsm.AsSpan(RecoveryShadow.OldDplReferenceOffset, ArtifactReference.Length).Clear();
        if (hasOldDpl)
            Reference(
                rsm.AsSpan(RecoveryShadow.OldDplReferenceOffset, ArtifactReference.Length),
                ArtifactType.Dpl1);
        rsm.AsSpan(RecoveryShadow.GenesisAnchorHashOffset, 32).Clear();
        if (hasAnchor)
            rsm.AsSpan(RecoveryShadow.GenesisAnchorHashOffset, 32).Fill(1);
        Reference(
            rsm.AsSpan(RecoveryShadow.DcmReferenceOffset, ArtifactReference.Length),
            ArtifactType.Dcm1);
        Reference(
            rsm.AsSpan(RecoveryShadow.DrsReferenceOffset, ArtifactReference.Length),
            ArtifactType.Drs1);
        Convert.FromHexString(RecoveryShadow.ExpectedSchemaFingerprintHex)
            .CopyTo(rsm, RecoveryShadow.SchemaFingerprintOffset);
        return rsm;
    }

    private static byte[] ComputeFingerprint(IEnumerable<string> sourceLines)
    {
        var payload = Encoding.UTF8.GetBytes(string.Join('\n', sourceLines) + '\n');
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-schema-profile-fingerprint",
            payload);
    }

    private static void Reference(Span<byte> destination, ArtifactType type)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination,(ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(destination[2..],1);
        destination[6..].Fill(1);
    }
}
