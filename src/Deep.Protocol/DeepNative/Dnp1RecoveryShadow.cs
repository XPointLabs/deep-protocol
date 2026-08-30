using System.Buffers.Binary;
using System.Text;

namespace Deep.Protocol.DeepNative;

internal static class RecoveryShadow
{
    internal const int Length = 723;
    internal const int PredecessorKindOffset = 96;
    internal const int OldDplReferenceOffset = 97;
    internal const int GenesisAnchorHashOffset = 135;
    internal const int DcmReferenceOffset = 167;
    internal const int DrsReferenceOffset = 205;
    internal const int PinCoreHashOffset = 243;
    internal const int DrmHashOffset = 275;
    internal const int ArtifactInventoryHashOffset = 307;
    internal const int RfcHashOffset = 339;
    internal const int RpfHashOffset = 371;
    internal const int RahHashOffset = 403;
    internal const int DtcHashOffset = 435;
    internal const int DwhHashOffset = 467;
    internal const int RfcKeyIdOffset = 499;
    internal const int DtcKeyIdOffset = 531;
    internal const int SchemaFingerprintOffset = 563;
    internal const int ReleaseContextFingerprintOffset = 595;
    internal const int IdentityContextFingerprintOffset = 627;
    internal const int CutoverOrGenesisSourceFingerprintOffset = 659;
    internal const int OldProtectedSourceFingerprintOffset = 691;

    private const byte ExistingDplPredecessor = 1;
    private const byte GenesisCutoverAnchorPredecessor = 2;
    private const string ShadowDomain = "Deep/Cutover/V2/recovery-shadow-state";
    private const string InventoryDomain = "Deep/Cutover/V1/recovery-artifact-inventory";
    private const string FrontierDomain = "Deep/Cutover/V1/recovery-frontier-checkpoint-hash";
    private const string ResetAuthorityHeadDomain =
        "Deep/Cutover/V1/recovery-reset-authority-head-fact";
    private const string SchemaDomain = "Deep/Cutover/V1/recovery-schema-profile-fingerprint";
    internal const string ExpectedSchemaFingerprintHex =
        "0728ac6fd910831c935077012a9a90284f343ae8e3642ebced7072a45debac11";

    internal static byte[] ComputeShadowHash(ReadOnlySpan<byte> exactRsm723)
    {
        Preflight(exactRsm723);
        return CanonicalGrammar.Sha256Domain(ShadowDomain, exactRsm723);
    }

    internal static byte[] ComputeInventoryHash(OwnedRecoveryManifest manifest)
    {
        var payload = new byte[2 + manifest.Rows.Count * ArtifactReference.Length];
        BinaryPrimitives.WriteUInt16BigEndian(payload, checked((ushort)manifest.Rows.Count));
        var offset = 2;
        foreach (var row in manifest.Rows)
        {
            CanonicalGrammar.EncodeReference(row.Reference).CopyTo(payload, offset);
            offset += ArtifactReference.Length;
        }
        return CanonicalGrammar.Sha256Domain(InventoryDomain, payload);
    }

    internal static byte[] ComputeFrontierCheckpointHash(ReadOnlySpan<byte> exactRfc)
    {
        if (exactRfc.Length < RecoveryManifestParser.RfcFixedLength ||
            exactRfc.Length > RecoveryManifestParser.RfcFixedLength +
                RecoveryManifestParser.MaximumFrontierCount *
                RecoveryManifestParser.RfcEntryLength)
            Invalid("The RFC1 length is invalid.");
        var payload = new byte[4 + exactRfc.Length];
        BinaryPrimitives.WriteUInt32BigEndian(payload, checked((uint)exactRfc.Length));
        exactRfc.CopyTo(payload.AsSpan(4));
        return CanonicalGrammar.Sha256Domain(FrontierDomain, payload);
    }

    internal static byte[] ComputeWitnessHeadHistoryHash(ReadOnlySpan<byte> exactDwh)
    {
        if (exactDwh.Length < RecoveryManifestParser.DwhFixedLength ||
            exactDwh.Length > RecoveryManifestParser.DwhFixedLength +
                64 * RecoveryManifestParser.DwhEntryLength)
            Invalid("The DWH1 length is invalid.");
        var payload = new byte[4 + exactDwh.Length];
        BinaryPrimitives.WriteUInt32BigEndian(payload, checked((uint)exactDwh.Length));
        exactDwh.CopyTo(payload.AsSpan(4));
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-witness-head-history", payload);
    }

    internal static byte[] ComputeResetAuthorityHeadHash(ReadOnlySpan<byte> exactRah)
    {
        if (exactRah.Length != RecoveryManifestParser.RahFixedLength)
            Invalid("The RAH1 length is invalid.");
        var payload = new byte[4 + exactRah.Length];
        BinaryPrimitives.WriteUInt32BigEndian(payload, checked((uint)exactRah.Length));
        exactRah.CopyTo(payload.AsSpan(4));
        return CanonicalGrammar.Sha256Domain(ResetAuthorityHeadDomain, payload);
    }

    internal static byte[] ComputeSchemaFingerprint()
    {
        var text = string.Join('\n', RecoverySchemaProfile.SourceLines) + '\n';
        var payload = Encoding.UTF8.GetBytes(text);
        if (RecoverySchemaProfile.SourceLines.Length != 26 || payload.Length != 72_345)
            Invalid("The compiled recovery schema profile source is invalid.");
        var computed = CanonicalGrammar.Sha256Domain(SchemaDomain, payload);
        Span<byte> expected = stackalloc byte[32];
        Convert.FromHexString(ExpectedSchemaFingerprintHex).CopyTo(expected);
        if (!CanonicalGrammar.FixedEquals(computed, expected))
            Invalid("The compiled recovery schema profile fingerprint is invalid.");
        return computed;
    }

    internal static byte[] ComputeCapsuleSource(ReadOnlySpan<byte> exactRsm723)
    {
        Preflight(exactRsm723);
        Span<byte> payload = stackalloc byte[289];
        payload[0] = exactRsm723[PredecessorKindOffset];
        exactRsm723.Slice(OldProtectedSourceFingerprintOffset, 32).CopyTo(payload[1..33]);
        ComputeShadowHash(exactRsm723).CopyTo(payload[33..65]);
        exactRsm723.Slice(RfcHashOffset, 32).CopyTo(payload[65..97]);
        exactRsm723.Slice(RfcKeyIdOffset, 32).CopyTo(payload[97..129]);
        exactRsm723.Slice(RpfHashOffset, 32).CopyTo(payload[129..161]);
        exactRsm723.Slice(RahHashOffset, 32).CopyTo(payload[161..193]);
        exactRsm723.Slice(DtcHashOffset, 32).CopyTo(payload[193..225]);
        exactRsm723.Slice(DtcKeyIdOffset, 32).CopyTo(payload[225..257]);
        exactRsm723.Slice(DwhHashOffset, 32).CopyTo(payload[257..289]);
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V2/recovery-capsule-source", payload);
    }

    internal static void Preflight(ReadOnlySpan<byte> value)
    {
        if (value.Length != Length || !value[..4].SequenceEqual(ProtocolMagicBytes.RSM2) ||
            value[4] != 1 || value[5] != 0 ||
            CanonicalGrammar.IsZero(value.Slice(6, 16)) ||
            !Enum.IsDefined((ComponentKind)BinaryPrimitives.ReadUInt16BigEndian(value[22..24])) ||
            BinaryPrimitives.ReadUInt16BigEndian(value[22..24]) == 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(value[88..96]) == 0 ||
            CanonicalGrammar.IsZero(value.Slice(OldProtectedSourceFingerprintOffset, 32)))
            Invalid("The RSM2 framing or source tuple is invalid.");

        var predecessorKind = value[PredecessorKindOffset];
        var oldDpl = CanonicalGrammar.DecodeReference(
            value.Slice(OldDplReferenceOffset, ArtifactReference.Length), allowZero: true);
        var anchorIsZero = CanonicalGrammar.IsZero(value.Slice(GenesisAnchorHashOffset, 32));
        if ((predecessorKind == ExistingDplPredecessor &&
                (oldDpl.IsZero || oldDpl.Type != ArtifactType.Dpl1 || !anchorIsZero)) ||
            (predecessorKind == GenesisCutoverAnchorPredecessor &&
                (!oldDpl.IsZero || anchorIsZero)) ||
            predecessorKind is not (ExistingDplPredecessor or GenesisCutoverAnchorPredecessor))
            Invalid("The RSM2 predecessor union is invalid.");

        var dcm = CanonicalGrammar.DecodeReference(
            value.Slice(DcmReferenceOffset, ArtifactReference.Length));
        var drs = CanonicalGrammar.DecodeReference(
            value.Slice(DrsReferenceOffset, ArtifactReference.Length));
        if (dcm.Type != ArtifactType.Dcm1 ||
            drs.Type != ArtifactType.Drs1)
            Invalid("RSM2 contains a wrong or descendant state reference.");
        for (var offset = PinCoreHashOffset; offset < Length; offset += 32)
            if (CanonicalGrammar.IsZero(value.Slice(offset, 32)))
                Invalid("RSM2 contains a zero binding hash or key ID.");
        if (!CanonicalGrammar.FixedEquals(
                value.Slice(SchemaFingerprintOffset, 32), ComputeSchemaFingerprint()))
            Invalid("RSM2 contains an unknown recovery schema profile fingerprint.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
