using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// One owned DRM20/RSM2 genesis authoring result. Plaintext is deliberately not exposed;
/// only the typed sealing path may consume it.
/// </summary>
public sealed class GenesisRecoveryManifestPlan : IDisposable
{
    private OwnedGenesisRecoveryManifest? _owned;
    internal GenesisRecoveryManifestPlan(OwnedGenesisRecoveryManifest owned) => _owned = owned;
    internal OwnedGenesisRecoveryManifest TakeOrGet() =>
        _owned ?? throw new ObjectDisposedException(nameof(GenesisRecoveryManifestPlan));
    public bool NoAuthorityClaim => true;
    public void Dispose() => Interlocked.Exchange(ref _owned, null)?.Dispose();
}

internal static class GenesisRecoveryManifestAuthor
{
    internal static async ValueTask<GenesisRecoveryManifestPlan> AuthorAsync(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisCutoverSourceContext source,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        if (!ReferenceEquals(intent.Identity, identity) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.Network, release.Network) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId, release.ResetId))
            Invalid("The genesis manifest inputs do not share one sealed authority axis.");

        var rows = CollectRows(identity.BaseIdentity, release);
        // First-deployment and same-account genesis have no historical DRA frontier. A
        // nonzero predecessor is never silently dropped: the closed parser below rejects it.
        var common = CommonSource(identity, intent, source);
        var protectedKeyId = identity.ProtectedStateHmacKeyId.ToArray();
        var rfc = await AuthorRfcAsync(common, protectedKeyId,
            hmacProvider, cancellationToken).ConfigureAwait(false);
        var rpf = "RPF1\x01\0\0\0"u8.ToArray();
        var rah = await AuthorAbsentRahAsync(common, protectedKeyId,
            hmacProvider, cancellationToken).ConfigureAwait(false);
        var dwh = await AuthorDwhAsync(common, release, protectedKeyId,
            hmacProvider, cancellationToken).ConfigureAwait(false);
        var projection = BuildProjection(identity, intent, release);

        var rowBytes = rows.Select(static row =>
        {
            var artifactReference = ArtifactRegistry.IsRetained(row.Type)
                ? new ArtifactReference(row.Type, checked((uint)row.Canonical.Length),
                    SHA256.HashData(row.Canonical.Span))
                : CanonicalGrammar.ComputeReference(row.Type, row.Canonical.Span);
            var reference = CanonicalGrammar.EncodeReference(artifactReference);
            var output = new byte[38 + row.Canonical.Length];
            reference.CopyTo(output, 0); row.Canonical.Span.CopyTo(output.AsSpan(38));
            return (Reference: reference, Bytes: output);
        }).OrderBy(static row => row.Reference, ByteArrayComparer.Instance).ToArray();
        for (var index = 1; index < rowBytes.Length; index++)
            if (rowBytes[index - 1].Reference.AsSpan().SequenceCompareTo(rowBytes[index].Reference) >= 0)
                Invalid("The sealed genesis contexts contain duplicate canonical artifacts.");
        var length = checked(RecoveryManifestParser.PrefixLength + rfc.Length + rpf.Length +
            rah.Length + identity.DrtCatalog.Length + dwh.Length +
            rowBytes.Sum(static row => row.Bytes.Length));
        if (rowBytes.Length > RecoveryManifestParser.MaximumArtifactCount ||
            length > RecoveryManifestParser.MaximumPlaintextLength)
            Invalid("The genesis DRM20 exceeds its exact bounded profile.");
        var drm = new byte[length];
        "DRMV"u8.CopyTo(drm); drm[4] = 20; drm[5] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(drm.AsSpan(6, 2), checked((ushort)rowBytes.Length));
        BinaryPrimitives.WriteUInt16BigEndian(drm.AsSpan(8, 2), 274);
        projection.CopyTo(drm, 10);
        var offset = RecoveryManifestParser.PrefixLength;
        Append(rfc); Append(rpf); Append(rah); Append(identity.DrtCatalog); Append(dwh);
        foreach (var row in rowBytes) Append(row.Bytes);
        if (offset != drm.Length) Invalid("The genesis DRM20 assembly width drifted.");

        using var decoded = RecoveryManifestParser.DecodeOwned(
            drm, checked((ushort)rowBytes.Length));
        decoded.VerifyAuthenticatedAuthorityPartitions();
        var rsm = BuildRsm(identity, intent, release, source, decoded);
        return new GenesisRecoveryManifestPlan(new OwnedGenesisRecoveryManifest(drm, rsm));

        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(drm.AsSpan(offset)); offset += value.Length;
        }
    }

    private static IReadOnlyList<(ArtifactType Type, ReadOnlyMemory<byte> Canonical)> CollectRows(
        VerifiedGenesisBaseIdentityContext identity,
        GenesisReleaseContext release)
    {
        var rows = new List<(ArtifactType, ReadOnlyMemory<byte>)>();
        rows.AddRange(release.RecoveryRows);
        rows.AddRange(identity.RecoveryRows);
        return rows;
    }

    private static byte[] CommonSource(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisCutoverSourceContext source)
    {
        var common = new byte[160];
        identity.BaseIdentity.Network.CopyTo(common);
        identity.BaseIdentity.ResetId.CopyTo(common.AsSpan(16));
        BinaryPrimitives.WriteUInt16BigEndian(common.AsSpan(48, 2), (ushort)intent.ComponentKind);
        BinaryPrimitives.WriteUInt64BigEndian(common.AsSpan(50, 8), identity.BaseIdentity.AccountGeneration);
        // old DPL ref is canonically zero in the GenesisCutoverAnchor branch.
        source.OldProtectedSource.CopyTo(common.AsSpan(96));
        identity.Transaction.TransactionId.CopyTo(common.AsSpan(128));
        return common;
    }

    private static async ValueTask<byte[]> AuthorRfcAsync(
        ReadOnlyMemory<byte> common,
        ReadOnlyMemory<byte> keyId,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        var unsigned = new byte[RecoveryManifestParser.RfcFixedLength - 32];
        "RFC1"u8.CopyTo(unsigned); unsigned[4] = 1;
        common.Span.CopyTo(unsigned.AsSpan(6));
        // Count zero is valid only when every row predecessor is zero. The final DRM parser
        // proves that invariant before this plan can escape.
        keyId.Span.CopyTo(unsigned.AsSpan(168));
        return await GenesisProtectedRecords.AuthorAsync(
            "Deep/ProtectedState/V1/RFC1", unsigned, keyId,
            RecoveryManifestParser.RfcFixedLength, provider, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<byte[]> AuthorAbsentRahAsync(
        ReadOnlyMemory<byte> common,
        ReadOnlyMemory<byte> keyId,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        var unsigned = new byte[RecoveryManifestParser.RahFixedLength - 32];
        "RAH1"u8.CopyTo(unsigned); unsigned[4] = 1;
        common.Span.CopyTo(unsigned.AsSpan(6));
        // present=0 and the complete 195-byte historical tuple remain zero.
        keyId.Span.CopyTo(unsigned.AsSpan(362));
        return await GenesisProtectedRecords.AuthorAsync(
            "Deep/ProtectedState/V1/RAH1", unsigned, keyId,
            RecoveryManifestParser.RahFixedLength, provider, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<byte[]> AuthorDwhAsync(
        ReadOnlyMemory<byte> common,
        GenesisReleaseContext release,
        ReadOnlyMemory<byte> keyId,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        var whl = release.WitnessHeadHistoryLkg;
        var count = BinaryPrimitives.ReadUInt16BigEndian(whl.Slice(156, 2));
        var length = checked(RecoveryManifestParser.DwhFixedLength +
            count * RecoveryManifestParser.DwhEntryLength);
        var unsigned = new byte[length - 32];
        "DWH1"u8.CopyTo(unsigned); unsigned[4] = 1;
        common.Span.CopyTo(unsigned.AsSpan(6));
        BinaryPrimitives.WriteUInt16BigEndian(unsigned.AsSpan(166, 2), count);
        whl.Slice(158, count * RecoveryManifestParser.DwhEntryLength)
            .CopyTo(unsigned.AsSpan(168));
        keyId.Span.CopyTo(unsigned.AsSpan(unsigned.Length - 32));
        return await GenesisProtectedRecords.AuthorAsync(
            "Deep/ProtectedState/V1/DWH1", unsigned, keyId, length,
            provider, cancellationToken).ConfigureAwait(false);
    }

    private static byte[] BuildProjection(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release)
    {
        var dcm = identity.BaseIdentity.Manifest.Record;
        var drs = identity.BaseIdentity.Identity.Revocations.Snapshot.Record;
        var output = new byte[274]; var offset = 0;
        Append(identity.BaseIdentity.Network); U16((ushort)intent.ComponentKind);
        U64(identity.BaseIdentity.AccountGeneration);
        Append(Reference(ArtifactType.Dpa1, identity.BaseIdentity.Identity.Account.Certificate.Record));
        U64(Scalars.UInt64(dcm.FieldSpan(3))); Append(Reference(ArtifactType.Dcm1, dcm));
        Append(dcm.FieldSpan(11)); U64(Scalars.UInt64(drs.FieldSpan(4)));
        U64(Scalars.UInt16(drs.FieldSpan(9))); Append(drs.FieldSpan(11));
        Append(Reference(ArtifactType.Drs1, drs));
        Append(release.CurrentReleaseTransitionReference);
        output[offset++] = 0; offset += 7;
        if (offset != output.Length) Invalid("The genesis DPL projection width drifted.");
        return output;
        void Append(ReadOnlySpan<byte> value) { value.CopyTo(output.AsSpan(offset)); offset += value.Length; }
        void U16(ushort value) { BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset,2),value); offset += 2; }
        void U64(ulong value) { BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset,8),value); offset += 8; }
    }

    internal static byte[] BuildRsm(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisCutoverSourceContext source,
        OwnedRecoveryManifest manifest)
    {
        var rsm = new byte[RecoveryShadow.Length];
        "RSM2"u8.CopyTo(rsm); rsm[4] = 1;
        identity.BaseIdentity.Network.CopyTo(rsm.AsSpan(6));
        BinaryPrimitives.WriteUInt16BigEndian(rsm.AsSpan(22,2),(ushort)intent.ComponentKind);
        intent.ComponentSubject.Span.CopyTo(rsm.AsSpan(24));
        identity.Transaction.TransactionId.CopyTo(rsm.AsSpan(56));
        BinaryPrimitives.WriteUInt64BigEndian(rsm.AsSpan(88,8),identity.BaseIdentity.AccountGeneration);
        rsm[96] = 2;
        source.GenesisAnchorHash.Span.CopyTo(rsm.AsSpan(135));
        Reference(ArtifactType.Dcm1, identity.BaseIdentity.Manifest.Record).CopyTo(rsm,167);
        Reference(ArtifactType.Drs1,
            identity.BaseIdentity.Identity.Revocations.Snapshot.Record).CopyTo(rsm,205);
        CanonicalGrammar.Sha256Domain("Deep/Cutover/V1/recovery-pin-core",
            manifest.PinCoreProjection).CopyTo(rsm,243);
        CanonicalGrammar.Sha256Domain("Deep/Cutover/V1/recovery-drm-hash",
            manifest.CanonicalSpan).CopyTo(rsm,275);
        RecoveryShadow.ComputeInventoryHash(manifest).CopyTo(rsm,307);
        RecoveryShadow.ComputeFrontierCheckpointHash(manifest.FrontierCheckpoint).CopyTo(rsm,339);
        CanonicalGrammar.Sha256Domain("Deep/Cutover/V1/recovery-predecessor-frontier",
            manifest.PredecessorFrontier).CopyTo(rsm,371);
        RecoveryShadow.ComputeResetAuthorityHeadHash(manifest.ResetAuthorityHead).CopyTo(rsm,403);
        CanonicalGrammar.Sha256Domain("Deep/Cutover/V1/recovery-drt-catalog",
            manifest.DrtCatalog).CopyTo(rsm,435);
        RecoveryShadow.ComputeWitnessHeadHistoryHash(manifest.WitnessHeadHistory).CopyTo(rsm,467);
        manifest.RfcProtectedKeyId.CopyTo(rsm.AsSpan(499));
        manifest.DtcProtectedKeyId.CopyTo(rsm.AsSpan(531));
        RecoveryShadow.ComputeSchemaFingerprint().CopyTo(rsm,563);
        release.Fingerprint.Span.CopyTo(rsm.AsSpan(595));
        identity.Fingerprint.Span.CopyTo(rsm.AsSpan(627));
        source.SourceFingerprint.Span.CopyTo(rsm.AsSpan(659));
        source.OldProtectedSource.CopyTo(rsm.AsSpan(691));
        RecoveryShadow.Preflight(rsm);
        return rsm;
    }

    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static ByteArrayComparer Instance { get; } = new();
        public int Compare(byte[]? left, byte[]? right) => left is null ? -1 : right is null ? 1 :
            left.AsSpan().SequenceCompareTo(right);
    }
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<GenesisRecoveryManifestPlan> AuthorGenesisRecoveryManifestAsync(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisCutoverSourceContext source,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default) =>
        await GenesisRecoveryManifestAuthor.AuthorAsync(identity, intent, release, source,
            hmacProvider, cancellationToken).ConfigureAwait(false);

    public static async ValueTask<SealedGenesisRecoveryCandidate> SealGenesisCandidateAsync(
        GenesisRecoveryManifestPlan manifest,
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisCutoverSourceContext source,
        GenesisRecoveryProtectorContext protector,
        RecoverySealingProvider provider,
        RecoveryNonceLatch nonceLatch,
        ulong createdAtUnixSeconds,
        ulong retainUntilUnixSeconds,
        CancellationToken cancellationToken = default) =>
        await GenesisRecoverySealer.SealCandidateAsync(manifest.TakeOrGet(), identity, intent,
            source, protector, provider, nonceLatch, createdAtUnixSeconds,
            retainUntilUnixSeconds, cancellationToken).ConfigureAwait(false);
}
