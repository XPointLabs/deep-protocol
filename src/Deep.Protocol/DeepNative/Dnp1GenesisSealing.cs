using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisRecoveryProtectorRequest
{
    private readonly byte[] _scope;
    internal GenesisRecoveryProtectorRequest(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(intent);
        if (!ReferenceEquals(intent.Identity, identity))
            Invalid("The genesis protector request combines unrelated sealed facts.");
        _scope = identity.Scope.ExactScope.ToArray();
    }
    public ReadOnlyMemory<byte> ExactTransactionScope => _scope.ToArray();
    internal ReadOnlySpan<byte> TrustedScope => _scope;
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisRecoveryProtectorReadResult
{
    private readonly byte[] _protectorKeyId;
    private readonly byte[] _latchKeyId;
    public GenesisRecoveryProtectorReadResult(
        ReadOnlySpan<byte> protectorKeyId,
        ReadOnlySpan<byte> recoveryNonceLatchKeyId,
        ulong sourceRevision,
        bool protectorHealthy,
        bool latchHealthy)
    {
        _protectorKeyId = protectorKeyId.ToArray();
        _latchKeyId = recoveryNonceLatchKeyId.ToArray();
        SourceRevision = sourceRevision;
        ProtectorHealthy = protectorHealthy;
        LatchHealthy = latchHealthy;
    }
    public ReadOnlyMemory<byte> ProtectorKeyId => _protectorKeyId.ToArray();
    public ReadOnlyMemory<byte> RecoveryNonceLatchKeyId => _latchKeyId.ToArray();
    public ulong SourceRevision { get; }
    public bool ProtectorHealthy { get; }
    public bool LatchHealthy { get; }
}

/// <summary>
/// Typed consumer/HSM boundary for deterministic recovery sealing. The provider owns all key
/// material; Protocol owns and clears every plaintext, ciphertext, nonce and self-open buffer.
/// </summary>
public abstract class RecoverySealingProvider
{
    public abstract ValueTask<GenesisRecoveryProtectorReadResult> ReadAsync(
        GenesisRecoveryProtectorRequest request,
        CancellationToken cancellationToken);

    public abstract ValueTask DeriveNonceAsync(
        RecoverySealRequest request,
        Memory<byte> derivedNonce24,
        CancellationToken cancellationToken);

    public abstract ValueTask SealAsync(
        RecoverySealRequest request,
        ReadOnlyMemory<byte> plaintext,
        Memory<byte> ciphertextDestination,
        Memory<byte> authenticationTag16,
        CancellationToken cancellationToken);

    public abstract ValueTask OpenAsync(
        RecoverySealRequest request,
        ReadOnlyMemory<byte> ciphertext,
        ReadOnlyMemory<byte> authenticationTag16,
        Memory<byte> plaintextDestination,
        CancellationToken cancellationToken);
}

public sealed class RecoverySealRequest
{
    private readonly byte[] _network;
    private readonly byte[] _componentSubject;
    private readonly byte[] _transaction;
    private readonly byte[] _protectorKeyId;
    private readonly byte[] _associatedData;
    internal RecoverySealRequest(
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> componentSubject,
        ReadOnlySpan<byte> transaction,
        ReadOnlySpan<byte> protectorKeyId,
        ReadOnlySpan<byte> associatedData)
    {
        _network = network.ToArray();
        _componentSubject = componentSubject.ToArray();
        _transaction = transaction.ToArray();
        _protectorKeyId = protectorKeyId.ToArray();
        _associatedData = associatedData.ToArray();
    }
    public ReadOnlyMemory<byte> NetworkId => _network.ToArray();
    public ReadOnlyMemory<byte> ComponentSubject => _componentSubject.ToArray();
    public ReadOnlyMemory<byte> TransactionId => _transaction.ToArray();
    public ReadOnlyMemory<byte> ProtectorKeyId => _protectorKeyId.ToArray();
    public ReadOnlyMemory<byte> AssociatedData => _associatedData.ToArray();
    public ushort Suite => 1;
}

public sealed class GenesisRecoveryProtectorContext
{
    private readonly byte[] _scope;
    private readonly byte[] _protectorKeyId;
    private readonly byte[] _latchKeyId;
    private GenesisRecoveryProtectorContext(
        GenesisRecoveryProtectorRequest request,
        ReadOnlySpan<byte> protectorKeyId,
        ReadOnlySpan<byte> latchKeyId,
        ulong sourceRevision)
    {
        _scope = request.TrustedScope.ToArray();
        _protectorKeyId = protectorKeyId.ToArray();
        _latchKeyId = latchKeyId.ToArray();
        SourceRevision = sourceRevision;
    }
    public ulong SourceRevision { get; }
    public bool NoAuthorityClaim => true;
    internal ReadOnlySpan<byte> ProtectorKeyId => _protectorKeyId;
    internal ReadOnlySpan<byte> RecoveryNonceLatchKeyId => _latchKeyId;
    internal ReadOnlySpan<byte> ExactScope => _scope;

    internal static async ValueTask<GenesisRecoveryProtectorContext> ReadAsync(
        RecoverySealingProvider provider,
        GenesisRecoveryProtectorRequest request,
        ReadOnlyMemory<byte> sharedProtectedStateHmacKeyId,
        GenesisProtectedKeySetContext keySet,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        var returned = await provider.ReadAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (returned is null || returned.SourceRevision == 0 ||
            !returned.ProtectorHealthy || !returned.LatchHealthy)
            Invalid("The genesis recovery protector source is absent or unhealthy.");
        var protector = returned!.ProtectorKeyId.ToArray();
        var latch = returned.RecoveryNonceLatchKeyId.ToArray();
        if (protector.Length != 32 || latch.Length != 32 ||
            CanonicalGrammar.IsZero(protector) || CanonicalGrammar.IsZero(latch) ||
            CanonicalGrammar.FixedEquals(protector, latch) ||
            CanonicalGrammar.FixedEquals(protector, sharedProtectedStateHmacKeyId.Span) ||
            CanonicalGrammar.FixedEquals(latch, sharedProtectedStateHmacKeyId.Span) ||
            Collides(keySet, protector) || Collides(keySet, latch))
            Invalid("The genesis recovery protector roles are cross-fed.");
        return new GenesisRecoveryProtectorContext(
            request, protector, latch, returned.SourceRevision);
    }

    internal async ValueTask RevalidateAsync(
        RecoverySealingProvider provider,
        GenesisRecoveryProtectorRequest request,
        ReadOnlyMemory<byte> sharedProtectedStateHmacKeyId,
        GenesisProtectedKeySetContext keySet,
        CancellationToken cancellationToken)
    {
        var current = await ReadAsync(provider, request, sharedProtectedStateHmacKeyId,
            keySet, cancellationToken).ConfigureAwait(false);
        if (current.SourceRevision != SourceRevision ||
            !CanonicalGrammar.FixedEquals(current._scope, _scope) ||
            !CanonicalGrammar.FixedEquals(current._protectorKeyId, _protectorKeyId) ||
            !CanonicalGrammar.FixedEquals(current._latchKeyId, _latchKeyId))
            Invalid("The genesis recovery protector source moved during authoring.");
    }

    private static bool Collides(GenesisProtectedKeySetContext keySet, ReadOnlySpan<byte> id) =>
        CanonicalGrammar.FixedEquals(keySet.DplKeyId, id) ||
        CanonicalGrammar.FixedEquals(keySet.DwlKeyId, id) ||
        CanonicalGrammar.FixedEquals(keySet.RrlKeyId, id) ||
        CanonicalGrammar.FixedEquals(keySet.RibKeyId, id) ||
        CanonicalGrammar.FixedEquals(keySet.MrlcKeyId, id) ||
        CanonicalGrammar.FixedEquals(keySet.DxrKeyId, id);
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisCutoverSourceContext
{
    private readonly byte[] _source;
    private readonly byte[] _sourceFingerprint;
    private readonly byte[] _anchor;
    private readonly byte[] _anchorHash;
    private readonly byte[] _oldProtectedSource;
    private readonly GenesisIdentityContext _identity;
    private readonly GenesisComponentIntent _intent;
    private readonly GenesisReleaseContext _release;
    private readonly GenesisProtectedKeySetContext _keySet;
    private readonly GenesisRecoveryProtectorContext _protector;

    internal GenesisCutoverSourceContext(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisProtectedKeySetContext keySet,
        GenesisRecoveryProtectorContext protector)
    {
        if (!ReferenceEquals(intent.Identity, identity) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.Network, release.Network) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId, release.ResetId) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.Network, keySet.Network) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId, keySet.ResetId) ||
            identity.BaseIdentity.AccountGeneration != keySet.AccountGeneration ||
            intent.ComponentKind != keySet.ComponentKind ||
            !CanonicalGrammar.FixedEquals(intent.ComponentSubject.Span, keySet.ComponentSubject) ||
            !CanonicalGrammar.FixedEquals(identity.ProtectedStateHmacKeyId,
                release.ProtectedStateHmacKeyId.Span) ||
            !CanonicalGrammar.FixedEquals(identity.Scope.ExactScope, protector.ExactScope))
            Invalid("The genesis cutover source combines different sealed axes.");

        _identity = identity;
        _intent = intent;
        _release = release;
        _keySet = keySet;
        _protector = protector;

        var dcm = identity.BaseIdentity.Manifest.Record;
        var drs = identity.BaseIdentity.Identity.Revocations.Snapshot.Record;
        _source = new byte[492];
        var offset = 0;
        Append(identity.BaseIdentity.Network); Append(identity.BaseIdentity.ResetId);
        U16((ushort)intent.ComponentKind); Append(intent.ComponentSubject.Span);
        U64(identity.BaseIdentity.AccountGeneration); U64(Scalars.UInt64(dcm.FieldSpan(3)));
        Append(Reference(ArtifactType.Dcm1, dcm)); U64(Scalars.UInt64(drs.FieldSpan(4)));
        U64(Scalars.UInt16(drs.FieldSpan(9))); Append(drs.FieldSpan(11));
        Append(Reference(ArtifactType.Drs1, drs)); Append(release.LatestDwdReference);
        U64(release.LatestWitnessEpoch); Append(intent.SchemaFingerprint.Span);
        Append(keySet.DplKeyId); Append(keySet.DwlKeyId); Append(keySet.RrlKeyId);
        Append(keySet.RibKeyId); Append(keySet.MrlcKeyId); Append(keySet.DxrKeyId);
        if (offset != _source.Length) Invalid("The genesis cutover source width drifted.");
        _sourceFingerprint = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V2/recovery-genesis-cutover-source", _source);

        _anchor = new byte[460]; offset = 0;
        AppendAnchor(identity.BaseIdentity.Network); AppendAnchor(identity.BaseIdentity.ResetId);
        U16Anchor((ushort)intent.ComponentKind); AppendAnchor(intent.ComponentSubject.Span);
        U64Anchor(identity.BaseIdentity.AccountGeneration);
        AppendAnchor(Reference(ArtifactType.Dcm1, dcm));
        AppendAnchor(Reference(ArtifactType.Drs1, drs));
        AppendAnchor(release.LatestDwdReference); AppendAnchor(release.Fingerprint.Span);
        AppendAnchor(identity.Fingerprint.Span); AppendAnchor(_sourceFingerprint);
        AppendAnchor(identity.Transaction.TransactionId); AppendAnchor(protector.ProtectorKeyId);
        AppendAnchor(identity.ProtectedStateHmacKeyId); AppendAnchor(protector.RecoveryNonceLatchKeyId);
        AppendAnchor(intent.SchemaFingerprint.Span);
        if (offset != _anchor.Length) Invalid("The genesis cutover anchor width drifted.");
        _anchorHash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V2/recovery-genesis-cutover-anchor", _anchor);
        _oldProtectedSource = ComputeGenesisOldSource(
            _anchorHash, release.Fingerprint.Span, identity.Fingerprint.Span,
            _sourceFingerprint, identity.ProtectedStateHmacKeyId,
            protector.RecoveryNonceLatchKeyId, protector.ProtectorKeyId);

        void Append(ReadOnlySpan<byte> value) { value.CopyTo(_source.AsSpan(offset)); offset += value.Length; }
        void U64(ulong value) { BinaryPrimitives.WriteUInt64BigEndian(_source.AsSpan(offset, 8), value); offset += 8; }
        void U16(ushort value) { BinaryPrimitives.WriteUInt16BigEndian(_source.AsSpan(offset, 2), value); offset += 2; }
        void AppendAnchor(ReadOnlySpan<byte> value) { value.CopyTo(_anchor.AsSpan(offset)); offset += value.Length; }
        void U64Anchor(ulong value) { BinaryPrimitives.WriteUInt64BigEndian(_anchor.AsSpan(offset, 8), value); offset += 8; }
        void U16Anchor(ushort value) { BinaryPrimitives.WriteUInt16BigEndian(_anchor.AsSpan(offset, 2), value); offset += 2; }
    }

    public ReadOnlyMemory<byte> SourceFingerprint => _sourceFingerprint.ToArray();
    public ReadOnlyMemory<byte> GenesisAnchorHash => _anchorHash.ToArray();
    public bool NoAuthorityClaim => true;
    internal GenesisIdentityContext Identity => _identity;
    internal GenesisComponentIntent Intent => _intent;
    internal GenesisReleaseContext Release => _release;
    internal GenesisProtectedKeySetContext KeySet => _keySet;
    internal GenesisRecoveryProtectorContext Protector => _protector;
    internal ReadOnlySpan<byte> Source => _source;
    internal ReadOnlySpan<byte> Anchor => _anchor;
    internal ReadOnlySpan<byte> OldProtectedSource => _oldProtectedSource;

    private static byte[] ComputeGenesisOldSource(
        ReadOnlySpan<byte> anchor,
        ReadOnlySpan<byte> release,
        ReadOnlySpan<byte> identity,
        ReadOnlySpan<byte> source,
        ReadOnlySpan<byte> hmacKey,
        ReadOnlySpan<byte> latchKey,
        ReadOnlySpan<byte> protectorKey)
    {
        var tuple = new byte[348];
        var offset = 0; tuple[offset++] = 2;
        Append(new byte[38]); Append(anchor); Append(release); Append(identity); Append(source);
        tuple[offset++] = 0; Append(new byte[38]); Append(new byte[38]); offset += 8;
        Append(hmacKey); Append(latchKey); Append(protectorKey);
        if (offset != tuple.Length) Invalid("The genesis old-source width drifted.");
        var hash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V2/recovery-old-protected-source", tuple);
        CryptographicOperations.ZeroMemory(tuple);
        return hash;
        void Append(ReadOnlySpan<byte> value) { value.CopyTo(tuple.AsSpan(offset)); offset += value.Length; }
    }

    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

/// <summary>
/// A defensively owned, self-opened genesis recovery capsule.  It is cryptographic evidence
/// only; storage, witness quorum and zero-to-one cutover remain consumer responsibilities.
/// </summary>
public sealed class SealedGenesisRecoveryCandidate : IDisposable
{
    private byte[]? _manifest;
    private readonly byte[] _manifestHash;
    private readonly byte[] _rsmHash;
    private int _disposed;

    internal SealedGenesisRecoveryCandidate(
        RecoveryCapsule capsule,
        ReadOnlySpan<byte> manifest,
        ReadOnlySpan<byte> rsm)
    {
        Capsule = capsule;
        _manifest = manifest.ToArray();
        _manifestHash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-drm-hash", manifest);
        _rsmHash = RecoveryShadow.ComputeShadowHash(rsm);
    }

    public RecoveryCapsule Capsule { get; }
    public ReadOnlyMemory<byte> ManifestHash => _manifestHash.ToArray();
    public ReadOnlyMemory<byte> ShadowStateHash => _rsmHash.ToArray();
    public bool NoAuthorityClaim => true;
    internal ReadOnlySpan<byte> Manifest =>
        _manifest ?? throw new ObjectDisposedException(nameof(SealedGenesisRecoveryCandidate));

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        if (_manifest is not null) CryptographicOperations.ZeroMemory(_manifest);
        _manifest = null;
    }
}

internal sealed class OwnedGenesisRecoveryManifest : IDisposable
{
    private byte[]? _plaintext;
    private byte[]? _rsm;
    private readonly OwnedRecoveryManifest _decoded;

    internal OwnedGenesisRecoveryManifest(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> rsm)
    {
        RecoveryShadow.Preflight(rsm);
        _plaintext = plaintext.ToArray();
        _rsm = rsm.ToArray();
        var artifactCount = BinaryPrimitives.ReadUInt16BigEndian(_plaintext.AsSpan(6, 2));
        _decoded = RecoveryManifestParser.DecodeOwned(_plaintext, artifactCount);
        if (_rsm[96] != 2 ||
            !CanonicalGrammar.IsZero(_rsm.AsSpan(97, 38)) ||
            CanonicalGrammar.IsZero(_rsm.AsSpan(135, 32)) ||
            !CanonicalGrammar.FixedEquals(_rsm.AsSpan(243, 32),
                CanonicalGrammar.Sha256Domain(
                    "Deep/Cutover/V1/recovery-pin-core", _decoded.PinCoreProjection)) ||
            !CanonicalGrammar.FixedEquals(_rsm.AsSpan(275, 32),
                CanonicalGrammar.Sha256Domain(
                    "Deep/Cutover/V1/recovery-drm-hash", _decoded.CanonicalSpan)) ||
            !CanonicalGrammar.FixedEquals(_rsm.AsSpan(307, 32),
                RecoveryShadow.ComputeInventoryHash(_decoded)))
            Invalid("The owned genesis DRM20/RSM2 pair is not a canonical zero-predecessor closure.");
    }

    internal ReadOnlySpan<byte> Plaintext =>
        _plaintext ?? throw new ObjectDisposedException(nameof(OwnedGenesisRecoveryManifest));
    internal ReadOnlySpan<byte> Rsm =>
        _rsm ?? throw new ObjectDisposedException(nameof(OwnedGenesisRecoveryManifest));
    internal OwnedRecoveryManifest Decoded => _decoded;

    public void Dispose()
    {
        _decoded.Dispose();
        if (_plaintext is not null) CryptographicOperations.ZeroMemory(_plaintext);
        if (_rsm is not null) CryptographicOperations.ZeroMemory(_rsm);
        _plaintext = null;
        _rsm = null;
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

internal static class GenesisRecoverySealer
{
    internal static async ValueTask<SealedGenesisRecoveryCandidate> SealCandidateAsync(
        OwnedGenesisRecoveryManifest manifest,
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisCutoverSourceContext source,
        GenesisRecoveryProtectorContext protector,
        RecoverySealingProvider provider,
        RecoveryNonceLatch nonceLatch,
        ulong createdAtUnixSeconds,
        ulong retainUntilUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(nonceLatch);
        cancellationToken.ThrowIfCancellationRequested();
        if (!ReferenceEquals(intent.Identity, identity) || createdAtUnixSeconds == 0 ||
            retainUntilUnixSeconds <= createdAtUnixSeconds ||
            manifest.Plaintext.Length > 33_554_432 ||
            !CanonicalGrammar.FixedEquals(manifest.Rsm.Slice(135, 32),
                source.GenesisAnchorHash.Span) ||
            !CanonicalGrammar.FixedEquals(manifest.Rsm.Slice(691, 32),
                source.OldProtectedSource) ||
            !CanonicalGrammar.FixedEquals(manifest.Decoded.DtcProtectedKeyId,
                identity.ProtectedStateHmacKeyId))
            Invalid("The sealed genesis candidate inputs differ before provider work.");

        var nonce = new byte[24];
        var ciphertext = GC.AllocateUninitializedArray<byte>(manifest.Plaintext.Length);
        var tag = new byte[16];
        var selfOpened = GC.AllocateUninitializedArray<byte>(manifest.Plaintext.Length);
        var providerPlaintext = manifest.Plaintext.ToArray();
        byte[]? associatedData = null;
        byte[]? intentHash = null;
        try
        {
            var nonceRequest = new RecoverySealRequest(
                identity.BaseIdentity.Network, intent.ComponentSubject.Span,
                identity.Transaction.TransactionId, protector.ProtectorKeyId, []);
            await provider.DeriveNonceAsync(nonceRequest, nonce, cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (CanonicalGrammar.IsZero(nonce))
                Invalid("The recovery provider returned a zero nonce.");

            var fields = BuildFields(manifest, identity, intent, protector, nonce,
                createdAtUnixSeconds, retainUntilUnixSeconds, ciphertext, tag);
            var placeholder = CanonicalGrammar.Encode(RecordDefinitions.Drc1, Memories(fields));
            var decoded = CanonicalGrammar.DecodeOwned(placeholder, RecordDefinitions.Drc1);
            associatedData = BuildAssociatedData(decoded);
            var request = new RecoverySealRequest(
                identity.BaseIdentity.Network, intent.ComponentSubject.Span,
                identity.Transaction.TransactionId, protector.ProtectorKeyId, associatedData);
            intentHash = ComputeSealIntent(manifest.Plaintext, request, nonce);
            var latchRequest = new RecoveryNonceLatchRequest(
                protector.RecoveryNonceLatchKeyId, protector.ProtectorKeyId, nonce, intentHash);
            var decision = await nonceLatch.CompareOrLatchAsync(latchRequest, cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (decision == RecoveryNonceLatchDecision.ForkLatched ||
                decision is not (RecoveryNonceLatchDecision.Stored or RecoveryNonceLatchDecision.ExactReplay))
                Invalid("The genesis recovery nonce is latched to different bytes.");

            await provider.SealAsync(request, providerPlaintext, ciphertext, tag,
                cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            await provider.OpenAsync(request, ciphertext, tag, selfOpened, cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!CanonicalGrammar.FixedEquals(selfOpened, manifest.Plaintext))
                throw new RecordException(RecordError.InvalidSignature,
                    "The sealed genesis recovery capsule did not self-open byte-exactly.");

            fields[15] = ciphertext.ToArray();
            fields[16] = tag.ToArray();
            var canonical = CanonicalGrammar.Encode(RecordDefinitions.Drc1, Memories(fields));
            var owned = CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Drc1);
            return new SealedGenesisRecoveryCandidate(
                new RecoveryCapsule(owned), manifest.Plaintext, manifest.Rsm);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(selfOpened);
            CryptographicOperations.ZeroMemory(providerPlaintext);
            if (associatedData is not null) CryptographicOperations.ZeroMemory(associatedData);
            if (intentHash is not null) CryptographicOperations.ZeroMemory(intentHash);
        }
    }

    private static byte[][] BuildFields(
        OwnedGenesisRecoveryManifest manifest,
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisRecoveryProtectorContext protector,
        ReadOnlySpan<byte> nonce,
        ulong createdAt,
        ulong retainUntil,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag)
    {
        var fields = RecordDefinitions.Drc1.Fields.Select(static field =>
            new byte[field.MinimumLength]).ToArray();
        fields[0] = identity.BaseIdentity.Network.ToArray();
        fields[1] = intent.ComponentSubject.ToArray();
        fields[2] = identity.Transaction.TransactionId.ToArray();
        fields[3] = U64(identity.BaseIdentity.AccountGeneration);
        fields[4] = Reference(ArtifactType.Dcm1, identity.BaseIdentity.Manifest.Record);
        fields[5] = Reference(ArtifactType.Drs1,
            identity.BaseIdentity.Identity.Revocations.Snapshot.Record);
        fields[6] = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-pin-core", manifest.Decoded.PinCoreProjection);
        fields[7] = RecoveryShadow.ComputeShadowHash(manifest.Rsm);
        fields[8] = U16(checked((ushort)manifest.Decoded.Rows.Count));
        fields[9] = U64(checked((ulong)manifest.Plaintext.Length));
        fields[10] = U64(checked((ulong)ciphertext.Length));
        fields[11] = nonce.ToArray();
        fields[12] = protector.ProtectorKeyId.ToArray();
        fields[13] = U64(createdAt);
        fields[14] = U64(retainUntil);
        fields[15] = ciphertext.ToArray();
        fields[16] = tag.ToArray();
        return fields;
    }

    private static byte[] BuildAssociatedData(OwnedRecord record)
    {
        var metadataLength = CanonicalGrammar.HeaderLength;
        for (var tag = 1; tag <= 15; tag++)
            metadataLength = checked(metadataLength + CanonicalGrammar.FieldHeaderLength +
                record.FieldSpan(tag).Length);
        var output = new byte[4 + metadataLength];
        BinaryPrimitives.WriteUInt32BigEndian(output, checked((uint)metadataLength));
        record.CanonicalSpan[..CanonicalGrammar.HeaderLength].CopyTo(output.AsSpan(4));
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(12, 2), 15);
        var destination = 4 + CanonicalGrammar.HeaderLength;
        var source = CanonicalGrammar.HeaderLength;
        for (var tag = 1; tag <= 15; tag++)
        {
            var framedLength = CanonicalGrammar.FieldHeaderLength + record.FieldSpan(tag).Length;
            record.CanonicalSpan.Slice(source, framedLength).CopyTo(output.AsSpan(destination));
            source += framedLength;
            destination += framedLength;
        }
        return output;
    }

    private static byte[] ComputeSealIntent(
        ReadOnlySpan<byte> plaintext,
        RecoverySealRequest request,
        ReadOnlySpan<byte> nonce)
    {
        Span<byte> length = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(length, checked((ulong)plaintext.Length));
        var hashInput = new byte[8 + plaintext.Length];
        length.CopyTo(hashInput); plaintext.CopyTo(hashInput.AsSpan(8));
        var plaintextHash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V5/recovery-seal-plaintext", hashInput);
        var ad = request.AssociatedData.Span;
        var transcript = new byte[2 + 32 + 24 + 32 + 4 + ad.Length + 8 + 32];
        var offset = 0;
        BinaryPrimitives.WriteUInt16BigEndian(transcript.AsSpan(offset, 2), 1); offset += 2;
        request.ProtectorKeyId.Span.CopyTo(transcript.AsSpan(offset)); offset += 32;
        nonce.CopyTo(transcript.AsSpan(offset)); offset += 24;
        request.TransactionId.Span.CopyTo(transcript.AsSpan(offset)); offset += 32;
        BinaryPrimitives.WriteUInt32BigEndian(transcript.AsSpan(offset, 4),
            checked((uint)ad.Length)); offset += 4;
        ad.CopyTo(transcript.AsSpan(offset)); offset += ad.Length;
        BinaryPrimitives.WriteUInt64BigEndian(transcript.AsSpan(offset, 8),
            checked((ulong)plaintext.Length)); offset += 8;
        plaintextHash.CopyTo(transcript, offset);
        var result = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V5/recovery-seal-intent", transcript);
        CryptographicOperations.ZeroMemory(hashInput);
        CryptographicOperations.ZeroMemory(plaintextHash);
        CryptographicOperations.ZeroMemory(transcript);
        return result;
    }

    private static byte[] U16(ushort value)
    {
        var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes;
    }
    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes;
    }
    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private static IReadOnlyList<ReadOnlyMemory<byte>> Memories(byte[][] fields) =>
        fields.Select(static value => (ReadOnlyMemory<byte>)value).ToArray();
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<GenesisRecoveryProtectorContext>
        ReadGenesisRecoveryProtectorAsync(
            GenesisIdentityContext identity,
            GenesisComponentIntent intent,
            GenesisProtectedKeySetContext keySet,
            RecoverySealingProvider provider,
            CancellationToken cancellationToken = default)
    {
        var request = new GenesisRecoveryProtectorRequest(identity, intent);
        return await GenesisRecoveryProtectorContext.ReadAsync(provider, request,
            identity.ProtectedStateHmacKeyId.ToArray(), keySet, cancellationToken)
            .ConfigureAwait(false);
    }

    public static GenesisCutoverSourceContext CreateGenesisCutoverSourceContext(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisProtectedKeySetContext keySet,
        GenesisRecoveryProtectorContext protector) =>
        new(identity, intent, release, keySet, protector);
}
