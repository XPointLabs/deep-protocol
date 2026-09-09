using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

public enum DxpReceiptPhase : byte { Pending = 0, Verified = 1, Aborted = 2 }

/// <summary>
/// Exact source tuple for one DXP issuance operation. Instances are minted only
/// from sealed current-state facts; the fingerprint is not authority by itself.
/// </summary>
public sealed class DxpOperationSource
{
    private const string Domain = "Deep/IdentityAuth/V2/dxp-operation-source";
    private readonly byte[] _canonical;
    private readonly byte[] _fingerprint;
    private readonly DxpIdentityIssuanceSource _issuanceSource;

    internal DxpOperationSource(
        DxpIdentityIssuanceSource issuanceSource,
        byte stage,
        ReadOnlySpan<byte> subjectProjectionHash32,
        ReadOnlySpan<byte> priorSubjectLkgRef38,
        ReadOnlySpan<byte> transcriptHash32,
        ReadOnlySpan<byte> subjectArtifactRef38,
        ReadOnlySpan<byte> identityCatalogKeyId32,
        ReadOnlySpan<byte> dxrKeyId32,
        ReadOnlySpan<byte> nonceIndexKeyId32)
    {
        ArgumentNullException.ThrowIfNull(issuanceSource);
        if (stage > 1 || subjectProjectionHash32.Length != 32 ||
            priorSubjectLkgRef38.Length != 38 || transcriptHash32.Length != 32 ||
            subjectArtifactRef38.Length != 38 || identityCatalogKeyId32.Length != 32 ||
            dxrKeyId32.Length != 32 || nonceIndexKeyId32.Length != 32 ||
            CanonicalGrammar.IsZero(subjectProjectionHash32) ||
            CanonicalGrammar.IsZero(identityCatalogKeyId32) ||
            CanonicalGrammar.IsZero(dxrKeyId32) ||
            CanonicalGrammar.IsZero(nonceIndexKeyId32))
            Invalid("The DXP operation source is malformed.");
        if (stage == 0 && (!CanonicalGrammar.IsZero(transcriptHash32) ||
                           !CanonicalGrammar.IsZero(subjectArtifactRef38)) ||
            stage == 1 && (CanonicalGrammar.IsZero(transcriptHash32) ||
                           CanonicalGrammar.IsZero(subjectArtifactRef38)))
            Invalid("The DXP operation source stage shape is invalid.");

        _issuanceSource = issuanceSource;
        _canonical = new byte[1 + 1 + 1 + 32 + 32 + 8 + 8 + 32 + 38 + 32 + 38 + 32 + 38 + 32 + 32 + 32];
        var offset = 0;
        Append([(byte)issuanceSource.Kind]);
        Append([(byte)issuanceSource.Role]);
        Append([stage]);
        Append(issuanceSource.TrustedIdentityIssuanceSource);
        Append(issuanceSource.TrustedIssuanceScope);
        Span<byte> scalar = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(scalar, issuanceSource.DrsRevision); Append(scalar);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, issuanceSource.DrsCount); Append(scalar);
        Append(issuanceSource.DrsHead); Append(issuanceSource.DrsReference); Append(subjectProjectionHash32);
        Append(priorSubjectLkgRef38); Append(transcriptHash32); Append(subjectArtifactRef38);
        Append(identityCatalogKeyId32); Append(dxrKeyId32); Append(nonceIndexKeyId32);
        if (offset != _canonical.Length) Invalid("The DXP operation source length is invalid.");
        _fingerprint = CanonicalGrammar.Sha256Domain(Domain, _canonical);

        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(_canonical.AsSpan(offset));
            offset += value.Length;
        }
    }

    internal ReadOnlySpan<byte> TrustedCanonical => _canonical;
    internal DxpIdentityIssuanceSource IssuanceSource => _issuanceSource;
    internal X25519PossessionRole Role => (X25519PossessionRole)_canonical[1];
    internal byte Stage => _canonical[2];
    internal ReadOnlySpan<byte> Network => _issuanceSource.Network;
    internal ulong DrsRevision => BinaryPrimitives.ReadUInt64BigEndian(_canonical.AsSpan(67, 8));
    internal ulong DrsCount => BinaryPrimitives.ReadUInt64BigEndian(_canonical.AsSpan(75, 8));
    internal ReadOnlySpan<byte> DrsHead => _canonical.AsSpan(83, 32);
    internal ReadOnlySpan<byte> DrsReference => _canonical.AsSpan(115, 38);
    internal ReadOnlySpan<byte> SubjectProjectionHash => _canonical.AsSpan(153, 32);
    internal ReadOnlySpan<byte> TranscriptHash => _canonical.AsSpan(223, 32);
    internal ReadOnlySpan<byte> SubjectArtifactReference => _canonical.AsSpan(255, 38);
    internal ReadOnlySpan<byte> DxrKeyId => _canonical.AsSpan(325, 32);
    public ReadOnlyMemory<byte> Fingerprint => _fingerprint.ToArray();
    public bool NoAuthorityClaim => true;

    internal bool IsFinalSuccessorOf(DxpOperationSource pending)
    {
        if (pending.Stage != 0 || Stage != 1 || !_issuanceSource.SameBase(pending._issuanceSource))
            return false;
        return CanonicalGrammar.FixedEquals(
            pending._canonical.AsSpan(0, 2), _canonical.AsSpan(0, 2)) &&
            CanonicalGrammar.FixedEquals(
                pending._canonical.AsSpan(3, 220), _canonical.AsSpan(3, 220)) &&
            CanonicalGrammar.FixedEquals(
                pending._canonical.AsSpan(293), _canonical.AsSpan(293));
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

/// <summary>HMAC-verified, defensively owned DXR1 receipt relative to exact current sources.</summary>
public sealed class DxpReceiptRelative
{
    private readonly byte[] _canonical;
    internal DxpReceiptRelative(OwnedRecord record, DxpOperationSource source)
    {
        Record = record;
        Source = source;
        _canonical = record.CanonicalCopy();
    }

    internal OwnedRecord Record { get; }
    internal DxpOperationSource Source { get; }
    public DxpReceiptPhase Phase => (DxpReceiptPhase)Record.FieldSpan(1)[0];
    public X25519PossessionRole Role => (X25519PossessionRole)Record.FieldSpan(2)[0];
    public ReadOnlyMemory<byte> CanonicalBytes => _canonical.ToArray();
    public ReadOnlyMemory<byte> OperationId => Record.FieldCopy(4);
    public ReadOnlyMemory<byte> SubjectProjectionHash => Record.FieldCopy(5);
    public ReadOnlyMemory<byte> TranscriptHash => Record.FieldCopy(13);
    public ReadOnlyMemory<byte> SubjectArtifactReference => Record.FieldCopy(14);
    public ReadOnlyMemory<byte> SourceFingerprint => Record.FieldCopy(15);
    public ReadOnlyMemory<byte> ProtectedStateKeyId => Record.FieldCopy(16);
    public bool ForkLatched => Record.FieldSpan(17)[0] == 1;
    public bool NoAuthorityClaim => true;
}

/// <summary>Exact old-to-new DXR1 tuple for a consumer-owned atomic CAS.</summary>
public sealed class DxpReceiptTransitionPlan
{
    internal DxpReceiptTransitionPlan(
        DxpReceiptRelative current,
        DxpReceiptRelative next)
    {
        Current = current;
        Next = next;
    }
    public DxpReceiptRelative Current { get; }
    public DxpReceiptRelative Next { get; }
    public bool NoAuthorityClaim => true;
}

/// <summary>Restores and compares protected DXR1 rows without accepting key material.</summary>
public sealed class DxpReceiptVerifier
{
    internal const string ProtectedDomain = "Deep/ProtectedState/V1/DXP1-verified-receipt";

    public async ValueTask<DxpReceiptRelative> RestoreAsync(
        ReadOnlyMemory<byte> canonicalDxr1,
        DxpOperationSource expectedSource,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedSource);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        CanonicalGrammar.Preflight(canonicalDxr1.Span, RecordDefinitions.Dxr1);
        var record = CanonicalGrammar.DecodeOwned(canonicalDxr1.Span, RecordDefinitions.Dxr1);
        var phase = record.FieldSpan(1)[0];
        if (phase != expectedSource.Stage &&
            !(phase == (byte)DxpReceiptPhase.Aborted && expectedSource.Stage == 0))
            throw new RecordException(RecordError.InvalidTransition,
                "The DXR1 phase differs from its exact operation source.");
        if (phase == (byte)DxpReceiptPhase.Aborted &&
            (!CanonicalGrammar.IsZero(record.FieldSpan(12)) ||
             !CanonicalGrammar.IsZero(record.FieldSpan(13)) ||
             !CanonicalGrammar.IsZero(record.FieldSpan(14))))
            throw new RecordException(RecordError.InvalidTransition,
                "An Aborted DXR1 must not carry verified subject evidence.");
        if (phase == (byte)DxpReceiptPhase.Pending &&
            (!CanonicalGrammar.IsZero(record.FieldSpan(12)) ||
             !CanonicalGrammar.IsZero(record.FieldSpan(13)) ||
             !CanonicalGrammar.IsZero(record.FieldSpan(14))))
            throw new RecordException(RecordError.InvalidTransition,
                "A Pending DXR1 must not carry verified subject evidence.");
        if (record.FieldSpan(2)[0] != (byte)expectedSource.Role)
            throw new RecordException(RecordError.InvalidTransition,
                "The DXR1 role differs from its exact operation source.");
        if (!CanonicalGrammar.FixedEquals(record.FieldSpan(3), expectedSource.Network))
            throw new RecordException(RecordError.InvalidTransition,
                "The DXR1 network differs from its exact operation source.");
        if (!CanonicalGrammar.FixedEquals(record.FieldSpan(5), expectedSource.SubjectProjectionHash))
            throw new RecordException(RecordError.InvalidTransition,
                "The DXR1 projection differs from its exact operation source.");
        if (!CanonicalGrammar.FixedEquals(record.FieldSpan(13), expectedSource.TranscriptHash) ||
            !CanonicalGrammar.FixedEquals(
                record.FieldSpan(14), expectedSource.SubjectArtifactReference))
            throw new RecordException(RecordError.InvalidTransition,
                "The DXR1 final evidence differs from its exact operation source.");
        if (!CanonicalGrammar.FixedEquals(record.FieldSpan(15), expectedSource.Fingerprint.Span))
            throw new RecordException(RecordError.InvalidTransition,
                "The DXR1 fingerprint differs from its exact operation source.");
        if (!CanonicalGrammar.FixedEquals(record.FieldSpan(16), expectedSource.DxrKeyId))
            throw new RecordException(RecordError.InvalidTransition,
                "The DXR1 protected key differs from its exact operation source.");
        var unsigned = Unsigned(record);
        var request = new ProtectedHmacRequest(
            ProtectedDomain,
            ArtifactRegistry.ProtectedHmacSha256,
            record.FieldSpan(16),
            unsigned);
        var returned = await hmacProvider.ComputeTagAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var tag = returned.ToArray();
        if (tag.Length != 32 || !CanonicalGrammar.FixedEquals(tag, record.FieldSpan(19)))
            throw new RecordException(RecordError.InvalidSignature,
                "The DXR1 protected-state HMAC is invalid.");
        return new DxpReceiptRelative(record, expectedSource);
    }

    public DxpReceiptTransitionPlan VerifyFinalCas(
        DxpReceiptRelative pending,
        DxpReceiptRelative verified,
        DxpOperationSource expectedPendingSource,
        DxpOperationSource expectedVerifiedSource)
    {
        ArgumentNullException.ThrowIfNull(pending);
        ArgumentNullException.ThrowIfNull(verified);
        ArgumentNullException.ThrowIfNull(expectedPendingSource);
        ArgumentNullException.ThrowIfNull(expectedVerifiedSource);
        if (pending.Phase != DxpReceiptPhase.Pending ||
            verified.Phase != DxpReceiptPhase.Verified ||
            expectedPendingSource.Stage != 0 || expectedVerifiedSource.Stage != 1 ||
            !expectedVerifiedSource.IsFinalSuccessorOf(expectedPendingSource))
            Invalid("The DXR1 final CAS phases are invalid.");
        for (var tag = 2; tag <= 11; tag++)
            Equal(pending.Record.FieldSpan(tag), verified.Record.FieldSpan(tag),
                "The DXR1 immutable operation tuple changed.");
        Equal(pending.Record.FieldSpan(4), verified.Record.FieldSpan(4),
            "The DXR1 operation ID changed.");
        Equal(pending.Record.FieldSpan(15), expectedPendingSource.Fingerprint.Span,
            "The DXR1 Pending source changed.");
        Equal(verified.Record.FieldSpan(15), expectedVerifiedSource.Fingerprint.Span,
            "The DXR1 Verified source changed.");
        Equal(pending.Record.FieldSpan(16), verified.Record.FieldSpan(16),
            "The DXR1 protected key changed.");
        Equal(pending.Record.FieldSpan(18), verified.Record.FieldSpan(18),
            "The DXR1 retention horizon changed.");
        if (pending.ForkLatched || verified.ForkLatched)
            throw new RecordException(RecordError.ForkDetected,
                "A fork-latched DXR1 cannot transition.");
        return new DxpReceiptTransitionPlan(pending, verified);
    }

    internal static byte[] Unsigned(OwnedRecord record)
    {
        var definition = record.Definition with
        {
            Fields = record.Definition.Fields.Take(18).ToArray(),
            MinimumLength = 12,
            MaximumLength = 573,
            OmittedSigningFieldIndexes = new HashSet<int>()
        };
        var fields = Enumerable.Range(1, 18)
            .Select(tag => (ReadOnlyMemory<byte>)record.FieldCopy(tag)).ToArray();
        return CanonicalGrammar.Encode(definition, fields);
    }

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string message)
    {
        if (!CanonicalGrammar.FixedEquals(actual, expected)) Invalid(message);
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidTransition, message);
}
