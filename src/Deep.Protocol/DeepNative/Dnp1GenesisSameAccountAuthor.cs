using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisSameAccountOperationRequest
{
    private readonly byte[] _branchHash;
    private readonly byte[] _currentDcmRef;
    internal GenesisSameAccountOperationRequest(GenesisCutoverBranchContext branch)
    {
        _branchHash = branch.BranchHash.ToArray();
        _currentDcmRef = branch.CurrentCutover!.TrustedDcmRef.ToArray();
    }
    public ReadOnlyMemory<byte> BranchHash => _branchHash.ToArray();
    public ReadOnlyMemory<byte> CurrentDcmReference => _currentDcmRef.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisSameAccountOperationReadResult
{
    private readonly byte[] _operationId;
    public GenesisSameAccountOperationReadResult(ReadOnlySpan<byte> operationId32,
        ulong sourceRevision, bool healthy)
    { _operationId = operationId32.ToArray(); SourceRevision = sourceRevision; Healthy = healthy; }
    public ReadOnlyMemory<byte> OperationId => _operationId.ToArray();
    public ulong SourceRevision { get; }
    public bool Healthy { get; }
    public bool NoAuthorityClaim => true;
}

/// <summary>
/// Consumer-owned stable CSPRNG operation source for SameAccount. The value is a nonce and
/// idempotency key only; GDI1 remains the HMAC-protected authoring receipt.
/// </summary>
public abstract class GenesisSameAccountOperationProvider
{
    public abstract ValueTask<GenesisSameAccountOperationReadResult> RestoreOrCreateAsync(
        GenesisSameAccountOperationRequest request, CancellationToken cancellationToken);
}

internal static class GenesisSameAccountAuthor
{
    internal static async ValueTask<GenesisSignedCutoverManifestPlan> AuthorAsync(
        GenesisCutoverBranchContext branch, GenesisSameAccountOperationProvider operationProvider,
        GenesisDcmAuthoringProvider provider, GenesisOriginSigner signer,
        IProtectedHmacProvider hmacProvider, ulong createdAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(branch); ArgumentNullException.ThrowIfNull(operationProvider);
        ArgumentNullException.ThrowIfNull(provider); ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(hmacProvider); cancellationToken.ThrowIfCancellationRequested();
        if (branch.BranchKind != 2 || branch.CurrentCutover is null || createdAtUnixSeconds == 0)
            Invalid("SameAccount authoring requires one verified current cutover.");
        var operationRequest = new GenesisSameAccountOperationRequest(branch);
        var operation = await ReadOperationAsync(operationProvider, operationRequest,
            cancellationToken).ConfigureAwait(false);
        var operationReread = await ReadOperationAsync(operationProvider, operationRequest,
            cancellationToken).ConfigureAwait(false);
        if (operation.SourceRevision != operationReread.SourceRevision ||
            !CanonicalGrammar.FixedEquals(operation.OperationId.Span, operationReread.OperationId.Span))
            Invalid("The SameAccount operation moved before GDI1 persistence.");

        var preparedDcm = CreatePreparedDcm(branch, operation.OperationId.Span,
            createdAtUnixSeconds);
        var keyId = branch.Governance.ExactDgi.Slice(96, 32).ToArray();
        var request = new GenesisDcmPreparedRequest(branch, new byte[32], preparedDcm,
            keyId, operation.OperationId.Span);
        var preparedResult = await provider.RestoreOrCreatePreparedAsync(request, cancellationToken)
            .ConfigureAwait(false);
        var phase = preparedResult?.ExactRecord.Length == DeploymentGovernanceRecords.GdiLength
            ? preparedResult.ExactRecord.Span[965] : (byte)0;
        var prepared = await VerifyReturnedAsync(preparedResult!, request, hmacProvider,
            createdAtUnixSeconds, phase == 2 ? (byte)2 : (byte)1, cancellationToken)
            .ConfigureAwait(false);
        if (phase == 2)
        {
            var restored = prepared.AsSpan(73, 812).ToArray();
            VerifySigned(branch, preparedDcm, restored);
            await VerifyOperationRereadAsync(operationProvider, operationRequest, operation,
                cancellationToken).ConfigureAwait(false);
            return new GenesisSignedCutoverManifestPlan(branch, null,
                CutoverCodec.DecodeManifest(restored), prepared);
        }

        var record = CanonicalGrammar.DecodeOwned(preparedDcm, RecordDefinitions.Dcm1);
        var signing = CanonicalGrammar.GetSigningBytes(record, "Deep/Cutover/V1/manifest");
        var reset = branch.NewIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl);
        var account = branch.NewIdentity.Account.Certificate.AccountEd25519PublicKey;
        var resetSignature = await SignAsync(operation.OperationId,
            GenesisOriginSignerRole.ResetControl, signing, reset.CurrentEd25519PublicKey,
            signer, cancellationToken).ConfigureAwait(false);
        var accountPop = await SignAsync(operation.OperationId,
            GenesisOriginSignerRole.AccountPossession, signing, account,
            signer, cancellationToken).ConfigureAwait(false);
        var fields = Enumerable.Range(1, 19)
            .Select(index => (ReadOnlyMemory<byte>)record.FieldSpan(index).ToArray()).ToArray();
        fields[17] = resetSignature; fields[18] = accountPop;
        var signedDcm = CanonicalGrammar.Encode(RecordDefinitions.Dcm1, fields);
        VerifySigned(branch, preparedDcm, signedDcm);
        var completeResult = await provider.CompleteSignedAsync(
            new GenesisDcmSignedRequest(prepared, signedDcm), cancellationToken).ConfigureAwait(false);
        var complete = await VerifyReturnedAsync(completeResult, request, hmacProvider,
            createdAtUnixSeconds, 2, cancellationToken).ConfigureAwait(false);
        if (!CanonicalGrammar.FixedEquals(complete.AsSpan(73, 812), signedDcm) ||
            BinaryPrimitives.ReadUInt64BigEndian(complete.AsSpan(949, 8)) != checked(
                BinaryPrimitives.ReadUInt64BigEndian(prepared.AsSpan(949, 8)) + 1))
            Invalid("Signed SameAccount GDI1 is not the exact prepared successor.");
        await VerifyOperationRereadAsync(operationProvider, operationRequest, operation,
            cancellationToken).ConfigureAwait(false);
        return new GenesisSignedCutoverManifestPlan(branch, null,
            CutoverCodec.DecodeManifest(signedDcm), complete);
    }

    private static byte[] CreatePreparedDcm(GenesisCutoverBranchContext branch,
        ReadOnlySpan<byte> operationId, ulong createdAt)
    {
        var current = branch.CurrentCutover!;
        var prior = CanonicalGrammar.DecodeOwned(current.TrustedDcm, RecordDefinitions.Dcm1);
        var identity = branch.NewIdentity; var dpa = identity.Account.Certificate;
        var drs = identity.Revocations.Snapshot;
        var reset = identity.Authority.GetKeyAuthority(KeyScope.ResetControl);
        var priorGeneration = Scalars.UInt64(prior.FieldSpan(3));
        if (priorGeneration == ulong.MaxValue) Invalid("The current DCM generation overflows.");
        var fields = RecordDefinitions.Dcm1.Fields.Select(static field =>
            (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        fields[0] = dpa.NetworkId; fields[1] = prior.FieldSpan(2).ToArray();
        fields[2] = U64(priorGeneration + 1); fields[3] = U64(dpa.AccountGeneration);
        fields[4] = Reference(ArtifactType.Dpa1, dpa.Record); fields[5] = U64(drs.Revision);
        fields[6] = U64(drs.EntryCount); fields[7] = drs.CurrentHead;
        fields[8] = Reference(ArtifactType.Drs1, drs.Record); fields[9] = U64(reset.Generation);
        fields[10] = SHA256.HashData(reset.CurrentEd25519PublicKey.Span);
        fields[11] = reset.Generation == 0 ? new byte[38] :
            CanonicalGrammar.EncodeReference(reset.TransitionReference);
        fields[12] = current.TrustedDcmRef.ToArray();
        fields[13] = U64(branch.Governance.ActivationAtUnixSeconds);
        fields[14] = branch.Governance.ComponentSchemaRows.ToArray(); fields[15] = U64(createdAt);
        fields[16] = operationId.ToArray();
        return CanonicalGrammar.Encode(RecordDefinitions.Dcm1, fields);
    }

    private static async ValueTask<GenesisSameAccountOperationReadResult> ReadOperationAsync(
        GenesisSameAccountOperationProvider provider, GenesisSameAccountOperationRequest request,
        CancellationToken cancellationToken)
    {
        var result = await provider.RestoreOrCreateAsync(request, cancellationToken).ConfigureAwait(false);
        if (result is null || !result.Healthy || result.SourceRevision == 0 ||
            result.OperationId.Length != 32 || CanonicalGrammar.IsZero(result.OperationId.Span))
            Invalid("The SameAccount operation source is absent, unhealthy, or malformed.");
        return result!;
    }

    private static async ValueTask VerifyOperationRereadAsync(
        GenesisSameAccountOperationProvider provider, GenesisSameAccountOperationRequest request,
        GenesisSameAccountOperationReadResult expected, CancellationToken cancellationToken)
    {
        var reread = await ReadOperationAsync(provider, request, cancellationToken).ConfigureAwait(false);
        if (reread.SourceRevision != expected.SourceRevision ||
            !CanonicalGrammar.FixedEquals(reread.OperationId.Span, expected.OperationId.Span))
            Invalid("The SameAccount operation moved during authoring.");
    }

    private static async ValueTask<byte[]> VerifyReturnedAsync(GenesisDcmAuthoringReadResult result,
        GenesisDcmPreparedRequest request, IProtectedHmacProvider hmacProvider, ulong now,
        byte expectedPhase, CancellationToken cancellationToken)
    {
        if (result is null || !result.Healthy) Invalid("The GDI1 provider is absent or unhealthy.");
        var value = result!.ExactRecord.ToArray();
        DeploymentGovernanceRecords.PreflightGdi(value, now);
        await GenesisProtectedRecords.VerifyAsync("Deep/ProtectedState/V1/GDI1", value,
            DeploymentGovernanceRecords.GdiKeyOffset, hmacProvider, cancellationToken).ConfigureAwait(false);
        if (value[8] != 2 || value[965] != expectedPhase ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(9, 32), request.BranchHash.Span) ||
            !CanonicalGrammar.IsZero(value.AsSpan(41, 32)) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(885, 32), request.GovernanceHash.Span) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(917, 32), request.OperationId.Span) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(967, 32), request.ProtectedKeyId.Span) ||
            (expectedPhase == 1 && !CanonicalGrammar.FixedEquals(
                value.AsSpan(73, 812), request.PreparedDcm.Span)))
            Invalid("SameAccount GDI1 differs from its sealed authoring request.");
        return value;
    }

    private static void VerifySigned(GenesisCutoverBranchContext branch,
        ReadOnlySpan<byte> preparedDcm, ReadOnlySpan<byte> signedDcm)
    {
        var prepared = CanonicalGrammar.DecodeOwned(preparedDcm, RecordDefinitions.Dcm1);
        var signed = CanonicalGrammar.DecodeOwned(signedDcm, RecordDefinitions.Dcm1);
        for (var field = 1; field <= 17; field++)
            if (!CanonicalGrammar.FixedEquals(prepared.FieldSpan(field), signed.FieldSpan(field)))
                Invalid("Signed SameAccount GDI1 changed its frozen DCM transcript.");
        var signing = CanonicalGrammar.GetSigningBytes(prepared, "Deep/Cutover/V1/manifest");
        VerifySignature(signed.FieldSpan(18), signing,
            branch.NewIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl)
                .CurrentEd25519PublicKey.Span);
        VerifySignature(signed.FieldSpan(19), signing,
            branch.NewIdentity.Account.Certificate.AccountEd25519PublicKey.Span);
    }

    private static async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> operationId,
        GenesisOriginSignerRole role, ReadOnlyMemory<byte> signing, ReadOnlyMemory<byte> publicKey,
        GenesisOriginSigner signer, CancellationToken cancellationToken)
    {
        var signature = new byte[64];
        try
        {
            var written = await signer.SignAsync(new GenesisOriginSigningRequest(operationId.Span,
                role, ArtifactType.Dcm1, signing.Span, publicKey.Span), signature, cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (written != 64) Invalid("The SameAccount DCM signer returned a wrong-length signature.");
            VerifySignature(signature, signing.Span, publicKey.Span); return signature.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(signature); }
    }

    private static void VerifySignature(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> signing,
        ReadOnlySpan<byte> publicKey)
    {
        if (!PublicKeyAuth.VerifyDetached(signature.ToArray(), signing.ToArray(), publicKey.ToArray()))
            throw new RecordException(RecordError.InvalidSignature,
                "The SameAccount DCM signature is invalid.");
    }
    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private static byte[] U64(ulong value)
    { var output = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(output, value); return output; }
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<GenesisSignedCutoverManifestPlan> AuthorSameAccountCutoverManifestAsync(
        GenesisCutoverBranchContext branch, GenesisSameAccountOperationProvider operationProvider,
        GenesisDcmAuthoringProvider provider, GenesisOriginSigner signer,
        IProtectedHmacProvider hmacProvider, ulong createdAtUnixSeconds,
        CancellationToken cancellationToken = default) =>
        await GenesisSameAccountAuthor.AuthorAsync(branch, operationProvider, provider, signer,
            hmacProvider, createdAtUnixSeconds, cancellationToken).ConfigureAwait(false);
}
