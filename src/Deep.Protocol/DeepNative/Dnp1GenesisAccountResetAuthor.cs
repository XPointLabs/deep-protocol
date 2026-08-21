using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisResetPreparedRequest
{
    private readonly byte[] _garReceiptHash;
    private readonly byte[] _newDcmRef;
    private readonly byte[] _dra;
    private readonly byte[] _operationId;
    private readonly byte[] _protectedKeyId;

    internal GenesisResetPreparedRequest(AccountResetOriginContext origin,
        ReadOnlySpan<byte> newDcmRef, ReadOnlySpan<byte> preparedDra,
        ReadOnlySpan<byte> protectedKeyId)
    {
        _garReceiptHash = origin.GarReceiptHash.ToArray();
        _newDcmRef = newDcmRef.ToArray();
        _dra = preparedDra.ToArray();
        _operationId = origin.OperationId.ToArray();
        _protectedKeyId = protectedKeyId.ToArray();
    }
    public ReadOnlyMemory<byte> GarReceiptHash => _garReceiptHash.ToArray();
    public ReadOnlyMemory<byte> NewDcmReference => _newDcmRef.ToArray();
    public ReadOnlyMemory<byte> PreparedDra => _dra.ToArray();
    public ReadOnlyMemory<byte> OperationId => _operationId.ToArray();
    public ReadOnlyMemory<byte> ProtectedKeyId => _protectedKeyId.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisResetSignedRequest
{
    private readonly byte[] _prepared;
    private readonly byte[] _signedDra;
    internal GenesisResetSignedRequest(ReadOnlySpan<byte> prepared, ReadOnlySpan<byte> signedDra)
    { _prepared = prepared.ToArray(); _signedDra = signedDra.ToArray(); }
    public ReadOnlyMemory<byte> PreparedRecord => _prepared.ToArray();
    public ReadOnlyMemory<byte> SignedDra => _signedDra.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisResetAuthoringReadResult
{
    private readonly byte[] _record;
    public GenesisResetAuthoringReadResult(ReadOnlySpan<byte> exactGra980, bool healthy)
    { _record = exactGra980.ToArray(); Healthy = healthy; }
    public ReadOnlyMemory<byte> ExactRecord => _record.ToArray();
    public bool Healthy { get; }
    public bool NoAuthorityClaim => true;
}

public abstract class GenesisResetAuthoringProvider
{
    public abstract ValueTask<GenesisResetAuthoringReadResult> RestoreOrCreatePreparedAsync(
        GenesisResetPreparedRequest request, CancellationToken cancellationToken);
    public abstract ValueTask<GenesisResetAuthoringReadResult> CompleteSignedAsync(
        GenesisResetSignedRequest request, CancellationToken cancellationToken);
}

public sealed class GenesisSignedAccountResetPlan
{
    private readonly byte[] _gra;
    internal GenesisSignedAccountResetPlan(GenesisSignedCutoverManifestPlan signedDcm,
        AccountResetAuthorization authorization, ReadOnlySpan<byte> gra)
    { SignedDcm = signedDcm; Authorization = authorization; _gra = gra.ToArray(); }
    public GenesisSignedCutoverManifestPlan SignedDcm { get; }
    public AccountResetAuthorization Authorization { get; }
    public ReadOnlyMemory<byte> SignedResetAuthoringReceipt => _gra.ToArray();
    internal ReadOnlySpan<byte> ExactGra => _gra;
    public bool NoAuthorityClaim => true;
}

internal static class GenesisAccountResetAuthor
{
    internal static async ValueTask<GenesisSignedAccountResetPlan> AuthorAsync(
        GenesisSignedCutoverManifestPlan signedDcm,
        AccountResetOriginProvider originProvider,
        GenesisResetAuthoringProvider provider,
        GenesisOriginSigner signer,
        IProtectedHmacProvider hmacProvider,
        ulong transactionTimeUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signedDcm); ArgumentNullException.ThrowIfNull(originProvider);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(signer); ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        var branch = signedDcm.Branch;
        if (branch.BranchKind != 3)
            Invalid("DRA authoring requires one verified AccountReset branch.");
        var origin = branch.AccountResetOrigin ?? throw new RecordException(
            RecordError.InvalidField, "The AccountReset branch has no verified origin.");
        await VerifyOriginRereadAsync(origin, originProvider, hmacProvider,
            transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);
        var gdi = signedDcm.ExactGdi.ToArray();
        DeploymentGovernanceRecords.PreflightGdi(gdi, transactionTimeUnixSeconds);
        await GenesisProtectedRecords.VerifyAsync("Deep/ProtectedState/V1/GDI1", gdi,
            DeploymentGovernanceRecords.GdiKeyOffset, hmacProvider, cancellationToken).ConfigureAwait(false);
        if (gdi[965] != 2 || !CanonicalGrammar.FixedEquals(gdi.AsSpan(917, 32), origin.OperationId.Span))
            Invalid("Signed GDI1 does not share the account-reset origin operation.");

        var dcm = signedDcm.Manifest.Record;
        var dcmRef = Reference(ArtifactType.Dcm1, dcm);
        var preparedDra = CreatePreparedDra(origin, dcm, dcmRef);
        var request = new GenesisResetPreparedRequest(origin, dcmRef, preparedDra,
            gdi.AsSpan(967, 32));
        var preparedResult = await provider.RestoreOrCreatePreparedAsync(request, cancellationToken)
            .ConfigureAwait(false);
        var phase = preparedResult?.ExactRecord.Length == DeploymentGovernanceRecords.GraLength
            ? preparedResult.ExactRecord.Span[914] : (byte)0;
        var prepared = await VerifyReturnedAsync(preparedResult!, request, hmacProvider,
            transactionTimeUnixSeconds, phase == 2 ? (byte)2 : (byte)1, cancellationToken)
            .ConfigureAwait(false);
        if (phase == 2)
        {
            var restored = prepared.AsSpan(78, 788).ToArray();
            VerifySignedDra(origin, preparedDra, restored, dcmRef);
            await VerifyOriginRereadAsync(origin, originProvider, hmacProvider,
                transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);
            return new GenesisSignedAccountResetPlan(signedDcm,
                CutoverCodec.DecodeAccountReset(restored), prepared);
        }

        var record = CanonicalGrammar.DecodeOwned(preparedDra, RecordDefinitions.Dra1);
        var signing = CanonicalGrammar.GetSigningBytes(record, "Deep/Cutover/V1/account-reset");
        var oldReset = origin.OldCutover.CurrentResetPublicKey;
        var newAccount = origin.NewIdentity.Account.Certificate.AccountEd25519PublicKey;
        var newReset = origin.NewIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl)
            .CurrentEd25519PublicKey;
        var oldSignature = await SignAsync(origin.OperationId, GenesisOriginSignerRole.OldResetControl,
            signing, oldReset, signer, cancellationToken).ConfigureAwait(false);
        var accountPop = await SignAsync(origin.OperationId, GenesisOriginSignerRole.AccountPossession,
            signing, newAccount, signer, cancellationToken).ConfigureAwait(false);
        var resetPop = await SignAsync(origin.OperationId, GenesisOriginSignerRole.ResetControl,
            signing, newReset, signer, cancellationToken).ConfigureAwait(false);
        var fields = Enumerable.Range(1, 21)
            .Select(index => (ReadOnlyMemory<byte>)record.FieldSpan(index).ToArray()).ToArray();
        fields[18] = oldSignature; fields[19] = accountPop; fields[20] = resetPop;
        var signedDra = CanonicalGrammar.Encode(RecordDefinitions.Dra1, fields);
        VerifySignedDra(origin, preparedDra, signedDra, dcmRef);

        var completeResult = await provider.CompleteSignedAsync(
            new GenesisResetSignedRequest(prepared, signedDra), cancellationToken).ConfigureAwait(false);
        var complete = await VerifyReturnedAsync(completeResult, request, hmacProvider,
            transactionTimeUnixSeconds, 2, cancellationToken).ConfigureAwait(false);
        if (!CanonicalGrammar.FixedEquals(complete.AsSpan(78, 788), signedDra) ||
            BinaryPrimitives.ReadUInt64BigEndian(complete.AsSpan(898, 8)) != checked(
                BinaryPrimitives.ReadUInt64BigEndian(prepared.AsSpan(898, 8)) + 1) ||
            !CanonicalGrammar.FixedEquals(complete.AsSpan(906, 8), prepared.AsSpan(906, 8)) ||
            complete[915] != prepared[915] ||
            !CanonicalGrammar.FixedEquals(complete.AsSpan(916, 32), prepared.AsSpan(916, 32)))
            Invalid("Signed GRA1 is not the exact Prepared-to-Signed successor.");
        await VerifyOriginRereadAsync(origin, originProvider, hmacProvider,
            transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);
        return new GenesisSignedAccountResetPlan(signedDcm,
            CutoverCodec.DecodeAccountReset(signedDra), complete);
    }

    private static byte[] CreatePreparedDra(AccountResetOriginContext origin,
        OwnedRecord newDcm, ReadOnlySpan<byte> newDcmRef)
    {
        var old = origin.OldCutover; var oldIdentity = old.Identity;
        var oldDcm = old.Manifest.Record; var oldDrs = oldIdentity.Revocations.Snapshot;
        var newIdentity = origin.NewIdentity; var newDpa = newIdentity.Account.Certificate;
        var t = origin.ExactTranscript.Span;
        var fields = RecordDefinitions.Dra1.Fields.Select(static field =>
            (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        fields[0] = t.Slice(0, 16).ToArray(); fields[1] = t.Slice(16, 8).ToArray();
        fields[2] = Reference(ArtifactType.Dpa1, oldIdentity.Account.Certificate.Record);
        fields[3] = U64(Scalars.UInt64(oldDcm.FieldSpan(3)));
        fields[4] = Reference(ArtifactType.Dcm1, oldDcm); fields[5] = U64(oldDrs.EntryCount);
        fields[6] = oldDrs.CurrentHead; fields[7] = Reference(ArtifactType.Drs1, oldDrs.Record);
        fields[8] = U64(newDpa.AccountGeneration); fields[9] = Reference(ArtifactType.Dpa1, newDpa.Record);
        fields[10] = newDcm.FieldSpan(3).ToArray(); fields[11] = newDcmRef.ToArray();
        fields[12] = t.Slice(578, 8).ToArray(); fields[13] = origin.OperationId.ToArray();
        fields[14] = t.Slice(586, 2).ToArray(); fields[15] = t.Slice(272, 32).ToArray();
        fields[16] = SHA256.HashData(newDpa.AccountEd25519PublicKey.Span);
        fields[17] = t.Slice(514, 32).ToArray();
        return CanonicalGrammar.Encode(RecordDefinitions.Dra1, fields);
    }

    private static async ValueTask<byte[]> VerifyReturnedAsync(GenesisResetAuthoringReadResult result,
        GenesisResetPreparedRequest request, IProtectedHmacProvider hmacProvider, ulong now,
        byte expectedPhase, CancellationToken cancellationToken)
    {
        if (result is null || !result.Healthy) Invalid("The GRA1 provider is absent or unhealthy.");
        var value = result!.ExactRecord.ToArray();
        DeploymentGovernanceRecords.PreflightGra(value, now);
        await GenesisProtectedRecords.VerifyAsync("Deep/ProtectedState/V1/GRA1", value,
            DeploymentGovernanceRecords.GraKeyOffset, hmacProvider, cancellationToken).ConfigureAwait(false);
        if (value[914] != expectedPhase ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(8, 32), request.GarReceiptHash.Span) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(40, 38), request.NewDcmReference.Span) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(866, 32), request.OperationId.Span) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(916, 32), request.ProtectedKeyId.Span) ||
            (expectedPhase == 1 && !CanonicalGrammar.FixedEquals(
                value.AsSpan(78, 788), request.PreparedDra.Span)))
            Invalid("GRA1 differs from its sealed reset-authoring request.");
        return value;
    }

    private static async ValueTask VerifyOriginRereadAsync(AccountResetOriginContext origin,
        AccountResetOriginProvider provider, IProtectedHmacProvider hmacProvider, ulong now,
        CancellationToken cancellationToken)
    {
        var result = await provider.ReadAsync(origin.Request, cancellationToken)
            .ConfigureAwait(false);
        var read = result ?? throw new RecordException(RecordError.InvalidField,
            "The GAR1 provider returned no record.");
        if (!read.Healthy) Invalid("The GAR1 provider is unhealthy.");
        var gar = read.ExactGar.ToArray();
        DeploymentGovernanceRecords.PreflightGar(gar, now);
        await GenesisProtectedRecords.VerifyAsync("Deep/ProtectedState/V1/GAR1", gar,
            DeploymentGovernanceRecords.GarKeyOffset, hmacProvider, cancellationToken).ConfigureAwait(false);
        if (!CanonicalGrammar.FixedEquals(gar, origin.ExactGar.Span))
            Invalid("GAR1 or its retained account-reset evidence moved during DRA authoring.");
    }

    private static void VerifySignedDra(AccountResetOriginContext origin,
        ReadOnlySpan<byte> preparedDra, ReadOnlySpan<byte> signedDra,
        ReadOnlySpan<byte> expectedDcmRef)
    {
        var prepared = CanonicalGrammar.DecodeOwned(preparedDra, RecordDefinitions.Dra1);
        var signed = CanonicalGrammar.DecodeOwned(signedDra, RecordDefinitions.Dra1);
        for (var field = 1; field <= 18; field++)
            if (!CanonicalGrammar.FixedEquals(prepared.FieldSpan(field), signed.FieldSpan(field)))
                Invalid("Restored Signed GRA1 changed the frozen DRA transcript.");
        if (!CanonicalGrammar.FixedEquals(signed.FieldSpan(12), expectedDcmRef))
            Invalid("DRA1 does not bind the newly signed DCM1.");
        var signing = CanonicalGrammar.GetSigningBytes(prepared, "Deep/Cutover/V1/account-reset");
        VerifySignature(signed.FieldSpan(19), signing, origin.OldCutover.CurrentResetPublicKey.Span);
        VerifySignature(signed.FieldSpan(20), signing,
            origin.NewIdentity.Account.Certificate.AccountEd25519PublicKey.Span);
        VerifySignature(signed.FieldSpan(21), signing,
            origin.NewIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl)
                .CurrentEd25519PublicKey.Span);
    }

    private static async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> operationId,
        GenesisOriginSignerRole role, ReadOnlyMemory<byte> signing, ReadOnlyMemory<byte> publicKey,
        GenesisOriginSigner signer, CancellationToken cancellationToken)
    {
        var signature = new byte[64];
        try
        {
            var written = await signer.SignAsync(new GenesisOriginSigningRequest(operationId.Span,
                role, ArtifactType.Dra1, signing.Span, publicKey.Span), signature, cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (written != 64) Invalid("The DRA signer returned a wrong-length signature.");
            VerifySignature(signature, signing.Span, publicKey.Span);
            return signature.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(signature); }
    }

    private static void VerifySignature(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> signing,
        ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != 64 || signature.IndexOfAnyExcept((byte)0) < 0 ||
            !PublicKeyAuth.VerifyDetached(signature.ToArray(), signing.ToArray(), publicKey.ToArray()))
            throw new RecordException(RecordError.InvalidSignature, "The DRA signature is invalid.");
    }
    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private static byte[] U64(ulong value)
    { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<GenesisSignedAccountResetPlan> AuthorAccountResetAsync(
        GenesisSignedCutoverManifestPlan signedDcm, AccountResetOriginProvider originProvider,
        GenesisResetAuthoringProvider provider,
        GenesisOriginSigner signer, IProtectedHmacProvider hmacProvider,
        ulong transactionTimeUnixSeconds, CancellationToken cancellationToken = default) =>
        await GenesisAccountResetAuthor.AuthorAsync(signedDcm, originProvider, provider, signer,
            hmacProvider,
            transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);
}
