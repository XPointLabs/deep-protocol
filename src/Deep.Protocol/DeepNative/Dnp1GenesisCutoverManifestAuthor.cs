using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepNative;

public enum GenesisOriginSignerRole : byte
{
    ResetControl = 1,
    AccountPossession = 2,
    OldResetControl = 3
}

public sealed class GenesisOriginSigningRequest
{
    private readonly byte[] _operationId;
    private readonly byte[] _signingBytes;
    private readonly byte[] _signingHash;
    private readonly byte[] _expectedPublicKey;

    internal GenesisOriginSigningRequest(ReadOnlySpan<byte> operationId,
        GenesisOriginSignerRole role, ArtifactType artifactType,
        ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> expectedPublicKey)
    {
        _operationId = operationId.ToArray();
        Role = role;
        ArtifactType = artifactType;
        _signingBytes = signingBytes.ToArray();
        _signingHash = SHA256.HashData(signingBytes);
        _expectedPublicKey = expectedPublicKey.ToArray();
    }

    public ReadOnlyMemory<byte> OperationId => _operationId.ToArray();
    public GenesisOriginSignerRole Role { get; }
    public ArtifactType ArtifactType { get; }
    public ReadOnlyMemory<byte> SigningBytes => _signingBytes.ToArray();
    public ReadOnlyMemory<byte> SigningHash => _signingHash.ToArray();
    public ReadOnlyMemory<byte> ExpectedEd25519PublicKey => _expectedPublicKey.ToArray();
    public bool NoAuthorityClaim => true;
}

public abstract class GenesisOriginSigner
{
    public abstract ValueTask<int> SignAsync(GenesisOriginSigningRequest request,
        Memory<byte> signature64, CancellationToken cancellationToken);
}

public sealed class GenesisDcmPreparedRequest
{
    private readonly byte[] _dcm;
    private readonly byte[] _branchHash;
    private readonly byte[] _reservationHash;
    private readonly byte[] _governanceHash;
    private readonly byte[] _operationId;
    private readonly byte[] _protectedKeyId;

    internal GenesisDcmPreparedRequest(GenesisCutoverBranchContext branch,
        ReadOnlySpan<byte> reservationHash, ReadOnlySpan<byte> dcm,
        ReadOnlySpan<byte> protectedKeyId, ReadOnlySpan<byte> operationId)
    {
        BranchKind = branch.BranchKind;
        _dcm = dcm.ToArray();
        _branchHash = branch.BranchHash.ToArray();
        _reservationHash = reservationHash.ToArray();
        _governanceHash = branch.Governance.DeploymentGovernanceBootstrapHash.ToArray();
        _operationId = operationId.ToArray();
        _protectedKeyId = protectedKeyId.ToArray();
    }

    public byte BranchKind { get; }
    public ReadOnlyMemory<byte> PreparedDcm => _dcm.ToArray();
    public ReadOnlyMemory<byte> BranchHash => _branchHash.ToArray();
    public ReadOnlyMemory<byte> ReservationHash => _reservationHash.ToArray();
    public ReadOnlyMemory<byte> GovernanceHash => _governanceHash.ToArray();
    public ReadOnlyMemory<byte> OperationId => _operationId.ToArray();
    public ReadOnlyMemory<byte> ProtectedKeyId => _protectedKeyId.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisDcmSignedRequest
{
    private readonly byte[] _prepared;
    private readonly byte[] _signedDcm;
    internal GenesisDcmSignedRequest(ReadOnlySpan<byte> prepared, ReadOnlySpan<byte> signedDcm)
    { _prepared = prepared.ToArray(); _signedDcm = signedDcm.ToArray(); }
    public ReadOnlyMemory<byte> PreparedRecord => _prepared.ToArray();
    public ReadOnlyMemory<byte> SignedDcm => _signedDcm.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisDcmAuthoringReadResult
{
    private readonly byte[] _record;
    public GenesisDcmAuthoringReadResult(ReadOnlySpan<byte> exactGdi1031, bool healthy)
    { _record = exactGdi1031.ToArray(); Healthy = healthy; }
    public ReadOnlyMemory<byte> ExactRecord => _record.ToArray();
    public bool Healthy { get; }
    public bool NoAuthorityClaim => true;
}

public abstract class GenesisDcmAuthoringProvider
{
    public abstract ValueTask<GenesisDcmAuthoringReadResult> RestoreOrCreatePreparedAsync(
        GenesisDcmPreparedRequest request, CancellationToken cancellationToken);
    public abstract ValueTask<GenesisDcmAuthoringReadResult> CompleteSignedAsync(
        GenesisDcmSignedRequest request, CancellationToken cancellationToken);
}

public sealed class GenesisSignedCutoverManifestPlan
{
    private readonly byte[] _gdi;
    internal GenesisSignedCutoverManifestPlan(GenesisCutoverBranchContext branch,
        GenesisResetReservationResult? reservation, CutoverManifest manifest, ReadOnlySpan<byte> gdi)
    { Branch = branch; Reservation = reservation; Manifest = manifest; _gdi = gdi.ToArray(); }
    internal GenesisCutoverBranchContext Branch { get; }
    internal GenesisResetReservationResult? Reservation { get; }
    internal ReadOnlySpan<byte> ExactGdi => _gdi;
    public CutoverManifest Manifest { get; }
    public ReadOnlyMemory<byte> SignedAuthoringReceipt => _gdi.ToArray();
    public bool NoAuthorityClaim => true;
}

internal static class GenesisCutoverManifestAuthor
{
    internal static async ValueTask<GenesisSignedCutoverManifestPlan> AuthorAsync(
        GenesisCutoverBranchContext branch, GenesisResetReservationResult reservation,
        GenesisResetReservationProvider reservationProvider,
        GenesisDcmAuthoringProvider provider, GenesisOriginSigner signer,
        IProtectedHmacProvider hmacProvider, ulong createdAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(branch); ArgumentNullException.ThrowIfNull(reservation);
        ArgumentNullException.ThrowIfNull(reservationProvider);
        ArgumentNullException.ThrowIfNull(provider); ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(hmacProvider); cancellationToken.ThrowIfCancellationRequested();
        if (createdAtUnixSeconds == 0 ||
            !CanonicalGrammar.FixedEquals(reservation.ReservationBytes.AsSpan(8, 235),
                branch.ReservationRequest.Intent.Span))
            Invalid("The DCM authoring branch, reservation, or creation time is invalid.");
        await VerifyReservationRereadAsync(branch, reservation, reservationProvider,
            hmacProvider, cancellationToken).ConfigureAwait(false);

        var operationId = AuthorOperationId(branch, reservation);
        var preparedDcm = CreatePreparedDcm(branch, reservation, createdAtUnixSeconds, operationId);
        var keyId = branch.Governance.ExactDgi.Slice(96, 32).ToArray();
        var request = new GenesisDcmPreparedRequest(branch, reservation.ReservationHash.Span,
            preparedDcm, keyId, operationId);
        var preparedResult = await provider.RestoreOrCreatePreparedAsync(request, cancellationToken)
            .ConfigureAwait(false);
        var preparedRead = preparedResult ?? throw new RecordException(RecordError.InvalidField,
            "The GDI1 provider returned no record.");
        var returnedPhase = preparedRead.ExactRecord.Length == DeploymentGovernanceRecords.GdiLength
            ? preparedRead.ExactRecord.Span[965] : (byte)0;
        var prepared = await VerifyReturnedAsync(preparedRead, request, hmacProvider,
            createdAtUnixSeconds, expectedPhase: returnedPhase == 2 ? (byte)2 : (byte)1,
            cancellationToken).ConfigureAwait(false);

        if (returnedPhase == 2)
        {
            var restoredDcm = prepared.AsSpan(73, 812).ToArray();
            VerifySignedDcm(branch, preparedDcm, restoredDcm);
            await VerifyReservationRereadAsync(branch, reservation, reservationProvider,
                hmacProvider, cancellationToken).ConfigureAwait(false);
            return new GenesisSignedCutoverManifestPlan(branch, reservation,
                CutoverCodec.DecodeManifest(restoredDcm), prepared);
        }

        var record = CanonicalGrammar.DecodeOwned(preparedDcm, RecordDefinitions.Dcm1);
        var signing = CanonicalGrammar.GetSigningBytes(record, "Deep/Cutover/V1/manifest");
        var reset = branch.NewIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl);
        var accountKey = branch.NewIdentity.Account.Certificate.AccountEd25519PublicKey;
        var resetSignature = await SignAsync(operationId,
            GenesisOriginSignerRole.ResetControl, signing,
            reset.CurrentEd25519PublicKey, signer, cancellationToken).ConfigureAwait(false);
        var accountSignature = await SignAsync(operationId,
            GenesisOriginSignerRole.AccountPossession, signing,
            accountKey, signer, cancellationToken).ConfigureAwait(false);
        var signedFields = Enumerable.Range(1, 19)
            .Select(index => (ReadOnlyMemory<byte>)record.FieldSpan(index).ToArray()).ToArray();
        signedFields[17] = resetSignature;
        signedFields[18] = accountSignature;
        var signedDcm = CanonicalGrammar.Encode(RecordDefinitions.Dcm1, signedFields);
        var decodedSigned = CanonicalGrammar.DecodeOwned(signedDcm, RecordDefinitions.Dcm1);
        VerifySignature(decodedSigned.FieldSpan(18), signing, reset.CurrentEd25519PublicKey.Span);
        VerifySignature(decodedSigned.FieldSpan(19), signing, accountKey.Span);

        var signedResult = await provider.CompleteSignedAsync(
            new GenesisDcmSignedRequest(prepared, signedDcm), cancellationToken).ConfigureAwait(false);
        var complete = await VerifyReturnedAsync(signedResult, request, hmacProvider,
            createdAtUnixSeconds, expectedPhase: 2, cancellationToken).ConfigureAwait(false);
        if (!CanonicalGrammar.FixedEquals(complete.AsSpan(73, 812), signedDcm) ||
            BinaryPrimitives.ReadUInt64BigEndian(complete.AsSpan(949, 8)) != checked(
                BinaryPrimitives.ReadUInt64BigEndian(prepared.AsSpan(949, 8)) + 1) ||
            !CanonicalGrammar.FixedEquals(complete.AsSpan(957, 8), prepared.AsSpan(957, 8)) ||
            complete[966] != prepared[966] ||
            !CanonicalGrammar.FixedEquals(complete.AsSpan(967, 32), prepared.AsSpan(967, 32)))
            Invalid("Signed GDI1 is not the exact Prepared-to-Signed successor.");
        await VerifyReservationRereadAsync(branch, reservation, reservationProvider,
            hmacProvider, cancellationToken).ConfigureAwait(false);
        return new GenesisSignedCutoverManifestPlan(branch, reservation,
            CutoverCodec.DecodeManifest(signedDcm), complete);
    }

    private static void VerifySignedDcm(GenesisCutoverBranchContext branch,
        ReadOnlySpan<byte> preparedDcm, ReadOnlySpan<byte> signedDcm)
    {
        var prepared = CanonicalGrammar.DecodeOwned(preparedDcm, RecordDefinitions.Dcm1);
        var signed = CanonicalGrammar.DecodeOwned(signedDcm, RecordDefinitions.Dcm1);
        for (var field = 1; field <= 17; field++)
            if (!CanonicalGrammar.FixedEquals(prepared.FieldSpan(field), signed.FieldSpan(field)))
                Invalid("Restored Signed GDI1 changed the frozen DCM transcript.");
        var signing = CanonicalGrammar.GetSigningBytes(prepared, "Deep/Cutover/V1/manifest");
        VerifySignature(signed.FieldSpan(18), signing,
            branch.NewIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl)
                .CurrentEd25519PublicKey.Span);
        VerifySignature(signed.FieldSpan(19), signing,
            branch.NewIdentity.Account.Certificate.AccountEd25519PublicKey.Span);
    }

    private static byte[] CreatePreparedDcm(GenesisCutoverBranchContext branch,
        GenesisResetReservationResult reservation, ulong createdAt, ReadOnlySpan<byte> operationId)
    {
        var identity = branch.NewIdentity; var account = identity.Account;
        var dpa = account.Certificate; var drs = identity.Revocations.Snapshot;
        var reset = identity.Authority.GetKeyAuthority(KeyScope.ResetControl);
        var fields = RecordDefinitions.Dcm1.Fields.Select(static field =>
            (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        fields[0] = dpa.NetworkId; fields[1] = reservation.ResetId.ToArray(); fields[2] = U64(1);
        fields[3] = U64(dpa.AccountGeneration); fields[4] = Reference(ArtifactType.Dpa1, dpa.Record);
        fields[5] = U64(drs.Revision); fields[6] = U64(drs.EntryCount); fields[7] = drs.CurrentHead;
        fields[8] = Reference(ArtifactType.Drs1, drs.Record); fields[9] = U64(reset.Generation);
        fields[10] = SHA256.HashData(reset.CurrentEd25519PublicKey.Span);
        fields[11] = reset.Generation == 0 ? new byte[38] : CanonicalGrammar.EncodeReference(reset.TransitionReference);
        fields[12] = new byte[38]; fields[13] = U64(branch.Governance.ActivationAtUnixSeconds);
        fields[14] = branch.Governance.ComponentSchemaRows.ToArray(); fields[15] = U64(createdAt);
        fields[16] = operationId.ToArray();
        return CanonicalGrammar.Encode(RecordDefinitions.Dcm1, fields);
    }

    private static byte[] AuthorOperationId(GenesisCutoverBranchContext branch,
        GenesisResetReservationResult reservation)
    {
        if (branch.BranchKind == 1) return reservation.OperationId.ToArray();
        if (branch.BranchKind != 3 || branch.AccountResetOrigin is null ||
            branch.OperationId.Length != 32 || CanonicalGrammar.IsZero(branch.OperationId) ||
            CanonicalGrammar.FixedEquals(reservation.ResetId,
                branch.AccountResetOrigin.OldCutover.Manifest.ResetId.Span))
            Invalid("The account-reset branch operation or reserved reset ID is invalid.");
        return branch.OperationId.ToArray();
    }

    private static async ValueTask VerifyReservationRereadAsync(
        GenesisCutoverBranchContext branch, GenesisResetReservationResult expected,
        GenesisResetReservationProvider provider, IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        var reread = await GenesisReservationVerifier.RestoreResetAsync(provider,
            branch.ReservationRequest, hmacProvider, cancellationToken).ConfigureAwait(false);
        if (!CanonicalGrammar.FixedEquals(reread.ReservationBytes, expected.ReservationBytes) ||
            !CanonicalGrammar.FixedEquals(reread.ReservationHash.Span, expected.ReservationHash.Span))
            Invalid("The reset reservation moved during DCM authoring.");
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
        if (value[8] != request.BranchKind || value[965] != expectedPhase ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(9, 32), request.BranchHash.Span) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(41, 32), request.ReservationHash.Span) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(885, 32), request.GovernanceHash.Span) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(917, 32), request.OperationId.Span) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(967, 32), request.ProtectedKeyId.Span) ||
            (expectedPhase == 1 && !CanonicalGrammar.FixedEquals(
                value.AsSpan(73, 812), request.PreparedDcm.Span)))
            Invalid("GDI1 differs from its sealed authoring request.");
        return value;
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
            if (written != 64) Invalid("The DCM signer returned a wrong-length signature.");
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
            throw new RecordException(RecordError.InvalidSignature, "The DCM signature is invalid.");
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
    public static async ValueTask<GenesisSignedCutoverManifestPlan> AuthorCutoverManifestAsync(
        GenesisCutoverBranchContext branch, GenesisResetReservationResult reservation,
        GenesisResetReservationProvider reservationProvider,
        GenesisDcmAuthoringProvider provider, GenesisOriginSigner signer,
        IProtectedHmacProvider hmacProvider, ulong createdAtUnixSeconds,
        CancellationToken cancellationToken = default) =>
        await GenesisCutoverManifestAuthor.AuthorAsync(branch, reservation, reservationProvider,
            provider, signer,
            hmacProvider, createdAtUnixSeconds, cancellationToken).ConfigureAwait(false);
}
