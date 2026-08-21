using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// A signed DCM1 verified relative to one sealed cutover branch. This fact carries no
/// persistence, signing, distribution, or commit authority.
/// </summary>
public sealed class VerifiedCutoverManifestRelative
{
    internal VerifiedCutoverManifestRelative(
        GenesisCutoverBranchContext branch,
        CutoverManifest manifest)
    {
        Branch = branch;
        Manifest = manifest;
    }

    internal GenesisCutoverBranchContext Branch { get; }
    public CutoverManifest Manifest { get; }
    public bool NoAuthorityClaim => true;
}

internal static class CutoverManifestRelativeVerifier
{
    internal static VerifiedCutoverManifestRelative VerifyReserved(
        GenesisCutoverBranchContext branch,
        GenesisResetReservationResult reservation,
        ReadOnlySpan<byte> exactSignedDcm812)
    {
        ArgumentNullException.ThrowIfNull(branch);
        ArgumentNullException.ThrowIfNull(reservation);
        if (branch.BranchKind is not (1 or 3) ||
            !CanonicalGrammar.FixedEquals(
                reservation.ReservationBytes.AsSpan(8, 235),
                branch.ReservationRequest.Intent.Span))
            Invalid("The reserved DCM branch and reservation differ.");

        return Verify(branch, reservation, exactSignedDcm812);
    }

    internal static VerifiedCutoverManifestRelative VerifySameAccount(
        GenesisCutoverBranchContext branch,
        ReadOnlySpan<byte> exactSignedDcm812)
    {
        ArgumentNullException.ThrowIfNull(branch);
        if (branch.BranchKind != 2 || branch.CurrentCutover is null)
            Invalid("The DCM is not a SameAccount branch.");

        return Verify(branch, null, exactSignedDcm812);
    }

    private static VerifiedCutoverManifestRelative Verify(
        GenesisCutoverBranchContext branch,
        GenesisResetReservationResult? reservation,
        ReadOnlySpan<byte> exactSignedDcm812)
    {
        var signed = CanonicalGrammar.DecodeOwned(exactSignedDcm812, RecordDefinitions.Dcm1);
        var identity = branch.NewIdentity;
        var account = identity.Account;
        var dpa = account.Certificate;
        var drs = identity.Revocations.Snapshot;
        var reset = identity.Authority.GetKeyAuthority(KeyScope.ResetControl);

        Equal(signed.FieldSpan(1), branch.Governance.Network, "network");
        Equal(signed.FieldSpan(4), U64(dpa.AccountGeneration), "account generation");
        Equal(signed.FieldSpan(5), Reference(ArtifactType.Dpa1, dpa.Record), "DPA reference");
        Equal(signed.FieldSpan(6), U64(drs.Revision), "DRS revision");
        Equal(signed.FieldSpan(7), U64(drs.EntryCount), "DRS count");
        Equal(signed.FieldSpan(8), drs.CurrentHead.Span, "DRS head");
        Equal(signed.FieldSpan(9), Reference(ArtifactType.Drs1, drs.Record), "DRS reference");
        Equal(signed.FieldSpan(10), U64(reset.Generation), "ResetControl generation");
        Equal(signed.FieldSpan(11), SHA256.HashData(reset.CurrentEd25519PublicKey.Span),
            "ResetControl key hash");
        Equal(signed.FieldSpan(12), reset.Generation == 0
            ? new byte[38]
            : CanonicalGrammar.EncodeReference(reset.TransitionReference),
            "ResetControl transition reference");
        Equal(signed.FieldSpan(14), U64(branch.Governance.ActivationAtUnixSeconds),
            "activation time");
        Equal(signed.FieldSpan(15), branch.Governance.ComponentSchemaRows,
            "component schema rows");
        PositiveU64(signed.FieldSpan(16), "creation time");
        Positive(signed.FieldSpan(17), "operation ID");

        switch (branch.BranchKind)
        {
            case 1:
                Equal(signed.FieldSpan(2), reservation!.ResetId, "reserved reset ID");
                Equal(signed.FieldSpan(3), U64(1), "reset generation");
                Zero(signed.FieldSpan(13), "predecessor DCM reference");
                Equal(signed.FieldSpan(17), reservation.OperationId, "reservation operation ID");
                break;
            case 2:
                VerifySameAccountAxes(branch, signed);
                break;
            case 3:
                Equal(signed.FieldSpan(2), reservation!.ResetId, "reserved reset ID");
                Equal(signed.FieldSpan(3), U64(1), "reset generation");
                Zero(signed.FieldSpan(13), "predecessor DCM reference");
                Equal(signed.FieldSpan(17), branch.OperationId, "reset-origin operation ID");
                if (CanonicalGrammar.FixedEquals(signed.FieldSpan(2),
                    branch.AccountResetOrigin!.OldCutover.Manifest.ResetId.Span))
                    Invalid("The account-reset DCM reused the old reset ID.");
                break;
            default:
                Invalid("The DCM branch kind is invalid.");
                break;
        }

        var signing = CanonicalGrammar.GetSigningBytes(
            signed, "Deep/Cutover/V1/manifest");
        VerifySignature(signed.FieldSpan(18), signing,
            reset.CurrentEd25519PublicKey.Span);
        VerifySignature(signed.FieldSpan(19), signing,
            dpa.AccountEd25519PublicKey.Span);
        return new VerifiedCutoverManifestRelative(branch, new CutoverManifest(signed));
    }

    private static void VerifySameAccountAxes(
        GenesisCutoverBranchContext branch,
        OwnedRecord signed)
    {
        var current = branch.CurrentCutover!;
        var prior = CanonicalGrammar.DecodeOwned(current.TrustedDcm, RecordDefinitions.Dcm1);
        var priorGeneration = Scalars.UInt64(prior.FieldSpan(3));
        if (priorGeneration == ulong.MaxValue)
            Invalid("The predecessor DCM generation overflows.");
        Equal(signed.FieldSpan(2), prior.FieldSpan(2), "preserved reset ID");
        Equal(signed.FieldSpan(3), U64(priorGeneration + 1), "successor reset generation");
        Equal(signed.FieldSpan(13), current.TrustedDcmRef, "predecessor DCM reference");
    }

    private static void VerifySignature(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> signing,
        ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != 64 || CanonicalGrammar.IsZero(signature) ||
            !PublicKeyAuth.VerifyDetached(
                signature.ToArray(), signing.ToArray(), publicKey.ToArray()))
            throw new RecordException(RecordError.InvalidSignature,
                "The relative DCM signature is invalid.");
    }

    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string name)
    {
        if (!CanonicalGrammar.FixedEquals(actual, expected))
            Invalid($"The DCM {name} differs from its sealed branch.");
    }

    private static void Positive(ReadOnlySpan<byte> value, string name)
    {
        if (CanonicalGrammar.IsZero(value)) Invalid($"The DCM {name} is zero.");
    }

    private static void PositiveU64(ReadOnlySpan<byte> value, string name)
    {
        if (BinaryPrimitives.ReadUInt64BigEndian(value) == 0)
            Invalid($"The DCM {name} is zero.");
    }

    private static void Zero(ReadOnlySpan<byte> value, string name)
    {
        if (!CanonicalGrammar.IsZero(value)) Invalid($"The DCM {name} is not zero.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static VerifiedCutoverManifestRelative VerifyCutoverManifestRelative(
        GenesisCutoverBranchContext branch,
        GenesisResetReservationResult reservation,
        ReadOnlySpan<byte> exactSignedDcm812) =>
        CutoverManifestRelativeVerifier.VerifyReserved(branch, reservation, exactSignedDcm812);

    public static VerifiedCutoverManifestRelative VerifyCutoverManifestRelative(
        GenesisCutoverBranchContext sameAccountBranch,
        ReadOnlySpan<byte> exactSignedDcm812) =>
        CutoverManifestRelativeVerifier.VerifySameAccount(sameAccountBranch, exactSignedDcm812);
}
