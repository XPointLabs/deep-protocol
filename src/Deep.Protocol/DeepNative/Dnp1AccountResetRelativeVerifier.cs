using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// A signed DRA1 verified relative to one retained account-reset origin and its verified
/// successor DCM. It carries no signing, mutation, distribution, or commit authority.
/// </summary>
public sealed class VerifiedAccountResetAuthorizationRelative
{
    internal VerifiedAccountResetAuthorizationRelative(
        VerifiedCutoverManifestRelative cutover,
        AccountResetAuthorization authorization)
    {
        Cutover = cutover;
        Authorization = authorization;
    }

    public VerifiedCutoverManifestRelative Cutover { get; }
    public AccountResetAuthorization Authorization { get; }
    public bool NoAuthorityClaim => true;
}

internal static class AccountResetRelativeVerifier
{
    internal static VerifiedAccountResetAuthorizationRelative Verify(
        AccountResetOriginContext origin,
        VerifiedCutoverManifestRelative newCutover,
        ReadOnlySpan<byte> exactSignedDra788)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(newCutover);
        if (newCutover.Branch.BranchKind != 3 ||
            !ReferenceEquals(newCutover.Branch.AccountResetOrigin, origin))
            Invalid("The DRA origin and verified successor DCM differ.");

        var signed = CanonicalGrammar.DecodeOwned(exactSignedDra788, RecordDefinitions.Dra1);
        var old = origin.OldCutover;
        var oldIdentity = old.Identity;
        var oldDcm = old.Manifest.Record;
        var oldDrs = oldIdentity.Revocations.Snapshot;
        var newIdentity = origin.NewIdentity;
        var newDpa = newIdentity.Account.Certificate;
        var newDcm = newCutover.Manifest.Record;
        var transcript = origin.ExactTranscript.Span;

        Equal(signed.FieldSpan(1), transcript.Slice(0, 16), "network");
        Equal(signed.FieldSpan(2), transcript.Slice(16, 8), "old account generation");
        Equal(signed.FieldSpan(3), Reference(ArtifactType.Dpa1,
            oldIdentity.Account.Certificate.Record), "old DPA reference");
        Equal(signed.FieldSpan(4), U64(Scalars.UInt64(oldDcm.FieldSpan(3))),
            "old reset generation");
        Equal(signed.FieldSpan(5), Reference(ArtifactType.Dcm1, oldDcm),
            "old DCM reference");
        Equal(signed.FieldSpan(6), U64(oldDrs.EntryCount), "old DRS count");
        Equal(signed.FieldSpan(7), oldDrs.CurrentHead.Span, "old DRS head");
        Equal(signed.FieldSpan(8), Reference(ArtifactType.Drs1, oldDrs.Record),
            "old DRS reference");
        Equal(signed.FieldSpan(9), U64(newDpa.AccountGeneration),
            "new account generation");
        Equal(signed.FieldSpan(10), Reference(ArtifactType.Dpa1, newDpa.Record),
            "new DPA reference");
        Equal(signed.FieldSpan(11), newDcm.FieldSpan(3), "new reset generation");
        Equal(signed.FieldSpan(12), Reference(ArtifactType.Dcm1, newDcm),
            "new DCM reference");
        Equal(signed.FieldSpan(13), transcript.Slice(578, 8), "cutoff time");
        Equal(signed.FieldSpan(14), origin.OperationId.Span, "operation ID");
        Equal(signed.FieldSpan(15), transcript.Slice(586, 2), "reset reason");
        Equal(signed.FieldSpan(16), transcript.Slice(272, 32), "old reset key hash");
        Equal(signed.FieldSpan(17), SHA256.HashData(newDpa.AccountEd25519PublicKey.Span),
            "new account key hash");
        Equal(signed.FieldSpan(18), transcript.Slice(514, 32), "new reset key hash");

        var signing = CanonicalGrammar.GetSigningBytes(
            signed, "Deep/Cutover/V1/account-reset");
        VerifySignature(signed.FieldSpan(19), signing, old.CurrentResetPublicKey.Span);
        VerifySignature(signed.FieldSpan(20), signing,
            newDpa.AccountEd25519PublicKey.Span);
        VerifySignature(signed.FieldSpan(21), signing,
            newIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl)
                .CurrentEd25519PublicKey.Span);

        return new VerifiedAccountResetAuthorizationRelative(
            newCutover, new AccountResetAuthorization(signed));
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
                "The relative DRA signature is invalid.");
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
            Invalid($"The DRA {name} differs from its sealed origin.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static VerifiedAccountResetAuthorizationRelative VerifyAccountResetRelative(
        AccountResetOriginContext origin,
        VerifiedCutoverManifestRelative newCutover,
        ReadOnlySpan<byte> exactSignedDra788) =>
        AccountResetRelativeVerifier.Verify(origin, newCutover, exactSignedDra788);
}
