using Sodium;

namespace Deep.Protocol.DeepNative;

internal static class IdentityVerifier
{
    private const string AccountDomain = "Deep/IdentityAuth/V1/account-certificate";
    private const string AccountIdDomain = "Deep/IdentityAuth/V1/account-id";

    internal static VerifiedAccount VerifyAccountCertificate(ReadOnlySpan<byte> canonical)
    {
        var certificate = IdentityCodec.DecodeAccountCertificate(canonical);
        var record = certificate.Record;
        Nonzero(record.FieldSpan(1), "network");
        var accountGeneration = Scalars.UInt64(record.FieldSpan(2));
        var certificateGeneration = Scalars.UInt64(record.FieldSpan(3));
        if (accountGeneration == 0 || certificateGeneration == 0 ||
            Scalars.UInt16(record.FieldSpan(12)) != ArtifactRegistry.IdentityAuthV1Ed25519)
            Invalid("The account generations or authentication suite are invalid.");
        var predecessor = CanonicalGrammar.DecodeReference(record.FieldSpan(4), allowZero: true);
        if (certificateGeneration == 1 != predecessor.IsZero)
            Invalid("Only a genesis account certificate has a zero predecessor.");
        var keys = new[] { record.FieldCopy(5), record.FieldCopy(6), record.FieldCopy(7), record.FieldCopy(8) };
        for (var index = 0; index < keys.Length; index++)
        {
            Nonzero(keys[index], "account role key");
            for (var other = 0; other < index; other++)
                if (CanonicalGrammar.FixedEquals(keys[index], keys[other]))
                    Invalid("Account role keys must be pairwise distinct.");
        }
        Nonzero(record.FieldSpan(9), "account revocation handle");
        if (Scalars.UInt64(record.FieldSpan(10)) == 0 ||
            Scalars.UInt64(record.FieldSpan(11)) == 0)
            Invalid("The DPA1 creation time or policy generation is zero.");
        var signing = CanonicalGrammar.GetSigningBytes(record, AccountDomain);
        Verify(record.FieldSpan(13), signing, record.FieldSpan(5));
        Verify(record.FieldSpan(14), signing, record.FieldSpan(6));
        Verify(record.FieldSpan(15), signing, record.FieldSpan(7));
        Verify(record.FieldSpan(16), signing, record.FieldSpan(8));

        Span<byte> payload = stackalloc byte[16 + 8 + 32];
        record.FieldSpan(1).CopyTo(payload);
        record.FieldSpan(2).CopyTo(payload[16..]);
        record.FieldSpan(5).CopyTo(payload[24..]);
        var accountHash = CanonicalGrammar.Sha256Domain(AccountIdDomain, payload);
        return new VerifiedAccount(certificate, accountHash);
    }

    private static void Verify(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != 64 || publicKey.Length != 32 ||
            !PublicKeyAuth.VerifyDetached(signature.ToArray(), message.ToArray(), publicKey.ToArray()))
            throw new RecordException(RecordError.InvalidSignature, "A DNP1 signature is invalid.");
    }

    private static void Nonzero(ReadOnlySpan<byte> value, string name)
    {
        if (CanonicalGrammar.IsZero(value)) Invalid($"The {name} is zero.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
