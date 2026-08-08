using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepExtension.MailboxAuthority;

/// <summary>Production verify-only Ed25519 adapter. It exposes no signing or key-custody API.</summary>
public sealed class SodiumProductionMailboxRevocationSnapshotSignatureVerifier
    : IProductionMailboxRevocationSnapshotSignatureVerifier
{
    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != ProductionMailboxAuthorityConstants.Ed25519PublicKeyLength ||
            signature.Length != ProductionMailboxAuthorityConstants.Ed25519SignatureLength)
            return false;
        try
        {
            return PublicKeyAuth.VerifyDetached(signature.ToArray(), signingBytes.ToArray(), publicKey.ToArray());
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}

public static class ProductionMailboxRevocationSnapshotVerifier
{
    public static VerifiedProductionMailboxRevocationSnapshot Verify(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority verifiedAuthority,
        ulong nowUnixSeconds,
        uint clockSkewSeconds,
        IProductionMailboxRevocationSnapshotSignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(verifiedAuthority);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (nowUnixSeconds == 0 || clockSkewSeconds > ProductionMailboxAuthorityConstants.MaximumClockSkewSeconds)
            throw Error(ProductionMailboxRevocationSnapshotError.InvalidField, "PMR1 verification time is invalid.");
        if (encoded.Length is < ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials
            or > ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes)
            throw Error(ProductionMailboxRevocationSnapshotError.InvalidLength,
                "PMR1 length is outside its strict bounds.");
        const int revokedSerialCountOffset = 152;
        var revokedSerialCount = BinaryPrimitives.ReadUInt16LittleEndian(
            encoded.Slice(revokedSerialCountOffset, 2));
        var expectedLength = ProductionMailboxRevocationSnapshotConstants
            .FixedArtifactBytesWithoutSerials +
            (revokedSerialCount * ProductionMailboxRevocationSnapshotConstants.RevokedGrantSerialBytes);
        if (revokedSerialCount > ProductionMailboxRevocationSnapshotConstants.MaximumRevokedGrantSerials
            || encoded.Length != expectedLength)
            throw Error(ProductionMailboxRevocationSnapshotError.InvalidLength,
                "PMR1 length does not match its bounded serial count.");

        // Freeze caller-owned bytes once so decode, hash and signature cannot observe different data.
        var canonicalBytes = encoded.ToArray();
        var snapshot = ProductionMailboxRevocationSnapshotCodec.Decode(canonicalBytes);
        var authority = verifiedAuthority.TrustedAuthority;
        VerifyWindow(authority.CurrentEpoch.NotBeforeUnixSeconds, authority.CurrentEpoch.NotAfterUnixSeconds,
            nowUnixSeconds, clockSkewSeconds, "verified PMA1 current epoch");
        VerifyWindow(authority.MrXApproval.RolloutNotBeforeUnixSeconds, authority.MrXApproval.RolloutNotAfterUnixSeconds,
            nowUnixSeconds, clockSkewSeconds, "verified PMA1 rollout");
        RequireEqual(snapshot.NetworkId.Span, authority.NetworkId.Span, "network ID");
        if (snapshot.AuthorityGeneration != authority.AuthorityGeneration)
            throw Error(ProductionMailboxRevocationSnapshotError.AuthorityFieldMismatch, "PMR1 authority generation does not match PMA1.");
        RequireEqual(snapshot.AuthorityBindingHash.Span,
            ProductionMailboxRevocationSnapshotCodec.ComputeAuthorityBindingHash(authority), "authority binding hash",
            ProductionMailboxRevocationSnapshotError.AuthorityBindingMismatch);
        if (snapshot.RevocationGeneration != authority.Revocation.Generation ||
            snapshot.IssuedAtUnixSeconds != authority.Revocation.IssuedAtUnixSeconds ||
            snapshot.ExpiresAtUnixSeconds != authority.Revocation.ExpiresAtUnixSeconds)
            throw Error(ProductionMailboxRevocationSnapshotError.AuthorityFieldMismatch, "PMR1 revocation generation or time does not match PMA1.");
        RequireEqual(snapshot.RevocationHeadHash.Span, authority.Revocation.HeadHash.Span, "revocation head");
        RequireEqual(snapshot.PreviousRevocationHeadHash.Span, authority.Revocation.PreviousHeadHash.Span, "previous revocation head");

        var canonicalHash = SHA256.HashData(canonicalBytes);
        RequireEqual(canonicalHash, authority.Revocation.SnapshotHash.Span, "snapshot hash",
            ProductionMailboxRevocationSnapshotError.SnapshotHashMismatch);
        if (nowUnixSeconds < snapshot.IssuedAtUnixSeconds && snapshot.IssuedAtUnixSeconds - nowUnixSeconds > clockSkewSeconds)
            throw Error(ProductionMailboxRevocationSnapshotError.NotYetValid, "PMR1 is not yet valid.");
        if (nowUnixSeconds > snapshot.ExpiresAtUnixSeconds && nowUnixSeconds - snapshot.ExpiresAtUnixSeconds > clockSkewSeconds)
            throw Error(ProductionMailboxRevocationSnapshotError.Expired, "PMR1 has expired.");
        if (!signatureVerifier.Verify(
                authority.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(snapshot),
                snapshot.IssuerSignature.Span))
            throw Error(ProductionMailboxRevocationSnapshotError.InvalidSignature, "PMR1 issuer signature is invalid.");

        return new VerifiedProductionMailboxRevocationSnapshot(
            snapshot, canonicalHash, authority.MailboxIssuerEd25519PublicKey.Span);
    }

    private static void VerifyWindow(ulong from, ulong until, ulong now, uint skew, string name)
    {
        if (now < from && from - now > skew)
            throw Error(ProductionMailboxRevocationSnapshotError.NotYetValid, $"{name} is not yet valid.");
        if (now > until && now - until > skew)
            throw Error(ProductionMailboxRevocationSnapshotError.Expired, $"{name} has expired.");
    }

    private static void RequireEqual(
        ReadOnlySpan<byte> actual,
        ReadOnlySpan<byte> expected,
        string name,
        ProductionMailboxRevocationSnapshotError error = ProductionMailboxRevocationSnapshotError.AuthorityFieldMismatch)
    {
        if (actual.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw Error(error, $"PMR1 {name} does not match verified PMA1.");
    }

    private static ProductionMailboxRevocationSnapshotException Error(
        ProductionMailboxRevocationSnapshotError error,
        string message) => new(error, message);
}
