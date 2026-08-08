using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepExtension.MailboxAuthority;

/// <summary>Production verifier only. It has no signing or private-key API.</summary>
public sealed class SodiumProductionMailboxAuthoritySignatureVerifier : IProductionMailboxAuthoritySignatureVerifier
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

public static class ProductionMailboxAuthorityVerifier
{
    internal static VerifiedProductionMailboxAuthority VerifyForwardCheckpoint(
        ReadOnlySpan<byte> canonicalAuthority,
        ProductionMailboxAuthorityCheckpointVerificationContext context,
        IProductionMailboxAuthoritySignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ValidateCheckpointContext(context);
        var frozenBytes = canonicalAuthority.ToArray();
        var frozen = ProductionMailboxAuthorityCodec.Decode(frozenBytes);
        if (!frozenBytes.AsSpan().SequenceEqual(ProductionMailboxAuthorityCodec.Encode(frozen)))
            throw Error(ProductionMailboxAuthorityError.NonCanonical,
                "Forward checkpoint PMA1 is not canonical.");
        if (!CryptographicOperations.FixedTimeEquals(frozen.NetworkId.Span,
                context.ExpectedNetworkId.Span))
            throw Error(ProductionMailboxAuthorityError.InvalidField,
                "Forward checkpoint authority is for another network.");
        if (frozen.AuthorityGeneration == ulong.MaxValue ||
            frozen.AuthorityGeneration <= context.LastCommittedGeneration)
            throw Error(ProductionMailboxAuthorityError.AuthorityRollback,
                "Forward checkpoint authority did not advance durable generation.");
        if (!CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(frozen.MrXApprovalEd25519PublicKey.Span),
                context.PinnedMrXPublicKeySha256.Span))
            throw Error(ProductionMailboxAuthorityError.UntrustedMrXKey,
                "Forward checkpoint Mr. X key does not match the caller-pinned key hash.");
        if (!signatureVerifier.Verify(frozen.MrXApprovalEd25519PublicKey.Span,
                ProductionMailboxAuthorityCodec.GetSigningBytes(frozen), frozen.Signature.Span))
            throw Error(ProductionMailboxAuthorityError.InvalidSignature,
                "Forward checkpoint PMA1 signature is invalid.");
        VerifyCheckpointRevocation(frozen.Revocation, context);
        VerifyTime(frozen, context.NowUnixSeconds, context.ClockSkewSeconds);
        return new VerifiedProductionMailboxAuthority(
            frozen, SHA256.HashData(frozenBytes), frozen.AuthorityGeneration);
    }

    public static VerifiedProductionMailboxAuthority Verify(
        ProductionMailboxAuthority authority,
        ProductionMailboxAuthorityVerificationContext context,
        IProductionMailboxAuthoritySignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ValidateContext(context);

        // Freeze caller-owned backing arrays once. Every trust decision below uses only the strict
        // canonical re-decode, so concurrent mutation cannot create a verified mixed snapshot.
        var encoded = ProductionMailboxAuthorityCodec.Encode(authority);
        var frozen = ProductionMailboxAuthorityCodec.Decode(encoded);
        var canonicalHash = SHA256.HashData(encoded);
        if (!CryptographicOperations.FixedTimeEquals(frozen.NetworkId.Span, context.ExpectedNetworkId.Span))
            throw Error(ProductionMailboxAuthorityError.InvalidField, "Authority is for another network.");
        if (frozen.AuthorityGeneration == ulong.MaxValue || frozen.AuthorityGeneration != context.LastCommittedGeneration + 1)
            throw Error(ProductionMailboxAuthorityError.AuthorityRollback, "Authority generation is not the next durable generation.");
        if (!CryptographicOperations.FixedTimeEquals(frozen.PreviousAuthorityHash.Span, context.LastCommittedAuthorityHash.Span))
            throw Error(ProductionMailboxAuthorityError.PreviousHashMismatch, "Authority previous hash does not match durable state.");
        if (!CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(frozen.MrXApprovalEd25519PublicKey.Span), context.PinnedMrXPublicKeySha256.Span))
            throw Error(ProductionMailboxAuthorityError.UntrustedMrXKey, "Authority Mr. X key does not match the caller-pinned key hash.");
        if (!signatureVerifier.Verify(
                frozen.MrXApprovalEd25519PublicKey.Span,
                ProductionMailboxAuthorityCodec.GetSigningBytes(frozen),
                frozen.Signature.Span))
            throw Error(ProductionMailboxAuthorityError.InvalidSignature, "Authority signature is invalid.");
        VerifyRevocationSuccessor(frozen.Revocation, context);
        VerifyTime(frozen, context.NowUnixSeconds, context.ClockSkewSeconds);
        return new VerifiedProductionMailboxAuthority(frozen, canonicalHash, frozen.AuthorityGeneration);
    }

    private static void ValidateContext(ProductionMailboxAuthorityVerificationContext context)
    {
        if (context.PinnedMrXPublicKeySha256.Length != ProductionMailboxAuthorityConstants.HashLength ||
            context.PinnedMrXPublicKeySha256.Span.IndexOfAnyExcept((byte)0) < 0 ||
            context.ExpectedNetworkId.Length != ProductionMailboxAuthorityConstants.NetworkIdLength ||
            context.ExpectedNetworkId.Span.IndexOfAnyExcept((byte)0) < 0 ||
            context.LastCommittedGeneration == 0 ||
            context.LastCommittedAuthorityHash.Length != ProductionMailboxAuthorityConstants.HashLength ||
            context.LastCommittedAuthorityHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            context.LastCommittedRevocationGeneration == 0 ||
            context.LastCommittedRevocationHeadHash.Length != ProductionMailboxAuthorityConstants.HashLength ||
            context.LastCommittedRevocationHeadHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            context.LastCommittedRevocationSnapshotHash.Length != ProductionMailboxAuthorityConstants.HashLength ||
            context.LastCommittedRevocationSnapshotHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            context.NowUnixSeconds == 0 || context.ClockSkewSeconds > ProductionMailboxAuthorityConstants.MaximumClockSkewSeconds)
            throw Error(ProductionMailboxAuthorityError.InvalidField, "Verification context is incomplete or unsafe.");
    }

    private static void ValidateCheckpointContext(
        ProductionMailboxAuthorityCheckpointVerificationContext context)
    {
        if (context.PinnedMrXPublicKeySha256.Length != ProductionMailboxAuthorityConstants.HashLength ||
            context.PinnedMrXPublicKeySha256.Span.IndexOfAnyExcept((byte)0) < 0 ||
            context.ExpectedNetworkId.Length != ProductionMailboxAuthorityConstants.NetworkIdLength ||
            context.ExpectedNetworkId.Span.IndexOfAnyExcept((byte)0) < 0 ||
            context.LastCommittedGeneration == 0 ||
            context.LastCommittedRevocationGeneration == 0 ||
            context.LastCommittedRevocationHeadHash.Length != ProductionMailboxAuthorityConstants.HashLength ||
            context.LastCommittedRevocationHeadHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            context.LastCommittedRevocationSnapshotHash.Length != ProductionMailboxAuthorityConstants.HashLength ||
            context.LastCommittedRevocationSnapshotHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            context.NowUnixSeconds == 0 ||
            context.ClockSkewSeconds > ProductionMailboxAuthorityConstants.MaximumClockSkewSeconds)
            throw Error(ProductionMailboxAuthorityError.InvalidField,
                "Forward checkpoint verification context is incomplete or unsafe.");
    }

    private static void VerifyCheckpointRevocation(
        ProductionMailboxAuthorityRevocation revocation,
        ProductionMailboxAuthorityCheckpointVerificationContext context)
    {
        if (revocation.Generation == ulong.MaxValue ||
            revocation.Generation < context.LastCommittedRevocationGeneration)
            throw Error(ProductionMailboxAuthorityError.AuthorityRollback,
                "Forward checkpoint revocation generation rolled back.");
        if (revocation.Generation == context.LastCommittedRevocationGeneration)
        {
            if (!CryptographicOperations.FixedTimeEquals(revocation.HeadHash.Span,
                    context.LastCommittedRevocationHeadHash.Span) ||
                !CryptographicOperations.FixedTimeEquals(revocation.SnapshotHash.Span,
                    context.LastCommittedRevocationSnapshotHash.Span))
                throw Error(ProductionMailboxAuthorityError.PreviousHashMismatch,
                    "Same revocation generation conflicts with durable state.");
            return;
        }
    }

    private static void VerifyRevocationSuccessor(
        ProductionMailboxAuthorityRevocation revocation,
        ProductionMailboxAuthorityVerificationContext context)
    {
        if (revocation.Generation < context.LastCommittedRevocationGeneration)
            throw Error(ProductionMailboxAuthorityError.AuthorityRollback, "Revocation generation rolled back.");
        if (revocation.Generation == context.LastCommittedRevocationGeneration)
        {
            if (!CryptographicOperations.FixedTimeEquals(revocation.HeadHash.Span, context.LastCommittedRevocationHeadHash.Span) ||
                !CryptographicOperations.FixedTimeEquals(revocation.SnapshotHash.Span, context.LastCommittedRevocationSnapshotHash.Span))
                throw Error(ProductionMailboxAuthorityError.PreviousHashMismatch, "Same revocation generation has a conflicting head or snapshot.");
            return;
        }
        if (context.LastCommittedRevocationGeneration == ulong.MaxValue ||
            revocation.Generation != context.LastCommittedRevocationGeneration + 1)
            throw Error(ProductionMailboxAuthorityError.AuthorityRollback, "Revocation generation is not the next durable generation.");
        if (!CryptographicOperations.FixedTimeEquals(revocation.PreviousHeadHash.Span, context.LastCommittedRevocationHeadHash.Span))
            throw Error(ProductionMailboxAuthorityError.PreviousHashMismatch, "Revocation previous head does not match durable state.");
    }

    private static void VerifyTime(ProductionMailboxAuthority authority, ulong now, uint skew)
    {
        VerifyWindow(authority.CurrentEpoch.NotBeforeUnixSeconds, authority.CurrentEpoch.NotAfterUnixSeconds, now, skew, "current epoch");
        VerifyWindow(authority.MrXApproval.RolloutNotBeforeUnixSeconds, authority.MrXApproval.RolloutNotAfterUnixSeconds, now, skew, "rollout");
        if (now < authority.Revocation.IssuedAtUnixSeconds && authority.Revocation.IssuedAtUnixSeconds - now > skew)
            throw Error(ProductionMailboxAuthorityError.NotYetValid, "Revocation snapshot is not yet valid.");
        if (now > authority.Revocation.ExpiresAtUnixSeconds && now - authority.Revocation.ExpiresAtUnixSeconds > skew)
            throw Error(ProductionMailboxAuthorityError.Expired, "Revocation snapshot has expired.");
    }

    private static void VerifyWindow(ulong from, ulong until, ulong now, uint skew, string name)
    {
        if (now < from && from - now > skew)
            throw Error(ProductionMailboxAuthorityError.NotYetValid, $"{name} is not yet valid.");
        if (now > until && now - until > skew)
            throw Error(ProductionMailboxAuthorityError.Expired, $"{name} has expired.");
    }

    private static ProductionMailboxAuthorityException Error(ProductionMailboxAuthorityError error, string message) => new(error, message);
}
