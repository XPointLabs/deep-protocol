using System.Buffers.Binary;

namespace Deep.Protocol.DeepExtension.MailboxAuthority;

public enum ProductionMailboxIssuanceIntent : byte
{
    LocalOwner = 1,
    PeerDeposit = 2
}

public enum ProductionMailboxClientPlatform : byte
{
    Android = 1,
    Windows = 2
}

public enum ProductionMailboxHolderProofError
{
    InvalidIntent,
    InvalidPlatform,
    InvalidField,
    InvalidRoute,
    InvalidSignature
}

public sealed class ProductionMailboxHolderProofException(
    ProductionMailboxHolderProofError error,
    string message) : Exception(message)
{
    public ProductionMailboxHolderProofError Error { get; } = error;
}

public sealed record ProductionMailboxHolderProofInput
{
    public required ProductionMailboxIssuanceIntent Intent { get; init; }
    public required ProductionMailboxClientPlatform Platform { get; init; }
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ReadOnlyMemory<byte> CanonicalAuthorityHash { get; init; }
    public required ReadOnlyMemory<byte> HolderEd25519PublicKey { get; init; }
    public required ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey { get; init; }
    /// <summary>All zero only for LocalOwner route derivation; otherwise exact blinded route.</summary>
    public required ReadOnlyMemory<byte> BlindedMailboxId { get; init; }
    public required ReadOnlyMemory<byte> BlindedPlacementId { get; init; }
    public required ReadOnlyMemory<byte> SelectionInputCommitment { get; init; }
    public required ReadOnlyMemory<byte> SigningCertificateSha256 { get; init; }
    public required ReadOnlyMemory<byte> BuildArtifactSha256 { get; init; }
    public required ReadOnlyMemory<byte> IdempotencyKey { get; init; }
    /// <summary>SHA-256 of an opaque entitlement, or all zero when base-free limits are requested.</summary>
    public required ReadOnlyMemory<byte> EntitlementCommitment { get; init; }
    public required ReadOnlyMemory<byte> ChallengeId { get; init; }
    public required ReadOnlyMemory<byte> Challenge { get; init; }
    public required ulong ProofOfWorkNonce { get; init; }
}

public interface IProductionMailboxHolderProofSignatureVerifier
{
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature);
}

/// <summary>Verify-only adapter; no issuer, holder, or owner private-key API exists here.</summary>
public sealed class SodiumProductionMailboxHolderProofSignatureVerifier
    : IProductionMailboxHolderProofSignatureVerifier
{
    private readonly SodiumProductionMailboxAuthoritySignatureVerifier inner = new();

    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature) =>
        inner.Verify(publicKey, signingBytes, signature);
}

public static class ProductionMailboxHolderProof
{
    public const int CanonicalPayloadLength = 400;
    private static ReadOnlySpan<byte> Domain => "Deep/production-mailbox/holder-proof/v1"u8;
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.PHP1;

    public static byte[] GetSigningBytes(ProductionMailboxHolderProofInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        ValidateFixedFieldLengths(input);
        var frozen = Freeze(input);
        return GetFrozenSigningBytes(frozen);
    }

    private static byte[] GetFrozenSigningBytes(ProductionMailboxHolderProofInput input)
    {
        Validate(input);
        var payload = new byte[CanonicalPayloadLength];
        Magic.CopyTo(payload); payload[4] = 1; payload[5] = (byte)input.Intent;
        payload[6] = (byte)input.Platform; payload[7] = 0;
        var offset = 8;
        Copy(input.NetworkId.Span, payload, ref offset);
        Copy(input.CanonicalAuthorityHash.Span, payload, ref offset);
        Copy(input.HolderEd25519PublicKey.Span, payload, ref offset);
        Copy(input.MailboxOwnerEd25519PublicKey.Span, payload, ref offset);
        Copy(input.BlindedMailboxId.Span, payload, ref offset);
        Copy(input.BlindedPlacementId.Span, payload, ref offset);
        Copy(input.SelectionInputCommitment.Span, payload, ref offset);
        Copy(input.SigningCertificateSha256.Span, payload, ref offset);
        Copy(input.BuildArtifactSha256.Span, payload, ref offset);
        Copy(input.IdempotencyKey.Span, payload, ref offset);
        Copy(input.EntitlementCommitment.Span, payload, ref offset);
        Copy(input.ChallengeId.Span, payload, ref offset);
        Copy(input.Challenge.Span, payload, ref offset);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(offset), input.ProofOfWorkNonce);
        return [.. Domain, .. payload];
    }

    public static void VerifyHolder(
        ProductionMailboxHolderProofInput input,
        ReadOnlySpan<byte> signature,
        IProductionMailboxHolderProofSignatureVerifier verifier) =>
        Verify(input, false, signature, verifier, "holder");

    public static void VerifyOwner(
        ProductionMailboxHolderProofInput input,
        ReadOnlySpan<byte> signature,
        IProductionMailboxHolderProofSignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input.Intent != ProductionMailboxIssuanceIntent.LocalOwner)
            throw Error(ProductionMailboxHolderProofError.InvalidIntent,
                "Owner proof is valid only for LocalOwner issuance.");
        Verify(input, true, signature, verifier, "owner");
    }

    private static void Verify(
        ProductionMailboxHolderProofInput input,
        bool owner,
        ReadOnlySpan<byte> signature,
        IProductionMailboxHolderProofSignatureVerifier verifier,
        string role)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(verifier);
        ValidateFixedFieldLengths(input);
        if (signature.Length != 64)
            throw Error(ProductionMailboxHolderProofError.InvalidSignature,
                $"Production mailbox {role} proof is invalid.");
        var frozen = Freeze(input);
        var frozenPublicKey = (owner
            ? frozen.MailboxOwnerEd25519PublicKey : frozen.HolderEd25519PublicKey).ToArray();
        var frozenSignature = signature.ToArray();
        var signingBytes = GetFrozenSigningBytes(frozen);
        if (!verifier.Verify(frozenPublicKey, signingBytes, frozenSignature))
            throw Error(ProductionMailboxHolderProofError.InvalidSignature,
                $"Production mailbox {role} proof is invalid.");
    }

    private static void Validate(ProductionMailboxHolderProofInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!Enum.IsDefined(input.Intent))
            throw Error(ProductionMailboxHolderProofError.InvalidIntent, "Issuance intent is invalid.");
        if (!Enum.IsDefined(input.Platform))
            throw Error(ProductionMailboxHolderProofError.InvalidPlatform, "Client platform is invalid.");
        FixedNonzero(input.NetworkId, 16, "network ID");
        FixedNonzero(input.CanonicalAuthorityHash, 32, "authority hash");
        FixedNonzero(input.HolderEd25519PublicKey, 32, "holder key");
        FixedNonzero(input.MailboxOwnerEd25519PublicKey, 32, "owner key");
        FixedNonzero(input.SigningCertificateSha256, 32, "certificate hash");
        FixedNonzero(input.BuildArtifactSha256, 32, "build hash");
        FixedNonzero(input.IdempotencyKey, 32, "idempotency key");
        FixedLength(input.EntitlementCommitment, 32, "entitlement commitment");
        FixedNonzero(input.ChallengeId, 16, "challenge ID");
        FixedNonzero(input.Challenge, 32, "challenge");
        FixedLength(input.BlindedMailboxId, 32, "blinded mailbox ID");
        FixedLength(input.BlindedPlacementId, 32, "blinded placement ID");
        FixedLength(input.SelectionInputCommitment, 32, "selection commitment");
        var routeFields = new[]
        {
            input.BlindedMailboxId.Span.IndexOfAnyExcept((byte)0) >= 0,
            input.BlindedPlacementId.Span.IndexOfAnyExcept((byte)0) >= 0,
            input.SelectionInputCommitment.Span.IndexOfAnyExcept((byte)0) >= 0
        };
        if (routeFields.Distinct().Count() != 1 ||
            input.Intent == ProductionMailboxIssuanceIntent.LocalOwner && routeFields[0] ||
            input.Intent == ProductionMailboxIssuanceIntent.PeerDeposit && !routeFields[0])
            throw Error(ProductionMailboxHolderProofError.InvalidRoute,
                "LocalOwner requires a zero route; PeerDeposit requires a complete route.");
    }

    private static void ValidateFixedFieldLengths(ProductionMailboxHolderProofInput input)
    {
        if (input.NetworkId.Length != 16 ||
            input.CanonicalAuthorityHash.Length != 32 ||
            input.HolderEd25519PublicKey.Length != 32 ||
            input.MailboxOwnerEd25519PublicKey.Length != 32 ||
            input.BlindedMailboxId.Length != 32 ||
            input.BlindedPlacementId.Length != 32 ||
            input.SelectionInputCommitment.Length != 32 ||
            input.SigningCertificateSha256.Length != 32 ||
            input.BuildArtifactSha256.Length != 32 ||
            input.IdempotencyKey.Length != 32 ||
            input.EntitlementCommitment.Length != 32 ||
            input.ChallengeId.Length != 16 ||
            input.Challenge.Length != 32)
            throw Error(ProductionMailboxHolderProofError.InvalidField,
                "Holder-proof fixed field length is invalid.");
    }

    private static ProductionMailboxHolderProofInput Freeze(ProductionMailboxHolderProofInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        return input with
        {
            NetworkId = input.NetworkId.ToArray(),
            CanonicalAuthorityHash = input.CanonicalAuthorityHash.ToArray(),
            HolderEd25519PublicKey = input.HolderEd25519PublicKey.ToArray(),
            MailboxOwnerEd25519PublicKey = input.MailboxOwnerEd25519PublicKey.ToArray(),
            BlindedMailboxId = input.BlindedMailboxId.ToArray(),
            BlindedPlacementId = input.BlindedPlacementId.ToArray(),
            SelectionInputCommitment = input.SelectionInputCommitment.ToArray(),
            SigningCertificateSha256 = input.SigningCertificateSha256.ToArray(),
            BuildArtifactSha256 = input.BuildArtifactSha256.ToArray(),
            IdempotencyKey = input.IdempotencyKey.ToArray(),
            EntitlementCommitment = input.EntitlementCommitment.ToArray(),
            ChallengeId = input.ChallengeId.ToArray(),
            Challenge = input.Challenge.ToArray()
        };
    }

    private static void FixedNonzero(ReadOnlyMemory<byte> value, int length, string name)
    {
        FixedLength(value, length, name);
        if (value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Error(ProductionMailboxHolderProofError.InvalidField, $"{name} is all zero.");
    }

    private static void FixedLength(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw Error(ProductionMailboxHolderProofError.InvalidField, $"{name} length is invalid.");
    }

    private static void Copy(ReadOnlySpan<byte> value, byte[] output, ref int offset)
    {
        value.CopyTo(output.AsSpan(offset)); offset += value.Length;
    }

    private static ProductionMailboxHolderProofException Error(
        ProductionMailboxHolderProofError error,
        string message) => new(error, message);
}
