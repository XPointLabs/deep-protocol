using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public sealed class SodiumMailboxCapabilityCrypto : IMailboxAuthenticatedCapabilityCrypto
{
    public byte[] GetPublicKey(ReadOnlySpan<byte> seedOrPrivateKey)
    {
        var privateKey = NormalizePrivateKey(seedOrPrivateKey);
        return PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(privateKey);
    }

    public MailboxAuthenticatedGrant SignGrant(
        MailboxAuthenticatedGrant unsignedGrant,
        ReadOnlySpan<byte> issuerSeedOrPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(unsignedGrant);
        var publicKey = GetPublicKey(issuerSeedOrPrivateKey);
        if (!CryptographicOperations.FixedTimeEquals(publicKey, unsignedGrant.IssuerPublicKey.Span))
            throw new ArgumentException("Issuer private key does not match the grant public key.", nameof(issuerSeedOrPrivateKey));
        var signature = PublicKeyAuth.SignDetached(
            MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(unsignedGrant),
            NormalizePrivateKey(issuerSeedOrPrivateKey));
        return unsignedGrant with { IssuerSignature = signature };
    }

    public MailboxAuthenticatedPresentation SignPresentation(
        MailboxAuthenticatedGrant signedGrant,
        MailboxAuthenticatedRequestBinding binding,
        ulong replayCounter,
        ReadOnlySpan<byte> holderSeedOrPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(signedGrant);
        ArgumentNullException.ThrowIfNull(binding);
        var publicKey = GetPublicKey(holderSeedOrPrivateKey);
        if (!CryptographicOperations.FixedTimeEquals(publicKey, signedGrant.HolderPublicKey.Span))
            throw new ArgumentException("Holder private key does not match the grant public key.", nameof(holderSeedOrPrivateKey));
        var unsigned = new MailboxAuthenticatedPresentation
        {
            Operation = binding.Operation,
            OperationId = binding.OperationId.ToArray(),
            ReplayCounter = replayCounter,
            RequestDigest = binding.RequestDigest.ToArray(),
            Grant = signedGrant,
            HolderSignature = new byte[MailboxAuthenticatedCapabilityLimits.SignatureLength]
        };
        var signature = PublicKeyAuth.SignDetached(
            MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(unsigned),
            NormalizePrivateKey(holderSeedOrPrivateKey));
        return unsigned with { HolderSignature = signature };
    }

    public bool VerifyIssuer(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature) =>
        Verify(publicKey, signingBytes, signature);

    public bool VerifyHolder(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature) =>
        Verify(publicKey, signingBytes, signature);

    public byte[] Digest(ReadOnlySpan<byte> canonicalBytes) =>
        SHA256.HashData(canonicalBytes);

    private static bool Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != MailboxAuthenticatedCapabilityLimits.PublicKeyLength ||
            signature.Length != MailboxAuthenticatedCapabilityLimits.SignatureLength)
            return false;
        try
        {
            return PublicKeyAuth.VerifyDetached(
                signature.ToArray(),
                signingBytes.ToArray(),
                publicKey.ToArray());
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static byte[] NormalizePrivateKey(ReadOnlySpan<byte> value) =>
        value.Length switch
        {
            32 => PublicKeyAuth.GenerateKeyPair(value.ToArray()).PrivateKey,
            64 => value.ToArray(),
            _ => throw new ArgumentException("Ed25519 key material must be a 32-byte seed or 64-byte private key.")
        };
}
