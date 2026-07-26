using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public sealed class SodiumMailboxPeerReplicationCrypto : IMailboxPeerReplicationCrypto
{
    public byte[] GetPublicKey(ReadOnlySpan<byte> seedOrPrivateKey)
    {
        var privateKey = NormalizePrivateKey(seedOrPrivateKey);
        return PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(privateKey);
    }

    public MailboxPeerReplicationRequest SignRequest(
        MailboxPeerReplicationRequest unsignedRequest,
        ReadOnlySpan<byte> sourceSeedOrPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(unsignedRequest);
        var publicKey = GetPublicKey(sourceSeedOrPrivateKey);
        if (!CryptographicOperations.FixedTimeEquals(
                publicKey,
                unsignedRequest.SourceMembershipProof.SigningPublicKey.Span))
            throw new ArgumentException("Source key does not match MIP1.", nameof(sourceSeedOrPrivateKey));
        return unsignedRequest with
        {
            Signature = PublicKeyAuth.SignDetached(
                MailboxPeerReplicationCodec.GetSigningBytes(unsignedRequest),
                NormalizePrivateKey(sourceSeedOrPrivateKey))
        };
    }

    public bool Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64)
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

    public byte[] Digest(ReadOnlySpan<byte> canonicalBytes) =>
        SHA256.HashData(canonicalBytes);

    private static byte[] NormalizePrivateKey(ReadOnlySpan<byte> value) =>
        value.Length switch
        {
            32 => PublicKeyAuth.GenerateKeyPair(value.ToArray()).PrivateKey,
            64 => value.ToArray(),
            _ => throw new ArgumentException("Ed25519 key material must be a 32-byte seed or 64-byte private key.")
        };
}

