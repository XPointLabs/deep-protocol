using Deep.Protocol.Abstractions;
using Deep.Protocol.Abstractions.Crypto;

namespace Deep.Protocol;

public sealed class ProProofService
{
    private readonly IProtocolHashing hashing;
    private readonly ISessionProtocolCrypto crypto;

    public ProProofService(IProtocolHashing hashing, ISessionProtocolCrypto crypto)
    {
        this.hashing = hashing;
        this.crypto = crypto;
    }

    public byte[] ComputeHash(ProProof proof)
    {
        ByteHelpers.RequireSize(
            proof.GenerationIndexHash,
            ProtocolConstants.Ed25519PublicKeySize,
            nameof(proof.GenerationIndexHash));
        ByteHelpers.RequireSize(
            proof.RotatingPublicKey,
            ProtocolConstants.Ed25519PublicKeySize,
            nameof(proof.RotatingPublicKey));

        return hashing.Blake2b256Personalized(
            ProtocolConstants.ProBuildProofHashPersonalisation,
            new[] { proof.Version },
            proof.GenerationIndexHash,
            proof.RotatingPublicKey,
            ByteHelpers.UnixMillisecondsLittleEndian(proof.ExpiryUnixTime));
    }

    public ProStatus GetStatus(
        ProProof proof,
        ReadOnlySpan<byte> proBackendPublicKey,
        DateTimeOffset unixTimestamp,
        ProSignedMessage? signedMessage)
    {
        if (proBackendPublicKey.Length != ProtocolConstants.Ed25519PublicKeySize)
        {
            throw new ArgumentException("Pro backend public key must be 32 bytes.", nameof(proBackendPublicKey));
        }

        var proofHash = ComputeHash(proof);
        if (!crypto.VerifyEd25519Detached(proof.Signature.Span, proofHash, proBackendPublicKey))
        {
            return ProStatus.InvalidProBackendSignature;
        }

        if (signedMessage is not null &&
            !crypto.VerifyEd25519Detached(
                signedMessage.Signature.Span,
                signedMessage.Message.Span,
                proof.RotatingPublicKey.Span))
        {
            return ProStatus.InvalidUserSignature;
        }

        return unixTimestamp <= proof.ExpiryUnixTime ? ProStatus.Valid : ProStatus.Expired;
    }
}
