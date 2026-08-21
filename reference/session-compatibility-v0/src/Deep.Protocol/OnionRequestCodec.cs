using Deep.Protocol.Abstractions.OnionRequests;

namespace Deep.Protocol;

public sealed class OnionRequestCodec
{
    private readonly IOnionRequestCrypto crypto;

    public OnionRequestCodec(IOnionRequestCrypto? crypto = null)
    {
        this.crypto = crypto ?? new SodiumOnionRequestCrypto();
    }

    public static OnionEncryptionType ParseEncryptionType(string value) =>
        value switch
        {
            "xchacha20" => OnionEncryptionType.XChaCha20,
            "aes-gcm" or "gcm" => OnionEncryptionType.AesGcm,
            _ => throw new ArgumentException(
                "Supported onion request encryption values are xchacha20, aes-gcm, and gcm.",
                nameof(value))
        };

    public static string ToWireString(OnionEncryptionType type) =>
        type switch
        {
            OnionEncryptionType.XChaCha20 => "xchacha20",
            OnionEncryptionType.AesGcm => "aes-gcm",
            _ => throw new ArgumentOutOfRangeException(nameof(type))
        };

    public OnionRequestPayload Build(OnionRequestBuildOptions options, ReadOnlySpan<byte> plaintextBody) =>
        crypto.Build(options, plaintextBody);

    public OnionResponse DecryptResponse(
        OnionEncryptionType encryptionType,
        ReadOnlySpan<byte> destinationX25519PublicKey,
        ReadOnlySpan<byte> finalHopX25519PublicKey,
        ReadOnlySpan<byte> finalHopX25519SecretKey,
        ReadOnlySpan<byte> encryptedResponse,
        bool v4Request = false) =>
        crypto.DecryptResponse(
            encryptionType,
            destinationX25519PublicKey,
            finalHopX25519PublicKey,
            finalHopX25519SecretKey,
            encryptedResponse,
            v4Request);
}
