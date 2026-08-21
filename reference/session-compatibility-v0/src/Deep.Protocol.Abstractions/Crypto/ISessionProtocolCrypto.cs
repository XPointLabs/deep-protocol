namespace Deep.Protocol.Abstractions.Crypto;

public sealed record RecipientDecryptionResult(
    ReadOnlyMemory<byte> Plaintext,
    ReadOnlyMemory<byte> SenderEd25519PublicKey);

public sealed record GroupDecryptionResult(
    int KeyIndex,
    string SenderSessionIdHex,
    ReadOnlyMemory<byte> Plaintext);

public interface IProtocolHashing
{
    byte[] Blake2b256Personalized(string personalization, params ReadOnlyMemory<byte>[] parts);
}

public interface ISessionProtocolCrypto
{
    byte[] NormalizeEd25519SecretKey(ReadOnlySpan<byte> secretKeyOrSeed);

    byte[] GenerateEd25519SecretKey();

    byte[] SignEd25519Detached(ReadOnlySpan<byte> message, ReadOnlySpan<byte> ed25519SecretKey);

    bool VerifyEd25519Detached(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> ed25519PublicKey);

    byte[] ConvertEd25519PublicKeyToX25519(ReadOnlySpan<byte> ed25519PublicKey);

    byte[] EncryptForRecipient(
        ReadOnlySpan<byte> ed25519SecretKey,
        ReadOnlySpan<byte> recipientX25519PublicKey,
        ReadOnlySpan<byte> message);

    RecipientDecryptionResult DecryptIncoming(
        ReadOnlySpan<byte> ed25519SecretKey,
        ReadOnlySpan<byte> ciphertext);

    byte[] EncryptForBlindedRecipient(
        ReadOnlySpan<byte> ed25519SecretKey,
        ReadOnlySpan<byte> serverPublicKey,
        ReadOnlySpan<byte> recipientBlindedId,
        ReadOnlySpan<byte> message);

    byte[] EncryptForGroup(
        ReadOnlySpan<byte> userEd25519SecretKey,
        ReadOnlySpan<byte> groupEd25519PublicKey,
        ReadOnlySpan<byte> groupEncryptionKey,
        ReadOnlySpan<byte> plaintext,
        bool compress,
        int padding);

    GroupDecryptionResult DecryptGroupMessage(
        IReadOnlyList<ReadOnlyMemory<byte>> decryptEd25519PrivateKeys,
        ReadOnlySpan<byte> groupEd25519PublicKey,
        ReadOnlySpan<byte> ciphertext);
}
