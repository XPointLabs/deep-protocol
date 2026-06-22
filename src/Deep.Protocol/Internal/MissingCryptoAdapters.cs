using Deep.Protocol.Abstractions;
using Deep.Protocol.Abstractions.Crypto;

namespace Deep.Protocol.Internal;

internal sealed class MissingProtocolHashing : IProtocolHashing
{
    public static MissingProtocolHashing Instance { get; } = new();

    private MissingProtocolHashing()
    {
    }

    public byte[] Blake2b256Personalized(string personalization, params ReadOnlyMemory<byte>[] parts) =>
        throw new NotSupportedException(
            "BLAKE2b-256 with Session personalization is crypto adapter boundary. " +
            "Provide an IProtocolHashing implementation backed by a Session-compatible crypto library.");
}

internal sealed class MissingSessionProtocolCrypto : ISessionProtocolCrypto
{
    public static MissingSessionProtocolCrypto Instance { get; } = new();

    private MissingSessionProtocolCrypto()
    {
    }

    public byte[] NormalizeEd25519SecretKey(ReadOnlySpan<byte> secretKeyOrSeed) => Throw();

    public byte[] GenerateEd25519SecretKey() => Throw();

    public byte[] SignEd25519Detached(ReadOnlySpan<byte> message, ReadOnlySpan<byte> ed25519SecretKey) => Throw();

    public bool VerifyEd25519Detached(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> ed25519PublicKey) => ThrowBool();

    public byte[] ConvertEd25519PublicKeyToX25519(ReadOnlySpan<byte> ed25519PublicKey) => Throw();

    public byte[] EncryptForRecipient(
        ReadOnlySpan<byte> ed25519SecretKey,
        ReadOnlySpan<byte> recipientX25519PublicKey,
        ReadOnlySpan<byte> message) => Throw();

    public RecipientDecryptionResult DecryptIncoming(
        ReadOnlySpan<byte> ed25519SecretKey,
        ReadOnlySpan<byte> ciphertext) => ThrowObject<RecipientDecryptionResult>();

    public byte[] EncryptForBlindedRecipient(
        ReadOnlySpan<byte> ed25519SecretKey,
        ReadOnlySpan<byte> serverPublicKey,
        ReadOnlySpan<byte> recipientBlindedId,
        ReadOnlySpan<byte> message) => Throw();

    public byte[] EncryptForGroup(
        ReadOnlySpan<byte> userEd25519SecretKey,
        ReadOnlySpan<byte> groupEd25519PublicKey,
        ReadOnlySpan<byte> groupEncryptionKey,
        ReadOnlySpan<byte> plaintext,
        bool compress,
        int padding) => Throw();

    public GroupDecryptionResult DecryptGroupMessage(
        IReadOnlyList<ReadOnlyMemory<byte>> decryptEd25519PrivateKeys,
        ReadOnlySpan<byte> groupEd25519PublicKey,
        ReadOnlySpan<byte> ciphertext) => ThrowObject<GroupDecryptionResult>();

    private static byte[] Throw() => throw CreateException();

    private static bool ThrowBool() => throw CreateException();

    private static T ThrowObject<T>() => throw CreateException();

    private static NotSupportedException CreateException() =>
        new(
            "Session protocol cryptography is an adapter boundary. " +
            "Provide an ISessionProtocolCrypto implementation backed by libsodium-compatible native bindings.");
}
