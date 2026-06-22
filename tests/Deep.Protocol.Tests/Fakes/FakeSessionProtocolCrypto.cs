using System.Security.Cryptography;
using Deep.Protocol.Abstractions;
using Deep.Protocol.Abstractions.Crypto;

namespace Deep.Protocol.Tests.Fakes;

internal sealed class FakeSessionProtocolCrypto : ISessionProtocolCrypto, IProtocolHashing
{
    public static readonly byte[] SenderEd25519PublicKey = Convert.FromHexString(
        "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");

    public static readonly byte[] SenderX25519PublicKey = Convert.FromHexString(
        "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");

    public byte[] Blake2b256Personalized(string personalization, params ReadOnlyMemory<byte>[] parts)
    {
        using var sha = SHA256.Create();
        sha.TransformBlock(System.Text.Encoding.ASCII.GetBytes(personalization), 0, personalization.Length, null, 0);
        foreach (var part in parts)
        {
            var bytes = part.ToArray();
            sha.TransformBlock(bytes, 0, bytes.Length, null, 0);
        }

        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return sha.Hash!;
    }

    public byte[] NormalizeEd25519SecretKey(ReadOnlySpan<byte> secretKeyOrSeed)
    {
        if (secretKeyOrSeed.Length == ProtocolConstants.Ed25519SecretKeySize)
        {
            return secretKeyOrSeed.ToArray();
        }

        if (secretKeyOrSeed.Length == ProtocolConstants.Ed25519SeedSize)
        {
            var result = new byte[ProtocolConstants.Ed25519SecretKeySize];
            secretKeyOrSeed.CopyTo(result);
            SenderEd25519PublicKey.CopyTo(result.AsSpan(ProtocolConstants.Ed25519SeedSize));
            return result;
        }

        throw new ArgumentException("Invalid fake secret key size.");
    }

    public byte[] GenerateEd25519SecretKey() =>
        Enumerable.Repeat((byte)0x42, ProtocolConstants.Ed25519SecretKeySize).ToArray();

    public byte[] SignEd25519Detached(ReadOnlySpan<byte> message, ReadOnlySpan<byte> ed25519SecretKey)
    {
        using var hmac = new HMACSHA512(ed25519SecretKey.ToArray());
        return hmac.ComputeHash(message.ToArray());
    }

    public bool VerifyEd25519Detached(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> ed25519PublicKey) =>
        signature.Length == ProtocolConstants.SignatureSize;

    public byte[] ConvertEd25519PublicKeyToX25519(ReadOnlySpan<byte> ed25519PublicKey) =>
        ed25519PublicKey.SequenceEqual(SenderEd25519PublicKey)
            ? SenderX25519PublicKey.ToArray()
            : SHA256.HashData(ed25519PublicKey.ToArray());

    public byte[] EncryptForRecipient(
        ReadOnlySpan<byte> ed25519SecretKey,
        ReadOnlySpan<byte> recipientX25519PublicKey,
        ReadOnlySpan<byte> message) =>
        WithMarker(0xee, message);

    public RecipientDecryptionResult DecryptIncoming(
        ReadOnlySpan<byte> ed25519SecretKey,
        ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length == 0 || ciphertext[0] != 0xee)
        {
            throw new InvalidOperationException("Fake decrypt failed.");
        }

        return new RecipientDecryptionResult(ciphertext[1..].ToArray(), SenderEd25519PublicKey);
    }

    public byte[] EncryptForBlindedRecipient(
        ReadOnlySpan<byte> ed25519SecretKey,
        ReadOnlySpan<byte> serverPublicKey,
        ReadOnlySpan<byte> recipientBlindedId,
        ReadOnlySpan<byte> message) =>
        WithMarker(0xb1, message);

    public byte[] EncryptForGroup(
        ReadOnlySpan<byte> userEd25519SecretKey,
        ReadOnlySpan<byte> groupEd25519PublicKey,
        ReadOnlySpan<byte> groupEncryptionKey,
        ReadOnlySpan<byte> plaintext,
        bool compress,
        int padding) =>
        WithMarker(0xe3, plaintext);

    public GroupDecryptionResult DecryptGroupMessage(
        IReadOnlyList<ReadOnlyMemory<byte>> decryptEd25519PrivateKeys,
        ReadOnlySpan<byte> groupEd25519PublicKey,
        ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length == 0 || ciphertext[0] != 0xe3)
        {
            throw new InvalidOperationException("Fake group decrypt failed.");
        }

        return new GroupDecryptionResult(
            0,
            "05" + Convert.ToHexString(SenderX25519PublicKey).ToLowerInvariant(),
            ciphertext[1..].ToArray());
    }

    private static byte[] WithMarker(byte marker, ReadOnlySpan<byte> payload)
    {
        var result = new byte[payload.Length + 1];
        result[0] = marker;
        payload.CopyTo(result.AsSpan(1));
        return result;
    }
}
