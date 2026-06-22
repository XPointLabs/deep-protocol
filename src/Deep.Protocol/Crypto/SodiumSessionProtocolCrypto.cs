using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;
using Deep.Protocol.Abstractions;
using Deep.Protocol.Abstractions.Crypto;
using Sodium;

namespace Deep.Protocol;

public sealed class SodiumSessionProtocolCrypto : ISessionProtocolCrypto, IProtocolHashing
{
    private static readonly byte[] ZeroSalt = new byte[16];

    public byte[] Blake2b256Personalized(string personalization, params ReadOnlyMemory<byte>[] parts)
    {
        var content = Combine(parts);
        var personal = Encoding.ASCII.GetBytes(personalization);
        if (personal.Length != 16)
        {
            throw new ArgumentException("Session personalisation must be 16 bytes.", nameof(personalization));
        }

        return GenericHash.HashSaltPersonal(content, key: null, ZeroSalt, personal, bytes: 32);
    }

    public byte[] NormalizeEd25519SecretKey(ReadOnlySpan<byte> secretKeyOrSeed)
    {
        if (secretKeyOrSeed.Length == ProtocolConstants.Ed25519SecretKeySize)
        {
            return secretKeyOrSeed.ToArray();
        }

        if (secretKeyOrSeed.Length != ProtocolConstants.Ed25519SeedSize)
        {
            throw new ArgumentException("Ed25519 key material must be 32-byte seed or 64-byte secret key.", nameof(secretKeyOrSeed));
        }

        return PublicKeyAuth.GenerateKeyPair(secretKeyOrSeed.ToArray()).PrivateKey;
    }

    public byte[] GenerateEd25519SecretKey()
    {
        var seed = RandomNumberGenerator.GetBytes(ProtocolConstants.Ed25519SeedSize);
        return PublicKeyAuth.GenerateKeyPair(seed).PrivateKey;
    }

    public byte[] SignEd25519Detached(ReadOnlySpan<byte> message, ReadOnlySpan<byte> ed25519SecretKey)
    {
        return PublicKeyAuth.SignDetached(message.ToArray(), NormalizeEd25519SecretKey(ed25519SecretKey).ToArray());
    }

    public bool VerifyEd25519Detached(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> ed25519PublicKey)
    {
        return PublicKeyAuth.VerifyDetached(signature.ToArray(), message.ToArray(), ed25519PublicKey.ToArray());
    }

    public byte[] ConvertEd25519PublicKeyToX25519(ReadOnlySpan<byte> ed25519PublicKey)
    {
        return PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(ed25519PublicKey.ToArray());
    }

    public byte[] EncryptForRecipient(
        ReadOnlySpan<byte> ed25519SecretKey,
        ReadOnlySpan<byte> recipientX25519PublicKey,
        ReadOnlySpan<byte> message)
    {
        var normalized = NormalizeEd25519SecretKey(ed25519SecretKey);
        var senderEd25519PublicKey = PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(normalized);
        var senderId = new byte[ProtocolConstants.SessionIdSize];
        senderId[0] = (byte)SessionIdPrefix.Standard;
        senderEd25519PublicKey.CopyTo(senderId.AsSpan(1));

        var payload = Combine(senderId, message.ToArray());
        return SealedPublicKeyBox.Create(payload, recipientX25519PublicKey.ToArray());
    }

    public RecipientDecryptionResult DecryptIncoming(
        ReadOnlySpan<byte> ed25519SecretKey,
        ReadOnlySpan<byte> ciphertext)
    {
        var normalized = NormalizeEd25519SecretKey(ed25519SecretKey);
        var recipientX25519SecretKey = PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(normalized);
        var recipientEd25519PublicKey = PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(normalized);
        var recipientX25519PublicKey = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(recipientEd25519PublicKey);

        var plaintext = SealedPublicKeyBox.Open(ciphertext.ToArray(), recipientX25519SecretKey, recipientX25519PublicKey);
        if (plaintext.Length < ProtocolConstants.SessionIdSize)
        {
            throw new InvalidOperationException("Decrypted recipient payload is too small.");
        }

        var senderSessionId = plaintext[..ProtocolConstants.SessionIdSize];
        var message = plaintext[ProtocolConstants.SessionIdSize..];
        return new RecipientDecryptionResult(message, senderSessionId[1..].ToArray());
    }

    public byte[] EncryptForBlindedRecipient(
        ReadOnlySpan<byte> ed25519SecretKey,
        ReadOnlySpan<byte> serverPublicKey,
        ReadOnlySpan<byte> recipientBlindedId,
        ReadOnlySpan<byte> message)
    {
        _ = ByteHelpers.RequireSize(serverPublicKey, ProtocolConstants.X25519PublicKeySize, nameof(serverPublicKey));
        var (recipientPrefix, recipientBlindedPublicKey) = ResolveBlindedRecipient(recipientBlindedId);

        var senderEd25519PublicKey = PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(
            NormalizeEd25519SecretKey(ed25519SecretKey));
        var senderId = new byte[ProtocolConstants.SessionIdSize];
        senderId[0] = recipientPrefix;
        senderEd25519PublicKey.CopyTo(senderId.AsSpan(1));

        return SealedPublicKeyBox.Create(Combine(senderId, message.ToArray()), recipientBlindedPublicKey);
    }

    public byte[] EncryptForGroup(
        ReadOnlySpan<byte> userEd25519SecretKey,
        ReadOnlySpan<byte> groupEd25519PublicKey,
        ReadOnlySpan<byte> groupEncryptionKey,
        ReadOnlySpan<byte> plaintext,
        bool compress,
        int padding)
    {
        _ = ByteHelpers.RequireSize(groupEncryptionKey, ProtocolConstants.X25519PublicKeySize, nameof(groupEncryptionKey));

        var senderEd25519PublicKey = PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(
            NormalizeEd25519SecretKey(userEd25519SecretKey));
        var senderId = new byte[ProtocolConstants.SessionIdSize];
        senderId[0] = (byte)SessionIdPrefix.Standard;
        senderEd25519PublicKey.CopyTo(senderId.AsSpan(1));

        var payloadBody = ApplyGroupPadding(plaintext.ToArray(), padding);
        if (compress)
        {
            payloadBody = Compress(payloadBody);
        }

        var payload = Combine(senderId, payloadBody);
        var groupRecipient = ConvertEd25519PublicKeyToX25519(groupEd25519PublicKey);
        return SealedPublicKeyBox.Create(payload, groupRecipient);
    }

    public GroupDecryptionResult DecryptGroupMessage(
        IReadOnlyList<ReadOnlyMemory<byte>> decryptEd25519PrivateKeys,
        ReadOnlySpan<byte> groupEd25519PublicKey,
        ReadOnlySpan<byte> ciphertext)
    {
        var groupRecipient = ConvertEd25519PublicKeyToX25519(groupEd25519PublicKey);

        for (var index = 0; index < decryptEd25519PrivateKeys.Count; index++)
        {
            var key = NormalizeEd25519SecretKey(decryptEd25519PrivateKeys[index].Span);
            var recipientX25519SecretKey = PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(key);

            try
            {
                var plaintext = SealedPublicKeyBox.Open(ciphertext.ToArray(), recipientX25519SecretKey, groupRecipient);
                if (plaintext.Length < ProtocolConstants.SessionIdSize)
                {
                    continue;
                }

                var senderSessionId = plaintext[..ProtocolConstants.SessionIdSize];
                var message = TryRestoreGroupPayload(plaintext[ProtocolConstants.SessionIdSize..]);
                return new GroupDecryptionResult(index, Convert.ToHexString(senderSessionId).ToLowerInvariant(), message);
            }
            catch
            {
            }
        }

        throw new InvalidOperationException($"Group message decryption failed, tried {decryptEd25519PrivateKeys.Count} key(s).");
    }

    private static byte[] Combine(params ReadOnlyMemory<byte>[] parts)
    {
        var total = parts.Sum(part => part.Length);
        var result = new byte[total];
        var offset = 0;

        foreach (var part in parts)
        {
            part.Span.CopyTo(result.AsSpan(offset));
            offset += part.Length;
        }

        return result;
    }

    private static (byte Prefix, byte[] PublicKey) ResolveBlindedRecipient(ReadOnlySpan<byte> recipientBlindedId)
    {
        if (recipientBlindedId.Length == ProtocolConstants.X25519PublicKeySize)
        {
            return ((byte)SessionIdPrefix.Blind15, recipientBlindedId.ToArray());
        }

        if (recipientBlindedId.Length == ProtocolConstants.SessionIdSize)
        {
            var prefix = recipientBlindedId[0];
            if (prefix is not (byte)SessionIdPrefix.Blind15 and not (byte)SessionIdPrefix.Blind25)
            {
                throw new ArgumentException(
                    "Blinded recipient session id must use 0x15 or 0x25 prefix.",
                    nameof(recipientBlindedId));
            }

            return (prefix, recipientBlindedId[1..].ToArray());
        }

        throw new ArgumentException(
            $"Blinded recipient must be {ProtocolConstants.X25519PublicKeySize} or {ProtocolConstants.SessionIdSize} bytes.",
            nameof(recipientBlindedId));
    }

    private static byte[] ApplyGroupPadding(byte[] payload, int padding)
    {
        if (padding <= 0)
        {
            return payload;
        }

        var paddedContentSize = payload.Length + 1;
        var bytesForPadding = padding - (paddedContentSize % padding);
        if (bytesForPadding == padding)
        {
            bytesForPadding = 0;
        }

        var result = new byte[paddedContentSize + bytesForPadding];
        payload.CopyTo(result, 0);
        result[payload.Length] = 0x80;
        return result;
    }

    private static byte[] StripGroupPadding(byte[] payload)
    {
        var sizeWithoutPadding = payload.Length;
        while (sizeWithoutPadding > 0)
        {
            var ch = payload[sizeWithoutPadding - 1];
            if (ch != 0 && ch != 0x80)
            {
                break;
            }

            sizeWithoutPadding--;
            if (ch == 0x80)
            {
                return payload[..sizeWithoutPadding];
            }
        }

        return payload;
    }

    private static byte[] Compress(byte[] payload)
    {
        using var output = new MemoryStream();
        using (var compressor = new BrotliStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            compressor.Write(payload, 0, payload.Length);
        }

        return output.ToArray();
    }

    private static byte[] TryDecompress(byte[] payload)
    {
        try
        {
            using var input = new MemoryStream(payload);
            using var decompressor = new BrotliStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            decompressor.CopyTo(output);
            return output.ToArray();
        }
        catch
        {
            return payload;
        }
    }

    private static byte[] TryRestoreGroupPayload(byte[] payload)
    {
        var maybeDecompressed = TryDecompress(payload);
        return StripGroupPadding(maybeDecompressed);
    }
}