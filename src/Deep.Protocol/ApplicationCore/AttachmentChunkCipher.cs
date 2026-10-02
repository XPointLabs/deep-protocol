using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.ApplicationCore;

/// <summary>
/// Frozen section-16 attachment chunk cryptography, not blob/dispatch authority.
/// An object ID/key pair is single-use: the sender must durably retain identical
/// ciphertext before retry or transport switching, never encrypt changed content
/// at an already authored index. Callers own and must clear returned plaintext.
/// </summary>
public static class AttachmentChunkCipher
{
    private const uint ChunkSize = 262_144;
    private const ulong MaximumBytes = 26_214_400;

    public static byte[] Encrypt(ReadOnlySpan<byte> networkId16, ReadOnlySpan<byte> objectId32,
        ReadOnlySpan<byte> objectKey32, uint index, ulong totalPlaintextBytes, ReadOnlySpan<byte> plaintext)
    {
        RequireScope(networkId16, objectId32, objectKey32);
        var length = PlaintextLength(index, totalPlaintextBytes);
        if (plaintext.Length != length) throw new ArgumentException("Attachment plaintext disagrees with its chunk geometry.", nameof(plaintext));
        var input = plaintext.ToArray();
        try { return Transform(networkId16, objectId32, objectKey32, index, totalPlaintextBytes, length, input, false); }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    public static byte[] Decrypt(ParsedDam1 manifest, uint index, ReadOnlySpan<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        manifest.RequireReadable();
        // ParsedDam1 has a closed canonical constructor. Validate geometry and
        // ciphertext commitment before allocating a key or invoking AEAD.
        var length = PlaintextLength(index, manifest.TotalPlaintextBytes);
        var entry = manifest.Chunks[checked((int)index)];
        if (ciphertext.Length != length + 16 || entry.CiphertextLength != ciphertext.Length ||
            !CryptographicOperations.FixedTimeEquals(SHA256.HashData(ciphertext), entry.CiphertextHash.Span))
            throw new CryptographicException("Attachment ciphertext does not match its authenticated manifest.");
        var input = ciphertext.ToArray();
        try { return Transform(manifest.NetworkIdSpan, manifest.ObjectIdSpan, manifest.ObjectKeySpan, index,
            manifest.TotalPlaintextBytes, length, input, true); }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    private static int PlaintextLength(uint index, ulong total)
    {
        if (total is 0 or > MaximumBytes) throw new ArgumentOutOfRangeException(nameof(total));
        var count = checked((uint)((total + ChunkSize - 1) / ChunkSize));
        if (index >= count) throw new ArgumentOutOfRangeException(nameof(index));
        return checked((int)(index == count - 1 ? total - (ulong)index * ChunkSize : ChunkSize));
    }

    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> id, ReadOnlySpan<byte> key)
    {
        if (network.Length != 16 || id.Length != 32 || key.Length != 32 ||
            id.IndexOfAnyExcept((byte)0) < 0 || key.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Attachment cryptographic scope is invalid.");
    }

    private static byte[] Transform(ReadOnlySpan<byte> network, ReadOnlySpan<byte> id,
        ReadOnlySpan<byte> objectKey, uint index, ulong total, int length, byte[] input, bool decrypt)
    {
        Span<byte> prk = stackalloc byte[64];
        var key = new byte[32]; var nonce = new byte[24]; var aad = new byte[64];
        ReadOnlySpan<byte> label = "Deep/Attachment/V1/chunk-key"u8;
        Span<byte> info = stackalloc byte[label.Length + 5];
        label.CopyTo(info); info[label.Length] = 0;
        BinaryPrimitives.WriteUInt32BigEndian(info[(label.Length + 1)..], index);
        // Expand has no length prefix, whereas SHA512-D below has LP32.
        try
        {
            if (HKDF.Extract(HashAlgorithmName.SHA512, objectKey, id, prk) != 64)
                throw new CryptographicException("Attachment HKDF extract length is invalid.");
            HKDF.Expand(HashAlgorithmName.SHA512, prk, key, info);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
            hash.AppendData("Deep/Attachment/V1/chunk-nonce"u8); hash.AppendData([0]);
            Span<byte> number = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(number, 36);
            hash.AppendData(number); hash.AppendData(id);
            BinaryPrimitives.WriteUInt32BigEndian(number, index); hash.AppendData(number);
            Span<byte> digest = stackalloc byte[64];
            if (hash.GetHashAndReset(digest) != 64) throw new CryptographicException("Attachment nonce digest length is invalid.");
            digest[..24].CopyTo(nonce); CryptographicOperations.ZeroMemory(digest);
            network.CopyTo(aad); id.CopyTo(aad.AsSpan(16));
            BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(48), index);
            BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(52), checked((uint)length));
            BinaryPrimitives.WriteUInt64BigEndian(aad.AsSpan(56), total);
            return decrypt ? SecretAeadXChaCha20Poly1305.Decrypt(input, nonce, key, aad) :
                SecretAeadXChaCha20Poly1305.Encrypt(input, nonce, key, aad);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prk); CryptographicOperations.ZeroMemory(info);
            foreach (var buffer in new[] { key, nonce, aad }) CryptographicOperations.ZeroMemory(buffer);
        }
    }
}
