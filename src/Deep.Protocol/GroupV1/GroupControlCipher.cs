using Deep.Protocol.ApplicationCore;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.GroupV1;

/// <summary>DR-0145 exact control-chunk sealing, using only existing suite0201 primitives.</summary>
public static class GroupControlCipher
{
    /// <summary>Generates an independent sealing scalar; the owner must protect and clear it.</summary>
    public static byte[] GeneratePrivateKey() => RandomNumberGenerator.GetBytes(32);

    /// <summary>Derives the public half of an independent sealing key.</summary>
    public static byte[] PublicKey(ReadOnlySpan<byte> scalar)
    {
        if (scalar.Length != 32 || scalar.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("Nonzero scalar32 required.");
        var copy = scalar.ToArray(); try { return ScalarMult.Base(copy); } finally { CryptographicOperations.ZeroMemory(copy); }
    }

    /// <summary>Creates original sealed bytes. Retry must use these exact retained bytes, not call Seal again.</summary>
    public static byte[] Seal(GroupControlRendezvousRecord descriptor, ulong sequence, ReadOnlySpan<byte> predecessor,
        ulong expires, GroupCommitChunkRecord chunk)
    {
        var scalar = GeneratePrivateKey(); var publicKey = PublicKey(scalar); var nonce = RandomNumberGenerator.GetBytes(24);
        var plain = chunk.CanonicalBytes.ToArray();
        try
        {
            var encrypted = Transform(descriptor, sequence, predecessor, expires, scalar, descriptor.Field(9).ToArray(), publicKey, nonce, plain, false);
            return [.. publicKey, .. nonce, .. encrypted];
        }
        finally { foreach (var bytes in new[] { scalar, publicKey, nonce, plain }) CryptographicOperations.ZeroMemory(bytes); }
    }

    /// <summary>Authenticates/decrypts before canonical GCF1 parsing and never adopts membership.</summary>
    public static GroupCommitChunkRecord Open(GroupControlRendezvousRecord descriptor, ReadOnlySpan<byte> scalar,
        ulong sequence, ReadOnlySpan<byte> predecessor, ulong expires, ReadOnlySpan<byte> sealedBytes)
    {
        if (sealedBytes.Length is < 73 or > 32768 || !PublicKey(scalar).AsSpan().SequenceEqual(descriptor.Field(9).Span))
            throw new CryptographicException("Control sealing key/framing mismatch.");
        var privateCopy = scalar.ToArray(); var publicKey = sealedBytes[..32].ToArray(); var nonce = sealedBytes.Slice(32, 24).ToArray();
        var input = sealedBytes[56..].ToArray(); byte[] plain = [];
        try
        {
            plain = Transform(descriptor, sequence, predecessor, expires, privateCopy, publicKey, publicKey, nonce, input, true);
            return (GroupCommitChunkRecord)GroupCodec.Decode(ProtocolMagic.GCF1, plain);
        }
        finally { foreach (var bytes in new[] { privateCopy, publicKey, nonce, input, plain }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static byte[] Transform(GroupControlRendezvousRecord descriptor, ulong sequence, ReadOnlySpan<byte> predecessor,
        ulong expires, byte[] scalar, byte[] peer, byte[] ephemeral, byte[] nonce, byte[] input, bool decrypt)
    {
        if (sequence == 0 || predecessor.Length != 32 || (sequence == 1) != (predecessor.IndexOfAnyExcept((byte)0) < 0) ||
            expires == 0 || expires > BinaryPrimitives.ReadUInt64BigEndian(descriptor.Field(13).Span)) throw new CryptographicException("Control cipher scope mismatch.");
        var info = new byte["Deep/Group/V1/control-seal"u8.Length + 1 + 16 + 8 + 32 + 8];
        "Deep/Group/V1/control-seal"u8.CopyTo(info); var at = "Deep/Group/V1/control-seal"u8.Length + 1;
        descriptor.Field(1).Span.CopyTo(info.AsSpan(at)); at += 16;
        BinaryPrimitives.WriteUInt64BigEndian(info.AsSpan(at), sequence); at += 8; predecessor.CopyTo(info.AsSpan(at)); at += 32;
        BinaryPrimitives.WriteUInt64BigEndian(info.AsSpan(at), expires);
        var aad = new byte[info.Length + 64]; info.CopyTo(aad, 0); descriptor.Field(8).Span.CopyTo(aad.AsSpan(info.Length)); ephemeral.CopyTo(aad, info.Length + 32);
        var secret = ScalarMult.Mult(scalar, peer); var key = new byte[32]; Span<byte> prk = stackalloc byte[64];
        try
        {
            if (secret.Length != 32 || secret.AsSpan().IndexOfAnyExcept((byte)0) < 0) throw new CryptographicException("Zero control DH forbidden.");
            HKDF.Extract(HashAlgorithmName.SHA512, secret, descriptor.ArtifactHash.Span, prk);
            HKDF.Expand(HashAlgorithmName.SHA512, prk, key, info);
            return decrypt ? SecretAeadXChaCha20Poly1305.Decrypt(input, nonce, key, aad) : SecretAeadXChaCha20Poly1305.Encrypt(input, nonce, key, aad);
        }
        finally { CryptographicOperations.ZeroMemory(prk); foreach (var bytes in new[] { secret, key, info, aad }) CryptographicOperations.ZeroMemory(bytes); }
    }
}
