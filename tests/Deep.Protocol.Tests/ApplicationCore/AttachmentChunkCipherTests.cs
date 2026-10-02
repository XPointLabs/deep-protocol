using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Sodium;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class AttachmentChunkCipherTests
{
    private static byte[] Bytes(int size, byte value) => Enumerable.Repeat(value, size).ToArray();

    [Theory]
    [InlineData(1)]
    [InlineData(262144)]
    [InlineData(262145)]
    [InlineData(26214400)]
    public void FrozenChunksRoundTripAndMatchIndependentTranscript(int total)
    {
        var network = Bytes(16, 0x11); var id = Bytes(32, 0x22); var key = Bytes(32, 0x33);
        var chunks = new List<byte[]>(); var entries = new List<Dam1ChunkEntry>();
        for (var offset = 0; offset < total; offset += 262144)
        {
            var index = checked((uint)chunks.Count);
            var plain = Bytes(Math.Min(262144, total - offset), checked((byte)(index + 1)));
            var cipher = AttachmentChunkCipher.Encrypt(network, id, key, index, (ulong)total, plain);
            Assert.Equal(plain.Length + 16, cipher.Length);
            Assert.Equal(ReferenceEncrypt(network, id, key, index, (ulong)total, plain), cipher);
            Assert.Equal(cipher, AttachmentChunkCipher.Encrypt(network, id, key, index, (ulong)total, plain));
            chunks.Add(cipher); entries.Add(new(index, (uint)cipher.Length, SHA256.HashData(cipher)));
        }
        using var manifest = ApplicationCoreCodec.AuthorDam1(network, id, Bytes(32, 0x44), key,
            (ulong)total, entries, 2_000_000_000, "image.png", "image/png");
        for (var i = 0; i < chunks.Count; i++)
        {
            var plain = AttachmentChunkCipher.Decrypt(manifest, (uint)i, chunks[i]);
            try { Assert.All(plain, value => Assert.Equal((byte)(i + 1), value)); }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
    }

    [Fact]
    public void DisposingManifestClearsOwnedKeyAndCanonicalAndRejectsUse()
    {
        using var manifest = ApplicationCoreCodec.AuthorDam1(Bytes(16, 1), Bytes(32, 2), Bytes(32, 3),
            Bytes(32, 4), 1, [new(0, 17, Bytes(32, 5))], 1, "", "");
        var key = manifest.ObjectKeySpan; var canonical = manifest.CanonicalSpan;
        manifest.Dispose();
        Assert.All(key.ToArray(), value => Assert.Equal((byte)0, value));
        Assert.All(canonical.ToArray(), value => Assert.Equal((byte)0, value));
        Assert.Throws<ObjectDisposedException>(() => manifest.ObjectKey);
        Assert.Throws<ObjectDisposedException>(() => manifest.CanonicalBytes);
        Assert.Throws<ObjectDisposedException>(() => AttachmentChunkCipher.Decrypt(manifest, 0, new byte[17]));
    }

    [Fact]
    public void ChangedCommitmentAndAeadScopeRejectWithoutReturningPlaintext()
    {
        var network = Bytes(16, 0x11); var id = Bytes(32, 0x22); var key = Bytes(32, 0x33);
        var plain = Bytes(1, 0x55);
        var cipher = AttachmentChunkCipher.Encrypt(network, id, key, 0, 1, plain);
        ParsedDam1 Manifest(byte[] net, byte[] objectId, byte[] objectKey, byte[] exact) =>
            ApplicationCoreCodec.AuthorDam1(net, objectId, Bytes(32, 0x44), objectKey, 1,
                [new(0, 17, SHA256.HashData(exact))], 2_000_000_000, "", "");
        var valid = Manifest(network, id, key, cipher);
        var changed = cipher.ToArray(); changed[^1] ^= 1;
        Assert.Throws<CryptographicException>(() => AttachmentChunkCipher.Decrypt(valid, 0, changed));
        // Even recomputing the public commitment cannot repair an AEAD forgery.
        Assert.Throws<CryptographicException>(() => AttachmentChunkCipher.Decrypt(Manifest(network, id, key, changed), 0, changed));
        foreach (var wrong in new[] { Manifest(Bytes(16, 0x12), id, key, cipher),
            Manifest(network, Bytes(32, 0x23), key, cipher), Manifest(network, id, Bytes(32, 0x34), cipher) })
            Assert.Throws<CryptographicException>(() => AttachmentChunkCipher.Decrypt(wrong, 0, cipher));
        Assert.Throws<CryptographicException>(() => AttachmentChunkCipher.Decrypt(valid, 0, cipher[..^1]));
        Assert.Throws<CryptographicException>(() => AttachmentChunkCipher.Decrypt(valid, 0, [.. cipher, 0]));
        Assert.Throws<ArgumentOutOfRangeException>(() => AttachmentChunkCipher.Decrypt(valid, 1, cipher));
    }

    [Fact]
    public void GeometryAndScopeRejectBeforeAead()
    {
        var net = Bytes(16, 1); var id = Bytes(32, 2); var key = Bytes(32, 3);
        Assert.Throws<ArgumentOutOfRangeException>(() => AttachmentChunkCipher.Encrypt(net, id, key, 0, 0, [1]));
        Assert.Throws<ArgumentOutOfRangeException>(() => AttachmentChunkCipher.Encrypt(net, id, key, 0, 26214401, [1]));
        Assert.Throws<ArgumentOutOfRangeException>(() => AttachmentChunkCipher.Encrypt(net, id, key, 100, 26214400, [1]));
        Assert.Throws<ArgumentException>(() => AttachmentChunkCipher.Encrypt(net, id, key, 0, 2, [1]));
        Assert.Throws<ArgumentException>(() => AttachmentChunkCipher.Encrypt(net, id, key, 0, 1, []));
        Assert.Throws<ArgumentException>(() => AttachmentChunkCipher.Encrypt(net[..^1], id, key, 0, 1, [1]));
        Assert.Throws<ArgumentException>(() => AttachmentChunkCipher.Encrypt(net, new byte[32], key, 0, 1, [1]));
        Assert.Throws<ArgumentException>(() => AttachmentChunkCipher.Encrypt(net, id, new byte[32], 0, 1, [1]));
        var full = Bytes(262144, 5);
        Assert.NotEqual(AttachmentChunkCipher.Encrypt(net, id, key, 0, 524288, full),
            AttachmentChunkCipher.Encrypt(net, id, key, 1, 524288, full));
        Assert.NotEqual(AttachmentChunkCipher.Encrypt(net, id, key, 0, 524288, full),
            AttachmentChunkCipher.Encrypt(net, id, key, 0, 524289, full));
    }

    // Independent frozen transcript: manual RFC5869 single-block expand and
    // explicit domain framing, not the production HKDF/nonce helpers.
    private static byte[] ReferenceEncrypt(byte[] net, byte[] id, byte[] root, uint index, ulong total, byte[] plain)
    {
        var prk = HMACSHA512.HashData(id, root);
        var label = Encoding.ASCII.GetBytes("Deep/Attachment/V1/chunk-key");
        var info = new byte[label.Length + 6]; label.CopyTo(info, 0);
        BinaryPrimitives.WriteUInt32BigEndian(info.AsSpan(label.Length + 1), index); info[^1] = 1;
        var expanded = HMACSHA512.HashData(prk, info);
        var domain = Encoding.ASCII.GetBytes("Deep/Attachment/V1/chunk-nonce");
        var frame = new byte[domain.Length + 1 + 4 + 36]; domain.CopyTo(frame, 0);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(domain.Length + 1), 36);
        id.CopyTo(frame, domain.Length + 5);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(frame.Length - 4), index);
        var aad = new byte[64]; net.CopyTo(aad, 0); id.CopyTo(aad, 16);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(48), index);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(52), (uint)plain.Length);
        BinaryPrimitives.WriteUInt64BigEndian(aad.AsSpan(56), total);
        try { return SecretAeadXChaCha20Poly1305.Encrypt(plain, SHA512.HashData(frame)[..24], expanded[..32], aad); }
        finally { CryptographicOperations.ZeroMemory(prk); CryptographicOperations.ZeroMemory(expanded); }
    }
}
