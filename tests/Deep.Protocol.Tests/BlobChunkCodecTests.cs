using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.BlobV1;

namespace Deep.Protocol.Tests;

public sealed class BlobChunkCodecTests
{
    [Fact]
    public void ExactPutGetAndBoundRepliesRoundTripWithoutPlaintextMetadata()
    {
        var cipher = Bytes(528, 0x55); using var manifest = Manifest(cipher);
        var put = BlobChunkCodec.EncodeRequest(manifest, BlobChunkOperation.Put, 0, cipher);
        using var parsed = BlobChunkCodec.DecodeRequest(put);
        Assert.Equal(cipher, parsed.Ciphertext.ToArray());
        Assert.Equal(BlobChunkStatus.Stored, BlobChunkCodec.DecodeResponse(parsed,
            BlobChunkCodec.EncodeResponse(parsed, BlobChunkStatus.Stored)).Status);
        var descriptor = parsed.Descriptor.CanonicalBytes.ToArray();
        Assert.True(descriptor.AsSpan().IndexOf(manifest.ObjectKey.Span) < 0);
        Assert.True(descriptor.AsSpan().IndexOf(manifest.BlobCapability.Span) < 0);
        Assert.True(descriptor.AsSpan().IndexOf("private-filename.dat"u8) < 0);
        using var get = BlobChunkCodec.DecodeRequest(BlobChunkCodec.EncodeRequest(manifest, BlobChunkOperation.Get, 0));
        Assert.Equal(cipher, BlobChunkCodec.DecodeResponse(get, BlobChunkCodec.EncodeResponse(get, BlobChunkStatus.Chunk, cipher)).Ciphertext.ToArray());
        Assert.Throws<CryptographicException>(() => BlobChunkCodec.EncodeResponse(get, BlobChunkStatus.Stored));
        Assert.Throws<CryptographicException>(() => BlobChunkCodec.EncodeResponse(parsed, BlobChunkStatus.Chunk, cipher));
        Assert.Throws<CryptographicException>(() => BlobChunkCodec.DecodeResponse(get, BlobChunkCodec.EncodeResponse(parsed, BlobChunkStatus.Stored)));
    }

    [Theory]
    [InlineData(0)] [InlineData(4)] [InlineData(6)] [InlineData(8)] [InlineData(9)]
    [InlineData(12)] [InlineData(16)] [InlineData(20)] [InlineData(140)] [InlineData(148)] [InlineData(154)]
    public void HostileHeaderGeometryCapabilityAndCommitmentsReject(int offset)
    {
        var cipher = Bytes(528, 0x55); using var manifest = Manifest(cipher);
        var request = BlobChunkCodec.EncodeRequest(manifest, BlobChunkOperation.Put, 0, cipher);
        request[offset] ^= 0x80;
        Assert.Throws<CryptographicException>(() => BlobChunkCodec.DecodeRequest(request));
    }

    [Fact]
    public void TruncationTrailingBodiesCorruptRepliesAndDisposedBearerReject()
    {
        var cipher = Bytes(528, 0x55); using var manifest = Manifest(cipher);
        var request = BlobChunkCodec.EncodeRequest(manifest, BlobChunkOperation.Get, 0);
        Assert.Throws<CryptographicException>(() => BlobChunkCodec.DecodeRequest(request[..^1]));
        Assert.Throws<CryptographicException>(() => BlobChunkCodec.DecodeRequest([.. request, 1]));
        using var parsed = BlobChunkCodec.DecodeRequest(request);
        var response = BlobChunkCodec.EncodeResponse(parsed, BlobChunkStatus.Chunk, cipher);
        response[^1] ^= 1;
        Assert.Throws<CryptographicException>(() => BlobChunkCodec.DecodeResponse(parsed, response));
        parsed.Dispose();
        Assert.Throws<ObjectDisposedException>(() => parsed.CanonicalBytes);
        Assert.Throws<ObjectDisposedException>(() => parsed.Ciphertext);
    }

    private static ParsedDam1 Manifest(byte[] cipher) => ApplicationCoreCodec.AuthorDam1(Bytes(16, 1), Bytes(32, 2), Bytes(32, 3), Bytes(32, 4),
        512, [new(0, 528, SHA256.HashData(cipher))], 2_000_000_000, "private-filename.dat", "application/octet-stream");
    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
}
