using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.BlobV1;

public enum BlobChunkOperation : byte { Put = 1, Get = 2 }
public enum BlobChunkStatus : byte { Stored = 1, ExactReplay = 2, Chunk = 3, Missing = 4, Expired = 5, Quota = 6, Conflict = 7 }

/// <summary>Public commitments only; never a manifest, object key or plaintext metadata.</summary>
public sealed class BlobObjectDescriptor
{
    private readonly byte[] exact;
    internal BlobObjectDescriptor(ReadOnlySpan<byte> bytes) => exact = bytes.ToArray();
    public ReadOnlyMemory<byte> CanonicalBytes => exact.ToArray();
    public ReadOnlyMemory<byte> NetworkId => exact.AsMemory(0, 16).ToArray();
    public ReadOnlyMemory<byte> ObjectId => exact.AsMemory(16, 32).ToArray();
    public ulong ExpiresAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(80));
    public ulong PlaintextBytes => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(88));
    public ushort ChunkCount => BinaryPrimitives.ReadUInt16BigEndian(exact.AsSpan(96));
    public uint ChunkBytes(uint index) { RequireIndex(index); return BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(98 + checked((int)index) * 36)); }
    public ReadOnlyMemory<byte> ChunkHash(uint index) { RequireIndex(index); return exact.AsMemory(102 + checked((int)index) * 36, 32).ToArray(); }
    internal ReadOnlySpan<byte> CapabilityHash => exact.AsSpan(48, 32);
    private void RequireIndex(uint index) { if (index >= ChunkCount) throw new ArgumentOutOfRangeException(nameof(index)); }
}

/// <summary>Owns key-bearing bearer request storage. Independent exported copies belong to their caller.</summary>
public sealed class BlobChunkRequest : IDisposable
{
    private readonly byte[] exact;
    private bool disposed;
    internal BlobChunkRequest(byte[] owned, BlobObjectDescriptor descriptor) { exact = owned; Descriptor = descriptor; }
    public BlobObjectDescriptor Descriptor { get; }
    public BlobChunkOperation Operation { get { RequireAlive(); return (BlobChunkOperation)exact[8]; } }
    public uint ChunkIndex { get { RequireAlive(); return BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(16)); } }
    public ReadOnlyMemory<byte> CanonicalBytes { get { RequireAlive(); return exact.ToArray(); } }
    public ReadOnlyMemory<byte> Ciphertext { get { RequireAlive(); return exact.AsMemory(52 + Descriptor.CanonicalBytes.Length).ToArray(); } }
    internal ReadOnlySpan<byte> Exact { get { RequireAlive(); return exact; } }
    private void RequireAlive() => ObjectDisposedException.ThrowIf(disposed, this);
    public void Dispose() { if (disposed) return; disposed = true; CryptographicOperations.ZeroMemory(exact); GC.SuppressFinalize(this); }
    ~BlobChunkRequest() => Dispose();
}

public sealed record BlobChunkResponse(BlobChunkStatus Status, ReadOnlyMemory<byte> Ciphertext);

/// <summary>DR-0141 / blob-chunk-v1.registry.json. Decode hostile bounds before copying or callbacks.</summary>
public static class BlobChunkCodec
{
    public const int MaximumRequestBytes = 265_910;
    public const int MaximumResponseBytes = 262_208;
    public const ulong MaximumRetentionSeconds = 2_592_000;

    public static BlobObjectDescriptor DescriptorFromManifest(ParsedDam1 manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var bytes = new byte[98 + checked((int)manifest.ChunkCount) * 36];
        manifest.NetworkId.Span.CopyTo(bytes); manifest.ObjectId.Span.CopyTo(bytes.AsSpan(16));
        var capability = manifest.BlobCapability.ToArray();
        try { SHA256.HashData(capability).CopyTo(bytes, 48); }
        finally { CryptographicOperations.ZeroMemory(capability); }
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(80), manifest.ExpiresAtUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(88), manifest.TotalPlaintextBytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(96), checked((ushort)manifest.ChunkCount));
        for (var i = 0; i < manifest.Chunks.Count; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(98 + i * 36), manifest.Chunks[i].CiphertextLength);
            manifest.Chunks[i].CiphertextHash.Span.CopyTo(bytes.AsSpan(102 + i * 36));
        }
        return DecodeDescriptor(bytes);
    }

    public static BlobObjectDescriptor DecodeDescriptor(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 134 or > 3698) throw Invalid();
        var count = BinaryPrimitives.ReadUInt16BigEndian(bytes[96..]);
        var total = BinaryPrimitives.ReadUInt64BigEndian(bytes[88..]);
        if (count is < 1 or > 100 || bytes.Length != 98 + count * 36 || total is < 1 or > 26_214_400 ||
            (total + 262143) / 262144 != count || BinaryPrimitives.ReadUInt64BigEndian(bytes[80..]) == 0 ||
            Zero(bytes[..16]) || Zero(bytes.Slice(16, 32)) || Zero(bytes.Slice(48, 32))) throw Invalid();
        for (var i = 0; i < count; i++)
        {
            var length = (i == count - 1 ? total - (ulong)i * 262144 : 262144) + 16;
            if (BinaryPrimitives.ReadUInt32BigEndian(bytes[(98 + i * 36)..]) != length || Zero(bytes.Slice(102 + i * 36, 32))) throw Invalid();
        }
        return new(bytes);
    }

    public static byte[] EncodeRequest(ParsedDam1 manifest, BlobChunkOperation operation, uint index, ReadOnlySpan<byte> ciphertext = default)
    {
        if (ciphertext.Length > 262_160) throw Invalid();
        var descriptor = DescriptorFromManifest(manifest).CanonicalBytes;
        var capability = manifest.BlobCapability.ToArray();
        var result = new byte[52 + descriptor.Length + ciphertext.Length];
        try
        {
            ProtocolMagicBytes.XBQ1.CopyTo(result); BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), 0x0301); result[8] = (byte)operation;
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(12), checked((uint)descriptor.Length));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(16), index); capability.CopyTo(result, 20);
            descriptor.Span.CopyTo(result.AsSpan(52)); ciphertext.CopyTo(result.AsSpan(52 + descriptor.Length));
            using var verified = DecodeRequest(result); return result;
        }
        catch { CryptographicOperations.ZeroMemory(result); throw; }
        finally { CryptographicOperations.ZeroMemory(capability); }
    }

    public static BlobChunkRequest DecodeRequest(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 186 or > MaximumRequestBytes || !bytes[..4].SequenceEqual(ProtocolMagicBytes.XBQ1) ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]) != 1 || BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]) != 0x0301 ||
            bytes[8] is < 1 or > 2 || !Zero(bytes.Slice(9, 3)) || Zero(bytes.Slice(20, 32))) throw Invalid();
        var length = BinaryPrimitives.ReadUInt32BigEndian(bytes[12..]);
        if (length is < 134 or > 3698 || length > bytes.Length - 52) throw Invalid();
        var descriptor = DecodeDescriptor(bytes.Slice(52, (int)length));
        var index = BinaryPrimitives.ReadUInt32BigEndian(bytes[16..]);
        if (index >= descriptor.ChunkCount || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes.Slice(20, 32)), descriptor.CapabilityHash)) throw Invalid();
        var body = bytes[(52 + (int)length)..];
        if (bytes[8] == (byte)BlobChunkOperation.Get ? body.Length != 0 :
            body.Length != descriptor.ChunkBytes(index) || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(body), descriptor.ChunkHash(index).Span)) throw Invalid();
        return new(bytes.ToArray(), descriptor);
    }

    public static byte[] EncodeResponse(BlobChunkRequest request, BlobChunkStatus status, ReadOnlySpan<byte> ciphertext = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (ciphertext.Length > MaximumResponseBytes - 48) throw Invalid();
        var result = new byte[48 + ciphertext.Length];
        ProtocolMagicBytes.XBS1.CopyTo(result); BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), 0x0301); result[8] = (byte)request.Operation; result[9] = (byte)status;
        SHA256.HashData(request.Exact).CopyTo(result, 12); BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(44), checked((uint)ciphertext.Length));
        ciphertext.CopyTo(result.AsSpan(48)); _ = DecodeResponse(request, result); return result;
    }

    public static BlobChunkResponse DecodeResponse(BlobChunkRequest request, ReadOnlySpan<byte> bytes)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (bytes.Length is < 48 or > MaximumResponseBytes || !bytes[..4].SequenceEqual(ProtocolMagicBytes.XBS1) ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]) != 1 || BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]) != 0x0301 ||
            bytes[8] != (byte)request.Operation || bytes[9] is < 1 or > 7 || !Zero(bytes.Slice(10, 2)) ||
            BinaryPrimitives.ReadUInt32BigEndian(bytes[44..]) != bytes.Length - 48 ||
            !CryptographicOperations.FixedTimeEquals(bytes.Slice(12, 32), SHA256.HashData(request.Exact))) throw Invalid();
        var status = (BlobChunkStatus)bytes[9]; var body = bytes[48..];
        if (status == BlobChunkStatus.Chunk)
        {
            if (request.Operation != BlobChunkOperation.Get || body.Length != request.Descriptor.ChunkBytes(request.ChunkIndex) ||
                !CryptographicOperations.FixedTimeEquals(SHA256.HashData(body), request.Descriptor.ChunkHash(request.ChunkIndex).Span)) throw Invalid();
        }
        else if (body.Length != 0 || (status is BlobChunkStatus.Stored or BlobChunkStatus.ExactReplay) && request.Operation != BlobChunkOperation.Put ||
                 status == BlobChunkStatus.Missing && request.Operation != BlobChunkOperation.Get) throw Invalid();
        return new(status, body.ToArray());
    }
    private static bool Zero(ReadOnlySpan<byte> bytes) => bytes.IndexOfAnyExcept((byte)0) < 0;
    private static CryptographicException Invalid() => new("Noncanonical or unbound BLOB chunk record.");
}
