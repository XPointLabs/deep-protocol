using System.Buffers.Binary;
using System.Text;

namespace Deep.Protocol.ApplicationCore;

public sealed class Dam1ChunkEntry
{
    private readonly byte[] ciphertextHash;

    public Dam1ChunkEntry(uint index, uint ciphertextLength, ReadOnlySpan<byte> ciphertextHash32)
    {
        if (ciphertextHash32.Length != 32)
            throw new ArgumentException("A DAM1 ciphertext hash must be exactly 32 bytes.", nameof(ciphertextHash32));
        Index = index;
        CiphertextLength = ciphertextLength;
        ciphertextHash = ciphertextHash32.ToArray();
    }

    public uint Index { get; }
    public uint CiphertextLength { get; }
    public ReadOnlyMemory<byte> CiphertextHash => ciphertextHash.ToArray();
    internal ReadOnlySpan<byte> CiphertextHashSpan => ciphertextHash;
}

public sealed class ParsedDam1 : ParsedApplicationCoreRecord
{
    private readonly byte[] networkId;
    private readonly byte[] objectId;
    private readonly byte[] blobCapability;
    private readonly byte[] objectKey;
    private readonly byte[] manifestHash;
    private readonly Dam1ChunkEntry[] chunks;

    internal ParsedDam1(
        byte[] canonical,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> objectId,
        ReadOnlySpan<byte> blobCapability,
        ReadOnlySpan<byte> objectKey,
        ulong totalPlaintextBytes,
        uint finalChunkPlaintextBytes,
        ushort ciphertextCapacityBucketId,
        ulong expiresAtUnixSeconds,
        string filename,
        string mediaType,
        Dam1ChunkEntry[] chunks)
        : base(ProtocolMagic.DAM1, canonical)
    {
        this.networkId = networkId.ToArray();
        this.objectId = objectId.ToArray();
        this.blobCapability = blobCapability.ToArray();
        this.objectKey = objectKey.ToArray();
        TotalPlaintextBytes = totalPlaintextBytes;
        FinalChunkPlaintextBytes = finalChunkPlaintextBytes;
        CiphertextCapacityBucketId = ciphertextCapacityBucketId;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
        Filename = filename;
        MediaType = mediaType;
        this.chunks = chunks;
        manifestHash = ApplicationCoreFormat.Sha256Domain("Deep/Attachment/V1/manifest", canonical);
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> ObjectId => objectId.ToArray();
    public ReadOnlyMemory<byte> BlobCapability => blobCapability.ToArray();
    public ReadOnlyMemory<byte> ObjectKey => objectKey.ToArray();
    public ulong TotalPlaintextBytes { get; }
    public const uint NonFinalChunkPlaintextBytes = 262_144;
    public uint ChunkCount => checked((uint)chunks.Length);
    public uint FinalChunkPlaintextBytes { get; }
    public IReadOnlyList<Dam1ChunkEntry> Chunks => Array.AsReadOnly(chunks);
    public ushort CiphertextCapacityBucketId { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public string Filename { get; }
    public string MediaType { get; }
    public ReadOnlyMemory<byte> ManifestHash => manifestHash.ToArray();
}

public static partial class ApplicationCoreCodec
{
    private static ReadOnlySpan<byte> DamMagic => ProtocolMagicBytes.DAM1;
    private const uint DamChunkPlaintextBytes = 262_144;
    private const ulong DamMaximumPlaintextBytes = 26_214_400;

    public static ParsedDam1 AuthorDam1(
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> objectId32,
        ReadOnlySpan<byte> blobCapability32,
        ReadOnlySpan<byte> objectKey32,
        ulong totalPlaintextBytes,
        IReadOnlyList<Dam1ChunkEntry> chunks,
        ulong expiresAtUnixSeconds,
        string filename,
        string mediaType)
    {
        RequireLength(networkId16, 16, "network ID");
        RequireNonzeroId(objectId32, "attachment object ID");
        RequireNonzeroId(blobCapability32, "blob capability");
        RequireNonzeroId(objectKey32, "attachment object key");
        ArgumentNullException.ThrowIfNull(chunks);

        var filenameBytes = EncodeDamFilename(filename);
        var mediaTypeBytes = EncodeDamMediaType(mediaType);
        if (chunks.Count is < 1 or > 100)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "DAM1 contains 1 through 100 chunks.");

        var finalBytes = ExpectedFinalChunkBytes(totalPlaintextBytes, chunks.Count);
        var bucket = ExpectedBucket(chunks.Count);
        var chunkBytes = new byte[checked(chunks.Count * 40)];
        for (var index = 0; index < chunks.Count; index++)
        {
            ArgumentNullException.ThrowIfNull(chunks[index]);
            var entry = chunks[index];
            if (entry.Index != (uint)index)
                PayloadInvalid(ApplicationCoreRejection.InvalidOrdering, "DAM1 chunk indexes must be exactly 0..N-1.");
            var plaintextLength = index == chunks.Count - 1 ? finalBytes : DamChunkPlaintextBytes;
            if (entry.CiphertextLength != checked(plaintextLength + 16))
                PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch,
                    "DAM1 ciphertext length must equal plaintext length plus the AEAD tag.");
            var row = chunkBytes.AsSpan(index * 40, 40);
            BinaryPrimitives.WriteUInt32BigEndian(row, entry.Index);
            BinaryPrimitives.WriteUInt32BigEndian(row[4..], entry.CiphertextLength);
            entry.CiphertextHashSpan.CopyTo(row[8..]);
        }

        Span<byte> totalBytes = stackalloc byte[8];
        Span<byte> chunkSize = stackalloc byte[4];
        Span<byte> chunkCount = stackalloc byte[4];
        Span<byte> finalChunk = stackalloc byte[4];
        Span<byte> entryCount = stackalloc byte[4];
        Span<byte> bucketBytes = stackalloc byte[2];
        Span<byte> expiryBytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(totalBytes, totalPlaintextBytes);
        BinaryPrimitives.WriteUInt32BigEndian(chunkSize, DamChunkPlaintextBytes);
        BinaryPrimitives.WriteUInt32BigEndian(chunkCount, checked((uint)chunks.Count));
        BinaryPrimitives.WriteUInt32BigEndian(finalChunk, finalBytes);
        BinaryPrimitives.WriteUInt32BigEndian(entryCount, checked((uint)chunks.Count));
        BinaryPrimitives.WriteUInt16BigEndian(bucketBytes, bucket);
        BinaryPrimitives.WriteUInt64BigEndian(expiryBytes, expiresAtUnixSeconds);

        var canonical = AllocateRecord(14, checked(146 + chunkBytes.Length + filenameBytes.Length + mediaTypeBytes.Length));
        var writer = new ApplicationRecordWriter(canonical, DamMagic, 14);
        writer.Write(1, networkId16);
        writer.Write(2, objectId32);
        writer.Write(3, blobCapability32);
        writer.Write(4, objectKey32);
        writer.Write(5, totalBytes);
        writer.Write(6, chunkSize);
        writer.Write(7, chunkCount);
        writer.Write(8, finalChunk);
        writer.Write(9, entryCount);
        writer.Write(10, chunkBytes);
        writer.Write(11, bucketBytes);
        writer.Write(12, expiryBytes);
        writer.Write(13, filenameBytes);
        writer.Write(14, mediaTypeBytes);
        writer.Complete();
        return DecodeDam1(canonical);
    }

    public static ParsedDam1 DecodeDam1(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[14];
        ApplicationCoreFormat.Preflight(canonical, DamMagic, 14, 310, 4653, fields);
        Exact(fields, 16, 32, 32, 32, 8, 4, 4, 4, 4, -1, 2, 8, -1, -1);
        if (fields[12].Length > 255 || fields[13].Length > 128)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "DAM1 text fields exceed their frozen bounds.");

        var network = Field(canonical, fields, 1);
        var objectId = Field(canonical, fields, 2);
        var capability = Field(canonical, fields, 3);
        var objectKey = Field(canonical, fields, 4);
        ApplicationCoreFormat.NonZero(objectId, "attachment object ID");
        ApplicationCoreFormat.NonZero(capability, "blob capability");
        ApplicationCoreFormat.NonZero(objectKey, "attachment object key");

        var total = U64(Field(canonical, fields, 5));
        if (U32(Field(canonical, fields, 6)) != DamChunkPlaintextBytes)
            PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch, "DAM1 non-final chunk size is not 262144.");
        var count = U32(Field(canonical, fields, 7));
        var finalBytes = U32(Field(canonical, fields, 8));
        var entryCount = U32(Field(canonical, fields, 9));
        if (count is < 1 or > 100 || entryCount != count || count > int.MaxValue)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "DAM1 chunk counts are invalid or disagree.");
        var countInt = checked((int)count);
        if (fields[9].Length != checked(countInt * 40) ||
            canonical.Length != checked(270 + fields[9].Length + fields[12].Length + fields[13].Length))
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "DAM1 list length or exact total-size formula disagrees.");
        var expectedFinal = ExpectedFinalChunkBytes(total, countInt);
        if (finalBytes != expectedFinal)
            PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch, "DAM1 final chunk length disagrees with total plaintext.");
        var bucket = U16(Field(canonical, fields, 11));
        if (bucket != ExpectedBucket(countInt))
            PayloadInvalid(ApplicationCoreRejection.InvalidEnum, "DAM1 capacity bucket is unknown or non-minimal.");

        var rows = Field(canonical, fields, 10);
        var chunks = new Dam1ChunkEntry[countInt];
        for (var index = 0; index < countInt; index++)
        {
            var row = rows.Slice(index * 40, 40);
            var encodedIndex = BinaryPrimitives.ReadUInt32BigEndian(row);
            var ciphertextLength = BinaryPrimitives.ReadUInt32BigEndian(row[4..]);
            var plaintextLength = index == countInt - 1 ? expectedFinal : DamChunkPlaintextBytes;
            if (encodedIndex != (uint)index)
                PayloadInvalid(ApplicationCoreRejection.InvalidOrdering, "DAM1 chunk indexes must be exactly 0..N-1.");
            if (ciphertextLength != checked(plaintextLength + 16))
                PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch,
                    "DAM1 ciphertext length must equal plaintext length plus the AEAD tag.");
            chunks[index] = new Dam1ChunkEntry(encodedIndex, ciphertextLength, row[8..]);
        }

        var filename = DecodeDamFilename(Field(canonical, fields, 13));
        var mediaType = DecodeDamMediaType(Field(canonical, fields, 14));
        var owned = canonical.ToArray();
        return new ParsedDam1(owned, network, objectId, capability, objectKey, total, finalBytes,
            bucket, U64(Field(canonical, fields, 12)), filename, mediaType, chunks);
    }

    private static uint ExpectedFinalChunkBytes(ulong totalPlaintextBytes, int count)
    {
        if (totalPlaintextBytes is < 1 or > DamMaximumPlaintextBytes)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "DAM1 total plaintext is outside 1..26214400.");
        var expectedCount = checked((int)((totalPlaintextBytes + DamChunkPlaintextBytes - 1) / DamChunkPlaintextBytes));
        if (count != expectedCount)
            PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch, "DAM1 chunk count is not ceil(total/262144).");
        return checked((uint)(totalPlaintextBytes - (ulong)DamChunkPlaintextBytes * (ulong)(count - 1)));
    }

    private static ushort ExpectedBucket(int count) => count switch
    {
        <= 1 => 1,
        <= 4 => 2,
        <= 16 => 3,
        <= 64 => 4,
        <= 100 => 5,
        _ => throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.TypedPayload,
            ApplicationCoreRejection.InvalidFieldLength, "DAM1 has too many chunks."),
    };

    private static uint U32(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt32BigEndian(value);

    private static byte[] EncodeDamFilename(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        byte[] encoded;
        try { encoded = ApplicationCoreFormat.StrictUtf8.GetBytes(value); }
        catch (EncoderFallbackException exception)
        {
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.TypedPayload,
                ApplicationCoreRejection.NonCanonicalText, "DAM1 filename contains invalid UTF-16.", exception);
        }
        _ = DecodeDamFilename(encoded);
        return encoded;
    }

    private static string DecodeDamFilename(ReadOnlySpan<byte> encoded)
    {
        var value = ApplicationCoreFormat.DecodeCanonicalText(encoded, 0, 255, oneGrapheme: false);
        if (value.Any(static c => char.IsControl(c) || c is '/' or '\\') ||
            (value.Length != 0 && !value.Any(static c => !char.IsWhiteSpace(c))))
            PayloadInvalid(ApplicationCoreRejection.NonCanonicalText,
                "DAM1 filename contains a control/separator or consists only of whitespace.");
        return value;
    }

    private static byte[] EncodeDamMediaType(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Any(static c => c > 0x7f))
            PayloadInvalid(ApplicationCoreRejection.NonCanonicalText, "DAM1 media type must be ASCII.");
        var encoded = Encoding.ASCII.GetBytes(value);
        _ = DecodeDamMediaType(encoded);
        return encoded;
    }

    private static string DecodeDamMediaType(ReadOnlySpan<byte> encoded)
    {
        if (encoded.IsEmpty)
            return string.Empty;
        if (encoded.Length is < 3 or > 128)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "DAM1 media type length is outside 3..128.");
        var slash = encoded.IndexOf((byte)'/');
        if (slash <= 0 || slash != encoded.LastIndexOf((byte)'/') || slash == encoded.Length - 1)
            PayloadInvalid(ApplicationCoreRejection.NonCanonicalText, "DAM1 media type must be lowercase type/subtype.");
        for (var index = 0; index < encoded.Length; index++)
        {
            if (index == slash)
                continue;
            var value = encoded[index];
            var allowed = value is >= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9' ||
                value is (byte)'!' or (byte)'#' or (byte)'$' or (byte)'&' or (byte)'^' or
                    (byte)'_' or (byte)'.' or (byte)'+' or (byte)'-';
            if (!allowed)
                PayloadInvalid(ApplicationCoreRejection.NonCanonicalText,
                    "DAM1 media type contains an unregistered character.");
        }
        return Encoding.ASCII.GetString(encoded);
    }
}
