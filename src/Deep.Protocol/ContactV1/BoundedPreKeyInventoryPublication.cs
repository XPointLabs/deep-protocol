using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV1;

public enum Xpp1BoundedPhase : byte
{
    Manifest = 1,
    Chunk = 2,
    Commit = 3,
}

/// <summary>One exact, bounded XPP1 privacy request. Instances are minted only by the canonical codec.</summary>
public abstract class Xpp1BoundedRequest
{
    private readonly byte[] _canonical;
    private readonly byte[][] _fields;

    private protected Xpp1BoundedRequest(byte[] canonical, byte[][] fields)
    {
        _canonical = canonical;
        _fields = fields;
    }

    public Xpp1BoundedPhase Phase => (Xpp1BoundedPhase)_fields[0][0];
    public ReadOnlyMemory<byte> NetworkId => Field(2);
    public ReadOnlyMemory<byte> PublicationOperationId => Field(3);
    public ReadOnlyMemory<byte> ViewHash => Field(4);
    public ReadOnlyMemory<byte> PlacementHash => Field(5);
    public ulong IssuedAtUnixSeconds => PreKeyInventoryWire.ReadU64(FieldSpan(6));
    public ulong ExpiresAtUnixSeconds => PreKeyInventoryWire.ReadU64(FieldSpan(7));
    public ReadOnlyMemory<byte> PublicationHash => Field(8);
    public ReadOnlyMemory<byte> Xpi1Hash => Field(10);
    public ulong InventoryTotalLength => PreKeyInventoryWire.ReadU64(FieldSpan(11));
    public ReadOnlyMemory<byte> InventoryHash => Field(12);
    public ushort ChunkCount => PreKeyInventoryWire.ReadU16(FieldSpan(13));
    public ushort ChunkIndex => PreKeyInventoryWire.ReadU16(FieldSpan(14));
    public ReadOnlyMemory<byte> ChunkHash => Field(15);
    public ReadOnlyMemory<byte> CanonicalBytes => _canonical.ToArray();
    public ReadOnlyMemory<byte> RequestHash => Xpp1BoundedCodec.ComputeRequestHash(_canonical);

    internal ReadOnlySpan<byte> FieldSpan(int tag) => _fields[tag - 1];
    private ReadOnlyMemory<byte> Field(int tag) => _fields[tag - 1].ToArray();
}

public sealed class Xpp1ManifestRequest : Xpp1BoundedRequest
{
    internal Xpp1ManifestRequest(byte[] canonical, byte[][] fields, Xpi1Record manifest, Xpp1ChunkDescriptor[] descriptors)
        : base(canonical, fields)
    {
        Manifest = manifest;
        ChunkDescriptors = Array.AsReadOnly(descriptors);
    }

    public Xpi1Record Manifest { get; }
    public IReadOnlyList<Xpp1ChunkDescriptor> ChunkDescriptors { get; }
    public ReadOnlyMemory<byte> EpochJournalKey => Xpp1BoundedCodec.ComputeEpochJournalKey(Manifest);
}

public sealed class Xpp1ChunkRequest : Xpp1BoundedRequest
{
    private readonly byte[] _payload;

    internal Xpp1ChunkRequest(byte[] canonical, byte[][] fields) : base(canonical, fields) =>
        _payload = fields[15].ToArray();

    public ulong ChunkOffset => checked((ulong)ChunkIndex * Xpp1BoundedCodec.MaximumChunkPayloadBytes);
    public ReadOnlyMemory<byte> Payload => _payload.ToArray();
}

public sealed class Xpp1CommitRequest : Xpp1BoundedRequest
{
    internal Xpp1CommitRequest(byte[] canonical, byte[][] fields) : base(canonical, fields) { }
}

public sealed class Xpp1ChunkDescriptor
{
    private readonly byte[] _hash;

    internal Xpp1ChunkDescriptor(ushort index, uint length, ReadOnlySpan<byte> hash)
    {
        Index = index;
        Length = length;
        _hash = hash.ToArray();
    }

    public ushort Index { get; }
    public uint Length { get; }
    public ReadOnlyMemory<byte> Hash => _hash.ToArray();
}

public static class Xpp1BoundedCodec
{
    // The production replica RPC envelope is capped at 70,400 bytes. Keep the
    // exact canonical XPP1 request below both that ceiling and the 1 MiB ONION
    // limit without changing either transport limit.
    public const int MaximumChunkPayloadBytes = 64 * 1024;
    public const int MaximumCanonicalRequestBytes = 65_945;
    public const int MaximumChunkCount = 128;
    public const ushort NonChunkIndex = ushort.MaxValue;
    public const string RequestHashDomain = "Deep/ContactResolver/V1/bounded-prekey-publication-request";
    public const string InventoryHashDomain = "Deep/ContactResolver/V1/prekey-inventory-stream";
    public const string ChunkHashDomain = "Deep/ContactResolver/V1/prekey-inventory-chunk";
    public const string PublicationHashDomain = "Deep/ContactResolver/V1/bounded-prekey-publication";
    public const string EpochJournalKeyDomain = "Deep/ContactResolver/V1/prekey-inventory-epoch-journal";

    private const int MinimumCanonicalRequestBytes = 409;
    private const int LogicalXpp1FixedBytes = 692;
    private const int MinimumInventoryBytes = Xpp1Codec.MinimumTotalBytes - LogicalXpp1FixedBytes;
    private const int MaximumInventoryBytes = Xpp1Codec.MaximumTotalBytes - LogicalXpp1FixedBytes;
    private static readonly int[] FieldLengths = [1, 16, 32, 32, 32, 8, 8, 32, -1, 32, 8, 32, 2, 2, 32, -1];

    public static Xpp1BoundedRequest Decode(ReadOnlySpan<byte> canonical)
    {
        var layout = PreKeyInventoryWire.Preflight(
            canonical, ProtocolMagic.XPP1, FieldLengths,
            MinimumCanonicalRequestBytes, MaximumCanonicalRequestBytes);
        for (var tag = 2; tag <= 5; tag++) PreKeyInventoryWire.RequireNonZero(layout.Value(canonical, tag), $"Xpp1BoundedTag{tag}");
        for (var tag = 8; tag <= 12; tag++)
            if (tag != 9 && tag != 11) PreKeyInventoryWire.RequireNonZero(layout.Value(canonical, tag), $"Xpp1BoundedTag{tag}");

        var phase = (Xpp1BoundedPhase)layout.Value(canonical, 1)[0];
        if (phase is not (Xpp1BoundedPhase.Manifest or Xpp1BoundedPhase.Chunk or Xpp1BoundedPhase.Commit))
            Reject("Xpp1BoundedPhaseInvalid");
        var issuedAt = PreKeyInventoryWire.ReadU64(layout.Value(canonical, 6));
        var expiresAt = PreKeyInventoryWire.ReadU64(layout.Value(canonical, 7));
        var totalLength = PreKeyInventoryWire.ReadU64(layout.Value(canonical, 11));
        var chunkCount = PreKeyInventoryWire.ReadU16(layout.Value(canonical, 13));
        var chunkIndex = PreKeyInventoryWire.ReadU16(layout.Value(canonical, 14));
        if (issuedAt >= expiresAt) Reject("Xpp1BoundedTimeInvalid");
        if (totalLength is < MinimumInventoryBytes or > MaximumInventoryBytes) Reject("Xpp1BoundedInventoryLengthInvalid");
        var expectedCount = checked((ushort)((totalLength + MaximumChunkPayloadBytes - 1) / MaximumChunkPayloadBytes));
        if (chunkCount != expectedCount || chunkCount is 0 or > MaximumChunkCount) Reject("Xpp1BoundedChunkCountInvalid");

        var owned = canonical.ToArray();
        var ownedLayout = PreKeyInventoryWire.Preflight(
            owned, ProtocolMagic.XPP1, FieldLengths,
            MinimumCanonicalRequestBytes, MaximumCanonicalRequestBytes);
        var fields = Enumerable.Range(1, FieldLengths.Length)
            .Select(tag => ownedLayout.Value(owned, tag).ToArray()).ToArray();

        if (phase == Xpp1BoundedPhase.Manifest)
        {
            if (chunkIndex != NonChunkIndex || !PreKeyInventoryWire.IsZero(fields[14]))
                Reject("Xpp1BoundedManifestChunkFieldsInvalid");
            var manifest = Xpi1Codec.Decode(fields[8]);
            if (!CryptographicOperations.FixedTimeEquals(manifest.Xpi1Hash.Span, fields[9]))
                Reject("Xpp1BoundedXpi1HashMismatch");
            var descriptors = DecodeDescriptors(fields[15], chunkCount, totalLength);
            var expectedPublicationHash = ComputePublicationHash(fields, fields[15]);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(expectedPublicationHash, fields[7]))
                    Reject("Xpp1BoundedPublicationHashMismatch");
            }
            finally { CryptographicOperations.ZeroMemory(expectedPublicationHash); }
            return new Xpp1ManifestRequest(owned, fields, manifest, descriptors);
        }

        if (fields[8].Length != 0) Reject("Xpp1BoundedUnexpectedXpi1");
        if (phase == Xpp1BoundedPhase.Commit)
        {
            if (chunkIndex != NonChunkIndex || !PreKeyInventoryWire.IsZero(fields[14]) || fields[15].Length != 0)
                Reject("Xpp1BoundedCommitShapeInvalid");
            return new Xpp1CommitRequest(owned, fields);
        }

        if (chunkIndex >= chunkCount) Reject("Xpp1BoundedChunkIndexInvalid");
        var expectedLength = ChunkLength(totalLength, chunkIndex, chunkCount);
        if (fields[15].Length != expectedLength) Reject("Xpp1BoundedChunkLengthInvalid");
        var expectedChunkHash = ComputeChunkHash(chunkIndex, fields[15]);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(expectedChunkHash, fields[14]))
                Reject("Xpp1BoundedChunkHashMismatch");
        }
        finally { CryptographicOperations.ZeroMemory(expectedChunkHash); }
        return new Xpp1ChunkRequest(owned, fields);
    }

    public static byte[] ComputeRequestHash(ReadOnlySpan<byte> exactRequest)
    {
        _ = Decode(exactRequest);
        return ContactCodec.Sha256Domain(RequestHashDomain, exactRequest);
    }

    internal static byte[] Encode(
        Xpp1BoundedPhase phase,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> viewHash,
        ReadOnlySpan<byte> placementHash,
        ulong issuedAt,
        ulong expiresAt,
        ReadOnlySpan<byte> publicationHash,
        ReadOnlySpan<byte> exactXpi1,
        ReadOnlySpan<byte> xpi1Hash,
        ulong inventoryLength,
        ReadOnlySpan<byte> inventoryHash,
        ushort chunkCount,
        ushort chunkIndex,
        ReadOnlySpan<byte> chunkHash,
        ReadOnlySpan<byte> payload)
    {
        var fields = new (ushort Tag, byte[] Value)[]
        {
            (1, [(byte)phase]), (2, networkId.ToArray()), (3, operationId.ToArray()),
            (4, viewHash.ToArray()), (5, placementHash.ToArray()), (6, PreKeyInventoryWire.U64(issuedAt)),
            (7, PreKeyInventoryWire.U64(expiresAt)), (8, publicationHash.ToArray()), (9, exactXpi1.ToArray()),
            (10, xpi1Hash.ToArray()), (11, PreKeyInventoryWire.U64(inventoryLength)), (12, inventoryHash.ToArray()),
            (13, PreKeyInventoryWire.U16(chunkCount)), (14, PreKeyInventoryWire.U16(chunkIndex)),
            (15, chunkHash.ToArray()), (16, payload.ToArray()),
        };
        return PreKeyInventoryWire.Encode(ProtocolMagic.XPP1, fields, MaximumCanonicalRequestBytes);
    }

    internal static byte[] EncodeDescriptors(IReadOnlyList<Xpp1ChunkDescriptor> descriptors)
    {
        var output = new byte[checked(descriptors.Count * 36)];
        for (var index = 0; index < descriptors.Count; index++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(index * 36), descriptors[index].Length);
            descriptors[index].Hash.Span.CopyTo(output.AsSpan(index * 36 + 4));
        }
        return output;
    }

    internal static byte[] ComputePublicationHash(byte[][] fields, ReadOnlySpan<byte> descriptors) =>
        ContactCodec.Sha256Domain(PublicationHashDomain, Join(
            fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[9], fields[10],
            fields[11], fields[12], descriptors.ToArray()));

    internal static byte[] ComputePublicationHash(
        ReadOnlySpan<byte> networkId, ReadOnlySpan<byte> operationId, ReadOnlySpan<byte> viewHash,
        ReadOnlySpan<byte> placementHash, ulong issuedAt, ulong expiresAt, ReadOnlySpan<byte> xpi1Hash,
        ulong inventoryLength, ReadOnlySpan<byte> inventoryHash, ushort chunkCount, ReadOnlySpan<byte> descriptors) =>
        ContactCodec.Sha256Domain(PublicationHashDomain, Join(
            networkId.ToArray(), operationId.ToArray(), viewHash.ToArray(), placementHash.ToArray(),
            PreKeyInventoryWire.U64(issuedAt), PreKeyInventoryWire.U64(expiresAt), xpi1Hash.ToArray(),
            PreKeyInventoryWire.U64(inventoryLength), inventoryHash.ToArray(), PreKeyInventoryWire.U16(chunkCount),
            descriptors.ToArray()));

    internal static byte[] ComputeChunkHash(ushort index, ReadOnlySpan<byte> payload) =>
        ContactCodec.Sha256Domain(ChunkHashDomain, Join(PreKeyInventoryWire.U16(index), payload.ToArray()));

    internal static byte[] ComputeEpochJournalKey(Xpi1Record manifest) => ContactCodec.Sha256Domain(
        EpochJournalKeyDomain, Join(
            manifest.NetworkId.ToArray(), manifest.ServiceCapability.ToArray(),
            PreKeyInventoryWire.U64(manifest.ServiceGeneration), PreKeyInventoryWire.U64(manifest.InventoryEpoch)));

    internal static int ChunkLength(ulong totalLength, ushort index, ushort count)
    {
        if (index >= count) throw new ArgumentOutOfRangeException(nameof(index));
        var offset = checked((ulong)index * MaximumChunkPayloadBytes);
        return checked((int)Math.Min((ulong)MaximumChunkPayloadBytes, totalLength - offset));
    }

    private static Xpp1ChunkDescriptor[] DecodeDescriptors(ReadOnlySpan<byte> encoded, ushort count, ulong totalLength)
    {
        if (encoded.Length != count * 36) Reject("Xpp1BoundedDescriptorLengthInvalid");
        var output = new Xpp1ChunkDescriptor[count];
        ulong sum = 0;
        for (ushort index = 0; index < count; index++)
        {
            var row = encoded.Slice(index * 36, 36);
            var length = BinaryPrimitives.ReadUInt32BigEndian(row);
            if (length != ChunkLength(totalLength, index, count) || PreKeyInventoryWire.IsZero(row[4..]))
                Reject("Xpp1BoundedDescriptorInvalid");
            sum = checked(sum + length);
            output[index] = new Xpp1ChunkDescriptor(index, length, row[4..]);
        }
        if (sum != totalLength) Reject("Xpp1BoundedDescriptorTotalMismatch");
        return output;
    }

    private static byte[] Join(params byte[][] values)
    {
        var output = new byte[checked(values.Sum(static value => value.Length))];
        var offset = 0;
        foreach (var value in values) { value.CopyTo(output, offset); offset += value.Length; }
        return output;
    }

    [DoesNotReturn]
    private static void Reject(string code) => PreKeyInventoryWire.Reject(ContactValidationStage.Scalar, code);
}

/// <summary>Deterministic client-side operation material suitable for a durable sequential journal.</summary>
public sealed class BoundedPreKeyInventoryPublication
{
    private readonly Xpp1ChunkRequest[] _chunks;
    private readonly Xpp1BoundedRequest[] _ordered;

    private BoundedPreKeyInventoryPublication(
        Xpp1Record logicalPublication,
        Xpp1ManifestRequest manifest,
        Xpp1ChunkRequest[] chunks,
        Xpp1CommitRequest commit)
    {
        LogicalPublication = logicalPublication;
        ManifestRequest = manifest;
        _chunks = chunks;
        CommitRequest = commit;
        _ordered = [manifest, .. chunks, commit];
    }

    public Xpp1ManifestRequest ManifestRequest { get; }
    public IReadOnlyList<Xpp1ChunkRequest> ChunkRequests => Array.AsReadOnly(_chunks);
    public Xpp1CommitRequest CommitRequest { get; }
    public IReadOnlyList<Xpp1BoundedRequest> OrderedRequests => Array.AsReadOnly(_ordered);
    public ReadOnlyMemory<byte> PublicationHash => ManifestRequest.PublicationHash;
    public ReadOnlyMemory<byte> EpochJournalKey => ManifestRequest.EpochJournalKey;
    internal Xpp1Record LogicalPublication { get; }

    public static BoundedPreKeyInventoryPublication Create(
        Xpp1Record logicalPublication,
        ReadOnlySpan<byte> viewHash32,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(logicalPublication);
        if (viewHash32.Length != 32 || PreKeyInventoryWire.IsZero(viewHash32))
            throw new ArgumentException("The verified view hash must be nonzero 32 bytes.", nameof(viewHash32));
        if (issuedAtUnixSeconds >= expiresAtUnixSeconds ||
            issuedAtUnixSeconds < logicalPublication.Manifest.IssuedAtUnixSeconds ||
            expiresAtUnixSeconds > logicalPublication.Manifest.ExpiresAtUnixSeconds)
            throw new ArgumentOutOfRangeException(nameof(expiresAtUnixSeconds), "The request lifetime must be non-empty and contained by XPI1.");

        var inventory = EncodeInventory(logicalPublication);
        var inventoryHash = ContactCodec.Sha256Domain(Xpp1BoundedCodec.InventoryHashDomain, inventory);
        var count = checked((ushort)((inventory.Length + Xpp1BoundedCodec.MaximumChunkPayloadBytes - 1) /
            Xpp1BoundedCodec.MaximumChunkPayloadBytes));
        var descriptors = new Xpp1ChunkDescriptor[count];
        var payloads = new byte[count][];
        for (ushort index = 0; index < count; index++)
        {
            var offset = index * Xpp1BoundedCodec.MaximumChunkPayloadBytes;
            var length = Math.Min(Xpp1BoundedCodec.MaximumChunkPayloadBytes, inventory.Length - offset);
            payloads[index] = inventory.AsSpan(offset, length).ToArray();
            var hash = Xpp1BoundedCodec.ComputeChunkHash(index, payloads[index]);
            descriptors[index] = new Xpp1ChunkDescriptor(index, checked((uint)length), hash);
        }
        var descriptorBytes = Xpp1BoundedCodec.EncodeDescriptors(descriptors);
        var xpi1Hash = logicalPublication.Manifest.Xpi1Hash.ToArray();
        var viewHash = viewHash32.ToArray();
        var publicationHash = Xpp1BoundedCodec.ComputePublicationHash(
            logicalPublication.NetworkId.Span, logicalPublication.PublicationOperationId.Span, viewHash,
            logicalPublication.PlacementHash.Span, issuedAtUnixSeconds, expiresAtUnixSeconds,
            xpi1Hash, checked((ulong)inventory.Length), inventoryHash, count, descriptorBytes);

        Xpp1BoundedRequest EncodePhase(Xpp1BoundedPhase phase, ushort index, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> payload, bool includeXpi1) =>
            Xpp1BoundedCodec.Decode(Xpp1BoundedCodec.Encode(
                phase, logicalPublication.NetworkId.Span, logicalPublication.PublicationOperationId.Span,
                viewHash, logicalPublication.PlacementHash.Span, issuedAtUnixSeconds, expiresAtUnixSeconds,
                publicationHash, includeXpi1 ? logicalPublication.Manifest.CanonicalBytes.Span : [], xpi1Hash,
                checked((ulong)inventory.Length), inventoryHash, count, index, hash, payload));

        var manifest = (Xpp1ManifestRequest)EncodePhase(
            Xpp1BoundedPhase.Manifest, Xpp1BoundedCodec.NonChunkIndex, new byte[32], descriptorBytes, true);
        var chunks = new Xpp1ChunkRequest[count];
        for (ushort index = 0; index < count; index++)
            chunks[index] = (Xpp1ChunkRequest)EncodePhase(
                Xpp1BoundedPhase.Chunk, index, descriptors[index].Hash.Span, payloads[index], false);
        var commit = (Xpp1CommitRequest)EncodePhase(
            Xpp1BoundedPhase.Commit, Xpp1BoundedCodec.NonChunkIndex, new byte[32], [], false);
        return new BoundedPreKeyInventoryPublication(logicalPublication, manifest, chunks, commit);
    }

    internal static Xpp1Record Assemble(Xpp1ManifestRequest manifest, IReadOnlyList<Xpp1ChunkRequest> chunks)
    {
        if (chunks.Count != manifest.ChunkCount) throw new InvalidOperationException("The bounded publication is incomplete.");
        var inventory = new byte[checked((int)manifest.InventoryTotalLength)];
        var offset = 0;
        for (var index = 0; index < chunks.Count; index++)
        {
            var chunk = chunks[index];
            if (chunk.ChunkIndex != index) throw new InvalidOperationException("The bounded publication chunks are not ordered.");
            chunk.Payload.Span.CopyTo(inventory.AsSpan(offset));
            offset += chunk.Payload.Length;
        }
        var hash = ContactCodec.Sha256Domain(Xpp1BoundedCodec.InventoryHashDomain, inventory);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(hash, manifest.InventoryHash.Span))
                throw new InvalidOperationException("The assembled inventory hash does not match the manifest.");
        }
        finally { CryptographicOperations.ZeroMemory(hash); }
        var logical = PreKeyInventoryWire.Encode(ProtocolMagic.XPP1,
        [
            (1, manifest.NetworkId.ToArray()), (2, manifest.PublicationOperationId.ToArray()),
            (3, manifest.PlacementHash.ToArray()), (4, manifest.Manifest.CanonicalBytes.ToArray()), (5, inventory),
        ], Xpp1Codec.MaximumTotalBytes);
        return Xpp1Codec.Decode(logical);
    }

    private static byte[] EncodeInventory(Xpp1Record publication)
    {
        var bodyLength = checked(2 + publication.OneTimeDpk2Bytes.Sum(static value => 4 + value.Length) +
            4 + publication.LastResortDpk2Bytes.Length);
        var output = new byte[bodyLength];
        BinaryPrimitives.WriteUInt16BigEndian(output, checked((ushort)publication.OneTimeDpk2Bytes.Count));
        var offset = 2;
        foreach (var exact in publication.OneTimeDpk2Bytes)
        {
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset), checked((uint)exact.Length));
            offset += 4;
            exact.CopyTo(output, offset);
            offset += exact.Length;
        }
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset), checked((uint)publication.LastResortDpk2Bytes.Length));
        publication.LastResortDpk2Bytes.CopyTo(output.AsSpan(offset + 4));
        return output;
    }
}
