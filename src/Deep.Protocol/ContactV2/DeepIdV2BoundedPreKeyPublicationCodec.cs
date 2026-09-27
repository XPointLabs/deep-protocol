using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV2;

public enum Xpp1V2FragmentPhase : byte
{
    Manifest = 1,
    Chunk = 2,
    Commit = 3,
}

/// <summary>
/// One bounded XPP1 V2 transport record. This is not a published inventory:
/// selected replicas must durably reconstruct and verify the exact aggregate.
/// </summary>
public sealed class ParsedXpp1V2Fragment
{
    private readonly byte[] canonical;
    private readonly byte[][] fields;

    internal ParsedXpp1V2Fragment(byte[] canonical, byte[][] fields)
    {
        this.canonical = canonical;
        this.fields = fields;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public Xpp1V2FragmentPhase Phase => (Xpp1V2FragmentPhase)fields[0][0];
    public ReadOnlyMemory<byte> NetworkId => Field(2);
    public ReadOnlyMemory<byte> PublicationOperationId => Field(3);
    public ReadOnlyMemory<byte> ViewHash => Field(4);
    public ReadOnlyMemory<byte> PlacementHash => Field(5);
    public ReadOnlyMemory<byte> ExactAggregateHash => Field(6);
    public uint AggregateLength => BinaryPrimitives.ReadUInt32BigEndian(fields[6]);
    public ushort ChunkCount => BinaryPrimitives.ReadUInt16BigEndian(fields[7]);
    public ushort ChunkIndex => BinaryPrimitives.ReadUInt16BigEndian(fields[8]);
    public ReadOnlyMemory<byte> ChunkHash => Field(10);
    public ReadOnlyMemory<byte> PublisherDescriptorCommitment => Field(11);
    public ReadOnlyMemory<byte> Body => Field(12);
    /// <summary>
    /// Public DID2 credential carried only by a manifest. It is an untrusted
    /// directory lookup input, not publisher or inventory authority.
    /// </summary>
    public ReadOnlyMemory<byte> PublisherDid2 => Phase == Xpp1V2FragmentPhase.Manifest
        ? fields[11].AsMemory(0, DeepIdV2Codec.Did2Length).ToArray()
        : ReadOnlyMemory<byte>.Empty;
    public ReadOnlyMemory<byte> RequestHash => ApplicationCoreFormat.Sha256Domain(
        DeepIdV2BoundedPreKeyPublicationCodec.RequestHashDomain, canonical);

    public ReadOnlyMemory<byte> Field(int tag) => tag is >= 1 and <= 12
        ? fields[tag - 1].ToArray()
        : throw new ArgumentOutOfRangeException(nameof(tag));
}

/// <summary>
/// Closed, bounded XPP1 V2 carriage for one exact five-tag DID2 aggregate.
/// No manifest/chunk/commit record grants XPI1 publication authority.
/// </summary>
public static class DeepIdV2BoundedPreKeyPublicationCodec
{
    public const int MaximumChunkBytes = 65_536;
    public const int MaximumChunkCount = 128;
    public const int MaximumCanonicalBytes = 65_861;
    public const ushort NonChunkIndex = ushort.MaxValue;
    public const string AggregateHashDomain =
        "Deep/ContactResolver/V2/exact-xpp1";
    public const string DescriptorHashDomain =
        "Deep/ContactResolver/V2/xpp1-descriptors";
    public const string ChunkHashDomain =
        "Deep/ContactResolver/V2/xpp1-chunk";
    public const string RequestHashDomain =
        "Deep/ContactResolver/V2/xpp1-fragment";
    public static bool RuntimeActivation => false;

    private const int MinimumCanonicalBytes = 325;
    private static ReadOnlySpan<int> FixedLengths =>
        [1, 16, 32, 32, 32, 32, 4, 2, 2, 32, 32];

    /// <summary>
    /// Produces one manifest, every exact aggregate slice, and one commit.
    /// The caller must send them to both authenticated selected replicas and
    /// verify two final XIC1 receipts independently.
    /// </summary>
    public static IReadOnlyList<byte[]> CreateSequence(
        ReadOnlySpan<byte> exactAggregate, ReadOnlySpan<byte> currentViewHash32,
        ReadOnlySpan<byte> exactPublisherDid2)
    {
        if (currentViewHash32.Length != 32 ||
            ApplicationCoreFormat.IsZero(currentViewHash32))
            throw new ArgumentException("The current XNV view hash is required.",
                nameof(currentViewHash32));
        var aggregate = DeepIdV2PreKeyPublicationCodec.Decode(exactAggregate);
        var publisher = DeepIdV2Codec.DecodeDid2(exactPublisherDid2);
        var totalLength = checked((uint)exactAggregate.Length);
        var chunkCount = ChunkCount(totalLength);
        var aggregateHash = ApplicationCoreFormat.Sha256Domain(
            AggregateHashDomain, exactAggregate);
        var descriptors = new byte[checked(chunkCount * 36)];
        for (var index = 0; index < chunkCount; index++)
        {
            var slice = Chunk(exactAggregate, totalLength, index);
            BinaryPrimitives.WriteUInt32BigEndian(
                descriptors.AsSpan(index * 36, 4), checked((uint)slice.Length));
            ComputeChunkHash(checked((ushort)index), slice)
                .CopyTo(descriptors, index * 36 + 4);
        }
        var manifestBytes = aggregate.Manifest.CanonicalBytes;
        var manifestBody = new byte[DeepIdV2Codec.Did2Length +
            manifestBytes.Length + descriptors.Length];
        publisher.CanonicalBytes.Span.CopyTo(manifestBody);
        manifestBytes.Span.CopyTo(manifestBody.AsSpan(DeepIdV2Codec.Did2Length));
        descriptors.CopyTo(manifestBody,
            DeepIdV2Codec.Did2Length + manifestBytes.Length);
        var descriptorHash = ComputeManifestDescriptorHash(
            publisher.CanonicalBytes.Span, descriptors);
        var common = new FragmentHeader(aggregate.NetworkId.ToArray(),
            aggregate.PublicationOperationId.ToArray(),
            currentViewHash32.ToArray(), aggregate.PlacementHash.ToArray(),
            aggregateHash, totalLength, chunkCount, descriptorHash);
        var output = new List<byte[]>(chunkCount + 2)
        {
            Encode(common, Xpp1V2FragmentPhase.Manifest, NonChunkIndex,
                new byte[32], manifestBody)
        };
        for (var index = 0; index < chunkCount; index++)
        {
            var slice = Chunk(exactAggregate, totalLength, index);
            var hash = descriptors.AsSpan(index * 36 + 4, 32);
            output.Add(Encode(common, Xpp1V2FragmentPhase.Chunk,
                checked((ushort)index), hash, slice));
        }
        output.Add(Encode(common, Xpp1V2FragmentPhase.Commit,
            NonChunkIndex, new byte[32], []));
        return output.AsReadOnly();
    }

    public static ParsedXpp1V2Fragment Decode(ReadOnlySpan<byte> canonical)
    {
        var slices = new ApplicationFieldSlice[12];
        ApplicationCoreFormat.Preflight(canonical, ProtocolMagicBytes.XPP1,
            12, MinimumCanonicalBytes, MaximumCanonicalBytes, slices, 2,
            DeepIdV2Codec.Suite);
        var owned = canonical.ToArray();
        var lengths = FixedLengths;
        for (var tag = 1; tag <= lengths.Length; tag++)
            ApplicationCoreFormat.ExactLength(slices, tag, lengths[tag - 1]);
        ReadOnlySpan<byte> Field(int tag) =>
            ApplicationCoreFormat.Field(owned, slices, tag);
        for (var tag = 2; tag <= 6; tag++)
            ApplicationCoreFormat.NonZero(Field(tag), "XPP1 V2 fragment header");
        ApplicationCoreFormat.NonZero(Field(11),
            "XPP1 V2 publisher/descriptor commitment");
        var phase = (Xpp1V2FragmentPhase)Field(1)[0];
        if (!Enum.IsDefined(phase))
            Reject(ApplicationCoreRejection.InvalidEnum,
                "XPP1 V2 fragment phase is invalid.");
        var totalLength = BinaryPrimitives.ReadUInt32BigEndian(Field(7));
        if (totalLength is < DeepIdV2PreKeyPublicationCodec.MinimumTotalBytes or
            > DeepIdV2PreKeyPublicationCodec.MaximumTotalBytes)
            Reject(ApplicationCoreRejection.InvalidFieldLength,
                "XPP1 V2 aggregate length is outside its closed bound.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(Field(8));
        if (count != ChunkCount(totalLength))
            Reject(ApplicationCoreRejection.CrossFieldMismatch,
                "XPP1 V2 chunk count does not cover the exact aggregate.");
        var index = BinaryPrimitives.ReadUInt16BigEndian(Field(9));
        var body = Field(12);
        switch (phase)
        {
            case Xpp1V2FragmentPhase.Manifest:
                if (index != NonChunkIndex ||
                    !ApplicationCoreFormat.IsZero(Field(10)) ||
                    body.Length != DeepIdV2Codec.Did2Length +
                        DeepIdV2PreKeyManifestCodec.CanonicalLength +
                        count * 36)
                    Reject(ApplicationCoreRejection.InvalidFieldLength,
                        "XPP1 V2 manifest fragment shape is invalid.");
                try
                {
                    _ = DeepIdV2Codec.DecodeDid2(
                        body[..DeepIdV2Codec.Did2Length]);
                }
                catch (FormatException exception)
                {
                    throw ApplicationCoreFormat.Error(
                        ApplicationCoreValidationStage.EmbeddedRecord,
                        ApplicationCoreRejection.EmbeddedRecordRejected,
                        "XPP1 V2 fragment embeds an invalid DID2 publisher hint.",
                        exception);
                }
                ParsedXpi1V2 manifest;
                try
                {
                    manifest = DeepIdV2PreKeyManifestCodec.Decode(
                        body.Slice(DeepIdV2Codec.Did2Length,
                            DeepIdV2PreKeyManifestCodec.CanonicalLength));
                }
                catch (FormatException exception)
                {
                    throw ApplicationCoreFormat.Error(
                        ApplicationCoreValidationStage.EmbeddedRecord,
                        ApplicationCoreRejection.EmbeddedRecordRejected,
                        "XPP1 V2 fragment embeds an invalid DID2 manifest.",
                        exception);
                }
                if (!Fixed(Field(2), manifest.Field(1).Span) ||
                    !Fixed(ComputeManifestDescriptorHash(
                            body[..DeepIdV2Codec.Did2Length],
                            body[(DeepIdV2Codec.Did2Length +
                                DeepIdV2PreKeyManifestCodec.CanonicalLength)..]),
                        Field(11)))
                    Reject(ApplicationCoreRejection.CrossFieldMismatch,
                        "XPP1 V2 manifest network or publisher/descriptor commitment differs.");
                var descriptors = body[(DeepIdV2Codec.Did2Length +
                    DeepIdV2PreKeyManifestCodec.CanonicalLength)..];
                for (var current = 0; current < count; current++)
                {
                    var row = descriptors.Slice(current * 36, 36);
                    if (BinaryPrimitives.ReadUInt32BigEndian(row) !=
                            ChunkLength(totalLength, current) ||
                        ApplicationCoreFormat.IsZero(row[4..]))
                        Reject(ApplicationCoreRejection.InvalidFieldLength,
                            "XPP1 V2 descriptor does not name an exact nonempty slice.");
                }
                break;
            case Xpp1V2FragmentPhase.Chunk:
                if (index >= count ||
                    body.Length != ChunkLength(totalLength, index) ||
                    !Fixed(ComputeChunkHash(index, body), Field(10)))
                    Reject(ApplicationCoreRejection.CrossFieldMismatch,
                        "XPP1 V2 chunk does not match its exact index and hash.");
                break;
            case Xpp1V2FragmentPhase.Commit:
                if (index != NonChunkIndex ||
                    !ApplicationCoreFormat.IsZero(Field(10)) ||
                    !body.IsEmpty)
                    Reject(ApplicationCoreRejection.InvalidFieldLength,
                        "XPP1 V2 commit fragment shape is invalid.");
                break;
        }
        var fields = new byte[12][];
        for (var tag = 1; tag <= fields.Length; tag++)
            fields[tag - 1] = ApplicationCoreFormat.Field(owned, slices, tag)
                .ToArray();
        return new ParsedXpp1V2Fragment(owned, fields);
    }

    public static byte[] ComputeAggregateHash(ReadOnlySpan<byte> exactAggregate)
    {
        _ = DeepIdV2PreKeyPublicationCodec.Decode(exactAggregate);
        return ApplicationCoreFormat.Sha256Domain(AggregateHashDomain,
            exactAggregate);
    }

    private static byte[] Encode(FragmentHeader header,
        Xpp1V2FragmentPhase phase, ushort index,
        ReadOnlySpan<byte> chunkHash, ReadOnlySpan<byte> body)
    {
        var totalLength = checked(MinimumCanonicalBytes + body.Length);
        if (totalLength > MaximumCanonicalBytes)
            throw new ArgumentOutOfRangeException(nameof(body));
        var bytes = new byte[totalLength];
        var writer = new ApplicationRecordWriter(bytes,
            ProtocolMagicBytes.XPP1, 12, 2, DeepIdV2Codec.Suite);
        writer.Write(1, [(byte)phase]);
        writer.Write(2, header.NetworkId);
        writer.Write(3, header.OperationId);
        writer.Write(4, header.ViewHash);
        writer.Write(5, header.PlacementHash);
        writer.Write(6, header.AggregateHash);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, header.AggregateLength);
        writer.Write(7, length);
        Span<byte> count = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(count, header.ChunkCount);
        writer.Write(8, count);
        Span<byte> chunkIndex = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(chunkIndex, index);
        writer.Write(9, chunkIndex);
        writer.Write(10, chunkHash);
        writer.Write(11, header.DescriptorHash);
        writer.Write(12, body);
        writer.Complete();
        _ = Decode(bytes);
        return bytes;
    }

    private static ushort ChunkCount(uint totalLength) =>
        checked((ushort)((totalLength + MaximumChunkBytes - 1) /
            MaximumChunkBytes));

    private static uint ChunkLength(uint totalLength, int index)
    {
        var offset = checked((uint)index * MaximumChunkBytes);
        return Math.Min(MaximumChunkBytes, totalLength - offset);
    }

    private static ReadOnlySpan<byte> Chunk(ReadOnlySpan<byte> aggregate,
        uint totalLength, int index) => aggregate.Slice(
            checked(index * MaximumChunkBytes),
            checked((int)ChunkLength(totalLength, index)));

    private static byte[] ComputeChunkHash(ushort index,
        ReadOnlySpan<byte> body)
    {
        var input = new byte[2 + body.Length];
        BinaryPrimitives.WriteUInt16BigEndian(input, index);
        body.CopyTo(input.AsSpan(2));
        return ApplicationCoreFormat.Sha256Domain(ChunkHashDomain, input);
    }

    private static byte[] ComputeManifestDescriptorHash(
        ReadOnlySpan<byte> exactDid2, ReadOnlySpan<byte> descriptors)
    {
        var input = new byte[checked(exactDid2.Length + descriptors.Length)];
        exactDid2.CopyTo(input);
        descriptors.CopyTo(input.AsSpan(exactDid2.Length));
        return ApplicationCoreFormat.Sha256Domain(DescriptorHashDomain, input);
    }

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static void Reject(ApplicationCoreRejection rejection,
        string message) => throw ApplicationCoreFormat.Error(
            ApplicationCoreValidationStage.SemanticFields, rejection,
            message);

    private sealed record FragmentHeader(byte[] NetworkId, byte[] OperationId,
        byte[] ViewHash, byte[] PlacementHash, byte[] AggregateHash,
        uint AggregateLength, ushort ChunkCount, byte[] DescriptorHash);
}
