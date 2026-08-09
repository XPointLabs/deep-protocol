using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

internal static class ProductionMailboxRouteHistoryConstants
{
    internal const byte Version = 1;
    internal const int HeaderLength = 64;
    internal const int ArtifactItemLength = 40;
    internal const int LinkItemLength = 32;
    internal const int MaximumLinks = 16;
    internal const int MaximumArtifacts = 128;
    internal const int MaximumPayloadBytes = 8 * 1024 * 1024;
    internal const int MaximumEncodedBytes = 8_394_304;
    internal const int MaximumBatches = 32;
    internal const int MaximumCumulativeLinks = 512;
    internal const ulong MaximumCumulativePayloadBytes = 256UL * 1024 * 1024;
}

internal enum ProductionMailboxRouteHistoryArtifactKind : byte
{
    Authority = 1,
    Revocations = 2,
    RouteCertificate = 3,
    RevocationCheckpoint = 4,
    TransitionContext = 5,
    ContinuityActivation = 6,
    OwnerAdvertisement = 7
}

internal sealed record ProductionMailboxRouteHistoryArtifact
{
    internal required ProductionMailboxRouteHistoryArtifactKind Kind { get; init; }
    internal required ReadOnlyMemory<byte> CanonicalBytes { get; init; }
}

internal sealed record ProductionMailboxRouteHistoryLink
{
    internal required ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; init; }
    internal required ushort AuthorityIndex { get; init; }
    internal required ushort RevocationsIndex { get; init; }
    internal required ushort RouteCertificateIndex { get; init; }
    internal required ushort RevocationCheckpointIndex { get; init; }
    internal required ushort TransitionContextIndex { get; init; }
    internal required ushort AuthorizationIndex { get; init; }
    internal required ulong PredecessorSequence { get; init; }
    internal required ulong NewSequence { get; init; }
}

internal sealed record ProductionMailboxRouteHistoryBatch
{
    internal required ulong BatchSequence { get; init; }
    internal required ReadOnlyMemory<byte> PreviousCheckpointHash { get; init; }
    internal required IReadOnlyList<ProductionMailboxRouteHistoryArtifact> Artifacts { get; init; }
    internal required IReadOnlyList<ProductionMailboxRouteHistoryLink> Links { get; init; }
}

internal readonly record struct ProductionMailboxRouteHistoryPreflightHeader(
    ulong BatchSequence,
    ushort LinkCount,
    ushort ArtifactCount,
    int TableBytes,
    int PayloadBytes);

internal static class ProductionMailboxRouteHistoryCodec
{
    private static ReadOnlySpan<byte> Magic => "RHB1"u8;

    internal static byte[] Encode(ProductionMailboxRouteHistoryBatch value)
    {
        var frozen = Freeze(value);
        Validate(frozen);
        var artifactCount = frozen.Artifacts.Count;
        var linkCount = frozen.Links.Count;
        var tableBytes = checked((artifactCount * ProductionMailboxRouteHistoryConstants.ArtifactItemLength) +
            (linkCount * ProductionMailboxRouteHistoryConstants.LinkItemLength));
        var payloadBytes = frozen.Artifacts.Sum(static item => item.CanonicalBytes.Length);
        var output = new byte[checked(ProductionMailboxRouteHistoryConstants.HeaderLength + tableBytes + payloadBytes)];
        Magic.CopyTo(output);
        output[4] = ProductionMailboxRouteHistoryConstants.Version;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8, 8), frozen.BatchSequence);
        frozen.PreviousCheckpointHash.Span.CopyTo(output.AsSpan(16, 32));
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(48, 2), checked((ushort)linkCount));
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(50, 2), checked((ushort)artifactCount));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(52, 4), checked((uint)tableBytes));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(56, 4), checked((uint)payloadBytes));
        var offset = ProductionMailboxRouteHistoryConstants.HeaderLength;
        foreach (var item in frozen.Artifacts)
        {
            output[offset] = (byte)item.Kind;
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4, 4), checked((uint)item.CanonicalBytes.Length));
            SHA256.HashData(item.CanonicalBytes.Span).CopyTo(output.AsSpan(offset + 8, 32));
            offset += ProductionMailboxRouteHistoryConstants.ArtifactItemLength;
        }
        foreach (var link in frozen.Links)
        {
            output[offset] = (byte)link.AuthorizationKind;
            WriteUInt16(output, offset + 4, link.AuthorityIndex);
            WriteUInt16(output, offset + 6, link.RevocationsIndex);
            WriteUInt16(output, offset + 8, link.RouteCertificateIndex);
            WriteUInt16(output, offset + 10, link.RevocationCheckpointIndex);
            WriteUInt16(output, offset + 12, link.TransitionContextIndex);
            WriteUInt16(output, offset + 14, link.AuthorizationIndex);
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset + 16, 8), link.PredecessorSequence);
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset + 24, 8), link.NewSequence);
            offset += ProductionMailboxRouteHistoryConstants.LinkItemLength;
        }
        foreach (var item in frozen.Artifacts)
        {
            item.CanonicalBytes.Span.CopyTo(output.AsSpan(offset));
            offset += item.CanonicalBytes.Length;
        }
        return output;
    }

    internal static ProductionMailboxRouteHistoryPreflightHeader PreflightHeader(
        ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < ProductionMailboxRouteHistoryConstants.HeaderLength ||
            encoded.Length > ProductionMailboxRouteHistoryConstants.MaximumEncodedBytes)
            throw new FormatException("RHB1 length is outside its strict bound.");
        if (!encoded[..4].SequenceEqual(Magic) ||
            encoded[4] != ProductionMailboxRouteHistoryConstants.Version)
            throw new FormatException("RHB1 magic or version is invalid.");
        if (encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(60, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException("RHB1 reserved bytes must be zero.");
        var batchSequence = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8));
        var linkCount = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(48, 2));
        var artifactCount = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(50, 2));
        var tableBytes = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(52, 4));
        var payloadBytes = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(56, 4));
        if (batchSequence == 0 ||
            linkCount is 0 or > ProductionMailboxRouteHistoryConstants.MaximumLinks ||
            artifactCount is 0 or > ProductionMailboxRouteHistoryConstants.MaximumArtifacts ||
            payloadBytes > ProductionMailboxRouteHistoryConstants.MaximumPayloadBytes)
            throw new FormatException("RHB1 scalar bounds are invalid.");
        var expectedTable = checked(
            artifactCount * ProductionMailboxRouteHistoryConstants.ArtifactItemLength +
            linkCount * ProductionMailboxRouteHistoryConstants.LinkItemLength);
        var expectedLength = checked(
            ProductionMailboxRouteHistoryConstants.HeaderLength +
            expectedTable + checked((int)payloadBytes));
        if (tableBytes != checked((uint)expectedTable) || expectedLength != encoded.Length)
            throw new FormatException("RHB1 count-derived length is invalid.");
        return new(batchSequence, linkCount, artifactCount, expectedTable,
            checked((int)payloadBytes));
    }

    internal static ProductionMailboxRouteHistoryPreflightHeader PreflightCanonical(
        ReadOnlySpan<byte> encoded,
        bool validateNestedFraming,
        ulong? expectedFirstPredecessorSequence = null)
    {
        var header = PreflightHeader(encoded);
        var tableOffset = ProductionMailboxRouteHistoryConstants.HeaderLength;
        var payloadCursor = checked(ProductionMailboxRouteHistoryConstants.HeaderLength +
            header.TableBytes);
        byte previousKind = 0;
        ReadOnlySpan<byte> previousHash = default;
        Span<byte> priorHashes = stackalloc byte[
            ProductionMailboxRouteHistoryConstants.MaximumArtifacts * 32];
        Span<byte> digest = stackalloc byte[32];
        for (var index = 0; index < header.ArtifactCount; index++)
        {
            var kind = (ProductionMailboxRouteHistoryArtifactKind)encoded[tableOffset];
            if (!Enum.IsDefined(kind) ||
                encoded.Slice(tableOffset + 1, 3).IndexOfAnyExcept((byte)0) >= 0)
                throw new FormatException("RHB1 artifact tag or reserved bytes are invalid.");
            var rawLength = BinaryPrimitives.ReadUInt32BigEndian(
                encoded.Slice(tableOffset + 4, 4));
            if (rawLength == 0 || rawLength > int.MaxValue)
                throw new FormatException("RHB1 artifact payload length is invalid.");
            var length = checked((int)rawLength);
            if (payloadCursor > encoded.Length - length)
                throw new FormatException("RHB1 artifact payload length is invalid.");
            var payload = encoded.Slice(payloadCursor, length);
            PreflightArtifact(kind, payload, validateNestedFraming);
            var declaredHash = encoded.Slice(tableOffset + 8, 32);
            SHA256.HashData(payload, digest);
            if (!CryptographicOperations.FixedTimeEquals(declaredHash, digest))
                throw new FormatException("RHB1 artifact payload hash is invalid.");
            for (var priorIndex = 0; priorIndex < index; priorIndex++)
            {
                if (CryptographicOperations.FixedTimeEquals(declaredHash,
                        priorHashes.Slice(priorIndex * 32, 32)))
                    throw new FormatException(
                        "RHB1 duplicate or cross-type hash alias is forbidden.");
            }
            declaredHash.CopyTo(priorHashes.Slice(index * 32, 32));
            if (index != 0)
            {
                var kindOrder = previousKind.CompareTo((byte)kind);
                var hashOrder = previousHash.SequenceCompareTo(declaredHash);
                if (kindOrder > 0 || kindOrder == 0 && hashOrder >= 0)
                    throw new FormatException(
                        "RHB1 artifact table is not strictly ordered.");
            }
            previousKind = (byte)kind;
            previousHash = declaredHash;
            payloadCursor += length;
            tableOffset += ProductionMailboxRouteHistoryConstants.ArtifactItemLength;
        }
        if (payloadCursor != encoded.Length)
            throw new FormatException("RHB1 payload has trailing bytes.");

        Span<byte> used = stackalloc byte[ProductionMailboxRouteHistoryConstants.MaximumArtifacts];
        var expectedPredecessor = expectedFirstPredecessorSequence;
        for (var index = 0; index < header.LinkCount; index++)
        {
            var offset = ProductionMailboxRouteHistoryConstants.HeaderLength +
                header.ArtifactCount * ProductionMailboxRouteHistoryConstants.ArtifactItemLength +
                index * ProductionMailboxRouteHistoryConstants.LinkItemLength;
            var kind = (ProductionMailboxRouteAuthorizationKind)encoded[offset];
            if (kind is not ProductionMailboxRouteAuthorizationKind.OwnerPRA2 and
                    not ProductionMailboxRouteAuthorizationKind.DelegatedRCA1 ||
                encoded.Slice(offset + 1, 3).IndexOfAnyExcept((byte)0) >= 0)
                throw new FormatException("RHB1 link kind or reserved bytes are invalid.");
            var authority = ReadUInt16(encoded, offset + 4);
            var revocations = ReadUInt16(encoded, offset + 6);
            var certificate = ReadUInt16(encoded, offset + 8);
            var checkpoint = ReadUInt16(encoded, offset + 10);
            var transition = ReadUInt16(encoded, offset + 12);
            var authorization = ReadUInt16(encoded, offset + 14);
            var predecessor = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(offset + 16, 8));
            var next = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(offset + 24, 8));
            if (predecessor == ulong.MaxValue || next is 0 or ulong.MaxValue ||
                next != predecessor + 1)
                throw new FormatException("RHB1 link sequence is invalid.");
            if (expectedPredecessor.HasValue &&
                predecessor != expectedPredecessor.Value)
                throw new FormatException(
                    "RHB1 link chain differs from the sealed predecessor sequence.");
            expectedPredecessor = next;
            RequirePreflightArtifact(encoded, used, header.ArtifactCount, authority,
                ProductionMailboxRouteHistoryArtifactKind.Authority);
            RequirePreflightArtifact(encoded, used, header.ArtifactCount, revocations,
                ProductionMailboxRouteHistoryArtifactKind.Revocations);
            RequirePreflightArtifact(encoded, used, header.ArtifactCount, certificate,
                ProductionMailboxRouteHistoryArtifactKind.RouteCertificate);
            RequirePreflightArtifact(encoded, used, header.ArtifactCount, authorization,
                kind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                ? ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement
                : ProductionMailboxRouteHistoryArtifactKind.ContinuityActivation);
            if (kind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
            {
                if (checkpoint != ushort.MaxValue || transition != ushort.MaxValue)
                    throw new FormatException("RHB1 owner link must omit RCH1 and RTC1.");
            }
            else
            {
                RequirePreflightArtifact(encoded, used, header.ArtifactCount, checkpoint,
                    ProductionMailboxRouteHistoryArtifactKind.RevocationCheckpoint);
                RequirePreflightArtifact(encoded, used, header.ArtifactCount, transition,
                    ProductionMailboxRouteHistoryArtifactKind.TransitionContext);
            }
        }
        if (used[..header.ArtifactCount].IndexOf((byte)0) >= 0)
            throw new FormatException("RHB1 contains an unreferenced artifact row.");
        return header;
    }

    private static void RequirePreflightArtifact(ReadOnlySpan<byte> encoded, Span<byte> used,
        ushort artifactCount, ushort artifactIndex,
        ProductionMailboxRouteHistoryArtifactKind expected)
    {
        if (artifactIndex >= artifactCount)
            throw new FormatException("RHB1 link artifact index is invalid.");
        var artifactOffset = ProductionMailboxRouteHistoryConstants.HeaderLength +
            artifactIndex * ProductionMailboxRouteHistoryConstants.ArtifactItemLength;
        if ((ProductionMailboxRouteHistoryArtifactKind)encoded[artifactOffset] != expected)
            throw new FormatException("RHB1 link artifact tag is invalid.");
        used[artifactIndex] = 1;
    }

    private static void PreflightArtifact(ProductionMailboxRouteHistoryArtifactKind kind,
        ReadOnlySpan<byte> payload,
        bool validateNestedFraming)
    {
        if (!validateNestedFraming)
            return;
        var exactLength = kind switch
        {
            ProductionMailboxRouteHistoryArtifactKind.RouteCertificate =>
                ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength,
            ProductionMailboxRouteHistoryArtifactKind.RevocationCheckpoint =>
                ProductionMailboxRouteContinuityConstants.CanonicalRevocationCheckpointLength,
            ProductionMailboxRouteHistoryArtifactKind.TransitionContext =>
                ProductionMailboxRouteAuthorizationConstants.CanonicalTransitionContextLength,
            ProductionMailboxRouteHistoryArtifactKind.ContinuityActivation =>
                ProductionMailboxRouteAuthorizationConstants.CanonicalContinuityActivationLength,
            ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement =>
                ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length,
            _ => 0
        };
        if (exactLength != 0 && payload.Length != exactLength)
            throw new FormatException("RHB1 fixed artifact length is invalid.");
        if (kind == ProductionMailboxRouteHistoryArtifactKind.Authority &&
            payload.Length > ProductionMailboxAuthorityConstants.MaximumArtifactBytes)
            throw new FormatException("RHB1 PMA1 length is outside its bound.");
        if (kind == ProductionMailboxRouteHistoryArtifactKind.Revocations)
            ProductionMailboxRevocationSnapshotCodec.PreflightCanonical(payload);
    }

    internal static ProductionMailboxRouteHistoryBatch Decode(ReadOnlySpan<byte> encoded)
    {
        PreflightCanonical(encoded, validateNestedFraming: false);
        return DecodeOwned(encoded.ToArray(), validateNestedFraming: false);
    }

    internal static ProductionMailboxRouteHistoryBatch DecodeOwned(
        byte[] frozen,
        bool validateNestedFraming)
    {
        ArgumentNullException.ThrowIfNull(frozen);
        var encoded = frozen.AsSpan();
        var preflight = PreflightCanonical(encoded, validateNestedFraming);
        var batchSequence = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8));
        var linkCount = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(48, 2));
        var artifactCount = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(50, 2));
        var tableBytes = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(52, 4));
        var payloadBytes = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(56, 4));
        if (batchSequence != preflight.BatchSequence || linkCount != preflight.LinkCount ||
            artifactCount != preflight.ArtifactCount ||
            tableBytes != checked((uint)preflight.TableBytes) ||
            payloadBytes != checked((uint)preflight.PayloadBytes))
            throw new FormatException("RHB1 owned preflight changed unexpectedly.");
        var artifacts = new ProductionMailboxRouteHistoryArtifact[artifactCount];
        var hashes = new byte[artifactCount][];
        var lengths = new int[artifactCount];
        var tableOffset = ProductionMailboxRouteHistoryConstants.HeaderLength;
        var payloadOffset = checked(ProductionMailboxRouteHistoryConstants.HeaderLength + (int)tableBytes);
        var cursor = payloadOffset;
        for (var i = 0; i < artifactCount; i++)
        {
            var kind = (ProductionMailboxRouteHistoryArtifactKind)frozen[tableOffset];
            if (!Enum.IsDefined(kind) || frozen.AsSpan(tableOffset + 1, 3).IndexOfAnyExcept((byte)0) >= 0)
                throw new FormatException("RHB1 artifact tag or reserved bytes are invalid.");
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(frozen.AsSpan(tableOffset + 4, 4)));
            if (length <= 0 || cursor > frozen.Length - length)
                throw new FormatException("RHB1 artifact payload length is invalid.");
            var hash = frozen.AsSpan(tableOffset + 8, 32).ToArray();
            var bytes = frozen.AsMemory(cursor, length).ToArray();
            if (!CryptographicOperations.FixedTimeEquals(hash, SHA256.HashData(bytes)))
                throw new FormatException("RHB1 artifact payload hash is invalid.");
            artifacts[i] = new() { Kind = kind, CanonicalBytes = bytes };
            hashes[i] = hash;
            lengths[i] = length;
            cursor += length;
            tableOffset += ProductionMailboxRouteHistoryConstants.ArtifactItemLength;
        }
        if (cursor != frozen.Length)
            throw new FormatException("RHB1 payload has trailing bytes.");
        ValidateArtifactOrder(artifacts, hashes);
        var links = new ProductionMailboxRouteHistoryLink[linkCount];
        var used = new bool[artifactCount];
        for (var i = 0; i < linkCount; i++)
        {
            var offset = ProductionMailboxRouteHistoryConstants.HeaderLength +
                (artifactCount * ProductionMailboxRouteHistoryConstants.ArtifactItemLength) +
                (i * ProductionMailboxRouteHistoryConstants.LinkItemLength);
            var kind = (ProductionMailboxRouteAuthorizationKind)frozen[offset];
            if (frozen.AsSpan(offset + 1, 3).IndexOfAnyExcept((byte)0) >= 0)
                throw new FormatException("RHB1 link reserved bytes must be zero.");
            var link = new ProductionMailboxRouteHistoryLink
            {
                AuthorizationKind = kind,
                AuthorityIndex = ReadUInt16(frozen, offset + 4),
                RevocationsIndex = ReadUInt16(frozen, offset + 6),
                RouteCertificateIndex = ReadUInt16(frozen, offset + 8),
                RevocationCheckpointIndex = ReadUInt16(frozen, offset + 10),
                TransitionContextIndex = ReadUInt16(frozen, offset + 12),
                AuthorizationIndex = ReadUInt16(frozen, offset + 14),
                PredecessorSequence = BinaryPrimitives.ReadUInt64BigEndian(frozen.AsSpan(offset + 16, 8)),
                NewSequence = BinaryPrimitives.ReadUInt64BigEndian(frozen.AsSpan(offset + 24, 8))
            };
            ValidateLink(link, artifacts, used);
            links[i] = link;
        }
        if (used.Any(static value => !value))
            throw new FormatException("RHB1 contains an unreferenced artifact row.");
        var result = new ProductionMailboxRouteHistoryBatch
        {
            BatchSequence = batchSequence,
            PreviousCheckpointHash = frozen.AsMemory(16, 32).ToArray(),
            Artifacts = artifacts,
            Links = links
        };
        if (!frozen.AsSpan().SequenceEqual(Encode(result)))
            throw new FormatException("RHB1 is not canonical.");
        return result;
    }

    internal static byte[] ComputeHash(ReadOnlySpan<byte> canonicalBatch) => SHA256.HashData(canonicalBatch);

    private static ProductionMailboxRouteHistoryBatch Freeze(ProductionMailboxRouteHistoryBatch value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.PreviousCheckpointHash.Length != 32 || value.Artifacts is null || value.Links is null)
            throw new FormatException("RHB1 required fields are invalid.");
        var artifactCount = value.Artifacts.Count;
        var linkCount = value.Links.Count;
        if (artifactCount is 0 or > ProductionMailboxRouteHistoryConstants.MaximumArtifacts ||
            linkCount is 0 or > ProductionMailboxRouteHistoryConstants.MaximumLinks)
            throw new FormatException("RHB1 collection counts are invalid.");
        var artifacts = new ProductionMailboxRouteHistoryArtifact[artifactCount];
        for (var i = 0; i < artifactCount; i++)
        {
            var item = value.Artifacts[i] ?? throw new FormatException("RHB1 artifact is null.");
            if (item.CanonicalBytes.Length is <= 0 or > ProductionMailboxRouteHistoryConstants.MaximumPayloadBytes)
                throw new FormatException("RHB1 artifact length is invalid.");
            artifacts[i] = new() { Kind = item.Kind, CanonicalBytes = item.CanonicalBytes.ToArray() };
        }
        if (value.Artifacts.Count != artifactCount)
            throw new FormatException("RHB1 artifact collection mutated.");
        var links = new ProductionMailboxRouteHistoryLink[linkCount];
        for (var i = 0; i < linkCount; i++)
            links[i] = value.Links[i] with { };
        if (value.Links.Count != linkCount)
            throw new FormatException("RHB1 link collection mutated.");
        return new()
        {
            BatchSequence = value.BatchSequence,
            PreviousCheckpointHash = value.PreviousCheckpointHash.ToArray(),
            Artifacts = artifacts,
            Links = links
        };
    }

    private static void Validate(ProductionMailboxRouteHistoryBatch value)
    {
        if (value.BatchSequence == 0 || value.PreviousCheckpointHash.Length != 32 ||
            value.PreviousCheckpointHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("RHB1 predecessor state is invalid.");
        var hashes = value.Artifacts.Select(static item => SHA256.HashData(item.CanonicalBytes.Span)).ToArray();
        ValidateArtifactOrder(value.Artifacts, hashes);
        var used = new bool[value.Artifacts.Count];
        foreach (var link in value.Links)
            ValidateLink(link, value.Artifacts, used);
        if (used.Any(static item => !item))
            throw new FormatException("RHB1 contains an unreferenced artifact row.");
        var payload = value.Artifacts.Sum(static item => item.CanonicalBytes.Length);
        var total = checked(ProductionMailboxRouteHistoryConstants.HeaderLength +
            (value.Artifacts.Count * ProductionMailboxRouteHistoryConstants.ArtifactItemLength) +
            (value.Links.Count * ProductionMailboxRouteHistoryConstants.LinkItemLength) + payload);
        if (payload > ProductionMailboxRouteHistoryConstants.MaximumPayloadBytes ||
            total > ProductionMailboxRouteHistoryConstants.MaximumEncodedBytes)
            throw new FormatException("RHB1 payload exceeds its bound.");
    }

    private static void ValidateArtifactOrder(IReadOnlyList<ProductionMailboxRouteHistoryArtifact> artifacts,
        IReadOnlyList<byte[]> hashes)
    {
        for (var i = 0; i < artifacts.Count; i++)
        {
            if (!Enum.IsDefined(artifacts[i].Kind))
                throw new FormatException("RHB1 artifact type is invalid.");
            for (var j = 0; j < i; j++)
            {
                var hashComparison = hashes[j].AsSpan().SequenceCompareTo(hashes[i]);
                if (hashComparison == 0)
                    throw new FormatException("RHB1 duplicate or cross-type hash alias is forbidden.");
            }
            if (i == 0)
                continue;
            var typeComparison = ((byte)artifacts[i - 1].Kind).CompareTo((byte)artifacts[i].Kind);
            var hashOrder = hashes[i - 1].AsSpan().SequenceCompareTo(hashes[i]);
            if (typeComparison > 0 || (typeComparison == 0 && hashOrder >= 0))
                throw new FormatException("RHB1 artifact table is not strictly ordered.");
        }
    }

    private static void ValidateLink(ProductionMailboxRouteHistoryLink link,
        IReadOnlyList<ProductionMailboxRouteHistoryArtifact> artifacts, bool[] used)
    {
        if (link.AuthorizationKind is not ProductionMailboxRouteAuthorizationKind.OwnerPRA2 and
            not ProductionMailboxRouteAuthorizationKind.DelegatedRCA1 ||
            link.NewSequence == 0 || link.NewSequence == ulong.MaxValue ||
            link.PredecessorSequence == ulong.MaxValue || link.NewSequence != link.PredecessorSequence + 1)
            throw new FormatException("RHB1 link kind or sequence is invalid.");
        Require(link.AuthorityIndex, ProductionMailboxRouteHistoryArtifactKind.Authority, artifacts, used);
        Require(link.RevocationsIndex, ProductionMailboxRouteHistoryArtifactKind.Revocations, artifacts, used);
        Require(link.RouteCertificateIndex, ProductionMailboxRouteHistoryArtifactKind.RouteCertificate, artifacts, used);
        Require(link.AuthorizationIndex,
            link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                ? ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement
                : ProductionMailboxRouteHistoryArtifactKind.ContinuityActivation, artifacts, used);
        if (link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
        {
            if (link.RevocationCheckpointIndex != ushort.MaxValue || link.TransitionContextIndex != ushort.MaxValue)
                throw new FormatException("RHB1 owner link must omit RCH1 and RTC1.");
        }
        else
        {
            Require(link.RevocationCheckpointIndex, ProductionMailboxRouteHistoryArtifactKind.RevocationCheckpoint,
                artifacts, used);
            Require(link.TransitionContextIndex, ProductionMailboxRouteHistoryArtifactKind.TransitionContext,
                artifacts, used);
        }
    }

    private static void Require(ushort index, ProductionMailboxRouteHistoryArtifactKind kind,
        IReadOnlyList<ProductionMailboxRouteHistoryArtifact> artifacts, bool[] used)
    {
        if (index >= artifacts.Count || artifacts[index].Kind != kind)
            throw new FormatException("RHB1 link artifact index or tag is invalid.");
        used[index] = true;
    }

    private static ushort ReadUInt16(byte[] value, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(offset, 2));

    private static ushort ReadUInt16(ReadOnlySpan<byte> value, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(value.Slice(offset, 2));

    private static void WriteUInt16(byte[] value, int offset, ushort item) =>
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(offset, 2), item);
}
