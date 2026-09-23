using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>Witness-private V2 transition, never an admission or freshness proof alone.</summary>
public sealed class ParsedDirectoryTransitionV2
{
    private readonly byte[] canonical;
    private readonly byte[] leafKey;
    private readonly byte[] previousReference;
    private readonly byte[] nextReference;
    private readonly byte[] previousMapRoot;
    private readonly byte[] nextMapRoot;

    internal ParsedDirectoryTransitionV2(ReadOnlySpan<byte> canonical, ulong logIndex,
        ReadOnlySpan<byte> leafKey, ReadOnlySpan<byte> previousReference,
        ReadOnlySpan<byte> nextReference, ReadOnlySpan<byte> previousMapRoot,
        ReadOnlySpan<byte> nextMapRoot)
    {
        this.canonical = canonical.ToArray();
        LogIndex = logIndex;
        this.leafKey = leafKey.ToArray();
        this.previousReference = previousReference.ToArray();
        this.nextReference = nextReference.ToArray();
        this.previousMapRoot = previousMapRoot.ToArray();
        this.nextMapRoot = nextMapRoot.ToArray();
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ulong LogIndex { get; }
    public ReadOnlyMemory<byte> DirectoryLeafKey => leafKey.ToArray();
    public ReadOnlyMemory<byte> PreviousAdc1Reference => previousReference.ToArray();
    public ReadOnlyMemory<byte> NextAdc1Reference => nextReference.ToArray();
    public ReadOnlyMemory<byte> PreviousMapRoot => previousMapRoot.ToArray();
    public ReadOnlyMemory<byte> NextMapRoot => nextMapRoot.ToArray();
    public ReadOnlyMemory<byte> Commitment => AccountDirectoryCrypto.Sha256Domain(
        "Deep/AccountDirectory/V2/transition", canonical);
    public ReadOnlyMemory<byte> AppendLogLeafHash => AccountDirectoryRfc6962.ComputeLeafHash(
        Commitment.Span);
}

public static class DeepIdV2DirectoryTransitionCodec
{
    public const ushort Version = 2;
    public const int CanonicalLength = 182;

    public static ParsedDirectoryTransitionV2 Decode(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length != CanonicalLength ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical) != Version)
            throw Invalid("Directory V2 transition length or version is invalid.");
        var leaf = canonical.Slice(10, 32);
        var previous = canonical.Slice(42, 38);
        var next = canonical.Slice(80, 38);
        var previousRoot = canonical.Slice(118, 32);
        var nextRoot = canonical.Slice(150, 32);
        ValidateAdcReference(previous, allowZero: true);
        ValidateAdcReference(next, allowZero: false);
        if (IsZero(leaf) || IsZero(previousRoot) || IsZero(nextRoot))
            throw Invalid("Directory V2 transition contains a zero leaf or map root.");
        return new ParsedDirectoryTransitionV2(canonical,
            BinaryPrimitives.ReadUInt64BigEndian(canonical[2..10]), leaf, previous,
            next, previousRoot, nextRoot);
    }

    public static ParsedDirectoryTransitionV2 Author(ulong logIndex,
        ReadOnlySpan<byte> directoryLeafKey32,
        ReadOnlySpan<byte> previousAdc1Reference38,
        ReadOnlySpan<byte> nextAdc1Reference38,
        ReadOnlySpan<byte> previousMapRoot32,
        ReadOnlySpan<byte> nextMapRoot32)
    {
        if (directoryLeafKey32.Length != 32 ||
            previousAdc1Reference38.Length != 38 ||
            nextAdc1Reference38.Length != 38 ||
            previousMapRoot32.Length != 32 || nextMapRoot32.Length != 32)
            throw new ArgumentException("Directory V2 transition fields have incorrect lengths.");
        var canonical = new byte[CanonicalLength];
        BinaryPrimitives.WriteUInt16BigEndian(canonical, Version);
        BinaryPrimitives.WriteUInt64BigEndian(canonical.AsSpan(2), logIndex);
        directoryLeafKey32.CopyTo(canonical.AsSpan(10));
        previousAdc1Reference38.CopyTo(canonical.AsSpan(42));
        nextAdc1Reference38.CopyTo(canonical.AsSpan(80));
        previousMapRoot32.CopyTo(canonical.AsSpan(118));
        nextMapRoot32.CopyTo(canonical.AsSpan(150));
        return Decode(canonical);
    }

    internal static void ValidateAdcReference(ReadOnlySpan<byte> reference, bool allowZero)
    {
        if (reference.Length != 38)
            throw Invalid("Directory V2 ADC1 reference length is invalid.");
        if (allowZero && IsZero(reference)) return;
        if (!reference[..4].SequenceEqual(ProtocolMagicBytes.ADC1) ||
            BinaryPrimitives.ReadUInt16BigEndian(reference[4..6]) != 2 ||
            IsZero(reference[6..]))
            throw Invalid("Directory V2 transition requires an exact ADC1 V2 reference.");
    }

    private static bool IsZero(ReadOnlySpan<byte> value) =>
        value.IndexOfAnyExcept((byte)0) < 0;

    private static AccountDirectoryAdp1FormatException Invalid(string message) => new(message);
}

/// <summary>V2 depth-256 sparse map; V1 roots and references cannot be mixed in.</summary>
public static class DeepIdV2DirectorySparseMap
{
    private const string EmptyLeafDomain = "Deep/AccountDirectory/V2/map-empty-leaf";
    private const string PresentDomain = "Deep/AccountDirectory/V2/map-present";
    private const string NodeDomain = "Deep/AccountDirectory/V2/map-node";
    private static readonly byte[][] Empty = BuildEmpty();

    public static ReadOnlyMemory<byte> EmptyMapRoot => Empty[256].ToArray();

    internal static byte[] ComputeFullMapRoot(
        IReadOnlyDictionary<string, byte[]> currentReferencesByHexLeaf)
    {
        var levels = BuildLevels(currentReferencesByHexLeaf);
        return currentReferencesByHexLeaf.Count == 0
            ? Empty[256].ToArray()
            : levels[256].Single().Value.ToArray();
    }

    internal static (byte[] Bitmap, byte[] Siblings) CreateProof(
        IReadOnlyDictionary<string, byte[]> currentReferencesByHexLeaf,
        ReadOnlySpan<byte> queriedLeafKey32)
    {
        Require(queriedLeafKey32, 32, nameof(queriedLeafKey32));
        if (queriedLeafKey32.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Directory V2 query key cannot be zero.",
                nameof(queriedLeafKey32));
        var levels = BuildLevels(currentReferencesByHexLeaf);
        var position = queriedLeafKey32.ToArray();
        var bitmap = new byte[32];
        var siblings = new List<byte>();
        for (var level = 0; level < 256; level++)
        {
            ToggleBit(position, 255 - level);
            var sibling = levels[level].GetValueOrDefault(
                Convert.ToHexString(position), Empty[level]);
            ToggleBit(position, 255 - level);
            if (!CryptographicOperations.FixedTimeEquals(sibling, Empty[level]))
            {
                bitmap[level / 8] |= checked((byte)(0x80 >> (level % 8)));
                siblings.AddRange(sibling);
            }
            ClearBit(position, 255 - level);
        }
        var query = Convert.ToHexString(queriedLeafKey32);
        var root = currentReferencesByHexLeaf.TryGetValue(query, out var reference)
            ? ComputePresentRoot(queriedLeafKey32, reference, bitmap,
                siblings.ToArray())
            : ComputeNonMembershipRoot(queriedLeafKey32, bitmap,
                siblings.ToArray());
        var expectedRoot = currentReferencesByHexLeaf.Count == 0
            ? Empty[256]
            : levels[256].Single().Value;
        if (!CryptographicOperations.FixedTimeEquals(root, expectedRoot))
            throw new CryptographicException(
                "Directory V2 sparse proof does not reconstruct its source map.");
        return (bitmap, siblings.ToArray());
    }

    public static byte[] ComputeNonMembershipRoot(ReadOnlySpan<byte> leafKey32,
        ReadOnlySpan<byte> bitmap32, ReadOnlySpan<byte> siblings) =>
        Compute(leafKey32, Empty[0], bitmap32, siblings);

    public static byte[] ComputePresentRoot(ReadOnlySpan<byte> leafKey32,
        ReadOnlySpan<byte> exactAdc1V2Reference38, ReadOnlySpan<byte> bitmap32,
        ReadOnlySpan<byte> siblings)
    {
        Require(leafKey32, 32, nameof(leafKey32));
        DeepIdV2DirectoryTransitionCodec.ValidateAdcReference(
            exactAdc1V2Reference38, allowZero: false);
        Span<byte> payload = stackalloc byte[70];
        leafKey32.CopyTo(payload);
        exactAdc1V2Reference38.CopyTo(payload[32..]);
        return Compute(leafKey32,
            AccountDirectoryCrypto.Sha256Domain(PresentDomain, payload),
            bitmap32, siblings);
    }

    private static byte[] Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> leaf,
        ReadOnlySpan<byte> bitmap, ReadOnlySpan<byte> siblings)
    {
        Require(key, 32, nameof(key));
        Require(bitmap, 32, nameof(bitmap));
        if (key.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Directory V2 leaf key cannot be zero.", nameof(key));
        var count = 0;
        foreach (var item in bitmap) count += BitOperations.PopCount(item);
        if (siblings.Length != checked(count * 32))
            throw new ArgumentException("Directory V2 siblings do not match bitmap.",
                nameof(siblings));
        var current = leaf.ToArray();
        var siblingOffset = 0;
        Span<byte> pair = stackalloc byte[64];
        for (var level = 0; level < 256; level++)
        {
            var supplied = (bitmap[level / 8] & (0x80 >> (level % 8))) != 0;
            var sibling = supplied ? siblings.Slice(siblingOffset, 32) : Empty[level];
            if (supplied)
            {
                if (CryptographicOperations.FixedTimeEquals(sibling, Empty[level]))
                    throw new ArgumentException(
                        "Directory V2 proof encodes a default sibling explicitly.",
                        nameof(siblings));
                siblingOffset += 32;
            }
            var keyIndex = 255 - level;
            var right = (key[keyIndex / 8] & (0x80 >> (keyIndex % 8))) != 0;
            if (right)
            {
                sibling.CopyTo(pair);
                current.CopyTo(pair[32..]);
            }
            else
            {
                current.CopyTo(pair);
                sibling.CopyTo(pair[32..]);
            }
            current = AccountDirectoryCrypto.Sha256Domain(NodeDomain, pair);
        }
        return current;
    }

    private static byte[][] BuildEmpty()
    {
        var empty = new byte[257][];
        empty[0] = AccountDirectoryCrypto.Sha256Domain(EmptyLeafDomain, []);
        Span<byte> pair = stackalloc byte[64];
        for (var level = 0; level < 256; level++)
        {
            empty[level].CopyTo(pair);
            empty[level].CopyTo(pair[32..]);
            empty[level + 1] = AccountDirectoryCrypto.Sha256Domain(NodeDomain, pair);
        }
        return empty;
    }

    private static Dictionary<string, byte[]>[] BuildLevels(
        IReadOnlyDictionary<string, byte[]> map)
    {
        ArgumentNullException.ThrowIfNull(map);
        if (map.Count > 1_000_000)
            throw new ArgumentOutOfRangeException(nameof(map));
        var levels = new Dictionary<string, byte[]>[257];
        var leaves = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        Span<byte> payload = stackalloc byte[70];
        Span<byte> pair = stackalloc byte[64];
        foreach (var entry in map)
        {
            if (entry.Key.Length != 64)
                throw new ArgumentException("Directory V2 leaf keys must be canonical hex.",
                    nameof(map));
            byte[] key;
            try { key = Convert.FromHexString(entry.Key); }
            catch (FormatException exception)
            { throw new ArgumentException("Directory V2 leaf key is not hex.",
                nameof(map), exception); }
            if (!string.Equals(Convert.ToHexString(key), entry.Key,
                    StringComparison.Ordinal))
                throw new ArgumentException("Directory V2 leaf key is not canonical hex.",
                    nameof(map));
            if (key.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                throw new ArgumentException("Directory V2 leaf key cannot be zero.",
                    nameof(map));
            ValidateReference(entry.Value);
            key.AsSpan().CopyTo(payload);
            entry.Value.AsSpan().CopyTo(payload[32..]);
            leaves.Add(entry.Key, AccountDirectoryCrypto.Sha256Domain(
                PresentDomain, payload));
        }
        levels[0] = leaves;
        for (var level = 0; level < 256; level++)
        {
            var current = levels[level];
            var next = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            var consumed = new HashSet<string>(StringComparer.Ordinal);
            foreach (var entry in current)
            {
                if (!consumed.Add(entry.Key)) continue;
                var position = Convert.FromHexString(entry.Key);
                ToggleBit(position, 255 - level);
                var siblingKey = Convert.ToHexString(position);
                var sibling = current.GetValueOrDefault(siblingKey, Empty[level]);
                consumed.Add(siblingKey);
                ToggleBit(position, 255 - level);
                if (Bit(position, 255 - level))
                {
                    sibling.AsSpan().CopyTo(pair);
                    entry.Value.AsSpan().CopyTo(pair[32..]);
                }
                else
                {
                    entry.Value.AsSpan().CopyTo(pair);
                    sibling.AsSpan().CopyTo(pair[32..]);
                }
                next.Add(Convert.ToHexString(Cleared(position, 255 - level)),
                    AccountDirectoryCrypto.Sha256Domain(NodeDomain, pair));
            }
            levels[level + 1] = next;
        }
        return levels;
    }

    private static void ValidateReference(byte[]? reference)
    {
        if (reference is null)
            throw new ArgumentException("Directory V2 map reference is null.");
        DeepIdV2DirectoryTransitionCodec.ValidateAdcReference(reference,
            allowZero: false);
    }

    private static byte[] Cleared(byte[] position, int bit)
    {
        ClearBit(position, bit);
        return position;
    }

    private static bool Bit(ReadOnlySpan<byte> value, int bit) =>
        (value[bit / 8] & (0x80 >> (bit % 8))) != 0;

    private static void ToggleBit(Span<byte> value, int bit) =>
        value[bit / 8] ^= checked((byte)(0x80 >> (bit % 8)));

    private static void ClearBit(Span<byte> value, int bit) =>
        value[bit / 8] &= unchecked((byte)~(0x80 >> (bit % 8)));

    private static void Require(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw new ArgumentException($"{name} must be exactly {length} bytes.", name);
    }
}
