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

    private static void Require(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw new ArgumentException($"{name} must be exactly {length} bytes.", name);
    }
}
