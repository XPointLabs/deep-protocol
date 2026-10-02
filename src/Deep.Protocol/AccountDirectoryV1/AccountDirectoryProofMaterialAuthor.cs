using System.Numerics;
using System.Security.Cryptography;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Replays an authority-private ADT1 journal and derives the minimal canonical
/// sparse-map, inclusion and consistency proof material for one query. Raw
/// identity bytes can enter the result only through verifier-minted checkpoint
/// capabilities.
/// </summary>
public static class AccountDirectoryProofMaterialAuthor
{
    private const string TransitionDomain = "Deep/AccountDirectory/V1/transition";
    private static readonly byte[][] SparseEmpty = BuildSparseEmpty();

    internal static ReadOnlyMemory<byte>[] BuildConsistencyProof(
        AccountDirectoryProtectedLkg? caller,
        AccountDirectoryProtectedLkg current,
        IReadOnlyList<byte[]> leaves)
    {
        if (caller is null)
            return [];
        if (!Fixed(caller.Head.NetworkId.Span, current.Head.NetworkId.Span) ||
            caller.TreeSize > current.TreeSize)
            throw new CryptographicException("The caller LKG is outside the current directory history.");
        if (caller.TreeSize == current.TreeSize)
        {
            if (!Fixed(caller.AppendLogMerkleRoot.Span, current.AppendLogMerkleRoot.Span))
                throw new CryptographicException("Equal-size directory heads have different append roots.");
            return [];
        }
        if (caller.TreeSize == 0)
        {
            if (!Fixed(caller.AppendLogMerkleRoot.Span,
                    AccountDirectoryRfc6962.ComputeEmptyTreeHash()))
                throw new CryptographicException("The caller genesis LKG has a non-empty append root.");
            return [];
        }
        var oldSize = checked((int)caller.TreeSize);
        var oldRoot = TreeHash(leaves, 0, oldSize);
        if (!Fixed(oldRoot, caller.AppendLogMerkleRoot.Span))
            throw new CryptographicException("The caller LKG is not a prefix of the authority journal.");
        var nodes = new List<byte[]>();
        AppendConsistencySubproof(leaves, oldSize, 0, leaves.Count, true, nodes);
        var encoded = Join(nodes);
        if (!AccountDirectoryRfc6962.VerifyConsistency(
                caller.TreeSize, current.TreeSize,
                caller.AppendLogMerkleRoot.Span, current.AppendLogMerkleRoot.Span, encoded))
            throw new CryptographicException("The authored append-log consistency proof did not verify.");
        return nodes.Select(static value => (ReadOnlyMemory<byte>)value).ToArray();
    }

    private static void AppendConsistencySubproof(
        IReadOnlyList<byte[]> leaves,
        int oldSize,
        int offset,
        int count,
        bool completeSubtree,
        ICollection<byte[]> output)
    {
        if (oldSize == count)
        {
            if (!completeSubtree)
                output.Add(TreeHash(leaves, offset, count));
            return;
        }
        var split = LargestPowerOfTwoLessThan(count);
        if (oldSize <= split)
        {
            AppendConsistencySubproof(
                leaves, oldSize, offset, split, completeSubtree, output);
            output.Add(TreeHash(leaves, offset + split, count - split));
        }
        else
        {
            AppendConsistencySubproof(
                leaves, oldSize - split, offset + split, count - split, false, output);
            output.Add(TreeHash(leaves, offset, split));
        }
    }

    internal static ReadOnlyMemory<byte>[] BuildInclusionProof(
        IReadOnlyList<byte[]> leaves,
        int leafIndex)
    {
        var nodes = new List<byte[]>();
        AppendInclusionProof(leaves, leafIndex, 0, leaves.Count, nodes);
        var encoded = Join(nodes);
        var root = TreeHash(leaves, 0, leaves.Count);
        if (!AccountDirectoryRfc6962.VerifyInclusion(
                leaves[leafIndex], checked((ulong)leafIndex), checked((ulong)leaves.Count),
                encoded, root))
            throw new CryptographicException("The authored append-log inclusion proof did not verify.");
        return nodes.Select(static value => (ReadOnlyMemory<byte>)value).ToArray();
    }

    private static void AppendInclusionProof(
        IReadOnlyList<byte[]> leaves,
        int leafIndex,
        int offset,
        int count,
        ICollection<byte[]> output)
    {
        if (count == 1)
            return;
        var split = LargestPowerOfTwoLessThan(count);
        if (leafIndex < split)
        {
            AppendInclusionProof(leaves, leafIndex, offset, split, output);
            output.Add(TreeHash(leaves, offset + split, count - split));
        }
        else
        {
            AppendInclusionProof(leaves, leafIndex - split, offset + split, count - split, output);
            output.Add(TreeHash(leaves, offset, split));
        }
    }

    private static SparseProof BuildSparseProof(
        IReadOnlyDictionary<string, byte[]> map,
        ReadOnlySpan<byte> query)
    {
        var levels = BuildSparseLevels(map);
        var position = query.ToArray();
        var bitmap = new byte[32];
        var siblings = new List<ReadOnlyMemory<byte>>();
        for (var level = 0; level < 256; level++)
        {
            ToggleBit(position, 255 - level);
            var sibling = levels[level].GetValueOrDefault(
                Convert.ToHexString(position), SparseEmpty[level]);
            ToggleBit(position, 255 - level);
            if (!Fixed(sibling, SparseEmpty[level]))
            {
                bitmap[level / 8] |= checked((byte)(0x80 >> (level % 8)));
                siblings.Add(sibling.ToArray());
            }
            ClearBit(position, 255 - level);
        }
        if (siblings.Count != bitmap.Sum(static value => BitOperations.PopCount(value)))
            throw new CryptographicException("The authored sparse-map proof is non-canonical.");
        return new SparseProof(bitmap, siblings.ToArray());
    }

    private static byte[] ComputeSparseRoot(IReadOnlyDictionary<string, byte[]> map) =>
        map.Count == 0
            ? SparseEmpty[256].ToArray()
            : BuildSparseLevels(map)[256].Single().Value.ToArray();

    private static Dictionary<string, byte[]>[] BuildSparseLevels(
        IReadOnlyDictionary<string, byte[]> map)
    {
        var levels = new Dictionary<string, byte[]>[257];
        levels[0] = map.ToDictionary(
            static entry => entry.Key,
            static entry => PresentLeaf(Convert.FromHexString(entry.Key), entry.Value),
            StringComparer.Ordinal);
        for (var level = 0; level < 256; level++)
        {
            var current = levels[level];
            var next = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            var consumed = new HashSet<string>(StringComparer.Ordinal);
            foreach (var entry in current)
            {
                if (!consumed.Add(entry.Key))
                    continue;
                var position = Convert.FromHexString(entry.Key);
                ToggleBit(position, 255 - level);
                var siblingKey = Convert.ToHexString(position);
                var sibling = current.GetValueOrDefault(siblingKey, SparseEmpty[level]);
                consumed.Add(siblingKey);
                ToggleBit(position, 255 - level);
                var parent = Bit(position, 255 - level)
                    ? SparseNode(sibling, entry.Value)
                    : SparseNode(entry.Value, sibling);
                ClearBit(position, 255 - level);
                next.Add(Convert.ToHexString(position), parent);
            }
            levels[level + 1] = next;
        }
        return levels;
    }

    internal static byte[] TreeHash(IReadOnlyList<byte[]> leaves, int offset, int count)
    {
        if (count == 1)
            return leaves[offset].ToArray();
        var split = LargestPowerOfTwoLessThan(count);
        return AccountDirectoryRfc6962.ComputeNodeHash(
            TreeHash(leaves, offset, split),
            TreeHash(leaves, offset + split, count - split));
    }

    private static int LargestPowerOfTwoLessThan(int value)
    {
        var result = 1;
        while (checked(result * 2) < value)
            result *= 2;
        return result;
    }

    private static byte[] CheckpointReference(AccountDirectoryAdc1 checkpoint) =>
        AccountDirectoryCrypto.CreateReference(
            ProtocolMagicBytes.ADC1, 1, SHA256.HashData(AccountDirectoryAdc1Codec.Encode(checkpoint)));

    private static byte[] PresentLeaf(ReadOnlySpan<byte> key, ReadOnlySpan<byte> reference)
    {
        Span<byte> payload = stackalloc byte[70];
        key.CopyTo(payload);
        reference.CopyTo(payload[32..]);
        return AccountDirectoryCrypto.Sha256Domain(
            "Deep/AccountDirectory/V1/map-present", payload);
    }

    private static byte[] SparseNode(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        Span<byte> pair = stackalloc byte[64];
        left.CopyTo(pair);
        right.CopyTo(pair[32..]);
        return AccountDirectoryCrypto.Sha256Domain(
            "Deep/AccountDirectory/V1/map-node", pair);
    }

    private static byte[][] BuildSparseEmpty()
    {
        var result = new byte[257][];
        result[0] = AccountDirectoryCrypto.Sha256Domain(
            "Deep/AccountDirectory/V1/map-empty-leaf", []);
        Span<byte> pair = stackalloc byte[64];
        for (var index = 0; index < 256; index++)
        {
            result[index].CopyTo(pair);
            result[index].CopyTo(pair[32..]);
            result[index + 1] = AccountDirectoryCrypto.Sha256Domain(
                "Deep/AccountDirectory/V1/map-node", pair);
        }
        return result;
    }

    private static byte[] Join(IEnumerable<byte[]> values)
    {
        var items = values.ToArray();
        var result = new byte[checked(items.Length * 32)];
        for (var index = 0; index < items.Length; index++)
            items[index].CopyTo(result, index * 32);
        return result;
    }

    private static bool Bit(ReadOnlySpan<byte> value, int bit) =>
        (value[bit / 8] & (0x80 >> (bit % 8))) != 0;

    private static void ToggleBit(Span<byte> value, int bit) =>
        value[bit / 8] ^= checked((byte)(0x80 >> (bit % 8)));

    private static void ClearBit(Span<byte> value, int bit) =>
        value[bit / 8] &= unchecked((byte)~(0x80 >> (bit % 8)));

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private sealed record SparseProof(
        byte[] Bitmap,
        ReadOnlyMemory<byte>[] Siblings);
}
