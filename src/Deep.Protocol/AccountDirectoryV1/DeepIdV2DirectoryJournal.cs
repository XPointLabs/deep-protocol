using System.Security.Cryptography;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Replays an authority-private V2 transition journal against an already
/// authenticated and protected ADH1 head. It never promotes a raw head.
/// </summary>
internal static class DeepIdV2DirectoryJournal
{
    internal static IReadOnlyDictionary<string, byte[]> ReplayAndVerify(
        AccountDirectoryProtectedLkg protectedHead,
        IReadOnlyList<ReadOnlyMemory<byte>> exactTransitions) =>
        ReplayHistoryAndVerify([protectedHead],exactTransitions);

    internal static IReadOnlyDictionary<string, byte[]> ReplayHistoryAndVerify(
        IReadOnlyList<AccountDirectoryProtectedLkg> heads,
        IReadOnlyList<ReadOnlyMemory<byte>> exactTransitions,
        IReadOnlyList<VerifiedAdc1V2>? orderedCheckpoints = null)
    {
        ArgumentNullException.ThrowIfNull(heads);
        ArgumentNullException.ThrowIfNull(exactTransitions);
        if (heads.Count is < 1 or > 1_000_000) throw new ArgumentException("V2 history is unbounded.");
        var protectedHead = heads[^1];
        if (protectedHead.Head.MinimumReader < 2 ||
            exactTransitions.Count > 1_000_000 ||
            (ulong)exactTransitions.Count != protectedHead.TreeSize)
            throw new CryptographicException(
                "The V2 journal and protected ADH1 reader/tree-size floor disagree.");

        var map = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var leaves = new byte[exactTransitions.Count][];
        var sparse = new DeepIdV2DirectorySparseMap.Accumulator();
        var nextHead = 0;
        VerifyPrefix(0);
        for (var index = 0; index < exactTransitions.Count; index++)
        {
            var transition = DeepIdV2DirectoryTransitionCodec.Decode(
                exactTransitions[index].Span);
            if (transition.LogIndex != (ulong)index)
                throw new CryptographicException(
                    "The V2 directory journal has a non-contiguous log index.");
            var key = Convert.ToHexString(transition.DirectoryLeafKey.Span);
            var previousReference = map.TryGetValue(key, out var current)
                ? current
                : new byte[38];
            if (!Fixed(previousReference, transition.PreviousAdc1Reference.Span) ||
                !Fixed(sparse.Root, transition.PreviousMapRoot.Span))
                throw new CryptographicException(
                    "The V2 directory transition does not consume its predecessor.");
            map[key] = transition.NextAdc1Reference.ToArray();
            sparse.Update(transition.DirectoryLeafKey.Span,transition.NextAdc1Reference.Span);
            if (!Fixed(sparse.Root, transition.NextMapRoot.Span))
                throw new CryptographicException(
                    "The V2 directory transition does not produce its committed map root.");
            leaves[index] = transition.AppendLogLeafHash.ToArray();
            VerifyPrefix(index+1);
        }

        var appendRoot = ComputeAppendRoot(leaves);
        var mapRoot = sparse.Root;
        if (!Fixed(appendRoot, protectedHead.AppendLogMerkleRoot.Span) ||
            !Fixed(mapRoot, protectedHead.CurrentValueMapRoot.Span))
            throw new CryptographicException(
                "The complete V2 journal differs from the protected ADH1 roots.");
        return map.ToDictionary(static entry => entry.Key,
            static entry => entry.Value.ToArray(), StringComparer.Ordinal);

        void VerifyPrefix(int count)
        {
            if (nextHead < heads.Count && heads[nextHead].TreeSize < (ulong)count)
                throw new CryptographicException("V2 historical tree sizes regress.");
            byte[]? append = null;
            while (nextHead < heads.Count && heads[nextHead].TreeSize == (ulong)count) {
                var head = heads[nextHead++];
                append ??= count==0 ? AccountDirectoryRfc6962.ComputeEmptyTreeHash() : TreeHash(leaves,0,count);
                if (head.Head.MinimumReader != 2 || !Fixed(head.Head.NetworkId.Span,protectedHead.Head.NetworkId.Span) ||
                    !Fixed(append,head.AppendLogMerkleRoot.Span) || !Fixed(sparse.Root,head.CurrentValueMapRoot.Span))
                    throw new CryptographicException("V2 historical head differs from its exact journal prefix.");
                if (orderedCheckpoints is not null) {
                    if (Math.Min(count,orderedCheckpoints.Count)!=map.Count)
                        throw new CryptographicException("V2 historical checkpoint prefix is incomplete.");
                    var seen = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var capability in orderedCheckpoints.Take(count)) {
                        if (capability is null || !Fixed(capability.Checkpoint.NetworkId.Span,head.Head.NetworkId.Span))
                            throw new CryptographicException("V2 historical checkpoint prefix is cross-network.");
                        var key = Convert.ToHexString(capability.Checkpoint.DirectoryLeafKey.Span);
                        if (!seen.Add(key) || !map.TryGetValue(key,out var reference) || !Fixed(reference,capability.Checkpoint.ArtifactReference.Span))
                            throw new CryptographicException("V2 historical checkpoint prefix differs from its journal.");
                    }
                }
            }
            if (count==exactTransitions.Count && nextHead!=heads.Count)
                throw new CryptographicException("V2 history exceeds its verified journal.");
        }
    }

    internal static byte[] ComputeAppendRoot(
        IReadOnlyList<ReadOnlyMemory<byte>> exactTransitions)
    {
        ArgumentNullException.ThrowIfNull(exactTransitions);
        if (exactTransitions.Count > 1_000_000)
            throw new ArgumentOutOfRangeException(nameof(exactTransitions));
        var leaves = new byte[exactTransitions.Count][];
        for (var index = 0; index < exactTransitions.Count; index++)
        {
            var transition = DeepIdV2DirectoryTransitionCodec.Decode(
                exactTransitions[index].Span);
            if (transition.LogIndex != (ulong)index)
                throw new CryptographicException(
                    "The V2 directory append log has a non-contiguous index.");
            leaves[index] = transition.AppendLogLeafHash.ToArray();
        }
        return ComputeAppendRoot(leaves);
    }

    private static byte[] ComputeAppendRoot(IReadOnlyList<byte[]> leaves) =>
        leaves.Count == 0
            ? AccountDirectoryRfc6962.ComputeEmptyTreeHash()
            : TreeHash(leaves, 0, leaves.Count);

    private static byte[] TreeHash(IReadOnlyList<byte[]> leaves,
        int offset, int count)
    {
        if (count == 1) return leaves[offset].ToArray();
        var split = 1;
        while (checked(split * 2) < count) split *= 2;
        return AccountDirectoryRfc6962.ComputeNodeHash(
            TreeHash(leaves, offset, split),
            TreeHash(leaves, offset + split, count - split));
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
