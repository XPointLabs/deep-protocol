using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.XPointNetworkV1;

internal sealed class XPointNetworkViewAppendProof
{
    internal XPointNetworkViewAppendProof(byte[] root, IReadOnlyList<byte[]> consistencyNodes)
    {
        Root = root.ToArray();
        ConsistencyNodes = consistencyNodes.Select(static value => value.ToArray()).ToArray();
    }

    internal byte[] Root { get; }
    internal IReadOnlyList<byte[]> ConsistencyNodes { get; }
}

/// <summary>
/// Authors the exact RFC-6962 one-view append material for XNH1. The caller must
/// separately authenticate the protected head and threshold-sign the successor;
/// this helper proves that its supplied history is the protected prefix.
/// </summary>
internal static class XPointNetworkViewLogAuthor
{
    private const int MaximumHistoryViews = 4_096;

    internal static XPointNetworkViewAppendProof BuildAppendProof(
        IReadOnlyList<ReadOnlyMemory<byte>> exactAcceptedViews,
        ReadOnlySpan<byte> exactProtectedHead,
        ReadOnlySpan<byte> exactSuccessorView)
    {
        ArgumentNullException.ThrowIfNull(exactAcceptedViews);
        if (exactAcceptedViews.Count is < 1 or > MaximumHistoryViews)
            throw new ArgumentException("The bounded accepted view history is empty or too long.", nameof(exactAcceptedViews));

        var head = XPointNetworkCodec.Parse<Xnh1Record>(exactProtectedHead);
        var successor = XPointNetworkCodec.Parse<Xnv1Record>(exactSuccessorView);
        var (previous, leaves) = RestoreProtectedPrefix(exactAcceptedViews, head);
        XPointNetworkVerifier.RequireSuccessor(previous, successor);
        if (!successor.NetworkId.Equals(head.NetworkId) ||
            !successor.AuthorizingXna.Equals(head.AuthorizingXna) ||
            !successor.DirectoryWitnessPolicyHash.Equals(head.DirectoryWitnessPolicyHash))
            throw new CryptographicException("The successor view changes the protected network authority.");
        var appendedLeaf = ViewLeaf(successor);
        leaves.Add(appendedLeaf);
        var root = TreeHash(leaves, 0, leaves.Count);
        var nodes = new List<byte[]>();
        AppendConsistencySubproof(leaves, exactAcceptedViews.Count, 0, leaves.Count, true, nodes);
        var flattened = nodes.SelectMany(static value => value).ToArray();
        if (nodes.Count > 64 || !nodes.Any(value => value.AsSpan().SequenceEqual(appendedLeaf)))
            throw new CryptographicException("The XNH1 append proof is too long or omits the new leaf.");
        XPointMerkleProofs.VerifyConsistency(
            head.TreeSize, checked(head.TreeSize + 1), head.Root.Span, root, flattened, nodes.Count);
        return new XPointNetworkViewAppendProof(root, nodes);
    }

    internal static void RequireProtectedPrefix(IReadOnlyList<ReadOnlyMemory<byte>> exactAcceptedViews,
        ReadOnlySpan<byte> exactProtectedHead) =>
        _ = RestoreProtectedPrefix(exactAcceptedViews, XPointNetworkCodec.Parse<Xnh1Record>(exactProtectedHead));

    private static (Xnv1Record Previous, List<byte[]> Leaves) RestoreProtectedPrefix(
        IReadOnlyList<ReadOnlyMemory<byte>> exactAcceptedViews, Xnh1Record head)
    {
        if (exactAcceptedViews.Count is < 1 or > MaximumHistoryViews)
            throw new ArgumentException("The bounded accepted view history is empty or too long.");
        if (head.TreeSize != checked((ulong)exactAcceptedViews.Count))
            throw new CryptographicException("The protected head does not cover the exact accepted view history.");

        var accepted = new Xnv1Record[exactAcceptedViews.Count];
        var leaves = new List<byte[]>(exactAcceptedViews.Count + 1);
        for (var index = 0; index < exactAcceptedViews.Count; index++)
        {
            var view = XPointNetworkCodec.Parse<Xnv1Record>(exactAcceptedViews[index].Span);
            if (view.ViewGeneration != checked((ulong)index) ||
                !view.NetworkId.Equals(head.NetworkId) ||
                !view.AuthorizingXna.Equals(head.AuthorizingXna) ||
                !view.DirectoryWitnessPolicyHash.Equals(head.DirectoryWitnessPolicyHash) ||
                (index == 0 && view.FieldSpan(3).IndexOfAnyExcept((byte)0) >= 0))
                throw new CryptographicException("The accepted view history is not a canonical network lineage.");
            if (index > 0)
                XPointNetworkVerifier.RequireSuccessor(accepted[index - 1], view);
            accepted[index] = view;
            leaves.Add(ViewLeaf(view));
        }

        var previous = accepted[^1];
        if (head.LogGeneration != previous.ViewGeneration ||
            !head.LatestView.Equals(previous.CoreReferenceValue) ||
            head.LatestViewGeneration != previous.ViewGeneration ||
            !CryptographicOperations.FixedTimeEquals(
                TreeHash(leaves, 0, leaves.Count), head.Root.Span))
            throw new CryptographicException("The accepted views do not reconstruct the protected XNH1 root.");
        return (previous, leaves);
    }

    private static byte[] ViewLeaf(Xnv1Record view)
    {
        Span<byte> payload = stackalloc byte[72];
        BinaryPrimitives.WriteUInt64BigEndian(payload, view.ViewGeneration);
        view.FieldSpan(3).CopyTo(payload[8..40]);
        view.CoreHash.Span.CopyTo(payload[40..]);
        return XPointNetworkCrypto.Rfc6962Leaf(payload);
    }

    private static byte[] TreeHash(IReadOnlyList<byte[]> leaves, int offset, int count)
    {
        if (count == 1) return leaves[offset].ToArray();
        var split = LargestPowerOfTwoLessThan(count);
        return XPointNetworkCrypto.Rfc6962Inner(
            TreeHash(leaves, offset, split), TreeHash(leaves, offset + split, count - split));
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
            AppendConsistencySubproof(leaves, oldSize, offset, split, completeSubtree, output);
            output.Add(TreeHash(leaves, offset + split, count - split));
        }
        else
        {
            AppendConsistencySubproof(leaves, oldSize - split, offset + split, count - split, false, output);
            output.Add(TreeHash(leaves, offset, split));
        }
    }

    private static int LargestPowerOfTwoLessThan(int count)
    {
        var value = 1;
        while (value <= (count - 1) / 2) value <<= 1;
        return value;
    }
}
