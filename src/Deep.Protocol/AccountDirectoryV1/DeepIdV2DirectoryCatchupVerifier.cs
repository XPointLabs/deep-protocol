using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>Historical lineage only; never a freshness or operation capability.</summary>
public sealed class VerifiedDeepIdV2DirectoryCatchup
{
    internal VerifiedDeepIdV2DirectoryCatchup(AccountDirectoryProtectedLkg prior,
        AccountDirectoryProtectedLkg next)
    {
        PriorProtectedLkg = prior;
        ProtectedLkg = next;
    }

    public AccountDirectoryProtectedLkg PriorProtectedLkg { get; }
    public AccountDirectoryProtectedLkg ProtectedLkg { get; }
}

/// <summary>
/// Advances authenticated history in bounded pages, independently of wall time.
/// Expired signed heads remain history, not current account/network authority.
/// </summary>
public static class DeepIdV2DirectoryCatchupVerifier
{
    public static VerifiedDeepIdV2DirectoryCatchup Verify(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProtectedLkg protectedSource,
        IReadOnlyList<ReadOnlyMemory<byte>> exactSuccessors,
        ReadOnlyMemory<byte> consistencyNodes)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(protectedSource);
        ArgumentNullException.ThrowIfNull(exactSuccessors);
        if (exactSuccessors.Count is < 1 or > 64 ||
            consistencyNodes.Length % 32 != 0 || consistencyNodes.Length > 64 * 32 ||
            exactSuccessors.Any(static bytes => bytes.Length is < 1 or > 4_096))
            throw new ArgumentException("Historical directory page is empty or unbounded.");
        var owned = exactSuccessors.Select(static bytes => bytes.ToArray()).ToArray();
        var proof = consistencyNodes.ToArray();
        var source = AccountDirectoryProtectedLkgFactory.Restore(authority,
            protectedSource.ExactAdh1, protectedSource.CoreHash.Span);
        RequireReader(source);
        var previous = source;
        foreach (var exact in owned)
        {
            var head = AccountDirectoryAdh1Codec.Decode(exact);
            var next = AccountDirectoryProtectedLkgFactory.Restore(authority,
                exact, AccountDirectoryCrypto.ComputeAdh1CoreHash(head));
            RequireReader(next);
            if (previous.LogGeneration == ulong.MaxValue ||
                next.LogGeneration != previous.LogGeneration + 1 ||
                !Fixed(next.Head.PredecessorAdh1CoreHash.Span, previous.CoreHash.Span) ||
                next.TreeSize < previous.TreeSize ||
                next.TreeSize == previous.TreeSize &&
                (!Fixed(next.AppendLogMerkleRoot.Span, previous.AppendLogMerkleRoot.Span) ||
                 !Fixed(next.CurrentValueMapRoot.Span, previous.CurrentValueMapRoot.Span)))
                throw new CryptographicException("Historical directory page does not consume its exact protected lineage.");
            previous = next;
        }
        if (!AccountDirectoryRfc6962.VerifyConsistency(source.TreeSize,
                previous.TreeSize, source.AppendLogMerkleRoot.Span,
                previous.AppendLogMerkleRoot.Span, proof))
            throw new CryptographicException("Historical directory page append log is inconsistent with its protected source.");
        return new VerifiedDeepIdV2DirectoryCatchup(source, previous);
    }

    private static void RequireReader(AccountDirectoryProtectedLkg head)
    {
        if (head.Head.MinimumReader != 2)
            throw new CryptographicException("Historical DID2 catch-up requires the supported reader-2 lineage.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
