using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Restores the separately pinned, threshold-signed empty DID2 directory head.
/// A V1 empty-map head cannot serve as the V2 journal's genesis floor.
/// </summary>
public static class DeepIdV2DirectoryBootstrapVerifier
{
    public static AccountDirectoryProtectedLkg RestoreGenesis(
        VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlySpan<byte> protectedAdh1CoreHash)
    {
        var restored = AccountDirectoryProtectedLkgFactory.Restore(
            authority, exactAdh1, protectedAdh1CoreHash);
        var head = restored.Head;
        if (head.MinimumReader < 2 || head.LogGeneration != 0 ||
            head.TreeSize != 0 ||
            head.PredecessorAdh1CoreHash.Span.IndexOfAnyExcept((byte)0) >= 0 ||
            !Fixed(head.AppendLogMerkleRoot.Span,
                AccountDirectoryRfc6962.ComputeEmptyTreeHash()) ||
            !Fixed(head.CurrentValueMapRoot.Span,
                DeepIdV2DirectorySparseMap.EmptyMapRoot.Span))
            throw new AccountDirectoryFreshnessVerificationException(
                "InvalidDid2Bootstrap",
                "The protected ADH1 is not the signed empty DID2 directory genesis.");
        return restored;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
