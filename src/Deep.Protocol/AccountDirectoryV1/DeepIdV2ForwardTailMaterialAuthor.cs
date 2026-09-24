using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Builds untrusted DID2 forward inputs from a complete restored ADA2 lineage
/// and externally imported, already root-signed ADF1 records. It never holds
/// a root private key. Final issuer self-verification authenticates the full
/// package against the live DTT1 before any result is released.
/// </summary>
public static class DeepIdV2ForwardTailMaterialAuthor
{
    public static DeepIdV2ForwardTailAuthoringInput Create(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<AccountDirectoryProtectedLkg> orderedHeads,
        IReadOnlyList<ReadOnlyMemory<byte>> exactTransitions,
        IReadOnlyList<VerifiedAdc1V2> currentCheckpoints,
        ReadOnlySpan<byte> queriedDirectoryLeafKey,
        AccountDirectoryProtectedLkg callerProtectedLkg,
        IReadOnlyList<ReadOnlyMemory<byte>> exactAdf1Chain)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(orderedHeads);
        ArgumentNullException.ThrowIfNull(exactTransitions);
        ArgumentNullException.ThrowIfNull(currentCheckpoints);
        ArgumentNullException.ThrowIfNull(callerProtectedLkg);
        ArgumentNullException.ThrowIfNull(exactAdf1Chain);
        if (orderedHeads.Count is < 2 or > 1_000_000 ||
            exactAdf1Chain.Count is < 1 or > 64 ||
            queriedDirectoryLeafKey.Length != 32)
            throw new CryptographicException(
                "DID2 forward-tail authority history exceeds its bounds.");
        var current = orderedHeads[^1];
        if (!Fixed(current.Head.NetworkId.Span, authority.NetworkId.Span) ||
            !orderedHeads.Any(head =>
                Fixed(head.ExactAdh1.Span,
                    callerProtectedLkg.ExactAdh1.Span)))
            throw new CryptographicException(
                "The protected DID2 floor is outside the restored lineage.");
        for (var index = 1; index < orderedHeads.Count; index++)
        {
            var prior = orderedHeads[index - 1];
            var next = orderedHeads[index];
            if (prior.LogGeneration == ulong.MaxValue ||
                next.LogGeneration != prior.LogGeneration + 1 ||
                !Fixed(next.Head.PredecessorAdh1CoreHash.Span,
                    prior.CoreHash.Span) ||
                !Fixed(next.Head.NetworkId.Span,
                    authority.NetworkId.Span))
                throw new CryptographicException(
                    "The restored DID2 head lineage is incomplete.");
        }

        var checkpoints = exactAdf1Chain.Select(static value =>
            AccountDirectoryAdf1Codec.Decode(value.Span)).ToArray();
        var covered = new AccountDirectoryProtectedLkg[checkpoints.Length][];
        var targetHeads = new ReadOnlyMemory<byte>[checkpoints.Length];
        var previousTargetIndex = -1;
        for (var index = 0; index < checkpoints.Length; index++)
        {
            var checkpoint = checkpoints[index];
            if (checkpoint.CheckpointGeneration != (ulong)index ||
                !Fixed(checkpoint.NetworkId.Span,
                    authority.NetworkId.Span) ||
                index == 0 && !Zero(checkpoint.PredecessorCoreHash.Span) ||
                index > 0 && !Fixed(checkpoint.PredecessorCoreHash.Span,
                    AccountDirectoryCrypto.ComputeAdf1CoreHash(
                        checkpoints[index - 1])))
                throw new CryptographicException(
                    "The root-signed ADF1 predecessor chain is incomplete.");
            covered[index] = orderedHeads.Where(head =>
                head.LogGeneration >= checkpoint.CoveredFirstAdhGeneration &&
                head.LogGeneration <= checkpoint.CoveredLastAdhGeneration)
                .ToArray();
            if (covered[index].Length == 0 ||
                (ulong)covered[index].Length != checkpoint.CoveredHeadCount)
                throw new CryptographicException(
                    "The ADF1 covered-head set is incomplete.");
            var coveredLeaves = covered[index].Select(CoveredLeaf).ToArray();
            if (!Fixed(AccountDirectoryProofMaterialAuthor.TreeHash(
                    coveredLeaves, 0, coveredLeaves.Length),
                    checkpoint.CoveredHeadMerkleRoot.Span))
                throw new CryptographicException(
                    "The ADF1 covered-head Merkle root differs from ADA2 history.");
            var targetIndex = -1;
            for (var candidate = previousTargetIndex + 1;
                 candidate < orderedHeads.Count; candidate++)
            {
                if (Fixed(checkpoint.TargetAdh1CoreReference.Span[6..],
                        orderedHeads[candidate].CoreHash.Span))
                { targetIndex = candidate; break; }
            }
            if (targetIndex < 0 ||
                orderedHeads[targetIndex].LogGeneration <=
                    checkpoint.CoveredLastAdhGeneration)
                throw new CryptographicException(
                    "The ADF1 target is absent from the restored DID2 lineage.");
            targetHeads[index] = orderedHeads[targetIndex].ExactAdh1;
            previousTargetIndex = targetIndex;
        }

        var anchor = orderedHeads[previousTargetIndex];
        var tailCount = orderedHeads.Count - previousTargetIndex - 1;
        if (tailCount > DeepIdV2ForwardTailCodec.MaximumTailHeads)
            throw new CryptographicException(
                "The DID2 successor tail exceeds its offline-root horizon.");
        var sourceCheckpointIndex = -1;
        var sourceLeafIndex = -1;
        for (var index = checkpoints.Length - 1; index >= 0; index--)
        {
            for (var leafIndex = 0; leafIndex < covered[index].Length;
                 leafIndex++)
            {
                if (!Fixed(covered[index][leafIndex].ExactAdh1.Span,
                        callerProtectedLkg.ExactAdh1.Span)) continue;
                sourceCheckpointIndex = index;
                sourceLeafIndex = leafIndex;
                break;
            }
            if (sourceCheckpointIndex >= 0) break;
        }
        if (sourceCheckpointIndex < 0 ||
            callerProtectedLkg.LogGeneration >= anchor.LogGeneration)
            throw new CryptographicException(
                "No root checkpoint covers the protected DID2 floor.");

        var chainSource = covered[0][0];
        var chainLeaves = covered[0].Select(CoveredLeaf).ToArray();
        var sourceLeaves = covered[sourceCheckpointIndex]
            .Select(CoveredLeaf).ToArray();
        var anchorProofMaterial = DeepIdV2DirectoryProofMaterialAuthor.Create(
            current, exactTransitions, currentCheckpoints,
            queriedDirectoryLeafKey, anchor);
        return new DeepIdV2ForwardTailAuthoringInput(
            chainSource,
            authority.AuthorityChain.Select(static value =>
                (ReadOnlyMemory<byte>)value.CanonicalSpan.ToArray()).ToArray(),
            exactAdf1Chain, targetHeads, 0,
            AccountDirectoryProofMaterialAuthor.BuildInclusionProof(
                chainLeaves, 0),
            checked((byte)sourceCheckpointIndex),
            checked((ulong)sourceLeafIndex),
            AccountDirectoryProofMaterialAuthor.BuildInclusionProof(
                sourceLeaves, sourceLeafIndex),
            orderedHeads.Skip(previousTargetIndex + 1).Select(static head =>
                head.ExactAdh1).ToArray(),
            anchorProofMaterial.ConsistencyProofNodes);
    }

    private static byte[] CoveredLeaf(AccountDirectoryProtectedLkg head) =>
        AccountDirectoryCurrentProofVerifier.ComputeCoveredHeadLeaf(
            head.LogGeneration, head.TreeSize, head.CoreHash.Span);

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static bool Zero(ReadOnlySpan<byte> value) =>
        value.IndexOfAnyExcept((byte)0) < 0;
}
