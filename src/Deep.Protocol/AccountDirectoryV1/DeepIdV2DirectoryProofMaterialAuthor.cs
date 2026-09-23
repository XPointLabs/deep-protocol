using System.Security.Cryptography;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Authority-private proof inputs for a future ADP1 V2 envelope. This object
/// is not a freshness capability and cannot be sent to a client as proof.
/// </summary>
public sealed class DeepIdV2DirectoryProofMaterial
{
    private readonly byte[] queriedLeafKey;
    private readonly byte[] sparseBitmap;
    private readonly byte[] exactTransition;
    private readonly ReadOnlyMemory<byte>[] sparseSiblings;
    private readonly ReadOnlyMemory<byte>[] consistencyNodes;
    private readonly ReadOnlyMemory<byte>[] inclusionNodes;

    internal DeepIdV2DirectoryProofMaterial(
        AccountDirectoryProtectedLkg currentHead,
        AccountDirectoryProtectedLkg? callerProtectedLkg,
        ReadOnlySpan<byte> queriedLeafKey,
        ReadOnlySpan<byte> sparseBitmap,
        ReadOnlySpan<byte> sparseSiblings,
        IReadOnlyList<ReadOnlyMemory<byte>> consistencyNodes,
        VerifiedAdc1V2? currentCheckpoint,
        ReadOnlySpan<byte> exactTransition,
        ulong appendLogIndex,
        IReadOnlyList<ReadOnlyMemory<byte>> inclusionNodes)
    {
        CurrentHead = currentHead;
        CallerProtectedLkg = callerProtectedLkg;
        this.queriedLeafKey = queriedLeafKey.ToArray();
        this.sparseBitmap = sparseBitmap.ToArray();
        this.sparseSiblings = SplitNodes(sparseSiblings);
        this.consistencyNodes = CopyNodes(consistencyNodes);
        CurrentCheckpoint = currentCheckpoint;
        this.exactTransition = exactTransition.ToArray();
        AppendLogIndex = appendLogIndex;
        this.inclusionNodes = CopyNodes(inclusionNodes);
    }

    public AccountDirectoryProtectedLkg CurrentHead { get; }
    public AccountDirectoryProtectedLkg? CallerProtectedLkg { get; }
    public AccountDirectoryAdp1ResultKind ResultKind => CurrentCheckpoint is null
        ? AccountDirectoryAdp1ResultKind.NonMembership
        : AccountDirectoryAdp1ResultKind.CurrentValue;
    public ReadOnlyMemory<byte> QueriedDirectoryLeafKey => queriedLeafKey.ToArray();
    public ReadOnlyMemory<byte> SparseMapBitmap => sparseBitmap.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> SparseMapSiblings => CopyNodes(sparseSiblings);
    public IReadOnlyList<ReadOnlyMemory<byte>> ConsistencyProofNodes => CopyNodes(consistencyNodes);
    public VerifiedAdc1V2? CurrentCheckpoint { get; }
    public ReadOnlyMemory<byte> ExactTransition => exactTransition.ToArray();
    public ulong AppendLogIndex { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> InclusionProofNodes => CopyNodes(inclusionNodes);

    private static ReadOnlyMemory<byte>[] SplitNodes(ReadOnlySpan<byte> values)
    {
        if (values.Length % 32 != 0 || values.Length > 256 * 32)
            throw new ArgumentException("V2 sparse siblings have an invalid length.");
        var result = new ReadOnlyMemory<byte>[values.Length / 32];
        for (var index = 0; index < result.Length; index++)
            result[index] = values.Slice(index * 32, 32).ToArray();
        return result;
    }

    private static ReadOnlyMemory<byte>[] CopyNodes(
        IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        if (values.Count > 64 || values.Any(static value => value.Length != 32))
            throw new ArgumentException("V2 Merkle nodes have an invalid count or length.");
        return values.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
    }
}

/// <summary>
/// Builds V2 sparse and RFC-6962 proof material only after the entire private
/// V2 journal and complete current ADC1 V2 capability map close the head.
/// </summary>
public static class DeepIdV2DirectoryProofMaterialAuthor
{
    public static DeepIdV2DirectoryProofMaterial Create(
        AccountDirectoryProtectedLkg currentHead,
        IReadOnlyList<ReadOnlyMemory<byte>> exactTransitions,
        IReadOnlyList<VerifiedAdc1V2> currentCheckpoints,
        ReadOnlySpan<byte> queriedDirectoryLeafKey,
        AccountDirectoryProtectedLkg? callerProtectedLkg = null)
    {
        ArgumentNullException.ThrowIfNull(currentHead);
        ArgumentNullException.ThrowIfNull(exactTransitions);
        ArgumentNullException.ThrowIfNull(currentCheckpoints);
        if (queriedDirectoryLeafKey.Length != 32 ||
            queriedDirectoryLeafKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("V2 query leaf must be nonzero and 32 bytes.",
                nameof(queriedDirectoryLeafKey));
        if (currentHead.Head.MinimumReader < 2)
            throw new CryptographicException("V2 proof requires a protected reader floor of two.");
        var map = DeepIdV2DirectoryJournal.ReplayAndVerify(
            currentHead, exactTransitions);
        if (currentCheckpoints.Count != map.Count)
            throw new CryptographicException("Current ADC1 V2 capability set is incomplete.");
        var capabilities = new Dictionary<string, VerifiedAdc1V2>(
            StringComparer.Ordinal);
        foreach (var capability in currentCheckpoints)
        {
            if (capability is null ||
                !Fixed(capability.Checkpoint.NetworkId.Span,
                    currentHead.Head.NetworkId.Span))
                throw new CryptographicException("Current ADC1 V2 capability is absent or cross-network.");
            var key = Convert.ToHexString(capability.Checkpoint.DirectoryLeafKey.Span);
            if (!capabilities.TryAdd(key, capability) ||
                !map.TryGetValue(key, out var reference) ||
                !Fixed(reference, capability.Checkpoint.ArtifactReference.Span))
                throw new CryptographicException("Current ADC1 V2 capability differs from the head map.");
        }

        if (callerProtectedLkg is not null)
        {
            if (callerProtectedLkg.Head.MinimumReader < 2 ||
                callerProtectedLkg.TreeSize > currentHead.TreeSize)
                throw new CryptographicException("Caller LKG is not a DID2 directory floor.");
            _ = DeepIdV2DirectoryJournal.ReplayAndVerify(callerProtectedLkg,
                exactTransitions.Take(checked((int)callerProtectedLkg.TreeSize))
                    .ToArray());
        }

        var leaves = new byte[exactTransitions.Count][];
        var lastIndex = new Dictionary<string, int>(StringComparer.Ordinal);
        for (var index = 0; index < exactTransitions.Count; index++)
        {
            var transition = DeepIdV2DirectoryTransitionCodec.Decode(
                exactTransitions[index].Span);
            leaves[index] = transition.AppendLogLeafHash.ToArray();
            lastIndex[Convert.ToHexString(transition.DirectoryLeafKey.Span)] = index;
        }
        var consistency = AccountDirectoryProofMaterialAuthor.BuildConsistencyProof(
            callerProtectedLkg, currentHead, leaves);
        var sparse = DeepIdV2DirectorySparseMap.CreateProof(map,
            queriedDirectoryLeafKey);
        var query = Convert.ToHexString(queriedDirectoryLeafKey);
        if (!capabilities.TryGetValue(query, out var checkpoint))
        {
            if (!Fixed(DeepIdV2DirectorySparseMap.ComputeNonMembershipRoot(
                    queriedDirectoryLeafKey, sparse.Bitmap, sparse.Siblings),
                    currentHead.CurrentValueMapRoot.Span))
                throw new CryptographicException("Authored V2 non-membership proof did not verify.");
            return new DeepIdV2DirectoryProofMaterial(currentHead,
                callerProtectedLkg, queriedDirectoryLeafKey, sparse.Bitmap,
                sparse.Siblings, consistency, null, [], 0, []);
        }

        var logIndex = lastIndex[query];
        var inclusion = AccountDirectoryProofMaterialAuthor.BuildInclusionProof(
            leaves, logIndex);
        var flatInclusion = Flatten(inclusion);
        if (!Fixed(DeepIdV2DirectorySparseMap.ComputePresentRoot(
                queriedDirectoryLeafKey,
                checkpoint.Checkpoint.ArtifactReference.Span,
                sparse.Bitmap, sparse.Siblings),
                currentHead.CurrentValueMapRoot.Span) ||
            !AccountDirectoryRfc6962.VerifyInclusion(leaves[logIndex],
                checked((ulong)logIndex), currentHead.TreeSize, flatInclusion,
                currentHead.AppendLogMerkleRoot.Span))
            throw new CryptographicException("Authored V2 current proof did not verify.");
        return new DeepIdV2DirectoryProofMaterial(currentHead,
            callerProtectedLkg, queriedDirectoryLeafKey, sparse.Bitmap,
            sparse.Siblings, consistency, checkpoint,
            exactTransitions[logIndex].Span, checked((ulong)logIndex),
            inclusion);
    }

    private static byte[] Flatten(IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        var output = new byte[checked(values.Count * 32)];
        for (var index = 0; index < values.Count; index++)
            values[index].Span.CopyTo(output.AsSpan(index * 32));
        return output;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
