using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Offline root custody for one ADF1 signature. Implementations must not run
/// in the Registry process or release private key material to this API.
/// </summary>
public interface IAccountDirectoryAdf1RootSigner
{
    ReadOnlyMemory<byte> RootKeyId { get; }
    ValueTask<int> SignAsync(ReadOnlyMemory<byte> signingInput,
        Memory<byte> signature64, CancellationToken cancellationToken);
}

/// <summary>
/// Authors the initial DID2 forward checkpoint over a complete, contiguous
/// signed-head lineage from genesis through the target's predecessor. Exact
/// heads are re-authenticated against the verified network authority; the
/// caller cannot supply a raw hash, leaf, authority reference or receipt.
/// Periodic checkpoints retain the independently pinned, authenticated previous
/// root checkpoint and cover every newly intervening signed head.
/// </summary>
public static class AccountDirectoryAdf1OfflineAuthor
{
    public static ValueTask<byte[]> AuthorInitialAsync(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProtectedLkg protectedSource,
        AccountDirectoryProtectedLkg target,
        ulong issuedAtUnixSeconds, ushort minimumReader,
        IReadOnlyList<IAccountDirectoryAdf1RootSigner> rootSigners,
        CancellationToken cancellationToken = default) =>
        AuthorInitialAsync(authority, [protectedSource], target,
            issuedAtUnixSeconds, minimumReader, rootSigners,
            cancellationToken);

    public static ValueTask<byte[]> AuthorInitialAsync(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<AccountDirectoryProtectedLkg> coveredHeads,
        AccountDirectoryProtectedLkg target,
        ulong issuedAtUnixSeconds, ushort minimumReader,
        IReadOnlyList<IAccountDirectoryAdf1RootSigner> rootSigners,
        CancellationToken cancellationToken = default) =>
        AuthorCoreAsync(authority, coveredHeads, target, issuedAtUnixSeconds,
            minimumReader, rootSigners, null, cancellationToken);

    /// <summary>Extends, never replaces, an independently pinned root checkpoint.
    /// The complete genesis-to-target head export remains mandatory. This path
    /// supports one unchanged XNA root authority, not authority rotation.</summary>
    public static ValueTask<byte[]> AuthorSuccessorAsync(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<AccountDirectoryProtectedLkg> coveredHeads,
        AccountDirectoryProtectedLkg target,
        ReadOnlyMemory<byte> exactPreviousAdf1,
        ReadOnlyMemory<byte> expectedPreviousCoreHash,
        ulong issuedAtUnixSeconds, ushort minimumReader,
        IReadOnlyList<IAccountDirectoryAdf1RootSigner> rootSigners,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        cancellationToken.ThrowIfCancellationRequested();
        if (exactPreviousAdf1.Length is < 1 or > 16_384 ||
            expectedPreviousCoreHash.Length != 32 ||
            expectedPreviousCoreHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException("The periodic ADF1 predecessor input is invalid.");
        var previous = AccountDirectoryAdf1Codec.Decode(exactPreviousAdf1.Span);
        if (previous.CheckpointGeneration == ulong.MaxValue ||
            !Fixed(AccountDirectoryCrypto.ComputeAdf1CoreHash(previous), expectedPreviousCoreHash.Span) ||
            !Fixed(previous.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(previous.AuthorityXnaCoreReference.Span, authority.AuthorityCoreReference.Span) ||
            previous.MinimumReader < 2 || minimumReader < previous.MinimumReader ||
            previous.IssuedAt < authority.NotBefore || previous.IssuedAt > authority.ExpiresAt ||
            issuedAtUnixSeconds < previous.IssuedAt ||
            previous.Receipts.Count < authority.RootThreshold ||
            previous.Receipts.Count > authority.RootKeys.Count)
            throw new CryptographicException("The periodic ADF1 predecessor is unpinned or outside its authority.");
        var input = AccountDirectoryCrypto.ComputeAdf1SigningInput(previous);
        try
        {
            foreach (var receipt in previous.Receipts)
            {
                var key = authority.RootKeys.SingleOrDefault(key =>
                    Fixed(key.Id.Span, receipt.RootKeyId.Span));
                if (key is null || !PublicKeyAuth.VerifyDetached(receipt.Signature.ToArray(),
                    input, key.Ed25519PublicKey.ToArray()))
                    throw new CryptographicException("The periodic ADF1 predecessor root signature is invalid.");
            }
        }
        finally { CryptographicOperations.ZeroMemory(input); }
        return AuthorCoreAsync(authority, coveredHeads, target, issuedAtUnixSeconds,
            minimumReader, rootSigners, previous, cancellationToken);
    }

    private static async ValueTask<byte[]> AuthorCoreAsync(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<AccountDirectoryProtectedLkg> coveredHeads,
        AccountDirectoryProtectedLkg target,
        ulong issuedAtUnixSeconds, ushort minimumReader,
        IReadOnlyList<IAccountDirectoryAdf1RootSigner> rootSigners,
        AccountDirectoryAdf1? previousCheckpoint,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(coveredHeads);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(rootSigners);
        cancellationToken.ThrowIfCancellationRequested();
        if (coveredHeads.Count is < 1 or > 4096 ||
            coveredHeads.Any(static head => head is null) ||
            rootSigners.Count < authority.RootThreshold ||
            rootSigners.Count > authority.RootKeys.Count ||
            minimumReader < 2 || target.Head.MinimumReader < 2 ||
            minimumReader < target.Head.MinimumReader ||
            target.TreeSize == 0 ||
            issuedAtUnixSeconds < target.Head.ValidFrom ||
            issuedAtUnixSeconds >= target.Head.ValidUntil ||
            issuedAtUnixSeconds < authority.NotBefore ||
            issuedAtUnixSeconds > authority.ExpiresAt)
            throw new CryptographicException(
                "The initial ADF1 source, target, signer threshold, reader or issue time is invalid.");

        var source = coveredHeads[0];
        if (source.LogGeneration != 0 || source.TreeSize != 0)
            throw new CryptographicException(
                "The initial ADF1 covered set must begin at DID2 genesis.");
        _ = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(authority,
            source.ExactAdh1, source.CoreHash.Span);
        for (var index = 1; index < coveredHeads.Count; index++)
        {
            var previous = coveredHeads[index - 1];
            var current = coveredHeads[index];
            _ = AccountDirectoryProtectedLkgFactory.Restore(authority,
                current.ExactAdh1, current.CoreHash.Span);
            if (current.LogGeneration != (ulong)index ||
                current.TreeSize < previous.TreeSize ||
                !CryptographicOperations.FixedTimeEquals(
                    current.Head.PredecessorAdh1CoreHash.Span,
                    previous.CoreHash.Span))
                throw new CryptographicException(
                    "The initial ADF1 covered-head lineage is incomplete.");
        }
        var lastCovered = coveredHeads[^1];
        if (target.LogGeneration != (ulong)coveredHeads.Count ||
            target.TreeSize < lastCovered.TreeSize ||
            !CryptographicOperations.FixedTimeEquals(
                target.Head.PredecessorAdh1CoreHash.Span,
                lastCovered.CoreHash.Span))
            throw new CryptographicException(
                "The initial ADF1 target is not the next signed head.");
        AccountDirectoryCurrentProofVerifier.VerifyAdhAuthorityAndWitnessClosure(
            authority, target.Head, requireCurrentAuthority: true);

        IReadOnlyList<AccountDirectoryProtectedLkg> newlyCovered = coveredHeads;
        if (previousCheckpoint is not null)
        {
            var priorTarget = coveredHeads.SingleOrDefault(head =>
                Fixed(head.CoreHash.Span, previousCheckpoint.TargetAdh1CoreReference.Span[6..]));
            if (priorTarget is null ||
                priorTarget.TreeSize != previousCheckpoint.TargetTreeSize ||
                !Fixed(priorTarget.AppendLogMerkleRoot.Span, previousCheckpoint.TargetAppendLogRoot.Span) ||
                !Fixed(priorTarget.CurrentValueMapRoot.Span, previousCheckpoint.TargetCurrentValueMapRoot.Span) ||
                !Fixed(priorTarget.Head.ExactXnaAuthorityCoreReference.Span, previousCheckpoint.AuthorityXnaCoreReference.Span) ||
                previousCheckpoint.CoveredLastAdhGeneration >= priorTarget.LogGeneration ||
                previousCheckpoint.IssuedAt < priorTarget.Head.ValidFrom ||
                previousCheckpoint.IssuedAt >= priorTarget.Head.ValidUntil)
                throw new CryptographicException("The periodic ADF1 previous target is outside the authenticated head history.");
            var priorCovered = coveredHeads.Where(head =>
                head.LogGeneration >= previousCheckpoint.CoveredFirstAdhGeneration &&
                head.LogGeneration <= previousCheckpoint.CoveredLastAdhGeneration).ToArray();
            if ((ulong)priorCovered.Length != previousCheckpoint.CoveredHeadCount ||
                priorCovered.Length == 0 ||
                !Fixed(CoveredRoot(priorCovered), previousCheckpoint.CoveredHeadMerkleRoot.Span))
                throw new CryptographicException("The periodic ADF1 previous coverage differs from authenticated head history.");
            newlyCovered = coveredHeads.Where(head =>
                head.LogGeneration > previousCheckpoint.CoveredLastAdhGeneration).ToArray();
            if (newlyCovered.Count == 0 ||
                newlyCovered[0].LogGeneration != previousCheckpoint.CoveredLastAdhGeneration + 1)
                throw new CryptographicException("The periodic ADF1 would omit intervening protected heads.");
        }
        var checkpointGeneration = previousCheckpoint is null ? 0UL :
            checked(previousCheckpoint.CheckpointGeneration + 1);
        var predecessorHash = previousCheckpoint is null ? new byte[32] :
            AccountDirectoryCrypto.ComputeAdf1CoreHash(previousCheckpoint);

        var roots = authority.RootKeys.ToDictionary(
            static key => Convert.ToHexString(key.Id.Span),
            StringComparer.Ordinal);
        var selected = new List<(byte[] Id, byte[] PublicKey,
            IAccountDirectoryAdf1RootSigner Signer)>(rootSigners.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var signer in rootSigners)
        {
            ArgumentNullException.ThrowIfNull(signer);
            var id = signer.RootKeyId.ToArray();
            var hex = Convert.ToHexString(id);
            if (id.Length != 32 || !seen.Add(hex) ||
                !roots.TryGetValue(hex, out var key))
                throw new CryptographicException(
                    "An ADF1 root signer is duplicate or outside the verified authority.");
            selected.Add((id, key.Ed25519PublicKey.ToArray(), signer));
        }
        selected.Sort(static (left, right) =>
            left.Id.AsSpan().SequenceCompareTo(right.Id));

        var coveredRoot = CoveredRoot(newlyCovered);
        var targetReference = AccountDirectoryCrypto.CreateReference(
            ProtocolMagicBytes.ADH1, 1, target.CoreHash.Span);
        var placeholders = selected.Select(static item =>
            new AccountDirectoryAdf1RootReceipt(item.Id,
                Enumerable.Repeat((byte)1, 64).ToArray())).ToArray();
        var unsigned = new AccountDirectoryAdf1(authority.NetworkId.Span,
            checkpointGeneration, predecessorHash, newlyCovered[0].LogGeneration,
            lastCovered.LogGeneration, (ulong)newlyCovered.Count,
            coveredRoot, targetReference,
            target.TreeSize, target.AppendLogMerkleRoot.Span,
            target.CurrentValueMapRoot.Span,
            authority.AuthorityCoreReference.Span, issuedAtUnixSeconds,
            minimumReader, placeholders);
        var signingInput = AccountDirectoryCrypto
            .ComputeAdf1SigningInput(unsigned);
        try
        {
            var receipts = new List<AccountDirectoryAdf1RootReceipt>(selected.Count);
            foreach (var item in selected)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var signature = new byte[64];
                try
                {
                    var count = await item.Signer.SignAsync(signingInput,
                        signature, cancellationToken).ConfigureAwait(false);
                    if (count != signature.Length ||
                        !PublicKeyAuth.VerifyDetached(signature, signingInput,
                            item.PublicKey))
                        throw new CryptographicException(
                            "An ADF1 root signer returned an invalid signature.");
                    receipts.Add(new AccountDirectoryAdf1RootReceipt(
                        item.Id, signature));
                }
                finally { CryptographicOperations.ZeroMemory(signature); }
            }
            var signed = new AccountDirectoryAdf1(authority.NetworkId.Span,
                checkpointGeneration, predecessorHash, newlyCovered[0].LogGeneration,
                lastCovered.LogGeneration, (ulong)newlyCovered.Count,
                coveredRoot, targetReference,
                target.TreeSize, target.AppendLogMerkleRoot.Span,
                target.CurrentValueMapRoot.Span,
                authority.AuthorityCoreReference.Span, issuedAtUnixSeconds,
                minimumReader, receipts);
            return AccountDirectoryAdf1Codec.Encode(signed);
        }
        finally { CryptographicOperations.ZeroMemory(signingInput); }
    }

    private static byte[] CoveredRoot(IReadOnlyList<AccountDirectoryProtectedLkg> heads)
    {
        var leaves = heads.Select(static head => AccountDirectoryCurrentProofVerifier
            .ComputeCoveredHeadLeaf(head.LogGeneration, head.TreeSize, head.CoreHash.Span)).ToArray();
        return AccountDirectoryProofMaterialAuthor.TreeHash(leaves, 0, leaves.Length);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
