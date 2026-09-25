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
/// Later periodic checkpoints require a separate authoring path.
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

    public static async ValueTask<byte[]> AuthorInitialAsync(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<AccountDirectoryProtectedLkg> coveredHeads,
        AccountDirectoryProtectedLkg target,
        ulong issuedAtUnixSeconds, ushort minimumReader,
        IReadOnlyList<IAccountDirectoryAdf1RootSigner> rootSigners,
        CancellationToken cancellationToken = default)
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

        var coveredLeaves = coveredHeads.Select(static head =>
            AccountDirectoryCurrentProofVerifier.ComputeCoveredHeadLeaf(
                head.LogGeneration, head.TreeSize, head.CoreHash.Span)).ToArray();
        var coveredRoot = AccountDirectoryProofMaterialAuthor.TreeHash(
            coveredLeaves, 0, coveredLeaves.Length);
        var targetReference = AccountDirectoryCrypto.CreateReference(
            ProtocolMagicBytes.ADH1, 1, target.CoreHash.Span);
        var placeholders = selected.Select(static item =>
            new AccountDirectoryAdf1RootReceipt(item.Id,
                Enumerable.Repeat((byte)1, 64).ToArray())).ToArray();
        var unsigned = new AccountDirectoryAdf1(authority.NetworkId.Span,
            0, new byte[32], 0,
            lastCovered.LogGeneration, (ulong)coveredHeads.Count,
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
                0, new byte[32], 0,
                lastCovered.LogGeneration, (ulong)coveredHeads.Count,
                coveredRoot, targetReference,
                target.TreeSize, target.AppendLogMerkleRoot.Span,
                target.CurrentValueMapRoot.Span,
                authority.AuthorityCoreReference.Span, issuedAtUnixSeconds,
                minimumReader, receipts);
            return AccountDirectoryAdf1Codec.Encode(signed);
        }
        finally { CryptographicOperations.ZeroMemory(signingInput); }
    }
}
