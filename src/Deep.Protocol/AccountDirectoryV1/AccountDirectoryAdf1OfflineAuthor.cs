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
/// Authors the initial, single-covered-head DID2 forward checkpoint. Both
/// exact heads are re-authenticated against the verified network authority;
/// the caller cannot supply a raw hash, leaf, authority reference or receipt.
/// Later periodic checkpoints require a separate covered-set authoring path.
/// </summary>
public static class AccountDirectoryAdf1OfflineAuthor
{
    public static async ValueTask<byte[]> AuthorInitialAsync(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProtectedLkg protectedSource,
        AccountDirectoryProtectedLkg target,
        ulong issuedAtUnixSeconds, ushort minimumReader,
        IReadOnlyList<IAccountDirectoryAdf1RootSigner> rootSigners,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(protectedSource);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(rootSigners);
        cancellationToken.ThrowIfCancellationRequested();
        if (rootSigners.Count < authority.RootThreshold ||
            rootSigners.Count > authority.RootKeys.Count ||
            minimumReader < 2 || target.Head.MinimumReader < 2 ||
            minimumReader < target.Head.MinimumReader ||
            protectedSource.LogGeneration != 0 || protectedSource.TreeSize != 0 ||
            target.LogGeneration <= protectedSource.LogGeneration ||
            target.TreeSize == 0 ||
            issuedAtUnixSeconds < target.Head.ValidFrom ||
            issuedAtUnixSeconds >= target.Head.ValidUntil ||
            issuedAtUnixSeconds < authority.NotBefore ||
            issuedAtUnixSeconds > authority.ExpiresAt)
            throw new CryptographicException(
                "The initial ADF1 source, target, signer threshold, reader or issue time is invalid.");

        _ = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(authority,
            protectedSource.ExactAdh1, protectedSource.CoreHash.Span);
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

        var coveredRoot = AccountDirectoryCurrentProofVerifier
            .ComputeCoveredHeadLeaf(protectedSource.LogGeneration,
                protectedSource.TreeSize, protectedSource.CoreHash.Span);
        var targetReference = AccountDirectoryCrypto.CreateReference(
            ProtocolMagicBytes.ADH1, 1, target.CoreHash.Span);
        var placeholders = selected.Select(static item =>
            new AccountDirectoryAdf1RootReceipt(item.Id,
                Enumerable.Repeat((byte)1, 64).ToArray())).ToArray();
        var unsigned = new AccountDirectoryAdf1(authority.NetworkId.Span,
            0, new byte[32], protectedSource.LogGeneration,
            protectedSource.LogGeneration, 1, coveredRoot, targetReference,
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
                0, new byte[32], protectedSource.LogGeneration,
                protectedSource.LogGeneration, 1, coveredRoot, targetReference,
                target.TreeSize, target.AppendLogMerkleRoot.Span,
                target.CurrentValueMapRoot.Span,
                authority.AuthorityCoreReference.Span, issuedAtUnixSeconds,
                minimumReader, receipts);
            return AccountDirectoryAdf1Codec.Encode(signed);
        }
        finally { CryptographicOperations.ZeroMemory(signingInput); }
    }
}
