using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>Authored public successor bytes, not verified current authority.
/// Consumers must verify the complete unchanged-genesis chain before use.</summary>
public sealed class AuthoredXPointNetworkAuthorityRenewal
{
    internal AuthoredXPointNetworkAuthorityRenewal(byte[] xna, byte[] dts)
    { ExactXna1 = xna.ToArray(); ExactDts1 = dts.ToArray(); }
    public ReadOnlyMemory<byte> ExactXna1 { get; }
    public ReadOnlyMemory<byte> ExactDts1 { get; }
}

public static partial class XPointNetworkBootstrapAuthor
{
    /// <summary>Offline routine authority/time-policy renewal preserving keys,
    /// thresholds, source policy and client floors. No root/witness rotation,
    /// genesis replacement, publication or protected-floor mutation.</summary>
    public static async ValueTask<AuthoredXPointNetworkAuthorityRenewal> AuthorSameKeyRenewalAsync(
        ReadOnlyMemory<byte> ceremonyId, VerifiedXPointNetworkAuthority predecessor,
        IReadOnlyList<ReadOnlyMemory<byte>> exactDts1PolicyChain,
        ulong authorityIssuedAtUnixSeconds, ulong authorityNotBeforeUnixSeconds, ulong authorityExpiresAtUnixSeconds,
        ulong timePolicyNotBeforeUnixSeconds, ulong timePolicyExpiresAtUnixSeconds,
        IReadOnlyList<IXPointNetworkBootstrapRootSigner> rootSigners, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor);
        ArgumentNullException.ThrowIfNull(exactDts1PolicyChain);
        ArgumentNullException.ThrowIfNull(rootSigners);
        cancellationToken.ThrowIfCancellationRequested();
        if (ceremonyId.Length != 32 || ceremonyId.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero32-byte renewal ceremony is required.", nameof(ceremonyId));
        var ceremony = ceremonyId.ToArray();
        if (exactDts1PolicyChain.Count != predecessor.AuthorityChain.Count ||
            exactDts1PolicyChain.Any(bytes => bytes.Length is < 12 or > 65_535) ||
            rootSigners.Count > predecessor.RootKeys.Count)
            throw new ArgumentException("Renewal inputs must be bounded to the exact verified predecessor chain and key set.");
        var xnaChain = predecessor.AuthorityChain.Select(record => (ReadOnlyMemory<byte>)record.CanonicalCopy()).ToArray();
        var dtsChain = exactDts1PolicyChain.Select(bytes => (ReadOnlyMemory<byte>)bytes.ToArray()).ToArray();
        var pin = new XPointNetworkGenesisPin(predecessor.NetworkId.Span, predecessor.AuthorityChain[0].CoreHash.Span);
        // Reauthenticate the actual full paired chain before signer callbacks.
        _ = XPointNetworkAuthorityVerifier.Verify(pin, xnaChain, dtsChain);
        var prior = predecessor.AuthorityChain[^1];
        var priorDts = AccountDirectoryDts1Codec.Decode(dtsChain[^1].Span);
        if (authorityIssuedAtUnixSeconds < predecessor.NotBefore || authorityIssuedAtUnixSeconds >= predecessor.ExpiresAt ||
            authorityIssuedAtUnixSeconds > authorityNotBeforeUnixSeconds || authorityNotBeforeUnixSeconds < predecessor.NotBefore ||
            authorityNotBeforeUnixSeconds >= predecessor.ExpiresAt || authorityNotBeforeUnixSeconds >= authorityExpiresAtUnixSeconds ||
            authorityExpiresAtUnixSeconds - authorityNotBeforeUnixSeconds > 34_560_000 ||
            authorityExpiresAtUnixSeconds < predecessor.ExpiresAt ||
            timePolicyNotBeforeUnixSeconds < authorityNotBeforeUnixSeconds || timePolicyNotBeforeUnixSeconds < priorDts.NotBefore ||
            timePolicyNotBeforeUnixSeconds >= priorDts.ExpiresAt || timePolicyNotBeforeUnixSeconds >= timePolicyExpiresAtUnixSeconds ||
            timePolicyExpiresAtUnixSeconds - timePolicyNotBeforeUnixSeconds > 2_592_000 ||
            timePolicyExpiresAtUnixSeconds <= priorDts.ExpiresAt || timePolicyExpiresAtUnixSeconds > authorityExpiresAtUnixSeconds)
            throw new ArgumentException("Renewal requires overlapping bounded authority/DTS intervals and a strictly later DTS horizon.");
        var known = predecessor.RootKeys.ToDictionary(key => Convert.ToHexString(key.Id.Span), StringComparer.Ordinal);
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        var bindings = new List<SignerBinding>();
        foreach (var signer in rootSigners)
        {
            if (signer is null || !ids.Add(Convert.ToHexString(signer.RootKeyId.Span)) ||
                !known.TryGetValue(Convert.ToHexString(signer.RootKeyId.Span), out var key) ||
                key.Generation != signer.KeyGeneration || !Fixed(key.Ed25519PublicKey.Span, signer.Ed25519PublicKey.Span) ||
                signer.CustodyDomainHash.Length != 32 || signer.CustodyDomainHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
                !domains.Add(Convert.ToHexString(signer.CustodyDomainHash.Span)))
                throw new CryptographicException("Renewal signer does not match the exact predecessor key/custody threshold.");
            bindings.Add(new SignerBinding(signer, signer.RootKeyId.ToArray(), key.Generation,
                key.Ed25519PublicKey.ToArray(), signer.CustodyDomainHash.ToArray()));
        }
        var signers = bindings.OrderBy(signer => Convert.ToHexString(signer.Id), StringComparer.Ordinal).ToArray();
        if (signers.Length < predecessor.RootThreshold)
            throw new CryptographicException("Renewal root threshold is incomplete.");
        var generation = checked(predecessor.AuthorityGeneration + 1);
        var policyGeneration = checked(priorDts.PolicyGeneration + 1);
        AccountDirectoryDts1 Policy(IReadOnlyList<AccountDirectoryDts1RootReceipt> receipts) => new(predecessor.NetworkId.Span,
            policyGeneration, AccountDirectoryCrypto.ComputeDts1PolicyHash(priorDts), priorDts.Sources,
            priorDts.RequiredSourceCount, priorDts.RequiredDistinctFailureFamilies, priorDts.MaximumIntervalWidthSeconds,
            priorDts.MaximumSourceSampleAgeSeconds, timePolicyNotBeforeUnixSeconds, timePolicyExpiresAtUnixSeconds,
            priorDts.MinimumReader, generation, receipts);
        var unsignedDts = Policy(signers.Select(signer => new AccountDirectoryDts1RootReceipt(signer.Id, NonZeroPlaceholder(64))).ToArray());
        var hash = AccountDirectoryCrypto.ComputeDts1PolicyHash(unsignedDts);
        var fields = Enumerable.Range(1, 20).Select(tag => (ReadOnlyMemory<byte>)prior.FieldSpan(tag).ToArray()).ToArray();
        fields[1] = U64(generation); fields[2] = prior.CoreHash.ToArray();
        fields[11] = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.DTS1, hash); fields[12] = hash;
        fields[15] = U64(authorityIssuedAtUnixSeconds); fields[16] = U64(authorityNotBeforeUnixSeconds); fields[17] = U64(authorityExpiresAtUnixSeconds);
        fields[18] = new[] { checked((byte)signers.Length) };
        fields[19] = EncodeSignatureEntries(signers.Select(signer => new SignatureBinding(signer.Id, NonZeroPlaceholder(64))).ToArray());
        var candidate = XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
        XPointNetworkVerifier.RequireSuccessor(prior, candidate);
        var xnaInput = XPointNetworkCrypto.ComputeSigningInput(candidate);
        var dtsInput = AccountDirectoryCrypto.ComputeDts1SigningInput(unsignedDts);
        try
        {
            fields[19] = EncodeSignatureEntries(await Sign(XPointNetworkRootSignaturePurpose.AuthorityRenewal, generation, xnaInput).ConfigureAwait(false));
            var dtsReceipts = await Sign(XPointNetworkRootSignaturePurpose.DirectoryTimeSourcePolicy, generation, dtsInput).ConfigureAwait(false);
            var xna = XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields);
            var dts = AccountDirectoryDts1Codec.Encode(Policy(dtsReceipts.Select(row => new AccountDirectoryDts1RootReceipt(row.Id, row.Signature)).ToArray()));
            _ = XPointNetworkAuthorityVerifier.Verify(pin, [.. xnaChain, xna], [.. dtsChain, dts]);
            cancellationToken.ThrowIfCancellationRequested();
            return new(xna, dts);
        }
        finally
        { CryptographicOperations.ZeroMemory(ceremony); CryptographicOperations.ZeroMemory(xnaInput); CryptographicOperations.ZeroMemory(dtsInput); }

        async ValueTask<SignatureBinding[]> Sign(XPointNetworkRootSignaturePurpose purpose, ulong signingGeneration, byte[] input)
        {
            var receipts = new List<SignatureBinding>();
            foreach (var signer in signers)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var request = new XPointNetworkRootSigningRequest(ceremony, purpose, predecessor.NetworkId.Span,
                    signingGeneration, signer.Id, signer.Generation, signer.PublicKey,
                    signer.CustodyDomainHash, input);
                var signature = new byte[64];
                try
                {
                    var written = await signer.Signer.SignAsync(request, signature, cancellationToken).ConfigureAwait(false);
                    if (written != 64 || !PublicKeyAuth.VerifyDetached(signature, input, signer.PublicKey))
                        throw new CryptographicException("Authority renewal signer returned an invalid exact receipt.");
                    receipts.Add(new(signer.Id.ToArray(), signature.ToArray()));
                }
                finally { request.Clear(); CryptographicOperations.ZeroMemory(signature); }
            }
            return receipts.ToArray();
        }
    }
}
