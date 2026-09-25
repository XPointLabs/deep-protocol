using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Sodium;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed partial class AccountDirectoryFreshnessVerificationTests
{
    [Fact]
    public async Task InitialAdf1OfflineAuthor_CoversEveryPriorSignedHead()
    {
        var fixture = AuthorityFixture.Create();
        AccountDirectoryProtectedLkg Restore(AccountDirectoryAdh1 head) =>
            AccountDirectoryProtectedLkgFactory.Restore(fixture.Verified,
                AccountDirectoryAdh1Codec.Encode(head),
                AccountDirectoryCrypto.ComputeAdh1CoreHash(head));
        var genesis = Restore(fixture.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
            DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray(),
            minimumReader: 2));
        var covered = new List<AccountDirectoryProtectedLkg> { genesis };
        for (ulong generation = 1; generation <= 3; generation++)
            covered.Add(Restore(fixture.Head(generation,
                covered[^1].CoreHash.ToArray(), generation,
                Bytes(32, checked((byte)(0x70 + generation))),
                Bytes(32, checked((byte)(0x80 + generation))),
                minimumReader: 2)));
        var target = Restore(fixture.Head(4,
            covered[^1].CoreHash.ToArray(), 3,
            covered[^1].AppendLogMerkleRoot.ToArray(),
            covered[^1].CurrentValueMapRoot.ToArray(),
            minimumReader: 2));
        var exact = await AccountDirectoryAdf1OfflineAuthor.AuthorInitialAsync(
            fixture.Verified, covered, target, 1_700_000_400, 2,
            [fixture.InitialAdf1Signer()]);
        var checkpoint = AccountDirectoryAdf1Codec.Decode(exact);
        Assert.Equal(0UL, checkpoint.CoveredFirstAdhGeneration);
        Assert.Equal(3UL, checkpoint.CoveredLastAdhGeneration);
        Assert.Equal(4UL, checkpoint.CoveredHeadCount);
        var leaves = covered.Select(static head =>
            AccountDirectoryCurrentProofVerifier.ComputeCoveredHeadLeaf(
                head.LogGeneration, head.TreeSize, head.CoreHash.Span)).ToArray();
        Assert.Equal(AccountDirectoryProofMaterialAuthor.TreeHash(leaves, 0,
                leaves.Length), checkpoint.CoveredHeadMerkleRoot.ToArray());
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await AccountDirectoryAdf1OfflineAuthor.AuthorInitialAsync(
                fixture.Verified, [genesis, covered[2], covered[3]], target,
                1_700_000_400, 2, [fixture.InitialAdf1Signer()]));
    }

    [Fact]
    public async Task InitialAdf1OfflineAuthor_BindsExactVerifiedHeadsAndRootReceipt()
    {
        var fixture = AuthorityFixture.Create();
        var sourceHead = fixture.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
            DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray(),
            minimumReader: 2);
        var source = AccountDirectoryProtectedLkgFactory.Restore(
            fixture.Verified, AccountDirectoryAdh1Codec.Encode(sourceHead),
            AccountDirectoryCrypto.ComputeAdh1CoreHash(sourceHead));
        var targetHead = fixture.Head(1, source.CoreHash.ToArray(), 1,
            AccountDirectoryRfc6962.ComputeLeafHash(Bytes(32, 0x71)),
            Bytes(32, 0x72), minimumReader: 2);
        var target = AccountDirectoryProtectedLkgFactory.Restore(
            fixture.Verified, AccountDirectoryAdh1Codec.Encode(targetHead),
            AccountDirectoryCrypto.ComputeAdh1CoreHash(targetHead));
        var signer = fixture.InitialAdf1Signer();

        var exact = await AccountDirectoryAdf1OfflineAuthor.AuthorInitialAsync(
            fixture.Verified, source, target, 1_700_000_400, 2, [signer]);
        var signed = AccountDirectoryAdf1Codec.Decode(exact);
        Assert.Equal(exact, AccountDirectoryAdf1Codec.Encode(signed));
        Assert.Equal(0UL, signed.CheckpointGeneration);
        Assert.Equal(source.LogGeneration, signed.CoveredFirstAdhGeneration);
        Assert.Equal(source.LogGeneration, signed.CoveredLastAdhGeneration);
        Assert.Equal(1UL, signed.CoveredHeadCount);
        Assert.Equal(AccountDirectoryCurrentProofVerifier.ComputeCoveredHeadLeaf(
                source.LogGeneration, source.TreeSize, source.CoreHash.Span),
            signed.CoveredHeadMerkleRoot.ToArray());
        Assert.Equal(target.TreeSize, signed.TargetTreeSize);
        Assert.Equal(target.CoreHash.ToArray(),
            signed.TargetAdh1CoreReference.Span[6..].ToArray());
        var receipt = Assert.Single(signed.Receipts);
        Assert.Equal(fixture.Verified.RootKeys[0].Id.ToArray(),
            receipt.RootKeyId.ToArray());
        Assert.True(PublicKeyAuth.VerifyDetached(receipt.Signature.ToArray(),
            AccountDirectoryCrypto.ComputeAdf1SigningInput(signed),
            fixture.Verified.RootKeys[0].Ed25519PublicKey.ToArray()));

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await AccountDirectoryAdf1OfflineAuthor.AuthorInitialAsync(
                fixture.Verified, source, target, 1_700_020_000, 2,
                [signer]));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await AccountDirectoryAdf1OfflineAuthor.AuthorInitialAsync(
                fixture.Verified, target, target, 1_700_000_400, 2,
                [signer]));
        var wrongGenesisHead = fixture.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
            Bytes(32, 0x79), minimumReader: 2);
        var wrongGenesis = AccountDirectoryProtectedLkgFactory.Restore(
            fixture.Verified, AccountDirectoryAdh1Codec.Encode(wrongGenesisHead),
            AccountDirectoryCrypto.ComputeAdh1CoreHash(wrongGenesisHead));
        await Assert.ThrowsAsync<AccountDirectoryFreshnessVerificationException>(
            async () => await AccountDirectoryAdf1OfflineAuthor.AuthorInitialAsync(
                fixture.Verified, wrongGenesis, target, 1_700_000_400, 2,
                [signer]));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await AccountDirectoryAdf1OfflineAuthor.AuthorInitialAsync(
                fixture.Verified, source, target, 1_700_000_400, 2,
                [new TestAdf1RootSigner(signer.RootKeyId, Bytes(64, 0x55),
                    invalid: true)]));
    }

    private sealed class TestAdf1RootSigner(
        ReadOnlyMemory<byte> rootKeyId, byte[] privateKey,
        bool invalid = false) :
        IAccountDirectoryAdf1RootSigner
    {
        public ReadOnlyMemory<byte> RootKeyId => rootKeyId.ToArray();

        public ValueTask<int> SignAsync(ReadOnlyMemory<byte> signingInput,
            Memory<byte> signature64, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (invalid)
            {
                signature64.Span.Fill(0x55);
                return ValueTask.FromResult(64);
            }
            var signature = PublicKeyAuth.SignDetached(
                signingInput.ToArray(), privateKey);
            try
            {
                signature.CopyTo(signature64);
                return ValueTask.FromResult(signature.Length);
            }
            finally { CryptographicOperations.ZeroMemory(signature); }
        }
    }
}
