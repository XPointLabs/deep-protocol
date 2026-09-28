using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.Tests.Identity;
using Sodium;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed partial class AccountDirectoryFreshnessVerificationTests
{
    [Fact]
    public async Task PeriodicAdf1OfflineAuthor_OutputRecoversInterveningFloorThroughDid2Reader()
    {
        var (_, checkpoint, _, _) = await
            Dnp1IdentityAuthoringV1Tests.CreateRealDid2DirectoryGenesisWithDcaAsync();
        var authority = AuthorityFixture.Create(
            networkOverride: checkpoint.Checkpoint.NetworkId.ToArray(), timeBase: 1_900_000_000);
        var leaf = checkpoint.Checkpoint.DirectoryLeafKey.ToArray();
        var mapRoot = DeepIdV2DirectorySparseMap.ComputeFullMapRoot(
            new Dictionary<string, byte[]> { [Convert.ToHexString(leaf)] = checkpoint.Checkpoint.ArtifactReference.ToArray() });
        var transition = DeepIdV2DirectoryTransitionCodec.Author(0, leaf, new byte[38],
            checkpoint.Checkpoint.ArtifactReference.Span, DeepIdV2DirectorySparseMap.EmptyMapRoot.Span, mapRoot);
        ReadOnlyMemory<byte>[] journal = [transition.CanonicalBytes];
        var history = new List<AccountDirectoryProtectedLkg>();
        for (var generation = 0; generation <= 4; generation++)
        {
            var head = authority.Head((ulong)generation,
                generation == 0 ? new byte[32] : history[^1].CoreHash.ToArray(),
                generation == 0 ? 0UL : 1UL,
                generation == 0 ? AccountDirectoryRfc6962.ComputeEmptyTreeHash() : DeepIdV2DirectoryJournal.ComputeAppendRoot(journal),
                generation == 0 ? DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray() : mapRoot, minimumReader: 2);
            history.Add(AccountDirectoryProtectedLkgFactory.Restore(authority.Verified,
                AccountDirectoryAdh1Codec.Encode(head), AccountDirectoryCrypto.ComputeAdh1CoreHash(head)));
        }
        var initial = await AccountDirectoryAdf1OfflineAuthor.AuthorInitialAsync(
            authority.Verified, history.Take(1).ToArray(), history[1], 1_900_000_100, 2,
            [authority.InitialAdf1Signer()]);
        var periodic = await AccountDirectoryAdf1OfflineAuthor.AuthorSuccessorAsync(
            authority.Verified, history.Take(3).ToArray(), history[3], initial,
            AccountDirectoryCrypto.ComputeAdf1CoreHash(AccountDirectoryAdf1Codec.Decode(initial)),
            1_900_000_200, 2, [authority.InitialAdf1Signer()]);
        var queriedLeaf = Bytes(32, 0x32);
        var source = history[2];
        var nonce = Bytes(32, 0x34);
        var material = DeepIdV2DirectoryProofMaterialAuthor.Create(history[4], journal,
            [checkpoint], queriedLeaf, source);
        var forward = DeepIdV2ForwardTailMaterialAuthor.Create(authority.Verified,
            history, journal, [checkpoint], queriedLeaf, source, [initial, periodic]);
        Assert.Equal((byte)1, forward.SourceCheckpointIndex);
        var request = new AccountDirectoryProofAuthoringRequest(authority.Network, nonce,
            Bytes(16, 0x44), 1_000, history[4].ExactAdh1.Span, authority.CurrentXnv(),
            1_900_000_300, 5, 1_900_000_300, 1_900_000_360,
            AccountDirectoryDtt1IssuanceEpoch.Derive(authority.Verified, 1_900_000_300, 5), 2);
        var issued = await DeepIdV2DirectoryProofAuthor.IssueWithForwardTailAsync(
            authority.Verified, request, material, forward,
            authority.Witnesses.Take(2).Select(WitnessSigner.Valid)
                .Cast<IAccountDirectoryDtt1WitnessSigner>().ToArray(), 1, new DenyingMlDsa65Verifier());
        var verified = DeepIdV2DirectoryCurrentProofVerifier.VerifyExactLeafForAuthor(
            authority.Verified, issued.ExactAdh1, issued.ExactDtt1, issued.ExactAdp1V2,
            nonce, queriedLeaf, Window(), source, 1, 2, new DenyingMlDsa65Verifier());
        Assert.True(verified.HasRootAuthorizedForwardLineage);
        Assert.Equal(4UL, verified.NextProtectedLkg.LogGeneration);
        Assert.Equal(source.ExactAdh1.ToArray(), verified.VerifiedProtectedLkgExactAdh1.ToArray());
    }

    [Fact]
    public async Task PeriodicAdf1OfflineAuthor_CoversEveryNewHeadAndPreservesPredecessor()
    {
        var fixture = AuthorityFixture.Create();
        var heads = PeriodicHeads(fixture, 7);
        var signer = fixture.InitialAdf1Signer();
        var initial = await AccountDirectoryAdf1OfflineAuthor.AuthorInitialAsync(
            fixture.Verified, heads.Take(2).ToArray(), heads[2],
            1_700_000_400, 2, [signer]);
        var initialCore = AccountDirectoryCrypto.ComputeAdf1CoreHash(AccountDirectoryAdf1Codec.Decode(initial));
        var next = await AccountDirectoryAdf1OfflineAuthor.AuthorSuccessorAsync(
            fixture.Verified, heads.Take(5).ToArray(), heads[5], initial,
            initialCore, 1_700_000_401, 2, [signer]);
        var parsed = AccountDirectoryAdf1Codec.Decode(next);
        Assert.Equal(1UL, parsed.CheckpointGeneration);
        Assert.Equal(initialCore, parsed.PredecessorCoreHash.ToArray());
        Assert.Equal(2UL, parsed.CoveredFirstAdhGeneration);
        Assert.Equal(4UL, parsed.CoveredLastAdhGeneration);
        Assert.Equal(3UL, parsed.CoveredHeadCount);
        var leaves = heads.Skip(2).Take(3).Select(static head =>
            AccountDirectoryCurrentProofVerifier.ComputeCoveredHeadLeaf(
                head.LogGeneration, head.TreeSize, head.CoreHash.Span)).ToArray();
        Assert.Equal(AccountDirectoryProofMaterialAuthor.TreeHash(leaves, 0, leaves.Length),
            parsed.CoveredHeadMerkleRoot.ToArray());
        Assert.Equal(next, AccountDirectoryAdf1Codec.Encode(parsed));
        var third = AccountDirectoryAdf1Codec.Decode(await AccountDirectoryAdf1OfflineAuthor.AuthorSuccessorAsync(
            fixture.Verified, heads.Take(7).ToArray(), heads[7], next,
            AccountDirectoryCrypto.ComputeAdf1CoreHash(parsed), 1_700_000_402, 2, [signer]));
        Assert.Equal(2UL, third.CheckpointGeneration);
        Assert.Equal(5UL, third.CoveredFirstAdhGeneration);
        Assert.Equal(6UL, third.CoveredLastAdhGeneration);
        Assert.True(PublicKeyAuth.VerifyDetached(third.Receipts[0].Signature.ToArray(),
            AccountDirectoryCrypto.ComputeAdf1SigningInput(third),
            fixture.Verified.RootKeys[0].Ed25519PublicKey.ToArray()));
    }

    [Theory]
    [InlineData("pin")]
    [InlineData("signature")]
    [InlineData("gap")]
    [InlineData("previous-target")]
    [InlineData("coverage")]
    [InlineData("time")]
    public async Task PeriodicAdf1OfflineAuthor_RejectsBeforeCallingRootCustody(string fault)
    {
        var fixture = AuthorityFixture.Create();
        var heads = PeriodicHeads(fixture, 5);
        var previous = await AccountDirectoryAdf1OfflineAuthor.AuthorInitialAsync(
            fixture.Verified, heads.Take(2).ToArray(), heads[2],
            1_700_000_400, 2, [fixture.InitialAdf1Signer()]);
        var parsed = AccountDirectoryAdf1Codec.Decode(previous);
        if (fault is "signature" or "coverage")
        {
            parsed = new AccountDirectoryAdf1(parsed.NetworkId.Span, parsed.CheckpointGeneration,
                parsed.PredecessorCoreHash.Span, parsed.CoveredFirstAdhGeneration,
                parsed.CoveredLastAdhGeneration, parsed.CoveredHeadCount,
                fault == "coverage" ? Bytes(32, 0x57) : parsed.CoveredHeadMerkleRoot.Span,
                parsed.TargetAdh1CoreReference.Span, parsed.TargetTreeSize,
                parsed.TargetAppendLogRoot.Span, parsed.TargetCurrentValueMapRoot.Span,
                parsed.AuthorityXnaCoreReference.Span, parsed.IssuedAt, parsed.MinimumReader,
                fault == "signature" ? [new(parsed.Receipts[0].RootKeyId.Span, Bytes(64, 0x55))] : parsed.Receipts);
            if (fault == "coverage")
            {
                var signature = new byte[64];
                await fixture.InitialAdf1Signer().SignAsync(
                    AccountDirectoryCrypto.ComputeAdf1SigningInput(parsed), signature, default);
                parsed = new AccountDirectoryAdf1(parsed.NetworkId.Span, parsed.CheckpointGeneration,
                    parsed.PredecessorCoreHash.Span, parsed.CoveredFirstAdhGeneration,
                    parsed.CoveredLastAdhGeneration, parsed.CoveredHeadCount, parsed.CoveredHeadMerkleRoot.Span,
                    parsed.TargetAdh1CoreReference.Span, parsed.TargetTreeSize, parsed.TargetAppendLogRoot.Span,
                    parsed.TargetCurrentValueMapRoot.Span, parsed.AuthorityXnaCoreReference.Span,
                    parsed.IssuedAt, parsed.MinimumReader, [new(parsed.Receipts[0].RootKeyId.Span, signature)]);
            }
            previous = AccountDirectoryAdf1Codec.Encode(parsed);
        }
        var priorPin = fault == "pin" ? Bytes(32, 0x59) : AccountDirectoryCrypto.ComputeAdf1CoreHash(parsed);
        var covered = heads.Take(5).ToArray();
        if (fault == "gap") covered = [heads[0], heads[1], heads[3], heads[4]];
        if (fault == "previous-target") covered = PeriodicHeads(fixture, 5, 0x60).Take(5).ToArray();
        var custody = new CountingAdf1Signer(fixture.InitialAdf1Signer());
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await AccountDirectoryAdf1OfflineAuthor.AuthorSuccessorAsync(fixture.Verified,
                covered, fault == "previous-target" ? PeriodicHeads(fixture, 5, 0x60)[5] : heads[5],
                previous, priorPin, fault == "time" ? 1_700_000_399UL : 1_700_000_401UL, 2, [custody]));
        Assert.Equal(0, custody.Calls);
    }

    private static AccountDirectoryProtectedLkg[] PeriodicHeads(AuthorityFixture fixture, int last, byte rootSalt = 0x70)
    {
        var result = new List<AccountDirectoryProtectedLkg>();
        for (var index = 0; index <= last; index++)
        {
            var head = fixture.Head((ulong)index, index == 0 ? new byte[32] : result[^1].CoreHash.ToArray(),
                (ulong)index, index == 0 ? AccountDirectoryRfc6962.ComputeEmptyTreeHash() : Bytes(32, (byte)(rootSalt + index)),
                index == 0 ? DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray() : Bytes(32, (byte)(0x80 + index)), minimumReader: 2);
            result.Add(AccountDirectoryProtectedLkgFactory.Restore(fixture.Verified,
                AccountDirectoryAdh1Codec.Encode(head), AccountDirectoryCrypto.ComputeAdh1CoreHash(head)));
        }
        return result.ToArray();
    }

    private sealed class CountingAdf1Signer(IAccountDirectoryAdf1RootSigner inner) : IAccountDirectoryAdf1RootSigner
    {
        public int Calls { get; private set; }
        public ReadOnlyMemory<byte> RootKeyId => inner.RootKeyId;
        public ValueTask<int> SignAsync(ReadOnlyMemory<byte> input, Memory<byte> signature, CancellationToken cancellationToken)
        {
            Calls++;
            return inner.SignAsync(input, signature, cancellationToken);
        }
    }

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
