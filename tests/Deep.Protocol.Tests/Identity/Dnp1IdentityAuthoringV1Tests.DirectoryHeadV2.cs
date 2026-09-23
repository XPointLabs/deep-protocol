using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;
using Deep.Protocol.Tests.ContactV1;
using Sodium;

namespace Deep.Protocol.Tests.Identity;

public sealed partial class Dnp1IdentityAuthoringV1Tests
{
    private const string OtherMnemonic = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";

    [Fact]
    public async Task Did2Admission_AdvancesThresholdHeadAndRejectsChangedPrivateJournal()
    {
        var network = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        using var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(
            Encoding.ASCII.GetBytes(Mnemonic));
        using var recovery = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase, network.Network, 1);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var closure = ApplicationCoreVerifier.CreateIdentityClosure(
            issued.Verified.Identity, [issued.Verified]);
        var binding = recovery.AuthorGenesisDab2(phrase, closure,
            deploymentProfileId: 1);
        var directory = recovery.AuthorGenesisDmd1(closure, 1_900_000_200);
        var checkpoint = recovery.AuthorGenesisAdc1V2(binding, directory,
            issuedAtUnixSeconds: 1_900_000_300);
        var genesis = Did2DirectoryGenesisHead(network);
        var signers = network.Witnesses.Take(2).Select(static witness =>
            (IAccountDirectoryAdh1WitnessSigner)new Did2WitnessSigner(witness))
            .ToArray();

        var first = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(
            network.Authority, genesis,
            new DeepIdV2DirectoryHeadMutationRequest([], [], [checkpoint],
                30, 60, 2), signers);

        Assert.Equal<ulong>(1, first.ProtectedHead.TreeSize);
        Assert.Equal((ushort)2, first.ProtectedHead.Head.MinimumReader);
        Assert.Equal(checkpoint.Checkpoint.ArtifactReference.ToArray(),
            DeepIdV2DirectoryJournal.ReplayAndVerify(first.ProtectedHead,
                first.ExactAllTransitions)[Convert.ToHexString(
                checkpoint.Checkpoint.DirectoryLeafKey.Span)]);
        var transition = DeepIdV2DirectoryTransitionCodec.Decode(
            first.ExactTransitions.Single().Span);
        Assert.Equal(checkpoint.Checkpoint.ArtifactReference.ToArray(),
            transition.NextAdc1Reference.ToArray());
        Assert.Equal(genesis.CurrentValueMapRoot.ToArray(),
            transition.PreviousMapRoot.ToArray());
        var present = DeepIdV2DirectoryProofMaterialAuthor.Create(
            first.ProtectedHead, first.ExactAllTransitions, [checkpoint],
            checkpoint.Checkpoint.DirectoryLeafKey.Span, genesis);
        Assert.Equal(AccountDirectoryAdp1ResultKind.CurrentValue,
            present.ResultKind);
        Assert.Same(checkpoint, present.CurrentCheckpoint);
        Assert.Equal(transition.CanonicalBytes.ToArray(),
            present.ExactTransition.ToArray());
        Assert.Equal(first.ProtectedHead.CurrentValueMapRoot.ToArray(),
            DeepIdV2DirectorySparseMap.ComputePresentRoot(
                present.QueriedDirectoryLeafKey.Span,
                checkpoint.Checkpoint.ArtifactReference.Span,
                present.SparseMapBitmap.Span,
                JoinV2(present.SparseMapSiblings)));
        var absentKey = Enumerable.Repeat((byte)0xe1, 32).ToArray();
        var absent = DeepIdV2DirectoryProofMaterialAuthor.Create(
            first.ProtectedHead, first.ExactAllTransitions, [checkpoint],
            absentKey, genesis);
        Assert.Equal(AccountDirectoryAdp1ResultKind.NonMembership,
            absent.ResultKind);
        Assert.Equal(first.ProtectedHead.CurrentValueMapRoot.ToArray(),
            DeepIdV2DirectorySparseMap.ComputeNonMembershipRoot(
                absentKey, absent.SparseMapBitmap.Span,
                JoinV2(absent.SparseMapSiblings)));

        var refreshed = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(
            network.Authority, first.ProtectedHead,
            new DeepIdV2DirectoryHeadMutationRequest(first.ExactAllTransitions,
                [checkpoint], [], 31, 61, 2), signers);
        Assert.Equal(first.ProtectedHead.AppendLogMerkleRoot.ToArray(),
            refreshed.ProtectedHead.AppendLogMerkleRoot.ToArray());
        Assert.Equal(first.ProtectedHead.CurrentValueMapRoot.ToArray(),
            refreshed.ProtectedHead.CurrentValueMapRoot.ToArray());

        var changed = first.ExactAllTransitions.Single().ToArray();
        changed[^1] ^= 1;
        await Assert.ThrowsAsync<AccountDirectoryHeadAuthoringException>(() =>
            DeepIdV2DirectoryHeadAuthor.AdvanceAsync(network.Authority,
                first.ProtectedHead,
                new DeepIdV2DirectoryHeadMutationRequest([changed],
                    [checkpoint], [], 31, 61, 2), signers).AsTask());
        var missing = await Assert.ThrowsAsync<AccountDirectoryHeadAuthoringException>(
            () => DeepIdV2DirectoryHeadAuthor.AdvanceAsync(network.Authority,
                first.ProtectedHead,
                new DeepIdV2DirectoryHeadMutationRequest(
                    first.ExactAllTransitions, [], [], 31, 61, 2),
                signers).AsTask());
        Assert.Equal("CurrentCheckpointIncomplete", missing.Code);
        Assert.Throws<CryptographicException>(() =>
            DeepIdV2DirectoryProofMaterialAuthor.Create(first.ProtectedHead,
                first.ExactAllTransitions, [], absentKey, genesis));

        var oldReader = await Assert.ThrowsAsync<AccountDirectoryHeadAuthoringException>(
            () => DeepIdV2DirectoryHeadAuthor.AdvanceAsync(network.Authority,
                Did2DirectoryGenesisHead(network, minimumReader: 1),
                new DeepIdV2DirectoryHeadMutationRequest([], [], [checkpoint],
                    30, 60, 2), signers).AsTask());
        Assert.Equal("ReaderRollback", oldReader.Code);
        var duplicateWitness = await Assert.ThrowsAsync<AccountDirectoryHeadAuthoringException>(
            () => DeepIdV2DirectoryHeadAuthor.AdvanceAsync(network.Authority,
                genesis,
                new DeepIdV2DirectoryHeadMutationRequest([], [], [checkpoint],
                    30, 60, 2), [signers[0], signers[0]]).AsTask());
        Assert.Equal("DuplicateOrInvalidSigner", duplicateWitness.Code);
    }

    [Fact]
    public async Task Did2Proof_EarlierLeafInSameBatchUsesFinalMapWithoutRewritingTransition()
    {
        var network = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var first = await Did2Checkpoint(Mnemonic, network.Network);
        var second = await Did2Checkpoint(OtherMnemonic, network.Network);
        var signers = network.Witnesses.Take(2).Select(static witness =>
            (IAccountDirectoryAdh1WitnessSigner)new Did2WitnessSigner(witness))
            .ToArray();
        var head = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(
            network.Authority, Did2DirectoryGenesisHead(network),
            new DeepIdV2DirectoryHeadMutationRequest([], [], [second, first],
                30, 60, 2), signers);
        var earlierTransition = DeepIdV2DirectoryTransitionCodec.Decode(
            head.ExactTransitions[0].Span);
        var earlier = new[] { first, second }.Single(value =>
            value.Checkpoint.DirectoryLeafKey.Span.SequenceEqual(
                earlierTransition.DirectoryLeafKey.Span));
        Assert.NotEqual(earlierTransition.NextMapRoot.ToArray(),
            head.ProtectedHead.CurrentValueMapRoot.ToArray());

        var proof = DeepIdV2DirectoryProofMaterialAuthor.Create(
            head.ProtectedHead, head.ExactAllTransitions, [first, second],
            earlier.Checkpoint.DirectoryLeafKey.Span);
        Assert.Equal(AccountDirectoryAdp1ResultKind.CurrentValue,
            proof.ResultKind);
        Assert.Equal<ulong>(0, proof.AppendLogIndex);
        Assert.Equal(head.ProtectedHead.CurrentValueMapRoot.ToArray(),
            DeepIdV2DirectorySparseMap.ComputePresentRoot(
                proof.QueriedDirectoryLeafKey.Span,
                earlier.Checkpoint.ArtifactReference.Span,
                proof.SparseMapBitmap.Span,
                JoinV2(proof.SparseMapSiblings)));
        Assert.True(AccountDirectoryRfc6962.VerifyInclusion(
            earlierTransition.AppendLogLeafHash.Span, proof.AppendLogIndex,
            head.ProtectedHead.TreeSize,
            JoinV2(proof.InclusionProofNodes),
            head.ProtectedHead.AppendLogMerkleRoot.Span));
    }

    private static async Task<VerifiedAdc1V2> Did2Checkpoint(string words,
        byte[] network)
    {
        using var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(
            Encoding.ASCII.GetBytes(words));
        using var recovery = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase, network, 1);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var closure = ApplicationCoreVerifier.CreateIdentityClosure(
            issued.Verified.Identity, [issued.Verified]);
        var binding = recovery.AuthorGenesisDab2(phrase, closure,
            deploymentProfileId: 1);
        var directory = recovery.AuthorGenesisDmd1(closure, 1_900_000_200);
        return recovery.AuthorGenesisAdc1V2(binding, directory,
            issuedAtUnixSeconds: 1_900_000_300);
    }

    private static AccountDirectoryProtectedLkg Did2DirectoryGenesisHead(
        ContactNetworkAuthorityVerifierTests.Fixture fixture,
        ushort minimumReader = 2)
    {
        var witnesses = fixture.Witnesses.Take(2).ToArray();
        var provisional = new AccountDirectoryAdh1(fixture.Network, 0,
            new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
            DeepIdV2DirectorySparseMap.EmptyMapRoot.Span,
            fixture.Authority.AuthorityCoreReference.Span,
            fixture.Authority.DirectoryWitnessPolicyHash.Span,
            20, 80, minimumReader,
            witnesses.Select(static witness => new AccountDirectoryAdh1WitnessEntry(
                witness.Id, Enumerable.Repeat((byte)1, 64).ToArray())).ToArray());
        var input = AccountDirectoryCrypto.ComputeAdh1SigningInput(provisional);
        try
        {
            var signed = new AccountDirectoryAdh1(provisional.NetworkId.Span,
                provisional.LogGeneration,
                provisional.PredecessorAdh1CoreHash.Span,
                provisional.TreeSize,
                provisional.AppendLogMerkleRoot.Span,
                provisional.CurrentValueMapRoot.Span,
                provisional.ExactXnaAuthorityCoreReference.Span,
                provisional.WitnessPolicyHash.Span,
                provisional.ValidFrom, provisional.ValidUntil,
                provisional.MinimumReader,
                witnesses.Select(witness => new AccountDirectoryAdh1WitnessEntry(
                    witness.Id,
                    PublicKeyAuth.SignDetached(input, witness.Key.PrivateKey)))
                    .ToArray());
            return AccountDirectoryProtectedLkgFactory.Restore(
                fixture.Authority, AccountDirectoryAdh1Codec.Encode(signed),
                AccountDirectoryCrypto.ComputeAdh1CoreHash(signed));
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    private sealed class Did2WitnessSigner(
        ContactCodecSecurityTests.CryptoDcrFixture.Witness witness) :
        IAccountDirectoryAdh1WitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => witness.Id.ToArray();

        public ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                PublicKeyAuth.SignDetached(signingInput.ToArray(),
                    witness.Key.PrivateKey));
        }
    }

    private static byte[] JoinV2(IEnumerable<ReadOnlyMemory<byte>> values) =>
        values.SelectMany(static value => value.ToArray()).ToArray();
}
