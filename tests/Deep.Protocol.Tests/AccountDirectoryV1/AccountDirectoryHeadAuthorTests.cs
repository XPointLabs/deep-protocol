using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Tests.ContactV1;
using Sodium;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryHeadAuthorTests
{
    [Fact]
    public async Task TwoGenesisAdmissionsAdvanceOneThresholdVerifiedHead()
    {
        var network = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var alice = AccountDirectoryAdc1VerificationTests.Fixture.Create(
            0x21, network.Network);
        var bob = AccountDirectoryAdc1VerificationTests.Fixture.Create(
            0x31, network.Network);
        ReadOnlyMemory<byte>[] revoked = [];
        var aliceCheckpoint = AccountDirectoryAdc1Verifier.Verify(
            alice.CreateCheckpoint(revoked), alice.Binding, alice.Directory, revoked, 1);
        var bobCheckpoint = AccountDirectoryAdc1Verifier.Verify(
            bob.CreateCheckpoint(revoked), bob.Binding, bob.Directory, revoked, 1);
        var predecessor = GenesisHead(network);
        var signers = network.Witnesses.Take(2).Select(static value =>
            (IAccountDirectoryAdh1WitnessSigner)new Signer(value)).ToArray();

        var authored = await AccountDirectoryHeadAuthor.AdvanceAsync(
            network.Authority,
            predecessor,
            new AccountDirectoryHeadMutationRequest(
                [], [], [bobCheckpoint, aliceCheckpoint], 30, 60, 1),
            signers);

        Assert.Equal<ulong>(1, authored.ProtectedHead.LogGeneration);
        Assert.Equal<ulong>(2, authored.ProtectedHead.TreeSize);
        Assert.Equal(2, authored.ExactTransitions.Count);
        Assert.Equal(2, authored.ExactAllTransitions.Count);
        Assert.Equal(authored.CoreHash.ToArray(), authored.ProtectedHead.CoreHash.ToArray());
        var transitions = authored.ExactTransitions
            .Select(static value => AccountDirectoryTransitionCodec.Decode(value.Span))
            .ToArray();
        Assert.Equal<ulong>(0, transitions[0].LogIndex);
        Assert.Equal<ulong>(1, transitions[1].LogIndex);
        Assert.True(transitions[0].DirectoryLeafKey.Span.SequenceCompareTo(
            transitions[1].DirectoryLeafKey.Span) < 0);
        Assert.Equal(predecessor.CurrentValueMapRoot.ToArray(),
            transitions[0].PreviousMapRoot.ToArray());
        Assert.Equal(authored.ProtectedHead.CurrentValueMapRoot.ToArray(),
            transitions[1].NextMapRoot.ToArray());
    }

    [Fact]
    public async Task ChangedPrivateJournalCannotAdvanceProtectedHead()
    {
        var network = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var alice = AccountDirectoryAdc1VerificationTests.Fixture.Create(
            0x21, network.Network);
        ReadOnlyMemory<byte>[] revoked = [];
        var checkpoint = AccountDirectoryAdc1Verifier.Verify(
            alice.CreateCheckpoint(revoked), alice.Binding, alice.Directory, revoked, 1);
        var signers = network.Witnesses.Take(2).Select(static value =>
            (IAccountDirectoryAdh1WitnessSigner)new Signer(value)).ToArray();
        var first = await AccountDirectoryHeadAuthor.AdvanceAsync(
            network.Authority,
            GenesisHead(network),
            new AccountDirectoryHeadMutationRequest([], [], [checkpoint], 30, 60, 1),
            signers);
        var checkpointReference = AccountDirectoryCrypto.CreateReference(
            "ADC1"u8, 1, SHA256.HashData(AccountDirectoryAdc1Codec.Encode(checkpoint.Checkpoint)));
        Assert.Equal(
            AccountDirectorySparseMap.ComputePresentRoot(
                checkpoint.Checkpoint.DirectoryLeafKey.Span,
                checkpointReference,
                new byte[32],
                []).ToArray(),
            first.ProtectedHead.CurrentValueMapRoot.ToArray());
        var changed = first.ExactAllTransitions[0].ToArray();
        changed[^1] ^= 1;

        var error = await Assert.ThrowsAsync<AccountDirectoryHeadAuthoringException>(() =>
            AccountDirectoryHeadAuthor.AdvanceAsync(
                network.Authority,
                first.ProtectedHead,
                new AccountDirectoryHeadMutationRequest(
                    [changed], [checkpoint], [checkpoint], 31, 61, 1),
                signers).AsTask());

        Assert.Equal("JournalSuccessorMismatch", error.Code);
    }

    [Fact]
    public async Task CurrentAndAbsentQueriesReceiveVerifiableSparseAndAppendProofs()
    {
        var network = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var alice = AccountDirectoryAdc1VerificationTests.Fixture.Create(0x21, network.Network);
        var bob = AccountDirectoryAdc1VerificationTests.Fixture.Create(0x31, network.Network);
        ReadOnlyMemory<byte>[] revoked = [];
        var aliceCheckpoint = AccountDirectoryAdc1Verifier.Verify(
            alice.CreateCheckpoint(revoked), alice.Binding, alice.Directory, revoked, 1);
        var bobCheckpoint = AccountDirectoryAdc1Verifier.Verify(
            bob.CreateCheckpoint(revoked), bob.Binding, bob.Directory, revoked, 1);
        var genesis = GenesisHead(network);
        var signers = network.Witnesses.Take(2).Select(static value =>
            (IAccountDirectoryAdh1WitnessSigner)new Signer(value)).ToArray();
        var authored = await AccountDirectoryHeadAuthor.AdvanceAsync(
            network.Authority,
            genesis,
            new AccountDirectoryHeadMutationRequest(
                [], [], [bobCheckpoint, aliceCheckpoint], 30, 60, 1),
            signers);

        var present = AccountDirectoryProofMaterialAuthor.Create(
            authored.ProtectedHead,
            authored.ExactAllTransitions,
            [aliceCheckpoint, bobCheckpoint],
            aliceCheckpoint.Checkpoint.DirectoryLeafKey.Span,
            genesis);
        var reference = AccountDirectoryCrypto.CreateReference(
            "ADC1"u8, 1,
            SHA256.HashData(AccountDirectoryAdc1Codec.Encode(aliceCheckpoint.Checkpoint)));
        Assert.Equal(
            authored.ProtectedHead.CurrentValueMapRoot.ToArray(),
            AccountDirectorySparseMap.ComputePresentRoot(
                aliceCheckpoint.Checkpoint.DirectoryLeafKey.Span,
                reference,
                present.SparseMapBitmap.Span,
                Join(present.SparseMapSiblings)).ToArray());
        var transitionCommitment = AccountDirectoryCrypto.Sha256Domain(
            "Deep/AccountDirectory/V1/transition", present.ExactTransition.Span);
        var leaf = AccountDirectoryRfc6962.ComputeLeafHash(transitionCommitment);
        Assert.True(AccountDirectoryRfc6962.VerifyInclusion(
            leaf,
            present.AppendLogIndex,
            authored.ProtectedHead.TreeSize,
            Join(present.InclusionProofNodes),
            authored.ProtectedHead.AppendLogMerkleRoot.Span));

        var missingKey = Enumerable.Repeat((byte)0xe1, 32).ToArray();
        var absent = AccountDirectoryProofMaterialAuthor.Create(
            authored.ProtectedHead,
            authored.ExactAllTransitions,
            [aliceCheckpoint, bobCheckpoint],
            missingKey,
            genesis);
        Assert.Equal(AccountDirectoryAdp1ResultKind.NonMembership, absent.ResultKind);
        Assert.Equal(
            authored.ProtectedHead.CurrentValueMapRoot.ToArray(),
            AccountDirectorySparseMap.ComputeNonMembershipRoot(
                missingKey,
                absent.SparseMapBitmap.Span,
                Join(absent.SparseMapSiblings)));
    }

    [Fact]
    public async Task SuccessorHeadReceivesVerifiableConsistencyProofFromPriorLkg()
    {
        var network = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var alice = AccountDirectoryAdc1VerificationTests.Fixture.Create(0x21, network.Network);
        var bob = AccountDirectoryAdc1VerificationTests.Fixture.Create(0x31, network.Network);
        ReadOnlyMemory<byte>[] revoked = [];
        var aliceCheckpoint = AccountDirectoryAdc1Verifier.Verify(
            alice.CreateCheckpoint(revoked), alice.Binding, alice.Directory, revoked, 1);
        var bobCheckpoint = AccountDirectoryAdc1Verifier.Verify(
            bob.CreateCheckpoint(revoked), bob.Binding, bob.Directory, revoked, 1);
        var signers = network.Witnesses.Take(2).Select(static value =>
            (IAccountDirectoryAdh1WitnessSigner)new Signer(value)).ToArray();
        var first = await AccountDirectoryHeadAuthor.AdvanceAsync(
            network.Authority,
            GenesisHead(network),
            new AccountDirectoryHeadMutationRequest([], [], [aliceCheckpoint], 30, 60, 1),
            signers);
        var second = await AccountDirectoryHeadAuthor.AdvanceAsync(
            network.Authority,
            first.ProtectedHead,
            new AccountDirectoryHeadMutationRequest(
                first.ExactAllTransitions, [aliceCheckpoint], [bobCheckpoint], 31, 61, 1),
            signers);

        var proof = AccountDirectoryProofMaterialAuthor.Create(
            second.ProtectedHead,
            second.ExactAllTransitions,
            [aliceCheckpoint, bobCheckpoint],
            bobCheckpoint.Checkpoint.DirectoryLeafKey.Span,
            first.ProtectedHead);

        Assert.NotEmpty(proof.ConsistencyProofNodes);
        Assert.True(AccountDirectoryRfc6962.VerifyConsistency(
            first.ProtectedHead.TreeSize,
            second.ProtectedHead.TreeSize,
            first.ProtectedHead.AppendLogMerkleRoot.Span,
            second.ProtectedHead.AppendLogMerkleRoot.Span,
            Join(proof.ConsistencyProofNodes)));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(7)]
    [InlineData(8)]
    public async Task ConsistencyProofCoversBalancedAndUnbalancedTreeSizes(int priorCount)
    {
        const int total = 9;
        var network = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        ReadOnlyMemory<byte>[] revoked = [];
        var checkpoints = Enumerable.Range(0, total)
            .Select(index => AccountDirectoryAdc1VerificationTests.Fixture.Create(
                checked((byte)(0x20 + index)), network.Network))
            .Select(value => AccountDirectoryAdc1Verifier.Verify(
                value.CreateCheckpoint(revoked), value.Binding, value.Directory, revoked, 1))
            .ToArray();
        var signers = network.Witnesses.Take(2).Select(static value =>
            (IAccountDirectoryAdh1WitnessSigner)new Signer(value)).ToArray();
        var first = await AccountDirectoryHeadAuthor.AdvanceAsync(
            network.Authority,
            GenesisHead(network),
            new AccountDirectoryHeadMutationRequest(
                [], [], checkpoints.Take(priorCount).ToArray(), 30, 60, 1),
            signers);
        var second = await AccountDirectoryHeadAuthor.AdvanceAsync(
            network.Authority,
            first.ProtectedHead,
            new AccountDirectoryHeadMutationRequest(
                first.ExactAllTransitions,
                checkpoints.Take(priorCount).ToArray(),
                checkpoints.Skip(priorCount).ToArray(),
                31, 61, 1),
            signers);

        var proof = AccountDirectoryProofMaterialAuthor.Create(
            second.ProtectedHead,
            second.ExactAllTransitions,
            checkpoints,
            checkpoints[^1].Checkpoint.DirectoryLeafKey.Span,
            first.ProtectedHead);

        Assert.True(AccountDirectoryRfc6962.VerifyConsistency(
            first.ProtectedHead.TreeSize,
            second.ProtectedHead.TreeSize,
            first.ProtectedHead.AppendLogMerkleRoot.Span,
            second.ProtectedHead.AppendLogMerkleRoot.Span,
            Join(proof.ConsistencyProofNodes)));
    }

    private static AccountDirectoryProtectedLkg GenesisHead(
        ContactNetworkAuthorityVerifierTests.Fixture fixture)
    {
        var witnesses = fixture.Witnesses.Take(2).ToArray();
        var provisional = new AccountDirectoryAdh1(
            fixture.Network,
            0,
            new byte[32],
            0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
            AccountDirectorySparseMap.EmptyMapRoot.Span,
            fixture.Authority.AuthorityCoreReference.Span,
            fixture.Authority.DirectoryWitnessPolicyHash.Span,
            20,
            80,
            1,
            witnesses.Select(static value => new AccountDirectoryAdh1WitnessEntry(
                value.Id, Enumerable.Repeat((byte)1, 64).ToArray())).ToArray());
        var signingInput = AccountDirectoryCrypto.ComputeAdh1SigningInput(provisional);
        var signed = new AccountDirectoryAdh1(
            provisional.NetworkId.Span,
            provisional.LogGeneration,
            provisional.PredecessorAdh1CoreHash.Span,
            provisional.TreeSize,
            provisional.AppendLogMerkleRoot.Span,
            provisional.CurrentValueMapRoot.Span,
            provisional.ExactXnaAuthorityCoreReference.Span,
            provisional.WitnessPolicyHash.Span,
            provisional.ValidFrom,
            provisional.ValidUntil,
            provisional.MinimumReader,
            witnesses.Select(value => new AccountDirectoryAdh1WitnessEntry(
                value.Id, PublicKeyAuth.SignDetached(signingInput, value.Key.PrivateKey))).ToArray());
        CryptographicOperations.ZeroMemory(signingInput);
        var exact = AccountDirectoryAdh1Codec.Encode(signed);
        return AccountDirectoryProtectedLkgFactory.Restore(
            fixture.Authority,
            exact,
            AccountDirectoryCrypto.ComputeAdh1CoreHash(signed));
    }

    private sealed class Signer(
        ContactCodecSecurityTests.CryptoDcrFixture.Witness witness) :
        IAccountDirectoryAdh1WitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => witness.Id.ToArray();

        public ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                PublicKeyAuth.SignDetached(signingInput.ToArray(), witness.Key.PrivateKey));
        }
    }

    private static byte[] Join(IEnumerable<ReadOnlyMemory<byte>> values) =>
        values.SelectMany(static value => value.ToArray()).ToArray();
}
