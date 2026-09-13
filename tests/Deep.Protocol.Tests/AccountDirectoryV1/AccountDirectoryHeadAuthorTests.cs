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
}
