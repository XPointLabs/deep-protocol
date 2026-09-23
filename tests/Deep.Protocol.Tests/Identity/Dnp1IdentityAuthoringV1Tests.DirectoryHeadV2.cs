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
}
