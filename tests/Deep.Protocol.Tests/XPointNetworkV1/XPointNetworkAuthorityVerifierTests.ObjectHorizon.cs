using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed partial class XPointNetworkAuthorityVerifierTests
{
    private sealed record AuthorityWindow(ulong IssuedAt, ulong NotBefore, ulong ExpiresAt,
        ulong DtsNotBefore, ulong DtsExpiresAt);

    // These are real signed XNA1/DTS1 successors, not a widened time policy,
    // a replacement genesis, a synthetic Verified capability or a clock bypass.
    private static (AuthorityFixture Fixture, AuthorityPair First, AuthorityPair Second)
        ObjectHorizonAuthorityChain()
    {
        var fixture = AuthorityFixture.CreateForObjectHorizon();
        var first = fixture.BuildPair(1, fixture.Genesis.CoreHash, 1, fixture.Genesis.PolicyHash,
            fixture.Genesis.Roots, fixture.Genesis.Roots,
            window: new(8_500, 8_500, 3_100_000, 8_500, 2_592_500), witnessPolicyGeneration: 0);
        var second = fixture.BuildPair(2, first.CoreHash, 2, first.PolicyHash,
            fixture.Genesis.Roots, fixture.Genesis.Roots,
            window: new(2_580_000, 2_580_000, 3_100_000, 2_580_000, 2_700_000), witnessPolicyGeneration: 0);
        return (fixture, first, second);
    }

    [Fact]
    public void ObjectHorizon_DtsRenewalUsesActualSignedLineageAndPreservesGenesisKeysAndWitnessPolicy()
    {
        var (fixture, first, second) = ObjectHorizonAuthorityChain();
        var genesis = XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna], [fixture.Genesis.Dts]);
        var current = XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna, first.Xna, second.Xna], [fixture.Genesis.Dts, first.Dts, second.Dts]);
        // Preserve the configured witness trust policy, not its DTS-bound
        // commitment. The latter MUST change on authenticated DTS renewal.
        Assert.Equal(genesis.DirectoryWitnessPolicyGeneration, current.DirectoryWitnessPolicyGeneration);
        Assert.Equal(genesis.WitnessThreshold, current.WitnessThreshold);
        Assert.Equal(genesis.MaximumWitnessUncertaintySeconds, current.MaximumWitnessUncertaintySeconds);
        Assert.Equal(genesis.MinimumClientGeneration, current.MinimumClientGeneration);
        Assert.Equal(genesis.RootThreshold, current.RootThreshold);
        Assert.Equal(genesis.RootKeys.Select(key => (key.Generation, Convert.ToHexString(key.Id.Span), Convert.ToHexString(key.Ed25519PublicKey.Span))),
            current.RootKeys.Select(key => (key.Generation, Convert.ToHexString(key.Id.Span), Convert.ToHexString(key.Ed25519PublicKey.Span))));
        Assert.Equal(genesis.WitnessKeys.Select(key => (key.Generation, Convert.ToHexString(key.Id.Span),
                Convert.ToHexString(key.Ed25519PublicKey.Span), Convert.ToHexString(key.FailureDomainHash.Span))),
            current.WitnessKeys.Select(key => (key.Generation, Convert.ToHexString(key.Id.Span),
                Convert.ToHexString(key.Ed25519PublicKey.Span), Convert.ToHexString(key.FailureDomainHash.Span))));
        Assert.False(genesis.DirectoryWitnessPolicyHash.Span.SequenceEqual(current.DirectoryWitnessPolicyHash.Span));
        // Reusing the prior signed time policy under the new authority is not
        // preservation: the exact paired lineage must independently reject it.
        Assert.Throws<XPointNetworkAuthorityVerificationException>(() => XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna, first.Xna, second.Xna], [fixture.Genesis.Dts, first.Dts, first.Dts]));
    }

    [Fact]
    public void ObjectHorizon_DtsRenewalUsesActualSignedLineageAndPreservesGenesisAndWitnessKeys()
    {
        var (fixture, first, second) = ObjectHorizonAuthorityChain();
        var genesis = XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna], [fixture.Genesis.Dts]);
        var intermediate = XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna, first.Xna], [fixture.Genesis.Dts, first.Dts]);
        var current = XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna, first.Xna, second.Xna], [fixture.Genesis.Dts, first.Dts, second.Dts]);
        const ulong originalAuthorizationExpiry = 1_800;
        var horizon = checked(originalAuthorizationExpiry +
            (ulong)Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxClientLimits.MaximumTtlSeconds + 31);
        Assert.Throws<CryptographicException>(() => AccountDirectoryDtt1IssuanceEpoch.Derive(genesis, horizon, 5));
        Assert.Throws<CryptographicException>(() => AccountDirectoryDtt1IssuanceEpoch.Derive(intermediate, horizon, 5));
        var epoch = AccountDirectoryDtt1IssuanceEpoch.Derive(current, horizon, 5);
        Assert.Equal(horizon / AccountDirectoryDtt1IssuanceEpoch.DurationSeconds, epoch.Number);
        Assert.Equal(2UL, current.AuthorityGeneration);
        Assert.Equal(2UL, current.Dts1PolicyGeneration);
        Assert.Equal(fixture.Genesis.CoreHash, fixture.Pin.AuthorityCoreHash.ToArray());
        // The frozen policy projection includes DTS1 references. Renewing
        // DTS1 necessarily changes this hash, even without witness rotation.
        Assert.False(genesis.DirectoryWitnessPolicyHash.Span.SequenceEqual(current.DirectoryWitnessPolicyHash.Span));
        Assert.Equal(0UL, current.DirectoryWitnessPolicyGeneration);
        Assert.Equal(genesis.RootThreshold, current.RootThreshold);
        Assert.Equal(genesis.MinimumClientGeneration, current.MinimumClientGeneration);
        Assert.Equal(genesis.RootKeys.Count, current.RootKeys.Count);
        for (var index = 0; index < genesis.RootKeys.Count; index++)
        {
            Assert.Equal(genesis.RootKeys[index].Id.ToArray(), current.RootKeys[index].Id.ToArray());
            Assert.Equal(genesis.RootKeys[index].Ed25519PublicKey.ToArray(), current.RootKeys[index].Ed25519PublicKey.ToArray());
            Assert.Equal(genesis.RootKeys[index].Generation, current.RootKeys[index].Generation);
        }
        Assert.Equal(genesis.WitnessKeys.Count, current.WitnessKeys.Count);
        Assert.Equal(genesis.WitnessThreshold, current.WitnessThreshold);
        for (var index = 0; index < genesis.WitnessKeys.Count; index++)
        {
            Assert.Equal(genesis.WitnessKeys[index].Id.ToArray(), current.WitnessKeys[index].Id.ToArray());
            Assert.Equal(genesis.WitnessKeys[index].Ed25519PublicKey.ToArray(), current.WitnessKeys[index].Ed25519PublicKey.ToArray());
            Assert.Equal(genesis.WitnessKeys[index].Generation, current.WitnessKeys[index].Generation);
            Assert.Equal(genesis.WitnessKeys[index].FailureDomainHash.ToArray(), current.WitnessKeys[index].FailureDomainHash.ToArray());
        }
        foreach (var pair in new[] { fixture.Genesis, first, second })
        {
            var policy = AccountDirectoryDts1Codec.Decode(pair.Dts);
            Assert.InRange(policy.ExpiresAt - policy.NotBefore, 1UL, 2_592_000UL);
        }
    }

    [Theory]
    [InlineData("missing-predecessor")]
    [InlineData("cross-paired-policy")]
    [InlineData("changed-signature")]
    public void ObjectHorizon_RenewalRejectsIncompleteOrAlteredAuthorityBeforeMintingTime(string fault)
    {
        var (fixture, first, second) = ObjectHorizonAuthorityChain();
        ReadOnlyMemory<byte>[] authorities = [fixture.Genesis.Xna, first.Xna, second.Xna];
        ReadOnlyMemory<byte>[] policies = [fixture.Genesis.Dts, first.Dts, second.Dts];
        if (fault == "missing-predecessor")
        { authorities = [fixture.Genesis.Xna, second.Xna]; policies = [fixture.Genesis.Dts, second.Dts]; }
        else if (fault == "cross-paired-policy") policies = [fixture.Genesis.Dts, second.Dts, first.Dts];
        else
        {
            var altered = second.Xna.ToArray(); altered[^1] ^= 1; authorities[^1] = altered;
        }
        Assert.Throws<XPointNetworkAuthorityVerificationException>(() =>
            XPointNetworkAuthorityVerifier.Verify(fixture.Pin, authorities, policies));
    }

    [Fact]
    public void ObjectHorizon_RenewedPolicyStillRejectsUncertaintyAcrossItsBoundary()
    {
        var (fixture, first, second) = ObjectHorizonAuthorityChain();
        var current = XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna, first.Xna, second.Xna], [fixture.Genesis.Dts, first.Dts, second.Dts]);
        Assert.Throws<CryptographicException>(() => AccountDirectoryDtt1IssuanceEpoch.Derive(current, current.Dts1NotBefore, 5));
        Assert.Throws<CryptographicException>(() => AccountDirectoryDtt1IssuanceEpoch.Derive(current, current.Dts1ExpiresAt, 5));
    }

    [Fact]
    public async Task ObjectHorizon_DirectoryHeadAdvancesExactHistoricalFloorUnderRenewedAuthority()
    {
        var (fixture, first, second) = ObjectHorizonAuthorityChain();
        var genesisAuthority = XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna], [fixture.Genesis.Dts]);
        var current = XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna, first.Xna, second.Xna], [fixture.Genesis.Dts, first.Dts, second.Dts]);
        using var witness0 = new HorizonHeadSigner(0);
        using var witness1 = new HorizonHeadSigner(1);
        IAccountDirectoryAdh1WitnessSigner[] signers = [witness0, witness1];
        var genesis = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(genesisAuthority, 990, 6_000, signers);
        var advanced = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(current, genesis.ProtectedHead,
            new([], [], [], 2_593_800, 2_599_800, 2), signers);
        Assert.Equal(1UL, advanced.ProtectedHead.LogGeneration);
        Assert.Equal(genesis.CoreHash.ToArray(), advanced.ProtectedHead.Head.PredecessorAdh1CoreHash.ToArray());
        Assert.Equal(current.AuthorityCoreReference.ToArray(), advanced.ProtectedHead.Head.ExactXnaAuthorityCoreReference.ToArray());
        Assert.Equal(genesis.ProtectedHead.TreeSize, advanced.ProtectedHead.TreeSize);
        Assert.Equal(genesis.ProtectedHead.AppendLogMerkleRoot.ToArray(), advanced.ProtectedHead.AppendLogMerkleRoot.ToArray());
        Assert.Equal(genesis.ProtectedHead.CurrentValueMapRoot.ToArray(), advanced.ProtectedHead.CurrentValueMapRoot.ToArray());
        Assert.Empty(advanced.ExactAllTransitions);
        var caughtUp = DeepIdV2DirectoryCatchupVerifier.Verify(current, genesis.ProtectedHead, [advanced.ExactAdh1], default);
        Assert.Equal(genesis.CoreHash.ToArray(), caughtUp.PriorProtectedLkg.CoreHash.ToArray());
        Assert.Equal(advanced.CoreHash.ToArray(), caughtUp.ProtectedLkg.CoreHash.ToArray());
    }

    [Theory]
    [InlineData("changed-signature")]
    [InlineData("foreign-authority")]
    [InlineData("reader-rollback")]
    [InlineData("current-window")]
    public async Task ObjectHorizon_DirectoryRenewalRejectsInvalidHistoricalFloorBeforeWitnessCallback(string fault)
    {
        var (fixture, first, second) = ObjectHorizonAuthorityChain();
        var genesisAuthority = XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna], [fixture.Genesis.Dts]);
        var current = XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna, first.Xna, second.Xna], [fixture.Genesis.Dts, first.Dts, second.Dts]);
        using var witness0 = new HorizonHeadSigner(0);
        using var witness1 = new HorizonHeadSigner(1);
        IAccountDirectoryAdh1WitnessSigner[] signers = [witness0, witness1];
        var genesis = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(genesisAuthority, 990, 6_000, signers);
        var predecessor = genesis.ProtectedHead;
        if (fault == "changed-signature")
        { var changed = genesis.ExactAdh1.ToArray(); changed[^1] ^= 1; predecessor = new(changed); }
        else if (fault == "foreign-authority")
        {
            var unrelated = AuthorityFixture.Create();
            var unrelatedAuthority = XPointNetworkAuthorityVerifier.Verify(unrelated.Pin,
                [unrelated.Genesis.Xna], [unrelated.Genesis.Dts]);
            predecessor = (await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(unrelatedAuthority, 100, 900, signers)).ProtectedHead;
        }
        witness0.Calls = witness1.Calls = 0;
        var request = new DeepIdV2DirectoryHeadMutationRequest([], [], [],
            fault == "current-window" ? 2_579_999UL : 2_593_800UL,
            fault == "current-window" ? 2_580_999UL : 2_599_800UL, 2);
        if (fault == "reader-rollback")
        {
            // A genuinely threshold-signed, higher, unsupported reader floor.
            // The current reader-2 journal producer must not author reader-3
            // application state just to construct this negative fixture.
            var h = predecessor.Head;
            AccountDirectoryAdh1 Higher(IReadOnlyList<AccountDirectoryAdh1WitnessEntry> receipts) => new(
                h.NetworkId.Span, h.LogGeneration, h.PredecessorAdh1CoreHash.Span, h.TreeSize,
                h.AppendLogMerkleRoot.Span, h.CurrentValueMapRoot.Span,
                h.ExactXnaAuthorityCoreReference.Span, h.WitnessPolicyHash.Span, h.ValidFrom, h.ValidUntil, 3, receipts);
            var unsigned = Higher(signers.Select(signer => new AccountDirectoryAdh1WitnessEntry(signer.WitnessId.Span, Bytes(64, 1))).ToArray());
            var input = AccountDirectoryCrypto.ComputeAdh1SigningInput(unsigned);
            var receipts = new List<AccountDirectoryAdh1WitnessEntry>();
            foreach (var signer in signers)
            {
                var signature = await signer.SignAdh1Async(input, default);
                receipts.Add(new(signer.WitnessId.Span, signature.Span));
            }
            var higher = Higher(receipts);
            predecessor = AccountDirectoryProtectedLkgFactory.Restore(genesisAuthority,
                AccountDirectoryAdh1Codec.Encode(higher), AccountDirectoryCrypto.ComputeAdh1CoreHash(higher));
            CryptographicOperations.ZeroMemory(input);
            witness0.Calls = witness1.Calls = 0;
        }
        await Assert.ThrowsAsync<AccountDirectoryHeadAuthoringException>(() =>
            DeepIdV2DirectoryHeadAuthor.AdvanceAsync(current, predecessor, request, signers).AsTask());
        Assert.Equal(0, witness0.Calls); Assert.Equal(0, witness1.Calls);
    }

    private sealed class HorizonHeadSigner(int index) : IAccountDirectoryAdh1WitnessSigner, IDisposable
    {
        private readonly KeyPair key = PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(0xc0 + index))));
        public ReadOnlyMemory<byte> WitnessId => Bytes(32, checked((byte)(0x80 + index)));
        internal int Calls { get; set; }
        public ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(ReadOnlyMemory<byte> input, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Calls++;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey));
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
}
