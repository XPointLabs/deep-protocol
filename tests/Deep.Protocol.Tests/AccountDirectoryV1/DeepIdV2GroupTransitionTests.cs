using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.DeepNative;
using Deep.Protocol.GroupV1;
using Deep.Protocol.Identity;
using Deep.Protocol.Tests.Identity;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed partial class AccountDirectoryFreshnessVerificationTests
{
    [Fact]
    public async Task Did2Groups_CreateInviteConsentActivate_WithIndependentNonceProofsAndOwnedKeys()
    {
        using var fixture = await CurrentGroupFixture.CreateAsync();
        using var aliceDevice = CurrentGroupDevice(); using var bobDevice = CurrentGroupDevice();
        var genesis = await DeepIdV2GroupTransitions.CreateGenesisAsync(fixture.Alice, aliceDevice, "CLI governed group", fixture.Time);
        Assert.Equal(0UL, ReadGroupEpoch(genesis.Transition));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(genesis.Transition.Commit.Field(11).Span));
        var independentGenesis = await DeepIdV2GroupTransitions.VerifyGenesisAsync(genesis.Package, fixture.Alice, fixture.Time);
        Assert.True(independentGenesis.BindsExactGcp1(genesis.CanonicalPackageBytes.Span));
        var invitation = await DeepIdV2GroupTransitions.InviteAsync(independentGenesis, fixture.Alice, aliceDevice, fixture.Bob, fixture.Time);
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(independentGenesis.Commit.Field(11).Span));
        var independentBob = await fixture.RefreshBobAsync();
        Assert.NotEqual(fixture.Bob.ExactLookupProof.ToArray(), independentBob.ExactLookupProof.ToArray());
        Assert.Equal(fixture.Bob.ExactCheckpointReference.ToArray(), independentBob.ExactCheckpointReference.ToArray());
        var acceptance = await DeepIdV2GroupTransitions.AcceptAsync(independentGenesis, invitation, fixture.Alice, independentBob, bobDevice, fixture.Time);
        Assert.Equal(invitation.Field(13).ToArray(), acceptance.Field(10).ToArray());
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(independentGenesis.Commit.Field(11).Span));
        var activation = await DeepIdV2GroupTransitions.ActivateAsync(independentGenesis, genesis.Package, invitation,
            acceptance, fixture.Alice, aliceDevice, independentBob, fixture.Bob.ExactLookupProof, [fixture.Alice, independentBob], fixture.Time);
        Assert.Equal(1UL, ReadGroupEpoch(activation.Transition));
        Assert.Equal(2, BinaryPrimitives.ReadUInt16BigEndian(activation.Transition.Commit.Field(11).Span));
        var independent = await DeepIdV2GroupTransitions.VerifyActivationAsync(independentGenesis, activation.Package,
            [fixture.Alice, independentBob], fixture.Time);
        Assert.Equal(activation.Transition.Commit.ArtifactHash.ToArray(), independent.Commit.ArtifactHash.ToArray());
        Assert.True(independent.BindsExactGcp1(activation.Package.CanonicalBytes.Span));
        Assert.Equal(genesis.Transition.Commit.ArtifactHash.ToArray(), independent.Predecessor!.ArtifactHash.ToArray());
        Assert.False(GroupCodec.RuntimeActivation); // Protocol reducer success is not runtime/E2E activation.
    }

    [Fact]
    public async Task Did2Groups_RejectWrongCustodyForgedConsentMissingSupportAndClockChanges()
    {
        using var fixture = await CurrentGroupFixture.CreateAsync();
        using var device = CurrentGroupDevice(); using var wrong = new OwnedGenesisDeviceSecrets();
        Assert.Empty(typeof(VerifiedDeepIdV2GroupDirectory).GetConstructors());
        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2GroupTransitions.CreateGenesisAsync(
            fixture.Alice, wrong, "g", fixture.Time));
        var genesis = await DeepIdV2GroupTransitions.CreateGenesisAsync(fixture.Alice, device, "g", fixture.Time);
        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2GroupTransitions.InviteAsync(
            genesis.Transition, fixture.Alice, device, fixture.Alice, fixture.Time));
        var invitation = await DeepIdV2GroupTransitions.InviteAsync(genesis.Transition, fixture.Alice, device, fixture.Bob, fixture.Time);
        var acceptance = await DeepIdV2GroupTransitions.AcceptAsync(genesis.Transition, invitation, fixture.Alice, fixture.Bob, device, fixture.Time);
        var forgedBytes = acceptance.CanonicalBytes.ToArray(); forgedBytes[^1] ^= 0x80;
        var forged = (GroupInvitationAcceptanceRecord)GroupCodec.Decode(forgedBytes);
        Assert.Equal("DeviceSignatureVerificationFailed", (await Assert.ThrowsAsync<GroupFormatException>(async () =>
            await DeepIdV2GroupTransitions.ActivateAsync(genesis.Transition, genesis.Package, invitation, forged,
                fixture.Alice, device, fixture.Bob, fixture.Bob.ExactLookupProof, [fixture.Alice, fixture.Bob], fixture.Time))).Code);
        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2GroupTransitions.ActivateAsync(
            genesis.Transition, genesis.Package, invitation, acceptance, fixture.Alice, device, fixture.Bob,
            fixture.Alice.ExactLookupProof, [fixture.Alice, fixture.Bob], fixture.Time));
        var fields = Enumerable.Range(1, 11).Select(genesis.Package.Field).ToArray();
        fields[6] = new byte[4]; fields[7] = Array.Empty<byte>();
        var missing = (GroupCommitPackageRecord)GroupCodec.CreateForAuthoring("GCP1", fields);
        Assert.Equal("GroupPackageSupportSetMismatch", (await Assert.ThrowsAsync<GroupFormatException>(async () =>
            await DeepIdV2GroupTransitions.VerifyGenesisAsync(missing, fixture.Alice, fixture.Time))).Code);
        fixture.Clock.Sample = ulong.MaxValue;
        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2GroupTransitions.VerifyGenesisAsync(
            genesis.Package, fixture.Alice, fixture.Time));
        fixture.Clock.Sample = 1003; fixture.Clock.Boot = Bytes(16, 0x71);
        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2GroupDirectoryAuthority.VerifyAsync(fixture.AliceProof, fixture.Time));
    }

    [Fact]
    public async Task Did2Groups_RecheckClockAfterAuthoringAndRejectRetiredReference()
    {
        using var fixture = await CurrentGroupFixture.CreateAsync(); using var device = CurrentGroupDevice();
        var genesis = await DeepIdV2GroupTransitions.CreateGenesisAsync(fixture.Alice, device, "g", fixture.Time);
        var invitation = await DeepIdV2GroupTransitions.InviteAsync(genesis.Transition, fixture.Alice, device, fixture.Bob, fixture.Time);
        var retired = invitation.CanonicalBytes.ToArray(); var at = 12;
        for (var tag = 1; tag < 11; tag++) at += checked(8 + (int)BinaryPrimitives.ReadUInt32BigEndian(retired.AsSpan(at + 4)));
        retired[at + 8 + 5] = 1;
        Assert.Equal("ReferenceTypeMismatch", Assert.Throws<GroupFormatException>(() => GroupCodec.Decode(retired)).Code);
        fixture.Clock.ExpireOnRead = fixture.Clock.Reads + 2;
        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2GroupTransitions.CreateGenesisAsync(
            fixture.Alice, device, "clock closure", fixture.Time));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await DeepIdV2GroupDirectoryAuthority.VerifyAsync(
            fixture.AliceProof, fixture.Time, cancelled.Token));
    }

    private static ulong ReadGroupEpoch(VerifiedGroupTransition transition) => BinaryPrimitives.ReadUInt64BigEndian(transition.Commit.Field(4).Span);

    [Fact]
    public async Task Did2Groups_ExactReplayIsStableAndTwoValidOwnerSuccessorsForkLatchAcrossRestore()
    {
        using var fixture = await CurrentGroupFixture.CreateAsync(); using var device = CurrentGroupDevice();
        var genesis = await DeepIdV2GroupTransitions.CreateGenesisAsync(fixture.Alice, device, "fork refusal", fixture.Time);
        fixture.Clock.Sample = 1005;
        var invitation = await DeepIdV2GroupTransitions.InviteAsync(genesis.Transition, fixture.Alice, device, fixture.Bob, fixture.Time);
        var consent = await DeepIdV2GroupTransitions.AcceptAsync(genesis.Transition, invitation, fixture.Alice, fixture.Bob, device, fixture.Time);
        var first = await DeepIdV2GroupTransitions.ActivateAsync(genesis.Transition, genesis.Package, invitation, consent,
            fixture.Alice, device, fixture.Bob, fixture.Bob.ExactLookupProof, [fixture.Alice, fixture.Bob], fixture.Time);
        var second = await DeepIdV2GroupTransitions.ActivateAsync(genesis.Transition, genesis.Package, invitation, consent,
            fixture.Alice, device, fixture.Bob, fixture.Bob.ExactLookupProof, [fixture.Alice, fixture.Bob], fixture.Time);
        Assert.NotEqual(first.Transition.Commit.ArtifactHash.ToArray(), second.Transition.Commit.ArtifactHash.ToArray());
        // A genuinely owner-signed commit may not predate the consent/proposal,
        // even when it is later than genesis and inside the device lifetime.
        var commitFields = Enumerable.Range(1, 17).Select(first.Transition.Commit.Field).ToArray();
        var earlier = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(earlier,
            BinaryPrimitives.ReadUInt64BigEndian(commitFields[15].Span) - 1); commitFields[15] = earlier;
        var candidate = GroupCodec.CreateForAuthoring("DGC1", commitFields);
        var signature = device.SignCurrentGroupRecord(candidate, fixture.Alice); commitFields[16] = signature;
        var signed = GroupCodec.CreateForAuthoring("DGC1", commitFields);
        var embedded = new byte[4 + signed.CanonicalBytes.Length]; BinaryPrimitives.WriteUInt32BigEndian(embedded,
            checked((uint)signed.CanonicalBytes.Length)); signed.CanonicalBytes.Span.CopyTo(embedded.AsSpan(4));
        var packageFields = Enumerable.Range(1, 11).Select(first.Package.Field).ToArray(); packageFields[3] = embedded;
        var reordered = (GroupCommitPackageRecord)GroupCodec.CreateForAuthoring("GCP1", packageFields);
        Assert.Equal("GroupConsentTimeOrderMismatch", (await Assert.ThrowsAsync<GroupFormatException>(async () =>
            await DeepIdV2GroupTransitions.VerifyActivationAsync(genesis.Transition, reordered,
                [fixture.Alice, fixture.Bob], fixture.Time))).Code);
        var latch = GroupSuccessorLatch.CreateEmpty(); var store = new GroupLatchStore(latch.Snapshot);
        Assert.Equal(GroupLineageDisposition.AcceptedGenesis, latch.ObserveAndPersist(genesis.Transition, store));
        Assert.Equal(GroupLineageDisposition.AcceptedSuccessor, latch.ObserveAndPersist(first.Transition, store));
        var stable = latch.Snapshot.ToArray();
        Assert.Equal(GroupLineageDisposition.ExactReplay, latch.ObserveAndPersist(first.Transition, store));
        Assert.Equal(stable, latch.Snapshot.ToArray());
        Assert.Equal(GroupLineageDisposition.ForkLatched, latch.ObserveAndPersist(second.Transition, store));
        Assert.True(GroupSuccessorLatch.Restore(store.Exact).ForkLatched);
        Assert.False(GroupCodec.RuntimeActivation);
    }

    private sealed class GroupLatchStore(ReadOnlyMemory<byte> initial) : IGroupSuccessorStateStore
    {
        internal byte[] Exact = initial.ToArray();
        public bool CompareExchange(ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement)
        { if (!Exact.AsSpan().SequenceEqual(expected.Span)) return false; Exact = replacement.ToArray(); return true; }
    }

    private static OwnedGenesisDeviceSecrets CurrentGroupDevice() => new(
        Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray(),
        Enumerable.Range(33, 32).Select(static value => (byte)value).ToArray(),
        Enumerable.Repeat((byte)0xd1, 32).ToArray(), Enumerable.Repeat((byte)0xe1, 32).ToArray());

    private sealed class GroupClock : IOnionMonotonicClock
    {
        internal byte[] Boot = Bytes(16, 0x44); internal ulong Sample = 1003; internal int Reads; internal int ExpireOnRead;
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); Reads++; if (ExpireOnRead != 0 && Reads >= ExpireOnRead) Sample = ulong.MaxValue; return ValueTask.FromResult(new OnionMonotonicReading(Boot, Sample)); }
    }

    private sealed class CurrentGroupFixture : IDisposable
    {
        private readonly AuthorityFixture authority;
        private readonly VerifiedAdc1V2[] checkpoints;
        private readonly ReadOnlyMemory<byte>[] journal;
        private readonly AccountDirectoryProtectedLkg initial, head;
        private readonly IDeepMlDsa65VerifierLease pq;
        private CurrentGroupFixture(AuthorityFixture authority, VerifiedAdc1V2[] checkpoints, ReadOnlyMemory<byte>[] journal,
            AccountDirectoryProtectedLkg initial, AccountDirectoryProtectedLkg head)
        { this.authority = authority; this.checkpoints = checkpoints; this.journal = journal; this.initial = initial; this.head = head;
          pq = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess(); Time = new(Clock); }
        internal readonly GroupClock Clock = new(); internal OnionTrustedTimeAuthority Time { get; }
        internal VerifiedDeepIdV2GroupDirectory Alice = null!, Bob = null!;
        internal VerifiedDeepIdV2DirectoryFreshness AliceProof = null!;
        internal static async Task<CurrentGroupFixture> CreateAsync()
        {
            var network = Bytes(16, 0x11);
            var alice = await Dnp1IdentityAuthoringV1Tests.CreateRealDid2DirectoryGenesisAsync(network, mnemonicOverride: Phrase(0));
            var bob = await Dnp1IdentityAuthoringV1Tests.CreateRealDid2DirectoryGenesisAsync(network, mnemonicOverride: Phrase(1));
            var authority = AuthorityFixture.Create(networkOverride: network, timeBase: 1_900_000_000);
            var initial = new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(authority.Head(0, new byte[32], 0,
                AccountDirectoryRfc6962.ComputeEmptyTreeHash(), DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray(), minimumReader: 2)));
            var map = new Dictionary<string, byte[]>(StringComparer.Ordinal); var previous = DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray();
            VerifiedAdc1V2[] checkpoints = [alice.Checkpoint, bob.Checkpoint]; var transitions = new List<ReadOnlyMemory<byte>>();
            foreach (var checkpoint in checkpoints)
            {
                var leaf = checkpoint.Checkpoint.DirectoryLeafKey; map.Add(Convert.ToHexString(leaf.Span), checkpoint.Checkpoint.ArtifactReference.ToArray());
                var root = DeepIdV2DirectorySparseMap.ComputeFullMapRoot(map);
                transitions.Add(DeepIdV2DirectoryTransitionCodec.Author(checked((ulong)transitions.Count), leaf.Span, new byte[38],
                    checkpoint.Checkpoint.ArtifactReference.Span, previous, root).CanonicalBytes); previous = root;
            }
            var head = new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(authority.Head(1, initial.CoreHash.ToArray(), 2,
                DeepIdV2DirectoryJournal.ComputeAppendRoot(transitions), previous, minimumReader: 2)));
            var fixture = new CurrentGroupFixture(authority, checkpoints, transitions.ToArray(), initial, head);
            try
            {
                fixture.AliceProof = await fixture.ProofAsync(0, 0x31);
                fixture.Alice = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(fixture.AliceProof, fixture.Time);
                fixture.Bob = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(await fixture.ProofAsync(1, 0x32), fixture.Time);
                return fixture;
            }
            catch { fixture.Dispose(); throw; }
        }
        internal async Task<VerifiedDeepIdV2GroupDirectory> RefreshBobAsync() =>
            await DeepIdV2GroupDirectoryAuthority.VerifyAsync(await ProofAsync(1, 0x33), Time);
        private async Task<VerifiedDeepIdV2DirectoryFreshness> ProofAsync(int index, byte nonceByte)
        {
            var checkpoint = checkpoints[index]; var leaf = checkpoint.Checkpoint.DirectoryLeafKey;
            var material = DeepIdV2DirectoryProofMaterialAuthor.Create(head, journal, checkpoints, leaf.Span, initial);
            var nonce = Bytes(32, nonceByte);
            var request = new AccountDirectoryProofAuthoringRequest(authority.Network, nonce, Bytes(16, 0x44), 1000,
                head.ExactAdh1.Span, authority.CurrentXnv(), 1_900_000_300, 5, 1_900_000_300, 1_900_000_360,
                AccountDirectoryDtt1IssuanceEpoch.Derive(authority.Verified, 1_900_000_300, 5), 2);
            var package = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(authority.Verified, request, material,
                authority.Witnesses.Take(2).Select(WitnessSigner.Valid).Cast<IAccountDirectoryDtt1WitnessSigner>().ToArray(), 1, pq);
            var adl = DeepIdV2AccountDirectoryLookupCodec.Author(checkpoint.Binding.DeepId, authority.Network,
                initial.LogGeneration, initial.CoreHash.Span, 1, new byte[38], new byte[32]);
            var query = VerifiedDeepIdV2DirectoryQuery.VerifyBinding(adl, checkpoint.Binding);
            return DeepIdV2DirectoryCurrentProofVerifier.VerifyGenesis(authority.Verified, package.ExactAdh1, package.ExactDtt1,
                package.ExactAdp1V2, nonce, query, Window(), initial, 1, 2, pq);
        }
        private static string Phrase(byte value)
        {
            var entropy = new byte[32]; entropy[0] = value; using var phrase = new VerifiedDeepRecoveryPhrase(entropy);
            var encoded = new byte[phrase.CanonicalUtf8Length]; phrase.WriteCanonicalUtf8(encoded);
            try { return Encoding.ASCII.GetString(encoded); } finally { CryptographicOperations.ZeroMemory(encoded); }
        }
        public void Dispose() => pq.Dispose();
    }
}
