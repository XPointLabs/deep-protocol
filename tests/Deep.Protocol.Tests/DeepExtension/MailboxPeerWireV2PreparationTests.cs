using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed partial class MailboxPeerWireV2ContractTests
{
    [Fact]
    public void PureReplayRequestDigestMatchesVerifiedIdentityAndBindsSignatureWithoutAdmission()
    {
        var f = new Fixture(MailboxPeerReplicationOperation.Store);
        var exact = MailboxPeerWireV2Codec.Encode(f.Sign(f.Request));
        var plan = MailboxPeerWireV2Codec.PrepareReplayReservation(exact,
            ForwardPolicy(f, 1050), f.Crypto, f.MembershipVerifier, f.Journal);
        Assert.Equal(plan.Snapshot.RequestDigest.ToArray(), MailboxPeerWireV2Codec.GetReplayRequestDigest(exact));
        var original = MailboxPeerWireV2Codec.GetReplayRequestDigest(exact); exact[^1] ^= 1;
        Assert.NotEqual(original, MailboxPeerWireV2Codec.GetReplayRequestDigest(exact));
        Assert.Equal(0, f.Journal.Count);
        Assert.Throws<MailboxPeerReplicationException>(() => MailboxPeerWireV2Codec.GetReplayRequestDigest(exact[..^1]));
    }
    [Fact]
    public void PreparationDoesNotReserveAndExportsDefensiveSnapshotBeforeActualCommit()
    {
        var f = new Fixture(MailboxPeerReplicationOperation.Store);
        var exact = MailboxPeerWireV2Codec.Encode(f.Sign(f.Request));
        var plan = MailboxPeerWireV2Codec.PrepareReplayReservation(exact,
            ForwardPolicy(f, 1050), f.Crypto, f.MembershipVerifier, f.Journal);
        plan.RequireReservable(); Assert.Equal(0, f.Journal.Count);
        var altered = plan.Snapshot;
        System.Runtime.InteropServices.MemoryMarshal.TryGetArray(altered.RequestDigest, out var digestBytes);
        digestBytes.Array![digestBytes.Offset] ^= 1;
        var request = plan.Request; System.Runtime.InteropServices.MemoryMarshal.TryGetArray(request.Signature, out var bytes);
        bytes.Array![bytes.Offset] ^= 1;
        var committed = MailboxPeerWireV2Codec.CommitPreparedReservation(plan, f.Journal, f.Crypto);
        Assert.Equal(1, f.Journal.Count);
        Assert.Equal(MailboxPeerReplayDisposition.NewReserved, committed.ReplayDisposition);
        Assert.Equal(plan.Snapshot.RequestDigest.ToArray(), committed.ReplayClaim.RequestDigest.ToArray());
        Assert.Empty(typeof(PreparedMailboxPeerReservationV2).GetConstructors());
    }

    [Fact]
    public void UnaidedStalePreparationCannotCreateReservationOrPretendToBeDurable()
    {
        var f = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var exact = MailboxPeerWireV2Codec.Encode(f.Sign(f.Request with { ExpiresAtUnixSeconds = 1199 }));
        var plan = MailboxPeerWireV2Codec.PrepareReplayReservation(exact,
            ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier, f.Journal);
        Assert.Throws<MailboxPeerReplicationException>(() => plan.RequireReservable());
        Assert.Throws<MailboxPeerReplicationException>(() => MailboxPeerWireV2Codec.CommitPreparedReservation(plan, f.Journal, f.Crypto));
        Assert.Equal(0, f.Journal.Count);
    }

    [Fact]
    public void ForwardedAndOwnedAckPreparationAuthenticateBeforeAnyReservation()
    {
        var f = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var (exact, forwarding) = Forwarding(f);
        var target = new InMemoryReplayJournal();
        var plan = MailboxPeerWireV2Codec.PrepareForwardedTombstoneReservation(forwarding,
            ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier, target);
        plan.RequireReservable(); Assert.Equal(0, target.Count);
        Assert.Equal(1050UL, plan.Snapshot.ReservedAtUnixSeconds);
        var admitted = MailboxPeerWireV2Codec.CommitPreparedReservation(plan, target, f.Crypto);
        Assert.Equal(1, target.Count); Assert.Equal(1050UL, admitted.ReplayClaim.ReservedAtUnixSeconds);
        var proof = MailboxPeerWireV2Codec.CreateOwnedAckAdmissionProof(exact, f.SenderSeed);
        proof[0] ^= 1;
        Assert.Throws<MailboxPeerReplicationException>(() => MailboxPeerWireV2Codec.PrepareOwnedAckReservation(
            exact, proof, ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier, new InMemoryReplayJournal()));
    }
}
