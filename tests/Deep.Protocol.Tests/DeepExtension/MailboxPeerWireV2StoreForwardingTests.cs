using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed partial class MailboxPeerWireV2ContractTests
{
    [Fact]
    public void StoreForwardingProvesExactOriginalAdmissionWithoutNativeMutationDuringPreparation()
    {
        var f = new Fixture(MailboxPeerReplicationOperation.Store);
        var (exact, frame) = StoreForwarding(f);
        var target = new InMemoryReplayJournal();
        var plan = MailboxPeerWireV2Codec.PrepareForwardedStoreReservation(frame, ForwardPolicy(f, 1180),
            f.Crypto, f.MembershipVerifier, target);
        Assert.Equal(0, target.Count); Assert.Equal(1050UL, plan.Snapshot.ReservedAtUnixSeconds);
        var committed = MailboxPeerWireV2Codec.CommitPreparedReservation(plan, target, f.Crypto);
        Assert.Equal(1, target.Count); Assert.Equal(exact, MailboxPeerWireV2Codec.Encode(committed.Request));
        var retry = MailboxPeerWireV2Codec.PrepareForwardedStoreReservation(frame, ForwardPolicy(f, 1181),
            f.Crypto, f.MembershipVerifier, target);
        Assert.Equal(1050UL, retry.Snapshot.ReservedAtUnixSeconds);
        Assert.Throws<MailboxPeerReplicationException>(() => MailboxPeerWireV2Codec.PrepareForwardedStoreRecovery(
            frame, ForwardPolicy(f, 1199), f.Crypto, f.MembershipVerifier));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(40)]
    [InlineData(-1)]
    public void StoreForwardingRejectsFramingOrExactSignatureBeforeReservation(int offset)
    {
        var f = new Fixture(MailboxPeerReplicationOperation.Store);
        var (_, frame) = StoreForwarding(f);
        frame[offset < 0 ? frame.Length - 1 : offset] ^= 1;
        var target = new InMemoryReplayJournal();
        Assert.Throws<MailboxPeerReplicationException>(() => MailboxPeerWireV2Codec.PrepareForwardedStoreReservation(
            frame, ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier, target));
        Assert.Equal(0, target.Count);
    }

    [Fact]
    public void StoreForwardingRejectsRawWrongOperationRoleKeyAndFutureDurability()
    {
        var f = new Fixture(MailboxPeerReplicationOperation.Store);
        var (exact, frame) = StoreForwarding(f);
        Assert.Throws<MailboxPeerReplicationException>(() => MailboxPeerWireV2Codec.DecodeForwardedStoreRequest(exact));
        var (_, tombstone) = Forwarding(new Fixture(MailboxPeerReplicationOperation.Tombstone));
        Assert.Throws<MailboxPeerReplicationException>(() => MailboxPeerWireV2Codec.DecodeForwardedStoreRequest(tombstone));
        var source = f.VerifyAt(exact, 1050, 1199);
        var recipient = MailboxReceiptV2Codec.EncodeReplica(f.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableReplicaResponseAfterPersistence(source,
                MailboxPeerWireResponseReplicaV2.Recipient, MailboxReplicaDisposition.Stored, 1050, 1051), f.RecipientSeed));
        Assert.Throws<MailboxPeerReplicationException>(() => MailboxPeerWireV2Codec.CreateDurableStoreForwarding(source, recipient, f.SenderSeed));
        var originalReceipt = frame.AsSpan(8 + exact.Length, MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength).ToArray();
        Assert.Throws<MailboxPeerReplicationException>(() => MailboxPeerWireV2Codec.CreateDurableStoreForwarding(source, originalReceipt, f.RecipientSeed));
        var future = MailboxReceiptV2Codec.EncodeReplica(f.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableReplicaResponseAfterPersistence(source,
                MailboxPeerWireResponseReplicaV2.Sender, MailboxReplicaDisposition.Stored, 1050, 1181), f.SenderSeed));
        var futureFrame = MailboxPeerWireV2Codec.CreateDurableStoreForwarding(source, future, f.SenderSeed);
        var error = Assert.Throws<MailboxPeerReplicationException>(() => MailboxPeerWireV2Codec.PrepareForwardedStoreRecovery(
            futureFrame, ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier));
        Assert.Equal("DurableFuture", error.Data["Deep.MailboxPeer.Forwarding.Check"]);
    }

    private static (byte[] Exact, byte[] Frame) StoreForwarding(Fixture f)
    {
        var payload = MailboxClientCodec.EncodeEncryptedEnvelope(f.Envelope with { ExpiresAtUnixSeconds = 1199 });
        var exact = MailboxPeerWireV2Codec.Encode(f.Sign(f.Request with
        { ExpiresAtUnixSeconds = 1199, Payload = payload, PayloadDigest = SHA256.HashData(payload) }));
        var source = f.VerifyAt(exact, 1050, 1199);
        var receipt = MailboxReceiptV2Codec.EncodeReplica(f.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableReplicaResponseAfterPersistence(source,
                MailboxPeerWireResponseReplicaV2.Sender, MailboxReplicaDisposition.Stored, 1050, 1051), f.SenderSeed));
        return (exact, MailboxPeerWireV2Codec.CreateDurableStoreForwarding(source, receipt, f.SenderSeed));
    }
}
