using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed partial class MailboxPeerWireV2ContractTests
{
    [Fact]
    public void OwnedOriginalAckAdmission_BindsExactRequestDomainAndKeepsExistingHistory()
    {
        var f = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var (exact, forwarding) = Forwarding(f);
        var proof = MailboxPeerWireV2Codec.CreateOwnedAckAdmissionProof(exact, f.SenderSeed);
        var target = new InMemoryReplayJournal();
        foreach (var bad in new[] { proof[..^1], forwarding[^64..], new byte[64] })
            Assert.Throws<MailboxPeerReplicationException>(() =>
                MailboxPeerWireV2Codec.VerifyAndReserveOwnedAckIntent(exact, bad,
                    ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier, target));
        Assert.Equal(0, target.Count);
        var admitted = MailboxPeerWireV2Codec.VerifyAndReserveOwnedAckIntent(exact, proof,
            ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier, target);
        Assert.Equal(1050UL, admitted.ReplayClaim.ReservedAtUnixSeconds);
        Assert.Equal(1, target.Count);
        var existing = new InMemoryReplayJournal();
        _ = MailboxPeerWireV2Codec.VerifyAndReserve(exact, ForwardPolicy(f, 1055),
            f.Crypto, f.MembershipVerifier, existing);
        Assert.Equal(1055UL, MailboxPeerWireV2Codec.VerifyAndReserveOwnedAckIntent(exact, proof,
            ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier, existing).ReplayClaim.ReservedAtUnixSeconds);
        var expired = new InMemoryReplayJournal();
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.VerifyAndReserveOwnedAckIntent(exact, proof,
                ForwardPolicy(f, 1199), f.Crypto, f.MembershipVerifier, expired));
        Assert.Equal(0, expired.Count);
        var store = new Fixture(MailboxPeerReplicationOperation.Store);
        var storeBytes = MailboxPeerWireV2Codec.Encode(store.Sign(store.Request));
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.CreateOwnedAckAdmissionProof(storeBytes, store.SenderSeed));
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.CreateOwnedAckAdmissionProof(exact, f.RecipientSeed));
    }

    [Fact]
    public void SignedFutureDurabilityCreatesNoReservationUntilActualTimeCoversIt()
    {
        var f = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var (exact, _) = Forwarding(f);
        var source = f.VerifyAt(exact, 1050, 1199);
        var receipt = MailboxReceiptV2Codec.EncodeReplica(f.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableReplicaResponseAfterPersistence(source,
                MailboxPeerWireResponseReplicaV2.Sender, MailboxReplicaDisposition.Tombstone, 1050, 1181), f.SenderSeed));
        var bytes = MailboxPeerWireV2Codec.CreateDurableTombstoneForwarding(source, receipt, f.SenderSeed);
        var target = new InMemoryReplayJournal();
        var error = Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.VerifyAndReserveForwardedTombstone(bytes,
                ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier, target));
        Assert.Equal("DurableFuture", error.Data["Deep.MailboxPeer.Forwarding.Check"]);
        Assert.Equal(1UL, error.Data["Deep.MailboxPeer.Forwarding.LeadSeconds"]);
        Assert.Equal(0, target.Count);
        var admitted = MailboxPeerWireV2Codec.VerifyAndReserveForwardedTombstone(bytes,
            ForwardPolicy(f, 1182), f.Crypto, f.MembershipVerifier, target);
        Assert.Equal(1050UL, admitted.ReplayClaim.ReservedAtUnixSeconds);
        Assert.Equal(1, target.Count);
        bytes[^1] ^= 1;
        var bad = Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.VerifyAndReserveForwardedTombstone(bytes,
                ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier, new InMemoryReplayJournal()));
        Assert.Equal(MailboxPeerReplicationError.InvalidSignature, bad.Error);
        Assert.Null(bad.Data["Deep.MailboxPeer.Forwarding.Check"]);
    }

    [Fact]
    public void DurableForwarding_CannotSignStoreOrAnotherSourceKey()
    {
        var store = new Fixture(MailboxPeerReplicationOperation.Store);
        var verifiedStore = store.Verify(MailboxPeerWireV2Codec.Encode(store.Sign(store.Request)));
        var receipt = MailboxReceiptV2Codec.EncodeReplica(store.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableReplicaResponseAfterPersistence(verifiedStore,
                MailboxPeerWireResponseReplicaV2.Sender, MailboxReplicaDisposition.Stored, 1050, 1051),
            store.SenderSeed));
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.CreateDurableTombstoneForwarding(verifiedStore, receipt, store.SenderSeed));
        var f = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var (exact, bytes) = Forwarding(f);
        var source = f.VerifyAt(exact, 1050, 1199);
        var originalReceipt = bytes.AsMemory(8 + exact.Length, MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength);
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.CreateDurableTombstoneForwarding(source, originalReceipt.Span, f.RecipientSeed));
    }

    [Fact]
    public void DurableForwarding_DoesNotReplaceExistingRecipientAdmissionTime()
    {
        var f = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var (exact, bytes) = Forwarding(f);
        var target = new InMemoryReplayJournal();
        var first = MailboxPeerWireV2Codec.VerifyAndReserve(
            exact, ForwardPolicy(f, 1055), f.Crypto, f.MembershipVerifier, target);
        var retry = MailboxPeerWireV2Codec.VerifyAndReserveForwardedTombstone(
            bytes, ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier, target);
        Assert.Equal(1055UL, retry.ReplayClaim.ReservedAtUnixSeconds);
        Assert.Equal(first.ReplayClaim.RequestDigest.ToArray(), retry.ReplayClaim.RequestDigest.ToArray());
        Assert.Equal(MailboxPeerReplayDisposition.InFlight, retry.ReplayDisposition);
        Assert.Equal(1, target.Count);
    }

    [Fact]
    public void DurableForwarding_ProvesOriginalAdmission_AndColdExactReplay()
    {
        var f = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var (exact, forwarding) = Forwarding(f);
        var target = new InMemoryReplayJournal();
        Assert.Throws<MailboxPeerReplicationException>(() => MailboxPeerWireV2Codec.VerifyAndReserve(
            exact, ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier, target));
        Assert.Equal(0, target.Count);
        Assert.Equal(exact, MailboxPeerWireV2Codec.DecodeForwardedTombstoneRequest(forwarding));
        var admitted = MailboxPeerWireV2Codec.VerifyAndReserveForwardedTombstone(
            forwarding, ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier, target);
        Assert.Equal(1050UL, admitted.ReplayClaim.ReservedAtUnixSeconds);
        Assert.Equal(MailboxPeerReplayDisposition.NewReserved, admitted.ReplayDisposition);
        var response = MailboxReceiptV2Codec.EncodeReplica(f.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableResponseAfterPersistence(
                admitted, MailboxReplicaDisposition.Tombstone, 1050, 1180), f.RecipientSeed));
        MailboxPeerWireV2Codec.CompleteAtomically(admitted, response, f.Crypto, target);
        var cold = new InMemoryReplayJournal(admitted.ReplayClaim.ScopeKey, target.Snapshot(admitted.ReplayClaim));
        var retry = MailboxPeerWireV2Codec.VerifyAndReserveForwardedTombstone(
            forwarding, ForwardPolicy(f, 1181), f.Crypto, f.MembershipVerifier, cold);
        Assert.Equal(response, retry.CachedResponse.ToArray());
        var expired = new InMemoryReplayJournal();
        Assert.Throws<MailboxPeerReplicationException>(() => MailboxPeerWireV2Codec.VerifyAndReserveForwardedTombstone(
            forwarding, ForwardPolicy(f, 1199), f.Crypto, f.MembershipVerifier, expired));
        Assert.Equal(0, expired.Count);
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("nonce")]
    [InlineData("receipt")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("length")]
    [InlineData("raw")]
    [InlineData("wrong-role")]
    [InlineData("late-admission")]
    [InlineData("future-durable")]
    public void InvalidForwarding_NeverCreatesReservation(string defect)
    {
        var f = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var (exact, bytes) = Forwarding(f);
        if (defect is "wrong-role" or "late-admission" or "future-durable")
        {
            var r = MailboxReceiptV2Codec.DecodeReplica(bytes.AsSpan(8 + exact.Length,
                MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength));
            r = defect switch
            {
                "wrong-role" => r with { ReplicaId = f.Request.RecipientRouterId },
                "late-admission" => r with { AcceptedAtUnixSeconds = 1171, DurableAtUnixSeconds = 1172 },
                _ => r with { DurableAtUnixSeconds = 1181 }
            };
            var altered = MailboxReceiptV2Codec.EncodeReplica(f.Crypto.SignReplicaResponse(r,
                defect == "wrong-role" ? f.RecipientSeed : f.SenderSeed));
            altered.CopyTo(bytes, 8 + exact.Length);
        }
        else if (defect == "signature") bytes[^1] ^= 1;
        else if (defect == "nonce") bytes[8 + 200] ^= 1;
        else if (defect == "receipt") bytes[8 + exact.Length + 40] ^= 1;
        else if (defect == "truncated") bytes = bytes[..^1];
        else if (defect == "trailing") bytes = [.. bytes, 0];
        else if (defect == "length") bytes[7] ^= 1;
        else if (defect == "raw") bytes = exact;
        var target = new InMemoryReplayJournal();
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.VerifyAndReserveForwardedTombstone(
                bytes, ForwardPolicy(f, 1180), f.Crypto, f.MembershipVerifier, target));
        Assert.Equal(0, target.Count);
    }

    private static (byte[] Exact, byte[] Forwarding) Forwarding(Fixture f)
    {
        var exact = MailboxPeerWireV2Codec.Encode(f.Sign(f.Request with { ExpiresAtUnixSeconds = 1199 }));
        var source = f.VerifyAt(exact, 1050, 1199);
        var receipt = MailboxReceiptV2Codec.EncodeReplica(f.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableReplicaResponseAfterPersistence(
                source, MailboxPeerWireResponseReplicaV2.Sender, MailboxReplicaDisposition.Tombstone, 1050, 1051),
            f.SenderSeed));
        return (exact, MailboxPeerWireV2Codec.CreateDurableTombstoneForwarding(source, receipt, f.SenderSeed));
    }

    private static MailboxPeerWireVerificationPolicyV2 ForwardPolicy(Fixture f, ulong now) => new()
    {
        ExpectedOperation = f.Operation, Epoch = f.Request.Epoch,
        OperationId = f.Request.OperationId, SenderRouterId = f.Request.SenderRouterId,
        RecipientRouterId = f.Request.RecipientRouterId, MembershipCommitment = f.Request.MembershipCommitment,
        PlacementCommitment = f.Request.PlacementCommitment, PlacementId = f.Envelope.PlacementId,
        NowUnixSeconds = now, EpochExpiresAtUnixSeconds = 1199
    };
}
