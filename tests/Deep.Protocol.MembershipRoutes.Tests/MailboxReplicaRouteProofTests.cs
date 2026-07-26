using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class MailboxReplicaRouteProofTests
{
    [Fact]
    public void ExactMrl1Proof_BindsReplicaKeyRoleEpochAndMembershipRoot()
    {
        var members = new[] { Descriptor(0x10), Descriptor(0x40) };
        var root = MembershipRouteDescriptorCodec.ComputeRoot(members);
        var proof = MembershipRouteDescriptorCodec.BuildProofs(members)[0];
        var mailboxProof = new MailboxReplicaMembershipProof
        {
            ReplicaId = members[0].RouterId,
            SigningPublicKey = members[0].Ed25519PublicKey,
            Epoch = members[0].Epoch,
            MembershipCommitment = root,
            CanonicalInclusionProof = MailboxReplicaRouteProofCodec.Encode(members[0], proof)
        };
        var verifier = new MembershipRoutesMailboxReplicaProofVerifier();

        Assert.True(verifier.VerifyStorageReplica(mailboxProof, 1050));
        Assert.False(verifier.VerifyStorageReplica(mailboxProof with
        {
            MembershipCommitment = Enumerable.Repeat((byte)0x77, 32).ToArray()
        }, 1050));
        Assert.False(verifier.VerifyStorageReplica(mailboxProof with
        {
            SigningPublicKey = Enumerable.Repeat((byte)0x88, 32).ToArray()
        }, 1050));
    }

    [Fact]
    public void NonStorageExpiredAndMalformedProofs_FailClosed()
    {
        var nonStorage = Descriptor(0x10) with
        {
            Roles = MembershipRouteRole.Core,
            Capabilities = MembershipRouteCapability.OnionV1
        };
        var root = MembershipRouteDescriptorCodec.ComputeRoot([nonStorage]);
        var proof = new MailboxReplicaMembershipProof
        {
            ReplicaId = nonStorage.RouterId,
            SigningPublicKey = nonStorage.Ed25519PublicKey,
            Epoch = nonStorage.Epoch,
            MembershipCommitment = root,
            CanonicalInclusionProof = MailboxReplicaRouteProofCodec.Encode(
                nonStorage,
                MembershipRouteDescriptorCodec.BuildProofs([nonStorage])[0])
        };
        Assert.False(new MembershipRoutesMailboxReplicaProofVerifier()
            .VerifyStorageReplica(proof, 1050));

        var storage = Descriptor(0x40);
        root = MembershipRouteDescriptorCodec.ComputeRoot([storage]);
        proof = proof with
        {
            ReplicaId = storage.RouterId,
            SigningPublicKey = storage.Ed25519PublicKey,
            Epoch = storage.Epoch,
            MembershipCommitment = root,
            CanonicalInclusionProof = MailboxReplicaRouteProofCodec.Encode(
                storage,
                MembershipRouteDescriptorCodec.BuildProofs([storage])[0])
        };
        Assert.False(new MembershipRoutesMailboxReplicaProofVerifier()
            .VerifyStorageReplica(proof, 1200));
        Assert.False(new MembershipRoutesMailboxReplicaProofVerifier()
            .VerifyStorageReplica(
                proof with { CanonicalInclusionProof = "json"u8.ToArray() },
                1050));
    }

    private static MembershipRouteDescriptor Descriptor(int start) =>
        new()
        {
            RouterId = Range(start, 32),
            Ed25519PublicKey = Range(start + 32, 32),
            X25519PublicKey = Range(start + 64, 32),
            RpcEndpoint = $"https://node-{start}.example/",
            Roles = MembershipRouteRole.Storage,
            Capabilities = MembershipRouteCapability.Storage,
            Epoch = 7,
            ValidFromUnixSeconds = 1000,
            ValidUntilUnixSeconds = 1100
        };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => unchecked((byte)value)).ToArray();
}
