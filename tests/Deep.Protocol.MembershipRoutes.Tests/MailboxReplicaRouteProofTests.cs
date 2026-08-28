using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Deep.Protocol.DeepExtension.MailboxTopology;
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
        Assert.Equal(206, mailboxProof.CanonicalInclusionProof.Length);
        Assert.Equal(
            "3a0fefcd2018dd2ef108635e1cb48cd7a9dcd5556860fd5d7dd6217cb7829a6a",
            Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    mailboxProof.CanonicalInclusionProof.Span)).ToLowerInvariant());
        var verifier = new MembershipRoutesMailboxReplicaProofVerifier();

        Assert.NotEqual(mailboxProof.ReplicaId.ToArray(), mailboxProof.SigningPublicKey.ToArray());
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

    [Theory]
    [InlineData(4, true)]
    [InlineData(ProductionMailboxTopologyConstants.MaximumClockSkewSeconds, true)]
    [InlineData(ProductionMailboxTopologyConstants.MaximumClockSkewSeconds + 1, false)]
    public void SkewAwareVerification_AcceptsOnlyTheBoundedFutureWindow(
        int futureSeconds,
        bool expected)
    {
        const ulong now = 1_000;
        var descriptor = Descriptor(0x40) with
        {
            ValidFromUnixSeconds = now + (uint)futureSeconds,
            ValidUntilUnixSeconds = now + 1_000
        };
        var proof = new MailboxReplicaMembershipProof
        {
            ReplicaId = descriptor.RouterId,
            SigningPublicKey = descriptor.Ed25519PublicKey,
            Epoch = descriptor.Epoch,
            MembershipCommitment = MembershipRouteDescriptorCodec.ComputeRoot([descriptor]),
            CanonicalInclusionProof = MailboxReplicaRouteProofCodec.Encode(
                descriptor,
                MembershipRouteDescriptorCodec.BuildProofs([descriptor])[0])
        };
        var verifier = new MembershipRoutesMailboxReplicaProofVerifier();

        Assert.False(verifier.VerifyStorageReplica(proof, now));
        Assert.Equal(expected, verifier.VerifyStorageReplica(
            proof, now, ProductionMailboxTopologyConstants.MaximumClockSkewSeconds));
    }

    [Fact]
    public void SkewAwareVerification_RejectsAnUnboundedSkewPolicy()
    {
        var descriptor = Descriptor(0x40);
        var proof = new MailboxReplicaMembershipProof
        {
            ReplicaId = descriptor.RouterId,
            SigningPublicKey = descriptor.Ed25519PublicKey,
            Epoch = descriptor.Epoch,
            MembershipCommitment = MembershipRouteDescriptorCodec.ComputeRoot([descriptor]),
            CanonicalInclusionProof = MailboxReplicaRouteProofCodec.Encode(
                descriptor,
                MembershipRouteDescriptorCodec.BuildProofs([descriptor])[0])
        };

        Assert.False(new MembershipRoutesMailboxReplicaProofVerifier().VerifyStorageReplica(
            proof,
            1_050,
            ProductionMailboxTopologyConstants.MaximumClockSkewSeconds + 1));
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
