using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.GroupV1;
using Sodium;

namespace Deep.Protocol.Tests.GroupV1;

public sealed class GroupProductionAuthorTests
{
    [Fact]
    public async Task FullCreateInviteAcceptCommitAndMessageCycleIsVerifierAccepted()
    {
        var ownerFixture = Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create();
        var inviteeFixture = Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create(1);
        var owner = ownerFixture.Promote(ownerFixture.Dcr); var invitee = inviteeFixture.Promote(inviteeFixture.Dcr);
        var ownerDevice = owner.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId;
        var inviteeDevice = invitee.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId;
        var ownerSigner = new CustodySigner(ownerFixture.Device, ownerDevice.Span);
        var inviteeSigner = new CustodySigner(inviteeFixture.Device, inviteeDevice.Span);

        var genesis = await GroupProductionAuthor.AuthorGenesisAsync(new GroupGenesisAuthoringRequest(
            Bytes(32, 0x30), owner, ownerDevice.Span, "production group", false, 3_600, 30,
            ownerFixture.BootId, ownerFixture.CurrentMonotonicSample), ownerSigner);
        Assert.Equal((ulong)0, BinaryPrimitives.ReadUInt64BigEndian(genesis.Transition.Commit.Field(4).Span));
        Assert.True(genesis.Transition.BindsExactGcp1(genesis.CanonicalPackageBytes.Span));

        var invitation = await GroupProductionAuthor.AuthorInvitationAsync(new GroupInvitationAuthoringRequest(
            genesis.Transition, owner, ownerDevice.Span, invitee, Bytes(32, 0x44), GroupRole.Member, 20, 40), ownerSigner);
        var acceptance = await GroupProductionAuthor.AuthorInvitationAcceptanceAsync(new GroupInvitationAcceptanceAuthoringRequest(
            invitation, invitee, inviteeDevice.Span, 25, 39), inviteeSigner);
        var proposal = await GroupProductionAuthor.AuthorActivationProposalAsync(new GroupActivationProposalAuthoringRequest(
            acceptance, owner, ownerDevice.Span, Bytes(32, 0x45), 20, 60), ownerSigner);
        var successor = await GroupProductionAuthor.AuthorMembershipCommitAsync(new GroupMembershipCommitAuthoringRequest(
            genesis.Transition, proposal, [owner], [invitee, owner], 30, ownerFixture.BootId,
            ownerFixture.CurrentMonotonicSample), ownerSigner);

        Assert.Equal((ulong)1, BinaryPrimitives.ReadUInt64BigEndian(successor.Transition.Commit.Field(4).Span));
        Assert.Equal((ushort)2, BinaryPrimitives.ReadUInt16BigEndian(successor.Transition.Commit.Field(11).Span));
        Assert.True(successor.Transition.BindsExactGcp1(successor.CanonicalPackageBytes.Span));
        Assert.IsType<GroupCommitPackageRecord>(GroupCodec.Decode(successor.CanonicalPackageBytes.Span));

        var message = GroupProductionAuthor.AuthorApplicationMessage(new GroupApplicationMessageAuthoringRequest(
            successor.Transition, invitee, inviteeDevice.Span, Bytes(32, 0x55), 1, 30_000, 35_000,
            GroupApplicationEventKind.Text, "hello"u8, ownerFixture.BootId, ownerFixture.CurrentMonotonicSample));
        Assert.IsType<GroupApplicationMessageRecord>(GroupCodec.Decode(message.CanonicalBytes.Span));
        Assert.Equal(successor.Transition.Commit.ArtifactHash.ToArray(), message.Record.Field(4).ToArray());
        Assert.Equal([GroupDeviceSignaturePurpose.Commit, GroupDeviceSignaturePurpose.Invitation,
            GroupDeviceSignaturePurpose.Proposal, GroupDeviceSignaturePurpose.Commit], ownerSigner.Purposes);
        Assert.Equal([GroupDeviceSignaturePurpose.InvitationAcceptance], inviteeSigner.Purposes);
    }

    [Fact]
    public async Task CustodySignerMismatchAndInvalidSignatureFailClosed()
    {
        var fixture = Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create();
        var contact = fixture.Promote(fixture.Dcr); var device = contact.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId;
        var request = new GroupGenesisAuthoringRequest(Bytes(32, 0x30), contact, device.Span, "g", false, 60, 30,
            fixture.BootId, fixture.CurrentMonotonicSample);
        var foreign = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xd0));
        var mismatch = new CustodySigner(foreign, device.Span);
        Assert.Equal("signer-binding-mismatch", (await Assert.ThrowsAsync<GroupAuthoringException>(async () =>
            await GroupProductionAuthor.AuthorGenesisAsync(request, mismatch))).Code);

        var invalid = new CustodySigner(fixture.Device, device.Span, signingKey: foreign);
        Assert.Equal("signature-invalid", (await Assert.ThrowsAsync<GroupAuthoringException>(async () =>
            await GroupProductionAuthor.AuthorGenesisAsync(request, invalid))).Code);
    }

    [Fact]
    public async Task DirectoryDeviceAndExpirySubstitutionsRejectBeforeCapabilityEmission()
    {
        var ownerFixture = Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create();
        var otherFixture = Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create(1);
        var owner = ownerFixture.Promote(ownerFixture.Dcr); var other = otherFixture.Promote(otherFixture.Dcr);
        var device = owner.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId;
        var signer = new CustodySigner(ownerFixture.Device, device.Span);
        var genesis = await GroupProductionAuthor.AuthorGenesisAsync(new GroupGenesisAuthoringRequest(
            Bytes(32, 0x30), owner, device.Span, "g", false, 60, 30, ownerFixture.BootId,
            ownerFixture.CurrentMonotonicSample), signer);
        Assert.Throws<ArgumentOutOfRangeException>(() => new GroupInvitationAuthoringRequest(
            genesis.Transition, owner, device.Span, other, Bytes(32, 1), GroupRole.Member, 1, 604_802));
        Assert.Equal("member-binding-mismatch", Assert.Throws<GroupAuthoringException>(() =>
            GroupProductionAuthor.AuthorApplicationMessage(new GroupApplicationMessageAuthoringRequest(
                genesis.Transition, other, other.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId.Span,
                Bytes(32, 2), 1, 30_000, 31_000, GroupApplicationEventKind.Text, [],
                ownerFixture.BootId, ownerFixture.CurrentMonotonicSample))).Code);
        Assert.Equal("message-expiry-exceeded", Assert.Throws<GroupAuthoringException>(() =>
            GroupProductionAuthor.AuthorApplicationMessage(new GroupApplicationMessageAuthoringRequest(
                genesis.Transition, owner, device.Span, Bytes(32, 3), 1, 30_000, 91_000,
                GroupApplicationEventKind.Text, [], ownerFixture.BootId,
                ownerFixture.CurrentMonotonicSample))).Code);
    }

    [Fact]
    public void VerifiedOutputsAndSigningRequestAreNotPubliclyConstructible()
    {
        foreach (var type in new[] { typeof(VerifiedAuthoredGroupTransition), typeof(VerifiedGroupInvitation),
                     typeof(VerifiedGroupInvitationAcceptance), typeof(VerifiedGroupActivationProposal),
                     typeof(VerifiedGroupMembershipProposal), typeof(VerifiedGroupApplicationMessage),
                     typeof(GroupDeviceSigningRequest) })
            Assert.Empty(type.GetConstructors());
        Assert.False(GroupCodec.RuntimeActivation);
    }

    [Fact]
    public async Task AuthoringRequestRejectsMemberBoundAndCrossTransitionProposal()
    {
        var ownerFixture = Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create();
        var inviteeFixture = Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create(1);
        var owner = ownerFixture.Promote(ownerFixture.Dcr); var invitee = inviteeFixture.Promote(inviteeFixture.Dcr);
        var ownerDevice = owner.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId;
        var inviteeDevice = invitee.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId;
        var ownerSigner = new CustodySigner(ownerFixture.Device, ownerDevice.Span);
        var inviteeSigner = new CustodySigner(inviteeFixture.Device, inviteeDevice.Span);
        var first = await GroupProductionAuthor.AuthorGenesisAsync(new GroupGenesisAuthoringRequest(
            Bytes(32,0x30),owner,ownerDevice.Span,"first",false,60,30,ownerFixture.BootId,
            ownerFixture.CurrentMonotonicSample),ownerSigner);
        var second = await GroupProductionAuthor.AuthorGenesisAsync(new GroupGenesisAuthoringRequest(
            Bytes(32,0x70),owner,ownerDevice.Span,"second",false,60,30,ownerFixture.BootId,
            ownerFixture.CurrentMonotonicSample),ownerSigner);
        var invitation = await GroupProductionAuthor.AuthorInvitationAsync(new GroupInvitationAuthoringRequest(
            first.Transition,owner,ownerDevice.Span,invitee,Bytes(32,0x40),GroupRole.Member,20,40),ownerSigner);
        var acceptance = await GroupProductionAuthor.AuthorInvitationAcceptanceAsync(new GroupInvitationAcceptanceAuthoringRequest(
            invitation,invitee,inviteeDevice.Span,25,39),inviteeSigner);
        var proposal = await GroupProductionAuthor.AuthorActivationProposalAsync(new GroupActivationProposalAuthoringRequest(
            acceptance,owner,ownerDevice.Span,Bytes(32,0x50),20,60),ownerSigner);

        Assert.Throws<ArgumentOutOfRangeException>(() => new GroupMembershipCommitAuthoringRequest(
            first.Transition, proposal, [owner], Enumerable.Repeat(owner,101).ToArray(), 30,
            ownerFixture.BootId, ownerFixture.CurrentMonotonicSample));
        Assert.Equal("proposal-base-mismatch", (await Assert.ThrowsAsync<GroupAuthoringException>(async () =>
            await GroupProductionAuthor.AuthorMembershipCommitAsync(new GroupMembershipCommitAuthoringRequest(
                second.Transition,proposal,[owner],[owner,invitee],30,ownerFixture.BootId,
                ownerFixture.CurrentMonotonicSample),ownerSigner))).Code);
    }

    [Fact]
    public async Task RoleChangeThenLeaveAreExactVerifierAcceptedTransitions()
    {
        var ownerFixture = Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create();
        var memberFixture = Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create(1);
        var owner = ownerFixture.Promote(ownerFixture.Dcr); var member = memberFixture.Promote(memberFixture.Dcr);
        var ownerDevice = owner.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId;
        var memberDevice = member.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId;
        var ownerSigner = new CustodySigner(ownerFixture.Device, ownerDevice.Span);
        var memberSigner = new CustodySigner(memberFixture.Device, memberDevice.Span);
        var active = await AddMemberAsync(ownerFixture, owner, ownerDevice, ownerSigner,
            member, memberDevice, memberSigner);

        var roleProposal = await GroupProductionAuthor.AuthorRoleChangeProposalAsync(
            new GroupRoleChangeProposalAuthoringRequest(active, owner, ownerDevice.Span, member,
                GroupRole.Admin, Bytes(32, 0x61), 20, 60), ownerSigner);
        Assert.Equal(GroupProposalAction.ChangeRole, roleProposal.Action);
        var promoted = await GroupProductionAuthor.AuthorMembershipChangeCommitAsync(
            new GroupMembershipChangeCommitAuthoringRequest(active, roleProposal, [owner, member],
                [member, owner], 30, ownerFixture.BootId, ownerFixture.CurrentMonotonicSample), ownerSigner);
        Assert.Equal(GroupRole.Admin, RoleOf(promoted.Transition.Commit, member.Directory.Record.DeepAccountId.Span));

        var leaveProposal = await GroupProductionAuthor.AuthorLeaveAccountProposalAsync(
            new GroupLeaveAccountProposalAuthoringRequest(promoted.Transition, member, memberDevice.Span,
                Bytes(32, 0x62), 7, 20, 60), memberSigner);
        Assert.Equal(GroupProposalAction.LeaveAccount, leaveProposal.Action);
        var left = await GroupProductionAuthor.AuthorMembershipChangeCommitAsync(
            new GroupMembershipChangeCommitAuthoringRequest(promoted.Transition, leaveProposal,
                [owner, member], [owner, member], 30, ownerFixture.BootId,
                ownerFixture.CurrentMonotonicSample), ownerSigner);

        Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(left.Transition.Commit.Field(11).Span));
        Assert.True(left.Transition.BindsExactGcp1(left.CanonicalPackageBytes.Span));
        Assert.Throws<InvalidOperationException>(() => RoleOf(left.Transition.Commit,
            member.Directory.Record.DeepAccountId.Span));
    }

    [Fact]
    public async Task RemoveAccountIsExactAndOwnerOrRoleSubstitutionsFailClosed()
    {
        var ownerFixture = Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create();
        var memberFixture = Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create(1);
        var owner = ownerFixture.Promote(ownerFixture.Dcr); var member = memberFixture.Promote(memberFixture.Dcr);
        var ownerDevice = owner.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId;
        var memberDevice = member.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId;
        var ownerSigner = new CustodySigner(ownerFixture.Device, ownerDevice.Span);
        var memberSigner = new CustodySigner(memberFixture.Device, memberDevice.Span);
        var active = await AddMemberAsync(ownerFixture, owner, ownerDevice, ownerSigner,
            member, memberDevice, memberSigner);

        var remove = await GroupProductionAuthor.AuthorRemoveAccountProposalAsync(
            new GroupRemoveAccountProposalAuthoringRequest(active, owner, ownerDevice.Span, member,
                Bytes(32, 0x71), 9, 20, 60), ownerSigner);
        var removed = await GroupProductionAuthor.AuthorMembershipChangeCommitAsync(
            new GroupMembershipChangeCommitAuthoringRequest(active, remove, [owner, member],
                [member, owner], 30, ownerFixture.BootId, ownerFixture.CurrentMonotonicSample), ownerSigner);
        Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(removed.Transition.Commit.Field(11).Span));

        Assert.Equal("owner-removal-forbidden", (await Assert.ThrowsAsync<GroupAuthoringException>(async () =>
            await GroupProductionAuthor.AuthorRemoveAccountProposalAsync(
                new GroupRemoveAccountProposalAuthoringRequest(active, owner, ownerDevice.Span, owner,
                    Bytes(32, 0x72), 0, 20, 60), ownerSigner))).Code);
        Assert.Equal("owner-leave-forbidden", (await Assert.ThrowsAsync<GroupAuthoringException>(async () =>
            await GroupProductionAuthor.AuthorLeaveAccountProposalAsync(
                new GroupLeaveAccountProposalAuthoringRequest(active, owner, ownerDevice.Span,
                    Bytes(32, 0x73), 0, 20, 60), ownerSigner))).Code);
        Assert.Equal("role-unchanged", (await Assert.ThrowsAsync<GroupAuthoringException>(async () =>
            await GroupProductionAuthor.AuthorRoleChangeProposalAsync(
                new GroupRoleChangeProposalAuthoringRequest(active, owner, ownerDevice.Span, member,
                    GroupRole.Member, Bytes(32, 0x74), 20, 60), ownerSigner))).Code);
    }

    private sealed class CustodySigner : IGroupDeviceCustodySigner
    {
        private readonly KeyPair advertised, signing;
        public CustodySigner(KeyPair advertised, ReadOnlySpan<byte> deviceId, KeyPair? signingKey = null)
        { this.advertised = advertised; signing = signingKey ?? advertised; DeviceId = deviceId.ToArray(); }
        public ReadOnlyMemory<byte> DeviceId { get; }
        public ReadOnlyMemory<byte> Ed25519PublicKey => advertised.PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => Bytes(32, 0x90);
        public List<GroupDeviceSignaturePurpose> Purposes { get; } = [];
        public ValueTask<int> SignAsync(GroupDeviceSigningRequest request, Memory<byte> signature64, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Purposes.Add(request.Purpose);
            var signature = PublicKeyAuth.SignDetached(request.SigningInput.ToArray(), signing.PrivateKey);
            signature.CopyTo(signature64); CryptographicOperations.ZeroMemory(signature); return ValueTask.FromResult(64);
        }
    }

    private static async Task<VerifiedGroupTransition> AddMemberAsync(
        Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture ownerFixture,
        VerifiedContactBundleClosure owner, ReadOnlyMemory<byte> ownerDevice, CustodySigner ownerSigner,
        VerifiedContactBundleClosure member, ReadOnlyMemory<byte> memberDevice, CustodySigner memberSigner)
    {
        var genesis = await GroupProductionAuthor.AuthorGenesisAsync(new GroupGenesisAuthoringRequest(
            Bytes(32, 0x30), owner, ownerDevice.Span, "membership", false, 3_600, 30,
            ownerFixture.BootId, ownerFixture.CurrentMonotonicSample), ownerSigner);
        var invitation = await GroupProductionAuthor.AuthorInvitationAsync(new GroupInvitationAuthoringRequest(
            genesis.Transition, owner, ownerDevice.Span, member, Bytes(32, 0x41),
            GroupRole.Member, 20, 60), ownerSigner);
        var acceptance = await GroupProductionAuthor.AuthorInvitationAcceptanceAsync(
            new GroupInvitationAcceptanceAuthoringRequest(invitation, member, memberDevice.Span, 25, 59), memberSigner);
        var proposal = await GroupProductionAuthor.AuthorActivationProposalAsync(
            new GroupActivationProposalAuthoringRequest(acceptance, owner, ownerDevice.Span,
                Bytes(32, 0x42), 20, 60), ownerSigner);
        var successor = await GroupProductionAuthor.AuthorMembershipCommitAsync(
            new GroupMembershipCommitAuthoringRequest(genesis.Transition, proposal, [owner], [owner, member],
                30, ownerFixture.BootId, ownerFixture.CurrentMonotonicSample), ownerSigner);
        return successor.Transition;
    }

    private static GroupRole RoleOf(GroupCommitRecord commit, ReadOnlySpan<byte> account)
    {
        var members = commit.Field(12).Span; var at = 0;
        while (at < members.Length)
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(members[at..]);
            var row = members.Slice(at + 2, length);
            if (row[..32].SequenceEqual(account)) return (GroupRole)row[32];
            at += 2 + length;
        }
        throw new InvalidOperationException("Member not found.");
    }
    private static byte[] Bytes(int length, byte seed) => Enumerable.Range(0, length).Select(index => unchecked((byte)(seed + index))).ToArray();
}
