using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.GroupV1;

public static partial class GroupCodec
{
    /// <summary>
    /// The Contact verifier capability now binds exact ADC1/ADH1/ADP1 evidence,
    /// current DMD1/DRS1 identity state and trusted time without accepting caller keys.
    /// </summary>
    public static bool AccountDirectoryCapabilityAvailable => true;

    public static VerifiedGroupControlRendezvous VerifyControlRendezvous(
        GroupControlRendezvousRecord record,
        Deep.Protocol.ContactV1.VerifiedContactBundleClosure owner,
        ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(record); ArgumentNullException.ThrowIfNull(owner);
        var trustedLower = owner.Freshness.TrustedLowerUnixSeconds;
        var trustedUpper = owner.Freshness.TrustedUpperUnixSeconds;
        if (!record.FieldSpan(1).SequenceEqual(owner.Directory.Record.NetworkId.Span) ||
            U64(record.FieldSpan(12)) > trustedLower || U64(record.FieldSpan(13)) <= trustedUpper ||
            !owner.Freshness.IsCurrentAtMonotonic(currentBootId, currentMonotonicSample))
            Reject(GroupValidationStage.Closure, "ControlRendezvousNotCurrent");
        VerifiedDevice? signer = null;
        foreach (var device in owner.Directory.Identity.ActiveDevices)
            if (device.Certificate.DeviceId.Span.SequenceEqual(record.FieldSpan(10))) { signer = device; break; }
        if (signer is null || !record.FieldSpan(11).SequenceEqual(ReferenceBytes(ProtocolMagic.DPD1, signer.Certificate.CanonicalHash.Span)))
            Reject(GroupValidationStage.Closure, "ControlRendezvousSignerNotCurrent");
        var currentSigner = signer!;
        if (currentSigner.Certificate.IssuedAtUnixSeconds > trustedLower ||
            currentSigner.Certificate.ExpiresAtUnixSeconds <= trustedUpper)
            Reject(GroupValidationStage.Closure, "ControlRendezvousSignerNotCurrent");
        if (!PublicKeyAuth.VerifyDetached(record.FieldSpan(14).ToArray(), record.SignatureInput.ToArray(),
                currentSigner.Certificate.DeviceEd25519PublicKey.ToArray()))
            Reject(GroupValidationStage.Signature, "ControlRendezvousSignatureFailed");
        return new VerifiedGroupControlRendezvous(record, owner);
    }

    public static VerifiedGroupTransition VerifyCommitPackage(
        GroupCommitPackageRecord package,
        VerifiedGroupTransition? previous,
        GroupIdentityClosure identities,
        IGroupClosureResolver resolver)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(identities);
        ArgumentNullException.ThrowIfNull(resolver);
        var predecessor = previous?.Commit;
        var commit = (GroupCommitRecord)Decode(ProtocolMagic.DGC1, ExactLp(package.FieldSpan(4)));
        if (!commit.FieldSpan(1).SequenceEqual(package.FieldSpan(1)) ||
            !commit.FieldSpan(2).SequenceEqual(package.FieldSpan(2)) ||
            !commit.FieldSpan(4).SequenceEqual(package.FieldSpan(3)))
            Reject(GroupValidationStage.Closure, "CommitHeaderMismatch");

        var proposals = ReadLpList(package.FieldSpan(6), U16(package.FieldSpan(5)), 1, 65535, ProtocolMagic.DGP1);
        EnsureStrictHashes(proposals);
        var supports = ReadSupport(package.FieldSpan(8), U32(package.FieldSpan(7)));
        VerifySupport(supports, resolver);
        var pairs = ReadInvitationPairs(package.FieldSpan(10), U16(package.FieldSpan(9)));
        VerifyInvitePairs(pairs);
        var transfer = package.FieldSpan(11).Length == 0
            ? null
            : (GroupEmergencyTransferRecord)Decode(ProtocolMagic.DGT1, ExactLp(package.FieldSpan(11)));

        var requiredCurrentAccounts = ReadMembers(commit.FieldSpan(12)).Select(static member => Convert.ToHexString(member.Account)).ToHashSet(StringComparer.Ordinal);
        foreach (var proposal in proposals)
        {
            var action = (GroupProposalAction)U16(proposal.FieldSpan(9));
            if (action is GroupProposalAction.RemoveAccount or GroupProposalAction.LeaveAccount)
                requiredCurrentAccounts.Add(Convert.ToHexString(proposal.FieldSpan(10)[..32]));
        }
        var suppliedCurrentAccounts = identities.CurrentDirectories.Select(static closure => Convert.ToHexString(closure.Directory.Record.DeepAccountId.Span)).ToHashSet(StringComparer.Ordinal);
        var requiredBaseAccounts = predecessor is null ? new HashSet<string>(StringComparer.Ordinal) :
            ReadMembers(predecessor.FieldSpan(12)).Select(static member => Convert.ToHexString(member.Account)).ToHashSet(StringComparer.Ordinal);
        var suppliedBaseAccounts = identities.BaseDirectories.Select(static closure => Convert.ToHexString(closure.Directory.Record.DeepAccountId.Span)).ToHashSet(StringComparer.Ordinal);
        if (!requiredCurrentAccounts.SetEquals(suppliedCurrentAccounts) || !requiredBaseAccounts.SetEquals(suppliedBaseAccounts))
            Reject(GroupValidationStage.Closure, "VerifiedIdentitySetNotExact");
        var required = RequiredReferences(commit, proposals, pairs);
        AddIdentityReferences(required, identities);
        var actual = supports.Select(static support => Convert.ToHexString(support.Reference.CanonicalBytes.Span))
            .ToHashSet(StringComparer.Ordinal);
        if (!required.SetEquals(actual)) Reject(GroupValidationStage.Closure, "SupportClosureNotExact");

        var index = new IdentityIndex(
            identities, supports, commit.FieldSpan(1), U64(commit.FieldSpan(16)),
            predecessor is null ? null : U64(predecessor.FieldSpan(16)));
        if (predecessor is not null)
            VerifyMemberClosures(ReadMembers(predecessor.FieldSpan(12)), index, useBase: true);
        VerifyMemberClosures(ReadMembers(commit.FieldSpan(12)), index, useBase: false);
        VerifyControlSignatures(commit, predecessor, proposals, pairs, transfer, index);
        VerifyTransition(commit, predecessor, proposals, pairs, transfer, index);
        return new VerifiedGroupTransitionImpl(commit, predecessor, package.CanonicalBytes.Span);
    }

    private static void VerifyControlSignatures(
        GroupCommitRecord commit,
        GroupCommitRecord? predecessor,
        List<GroupRecord> proposals,
        List<InvitationPair> pairs,
        GroupEmergencyTransferRecord? transfer,
        IdentityIndex index)
    {
        foreach (var proposal in proposals)
            VerifyDeviceSignatureFromClosure(proposal, proposal.FieldSpan(6), proposal.FieldSpan(7), proposal.FieldSpan(8), index, useBase: true);
        foreach (var pair in pairs)
        {
            VerifyDeviceSignatureFromClosure(pair.Invitation, pair.Invitation.FieldSpan(6), pair.Invitation.FieldSpan(7), pair.Invitation.FieldSpan(8), index, useBase: true);
            VerifyDeviceSignatureFromClosure(pair.Acceptance, pair.Acceptance.FieldSpan(5), pair.Acceptance.FieldSpan(6), pair.Acceptance.FieldSpan(7), index, useBase: false);
        }

        if (predecessor is null)
            VerifyDeviceSignatureFromClosure(commit, commit.FieldSpan(6), commit.FieldSpan(7), commit.FieldSpan(8), index, useBase: false);
        else if (transfer is not null)
            VerifyDeviceSignatureFromClosure(commit, commit.FieldSpan(6), transfer.FieldSpan(6), transfer.FieldSpan(7), index, useBase: false);
        else
            VerifyDeviceSignatureFromClosure(commit, predecessor.FieldSpan(6), predecessor.FieldSpan(7), predecessor.FieldSpan(8), index, useBase: true);

        if (transfer is not null)
        {
            var owner = index.RequireCurrentAccount(commit.FieldSpan(6));
            if (!PublicKeyAuth.VerifyDetached(transfer.FieldSpan(14).ToArray(), transfer.SignatureInput.Span.ToArray(),
                    owner.Directory.Identity.Account.Certificate.AccountEd25519PublicKey.ToArray()))
                Reject(GroupValidationStage.Signature, "EmergencyTransferSignatureFailed");
            _ = index.RequireCurrentDevice(commit.FieldSpan(6), transfer.FieldSpan(6), transfer.FieldSpan(7));
            if (!transfer.FieldSpan(8).SequenceEqual(owner.Directory.Record.RecordHash.Span))
                Reject(GroupValidationStage.Closure, "EmergencyTransferDirectoryMismatch");
            RequireReference(transfer.FieldSpan(9), ProtocolMagic.DRS1, owner.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span);
            RequireReference(transfer.FieldSpan(13), ProtocolMagic.DPA1, owner.Directory.Identity.Account.Certificate.CanonicalHash.Span);
        }
    }

    private static void AddIdentityReferences(HashSet<string> required, GroupIdentityClosure identities)
    {
        foreach (var closure in identities.BaseDirectories.Concat(identities.CurrentDirectories))
        {
            var directory = closure.Directory;
            required.Add(Convert.ToHexString(closure.Freshness.ExactAdc1Reference.Span));
            required.Add(Convert.ToHexString(closure.Freshness.ExactAdh1CoreReference.Span));
            required.Add(Convert.ToHexString(ReferenceBytes(ProtocolMagic.ADP1, closure.Freshness.ExactAdp1Hash.Span)));
            required.Add(Convert.ToHexString(ReferenceBytes(ProtocolMagic.DMD1, directory.Record.RecordHash.Span)));
            required.Add(Convert.ToHexString(ReferenceBytes(ProtocolMagic.DRS1, directory.Identity.Revocations.Snapshot.CanonicalHash.Span)));
            foreach (var device in directory.Identity.ActiveDevices)
                required.Add(Convert.ToHexString(ReferenceBytes(ProtocolMagic.DPD1, device.Certificate.CanonicalHash.Span)));
        }
    }

    private static void VerifyDeviceSignatureFromClosure(
        GroupRecord record,
        ReadOnlySpan<byte> account,
        ReadOnlySpan<byte> device,
        ReadOnlySpan<byte> dpdReference,
        IdentityIndex index,
        bool useBase)
    {
        var verified = useBase ? index.RequireBaseDevice(account, device, dpdReference) : index.RequireCurrentDevice(account, device, dpdReference);
        if (!PublicKeyAuth.VerifyDetached(record.FieldSpan(SignatureTag(record.Magic)).ToArray(),
                record.SignatureInput.Span.ToArray(), verified.Certificate.DeviceEd25519PublicKey.ToArray()))
            Reject(GroupValidationStage.Signature, "DeviceSignatureVerificationFailed");
    }

    private static void VerifyTransition(
        GroupCommitRecord commit,
        GroupCommitRecord? predecessor,
        List<GroupRecord> proposals,
        List<InvitationPair> pairs,
        GroupEmergencyTransferRecord? transfer,
        IdentityIndex index)
    {
        var epoch = U64(commit.FieldSpan(4));
        if (predecessor is null)
        {
            if (epoch != 0 || !Zero(commit.FieldSpan(5)) || proposals.Count != 0 || pairs.Count != 0 || transfer is not null)
                Reject(GroupValidationStage.Transition, "InvalidGenesisCommit");
            var genesisMembers = ReadMembers(commit.FieldSpan(12));
            if (genesisMembers.Count != 1 || genesisMembers[0].Role != GroupRole.Owner ||
                !genesisMembers[0].Account.AsSpan().SequenceEqual(commit.FieldSpan(6)) ||
                !genesisMembers[0].Devices.Any(device => device.Id.AsSpan().SequenceEqual(commit.FieldSpan(7))))
                Reject(GroupValidationStage.Transition, "GenesisMustContainOnlyOwnerCurrentDevices");
            return;
        }

        if (!commit.FieldSpan(1).SequenceEqual(predecessor.FieldSpan(1)) ||
            !commit.FieldSpan(2).SequenceEqual(predecessor.FieldSpan(2)) ||
            !commit.FieldSpan(6).SequenceEqual(predecessor.FieldSpan(6)) ||
            U64(predecessor.FieldSpan(4)) == ulong.MaxValue || epoch != U64(predecessor.FieldSpan(4)) + 1 ||
            !commit.FieldSpan(5).SequenceEqual(predecessor.ArtifactHash.Span))
            Reject(GroupValidationStage.Transition, "InvalidCommitSuccessor");

        var expectedHashes = proposals.Select(static proposal => proposal.ArtifactHash.ToArray()).ToArray();
        if (expectedHashes.Length != U16(commit.FieldSpan(9)) ||
            !expectedHashes.SelectMany(static hash => hash).ToArray().AsSpan().SequenceEqual(commit.FieldSpan(10)))
            Reject(GroupValidationStage.Transition, "ProposalSetMismatch");

        var baseMembers = ReadMembers(predecessor.FieldSpan(12));
        var members = baseMembers.Select(CloneMember).ToList();
        var baseByAccount = baseMembers.ToDictionary(static member => Convert.ToHexString(member.Account), StringComparer.Ordinal);
        VerifyInvitationsAgainstBase(pairs, predecessor, baseByAccount, index, U64(commit.FieldSpan(16)));
        var invitationByReference = pairs.ToDictionary(
            static pair => Convert.ToHexString(pair.InvitationReference.CanonicalBytes.Span), StringComparer.Ordinal);
        var consumedInvitations = new HashSet<string>(StringComparer.Ordinal);
        var targets = new HashSet<string>(StringComparer.Ordinal);
        var commitTime = U64(commit.FieldSpan(16));
        var nextSequencer = predecessor.FieldSpan(7).ToArray();
        var expectedName = predecessor.FieldSpan(13).ToArray();
        var expectedHistoryPolicy = predecessor.FieldSpan(14).ToArray();
        var expectedOrdinaryExpiry = predecessor.FieldSpan(15).ToArray();

        foreach (var proposal in proposals)
        {
            if (!proposal.FieldSpan(1).SequenceEqual(predecessor.FieldSpan(1)) ||
                !proposal.FieldSpan(2).SequenceEqual(predecessor.FieldSpan(2)) ||
                U64(proposal.FieldSpan(3)) != U64(predecessor.FieldSpan(4)) ||
                !proposal.FieldSpan(4).SequenceEqual(predecessor.ArtifactHash.Span) ||
                commitTime < U64(proposal.FieldSpan(11)) || commitTime >= U64(proposal.FieldSpan(12)))
                Reject(GroupValidationStage.Transition, "ProposalBaseMismatch");

            var proposerKey = Convert.ToHexString(proposal.FieldSpan(6));
            if (!baseByAccount.TryGetValue(proposerKey, out var baseProposer) ||
                !members.Any(member => member.Account.AsSpan().SequenceEqual(proposal.FieldSpan(6))))
                Reject(GroupValidationStage.Transition, "ProposerNotActive");
            var currentProposer = members.Single(member => member.Account.AsSpan().SequenceEqual(proposal.FieldSpan(6)));
            var baseDevice = FindDevice(baseProposer!, proposal.FieldSpan(7));
            var currentDevice = FindDevice(currentProposer, proposal.FieldSpan(7));
            if (baseDevice is null || currentDevice is null ||
                !baseDevice.Reference.AsSpan().SequenceEqual(proposal.FieldSpan(8)) ||
                !currentDevice.Reference.AsSpan().SequenceEqual(proposal.FieldSpan(8)))
                Reject(GroupValidationStage.Transition, "ProposerDeviceNotActive");
            var action = (GroupProposalAction)U16(proposal.FieldSpan(9));
            Authorize(action, proposal.FieldSpan(6), baseProposer!.Role, currentProposer.Role, proposal.FieldSpan(10));
            if (baseProposer.Role == GroupRole.Admin && action is GroupProposalAction.RemoveAccount or
                    GroupProposalAction.ChangeRole or GroupProposalAction.AddDevice or GroupProposalAction.RemoveDevice &&
                baseByAccount.TryGetValue(Convert.ToHexString(proposal.FieldSpan(10)[..32]), out var targetMember) &&
                targetMember.Role == GroupRole.Owner)
                Reject(GroupValidationStage.Transition, "AdminCannotMutateOwner");
            if (action == GroupProposalAction.ChangeProfile)
            {
                var actionPayload = proposal.FieldSpan(10);
                var nameLength = U16(actionPayload);
                expectedName = actionPayload.Slice(2, nameLength).ToArray();
                expectedHistoryPolicy = actionPayload.Slice(2 + nameLength, 1).ToArray();
                expectedOrdinaryExpiry = actionPayload.Slice(3 + nameLength, 4).ToArray();
            }
            ApplyAction(action, proposal.FieldSpan(10), proposal, members, invitationByReference,
                consumedInvitations, targets, index, ref nextSequencer);
            EnforceGroupLimits(members);
        }

        if (consumedInvitations.Count != pairs.Count)
            Reject(GroupValidationStage.Closure, "InvitationPairSetMismatch");

        if (transfer is not null)
        {
            if (targets.Contains("sequencer"))
                Reject(GroupValidationStage.Transition, "ConflictingSequencerTransfers");
            if (!transfer.FieldSpan(1).SequenceEqual(predecessor.FieldSpan(1)) ||
                !transfer.FieldSpan(2).SequenceEqual(predecessor.FieldSpan(2)) ||
                !transfer.FieldSpan(3).SequenceEqual(ArtifactReference(ProtocolMagic.DGC1, predecessor).CanonicalBytes.Span) ||
                U64(transfer.FieldSpan(4)) != U64(predecessor.FieldSpan(4)) ||
                !transfer.FieldSpan(5).SequenceEqual(predecessor.FieldSpan(7)) ||
                commitTime < U64(transfer.FieldSpan(11)) || commitTime >= U64(transfer.FieldSpan(12)))
                Reject(GroupValidationStage.Transition, "EmergencyTransferMismatch");
            nextSequencer = transfer.FieldSpan(6).ToArray();
        }

        if (!nextSequencer.AsSpan().SequenceEqual(commit.FieldSpan(7)))
            Reject(GroupValidationStage.Transition, "SequencerResultMismatch");
        var owner = members.SingleOrDefault(static member => member.Role == GroupRole.Owner);
        if (owner is null || !owner.Account.AsSpan().SequenceEqual(commit.FieldSpan(6)) ||
            FindDevice(owner, commit.FieldSpan(7)) is not { } resultingSequencer ||
            !resultingSequencer.Reference.AsSpan().SequenceEqual(commit.FieldSpan(8)))
            Reject(GroupValidationStage.Transition, "OwnerResultMismatch");

        var serialized = SerializeMembers(members);
        if (!serialized.AsSpan().SequenceEqual(commit.FieldSpan(12)) ||
            !expectedName.AsSpan().SequenceEqual(commit.FieldSpan(13)) ||
            !expectedHistoryPolicy.AsSpan().SequenceEqual(commit.FieldSpan(14)) ||
            !expectedOrdinaryExpiry.AsSpan().SequenceEqual(commit.FieldSpan(15)))
            Reject(GroupValidationStage.Transition, "ResultStateMismatch");
    }

    private static void Authorize(GroupProposalAction action, ReadOnlySpan<byte> proposer, GroupRole baseRole, GroupRole currentRole, ReadOnlySpan<byte> payload)
    {
        if (baseRole != currentRole) Reject(GroupValidationStage.Transition, "ProposalAuthorizationChanged");
        var ownLeave = action == GroupProposalAction.LeaveAccount && payload[..32].SequenceEqual(proposer);
        var allowed = baseRole switch
        {
            GroupRole.Owner => action != GroupProposalAction.LeaveAccount,
            GroupRole.Admin => action is GroupProposalAction.ActivateAcceptedInvite or GroupProposalAction.RemoveAccount or
                GroupProposalAction.ChangeRole or GroupProposalAction.AddDevice or GroupProposalAction.RemoveDevice or
                GroupProposalAction.ChangeProfile || ownLeave,
            GroupRole.Member => ownLeave,
            _ => false,
        };
        if (!allowed) Reject(GroupValidationStage.Transition, "ProposalUnauthorized");
    }

    private static void VerifyInvitationsAgainstBase(
        IEnumerable<InvitationPair> pairs,
        GroupCommitRecord predecessor,
        IReadOnlyDictionary<string, Member> baseMembers,
        IdentityIndex index,
        ulong commitTime)
    {
        foreach (var pair in pairs)
        {
            var invitation = pair.Invitation;
            var acceptance = pair.Acceptance;
            baseMembers.TryGetValue(Convert.ToHexString(invitation.FieldSpan(6)), out var inviter);
            if (!invitation.FieldSpan(1).SequenceEqual(predecessor.FieldSpan(1)) ||
                !invitation.FieldSpan(2).SequenceEqual(predecessor.FieldSpan(2)) ||
                U64(invitation.FieldSpan(4)) != U64(predecessor.FieldSpan(4)) ||
                !invitation.FieldSpan(5).SequenceEqual(predecessor.ArtifactHash.Span) ||
                inviter is null ||
                inviter.Role is not (GroupRole.Owner or GroupRole.Admin) ||
                !acceptance.FieldSpan(1).SequenceEqual(invitation.FieldSpan(1)) ||
                !acceptance.FieldSpan(2).SequenceEqual(invitation.FieldSpan(2)) ||
                !acceptance.FieldSpan(3).SequenceEqual(invitation.FieldSpan(3)) ||
                !acceptance.FieldSpan(4).SequenceEqual(pair.InvitationReference.CanonicalBytes.Span) ||
                !acceptance.FieldSpan(5).SequenceEqual(invitation.FieldSpan(9)) ||
                U64(acceptance.FieldSpan(13)) < U64(invitation.FieldSpan(16)) ||
                U64(acceptance.FieldSpan(14)) > U64(invitation.FieldSpan(17)) ||
                commitTime < U64(invitation.FieldSpan(16)) || commitTime >= U64(invitation.FieldSpan(17)) ||
                commitTime < U64(acceptance.FieldSpan(13)) || commitTime >= U64(acceptance.FieldSpan(14)))
                Reject(GroupValidationStage.Transition, "InvitationBaseMismatch");
            var inviterDevice = FindDevice(inviter!, invitation.FieldSpan(7));
            if (inviterDevice is null || !inviterDevice.Reference.AsSpan().SequenceEqual(invitation.FieldSpan(8)))
                Reject(GroupValidationStage.Transition, "InviterDeviceNotActive");
            _ = index.RequireBaseDevice(invitation.FieldSpan(6), invitation.FieldSpan(7), invitation.FieldSpan(8));
            _ = index.RequireCurrentDevice(acceptance.FieldSpan(5), acceptance.FieldSpan(6), acceptance.FieldSpan(7));
            var invitee = index.RequireCurrentAccount(acceptance.FieldSpan(5));
            RequireDirectoryEvidence(invitee, acceptance.FieldSpan(8), acceptance.FieldSpan(9), acceptance.FieldSpan(10));
            if (!acceptance.FieldSpan(11).SequenceEqual(invitee.Directory.Record.RecordHash.Span))
                Reject(GroupValidationStage.Closure, "InvitationDirectoryMismatch");
            RequireReference(acceptance.FieldSpan(12), ProtocolMagic.DRS1, invitee.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span);
        }
    }

    private static void ApplyAction(
        GroupProposalAction action,
        ReadOnlySpan<byte> payload,
        GroupRecord proposal,
        List<Member> members,
        Dictionary<string, InvitationPair> invitations,
        HashSet<string> consumedInvitations,
        HashSet<string> targets,
        IdentityIndex index,
        ref byte[] nextSequencer)
    {
        string AccountKey(ReadOnlySpan<byte> account) => "account:" + Convert.ToHexString(account);
        void Claim(string key) { if (!targets.Add(key)) Reject(GroupValidationStage.Transition, "ConflictingProposals"); }
        switch (action)
        {
            case GroupProposalAction.ActivateAcceptedInvite:
            {
                Claim(AccountKey(payload.Slice(76, 32)));
                var inviteKey = Convert.ToHexString(payload[..38]);
                if (!invitations.TryGetValue(inviteKey, out var pair) || !consumedInvitations.Add(inviteKey) ||
                    !pair.AcceptanceReference.CanonicalBytes.Span.SequenceEqual(payload.Slice(38, 38)) ||
                    !pair.Invitation.FieldSpan(9).SequenceEqual(payload.Slice(76, 32)) ||
                    !pair.Invitation.FieldSpan(10).SequenceEqual(payload.Slice(108, 1)) ||
                    !pair.Acceptance.FieldSpan(8).SequenceEqual(payload.Slice(109, 38)) ||
                    !pair.Acceptance.FieldSpan(9).SequenceEqual(payload.Slice(147, 38)) ||
                    !pair.Acceptance.FieldSpan(10).SequenceEqual(payload.Slice(185, 32)) ||
                    !pair.Acceptance.FieldSpan(11).SequenceEqual(payload.Slice(217, 32)) ||
                    !pair.Acceptance.FieldSpan(12).SequenceEqual(payload.Slice(249, 38)) ||
                    FindMember(members, payload.Slice(76, 32), required: false) is not null)
                    Reject(GroupValidationStage.Transition, "InvitationActivationMismatch");
                var directory = index.RequireCurrentAccount(payload.Slice(76, 32));
                RequireDirectoryEvidence(directory, payload.Slice(109, 38), payload.Slice(147, 38), payload.Slice(185, 32));
                members.Add(MemberFromDirectory(directory, (GroupRole)payload[108]));
                break;
            }
            case GroupProposalAction.RemoveAccount:
            case GroupProposalAction.LeaveAccount:
            {
                Claim(AccountKey(payload[..32]));
                var member = FindMember(members, payload[..32], required: true)!;
                RequireMemberHash(member, payload.Slice(32, 32));
                if (member.Role == GroupRole.Owner) Reject(GroupValidationStage.Transition, "OwnerRemovalForbidden");
                members.Remove(member);
                break;
            }
            case GroupProposalAction.ChangeRole:
            {
                Claim(AccountKey(payload[..32]));
                var member = FindMember(members, payload[..32], required: true)!;
                RequireMemberHash(member, payload.Slice(34, 32));
                if ((byte)member.Role != payload[32] || member.Role == GroupRole.Owner) Reject(GroupValidationStage.Transition, "RolePreconditionFailed");
                members[members.IndexOf(member)] = member with { Role = (GroupRole)payload[33] };
                break;
            }
            case GroupProposalAction.AddDevice:
            case GroupProposalAction.RemoveDevice:
            {
                Claim(AccountKey(payload[..32]));
                var member = FindMember(members, payload[..32], required: true)!;
                var directory = index.RequireCurrentAccount(payload[..32]);
                RequireReference(payload.Slice(134, 38), ProtocolMagic.DRS1, directory.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span);
                if (!payload.Slice(102, 32).SequenceEqual(directory.Directory.Record.RecordHash.Span)) Reject(GroupValidationStage.Closure, "DirectoryHashMismatch");
                if (action == GroupProposalAction.AddDevice)
                {
                    if (!payload.Slice(172, 32).SequenceEqual(directory.Freshness.ExactAdp1Hash.Span)) Reject(GroupValidationStage.Closure, "DirectoryProofHashMismatch");
                    _ = index.RequireCurrentDevice(payload[..32], payload.Slice(32, 32), payload.Slice(64, 38));
                    if (FindDevice(member, payload.Slice(32, 32)) is not null) Reject(GroupValidationStage.Transition, "DeviceAlreadyPresent");
                }
                else
                {
                    var old = FindDevice(member, payload.Slice(32, 32));
                    if (old is null || !old.Reference.AsSpan().SequenceEqual(payload.Slice(64, 38))) Reject(GroupValidationStage.Transition, "DevicePreconditionFailed");
                }
                var replacement = MemberFromDirectory(directory, member.Role);
                VerifySingleDeviceDelta(member, replacement, payload.Slice(32, 32), payload.Slice(64, 38), action);
                members[members.IndexOf(member)] = replacement;
                break;
            }
            case GroupProposalAction.ChangeProfile:
                Claim("profile");
                break;
            case GroupProposalAction.TransferOwnerDevice:
            {
                Claim("sequencer");
                var owner = members.Single(member => member.Role == GroupRole.Owner);
                if (FindDevice(owner, payload[..32]) is null ||
                    !nextSequencer.AsSpan().SequenceEqual(payload[..32]))
                    Reject(GroupValidationStage.Transition, "SequencerPreconditionFailed");
                _ = index.RequireCurrentDevice(owner.Account, payload.Slice(32, 32), payload.Slice(64, 38));
                var directory = index.RequireCurrentAccount(owner.Account);
                if (!payload.Slice(102, 32).SequenceEqual(directory.Directory.Record.RecordHash.Span)) Reject(GroupValidationStage.Closure, "DirectoryHashMismatch");
                RequireReference(payload.Slice(134, 38), ProtocolMagic.DRS1, directory.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span);
                nextSequencer = payload.Slice(32, 32).ToArray();
                break;
            }
            default:
                Reject(GroupValidationStage.Transition, "InvalidAction");
                break;
        }
    }

    private static Member MemberFromDirectory(VerifiedAccountDirectory directory, GroupRole role)
    {
        var verified = directory.Directory;
        var devices = verified.Identity.ActiveDevices
            .OrderBy(static device => device.Certificate.DeviceId, ReadOnlyMemoryComparer.Instance)
            .Select(static device => new Device(device.Certificate.DeviceId.ToArray(), ReferenceBytes(ProtocolMagic.DPD1, device.Certificate.CanonicalHash.Span)))
            .ToList();
        return new Member(verified.Record.DeepAccountId.ToArray(), role,
            directory.Freshness.ExactAdc1Reference.ToArray(), directory.Freshness.ExactAdh1CoreReference.ToArray(),
            directory.Freshness.ExactAdp1Hash.ToArray(), verified.Record.DirectoryGeneration, verified.Record.RecordHash.ToArray(),
            ReferenceBytes(ProtocolMagic.DRS1, verified.Identity.Revocations.Snapshot.CanonicalHash.Span), devices);
    }

    private static void VerifyMemberClosures(IEnumerable<Member> members, IdentityIndex index, bool useBase)
    {
        foreach (var member in members)
        {
            var directory = useBase
                ? index.RequireBaseAccount(member.Account)
                : index.RequireCurrentAccount(member.Account);
            var expected = MemberFromDirectory(directory, member.Role);
            if (!SerializeMember(member).AsSpan().SequenceEqual(SerializeMember(expected)))
                Reject(GroupValidationStage.Closure, "MemberIdentityClosureMismatch");
        }
    }

    private static void VerifySingleDeviceDelta(
        Member before,
        Member after,
        ReadOnlySpan<byte> targetDeviceId,
        ReadOnlySpan<byte> targetDpdReference,
        GroupProposalAction action)
    {
        var beforeById = before.Devices.ToDictionary(
            static device => Convert.ToHexString(device.Id), StringComparer.Ordinal);
        var afterById = after.Devices.ToDictionary(
            static device => Convert.ToHexString(device.Id), StringComparer.Ordinal);
        var target = Convert.ToHexString(targetDeviceId);

        foreach (var pair in beforeById)
        {
            if (pair.Key == target && action == GroupProposalAction.RemoveDevice)
                continue;
            if (!afterById.TryGetValue(pair.Key, out var unchanged) ||
                !unchanged.Reference.AsSpan().SequenceEqual(pair.Value.Reference))
                Reject(GroupValidationStage.Transition, "DeviceDirectoryDeltaMismatch");
        }

        if (action == GroupProposalAction.AddDevice)
        {
            if (beforeById.ContainsKey(target) || afterById.Count != beforeById.Count + 1 ||
                !afterById.TryGetValue(target, out var added) ||
                !added.Reference.AsSpan().SequenceEqual(targetDpdReference))
                Reject(GroupValidationStage.Transition, "DeviceDirectoryDeltaMismatch");
        }
        else if (action == GroupProposalAction.RemoveDevice)
        {
            if (!beforeById.TryGetValue(target, out var removed) ||
                !removed.Reference.AsSpan().SequenceEqual(targetDpdReference) ||
                afterById.ContainsKey(target) || beforeById.Count != afterById.Count + 1)
                Reject(GroupValidationStage.Transition, "DeviceDirectoryDeltaMismatch");
        }
        else
        {
            Reject(GroupValidationStage.Transition, "InvalidDeviceDirectoryDeltaAction");
        }
    }

    private static void RequireMemberHash(Member member, ReadOnlySpan<byte> expected)
    {
        if (!SHA256.HashData(SerializeMember(member)).AsSpan().SequenceEqual(expected))
            Reject(GroupValidationStage.Transition, "MemberEntryHashMismatch");
    }

    private static Member? FindMember(List<Member> members, ReadOnlySpan<byte> account, bool required)
    {
        foreach (var member in members)
            if (member.Account.AsSpan().SequenceEqual(account)) return member;
        if (required) Reject(GroupValidationStage.Transition, "MemberPreconditionFailed");
        return null;
    }

    private static Device? FindDevice(Member member, ReadOnlySpan<byte> deviceId)
    {
        foreach (var device in member.Devices)
            if (device.Id.AsSpan().SequenceEqual(deviceId)) return device;
        return null;
    }

    private static Member CloneMember(Member member) => member with
    {
        Account = member.Account.ToArray(), Adc = member.Adc.ToArray(), Adh = member.Adh.ToArray(),
        Adp = member.Adp.ToArray(), Dmd = member.Dmd.ToArray(), Drs = member.Drs.ToArray(),
        Devices = member.Devices.Select(static device => new Device(device.Id.ToArray(), device.Reference.ToArray())).ToList(),
    };

    private static void EnforceGroupLimits(List<Member> members)
    {
        if (members.Count is < 1 or > 100 || members.Count(member => member.Role == GroupRole.Owner) != 1 ||
            members.Count(member => member.Role is GroupRole.Owner or GroupRole.Admin) > 5 ||
            members.Any(member => member.Devices.Count is < 1 or > 5) || members.Sum(member => member.Devices.Count) > 500)
            Reject(GroupValidationStage.Transition, "GroupLimitExceeded");
    }

    private static byte[] SerializeMembers(IEnumerable<Member> members) => members
        .OrderBy(static member => member.Account, ByteArrayComparer.Instance)
        .SelectMany(SerializeMember).ToArray();

    private static byte[] SerializeMember(Member member)
    {
        var devices = member.Devices.OrderBy(static device => device.Id, ByteArrayComparer.Instance).ToArray();
        var body = new byte[220 + devices.Length * 70];
        member.Account.CopyTo(body, 0); body[32] = (byte)member.Role; member.Adc.CopyTo(body, 33); member.Adh.CopyTo(body, 71);
        member.Adp.CopyTo(body, 109); BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(141), member.DirectoryGeneration);
        member.Dmd.CopyTo(body, 149); member.Drs.CopyTo(body, 181); body[219] = checked((byte)devices.Length);
        for (var i = 0; i < devices.Length; i++) { devices[i].Id.CopyTo(body, 220 + i * 70); devices[i].Reference.CopyTo(body, 252 + i * 70); }
        var result = new byte[body.Length + 2]; BinaryPrimitives.WriteUInt16BigEndian(result, checked((ushort)body.Length)); body.CopyTo(result, 2);
        return result;
    }

    private static ReadOnlySpan<byte> ExactLp(ReadOnlySpan<byte> value)
    {
        var payload = Lp(value, out var used);
        if (used != value.Length) Reject(GroupValidationStage.Bounds, "TrailingLp32Bytes");
        return payload;
    }

    private static byte[] ReferenceBytes(string magic, ReadOnlySpan<byte> hash)
    {
        var value = new byte[38]; Encoding.ASCII.GetBytes(magic).CopyTo(value, 0); value[5] = 1; hash.CopyTo(value.AsSpan(6)); return value;
    }

    private static void RequireReference(ReadOnlySpan<byte> reference, string magic, ReadOnlySpan<byte> hash)
    {
        if (!reference.SequenceEqual(ReferenceBytes(magic, hash))) Reject(GroupValidationStage.Closure, "VerifiedReferenceMismatch");
    }

    private static void RequireDirectoryEvidence(
        VerifiedAccountDirectory directory,
        ReadOnlySpan<byte> adc1Reference,
        ReadOnlySpan<byte> adh1CoreReference,
        ReadOnlySpan<byte> adp1Hash)
    {
        if (!adc1Reference.SequenceEqual(directory.Freshness.ExactAdc1Reference.Span) ||
            !adh1CoreReference.SequenceEqual(directory.Freshness.ExactAdh1CoreReference.Span) ||
            !adp1Hash.SequenceEqual(directory.Freshness.ExactAdp1Hash.Span))
            Reject(GroupValidationStage.Closure, "AccountDirectoryEvidenceMismatch");
    }

    private sealed class VerifiedAccountDirectory(Deep.Protocol.ContactV1.VerifiedContactBundleClosure closure)
    {
        internal VerifiedDmd1 Directory => closure.Directory;
        internal VerifiedAccountDirectoryFreshness Freshness => closure.Freshness;
    }

    private sealed class IdentityIndex
    {
        private readonly Dictionary<string, VerifiedAccountDirectory> baseAccounts = new(StringComparer.Ordinal);
        private readonly Dictionary<string, VerifiedAccountDirectory> currentAccounts = new(StringComparer.Ordinal);
        private readonly Dictionary<string, Support> supports;

        internal IdentityIndex(
            GroupIdentityClosure closure,
            IReadOnlyList<Support> support,
            ReadOnlySpan<byte> networkId,
            ulong commitTime,
            ulong? baseCommitTime)
        {
            supports = support.ToDictionary(static item => Convert.ToHexString(item.Reference.CanonicalBytes.Span), StringComparer.Ordinal);
            AddVerified(closure.BaseDirectories, baseAccounts, networkId, baseCommitTime,
                closure.CurrentBootId, closure.CurrentMonotonicSample, requireMonotonicCurrent: false);
            AddVerified(closure.CurrentDirectories, currentAccounts, networkId, commitTime,
                closure.CurrentBootId, closure.CurrentMonotonicSample, requireMonotonicCurrent: true);
            VerifyDmdLineages();
        }

        private void AddVerified(
            IReadOnlyList<Deep.Protocol.ContactV1.VerifiedContactBundleClosure> closures,
            Dictionary<string, VerifiedAccountDirectory> destination,
            ReadOnlySpan<byte> networkId,
            ulong? evidenceTime,
            ReadOnlySpan<byte> currentBootId,
            ulong currentMonotonicSample,
            bool requireMonotonicCurrent)
        {
            foreach (var closure in closures)
            {
                var directory = closure.Directory;
                var verifiedAt = evidenceTime.GetValueOrDefault();
                if (!directory.Record.NetworkId.Span.SequenceEqual(networkId))
                    Reject(GroupValidationStage.Closure, "VerifiedIdentityNetworkMismatch");
                if (evidenceTime is null ||
                    verifiedAt < closure.Freshness.TrustedLowerUnixSeconds ||
                    verifiedAt > closure.Freshness.TrustedUpperUnixSeconds ||
                    requireMonotonicCurrent &&
                    !closure.Freshness.IsCurrentAtMonotonic(currentBootId, currentMonotonicSample))
                    Reject(GroupValidationStage.Closure, "DirectoryEvidenceNotCurrentAtCommitTime");
                var key = Convert.ToHexString(directory.Record.DeepAccountId.Span);
                if (!destination.TryAdd(key, new VerifiedAccountDirectory(closure))) Reject(GroupValidationStage.Closure, "DuplicateVerifiedAccount");
                RequireSupported(ProtocolMagic.ADC1, closure.Freshness.ExactAdc1Reference.Span[6..], ResolveExact(closure.Freshness.ExactAdc1Reference.Span));
                RequireSupported(ProtocolMagic.ADH1, closure.Freshness.ExactAdh1CoreReference.Span[6..], ResolveExact(closure.Freshness.ExactAdh1CoreReference.Span));
                RequireSupported(ProtocolMagic.ADP1, closure.Freshness.ExactAdp1Hash.Span, ResolveExact(ReferenceBytes(ProtocolMagic.ADP1, closure.Freshness.ExactAdp1Hash.Span)));
                RequireSupported(ProtocolMagic.DMD1, directory.Record.RecordHash.Span, directory.Record.CanonicalBytes.Span);
                RequireSupported(ProtocolMagic.DRS1, directory.Identity.Revocations.Snapshot.CanonicalHash.Span,
                    directory.Identity.Revocations.Snapshot.CanonicalBytes.Span);
                foreach (var device in directory.Identity.ActiveDevices)
                {
                    if (device.Certificate.IssuedAtUnixSeconds > verifiedAt ||
                        device.Certificate.ExpiresAtUnixSeconds <= verifiedAt)
                        Reject(GroupValidationStage.Closure, "DeviceNotCurrentAtCommitTime");
                    RequireSupported(ProtocolMagic.DPD1, device.Certificate.CanonicalHash.Span, device.Certificate.CanonicalBytes.Span);
                }
            }
        }

        internal VerifiedAccountDirectory RequireBaseAccount(ReadOnlySpan<byte> account) => RequireAccount(baseAccounts, account);
        internal VerifiedAccountDirectory RequireCurrentAccount(ReadOnlySpan<byte> account) => RequireAccount(currentAccounts, account);

        private static VerifiedAccountDirectory RequireAccount(Dictionary<string, VerifiedAccountDirectory> source, ReadOnlySpan<byte> account)
        {
            if (!source.TryGetValue(Convert.ToHexString(account), out var directory))
                Reject(GroupValidationStage.Closure, "MissingVerifiedAccount");
            return directory!;
        }

        internal VerifiedDevice RequireBaseDevice(ReadOnlySpan<byte> account, ReadOnlySpan<byte> deviceId, ReadOnlySpan<byte> reference) =>
            RequireDevice(RequireBaseAccount(account), deviceId, reference);
        internal VerifiedDevice RequireCurrentDevice(ReadOnlySpan<byte> account, ReadOnlySpan<byte> deviceId, ReadOnlySpan<byte> reference) =>
            RequireDevice(RequireCurrentAccount(account), deviceId, reference);

        private static VerifiedDevice RequireDevice(VerifiedAccountDirectory account, ReadOnlySpan<byte> deviceId, ReadOnlySpan<byte> reference)
        {
            var directory = account.Directory;
            VerifiedDevice? device = null;
            foreach (var candidate in directory.Identity.ActiveDevices)
                if (candidate.Certificate.DeviceId.Span.SequenceEqual(deviceId)) { device = candidate; break; }
            if (device is null) Reject(GroupValidationStage.Closure, "MissingVerifiedDevice");
            RequireReference(reference, ProtocolMagic.DPD1, device!.Certificate.CanonicalHash.Span);
            return device;
        }

        private void RequireSupported(string magic, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> canonical)
        {
            var key = Convert.ToHexString(ReferenceBytes(magic, hash));
            if (!supports.TryGetValue(key, out var support) || !support.Bytes.AsSpan().SequenceEqual(canonical))
                Reject(GroupValidationStage.Closure, "VerifiedSupportObjectMissing");
        }

        private ReadOnlySpan<byte> ResolveExact(ReadOnlySpan<byte> reference)
        {
            var key = Convert.ToHexString(reference);
            if (!supports.TryGetValue(key, out var support)) Reject(GroupValidationStage.Closure, "VerifiedSupportObjectMissing");
            return support!.Bytes;
        }

        private void VerifyDmdLineages()
        {
            foreach (var pair in baseAccounts)
            {
                if (!currentAccounts.TryGetValue(pair.Key, out var current)) continue;
                var previous = pair.Value.Directory.Record; var next = current.Directory.Record;
                if (previous.CanonicalBytes.Span.SequenceEqual(next.CanonicalBytes.Span)) continue;
                if (previous.DirectoryGeneration == ulong.MaxValue ||
                    next.DirectoryGeneration != previous.DirectoryGeneration + 1 ||
                    !next.PredecessorDmd1Hash.Span.SequenceEqual(previous.RecordHash.Span))
                    Reject(GroupValidationStage.Closure, "InvalidDmd1Successor");
            }
        }

    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? x, byte[]? y) => (x ?? []).AsSpan().SequenceCompareTo(y ?? []);
    }

    private sealed class ReadOnlyMemoryComparer : IComparer<ReadOnlyMemory<byte>>
    {
        internal static readonly ReadOnlyMemoryComparer Instance = new();
        public int Compare(ReadOnlyMemory<byte> x, ReadOnlyMemory<byte> y) => x.Span.SequenceCompareTo(y.Span);
    }

    private sealed class VerifiedGroupTransitionImpl(
        GroupCommitRecord commit,
        GroupCommitRecord? predecessor,
        ReadOnlySpan<byte> exactCanonicalGcp1Bytes)
        : VerifiedGroupTransition(commit, predecessor, exactCanonicalGcp1Bytes);
}

/// <summary>
/// Atomic persistence seam for the permanent group fork latch.  Implementations
/// must durably compare exact bytes and fsync/commit <paramref name="replacement"/>
/// before returning true.
/// </summary>
public interface IGroupSuccessorStateStore
{
    bool CompareExchange(ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement);
}

/// <summary>Restart-safe permanent fork latch for one verified group lineage.</summary>
public sealed class GroupSuccessorLatch
{
    private const int HeaderBytes = 58;
    private byte[] snapshot;
    private ulong revision;
    private ulong? headEpoch;
    private byte[]? headHash;
    private readonly List<ObservedCommit> observed = [];

    private GroupSuccessorLatch() { snapshot = Encode(false, 0, null, null, observed); }

    public bool ForkLatched { get; private set; }
    public ReadOnlyMemory<byte> Snapshot => snapshot.ToArray();
    public static GroupSuccessorLatch CreateEmpty() => new();

    public static GroupSuccessorLatch Restore(ReadOnlySpan<byte> persisted)
    {
        if (persisted.Length < HeaderBytes || !persisted[..4].SequenceEqual(ProtocolMagicBytes.GLS1) ||
            BinaryPrimitives.ReadUInt16BigEndian(persisted[4..]) != 1 ||
            BinaryPrimitives.ReadUInt16BigEndian(persisted[6..]) > 1)
            throw new GroupFormatException(GroupValidationStage.Transition, "InvalidPersistedGroupLineage");
        var count = BinaryPrimitives.ReadUInt16BigEndian(persisted[56..]);
        if (persisted.Length != HeaderBytes + count * 40)
            throw new GroupFormatException(GroupValidationStage.Transition, "InvalidPersistedGroupLineage");
        var latch = new GroupSuccessorLatch
        {
            snapshot = persisted.ToArray(),
            ForkLatched = BinaryPrimitives.ReadUInt16BigEndian(persisted[6..]) == 1,
            revision = BinaryPrimitives.ReadUInt64BigEndian(persisted[8..]),
        };
        // Every durable state change appends exactly one previously unseen commit.
        // Binding the CAS revision to that cardinality prevents rollback/tampering
        // from manufacturing a canonical-looking snapshot after restart.
        if (latch.revision != count)
            throw new GroupFormatException(GroupValidationStage.Transition, "InvalidPersistedGroupLineage");
        var encodedHeadEpoch = BinaryPrimitives.ReadUInt64BigEndian(persisted[16..]);
        var encodedHeadHash = persisted.Slice(24, 32);
        if (count == 0)
        {
            if (encodedHeadEpoch != ulong.MaxValue || encodedHeadHash.IndexOfAnyExcept((byte)0) >= 0 || latch.revision != 0 || latch.ForkLatched)
                throw new GroupFormatException(GroupValidationStage.Transition, "InvalidPersistedGroupLineage");
        }
        else
        {
            latch.headEpoch = encodedHeadEpoch;
            latch.headHash = encodedHeadHash.ToArray();
        }
        var at = HeaderBytes;
        ObservedCommit? priorEntry = null;
        for (var index = 0; index < count; index++, at += 40)
        {
            var epoch = BinaryPrimitives.ReadUInt64BigEndian(persisted[at..]);
            var hash = persisted.Slice(at + 8, 32).ToArray();
            var entry = new ObservedCommit(epoch, hash);
            if (hash.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                priorEntry is not null && Compare(priorEntry, entry) >= 0)
                throw new GroupFormatException(GroupValidationStage.Transition, "InvalidPersistedGroupLineage");
            latch.observed.Add(entry); priorEntry = entry;
        }
        if (latch.headEpoch is { } head &&
            !latch.observed.Any(entry => entry.Epoch == head && entry.Hash.AsSpan().SequenceEqual(latch.headHash)))
            throw new GroupFormatException(GroupValidationStage.Transition, "InvalidPersistedGroupLineage");
        if (!Encode(latch.ForkLatched, latch.revision, latch.headEpoch, latch.headHash, latch.observed).AsSpan().SequenceEqual(persisted))
            throw new GroupFormatException(GroupValidationStage.Transition, "NonCanonicalPersistedGroupLineage");
        return latch;
    }

    public GroupLineageDisposition ObserveAndPersist(VerifiedGroupTransition transition, IGroupSuccessorStateStore store)
    {
        ArgumentNullException.ThrowIfNull(transition); ArgumentNullException.ThrowIfNull(store);
        if (ForkLatched) return GroupLineageDisposition.ForkLatched;
        var commit = transition.Commit;
        var epoch = BinaryPrimitives.ReadUInt64BigEndian(commit.Field(4).Span);
        var hash = commit.ArtifactHash.ToArray();
        var nextObserved = observed.Select(static entry => new ObservedCommit(entry.Epoch, entry.Hash.ToArray())).ToList();
        var nextFork = false; ulong? nextHeadEpoch = headEpoch; byte[]? nextHeadHash = headHash?.ToArray();
        GroupLineageDisposition disposition;
        var sameEpoch = nextObserved.Where(entry => entry.Epoch == epoch).ToArray();
        if (sameEpoch.Any(entry => entry.Hash.AsSpan().SequenceEqual(hash)))
            return GroupLineageDisposition.ExactReplay;
        if (sameEpoch.Length != 0)
        {
            nextObserved.Add(new ObservedCommit(epoch, hash));
            nextFork = true; disposition = GroupLineageDisposition.ForkLatched;
        }
        else if (headEpoch is null)
        {
            if (epoch != 0) throw new GroupFormatException(GroupValidationStage.Transition, "LineageMustStartAtGenesis");
            nextObserved.Add(new ObservedCommit(epoch, hash)); nextHeadEpoch = epoch; nextHeadHash = hash;
            disposition = GroupLineageDisposition.AcceptedGenesis;
        }
        else
        {
            if (headEpoch == ulong.MaxValue || epoch != headEpoch + 1 || !commit.Field(5).Span.SequenceEqual(headHash))
                throw new GroupFormatException(GroupValidationStage.Transition, "NonSuccessorCommit");
            nextObserved.Add(new ObservedCommit(epoch, hash)); nextHeadEpoch = epoch; nextHeadHash = hash;
            disposition = GroupLineageDisposition.AcceptedSuccessor;
        }
        if (revision == ulong.MaxValue) throw new GroupFormatException(GroupValidationStage.Transition, "LineageRevisionExhausted");
        var replacement = Encode(nextFork, revision + 1, nextHeadEpoch, nextHeadHash, nextObserved);
        if (!store.CompareExchange(snapshot, replacement))
            throw new GroupFormatException(GroupValidationStage.Transition, "LineagePersistenceConflict");
        snapshot = replacement; revision++;
        ForkLatched = nextFork; headEpoch = nextHeadEpoch; headHash = nextHeadHash;
        observed.Clear(); observed.AddRange(nextObserved.OrderBy(static entry => entry.Epoch).ThenBy(static entry => entry.Hash, HashComparer.Instance));
        return disposition;
    }

    private static byte[] Encode(bool fork, ulong revision, ulong? headEpoch, byte[]? headHash, IEnumerable<ObservedCommit> entries)
    {
        var ordered = entries.OrderBy(static entry => entry.Epoch).ThenBy(static entry => entry.Hash, HashComparer.Instance).ToArray();
        var bytes = new byte[checked(HeaderBytes + ordered.Length * 40)];
        ProtocolMagicBytes.GLS1.CopyTo(bytes); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), fork ? (ushort)1 : (ushort)0);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(8), revision);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(16), headEpoch ?? ulong.MaxValue);
        headHash?.CopyTo(bytes, 24); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(56), checked((ushort)ordered.Length));
        var at = HeaderBytes; foreach (var entry in ordered) { BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(at), entry.Epoch); entry.Hash.CopyTo(bytes, at + 8); at += 40; }
        return bytes;
    }

    private static int Compare(ObservedCommit left, ObservedCommit right)
    {
        var epoch = left.Epoch.CompareTo(right.Epoch);
        return epoch != 0 ? epoch : left.Hash.AsSpan().SequenceCompareTo(right.Hash);
    }

    private sealed record ObservedCommit(ulong Epoch, byte[] Hash);
    private sealed class HashComparer : IComparer<byte[]>
    {
        internal static readonly HashComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => (left ?? []).AsSpan().SequenceCompareTo(right ?? []);
    }
}
