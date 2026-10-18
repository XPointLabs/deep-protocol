using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.GroupV1;

public static partial class GroupCodec
{
    internal static VerifiedGroupTransition VerifyCurrentGenesis(GroupCommitPackageRecord package,
        VerifiedDeepIdV2GroupDirectory owner, OnionMonotonicReading reading)
    {
        owner.RequireCurrent(reading);
        var parsed = ReadCurrentPackage(package);
        var commit = parsed.Commit;
        if (U64(commit.FieldSpan(4)) != 0 || parsed.Proposals.Count != 0 || parsed.Pairs.Count != 0 ||
            U16(commit.FieldSpan(11)) != 1)
            Reject(GroupValidationStage.Transition, "InvalidCurrentGroupGenesis");
        VerifyCurrentMembers(commit, [owner]);
        VerifyCurrentDeviceSignature(commit, 6, 7, 8, 17, owner);
        RequireCommitTime(commit, owner, reading);
        return new VerifiedGroupTransitionImpl(commit, null, package.CanonicalBytes.Span);
    }

    internal static VerifiedGroupTransition VerifyCurrentActivation(VerifiedGroupTransition previous,
        GroupCommitPackageRecord package, IReadOnlyList<VerifiedDeepIdV2GroupDirectory> authorities, OnionMonotonicReading reading)
    {
        ArgumentNullException.ThrowIfNull(previous); ArgumentNullException.ThrowIfNull(package);
        var parsed = ReadCurrentPackage(package); var commit = parsed.Commit; var prior = previous.Commit;
        if (!commit.FieldSpan(1).SequenceEqual(prior.FieldSpan(1)) || !commit.FieldSpan(2).SequenceEqual(prior.FieldSpan(2)) ||
            U64(prior.FieldSpan(4)) == ulong.MaxValue || U64(commit.FieldSpan(4)) != U64(prior.FieldSpan(4)) + 1 ||
            !commit.FieldSpan(5).SequenceEqual(prior.ArtifactHash.Span) || parsed.Proposals.Count != 1 || parsed.Pairs.Count != 1)
            Reject(GroupValidationStage.Transition, "InvalidCurrentGroupSuccessor");
        var owner = FindAuthority(authorities, prior.FieldSpan(6));
        RequireCurrentSequencer(prior, owner, commit.FieldSpan(7));
        if (!commit.FieldSpan(6).SequenceEqual(prior.FieldSpan(6)) ||
            !commit.FieldSpan(8).SequenceEqual(prior.FieldSpan(8)))
            Reject(GroupValidationStage.Transition, "GroupSequencerChanged");
        var pair = parsed.Pairs.Single();
        var invitation = (GroupInvitationRecord)pair.Invitation;
        var acceptance = (GroupInvitationAcceptanceRecord)pair.Acceptance;
        var invitee = FindAuthority(authorities, invitation.FieldSpan(9));
        RequireCurrentConsent(prior, invitation, acceptance, owner, invitee, reading);
        var proposal = parsed.Proposals.Single();
        if (U16(proposal.FieldSpan(9)) != (ushort)GroupProposalAction.ActivateAcceptedInvite ||
            !proposal.FieldSpan(2).SequenceEqual(prior.FieldSpan(2)) ||
            !proposal.FieldSpan(3).SequenceEqual(prior.FieldSpan(4)) ||
            !proposal.FieldSpan(4).SequenceEqual(prior.ArtifactHash.Span))
            Reject(GroupValidationStage.Transition, "GroupActivationProposalMismatch");
        VerifyCurrentDeviceSignature(proposal, 6, 7, 8, 13, owner);
        if (!proposal.FieldSpan(7).SequenceEqual(prior.FieldSpan(7)))
            Reject(GroupValidationStage.Transition, "GroupActivationProposerMismatch");
        RequireWindowAt(proposal, 11, 12, owner, reading);
        if (U64(proposal.FieldSpan(11)) < U64(acceptance.FieldSpan(13)) ||
            U64(commit.FieldSpan(16)) < U64(proposal.FieldSpan(11)))
            Reject(GroupValidationStage.Transition, "GroupConsentTimeOrderMismatch");
        var expectedPayload = new[] { pair.InvitationReference.CanonicalBytes.ToArray(), pair.AcceptanceReference.CanonicalBytes.ToArray(),
            invitation.Field(9).ToArray(), invitation.Field(10).ToArray(), invitation.Field(11).ToArray(), invitation.Field(12).ToArray(),
            invitation.Field(13).ToArray(), invitation.Field(14).ToArray(), invitation.Field(15).ToArray() }.SelectMany(static value => value).ToArray();
        if (!proposal.FieldSpan(10).SequenceEqual(expectedPayload))
            Reject(GroupValidationStage.Transition, "GroupActivationProposalMismatch");
        var members = ReadMembers(prior.FieldSpan(12));
        if (FindMember(members, invitee.AccountId.Span, false) is not null)
            Reject(GroupValidationStage.Transition, "GroupInviteeAlreadyMember");
        var added = invitee.Member((GroupRole)invitation.FieldSpan(10)[0]) with
            { Adh = invitation.Field(12).ToArray(), Adp = invitation.Field(13).ToArray() };
        members.Add(added); EnforceGroupLimits(members);
        if (!commit.FieldSpan(12).SequenceEqual(SerializeMembers(members)) ||
            new[] { 3, 13, 14, 15 }.Any(tag => !commit.FieldSpan(tag).SequenceEqual(prior.FieldSpan(tag))))
            Reject(GroupValidationStage.Transition, "GroupActivationReducerMismatch");
        VerifyCurrentMembers(commit, authorities);
        VerifyCurrentDeviceSignature(commit, 6, 7, 8, 17, owner);
        RequireCommitTime(commit, owner, reading);
        if (U64(commit.FieldSpan(16)) < U64(prior.FieldSpan(16)))
            Reject(GroupValidationStage.Transition, "GroupCommitTimeRollback");
        return new VerifiedGroupTransitionImpl(commit, prior, package.CanonicalBytes.Span);
    }

    internal static void RequireCurrentSequencer(GroupCommitRecord head, VerifiedDeepIdV2GroupDirectory owner, ReadOnlySpan<byte> device)
    {
        if (!head.FieldSpan(1).SequenceEqual(owner.NetworkId.Span) || !head.FieldSpan(6).SequenceEqual(owner.AccountId.Span) ||
            !head.FieldSpan(7).SequenceEqual(device))
            Reject(GroupValidationStage.Transition, "GroupCurrentSequencerMismatch");
        var member = ReadMembers(head.FieldSpan(12)).Single(candidate => candidate.Role == GroupRole.Owner);
        RequireCurrentMember(member, owner);
        RequireReference(head.FieldSpan(8), ProtocolMagic.DPD1, owner.RequireDevice(device).Certificate.CanonicalHash.Span);
    }

    internal static void RequireCurrentInvitation(GroupCommitRecord head, GroupInvitationRecord invitation,
        VerifiedDeepIdV2GroupDirectory inviter, VerifiedDeepIdV2GroupDirectory invitee, OnionMonotonicReading reading)
    {
        inviter.RequireCurrent(reading); invitee.RequireCurrent(reading);
        if (!invitation.FieldSpan(2).SequenceEqual(head.FieldSpan(2)) ||
            !invitation.FieldSpan(4).SequenceEqual(head.FieldSpan(4)) ||
            !invitation.FieldSpan(5).SequenceEqual(head.ArtifactHash.Span) ||
            !invitation.FieldSpan(9).SequenceEqual(invitee.AccountId.Span) ||
            !inviter.NetworkId.Span.SequenceEqual(invitee.NetworkId.Span) ||
            inviter.AccountId.Span.SequenceEqual(invitee.AccountId.Span))
            Reject(GroupValidationStage.Closure, "GroupInvitationBaseMismatch");
        var members = ReadMembers(head.FieldSpan(12));
        var member = FindMember(members, inviter.AccountId.Span, true)!;
        RequireCurrentMember(member, inviter);
        if (member.Role is not (GroupRole.Owner or GroupRole.Admin) || FindMember(members, invitee.AccountId.Span, false) is not null)
            Reject(GroupValidationStage.Transition, "GroupInvitationUnauthorized");
        invitee.RequireStableTuple(invitation.FieldSpan(11), invitation.FieldSpan(14), invitation.FieldSpan(15));
        VerifyCurrentDeviceSignature(invitation, 6, 7, 8, 18, inviter);
        RequireWindowAt(invitation, 16, 17, inviter, reading);
    }

    internal static void RequireCurrentConsent(GroupCommitRecord head, GroupInvitationRecord invitation,
        GroupInvitationAcceptanceRecord acceptance, VerifiedDeepIdV2GroupDirectory inviter,
        VerifiedDeepIdV2GroupDirectory invitee, OnionMonotonicReading reading)
    {
        RequireCurrentInvitation(head, invitation, inviter, invitee, reading);
        if (!acceptance.FieldSpan(1).SequenceEqual(invitation.FieldSpan(1)) ||
            !acceptance.FieldSpan(4).SequenceEqual(ArtifactReference(ProtocolMagic.GIV1, invitation).CanonicalBytes.Span))
            Reject(GroupValidationStage.Closure, "InvitationAcceptanceMismatch");
        VerifyInvitePairs([new InvitationPair(ArtifactReference(ProtocolMagic.GIV1, invitation),
            ArtifactReference(ProtocolMagic.GIA1, acceptance), invitation, acceptance)]);
        if (U64(acceptance.FieldSpan(14)) > U64(invitation.FieldSpan(17)) ||
            U64(acceptance.FieldSpan(13)) < U64(invitation.FieldSpan(16)))
            Reject(GroupValidationStage.Closure, "InvitationAcceptanceMismatch");
        invitee.RequireStableTuple(acceptance.FieldSpan(8), acceptance.FieldSpan(11), acceptance.FieldSpan(12));
        VerifyCurrentDeviceSignature(acceptance, 5, 6, 7, 15, invitee);
        RequireWindowAt(acceptance, 13, 14, invitee, reading);
    }

    private static void VerifyCurrentMembers(GroupCommitRecord commit, IReadOnlyList<VerifiedDeepIdV2GroupDirectory> authorities)
    {
        var members = ReadMembers(commit.FieldSpan(12));
        if (authorities.Count != members.Count) Reject(GroupValidationStage.Closure, "GroupCurrentAuthoritySetMismatch");
        foreach (var member in members) RequireCurrentMember(member, FindAuthority(authorities, member.Account));
    }

    private static void RequireCurrentMember(Member member, VerifiedDeepIdV2GroupDirectory authority)
    {
        authority.RequireStableTuple(member.Adc, member.Dmd, member.Drs);
        var expected = authority.Member(member.Role);
        if (member.DirectoryGeneration != expected.DirectoryGeneration || member.Devices.Count != expected.Devices.Count ||
            member.Devices.Any(device => !expected.Devices.Any(other => device.Id.AsSpan().SequenceEqual(other.Id) &&
                device.Reference.AsSpan().SequenceEqual(other.Reference))))
            Reject(GroupValidationStage.Closure, "GroupCurrentDeviceSetMismatch");
    }

    private static VerifiedDeepIdV2GroupDirectory FindAuthority(IReadOnlyList<VerifiedDeepIdV2GroupDirectory> authorities, ReadOnlySpan<byte> account)
    {
        foreach (var authority in authorities) if (authority.AccountId.Span.SequenceEqual(account)) return authority;
        throw new GroupFormatException(GroupValidationStage.Closure, "GroupCurrentAuthorityMissing");
    }

    private static void RequireWindowAt(GroupRecord record, int issuedTag, int expiryTag,
        VerifiedDeepIdV2GroupDirectory authority, OnionMonotonicReading reading)
    {
        var upper = checked(authority.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - authority.Proof.MonotonicSample);
        if (U64(record.FieldSpan(issuedTag)) > upper || U64(record.FieldSpan(expiryTag)) <= upper)
            Reject(GroupValidationStage.Transition, "GroupRecordNotCurrent");
    }

    private static void RequireCommitTime(GroupCommitRecord commit, VerifiedDeepIdV2GroupDirectory authority, OnionMonotonicReading reading)
    {
        var upper = checked(authority.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - authority.Proof.MonotonicSample);
        if (U64(commit.FieldSpan(16)) > upper)
            Reject(GroupValidationStage.Transition, "GroupCommitFromFuture");
    }

    private sealed record CurrentPackage(GroupCommitRecord Commit, List<GroupRecord> Proposals, List<InvitationPair> Pairs);
    private static CurrentPackage ReadCurrentPackage(GroupCommitPackageRecord package)
    {
        ArgumentNullException.ThrowIfNull(package);
        var commit = (GroupCommitRecord)Decode(ProtocolMagic.DGC1, ExactLp(package.FieldSpan(4)));
        if (!package.FieldSpan(1).SequenceEqual(commit.FieldSpan(1)) || !package.FieldSpan(2).SequenceEqual(commit.FieldSpan(2)) ||
            !package.FieldSpan(3).SequenceEqual(commit.FieldSpan(4)) || !package.FieldSpan(11).IsEmpty)
            Reject(GroupValidationStage.Closure, "GroupPackageCommitMismatch");
        var proposals = ReadLpList(package.FieldSpan(6), U16(package.FieldSpan(5)), 421, 8612, ProtocolMagic.DGP1);
        EnsureStrictHashes(proposals);
        if (U16(commit.FieldSpan(9)) != proposals.Count ||
            !commit.FieldSpan(10).SequenceEqual(proposals.SelectMany(static proposal => proposal.ArtifactHash.ToArray()).ToArray()))
            Reject(GroupValidationStage.Closure, "GroupPackageProposalMismatch");
        var pairs = ReadInvitationPairs(package.FieldSpan(10), U16(package.FieldSpan(9)));
        VerifyInvitePairs(pairs);
        var supports = ReadSupport(package.FieldSpan(8), U32(package.FieldSpan(7)));
        var required = RequiredReferences(commit, proposals, pairs);
        if (!required.SetEquals(supports.Select(static support => Convert.ToHexString(support.Reference.CanonicalBytes.Span))))
            Reject(GroupValidationStage.Closure, "GroupPackageSupportSetMismatch");
        var resolver = new AuthorResolver(supports.ToDictionary(static support => Convert.ToHexString(support.Reference.CanonicalBytes.Span),
            static support => support.Bytes, StringComparer.Ordinal));
        VerifySupport(supports, resolver);
        // Historical nonce evidence is provenance only, but must still describe
        // the exact stable state named by its member row, never another lookup.
        foreach (var member in ReadMembers(commit.FieldSpan(12)))
        {
            var reference = ReferenceBytes(ProtocolMagic.ADP1, member.Adp);
            var support = supports.Single(item => item.Reference.CanonicalBytes.Span.SequenceEqual(reference));
            var adp = Deep.Protocol.AccountDirectoryV1.DeepIdV2Adp1Codec.Decode(support.Bytes);
            var adc = Deep.Protocol.AccountDirectoryV1.DeepIdV2AccountDirectoryCodec.Decode(adp.ExactCurrentAdc1V2.Span);
            if (!adc.ArtifactReference.Span.SequenceEqual(member.Adc) ||
                !adc.ExactDmd1Hash.Span.SequenceEqual(member.Dmd) || !adc.ExactDrs1Reference.Span.SequenceEqual(member.Drs) ||
                !ReferenceBytes(ProtocolMagic.ADH1, Deep.Protocol.AccountDirectoryV1.AccountDirectoryCrypto.ComputeAdh1CoreHash(adp.Head))
                    .AsSpan().SequenceEqual(member.Adh))
                Reject(GroupValidationStage.Closure, "GroupMemberProvenanceMismatch");
        }
        return new(commit, proposals, pairs);
    }

    internal static IReadOnlyList<AuthorSupport> MergeCurrentSupports(GroupCommitPackageRecord previous, IReadOnlyList<AuthorSupport> fresh,
        GroupCommitRecord commit, IReadOnlyList<GroupProposalRecord> proposals,
        IReadOnlyList<(GroupInvitationRecord Invitation, GroupInvitationAcceptanceRecord Acceptance)> pairs)
    {
        var all = ReadSupport(previous.FieldSpan(8), U32(previous.FieldSpan(7))).Select(static support =>
            new AuthorSupport(support.Kind, support.Reference.CanonicalBytes.ToArray(), support.Bytes)).Concat(fresh);
        var values = new Dictionary<string, AuthorSupport>(StringComparer.Ordinal);
        foreach (var support in all)
        {
            var key = Convert.ToHexString(support.Reference);
            if (values.TryGetValue(key, out var retained) && !retained.Bytes.AsSpan().SequenceEqual(support.Bytes))
                Reject(GroupValidationStage.Closure, "GroupSupportHashCollision");
            values[key] = support;
        }
        var pairRecords = pairs.Select(static pair => new InvitationPair(ArtifactReference(ProtocolMagic.GIV1, pair.Invitation),
            ArtifactReference(ProtocolMagic.GIA1, pair.Acceptance), pair.Invitation, pair.Acceptance)).ToList();
        var required = RequiredReferences(commit, proposals.Cast<GroupRecord>().ToList(), pairRecords);
        if (required.Any(key => !values.ContainsKey(key))) Reject(GroupValidationStage.Closure, "GroupSupportMissing");
        return required.Select(key => values[key]).ToArray();
    }
}
