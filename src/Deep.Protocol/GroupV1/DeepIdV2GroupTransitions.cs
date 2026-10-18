using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;

namespace Deep.Protocol.GroupV1;

/// <summary>Current DID2 owner/consent reducer. This does not activate DMC2 emission.</summary>
public static class DeepIdV2GroupTransitions
{
    public static async ValueTask<VerifiedAuthoredGroupTransition> CreateGenesisAsync(
        VerifiedDeepIdV2GroupDirectory owner, OwnedGenesisDeviceSecrets device, string name,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device); ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var encodedName = new UTF8Encoding(false, true).GetBytes(name);
        if (!name.IsNormalized(NormalizationForm.FormC) || encodedName.Length is < 1 or > 128 || name.Contains('\0'))
            throw new ArgumentException("Group name must be canonical and bounded.", nameof(name));
        return await CurrentAsync([owner], trustedTime, reading =>
        {
            var member = owner.Member(GroupRole.Owner);
            var commit = (GroupCommitRecord)Signed(ProtocolMagic.DGC1,
                [owner.NetworkId, RandomNumberGenerator.GetBytes(32), U16(1), U64(0), new byte[32], owner.AccountId,
                 device.DeviceId.Bytes, DeviceReference(owner, device), U16(0), Array.Empty<byte>(), U16(1),
                 GroupCodec.SerializeMembersForAuthoring([member]), encodedName, new byte[] { 0 }, U32(604800),
                 U64(Now(owner, reading)), Placeholder()], 17, owner, device);
            var package = GroupCodec.PackageForAuthoring(commit, [], Supports(owner), []);
            return new VerifiedAuthoredGroupTransition(package, GroupCodec.VerifyCurrentGenesis(package, owner, reading));
        }, cancellationToken).ConfigureAwait(false);
    }

    public static ValueTask<VerifiedGroupTransition> VerifyGenesisAsync(GroupCommitPackageRecord package,
        VerifiedDeepIdV2GroupDirectory owner, OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default) =>
        CurrentAsync([owner], trustedTime, reading => GroupCodec.VerifyCurrentGenesis(package, owner, reading), cancellationToken);

    public static ValueTask<GroupInvitationRecord> InviteAsync(VerifiedGroupTransition head,
        VerifiedDeepIdV2GroupDirectory owner, OwnedGenesisDeviceSecrets device,
        VerifiedDeepIdV2GroupDirectory invitee, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default) => CurrentAsync([owner, invitee], trustedTime, reading =>
    {
        RequireDistinct(owner, invitee); GroupCodec.RequireCurrentSequencer(head.Commit, owner, device.DeviceId.Bytes.Span);
        if (GroupCodec.ReadMembersForAuthoring(head.Commit).Any(member => member.Account.AsSpan().SequenceEqual(invitee.AccountId.Span)))
            throw new InvalidOperationException("The invitee is already a group member.");
        var member = invitee.Member(GroupRole.Member); var now = Now(owner, reading);
        return (GroupInvitationRecord)Signed(ProtocolMagic.GIV1,
            [owner.NetworkId, head.Commit.Field(2), RandomNumberGenerator.GetBytes(32), head.Commit.Field(4),
             head.Commit.ArtifactHash, owner.AccountId, device.DeviceId.Bytes, DeviceReference(owner, device),
             invitee.AccountId, new byte[] { 3 }, member.Adc, member.Adh, member.Adp, member.Dmd, member.Drs,
             U64(now), U64(checked(now + 604800)), Placeholder()], 18, owner, device);
    }, cancellationToken);

    public static ValueTask<GroupInvitationAcceptanceRecord> AcceptAsync(VerifiedGroupTransition head,
        GroupInvitationRecord invitation, VerifiedDeepIdV2GroupDirectory inviter,
        VerifiedDeepIdV2GroupDirectory invitee, OwnedGenesisDeviceSecrets acceptingDevice,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default) =>
        CurrentAsync([inviter, invitee], trustedTime, reading =>
    {
        GroupCodec.RequireCurrentInvitation(head.Commit, invitation, inviter, invitee, reading);
        var now = Math.Max(Now(invitee, reading), BinaryPrimitives.ReadUInt64BigEndian(invitation.Field(16).Span));
        var upper = checked(invitee.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - invitee.Proof.MonotonicSample);
        if (now > upper) throw new CryptographicException("Invitation issue time exceeds the accepting device's trusted interval.");
        return (GroupInvitationAcceptanceRecord)Signed(ProtocolMagic.GIA1,
            [invitee.NetworkId, invitation.Field(2), invitation.Field(3), GroupCodec.ArtifactReference(ProtocolMagic.GIV1, invitation).CanonicalBytes,
             invitee.AccountId, acceptingDevice.DeviceId.Bytes, DeviceReference(invitee, acceptingDevice),
             invitation.Field(11), invitation.Field(12), invitation.Field(13), invitation.Field(14), invitation.Field(15),
             U64(now), invitation.Field(17), Placeholder()], 15, invitee, acceptingDevice);
    }, cancellationToken);

    public static ValueTask<VerifiedAuthoredGroupTransition> ActivateAsync(VerifiedGroupTransition head,
        GroupCommitPackageRecord exactBasePackage, GroupInvitationRecord invitation,
        GroupInvitationAcceptanceRecord acceptance, VerifiedDeepIdV2GroupDirectory owner,
        OwnedGenesisDeviceSecrets sequencer, VerifiedDeepIdV2GroupDirectory invitee,
        ReadOnlyMemory<byte> exactInvitationLookupProof,
        IReadOnlyList<VerifiedDeepIdV2GroupDirectory> currentAccounts,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        var captured = CaptureAccounts(currentAccounts);
        if (!captured.Contains(owner) || !captured.Contains(invitee))
            throw new ArgumentException("Activation requires its exact owner and invitee current authorities.", nameof(currentAccounts));
        return CurrentAsync(captured, trustedTime, reading =>
    {
        if (!head.BindsExactGcp1(exactBasePackage.CanonicalBytes.Span))
            throw new CryptographicException("Activation base package differs from its verified transition.");
        GroupCodec.RequireCurrentSequencer(head.Commit, owner, sequencer.DeviceId.Bytes.Span);
        GroupCodec.RequireCurrentConsent(head.Commit, invitation, acceptance, owner, invitee, reading);
        var now = Math.Max(Now(owner, reading), BinaryPrimitives.ReadUInt64BigEndian(acceptance.Field(13).Span));
        var payload = Join(GroupCodec.ArtifactReference(ProtocolMagic.GIV1, invitation).CanonicalBytes.ToArray(),
            GroupCodec.ArtifactReference(ProtocolMagic.GIA1, acceptance).CanonicalBytes.ToArray(), invitee.AccountId.ToArray(),
            invitation.Field(10).ToArray(), invitation.Field(11).ToArray(), invitation.Field(12).ToArray(),
            invitation.Field(13).ToArray(), invitation.Field(14).ToArray(), invitation.Field(15).ToArray());
        var proposal = (GroupProposalRecord)Signed(ProtocolMagic.DGP1,
            [owner.NetworkId, head.Commit.Field(2), head.Commit.Field(4), head.Commit.ArtifactHash,
             RandomNumberGenerator.GetBytes(32), owner.AccountId, sequencer.DeviceId.Bytes, DeviceReference(owner, sequencer),
             U16(1), payload, U64(now), invitation.Field(17), Placeholder()], 13, owner, sequencer);
        var members = GroupCodec.ReadMembersForAuthoring(head.Commit);
        // Consent provenance is echoed, current stable facts are selected independently.
        var member = invitee.Member((GroupRole)invitation.Field(10).Span[0]) with
            { Adh = invitation.Field(12).ToArray(), Adp = invitation.Field(13).ToArray() };
        members.Add(member); GroupCodec.EnforceLimitsForAuthoring(members);
        var epoch = BinaryPrimitives.ReadUInt64BigEndian(head.Commit.Field(4).Span);
        var commit = (GroupCommitRecord)Signed(ProtocolMagic.DGC1,
            [owner.NetworkId, head.Commit.Field(2), head.Commit.Field(3), U64(checked(epoch + 1)), head.Commit.ArtifactHash,
             owner.AccountId, sequencer.DeviceId.Bytes, DeviceReference(owner, sequencer), U16(1), proposal.ArtifactHash,
             U16(checked((ushort)members.Count)), GroupCodec.SerializeMembersForAuthoring(members), head.Commit.Field(13),
             head.Commit.Field(14), head.Commit.Field(15), U64(now), Placeholder()], 17, owner, sequencer);
        var original = DeepIdV2Adp1Codec.Decode(exactInvitationLookupProof.Span);
        if (!original.ExactCurrentAdc1V2.Span.SequenceEqual(invitee.Checkpoint.Checkpoint.CanonicalBytes.Span) ||
            !GroupCodec.CurrentAdpHash(original.CanonicalBytes.Span).AsSpan().SequenceEqual(invitation.Field(13).Span) ||
            !GroupCodec.ReferenceForAuthoring(ProtocolMagic.ADH1, AccountDirectoryCrypto.ComputeAdh1CoreHash(original.Head))
                .AsSpan().SequenceEqual(invitation.Field(12).Span))
            throw new CryptographicException("Retained invitation provenance differs from exact signed/current stable state.");
        GroupCodec.AuthorSupport[] provenance =
        [new(2, invitation.Field(12).ToArray(), AccountDirectoryAdh1Codec.Encode(original.Head)),
         new(3, GroupCodec.ReferenceForAuthoring(ProtocolMagic.ADP1, invitation.Field(13).Span), original.CanonicalBytes.ToArray())];
        var supports = GroupCodec.MergeCurrentSupports(exactBasePackage, Supports(owner).Concat(Supports(invitee)).Concat(provenance).ToArray(),
            commit, [proposal], [(invitation, acceptance)]);
        var package = GroupCodec.PackageForAuthoring(commit, [proposal], supports, [(invitation, acceptance)]);
        var transition = GroupCodec.VerifyCurrentActivation(head, package, captured, reading);
        return new VerifiedAuthoredGroupTransition(package, transition);
    }, cancellationToken);
    }

    public static ValueTask<VerifiedGroupTransition> VerifyActivationAsync(VerifiedGroupTransition head,
        GroupCommitPackageRecord package, IReadOnlyList<VerifiedDeepIdV2GroupDirectory> accounts,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        var captured = CaptureAccounts(accounts);
        return CurrentAsync(captured, trustedTime, reading => GroupCodec.VerifyCurrentActivation(head, package, captured, reading), cancellationToken);
    }

    private static VerifiedDeepIdV2GroupDirectory[] CaptureAccounts(IReadOnlyList<VerifiedDeepIdV2GroupDirectory> accounts)
    {
        ArgumentNullException.ThrowIfNull(accounts); var count = accounts.Count;
        if (count is < 1 or > 100) throw new ArgumentException("Group account set exceeds its closed bound.", nameof(accounts));
        var result = new VerifiedDeepIdV2GroupDirectory[count];
        for (var index = 0; index < count; index++) result[index] = accounts[index];
        if (accounts.Count != count) throw new ArgumentException("Group account set changed during capture.", nameof(accounts));
        return result;
    }

    private static async ValueTask<T> CurrentAsync<T>(VerifiedDeepIdV2GroupDirectory[] accounts,
        OnionTrustedTimeAuthority trustedTime, Func<OnionMonotonicReading, T> action, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(trustedTime); ct.ThrowIfCancellationRequested();
        if (accounts.Length is < 1 or > 100 || accounts.Any(static account => account is null))
            throw new ArgumentException("Group current account set is invalid.", nameof(accounts));
        if (accounts.Select(account => Convert.ToHexString(account.AccountId.Span)).Distinct(StringComparer.Ordinal).Count() != accounts.Length ||
            accounts.Any(account => !account.NetworkId.Span.SequenceEqual(accounts[0].NetworkId.Span)))
            throw new CryptographicException("Group authorities must be unique accounts on one network.");
        if (accounts.GroupBy(account => account.Proof.NextProtectedLkg.LogGeneration).Any(group =>
            group.Select(account => Convert.ToHexString(account.Proof.NextProtectedLkg.CoreHash.Span)).Distinct(StringComparer.Ordinal).Count() != 1))
            throw new CryptographicException("Group authorities contain conflicting heads at one directory generation.");
        var first = await trustedTime.ReadCurrentAsync(ct).ConfigureAwait(false);
        foreach (var account in accounts) account.RequireCurrent(first);
        var result = action(first);
        var final = await trustedTime.ReadCurrentAsync(ct).ConfigureAwait(false); ct.ThrowIfCancellationRequested();
        ContactControlEndpointV2.RequireContinuous(first, final);
        foreach (var account in accounts) account.RequireCurrent(final);
        return result;
    }

    private static GroupRecord Signed(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields, int tag,
        VerifiedDeepIdV2GroupDirectory authority, OwnedGenesisDeviceSecrets device)
    {
        var record = GroupCodec.CreateForAuthoring(magic, fields);
        var signature = device.SignCurrentGroupRecord(record, authority);
        try { var signed = fields.ToArray(); signed[tag - 1] = signature; return GroupCodec.CreateForAuthoring(magic, signed); }
        finally { CryptographicOperations.ZeroMemory(signature); }
    }

    private static IReadOnlyList<GroupCodec.AuthorSupport> Supports(VerifiedDeepIdV2GroupDirectory authority)
    {
        var member = authority.Member(GroupRole.Member); var identity = authority.Checkpoint.Directory.Identity;
        var values = new List<GroupCodec.AuthorSupport>
        {
            new(1, member.Adc, authority.Checkpoint.Checkpoint.CanonicalBytes.ToArray()),
            new(2, member.Adh, authority.Proof.ExactAdh1.ToArray()),
            new(3, GroupCodec.ReferenceForAuthoring(ProtocolMagic.ADP1, member.Adp), authority.Proof.ExactAdp1V2.ToArray()),
            new(4, GroupCodec.ReferenceForAuthoring(ProtocolMagic.DMD1, member.Dmd), authority.Checkpoint.Directory.Record.CanonicalBytes.ToArray()),
            new(5, member.Drs, identity.Revocations.Snapshot.CanonicalBytes.ToArray())
        };
        values.AddRange(identity.ActiveDevices.Select(device => new GroupCodec.AuthorSupport(6,
            GroupCodec.ReferenceForAuthoring(ProtocolMagic.DPD1, device.Certificate.CanonicalHash.Span), device.Certificate.CanonicalBytes.ToArray())));
        return values;
    }

    private static void RequireDistinct(VerifiedDeepIdV2GroupDirectory left, VerifiedDeepIdV2GroupDirectory right)
    { if (left.AccountId.Span.SequenceEqual(right.AccountId.Span)) throw new CryptographicException("Group invitation requires distinct accounts."); }
    internal static ulong Now(VerifiedDeepIdV2GroupDirectory account, OnionMonotonicReading reading) =>
        checked(account.Proof.TrustedLowerUnixSeconds + reading.SampleSeconds - account.Proof.MonotonicSample);
    private static byte[] DeviceReference(VerifiedDeepIdV2GroupDirectory account, OwnedGenesisDeviceSecrets device) =>
        GroupCodec.ReferenceForAuthoring(ProtocolMagic.DPD1, account.RequireDevice(device.DeviceId.Bytes.Span).Certificate.CanonicalHash.Span);
    private static byte[] Placeholder() { var bytes = new byte[64]; bytes[0] = 1; return bytes; }
    private static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static byte[] U32(uint value) { var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes; }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] Join(params byte[][] values) => values.SelectMany(static value => value).ToArray();
}
