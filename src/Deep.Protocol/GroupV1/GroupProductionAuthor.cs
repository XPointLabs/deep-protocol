using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.GroupV1;

public enum GroupDeviceSignaturePurpose : byte
{
    Invitation = 1,
    InvitationAcceptance = 2,
    Proposal = 3,
    Commit = 4,
}

public sealed class GroupAuthoringException : CryptographicException
{
    internal GroupAuthoringException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;
    public string Code { get; }
}

/// <summary>Custody boundary for one verified active device signing key.</summary>
public interface IGroupDeviceCustodySigner
{
    ReadOnlyMemory<byte> DeviceId { get; }
    ReadOnlyMemory<byte> Ed25519PublicKey { get; }
    ReadOnlyMemory<byte> CustodyDomainHash { get; }
    ValueTask<int> SignAsync(GroupDeviceSigningRequest request, Memory<byte> signature64, CancellationToken cancellationToken);
}

public sealed class GroupDeviceSigningRequest
{
    private readonly byte[] networkId, groupId, accountId, deviceId, custodyDomainHash, signingInput, signingInputHash;
    internal GroupDeviceSigningRequest(GroupDeviceSignaturePurpose purpose, ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> groupId, ReadOnlySpan<byte> accountId, ReadOnlySpan<byte> deviceId,
        ReadOnlySpan<byte> custodyDomainHash, ReadOnlySpan<byte> signingInput)
    {
        Purpose = purpose; this.networkId = networkId.ToArray(); this.groupId = groupId.ToArray();
        this.accountId = accountId.ToArray(); this.deviceId = deviceId.ToArray();
        this.custodyDomainHash = custodyDomainHash.ToArray(); this.signingInput = signingInput.ToArray();
        signingInputHash = SHA256.HashData(signingInput);
    }
    public GroupDeviceSignaturePurpose Purpose { get; }
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> GroupId => groupId.ToArray();
    public ReadOnlyMemory<byte> AccountId => accountId.ToArray();
    public ReadOnlyMemory<byte> DeviceId => deviceId.ToArray();
    public ReadOnlyMemory<byte> CustodyDomainHash => custodyDomainHash.ToArray();
    /// <summary>Exact GROUP-CODEC-01 signing input; valid only during SignAsync.</summary>
    public ReadOnlyMemory<byte> SigningInput => signingInput;
    public ReadOnlyMemory<byte> SigningInputSha256 => signingInputHash;
    internal void Clear() { CryptographicOperations.ZeroMemory(signingInput); CryptographicOperations.ZeroMemory(signingInputHash); }
}

public sealed class GroupGenesisAuthoringRequest
{
    private readonly byte[] groupId, sequencerDeviceId, currentBootId;
    public GroupGenesisAuthoringRequest(ReadOnlySpan<byte> groupId, VerifiedContactBundleClosure owner,
        ReadOnlySpan<byte> sequencerDeviceId, string groupName, bool explicitHistoryTransfer,
        uint ordinaryEventExpirySeconds, ulong issuedAtUnixSeconds, ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample)
    {
        this.groupId = Required(groupId, 32, nameof(groupId)); Owner = owner ?? throw new ArgumentNullException(nameof(owner));
        this.sequencerDeviceId = Required(sequencerDeviceId, 32, nameof(sequencerDeviceId));
        GroupName = CanonicalName(groupName); ExplicitHistoryTransfer = explicitHistoryTransfer;
        if (ordinaryEventExpirySeconds == 0) throw new ArgumentOutOfRangeException(nameof(ordinaryEventExpirySeconds));
        OrdinaryEventExpirySeconds = ordinaryEventExpirySeconds;
        if (issuedAtUnixSeconds == 0) throw new ArgumentOutOfRangeException(nameof(issuedAtUnixSeconds));
        IssuedAtUnixSeconds = issuedAtUnixSeconds; this.currentBootId = Required(currentBootId, 16, nameof(currentBootId));
        CurrentMonotonicSample = currentMonotonicSample;
    }
    public ReadOnlyMemory<byte> GroupId => groupId.ToArray(); public VerifiedContactBundleClosure Owner { get; }
    public ReadOnlyMemory<byte> SequencerDeviceId => sequencerDeviceId.ToArray(); public string GroupName { get; }
    public bool ExplicitHistoryTransfer { get; } public uint OrdinaryEventExpirySeconds { get; }
    public ulong IssuedAtUnixSeconds { get; } public ReadOnlyMemory<byte> CurrentBootId => currentBootId.ToArray();
    public ulong CurrentMonotonicSample { get; }
    internal static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    { if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name); return value.ToArray(); }
    internal static string CanonicalName(string value)
    { ArgumentNullException.ThrowIfNull(value); if (!value.IsNormalized(NormalizationForm.FormC) || value.Contains('\0') || Encoding.UTF8.GetByteCount(value) is < 1 or > 128) throw new ArgumentException("Group name must be NFC UTF-8 with 1..128 bytes.", nameof(value)); return value; }
}

public sealed class GroupInvitationAuthoringRequest
{
    private readonly byte[] invitationId, inviterDeviceId;
    public GroupInvitationAuthoringRequest(VerifiedGroupTransition baseState,
        VerifiedContactBundleClosure inviter, ReadOnlySpan<byte> inviterDeviceId,
        VerifiedContactBundleClosure invitee, ReadOnlySpan<byte> invitationId, GroupRole requestedRole,
        ulong issuedAtUnixSeconds, ulong expiresAtUnixSeconds)
    {
        BaseState = baseState ?? throw new ArgumentNullException(nameof(baseState)); Inviter = inviter ?? throw new ArgumentNullException(nameof(inviter));
        Invitee = invitee ?? throw new ArgumentNullException(nameof(invitee)); this.inviterDeviceId = GroupGenesisAuthoringRequest.Required(inviterDeviceId, 32, nameof(inviterDeviceId));
        this.invitationId = GroupGenesisAuthoringRequest.Required(invitationId, 32, nameof(invitationId));
        if (requestedRole is not (GroupRole.Admin or GroupRole.Member)) throw new ArgumentOutOfRangeException(nameof(requestedRole));
        RequestedRole = requestedRole; ValidateWindow(issuedAtUnixSeconds, expiresAtUnixSeconds);
        IssuedAtUnixSeconds = issuedAtUnixSeconds; ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }
    public VerifiedGroupTransition BaseState { get; } public VerifiedContactBundleClosure Inviter { get; }
    public VerifiedContactBundleClosure Invitee { get; } public ReadOnlyMemory<byte> InviterDeviceId => inviterDeviceId.ToArray();
    public ReadOnlyMemory<byte> InvitationId => invitationId.ToArray(); public GroupRole RequestedRole { get; }
    public ulong IssuedAtUnixSeconds { get; } public ulong ExpiresAtUnixSeconds { get; }
    internal static void ValidateWindow(ulong issued, ulong expires)
    { if (issued == 0 || expires <= issued || expires - issued > 604_800) throw new ArgumentOutOfRangeException(nameof(expires), "Window must be non-zero and at most seven days."); }
}

public sealed class GroupInvitationAcceptanceAuthoringRequest
{
    private readonly byte[] acceptingDeviceId;
    public GroupInvitationAcceptanceAuthoringRequest(VerifiedGroupInvitation invitation,
        VerifiedContactBundleClosure invitee, ReadOnlySpan<byte> acceptingDeviceId,
        ulong acceptedAtUnixSeconds, ulong expiresAtUnixSeconds)
    {
        Invitation = invitation ?? throw new ArgumentNullException(nameof(invitation)); Invitee = invitee ?? throw new ArgumentNullException(nameof(invitee));
        this.acceptingDeviceId = GroupGenesisAuthoringRequest.Required(acceptingDeviceId, 32, nameof(acceptingDeviceId));
        GroupInvitationAuthoringRequest.ValidateWindow(acceptedAtUnixSeconds, expiresAtUnixSeconds);
        AcceptedAtUnixSeconds = acceptedAtUnixSeconds; ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }
    public VerifiedGroupInvitation Invitation { get; } public VerifiedContactBundleClosure Invitee { get; }
    public ReadOnlyMemory<byte> AcceptingDeviceId => acceptingDeviceId.ToArray();
    public ulong AcceptedAtUnixSeconds { get; } public ulong ExpiresAtUnixSeconds { get; }
}

public sealed class GroupActivationProposalAuthoringRequest
{
    private readonly byte[] proposalId, proposerDeviceId;
    public GroupActivationProposalAuthoringRequest(VerifiedGroupInvitationAcceptance acceptance,
        VerifiedContactBundleClosure proposer, ReadOnlySpan<byte> proposerDeviceId, ReadOnlySpan<byte> proposalId,
        ulong issuedAtUnixSeconds, ulong expiresAtUnixSeconds)
    {
        Acceptance = acceptance ?? throw new ArgumentNullException(nameof(acceptance)); Proposer = proposer ?? throw new ArgumentNullException(nameof(proposer));
        this.proposerDeviceId = GroupGenesisAuthoringRequest.Required(proposerDeviceId, 32, nameof(proposerDeviceId));
        this.proposalId = GroupGenesisAuthoringRequest.Required(proposalId, 32, nameof(proposalId));
        GroupInvitationAuthoringRequest.ValidateWindow(issuedAtUnixSeconds, expiresAtUnixSeconds);
        IssuedAtUnixSeconds = issuedAtUnixSeconds; ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }
    public VerifiedGroupInvitationAcceptance Acceptance { get; } public VerifiedContactBundleClosure Proposer { get; }
    public ReadOnlyMemory<byte> ProposerDeviceId => proposerDeviceId.ToArray(); public ReadOnlyMemory<byte> ProposalId => proposalId.ToArray();
    public ulong IssuedAtUnixSeconds { get; } public ulong ExpiresAtUnixSeconds { get; }
}

public sealed class GroupRemoveAccountProposalAuthoringRequest
{
    private readonly byte[] proposerDeviceId, proposalId;
    public GroupRemoveAccountProposalAuthoringRequest(VerifiedGroupTransition baseState,
        VerifiedContactBundleClosure proposer, ReadOnlySpan<byte> proposerDeviceId,
        VerifiedContactBundleClosure target, ReadOnlySpan<byte> proposalId, ushort reason,
        ulong issuedAtUnixSeconds, ulong expiresAtUnixSeconds)
    {
        BaseState = baseState ?? throw new ArgumentNullException(nameof(baseState));
        Proposer = proposer ?? throw new ArgumentNullException(nameof(proposer));
        Target = target ?? throw new ArgumentNullException(nameof(target));
        this.proposerDeviceId = GroupGenesisAuthoringRequest.Required(proposerDeviceId, 32, nameof(proposerDeviceId));
        this.proposalId = GroupGenesisAuthoringRequest.Required(proposalId, 32, nameof(proposalId));
        Reason = reason;
        GroupInvitationAuthoringRequest.ValidateWindow(issuedAtUnixSeconds, expiresAtUnixSeconds);
        IssuedAtUnixSeconds = issuedAtUnixSeconds; ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }
    public VerifiedGroupTransition BaseState { get; } public VerifiedContactBundleClosure Proposer { get; }
    public VerifiedContactBundleClosure Target { get; } public ReadOnlyMemory<byte> ProposerDeviceId => proposerDeviceId.ToArray();
    public ReadOnlyMemory<byte> ProposalId => proposalId.ToArray(); public ushort Reason { get; }
    public ulong IssuedAtUnixSeconds { get; } public ulong ExpiresAtUnixSeconds { get; }
}

public sealed class GroupLeaveAccountProposalAuthoringRequest
{
    private readonly byte[] proposerDeviceId, proposalId;
    public GroupLeaveAccountProposalAuthoringRequest(VerifiedGroupTransition baseState,
        VerifiedContactBundleClosure member, ReadOnlySpan<byte> memberDeviceId,
        ReadOnlySpan<byte> proposalId, ushort reason, ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds)
    {
        BaseState = baseState ?? throw new ArgumentNullException(nameof(baseState));
        Member = member ?? throw new ArgumentNullException(nameof(member));
        proposerDeviceId = GroupGenesisAuthoringRequest.Required(memberDeviceId, 32, nameof(memberDeviceId));
        this.proposalId = GroupGenesisAuthoringRequest.Required(proposalId, 32, nameof(proposalId));
        Reason = reason;
        GroupInvitationAuthoringRequest.ValidateWindow(issuedAtUnixSeconds, expiresAtUnixSeconds);
        IssuedAtUnixSeconds = issuedAtUnixSeconds; ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }
    public VerifiedGroupTransition BaseState { get; } public VerifiedContactBundleClosure Member { get; }
    public ReadOnlyMemory<byte> MemberDeviceId => proposerDeviceId.ToArray(); public ReadOnlyMemory<byte> ProposalId => proposalId.ToArray();
    public ushort Reason { get; } public ulong IssuedAtUnixSeconds { get; } public ulong ExpiresAtUnixSeconds { get; }
}

public sealed class GroupRoleChangeProposalAuthoringRequest
{
    private readonly byte[] proposerDeviceId, proposalId;
    public GroupRoleChangeProposalAuthoringRequest(VerifiedGroupTransition baseState,
        VerifiedContactBundleClosure proposer, ReadOnlySpan<byte> proposerDeviceId,
        VerifiedContactBundleClosure target, GroupRole newRole, ReadOnlySpan<byte> proposalId,
        ulong issuedAtUnixSeconds, ulong expiresAtUnixSeconds)
    {
        BaseState = baseState ?? throw new ArgumentNullException(nameof(baseState));
        Proposer = proposer ?? throw new ArgumentNullException(nameof(proposer));
        Target = target ?? throw new ArgumentNullException(nameof(target));
        if (newRole is not (GroupRole.Admin or GroupRole.Member)) throw new ArgumentOutOfRangeException(nameof(newRole));
        NewRole = newRole;
        this.proposerDeviceId = GroupGenesisAuthoringRequest.Required(proposerDeviceId, 32, nameof(proposerDeviceId));
        this.proposalId = GroupGenesisAuthoringRequest.Required(proposalId, 32, nameof(proposalId));
        GroupInvitationAuthoringRequest.ValidateWindow(issuedAtUnixSeconds, expiresAtUnixSeconds);
        IssuedAtUnixSeconds = issuedAtUnixSeconds; ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }
    public VerifiedGroupTransition BaseState { get; } public VerifiedContactBundleClosure Proposer { get; }
    public VerifiedContactBundleClosure Target { get; } public GroupRole NewRole { get; }
    public ReadOnlyMemory<byte> ProposerDeviceId => proposerDeviceId.ToArray(); public ReadOnlyMemory<byte> ProposalId => proposalId.ToArray();
    public ulong IssuedAtUnixSeconds { get; } public ulong ExpiresAtUnixSeconds { get; }
}

public sealed class GroupMembershipChangeCommitAuthoringRequest
{
    private readonly VerifiedContactBundleClosure[] baseDirectories, currentDirectories; private readonly byte[] currentBootId;
    public GroupMembershipChangeCommitAuthoringRequest(VerifiedGroupTransition previous,
        VerifiedGroupMembershipProposal proposal, IReadOnlyList<VerifiedContactBundleClosure> baseDirectories,
        IReadOnlyList<VerifiedContactBundleClosure> currentDirectories, ulong issuedAtUnixSeconds,
        ReadOnlySpan<byte> currentBootId, ulong currentMonotonicSample)
    {
        Previous = previous ?? throw new ArgumentNullException(nameof(previous));
        Proposal = proposal ?? throw new ArgumentNullException(nameof(proposal));
        this.baseDirectories = Copy(baseDirectories, nameof(baseDirectories));
        this.currentDirectories = Copy(currentDirectories, nameof(currentDirectories));
        if (issuedAtUnixSeconds == 0) throw new ArgumentOutOfRangeException(nameof(issuedAtUnixSeconds));
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        this.currentBootId = GroupGenesisAuthoringRequest.Required(currentBootId, 16, nameof(currentBootId));
        CurrentMonotonicSample = currentMonotonicSample;
    }
    public VerifiedGroupTransition Previous { get; } public VerifiedGroupMembershipProposal Proposal { get; }
    public IReadOnlyList<VerifiedContactBundleClosure> BaseDirectories => Array.AsReadOnly(baseDirectories.ToArray());
    public IReadOnlyList<VerifiedContactBundleClosure> CurrentDirectories => Array.AsReadOnly(currentDirectories.ToArray());
    public ulong IssuedAtUnixSeconds { get; } public ReadOnlyMemory<byte> CurrentBootId => currentBootId.ToArray(); public ulong CurrentMonotonicSample { get; }
    private static VerifiedContactBundleClosure[] Copy(IReadOnlyList<VerifiedContactBundleClosure> values, string name)
    { ArgumentNullException.ThrowIfNull(values); if (values.Count is < 1 or > 100) throw new ArgumentOutOfRangeException(name); return values.Select(value => value ?? throw new ArgumentException("Null directory capability.", name)).ToArray(); }
}

public sealed class GroupMembershipCommitAuthoringRequest
{
    private readonly VerifiedContactBundleClosure[] baseDirectories, currentDirectories; private readonly byte[] currentBootId;
    public GroupMembershipCommitAuthoringRequest(VerifiedGroupTransition previous,
        VerifiedGroupActivationProposal proposal, IReadOnlyList<VerifiedContactBundleClosure> baseDirectories,
        IReadOnlyList<VerifiedContactBundleClosure> currentDirectories, ulong issuedAtUnixSeconds,
        ReadOnlySpan<byte> currentBootId, ulong currentMonotonicSample)
    {
        Previous = previous ?? throw new ArgumentNullException(nameof(previous)); Proposal = proposal ?? throw new ArgumentNullException(nameof(proposal));
        this.baseDirectories = Copy(baseDirectories, nameof(baseDirectories)); this.currentDirectories = Copy(currentDirectories, nameof(currentDirectories));
        if (issuedAtUnixSeconds == 0) throw new ArgumentOutOfRangeException(nameof(issuedAtUnixSeconds)); IssuedAtUnixSeconds = issuedAtUnixSeconds;
        this.currentBootId = GroupGenesisAuthoringRequest.Required(currentBootId, 16, nameof(currentBootId)); CurrentMonotonicSample = currentMonotonicSample;
    }
    public VerifiedGroupTransition Previous { get; } public VerifiedGroupActivationProposal Proposal { get; }
    public IReadOnlyList<VerifiedContactBundleClosure> BaseDirectories => Array.AsReadOnly(baseDirectories.ToArray());
    public IReadOnlyList<VerifiedContactBundleClosure> CurrentDirectories => Array.AsReadOnly(currentDirectories.ToArray());
    public ulong IssuedAtUnixSeconds { get; } public ReadOnlyMemory<byte> CurrentBootId => currentBootId.ToArray(); public ulong CurrentMonotonicSample { get; }
    private static VerifiedContactBundleClosure[] Copy(IReadOnlyList<VerifiedContactBundleClosure> values, string name)
    { ArgumentNullException.ThrowIfNull(values); if (values.Count is < 1 or > 100) throw new ArgumentOutOfRangeException(name); return values.Select(v => v ?? throw new ArgumentException("Null directory capability.", name)).ToArray(); }
}

public sealed class GroupApplicationMessageAuthoringRequest
{
    private readonly byte[] eventId, senderDeviceId, payload, currentBootId;
    public GroupApplicationMessageAuthoringRequest(VerifiedGroupTransition state, VerifiedContactBundleClosure sender,
        ReadOnlySpan<byte> senderDeviceId, ReadOnlySpan<byte> eventId, ulong senderSequence,
        ulong createdAtUnixMilliseconds, ulong expiresAtUnixMilliseconds, GroupApplicationEventKind kind,
        ReadOnlySpan<byte> canonicalPayload, ReadOnlySpan<byte> currentBootId, ulong currentMonotonicSample)
    {
        State = state ?? throw new ArgumentNullException(nameof(state)); Sender = sender ?? throw new ArgumentNullException(nameof(sender));
        this.senderDeviceId = GroupGenesisAuthoringRequest.Required(senderDeviceId, 32, nameof(senderDeviceId));
        this.eventId = GroupGenesisAuthoringRequest.Required(eventId, 32, nameof(eventId));
        if (senderSequence == 0) throw new ArgumentOutOfRangeException(nameof(senderSequence)); SenderSequence = senderSequence;
        if (createdAtUnixMilliseconds == 0 || expiresAtUnixMilliseconds <= createdAtUnixMilliseconds) throw new ArgumentOutOfRangeException(nameof(expiresAtUnixMilliseconds));
        CreatedAtUnixMilliseconds = createdAtUnixMilliseconds; ExpiresAtUnixMilliseconds = expiresAtUnixMilliseconds;
        if (kind is < GroupApplicationEventKind.Text or > GroupApplicationEventKind.ProfileNotice) throw new ArgumentOutOfRangeException(nameof(kind)); Kind = kind;
        if (canonicalPayload.Length > 24_576) throw new ArgumentOutOfRangeException(nameof(canonicalPayload)); payload = canonicalPayload.ToArray();
        this.currentBootId = GroupGenesisAuthoringRequest.Required(currentBootId, 16, nameof(currentBootId)); CurrentMonotonicSample = currentMonotonicSample;
    }
    public VerifiedGroupTransition State { get; } public VerifiedContactBundleClosure Sender { get; }
    public ReadOnlyMemory<byte> SenderDeviceId => senderDeviceId.ToArray(); public ReadOnlyMemory<byte> EventId => eventId.ToArray();
    public ulong SenderSequence { get; } public ulong CreatedAtUnixMilliseconds { get; } public ulong ExpiresAtUnixMilliseconds { get; }
    public GroupApplicationEventKind Kind { get; } public ReadOnlyMemory<byte> CanonicalPayload => payload.ToArray();
    public ReadOnlyMemory<byte> CurrentBootId => currentBootId.ToArray(); public ulong CurrentMonotonicSample { get; }
}

public sealed class VerifiedAuthoredGroupTransition
{
    internal VerifiedAuthoredGroupTransition(GroupCommitPackageRecord package, VerifiedGroupTransition transition)
    { Package = package; Transition = transition; }
    public GroupCommitPackageRecord Package { get; } public VerifiedGroupTransition Transition { get; }
    public ReadOnlyMemory<byte> CanonicalPackageBytes => Package.CanonicalBytes;
}
public sealed class VerifiedGroupInvitation
{
    internal VerifiedGroupInvitation(GroupInvitationRecord record, VerifiedGroupTransition baseState, VerifiedContactBundleClosure invitee)
    { Record = record; BaseState = baseState; Invitee = invitee; }
    public GroupInvitationRecord Record { get; } public VerifiedGroupTransition BaseState { get; } public VerifiedContactBundleClosure Invitee { get; }
}
public sealed class VerifiedGroupInvitationAcceptance
{
    internal VerifiedGroupInvitationAcceptance(GroupInvitationAcceptanceRecord record, VerifiedGroupInvitation invitation, VerifiedContactBundleClosure invitee)
    { Record = record; Invitation = invitation; Invitee = invitee; }
    public GroupInvitationAcceptanceRecord Record { get; } public VerifiedGroupInvitation Invitation { get; } public VerifiedContactBundleClosure Invitee { get; }
}
public sealed class VerifiedGroupActivationProposal
{
    internal VerifiedGroupActivationProposal(GroupProposalRecord record, VerifiedGroupInvitationAcceptance acceptance)
    { Record = record; Acceptance = acceptance; }
    public GroupProposalRecord Record { get; } public VerifiedGroupInvitationAcceptance Acceptance { get; }
}
public sealed class VerifiedGroupMembershipProposal
{
    internal VerifiedGroupMembershipProposal(GroupProposalRecord record, VerifiedGroupTransition baseState,
        VerifiedContactBundleClosure proposer, VerifiedContactBundleClosure target, GroupProposalAction action,
        GroupRole? newRole)
    { Record = record; BaseState = baseState; Proposer = proposer; Target = target; Action = action; NewRole = newRole; }
    public GroupProposalRecord Record { get; } public VerifiedGroupTransition BaseState { get; }
    public VerifiedContactBundleClosure Proposer { get; } public VerifiedContactBundleClosure Target { get; }
    public GroupProposalAction Action { get; } public GroupRole? NewRole { get; }
}
public sealed class VerifiedGroupApplicationMessage
{
    internal VerifiedGroupApplicationMessage(GroupApplicationMessageRecord record, VerifiedGroupTransition state, VerifiedContactBundleClosure sender)
    { Record = record; State = state; Sender = sender; }
    public GroupApplicationMessageRecord Record { get; } public VerifiedGroupTransition State { get; } public VerifiedContactBundleClosure Sender { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => Record.CanonicalBytes;
}

public static class GroupProductionAuthor
{
    public static async ValueTask<VerifiedAuthoredGroupTransition> AuthorGenesisAsync(GroupGenesisAuthoringRequest request,
        IGroupDeviceCustodySigner signer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(signer); cancellationToken.ThrowIfCancellationRequested();
        var owner = request.Owner; RequireCurrent(owner, request.IssuedAtUnixSeconds, request.CurrentBootId.Span, request.CurrentMonotonicSample);
        var member = GroupCodec.MemberFromDirectoryForAuthoring(owner, GroupRole.Owner);
        var device = GroupCodec.RequireClosureDeviceForAuthoring(owner, request.SequencerDeviceId.Span);
        var dpd = GroupCodec.ReferenceForAuthoring(ProtocolMagic.DPD1, device.Certificate.CanonicalHash.Span);
        var supports = GroupCodec.SupportForAuthoring([owner]);
        var fields = new ReadOnlyMemory<byte>[] { owner.Directory.Record.NetworkId, request.GroupId, U16(1), U64(0), new byte[32],
            owner.Directory.Record.DeepAccountId, request.SequencerDeviceId, dpd, U16(0), Array.Empty<byte>(), U16(1),
            GroupCodec.SerializeMembersForAuthoring([member]), Encoding.UTF8.GetBytes(request.GroupName),
            new byte[] { request.ExplicitHistoryTransfer ? (byte)1 : (byte)0 }, U32(request.OrdinaryEventExpirySeconds), U64(request.IssuedAtUnixSeconds), SignaturePlaceholder() };
        var commit = (GroupCommitRecord)await GroupCodec.SignForAuthoringAsync(ProtocolMagic.DGC1, fields, 17,
            GroupDeviceSignaturePurpose.Commit, owner, request.SequencerDeviceId, signer, cancellationToken).ConfigureAwait(false);
        var package = GroupCodec.PackageForAuthoring(commit, [], supports, []);
        var identities = GroupIdentityClosure.FromVerifiedContactDirectories([], [owner], request.CurrentBootId.Span, request.CurrentMonotonicSample);
        return GroupCodec.VerifyAuthoredPackage(package, null, identities);
    }

    public static async ValueTask<VerifiedGroupInvitation> AuthorInvitationAsync(GroupInvitationAuthoringRequest request,
        IGroupDeviceCustodySigner signer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(signer);
        var commit = request.BaseState.Commit; GroupCodec.RequireMemberForAuthoring(commit, request.Inviter, request.InviterDeviceId.Span, requireAdministrator: true);
        RequireSameNetwork(request.Inviter, request.Invitee);
        var fields = new ReadOnlyMemory<byte>[] { commit.Field(1), commit.Field(2), request.InvitationId, commit.Field(4), commit.ArtifactHash,
            request.Inviter.Directory.Record.DeepAccountId, request.InviterDeviceId,
            GroupCodec.ReferenceForAuthoring(ProtocolMagic.DPD1, GroupCodec.RequireClosureDeviceForAuthoring(request.Inviter, request.InviterDeviceId.Span).Certificate.CanonicalHash.Span),
            request.Invitee.Directory.Record.DeepAccountId, new byte[] { (byte)request.RequestedRole }, request.Invitee.Freshness.ExactAdc1Reference,
            request.Invitee.Freshness.ExactAdh1CoreReference, request.Invitee.Freshness.ExactAdp1Hash, request.Invitee.Directory.Record.RecordHash,
            GroupCodec.ReferenceForAuthoring(ProtocolMagic.DRS1, request.Invitee.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span),
            U64(request.IssuedAtUnixSeconds), U64(request.ExpiresAtUnixSeconds), SignaturePlaceholder() };
        var record = (GroupInvitationRecord)await GroupCodec.SignForAuthoringAsync(ProtocolMagic.GIV1, fields, 18,
            GroupDeviceSignaturePurpose.Invitation, request.Inviter, request.InviterDeviceId, signer, cancellationToken).ConfigureAwait(false);
        return new VerifiedGroupInvitation(record, request.BaseState, request.Invitee);
    }

    public static async ValueTask<VerifiedGroupInvitationAcceptance> AuthorInvitationAcceptanceAsync(
        GroupInvitationAcceptanceAuthoringRequest request, IGroupDeviceCustodySigner signer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(signer); var invitation = request.Invitation.Record;
        if (!ReferenceEquals(request.Invitee, request.Invitation.Invitee) || request.ExpiresAtUnixSeconds > BinaryPrimitives.ReadUInt64BigEndian(invitation.Field(17).Span))
            Fail("invitation-directory-mismatch", "Acceptance must use the exact invited directory capability and cannot outlive GIV1.");
        var device = GroupCodec.RequireClosureDeviceForAuthoring(request.Invitee, request.AcceptingDeviceId.Span);
        if (device.Certificate.IssuedAtUnixSeconds > request.AcceptedAtUnixSeconds || device.Certificate.ExpiresAtUnixSeconds <= request.AcceptedAtUnixSeconds)
            Fail("accepting-device-not-current", "Accepting device is outside its verified certificate lifetime.");
        var fields = new ReadOnlyMemory<byte>[] { invitation.Field(1), invitation.Field(2), invitation.Field(3),
            GroupCodec.ArtifactReference(ProtocolMagic.GIV1, invitation).CanonicalBytes, request.Invitee.Directory.Record.DeepAccountId,
            request.AcceptingDeviceId, GroupCodec.ReferenceForAuthoring(ProtocolMagic.DPD1, device.Certificate.CanonicalHash.Span),
            request.Invitee.Freshness.ExactAdc1Reference, request.Invitee.Freshness.ExactAdh1CoreReference, request.Invitee.Freshness.ExactAdp1Hash,
            request.Invitee.Directory.Record.RecordHash, GroupCodec.ReferenceForAuthoring(ProtocolMagic.DRS1, request.Invitee.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span),
            U64(request.AcceptedAtUnixSeconds), U64(request.ExpiresAtUnixSeconds), SignaturePlaceholder() };
        var record = (GroupInvitationAcceptanceRecord)await GroupCodec.SignForAuthoringAsync(ProtocolMagic.GIA1, fields, 15,
            GroupDeviceSignaturePurpose.InvitationAcceptance, request.Invitee, request.AcceptingDeviceId, signer, cancellationToken).ConfigureAwait(false);
        return new VerifiedGroupInvitationAcceptance(record, request.Invitation, request.Invitee);
    }

    public static async ValueTask<VerifiedGroupActivationProposal> AuthorActivationProposalAsync(
        GroupActivationProposalAuthoringRequest request, IGroupDeviceCustodySigner signer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(signer);
        var invitation = request.Acceptance.Invitation; var acceptance = request.Acceptance.Record; var commit = invitation.BaseState.Commit;
        GroupCodec.RequireMemberForAuthoring(commit, request.Proposer, request.ProposerDeviceId.Span, requireAdministrator: true);
        var invitee = request.Acceptance.Invitee;
        var payload = Join(GroupCodec.ArtifactReference(ProtocolMagic.GIV1, invitation.Record).CanonicalBytes.ToArray(),
            GroupCodec.ArtifactReference(ProtocolMagic.GIA1, acceptance).CanonicalBytes.ToArray(), invitee.Directory.Record.DeepAccountId.ToArray(),
            new byte[] { invitation.Record.Field(10).Span[0] }, invitee.Freshness.ExactAdc1Reference.ToArray(), invitee.Freshness.ExactAdh1CoreReference.ToArray(),
            invitee.Freshness.ExactAdp1Hash.ToArray(), invitee.Directory.Record.RecordHash.ToArray(),
            GroupCodec.ReferenceForAuthoring(ProtocolMagic.DRS1, invitee.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span));
        var proposerDevice = GroupCodec.RequireClosureDeviceForAuthoring(request.Proposer, request.ProposerDeviceId.Span);
        var fields = new ReadOnlyMemory<byte>[] { commit.Field(1), commit.Field(2), commit.Field(4), commit.ArtifactHash, request.ProposalId,
            request.Proposer.Directory.Record.DeepAccountId, request.ProposerDeviceId,
            GroupCodec.ReferenceForAuthoring(ProtocolMagic.DPD1, proposerDevice.Certificate.CanonicalHash.Span), U16((ushort)GroupProposalAction.ActivateAcceptedInvite),
            payload, U64(request.IssuedAtUnixSeconds), U64(request.ExpiresAtUnixSeconds), SignaturePlaceholder() };
        var record = (GroupProposalRecord)await GroupCodec.SignForAuthoringAsync(ProtocolMagic.DGP1, fields, 13,
            GroupDeviceSignaturePurpose.Proposal, request.Proposer, request.ProposerDeviceId, signer, cancellationToken).ConfigureAwait(false);
        return new VerifiedGroupActivationProposal(record, request.Acceptance);
    }

    public static async ValueTask<VerifiedGroupMembershipProposal> AuthorRemoveAccountProposalAsync(
        GroupRemoveAccountProposalAuthoringRequest request, IGroupDeviceCustodySigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(signer);
        RequireSameNetwork(request.Proposer, request.Target);
        GroupCodec.RequireMemberForAuthoring(request.BaseState.Commit, request.Proposer,
            request.ProposerDeviceId.Span, requireAdministrator: true);
        var target = GroupCodec.RequireMemberClosureForAuthoring(request.BaseState.Commit, request.Target);
        if (target.Role == GroupRole.Owner) Fail("owner-removal-forbidden", "The owner account cannot be removed.");
        var payload = Join(target.Account, GroupCodec.MemberEntryHashForAuthoring(target), U16(request.Reason));
        return await AuthorMembershipProposalAsync(request.BaseState, request.Proposer,
            request.ProposerDeviceId, request.Target, request.ProposalId, GroupProposalAction.RemoveAccount,
            payload, request.IssuedAtUnixSeconds, request.ExpiresAtUnixSeconds, null, signer,
            cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<VerifiedGroupMembershipProposal> AuthorLeaveAccountProposalAsync(
        GroupLeaveAccountProposalAuthoringRequest request, IGroupDeviceCustodySigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(signer);
        GroupCodec.RequireMemberForAuthoring(request.BaseState.Commit, request.Member,
            request.MemberDeviceId.Span, requireAdministrator: false);
        var member = GroupCodec.RequireMemberClosureForAuthoring(request.BaseState.Commit, request.Member);
        if (member.Role == GroupRole.Owner) Fail("owner-leave-forbidden", "The owner must transfer ownership before leaving.");
        var payload = Join(member.Account, GroupCodec.MemberEntryHashForAuthoring(member), U16(request.Reason));
        return await AuthorMembershipProposalAsync(request.BaseState, request.Member,
            request.MemberDeviceId, request.Member, request.ProposalId, GroupProposalAction.LeaveAccount,
            payload, request.IssuedAtUnixSeconds, request.ExpiresAtUnixSeconds, null, signer,
            cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<VerifiedGroupMembershipProposal> AuthorRoleChangeProposalAsync(
        GroupRoleChangeProposalAuthoringRequest request, IGroupDeviceCustodySigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(signer);
        RequireSameNetwork(request.Proposer, request.Target);
        GroupCodec.RequireMemberForAuthoring(request.BaseState.Commit, request.Proposer,
            request.ProposerDeviceId.Span, requireAdministrator: true);
        var target = GroupCodec.RequireMemberClosureForAuthoring(request.BaseState.Commit, request.Target);
        if (target.Role == GroupRole.Owner) Fail("owner-role-change-forbidden", "The owner role cannot be changed by DGP1.");
        if (target.Role == request.NewRole) Fail("role-unchanged", "A role-change proposal must change the target role.");
        var payload = Join(target.Account, [(byte)target.Role], [(byte)request.NewRole],
            GroupCodec.MemberEntryHashForAuthoring(target));
        return await AuthorMembershipProposalAsync(request.BaseState, request.Proposer,
            request.ProposerDeviceId, request.Target, request.ProposalId, GroupProposalAction.ChangeRole,
            payload, request.IssuedAtUnixSeconds, request.ExpiresAtUnixSeconds, request.NewRole, signer,
            cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<VerifiedAuthoredGroupTransition> AuthorMembershipChangeCommitAsync(
        GroupMembershipChangeCommitAuthoringRequest request, IGroupDeviceCustodySigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(signer);
        if (!ReferenceEquals(request.Proposal.BaseState, request.Previous))
            Fail("proposal-base-mismatch", "Proposal capability belongs to another base transition.");
        var previous = request.Previous; var proposal = request.Proposal.Record;
        var baseMembers = GroupCodec.ReadMembersForAuthoring(previous.Commit);
        GroupCodec.RequireExactDirectorySetForAuthoring(baseMembers, request.BaseDirectories);
        GroupCodec.RequireExactDirectoryAccountSetForAuthoring(baseMembers, request.CurrentDirectories);
        if (request.IssuedAtUnixSeconds < BinaryPrimitives.ReadUInt64BigEndian(proposal.Field(11).Span) ||
            request.IssuedAtUnixSeconds >= BinaryPrimitives.ReadUInt64BigEndian(proposal.Field(12).Span))
            Fail("commit-window-invalid", "Commit instant is outside the proposal window.");
        foreach (var current in request.CurrentDirectories)
            RequireCurrent(current, request.IssuedAtUnixSeconds, request.CurrentBootId.Span,
                request.CurrentMonotonicSample);

        var targetAccount = request.Proposal.Target.Directory.Record.DeepAccountId.Span;
        var members = new List<GroupCodec.Member>(baseMembers.Count);
        foreach (var prior in baseMembers)
        {
            if (request.Proposal.Action is GroupProposalAction.RemoveAccount or GroupProposalAction.LeaveAccount &&
                prior.Account.AsSpan().SequenceEqual(targetAccount))
                continue;
            var current = request.CurrentDirectories.Single(value =>
                value.Directory.Record.DeepAccountId.Span.SequenceEqual(prior.Account));
            var role = prior.Account.AsSpan().SequenceEqual(targetAccount) &&
                request.Proposal.Action == GroupProposalAction.ChangeRole
                ? request.Proposal.NewRole!.Value
                : prior.Role;
            members.Add(GroupCodec.MemberFromDirectoryForAuthoring(current, role));
        }
        GroupCodec.EnforceLimitsForAuthoring(members);
        var ownerAccount = previous.Commit.Field(6).ToArray();
        var ownerBase = request.BaseDirectories.Single(value =>
            value.Directory.Record.DeepAccountId.Span.SequenceEqual(ownerAccount));
        var sequencerId = previous.Commit.Field(7);
        GroupCodec.RequireMemberForAuthoring(previous.Commit, ownerBase, sequencerId.Span,
            requireAdministrator: true);
        var supports = GroupCodec.SupportForAuthoring(request.BaseDirectories.Concat(request.CurrentDirectories).ToArray());
        var fields = new ReadOnlyMemory<byte>[] { previous.Commit.Field(1), previous.Commit.Field(2), U16(1),
            U64(checked(BinaryPrimitives.ReadUInt64BigEndian(previous.Commit.Field(4).Span) + 1)), previous.Commit.ArtifactHash,
            previous.Commit.Field(6), sequencerId, previous.Commit.Field(8), U16(1), proposal.ArtifactHash,
            U16(checked((ushort)members.Count)), GroupCodec.SerializeMembersForAuthoring(members),
            previous.Commit.Field(13), previous.Commit.Field(14), previous.Commit.Field(15),
            U64(request.IssuedAtUnixSeconds), SignaturePlaceholder() };
        var commit = (GroupCommitRecord)await GroupCodec.SignForAuthoringAsync(ProtocolMagic.DGC1,
            fields, 17, GroupDeviceSignaturePurpose.Commit, ownerBase, sequencerId, signer,
            cancellationToken).ConfigureAwait(false);
        var package = GroupCodec.PackageForAuthoring(commit, [proposal], supports, []);
        var identities = GroupIdentityClosure.FromVerifiedContactDirectories(request.BaseDirectories,
            request.CurrentDirectories, request.CurrentBootId.Span, request.CurrentMonotonicSample);
        return GroupCodec.VerifyAuthoredPackage(package, previous, identities);
    }

    public static async ValueTask<VerifiedAuthoredGroupTransition> AuthorMembershipCommitAsync(
        GroupMembershipCommitAuthoringRequest request, IGroupDeviceCustodySigner signer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(signer); var previous = request.Previous;
        if (!ReferenceEquals(request.Proposal.Acceptance.Invitation.BaseState, request.Previous)) Fail("proposal-base-mismatch", "Proposal capability belongs to another base transition.");
        var baseMembers = GroupCodec.ReadMembersForAuthoring(previous.Commit);
        GroupCodec.RequireExactDirectorySetForAuthoring(baseMembers, request.BaseDirectories);
        var proposal = request.Proposal.Record; var invitee = request.Proposal.Acceptance.Invitee;
        var invitation = request.Proposal.Acceptance.Invitation.Record; var acceptance = request.Proposal.Acceptance.Record;
        if (request.IssuedAtUnixSeconds < BinaryPrimitives.ReadUInt64BigEndian(proposal.Field(11).Span) ||
            request.IssuedAtUnixSeconds >= BinaryPrimitives.ReadUInt64BigEndian(proposal.Field(12).Span) ||
            request.IssuedAtUnixSeconds < BinaryPrimitives.ReadUInt64BigEndian(invitation.Field(16).Span) ||
            request.IssuedAtUnixSeconds >= BinaryPrimitives.ReadUInt64BigEndian(invitation.Field(17).Span) ||
            request.IssuedAtUnixSeconds < BinaryPrimitives.ReadUInt64BigEndian(acceptance.Field(13).Span) ||
            request.IssuedAtUnixSeconds >= BinaryPrimitives.ReadUInt64BigEndian(acceptance.Field(14).Span))
            Fail("commit-window-invalid", "Commit instant is outside proposal or accepted-invitation windows.");
        foreach (var current in request.CurrentDirectories)
            RequireCurrent(current, request.IssuedAtUnixSeconds, request.CurrentBootId.Span, request.CurrentMonotonicSample);
        var inviteeAccount = invitee.Directory.Record.DeepAccountId.ToArray();
        if (baseMembers.Any(member => member.Account.AsSpan().SequenceEqual(inviteeAccount))) Fail("member-already-active", "Invitee is already active.");
        var members = baseMembers.Select(GroupCodec.CloneMemberForAuthoring).ToList();
        members.Add(GroupCodec.MemberFromDirectoryForAuthoring(invitee, (GroupRole)request.Proposal.Acceptance.Invitation.Record.Field(10).Span[0]));
        GroupCodec.EnforceLimitsForAuthoring(members); GroupCodec.RequireExactDirectorySetForAuthoring(members, request.CurrentDirectories);
        var owner = members.Single(member => member.Role == GroupRole.Owner); var sequencerId = previous.Commit.Field(7).ToArray();
        var ownerBase = request.BaseDirectories.Single(value => value.Directory.Record.DeepAccountId.Span.SequenceEqual(owner.Account));
        GroupCodec.RequireMemberForAuthoring(previous.Commit, ownerBase, sequencerId, requireAdministrator: true);
        var supports = GroupCodec.SupportForAuthoring(request.BaseDirectories.Concat(request.CurrentDirectories).ToArray());
        var fields = new ReadOnlyMemory<byte>[] { previous.Commit.Field(1), previous.Commit.Field(2), U16(1),
            U64(checked(BinaryPrimitives.ReadUInt64BigEndian(previous.Commit.Field(4).Span) + 1)), previous.Commit.ArtifactHash,
            previous.Commit.Field(6), previous.Commit.Field(7), previous.Commit.Field(8), U16(1), proposal.ArtifactHash, U16(checked((ushort)members.Count)),
            GroupCodec.SerializeMembersForAuthoring(members), previous.Commit.Field(13), previous.Commit.Field(14), previous.Commit.Field(15),
            U64(request.IssuedAtUnixSeconds), SignaturePlaceholder() };
        var commit = (GroupCommitRecord)await GroupCodec.SignForAuthoringAsync(ProtocolMagic.DGC1, fields, 17,
            GroupDeviceSignaturePurpose.Commit, ownerBase, sequencerId, signer, cancellationToken).ConfigureAwait(false);
        var pair = request.Proposal.Acceptance;
        var package = GroupCodec.PackageForAuthoring(commit, [proposal], supports, [(pair.Invitation.Record, pair.Record)]);
        var identities = GroupIdentityClosure.FromVerifiedContactDirectories(request.BaseDirectories, request.CurrentDirectories,
            request.CurrentBootId.Span, request.CurrentMonotonicSample);
        return GroupCodec.VerifyAuthoredPackage(package, previous, identities);
    }

    public static VerifiedGroupApplicationMessage AuthorApplicationMessage(GroupApplicationMessageAuthoringRequest request)
    {
        ArgumentNullException.ThrowIfNull(request); var commit = request.State.Commit;
        RequireCurrent(request.Sender, request.CreatedAtUnixMilliseconds / 1000, request.CurrentBootId.Span, request.CurrentMonotonicSample);
        GroupCodec.RequireMemberForAuthoring(commit, request.Sender, request.SenderDeviceId.Span, requireAdministrator: false);
        var allowed = checked((ulong)BinaryPrimitives.ReadUInt32BigEndian(commit.Field(15).Span) * 1000);
        if (request.ExpiresAtUnixMilliseconds - request.CreatedAtUnixMilliseconds > allowed)
            Fail("message-expiry-exceeded", "DGM1 expiry exceeds the exact commit ordinary-event policy.");
        var fields = new ReadOnlyMemory<byte>[] { commit.Field(1), commit.Field(2), commit.Field(4), commit.ArtifactHash, request.EventId,
            request.Sender.Directory.Record.DeepAccountId, request.SenderDeviceId, U64(request.SenderSequence), U64(request.CreatedAtUnixMilliseconds),
            U64(request.ExpiresAtUnixMilliseconds), U16((ushort)request.Kind), request.CanonicalPayload };
        var record = (GroupApplicationMessageRecord)GroupCodec.CreateForAuthoring(ProtocolMagic.DGM1, fields);
        var roundTrip = (GroupApplicationMessageRecord)GroupCodec.Decode(ProtocolMagic.DGM1, record.CanonicalBytes.Span);
        if (!roundTrip.CanonicalBytes.Span.SequenceEqual(record.CanonicalBytes.Span)) Fail("round-trip-failed", "DGM1 did not round-trip exactly.");
        return new VerifiedGroupApplicationMessage(roundTrip, request.State, request.Sender);
    }

    private static async ValueTask<VerifiedGroupMembershipProposal> AuthorMembershipProposalAsync(
        VerifiedGroupTransition baseState, VerifiedContactBundleClosure proposer,
        ReadOnlyMemory<byte> proposerDeviceId, VerifiedContactBundleClosure target,
        ReadOnlyMemory<byte> proposalId, GroupProposalAction action, byte[] payload,
        ulong issuedAtUnixSeconds, ulong expiresAtUnixSeconds, GroupRole? newRole,
        IGroupDeviceCustodySigner signer, CancellationToken cancellationToken)
    {
        var commit = baseState.Commit;
        var proposerDevice = GroupCodec.RequireClosureDeviceForAuthoring(proposer, proposerDeviceId.Span);
        var fields = new ReadOnlyMemory<byte>[] { commit.Field(1), commit.Field(2), commit.Field(4),
            commit.ArtifactHash, proposalId, proposer.Directory.Record.DeepAccountId, proposerDeviceId,
            GroupCodec.ReferenceForAuthoring(ProtocolMagic.DPD1, proposerDevice.Certificate.CanonicalHash.Span),
            U16((ushort)action), payload, U64(issuedAtUnixSeconds), U64(expiresAtUnixSeconds), SignaturePlaceholder() };
        var record = (GroupProposalRecord)await GroupCodec.SignForAuthoringAsync(ProtocolMagic.DGP1,
            fields, 13, GroupDeviceSignaturePurpose.Proposal, proposer, proposerDeviceId, signer,
            cancellationToken).ConfigureAwait(false);
        return new VerifiedGroupMembershipProposal(record, baseState, proposer, target, action, newRole);
    }

    private static void RequireCurrent(VerifiedContactBundleClosure closure, ulong instant, ReadOnlySpan<byte> bootId, ulong monotonic)
    {
        if (instant < closure.Freshness.TrustedLowerUnixSeconds || instant > closure.Freshness.TrustedUpperUnixSeconds ||
            !closure.Freshness.IsCurrentAtMonotonic(bootId, monotonic)) Fail("directory-not-current", "Directory capability is not current at the authoring instant.");
    }
    private static void RequireSameNetwork(VerifiedContactBundleClosure left, VerifiedContactBundleClosure right)
    { if (!CryptographicOperations.FixedTimeEquals(left.Directory.Record.NetworkId.Span, right.Directory.Record.NetworkId.Span)) Fail("network-mismatch", "Verified directories belong to different networks."); }
    private static byte[] SignaturePlaceholder() { var value = new byte[64]; value[0] = 1; return value; }
    private static byte[] U16(ushort value) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    private static byte[] U32(uint value) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
    private static byte[] Join(params byte[][] values) { var result = new byte[checked(values.Sum(v => v.Length))]; var at = 0; foreach (var value in values) { value.CopyTo(result, at); at += value.Length; } return result; }
    private static void Fail(string code, string message) => throw new GroupAuthoringException(code, message);
}

public static partial class GroupCodec
{
    internal static GroupRecord CreateForAuthoring(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
        => CreateTaggedForAuthoring(magic, Enumerable.Range(1, fields.Count).ToArray(), fields);

    internal static GroupRecord CreateTaggedForAuthoring(string magic, IReadOnlyList<int> tags,
        IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        if (tags.Count != fields.Count) throw new ArgumentException("Tag and field counts must match.", nameof(tags));
        var size = checked(12 + fields.Sum(field => 8 + field.Length)); var bytes = new byte[size]; Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count)); var at = 12;
        for (var index = 0; index < fields.Count; index++) { BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(at), checked((ushort)tags[index])); BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(at + 4), checked((uint)fields[index].Length)); at += 8; fields[index].Span.CopyTo(bytes.AsSpan(at)); at += fields[index].Length; }
        try { return Decode(magic, bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static async ValueTask<GroupRecord> SignForAuthoringAsync(string magic, ReadOnlyMemory<byte>[] fields, int signatureTag,
        GroupDeviceSignaturePurpose purpose, VerifiedContactBundleClosure closure, ReadOnlyMemory<byte> deviceId,
        IGroupDeviceCustodySigner signer, CancellationToken cancellationToken)
    {
        var device = RequireClosureDeviceForAuthoring(closure, deviceId.Span); var signerId = signer.DeviceId.ToArray(); var signerKey = signer.Ed25519PublicKey.ToArray();
        var custody = signer.CustodyDomainHash.ToArray(); var signature = new byte[64]; GroupDeviceSigningRequest? signingRequest = null;
        try
        {
            if (signerId.Length != 32 || !CryptographicOperations.FixedTimeEquals(signerId, deviceId.Span) || signerKey.Length != 32 ||
                !CryptographicOperations.FixedTimeEquals(signerKey, device.Certificate.DeviceEd25519PublicKey.Span) || custody.Length != 32 || custody.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                throw new GroupAuthoringException("signer-binding-mismatch", "Custody signer does not match the exact verified active device.");
            var placeholder = CreateForAuthoring(magic, fields); signingRequest = new GroupDeviceSigningRequest(purpose, placeholder.FieldSpan(1), placeholder.FieldSpan(2),
                closure.Directory.Record.DeepAccountId.Span, deviceId.Span, custody, placeholder.SignatureInput.Span);
            int written;
            try { written = await signer.SignAsync(signingRequest, signature, cancellationToken).ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch (Exception exception) { throw new GroupAuthoringException("signer-failed", "Custody signer failed.", exception); }
            if (written != 64 || signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !PublicKeyAuth.VerifyDetached(signature, signingRequest.SigningInput.ToArray(), signerKey))
                throw new GroupAuthoringException("signature-invalid", "Custody signer did not return one valid Ed25519 signature.");
            fields[signatureTag - 1] = signature.ToArray(); var record = CreateForAuthoring(magic, fields);
            if (!PublicKeyAuth.VerifyDetached(record.FieldSpan(signatureTag).ToArray(), record.SignatureInput.ToArray(), signerKey) ||
                !record.CanonicalBytes.Span.SequenceEqual(Decode(magic, record.CanonicalBytes.Span).CanonicalBytes.Span))
                throw new GroupAuthoringException("round-trip-failed", "Signed group record failed exact verification or round-trip.");
            return record;
        }
        finally
        {
            signingRequest?.Clear(); CryptographicOperations.ZeroMemory(signature); CryptographicOperations.ZeroMemory(signerId);
            CryptographicOperations.ZeroMemory(signerKey); CryptographicOperations.ZeroMemory(custody);
        }
    }

    internal static VerifiedDevice RequireClosureDeviceForAuthoring(VerifiedContactBundleClosure closure, ReadOnlySpan<byte> deviceId)
    {
        foreach (var device in closure.Directory.Identity.ActiveDevices)
            if (device.Certificate.DeviceId.Span.SequenceEqual(deviceId)) return device;
        throw new GroupAuthoringException("device-not-active", "Device is not active in the exact verified directory.");
    }
    internal static byte[] ReferenceForAuthoring(string magic, ReadOnlySpan<byte> hash) => ReferenceBytes(magic, hash);
    internal static Member MemberFromDirectoryForAuthoring(VerifiedContactBundleClosure closure, GroupRole role) => MemberFromDirectory(new VerifiedAccountDirectory(closure), role);
    internal static byte[] SerializeMembersForAuthoring(IEnumerable<Member> members) => SerializeMembers(members);
    internal static List<Member> ReadMembersForAuthoring(GroupCommitRecord commit) => ReadMembers(commit.FieldSpan(12));
    internal static Member CloneMemberForAuthoring(Member member) => CloneMember(member);
    internal static void EnforceLimitsForAuthoring(List<Member> members) => EnforceGroupLimits(members);
    internal static byte[] MemberEntryHashForAuthoring(Member member) => SHA256.HashData(SerializeMember(member));

    internal static Member RequireMemberClosureForAuthoring(GroupCommitRecord commit, VerifiedContactBundleClosure closure)
    {
        var member = ReadMembers(commit.FieldSpan(12)).SingleOrDefault(value =>
            value.Account.AsSpan().SequenceEqual(closure.Directory.Record.DeepAccountId.Span));
        if (member is null || !SerializeMember(member).AsSpan().SequenceEqual(
                SerializeMember(MemberFromDirectoryForAuthoring(closure, member.Role))))
            throw new GroupAuthoringException("member-binding-mismatch",
                "Directory is not an exact active member of the base commit.");
        return member;
    }

    internal static void RequireMemberForAuthoring(GroupCommitRecord commit, VerifiedContactBundleClosure closure, ReadOnlySpan<byte> deviceId, bool requireAdministrator)
    {
        var member = ReadMembers(commit.FieldSpan(12)).SingleOrDefault(value => value.Account.AsSpan().SequenceEqual(closure.Directory.Record.DeepAccountId.Span));
        if (member is null || requireAdministrator && member.Role is not (GroupRole.Owner or GroupRole.Admin) ||
            !SerializeMember(member).AsSpan().SequenceEqual(SerializeMember(MemberFromDirectoryForAuthoring(closure, member.Role))) || FindDevice(member, deviceId) is null)
            throw new GroupAuthoringException("member-binding-mismatch", "Directory/device is not an exact active member of the base commit.");
    }

    internal static void RequireExactDirectorySetForAuthoring(IReadOnlyList<Member> members, IReadOnlyList<VerifiedContactBundleClosure> directories)
    {
        if (members.Count != directories.Count || directories.Select(value => Convert.ToHexString(value.Directory.Record.DeepAccountId.Span)).Distinct(StringComparer.Ordinal).Count() != directories.Count)
            throw new GroupAuthoringException("directory-set-mismatch", "Verified directory set is not exact for the commit members.");
        foreach (var member in members)
        {
            var closure = directories.SingleOrDefault(value => value.Directory.Record.DeepAccountId.Span.SequenceEqual(member.Account));
            if (closure is null || !SerializeMember(member).AsSpan().SequenceEqual(SerializeMember(MemberFromDirectoryForAuthoring(closure, member.Role))))
                throw new GroupAuthoringException("directory-set-mismatch", "Verified directory tuple differs from the exact member entry.");
        }
    }

    internal static void RequireExactDirectoryAccountSetForAuthoring(IReadOnlyList<Member> members,
        IReadOnlyList<VerifiedContactBundleClosure> directories)
    {
        var expected = members.Select(value => Convert.ToHexString(value.Account)).ToHashSet(StringComparer.Ordinal);
        var actual = directories.Select(value => Convert.ToHexString(value.Directory.Record.DeepAccountId.Span)).ToArray();
        if (actual.Length != expected.Count || actual.Distinct(StringComparer.Ordinal).Count() != actual.Length ||
            !expected.SetEquals(actual))
            throw new GroupAuthoringException("directory-set-mismatch",
                "Verified current directory accounts are not exact for the membership transition.");
    }

    internal sealed record AuthorSupport(ushort Kind, byte[] Reference, byte[] Bytes);
    internal static AuthorSupport[] SupportForAuthoring(IReadOnlyList<VerifiedContactBundleClosure> directories)
    {
        var values = new Dictionary<string, AuthorSupport>(StringComparer.Ordinal);
        foreach (var closure in directories)
        {
            var checkpoint = closure.Freshness.CurrentCheckpoint ?? throw new GroupAuthoringException("checkpoint-missing", "Current ADC1 checkpoint bytes are required for GCP1 closure.");
            Add(1, closure.Freshness.ExactAdc1Reference.Span, AccountDirectoryAdc1Codec.Encode(checkpoint.Checkpoint));
            Add(2, closure.Freshness.ExactAdh1CoreReference.Span, closure.Freshness.ExactAdh1.ToArray());
            Add(3, ReferenceBytes(ProtocolMagic.ADP1, closure.Freshness.ExactAdp1Hash.Span), closure.Freshness.ExactAdp1.ToArray());
            Add(4, ReferenceBytes(ProtocolMagic.DMD1, closure.Directory.Record.RecordHash.Span), closure.Directory.Record.CanonicalBytes.ToArray());
            Add(5, ReferenceBytes(ProtocolMagic.DRS1, closure.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span), closure.Directory.Identity.Revocations.Snapshot.CanonicalBytes.ToArray());
            foreach (var device in closure.Directory.Identity.ActiveDevices)
                Add(6, ReferenceBytes(ProtocolMagic.DPD1, device.Certificate.CanonicalHash.Span), device.Certificate.CanonicalBytes.ToArray());
        }
        return values.Values.OrderBy(value => value.Kind).ThenBy(value => value.Reference, AuthorByteComparer.Instance).ToArray();
        void Add(ushort kind, ReadOnlySpan<byte> reference, byte[] bytes)
        {
            var key = Convert.ToHexString(reference); if (values.TryGetValue(key, out var prior))
            { if (prior.Kind != kind || !prior.Bytes.AsSpan().SequenceEqual(bytes)) throw new GroupAuthoringException("support-fork", "One support reference resolved to changed bytes."); return; }
            values.Add(key, new AuthorSupport(kind, reference.ToArray(), bytes));
        }
    }

    internal static GroupCommitPackageRecord PackageForAuthoring(GroupCommitRecord commit, IReadOnlyList<GroupProposalRecord> proposals,
        IReadOnlyList<AuthorSupport> supports, IReadOnlyList<(GroupInvitationRecord Invitation, GroupInvitationAcceptanceRecord Acceptance)> pairs)
    {
        var orderedProposals = proposals.OrderBy(value => value.ArtifactHash.ToArray(), AuthorByteComparer.Instance).ToArray();
        var proposalBytes = JoinAuthor(orderedProposals.Select(value => LpAuthor(value.CanonicalBytes.Span)).ToArray());
        var supportParts = supports.OrderBy(value => value.Kind).ThenBy(value => value.Reference, AuthorByteComparer.Instance)
            .Select(value => JoinAuthor(U16Author(value.Kind), value.Reference, LpAuthor(value.Bytes))).ToArray();
        var orderedPairs = pairs.OrderBy(value => value.Invitation.Field(3).ToArray(), AuthorByteComparer.Instance).ToArray();
        var pairParts = orderedPairs.Select(value => JoinAuthor(ArtifactReference(ProtocolMagic.GIV1, value.Invitation).CanonicalBytes.ToArray(), LpAuthor(value.Invitation.CanonicalBytes.Span),
            ArtifactReference(ProtocolMagic.GIA1, value.Acceptance).CanonicalBytes.ToArray(), LpAuthor(value.Acceptance.CanonicalBytes.Span))).ToArray();
        return (GroupCommitPackageRecord)CreateForAuthoring(ProtocolMagic.GCP1, [commit.Field(1), commit.Field(2), commit.Field(4), LpAuthor(commit.CanonicalBytes.Span),
            U16Author(checked((ushort)orderedProposals.Length)), proposalBytes, U32Author(checked((uint)supports.Count)), JoinAuthor(supportParts),
            U16Author(checked((ushort)orderedPairs.Length)), JoinAuthor(pairParts), Array.Empty<byte>()]);
    }

    internal static VerifiedAuthoredGroupTransition VerifyAuthoredPackage(GroupCommitPackageRecord package, VerifiedGroupTransition? previous, GroupIdentityClosure identities)
    {
        var values = ReadSupport(package.FieldSpan(8), U32(package.FieldSpan(7))).ToDictionary(value => Convert.ToHexString(value.Reference.CanonicalBytes.Span), value => value.Bytes, StringComparer.Ordinal);
        var transition = VerifyCommitPackage(package, previous, identities, new AuthorResolver(values));
        if (!transition.BindsExactGcp1(package.CanonicalBytes.Span)) throw new GroupAuthoringException("package-binding-failed", "Verifier did not bind exact GCP1 bytes.");
        return new VerifiedAuthoredGroupTransition(package, transition);
    }
    private sealed class AuthorResolver(Dictionary<string, byte[]> values) : IGroupClosureResolver
    { public ReadOnlyMemory<byte>? Resolve(GroupArtifactReference reference) => values.TryGetValue(Convert.ToHexString(reference.CanonicalBytes.Span), out var value) ? value : null; }
    private sealed class AuthorByteComparer : IComparer<byte[]> { internal static readonly AuthorByteComparer Instance = new(); public int Compare(byte[]? x, byte[]? y) => x.AsSpan().SequenceCompareTo(y); }
    private static byte[] LpAuthor(ReadOnlySpan<byte> value) { var result = new byte[checked(value.Length + 4)]; BinaryPrimitives.WriteUInt32BigEndian(result, checked((uint)value.Length)); value.CopyTo(result.AsSpan(4)); return result; }
    private static byte[] U16Author(ushort value) { var result = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(result, value); return result; }
    private static byte[] U32Author(uint value) { var result = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(result, value); return result; }
    private static byte[] JoinAuthor(params byte[][] values) { var result = new byte[checked(values.Sum(value => value.Length))]; var at = 0; foreach (var value in values) { value.CopyTo(result, at); at += value.Length; } return result; }
}
