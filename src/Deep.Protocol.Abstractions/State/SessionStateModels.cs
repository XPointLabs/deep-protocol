namespace Deep.Protocol.Abstractions.State;

public enum OneToOneApprovalState
{
    Unknown,
    Pending,
    Approved,
    Rejected,
    Blocked
}

public enum OneToOneSessionEventKind
{
    LocalMessageSent,
    IncomingMessageReceived,
    MessageRequestApproved,
    MessageRequestRejected,
    ConversationBlocked,
    ConversationUnblocked
}

public sealed record OneToOneSessionEvent(
    OneToOneSessionEventKind Kind,
    DateTimeOffset Timestamp,
    string? PeerSessionId = null);

public sealed record OneToOneSessionState(
    string PeerSessionId,
    OneToOneApprovalState ApprovalState,
    DateTimeOffset? LastTransitionAt)
{
    public OneToOneSessionState Apply(OneToOneSessionEvent transition)
    {
        if (!string.IsNullOrWhiteSpace(transition.PeerSessionId) &&
            !StringComparer.OrdinalIgnoreCase.Equals(transition.PeerSessionId, PeerSessionId))
        {
            throw new InvalidOperationException("Transition peer does not match the session state peer.");
        }

        var next = transition.Kind switch
        {
            OneToOneSessionEventKind.LocalMessageSent when ApprovalState is OneToOneApprovalState.Unknown =>
                OneToOneApprovalState.Pending,
            OneToOneSessionEventKind.IncomingMessageReceived when ApprovalState is OneToOneApprovalState.Unknown =>
                OneToOneApprovalState.Pending,
            OneToOneSessionEventKind.MessageRequestApproved => OneToOneApprovalState.Approved,
            OneToOneSessionEventKind.MessageRequestRejected => OneToOneApprovalState.Rejected,
            OneToOneSessionEventKind.ConversationBlocked => OneToOneApprovalState.Blocked,
            OneToOneSessionEventKind.ConversationUnblocked when ApprovalState is OneToOneApprovalState.Blocked =>
                OneToOneApprovalState.Unknown,
            _ => ApprovalState
        };

        return this with
        {
            ApprovalState = next,
            LastTransitionAt = next == ApprovalState ? LastTransitionAt : transition.Timestamp
        };
    }
}

public enum GroupUpdateEventKind
{
    Invite,
    InfoChange,
    MemberChange,
    Promote,
    MemberLeft,
    InviteResponse,
    DeleteMemberContent,
    MemberLeftNotification
}

public sealed record GroupUpdateEvent(
    GroupUpdateEventKind Kind,
    IReadOnlyList<string> MemberSessionIds,
    ReadOnlyMemory<byte> AdminSignature,
    string? GroupSessionId = null,
    string? UpdatedName = null,
    uint? UpdatedExpirationSeconds = null,
    bool? IsApproved = null,
    bool? HistoryShared = null,
    IReadOnlyList<string>? MessageHashes = null,
    ReadOnlyMemory<byte>? MemberAuthData = null,
    ReadOnlyMemory<byte>? GroupIdentitySeed = null);

public enum SharedConfigMergeOutcome
{
    Applied,
    Duplicate,
    Stale,
    Invalid
}

public sealed record SharedConfigNamespaceEntry(
    int Kind,
    long SeqNo,
    ReadOnlyMemory<byte> Data,
    DateTimeOffset UpdatedAt);

public sealed record SharedConfigNamespaceState
{
    public IReadOnlyDictionary<int, SharedConfigNamespaceEntry> Namespaces { get; init; } =
        new Dictionary<int, SharedConfigNamespaceEntry>();
}

public sealed record SharedConfigNamespaceMergeResult(
    SharedConfigNamespaceState State,
    SharedConfigMergeOutcome Outcome,
    SharedConfigNamespaceEntry? AppliedEntry = null);

public sealed record SharedConfigEnvelope(
    int Kind,
    long SeqNo,
    ReadOnlyMemory<byte> Data);
