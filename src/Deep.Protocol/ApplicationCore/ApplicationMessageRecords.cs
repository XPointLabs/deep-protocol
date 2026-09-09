using Deep.Protocol.DeepNative;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.ApplicationCore;

public enum Dmc2ContentKind : ushort
{
    SessionInit = 1,
    ContactHello = 2,
    ContactAccept = 3,
    ContactReject = 4,
    MessageCreate = 5,
    MessageEdit = 6,
    MessageDelete = 7,
    ReactionSet = 8,
    ReceiptDelivered = 9,
    ReceiptRead = 10,
    Typing = 11,
    DeviceListUpdate = 12,
    DeviceRevocation = 13,
    // The numeric allocation is frozen, but route emission remains fail-closed
    // until the conflicting XRA1/DMC2 closure sizes are corrected in the root SoT.
    ContactRouteUpdate = 14,
    GroupProposal = 15,
    GroupCommit = 16,
    GroupApplicationMessage = 17,
    AttachmentOffer = 18,
    AttachmentCancel = 19,
    GroupInvite = 26,
    GroupInvitationAcceptance = 27,
    GroupCommitChunk = 28,
    GroupEmergencySequencerTransfer = 29,
}

[Flags]
public enum Dmc2Flags : uint
{
    None = 0,
    Silent = 1 << 0,
    Disappearing = 1 << 1,
    HighPriority = 1 << 2,
}

[Flags]
public enum SessionInitCapabilities : uint
{
    None = 0,
    TextCore = 1 << 0,
    DeviceControl = 1 << 1,
    AttachmentCodec = 1 << 2,
}

public enum MessageDeleteScope : byte
{
    LocalRequest = 1,
    ConversationTombstone = 2,
}

public enum ReactionOperation : byte
{
    Add = 1,
    Remove = 2,
}

public enum DeliveryReceiptStatus : byte
{
    StoreAccepted = 1,
    Materialized = 2,
    Expired = 3,
    TerminalRejected = 4,
}

public enum TypingOperation : byte
{
    Start = 1,
    Stop = 2,
}

public enum AttachmentCancelReason : ushort
{
    SenderCancelled = 1,
    Superseded = 2,
    LocalPolicy = 3,
}

[Flags]
public enum ContactPolicy : ushort
{
    None = 0,
    ManualApproval = 1 << 0,
    AllowRouteUpdates = 1 << 1,
}

public enum ContactRejectReason : ushort
{
    UserDeclined = 1,
    Policy = 2,
    Expired = 3,
    AlreadyActive = 4,
}

public abstract class Dmc2Payload
{
    private readonly byte[] canonical;

    internal Dmc2Payload(Dmc2ContentKind kind, byte[] canonical)
    {
        Kind = kind;
        this.canonical = canonical;
    }

    public Dmc2ContentKind Kind { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    internal ReadOnlySpan<byte> CanonicalSpan => canonical;
}

public sealed class SessionInitDmc2Payload : Dmc2Payload
{
    private readonly byte[] handshakeNonce;
    private readonly byte[] senderDmd1Hash;

    internal SessionInitDmc2Payload(
        byte[] canonical,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> dmdHash,
        ParsedDmd1 directory,
        SessionInitCapabilities capabilities)
        : base(Dmc2ContentKind.SessionInit, canonical)
    {
        handshakeNonce = nonce.ToArray();
        senderDmd1Hash = dmdHash.ToArray();
        SenderDirectory = directory;
        Capabilities = capabilities;
    }

    public ReadOnlyMemory<byte> HandshakeNonce => handshakeNonce.ToArray();
    public ReadOnlyMemory<byte> SenderDmd1Hash => senderDmd1Hash.ToArray();
    public ParsedDmd1 SenderDirectory { get; }
    public SessionInitCapabilities Capabilities { get; }
}

public sealed class MessageCreateDmc2Payload : Dmc2Payload
{
    internal MessageCreateDmc2Payload(byte[] canonical, string text)
        : base(Dmc2ContentKind.MessageCreate, canonical) => Text = text;

    public string Text { get; }
}

public sealed class MessageEditDmc2Payload : Dmc2Payload
{
    private readonly byte[] target;

    internal MessageEditDmc2Payload(byte[] canonical, ReadOnlySpan<byte> targetLogicalMessageId, string text)
        : base(Dmc2ContentKind.MessageEdit, canonical)
    {
        target = targetLogicalMessageId.ToArray();
        Text = text;
    }

    public ReadOnlyMemory<byte> TargetLogicalMessageId => target.ToArray();
    public string Text { get; }
}

public sealed class MessageDeleteDmc2Payload : Dmc2Payload
{
    private readonly byte[] target;

    internal MessageDeleteDmc2Payload(
        byte[] canonical,
        ReadOnlySpan<byte> targetLogicalMessageId,
        MessageDeleteScope scope)
        : base(Dmc2ContentKind.MessageDelete, canonical)
    {
        target = targetLogicalMessageId.ToArray();
        Scope = scope;
    }

    public ReadOnlyMemory<byte> TargetLogicalMessageId => target.ToArray();
    public MessageDeleteScope Scope { get; }
}

public sealed class ReactionSetDmc2Payload : Dmc2Payload
{
    private readonly byte[] target;

    internal ReactionSetDmc2Payload(
        byte[] canonical,
        ReadOnlySpan<byte> targetLogicalMessageId,
        ReactionOperation operation,
        string reaction)
        : base(Dmc2ContentKind.ReactionSet, canonical)
    {
        target = targetLogicalMessageId.ToArray();
        Operation = operation;
        Reaction = reaction;
    }

    public ReadOnlyMemory<byte> TargetLogicalMessageId => target.ToArray();
    public ReactionOperation Operation { get; }
    public string Reaction { get; }
}

public sealed class Dmc2LogicalMessageReference
{
    private readonly byte[] logicalMessageId;

    public Dmc2LogicalMessageReference(ReadOnlySpan<byte> logicalMessageId)
    {
        if (logicalMessageId.Length != 32 || ApplicationCoreFormat.IsZero(logicalMessageId))
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.TypedPayload,
                ApplicationCoreRejection.ZeroForbidden, "A logical message reference must be a nonzero 32-byte ID.");
        this.logicalMessageId = logicalMessageId.ToArray();
    }

    public ReadOnlyMemory<byte> LogicalMessageId => logicalMessageId.ToArray();
    internal ReadOnlySpan<byte> LogicalMessageIdSpan => logicalMessageId;
}

public sealed class Dmc2DeliveryReceiptEntry
{
    public Dmc2DeliveryReceiptEntry(ReadOnlySpan<byte> logicalMessageId, DeliveryReceiptStatus status)
    {
        Message = new Dmc2LogicalMessageReference(logicalMessageId);
        if (status is < DeliveryReceiptStatus.StoreAccepted or > DeliveryReceiptStatus.TerminalRejected)
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.TypedPayload,
                ApplicationCoreRejection.InvalidEnum, "The delivery receipt status is not registered.");
        Status = status;
    }

    public Dmc2LogicalMessageReference Message { get; }
    public DeliveryReceiptStatus Status { get; }
}

public sealed class ReceiptDeliveredDmc2Payload : Dmc2Payload
{
    private readonly Dmc2DeliveryReceiptEntry[] entries;

    internal ReceiptDeliveredDmc2Payload(byte[] canonical, Dmc2DeliveryReceiptEntry[] entries)
        : base(Dmc2ContentKind.ReceiptDelivered, canonical) => this.entries = entries;

    public IReadOnlyList<Dmc2DeliveryReceiptEntry> Entries => Array.AsReadOnly(entries.ToArray());
}

public sealed class ReceiptReadDmc2Payload : Dmc2Payload
{
    private readonly Dmc2LogicalMessageReference[] messages;

    internal ReceiptReadDmc2Payload(byte[] canonical, Dmc2LogicalMessageReference[] messages)
        : base(Dmc2ContentKind.ReceiptRead, canonical) => this.messages = messages;

    public IReadOnlyList<Dmc2LogicalMessageReference> Messages => Array.AsReadOnly(messages.ToArray());
}

public sealed class TypingDmc2Payload : Dmc2Payload
{
    private readonly byte[] activityId;

    internal TypingDmc2Payload(byte[] canonical, TypingOperation operation, ReadOnlySpan<byte> activityId)
        : base(Dmc2ContentKind.Typing, canonical)
    {
        Operation = operation;
        this.activityId = activityId.ToArray();
    }

    public TypingOperation Operation { get; }
    public ReadOnlyMemory<byte> ActivityId => activityId.ToArray();
}

public sealed class DeviceListUpdateDmc2Payload : Dmc2Payload
{
    internal DeviceListUpdateDmc2Payload(byte[] canonical, ParsedDmd1 directory)
        : base(Dmc2ContentKind.DeviceListUpdate, canonical) => Directory = directory;

    public ParsedDmd1 Directory { get; }
}

public sealed class DeviceRevocationDmc2Payload : Dmc2Payload
{
    internal DeviceRevocationDmc2Payload(
        byte[] canonical,
        RevocationSnapshot revocations,
        ParsedDmd1 directory)
        : base(Dmc2ContentKind.DeviceRevocation, canonical)
    {
        Revocations = revocations;
        Directory = directory;
    }

    public RevocationSnapshot Revocations { get; }
    public ParsedDmd1 Directory { get; }
}

public sealed class AttachmentOfferDmc2Payload : Dmc2Payload
{
    internal AttachmentOfferDmc2Payload(byte[] canonical, ParsedDam1 manifest)
        : base(Dmc2ContentKind.AttachmentOffer, canonical) => Manifest = manifest;

    public ParsedDam1 Manifest { get; }
}

public sealed class AttachmentCancelDmc2Payload : Dmc2Payload
{
    private readonly byte[] objectId;

    internal AttachmentCancelDmc2Payload(
        byte[] canonical,
        ReadOnlySpan<byte> objectId,
        AttachmentCancelReason reason)
        : base(Dmc2ContentKind.AttachmentCancel, canonical)
    {
        this.objectId = objectId.ToArray();
        Reason = reason;
    }

    public ReadOnlyMemory<byte> ObjectId => objectId.ToArray();
    public AttachmentCancelReason Reason { get; }
}

public sealed class ContactRouteUpdateDmc2Payload : Dmc2Payload
{
    private readonly byte[] relationshipId;
    private readonly byte[] predecessorRouteUpdateHash;

    internal ContactRouteUpdateDmc2Payload(
        byte[] canonical,
        ReadOnlySpan<byte> relationshipId,
        ulong routeGeneration,
        ReadOnlySpan<byte> predecessorRouteUpdateHash,
        ContactRecord reachability,
        ContactRecord authorization,
        ContactRecord route,
        ContactRecord successor,
        ContactRecord mailboxProjection,
        ContactRecord mailboxSelection)
        : base(Dmc2ContentKind.ContactRouteUpdate, canonical)
    {
        this.relationshipId = relationshipId.ToArray();
        RouteGeneration = routeGeneration;
        this.predecessorRouteUpdateHash = predecessorRouteUpdateHash.ToArray();
        Reachability = reachability;
        Authorization = authorization;
        Route = route;
        Successor = successor;
        MailboxProjection = mailboxProjection;
        MailboxSelection = mailboxSelection;
    }

    public ReadOnlyMemory<byte> RelationshipId => relationshipId.ToArray();
    public ulong RouteGeneration { get; }
    public ReadOnlyMemory<byte> PredecessorRouteUpdateHash => predecessorRouteUpdateHash.ToArray();
    public ContactRecord Reachability { get; }
    public ContactRecord Authorization { get; }
    public ContactRecord Route { get; }
    public ContactRecord Successor { get; }
    public ContactRecord MailboxProjection { get; }
    public ContactRecord MailboxSelection { get; }
}

public sealed class ContactHelloDmc2Payload : Dmc2Payload
{
    private readonly byte[] relationshipId; private readonly byte[] dab1Reference; private readonly byte[] dmd1Hash; private readonly byte[] safetyNumberHash; private readonly byte[] inboundXur1;
    internal ContactHelloDmc2Payload(byte[] canonical, ReadOnlySpan<byte> relationshipId, ReadOnlySpan<byte> dab1Reference, ReadOnlySpan<byte> dmd1Hash, ReadOnlySpan<byte> safetyNumberHash, ContactPolicy policy, ReadOnlySpan<byte> inboundXur1) : base(Dmc2ContentKind.ContactHello, canonical) { this.relationshipId=relationshipId.ToArray(); this.dab1Reference=dab1Reference.ToArray(); this.dmd1Hash=dmd1Hash.ToArray(); this.safetyNumberHash=safetyNumberHash.ToArray(); Policy=policy; this.inboundXur1=inboundXur1.ToArray(); }
    public ReadOnlyMemory<byte> RelationshipId => relationshipId.ToArray(); public ReadOnlyMemory<byte> InitiatorDab1Reference => dab1Reference.ToArray(); public ReadOnlyMemory<byte> InitiatorDmd1Hash => dmd1Hash.ToArray(); public ReadOnlyMemory<byte> SafetyNumberHash => safetyNumberHash.ToArray(); public ContactPolicy Policy { get; } public ReadOnlyMemory<byte> InboundXur1 => inboundXur1.ToArray();
}

public sealed class ContactAcceptDmc2Payload : Dmc2Payload
{
    private readonly byte[] relationshipId; private readonly byte[] helloHash; private readonly byte[] dab1Reference; private readonly byte[] dmd1Hash; private readonly byte[] inboundXur1;
    internal ContactAcceptDmc2Payload(byte[] canonical, ReadOnlySpan<byte> relationshipId, ReadOnlySpan<byte> helloHash, ReadOnlySpan<byte> dab1Reference, ReadOnlySpan<byte> dmd1Hash, ContactPolicy policy, ReadOnlySpan<byte> inboundXur1) : base(Dmc2ContentKind.ContactAccept, canonical) { this.relationshipId=relationshipId.ToArray(); this.helloHash=helloHash.ToArray(); this.dab1Reference=dab1Reference.ToArray(); this.dmd1Hash=dmd1Hash.ToArray(); Policy=policy; this.inboundXur1=inboundXur1.ToArray(); }
    public ReadOnlyMemory<byte> RelationshipId => relationshipId.ToArray(); public ReadOnlyMemory<byte> ContactHelloHash => helloHash.ToArray(); public ReadOnlyMemory<byte> ResponderDab1Reference => dab1Reference.ToArray(); public ReadOnlyMemory<byte> ResponderDmd1Hash => dmd1Hash.ToArray(); public ContactPolicy Policy { get; } public ReadOnlyMemory<byte> InboundXur1 => inboundXur1.ToArray();
}

public sealed class ContactRejectDmc2Payload : Dmc2Payload
{
    private readonly byte[] relationshipId; private readonly byte[] helloHash;
    internal ContactRejectDmc2Payload(byte[] canonical, ReadOnlySpan<byte> relationshipId, ReadOnlySpan<byte> helloHash, ContactRejectReason reason) : base(Dmc2ContentKind.ContactReject, canonical) { this.relationshipId=relationshipId.ToArray(); this.helloHash=helloHash.ToArray(); Reason=reason; }
    public ReadOnlyMemory<byte> RelationshipId => relationshipId.ToArray(); public ReadOnlyMemory<byte> ContactHelloHash => helloHash.ToArray(); public ContactRejectReason Reason { get; }
}

public sealed class ParsedDmc2 : ParsedApplicationCoreRecord
{
    private readonly byte[] networkId;
    private readonly byte[] logicalMessageId;
    private readonly byte[] conversationId;
    private readonly byte[] senderAccountId;
    private readonly byte[] senderDeviceId;
    private readonly byte[] replyToLogicalMessageId;
    private readonly byte[] payloadBytes;

    internal ParsedDmc2(
        byte[] canonical,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> logicalMessageId,
        ReadOnlySpan<byte> conversationId,
        ReadOnlySpan<byte> senderAccountId,
        ReadOnlySpan<byte> senderDeviceId,
        ulong senderClientSequence,
        ulong createdAtUnixMilliseconds,
        ulong expiresAtUnixMilliseconds,
        Dmc2Flags flags,
        ReadOnlySpan<byte> replyToLogicalMessageId,
        Dmc2Payload payload)
        : base(ProtocolMagic.DMC2, canonical)
    {
        this.networkId = networkId.ToArray();
        this.logicalMessageId = logicalMessageId.ToArray();
        this.conversationId = conversationId.ToArray();
        this.senderAccountId = senderAccountId.ToArray();
        this.senderDeviceId = senderDeviceId.ToArray();
        SenderClientSequence = senderClientSequence;
        CreatedAtUnixMilliseconds = createdAtUnixMilliseconds;
        ExpiresAtUnixMilliseconds = expiresAtUnixMilliseconds;
        Flags = flags;
        this.replyToLogicalMessageId = replyToLogicalMessageId.ToArray();
        ParsedPayload = payload;
        payloadBytes = payload.CanonicalSpan.ToArray();
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> LogicalMessageId => logicalMessageId.ToArray();
    public ReadOnlyMemory<byte> ConversationId => conversationId.ToArray();
    public ReadOnlyMemory<byte> SenderAccountId => senderAccountId.ToArray();
    public ReadOnlyMemory<byte> SenderDeviceId => senderDeviceId.ToArray();
    public ulong SenderClientSequence { get; }
    public ulong CreatedAtUnixMilliseconds { get; }
    public ulong ExpiresAtUnixMilliseconds { get; }
    public Dmc2ContentKind ContentKind => ParsedPayload.Kind;
    public Dmc2Flags Flags { get; }
    public ReadOnlyMemory<byte> ReplyToLogicalMessageId => replyToLogicalMessageId.ToArray();
    public ReadOnlyMemory<byte> PayloadBytes => payloadBytes.ToArray();
    internal Dmc2Payload ParsedPayload { get; }
}
