using System.Buffers.Binary;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.GroupV1;

namespace Deep.Protocol.ApplicationCore;

public static partial class ApplicationCoreCodec
{
    private static ReadOnlySpan<byte> DmcMagic => ProtocolMagicBytes.DMC2;
    private const uint CoreFlagMask = (uint)(Dmc2Flags.Silent | Dmc2Flags.Disappearing | Dmc2Flags.HighPriority);
    private const uint SessionCapabilityMask = (uint)(SessionInitCapabilities.TextCore |
        SessionInitCapabilities.DeviceControl | SessionInitCapabilities.AttachmentCodec);

    public static ParsedDmc2 DecodeDmc2(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[12];
        ApplicationCoreFormat.Preflight(canonical, DmcMagic, 12, 282, 33082, fields);
        Exact(fields, 16, 32, 32, 32, 32, 8, 8, 8, 2, 4, -1, -1);
        ApplicationCoreFormat.EitherLength(fields, 11, 0, 32);
        if (fields[11].Length > 32768 || canonical.Length != 282 + fields[10].Length + fields[11].Length)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength,
                "DMC2 reply and payload lengths do not match the exact total-size formula.");

        var network = Field(canonical, fields, 1);
        var logicalMessageId = Field(canonical, fields, 2);
        var conversationId = Field(canonical, fields, 3);
        var senderAccountId = Field(canonical, fields, 4);
        var senderDeviceId = Field(canonical, fields, 5);
        var sequence = U64(Field(canonical, fields, 6));
        var createdAt = U64(Field(canonical, fields, 7));
        var expiresAt = U64(Field(canonical, fields, 8));
        var kindValue = U16(Field(canonical, fields, 9));
        var flagsValue = BinaryPrimitives.ReadUInt32BigEndian(Field(canonical, fields, 10));
        var reply = Field(canonical, fields, 11);
        var payloadBytes = Field(canonical, fields, 12);

        ApplicationCoreFormat.NonZero(network, "DMC2 network ID");
        ApplicationCoreFormat.NonZero(logicalMessageId, "DMC2 logical message ID");
        ApplicationCoreFormat.NonZero(conversationId, "DMC2 conversation ID");
        ApplicationCoreFormat.NonZero(senderAccountId, "DMC2 sender account ID");
        ApplicationCoreFormat.NonZero(senderDeviceId, "DMC2 sender device ID");
        if (sequence == 0 || createdAt == 0)
            Invalid(ApplicationCoreRejection.InvalidGeneration,
                "DMC2 sequence and creation time start at one.");
        if (expiresAt != 0 && expiresAt <= createdAt)
            Invalid(ApplicationCoreRejection.InvalidTimeRange,
                "DMC2 expiry must be zero or later than creation.");
        if ((flagsValue & ~CoreFlagMask) != 0)
            Invalid(ApplicationCoreRejection.InvalidFlags, "DMC2 contains an unregistered flag.");
        if (!Enum.IsDefined(typeof(Dmc2ContentKind), kindValue))
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.TypedPayload,
                ApplicationCoreRejection.ReservedContentKind,
                "The DMC2 content kind is unknown, reserved, or owned by an inactive codec package.");

        var kind = (Dmc2ContentKind)kindValue;
        var flags = (Dmc2Flags)flagsValue;
        ValidateCommonKindRules(kind, flags, reply, createdAt, expiresAt);

        var owned = canonical.ToArray();
        var ownedNetwork = Field(owned, fields, 1);
        var ownedSenderAccount = Field(owned, fields, 4);
        var ownedSenderDevice = Field(owned, fields, 5);
        var payload = DecodePayload(kind, Field(owned, fields, 12), ownedNetwork, ownedSenderAccount, ownedSenderDevice);
        return new ParsedDmc2(owned, ownedNetwork, Field(owned, fields, 2), Field(owned, fields, 3),
            ownedSenderAccount, ownedSenderDevice, sequence, createdAt, expiresAt, flags,
            Field(owned, fields, 11), payload);
    }

    public static ParsedDmc2 AuthorDmc2(
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> logicalMessageId32,
        ReadOnlySpan<byte> conversationId32,
        ReadOnlySpan<byte> senderAccountId32,
        ReadOnlySpan<byte> senderDeviceId32,
        ulong senderClientSequence,
        ulong createdAtUnixMilliseconds,
        ulong expiresAtUnixMilliseconds,
        Dmc2Flags flags,
        ReadOnlySpan<byte> replyToLogicalMessageId,
        Dmc2Payload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if ((payload.Kind is Dmc2ContentKind.ContactHello or Dmc2ContentKind.ContactAccept or
            Dmc2ContentKind.ContactReject or Dmc2ContentKind.ContactRouteUpdate) && !ContactCodec.RuntimeActivation)
            throw new InvalidOperationException("CONTACT-CODEC-01 production emission is disabled until runtime activation.");
        if (payload is GroupDmc2Payload && !GroupCodec.RuntimeActivation)
            throw new InvalidOperationException("GROUP-CODEC-01 production emission is disabled until runtime activation.");
        return AuthorDmc2Core(networkId16, logicalMessageId32, conversationId32, senderAccountId32,
            senderDeviceId32, senderClientSequence, createdAtUnixMilliseconds, expiresAtUnixMilliseconds,
            flags, replyToLogicalMessageId, payload);
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static ParsedDmc2 AuthorDmc2ForValidation(
        ReadOnlySpan<byte> networkId16, ReadOnlySpan<byte> logicalMessageId32,
        ReadOnlySpan<byte> conversationId32, ReadOnlySpan<byte> senderAccountId32,
        ReadOnlySpan<byte> senderDeviceId32, ulong senderClientSequence,
        ulong createdAtUnixMilliseconds, ulong expiresAtUnixMilliseconds, Dmc2Flags flags,
        ReadOnlySpan<byte> replyToLogicalMessageId, Dmc2Payload payload) =>
        AuthorDmc2Core(networkId16, logicalMessageId32, conversationId32, senderAccountId32,
            senderDeviceId32, senderClientSequence, createdAtUnixMilliseconds, expiresAtUnixMilliseconds,
            flags, replyToLogicalMessageId, payload);
#endif

    private static ParsedDmc2 AuthorDmc2Core(
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> logicalMessageId32,
        ReadOnlySpan<byte> conversationId32,
        ReadOnlySpan<byte> senderAccountId32,
        ReadOnlySpan<byte> senderDeviceId32,
        ulong senderClientSequence,
        ulong createdAtUnixMilliseconds,
        ulong expiresAtUnixMilliseconds,
        Dmc2Flags flags,
        ReadOnlySpan<byte> replyToLogicalMessageId,
        Dmc2Payload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        RequireLength(networkId16, 16, "network ID");
        RequireLength(logicalMessageId32, 32, "logical message ID");
        RequireLength(conversationId32, 32, "conversation ID");
        RequireLength(senderAccountId32, 32, "sender account ID");
        RequireLength(senderDeviceId32, 32, "sender device ID");
        if (replyToLogicalMessageId.Length is not (0 or 32))
            Invalid(ApplicationCoreRejection.InvalidFieldLength, "The DMC2 reply ID must be empty or 32 bytes.");

        Span<byte> sequenceBytes = stackalloc byte[8];
        Span<byte> createdAtBytes = stackalloc byte[8];
        Span<byte> expiresAtBytes = stackalloc byte[8];
        Span<byte> kindBytes = stackalloc byte[2];
        Span<byte> flagsBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt64BigEndian(sequenceBytes, senderClientSequence);
        BinaryPrimitives.WriteUInt64BigEndian(createdAtBytes, createdAtUnixMilliseconds);
        BinaryPrimitives.WriteUInt64BigEndian(expiresAtBytes, expiresAtUnixMilliseconds);
        BinaryPrimitives.WriteUInt16BigEndian(kindBytes, (ushort)payload.Kind);
        BinaryPrimitives.WriteUInt32BigEndian(flagsBytes, (uint)flags);

        var canonical = AllocateRecord(12, networkId16.Length + logicalMessageId32.Length +
            conversationId32.Length + senderAccountId32.Length + senderDeviceId32.Length +
            sequenceBytes.Length + createdAtBytes.Length + expiresAtBytes.Length + kindBytes.Length +
            flagsBytes.Length + replyToLogicalMessageId.Length + payload.CanonicalSpan.Length);
        var writer = new ApplicationRecordWriter(canonical, DmcMagic, 12);
        writer.Write(1, networkId16);
        writer.Write(2, logicalMessageId32);
        writer.Write(3, conversationId32);
        writer.Write(4, senderAccountId32);
        writer.Write(5, senderDeviceId32);
        writer.Write(6, sequenceBytes);
        writer.Write(7, createdAtBytes);
        writer.Write(8, expiresAtBytes);
        writer.Write(9, kindBytes);
        writer.Write(10, flagsBytes);
        writer.Write(11, replyToLogicalMessageId);
        writer.Write(12, payload.CanonicalSpan);
        writer.Complete();
        return DecodeDmc2(canonical);
    }

    public static SessionInitDmc2Payload CreateSessionInitPayload(
        ReadOnlySpan<byte> handshakeNonce32,
        ParsedDmd1 senderDirectory,
        SessionInitCapabilities capabilities)
    {
        RequireLength(handshakeNonce32, 32, "handshake nonce");
        ArgumentNullException.ThrowIfNull(senderDirectory);
        var directory = senderDirectory.CanonicalSpan;
        var payload = new byte[checked(32 + 32 + 4 + directory.Length + 4)];
        handshakeNonce32.CopyTo(payload);
        senderDirectory.RecordHashSpan.CopyTo(payload.AsSpan(32, 32));
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(64, 4), checked((uint)directory.Length));
        directory.CopyTo(payload.AsSpan(68));
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(68 + directory.Length, 4), (uint)capabilities);
        return (SessionInitDmc2Payload)DecodePayload(Dmc2ContentKind.SessionInit, payload,
            senderDirectory.NetworkId.Span, senderDirectory.DeepAccountId.Span,
            senderDirectory.ActiveDevices[0].DeviceId.Span, validateSenderDevice: false);
    }

    public static MessageCreateDmc2Payload CreateMessageCreatePayload(string text)
    {
        var encoded = ApplicationCoreFormat.EncodeCanonicalText(text, 1, 16384, oneGrapheme: false);
        return new MessageCreateDmc2Payload(Lp16(encoded), text);
    }

    public static ContactHelloDmc2Payload CreateContactHelloPayload(
        ReadOnlySpan<byte> relationshipId32, ReadOnlySpan<byte> initiatorDab1Reference38,
        ReadOnlySpan<byte> initiatorDmd1Hash32, ReadOnlySpan<byte> safetyNumberHash32,
        ContactPolicy policy, ReadOnlySpan<byte> exactInitiatorInboundXur1)
    {
        EnsureContactEmissionAllowed();
        return CreateContactHelloPayloadCore(relationshipId32, initiatorDab1Reference38, initiatorDmd1Hash32,
            safetyNumberHash32, policy, exactInitiatorInboundXur1);
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static ContactHelloDmc2Payload CreateContactHelloPayloadForValidation(
        ReadOnlySpan<byte> relationshipId32, ReadOnlySpan<byte> initiatorDab1Reference38,
        ReadOnlySpan<byte> initiatorDmd1Hash32, ReadOnlySpan<byte> safetyNumberHash32,
        ContactPolicy policy, ReadOnlySpan<byte> exactInitiatorInboundXur1) =>
        CreateContactHelloPayloadCore(relationshipId32, initiatorDab1Reference38, initiatorDmd1Hash32,
            safetyNumberHash32, policy, exactInitiatorInboundXur1);
#endif

    private static ContactHelloDmc2Payload CreateContactHelloPayloadCore(
        ReadOnlySpan<byte> relationshipId32, ReadOnlySpan<byte> initiatorDab1Reference38,
        ReadOnlySpan<byte> initiatorDmd1Hash32, ReadOnlySpan<byte> safetyNumberHash32,
        ContactPolicy policy, ReadOnlySpan<byte> exactInitiatorInboundXur1)
    {
        RequireLength(relationshipId32, 32, "relationship ID"); RequireLength(initiatorDab1Reference38, 38, "DAB1 reference");
        RequireLength(initiatorDmd1Hash32, 32, "initiator DMD1 hash"); RequireLength(safetyNumberHash32, 32, "safety-number hash");
        RequireLength(exactInitiatorInboundXur1, 538, "inbound XUR1");
        var payload = new byte[678];
        relationshipId32.CopyTo(payload); initiatorDab1Reference38.CopyTo(payload.AsSpan(32));
        initiatorDmd1Hash32.CopyTo(payload.AsSpan(70)); safetyNumberHash32.CopyTo(payload.AsSpan(102));
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(134), (ushort)policy);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(136), checked((uint)exactInitiatorInboundXur1.Length));
        exactInitiatorInboundXur1.CopyTo(payload.AsSpan(140));
        return DecodeContactHello(payload);
    }

    public static ContactAcceptDmc2Payload CreateContactAcceptPayload(
        ReadOnlySpan<byte> relationshipId32, ReadOnlySpan<byte> contactHelloHash32,
        ReadOnlySpan<byte> responderDab1Reference38, ReadOnlySpan<byte> responderDmd1Hash32,
        ContactPolicy policy, ReadOnlySpan<byte> exactResponderInboundXur1)
    {
        EnsureContactEmissionAllowed();
        return CreateContactAcceptPayloadCore(relationshipId32, contactHelloHash32, responderDab1Reference38,
            responderDmd1Hash32, policy, exactResponderInboundXur1);
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static ContactAcceptDmc2Payload CreateContactAcceptPayloadForValidation(
        ReadOnlySpan<byte> relationshipId32, ReadOnlySpan<byte> contactHelloHash32,
        ReadOnlySpan<byte> responderDab1Reference38, ReadOnlySpan<byte> responderDmd1Hash32,
        ContactPolicy policy, ReadOnlySpan<byte> exactResponderInboundXur1) =>
        CreateContactAcceptPayloadCore(relationshipId32, contactHelloHash32, responderDab1Reference38,
            responderDmd1Hash32, policy, exactResponderInboundXur1);
#endif

    private static ContactAcceptDmc2Payload CreateContactAcceptPayloadCore(
        ReadOnlySpan<byte> relationshipId32, ReadOnlySpan<byte> contactHelloHash32,
        ReadOnlySpan<byte> responderDab1Reference38, ReadOnlySpan<byte> responderDmd1Hash32,
        ContactPolicy policy, ReadOnlySpan<byte> exactResponderInboundXur1)
    {
        RequireLength(relationshipId32, 32, "relationship ID"); RequireLength(contactHelloHash32, 32, "ContactHello hash");
        RequireLength(responderDab1Reference38, 38, "DAB1 reference"); RequireLength(responderDmd1Hash32, 32, "responder DMD1 hash");
        RequireLength(exactResponderInboundXur1, 538, "inbound XUR1");
        var payload = new byte[678];
        relationshipId32.CopyTo(payload); contactHelloHash32.CopyTo(payload.AsSpan(32));
        responderDab1Reference38.CopyTo(payload.AsSpan(64)); responderDmd1Hash32.CopyTo(payload.AsSpan(102));
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(134), (ushort)policy);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(136), checked((uint)exactResponderInboundXur1.Length));
        exactResponderInboundXur1.CopyTo(payload.AsSpan(140));
        return DecodeContactAccept(payload);
    }

    public static ContactRejectDmc2Payload CreateContactRejectPayload(ReadOnlySpan<byte> relationshipId32,
        ReadOnlySpan<byte> contactHelloHash32, ContactRejectReason reason)
    {
        EnsureContactEmissionAllowed();
        return CreateContactRejectPayloadCore(relationshipId32, contactHelloHash32, reason);
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static ContactRejectDmc2Payload CreateContactRejectPayloadForValidation(ReadOnlySpan<byte> relationshipId32,
        ReadOnlySpan<byte> contactHelloHash32, ContactRejectReason reason) =>
        CreateContactRejectPayloadCore(relationshipId32, contactHelloHash32, reason);
#endif

    private static ContactRejectDmc2Payload CreateContactRejectPayloadCore(ReadOnlySpan<byte> relationshipId32,
        ReadOnlySpan<byte> contactHelloHash32, ContactRejectReason reason)
    {
        RequireLength(relationshipId32, 32, "relationship ID"); RequireLength(contactHelloHash32, 32, "ContactHello hash");
        var payload = new byte[66]; relationshipId32.CopyTo(payload); contactHelloHash32.CopyTo(payload.AsSpan(32));
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(64), (ushort)reason);
        return DecodeContactReject(payload);
    }

    public static ContactRouteUpdateDmc2Payload CreateContactRouteUpdatePayload(
        ReadOnlySpan<byte> relationshipId32,
        ulong routeGeneration,
        ReadOnlySpan<byte> predecessorRouteUpdateHash32,
        ContactRecord xrr1,
        ContactRecord xra1,
        ContactRecord xrc1,
        ContactRecord xss1,
        ContactRecord pmt2,
        ContactRecord pms2)
    {
        EnsureContactEmissionAllowed();
        return CreateContactRouteUpdatePayloadCore(relationshipId32, routeGeneration, predecessorRouteUpdateHash32,
            xrr1, xra1, xrc1, xss1, pmt2, pms2);
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static ContactRouteUpdateDmc2Payload CreateContactRouteUpdatePayloadForValidation(
        ReadOnlySpan<byte> relationshipId32, ulong routeGeneration,
        ReadOnlySpan<byte> predecessorRouteUpdateHash32, ContactRecord xrr1, ContactRecord xra1,
        ContactRecord xrc1, ContactRecord xss1, ContactRecord pmt2, ContactRecord pms2) =>
        CreateContactRouteUpdatePayloadCore(relationshipId32, routeGeneration, predecessorRouteUpdateHash32,
            xrr1, xra1, xrc1, xss1, pmt2, pms2);
#endif

    private static ContactRouteUpdateDmc2Payload CreateContactRouteUpdatePayloadCore(
        ReadOnlySpan<byte> relationshipId32,
        ulong routeGeneration,
        ReadOnlySpan<byte> predecessorRouteUpdateHash32,
        ContactRecord xrr1,
        ContactRecord xra1,
        ContactRecord xrc1,
        ContactRecord xss1,
        ContactRecord pmt2,
        ContactRecord pms2)
    {
        RequireLength(relationshipId32, 32, "relationship ID");
        RequireLength(predecessorRouteUpdateHash32, 32, "predecessor route-update hash");
        ArgumentNullException.ThrowIfNull(xrr1); ArgumentNullException.ThrowIfNull(xra1);
        ArgumentNullException.ThrowIfNull(xrc1); ArgumentNullException.ThrowIfNull(xss1);
        ArgumentNullException.ThrowIfNull(pmt2); ArgumentNullException.ThrowIfNull(pms2);

        var records = new[] { xrr1, xra1, xrc1, xss1, pmt2, pms2 };
        var payload = new byte[checked(97 + records.Sum(record => record.CanonicalBytes.Length))];
        relationshipId32.CopyTo(payload);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(32, 8), routeGeneration);
        predecessorRouteUpdateHash32.CopyTo(payload.AsSpan(40, 32));
        payload[72] = 6;
        var offset = 73;
        foreach (var record in records)
        {
            var canonical = record.CanonicalBytes;
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(offset, 4), checked((uint)canonical.Length));
            canonical.Span.CopyTo(payload.AsSpan(offset + 4));
            offset += 4 + canonical.Length;
        }
        return DecodeContactRouteUpdate(payload, xrr1.Field(1).Span);
    }

    public static MessageEditDmc2Payload CreateMessageEditPayload(
        ReadOnlySpan<byte> targetLogicalMessageId32,
        string text)
    {
        RequireNonzeroId(targetLogicalMessageId32, "edit target");
        var encoded = ApplicationCoreFormat.EncodeCanonicalText(text, 0, 16384, oneGrapheme: false);
        var payload = new byte[checked(32 + 2 + encoded.Length)];
        targetLogicalMessageId32.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(32, 2), checked((ushort)encoded.Length));
        encoded.CopyTo(payload, 34);
        return new MessageEditDmc2Payload(payload, targetLogicalMessageId32, text);
    }

    public static MessageDeleteDmc2Payload CreateMessageDeletePayload(
        ReadOnlySpan<byte> targetLogicalMessageId32,
        MessageDeleteScope scope)
    {
        RequireNonzeroId(targetLogicalMessageId32, "delete target");
        if (scope is < MessageDeleteScope.LocalRequest or > MessageDeleteScope.ConversationTombstone)
            PayloadInvalid(ApplicationCoreRejection.InvalidEnum, "The message-delete scope is not registered.");
        var payload = new byte[33];
        targetLogicalMessageId32.CopyTo(payload);
        payload[32] = (byte)scope;
        return new MessageDeleteDmc2Payload(payload, targetLogicalMessageId32, scope);
    }

    public static ReactionSetDmc2Payload CreateReactionSetPayload(
        ReadOnlySpan<byte> targetLogicalMessageId32,
        ReactionOperation operation,
        string reaction)
    {
        RequireNonzeroId(targetLogicalMessageId32, "reaction target");
        if (operation is < ReactionOperation.Add or > ReactionOperation.Remove)
            PayloadInvalid(ApplicationCoreRejection.InvalidEnum, "The reaction operation is not registered.");
        var encoded = ApplicationCoreFormat.EncodeCanonicalText(reaction, 1, 32, oneGrapheme: true);
        var payload = new byte[checked(35 + encoded.Length)];
        targetLogicalMessageId32.CopyTo(payload);
        payload[32] = (byte)operation;
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(33, 2), checked((ushort)encoded.Length));
        encoded.CopyTo(payload, 35);
        return new ReactionSetDmc2Payload(payload, targetLogicalMessageId32, operation, reaction);
    }

    public static ReceiptDeliveredDmc2Payload CreateReceiptDeliveredPayload(
        IReadOnlyList<Dmc2DeliveryReceiptEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        if (entries.Count is < 1 or > 128)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "A delivery receipt contains 1 through 128 entries.");
        var payload = new byte[1 + 33 * entries.Count];
        payload[0] = checked((byte)entries.Count);
        ReadOnlySpan<byte> previous = default;
        for (var index = 0; index < entries.Count; index++)
        {
            ArgumentNullException.ThrowIfNull(entries[index]);
            var id = entries[index].Message.LogicalMessageIdSpan;
            if (!previous.IsEmpty && ApplicationCoreFormat.Compare(previous, id) >= 0)
                PayloadInvalid(ApplicationCoreRejection.InvalidOrdering,
                    "Delivery receipt IDs must be strictly sorted and unique.");
            id.CopyTo(payload.AsSpan(1 + 33 * index, 32));
            payload[1 + 33 * index + 32] = (byte)entries[index].Status;
            previous = id;
        }
        return DecodeReceiptDelivered(payload);
    }

    public static ReceiptReadDmc2Payload CreateReceiptReadPayload(
        IReadOnlyList<Dmc2LogicalMessageReference> messages)
    {
        ArgumentNullException.ThrowIfNull(messages);
        if (messages.Count is < 1 or > 128)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "A read receipt contains 1 through 128 IDs.");
        var payload = new byte[1 + 32 * messages.Count];
        payload[0] = checked((byte)messages.Count);
        ReadOnlySpan<byte> previous = default;
        for (var index = 0; index < messages.Count; index++)
        {
            ArgumentNullException.ThrowIfNull(messages[index]);
            var id = messages[index].LogicalMessageIdSpan;
            if (!previous.IsEmpty && ApplicationCoreFormat.Compare(previous, id) >= 0)
                PayloadInvalid(ApplicationCoreRejection.InvalidOrdering,
                    "Read receipt IDs must be strictly sorted and unique.");
            id.CopyTo(payload.AsSpan(1 + 32 * index, 32));
            previous = id;
        }
        return DecodeReceiptRead(payload);
    }

    public static TypingDmc2Payload CreateTypingPayload(TypingOperation operation, ReadOnlySpan<byte> activityId32)
    {
        if (operation is < TypingOperation.Start or > TypingOperation.Stop)
            PayloadInvalid(ApplicationCoreRejection.InvalidEnum, "The typing operation is not registered.");
        RequireNonzeroId(activityId32, "typing activity");
        var payload = new byte[33];
        payload[0] = (byte)operation;
        activityId32.CopyTo(payload.AsSpan(1));
        return new TypingDmc2Payload(payload, operation, activityId32);
    }

    public static DeviceListUpdateDmc2Payload CreateDeviceListUpdatePayload(ParsedDmd1 directory)
    {
        ArgumentNullException.ThrowIfNull(directory);
        return new DeviceListUpdateDmc2Payload(Lp32(directory.CanonicalSpan), directory);
    }

    public static DeviceRevocationDmc2Payload CreateDeviceRevocationPayload(
        RevocationSnapshot revocations,
        ParsedDmd1 directory)
    {
        ArgumentNullException.ThrowIfNull(revocations);
        ArgumentNullException.ThrowIfNull(directory);
        var drs = revocations.CanonicalBytes;
        var payloadLength = checked(4 + drs.Length + 4 + directory.CanonicalSpan.Length);
        if (payloadLength > 32768)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength,
                "The DRS1 and DMD1 pair exceeds the DMC2 payload bound.");
        var payload = new byte[payloadLength];
        BinaryPrimitives.WriteUInt32BigEndian(payload, checked((uint)drs.Length));
        drs.Span.CopyTo(payload.AsSpan(4));
        var dmdOffset = 4 + drs.Length;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(dmdOffset, 4), checked((uint)directory.CanonicalSpan.Length));
        directory.CanonicalSpan.CopyTo(payload.AsSpan(dmdOffset + 4));
        ValidateRevocationDirectoryPair(revocations, directory);
        return new DeviceRevocationDmc2Payload(payload, revocations, directory);
    }

    public static AttachmentOfferDmc2Payload CreateAttachmentOfferPayload(ParsedDam1 manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        return new AttachmentOfferDmc2Payload(Lp32(manifest.CanonicalSpan), manifest);
    }

    public static AttachmentCancelDmc2Payload CreateAttachmentCancelPayload(
        ReadOnlySpan<byte> objectId32,
        AttachmentCancelReason reason)
    {
        RequireNonzeroId(objectId32, "attachment object ID");
        if (reason is < AttachmentCancelReason.SenderCancelled or > AttachmentCancelReason.LocalPolicy)
            PayloadInvalid(ApplicationCoreRejection.InvalidEnum, "The attachment cancel reason is not registered.");
        var payload = new byte[34];
        objectId32.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(32), (ushort)reason);
        return new AttachmentCancelDmc2Payload(payload, objectId32, reason);
    }

    private static Dmc2Payload DecodePayload(
        Dmc2ContentKind kind,
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> senderAccount,
        ReadOnlySpan<byte> senderDevice,
        bool validateSenderDevice = true)
    {
        try
        {
        return kind switch
        {
            Dmc2ContentKind.GroupProposal or Dmc2ContentKind.GroupCommit or Dmc2ContentKind.GroupApplicationMessage or
            Dmc2ContentKind.GroupInvite or Dmc2ContentKind.GroupInvitationAcceptance or Dmc2ContentKind.GroupCommitChunk or
            Dmc2ContentKind.GroupEmergencySequencerTransfer => DecodeGroupPayload(kind, payload, network, senderAccount, senderDevice),
                Dmc2ContentKind.SessionInit => DecodeSessionInit(payload, network, senderAccount, senderDevice, validateSenderDevice),
                Dmc2ContentKind.ContactHello => DecodeContactHello(payload),
                Dmc2ContentKind.ContactAccept => DecodeContactAccept(payload),
                Dmc2ContentKind.ContactReject => DecodeContactReject(payload),
                Dmc2ContentKind.ContactRouteUpdate => DecodeContactRouteUpdate(payload, network),
                Dmc2ContentKind.MessageCreate => DecodeMessageCreate(payload),
                Dmc2ContentKind.MessageEdit => DecodeMessageEdit(payload),
                Dmc2ContentKind.MessageDelete => DecodeMessageDelete(payload),
                Dmc2ContentKind.ReactionSet => DecodeReactionSet(payload),
                Dmc2ContentKind.ReceiptDelivered => DecodeReceiptDelivered(payload),
                Dmc2ContentKind.ReceiptRead => DecodeReceiptRead(payload),
                Dmc2ContentKind.Typing => DecodeTyping(payload),
                Dmc2ContentKind.DeviceListUpdate => DecodeDeviceListUpdate(payload, network, senderAccount, senderDevice),
                Dmc2ContentKind.DeviceRevocation => DecodeDeviceRevocation(payload, network, senderAccount, senderDevice),
                Dmc2ContentKind.AttachmentOffer => DecodeAttachmentOffer(payload, network),
                Dmc2ContentKind.AttachmentCancel => DecodeAttachmentCancel(payload),
                _ => throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.TypedPayload,
                    ApplicationCoreRejection.ReservedContentKind, "The DMC2 kind is not active in APPLICATION-CORE-CODEC-01."),
            };
        }
        catch (ApplicationCoreFormatException)
        {
            throw;
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or OverflowException or RecordException)
        {
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.EmbeddedRecord,
                ApplicationCoreRejection.EmbeddedRecordRejected,
                "A nested DMC2 record is not canonical.", exception);
        }
    }

    private static GroupDmc2Payload DecodeGroupPayload(Dmc2ContentKind kind, ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> senderAccount, ReadOnlySpan<byte> senderDevice)
    {
        var group = GroupCodec.DecodeDmc2Payload(kind, payload);
        var record = group.Record;
        if (record.Magic is ProtocolMagic.DGP1 or ProtocolMagic.DGC1 or ProtocolMagic.DGM1 or ProtocolMagic.GIV1 or ProtocolMagic.GIA1 or ProtocolMagic.DGT1)
        {
            if (!record.Field(1).Span.SequenceEqual(network))
                PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch, "The group record network differs from DMC2.");
            var accountTag = record.Magic switch { ProtocolMagic.DGP1 => 6, ProtocolMagic.DGC1 => 6, ProtocolMagic.DGM1 => 6, ProtocolMagic.GIV1 => 6, ProtocolMagic.GIA1 => 5, _ => 0 };
            var deviceTag = record.Magic switch { ProtocolMagic.DGP1 => 7, ProtocolMagic.DGC1 => 7, ProtocolMagic.DGM1 => 7, ProtocolMagic.GIV1 => 7, ProtocolMagic.GIA1 => 6, _ => 0 };
            if (accountTag != 0 && (!record.Field(accountTag).Span.SequenceEqual(senderAccount) || !record.Field(deviceTag).Span.SequenceEqual(senderDevice)))
                PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch, "The group record author differs from authenticated DMC2 sender.");
        }
        return group;
    }

    private static SessionInitDmc2Payload DecodeSessionInit(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> senderAccount,
        ReadOnlySpan<byte> senderDevice,
        bool validateSenderDevice)
    {
        if (payload.Length < 498)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "SessionInit is shorter than one-device DMD1.");
        var nonce = payload[..32];
        var dmdHash = payload.Slice(32, 32);
        RequireNonzeroId(nonce, "handshake nonce");
        RequireNonzeroId(dmdHash, "sender DMD1 hash");
        var dmdLength = ReadLp32Length(payload, 64, 426, 1476, out var dmdStart);
        var capabilitiesOffset = checked(dmdStart + dmdLength);
        if (capabilitiesOffset != payload.Length - 4)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "SessionInit has trailing or truncated bytes.");
        var directory = DecodeEmbeddedDmd1(payload.Slice(dmdStart, dmdLength));
        if (!directory.RecordHashSpan.SequenceEqual(dmdHash))
            PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch, "SessionInit DMD1 hash does not match exact DMD1.");
        var capabilitiesValue = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(capabilitiesOffset, 4));
        if ((capabilitiesValue & ~SessionCapabilityMask) != 0 ||
            (capabilitiesValue & (uint)(SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl)) !=
            (uint)(SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl))
            PayloadInvalid(ApplicationCoreRejection.InvalidFlags,
                "SessionInit capabilities must include TextCore and DeviceControl and contain no unknown bits.");
        ValidateDirectoryIdentity(directory, network, senderAccount, senderDevice, validateSenderDevice);
        return new SessionInitDmc2Payload(payload.ToArray(), nonce, dmdHash, directory,
            (SessionInitCapabilities)capabilitiesValue);
    }

    private static ContactHelloDmc2Payload DecodeContactHello(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 678 || BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(136, 4)) != 538)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "ContactHello has a noncanonical payload length.");
        return new ContactHelloDmc2Payload(payload.ToArray(), NonzeroContact(payload[..32], "relationship ID"),
            DecodeContactDabReference(payload.Slice(32, 38)), NonzeroContact(payload.Slice(70, 32), "initiator DMD1 hash"),
            NonzeroContact(payload.Slice(102, 32), "safety-number hash"), DecodeContactPolicy(payload.Slice(134, 2)),
            DecodeContactInboundXur1(payload.Slice(140, 538)));
    }

    private static ContactAcceptDmc2Payload DecodeContactAccept(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 678 || BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(136, 4)) != 538)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "ContactAccept has a noncanonical payload length.");
        return new ContactAcceptDmc2Payload(payload.ToArray(), NonzeroContact(payload[..32], "relationship ID"),
            NonzeroContact(payload.Slice(32, 32), "ContactHello hash"), DecodeContactDabReference(payload.Slice(64, 38)),
            NonzeroContact(payload.Slice(102, 32), "responder DMD1 hash"), DecodeContactPolicy(payload.Slice(134, 2)),
            DecodeContactInboundXur1(payload.Slice(140, 538)));
    }

    private static ContactRejectDmc2Payload DecodeContactReject(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 66) PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "ContactReject must be exactly 66 bytes.");
        var reason = (ContactRejectReason)BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(64, 2));
        if (reason is < ContactRejectReason.UserDeclined or > ContactRejectReason.AlreadyActive)
            PayloadInvalid(ApplicationCoreRejection.InvalidEnum, "The ContactReject reason is not registered.");
        return new ContactRejectDmc2Payload(payload.ToArray(), NonzeroContact(payload[..32], "relationship ID"),
            NonzeroContact(payload.Slice(32, 32), "ContactHello hash"), reason);
    }

    private static ContactRouteUpdateDmc2Payload DecodeContactRouteUpdate(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> network)
    {
        if (payload.Length is < 4_215 or > 23_367 || payload[72] != 6)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "ContactRouteUpdate has a noncanonical closure count or total length.");
        var relationshipId = NonzeroContact(payload[..32], "relationship ID");
        var routeGeneration = BinaryPrimitives.ReadUInt64BigEndian(payload.Slice(32, 8));
        var predecessor = payload.Slice(40, 32);
        if ((routeGeneration == 0) != IsZeroContact(predecessor))
            PayloadInvalid(ApplicationCoreRejection.InvalidLineage, "ContactRouteUpdate predecessor does not match its generation.");

        var offset = 73;
        var xrr1 = DecodeContactRouteRecord(payload, ref offset, ProtocolMagic.XRR1, 643, 643);
        var xra1 = DecodeContactRouteRecord(payload, ref offset, ProtocolMagic.XRA1, 550, 550);
        var xrc1 = DecodeContactRouteRecord(payload, ref offset, ProtocolMagic.XRC1, 940, 4_012);
        var xss1 = DecodeContactRouteRecord(payload, ref offset, ProtocolMagic.XSS1, 643, 3_523);
        var pmt2 = DecodeContactRouteRecord(payload, ref offset, ProtocolMagic.PMT2, 842, 11_066);
        var pms2 = DecodeContactRouteRecord(payload, ref offset, ProtocolMagic.PMS2, 500, 3_476);
        if (offset != payload.Length)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "ContactRouteUpdate has trailing bytes.");

        if (!xrr1.Field(1).Span.SequenceEqual(network) || !xra1.Field(1).Span.SequenceEqual(network) ||
            !xrc1.Field(1).Span.SequenceEqual(network) || !xss1.Field(1).Span.SequenceEqual(network) ||
            !pmt2.Field(1).Span.SequenceEqual(network) || !pms2.Field(1).Span.SequenceEqual(network))
            PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch, "ContactRouteUpdate closure networks differ from DMC2.");
        if (BinaryPrimitives.ReadUInt64BigEndian(xrr1.Field(3).Span) != routeGeneration)
            PayloadInvalid(ApplicationCoreRejection.InvalidLineage, "ContactRouteUpdate generation differs from XRR1.");

        try { ContactCodec.ValidateRouteUpdateGraph(xrr1, xra1, xrc1, xss1, pmt2, pms2); }
        catch (ContactFormatException exception)
        {
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.EmbeddedRecord,
                ApplicationCoreRejection.CrossFieldMismatch, "ContactRouteUpdate closure is not one exact route/placement graph.", exception);
        }

        return new ContactRouteUpdateDmc2Payload(payload.ToArray(), relationshipId, routeGeneration, predecessor,
            xrr1, xra1, xrc1, xss1, pmt2, pms2);
    }

    private static ContactRecord DecodeContactRouteRecord(ReadOnlySpan<byte> payload, ref int offset, string expectedMagic, int minimum, int maximum)
    {
        var length = ReadLp32Length(payload, offset, minimum, maximum, out var valueOffset);
        offset = checked(valueOffset + length);
        try { return ContactCodec.Decode(expectedMagic, payload.Slice(valueOffset, length)); }
        catch (ContactFormatException exception)
        {
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.EmbeddedRecord,
                ApplicationCoreRejection.EmbeddedRecordRejected, "ContactRouteUpdate contains a noncanonical closure record.", exception);
        }
    }

    private static void RequireContactReference(ContactRecord source, int tag, ContactRecord expected)
    {
        if (!source.Field(tag).Span.SequenceEqual(ContactCodec.ArtifactReference(expected.Magic, expected).CanonicalBytes.Span))
            PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch, "ContactRouteUpdate closure reference does not match its embedded record.");
    }

    private static void RequireContactHash(ContactRecord source, int tag, ContactRecord expected)
    {
        if (!source.Field(tag).Span.SequenceEqual(expected.ArtifactHash.Span))
            PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch, "ContactRouteUpdate closure hash does not match its embedded record.");
    }

    private static void EnsureContactEmissionAllowed()
    {
        if (!ContactCodec.RuntimeActivation)
            throw new InvalidOperationException("CONTACT-CODEC-01 production emission is disabled until runtime activation.");
    }

    private static bool IsZeroContact(ReadOnlySpan<byte> value)
    {
        byte aggregate = 0;
        foreach (var item in value) aggregate |= item;
        return aggregate == 0;
    }

    private static ReadOnlySpan<byte> DecodeContactDabReference(ReadOnlySpan<byte> reference)
    {
        try { _ = ContactCodec.DecodeArtifactReference(reference, ProtocolMagic.DAB1); return reference; }
        catch (ContactFormatException exception) { throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.TypedPayload,
            ApplicationCoreRejection.InvalidReference, "Contact DAB1 reference is invalid.", exception); }
    }

    private static ReadOnlySpan<byte> DecodeContactInboundXur1(ReadOnlySpan<byte> canonical)
    {
        try
        {
            var record = ContactCodec.Decode(ProtocolMagic.XUR1, canonical);
            if (BinaryPrimitives.ReadUInt16BigEndian(record.Field(10).Span) != 0x0007)
                PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch,
                    "An inbound contact XUR1 must allow all three contact-control events.");
            return canonical;
        }
        catch (ContactFormatException exception) { throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.EmbeddedRecord,
            ApplicationCoreRejection.EmbeddedRecordRejected, "Contact inbound XUR1 is not canonical.", exception); }
    }

    private static ReadOnlySpan<byte> NonzeroContact(ReadOnlySpan<byte> value, string name)
    {
        ApplicationCoreFormat.NonZero(value, name); return value;
    }

    private static ContactPolicy DecodeContactPolicy(ReadOnlySpan<byte> value)
    {
        var policy = (ContactPolicy)BinaryPrimitives.ReadUInt16BigEndian(value);
        if ((policy & ~(ContactPolicy.ManualApproval | ContactPolicy.AllowRouteUpdates)) != 0)
            PayloadInvalid(ApplicationCoreRejection.InvalidFlags, "Contact policy contains an unregistered bit.");
        return policy;
    }

    private static MessageCreateDmc2Payload DecodeMessageCreate(ReadOnlySpan<byte> payload)
    {
        var textBytes = ReadLp16Exact(payload, 0, 1, 16384);
        return new MessageCreateDmc2Payload(payload.ToArray(),
            ApplicationCoreFormat.DecodeCanonicalText(textBytes, 1, 16384, oneGrapheme: false));
    }

    private static MessageEditDmc2Payload DecodeMessageEdit(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 34)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "MessageEdit is truncated.");
        var target = payload[..32];
        RequireNonzeroId(target, "edit target");
        var textBytes = ReadLp16Exact(payload, 32, 0, 16384);
        return new MessageEditDmc2Payload(payload.ToArray(), target,
            ApplicationCoreFormat.DecodeCanonicalText(textBytes, 0, 16384, oneGrapheme: false));
    }

    private static MessageDeleteDmc2Payload DecodeMessageDelete(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 33)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "MessageDelete must be exactly 33 bytes.");
        RequireNonzeroId(payload[..32], "delete target");
        var scope = (MessageDeleteScope)payload[32];
        if (scope is < MessageDeleteScope.LocalRequest or > MessageDeleteScope.ConversationTombstone)
            PayloadInvalid(ApplicationCoreRejection.InvalidEnum, "The message-delete scope is not registered.");
        return new MessageDeleteDmc2Payload(payload.ToArray(), payload[..32], scope);
    }

    private static ReactionSetDmc2Payload DecodeReactionSet(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 36)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "ReactionSet is truncated.");
        RequireNonzeroId(payload[..32], "reaction target");
        var operation = (ReactionOperation)payload[32];
        if (operation is < ReactionOperation.Add or > ReactionOperation.Remove)
            PayloadInvalid(ApplicationCoreRejection.InvalidEnum, "The reaction operation is not registered.");
        var reactionBytes = ReadLp16Exact(payload, 33, 1, 32);
        var reaction = ApplicationCoreFormat.DecodeCanonicalText(reactionBytes, 1, 32, oneGrapheme: true);
        return new ReactionSetDmc2Payload(payload.ToArray(), payload[..32], operation, reaction);
    }

    private static ReceiptDeliveredDmc2Payload DecodeReceiptDelivered(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 34 || payload[0] is < 1 or > 128 || payload.Length != 1 + 33 * payload[0])
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "ReceiptDelivered count and payload length disagree.");
        var entries = new Dmc2DeliveryReceiptEntry[payload[0]];
        ReadOnlySpan<byte> previous = default;
        for (var index = 0; index < entries.Length; index++)
        {
            var row = payload.Slice(1 + 33 * index, 33);
            RequireNonzeroId(row[..32], "delivery receipt ID");
            if (!previous.IsEmpty && ApplicationCoreFormat.Compare(previous, row[..32]) >= 0)
                PayloadInvalid(ApplicationCoreRejection.InvalidOrdering,
                    "Delivery receipt IDs must be strictly sorted and unique.");
            var status = (DeliveryReceiptStatus)row[32];
            if (status is < DeliveryReceiptStatus.StoreAccepted or > DeliveryReceiptStatus.TerminalRejected)
                PayloadInvalid(ApplicationCoreRejection.InvalidEnum, "The delivery receipt status is not registered.");
            entries[index] = new Dmc2DeliveryReceiptEntry(row[..32], status);
            previous = row[..32];
        }
        return new ReceiptDeliveredDmc2Payload(payload.ToArray(), entries);
    }

    private static ReceiptReadDmc2Payload DecodeReceiptRead(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 33 || payload[0] is < 1 or > 128 || payload.Length != 1 + 32 * payload[0])
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "ReceiptRead count and payload length disagree.");
        var messages = new Dmc2LogicalMessageReference[payload[0]];
        ReadOnlySpan<byte> previous = default;
        for (var index = 0; index < messages.Length; index++)
        {
            var id = payload.Slice(1 + 32 * index, 32);
            RequireNonzeroId(id, "read receipt ID");
            if (!previous.IsEmpty && ApplicationCoreFormat.Compare(previous, id) >= 0)
                PayloadInvalid(ApplicationCoreRejection.InvalidOrdering,
                    "Read receipt IDs must be strictly sorted and unique.");
            messages[index] = new Dmc2LogicalMessageReference(id);
            previous = id;
        }
        return new ReceiptReadDmc2Payload(payload.ToArray(), messages);
    }

    private static TypingDmc2Payload DecodeTyping(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 33)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "Typing must be exactly 33 bytes.");
        var operation = (TypingOperation)payload[0];
        if (operation is < TypingOperation.Start or > TypingOperation.Stop)
            PayloadInvalid(ApplicationCoreRejection.InvalidEnum, "The typing operation is not registered.");
        RequireNonzeroId(payload[1..], "typing activity");
        return new TypingDmc2Payload(payload.ToArray(), operation, payload[1..]);
    }

    private static DeviceListUpdateDmc2Payload DecodeDeviceListUpdate(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> senderAccount,
        ReadOnlySpan<byte> senderDevice)
    {
        var dmd = ReadLp32Exact(payload, 0, 426, 1476);
        var directory = DecodeEmbeddedDmd1(dmd);
        ValidateDirectoryIdentity(directory, network, senderAccount, senderDevice, validateSenderDevice: true);
        return new DeviceListUpdateDmc2Payload(payload.ToArray(), directory);
    }

    private static DeviceRevocationDmc2Payload DecodeDeviceRevocation(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> senderAccount,
        ReadOnlySpan<byte> senderDevice)
    {
        var drsLength = ReadLp32Length(payload, 0, 356, 32768, out var drsStart);
        var dmdPrefix = checked(drsStart + drsLength);
        if (dmdPrefix > payload.Length - 4)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "DeviceRevocation DMD1 prefix is truncated.");
        var dmdLength = ReadLp32Length(payload, dmdPrefix, 426, 1476, out var dmdStart);
        if (dmdStart + dmdLength != payload.Length)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "DeviceRevocation has trailing bytes.");
        var revocations = DecodeEmbeddedDrs1(payload.Slice(drsStart, drsLength));
        var directory = DecodeEmbeddedDmd1(payload.Slice(dmdStart, dmdLength));
        ValidateRevocationDirectoryPair(revocations, directory);
        ValidateDirectoryIdentity(directory, network, senderAccount, senderDevice, validateSenderDevice: true);
        return new DeviceRevocationDmc2Payload(payload.ToArray(), revocations, directory);
    }

    private static AttachmentOfferDmc2Payload DecodeAttachmentOffer(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> network)
    {
        var manifestBytes = ReadLp32Exact(payload, 0, 310, 4653);
        var manifest = DecodeDam1(manifestBytes);
        if (!manifest.NetworkId.Span.SequenceEqual(network))
            PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch,
                "Embedded DAM1 network differs from the authenticated DMC2 network.");
        return new AttachmentOfferDmc2Payload(payload.ToArray(), manifest);
    }

    private static AttachmentCancelDmc2Payload DecodeAttachmentCancel(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 34)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength,
                "AttachmentCancel must be exactly 34 bytes.");
        RequireNonzeroId(payload[..32], "attachment object ID");
        var reason = (AttachmentCancelReason)BinaryPrimitives.ReadUInt16BigEndian(payload[32..]);
        if (reason is < AttachmentCancelReason.SenderCancelled or > AttachmentCancelReason.LocalPolicy)
            PayloadInvalid(ApplicationCoreRejection.InvalidEnum,
                "The attachment cancel reason is not registered.");
        return new AttachmentCancelDmc2Payload(payload.ToArray(), payload[..32], reason);
    }

    private static void ValidateCommonKindRules(
        Dmc2ContentKind kind,
        Dmc2Flags flags,
        ReadOnlySpan<byte> reply,
        ulong createdAt,
        ulong expiresAt)
    {
        if (!reply.IsEmpty)
        {
            ApplicationCoreFormat.NonZero(reply, "DMC2 reply ID");
            if (kind is not (Dmc2ContentKind.MessageCreate or Dmc2ContentKind.AttachmentOffer))
                Invalid(ApplicationCoreRejection.InvalidFlags, "Only MessageCreate and AttachmentOffer may carry reply-to.");
        }
        switch (kind)
        {
            case Dmc2ContentKind.SessionInit:
                if (flags != Dmc2Flags.None)
                    Invalid(ApplicationCoreRejection.InvalidFlags, "SessionInit requires zero flags.");
                if (expiresAt == 0 || expiresAt - createdAt > 86_400_000)
                    Invalid(ApplicationCoreRejection.InvalidTimeRange,
                        "SessionInit requires expiry within 24 hours.");
                break;
            case Dmc2ContentKind.ContactHello:
            case Dmc2ContentKind.ContactAccept:
            case Dmc2ContentKind.ContactReject:
            case Dmc2ContentKind.ContactRouteUpdate:
                if (flags != Dmc2Flags.None || !reply.IsEmpty || expiresAt == 0 || expiresAt - createdAt > 604_800_000)
                    Invalid(ApplicationCoreRejection.InvalidFlags,
                        "Contact control events require zero flags/reply and expiry within seven days.");
                break;
            case Dmc2ContentKind.GroupProposal:
            case Dmc2ContentKind.GroupCommit:
            case Dmc2ContentKind.GroupInvite:
            case Dmc2ContentKind.GroupInvitationAcceptance:
            case Dmc2ContentKind.GroupCommitChunk:
            case Dmc2ContentKind.GroupEmergencySequencerTransfer:
                if (flags != Dmc2Flags.None || !reply.IsEmpty || expiresAt == 0 || expiresAt - createdAt > 604_800_000)
                    Invalid(ApplicationCoreRejection.InvalidFlags,
                        "Group control events require zero flags/reply and expiry within seven days.");
                break;
            case Dmc2ContentKind.GroupApplicationMessage:
                if (flags != Dmc2Flags.None || !reply.IsEmpty)
                    Invalid(ApplicationCoreRejection.InvalidFlags,
                        "Group application events require zero flags and no reply-to ID.");
                break;
            case Dmc2ContentKind.MessageCreate:
            case Dmc2ContentKind.AttachmentOffer:
                break;
            case Dmc2ContentKind.MessageEdit:
            case Dmc2ContentKind.MessageDelete:
            case Dmc2ContentKind.ReactionSet:
            case Dmc2ContentKind.ReceiptDelivered:
            case Dmc2ContentKind.ReceiptRead:
            case Dmc2ContentKind.DeviceListUpdate:
            case Dmc2ContentKind.DeviceRevocation:
                if (flags != Dmc2Flags.None)
                    Invalid(ApplicationCoreRejection.InvalidFlags, "This DMC2 kind requires zero flags.");
                break;
            case Dmc2ContentKind.Typing:
                if (flags != Dmc2Flags.Silent)
                    Invalid(ApplicationCoreRejection.InvalidFlags, "Typing requires exactly Silent.");
                if (expiresAt == 0 || expiresAt - createdAt > 120_000)
                    Invalid(ApplicationCoreRejection.InvalidTimeRange,
                        "Typing requires expiry within 120 seconds.");
                break;
            case Dmc2ContentKind.AttachmentCancel:
                if (flags != Dmc2Flags.Silent)
                    Invalid(ApplicationCoreRejection.InvalidFlags, "AttachmentCancel requires exactly Silent.");
                break;
            default:
                throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.TypedPayload,
                    ApplicationCoreRejection.ReservedContentKind, "The DMC2 kind is not active in the core package.");
        }
    }

    private static ParsedDmd1 DecodeEmbeddedDmd1(ReadOnlySpan<byte> canonical)
    {
        try
        {
            return DecodeDmd1(canonical);
        }
        catch (ApplicationCoreFormatException exception)
        {
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.EmbeddedRecord,
                ApplicationCoreRejection.EmbeddedRecordRejected,
                "Embedded DMD1 is not canonical.", exception);
        }
    }

    private static RevocationSnapshot DecodeEmbeddedDrs1(ReadOnlySpan<byte> canonical)
    {
        try
        {
            return IdentityCodec.DecodeRevocationSnapshot(canonical);
        }
        catch (RecordException exception)
        {
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.EmbeddedRecord,
                ApplicationCoreRejection.EmbeddedRecordRejected,
                "Embedded DRS1 is not canonical.", exception);
        }
    }

    private static void ValidateDirectoryIdentity(
        ParsedDmd1 directory,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> senderAccount,
        ReadOnlySpan<byte> senderDevice,
        bool validateSenderDevice)
    {
        if (!directory.NetworkId.Span.SequenceEqual(network) ||
            !directory.DeepAccountId.Span.SequenceEqual(senderAccount))
            PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch,
                "Embedded DMD1 network/account differs from authenticated DMC2 sender identity.");
        if (validateSenderDevice)
        {
            var found = false;
            foreach (var entry in directory.ActiveDevices)
            {
                if (entry.DeviceId.Span.SequenceEqual(senderDevice))
                {
                    found = true;
                    break;
                }
            }
            if (!found)
                PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch,
                    "The authenticated DMC2 sender device is not active in embedded DMD1.");
        }
    }

    private static void ValidateRevocationDirectoryPair(RevocationSnapshot revocations, ParsedDmd1 directory)
    {
        if (!revocations.NetworkId.Span.SequenceEqual(directory.NetworkId.Span) ||
            !revocations.AccountHash.Span.SequenceEqual(directory.DeepAccountId.Span) ||
            revocations.AccountGeneration != directory.AccountGeneration ||
            directory.Drs1Reference.TypeCode != (ushort)ArtifactType.Drs1 ||
            directory.Drs1Reference.CanonicalLength != revocations.CanonicalBytes.Length ||
            !directory.Drs1Reference.HashSpan.SequenceEqual(revocations.CanonicalHash.Span))
            PayloadInvalid(ApplicationCoreRejection.CrossFieldMismatch,
                "Embedded DRS1 and DMD1 do not form one exact account/revocation closure.");
    }

    private static byte[] Lp16(ReadOnlySpan<byte> value)
    {
        var output = new byte[checked(2 + value.Length)];
        BinaryPrimitives.WriteUInt16BigEndian(output, checked((ushort)value.Length));
        value.CopyTo(output.AsSpan(2));
        return output;
    }

    private static byte[] Lp32(ReadOnlySpan<byte> value)
    {
        var output = new byte[checked(4 + value.Length)];
        BinaryPrimitives.WriteUInt32BigEndian(output, checked((uint)value.Length));
        value.CopyTo(output.AsSpan(4));
        return output;
    }

    private static ReadOnlySpan<byte> ReadLp16Exact(ReadOnlySpan<byte> source, int prefixOffset, int minimum, int maximum)
    {
        if (prefixOffset < 0 || prefixOffset > source.Length - 2)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "An LP16 prefix is truncated.");
        var length = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(prefixOffset, 2));
        if (length < minimum || length > maximum || prefixOffset + 2 + length != source.Length)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "An LP16 value has a noncanonical length.");
        return source.Slice(prefixOffset + 2, length);
    }

    private static ReadOnlySpan<byte> ReadLp32Exact(ReadOnlySpan<byte> source, int prefixOffset, int minimum, int maximum)
    {
        var length = ReadLp32Length(source, prefixOffset, minimum, maximum, out var valueOffset);
        if (valueOffset + length != source.Length)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "An LP32 value has trailing bytes.");
        return source.Slice(valueOffset, length);
    }

    private static int ReadLp32Length(
        ReadOnlySpan<byte> source,
        int prefixOffset,
        int minimum,
        int maximum,
        out int valueOffset)
    {
        if (prefixOffset < 0 || prefixOffset > source.Length - 4)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "An LP32 prefix is truncated.");
        var encodedLength = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(prefixOffset, 4));
        if (encodedLength > int.MaxValue)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "An LP32 value exceeds the bounded decoder.");
        var length = checked((int)encodedLength);
        valueOffset = checked(prefixOffset + 4);
        if (length < minimum || length > maximum || length > source.Length - valueOffset)
            PayloadInvalid(ApplicationCoreRejection.InvalidFieldLength, "An LP32 value has a noncanonical length.");
        return length;
    }

    private static void RequireNonzeroId(ReadOnlySpan<byte> value, string name)
    {
        RequireLength(value, 32, name);
        ApplicationCoreFormat.NonZero(value, name);
    }

    private static void PayloadInvalid(ApplicationCoreRejection rejection, string message) =>
        throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.TypedPayload, rejection, message);
}
