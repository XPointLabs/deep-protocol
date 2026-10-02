using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.ApplicationCore;

public static partial class ApplicationCoreCodec
{
    /// <summary>Current DID2 endpoint-bound author, not DPH2, placement,
    /// acceptance, session, materialization or ACK authority.</summary>
    public static async ValueTask<AuthoredVerifiedContactHello> AuthorVerifiedContactHelloAsync(
        VerifiedDeepIdV2ContactUpdateRendezvous inboundRendezvous,
        ParsedDeepIdV2ContactMailboxRoute initiatorMailboxRoute,
        VerifiedDeepIdV2DirectoryFreshness recipientFreshness,
        ReadOnlyMemory<byte> relationshipId32, ReadOnlyMemory<byte> logicalMessageId32,
        ReadOnlyMemory<byte> conversationId32, ulong createdAtUnixMilliseconds,
        ulong expiresAtUnixMilliseconds, OnionTrustedTimeAuthority trustedTime,
        ContactPolicy policy = ContactPolicy.AllowRouteUpdates,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inboundRendezvous);
        ArgumentNullException.ThrowIfNull(initiatorMailboxRoute);
        ArgumentNullException.ThrowIfNull(recipientFreshness);
        ArgumentNullException.ThrowIfNull(trustedTime);
        cancellationToken.ThrowIfCancellationRequested();
        // Bound and own all caller-supplied bytes before the first await.
        RequireNonzeroId(relationshipId32.Span, "relationship ID");
        RequireNonzeroId(logicalMessageId32.Span, "logical message ID");
        RequireNonzeroId(conversationId32.Span, "conversation ID");
        var relationship = relationshipId32.ToArray();
        var logical = logicalMessageId32.ToArray();
        var conversation = conversationId32.ToArray();
        var first = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var sender = ContactControlEndpointV2.RequirePair(
            inboundRendezvous.Freshness, recipientFreshness, first);
        inboundRendezvous.RequireCurrentAt(first);
        var safety = ContactControlEndpointV2.Safety(sender, recipientFreshness.CurrentCheckpoint!);
        ParsedDmc2 record;
        try
        {
            var payload = CreateContactHelloPayloadCore(relationship,
                new ContactArtifactReference(ProtocolMagic.DAB2, 2,
                    sender.Binding.Record.RecordHash.Span).CanonicalBytes.Span,
                sender.Directory.Record.RecordHash.Span, safety, policy,
                inboundRendezvous.ExactXur1.Span, initiatorMailboxRoute.ExactBytes.Span);
            record = AuthorDmc2Core(sender.Checkpoint.NetworkId.Span, logical, conversation,
                sender.Binding.Record.DeepAccountId.Span, inboundRendezvous.Record.FieldSpan(13),
                2, createdAtUnixMilliseconds, expiresAtUnixMilliseconds, Dmc2Flags.None, [], payload);
            ContactControlEndpointV2.RequireHello(record, sender, recipientFreshness.CurrentCheckpoint!,
                inboundRendezvous.Record);
        }
        finally { CryptographicOperations.ZeroMemory(safety); }
        var final = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        ContactControlEndpointV2.RequireContinuous(first, final);
        _ = ContactControlEndpointV2.RequirePair(inboundRendezvous.Freshness, recipientFreshness, final);
        inboundRendezvous.RequireCurrentAt(final);
        return new AuthoredVerifiedContactHello(record);
    }

    /// <summary>Endpoint-bound response author. The runtime must independently
    /// authenticate and retain the exact pending Hello before local acceptance.</summary>
    public static async ValueTask<AuthoredVerifiedContactAccept> AuthorVerifiedContactAcceptAsync(
        ParsedDmc2 hello, VerifiedDeepIdV2DirectoryFreshness initiatorFreshness,
        VerifiedDeepIdV2ContactUpdateRendezvous responderRendezvous,
        ParsedDeepIdV2ContactMailboxRoute responderMailboxRoute,
        ReadOnlyMemory<byte> logicalMessageId32, ulong senderClientSequence,
        ulong createdAtUnixMilliseconds, ulong expiresAtUnixMilliseconds,
        OnionTrustedTimeAuthority trustedTime, ContactPolicy policy = ContactPolicy.AllowRouteUpdates,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(hello);
        ArgumentNullException.ThrowIfNull(initiatorFreshness);
        ArgumentNullException.ThrowIfNull(responderRendezvous);
        ArgumentNullException.ThrowIfNull(responderMailboxRoute);
        ArgumentNullException.ThrowIfNull(trustedTime);
        cancellationToken.ThrowIfCancellationRequested();
        RequireNonzeroId(logicalMessageId32.Span, "logical message ID");
        var logical = logicalMessageId32.ToArray();
        var first = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var responder = ContactControlEndpointV2.RequirePair(responderRendezvous.Freshness,
            initiatorFreshness, first);
        responderRendezvous.RequireCurrentAt(first);
        var request = hello.ParsedPayload as ContactHelloDmc2Payload ??
            throw new CryptographicException("The pending event is not ContactHello.");
        var payload = CreateContactAcceptPayloadCore(request.RelationshipId.Span,
            SHA256.HashData(hello.CanonicalBytes.Span),
            new ContactArtifactReference(ProtocolMagic.DAB2, 2, responder.Binding.Record.RecordHash.Span).CanonicalBytes.Span,
            responder.Directory.Record.RecordHash.Span, policy, responderRendezvous.ExactXur1.Span, responderMailboxRoute.ExactBytes.Span);
        var record = AuthorDmc2Core(responder.Checkpoint.NetworkId.Span, logical, hello.ConversationId.Span,
            responder.Binding.Record.DeepAccountId.Span, responderRendezvous.Record.FieldSpan(13),
            senderClientSequence, createdAtUnixMilliseconds, expiresAtUnixMilliseconds, Dmc2Flags.None, [], payload);
        ContactControlEndpointV2.RequireAccept(record, hello, initiatorFreshness.CurrentCheckpoint!, responder,
            responderRendezvous.Record);
        var final = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        ContactControlEndpointV2.RequireContinuous(first, final);
        _ = ContactControlEndpointV2.RequirePair(responderRendezvous.Freshness, initiatorFreshness, final);
        responderRendezvous.RequireCurrentAt(final);
        return new AuthoredVerifiedContactAccept(record);
    }
}

public static partial class ApplicationCoreVerifier
{
    /// <summary>Normative key-free contact conversation identifier. This
    /// derives an identifier only, never endpoint or contact authority.</summary>
    public static byte[] ComputeContactConversationId(ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> relationshipId32, ReadOnlySpan<byte> accountA32, ReadOnlySpan<byte> accountB32)
    {
        if (networkId16.Length != 16 || networkId16.IndexOfAnyExcept((byte)0) < 0 ||
            relationshipId32.Length != 32 || relationshipId32.IndexOfAnyExcept((byte)0) < 0 ||
            accountA32.Length != 32 || accountA32.IndexOfAnyExcept((byte)0) < 0 ||
            accountB32.Length != 32 || accountB32.IndexOfAnyExcept((byte)0) < 0 || accountA32.SequenceEqual(accountB32))
            throw new ArgumentException("Contact conversation derivation requires exact network, relationship and distinct accounts.");
        Span<byte> material = stackalloc byte[112];
        networkId16.CopyTo(material); relationshipId32.CopyTo(material[16..]);
        var first = accountA32.SequenceCompareTo(accountB32) < 0 ? accountA32 : accountB32;
        var second = accountA32.SequenceCompareTo(accountB32) < 0 ? accountB32 : accountA32;
        first.CopyTo(material[48..]); second.CopyTo(material[80..]);
        return ApplicationCoreFormat.Sha256Domain("Deep/Application/V1/contact-conversation", material);
    }

    /// <summary>Checks DID2 endpoint metadata only. Independently authenticate
    /// the DPH2/DPE2 event and route before durable contact/inbox state and ACK.</summary>
    public static async ValueTask RequireContactHelloEndpointBindingsAsync(
        ParsedDmc2 hello, VerifiedDeepIdV2DirectoryFreshness initiatorFreshness,
        VerifiedDeepIdV2DirectoryFreshness recipientFreshness,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(hello);
        ArgumentNullException.ThrowIfNull(initiatorFreshness);
        ArgumentNullException.ThrowIfNull(recipientFreshness);
        ArgumentNullException.ThrowIfNull(trustedTime);
        cancellationToken.ThrowIfCancellationRequested();
        if (hello.ParsedPayload is not ContactHelloDmc2Payload payload)
            throw new CryptographicException("The initial event is not ContactHello.");
        var xur = ContactCodec.Decode(ProtocolMagic.XUR1, payload.InboundXur1.Span);
        var first = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var sender = ContactControlEndpointV2.RequirePair(initiatorFreshness, recipientFreshness, first);
        DeepIdV2ContactUpdateRendezvousVerifier.RequireCurrentIssuer(xur, initiatorFreshness, first);
        ContactControlEndpointV2.RequireHello(hello, sender, recipientFreshness.CurrentCheckpoint!, xur);
        var final = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        ContactControlEndpointV2.RequireContinuous(first, final);
        _ = ContactControlEndpointV2.RequirePair(initiatorFreshness, recipientFreshness, final);
        DeepIdV2ContactUpdateRendezvousVerifier.RequireCurrentIssuer(xur, initiatorFreshness, final);
    }

    /// <summary>Endpoint metadata only; does not authenticate a parsed Accept
    /// or establish pending Hello custody, contact acceptance, materialization or ACK.</summary>
    public static async ValueTask RequireContactAcceptEndpointBindingsAsync(
        ParsedDmc2 accept, ParsedDmc2 hello, VerifiedDeepIdV2DirectoryFreshness initiatorFreshness,
        VerifiedDeepIdV2DirectoryFreshness responderFreshness, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accept);
        ArgumentNullException.ThrowIfNull(hello);
        ArgumentNullException.ThrowIfNull(initiatorFreshness);
        ArgumentNullException.ThrowIfNull(responderFreshness);
        ArgumentNullException.ThrowIfNull(trustedTime);
        cancellationToken.ThrowIfCancellationRequested();
        if (accept.ParsedPayload is not ContactAcceptDmc2Payload payload)
            throw new CryptographicException("The response event is not ContactAccept.");
        var xur = ContactCodec.Decode(ProtocolMagic.XUR1, payload.InboundXur1.Span);
        var first = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var responder = ContactControlEndpointV2.RequirePair(responderFreshness, initiatorFreshness, first);
        DeepIdV2ContactUpdateRendezvousVerifier.RequireCurrentIssuer(xur, responderFreshness, first);
        ContactControlEndpointV2.RequireAccept(accept, hello, initiatorFreshness.CurrentCheckpoint!, responder, xur);
        var final = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        ContactControlEndpointV2.RequireContinuous(first, final);
        _ = ContactControlEndpointV2.RequirePair(responderFreshness, initiatorFreshness, final);
        DeepIdV2ContactUpdateRendezvousVerifier.RequireCurrentIssuer(xur, responderFreshness, final);
    }
}

internal static class ContactControlEndpointV2
{
    internal static VerifiedAdc1V2 RequirePair(VerifiedDeepIdV2DirectoryFreshness sender,
        VerifiedDeepIdV2DirectoryFreshness recipient, OnionMonotonicReading reading)
    {
        foreach (var proof in new[] { sender, recipient })
            if (proof.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue ||
                proof.CurrentCheckpoint is null ||
                !proof.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds))
                throw new CryptographicException("Contact control requires two current DID2 directory proofs.");
        if (!Fixed(sender.NetworkId.Span, recipient.NetworkId.Span) ||
            Fixed(sender.CurrentCheckpoint!.Binding.Record.DeepAccountId.Span,
                recipient.CurrentCheckpoint!.Binding.Record.DeepAccountId.Span))
            throw new CryptographicException("Contact control requires distinct current accounts on one network.");
        return sender.CurrentCheckpoint!;
    }

    internal static byte[] Safety(VerifiedAdc1V2 sender, VerifiedAdc1V2 recipient) =>
        DeepIdV2Verifier.ComputeContactSafetyNumber(
            new Dab2LineageState(sender.Binding, false), new Dab2LineageState(recipient.Binding, false));

    internal static void RequireHello(ParsedDmc2 hello, VerifiedAdc1V2 sender,
        VerifiedAdc1V2 recipient, ContactRecord xur)
    {
        var payload = hello.ParsedPayload as ContactHelloDmc2Payload ??
            throw new CryptographicException("The initial event is not ContactHello.");
        var directory = sender.Directory.Record;
        RequireMailboxEndpoint(payload.MailboxRoute, sender, hello.SenderDeviceId.Span);
        var expectedConversation = ApplicationCoreVerifier.ComputeContactConversationId(sender.Checkpoint.NetworkId.Span,
            payload.RelationshipId.Span, sender.Binding.Record.DeepAccountId.Span, recipient.Binding.Record.DeepAccountId.Span);
        var device = sender.Directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.Certificate.DeviceId.Span, hello.SenderDeviceId.Span));
        if (device is null || !Fixed(hello.NetworkId.Span, sender.Checkpoint.NetworkId.Span) ||
            !Fixed(hello.SenderAccountId.Span, sender.Binding.Record.DeepAccountId.Span) ||
            !Fixed(hello.SenderDeviceId.Span, xur.FieldSpan(13)) ||
            !Fixed(hello.NetworkId.Span, xur.FieldSpan(1)) ||
            !Fixed(xur.FieldSpan(14), new ContactArtifactReference(ProtocolMagic.DPD1, 1,
                device.Certificate.CanonicalHash.Span).CanonicalBytes.Span) ||
            BinaryPrimitives.ReadUInt16BigEndian(xur.FieldSpan(10)) != 7 ||
            BinaryPrimitives.ReadUInt64BigEndian(xur.FieldSpan(4)) != 0 ||
            xur.FieldSpan(5).IndexOfAnyExcept((byte)0) >= 0 ||
            !Fixed(payload.InitiatorDab2Reference.Span, new ContactArtifactReference(
                ProtocolMagic.DAB2, 2, sender.Binding.Record.RecordHash.Span).CanonicalBytes.Span) ||
            !Fixed(payload.InitiatorDmd1Hash.Span, directory.RecordHash.Span) ||
            hello.SenderClientSequence != 2 || !Fixed(hello.ConversationId.Span, expectedConversation))
            throw new CryptographicException("ContactHello differs from its exact current DID2 endpoints.");
        var safety = Safety(sender, recipient);
        try
        {
            if (!Fixed(payload.SafetyNumberHash.Span, safety))
                throw new CryptographicException("ContactHello differs from its PQ-bound safety number.");
        }
        finally { CryptographicOperations.ZeroMemory(safety); }
        var created = hello.CreatedAtUnixMilliseconds / 1000;
        if (BinaryPrimitives.ReadUInt64BigEndian(xur.FieldSpan(11)) > created ||
            BinaryPrimitives.ReadUInt64BigEndian(xur.FieldSpan(12)) <= created ||
            device.Certificate.IssuedAtUnixSeconds > created ||
            device.Certificate.ExpiresAtUnixSeconds <= created)
            throw new CryptographicException("ContactHello is outside the issuer/device validity interval.");
        ContactCodec.VerifyDeviceSignature(xur, device.Certificate.DeviceEd25519PublicKey.Span);
    }

    internal static void RequireContinuous(OnionMonotonicReading first, OnionMonotonicReading final)
    {
        if (final.SampleSeconds < first.SampleSeconds || !Fixed(first.BootId.Span, final.BootId.Span))
            throw new CryptographicException("Contact control crossed a protected clock discontinuity.");
    }

    internal static void RequireAccept(ParsedDmc2 accept, ParsedDmc2 hello,
        VerifiedAdc1V2 initiator, VerifiedAdc1V2 responder, ContactRecord xur)
    {
        var request = hello.ParsedPayload as ContactHelloDmc2Payload ??
            throw new CryptographicException("The pending event is not ContactHello.");
        var response = accept.ParsedPayload as ContactAcceptDmc2Payload ??
            throw new CryptographicException("The response event is not ContactAccept.");
        RequireMailboxEndpoint(response.MailboxRoute, responder, accept.SenderDeviceId.Span);
        var originalXur = ContactCodec.Decode(ProtocolMagic.XUR1, request.InboundXur1.Span);
        // This proves original endpoint metadata, not authenticated pending custody.
        RequireHello(hello, initiator, responder, originalXur);
        var device = responder.Directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.Certificate.DeviceId.Span, accept.SenderDeviceId.Span));
        if (device is null || !Fixed(accept.NetworkId.Span, hello.NetworkId.Span) ||
            !Fixed(accept.ConversationId.Span, hello.ConversationId.Span) ||
            !Fixed(response.RelationshipId.Span, request.RelationshipId.Span) ||
            !Fixed(response.ContactHelloHash.Span, SHA256.HashData(hello.CanonicalBytes.Span)) ||
            !Fixed(accept.SenderAccountId.Span, responder.Binding.Record.DeepAccountId.Span) ||
            !Fixed(accept.SenderDeviceId.Span, xur.FieldSpan(13)) ||
            !Fixed(response.ResponderDab2Reference.Span, new ContactArtifactReference(
                ProtocolMagic.DAB2, 2, responder.Binding.Record.RecordHash.Span).CanonicalBytes.Span) ||
            !Fixed(response.ResponderDmd1Hash.Span, responder.Directory.Record.RecordHash.Span) ||
            accept.CreatedAtUnixMilliseconds < hello.CreatedAtUnixMilliseconds ||
            accept.CreatedAtUnixMilliseconds >= hello.ExpiresAtUnixMilliseconds)
            throw new CryptographicException("ContactAccept differs from its exact pending Hello/current endpoints.");
        var created = accept.CreatedAtUnixMilliseconds / 1000;
        if (BinaryPrimitives.ReadUInt64BigEndian(xur.FieldSpan(11)) > created ||
            BinaryPrimitives.ReadUInt64BigEndian(xur.FieldSpan(12)) <= created ||
            device.Certificate.IssuedAtUnixSeconds > created || device.Certificate.ExpiresAtUnixSeconds <= created)
            throw new CryptographicException("ContactAccept is outside its issuer/device validity interval.");
    }

    private static void RequireMailboxEndpoint(ParsedDeepIdV2ContactMailboxRoute package,
        VerifiedAdc1V2 sender, ReadOnlySpan<byte> device)
    {
        var dca = package.Authorization;
        if (!Fixed(dca.NetworkId.Span, sender.Checkpoint.NetworkId.Span) ||
            !Fixed(dca.DeepAccountId.Span, sender.Binding.Record.DeepAccountId.Span) ||
            !Fixed(dca.PublisherDeviceId.Span, device) ||
            !Fixed(dca.ExactDid2Hash.Span, sender.Binding.DeepId.RecordHash.Span) ||
            !Fixed(dca.Dab2Reference.CanonicalHash.Span, sender.Binding.Record.RecordHash.Span) ||
            dca.AuthorizedDmd1Generation != sender.Directory.Record.DirectoryGeneration ||
            !Fixed(dca.AuthorizedDmd1Hash.Span, sender.Directory.Record.RecordHash.Span))
            throw new CryptographicException("The private reply route differs from its exact current contact sender endpoint.");
        // Metadata only. Full DCA/threshold/time verification belongs to the
        // independent current-network route gate, never to this trust marker.
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
