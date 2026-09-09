#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV1;

/// <summary>
/// Explicit non-production seam for fixture construction and codec validation.
/// It never enables CONTACT-CODEC runtime activation or service emission.
/// </summary>
// Internal test-only surface. Deep.Protocol.csproj friends only the test
// assemblies; package consumers cannot bypass the inactive runtime gate.
internal static class ContactCodecValidation
{
    public static ContactRecord AuthorRecord(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields) =>
        ContactCodec.AuthorForValidation(magic, fields);

    public static byte[] SealPermanentDcr1(
        ContactRecord dcr1, ReadOnlySpan<byte> networkId16,
        ParsedDid1 permanentDeepId, PermanentContactResolution resolution,
        ReadOnlySpan<byte> nonce24)
    {
        var nonce = nonce24.ToArray();
        return Dcr1ObjectProtectionCodec.SealPermanentCore(
            dcr1, networkId16, permanentDeepId, resolution,
            destination => nonce.CopyTo(destination));
    }

    public static byte[] SealOneTimeDcr1(
        ContactRecord dcr1, ContactRecord dia1, ReadOnlySpan<byte> nonce24)
    {
        var nonce = nonce24.ToArray();
        return Dcr1ObjectProtectionCodec.SealOneTimeCore(
            dcr1, dia1, destination => nonce.CopyTo(destination));
    }

    public static ContactHelloDmc2Payload CreateContactHelloPayload(
        ReadOnlySpan<byte> relationshipId32, ReadOnlySpan<byte> initiatorDab1Reference38,
        ReadOnlySpan<byte> initiatorDmd1Hash32, ReadOnlySpan<byte> safetyNumberHash32,
        ContactPolicy policy, ReadOnlySpan<byte> exactInitiatorInboundXur1) =>
        ApplicationCoreCodec.CreateContactHelloPayloadForValidation(relationshipId32, initiatorDab1Reference38,
            initiatorDmd1Hash32, safetyNumberHash32, policy, exactInitiatorInboundXur1);

    public static ContactAcceptDmc2Payload CreateContactAcceptPayload(
        ReadOnlySpan<byte> relationshipId32, ReadOnlySpan<byte> contactHelloHash32,
        ReadOnlySpan<byte> responderDab1Reference38, ReadOnlySpan<byte> responderDmd1Hash32,
        ContactPolicy policy, ReadOnlySpan<byte> exactResponderInboundXur1) =>
        ApplicationCoreCodec.CreateContactAcceptPayloadForValidation(relationshipId32, contactHelloHash32,
            responderDab1Reference38, responderDmd1Hash32, policy, exactResponderInboundXur1);

    public static ContactRejectDmc2Payload CreateContactRejectPayload(ReadOnlySpan<byte> relationshipId32,
        ReadOnlySpan<byte> contactHelloHash32, ContactRejectReason reason) =>
        ApplicationCoreCodec.CreateContactRejectPayloadForValidation(relationshipId32, contactHelloHash32, reason);

    public static ContactRouteUpdateDmc2Payload CreateContactRouteUpdatePayload(
        ReadOnlySpan<byte> relationshipId32, ulong routeGeneration, ReadOnlySpan<byte> predecessorRouteUpdateHash32,
        ContactRecord xrr1, ContactRecord xra1, ContactRecord xrc1, ContactRecord xss1,
        ContactRecord pmt2, ContactRecord pms2) =>
        ApplicationCoreCodec.CreateContactRouteUpdatePayloadForValidation(relationshipId32, routeGeneration,
            predecessorRouteUpdateHash32, xrr1, xra1, xrc1, xss1, pmt2, pms2);

    public static ParsedDmc2 AuthorDmc2(
        ReadOnlySpan<byte> networkId16, ReadOnlySpan<byte> logicalMessageId32,
        ReadOnlySpan<byte> conversationId32, ReadOnlySpan<byte> senderAccountId32,
        ReadOnlySpan<byte> senderDeviceId32, ulong senderClientSequence,
        ulong createdAtUnixMilliseconds, ulong expiresAtUnixMilliseconds, Dmc2Flags flags,
        ReadOnlySpan<byte> replyToLogicalMessageId, Dmc2Payload payload) =>
        ApplicationCoreCodec.AuthorDmc2ForValidation(networkId16, logicalMessageId32, conversationId32,
            senderAccountId32, senderDeviceId32, senderClientSequence, createdAtUnixMilliseconds,
            expiresAtUnixMilliseconds, flags, replyToLogicalMessageId, payload);
}
#endif
