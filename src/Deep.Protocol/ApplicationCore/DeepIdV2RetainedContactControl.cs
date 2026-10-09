using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.ApplicationCore;

public static partial class ApplicationCoreVerifier
{
    /// <summary>Historical endpoint metadata only. The caller must independently
    /// prove exact native-committed Hello custody. No current rendezvous, route,
    /// new event admission, consent, materialization or ACK authority is returned.</summary>
    public static ValueTask RequireRetainedContactHelloEndpointBindingsAsync(
        ParsedDmc2 hello, VerifiedDeepIdV2DirectoryFreshness initiatorFreshness,
        VerifiedDeepIdV2DirectoryFreshness recipientFreshness,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default) =>
        RequireRetainedContactEndpointBindingsAsync(hello, null, initiatorFreshness,
            recipientFreshness, trustedTime, cancellationToken);

    /// <summary>Historical endpoint metadata only, including exact pending Hello
    /// binding. Independently prove native-committed Accept and Hello custody;
    /// these facts never authorize a new receive, send, route, grant or ACK.</summary>
    public static ValueTask RequireRetainedContactAcceptEndpointBindingsAsync(
        ParsedDmc2 accept, ParsedDmc2 hello, VerifiedDeepIdV2DirectoryFreshness initiatorFreshness,
        VerifiedDeepIdV2DirectoryFreshness responderFreshness,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(hello);
        return RequireRetainedContactEndpointBindingsAsync(accept, hello, initiatorFreshness,
            responderFreshness, trustedTime, cancellationToken);
    }

    private static async ValueTask RequireRetainedContactEndpointBindingsAsync(
        ParsedDmc2 record, ParsedDmc2? hello, VerifiedDeepIdV2DirectoryFreshness initiator,
        VerifiedDeepIdV2DirectoryFreshness responder, OnionTrustedTimeAuthority time, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(record); ArgumentNullException.ThrowIfNull(initiator);
        ArgumentNullException.ThrowIfNull(responder); ArgumentNullException.ThrowIfNull(time);
        ct.ThrowIfCancellationRequested();
        var exactXur = hello is null
            ? (record.ParsedPayload as ContactHelloDmc2Payload)?.InboundXur1
            : (record.ParsedPayload as ContactAcceptDmc2Payload)?.InboundXur1;
        if (exactXur is null) throw new CryptographicException("The retained contact event has the wrong kind.");
        var xur = ContactCodec.Decode(ProtocolMagic.XUR1, exactXur.Value.Span);
        var first = await time.ReadCurrentAsync(ct).ConfigureAwait(false);
        RequireAt(first);
        var final = await time.ReadCurrentAsync(ct).ConfigureAwait(false);
        ContactControlEndpointV2.RequireContinuous(first, final);
        RequireAt(final); ct.ThrowIfCancellationRequested();

        void RequireAt(OnionMonotonicReading reading)
        {
            ct.ThrowIfCancellationRequested();
            var sender = ContactControlEndpointV2.RequirePair(hello is null ? initiator : responder,
                hello is null ? responder : initiator, reading);
            DeepIdV2ContactUpdateRendezvousVerifier.RequireIssuerBinding(xur,
                hello is null ? initiator : responder, reading);
            if (hello is null) ContactControlEndpointV2.RequireHello(record, sender, responder.CurrentCheckpoint!, xur);
            else ContactControlEndpointV2.RequireAccept(record, hello, initiator.CurrentCheckpoint!, sender, xur);
            // Owned authors use the conservative endpoint upper bound + 1s.
            // Do not reject that genuine just-committed event against lower,
            // or allow a parsed event beyond the same authoring envelope.
            var upper = checked(initiator.TrustedUpperUnixSeconds + checked(reading.SampleSeconds - initiator.MonotonicSample));
            var otherUpper = checked(responder.TrustedUpperUnixSeconds + checked(reading.SampleSeconds - responder.MonotonicSample));
            if (record.CreatedAtUnixMilliseconds / 1000 > checked(Math.Max(upper, otherUpper) + 1))
                throw new CryptographicException("The retained contact event is in the authenticated future.");
        }
    }
}
