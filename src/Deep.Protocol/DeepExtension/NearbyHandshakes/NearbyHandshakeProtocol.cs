namespace Deep.Protocol.DeepExtension.NearbyHandshakes;

public static class NearbyHandshakeProtocol
{
    public static byte[] CreateAdvertisement(
        ReadOnlySpan<byte> contactDiscoverySecret,
        ulong period,
        byte bundleVersion,
        INearbyAuthenticatedKeyExchange crypto)
    {
        ArgumentNullException.ThrowIfNull(crypto);
        ValidateContactSecret(contactDiscoverySecret);
        if (period == 0)
        {
            throw Error(NearbyHandshakeError.InvalidPeriod, "Period must be nonzero.");
        }

        var hint = crypto.DeriveRendezvousHint(
            contactDiscoverySecret, period, bundleVersion);
        return NearbyHandshakeCodec.EncodeAdvertisement(bundleVersion, hint);
    }

    public static NearbyRendezvousMatch MatchAdvertisement(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> contactDiscoverySecret,
        ulong currentPeriod,
        NearbyRendezvousPolicy policy,
        INearbyAuthenticatedKeyExchange crypto)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(crypto);
        ValidateContactSecret(contactDiscoverySecret);
        if (currentPeriod == 0 || policy.PreviousPeriods > 1 || policy.FuturePeriods > 1)
        {
            throw Error(
                NearbyHandshakeError.InvalidPeriod,
                "Rendezvous candidate periods are outside the bounded policy.");
        }

        var advertisement = NearbyHandshakeCodec.DecodeAdvertisement(encoded);
        var first = currentPeriod - Math.Min((ulong)policy.PreviousPeriods, currentPeriod - 1);
        var last = currentPeriod > ulong.MaxValue - policy.FuturePeriods
            ? ulong.MaxValue
            : currentPeriod + policy.FuturePeriods;
        for (var period = first; ; period++)
        {
            var candidate = crypto.DeriveRendezvousHint(
                contactDiscoverySecret, period, advertisement.BundleVersion);
            if (candidate.Length == NearbyHandshakeLimits.HintLength &&
                System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    candidate, advertisement.Hint.Span))
            {
                return advertisement with { Period = period };
            }

            if (period == last)
            {
                break;
            }
        }

        throw Error(
            NearbyHandshakeError.NoContactMatch,
            "Advertisement does not match the bounded contact-period candidates.");
    }

    public static byte[] CreateInitiator(
        NearbyHandshakeBinding binding,
        ReadOnlySpan<byte> expectedPeerIdentity,
        INearbyAuthenticatedKeyExchange crypto)
    {
        ArgumentNullException.ThrowIfNull(crypto);
        ValidateIdentity(expectedPeerIdentity);
        NearbyHandshakeCodec.ValidateBinding(binding);
        var payload = crypto.CreateInitiatorPayload(binding, expectedPeerIdentity);
        return NearbyHandshakeCodec.EncodeFrame(
            NearbyHandshakeMessageKind.InitiatorHello, binding, payload);
    }

    public static NearbyProtocolResponderResult Respond(
        ReadOnlySpan<byte> canonicalInitiatorFrame,
        ReadOnlySpan<byte> expectedPeerIdentity,
        INearbyAuthenticatedKeyExchange crypto,
        INearbyHandshakeReplayGuard replayGuard)
    {
        ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(replayGuard);
        ValidateIdentity(expectedPeerIdentity);
        var initiator = NearbyHandshakeCodec.DecodeFrame(canonicalInitiatorFrame);
        if (initiator.Kind != NearbyHandshakeMessageKind.InitiatorHello)
        {
            throw Error(
                NearbyHandshakeError.TranscriptMismatch,
                "Responder requires an initiator frame.");
        }

        var adapterPayload = crypto.CreateResponderPayload(
            initiator.Binding, canonicalInitiatorFrame, expectedPeerIdentity);
        var response = NearbyHandshakeCodec.EncodeFrame(
            NearbyHandshakeMessageKind.ResponderResponse,
            initiator.Binding,
            adapterPayload);
        var session = crypto.CompleteResponder(
            initiator.Binding,
            canonicalInitiatorFrame,
            response,
            expectedPeerIdentity);
        ValidateSession(session, expectedPeerIdentity);
        AcceptReplay(
            expectedPeerIdentity,
            initiator.Binding,
            canonicalInitiatorFrame,
            replayGuard);
        return new NearbyProtocolResponderResult(response, session);
    }

    public static NearbyEstablishedSession CompleteInitiator(
        ReadOnlySpan<byte> canonicalInitiatorFrame,
        ReadOnlySpan<byte> canonicalResponderFrame,
        ReadOnlySpan<byte> expectedPeerIdentity,
        INearbyAuthenticatedKeyExchange crypto,
        INearbyHandshakeReplayGuard replayGuard)
    {
        ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(replayGuard);
        ValidateIdentity(expectedPeerIdentity);
        var initiator = NearbyHandshakeCodec.DecodeFrame(canonicalInitiatorFrame);
        var responder = NearbyHandshakeCodec.DecodeFrame(canonicalResponderFrame);
        if (initiator.Kind != NearbyHandshakeMessageKind.InitiatorHello ||
            responder.Kind != NearbyHandshakeMessageKind.ResponderResponse ||
            !NearbyHandshakeCodec.GetBindingBytes(initiator.Binding)
                .AsSpan()
                .SequenceEqual(NearbyHandshakeCodec.GetBindingBytes(responder.Binding)))
        {
            throw Error(
                NearbyHandshakeError.TranscriptMismatch,
                "Initiator and responder transcript bindings differ.");
        }

        var session = crypto.CompleteInitiator(
            initiator.Binding,
            canonicalInitiatorFrame,
            canonicalResponderFrame,
            expectedPeerIdentity);
        ValidateSession(session, expectedPeerIdentity);
        AcceptReplay(
            expectedPeerIdentity,
            initiator.Binding,
            [.. canonicalInitiatorFrame, .. canonicalResponderFrame],
            replayGuard);
        return session;
    }

    private static void AcceptReplay(
        ReadOnlySpan<byte> expectedPeerIdentity,
        NearbyHandshakeBinding binding,
        ReadOnlySpan<byte> transcript,
        INearbyHandshakeReplayGuard replayGuard)
    {
        var scope = new NearbyHandshakeReplayScope(
            expectedPeerIdentity.ToArray(),
            binding.Period,
            binding.TransportAttemptId.ToArray(),
            binding.Mode,
            binding.ResumeCounter,
            transcript.ToArray());
        if (!replayGuard.TryAccept(scope))
        {
            throw Error(
                NearbyHandshakeError.ReplayRejected,
                "The authenticated nearby transcript was already accepted.");
        }
    }

    private static void ValidateContactSecret(ReadOnlySpan<byte> secret)
    {
        if (secret.Length != NearbyHandshakeLimits.ContactDiscoverySecretLength)
        {
            throw Error(
                NearbyHandshakeError.InvalidIdentifier,
                "Contact discovery secret must be exactly 32 bytes.");
        }
    }

    private static void ValidateIdentity(ReadOnlySpan<byte> identity)
    {
        if (identity.Length is <= 0 or > NearbyHandshakeLimits.MaximumIdentityLength)
        {
            throw Error(
                NearbyHandshakeError.InvalidIdentifier,
                "Expected contact identity length is invalid.");
        }
    }

    private static void ValidateSession(
        NearbyEstablishedSession session,
        ReadOnlySpan<byte> expectedPeerIdentity)
    {
        if (session is null ||
            !session.PeerIdentity.Span.SequenceEqual(expectedPeerIdentity) ||
            session.SessionKey.Length is
                < NearbyHandshakeLimits.MinimumSessionKeyLength or
                > NearbyHandshakeLimits.MaximumSessionKeyLength)
        {
            throw Error(
                NearbyHandshakeError.InvalidAdapterOutput,
                "Authenticated adapter output is inconsistent with the expected contact.");
        }
    }

    private static NearbyHandshakeException Error(
        NearbyHandshakeError error,
        string message) =>
        new(error, message);
}
