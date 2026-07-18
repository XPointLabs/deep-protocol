namespace Deep.Protocol.DeepExtension.NearbyHandshakes;

public static class NearbyHandshakeProtocol
{
    public static byte[] CreateAdvertisement(
        ContactDiscoverySecret contactDiscoverySecret,
        ulong period,
        byte bundleVersion,
        INearbyAuthenticatedKeyExchange crypto)
    {
        ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(contactDiscoverySecret);
        if (period == 0)
        {
            throw Error(NearbyHandshakeError.InvalidPeriod, "Period must be nonzero.");
        }

        var hint = crypto.DeriveRendezvousHint(
            NearbyHandshakeDomains.RendezvousHint,
            contactDiscoverySecret, period, bundleVersion);
        return NearbyHandshakeCodec.EncodeAdvertisement(bundleVersion, hint);
    }

    public static NearbyRendezvousMatch MatchAdvertisement(
        ReadOnlySpan<byte> encoded,
        ContactDiscoverySecret contactDiscoverySecret,
        ulong currentPeriod,
        NearbyRendezvousPolicy policy,
        INearbyAuthenticatedKeyExchange crypto)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(contactDiscoverySecret);
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
                NearbyHandshakeDomains.RendezvousHint,
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
        NearbyHandshakePeriodPolicy periodPolicy,
        ReadOnlySpan<byte> expectedPeerIdentity,
        INearbyAuthenticatedKeyExchange crypto)
    {
        ArgumentNullException.ThrowIfNull(crypto);
        ValidateIdentity(expectedPeerIdentity);
        NearbyHandshakeCodec.ValidateBinding(binding);
        ValidatePeriod(binding.Period, periodPolicy);
        var payload = crypto.CreateInitiatorPayload(
            NearbyHandshakeDomains.AuthenticatedKeyExchange,
            binding,
            expectedPeerIdentity);
        return NearbyHandshakeCodec.EncodeFrame(
            NearbyHandshakeMessageKind.InitiatorHello, binding, payload);
    }

    public static NearbyProtocolResponderResult Respond(
        ReadOnlySpan<byte> canonicalInitiatorFrame,
        NearbyHandshakePeriodPolicy periodPolicy,
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
        ValidatePeriod(initiator.Binding.Period, periodPolicy);

        var adapterPayload = crypto.CreateResponderPayload(
            NearbyHandshakeDomains.AuthenticatedKeyExchange,
            initiator.Binding, canonicalInitiatorFrame, expectedPeerIdentity);
        var response = NearbyHandshakeCodec.EncodeFrame(
            NearbyHandshakeMessageKind.ResponderResponse,
            initiator.Binding,
            adapterPayload);
        var session = crypto.CompleteResponder(
            NearbyHandshakeDomains.AuthenticatedKeyExchange,
            initiator.Binding,
            canonicalInitiatorFrame,
            response,
            expectedPeerIdentity);
        ValidateSession(session, expectedPeerIdentity);
        AcceptReplay(
            expectedPeerIdentity,
            initiator.Binding,
            [.. canonicalInitiatorFrame, .. response],
            replayGuard);
        return new NearbyProtocolResponderResult(response, session);
    }

    public static NearbyEstablishedSession CompleteInitiator(
        ReadOnlySpan<byte> canonicalInitiatorFrame,
        ReadOnlySpan<byte> canonicalResponderFrame,
        NearbyHandshakePeriodPolicy periodPolicy,
        ReadOnlySpan<byte> expectedPeerIdentity,
        INearbyAuthenticatedKeyExchange crypto,
        INearbyHandshakeReplayGuard replayGuard)
    {
        ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(replayGuard);
        ValidateIdentity(expectedPeerIdentity);
        var initiator = NearbyHandshakeCodec.DecodeFrame(canonicalInitiatorFrame);
        var responder = NearbyHandshakeCodec.DecodeFrame(canonicalResponderFrame);
        ValidatePeriod(initiator.Binding.Period, periodPolicy);
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
            NearbyHandshakeDomains.AuthenticatedKeyExchange,
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
            binding.TransportAttemptId.Bytes.ToArray(),
            binding.Mode,
            binding.ResumeCounter,
            transcript.ToArray());
        var decision = replayGuard.Evaluate(scope);
        var accepted =
            binding.Mode == NearbyHandshakeMode.Fresh &&
            decision == NearbyHandshakeReplayDecision.AcceptedFresh ||
            binding.Mode == NearbyHandshakeMode.Resumption &&
            decision == NearbyHandshakeReplayDecision.AcceptedResumption;
        if (!accepted)
        {
            throw Error(
                NearbyHandshakeError.ReplayRejected,
                "The authenticated nearby transcript was already accepted.");
        }
    }

    private static void ValidatePeriod(
        ulong period,
        NearbyHandshakePeriodPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.CurrentPeriod == 0 ||
            policy.PreviousPeriods > 1 ||
            policy.FuturePeriods > 1)
        {
            throw Error(
                NearbyHandshakeError.InvalidPeriod,
                "Handshake period policy is outside strict bounds.");
        }

        var first =
            policy.CurrentPeriod -
            Math.Min((ulong)policy.PreviousPeriods, policy.CurrentPeriod - 1);
        var last = policy.CurrentPeriod > ulong.MaxValue - policy.FuturePeriods
            ? ulong.MaxValue
            : policy.CurrentPeriod + policy.FuturePeriods;
        if (period < first || period > last)
        {
            throw Error(
                NearbyHandshakeError.InvalidPeriod,
                "Handshake period is outside the bounded current/skew window.");
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
