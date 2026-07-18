namespace Deep.Protocol.DeepExtension.NearbyHandshakes;

public static class NearbyHandshakeLifecycle
{
    public static NearbySimultaneousOpenRole ResolveSimultaneousOpen(
        ReadOnlySpan<byte> localToken,
        ReadOnlySpan<byte> remoteToken)
    {
        if (localToken.Length != NearbyHandshakeLimits.IdentifierLength ||
            remoteToken.Length != NearbyHandshakeLimits.IdentifierLength)
        {
            throw Error(
                NearbyHandshakeError.InvalidIdentifier,
                "Simultaneous-open tokens must be exactly 16 bytes.");
        }

        var comparison = localToken.SequenceCompareTo(remoteToken);
        return comparison switch
        {
            < 0 => NearbySimultaneousOpenRole.Initiator,
            > 0 => NearbySimultaneousOpenRole.Responder,
            _ => throw Error(
                NearbyHandshakeError.SimultaneousOpenCollision,
                "Equal simultaneous-open tokens require fresh attempt material.")
        };
    }

    public static NearbyHandshakeState Transition(
        NearbyHandshakeState state,
        NearbyHandshakeEvent @event) =>
        (state, @event) switch
        {
            (NearbyHandshakeState.Idle, NearbyHandshakeEvent.HintMatched) =>
                NearbyHandshakeState.HintMatched,
            (NearbyHandshakeState.HintMatched, NearbyHandshakeEvent.InitiatorHelloCreated) =>
                NearbyHandshakeState.InitiatorHelloSent,
            (NearbyHandshakeState.HintMatched, NearbyHandshakeEvent.InitiatorHelloReceived) =>
                NearbyHandshakeState.ResponderHelloReceived,
            (NearbyHandshakeState.ResponderHelloReceived, NearbyHandshakeEvent.ResponseSent) =>
                NearbyHandshakeState.ResponderResponseSent,
            (NearbyHandshakeState.InitiatorHelloSent, NearbyHandshakeEvent.ResponseReceived) =>
                NearbyHandshakeState.ResponseReceived,
            (NearbyHandshakeState.ResponseReceived, NearbyHandshakeEvent.Established) =>
                NearbyHandshakeState.Established,
            (NearbyHandshakeState.ResponderResponseSent, NearbyHandshakeEvent.Established) =>
                NearbyHandshakeState.Established,
            (_, NearbyHandshakeEvent.Failed) when state is not (
                NearbyHandshakeState.Established or NearbyHandshakeState.Closed) =>
                NearbyHandshakeState.Failed,
            (NearbyHandshakeState.Established, NearbyHandshakeEvent.Closed) =>
                NearbyHandshakeState.Closed,
            (NearbyHandshakeState.Failed, NearbyHandshakeEvent.Closed) =>
                NearbyHandshakeState.Closed,
            _ => throw Error(
                NearbyHandshakeError.InvalidTransition,
                "Nearby handshake lifecycle transition is invalid.")
        };

    private static NearbyHandshakeException Error(
        NearbyHandshakeError error,
        string message) =>
        new(error, message);
}
