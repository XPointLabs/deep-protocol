namespace Deep.Protocol.DeepExtension.NearbyHandshakes;

public static class NearbyHandshakeLimits
{
    public const int HintLength = 16;
    public const int IdentifierLength = 16;
    public const int AdvertisementLength = 24;
    public const int FrameHeaderLength = 64;
    public const int MinimumAdapterPayloadLength = 16;
    public const int MaximumAdapterPayloadLength = 1024;
    public const int ContactDiscoverySecretLength = 32;
    public const int MaximumIdentityLength = 512;
    public const int MinimumSessionKeyLength = 16;
    public const int MaximumSessionKeyLength = 128;
}

public enum NearbyHandshakeMessageKind : byte
{
    InitiatorHello = 1,
    ResponderResponse = 2
}

public enum NearbyHandshakeMode : byte
{
    Fresh = 1,
    Resumption = 2
}

public enum NearbyHandshakeState
{
    Idle,
    HintMatched,
    InitiatorHelloSent,
    ResponderHelloReceived,
    ResponderResponseSent,
    ResponseReceived,
    Established,
    Failed,
    Closed
}

public enum NearbyHandshakeEvent
{
    HintMatched,
    InitiatorHelloCreated,
    InitiatorHelloReceived,
    ResponseSent,
    ResponseReceived,
    Established,
    Failed,
    Closed
}

public enum NearbySimultaneousOpenRole
{
    Initiator,
    Responder
}

public enum NearbyHandshakeError
{
    None,
    EncodedLengthOutOfRange,
    InvalidMagic,
    UnsupportedVersion,
    InvalidEnumValue,
    ReservedFieldNotZero,
    MalformedLength,
    InvalidIdentifier,
    InvalidPeriod,
    InvalidResumption,
    InvalidHint,
    NoContactMatch,
    TranscriptMismatch,
    AuthenticationFailed,
    ReplayRejected,
    SimultaneousOpenCollision,
    InvalidTransition,
    InvalidAdapterOutput
}

public sealed record NearbyRendezvousPolicy
{
    public required byte PreviousPeriods { get; init; }
    public required byte FuturePeriods { get; init; }
}

public sealed record NearbyRendezvousMatch(
    ulong Period,
    byte BundleVersion,
    ReadOnlyMemory<byte> Hint);

public sealed record NearbyHandshakeBinding
{
    public required byte BundleVersion { get; init; }
    public required ulong Period { get; init; }
    public required ReadOnlyMemory<byte> TransportAttemptId { get; init; }
    public required ReadOnlyMemory<byte> SimultaneousOpenToken { get; init; }
    public required NearbyHandshakeMode Mode { get; init; }
    public required ulong ResumeCounter { get; init; }
}

public sealed record NearbyHandshakeFrame
{
    public required NearbyHandshakeMessageKind Kind { get; init; }
    public required NearbyHandshakeBinding Binding { get; init; }
    public required ReadOnlyMemory<byte> AdapterPayload { get; init; }
}

public sealed record NearbyEstablishedSession(
    ReadOnlyMemory<byte> PeerIdentity,
    ReadOnlyMemory<byte> SessionKey);

public sealed record NearbyProtocolResponderResult(
    byte[] Frame,
    NearbyEstablishedSession Session);

public sealed record NearbyHandshakeReplayScope(
    ReadOnlyMemory<byte> ExpectedPeerIdentity,
    ulong Period,
    ReadOnlyMemory<byte> TransportAttemptId,
    NearbyHandshakeMode Mode,
    ulong ResumeCounter,
    ReadOnlyMemory<byte> CanonicalTranscript);

public interface INearbyHandshakeReplayGuard
{
    bool TryAccept(NearbyHandshakeReplayScope scope);
}

public interface INearbyAuthenticatedKeyExchange
{
    byte[] DeriveRendezvousHint(
        ReadOnlySpan<byte> contactSecret,
        ulong period,
        byte bundleVersion);

    byte[] CreateInitiatorPayload(
        NearbyHandshakeBinding binding,
        ReadOnlySpan<byte> expectedPeerIdentity);

    byte[] CreateResponderPayload(
        NearbyHandshakeBinding binding,
        ReadOnlySpan<byte> canonicalInitiatorFrame,
        ReadOnlySpan<byte> expectedPeerIdentity);

    NearbyEstablishedSession CompleteResponder(
        NearbyHandshakeBinding binding,
        ReadOnlySpan<byte> canonicalInitiatorFrame,
        ReadOnlySpan<byte> canonicalResponderFrame,
        ReadOnlySpan<byte> expectedPeerIdentity);

    NearbyEstablishedSession CompleteInitiator(
        NearbyHandshakeBinding binding,
        ReadOnlySpan<byte> canonicalInitiatorFrame,
        ReadOnlySpan<byte> canonicalResponderFrame,
        ReadOnlySpan<byte> expectedPeerIdentity);
}

public sealed class NearbyHandshakeException(
    NearbyHandshakeError error,
    string message)
    : Exception(message)
{
    public NearbyHandshakeError Error { get; } = error;
}
