using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.DeepExtension.NearbyHandshakes;

public static class NearbyHandshakeDomains
{
    public static ReadOnlySpan<byte> RendezvousHint => "Deep/P03C/RendezvousHint/v1"u8;
    public static ReadOnlySpan<byte> AuthenticatedKeyExchange => "Deep/P03C/AuthenticatedAKE/v1"u8;
}

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

public sealed record NearbyHandshakePeriodPolicy
{
    public required ulong CurrentPeriod { get; init; }
    public required byte PreviousPeriods { get; init; }
    public required byte FuturePeriods { get; init; }
}

public sealed class ContactDiscoverySecret
{
    internal ContactDiscoverySecret() { }
}

public interface IContactDiscoverySecretProvider
{
    ContactDiscoverySecret GetContactScopedSecret();
}

public abstract class ContactDiscoverySecretProviderBase : IContactDiscoverySecretProvider
{
    public abstract ContactDiscoverySecret GetContactScopedSecret();

    protected static ContactDiscoverySecret CreateOpaqueSecretHandle() => new();
}

public sealed record NearbyRendezvousMatch(
    ulong Period,
    byte BundleVersion,
    ReadOnlyMemory<byte> Hint);

public sealed record NearbyHandshakeBinding
{
    public required byte BundleVersion { get; init; }
    public required ulong Period { get; init; }
    public required TransportAttemptId TransportAttemptId { get; init; }
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

public enum NearbyHandshakeReplayDecision
{
    AcceptedFresh = 1,
    AcceptedResumption = 2,
    Rejected = 3
}

public interface INearbyHandshakeReplayGuard
{
    NearbyHandshakeReplayDecision Evaluate(NearbyHandshakeReplayScope scope);
}

public interface INearbyAuthenticatedKeyExchange
{
    byte[] DeriveRendezvousHint(
        ReadOnlySpan<byte> domain,
        ContactDiscoverySecret contactSecret,
        ulong period,
        byte bundleVersion);

    byte[] CreateInitiatorPayload(
        ReadOnlySpan<byte> domain,
        NearbyHandshakeBinding binding,
        ReadOnlySpan<byte> expectedPeerIdentity);

    byte[] CreateResponderPayload(
        ReadOnlySpan<byte> domain,
        NearbyHandshakeBinding binding,
        ReadOnlySpan<byte> canonicalInitiatorFrame,
        ReadOnlySpan<byte> expectedPeerIdentity);

    NearbyEstablishedSession CompleteResponder(
        ReadOnlySpan<byte> domain,
        NearbyHandshakeBinding binding,
        ReadOnlySpan<byte> canonicalInitiatorFrame,
        ReadOnlySpan<byte> canonicalResponderFrame,
        ReadOnlySpan<byte> expectedPeerIdentity);

    NearbyEstablishedSession CompleteInitiator(
        ReadOnlySpan<byte> domain,
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
