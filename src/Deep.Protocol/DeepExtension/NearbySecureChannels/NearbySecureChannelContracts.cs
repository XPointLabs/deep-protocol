using Deep.Protocol.DeepExtension.NearbyHandshakes;
using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.DeepExtension.NearbySecureChannels;

public static class NearbySecureChannelLimits
{
    public const int MinimumAccountIdentityLength = 1;
    public const int MaximumAccountIdentityLength = NearbyHandshakeLimits.MaximumIdentityLength;
    public const int MinimumDeviceKeyIdLength = NearbyHandshakeLimits.IdentifierLength;
    public const int MaximumDeviceKeyIdLength = 64;
    public const int MinimumTranscriptDigestLength = 32;
    public const int MaximumTranscriptDigestLength = 64;
    public const int MinimumHandshakePayloadLength = NearbyHandshakeLimits.MinimumAdapterPayloadLength;
    public const int MaximumHandshakePayloadLength = NearbyHandshakeLimits.MaximumAdapterPayloadLength;
    public const int MinimumRecordPlaintextLength = 1;
    public const int MaximumRecordPlaintextLength = OpaqueBundleLimits.MaximumEncodedLength;
}

public enum NearbySecureChannelProfileId : ushort
{
    UnassignedPendingExternalCryptoReview = 0
}

public enum NearbyDeviceCredentialStatus : byte
{
    Active = 1,
    Revoked = 2
}

public enum NearbyHandshakePayloadPurpose : byte
{
    AuthenticatedKeyExchangeOnly = 1
}

public enum NearbyRecordKind : byte
{
    Control = 1,
    OpaqueBundle = 2
}

public enum NearbyReplayClaimClassification : byte
{
    AcceptedFresh = 1,
    DuplicateSameTranscript = 2,
    CollisionDifferentTranscript = 3,
    Rejected = 4
}

public enum NearbySecureChannelError
{
    None = 0,
    UnsupportedProfile,
    ResumptionNotSupported,
    InvalidIdentifier,
    InvalidCredential,
    InvalidRosterEpoch,
    CredentialNotYetValid,
    CredentialExpired,
    CredentialRevoked,
    RosterRollback,
    InvalidHandshakePayload,
    ApplicationPayloadForbidden,
    AuthenticationFailed,
    ReplayRejected,
    ReplayCollision,
    InvalidAcceptance,
    InvalidRecord,
    DirectionReflection,
    CounterReuse,
    CounterOverflow,
    InvalidState,
    Unsupported
}

public sealed class NearbySecureChannelException(
    NearbySecureChannelError error,
    string message)
    : Exception(message)
{
    public NearbySecureChannelError Error { get; } = error;
}

public sealed class NearbyAccountIdentity
{
    private readonly byte[] bytes;

    public NearbyAccountIdentity(ReadOnlyMemory<byte> bytes)
    {
        this.bytes = ValidateOpaqueBytes(
            bytes.Span,
            NearbySecureChannelLimits.MinimumAccountIdentityLength,
            NearbySecureChannelLimits.MaximumAccountIdentityLength,
            nameof(bytes),
            "Nearby account identities");
    }

    public ReadOnlyMemory<byte> Bytes => bytes.ToArray();

    public override string ToString() => "NearbyAccountIdentity[redacted]";

    private static byte[] ValidateOpaqueBytes(
        ReadOnlySpan<byte> value,
        int minimumLength,
        int maximumLength,
        string parameterName,
        string description)
    {
        if (value.Length < minimumLength || value.Length > maximumLength ||
            value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw Error(
                NearbySecureChannelError.InvalidIdentifier,
                $"{description} must be {minimumLength}..{maximumLength} nonzero opaque bytes.",
                parameterName);
        }

        return value.ToArray();
    }

    private static NearbySecureChannelException Error(
        NearbySecureChannelError error,
        string message,
        string parameterName) =>
        new(error, $"{message} Parameter: {parameterName}.");
}

public sealed class NearbyDeviceKeyId
{
    private readonly byte[] bytes;

    public NearbyDeviceKeyId(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length is
                < NearbySecureChannelLimits.MinimumDeviceKeyIdLength or
                > NearbySecureChannelLimits.MaximumDeviceKeyIdLength ||
            bytes.Span.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidIdentifier,
                $"Nearby device-key identifiers must be " +
                $"{NearbySecureChannelLimits.MinimumDeviceKeyIdLength}.." +
                $"{NearbySecureChannelLimits.MaximumDeviceKeyIdLength} nonzero opaque bytes.");
        }

        this.bytes = bytes.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => bytes.ToArray();

    public override string ToString() => "NearbyDeviceKeyId[redacted]";
}

public sealed class NearbyTranscriptDigest
{
    private readonly byte[] bytes;

    public NearbyTranscriptDigest(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length is
                < NearbySecureChannelLimits.MinimumTranscriptDigestLength or
                > NearbySecureChannelLimits.MaximumTranscriptDigestLength ||
            bytes.Span.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidIdentifier,
                $"Nearby transcript digests must be " +
                $"{NearbySecureChannelLimits.MinimumTranscriptDigestLength}.." +
                $"{NearbySecureChannelLimits.MaximumTranscriptDigestLength} nonzero opaque bytes.");
        }

        this.bytes = bytes.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => bytes.ToArray();

    public override string ToString() => "NearbyTranscriptDigest[redacted]";
}

public sealed class NearbyLocalDeviceKeyHandle
{
    internal NearbyLocalDeviceKeyHandle()
    {
    }

    public override string ToString() => "NearbyLocalDeviceKeyHandle[redacted]";
}

public abstract class NearbyLocalDeviceKeyHandleProviderBase
{
    protected static NearbyLocalDeviceKeyHandle CreateOpaqueLocalKeyHandle() => new();
}

public sealed class NearbyDeviceCredential
{
    public NearbyDeviceCredential(
        NearbyAccountIdentity accountIdentity,
        NearbyDeviceKeyId deviceKeyId,
        ulong rosterEpoch,
        DateTimeOffset validFrom,
        DateTimeOffset validUntil,
        NearbyDeviceCredentialStatus status)
    {
        ArgumentNullException.ThrowIfNull(accountIdentity);
        ArgumentNullException.ThrowIfNull(deviceKeyId);
        if (rosterEpoch == 0)
        {
            throw Error(
                NearbySecureChannelError.InvalidRosterEpoch,
                "Credential roster epoch must be nonzero.");
        }

        if (validUntil <= validFrom ||
            status is not (NearbyDeviceCredentialStatus.Active or NearbyDeviceCredentialStatus.Revoked))
        {
            throw Error(
                NearbySecureChannelError.InvalidCredential,
                "Credential validity interval or status is invalid.");
        }

        AccountIdentity = accountIdentity;
        DeviceKeyId = deviceKeyId;
        RosterEpoch = rosterEpoch;
        ValidFrom = validFrom;
        ValidUntil = validUntil;
        Status = status;
    }

    public NearbyAccountIdentity AccountIdentity { get; }

    public NearbyDeviceKeyId DeviceKeyId { get; }

    public ulong RosterEpoch { get; }

    public DateTimeOffset ValidFrom { get; }

    public DateTimeOffset ValidUntil { get; }

    public NearbyDeviceCredentialStatus Status { get; }

    public override string ToString() => "NearbyDeviceCredential[redacted]";

    internal void ValidateAt(ulong expectedRosterEpoch, DateTimeOffset validationTime)
    {
        if (RosterEpoch < expectedRosterEpoch)
        {
            throw Error(
                NearbySecureChannelError.RosterRollback,
                "Peer credential roster epoch is older than the expected roster.");
        }

        if (RosterEpoch != expectedRosterEpoch)
        {
            throw Error(
                NearbySecureChannelError.InvalidCredential,
                "Peer credential roster epoch does not match the expected roster.");
        }

        if (Status == NearbyDeviceCredentialStatus.Revoked)
        {
            throw Error(
                NearbySecureChannelError.CredentialRevoked,
                "Peer credential is revoked.");
        }

        if (validationTime < ValidFrom)
        {
            throw Error(
                NearbySecureChannelError.CredentialNotYetValid,
                "Peer credential is not yet valid.");
        }

        if (validationTime >= ValidUntil)
        {
            throw Error(
                NearbySecureChannelError.CredentialExpired,
                "Peer credential is expired.");
        }
    }

    private static NearbySecureChannelException Error(
        NearbySecureChannelError error,
        string message) =>
        new(error, message);
}

public sealed class NearbyAkeContext
{
    private readonly NearbyHandshakeBinding binding;

    public NearbyAkeContext(
        NearbySecureChannelProfileId profileId,
        NearbyHandshakeBinding binding,
        NearbyAccountIdentity localAccountIdentity,
        NearbyDeviceKeyId localDeviceKeyId,
        NearbyLocalDeviceKeyHandle localKeyHandle,
        NearbyDeviceCredential expectedPeerCredential,
        ulong rosterEpoch,
        DateTimeOffset validationTime)
    {
        if (profileId != NearbySecureChannelProfileId.UnassignedPendingExternalCryptoReview)
        {
            throw Error(
                NearbySecureChannelError.UnsupportedProfile,
                "Nearby secure-channel profile is not recognized.");
        }

        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(localAccountIdentity);
        ArgumentNullException.ThrowIfNull(localDeviceKeyId);
        ArgumentNullException.ThrowIfNull(localKeyHandle);
        ArgumentNullException.ThrowIfNull(expectedPeerCredential);

        NearbyHandshakeCodec.ValidateBinding(binding);
        if (binding.Mode != NearbyHandshakeMode.Fresh || binding.ResumeCounter != 0)
        {
            throw Error(
                NearbySecureChannelError.ResumptionNotSupported,
                "P03D v1 accepts only fresh nearby handshakes.");
        }

        if (rosterEpoch == 0)
        {
            throw Error(
                NearbySecureChannelError.InvalidRosterEpoch,
                "Expected roster epoch must be nonzero.");
        }

        expectedPeerCredential.ValidateAt(rosterEpoch, validationTime);

        ProfileId = profileId;
        this.binding = CopyBinding(binding);
        LocalAccountIdentity = localAccountIdentity;
        LocalDeviceKeyId = localDeviceKeyId;
        LocalKeyHandle = localKeyHandle;
        ExpectedPeerCredential = expectedPeerCredential;
        RosterEpoch = rosterEpoch;
        ValidationTime = validationTime;
    }

    public NearbySecureChannelProfileId ProfileId { get; }

    public NearbyHandshakeBinding Binding => CopyBinding(binding);

    public NearbyAccountIdentity LocalAccountIdentity { get; }

    public NearbyDeviceKeyId LocalDeviceKeyId { get; }

    public NearbyLocalDeviceKeyHandle LocalKeyHandle { get; }

    public NearbyDeviceCredential ExpectedPeerCredential { get; }

    public ulong RosterEpoch { get; }

    public DateTimeOffset ValidationTime { get; }

    public override string ToString() => "NearbyAkeContext[redacted]";

    private static NearbyHandshakeBinding CopyBinding(NearbyHandshakeBinding binding) =>
        new()
        {
            BundleVersion = binding.BundleVersion,
            Period = binding.Period,
            TransportAttemptId = new TransportAttemptId(binding.TransportAttemptId.Bytes.Span),
            SimultaneousOpenToken = binding.SimultaneousOpenToken.ToArray(),
            Mode = binding.Mode,
            ResumeCounter = binding.ResumeCounter
        };

    private static NearbySecureChannelException Error(
        NearbySecureChannelError error,
        string message) =>
        new(error, message);
}

public sealed class NearbyHandshakePayload
{
    private readonly byte[] bytes;

    public NearbyHandshakePayload(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length is
            < NearbySecureChannelLimits.MinimumHandshakePayloadLength or
            > NearbySecureChannelLimits.MaximumHandshakePayloadLength)
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidHandshakePayload,
                $"AKE flight payloads must be " +
                $"{NearbySecureChannelLimits.MinimumHandshakePayloadLength}.." +
                $"{NearbySecureChannelLimits.MaximumHandshakePayloadLength} bytes.");
        }

        this.bytes = bytes.ToArray();
    }

    public NearbyHandshakePayloadPurpose Purpose =>
        NearbyHandshakePayloadPurpose.AuthenticatedKeyExchangeOnly;

    public ReadOnlyMemory<byte> Bytes => bytes.ToArray();

    public override string ToString() => "NearbyHandshakePayload[redacted]";
}

public interface INearbyInitiatorState : IDisposable
{
}

public sealed class NearbyInitiatorFlight
{
    public NearbyInitiatorFlight(
        NearbyHandshakePayload handshakePayload,
        INearbyInitiatorState state)
    {
        ArgumentNullException.ThrowIfNull(handshakePayload);
        ArgumentNullException.ThrowIfNull(state);
        HandshakePayload = handshakePayload;
        State = state;
    }

    public NearbyHandshakePayload HandshakePayload { get; }

    public INearbyInitiatorState State { get; }

    public override string ToString() => "NearbyInitiatorFlight[redacted]";
}

public sealed class NearbyResponderFlight
{
    public NearbyResponderFlight(
        NearbyHandshakePayload handshakePayload,
        INearbyPendingSession pendingSession)
    {
        ArgumentNullException.ThrowIfNull(handshakePayload);
        ArgumentNullException.ThrowIfNull(pendingSession);
        HandshakePayload = handshakePayload;
        PendingSession = pendingSession;
    }

    public NearbyHandshakePayload HandshakePayload { get; }

    public INearbyPendingSession PendingSession { get; }

    public override string ToString() => "NearbyResponderFlight[redacted]";
}

public sealed class NearbyAuthenticatedPeer
{
    public NearbyAuthenticatedPeer(
        NearbyDeviceCredential credential,
        ulong rosterEpoch,
        DateTimeOffset authenticatedAt)
    {
        ArgumentNullException.ThrowIfNull(credential);
        credential.ValidateAt(rosterEpoch, authenticatedAt);
        Credential = credential;
        RosterEpoch = rosterEpoch;
        AuthenticatedAt = authenticatedAt;
    }

    public NearbyDeviceCredential Credential { get; }

    public ulong RosterEpoch { get; }

    public DateTimeOffset AuthenticatedAt { get; }

    public override string ToString() => "NearbyAuthenticatedPeer[redacted]";
}

public interface INearbyFreshAke
{
    NearbyInitiatorFlight BeginInitiator(NearbyAkeContext context);

    NearbyResponderFlight AcceptInitiator(
        NearbyAkeContext context,
        ReadOnlySpan<byte> canonicalInitiatorFrame);

    INearbyPendingSession AcceptResponder(
        INearbyInitiatorState state,
        ReadOnlySpan<byte> canonicalInitiatorFrame,
        ReadOnlySpan<byte> canonicalResponderFrame);
}

public interface INearbyPendingSession : IDisposable
{
    NearbyAuthenticatedPeer Peer { get; }

    NearbyTranscriptDigest HandshakeHash { get; }

    INearbySecureSession Activate(NearbyReplayAcceptance acceptance);
}

public interface INearbySecureSession : IDisposable
{
    NearbyAuthenticatedPeer Peer { get; }

    byte[] Seal(NearbyRecordKind kind, ReadOnlySpan<byte> plaintext);

    NearbyOpenedRecord Open(ReadOnlySpan<byte> record);
}

public sealed class NearbyFreshReplayClaim
{
    private readonly byte[] transportAttemptId;

    public NearbyFreshReplayClaim(
        NearbyDeviceKeyId localDeviceKeyId,
        NearbyDeviceKeyId peerDeviceKeyId,
        TransportAttemptId transportAttemptId,
        NearbyTranscriptDigest transcriptDigest,
        ulong rosterEpoch)
    {
        ArgumentNullException.ThrowIfNull(localDeviceKeyId);
        ArgumentNullException.ThrowIfNull(peerDeviceKeyId);
        ArgumentNullException.ThrowIfNull(transportAttemptId);
        ArgumentNullException.ThrowIfNull(transcriptDigest);
        if (transportAttemptId.Bytes.Span.IndexOfAnyExcept((byte)0) < 0)
        {
            throw Error(
                NearbySecureChannelError.InvalidIdentifier,
                "Replay transport-attempt identifier must be nonzero.");
        }

        if (rosterEpoch == 0)
        {
            throw Error(
                NearbySecureChannelError.InvalidRosterEpoch,
                "Replay roster epoch must be nonzero.");
        }

        LocalDeviceKeyId = localDeviceKeyId;
        PeerDeviceKeyId = peerDeviceKeyId;
        this.transportAttemptId = transportAttemptId.Bytes.ToArray();
        TranscriptDigest = transcriptDigest;
        RosterEpoch = rosterEpoch;
    }

    public NearbyDeviceKeyId LocalDeviceKeyId { get; }

    public NearbyDeviceKeyId PeerDeviceKeyId { get; }

    public TransportAttemptId TransportAttemptId => new(transportAttemptId);

    public NearbyTranscriptDigest TranscriptDigest { get; }

    public ulong RosterEpoch { get; }

    public override string ToString() => "NearbyFreshReplayClaim[redacted]";

    private static NearbySecureChannelException Error(
        NearbySecureChannelError error,
        string message) =>
        new(error, message);
}

public sealed class NearbyReplayAcceptance
{
    private readonly byte[] transportAttemptId;

    internal NearbyReplayAcceptance(
        NearbyDeviceKeyId localDeviceKeyId,
        NearbyDeviceKeyId peerDeviceKeyId,
        TransportAttemptId transportAttemptId,
        NearbyTranscriptDigest transcriptDigest,
        ulong rosterEpoch,
        NearbyReplayClaimClassification classification)
    {
        ArgumentNullException.ThrowIfNull(localDeviceKeyId);
        ArgumentNullException.ThrowIfNull(peerDeviceKeyId);
        ArgumentNullException.ThrowIfNull(transportAttemptId);
        ArgumentNullException.ThrowIfNull(transcriptDigest);
        if (classification != NearbyReplayClaimClassification.AcceptedFresh)
        {
            throw Error(
                classification == NearbyReplayClaimClassification.CollisionDifferentTranscript
                    ? NearbySecureChannelError.ReplayCollision
                    : NearbySecureChannelError.ReplayRejected,
                "Only a durable fresh replay claim can activate a pending nearby session.");
        }

        if (transportAttemptId.Bytes.Span.IndexOfAnyExcept((byte)0) < 0)
        {
            throw Error(
                NearbySecureChannelError.InvalidIdentifier,
                "Replay acceptance transport-attempt identifier must be nonzero.");
        }

        if (rosterEpoch == 0)
        {
            throw Error(
                NearbySecureChannelError.InvalidRosterEpoch,
                "Replay acceptance roster epoch must be nonzero.");
        }

        LocalDeviceKeyId = localDeviceKeyId;
        PeerDeviceKeyId = peerDeviceKeyId;
        this.transportAttemptId = transportAttemptId.Bytes.ToArray();
        TranscriptDigest = transcriptDigest;
        RosterEpoch = rosterEpoch;
        Classification = classification;
    }

    public NearbyDeviceKeyId LocalDeviceKeyId { get; }

    public NearbyDeviceKeyId PeerDeviceKeyId { get; }

    public TransportAttemptId TransportAttemptId => new(transportAttemptId);

    public NearbyTranscriptDigest TranscriptDigest { get; }

    public ulong RosterEpoch { get; }

    public NearbyReplayClaimClassification Classification { get; }

    public override string ToString() => "NearbyReplayAcceptance[redacted]";

    private static NearbySecureChannelException Error(
        NearbySecureChannelError error,
        string message) =>
        new(error, message);
}

public sealed record NearbyReplayCommitResult
{
    public NearbyReplayCommitResult(
        NearbyReplayClaimClassification classification,
        NearbyReplayAcceptance? acceptance)
    {
        if (classification == NearbyReplayClaimClassification.AcceptedFresh)
        {
            ArgumentNullException.ThrowIfNull(acceptance);
        }
        else if (acceptance is not null)
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidAcceptance,
                "Rejected, duplicate or colliding replay claims cannot carry an acceptance.");
        }

        if (classification is not (
            NearbyReplayClaimClassification.AcceptedFresh or
            NearbyReplayClaimClassification.DuplicateSameTranscript or
            NearbyReplayClaimClassification.CollisionDifferentTranscript or
            NearbyReplayClaimClassification.Rejected))
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidAcceptance,
                "Replay claim classification is invalid.");
        }

        Classification = classification;
        Acceptance = acceptance;
    }

    public NearbyReplayClaimClassification Classification { get; }

    public NearbyReplayAcceptance? Acceptance { get; }
}

public interface INearbyReplayCommitter
{
    ValueTask<NearbyReplayCommitResult> CommitFreshAsync(
        NearbyFreshReplayClaim claim,
        CancellationToken cancellationToken = default);
}

public abstract class NearbyReplayCommitterBase : INearbyReplayCommitter
{
    public abstract ValueTask<NearbyReplayCommitResult> CommitFreshAsync(
        NearbyFreshReplayClaim claim,
        CancellationToken cancellationToken = default);

    protected static NearbyReplayAcceptance CreateDurableFreshAcceptance(
        NearbyFreshReplayClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        return new NearbyReplayAcceptance(
            claim.LocalDeviceKeyId,
            claim.PeerDeviceKeyId,
            claim.TransportAttemptId,
            claim.TranscriptDigest,
            claim.RosterEpoch,
            NearbyReplayClaimClassification.AcceptedFresh);
    }
}

public sealed class NearbyOpenedRecord
{
    private readonly byte[] plaintext;

    public NearbyOpenedRecord(
        NearbyRecordKind kind,
        ulong counter,
        ReadOnlyMemory<byte> plaintext)
    {
        if (kind is not (NearbyRecordKind.Control or NearbyRecordKind.OpaqueBundle) ||
            plaintext.Length is
                < NearbySecureChannelLimits.MinimumRecordPlaintextLength or
                > NearbySecureChannelLimits.MaximumRecordPlaintextLength)
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidRecord,
                "Opened nearby record kind or plaintext length is invalid.");
        }

        Kind = kind;
        Counter = counter;
        this.plaintext = plaintext.ToArray();
    }

    public NearbyRecordKind Kind { get; }

    public ulong Counter { get; }

    public ReadOnlyMemory<byte> Plaintext => plaintext.ToArray();

    public override string ToString() => "NearbyOpenedRecord[redacted]";
}
