using Deep.Protocol.DeepExtension.NearbyHandshakes;
using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.DeepExtension.NearbySecureChannels;

public static class NearbySecureChannelLimits
{
    public const int MinimumAccountIdentityLength = 1;
    public const int MaximumAccountIdentityLength = NearbyHandshakeLimits.MaximumIdentityLength;
    public const int MinimumDeviceKeyIdLength = NearbyHandshakeLimits.IdentifierLength;
    public const int MaximumDeviceKeyIdLength = 64;
    public const int MinimumLocalKeyReferenceLength = NearbyHandshakeLimits.IdentifierLength;
    public const int MaximumLocalKeyReferenceLength = 64;
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

public enum NearbySessionRole : byte
{
    Initiator = 1,
    Responder = 2
}

public enum NearbyRecordDirection : byte
{
    InitiatorToResponder = 1,
    ResponderToInitiator = 2
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

public sealed class NearbyAccountIdentity : IEquatable<NearbyAccountIdentity>
{
    private readonly byte[] bytes;

    public NearbyAccountIdentity(ReadOnlyMemory<byte> bytes)
    {
        this.bytes = NearbyOpaqueValue.Validate(
            bytes.Span,
            NearbySecureChannelLimits.MinimumAccountIdentityLength,
            NearbySecureChannelLimits.MaximumAccountIdentityLength,
            "Nearby account identity");
    }

    public ReadOnlyMemory<byte> Bytes => bytes.ToArray();

    public bool Equals(NearbyAccountIdentity? other) =>
        other is not null && bytes.AsSpan().SequenceEqual(other.bytes);

    public override bool Equals(object? obj) =>
        obj is NearbyAccountIdentity other && Equals(other);

    public override int GetHashCode() => NearbyOpaqueValue.GetHashCode(bytes);

    public override string ToString() => "NearbyAccountIdentity[redacted]";
}

public sealed class NearbyDeviceKeyId : IEquatable<NearbyDeviceKeyId>
{
    private readonly byte[] bytes;

    public NearbyDeviceKeyId(ReadOnlyMemory<byte> bytes)
    {
        this.bytes = NearbyOpaqueValue.Validate(
            bytes.Span,
            NearbySecureChannelLimits.MinimumDeviceKeyIdLength,
            NearbySecureChannelLimits.MaximumDeviceKeyIdLength,
            "Nearby device-key identifier");
    }

    public ReadOnlyMemory<byte> Bytes => bytes.ToArray();

    public bool Equals(NearbyDeviceKeyId? other) =>
        other is not null && bytes.AsSpan().SequenceEqual(other.bytes);

    public override bool Equals(object? obj) =>
        obj is NearbyDeviceKeyId other && Equals(other);

    public override int GetHashCode() => NearbyOpaqueValue.GetHashCode(bytes);

    public override string ToString() => "NearbyDeviceKeyId[redacted]";
}

public sealed class NearbyLocalKeyReference : IEquatable<NearbyLocalKeyReference>
{
    private readonly byte[] bytes;

    public NearbyLocalKeyReference(ReadOnlyMemory<byte> bytes)
    {
        this.bytes = NearbyOpaqueValue.Validate(
            bytes.Span,
            NearbySecureChannelLimits.MinimumLocalKeyReferenceLength,
            NearbySecureChannelLimits.MaximumLocalKeyReferenceLength,
            "Nearby local platform-key reference");
    }

    public ReadOnlyMemory<byte> Bytes => bytes.ToArray();

    public bool Equals(NearbyLocalKeyReference? other) =>
        other is not null && bytes.AsSpan().SequenceEqual(other.bytes);

    public override bool Equals(object? obj) =>
        obj is NearbyLocalKeyReference other && Equals(other);

    public override int GetHashCode() => NearbyOpaqueValue.GetHashCode(bytes);

    public override string ToString() => "NearbyLocalKeyReference[redacted]";
}

public sealed class NearbyTranscriptDigest : IEquatable<NearbyTranscriptDigest>
{
    private readonly byte[] bytes;

    public NearbyTranscriptDigest(ReadOnlyMemory<byte> bytes)
    {
        this.bytes = NearbyOpaqueValue.Validate(
            bytes.Span,
            NearbySecureChannelLimits.MinimumTranscriptDigestLength,
            NearbySecureChannelLimits.MaximumTranscriptDigestLength,
            "Nearby transcript digest");
    }

    public ReadOnlyMemory<byte> Bytes => bytes.ToArray();

    public bool Equals(NearbyTranscriptDigest? other) =>
        other is not null && bytes.AsSpan().SequenceEqual(other.bytes);

    public override bool Equals(object? obj) =>
        obj is NearbyTranscriptDigest other && Equals(other);

    public override int GetHashCode() => NearbyOpaqueValue.GetHashCode(bytes);

    public override string ToString() => "NearbyTranscriptDigest[redacted]";
}

public sealed class NearbyDeviceCredentialDescriptor
{
    public NearbyDeviceCredentialDescriptor(
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

    public override string ToString() => "NearbyDeviceCredentialDescriptor[redacted]";

    private static NearbySecureChannelException Error(
        NearbySecureChannelError error,
        string message) =>
        new(error, message);
}

public sealed class NearbyCredentialVerificationExpectation
{
    public NearbyCredentialVerificationExpectation(
        NearbyAccountIdentity accountIdentity,
        NearbyDeviceKeyId deviceKeyId,
        ulong rosterEpoch,
        DateTimeOffset validationTime)
    {
        ArgumentNullException.ThrowIfNull(accountIdentity);
        ArgumentNullException.ThrowIfNull(deviceKeyId);
        if (rosterEpoch == 0)
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidRosterEpoch,
                "Expected credential roster epoch must be nonzero.");
        }

        AccountIdentity = accountIdentity;
        DeviceKeyId = deviceKeyId;
        RosterEpoch = rosterEpoch;
        ValidationTime = validationTime;
    }

    public NearbyAccountIdentity AccountIdentity { get; }

    public NearbyDeviceKeyId DeviceKeyId { get; }

    public ulong RosterEpoch { get; }

    public DateTimeOffset ValidationTime { get; }

    public override string ToString() => "NearbyCredentialVerificationExpectation[redacted]";
}

public sealed class NearbyVerifiedDeviceCredential
{
    internal NearbyVerifiedDeviceCredential(NearbyDeviceCredentialDescriptor descriptor)
    {
        AccountIdentity = descriptor.AccountIdentity;
        DeviceKeyId = descriptor.DeviceKeyId;
        RosterEpoch = descriptor.RosterEpoch;
        ValidFrom = descriptor.ValidFrom;
        ValidUntil = descriptor.ValidUntil;
        Status = descriptor.Status;
    }

    public NearbyAccountIdentity AccountIdentity { get; }

    public NearbyDeviceKeyId DeviceKeyId { get; }

    public ulong RosterEpoch { get; }

    public DateTimeOffset ValidFrom { get; }

    public DateTimeOffset ValidUntil { get; }

    public NearbyDeviceCredentialStatus Status { get; }

    public override string ToString() => "NearbyVerifiedDeviceCredential[redacted]";

    internal void ValidateAt(NearbyCredentialVerificationExpectation expectation)
    {
        ArgumentNullException.ThrowIfNull(expectation);
        if (!AccountIdentity.Equals(expectation.AccountIdentity) ||
            !DeviceKeyId.Equals(expectation.DeviceKeyId))
        {
            throw Error(
                NearbySecureChannelError.InvalidCredential,
                "Credential account or device does not match the expected peer.");
        }

        if (RosterEpoch < expectation.RosterEpoch)
        {
            throw Error(
                NearbySecureChannelError.RosterRollback,
                "Credential roster epoch is older than the expected roster.");
        }

        if (RosterEpoch != expectation.RosterEpoch)
        {
            throw Error(
                NearbySecureChannelError.InvalidCredential,
                "Credential roster epoch does not match the expected roster.");
        }

        if (Status == NearbyDeviceCredentialStatus.Revoked)
        {
            throw Error(
                NearbySecureChannelError.CredentialRevoked,
                "Credential is revoked.");
        }

        if (expectation.ValidationTime < ValidFrom)
        {
            throw Error(
                NearbySecureChannelError.CredentialNotYetValid,
                "Credential is not yet valid.");
        }

        if (expectation.ValidationTime >= ValidUntil)
        {
            throw Error(
                NearbySecureChannelError.CredentialExpired,
                "Credential is expired.");
        }
    }

    private static NearbySecureChannelException Error(
        NearbySecureChannelError error,
        string message) =>
        new(error, message);
}

public interface INearbyDeviceCredentialVerifier
{
    ValueTask<NearbyVerifiedDeviceCredential> VerifyAsync(
        NearbyDeviceCredentialDescriptor descriptor,
        NearbyCredentialVerificationExpectation expectation,
        CancellationToken cancellationToken = default);
}

public abstract class NearbyDeviceCredentialVerifierBase : INearbyDeviceCredentialVerifier
{
    public abstract ValueTask<NearbyVerifiedDeviceCredential> VerifyAsync(
        NearbyDeviceCredentialDescriptor descriptor,
        NearbyCredentialVerificationExpectation expectation,
        CancellationToken cancellationToken = default);

    protected static NearbyVerifiedDeviceCredential CreateVerifiedCredential(
        NearbyDeviceCredentialDescriptor descriptor,
        NearbyCredentialVerificationExpectation expectation)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(expectation);
        var credential = new NearbyVerifiedDeviceCredential(descriptor);
        credential.ValidateAt(expectation);
        return credential;
    }
}

public sealed class NearbyLocalDeviceKeyHandle
{
    internal NearbyLocalDeviceKeyHandle(
        NearbyVerifiedDeviceCredential credential,
        NearbyLocalKeyReference keyReference)
    {
        Credential = credential;
        KeyReference = keyReference;
    }

    public NearbyVerifiedDeviceCredential Credential { get; }

    public NearbyLocalKeyReference KeyReference { get; }

    public override string ToString() => "NearbyLocalDeviceKeyHandle[redacted]";
}

public interface INearbyLocalDeviceKeyProvider
{
    ValueTask<NearbyLocalDeviceKeyHandle> GetLocalKeyAsync(
        NearbyVerifiedDeviceCredential credential,
        CancellationToken cancellationToken = default);
}

public abstract class NearbyLocalDeviceKeyProviderBase : INearbyLocalDeviceKeyProvider
{
    public abstract ValueTask<NearbyLocalDeviceKeyHandle> GetLocalKeyAsync(
        NearbyVerifiedDeviceCredential credential,
        CancellationToken cancellationToken = default);

    protected static NearbyLocalDeviceKeyHandle CreateOpaqueLocalKeyHandle(
        NearbyVerifiedDeviceCredential credential,
        NearbyLocalKeyReference keyReference)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(keyReference);
        return new NearbyLocalDeviceKeyHandle(credential, keyReference);
    }
}

public sealed class NearbyAkeContext
{
    private readonly NearbyHandshakeBinding binding;

    public NearbyAkeContext(
        NearbySecureChannelProfileId profileId,
        NearbyHandshakeBinding binding,
        NearbySessionRole localRole,
        NearbyLocalDeviceKeyHandle localKeyHandle,
        NearbyVerifiedDeviceCredential expectedPeerCredential,
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
        ArgumentNullException.ThrowIfNull(localKeyHandle);
        ArgumentNullException.ThrowIfNull(expectedPeerCredential);
        ValidateRole(localRole);
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

        var localCredential = localKeyHandle.Credential;
        localCredential.ValidateAt(new NearbyCredentialVerificationExpectation(
            localCredential.AccountIdentity,
            localCredential.DeviceKeyId,
            rosterEpoch,
            validationTime));
        expectedPeerCredential.ValidateAt(new NearbyCredentialVerificationExpectation(
            expectedPeerCredential.AccountIdentity,
            expectedPeerCredential.DeviceKeyId,
            rosterEpoch,
            validationTime));

        ProfileId = profileId;
        this.binding = CopyBinding(binding);
        LocalRole = localRole;
        LocalKeyHandle = localKeyHandle;
        LocalCredential = localCredential;
        ExpectedPeerCredential = expectedPeerCredential;
        RosterEpoch = rosterEpoch;
        ValidationTime = validationTime;
    }

    public NearbySecureChannelProfileId ProfileId { get; }

    public NearbyHandshakeBinding Binding => CopyBinding(binding);

    public NearbySessionRole LocalRole { get; }

    public NearbyLocalDeviceKeyHandle LocalKeyHandle { get; }

    public NearbyVerifiedDeviceCredential LocalCredential { get; }

    public NearbyVerifiedDeviceCredential ExpectedPeerCredential { get; }

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

    private static void ValidateRole(NearbySessionRole role)
    {
        if (role is not (NearbySessionRole.Initiator or NearbySessionRole.Responder))
        {
            throw Error(
                NearbySecureChannelError.InvalidState,
                "Nearby session role is invalid.");
        }
    }

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

public sealed class NearbyInitiatorFlight : IDisposable
{
    private INearbyInitiatorState? ownedState;

    public NearbyInitiatorFlight(
        NearbyHandshakePayload handshakePayload,
        INearbyInitiatorState state)
    {
        ArgumentNullException.ThrowIfNull(handshakePayload);
        ArgumentNullException.ThrowIfNull(state);
        HandshakePayload = handshakePayload;
        ownedState = state;
    }

    public NearbyHandshakePayload HandshakePayload { get; }

    public INearbyInitiatorState TakeState() =>
        Interlocked.Exchange(ref ownedState, null) ??
        throw Error("Initiator state was already transferred or disposed.");

    public void Dispose() =>
        Interlocked.Exchange(ref ownedState, null)?.Dispose();

    public override string ToString() => "NearbyInitiatorFlight[redacted]";

    private static NearbySecureChannelException Error(string message) =>
        new(NearbySecureChannelError.InvalidState, message);
}

public sealed class NearbyResponderFlight : IDisposable
{
    private INearbyPendingSession? ownedPendingSession;

    public NearbyResponderFlight(
        NearbyHandshakePayload handshakePayload,
        INearbyPendingSession pendingSession)
    {
        ArgumentNullException.ThrowIfNull(handshakePayload);
        ArgumentNullException.ThrowIfNull(pendingSession);
        HandshakePayload = handshakePayload;
        ownedPendingSession = pendingSession;
    }

    public NearbyHandshakePayload HandshakePayload { get; }

    public INearbyPendingSession TakePendingSession() =>
        Interlocked.Exchange(ref ownedPendingSession, null) ??
        throw Error("Pending session was already transferred or disposed.");

    public void Dispose() =>
        Interlocked.Exchange(ref ownedPendingSession, null)?.Dispose();

    public override string ToString() => "NearbyResponderFlight[redacted]";

    private static NearbySecureChannelException Error(string message) =>
        new(NearbySecureChannelError.InvalidState, message);
}

public sealed class NearbyAuthenticatedPeer
{
    internal NearbyAuthenticatedPeer(
        NearbyVerifiedDeviceCredential credential,
        ulong rosterEpoch,
        DateTimeOffset authenticatedAt)
    {
        ArgumentNullException.ThrowIfNull(credential);
        credential.ValidateAt(new NearbyCredentialVerificationExpectation(
            credential.AccountIdentity,
            credential.DeviceKeyId,
            rosterEpoch,
            authenticatedAt));
        Credential = credential;
        RosterEpoch = rosterEpoch;
        AuthenticatedAt = authenticatedAt;
    }

    public NearbyVerifiedDeviceCredential Credential { get; }

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

    NearbySessionRole LocalRole { get; }

    NearbyTranscriptDigest HandshakeHash { get; }

    NearbyFreshReplayClaim ReplayClaim { get; }

    ValueTask<INearbySecureSession> ActivateAsync(
        INearbyReplayCommitter replayCommitter,
        CancellationToken cancellationToken = default);
}

public interface INearbySecureSession : IDisposable
{
    NearbyAuthenticatedPeer Peer { get; }

    NearbySessionRole LocalRole { get; }

    NearbyRecordDirection SendDirection { get; }

    NearbyRecordDirection ReceiveDirection { get; }

    byte[] Seal(NearbyRecordKind kind, ReadOnlySpan<byte> plaintext);

    NearbyOpenedRecord Open(ReadOnlySpan<byte> record);
}

public abstract class NearbySecureSessionBase : INearbySecureSession
{
    protected NearbySecureSessionBase(
        NearbySessionRole localRole,
        NearbyVerifiedDeviceCredential peerCredential,
        ulong rosterEpoch,
        DateTimeOffset authenticatedAt)
    {
        if (localRole is not (NearbySessionRole.Initiator or NearbySessionRole.Responder))
        {
            throw Error(
                NearbySecureChannelError.InvalidState,
                "Nearby secure-session role is invalid.");
        }

        ArgumentNullException.ThrowIfNull(peerCredential);
        LocalRole = localRole;
        Peer = new NearbyAuthenticatedPeer(
            peerCredential,
            rosterEpoch,
            authenticatedAt);
    }

    public NearbyAuthenticatedPeer Peer { get; }

    public NearbySessionRole LocalRole { get; }

    public NearbyRecordDirection SendDirection =>
        NearbyRecordDirectionPolicy.SendFor(LocalRole);

    public NearbyRecordDirection ReceiveDirection =>
        NearbyRecordDirectionPolicy.ReceiveFor(LocalRole);

    public byte[] Seal(NearbyRecordKind kind, ReadOnlySpan<byte> plaintext)
    {
        if (kind is not (NearbyRecordKind.Control or NearbyRecordKind.OpaqueBundle) ||
            plaintext.Length is
                < NearbySecureChannelLimits.MinimumRecordPlaintextLength or
                > NearbySecureChannelLimits.MaximumRecordPlaintextLength)
        {
            throw Error(
                NearbySecureChannelError.InvalidRecord,
                "Nearby record kind or plaintext length is invalid.");
        }

        return SealCore(SendDirection, kind, plaintext) ??
            throw Error(
                NearbySecureChannelError.InvalidRecord,
                "Nearby record sealing returned no record.");
    }

    public NearbyOpenedRecord Open(ReadOnlySpan<byte> record)
    {
        if (record.IsEmpty)
        {
            throw Error(
                NearbySecureChannelError.InvalidRecord,
                "Nearby encoded record must not be empty.");
        }

        var opened = OpenCore(ReceiveDirection, record) ??
            throw Error(
                NearbySecureChannelError.InvalidRecord,
                "Nearby record opening returned no result.");
        if (opened.Direction != ReceiveDirection)
        {
            throw Error(
                NearbySecureChannelError.DirectionReflection,
                "Opened nearby record direction is reflected.");
        }

        return opened;
    }

    public abstract void Dispose();

    protected abstract byte[] SealCore(
        NearbyRecordDirection direction,
        NearbyRecordKind kind,
        ReadOnlySpan<byte> plaintext);

    protected abstract NearbyOpenedRecord OpenCore(
        NearbyRecordDirection expectedDirection,
        ReadOnlySpan<byte> record);

    private static NearbySecureChannelException Error(
        NearbySecureChannelError error,
        string message) =>
        new(error, message);
}

public sealed class NearbyFreshReplayClaim : IEquatable<NearbyFreshReplayClaim>
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

    public bool Equals(NearbyFreshReplayClaim? other) =>
        other is not null &&
        LocalDeviceKeyId.Equals(other.LocalDeviceKeyId) &&
        PeerDeviceKeyId.Equals(other.PeerDeviceKeyId) &&
        transportAttemptId.AsSpan().SequenceEqual(other.transportAttemptId) &&
        TranscriptDigest.Equals(other.TranscriptDigest) &&
        RosterEpoch == other.RosterEpoch;

    public override bool Equals(object? obj) =>
        obj is NearbyFreshReplayClaim other && Equals(other);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(LocalDeviceKeyId);
        hash.Add(PeerDeviceKeyId);
        foreach (var value in transportAttemptId)
        {
            hash.Add(value);
        }

        hash.Add(TranscriptDigest);
        hash.Add(RosterEpoch);
        return hash.ToHashCode();
    }

    public override string ToString() => "NearbyFreshReplayClaim[redacted]";

    private static NearbySecureChannelException Error(
        NearbySecureChannelError error,
        string message) =>
        new(error, message);
}

public sealed class NearbyReplayCommitOutcome
{
    public NearbyReplayCommitOutcome(NearbyReplayClaimClassification classification)
    {
        if (classification is not (
            NearbyReplayClaimClassification.AcceptedFresh or
            NearbyReplayClaimClassification.DuplicateSameTranscript or
            NearbyReplayClaimClassification.CollisionDifferentTranscript or
            NearbyReplayClaimClassification.Rejected))
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.ReplayRejected,
                "Replay commit classification is invalid.");
        }

        Classification = classification;
    }

    public NearbyReplayClaimClassification Classification { get; }
}

public interface INearbyReplayCommitter
{
    ValueTask<NearbyReplayCommitOutcome> CommitFreshAsync(
        NearbyFreshReplayClaim claim,
        CancellationToken cancellationToken = default);
}

public abstract class NearbyPendingSessionBase : INearbyPendingSession
{
    private const int Pending = 0;
    private const int Activating = 1;
    private const int Activated = 2;
    private const int Disposed = 3;

    private readonly object lifecycleGate = new();
    private int lifecycleState;
    private int pendingStateDisposed;

    protected NearbyPendingSessionBase(
        NearbyAkeContext context,
        DateTimeOffset authenticatedAt,
        NearbyTranscriptDigest handshakeHash,
        NearbyFreshReplayClaim replayClaim)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(handshakeHash);
        ArgumentNullException.ThrowIfNull(replayClaim);
        var binding = context.Binding;
        if (!context.LocalCredential.DeviceKeyId.Equals(replayClaim.LocalDeviceKeyId) ||
            !context.ExpectedPeerCredential.DeviceKeyId.Equals(replayClaim.PeerDeviceKeyId) ||
            context.RosterEpoch != replayClaim.RosterEpoch ||
            !binding.TransportAttemptId.Bytes.Span.SequenceEqual(
                replayClaim.TransportAttemptId.Bytes.Span))
        {
            throw Error(
                NearbySecureChannelError.InvalidCredential,
                "Pending context does not match its immutable replay claim.");
        }

        LocalRole = context.LocalRole;
        Peer = new NearbyAuthenticatedPeer(
            context.ExpectedPeerCredential,
            replayClaim.RosterEpoch,
            authenticatedAt);
        HandshakeHash = handshakeHash;
        ReplayClaim = replayClaim;
    }

    public NearbyAuthenticatedPeer Peer { get; }

    public NearbySessionRole LocalRole { get; }

    public NearbyTranscriptDigest HandshakeHash { get; }

    public NearbyFreshReplayClaim ReplayClaim { get; }

    public async ValueTask<INearbySecureSession> ActivateAsync(
        INearbyReplayCommitter replayCommitter,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(replayCommitter);
        lock (lifecycleGate)
        {
            if (lifecycleState != Pending)
            {
                throw Error(
                    NearbySecureChannelError.InvalidState,
                    "Pending nearby session was already consumed or disposed.");
            }

            lifecycleState = Activating;
        }

        try
        {
            var outcome = await replayCommitter
                .CommitFreshAsync(ReplayClaim, cancellationToken)
                .ConfigureAwait(false);
            ArgumentNullException.ThrowIfNull(outcome);
            if (outcome.Classification != NearbyReplayClaimClassification.AcceptedFresh)
            {
                throw Error(
                    outcome.Classification ==
                        NearbyReplayClaimClassification.CollisionDifferentTranscript
                        ? NearbySecureChannelError.ReplayCollision
                        : NearbySecureChannelError.ReplayRejected,
                    "Durable replay commit did not accept a fresh transcript.");
            }

            lock (lifecycleGate)
            {
                if (lifecycleState != Activating)
                {
                    throw Error(
                        NearbySecureChannelError.InvalidState,
                        "Pending nearby session was disposed during activation.");
                }

                var channel = ActivateAfterReplayCommit() ??
                    throw Error(
                        NearbySecureChannelError.InvalidState,
                        "Accepted pending session did not transfer a secure channel.");
                if (channel.LocalRole != LocalRole ||
                    !channel.Peer.Credential.DeviceKeyId.Equals(Peer.Credential.DeviceKeyId) ||
                    channel.SendDirection != NearbyRecordDirectionPolicy.SendFor(LocalRole) ||
                    channel.ReceiveDirection != NearbyRecordDirectionPolicy.ReceiveFor(LocalRole))
                {
                    channel.Dispose();
                    throw Error(
                        NearbySecureChannelError.DirectionReflection,
                        "Activated channel role, peer or direction does not match the pending session.");
                }

                lifecycleState = Activated;
                return channel;
            }
        }
        catch
        {
            lock (lifecycleGate)
            {
                lifecycleState = Disposed;
            }

            DisposePendingStateOnce();
            throw;
        }
    }

    public void Dispose()
    {
        var disposePendingState = false;
        lock (lifecycleGate)
        {
            if (lifecycleState is Activated or Disposed)
            {
                return;
            }

            lifecycleState = Disposed;
            disposePendingState = true;
        }

        if (disposePendingState)
        {
            DisposePendingStateOnce();
        }
    }

    protected abstract INearbySecureSession ActivateAfterReplayCommit();

    protected abstract void DisposePendingState();

    private void DisposePendingStateOnce()
    {
        if (Interlocked.CompareExchange(ref pendingStateDisposed, 1, 0) == 0)
        {
            DisposePendingState();
        }
    }

    private static NearbySecureChannelException Error(
        NearbySecureChannelError error,
        string message) =>
        new(error, message);
}

public static class NearbyRecordDirectionPolicy
{
    public static NearbyRecordDirection SendFor(NearbySessionRole localRole) =>
        localRole switch
        {
            NearbySessionRole.Initiator => NearbyRecordDirection.InitiatorToResponder,
            NearbySessionRole.Responder => NearbyRecordDirection.ResponderToInitiator,
            _ => throw Error()
        };

    public static NearbyRecordDirection ReceiveFor(NearbySessionRole localRole) =>
        localRole switch
        {
            NearbySessionRole.Initiator => NearbyRecordDirection.ResponderToInitiator,
            NearbySessionRole.Responder => NearbyRecordDirection.InitiatorToResponder,
            _ => throw Error()
        };

    private static NearbySecureChannelException Error() =>
        new(
            NearbySecureChannelError.InvalidState,
            "Nearby session role is invalid.");
}

public sealed class NearbyOpenedRecord
{
    private readonly byte[] plaintext;

    public NearbyOpenedRecord(
        NearbyRecordDirection direction,
        NearbyRecordKind kind,
        ulong counter,
        ReadOnlyMemory<byte> plaintext)
    {
        if (direction is not (
                NearbyRecordDirection.InitiatorToResponder or
                NearbyRecordDirection.ResponderToInitiator) ||
            kind is not (NearbyRecordKind.Control or NearbyRecordKind.OpaqueBundle) ||
            plaintext.Length is
                < NearbySecureChannelLimits.MinimumRecordPlaintextLength or
                > NearbySecureChannelLimits.MaximumRecordPlaintextLength)
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidRecord,
                "Opened nearby record direction, kind or plaintext length is invalid.");
        }

        Direction = direction;
        Kind = kind;
        Counter = counter;
        this.plaintext = plaintext.ToArray();
    }

    public NearbyRecordDirection Direction { get; }

    public NearbyRecordKind Kind { get; }

    public ulong Counter { get; }

    public ReadOnlyMemory<byte> Plaintext => plaintext.ToArray();

    public override string ToString() => "NearbyOpenedRecord[redacted]";
}

internal static class NearbyOpaqueValue
{
    public static byte[] Validate(
        ReadOnlySpan<byte> value,
        int minimumLength,
        int maximumLength,
        string description)
    {
        if (value.Length < minimumLength || value.Length > maximumLength ||
            value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidIdentifier,
                $"{description} must be {minimumLength}..{maximumLength} nonzero opaque bytes.");
        }

        return value.ToArray();
    }

    public static int GetHashCode(ReadOnlySpan<byte> value)
    {
        var hash = new HashCode();
        foreach (var item in value)
        {
            hash.Add(item);
        }

        return hash.ToHashCode();
    }
}
