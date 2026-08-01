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
    public const int MinimumCanonicalAkeFrameLength =
        NearbyHandshakeLimits.FrameHeaderLength + NearbyHandshakeLimits.MinimumAdapterPayloadLength;
    public const int MaximumCanonicalAkeFrameLength =
        NearbyHandshakeLimits.FrameHeaderLength + NearbyHandshakeLimits.MaximumAdapterPayloadLength;
    public const int MinimumRecordPlaintextLength = 1;
    public const int MaximumRecordPlaintextLength = OpaqueBundleLimits.MaximumEncodedLength;
    // Allows a bounded record envelope without choosing an AKE/AEAD record format.
    public const int MaximumEncodedRecordLength = OpaqueBundleLimits.MaximumEncodedLength + 4_096;
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

    internal bool HasExactValue(NearbyVerifiedDeviceCredential other) =>
        ReferenceEquals(this, other) ||
        (AccountIdentity.Equals(other.AccountIdentity) &&
         DeviceKeyId.Equals(other.DeviceKeyId) &&
         RosterEpoch == other.RosterEpoch &&
         ValidFrom == other.ValidFrom &&
         ValidUntil == other.ValidUntil &&
         Status == other.Status);

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
    public async ValueTask<NearbyLocalDeviceKeyHandle> GetLocalKeyAsync(
        NearbyVerifiedDeviceCredential credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        var handle = await GetLocalKeyCoreAsync(credential, cancellationToken).ConfigureAwait(false);
        ArgumentNullException.ThrowIfNull(handle);
        if (!ReferenceEquals(handle.Credential, credential))
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidCredential,
                "Local key provider returned a handle for a different verified credential.");
        }

        return handle;
    }

    protected abstract ValueTask<NearbyLocalDeviceKeyHandle> GetLocalKeyCoreAsync(
        NearbyVerifiedDeviceCredential credential,
        CancellationToken cancellationToken);

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
        NearbyVerifiedDeviceCredential localCredential,
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
        ArgumentNullException.ThrowIfNull(localCredential);
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

        if (!ReferenceEquals(localCredential, localKeyHandle.Credential))
        {
            throw Error(
                NearbySecureChannelError.InvalidCredential,
                "Local key handle does not bind the independently verified local credential.");
        }

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

    internal bool HasExactBinding(NearbyHandshakeBinding candidate) =>
        binding.BundleVersion == candidate.BundleVersion &&
        binding.Period == candidate.Period &&
        binding.TransportAttemptId.Bytes.Span.SequenceEqual(
            candidate.TransportAttemptId.Bytes.Span) &&
        binding.SimultaneousOpenToken.Span.SequenceEqual(
            candidate.SimultaneousOpenToken.Span) &&
        binding.Mode == candidate.Mode &&
        binding.ResumeCounter == candidate.ResumeCounter;

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

public sealed class NearbyInitiatorHelloFrame
{
    private readonly NearbyFreshAkeFrameValue value;

    public NearbyInitiatorHelloFrame(
        NearbyAkeContext context,
        ReadOnlyMemory<byte> canonicalFrame)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
        value = NearbyFreshAkeFrameValue.Create(
            context,
            canonicalFrame,
            NearbyHandshakeMessageKind.InitiatorHello);
    }

    public NearbyAkeContext Context { get; }

    public ReadOnlyMemory<byte> Bytes => value.Bytes;

    public NearbyHandshakeBinding Binding => value.Binding;

    internal ReadOnlyMemory<byte> AdapterPayload => value.AdapterPayload;

    public override string ToString() => "NearbyInitiatorHelloFrame[redacted]";
}

public sealed class NearbyResponderResponseFrame
{
    private readonly NearbyFreshAkeFrameValue value;

    public NearbyResponderResponseFrame(
        NearbyAkeContext context,
        NearbyInitiatorHelloFrame initiatorHello,
        ReadOnlyMemory<byte> canonicalFrame)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
        InitiatorHello = initiatorHello ??
            throw new ArgumentNullException(nameof(initiatorHello));
        if (!ReferenceEquals(context, initiatorHello.Context))
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidCredential,
                "Responder frame does not own the exact initiator context capability.");
        }

        value = NearbyFreshAkeFrameValue.Create(
            context,
            canonicalFrame,
            NearbyHandshakeMessageKind.ResponderResponse);
    }

    public NearbyAkeContext Context { get; }

    public NearbyInitiatorHelloFrame InitiatorHello { get; }

    public ReadOnlyMemory<byte> Bytes => value.Bytes;

    public NearbyHandshakeBinding Binding => value.Binding;

    public override string ToString() => "NearbyResponderResponseFrame[redacted]";
}

public sealed class NearbyInitiatorFlight : IDisposable
{
    private readonly object issuerCapability;
    private NearbyInitiatorContinuation? ownedContinuation;

    internal NearbyInitiatorFlight(
        object issuerCapability,
        NearbyAkeContext context,
        NearbyHandshakePayload handshakePayload,
        NearbyInitiatorContinuation continuation)
    {
        this.issuerCapability = issuerCapability ??
            throw new ArgumentNullException(nameof(issuerCapability));
        Context = context ?? throw new ArgumentNullException(nameof(context));
        ArgumentNullException.ThrowIfNull(handshakePayload);
        ArgumentNullException.ThrowIfNull(continuation);
        HandshakePayload = handshakePayload;
        ownedContinuation = continuation;
    }

    public NearbyAkeContext Context { get; }

    public NearbyHandshakePayload HandshakePayload { get; }

    public NearbyInitiatorResponseFlight BindResponse(
        NearbyInitiatorHelloFrame initiatorHello,
        NearbyResponderResponseFrame responderResponse)
    {
        ArgumentNullException.ThrowIfNull(initiatorHello);
        ArgumentNullException.ThrowIfNull(responderResponse);
        if (!ReferenceEquals(Context, initiatorHello.Context) ||
            !ReferenceEquals(Context, responderResponse.Context) ||
            !ReferenceEquals(initiatorHello, responderResponse.InitiatorHello))
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidCredential,
                "Initiator state and response do not share exact context/frame capabilities.");
        }

        if (!HandshakePayload.Bytes.Span.SequenceEqual(
                initiatorHello.AdapterPayload.Span))
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidState,
                "Initiator state payload does not match the exact initiator frame.");
        }

        var continuation = Interlocked.Exchange(ref ownedContinuation, null) ??
            throw Error("Initiator state was already bound or disposed.");
        return new NearbyInitiatorResponseFlight(
            issuerCapability,
            Context,
            initiatorHello,
            responderResponse,
            continuation);
    }

    public void Dispose() =>
        Interlocked.Exchange(ref ownedContinuation, null)?.Dispose();

    public override string ToString() => "NearbyInitiatorFlight[redacted]";

    internal bool IsIssuedBy(object expectedIssuer) =>
        ReferenceEquals(issuerCapability, expectedIssuer);

    private static NearbySecureChannelException Error(string message) =>
        new(NearbySecureChannelError.InvalidState, message);
}

public sealed class NearbyInitiatorResponseFlight : IDisposable
{
    private readonly object issuerCapability;
    private NearbyInitiatorContinuation? ownedContinuation;

    internal NearbyInitiatorResponseFlight(
        object issuerCapability,
        NearbyAkeContext context,
        NearbyInitiatorHelloFrame initiatorHello,
        NearbyResponderResponseFrame responderResponse,
        NearbyInitiatorContinuation continuation)
    {
        this.issuerCapability = issuerCapability;
        Context = context;
        InitiatorHello = initiatorHello;
        ResponderResponse = responderResponse;
        ownedContinuation = continuation;
    }

    public NearbyAkeContext Context { get; }

    public NearbyInitiatorHelloFrame InitiatorHello { get; }

    public NearbyResponderResponseFrame ResponderResponse { get; }

    public void Dispose() =>
        Interlocked.Exchange(ref ownedContinuation, null)?.Dispose();

    public override string ToString() => "NearbyInitiatorResponseFlight[redacted]";

    internal bool IsIssuedBy(object expectedIssuer) =>
        ReferenceEquals(issuerCapability, expectedIssuer);

    internal INearbyPendingSession AcceptResponse(object expectedIssuer)
    {
        if (!ReferenceEquals(issuerCapability, expectedIssuer))
        {
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidCredential,
                "Initiator response was issued by a different AKE capability.");
        }

        var continuation = Interlocked.Exchange(ref ownedContinuation, null) ??
            throw Error(
                "Initiator response state was already accepted or disposed.");
        return continuation.Accept(ResponderResponse);
    }

    private static NearbySecureChannelException Error(string message) =>
        new(NearbySecureChannelError.InvalidState, message);
}

public sealed class NearbyResponderFlight : IDisposable
{
    private readonly object issuerCapability;
    private INearbyPendingSession? ownedPendingSession;

    internal NearbyResponderFlight(
        object issuerCapability,
        NearbyAkeContext context,
        NearbyInitiatorHelloFrame initiatorHello,
        NearbyHandshakePayload handshakePayload,
        INearbyPendingSession pendingSession)
    {
        this.issuerCapability = issuerCapability ??
            throw new ArgumentNullException(nameof(issuerCapability));
        Context = context ?? throw new ArgumentNullException(nameof(context));
        InitiatorHello = initiatorHello ??
            throw new ArgumentNullException(nameof(initiatorHello));
        ArgumentNullException.ThrowIfNull(handshakePayload);
        ArgumentNullException.ThrowIfNull(pendingSession);
        HandshakePayload = handshakePayload;
        ownedPendingSession = pendingSession;
    }

    public NearbyAkeContext Context { get; }

    public NearbyInitiatorHelloFrame InitiatorHello { get; }

    public NearbyHandshakePayload HandshakePayload { get; }

    public INearbyPendingSession TakePendingSession() =>
        Interlocked.Exchange(ref ownedPendingSession, null) ??
        throw Error("Pending session was already transferred or disposed.");

    public void Dispose() =>
        Interlocked.Exchange(ref ownedPendingSession, null)?.Dispose();

    public override string ToString() => "NearbyResponderFlight[redacted]";

    internal bool IsIssuedBy(object expectedIssuer) =>
        ReferenceEquals(issuerCapability, expectedIssuer);

    private static NearbySecureChannelException Error(string message) =>
        new(NearbySecureChannelError.InvalidState, message);
}

internal sealed class NearbyInitiatorContinuation : IDisposable
{
    private readonly Func<
        NearbyResponderResponseFrame,
        INearbyPendingSession> acceptResponder;
    private Action? disposeState;

    internal NearbyInitiatorContinuation(
        Func<NearbyResponderResponseFrame, INearbyPendingSession> acceptResponder,
        Action disposeState)
    {
        this.acceptResponder = acceptResponder ??
            throw new ArgumentNullException(nameof(acceptResponder));
        this.disposeState = disposeState ??
            throw new ArgumentNullException(nameof(disposeState));
    }

    internal INearbyPendingSession Accept(
        NearbyResponderResponseFrame responderResponse)
    {
        var dispose = Interlocked.Exchange(ref disposeState, null) ??
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidState,
                "Initiator continuation was already accepted or disposed.");
        try
        {
            return acceptResponder(responderResponse) ??
                throw new NearbySecureChannelException(
                    NearbySecureChannelError.InvalidState,
                    "AKE returned no pending session.");
        }
        catch
        {
            dispose();
            throw;
        }
    }

    public void Dispose() =>
        Interlocked.Exchange(ref disposeState, null)?.Invoke();
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
        NearbyInitiatorHelloFrame canonicalInitiatorFrame);

    INearbyPendingSession AcceptResponder(
        NearbyInitiatorResponseFlight initiatorResponse);
}

public abstract class NearbyFreshAkeBase : INearbyFreshAke
{
    private readonly object issuerCapability = new();

    public NearbyInitiatorFlight BeginInitiator(NearbyAkeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var flight = BeginInitiatorCore(context) ??
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidState,
                "AKE returned no initiator flight.");
        if (!flight.IsIssuedBy(issuerCapability) ||
            !ReferenceEquals(context, flight.Context))
        {
            flight.Dispose();
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidCredential,
                "AKE returned an initiator flight for a different issuer or context capability.");
        }

        return flight;
    }

    public NearbyResponderFlight AcceptInitiator(
        NearbyInitiatorHelloFrame canonicalInitiatorFrame)
    {
        ArgumentNullException.ThrowIfNull(canonicalInitiatorFrame);
        var flight = AcceptInitiatorCore(canonicalInitiatorFrame) ??
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidState,
                "AKE returned no responder flight.");
        if (!flight.IsIssuedBy(issuerCapability) ||
            !ReferenceEquals(flight.Context, canonicalInitiatorFrame.Context) ||
            !ReferenceEquals(flight.InitiatorHello, canonicalInitiatorFrame))
        {
            flight.Dispose();
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidCredential,
                "AKE returned a responder flight for a different issuer, context, or initiator frame capability.");
        }

        return flight;
    }

    public INearbyPendingSession AcceptResponder(
        NearbyInitiatorResponseFlight initiatorResponse)
    {
        ArgumentNullException.ThrowIfNull(initiatorResponse);
        if (!initiatorResponse.IsIssuedBy(issuerCapability))
        {
            // A wrong issuer must not consume another instance's continuation:
            // the owning issuer may still accept it, or its holder may dispose it.
            throw new NearbySecureChannelException(
                NearbySecureChannelError.InvalidCredential,
                "Initiator response was issued by a different AKE capability.");
        }

        return initiatorResponse.AcceptResponse(issuerCapability);
    }

    protected abstract NearbyInitiatorFlight BeginInitiatorCore(
        NearbyAkeContext context);

    protected abstract NearbyResponderFlight AcceptInitiatorCore(
        NearbyInitiatorHelloFrame canonicalInitiatorFrame);

    protected NearbyInitiatorFlight CreateInitiatorFlight(
        NearbyAkeContext context,
        NearbyHandshakePayload handshakePayload,
        Func<NearbyResponderResponseFrame, INearbyPendingSession> acceptResponder,
        Action disposeState) =>
        new(
            issuerCapability,
            context,
            handshakePayload,
            new NearbyInitiatorContinuation(acceptResponder, disposeState));

    protected NearbyResponderFlight CreateResponderFlight(
        NearbyInitiatorHelloFrame initiatorHello,
        NearbyHandshakePayload handshakePayload,
        INearbyPendingSession pendingSession)
    {
        ArgumentNullException.ThrowIfNull(initiatorHello);
        return new NearbyResponderFlight(
            issuerCapability,
            initiatorHello.Context,
            initiatorHello,
            handshakePayload,
            pendingSession);
    }
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

        var record = SealCore(SendDirection, kind, plaintext) ??
            throw Error(
                NearbySecureChannelError.InvalidRecord,
                "Nearby record sealing returned no record.");
        if (record.Length is <= 0 or > NearbySecureChannelLimits.MaximumEncodedRecordLength)
        {
            throw Error(
                NearbySecureChannelError.InvalidRecord,
                "Nearby encoded record length is invalid.");
        }

        return record;
    }

    public NearbyOpenedRecord Open(ReadOnlySpan<byte> record)
    {
        if (record.Length is <= 0 or > NearbySecureChannelLimits.MaximumEncodedRecordLength)
        {
            throw Error(
                NearbySecureChannelError.InvalidRecord,
                "Nearby encoded record length is invalid.");
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
    private bool externalTransferInspectionInProgress;

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
            !handshakeHash.Equals(replayClaim.TranscriptDigest) ||
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

        INearbySecureSession? channel = null;
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

                externalTransferInspectionInProgress = true;
            }

            channel = ActivateAfterReplayCommit() ??
                throw Error(
                    NearbySecureChannelError.InvalidState,
                    "Accepted pending session did not transfer a secure channel.");
            ValidateActivatedChannel(channel);

            lock (lifecycleGate)
            {
                if (lifecycleState != Activating)
                {
                    throw Error(
                        NearbySecureChannelError.InvalidState,
                        "Pending nearby session was disposed during channel transfer.");
                }

                externalTransferInspectionInProgress = false;
                lifecycleState = Activated;
            }

            return channel;
        }
        catch
        {
            try
            {
                channel?.Dispose();
            }
            finally
            {
                lock (lifecycleGate)
                {
                    externalTransferInspectionInProgress = false;
                    lifecycleState = Disposed;
                }

                DisposePendingStateOnce();
            }

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
            disposePendingState = !externalTransferInspectionInProgress;
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

    private void ValidateActivatedChannel(INearbySecureSession channel)
    {
        if (channel.LocalRole != LocalRole)
        {
            throw Error(
                NearbySecureChannelError.DirectionReflection,
                "Activated channel role is reflected.");
        }

        var actual = channel.Peer;
        var expected = Peer;
        ArgumentNullException.ThrowIfNull(actual);
        var actualCredential = actual.Credential;
        var expectedCredential = expected.Credential;
        if (!ReferenceEquals(actualCredential, expectedCredential) ||
            !actualCredential.HasExactValue(expectedCredential) ||
            actual.RosterEpoch != expected.RosterEpoch)
        {
            throw Error(
                NearbySecureChannelError.InvalidCredential,
                "Activated channel peer credential does not match the pending session.");
        }

        if (actual.AuthenticatedAt != expected.AuthenticatedAt)
        {
            throw Error(
                NearbySecureChannelError.AuthenticationFailed,
                "Activated channel authentication context does not match the pending session.");
        }

        if (channel.SendDirection != NearbyRecordDirectionPolicy.SendFor(LocalRole) ||
            channel.ReceiveDirection != NearbyRecordDirectionPolicy.ReceiveFor(LocalRole))
        {
            throw Error(
                NearbySecureChannelError.DirectionReflection,
                "Activated channel record direction is reflected.");
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

internal sealed class NearbyFreshAkeFrameValue
{
    private readonly byte[] bytes;
    private readonly NearbyHandshakeBinding binding;
    private readonly byte[] adapterPayload;

    private NearbyFreshAkeFrameValue(
        byte[] bytes,
        NearbyHandshakeBinding binding,
        ReadOnlySpan<byte> adapterPayload)
    {
        this.bytes = bytes;
        this.binding = CopyBinding(binding);
        this.adapterPayload = adapterPayload.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => bytes.ToArray();

    public NearbyHandshakeBinding Binding => CopyBinding(binding);

    public ReadOnlyMemory<byte> AdapterPayload => adapterPayload.ToArray();

    public static NearbyFreshAkeFrameValue Create(
        NearbyAkeContext context,
        ReadOnlyMemory<byte> canonicalFrame,
        NearbyHandshakeMessageKind expectedKind)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (canonicalFrame.Length is
            < NearbySecureChannelLimits.MinimumCanonicalAkeFrameLength or
            > NearbySecureChannelLimits.MaximumCanonicalAkeFrameLength)
        {
            throw Error(
                NearbySecureChannelError.InvalidHandshakePayload,
                "Canonical AKE frame length is outside strict P03C bounds.");
        }

        // Snapshot caller-owned memory before parsing any content from it.
        var snapshot = canonicalFrame.ToArray();
        NearbyHandshakeFrame decoded;
        try
        {
            decoded = NearbyHandshakeCodec.DecodeFrame(snapshot);
        }
        catch (NearbyHandshakeException exception)
        {
            throw Error(
                NearbySecureChannelError.InvalidHandshakePayload,
                $"Canonical AKE frame is invalid: {exception.Error}.");
        }

        if (decoded.Kind != expectedKind)
        {
            throw Error(
                NearbySecureChannelError.DirectionReflection,
                "Canonical AKE frame kind is reflected.");
        }

        if (decoded.Binding.Mode != NearbyHandshakeMode.Fresh ||
            decoded.Binding.ResumeCounter != 0)
        {
            throw Error(
                NearbySecureChannelError.ResumptionNotSupported,
                "P03D AKE frames must use the fresh P03C binding.");
        }

        if (!context.HasExactBinding(decoded.Binding))
        {
            throw Error(
                NearbySecureChannelError.InvalidHandshakePayload,
                "Canonical AKE frame does not match its exact P03C context binding.");
        }

        return new NearbyFreshAkeFrameValue(
            snapshot,
            decoded.Binding,
            decoded.AdapterPayload.Span);
    }

    private static NearbyHandshakeBinding CopyBinding(NearbyHandshakeBinding value) =>
        new()
        {
            BundleVersion = value.BundleVersion,
            Period = value.Period,
            TransportAttemptId = new TransportAttemptId(
                value.TransportAttemptId.Bytes.Span),
            SimultaneousOpenToken = value.SimultaneousOpenToken.ToArray(),
            Mode = value.Mode,
            ResumeCounter = value.ResumeCounter
        };

    private static NearbySecureChannelException Error(
        NearbySecureChannelError error,
        string message) =>
        new(error, message);
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
