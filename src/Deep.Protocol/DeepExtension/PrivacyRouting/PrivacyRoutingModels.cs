using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.PrivacyRouting;

internal static class PrivacyRoutingLimits
{
    public const int RouteHopCount = 3;
    public const int NetworkIdBytes = 16;
    public const int RouterIdBytes = 32;
    public const int X25519KeyBytes = 32;
    public const int OperationIdBytes = 32;
    public const int AttemptIdBytes = 32;
    public const int HopReplayIdBytes = 32;
    public const int DefaultPaddingBlockBytes = 4_096;
    public const int MinimumPaddingBlockBytes = 256;
    public const int MaximumPaddingBlockBytes = 65_536;
    public const int MinimumFrameBytes = 176;
    public const int MaximumFrameBytes = 1_572_864;
    public const int MaximumApplicationPayloadBytes = 1_048_576;
    public const int MaximumContactResolverRequestBytes = 69_649;
    public const int MaximumContactResolverResponseBytes = 131_072;
    public const int MaximumGroupControlRequestBytes = 33_160;
    public const int MaximumGroupControlResponseBytes = 65_535;
    public static readonly TimeSpan ReplyContextLifetime = TimeSpan.FromMinutes(10);
    internal const int MaximumTerminalSuccessBodyBytes = MaximumApplicationPayloadBytes - 20;
}

internal enum PrivacyRoutingOperation : byte { Store = 1, Retrieve = 2, Acknowledge = 3, ContactResolve = 4, GroupControl = 5 }
internal enum PrivacyRoutingKeyRole : byte { Relay = 1, Exit = 2 }
internal enum PrivacyRoutingReceivePosition : byte { Ingress = 1, Core = 2, Exit = 3 }

internal enum PrivacyRoutingProtocolError
{
    None = 0, FrameLengthOutOfRange, UnsupportedVersion, UnsupportedSuite, WrongFramePurpose,
    InvalidKeyLength, InvalidRoute, InvalidOperation, InvalidIdentifier, InvalidLength,
    InvalidPadding, AuthenticationFailed, ReplyContextMismatch, ReplyContextDisposed,
    ReplayRejected, InvalidKeyBinding
}

internal sealed class PrivacyRoutingProtocolException : Exception
{
    public PrivacyRoutingProtocolException(PrivacyRoutingProtocolError error, string message, Exception? innerException = null)
        : base(message, innerException) => Error = error;
    public PrivacyRoutingProtocolError Error { get; }
}

/// <summary>One explicit, already-authorized ONION-01 traffic-key binding.</summary>
internal sealed class PrivacyRoutingHop
{
    private readonly byte[] _routerOwnerId, _keyId, _x25519PublicKey;

    public PrivacyRoutingHop(
        ReadOnlySpan<byte> routerOwnerId,
        ReadOnlySpan<byte> keyId,
        ulong epoch,
        PrivacyRoutingKeyRole role,
        ReadOnlySpan<byte> x25519PublicKey)
    {
        PrivacyRoutingWire.ValidateId(routerOwnerId, PrivacyRoutingProtocolError.InvalidIdentifier, "router owner id");
        PrivacyRoutingWire.ValidateId(keyId, PrivacyRoutingProtocolError.InvalidIdentifier, "traffic key id");
        PrivacyRoutingWire.ValidateEpoch(epoch, response: false);
        PrivacyRoutingWire.ValidateRole(role);
        PrivacyRoutingWire.ValidatePublicKey(x25519PublicKey);
        _routerOwnerId = routerOwnerId.ToArray();
        _keyId = keyId.ToArray();
        _x25519PublicKey = x25519PublicKey.ToArray();
        Epoch = epoch;
        Role = role;
    }

    public ReadOnlyMemory<byte> RouterOwnerId => _routerOwnerId.ToArray();
    public ReadOnlyMemory<byte> KeyId => _keyId.ToArray();
    public ulong Epoch { get; }
    public PrivacyRoutingKeyRole Role { get; }
    public ReadOnlyMemory<byte> X25519PublicKey => _x25519PublicKey.ToArray();
    internal ReadOnlySpan<byte> RouterOwnerIdSpan => _routerOwnerId;
    internal ReadOnlySpan<byte> KeyIdSpan => _keyId;
    internal ReadOnlySpan<byte> X25519PublicKeySpan => _x25519PublicKey;
}

/// <summary>
/// Disposable local receive-key state bound to one network, owner, key, epoch and route position.
/// Ingress and Core contexts also bind the exact next traffic key.
/// </summary>
internal sealed class PrivacyRoutingReceiveKey : IDisposable
{
    private readonly byte[] _networkId, _ownerId, _keyId;
    private readonly PrivacyRoutingHop? _nextHop;
    private byte[]? _privateKey;

    public PrivacyRoutingReceiveKey(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> ownerId,
        ReadOnlySpan<byte> keyId,
        ulong epoch,
        PrivacyRoutingReceivePosition position,
        ReadOnlySpan<byte> privateKey,
        PrivacyRoutingHop? nextHop = null)
    {
        PrivacyRoutingWire.ValidateNetwork(networkId);
        PrivacyRoutingWire.ValidateId(ownerId, PrivacyRoutingProtocolError.InvalidIdentifier, "key owner id");
        PrivacyRoutingWire.ValidateId(keyId, PrivacyRoutingProtocolError.InvalidIdentifier, "traffic key id");
        PrivacyRoutingWire.ValidateEpoch(epoch, response: false);
        PrivacyRoutingWire.ValidateReceivePosition(position);
        PrivacyRoutingWire.ValidatePrivateKey(privateKey);

        var requiredNextRole = position switch
        {
            PrivacyRoutingReceivePosition.Ingress => PrivacyRoutingKeyRole.Relay,
            PrivacyRoutingReceivePosition.Core => PrivacyRoutingKeyRole.Exit,
            PrivacyRoutingReceivePosition.Exit => (PrivacyRoutingKeyRole?)null,
            _ => throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidKeyBinding, "Receive position is invalid.")
        };
        if (requiredNextRole is null && nextHop is not null ||
            requiredNextRole is not null && (nextHop is null || nextHop.Role != requiredNextRole))
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidKeyBinding, "Receive position and next-hop role are inconsistent.");
        if (nextHop is not null &&
            (CryptographicOperations.FixedTimeEquals(ownerId, nextHop.RouterOwnerIdSpan) ||
             CryptographicOperations.FixedTimeEquals(keyId, nextHop.KeyIdSpan)))
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidRoute, "Local and next-hop owner/key IDs must differ.");

        _networkId = networkId.ToArray();
        _ownerId = ownerId.ToArray();
        _keyId = keyId.ToArray();
        _privateKey = privateKey.ToArray();
        _nextHop = nextHop;
        Epoch = epoch;
        Position = position;
    }

    public ulong Epoch { get; }
    public PrivacyRoutingReceivePosition Position { get; }
    public PrivacyRoutingKeyRole Role => Position == PrivacyRoutingReceivePosition.Exit
        ? PrivacyRoutingKeyRole.Exit
        : PrivacyRoutingKeyRole.Relay;
    public ReadOnlyMemory<byte> NetworkId => Available(_networkId).ToArray();
    public ReadOnlyMemory<byte> OwnerId => Available(_ownerId).ToArray();
    public ReadOnlyMemory<byte> KeyId => Available(_keyId).ToArray();
    public PrivacyRoutingHop? NextHop => _nextHop;
    internal ReadOnlySpan<byte> NetworkIdSpan => Available(_networkId);
    internal ReadOnlySpan<byte> OwnerIdSpan => Available(_ownerId);
    internal ReadOnlySpan<byte> KeyIdSpan => Available(_keyId);
    internal ReadOnlySpan<byte> PrivateKey => _privateKey ??
        throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidKeyLength, "The receive key has been disposed.");

    public void Dispose()
    {
        var privateKey = Interlocked.Exchange(ref _privateKey, null);
        if (privateKey is null) return;
        CryptographicOperations.ZeroMemory(privateKey);
        CryptographicOperations.ZeroMemory(_networkId);
        CryptographicOperations.ZeroMemory(_ownerId);
        CryptographicOperations.ZeroMemory(_keyId);
    }

    private ReadOnlySpan<byte> Available(byte[] value)
    {
        if (Volatile.Read(ref _privateKey) is null)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidKeyLength, "The receive key has been disposed.");
        return value;
    }
}

internal sealed class PrivacyRoutingBuiltRequestCore : IDisposable
{
    private byte[]? _frame;
    private bool _disposeReplyContext = true;

    internal PrivacyRoutingBuiltRequestCore(byte[] frame, PrivacyRoutingReplyContext replyContext)
    {
        _frame = frame;
        ReplyContext = replyContext;
    }

    public ReadOnlyMemory<byte> Frame => (_frame ?? throw new ObjectDisposedException(nameof(PrivacyRoutingBuiltRequestCore))).ToArray();
    public PrivacyRoutingReplyContext ReplyContext { get; }

    public void Dispose()
    {
        if (_frame is not null)
        {
            CryptographicOperations.ZeroMemory(_frame);
            _frame = null;
        }
        if (_disposeReplyContext) ReplyContext.Dispose();
    }

    internal void DetachReplyContextForProduction() => _disposeReplyContext = false;
}

/// <summary>Single-use client reply private-key state. Expiry uses monotonic time only.</summary>
internal sealed class PrivacyRoutingReplyContext : IDisposable
{
    private readonly byte[] _networkId, _ownerId, _keyId, _publicKey, _operationId, _attemptId, _canonicalRequest;
    private readonly TimeProvider _timeProvider;
    private readonly long _createdTimestamp;
    private readonly TimeSpan _lifetime;
    private readonly object _sync = new();
    private byte[]? _privateKey;
    private bool _opening;

    internal PrivacyRoutingReplyContext(
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> ownerId,
        ReadOnlySpan<byte> keyId,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> attemptId,
        ReadOnlySpan<byte> canonicalRequest,
        byte[] privateKey,
        TimeProvider timeProvider,
        TimeSpan lifetime)
    {
        Operation = operation;
        _networkId = networkId.ToArray();
        _ownerId = ownerId.ToArray();
        _keyId = keyId.ToArray();
        _publicKey = publicKey.ToArray();
        _operationId = operationId.ToArray();
        _attemptId = attemptId.ToArray();
        _canonicalRequest = canonicalRequest.ToArray();
        _privateKey = privateKey;
        _timeProvider = timeProvider;
        _createdTimestamp = timeProvider.GetTimestamp();
        _lifetime = lifetime;
    }

    public PrivacyRoutingOperation Operation { get; }
    public TimeSpan MaximumLifetime => _lifetime;
    public ReadOnlyMemory<byte> OperationId => OwnAvailable(_operationId);
    public ReadOnlyMemory<byte> AttemptId => OwnAvailable(_attemptId);
    internal ReadOnlySpan<byte> NetworkIdSpan => _networkId;
    internal ReadOnlySpan<byte> OwnerIdSpan => _ownerId;
    internal ReadOnlySpan<byte> KeyIdSpan => _keyId;
    internal ReadOnlySpan<byte> PublicKeySpan => _publicKey;
    internal ReadOnlySpan<byte> OperationIdSpan => _operationId;
    internal ReadOnlySpan<byte> AttemptIdSpan => _attemptId;
    internal ReadOnlySpan<byte> CanonicalRequestSpan => _canonicalRequest;

    internal PrivacyRoutingReplyOpenState BeginOpen()
    {
        lock (_sync)
        {
            if (_privateKey is null || _opening)
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextDisposed, "The reply context is unavailable.");
            if (_timeProvider.GetElapsedTime(_createdTimestamp) >= _lifetime)
            {
                DisposeCore();
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextDisposed, "The reply context has expired.");
            }
            _opening = true;
            return new PrivacyRoutingReplyOpenState(
                Operation,
                _networkId,
                _ownerId,
                _keyId,
                _operationId,
                _attemptId,
                _canonicalRequest,
                _privateKey);
        }
    }

    internal void CompleteOpen(bool success)
    {
        lock (_sync)
        {
            if (!_opening) return;
            _opening = false;
            if (success) DisposeCore();
        }
    }

    public void Dispose()
    {
        lock (_sync) DisposeCore();
    }

    private ReadOnlyMemory<byte> OwnAvailable(byte[] value)
    {
        lock (_sync)
        {
            if (_privateKey is null)
                throw new ObjectDisposedException(nameof(PrivacyRoutingReplyContext));
            return value.ToArray();
        }
    }

    private void DisposeCore()
    {
        if (_privateKey is not null)
        {
            CryptographicOperations.ZeroMemory(_privateKey);
            _privateKey = null;
        }
        CryptographicOperations.ZeroMemory(_networkId);
        CryptographicOperations.ZeroMemory(_ownerId);
        CryptographicOperations.ZeroMemory(_keyId);
        CryptographicOperations.ZeroMemory(_publicKey);
        CryptographicOperations.ZeroMemory(_operationId);
        CryptographicOperations.ZeroMemory(_attemptId);
        CryptographicOperations.ZeroMemory(_canonicalRequest);
        _opening = false;
    }
}

internal sealed class PrivacyRoutingReplyOpenState : IDisposable
{
    private byte[]? _networkId, _ownerId, _keyId, _operationId, _attemptId, _canonicalRequest, _privateKey;

    internal PrivacyRoutingReplyOpenState(
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> ownerId,
        ReadOnlySpan<byte> keyId,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> attemptId,
        ReadOnlySpan<byte> canonicalRequest,
        ReadOnlySpan<byte> privateKey)
    {
        Operation = operation;
        _networkId = networkId.ToArray();
        _ownerId = ownerId.ToArray();
        _keyId = keyId.ToArray();
        _operationId = operationId.ToArray();
        _attemptId = attemptId.ToArray();
        _canonicalRequest = canonicalRequest.ToArray();
        _privateKey = privateKey.ToArray();
    }

    internal PrivacyRoutingOperation Operation { get; }
    internal ReadOnlySpan<byte> NetworkIdSpan => Available(_networkId);
    internal ReadOnlySpan<byte> OwnerIdSpan => Available(_ownerId);
    internal ReadOnlySpan<byte> KeyIdSpan => Available(_keyId);
    internal ReadOnlySpan<byte> OperationIdSpan => Available(_operationId);
    internal ReadOnlySpan<byte> AttemptIdSpan => Available(_attemptId);
    internal ReadOnlySpan<byte> CanonicalRequestSpan => Available(_canonicalRequest);
    internal ReadOnlySpan<byte> PrivateKeySpan => Available(_privateKey);

    public void Dispose()
    {
        foreach (var value in new[]
                 {
                     Interlocked.Exchange(ref _networkId, null),
                     Interlocked.Exchange(ref _ownerId, null),
                     Interlocked.Exchange(ref _keyId, null),
                     Interlocked.Exchange(ref _operationId, null),
                     Interlocked.Exchange(ref _attemptId, null),
                     Interlocked.Exchange(ref _canonicalRequest, null),
                     Interlocked.Exchange(ref _privateKey, null)
                 })
            if (value is not null) CryptographicOperations.ZeroMemory(value);
    }

    private static ReadOnlySpan<byte> Available(byte[]? value) =>
        value ?? throw new ObjectDisposedException(nameof(PrivacyRoutingReplyOpenState));
}

internal abstract class PrivacyRoutingOpenedLayer : IDisposable
{
    private byte[]? _replayId;

    private protected PrivacyRoutingOpenedLayer(ReadOnlySpan<byte> replayId) => _replayId = replayId.ToArray();

    public ReadOnlyMemory<byte> ReplayId => Own(_replayId, nameof(ReplayId));
    internal ReadOnlySpan<byte> ReplayIdSpan => Span(_replayId, nameof(ReplayId));

    public void Dispose()
    {
        var replayId = Interlocked.Exchange(ref _replayId, null);
        if (replayId is not null) CryptographicOperations.ZeroMemory(replayId);
        DisposeCore();
    }

    private protected abstract void DisposeCore();
    private protected static ReadOnlyMemory<byte> Own(byte[]? value, string name) =>
        (value ?? throw new ObjectDisposedException(name)).ToArray();
    private protected static ReadOnlySpan<byte> Span(byte[]? value, string name) =>
        value ?? throw new ObjectDisposedException(name);
}

internal sealed class PrivacyRoutingRelayLayer : PrivacyRoutingOpenedLayer
{
    private byte[]? _nextRouterId, _innerFrame;

    internal PrivacyRoutingRelayLayer(ReadOnlySpan<byte> replayId, ReadOnlySpan<byte> nextRouterId, ReadOnlySpan<byte> innerFrame)
        : base(replayId)
    {
        _nextRouterId = nextRouterId.ToArray();
        _innerFrame = innerFrame.ToArray();
    }

    public ReadOnlyMemory<byte> NextRouterId => Own(_nextRouterId, nameof(NextRouterId));
    public ReadOnlyMemory<byte> InnerFrame => Own(_innerFrame, nameof(InnerFrame));

    private protected override void DisposeCore()
    {
        var next = Interlocked.Exchange(ref _nextRouterId, null);
        var inner = Interlocked.Exchange(ref _innerFrame, null);
        if (next is not null) CryptographicOperations.ZeroMemory(next);
        if (inner is not null) CryptographicOperations.ZeroMemory(inner);
    }
}

internal sealed class PrivacyRoutingExitLayer : PrivacyRoutingOpenedLayer
{
    private byte[]? _networkId, _operationId, _attemptId, _replyPublicKey, _payload;
    private int _responseSealed;

    internal PrivacyRoutingExitLayer(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> replayId,
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> attemptId,
        ReadOnlySpan<byte> replyPublicKey,
        ReadOnlySpan<byte> payload)
        : base(replayId)
    {
        Operation = operation;
        _networkId = networkId.ToArray();
        _operationId = operationId.ToArray();
        _attemptId = attemptId.ToArray();
        _replyPublicKey = replyPublicKey.ToArray();
        _payload = payload.ToArray();
    }

    public PrivacyRoutingOperation Operation { get; }
    public ReadOnlyMemory<byte> OperationId => Own(_operationId, nameof(OperationId));
    public ReadOnlyMemory<byte> AttemptId => Own(_attemptId, nameof(AttemptId));
    public ReadOnlyMemory<byte> ReplyPublicKey => Own(_replyPublicKey, nameof(ReplyPublicKey));
    public ReadOnlyMemory<byte> Payload => Own(_payload, nameof(Payload));
    internal ReadOnlySpan<byte> NetworkIdSpan => Span(_networkId, nameof(PrivacyRoutingExitLayer));
    internal ReadOnlySpan<byte> OperationIdSpan => Span(_operationId, nameof(OperationId));
    internal ReadOnlySpan<byte> AttemptIdSpan => Span(_attemptId, nameof(AttemptId));
    internal ReadOnlySpan<byte> ReplyPublicKeySpan => Span(_replyPublicKey, nameof(ReplyPublicKey));
    internal ReadOnlySpan<byte> PayloadSpan => Span(_payload, nameof(Payload));

    internal void BeginResponseSeal()
    {
        _ = NetworkIdSpan;
        if (Interlocked.Exchange(ref _responseSealed, 1) != 0)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextDisposed, "The exit reply context is single-use.");
    }

    private protected override void DisposeCore()
    {
        foreach (var value in new[]
                 {
                     Interlocked.Exchange(ref _networkId, null),
                     Interlocked.Exchange(ref _operationId, null),
                     Interlocked.Exchange(ref _attemptId, null),
                     Interlocked.Exchange(ref _replyPublicKey, null),
                     Interlocked.Exchange(ref _payload, null)
                 })
            if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}

internal sealed class PrivacyRoutingOpenedResponseCore
{
    internal PrivacyRoutingOpenedResponseCore(PrivacyRoutingTerminalResult result) => Result = result;
    public PrivacyRoutingTerminalResult Result { get; }
    public PrivacyRoutingOperation Operation => Result.Operation;
    public ReadOnlyMemory<byte> Payload => Result.Body;
}

internal enum PrivacyRoutingReplayResult { Accepted = 1, Replayed = 2, Saturated = 3 }

internal sealed class PrivacyRoutingReplayScope
{
    private readonly byte[] _networkId, _ownerId, _keyId;

    internal PrivacyRoutingReplayScope(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> ownerId,
        ReadOnlySpan<byte> keyId,
        ulong epoch,
        PrivacyRoutingReceivePosition position)
    {
        PrivacyRoutingWire.ValidateNetwork(networkId);
        PrivacyRoutingWire.ValidateId(ownerId, PrivacyRoutingProtocolError.InvalidIdentifier, "router owner id");
        PrivacyRoutingWire.ValidateId(keyId, PrivacyRoutingProtocolError.InvalidIdentifier, "key id");
        PrivacyRoutingWire.ValidateEpoch(epoch, response: false);
        PrivacyRoutingWire.ValidateReceivePosition(position);
        _networkId = networkId.ToArray();
        _ownerId = ownerId.ToArray();
        _keyId = keyId.ToArray();
        Epoch = epoch;
        Position = position;
    }

    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> OwnerId => _ownerId.ToArray();
    public ReadOnlyMemory<byte> KeyId => _keyId.ToArray();
    public ulong Epoch { get; }
    public PrivacyRoutingReceivePosition Position { get; }
    internal string StableKey => $"{Convert.ToHexString(_networkId)}:{Convert.ToHexString(_ownerId)}:{Convert.ToHexString(_keyId)}:{Epoch}:{(byte)Position}";
}

/// <summary>
/// The production implementation must durably commit accepted IDs per exact scope before returning.
/// It must not evict accepted IDs while the traffic key is live.
/// </summary>
internal interface IPrivacyRoutingReplayStateStore
{
    PrivacyRoutingReplayResult TryAccept(PrivacyRoutingReplayScope scope, ReadOnlySpan<byte> replayId);
}

/// <summary>Bounded process-local utility for tests; it is not a durable production replay store.</summary>
internal sealed class PrivacyRoutingReplayWindow
{
    private readonly int _capacity;
    private readonly HashSet<string> _accepted = new(StringComparer.Ordinal);
    private readonly object _sync = new();

    public PrivacyRoutingReplayWindow(int capacity)
    {
        if (capacity is < 1 or > 65_536) throw new ArgumentOutOfRangeException(nameof(capacity));
        _capacity = capacity;
    }

    public int Count { get { lock (_sync) return _accepted.Count; } }

    public PrivacyRoutingReplayResult TryAccept(ReadOnlySpan<byte> replayId)
    {
        PrivacyRoutingWire.ValidateId(replayId, PrivacyRoutingProtocolError.InvalidIdentifier, "replay id");
        var id = Convert.ToHexString(replayId);
        lock (_sync)
        {
            if (_accepted.Contains(id)) return PrivacyRoutingReplayResult.Replayed;
            if (_accepted.Count == _capacity) return PrivacyRoutingReplayResult.Saturated;
            _accepted.Add(id);
            return PrivacyRoutingReplayResult.Accepted;
        }
    }
}
