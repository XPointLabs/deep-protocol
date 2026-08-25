using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.PrivacyRouting;

public static class PrivacyRoutingLimits
{
    public const int RouteHopCount = 3;
    public const int RouterIdBytes = 32;
    public const int X25519KeyBytes = 32;
    public const int OperationIdBytes = 32;
    public const int AttemptIdBytes = 32;
    public const int HopReplayIdBytes = 32;
    public const int DefaultPaddingBlockBytes = 4_096;
    public const int MinimumPaddingBlockBytes = 256;
    public const int MaximumPaddingBlockBytes = 65_536;
    public const int MaximumApplicationPayloadBytes = 1_048_576;
    internal const int MaximumTerminalSuccessBodyBytes = MaximumApplicationPayloadBytes - 20;
}

public enum PrivacyRoutingOperation : byte
{
    Store = 1,
    Retrieve = 2,
    Acknowledge = 3
}

public enum PrivacyRoutingProtocolError
{
    None = 0,
    FrameLengthOutOfRange,
    UnsupportedVersion,
    UnsupportedSuite,
    WrongFramePurpose,
    InvalidKeyLength,
    InvalidRoute,
    InvalidOperation,
    InvalidIdentifier,
    InvalidLength,
    InvalidPadding,
    AuthenticationFailed,
    ReplyContextMismatch,
    ReplyContextDisposed
}

public sealed class PrivacyRoutingProtocolException : Exception
{
    public PrivacyRoutingProtocolException(
        PrivacyRoutingProtocolError error,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Error = error;
    }

    public PrivacyRoutingProtocolError Error { get; }
}

public sealed class PrivacyRoutingHop
{
    private readonly byte[] _routerId;
    private readonly byte[] _x25519PublicKey;

    public PrivacyRoutingHop(
        ReadOnlySpan<byte> routerId,
        ReadOnlySpan<byte> x25519PublicKey)
    {
        if (routerId.Length != PrivacyRoutingLimits.RouterIdBytes || IsZero(routerId))
        {
            throw Error(PrivacyRoutingProtocolError.InvalidIdentifier, "A router id must be a nonzero 32-byte value.");
        }

        if (x25519PublicKey.Length != PrivacyRoutingLimits.X25519KeyBytes || IsZero(x25519PublicKey))
        {
            throw Error(PrivacyRoutingProtocolError.InvalidKeyLength, "An independent X25519 public key must be a nonzero 32-byte value.");
        }

        _routerId = routerId.ToArray();
        _x25519PublicKey = x25519PublicKey.ToArray();
    }

    public ReadOnlyMemory<byte> RouterId => _routerId.ToArray();

    public ReadOnlyMemory<byte> X25519PublicKey => _x25519PublicKey.ToArray();

    internal ReadOnlySpan<byte> RouterIdSpan => _routerId;

    internal ReadOnlySpan<byte> X25519PublicKeySpan => _x25519PublicKey;

    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        var aggregate = 0;
        foreach (var item in value)
        {
            aggregate |= item;
        }

        return aggregate == 0;
    }

    private static PrivacyRoutingProtocolException Error(
        PrivacyRoutingProtocolError error,
        string message) => new(error, message);
}

public sealed class PrivacyRoutingBuiltRequest : IDisposable
{
    private readonly byte[] _frame;

    internal PrivacyRoutingBuiltRequest(
        byte[] frame,
        PrivacyRoutingReplyContext replyContext)
    {
        _frame = frame;
        ReplyContext = replyContext;
    }

    public ReadOnlyMemory<byte> Frame => _frame.ToArray();

    public PrivacyRoutingReplyContext ReplyContext { get; }

    public void Dispose() => ReplyContext.Dispose();
}

public sealed class PrivacyRoutingReplyContext : IDisposable
{
    private readonly byte[] _operationId;
    private readonly byte[] _attemptId;
    private byte[]? _privateKey;

    internal PrivacyRoutingReplyContext(
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> attemptId,
        byte[] privateKey)
    {
        Operation = operation;
        _operationId = operationId.ToArray();
        _attemptId = attemptId.ToArray();
        _privateKey = privateKey;
    }

    public PrivacyRoutingOperation Operation { get; }

    public ReadOnlyMemory<byte> OperationId => _operationId.ToArray();

    public ReadOnlyMemory<byte> AttemptId => _attemptId.ToArray();

    internal ReadOnlySpan<byte> OperationIdSpan => _operationId;

    internal ReadOnlySpan<byte> AttemptIdSpan => _attemptId;

    internal ReadOnlySpan<byte> GetPrivateKey()
    {
        if (_privateKey is null)
        {
            throw new PrivacyRoutingProtocolException(
                PrivacyRoutingProtocolError.ReplyContextDisposed,
                "The reply context has already been disposed.");
        }

        return _privateKey;
    }

    public void Dispose()
    {
        if (_privateKey is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_privateKey);
        _privateKey = null;
    }
}

public abstract class PrivacyRoutingOpenedLayer
{
    private readonly byte[] _replayId;

    private protected PrivacyRoutingOpenedLayer(ReadOnlySpan<byte> replayId)
    {
        _replayId = replayId.ToArray();
    }

    public ReadOnlyMemory<byte> ReplayId => _replayId.ToArray();
}

public sealed class PrivacyRoutingRelayLayer : PrivacyRoutingOpenedLayer
{
    private readonly byte[] _nextRouterId;
    private readonly byte[] _innerFrame;

    internal PrivacyRoutingRelayLayer(
        ReadOnlySpan<byte> replayId,
        ReadOnlySpan<byte> nextRouterId,
        ReadOnlySpan<byte> innerFrame)
        : base(replayId)
    {
        _nextRouterId = nextRouterId.ToArray();
        _innerFrame = innerFrame.ToArray();
    }

    public ReadOnlyMemory<byte> NextRouterId => _nextRouterId.ToArray();

    public ReadOnlyMemory<byte> InnerFrame => _innerFrame.ToArray();
}

public sealed class PrivacyRoutingExitLayer : PrivacyRoutingOpenedLayer
{
    private readonly byte[] _operationId;
    private readonly byte[] _attemptId;
    private readonly byte[] _replyPublicKey;
    private readonly byte[] _payload;

    internal PrivacyRoutingExitLayer(
        ReadOnlySpan<byte> replayId,
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> attemptId,
        ReadOnlySpan<byte> replyPublicKey,
        ReadOnlySpan<byte> payload)
        : base(replayId)
    {
        Operation = operation;
        _operationId = operationId.ToArray();
        _attemptId = attemptId.ToArray();
        _replyPublicKey = replyPublicKey.ToArray();
        _payload = payload.ToArray();
    }

    public PrivacyRoutingOperation Operation { get; }

    public ReadOnlyMemory<byte> OperationId => _operationId.ToArray();

    public ReadOnlyMemory<byte> AttemptId => _attemptId.ToArray();

    public ReadOnlyMemory<byte> ReplyPublicKey => _replyPublicKey.ToArray();

    public ReadOnlyMemory<byte> Payload => _payload.ToArray();

    internal ReadOnlySpan<byte> OperationIdSpan => _operationId;

    internal ReadOnlySpan<byte> AttemptIdSpan => _attemptId;

    internal ReadOnlySpan<byte> ReplyPublicKeySpan => _replyPublicKey;
}

public sealed class PrivacyRoutingOpenedResponse
{
    private readonly byte[] _payload;

    internal PrivacyRoutingOpenedResponse(
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> payload)
    {
        Operation = operation;
        _payload = payload.ToArray();
    }

    public PrivacyRoutingOperation Operation { get; }

    public ReadOnlyMemory<byte> Payload => _payload.ToArray();
}

public enum PrivacyRoutingReplayResult
{
    Accepted = 1,
    Replayed = 2,
    Saturated = 3
}

public sealed class PrivacyRoutingReplayWindow
{
    private readonly int _capacity;
    private readonly HashSet<string> _accepted = new(StringComparer.Ordinal);
    private readonly object _sync = new();

    public PrivacyRoutingReplayWindow(int capacity)
    {
        if (capacity is < 1 or > 65_536)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity), "Replay capacity must be from 1 through 65536.");
        }

        _capacity = capacity;
    }

    public int Count
    {
        get
        {
            lock (_sync)
            {
                return _accepted.Count;
            }
        }
    }

    public PrivacyRoutingReplayResult TryAccept(ReadOnlySpan<byte> replayId)
    {
        if (replayId.Length != PrivacyRoutingLimits.HopReplayIdBytes || IsZero(replayId))
        {
            throw new PrivacyRoutingProtocolException(
                PrivacyRoutingProtocolError.InvalidIdentifier,
                "A replay id must be a nonzero 32-byte value.");
        }

        var key = Convert.ToHexString(replayId);
        lock (_sync)
        {
            if (_accepted.Contains(key))
            {
                return PrivacyRoutingReplayResult.Replayed;
            }

            if (_accepted.Count == _capacity)
            {
                return PrivacyRoutingReplayResult.Saturated;
            }

            _accepted.Add(key);
            return PrivacyRoutingReplayResult.Accepted;
        }
    }

    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        var aggregate = 0;
        foreach (var item in value)
        {
            aggregate |= item;
        }

        return aggregate == 0;
    }
}
