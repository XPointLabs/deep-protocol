using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.MessagingCrypto;

/// <summary>
/// Non-serializable, verifier-minted bridge shared by the durable device-wide
/// pre-key owner and Protocol's responder handshake. It contains identifiers
/// and replay commitments only; private key material never crosses this type.
/// Each consumer lane is independently single-use.
/// </summary>
public sealed class VerifiedInitialSessionPreKeyClaim : IDisposable
{
    private byte[]? _deviceOperationId;
    private byte[]? _deviceSessionId;
    private byte[]? _deviceExactDpk2Hash;
    private byte[]? _deviceXpc1FullReplayHash;
    private byte[]? _deviceDph2FullReplayHash;
    private byte[]? _deviceX25519PreKeyId;
    private byte[]? _deviceMlKemPreKeyId;
    private byte[]? _protocolOperationId;
    private byte[]? _protocolSessionId;
    private byte[]? _protocolExactDpk2Hash;
    private byte[]? _protocolXpc1FullReplayHash;
    private byte[]? _protocolDph2FullReplayHash;
    private byte[]? _protocolX25519PreKeyId;
    private byte[]? _protocolMlKemPreKeyId;
    private int _deviceConsumed;
    private int _protocolConsumed;
    private readonly VerifiedDph2Initiation _initiation;

    internal VerifiedInitialSessionPreKeyClaim(
        Dpk2PrekeyKind kind,
        ushort lastResortUseCounter,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> exactDpk2Hash,
        ReadOnlySpan<byte> xpc1FullReplayHash,
        ReadOnlySpan<byte> dph2FullReplayHash,
        ReadOnlySpan<byte> x25519PreKeyId,
        ReadOnlySpan<byte> mlKemPreKeyId,
        VerifiedDph2Initiation initiation)
    {
        ArgumentNullException.ThrowIfNull(initiation);
        RequireNonZero32(operationId, nameof(operationId));
        RequireNonZero32(sessionId, nameof(sessionId));
        RequireNonZero32(exactDpk2Hash, nameof(exactDpk2Hash));
        RequireNonZero32(xpc1FullReplayHash, nameof(xpc1FullReplayHash));
        RequireNonZero32(dph2FullReplayHash, nameof(dph2FullReplayHash));
        RequireNonZero32(mlKemPreKeyId, nameof(mlKemPreKeyId));
        if (kind == Dpk2PrekeyKind.OneTime)
        {
            RequireNonZero32(x25519PreKeyId, nameof(x25519PreKeyId));
            if (lastResortUseCounter != 0)
                throw new ArgumentOutOfRangeException(nameof(lastResortUseCounter));
        }
        else if (kind == Dpk2PrekeyKind.LastResort)
        {
            if (!x25519PreKeyId.IsEmpty || lastResortUseCounter is < 1 or > 64)
                throw new ArgumentException("The verified last-resort claim shape is invalid.");
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Kind = kind;
        LastResortUseCounter = lastResortUseCounter;
        _deviceOperationId = operationId.ToArray();
        _deviceSessionId = sessionId.ToArray();
        _deviceExactDpk2Hash = exactDpk2Hash.ToArray();
        _deviceXpc1FullReplayHash = xpc1FullReplayHash.ToArray();
        _deviceDph2FullReplayHash = dph2FullReplayHash.ToArray();
        _deviceX25519PreKeyId = x25519PreKeyId.ToArray();
        _deviceMlKemPreKeyId = mlKemPreKeyId.ToArray();
        _protocolOperationId = operationId.ToArray();
        _protocolSessionId = sessionId.ToArray();
        _protocolExactDpk2Hash = exactDpk2Hash.ToArray();
        _protocolXpc1FullReplayHash = xpc1FullReplayHash.ToArray();
        _protocolDph2FullReplayHash = dph2FullReplayHash.ToArray();
        _protocolX25519PreKeyId = x25519PreKeyId.ToArray();
        _protocolMlKemPreKeyId = mlKemPreKeyId.ToArray();
        _initiation = initiation;
    }

    public Dpk2PrekeyKind Kind { get; }
    public ushort LastResortUseCounter { get; }

    /// <summary>
    /// Transfers the durable reservation facts exactly once to the device-wide
    /// pre-key owner. The returned payload is verifier-minted and disposable.
    /// </summary>
    public VerifiedDevicePreKeyClaimReservation ConsumeForDevicePreKeyOwner()
    {
        if (Interlocked.CompareExchange(ref _deviceConsumed, 1, 0) != 0)
            throw new InvalidOperationException("The verified device pre-key claim lane is single-use.");
        return new VerifiedDevicePreKeyClaimReservation(
            Kind,
            LastResortUseCounter,
            Take(ref _deviceOperationId),
            Take(ref _deviceSessionId),
            Take(ref _deviceExactDpk2Hash),
            Take(ref _deviceXpc1FullReplayHash),
            Take(ref _deviceDph2FullReplayHash),
            Take(ref _deviceX25519PreKeyId),
            Take(ref _deviceMlKemPreKeyId));
    }

    internal ProtocolClaimPayload ConsumeForProtocolHandshake()
    {
        if (Interlocked.CompareExchange(ref _protocolConsumed, 1, 0) != 0)
            throw new InvalidOperationException("The verified Protocol handshake claim lane is single-use.");
        return new ProtocolClaimPayload(
            Kind,
            LastResortUseCounter,
            Take(ref _protocolOperationId),
            Take(ref _protocolSessionId),
            Take(ref _protocolExactDpk2Hash),
            Take(ref _protocolXpc1FullReplayHash),
            Take(ref _protocolDph2FullReplayHash),
            Take(ref _protocolX25519PreKeyId),
            Take(ref _protocolMlKemPreKeyId),
            _initiation);
    }

    public void Dispose()
    {
        Zero(ref _deviceOperationId);
        Zero(ref _deviceSessionId);
        Zero(ref _deviceExactDpk2Hash);
        Zero(ref _deviceXpc1FullReplayHash);
        Zero(ref _deviceDph2FullReplayHash);
        Zero(ref _deviceX25519PreKeyId);
        Zero(ref _deviceMlKemPreKeyId);
        Zero(ref _protocolOperationId);
        Zero(ref _protocolSessionId);
        Zero(ref _protocolExactDpk2Hash);
        Zero(ref _protocolXpc1FullReplayHash);
        Zero(ref _protocolDph2FullReplayHash);
        Zero(ref _protocolX25519PreKeyId);
        Zero(ref _protocolMlKemPreKeyId);
    }

    private static void RequireNonZero32(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly 32 non-zero bytes.", name);
    }

    private static byte[] Take(ref byte[]? value) =>
        Interlocked.Exchange(ref value, null) ??
        throw new InvalidOperationException("Verified pre-key claim ownership was lost.");

    private static void Zero(ref byte[]? value)
    {
        var owned = Interlocked.Exchange(ref value, null);
        if (owned is not null)
            CryptographicOperations.ZeroMemory(owned);
    }

    internal sealed class ProtocolClaimPayload(
        Dpk2PrekeyKind kind,
        ushort lastResortUseCounter,
        byte[] operationId,
        byte[] sessionId,
        byte[] exactDpk2Hash,
        byte[] xpc1FullReplayHash,
        byte[] dph2FullReplayHash,
        byte[] x25519PreKeyId,
        byte[] mlKemPreKeyId,
        VerifiedDph2Initiation initiation) : IDisposable
    {
        internal Dpk2PrekeyKind Kind { get; } = kind;
        internal ushort LastResortUseCounter { get; } = lastResortUseCounter;
        internal byte[] OperationId { get; } = operationId;
        internal byte[] SessionId { get; } = sessionId;
        internal byte[] ExactDpk2Hash { get; } = exactDpk2Hash;
        internal byte[] Xpc1FullReplayHash { get; } = xpc1FullReplayHash;
        internal byte[] Dph2FullReplayHash { get; } = dph2FullReplayHash;
        internal byte[] X25519PreKeyId { get; } = x25519PreKeyId;
        internal byte[] MlKemPreKeyId { get; } = mlKemPreKeyId;
        internal VerifiedDph2Initiation Initiation { get; } = initiation;

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(OperationId);
            CryptographicOperations.ZeroMemory(SessionId);
            CryptographicOperations.ZeroMemory(ExactDpk2Hash);
            CryptographicOperations.ZeroMemory(Xpc1FullReplayHash);
            CryptographicOperations.ZeroMemory(Dph2FullReplayHash);
            CryptographicOperations.ZeroMemory(X25519PreKeyId);
            CryptographicOperations.ZeroMemory(MlKemPreKeyId);
        }
    }
}

/// <summary>
/// Verifier-minted, single-owner reservation facts for the device-wide private
/// pre-key store. All byte properties return defensive copies.
/// </summary>
public sealed class VerifiedDevicePreKeyClaimReservation : IDisposable
{
    private byte[]? _operationId;
    private byte[]? _sessionId;
    private byte[]? _exactDpk2Hash;
    private byte[]? _xpc1FullReplayHash;
    private byte[]? _dph2FullReplayHash;
    private byte[]? _x25519PreKeyId;
    private byte[]? _mlKemPreKeyId;

    internal VerifiedDevicePreKeyClaimReservation(
        Dpk2PrekeyKind kind,
        ushort lastResortUseCounter,
        byte[] operationId,
        byte[] sessionId,
        byte[] exactDpk2Hash,
        byte[] xpc1FullReplayHash,
        byte[] dph2FullReplayHash,
        byte[] x25519PreKeyId,
        byte[] mlKemPreKeyId)
    {
        Kind = kind;
        LastResortUseCounter = lastResortUseCounter;
        _operationId = operationId;
        _sessionId = sessionId;
        _exactDpk2Hash = exactDpk2Hash;
        _xpc1FullReplayHash = xpc1FullReplayHash;
        _dph2FullReplayHash = dph2FullReplayHash;
        _x25519PreKeyId = x25519PreKeyId;
        _mlKemPreKeyId = mlKemPreKeyId;
    }

    public Dpk2PrekeyKind Kind { get; }
    public ushort LastResortUseCounter { get; }
    public ReadOnlyMemory<byte> OperationId => Copy(_operationId);
    public ReadOnlyMemory<byte> SessionId => Copy(_sessionId);
    public ReadOnlyMemory<byte> ExactDpk2Hash => Copy(_exactDpk2Hash);
    public ReadOnlyMemory<byte> Xpc1FullReplayHash => Copy(_xpc1FullReplayHash);
    public ReadOnlyMemory<byte> Dph2FullReplayHash => Copy(_dph2FullReplayHash);
    public ReadOnlyMemory<byte> X25519PreKeyId => Copy(_x25519PreKeyId);
    public ReadOnlyMemory<byte> MlKemPreKeyId => Copy(_mlKemPreKeyId);

    public void Dispose()
    {
        Zero(ref _operationId);
        Zero(ref _sessionId);
        Zero(ref _exactDpk2Hash);
        Zero(ref _xpc1FullReplayHash);
        Zero(ref _dph2FullReplayHash);
        Zero(ref _x25519PreKeyId);
        Zero(ref _mlKemPreKeyId);
    }

    private static ReadOnlyMemory<byte> Copy(byte[]? value) =>
        (value ?? throw new ObjectDisposedException(nameof(VerifiedDevicePreKeyClaimReservation))).ToArray();

    private static void Zero(ref byte[]? value)
    {
        var owned = Interlocked.Exchange(ref value, null);
        if (owned is not null)
            CryptographicOperations.ZeroMemory(owned);
    }
}
