using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV1;

public sealed class Xpc1PreKeyClaimReceiptException : CryptographicException
{
    internal Xpc1PreKeyClaimReceiptException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Non-serializable proof that one exact XPK1 was durably claimed by the two
/// current PreKeyClaim replicas and returned the exact recipient-bound DPK2.
/// It deliberately exposes identifiers and hashes, never receipt bytes or keys.
/// </summary>
public sealed class VerifiedXpc1PreKeyClaimReceipt
{
    private readonly VerifiedDpk2Offering _offering;
    private readonly byte[] _networkId;
    private readonly byte[] _operationId;
    private readonly byte[] _requestHash;
    private readonly byte[] _claimReceiptHash;
    private readonly byte[] _exactDpk2Hash;
    private readonly byte[] _xpi1Hash;
    private readonly byte[] _responderAccountId;
    private readonly byte[] _responderDeviceId;
    private readonly byte[] _signedX25519PrekeyId;
    private readonly byte[] _selectedOneTimePrekeyId;
    private readonly byte[] _mlKemPrekeyId;
    private readonly byte[] _senderEphemeralCommitment;
    private readonly byte[] _fullExactReplayHash;
    private readonly byte[][] _replicaNodeIds;
    private int _handshakeConsumed;

    internal VerifiedXpc1PreKeyClaimReceipt(
        Xpk1Request request,
        Xpc1Result result,
        Dpk2Record dpk2,
        ReadOnlySpan<byte> exactDpk2Hash,
        ReadOnlySpan<byte> fullExactReplayHash,
        IReadOnlyList<VerifiedNetworkNode> replicas)
    {
        _offering = new VerifiedDpk2Offering(dpk2, exactDpk2Hash.ToArray());
        _networkId = request.NetworkId.ToArray();
        _operationId = request.OperationId.ToArray();
        _requestHash = request.RequestHash.ToArray();
        _claimReceiptHash = result.Field(18).ToArray();
        _exactDpk2Hash = exactDpk2Hash.ToArray();
        _xpi1Hash = Xpi1Codec.ComputeHash(result.FieldSpan(26));
        _responderAccountId = dpk2.ResponderAccountId.ToArray();
        _responderDeviceId = dpk2.ResponderDeviceId.ToArray();
        ResponderDeviceGeneration = dpk2.ResponderDeviceGeneration;
        _signedX25519PrekeyId = dpk2.SignedX25519PrekeyId.ToArray();
        _selectedOneTimePrekeyId = result.Field(17).ToArray();
        _mlKemPrekeyId = dpk2.MlKemPrekeyId.ToArray();
        _senderEphemeralCommitment = request.SenderEphemeralCommitment.ToArray();
        _fullExactReplayHash = fullExactReplayHash.ToArray();
        PrekeyKind = dpk2.MlKemKind;
        ServiceGeneration = ServiceWire.U64(result.FieldSpan(21));
        PrekeyExpiresAtUnixSeconds = ServiceWire.U64(result.FieldSpan(22));
        LastResortUseCounter = ServiceWire.U16(result.FieldSpan(23));
        ClaimCommitGeneration = ServiceWire.U64(result.FieldSpan(24));
        InventoryEpoch = Xpi1Codec.Decode(result.FieldSpan(26)).InventoryEpoch;
        InventoryIndex = ServiceWire.U16(result.FieldSpan(27));
        ServerTimeUnixSeconds = result.ServerTimeUnixSeconds;
        Status = result.Status;
        _replicaNodeIds = replicas
            .OrderBy(static replica => replica.NodeId, ByteArrayComparer.Instance)
            .Select(static replica => replica.NodeId.ToArray())
            .ToArray();
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static VerifiedXpc1PreKeyClaimReceipt CreateInitiatorRecoveryTestReceipt(
        Dpk2Record dpk2,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> claimReceiptHash,
        ReadOnlySpan<byte> senderEphemeralCommitment,
        ushort lastResortUseCounter)
    {
        ArgumentNullException.ThrowIfNull(dpk2);
        return new VerifiedXpc1PreKeyClaimReceipt(
            dpk2,
            operationId,
            claimReceiptHash,
            senderEphemeralCommitment,
            lastResortUseCounter);
    }

    private VerifiedXpc1PreKeyClaimReceipt(
        Dpk2Record dpk2,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> claimReceiptHash,
        ReadOnlySpan<byte> senderEphemeralCommitment,
        ushort lastResortUseCounter)
    {
        if (operationId.Length != 32 || operationId.IndexOfAnyExcept((byte)0) < 0 ||
            claimReceiptHash.Length != 32 || claimReceiptHash.IndexOfAnyExcept((byte)0) < 0 ||
            senderEphemeralCommitment.Length != 32 || senderEphemeralCommitment.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Recovery-test receipt values must be exact nonzero 32-byte values.");
        if ((dpk2.MlKemKind == Dpk2PrekeyKind.OneTime && lastResortUseCounter != 0) ||
            (dpk2.MlKemKind == Dpk2PrekeyKind.LastResort &&
             (lastResortUseCounter is < 1 or > 64 || lastResortUseCounter > dpk2.ReuseLimit)))
            throw new ArgumentOutOfRangeException(nameof(lastResortUseCounter));

        var exactDpk2Hash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(dpk2);
        _offering = new VerifiedDpk2Offering(dpk2, exactDpk2Hash);
        _networkId = dpk2.NetworkId.ToArray();
        _operationId = operationId.ToArray();
        _requestHash = SHA256.HashData(operationId);
        _claimReceiptHash = claimReceiptHash.ToArray();
        _exactDpk2Hash = exactDpk2Hash;
        _xpi1Hash = SHA256.HashData(dpk2.BundleId.Span);
        _responderAccountId = dpk2.ResponderAccountId.ToArray();
        _responderDeviceId = dpk2.ResponderDeviceId.ToArray();
        ResponderDeviceGeneration = dpk2.ResponderDeviceGeneration;
        _signedX25519PrekeyId = dpk2.SignedX25519PrekeyId.ToArray();
        _selectedOneTimePrekeyId = dpk2.MlKemKind == Dpk2PrekeyKind.OneTime
            ? dpk2.OneTimeX25519PrekeyId.ToArray()
            : new byte[32];
        _mlKemPrekeyId = dpk2.MlKemPrekeyId.ToArray();
        _senderEphemeralCommitment = senderEphemeralCommitment.ToArray();
        _fullExactReplayHash = SHA256.HashData(claimReceiptHash);
        PrekeyKind = dpk2.MlKemKind;
        ServiceGeneration = dpk2.PrekeyServiceGeneration;
        PrekeyExpiresAtUnixSeconds = dpk2.ExpiresAt;
        LastResortUseCounter = lastResortUseCounter;
        ClaimCommitGeneration = 1;
        InventoryEpoch = dpk2.InventoryEpoch;
        InventoryIndex = 0;
        ServerTimeUnixSeconds = dpk2.NotBefore;
        Status = Xpc1Status.Claimed;
        _replicaNodeIds = [];
    }
#endif

    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    /// <summary>
    /// The exact DPK2 selected and authenticated by this XPC1 receipt. This is
    /// public pre-key material; the corresponding secrets remain solely with
    /// the responder's pre-key owner.
    /// </summary>
    public VerifiedDpk2Offering Offering => _offering;
    public ReadOnlyMemory<byte> OperationId => _operationId.ToArray();
    public ReadOnlyMemory<byte> RequestHash => _requestHash.ToArray();
    public ReadOnlyMemory<byte> ClaimReceiptHash => _claimReceiptHash.ToArray();
    public ReadOnlyMemory<byte> ExactDpk2Hash => _exactDpk2Hash.ToArray();
    public ReadOnlyMemory<byte> Xpi1Hash => _xpi1Hash.ToArray();
    public ReadOnlyMemory<byte> ResponderAccountId => _responderAccountId.ToArray();
    public ReadOnlyMemory<byte> ResponderDeviceId => _responderDeviceId.ToArray();
    public ulong ResponderDeviceGeneration { get; }
    public ReadOnlyMemory<byte> SignedX25519PrekeyId => _signedX25519PrekeyId.ToArray();
    public ReadOnlyMemory<byte> SelectedOneTimePrekeyId => _selectedOneTimePrekeyId.ToArray();
    public ReadOnlyMemory<byte> MlKemPrekeyId => _mlKemPrekeyId.ToArray();
    public Dpk2PrekeyKind PrekeyKind { get; }
    public ulong ServiceGeneration { get; }
    public ulong PrekeyExpiresAtUnixSeconds { get; }
    public ushort LastResortUseCounter { get; }
    public ulong ClaimCommitGeneration { get; }
    public ulong InventoryEpoch { get; }
    public ushort InventoryIndex { get; }
    public ulong ServerTimeUnixSeconds { get; }
    public Xpc1Status Status { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ReplicaNodeIds =>
        Array.AsReadOnly(_replicaNodeIds.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());

    /// <summary>
    /// Binds this witnessed claim to the exact verified responder-side DPH2 and
    /// transfers it into the two-lane initial-session boundary. The returned
    /// capability can be constructed only by this verifier: one lane authorizes
    /// the device-wide private pre-key owner, while the other remains reserved
    /// for Protocol's handshake state machine.
    /// </summary>
    public VerifiedInitialSessionPreKeyClaim BindForInitialSession(
        VerifiedDph2Initiation initiation)
    {
        var binding = ConsumeForHandshake(initiation);
        return new VerifiedInitialSessionPreKeyClaim(
            PrekeyKind,
            LastResortUseCounter,
            _operationId,
            binding.SessionId,
            _exactDpk2Hash,
            binding.Xpc1FullReplayHash,
            binding.Dph2FullReplayHash,
            PrekeyKind == Dpk2PrekeyKind.OneTime ? _selectedOneTimePrekeyId : [],
            _mlKemPrekeyId,
            initiation);
    }

    internal VerifiedXpc1Dph2Binding ConsumeForHandshake(VerifiedDph2Initiation initiation)
    {
        ArgumentNullException.ThrowIfNull(initiation);
        RequireMatchesDph2Header(initiation.Record);
        if (Interlocked.CompareExchange(ref _handshakeConsumed, 1, 0) != 0)
            Fail("ClaimCapabilityConsumed", "The verified XPC1 claim capability is single-use at the handshake boundary.");
        return new VerifiedXpc1Dph2Binding(
            initiation.Record.SessionId.Span,
            _requestHash,
            _fullExactReplayHash,
            initiation.FullReplayHash.Span);
    }

    /// <summary>
    /// Rechecks the immutable tags 1..19 that XPC1 authenticated without
    /// consuming the claim. This exists for the initiator's pre-encryption
    /// transcript pass; only <see cref="ConsumeForHandshake"/> can spend the
    /// receipt after the final tag-20 ciphertext has been verified.
    /// </summary>
    internal void RequireMatchesDph2Header(Dph2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var senderCommitment = MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(record);
        try
        {
            if (!Fixed(_networkId, record.NetworkId.Span) ||
                !Fixed(_responderAccountId, record.ResponderAccountId.Span) ||
                !Fixed(_responderDeviceId, record.ResponderDeviceId.Span) ||
                ResponderDeviceGeneration != record.ResponderDeviceGeneration ||
                !Fixed(_operationId, record.ClaimOperationId.Span) ||
                !Fixed(_claimReceiptHash, record.ClaimReceiptHash.Span) ||
                !Fixed(_exactDpk2Hash, record.ExactDpk2Hash.Span) ||
                !Fixed(_signedX25519PrekeyId, record.SelectedPrekey.SignedX25519PrekeyId.Span) ||
                !Fixed(_selectedOneTimePrekeyId, record.SelectedPrekey.OneTimeX25519PrekeyIdOrZero.Span) ||
                !Fixed(_mlKemPrekeyId, record.SelectedPrekey.MlKemPrekeyId.Span) ||
                PrekeyKind != record.SelectedPrekey.Kind ||
                LastResortUseCounter != record.LastResortUseCounter ||
                !Fixed(_senderEphemeralCommitment, senderCommitment))
                Fail("Dph2ClaimBindingMismatch", "DPH2 does not reproduce the exact verified XPC1 claim closure.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(senderCommitment);
        }
    }

    internal static void RequireExactReplay(
        VerifiedXpc1PreKeyClaimReceipt retained,
        VerifiedXpc1PreKeyClaimReceipt candidate)
    {
        ArgumentNullException.ThrowIfNull(retained);
        ArgumentNullException.ThrowIfNull(candidate);
        if (!Fixed(retained._operationId, candidate._operationId) ||
            !Fixed(retained._requestHash, candidate._requestHash) ||
            !Fixed(retained._fullExactReplayHash, candidate._fullExactReplayHash))
            Fail("ChangedClaimReplay", "An XPC1 replay changed its operation, request, or exact canonical result.");
    }

    internal void RequireExactJournalResult(Xpk1Request request, Xpc1Result result)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(result);
        var fullReplayHash = Xpc1PreKeyClaimReceiptVerifier.ComputeFullExactReplayHash(request, result);
        try
        {
            if (!Fixed(_operationId, request.OperationId.Span) ||
                !Fixed(_requestHash, request.RequestHash.Span) ||
                !Fixed(_operationId, result.OperationId.Span) ||
                !Fixed(_requestHash, result.RequestHash.Span) ||
                !Fixed(_claimReceiptHash, result.Field(18).Span) ||
                !Fixed(_fullExactReplayHash, fullReplayHash))
                Fail("ChangedClaimReplay", "The verified XPC1 receipt does not bind the exact journal result.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fullReplayHash);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new Xpc1PreKeyClaimReceiptException(code, message);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}

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

internal sealed class VerifiedXpc1Dph2Binding
{
    private readonly byte[] _sessionId;
    private readonly byte[] _requestHash;
    private readonly byte[] _xpc1FullReplayHash;
    private readonly byte[] _dph2FullReplayHash;

    internal VerifiedXpc1Dph2Binding(
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> requestHash,
        ReadOnlySpan<byte> xpc1FullReplayHash,
        ReadOnlySpan<byte> dph2FullReplayHash)
    {
        _sessionId = sessionId.ToArray();
        _requestHash = requestHash.ToArray();
        _xpc1FullReplayHash = xpc1FullReplayHash.ToArray();
        _dph2FullReplayHash = dph2FullReplayHash.ToArray();
    }

    internal ReadOnlySpan<byte> SessionId => _sessionId;
    internal ReadOnlySpan<byte> RequestHash => _requestHash;
    internal ReadOnlySpan<byte> Xpc1FullReplayHash => _xpc1FullReplayHash;
    internal ReadOnlySpan<byte> Dph2FullReplayHash => _dph2FullReplayHash;
}

public static class Xpc1PreKeyClaimReceiptVerifier
{
    private const string ReceiptSignatureDomain = "Deep/ContactResolver/V1/prekey-claim-commit";
    private const string ExactReplayDomain = "Deep/ContactResolver/V1/exact-prekey-claim-replay";
    private const int ReceiptCount = 2;
    private const int ReceiptWidth = 96;
    private const int ReceiptContainerLength = 1 + (ReceiptCount * ReceiptWidth);
    private const int ReceiptTranscriptLength = 138;

    public static async ValueTask<VerifiedXpc1PreKeyClaimReceipt> VerifyAsync(
        Xpk1Request request,
        Xpc1Result result,
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority authority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(placement);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(recipientBundle);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var reading = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
            var interval = VerifyTrustedTime(reading, request, result, placement, authority);
            VerifyPlacementAndCorrelation(request, result, placement, authority);
            var xps1 = FindRecipientXps1(recipientBundle, authority);
            var dpk2 = Dpk2Codec.Decode(result.FieldSpan(16));
            var manifest = Xpi1Codec.Decode(result.FieldSpan(26));
            VerifyRecipientBundleAndDpk2(request, result, recipientBundle, authority, xps1, dpk2, manifest, interval);
            VerifyDpk2Signatures(dpk2, authority.RecipientDeviceSigningPublicKeySpan);
            var exactDpk2Hash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(dpk2);
            var replicas = placement.ResolveSelectedReplicas();
            VerifyReplicaReceipts(request, result, exactDpk2Hash, manifest, replicas);
            var fullReplayHash = ComputeFullExactReplayHash(request, result);
            return new VerifiedXpc1PreKeyClaimReceipt(
                request, result, dpk2, exactDpk2Hash, fullReplayHash, replicas);
        }
        catch (Xpc1PreKeyClaimReceiptException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (OnionBoundaryException exception)
        {
            throw new Xpc1PreKeyClaimReceiptException(
                "PlacementNotCurrent", "The exact PreKeyClaim placement or trusted-time lease is no longer current.", exception);
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or
            CryptographicException or OverflowException)
        {
            throw new Xpc1PreKeyClaimReceiptException(
                "InvalidPreKeyClaimReceipt", "The exact XPK1/XPC1 pre-key claim closure is invalid.", exception);
        }
    }

    private static (ulong Lower, ulong Upper) VerifyTrustedTime(
        OnionMonotonicReading reading,
        Xpk1Request request,
        Xpc1Result result,
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority authority)
    {
        var lease = placement.Network.TrustedTime ??
            throw new Xpc1PreKeyClaimReceiptException(
                "PlacementTimeMissing", "The verified PreKeyClaim placement has no trusted-time lease.");
        lease.EnsureLive();
        if (!Fixed(reading.BootId.Span, authority.MonotonicBootIdSpan) ||
            reading.SampleSeconds < authority.VerifiedAtMonotonicSeconds ||
            reading.SampleSeconds >= authority.FreshnessDeadlineMonotonicSeconds)
            Fail("TrustedTimeInvalid", "The current protected monotonic reading is outside the authority capability.");

        var elapsed = reading.SampleSeconds - authority.VerifiedAtMonotonicSeconds;
        var lower = checked(authority.TrustedLowerUnixSeconds + elapsed);
        var upper = checked(authority.TrustedUpperUnixSeconds + elapsed);
        if (authority.NotBeforeUnixSeconds > lower || upper >= authority.ExpiresAtUnixSeconds ||
            request.IssuedAtUnixSeconds > lower || upper >= request.ExpiresAtUnixSeconds ||
            result.ServerTimeUnixSeconds < lower || result.ServerTimeUnixSeconds > upper ||
            upper >= placement.ValidUntilUnixSeconds)
            Fail("ClaimTimeInvalid", "The complete trusted interval is not covered by request, result, authority and placement.");
        return (lower, upper);
    }

    private static void VerifyPlacementAndCorrelation(
        Xpk1Request request,
        Xpc1Result result,
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority authority)
    {
        if (result.Status is not (Xpc1Status.Claimed or Xpc1Status.Replay) ||
            result.MutationOutcome != ContactServiceMutationOutcome.DurablyCommitted ||
            result.RetryAfterSeconds != 0)
            Fail("NotDurablyClaimed", "Only a durably committed Claimed or exact Replay XPC1 can mint a claim capability.");

        if (!Fixed(request.OperationId.Span, request.ClaimOperationId.Span) ||
            !Fixed(result.NetworkId.Span, request.NetworkId.Span) ||
            !Fixed(result.OperationId.Span, request.OperationId.Span) ||
            !Fixed(result.RequestHash.Span, request.RequestHash.Span))
            Fail("RequestCorrelationMismatch", "XPC1 does not authenticate the exact XPK1 operation and request hash.");

        var viewReference = authority.Xnv1CoreReference.Span;
        var closure = placement.Network.Closure;
        if (!placement.Binds(ContactServiceRequestKind.ClaimPreKey, request.ServiceCapability) ||
            placement.RequestKind != ContactServiceRequestKind.ClaimPreKey ||
            placement.ServiceClass != ContactServiceClass.PreKeyClaim ||
            !Fixed(request.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(request.NetworkId.Span, placement.Network.NetworkId.Span) ||
            !Fixed(request.ViewHash.Span, placement.ViewHash.Span) ||
            !Fixed(request.PlacementHash.Span, placement.PlacementHash.Span) ||
            viewReference.Length != 38 || !Fixed(viewReference[6..], placement.ViewHash.Span) ||
            closure is null || !Fixed(closure.PmtArtifactReference, authority.Pmt2ArtifactReference.Span))
            Fail("PlacementMismatch", "XPK1 is not bound to the exact current ClaimPreKey placement and authority.");
    }

    private static ContactCodec.Xps1Record FindRecipientXps1(
        VerifiedContactBundleClosure bundle,
        VerifiedContactNetworkAuthority authority)
    {
        var list = bundle.Bundle.FieldSpan(12);
        var count = list[0];
        var offset = 1;
        ContactCodec.Xps1Record? selected = null;
        for (var index = 0; index < count; index++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(list.Slice(offset, 4)));
            offset += 4;
            var xps = ContactCodec.DecodeXps1(list.Slice(offset, length));
            offset += length;
            if (Fixed(xps.DeviceId, authority.RecipientDeviceId.Span))
            {
                if (selected is not null)
                    Fail("Xps1BindingMismatch", "The verified DCB1 contains duplicate XPS1 entries for the recipient.");
                selected = xps;
            }
        }
        if (offset != list.Length || selected is null)
            Fail("Xps1BindingMismatch", "The verified DCB1 has no exact XPS1 for the recipient device.");
        return selected;
    }

    private static void VerifyRecipientBundleAndDpk2(
        Xpk1Request request,
        Xpc1Result result,
        VerifiedContactBundleClosure bundle,
        VerifiedContactNetworkAuthority authority,
        ContactCodec.Xps1Record xps1,
        Dpk2Record dpk2,
        Xpi1Record manifest,
        (ulong Lower, ulong Upper) interval)
    {
        var dcb1Hash = bundle.Bundle.ArtifactHash.Span;
        var xps1Hash = SHA256.HashData(xps1.CanonicalBytes);
        var xps1Reference = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(ProtocolMagic.XPS1).CopyTo(xps1Reference, 0);
        BinaryPrimitives.WriteUInt16BigEndian(xps1Reference.AsSpan(4), 1);
        xps1Hash.CopyTo(xps1Reference, 6);
        try
        {
            if (!Fixed(bundle.Bundle.FieldSpan(1), authority.NetworkId.Span) ||
                !Fixed(bundle.Bundle.FieldSpan(2), authority.RecipientAccountIdSpan) ||
                !Fixed(bundle.Directory.Record.RecordHash.Span, authority.RecipientDmd1HashSpan) ||
                bundle.Directory.Record.DirectoryGeneration != authority.RecipientDmd1Generation ||
                !Fixed(bundle.Directory.Record.Drs1Reference.CanonicalBytes.Span, authority.RecipientDrs1ReferenceSpan) ||
                !MatchesArtifactReference(
                    authority.Dca1Reference.Span, ProtocolMagic.DCA1,
                    bundle.Authorization.Verified.Record.RecordHash.Span) ||
                !Fixed(request.Dcb1Hash.Span, dcb1Hash) ||
                !Fixed(request.Xps1Hash.Span, xps1Hash) ||
                !Fixed(request.ServiceCapability.Span, xps1.ServiceCapability) ||
                !Fixed(request.ResponderDeviceId.Span, xps1.DeviceId) ||
                !Fixed(xps1.NetworkId, authority.NetworkId.Span) ||
                !Fixed(xps1.Dpd1Reference, authority.RecipientDpd1Reference.Span) ||
                xps1.SupportedSuite != request.RequestedSuite)
                Fail("RecipientBundleMismatch", "XPK1 does not bind the exact current recipient DCB1/XPS1/DPD1 closure.");

            if (!Fixed(manifest.NetworkId.Span, authority.NetworkId.Span) ||
                !Fixed(manifest.ServiceCapability.Span, xps1.ServiceCapability) ||
                !Fixed(manifest.ResponderDeviceId.Span, authority.RecipientDeviceId.Span) ||
                !Fixed(manifest.ResponderDpd1Reference.Span, authority.RecipientDpd1Reference.Span) ||
                manifest.ServiceGeneration != xps1.ServiceGeneration ||
                !Fixed(manifest.Xps1Reference.Span, xps1Reference) ||
                manifest.OneTimeDpk2Count < xps1.MinimumOneTimeInventory ||
                !Fixed(manifest.CurrentDmd1Hash.Span, authority.RecipientDmd1HashSpan) ||
                !MatchesApplicationArtifactReference(
                    manifest.CurrentDrs1Reference.Span, ProtocolMagic.DRS1, authority.RecipientDrs1ReferenceSpan) ||
                xps1.IssuedAtUnixSeconds > manifest.IssuedAtUnixSeconds ||
                manifest.ExpiresAtUnixSeconds > xps1.ExpiresAtUnixSeconds ||
                manifest.IssuedAtUnixSeconds > interval.Lower ||
                interval.Upper >= manifest.ExpiresAtUnixSeconds)
                Fail("Xpi1RecipientMismatch", "The exact XPI1 is not bound to the current recipient identity and XPS1 closure.");

            try
            {
                ContactCodec.VerifyDeviceSignature(manifest.Record, authority.RecipientDeviceSigningPublicKeySpan);
                PreKeyInventoryPublicationVerifier.VerifyClaimMembership(
                    manifest, result.FieldSpan(16), ServiceWire.U16(result.FieldSpan(27)), result.FieldSpan(28));
            }
            catch (Exception exception) when (exception is FormatException or ArgumentException or CryptographicException)
            {
                throw new Xpc1PreKeyClaimReceiptException(
                    "Xpi1VerificationFailed", "The exact device-signed XPI1 or selected DPK2 membership proof is invalid.", exception);
            }

            if (!Fixed(dpk2.NetworkId.Span, authority.NetworkId.Span) ||
                !Fixed(dpk2.ResponderAccountId.Span, authority.RecipientAccountIdSpan) ||
                !Fixed(dpk2.ResponderDeviceId.Span, authority.RecipientDeviceId.Span) ||
                dpk2.ResponderDeviceGeneration != authority.RecipientDeviceGeneration ||
                !Fixed(dpk2.ResponderDpd1Ref.Span, authority.RecipientDpd1Reference.Span) ||
                !Fixed(dpk2.DeviceAgreementPublicKey.Span, authority.RecipientDeviceAgreementPublicKeySpan) ||
                dpk2.DeviceDirectoryGeneration != authority.RecipientDmd1Generation ||
                !Fixed(dpk2.DeviceDirectoryHeadHash.Span, authority.RecipientDmd1HashSpan) ||
                dpk2.PrekeyServiceGeneration != xps1.ServiceGeneration ||
                dpk2.InventoryEpoch != manifest.InventoryEpoch ||
                dpk2.NotBefore != manifest.IssuedAtUnixSeconds ||
                dpk2.IssuedAt > manifest.IssuedAtUnixSeconds ||
                dpk2.ExpiresAt != manifest.ExpiresAtUnixSeconds ||
                dpk2.PrekeyServiceGeneration != ServiceWire.U64(result.FieldSpan(21)) ||
                !Fixed(result.FieldSpan(19), authority.RecipientDmd1HashSpan) ||
                !MatchesApplicationArtifactReference(
                    result.FieldSpan(20), ProtocolMagic.DRS1, authority.RecipientDrs1ReferenceSpan))
                Fail("Dpk2RecipientMismatch", "The selected DPK2 is not bound to the exact current recipient identity and XPS1.");

            var selectedId = result.FieldSpan(17);
            if ((dpk2.MlKemKind == Dpk2PrekeyKind.OneTime &&
                    (!Fixed(selectedId, dpk2.OneTimeX25519PrekeyId.Span) || ServiceWire.U16(result.FieldSpan(23)) != 0)) ||
                (dpk2.MlKemKind == Dpk2PrekeyKind.LastResort &&
                    (!ServiceWire.IsZero(selectedId) || ServiceWire.U16(result.FieldSpan(23)) is 0 ||
                     ServiceWire.U16(result.FieldSpan(23)) > dpk2.ReuseLimit ||
                     ServiceWire.U16(result.FieldSpan(23)) > xps1.LastResortReuseLimit)) ||
                dpk2.ExpiresAt != ServiceWire.U64(result.FieldSpan(22)) ||
                ServiceWire.U64(result.FieldSpan(24)) == 0)
                Fail("PrekeySelectionMismatch", "XPC1 does not select the exact DPK2 pre-key IDs, counter and commit generation.");

            if (xps1.IssuedAtUnixSeconds > interval.Lower || interval.Upper >= xps1.ExpiresAtUnixSeconds ||
                ServiceWire.U64(bundle.Bundle.FieldSpan(17)) > interval.Lower ||
                interval.Upper >= ServiceWire.U64(bundle.Bundle.FieldSpan(18)) ||
                dpk2.NotBefore > interval.Lower || interval.Upper >= dpk2.ExpiresAt ||
                result.ServerTimeUnixSeconds < dpk2.NotBefore || result.ServerTimeUnixSeconds >= dpk2.ExpiresAt)
                Fail("ClaimTimeInvalid", "The complete trusted interval is not covered by DCB1, XPS1 and DPK2.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(xps1Hash);
            CryptographicOperations.ZeroMemory(xps1Reference);
        }
    }

    private static void VerifyDpk2Signatures(Dpk2Record dpk2, ReadOnlySpan<byte> signingKey)
    {
        var x25519Input = MessagingWireCryptographicInputs.GetX25519SignedPrekeySignatureInput(dpk2);
        var mlKemInput = MessagingWireCryptographicInputs.GetMlKemPrekeySignatureInput(dpk2);
        var bundleInput = MessagingWireCryptographicInputs.GetPrekeyBundleSignatureInput(dpk2);
        try
        {
            if (!VerifyEd25519(signingKey, x25519Input, dpk2.SignedX25519PrekeySignature.Span) ||
                !VerifyEd25519(signingKey, mlKemInput, dpk2.MlKemPrekeySignature.Span) ||
                !VerifyEd25519(signingKey, bundleInput, dpk2.BundleSignature.Span))
                Fail("Dpk2SignatureInvalid", "The exact DPK2 signatures do not verify under the recipient DPD1 key.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(x25519Input);
            CryptographicOperations.ZeroMemory(mlKemInput);
            CryptographicOperations.ZeroMemory(bundleInput);
        }
    }

    private static void VerifyReplicaReceipts(
        Xpk1Request request,
        Xpc1Result result,
        ReadOnlySpan<byte> exactDpk2Hash,
        Xpi1Record manifest,
        IReadOnlyList<VerifiedNetworkNode> selectedReplicas)
    {
        if (selectedReplicas.Count != ReceiptCount)
            Fail("ReplicaSetMismatch", "The exact ClaimPreKey placement must select exactly two replicas.");
        var replicas = selectedReplicas.OrderBy(static replica => replica.NodeId, ByteArrayComparer.Instance).ToArray();
        if (Fixed(replicas[0].NodeId, replicas[1].NodeId) ||
            Fixed(replicas[0].FailureDomainHash, replicas[1].FailureDomainHash))
            Fail("ReplicaDiversityInvalid", "Claim replicas must have distinct identities and failure domains.");

        var receipts = result.FieldSpan(25);
        if (receipts.Length != ReceiptContainerLength || receipts[0] != ReceiptCount)
            Fail("ReplicaReceiptShapeInvalid", "XPC1 must contain exactly two canonical replica receipts.");

        var transcript = new byte[ReceiptTranscriptLength];
        byte[]? signatureInput = null;
        try
        {
            request.RequestHash.Span.CopyTo(transcript);
            exactDpk2Hash.CopyTo(transcript.AsSpan(32));
            var xpi1Hash = Xpi1Codec.ComputeHash(manifest.CanonicalBytes.Span);
            xpi1Hash.CopyTo(transcript.AsSpan(64));
            result.FieldSpan(17).CopyTo(transcript.AsSpan(96));
            BinaryPrimitives.WriteUInt64BigEndian(transcript.AsSpan(128), ServiceWire.U64(result.FieldSpan(24)));
            BinaryPrimitives.WriteUInt16BigEndian(transcript.AsSpan(136), ServiceWire.U16(result.FieldSpan(23)));
            CryptographicOperations.ZeroMemory(xpi1Hash);
            signatureInput = ContactCodec.SignatureInput(ReceiptSignatureDomain, transcript);

            for (var index = 0; index < ReceiptCount; index++)
            {
                var row = receipts.Slice(1 + (index * ReceiptWidth), ReceiptWidth);
                var identityKey = replicas[index].IdentityPublicKey;
                if (!Fixed(row[..32], replicas[index].NodeId) || identityKey is not { Length: 32 } ||
                    !VerifyEd25519(identityKey, signatureInput, row[32..]))
                    Fail("ReplicaSignatureInvalid", "An XPC1 receipt is not signed by the exact selected replica identity key.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(transcript);
            if (signatureInput is not null) CryptographicOperations.ZeroMemory(signatureInput);
        }
    }

    internal static byte[] ComputeFullExactReplayHash(Xpk1Request request, Xpc1Result result)
    {
        var requestBytes = request.CanonicalBytes.Span;
        var resultBytes = result.CanonicalBytes.Span;
        var tuple = new byte[checked(8 + requestBytes.Length + resultBytes.Length)];
        BinaryPrimitives.WriteUInt32BigEndian(tuple, checked((uint)requestBytes.Length));
        requestBytes.CopyTo(tuple.AsSpan(4));
        var offset = 4 + requestBytes.Length;
        BinaryPrimitives.WriteUInt32BigEndian(tuple.AsSpan(offset), checked((uint)resultBytes.Length));
        resultBytes.CopyTo(tuple.AsSpan(offset + 4));
        try
        {
            return ContactCodec.Sha256Domain(ExactReplayDomain, tuple);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tuple);
        }
    }

    private static bool VerifyEd25519(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64) return false;
        try { return PublicKeyAuth.VerifyDetached(signature.ToArray(), message.ToArray(), publicKey.ToArray()); }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException) { return false; }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static bool MatchesArtifactReference(
        ReadOnlySpan<byte> reference,
        ReadOnlySpan<char> magic,
        ReadOnlySpan<byte> hash) =>
        reference.Length == 38 && hash.Length == 32 &&
        reference[..4].SequenceEqual(System.Text.Encoding.ASCII.GetBytes(magic.ToString())) &&
        BinaryPrimitives.ReadUInt16BigEndian(reference[4..6]) == 1 &&
        Fixed(reference[6..], hash);

    private static bool MatchesApplicationArtifactReference(
        ReadOnlySpan<byte> contactReference,
        ReadOnlySpan<char> magic,
        ReadOnlySpan<byte> applicationReference) =>
        applicationReference.Length == 38 &&
        contactReference.Length == 38 &&
        contactReference[..4].SequenceEqual(System.Text.Encoding.ASCII.GetBytes(magic.ToString())) &&
        BinaryPrimitives.ReadUInt16BigEndian(contactReference[4..6]) == 1 &&
        Fixed(contactReference[6..], applicationReference[6..]);

    [DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new Xpc1PreKeyClaimReceiptException(code, message);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
