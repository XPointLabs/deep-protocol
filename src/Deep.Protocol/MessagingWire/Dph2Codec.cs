using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.MessagingWire;

public sealed class Dph2InitialCiphertext
{
    private readonly byte[] _ciphertext;

    private Dph2InitialCiphertext(ReadOnlySpan<byte> ciphertext)
    {
        if (!IsAllowed(ciphertext.Length))
            throw new ArgumentException("DPH2 initial ciphertext must be exactly 4112, 16400 or 32784 bytes.", nameof(ciphertext));
        _ciphertext = ciphertext.ToArray();
    }

    public int Length => _ciphertext.Length;

    public static Dph2InitialCiphertext Import(ReadOnlySpan<byte> ciphertext) => new(ciphertext);

    public void CopyCiphertextTo(Span<byte> destination)
    {
        if (destination.Length != _ciphertext.Length)
            throw new ArgumentException("The destination must have the exact ciphertext length.", nameof(destination));
        _ciphertext.CopyTo(destination);
    }

    internal ReadOnlySpan<byte> Span => _ciphertext;
    internal static bool IsAllowed(int length) => length is 4112 or 16400 or 32784;
}

public sealed class Dph2SelectedPrekey
{
    private readonly byte[] _signedX25519PrekeyId;
    private readonly byte[] _oneTimeX25519PrekeyIdOrZero;
    private readonly byte[] _mlKemPrekeyId;

    private Dph2SelectedPrekey(
        ReadOnlySpan<byte> signedX25519PrekeyId,
        ReadOnlySpan<byte> oneTimeX25519PrekeyIdOrZero,
        ReadOnlySpan<byte> mlKemPrekeyId,
        Dpk2PrekeyKind kind)
    {
        NonZeroExact(signedX25519PrekeyId, nameof(signedX25519PrekeyId));
        Exact(oneTimeX25519PrekeyIdOrZero, nameof(oneTimeX25519PrekeyIdOrZero));
        NonZeroExact(mlKemPrekeyId, nameof(mlKemPrekeyId));
        if (kind == Dpk2PrekeyKind.OneTime)
        {
            if (MessagingWireFraming.IsZero(oneTimeX25519PrekeyIdOrZero))
                throw new ArgumentException("A one-time selection requires a nonzero one-time X25519 ID.", nameof(oneTimeX25519PrekeyIdOrZero));
        }
        else if (kind == Dpk2PrekeyKind.LastResort)
        {
            if (!MessagingWireFraming.IsZero(oneTimeX25519PrekeyIdOrZero))
                throw new ArgumentException("A last-resort selection requires ZERO32 for the one-time ID.", nameof(oneTimeX25519PrekeyIdOrZero));
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(kind), "The selected prekey kind is unknown.");
        }

        _signedX25519PrekeyId = signedX25519PrekeyId.ToArray();
        _oneTimeX25519PrekeyIdOrZero = oneTimeX25519PrekeyIdOrZero.ToArray();
        _mlKemPrekeyId = mlKemPrekeyId.ToArray();
        Kind = kind;
    }

    public ReadOnlyMemory<byte> SignedX25519PrekeyId => MessagingWireOwned.PublicCopy(_signedX25519PrekeyId);
    public ReadOnlyMemory<byte> OneTimeX25519PrekeyIdOrZero => MessagingWireOwned.PublicCopy(_oneTimeX25519PrekeyIdOrZero);
    public ReadOnlyMemory<byte> MlKemPrekeyId => MessagingWireOwned.PublicCopy(_mlKemPrekeyId);
    public Dpk2PrekeyKind Kind { get; }

    public static Dph2SelectedPrekey OneTime(
        ReadOnlySpan<byte> signedX25519PrekeyId,
        ReadOnlySpan<byte> oneTimeX25519PrekeyId,
        ReadOnlySpan<byte> mlKemPrekeyId) =>
        new(signedX25519PrekeyId, oneTimeX25519PrekeyId, mlKemPrekeyId, Dpk2PrekeyKind.OneTime);

    public static Dph2SelectedPrekey LastResort(
        ReadOnlySpan<byte> signedX25519PrekeyId,
        ReadOnlySpan<byte> mlKemPrekeyId) =>
        new(signedX25519PrekeyId, new byte[32], mlKemPrekeyId, Dpk2PrekeyKind.LastResort);

    internal ReadOnlySpan<byte> SignedX25519PrekeyIdSpan => _signedX25519PrekeyId;
    internal ReadOnlySpan<byte> OneTimeX25519PrekeyIdOrZeroSpan => _oneTimeX25519PrekeyIdOrZero;
    internal ReadOnlySpan<byte> MlKemPrekeyIdSpan => _mlKemPrekeyId;

    internal byte[] Encode()
    {
        var output = new byte[97];
        _signedX25519PrekeyId.CopyTo(output, 0);
        _oneTimeX25519PrekeyIdOrZero.CopyTo(output, 32);
        _mlKemPrekeyId.CopyTo(output, 64);
        output[96] = (byte)Kind;
        return output;
    }

    internal static Dph2SelectedPrekey DecodeValidated(ReadOnlySpan<byte> value) =>
        new(value[..32], value[32..64], value[64..96], (Dpk2PrekeyKind)value[96]);

    private static void Exact(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32)
            throw new ArgumentException($"{name} must be exactly 32 bytes.", name);
    }

    private static void NonZeroExact(ReadOnlySpan<byte> value, string name)
    {
        Exact(value, name);
        if (MessagingWireFraming.IsZero(value))
            throw new ArgumentException($"{name} cannot be all-zero.", name);
    }
}

public sealed class Dph2Record
{
    private readonly byte[] _networkId;
    private readonly byte[] _initiatorAccountId;
    private readonly byte[] _initiatorDeviceId;
    private readonly byte[] _initiatorDpd1Ref;
    private readonly byte[] _responderAccountId;
    private readonly byte[] _responderDeviceId;
    private readonly byte[] _exactDpk2Hash;
    private readonly byte[] _claimOperationId;
    private readonly byte[] _claimReceiptHash;
    private readonly byte[] _sessionId;
    private readonly byte[] _initiatorDeviceAgreementPublicKey;
    private readonly byte[] _initiatorEphemeralX25519PublicKey;
    private readonly byte[] _actualMlKem768Ciphertext;
    private readonly byte[] _initiatorInitialRatchetX25519PublicKey;
    private readonly byte[] _initialPayloadNonce;

    public Dph2Record(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> initiatorAccountId,
        ReadOnlySpan<byte> initiatorDeviceId,
        ulong initiatorDeviceGeneration,
        ReadOnlySpan<byte> initiatorDpd1Ref,
        ReadOnlySpan<byte> responderAccountId,
        ReadOnlySpan<byte> responderDeviceId,
        ulong responderDeviceGeneration,
        ReadOnlySpan<byte> exactDpk2Hash,
        ReadOnlySpan<byte> claimOperationId,
        ReadOnlySpan<byte> claimReceiptHash,
        ushort lastResortUseCounter,
        ReadOnlySpan<byte> initiatorDeviceAgreementPublicKey,
        ReadOnlySpan<byte> initiatorEphemeralX25519PublicKey,
        Dph2SelectedPrekey selectedPrekey,
        ReadOnlySpan<byte> actualMlKem768Ciphertext,
        ReadOnlySpan<byte> initiatorInitialRatchetX25519PublicKey,
        ReadOnlySpan<byte> initialPayloadNonce,
        Dph2InitialCiphertext initialCiphertext)
        : this(
            networkId,
            initiatorAccountId,
            initiatorDeviceId,
            initiatorDeviceGeneration,
            initiatorDpd1Ref,
            responderAccountId,
            responderDeviceId,
            responderDeviceGeneration,
            exactDpk2Hash,
            claimOperationId,
            claimReceiptHash,
            lastResortUseCounter,
            ReadOnlySpan<byte>.Empty,
            initiatorDeviceAgreementPublicKey,
            initiatorEphemeralX25519PublicKey,
            selectedPrekey,
            actualMlKem768Ciphertext,
            initiatorInitialRatchetX25519PublicKey,
            initialPayloadNonce,
            initialCiphertext,
            deriveSessionId: true)
    {
    }

    private Dph2Record(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> initiatorAccountId,
        ReadOnlySpan<byte> initiatorDeviceId,
        ulong initiatorDeviceGeneration,
        ReadOnlySpan<byte> initiatorDpd1Ref,
        ReadOnlySpan<byte> responderAccountId,
        ReadOnlySpan<byte> responderDeviceId,
        ulong responderDeviceGeneration,
        ReadOnlySpan<byte> exactDpk2Hash,
        ReadOnlySpan<byte> claimOperationId,
        ReadOnlySpan<byte> claimReceiptHash,
        ushort lastResortUseCounter,
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> initiatorDeviceAgreementPublicKey,
        ReadOnlySpan<byte> initiatorEphemeralX25519PublicKey,
        Dph2SelectedPrekey selectedPrekey,
        ReadOnlySpan<byte> actualMlKem768Ciphertext,
        ReadOnlySpan<byte> initiatorInitialRatchetX25519PublicKey,
        ReadOnlySpan<byte> initialPayloadNonce,
        Dph2InitialCiphertext initialCiphertext,
        bool deriveSessionId)
    {
        ArgumentNullException.ThrowIfNull(selectedPrekey);
        ArgumentNullException.ThrowIfNull(initialCiphertext);
        Validate(
            networkId,
            initiatorAccountId,
            initiatorDeviceId,
            initiatorDeviceGeneration,
            initiatorDpd1Ref,
            responderAccountId,
            responderDeviceId,
            responderDeviceGeneration,
            exactDpk2Hash,
            claimOperationId,
            claimReceiptHash,
            lastResortUseCounter,
            sessionId,
            deriveSessionId,
            initiatorDeviceAgreementPublicKey,
            initiatorEphemeralX25519PublicKey,
            selectedPrekey,
            actualMlKem768Ciphertext,
            initiatorInitialRatchetX25519PublicKey,
            initialPayloadNonce);

        _networkId = networkId.ToArray();
        _initiatorAccountId = initiatorAccountId.ToArray();
        _initiatorDeviceId = initiatorDeviceId.ToArray();
        InitiatorDeviceGeneration = initiatorDeviceGeneration;
        _initiatorDpd1Ref = initiatorDpd1Ref.ToArray();
        _responderAccountId = responderAccountId.ToArray();
        _responderDeviceId = responderDeviceId.ToArray();
        ResponderDeviceGeneration = responderDeviceGeneration;
        _exactDpk2Hash = exactDpk2Hash.ToArray();
        _claimOperationId = claimOperationId.ToArray();
        _claimReceiptHash = claimReceiptHash.ToArray();
        LastResortUseCounter = lastResortUseCounter;
        _initiatorDeviceAgreementPublicKey = initiatorDeviceAgreementPublicKey.ToArray();
        _initiatorEphemeralX25519PublicKey = initiatorEphemeralX25519PublicKey.ToArray();
        SelectedPrekey = selectedPrekey;
        _actualMlKem768Ciphertext = actualMlKem768Ciphertext.ToArray();
        _initiatorInitialRatchetX25519PublicKey = initiatorInitialRatchetX25519PublicKey.ToArray();
        _initialPayloadNonce = initialPayloadNonce.ToArray();
        InitialCiphertext = initialCiphertext;

        var derived = MessagingWireCryptographicInputs.ComputeDph2SessionId(BuildSessionIdValue());
        if (deriveSessionId)
        {
            _sessionId = derived;
        }
        else
        {
            if (!CryptographicOperations.FixedTimeEquals(derived, sessionId))
            {
                throw MessagingWireFraming.Error(
                    MessagingWirePrevalidationStage.HashProjection,
                    MessagingWireRejection.DerivedValueMismatch,
                    "DPH2 tag 13 does not equal the frozen non-circular session ID.");
            }

            _sessionId = sessionId.ToArray();
        }
    }

    public ReadOnlyMemory<byte> NetworkId => MessagingWireOwned.PublicCopy(_networkId);
    public ReadOnlyMemory<byte> InitiatorAccountId => MessagingWireOwned.PublicCopy(_initiatorAccountId);
    public ReadOnlyMemory<byte> InitiatorDeviceId => MessagingWireOwned.PublicCopy(_initiatorDeviceId);
    public ulong InitiatorDeviceGeneration { get; }
    public ReadOnlyMemory<byte> InitiatorDpd1Ref => MessagingWireOwned.PublicCopy(_initiatorDpd1Ref);
    public ReadOnlyMemory<byte> ResponderAccountId => MessagingWireOwned.PublicCopy(_responderAccountId);
    public ReadOnlyMemory<byte> ResponderDeviceId => MessagingWireOwned.PublicCopy(_responderDeviceId);
    public ulong ResponderDeviceGeneration { get; }
    public ReadOnlyMemory<byte> ExactDpk2Hash => MessagingWireOwned.PublicCopy(_exactDpk2Hash);
    public ReadOnlyMemory<byte> ClaimOperationId => MessagingWireOwned.PublicCopy(_claimOperationId);
    public ReadOnlyMemory<byte> ClaimReceiptHash => MessagingWireOwned.PublicCopy(_claimReceiptHash);
    public ushort LastResortUseCounter { get; }
    public ReadOnlyMemory<byte> SessionId => MessagingWireOwned.PublicCopy(_sessionId);
    public ReadOnlyMemory<byte> InitiatorDeviceAgreementPublicKey => MessagingWireOwned.PublicCopy(_initiatorDeviceAgreementPublicKey);
    public ReadOnlyMemory<byte> InitiatorEphemeralX25519PublicKey => MessagingWireOwned.PublicCopy(_initiatorEphemeralX25519PublicKey);
    public Dph2SelectedPrekey SelectedPrekey { get; }
    public ReadOnlyMemory<byte> ActualMlKem768Ciphertext => MessagingWireOwned.PublicCopy(_actualMlKem768Ciphertext);
    public ReadOnlyMemory<byte> InitiatorInitialRatchetX25519PublicKey => MessagingWireOwned.PublicCopy(_initiatorInitialRatchetX25519PublicKey);
    public ReadOnlyMemory<byte> InitialPayloadNonce => MessagingWireOwned.PublicCopy(_initialPayloadNonce);
    public Dph2InitialCiphertext InitialCiphertext { get; }

    internal ReadOnlySpan<byte> NetworkIdSpan => _networkId;
    internal ReadOnlySpan<byte> InitiatorAccountIdSpan => _initiatorAccountId;
    internal ReadOnlySpan<byte> InitiatorDeviceIdSpan => _initiatorDeviceId;
    internal ReadOnlySpan<byte> InitiatorDpd1RefSpan => _initiatorDpd1Ref;
    internal ReadOnlySpan<byte> ResponderAccountIdSpan => _responderAccountId;
    internal ReadOnlySpan<byte> ResponderDeviceIdSpan => _responderDeviceId;
    internal ReadOnlySpan<byte> ExactDpk2HashSpan => _exactDpk2Hash;
    internal ReadOnlyMemory<byte> ExactDpk2HashMemory => _exactDpk2Hash;
    internal ReadOnlySpan<byte> ClaimOperationIdSpan => _claimOperationId;
    internal ReadOnlyMemory<byte> ClaimOperationIdMemory => _claimOperationId;
    internal ReadOnlySpan<byte> ClaimReceiptHashSpan => _claimReceiptHash;
    internal ReadOnlyMemory<byte> ClaimReceiptHashMemory => _claimReceiptHash;
    internal ReadOnlySpan<byte> SessionIdSpan => _sessionId;
    internal ReadOnlyMemory<byte> SessionIdMemory => _sessionId;
    internal ReadOnlySpan<byte> InitiatorDeviceAgreementPublicKeySpan => _initiatorDeviceAgreementPublicKey;
    internal ReadOnlySpan<byte> InitiatorEphemeralX25519PublicKeySpan => _initiatorEphemeralX25519PublicKey;
    internal ReadOnlySpan<byte> ActualMlKem768CiphertextSpan => _actualMlKem768Ciphertext;
    internal ReadOnlySpan<byte> InitiatorInitialRatchetX25519PublicKeySpan => _initiatorInitialRatchetX25519PublicKey;
    internal ReadOnlySpan<byte> InitialPayloadNonceSpan => _initialPayloadNonce;

    internal byte[] BuildSenderEphemeralCommitmentValue() => MessagingWireCryptographicInputs.Concat(
        _networkId,
        _initiatorAccountId,
        _initiatorDeviceId,
        _initiatorDpd1Ref,
        _initiatorDeviceAgreementPublicKey,
        _initiatorEphemeralX25519PublicKey,
        _initiatorInitialRatchetX25519PublicKey);

    internal byte[] BuildSessionIdValue()
    {
        Span<byte> initiatorGeneration = stackalloc byte[8];
        Span<byte> responderGeneration = stackalloc byte[8];
        Span<byte> counter = stackalloc byte[2];
        BinaryPrimitives.WriteUInt64BigEndian(initiatorGeneration, InitiatorDeviceGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(responderGeneration, ResponderDeviceGeneration);
        BinaryPrimitives.WriteUInt16BigEndian(counter, LastResortUseCounter);
        return MessagingWireCryptographicInputs.Concat(
            _networkId,
            _initiatorAccountId,
            _initiatorDeviceId,
            initiatorGeneration.ToArray(),
            _initiatorDpd1Ref,
            _responderAccountId,
            _responderDeviceId,
            responderGeneration.ToArray(),
            _exactDpk2Hash,
            _claimOperationId,
            _claimReceiptHash,
            counter.ToArray(),
            SelectedPrekey.Encode(),
            _initiatorEphemeralX25519PublicKey,
            _actualMlKem768Ciphertext,
            _initiatorInitialRatchetX25519PublicKey);
    }

    private static void Validate(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> initiatorAccountId,
        ReadOnlySpan<byte> initiatorDeviceId,
        ulong initiatorDeviceGeneration,
        ReadOnlySpan<byte> initiatorDpd1Ref,
        ReadOnlySpan<byte> responderAccountId,
        ReadOnlySpan<byte> responderDeviceId,
        ulong responderDeviceGeneration,
        ReadOnlySpan<byte> exactDpk2Hash,
        ReadOnlySpan<byte> claimOperationId,
        ReadOnlySpan<byte> claimReceiptHash,
        ushort lastResortUseCounter,
        ReadOnlySpan<byte> sessionId,
        bool deriveSessionId,
        ReadOnlySpan<byte> initiatorDeviceAgreementPublicKey,
        ReadOnlySpan<byte> initiatorEphemeralX25519PublicKey,
        Dph2SelectedPrekey selectedPrekey,
        ReadOnlySpan<byte> actualMlKem768Ciphertext,
        ReadOnlySpan<byte> initiatorInitialRatchetX25519PublicKey,
        ReadOnlySpan<byte> initialPayloadNonce)
    {
        NonZeroExact(networkId, 16, nameof(networkId));
        NonZeroExact(initiatorAccountId, 32, nameof(initiatorAccountId));
        NonZeroExact(initiatorDeviceId, 32, nameof(initiatorDeviceId));
        Generation(initiatorDeviceGeneration, nameof(initiatorDeviceGeneration));
        Exact(initiatorDpd1Ref, 38, nameof(initiatorDpd1Ref));
        NonZeroExact(responderAccountId, 32, nameof(responderAccountId));
        NonZeroExact(responderDeviceId, 32, nameof(responderDeviceId));
        Generation(responderDeviceGeneration, nameof(responderDeviceGeneration));
        NonZeroExact(exactDpk2Hash, 32, nameof(exactDpk2Hash));
        NonZeroExact(claimOperationId, 32, nameof(claimOperationId));
        NonZeroExact(claimReceiptHash, 32, nameof(claimReceiptHash));
        if (!deriveSessionId)
            NonZeroExact(sessionId, 32, nameof(sessionId));
        NonZeroExact(initiatorDeviceAgreementPublicKey, 32, nameof(initiatorDeviceAgreementPublicKey));
        NonZeroExact(initiatorEphemeralX25519PublicKey, 32, nameof(initiatorEphemeralX25519PublicKey));
        Exact(actualMlKem768Ciphertext, 1088, nameof(actualMlKem768Ciphertext));
        NonZeroExact(initiatorInitialRatchetX25519PublicKey, 32, nameof(initiatorInitialRatchetX25519PublicKey));
        Exact(initialPayloadNonce, 24, nameof(initialPayloadNonce));

        if (selectedPrekey.Kind == Dpk2PrekeyKind.OneTime)
        {
            if (lastResortUseCounter != 0)
                throw Semantic(MessagingWireRejection.CrossFieldMismatch, "A one-time DPH2 selection requires counter zero.");
        }
        else if (selectedPrekey.Kind == Dpk2PrekeyKind.LastResort)
        {
            if (lastResortUseCounter is < 1 or > 64)
                throw Semantic(MessagingWireRejection.InvalidCounter, "A last-resort DPH2 counter must be 1..64.");
        }
        else
        {
            throw Semantic(MessagingWireRejection.InvalidEnum, "The DPH2 selected prekey kind is unknown.");
        }
    }

    private static void Exact(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw new ArgumentException($"{name} must be exactly {length} bytes.", name);
    }

    private static void NonZeroExact(ReadOnlySpan<byte> value, int length, string name)
    {
        Exact(value, length, name);
        if (MessagingWireFraming.IsZero(value))
            throw new ArgumentException($"{name} cannot be all-zero.", name);
    }

    private static void Generation(ulong value, string name)
    {
        if (value == 0)
            throw new ArgumentOutOfRangeException(name, "A device generation must be nonzero.");
    }

    private static MessagingWireFormatException Semantic(MessagingWireRejection rejection, string message) =>
        MessagingWireFraming.Error(MessagingWirePrevalidationStage.SemanticFields, rejection, message);

    internal static Dph2Record FromDecoded(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> initiatorAccountId,
        ReadOnlySpan<byte> initiatorDeviceId,
        ulong initiatorDeviceGeneration,
        ReadOnlySpan<byte> initiatorDpd1Ref,
        ReadOnlySpan<byte> responderAccountId,
        ReadOnlySpan<byte> responderDeviceId,
        ulong responderDeviceGeneration,
        ReadOnlySpan<byte> exactDpk2Hash,
        ReadOnlySpan<byte> claimOperationId,
        ReadOnlySpan<byte> claimReceiptHash,
        ushort lastResortUseCounter,
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> initiatorDeviceAgreementPublicKey,
        ReadOnlySpan<byte> initiatorEphemeralX25519PublicKey,
        Dph2SelectedPrekey selectedPrekey,
        ReadOnlySpan<byte> actualMlKem768Ciphertext,
        ReadOnlySpan<byte> initiatorInitialRatchetX25519PublicKey,
        ReadOnlySpan<byte> initialPayloadNonce,
        Dph2InitialCiphertext initialCiphertext) =>
        new(
            networkId,
            initiatorAccountId,
            initiatorDeviceId,
            initiatorDeviceGeneration,
            initiatorDpd1Ref,
            responderAccountId,
            responderDeviceId,
            responderDeviceGeneration,
            exactDpk2Hash,
            claimOperationId,
            claimReceiptHash,
            lastResortUseCounter,
            sessionId,
            initiatorDeviceAgreementPublicKey,
            initiatorEphemeralX25519PublicKey,
            selectedPrekey,
            actualMlKem768Ciphertext,
            initiatorInitialRatchetX25519PublicKey,
            initialPayloadNonce,
            initialCiphertext,
            deriveSessionId: false);
}

public static class Dph2Codec
{
    public const int SmallTotalBytes = 5917;
    public const int MediumTotalBytes = 18205;
    public const int LargeTotalBytes = 34589;
    private const ushort FieldCount = 20;

    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.DPH2;
    public static ReadOnlySpan<int> AllowedTotalSizes => [SmallTotalBytes, MediumTotalBytes, LargeTotalBytes];

    public static byte[] Encode(Dph2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var totalLength = record.InitialCiphertext.Length switch
        {
            4112 => SmallTotalBytes,
            16400 => MediumTotalBytes,
            32784 => LargeTotalBytes,
            _ => throw new InvalidOperationException("The owned DPH2 ciphertext has an impossible length."),
        };
        var output = new byte[totalLength];
        var writer = new MessagingWireWriter(output, Magic, FieldCount);
        WriteHeaderFields(ref writer, record);
        writer.Write(20, record.InitialCiphertext.Span);
        writer.Complete();
        return output;
    }

    public static Dph2Record Decode(ReadOnlySpan<byte> encoded)
    {
        Span<MessagingWireFieldSlice> fields = stackalloc MessagingWireFieldSlice[FieldCount];
        MessagingWireFraming.Preflight(encoded, Magic, FieldCount, AllowedTotalSizes, fields);
        ValidateLengths(fields);
        ValidateSemanticFields(encoded, fields);

        var owned = encoded.ToArray();
        MessagingWireFraming.Preflight(owned, Magic, FieldCount, AllowedTotalSizes, fields);
        ValidateLengths(fields);
        ValidateSemanticFields(owned, fields);
        var selected = Dph2SelectedPrekey.DecodeValidated(Value(owned, fields, 16));
        var ciphertext = Dph2InitialCiphertext.Import(Value(owned, fields, 20));
        return Dph2Record.FromDecoded(
            Value(owned, fields, 1),
            Value(owned, fields, 2),
            Value(owned, fields, 3),
            U64(owned, fields, 4),
            Value(owned, fields, 5),
            Value(owned, fields, 6),
            Value(owned, fields, 7),
            U64(owned, fields, 8),
            Value(owned, fields, 9),
            Value(owned, fields, 10),
            Value(owned, fields, 11),
            BinaryPrimitives.ReadUInt16BigEndian(Value(owned, fields, 12)),
            Value(owned, fields, 13),
            Value(owned, fields, 14),
            Value(owned, fields, 15),
            selected,
            Value(owned, fields, 17),
            Value(owned, fields, 18),
            Value(owned, fields, 19),
            ciphertext);
    }

    public static Dph2Record Decode(ReadOnlySpan<byte> encoded, Dpk2Record exactOffering)
    {
        ArgumentNullException.ThrowIfNull(exactOffering);
        var record = Decode(encoded);
        ValidateSelection(record, exactOffering);
        return record;
    }

    public static void ValidateSelection(Dph2Record record, Dpk2Record exactOffering)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(exactOffering);
        var expectedHash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(exactOffering);
        var selected = record.SelectedPrekey;
        var matches = CryptographicOperations.FixedTimeEquals(exactOffering.NetworkIdSpan, record.NetworkIdSpan) &&
                      CryptographicOperations.FixedTimeEquals(expectedHash, record.ExactDpk2HashSpan) &&
                      CryptographicOperations.FixedTimeEquals(exactOffering.ResponderAccountIdSpan, record.ResponderAccountIdSpan) &&
                      CryptographicOperations.FixedTimeEquals(exactOffering.ResponderDeviceIdSpan, record.ResponderDeviceIdSpan) &&
                      exactOffering.ResponderDeviceGeneration == record.ResponderDeviceGeneration &&
                      exactOffering.MlKemKind == selected.Kind &&
                      CryptographicOperations.FixedTimeEquals(exactOffering.SignedX25519PrekeyIdSpan, selected.SignedX25519PrekeyIdSpan) &&
                      CryptographicOperations.FixedTimeEquals(exactOffering.MlKemPrekeyIdSpan, selected.MlKemPrekeyIdSpan);

        if (matches && selected.Kind == Dpk2PrekeyKind.OneTime)
        {
            matches = record.LastResortUseCounter == 0 &&
                      CryptographicOperations.FixedTimeEquals(
                          exactOffering.OneTimeX25519PrekeyIdSpan,
                          selected.OneTimeX25519PrekeyIdOrZeroSpan);
        }
        else if (matches)
        {
            matches = MessagingWireFraming.IsZero(selected.OneTimeX25519PrekeyIdOrZeroSpan) &&
                      record.LastResortUseCounter is >= 1 &&
                      record.LastResortUseCounter <= exactOffering.ReuseLimit;
        }

        if (!matches)
        {
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.HashProjection,
                MessagingWireRejection.CrossFieldMismatch,
                "DPH2 does not select the exact supplied DPK2 offering.");
        }
    }

    public static byte[] GetHandshakeHeader(Dph2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var output = new byte[1797];
        var writer = new MessagingWireWriter(output, Magic, 19);
        WriteHeaderFields(ref writer, record);
        writer.Complete();
        return output;
    }

    private static void WriteHeaderFields(ref MessagingWireWriter writer, Dph2Record record)
    {
        Span<byte> u64 = stackalloc byte[8];
        Span<byte> u16 = stackalloc byte[2];
        writer.Write(1, record.NetworkIdSpan);
        writer.Write(2, record.InitiatorAccountIdSpan);
        writer.Write(3, record.InitiatorDeviceIdSpan);
        WriteU64(ref writer, 4, record.InitiatorDeviceGeneration, u64);
        writer.Write(5, record.InitiatorDpd1RefSpan);
        writer.Write(6, record.ResponderAccountIdSpan);
        writer.Write(7, record.ResponderDeviceIdSpan);
        WriteU64(ref writer, 8, record.ResponderDeviceGeneration, u64);
        writer.Write(9, record.ExactDpk2HashSpan);
        writer.Write(10, record.ClaimOperationIdSpan);
        writer.Write(11, record.ClaimReceiptHashSpan);
        BinaryPrimitives.WriteUInt16BigEndian(u16, record.LastResortUseCounter);
        writer.Write(12, u16);
        writer.Write(13, record.SessionIdSpan);
        writer.Write(14, record.InitiatorDeviceAgreementPublicKeySpan);
        writer.Write(15, record.InitiatorEphemeralX25519PublicKeySpan);
        writer.Write(16, record.SelectedPrekey.Encode());
        writer.Write(17, record.ActualMlKem768CiphertextSpan);
        writer.Write(18, record.InitiatorInitialRatchetX25519PublicKeySpan);
        writer.Write(19, record.InitialPayloadNonceSpan);
    }

    private static void ValidateLengths(ReadOnlySpan<MessagingWireFieldSlice> fields)
    {
        ReadOnlySpan<int> exact = [16, 32, 32, 8, 38, 32, 32, 8, 32, 32, 32, 2, 32, 32, 32, 97, 1088, 32, 24];
        for (var tag = 1; tag <= exact.Length; tag++)
            MessagingWireFraming.RequireLength(fields, tag, exact[tag - 1]);
        MessagingWireFraming.RequireLengthIn(fields, 20, [4112, 16400, 32784]);
    }

    private static void ValidateSemanticFields(ReadOnlySpan<byte> encoded, ReadOnlySpan<MessagingWireFieldSlice> fields)
    {
        RequireNonZero(encoded, fields, 1, "networkId");
        RequireNonZero(encoded, fields, 2, "initiatorAccountId");
        RequireNonZero(encoded, fields, 3, "initiatorDeviceId");
        RequireGeneration(encoded, fields, 4, "initiatorDeviceGeneration");
        RequireNonZero(encoded, fields, 6, "responderAccountId");
        RequireNonZero(encoded, fields, 7, "responderDeviceId");
        RequireGeneration(encoded, fields, 8, "responderDeviceGeneration");
        RequireNonZero(encoded, fields, 9, "exactDpk2Hash");
        RequireNonZero(encoded, fields, 10, "claimOperationId");
        RequireNonZero(encoded, fields, 11, "claimReceiptHash");
        RequireNonZero(encoded, fields, 13, "sessionId");
        RequireNonZero(encoded, fields, 14, "initiatorDeviceAgreementPublicKey");
        RequireNonZero(encoded, fields, 15, "initiatorEphemeralX25519PublicKey");
        RequireNonZero(encoded, fields, 18, "initiatorInitialRatchetX25519PublicKey");

        var tuple = Value(encoded, fields, 16);
        MessagingWireFraming.RequireNonZero(tuple[..32], "selected signed X25519 prekey ID");
        MessagingWireFraming.RequireNonZero(tuple[64..96], "selected ML-KEM prekey ID");
        var counter = BinaryPrimitives.ReadUInt16BigEndian(Value(encoded, fields, 12));
        switch ((Dpk2PrekeyKind)tuple[96])
        {
            case Dpk2PrekeyKind.OneTime:
                if (MessagingWireFraming.IsZero(tuple[32..64]) || counter != 0)
                    throw Semantic(MessagingWireRejection.CrossFieldMismatch, "The one-time tuple and counter do not agree.");
                break;
            case Dpk2PrekeyKind.LastResort:
                if (!MessagingWireFraming.IsZero(tuple[32..64]) || counter is < 1 or > 64)
                    throw Semantic(MessagingWireRejection.CrossFieldMismatch, "The last-resort tuple and counter do not agree.");
                break;
            default:
                throw Semantic(MessagingWireRejection.InvalidEnum, "The DPH2 selected prekey kind is unknown.");
        }

        var expectedTotal = fields[19].Length switch
        {
            4112 => SmallTotalBytes,
            16400 => MediumTotalBytes,
            32784 => LargeTotalBytes,
            _ => 0,
        };
        if (encoded.Length != expectedTotal)
            throw Semantic(MessagingWireRejection.CrossFieldMismatch, "The DPH2 ciphertext bucket and total size do not agree.");
    }

    private static void WriteU64(ref MessagingWireWriter writer, ushort tag, ulong value, scoped Span<byte> buffer)
    {
        BinaryPrimitives.WriteUInt64BigEndian(buffer, value);
        writer.Write(tag, buffer);
    }

    private static ReadOnlySpan<byte> Value(ReadOnlySpan<byte> encoded, ReadOnlySpan<MessagingWireFieldSlice> fields, int tag) =>
        MessagingWireFraming.Value(encoded, fields, tag);

    private static ulong U64(ReadOnlySpan<byte> encoded, ReadOnlySpan<MessagingWireFieldSlice> fields, int tag) =>
        BinaryPrimitives.ReadUInt64BigEndian(Value(encoded, fields, tag));

    private static void RequireGeneration(ReadOnlySpan<byte> encoded, ReadOnlySpan<MessagingWireFieldSlice> fields, int tag, string name)
    {
        if (U64(encoded, fields, tag) == 0)
            throw Semantic(MessagingWireRejection.InvalidGeneration, $"{name} must be nonzero.");
    }

    private static void RequireNonZero(ReadOnlySpan<byte> encoded, ReadOnlySpan<MessagingWireFieldSlice> fields, int tag, string name) =>
        MessagingWireFraming.RequireNonZero(Value(encoded, fields, tag), name);

    private static MessagingWireFormatException Semantic(MessagingWireRejection rejection, string message) =>
        MessagingWireFraming.Error(MessagingWirePrevalidationStage.SemanticFields, rejection, message);
}
