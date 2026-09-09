using System.Buffers.Binary;

namespace Deep.Protocol.MessagingWire;

public enum Dtr2BraidMessageKind : byte
{
    None = 0,
    Header = 1,
    EncapsulationKey = 2,
    EncapsulationKeyWithCiphertext1Ack = 3,
    Ciphertext1Ack = 4,
    Ciphertext1 = 5,
    Ciphertext2 = 6,
}

public sealed class Dtr2BraidMessage
{
    private readonly byte[] _payload;

    private Dtr2BraidMessage(Dtr2BraidMessageKind kind, ReadOnlySpan<byte> payload)
    {
        Validate(kind, payload.Length);
        Kind = kind;
        _payload = payload.ToArray();
    }

    public Dtr2BraidMessageKind Kind { get; }
    public int EncodedPayloadLength => _payload.Length;

    public static Dtr2BraidMessage None() => new(Dtr2BraidMessageKind.None, []);

    public static Dtr2BraidMessage Header(
        ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyHash,
        ReadOnlySpan<byte> headerHmac)
    {
        Exact(encapsulationKeySeed, 32, nameof(encapsulationKeySeed));
        Exact(encapsulationKeyHash, 32, nameof(encapsulationKeyHash));
        Exact(headerHmac, 32, nameof(headerHmac));
        var payload = new byte[96];
        encapsulationKeySeed.CopyTo(payload);
        encapsulationKeyHash.CopyTo(payload.AsSpan(32));
        headerHmac.CopyTo(payload.AsSpan(64));
        return new Dtr2BraidMessage(Dtr2BraidMessageKind.Header, payload);
    }

    public static Dtr2BraidMessage EncapsulationKey(ReadOnlySpan<byte> encapsulationKey) =>
        ExactPayload(Dtr2BraidMessageKind.EncapsulationKey, encapsulationKey, 1152, nameof(encapsulationKey));

    public static Dtr2BraidMessage EncapsulationKeyWithCiphertext1Ack(ReadOnlySpan<byte> encapsulationKey) =>
        ExactPayload(
            Dtr2BraidMessageKind.EncapsulationKeyWithCiphertext1Ack,
            encapsulationKey,
            1152,
            nameof(encapsulationKey));

    public static Dtr2BraidMessage Ciphertext1Ack() => new(Dtr2BraidMessageKind.Ciphertext1Ack, []);

    public static Dtr2BraidMessage Ciphertext1(ReadOnlySpan<byte> ciphertext1) =>
        ExactPayload(Dtr2BraidMessageKind.Ciphertext1, ciphertext1, 960, nameof(ciphertext1));

    public static Dtr2BraidMessage Ciphertext2(
        ReadOnlySpan<byte> ciphertext2,
        ReadOnlySpan<byte> ciphertextHmac)
    {
        Exact(ciphertext2, 128, nameof(ciphertext2));
        Exact(ciphertextHmac, 32, nameof(ciphertextHmac));
        var payload = new byte[160];
        ciphertext2.CopyTo(payload);
        ciphertextHmac.CopyTo(payload.AsSpan(128));
        return new Dtr2BraidMessage(Dtr2BraidMessageKind.Ciphertext2, payload);
    }

    public void CopyHeaderTo(
        Span<byte> encapsulationKeySeed,
        Span<byte> encapsulationKeyHash,
        Span<byte> headerHmac)
    {
        RequireKind(Dtr2BraidMessageKind.Header);
        RequireDestination(encapsulationKeySeed, 32, nameof(encapsulationKeySeed));
        RequireDestination(encapsulationKeyHash, 32, nameof(encapsulationKeyHash));
        RequireDestination(headerHmac, 32, nameof(headerHmac));
        _payload.AsSpan(0, 32).CopyTo(encapsulationKeySeed);
        _payload.AsSpan(32, 32).CopyTo(encapsulationKeyHash);
        _payload.AsSpan(64, 32).CopyTo(headerHmac);
    }

    public void CopyEncapsulationKeyTo(Span<byte> destination)
    {
        if (Kind is not (Dtr2BraidMessageKind.EncapsulationKey or Dtr2BraidMessageKind.EncapsulationKeyWithCiphertext1Ack))
            throw new InvalidOperationException("This Braid message does not contain an encapsulation key.");
        RequireDestination(destination, 1152, nameof(destination));
        _payload.CopyTo(destination);
    }

    public void CopyCiphertext1To(Span<byte> destination)
    {
        RequireKind(Dtr2BraidMessageKind.Ciphertext1);
        RequireDestination(destination, 960, nameof(destination));
        _payload.CopyTo(destination);
    }

    public void CopyCiphertext2To(Span<byte> ciphertext2, Span<byte> ciphertextHmac)
    {
        RequireKind(Dtr2BraidMessageKind.Ciphertext2);
        RequireDestination(ciphertext2, 128, nameof(ciphertext2));
        RequireDestination(ciphertextHmac, 32, nameof(ciphertextHmac));
        _payload.AsSpan(0, 128).CopyTo(ciphertext2);
        _payload.AsSpan(128, 32).CopyTo(ciphertextHmac);
    }

    internal ReadOnlySpan<byte> PayloadSpan => _payload;
    internal static Dtr2BraidMessage DecodeValidated(Dtr2BraidMessageKind kind, ReadOnlySpan<byte> payload) => new(kind, payload);

    private static Dtr2BraidMessage ExactPayload(
        Dtr2BraidMessageKind kind,
        ReadOnlySpan<byte> payload,
        int length,
        string name)
    {
        Exact(payload, length, name);
        return new Dtr2BraidMessage(kind, payload);
    }

    private static void Validate(Dtr2BraidMessageKind kind, int payloadLength)
    {
        var valid = kind switch
        {
            Dtr2BraidMessageKind.None or Dtr2BraidMessageKind.Ciphertext1Ack => payloadLength == 0,
            Dtr2BraidMessageKind.Header => payloadLength == 96,
            Dtr2BraidMessageKind.EncapsulationKey or Dtr2BraidMessageKind.EncapsulationKeyWithCiphertext1Ack => payloadLength == 1152,
            Dtr2BraidMessageKind.Ciphertext1 => payloadLength == 960,
            Dtr2BraidMessageKind.Ciphertext2 => payloadLength == 160,
            _ => false,
        };
        if (!valid)
            throw new ArgumentException("The Braid kind and exact payload length do not agree.", nameof(payloadLength));
    }

    private static void Exact(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw new ArgumentException($"{name} must be exactly {length} bytes.", name);
    }

    private static void RequireDestination(Span<byte> destination, int length, string name)
    {
        if (destination.Length != length)
            throw new ArgumentException($"{name} must be exactly {length} bytes.", name);
    }

    private void RequireKind(Dtr2BraidMessageKind expected)
    {
        if (Kind != expected)
            throw new InvalidOperationException($"This Braid message is {Kind}, not {expected}.");
    }
}

public sealed class Dtr2Record
{
    private readonly byte[] _networkId;
    private readonly byte[] _ecRatchetPublicKey;

    public Dtr2Record(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> ecRatchetPublicKey,
        ulong ecPreviousSendingChainLength,
        ulong ecMessageNumber,
        ulong sckaSendingEpoch,
        ulong sckaPreviousSendingChainLength,
        ulong sckaMessageNumber,
        ulong braidEpoch,
        Dtr2BraidMessage braidMessage)
    {
        ArgumentNullException.ThrowIfNull(braidMessage);
        if (networkId.Length != 16)
            throw new ArgumentException("The network ID must be exactly 16 bytes.", nameof(networkId));
        if (MessagingWireFraming.IsZero(networkId))
            throw new ArgumentException("The network ID cannot be all-zero.", nameof(networkId));
        if (ecRatchetPublicKey.Length != 32)
            throw new ArgumentException("The EC ratchet public key must be exactly 32 bytes.", nameof(ecRatchetPublicKey));
        if (MessagingWireFraming.IsZero(ecRatchetPublicKey))
            throw new ArgumentException("The EC ratchet public key cannot be all-zero.", nameof(ecRatchetPublicKey));
        if (braidEpoch == 0)
            throw new ArgumentOutOfRangeException(nameof(braidEpoch), "The Braid epoch must be nonzero.");

        _networkId = networkId.ToArray();
        _ecRatchetPublicKey = ecRatchetPublicKey.ToArray();
        EcPreviousSendingChainLength = ecPreviousSendingChainLength;
        EcMessageNumber = ecMessageNumber;
        SckaSendingEpoch = sckaSendingEpoch;
        SckaPreviousSendingChainLength = sckaPreviousSendingChainLength;
        SckaMessageNumber = sckaMessageNumber;
        BraidEpoch = braidEpoch;
        BraidMessage = braidMessage;
    }

    public ReadOnlyMemory<byte> NetworkId => MessagingWireOwned.PublicCopy(_networkId);
    public ReadOnlyMemory<byte> EcRatchetPublicKey => MessagingWireOwned.PublicCopy(_ecRatchetPublicKey);
    public ulong EcPreviousSendingChainLength { get; }
    public ulong EcMessageNumber { get; }
    public ulong SckaSendingEpoch { get; }
    public ulong SckaPreviousSendingChainLength { get; }
    public ulong SckaMessageNumber { get; }
    public ulong BraidEpoch { get; }
    public Dtr2BraidMessage BraidMessage { get; }

    internal ReadOnlySpan<byte> NetworkIdSpan => _networkId;
    internal ReadOnlySpan<byte> EcRatchetPublicKeySpan => _ecRatchetPublicKey;
}

public static class Dtr2Codec
{
    public const int EmptyTotalBytes = 189;
    public const int HeaderTotalBytes = 285;
    public const int Ciphertext2TotalBytes = 349;
    public const int Ciphertext1TotalBytes = 1149;
    public const int EncapsulationKeyTotalBytes = 1341;
    private const ushort FieldCount = 10;

    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.DTR2;
    public static ReadOnlySpan<int> AllowedTotalSizes =>
        [EmptyTotalBytes, HeaderTotalBytes, Ciphertext2TotalBytes, Ciphertext1TotalBytes, EncapsulationKeyTotalBytes];

    public static byte[] EncodeEmbedded(Dtr2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var totalLength = TotalLength(record.BraidMessage.Kind);
        var output = new byte[totalLength];
        var writer = new MessagingWireWriter(output, Magic, FieldCount);
        Span<byte> u64 = stackalloc byte[8];
        writer.Write(1, record.NetworkIdSpan);
        writer.Write(2, record.EcRatchetPublicKeySpan);
        WriteU64(ref writer, 3, record.EcPreviousSendingChainLength, u64);
        WriteU64(ref writer, 4, record.EcMessageNumber, u64);
        WriteU64(ref writer, 5, record.SckaSendingEpoch, u64);
        WriteU64(ref writer, 6, record.SckaPreviousSendingChainLength, u64);
        WriteU64(ref writer, 7, record.SckaMessageNumber, u64);
        WriteU64(ref writer, 8, record.BraidEpoch, u64);
        writer.Write(9, [(byte)record.BraidMessage.Kind]);
        writer.Write(10, record.BraidMessage.PayloadSpan);
        writer.Complete();
        return output;
    }

    public static Dtr2Record DecodeEmbedded(ReadOnlySpan<byte> encoded)
    {
        Span<MessagingWireFieldSlice> fields = stackalloc MessagingWireFieldSlice[FieldCount];
        MessagingWireFraming.Preflight(encoded, Magic, FieldCount, AllowedTotalSizes, fields);
        _ = ValidateFields(encoded, fields);

        var owned = encoded.ToArray();
        MessagingWireFraming.Preflight(owned, Magic, FieldCount, AllowedTotalSizes, fields);
        var kind = ValidateFields(owned, fields);
        var message = Dtr2BraidMessage.DecodeValidated(kind, Value(owned, fields, 10));
        return new Dtr2Record(
            Value(owned, fields, 1),
            Value(owned, fields, 2),
            U64(owned, fields, 3),
            U64(owned, fields, 4),
            U64(owned, fields, 5),
            U64(owned, fields, 6),
            U64(owned, fields, 7),
            U64(owned, fields, 8),
            message);
    }

    private static Dtr2BraidMessageKind ValidateFields(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<MessagingWireFieldSlice> fields)
    {
        MessagingWireFraming.RequireLength(fields, 1, 16);
        MessagingWireFraming.RequireLength(fields, 2, 32);
        for (var tag = 3; tag <= 8; tag++)
            MessagingWireFraming.RequireLength(fields, tag, 8);
        MessagingWireFraming.RequireLength(fields, 9, 1);
        MessagingWireFraming.RequireLengthIn(fields, 10, [0, 96, 160, 960, 1152]);

        MessagingWireFraming.RequireNonZero(Value(encoded, fields, 1), "networkId");
        MessagingWireFraming.RequireNonZero(Value(encoded, fields, 2), "ecRatchetPublicKey");
        var braidEpoch = U64(encoded, fields, 8);
        if (braidEpoch == 0)
        {
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.SemanticFields,
                MessagingWireRejection.InvalidGeneration,
                "The DTR2 Braid epoch must be nonzero.");
        }

        var kindValue = Value(encoded, fields, 9)[0];
        if (kindValue > (byte)Dtr2BraidMessageKind.Ciphertext2)
        {
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.SemanticFields,
                MessagingWireRejection.InvalidEnum,
                "The DTR2 Braid message kind is unknown.");
        }

        var kind = (Dtr2BraidMessageKind)kindValue;
        var expectedPayloadLength = PayloadLength(kind);
        if (fields[9].Length != expectedPayloadLength || encoded.Length != TotalLength(kind))
        {
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.SemanticFields,
                MessagingWireRejection.CrossFieldMismatch,
                "The DTR2 Braid kind, payload and exact total size do not agree.");
        }

        return kind;
    }

    private static int PayloadLength(Dtr2BraidMessageKind kind) => kind switch
    {
        Dtr2BraidMessageKind.None or Dtr2BraidMessageKind.Ciphertext1Ack => 0,
        Dtr2BraidMessageKind.Header => 96,
        Dtr2BraidMessageKind.EncapsulationKey or Dtr2BraidMessageKind.EncapsulationKeyWithCiphertext1Ack => 1152,
        Dtr2BraidMessageKind.Ciphertext1 => 960,
        Dtr2BraidMessageKind.Ciphertext2 => 160,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private static int TotalLength(Dtr2BraidMessageKind kind) =>
        MessagingWireFraming.RecordHeaderLength +
        FieldCount * MessagingWireFraming.FieldHeaderLength +
        97 +
        PayloadLength(kind);

    private static void WriteU64(ref MessagingWireWriter writer, ushort tag, ulong value, scoped Span<byte> buffer)
    {
        BinaryPrimitives.WriteUInt64BigEndian(buffer, value);
        writer.Write(tag, buffer);
    }

    private static ReadOnlySpan<byte> Value(ReadOnlySpan<byte> encoded, ReadOnlySpan<MessagingWireFieldSlice> fields, int tag) =>
        MessagingWireFraming.Value(encoded, fields, tag);

    private static ulong U64(ReadOnlySpan<byte> encoded, ReadOnlySpan<MessagingWireFieldSlice> fields, int tag) =>
        BinaryPrimitives.ReadUInt64BigEndian(Value(encoded, fields, tag));
}
