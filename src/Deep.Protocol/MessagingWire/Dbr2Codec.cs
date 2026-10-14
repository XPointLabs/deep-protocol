using System.Buffers.Binary;
using System.Text;

namespace Deep.Protocol.MessagingWire;

/// <summary>
/// Immutable structural snapshot only. It does not authenticate the peer,
/// authorize a Braid transition, reset a data limit, or grant dispatch/ACK.
/// </summary>
public sealed class UnverifiedDbr2Record
{
    private readonly byte[] canonical;
    private readonly MessagingWireFieldSlice[] fields;

    internal UnverifiedDbr2Record(byte[] ownedCanonical, ReadOnlySpan<MessagingWireFieldSlice> fieldTable,
        Dtr2BraidMessageKind kind)
    {
        canonical = ownedCanonical;
        fields = fieldTable.ToArray();
        BraidMessage = Dtr2BraidMessage.DecodeValidated(kind, Value(9));
    }

    public ReadOnlyMemory<byte> NetworkId => Value(1).ToArray();
    public ReadOnlyMemory<byte> SessionId => Value(2).ToArray();
    public ReadOnlyMemory<byte> SenderDeviceId => Value(3).ToArray();
    public ReadOnlyMemory<byte> RecipientDeviceId => Value(4).ToArray();
    public ReadOnlyMemory<byte> OperationId => Value(5).ToArray();
    public ulong BraidEpoch => BinaryPrimitives.ReadUInt64BigEndian(Value(6));
    public byte ControlCounter => Value(7)[0];
    public Dtr2BraidMessage BraidMessage { get; }
    public ReadOnlyMemory<byte> Authenticator => Value(11).ToArray();
    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    internal ReadOnlySpan<byte> Exact => canonical;
    internal ReadOnlySpan<byte> Value(int tag) => canonical.AsSpan(fields[tag - 1].Offset, fields[tag - 1].Length);
}

/// <summary>
/// DR-0111's parser-only frozen target. Authentication/native state and transport
/// activation are deliberately absent until their separately reviewed closure.
/// </summary>
public static class Dbr2Codec
{
    public const string CodecStatus = "FROZEN_TARGET_NOT_ACTIVE";
    public const bool ProductionActive = false;
    public const int TotalBytes = 4112;
    public const byte MaximumControlCounter = 2;
    private const ushort FieldCount = 11;
    private const int ProjectionBytes = 4072;
    private const string AuthenticationDomain = "Deep/MSG-V2/braid-recovery-auth";
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.DBR2;

    public static UnverifiedDbr2Record Decode(ReadOnlySpan<byte> encoded)
    {
        Span<MessagingWireFieldSlice> fields = stackalloc MessagingWireFieldSlice[FieldCount];
        MessagingWireFraming.Preflight(encoded, Magic, FieldCount, [TotalBytes], fields);
        _ = Validate(encoded, fields);
        var owned = encoded.ToArray();
        MessagingWireFraming.Preflight(owned, Magic, FieldCount, [TotalBytes], fields);
        var kind = Validate(owned, fields);
        return new UnverifiedDbr2Record(owned, fields, kind);
    }

    public static byte[] Encode(UnverifiedDbr2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return record.Exact.ToArray();
    }

    // Projection/AAD, never a signature, key or verification capability. As in
    // the common grammar, rebuild the field count; do not zero a tag11 placeholder.
    public static byte[] GetAuthenticationInput(UnverifiedDbr2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var projection = new byte[ProjectionBytes];
        var writer = new MessagingWireWriter(projection, Magic, 10);
        for (ushort tag = 1; tag <= 10; tag++) writer.Write(tag, record.Value(tag));
        writer.Complete();
        var domain = Encoding.UTF8.GetBytes(AuthenticationDomain);
        var input = new byte[domain.Length + 1 + projection.Length];
        domain.CopyTo(input, 0);
        projection.CopyTo(input, domain.Length + 1);
        return input;
    }

    private static Dtr2BraidMessageKind Validate(ReadOnlySpan<byte> encoded, ReadOnlySpan<MessagingWireFieldSlice> fields)
    {
        MessagingWireFraming.RequireLength(fields, 1, 16);
        for (var tag = 2; tag <= 5; tag++) MessagingWireFraming.RequireLength(fields, tag, 32);
        MessagingWireFraming.RequireLength(fields, 6, 8);
        MessagingWireFraming.RequireLength(fields, 7, 1);
        MessagingWireFraming.RequireLength(fields, 8, 1);
        MessagingWireFraming.RequireLengthIn(fields, 9, [96, 1152, 960, 160]);
        MessagingWireFraming.RequireLength(fields, 11, 32);
        for (var tag = 1; tag <= 5; tag++)
            if (Value(encoded, fields, tag).IndexOfAnyExcept((byte)0) < 0)
                throw Error(MessagingWireRejection.ZeroForbidden, "DBR2 identifiers cannot be zero.");
        if (Value(encoded, fields, 3).SequenceEqual(Value(encoded, fields, 4)))
            throw Error(MessagingWireRejection.CrossFieldMismatch, "DBR2 endpoints cannot be reflected onto the same device.");
        var epoch = BinaryPrimitives.ReadUInt64BigEndian(Value(encoded, fields, 6));
        if (epoch is 0 or ulong.MaxValue)
            throw Error(MessagingWireRejection.InvalidCounter, "DBR2 Braid epoch cannot be zero or wrap.");
        if (Value(encoded, fields, 7)[0] is not (1 or MaximumControlCounter))
            throw Error(MessagingWireRejection.InvalidCounter, "DBR2 has only two distinct control slots per sender/epoch.");
        var kind = (Dtr2BraidMessageKind)Value(encoded, fields, 8)[0];
        var payloadBytes = kind switch
        {
            Dtr2BraidMessageKind.Header => 96,
            Dtr2BraidMessageKind.EncapsulationKeyWithCiphertext1Ack => 1152,
            Dtr2BraidMessageKind.Ciphertext1 => 960,
            Dtr2BraidMessageKind.Ciphertext2 => 160,
            _ => throw Error(MessagingWireRejection.InvalidEnum, "DBR2 permits only complete progress-bearing Braid payloads."),
        };
        if (fields[8].Length != payloadBytes || fields[9].Length != 3826 - payloadBytes)
            throw Error(MessagingWireRejection.CrossFieldMismatch, "DBR2 kind, payload and padding sizes disagree.");
        if (Value(encoded, fields, 10).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(MessagingWireRejection.ReservedNotZero, "DBR2 padding cannot carry application data.");
        return kind;
    }

    private static ReadOnlySpan<byte> Value(ReadOnlySpan<byte> encoded, ReadOnlySpan<MessagingWireFieldSlice> fields, int tag) =>
        encoded.Slice(fields[tag - 1].Offset, fields[tag - 1].Length);
    private static MessagingWireFormatException Error(MessagingWireRejection rejection, string message) =>
        MessagingWireFraming.Error(MessagingWirePrevalidationStage.SemanticFields, rejection, message);
}
