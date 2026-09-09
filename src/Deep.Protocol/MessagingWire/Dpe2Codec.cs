namespace Deep.Protocol.MessagingWire;

public sealed class Dpe2Ciphertext
{
    private readonly byte[] _ciphertext;

    private Dpe2Ciphertext(ReadOnlySpan<byte> ciphertext)
    {
        if (!IsAllowed(ciphertext.Length))
            throw new ArgumentException(
                "DPE2 ciphertext must be exactly 4112, 16400, 32784 or 49152 bytes.",
                nameof(ciphertext));
        _ciphertext = ciphertext.ToArray();
    }

    public int Length => _ciphertext.Length;

    public static Dpe2Ciphertext Import(ReadOnlySpan<byte> ciphertext) => new(ciphertext);

    public void CopyCiphertextTo(Span<byte> destination)
    {
        if (destination.Length != _ciphertext.Length)
            throw new ArgumentException("The destination must have the exact ciphertext length.", nameof(destination));
        _ciphertext.CopyTo(destination);
    }

    internal ReadOnlySpan<byte> Span => _ciphertext;
    internal static bool IsAllowed(int length) => length is 4112 or 16400 or 32784 or 49152;
}

public sealed class Dpe2Record
{
    private readonly byte[] _networkId;
    private readonly byte[] _sessionId;
    private readonly byte[] _senderDeviceId;
    private readonly byte[] _recipientDeviceId;
    private readonly byte[] _operationId;

    public Dpe2Record(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> senderDeviceId,
        ReadOnlySpan<byte> recipientDeviceId,
        ReadOnlySpan<byte> operationId,
        Dtr2Record ratchetHeader,
        Dpe2Ciphertext ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ratchetHeader);
        ArgumentNullException.ThrowIfNull(ciphertext);
        Exact(networkId, 16, nameof(networkId), nonzero: true);
        Exact(sessionId, 32, nameof(sessionId), nonzero: true);
        Exact(senderDeviceId, 32, nameof(senderDeviceId), nonzero: true);
        Exact(recipientDeviceId, 32, nameof(recipientDeviceId), nonzero: true);
        Exact(operationId, 32, nameof(operationId), nonzero: true);
        if (!networkId.SequenceEqual(ratchetHeader.NetworkIdSpan))
            throw new ArgumentException(
                "The DPE2 and embedded DTR2 network IDs must match exactly.",
                nameof(ratchetHeader));
        _networkId = networkId.ToArray();
        _sessionId = sessionId.ToArray();
        _senderDeviceId = senderDeviceId.ToArray();
        _recipientDeviceId = recipientDeviceId.ToArray();
        _operationId = operationId.ToArray();
        RatchetHeader = ratchetHeader;
        Ciphertext = ciphertext;
    }

    public ReadOnlyMemory<byte> NetworkId => MessagingWireOwned.PublicCopy(_networkId);
    public ReadOnlyMemory<byte> SessionId => MessagingWireOwned.PublicCopy(_sessionId);
    public ReadOnlyMemory<byte> SenderDeviceId => MessagingWireOwned.PublicCopy(_senderDeviceId);
    public ReadOnlyMemory<byte> RecipientDeviceId => MessagingWireOwned.PublicCopy(_recipientDeviceId);
    public ReadOnlyMemory<byte> OperationId => MessagingWireOwned.PublicCopy(_operationId);
    public Dtr2Record RatchetHeader { get; }
    public Dpe2Ciphertext Ciphertext { get; }

    internal ReadOnlySpan<byte> NetworkIdSpan => _networkId;
    internal ReadOnlySpan<byte> SessionIdSpan => _sessionId;
    internal ReadOnlyMemory<byte> SessionIdMemory => _sessionId;
    internal ReadOnlySpan<byte> SenderDeviceIdSpan => _senderDeviceId;
    internal ReadOnlySpan<byte> RecipientDeviceIdSpan => _recipientDeviceId;
    internal ReadOnlySpan<byte> OperationIdSpan => _operationId;
    internal ReadOnlyMemory<byte> OperationIdMemory => _operationId;

    private static void Exact(ReadOnlySpan<byte> value, int length, string name, bool nonzero)
    {
        if (value.Length != length)
            throw new ArgumentException($"{name} must be exactly {length} bytes.", name);
        if (nonzero && MessagingWireFraming.IsZero(value))
            throw new ArgumentException($"{name} cannot be all-zero.", name);
    }
}

public static class Dpe2Codec
{
    private const ushort FieldCount = 7;
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.DPE2;

    public static ReadOnlySpan<int> AllowedTotalSizes =>
    [
        4513, 4609, 4673, 5473, 5665,
        16801, 16897, 16961, 17761, 17953,
        33185, 33281, 33345, 34145, 34337,
        49553, 49649, 49713, 50513, 50705,
    ];

    public static byte[] Encode(Dpe2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var embedded = Dtr2Codec.EncodeEmbedded(record.RatchetHeader);
        var totalLength = checked(212 + embedded.Length + record.Ciphertext.Length);
        if (!IsAllowedTotal(totalLength))
            throw new InvalidOperationException("The DPE2 component lengths do not form an exact allowed bucket.");

        var output = new byte[totalLength];
        var writer = new MessagingWireWriter(output, Magic, FieldCount);
        WriteHeaderFields(ref writer, record, embedded);
        writer.Write(7, record.Ciphertext.Span);
        writer.Complete();
        return output;
    }

    public static Dpe2Record Decode(ReadOnlySpan<byte> encoded)
    {
        Span<MessagingWireFieldSlice> fields = stackalloc MessagingWireFieldSlice[FieldCount];
        MessagingWireFraming.Preflight(encoded, Magic, FieldCount, AllowedTotalSizes, fields);
        ValidateOuter(encoded, fields);

        var ownedEmbedded = Value(encoded, fields, 6).ToArray();
        Dtr2Record embedded;
        try
        {
            embedded = Dtr2Codec.DecodeEmbedded(ownedEmbedded);
        }
        catch (MessagingWireFormatException exception)
        {
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.OwnedCopy,
                MessagingWireRejection.EmbeddedRecordRejected,
                "DPE2 tag 6 is not an exact frozen DTR2 record.",
                exception);
        }

        var owned = encoded.ToArray();
        MessagingWireFraming.Preflight(owned, Magic, FieldCount, AllowedTotalSizes, fields);
        ValidateOuter(owned, fields);
        if (!Value(owned, fields, 6).SequenceEqual(ownedEmbedded))
        {
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.OwnedCopy,
                MessagingWireRejection.EmbeddedRecordRejected,
                "DPE2 embedded DTR2 changed while the immutable snapshot was acquired.");
        }
        if (!Value(owned, fields, 1).SequenceEqual(embedded.NetworkIdSpan))
        {
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.OwnedCopy,
                MessagingWireRejection.CrossFieldMismatch,
                "DPE2 and its immutable embedded DTR2 snapshot use different network IDs.");
        }
        var ciphertext = Dpe2Ciphertext.Import(Value(owned, fields, 7));
        return new Dpe2Record(
            Value(owned, fields, 1),
            Value(owned, fields, 2),
            Value(owned, fields, 3),
            Value(owned, fields, 4),
            Value(owned, fields, 5),
            embedded,
            ciphertext);
    }

    private static void ValidateOuter(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<MessagingWireFieldSlice> fields)
    {
        MessagingWireFraming.RequireLength(fields, 1, 16);
        MessagingWireFraming.RequireLength(fields, 2, 32);
        MessagingWireFraming.RequireLength(fields, 3, 32);
        MessagingWireFraming.RequireLength(fields, 4, 32);
        MessagingWireFraming.RequireLength(fields, 5, 32);
        MessagingWireFraming.RequireLengthIn(fields, 6, Dtr2Codec.AllowedTotalSizes);
        MessagingWireFraming.RequireLengthIn(fields, 7, [4112, 16400, 32784, 49152]);

        MessagingWireFraming.RequireNonZero(Value(encoded, fields, 1), "networkId");
        MessagingWireFraming.RequireNonZero(Value(encoded, fields, 2), "sessionId");
        MessagingWireFraming.RequireNonZero(Value(encoded, fields, 3), "senderDeviceId");
        MessagingWireFraming.RequireNonZero(Value(encoded, fields, 4), "recipientDeviceId");
        MessagingWireFraming.RequireNonZero(Value(encoded, fields, 5), "operationId");

        var expectedTotal = checked(212 + fields[5].Length + fields[6].Length);
        if (encoded.Length != expectedTotal)
        {
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.SemanticFields,
                MessagingWireRejection.CrossFieldMismatch,
                "The DPE2 embedded-header and ciphertext buckets do not form an allowed total.");
        }

    }

    public static byte[] GetHeader(Dpe2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var embedded = Dtr2Codec.EncodeEmbedded(record.RatchetHeader);
        var output = new byte[204 + embedded.Length];
        var writer = new MessagingWireWriter(output, Magic, 6);
        WriteHeaderFields(ref writer, record, embedded);
        writer.Complete();
        return output;
    }

    private static void WriteHeaderFields(
        ref MessagingWireWriter writer,
        Dpe2Record record,
        ReadOnlySpan<byte> embedded)
    {
        writer.Write(1, record.NetworkIdSpan);
        writer.Write(2, record.SessionIdSpan);
        writer.Write(3, record.SenderDeviceIdSpan);
        writer.Write(4, record.RecipientDeviceIdSpan);
        writer.Write(5, record.OperationIdSpan);
        writer.Write(6, embedded);
    }

    private static bool IsAllowedTotal(int total)
    {
        foreach (var allowed in AllowedTotalSizes)
        {
            if (allowed == total)
                return true;
        }

        return false;
    }

    private static ReadOnlySpan<byte> Value(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<MessagingWireFieldSlice> fields,
        int tag) => MessagingWireFraming.Value(encoded, fields, tag);
}
