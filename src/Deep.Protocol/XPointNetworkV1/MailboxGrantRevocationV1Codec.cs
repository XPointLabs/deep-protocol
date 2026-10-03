using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>Canonical signed-looking MGR1 data, not floor or admission authority.</summary>
public sealed class ParsedMailboxGrantRevocationV1
{
    private readonly byte[] exact, unsigned;
    private readonly byte[][] fields;
    internal ParsedMailboxGrantRevocationV1(byte[] exact, byte[] unsigned, byte[][] fields)
    { this.exact = exact; this.unsigned = unsigned; this.fields = fields; }
    public ReadOnlyMemory<byte> CanonicalBytes => exact.ToArray();
    public ReadOnlyMemory<byte> CoreHash => ApplicationCoreFormat.Sha256Domain("Deep/XPoint/V1/MGR1/core", unsigned);
    public ReadOnlyMemory<byte> SignatureInput => ApplicationCoreFormat.SignatureInput("Deep/XPoint/V1/MGR1/issuer", unsigned);
    public MailboxCapabilityDomain Domain => (MailboxCapabilityDomain)fields[2][0];
    public ulong Generation => BinaryPrimitives.ReadUInt64BigEndian(fields[4]);
    public ulong IssuedAt => BinaryPrimitives.ReadUInt64BigEndian(fields[6]);
    public ulong NotBefore => BinaryPrimitives.ReadUInt64BigEndian(fields[7]);
    public ulong ExpiresAt => BinaryPrimitives.ReadUInt64BigEndian(fields[8]);
    public uint SerialCount => BinaryPrimitives.ReadUInt32BigEndian(fields[9]);
    public ReadOnlyMemory<byte> Field(int tag) => tag is >= 1 and <= 12
        ? fields[tag - 1].ToArray() : throw new ArgumentOutOfRangeException(nameof(tag));
    internal ReadOnlySpan<byte> FieldSpan(int tag) => fields[tag - 1];
    internal bool ContainsSerial(ReadOnlySpan<byte> serial)
    {
        var low = 0; var high = checked((int)SerialCount) - 1;
        while (low <= high)
        {
            var middle = low + (high - low) / 2;
            var order = fields[10].AsSpan(middle * 16, 16).SequenceCompareTo(serial);
            if (order == 0) return true;
            if (order < 0) low = middle + 1; else high = middle - 1;
        }
        return false;
    }
}

public static class MailboxGrantRevocationV1Codec
{
    // 12-byte header + twelve 8-byte field headers + 219 fixed value bytes.
    public const int MinimumBytes = 327;
    public const int MaximumSerials = 4_096;
    public const int MaximumBytes = MinimumBytes + MaximumSerials * 16;
    public const ulong MaximumLifetimeSeconds = 300;
    public static bool RuntimeActivation => false;
    private static ReadOnlySpan<int> Lengths => [16, 38, 1, 32, 8, 32, 8, 8, 8, 4, -1, 64];

    public static byte[] Encode(IReadOnlyList<ReadOnlyMemory<byte>> unsignedFields, ReadOnlySpan<byte> signature64)
    {
        ArgumentNullException.ThrowIfNull(unsignedFields);
        if (unsignedFields.Count != 11 || signature64.Length != 64)
            throw new ArgumentException("MGR1 requires eleven unsigned fields and one signature.");
        for (var index = 0; index < 11; index++)
            if ((index != 10 && unsignedFields[index].Length != Lengths[index]) ||
                (index == 10 && unsignedFields[index].Length > MaximumSerials * 16))
                throw new ArgumentException("MGR1 field exceeds its exact bounds.");
        var exact = new byte[checked(MinimumBytes + unsignedFields[10].Length)];
        var writer = new ApplicationRecordWriter(exact, ProtocolMagicBytes.MGR1, 12);
        for (ushort tag = 1; tag <= 11; tag++) writer.Write(tag, unsignedFields[tag - 1].Span);
        writer.Write(12, signature64); writer.Complete();
        _ = Decode(exact);
        return exact;
    }

    public static byte[] CreateSignatureInput(IReadOnlyList<ReadOnlyMemory<byte>> unsignedFields) =>
        Decode(Encode(unsignedFields, Enumerable.Repeat((byte)1, 64).ToArray())).SignatureInput.ToArray();

    public static ParsedMailboxGrantRevocationV1 Decode(ReadOnlySpan<byte> exact)
    {
        Span<ApplicationFieldSlice> slices = stackalloc ApplicationFieldSlice[12];
        ApplicationCoreFormat.Preflight(exact, ProtocolMagicBytes.MGR1, 12, MinimumBytes, MaximumBytes, slices);
        for (var tag = 1; tag <= 12; tag++)
            if (tag != 11) ApplicationCoreFormat.ExactLength(slices, tag, Lengths[tag - 1]);
        var field = new byte[12][];
        // Copy only after exact header/length bounds and count have been checked.
        var count = BinaryPrimitives.ReadUInt32BigEndian(ApplicationCoreFormat.Field(exact, slices, 10));
        if (count > MaximumSerials || slices[10].Length != count * 16)
            throw Error("MGR1 revoked serial count is not canonical.");
        var role = ApplicationCoreFormat.Field(exact, slices, 3)[0];
        if (role is not (1 or 2)) throw Error("MGR1 role is invalid.");
        foreach (var tag in new[] { 1, 4, 12 })
            ApplicationCoreFormat.NonZero(ApplicationCoreFormat.Field(exact, slices, tag), "MGR1 required field");
        var reference = ApplicationCoreFormat.Field(exact, slices, 2);
        if (!reference[..4].SequenceEqual(ProtocolMagicBytes.PMA2) ||
            BinaryPrimitives.ReadUInt16BigEndian(reference[4..6]) != 1 || reference[6..].IndexOfAnyExcept((byte)0) < 0)
            throw Error("MGR1 needs an exact nonzero PMA2 CoreRef.");
        var generation = BinaryPrimitives.ReadUInt64BigEndian(ApplicationCoreFormat.Field(exact, slices, 5));
        var predecessor = ApplicationCoreFormat.Field(exact, slices, 6);
        if (generation == 0 || (generation == 1) != (predecessor.IndexOfAnyExcept((byte)0) < 0))
            throw Error("MGR1 generation/predecessor is invalid.");
        var issued = BinaryPrimitives.ReadUInt64BigEndian(ApplicationCoreFormat.Field(exact, slices, 7));
        var start = BinaryPrimitives.ReadUInt64BigEndian(ApplicationCoreFormat.Field(exact, slices, 8));
        var end = BinaryPrimitives.ReadUInt64BigEndian(ApplicationCoreFormat.Field(exact, slices, 9));
        if (issued == 0 || issued > start || start >= end || end - start > MaximumLifetimeSeconds)
            throw Error("MGR1 time window is invalid.");
        var serials = ApplicationCoreFormat.Field(exact, slices, 11);
        for (var index = 0; index < count; index++)
        {
            var serial = serials.Slice(index * 16, 16);
            if (serial.IndexOfAnyExcept((byte)0) < 0 ||
                index > 0 && serials.Slice((index - 1) * 16, 16).SequenceCompareTo(serial) >= 0)
                throw Error("MGR1 serials must be nonzero and strictly ordered.");
        }
        var owned = exact.ToArray();
        for (var tag = 1; tag <= 12; tag++) field[tag - 1] = ApplicationCoreFormat.Field(owned, slices, tag).ToArray();
        var unsigned = new byte[exact.Length - 72];
        var writer = new ApplicationRecordWriter(unsigned, ProtocolMagicBytes.MGR1, 11);
        for (ushort tag = 1; tag <= 11; tag++) writer.Write(tag, field[tag - 1]);
        writer.Complete();
        return new(owned, unsigned, field);
    }

    private static ApplicationCoreFormatException Error(string message) => ApplicationCoreFormat.Error(
        ApplicationCoreValidationStage.SemanticFields, ApplicationCoreRejection.CrossFieldMismatch, message);
}
