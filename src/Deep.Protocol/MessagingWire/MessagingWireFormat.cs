using System.Buffers.Binary;

namespace Deep.Protocol.MessagingWire;

internal static class MessagingWireActivation
{
    internal const string CodecStatus = "FROZEN_CLEAN_BREAK";
    internal const bool ProductionActive = false;
}

public enum MessagingWirePrevalidationStage
{
    ExactTotalSize = 1,
    FixedHeader = 2,
    FieldHeaders = 3,
    FieldLengths = 4,
    SemanticFields = 5,
    OwnedCopy = 6,
    HashProjection = 7,
    CryptographicVerification = 8,
    ApplicationAndMutation = 9,
}

public enum MessagingWireRejection
{
    InvalidTotalSize,
    WrongMagic,
    WrongVersion,
    WrongSuite,
    WrongFieldCount,
    ReservedNotZero,
    TruncatedFieldHeader,
    UnknownTag,
    DuplicateTag,
    OutOfOrderTag,
    InvalidFieldLength,
    TrailingBytes,
    InvalidEnum,
    ZeroForbidden,
    InvalidGeneration,
    InvalidCounter,
    InvalidTimeRange,
    CrossFieldMismatch,
    EmbeddedRecordRejected,
    DerivedValueMismatch,
    CallbackRejected,
}

public sealed class MessagingWireFormatException : FormatException
{
    internal MessagingWireFormatException(
        MessagingWirePrevalidationStage stage,
        MessagingWireRejection rejection,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Stage = stage;
        Rejection = rejection;
    }

    public MessagingWirePrevalidationStage Stage { get; }
    public MessagingWireRejection Rejection { get; }
}

internal readonly struct MessagingWireFieldSlice(int offset, int length)
{
    internal int Offset { get; } = offset;
    internal int Length { get; } = length;
}

internal static class MessagingWireFraming
{
    internal const int RecordHeaderLength = 12;
    internal const int FieldHeaderLength = 8;
    internal const ushort Version = 1;
    internal const ushort Suite = 0x0201;

    internal static void Preflight(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> expectedMagic,
        ushort expectedFieldCount,
        ReadOnlySpan<int> allowedTotalSizes,
        Span<MessagingWireFieldSlice> fields)
    {
        if (!Contains(allowedTotalSizes, encoded.Length))
        {
            throw Error(
                MessagingWirePrevalidationStage.ExactTotalSize,
                MessagingWireRejection.InvalidTotalSize,
                "The record does not have an exact allowed total size.");
        }

        if (fields.Length != expectedFieldCount)
            throw new InvalidOperationException("The codec field table is inconsistent.");

        if (!encoded[..4].SequenceEqual(expectedMagic))
        {
            throw Error(
                MessagingWirePrevalidationStage.FixedHeader,
                MessagingWireRejection.WrongMagic,
                "The record magic is not accepted by this clean-break decoder.");
        }

        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[4..6]) != Version)
        {
            throw Error(
                MessagingWirePrevalidationStage.FixedHeader,
                MessagingWireRejection.WrongVersion,
                "The record version is not frozen version 1.");
        }

        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[6..8]) != Suite)
        {
            throw Error(
                MessagingWirePrevalidationStage.FixedHeader,
                MessagingWireRejection.WrongSuite,
                "The record suite is not frozen suite 0x0201.");
        }

        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[8..10]) != expectedFieldCount)
        {
            throw Error(
                MessagingWirePrevalidationStage.FixedHeader,
                MessagingWireRejection.WrongFieldCount,
                "The record field count is not exact.");
        }

        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[10..12]) != 0)
        {
            throw Error(
                MessagingWirePrevalidationStage.FixedHeader,
                MessagingWireRejection.ReservedNotZero,
                "The record reserved value must be zero.");
        }

        Span<bool> seen = stackalloc bool[expectedFieldCount + 1];
        var offset = RecordHeaderLength;
        for (ushort expectedTag = 1; expectedTag <= expectedFieldCount; expectedTag++)
        {
            if (offset > encoded.Length - FieldHeaderLength)
            {
                throw Error(
                    MessagingWirePrevalidationStage.FieldHeaders,
                    MessagingWireRejection.TruncatedFieldHeader,
                    "A field header is truncated.");
            }

            var actualTag = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset, 2));
            if (actualTag != expectedTag)
            {
                var rejection = actualTag == 0 || actualTag > expectedFieldCount
                    ? MessagingWireRejection.UnknownTag
                    : seen[actualTag]
                        ? MessagingWireRejection.DuplicateTag
                        : MessagingWireRejection.OutOfOrderTag;
                throw Error(
                    MessagingWirePrevalidationStage.FieldHeaders,
                    rejection,
                    "Field tags must be the exact known, unique, strictly increasing set.");
            }

            if (BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset + 2, 2)) != 0)
            {
                throw Error(
                    MessagingWirePrevalidationStage.FieldHeaders,
                    MessagingWireRejection.ReservedNotZero,
                    "Every field reserved value must be zero.");
            }

            seen[actualTag] = true;
            var encodedLength = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(offset + 4, 4));
            offset += FieldHeaderLength;
            if (encodedLength > int.MaxValue || encodedLength > (uint)(encoded.Length - offset))
            {
                throw Error(
                    MessagingWirePrevalidationStage.FieldHeaders,
                    MessagingWireRejection.InvalidFieldLength,
                    "A field length exceeds the remaining bounded record.");
            }

            var length = (int)encodedLength;
            fields[expectedTag - 1] = new MessagingWireFieldSlice(offset, length);
            offset += length;
        }

        if (offset != encoded.Length)
        {
            throw Error(
                MessagingWirePrevalidationStage.FieldLengths,
                MessagingWireRejection.TrailingBytes,
                "The record has trailing bytes or an incomplete exact field set.");
        }
    }

    internal static ReadOnlySpan<byte> Value(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<MessagingWireFieldSlice> fields,
        int tag)
    {
        var field = fields[tag - 1];
        return encoded.Slice(field.Offset, field.Length);
    }

    internal static void RequireLength(
        ReadOnlySpan<MessagingWireFieldSlice> fields,
        int tag,
        int exactLength)
    {
        if (fields[tag - 1].Length != exactLength)
            throw InvalidLength(tag);
    }

    internal static void RequireLength(
        ReadOnlySpan<MessagingWireFieldSlice> fields,
        int tag,
        int first,
        int second)
    {
        var actual = fields[tag - 1].Length;
        if (actual != first && actual != second)
            throw InvalidLength(tag);
    }

    internal static void RequireLengthIn(
        ReadOnlySpan<MessagingWireFieldSlice> fields,
        int tag,
        ReadOnlySpan<int> allowed)
    {
        if (!Contains(allowed, fields[tag - 1].Length))
            throw InvalidLength(tag);
    }

    internal static void RequireNonZero(ReadOnlySpan<byte> value, string fieldName)
    {
        byte aggregate = 0;
        foreach (var item in value)
            aggregate |= item;
        if (aggregate == 0)
        {
            throw Error(
                MessagingWirePrevalidationStage.SemanticFields,
                MessagingWireRejection.ZeroForbidden,
                $"{fieldName} cannot be all-zero.");
        }
    }

    internal static bool IsZero(ReadOnlySpan<byte> value)
    {
        byte aggregate = 0;
        foreach (var item in value)
            aggregate |= item;
        return aggregate == 0;
    }

    internal static MessagingWireFormatException Error(
        MessagingWirePrevalidationStage stage,
        MessagingWireRejection rejection,
        string message,
        Exception? innerException = null) => new(stage, rejection, message, innerException);

    private static bool Contains(ReadOnlySpan<int> values, int candidate)
    {
        foreach (var value in values)
        {
            if (value == candidate)
                return true;
        }

        return false;
    }

    private static MessagingWireFormatException InvalidLength(int tag) => Error(
        MessagingWirePrevalidationStage.FieldLengths,
        MessagingWireRejection.InvalidFieldLength,
        $"Field {tag} does not have an exact allowed length.");
}

internal ref struct MessagingWireWriter
{
    private readonly Span<byte> _destination;
    private readonly ushort _fieldCount;
    private int _offset;
    private ushort _nextField;

    internal MessagingWireWriter(
        Span<byte> destination,
        ReadOnlySpan<byte> magic,
        ushort fieldCount)
    {
        _destination = destination;
        _fieldCount = fieldCount;
        _offset = MessagingWireFraming.RecordHeaderLength;
        _nextField = 0;
        magic.CopyTo(destination);
        BinaryPrimitives.WriteUInt16BigEndian(destination[4..6], MessagingWireFraming.Version);
        BinaryPrimitives.WriteUInt16BigEndian(destination[6..8], MessagingWireFraming.Suite);
        BinaryPrimitives.WriteUInt16BigEndian(destination[8..10], fieldCount);
        BinaryPrimitives.WriteUInt16BigEndian(destination[10..12], 0);
    }

    internal void Write(ushort tag, scoped ReadOnlySpan<byte> value)
    {
        if (tag <= _nextField)
            throw new InvalidOperationException("Codec fields must be written in canonical order.");
        if (_offset > _destination.Length - MessagingWireFraming.FieldHeaderLength - value.Length)
            throw new InvalidOperationException("The codec output length is inconsistent.");

        BinaryPrimitives.WriteUInt16BigEndian(_destination.Slice(_offset, 2), tag);
        BinaryPrimitives.WriteUInt16BigEndian(_destination.Slice(_offset + 2, 2), 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            _destination.Slice(_offset + 4, 4),
            checked((uint)value.Length));
        _offset += MessagingWireFraming.FieldHeaderLength;
        value.CopyTo(_destination[_offset..]);
        _offset += value.Length;
        _nextField = tag;
    }

    internal void Complete()
    {
        if (_offset != _destination.Length || _fieldCount == 0)
            throw new InvalidOperationException("The codec did not fill the exact output record.");
    }
}

internal static class MessagingWireOwned
{
    internal static byte[] Copy(ReadOnlySpan<byte> value) => value.ToArray();
    internal static ReadOnlyMemory<byte> PublicCopy(byte[] value) => value.ToArray();
}
