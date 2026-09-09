using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Protocol.ApplicationCore;

public enum ApplicationCoreValidationStage
{
    ExactTotalSize = 1,
    FixedHeader = 2,
    FieldHeaders = 3,
    FieldLengths = 4,
    SemanticFields = 5,
    TypedPayload = 6,
    EmbeddedRecord = 7,
    OwnedCopy = 8,
    CryptographicVerification = 9,
    ApplicationCallback = 10,
}

public enum ApplicationCoreRejection
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
    InvalidFlags,
    ZeroForbidden,
    InvalidGeneration,
    InvalidTimeRange,
    InvalidReference,
    InvalidOrdering,
    NonCanonicalText,
    ReservedContentKind,
    CrossFieldMismatch,
    EmbeddedRecordRejected,
    InvalidLineage,
    VerificationFailed,
}

public sealed class ApplicationCoreFormatException : FormatException
{
    internal ApplicationCoreFormatException(
        ApplicationCoreValidationStage stage,
        ApplicationCoreRejection rejection,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Stage = stage;
        Rejection = rejection;
    }

    public ApplicationCoreValidationStage Stage { get; }
    public ApplicationCoreRejection Rejection { get; }
}

internal readonly struct ApplicationFieldSlice(int offset, int length)
{
    internal int Offset { get; } = offset;
    internal int Length { get; } = length;
}

internal static class ApplicationCoreFormat
{
    internal const ushort Version = 1;
    internal const ushort Suite = 0x0201;
    internal const int HeaderLength = 12;
    internal const int FieldHeaderLength = 8;
    internal static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static void Preflight(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> magic,
        ushort fieldCount,
        int minimumTotal,
        int maximumTotal,
        Span<ApplicationFieldSlice> fields)
    {
        if (encoded.Length < minimumTotal || encoded.Length > maximumTotal ||
            encoded.Length < HeaderLength)
            throw Error(ApplicationCoreValidationStage.ExactTotalSize,
                ApplicationCoreRejection.InvalidTotalSize, "The record total size is outside its frozen bound.");
        if (fields.Length != fieldCount)
            throw new InvalidOperationException("The application field table is inconsistent.");
        if (!encoded[..4].SequenceEqual(magic))
            throw Error(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.WrongMagic, "The record magic is not accepted by this codec.");
        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[4..6]) != Version)
            throw Error(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.WrongVersion, "Only version 1 is accepted.");
        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[6..8]) != Suite)
            throw Error(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.WrongSuite, "Only suite 0x0201 is accepted.");
        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[8..10]) != fieldCount)
            throw Error(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.WrongFieldCount, "The field count is not exact.");
        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[10..12]) != 0)
            throw Error(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.ReservedNotZero, "The record reserved value must be zero.");

        Span<bool> seen = fieldCount <= 64 ? stackalloc bool[fieldCount + 1] : new bool[fieldCount + 1];
        var offset = HeaderLength;
        for (ushort expectedTag = 1; expectedTag <= fieldCount; expectedTag++)
        {
            if (offset > encoded.Length - FieldHeaderLength)
                throw Error(ApplicationCoreValidationStage.FieldHeaders,
                    ApplicationCoreRejection.TruncatedFieldHeader, "A field header is truncated.");
            var actualTag = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset, 2));
            if (actualTag != expectedTag)
            {
                var rejection = actualTag == 0 || actualTag > fieldCount
                    ? ApplicationCoreRejection.UnknownTag
                    : seen[actualTag]
                        ? ApplicationCoreRejection.DuplicateTag
                        : ApplicationCoreRejection.OutOfOrderTag;
                throw Error(ApplicationCoreValidationStage.FieldHeaders, rejection,
                    "Fields must be the exact known, unique, strictly increasing set.");
            }
            if (BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset + 2, 2)) != 0)
                throw Error(ApplicationCoreValidationStage.FieldHeaders,
                    ApplicationCoreRejection.ReservedNotZero, "A field reserved value is nonzero.");
            seen[actualTag] = true;
            var encodedLength = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(offset + 4, 4));
            offset += FieldHeaderLength;
            if (encodedLength > int.MaxValue || encodedLength > (uint)(encoded.Length - offset))
                throw Error(ApplicationCoreValidationStage.FieldLengths,
                    ApplicationCoreRejection.InvalidFieldLength, "A field exceeds the remaining bounded record.");
            fields[expectedTag - 1] = new ApplicationFieldSlice(offset, (int)encodedLength);
            offset += (int)encodedLength;
        }
        if (offset != encoded.Length)
            throw Error(ApplicationCoreValidationStage.FieldLengths,
                ApplicationCoreRejection.TrailingBytes, "The record has trailing bytes.");
    }

    internal static ReadOnlySpan<byte> Field(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<ApplicationFieldSlice> fields,
        int tag)
    {
        var field = fields[tag - 1];
        return encoded.Slice(field.Offset, field.Length);
    }

    internal static void ExactLength(ReadOnlySpan<ApplicationFieldSlice> fields, int tag, int length)
    {
        if (fields[tag - 1].Length != length)
            throw Error(ApplicationCoreValidationStage.FieldLengths,
                ApplicationCoreRejection.InvalidFieldLength, $"Field {tag} has a noncanonical length.");
    }

    internal static void EitherLength(ReadOnlySpan<ApplicationFieldSlice> fields, int tag, int first, int second)
    {
        var value = fields[tag - 1].Length;
        if (value != first && value != second)
            throw Error(ApplicationCoreValidationStage.FieldLengths,
                ApplicationCoreRejection.InvalidFieldLength, $"Field {tag} has a noncanonical length.");
    }

    internal static void NonZero(ReadOnlySpan<byte> value, string name)
    {
        if (IsZero(value))
            throw Error(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.ZeroForbidden, $"{name} cannot be all-zero.");
    }

    internal static bool IsZero(ReadOnlySpan<byte> value)
    {
        byte aggregate = 0;
        foreach (var item in value)
            aggregate |= item;
        return aggregate == 0;
    }

    internal static byte[] Sha256Domain(string label, ReadOnlySpan<byte> value)
    {
        var labelBytes = AsciiLabel(label);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(labelBytes);
        hash.AppendData([0]);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length);
        hash.AppendData(value);
        return hash.GetHashAndReset();
    }

    internal static byte[] SignatureInput(string label, ReadOnlySpan<byte> record)
    {
        var labelBytes = AsciiLabel(label);
        var output = new byte[labelBytes.Length + 1 + 2 + 4 + record.Length];
        labelBytes.CopyTo(output, 0);
        var offset = labelBytes.Length;
        output[offset++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset, 2), Suite);
        offset += 2;
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset, 4), checked((uint)record.Length));
        offset += 4;
        record.CopyTo(output.AsSpan(offset));
        return output;
    }

    internal static string DecodeCanonicalText(ReadOnlySpan<byte> encoded, int minimum, int maximum, bool oneGrapheme)
    {
        if (encoded.Length < minimum || encoded.Length > maximum)
            throw Error(ApplicationCoreValidationStage.TypedPayload,
                ApplicationCoreRejection.InvalidFieldLength, "Text length is outside its frozen UTF-8 bound.");
        string value;
        try
        {
            value = StrictUtf8.GetString(encoded);
        }
        catch (DecoderFallbackException exception)
        {
            throw Error(ApplicationCoreValidationStage.TypedPayload,
                ApplicationCoreRejection.NonCanonicalText, "Text is not strict UTF-8.", exception);
        }
        if (!value.IsNormalized(NormalizationForm.FormC) || value.Contains('\0'))
            throw Error(ApplicationCoreValidationStage.TypedPayload,
                ApplicationCoreRejection.NonCanonicalText, "Text must be NFC and must not contain U+0000.");
        if (oneGrapheme)
        {
            var starts = System.Globalization.StringInfo.ParseCombiningCharacters(value);
            if (starts.Length != 1)
                throw Error(ApplicationCoreValidationStage.TypedPayload,
                    ApplicationCoreRejection.NonCanonicalText, "A reaction must contain exactly one extended grapheme cluster.");
        }
        return value;
    }

    internal static byte[] EncodeCanonicalText(string value, int minimum, int maximum, bool oneGrapheme)
    {
        ArgumentNullException.ThrowIfNull(value);
        byte[] encoded;
        try
        {
            encoded = StrictUtf8.GetBytes(value);
        }
        catch (EncoderFallbackException exception)
        {
            throw Error(ApplicationCoreValidationStage.TypedPayload,
                ApplicationCoreRejection.NonCanonicalText, "Text contains invalid UTF-16.", exception);
        }
        _ = DecodeCanonicalText(encoded, minimum, maximum, oneGrapheme);
        return encoded;
    }

    internal static int Compare(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.SequenceCompareTo(right);

    internal static ApplicationCoreFormatException Error(
        ApplicationCoreValidationStage stage,
        ApplicationCoreRejection rejection,
        string message,
        Exception? innerException = null) => new(stage, rejection, message, innerException);

    private static byte[] AsciiLabel(string label)
    {
        if (string.IsNullOrEmpty(label) || label.Any(static c => c > 0x7f))
            throw new InvalidOperationException("A protocol domain label must be nonempty ASCII.");
        return Encoding.ASCII.GetBytes(label);
    }
}

internal ref struct ApplicationRecordWriter
{
    private readonly Span<byte> _destination;
    private int _offset;
    private ushort _lastTag;

    internal ApplicationRecordWriter(Span<byte> destination, ReadOnlySpan<byte> magic, ushort fieldCount)
    {
        _destination = destination;
        _offset = ApplicationCoreFormat.HeaderLength;
        _lastTag = 0;
        magic.CopyTo(destination);
        BinaryPrimitives.WriteUInt16BigEndian(destination[4..6], ApplicationCoreFormat.Version);
        BinaryPrimitives.WriteUInt16BigEndian(destination[6..8], ApplicationCoreFormat.Suite);
        BinaryPrimitives.WriteUInt16BigEndian(destination[8..10], fieldCount);
        BinaryPrimitives.WriteUInt16BigEndian(destination[10..12], 0);
    }

    internal void Write(ushort tag, scoped ReadOnlySpan<byte> value)
    {
        if (tag <= _lastTag || _offset > _destination.Length - ApplicationCoreFormat.FieldHeaderLength - value.Length)
            throw new InvalidOperationException("The codec output shape is inconsistent.");
        BinaryPrimitives.WriteUInt16BigEndian(_destination.Slice(_offset, 2), tag);
        BinaryPrimitives.WriteUInt16BigEndian(_destination.Slice(_offset + 2, 2), 0);
        BinaryPrimitives.WriteUInt32BigEndian(_destination.Slice(_offset + 4, 4), checked((uint)value.Length));
        _offset += ApplicationCoreFormat.FieldHeaderLength;
        value.CopyTo(_destination[_offset..]);
        _offset += value.Length;
        _lastTag = tag;
    }

    internal void Complete()
    {
        if (_offset != _destination.Length)
            throw new InvalidOperationException("The codec did not fill the exact output record.");
    }
}
