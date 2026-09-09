using System.Buffers.Binary;
using System.Text;

namespace Deep.Protocol.XPointNetworkV1;

internal static class XPointNetworkCodec
{
    internal static XPointParsedRecord Parse(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < XPointNetworkRegistry.HeaderBytes ||
            encoded.Length > XPointNetworkRegistry.MaximumRecordBytes)
            throw Error(XPointValidationStage.Length, "RecordLengthOutOfRange", "The record length is outside the global bound.");

        Span<char> magicChars = stackalloc char[4];
        for (var index = 0; index < magicChars.Length; index++)
        {
            var value = encoded[index];
            if (value is < 0x21 or > 0x7e)
                throw Error(XPointValidationStage.Header, "UnknownMagic", "The magic is not printable ASCII.");
            magicChars[index] = (char)value;
        }

        var definition = XPointNetworkRegistry.Get(new string(magicChars));
        Preflight(encoded, definition);

        // Ownership occurs only after the complete hostile-size/tag/list/reference preflight.
        var owned = encoded.ToArray();
        var fields = CopyFields(owned, definition.Fields.Count);
        var parsed = Materialize(definition, owned, fields);
        XPointNetworkSemantics.Validate(parsed);
        return parsed;
    }

    internal static T Parse<T>(ReadOnlySpan<byte> encoded) where T : XPointParsedRecord =>
        Parse(encoded) is T record
            ? record
            : throw Error(XPointValidationStage.Header, "WrongRecordType", "The canonical record has a different type.");

    internal static byte[] Write(XPointRecordDefinition definition, IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(fields);
        if (fields.Count != definition.Fields.Count)
            throw Error(XPointValidationStage.Header, "WrongFieldCount", "The writer requires the exact known field set.");

        var total = XPointNetworkRegistry.HeaderBytes;
        for (var index = 0; index < fields.Count; index++)
        {
            var bound = definition.Fields[index];
            if (fields[index].Length < bound.MinimumLength || fields[index].Length > bound.MaximumLength)
                throw Error(XPointValidationStage.Length, "FieldLengthOutOfRange", "A field length is outside its frozen bound.");
            total = checked(total + XPointNetworkRegistry.FieldHeaderBytes + fields[index].Length);
        }
        if (total < definition.MinimumBytes || total > definition.MaximumBytes || total > XPointNetworkRegistry.MaximumRecordBytes)
            throw Error(XPointValidationStage.Length, "InvalidRecordLength", "The encoded record is outside its frozen bound.");

        var output = new byte[total];
        Encoding.ASCII.GetBytes(definition.Magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), definition.Version);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), definition.Suite);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Count));
        var offset = XPointNetworkRegistry.HeaderBytes;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += XPointNetworkRegistry.FieldHeaderBytes;
            fields[index].Span.CopyTo(output.AsSpan(offset));
            offset += fields[index].Length;
        }
        _ = Parse(output);
        return output;
    }

    internal static XPointCoreReference DecodeCoreReference(ReadOnlySpan<byte> value) =>
        new(DecodeReferenceMagic(value), BinaryPrimitives.ReadUInt16BigEndian(value[4..6]), new(value[6..38]));

    internal static XPointArtifactReference DecodeArtifactReference(ReadOnlySpan<byte> value) =>
        new(DecodeReferenceMagic(value), BinaryPrimitives.ReadUInt16BigEndian(value[4..6]), new(value[6..38]));

    internal static byte[] EncodeCoreReference(string magic, ReadOnlySpan<byte> hash)
    {
        if (magic.Length != 4 || hash.Length != 32 || IsZero(hash))
            throw Error(XPointValidationStage.Reference, "InvalidReference", "A core reference is invalid.");
        var output = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        hash.CopyTo(output.AsSpan(6));
        return output;
    }

    private static void Preflight(ReadOnlySpan<byte> encoded, XPointRecordDefinition definition)
    {
        if (encoded.Length < definition.MinimumBytes || encoded.Length > definition.MaximumBytes)
            throw Error(XPointValidationStage.Length, "RecordLengthOutOfRange", "The record length is outside its per-record bound.");
        if (!encoded[..4].SequenceEqual(Encoding.ASCII.GetBytes(definition.Magic)))
            throw Error(XPointValidationStage.Header, "WrongMagic", "The record magic is invalid.");
        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[4..6]) != definition.Version)
            throw Error(XPointValidationStage.Header, "UnsupportedVersion", "The record version is unsupported.");
        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[6..8]) != definition.Suite)
            throw Error(XPointValidationStage.Header, "UnknownSuite", "The record suite is unsupported.");
        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[8..10]) != definition.Fields.Count)
            throw Error(XPointValidationStage.Header, "WrongFieldCount", "The field count is not the exact frozen value.");
        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[10..12]) != 0)
            throw Error(XPointValidationStage.Header, "NonCanonicalReserved", "The header reserved value is nonzero.");

        Span<int> fieldOffsets = stackalloc int[definition.Fields.Count];
        Span<int> fieldLengths = stackalloc int[definition.Fields.Count];
        var offset = XPointNetworkRegistry.HeaderBytes;
        for (var index = 0; index < definition.Fields.Count; index++)
        {
            if (encoded.Length - offset < XPointNetworkRegistry.FieldHeaderBytes)
                throw Error(XPointValidationStage.Length, "TruncatedFieldHeader", "A field header is truncated.");
            var expectedTag = checked((ushort)(index + 1));
            var tag = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset, 2));
            if (tag != expectedTag)
                throw Error(XPointValidationStage.Header, "NonCanonicalTag", "Tags must be the exact contiguous known set.");
            if (BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset + 2, 2)) != 0)
                throw Error(XPointValidationStage.Header, "NonCanonicalReserved", "A field reserved value is nonzero.");
            var declared = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(offset + 4, 4));
            var field = definition.Fields[index];
            if (declared > int.MaxValue || declared < field.MinimumLength || declared > field.MaximumLength)
                throw Error(XPointValidationStage.Length, "FieldLengthOutOfRange", "A field length is outside its frozen bound.");
            offset = checked(offset + XPointNetworkRegistry.FieldHeaderBytes);
            if ((int)declared > encoded.Length - offset)
                throw Error(XPointValidationStage.Length, "TruncatedField", "A field value is truncated.");
            fieldOffsets[index] = offset;
            fieldLengths[index] = (int)declared;
            ValidateScalar(encoded.Slice(offset, (int)declared), field, encoded, fieldOffsets, fieldLengths);
            offset = checked(offset + (int)declared);
        }
        if (offset != encoded.Length)
            throw Error(XPointValidationStage.Length, "TrailingBytes", "Trailing bytes are forbidden.");
    }

    private static void ValidateScalar(
        ReadOnlySpan<byte> value,
        XPointFieldDefinition field,
        ReadOnlySpan<byte> record,
        ReadOnlySpan<int> offsets,
        ReadOnlySpan<int> lengths)
    {
        if (field.NonZero && value.Length != 0 && IsZero(value))
            throw Error(XPointValidationStage.Scalar, "ZeroForbidden", $"Field {field.Tag} is all zero.");

        ulong scalar = field.Kind switch
        {
            XPointFieldKind.UInt8 => value[0],
            XPointFieldKind.UInt16 => BinaryPrimitives.ReadUInt16BigEndian(value),
            XPointFieldKind.UInt32 => BinaryPrimitives.ReadUInt32BigEndian(value),
            XPointFieldKind.UInt64 => BinaryPrimitives.ReadUInt64BigEndian(value),
            _ => 0,
        };
        if (field.Kind is XPointFieldKind.UInt8 or XPointFieldKind.UInt16 or XPointFieldKind.UInt32 or XPointFieldKind.UInt64)
        {
            if (scalar < field.MinimumValue || scalar > field.MaximumValue ||
                field.AllowedValues is { Length: > 0 } && !field.AllowedValues.Contains(scalar))
            {
                var error = field.Name == "rootSignatureCount" ? "RootSignatureCountOutOfRange" : "ScalarOutOfRange";
                throw Error(XPointValidationStage.Scalar, error, $"Field {field.Tag} is outside its frozen scalar domain.");
            }
        }

        if (field.ZeroIffGenerationTag != 0)
        {
            var generationIndex = field.ZeroIffGenerationTag - 1;
            var generation = BinaryPrimitives.ReadUInt64BigEndian(record.Slice(offsets[generationIndex], lengths[generationIndex]));
            if (IsZero(value) != (generation == 0))
                throw Error(XPointValidationStage.Scalar, "InvalidGenesisPredecessor", "The predecessor zero rule is violated.");
        }

        if (field.Kind == XPointFieldKind.FixedList)
        {
            var countIndex = field.CountTag - 1;
            var countField = record.Slice(offsets[countIndex], lengths[countIndex]);
            var count = countField.Length switch
            {
                1 => countField[0],
                2 => BinaryPrimitives.ReadUInt16BigEndian(countField),
                _ => throw Error(XPointValidationStage.ListArithmetic, "InvalidCountWidth", "The list count width is invalid."),
            };
            int expected;
            try { expected = checked((int)count * field.EntryBytes); }
            catch (OverflowException) { throw Error(XPointValidationStage.ListArithmetic, "ListLengthOverflow", "The list length overflows."); }
            if (expected != value.Length)
                throw Error(XPointValidationStage.ListArithmetic, "CountLengthMismatch", "The list byte length does not equal count times entry width.");
        }

        if (field.Kind is XPointFieldKind.CoreReference or XPointFieldKind.ArtifactReference)
        {
            if (value.Length != 38 || !value[..4].SequenceEqual(Encoding.ASCII.GetBytes(field.ReferenceMagic!)) ||
                BinaryPrimitives.ReadUInt16BigEndian(value[4..6]) != 1 || IsZero(value[6..]))
                throw Error(XPointValidationStage.Reference, "ReferenceTypeMismatch", "A typed reference has the wrong magic, version, or zero hash.");
        }
    }

    private static byte[][] CopyFields(byte[] canonical, int count)
    {
        var fields = new byte[count][];
        var offset = XPointNetworkRegistry.HeaderBytes;
        for (var index = 0; index < count; index++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(canonical.AsSpan(offset + 4, 4)));
            offset += XPointNetworkRegistry.FieldHeaderBytes;
            fields[index] = canonical.AsSpan(offset, length).ToArray();
            offset += length;
        }
        return fields;
    }

    private static XPointParsedRecord Materialize(XPointRecordDefinition d, byte[] c, byte[][] f) => d.Kind switch
    {
        XPointRecordKind.Xna1 => new Xna1Record(d,c,f), XPointRecordKind.Xvp1 => new Xvp1Record(d,c,f),
        XPointRecordKind.Xnd1 => new Xnd1Record(d,c,f), XPointRecordKind.Xnv1 => new Xnv1Record(d,c,f),
        XPointRecordKind.Xnh1 => new Xnh1Record(d,c,f), XPointRecordKind.Xnp1 => new Xnp1Record(d,c,f),
        XPointRecordKind.Xnf1 => new Xnf1Record(d,c,f), XPointRecordKind.Nfp1 => new Nfp1Record(d,c,f),
        XPointRecordKind.Xcd1 => new Xcd1Record(d,c,f),
        _ => throw new InvalidOperationException(),
    };

    private static string DecodeReferenceMagic(ReadOnlySpan<byte> value)
    {
        if (value.Length != 38) throw Error(XPointValidationStage.Reference, "InvalidReference", "The reference length is invalid.");
        return Encoding.ASCII.GetString(value[..4]);
    }

    internal static bool IsZero(ReadOnlySpan<byte> value)
    {
        byte combined = 0;
        foreach (var item in value) combined |= item;
        return combined == 0;
    }

    internal static XPointValidationException Error(XPointValidationStage stage, string error, string message) =>
        new(stage, error, message);
}
