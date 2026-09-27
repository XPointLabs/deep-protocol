using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Exact DID2 XIC1 receipt. Parsing a signed-looking record is not replica
/// authentication or proof that a two-replica publication was committed.
/// </summary>
public sealed class ParsedXic1V2
{
    private readonly byte[] canonical;
    private readonly byte[][] fields;
    private readonly byte[] unsigned;

    internal ParsedXic1V2(byte[] canonical, byte[][] fields, byte[] unsigned)
    {
        this.canonical = canonical;
        this.fields = fields;
        this.unsigned = unsigned;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> SignatureInput =>
        ApplicationCoreFormat.SignatureInput(
            "Deep/ContactResolver/V2/prekey-inventory-commit", unsigned,
            DeepIdV2Codec.Suite);
    public ReadOnlyMemory<byte> Field(int tag)
    {
        if (tag is < 1 or > 7)
            throw new ArgumentOutOfRangeException(nameof(tag));
        return fields[tag - 1].ToArray();
    }
}

/// <summary>
/// Closed V2 XIC1 codec. The old receipt version, suite and signing domain
/// cannot be consumed by the DID2 publication path.
/// </summary>
public static class DeepIdV2PreKeyCommitReceiptCodec
{
    public const int CanonicalLength = 284;
    public static bool RuntimeActivation => false;
    private static ReadOnlySpan<int> FieldLengths => [16, 32, 32, 32, 32, 8, 64];

    public static byte[] CreateSignatureInput(
        IReadOnlyList<ReadOnlyMemory<byte>> unsignedFields)
    {
        var placeholder = new byte[64];
        placeholder.AsSpan().Fill(1);
        return Decode(Encode(unsignedFields, placeholder)).SignatureInput.ToArray();
    }

    public static byte[] Encode(
        IReadOnlyList<ReadOnlyMemory<byte>> unsignedFields,
        ReadOnlySpan<byte> replicaSignature64)
    {
        ArgumentNullException.ThrowIfNull(unsignedFields);
        if (unsignedFields.Count != 6 ||
            unsignedFields.Where((field, index) =>
                field.Length != FieldLengths[index]).Any() ||
            replicaSignature64.Length != 64)
            throw new ArgumentException("XIC1 V2 authoring fields are not exact.");
        var canonical = new byte[CanonicalLength];
        var writer = new ApplicationRecordWriter(canonical,
            ProtocolMagicBytes.XIC1, 7, 2, DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= 6; tag++)
            writer.Write(tag, unsignedFields[tag - 1].Span);
        writer.Write(7, replicaSignature64);
        writer.Complete();
        _ = Decode(canonical);
        return canonical;
    }

    public static ParsedXic1V2 Decode(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> slices = stackalloc ApplicationFieldSlice[7];
        ApplicationCoreFormat.Preflight(canonical, ProtocolMagicBytes.XIC1,
            7, CanonicalLength, CanonicalLength, slices, 2,
            DeepIdV2Codec.Suite);
        var lengths = FieldLengths;
        for (var tag = 1; tag <= lengths.Length; tag++)
            ApplicationCoreFormat.ExactLength(slices, tag, lengths[tag - 1]);
        for (var tag = 1; tag <= 5; tag++)
            ApplicationCoreFormat.NonZero(
                ApplicationCoreFormat.Field(canonical, slices, tag),
                "XIC1 V2 required field");
        ApplicationCoreFormat.NonZero(
            ApplicationCoreFormat.Field(canonical, slices, 7),
            "XIC1 V2 replica signature");
        if (BinaryPrimitives.ReadUInt64BigEndian(
                ApplicationCoreFormat.Field(canonical, slices, 6)) == 0)
            throw ApplicationCoreFormat.Error(
                ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.InvalidTimeRange,
                "XIC1 V2 commit time must be nonzero.");

        var owned = canonical.ToArray();
        var fields = new byte[7][];
        for (var tag = 1; tag <= fields.Length; tag++)
            fields[tag - 1] = ApplicationCoreFormat.Field(owned, slices, tag).ToArray();
        var unsigned = new byte[212];
        var writer = new ApplicationRecordWriter(unsigned,
            ProtocolMagicBytes.XIC1, 6, 2, DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= 6; tag++)
            writer.Write(tag, fields[tag - 1]);
        writer.Complete();
        return new ParsedXic1V2(owned, fields, unsigned);
    }
}
