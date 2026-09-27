using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Exact DID2-generation XPI1 bytes. Parsing does not grant inventory,
/// publication, or claim authority; the current DID2 closure must verify the
/// device signature separately.
/// </summary>
public sealed class ParsedXpi1V2
{
    private readonly byte[] canonical;
    private readonly byte[][] fields;
    private readonly byte[] unsigned;

    internal ParsedXpi1V2(byte[] canonical, byte[][] fields, byte[] unsigned)
    {
        this.canonical = canonical;
        this.fields = fields;
        this.unsigned = unsigned;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> ExactHash => ApplicationCoreFormat.Sha256Domain(
        "Deep/ContactResolver/V2/exact-xpi1", canonical);
    public ReadOnlyMemory<byte> SignatureInput => ApplicationCoreFormat.SignatureInput(
        "Deep/ContactResolver/V2/prekey-inventory", unsigned,
        DeepIdV2Codec.Suite);
    public ReadOnlyMemory<byte> Field(int tag) => fields[tag - 1].ToArray();
    internal ReadOnlySpan<byte> FieldSpan(int tag) => fields[tag - 1];
}

/// <summary>
/// Closed V2 XPI1 codec. The old CONTACT-CODEC V1 record, signature domain,
/// and hash domain cannot be consumed by the DID2 contact path.
/// </summary>
public static class DeepIdV2PreKeyManifestCodec
{
    public const int CanonicalLength = 560;
    public static bool RuntimeActivation => false;
    private static ReadOnlySpan<int> FieldLengths =>
        [16, 32, 32, 38, 8, 38, 8, 32, 2, 32, 32, 32, 38, 8, 8, 64];

    /// <summary>
    /// Canonical unsigned projection for the account-owned device signer.
    /// The resulting bytes are not publication authority.
    /// </summary>
    public static byte[] CreateSignatureInput(
        IReadOnlyList<ReadOnlyMemory<byte>> unsignedFields)
    {
        var placeholder = new byte[64];
        placeholder.AsSpan().Fill(1);
        return Decode(Encode(unsignedFields, placeholder)).SignatureInput.ToArray();
    }

    public static byte[] Encode(
        IReadOnlyList<ReadOnlyMemory<byte>> unsignedFields,
        ReadOnlySpan<byte> publisherSignature64)
    {
        ArgumentNullException.ThrowIfNull(unsignedFields);
        if (unsignedFields.Count != 15 ||
            unsignedFields.Where((field, index) => field.Length != FieldLengths[index]).Any() ||
            publisherSignature64.Length != 64)
            throw new ArgumentException("XPI1 V2 authoring fields are not exact.");
        var bytes = new byte[CanonicalLength];
        var writer = new ApplicationRecordWriter(bytes,
            ProtocolMagicBytes.XPI1, 16, 2, DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= 15; tag++)
            writer.Write(tag, unsignedFields[tag - 1].Span);
        writer.Write(16, publisherSignature64);
        writer.Complete();
        _ = Decode(bytes);
        return bytes;
    }

    public static ParsedXpi1V2 Decode(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> slices = stackalloc ApplicationFieldSlice[16];
        ApplicationCoreFormat.Preflight(canonical, ProtocolMagicBytes.XPI1, 16,
            CanonicalLength, CanonicalLength, slices, 2, DeepIdV2Codec.Suite);
        var lengths = FieldLengths;
        for (var tag = 1; tag <= lengths.Length; tag++)
            ApplicationCoreFormat.ExactLength(slices, tag, lengths[tag - 1]);

        foreach (var tag in new[] { 1, 2, 3, 10, 11, 12, 16 })
            ApplicationCoreFormat.NonZero(Get(canonical, slices, tag),
                "XPI1 V2 required field");
        Reference(Get(canonical, slices, 4), ProtocolMagicBytes.DPD1);
        Reference(Get(canonical, slices, 6), ProtocolMagicBytes.XPS1);
        Reference(Get(canonical, slices, 13), ProtocolMagicBytes.DRS1);
        if (U64(Get(canonical, slices, 5)) == 0)
            Invalid(ApplicationCoreRejection.InvalidGeneration,
                "XPI1 V2 service generation must be nonzero.");
        var epoch = U64(Get(canonical, slices, 7));
        if (epoch is < 1 or > 14 ||
            ApplicationCoreFormat.IsZero(Get(canonical, slices, 8)) != (epoch == 1))
            Invalid(ApplicationCoreRejection.InvalidLineage,
                "XPI1 V2 predecessor is zero exactly at epoch one.");
        if (U16(Get(canonical, slices, 9)) is < 32 or > 4096)
            Invalid(ApplicationCoreRejection.InvalidFieldLength,
                "XPI1 V2 one-time inventory count is outside its bound.");
        if (U64(Get(canonical, slices, 14)) >= U64(Get(canonical, slices, 15)))
            Invalid(ApplicationCoreRejection.InvalidTimeRange,
                "XPI1 V2 expiry must follow issuance.");

        var owned = canonical.ToArray();
        var fields = new byte[16][];
        for (var tag = 1; tag <= fields.Length; tag++)
            fields[tag - 1] = ApplicationCoreFormat.Field(owned, slices, tag).ToArray();
        var unsigned = new byte[488];
        var writer = new ApplicationRecordWriter(unsigned,
            ProtocolMagicBytes.XPI1, 15, 2, DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= 15; tag++)
            writer.Write(tag, fields[tag - 1]);
        writer.Complete();
        return new ParsedXpi1V2(owned, fields, unsigned);
    }

    private static void Reference(ReadOnlySpan<byte> value,
        ReadOnlySpan<byte> magic)
    {
        if (!value[..4].SequenceEqual(magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(value[4..6]) != 1 ||
            ApplicationCoreFormat.IsZero(value[6..]))
            Invalid(ApplicationCoreRejection.InvalidReference,
                "XPI1 V2 has an unknown or empty artifact reference.");
    }

    private static ReadOnlySpan<byte> Get(ReadOnlySpan<byte> canonical,
        ReadOnlySpan<ApplicationFieldSlice> slices, int tag) =>
        ApplicationCoreFormat.Field(canonical, slices, tag);

    private static ushort U16(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt16BigEndian(value);

    private static ulong U64(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt64BigEndian(value);

    private static void Invalid(ApplicationCoreRejection rejection,
        string message) => throw ApplicationCoreFormat.Error(
            ApplicationCoreValidationStage.SemanticFields, rejection, message);
}
