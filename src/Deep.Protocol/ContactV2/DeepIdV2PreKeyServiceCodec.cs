using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// DID2-only XPS1. The same field shape as the retired service descriptor is
/// deliberately re-versioned and re-signed; its bytes cannot be replayed into
/// the V2 inventory or contact bundle.
/// </summary>
public sealed class ParsedXps1V2
{
    private readonly byte[] canonical;
    private readonly byte[][] fields;
    private readonly byte[] unsigned;

    internal ParsedXps1V2(byte[] canonical, byte[][] fields,
        byte[] unsigned)
    {
        this.canonical = canonical;
        this.fields = fields;
        this.unsigned = unsigned;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> SignatureInput =>
        ApplicationCoreFormat.SignatureInput(
            DeepIdV2PreKeyServiceCodec.SignatureDomain, unsigned,
            DeepIdV2Codec.Suite);
    public ReadOnlyMemory<byte> Field(int tag) => tag is >= 1 and <= 12
        ? fields[tag - 1].ToArray()
        : throw new ArgumentOutOfRangeException(nameof(tag));
}

public static class DeepIdV2PreKeyServiceCodec
{
    public const int CanonicalLength = 352;
    public const string SignatureDomain =
        "Deep/ContactResolver/V2/prekey-service";
    private static ReadOnlySpan<int> FieldLengths =>
        [16, 32, 32, 38, 8, 32, 2, 2, 2, 8, 8, 64];

    public static byte[] CreateSignatureInput(
        IReadOnlyList<ReadOnlyMemory<byte>> unsignedFields)
    {
        var placeholder = new byte[64];
        placeholder.AsSpan().Fill(1);
        return Decode(Encode(unsignedFields, placeholder))
            .SignatureInput.ToArray();
    }

    public static byte[] Encode(
        IReadOnlyList<ReadOnlyMemory<byte>> unsignedFields,
        ReadOnlySpan<byte> deviceSignature64)
    {
        ArgumentNullException.ThrowIfNull(unsignedFields);
        if (unsignedFields.Count != 11 ||
            unsignedFields.Where((field, index) =>
                field.Length != FieldLengths[index]).Any() ||
            deviceSignature64.Length != 64)
            throw new ArgumentException("XPS1 V2 authoring fields are not exact.");
        var bytes = new byte[CanonicalLength];
        var writer = new ApplicationRecordWriter(bytes,
            ProtocolMagicBytes.XPS1, 12, 2, DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= 11; tag++)
            writer.Write(tag, unsignedFields[tag - 1].Span);
        writer.Write(12, deviceSignature64);
        writer.Complete();
        _ = Decode(bytes);
        return bytes;
    }

    public static ParsedXps1V2 Decode(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> slices = stackalloc ApplicationFieldSlice[12];
        ApplicationCoreFormat.Preflight(canonical, ProtocolMagicBytes.XPS1,
            12, CanonicalLength, CanonicalLength, slices, 2,
            DeepIdV2Codec.Suite);
        var lengths = FieldLengths;
        for (var tag = 1; tag <= lengths.Length; tag++)
            ApplicationCoreFormat.ExactLength(slices, tag, lengths[tag - 1]);
        var fields = new byte[12][];
        for (var tag = 1; tag <= fields.Length; tag++)
            fields[tag - 1] = ApplicationCoreFormat.Field(canonical, slices,
                tag).ToArray();
        for (var tag = 1; tag <= 3; tag++)
            ApplicationCoreFormat.NonZero(fields[tag - 1],
                "XPS1 V2 required field");
        ApplicationCoreFormat.NonZero(fields[11],
            "XPS1 V2 device signature");
        var dpd = fields[3].AsSpan();
        var generation = BinaryPrimitives.ReadUInt64BigEndian(fields[4]);
        var minimum = BinaryPrimitives.ReadUInt16BigEndian(fields[7]);
        var reuse = BinaryPrimitives.ReadUInt16BigEndian(fields[8]);
        if (!dpd[..4].SequenceEqual(ProtocolMagicBytes.DPD1) ||
            BinaryPrimitives.ReadUInt16BigEndian(dpd[4..6]) != 1 ||
            ApplicationCoreFormat.IsZero(dpd[6..]) ||
            generation == 0 ||
            ApplicationCoreFormat.IsZero(fields[5]) != (generation == 1) ||
            BinaryPrimitives.ReadUInt16BigEndian(fields[6]) !=
                DeepIdV2Codec.Suite ||
            minimum is < 1 or > 4096 || reuse is < 1 or > 64 ||
            BinaryPrimitives.ReadUInt64BigEndian(fields[9]) >=
                BinaryPrimitives.ReadUInt64BigEndian(fields[10]))
            throw ApplicationCoreFormat.Error(
                ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.CrossFieldMismatch,
                "XPS1 V2 is not a canonical DID2 service descriptor.");
        var owned = canonical.ToArray();
        var unsigned = new byte[280];
        var projection = new ApplicationRecordWriter(unsigned,
            ProtocolMagicBytes.XPS1, 11, 2, DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= 11; tag++)
            projection.Write(tag, fields[tag - 1]);
        projection.Complete();
        return new ParsedXps1V2(owned, fields, unsigned);
    }

    public static void VerifyDeviceSignature(ParsedXps1V2 descriptor,
        ReadOnlySpan<byte> deviceEd25519PublicKey)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (deviceEd25519PublicKey.Length != 32 ||
            !PublicKeyAuth.VerifyDetached(descriptor.Field(12).ToArray(),
                descriptor.SignatureInput.ToArray(),
                deviceEd25519PublicKey.ToArray()))
            throw ApplicationCoreFormat.Error(
                ApplicationCoreValidationStage.CryptographicVerification,
                ApplicationCoreRejection.VerificationFailed,
                "XPS1 V2 device signature is invalid.");
    }
}
