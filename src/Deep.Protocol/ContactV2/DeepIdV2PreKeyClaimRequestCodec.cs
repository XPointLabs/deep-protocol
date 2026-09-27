using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Parsed exact DID2 XPK1 request. Parsing does not authenticate placement,
/// prove inventory publication, or consume a one-time pre-key.
/// </summary>
public sealed class ParsedXpk1V2
{
    private readonly byte[] canonical;
    private readonly byte[][] fields;

    internal ParsedXpk1V2(byte[] canonical, byte[][] fields)
    {
        this.canonical = canonical;
        this.fields = fields;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> RequestHash =>
        ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V2/request", canonical);
    public ReadOnlyMemory<byte> Field(int tag) => tag switch
    {
        >= 1 and <= 6 => fields[tag - 1].ToArray(),
        >= 16 and <= 22 => fields[tag - 10].ToArray(),
        _ => throw new ArgumentOutOfRangeException(nameof(tag))
    };
}

/// <summary>
/// Fixed 438-byte DID2 XPK1 request, version 2 / suite 0x0301. Its sparse
/// CONTACT-CODEC tags are closed; the V1 parser cannot be used for DID2.
/// </summary>
public static class DeepIdV2PreKeyClaimRequestCodec
{
    public const int CanonicalLength = 438;
    public static bool RuntimeActivation => false;
    private static ReadOnlySpan<ushort> Tags =>
        [1, 2, 3, 4, 5, 6, 16, 17, 18, 19, 20, 21, 22];
    private static ReadOnlySpan<int> Lengths =>
        [16, 32, 32, 32, 8, 8, 32, 32, 32, 32, 2, 32, 32];

    public static byte[] Encode(ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> operationId32, ReadOnlySpan<byte> viewHash32,
        ReadOnlySpan<byte> placementHash32, ulong issuedAt,
        ulong expiresAt, ReadOnlySpan<byte> serviceCapability32,
        ReadOnlySpan<byte> exactDcb1Hash32,
        ReadOnlySpan<byte> exactXps1Hash32,
        ReadOnlySpan<byte> responderDeviceId32,
        ReadOnlySpan<byte> senderEphemeralCommitment32)
    {
        var issued = new byte[8];
        var expires = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(issued, issuedAt);
        BinaryPrimitives.WriteUInt64BigEndian(expires, expiresAt);
        Span<byte> requestedSuite = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(requestedSuite,
            DeepIdV2Codec.Suite);
        var canonical = new byte[CanonicalLength];
        var writer = new ApplicationRecordWriter(canonical,
            ProtocolMagicBytes.XPK1, 13, 2, DeepIdV2Codec.Suite);
        writer.Write(1, networkId16);
        writer.Write(2, operationId32);
        writer.Write(3, viewHash32);
        writer.Write(4, placementHash32);
        writer.Write(5, issued);
        writer.Write(6, expires);
        writer.Write(16, serviceCapability32);
        writer.Write(17, exactDcb1Hash32);
        writer.Write(18, exactXps1Hash32);
        writer.Write(19, responderDeviceId32);
        writer.Write(20, requestedSuite);
        writer.Write(21, senderEphemeralCommitment32);
        writer.Write(22, operationId32);
        writer.Complete();
        _ = Decode(canonical);
        return canonical;
    }

    public static ParsedXpk1V2 Decode(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length != CanonicalLength)
            Reject(ApplicationCoreValidationStage.ExactTotalSize,
                ApplicationCoreRejection.InvalidTotalSize,
                "XPK1 V2 must have its exact closed size.");
        if (!canonical[..4].SequenceEqual(ProtocolMagicBytes.XPK1))
            Reject(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.WrongMagic,
                "XPK1 V2 magic is invalid.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[4..6]) != 2)
            Reject(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.WrongVersion,
                "XPK1 V2 does not accept a V1 envelope.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[6..8]) !=
            DeepIdV2Codec.Suite)
            Reject(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.WrongSuite,
                "XPK1 V2 suite is invalid.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[8..10]) != 13)
            Reject(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.WrongFieldCount,
                "XPK1 V2 field count is invalid.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[10..12]) != 0)
            Reject(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.ReservedNotZero,
                "XPK1 V2 header reserved value is nonzero.");

        var tags = Tags;
        var lengths = Lengths;
        var fields = new byte[tags.Length][];
        var offset = 12;
        for (var index = 0; index < tags.Length; index++)
        {
            if (canonical.Length - offset < 8)
                Reject(ApplicationCoreValidationStage.FieldHeaders,
                    ApplicationCoreRejection.TruncatedFieldHeader,
                    "XPK1 V2 field header is truncated.");
            if (BinaryPrimitives.ReadUInt16BigEndian(
                    canonical.Slice(offset, 2)) != tags[index])
                Reject(ApplicationCoreValidationStage.FieldHeaders,
                    ApplicationCoreRejection.OutOfOrderTag,
                    "XPK1 V2 tag sequence is not exact.");
            if (BinaryPrimitives.ReadUInt16BigEndian(
                    canonical.Slice(offset + 2, 2)) != 0)
                Reject(ApplicationCoreValidationStage.FieldHeaders,
                    ApplicationCoreRejection.ReservedNotZero,
                    "XPK1 V2 field reserved value is nonzero.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(
                canonical.Slice(offset + 4, 4));
            offset += 8;
            if (length != lengths[index] || length > canonical.Length - offset)
                Reject(ApplicationCoreValidationStage.FieldLengths,
                    ApplicationCoreRejection.InvalidFieldLength,
                    "XPK1 V2 field length is not exact.");
            fields[index] = canonical.Slice(offset, lengths[index]).ToArray();
            offset += lengths[index];
        }
        if (offset != canonical.Length)
            Reject(ApplicationCoreValidationStage.FieldLengths,
                ApplicationCoreRejection.TrailingBytes,
                "XPK1 V2 has trailing bytes.");
        foreach (var index in new[] { 0, 1, 2, 3, 6, 7, 8, 9, 11 })
            ApplicationCoreFormat.NonZero(fields[index],
                "XPK1 V2 required field");
        if (BinaryPrimitives.ReadUInt64BigEndian(fields[4]) >=
            BinaryPrimitives.ReadUInt64BigEndian(fields[5]))
            Reject(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.InvalidTimeRange,
                "XPK1 V2 expires before or at issuance.");
        if (BinaryPrimitives.ReadUInt16BigEndian(fields[10]) !=
            DeepIdV2Codec.Suite)
            Reject(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.InvalidEnum,
                "XPK1 V2 requested suite is not the DID2 pre-key suite.");
        if (!fields[1].AsSpan().SequenceEqual(fields[12]))
            Reject(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.CrossFieldMismatch,
                "XPK1 V2 claim operation differs from its request operation.");
        return new ParsedXpk1V2(canonical.ToArray(), fields);
    }

    private static void Reject(ApplicationCoreValidationStage stage,
        ApplicationCoreRejection rejection, string message) =>
        throw ApplicationCoreFormat.Error(stage, rejection, message);
}
