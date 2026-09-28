using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV2;

internal sealed class ParsedXpu1V2
{
    private readonly byte[] canonical;
    private readonly byte[][] fields;

    internal ParsedXpu1V2(byte[] canonical, byte[][] fields, ParsedXpa1V2 authorization)
    {
        this.canonical = canonical;
        this.fields = fields;
        Authorization = authorization;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> RequestHash => ApplicationCoreFormat.Sha256Domain(
        "Deep/ContactResolver/V2/request", canonical);
    public ParsedXpa1V2 Authorization { get; }
    public ReadOnlyMemory<byte> Field(int tag) =>
        DeepIdV2ContactPublicationCodec.Field(fields, tag,
            DeepIdV2ContactPublicationCodec.XpuTags);
}

internal sealed class ParsedXpa1V2
{
    private readonly byte[] canonical;
    private readonly byte[][] fields;

    internal ParsedXpa1V2(byte[] canonical, byte[][] fields)
    {
        this.canonical = canonical;
        this.fields = fields;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> Field(int tag) =>
        DeepIdV2ContactPublicationCodec.Field(fields, tag,
            DeepIdV2ContactPublicationCodec.XpaTags);
    public ReadOnlyMemory<byte> WitnessSigningInput =>
        DeepIdV2ContactPublicationCodec.CreateWitnessSigningInput(fields);
}

/// <summary>
/// Closed DID2-generation XPU1/XPA1 wire and cross-record binding only.
/// This parser does not verify witnesses, route authority, directory freshness,
/// DCR1 plaintext or durable two-replica publication.
/// </summary>
internal static class DeepIdV2ContactPublicationCodec
{
    public const int MaximumXpuLength = 93_032;
    public const int MinimumXpuLength = 14_622;
    public const int MinimumXpaLength = 786;
    public const int MaximumXpaLength = 3_666;
    public const int MinimumCiphertextLength = 24 + 16 + 62 +
        DeepIdV2ContactBundleCodec.MinimumLength + 1;
    public const int MaximumCiphertextLength = 65_575;
    public static bool RuntimeActivation => false;
    internal static ReadOnlySpan<ushort> XpuTags =>
        [1, 2, 3, 4, 5, 6, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27];
    internal static ReadOnlySpan<ushort> XpaTags =>
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21];
    private static ReadOnlySpan<byte> XpuMagic => ProtocolMagicBytes.XPU1;
    private static ReadOnlySpan<byte> XpaMagic => ProtocolMagicBytes.XPA1;

    public static ParsedXpu1V2 DecodeXpu1(ReadOnlySpan<byte> canonical)
    {
        var fields = Parse(canonical, XpuMagic, XpuTags,
            MinimumXpuLength, MaximumXpuLength);
        Exact(fields, 0, 16); Exact(fields, 1, 32);
        Exact(fields, 2, 32); Exact(fields, 3, 32);
        Exact(fields, 4, 8); Exact(fields, 5, 8);
        Exact(fields, 6, 32); Exact(fields, 7, 32);
        Exact(fields, 8, 8); Exact(fields, 9, 32);
        Exact(fields, 10, 32); Exact(fields, 12, 4);
        Exact(fields, 13, 8); Exact(fields, 14, 32);
        Exact(fields, 17, 32);
        Range(fields, 11, MinimumCiphertextLength, MaximumCiphertextLength);
        Range(fields, 15, 4_143, 23_295);
        Range(fields, 16, MinimumXpaLength, MaximumXpaLength);
        foreach (var index in new[] { 0, 1, 2, 3, 6, 7, 10, 14, 17 })
            Nonzero(fields[index]);
        var issued = U64(fields[4]);
        var expiry = U64(fields[5]);
        var generation = U64(fields[8]);
        if (issued >= expiry || U64(fields[13]) < expiry ||
            (generation == 0) != IsZero(fields[9]) || U32(fields[12]) > 1)
            Reject(ApplicationCoreRejection.InvalidTimeRange,
                "XPU1 V2 time, generation or usage is invalid.");
        if (!Fixed(SHA256.HashData(fields[11]), fields[10]) ||
            !Fixed(SHA256.HashData(fields[15]), fields[14]))
            Reject(ApplicationCoreRejection.CrossFieldMismatch,
                "XPU1 V2 ciphertext or route hash differs from its exact bytes.");
        var xpa = DecodeXpa1(fields[16]);
        BindXpa1(fields, xpa);
        return new ParsedXpu1V2(canonical.ToArray(), fields, xpa);
    }

    public static ParsedXpa1V2 DecodeXpa1(ReadOnlySpan<byte> canonical)
    {
        var fields = Parse(canonical, XpaMagic, XpaTags,
            MinimumXpaLength, MaximumXpaLength);
        ReadOnlySpan<int> lengths =
            [16, 32, 32, 32, 1, 32, 32, 32, 8, 32, 32, 4, 8,
             32, 8, 8, 8, 32, 32, 1];
        for (var index = 0; index < lengths.Length; index++)
            Exact(fields, index, lengths[index]);
        foreach (var index in new[] { 0, 1, 2, 3, 5, 6, 7, 10, 13, 17, 18 })
            Nonzero(fields[index]);
        var count = fields[19][0];
        if (count is < 2 or > 32 || fields[20].Length != count * 96 ||
            fields[4][0] is not (1 or 2) ||
            U32(fields[11]) != (fields[4][0] == 1 ? 0u : 1u) ||
            (U64(fields[8]) == 0) != IsZero(fields[9]) ||
            U64(fields[14]) > U64(fields[15]) ||
            U64(fields[15]) >= U64(fields[16]))
            Reject(ApplicationCoreRejection.InvalidEnum,
                "XPA1 V2 witness count, kind, lineage or time is invalid.");
        ReadOnlySpan<byte> prior = default;
        for (var index = 0; index < count; index++)
        {
            var row = fields[20].AsSpan(index * 96, 96);
            if (IsZero(row[..32]) || IsZero(row[32..]) ||
                (!prior.IsEmpty && prior.SequenceCompareTo(row[..32]) >= 0))
                Reject(ApplicationCoreRejection.InvalidEnum,
                    "XPA1 V2 witnesses are duplicate, unordered or zero.");
            prior = row[..32];
        }
        return new ParsedXpa1V2(canonical.ToArray(), fields);
    }

    public static byte[] ComputeAuthorizedBodyHash(ReadOnlySpan<byte> exactXpu1)
    {
        var fields = Parse(exactXpu1, XpuMagic, XpuTags,
            MinimumXpuLength, MaximumXpuLength);
        return BodyHash(fields);
    }

    internal static byte[] CreateWitnessSigningInput(byte[][] fields)
    {
        var length = 12;
        for (var index = 0; index < 20; index++)
            length = checked(length + 8 + fields[index].Length);
        var unsigned = new byte[length];
        var writer = new ApplicationRecordWriter(unsigned, XpaMagic,
            20, 2, DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= 20; tag++)
            writer.Write(tag, fields[tag - 1]);
        writer.Complete();
        return ApplicationCoreFormat.SignatureInput(
            "Deep/ContactResolver/V2/publication-authorization",
            unsigned, DeepIdV2Codec.Suite);
    }

    private static void BindXpa1(byte[][] xpu, ParsedXpa1V2 parsed)
    {
        var xpa = Enumerable.Range(1, 21)
            .Select(tag => parsed.Field(tag).ToArray()).ToArray();
        if (!Fixed(xpa[0], xpu[0]) || !Fixed(xpa[2], xpu[1]) ||
            !Fixed(xpa[3], xpu[6]) || !Fixed(xpa[7], xpu[7]) ||
            !Fixed(xpa[8], xpu[8]) || !Fixed(xpa[9], xpu[9]) ||
            !Fixed(xpa[10], xpu[10]) || !Fixed(xpa[11], xpu[12]) ||
            !Fixed(xpa[12], xpu[13]) || !Fixed(xpa[18], BodyHash(xpu)) ||
            xpa[4][0] == 1 && U32(xpu[12]) != 0 ||
            xpa[4][0] == 2 && U32(xpu[12]) != 1)
            Reject(ApplicationCoreRejection.CrossFieldMismatch,
                "XPA1 V2 does not bind the exact XPU1 V2 body.");
        var authorizationInput = new byte[96];
        xpu[1].CopyTo(authorizationInput, 0);
        xpa[18].CopyTo(authorizationInput, 32);
        xpa[17].CopyTo(authorizationInput, 64);
        var expected = ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V2/publication-authorization-id",
            authorizationInput);
        if (!Fixed(expected, xpa[1]))
            Reject(ApplicationCoreRejection.CrossFieldMismatch,
                "XPA1 V2 authorization ID differs from its operation, body and head.");
    }

    private static byte[] BodyHash(byte[][] fields)
    {
        var tags = XpuTags;
        var length = 12;
        for (var index = 0; index < fields.Length; index++)
            if (tags[index] != 26) length = checked(length + 8 + fields[index].Length);
        var projection = new byte[length];
        var writer = new ApplicationRecordWriter(projection, XpuMagic,
            17, 2, DeepIdV2Codec.Suite);
        for (var index = 0; index < fields.Length; index++)
            if (tags[index] != 26) writer.Write(tags[index], fields[index]);
        writer.Complete();
        return ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V2/XPU-authorized-body", projection);
    }

    internal static ReadOnlyMemory<byte> Field(byte[][] fields, int tag,
        ReadOnlySpan<ushort> tags)
    {
        for (var index = 0; index < tags.Length; index++)
            if (tags[index] == tag) return fields[index].ToArray();
        throw new ArgumentOutOfRangeException(nameof(tag));
    }

    private static byte[][] Parse(ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> magic, ReadOnlySpan<ushort> tags,
        int minimum, int maximum)
    {
        if (canonical.Length < minimum || canonical.Length > maximum)
            Reject(ApplicationCoreRejection.InvalidTotalSize,
                "Contact publication V2 record size is invalid.");
        if (!canonical[..4].SequenceEqual(magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[4..6]) != 2 ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[6..8]) !=
                DeepIdV2Codec.Suite ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[8..10]) != tags.Length ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[10..12]) != 0)
            Reject(ApplicationCoreRejection.WrongVersion,
                "Contact publication V2 header is invalid.");
        var fields = new byte[tags.Length][];
        var offset = 12;
        for (var index = 0; index < tags.Length; index++)
        {
            if (canonical.Length - offset < 8 ||
                BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(offset, 2)) != tags[index] ||
                BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(offset + 2, 2)) != 0)
                Reject(ApplicationCoreRejection.OutOfOrderTag,
                    "Contact publication V2 tag or reserved field is invalid.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(offset + 4, 4));
            offset += 8;
            if (length > int.MaxValue || length > canonical.Length - offset)
                Reject(ApplicationCoreRejection.InvalidFieldLength,
                    "Contact publication V2 field length is invalid.");
            fields[index] = canonical.Slice(offset, (int)length).ToArray();
            offset += (int)length;
        }
        if (offset != canonical.Length)
            Reject(ApplicationCoreRejection.TrailingBytes,
                "Contact publication V2 has trailing bytes.");
        return fields;
    }

    private static void Exact(byte[][] fields, int index, int length)
    {
        if (fields[index].Length != length)
            Reject(ApplicationCoreRejection.InvalidFieldLength,
                "Contact publication V2 fixed field length is invalid.");
    }

    private static void Range(byte[][] fields, int index, int minimum, int maximum)
    {
        if (fields[index].Length < minimum || fields[index].Length > maximum)
            Reject(ApplicationCoreRejection.InvalidFieldLength,
                "Contact publication V2 variable field length is invalid.");
    }

    private static void Nonzero(ReadOnlySpan<byte> bytes)
    {
        if (IsZero(bytes))
            Reject(ApplicationCoreRejection.ZeroForbidden,
                "Contact publication V2 required field is zero.");
    }

    private static bool IsZero(ReadOnlySpan<byte> bytes) =>
        bytes.IndexOfAnyExcept((byte)0) < 0;
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static ulong U64(ReadOnlySpan<byte> bytes) =>
        BinaryPrimitives.ReadUInt64BigEndian(bytes);
    private static uint U32(ReadOnlySpan<byte> bytes) =>
        BinaryPrimitives.ReadUInt32BigEndian(bytes);
    private static void Reject(ApplicationCoreRejection code, string message) =>
        throw ApplicationCoreFormat.Error(
            ApplicationCoreValidationStage.SemanticFields, code, message);
}
