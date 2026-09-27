using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Parsed exact DID2 XPP1 publication. Structural validity does not prove
/// current placement, predecessor lineage, replica commit, or claimability.
/// </summary>
public sealed class ParsedXpp1V2
{
    private readonly byte[] canonical;
    private readonly byte[] networkId;
    private readonly byte[] operationId;
    private readonly byte[] placementHash;
    private readonly IReadOnlyList<ParsedDpk2V2> oneTimeMembers;

    internal ParsedXpp1V2(byte[] canonical, byte[] networkId,
        byte[] operationId, byte[] placementHash, ParsedXpi1V2 manifest,
        ParsedDpk2V2[] oneTimeMembers, ParsedDpk2V2 lastResortMember)
    {
        this.canonical = canonical;
        this.networkId = networkId;
        this.operationId = operationId;
        this.placementHash = placementHash;
        Manifest = manifest;
        this.oneTimeMembers = Array.AsReadOnly(oneTimeMembers);
        LastResortMember = lastResortMember;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> PublicationOperationId => operationId.ToArray();
    public ReadOnlyMemory<byte> PlacementHash => placementHash.ToArray();
    public ParsedXpi1V2 Manifest { get; }
    public IReadOnlyList<ParsedDpk2V2> OneTimeMembers => oneTimeMembers;
    public ParsedDpk2V2 LastResortMember { get; }
}

/// <summary>
/// Bounded, closed DID2 XPP1 envelope. It never accepts V1 XPI1 or DPK2.
/// The complete inventory and current authorization must be independently
/// verified before either replica may durably commit this publication.
/// </summary>
public static class DeepIdV2PreKeyPublicationCodec
{
    public const int MinimumTotalBytes = 67_983;
    public const int MaximumTotalBytes = 8_362_607;
    public static bool RuntimeActivation => false;

    public static byte[] Encode(ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> publicationOperationId32,
        ReadOnlySpan<byte> placementHash32, ParsedXpi1V2 manifest,
        IReadOnlyList<ParsedDpk2V2> oneTimeMembers,
        ParsedDpk2V2 lastResortMember)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(oneTimeMembers);
        ArgumentNullException.ThrowIfNull(lastResortMember);
        if (networkId16.Length != 16 ||
            publicationOperationId32.Length != 32 ||
            placementHash32.Length != 32 ||
            ApplicationCoreFormat.IsZero(networkId16) ||
            ApplicationCoreFormat.IsZero(publicationOperationId32) ||
            ApplicationCoreFormat.IsZero(placementHash32))
            throw new ArgumentException("XPP1 network, operation and placement must be exact nonzero values.");
        if (oneTimeMembers.Count is < 32 or > 4096 ||
            oneTimeMembers.Count != BinaryPrimitives.ReadUInt16BigEndian(
                manifest.Field(9).Span) ||
            !networkId16.SequenceEqual(manifest.Field(1).Span))
            throw new ArgumentException("XPP1 does not match its exact V2 XPI1 manifest.");

        var oneTimeBytes = new byte[oneTimeMembers.Count][];
        for (var index = 0; index < oneTimeBytes.Length; index++)
        {
            var member = oneTimeMembers[index] ?? throw new ArgumentException(
                "XPP1 contains a missing one-time DPK2.", nameof(oneTimeMembers));
            if (member.Kind != Dpk2PrekeyKind.OneTime ||
                !networkId16.SequenceEqual(member.NetworkId.Span))
                throw new ArgumentException("XPP1 contains a wrong-kind or wrong-network DPK2.",
                    nameof(oneTimeMembers));
            oneTimeBytes[index] = member.CanonicalBytes.ToArray();
        }
        if (lastResortMember.Kind != Dpk2PrekeyKind.LastResort ||
            !networkId16.SequenceEqual(lastResortMember.NetworkId.Span))
            throw new ArgumentException("XPP1 last-resort DPK2 is invalid.",
                nameof(lastResortMember));
        var lastResortBytes = lastResortMember.CanonicalBytes.ToArray();
        var bodyLength = checked(2 +
            oneTimeBytes.Length * (4 + Dpk2Codec.OneTimeTotalBytes) +
            4 + Dpk2Codec.LastResortTotalBytes);
        var body = new byte[bodyLength];
        BinaryPrimitives.WriteUInt16BigEndian(body, checked((ushort)oneTimeBytes.Length));
        var offset = 2;
        foreach (var exact in oneTimeBytes)
        {
            BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(offset, 4),
                checked((uint)exact.Length));
            offset += 4;
            exact.CopyTo(body, offset);
            offset += exact.Length;
        }
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(offset, 4),
            checked((uint)lastResortBytes.Length));
        lastResortBytes.CopyTo(body, offset + 4);

        var exactManifest = manifest.CanonicalBytes;
        var total = checked(12 + 5 * 8 + 16 + 32 + 32 +
            exactManifest.Length + body.Length);
        if (total is < MinimumTotalBytes or > MaximumTotalBytes)
            throw new ArgumentException("XPP1 exceeds its closed allocation bound.");
        var canonical = new byte[total];
        var writer = new ApplicationRecordWriter(canonical,
            ProtocolMagicBytes.XPP1, 5, 2, DeepIdV2Codec.Suite);
        writer.Write(1, networkId16);
        writer.Write(2, publicationOperationId32);
        writer.Write(3, placementHash32);
        writer.Write(4, exactManifest.Span);
        writer.Write(5, body);
        writer.Complete();
        _ = Decode(canonical);
        return canonical;
    }

    public static ParsedXpp1V2 Decode(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[5];
        ApplicationCoreFormat.Preflight(canonical, ProtocolMagicBytes.XPP1,
            5, MinimumTotalBytes, MaximumTotalBytes, fields, 2,
            DeepIdV2Codec.Suite);
        ApplicationCoreFormat.ExactLength(fields, 1, 16);
        ApplicationCoreFormat.ExactLength(fields, 2, 32);
        ApplicationCoreFormat.ExactLength(fields, 3, 32);
        ApplicationCoreFormat.ExactLength(fields, 4,
            DeepIdV2PreKeyManifestCodec.CanonicalLength);
        var network = ApplicationCoreFormat.Field(canonical, fields, 1);
        var operation = ApplicationCoreFormat.Field(canonical, fields, 2);
        var placement = ApplicationCoreFormat.Field(canonical, fields, 3);
        ApplicationCoreFormat.NonZero(network, "XPP1 network ID");
        ApplicationCoreFormat.NonZero(operation, "XPP1 operation ID");
        ApplicationCoreFormat.NonZero(placement, "XPP1 placement hash");
        var manifest = DecodeManifest(
            ApplicationCoreFormat.Field(canonical, fields, 4));
        if (!network.SequenceEqual(manifest.Field(1).Span))
            Reject(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.CrossFieldMismatch,
                "XPP1 network differs from its V2 XPI1 manifest.");

        var body = ApplicationCoreFormat.Field(canonical, fields, 5);
        if (body.Length < 2)
            Reject(ApplicationCoreValidationStage.FieldLengths,
                ApplicationCoreRejection.InvalidFieldLength,
                "XPP1 inventory body is truncated.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(body);
        if (count is < 32 or > 4096 ||
            count != BinaryPrimitives.ReadUInt16BigEndian(manifest.Field(9).Span) ||
            body.Length != 2 + count * (4 + Dpk2Codec.OneTimeTotalBytes) +
                4 + Dpk2Codec.LastResortTotalBytes)
            Reject(ApplicationCoreValidationStage.FieldLengths,
                ApplicationCoreRejection.InvalidFieldLength,
                "XPP1 body does not contain the manifest's exact bounded inventory.");
        var members = new ParsedDpk2V2[count];
        var offset = 2;
        for (var index = 0; index < count; index++)
        {
            var exact = ReadMember(body, ref offset, Dpk2Codec.OneTimeTotalBytes);
            members[index] = DecodeMember(exact);
            if (members[index].Kind != Dpk2PrekeyKind.OneTime ||
                !network.SequenceEqual(members[index].NetworkId.Span))
                Reject(ApplicationCoreValidationStage.SemanticFields,
                    ApplicationCoreRejection.CrossFieldMismatch,
                    "XPP1 contains a wrong-kind or wrong-network one-time DPK2.");
        }
        var last = DecodeMember(ReadMember(body, ref offset,
            Dpk2Codec.LastResortTotalBytes));
        if (offset != body.Length || last.Kind != Dpk2PrekeyKind.LastResort ||
            !network.SequenceEqual(last.NetworkId.Span))
            Reject(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.CrossFieldMismatch,
                "XPP1 last-resort DPK2 or body extent is invalid.");
        return new ParsedXpp1V2(canonical.ToArray(), network.ToArray(),
            operation.ToArray(), placement.ToArray(), manifest, members, last);
    }

    private static ParsedXpi1V2 DecodeManifest(ReadOnlySpan<byte> exact)
    {
        try { return DeepIdV2PreKeyManifestCodec.Decode(exact); }
        catch (FormatException exception)
        {
            throw ApplicationCoreFormat.Error(
                ApplicationCoreValidationStage.EmbeddedRecord,
                ApplicationCoreRejection.EmbeddedRecordRejected,
                "XPP1 contains an invalid exact V2 XPI1.", exception);
        }
    }

    private static ParsedDpk2V2 DecodeMember(ReadOnlySpan<byte> exact)
    {
        try { return DeepIdV2Dpk2Codec.Decode(exact); }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            throw ApplicationCoreFormat.Error(
                ApplicationCoreValidationStage.EmbeddedRecord,
                ApplicationCoreRejection.EmbeddedRecordRejected,
                "XPP1 contains an invalid exact V2 DPK2.", exception);
        }
    }

    private static ReadOnlySpan<byte> ReadMember(ReadOnlySpan<byte> body,
        ref int offset, int expectedLength)
    {
        if (body.Length - offset < 4 ||
            BinaryPrimitives.ReadUInt32BigEndian(body.Slice(offset, 4)) !=
                expectedLength || body.Length - offset - 4 < expectedLength)
            Reject(ApplicationCoreValidationStage.FieldLengths,
                ApplicationCoreRejection.InvalidFieldLength,
                "XPP1 has a noncanonical DPK2 length prefix.");
        offset += 4;
        var exact = body.Slice(offset, expectedLength);
        offset += expectedLength;
        return exact;
    }

    private static void Reject(ApplicationCoreValidationStage stage,
        ApplicationCoreRejection rejection, string message) =>
        throw ApplicationCoreFormat.Error(stage, rejection, message);
}
