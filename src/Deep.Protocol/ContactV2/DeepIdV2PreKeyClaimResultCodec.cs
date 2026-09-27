using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.ContactV2;

public enum Xpc1V2Status : ushort
{
    Claimed = 1,
    Replay = 2,
    PreKeysUnavailable = 3,
    Expired = 4,
    StaleBundle = 5,
    RateLimited = 6,
    Conflict = 7,
    OutcomeUnknown = 8,
}

public enum Xpc1V2MutationOutcome : byte
{
    None = 0,
    DurablyCommitted = 1,
    OutcomeUnknown = 2,
}

/// <summary>
/// Parsed padded XPC1 V2 wire. This is not an authenticated replica result:
/// PMT2 placement, both replica signatures and durable CAS are external gates.
/// </summary>
public sealed class ParsedXpc1V2
{
    private readonly byte[] canonical;
    private readonly byte[] wire;
    private readonly IReadOnlyDictionary<int, byte[]> fields;

    internal ParsedXpc1V2(byte[] canonical, byte[] wire,
        Dictionary<int, byte[]> fields, Xpc1V2Status status,
        Xpc1V2MutationOutcome mutationOutcome)
    {
        this.canonical = canonical;
        this.wire = wire;
        this.fields = fields;
        Status = status;
        MutationOutcome = mutationOutcome;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> WireBytes => wire.ToArray();
    public Xpc1V2Status Status { get; }
    public Xpc1V2MutationOutcome MutationOutcome { get; }
    public ReadOnlyMemory<byte> Field(int tag) => fields.TryGetValue(tag,
        out var value) ? value.ToArray() : ReadOnlyMemory<byte>.Empty;
}

/// <summary>
/// Closed DID2 XPC1 result grammar. It validates exact V2 claim bindings and
/// inventory inclusion but cannot turn unsigned bytes into claim authority.
/// </summary>
public static class DeepIdV2PreKeyClaimResultCodec
{
    private static ReadOnlySpan<int> PaddingBuckets => [256, 1024, 4096, 16384];
    public static bool RuntimeActivation => false;

    public static byte[] Encode(ReadOnlySpan<byte> exactXpk1,
        Xpc1V2Status status, Xpc1V2MutationOutcome outcome,
        ulong serverTime, uint retryAfter,
        IReadOnlyList<ReadOnlyMemory<byte>> payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var request = DeepIdV2PreKeyClaimRequestCodec.Decode(exactXpk1);
        if (payload.Count > 13)
            throw new ArgumentOutOfRangeException(nameof(payload));
        var count = checked((ushort)(8 + payload.Count));
        var canonicalLength = checked(12 + count * 8 + 16 + 32 + 32 +
            2 + 1 + 8 + 4 + 2 + payload.Sum(static item => item.Length));
        var paddingClass = PaddingClass(canonicalLength);
        var canonical = new byte[canonicalLength];
        var writer = new ApplicationRecordWriter(canonical,
            ProtocolMagicBytes.XPC1, count, 2, DeepIdV2Codec.Suite);
        writer.Write(1, request.Field(1).Span);
        writer.Write(2, request.Field(2).Span);
        writer.Write(3, request.RequestHash.Span);
        Span<byte> statusBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(statusBytes, (ushort)status);
        writer.Write(4, statusBytes);
        writer.Write(5, [(byte)outcome]);
        Span<byte> timeBytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(timeBytes, serverTime);
        writer.Write(6, timeBytes);
        Span<byte> retryBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(retryBytes, retryAfter);
        writer.Write(7, retryBytes);
        Span<byte> classBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(classBytes,
            checked((ushort)paddingClass));
        writer.Write(8, classBytes);
        for (var index = 0; index < payload.Count; index++)
            writer.Write(checked((ushort)(16 + index)), payload[index].Span);
        writer.Complete();
        var wire = new byte[PaddingBuckets[paddingClass]];
        canonical.CopyTo(wire, 0);
        _ = Decode(wire, exactXpk1);
        return wire;
    }

    public static ParsedXpc1V2 Decode(ReadOnlySpan<byte> exactWire,
        ReadOnlySpan<byte> exactXpk1)
    {
        var request = DeepIdV2PreKeyClaimRequestCodec.Decode(exactXpk1);
        if (exactWire.Length is not (256 or 1024 or 4096 or 16384))
            Fail(ApplicationCoreValidationStage.ExactTotalSize,
                ApplicationCoreRejection.InvalidTotalSize,
                "XPC1 V2 has no canonical padding bucket.");
        if (!exactWire[..4].SequenceEqual(ProtocolMagicBytes.XPC1))
            Fail(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.WrongMagic,
                "XPC1 V2 magic is invalid.");
        if (BinaryPrimitives.ReadUInt16BigEndian(exactWire[4..6]) != 2)
            Fail(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.WrongVersion,
                "XPC1 V2 does not accept a V1 result.");
        if (BinaryPrimitives.ReadUInt16BigEndian(exactWire[6..8]) !=
            DeepIdV2Codec.Suite)
            Fail(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.WrongSuite,
                "XPC1 V2 suite is invalid.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exactWire[8..10]);
        if (count is < 8 or > 21)
            Fail(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.WrongFieldCount,
                "XPC1 V2 field count is outside its closed matrix.");
        if (BinaryPrimitives.ReadUInt16BigEndian(exactWire[10..12]) != 0)
            Fail(ApplicationCoreValidationStage.FixedHeader,
                ApplicationCoreRejection.ReservedNotZero,
                "XPC1 V2 reserved header value is nonzero.");

        var offsets = new int[29];
        var lengths = new int[29];
        var offset = 12;
        for (var index = 0; index < count; index++)
        {
            if (exactWire.Length - offset < 8)
                Fail(ApplicationCoreValidationStage.FieldHeaders,
                    ApplicationCoreRejection.TruncatedFieldHeader,
                    "XPC1 V2 field header is truncated.");
            var tag = BinaryPrimitives.ReadUInt16BigEndian(
                exactWire.Slice(offset, 2));
            var expected = index < 8 ? index + 1 : index + 8;
            if (tag != expected)
                Fail(ApplicationCoreValidationStage.FieldHeaders,
                    ApplicationCoreRejection.OutOfOrderTag,
                    "XPC1 V2 field sequence is not exact.");
            if (BinaryPrimitives.ReadUInt16BigEndian(
                    exactWire.Slice(offset + 2, 2)) != 0)
                Fail(ApplicationCoreValidationStage.FieldHeaders,
                    ApplicationCoreRejection.ReservedNotZero,
                    "XPC1 V2 field reserved value is nonzero.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(
                exactWire.Slice(offset + 4, 4));
            offset += 8;
            if (length > exactWire.Length - offset)
                Fail(ApplicationCoreValidationStage.FieldLengths,
                    ApplicationCoreRejection.InvalidFieldLength,
                    "XPC1 V2 field exceeds its bounded wire.");
            offsets[tag] = offset;
            lengths[tag] = checked((int)length);
            offset += (int)length;
        }
        var canonicalLength = offset;
        for (var tag = 1; tag <= 8; tag++)
        {
            var expectedLength = tag switch
            {
                1 => 16, 2 or 3 => 32, 4 or 8 => 2,
                5 => 1, 6 => 8, 7 => 4, _ => 0
            };
            RequireLength(lengths, tag, expectedLength);
        }
        var ownedWire = exactWire.ToArray();
        ReadOnlySpan<byte> Field(int tag) =>
            ownedWire.AsSpan(offsets[tag], lengths[tag]);
        foreach (var tag in new[] { 1, 2, 3 })
            ApplicationCoreFormat.NonZero(Field(tag),
                "XPC1 V2 required field");
        if (!Fixed(Field(1), request.Field(1).Span) ||
            !Fixed(Field(2), request.Field(2).Span) ||
            !Fixed(Field(3), request.RequestHash.Span))
            Fail(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.CrossFieldMismatch,
                "XPC1 V2 does not bind its exact V2 request.");
        var classId = BinaryPrimitives.ReadUInt16BigEndian(Field(8));
        if (classId >= PaddingBuckets.Length ||
            classId != PaddingClass(canonicalLength) ||
            exactWire.Length != PaddingBuckets[classId] ||
            !ApplicationCoreFormat.IsZero(exactWire[canonicalLength..]))
            Fail(ApplicationCoreValidationStage.FieldLengths,
                ApplicationCoreRejection.InvalidFieldLength,
                "XPC1 V2 padding class or padding bytes are not canonical.");

        var status = (Xpc1V2Status)BinaryPrimitives.ReadUInt16BigEndian(Field(4));
        var outcome = (Xpc1V2MutationOutcome)Field(5)[0];
        var retry = BinaryPrimitives.ReadUInt32BigEndian(Field(7));
        var serverTime = BinaryPrimitives.ReadUInt64BigEndian(Field(6));
        if (!Enum.IsDefined(status) || !Enum.IsDefined(outcome) ||
            serverTime == 0)
            Fail(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.InvalidEnum,
                "XPC1 V2 status, mutation outcome or server time is invalid.");
        switch (status)
        {
            case Xpc1V2Status.Claimed:
            case Xpc1V2Status.Replay:
                if (count != 21 ||
                    outcome != Xpc1V2MutationOutcome.DurablyCommitted ||
                    retry != 0)
                    InvalidMatrix();
                VerifyClaimed(ownedWire, offsets, lengths, request,
                    serverTime);
                break;
            case Xpc1V2Status.StaleBundle:
                if (count != 11 || outcome != Xpc1V2MutationOutcome.None ||
                    retry != 0)
                    InvalidMatrix();
                for (var tag = 16; tag <= 18; tag++)
                {
                    RequireLength(lengths, tag, 32);
                    ApplicationCoreFormat.NonZero(Field(tag),
                        "XPC1 V2 stale-bundle hash");
                }
                break;
            case Xpc1V2Status.Conflict:
                if (count != 9 || outcome != Xpc1V2MutationOutcome.None ||
                    retry != 0)
                    InvalidMatrix();
                RequireLength(lengths, 16, 32);
                ApplicationCoreFormat.NonZero(Field(16),
                    "XPC1 V2 conflict evidence hash");
                break;
            case Xpc1V2Status.RateLimited:
                if (count != 8 || outcome != Xpc1V2MutationOutcome.None ||
                    retry == 0)
                    InvalidMatrix();
                break;
            case Xpc1V2Status.OutcomeUnknown:
                if (count != 8 ||
                    outcome != Xpc1V2MutationOutcome.OutcomeUnknown ||
                    retry == 0)
                    InvalidMatrix();
                break;
            default:
                if (count != 8 || outcome != Xpc1V2MutationOutcome.None ||
                    retry != 0)
                    InvalidMatrix();
                break;
        }
        var ownedFields = new Dictionary<int, byte[]>(count);
        for (var tag = 1; tag <= 28; tag++)
            if (lengths[tag] != 0 || tag is 28 && count == 21)
                ownedFields.Add(tag, Field(tag).ToArray());
        return new ParsedXpc1V2(ownedWire[..canonicalLength],
            ownedWire, ownedFields, status, outcome);
    }

    private static void VerifyClaimed(byte[] wire,
        int[] offsets, int[] lengths,
        ParsedXpk1V2 request, ulong serverTime)
    {
        ReadOnlySpan<byte> Field(int tag) =>
            wire.AsSpan(offsets[tag], lengths[tag]);
        RequireLength(lengths, 17, 32);
        RequireLength(lengths, 18, 32);
        RequireLength(lengths, 19, 32);
        RequireLength(lengths, 20, 38);
        RequireLength(lengths, 21, 8);
        RequireLength(lengths, 22, 8);
        RequireLength(lengths, 23, 2);
        RequireLength(lengths, 24, 8);
        RequireLength(lengths, 25, 193);
        RequireLength(lengths, 26,
            DeepIdV2PreKeyManifestCodec.CanonicalLength);
        RequireLength(lengths, 27, 2);
        if (lengths[16] is < 1 or > 2037 || lengths[28] > 384 ||
            lengths[28] % 32 != 0)
            Fail(ApplicationCoreValidationStage.FieldLengths,
                ApplicationCoreRejection.InvalidFieldLength,
                "XPC1 V2 DPK2 or inventory proof length is invalid.");

        ParsedDpk2V2 offering;
        ParsedXpi1V2 manifest;
        try
        {
            offering = DeepIdV2Dpk2Codec.Decode(Field(16));
            manifest = DeepIdV2PreKeyManifestCodec.Decode(Field(26));
        }
        catch (Exception exception) when (exception is FormatException or
            CryptographicException or ArgumentException)
        {
            Fail(ApplicationCoreValidationStage.EmbeddedRecord,
                ApplicationCoreRejection.EmbeddedRecordRejected,
                "XPC1 V2 contains an invalid exact DID2 offering or manifest.");
            throw;
        }

        // Server time is not a trusted clock source. Even as an unsigned
        // projection, a successful claim must not contradict the exact
        // request, inventory, or selected offering validity windows.
        if (serverTime < BinaryPrimitives.ReadUInt64BigEndian(
                request.Field(5).Span) ||
            serverTime >= BinaryPrimitives.ReadUInt64BigEndian(
                request.Field(6).Span) ||
            serverTime < BinaryPrimitives.ReadUInt64BigEndian(
                manifest.FieldSpan(14)) ||
            serverTime >= BinaryPrimitives.ReadUInt64BigEndian(
                manifest.FieldSpan(15)) ||
            serverTime < offering.Record.NotBefore ||
            serverTime >= offering.ExpiresAt)
            Fail(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.InvalidTimeRange,
                "XPC1 V2 server time is outside the exact claim and inventory validity windows.");

        var counter = BinaryPrimitives.ReadUInt16BigEndian(Field(23));
        var generation = BinaryPrimitives.ReadUInt64BigEndian(Field(24));
        byte[] expectedReceipt;
        try
        {
            expectedReceipt = DeepIdV2PreKeyClaimCommitment.ComputeReceiptHash(
                request.CanonicalBytes.Span, Field(16), Field(26),
                generation, counter);
        }
        catch (Exception exception) when (exception is FormatException or
            CryptographicException or ArgumentException)
        {
            Fail(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.CrossFieldMismatch,
                "XPC1 V2 claim tuple does not bind one DID2 inventory epoch.");
            throw;
        }
        if (!Fixed(expectedReceipt, Field(18)) ||
            !Fixed(offering.DeviceDirectoryHeadHash.Span, Field(19)) ||
            !Fixed(manifest.FieldSpan(13), Field(20)) ||
            offering.PrekeyServiceGeneration != BinaryPrimitives
                .ReadUInt64BigEndian(Field(21)) ||
            offering.ExpiresAt != BinaryPrimitives
                .ReadUInt64BigEndian(Field(22)))
            Fail(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.CrossFieldMismatch,
                "XPC1 V2 receipt or current device/service fields differ from DPK2/XPI1.");
        if (offering.Kind == Dpk2PrekeyKind.OneTime)
        {
            if (!Fixed(offering.OneTimePrekeyId.Span, Field(17)))
                InvalidSelection();
            VerifyOneTimeInclusion(offering.ExactHash.Span, manifest,
                BinaryPrimitives.ReadUInt16BigEndian(Field(27)), Field(28));
        }
        else if (!ApplicationCoreFormat.IsZero(Field(17)) ||
            BinaryPrimitives.ReadUInt16BigEndian(Field(27)) != ushort.MaxValue ||
            lengths[28] != 0 ||
            !Fixed(offering.ExactHash.Span, manifest.FieldSpan(11)))
            InvalidSelection();

        var receipts = Field(25);
        if (receipts[0] != 2 ||
            ApplicationCoreFormat.IsZero(receipts.Slice(1, 32)) ||
            ApplicationCoreFormat.IsZero(receipts.Slice(33, 64)) ||
            ApplicationCoreFormat.IsZero(receipts.Slice(97, 32)) ||
            ApplicationCoreFormat.IsZero(receipts.Slice(129, 64)) ||
            receipts.Slice(1, 32).SequenceCompareTo(
                receipts.Slice(97, 32)) >= 0)
            Fail(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.InvalidOrdering,
                "XPC1 V2 does not contain two sorted replica receipt rows.");
        // Replica identities and signatures are checked against authenticated
        // PMT2 placement by the authoritative verifier, not by this codec.
    }

    private static void VerifyOneTimeInclusion(ReadOnlySpan<byte> exactHash,
        ParsedXpi1V2 manifest, ushort index, ReadOnlySpan<byte> proof)
    {
        var count = BinaryPrimitives.ReadUInt16BigEndian(manifest.FieldSpan(9));
        var width = 1;
        while (width < count) width <<= 1;
        var depth = 0;
        for (var current = width; current > 1; current >>= 1) depth++;
        if (index >= count || proof.Length != depth * 32)
            InvalidSelection();
        Span<byte> leaf = stackalloc byte[34];
        BinaryPrimitives.WriteUInt16BigEndian(leaf, index);
        exactHash.CopyTo(leaf[2..]);
        var node = ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V2/prekey-inventory-leaf", leaf);
        Span<byte> pair = stackalloc byte[64];
        for (var level = 0; level < depth; level++)
        {
            var sibling = proof.Slice(level * 32, 32);
            if (((index >> level) & 1) == 0)
            {
                node.CopyTo(pair);
                sibling.CopyTo(pair[32..]);
            }
            else
            {
                sibling.CopyTo(pair);
                node.CopyTo(pair[32..]);
            }
            node = ApplicationCoreFormat.Sha256Domain(
                "Deep/ContactResolver/V2/prekey-inventory-node", pair);
        }
        if (!Fixed(node, manifest.FieldSpan(10)))
            InvalidSelection();
    }

    private static void InvalidSelection() =>
        Fail(ApplicationCoreValidationStage.SemanticFields,
            ApplicationCoreRejection.CrossFieldMismatch,
            "XPC1 V2 selected DPK2 is not the committed XPI1 inventory member.");

    private static int PaddingClass(int canonicalLength)
    {
        var buckets = PaddingBuckets;
        for (var index = 0; index < buckets.Length; index++)
            if (canonicalLength <= buckets[index])
                return index;
        throw ApplicationCoreFormat.Error(
            ApplicationCoreValidationStage.ExactTotalSize,
            ApplicationCoreRejection.InvalidTotalSize,
            "XPC1 V2 canonical record exceeds its maximum padding bucket.");
    }

    private static void RequireLength(ReadOnlySpan<int> lengths, int tag,
        int expected)
    {
        if (lengths[tag] != expected)
            Fail(ApplicationCoreValidationStage.FieldLengths,
                ApplicationCoreRejection.InvalidFieldLength,
                "XPC1 V2 has a noncanonical field length.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static void InvalidMatrix() =>
        Fail(ApplicationCoreValidationStage.SemanticFields,
            ApplicationCoreRejection.InvalidEnum,
            "XPC1 V2 status and outcome matrix is invalid.");

    private static void Fail(ApplicationCoreValidationStage stage,
        ApplicationCoreRejection rejection, string message) =>
        throw ApplicationCoreFormat.Error(stage, rejection, message);
}
