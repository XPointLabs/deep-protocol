using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.GroupV1;

/// <summary>Frozen, transport-neutral GROUP-CODEC-01 grammar. Runtime emission stays disabled.</summary>
public static partial class GroupCodec
{
    public static bool RuntimeActivation => false;
    private const ushort Version = 1, Suite = 0x0201;
    private const int Header = 12, FieldHeader = 8, MaxRecord = 8 * 1024 * 1024;
    private sealed record Definition(string Magic, int[] Shape, int Min, int Max, int SignatureTag, string? Domain, int[]? Tags = null);
    private static readonly Dictionary<string, Definition> Definitions = new(StringComparer.Ordinal)
    {
        [ProtocolMagic.GIV1] = new(ProtocolMagic.GIV1, [16,32,32,8,32,32,32,38,32,1,38,38,32,32,38,8,8,64], 669, 669, 18, "Deep/Group/V1/invitation"),
        [ProtocolMagic.GIA1] = new(ProtocolMagic.GIA1, [16,32,32,38,32,32,38,38,38,32,32,38,8,8,64], 610, 610, 15, "Deep/Group/V1/invitation-acceptance"),
        [ProtocolMagic.DGP1] = new(ProtocolMagic.DGP1, [16,32,8,32,32,32,32,38,2,-8192,8,8,64], 421, 8612, 13, "Deep/Group/V1/proposal"),
        [ProtocolMagic.DGC1] = new(ProtocolMagic.DGC1, [16,32,2,8,32,32,32,38,2,-3200,2,-60000,-128,1,4,8,64], 712, 93922, 17, "Deep/Group/V1/commit"),
        [ProtocolMagic.DGT1] = new(ProtocolMagic.DGT1, [16,32,38,8,32,32,38,32,38,32,8,8,38,64], 540, 540, 14, "Deep/Group/V1/emergency-sequencer-transfer"),
        [ProtocolMagic.DGM1] = new(ProtocolMagic.DGM1, [16,32,8,32,32,32,32,8,8,8,2,-24576], 318, 24946, 0, null),
        [ProtocolMagic.GCP1] = new(ProtocolMagic.GCP1, [16,32,8,-65539,2,-8388608,4,-8388608,2,-8388608,-544], 880, MaxRecord, 0, null),
        [ProtocolMagic.GCF1] = new(ProtocolMagic.GCF1, [32,4,4,4,4,32,-24580], 153, 24748, 0, null),
        [ProtocolMagic.GSR1] = new(ProtocolMagic.GSR1, [16,32,32,8,32,38,32,32,32,32,38,8,8,64], 528, 528, 14, "Deep/Group/V1/control-rendezvous"),
        [ProtocolMagic.GSW1] = new(ProtocolMagic.GSW1, [16,32,32,32,8,8,32,32,8,32,32,-32772,8], 393, 33160, 0, null, [1,2,3,4,5,6,16,17,18,19,20,21,22]),
        [ProtocolMagic.GSQ1] = new(ProtocolMagic.GSQ1, [16,32,32,32,8,8,32,32,8,2,2], 304, 304, 0, null, [1,2,3,4,5,6,16,17,18,19,20]),
        [ProtocolMagic.GSS1] = new(ProtocolMagic.GSS1, [16,32,32,2,1,8,4,2,1,-65535,-65535,-65535,-65535], 214, 65535, 0, null, [1,2,3,4,5,6,7,8,16,17,18,19,20]),
    };

    public static GroupRecord Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < Header || bytes.Length > MaxRecord) Reject(GroupValidationStage.Length, "RecordLengthOutOfRange");
        if (!AsciiMagic(bytes[..4])) Reject(GroupValidationStage.Header, "UnsupportedRecord");
        var magic = Encoding.ASCII.GetString(bytes[..4]);
        if (!Definitions.TryGetValue(magic, out var d)) Reject(GroupValidationStage.Header, "UnsupportedRecord");
        var definition = d ?? throw new GroupFormatException(GroupValidationStage.Header, "UnsupportedRecord");
        if (bytes.Length < definition.Min || bytes.Length > definition.Max) Reject(GroupValidationStage.Length, "RecordLengthOutOfRange");
        if (U16(bytes[4..]) != Version) Reject(GroupValidationStage.Header, "UnsupportedVersion");
        if (U16(bytes[6..]) != Suite) Reject(GroupValidationStage.Header, "UnknownSuite");
        if (U16(bytes[8..]) != definition.Shape.Length) Reject(GroupValidationStage.Header, "WrongFieldCount");
        if (U16(bytes[10..]) != 0) Reject(GroupValidationStage.Header, "NonCanonicalReserved");
        var offsets = new int[definition.Shape.Length]; var lengths = new int[definition.Shape.Length]; var offset = Header;
        for (var i = 0; i < definition.Shape.Length; i++)
        {
            if (bytes.Length - offset < FieldHeader) Reject(GroupValidationStage.FieldScan, "TruncatedFieldHeader");
            var expectedTag = definition.Tags?[i] ?? i + 1;
            if (U16(bytes.Slice(offset, 2)) != expectedTag) Reject(GroupValidationStage.FieldScan, "NonCanonicalTag");
            if (U16(bytes.Slice(offset + 2, 2)) != 0) Reject(GroupValidationStage.FieldScan, "NonCanonicalReserved");
            var declared = BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset + 4, 4)); offset += FieldHeader;
            if (declared > int.MaxValue || declared > bytes.Length - offset) Reject(GroupValidationStage.Bounds, "TruncatedField");
            offsets[i] = offset; lengths[i] = (int)declared; offset += (int)declared;
        }
        if (offset != bytes.Length) Reject(GroupValidationStage.Bounds, "TrailingBytes");
        for (var i = 0; i < definition.Shape.Length; i++) CheckShape(definition.Shape[i], lengths[i]);
        var owned = bytes.ToArray(); var fields = offsets.Select((at, i) => owned.AsSpan(at, lengths[i]).ToArray()).ToArray();
        Validate(definition, fields);
        return magic switch
        {
            ProtocolMagic.GIV1 => new GroupInvitationRecord(owned, fields), ProtocolMagic.GIA1 => new GroupInvitationAcceptanceRecord(owned, fields),
            ProtocolMagic.DGP1 => new GroupProposalRecord(owned, fields), ProtocolMagic.DGC1 => new GroupCommitRecord(owned, fields),
            ProtocolMagic.DGT1 => new GroupEmergencyTransferRecord(owned, fields), ProtocolMagic.DGM1 => new GroupApplicationMessageRecord(owned, fields),
            ProtocolMagic.GCP1 => new GroupCommitPackageRecord(owned, fields), ProtocolMagic.GCF1 => new GroupCommitChunkRecord(owned, fields),
            ProtocolMagic.GSR1 => new GroupControlRendezvousRecord(owned, fields), ProtocolMagic.GSW1 => new GroupControlWriteRecord(owned, fields),
            ProtocolMagic.GSQ1 => new GroupControlQueryRecord(owned, fields), ProtocolMagic.GSS1 => new GroupControlResultRecord(owned, fields),
            _ => throw new InvalidOperationException()
        };
    }

    public static GroupRecord Decode(string magic, ReadOnlySpan<byte> bytes)
    { var record = Decode(bytes); if (record.Magic != magic) Reject(GroupValidationStage.Header, "WrongRecordType"); return record; }
    public static GroupRecord Author(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
    { throw new InvalidOperationException("GROUP-CODEC-01 production authoring is disabled until runtime activation."); }
    public static GroupArtifactReference ArtifactReference(string magic, GroupRecord record)
    { if (record is null || record.Magic != magic) throw new ArgumentException("Wrong record type."); return new GroupArtifactReference(magic, record.ArtifactHash.Span); }
    public static GroupArtifactReference DecodeArtifactReference(ReadOnlySpan<byte> value, string magic)
    { if (value.Length != 38 || !value[..4].SequenceEqual(Encoding.ASCII.GetBytes(magic)) || U16(value[4..]) != Version || Zero(value[6..])) Reject(GroupValidationStage.Reference, "ReferenceTypeMismatch"); return new GroupArtifactReference(magic, value[6..]); }
    public static byte[] RecordHash(string magic, ReadOnlySpan<byte> exactCanonicalRecord) =>
        Sha256Domain($"Deep/Application/V1/record-hash/{magic}", exactCanonicalRecord);
    public static GroupChunkAssembler NewChunkAssembler() => new();
    internal static byte[] Project(GroupRecord record, IReadOnlyList<int> tags)
    { var total = checked(Header + tags.Sum(t => FieldHeader + record.FieldSpan(t).Length)); var b = new byte[total]; Encoding.ASCII.GetBytes(record.Magic).CopyTo(b, 0); BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(4), Version); BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(6), Suite); BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(8), (ushort)tags.Count); var at = Header; foreach (var tag in tags) { var f = record.FieldSpan(tag); BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(at), (ushort)tag); BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(at + 4), (uint)f.Length); at += FieldHeader; f.CopyTo(b.AsSpan(at)); at += f.Length; } return b; }
    internal static byte[] SignatureInput(string domain, ReadOnlySpan<byte> projection) { var label = Encoding.ASCII.GetBytes(domain); var b = new byte[checked(label.Length + 7 + projection.Length)]; label.CopyTo(b, 0); BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(label.Length + 1), Suite); BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(label.Length + 3), (uint)projection.Length); projection.CopyTo(b.AsSpan(label.Length + 7)); return b; }
    private static void Validate(Definition d, byte[][] f)
    {
        foreach (var tag in NonzeroTags(d.Magic)) if (Zero(f[tag - 1])) Reject(GroupValidationStage.Scalar, "ZeroForbidden");
        switch (d.Magic)
        {
            case ProtocolMagic.GIV1: Reference(f[7], ProtocolMagic.DPD1); Reference(f[10], ProtocolMagic.ADC1); Reference(f[11], ProtocolMagic.ADH1); Reference(f[14], ProtocolMagic.DRS1); Role(f[9], false); Window(U64(f[15]), U64(f[16])); break;
            case ProtocolMagic.GIA1: Reference(f[3], ProtocolMagic.GIV1); Reference(f[6], ProtocolMagic.DPD1); Reference(f[7], ProtocolMagic.ADC1); Reference(f[8], ProtocolMagic.ADH1); Reference(f[11], ProtocolMagic.DRS1); Window(U64(f[12]), U64(f[13])); break;
            case ProtocolMagic.DGP1: ValidateProposal(f); break;
            case ProtocolMagic.DGC1: ValidateCommit(f); break;
            case ProtocolMagic.DGT1: Reference(f[2], ProtocolMagic.DGC1); Reference(f[6], ProtocolMagic.DPD1); Reference(f[8], ProtocolMagic.DRS1); Reference(f[12], ProtocolMagic.DPA1); Window(U64(f[10]), U64(f[11])); break;
            case ProtocolMagic.DGM1: if (U16(f[10]) is < 1 or > 7 || U64(f[8]) == 0 || U64(f[9]) <= U64(f[8])) Reject(GroupValidationStage.Scalar, "InvalidGroupEvent"); break;
            case ProtocolMagic.GCP1: ValidatePackageShape(f); break;
            case ProtocolMagic.GCF1: ValidateChunk(f); break;
            case ProtocolMagic.GSR1:
                if ((U64(f[3]) == 0) != Zero(f[4]) || U64(f[11]) >= U64(f[12])) Reject(GroupValidationStage.Scalar, "InvalidControlRendezvous");
                Reference(f[5], ProtocolMagic.PMT2); Reference(f[10], ProtocolMagic.DPD1); break;
            case ProtocolMagic.GSW1: ValidateControlRequest(f, true); break;
            case ProtocolMagic.GSQ1: ValidateControlRequest(f, false); break;
            case ProtocolMagic.GSS1: ValidateControlResult(f); break;
        }
    }
    private static void ValidateCommit(byte[][] f)
    {
        if (U16(f[2]) != 1 || U16(f[8]) > 64 || f[9].Length != U16(f[8]) * 32 || U16(f[10]) is < 1 or > 100 || f[11].Length is < 1 or > 60000 || f[12].Length is < 1 or > 128 || f[13][0] > 1 || U64(f[15]) == 0) Reject(GroupValidationStage.Bounds, "InvalidCommitShape");
        if ((U64(f[3]) == 0) != Zero(f[4])) Reject(GroupValidationStage.Scalar, "InvalidGenesisPredecessor");
        EnsureRows(f[9], 32); var members = ReadMembers(f[11]); if (members.Count != U16(f[10]) || members.Count(m => m.Role == GroupRole.Owner) != 1 || !members.Single(m => m.Role == GroupRole.Owner).Account.AsSpan().SequenceEqual(f[5]) || !members.Single(m => m.Role == GroupRole.Owner).Devices.Any(d => d.Id.AsSpan().SequenceEqual(f[6]))) Reject(GroupValidationStage.Closure, "InvalidOwnerSerialization");
        if (members.Any(m => m.Devices.Count > 5) || members.Sum(m => m.Devices.Count) > 500) Reject(GroupValidationStage.Bounds, "DeviceLimitExceeded");
        if (members.Count(m => m.Role is GroupRole.Owner or GroupRole.Admin) > 5) Reject(GroupValidationStage.Bounds, "AdminLimitExceeded");
        _ = DecodeText(f[12]); Reference(f[7], ProtocolMagic.DPD1);
    }
    private static void ValidateProposal(byte[][] f)
    {
        var action = (GroupProposalAction)U16(f[8]);
        var payload = f[9].AsSpan();
        Reference(f[7], ProtocolMagic.DPD1);
        Window(U64(f[10]), U64(f[11]));
        switch (action)
        {
            case GroupProposalAction.ActivateAcceptedInvite:
                if (payload.Length != 287) Reject(GroupValidationStage.Bounds, "InvalidActionPayload");
                Reference(payload[..38], ProtocolMagic.GIV1); Reference(payload.Slice(38, 38), ProtocolMagic.GIA1);
                Role(payload.Slice(108, 1), false); Reference(payload.Slice(109, 38), ProtocolMagic.ADC1);
                Reference(payload.Slice(147, 38), ProtocolMagic.ADH1); Reference(payload.Slice(249, 38), ProtocolMagic.DRS1);
                if (Zero(payload.Slice(76, 32)) || Zero(payload.Slice(185, 32)) || Zero(payload.Slice(217, 32))) Reject(GroupValidationStage.Scalar, "ZeroForbidden");
                break;
            case GroupProposalAction.RemoveAccount:
            case GroupProposalAction.LeaveAccount:
                if (payload.Length != 66) Reject(GroupValidationStage.Bounds, "InvalidActionPayload");
                if (Zero(payload[..32]) || Zero(payload.Slice(32, 32))) Reject(GroupValidationStage.Scalar, "InvalidActionPayload");
                break;
            case GroupProposalAction.ChangeRole:
                if (payload.Length != 66 || Zero(payload[..32]) || payload[32] is < 1 or > 3 || payload[33] is < 2 or > 3 || payload[32] == payload[33] || Zero(payload[34..])) Reject(GroupValidationStage.Scalar, "InvalidActionPayload");
                break;
            case GroupProposalAction.AddDevice:
                if (payload.Length != 204) Reject(GroupValidationStage.Bounds, "InvalidActionPayload");
                if (Zero(payload[..32]) || Zero(payload.Slice(32, 32)) || Zero(payload.Slice(102, 32)) || Zero(payload.Slice(172, 32))) Reject(GroupValidationStage.Scalar, "InvalidActionPayload");
                Reference(payload.Slice(64, 38), ProtocolMagic.DPD1); Reference(payload.Slice(134, 38), ProtocolMagic.DRS1);
                break;
            case GroupProposalAction.RemoveDevice:
            case GroupProposalAction.TransferOwnerDevice:
                if (payload.Length != 172) Reject(GroupValidationStage.Bounds, "InvalidActionPayload");
                if (Zero(payload[..32]) || Zero(payload.Slice(32, 32)) || Zero(payload.Slice(102, 32))) Reject(GroupValidationStage.Scalar, "InvalidActionPayload");
                Reference(payload.Slice(64, 38), ProtocolMagic.DPD1); Reference(payload.Slice(134, 38), ProtocolMagic.DRS1);
                break;
            case GroupProposalAction.ChangeProfile:
                if (payload.Length < 8) Reject(GroupValidationStage.Bounds, "InvalidActionPayload");
                var nameLength = U16(payload);
                if (nameLength is < 1 or > 128 || payload.Length != 2 + nameLength + 5) Reject(GroupValidationStage.Bounds, "InvalidActionPayload");
                _ = DecodeText(payload.Slice(2, nameLength));
                if (payload[2 + nameLength] > 1 || U32(payload.Slice(3 + nameLength, 4)) == 0) Reject(GroupValidationStage.Scalar, "InvalidActionPayload");
                break;
            default:
                Reject(GroupValidationStage.Scalar, "InvalidAction");
                break;
        }
    }
    private static void ValidatePackageShape(byte[][] f) { if (f[3].Length < 5 || f[3].Length > 65539 || U16(f[4]) > 64 || U32(f[6]) > 20000 || U16(f[8]) > 64) Reject(GroupValidationStage.Bounds, "InvalidPackageShape"); }
    private static void ValidateChunk(byte[][] f) { var total = U32(f[1]); var chunkSize = U32(f[2]); var index = U32(f[3]); var count = U32(f[4]); var chunk = Lp(f[6], out var used); if (used != f[6].Length || total == 0 || total > 8 * 1024 * 1024 || chunkSize != 24576 || count is 0 or > 342 || index >= count || chunk.Length is < 1 or > 24576 || SHA256.HashData(chunk).AsSpan().SequenceEqual(f[5]) is false) Reject(GroupValidationStage.Bounds, "InvalidChunk"); var expected = (total + 24575) / 24576; if (count != expected || (index + 1 < count && chunk.Length != 24576) || (index + 1 == count && chunk.Length != total - 24576 * (count - 1))) Reject(GroupValidationStage.Bounds, "InvalidChunkGeometry"); }
    private static void ValidateControlRequest(byte[][] f, bool write)
    {
        if (Zero(f[0]) || Zero(f[1]) || Zero(f[2]) || Zero(f[3]) ||
            U64(f[4]) == 0 || U64(f[5]) <= U64(f[4]) || U64(f[5]) - U64(f[4]) > 86_400 ||
            Zero(f[6]) || Zero(f[7]))
            Reject(GroupValidationStage.Scalar, "InvalidControlRequestWindow");
        if (write)
        {
            var body = Lp(f[11], out var used);
            var sequence = U64(f[8]);
            if (used != f[11].Length || body.Length is < 1 or > 32768 || sequence == 0 ||
                (sequence == 1) != Zero(f[9]) || Zero(f[10]) || U64(f[12]) <= U64(f[4]))
                Reject(GroupValidationStage.Bounds, "InvalidControlWrite");
            if (!SHA256.HashData(body).AsSpan().SequenceEqual(f[10])) Reject(GroupValidationStage.Closure, "SealedChunkHashMismatch");
        }
        else if (U16(f[9]) is < 1 or > 64 || U16(f[10]) > 4)
            Reject(GroupValidationStage.Scalar, "InvalidControlQuery");
    }
    private static void ValidateControlResult(byte[][] f)
    {
        var status = U16(f[3]); var outcome = f[4][0]; var retry = U32(f[6]); var padding = U16(f[7]); var operation = f[8][0];
        if (Zero(f[0]) || Zero(f[1]) || Zero(f[2]) || U64(f[5]) == 0 ||
            operation is < 1 or > 2 || status is < 1 or > 11 || outcome > 2 || padding > 4)
            Reject(GroupValidationStage.Scalar, "InvalidControlResult");
        bool Empty(int index) => f[index].Length == 0;
        var valid = status switch
        {
            1 or 2 => operation == 1 && outcome == 1 && retry == 0 &&
                f[9].Length == 8 && U64(f[9]) != 0 && f[10].Length == 32 && !Zero(f[10]) &&
                f[11].Length == 8 && U64(f[11]) != 0 && ValidReplicaReceipts(f[12]),
            3 => operation == 2 && outcome == 0 && retry == 0 && ValidControlEvents(f[9], f[10], f[11], f[12]),
            4 => operation == 2 && outcome == 0 && retry == 0 && Empty(9) && Empty(10) && Empty(11) && Empty(12),
            5 => outcome == 0 && retry == 0 && Empty(9) && Empty(10) && Empty(11) && Empty(12),
            6 => outcome == 0 && retry != 0 && Empty(9) && Empty(10) && Empty(11) && Empty(12),
            7 => outcome == 0 && retry == 0 && f[9].Length == 8 && f[10].Length == 32 && !Zero(f[10]) && Empty(11) && Empty(12),
            8 => outcome == 0 && retry == 0 && f[9].Length == 32 && !Zero(f[9]) && Empty(10) && Empty(11) && Empty(12),
            9 => operation == 1 && outcome == 2 && retry != 0 && Empty(9) && Empty(10) && Empty(11) && Empty(12),
            10 => operation == 1 && outcome == 0 && retry == 0 && f[9].Length == 4 && U32(f[9]) == 32768 &&
                f[10].Length == 4 && U32(f[10]) > 32768 && Empty(11) && Empty(12),
            11 => operation == 2 && outcome == 0 && retry == 0 && f[9].Length == 2 && U16(f[9]) <= 4 &&
                f[10].Length == 4 && U32(f[10]) != 0 && Empty(11) && Empty(12),
            _ => false,
        };
        if (!valid) Reject(GroupValidationStage.Closure, "InvalidControlResultMatrix");
    }

    private static bool ValidReplicaReceipts(ReadOnlySpan<byte> receipts)
    {
        if (receipts.Length is < 96 or > 3072 || receipts.Length % 96 != 0) return false;
        ReadOnlySpan<byte> previous = default;
        for (var at = 0; at < receipts.Length; at += 96)
        {
            var row = receipts.Slice(at, 96);
            if (Zero(row) || (!previous.IsEmpty && previous[..32].SequenceCompareTo(row[..32]) >= 0)) return false;
            previous = row;
        }
        return true;
    }

    private static bool ValidControlEvents(ReadOnlySpan<byte> countField, ReadOnlySpan<byte> records,
        ReadOnlySpan<byte> nextAfterField, ReadOnlySpan<byte> hasMoreField)
    {
        if (countField.Length != 2 || nextAfterField.Length != 8 || hasMoreField.Length != 1 || hasMoreField[0] > 1) return false;
        var count = U16(countField);
        if (count is < 1 or > 64) return false;
        var at = 0; ulong previousSequence = 0; ReadOnlySpan<byte> previousHash = default;
        for (var index = 0; index < count; index++)
        {
            if (records.Length - at < 84) return false;
            var sequence = U64(records[at..]);
            var predecessor = records.Slice(at + 8, 32);
            var sealedHash = records.Slice(at + 40, 32);
            var expiresAt = U64(records.Slice(at + 72, 8));
            var body = Lp(records.Slice(at + 80), out var used);
            if (sequence == 0 || expiresAt == 0 || body.Length is < 1 or > 32768 || Zero(sealedHash) ||
                (sequence == 1) != Zero(predecessor) ||
                (index != 0 && (previousSequence == ulong.MaxValue || sequence != previousSequence + 1 || !predecessor.SequenceEqual(previousHash))) ||
                !SHA256.HashData(body).AsSpan().SequenceEqual(sealedHash)) return false;
            at += 80 + used; previousSequence = sequence; previousHash = sealedHash;
        }
        return at == records.Length && U64(nextAfterField) == previousSequence;
    }
    private static List<Member> ReadMembers(ReadOnlySpan<byte> value) { var answer = new List<Member>(); var at = 0; ReadOnlySpan<byte> prev = default; while (at < value.Length) { if (value.Length - at < 2) Reject(GroupValidationStage.Bounds, "TruncatedMemberEntry"); var n = U16(value[at..]); at += 2; if (n < 290 || n > value.Length - at) Reject(GroupValidationStage.Bounds, "InvalidMemberEntry"); var x = value.Slice(at, n); at += n; var deviceCount = x[219]; if (deviceCount is 0 or > 5 || n != 220 + deviceCount * 70 || Zero(x[..32]) || x[32] is < 1 or > 3 || Zero(x.Slice(109,32)) || U64(x.Slice(141,8)) == 0 || Zero(x.Slice(149,32)) || (!prev.IsEmpty && prev.SequenceCompareTo(x[..32]) >= 0)) Reject(GroupValidationStage.Bounds, "NonCanonicalMemberTable"); Reference(x.Slice(33,38), ProtocolMagic.ADC1); Reference(x.Slice(71,38), ProtocolMagic.ADH1); Reference(x.Slice(181,38), ProtocolMagic.DRS1); var ds = new List<Device>(); ReadOnlySpan<byte> prevDevice = default; for (var i=0;i<deviceCount;i++) { var row=x.Slice(220+i*70,70); if (Zero(row[..32]) || (!prevDevice.IsEmpty && prevDevice.SequenceCompareTo(row[..32])>=0)) Reject(GroupValidationStage.Bounds,"NonCanonicalDeviceTable"); Reference(row.Slice(32,38),ProtocolMagic.DPD1); ds.Add(new Device(row[..32].ToArray(),row.Slice(32,38).ToArray())); prevDevice=row[..32]; } answer.Add(new Member(x[..32].ToArray(),(GroupRole)x[32],x.Slice(33,38).ToArray(),x.Slice(71,38).ToArray(),x.Slice(109,32).ToArray(),U64(x.Slice(141,8)),x.Slice(149,32).ToArray(),x.Slice(181,38).ToArray(),ds)); prev=x[..32]; } return answer; }
    private static HashSet<string> RequiredReferences(GroupCommitRecord commit, List<GroupRecord> proposals, List<InvitationPair> pairs) { var set=new HashSet<string>(StringComparer.Ordinal); Add(set,commit.FieldSpan(8)); foreach(var m in ReadMembers(commit.FieldSpan(12))) { Add(set,m.Adc); Add(set,m.Adh); AddHash(set,ProtocolMagic.ADP1,m.Adp); AddHash(set,ProtocolMagic.DMD1,m.Dmd); Add(set,m.Drs); foreach(var d in m.Devices) Add(set,d.Reference); } foreach(var p in proposals) { Add(set,p.FieldSpan(8)); foreach(var r in ProposalReferences(p)) Add(set,r); } foreach(var pair in pairs) { AddInvitationReferences(set,pair.Invitation); AddInvitationReferences(set,pair.Acceptance); } return set; }
    private static IEnumerable<ReadOnlyMemory<byte>> ProposalReferences(GroupRecord p) { var a=(GroupProposalAction)U16(p.FieldSpan(9)); var x=p.FieldSpan(10); if(a==GroupProposalAction.ActivateAcceptedInvite && x.Length==287) return [x.Slice(109,38).ToArray(),x.Slice(147,38).ToArray(),ReferenceBytes(ProtocolMagic.ADP1,x.Slice(185,32)),ReferenceBytes(ProtocolMagic.DMD1,x.Slice(217,32)),x.Slice(249,38).ToArray()]; if(a==GroupProposalAction.AddDevice && x.Length==204) return [x.Slice(64,38).ToArray(),ReferenceBytes(ProtocolMagic.DMD1,x.Slice(102,32)),x.Slice(134,38).ToArray(),ReferenceBytes(ProtocolMagic.ADP1,x.Slice(172,32))]; if(a==GroupProposalAction.RemoveDevice && x.Length==172) return [x.Slice(64,38).ToArray(),ReferenceBytes(ProtocolMagic.DMD1,x.Slice(102,32)),x.Slice(134,38).ToArray()]; if(a==GroupProposalAction.TransferOwnerDevice && x.Length==172) return [x.Slice(64,38).ToArray(),ReferenceBytes(ProtocolMagic.DMD1,x.Slice(102,32)),x.Slice(134,38).ToArray()]; return []; }
    private static void AddInvitationReferences(HashSet<string> set, GroupRecord record) { var acceptance=record.Magic==ProtocolMagic.GIA1; Add(set,record.FieldSpan(acceptance?7:8)); Add(set,record.FieldSpan(acceptance?8:11)); Add(set,record.FieldSpan(acceptance?9:12)); AddHash(set,ProtocolMagic.ADP1,record.FieldSpan(acceptance?10:13)); AddHash(set,ProtocolMagic.DMD1,record.FieldSpan(acceptance?11:14)); Add(set,record.FieldSpan(acceptance?12:15)); }
    private static List<GroupRecord> ReadLpList(ReadOnlySpan<byte> value, ushort count, int min, int max, string magic) { var answer=new List<GroupRecord>(); var at=0; for(var i=0;i<count;i++){var b=Lp(value[at..],out var used); if(b.Length<min||b.Length>max)Reject(GroupValidationStage.Bounds,"InvalidEmbeddedLength");answer.Add(Decode(magic,b));at+=used;}if(at!=value.Length)Reject(GroupValidationStage.Bounds,"TrailingListBytes");return answer; }
    private sealed record Support(ushort Kind, GroupArtifactReference Reference, byte[] Bytes);
    private static List<Support> ReadSupport(ReadOnlySpan<byte> v,uint count){var a=new List<Support>();var at=0; string? prev=null;for(var i=0;i<count;i++){if(v.Length-at<40)Reject(GroupValidationStage.Bounds,"TruncatedSupport");var k=U16(v[at..]);var magic=k switch{1=>ProtocolMagic.ADC1,2=>ProtocolMagic.ADH1,3=>ProtocolMagic.ADP1,4=>ProtocolMagic.DMD1,5=>ProtocolMagic.DRS1,6=>ProtocolMagic.DPD1,_=>throw new GroupFormatException(GroupValidationStage.Bounds,"InvalidSupportKind")};var r=DecodeArtifactReference(v.Slice(at+2,38),magic);at+=40;var b=Lp(v[at..],out var used);at+=used;var key=$"{k:D5}:{Convert.ToHexString(r.CanonicalBytes.Span)}";if(prev is not null&&StringComparer.Ordinal.Compare(prev,key)>=0)Reject(GroupValidationStage.Bounds,"SupportNotStrictlyOrdered");prev=key;a.Add(new Support(k,r,b.ToArray()));}if(at!=v.Length)Reject(GroupValidationStage.Bounds,"TrailingSupportBytes");return a;}
    private static void VerifySupport(List<Support> support,IGroupClosureResolver resolver){foreach(var s in support){var resolved=resolver.Resolve(s.Reference);if(resolved is null||!resolved.Value.Span.SequenceEqual(s.Bytes))Reject(GroupValidationStage.Closure,"SupportResolutionMismatch");ReadOnlyMemory<byte> hash=s.Kind switch{1=>SHA256.HashData(s.Bytes),2=>DirectoryHeadCoreHash(s.Bytes),3=>RecordHash(ProtocolMagic.ADP1,s.Bytes),4=>ApplicationCoreCodec.DecodeDmd1(s.Bytes).RecordHash,5=>IdentityCodec.DecodeRevocationSnapshot(s.Bytes).CanonicalHash,6=>IdentityCodec.DecodeDeviceCertificate(s.Bytes).CanonicalHash,_=>throw new InvalidOperationException()};if(!hash.Span.SequenceEqual(s.Reference.Hash.Span))Reject(GroupValidationStage.Closure,"SupportResolutionMismatch");}}
    private sealed record InvitationPair(GroupArtifactReference InvitationReference,GroupArtifactReference AcceptanceReference,GroupRecord Invitation,GroupRecord Acceptance);
    private static List<InvitationPair> ReadInvitationPairs(ReadOnlySpan<byte> v,ushort count){var a=new List<InvitationPair>();var at=0;ReadOnlySpan<byte> prev=default;for(var i=0;i<count;i++){if(v.Length-at<38)Reject(GroupValidationStage.Bounds,"TruncatedInvitationPair");var ir=DecodeArtifactReference(v.Slice(at,38),ProtocolMagic.GIV1);at+=38;var inv=Decode(ProtocolMagic.GIV1,Lp(v[at..],out var n));at+=n;if(v.Length-at<38)Reject(GroupValidationStage.Bounds,"TruncatedInvitationPair");var ar=DecodeArtifactReference(v.Slice(at,38),ProtocolMagic.GIA1);at+=38;var acc=Decode(ProtocolMagic.GIA1,Lp(v[at..],out n));at+=n;if(!ir.Hash.Span.SequenceEqual(inv.ArtifactHash.Span)||!ar.Hash.Span.SequenceEqual(acc.ArtifactHash.Span)||(!prev.IsEmpty&&prev.SequenceCompareTo(inv.FieldSpan(3))>=0))Reject(GroupValidationStage.Closure,"InvalidInvitationPair");prev=inv.FieldSpan(3);a.Add(new InvitationPair(ir,ar,inv,acc));}if(at!=v.Length)Reject(GroupValidationStage.Bounds,"TrailingInvitationPairs");return a;}
    private static void VerifyInvitePairs(List<InvitationPair> pairs){foreach(var p in pairs)if(!p.Invitation.FieldSpan(2).SequenceEqual(p.Acceptance.FieldSpan(2))||!p.Invitation.FieldSpan(3).SequenceEqual(p.Acceptance.FieldSpan(3))||!p.Invitation.FieldSpan(9).SequenceEqual(p.Acceptance.FieldSpan(5))||!p.Invitation.FieldSpan(11).SequenceEqual(p.Acceptance.FieldSpan(8))||!p.Invitation.FieldSpan(12).SequenceEqual(p.Acceptance.FieldSpan(9))||!p.Invitation.FieldSpan(13).SequenceEqual(p.Acceptance.FieldSpan(10))||!p.Invitation.FieldSpan(14).SequenceEqual(p.Acceptance.FieldSpan(11))||!p.Invitation.FieldSpan(15).SequenceEqual(p.Acceptance.FieldSpan(12))||U64(p.Acceptance.FieldSpan(13))>U64(p.Invitation.FieldSpan(17)))Reject(GroupValidationStage.Closure,"InvitationAcceptanceMismatch");}
    private static ReadOnlySpan<byte> Lp(ReadOnlySpan<byte> v,out int used){if(v.Length<4)Reject(GroupValidationStage.Bounds,"TruncatedLp32");var n=BinaryPrimitives.ReadUInt32BigEndian(v);if(n>int.MaxValue||n>v.Length-4)Reject(GroupValidationStage.Bounds,"InvalidLp32");used=4+(int)n;return v.Slice(4,(int)n);}
    private static void EnsureStrictHashes(List<GroupRecord> records){ReadOnlySpan<byte> prev=default;foreach(var r in records){var h=r.ArtifactHash.Span;if(!prev.IsEmpty&&prev.SequenceCompareTo(h)>=0)Reject(GroupValidationStage.Bounds,"ProposalHashesNotStrictlyOrdered");prev=h;}}
    private static void EnsureRows(ReadOnlySpan<byte> rows,int width){ReadOnlySpan<byte> prev=default;for(var at=0;at<rows.Length;at+=width){var x=rows.Slice(at,width);if(Zero(x)||(!prev.IsEmpty&&prev.SequenceCompareTo(x)>=0))Reject(GroupValidationStage.Bounds,"NonCanonicalTable");prev=x;}}
    private static IEnumerable<int> NonzeroTags(string m)=>m switch{
        ProtocolMagic.GIV1=>[1,2,3,5,6,7,8,9,10,11,12,13,14,15,16,17,18],
        ProtocolMagic.GIA1=>Enumerable.Range(1,15), ProtocolMagic.DGP1=>[1,2,4,5,6,7,8,9,10,11,12,13],
        ProtocolMagic.DGC1=>[1,2,3,6,7,8,11,12,13,15,16,17], ProtocolMagic.DGT1=>[1,2,3,5,6,7,8,9,10,11,12,13,14],
        ProtocolMagic.DGM1=>[1,2,4,5,6,7,8,9,10,11], ProtocolMagic.GCP1=>[1,2,4], ProtocolMagic.GCF1=>[1,2,3,5,6,7],
        ProtocolMagic.GSR1=>[1,2,3,6,7,8,9,10,11,12,13,14], _=>[]};
    private static void Add(HashSet<string> set,ReadOnlySpan<byte> r){if(r.Length==38)set.Add(Convert.ToHexString(r));}
    private static void Add(HashSet<string> set,ReadOnlyMemory<byte> r) => Add(set, r.Span);
    private static void Add(HashSet<string> set,GroupArtifactReference r) => Add(set, r.CanonicalBytes.Span);
    private static void AddHash(HashSet<string> set,string magic,ReadOnlySpan<byte> hash) { var reference=new byte[38]; Encoding.ASCII.GetBytes(magic).CopyTo(reference,0); reference[5]=1; hash.CopyTo(reference.AsSpan(6)); Add(set,reference); }
    private static void Reference(ReadOnlySpan<byte> v,string magic)=>DecodeArtifactReference(v,magic);
    private static void Role(ReadOnlySpan<byte> v,bool owner) { if(v.Length!=1 || v[0] is < 1 or > 3 || (!owner&&v[0]==1)) Reject(GroupValidationStage.Scalar,"InvalidRole"); }
    private static void Window(ulong a,ulong b){if(a==0||b<=a||b-a>604800)Reject(GroupValidationStage.Scalar,"InvalidTimeWindow");}
    private static string DecodeText(ReadOnlySpan<byte> v){try{var t=new UTF8Encoding(false,true).GetString(v);if(!t.IsNormalized(NormalizationForm.FormC)||t.Contains('\0'))throw new FormatException();return t;}catch(Exception){Reject(GroupValidationStage.Scalar,"NonCanonicalText");return string.Empty;}}
    private static int SignatureTag(string m)=>Definitions[m].SignatureTag;
    private static void CheckShape(int x,int actual){if(x>=0&&actual!=x)Reject(GroupValidationStage.Bounds,"FieldLengthOutOfRange");if(x<0&&actual> -x)Reject(GroupValidationStage.Bounds,"FieldLengthOutOfRange");}
    private static ushort U16(ReadOnlySpan<byte> b)=>BinaryPrimitives.ReadUInt16BigEndian(b); private static uint U32(ReadOnlySpan<byte> b)=>BinaryPrimitives.ReadUInt32BigEndian(b); private static ulong U64(ReadOnlySpan<byte> b)=>BinaryPrimitives.ReadUInt64BigEndian(b);
    private static bool Zero(ReadOnlySpan<byte> b){byte x=0;foreach(var v in b)x|=v;return x==0;} private static bool AsciiMagic(ReadOnlySpan<byte> b)=>b.Length==4&&b.ToArray().All(x=>x is >=0x21 and <=0x7e);
    private static byte[] Sha256Domain(string domain, ReadOnlySpan<byte> value){var label=Encoding.ASCII.GetBytes(domain);var preimage=new byte[checked(label.Length+5+value.Length)];label.CopyTo(preimage,0);BinaryPrimitives.WriteUInt32BigEndian(preimage.AsSpan(label.Length+1),checked((uint)value.Length));value.CopyTo(preimage.AsSpan(label.Length+5));return SHA256.HashData(preimage);}
    private static byte[] DirectoryHeadCoreHash(ReadOnlySpan<byte> canonical){if(canonical.Length<12||!canonical[..4].SequenceEqual(ProtocolMagicBytes.ADH1)||U16(canonical[4..])!=1||U16(canonical[6..])!=Suite||U16(canonical[8..])!=13||U16(canonical[10..])!=0)Reject(GroupValidationStage.Closure,"InvalidDirectoryHead");var at=12;var fields=new List<byte[]>();for(var tag=1;tag<=13;tag++){if(canonical.Length-at<8||U16(canonical.Slice(at,2))!=tag||U16(canonical.Slice(at+2,2))!=0)Reject(GroupValidationStage.Closure,"InvalidDirectoryHead");var n=BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(at+4,4));at+=8;if(n>int.MaxValue||n>canonical.Length-at)Reject(GroupValidationStage.Closure,"InvalidDirectoryHead");if(tag<=11)fields.Add(canonical.Slice(at,(int)n).ToArray());at+=(int)n;}if(at!=canonical.Length)Reject(GroupValidationStage.Closure,"InvalidDirectoryHead");var projection=new byte[12+fields.Sum(x=>8+x.Length)];ProtocolMagicBytes.ADH1.CopyTo(projection);BinaryPrimitives.WriteUInt16BigEndian(projection.AsSpan(4),1);BinaryPrimitives.WriteUInt16BigEndian(projection.AsSpan(6),Suite);BinaryPrimitives.WriteUInt16BigEndian(projection.AsSpan(8),11);at=12;for(var i=0;i<fields.Count;i++){BinaryPrimitives.WriteUInt16BigEndian(projection.AsSpan(at),checked((ushort)(i+1)));BinaryPrimitives.WriteUInt32BigEndian(projection.AsSpan(at+4),checked((uint)fields[i].Length));at+=8;fields[i].CopyTo(projection,at);at+=fields[i].Length;}return Sha256Domain("Deep/AccountDirectory/V1/ADH1/core",projection);}
    private static void Reject(GroupValidationStage s,string c)=>throw new GroupFormatException(s,c);
    internal sealed record Device(byte[] Id,byte[] Reference); internal sealed record Member(byte[] Account,GroupRole Role,byte[] Adc,byte[] Adh,byte[] Adp,ulong DirectoryGeneration,byte[] Dmd,byte[] Drs,List<Device> Devices);
}

/// <summary>Transport-neutral hostile-fork latch for one GCP1 chunk transfer.</summary>
public sealed class GroupChunkAssembler
{
    private byte[]? packageHash; private uint? total; private uint? count; private readonly Dictionary<uint, byte[]> chunks = [];
    public bool ForkLatched { get; private set; }
    public bool TryAdd(GroupCommitChunkRecord chunk, out ReadOnlyMemory<byte> completed)
    { completed=default; if(ForkLatched)return false; var h=chunk.Field(1).ToArray();var t=BinaryPrimitives.ReadUInt32BigEndian(chunk.Field(2).Span);var c=BinaryPrimitives.ReadUInt32BigEndian(chunk.Field(5).Span);var i=BinaryPrimitives.ReadUInt32BigEndian(chunk.Field(4).Span);var field=chunk.Field(7).Span;var n=BinaryPrimitives.ReadUInt32BigEndian(field);var b=field.Slice(4,checked((int)n)).ToArray();if(packageHash is null){packageHash=h;total=t;count=c;}else if(!packageHash.AsSpan().SequenceEqual(h)||total!=t||count!=c){ForkLatched=true;return false;}if(chunks.TryGetValue(i,out var old)&&!old.AsSpan().SequenceEqual(b)){ForkLatched=true;return false;}chunks[i]=b;if(chunks.Count!=count)return true;var joined=chunks.OrderBy(x=>x.Key).SelectMany(x=>x.Value).ToArray();if(joined.Length!=total||!GroupCodec.RecordHash(ProtocolMagic.GCP1,joined).AsSpan().SequenceEqual(packageHash)){ForkLatched=true;return false;}completed=joined;return true; }
}
