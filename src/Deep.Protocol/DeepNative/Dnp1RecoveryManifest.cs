using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepNative;

internal readonly record struct RecoveryManifestRow(
    ArtifactReference Reference,
    int CanonicalOffset,
    int CanonicalLength);

internal readonly record struct RecoveryFrontierEntry(
    ushort FieldKind,
    int SubjectOffset,
    int PredecessorOffset);

internal readonly record struct RecoveryPredecessorEntry(
    int SuccessorOffset,
    ushort FieldKind,
    int PredecessorOffset);

internal readonly record struct RecoveryDrtEntry(int Offset);

internal sealed class OwnedRecoveryManifest : IDisposable
{
    private byte[]? _plaintext;
    private readonly RecoveryManifestRow[] _rows;
    private readonly RecoveryFrontierEntry[] _frontier;
    private readonly RecoveryPredecessorEntry[] _predecessors;
    private readonly RecoveryDrtEntry[] _drt;

    internal OwnedRecoveryManifest(
        byte[] plaintext,
        RecoveryManifestRow[] rows,
        RecoveryFrontierEntry[] frontier,
        RecoveryPredecessorEntry[] predecessors,
        RecoveryDrtEntry[] drt,
        int rfcOffset,
        int rfcLength,
        int rpfOffset,
        int rpfLength,
        int rahOffset,
        int dtcOffset,
        int dtcLength,
        int dwhOffset,
        int dwhLength)
    {
        _plaintext = plaintext;
        _rows = rows;
        _frontier = frontier;
        _predecessors = predecessors;
        _drt = drt;
        RfcOffset = rfcOffset;
        RfcLength = rfcLength;
        RpfOffset = rpfOffset;
        RpfLength = rpfLength;
        RahOffset = rahOffset;
        DtcOffset = dtcOffset;
        DtcLength = dtcLength;
        DwhOffset = dwhOffset;
        DwhLength = dwhLength;
    }

    internal IReadOnlyList<RecoveryManifestRow> Rows => _rows;
    internal IReadOnlyList<RecoveryFrontierEntry> FrontierEntries => _frontier;
    internal IReadOnlyList<RecoveryPredecessorEntry> PredecessorEntries => _predecessors;
    internal IReadOnlyList<RecoveryDrtEntry> DrtEntries => _drt;
    internal int RfcOffset { get; }
    internal int RfcLength { get; }
    internal int RpfOffset { get; }
    internal int RpfLength { get; }
    internal int RahOffset { get; }
    internal int DtcOffset { get; }
    internal int DtcLength { get; }
    internal int DwhOffset { get; }
    internal int DwhLength { get; }

    internal ReadOnlySpan<byte> CanonicalSpan => Owned;
    internal ReadOnlySpan<byte> PinCoreProjection => Owned.Slice(10, 274);
    internal ReadOnlySpan<byte> FrontierCheckpoint => Owned.Slice(RfcOffset, RfcLength);
    internal ReadOnlySpan<byte> PredecessorFrontier => Owned.Slice(RpfOffset, RpfLength);
    internal ReadOnlySpan<byte> ResetAuthorityHead =>
        Owned.Slice(RahOffset, RecoveryManifestParser.RahFixedLength);
    internal ReadOnlySpan<byte> DrtCatalog => Owned.Slice(DtcOffset, DtcLength);
    internal ReadOnlySpan<byte> WitnessHeadHistory => Owned.Slice(DwhOffset, DwhLength);
    internal ReadOnlySpan<byte> RfcProtectedKeyId =>
        Owned.Slice(RfcOffset + RfcLength - 64, 32);
    internal ReadOnlySpan<byte> RfcStoredHmac =>
        Owned.Slice(RfcOffset + RfcLength - 32, 32);
    internal ReadOnlySpan<byte> RahProtectedKeyId =>
        Owned.Slice(RahOffset + RecoveryManifestParser.RahFixedLength - 64, 32);
    internal ReadOnlySpan<byte> RahStoredHmac =>
        Owned.Slice(RahOffset + RecoveryManifestParser.RahFixedLength - 32, 32);
    internal ReadOnlySpan<byte> DtcProtectedKeyId =>
        Owned.Slice(DtcOffset + DtcLength - 64, 32);
    internal ReadOnlySpan<byte> DtcStoredHmac =>
        Owned.Slice(DtcOffset + DtcLength - 32, 32);
    internal ReadOnlySpan<byte> DwhProtectedKeyId =>
        Owned.Slice(DwhOffset + DwhLength - 64, 32);
    internal ReadOnlySpan<byte> DwhStoredHmac =>
        Owned.Slice(DwhOffset + DwhLength - 32, 32);
    internal ReadOnlySpan<byte> RfcSourceTuple => Owned.Slice(RfcOffset + 6, 160);
    internal ReadOnlySpan<byte> RowBytes(int index)
    {
        var row = _rows[index];
        return Owned.Slice(row.CanonicalOffset, row.CanonicalLength);
    }

    internal ReadOnlySpan<byte> RfcSubject(int index) =>
        Owned.Slice(_frontier[index].SubjectOffset, 32);
    internal ReadOnlySpan<byte> RfcPredecessor(int index) =>
        Owned.Slice(_frontier[index].PredecessorOffset, 38);
    internal ReadOnlySpan<byte> RpfSuccessor(int index) =>
        Owned.Slice(_predecessors[index].SuccessorOffset, 38);
    internal ReadOnlySpan<byte> RpfPredecessor(int index) =>
        Owned.Slice(_predecessors[index].PredecessorOffset, 38);
    internal ReadOnlySpan<byte> DtcEntry(int index) =>
        Owned.Slice(_drt[index].Offset, RecoveryManifestParser.DrtEntryLength);
    internal void VerifyAuthenticatedAuthorityPartitions() =>
        RecoveryManifestParser.VerifyAuthorityPartitions(
            _plaintext ?? throw new ObjectDisposedException(nameof(OwnedRecoveryManifest)),
            _rows,
            new RecoveryManifestShape(
                RfcOffset, RfcLength, _frontier.Length,
                RpfOffset, RpfLength, _predecessors.Length,
                RahOffset,
                DtcOffset, DtcLength, _drt.Length,
                BinaryPrimitives.ReadUInt16BigEndian(Owned.Slice(DtcOffset + 168, 2)),
                DwhOffset, DwhLength,
                BinaryPrimitives.ReadUInt16BigEndian(Owned.Slice(DwhOffset + 166, 2)),
                DwhOffset + DwhLength),
            verifyAuthenticatedRah: true);

    private ReadOnlySpan<byte> Owned =>
        _plaintext ?? throw new ObjectDisposedException(nameof(OwnedRecoveryManifest));

    public void Dispose()
    {
        var plaintext = Interlocked.Exchange(ref _plaintext, null);
        if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
    }
}

internal static class RecoveryManifestParser
{
    internal const int PrefixLength = 284;
    internal const int PinCoreLength = 274;
    internal const int RfcFixedLength = 232;
    internal const int RfcEntryLength = 72;
    internal const int RpfFixedLength = 8;
    internal const int RpfEntryLength = 78;
    internal const int RahFixedLength = 426;
    internal const int DtcFixedLength = 234;
    internal const int DrtEntryLength = 370;
    internal const int DrtHistoryEntryLength = 172;
    internal const int DwhFixedLength = 232;
    internal const int DwhEntryLength = 342;
    internal const int MaximumFrontierCount = 66;
    internal const int MaximumDrtCount = 1024;
    internal const int MaximumArtifactCount = 452;
    internal const int MaximumPlaintextLength = 33_554_432;

    private static readonly HashSet<ArtifactType> ComponentTypes =
    [
        ArtifactType.Dpa1, ArtifactType.Dcm1, ArtifactType.Drs1,
        ArtifactType.Dra1, ArtifactType.Dpd1, ArtifactType.Dpm1,
        ArtifactType.Dnr1, ArtifactType.Mrl2, ArtifactType.Dpc1,
        ArtifactType.Msm1, ArtifactType.Pma1, ArtifactType.Pmr1,
        ArtifactType.DgSource, ArtifactType.Mng1, ArtifactType.Mdg1,
        ArtifactType.Mrv1, ArtifactType.Mmc1
    ];

    internal static OwnedRecoveryManifest DecodeOwned(
        ReadOnlySpan<byte> plaintext,
        ushort expectedArtifactCount)
    {
        Preflight(plaintext, expectedArtifactCount);
        var owned = plaintext.ToArray();
        return TakeOwned(owned, expectedArtifactCount);
    }

    internal static OwnedRecoveryManifest TakeOwned(
        byte[] plaintext,
        ushort expectedArtifactCount)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        try
        {
            var shape = Preflight(plaintext, expectedArtifactCount);
            var rows = DescribeAndVerifyRows(plaintext, shape.RowsOffset, expectedArtifactCount);
            VerifyAuthorityPartitions(plaintext, rows, shape, verifyAuthenticatedRah: false);
            VerifyClosedProfile(plaintext, rows, shape);
            return new OwnedRecoveryManifest(
                plaintext,
                rows,
                DescribeRfc(plaintext, shape.RfcOffset, shape.RfcCount),
                DescribeRpf(plaintext, shape.RpfOffset, shape.RpfCount),
                DescribeDtc(shape.DtcOffset, shape.DtcCount),
                shape.RfcOffset,
                shape.RfcLength,
                shape.RpfOffset,
                shape.RpfLength,
                shape.RahOffset,
                shape.DtcOffset,
                shape.DtcLength,
                shape.DwhOffset,
                shape.DwhLength);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
    }

    internal static RecoveryManifestShape Preflight(
        ReadOnlySpan<byte> plaintext,
        ushort expectedArtifactCount)
    {
        if (plaintext.Length < PrefixLength + RfcFixedLength + RpfFixedLength + RahFixedLength +
                DtcFixedLength + DwhFixedLength ||
            plaintext.Length > MaximumPlaintextLength)
            Invalid(RecordError.InvalidLength, "The DRM20 plaintext length is invalid.");
        if (!plaintext[..4].SequenceEqual("DRMV"u8) || plaintext[4] != 20 || plaintext[5] != 1)
            Invalid(RecordError.InvalidHeader, "The DRM20 wire version or component profile is invalid.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(plaintext[6..8]);
        if (count is < 1 or > MaximumArtifactCount || count != expectedArtifactCount ||
            BinaryPrimitives.ReadUInt16BigEndian(plaintext[8..10]) != PinCoreLength)
            Invalid(RecordError.InvalidField, "The DRM20 artifact count or pin-core length is invalid.");
        PreflightProjection(plaintext.Slice(10, PinCoreLength));

        var rfcOffset = PrefixLength;
        var rfcCount = PreflightRfc(plaintext[rfcOffset..]);
        var rfcLength = checked(RfcFixedLength + RfcEntryLength * rfcCount);
        var rpfOffset = checked(rfcOffset + rfcLength);
        var rpfCount = PreflightRpf(plaintext[rpfOffset..]);
        if (rpfCount != rfcCount)
            Invalid(RecordError.InvalidField, "RFC1 and RPF1 frontier counts differ.");
        var rpfLength = checked(RpfFixedLength + RpfEntryLength * rpfCount);
        var rahOffset = checked(rpfOffset + rpfLength);
        PreflightRah(plaintext[rahOffset..]);
        var dtcOffset = checked(rahOffset + RahFixedLength);
        var (dtcCount, dtcHistoryCount) = PreflightDtc(plaintext[dtcOffset..]);
        var dtcLength = checked(DtcFixedLength + DrtEntryLength * dtcCount +
            DrtHistoryEntryLength * dtcHistoryCount);
        var dwhOffset = checked(dtcOffset + dtcLength);
        var dwhCount = PreflightDwh(plaintext[dwhOffset..]);
        var dwhLength = checked(DwhFixedLength + DwhEntryLength * dwhCount);
        var rowsOffset = checked(dwhOffset + dwhLength);
        var rfcSource = plaintext.Slice(rfcOffset + 6, 160);
        var rahSource = plaintext.Slice(rahOffset + 6, 160);
        var dtcSource = plaintext.Slice(dtcOffset + 6, 160);
        var dwhSource = plaintext.Slice(dwhOffset + 6, 160);
        if (!rfcSource.SequenceEqual(rahSource) ||
            !rfcSource.SequenceEqual(dwhSource) ||
            !SameContainerAxis(rfcSource, dtcSource))
            Invalid(RecordError.InvalidField,
                "RFC1, RAH1, DTC2 and DWH1 do not bind the same recovery source tuple.");
        var dtcGenesis = CanonicalGrammar.IsZero(dtcSource.Slice(58, 70));
        if (dtcGenesis
                ? !CanonicalGrammar.IsZero(rfcSource.Slice(58, 38))
                : !rfcSource.Slice(58, 70).SequenceEqual(dtcSource.Slice(58, 70)))
            Invalid(RecordError.InvalidField,
                "The DTC2 predecessor branch differs from the protected recovery source.");
        var sharedKeyOffset = rfcOffset + rfcLength - 64;
        if (!plaintext.Slice(sharedKeyOffset, 32).SequenceEqual(
                plaintext.Slice(rahOffset + RahFixedLength - 64, 32)) ||
            !plaintext.Slice(sharedKeyOffset, 32).SequenceEqual(
                plaintext.Slice(dtcOffset + dtcLength - 64, 32)) ||
            !plaintext.Slice(sharedKeyOffset, 32).SequenceEqual(
                plaintext.Slice(dwhOffset + dwhLength - 64, 32)))
            Invalid(RecordError.InvalidField,
                "RFC1, RAH1, DTC2 and DWH1 do not use one protected-state key ID.");
        var projection = plaintext.Slice(10, PinCoreLength);
        var rfc = plaintext.Slice(rfcOffset, rfcLength);
        if (!projection[..16].SequenceEqual(rfc.Slice(6, 16)) ||
            BinaryPrimitives.ReadUInt16BigEndian(projection[16..18]) !=
                BinaryPrimitives.ReadUInt16BigEndian(rfc[54..56]) ||
            BinaryPrimitives.ReadUInt64BigEndian(projection[18..26]) !=
                BinaryPrimitives.ReadUInt64BigEndian(rfc[56..64]))
            Invalid(RecordError.InvalidField,
                "The pin-core and protected recovery source tuples differ.");
        PreflightRows(plaintext, rowsOffset, count, dtcOffset, dtcCount);
        return new(rfcOffset, rfcLength, rfcCount, rpfOffset, rpfLength, rpfCount,
            rahOffset,
            dtcOffset, dtcLength, dtcCount, dtcHistoryCount,
            dwhOffset, dwhLength, dwhCount, rowsOffset);
    }

    private static void PreflightProjection(ReadOnlySpan<byte> value)
    {
        if (value.Length != PinCoreLength || CanonicalGrammar.IsZero(value[..16]) ||
            !Enum.IsDefined((ComponentKind)BinaryPrimitives.ReadUInt16BigEndian(value[16..18])) ||
            BinaryPrimitives.ReadUInt16BigEndian(value[16..18]) == 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(value[18..26]) == 0 ||
            value[266] > 1 || value[267..274].IndexOfAnyExcept((byte)0) >= 0)
            Invalid(RecordError.InvalidField, "The DRM20 pin-core projection is malformed.");
        Reference(value.Slice(26, 38), ArtifactType.Dpa1, false, "projection account");
        Reference(value.Slice(72, 38), ArtifactType.Dcm1, false, "projection DCM");
        Reference(value.Slice(190, 38), ArtifactType.Drs1, false, "projection DRS");
        var transition = CanonicalGrammar.DecodeReference(value.Slice(228, 38), allowZero: true);
        if (!transition.IsZero && transition.Type is not (
                ArtifactType.Rrm1 or ArtifactType.Krt1 or ArtifactType.Krf1))
            Invalid(RecordError.InvalidArtifactReference, "The projection ReleaseRoot transition type is invalid.");
    }

    private static int PreflightRfc(ReadOnlySpan<byte> value)
    {
        if (value.Length < RfcFixedLength || !value[..4].SequenceEqual("RFC1"u8) ||
            value[4] != 1 || value[5] != 0)
            Invalid(RecordError.InvalidHeader, "The RFC1 header is invalid.");
        CommonContainer(value, dtc: false);
        var count = BinaryPrimitives.ReadUInt16BigEndian(value[166..168]);
        if (count > MaximumFrontierCount || value.Length < checked(RfcFixedLength + count * RfcEntryLength))
            Invalid(RecordError.InvalidLength, "The RFC1 entry table is invalid.");
        ReadOnlySpan<byte> previous = default;
        for (var index = 0; index < count; index++)
        {
            var entry = value.Slice(168 + index * RfcEntryLength, RfcEntryLength);
            var kind = BinaryPrimitives.ReadUInt16BigEndian(entry);
            if (kind is < 1 or > 10 || CanonicalGrammar.IsZero(entry.Slice(2, 32)))
                Invalid(RecordError.InvalidField, "An RFC1 frontier key is invalid.");
            Reference(entry.Slice(34, 38), PredecessorType(kind), false, "RFC1 predecessor");
            var key = entry[..34];
            if (index != 0 && previous.SequenceCompareTo(key) >= 0)
                Invalid(RecordError.InvalidField, "RFC1 entries are not strictly sorted and unique.");
            previous = key;
        }
        var tail = 168 + count * RfcEntryLength;
        if (CanonicalGrammar.IsZero(value.Slice(tail, 32)))
            Invalid(RecordError.InvalidField, "The RFC1 protected-state key ID is zero.");
        return count;
    }

    private static int PreflightRpf(ReadOnlySpan<byte> value)
    {
        if (value.Length < RpfFixedLength || !value[..4].SequenceEqual("RPF1"u8) ||
            value[4] != 1 || value[5] != 0)
            Invalid(RecordError.InvalidHeader, "The RPF1 header is invalid.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(value[6..8]);
        if (count > MaximumFrontierCount || value.Length < checked(RpfFixedLength + count * RpfEntryLength))
            Invalid(RecordError.InvalidLength, "The RPF1 entry table is invalid.");
        Span<byte> previous = stackalloc byte[40];
        var hasPrevious = false;
        Span<byte> key = stackalloc byte[40];
        for (var index = 0; index < count; index++)
        {
            var entry = value.Slice(8 + index * RpfEntryLength, RpfEntryLength);
            var kind = BinaryPrimitives.ReadUInt16BigEndian(entry[38..40]);
            if (kind is < 1 or > 10)
                Invalid(RecordError.InvalidField, "An RPF1 field kind is invalid.");
            Reference(entry[..38], SuccessorType(kind), false, "RPF1 successor");
            Reference(entry.Slice(40, 38), PredecessorType(kind), false, "RPF1 predecessor");
            entry[..38].CopyTo(key);
            entry[38..40].CopyTo(key[38..]);
            if (hasPrevious && previous.SequenceCompareTo(key) >= 0)
                Invalid(RecordError.InvalidField, "RPF1 entries are not strictly sorted and unique.");
            key.CopyTo(previous);
            hasPrevious = true;
        }
        return count;
    }

    private static void PreflightRah(ReadOnlySpan<byte> value)
    {
        if (value.Length < RahFixedLength || !value[..4].SequenceEqual("RAH1"u8) ||
            value[4] != 1 || value[5] != 0)
            Invalid(RecordError.InvalidHeader, "The RAH1 header is invalid.");
        CommonContainer(value, dtc: false);
        var present = value[166];
        if (present > 1 || value[361] != 0)
            Invalid(RecordError.InvalidField, "The RAH1 presence or terminal state is invalid.");
        if (present == 0)
        {
            if (value.Slice(167, 195).IndexOfAnyExcept((byte)0) >= 0)
                Invalid(RecordError.InvalidField,
                    "An absent RAH1 contains recovery-reset authority facts.");
        }
        else
        {
            Reference(value.Slice(167, 38), ArtifactType.Dra1, false, "RAH1 DRA");
            Reference(value.Slice(213, 38), ArtifactType.Dpa1, false, "RAH1 old DPA");
            var head = CanonicalGrammar.DecodeReference(value.Slice(259, 38));
            if (head.Type is not (ArtifactType.Dpa1 or ArtifactType.Krt1))
                Invalid(RecordError.InvalidArtifactReference,
                    "The RAH1 reset-authority head type is invalid.");
            if (BinaryPrimitives.ReadUInt64BigEndian(value[205..213]) == 0 ||
                CanonicalGrammar.IsZero(value.Slice(297, 32)) ||
                CanonicalGrammar.IsZero(value.Slice(329, 32)))
                Invalid(RecordError.InvalidField,
                    "The RAH1 recovery-reset authority tuple is incomplete.");
            var generation = BinaryPrimitives.ReadUInt64BigEndian(value[251..259]);
            if ((generation == 0 && head.Type != ArtifactType.Dpa1) ||
                (generation != 0 && head.Type != ArtifactType.Krt1))
                Invalid(RecordError.InvalidTransition,
                    "The RAH1 head type does not match its generation.");
        }
        if (CanonicalGrammar.IsZero(value.Slice(362, 32)))
            Invalid(RecordError.InvalidField, "The RAH1 protected-state key ID is zero.");
    }

    private static (int TargetCount, int HistoryCount) PreflightDtc(ReadOnlySpan<byte> value)
    {
        if (value.Length < DtcFixedLength || !value[..4].SequenceEqual("DTC2"u8) ||
            value[4] != 2 || value[5] != 0)
            Invalid(RecordError.InvalidHeader, "The DTC2 header is invalid.");
        CommonContainer(value, dtc: true);
        var count = BinaryPrimitives.ReadUInt16BigEndian(value[166..168]);
        var historyCount = BinaryPrimitives.ReadUInt16BigEndian(value[168..170]);
        if (count > MaximumDrtCount || historyCount > count ||
            value.Length < checked(DtcFixedLength + count * DrtEntryLength +
                historyCount * DrtHistoryEntryLength))
            Invalid(RecordError.InvalidLength, "The DTC2 entry tables are invalid.");
        for (var index = 0; index < count; index++)
        {
            var entry = value.Slice(170 + index * DrtEntryLength, DrtEntryLength);
            Reference(entry[..38], ArtifactType.Drt1, false, "DTC2 DRT");
            Reference(entry.Slice(217, 38), TargetType(entry[255]), false, "DTC2 target");
            if (CanonicalGrammar.IsZero(entry.Slice(256, 32)) ||
                CanonicalGrammar.IsZero(entry.Slice(288, 32)))
                Invalid(RecordError.InvalidField, "A DTC2 account or subject key is zero.");
            var ordinal = BinaryPrimitives.ReadUInt16BigEndian(entry[368..370]);
            if ((entry[255] is 1 or 2 && (ordinal == 0 || ordinal > historyCount)) ||
                (entry[255] == 3 && ordinal != 0))
                Invalid(RecordError.InvalidField, "A DTC2 history ordinal is invalid.");
        }
        var historyOffset = 170 + count * DrtEntryLength;
        ReadOnlySpan<byte> previousHistory = default;
        for (var index = 0; index < historyCount; index++)
        {
            var entry = value.Slice(historyOffset + index * DrtHistoryEntryLength,
                DrtHistoryEntryLength);
            Reference(entry[..38], ArtifactType.Drs1, false, "DTC2 predecessor DRS");
            var historyEntryCount = BinaryPrimitives.ReadUInt64BigEndian(entry[46..54]);
            var transitionGeneration = BinaryPrimitives.ReadUInt64BigEndian(entry[94..102]);
            var transition = CanonicalGrammar.DecodeReference(entry.Slice(102, 38), allowZero: true);
            if (BinaryPrimitives.ReadUInt64BigEndian(entry[38..46]) == 0 ||
                (historyEntryCount == 0 ? !CanonicalGrammar.IsZero(entry.Slice(54, 32)) :
                    CanonicalGrammar.IsZero(entry.Slice(54, 32))) ||
                BinaryPrimitives.ReadUInt64BigEndian(entry[86..94]) == 0 ||
                (transitionGeneration == 0 ? !transition.IsZero :
                    transition.IsZero || transition.Type != ArtifactType.Krt1) ||
                CanonicalGrammar.IsZero(entry.Slice(140, 32)))
                Invalid(RecordError.InvalidField, "A DTC2 history entry is incomplete.");
            if (index != 0 && previousHistory.SequenceCompareTo(entry) >= 0)
                Invalid(RecordError.InvalidField,
                    "DTC2 history entries are not strictly sorted and unique.");
            previousHistory = entry;
        }
        var tail = historyOffset + historyCount * DrtHistoryEntryLength;
        if (CanonicalGrammar.IsZero(value.Slice(tail, 32)))
            Invalid(RecordError.InvalidField, "The DTC2 protected-state key ID is zero.");
        return (count, historyCount);
    }

    internal static int PreflightDtcContainer(ReadOnlySpan<byte> value)
    {
        var (count, historyCount) = PreflightDtc(value);
        if (value.Length != checked(DtcFixedLength + DrtEntryLength * count +
                DrtHistoryEntryLength * historyCount))
            Invalid(RecordError.InvalidLength, "The exact DTC2 container has trailing bytes.");
        return count;
    }

    private static int PreflightDwh(ReadOnlySpan<byte> value)
    {
        if (value.Length < DwhFixedLength || !value[..4].SequenceEqual("DWH1"u8) ||
            value[4] != 1 || value[5] != 0)
            Invalid(RecordError.InvalidHeader, "The DWH1 header is invalid.");
        CommonContainer(value, dtc: false);
        var count = BinaryPrimitives.ReadUInt16BigEndian(value[166..168]);
        if (count > 64 || value.Length < checked(DwhFixedLength + count * DwhEntryLength))
            Invalid(RecordError.InvalidLength, "The DWH1 entry table is invalid.");
        ulong previousGeneration = 0;
        for (var index = 0; index < count; index++)
        {
            var entry = value.Slice(168 + index * DwhEntryLength, DwhEntryLength);
            Reference(entry[..38], ArtifactType.Dwd1, false, "DWH1 successor DWD");
            var generation = BinaryPrimitives.ReadUInt64BigEndian(entry[38..46]);
            var predecessorEpoch = BinaryPrimitives.ReadUInt64BigEndian(entry[46..54]);
            if (generation == 0 || predecessorEpoch == 0 ||
                (index != 0 && generation != checked(previousGeneration + 1)))
                Invalid(RecordError.InvalidField,
                    "DWH1 entries are not consecutive successor generations.");
            for (var head = 0; head < 4; head++)
            {
                var row = entry.Slice(54 + head * 72, 72);
                if (CanonicalGrammar.IsZero(row[..32]))
                    Invalid(RecordError.InvalidField, "A DWH1 predecessor witness ID is zero.");
                for (var prior = 0; prior < head; prior++)
                    if (CanonicalGrammar.FixedEquals(row[..32],
                            entry.Slice(54 + prior * 72, 32)))
                        Invalid(RecordError.InvalidField,
                            "DWH1 predecessor witness IDs are duplicated.");
                if (BinaryPrimitives.ReadUInt64BigEndian(row[32..40]) != 0 &&
                    CanonicalGrammar.IsZero(row[40..72]))
                    Invalid(RecordError.InvalidField,
                        "A nonempty DWH1 predecessor tree has a zero root.");
            }
            previousGeneration = generation;
        }
        var tail = 168 + count * DwhEntryLength;
        if (CanonicalGrammar.IsZero(value.Slice(tail, 32)))
            Invalid(RecordError.InvalidField, "The DWH1 protected-state key ID is zero.");
        return count;
    }

    private static void CommonContainer(ReadOnlySpan<byte> value, bool dtc)
    {
        var oldDplIsZero = CanonicalGrammar.IsZero(value.Slice(64, 38));
        var oldSourceIsZero = CanonicalGrammar.IsZero(value.Slice(102, 32));
        if (CanonicalGrammar.IsZero(value.Slice(6, 16)) ||
            !Enum.IsDefined((ComponentKind)BinaryPrimitives.ReadUInt16BigEndian(value[54..56])) ||
            BinaryPrimitives.ReadUInt16BigEndian(value[54..56]) == 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(value[56..64]) == 0 ||
            (dtc ? oldDplIsZero != oldSourceIsZero : oldSourceIsZero) ||
            CanonicalGrammar.IsZero(value.Slice(134, 32)))
            Invalid(RecordError.InvalidField, "The protected recovery container tuple is invalid.");
        Reference(value.Slice(64, 38), ArtifactType.Dpl1, true, "old DPL");
    }

    private static bool SameContainerAxis(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left[..58].SequenceEqual(right[..58]) &&
        left.Slice(128, 32).SequenceEqual(right.Slice(128, 32));

    private static void PreflightRows(
        ReadOnlySpan<byte> plaintext,
        int offset,
        ushort count,
        int dtcOffset,
        int dtcCount)
    {
        Span<int> rowOffsets = stackalloc int[count];
        Span<int> canonicalOffsets = stackalloc int[count];
        Span<int> canonicalLengths = stackalloc int[count];
        Span<ArtifactType> rowTypes = stackalloc ArtifactType[count];
        Span<int> counts = stackalloc int[(int)ArtifactType.Dwt1 + 1];
        ReadOnlySpan<byte> previous = default;
        for (var index = 0; index < count; index++)
        {
            if (plaintext.Length - offset < ArtifactReference.Length)
                Invalid(RecordError.InvalidLength, "A DRM20 row key is truncated.");
            var rowKey = plaintext.Slice(offset, ArtifactReference.Length);
            var typeValue = BinaryPrimitives.ReadUInt16BigEndian(rowKey);
            var length = BinaryPrimitives.ReadUInt32BigEndian(rowKey[2..6]);
            if (!Enum.IsDefined(typeof(ArtifactType), typeValue) || length == 0 ||
                length > int.MaxValue || CanonicalGrammar.IsZero(rowKey[6..38]))
                Invalid(RecordError.InvalidArtifactReference, "A DRM20 row key is invalid.");
            var type = (ArtifactType)typeValue;
            if (!IsAllowed(type))
                Invalid(RecordError.InvalidArtifactReference,
                    "The artifact type is outside the closed DRM20 profile.");
            if (index > 0 && previous.SequenceCompareTo(rowKey) >= 0)
                Invalid(RecordError.InvalidArtifactReference,
                    "DRM20 row keys must be strictly increasing and unique.");
            previous = rowKey;
            var remaining = plaintext.Length - offset - ArtifactReference.Length;
            if (remaining < 0 || length > checked((uint)remaining))
                Invalid(RecordError.InvalidLength, "A DRM20 artifact is truncated.");
            rowOffsets[index] = offset;
            canonicalOffsets[index] = offset + ArtifactReference.Length;
            canonicalLengths[index] = (int)length;
            rowTypes[index] = type;
            counts[typeValue]++;
            if (!ArtifactRegistry.IsRetained(type))
                CanonicalGrammar.Preflight(
                    plaintext.Slice(canonicalOffsets[index], canonicalLengths[index]), Definition(type));
            offset += ArtifactReference.Length + (int)length;
        }
        if (offset != plaintext.Length)
            Invalid(RecordError.InvalidLength, "The DRM20 plaintext has trailing bytes.");

        PreflightCardinality(plaintext, canonicalOffsets, canonicalLengths,
            counts, rowTypes, count);
        PreflightAuthorityPartitions(
            plaintext, rowOffsets, canonicalOffsets, canonicalLengths, rowTypes);
        PreflightAdjacency(plaintext, rowOffsets, canonicalOffsets, canonicalLengths, rowTypes);
        PreflightDrsDtc(plaintext, rowOffsets, canonicalOffsets, canonicalLengths,
            rowTypes, dtcOffset, dtcCount);
    }

    private static void PreflightCardinality(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<int> canonicalOffsets,
        ReadOnlySpan<int> canonicalLengths,
        ReadOnlySpan<int> counts,
        ReadOnlySpan<ArtifactType> rowTypes,
        int total)
    {
        if (counts[(int)ArtifactType.Rrm1] != 1 ||
            counts[(int)ArtifactType.Dcm1] != 1 ||
            counts[(int)ArtifactType.Drs1] != 1)
            Invalid(RecordError.InvalidField, "The DRM20 mandatory cardinality is invalid.");
        var transitions = counts[(int)ArtifactType.Krt1] + counts[(int)ArtifactType.Krf1];
        var delegations = counts[(int)ArtifactType.Dwd1];
        var terminal = counts[(int)ArtifactType.Dwt1];
        var components = 0;
        foreach (var type in rowTypes)
            if (ComponentTypes.Contains(type)) components++;
        var dra = counts[(int)ArtifactType.Dra1];
        if (dra > 1 || counts[(int)ArtifactType.Dpa1] != 1 + dra ||
            transitions > 320 || delegations is < 1 or > 65 || terminal > 1 ||
            components is < 3 or > 65 ||
            (terminal == 1 ? total > 452 : total > 451))
            Invalid(RecordError.InvalidField, "The DRM20 closed-profile cardinality is invalid.");
        Span<int> scopes = stackalloc int[5];
        Span<int> revocations = stackalloc int[5];
        for (var index = 0; index < rowTypes.Length; index++)
        {
            if (rowTypes[index] is not (ArtifactType.Krt1 or ArtifactType.Krf1)) continue;
            var canonical = plaintext.Slice(canonicalOffsets[index], canonicalLengths[index]);
            var scope = RecordDefinitions.Field(canonical, 2)[0];
            if (scope is < 1 or > 4)
                Invalid(RecordError.InvalidField, "A DRM20 transition scope is invalid.");
            scopes[scope]++;
            if (rowTypes[index] == ArtifactType.Krf1) revocations[scope]++;
        }
        if (scopes[(int)KeyScope.ReleaseRoot] > 64 ||
            scopes[(int)KeyScope.DeviceCertificateIssuer] > 64 ||
            scopes[(int)KeyScope.AccountRevocation] > 64 ||
            scopes[(int)KeyScope.ResetControl] > (dra == 0 ? 64 : 128) ||
            revocations[(int)KeyScope.ReleaseRoot] > 1 ||
            revocations[(int)KeyScope.DeviceCertificateIssuer] > 1 ||
            revocations[(int)KeyScope.AccountRevocation] > 1 ||
            revocations[(int)KeyScope.ResetControl] > 1)
            Invalid(RecordError.InvalidField, "The DRM20 scoped transition cardinality is invalid.");
    }

    private static void PreflightAdjacency(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<int> rowOffsets,
        ReadOnlySpan<int> canonicalOffsets,
        ReadOnlySpan<int> canonicalLengths,
        ReadOnlySpan<ArtifactType> rowTypes)
    {
        for (var index = 0; index < rowTypes.Length; index++)
        {
            var type = rowTypes[index];
            if (ArtifactRegistry.IsRetained(type)) continue;
            var canonical = plaintext.Slice(canonicalOffsets[index], canonicalLengths[index]);
            switch (type)
            {
                case ArtifactType.Dpa1:
                case ArtifactType.Rrm1:
                    break;
                case ArtifactType.Dpd1:
                    PreflightOptionalRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 10), ArtifactType.Krt1);
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 13), ArtifactType.Drs1);
                    break;
                case ArtifactType.Dpm1:
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 5), ArtifactType.Dpd1);
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 11), ArtifactType.Drs1);
                    break;
                case ArtifactType.Drs1:
                    PreflightOptionalRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 7), ArtifactType.Krt1);
                    break;
                case ArtifactType.Krt1:
                case ArtifactType.Krf1:
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 6), ArtifactType.Rrm1,
                        ArtifactType.Dpa1, ArtifactType.Krt1);
                    break;
                case ArtifactType.Dcm1:
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 5), ArtifactType.Dpa1);
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 9), ArtifactType.Drs1);
                    PreflightOptionalRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 12), ArtifactType.Krt1);
                    break;
                case ArtifactType.Dra1:
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 3), ArtifactType.Dpa1);
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 10), ArtifactType.Dpa1);
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 12), ArtifactType.Dcm1);
                    break;
                case ArtifactType.Dwd1:
                    PreflightOptionalRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 3), ArtifactType.Dwd1);
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 16), ArtifactType.Rrm1,
                        ArtifactType.Krt1, ArtifactType.Krf1);
                    break;
                case ArtifactType.Dwt1:
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 3), ArtifactType.Dwd1);
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 6), ArtifactType.Krf1);
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 8), ArtifactType.Krf1);
                    break;
                case ArtifactType.Dnr1:
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 3), ArtifactType.Dpm1);
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 4), ArtifactType.Pma1);
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 6), ArtifactType.Pmr1);
                    break;
                case ArtifactType.Mrl2:
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 5), ArtifactType.Dnr1);
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 9), ArtifactType.Dpc1);
                    break;
                case ArtifactType.Dpc1:
                    PreflightRequiredRow(plaintext, rowOffsets, rowTypes,
                        RecordDefinitions.Field(canonical, 3), ArtifactType.Dnr1);
                    break;
                default:
                    Invalid(RecordError.InvalidArtifactReference,
                        "A canonical DRM20 row has no closed adjacency rule.");
                    break;
            }
        }
        PreflightSameTypeAcyclic(plaintext, rowOffsets, canonicalOffsets, canonicalLengths,
            rowTypes, ArtifactType.Krt1, 6);
        PreflightSameTypeAcyclic(plaintext, rowOffsets, canonicalOffsets, canonicalLengths,
            rowTypes, ArtifactType.Dwd1, 3);
    }

    private static void PreflightAuthorityPartitions(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<int> rowOffsets,
        ReadOnlySpan<int> canonicalOffsets,
        ReadOnlySpan<int> canonicalLengths,
        ReadOnlySpan<ArtifactType> rowTypes)
    {
        Span<byte> used = stackalloc byte[rowTypes.Length];
        var rootIndex = rowTypes.IndexOf(ArtifactType.Rrm1);
        if (rootIndex < 0) Invalid(RecordError.InvalidField, "DRM20 omits RRM1.");
        PreflightWalkAuthorityChain(plaintext, rowOffsets, canonicalOffsets, canonicalLengths,
            rowTypes, used, CanonicalRowReference(plaintext, rowOffsets, rootIndex),
            KeyScope.ReleaseRoot, default, 0, allowRevocation: true);

        var currentDpaReference = plaintext.Slice(36, 38);
        var currentDpaIndex = PreflightFindRow(plaintext, rowOffsets, currentDpaReference);
        if (rowTypes[currentDpaIndex] != ArtifactType.Dpa1)
            Invalid(RecordError.InvalidArtifactReference,
                "The DRM20 current account is not a DPA1 row.");
        var currentDpa = plaintext.Slice(
            canonicalOffsets[currentDpaIndex], canonicalLengths[currentDpaIndex]);
        Span<byte> currentAccountHash = stackalloc byte[32];
        PreflightAccountHash(currentDpa, currentAccountHash);
        var currentAccountGeneration = Scalars.UInt64(RecordDefinitions.Field(currentDpa, 2));
        PreflightWalkAuthorityChain(plaintext, rowOffsets, canonicalOffsets, canonicalLengths,
            rowTypes, used, currentDpaReference, KeyScope.DeviceCertificateIssuer,
            currentAccountHash, currentAccountGeneration, allowRevocation: true);
        PreflightWalkAuthorityChain(plaintext, rowOffsets, canonicalOffsets, canonicalLengths,
            rowTypes, used, currentDpaReference, KeyScope.AccountRevocation,
            currentAccountHash, currentAccountGeneration, allowRevocation: true);
        PreflightWalkAuthorityChain(plaintext, rowOffsets, canonicalOffsets, canonicalLengths,
            rowTypes, used, currentDpaReference, KeyScope.ResetControl,
            currentAccountHash, currentAccountGeneration, allowRevocation: true);

        var rahOffset = FindRahOffset(plaintext);
        var rah = plaintext.Slice(rahOffset, RahFixedLength);
        var draCount = 0;
        for (var index = 0; index < rowTypes.Length; index++)
            if (rowTypes[index] == ArtifactType.Dra1) draCount++;
        if ((rah[166] != 0) != (draCount == 1))
            Invalid(RecordError.InvalidField,
                "RAH1 presence does not match the historical reset partition.");
        if (rah[166] != 0)
        {
            var oldDpaIndex = PreflightFindRow(plaintext, rowOffsets, rah.Slice(213, 38));
            if (rowTypes[oldDpaIndex] != ArtifactType.Dpa1)
                Invalid(RecordError.InvalidArtifactReference,
                    "RAH1 historical account is not a DPA1 row.");
            var oldDpa = plaintext.Slice(
                canonicalOffsets[oldDpaIndex], canonicalLengths[oldDpaIndex]);
            Span<byte> oldAccountHash = stackalloc byte[32];
            PreflightAccountHash(oldDpa, oldAccountHash);
            PreflightWalkAuthorityChain(plaintext, rowOffsets, canonicalOffsets,
                canonicalLengths, rowTypes, used, rah.Slice(213, 38),
                KeyScope.ResetControl, oldAccountHash,
                Scalars.UInt64(RecordDefinitions.Field(oldDpa, 2)), allowRevocation: false);
        }

        for (var index = 0; index < rowTypes.Length; index++)
            if (rowTypes[index] is ArtifactType.Krt1 or ArtifactType.Krf1 && used[index] == 0)
                Invalid(RecordError.InvalidTransition,
                    "A DRM20 transition is outside the closed authority partitions.");

        PreflightIssuedBinding(plaintext, rowOffsets, canonicalOffsets, canonicalLengths,
            rowTypes, ArtifactType.Dpd1, 9, 10, KeyScope.DeviceCertificateIssuer);
        PreflightIssuedBinding(plaintext, rowOffsets, canonicalOffsets, canonicalLengths,
            rowTypes, ArtifactType.Drs1, 6, 7, KeyScope.AccountRevocation);
        PreflightIssuedBinding(plaintext, rowOffsets, canonicalOffsets, canonicalLengths,
            rowTypes, ArtifactType.Dcm1, 10, 12, KeyScope.ResetControl);
    }

    private static void PreflightWalkAuthorityChain(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<int> rowOffsets,
        ReadOnlySpan<int> canonicalOffsets,
        ReadOnlySpan<int> canonicalLengths,
        ReadOnlySpan<ArtifactType> rowTypes,
        Span<byte> used,
        ReadOnlySpan<byte> startReference,
        KeyScope expectedScope,
        ReadOnlySpan<byte> expectedAccountHash,
        ulong expectedAccountGeneration,
        bool allowRevocation)
    {
        Span<byte> predecessor = stackalloc byte[38];
        startReference.CopyTo(predecessor);
        for (ulong expectedGeneration = 1; expectedGeneration <= 64; expectedGeneration++)
        {
            var successor = -1;
            for (var index = 0; index < rowTypes.Length; index++)
            {
                if (rowTypes[index] is not (ArtifactType.Krt1 or ArtifactType.Krf1)) continue;
                var canonical = plaintext.Slice(canonicalOffsets[index], canonicalLengths[index]);
                if ((KeyScope)RecordDefinitions.Field(canonical, 2)[0] != expectedScope ||
                    (expectedScope != KeyScope.ReleaseRoot &&
                     (!CanonicalGrammar.FixedEquals(
                         RecordDefinitions.Field(canonical, 3), expectedAccountHash) ||
                      Scalars.UInt64(RecordDefinitions.Field(canonical, 4)) !=
                          expectedAccountGeneration)) ||
                    !CanonicalGrammar.FixedEquals(RecordDefinitions.Field(canonical, 6), predecessor))
                    continue;
                if (successor >= 0)
                    Invalid(RecordError.InvalidTransition,
                        "A DRM20 authority chain forks before artifact ownership.");
                successor = index;
            }
            if (successor < 0) return;
            var next = plaintext.Slice(canonicalOffsets[successor], canonicalLengths[successor]);
            if (Scalars.UInt64(RecordDefinitions.Field(next, 5)) != expectedGeneration ||
                used[successor] != 0)
                Invalid(RecordError.InvalidTransition,
                    "A DRM20 authority chain skips or aliases a transition.");
            if (rowTypes[successor] == ArtifactType.Krf1 && !allowRevocation)
                Invalid(RecordError.InvalidTransition,
                    "The historical reset chain contains KRF1.");
            used[successor] = 1;
            CanonicalRowReference(plaintext, rowOffsets, successor).CopyTo(predecessor);
            if (rowTypes[successor] == ArtifactType.Krf1) return;
        }
        for (var index = 0; index < rowTypes.Length; index++)
        {
            if (rowTypes[index] is not (ArtifactType.Krt1 or ArtifactType.Krf1)) continue;
            var canonical = plaintext.Slice(canonicalOffsets[index], canonicalLengths[index]);
            if ((KeyScope)RecordDefinitions.Field(canonical, 2)[0] == expectedScope &&
                CanonicalGrammar.FixedEquals(RecordDefinitions.Field(canonical, 6), predecessor))
                Invalid(RecordError.InvalidTransition,
                    "A DRM20 authority chain exceeds 64 transitions.");
        }
    }

    private static void PreflightAccountHash(
        ReadOnlySpan<byte> canonicalDpa, Span<byte> destination32)
    {
        ReadOnlySpan<byte> domain = "Deep/IdentityAuth/V1/account-id"u8;
        Span<byte> input = stackalloc byte[2 + 31 + 4 + 56];
        BinaryPrimitives.WriteUInt16BigEndian(input, checked((ushort)domain.Length));
        domain.CopyTo(input[2..]);
        var offset = 2 + domain.Length;
        BinaryPrimitives.WriteUInt32BigEndian(input.Slice(offset, 4), 56);
        offset += 4;
        RecordDefinitions.Field(canonicalDpa, 1).CopyTo(input[offset..]); offset += 16;
        RecordDefinitions.Field(canonicalDpa, 2).CopyTo(input[offset..]); offset += 8;
        RecordDefinitions.Field(canonicalDpa, 5).CopyTo(input[offset..]);
        if (!SHA256.TryHashData(input, destination32, out var written) || written != 32)
            Invalid(RecordError.InvalidField, "The DRM20 account hash could not be computed.");
    }

    private static void PreflightIssuedBinding(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<int> rowOffsets,
        ReadOnlySpan<int> canonicalOffsets,
        ReadOnlySpan<int> canonicalLengths,
        ReadOnlySpan<ArtifactType> rowTypes,
        ArtifactType artifactType,
        int generationTag,
        int referenceTag,
        KeyScope expectedScope)
    {
        for (var index = 0; index < rowTypes.Length; index++)
        {
            if (rowTypes[index] != artifactType) continue;
            var canonical = plaintext.Slice(canonicalOffsets[index], canonicalLengths[index]);
            var generation = Scalars.UInt64(RecordDefinitions.Field(canonical, generationTag));
            var reference = RecordDefinitions.Field(canonical, referenceTag);
            var decoded = CanonicalGrammar.DecodeReference(reference, allowZero: true);
            if (generation == 0)
            {
                if (!decoded.IsZero)
                    Invalid(RecordError.InvalidTransition,
                        "A generation-zero role binding has a transition reference.");
                continue;
            }
            var transitionIndex = PreflightFindRow(plaintext, rowOffsets, reference);
            if (decoded.Type != ArtifactType.Krt1 || rowTypes[transitionIndex] != ArtifactType.Krt1)
                Invalid(RecordError.InvalidTransition,
                    "A role binding names a terminal or wrong transition.");
            var transition = plaintext.Slice(
                canonicalOffsets[transitionIndex], canonicalLengths[transitionIndex]);
            if ((KeyScope)RecordDefinitions.Field(transition, 2)[0] != expectedScope ||
                Scalars.UInt64(RecordDefinitions.Field(transition, 5)) != generation)
                Invalid(RecordError.InvalidTransition,
                    "A role binding generation or scope differs from KRT1.");
        }
    }

    private static ReadOnlySpan<byte> CanonicalRowReference(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<int> rowOffsets,
        int index) => plaintext.Slice(rowOffsets[index], ArtifactReference.Length);

    private static int FindRahOffset(ReadOnlySpan<byte> plaintext)
    {
        var rfcCount = BinaryPrimitives.ReadUInt16BigEndian(plaintext.Slice(PrefixLength + 166, 2));
        var rpfOffset = checked(PrefixLength + RfcFixedLength + rfcCount * RfcEntryLength);
        var rpfCount = BinaryPrimitives.ReadUInt16BigEndian(plaintext.Slice(rpfOffset + 6, 2));
        return checked(rpfOffset + RpfFixedLength + rpfCount * RpfEntryLength);
    }

    private static void PreflightDrsDtc(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<int> rowOffsets,
        ReadOnlySpan<int> canonicalOffsets,
        ReadOnlySpan<int> canonicalLengths,
        ReadOnlySpan<ArtifactType> rowTypes,
        int dtcOffset,
        int dtcCount)
    {
        var drsIndex = rowTypes.IndexOf(ArtifactType.Drs1);
        var drs = plaintext.Slice(canonicalOffsets[drsIndex], canonicalLengths[drsIndex]);
        if (BinaryPrimitives.ReadUInt16BigEndian(RecordDefinitions.Field(drs, 9)) != dtcCount)
            Invalid(RecordError.InvalidField, "DTC2 count does not equal the cumulative DRS1 count.");
        var entries = RecordDefinitions.Field(drs, 10);
        for (var index = 0; index < dtcCount; index++)
        {
            var drsEntry = entries.Slice(index * 62, 62);
            var dtcEntry = plaintext.Slice(dtcOffset + 170 + index * DrtEntryLength, DrtEntryLength);
            if (drsEntry[0] != dtcEntry[255] ||
                !CanonicalGrammar.FixedEquals(drsEntry.Slice(1, 38), dtcEntry[..38]) ||
                BinaryPrimitives.ReadUInt64BigEndian(drsEntry[39..47]) !=
                    BinaryPrimitives.ReadUInt64BigEndian(dtcEntry[320..328]))
                Invalid(RecordError.InvalidArtifactReference, "DTC2 is not in exact DRS1 order.");
            CanonicalGrammar.Preflight(dtcEntry.Slice(38, 179), RecordDefinitions.Drt1);
            if (dtcEntry[255] == 3)
                PreflightRequiredRow(plaintext, rowOffsets, rowTypes, dtcEntry.Slice(217, 38),
                    ArtifactType.Dpa1);
            else
                PreflightForbiddenRow(rowOffsets, rowTypes, plaintext, dtcEntry.Slice(217, 38));
            for (var prior = 0; prior < index; prior++)
            {
                var priorEntry = plaintext.Slice(
                    dtcOffset + 170 + prior * DrtEntryLength, DrtEntryLength);
                if (CanonicalGrammar.FixedEquals(priorEntry.Slice(217, 38), dtcEntry.Slice(217, 38)) ||
                    CanonicalGrammar.FixedEquals(priorEntry.Slice(288, 32), dtcEntry.Slice(288, 32)))
                    Invalid(RecordError.InvalidField,
                        "DTC2 repeats a target or protected target fact.");
            }
        }
    }

    private static void PreflightForbiddenRow(
        ReadOnlySpan<int> rowOffsets,
        ReadOnlySpan<ArtifactType> rowTypes,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> reference)
    {
        for (var index = 0; index < rowOffsets.Length; index++)
            if (CanonicalGrammar.FixedEquals(
                    plaintext.Slice(rowOffsets[index], ArtifactReference.Length), reference))
                Invalid(RecordError.InvalidArtifactReference,
                    "A protected DTC2 target collides with an active DRM20 row.");
    }

    private static void PreflightOptionalRow(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<int> rowOffsets,
        ReadOnlySpan<ArtifactType> rowTypes,
        ReadOnlySpan<byte> reference,
        params ArtifactType[] allowed)
    {
        if (CanonicalGrammar.DecodeReference(reference, allowZero: true).IsZero) return;
        PreflightRequiredRow(plaintext, rowOffsets, rowTypes, reference, allowed);
    }

    private static void PreflightRequiredRow(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<int> rowOffsets,
        ReadOnlySpan<ArtifactType> rowTypes,
        ReadOnlySpan<byte> reference,
        params ArtifactType[] allowed)
    {
        var index = PreflightFindRow(plaintext, rowOffsets, reference);
        if (!allowed.Contains(rowTypes[index]))
            Invalid(RecordError.InvalidArtifactReference,
                "A DRM20 reference crosses its closed adjacency class.");
    }

    private static int PreflightFindRow(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<int> rowOffsets,
        ReadOnlySpan<byte> reference)
    {
        for (var index = 0; index < rowOffsets.Length; index++)
            if (CanonicalGrammar.FixedEquals(
                    plaintext.Slice(rowOffsets[index], ArtifactReference.Length), reference))
                return index;
        Invalid(RecordError.InvalidArtifactReference, "A DRM20 linked row is absent.");
        return -1;
    }

    private static void PreflightSameTypeAcyclic(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<int> rowOffsets,
        ReadOnlySpan<int> canonicalOffsets,
        ReadOnlySpan<int> canonicalLengths,
        ReadOnlySpan<ArtifactType> rowTypes,
        ArtifactType type,
        int predecessorTag)
    {
        Span<byte> visited = stackalloc byte[rowTypes.Length];
        for (var start = 0; start < rowTypes.Length; start++)
        {
            if (rowTypes[start] != type) continue;
            visited.Clear();
            var current = start;
            while (true)
            {
                if (visited[current] != 0)
                    Invalid(RecordError.InvalidTransition, "A DRM20 predecessor chain is cyclic.");
                visited[current] = 1;
                var canonical = plaintext.Slice(canonicalOffsets[current], canonicalLengths[current]);
                var predecessor = RecordDefinitions.Field(canonical, predecessorTag);
                var decoded = CanonicalGrammar.DecodeReference(predecessor, allowZero: true);
                if (decoded.IsZero || decoded.Type != type) break;
                current = PreflightFindRow(plaintext, rowOffsets, predecessor);
            }
        }
    }

    private static RecoveryManifestRow[] DescribeAndVerifyRows(byte[] plaintext, int offset, ushort count)
    {
        var rows = new RecoveryManifestRow[count];
        for (var index = 0; index < count; index++)
        {
            var rowKey = plaintext.AsSpan(offset, ArtifactReference.Length);
            var type = (ArtifactType)BinaryPrimitives.ReadUInt16BigEndian(rowKey);
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(rowKey[2..6]));
            var bytesOffset = offset + ArtifactReference.Length;
            var bytes = plaintext.AsSpan(bytesOffset, length);
            VerifyCanonicalReference(type, rowKey, bytes);
            rows[index] = new RecoveryManifestRow(
                new ArtifactReference(type, checked((uint)length), rowKey[6..38]),
                bytesOffset,
                length);
            offset = checked(bytesOffset + length);
        }
        return rows;
    }

    private static void VerifyClosedProfile(
        ReadOnlySpan<byte> plaintext,
        RecoveryManifestRow[] rows,
        RecoveryManifestShape shape)
    {
        var counts = new Dictionary<ArtifactType, int>();
        foreach (var row in rows)
        {
            counts[row.Reference.Type] = counts.GetValueOrDefault(row.Reference.Type) + 1;
            if (!IsAllowed(row.Reference.Type))
                Invalid(RecordError.InvalidArtifactReference,
                    "The artifact type is outside the closed DRM20 profile.");
        }
        Require(counts, ArtifactType.Rrm1, 1);
        Require(counts, ArtifactType.Dcm1, 1);
        Require(counts, ArtifactType.Drs1, 1);
        var transitions = counts.GetValueOrDefault(ArtifactType.Krt1) + counts.GetValueOrDefault(ArtifactType.Krf1);
        var delegations = counts.GetValueOrDefault(ArtifactType.Dwd1);
        var terminal = counts.GetValueOrDefault(ArtifactType.Dwt1);
        var component = rows.Count(static row => ComponentTypes.Contains(row.Reference.Type));
        var dra = counts.GetValueOrDefault(ArtifactType.Dra1);
        if (dra > 1 || counts.GetValueOrDefault(ArtifactType.Dpa1) != 1 + dra ||
            transitions > 320 || delegations is < 1 or > 65 || terminal > 1 ||
            component is < 3 or > 65 ||
            (terminal == 1 ? rows.Length > 452 : rows.Length > 451))
            Invalid(RecordError.InvalidField, "The DRM20 closed-profile cardinality is invalid.");

        var drsRow = rows.Single(static row => row.Reference.Type == ArtifactType.Drs1);
        var drs = CanonicalGrammar.DecodeOwned(
            plaintext.Slice(drsRow.CanonicalOffset, drsRow.CanonicalLength),
            RecordDefinitions.Drs1);
        if (BinaryPrimitives.ReadUInt16BigEndian(drs.FieldSpan(9)) != shape.DtcCount)
            Invalid(RecordError.InvalidField, "DTC1 count does not equal the cumulative DRS1 count.");
        VerifyDrtCatalog(plaintext, rows, drs, shape);
        VerifyFrontier(plaintext, rows, shape);
        VerifyAdjacency(plaintext, rows);
    }

    private static void VerifyAdjacency(ReadOnlySpan<byte> plaintext, RecoveryManifestRow[] rows)
    {
        foreach (var row in rows)
        {
            if (ArtifactRegistry.IsRetained(row.Reference.Type)) continue;
            var record = CanonicalGrammar.DecodeOwned(
                plaintext.Slice(row.CanonicalOffset, row.CanonicalLength), Definition(row.Reference.Type));
            switch (row.Reference.Type)
            {
                case ArtifactType.Dpa1:
                    break; // predecessor is closed through RPF1.
                case ArtifactType.Dpd1:
                    RequireOptionalRow(rows, record.FieldSpan(10), ArtifactType.Krt1);
                    RequireRow(rows, record.FieldSpan(13), ArtifactType.Drs1);
                    break;
                case ArtifactType.Dpm1:
                    RequireRow(rows, record.FieldSpan(5), ArtifactType.Dpd1);
                    RequireRow(rows, record.FieldSpan(11), ArtifactType.Drs1);
                    break;
                case ArtifactType.Drs1:
                    RequireOptionalRow(rows, record.FieldSpan(7), ArtifactType.Krt1);
                    break;
                case ArtifactType.Krt1:
                case ArtifactType.Krf1:
                    RequireRow(rows, record.FieldSpan(6), ArtifactType.Rrm1,
                        ArtifactType.Dpa1, ArtifactType.Krt1);
                    break;
                case ArtifactType.Dcm1:
                    RequireRow(rows, record.FieldSpan(5), ArtifactType.Dpa1);
                    RequireRow(rows, record.FieldSpan(9), ArtifactType.Drs1);
                    RequireOptionalRow(rows, record.FieldSpan(12), ArtifactType.Krt1);
                    break;
                case ArtifactType.Dra1:
                    RequireRow(rows, record.FieldSpan(3), ArtifactType.Dpa1);
                    RequireRow(rows, record.FieldSpan(10), ArtifactType.Dpa1);
                    RequireRow(rows, record.FieldSpan(12), ArtifactType.Dcm1);
                    break;
                case ArtifactType.Dwd1:
                    RequireOptionalRow(rows, record.FieldSpan(3), ArtifactType.Dwd1);
                    RequireRow(rows, record.FieldSpan(16), ArtifactType.Rrm1,
                        ArtifactType.Krt1, ArtifactType.Krf1);
                    break;
                case ArtifactType.Dwt1:
                    RequireRow(rows, record.FieldSpan(3), ArtifactType.Dwd1);
                    RequireRow(rows, record.FieldSpan(6), ArtifactType.Krf1);
                    RequireRow(rows, record.FieldSpan(8), ArtifactType.Krf1);
                    break;
                case ArtifactType.Dnr1:
                    RequireRow(rows, record.FieldSpan(3), ArtifactType.Dpm1);
                    RequireRow(rows, record.FieldSpan(4), ArtifactType.Pma1);
                    RequireRow(rows, record.FieldSpan(6), ArtifactType.Pmr1);
                    break;
                case ArtifactType.Mrl2:
                    RequireRow(rows, record.FieldSpan(5), ArtifactType.Dnr1);
                    RequireRow(rows, record.FieldSpan(9), ArtifactType.Dpc1);
                    break;
                case ArtifactType.Dpc1:
                    RequireRow(rows, record.FieldSpan(3), ArtifactType.Dnr1);
                    break;
                case ArtifactType.Rrm1:
                    break;
                default:
                    Invalid(RecordError.InvalidArtifactReference,
                        "A canonical DRM20 row has no closed adjacency rule.");
                    break;
            }
        }
        EnsureAcyclicSameType(rows, plaintext, ArtifactType.Krt1, 6);
        EnsureAcyclicSameType(rows, plaintext, ArtifactType.Dwd1, 3);
    }

    internal static void VerifyAuthorityPartitions(
        byte[] plaintext,
        RecoveryManifestRow[] rows,
        RecoveryManifestShape shape,
        bool verifyAuthenticatedRah)
    {
        var transitions = rows.Where(static row =>
            row.Reference.Type is ArtifactType.Krt1 or ArtifactType.Krf1).ToArray();
        var used = new HashSet<string>(StringComparer.Ordinal);
        var root = rows.Single(static row => row.Reference.Type == ArtifactType.Rrm1);
        ValidateChain(CanonicalGrammar.EncodeReference(root.Reference), KeyScope.ReleaseRoot,
            default, 0, allowRevocation: true, transitions, used, out _);

        var currentDpaReference = plaintext.AsSpan(10 + 26, 38);
        var currentDpaRow = FindRow(rows, currentDpaReference);
        if (currentDpaRow.Reference.Type != ArtifactType.Dpa1)
            Invalid(RecordError.InvalidArtifactReference,
                "The DRM20 current account reference is not DPA1.");
        var currentDpa = CanonicalGrammar.DecodeOwned(
            plaintext.AsSpan(currentDpaRow.CanonicalOffset, currentDpaRow.CanonicalLength),
            RecordDefinitions.Dpa1);
        var currentHash = ComputeAccountHash(currentDpa);
        var currentGeneration = Scalars.UInt64(currentDpa.FieldSpan(2));
        var currentChains = new Dictionary<KeyScope, HashSet<string>>();
        foreach (var scope in new[]
                 {
                     KeyScope.DeviceCertificateIssuer,
                     KeyScope.AccountRevocation,
                     KeyScope.ResetControl
                 })
        {
            var chain = ValidateChain(currentDpaReference, scope, currentHash,
                currentGeneration, allowRevocation: true, transitions, used, out _);
            currentChains.Add(scope, chain);
        }

        var rah = plaintext.AsSpan(shape.RahOffset, RahFixedLength);
        var draRows = rows.Where(static row => row.Reference.Type == ArtifactType.Dra1).ToArray();
        if ((rah[166] != 0) != (draRows.Length == 1))
            Invalid(RecordError.InvalidField,
                "RAH1 presence does not match the DRM20 historical-reset partition.");
        if (draRows.Length == 1)
        {
            var dra = CanonicalGrammar.DecodeOwned(
                plaintext.AsSpan(draRows[0].CanonicalOffset, draRows[0].CanonicalLength),
                RecordDefinitions.Dra1);
            var oldDpaReference = rah.Slice(213, 38);
            if (!CanonicalGrammar.FixedEquals(oldDpaReference, dra.FieldSpan(3)))
                Invalid(RecordError.InvalidArtifactReference,
                    "RAH1 and DRA1 identify different historical DPA1 rows.");
            var oldDpaRow = FindRow(rows, oldDpaReference);
            var oldDpa = CanonicalGrammar.DecodeOwned(
                plaintext.AsSpan(oldDpaRow.CanonicalOffset, oldDpaRow.CanonicalLength),
                RecordDefinitions.Dpa1);
            var oldHash = ComputeAccountHash(oldDpa);
            var oldGeneration = Scalars.UInt64(oldDpa.FieldSpan(2));
            if (oldGeneration != Scalars.UInt64(dra.FieldSpan(2)) ||
                oldGeneration != BinaryPrimitives.ReadUInt64BigEndian(rah[205..213]))
                Invalid(RecordError.InvalidTransition,
                    "RAH1/DRA1 historical account generation differs.");
            var historical = ValidateChain(oldDpaReference, KeyScope.ResetControl,
                oldHash, oldGeneration, allowRevocation: false, transitions, used,
                out var historicalHead);
            _ = historical;
            var expectedGeneration = historicalHead is null ? 0UL : historicalHead.Value.Generation;
            var expectedReference = historicalHead is null
                ? oldDpaReference.ToArray()
                : CanonicalGrammar.EncodeReference(historicalHead.Value.Row.Reference);
            var expectedPublic = historicalHead is null
                ? oldDpa.FieldSpan(8).ToArray()
                : historicalHead.Value.Record.FieldSpan(8).ToArray();
            if (verifyAuthenticatedRah &&
                (BinaryPrimitives.ReadUInt64BigEndian(rah[251..259]) != expectedGeneration ||
                !CanonicalGrammar.FixedEquals(rah.Slice(259, 38), expectedReference) ||
                !CanonicalGrammar.FixedEquals(rah.Slice(297, 32), expectedPublic) ||
                !CanonicalGrammar.FixedEquals(rah.Slice(329, 32), ComputeRoleKeyHash(
                    rah[..16], KeyScope.ResetControl, oldHash, oldGeneration, expectedPublic)) ||
                !CanonicalGrammar.FixedEquals(rah.Slice(329, 32), dra.FieldSpan(16))))
                Invalid(RecordError.InvalidField,
                    "RAH1 does not match the complete historical reset-control authority head.");
        }

        if (used.Count != transitions.Length)
            Invalid(RecordError.InvalidTransition,
                "A DRM20 key transition is outside the closed ReleaseRoot/current/historical partitions.");

        var dpd = rows.SingleOrDefault(static row => row.Reference.Type == ArtifactType.Dpd1);
        if (dpd.Reference.Type == ArtifactType.Dpd1)
            VerifyIssuedTransition(plaintext, dpd, 9, 10,
                KeyScope.DeviceCertificateIssuer, currentChains[KeyScope.DeviceCertificateIssuer]);
        var drs = rows.Single(static row => row.Reference.Type == ArtifactType.Drs1);
        VerifyIssuedTransition(plaintext, drs, 6, 7,
            KeyScope.AccountRevocation, currentChains[KeyScope.AccountRevocation]);
        var dcm = rows.Single(static row => row.Reference.Type == ArtifactType.Dcm1);
        VerifyIssuedTransition(plaintext, dcm, 10, 12,
            KeyScope.ResetControl, currentChains[KeyScope.ResetControl]);

        HashSet<string> ValidateChain(
            ReadOnlySpan<byte> startReference,
            KeyScope scope,
            ReadOnlySpan<byte> accountHash,
            ulong accountGeneration,
            bool allowRevocation,
            RecoveryManifestRow[] all,
            HashSet<string> globallyUsed,
            out ScopedTransition? head)
        {
            var candidates = new List<ScopedTransition>();
            foreach (var row in all)
            {
                var record = CanonicalGrammar.DecodeOwned(
                    plaintext.AsSpan(row.CanonicalOffset, row.CanonicalLength), Definition(row.Reference.Type));
                if ((KeyScope)record.FieldSpan(2)[0] != scope) continue;
                if (scope != KeyScope.ReleaseRoot &&
                    (!CanonicalGrammar.FixedEquals(record.FieldSpan(3), accountHash) ||
                     Scalars.UInt64(record.FieldSpan(4)) != accountGeneration))
                    continue;
                candidates.Add(new ScopedTransition(row, record,
                    Scalars.UInt64(record.FieldSpan(5))));
            }
            var local = new HashSet<string>(StringComparer.Ordinal);
            var predecessor = startReference.ToArray();
            head = null;
            for (ulong expected = 1; expected <= 64; expected++)
            {
                var successors = candidates.Where(value =>
                    CanonicalGrammar.FixedEquals(value.Record.FieldSpan(6), predecessor)).ToArray();
                if (successors.Length == 0) break;
                if (successors.Length != 1 || successors[0].Generation != expected)
                    Invalid(RecordError.InvalidTransition,
                        "A DRM20 scoped key chain forks or skips a generation.");
                var next = successors[0];
                if (next.Row.Reference.Type == ArtifactType.Krf1 && !allowRevocation)
                    Invalid(RecordError.InvalidTransition,
                        "A historical reset-authority chain contains a KRF1.");
                var key = Convert.ToHexString(CanonicalGrammar.EncodeReference(next.Row.Reference));
                if (!local.Add(key) || !globallyUsed.Add(key))
                    Invalid(RecordError.InvalidTransition,
                        "A DRM20 key transition belongs to multiple authority partitions.");
                head = next;
                predecessor = CanonicalGrammar.EncodeReference(next.Row.Reference);
                if (next.Row.Reference.Type == ArtifactType.Krf1) break;
            }
            if (candidates.Count != local.Count)
                Invalid(RecordError.InvalidTransition,
                    "A DRM20 scoped key chain is truncated, forked, or has a terminal successor.");
            return local;
        }

        void VerifyIssuedTransition(
            ReadOnlySpan<byte> source,
            RecoveryManifestRow row,
            int generationTag,
            int referenceTag,
            KeyScope expectedScope,
            HashSet<string> currentChain)
        {
            var record = CanonicalGrammar.DecodeOwned(
                source.Slice(row.CanonicalOffset, row.CanonicalLength), Definition(row.Reference.Type));
            var generation = Scalars.UInt64(record.FieldSpan(generationTag));
            var reference = CanonicalGrammar.DecodeReference(
                record.FieldSpan(referenceTag), allowZero: true);
            if (generation == 0)
            {
                if (!reference.IsZero)
                    Invalid(RecordError.InvalidTransition,
                        "A generation-zero role binding has a transition reference.");
                return;
            }
            if (reference.IsZero || reference.Type != ArtifactType.Krt1 ||
                !currentChain.Contains(Convert.ToHexString(CanonicalGrammar.EncodeReference(reference))))
                Invalid(RecordError.InvalidTransition,
                    "A role binding does not name its exact current nonterminal KRT1.");
            var transitionRow = FindRow(rows, CanonicalGrammar.EncodeReference(reference));
            var transition = CanonicalGrammar.DecodeOwned(
                source.Slice(transitionRow.CanonicalOffset, transitionRow.CanonicalLength),
                RecordDefinitions.Krt1);
            if ((KeyScope)transition.FieldSpan(2)[0] != expectedScope ||
                Scalars.UInt64(transition.FieldSpan(5)) != generation)
                Invalid(RecordError.InvalidTransition,
                    "A role binding generation or scope differs from its KRT1.");
        }
    }

    private static byte[] ComputeRoleKeyHash(
        ReadOnlySpan<byte> network,
        KeyScope scope,
        ReadOnlySpan<byte> accountHash,
        ulong accountGeneration,
        ReadOnlySpan<byte> publicKey)
    {
        Span<byte> payload = stackalloc byte[89];
        network.CopyTo(payload);
        payload[16] = (byte)scope;
        accountHash.CopyTo(payload[17..49]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[49..57], accountGeneration);
        publicKey.CopyTo(payload[57..89]);
        return CanonicalGrammar.Sha256Domain("Deep/IdentityAuth/V1/key-hash", payload);
    }

    private readonly record struct ScopedTransition(
        RecoveryManifestRow Row,
        OwnedRecord Record,
        ulong Generation);

    private static void EnsureAcyclicSameType(
        RecoveryManifestRow[] rows,
        ReadOnlySpan<byte> plaintext,
        ArtifactType type,
        int predecessorTag)
    {
        var byReference = rows.Where(row => row.Reference.Type == type).ToDictionary(
            row => Convert.ToHexString(CanonicalGrammar.EncodeReference(row.Reference)),
            StringComparer.Ordinal);
        foreach (var start in byReference.Values)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var current = start;
            while (true)
            {
                var key = Convert.ToHexString(CanonicalGrammar.EncodeReference(current.Reference));
                if (!seen.Add(key))
                    Invalid(RecordError.InvalidTransition, "A DRM20 predecessor chain is cyclic.");
                var record = CanonicalGrammar.DecodeOwned(
                    plaintext.Slice(current.CanonicalOffset, current.CanonicalLength), Definition(type));
                var predecessor = CanonicalGrammar.DecodeReference(
                    record.FieldSpan(predecessorTag), allowZero: true);
                if (predecessor.IsZero || predecessor.Type != type ||
                    !byReference.TryGetValue(
                        Convert.ToHexString(CanonicalGrammar.EncodeReference(predecessor)), out current))
                    break;
            }
        }
    }

    private static void RequireOptionalRow(
        RecoveryManifestRow[] rows,
        ReadOnlySpan<byte> reference,
        params ArtifactType[] allowed)
    {
        var decoded = CanonicalGrammar.DecodeReference(reference, allowZero: true);
        if (decoded.IsZero) return;
        RequireRow(rows, reference, allowed);
    }

    private static void RequireRow(
        RecoveryManifestRow[] rows,
        ReadOnlySpan<byte> reference,
        params ArtifactType[] allowed)
    {
        var row = FindRow(rows, reference);
        if (!allowed.Contains(row.Reference.Type))
            Invalid(RecordError.InvalidArtifactReference,
                "A DRM20 reference crosses its closed adjacency class.");
    }

    private static void VerifyDrtCatalog(
        ReadOnlySpan<byte> plaintext,
        RecoveryManifestRow[] rows,
        OwnedRecord drs,
        RecoveryManifestShape shape)
    {
        var entries = drs.FieldSpan(10);
        var dtc = plaintext.Slice(shape.DtcOffset, shape.DtcLength);
        var historyCount = BinaryPrimitives.ReadUInt16BigEndian(dtc.Slice(168, 2));
        var historyOffset = 170 + shape.DtcCount * DrtEntryLength;
        var usedHistory = new bool[historyCount];
        var seenTargets = new HashSet<string>(StringComparer.Ordinal);
        var seenSubjects = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < shape.DtcCount; index++)
        {
            var catalog = dtc.Slice(170 + index * DrtEntryLength, DrtEntryLength);
            var row = entries.Slice(index * 62, 62);
            if (!CanonicalGrammar.FixedEquals(row.Slice(1, 38), catalog[..38]) ||
                row[0] != catalog[255] ||
                BinaryPrimitives.ReadUInt64BigEndian(row[39..47]) !=
                    BinaryPrimitives.ReadUInt64BigEndian(catalog[320..328]))
                Invalid(RecordError.InvalidArtifactReference, "DTC2 is not in exact DRS1 order.");
            var drt = CanonicalGrammar.DecodeOwned(catalog.Slice(38, 179), RecordDefinitions.Drt1);
            var drtRef = CanonicalGrammar.EncodeReference(
                CanonicalGrammar.ComputeReference(ArtifactType.Drt1, drt.CanonicalSpan));
            if (!CanonicalGrammar.FixedEquals(catalog[..38], drtRef) ||
                drt.FieldSpan(2)[0] != catalog[255] || drt.FieldSpan(2)[0] != row[0] ||
                !CanonicalGrammar.FixedEquals(drt.FieldSpan(1), catalog.Slice(256, 32)) ||
                !CanonicalGrammar.FixedEquals(drt.FieldSpan(1), drs.FieldSpan(2)) ||
                !CanonicalGrammar.FixedEquals(drt.FieldSpan(3), catalog.Slice(328, 32)) ||
                !CanonicalGrammar.FixedEquals(drt.FieldSpan(5), catalog.Slice(217, 38)) ||
                Scalars.UInt64(drt.FieldSpan(4)) != BinaryPrimitives.ReadUInt64BigEndian(catalog[320..328]) ||
                Scalars.UInt64(drt.FieldSpan(6)) != BinaryPrimitives.ReadUInt64BigEndian(catalog[360..368]))
                Invalid(RecordError.InvalidField, "A DTC2 target fact differs from its exact DRT1.");
            var ordinal = BinaryPrimitives.ReadUInt16BigEndian(catalog.Slice(368, 2));
            if (catalog[255] == (byte)RevocationTargetKind.AccountTerminal)
            {
                var targetRow = FindRow(rows, catalog.Slice(217, 38));
                if (targetRow.Reference.Type != ArtifactType.Dpa1)
                    Invalid(RecordError.InvalidArtifactReference,
                        "A terminal DTC2 target is not the active DPA1.");
                var targetBytes = plaintext.Slice(targetRow.CanonicalOffset, targetRow.CanonicalLength);
                var target = CanonicalGrammar.DecodeOwned(targetBytes, RecordDefinitions.Dpa1);
                var targetSubject = ComputeTargetSubject(target, catalog[255]);
                if (ordinal != 0 ||
                    !CanonicalGrammar.FixedEquals(targetSubject, catalog.Slice(288, 32)))
                    Invalid(RecordError.InvalidField, "The terminal DTC2 target subject is invalid.");
                VerifyTargetFact(target, catalog);
            }
            else
            {
                if (ordinal == 0 || ordinal > historyCount)
                    Invalid(RecordError.InvalidField, "A protected DTC2 target history is absent.");
                var history = dtc.Slice(historyOffset + (ordinal - 1) * DrtHistoryEntryLength,
                    DrtHistoryEntryLength);
                VerifyProtectedHistory(plaintext, rows, drs, row, catalog, history, index);
                usedHistory[ordinal - 1] = true;
            }
            if (!seenTargets.Add(Convert.ToHexString(catalog.Slice(217, 38))) ||
                !seenSubjects.Add(Convert.ToHexString(catalog.Slice(288, 32))))
                Invalid(RecordError.InvalidField, "DTC2 repeats a target or protected target fact.");
        }
        if (usedHistory.Any(static used => !used))
            Invalid(RecordError.InvalidField, "DTC2 contains an unused protected history row.");
    }

    private static void VerifyProtectedHistory(ReadOnlySpan<byte> plaintext,
        RecoveryManifestRow[] rows, OwnedRecord currentDrs, ReadOnlySpan<byte> currentEntry,
        ReadOnlySpan<byte> catalog, ReadOnlySpan<byte> history, int currentIndex)
    {
        var currentRef = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Drs1, currentDrs.CanonicalSpan));
        var historyRevision = BinaryPrimitives.ReadUInt64BigEndian(history.Slice(38, 8));
        var historyCount = BinaryPrimitives.ReadUInt64BigEndian(history.Slice(46, 8));
        var currentRevision = Scalars.UInt64(currentDrs.FieldSpan(4));
        var currentCount = (ulong)Scalars.UInt16(currentDrs.FieldSpan(9));
        if (CanonicalGrammar.FixedEquals(history[..38], currentRef) ||
            historyRevision == 0 || historyRevision >= currentRevision ||
            historyCount > currentCount || historyCount > checked((ulong)currentIndex) ||
            !CanonicalGrammar.FixedEquals(history.Slice(54, 32),
                RecomputeDrsPrefixHead(currentDrs, checked((int)historyCount))))
            Invalid(RecordError.InvalidField,
                "A protected DTC2 target is not bound to an older exact DRS prefix.");

        var historyIssuedAt = BinaryPrimitives.ReadUInt64BigEndian(history.Slice(86, 8));
        var revokedAt = BinaryPrimitives.ReadUInt64BigEndian(currentEntry.Slice(47, 8));
        var currentIssuedAt = Scalars.UInt64(currentDrs.FieldSpan(5));
        if (historyIssuedAt == 0 || historyIssuedAt > revokedAt || revokedAt > currentIssuedAt)
            Invalid(RecordError.InvalidField, "A protected DTC2 history chronology is invalid.");

        var generation = BinaryPrimitives.ReadUInt64BigEndian(history.Slice(94, 8));
        ReadOnlySpan<byte> publicKey;
        if (generation == 0)
        {
            if (!CanonicalGrammar.IsZero(history.Slice(102, 38)))
                Invalid(RecordError.InvalidTransition,
                    "A generation-zero DTC2 history has a transition reference.");
            var dpaRow = FindRow(rows, plaintext.Slice(36, ArtifactReference.Length));
            if (dpaRow.Reference.Type != ArtifactType.Dpa1)
                Invalid(RecordError.InvalidArtifactReference, "The active DPA1 is absent.");
            var dpa = CanonicalGrammar.DecodeOwned(
                plaintext.Slice(dpaRow.CanonicalOffset, dpaRow.CanonicalLength), RecordDefinitions.Dpa1);
            publicKey = dpa.FieldSpan(7);
        }
        else
        {
            var transitionRow = FindRow(rows, history.Slice(102, 38));
            if (transitionRow.Reference.Type != ArtifactType.Krt1)
                Invalid(RecordError.InvalidTransition,
                    "A DTC2 history transition is not nonterminal KRT1.");
            var transition = CanonicalGrammar.DecodeOwned(
                plaintext.Slice(transitionRow.CanonicalOffset, transitionRow.CanonicalLength),
                RecordDefinitions.Krt1);
            if (transition.FieldSpan(2)[0] != (byte)KeyScope.AccountRevocation ||
                Scalars.UInt64(transition.FieldSpan(5)) != generation ||
                !CanonicalGrammar.FixedEquals(transition.FieldSpan(1), currentDrs.FieldSpan(1)) ||
                !CanonicalGrammar.FixedEquals(transition.FieldSpan(3), currentDrs.FieldSpan(2)) ||
                !CanonicalGrammar.FixedEquals(transition.FieldSpan(4), currentDrs.FieldSpan(3)))
                Invalid(RecordError.InvalidTransition,
                    "A DTC2 history transition crosses its scope-3 identity.");
            publicKey = transition.FieldSpan(8);
        }
        var keyHash = ComputeRoleKeyHash(currentDrs.FieldSpan(1), KeyScope.AccountRevocation,
            currentDrs.FieldSpan(2), Scalars.UInt64(currentDrs.FieldSpan(3)), publicKey);
        if (!CanonicalGrammar.FixedEquals(history.Slice(140, 32), keyHash) ||
            !CanonicalGrammar.FixedEquals(catalog.Slice(256, 32), currentDrs.FieldSpan(2)) ||
            (catalog[255] != (byte)RevocationTargetKind.DeviceCertificate &&
                catalog[255] != (byte)RevocationTargetKind.MailboxRoleCertificate))
            Invalid(RecordError.InvalidField,
                "A protected DTC2 target crosses its account, kind, or revocation authority.");
    }

    private static byte[] RecomputeDrsPrefixHead(OwnedRecord current, int count)
    {
        if (count < 0 || count > Scalars.UInt16(current.FieldSpan(9)))
            Invalid(RecordError.InvalidField, "The DTC2 history prefix count is invalid.");
        var head = new byte[32]; var payload = new byte[158];
        current.FieldSpan(1).CopyTo(payload); current.FieldSpan(2).CopyTo(payload.AsSpan(16));
        current.FieldSpan(3).CopyTo(payload.AsSpan(48));
        for (var index = 0; index < count; index++)
        {
            payload.AsSpan(56).Clear();
            BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(56, 8), checked((ulong)index));
            head.CopyTo(payload, 64);
            current.FieldSpan(10).Slice(index * 62, 62).CopyTo(payload.AsSpan(96));
            head = CanonicalGrammar.Sha256Domain(
                "Deep/IdentityAuth/V1/revocation-entry-head", payload);
        }
        return head;
    }

    private static void VerifyFrontier(
        ReadOnlySpan<byte> plaintext,
        RecoveryManifestRow[] rows,
        RecoveryManifestShape shape)
    {
        var rfc = plaintext.Slice(shape.RfcOffset, shape.RfcLength);
        var rpf = plaintext.Slice(shape.RpfOffset, shape.RpfLength);
        if (shape.RfcCount != shape.RpfCount)
            Invalid(RecordError.InvalidField, "RFC1 and RPF1 frontier counts differ.");
        for (var index = 0; index < shape.RpfCount; index++)
        {
            var rpfEntry = rpf.Slice(8 + index * RpfEntryLength, RpfEntryLength);
            var kind = BinaryPrimitives.ReadUInt16BigEndian(rpfEntry[38..40]);
            var successor = FindRow(rows, rpfEntry[..38]);
            var canonical = plaintext.Slice(successor.CanonicalOffset, successor.CanonicalLength);
            var record = CanonicalGrammar.DecodeOwned(canonical, Definition(successor.Reference.Type));
            var actual = PredecessorField(record, kind);
            if (!CanonicalGrammar.FixedEquals(actual, rpfEntry.Slice(40, 38)))
                Invalid(RecordError.InvalidArtifactReference, "RPF1 differs from the successor predecessor field.");
            var subject = ComputeFrontierSubject(plaintext, rows, record, kind);
            var match = -1;
            for (var rfcIndex = 0; rfcIndex < shape.RfcCount; rfcIndex++)
            {
                var rfcEntry = rfc.Slice(168 + rfcIndex * RfcEntryLength, RfcEntryLength);
                if (BinaryPrimitives.ReadUInt16BigEndian(rfcEntry) != kind ||
                    !CanonicalGrammar.FixedEquals(rfcEntry.Slice(2, 32), subject)) continue;
                if (match >= 0) Invalid(RecordError.InvalidField, "RFC1 repeats a typed subject slot.");
                match = rfcIndex;
                if (!CanonicalGrammar.FixedEquals(rfcEntry.Slice(34, 38), rpfEntry.Slice(40, 38)))
                    Invalid(RecordError.InvalidArtifactReference, "RFC1 and RPF1 predecessor facts differ.");
            }
            if (match < 0) Invalid(RecordError.InvalidField, "RFC1 omits an RPF1 typed subject slot.");
        }
        var expectedSlots = 0;
        foreach (var row in rows)
        {
            if (!TryPredecessorSlots(row.Reference.Type, out var kinds)) continue;
            var record = CanonicalGrammar.DecodeOwned(
                plaintext.Slice(row.CanonicalOffset, row.CanonicalLength), Definition(row.Reference.Type));
            foreach (var kind in kinds)
            {
                var predecessor = PredecessorField(record, kind);
                var decoded = CanonicalGrammar.DecodeReference(predecessor, allowZero: true);
                if (decoded.IsZero) continue;
                expectedSlots++;
                var successor = CanonicalGrammar.EncodeReference(row.Reference);
                var found = 0;
                for (var index = 0; index < shape.RpfCount; index++)
                {
                    var entry = rpf.Slice(8 + index * RpfEntryLength, RpfEntryLength);
                    if (BinaryPrimitives.ReadUInt16BigEndian(entry[38..40]) == kind &&
                        CanonicalGrammar.FixedEquals(entry[..38], successor)) found++;
                }
                if (found != 1)
                    Invalid(RecordError.InvalidField,
                        "A nonzero predecessor field has no exact RPF1 slot.");
            }
        }
        if (expectedSlots != shape.RpfCount)
            Invalid(RecordError.InvalidField, "RPF1 contains an extra predecessor slot.");
    }

    private static ReadOnlySpan<byte> PredecessorField(OwnedRecord record, ushort kind) => kind switch
    {
        1 => record.FieldSpan(4), 2 => record.FieldSpan(13), 3 => record.FieldSpan(4),
        4 => record.FieldSpan(5), 5 => record.FieldSpan(6), 6 => record.FieldSpan(20),
        7 => record.FieldSpan(17), 8 => record.FieldSpan(18), 9 => record.FieldSpan(12),
        10 => record.FieldSpan(5), _ => throw new UnreachableException()
    };

    private static byte[] ComputeFrontierSubject(
        ReadOnlySpan<byte> plaintext,
        RecoveryManifestRow[] rows,
        OwnedRecord record,
        ushort kind)
    {
        var domain = kind switch
        {
            1 => "DPA", 2 => "DCM", 3 or 4 or 5 => "DRA", 6 => "DPD", 7 => "DPM",
            8 => "DNR", 9 => "MRL", 10 => "DPC", _ => throw new UnreachableException()
        };
        using var stream = new MemoryStream();
        void Add(ReadOnlySpan<byte> value) => stream.Write(value);
        switch (kind)
        {
            case 1:
                Add(record.FieldSpan(1)); Add(ComputeAccountHash(record)); Add(record.FieldSpan(2)); break;
            case 2:
            {
                var account = ResolveRow(plaintext, rows, record.FieldSpan(5), ArtifactType.Dpa1);
                Add(record.FieldSpan(1)); Add(ComputeAccountHash(account)); Add(record.FieldSpan(4)); break;
            }
            case 3 or 4 or 5:
                // The old account bytes are intentionally outside DRM20. RFC1 is the protected
                // source of this subject after old-store loss; all three DRA slots must agree.
                return FindProtectedDraSubject(record, kind, plaintext, rows);
            case 6: Add(record.FieldSpan(1)); Add(record.FieldSpan(2)); Add(record.FieldSpan(3)); Add(record.FieldSpan(4)); Add(record.FieldSpan(5)); break;
            case 7: Add(record.FieldSpan(1)); Add(record.FieldSpan(2)); Add(record.FieldSpan(3)); Add(record.FieldSpan(6)); Add(record.FieldSpan(4)); Add(record.FieldSpan(7)); break;
            case 8: Add(record.FieldSpan(1)); Add(record.FieldSpan(2)); Add(record.FieldSpan(9)); Add(record.FieldSpan(10)); break;
            case 9: Add(record.FieldSpan(1)); Add(record.FieldSpan(4)); Add(record.FieldSpan(3)); break;
            case 10: Add(record.FieldSpan(1)); Add(record.FieldSpan(2)); Add(record.FieldSpan(4)); break;
        }
        return CanonicalGrammar.Sha256Domain(
            $"Deep/Cutover/V1/recovery-frontier-subject/{domain}", stream.ToArray());
    }

    private static byte[] FindProtectedDraSubject(
        OwnedRecord record,
        ushort kind,
        ReadOnlySpan<byte> plaintext,
        RecoveryManifestRow[] rows)
    {
        _ = record;
        _ = rows;
        var shape = Preflight(plaintext, BinaryPrimitives.ReadUInt16BigEndian(plaintext[6..8]));
        var rfc = plaintext.Slice(shape.RfcOffset, shape.RfcLength);
        byte[]? subject = null;
        for (var index = 0; index < shape.RfcCount; index++)
        {
            var entry = rfc.Slice(168 + index * RfcEntryLength, RfcEntryLength);
            var entryKind = BinaryPrimitives.ReadUInt16BigEndian(entry);
            if (entryKind is not (3 or 4 or 5)) continue;
            if (entryKind == kind) subject = entry.Slice(2, 32).ToArray();
        }
        if (subject is null)
            Invalid(RecordError.InvalidField, "RFC1 omits a DRA predecessor subject.");
        for (var index = 0; index < shape.RfcCount; index++)
        {
            var entry = rfc.Slice(168 + index * RfcEntryLength, RfcEntryLength);
            var entryKind = BinaryPrimitives.ReadUInt16BigEndian(entry);
            if (entryKind is 3 or 4 or 5 && !CanonicalGrammar.FixedEquals(entry.Slice(2, 32), subject))
                Invalid(RecordError.InvalidField, "The three DRA frontier kinds use different subjects.");
        }
        return subject!;
    }

    private static byte[] ComputeTargetSubject(OwnedRecord target, byte kind)
    {
        using var stream = new MemoryStream();
        void Add(ReadOnlySpan<byte> value) => stream.Write(value);
        string suffix;
        switch (kind)
        {
            case 1:
                suffix = "DPD"; Add(target.FieldSpan(1)); Add(target.FieldSpan(2));
                Add(target.FieldSpan(3)); Add(target.FieldSpan(4)); Add(target.FieldSpan(5)); break;
            case 2:
                suffix = "DPM"; Add(target.FieldSpan(1)); Add(target.FieldSpan(2));
                Add(target.FieldSpan(3)); Add(target.FieldSpan(4)); Add(target.FieldSpan(6)); Add(target.FieldSpan(7)); break;
            case 3:
                suffix = "DPA"; Add(target.FieldSpan(1)); Add(ComputeAccountHash(target)); Add(target.FieldSpan(2)); break;
            default: throw new UnreachableException();
        }
        return CanonicalGrammar.Sha256Domain(
            $"Deep/Cutover/V1/recovery-target-subject/{suffix}", stream.ToArray());
    }

    private static void VerifyTargetFact(OwnedRecord target, ReadOnlySpan<byte> catalog)
    {
        var kind = catalog[255];
        ReadOnlySpan<byte> account;
        ReadOnlySpan<byte> handle;
        ulong generation;
        ulong notAfter;
        switch (kind)
        {
            case 1:
                account = target.FieldSpan(2); handle = target.FieldSpan(8);
                generation = Scalars.UInt64(target.FieldSpan(5));
                notAfter = Scalars.UInt64(target.FieldSpan(17)); break;
            case 2:
                account = target.FieldSpan(2); handle = target.FieldSpan(9);
                generation = Scalars.UInt64(target.FieldSpan(7));
                notAfter = Scalars.UInt64(target.FieldSpan(15)); break;
            case 3:
                account = ComputeAccountHash(target); handle = target.FieldSpan(9);
                generation = Scalars.UInt64(target.FieldSpan(2)); notAfter = 0; break;
            default: throw new UnreachableException();
        }
        if (!CanonicalGrammar.FixedEquals(account, catalog.Slice(256, 32)) ||
            !CanonicalGrammar.FixedEquals(handle, catalog.Slice(328, 32)) ||
            generation != BinaryPrimitives.ReadUInt64BigEndian(catalog[320..328]) ||
            notAfter != BinaryPrimitives.ReadUInt64BigEndian(catalog[360..368]))
            Invalid(RecordError.InvalidField, "DTC2 target facts differ from the protected certificate.");
    }

    private static byte[] ComputeAccountHash(OwnedRecord account)
    {
        Span<byte> payload = stackalloc byte[56];
        account.FieldSpan(1).CopyTo(payload);
        account.FieldSpan(2).CopyTo(payload[16..]);
        account.FieldSpan(5).CopyTo(payload[24..]);
        return CanonicalGrammar.Sha256Domain("Deep/IdentityAuth/V1/account-id", payload);
    }

    private static OwnedRecord ResolveRow(
        ReadOnlySpan<byte> plaintext,
        RecoveryManifestRow[] rows,
        ReadOnlySpan<byte> reference,
        ArtifactType type)
    {
        var row = FindRow(rows, reference);
        if (row.Reference.Type != type)
            Invalid(RecordError.InvalidArtifactReference, "A DRM20 row has the wrong linked type.");
        return CanonicalGrammar.DecodeOwned(
            plaintext.Slice(row.CanonicalOffset, row.CanonicalLength), Definition(type));
    }

    private static bool TryPredecessorSlots(ArtifactType type, out ushort[] kinds)
    {
        kinds = type switch
        {
            ArtifactType.Dpa1 => [1], ArtifactType.Dcm1 => [2],
            ArtifactType.Dra1 => [3, 4, 5], ArtifactType.Dpd1 => [6],
            ArtifactType.Dpm1 => [7], ArtifactType.Dnr1 => [8],
            ArtifactType.Mrl2 => [9], ArtifactType.Dpc1 => [10], _ => []
        };
        return kinds.Length != 0;
    }

    private static RecoveryManifestRow FindRow(RecoveryManifestRow[] rows, ReadOnlySpan<byte> reference)
    {
        foreach (var row in rows)
            if (CanonicalGrammar.FixedEquals(CanonicalGrammar.EncodeReference(row.Reference), reference))
                return row;
        Invalid(RecordError.InvalidArtifactReference, "RPF1 successor is absent from DRM20 rows.");
        return default;
    }

    private static void VerifyCanonicalReference(ArtifactType type, ReadOnlySpan<byte> rowKey, ReadOnlySpan<byte> canonical)
    {
        byte[] hash;
        if (ArtifactRegistry.IsRetained(type)) hash = SHA256.HashData(canonical);
        else
        {
            var definition = Definition(type);
            CanonicalGrammar.Preflight(canonical, definition);
            hash = CanonicalGrammar.ComputeReference(type, canonical).CanonicalHash.ToArray();
        }
        if (!CryptographicOperations.FixedTimeEquals(hash, rowKey[6..38]))
            Invalid(RecordError.InvalidArtifactReference,
                "A DRM20 artifact does not reproduce its row reference.");
    }

    private static bool IsAllowed(ArtifactType type) => ComponentTypes.Contains(type) ||
        type is ArtifactType.Rrm1 or ArtifactType.Krt1 or ArtifactType.Krf1 or
        ArtifactType.Dwd1 or ArtifactType.Dwt1;

    private static void Require(Dictionary<ArtifactType, int> counts, ArtifactType type, int exact)
    {
        if (counts.GetValueOrDefault(type) != exact)
            Invalid(RecordError.InvalidField, $"DRM20 requires exactly {exact} {type} row(s).");
    }

    private static RecoveryFrontierEntry[] DescribeRfc(byte[] plaintext, int offset, int count) =>
        Enumerable.Range(0, count).Select(index =>
        {
            var entry = offset + 168 + index * RfcEntryLength;
            return new RecoveryFrontierEntry(
                BinaryPrimitives.ReadUInt16BigEndian(plaintext.AsSpan(entry, 2)), entry + 2, entry + 34);
        }).ToArray();

    private static RecoveryPredecessorEntry[] DescribeRpf(byte[] plaintext, int offset, int count) =>
        Enumerable.Range(0, count).Select(index =>
        {
            var entry = offset + 8 + index * RpfEntryLength;
            return new RecoveryPredecessorEntry(
                entry, BinaryPrimitives.ReadUInt16BigEndian(plaintext.AsSpan(entry + 38, 2)), entry + 40);
        }).ToArray();

    private static RecoveryDrtEntry[] DescribeDtc(int offset, int count) =>
        Enumerable.Range(0, count).Select(index =>
            new RecoveryDrtEntry(offset + 170 + index * DrtEntryLength)).ToArray();

    internal static RecordDefinition Definition(ArtifactType type) => type switch
    {
        ArtifactType.Dpa1 => RecordDefinitions.Dpa1, ArtifactType.Dpd1 => RecordDefinitions.Dpd1,
        ArtifactType.Dpm1 => RecordDefinitions.Dpm1, ArtifactType.Drs1 => RecordDefinitions.Drs1,
        ArtifactType.Krt1 => RecordDefinitions.Krt1, ArtifactType.Krf1 => RecordDefinitions.Krf1,
        ArtifactType.Dcm1 => RecordDefinitions.Dcm1, ArtifactType.Dra1 => RecordDefinitions.Dra1,
        ArtifactType.Dnr1 => RecordDefinitions.Dnr1, ArtifactType.Mrl2 => RecordDefinitions.Mrl2,
        ArtifactType.Dpc1 => RecordDefinitions.Dpc1, ArtifactType.Dwd1 => RecordDefinitions.Dwd1,
        ArtifactType.Rrm1 => RecordDefinitions.Rrm1, ArtifactType.Dwt1 => RecordDefinitions.Dwt1,
        _ => throw new RecordException(RecordError.InvalidArtifactReference,
            "The artifact type is not a canonical DNP row in DRM20.")
    };

    private static ArtifactType SuccessorType(ushort kind) => kind switch
    {
        1 => ArtifactType.Dpa1, 2 => ArtifactType.Dcm1,
        3 or 4 or 5 => ArtifactType.Dra1, 6 => ArtifactType.Dpd1,
        7 => ArtifactType.Dpm1, 8 => ArtifactType.Dnr1,
        9 => ArtifactType.Mrl2, 10 => ArtifactType.Dpc1,
        _ => throw new RecordException(RecordError.InvalidField, "Unknown recovery frontier kind.")
    };

    private static ArtifactType PredecessorType(ushort kind) => kind switch
    {
        1 or 3 => ArtifactType.Dpa1, 2 or 4 => ArtifactType.Dcm1,
        5 => ArtifactType.Drs1, 6 => ArtifactType.Dpd1,
        7 => ArtifactType.Dpm1, 8 => ArtifactType.Dnr1,
        9 => ArtifactType.Mrl2, 10 => ArtifactType.Dpc1,
        _ => throw new RecordException(RecordError.InvalidField, "Unknown recovery frontier kind.")
    };

    private static ArtifactType TargetType(byte kind) => kind switch
    {
        1 => ArtifactType.Dpd1, 2 => ArtifactType.Dpm1, 3 => ArtifactType.Dpa1,
        _ => throw new RecordException(RecordError.InvalidField, "Unknown recovery target kind.")
    };

    private static void Reference(ReadOnlySpan<byte> bytes, ArtifactType type, bool allowZero, string name)
    {
        var value = CanonicalGrammar.DecodeReference(bytes, allowZero);
        if (!value.IsZero && value.Type != type)
            Invalid(RecordError.InvalidArtifactReference, $"The {name} reference type is invalid.");
    }

    private static void Invalid(RecordError error, string message) =>
        throw new RecordException(error, message);
}

internal readonly record struct RecoveryManifestShape(
    int RfcOffset, int RfcLength, int RfcCount,
    int RpfOffset, int RpfLength, int RpfCount,
    int RahOffset,
    int DtcOffset, int DtcLength, int DtcCount, int DtcHistoryCount,
    int DwhOffset, int DwhLength, int DwhCount,
    int RowsOffset);
