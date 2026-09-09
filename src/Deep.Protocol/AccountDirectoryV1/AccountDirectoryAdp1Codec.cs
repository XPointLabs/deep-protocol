using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryAdp1FormatException(string message) : FormatException(message);

public enum AccountDirectoryAdp1ResultKind : byte
{
    CurrentValue = 1,
    NonMembership = 2,
}

public enum AccountDirectoryAdp1HistoryMode : byte
{
    ConsistencyOrGenesis = 0,
    ForwardCheckpoint = 1,
}

public sealed class AccountDirectoryTransition
{
    private readonly byte[] leafKey;
    private readonly byte[] previousAdc1Reference;
    private readonly byte[] nextAdc1Reference;
    private readonly byte[] previousMapRoot;
    private readonly byte[] nextMapRoot;

    internal AccountDirectoryTransition(
        ulong logIndex,
        ReadOnlySpan<byte> leafKey,
        ReadOnlySpan<byte> previousAdc1Reference,
        ReadOnlySpan<byte> nextAdc1Reference,
        ReadOnlySpan<byte> previousMapRoot,
        ReadOnlySpan<byte> nextMapRoot)
    {
        LogIndex = logIndex;
        this.leafKey = leafKey.ToArray();
        this.previousAdc1Reference = previousAdc1Reference.ToArray();
        this.nextAdc1Reference = nextAdc1Reference.ToArray();
        this.previousMapRoot = previousMapRoot.ToArray();
        this.nextMapRoot = nextMapRoot.ToArray();
    }

    public ulong LogIndex { get; }
    public ReadOnlyMemory<byte> DirectoryLeafKey => leafKey.ToArray();
    public ReadOnlyMemory<byte> PreviousAdc1Reference => previousAdc1Reference.ToArray();
    public ReadOnlyMemory<byte> NextAdc1Reference => nextAdc1Reference.ToArray();
    public ReadOnlyMemory<byte> PreviousMapRoot => previousMapRoot.ToArray();
    public ReadOnlyMemory<byte> NextMapRoot => nextMapRoot.ToArray();
}

public static class AccountDirectoryTransitionCodec
{
    public const int CanonicalLength = 182;
    public const ushort Version = 1;

    public static AccountDirectoryTransition Decode(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length != CanonicalLength || BinaryPrimitives.ReadUInt16BigEndian(canonical) != Version)
            throw new AccountDirectoryAdp1FormatException("Directory transition length/version is invalid.");
        var previous = canonical.Slice(42, 38);
        var next = canonical.Slice(80, 38);
        ValidateAdcReference(previous, allowZero: true);
        ValidateAdcReference(next, allowZero: false);
        if (IsZero(canonical.Slice(10, 32)) || IsZero(canonical.Slice(118, 32)) || IsZero(canonical.Slice(150, 32)))
            throw new AccountDirectoryAdp1FormatException("Directory transition contains a zero required key/root.");
        return new AccountDirectoryTransition(
            BinaryPrimitives.ReadUInt64BigEndian(canonical[2..10]), canonical[10..42], previous,
            next, canonical[118..150], canonical[150..182]);
    }

    public static byte[] Encode(AccountDirectoryTransition value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var result = new byte[CanonicalLength];
        BinaryPrimitives.WriteUInt16BigEndian(result, Version);
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(2), value.LogIndex);
        value.DirectoryLeafKey.Span.CopyTo(result.AsSpan(10));
        value.PreviousAdc1Reference.Span.CopyTo(result.AsSpan(42));
        value.NextAdc1Reference.Span.CopyTo(result.AsSpan(80));
        value.PreviousMapRoot.Span.CopyTo(result.AsSpan(118));
        value.NextMapRoot.Span.CopyTo(result.AsSpan(150));
        _ = Decode(result);
        return result;
    }

    internal static void ValidateAdcReference(ReadOnlySpan<byte> value, bool allowZero)
    {
        if (allowZero && IsZero(value)) return;
        if (value.Length != 38 || !value[..4].SequenceEqual(ProtocolMagicBytes.ADC1) ||
            BinaryPrimitives.ReadUInt16BigEndian(value[4..6]) != 1 || IsZero(value[6..]))
            throw new AccountDirectoryAdp1FormatException("Directory transition has an invalid ADC1 artifact reference.");
    }

    private static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;
}

public sealed class AccountDirectoryAdp1CurrentValue
{
    private readonly byte[] didHash;
    private readonly byte[] didAddressPublicKey;
    private readonly byte[] transitionBytes;
    private readonly ReadOnlyMemory<byte>[] dpdRecords;
    private readonly ReadOnlyMemory<byte>[] inclusionNodes;

    internal AccountDirectoryAdp1CurrentValue(
        AccountDirectoryAdc1 adc1,
        ParsedDab1 dab1,
        AccountCertificate dpa1,
        RevocationSnapshot drs1,
        ParsedDmd1 dmd1,
        DeviceCertificate[] devices,
        ReadOnlyMemory<byte>[] dpdRecords,
        ReadOnlySpan<byte> didHash,
        ReadOnlySpan<byte> didAddressPublicKey,
        ReadOnlySpan<byte> transitionBytes,
        AccountDirectoryTransition transition,
        ulong appendLogIndex,
        ReadOnlyMemory<byte>[] inclusionNodes)
    {
        Adc1 = adc1; Dab1 = dab1; Dpa1 = dpa1; Drs1 = drs1; Dmd1 = dmd1;
        Devices = Array.AsReadOnly(devices.ToArray());
        this.dpdRecords = CopyNodes(dpdRecords);
        this.didHash = didHash.ToArray();
        this.didAddressPublicKey = didAddressPublicKey.ToArray();
        this.transitionBytes = transitionBytes.ToArray();
        Transition = transition; AppendLogIndex = appendLogIndex;
        this.inclusionNodes = CopyNodes(inclusionNodes);
    }

    public AccountDirectoryAdc1 Adc1 { get; }
    public ParsedDab1 Dab1 { get; }
    public AccountCertificate Dpa1 { get; }
    public RevocationSnapshot Drs1 { get; }
    public ParsedDmd1 Dmd1 { get; }
    public IReadOnlyList<DeviceCertificate> Devices { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactDpd1Records => CopyNodes(dpdRecords);
    public ReadOnlyMemory<byte> ExactDid1Hash => didHash.ToArray();
    public ReadOnlyMemory<byte> Did1AddressPublicKey => didAddressPublicKey.ToArray();
    public ReadOnlyMemory<byte> ExactTransitionBytes => transitionBytes.ToArray();
    public AccountDirectoryTransition Transition { get; }
    public ulong AppendLogIndex { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> InclusionProofNodes => CopyNodes(inclusionNodes);

    private static ReadOnlyMemory<byte>[] CopyNodes(IEnumerable<ReadOnlyMemory<byte>> values) =>
        values.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
}

public sealed class AccountDirectoryAdp1
{
    private readonly byte[] canonical;
    private readonly byte[] networkId;
    private readonly byte[] queriedLeafKey;
    private readonly byte[] callerLkgAdh1CoreHash;
    private readonly byte[] sparseBitmap;
    private readonly byte[] exactAfp1;
    private readonly byte[] liveDtt1CoreHash;
    private readonly ReadOnlyMemory<byte>[] consistencyNodes;
    private readonly ReadOnlyMemory<byte>[] sparseSiblings;

    internal AccountDirectoryAdp1(
        byte[] canonical,
        ReadOnlySpan<byte> networkId,
        AccountDirectoryAdp1ResultKind resultKind,
        ReadOnlySpan<byte> queriedLeafKey,
        AccountDirectoryAdh1 head,
        ulong callerLkgTreeSize,
        ReadOnlySpan<byte> callerLkgAdh1CoreHash,
        ReadOnlyMemory<byte>[] consistencyNodes,
        ReadOnlySpan<byte> sparseBitmap,
        ReadOnlyMemory<byte>[] sparseSiblings,
        bool hasLkg,
        AccountDirectoryAdp1HistoryMode historyMode,
        ReadOnlySpan<byte> exactAfp1,
        ReadOnlySpan<byte> liveDtt1CoreHash,
        AccountDirectoryAdp1CurrentValue? currentValue)
    {
        this.canonical = canonical.ToArray(); this.networkId = networkId.ToArray();
        ResultKind = resultKind; this.queriedLeafKey = queriedLeafKey.ToArray(); Head = head;
        CallerLkgTreeSize = callerLkgTreeSize; this.callerLkgAdh1CoreHash = callerLkgAdh1CoreHash.ToArray();
        this.consistencyNodes = consistencyNodes.Select(static item => (ReadOnlyMemory<byte>)item.ToArray()).ToArray();
        this.sparseBitmap = sparseBitmap.ToArray();
        this.sparseSiblings = sparseSiblings.Select(static item => (ReadOnlyMemory<byte>)item.ToArray()).ToArray();
        HasLkg = hasLkg; HistoryMode = historyMode; this.exactAfp1 = exactAfp1.ToArray();
        this.liveDtt1CoreHash = liveDtt1CoreHash.ToArray(); CurrentValue = currentValue;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public AccountDirectoryAdp1ResultKind ResultKind { get; }
    public ReadOnlyMemory<byte> QueriedDirectoryLeafKey => queriedLeafKey.ToArray();
    public AccountDirectoryAdh1 Head { get; }
    public ulong CallerLkgTreeSize { get; }
    public ReadOnlyMemory<byte> CallerLkgAdh1CoreHash => callerLkgAdh1CoreHash.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> ConsistencyProofNodes => consistencyNodes.Select(static x => (ReadOnlyMemory<byte>)x.ToArray()).ToArray();
    public ReadOnlyMemory<byte> SparseMapBitmap => sparseBitmap.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> SparseMapSiblings => sparseSiblings.Select(static x => (ReadOnlyMemory<byte>)x.ToArray()).ToArray();
    public bool HasLkg { get; }
    public AccountDirectoryAdp1HistoryMode HistoryMode { get; }
    public ReadOnlyMemory<byte> ExactAfp1 => exactAfp1.ToArray();
    public ReadOnlyMemory<byte> LiveDtt1CoreHash => liveDtt1CoreHash.ToArray();
    public AccountDirectoryAdp1CurrentValue? CurrentValue { get; }
}

public static class AccountDirectoryAdp1Codec
{
    public const ushort Version = 1;
    public const ushort Suite = 0x0201;
    public const ushort NonMembershipFieldCount = 15;
    public const ushort CurrentValueFieldCount = 28;
    public const int MaximumLength = 65_535;
    private const int HeaderSize = 12;
    private const int FieldHeaderSize = 8;

    public static byte[] Encode(AccountDirectoryAdp1 value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value.CanonicalBytes.ToArray();
    }

    public static AccountDirectoryAdp1 Decode(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length is < HeaderSize or > MaximumLength || !canonical[..4].SequenceEqual(ProtocolMagicBytes.ADP1) ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[4..6]) != Version ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[6..8]) != Suite ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[10..12]) != 0)
            Reject("ADP1 envelope is invalid.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(canonical[8..10]);
        if (count is not (NonMembershipFieldCount or CurrentValueFieldCount))
            Reject("ADP1 field count is not a closed result-kind shape.");
        var fields = ScanFields(canonical, count);
        ExactLengths(fields.AsSpan(0, NonMembershipFieldCount), 16, 1, 32, -1, 8, 32, 1, -1, 32, 2, -1, 1, 1, -1, 32);

        var kind = (AccountDirectoryAdp1ResultKind)Scalar8(canonical, fields[1]);
        if ((kind == AccountDirectoryAdp1ResultKind.NonMembership) != (count == NonMembershipFieldCount))
            Reject("ADP1 result kind and exact field set disagree.");
        if (kind is not (AccountDirectoryAdp1ResultKind.CurrentValue or AccountDirectoryAdp1ResultKind.NonMembership))
            Reject("ADP1 result kind is unknown.");
        var network = Field(canonical, fields[0]);
        var key = Field(canonical, fields[2]);
        var dttHash = Field(canonical, fields[14]);
        Required(network, "network ID"); Required(key, "directory leaf key"); Required(dttHash, "live DTT1 core hash");

        AccountDirectoryAdh1 head;
        try { head = AccountDirectoryAdh1Codec.Decode(Field(canonical, fields[3])); }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        { throw new AccountDirectoryAdp1FormatException($"ADP1 exact ADH1 is invalid: {exception.Message}"); }
        if (!head.NetworkId.Span.SequenceEqual(network)) Reject("ADP1 network and ADH1 network differ.");

        var hasLkgByte = Scalar8(canonical, fields[11]);
        if (hasLkgByte > 1) Reject("ADP1 has-LKG is not 0 or 1.");
        var hasLkg = hasLkgByte == 1;
        var lkgSize = Scalar64(canonical, fields[4]);
        var lkgHash = Field(canonical, fields[5]);
        if (!hasLkg && (lkgSize != 0 || !IsZero(lkgHash)) ||
            hasLkg && IsZero(lkgHash))
            Reject("ADP1 LKG shape is invalid, including the distinguished valid empty-tree form.");

        var consistencyCount = Scalar8(canonical, fields[6]);
        ValidateFlatNodes(Field(canonical, fields[7]), consistencyCount, 64, "consistency proof");
        if (hasLkg && lkgSize == 0 && consistencyCount != 0)
            Reject("ADP1 valid empty-tree LKG has no consistency nodes.");
        var mode = (AccountDirectoryAdp1HistoryMode)Scalar8(canonical, fields[12]);
        var afp = Field(canonical, fields[13]);
        if (mode == AccountDirectoryAdp1HistoryMode.ConsistencyOrGenesis)
        {
            if (afp.Length != 0 || (!hasLkg && consistencyCount != 0)) Reject("ADP1 mode-0 history proof shape is invalid.");
        }
        else if (mode == AccountDirectoryAdp1HistoryMode.ForwardCheckpoint)
        {
            if (!hasLkg || consistencyCount != 0 || fields[7].Length != 0 || afp.Length == 0)
                Reject("ADP1 mode-1 history proof shape is invalid.");
            ValidateAfp1(afp, network, head, lkgSize, lkgHash, dttHash);
        }
        else Reject("ADP1 history proof mode is unknown.");

        var bitmap = Field(canonical, fields[8]);
        var sparseCount = Scalar16(canonical, fields[9]);
        if (sparseCount > 256 || sparseCount != PopCount(bitmap)) Reject("ADP1 sparse bitmap/count disagree.");
        ValidateFlatNodes(Field(canonical, fields[10]), sparseCount, 256, "sparse-map proof");
        var consistencyNodes = SplitNodes(Field(canonical, fields[7]));
        var sparseNodes = SplitNodes(Field(canonical, fields[10]));

        AccountDirectoryAdp1CurrentValue? current = null;
        if (kind == AccountDirectoryAdp1ResultKind.NonMembership)
        {
            byte[] root;
            try { root = AccountDirectorySparseMap.ComputeNonMembershipRoot(key, bitmap, Field(canonical, fields[10])); }
            catch (ArgumentException exception) { throw new AccountDirectoryAdp1FormatException($"ADP1 sparse-map proof is invalid: {exception.Message}"); }
            if (!CryptographicOperations.FixedTimeEquals(root, head.CurrentValueMapRoot.Span)) Reject("ADP1 non-membership sparse-map root is invalid.");
        }
        else
        {
            ExactLengths(fields[15..], -1, 32, 32, 394, 644, -1, -1, 1, -1, 182, 8, 1, -1);
            current = DecodeCurrent(canonical, fields, network, key, head, bitmap);
        }

        return new AccountDirectoryAdp1(canonical.ToArray(), network, kind, key, head, lkgSize, lkgHash,
            consistencyNodes, bitmap, sparseNodes, hasLkg, mode, afp, dttHash, current);
    }

    private static AccountDirectoryAdp1CurrentValue DecodeCurrent(
        ReadOnlySpan<byte> canonical,
        FieldSlice[] fields,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> key,
        AccountDirectoryAdh1 head,
        ReadOnlySpan<byte> bitmap)
    {
        AccountDirectoryAdc1 adc;
        ParsedDab1 dab;
        AccountCertificate dpa;
        RevocationSnapshot drs;
        ParsedDmd1 dmd;
        try
        {
            adc = AccountDirectoryAdc1Codec.Decode(Field(canonical, fields[15]));
            dab = ApplicationCoreCodec.DecodeDab1(Field(canonical, fields[18]));
            dpa = IdentityCodec.DecodeAccountCertificate(Field(canonical, fields[19]));
            drs = IdentityCodec.DecodeRevocationSnapshot(Field(canonical, fields[20]));
            dmd = ApplicationCoreCodec.DecodeDmd1(Field(canonical, fields[21]));
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or RecordException)
        { throw new AccountDirectoryAdp1FormatException($"ADP1 current closure record is invalid: {exception.Message}"); }

        var didHash = Field(canonical, fields[16]);
        var didAddress = Field(canonical, fields[17]);
        // ADP1 deliberately carries only the DID1 hash/address projection. It
        // cannot be passed to the DID1 decoder because the exact DID1 resolver
        // capability bytes are absent. The exact hash is instead closed by DAB1.
        Required(didHash, "exact DID1 hash"); Required(didAddress, "DID1 address public key");
        if (!adc.NetworkId.Span.SequenceEqual(network) || !adc.DirectoryLeafKey.Span.SequenceEqual(key) ||
            !dpa.NetworkId.Span.SequenceEqual(network) || !drs.NetworkId.Span.SequenceEqual(network) ||
            !dmd.NetworkId.Span.SequenceEqual(network)) Reject("ADP1 current closure network differs.");
        if (adc.AccountGeneration != dpa.AccountGeneration || adc.AccountGeneration != drs.AccountGeneration ||
            adc.AccountGeneration != dmd.AccountGeneration || adc.AccountGeneration != dab.AccountGeneration ||
            !drs.AccountHash.Span.SequenceEqual(dmd.DeepAccountId.Span) ||
            !drs.AccountHash.Span.SequenceEqual(dab.DeepAccountId.Span)) Reject("ADP1 account closure differs.");
        if (!dab.ExactDid1Hash.Span.SequenceEqual(didHash) || !dab.Dpa1Reference.CanonicalBytes.Span.SequenceEqual(StandardReference(1, dpa.CanonicalBytes.Length, dpa.CanonicalHash.Span)) ||
            !dmd.Dpa1Reference.CanonicalBytes.Span.SequenceEqual(StandardReference(1, dpa.CanonicalBytes.Length, dpa.CanonicalHash.Span)) ||
            !dmd.Drs1Reference.CanonicalBytes.Span.SequenceEqual(StandardReference(4, drs.CanonicalBytes.Length, drs.CanonicalHash.Span)) ||
            !adc.ExactDpa1Reference.Span.SequenceEqual(AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.DPA1, 1, dpa.CanonicalHash.Span)) ||
            !adc.ExactDrs1Reference.Span.SequenceEqual(AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.DRS1, 1, drs.CanonicalHash.Span)) ||
            !adc.ExactDmd1Hash.Span.SequenceEqual(dmd.RecordHash.Span) || !adc.ExactDab1Hash.Span.SequenceEqual(dab.RecordHash.Span))
            Reject("ADP1 exact artifact closure differs.");

        var dpdCount = Scalar8(canonical, fields[22]);
        if (dpdCount is < 1 or > 5 || dpdCount != dmd.ActiveDevices.Count) Reject("ADP1 DPD count differs from bounded DMD active devices.");
        var dpdBytes = ParseLp32Records(Field(canonical, fields[23]), dpdCount, ProtocolMagic.DPD1, 776);
        var devices = new DeviceCertificate[dpdCount];
        ReadOnlySpan<byte> previousId = default;
        for (var index = 0; index < dpdCount; index++)
        {
            try { devices[index] = IdentityCodec.DecodeDeviceCertificate(dpdBytes[index].Span); }
            catch (Exception exception) when (exception is FormatException or ArgumentException or RecordException)
            { throw new AccountDirectoryAdp1FormatException($"ADP1 exact DPD1 is invalid: {exception.Message}"); }
            var device = devices[index];
            if (!previousId.IsEmpty && previousId.SequenceCompareTo(device.DeviceId.Span) >= 0) Reject("ADP1 DPD1 records are not strictly device-ID sorted.");
            if (!device.DeviceId.Span.SequenceEqual(dmd.ActiveDevices[index].DeviceId.Span) ||
                !device.NetworkId.Span.SequenceEqual(network) || !device.AccountHash.Span.SequenceEqual(dmd.DeepAccountId.Span) ||
                device.AccountGeneration != dmd.AccountGeneration ||
                BinaryPrimitives.ReadUInt64BigEndian(device.Record.FieldSpan(12)) != drs.Revision ||
                !device.Record.FieldSpan(13).SequenceEqual(StandardReference(4, drs.CanonicalBytes.Length, drs.CanonicalHash.Span)) ||
                BinaryPrimitives.ReadUInt64BigEndian(device.Record.FieldSpan(14)) != drs.EntryCount ||
                !device.Record.FieldSpan(15).SequenceEqual(drs.CurrentHead.Span) ||
                !dmd.ActiveDevices[index].Dpd1Reference.CanonicalBytes.Span.SequenceEqual(StandardReference(2, 776, device.CanonicalHash.Span)))
                Reject("ADP1 DPD1 records do not close the exact DMD1 set.");
            previousId = device.DeviceId.Span;
        }

        var transitionBytes = Field(canonical, fields[24]);
        var transition = AccountDirectoryTransitionCodec.Decode(transitionBytes);
        var appendIndex = Scalar64(canonical, fields[25]);
        if (appendIndex != transition.LogIndex || !transition.DirectoryLeafKey.Span.SequenceEqual(key))
            Reject("ADP1 transition index/leaf does not match tags 26/3.");
        var expectedAdcReference = AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.ADC1, 1, AccountDirectoryCrypto.ComputeAdc1ArtifactHash(adc));
        var expectedPreviousReference = adc.CheckpointGeneration == 0
            ? new byte[38]
            : AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.ADC1, 1, adc.PredecessorCheckpointHash.Span);
        if (!transition.NextAdc1Reference.Span.SequenceEqual(expectedAdcReference) ||
            !transition.PreviousAdc1Reference.Span.SequenceEqual(expectedPreviousReference) ||
            !transition.NextMapRoot.Span.SequenceEqual(head.CurrentValueMapRoot.Span))
            Reject("ADP1 transition does not reference the exact ADC1/predecessor shape.");
        byte[] sparseRoot;
        try { sparseRoot = AccountDirectorySparseMap.ComputePresentRoot(key, expectedAdcReference, bitmap, Field(canonical, fields[10])); }
        catch (ArgumentException exception) { throw new AccountDirectoryAdp1FormatException($"ADP1 sparse-map proof is invalid: {exception.Message}"); }
        if (!CryptographicOperations.FixedTimeEquals(sparseRoot, head.CurrentValueMapRoot.Span)) Reject("ADP1 current-value sparse-map root is invalid.");

        var inclusionCount = Scalar8(canonical, fields[26]);
        ValidateFlatNodes(Field(canonical, fields[27]), inclusionCount, 64, "inclusion proof");
        var commitment = AccountDirectoryCrypto.Sha256Domain("Deep/AccountDirectory/V1/transition", transitionBytes);
        var leafHash = AccountDirectoryRfc6962.ComputeLeafHash(commitment);
        if (!AccountDirectoryRfc6962.VerifyInclusion(leafHash, appendIndex, head.TreeSize,
                Field(canonical, fields[27]), head.AppendLogMerkleRoot.Span))
            Reject("ADP1 append-log inclusion proof is invalid.");

        return new AccountDirectoryAdp1CurrentValue(adc, dab, dpa, drs, dmd, devices, dpdBytes,
            didHash, didAddress, transitionBytes, transition, appendIndex, SplitNodes(Field(canonical, fields[27])));
    }

    private static void ValidateAfp1(
        ReadOnlySpan<byte> value,
        ReadOnlySpan<byte> network,
        AccountDirectoryAdh1 head,
        ulong lkgTreeSize,
        ReadOnlySpan<byte> lkgHeadHash,
        ReadOnlySpan<byte> dttHash)
    {
        if (value.Length is < HeaderSize or > MaximumLength || !value[..4].SequenceEqual(ProtocolMagicBytes.AFP1) ||
            BinaryPrimitives.ReadUInt16BigEndian(value[4..6]) != 1 || BinaryPrimitives.ReadUInt16BigEndian(value[6..8]) != Suite ||
            BinaryPrimitives.ReadUInt16BigEndian(value[8..10]) != 12 || BinaryPrimitives.ReadUInt16BigEndian(value[10..12]) != 0)
            Reject("ADP1 AFP1 envelope is invalid.");
        var f = ScanFields(value, 12);
        ExactLengths(f, 16, 48, 32, 1, -1, 1, -1, 8, 1, -1, 32, -1);
        var sourceLkg = Field(value, f[1]);
        if (!Field(value, f[0]).SequenceEqual(network) ||
            BinaryPrimitives.ReadUInt64BigEndian(sourceLkg[8..16]) != lkgTreeSize ||
            !sourceLkg[16..48].SequenceEqual(lkgHeadHash) ||
            !Field(value, f[2]).SequenceEqual(AccountDirectoryCrypto.ComputeAdh1CoreHash(head)) ||
            !Field(value, f[10]).SequenceEqual(dttHash)) Reject("ADP1 AFP1 cross-links differ.");
        var xnaCount = Scalar8(value, f[3]);
        if (xnaCount is < 1 or > 64) Reject("AFP1 XNA1 count is invalid.");
        var xnaRecords = new Xna1Record[xnaCount];
        var xnaBytes = ParseLp32Records(Field(value, f[4]), xnaCount, ProtocolMagic.XNA1, null);
        for (var index = 0; index < xnaRecords.Length; index++)
        {
            try { xnaRecords[index] = XPointNetworkCodec.Parse<Xna1Record>(xnaBytes[index].Span); }
            catch (Exception exception) { throw new AccountDirectoryAdp1FormatException($"AFP1 exact XNA1 is invalid: {exception.Message}"); }
            if (!xnaRecords[index].NetworkId.Span.SequenceEqual(network)) Reject("AFP1 XNA1 network differs.");
            if (index > 0)
            {
                var priorGeneration = xnaRecords[index - 1].AuthorityGeneration;
                if (priorGeneration == ulong.MaxValue || xnaRecords[index].AuthorityGeneration != priorGeneration + 1 ||
                    !xnaRecords[index].PredecessorAuthorityCoreHash.Span.SequenceEqual(xnaRecords[index - 1].CoreHash.Span))
                    Reject("AFP1 XNA1 authority chain is not an exact successor chain.");
            }
        }
        var adfCount = Scalar8(value, f[5]);
        if (adfCount is < 1 or > 64) Reject("AFP1 ADF1 count is invalid.");
        var adfRecords = new AccountDirectoryAdf1[adfCount];
        var adfBytes = ParseLp32Records(Field(value, f[6]), adfCount, ProtocolMagic.ADF1, null);
        for (var index = 0; index < adfRecords.Length; index++)
        {
            ValidateAdf1(adfBytes[index].Span);
            try { adfRecords[index] = AccountDirectoryAdf1Codec.Decode(adfBytes[index].Span); }
            catch (Exception exception) when (exception is FormatException or ArgumentException)
            { throw new AccountDirectoryAdp1FormatException($"AFP1 exact ADF1 is invalid: {exception.Message}"); }
            var adf = adfRecords[index];
            if (!adf.NetworkId.Span.SequenceEqual(network)) Reject("AFP1 ADF1 network differs.");
            var authorityFound = false;
            foreach (var xna in xnaRecords)
                authorityFound |= adf.AuthorityXnaCoreReference.Span.SequenceEqual(
                    AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.XNA1, 1, xna.CoreHash.Span));
            if (!authorityFound)
                Reject("AFP1 ADF1 authority is absent from the exact XNA1 chain.");
            if (index > 0)
            {
                var priorGeneration = adfRecords[index - 1].CheckpointGeneration;
                if (priorGeneration == ulong.MaxValue || adf.CheckpointGeneration != priorGeneration + 1 ||
                    !adf.PredecessorCoreHash.Span.SequenceEqual(AccountDirectoryCrypto.ComputeAdf1CoreHash(adfRecords[index - 1])))
                    Reject("AFP1 ADF1 chain is not an exact predecessor-linked successor chain.");
            }
        }
        var targetHeadBytes = ParseLp32Records(Field(value, f[11]), adfCount, ProtocolMagic.ADH1, null);
        var targetHeads = new AccountDirectoryAdh1[adfCount];
        for (var index = 0; index < targetHeads.Length; index++)
        {
            try { targetHeads[index] = AccountDirectoryAdh1Codec.Decode(targetHeadBytes[index].Span); }
            catch (Exception exception) when (exception is FormatException or ArgumentException)
            { throw new AccountDirectoryAdp1FormatException($"AFP1 exact target ADH1 is invalid: {exception.Message}"); }
            var target = targetHeads[index];
            var adf = adfRecords[index];
            var targetHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(target);
            if (!target.NetworkId.Span.SequenceEqual(network) ||
                !adf.TargetAdh1CoreReference.Span[6..].SequenceEqual(targetHash) ||
                adf.TargetTreeSize != target.TreeSize ||
                !adf.TargetAppendLogRoot.Span.SequenceEqual(target.AppendLogMerkleRoot.Span) ||
                !adf.TargetCurrentValueMapRoot.Span.SequenceEqual(target.CurrentValueMapRoot.Span) ||
                !adf.AuthorityXnaCoreReference.Span.SequenceEqual(target.ExactXnaAuthorityCoreReference.Span) ||
                target.LogGeneration <= adf.CoveredLastAdhGeneration)
                Reject("AFP1 target ADH1 does not close its positionally paired ADF1.");
        }
        var membershipCount = Scalar8(value, f[8]);
        ValidateFlatNodes(Field(value, f[9]), membershipCount, 64, "AFP1 membership proof");
        var sourceIndex = Scalar64(value, f[7]);
        var firstAdf = adfRecords[0];
        if (sourceIndex >= firstAdf.CoveredHeadCount ||
            BinaryPrimitives.ReadUInt64BigEndian(sourceLkg[..8]) < firstAdf.CoveredFirstAdhGeneration ||
            BinaryPrimitives.ReadUInt64BigEndian(sourceLkg[..8]) > firstAdf.CoveredLastAdhGeneration)
            Reject("AFP1 source tuple is outside the first ADF1 covered set.");
        var leafInput = new byte[49]; leafInput[0] = 0; sourceLkg.CopyTo(leafInput.AsSpan(1));
        var sourceLeaf = SHA256.HashData(leafInput);
        if (!AccountDirectoryRfc6962.VerifyInclusion(sourceLeaf, sourceIndex, firstAdf.CoveredHeadCount,
                Field(value, f[9]), firstAdf.CoveredHeadMerkleRoot.Span))
            Reject("AFP1 source tuple membership proof is invalid.");
        var lastAdf = adfRecords[^1];
        var expectedHeadReference = AccountDirectoryCrypto.CreateReference(
            ProtocolMagicBytes.ADH1, 1, AccountDirectoryCrypto.ComputeAdh1CoreHash(head));
        if (!lastAdf.TargetAdh1CoreReference.Span.SequenceEqual(expectedHeadReference) ||
            lastAdf.TargetTreeSize != head.TreeSize ||
            !lastAdf.TargetAppendLogRoot.Span.SequenceEqual(head.AppendLogMerkleRoot.Span) ||
            !lastAdf.TargetCurrentValueMapRoot.Span.SequenceEqual(head.CurrentValueMapRoot.Span) ||
            !lastAdf.AuthorityXnaCoreReference.Span.SequenceEqual(head.ExactXnaAuthorityCoreReference.Span) ||
            head.LogGeneration <= lastAdf.CoveredLastAdhGeneration ||
            !targetHeadBytes[^1].Span.SequenceEqual(AccountDirectoryAdh1Codec.Encode(head)))
            Reject("AFP1 final ADF1 does not close the target ADH1.");
    }

    private static void ValidateAdf1(ReadOnlySpan<byte> value)
    {
        if (value.Length is < HeaderSize or > MaximumLength || !value[..4].SequenceEqual(ProtocolMagicBytes.ADF1) ||
            BinaryPrimitives.ReadUInt16BigEndian(value[4..6]) != 1 || BinaryPrimitives.ReadUInt16BigEndian(value[6..8]) != 0x0001 ||
            BinaryPrimitives.ReadUInt16BigEndian(value[8..10]) != 16 || BinaryPrimitives.ReadUInt16BigEndian(value[10..12]) != 0)
            Reject("AFP1 exact ADF1 envelope is invalid.");
        var f = ScanFields(value, 16);
        ExactLengths(f, 16, 8, 32, 8, 8, 8, 32, 38, 8, 32, 32, 38, 8, 2, 1, -1);
        var generation = Scalar64(value, f[1]);
        if ((generation == 0) != IsZero(Field(value, f[2])) || Scalar64(value, f[4]) < Scalar64(value, f[3]) ||
            Scalar64(value, f[5]) == 0 || IsZero(Field(value, f[0])) || IsZero(Field(value, f[6])) ||
            IsZero(Field(value, f[9])) || IsZero(Field(value, f[10]))) Reject("AFP1 exact ADF1 semantic shape is invalid.");
        ValidateMagicReference(Field(value, f[7]), ProtocolMagicBytes.ADH1); ValidateMagicReference(Field(value, f[11]), ProtocolMagicBytes.XNA1);
        var signatures = Scalar8(value, f[14]);
        if (signatures is < 1 or > 8 || f[15].Length != signatures * 96) Reject("AFP1 exact ADF1 signature shape is invalid.");
        ValidateSortedEntries(Field(value, f[15]), 96, 32, "ADF1 root signatures");
    }

    private static ReadOnlyMemory<byte>[] ParseLp32Records(ReadOnlySpan<byte> value, int count, ReadOnlySpan<char> magic, int? exactLength)
    {
        var result = new ReadOnlyMemory<byte>[count];
        var offset = 0;
        for (var index = 0; index < count; index++)
        {
            if (value.Length - offset < 4) Reject($"{magic.ToString()} LP32 length is truncated.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(value[offset..]); offset += 4;
            if (length > int.MaxValue || length > value.Length - offset || length < HeaderSize || (exactLength.HasValue && length != exactLength))
                Reject($"{magic.ToString()} LP32 record length is invalid.");
            var record = value.Slice(offset, (int)length);
            if (!record[..4].SequenceEqual(System.Text.Encoding.ASCII.GetBytes(magic.ToString()))) Reject($"LP32 record has the wrong {magic.ToString()} magic.");
            result[index] = record.ToArray(); offset += (int)length;
        }
        if (offset != value.Length) Reject($"{magic.ToString()} LP32 list has trailing/omitted records.");
        return result;
    }

    private static byte[] StandardReference(ushort type, int length, ReadOnlySpan<byte> hash)
    {
        var result = new byte[38]; BinaryPrimitives.WriteUInt16BigEndian(result, type);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(2), checked((uint)length)); hash.CopyTo(result.AsSpan(6)); return result;
    }

    private static FieldSlice[] ScanFields(ReadOnlySpan<byte> canonical, int count)
    {
        var fields = new FieldSlice[count]; var offset = HeaderSize;
        for (var index = 0; index < count; index++)
        {
            if (canonical.Length - offset < FieldHeaderSize) Reject("Canonical field header is truncated.");
            if (BinaryPrimitives.ReadUInt16BigEndian(canonical[offset..]) != index + 1 ||
                BinaryPrimitives.ReadUInt16BigEndian(canonical[(offset + 2)..]) != 0) Reject("Canonical tags/reserved fields are invalid.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(canonical[(offset + 4)..]); offset += FieldHeaderSize;
            if (length > int.MaxValue || length > canonical.Length - offset) Reject("Canonical field is truncated/oversized.");
            fields[index] = new(offset, (int)length); offset = checked(offset + (int)length);
        }
        if (offset != canonical.Length) Reject("Canonical record contains trailing bytes.");
        return fields;
    }

    private static void ExactLengths(ReadOnlySpan<FieldSlice> fields, params int[] lengths)
    {
        if (fields.Length != lengths.Length) Reject("Canonical field-length table is inconsistent.");
        for (var index = 0; index < lengths.Length; index++) if (lengths[index] >= 0 && fields[index].Length != lengths[index])
            Reject($"Canonical field {index + 1} length is invalid.");
    }

    private static void ValidateFlatNodes(ReadOnlySpan<byte> value, int count, int maximum, string name)
    {
        if (count > maximum || value.Length != checked(count * 32)) Reject($"ADP1 {name} count/length is invalid.");
    }

    private static void ValidateSortedEntries(ReadOnlySpan<byte> value, int width, int keyLength, string name)
    {
        for (var offset = 0; offset < value.Length; offset += width)
        {
            var key = value.Slice(offset, keyLength); Required(key, name);
            if (offset > 0 && value.Slice(offset - width, keyLength).SequenceCompareTo(key) >= 0) Reject($"{name} are not strictly sorted.");
            Required(value.Slice(offset + keyLength, width - keyLength), name);
        }
    }

    private static void ValidateMagicReference(ReadOnlySpan<byte> value, ReadOnlySpan<byte> magic)
    {
        if (value.Length != 38 || !value[..4].SequenceEqual(magic) || BinaryPrimitives.ReadUInt16BigEndian(value[4..6]) != 1 || IsZero(value[6..]))
            Reject("Canonical typed core reference is invalid.");
    }

    private static ReadOnlyMemory<byte>[] SplitNodes(ReadOnlySpan<byte> value)
    {
        var result = new ReadOnlyMemory<byte>[value.Length / 32];
        for (var index = 0; index < result.Length; index++)
            result[index] = value.Slice(index * 32, 32).ToArray();
        return result;
    }
    private static ReadOnlySpan<byte> Field(ReadOnlySpan<byte> source, FieldSlice field) => source.Slice(field.Offset, field.Length);
    private static byte Scalar8(ReadOnlySpan<byte> source, FieldSlice field) => Field(source, field)[0];
    private static ushort Scalar16(ReadOnlySpan<byte> source, FieldSlice field) => BinaryPrimitives.ReadUInt16BigEndian(Field(source, field));
    private static ulong Scalar64(ReadOnlySpan<byte> source, FieldSlice field) => BinaryPrimitives.ReadUInt64BigEndian(Field(source, field));
    private static int PopCount(ReadOnlySpan<byte> value) { var count = 0; foreach (var item in value) count += BitOperations.PopCount(item); return count; }
    private static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;
    private static void Required(ReadOnlySpan<byte> value, string name) { if (IsZero(value)) Reject($"ADP1 {name} is zero."); }
    private static void Reject(string message) => throw new AccountDirectoryAdp1FormatException(message);
    private readonly record struct FieldSlice(int Offset, int Length);
}

public static class AccountDirectorySparseMap
{
    private static readonly byte[][] Empty = BuildEmpty();

    public static ReadOnlyMemory<byte> EmptyMapRoot => Empty[256].ToArray();

    public static byte[] ComputeNonMembershipRoot(ReadOnlySpan<byte> leafKey32, ReadOnlySpan<byte> bitmap32, ReadOnlySpan<byte> siblings)
        => Compute(leafKey32, Empty[0], bitmap32, siblings);

    public static byte[] ComputePresentRoot(ReadOnlySpan<byte> leafKey32, ReadOnlySpan<byte> exactAdc1Reference38, ReadOnlySpan<byte> bitmap32, ReadOnlySpan<byte> siblings)
    {
        Require(leafKey32, 32, nameof(leafKey32)); Require(exactAdc1Reference38, 38, nameof(exactAdc1Reference38));
        AccountDirectoryTransitionCodec.ValidateAdcReference(exactAdc1Reference38, allowZero: false);
        var payload = new byte[70]; leafKey32.CopyTo(payload); exactAdc1Reference38.CopyTo(payload.AsSpan(32));
        return Compute(leafKey32, AccountDirectoryCrypto.Sha256Domain("Deep/AccountDirectory/V1/map-present", payload), bitmap32, siblings);
    }

    private static byte[] Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> leaf, ReadOnlySpan<byte> bitmap, ReadOnlySpan<byte> siblings)
    {
        Require(key, 32, nameof(key)); Require(bitmap, 32, nameof(bitmap));
        var expected = 0; foreach (var item in bitmap) expected += BitOperations.PopCount(item);
        if (siblings.Length != checked(expected * 32)) throw new ArgumentException("Sparse sibling bytes do not match bitmap popcount.", nameof(siblings));
        var current = leaf.ToArray(); var siblingOffset = 0;
        Span<byte> pair = stackalloc byte[64];
        for (var level = 0; level < 256; level++)
        {
            var supplied = (bitmap[level / 8] & (0x80 >> (level % 8))) != 0;
            var sibling = supplied ? siblings.Slice(siblingOffset, 32) : Empty[level];
            if (supplied)
            {
                if (CryptographicOperations.FixedTimeEquals(sibling, Empty[level]))
                    throw new ArgumentException("Sparse proof explicitly encodes a default sibling.", nameof(siblings));
                siblingOffset += 32;
            }
            var keyIndex = 255 - level;
            var right = (key[keyIndex / 8] & (0x80 >> (keyIndex % 8))) != 0;
            if (right) { sibling.CopyTo(pair); current.CopyTo(pair[32..]); }
            else { current.CopyTo(pair); sibling.CopyTo(pair[32..]); }
            current = AccountDirectoryCrypto.Sha256Domain("Deep/AccountDirectory/V1/map-node", pair);
        }
        return current;
    }

    private static byte[][] BuildEmpty()
    {
        var result = new byte[257][];
        result[0] = AccountDirectoryCrypto.Sha256Domain("Deep/AccountDirectory/V1/map-empty-leaf", []);
        Span<byte> pair = stackalloc byte[64];
        for (var level = 0; level < 256; level++)
        {
            result[level].CopyTo(pair); result[level].CopyTo(pair[32..]);
            result[level + 1] = AccountDirectoryCrypto.Sha256Domain("Deep/AccountDirectory/V1/map-node", pair);
        }
        return result;
    }

    private static void Require(ReadOnlySpan<byte> value, int length, string name)
    { if (value.Length != length) throw new ArgumentException($"{name} must be exactly {length} bytes.", name); }
}

public static class AccountDirectoryRfc6962
{
    public static byte[] ComputeEmptyTreeHash() => SHA256.HashData([]);
    public static byte[] ComputeLeafHash(ReadOnlySpan<byte> transitionCommitment32)
    {
        if (transitionCommitment32.Length != 32) throw new ArgumentException("RFC6962 transition commitment must be 32 bytes.", nameof(transitionCommitment32));
        Span<byte> input = stackalloc byte[33]; input[0] = 0; transitionCommitment32.CopyTo(input[1..]); return SHA256.HashData(input);
    }

    public static byte[] ComputeNodeHash(ReadOnlySpan<byte> left32, ReadOnlySpan<byte> right32)
    {
        if (left32.Length != 32 || right32.Length != 32) throw new ArgumentException("RFC6962 node children must be 32 bytes.");
        Span<byte> input = stackalloc byte[65]; input[0] = 1; left32.CopyTo(input[1..33]); right32.CopyTo(input[33..]); return SHA256.HashData(input);
    }

    public static bool VerifyInclusion(ReadOnlySpan<byte> leafHash32, ulong leafIndex, ulong treeSize, ReadOnlySpan<byte> proofNodes, ReadOnlySpan<byte> expectedRoot32)
    {
        RequireProof(leafHash32, proofNodes, expectedRoot32);
        if (treeSize == 0 || leafIndex >= treeSize) return false;
        var fn = leafIndex; var sn = treeSize - 1; var root = leafHash32.ToArray(); var offset = 0;
        while (sn != 0)
        {
            if (offset == proofNodes.Length) return false;
            var node = proofNodes.Slice(offset, 32); offset += 32;
            if ((fn & 1) != 0 || fn == sn)
            {
                root = ComputeNodeHash(node, root);
                while ((fn & 1) == 0 && fn != 0) { fn >>= 1; sn >>= 1; }
            }
            else root = ComputeNodeHash(root, node);
            fn >>= 1; sn >>= 1;
        }
        return offset == proofNodes.Length && CryptographicOperations.FixedTimeEquals(root, expectedRoot32);
    }

    public static bool VerifyConsistency(ulong oldSize, ulong newSize, ReadOnlySpan<byte> oldRoot32, ReadOnlySpan<byte> newRoot32, ReadOnlySpan<byte> proofNodes)
    {
        RequireProof(oldRoot32, proofNodes, newRoot32);
        if (oldSize > newSize) return false;
        if (oldSize == 0)
        {
            var empty = ComputeEmptyTreeHash();
            return proofNodes.Length == 0 && CryptographicOperations.FixedTimeEquals(oldRoot32, empty) &&
                (newSize != 0 || CryptographicOperations.FixedTimeEquals(newRoot32, empty));
        }
        if (oldSize == newSize) return proofNodes.Length == 0 && CryptographicOperations.FixedTimeEquals(oldRoot32, newRoot32);
        var fn = oldSize - 1; var sn = newSize - 1;
        while ((fn & 1) != 0) { fn >>= 1; sn >>= 1; }
        byte[] first; var offset = 0;
        if (fn == 0) first = oldRoot32.ToArray();
        else { if (proofNodes.Length == 0) return false; first = proofNodes[..32].ToArray(); offset = 32; }
        var old = first; var current = first;
        while (offset < proofNodes.Length)
        {
            if (sn == 0) return false;
            var node = proofNodes.Slice(offset, 32); offset += 32;
            if ((fn & 1) != 0 || fn == sn)
            {
                old = ComputeNodeHash(node, old); current = ComputeNodeHash(node, current);
                while ((fn & 1) == 0 && fn != 0) { fn >>= 1; sn >>= 1; }
            }
            else current = ComputeNodeHash(current, node);
            fn >>= 1; sn >>= 1;
        }
        return sn == 0 && CryptographicOperations.FixedTimeEquals(old, oldRoot32) && CryptographicOperations.FixedTimeEquals(current, newRoot32);
    }

    private static void RequireProof(ReadOnlySpan<byte> first, ReadOnlySpan<byte> proof, ReadOnlySpan<byte> second)
    {
        if (first.Length != 32 || second.Length != 32 || proof.Length % 32 != 0 || proof.Length > 64 * 32)
            throw new ArgumentException("RFC6962 proof has an invalid hash/count shape.");
    }
}
