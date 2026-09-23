using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Parsed ADP1 V2 bytes are untrusted proof shape, not account, witness or
/// freshness authority. Promotion requires the independent public verifier.
/// </summary>
public sealed class ParsedAdp1V2
{
    private readonly byte[] canonical;
    private readonly byte[][] fields;

    internal ParsedAdp1V2(ReadOnlySpan<byte> canonical, byte[][] fields,
        AccountDirectoryAdh1 head, AccountDirectoryAdp1ResultKind kind)
    {
        this.canonical = canonical.ToArray();
        this.fields = fields.Select(static value => value.ToArray()).ToArray();
        Head = head;
        ResultKind = kind;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public AccountDirectoryAdh1 Head { get; }
    public AccountDirectoryAdp1ResultKind ResultKind { get; }
    public ReadOnlyMemory<byte> QueriedDirectoryLeafKey => fields[2].ToArray();
    public ReadOnlyMemory<byte> LiveDtt1CoreHash => fields[14].ToArray();
    public ReadOnlyMemory<byte> ExactCurrentAdc1V2 =>
        fields.Length == DeepIdV2Adp1Codec.CurrentValueFieldCount
            ? fields[15].ToArray() : ReadOnlyMemory<byte>.Empty;
    public ReadOnlyMemory<byte> ExactDid2 =>
        fields.Length == DeepIdV2Adp1Codec.CurrentValueFieldCount
            ? fields[16].ToArray() : ReadOnlyMemory<byte>.Empty;
    public ReadOnlyMemory<byte> ExactDab2 =>
        fields.Length == DeepIdV2Adp1Codec.CurrentValueFieldCount
            ? fields[17].ToArray() : ReadOnlyMemory<byte>.Empty;

    public ReadOnlyMemory<byte> ExactField(int tag) =>
        tag is >= 1 && tag <= DeepIdV2Adp1Codec.CurrentValueFieldCount &&
            tag <= fields.Length
            ? fields[tag - 1].ToArray()
            : throw new ArgumentOutOfRangeException(nameof(tag));

    public IReadOnlyList<ReadOnlyMemory<byte>> RevokedDcaAuthorizationIds
    {
        get
        {
            if (fields.Length != DeepIdV2Adp1Codec.CurrentValueFieldCount)
                return [];
            var packed = fields[27];
            var count = BinaryPrimitives.ReadUInt16BigEndian(packed);
            var values = new ReadOnlyMemory<byte>[count];
            for (var index = 0; index < count; index++)
                values[index] = packed.AsSpan(2 + index * 32, 32).ToArray();
            return values;
        }
    }
}

/// <summary>
/// Closed ADP1 V2 candidate. Current values carry exact DID2/DAB2 and the
/// existing exact account/device records; V1 ADP1 cannot decode these bytes.
/// Decode verifies map/append proof shape, but not witness/PQ signatures or
/// nonce-bound DTT1 currentness.
/// </summary>
public static class DeepIdV2Adp1Codec
{
    public const ushort Version = 2;
    public const ushort Suite = DeepIdV2Codec.Suite;
    public const ushort NonMembershipFieldCount = 15;
    public const ushort CurrentValueFieldCount = 28;
    public const int MaximumLength = 512 * 1024;

    public static ParsedAdp1V2 Author(DeepIdV2DirectoryProofMaterial material,
        ReadOnlySpan<byte> liveDtt1CoreHash32)
    {
        ArgumentNullException.ThrowIfNull(material);
        if (liveDtt1CoreHash32.Length != 32 ||
            liveDtt1CoreHash32.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Live DTT1 core hash must be nonzero and 32 bytes.",
                nameof(liveDtt1CoreHash32));
        var caller = material.CallerProtectedLkg;
        var fields = new List<byte[]>
        {
            material.CurrentHead.Head.NetworkId.ToArray(),
            new byte[] { (byte)material.ResultKind },
            material.QueriedDirectoryLeafKey.ToArray(),
            material.CurrentHead.ExactAdh1.ToArray(),
            U64(caller?.TreeSize ?? 0),
            caller?.CoreHash.ToArray() ?? new byte[32],
            new byte[] { checked((byte)material.ConsistencyProofNodes.Count) },
            Flatten(material.ConsistencyProofNodes),
            material.SparseMapBitmap.ToArray(),
            U16(checked((ushort)material.SparseMapSiblings.Count)),
            Flatten(material.SparseMapSiblings),
            new byte[] { caller is null ? (byte)0 : (byte)1 },
            new byte[] { (byte)AccountDirectoryAdp1HistoryMode.ConsistencyOrGenesis },
            Array.Empty<byte>(),
            liveDtt1CoreHash32.ToArray()
        };
        if (material.CurrentCheckpoint is { } current)
        {
            var identity = current.Binding.Identity;
            var devices = identity.ActiveDevices
                .OrderBy(static value => value.Certificate.DeviceId.ToArray(),
                    ByteArrayComparer.Instance)
                .Select(static value => Lp32(value.Certificate.CanonicalBytes.Span))
                .ToArray();
            fields.AddRange(new byte[][]
            {
                current.Checkpoint.CanonicalBytes.ToArray(),
                current.Binding.DeepId.CanonicalBytes.ToArray(),
                current.Binding.Record.CanonicalBytes.ToArray(),
                identity.Account.Certificate.CanonicalBytes.ToArray(),
                identity.Revocations.Snapshot.CanonicalBytes.ToArray(),
                current.Directory.Record.CanonicalBytes.ToArray(),
                new byte[] { checked((byte)devices.Length) },
                Flatten(devices),
                material.ExactTransition.ToArray(),
                U64(material.AppendLogIndex),
                new byte[] { checked((byte)material.InclusionProofNodes.Count) },
                Flatten(material.InclusionProofNodes),
                PackRevoked(current.ExactRevokedDcaAuthorizationIds)
            });
        }
        var total = checked(12 + fields.Sum(static value => 8 + value.Length));
        if (total > MaximumLength)
            throw new AccountDirectoryAdp1FormatException("ADP1 V2 exceeds its exact envelope bound.");
        var canonical = new byte[total];
        var writer = new ApplicationRecordWriter(canonical,
            ProtocolMagicBytes.ADP1, checked((ushort)fields.Count), Version, Suite);
        for (ushort tag = 1; tag <= fields.Count; tag++)
            writer.Write(tag, fields[tag - 1]);
        writer.Complete();
        return Decode(canonical);
    }

    public static ParsedAdp1V2 Decode(ReadOnlySpan<byte> canonical)
    {
        try { return DecodeCore(canonical); }
        catch (AccountDirectoryAdp1FormatException) { throw; }
        catch (Exception exception) when (exception is FormatException or
            ArgumentException or RecordException or OverflowException)
        { throw new AccountDirectoryAdp1FormatException(exception.Message); }
    }

    private static ParsedAdp1V2 DecodeCore(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length is < 12 or > MaximumLength)
            throw Invalid("ADP1 V2 total size is invalid.");
        var fieldCount = BinaryPrimitives.ReadUInt16BigEndian(canonical[8..10]);
        if (fieldCount is not (NonMembershipFieldCount or CurrentValueFieldCount))
            throw Invalid("ADP1 V2 has an unknown result shape.");
        Span<ApplicationFieldSlice> slices = stackalloc ApplicationFieldSlice[fieldCount];
        try
        {
            ApplicationCoreFormat.Preflight(canonical, ProtocolMagicBytes.ADP1,
                fieldCount, 12 + fieldCount * 8, MaximumLength, slices,
                Version, Suite);
        }
        catch (FormatException exception)
        { throw new AccountDirectoryAdp1FormatException(exception.Message); }
        var fields = new byte[fieldCount][];
        for (var index = 0; index < fields.Length; index++)
            fields[index] = ApplicationCoreFormat.Field(canonical, slices,
                index + 1).ToArray();
        Exact(fields, 1, 16); Exact(fields, 2, 1); Exact(fields, 3, 32);
        Exact(fields, 5, 8); Exact(fields, 6, 32); Exact(fields, 7, 1);
        Exact(fields, 9, 32); Exact(fields, 10, 2); Exact(fields, 12, 1);
        Exact(fields, 13, 1); Exact(fields, 15, 32);
        RequireNonzero(fields[0], "network ID");
        RequireNonzero(fields[2], "query leaf");
        RequireNonzero(fields[14], "DTT1 core hash");
        var kind = (AccountDirectoryAdp1ResultKind)fields[1][0];
        if (kind == AccountDirectoryAdp1ResultKind.NonMembership !=
                (fieldCount == NonMembershipFieldCount) ||
            kind is not (AccountDirectoryAdp1ResultKind.NonMembership or
                AccountDirectoryAdp1ResultKind.CurrentValue))
            throw Invalid("ADP1 V2 result kind and field set differ.");
        AccountDirectoryAdh1 head;
        try { head = AccountDirectoryAdh1Codec.Decode(fields[3]); }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        { throw new AccountDirectoryAdp1FormatException(exception.Message); }
        if (head.MinimumReader < 2 ||
            !Fixed(head.NetworkId.Span, fields[0]))
            throw Invalid("ADP1 V2 head has an old reader floor or wrong network.");
        var hasLkg = fields[11][0];
        var lkgSize = BinaryPrimitives.ReadUInt64BigEndian(fields[4]);
        if (hasLkg > 1 || hasLkg == 0 &&
                (lkgSize != 0 || !Zero(fields[5])) ||
            hasLkg == 1 && Zero(fields[5]))
            throw Invalid("ADP1 V2 caller LKG shape is invalid.");
        var consistencyCount = fields[6][0];
        Nodes(fields[7], consistencyCount, 64);
        if (fields[12][0] != (byte)AccountDirectoryAdp1HistoryMode.ConsistencyOrGenesis ||
            fields[13].Length != 0 ||
            hasLkg == 0 && consistencyCount != 0 ||
            hasLkg == 1 && lkgSize == 0 && consistencyCount != 0)
            throw Invalid("ADP1 V2 history shape is invalid.");
        var sparseCount = BinaryPrimitives.ReadUInt16BigEndian(fields[9]);
        Nodes(fields[10], sparseCount, 256);
        var popCount = 0;
        foreach (var value in fields[8]) popCount += BitOperations.PopCount(value);
        if (sparseCount != popCount)
            throw Invalid("ADP1 V2 sparse bitmap and node count differ.");
        if (kind == AccountDirectoryAdp1ResultKind.NonMembership)
        {
            var root = DeepIdV2DirectorySparseMap.ComputeNonMembershipRoot(
                fields[2], fields[8], fields[10]);
            if (!Fixed(root, head.CurrentValueMapRoot.Span))
                throw Invalid("ADP1 V2 non-membership map root differs.");
        }
        else ValidateCurrent(fields, head);
        return new ParsedAdp1V2(canonical, fields, head, kind);
    }

    private static void ValidateCurrent(byte[][] fields,
        AccountDirectoryAdh1 head)
    {
        Exact(fields, 16, DeepIdV2AccountDirectoryCodec.CanonicalLength);
        Exact(fields, 17, DeepIdV2Codec.Did2Length);
        Exact(fields, 18, DeepIdV2Codec.Dab2Length);
        Exact(fields, 19, 644); Exact(fields, 22, 1);
        Exact(fields, 24, DeepIdV2DirectoryTransitionCodec.CanonicalLength);
        Exact(fields, 25, 8); Exact(fields, 26, 1);
        if (fields[19].Length is < 1 or > 16_384 ||
            fields[20].Length is < 1 or > 57_344)
            throw Invalid("ADP1 V2 DRS1 or DMD1 exceeds its bound.");
        ParsedAdc1V2 adc;
        ParsedDid2 did;
        ParsedDab2 dab;
        ParsedDirectoryTransitionV2 transition;
        AccountCertificate dpa;
        RevocationSnapshot drs;
        ParsedDmd1 dmd;
        try
        {
            adc = DeepIdV2AccountDirectoryCodec.Decode(fields[15]);
            did = DeepIdV2Codec.DecodeDid2(fields[16]);
            dab = DeepIdV2Codec.DecodeDab2(fields[17]);
            transition = DeepIdV2DirectoryTransitionCodec.Decode(fields[23]);
            dpa = IdentityCodec.DecodeAccountCertificate(fields[18]);
            drs = IdentityCodec.DecodeRevocationSnapshot(fields[19]);
            dmd = ApplicationCoreCodec.DecodeDmd1(fields[20]);
        }
        catch (Exception exception) when (exception is FormatException or
            ArgumentException or RecordException)
        { throw new AccountDirectoryAdp1FormatException(exception.Message); }
        if (!Fixed(adc.NetworkId.Span, fields[0]) ||
            !Fixed(adc.DirectoryLeafKey.Span, fields[2]) ||
            !Fixed(fields[2], DeepIdV2AccountDirectoryCodec.ComputeDirectoryLeafKey(
                fields[0], did)) ||
            !Fixed(dab.ExactDid2Hash.Span, did.RecordHash.Span) ||
            !Fixed(adc.ExactDab2Hash.Span, dab.RecordHash.Span) ||
            !Fixed(dpa.NetworkId.Span, fields[0]) ||
            !Fixed(drs.NetworkId.Span, fields[0]) ||
            !Fixed(dmd.NetworkId.Span, fields[0]) ||
            adc.AccountGeneration != dpa.AccountGeneration ||
            adc.AccountGeneration != drs.AccountGeneration ||
            adc.AccountGeneration != dmd.AccountGeneration ||
            adc.AccountGeneration != dab.AccountGeneration ||
            !Fixed(drs.AccountHash.Span, dmd.DeepAccountId.Span) ||
            !Fixed(drs.AccountHash.Span, dab.DeepAccountId.Span) ||
            !Fixed(adc.ExactDpa1Reference.Span,
                AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.DPA1,
                    1, dpa.CanonicalHash.Span)) ||
            !Fixed(adc.ExactDrs1Reference.Span,
                AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.DRS1,
                    1, drs.CanonicalHash.Span)) ||
            !Fixed(adc.ExactDmd1Hash.Span, dmd.RecordHash.Span) ||
            !Fixed(dab.Dpa1Reference.CanonicalBytes.Span,
                StandardReference(1, dpa.CanonicalBytes.Length,
                    dpa.CanonicalHash.Span)) ||
            !Fixed(dmd.Dpa1Reference.CanonicalBytes.Span,
                StandardReference(1, dpa.CanonicalBytes.Length,
                    dpa.CanonicalHash.Span)) ||
            !Fixed(dmd.Drs1Reference.CanonicalBytes.Span,
                StandardReference(4, drs.CanonicalBytes.Length,
                    drs.CanonicalHash.Span)) ||
            !Fixed(transition.DirectoryLeafKey.Span, fields[2]) ||
            !Fixed(transition.NextAdc1Reference.Span,
                adc.ArtifactReference.Span) ||
            transition.LogIndex != BinaryPrimitives.ReadUInt64BigEndian(fields[24]))
            throw Invalid("ADP1 V2 exact DID2/ADC1/transition links differ.");
        var expectedPrevious = adc.CheckpointGeneration == 0
            ? new byte[38]
            : AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.ADC1,
                2, adc.PredecessorCheckpointHash.Span);
        if (!Fixed(transition.PreviousAdc1Reference.Span, expectedPrevious))
            throw Invalid("ADP1 V2 transition does not consume the exact predecessor.");
        var revoked = ParseRevoked(fields[27]);
        if (!Fixed(adc.RevokedDcaAuthorizationIdsHash.Span,
                DeepIdV2AccountDirectoryCodec.ComputeRevokedDcaAuthorizationIdsHash(
                    revoked)))
            throw Invalid("ADP1 V2 revoked authorization list differs from ADC1.");
        var count = fields[21][0];
        if (count is < 1 or > 5 || count != dmd.ActiveDevices.Count)
            throw Invalid("ADP1 V2 active-device count is invalid.");
        var dpd = fields[22];
        var offset = 0;
        ReadOnlySpan<byte> priorId = default;
        for (var index = 0; index < count; index++)
        {
            if (dpd.Length - offset < 4 ||
                BinaryPrimitives.ReadUInt32BigEndian(dpd.AsSpan(offset)) != 776 ||
                dpd.Length - offset - 4 < 776)
                throw Invalid("ADP1 V2 DPD1 LP32 list is malformed.");
            offset += 4;
            var device = IdentityCodec.DecodeDeviceCertificate(
                dpd.AsSpan(offset, 776));
            if (!priorId.IsEmpty &&
                priorId.SequenceCompareTo(device.DeviceId.Span) >= 0)
                throw Invalid("ADP1 V2 DPD1 list is not device-ID sorted.");
            if (!Fixed(device.DeviceId.Span,
                    dmd.ActiveDevices[index].DeviceId.Span) ||
                !Fixed(device.NetworkId.Span, fields[0]) ||
                !Fixed(device.AccountHash.Span, dmd.DeepAccountId.Span) ||
                device.AccountGeneration != dmd.AccountGeneration ||
                !Fixed(dmd.ActiveDevices[index].Dpd1Reference.CanonicalBytes.Span,
                    StandardReference(2, 776, device.CanonicalHash.Span)))
                throw Invalid("ADP1 V2 DPD1 does not close the DMD1 active set.");
            priorId = device.DeviceId.Span;
            offset += 776;
        }
        if (offset != dpd.Length)
            throw Invalid("ADP1 V2 DPD1 list has trailing bytes.");
        var sparseRoot = DeepIdV2DirectorySparseMap.ComputePresentRoot(
            fields[2], adc.ArtifactReference.Span, fields[8], fields[10]);
        if (!Fixed(sparseRoot, head.CurrentValueMapRoot.Span))
            throw Invalid("ADP1 V2 current sparse-map root differs.");
        var inclusionCount = fields[25][0];
        Nodes(fields[26], inclusionCount, 64);
        if (!AccountDirectoryRfc6962.VerifyInclusion(
                transition.AppendLogLeafHash.Span, transition.LogIndex,
                head.TreeSize, fields[26], head.AppendLogMerkleRoot.Span))
            throw Invalid("ADP1 V2 append-log inclusion proof differs.");
    }

    private static void Exact(byte[][] fields, int tag, int length)
    {
        if (fields[tag - 1].Length != length)
            throw Invalid($"ADP1 V2 tag {tag} has an invalid length.");
    }

    private static void Nodes(byte[] bytes, int count, int maximum)
    {
        if (count > maximum || bytes.Length != count * 32)
            throw Invalid("ADP1 V2 Merkle node count and bytes differ.");
    }

    private static void RequireNonzero(ReadOnlySpan<byte> value, string name)
    {
        if (Zero(value)) throw Invalid($"ADP1 V2 {name} is zero.");
    }

    private static bool Zero(ReadOnlySpan<byte> value) =>
        value.IndexOfAnyExcept((byte)0) < 0;

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) => left.Length == right.Length &&
            CryptographicOperations.FixedTimeEquals(left, right);

    private static byte[] U16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    private static byte[] StandardReference(ushort type, int length,
        ReadOnlySpan<byte> hash)
    {
        var output = new byte[38];
        BinaryPrimitives.WriteUInt16BigEndian(output, type);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(2),
            checked((uint)length));
        hash.CopyTo(output.AsSpan(6));
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static byte[] Lp32(ReadOnlySpan<byte> value)
    {
        var result = new byte[checked(4 + value.Length)];
        BinaryPrimitives.WriteUInt32BigEndian(result, checked((uint)value.Length));
        value.CopyTo(result.AsSpan(4));
        return result;
    }

    private static byte[] PackRevoked(
        IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        if (values.Count > 4096)
            throw Invalid("ADP1 V2 revoked authorization count is invalid.");
        var result = new byte[checked(2 + values.Count * 32)];
        BinaryPrimitives.WriteUInt16BigEndian(result, checked((ushort)values.Count));
        for (var index = 0; index < values.Count; index++)
        {
            if (values[index].Length != 32 ||
                values[index].Span.IndexOfAnyExcept((byte)0) < 0 ||
                index > 0 && values[index - 1].Span.SequenceCompareTo(
                    values[index].Span) >= 0)
                throw Invalid("ADP1 V2 revoked IDs must be nonzero, sorted and unique.");
            values[index].Span.CopyTo(result.AsSpan(2 + index * 32));
        }
        return result;
    }

    private static ReadOnlyMemory<byte>[] ParseRevoked(ReadOnlySpan<byte> packed)
    {
        if (packed.Length < 2)
            throw Invalid("ADP1 V2 revoked list is truncated.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(packed);
        if (count > 4096 || packed.Length != checked(2 + count * 32))
            throw Invalid("ADP1 V2 revoked list length differs from its count.");
        var values = new ReadOnlyMemory<byte>[count];
        for (var index = 0; index < count; index++)
        {
            var value = packed.Slice(2 + index * 32, 32);
            if (value.IndexOfAnyExcept((byte)0) < 0 ||
                index > 0 && values[index - 1].Span.SequenceCompareTo(value) >= 0)
                throw Invalid("ADP1 V2 revoked IDs are not nonzero, sorted and unique.");
            values[index] = value.ToArray();
        }
        return values;
    }

    private static byte[] Flatten(IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        var result = new byte[checked(values.Sum(static value => value.Length))];
        var offset = 0;
        foreach (var value in values)
        {
            value.Span.CopyTo(result.AsSpan(offset));
            offset += value.Length;
        }
        return result;
    }

    private static byte[] Flatten(IReadOnlyList<byte[]> values)
    {
        var result = new byte[checked(values.Sum(static value => value.Length))];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(result, offset);
            offset += value.Length;
        }
        return result;
    }

    private static AccountDirectoryAdp1FormatException Invalid(string message) =>
        new(message);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) =>
            left.AsSpan().SequenceCompareTo(right);
    }
}
