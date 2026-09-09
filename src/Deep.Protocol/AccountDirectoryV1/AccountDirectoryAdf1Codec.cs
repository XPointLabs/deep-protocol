using System.Buffers.Binary;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryAdf1FormatException(string message) : FormatException(message);

public sealed class AccountDirectoryAdf1RootReceipt
{
    private readonly byte[] rootKeyId;
    private readonly byte[] signature;

    public AccountDirectoryAdf1RootReceipt(ReadOnlySpan<byte> rootKeyId, ReadOnlySpan<byte> signature)
    {
        this.rootKeyId = Required(rootKeyId, 32, nameof(rootKeyId));
        this.signature = Required(signature, 64, nameof(signature));
    }

    public ReadOnlyMemory<byte> RootKeyId => rootKeyId.ToArray();
    public ReadOnlyMemory<byte> Signature => signature.ToArray();

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }
}

public sealed class AccountDirectoryAdf1
{
    private readonly byte[] networkId;
    private readonly byte[] predecessorCoreHash;
    private readonly byte[] coveredHeadMerkleRoot;
    private readonly byte[] targetAdh1CoreReference;
    private readonly byte[] targetAppendLogRoot;
    private readonly byte[] targetCurrentValueMapRoot;
    private readonly byte[] authorityXnaCoreReference;
    private readonly AccountDirectoryAdf1RootReceipt[] receipts;

    public AccountDirectoryAdf1(
        ReadOnlySpan<byte> networkId,
        ulong checkpointGeneration,
        ReadOnlySpan<byte> predecessorCoreHash,
        ulong coveredFirstAdhGeneration,
        ulong coveredLastAdhGeneration,
        ulong coveredHeadCount,
        ReadOnlySpan<byte> coveredHeadMerkleRoot,
        ReadOnlySpan<byte> targetAdh1CoreReference,
        ulong targetTreeSize,
        ReadOnlySpan<byte> targetAppendLogRoot,
        ReadOnlySpan<byte> targetCurrentValueMapRoot,
        ReadOnlySpan<byte> authorityXnaCoreReference,
        ulong issuedAt,
        ushort minimumReader,
        IReadOnlyList<AccountDirectoryAdf1RootReceipt> receipts)
    {
        this.networkId = Required(networkId, 16, nameof(networkId));
        CheckpointGeneration = checkpointGeneration;
        this.predecessorCoreHash = Exact(predecessorCoreHash, 32, nameof(predecessorCoreHash));
        if (checkpointGeneration == 0 ? !IsZero(this.predecessorCoreHash) : IsZero(this.predecessorCoreHash))
            throw new ArgumentException("ADF1 predecessor is zero exactly at generation zero.", nameof(predecessorCoreHash));
        if (coveredLastAdhGeneration < coveredFirstAdhGeneration || coveredHeadCount == 0)
            throw new ArgumentException("ADF1 covered-head range or count is invalid.");
        CoveredFirstAdhGeneration = coveredFirstAdhGeneration;
        CoveredLastAdhGeneration = coveredLastAdhGeneration;
        CoveredHeadCount = coveredHeadCount;
        this.coveredHeadMerkleRoot = Required(coveredHeadMerkleRoot, 32, nameof(coveredHeadMerkleRoot));
        this.targetAdh1CoreReference = Reference(targetAdh1CoreReference, ProtocolMagic.ADH1, nameof(targetAdh1CoreReference));
        TargetTreeSize = targetTreeSize;
        this.targetAppendLogRoot = Required(targetAppendLogRoot, 32, nameof(targetAppendLogRoot));
        this.targetCurrentValueMapRoot = Required(targetCurrentValueMapRoot, 32, nameof(targetCurrentValueMapRoot));
        this.authorityXnaCoreReference = Reference(authorityXnaCoreReference, ProtocolMagic.XNA1, nameof(authorityXnaCoreReference));
        IssuedAt = issuedAt;
        MinimumReader = minimumReader;
        ArgumentNullException.ThrowIfNull(receipts);
        if (receipts.Count is < 1 or > 8)
            throw new ArgumentException("ADF1 requires between one and eight root receipts.", nameof(receipts));
        this.receipts = new AccountDirectoryAdf1RootReceipt[receipts.Count];
        ReadOnlySpan<byte> previous = default;
        for (var index = 0; index < receipts.Count; index++)
        {
            ArgumentNullException.ThrowIfNull(receipts[index]);
            var copy = new AccountDirectoryAdf1RootReceipt(receipts[index].RootKeyId.Span, receipts[index].Signature.Span);
            if (!previous.IsEmpty && previous.SequenceCompareTo(copy.RootKeyId.Span) >= 0)
                throw new ArgumentException("ADF1 root receipt IDs must be strictly increasing.", nameof(receipts));
            this.receipts[index] = copy;
            previous = copy.RootKeyId.Span;
        }
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong CheckpointGeneration { get; }
    public ReadOnlyMemory<byte> PredecessorCoreHash => predecessorCoreHash.ToArray();
    public ulong CoveredFirstAdhGeneration { get; }
    public ulong CoveredLastAdhGeneration { get; }
    public ulong CoveredHeadCount { get; }
    public ReadOnlyMemory<byte> CoveredHeadMerkleRoot => coveredHeadMerkleRoot.ToArray();
    public ReadOnlyMemory<byte> TargetAdh1CoreReference => targetAdh1CoreReference.ToArray();
    public ulong TargetTreeSize { get; }
    public ReadOnlyMemory<byte> TargetAppendLogRoot => targetAppendLogRoot.ToArray();
    public ReadOnlyMemory<byte> TargetCurrentValueMapRoot => targetCurrentValueMapRoot.ToArray();
    public ReadOnlyMemory<byte> AuthorityXnaCoreReference => authorityXnaCoreReference.ToArray();
    public ulong IssuedAt { get; }
    public ushort MinimumReader { get; }
    public IReadOnlyList<AccountDirectoryAdf1RootReceipt> Receipts => receipts.ToArray();

    private static byte[] Exact(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw new ArgumentException($"{name} must be exactly {length} bytes.", name);
        return value.ToArray();
    }

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        var result = Exact(value, length, name);
        if (IsZero(result))
            throw new ArgumentException($"{name} must be non-zero.", name);
        return result;
    }

    private static byte[] Reference(ReadOnlySpan<byte> value, ReadOnlySpan<char> magic, string name)
    {
        var result = Exact(value, 38, name);
        for (var index = 0; index < 4; index++)
            if (result[index] != (byte)magic[index])
                throw new ArgumentException($"{name} has the wrong magic.", name);
        if (BinaryPrimitives.ReadUInt16BigEndian(result.AsSpan(4)) != 1 || IsZero(result.AsSpan(6)))
            throw new ArgumentException($"{name} is not a non-zero version-1 reference.", name);
        return result;
    }

    private static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;
}

public static class AccountDirectoryAdf1Codec
{
    public const ushort Version = 1;
    public const ushort Suite = 0x0001;
    public const ushort FieldCount = 16;
    private const int HeaderSize = 12;
    private static readonly int[] FixedLengths = [16, 8, 32, 8, 8, 8, 32, 38, 8, 32, 32, 38, 8, 2, 1, -1];

    public static byte[] Encode(AccountDirectoryAdf1 value) => EncodeCore(value, FieldCount);
    public static byte[] EncodeUnsigned(AccountDirectoryAdf1 value) => EncodeCore(value, 14);

    public static AccountDirectoryAdf1 Decode(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length < HeaderSize || canonical.Length > 65_535 || !canonical[..4].SequenceEqual(ProtocolMagicBytes.ADF1) ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[4..]) != Version ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[6..]) != Suite ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[8..]) != FieldCount ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[10..]) != 0)
            Reject("ADF1 header is invalid.");
        var fields = new byte[FieldCount][];
        var offset = HeaderSize;
        for (var index = 0; index < FieldCount; index++)
        {
            if (canonical.Length - offset < 8 || BinaryPrimitives.ReadUInt16BigEndian(canonical[offset..]) != index + 1 ||
                BinaryPrimitives.ReadUInt16BigEndian(canonical[(offset + 2)..]) != 0)
                Reject("ADF1 field header is invalid.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(canonical[(offset + 4)..]);
            var expected = index == 15 && fields[14] is not null ? checked(fields[14][0] * 96) : FixedLengths[index];
            if (expected < 0 || length != (uint)expected)
                Reject("ADF1 field length is invalid.");
            offset += 8;
            if (canonical.Length - offset < expected)
                Reject("ADF1 field is truncated.");
            fields[index] = canonical.Slice(offset, expected).ToArray();
            offset += expected;
        }
        if (offset != canonical.Length)
            Reject("ADF1 contains trailing bytes.");
        try
        {
            var receipts = new AccountDirectoryAdf1RootReceipt[fields[14][0]];
            for (var index = 0; index < receipts.Length; index++)
            {
                var item = fields[15].AsSpan(index * 96, 96);
                receipts[index] = new AccountDirectoryAdf1RootReceipt(item[..32], item[32..]);
            }
            return new AccountDirectoryAdf1(fields[0], U64(fields[1]), fields[2], U64(fields[3]), U64(fields[4]),
                U64(fields[5]), fields[6], fields[7], U64(fields[8]), fields[9], fields[10], fields[11],
                U64(fields[12]), U16(fields[13]), receipts);
        }
        catch (ArgumentException exception)
        {
            throw new AccountDirectoryAdf1FormatException(exception.Message);
        }
    }

    private static byte[] EncodeCore(AccountDirectoryAdf1 value, ushort fieldCount)
    {
        ArgumentNullException.ThrowIfNull(value);
        var receiptBytes = new byte[checked(value.Receipts.Count * 96)];
        for (var index = 0; index < value.Receipts.Count; index++)
        {
            value.Receipts[index].RootKeyId.Span.CopyTo(receiptBytes.AsSpan(index * 96, 32));
            value.Receipts[index].Signature.Span.CopyTo(receiptBytes.AsSpan(index * 96 + 32, 64));
        }
        byte[][] fields =
        [
            value.NetworkId.ToArray(), Be64(value.CheckpointGeneration), value.PredecessorCoreHash.ToArray(),
            Be64(value.CoveredFirstAdhGeneration), Be64(value.CoveredLastAdhGeneration), Be64(value.CoveredHeadCount),
            value.CoveredHeadMerkleRoot.ToArray(), value.TargetAdh1CoreReference.ToArray(), Be64(value.TargetTreeSize),
            value.TargetAppendLogRoot.ToArray(), value.TargetCurrentValueMapRoot.ToArray(), value.AuthorityXnaCoreReference.ToArray(),
            Be64(value.IssuedAt), Be16(value.MinimumReader), [checked((byte)value.Receipts.Count)], receiptBytes
        ];
        var selected = fields.Take(fieldCount).ToArray();
        var result = new byte[checked(HeaderSize + selected.Sum(static field => 8 + field.Length))];
        ProtocolMagicBytes.ADF1.CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), Version);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), Suite);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8), fieldCount);
        var offset = HeaderSize;
        for (var index = 0; index < selected.Length; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset + 4), checked((uint)selected[index].Length));
            offset += 8;
            selected[index].CopyTo(result, offset);
            offset += selected[index].Length;
        }
        return result;
    }

    private static ushort U16(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt16BigEndian(value);
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    private static byte[] Be16(ushort value) { var result = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(result, value); return result; }
    private static byte[] Be64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
    private static void Reject(string message) => throw new AccountDirectoryAdf1FormatException(message);
}
