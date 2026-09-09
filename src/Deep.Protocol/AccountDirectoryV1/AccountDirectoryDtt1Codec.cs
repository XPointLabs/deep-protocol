using System.Buffers.Binary;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryDtt1FormatException(string message) : FormatException(message);

public sealed class AccountDirectoryDtt1WitnessReceipt
{
    private readonly byte[] witnessId;
    private readonly byte[] signature;

    public AccountDirectoryDtt1WitnessReceipt(ReadOnlySpan<byte> witnessId, ReadOnlySpan<byte> signature)
    {
        if (witnessId.Length != 32 || witnessId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Witness ID must be exactly 32 non-zero bytes.", nameof(witnessId));
        if (signature.Length != 64 || signature.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Witness signature must be exactly 64 non-zero bytes.", nameof(signature));
        this.witnessId = witnessId.ToArray();
        this.signature = signature.ToArray();
    }

    public ReadOnlyMemory<byte> WitnessId => witnessId.ToArray();
    public ReadOnlyMemory<byte> Signature => signature.ToArray();
}

public sealed class AccountDirectoryDtt1
{
    private readonly byte[] networkId;
    private readonly byte[] clientNonce;
    private readonly byte[] currentAdh1CoreHash;
    private readonly byte[] currentXnv1CoreHash;
    private readonly byte[] authorizingXna1CoreReference;
    private readonly byte[] witnessPolicyHash;
    private readonly byte[] issuanceEpochId;
    private readonly AccountDirectoryDtt1WitnessReceipt[] witnesses;

    public AccountDirectoryDtt1(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> clientNonce,
        ulong observedUnixTime,
        uint uncertaintySeconds,
        ReadOnlySpan<byte> currentAdh1CoreHash,
        ulong currentAdh1Generation,
        ReadOnlySpan<byte> currentXnv1CoreHash,
        ulong currentXnv1Generation,
        ReadOnlySpan<byte> authorizingXna1CoreReference,
        ReadOnlySpan<byte> witnessPolicyHash,
        ulong issuedAt,
        ulong expiresAt,
        ReadOnlySpan<byte> issuanceEpochId,
        IReadOnlyList<AccountDirectoryDtt1WitnessReceipt> witnesses)
    {
        this.networkId = Required(networkId, 16, nameof(networkId));
        this.clientNonce = Required(clientNonce, 32, nameof(clientNonce));
        ObservedUnixTime = observedUnixTime;
        if (uncertaintySeconds > 30)
            throw new ArgumentOutOfRangeException(nameof(uncertaintySeconds));
        UncertaintySeconds = uncertaintySeconds;
        this.currentAdh1CoreHash = Required(currentAdh1CoreHash, 32, nameof(currentAdh1CoreHash));
        CurrentAdh1Generation = currentAdh1Generation;
        this.currentXnv1CoreHash = Required(currentXnv1CoreHash, 32, nameof(currentXnv1CoreHash));
        CurrentXnv1Generation = currentXnv1Generation;
        this.authorizingXna1CoreReference = Required(authorizingXna1CoreReference, 38, nameof(authorizingXna1CoreReference));
        ValidateReference(this.authorizingXna1CoreReference, ProtocolMagicBytes.XNA1, nameof(authorizingXna1CoreReference));
        this.witnessPolicyHash = Required(witnessPolicyHash, 32, nameof(witnessPolicyHash));
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        if (AbsoluteDistance(observedUnixTime, issuedAt) > uncertaintySeconds)
            throw new ArgumentException("DTT1 issued-at is outside the observed uncertainty interval.", nameof(issuedAt));
        if (expiresAt <= issuedAt || expiresAt - issuedAt > 60)
            throw new ArgumentException("DTT1 expiry must be after issued-at and at most 60 seconds later.", nameof(expiresAt));
        this.issuanceEpochId = Required(issuanceEpochId, 32, nameof(issuanceEpochId));
        ArgumentNullException.ThrowIfNull(witnesses);
        if (witnesses.Count is < 1 or > 32)
            throw new ArgumentException("DTT1 requires between one and 32 witness receipts.", nameof(witnesses));
        this.witnesses = new AccountDirectoryDtt1WitnessReceipt[witnesses.Count];
        ReadOnlySpan<byte> previous = default;
        for (var index = 0; index < witnesses.Count; index++)
        {
            ArgumentNullException.ThrowIfNull(witnesses[index]);
            var copy = new AccountDirectoryDtt1WitnessReceipt(
                witnesses[index].WitnessId.Span,
                witnesses[index].Signature.Span);
            if (!previous.IsEmpty && previous.SequenceCompareTo(copy.WitnessId.Span) >= 0)
                throw new ArgumentException("DTT1 witness IDs must be strictly increasing.", nameof(witnesses));
            this.witnesses[index] = copy;
            previous = copy.WitnessId.Span;
        }
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> ClientNonce => clientNonce.ToArray();
    public ulong ObservedUnixTime { get; }
    public uint UncertaintySeconds { get; }
    public ReadOnlyMemory<byte> CurrentAdh1CoreHash => currentAdh1CoreHash.ToArray();
    public ulong CurrentAdh1Generation { get; }
    public ReadOnlyMemory<byte> CurrentXnv1CoreHash => currentXnv1CoreHash.ToArray();
    public ulong CurrentXnv1Generation { get; }
    public ReadOnlyMemory<byte> AuthorizingXna1CoreReference => authorizingXna1CoreReference.ToArray();
    public ReadOnlyMemory<byte> WitnessPolicyHash => witnessPolicyHash.ToArray();
    public ulong IssuedAt { get; }
    public ulong ExpiresAt { get; }
    public ReadOnlyMemory<byte> IssuanceEpochId => issuanceEpochId.ToArray();
    public IReadOnlyList<AccountDirectoryDtt1WitnessReceipt> Witnesses => witnesses.ToArray();

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }

    private static ulong AbsoluteDistance(ulong left, ulong right) =>
        left >= right ? left - right : right - left;

    private static void ValidateReference(ReadOnlySpan<byte> value, ReadOnlySpan<byte> magic, string name)
    {
        if (!value[..4].SequenceEqual(magic) || BinaryPrimitives.ReadUInt16BigEndian(value[4..]) != 1)
            throw new ArgumentException($"{name} has the wrong typed reference.", name);
    }
}

public static class AccountDirectoryDtt1Codec
{
    public const ushort Version = 1;
    public const ushort Suite = 0x0201;
    public const ushort FieldCount = 15;
    private const int HeaderSize = 12;
    private static readonly int[] FixedLengths = [16, 32, 8, 4, 32, 8, 32, 8, 38, 32, 8, 8, 32, 1];

    public static byte[] Encode(AccountDirectoryDtt1 value) => EncodeCore(value, FieldCount);
    public static byte[] EncodeUnsigned(AccountDirectoryDtt1 value) => EncodeCore(value, 13);

    public static AccountDirectoryDtt1 Decode(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length is < HeaderSize or > 65_535 || !canonical[..4].SequenceEqual(ProtocolMagicBytes.DTT1) ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[4..]) != Version ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[6..]) != Suite ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[8..]) != FieldCount ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[10..]) != 0)
            Reject("DTT1 header is invalid.");

        var fields = new byte[FieldCount][];
        var offset = HeaderSize;
        for (var index = 0; index < FieldCount; index++)
        {
            if (canonical.Length - offset < 8 ||
                BinaryPrimitives.ReadUInt16BigEndian(canonical[offset..]) != index + 1 ||
                BinaryPrimitives.ReadUInt16BigEndian(canonical[(offset + 2)..]) != 0)
                Reject("DTT1 field header is invalid.");
            var declared = BinaryPrimitives.ReadUInt32BigEndian(canonical[(offset + 4)..]);
            var expected = index < 14 ? FixedLengths[index] : checked(fields[13][0] * 96);
            if (declared != (uint)expected)
                Reject("DTT1 field length is invalid.");
            offset += 8;
            if (canonical.Length - offset < expected)
                Reject("DTT1 field is truncated.");
            fields[index] = canonical.Slice(offset, expected).ToArray();
            offset += expected;
        }
        if (offset != canonical.Length)
            Reject("DTT1 contains trailing bytes.");

        var receipts = new AccountDirectoryDtt1WitnessReceipt[fields[13][0]];
        try
        {
            for (var index = 0; index < receipts.Length; index++)
            {
                var entry = fields[14].AsSpan(index * 96, 96);
                receipts[index] = new AccountDirectoryDtt1WitnessReceipt(entry[..32], entry[32..]);
            }
            return new AccountDirectoryDtt1(
                fields[0], fields[1], BinaryPrimitives.ReadUInt64BigEndian(fields[2]),
                BinaryPrimitives.ReadUInt32BigEndian(fields[3]), fields[4],
                BinaryPrimitives.ReadUInt64BigEndian(fields[5]), fields[6],
                BinaryPrimitives.ReadUInt64BigEndian(fields[7]), fields[8], fields[9],
                BinaryPrimitives.ReadUInt64BigEndian(fields[10]),
                BinaryPrimitives.ReadUInt64BigEndian(fields[11]), fields[12], receipts);
        }
        catch (ArgumentException exception)
        {
            throw new AccountDirectoryDtt1FormatException(exception.Message);
        }
    }

    private static byte[] EncodeCore(AccountDirectoryDtt1 value, ushort fieldCount)
    {
        ArgumentNullException.ThrowIfNull(value);
        var receipts = new byte[checked(value.Witnesses.Count * 96)];
        for (var index = 0; index < value.Witnesses.Count; index++)
        {
            value.Witnesses[index].WitnessId.Span.CopyTo(receipts.AsSpan(index * 96, 32));
            value.Witnesses[index].Signature.Span.CopyTo(receipts.AsSpan(index * 96 + 32, 64));
        }
        byte[][] fields =
        [
            value.NetworkId.ToArray(), value.ClientNonce.ToArray(), U64(value.ObservedUnixTime), U32(value.UncertaintySeconds),
            value.CurrentAdh1CoreHash.ToArray(), U64(value.CurrentAdh1Generation), value.CurrentXnv1CoreHash.ToArray(),
            U64(value.CurrentXnv1Generation), value.AuthorizingXna1CoreReference.ToArray(), value.WitnessPolicyHash.ToArray(),
            U64(value.IssuedAt), U64(value.ExpiresAt), value.IssuanceEpochId.ToArray(),
            [checked((byte)value.Witnesses.Count)], receipts
        ];
        var selected = fields.Take(fieldCount).ToArray();
        var result = new byte[checked(HeaderSize + selected.Sum(static field => 8 + field.Length))];
        ProtocolMagicBytes.DTT1.CopyTo(result);
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

    private static byte[] U32(uint value)
    {
        var result = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static void Reject(string message) => throw new AccountDirectoryDtt1FormatException(message);
}
