using System.Buffers.Binary;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryAdc1FormatException(string message) : FormatException(message);

public sealed class AccountDirectoryAdc1
{
    private readonly byte[] networkId;
    private readonly byte[] directoryLeafKey;
    private readonly byte[] predecessorCheckpointHash;
    private readonly byte[] exactDpa1Reference;
    private readonly byte[] exactDrs1Reference;
    private readonly byte[] exactDmd1Hash;
    private readonly byte[] exactDab1Hash;
    private readonly byte[] revokedDcaAuthorizationIdsHash;
    private readonly byte[] deviceIssuerSignature;

    public AccountDirectoryAdc1(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> directoryLeafKey,
        ulong accountGeneration,
        ulong checkpointGeneration,
        ReadOnlySpan<byte> predecessorCheckpointHash,
        ReadOnlySpan<byte> exactDpa1Reference,
        ReadOnlySpan<byte> exactDrs1Reference,
        ReadOnlySpan<byte> exactDmd1Hash,
        ReadOnlySpan<byte> exactDab1Hash,
        ReadOnlySpan<byte> revokedDcaAuthorizationIdsHash,
        ulong issuedAt,
        ushort minimumReader,
        ReadOnlySpan<byte> deviceIssuerSignature)
        : this(
            networkId, directoryLeafKey, accountGeneration, checkpointGeneration,
            predecessorCheckpointHash, exactDpa1Reference, exactDrs1Reference,
            exactDmd1Hash, exactDab1Hash, revokedDcaAuthorizationIdsHash,
            issuedAt, minimumReader, deviceIssuerSignature, allowUnsigned: false)
    {
    }

    private AccountDirectoryAdc1(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> directoryLeafKey,
        ulong accountGeneration,
        ulong checkpointGeneration,
        ReadOnlySpan<byte> predecessorCheckpointHash,
        ReadOnlySpan<byte> exactDpa1Reference,
        ReadOnlySpan<byte> exactDrs1Reference,
        ReadOnlySpan<byte> exactDmd1Hash,
        ReadOnlySpan<byte> exactDab1Hash,
        ReadOnlySpan<byte> revokedDcaAuthorizationIdsHash,
        ulong issuedAt,
        ushort minimumReader,
        ReadOnlySpan<byte> deviceIssuerSignature,
        bool allowUnsigned)
    {
        this.networkId = Copy(networkId, 16, nameof(networkId));
        this.directoryLeafKey = Copy(directoryLeafKey, 32, nameof(directoryLeafKey));
        AccountGeneration = accountGeneration;
        CheckpointGeneration = checkpointGeneration;
        this.predecessorCheckpointHash = Copy(predecessorCheckpointHash, 32, nameof(predecessorCheckpointHash));
        this.exactDpa1Reference = Copy(exactDpa1Reference, 38, nameof(exactDpa1Reference));
        this.exactDrs1Reference = Copy(exactDrs1Reference, 38, nameof(exactDrs1Reference));
        ValidateReference(this.exactDpa1Reference, ProtocolMagic.DPA1, nameof(exactDpa1Reference));
        ValidateReference(this.exactDrs1Reference, ProtocolMagic.DRS1, nameof(exactDrs1Reference));
        this.exactDmd1Hash = Copy(exactDmd1Hash, 32, nameof(exactDmd1Hash));
        this.exactDab1Hash = Copy(exactDab1Hash, 32, nameof(exactDab1Hash));
        this.revokedDcaAuthorizationIdsHash = Copy(revokedDcaAuthorizationIdsHash, 32, nameof(revokedDcaAuthorizationIdsHash));
        IssuedAt = issuedAt;
        MinimumReader = minimumReader;
        this.deviceIssuerSignature = Copy(deviceIssuerSignature, 64, nameof(deviceIssuerSignature));
        if (IsZero(this.networkId) || IsZero(this.directoryLeafKey) || accountGeneration == 0 ||
            (checkpointGeneration == 0 ? !IsZero(this.predecessorCheckpointHash) : IsZero(this.predecessorCheckpointHash)) ||
            IsZero(this.exactDmd1Hash) || IsZero(this.exactDab1Hash) ||
            IsZero(this.revokedDcaAuthorizationIdsHash) || (!allowUnsigned && IsZero(this.deviceIssuerSignature)))
        {
            throw new ArgumentException("ADC1 contains a zero forbidden value or invalid predecessor generation.");
        }
    }

    internal static AccountDirectoryAdc1 CreateUnsigned(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> directoryLeafKey,
        ulong accountGeneration,
        ulong checkpointGeneration,
        ReadOnlySpan<byte> predecessorCheckpointHash,
        ReadOnlySpan<byte> exactDpa1Reference,
        ReadOnlySpan<byte> exactDrs1Reference,
        ReadOnlySpan<byte> exactDmd1Hash,
        ReadOnlySpan<byte> exactDab1Hash,
        ReadOnlySpan<byte> revokedDcaAuthorizationIdsHash,
        ulong issuedAt,
        ushort minimumReader) =>
        new(
            networkId, directoryLeafKey, accountGeneration, checkpointGeneration,
            predecessorCheckpointHash, exactDpa1Reference, exactDrs1Reference,
            exactDmd1Hash, exactDab1Hash, revokedDcaAuthorizationIdsHash,
            issuedAt, minimumReader, new byte[64], allowUnsigned: true);

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> DirectoryLeafKey => directoryLeafKey.ToArray();
    public ulong AccountGeneration { get; }
    public ulong CheckpointGeneration { get; }
    public ReadOnlyMemory<byte> PredecessorCheckpointHash => predecessorCheckpointHash.ToArray();
    public ReadOnlyMemory<byte> ExactDpa1Reference => exactDpa1Reference.ToArray();
    public ReadOnlyMemory<byte> ExactDrs1Reference => exactDrs1Reference.ToArray();
    public ReadOnlyMemory<byte> ExactDmd1Hash => exactDmd1Hash.ToArray();
    public ReadOnlyMemory<byte> ExactDab1Hash => exactDab1Hash.ToArray();
    public ReadOnlyMemory<byte> RevokedDcaAuthorizationIdsHash => revokedDcaAuthorizationIdsHash.ToArray();
    public ulong IssuedAt { get; }
    public ushort MinimumReader { get; }
    public ReadOnlyMemory<byte> DeviceIssuerSignature => deviceIssuerSignature.ToArray();

    private static byte[] Copy(ReadOnlySpan<byte> value, int expectedLength, string name)
    {
        if (value.Length != expectedLength)
            throw new ArgumentException($"{name} must be exactly {expectedLength} bytes.", name);
        return value.ToArray();
    }

    private static void ValidateReference(ReadOnlySpan<byte> value, ReadOnlySpan<char> magic, string name)
    {
        Span<byte> expectedMagic = stackalloc byte[4];
        for (var index = 0; index < expectedMagic.Length; index++)
            expectedMagic[index] = checked((byte)magic[index]);
        if (!value[..4].SequenceEqual(expectedMagic) ||
            BinaryPrimitives.ReadUInt16BigEndian(value[4..]) != 1 ||
            value[6..].IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"{name} must be a non-zero {magic.ToString()} version-1 reference.", name);
        }
    }

    private static bool IsZero(ReadOnlySpan<byte> value) =>
        value.IndexOfAnyExcept((byte)0) < 0;
}

public static class AccountDirectoryAdc1Codec
{
    public const ushort Version = 1;
    public const ushort Suite = 0x0201;
    public const ushort FieldCount = 13;
    private const int HeaderSize = 12;
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.ADC1;
    private static ReadOnlySpan<int> FieldLengths => [16, 32, 8, 8, 32, 38, 38, 32, 32, 32, 8, 2, 64];

    public static byte[] Encode(AccountDirectoryAdc1 value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return EncodeCore(value, includeSignature: true);
    }

    public static byte[] EncodeUnsigned(AccountDirectoryAdc1 value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return EncodeCore(value, includeSignature: false);
    }

    /// <summary>
    /// Creates the exact domain-framed bytes that the DPA1 device-issuer account
    /// role signs when authoring ADC1. This is the production authoring entry point:
    /// callers never need to construct an ADC1 with a placeholder signature.
    /// </summary>
    public static byte[] CreateDeviceIssuerSigningInput(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> directoryLeafKey,
        ulong accountGeneration,
        ulong checkpointGeneration,
        ReadOnlySpan<byte> predecessorCheckpointHash,
        ReadOnlySpan<byte> exactDpa1Reference,
        ReadOnlySpan<byte> exactDrs1Reference,
        ReadOnlySpan<byte> exactDmd1Hash,
        ReadOnlySpan<byte> exactDab1Hash,
        ReadOnlySpan<byte> revokedDcaAuthorizationIdsHash,
        ulong issuedAt,
        ushort minimumReader)
    {
        var unsigned = AccountDirectoryAdc1.CreateUnsigned(
            networkId, directoryLeafKey, accountGeneration, checkpointGeneration,
            predecessorCheckpointHash, exactDpa1Reference, exactDrs1Reference,
            exactDmd1Hash, exactDab1Hash, revokedDcaAuthorizationIdsHash,
            issuedAt, minimumReader);
        return AccountDirectoryCrypto.ComputeAdc1SigningInput(unsigned);
    }

    public static AccountDirectoryAdc1 Decode(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length < HeaderSize)
            Reject("ADC1 header is truncated.");
        if (!canonical[..4].SequenceEqual(Magic))
            Reject("ADC1 magic is invalid.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[4..]) != Version)
            Reject("ADC1 version is unsupported.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[6..]) != Suite)
            Reject("ADC1 suite is unsupported.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[8..]) != FieldCount)
            Reject("ADC1 field count is invalid.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[10..]) != 0)
            Reject("ADC1 header reserved value is non-zero.");

        var fields = new byte[FieldCount][];
        var offset = HeaderSize;
        for (var index = 0; index < FieldCount; index++)
        {
            if (canonical.Length - offset < 8)
                Reject("ADC1 field header is truncated.");
            var tag = BinaryPrimitives.ReadUInt16BigEndian(canonical[offset..]);
            if (tag != index + 1)
                Reject("ADC1 tags must be consecutive and ordered.");
            if (BinaryPrimitives.ReadUInt16BigEndian(canonical[(offset + 2)..]) != 0)
                Reject("ADC1 field reserved value is non-zero.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(canonical[(offset + 4)..]);
            var expectedLength = FieldLengths[index];
            if (length != (uint)expectedLength)
                Reject("ADC1 field length is invalid.");
            offset += 8;
            if (canonical.Length - offset < expectedLength)
                Reject("ADC1 field value is truncated.");
            fields[index] = canonical.Slice(offset, expectedLength).ToArray();
            offset += expectedLength;
        }

        if (offset != canonical.Length)
            Reject("ADC1 contains trailing bytes.");

        try
        {
            return new AccountDirectoryAdc1(
                fields[0], fields[1],
                BinaryPrimitives.ReadUInt64BigEndian(fields[2]),
                BinaryPrimitives.ReadUInt64BigEndian(fields[3]),
                fields[4], fields[5], fields[6], fields[7], fields[8], fields[9],
                BinaryPrimitives.ReadUInt64BigEndian(fields[10]),
                BinaryPrimitives.ReadUInt16BigEndian(fields[11]), fields[12]);
        }
        catch (ArgumentException exception)
        {
            throw new AccountDirectoryAdc1FormatException(exception.Message);
        }
    }

    private static byte[] EncodeCore(AccountDirectoryAdc1 value, bool includeSignature)
    {
        var fields = new byte[FieldCount][];
        fields[0] = value.NetworkId.ToArray();
        fields[1] = value.DirectoryLeafKey.ToArray();
        fields[2] = U64(value.AccountGeneration);
        fields[3] = U64(value.CheckpointGeneration);
        fields[4] = value.PredecessorCheckpointHash.ToArray();
        fields[5] = value.ExactDpa1Reference.ToArray();
        fields[6] = value.ExactDrs1Reference.ToArray();
        fields[7] = value.ExactDmd1Hash.ToArray();
        fields[8] = value.ExactDab1Hash.ToArray();
        fields[9] = value.RevokedDcaAuthorizationIdsHash.ToArray();
        fields[10] = U64(value.IssuedAt);
        fields[11] = U16(value.MinimumReader);
        fields[12] = value.DeviceIssuerSignature.ToArray();

        var count = includeSignature ? FieldCount : (ushort)(FieldCount - 1);
        var totalLength = HeaderSize + fields.Take(count).Sum(field => 8 + field.Length);
        var result = new byte[totalLength];
        Magic.CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), Version);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), Suite);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8), count);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(10), 0);
        var offset = HeaderSize;
        for (var index = 0; index < count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 2), 0);
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].CopyTo(result, offset);
            offset += fields[index].Length;
        }
        return result;
    }

    private static byte[] U16(ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static void Reject(string message) => throw new AccountDirectoryAdc1FormatException(message);
}
