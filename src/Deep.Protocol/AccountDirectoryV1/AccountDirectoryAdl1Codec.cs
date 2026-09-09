using System.Buffers.Binary;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryAdl1FormatException(string message) : FormatException(message);

public sealed class AccountDirectoryAdl1
{
    private readonly byte[] networkId;
    private readonly byte[] directoryLookupKey;
    private readonly byte[] minimumAdhHash;
    private readonly byte[] exactOhttpXod1CoreReference;
    private readonly byte[] exactOhttpXod1CoreHash;

    public AccountDirectoryAdl1(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> directoryLookupKey,
        ulong minimumAdhGeneration,
        ReadOnlySpan<byte> minimumAdhHash,
        ushort serviceProfile,
        ReadOnlySpan<byte> exactOhttpXod1CoreReference,
        ReadOnlySpan<byte> exactOhttpXod1CoreHash)
    {
        this.networkId = Copy(networkId, 16, nameof(networkId));
        this.directoryLookupKey = Copy(directoryLookupKey, 32, nameof(directoryLookupKey));
        MinimumAdhGeneration = minimumAdhGeneration;
        this.minimumAdhHash = Copy(minimumAdhHash, 32, nameof(minimumAdhHash));
        ServiceProfile = serviceProfile;
        this.exactOhttpXod1CoreReference = Copy(exactOhttpXod1CoreReference, 38, nameof(exactOhttpXod1CoreReference));
        this.exactOhttpXod1CoreHash = Copy(exactOhttpXod1CoreHash, 32, nameof(exactOhttpXod1CoreHash));
        if (IsZero(this.networkId) || IsZero(this.directoryLookupKey) || IsZero(this.minimumAdhHash))
            throw new ArgumentException("ADL1 network, lookup key, and ADH floor hash must be non-zero.");
        ValidateProfile(ServiceProfile, this.exactOhttpXod1CoreReference, this.exactOhttpXod1CoreHash);
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> DirectoryLookupKey => directoryLookupKey.ToArray();
    public ulong MinimumAdhGeneration { get; }
    public ReadOnlyMemory<byte> MinimumAdhHash => minimumAdhHash.ToArray();
    public ushort ServiceProfile { get; }
    public ReadOnlyMemory<byte> ExactOhttpXod1CoreReference => exactOhttpXod1CoreReference.ToArray();
    public ReadOnlyMemory<byte> ExactOhttpXod1CoreHash => exactOhttpXod1CoreHash.ToArray();

    private static byte[] Copy(ReadOnlySpan<byte> value, int expectedLength, string name)
    {
        if (value.Length != expectedLength)
            throw new ArgumentException($"{name} must be exactly {expectedLength} bytes.", name);
        return value.ToArray();
    }

    private static void ValidateProfile(ushort profile, ReadOnlySpan<byte> reference, ReadOnlySpan<byte> hash)
    {
        if (profile is < 1 or > 3)
            throw new ArgumentException("serviceProfile must be 1, 2, or 3.", nameof(profile));
        var referenceIsZero = IsZero(reference);
        var hashIsZero = IsZero(hash);
        if (profile == 1)
        {
            if (!referenceIsZero || !hashIsZero)
                throw new ArgumentException("XOD1 fields must be zero for serviceProfile 1.", nameof(profile));
            return;
        }
        if (referenceIsZero || hashIsZero)
            throw new ArgumentException("XOD1 fields must be non-zero for serviceProfile 2 or 3.", nameof(profile));
        if (!reference[..4].SequenceEqual(ProtocolMagicBytes.XOD1) ||
            BinaryPrimitives.ReadUInt16BigEndian(reference[4..]) != 1 ||
            !reference[6..].SequenceEqual(hash))
            throw new ArgumentException("XOD1 reference and hash are inconsistent.", nameof(reference));
    }

    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        foreach (var item in value)
            if (item != 0)
                return false;
        return true;
    }
}

public static class AccountDirectoryAdl1Codec
{
    public const ushort Version = 1;
    public const ushort Suite = 0x0201;
    public const ushort FieldCount = 7;
    private const int HeaderSize = 12;
    private static readonly int[] FieldLengths = [16, 32, 8, 32, 2, 38, 32];
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.ADL1;

    public static byte[] Encode(AccountDirectoryAdl1 value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var fields = Fields(value);
        var result = new byte[HeaderSize + fields.Sum(field => 8 + field.Length)];
        Magic.CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), Version);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), Suite);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8), FieldCount);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(10), 0);
        WriteFields(result, fields);
        return result;
    }

    public static AccountDirectoryAdl1 Decode(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length < HeaderSize)
            Reject("ADL1 header is truncated.");
        if (!canonical[..4].SequenceEqual(Magic))
            Reject("ADL1 magic is invalid.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[4..]) != Version)
            Reject("ADL1 version is unsupported.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[6..]) != Suite)
            Reject("ADL1 suite is unsupported.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[8..]) != FieldCount ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[10..]) != 0)
            Reject("ADL1 header fields are invalid.");

        var fields = new byte[FieldCount][];
        var offset = HeaderSize;
        for (var index = 0; index < FieldCount; index++)
        {
            if (canonical.Length - offset < 8)
                Reject("ADL1 field header is truncated.");
            if (BinaryPrimitives.ReadUInt16BigEndian(canonical[offset..]) != index + 1)
                Reject("ADL1 tags must be consecutive and ordered.");
            if (BinaryPrimitives.ReadUInt16BigEndian(canonical[(offset + 2)..]) != 0)
                Reject("ADL1 field reserved value is non-zero.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(canonical[(offset + 4)..]);
            var expectedLength = FieldLengths[index];
            if (length != (uint)expectedLength)
                Reject("ADL1 field length is invalid.");
            offset += 8;
            if (canonical.Length - offset < expectedLength)
                Reject("ADL1 field value is truncated.");
            fields[index] = canonical.Slice(offset, expectedLength).ToArray();
            offset += expectedLength;
        }
        if (offset != canonical.Length)
            Reject("ADL1 contains trailing bytes.");

        try
        {
            return new AccountDirectoryAdl1(
                fields[0], fields[1], BinaryPrimitives.ReadUInt64BigEndian(fields[2]), fields[3],
                BinaryPrimitives.ReadUInt16BigEndian(fields[4]), fields[5], fields[6]);
        }
        catch (ArgumentException exception)
        {
            throw new AccountDirectoryAdl1FormatException(exception.Message);
        }
    }

    private static byte[][] Fields(AccountDirectoryAdl1 value) =>
    [
        value.NetworkId.ToArray(), value.DirectoryLookupKey.ToArray(), U64(value.MinimumAdhGeneration),
        value.MinimumAdhHash.ToArray(), U16(value.ServiceProfile),
        value.ExactOhttpXod1CoreReference.ToArray(), value.ExactOhttpXod1CoreHash.ToArray()
    ];

    private static void WriteFields(byte[] destination, byte[][] fields)
    {
        var offset = HeaderSize;
        for (var index = 0; index < fields.Length; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(destination.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt16BigEndian(destination.AsSpan(offset + 2), 0);
            BinaryPrimitives.WriteUInt32BigEndian(destination.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].CopyTo(destination, offset);
            offset += fields[index].Length;
        }
    }

    private static byte[] U16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static void Reject(string message) => throw new AccountDirectoryAdl1FormatException(message);
}
