using System.Buffers.Binary;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryAdh1FormatException(string message) : FormatException(message);

public sealed class AccountDirectoryAdh1WitnessEntry
{
    private readonly byte[] witnessId;
    private readonly byte[] signature;

    public AccountDirectoryAdh1WitnessEntry(ReadOnlySpan<byte> witnessId, ReadOnlySpan<byte> signature)
    {
        if (witnessId.Length != 32)
            throw new ArgumentException("witnessId must be exactly 32 bytes.", nameof(witnessId));
        if (signature.Length != 64)
            throw new ArgumentException("signature must be exactly 64 bytes.", nameof(signature));
        this.witnessId = witnessId.ToArray();
        this.signature = signature.ToArray();
    }

    public ReadOnlyMemory<byte> WitnessId => witnessId.ToArray();
    public ReadOnlyMemory<byte> Signature => signature.ToArray();
}

public sealed class AccountDirectoryAdh1
{
    private readonly byte[] networkId;
    private readonly byte[] predecessorAdh1CoreHash;
    private readonly byte[] appendLogMerkleRoot;
    private readonly byte[] currentValueMapRoot;
    private readonly byte[] exactXnaAuthorityCoreReference;
    private readonly byte[] witnessPolicyHash;
    private readonly AccountDirectoryAdh1WitnessEntry[] witnesses;

    public AccountDirectoryAdh1(
        ReadOnlySpan<byte> networkId,
        ulong logGeneration,
        ReadOnlySpan<byte> predecessorAdh1CoreHash,
        ulong treeSize,
        ReadOnlySpan<byte> appendLogMerkleRoot,
        ReadOnlySpan<byte> currentValueMapRoot,
        ReadOnlySpan<byte> exactXnaAuthorityCoreReference,
        ReadOnlySpan<byte> witnessPolicyHash,
        ulong validFrom,
        ulong validUntil,
        ushort minimumReader,
        IReadOnlyList<AccountDirectoryAdh1WitnessEntry> witnesses)
    {
        this.networkId = Copy(networkId, 16, nameof(networkId));
        LogGeneration = logGeneration;
        this.predecessorAdh1CoreHash = Copy(predecessorAdh1CoreHash, 32, nameof(predecessorAdh1CoreHash));
        TreeSize = treeSize;
        this.appendLogMerkleRoot = Copy(appendLogMerkleRoot, 32, nameof(appendLogMerkleRoot));
        this.currentValueMapRoot = Copy(currentValueMapRoot, 32, nameof(currentValueMapRoot));
        this.exactXnaAuthorityCoreReference = Copy(exactXnaAuthorityCoreReference, 38, nameof(exactXnaAuthorityCoreReference));
        ValidateReference(this.exactXnaAuthorityCoreReference, ProtocolMagic.XNA1, nameof(exactXnaAuthorityCoreReference));
        this.witnessPolicyHash = Copy(witnessPolicyHash, 32, nameof(witnessPolicyHash));
        ValidFrom = validFrom;
        ValidUntil = validUntil;
        MinimumReader = minimumReader;
        if (validUntil <= validFrom || validUntil - validFrom > 86_400)
            throw new ArgumentException("ADH1 validity must be non-empty and at most 24 hours.", nameof(validUntil));
        if (logGeneration == 0 ? !IsZero(this.predecessorAdh1CoreHash) : IsZero(this.predecessorAdh1CoreHash))
            throw new ArgumentException("ADH1 predecessor hash must be zero exactly at generation zero.", nameof(predecessorAdh1CoreHash));
        if (IsZero(this.networkId) || IsZero(this.appendLogMerkleRoot) ||
            IsZero(this.currentValueMapRoot) || IsZero(this.witnessPolicyHash))
            throw new ArgumentException("ADH1 contains an all-zero required identifier or hash.");
        ArgumentNullException.ThrowIfNull(witnesses);
        if (witnesses.Count is < 1 or > 32)
            throw new ArgumentException("ADH1 must contain between one and 32 witnesses.", nameof(witnesses));
        this.witnesses = new AccountDirectoryAdh1WitnessEntry[witnesses.Count];
        ReadOnlySpan<byte> previousId = default;
        for (var index = 0; index < witnesses.Count; index++)
        {
            ArgumentNullException.ThrowIfNull(witnesses[index]);
            var source = witnesses[index];
            var copy = new AccountDirectoryAdh1WitnessEntry(source.WitnessId.Span, source.Signature.Span);
            if (IsZero(copy.WitnessId.Span) || IsZero(copy.Signature.Span))
                throw new ArgumentException("ADH1 witness IDs and signatures must be non-zero.", nameof(witnesses));
            if (!previousId.IsEmpty && previousId.SequenceCompareTo(copy.WitnessId.Span) >= 0)
                throw new ArgumentException("ADH1 witness IDs must be strictly increasing.", nameof(witnesses));
            this.witnesses[index] = copy;
            previousId = copy.WitnessId.Span;
        }
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong LogGeneration { get; }
    public ReadOnlyMemory<byte> PredecessorAdh1CoreHash => predecessorAdh1CoreHash.ToArray();
    public ulong TreeSize { get; }
    public ReadOnlyMemory<byte> AppendLogMerkleRoot => appendLogMerkleRoot.ToArray();
    public ReadOnlyMemory<byte> CurrentValueMapRoot => currentValueMapRoot.ToArray();
    public ReadOnlyMemory<byte> ExactXnaAuthorityCoreReference => exactXnaAuthorityCoreReference.ToArray();
    public ReadOnlyMemory<byte> WitnessPolicyHash => witnessPolicyHash.ToArray();
    public ulong ValidFrom { get; }
    public ulong ValidUntil { get; }
    public ushort MinimumReader { get; }
    public int WitnessCount => witnesses.Length;
    public IReadOnlyList<AccountDirectoryAdh1WitnessEntry> Witnesses => witnesses.ToArray();

    private static byte[] Copy(ReadOnlySpan<byte> value, int expectedLength, string name)
    {
        if (value.Length != expectedLength)
            throw new ArgumentException($"{name} must be exactly {expectedLength} bytes.", name);
        return value.ToArray();
    }

    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        foreach (var item in value)
            if (item != 0)
                return false;
        return true;
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
}

public static class AccountDirectoryAdh1Codec
{
    public const ushort Version = 1;
    public const ushort Suite = 0x0201;
    public const ushort FieldCount = 13;
    private const int HeaderSize = 12;
    private static readonly int[] FixedFieldLengths = [16, 8, 32, 8, 32, 32, 38, 32, 8, 8, 2, 1];
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.ADH1;

    public static byte[] Encode(AccountDirectoryAdh1 value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var fields = Fields(value);
        var result = new byte[checked(HeaderSize + fields.Sum(field => 8 + field.Length))];
        WriteHeader(result, FieldCount);
        WriteFields(result, fields);
        return result;
    }

    public static byte[] EncodeUnsigned(AccountDirectoryAdh1 value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var fields = Fields(value)[..11];
        var result = new byte[checked(HeaderSize + fields.Sum(field => 8 + field.Length))];
        WriteHeader(result, 11);
        WriteFields(result, fields);
        return result;
    }

    public static AccountDirectoryAdh1 Decode(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length < HeaderSize)
            Reject("ADH1 header is truncated.");
        if (!canonical[..4].SequenceEqual(Magic))
            Reject("ADH1 magic is invalid.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[4..]) != Version)
            Reject("ADH1 version is unsupported.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[6..]) != Suite)
            Reject("ADH1 suite is unsupported.");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[8..]) != FieldCount ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[10..]) != 0)
            Reject("ADH1 header fields are invalid.");

        var fields = new byte[FieldCount][];
        var offset = HeaderSize;
        for (var index = 0; index < FieldCount; index++)
        {
            if (canonical.Length - offset < 8)
                Reject("ADH1 field header is truncated.");
            if (BinaryPrimitives.ReadUInt16BigEndian(canonical[offset..]) != index + 1)
                Reject("ADH1 tags must be consecutive and ordered.");
            if (BinaryPrimitives.ReadUInt16BigEndian(canonical[(offset + 2)..]) != 0)
                Reject("ADH1 field reserved value is non-zero.");
            var declaredLength = BinaryPrimitives.ReadUInt32BigEndian(canonical[(offset + 4)..]);
            var expectedLength = index < 12
                ? FixedFieldLengths[index]
                : checked(96 * fields[11][0]);
            if (declaredLength != (uint)expectedLength)
                Reject("ADH1 field length is invalid.");
            offset += 8;
            if (canonical.Length - offset < expectedLength)
                Reject("ADH1 field value is truncated.");
            fields[index] = canonical.Slice(offset, expectedLength).ToArray();
            offset += expectedLength;
        }
        if (offset != canonical.Length)
            Reject("ADH1 contains trailing bytes.");

        var witnessEntries = new AccountDirectoryAdh1WitnessEntry[fields[11][0]];
        for (var index = 0; index < witnessEntries.Length; index++)
        {
            var entry = fields[12].AsSpan(index * 96, 96);
            witnessEntries[index] = new AccountDirectoryAdh1WitnessEntry(entry[..32], entry[32..]);
        }
        try
        {
            return new AccountDirectoryAdh1(
                fields[0], BinaryPrimitives.ReadUInt64BigEndian(fields[1]), fields[2],
                BinaryPrimitives.ReadUInt64BigEndian(fields[3]), fields[4], fields[5], fields[6], fields[7],
                BinaryPrimitives.ReadUInt64BigEndian(fields[8]), BinaryPrimitives.ReadUInt64BigEndian(fields[9]),
                BinaryPrimitives.ReadUInt16BigEndian(fields[10]), witnessEntries);
        }
        catch (ArgumentException exception)
        {
            throw new AccountDirectoryAdh1FormatException(exception.Message);
        }
    }

    private static byte[][] Fields(AccountDirectoryAdh1 value)
    {
        var witnessBytes = new byte[checked(value.WitnessCount * 96)];
        for (var index = 0; index < value.WitnessCount; index++)
        {
            var witness = value.Witnesses[index];
            witness.WitnessId.Span.CopyTo(witnessBytes.AsSpan(index * 96, 32));
            witness.Signature.Span.CopyTo(witnessBytes.AsSpan(index * 96 + 32, 64));
        }
        var count = new[] { checked((byte)value.WitnessCount) };
        return
        [
            value.NetworkId.ToArray(), U64(value.LogGeneration), value.PredecessorAdh1CoreHash.ToArray(),
            U64(value.TreeSize), value.AppendLogMerkleRoot.ToArray(), value.CurrentValueMapRoot.ToArray(),
            value.ExactXnaAuthorityCoreReference.ToArray(), value.WitnessPolicyHash.ToArray(), U64(value.ValidFrom),
            U64(value.ValidUntil), U16(value.MinimumReader), count, witnessBytes
        ];
    }

    private static void WriteHeader(byte[] destination, ushort count)
    {
        Magic.CopyTo(destination);
        BinaryPrimitives.WriteUInt16BigEndian(destination.AsSpan(4), Version);
        BinaryPrimitives.WriteUInt16BigEndian(destination.AsSpan(6), Suite);
        BinaryPrimitives.WriteUInt16BigEndian(destination.AsSpan(8), count);
        BinaryPrimitives.WriteUInt16BigEndian(destination.AsSpan(10), 0);
    }

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

    private static void Reject(string message) => throw new AccountDirectoryAdh1FormatException(message);
}
