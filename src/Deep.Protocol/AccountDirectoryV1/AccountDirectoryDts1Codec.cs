using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryDts1FormatException(string message) : FormatException(message);

public sealed class AccountDirectoryDts1Source
{
    private readonly byte[] sourceId;
    private readonly byte[] failureFamilyHash;
    private readonly byte[] tlsSpkiSha256;

    public AccountDirectoryDts1Source(
        ReadOnlySpan<byte> sourceId,
        ReadOnlySpan<byte> failureFamilyHash,
        ushort protocol,
        string hostAscii,
        ushort port,
        ReadOnlySpan<byte> tlsSpkiSha256,
        ushort maximumRadiusSeconds)
    {
        this.sourceId = Required(sourceId, 32, nameof(sourceId));
        this.failureFamilyHash = Required(failureFamilyHash, 32, nameof(failureFamilyHash));
        if (protocol != 1)
            throw new ArgumentOutOfRangeException(nameof(protocol));
        Protocol = protocol;
        HostAscii = ValidateHost(hostAscii);
        if (port == 0)
            throw new ArgumentOutOfRangeException(nameof(port));
        Port = port;
        this.tlsSpkiSha256 = Required(tlsSpkiSha256, 32, nameof(tlsSpkiSha256));
        if (maximumRadiusSeconds is < 1 or > 10)
            throw new ArgumentOutOfRangeException(nameof(maximumRadiusSeconds));
        MaximumRadiusSeconds = maximumRadiusSeconds;
    }

    public ReadOnlyMemory<byte> SourceId => sourceId.ToArray();
    public ReadOnlyMemory<byte> FailureFamilyHash => failureFamilyHash.ToArray();
    public ushort Protocol { get; }
    public string HostAscii { get; }
    public ushort Port { get; }
    public ReadOnlyMemory<byte> TlsSpkiSha256 => tlsSpkiSha256.ToArray();
    public ushort MaximumRadiusSeconds { get; }
    internal int EncodedLength => checked(103 + HostAscii.Length);

    private static string ValidateHost(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        if (value.Length > 253 || value[^1] == '.' || value.Any(static c => c > 0x7f) ||
            IPAddress.TryParse(value, out _))
            throw new ArgumentException("DTS1 host is not canonical DNS ASCII.", nameof(value));
        foreach (var label in value.Split('.', StringSplitOptions.None))
        {
            if (label.Length is < 1 or > 63 || !IsAlphaNumeric(label[0]) || !IsAlphaNumeric(label[^1]) ||
                label.Any(static c => !IsAlphaNumeric(c) && c != '-'))
                throw new ArgumentException("DTS1 host is not canonical DNS ASCII.", nameof(value));
        }
        return value;
    }

    private static bool IsAlphaNumeric(char value) => value is >= 'a' and <= 'z' or >= '0' and <= '9';

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }
}

public sealed class AccountDirectoryDts1RootReceipt
{
    private readonly byte[] rootKeyId;
    private readonly byte[] signature;

    public AccountDirectoryDts1RootReceipt(ReadOnlySpan<byte> rootKeyId, ReadOnlySpan<byte> signature)
    {
        rootKeyId = Required(rootKeyId, 32, nameof(rootKeyId));
        this.rootKeyId = rootKeyId.ToArray();
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

public sealed class AccountDirectoryDts1
{
    private readonly byte[] networkId;
    private readonly byte[] predecessorPolicyHash;
    private readonly AccountDirectoryDts1Source[] sources;
    private readonly AccountDirectoryDts1RootReceipt[] rootReceipts;

    public AccountDirectoryDts1(
        ReadOnlySpan<byte> networkId,
        ulong policyGeneration,
        ReadOnlySpan<byte> predecessorPolicyHash,
        IReadOnlyList<AccountDirectoryDts1Source> sources,
        byte requiredSourceCount,
        byte requiredDistinctFailureFamilies,
        uint maximumIntervalWidthSeconds,
        ushort maximumSourceSampleAgeSeconds,
        ulong notBefore,
        ulong expiresAt,
        ushort minimumReader,
        ulong rootAuthorityGeneration,
        IReadOnlyList<AccountDirectoryDts1RootReceipt> rootReceipts)
    {
        this.networkId = Required(networkId, 16, nameof(networkId));
        PolicyGeneration = policyGeneration;
        this.predecessorPolicyHash = predecessorPolicyHash.Length == 32
            ? predecessorPolicyHash.ToArray()
            : throw new ArgumentException("Predecessor hash must be exactly 32 bytes.", nameof(predecessorPolicyHash));
        if (policyGeneration == 0 ? this.predecessorPolicyHash.AsSpan().IndexOfAnyExcept((byte)0) >= 0 : this.predecessorPolicyHash.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("DTS1 predecessor is zero exactly at generation zero.", nameof(predecessorPolicyHash));
        ArgumentNullException.ThrowIfNull(sources);
        if (sources.Count is < 2 or > 8)
            throw new ArgumentException("DTS1 requires between two and eight sources.", nameof(sources));
        this.sources = new AccountDirectoryDts1Source[sources.Count];
        ReadOnlySpan<byte> previousSourceId = default;
        var tuples = new HashSet<string>(StringComparer.Ordinal);
        var families = new HashSet<string>(StringComparer.Ordinal);
        var sourceBytes = 0;
        for (var index = 0; index < sources.Count; index++)
        {
            ArgumentNullException.ThrowIfNull(sources[index]);
            var item = sources[index];
            var copy = new AccountDirectoryDts1Source(item.SourceId.Span, item.FailureFamilyHash.Span,
                item.Protocol, item.HostAscii, item.Port, item.TlsSpkiSha256.Span, item.MaximumRadiusSeconds);
            if (!previousSourceId.IsEmpty && previousSourceId.SequenceCompareTo(copy.SourceId.Span) >= 0)
                throw new ArgumentException("DTS1 source IDs must be strictly increasing.", nameof(sources));
            var tuple = $"{copy.HostAscii}:{copy.Port}:{Convert.ToHexString(copy.TlsSpkiSha256.Span)}";
            if (!tuples.Add(tuple))
                throw new ArgumentException("DTS1 source endpoint tuples must be unique.", nameof(sources));
            families.Add(Convert.ToHexString(copy.FailureFamilyHash.Span));
            sourceBytes = checked(sourceBytes + 2 + copy.EncodedLength);
            this.sources[index] = copy;
            previousSourceId = copy.SourceId.Span;
        }
        if (sourceBytes is < 1 or > 4096 || families.Count < 2)
            throw new ArgumentException("DTS1 source list bounds or failure-family diversity is invalid.", nameof(sources));
        if (requiredSourceCount != 2 || requiredDistinctFailureFamilies != 2 || maximumIntervalWidthSeconds != 30)
            throw new ArgumentException("DTS1 v1 fixed threshold or interval policy is invalid.");
        RequiredSourceCount = requiredSourceCount;
        RequiredDistinctFailureFamilies = requiredDistinctFailureFamilies;
        MaximumIntervalWidthSeconds = maximumIntervalWidthSeconds;
        if (maximumSourceSampleAgeSeconds is < 1 or > 30)
            throw new ArgumentOutOfRangeException(nameof(maximumSourceSampleAgeSeconds));
        MaximumSourceSampleAgeSeconds = maximumSourceSampleAgeSeconds;
        if (expiresAt <= notBefore || expiresAt - notBefore > 2_592_000)
            throw new ArgumentException("DTS1 validity is empty or exceeds 30 days.", nameof(expiresAt));
        NotBefore = notBefore;
        ExpiresAt = expiresAt;
        MinimumReader = minimumReader;
        RootAuthorityGeneration = rootAuthorityGeneration;
        ArgumentNullException.ThrowIfNull(rootReceipts);
        if (rootReceipts.Count is < 1 or > 8)
            throw new ArgumentException("DTS1 requires between one and eight root receipts.", nameof(rootReceipts));
        this.rootReceipts = new AccountDirectoryDts1RootReceipt[rootReceipts.Count];
        ReadOnlySpan<byte> previousRootId = default;
        for (var index = 0; index < rootReceipts.Count; index++)
        {
            ArgumentNullException.ThrowIfNull(rootReceipts[index]);
            var copy = new AccountDirectoryDts1RootReceipt(rootReceipts[index].RootKeyId.Span, rootReceipts[index].Signature.Span);
            if (!previousRootId.IsEmpty && previousRootId.SequenceCompareTo(copy.RootKeyId.Span) >= 0)
                throw new ArgumentException("DTS1 root receipt IDs must be strictly increasing.", nameof(rootReceipts));
            this.rootReceipts[index] = copy;
            previousRootId = copy.RootKeyId.Span;
        }
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong PolicyGeneration { get; }
    public ReadOnlyMemory<byte> PredecessorPolicyHash => predecessorPolicyHash.ToArray();
    public IReadOnlyList<AccountDirectoryDts1Source> Sources => sources.ToArray();
    public byte RequiredSourceCount { get; }
    public byte RequiredDistinctFailureFamilies { get; }
    public uint MaximumIntervalWidthSeconds { get; }
    public ushort MaximumSourceSampleAgeSeconds { get; }
    public ulong NotBefore { get; }
    public ulong ExpiresAt { get; }
    public ushort MinimumReader { get; }
    public ulong RootAuthorityGeneration { get; }
    public IReadOnlyList<AccountDirectoryDts1RootReceipt> RootReceipts => rootReceipts.ToArray();

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }
}

public static class AccountDirectoryDts1Codec
{
    public const ushort Version = 1;
    public const ushort Suite = 0x0001;
    public const ushort FieldCount = 15;
    private const int HeaderSize = 12;
    private static readonly int[] FixedLengths = [16, 8, 32, 1, -1, 1, 1, 4, 2, 8, 8, 2, 8, 1, -1];

    public static byte[] Encode(AccountDirectoryDts1 value) => EncodeCore(value, FieldCount);
    public static byte[] EncodeUnsigned(AccountDirectoryDts1 value) => EncodeCore(value, 13);

    public static AccountDirectoryDts1 Decode(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length is < HeaderSize or > 65_535 || !canonical[..4].SequenceEqual(ProtocolMagicBytes.DTS1) ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[4..]) != Version ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[6..]) != Suite ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[8..]) != FieldCount ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[10..]) != 0)
            Reject("DTS1 header is invalid.");
        var fields = new byte[FieldCount][];
        var offset = HeaderSize;
        for (var index = 0; index < FieldCount; index++)
        {
            if (canonical.Length - offset < 8 || BinaryPrimitives.ReadUInt16BigEndian(canonical[offset..]) != index + 1 ||
                BinaryPrimitives.ReadUInt16BigEndian(canonical[(offset + 2)..]) != 0)
                Reject("DTS1 field header is invalid.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(canonical[(offset + 4)..]);
            if (length > int.MaxValue)
                Reject("DTS1 field length overflows.");
            var expected = FixedLengths[index];
            if (index == 4 && (length is < 1 or > 4096) || index == 14 && fields[13] is not null && length != fields[13][0] * 96u ||
                expected >= 0 && length != (uint)expected)
                Reject("DTS1 field length is invalid.");
            offset += 8;
            if (canonical.Length - offset < (int)length)
                Reject("DTS1 field is truncated.");
            fields[index] = canonical.Slice(offset, (int)length).ToArray();
            offset += (int)length;
        }
        if (offset != canonical.Length)
            Reject("DTS1 contains trailing bytes.");
        try
        {
            var sources = DecodeSources(fields[4], fields[3][0]);
            var receipts = new AccountDirectoryDts1RootReceipt[fields[13][0]];
            for (var index = 0; index < receipts.Length; index++)
            {
                var entry = fields[14].AsSpan(index * 96, 96);
                receipts[index] = new AccountDirectoryDts1RootReceipt(entry[..32], entry[32..]);
            }
            return new AccountDirectoryDts1(fields[0], BinaryPrimitives.ReadUInt64BigEndian(fields[1]), fields[2], sources,
                fields[5][0], fields[6][0], BinaryPrimitives.ReadUInt32BigEndian(fields[7]),
                BinaryPrimitives.ReadUInt16BigEndian(fields[8]), BinaryPrimitives.ReadUInt64BigEndian(fields[9]),
                BinaryPrimitives.ReadUInt64BigEndian(fields[10]), BinaryPrimitives.ReadUInt16BigEndian(fields[11]),
                BinaryPrimitives.ReadUInt64BigEndian(fields[12]), receipts);
        }
        catch (ArgumentException exception)
        {
            throw new AccountDirectoryDts1FormatException(exception.Message);
        }
    }

    private static AccountDirectoryDts1Source[] DecodeSources(ReadOnlySpan<byte> encoded, int count)
    {
        var result = new AccountDirectoryDts1Source[count];
        var offset = 0;
        for (var index = 0; index < count; index++)
        {
            if (encoded.Length - offset < 2)
                Reject("DTS1 source length is truncated.");
            var length = BinaryPrimitives.ReadUInt16BigEndian(encoded[offset..]);
            offset += 2;
            if (length < 104 || encoded.Length - offset < length)
                Reject("DTS1 source entry length is invalid.");
            var entry = encoded.Slice(offset, length);
            offset += length;
            var hostLength = entry[66];
            if (hostLength == 0 || length != 103 + hostLength)
                Reject("DTS1 source host length is invalid.");
            var tail = 67 + hostLength;
            var host = Encoding.ASCII.GetString(entry.Slice(67, hostLength));
            result[index] = new AccountDirectoryDts1Source(entry[..32], entry.Slice(32, 32),
                BinaryPrimitives.ReadUInt16BigEndian(entry[64..]), host,
                BinaryPrimitives.ReadUInt16BigEndian(entry[tail..]), entry.Slice(tail + 2, 32),
                BinaryPrimitives.ReadUInt16BigEndian(entry[(tail + 34)..]));
        }
        if (offset != encoded.Length)
            Reject("DTS1 source list has missing or trailing entries.");
        return result;
    }

    private static byte[] EncodeCore(AccountDirectoryDts1 value, ushort fieldCount)
    {
        ArgumentNullException.ThrowIfNull(value);
        var sourceBytes = EncodeSources(value.Sources);
        var receiptBytes = new byte[checked(value.RootReceipts.Count * 96)];
        for (var index = 0; index < value.RootReceipts.Count; index++)
        {
            value.RootReceipts[index].RootKeyId.Span.CopyTo(receiptBytes.AsSpan(index * 96, 32));
            value.RootReceipts[index].Signature.Span.CopyTo(receiptBytes.AsSpan(index * 96 + 32, 64));
        }
        byte[][] fields =
        [
            value.NetworkId.ToArray(), U64(value.PolicyGeneration), value.PredecessorPolicyHash.ToArray(),
            [checked((byte)value.Sources.Count)], sourceBytes, [value.RequiredSourceCount],
            [value.RequiredDistinctFailureFamilies], U32(value.MaximumIntervalWidthSeconds), U16(value.MaximumSourceSampleAgeSeconds),
            U64(value.NotBefore), U64(value.ExpiresAt), U16(value.MinimumReader), U64(value.RootAuthorityGeneration),
            [checked((byte)value.RootReceipts.Count)], receiptBytes
        ];
        var selected = fields.Take(fieldCount).ToArray();
        var result = new byte[checked(HeaderSize + selected.Sum(static field => 8 + field.Length))];
        ProtocolMagicBytes.DTS1.CopyTo(result);
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

    private static byte[] EncodeSources(IReadOnlyList<AccountDirectoryDts1Source> sources)
    {
        var result = new byte[checked(sources.Sum(static source => 2 + source.EncodedLength))];
        var offset = 0;
        foreach (var source in sources)
        {
            var host = Encoding.ASCII.GetBytes(source.HostAscii);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset), checked((ushort)source.EncodedLength));
            offset += 2;
            source.SourceId.Span.CopyTo(result.AsSpan(offset, 32));
            source.FailureFamilyHash.Span.CopyTo(result.AsSpan(offset + 32, 32));
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 64), source.Protocol);
            result[offset + 66] = checked((byte)host.Length);
            host.CopyTo(result, offset + 67);
            var tail = offset + 67 + host.Length;
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(tail), source.Port);
            source.TlsSpkiSha256.Span.CopyTo(result.AsSpan(tail + 2, 32));
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(tail + 34), source.MaximumRadiusSeconds);
            offset += source.EncodedLength;
        }
        return result;
    }

    private static byte[] U16(ushort value) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    private static byte[] U32(uint value) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
    private static void Reject(string message) => throw new AccountDirectoryDts1FormatException(message);
}
