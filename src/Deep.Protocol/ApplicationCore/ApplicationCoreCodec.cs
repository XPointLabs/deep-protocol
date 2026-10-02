using System.Buffers.Binary;
using System.Text;

namespace Deep.Protocol.ApplicationCore;

public static partial class ApplicationCoreCodec
{
    private static ReadOnlySpan<byte> DmdMagic => ProtocolMagicBytes.DMD1;
    private static ReadOnlySpan<byte> DaoMagic => ProtocolMagicBytes.DAO1;
    private static readonly int[] DaoTotals =
    [
        4725, 4821, 4885, 5685, 5877, 8189, 17013, 17109, 17173, 17973, 18165,
        20477, 33397, 33493, 33557, 34357, 34549, 36861, 49765, 49861, 49925,
        50725, 50917,
    ];

    public static ParsedDmd1 DecodeDmd1(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[12];
        ApplicationCoreFormat.Preflight(canonical, DmdMagic, 12, 426, 1476, fields);
        Exact(fields, 16, 32, 8, 38, 38, 8, 32, 2, -1, 2, 8, 64);
        var count = U16(Field(canonical, fields, 8));
        if (count is < 1 or > 16 || fields[8].Length != 70 * count || canonical.Length != 356 + 70 * count)
            Invalid(ApplicationCoreRejection.InvalidFieldLength, "DMD1 count, entry bytes and total size disagree.");
        var network = Field(canonical, fields, 1);
        var account = Field(canonical, fields, 2);
        var accountGeneration = U64(Field(canonical, fields, 3));
        var directoryGeneration = U64(Field(canonical, fields, 6));
        var predecessor = Field(canonical, fields, 7);
        ApplicationCoreFormat.NonZero(network, "DMD1 network ID");
        ApplicationCoreFormat.NonZero(account, "DMD1 account ID");
        if (accountGeneration == 0 || directoryGeneration == 0)
            Invalid(ApplicationCoreRejection.InvalidGeneration, "DMD1 generations start at one.");
        ValidatePredecessor(directoryGeneration, predecessor, zeroGeneration: 1, ProtocolMagic.DMD1);
        if (U16(Field(canonical, fields, 10)) != ApplicationCoreFormat.Suite)
            Invalid(ApplicationCoreRejection.InvalidEnum, "DMD1 minimum messaging suite must be 0x0201.");
        ValidateReference(Field(canonical, fields, 4), 1, 644, 644, ProtocolMagic.DPA1);
        ValidateReference(Field(canonical, fields, 5), 4, 356, 63844, ProtocolMagic.DRS1);
        var entryBytes = Field(canonical, fields, 9);
        for (var index = 0; index < count; index++)
        {
            var row = entryBytes.Slice(index * 70, 70);
            var deviceId = row[..32];
            ApplicationCoreFormat.NonZero(deviceId, "DMD1 device ID");
            if (index > 0 && ApplicationCoreFormat.Compare(
                    entryBytes.Slice((index - 1) * 70, 32), deviceId) >= 0)
                Invalid(ApplicationCoreRejection.InvalidOrdering, "DMD1 device entries must be strictly sorted and unique.");
            ValidateReference(row[32..], 2, 776, 776, ProtocolMagic.DPD1);
        }

        var owned = canonical.ToArray();
        var dpa = ParseReference(Field(owned, fields, 4), 1, 644, 644, ProtocolMagic.DPA1);
        var drs = ParseReference(Field(owned, fields, 5), 4, 356, 63844, ProtocolMagic.DRS1);
        var ownedEntries = Field(owned, fields, 9);
        var entries = new DeviceDirectoryEntry[count];
        for (var index = 0; index < count; index++)
        {
            var row = ownedEntries.Slice(index * 70, 70);
            entries[index] = new DeviceDirectoryEntry(row[..32],
                ParseReference(row[32..], 2, 776, 776, ProtocolMagic.DPD1));
        }
        var unsigned = Projection(DmdMagic, owned, fields, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        if (unsigned.Length != 284 + 70 * count)
            throw new InvalidOperationException("The frozen DMD1 projection size is inconsistent.");
        return new ParsedDmd1(owned, Field(owned, fields, 1), Field(owned, fields, 2),
            accountGeneration, dpa, drs, directoryGeneration, Field(owned, fields, 7), entries,
            U64(Field(owned, fields, 11)), Field(owned, fields, 12), unsigned);
    }

    public static ParsedDmd1 AuthorDmd1(
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> deepAccountId32,
        ulong accountGeneration,
        ApplicationArtifactReference exactDpa1Reference,
        ApplicationArtifactReference exactDrs1Reference,
        ulong directoryGeneration,
        ReadOnlySpan<byte> predecessorDmd1Hash32,
        IReadOnlyList<DeviceDirectoryEntry> activeDevices,
        ulong issuedAtUnixSeconds,
        ReadOnlySpan<byte> deviceIssuerSignature64)
    {
        ArgumentNullException.ThrowIfNull(activeDevices);
        if (activeDevices.Count is < 1 or > 16)
            Invalid(ApplicationCoreRejection.InvalidFieldLength, "DMD1 accepts one through sixteen devices.");
        var entries = new byte[70 * activeDevices.Count];
        for (var index = 0; index < activeDevices.Count; index++)
        {
            ArgumentNullException.ThrowIfNull(activeDevices[index]);
            activeDevices[index].DeviceId.Span.CopyTo(entries.AsSpan(index * 70, 32));
            activeDevices[index].Dpd1Reference.CanonicalBytes.Span.CopyTo(entries.AsSpan(index * 70 + 32, 38));
        }
        RequireLength(networkId16, 16, "network ID");
        RequireLength(deepAccountId32, 32, "account ID");
        RequireReference(exactDpa1Reference, 1, 644, 644, ProtocolMagic.DPA1);
        RequireReference(exactDrs1Reference, 4, 356, 63844, ProtocolMagic.DRS1);
        RequireLength(predecessorDmd1Hash32, 32, "DMD1 predecessor");
        RequireLength(deviceIssuerSignature64, 64, "device issuer signature");
        Span<byte> accountGenerationBytes = stackalloc byte[8];
        Span<byte> directoryGenerationBytes = stackalloc byte[8];
        Span<byte> deviceCountBytes = stackalloc byte[2];
        Span<byte> suiteBytes = stackalloc byte[2];
        Span<byte> issuedAtBytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(accountGenerationBytes, accountGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(directoryGenerationBytes, directoryGeneration);
        BinaryPrimitives.WriteUInt16BigEndian(deviceCountBytes, checked((ushort)activeDevices.Count));
        BinaryPrimitives.WriteUInt16BigEndian(suiteBytes, ApplicationCoreFormat.Suite);
        BinaryPrimitives.WriteUInt64BigEndian(issuedAtBytes, issuedAtUnixSeconds);
        var dpaReference = exactDpa1Reference.CanonicalBytes;
        var drsReference = exactDrs1Reference.CanonicalBytes;
        var canonical = AllocateRecord(12, networkId16.Length + deepAccountId32.Length +
            accountGenerationBytes.Length + dpaReference.Length + drsReference.Length + directoryGenerationBytes.Length +
            predecessorDmd1Hash32.Length + deviceCountBytes.Length + entries.Length + suiteBytes.Length +
            issuedAtBytes.Length + deviceIssuerSignature64.Length);
        var writer = new ApplicationRecordWriter(canonical, DmdMagic, 12);
        writer.Write(1, networkId16);
        writer.Write(2, deepAccountId32);
        writer.Write(3, accountGenerationBytes);
        writer.Write(4, dpaReference.Span);
        writer.Write(5, drsReference.Span);
        writer.Write(6, directoryGenerationBytes);
        writer.Write(7, predecessorDmd1Hash32);
        writer.Write(8, deviceCountBytes);
        writer.Write(9, entries);
        writer.Write(10, suiteBytes);
        writer.Write(11, issuedAtBytes);
        writer.Write(12, deviceIssuerSignature64);
        writer.Complete();
        return DecodeDmd1(canonical);
    }

    public static ParsedDao1 DecodeDao1(ReadOnlySpan<byte> canonical)
    {
        if (Array.BinarySearch(DaoTotals, canonical.Length) < 0)
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.ExactTotalSize,
                ApplicationCoreRejection.InvalidTotalSize, "DAO1 total size is not an exact DPH2/DPE2 sealed size.");
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[6];
        ApplicationCoreFormat.Preflight(canonical, DaoMagic, 6, canonical.Length, canonical.Length, fields);
        Exact(fields, 16, 32, 32, 32, 24, -1);
        if (fields[5].Length != canonical.Length - 196 || fields[5].Length < 16)
            Invalid(ApplicationCoreRejection.InvalidFieldLength, "DAO1 sealed-record length is inconsistent.");
        ApplicationCoreFormat.NonZero(Field(canonical, fields, 1), "DAO1 network ID");
        ApplicationCoreFormat.NonZero(Field(canonical, fields, 2), "DAO1 sealing key ID");
        ApplicationCoreFormat.NonZero(Field(canonical, fields, 3), "DAO1 operation ID");
        ApplicationCoreFormat.NonZero(Field(canonical, fields, 4), "DAO1 ephemeral X25519 public key");
        var owned = canonical.ToArray();
        var header = Projection(DaoMagic, owned, fields, [1, 2, 3, 4, 5]);
        if (header.Length != 188)
            throw new InvalidOperationException("The frozen DAO1 AEAD header size is inconsistent.");
        return new ParsedDao1(owned, Field(owned, fields, 1), Field(owned, fields, 2),
            Field(owned, fields, 3), Field(owned, fields, 4), Field(owned, fields, 5),
            Field(owned, fields, 6), header);
    }

    public static ParsedDao1 AuthorDao1(
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> sealingKeyId32,
        ReadOnlySpan<byte> depositOperationId32,
        ReadOnlySpan<byte> ephemeralX25519PublicKey32,
        ReadOnlySpan<byte> nonce24,
        ReadOnlySpan<byte> sealedRecord)
    {
        RequireLength(networkId16, 16, "network ID");
        RequireLength(sealingKeyId32, 32, "sealing key ID");
        RequireLength(depositOperationId32, 32, "deposit operation ID");
        RequireLength(ephemeralX25519PublicKey32, 32, "ephemeral X25519 public key");
        RequireLength(nonce24, 24, "nonce");
        var totalLength = sealedRecord.Length <= DaoTotals[^1] - 196
            ? sealedRecord.Length + 196
            : -1;
        if (Array.BinarySearch(DaoTotals, totalLength) < 0)
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.ExactTotalSize,
                ApplicationCoreRejection.InvalidTotalSize, "DAO1 total size is not an exact DPH2/DPE2 sealed size.");
        var canonical = AllocateRecord(6, networkId16.Length + sealingKeyId32.Length + depositOperationId32.Length +
            ephemeralX25519PublicKey32.Length + nonce24.Length + sealedRecord.Length);
        var writer = new ApplicationRecordWriter(canonical, DaoMagic, 6);
        writer.Write(1, networkId16);
        writer.Write(2, sealingKeyId32);
        writer.Write(3, depositOperationId32);
        writer.Write(4, ephemeralX25519PublicKey32);
        writer.Write(5, nonce24);
        writer.Write(6, sealedRecord);
        writer.Complete();
        return DecodeDao1(canonical);
    }

    public static ApplicationArtifactReference DecodeArtifactReference(ReadOnlySpan<byte> canonical) =>
        ParseReference(canonical, null, 1, 65535, "artifact");

    public static ApplicationArtifactReference CreateArtifactReference(
        ushort typeCode, uint canonicalLength, ReadOnlySpan<byte> canonicalHash32)
    {
        if (typeCode == 0 || canonicalLength == 0 || canonicalHash32.Length != 32 ||
            ApplicationCoreFormat.IsZero(canonicalHash32))
            Invalid(ApplicationCoreRejection.InvalidReference, "An artifact reference must be nonzero and exact.");
        return new ApplicationArtifactReference(typeCode, canonicalLength, canonicalHash32);
    }

    public static ReadOnlyMemory<byte> DeriveIdentityRealmId(ReadOnlySpan<byte> networkId16, ushort deploymentProfileId)
    {
        RequireLength(networkId16, 16, "network ID");
        ApplicationCoreFormat.NonZero(networkId16, "identity-realm network ID");
        Span<byte> payload = stackalloc byte[18];
        networkId16.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload[16..], deploymentProfileId);
        return ApplicationCoreFormat.Sha256Domain("Deep/Application/V1/address-binding-realm", payload);
    }

    private static byte[] Projection(
        ReadOnlySpan<byte> magic,
        ReadOnlySpan<byte> source,
        ReadOnlySpan<ApplicationFieldSlice> sourceFields,
        ReadOnlySpan<ushort> includedTags)
    {
        var contentLength = 0;
        foreach (var tag in includedTags)
            contentLength = checked(contentLength + sourceFields[tag - 1].Length);
        var output = AllocateRecord(checked((ushort)includedTags.Length), contentLength);
        var writer = new ApplicationRecordWriter(output, magic, checked((ushort)includedTags.Length));
        foreach (var tag in includedTags)
            writer.Write(tag, ApplicationCoreFormat.Field(source, sourceFields, tag));
        writer.Complete();
        return output;
    }

    private static byte[] AllocateRecord(ushort fieldCount, int contentLength) =>
        new byte[checked(ApplicationCoreFormat.HeaderLength + fieldCount * ApplicationCoreFormat.FieldHeaderLength + contentLength)];

    private static ReadOnlySpan<byte> Field(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<ApplicationFieldSlice> fields,
        int tag) => ApplicationCoreFormat.Field(encoded, fields, tag);

    private static void Exact(ReadOnlySpan<ApplicationFieldSlice> fields, params int[] lengths)
    {
        for (var index = 0; index < lengths.Length; index++)
        {
            if (lengths[index] >= 0)
                ApplicationCoreFormat.ExactLength(fields, index + 1, lengths[index]);
        }
    }

    private static ApplicationArtifactReference ParseReference(
        ReadOnlySpan<byte> encoded,
        ushort? expectedType,
        int minimumLength,
        int maximumLength,
        string name)
    {
        ValidateReference(encoded, expectedType, minimumLength, maximumLength, name);
        return new ApplicationArtifactReference(U16(encoded[..2]),
            BinaryPrimitives.ReadUInt32BigEndian(encoded[2..6]), encoded[6..]);
    }

    private static void ValidateReference(
        ReadOnlySpan<byte> encoded,
        ushort? expectedType,
        int minimumLength,
        int maximumLength,
        string name)
    {
        if (encoded.Length != 38)
            Invalid(ApplicationCoreRejection.InvalidReference, $"{name} reference length is invalid.");
        var type = U16(encoded[..2]);
        var length = BinaryPrimitives.ReadUInt32BigEndian(encoded[2..6]);
        if (type == 0 || (expectedType.HasValue && type != expectedType.Value) ||
            length < minimumLength || length > maximumLength || ApplicationCoreFormat.IsZero(encoded[6..]))
            Invalid(ApplicationCoreRejection.InvalidReference, $"{name} reference is not exact.");
    }

    private static void RequireReference(
        ApplicationArtifactReference reference,
        ushort? expectedType,
        int minimumLength,
        int maximumLength,
        string name)
    {
        ArgumentNullException.ThrowIfNull(reference);
        _ = ParseReference(reference.CanonicalBytes.Span, expectedType, minimumLength, maximumLength, name);
    }

    private static void ValidatePredecessor(ulong generation, ReadOnlySpan<byte> predecessor, ulong zeroGeneration, string name)
    {
        var zero = ApplicationCoreFormat.IsZero(predecessor);
        if ((generation == zeroGeneration) != zero)
            Invalid(ApplicationCoreRejection.InvalidLineage,
                $"{name} predecessor is zero only at its initial generation.");
    }

    private static void RequireLength(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length)
            Invalid(ApplicationCoreRejection.InvalidFieldLength, $"The {name} length is invalid.");
    }

    private static ushort U16(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt16BigEndian(value);
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    private static void Invalid(ApplicationCoreRejection rejection, string message) =>
        throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.SemanticFields, rejection, message);
}

internal static class DeepIdText
{
    private const string Hrp = "deep";
    private const uint Bech32mConstant = 0x2bc830a3;
    private const string Alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    internal static string Encode(ReadOnlySpan<byte> publicKey32, ReadOnlySpan<byte> capability16)
        => Encode(1, publicKey32, capability16);

    internal static string Encode(
        byte formatVersion, ReadOnlySpan<byte> identityHashOrKey32,
        ReadOnlySpan<byte> capability16)
    {
        Span<byte> payload = stackalloc byte[49];
        payload[0] = formatVersion;
        identityHashOrKey32.CopyTo(payload[1..33]);
        capability16.CopyTo(payload[33..]);
        var data = ConvertBits(payload, 8, 5, true);
        var checksum = CreateChecksum(Hrp, data);
        var builder = new StringBuilder(90).Append(Hrp).Append('1');
        foreach (var value in data)
            builder.Append(Alphabet[value]);
        foreach (var value in checksum)
            builder.Append(Alphabet[value]);
        var result = builder.ToString();
        if (result.Length != 90)
            throw new InvalidOperationException("The frozen Deep ID text length is inconsistent.");
        return result;
    }

    internal static byte[] Decode(string text)
        => Decode(text, 1);

    internal static byte[] Decode(string text, byte formatVersion)
    {
        if (text.Length != 90 || text != text.ToLowerInvariant() || !text.StartsWith("deep1", StringComparison.Ordinal))
            Invalid("Deep ID text must be exact lowercase Bech32m with HRP deep.");
        var separator = text.LastIndexOf('1');
        if (separator != 4 || separator + 7 > text.Length)
            Invalid("Deep ID separator or checksum length is invalid.");
        var values = new byte[text.Length - separator - 1];
        for (var index = 0; index < values.Length; index++)
        {
            var alphabetIndex = Alphabet.IndexOf(text[separator + 1 + index]);
            if (alphabetIndex < 0)
                Invalid("Deep ID contains a non-Bech32 character.");
            values[index] = checked((byte)alphabetIndex);
        }
        if (Polymod(HrpExpand(Hrp).Concat(values).ToArray()) != Bech32mConstant)
            Invalid("Deep ID Bech32m checksum is invalid.");
        var payload = ConvertBits(values.AsSpan(0, values.Length - 6), 5, 8, false);
        if (payload.Length != 49 || payload[0] != formatVersion ||
            ApplicationCoreFormat.IsZero(payload.AsSpan(1, 32)) ||
            ApplicationCoreFormat.IsZero(payload.AsSpan(33, 16)))
            Invalid("Deep ID payload is not canonical for its required version.");
        var canonical = Encode(formatVersion, payload.AsSpan(1, 32), payload.AsSpan(33, 16));
        if (!string.Equals(canonical, text, StringComparison.Ordinal))
            Invalid("Deep ID re-encoding is not canonical.");
        return payload;
    }

    private static byte[] CreateChecksum(string hrp, ReadOnlySpan<byte> data)
    {
        var values = HrpExpand(hrp).Concat(data.ToArray()).Concat(new byte[6]).ToArray();
        var polymod = Polymod(values) ^ Bech32mConstant;
        var result = new byte[6];
        for (var index = 0; index < 6; index++)
            result[index] = checked((byte)((polymod >> (5 * (5 - index))) & 31));
        return result;
    }

    private static byte[] HrpExpand(string hrp) =>
        hrp.Select(static c => (byte)(c >> 5)).Concat(new byte[] { 0 }).Concat(hrp.Select(static c => (byte)(c & 31))).ToArray();

    private static uint Polymod(ReadOnlySpan<byte> values)
    {
        ReadOnlySpan<uint> generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        uint checksum = 1;
        foreach (var value in values)
        {
            var top = checksum >> 25;
            checksum = (checksum & 0x1ffffff) << 5 ^ value;
            for (var bit = 0; bit < 5; bit++)
                if (((top >> bit) & 1) != 0)
                    checksum ^= generators[bit];
        }
        return checksum;
    }

    private static byte[] ConvertBits(ReadOnlySpan<byte> input, int fromBits, int toBits, bool pad)
    {
        var accumulator = 0;
        var bits = 0;
        var maximum = (1 << toBits) - 1;
        var output = new List<byte>((input.Length * fromBits + toBits - 1) / toBits);
        foreach (var value in input)
        {
            if ((value >> fromBits) != 0)
                Invalid("Deep ID bit conversion input is invalid.");
            accumulator = (accumulator << fromBits) | value;
            bits += fromBits;
            while (bits >= toBits)
            {
                bits -= toBits;
                output.Add(checked((byte)((accumulator >> bits) & maximum)));
            }
        }
        if (pad)
        {
            if (bits > 0)
                output.Add(checked((byte)((accumulator << (toBits - bits)) & maximum)));
        }
        else if (bits >= fromBits || ((accumulator << (toBits - bits)) & maximum) != 0)
        {
            Invalid("Deep ID has noncanonical padding.");
        }
        return output.ToArray();
    }

    private static void Invalid(string message) =>
        throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.SemanticFields,
            ApplicationCoreRejection.NonCanonicalText, message);
}
