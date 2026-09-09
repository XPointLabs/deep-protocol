using System.Buffers.Binary;
using System.Text;

namespace Deep.Protocol.ApplicationCore;

public static partial class ApplicationCoreCodec
{
    public const ushort Dab1ArtifactTypeCode = 0x1001;
    private static ReadOnlySpan<byte> DidMagic => ProtocolMagicBytes.DID1;
    private static ReadOnlySpan<byte> DabMagic => ProtocolMagicBytes.DAB1;
    private static ReadOnlySpan<byte> DmdMagic => ProtocolMagicBytes.DMD1;
    private static ReadOnlySpan<byte> DcaMagic => ProtocolMagicBytes.DCA1;
    private static ReadOnlySpan<byte> DaoMagic => ProtocolMagicBytes.DAO1;
    private static readonly int[] DaoTotals =
    [
        4725, 4821, 4885, 5685, 5877, 6129, 17013, 17109, 17173, 17973, 18165,
        18417, 33397, 33493, 33557, 34357, 34549, 34801, 49765, 49861, 49925,
        50725, 50917,
    ];

    public static ParsedDid1 DecodeDid1(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[2];
        ApplicationCoreFormat.Preflight(canonical, DidMagic, 2, 76, 76, fields);
        ApplicationCoreFormat.ExactLength(fields, 1, 32);
        ApplicationCoreFormat.ExactLength(fields, 2, 16);
        ApplicationCoreFormat.NonZero(ApplicationCoreFormat.Field(canonical, fields, 1), "DID1 address public key");
        ApplicationCoreFormat.NonZero(ApplicationCoreFormat.Field(canonical, fields, 2), "DID1 resolver read capability");

        var owned = canonical.ToArray();
        return new ParsedDid1(owned, Field(owned, fields, 1), Field(owned, fields, 2));
    }

    public static ParsedDid1 AuthorDid1(ReadOnlySpan<byte> addressPublicKey32, ReadOnlySpan<byte> resolverReadCapability16)
    {
        RequireLength(addressPublicKey32, 32, "address public key");
        RequireLength(resolverReadCapability16, 16, "resolver read capability");
        var canonical = AllocateRecord(2, addressPublicKey32.Length + resolverReadCapability16.Length);
        var writer = new ApplicationRecordWriter(canonical, DidMagic, 2);
        writer.Write(1, addressPublicKey32);
        writer.Write(2, resolverReadCapability16);
        writer.Complete();
        return DecodeDid1(canonical);
    }

    public static ParsedDid1 DecodeDeepIdText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var payload = DeepIdText.Decode(text);
        return AuthorDid1(payload.AsSpan(1, 32), payload.AsSpan(33, 16));
    }

    public static ParsedDab1 DecodeDab1(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[9];
        ApplicationCoreFormat.Preflight(canonical, DabMagic, 9, 394, 394, fields);
        Exact(fields, 32, 32, 8, 32, 32, 8, 38, 64, 64);
        var didHash = Field(canonical, fields, 1);
        var realm = Field(canonical, fields, 2);
        var generation = U64(Field(canonical, fields, 3));
        var predecessor = Field(canonical, fields, 4);
        var account = Field(canonical, fields, 5);
        var accountGeneration = U64(Field(canonical, fields, 6));
        ApplicationCoreFormat.NonZero(didHash, "DAB1 DID hash");
        ApplicationCoreFormat.NonZero(realm, "DAB1 identity realm");
        ApplicationCoreFormat.NonZero(account, "DAB1 account ID");
        if (accountGeneration == 0)
            Invalid(ApplicationCoreRejection.InvalidGeneration, "DAB1 account generation starts at one.");
        ValidatePredecessor(generation, predecessor, zeroGeneration: 0, ProtocolMagic.DAB1);
        ValidateReference(Field(canonical, fields, 7), 1, 644, 644, ProtocolMagic.DPA1);

        var owned = canonical.ToArray();
        var dpa = ParseReference(Field(owned, fields, 7), 1, 644, 644, ProtocolMagic.DPA1);
        var unsigned = Projection(DabMagic, owned, fields, [1, 2, 3, 4, 5, 6, 7]);
        if (unsigned.Length != 250)
            throw new InvalidOperationException("The frozen DAB1 projection size is inconsistent.");
        return new ParsedDab1(owned, Field(owned, fields, 1), Field(owned, fields, 2), generation,
            Field(owned, fields, 4), Field(owned, fields, 5), accountGeneration, dpa,
            Field(owned, fields, 8), Field(owned, fields, 9), unsigned);
    }

    public static ParsedDab1 AuthorDab1(
        ReadOnlySpan<byte> exactDid1Hash32,
        ReadOnlySpan<byte> identityRealmId32,
        ulong bindingGeneration,
        ReadOnlySpan<byte> predecessorDab1Hash32,
        ReadOnlySpan<byte> deepAccountId32,
        ulong accountGeneration,
        ApplicationArtifactReference exactDpa1Reference,
        ReadOnlySpan<byte> addressSignature64,
        ReadOnlySpan<byte> accountSignature64)
    {
        RequireLength(exactDid1Hash32, 32, "DID1 hash");
        RequireLength(identityRealmId32, 32, "identity realm");
        RequireLength(predecessorDab1Hash32, 32, "DAB1 predecessor");
        RequireLength(deepAccountId32, 32, "account ID");
        RequireReference(exactDpa1Reference, 1, 644, 644, ProtocolMagic.DPA1);
        RequireLength(addressSignature64, 64, "address signature");
        RequireLength(accountSignature64, 64, "account signature");
        Span<byte> bindingGenerationBytes = stackalloc byte[8];
        Span<byte> accountGenerationBytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bindingGenerationBytes, bindingGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(accountGenerationBytes, accountGeneration);
        var dpaReference = exactDpa1Reference.CanonicalBytes;
        var canonical = AllocateRecord(9, exactDid1Hash32.Length + identityRealmId32.Length +
            bindingGenerationBytes.Length + predecessorDab1Hash32.Length + deepAccountId32.Length +
            accountGenerationBytes.Length + dpaReference.Length + addressSignature64.Length + accountSignature64.Length);
        var writer = new ApplicationRecordWriter(canonical, DabMagic, 9);
        writer.Write(1, exactDid1Hash32);
        writer.Write(2, identityRealmId32);
        writer.Write(3, bindingGenerationBytes);
        writer.Write(4, predecessorDab1Hash32);
        writer.Write(5, deepAccountId32);
        writer.Write(6, accountGenerationBytes);
        writer.Write(7, dpaReference.Span);
        writer.Write(8, addressSignature64);
        writer.Write(9, accountSignature64);
        writer.Complete();
        return DecodeDab1(canonical);
    }

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

    public static ParsedDca1 DecodeDca1(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[14];
        ApplicationCoreFormat.Preflight(canonical, DcaMagic, 14, 473, 473, fields);
        Exact(fields, 16, 32, 38, 8, 32, 32, 32, 1, 8, 8, 8, 64, 32, 38);
        var account = Field(canonical, fields, 2);
        var dmdGeneration = U64(Field(canonical, fields, 4));
        var mask = Field(canonical, fields, 8)[0];
        var notBefore = U64(Field(canonical, fields, 10));
        var expiresAt = U64(Field(canonical, fields, 11));
        ApplicationCoreFormat.NonZero(Field(canonical, fields, 1), "DCA1 network ID");
        ApplicationCoreFormat.NonZero(account, "DCA1 account ID");
        ApplicationCoreFormat.NonZero(Field(canonical, fields, 5), "DCA1 DMD1 hash");
        ApplicationCoreFormat.NonZero(Field(canonical, fields, 6), "DCA1 authorization ID");
        ApplicationCoreFormat.NonZero(Field(canonical, fields, 7), "DCA1 publisher device ID");
        ApplicationCoreFormat.NonZero(Field(canonical, fields, 13), "DCA1 DID1 hash");
        if (dmdGeneration == 0)
            Invalid(ApplicationCoreRejection.InvalidGeneration, "DCA1 DMD1 generation starts at one.");
        if (mask == 0 || (mask & ~0x03) != 0)
            Invalid(ApplicationCoreRejection.InvalidFlags, "DCA1 invite-kind mask is empty or contains unknown bits.");
        if (expiresAt == 0 || expiresAt <= notBefore)
            Invalid(ApplicationCoreRejection.InvalidTimeRange, "DCA1 expiry must be after not-before.");
        ValidateReference(Field(canonical, fields, 3), 1, 644, 644, ProtocolMagic.DPA1);
        ValidateReference(Field(canonical, fields, 14), Dab1ArtifactTypeCode, 394, 394, ProtocolMagic.DAB1);

        var owned = canonical.ToArray();
        var dpa = ParseReference(Field(owned, fields, 3), 1, 644, 644, ProtocolMagic.DPA1);
        var dab = ParseReference(Field(owned, fields, 14), Dab1ArtifactTypeCode, 394, 394, ProtocolMagic.DAB1);
        var projection = Projection(DcaMagic, owned, fields, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14]);
        if (projection.Length != 401)
            throw new InvalidOperationException("The frozen DCA1 projection size is inconsistent.");
        return new ParsedDca1(owned, Field(owned, fields, 1), Field(owned, fields, 2),
            dpa, dmdGeneration, Field(owned, fields, 5), Field(owned, fields, 6),
            Field(owned, fields, 7), mask, U64(Field(owned, fields, 9)), notBefore, expiresAt,
            Field(owned, fields, 12), Field(owned, fields, 13), dab, projection);
    }

    public static ParsedDca1 AuthorDca1(
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> deepAccountId32,
        ApplicationArtifactReference exactDpa1Reference,
        ulong authorizedDmd1Generation,
        ReadOnlySpan<byte> authorizedDmd1Hash32,
        ReadOnlySpan<byte> authorizationId32,
        ReadOnlySpan<byte> publisherDeviceId32,
        byte allowedInviteKindMask,
        ulong maximumBundleGeneration,
        ulong notBeforeUnixSeconds,
        ulong expiresAtUnixSeconds,
        ReadOnlySpan<byte> accountSignature64,
        ReadOnlySpan<byte> exactDid1Hash32,
        ApplicationArtifactReference exactCurrentDab1Reference)
    {
        RequireLength(networkId16, 16, "network ID");
        RequireLength(deepAccountId32, 32, "account ID");
        RequireReference(exactDpa1Reference, 1, 644, 644, ProtocolMagic.DPA1);
        RequireLength(authorizedDmd1Hash32, 32, "DMD1 hash");
        RequireLength(authorizationId32, 32, "authorization ID");
        RequireLength(publisherDeviceId32, 32, "publisher device ID");
        RequireLength(accountSignature64, 64, "account signature");
        RequireLength(exactDid1Hash32, 32, "DID1 hash");
        RequireReference(exactCurrentDab1Reference, null, 394, 394, ProtocolMagic.DAB1);
        Span<byte> dmdGenerationBytes = stackalloc byte[8];
        Span<byte> inviteKindMaskBytes = stackalloc byte[1];
        Span<byte> maximumBundleGenerationBytes = stackalloc byte[8];
        Span<byte> notBeforeBytes = stackalloc byte[8];
        Span<byte> expiresAtBytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(dmdGenerationBytes, authorizedDmd1Generation);
        inviteKindMaskBytes[0] = allowedInviteKindMask;
        BinaryPrimitives.WriteUInt64BigEndian(maximumBundleGenerationBytes, maximumBundleGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(notBeforeBytes, notBeforeUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(expiresAtBytes, expiresAtUnixSeconds);
        var dpaReference = exactDpa1Reference.CanonicalBytes;
        var dabReference = exactCurrentDab1Reference.CanonicalBytes;
        var canonical = AllocateRecord(14, networkId16.Length + deepAccountId32.Length + dpaReference.Length +
            dmdGenerationBytes.Length + authorizedDmd1Hash32.Length + authorizationId32.Length +
            publisherDeviceId32.Length + inviteKindMaskBytes.Length + maximumBundleGenerationBytes.Length +
            notBeforeBytes.Length + expiresAtBytes.Length + accountSignature64.Length + exactDid1Hash32.Length + dabReference.Length);
        var writer = new ApplicationRecordWriter(canonical, DcaMagic, 14);
        writer.Write(1, networkId16);
        writer.Write(2, deepAccountId32);
        writer.Write(3, dpaReference.Span);
        writer.Write(4, dmdGenerationBytes);
        writer.Write(5, authorizedDmd1Hash32);
        writer.Write(6, authorizationId32);
        writer.Write(7, publisherDeviceId32);
        writer.Write(8, inviteKindMaskBytes);
        writer.Write(9, maximumBundleGenerationBytes);
        writer.Write(10, notBeforeBytes);
        writer.Write(11, expiresAtBytes);
        writer.Write(12, accountSignature64);
        writer.Write(13, exactDid1Hash32);
        writer.Write(14, dabReference.Span);
        writer.Complete();
        return DecodeDca1(canonical);
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

    public static ApplicationArtifactReference CreateDab1ArtifactReference(ParsedDab1 binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        return new ApplicationArtifactReference(
            Dab1ArtifactTypeCode,
            checked((uint)binding.CanonicalBytes.Length),
            binding.RecordHash.Span);
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
    {
        Span<byte> payload = stackalloc byte[49];
        payload[0] = 1;
        publicKey32.CopyTo(payload[1..33]);
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
        if (payload.Length != 49 || payload[0] != 1 ||
            ApplicationCoreFormat.IsZero(payload.AsSpan(1, 32)) ||
            ApplicationCoreFormat.IsZero(payload.AsSpan(33, 16)))
            Invalid("Deep ID payload is not canonical version 1.");
        var canonical = Encode(payload.AsSpan(1, 32), payload.AsSpan(33, 16));
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
