using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepNative;

internal readonly record struct MembershipCatalogRow(
    ArtifactType Type,
    int CanonicalOffset,
    int CanonicalLength,
    ReadOnlyMemory<byte> CanonicalHash);

internal sealed class OwnedMembershipCatalog
{
    private readonly ReadOnlyMemory<byte> _canonical;
    private readonly MembershipCatalogRow[] _rows;

    internal OwnedMembershipCatalog(ReadOnlyMemory<byte> canonical, MembershipCatalogRow[] rows)
    {
        _canonical = canonical;
        _rows = rows;
    }

    internal IReadOnlyList<MembershipCatalogRow> Rows => _rows;
    internal ReadOnlySpan<byte> RowBytes(int index)
    {
        var row = _rows[index];
        return _canonical.Span.Slice(row.CanonicalOffset, row.CanonicalLength);
    }
}

internal static class MembershipCatalogParser
{
    private const int HeaderLength = 10;
    internal const int MaximumBytes = 16_777_216;
    internal const int MaximumEntries = 16_389;
    internal const int MaximumTransitions = 4_096;

    internal static OwnedMembershipCatalog DecodeOwned(
        ReadOnlySpan<byte> canonical,
        uint expectedEntries,
        uint memberCount)
    {
        Preflight(canonical, expectedEntries, memberCount);
        var owned = canonical.ToArray();
        Preflight(owned, expectedEntries, memberCount);
        var rows = DescribeAndVerify(owned, expectedEntries);
        return new OwnedMembershipCatalog(owned, rows);
    }

    internal static OwnedMembershipCatalog DecodeBorrowedOwnedSnapshot(
        ReadOnlyMemory<byte> canonical,
        uint expectedEntries,
        uint memberCount)
    {
        Preflight(canonical.Span, expectedEntries, memberCount);
        var rows = DescribeAndVerify(canonical.Span, expectedEntries);
        return new OwnedMembershipCatalog(canonical, rows);
    }

    internal static void Preflight(
        ReadOnlySpan<byte> canonical,
        uint expectedEntries,
        uint memberCount)
    {
        if (canonical.Length < HeaderLength || canonical.Length > MaximumBytes ||
            !canonical[..4].SequenceEqual("MRC1"u8) || canonical[4] != 1 || canonical[5] != 0)
            Invalid(RecordError.InvalidHeader, "The MRC1 header is invalid.");
        var count = BinaryPrimitives.ReadUInt32BigEndian(canonical[6..10]);
        if (count != expectedEntries || count is < 8 or > MaximumEntries ||
            memberCount is < 1 or > 4_096)
            Invalid(RecordError.InvalidField, "The MRC1 count is invalid.");
        var memberRows = checked(3u * memberCount);
        if (count < 5u + memberRows)
            Invalid(RecordError.InvalidField, "The MRC1 member count is inconsistent.");
        var transitions = count - 5u - memberRows;
        if (transitions > MaximumTransitions)
            Invalid(RecordError.InvalidField, "The MRC1 transition count exceeds the bound.");

        var offset = HeaderLength;
        for (uint index = 0; index < count; index++)
        {
            if (canonical.Length - offset < ArtifactReference.Length)
                Invalid(RecordError.InvalidLength, "An MRC1 row is truncated.");
            var typeValue = BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(offset, 2));
            var length = BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(offset + 2, 4));
            if (!Enum.IsDefined(typeof(ArtifactType), typeValue) || length == 0 ||
                length > int.MaxValue || CanonicalGrammar.IsZero(canonical.Slice(offset + 6, 32)))
                Invalid(RecordError.InvalidArtifactReference, "An MRC1 row reference is invalid.");
            var expectedType = ExpectedType(index, transitions);
            if ((ArtifactType)typeValue != expectedType &&
                !(index > 0 && index <= transitions &&
                  (typeValue == (ushort)ArtifactType.Mdg1 || typeValue == (ushort)ArtifactType.Mrv1)))
                Invalid(RecordError.InvalidArtifactReference, "The MRC1 row order is invalid.");
            var remaining = canonical.Length - offset - ArtifactReference.Length;
            if (remaining < 0 || length > checked((uint)remaining))
                Invalid(RecordError.InvalidLength, "An MRC1 artifact is truncated.");
            offset += ArtifactReference.Length + (int)length;
        }
        if (offset != canonical.Length)
            Invalid(RecordError.InvalidLength, "The MRC1 catalog has trailing bytes.");
    }

    private static MembershipCatalogRow[] DescribeAndVerify(ReadOnlySpan<byte> canonical, uint count)
    {
        var rows = new MembershipCatalogRow[count];
        var offset = HeaderLength;
        for (var index = 0; index < rows.Length; index++)
        {
            var type = (ArtifactType)BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(offset, 2));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(offset + 2, 4)));
            var expectedHash = canonical.Slice(offset + 6, 32);
            var bytesOffset = offset + ArtifactReference.Length;
            var bytes = canonical.Slice(bytesOffset, length);
            byte[] actualHash;
            if (ArtifactRegistry.IsRetained(type))
            {
                actualHash = SHA256.HashData(bytes);
            }
            else
            {
                CanonicalGrammar.Preflight(
                    bytes,
                    RecoveryManifestParser.Definition(type));
                actualHash = CanonicalGrammar.ComputeReference(type, bytes).CanonicalHash.ToArray();
            }
            if (!CanonicalGrammar.FixedEquals(actualHash, expectedHash))
                Invalid(RecordError.InvalidArtifactReference,
                    "An MRC1 row does not reproduce its exact reference.");
            rows[index] = new MembershipCatalogRow(
                type,
                bytesOffset,
                length,
                expectedHash.ToArray());
            offset = checked(bytesOffset + length);
        }
        return rows;
    }

    private static ArtifactType ExpectedType(uint index, uint transitions)
    {
        if (index == 0) return ArtifactType.Mng1;
        if (index <= transitions) return ArtifactType.Mdg1; // MDG/MRV union checked by caller.
        var tail = index - transitions - 1;
        return tail switch
        {
            0 => ArtifactType.Mmc1,
            1 => ArtifactType.Msm1,
            2 => ArtifactType.Pma1,
            3 => ArtifactType.Pmr1,
            _ => ((tail - 4) % 3) switch
            {
                0 => ArtifactType.Dnr1,
                1 => ArtifactType.Mrl2,
                _ => ArtifactType.Dpc1
            }
        };
    }

    private static void Invalid(RecordError error, string message) =>
        throw new RecordException(error, message);
}

/// <summary>
/// Exact MRLC envelope, catalog framing and local HMAC match. This is not yet a membership or
/// mailbox-authority fact; only the high-level closure verifier can mint the sealed LKG.
/// </summary>
public sealed class MembershipCatalogEnvelopeRelative
{
    private readonly byte[] _canonical;
    private readonly byte[] _catalogHash;
    private readonly byte[] _verifiedHmac;

    internal MembershipCatalogEnvelopeRelative(
        OwnedRecord record,
        OwnedMembershipCatalog catalog,
        ReadOnlySpan<byte> verifiedHmac)
    {
        Record = record;
        Catalog = catalog;
        _canonical = record.CanonicalCopy();
        _catalogHash = record.FieldCopy(25);
        _verifiedHmac = verifiedHmac.ToArray();
    }

    internal OwnedRecord Record { get; }
    internal OwnedMembershipCatalog Catalog { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => _canonical.ToArray();
    public ReadOnlyMemory<byte> CatalogHash => _catalogHash.ToArray();
    public ReadOnlyMemory<byte> VerifiedHmac => _verifiedHmac.ToArray();
    public uint ArtifactEntryCount => BinaryPrimitives.ReadUInt32BigEndian(Record.FieldSpan(23));
    public uint MemberCount => BinaryPrimitives.ReadUInt32BigEndian(Record.FieldSpan(13));
    public bool NoAuthorityClaim => true;
}

public static class MembershipCatalogEnvelopeVerifier
{
    private const string CatalogHashDomain = "Deep/NativeRouting/V2/catalog-hash";
    private const string ProtectedDomain = "Deep/ProtectedState/V1/MRLC1";

    public static async ValueTask<MembershipCatalogEnvelopeRelative> VerifyAsync(
        ReadOnlyMemory<byte> canonicalMrlc,
        ReadOnlyMemory<byte> protectedStateKeyId32,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken = default)
    {
        var pending = Parse(canonicalMrlc.Span, protectedStateKeyId32.Span);
        return await VerifyPendingAsync(pending, provider, cancellationToken).ConfigureAwait(false);
    }

    internal static MembershipCatalogEnvelopePending Parse(
        ReadOnlySpan<byte> canonicalMrlc,
        ReadOnlySpan<byte> protectedStateKeyId32)
    {
        if (protectedStateKeyId32.Length != 32 || CanonicalGrammar.IsZero(protectedStateKeyId32))
            throw new RecordException(RecordError.InvalidField,
                "The MRLC protected-state key ID is invalid.");
        CanonicalGrammar.Preflight(canonicalMrlc, RecordDefinitions.Mrlc);
        var record = CanonicalGrammar.DecodeOwned(canonicalMrlc, RecordDefinitions.Mrlc);
        var count = BinaryPrimitives.ReadUInt32BigEndian(record.FieldSpan(23));
        var members = BinaryPrimitives.ReadUInt32BigEndian(record.FieldSpan(13));
        var catalog = MembershipCatalogParser.DecodeBorrowedOwnedSnapshot(
            record.FieldMemory(26), count, members);
        if (!CanonicalGrammar.FixedEquals(
                ComputeCatalogHash(count, record.FieldSpan(26)),
                record.FieldSpan(25)))
            throw new RecordException(RecordError.InvalidArtifactReference,
                "The MRLC catalog hash is invalid.");
        var definition = record.Definition with
        {
            Fields = record.Definition.Fields.Take(26).ToArray(),
            MinimumLength = 12,
            MaximumLength = RecordDefinitions.Mrlc.MaximumLength,
            OmittedSigningFieldIndexes = new HashSet<int>()
        };
        var fields = Enumerable.Range(1, 26)
            .Select(tag => (ReadOnlyMemory<byte>)record.FieldCopy(tag)).ToArray();
        return new MembershipCatalogEnvelopePending(
            record,
            catalog,
            protectedStateKeyId32,
            CanonicalGrammar.Encode(definition, fields));
    }

    internal static async ValueTask<MembershipCatalogEnvelopeRelative> VerifyPendingAsync(
        MembershipCatalogEnvelopePending pending,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pending);
        ArgumentNullException.ThrowIfNull(provider);
        cancellationToken.ThrowIfCancellationRequested();
        var request = new ProtectedHmacRequest(
            ProtectedDomain,
            ArtifactRegistry.ProtectedHmacSha256,
            pending.ProtectedStateKeyId,
            pending.UnsignedCanonical);
        var returned = await provider.ComputeTagAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var ownedTag = returned.ToArray();
        if (ownedTag.Length != 32 ||
            !CanonicalGrammar.FixedEquals(ownedTag, pending.Record.FieldSpan(27)))
            throw new RecordException(RecordError.InvalidSignature,
                "The MRLC protected-state HMAC is invalid.");
        return new MembershipCatalogEnvelopeRelative(pending.Record, pending.Catalog, ownedTag);
    }

    internal static byte[] ComputeCatalogHash(uint count, ReadOnlySpan<byte> catalog)
    {
        Span<byte> prefix = stackalloc byte[12];
        BinaryPrimitives.WriteUInt32BigEndian(prefix[..4], count);
        BinaryPrimitives.WriteUInt64BigEndian(prefix[4..12], checked((ulong)catalog.Length));
        var domain = System.Text.Encoding.ASCII.GetBytes(CatalogHashDomain);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> scalar = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(scalar[..2], checked((ushort)domain.Length));
        hash.AppendData(scalar[..2]);
        hash.AppendData(domain);
        BinaryPrimitives.WriteUInt32BigEndian(scalar, checked((uint)(prefix.Length + catalog.Length)));
        hash.AppendData(scalar);
        hash.AppendData(prefix);
        hash.AppendData(catalog);
        return hash.GetHashAndReset();
    }
}

internal sealed class MembershipCatalogEnvelopePending
{
    private readonly byte[] _keyId;
    private readonly byte[] _unsigned;
    internal MembershipCatalogEnvelopePending(
        OwnedRecord record,
        OwnedMembershipCatalog catalog,
        ReadOnlySpan<byte> keyId,
        ReadOnlySpan<byte> unsigned)
    {
        Record = record;
        Catalog = catalog;
        _keyId = keyId.ToArray();
        _unsigned = unsigned.ToArray();
    }
    internal OwnedRecord Record { get; }
    internal OwnedMembershipCatalog Catalog { get; }
    internal ReadOnlySpan<byte> ProtectedStateKeyId => _keyId;
    internal ReadOnlySpan<byte> UnsignedCanonical => _unsigned;
}
