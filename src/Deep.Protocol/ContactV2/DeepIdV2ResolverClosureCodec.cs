using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Parsed DCR1 V2 is an exact support-object candidate, not a directory
/// freshness result, contact publication, prekey claim or message route.
/// </summary>
public sealed class ParsedDcr1V2
{
    private readonly byte[] canonical;

    internal ParsedDcr1V2(byte[] canonical, ParsedDcb1V2 bundle, ParsedXps1V2[] preKeyServiceHistory)
    {
        this.canonical = canonical;
        Bundle = bundle;
        PreKeyServiceHistory = Array.AsReadOnly(preKeyServiceHistory);
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ParsedDcb1V2 Bundle { get; }
    /// <summary>Parsed historical suffix only; no published left boundary or current authority.</summary>
    public IReadOnlyList<ParsedXps1V2> PreKeyServiceHistory { get; }
}

/// <summary>
/// Exact DID2-only DCR1 support closure. Network publication remains disabled
/// until freshness, XPS1, route and resolver-service gates are closed.
/// </summary>
public static class DeepIdV2ResolverClosureCodec
{
    public const int MaximumLength = 65_535;
    public const int MaximumPreKeyServiceHistoryEntries = 45;
    public static bool RuntimeActivation => false;

    public static ParsedDcr1V2 Decode(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> slices = stackalloc ApplicationFieldSlice[4];
        ApplicationCoreFormat.Preflight(canonical, ProtocolMagicBytes.DCR1, 4,
            62 + DeepIdV2ContactBundleCodec.MinimumLength + 1,
            MaximumLength, slices, 2, DeepIdV2Codec.Suite);
        ApplicationCoreFormat.ExactLength(slices, 1, 16);
        ApplicationCoreFormat.ExactLength(slices, 3, 2);
        var bundleBytes = Get(canonical, slices, 2);
        var support = Get(canonical, slices, 4);
        if (bundleBytes.Length is < DeepIdV2ContactBundleCodec.MinimumLength or
            > DeepIdV2ContactBundleCodec.MaximumLength ||
            support.Length is < 1 or > 16_384 ||
            canonical.Length != 62 + bundleBytes.Length + support.Length)
            Invalid(ApplicationCoreRejection.InvalidFieldLength,
                "DCR1 V2 bundle or support length is invalid.");
        var bundle = DeepIdV2ContactBundleCodec.Decode(bundleBytes);
        if (!Get(canonical, slices, 1).SequenceEqual(bundle.FieldSpan(1)))
            Invalid(ApplicationCoreRejection.InvalidReference,
                "DCR1 V2 network differs from its exact DCB1 V2.");
        var directory = ApplicationCoreCodec.DecodeDmd1(bundle.FieldSpan(5));
        var count = BinaryPrimitives.ReadUInt16BigEndian(Get(canonical, slices, 3));
        if (count < directory.ActiveDevices.Count + 1 || count > directory.ActiveDevices.Count + 1 + MaximumPreKeyServiceHistoryEntries)
            Invalid(ApplicationCoreRejection.InvalidFieldLength,
                "DCR1 V2 support count exceeds its exact device and history bounds.");

        var offset = 0;
        var sawDrs = false;
        var dpds = new List<DeviceCertificate>(directory.ActiveDevices.Count);
        var history = new List<ParsedXps1V2>();
        ushort previousKind = 0;
        byte[]? previousHash = null;
        for (var index = 0; index < count; index++)
        {
            if (support.Length - offset < 6)
                Invalid(ApplicationCoreRejection.InvalidFieldLength,
                    "DCR1 V2 support entry header is truncated.");
            var kind = BinaryPrimitives.ReadUInt16BigEndian(support[offset..]);
            var encodedLength = BinaryPrimitives.ReadUInt32BigEndian(support[(offset + 2)..]);
            offset += 6;
            if (kind is < 1 or > 3 || encodedLength > int.MaxValue ||
                encodedLength < 12 || encodedLength > support.Length - offset)
                Invalid(ApplicationCoreRejection.InvalidFieldLength,
                    "DCR1 V2 support entry is unknown or out of bounds.");
            var length = (int)encodedLength;
            var entry = support.Slice(offset, length);
            var hash = SHA256.HashData(entry);
            if (kind < previousKind ||
                (kind == previousKind && previousHash is not null &&
                 previousHash.AsSpan().SequenceCompareTo(hash) >= 0))
                Invalid(ApplicationCoreRejection.InvalidReference,
                    "DCR1 V2 support entries are not strictly ordered.");
            previousKind = kind;
            previousHash = hash;
            offset += length;
            if (kind == 1)
            {
                if (sawDrs)
                    Invalid(ApplicationCoreRejection.InvalidReference,
                        "DCR1 V2 has duplicate DRS1 support.");
                var drs = IdentityCodec.DecodeRevocationSnapshot(entry);
                if (!drs.CanonicalHash.Span.SequenceEqual(bundle.FieldSpan(4)[6..]))
                    Invalid(ApplicationCoreRejection.InvalidReference,
                        "DCR1 V2 DRS1 reference differs from DCB1 V2.");
                sawDrs = true;
            }
            else if (kind == 2)
            {
                if (length != 776)
                    Invalid(ApplicationCoreRejection.InvalidFieldLength,
                        "DCR1 V2 DPD1 has a noncanonical length.");
                dpds.Add(IdentityCodec.DecodeDeviceCertificate(entry));
            }
            else
            {
                if (length != DeepIdV2PreKeyServiceCodec.CanonicalLength)
                    Invalid(ApplicationCoreRejection.InvalidFieldLength, "DCR1 V2 historical XPS1 has a noncanonical length.");
                history.Add(DeepIdV2PreKeyServiceCodec.Decode(entry));
            }
        }
        if (offset != support.Length || !sawDrs ||
            dpds.Count != directory.ActiveDevices.Count || count != 1 + dpds.Count + history.Count)
            Invalid(ApplicationCoreRejection.InvalidFieldLength,
                "DCR1 V2 support closure is incomplete or trailing.");
        foreach (var device in directory.ActiveDevices)
        {
            var certificate = dpds.SingleOrDefault(candidate =>
                candidate.CanonicalHash.Span.SequenceEqual(
                    device.Dpd1Reference.CanonicalHash.Span));
            if (certificate is null ||
                !certificate.NetworkId.Span.SequenceEqual(directory.NetworkId.Span) ||
                !certificate.AccountHash.Span.SequenceEqual(directory.DeepAccountId.Span) ||
                certificate.AccountGeneration != directory.AccountGeneration ||
                !certificate.DeviceId.Span.SequenceEqual(device.DeviceId.Span))
                Invalid(ApplicationCoreRejection.InvalidReference,
                    "DCR1 V2 DPD1 does not close over the exact DMD1 device.");
        }
        return new ParsedDcr1V2(canonical.ToArray(), bundle, history.ToArray());
    }

    /// <summary>
    /// Requires byte-identical verified DRS1/DPD1 custody, DCB1 issuer and
    /// each signed XPS1 descriptor. Fresh ADH1/ADP1, XPI1/DPK2 and
    /// contact-service evidence are still mandatory.
    /// </summary>
    public static void VerifyIdentityAndSupport(ParsedDcr1V2 closure,
        VerifiedDca1V2 authorization, ulong trustedUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(closure);
        ArgumentNullException.ThrowIfNull(authorization);
        DeepIdV2ContactBundleCodec.VerifyPreKeyServices(
            closure.Bundle, authorization, trustedUnixSeconds);
        var canonical = closure.CanonicalBytes.ToArray();
        Span<ApplicationFieldSlice> slices = stackalloc ApplicationFieldSlice[4];
        ApplicationCoreFormat.Preflight(canonical,
            ProtocolMagicBytes.DCR1, 4,
            62 + DeepIdV2ContactBundleCodec.MinimumLength + 1,
            MaximumLength, slices, 2, DeepIdV2Codec.Suite);
        var support = Get(canonical, slices, 4);
        var identity = authorization.Binding.Identity;
        var expected = new Dictionary<string, VerifiedDevice>(StringComparer.Ordinal);
        foreach (var device in identity.ActiveDevices)
            expected.Add(Convert.ToHexString(device.Certificate.CanonicalHash.Span), device);
        var offset = 0;
        var sawDrs = false;
        while (offset < support.Length)
        {
            var kind = BinaryPrimitives.ReadUInt16BigEndian(support[offset..]);
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                support[(offset + 2)..]));
            offset += 6;
            var entry = support.Slice(offset, length);
            offset += length;
            if (kind == 1)
            {
                if (sawDrs || !entry.SequenceEqual(
                    identity.Revocations.Snapshot.CanonicalBytes.Span))
                    Reject("DCR1 V2 DRS1 bytes differ from verified custody.");
                sawDrs = true;
            }
            else if (kind == 2)
            {
                var certificate = IdentityCodec.DecodeDeviceCertificate(entry);
                var hash = Convert.ToHexString(certificate.CanonicalHash.Span);
                if (!expected.Remove(hash, out var device) ||
                    !entry.SequenceEqual(device.Certificate.CanonicalBytes.Span))
                    Reject("DCR1 V2 DPD1 bytes differ from verified custody.");
            }
        }
        if (!sawDrs || expected.Count != 0)
            Reject("DCR1 V2 verified support closure is incomplete.");
        VerifyServiceHistorySuffix(closure, authorization);
    }

    private static void VerifyServiceHistorySuffix(ParsedDcr1V2 closure, VerifiedDca1V2 authorization)
    {
        if (closure.PreKeyServiceHistory.Count == 0) return;
        var remaining = closure.PreKeyServiceHistory.ToList();
        var services = closure.Bundle.Field(12);
        foreach (var active in authorization.Directory.Record.ActiveDevices)
        {
            var device = authorization.Binding.Identity.ActiveDevices.Single(value =>
                value.Certificate.DeviceId.Span.SequenceEqual(active.DeviceId.Span));
            ParsedXps1V2? current = null;
            for (var offset = 1; offset < services.Length; offset += 356)
            {
                var item = DeepIdV2PreKeyServiceCodec.Decode(services.Span.Slice(offset + 4, 352));
                if (item.Field(3).Span.SequenceEqual(active.DeviceId.Span)) current = item;
            }
            if (current is null) Reject("DCR1 V2 historical support has no current service endpoint.");
            var group = remaining.Where(value => value.Field(3).Span.SequenceEqual(active.DeviceId.Span))
                .OrderBy(value => BinaryPrimitives.ReadUInt64BigEndian(value.Field(5).Span)).ToArray();
            if (group.Length == 0) continue;
            var endpointGeneration = BinaryPrimitives.ReadUInt64BigEndian(current!.Field(5).Span);
            var previous = group[0];
            if (BinaryPrimitives.ReadUInt64BigEndian(previous.Field(5).Span) >= endpointGeneration)
                Reject("DCR1 V2 history includes a current endpoint or unnecessary successor.");
            for (var index = 1; index < group.Length; index++)
            {
                var generation = BinaryPrimitives.ReadUInt64BigEndian(group[index].Field(5).Span);
                if (generation >= endpointGeneration || generation <=
                    BinaryPrimitives.ReadUInt64BigEndian(previous.Field(5).Span))
                    Reject("DCR1 V2 history repeats a generation or includes its current endpoint.");
                DeepIdV2PreKeyLineageVerifier.VerifyServiceTransition(group[index], previous, device.Certificate.DeviceEd25519PublicKey.Span);
                previous = group[index];
            }
            DeepIdV2PreKeyLineageVerifier.VerifyServiceTransition(current, previous, device.Certificate.DeviceEd25519PublicKey.Span);
            foreach (var item in group) remaining.Remove(item);
        }
        if (remaining.Count != 0) Reject("DCR1 V2 history contains a foreign or unused device.");
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static ParsedDcr1V2 AuthorForValidation(
        ReadOnlySpan<byte> networkId16, ReadOnlySpan<byte> exactDcb1V2,
        ushort supportCount, ReadOnlySpan<byte> supportEntries)
    {
        var total = 62 + exactDcb1V2.Length + supportEntries.Length;
        if (total > MaximumLength)
            throw new ArgumentException("DCR1 V2 total exceeds the exact bound.");
        var bytes = new byte[total];
        var writer = new ApplicationRecordWriter(bytes,
            ProtocolMagicBytes.DCR1, 4, 2, DeepIdV2Codec.Suite);
        Span<byte> count = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(count, supportCount);
        writer.Write(1, networkId16);
        writer.Write(2, exactDcb1V2);
        writer.Write(3, count);
        writer.Write(4, supportEntries);
        writer.Complete();
        return Decode(bytes);
    }
#endif

    private static ReadOnlySpan<byte> Get(ReadOnlySpan<byte> canonical,
        ReadOnlySpan<ApplicationFieldSlice> slices, int tag) =>
        ApplicationCoreFormat.Field(canonical, slices, tag);

    private static void Invalid(ApplicationCoreRejection rejection,
        string message) => throw ApplicationCoreFormat.Error(
            ApplicationCoreValidationStage.SemanticFields, rejection, message);

    private static void Reject(string message) => throw ApplicationCoreFormat.Error(
        ApplicationCoreValidationStage.CryptographicVerification,
        ApplicationCoreRejection.VerificationFailed, message);
}
