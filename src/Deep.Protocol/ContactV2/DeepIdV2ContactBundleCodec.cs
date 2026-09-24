using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Parsed DCB1 V2 bytes are not a publication or first-contact capability.
/// The XPS1, XRA1/PMT2, DCR1 and resolver service closures remain separate gates.
/// </summary>
public sealed class ParsedDcb1V2
{
    private readonly byte[] canonical;
    private readonly byte[][] fields;
    private readonly byte[] unsigned;

    internal ParsedDcb1V2(byte[] canonical, byte[][] fields, byte[] unsigned)
    {
        this.canonical = canonical;
        this.fields = fields;
        this.unsigned = unsigned;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> ObjectHash => SHA256.HashData(canonical);
    public ReadOnlyMemory<byte> SignatureInput => ApplicationCoreFormat.SignatureInput(
        "Deep/Application/V2/contact-bundle", unsigned, DeepIdV2Codec.Suite);
    public ReadOnlyMemory<byte> Field(int tag) => fields[tag - 1].ToArray();
    internal ReadOnlySpan<byte> FieldSpan(int tag) => fields[tag - 1];
}

/// <summary>
/// Isolated DID2-bound DCB1 identity/issuer candidate. It cannot authorize
/// contact publication while the remaining route, prekey and DCR1 gates are open.
/// </summary>
public static class DeepIdV2ContactBundleCodec
{
    public const int MinimumLength = 9_078;
    public const int MaximumLength = 15_596;
    public static bool RuntimeActivation => false;
    private static ReadOnlySpan<int> FieldLengths =>
        [16, 32, 644, 38, -1, 473, 32, 8, 32, 32, 1, -1, 1, 651,
         -1, 4, 8, 8, 64, 228, 40, 32, 2036, 3711];

    public static ParsedDcb1V2 Decode(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> slices = stackalloc ApplicationFieldSlice[24];
        ApplicationCoreFormat.Preflight(canonical, ProtocolMagicBytes.DCB1, 24,
            MinimumLength, MaximumLength, slices, 2, DeepIdV2Codec.Suite);
        var lengths = FieldLengths;
        for (var tag = 1; tag <= lengths.Length; tag++)
            if (lengths[tag - 1] >= 0)
                ApplicationCoreFormat.ExactLength(slices, tag, lengths[tag - 1]);
        var count = Get(canonical, slices, 11)[0];
        if (count is < 1 or > 16 || Get(canonical, slices, 13)[0] != 1 ||
            Get(canonical, slices, 12).Length != 1 + 356 * count ||
            Get(canonical, slices, 12)[0] != count ||
            Get(canonical, slices, 5).Length != 356 + 70 * count ||
            Get(canonical, slices, 15).Length > 128)
            Invalid(ApplicationCoreRejection.InvalidFieldLength,
                "DCB1 V2 device, descriptor or profile length is invalid.");
        try
        {
            var name = Get(canonical, slices, 15);
            var decoded = ApplicationCoreFormat.StrictUtf8.GetString(name);
            if (!ApplicationCoreFormat.StrictUtf8.GetBytes(decoded).AsSpan().SequenceEqual(name))
                Invalid(ApplicationCoreRejection.InvalidFieldLength,
                    "DCB1 V2 profile name is not canonical UTF-8.");
        }
        catch (DecoderFallbackException)
        {
            Invalid(ApplicationCoreRejection.InvalidFieldLength,
                "DCB1 V2 profile name is not canonical UTF-8.");
        }
        foreach (var tag in new[] { 1, 2, 7, 10, 19, 22 })
            ApplicationCoreFormat.NonZero(Get(canonical, slices, tag),
                "DCB1 V2 required field");
        var generation = U64(Get(canonical, slices, 8));
        if (ApplicationCoreFormat.IsZero(Get(canonical, slices, 9)) !=
            (generation == 0))
            Invalid(ApplicationCoreRejection.InvalidLineage,
                "DCB1 V2 predecessor must be zero exactly at genesis.");
        var policy = BinaryPrimitives.ReadUInt32BigEndian(Get(canonical, slices, 16));
        if ((policy & ~0x0bu) != 0 ||
            U64(Get(canonical, slices, 17)) >= U64(Get(canonical, slices, 18)))
            Invalid(ApplicationCoreRejection.InvalidEnum,
                "DCB1 V2 policy or validity is invalid.");
        var drs = Get(canonical, slices, 4);
        if (!drs[..4].SequenceEqual(ProtocolMagicBytes.DRS1) ||
            BinaryPrimitives.ReadUInt16BigEndian(drs[4..6]) != 1 ||
            ApplicationCoreFormat.IsZero(drs[6..]))
            Invalid(ApplicationCoreRejection.InvalidReference,
                "DCB1 V2 requires an exact DRS1 reference.");

        var descriptor = Get(canonical, slices, 14);
        if (BinaryPrimitives.ReadUInt16BigEndian(descriptor) != 1 ||
            BinaryPrimitives.ReadUInt16BigEndian(descriptor[2..]) != 1 ||
            BinaryPrimitives.ReadUInt32BigEndian(descriptor[36..40]) != 611 ||
            !SHA256.HashData(descriptor[40..]).AsSpan().SequenceEqual(descriptor[4..36]))
            Invalid(ApplicationCoreRejection.InvalidReference,
                "DCB1 V2 requires one exact XIR1 V2 descriptor.");
        _ = DeepIdV2InviteRendezvousCodec.Decode(descriptor[40..]);
        _ = IdentityCodec.DecodeAccountCertificate(Get(canonical, slices, 3));
        _ = ApplicationCoreCodec.DecodeDmd1(Get(canonical, slices, 5));
        _ = DeepIdV2Codec.DecodeDid2(Get(canonical, slices, 23));
        _ = DeepIdV2Codec.DecodeDab2(Get(canonical, slices, 24));
        _ = DeepIdV2ContactAuthorizationCodec.Decode(Get(canonical, slices, 6));
        _ = DeepIdV2AccountDirectoryLookupCodec.Decode(Get(canonical, slices, 20));

        var owned = canonical.ToArray();
        var fields = new byte[24][];
        for (var tag = 1; tag <= 24; tag++)
            fields[tag - 1] = ApplicationCoreFormat.Field(owned, slices, tag).ToArray();
        var unsigned = new byte[owned.Length - 72];
        var writer = new ApplicationRecordWriter(unsigned,
            ProtocolMagicBytes.DCB1, 23, 2, DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= 24; tag++)
            if (tag != 19) writer.Write(tag, fields[tag - 1]);
        writer.Complete();
        return new ParsedDcb1V2(owned, fields, unsigned);
    }

    /// <summary>
    /// Verifies DID2/DAB2/DCA1/ADL1 and the issuer device signature only.
    /// It does not verify XPS1 inventory, DCR1 support or route publication.
    /// </summary>
    public static void VerifyIdentityAndIssuer(ParsedDcb1V2 bundle,
        VerifiedDca1V2 authorization, ulong trustedUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        ArgumentNullException.ThrowIfNull(authorization);
        var dca = authorization.Record;
        var binding = authorization.Binding;
        var identity = binding.Identity;
        var directory = authorization.Directory.Record;
        var account = identity.Account.Certificate;
        var did = binding.DeepId;
        var policy = BinaryPrimitives.ReadUInt32BigEndian(bundle.FieldSpan(16));
        var inviteKind = DeepIdV2InviteRendezvousCodec.Decode(
            bundle.FieldSpan(14)[40..]).FieldSpan(9)[0];
        if (!bundle.FieldSpan(1).SequenceEqual(dca.NetworkId.Span) ||
            !bundle.FieldSpan(2).SequenceEqual(dca.DeepAccountId.Span) ||
            !bundle.FieldSpan(3).SequenceEqual(account.CanonicalBytes.Span) ||
            !bundle.FieldSpan(5).SequenceEqual(directory.CanonicalBytes.Span) ||
            !bundle.FieldSpan(6).SequenceEqual(dca.CanonicalBytes.Span) ||
            !bundle.FieldSpan(10).SequenceEqual(dca.PublisherDeviceId.Span) ||
            !bundle.FieldSpan(22).SequenceEqual(did.RecordHash.Span) ||
            !bundle.FieldSpan(23).SequenceEqual(did.CanonicalBytes.Span) ||
            !bundle.FieldSpan(24).SequenceEqual(binding.Record.CanonicalBytes.Span) ||
            bundle.FieldSpan(11)[0] != directory.ActiveDevices.Count ||
            (policy & (uint)(inviteKind == 1 ? 1 : 2)) == 0 ||
            (policy & 0x03u & ~(uint)dca.AllowedInviteKindMask) != 0 ||
            !bundle.FieldSpan(4).SequenceEqual(ReferenceBytes(
                ProtocolMagicBytes.DRS1, 1,
                identity.Revocations.Snapshot.CanonicalHash.Span)))
            Reject("DCB1 V2 is not the exact verified DID2/DAB2/DCA1 closure.");

        var lookup = DeepIdV2AccountDirectoryLookupCodec.Decode(bundle.FieldSpan(20));
        if (!lookup.NetworkId.Span.SequenceEqual(dca.NetworkId.Span) ||
            !bundle.FieldSpan(21)[..8].SequenceEqual(U64Bytes(
                lookup.MinimumAdhGeneration)) ||
            !bundle.FieldSpan(21)[8..].SequenceEqual(lookup.MinimumAdhHash.Span))
            Reject("DCB1 V2 ADL1 minimum checkpoint differs from the signed bundle.");
        _ = DeepIdV2AccountDirectoryLookupCodec.VerifyAndGetDirectoryLeafKey(
            lookup, binding);

        var issued = U64(bundle.FieldSpan(17));
        var expiry = U64(bundle.FieldSpan(18));
        if (U64(bundle.FieldSpan(8)) > dca.MaximumBundleGeneration ||
            issued < dca.NotBeforeUnixSeconds || expiry > dca.ExpiresAtUnixSeconds ||
            trustedUnixSeconds < issued || trustedUnixSeconds >= expiry)
            Reject("DCB1 V2 generation or validity is outside DCA1 V2 authority.");
        var invite = DeepIdV2InviteRendezvousCodec.Decode(bundle.FieldSpan(14)[40..]);
        DeepIdV2InviteRendezvousCodec.VerifyIssuerAndDca1(
            invite, authorization, trustedUnixSeconds);
        if (issued < U64(invite.FieldSpan(13)) ||
            expiry > U64(invite.FieldSpan(14)))
            Reject("DCB1 V2 validity exceeds its exact XIR1 V2 reachability.");
        var device = identity.ActiveDevices.SingleOrDefault(candidate =>
            candidate.Certificate.DeviceId.Span.SequenceEqual(
                dca.PublisherDeviceId.Span)) ?? throw ApplicationCoreFormat.Error(
                    ApplicationCoreValidationStage.CryptographicVerification,
                    ApplicationCoreRejection.VerificationFailed,
                    "DCB1 V2 publisher is not an active device.");
        if (!PublicKeyAuth.VerifyDetached(bundle.FieldSpan(19).ToArray(),
                bundle.SignatureInput.ToArray(),
                device.Certificate.DeviceEd25519PublicKey.ToArray()))
            Reject("DCB1 V2 issuer signature is invalid.");
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static ParsedDcb1V2 AuthorForValidation(
        IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        if (fields.Count != 24)
            throw new ArgumentException("DCB1 V2 requires 24 exact fields.", nameof(fields));
        var total = 12 + fields.Sum(field => 8 + field.Length);
        if (total is < MinimumLength or > MaximumLength)
            throw new ArgumentException("DCB1 V2 total size is invalid.", nameof(fields));
        var bytes = new byte[total];
        var writer = new ApplicationRecordWriter(bytes,
            ProtocolMagicBytes.DCB1, 24, 2, DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= 24; tag++)
            writer.Write(tag, fields[tag - 1].Span);
        writer.Complete();
        return Decode(bytes);
    }
#endif

    private static ReadOnlySpan<byte> Get(ReadOnlySpan<byte> canonical,
        ReadOnlySpan<ApplicationFieldSlice> slices, int tag) =>
        ApplicationCoreFormat.Field(canonical, slices, tag);

    private static ulong U64(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt64BigEndian(value);

    private static byte[] U64Bytes(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] ReferenceBytes(ReadOnlySpan<byte> magic,
        ushort version, ReadOnlySpan<byte> hash)
    {
        var value = new byte[38];
        magic.CopyTo(value);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), version);
        hash.CopyTo(value.AsSpan(6));
        return value;
    }

    private static void Invalid(ApplicationCoreRejection rejection,
        string message) => throw ApplicationCoreFormat.Error(
            ApplicationCoreValidationStage.SemanticFields, rejection, message);

    private static void Reject(string message) => throw ApplicationCoreFormat.Error(
        ApplicationCoreValidationStage.CryptographicVerification,
        ApplicationCoreRejection.VerificationFailed, message);
}
