using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Parsed XIR1 V2 bytes are not a publication or route capability. The
/// DCB1/DCR1, XRA1/PMT2 and directory closures remain separate release gates.
/// </summary>
public sealed class ParsedXir1V2
{
    private readonly byte[] canonical;
    private readonly byte[][] fields;
    private readonly byte[] unsigned;

    internal ParsedXir1V2(byte[] canonical, byte[][] fields, byte[] unsigned)
    {
        this.canonical = canonical;
        this.fields = fields;
        this.unsigned = unsigned;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> ObjectHash => SHA256.HashData(canonical);
    public ReadOnlyMemory<byte> SignatureInput => ApplicationCoreFormat.SignatureInput(
        "Deep/ContactResolver/V2/XIR1", unsigned, DeepIdV2Codec.Suite);
    public ReadOnlyMemory<byte> Field(int tag) => fields[tag - 1].ToArray();
    internal ReadOnlySpan<byte> FieldSpan(int tag) => fields[tag - 1];
}

/// <summary>
/// Isolated DID2 XIR1 candidate. It deliberately cannot author or activate a
/// contact publication; the V1 ContactCodec is not a fallback reader.
/// </summary>
public static class DeepIdV2InviteRendezvousCodec
{
    public const int CanonicalLength = 611;
    public static bool RuntimeActivation => false;
    private static ReadOnlySpan<int> FieldLengths =>
        [16, 32, 8, 32, 38, 32, 32, 32, 1, 4, 2, 32, 8, 8, 38, 38, 64, 38];

    public static ParsedXir1V2 Decode(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> slices = stackalloc ApplicationFieldSlice[18];
        ApplicationCoreFormat.Preflight(canonical, ProtocolMagicBytes.XIR1, 18,
            CanonicalLength, CanonicalLength, slices, 2, DeepIdV2Codec.Suite);
        var lengths = FieldLengths;
        for (var tag = 1; tag <= lengths.Length; tag++)
            ApplicationCoreFormat.ExactLength(slices, tag, lengths[tag - 1]);

        foreach (var tag in new[] { 1, 2, 5, 6, 7, 8, 12, 17 })
            ApplicationCoreFormat.NonZero(Get(canonical, slices, tag),
                "XIR1 V2 required field");
        var generation = BinaryPrimitives.ReadUInt64BigEndian(Get(canonical, slices, 3));
        if (ApplicationCoreFormat.IsZero(Get(canonical, slices, 4)) != (generation == 0))
            Invalid(ApplicationCoreRejection.InvalidLineage,
                "XIR1 V2 predecessor must be zero exactly at genesis.");
        var policy = Get(canonical, slices, 9)[0];
        var redemptionLimit = BinaryPrimitives.ReadUInt32BigEndian(Get(canonical, slices, 10));
        var reservations = BinaryPrimitives.ReadUInt16BigEndian(Get(canonical, slices, 11));
        if (policy is < 1 or > 2 ||
            redemptionLimit != (policy == 1 ? 0u : 1u) ||
            reservations is < 1 or > 256)
            Invalid(ApplicationCoreRejection.InvalidEnum,
                "XIR1 V2 invite policy or reservation bound is invalid.");
        var issued = BinaryPrimitives.ReadUInt64BigEndian(Get(canonical, slices, 13));
        var expiry = BinaryPrimitives.ReadUInt64BigEndian(Get(canonical, slices, 14));
        if (issued >= expiry)
            Invalid(ApplicationCoreRejection.InvalidTimeRange,
                "XIR1 V2 expiry must follow issuance.");
        Reference(Get(canonical, slices, 5), ProtocolMagicBytes.PMT2, 1);
        Reference(Get(canonical, slices, 15), ProtocolMagicBytes.DPD1, 1);
        Reference(Get(canonical, slices, 16), ProtocolMagicBytes.DCA1, 2);
        Reference(Get(canonical, slices, 18), ProtocolMagicBytes.XRA1, 1);

        var owned = canonical.ToArray();
        var fields = new byte[18][];
        for (var tag = 1; tag <= 18; tag++)
            fields[tag - 1] = ApplicationCoreFormat.Field(owned, slices, tag).ToArray();
        var unsigned = new byte[539];
        var writer = new ApplicationRecordWriter(unsigned,
            ProtocolMagicBytes.XIR1, 17, 2, DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= 18; tag++)
            if (tag != 17) writer.Write(tag, fields[tag - 1]);
        writer.Complete();
        return new ParsedXir1V2(owned, fields, unsigned);
    }

    /// <summary>
    /// Checks the issuer and DCA1 V2 binding only. It never verifies XRA1,
    /// PMT2, DCB1/DCR1 or freshness and cannot mint publication authority.
    /// </summary>
    public static void VerifyIssuerAndDca1(ParsedXir1V2 invite,
        VerifiedDca1V2 authorization, ulong trustedUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(invite);
        ArgumentNullException.ThrowIfNull(authorization);
        var dca = authorization.Record;
        var identity = authorization.Binding.Identity;
        var device = identity.ActiveDevices.SingleOrDefault(candidate =>
            candidate.Certificate.DeviceId.Span.SequenceEqual(
                dca.PublisherDeviceId.Span)) ?? throw ApplicationCoreFormat.Error(
                    ApplicationCoreValidationStage.CryptographicVerification,
                    ApplicationCoreRejection.VerificationFailed,
                    "XIR1 V2 issuer is not an active DCA1 V2 publisher device.");
        if (!invite.FieldSpan(1).SequenceEqual(dca.NetworkId.Span) ||
            !invite.FieldSpan(15).SequenceEqual(ReferenceBytes(
                ProtocolMagicBytes.DPD1, 1,
                device.Certificate.CanonicalHash.Span)) ||
            !invite.FieldSpan(16).SequenceEqual(ReferenceBytes(
                ProtocolMagicBytes.DCA1, 2, dca.RecordHash.Span)))
            Reject("XIR1 V2 issuer or exact DCA1 V2 reference differs from verified custody.");
        var policyBit = invite.FieldSpan(9)[0] == 1 ? 1 : 2;
        var issued = BinaryPrimitives.ReadUInt64BigEndian(invite.FieldSpan(13));
        var expiry = BinaryPrimitives.ReadUInt64BigEndian(invite.FieldSpan(14));
        if ((dca.AllowedInviteKindMask & policyBit) == 0 ||
            issued < dca.NotBeforeUnixSeconds ||
            expiry > dca.ExpiresAtUnixSeconds ||
            trustedUnixSeconds < issued || trustedUnixSeconds >= expiry)
            Reject("XIR1 V2 policy or validity is outside DCA1 V2 authority.");
        if (!PublicKeyAuth.VerifyDetached(invite.FieldSpan(17).ToArray(),
                invite.SignatureInput.ToArray(),
                device.Certificate.DeviceEd25519PublicKey.ToArray()))
            Reject("XIR1 V2 issuer signature is invalid.");
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static ParsedXir1V2 AuthorForValidation(
        IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        if (fields.Count != 18 ||
            fields.Where((field, index) => field.Length != FieldLengths[index]).Any())
            throw new ArgumentException("XIR1 V2 validation fields are not exact.",
                nameof(fields));
        var bytes = new byte[CanonicalLength];
        var writer = new ApplicationRecordWriter(bytes, ProtocolMagicBytes.XIR1,
            18, 2, DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= 18; tag++)
            writer.Write(tag, fields[tag - 1].Span);
        writer.Complete();
        return Decode(bytes);
    }
#endif

    private static void Reference(ReadOnlySpan<byte> value,
        ReadOnlySpan<byte> magic, ushort version)
    {
        if (!value[..4].SequenceEqual(magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(value[4..6]) != version ||
            ApplicationCoreFormat.IsZero(value[6..]))
            Invalid(ApplicationCoreRejection.InvalidReference,
                "XIR1 V2 has an unknown or empty artifact reference.");
    }

    private static ReadOnlySpan<byte> Get(ReadOnlySpan<byte> canonical,
        ReadOnlySpan<ApplicationFieldSlice> slices, int tag) =>
        ApplicationCoreFormat.Field(canonical, slices, tag);

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
