using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.ContactV1;

/// <summary>
/// Frozen CONTACT-CODEC-01 byte codec.  This package deliberately exposes no
/// service/client activation API: decoding a record is not authority to emit it.
/// </summary>
public static class ContactCodec
{
    public static bool RuntimeActivation => false;
    private const ushort Version = 1;
    private const ushort Suite = 0x0201;
    private const int HeaderBytes = 12;
    private const int FieldHeaderBytes = 8;
    private const int MaximumBytes = 65_535;

    private static readonly IReadOnlyDictionary<string, Definition> Definitions =
        new Dictionary<string, Definition>(StringComparer.Ordinal)
        {
            [ProtocolMagic.DCB1] = new(ProtocolMagic.DCB1, [16, 32, 644, 38, -1, 473, 32, 8, 32, 32, 1, -1, 1, 651, -1, 4, 8, 8, 64, 228, 40, 32, 32, 394], 3_757, 10_275,
                "Deep/Application/V1/contact-bundle", null, [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,20,21,22,23,24]),
            [ProtocolMagic.DCR1] = new(ProtocolMagic.DCR1, [16, -1, 2, -1], 1, MaximumBytes, null, null, []),
            [ProtocolMagic.DIA1] = new(ProtocolMagic.DIA1, [16, 32, 1, 2, 16, 32, 32, 8, 2], 225, 225, null, null, []),
            [ProtocolMagic.XIR1] = new(ProtocolMagic.XIR1, [16, 32, 8, 32, 38, 32, 32, 32, 1, 4, 2, 32, 8, 8, 38, 38, 64, 38], 611, 611,
                "Deep/ContactResolver/V1/XIR1", null, [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,18]),
            [ProtocolMagic.XPI1] = new(ProtocolMagic.XPI1, [16, 32, 32, 38, 8, 38, 8, 32, 2, 32, 32, 32, 38, 8, 8, 64], 560, 560,
                "Deep/ContactResolver/V1/prekey-inventory", null, [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]),
            [ProtocolMagic.XUR1] = new(ProtocolMagic.XUR1, [16, 32, 32, 8, 32, 38, 32, 32, 32, 2, 8, 8, 32, 38, 64], 538, 538,
                "Deep/Application/V1/contact-update-rendezvous", null, [1,2,3,4,5,6,7,8,9,10,11,12,13,14]),
            [ProtocolMagic.XRA1] = new(ProtocolMagic.XRA1, [16, 32, 8, 32, 38, 32, 2, 4, 32, 32, 32, 8, 8, 32, 38, 64], 550, 550,
                "Deep/XPoint/V1/XRA1", "Deep/XPoint/V1/XRA1/core", [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]),
            [ProtocolMagic.PMT2] = new(ProtocolMagic.PMT2, [16, 8, 32, 38, 38, 8, 1, 2, -136, 8, 8, 8, 32, 38, 1, -96], 842, 11_066,
                "Deep/XPoint/V1/PMT2", "Deep/XPoint/V1/PMT2/core", [1,2,3,4,5,6,7,8,9,10,11,12,13,14]),
            [ProtocolMagic.PMS2] = new(ProtocolMagic.PMS2, [16, 38, 32, 8, 1, -32, 32, 8, 8, 1, -96], 500, 3_476,
                "Deep/XPoint/V1/PMS2", null, [1,2,3,4,5,6,7,8,9]),
            [ProtocolMagic.XRC1] = new(ProtocolMagic.XRC1, [16, 32, 8, 32, 38, 38, 32, 38, 38, 32, 32, 32, 8, 1, -64, 8, 8, 8, 38, 1, -96], 940, 4_012,
                "Deep/XPoint/V1/XRC1", "Deep/XPoint/V1/XRC1/core", [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19]),
            [ProtocolMagic.XSS1] = new(ProtocolMagic.XSS1, [16, 32, 8, 32, 38, 38, 38, 38, 32, 8, 8, 38, 1, -96], 643, 3_523,
                "Deep/XPoint/V1/XSS1", "Deep/XPoint/V1/XSS1/core", [1,2,3,4,5,6,7,8,9,10,11,12]),
            [ProtocolMagic.XRR1] = new(ProtocolMagic.XRR1, [16, 32, 8, 32, 38, 38, 38, 38, 32, 32, 32, 1, 4, 2, 8, 8, 8, 38, 64, 2], 643, 643,
                "Deep/XPoint/V1/XRR1", "Deep/XPoint/V1/XRR1/core", [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,20]),
        };

    public static ContactRecord Decode(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length is < HeaderBytes or > MaximumBytes)
            Reject(ContactValidationStage.Length, "RecordLengthOutOfRange");
        if (!IsAsciiMagic(canonical[..4])) Reject(ContactValidationStage.Header, "UnknownMagic");
        var magic = Encoding.ASCII.GetString(canonical[..4]);
        if (!Definitions.TryGetValue(magic, out var definition))
            throw new ContactFormatException(ContactValidationStage.Header, "UnsupportedRecord");
        if (canonical.Length < definition.MinimumBytes || canonical.Length > definition.MaximumBytes)
            Reject(ContactValidationStage.Length, "RecordLengthOutOfRange");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[4..6]) != Version) Reject(ContactValidationStage.Header, "UnsupportedVersion");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[6..8]) != Suite) Reject(ContactValidationStage.Header, "UnknownSuite");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[8..10]) != definition.Lengths.Length) Reject(ContactValidationStage.Header, "WrongFieldCount");
        if (BinaryPrimitives.ReadUInt16BigEndian(canonical[10..12]) != 0) Reject(ContactValidationStage.Header, "NonCanonicalReserved");

        var offsets = new int[definition.Lengths.Length];
        var lengths = new int[definition.Lengths.Length];
        var offset = HeaderBytes;
        for (var index = 0; index < definition.Lengths.Length; index++)
        {
            if (canonical.Length - offset < FieldHeaderBytes) Reject(ContactValidationStage.FieldScan, "TruncatedFieldHeader");
            if (BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(offset, 2)) != index + 1)
                Reject(ContactValidationStage.FieldScan, "NonCanonicalTag");
            if (BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(offset + 2, 2)) != 0)
                Reject(ContactValidationStage.FieldScan, "NonCanonicalReserved");
            var declared = BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(offset + 4, 4));
            offset += FieldHeaderBytes;
            if (declared > int.MaxValue || declared > canonical.Length - offset) Reject(ContactValidationStage.Bounds, "TruncatedField");
            offsets[index] = offset;
            lengths[index] = (int)declared;
            offset += (int)declared;
        }
        if (offset != canonical.Length) Reject(ContactValidationStage.Bounds, "TrailingBytes");

        ValidateShape(definition, canonical, offsets, lengths);
        var owned = canonical.ToArray();
        var fields = new byte[lengths.Length][];
        for (var index = 0; index < fields.Length; index++) fields[index] = owned.AsSpan(offsets[index], lengths[index]).ToArray();
        var record = new ContactRecord(definition.Magic, owned, fields, definition.SignatureDomain, definition.CoreDomain, definition.ProjectionTags);
        ValidateSemantics(record);
        return record;
    }

    public static ContactRecord Decode(string expectedMagic, ReadOnlySpan<byte> canonical)
    {
        var record = Decode(canonical);
        if (!StringComparer.Ordinal.Equals(expectedMagic, record.Magic)) Reject(ContactValidationStage.Header, "WrongRecordType");
        return record;
    }

    /// <summary>
    /// CONTACT-CODEC-01 is frozen but not activated. Production callers cannot
    /// author contact records while the activation gate is false.
    /// </summary>
    public static ContactRecord Author(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        if (!RuntimeActivation)
            throw new InvalidOperationException("CONTACT-CODEC-01 production authoring is disabled until runtime activation.");
        return AuthorCore(magic, fields);
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static ContactRecord AuthorForValidation(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
        => AuthorCore(magic, fields);
#endif

    internal static ContactRecord AuthorForOperationalAuthority(
        string magic,
        IReadOnlyList<ReadOnlyMemory<byte>> fields) => AuthorCore(magic, fields);

    private static ContactRecord AuthorCore(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        ArgumentNullException.ThrowIfNull(magic);
        ArgumentNullException.ThrowIfNull(fields);
        if (!Definitions.TryGetValue(magic, out var definition) || fields.Count != definition.Lengths.Length)
            throw new ArgumentException("The authoring shape is not a frozen CONTACT-CODEC record.", nameof(fields));
        var total = HeaderBytes;
        foreach (var field in fields) total = checked(total + FieldHeaderBytes + field.Length);
        var bytes = new byte[total];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), Version);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), Suite);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count));
        var offset = HeaderBytes;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += FieldHeaderBytes;
            fields[index].Span.CopyTo(bytes.AsSpan(offset));
            offset += fields[index].Length;
        }
        return Decode(bytes);
    }

    public static ContactArtifactReference ArtifactReference(string expectedMagic, ContactRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (!StringComparer.Ordinal.Equals(expectedMagic, record.Magic)) throw new ArgumentException("Wrong record type.", nameof(record));
        return new ContactArtifactReference(record.Magic, Version, record.ArtifactHash.Span);
    }

    public static ContactArtifactReference DecodeArtifactReference(ReadOnlySpan<byte> value, string expectedMagic)
    {
        if (value.Length != 38 || !value[..4].SequenceEqual(Encoding.ASCII.GetBytes(expectedMagic)) ||
            BinaryPrimitives.ReadUInt16BigEndian(value[4..6]) != Version || IsZero(value[6..]))
            Reject(ContactValidationStage.Reference, "ReferenceTypeMismatch");
        return new ContactArtifactReference(expectedMagic, Version, value[6..]);
    }

    /// <summary>Verifies the three device-signed CONTACT-CODEC records only.</summary>
    public static void VerifyDeviceSignature(ContactRecord record, ReadOnlySpan<byte> publicKey32)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (publicKey32.Length != 32 || IsZero(publicKey32)) Reject(ContactValidationStage.Signature, "InvalidPublicKey");
        var signatureTag = record.Magic switch { ProtocolMagic.DCB1 => 19, ProtocolMagic.XIR1 => 17, ProtocolMagic.XPI1 => 16, ProtocolMagic.XUR1 => 15, ProtocolMagic.XRA1 => 16, ProtocolMagic.XRR1 => 19, _ => 0 };
        if (signatureTag == 0) throw new InvalidOperationException("This record has no device signature field.");
        if (!VerifyEd25519(publicKey32, record.SignatureInput.Span, record.FieldSpan(signatureTag)))
            Reject(ContactValidationStage.Signature, "SignatureVerificationFailed");
    }

    /// <summary>
    /// Promotes a parsed DCR1 only from an authenticated, nonce-bound current
    /// account-directory proof and the exact DCA1 capability closed by its ADC1.
    /// Raw DPA1/DRS1/DPD1/ADC1 bytes never form this capability.
    /// </summary>
    public static VerifiedContactBundleClosure VerifyDcr1Closure(
        ContactRecord dcr1,
        CurrentlyAuthoritativeDca1 authorization,
        VerifiedAccountDirectoryFreshness freshness,
        ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(dcr1);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(freshness);
        RequireRecord(dcr1, ProtocolMagic.DCR1);

        if (freshness.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue)
            Reject(ContactValidationStage.Closure, "CurrentAccountDirectoryCheckpointRequired");
        var checkpoint = freshness.CurrentCheckpoint ??
            throw new ContactFormatException(
                ContactValidationStage.Closure, "CurrentAccountDirectoryCheckpointRequired");
        if (!freshness.IsCurrentAtMonotonic(currentBootId, currentMonotonicSample))
            Reject(ContactValidationStage.Closure, "DirectoryFreshnessExpired");

        var binding = checkpoint.Binding;
        var directory = checkpoint.Directory;
        var identity = directory.Identity;
        if (!ReferenceEquals(binding.Identity, identity) ||
            !ReferenceEquals(authorization.Verified.Binding, binding) ||
            !ReferenceEquals(authorization.Verified.Directory, directory))
            Reject(ContactValidationStage.Closure, "VerifiedIdentityClosureMismatch");
        if (checkpoint.IsDcaAuthorizationRevoked(authorization.Verified.Record.AuthorizationId.Span))
            Reject(ContactValidationStage.Closure, "DcaAuthorizationRevoked");

        var bundle = Decode(ProtocolMagic.DCB1, dcr1.FieldSpan(2));
        var account = identity.Account.Certificate;
        var revocations = identity.Revocations.Snapshot;
        if (!bundle.FieldSpan(1).SequenceEqual(account.NetworkId.Span) ||
            !bundle.FieldSpan(2).SequenceEqual(identity.Account.DeepAccountIdHash.Span) ||
            !bundle.FieldSpan(3).SequenceEqual(account.CanonicalBytes.Span) ||
            !ReferenceMatches(bundle.FieldSpan(4), revocations, ProtocolMagic.DRS1) ||
            !bundle.FieldSpan(5).SequenceEqual(directory.Record.CanonicalBytes.Span) ||
            !bundle.FieldSpan(6).SequenceEqual(authorization.Verified.Record.CanonicalBytes.Span) ||
            !bundle.FieldSpan(24).SequenceEqual(binding.Record.CanonicalBytes.Span) ||
            !dcr1.FieldSpan(1).SequenceEqual(account.NetworkId.Span))
            Reject(ContactValidationStage.Closure, "VerifiedBundleIdentityMismatch");

        AccountDirectoryAdl1 lookup;
        try { lookup = AccountDirectoryAdl1Codec.Decode(bundle.FieldSpan(20)); }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            Reject(ContactValidationStage.Closure, "DirectoryLookupRejected");
            throw new InvalidOperationException("Unreachable after Contact rejection.", exception);
        }
        var lookupLeaf = AccountDirectoryCrypto.Sha256Domain(
            AccountDirectoryAdc1Verifier.LeafDomain, lookup.DirectoryLookupKey.Span);
        var bundleFloorGeneration = U64(bundle.FieldSpan(21)[..8]);
        var bundleFloorHash = bundle.FieldSpan(21)[8..];
        var floorMismatch = lookup.MinimumAdhGeneration != bundleFloorGeneration ||
            !CryptographicOperations.FixedTimeEquals(lookup.MinimumAdhHash.Span, bundleFloorHash) ||
            freshness.AdhGeneration < bundleFloorGeneration ||
            (freshness.AdhGeneration == bundleFloorGeneration &&
             !CryptographicOperations.FixedTimeEquals(
                 bundleFloorHash, freshness.ExactAdh1CoreHash.Span));
        if (!freshness.NetworkId.Span.SequenceEqual(account.NetworkId.Span) ||
            !lookup.NetworkId.Span.SequenceEqual(freshness.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(lookupLeaf, freshness.DirectoryLeafKey.Span) ||
            floorMismatch ||
            !bundle.FieldSpan(22).SequenceEqual(binding.DeepId.RecordHash.Span) ||
            !bundle.FieldSpan(23).SequenceEqual(binding.DeepId.AddressPublicKey.Span))
            Reject(ContactValidationStage.Closure, "DirectoryFreshnessIdentityMismatch");

        var dca = authorization.Verified.Record;
        var xir = Decode(ProtocolMagic.XIR1, bundle.FieldSpan(14).Slice(40, 611));
        var trustedLower = freshness.TrustedLowerUnixSeconds;
        var trustedUpper = freshness.TrustedUpperUnixSeconds;
        if (authorization.TrustedUnixSeconds < trustedLower || authorization.TrustedUnixSeconds > trustedUpper ||
            dca.NotBeforeUnixSeconds > trustedLower || dca.ExpiresAtUnixSeconds <= trustedUpper ||
            U64(bundle.FieldSpan(17)) > trustedLower || U64(bundle.FieldSpan(18)) <= trustedUpper ||
            U64(xir.FieldSpan(13)) > trustedLower || U64(xir.FieldSpan(14)) <= trustedUpper)
            Reject(ContactValidationStage.Closure, "ContactValidityDoesNotCoverAuthenticatedTime");

        var kindBit = xir.FieldSpan(9)[0] switch { 1 => (byte)0x01, 2 => (byte)0x02, _ => (byte)0 };
        var publisher = FindVerifiedDevice(identity, bundle.FieldSpan(10));
        if (kindBit == 0 || (dca.AllowedInviteKindMask & kindBit) == 0 ||
            U64(bundle.FieldSpan(8)) > dca.MaximumBundleGeneration ||
            (U32(bundle.FieldSpan(16)) & kindBit) == 0 ||
            !xir.FieldSpan(15).SequenceEqual(ArtifactReferenceFor(ProtocolMagic.DPD1, publisher.Certificate.CanonicalHash.Span)) ||
            !xir.FieldSpan(16).SequenceEqual(ArtifactReferenceFor(ProtocolMagic.DCA1, dca.RecordHash.Span)))
            Reject(ContactValidationStage.Closure, "ContactPublicationPolicyMismatch");

        VerifyDeviceSignature(bundle, publisher.Certificate.DeviceEd25519PublicKey.Span);
        VerifyDeviceSignature(xir, publisher.Certificate.DeviceEd25519PublicKey.Span);
        VerifyDcrSupportObjects(dcr1, directory, identity);
        VerifyBundleXpsSignatures(bundle, identity, trustedLower, trustedUpper);
        return new VerifiedContactBundleClosure(dcr1, bundle, binding, directory, authorization, freshness);
    }

    /// <summary>
    /// Resolves only contact-owned records by their exact artifact reference.
    /// Network/identity evidence stays behind its owning verifier.
    /// </summary>
    public static void VerifyContactOwnedClosure(ContactRecord record, IContactRecordResolver resolver)
    {
        ArgumentNullException.ThrowIfNull(record); ArgumentNullException.ThrowIfNull(resolver);
        switch (record.Magic)
        {
            case ProtocolMagic.XIR1: RequireResolved(record, 5, ProtocolMagic.PMT2, resolver); RequireResolved(record, 18, ProtocolMagic.XRA1, resolver); break;
            case ProtocolMagic.XUR1: RequireResolved(record, 6, ProtocolMagic.PMT2, resolver); break;
            case ProtocolMagic.XRA1: RequireResolved(record, 5, ProtocolMagic.PMT2, resolver); break;
            case ProtocolMagic.PMS2:
                ValidatePmsSelection(record, RequireResolved(record, 2, ProtocolMagic.PMT2, resolver));
                break;
            case ProtocolMagic.XRC1: RequireResolved(record, 5, ProtocolMagic.XRA1, resolver); RequireResolved(record, 6, ProtocolMagic.PMT2, resolver); break;
            case ProtocolMagic.XSS1: RequireResolved(record, 5, ProtocolMagic.XRC1, resolver); RequireResolved(record, 6, ProtocolMagic.XRC1, resolver); RequireResolved(record, 7, ProtocolMagic.PMT2, resolver); break;
            case ProtocolMagic.XRR1: RequireResolved(record, 5, ProtocolMagic.XRA1, resolver); RequireResolved(record, 6, ProtocolMagic.XRC1, resolver); RequireResolved(record, 7, ProtocolMagic.XSS1, resolver); RequireResolved(record, 8, ProtocolMagic.PMT2, resolver); break;
        }
    }

    /// <summary>
    /// Validates the complete in-band DMC2/14 route closure. This is a pure
    /// validation API; it does not grant authority to emit or activate routes.
    /// </summary>
    internal static void ValidateRouteUpdateGraph(
        ContactRecord xrr1, ContactRecord xra1, ContactRecord xrc1,
        ContactRecord xss1, ContactRecord pmt2, ContactRecord pms2)
    {
        ArgumentNullException.ThrowIfNull(xrr1); ArgumentNullException.ThrowIfNull(xra1);
        RequireRecord(xrr1, ProtocolMagic.XRR1);
        ValidateThresholdRouteGraph(xra1, xrc1, xss1, pmt2, pms2);
        if (!xrr1.FieldSpan(1).SequenceEqual(xra1.FieldSpan(1)))
            Reject(ContactValidationStage.Closure, "ClosureNetworkMismatch");
        RequireReference(xrr1, 5, xra1); RequireReference(xrr1, 6, xrc1);
        RequireReference(xrr1, 7, xss1); RequireReference(xrr1, 8, pmt2);
        RequireHash(xrr1, 9, pms2);

        if (!xrr1.FieldSpan(18).SequenceEqual(xra1.FieldSpan(15)) ||
            U64(xrr1.FieldSpan(16)) < U64(xrc1.FieldSpan(17)) ||
            U64(xrr1.FieldSpan(17)) > U64(xrc1.FieldSpan(18)))
            Reject(ContactValidationStage.Closure, "RouteValidityIntersectionMismatch");
    }

    internal static void ValidateThresholdRouteGraph(
        ContactRecord xra1, ContactRecord xrc1,
        ContactRecord xss1, ContactRecord pmt2, ContactRecord pms2)
    {
        ArgumentNullException.ThrowIfNull(xra1); ArgumentNullException.ThrowIfNull(xrc1);
        ArgumentNullException.ThrowIfNull(xss1); ArgumentNullException.ThrowIfNull(pmt2);
        ArgumentNullException.ThrowIfNull(pms2);
        RequireRecord(xra1, ProtocolMagic.XRA1); RequireRecord(xrc1, ProtocolMagic.XRC1);
        RequireRecord(xss1, ProtocolMagic.XSS1); RequireRecord(pmt2, ProtocolMagic.PMT2);
        RequireRecord(pms2, ProtocolMagic.PMS2);

        var network = xra1.FieldSpan(1);
        foreach (var record in new[] { xrc1, xss1, pmt2, pms2 })
            if (!record.FieldSpan(1).SequenceEqual(network))
                Reject(ContactValidationStage.Closure, "ClosureNetworkMismatch");

        RequireReference(xra1, 5, pmt2);

        ValidatePmsSelection(pms2, pmt2);
        if (!pms2.FieldSpan(3).SequenceEqual(xra1.FieldSpan(6)) ||
            U64(pms2.FieldSpan(4)) != U64(pmt2.FieldSpan(6)))
            Reject(ContactValidationStage.Closure, "Pms2PlacementBindingMismatch");

        RequireReference(xrc1, 5, xra1); RequireReference(xrc1, 6, pmt2);
        RequireHash(xrc1, 7, pms2);
        if (!xrc1.FieldSpan(8).SequenceEqual(pmt2.FieldSpan(5)) ||
            !xrc1.FieldSpan(11).SequenceEqual(xra1.FieldSpan(10)) ||
            !xrc1.FieldSpan(12).SequenceEqual(xra1.FieldSpan(11)))
            Reject(ContactValidationStage.Closure, "Xrc1AuthorityBindingMismatch");
        RequireReplicaSet(xrc1, pms2);

        RequireReference(xss1, 5, xrc1); RequireReference(xss1, 6, xrc1);
        RequireReference(xss1, 7, pmt2); RequireHash(xss1, 9, pms2);
        var xrcGeneration = U64(xrc1.FieldSpan(3));
        if (xrcGeneration == ulong.MaxValue || !xss1.FieldSpan(2).SequenceEqual(xrc1.FieldSpan(2)) ||
            U64(xss1.FieldSpan(3)) != xrcGeneration + 1 ||
            !xss1.FieldSpan(4).SequenceEqual(xrc1.CoreHash.Span) ||
            !xss1.FieldSpan(8).SequenceEqual(xrc1.FieldSpan(8)))
            Reject(ContactValidationStage.Closure, "Xss1PredecessorCurrentMismatch");

        if (U64(xrc1.FieldSpan(17)) < U64(xra1.FieldSpan(12)) ||
            U64(xrc1.FieldSpan(18)) > U64(xra1.FieldSpan(13)) ||
            U64(xrc1.FieldSpan(17)) < U64(pmt2.FieldSpan(11)) ||
            U64(xrc1.FieldSpan(18)) > U64(pmt2.FieldSpan(12)))
            Reject(ContactValidationStage.Closure, "RouteValidityIntersectionMismatch");
    }

    /// <summary>
    /// Promotes a route only from a production-owned network/directory authority
    /// capability. Raw records, caller-selected keys and structural validity are
    /// insufficient to create this result.
    /// </summary>
    public static VerifiedContactRouteClosure VerifyRouteUpdateClosure(
        ContactRecord xir1, ContactRecord xrr1, ContactRecord xra1, ContactRecord xrc1,
        ContactRecord xss1, ContactRecord pmt2, ContactRecord pms2,
        VerifiedContactNetworkAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(xir1); ArgumentNullException.ThrowIfNull(authority);
        RequireRecord(xir1, ProtocolMagic.XIR1);
        ValidateRouteUpdateGraph(xrr1, xra1, xrc1, xss1, pmt2, pms2);

        var trusted = authority.TrustedUnixSeconds;
        var network = authority.NetworkId.Span;
        foreach (var record in new[] { xir1, xrr1, xra1, xrc1, xss1, pmt2, pms2 })
            if (!record.FieldSpan(1).SequenceEqual(network))
                Reject(ContactValidationStage.Closure, "AuthorityNetworkMismatch");

        RequireReference(xir1, 5, pmt2); RequireReference(xir1, 18, xra1);
        if (!xir1.FieldSpan(6).SequenceEqual(xra1.FieldSpan(6)) ||
            !xir1.FieldSpan(7).SequenceEqual(xra1.FieldSpan(10)) ||
            !xir1.FieldSpan(8).SequenceEqual(xra1.FieldSpan(11)) ||
            !xir1.FieldSpan(12).SequenceEqual(xra1.FieldSpan(9)) ||
            !xir1.FieldSpan(13).SequenceEqual(xra1.FieldSpan(12)) ||
            !xir1.FieldSpan(14).SequenceEqual(xra1.FieldSpan(13)) ||
            !xir1.FieldSpan(15).SequenceEqual(xra1.FieldSpan(15)) ||
            !xrr1.FieldSpan(11).SequenceEqual(xra1.FieldSpan(9)) ||
            !xra1.FieldSpan(14).SequenceEqual(authority.RecipientDeviceId.Span) ||
            !xra1.FieldSpan(15).SequenceEqual(authority.RecipientDpd1Reference.Span) ||
            !xrr1.FieldSpan(18).SequenceEqual(authority.RecipientDpd1Reference.Span) ||
            !xir1.FieldSpan(16).SequenceEqual(authority.Dca1Reference.Span))
            Reject(ContactValidationStage.Closure, "InviteRouteAuthorityMismatch");

        // PMT2 tag 14 is an issuance-time audit anchor; XRC1/XSS1 carry the
        // exact current directory authority for this route closure.
        if (!pmt2.FieldSpan(5).SequenceEqual(authority.Xnv1CoreReference.Span) ||
            !ContactCodec.ArtifactReference(ProtocolMagic.PMT2, pmt2).CanonicalBytes.Span.SequenceEqual(authority.Pmt2ArtifactReference.Span) ||
            !pms2.ArtifactHash.Span.SequenceEqual(authority.Pms2ArtifactHash.Span) ||
            !xrc1.FieldSpan(8).SequenceEqual(authority.Xnv1CoreReference.Span) ||
            !xrc1.FieldSpan(9).SequenceEqual(authority.Xnh1CoreReference.Span) ||
            !xrc1.FieldSpan(19).SequenceEqual(authority.Adh1CoreReference.Span) ||
            !xss1.FieldSpan(8).SequenceEqual(authority.Xnv1CoreReference.Span) ||
            !xss1.FieldSpan(12).SequenceEqual(authority.Adh1CoreReference.Span))
            Reject(ContactValidationStage.Closure, "NetworkDirectoryAuthorityMismatch");

        if (!authority.IsCurrentAt(trusted) ||
            !CurrentAt(xir1, 13, 14, trusted) || !CurrentAt(xra1, 12, 13, trusted) ||
            !CurrentAt(pmt2, 11, 12, trusted) || !CurrentAt(pms2, 8, 9, trusted) ||
            !CurrentAt(xrc1, 17, 18, trusted) || !CurrentAt(xss1, 10, 11, trusted) ||
            !CurrentAt(xrr1, 16, 17, trusted))
            Reject(ContactValidationStage.Closure, "RouteNotCurrentAtTrustedTime");

        VerifyDeviceSignature(xir1, authority.RecipientDevicePublicKey.Span);
        VerifyDeviceSignature(xra1, authority.RecipientDevicePublicKey.Span);
        VerifyDeviceSignature(xrr1, authority.RecipientDevicePublicKey.Span);
        VerifyWitnessThreshold(pmt2, 16, authority);
        VerifyWitnessThreshold(pms2, 11, authority);
        VerifyWitnessThreshold(xrc1, 21, authority);
        VerifyWitnessThreshold(xss1, 14, authority);
        return new VerifiedContactRouteClosure(xir1, xrr1, xra1, xrc1, xss1, pmt2, pms2, authority);
    }

    internal static byte[] Project(ContactRecord record, IReadOnlyList<int> tags)
    {
        var total = HeaderBytes + tags.Sum(tag => FieldHeaderBytes + record.FieldSpan(tag).Length);
        var output = new byte[total];
        Encoding.ASCII.GetBytes(record.Magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), Version);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), Suite);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)tags.Count));
        var offset = HeaderBytes;
        foreach (var tag in tags)
        {
            var field = record.FieldSpan(tag);
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)tag));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)field.Length));
            offset += FieldHeaderBytes;
            field.CopyTo(output.AsSpan(offset));
            offset += field.Length;
        }
        return output;
    }

    internal static byte[] Sha256Domain(string domain, ReadOnlySpan<byte> bytes)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var preimage = new byte[checked(label.Length + 5 + bytes.Length)];
        label.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(preimage.AsSpan(label.Length + 1), checked((uint)bytes.Length));
        bytes.CopyTo(preimage.AsSpan(label.Length + 5));
        return SHA256.HashData(preimage);
    }

    internal static byte[] SignatureInput(string domain, ReadOnlySpan<byte> projection)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var output = new byte[checked(label.Length + 7 + projection.Length)];
        label.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(label.Length + 1), Suite);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(label.Length + 3), checked((uint)projection.Length));
        projection.CopyTo(output.AsSpan(label.Length + 7));
        return output;
    }

    private static void ValidateShape(Definition d, ReadOnlySpan<byte> bytes, int[] offsets, int[] lengths)
    {
        for (var index = 0; index < d.Lengths.Length; index++)
        {
            var required = d.Lengths[index];
            if (required > 0 && lengths[index] != required) Reject(ContactValidationStage.Bounds, "FieldLengthOutOfRange");
        }
        switch (d.Magic)
        {
            case ProtocolMagic.DCB1:
                RequireCount(bytes, offsets, lengths, 11, 1, 16);
                if (lengths[11] != checked(1 + (int)Scalar(bytes, offsets, lengths, 11) * 356))
                    Reject(ContactValidationStage.Bounds, "CountLengthMismatch");
                if (lengths[4] is < 426 or > 1_476 || lengths[14] > 128) Reject(ContactValidationStage.Bounds, "FieldLengthOutOfRange");
                break;
            case ProtocolMagic.DCR1:
                if (lengths[1] is < 1 or > 57_344 || lengths[3] is < 1 or > 16_384 || canonicalLength(62, lengths[1], lengths[3]) != bytes.Length)
                    Reject(ContactValidationStage.Bounds, "InvalidResolverClosureLength");
                break;
            case ProtocolMagic.PMT2:
                RequireCount(bytes, offsets, lengths, 7, 2, 5); RequireCount(bytes, offsets, lengths, 8, 2, 56);
                RequireList(lengths[8], Scalar(bytes, offsets, lengths, 8), 136); RequireCount(bytes, offsets, lengths, 15, 2, 32);
                RequireList(lengths[15], Scalar(bytes, offsets, lengths, 15), 96); break;
            case ProtocolMagic.PMS2:
                RequireCount(bytes, offsets, lengths, 5, 2, 5); RequireList(lengths[5], Scalar(bytes, offsets, lengths, 5), 32);
                RequireCount(bytes, offsets, lengths, 10, 2, 32); RequireList(lengths[10], Scalar(bytes, offsets, lengths, 10), 96); break;
            case ProtocolMagic.XRC1:
                RequireCount(bytes, offsets, lengths, 14, 2, 5); RequireList(lengths[14], Scalar(bytes, offsets, lengths, 14), 64);
                RequireCount(bytes, offsets, lengths, 20, 2, 32); RequireList(lengths[20], Scalar(bytes, offsets, lengths, 20), 96); break;
            case ProtocolMagic.XSS1:
                RequireCount(bytes, offsets, lengths, 13, 2, 32); RequireList(lengths[13], Scalar(bytes, offsets, lengths, 13), 96); break;
        }
    }

    private static ContactRecord RequireResolved(ContactRecord record, int tag, string magic, IContactRecordResolver resolver)
    {
        var reference = DecodeArtifactReference(record.FieldSpan(tag), magic);
        var resolved = resolver.Resolve(reference) ?? throw new ContactFormatException(ContactValidationStage.Closure, "MissingClosureRecord");
        if (!StringComparer.Ordinal.Equals(resolved.Magic, magic) || !resolved.ArtifactHash.Span.SequenceEqual(reference.Hash.Span))
            Reject(ContactValidationStage.Closure, "ClosureReferenceMismatch");
        return resolved;
    }

    private static void ValidateSemantics(ContactRecord r)
    {
        var f = r.FieldSpan;
        NonZero(f(1));
        switch (r.Magic)
        {
            case ProtocolMagic.DCB1: ValidateDcb1(r); break;
            case ProtocolMagic.DCR1: ValidateDcr1(r); break;
            case ProtocolMagic.DIA1:
                NonZero(f(2)); if (f(3)[0] != 2 || BinaryPrimitives.ReadUInt16BigEndian(f(4)) != 1 || IsZero(f(5)) || IsZero(f(6)) || IsZero(f(7)) || U64(f(8)) == 0 || BinaryPrimitives.ReadUInt16BigEndian(f(9)) != 1) Reject(ContactValidationStage.Scalar, "InvalidInvitationScalar"); break;
            case ProtocolMagic.XIR1:
                NonZero(f(2)); GenPredecessor(f(3), f(4)); Reference(f(5), ProtocolMagic.PMT2); NonZero(f(6)); NonZero(f(7)); NonZero(f(8));
                if (f(9)[0] is < 1 or > 2 || (f(9)[0] == 1 && U32(f(10)) != 0) || (f(9)[0] == 2 && U32(f(10)) != 1) || U16(f(11)) is < 1 or > 256 || U64(f(13)) >= U64(f(14))) Reject(ContactValidationStage.Scalar, "InvalidInviteScalar");
                NonZero(f(12)); Reference(f(15), ProtocolMagic.DPD1); Reference(f(16), ProtocolMagic.DCA1); NonZero(f(17)); Reference(f(18), ProtocolMagic.XRA1); break;
            case ProtocolMagic.XPI1:
                NonZero(f(2)); NonZero(f(3)); Reference(f(4), ProtocolMagic.DPD1);
                if (U64(f(5)) == 0) Reject(ContactValidationStage.Scalar, "InvalidPreKeyInventoryServiceGeneration");
                Reference(f(6), ProtocolMagic.XPS1);
                var inventoryEpoch = U64(f(7));
                if (inventoryEpoch is < 1 or > 14 || IsZero(f(8)) != (inventoryEpoch == 1))
                    Reject(ContactValidationStage.Scalar, "InvalidPreKeyInventoryLineage");
                if (U16(f(9)) is < 32 or > 4096 || IsZero(f(10)) || IsZero(f(11)) || IsZero(f(12)))
                    Reject(ContactValidationStage.Scalar, "InvalidPreKeyInventoryCommitment");
                Reference(f(13), ProtocolMagic.DRS1);
                if (U64(f(14)) >= U64(f(15)) || IsZero(f(16)))
                    Reject(ContactValidationStage.Scalar, "InvalidPreKeyInventoryValidity");
                break;
            case ProtocolMagic.XUR1:
                NonZero(f(2)); NonZero(f(3)); GenPredecessor(f(4), f(5)); Reference(f(6), ProtocolMagic.PMT2); NonZero(f(7)); NonZero(f(8)); NonZero(f(9));
                if (U16(f(10)) is < 1 or > 7 || !ValidWindow(U64(f(11)), U64(f(12)), 2_592_000)) Reject(ContactValidationStage.Scalar, "InvalidUpdateWindow");
                NonZero(f(13)); Reference(f(14), ProtocolMagic.DPD1); NonZero(f(15)); break;
            case ProtocolMagic.XRA1:
                NonZero(f(2)); GenPredecessor(f(3), f(4)); Reference(f(5), ProtocolMagic.PMT2); NonZero(f(6));
                if (U16(f(7)) != 1 || U32(f(8)) is < 1 or > 65_535 || !ValidWindow(U64(f(12)), U64(f(13)), 2_592_000)) Reject(ContactValidationStage.Scalar, "InvalidReachabilityAuthorization");
                NonZero(f(9)); NonZero(f(10)); NonZero(f(11)); NonZero(f(14)); Reference(f(15), ProtocolMagic.DPD1); NonZero(f(16)); break;
            case ProtocolMagic.PMT2:
                GenPredecessor(f(2), f(3)); Reference(f(4), ProtocolMagic.PMA2); Reference(f(5), ProtocolMagic.XNV1);
                if (!ValidWindowWithNotBefore(U64(f(10)), U64(f(11)), U64(f(12)), 1_209_600)) Reject(ContactValidationStage.Scalar, "InvalidProjectionWindow");
                Reference(f(14), ProtocolMagic.ADH1); SortedRows(f(9), 136); SortedRows(f(16), 96); break;
            case ProtocolMagic.PMS2:
                Reference(f(2), ProtocolMagic.PMT2); NonZero(f(3)); UniqueRows(f(6), 32); SortedRows(f(11), 96);
                if (!f(7).SequenceEqual(Sha256Domain("Deep/XPoint/V1/PMS2/selection", Project(r, [1,2,3,4,5,6]))) || U64(f(8)) >= U64(f(9))) Reject(ContactValidationStage.Derived, "InvalidSelectionHash"); break;
            case ProtocolMagic.XRC1:
                NonZero(f(2)); GenPredecessor(f(3), f(4)); Reference(f(5), ProtocolMagic.XRA1); Reference(f(6), ProtocolMagic.PMT2); NonZero(f(7)); Reference(f(8), ProtocolMagic.XNV1); Reference(f(9), ProtocolMagic.XNH1); NonZero(f(10)); NonZero(f(11)); NonZero(f(12));
                if (!ValidWindowWithNotBefore(U64(f(16)), U64(f(17)), U64(f(18)), 86_400)) Reject(ContactValidationStage.Scalar, "InvalidRouteWindow"); Reference(f(19), ProtocolMagic.ADH1); UniqueRows(f(15), 64); SortedRows(f(21), 96); break;
            case ProtocolMagic.XSS1:
                NonZero(f(2)); NonZero(f(4)); Reference(f(5), ProtocolMagic.XRC1); Reference(f(6), ProtocolMagic.XRC1); Reference(f(7), ProtocolMagic.PMT2); Reference(f(8), ProtocolMagic.XNV1); NonZero(f(9));
                if (U64(f(10)) >= U64(f(11))) Reject(ContactValidationStage.Scalar, "InvalidSuccessorWindow"); Reference(f(12), ProtocolMagic.ADH1); SortedRows(f(14), 96); break;
            case ProtocolMagic.XRR1:
                NonZero(f(2)); GenPredecessor(f(3), f(4)); Reference(f(5), ProtocolMagic.XRA1); Reference(f(6), ProtocolMagic.XRC1); Reference(f(7), ProtocolMagic.XSS1); Reference(f(8), ProtocolMagic.PMT2); NonZero(f(9)); NonZero(f(10)); NonZero(f(11));
                var policy = f(12)[0]; var maximum = U32(f(13)); if (policy is < 1 or > 3 || U16(f(14)) == 0 || (policy == 1 && maximum != 1) || (policy == 2 && (maximum < 2 || maximum > 65_535)) || (policy == 3 && (maximum < 1 || maximum > 65_535)) || !ValidWindowWithNotBefore(U64(f(15)), U64(f(16)), U64(f(17)), ulong.MaxValue)) Reject(ContactValidationStage.Scalar, "InvalidReachabilityPolicy");
                Reference(f(18), ProtocolMagic.DPD1); NonZero(f(19)); if (!IsZero(f(20))) Reject(ContactValidationStage.Scalar, "ReservedMustBeZero"); break;
        }
    }

    private static int canonicalLength(int baseBytes, int first, int second) => checked(baseBytes + first + second);

    private static void ValidateDcb1(ContactRecord r)
    {
        var f = r.FieldSpan;
        NonZero(f(2)); Reference(f(4), ProtocolMagic.DRS1);
        AccountCertificate accountCertificate;
        ParsedDmd1 directory;
        ParsedDca1 authorization;
        ParsedDab1 binding;
        AccountDirectoryAdl1 lookup;
        try
        {
            accountCertificate = IdentityCodec.DecodeAccountCertificate(f(3));
            directory = ApplicationCoreCodec.DecodeDmd1(f(5));
            authorization = ApplicationCoreCodec.DecodeDca1(f(6));
            binding = ApplicationCoreCodec.DecodeDab1(f(24));
            lookup = AccountDirectoryAdl1Codec.Decode(f(20));
        }
        catch (Exception exception) when (exception is FormatException or RecordException or ArgumentException) { throw new ContactFormatException(ContactValidationStage.Derived, "EmbeddedApplicationRecordRejected"); }
        if (!accountCertificate.NetworkId.Span.SequenceEqual(f(1)) || !directory.NetworkId.Span.SequenceEqual(f(1)) ||
            !directory.DeepAccountId.Span.SequenceEqual(f(2)) ||
            !ReferenceMatches(directory.Dpa1Reference, accountCertificate) ||
            !authorization.NetworkId.Span.SequenceEqual(f(1)) || !authorization.DeepAccountId.Span.SequenceEqual(f(2)) ||
            !ReferenceMatches(authorization.Dpa1Reference, accountCertificate) ||
            authorization.AuthorizedDmd1Generation != directory.DirectoryGeneration ||
            !authorization.AuthorizedDmd1Hash.Span.SequenceEqual(directory.RecordHash.Span) ||
            !authorization.PublisherDeviceId.Span.SequenceEqual(f(10)) ||
            !binding.DeepAccountId.Span.SequenceEqual(f(2)) ||
            !lookup.NetworkId.Span.SequenceEqual(f(1)) ||
            lookup.MinimumAdhGeneration != U64(f(21)[..8]) ||
            !CryptographicOperations.FixedTimeEquals(lookup.MinimumAdhHash.Span, f(21)[8..]) ||
            !ReferenceMatches(binding.Dpa1Reference, accountCertificate))
            Reject(ContactValidationStage.Derived, "ApplicationClosureMismatch");
        NonZero(f(7)); GenPredecessor(f(8), f(9)); NonZero(f(10));
        if (f(11)[0] != directory.ActiveDevices.Count || f(13)[0] != 1) Reject(ContactValidationStage.Derived, "DeviceCoverageMismatch");
        ValidateXpsList(f(12), directory, f(1)); ValidateDcbDescriptor(f(14));
        if ((BinaryPrimitives.ReadUInt32BigEndian(f(16)) & ~0x0000000fU) != 0 || !ValidWindow(U64(f(17)), U64(f(18)), ulong.MaxValue)) Reject(ContactValidationStage.Scalar, "InvalidBundleWindow");
        RequireCanonicalUtf8(f(15));
        NonZero(f(19)); if (IsZero(f(21)[8..])) Reject(ContactValidationStage.Scalar, "InvalidDirectoryMinimum"); NonZero(f(22)); NonZero(f(23));
    }

    private static void ValidateXpsList(ReadOnlySpan<byte> value, ParsedDmd1 directory, ReadOnlySpan<byte> network)
    {
        var count = directory.ActiveDevices.Count;
        if (value[0] != count) Reject(ContactValidationStage.Derived, "XpsCountMismatch");
        var offset = 1; ReadOnlySpan<byte> previous = default;
        for (var index = 0; index < count; index++)
        {
            var encodedLength = BinaryPrimitives.ReadUInt32BigEndian(value.Slice(offset, 4));
            if (encodedLength > int.MaxValue) Reject(ContactValidationStage.Bounds, "InvalidXpsEntry");
            var length = (int)encodedLength;
            if (length != 352 || offset + 4 + length > value.Length) Reject(ContactValidationStage.Bounds, "InvalidXpsEntry");
            var xps = DecodeXps1(value.Slice(offset + 4, length));
            var device = xps.DeviceId;
            if (!previous.IsEmpty && previous.SequenceCompareTo(device) >= 0) Reject(ContactValidationStage.Bounds, "XpsNotStrictlyOrdered");
            if (!device.SequenceEqual(directory.ActiveDevices[index].DeviceId.Span) ||
                !directory.ActiveDevices[index].Dpd1Reference.CanonicalBytes.Span[6..].SequenceEqual(xps.Dpd1Reference.AsSpan(6)))
                Reject(ContactValidationStage.Derived, "XpsDeviceCoverageMismatch");
            if (!xps.NetworkId.SequenceEqual(network)) Reject(ContactValidationStage.Derived, "XpsNetworkMismatch");
            previous = device; offset += 4 + length;
        }
        if (offset != value.Length) Reject(ContactValidationStage.Bounds, "InvalidXpsEntry");
    }

    private static void ValidateDcbDescriptor(ReadOnlySpan<byte> value)
    {
        if (BinaryPrimitives.ReadUInt16BigEndian(value) != 1 || BinaryPrimitives.ReadUInt16BigEndian(value[2..]) != 1 || BinaryPrimitives.ReadUInt32BigEndian(value.Slice(36, 4)) != 611)
            Reject(ContactValidationStage.Derived, "InvalidReachabilityDescriptor");
        var xir = Decode(ProtocolMagic.XIR1, value.Slice(40, 611));
        if (!SHA256.HashData(xir.CanonicalBytes.Span).AsSpan().SequenceEqual(value.Slice(4, 32))) Reject(ContactValidationStage.Derived, "DescriptorHashMismatch");
    }

    private static void ValidateDcr1(ContactRecord r)
    {
        var f = r.FieldSpan; var bundle = Decode(ProtocolMagic.DCB1, f(2));
        if (!f(1).SequenceEqual(bundle.FieldSpan(1))) Reject(ContactValidationStage.Derived, "BundleNetworkMismatch");
        ParsedDmd1 directory;
        try { directory = ApplicationCoreCodec.DecodeDmd1(bundle.FieldSpan(5)); }
        catch (Exception exception) when (exception is FormatException or RecordException) { Reject(ContactValidationStage.Derived, "EmbeddedDirectoryRejected"); return; }
        var count = BinaryPrimitives.ReadUInt16BigEndian(f(3));
        if (count != directory.ActiveDevices.Count + 1) Reject(ContactValidationStage.Derived, "SupportCountMismatch");
        var offset = 0; var drsFound = false; var dpds = new List<DeviceCertificate>(); ushort previousKind = 0; ReadOnlySpan<byte> previousHash = default;
        for (var index = 0; index < count; index++)
        {
            if (f(4).Length - offset < 6) Reject(ContactValidationStage.Bounds, "TruncatedSupportEntry");
            var kind = BinaryPrimitives.ReadUInt16BigEndian(f(4).Slice(offset, 2)); var encodedLength = BinaryPrimitives.ReadUInt32BigEndian(f(4).Slice(offset + 2, 4));
            if (encodedLength > int.MaxValue) Reject(ContactValidationStage.Bounds, "InvalidSupportEntry");
            var length = (int)encodedLength; offset += 6;
            if (length < 12 || length > f(4).Length - offset || kind is < 1 or > 2) Reject(ContactValidationStage.Bounds, "InvalidSupportEntry");
            var entry = f(4).Slice(offset, length); var hash = SHA256.HashData(entry);
            if (kind < previousKind || (kind == previousKind && !previousHash.IsEmpty && previousHash.SequenceCompareTo(hash) >= 0)) Reject(ContactValidationStage.Bounds, "SupportNotStrictlyOrdered");
            previousKind = kind; previousHash = hash; offset += length;
            if (kind == 1)
            {
                if (drsFound) Reject(ContactValidationStage.Derived, "DuplicateDrs1");
                RevocationSnapshot snapshot;
                try { snapshot = IdentityCodec.DecodeRevocationSnapshot(entry); }
                catch (Exception exception) when (exception is FormatException or RecordException)
                {
                    Reject(ContactValidationStage.Derived, "EmbeddedDrs1Rejected");
                    return;
                }
                if (!snapshot.CanonicalHash.Span.SequenceEqual(bundle.FieldSpan(4)[6..]))
                    Reject(ContactValidationStage.Derived, "DrsReferenceMismatch");
                drsFound = true;
            }
            else
            {
                if (length != 776) Reject(ContactValidationStage.Bounds, "InvalidDpd1Length");
                try { dpds.Add(IdentityCodec.DecodeDeviceCertificate(entry)); }
                catch (Exception exception) when (exception is FormatException or RecordException) { Reject(ContactValidationStage.Derived, "EmbeddedDpd1Rejected"); }
            }
        }
        if (offset != f(4).Length || !drsFound || dpds.Count != directory.ActiveDevices.Count) Reject(ContactValidationStage.Derived, "IncompleteResolverClosure");
        foreach (var device in directory.ActiveDevices)
        {
            var certificate = dpds.SingleOrDefault(candidate => candidate.CanonicalHash.Span.SequenceEqual(device.Dpd1Reference.CanonicalBytes.Span[6..]));
            if (certificate is null || !certificate.NetworkId.Span.SequenceEqual(directory.NetworkId.Span) ||
                !certificate.AccountHash.Span.SequenceEqual(directory.DeepAccountId.Span) ||
                certificate.AccountGeneration != directory.AccountGeneration ||
                !certificate.DeviceId.Span.SequenceEqual(device.DeviceId.Span))
                Reject(ContactValidationStage.Derived, "Dpd1DirectoryCorrespondenceMismatch");
        }
    }

    private static void VerifyDcrSupportObjects(
        ContactRecord dcr1,
        VerifiedDmd1 directory,
        VerifiedApplicationIdentityClosure identity)
    {
        var support = dcr1.FieldSpan(4);
        var expected = new Dictionary<string, VerifiedDevice>(StringComparer.Ordinal);
        foreach (var device in identity.ActiveDevices)
            expected.Add(Convert.ToHexString(device.Certificate.CanonicalHash.Span), device);

        var sawDrs = false;
        var offset = 0;
        while (offset < support.Length)
        {
            var kind = BinaryPrimitives.ReadUInt16BigEndian(support.Slice(offset, 2));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(support.Slice(offset + 2, 4)));
            offset = checked(offset + 6);
            var bytes = support.Slice(offset, length);
            offset = checked(offset + length);
            if (kind == 1)
            {
                if (sawDrs || !bytes.SequenceEqual(identity.Revocations.Snapshot.CanonicalBytes.Span))
                    Reject(ContactValidationStage.Closure, "VerifiedDrs1Mismatch");
                sawDrs = true;
                continue;
            }

            DeviceCertificate parsed;
            try { parsed = IdentityCodec.DecodeDeviceCertificate(bytes); }
            catch (Exception exception) when (exception is FormatException or RecordException)
            {
                Reject(ContactValidationStage.Closure, "VerifiedDpd1Rejected");
                return;
            }
            var hash = Convert.ToHexString(parsed.CanonicalHash.Span);
            if (!expected.Remove(hash, out var verified) ||
                !bytes.SequenceEqual(verified.Certificate.CanonicalBytes.Span) ||
                !directory.Record.ActiveDevices.Any(entry =>
                    entry.DeviceId.Span.SequenceEqual(verified.Certificate.DeviceId.Span) &&
                    entry.Dpd1Reference.CanonicalHash.Span.SequenceEqual(verified.Certificate.CanonicalHash.Span)))
                Reject(ContactValidationStage.Closure, "VerifiedDpd1Mismatch");
        }
        if (!sawDrs || expected.Count != 0)
            Reject(ContactValidationStage.Closure, "IncompleteVerifiedDcrClosure");
    }

    private static void VerifyBundleXpsSignatures(
        ContactRecord bundle,
        VerifiedApplicationIdentityClosure identity,
        ulong trustedLowerUnixSeconds,
        ulong trustedUpperUnixSeconds)
    {
        var list = bundle.FieldSpan(12);
        var count = list[0];
        var offset = 1;
        for (var index = 0; index < count; index++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(list.Slice(offset, 4)));
            var xps = list.Slice(offset + 4, length);
            offset = checked(offset + 4 + length);
            var device = FindVerifiedDevice(identity, ReadField(xps, 3, 12));
            var dpdReference = ReadField(xps, 4, 12);
            if (!ReferenceMatches(dpdReference, device.Certificate, ProtocolMagic.DPD1))
                Reject(ContactValidationStage.Closure, "Xps1VerifiedDeviceMismatch");
            var projection = ProjectRawRecord(xps, 11);
            var input = SignatureInput("Deep/ContactResolver/V1/prekey-service", projection);
            if (U64(ReadField(xps, 10, 12)) > trustedLowerUnixSeconds ||
                U64(ReadField(xps, 11, 12)) <= trustedUpperUnixSeconds)
                Reject(ContactValidationStage.Closure, "Xps1ValidityDoesNotCoverAuthenticatedTime");
            if (!VerifyEd25519(device.Certificate.DeviceEd25519PublicKey.Span, input, ReadField(xps, 12, 12)))
                Reject(ContactValidationStage.Signature, "Xps1SignatureVerificationFailed");
        }
        if (offset != list.Length) Reject(ContactValidationStage.Closure, "Xps1ListLengthMismatch");
    }

    private static VerifiedDevice FindVerifiedDevice(
        VerifiedApplicationIdentityClosure identity,
        ReadOnlySpan<byte> deviceId)
    {
        if (!identity.TryGetDevice(deviceId, out var device) || device is null)
            throw new ContactFormatException(ContactValidationStage.Closure, "VerifiedDeviceMissingOrRevoked");
        return device;
    }

    private static bool ReferenceMatches(ReadOnlySpan<byte> reference, CanonicalIdentityArtifact artifact, string magic)
    {
        if (reference.Length != 38 || !reference[..4].SequenceEqual(Encoding.ASCII.GetBytes(magic)) ||
            BinaryPrimitives.ReadUInt16BigEndian(reference[4..6]) != Version)
            return false;
        return reference[6..].SequenceEqual(artifact.CanonicalHash.Span);
    }

    private static byte[] ArtifactReferenceFor(string magic, ReadOnlySpan<byte> hash)
    {
        var output = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), Version);
        hash.CopyTo(output.AsSpan(6));
        return output;
    }

    private static bool VerifyEd25519(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature) =>
        publicKey.Length == 32 && signature.Length == 64 &&
        PublicKeyAuth.VerifyDetached(signature.ToArray(), message.ToArray(), publicKey.ToArray());

    private static bool CurrentAt(ContactRecord record, int fromTag, int untilTag, ulong trusted) =>
        trusted >= U64(record.FieldSpan(fromTag)) && trusted < U64(record.FieldSpan(untilTag));

    private static void VerifyWitnessThreshold(
        ContactRecord record, int receiptTag, VerifiedContactNetworkAuthority authority)
        => authority.VerifyWitnessThreshold(record, receiptTag);

    private static byte[] ProjectRawRecord(ReadOnlySpan<byte> canonical, int includedFieldCount)
    {
        var offset = HeaderBytes;
        var end = HeaderBytes;
        for (var tag = 1; tag <= includedFieldCount; tag++)
        {
            if (canonical.Length - end < FieldHeaderBytes) Reject(ContactValidationStage.Bounds, "EmbeddedFieldTruncated");
            var length = BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(end + 4, 4));
            if (length > int.MaxValue || length > canonical.Length - end - FieldHeaderBytes)
                Reject(ContactValidationStage.Bounds, "EmbeddedFieldTruncated");
            end = checked(end + FieldHeaderBytes + (int)length);
        }
        var projection = new byte[end];
        canonical[..4].CopyTo(projection);
        BinaryPrimitives.WriteUInt16BigEndian(projection.AsSpan(4), Version);
        BinaryPrimitives.WriteUInt16BigEndian(projection.AsSpan(6), Suite);
        BinaryPrimitives.WriteUInt16BigEndian(projection.AsSpan(8), checked((ushort)includedFieldCount));
        canonical.Slice(offset, end - offset).CopyTo(projection.AsSpan(offset));
        return projection;
    }

    internal static void ValidatePmsSelection(ContactRecord pms2, ContactRecord pmt2)
    {
        RequireRecord(pms2, ProtocolMagic.PMS2); RequireRecord(pmt2, ProtocolMagic.PMT2);
        RequireReference(pms2, 2, pmt2);
        if (!pms2.FieldSpan(1).SequenceEqual(pmt2.FieldSpan(1)) ||
            U64(pms2.FieldSpan(8)) < U64(pmt2.FieldSpan(10)) ||
            U64(pms2.FieldSpan(9)) > U64(pmt2.FieldSpan(12)))
            Reject(ContactValidationStage.Closure, "Pms2ProjectionWindowMismatch");

        var replicaCount = pms2.FieldSpan(5)[0];
        var candidates = pmt2.FieldSpan(9);
        var ranked = new List<(byte[] NodeId, byte[] Score)>();
        for (var offset = 0; offset < candidates.Length; offset += 136)
        {
            var node = candidates.Slice(offset, 32);
            ranked.Add((node.ToArray(), RendezvousScore(pms2.FieldSpan(1), pms2.FieldSpan(2),
                pms2.FieldSpan(4), pms2.FieldSpan(3), node)));
        }
        ranked.Sort(static (left, right) =>
        {
            var score = left.Score.AsSpan().SequenceCompareTo(right.Score);
            return score != 0 ? score : left.NodeId.AsSpan().SequenceCompareTo(right.NodeId);
        });
        var actual = pms2.FieldSpan(6);
        for (var index = 0; index < replicaCount; index++)
            if (!actual.Slice(index * 32, 32).SequenceEqual(ranked[index].NodeId))
                Reject(ContactValidationStage.Closure, "Pms2RendezvousRankMismatch");
    }

    // RFC 3629's shortest-form UTF-8 requirement is not implied by .NET's
    // default decoder.  Decode with replacement disabled and round-trip the
    // bytes so profile names have exactly one representation.
    private static void RequireCanonicalUtf8(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty) return;
        try
        {
            var strict = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
            var text = strict.GetString(value);
            if (!strict.GetBytes(text).AsSpan().SequenceEqual(value))
                Reject(ContactValidationStage.Derived, "NonCanonicalUtf8");
        }
        catch (DecoderFallbackException)
        {
            Reject(ContactValidationStage.Derived, "NonCanonicalUtf8");
        }
    }

    private static byte[] RendezvousScore(ReadOnlySpan<byte> network, ReadOnlySpan<byte> pmtReference,
        ReadOnlySpan<byte> selectionEpoch, ReadOnlySpan<byte> placementInput, ReadOnlySpan<byte> nodeId)
    {
        const string domain = "Deep/XPoint/V1/PMS2/rendezvous-sha256/v2";
        var label = Encoding.ASCII.GetBytes(domain);
        var input = new byte[label.Length + 1 + network.Length + pmtReference.Length + selectionEpoch.Length + placementInput.Length + nodeId.Length];
        var offset = 0;
        label.CopyTo(input, offset); offset += label.Length; input[offset++] = 0;
        network.CopyTo(input.AsSpan(offset)); offset += network.Length;
        pmtReference.CopyTo(input.AsSpan(offset)); offset += pmtReference.Length;
        selectionEpoch.CopyTo(input.AsSpan(offset)); offset += selectionEpoch.Length;
        placementInput.CopyTo(input.AsSpan(offset)); offset += placementInput.Length;
        nodeId.CopyTo(input.AsSpan(offset));
        return SHA256.HashData(input);
    }

    private static void RequireReplicaSet(ContactRecord xrc1, ContactRecord pms2)
    {
        if (xrc1.FieldSpan(14)[0] != pms2.FieldSpan(5)[0])
            Reject(ContactValidationStage.Closure, "Xrc1ReplicaCountMismatch");
        var replicas = xrc1.FieldSpan(15);
        var ranked = pms2.FieldSpan(6);
        for (var index = 0; index < ranked.Length / 32; index++)
            if (!replicas.Slice(index * 64, 32).SequenceEqual(ranked.Slice(index * 32, 32)))
                Reject(ContactValidationStage.Closure, "Xrc1ReplicaSetMismatch");
    }

    internal static Xps1Record DecodeXps1(ReadOnlySpan<byte> canonical)
    {
        const int fieldCount = 12;
        ReadOnlySpan<int> lengths = [16, 32, 32, 38, 8, 32, 2, 2, 2, 8, 8, 64];
        if (canonical.Length != 352 || !canonical[..4].SequenceEqual(ProtocolMagicBytes.XPS1) ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[4..6]) != Version ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[6..8]) != Suite ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[8..10]) != fieldCount ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[10..12]) != 0)
            Reject(ContactValidationStage.Derived, "InvalidXps1CanonicalRecord");

        var offsets = new int[fieldCount];
        var offset = HeaderBytes;
        for (var index = 0; index < fieldCount; index++)
        {
            if (canonical.Length - offset < FieldHeaderBytes ||
                BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(offset, 2)) != index + 1 ||
                BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(offset + 2, 2)) != 0)
                Reject(ContactValidationStage.Derived, "InvalidXps1CanonicalRecord");
            var declared = BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(offset + 4, 4));
            offset += FieldHeaderBytes;
            if (declared != lengths[index] || declared > canonical.Length - offset)
                Reject(ContactValidationStage.Derived, "InvalidXps1CanonicalRecord");
            offsets[index] = offset;
            offset += (int)declared;
        }
        if (offset != canonical.Length) Reject(ContactValidationStage.Derived, "InvalidXps1CanonicalRecord");
        var network = canonical.Slice(offsets[0], lengths[0]);
        var capability = canonical.Slice(offsets[1], lengths[1]);
        var device = canonical.Slice(offsets[2], lengths[2]);
        var dpdReference = canonical.Slice(offsets[3], lengths[3]);
        var generation = canonical.Slice(offsets[4], lengths[4]);
        var predecessor = canonical.Slice(offsets[5], lengths[5]);
        var suite = canonical.Slice(offsets[6], lengths[6]);
        var minimumInventory = canonical.Slice(offsets[7], lengths[7]);
        var reuseLimit = canonical.Slice(offsets[8], lengths[8]);
        var issuedAt = canonical.Slice(offsets[9], lengths[9]);
        var expiresAt = canonical.Slice(offsets[10], lengths[10]);
        var signature = canonical.Slice(offsets[11], lengths[11]);
        if (IsZero(network) || IsZero(capability) || IsZero(device) || IsZero(signature) ||
            BinaryPrimitives.ReadUInt16BigEndian(suite) != Suite ||
            BinaryPrimitives.ReadUInt16BigEndian(minimumInventory) == 0 ||
            BinaryPrimitives.ReadUInt16BigEndian(reuseLimit) == 0 ||
            !ValidWindow(U64(issuedAt), U64(expiresAt), ulong.MaxValue) ||
            (U64(generation) == 0) != IsZero(predecessor))
            Reject(ContactValidationStage.Derived, "InvalidXps1Scalar");
        Reference(dpdReference, ProtocolMagic.DPD1);
        return new Xps1Record(
            canonical.ToArray(), network.ToArray(), capability.ToArray(), device.ToArray(),
            dpdReference.ToArray(), U64(generation), U16(suite), U16(minimumInventory), U16(reuseLimit),
            U64(issuedAt), U64(expiresAt));
    }

    private static void RequireMagic(ReadOnlySpan<byte> record, string magic)
    {
        if (record.Length < 12 || !record[..4].SequenceEqual(Encoding.ASCII.GetBytes(magic)) || BinaryPrimitives.ReadUInt16BigEndian(record[4..6]) != 1)
            Reject(ContactValidationStage.Derived, "EmbeddedMagicMismatch");
    }

    private static ReadOnlySpan<byte> ReadField(ReadOnlySpan<byte> record, int wantedTag, int fieldCount)
    {
        if (BinaryPrimitives.ReadUInt16BigEndian(record[8..10]) != fieldCount) Reject(ContactValidationStage.Derived, "EmbeddedFieldCountMismatch");
        var offset = 12;
        for (var tag = 1; tag <= fieldCount; tag++)
        {
            if (record.Length - offset < 8 || BinaryPrimitives.ReadUInt16BigEndian(record.Slice(offset,2)) != tag || BinaryPrimitives.ReadUInt16BigEndian(record.Slice(offset + 2,2)) != 0) Reject(ContactValidationStage.Derived, "EmbeddedTagMismatch");
            var encodedLength = BinaryPrimitives.ReadUInt32BigEndian(record.Slice(offset+4,4));
            if (encodedLength > int.MaxValue) Reject(ContactValidationStage.Bounds, "EmbeddedFieldTruncated");
            var length = (int)encodedLength; offset += 8;
            if (length > record.Length - offset) Reject(ContactValidationStage.Bounds, "EmbeddedFieldTruncated");
            var value = record.Slice(offset,length); offset += length; if(tag==wantedTag) return value;
        }
        Reject(ContactValidationStage.Derived, "MissingEmbeddedField"); return default;
    }

    private static ulong Scalar(ReadOnlySpan<byte> bytes, int[] offsets, int[] lengths, int tag) => lengths[tag - 1] switch { 1 => bytes[offsets[tag - 1]], 2 => BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(offsets[tag - 1],2)), _ => throw new InvalidOperationException() };
    private static void RequireCount(ReadOnlySpan<byte> bytes, int[] offsets, int[] lengths, int tag, ulong min, ulong max) { var count=Scalar(bytes,offsets,lengths,tag); if (count<min || count>max) Reject(ContactValidationStage.Scalar,"CountOutOfRange"); }
    private static void RequireList(int actual, ulong count, int itemBytes) { if (actual != checked((int)count * itemBytes)) Reject(ContactValidationStage.Bounds,"CountLengthMismatch"); }
    private static void SortedRows(ReadOnlySpan<byte> value, int rowBytes) { ReadOnlySpan<byte> previous=default; for(var i=0;i<value.Length;i+=rowBytes) { var row=value.Slice(i,rowBytes); NonZero(row[..32]); if(!previous.IsEmpty && previous.SequenceCompareTo(row[..32])>=0) Reject(ContactValidationStage.Bounds,"ListNotStrictlyOrdered"); previous=row[..32]; } }
    private static void UniqueRows(ReadOnlySpan<byte> value, int rowBytes) { for(var i=0;i<value.Length;i+=rowBytes) { var row=value.Slice(i,rowBytes); NonZero(row[..32]); for(var prior=0;prior<i;prior+=rowBytes) if(row[..32].SequenceEqual(value.Slice(prior,32))) Reject(ContactValidationStage.Bounds,"ListNotUnique"); } }
    private static void GenPredecessor(ReadOnlySpan<byte> generation, ReadOnlySpan<byte> predecessor) { if (IsZero(predecessor) != (U64(generation)==0)) Reject(ContactValidationStage.Scalar,"InvalidGenesisPredecessor"); }
    private static bool ValidWindow(ulong issued, ulong expires, ulong maximum) => issued < expires && expires - issued <= maximum;
    private static bool ValidWindowWithNotBefore(ulong issued, ulong notBefore, ulong expires, ulong maximum) => issued <= notBefore && notBefore < expires && expires - issued <= maximum;
    private static void Reference(ReadOnlySpan<byte> value,string magic) { _=DecodeArtifactReference(value,magic); }
    private static void RequireRecord(ContactRecord record, string magic) { if (!StringComparer.Ordinal.Equals(record.Magic, magic)) Reject(ContactValidationStage.Closure, "ClosureRecordTypeMismatch"); }
    private static void RequireReference(ContactRecord source, int tag, ContactRecord expected) { if (!source.FieldSpan(tag).SequenceEqual(ArtifactReference(expected.Magic, expected).CanonicalBytes.Span)) Reject(ContactValidationStage.Closure, "ClosureReferenceMismatch"); }
    private static void RequireHash(ContactRecord source, int tag, ContactRecord expected) { if (!source.FieldSpan(tag).SequenceEqual(expected.ArtifactHash.Span)) Reject(ContactValidationStage.Closure, "ClosureHashMismatch"); }
    private static bool ReferenceMatches(ApplicationArtifactReference reference, CanonicalIdentityArtifact artifact) =>
        reference.CanonicalLength == artifact.CanonicalBytes.Length &&
        reference.CanonicalHash.Span.SequenceEqual(artifact.CanonicalHash.Span);
    private static void NonZero(ReadOnlySpan<byte> value) { if(IsZero(value)) Reject(ContactValidationStage.Scalar,"ZeroForbidden"); }
    private static ulong U64(ReadOnlySpan<byte> value)=>BinaryPrimitives.ReadUInt64BigEndian(value);
    private static uint U32(ReadOnlySpan<byte> value)=>BinaryPrimitives.ReadUInt32BigEndian(value);
    private static ushort U16(ReadOnlySpan<byte> value)=>BinaryPrimitives.ReadUInt16BigEndian(value);
    private static bool IsZero(ReadOnlySpan<byte> value) { byte x=0; foreach(var b in value)x|=b; return x==0; }
    private static bool IsAsciiMagic(ReadOnlySpan<byte> value) => value.Length==4 && value.ToArray().All(static b=>b is >=0x21 and <=0x7e);
    private static void Reject(ContactValidationStage stage,string code) => throw new ContactFormatException(stage,code);

    private sealed record Definition(string Magic,int[] Lengths,int MinimumBytes,int MaximumBytes,string? SignatureDomain,string? CoreDomain,int[] ProjectionTags);
    internal sealed record Xps1Record(
        byte[] CanonicalBytes,
        byte[] NetworkId,
        byte[] ServiceCapability,
        byte[] DeviceId,
        byte[] Dpd1Reference,
        ulong ServiceGeneration,
        ushort SupportedSuite,
        ushort MinimumOneTimeInventory,
        ushort LastResortReuseLimit,
        ulong IssuedAtUnixSeconds,
        ulong ExpiresAtUnixSeconds);
}

public enum ContactValidationStage { Length, Header, FieldScan, Bounds, Scalar, Derived, Reference, Signature, Closure, Transition }
public sealed class ContactFormatException(ContactValidationStage stage, string code) : FormatException(code) { public ContactValidationStage Stage { get; } = stage; public string Code { get; } = code; }
public interface IContactRecordResolver { ContactRecord? Resolve(ContactArtifactReference reference); }

public sealed class ContactArtifactReference
{
    private readonly byte[] hash;
    internal ContactArtifactReference(string magic, ushort version, ReadOnlySpan<byte> hash) { Magic=magic; Version=version; this.hash=hash.ToArray(); }
    public string Magic { get; } public ushort Version { get; } public ReadOnlyMemory<byte> Hash => hash.ToArray();
    public ReadOnlyMemory<byte> CanonicalBytes { get { var output=new byte[38]; Encoding.ASCII.GetBytes(Magic).CopyTo(output,0); BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4),Version); hash.CopyTo(output,6); return output; } }
}

public sealed class ContactRecord
{
    private readonly byte[] canonical; private readonly byte[][] fields; private readonly string? signatureDomain; private readonly string? coreDomain; private readonly int[] projectionTags;
    internal ContactRecord(string magic,byte[] canonical,byte[][] fields,string? signatureDomain,string? coreDomain,int[] projectionTags) { Magic=magic; this.canonical=canonical; this.fields=fields; this.signatureDomain=signatureDomain; this.coreDomain=coreDomain; this.projectionTags=projectionTags; }
    public string Magic { get; } public ReadOnlyMemory<byte> CanonicalBytes=>canonical.ToArray(); public ReadOnlyMemory<byte> ArtifactHash=>SHA256.HashData(canonical);
    public ReadOnlyMemory<byte> Field(int tag)=>FieldSpan(tag).ToArray(); internal ReadOnlySpan<byte> FieldSpan(int tag)=>fields[tag-1];
    public ReadOnlyMemory<byte> SigningProjection=>signatureDomain is null ? throw new InvalidOperationException("Record has no signature projection.") : ContactCodec.Project(this,projectionTags);
    public ReadOnlyMemory<byte> SignatureInput=>signatureDomain is null ? throw new InvalidOperationException("Record has no signature projection.") : ContactCodec.SignatureInput(signatureDomain,SigningProjection.Span);
    public ReadOnlyMemory<byte> CoreHash=>coreDomain is null ? ArtifactHash : ContactCodec.Sha256Domain(coreDomain,ContactCodec.Project(this,projectionTags));
}

/// <summary>
/// Non-forgeable result of <see cref="ContactCodec.VerifyDcr1Closure"/>.  A
/// consumer must hold this result before treating a contact bundle as an
/// identity- and revocation-verified publication.
/// </summary>
public sealed class VerifiedContactBundleClosure
{
    internal VerifiedContactBundleClosure(
        ContactRecord resolverResponse,
        ContactRecord bundle,
        VerifiedDab1 binding,
        VerifiedDmd1 directory,
        CurrentlyAuthoritativeDca1 authorization,
        VerifiedAccountDirectoryFreshness freshness)
    {
        ResolverResponse = resolverResponse;
        Bundle = bundle;
        Binding = binding;
        Directory = directory;
        Authorization = authorization;
        Freshness = freshness;
    }

    public ContactRecord ResolverResponse { get; }
    public ContactRecord Bundle { get; }
    public VerifiedDab1 Binding { get; }
    public VerifiedDmd1 Directory { get; }
    public CurrentlyAuthoritativeDca1 Authorization { get; }
    public VerifiedAccountDirectoryFreshness Freshness { get; }
}

/// <summary>
/// Production-owned proof of the exact current XNV/XNH/ADH authority and its
/// directory witness keys. It has no public construction or caller-key path.
/// </summary>
public sealed partial class VerifiedContactNetworkAuthority
{
}

/// <summary>Exact route graph authorized by verified network ownership and trusted time.</summary>
public sealed class VerifiedContactRouteClosure
{
    internal VerifiedContactRouteClosure(
        ContactRecord invite, ContactRecord reachability, ContactRecord authorization,
        ContactRecord route, ContactRecord successor, ContactRecord projection,
        ContactRecord selection, VerifiedContactNetworkAuthority authority)
    {
        Invite = invite; Reachability = reachability; Authorization = authorization;
        Route = route; Successor = successor; Projection = projection; Selection = selection;
        Authority = authority;
    }
    public ContactRecord Invite { get; }
    public ContactRecord Reachability { get; }
    public ContactRecord Authorization { get; }
    public ContactRecord Route { get; }
    public ContactRecord Successor { get; }
    public ContactRecord Projection { get; }
    public ContactRecord Selection { get; }
    public VerifiedContactNetworkAuthority Authority { get; }
}
