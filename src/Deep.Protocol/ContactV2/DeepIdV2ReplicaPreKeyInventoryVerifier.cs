using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Verifies a selected replica's public XPS1/XPI1/DPK2 support against one
/// independently refreshed DID2 authority. It never opens or accepts DCR1
/// plaintext. Placement, lineage, durable commit and XIC1 remain separate.
/// </summary>
public static class DeepIdV2ReplicaPreKeyInventoryVerifier
{
    public static bool RuntimeActivation => false;

    public static void VerifyComplete(ParsedDid2 publisherHint,
        ReadOnlySpan<byte> exactXps1,
        DeepIdV2CurrentContactAuthorization currentAuthorization,
        ParsedXpp1V2 publication, ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(publisherHint);
        ArgumentNullException.ThrowIfNull(currentAuthorization);
        ArgumentNullException.ThrowIfNull(publication);
        var current = DeepIdV2CurrentContactAuthorizationVerifier.Verify(
            currentAuthorization.Freshness, currentAuthorization.Authorization,
            currentBootId, currentMonotonicSample);
        var authorization = current.Authorization;
        if (!CryptographicOperations.FixedTimeEquals(
                publisherHint.CanonicalBytes.Span,
                authorization.Binding.DeepId.CanonicalBytes.Span))
            Reject("XPP1 publisher hint differs from the current DID2 recipient.");

        var manifest = publication.Manifest;
        var xps = DecodeXps1(exactXps1);
        var directory = authorization.Directory.Record;
        var identity = authorization.Binding.Identity;
        var signer = identity.ActiveDevices.SingleOrDefault(candidate =>
            candidate.Certificate.DeviceId.Span.SequenceEqual(
                manifest.FieldSpan(3)));
        if (signer is null || !directory.ActiveDevices.Any(device =>
                device.DeviceId.Span.SequenceEqual(manifest.FieldSpan(3))))
            Reject("XPP1 responder has no current DID2 device custody.");
        var certificate = signer!.Certificate;
        var dpdReference = Reference(ProtocolMagicBytes.DPD1,
            certificate.CanonicalHash.Span);
        var drsReference = Reference(ProtocolMagicBytes.DRS1,
            identity.Revocations.Snapshot.CanonicalHash.Span);
        var xpsReference = Reference(ProtocolMagicBytes.XPS1,
            SHA256.HashData(exactXps1));
        if (!Field(xps, 1).SequenceEqual(authorization.Record.NetworkId.Span) ||
            !Field(xps, 2).SequenceEqual(manifest.FieldSpan(2)) ||
            !Field(xps, 3).SequenceEqual(manifest.FieldSpan(3)) ||
            !Field(xps, 4).SequenceEqual(dpdReference) ||
            !manifest.FieldSpan(1).SequenceEqual(authorization.Record.NetworkId.Span) ||
            !manifest.FieldSpan(4).SequenceEqual(dpdReference) ||
            !manifest.FieldSpan(6).SequenceEqual(xpsReference) ||
            !manifest.FieldSpan(12).SequenceEqual(directory.RecordHash.Span) ||
            !manifest.FieldSpan(13).SequenceEqual(drsReference) ||
            U64(manifest.FieldSpan(5)) != U64(Field(xps, 5)) ||
            U16(manifest.FieldSpan(9)) < U16(Field(xps, 8)) ||
            U64(manifest.FieldSpan(14)) < U64(Field(xps, 10)) ||
            U64(manifest.FieldSpan(15)) > U64(Field(xps, 11)) ||
            current.TrustedLowerUnixSeconds < U64(manifest.FieldSpan(14)) ||
            current.TrustedUpperUnixSeconds >= U64(manifest.FieldSpan(15)))
            Reject("XPP1 XPS1/XPI1 differ from the current DID2 device authority.");

        var unsignedXps = exactXps1[..280].ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(unsignedXps.AsSpan(8), 11);
        var xpsSignatureInput = ApplicationCoreFormat.SignatureInput(
            "Deep/ContactResolver/V1/prekey-service", unsignedXps, 0x0201);
        var signingKey = certificate.DeviceEd25519PublicKey.ToArray();
        if (!PublicKeyAuth.VerifyDetached(Field(xps, 12).ToArray(),
                xpsSignatureInput, signingKey) ||
            !PublicKeyAuth.VerifyDetached(manifest.Field(16).ToArray(),
                manifest.SignatureInput.ToArray(), signingKey))
            Reject("XPP1 public pre-key service or inventory signature is invalid.");

        var members = publication.OneTimeMembers;
        if (members.Count is < 32 or > 4096 ||
            members.Count != U16(manifest.FieldSpan(9)))
            Reject("XPP1 one-time member count differs from XPI1.");
        var hashes = new byte[members.Count][];
        ReadOnlyMemory<byte> previousId = default;
        for (var index = 0; index < members.Count; index++)
        {
            var member = members[index];
            if (member.Kind != Dpk2PrekeyKind.OneTime ||
                (!previousId.IsEmpty &&
                 previousId.Span.SequenceCompareTo(member.OneTimePrekeyId.Span) >= 0))
                Reject("XPP1 one-time DPK2 members are not strictly ordered.");
            previousId = member.OneTimePrekeyId;
            DeepIdV2Dpk2MemberBinding.VerifyAfterManifest(
                authorization.Record.DeepAccountId.Span, current, manifest,
                member);
            hashes[index] = member.ExactHash.ToArray();
        }
        var last = publication.LastResortMember;
        if (last.Kind != Dpk2PrekeyKind.LastResort ||
            last.Record.ReuseLimit > U16(Field(xps, 9)))
            Reject("XPP1 last-resort DPK2 exceeds the signed XPS1 policy.");
        DeepIdV2Dpk2MemberBinding.VerifyAfterManifest(
            authorization.Record.DeepAccountId.Span, current, manifest,
            last);
        if (!CryptographicOperations.FixedTimeEquals(
                DeepIdV2PreKeyInventoryVerifier.ComputeRoot(hashes),
                manifest.FieldSpan(10)) ||
            !CryptographicOperations.FixedTimeEquals(last.ExactHash.Span,
                manifest.FieldSpan(11)))
            Reject("XPP1 inventory differs from the complete signed XPI1 root.");
    }

    private static Xps1Fields DecodeXps1(ReadOnlySpan<byte> exact)
    {
        Span<ApplicationFieldSlice> slices = stackalloc ApplicationFieldSlice[12];
        ApplicationCoreFormat.Preflight(exact, ProtocolMagicBytes.XPS1, 12,
            352, 352, slices, 1, 0x0201);
        ReadOnlySpan<int> lengths = [16, 32, 32, 38, 8, 32, 2, 2, 2, 8, 8, 64];
        for (var tag = 1; tag <= lengths.Length; tag++)
            ApplicationCoreFormat.ExactLength(slices, tag, lengths[tag - 1]);
        var fields = new byte[12][];
        for (var tag = 1; tag <= fields.Length; tag++)
            fields[tag - 1] = ApplicationCoreFormat.Field(exact, slices, tag)
                .ToArray();
        if (fields[1].AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            fields[2].AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            fields[11].AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            !fields[3].AsSpan(0, 4).SequenceEqual(ProtocolMagicBytes.DPD1) ||
            U16(fields[3].AsSpan(4, 2)) != 1 ||
            U16(fields[6]) != 0x0201 || U16(fields[7]) == 0 ||
            U16(fields[8]) == 0 ||
            (fields[5].AsSpan().IndexOfAnyExcept((byte)0) < 0) !=
                (U64(fields[4]) == 0) ||
            U64(fields[9]) >= U64(fields[10]))
            Reject("XPP1 XPS1 descriptor is not canonical.");
        return new Xps1Fields(fields);
    }

    private static ReadOnlySpan<byte> Field(Xps1Fields xps, int tag) =>
        xps.Fields[tag - 1];

    private static byte[] Reference(ReadOnlySpan<byte> magic,
        ReadOnlySpan<byte> hash)
    {
        var bytes = new byte[38];
        magic.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        hash.CopyTo(bytes.AsSpan(6));
        return bytes;
    }

    private static ushort U16(ReadOnlySpan<byte> bytes) =>
        BinaryPrimitives.ReadUInt16BigEndian(bytes);

    private static ulong U64(ReadOnlySpan<byte> bytes) =>
        BinaryPrimitives.ReadUInt64BigEndian(bytes);

    private static void Reject(string message) => throw ApplicationCoreFormat.Error(
        ApplicationCoreValidationStage.CryptographicVerification,
        ApplicationCoreRejection.VerificationFailed, message);

    private sealed record Xps1Fields(byte[][] Fields);
}
