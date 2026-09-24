using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// DID2 recipient binding for the independently versioned XPI1 manifest.
/// A positive result is not an XPP1 inventory, replica receipt or prekey claim.
/// </summary>
public static class DeepIdV2PreKeyManifestBinding
{
    public static bool RuntimeActivation => false;

    public static void Verify(ParsedDcr1V2 closure,
        VerifiedDca1V2 authorization, Xpi1Record manifest,
        ulong trustedUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(closure);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(manifest);
        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(
            closure, authorization, trustedUnixSeconds);
        var bundle = closure.Bundle;
        var directory = authorization.Directory.Record;
        var identity = authorization.Binding.Identity;
        var recipientId = manifest.ResponderDeviceId.ToArray();
        var index = -1;
        for (var current = 0; current < directory.ActiveDevices.Count; current++)
            if (directory.ActiveDevices[current].DeviceId.Span.SequenceEqual(recipientId))
            {
                index = current;
                break;
            }
        if (index < 0)
        {
            Reject("XPI1 responder is not an active DCB1 V2 device.");
            return;
        }
        var device = identity.ActiveDevices.SingleOrDefault(candidate =>
            candidate.Certificate.DeviceId.Span.SequenceEqual(recipientId));
        if (device is null)
        {
            Reject("XPI1 responder has no verified DPD1 custody.");
            return;
        }
        var list = bundle.FieldSpan(12);
        var xps = list.Slice(1 + index * 356 + 4, 352);
        Span<ApplicationFieldSlice> slices = stackalloc ApplicationFieldSlice[12];
        ApplicationCoreFormat.Preflight(xps, ProtocolMagicBytes.XPS1, 12,
            352, 352, slices, 1, 0x0201);
        var expectedDpd = Reference(ProtocolMagicBytes.DPD1, 1,
            device.Certificate.CanonicalHash.Span);
        var expectedXps = Reference(ProtocolMagicBytes.XPS1, 1,
            SHA256.HashData(xps));
        var expectedDrs = Reference(ProtocolMagicBytes.DRS1, 1,
            identity.Revocations.Snapshot.CanonicalHash.Span);
        if (!manifest.NetworkId.Span.SequenceEqual(bundle.FieldSpan(1)) ||
            !manifest.ServiceCapability.Span.SequenceEqual(Get(xps, slices, 2)) ||
            !manifest.ResponderDpd1Reference.Span.SequenceEqual(expectedDpd) ||
            !manifest.Xps1Reference.Span.SequenceEqual(expectedXps) ||
            manifest.ServiceGeneration != U64(Get(xps, slices, 5)) ||
            manifest.OneTimeDpk2Count < U16(Get(xps, slices, 8)) ||
            !manifest.CurrentDmd1Hash.Span.SequenceEqual(directory.RecordHash.Span) ||
            !manifest.CurrentDrs1Reference.Span.SequenceEqual(expectedDrs) ||
            manifest.IssuedAtUnixSeconds < U64(Get(xps, slices, 10)) ||
            manifest.ExpiresAtUnixSeconds > U64(Get(xps, slices, 11)) ||
            manifest.IssuedAtUnixSeconds < U64(bundle.FieldSpan(17)) ||
            manifest.ExpiresAtUnixSeconds > U64(bundle.FieldSpan(18)) ||
            trustedUnixSeconds < manifest.IssuedAtUnixSeconds ||
            trustedUnixSeconds >= manifest.ExpiresAtUnixSeconds)
            Reject("XPI1 does not bind the exact current DID2 recipient XPS1/DMD1/DRS1 closure.");
        if (!PublicKeyAuth.VerifyDetached(manifest.PublisherSignature.ToArray(),
                manifest.Record.SignatureInput.ToArray(),
                device.Certificate.DeviceEd25519PublicKey.ToArray()))
            Reject("XPI1 responder signature is invalid.");
    }

    private static ReadOnlySpan<byte> Get(ReadOnlySpan<byte> canonical,
        ReadOnlySpan<ApplicationFieldSlice> slices, int tag) =>
        ApplicationCoreFormat.Field(canonical, slices, tag);

    private static ushort U16(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt16BigEndian(value);

    private static ulong U64(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt64BigEndian(value);

    private static byte[] Reference(ReadOnlySpan<byte> magic,
        ushort version, ReadOnlySpan<byte> hash)
    {
        var value = new byte[38];
        magic.CopyTo(value);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), version);
        hash.CopyTo(value.AsSpan(6));
        return value;
    }

    private static void Reject(string message) => throw ApplicationCoreFormat.Error(
        ApplicationCoreValidationStage.CryptographicVerification,
        ApplicationCoreRejection.VerificationFailed, message);
}
