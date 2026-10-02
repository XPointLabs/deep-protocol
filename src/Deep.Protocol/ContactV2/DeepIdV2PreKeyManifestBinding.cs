using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
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
        DeepIdV2CurrentContactAuthorization currentAuthorization,
        ParsedXpi1V2 manifest, ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(closure);
        ArgumentNullException.ThrowIfNull(currentAuthorization);
        ArgumentNullException.ThrowIfNull(manifest);
        var refreshed = DeepIdV2CurrentContactAuthorizationVerifier.Verify(
            currentAuthorization.Freshness,
            currentAuthorization.Authorization, currentBootId,
            currentMonotonicSample);
        var lower = refreshed.TrustedLowerUnixSeconds;
        var upper = refreshed.TrustedUpperUnixSeconds;
        var authorization = refreshed.Authorization;
        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(
            closure, authorization, lower);
        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(
            closure, authorization, upper);
        var bundle = closure.Bundle;
        var directory = authorization.Directory.Record;
        var identity = authorization.Binding.Identity;
        var recipientId = manifest.Field(3).ToArray();
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
        var service = DeepIdV2PreKeyServiceCodec.Decode(xps);
        var expectedDpd = Reference(ProtocolMagicBytes.DPD1, 1,
            device.Certificate.CanonicalHash.Span);
        var expectedXps = Reference(ProtocolMagicBytes.XPS1, 2,
            SHA256.HashData(xps));
        var expectedDrs = Reference(ProtocolMagicBytes.DRS1, 1,
            identity.Revocations.Snapshot.CanonicalHash.Span);
        if (!manifest.FieldSpan(1).SequenceEqual(bundle.FieldSpan(1)) ||
            !manifest.FieldSpan(2).SequenceEqual(service.Field(2).Span) ||
            !manifest.FieldSpan(4).SequenceEqual(expectedDpd) ||
            !manifest.FieldSpan(6).SequenceEqual(expectedXps) ||
            U64(manifest.FieldSpan(5)) != U64(service.Field(5).Span) ||
            U16(manifest.FieldSpan(9)) < U16(service.Field(8).Span) ||
            !manifest.FieldSpan(12).SequenceEqual(directory.RecordHash.Span) ||
            !manifest.FieldSpan(13).SequenceEqual(expectedDrs) ||
            U64(manifest.FieldSpan(14)) < U64(service.Field(10).Span) ||
            U64(manifest.FieldSpan(15)) > U64(service.Field(11).Span) ||
            lower < U64(manifest.FieldSpan(14)) ||
            upper >= U64(manifest.FieldSpan(15)))
            Reject("XPI1 does not bind the exact current DID2 recipient XPS1/DMD1/DRS1 closure.");
        if (!PublicKeyAuth.VerifyDetached(manifest.Field(16).ToArray(),
                manifest.SignatureInput.ToArray(),
                device.Certificate.DeviceEd25519PublicKey.ToArray()))
            Reject("XPI1 responder signature is invalid.");
    }

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
