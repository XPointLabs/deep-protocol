using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Verifies one DID2-generation DPK2 against the current recipient and XPI1.
/// This is not Merkle membership, two-replica publication or live claim proof.
/// </summary>
public static class DeepIdV2Dpk2MemberBinding
{
    public static bool RuntimeActivation => false;

    public static void Verify(ParsedDcr1V2 closure,
        DeepIdV2CurrentContactAuthorization currentAuthorization,
        ParsedXpi1V2 manifest, ParsedDpk2V2 offering,
        ReadOnlySpan<byte> currentBootId, ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(offering);
        DeepIdV2PreKeyManifestBinding.Verify(closure, currentAuthorization,
            manifest, currentBootId, currentMonotonicSample);
        VerifyAfterManifest(closure, currentAuthorization, manifest, offering);
    }

    internal static void VerifyAfterManifest(ParsedDcr1V2 closure,
        DeepIdV2CurrentContactAuthorization currentAuthorization,
        ParsedXpi1V2 manifest, ParsedDpk2V2 offering)
    {
        ArgumentNullException.ThrowIfNull(closure);
        VerifyAfterManifest(closure.Bundle.FieldSpan(2), currentAuthorization,
            manifest, offering);
    }

    internal static void VerifyAfterManifest(ReadOnlySpan<byte> expectedAccountId,
        DeepIdV2CurrentContactAuthorization currentAuthorization,
        ParsedXpi1V2 manifest, ParsedDpk2V2 offering)
    {
        ArgumentNullException.ThrowIfNull(currentAuthorization);
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(offering);
        if (expectedAccountId.Length != 32)
            throw new ArgumentException("The exact account ID is required.",
                nameof(expectedAccountId));
        var record = offering.Record;
        var directory = currentAuthorization.Authorization.Directory.Record;
        var signer = currentAuthorization.Authorization.Binding.Identity
            .ActiveDevices.SingleOrDefault(candidate =>
                candidate.Certificate.DeviceId.Span.SequenceEqual(
                    manifest.FieldSpan(3)));
        if (signer is null)
        {
            Reject("DPK2 responder has no current DID2 device custody.");
            return;
        }
        var certificate = signer.Certificate;
        if (!record.NetworkId.Span.SequenceEqual(manifest.FieldSpan(1)) ||
            !record.ResponderAccountId.Span.SequenceEqual(
                expectedAccountId) ||
            !record.ResponderDeviceId.Span.SequenceEqual(manifest.FieldSpan(3)) ||
            record.ResponderDeviceGeneration != certificate.DeviceGeneration ||
            !record.ResponderDpd1Ref.Span.SequenceEqual(manifest.FieldSpan(4)) ||
            record.DeviceDirectoryGeneration != directory.DirectoryGeneration ||
            !record.DeviceDirectoryHeadHash.Span.SequenceEqual(
                manifest.FieldSpan(12)) ||
            record.PrekeyServiceGeneration != U64(manifest.FieldSpan(5)) ||
            record.InventoryEpoch != U64(manifest.FieldSpan(7)) ||
            record.NotBefore != U64(manifest.FieldSpan(14)) ||
            record.IssuedAt > U64(manifest.FieldSpan(14)) ||
            record.ExpiresAt != U64(manifest.FieldSpan(15)) ||
            !record.DeviceAgreementPublicKey.Span.SequenceEqual(
                certificate.DeviceX25519PublicKey.Span))
            Reject("DPK2 is not the exact current DID2 recipient inventory member.");

        var signingKey = certificate.DeviceEd25519PublicKey.ToArray();
        if (!PublicKeyAuth.VerifyDetached(
                record.SignedX25519PrekeySignature.ToArray(),
                DeepIdV2Dpk2Codec.GetX25519SignedPrekeySignatureInput(record),
                signingKey) ||
            !PublicKeyAuth.VerifyDetached(
                record.MlKemPrekeySignature.ToArray(),
                DeepIdV2Dpk2Codec.GetMlKemPrekeySignatureInput(record),
                signingKey) ||
            !PublicKeyAuth.VerifyDetached(
                record.BundleSignature.ToArray(),
                DeepIdV2Dpk2Codec.GetPrekeyBundleSignatureInput(record),
                signingKey))
            Reject("DPK2 DID2 responder signatures are invalid.");
    }

    private static ulong U64(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt64BigEndian(value);

    private static void Reject(string message) => throw ApplicationCoreFormat.Error(
        ApplicationCoreValidationStage.CryptographicVerification,
        ApplicationCoreRejection.VerificationFailed, message);
}
