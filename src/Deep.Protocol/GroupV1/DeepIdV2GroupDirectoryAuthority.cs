using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;
using Sodium;

namespace Deep.Protocol.GroupV1;

/// <summary>
/// Current DID2 group account facts. Parsing support bytes or supplying a key
/// cannot construct this capability. It is not group membership or ACK authority.
/// </summary>
public sealed class VerifiedDeepIdV2GroupDirectory
{
    internal VerifiedDeepIdV2GroupDirectory(VerifiedDeepIdV2DirectoryFreshness proof) => Proof = proof;
    internal VerifiedDeepIdV2DirectoryFreshness Proof { get; }
    internal VerifiedAdc1V2 Checkpoint => Proof.CurrentCheckpoint!;
    public ReadOnlyMemory<byte> NetworkId => Proof.NetworkId;
    public ReadOnlyMemory<byte> AccountId => Checkpoint.Binding.Record.DeepAccountId;
    public ReadOnlyMemory<byte> ExactCheckpointReference => Checkpoint.Checkpoint.ArtifactReference;
    public ReadOnlyMemory<byte> ExactDirectoryHash => Checkpoint.Directory.Record.RecordHash;
    public ReadOnlyMemory<byte> ExactRevocationReference => Checkpoint.Checkpoint.ExactDrs1Reference;
    /// <summary>Public lookup provenance to retain with an authored invite; these bytes alone grant no authority.</summary>
    public ReadOnlyMemory<byte> ExactLookupProof => Proof.ExactAdp1V2;

    internal void RequireCurrent(OnionMonotonicReading reading)
    {
        if (!Proof.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds))
            throw new CryptographicException("Group directory authority is no longer current on this boot.");
        var lower = DeepIdV2GroupTransitions.Now(this, reading);
        var upper = checked(Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - Proof.MonotonicSample);
        if (Checkpoint.Directory.Record.IssuedAtUnixSeconds > lower ||
            Checkpoint.Directory.Identity.ActiveDevices.Any(device => device.Certificate.IssuedAtUnixSeconds > lower ||
                device.Certificate.ExpiresAtUnixSeconds <= upper))
            throw new CryptographicException("Group directory devices are not valid throughout the current trusted interval.");
    }

    internal VerifiedDevice RequireDevice(ReadOnlySpan<byte> id)
    {
        foreach (var device in Checkpoint.Directory.Identity.ActiveDevices)
            if (device.Certificate.DeviceId.Span.SequenceEqual(id)) return device;
        throw new CryptographicException("Group signer is absent from the current DID2 directory.");
    }

    internal GroupCodec.Member Member(GroupRole role) => new(AccountId.ToArray(), role,
        ExactCheckpointReference.ToArray(),
        AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.ADH1, 1, Proof.NextProtectedLkg.CoreHash.Span),
        GroupCodec.CurrentAdpHash(Proof.ExactAdp1V2.Span), Checkpoint.Directory.Record.DirectoryGeneration,
        ExactDirectoryHash.ToArray(), ExactRevocationReference.ToArray(),
        Checkpoint.Directory.Identity.ActiveDevices.Select(device => new GroupCodec.Device(
            device.Certificate.DeviceId.ToArray(), GroupCodec.ReferenceForAuthoring(ProtocolMagic.DPD1,
                device.Certificate.CanonicalHash.Span))).ToList());

    internal void RequireStableTuple(ReadOnlySpan<byte> adc, ReadOnlySpan<byte> dmd, ReadOnlySpan<byte> drs)
    {
        if (!adc.SequenceEqual(ExactCheckpointReference.Span) || !dmd.SequenceEqual(ExactDirectoryHash.Span) ||
            !drs.SequenceEqual(ExactRevocationReference.Span))
            throw new CryptographicException("Group directory state advanced or differs from the signed tuple.");
    }
}

public static class DeepIdV2GroupDirectoryAuthority
{
    public static async ValueTask<VerifiedDeepIdV2GroupDirectory> VerifyAsync(
        VerifiedDeepIdV2DirectoryFreshness proof, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proof); ArgumentNullException.ThrowIfNull(trustedTime);
        cancellationToken.ThrowIfCancellationRequested();
        if (proof.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue || proof.CurrentCheckpoint is null)
            throw new CryptographicException("Group authority requires a positive current DID2 directory result.");
        var first = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        var result = new VerifiedDeepIdV2GroupDirectory(proof); result.RequireCurrent(first);
        var checkpoint = proof.CurrentCheckpoint;
        if (!proof.NetworkId.Span.SequenceEqual(checkpoint.Checkpoint.NetworkId.Span) ||
            !checkpoint.Checkpoint.ExactDmd1Hash.Span.SequenceEqual(checkpoint.Directory.Record.RecordHash.Span) ||
            checkpoint.Directory.Identity.ActiveDevices.Count is < 1 or > 5)
            throw new CryptographicException("Group directory closure differs from its verified checkpoint.");
        var final = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        ContactControlEndpointV2.RequireContinuous(first, final); result.RequireCurrent(final);
        return result;
    }
}

public static partial class GroupCodec
{
    internal static byte[] CurrentAdpHash(ReadOnlySpan<byte> exact) =>
        RecordHash(ProtocolMagic.ADP1, exact);

    internal static void VerifyCurrentDeviceSignature(GroupRecord record, int accountTag, int deviceTag,
        int referenceTag, int signatureTag, VerifiedDeepIdV2GroupDirectory authority)
    {
        if (!record.FieldSpan(1).SequenceEqual(authority.NetworkId.Span) ||
            !record.FieldSpan(accountTag).SequenceEqual(authority.AccountId.Span))
            Reject(GroupValidationStage.Closure, "GroupCurrentAccountMismatch");
        var device = authority.RequireDevice(record.FieldSpan(deviceTag));
        var issuedTag = record.Magic switch { ProtocolMagic.DGC1 => 16, ProtocolMagic.GIV1 => 16,
            ProtocolMagic.GIA1 => 13, ProtocolMagic.DGP1 => 11, _ => throw new CryptographicException("Unsupported group signature intent.") };
        var issued = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(record.FieldSpan(issuedTag));
        if (issued < device.Certificate.IssuedAtUnixSeconds || issued >= device.Certificate.ExpiresAtUnixSeconds)
            Reject(GroupValidationStage.Signature, "GroupSignatureOutsideDeviceLifetime");
        RequireReference(record.FieldSpan(referenceTag), ProtocolMagic.DPD1, device.Certificate.CanonicalHash.Span);
        if (!PublicKeyAuth.VerifyDetached(record.Field(signatureTag).ToArray(), record.SignatureInput.ToArray(),
                device.Certificate.DeviceEd25519PublicKey.ToArray()))
            Reject(GroupValidationStage.Signature, "DeviceSignatureVerificationFailed");
    }
}
