using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.Registry;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Authenticates a DID2 DPK2 offering against a nonce-fresh current directory
/// proof. It does not grant XPI1 inventory membership, XPC1 claim, or durable
/// publication authority.
/// </summary>
public static class DeepIdV2Dpk2PreClaimVerifier
{
    public static VerifiedDpk2Offering Verify(
        ReadOnlySpan<byte> exactDpk2,
        VerifiedDeepIdV2DirectoryFreshness peerProof,
        ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(peerProof);
        if (peerProof.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue ||
            peerProof.CurrentCheckpoint is null ||
            !peerProof.IsCurrentAtMonotonic(currentBootId,
                currentMonotonicSample))
            throw new CryptographicException(
                "The DID2 DPK2 peer proof is not current at this operation.");
        ulong lower, upper;
        try
        {
            var elapsed = checked(currentMonotonicSample - peerProof.MonotonicSample);
            lower = checked(peerProof.TrustedLowerUnixSeconds + elapsed);
            upper = checked(peerProof.TrustedUpperUnixSeconds + elapsed);
        }
        catch (OverflowException exception)
        {
            throw new CryptographicException(
                "The DID2 DPK2 trusted-time interval overflowed.", exception);
        }
        return MessagingWireVerification.VerifyDpk2V2(exactDpk2,
            new CurrentPeerCallbacks(peerProof, lower, upper));
    }

    private sealed class CurrentPeerCallbacks(
        VerifiedDeepIdV2DirectoryFreshness peerProof,
        ulong trustedLowerUnixSeconds,
        ulong trustedUpperUnixSeconds)
        : IDpk2VerificationCallbacks
    {
        public Dpk2ResolvedDevice ResolveActiveDevice(Dpk2Record offering)
        {
            var checkpoint = peerProof.CurrentCheckpoint!;
            var identity = checkpoint.Binding.Identity;
            var directory = checkpoint.Directory.Record;
            if (!Fixed(offering.NetworkId.Span, peerProof.NetworkId.Span) ||
                !Fixed(offering.ResponderAccountId.Span,
                    identity.Account.DeepAccountIdHash.Span) ||
                !Fixed(directory.NetworkId.Span, peerProof.NetworkId.Span) ||
                !Fixed(directory.DeepAccountId.Span,
                    offering.ResponderAccountId.Span) ||
                offering.DeviceDirectoryGeneration !=
                    directory.DirectoryGeneration ||
                !Fixed(offering.DeviceDirectoryHeadHash.Span,
                    directory.RecordHash.Span) ||
                offering.IssuedAt < directory.IssuedAtUnixSeconds ||
                trustedLowerUnixSeconds < offering.NotBefore ||
                trustedUpperUnixSeconds >= offering.ExpiresAt)
                throw new CryptographicException(
                    "DPK2 is outside the exact current DID2 peer directory or validity window.");
            var entry = directory.ActiveDevices.SingleOrDefault(device =>
                Fixed(device.DeviceId.Span, offering.ResponderDeviceId.Span));
            var device = identity.ActiveDevices.SingleOrDefault(candidate =>
                Fixed(candidate.Certificate.DeviceId.Span,
                    offering.ResponderDeviceId.Span));
            if (entry is null || device is null ||
                device.Certificate.DeviceGeneration !=
                    offering.ResponderDeviceGeneration ||
                !offering.ResponderDpd1Ref.Span[..4].SequenceEqual(
                    DeepProtocolIdentifiers.MagicBytes.DPD1) ||
                offering.ResponderDpd1Ref.Span[4] != 0 ||
                offering.ResponderDpd1Ref.Span[5] != 1 ||
                !Fixed(offering.ResponderDpd1Ref.Span[6..],
                    entry.Dpd1Reference.CanonicalHash.Span) ||
                !Fixed(entry.Dpd1Reference.CanonicalHash.Span,
                    device.Certificate.CanonicalHash.Span))
                throw new CryptographicException(
                    "DPK2 responder is not an exact active DID2 device.");
            return new Dpk2ResolvedDevice(
                device.Certificate.DeviceEd25519PublicKey.Span,
                device.Certificate.DeviceX25519PublicKey.Span);
        }

        public bool VerifyEd25519(ReadOnlyMemory<byte> publicKey,
            ReadOnlyMemory<byte> signatureInput,
            ReadOnlyMemory<byte> signature) =>
            PublicKeyAuth.VerifyDetached(signature.ToArray(),
                signatureInput.ToArray(), publicKey.ToArray());
    }

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
