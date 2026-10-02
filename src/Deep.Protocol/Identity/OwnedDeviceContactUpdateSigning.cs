using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Identity;

public sealed partial class OwnedGenesisDeviceSecrets
{
    internal byte[] SignContactUpdateRendezvous(ContactRecord record,
        VerifiedDeepIdV2DirectoryFreshness freshness)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            var checkpoint = freshness.CurrentCheckpoint ??
                throw new CryptographicException("The rendezvous has no current device checkpoint.");
            var device = checkpoint.Directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
                candidate.Certificate.DeviceId.Span.SequenceEqual(DeviceId.Bytes.Span));
            if (record.Magic != ProtocolMagic.XUR1 || device is null ||
                !record.FieldSpan(1).SequenceEqual(freshness.NetworkId.Span) ||
                !record.FieldSpan(13).SequenceEqual(DeviceId.Bytes.Span) ||
                !SigningPublicKey.Matches(device.Certificate.DeviceEd25519PublicKey.Span) ||
                !record.FieldSpan(14).SequenceEqual(new ContactArtifactReference(ProtocolMagic.DPD1, 1,
                    device.Certificate.CanonicalHash.Span).CanonicalBytes.Span))
                throw new CryptographicException("The XUR1 signing intent differs from the owned current device.");
            var signature = new byte[OwnedSodiumEd25519.SignatureSize];
            try
            {
                Span<byte> temporaryPublic = stackalloc byte[OwnedSodiumEd25519.PublicKeySize];
                Span<byte> temporarySecret = stackalloc byte[OwnedSodiumEd25519.SecretKeySize];
                OwnedSodiumEd25519.SignDetached(signingSeed, record.SignatureInput.Span, signature,
                    temporaryPublic, temporarySecret);
                return signature;
            }
            catch { CryptographicOperations.ZeroMemory(signature); throw; }
        }
    }
}
