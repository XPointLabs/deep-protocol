using System.Security.Cryptography;
using Deep.Protocol.GroupV1;

namespace Deep.Protocol.Identity;

public sealed partial class OwnedGenesisDeviceSecrets
{
    internal void RequireCurrentGroupDevice(VerifiedDeepIdV2GroupDirectory authority)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            if (!SigningPublicKey.Matches(authority.RequireDevice(DeviceId.Bytes.Span).Certificate.DeviceEd25519PublicKey.Span))
                throw new CryptographicException("Group device custody differs from the verified current device.");
        }
    }
    // Artifact-specific internal intent; never export a general device signer.
    internal byte[] SignCurrentGroupRecord(GroupRecord record, VerifiedDeepIdV2GroupDirectory authority)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            var (account, device, reference) = record.Magic switch
            {
                ProtocolMagic.DGC1 => (6, 7, 8),
                ProtocolMagic.GIV1 => (6, 7, 8),
                ProtocolMagic.GIA1 => (5, 6, 7),
                ProtocolMagic.DGP1 => (6, 7, 8),
                _ => throw new CryptographicException("Unsupported owned group signing intent.")
            };
            var current = authority.RequireDevice(DeviceId.Bytes.Span);
            if (!SigningPublicKey.Matches(current.Certificate.DeviceEd25519PublicKey.Span) ||
                !record.FieldSpan(1).SequenceEqual(authority.NetworkId.Span) ||
                !record.FieldSpan(account).SequenceEqual(authority.AccountId.Span) ||
                !record.FieldSpan(device).SequenceEqual(DeviceId.Bytes.Span) ||
                !record.FieldSpan(reference).SequenceEqual(GroupCodec.ReferenceForAuthoring(ProtocolMagic.DPD1,
                    current.Certificate.CanonicalHash.Span)))
                throw new CryptographicException("Group intent differs from owned current DID2 device custody.");
            return SignRouteIntent(record.SignatureInput.Span);
        }
    }
}
