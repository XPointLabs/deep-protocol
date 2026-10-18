using Deep.Protocol.ApplicationCore;
using System.Security.Cryptography;
using Deep.Protocol.GroupV1;

namespace Deep.Protocol.Identity;

public sealed partial class OwnedGenesisDeviceSecrets
{
    internal byte[] SignCurrentGroupControlRendezvous(GroupRecord record, VerifiedDeepIdV2GroupDirectory authority)
    {
        lock (sync)
        {
            ThrowIfDisposed(); RequireCurrentGroupDevice(authority);
            var certificate = authority.RequireDevice(DeviceId.Bytes.Span).Certificate;
            if (record.Magic != ProtocolMagic.GSR1 || !record.Field(1).Span.SequenceEqual(authority.NetworkId.Span) ||
                !record.Field(10).Span.SequenceEqual(DeviceId.Bytes.Span) ||
                !record.Field(11).Span.SequenceEqual(GroupCodec.ReferenceForAuthoring(ProtocolMagic.DPD1, certificate.CanonicalHash.Span)))
                throw new CryptographicException("Control signing intent differs from current owned device.");
            return SignRouteIntent(record.SignatureInput.Span);
        }
    }
}
