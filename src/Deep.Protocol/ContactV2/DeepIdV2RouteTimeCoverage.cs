using System.Security.Cryptography;

namespace Deep.Protocol.ContactV2;

// Closed diagnostic labels only. Never include bounds, IDs, keys or artifact bytes.
internal enum DeepIdV2RouteTimeArtifact
{
    Xna1, Xnv1, Xnh1, Adh1, DeviceCertificate, Dca1, Pmt2,
    Xra1, Pms2, Xrc1, Xss1, Xir1V2, Xrr1, ThresholdAuthoring, ResolveRequest
}

internal static class DeepIdV2RouteTimeCoverage
{
    internal static void Require(ulong lower, ulong upper, ulong start, ulong expiry,
        DeepIdV2RouteTimeArtifact artifact)
    {
        var label = artifact switch
        {
            DeepIdV2RouteTimeArtifact.Xna1 => ProtocolMagic.XNA1,
            DeepIdV2RouteTimeArtifact.Xnv1 => ProtocolMagic.XNV1,
            DeepIdV2RouteTimeArtifact.Xnh1 => ProtocolMagic.XNH1,
            DeepIdV2RouteTimeArtifact.Adh1 => ProtocolMagic.ADH1,
            DeepIdV2RouteTimeArtifact.DeviceCertificate => "DeviceCertificate",
            DeepIdV2RouteTimeArtifact.Dca1 => ProtocolMagic.DCA1,
            DeepIdV2RouteTimeArtifact.Pmt2 => ProtocolMagic.PMT2,
            DeepIdV2RouteTimeArtifact.Xra1 => ProtocolMagic.XRA1,
            DeepIdV2RouteTimeArtifact.Pms2 => ProtocolMagic.PMS2,
            DeepIdV2RouteTimeArtifact.Xrc1 => ProtocolMagic.XRC1,
            DeepIdV2RouteTimeArtifact.Xss1 => ProtocolMagic.XSS1,
            DeepIdV2RouteTimeArtifact.Xir1V2 => "XIR1V2",
            DeepIdV2RouteTimeArtifact.Xrr1 => ProtocolMagic.XRR1,
            DeepIdV2RouteTimeArtifact.ThresholdAuthoring => "ThresholdAuthoring",
            DeepIdV2RouteTimeArtifact.ResolveRequest => "ResolveRequest",
            _ => throw new ArgumentOutOfRangeException(nameof(artifact))
        };
        // Identical conservative predicate to the route verifier's previous check.
        var reason = lower > upper ? "InvalidInterval" :
            start > lower ? "NotBefore" : upper >= expiry ? "Expiry" : null;
        if (reason is not null)
            throw new CryptographicException($"DID2 route time coverage failed ({label}; {reason}).");
    }
}
