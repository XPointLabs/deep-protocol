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
        var label = Label(artifact);
        // Identical conservative predicate to the route verifier's previous check.
        var reason = lower > upper ? "InvalidInterval" :
            start > lower ? "NotBefore" : upper >= expiry ? "Expiry" : null;
        if (reason is not null) throw Error(label, reason);
    }

    // Used ONLY inside the retained-threshold verifier. An in-window future
    // start is collected, not admitted; expiry/invalidity always reject first.
    internal static bool RequireSchedulingWindow(ulong lower, ulong upper, ulong start, ulong expiry,
        DeepIdV2RouteTimeArtifact artifact)
    {
        var label = Label(artifact);
        if (lower > upper) throw Error(label, "InvalidInterval");
        if (upper >= expiry) throw Error(label, "Expiry");
        if (start > upper) throw Error(label, "NotBefore");
        return start > lower;
    }

    private static CryptographicException Error(string label, string reason) =>
        new($"DID2 route time coverage failed ({label}; {reason}).");

    private static string Label(DeepIdV2RouteTimeArtifact artifact) => artifact switch
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
}

// A private invocation-local scheduling accumulator. It contains no verified
// route or reusable context and can never relax an ordinary coverage check.
internal sealed class DeepIdV2RouteNotBeforeWindow(ulong lower, ulong upper)
{
    private ulong latestStart;
    internal void Require(ulong start, ulong expiry, DeepIdV2RouteTimeArtifact artifact)
    {
        if (artifact is not (DeepIdV2RouteTimeArtifact.Pms2 or DeepIdV2RouteTimeArtifact.Xrc1 or DeepIdV2RouteTimeArtifact.Xss1))
            throw new ArgumentOutOfRangeException(nameof(artifact));
        if (DeepIdV2RouteTimeCoverage.RequireSchedulingWindow(lower, upper, start, expiry, artifact))
            latestStart = Math.Max(latestStart, start);
    }

    // Called only AFTER complete signatures, exact request/head/ancestry/scope
    // and the final actual clock/currentness verification have all succeeded.
    internal void ThrowIfPending()
    {
        if (latestStart <= lower) return;
        var seconds = latestStart - lower;
        if (seconds > uint.MaxValue) throw new CryptographicException("Route scheduling duration is outside its bound.");
        throw new DeepIdV2RouteNotBeforeException(checked((uint)seconds));
    }
}
