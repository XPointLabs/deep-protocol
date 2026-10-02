using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>
/// Explicit operator-only capture check. Inputs are already authenticated by
/// XNode's offline custody audit. This emits no verified/current capability and
/// adds no shipping API or foreign DNH2 parser. Normal CI skips this live input.
/// </summary>
public sealed class ProtectedPredecessorCaptureTests
{
    [OperatorCaptureFact]
    public void CapturedNodeHistoriesOccurExactlyInRetainedEightChainBase()
    {
        try
        {
            var encoded = Environment.GetEnvironmentVariable("DEEP_PROTECTED_PREDECESSOR_CAPTURE_INPUT") ??
                throw new InvalidOperationException();
            Require(encoded.Length <= 32_768);
            var input = JsonSerializer.Deserialize<CaptureInput>(encoded, new JsonSerializerOptions {
                PropertyNameCaseInsensitive = false, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
            }) ?? throw new InvalidOperationException();
            Require(input.Histories.Length == 3 && input.Histories.Select(item => item.Path).Distinct().Count() == 3);
            var network = Hex(input.NetworkHex, 16); var pinHash = Hex(input.GenesisCoreHashHex, 32);
            var bundle = XPointNetworkClosureWireCodec.DecodeResponse(Read(input.BundlePath,
                XPointNetworkClosureWireCodec.MaximumResponseLength));
            Require(bundle.NetworkId.Span.SequenceEqual(network));
            var authority = XPointNetworkAuthorityVerifier.Verify(new XPointNetworkGenesisPin(network, pinHash),
                bundle.ExactAuthorityChain, bundle.ExactTimePolicyChain);
            Require(SHA256.HashData(bundle.ExactViewChain[^1].Span).AsSpan().SequenceEqual(Hex(input.ExpectedTipXnvSha256, 32)));
            Require(bundle.ExactViewChain.Count == bundle.ExactHeadChain.Count);
            ulong? retainedGeneration = null;
            foreach (var capture in input.Histories)
            {
                var exact = Read(capture.Path, 16 + 225 + 2 * 65_535);
                Require(SHA256.HashData(exact).AsSpan().SequenceEqual(Hex(capture.Sha256, 32)));
                var history = OnionNetworkProtectedHistoryCodec.Decode(exact);
                Require(history.Lkg.NetworkId.Span.SequenceEqual(network));
                Require(history.Lkg.AuthorityCoreReference.Span.SequenceEqual(
                    XPointNetworkCodec.EncodeCoreReference("XNA1", authority.AuthorityCoreHash.Span)));
                var matches = 0;
                for (var i = 0; i < bundle.ExactViewChain.Count; i++)
                {
                    var view = XPointNetworkCodec.Parse<Xnv1Record>(bundle.ExactViewChain[i].Span);
                    var head = XPointNetworkCodec.Parse<Xnh1Record>(bundle.ExactHeadChain[i].Span);
                    if (view.ViewGeneration != history.Lkg.ViewGeneration) continue;
                    Require(history.Lkg.ViewCoreReference.Span.SequenceEqual(XPointNetworkCodec.EncodeCoreReference("XNV1", view.CoreHash.Span)));
                    Require(history.Lkg.HeadCoreReference.Span.SequenceEqual(XPointNetworkCodec.EncodeCoreReference("XNH1", head.CoreHash.Span)));
                    Require(history.Lkg.HeadTreeSize == head.TreeSize && history.Lkg.HeadRoot.Span.SequenceEqual(head.Root.Span));
                    Require(view.ActivePolicy.Hash.Span.SequenceEqual(history.Policy.CoreHash.Span));
                    matches++;
                }
                Require(matches == 1);
                Require(bundle.ExactNetworkPolicyChain.Any(record => record.Span.SequenceEqual(history.Policy.CanonicalCopy())));
                Require(bundle.ExactPlacementTopologyChain.Any(record => record.Span.SequenceEqual(history.Pmt.CanonicalBytes.Span)));
                Require(retainedGeneration is null || retainedGeneration == history.Lkg.ViewGeneration);
                retainedGeneration = history.Lkg.ViewGeneration;
            }
            var tipHead = XPointNetworkCodec.Parse<Xnh1Record>(bundle.ExactHeadChain[^1].Span);
            var tipView = XPointNetworkCodec.Parse<Xnv1Record>(bundle.ExactViewChain[^1].Span);
            var tipPmt = ContactCodec.Decode("PMT2", bundle.ExactPlacementTopologyChain[^1].Span);
            Require(tipPmt.Field(5).Span.SequenceEqual(XPointNetworkCodec.EncodeCoreReference("XNV1", tipView.CoreHash.Span)));
            Require(retainedGeneration <= tipView.ViewGeneration);
            var report = JsonSerializer.SerializeToUtf8Bytes(new {
                schema = "deep.network.protected-predecessor-capture.v1", reusableFreshnessEvidence = false,
                capturedNodeCount = 3, retainedViewGeneration = retainedGeneration, baseViewGeneration = tipView.ViewGeneration,
                sourceHeadCoreHashHex = Convert.ToHexString(tipHead.CoreHash.Span),
                sourcePmtArtifactHashHex = Convert.ToHexString(tipPmt.ArtifactHash.Span)
            });
            Require(Path.IsPathFullyQualified(input.OutputPath));
            using var stream = new FileStream(input.OutputPath, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.WriteThrough);
            stream.Write(report); stream.Flush(true);
        }
        catch { throw new InvalidOperationException("Protected predecessor capture rejected; no fresh authority was issued."); }
    }

    private static byte[] Read(string path, long maximum)
    {
        Require(Path.IsPathFullyQualified(path));
        for (string? parent = Path.GetFullPath(path); parent is not null; parent = Path.GetDirectoryName(parent))
            Require((File.GetAttributes(parent) & FileAttributes.ReparsePoint) == 0);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Require(stream.Length is > 0 && stream.Length <= maximum);
        var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes); Require(stream.ReadByte() == -1);
        return bytes;
    }
    private static byte[] Hex(string text, int length)
    {
        Require(text.Length == length * 2); var bytes = Convert.FromHexString(text);
        Require(bytes.AsSpan().IndexOfAnyExcept((byte)0) >= 0); return bytes;
    }
    private static void Require(bool condition) { if (!condition) throw new InvalidOperationException(); }
    private sealed record CaptureInput(string BundlePath, string NetworkHex, string GenesisCoreHashHex,
        string ExpectedTipXnvSha256, Capture[] Histories, string OutputPath);
    private sealed record Capture(string Path, string Sha256);
    private sealed class OperatorCaptureFactAttribute : FactAttribute
    {
        public OperatorCaptureFactAttribute()
        {
            if (Environment.GetEnvironmentVariable("DEEP_PROTECTED_PREDECESSOR_CAPTURE_INPUT") is null)
                Skip = "Explicit authenticated operator capture inputs are absent; not a device/release gate.";
        }
    }
}
