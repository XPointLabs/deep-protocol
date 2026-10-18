using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.PrivacyRouting;

public static partial class OnionPathContextFactory
{
    public static IReadOnlyList<ReadOnlyMemory<byte>> BlobNodeIds(VerifiedOnionNetworkContext network, ReadOnlyMemory<byte> objectId)
    {
        ArgumentNullException.ThrowIfNull(network); network.EnsureCurrent();
        if (objectId.Length != 32 || objectId.Span.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("Exact object ID required.");
        var eligible = network.CandidateNodes.Where(node => (node.RoleMask & 12) == 12 && node.BlobCapacity > 0).ToArray();
        if (eligible.Length is < 2 or > 128) throw new OnionBoundaryException("blob-cohort-invalid", "Bounded current Blob cohort unavailable.");
        return eligible.Select(node => (Node: node, Rank: SHA256.HashData([.. network.NetworkId.Span, .. objectId.Span, .. node.NodeId])))
            .OrderBy(row => Convert.ToHexString(row.Rank), StringComparer.Ordinal)
            .ThenBy(row => Convert.ToHexString(row.Node.NodeId), StringComparer.Ordinal)
            .Select(row => (ReadOnlyMemory<byte>)row.Node.NodeId.ToArray()).ToArray();
    }

    public static VerifiedOnionPathContext CreateBlob(VerifiedOnionNetworkContext network,
        ReadOnlyMemory<byte> ingressNodeId, ReadOnlyMemory<byte> coreNodeId, ReadOnlyMemory<byte> exitNodeId)
    {
        ArgumentNullException.ThrowIfNull(network); network.EnsureCurrent();
        var time = network.TrustedTime ?? throw new OnionBoundaryException("network-context-incomplete", "Current trusted time is absent.");
        time.EnsureLive();
        var nodes = new[] { network.ResolveNode(ingressNodeId.Span), network.ResolveNode(coreNodeId.Span), network.ResolveNode(exitNodeId.Span) };
        RequireRole(nodes[0], 0, "Ingress"); RequireRole(nodes[1], 1, "Core"); RequireRole(nodes[2], 2, "Exit"); RequireRole(nodes[2], 3, "Blob");
        if (nodes[2].BlobCapacity == 0) throw new OnionBoundaryException("blob-capacity-invalid", "Blob exit advertises no storage.");
        RequireExactPathDiversity(nodes);
        return new(network, time, OnionOperation.Blob, [Hop(nodes[0], PrivacyRoutingKeyRole.Relay), Hop(nodes[1], PrivacyRoutingKeyRole.Relay), Hop(nodes[2], PrivacyRoutingKeyRole.Exit)]);
    }
}
