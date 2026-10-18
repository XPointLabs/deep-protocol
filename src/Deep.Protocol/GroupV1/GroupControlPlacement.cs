using Deep.Protocol.ApplicationCore;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.DeepExtension.PrivacyRouting;

/// <summary>Current NETCODEC-owned placement of one opaque control stream.</summary>
public sealed class VerifiedGroupControlPlacement
{
    private readonly byte[] selector, hash, view;
    private readonly byte[][] replicas;
    internal VerifiedGroupControlPlacement(VerifiedOnionNetworkContext network, byte[] selector, byte[] hash, byte[][] replicas)
        : this(network, selector, hash, replicas, network.Closure!.ViewCoreHash) { }
    internal VerifiedGroupControlPlacement(VerifiedOnionNetworkContext network, byte[] selector, byte[] hash, byte[][] replicas, byte[] view)
    { Network = network; this.selector = selector; this.hash = hash; this.replicas = replicas; this.view = view.ToArray(); }
    public VerifiedOnionNetworkContext Network { get; }
    public ReadOnlyMemory<byte> Selector => selector.ToArray();
    public ReadOnlyMemory<byte> PlacementHash => hash.ToArray();
    public ReadOnlyMemory<byte> ViewHash => view.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> ReplicaIds => replicas.Select(id => (ReadOnlyMemory<byte>)id.ToArray()).ToArray();
}

public static partial class GroupControlPlacementVerifier
{
    // Receipt verification is not a dispatch lease. Request windows are checked
    // by the actual current service authority, not by an expired anchor view.
    internal static VerifiedGroupControlPlacement OriginalFacts(VerifiedOnionNetworkContext network, Deep.Protocol.GroupV1.GroupControlWriteRecord request)
    {
        var placement = CreateForRequest(network, request);
        if (!placement.PlacementHash.Span.SequenceEqual(request.Field(4).Span))
            throw new CryptographicException("Control write changed original placement.");
        return placement;
    }

    /// <summary>Uses the descriptor's exact retained PMT2 as placement facts, with current admission for both replicas.</summary>
    public static VerifiedGroupControlPlacement Create(VerifiedOnionNetworkContext network, ReadOnlyMemory<byte> selector, ReadOnlyMemory<byte> anchorPmtReference)
    {
        ArgumentNullException.ThrowIfNull(network); network.EnsureCurrent();
        var closure = network.Closure ?? throw new CryptographicException("Current NETCODEC closure required.");
        var pmt = closure.RetainedPmts.SingleOrDefault(value =>
            Deep.Protocol.ContactV1.ContactCodec.ArtifactReference(ProtocolMagic.PMT2, value).CanonicalBytes.Span.SequenceEqual(anchorPmtReference.Span)) ??
            throw new CryptographicException("Control descriptor anchor is absent from verified history.");
        return CreateCore(network, selector, pmt);
    }

    /// <summary>Resolves opaque request placement facts without treating the anchor view as current network authority.</summary>
    public static VerifiedGroupControlPlacement CreateForRequest(VerifiedOnionNetworkContext network, Deep.Protocol.GroupV1.GroupRecord request)
    {
        ArgumentNullException.ThrowIfNull(network); network.EnsureCurrent();
        if (request is not (Deep.Protocol.GroupV1.GroupControlWriteRecord or Deep.Protocol.GroupV1.GroupControlQueryRecord) ||
            !request.Field(1).Span.SequenceEqual(network.NetworkId.Span)) throw new CryptographicException("Control request network/type mismatch.");
        return CreateForView(network, request.Field(16), request.Field(3));
    }

    internal static VerifiedGroupControlPlacement CreateForView(VerifiedOnionNetworkContext network, ReadOnlyMemory<byte> selector, ReadOnlyMemory<byte> view)
    {
        network.EnsureCurrent();
        var pmt = network.Closure!.RetainedPmts.SingleOrDefault(value => value.Field(5).Span[6..].SequenceEqual(view.Span)) ??
            throw new CryptographicException("Control placement anchor is absent from verified history.");
        return CreateCore(network, selector, pmt);
    }

    private static VerifiedGroupControlPlacement CreateCore(VerifiedOnionNetworkContext network, ReadOnlyMemory<byte> selector, Deep.Protocol.ContactV1.ContactRecord pmt)
    {
        if (selector.Length != 32 || selector.Span.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("Nonzero opaque selector required.");
        var closure = network.Closure!;
        if (pmt.Field(7).Span[0] != 2) throw new CryptographicException("Control anchor requires exactly two replicas.");
        var pmtReference = Deep.Protocol.ContactV1.ContactCodec.ArtifactReference(ProtocolMagic.PMT2, pmt).CanonicalBytes.ToArray();
        var epoch = BinaryPrimitives.ReadUInt64BigEndian(pmt.Field(6).Span);
        var input = XPointNetworkCrypto.Sha256Domain("Deep/Group/V1/control-placement-input", Join(closure.NetworkId, selector.ToArray()));
        var rows = pmt.Field(9).ToArray();
        var ranked = Enumerable.Range(0, rows.Length / 136).Select(i => rows.AsSpan(i * 136, 32).ToArray())
            .Select(id => (Id: id, Rank: SHA256.HashData(Join(RankDomain, [0], closure.NetworkId, pmtReference, U64(epoch), input, id))))
            .OrderBy(row => Convert.ToHexString(row.Rank), StringComparer.Ordinal)
            .ThenBy(row => Convert.ToHexString(row.Id), StringComparer.Ordinal).Take(2).Select(row => row.Id).ToArray();
        if (ranked.Length != 2 || ranked[0].AsSpan().SequenceEqual(ranked[1])) throw new CryptographicException("Control replica cohort is incomplete.");
        foreach (var id in ranked)
        {
            if (!closure.PmtNodeIds.Any(current => current.AsSpan().SequenceEqual(id)))
                throw new CryptographicException("A pinned control replica is no longer currently admitted; handover required.");
            _ = network.ResolveNodeIdentityPublicKey(id);
        }
        var hash = XPointNetworkCrypto.Sha256Domain("Deep/Group/V1/control-placement", Join(closure.NetworkId,
            pmt.Field(5).ToArray(), pmtReference, U64(epoch), selector.ToArray(), ranked[0], ranked[1]));
        network.EnsureCurrent(); return new(network, selector.ToArray(), hash, ranked, pmt.Field(5).Span[6..].ToArray());
    }
}

public static partial class OnionPathContextFactory
{
    /// <summary>Builds only a diverse three-hop path terminating at an actual selected control replica.</summary>
    public static VerifiedOnionPathContext CreateGroupControl(VerifiedGroupControlPlacement placement,
        ReadOnlyMemory<byte> ingressNodeId, ReadOnlyMemory<byte> coreNodeId, ReadOnlyMemory<byte> exitNodeId)
    {
        ArgumentNullException.ThrowIfNull(placement); var network = placement.Network; network.EnsureCurrent();
        if (!GroupControlPlacementVerifier.CreateForView(network, placement.Selector, placement.ViewHash).PlacementHash.Span.SequenceEqual(placement.PlacementHash.Span))
            throw new CryptographicException("Historical placement facts grant no current dispatch permission.");
        if (!placement.ReplicaIds.Any(id => id.Span.SequenceEqual(exitNodeId.Span))) throw new CryptographicException("Control exit is not a selected replica.");
        var time = network.TrustedTime ?? throw new CryptographicException("Current trusted time required."); time.EnsureLive();
        var nodes = new[] { network.ResolveNode(ingressNodeId.Span), network.ResolveNode(coreNodeId.Span), network.ResolveNode(exitNodeId.Span) };
        RequireRole(nodes[0], 0, "Ingress"); RequireRole(nodes[1], 1, "Core"); RequireRole(nodes[2], 2, "Exit"); RequireRole(nodes[2], 3, "Control");
        RequireExactPathDiversity(nodes);
        return new(network, time, OnionOperation.GroupControl, [Hop(nodes[0], PrivacyRoutingKeyRole.Relay), Hop(nodes[1], PrivacyRoutingKeyRole.Relay), Hop(nodes[2], PrivacyRoutingKeyRole.Exit)]);
    }
}
