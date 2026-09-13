using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

public enum ContactServiceRequestKind : byte
{
    PublishInvite = 1,
    ResolveInvite = 2,
    ClaimPreKey = 3,
    PublishContactUpdate = 4,
    QueryContactUpdate = 5,
    PublishPreKeyInventory = 6,
}

public enum ContactServiceClass : byte
{
    InviteResolver = 1,
    PreKeyClaim = 2,
    ContactUpdate = 3,
}

public sealed class VerifiedContactServicePlacement
{
    private readonly byte[] _viewHash;
    private readonly byte[] _placementHash;
    private readonly byte[] _shardKey;
    private readonly byte[][] _rankedReplicaNodeIds;

    internal VerifiedContactServicePlacement(
        VerifiedOnionNetworkContext network,
        ContactServiceRequestKind requestKind,
        ContactServiceClass serviceClass,
        ReadOnlySpan<byte> viewHash,
        ReadOnlySpan<byte> placementHash,
        ReadOnlySpan<byte> shardKey,
        ulong selectionEpoch,
        ulong validUntilUnixSeconds,
        IEnumerable<byte[]> rankedReplicaNodeIds)
    {
        Network = network;
        RequestKind = requestKind;
        ServiceClass = serviceClass;
        _viewHash = viewHash.ToArray();
        _placementHash = placementHash.ToArray();
        _shardKey = shardKey.ToArray();
        SelectionEpoch = selectionEpoch;
        ValidUntilUnixSeconds = validUntilUnixSeconds;
        _rankedReplicaNodeIds = rankedReplicaNodeIds.Select(static value => value.ToArray()).ToArray();
    }

    public VerifiedOnionNetworkContext Network { get; }
    public ContactServiceRequestKind RequestKind { get; }
    public ContactServiceClass ServiceClass { get; }
    public ReadOnlyMemory<byte> ViewHash => _viewHash.ToArray();
    public ReadOnlyMemory<byte> PlacementHash => _placementHash.ToArray();
    public ulong SelectionEpoch { get; }
    public ulong ValidUntilUnixSeconds { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> RankedReplicaNodeIds =>
        Array.AsReadOnly(_rankedReplicaNodeIds.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());

    public bool Binds(ContactServiceRequestKind requestKind, ReadOnlyMemory<byte> shardKey) =>
        requestKind == RequestKind && shardKey.Length == 32 &&
        CryptographicOperations.FixedTimeEquals(_shardKey, shardKey.Span);

    internal bool ContainsReplica(ReadOnlySpan<byte> nodeId)
    {
        foreach (var value in _rankedReplicaNodeIds)
            if (CryptographicOperations.FixedTimeEquals(value, nodeId)) return true;
        return false;
    }

    internal VerifiedNetworkNode[] ResolveSelectedReplicas() =>
        _rankedReplicaNodeIds.Select(nodeId => Network.ResolveNode(nodeId)).ToArray();
}

public static class ContactServicePlacementFactory
{
    public static VerifiedContactServicePlacement Create(
        VerifiedOnionNetworkContext network,
        ContactServiceRequestKind requestKind,
        ReadOnlyMemory<byte> shardKey)
    {
        ArgumentNullException.ThrowIfNull(network);
        var closure = network.Closure ?? throw new OnionBoundaryException(
            "network-context-incomplete", "Contact placement requires a complete NETCODEC-minted network context.");
        network.TrustedTime?.EnsureLive();
        if (shardKey.Length != 32 || shardKey.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new OnionBoundaryException("service-shard-invalid", "The Contact Resolver shard key must be nonzero 32 bytes.");

        var serviceClass = requestKind switch
        {
            ContactServiceRequestKind.PublishInvite or ContactServiceRequestKind.ResolveInvite => ContactServiceClass.InviteResolver,
            ContactServiceRequestKind.ClaimPreKey or ContactServiceRequestKind.PublishPreKeyInventory => ContactServiceClass.PreKeyClaim,
            ContactServiceRequestKind.PublishContactUpdate or ContactServiceRequestKind.QueryContactUpdate => ContactServiceClass.ContactUpdate,
            _ => throw new OnionBoundaryException("service-class-invalid", "The Contact Resolver request kind is unknown."),
        };

        var placementInputPayload = Join(closure.NetworkId, [(byte)serviceClass], shardKey.ToArray());
        var placementInput = XPointNetworkCrypto.Sha256Domain(
            "Deep/ContactResolver/V1/service-placement-input", placementInputPayload);
        var ranked = closure.PmtNodeIds
            .Select(nodeId => (NodeId: nodeId, Rank: Rank(closure.NetworkId, closure.SelectionEpoch, placementInput, nodeId)))
            .OrderBy(static value => value.Rank, ByteArrayComparer.Instance)
            .ThenBy(static value => value.NodeId, ByteArrayComparer.Instance)
            .Take(closure.ReplicaCount)
            .Select(static value => value.NodeId.ToArray())
            .ToArray();
        var placementPayload = Join(
            closure.NetworkId,
            closure.ViewCoreReference,
            closure.PmtArtifactReference,
            U64(closure.SelectionEpoch),
            [(byte)serviceClass],
            shardKey.ToArray(),
            placementInput,
            [closure.ReplicaCount],
            Join(ranked));
        var placementHash = XPointNetworkCrypto.Sha256Domain(
            "Deep/ContactResolver/V1/service-placement", placementPayload);
        return new VerifiedContactServicePlacement(
            network, requestKind, serviceClass, closure.ViewCoreHash, placementHash,
            shardKey.Span, closure.SelectionEpoch, closure.HardUpperUnixSeconds, ranked);
    }

    private static byte[] Rank(
        ReadOnlySpan<byte> networkId,
        ulong selectionEpoch,
        ReadOnlySpan<byte> placementInput,
        ReadOnlySpan<byte> nodeId)
    {
        var label = Encoding.ASCII.GetBytes("Deep/ContactResolver/V1/service-rendezvous-sha256/v1");
        var input = new byte[label.Length + 1 + 16 + 8 + 32 + 32];
        var offset = 0;
        label.CopyTo(input, offset); offset += label.Length;
        input[offset++] = 0;
        networkId.CopyTo(input.AsSpan(offset)); offset += 16;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset), selectionEpoch); offset += 8;
        placementInput.CopyTo(input.AsSpan(offset)); offset += 32;
        nodeId.CopyTo(input.AsSpan(offset));
        return SHA256.HashData(input);
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static byte[] Join(params byte[][] values)
    {
        var total = values.Aggregate(0, static (sum, value) => checked(sum + value.Length));
        var output = new byte[total];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }
        return output;
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}

internal sealed class VerifiedOnionNetworkClosure
{
    internal required byte[] NetworkId { get; init; }
    internal required Xvp1Record Policy { get; init; }
    internal required Xnv1Record View { get; init; }
    internal required Xnh1Record Head { get; init; }
    internal required ContactRecord Pmt { get; init; }
    internal required byte[] ViewCoreHash { get; init; }
    internal required byte[] ViewCoreReference { get; init; }
    internal required byte[] PmtArtifactReference { get; init; }
    internal required byte[][] PmtNodeIds { get; init; }
    internal required ulong SelectionEpoch { get; init; }
    internal required byte ReplicaCount { get; init; }
    internal required ulong HardUpperUnixSeconds { get; init; }
    internal required byte[] Adh1CoreReference { get; init; }
    internal required byte[] Dtt1CoreHash { get; init; }
    internal required byte[] FreshnessBootId { get; init; }
    internal required ulong TrustedLowerUnixSeconds { get; init; }
    internal required ulong TrustedUpperUnixSeconds { get; init; }
    internal required ulong FreshnessMonotonicSample { get; init; }
    internal required ulong FreshnessDeadlineMonotonicSeconds { get; init; }
}

internal static class XPointOnionCapabilityProducer
{
    private const int MaximumSuccessorChainLength = 4_096;
    private const int MaximumSuccessorChainBytes = 64 * 1024 * 1024;

    internal static async ValueTask<VerifiedOnionNetworkContext> VerifyAsync(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness freshness,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXvp1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnv1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnh1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactActiveXnd1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedPmt2Chain,
        VerifiedOnionNetworkContext? protectedPrevious,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken,
        VerifiedXPointNetworkForwardCheckpoint? forwardCheckpoint = null)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(freshness);
        ArgumentNullException.ThrowIfNull(exactOrderedXvp1Chain);
        ArgumentNullException.ThrowIfNull(exactOrderedXnv1Chain);
        ArgumentNullException.ThrowIfNull(exactOrderedXnh1Chain);
        ArgumentNullException.ThrowIfNull(exactActiveXnd1);
        ArgumentNullException.ThrowIfNull(exactOrderedPmt2Chain);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        cancellationToken.ThrowIfCancellationRequested();
        forwardCheckpoint?.EnsureUsable(authority, freshness);

        var xvpBytes = OwnChain(exactOrderedXvp1Chain, ProtocolMagic.XVP1);
        var xnvBytes = OwnChain(exactOrderedXnv1Chain, ProtocolMagic.XNV1);
        var xnhBytes = OwnChain(exactOrderedXnh1Chain, ProtocolMagic.XNH1);
        var pmtBytes = OwnChain(exactOrderedPmt2Chain, ProtocolMagic.PMT2);
        if (xnvBytes.Length != xnhBytes.Length)
            Fail("network-chain-invalid", "The ordered XNV1 and XNH1 successor chains must contain exact corresponding pairs.");
        if (forwardCheckpoint is not null &&
            (protectedPrevious is not null || xvpBytes.Length != 1 || xnvBytes.Length != 1 ||
             xnhBytes.Length != 1 || pmtBytes.Length != 1 ||
             !Fixed(xnvBytes[0], forwardCheckpoint.ExactTargetXnv1.Span) ||
             !Fixed(xnhBytes[0], forwardCheckpoint.ExactTargetXnh1.Span)))
            Fail("forward-capability-mismatch",
                "A reset composition requires exactly the XNV1/XNH1 target and one terminal XVP1/PMT2 snapshot.");
        var nodeBytes = exactActiveXnd1.Select(value => Own(value, ProtocolMagic.XND1)).ToArray();
        var totalBytes = xvpBytes.Sum(static value => (long)value.Length) +
            xnvBytes.Sum(static value => (long)value.Length) + xnhBytes.Sum(static value => (long)value.Length) +
            pmtBytes.Sum(static value => (long)value.Length) + nodeBytes.Sum(static value => (long)value.Length);
        if (totalBytes > MaximumSuccessorChainBytes)
            Fail("network-chain-too-large", "The exact successor closure exceeds the bounded verification budget.");
        try
        {
            var policies = xvpBytes.Select(static value => XPointNetworkCodec.Parse<Xvp1Record>(value)).ToArray();
            var views = xnvBytes.Select(static value => XPointNetworkCodec.Parse<Xnv1Record>(value)).ToArray();
            var heads = xnhBytes.Select(static value => XPointNetworkCodec.Parse<Xnh1Record>(value)).ToArray();
            var pmts = pmtBytes.Select(static value => ContactCodec.Decode(ProtocolMagic.PMT2, value)).ToArray();
            var nodes = nodeBytes.Select(static value => XPointNetworkCodec.Parse<Xnd1Record>(value)).ToArray();
            var dtt = AccountDirectoryDtt1Codec.Decode(freshness.ExactDtt1.Span);
            var previous = protectedPrevious?.Closure;
            if (protectedPrevious is not null && previous is null)
                Fail("network-lkg-invalid", "The protected predecessor was not minted by the complete NETCODEC verifier.");

            Xvp1Record? policyCursor = previous?.Policy;
            for (var index = 0; index < policies.Length; index++)
            {
                var policy = policies[index];
                VerifyPolicyBinding(authority, policy);
                if (forwardCheckpoint is null)
                    VerifyOrderedLineage(policyCursor, policy, "policy", policies.Length == 1 && index == 0);
                VerifyPolicy(authority, policy);
                policyCursor = policy;
            }

            Xvp1Record[] knownPolicies = previous is null ? policies : [previous.Policy, .. policies];
            Xnv1Record? viewCursor = previous?.View;
            Xnh1Record? headCursor = previous?.Head;
            for (var index = 0; index < views.Length; index++)
            {
                var view = views[index];
                var head = heads[index];
                var activePolicy = FindPolicy(knownPolicies, view.ActivePolicy.Hash.Span);
                VerifyViewAndHeadBinding(authority, activePolicy, view, head);
                if (forwardCheckpoint is null)
                {
                    VerifyOrderedLineage(viewCursor, view, "view", views.Length == 1 && index == 0);
                    VerifyOrderedLineage(headCursor, head, "head", heads.Length == 1 && index == 0);
                }
                VerifyThreshold(view.WitnessSignatures, authority, XPointNetworkCrypto.ComputeSigningInput(view), "view-threshold-invalid");
                VerifyThreshold(head.WitnessSignatures, authority, XPointNetworkCrypto.ComputeSigningInput(head), "head-threshold-invalid");
                if (forwardCheckpoint is null) VerifyHead(view, head, viewCursor, headCursor);
                viewCursor = view;
                headCursor = head;
            }

            Xnv1Record[] knownViews = previous is null ? views : [previous.View, .. views];
            ContactRecord? pmtCursor = previous?.Pmt;
            for (var index = 0; index < pmts.Length; index++)
            {
                var candidate = pmts[index];
                var candidateView = FindView(knownViews, candidate.FieldSpan(5));
                var candidatePolicy = FindPolicy(knownPolicies, candidateView.ActivePolicy.Hash.Span);
                VerifyPmtAuthenticated(authority, candidatePolicy, candidateView, candidate, pmtCursor,
                    pmts.Length == 1 && index == 0, forwardCheckpoint is not null);
                pmtCursor = candidate;
            }

            var xvp = policies[^1];
            var xnv = views[^1];
            var xnh = heads[^1];
            var pmt = pmts[^1];
            VerifyCommonBindings(authority, freshness, dtt, xvp, xnv, xnh);
            VerifyDtt(authority, freshness, dtt, xnv);
            if (!pmt.FieldSpan(5).SequenceEqual(XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, xnv.CoreHash.Span)) ||
                BinaryPrimitives.ReadUInt64BigEndian(pmt.FieldSpan(2)) != xvp.UInt64(12))
                Fail("pmt-binding-invalid", "The terminal PMT2 does not bind the DTT1-authenticated terminal view and policy.");

            var verifiedNodes = VerifyNodes(authority, freshness, xvp, xnv, pmt, nodes, out var hardUpper);
            VerifyCurrentPmt(freshness, pmt, nodes);
            hardUpper = Math.Min(hardUpper, BinaryPrimitives.ReadUInt64BigEndian(pmt.FieldSpan(12)));
            var trustedTime = await trustedTimeAuthority.MintAsync(freshness, hardUpper, cancellationToken).ConfigureAwait(false);
            var viewReference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, xnv.CoreHash.Span);
            var pmtReference = ArtifactReference(ProtocolMagic.PMT2, pmt.ArtifactHash.Span);
            var pmtNodeIds = Rows(pmt.FieldSpan(9), 136).Select(static row => row[..32].ToArray()).ToArray();
            var priorLkg = forwardCheckpoint?.PriorProtectedLkg
                ?? protectedPrevious?.ProtectedLkg;
            var nextLkg = forwardCheckpoint?.NextProtectedLkg
                ?? new XPointNetworkProtectedLkg(
                    authority.NetworkId,
                    XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNH1, xnh.CoreHash.Span),
                    xnh.TreeSize,
                    xnh.Root.ToArray(),
                    viewReference,
                    xnv.ViewGeneration,
                    authority.AuthorityCoreReference,
                    priorLkg?.LastForwardCheckpointCoreReference ?? default,
                    priorLkg?.LastForwardCheckpointGeneration);
            var closure = new VerifiedOnionNetworkClosure
            {
                NetworkId = authority.NetworkId.ToArray(),
                Policy = xvp,
                View = xnv,
                Head = xnh,
                Pmt = pmt,
                ViewCoreHash = xnv.CoreHash.ToArray(),
                ViewCoreReference = viewReference,
                PmtArtifactReference = pmtReference,
                PmtNodeIds = pmtNodeIds,
                SelectionEpoch = BinaryPrimitives.ReadUInt64BigEndian(pmt.FieldSpan(6)),
                ReplicaCount = pmt.FieldSpan(7)[0],
                HardUpperUnixSeconds = hardUpper,
                Adh1CoreReference = freshness.ExactAdh1CoreReference.ToArray(),
                Dtt1CoreHash = freshness.ExactDtt1CoreHash.ToArray(),
                FreshnessBootId = freshness.BootId.ToArray(),
                TrustedLowerUnixSeconds = freshness.TrustedLowerUnixSeconds,
                TrustedUpperUnixSeconds = freshness.TrustedUpperUnixSeconds,
                FreshnessMonotonicSample = freshness.MonotonicSample,
                FreshnessDeadlineMonotonicSeconds = freshness.FreshnessDeadlineMonotonicSeconds,
            };
            return new VerifiedOnionNetworkContext(
                authority.NetworkId.Span,
                trustedTime,
                verifiedNodes,
                closure,
                nextLkg,
                priorLkg);
        }
        catch (OnionBoundaryException) { throw; }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is FormatException or ArgumentException or CryptographicException or OverflowException)
        {
            throw new OnionBoundaryException(
                "network-closure-invalid",
                "The exact XNA1/XVP1/XNV1/XNH1/XND1/PMT2/DTT1 closure is invalid.",
                exception);
        }
    }

    private static void VerifyPolicyBinding(
        VerifiedXPointNetworkAuthority authority,
        Xvp1Record policy)
    {
        if (!Fixed(authority.NetworkId.Span, policy.NetworkId.Span) ||
            !Fixed(authority.AuthorityCoreReference.Span, policy.FieldSpan(18)))
            Fail("network-binding-invalid", "An XVP1 successor is outside the pinned XPoint authority.");
    }

    private static void VerifyViewAndHeadBinding(
        VerifiedXPointNetworkAuthority authority,
        Xvp1Record policy,
        Xnv1Record view,
        Xnh1Record head)
    {
        if (!Fixed(authority.NetworkId.Span, view.NetworkId.Span) ||
            !Fixed(authority.NetworkId.Span, head.NetworkId.Span) ||
            !Fixed(authority.AuthorityCoreReference.Span, view.FieldSpan(7)) ||
            !Fixed(authority.AuthorityCoreReference.Span, head.FieldSpan(8)) ||
            !Fixed(authority.DirectoryWitnessPolicyHash.Span, view.FieldSpan(8)) ||
            !Fixed(authority.DirectoryWitnessPolicyHash.Span, head.FieldSpan(9)) ||
            view.ActivePolicy.Magic != ProtocolMagic.XVP1 || !Fixed(policy.CoreHash.Span, view.ActivePolicy.Hash.Span) ||
            !head.LatestView.Equals(view.CoreReferenceValue) || head.LatestViewGeneration != view.ViewGeneration)
            Fail("network-binding-invalid", "An ordered XNV1/XNH1 pair does not bind one verified policy and authority.");
    }

    private static Xvp1Record FindPolicy(IEnumerable<Xvp1Record> policies, ReadOnlySpan<byte> coreHash)
    {
        foreach (var policy in policies)
            if (Fixed(policy.CoreHash.Span, coreHash)) return policy;
        Fail("network-chain-incomplete", "The successor chain omits an XVP1 referenced by an XNV1.");
        return null!;
    }

    private static Xnv1Record FindView(IEnumerable<Xnv1Record> views, ReadOnlySpan<byte> coreReference)
    {
        foreach (var view in views)
            if (Fixed(XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, view.CoreHash.Span), coreReference)) return view;
        Fail("network-chain-incomplete", "The successor chain omits an XNV1 referenced by a PMT2.");
        return null!;
    }

    private static void VerifyCommonBindings(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness freshness,
        AccountDirectoryDtt1 dtt,
        Xvp1Record xvp,
        Xnv1Record xnv,
        Xnh1Record xnh)
    {
        if (!Fixed(authority.NetworkId.Span, freshness.NetworkId.Span) ||
            !Fixed(authority.NetworkId.Span, dtt.NetworkId.Span) ||
            !Fixed(authority.NetworkId.Span, xvp.NetworkId.Span) ||
            !Fixed(authority.NetworkId.Span, xnv.NetworkId.Span) ||
            !Fixed(authority.NetworkId.Span, xnh.NetworkId.Span) ||
            !Fixed(authority.AuthorityCoreReference.Span, xvp.FieldSpan(18)) ||
            !Fixed(authority.AuthorityCoreReference.Span, xnv.FieldSpan(7)) ||
            !Fixed(authority.AuthorityCoreReference.Span, xnh.FieldSpan(8)) ||
            !Fixed(authority.DirectoryWitnessPolicyHash.Span, xnv.FieldSpan(8)) ||
            !Fixed(authority.DirectoryWitnessPolicyHash.Span, xnh.FieldSpan(9)) ||
            xnv.ActivePolicy.Magic != ProtocolMagic.XVP1 || !Fixed(xvp.CoreHash.Span, xnv.ActivePolicy.Hash.Span) ||
            !xnh.LatestView.Equals(xnv.CoreReferenceValue) || xnh.LatestViewGeneration != xnv.ViewGeneration)
            Fail("network-binding-invalid", "The authority, policy, view and transparency head do not form one exact closure.");

        var low = freshness.TrustedLowerUnixSeconds;
        var high = freshness.TrustedUpperUnixSeconds;
        if (low > high || authority.NotBefore > low || high >= authority.ExpiresAt ||
            xvp.NotBefore > low || high >= xvp.ExpiresAt || xnv.NotBefore > low || high >= xnv.ExpiresAt ||
            xnh.ValidFrom > low || high >= xnh.ValidUntil)
            Fail("network-time-invalid", "The complete trusted interval is outside an exact network artifact interval.");
    }

    private static void VerifyPolicy(VerifiedXPointNetworkAuthority authority, Xvp1Record policy)
    {
        VerifyRootThreshold(policy.Signatures, authority, XPointNetworkCrypto.ComputeSigningInput(policy));
        if (policy.UInt8(5) != OnionLimits.RouteHopCount || (policy.UInt16(7) & 0x000f) != 0x000f)
            Fail("network-policy-invalid", "The active policy does not require the exact V1 route constraints.");
    }

    private static void VerifyDtt(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness freshness,
        AccountDirectoryDtt1 dtt,
        Xnv1Record view)
    {
        if (!Fixed(dtt.AuthorizingXna1CoreReference.Span, authority.AuthorityCoreReference.Span) ||
            !Fixed(dtt.WitnessPolicyHash.Span, authority.DirectoryWitnessPolicyHash.Span) ||
            !Fixed(dtt.CurrentXnv1CoreHash.Span, view.CoreHash.Span) ||
            dtt.CurrentXnv1Generation != view.ViewGeneration ||
            dtt.UncertaintySeconds > authority.MaximumWitnessUncertaintySeconds ||
            !Fixed(AccountDirectoryDtt1Codec.Encode(dtt), freshness.ExactDtt1.Span))
            Fail("dtt-binding-invalid", "The nonce-bound DTT1 does not authenticate the exact current network view.");
        VerifyDttThreshold(dtt.Witnesses, authority, AccountDirectoryCrypto.ComputeDtt1SigningInput(dtt));
    }

    private static VerifiedNetworkNode[] VerifyNodes(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness freshness,
        Xvp1Record policy,
        Xnv1Record view,
        ContactRecord pmt,
        IReadOnlyList<Xnd1Record> nodes,
        out ulong hardUpper)
    {
        var refs = Rows(view.FieldSpan(12), 38)
            .Select(static value => XPointNetworkCodec.DecodeArtifactReference(value))
            .ToArray();
        if (refs.Length != nodes.Count)
            Fail("network-view-incomplete", "Every current XND1 artifact must be supplied exactly once.");
        var revoked = Rows(view.FieldSpan(14), 32).Select(Convert.ToHexString).ToHashSet(StringComparer.Ordinal);
        var pmtRows = Rows(pmt.FieldSpan(9), 136).ToDictionary(static row => Convert.ToHexString(row[..32]), StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var output = new List<VerifiedNetworkNode>(nodes.Count);
        ushort aggregateRoles = 0;
        hardUpper = new[] { authority.ExpiresAt, policy.ExpiresAt, view.ExpiresAt, freshness.ExpiresAtUnixSeconds }.Min();
        foreach (var node in nodes)
        {
            var nodeId = Convert.ToHexString(node.NodeId.Span);
            var artifactHash = XPointNetworkCrypto.ComputeArtifactHash(node);
            if (!seen.Add(nodeId) || revoked.Contains(nodeId) || !Fixed(node.NetworkId.Span, authority.NetworkId.Span) ||
                !refs.Any(reference => reference.Magic == ProtocolMagic.XND1 && Fixed(reference.Hash.Span, artifactHash)))
                Fail("network-node-invalid", "An XND1 is duplicated, revoked, cross-network or not committed by XNV1.");
            if (!VerifyEd25519(node.IdentityPublicKey.Span, XPointNetworkCrypto.ComputeSigningInput(node), node.Signature.Span))
                Fail("network-node-signature-invalid", "An XND1 self-signature is invalid.");
            if (node.NotBefore > view.NotBefore || view.ExpiresAt > node.ExpiresAt ||
                !Covers(node.UInt64(23), node.UInt64(24), node.UInt64(27), node.UInt64(28), view.NotBefore, view.ExpiresAt) ||
                !node.Origins.Any(origin => Covers(origin.CurrentNotBefore, origin.CurrentExpiresAt,
                    origin.NextNotBefore, origin.NextExpiresAt, view.NotBefore, view.ExpiresAt)))
                Fail("network-node-time-invalid", "An XND1 descriptor, onion key or origin does not cover the complete XNV1 interval.");

            var (epoch, onionKey, onionUntil) = SelectOnionKey(node, freshness.TrustedLowerUnixSeconds, freshness.TrustedUpperUnixSeconds);
            XPointPeerOriginEntry origin;
            if (pmtRows.TryGetValue(nodeId, out var pmtRow))
            {
                origin = node.Origins.SingleOrDefault(value => value.Id.Span.SequenceEqual(pmtRow.AsSpan(40, 32))) ??
                    throw new OnionBoundaryException("pmt-node-projection-invalid", "The PMT2 origin is absent from its exact XND1 descriptor.");
            }
            else
            {
                origin = node.Origins.First(value =>
                    CoversEither(value.CurrentNotBefore, value.CurrentExpiresAt, value.NextNotBefore, value.NextExpiresAt,
                        freshness.TrustedLowerUnixSeconds, freshness.TrustedUpperUnixSeconds));
            }
            var (originSpki, originUntil) = SelectOriginSpki(origin, freshness.TrustedLowerUnixSeconds, freshness.TrustedUpperUnixSeconds);
            var epochBytes = U64(epoch);
            var keyId = XPointNetworkCrypto.Sha256Domain(
                "Deep/XPoint/V1/onion-key-id", Join(node.NodeId.ToArray(), epochBytes, onionKey));
            aggregateRoles |= node.RoleMask;
            hardUpper = Math.Min(hardUpper, Math.Min(node.ExpiresAt, Math.Min(onionUntil, originUntil)));
            output.Add(new VerifiedNetworkNode(
                node.NodeId.ToArray(), node.NodeId.ToArray(), node.FieldSpan(8).ToArray(), node.FailureDomainHash.ToArray(),
                origin.Id.ToArray(), origin.Transport, origin.AddressFamily, origin.Address.ToArray(), origin.Port,
                originSpki, node.RoleMask, node.UInt32(14), node.UInt64(15), node.UInt64(16),
                epoch, keyId, onionKey, node.IdentityPublicKey.ToArray()));
        }
        if (aggregateRoles != policy.EnabledRoleMask)
            Fail("network-role-projection-invalid", "The current XND1 roster does not exactly project every active XVP1 role.");
        return output.ToArray();
    }

    private static void VerifyPmtAuthenticated(
        VerifiedXPointNetworkAuthority authority,
        Xvp1Record policy,
        Xnv1Record view,
        ContactRecord pmt,
        ContactRecord? previous,
        bool allowUnchanged,
        bool allowForwardReset = false)
    {
        if (!pmt.FieldSpan(1).SequenceEqual(authority.NetworkId.Span) ||
            !pmt.FieldSpan(5).SequenceEqual(XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, view.CoreHash.Span)) ||
            BinaryPrimitives.ReadUInt64BigEndian(pmt.FieldSpan(2)) != policy.UInt64(12) ||
            pmt.FieldSpan(7)[0] != policy.MailboxReplicaCount)
            Fail("pmt-binding-invalid", "A PMT2 successor is not the exact projection required by its verified XVP1/XNV1 pair.");
        VerifyContactThreshold(pmt, authority);
        if (!allowForwardReset) VerifyOrderedPmtLineage(previous, pmt, allowUnchanged);
    }

    private static void VerifyCurrentPmt(
        VerifiedAccountDirectoryFreshness freshness,
        ContactRecord pmt,
        IReadOnlyList<Xnd1Record> nodes)
    {
        // PMT2 tag 14 is the signed directory-head audit anchor from issuance,
        // not a pin to the independently advancing current ADH1.
        if (BinaryPrimitives.ReadUInt64BigEndian(pmt.FieldSpan(11)) > freshness.TrustedLowerUnixSeconds ||
            freshness.TrustedUpperUnixSeconds >= BinaryPrimitives.ReadUInt64BigEndian(pmt.FieldSpan(12)))
            Fail("pmt-binding-invalid", "The terminal PMT2 does not cover the authenticated directory freshness interval.");

        var mailboxNodes = nodes.Where(static node => (node.RoleMask & (1 << 2)) != 0)
            .OrderBy(static node => node.NodeId.ToArray(), ByteArrayComparer.Instance).ToArray();
        var rows = Rows(pmt.FieldSpan(9), 136).ToArray();
        if (rows.Length != mailboxNodes.Length)
            Fail("pmt-projection-incomplete", "PMT2 must contain every and only current Mailbox-role XND1 node.");
        for (var index = 0; index < rows.Length; index++)
        {
            var row = rows[index];
            var node = mailboxNodes[index];
            var origin = node.Origins.SingleOrDefault(value => value.Id.Span.SequenceEqual(row[40..72]));
            if (!row[..32].SequenceEqual(node.NodeId.Span) ||
                BinaryPrimitives.ReadUInt64BigEndian(row[32..40]) != node.UInt64(16) ||
                origin is null || !row[72..104].SequenceEqual(origin.CurrentSpki.Span) ||
                !row[104..136].SequenceEqual(origin.NextSpki.Span))
                Fail("pmt-node-projection-invalid", "A PMT2 node row does not exactly project its XND1 mailbox capacity and origin.");
        }
    }

    private static void VerifyHead(Xnv1Record view, Xnh1Record head, Xnv1Record? priorView, Xnh1Record? priorHead)
    {
        var leaf = ViewLeaf(view);
        if (priorHead is null)
        {
            if (view.ViewGeneration != 0 || head.LogGeneration != 0 || head.TreeSize != 1 ||
                !head.Root.Span.SequenceEqual(leaf))
                Fail("network-genesis-required", "Without a protected predecessor, only the exact generation-zero XNV1/XNH1 pair is admissible.");
            return;
        }
        if (head.CoreHash.Equals(priorHead.CoreHash))
        {
            if (priorView is null || !view.CoreHash.Equals(priorView.CoreHash))
                Fail("network-fork", "An unchanged XNH1 head cannot authenticate a changed XNV1 core.");
            return;
        }
        if (priorView is null || priorHead.TreeSize == ulong.MaxValue || priorHead.LatestViewGeneration == ulong.MaxValue ||
            head.TreeSize != priorHead.TreeSize + 1 || head.LatestViewGeneration != priorHead.LatestViewGeneration + 1 ||
            !view.FieldSpan(3).SequenceEqual(priorView.CoreHash.Span) || !ContainsRow(head.FieldSpan(14), leaf))
            Fail("network-fork", "The XNV1/XNH1 pair is not the exact append-only successor of protected LKG.");
        XPointMerkleProofs.VerifyConsistency(
            priorHead.TreeSize, head.TreeSize, priorHead.Root.Span, head.Root.Span,
            head.FieldSpan(14), head.UInt8(13));
    }

    private static void VerifyLineage(XPointParsedRecord? previous, XPointParsedRecord current, string name)
    {
        if (previous is null)
        {
            if (current.Generation != 0 || current.FieldSpan(current.Definition.PredecessorHashTag).IndexOfAnyExcept((byte)0) >= 0)
                Fail("network-genesis-required", $"The first verified {name} must be generation zero.");
            return;
        }
        if (current.Generation == previous.Generation && current.CoreHash.Equals(previous.CoreHash)) return;
        if (current.Generation <= previous.Generation)
            Fail("network-stale-or-fork", $"The candidate {name} is stale or forks protected LKG.");
        try { XPointNetworkVerifier.RequireSuccessor(previous, current); }
        catch (XPointValidationException exception) { throw new OnionBoundaryException("network-stale-or-fork", exception.Message, exception); }
    }

    private static void VerifyOrderedLineage(
        XPointParsedRecord? previous,
        XPointParsedRecord current,
        string name,
        bool allowUnchanged)
    {
        if (previous is not null && current.Generation == previous.Generation && current.CoreHash.Equals(previous.CoreHash))
        {
            if (allowUnchanged) return;
            Fail("network-chain-invalid", $"The ordered {name} chain contains a duplicate element.");
        }
        VerifyLineage(previous, current, name);
    }

    private static void VerifyPmtLineage(ContactRecord? previous, ContactRecord current)
    {
        var generation = BinaryPrimitives.ReadUInt64BigEndian(current.FieldSpan(2));
        if (previous is null)
        {
            if (generation != 0 || current.FieldSpan(3).IndexOfAnyExcept((byte)0) >= 0)
                Fail("pmt-genesis-required", "The first verified PMT2 must be generation zero.");
            return;
        }
        var priorGeneration = BinaryPrimitives.ReadUInt64BigEndian(previous.FieldSpan(2));
        if (generation == priorGeneration && current.CoreHash.Span.SequenceEqual(previous.CoreHash.Span)) return;
        if (priorGeneration == ulong.MaxValue || generation != priorGeneration + 1 ||
            !current.FieldSpan(3).SequenceEqual(previous.CoreHash.Span) ||
            previous.FieldSpan(13).IndexOfAnyExcept((byte)0) >= 0 && !previous.FieldSpan(13).SequenceEqual(current.CoreHash.Span))
            Fail("pmt-stale-or-fork", "PMT2 is not the exact successor of protected projection LKG.");
    }

    private static void VerifyOrderedPmtLineage(ContactRecord? previous, ContactRecord current, bool allowUnchanged)
    {
        if (previous is not null &&
            BinaryPrimitives.ReadUInt64BigEndian(current.FieldSpan(2)) == BinaryPrimitives.ReadUInt64BigEndian(previous.FieldSpan(2)) &&
            current.CoreHash.Span.SequenceEqual(previous.CoreHash.Span))
        {
            if (allowUnchanged) return;
            Fail("network-chain-invalid", "The ordered PMT2 chain contains a duplicate element.");
        }
        VerifyPmtLineage(previous, current);
    }

    private static void VerifyRootThreshold(
        IReadOnlyList<XPointSignatureEntry> signatures,
        VerifiedXPointNetworkAuthority authority,
        ReadOnlySpan<byte> message)
    {
        var keys = authority.RootKeys.ToDictionary(static key => Convert.ToHexString(key.Id.Span), StringComparer.Ordinal);
        var valid = 0;
        foreach (var signature in signatures)
        {
            if (!keys.TryGetValue(Convert.ToHexString(signature.Id.Span), out var key) ||
                !VerifyEd25519(key.Ed25519PublicKey.Span, message, signature.Signature.Span))
                Fail("policy-threshold-invalid", "An XVP1 root receipt is unknown or invalid.");
            valid++;
        }
        if (valid < authority.RootThreshold) Fail("policy-threshold-invalid", "XVP1 does not meet the exact root threshold.");
    }

    private static void VerifyThreshold(
        IReadOnlyList<XPointSignatureEntry> signatures,
        VerifiedXPointNetworkAuthority authority,
        ReadOnlySpan<byte> message,
        string code)
    {
        VerifyWitnessRows(signatures.Select(static value => (value.Id.Span.ToArray(), value.Signature.Span.ToArray())), authority, message, code);
    }

    private static void VerifyDttThreshold(
        IReadOnlyList<AccountDirectoryDtt1WitnessReceipt> signatures,
        VerifiedXPointNetworkAuthority authority,
        ReadOnlySpan<byte> message)
    {
        VerifyWitnessRows(signatures.Select(static value => (value.WitnessId.ToArray(), value.Signature.ToArray())), authority, message, "dtt-threshold-invalid");
    }

    private static void VerifyContactThreshold(ContactRecord record, VerifiedXPointNetworkAuthority authority)
    {
        var rows = Rows(record.FieldSpan(16), 96).Select(static row => (row[..32].ToArray(), row[32..].ToArray()));
        VerifyWitnessRows(rows, authority, record.SignatureInput.Span, "pmt-threshold-invalid");
    }

    private static void VerifyWitnessRows(
        IEnumerable<(byte[] Id, byte[] Signature)> signatures,
        VerifiedXPointNetworkAuthority authority,
        ReadOnlySpan<byte> message,
        string code)
    {
        var keys = authority.WitnessKeys.ToDictionary(static key => Convert.ToHexString(key.Id.Span), StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        var valid = 0;
        foreach (var signature in signatures)
        {
            if (!keys.TryGetValue(Convert.ToHexString(signature.Id), out var key) ||
                !VerifyEd25519(key.Ed25519PublicKey.Span, message, signature.Signature) ||
                !domains.Add(Convert.ToHexString(key.FailureDomainHash.Span)))
                Fail(code, "A witness receipt is unknown, invalid or repeats a physical failure domain.");
            valid++;
        }
        if (valid < authority.WitnessThreshold) Fail(code, "The exact witness threshold is incomplete.");
    }

    private static (ulong Epoch, byte[] Key, ulong Until) SelectOnionKey(Xnd1Record node, ulong low, ulong high)
    {
        if (node.UInt64(23) <= low && high < node.UInt64(24))
            return (node.UInt64(21), node.FieldSpan(22).ToArray(), node.UInt64(24));
        if (node.UInt64(27) <= low && high < node.UInt64(28))
            return (node.UInt64(25), node.FieldSpan(26).ToArray(), node.UInt64(28));
        Fail("network-key-time-invalid", "No one XND1 onion traffic key covers the complete trusted interval.");
        return default;
    }

    private static (byte[] Spki, ulong Until) SelectOriginSpki(XPointPeerOriginEntry origin, ulong low, ulong high)
    {
        if (origin.CurrentNotBefore <= low && high < origin.CurrentExpiresAt)
            return (origin.CurrentSpki.ToArray(), origin.CurrentExpiresAt);
        if (origin.NextNotBefore <= low && high < origin.NextExpiresAt)
            return (origin.NextSpki.ToArray(), origin.NextExpiresAt);
        Fail("network-origin-time-invalid", "No one XND1 origin certificate covers the complete trusted interval.");
        return default;
    }

    private static bool Covers(ulong firstFrom, ulong firstUntil, ulong nextFrom, ulong nextUntil, ulong from, ulong until) =>
        firstFrom <= from && until <= firstUntil ||
        nextFrom <= from && until <= nextUntil ||
        firstFrom <= from && nextFrom <= firstUntil && until <= nextUntil;

    private static bool CoversEither(ulong firstFrom, ulong firstUntil, ulong nextFrom, ulong nextUntil, ulong from, ulong until) =>
        firstFrom <= from && until < firstUntil || nextFrom <= from && until < nextUntil;

    private static byte[] ViewLeaf(Xnv1Record view)
    {
        Span<byte> payload = stackalloc byte[72];
        BinaryPrimitives.WriteUInt64BigEndian(payload, view.ViewGeneration);
        view.FieldSpan(3).CopyTo(payload[8..40]);
        view.CoreHash.Span.CopyTo(payload[40..]);
        return XPointNetworkCrypto.Rfc6962Leaf(payload);
    }

    private static bool ContainsRow(ReadOnlySpan<byte> rows, ReadOnlySpan<byte> expected)
    {
        for (var offset = 0; offset < rows.Length; offset += expected.Length)
            if (rows.Slice(offset, expected.Length).SequenceEqual(expected)) return true;
        return false;
    }

    private static IEnumerable<byte[]> Rows(ReadOnlySpan<byte> source, int width)
    {
        var rows = new List<byte[]>(source.Length / width);
        for (var offset = 0; offset < source.Length; offset += width)
            rows.Add(source.Slice(offset, width).ToArray());
        return rows;
    }

    private static byte[] ArtifactReference(string magic, ReadOnlySpan<byte> hash)
    {
        var result = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }

    private static byte[] Own(ReadOnlyMemory<byte> value, string name)
    {
        if (value.IsEmpty) throw new ArgumentException($"The exact {name} artifact is empty.", name);
        return value.ToArray();
    }

    private static byte[][] OwnChain(IReadOnlyList<ReadOnlyMemory<byte>> values, string name)
    {
        if (values.Count is 0 or > MaximumSuccessorChainLength)
            throw new ArgumentException(
                $"The exact ordered {name} chain must contain 1..{MaximumSuccessorChainLength} artifacts.",
                name);
        return values.Select(value => Own(value, name)).ToArray();
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static byte[] Join(params byte[][] values)
    {
        var output = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values) { value.CopyTo(output, offset); offset += value.Length; }
        return output;
    }

    private static bool VerifyEd25519(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        try { return PublicKeyAuth.VerifyDetached(signature.ToArray(), message.ToArray(), key.ToArray()); }
        catch (Exception) { return false; }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) => throw new OnionBoundaryException(code, message);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
