using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MembershipRoutes;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

public static class ProductionMailboxReplicaSelection
{
    private static ReadOnlySpan<byte> InputDomain => "Deep/PMT1/selection-input/v1"u8;
    private static ReadOnlySpan<byte> ScoreDomain => "Deep/PMT1/rendezvous-sha256/v2"u8;

    /// <summary>The public selection input reveals only a domain-separated commitment, never a raw mailbox identifier.</summary>
    public static byte[] ComputeSelectionInputCommitment(BlindedPlacementId blindedPlacementId)
    {
        ArgumentNullException.ThrowIfNull(blindedPlacementId);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(InputDomain); hash.AppendData(blindedPlacementId.Bytes.Span);
        return hash.GetHashAndReset();
    }

    public static IReadOnlyList<ReadOnlyMemory<byte>> Select(
        ReadOnlySpan<byte> networkId, ProductionMailboxTopologyEpoch epoch,
        ReadOnlySpan<byte> selectionInputCommitment)
    {
        ArgumentNullException.ThrowIfNull(epoch);
        if (networkId.Length != 16 || selectionInputCommitment.Length != 32 ||
            epoch.MembershipCommitment.Length != 32 ||
            epoch.TopologyPlacementCommitment.Length != 32 || epoch.Nodes is null)
            throw Error(ProductionMailboxTopologyError.InvalidField, "Selection inputs are invalid.");

        var network = networkId.ToArray();
        var selectionInput = selectionInputCommitment.ToArray();
        var membership = epoch.MembershipCommitment.ToArray();
        var topologyPlacement = epoch.TopologyPlacementCommitment.ToArray();
        var epochNumber = epoch.Epoch;
        var epochGeneration = epoch.Generation;
        var sourceNodes = epoch.Nodes;
        int nodeCount;
        byte[][] nodes;
        try
        {
            nodeCount = sourceNodes.Count;
            if (nodeCount is < 2 or > ProductionMailboxTopologyConstants.MaximumNodesPerEpoch)
                throw Error(ProductionMailboxTopologyError.InvalidField,
                    "Selection inputs are invalid.");
            nodes = new byte[nodeCount][];
            for (var index = 0; index < nodeCount; index++)
            {
                if (sourceNodes.Count != nodeCount)
                    throw Error(ProductionMailboxTopologyError.InvalidField,
                        "Selection node set changed while being snapshotted.");
                var node = sourceNodes[index];
                if (node is null || node.NodeId.Length != 32)
                    throw Error(ProductionMailboxTopologyError.InvalidField,
                        "Selection node is invalid.");
                nodes[index] = node.NodeId.ToArray();
            }
            if (sourceNodes.Count != nodeCount)
                throw Error(ProductionMailboxTopologyError.InvalidField,
                    "Selection node set changed while being snapshotted.");
        }
        catch (Exception exception) when (exception is ArgumentOutOfRangeException
            or IndexOutOfRangeException or InvalidOperationException)
        {
            throw Error(ProductionMailboxTopologyError.InvalidField,
                "Selection node set could not be snapshotted.");
        }
        if (network.IndexOfAnyExcept((byte)0) < 0 ||
            selectionInput.IndexOfAnyExcept((byte)0) < 0 || epochNumber == 0 ||
            epochGeneration == 0 || membership.IndexOfAnyExcept((byte)0) < 0 ||
            topologyPlacement.IndexOfAnyExcept((byte)0) < 0 ||
            nodes.Any(static node => node.AsSpan().IndexOfAnyExcept((byte)0) < 0) ||
            nodes.Select(Convert.ToHexString).Distinct(StringComparer.Ordinal).Count() != nodeCount)
            throw Error(ProductionMailboxTopologyError.InvalidField, "Selection inputs are invalid.");
        var numbers = new byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(numbers, epochNumber);
        BinaryPrimitives.WriteUInt64BigEndian(numbers.AsSpan(8), epochGeneration);
        return nodes.Select(node => new
        {
            Node = node,
            Score = Score(network, numbers, membership, topologyPlacement, selectionInput, node)
        })
            .OrderBy(static item => item.Score, ByteArrayComparer.Instance)
            .ThenBy(static item => item.Node, ByteArrayComparer.Instance)
            .Take(2).Select(static item => (ReadOnlyMemory<byte>)item.Node).ToArray();
    }

    private static byte[] Score(ReadOnlySpan<byte> networkId, ReadOnlySpan<byte> numbers,
        ReadOnlySpan<byte> membershipCommitment, ReadOnlySpan<byte> topologyPlacementCommitment,
        ReadOnlySpan<byte> selectionInput, ReadOnlySpan<byte> nodeId)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(ScoreDomain); hash.AppendData(networkId); hash.AppendData(numbers);
        hash.AppendData(membershipCommitment); hash.AppendData(topologyPlacementCommitment);
        hash.AppendData(selectionInput); hash.AppendData(nodeId);
        return hash.GetHashAndReset();
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        public static ByteArrayComparer Instance { get; } = new();
        public int Compare(byte[]? x, byte[]? y) => x is null ? (y is null ? 0 : -1) : y is null ? 1 : x.AsSpan().SequenceCompareTo(y);
    }

    private static ProductionMailboxTopologyException Error(ProductionMailboxTopologyError error, string message) => new(error, message);
}

public static class ProductionMailboxTopologyVerifier
{
    internal static VerifiedProductionMailboxTopology VerifyForwardCheckpoint(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority verifiedAuthority,
        ProductionMailboxTopologyCheckpointVerificationContext context,
        IProductionMailboxTopologySignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.LastCommittedTopologyGeneration == 0 || context.NowUnixSeconds == 0 ||
            context.ClockSkewSeconds > ProductionMailboxTopologyConstants.MaximumClockSkewSeconds)
            throw Error(ProductionMailboxTopologyError.InvalidField,
                "Topology checkpoint context is incomplete or unsafe.");
        return VerifyCore(encoded, verifiedAuthority, signatureVerifier,
            context.LastCommittedTopologyGeneration, default, context.NowUnixSeconds,
            context.ClockSkewSeconds, forwardCheckpoint: true);
    }

    public static VerifiedProductionMailboxTopology Verify(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority verifiedAuthority,
        ProductionMailboxTopologyVerificationContext context,
        IProductionMailboxTopologySignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.LastCommittedTopologyHash.Length != 32)
            throw Error(ProductionMailboxTopologyError.InvalidField,
                "Topology verification context hash length is invalid.");
        context = context with { LastCommittedTopologyHash = context.LastCommittedTopologyHash.ToArray() };
        ValidateContext(context);
        return VerifyCore(encoded, verifiedAuthority, signatureVerifier,
            context.LastCommittedTopologyGeneration, context.LastCommittedTopologyHash,
            context.NowUnixSeconds, context.ClockSkewSeconds, forwardCheckpoint: false);
    }

    private static VerifiedProductionMailboxTopology VerifyCore(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority verifiedAuthority,
        IProductionMailboxTopologySignatureVerifier signatureVerifier,
        ulong lastCommittedTopologyGeneration,
        ReadOnlyMemory<byte> lastCommittedTopologyHash,
        ulong nowUnixSeconds,
        uint clockSkewSeconds,
        bool forwardCheckpoint)
    {
        ArgumentNullException.ThrowIfNull(verifiedAuthority);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (encoded.Length > ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes)
            throw Error(ProductionMailboxTopologyError.InvalidLength, "PMT1 exceeds its strict maximum length.");
        var frozenBytes = encoded.ToArray();
        var topology = ProductionMailboxTopologyCodec.Decode(frozenBytes);
        var authority = verifiedAuthority.Authority;
        var authorityHash = verifiedAuthority.CanonicalAuthorityHash.ToArray();
        VerifyLiveAuthority(authority, nowUnixSeconds, clockSkewSeconds);
        Equal(topology.NetworkId.Span, authority.NetworkId.Span, ProductionMailboxTopologyError.AuthorityMismatch, "Network mismatch.");
        Equal(topology.CanonicalAuthorityHash.Span, authorityHash, ProductionMailboxTopologyError.AuthorityMismatch, "Authority hash mismatch.");
        if (topology.AuthorityGeneration != authority.AuthorityGeneration)
            throw Error(ProductionMailboxTopologyError.AuthorityMismatch, "Authority generation mismatch.");
        BindEpoch(topology.CurrentEpoch, authority.CurrentEpoch, "current");
        BindEpoch(topology.NextEpoch, authority.NextEpoch, "next");
        if (topology.TopologyGeneration == ulong.MaxValue)
            throw Error(ProductionMailboxTopologyError.TopologyRollback,
                "A terminal topology generation cannot be committed.");
        if (forwardCheckpoint)
        {
            if (topology.TopologyGeneration <= lastCommittedTopologyGeneration)
                throw Error(ProductionMailboxTopologyError.TopologyRollback,
                    "Topology checkpoint must move to a non-terminal forward generation.");
        }
        else
        {
            if (lastCommittedTopologyGeneration == ulong.MaxValue ||
                topology.TopologyGeneration != lastCommittedTopologyGeneration + 1)
                throw Error(ProductionMailboxTopologyError.TopologyRollback,
                    "Topology is not the exact durable successor.");
            Equal(topology.PreviousTopologyHash.Span, lastCommittedTopologyHash.Span,
                ProductionMailboxTopologyError.PreviousHashMismatch, "Previous topology hash mismatch.");
        }
        VerifyWindow(topology.IssuedAtUnixSeconds, topology.ExpiresAtUnixSeconds,
            nowUnixSeconds, clockSkewSeconds, "topology");
        if (topology.IssuedAtUnixSeconds < authority.MrXApproval.RolloutNotBeforeUnixSeconds ||
            topology.ExpiresAtUnixSeconds > authority.MrXApproval.RolloutNotAfterUnixSeconds ||
            topology.IssuedAtUnixSeconds < authority.Revocation.IssuedAtUnixSeconds ||
            topology.ExpiresAtUnixSeconds > authority.Revocation.ExpiresAtUnixSeconds)
            throw Error(ProductionMailboxTopologyError.InvalidValidityWindow, "PMT1 lifetime exceeds the verified authority rollout/revocation envelope.");
        VerifyEndpointPolicy(topology, authority);
        if (!signatureVerifier.Verify(authority.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxTopologyCodec.GetSigningBytes(topology), topology.IssuerSignature.Span))
            throw Error(ProductionMailboxTopologyError.InvalidSignature, "PMT1 issuer signature is invalid.");
        return new VerifiedProductionMailboxTopology(topology, SHA256.HashData(frozenBytes));
    }

    private static void ValidateContext(ProductionMailboxTopologyVerificationContext context)
    {
        if (context.LastCommittedTopologyHash.Length != 32 || context.NowUnixSeconds == 0 ||
            context.ClockSkewSeconds > ProductionMailboxTopologyConstants.MaximumClockSkewSeconds)
            throw Error(ProductionMailboxTopologyError.InvalidField, "Topology verification context is incomplete or unsafe.");
        var isZero = context.LastCommittedTopologyHash.Span.IndexOfAnyExcept((byte)0) < 0;
        if ((context.LastCommittedTopologyGeneration == 0) != isZero)
            throw Error(ProductionMailboxTopologyError.InvalidField, "Topology genesis requires generation zero and an all-zero previous hash; established state requires both non-zero.");
    }

    internal static void VerifyLiveAuthority(ProductionMailboxAuthority authority, ulong now, uint skew)
    {
        if (authority.DevelopmentOnly || authority.Environment != ProductionMailboxAuthorityEnvironment.Production)
            throw Error(ProductionMailboxTopologyError.AuthorityMismatch, "Development authority is forbidden.");
        VerifyWindow(authority.CurrentEpoch.NotBeforeUnixSeconds, authority.CurrentEpoch.NotAfterUnixSeconds, now, skew, "authority current epoch");
        VerifyWindow(authority.MrXApproval.RolloutNotBeforeUnixSeconds, authority.MrXApproval.RolloutNotAfterUnixSeconds, now, skew, "Mr. X rollout");
        VerifyWindow(authority.Revocation.IssuedAtUnixSeconds, authority.Revocation.ExpiresAtUnixSeconds, now, skew, "authority revocation snapshot");
    }

    private static void BindEpoch(ProductionMailboxTopologyEpoch topology, ProductionMailboxAuthorityEpoch authority, string name)
    {
        if (topology.Epoch != authority.Epoch || topology.Generation != authority.Generation ||
            topology.NotBeforeUnixSeconds != authority.NotBeforeUnixSeconds || topology.NotAfterUnixSeconds != authority.NotAfterUnixSeconds)
            throw Error(ProductionMailboxTopologyError.AuthorityMismatch, $"PMT1 {name} epoch metadata mismatch.");
        Equal(topology.MembershipCommitment.Span, authority.MembershipCommitment.Span,
            ProductionMailboxTopologyError.AuthorityMismatch, $"PMT1 {name} membership commitment mismatch.");
        Equal(topology.TopologyPlacementCommitment.Span, authority.TopologyPlacementCommitment.Span,
            ProductionMailboxTopologyError.AuthorityMismatch, $"PMT1 {name} topology placement commitment mismatch.");
    }

    private static void VerifyEndpointPolicy(ProductionMailboxTopologySnapshot topology, ProductionMailboxAuthority authority)
    {
        foreach (var node in topology.CurrentEpoch.Nodes.Concat(topology.NextEpoch.Nodes))
        {
            var isPrivate = ProductionMailboxTopologyCodec.IsPrivateEndpoint(node.HttpsEndpoint);
            if (isPrivate && (authority.Ownership != ProductionMailboxAuthorityOwnership.UserManaged ||
                authority.EndpointPolicy != ProductionMailboxAuthorityEndpointPolicy.UserManagedPrivateHttps))
                throw Error(ProductionMailboxTopologyError.InvalidEndpoint, "Private endpoint is allowed only by an explicit user-managed authority.");
        }
    }

    internal static void VerifyWindow(ulong from, ulong until, ulong now, uint skew, string name)
    {
        if (now < from && from - now > skew) throw Error(ProductionMailboxTopologyError.NotYetValid, $"{name} is not yet valid.");
        if (now > until && now - until > skew) throw Error(ProductionMailboxTopologyError.Expired, $"{name} has expired.");
    }

    internal static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, ProductionMailboxTopologyError error, string message)
    { if (actual.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(actual, expected)) throw Error(error, message); }
    internal static ProductionMailboxTopologyException Error(ProductionMailboxTopologyError error, string message) => new(error, message);
}

public static class ProductionMailboxSelectionVerifier
{
    public static VerifiedProductionMailboxSelection Verify(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority verifiedAuthority,
        VerifiedProductionMailboxTopology verifiedTopology,
        BlindedPlacementId expectedPlacementId,
        ulong nowUnixSeconds,
        uint clockSkewSeconds,
        IProductionMailboxTopologySignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(verifiedAuthority); ArgumentNullException.ThrowIfNull(verifiedTopology);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (encoded.Length > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes)
            throw ProductionMailboxTopologyVerifier.Error(ProductionMailboxTopologyError.InvalidLength, "PMS1 exceeds its strict maximum length.");
        ArgumentNullException.ThrowIfNull(expectedPlacementId);
        var frozenExpectedSelectionInput = ProductionMailboxReplicaSelection
            .ComputeSelectionInputCommitment(expectedPlacementId);
        var expectedMailboxPlacementCommitment = MailboxPlacementCommitment.Compute(expectedPlacementId);
        if (nowUnixSeconds == 0 || clockSkewSeconds > ProductionMailboxTopologyConstants.MaximumClockSkewSeconds)
            throw ProductionMailboxTopologyVerifier.Error(ProductionMailboxTopologyError.InvalidField, "Selection verification time is unsafe.");
        var frozenBytes = encoded.ToArray();
        var proof = ProductionMailboxTopologyCodec.DecodeSelection(frozenBytes);
        var authority = verifiedAuthority.Authority;
        var authorityHash = verifiedAuthority.CanonicalAuthorityHash.ToArray();
        var topology = verifiedTopology.Snapshot;
        var topologyHash = verifiedTopology.CanonicalTopologyHash.ToArray();
        ProductionMailboxTopologyVerifier.VerifyLiveAuthority(authority, nowUnixSeconds, clockSkewSeconds);
        ProductionMailboxTopologyVerifier.VerifyWindow(topology.IssuedAtUnixSeconds, topology.ExpiresAtUnixSeconds, nowUnixSeconds, clockSkewSeconds, "topology");
        ProductionMailboxTopologyVerifier.VerifyWindow(proof.IssuedAtUnixSeconds, proof.ExpiresAtUnixSeconds, nowUnixSeconds, clockSkewSeconds, "selection");
        if (proof.IssuedAtUnixSeconds < topology.IssuedAtUnixSeconds || proof.ExpiresAtUnixSeconds > topology.ExpiresAtUnixSeconds)
            throw ProductionMailboxTopologyVerifier.Error(ProductionMailboxTopologyError.InvalidValidityWindow, "PMS1 lifetime exceeds PMT1.");
        ProductionMailboxTopologyVerifier.Equal(proof.NetworkId.Span, authority.NetworkId.Span, ProductionMailboxTopologyError.SelectionMismatch, "Selection network mismatch.");
        ProductionMailboxTopologyVerifier.Equal(proof.CanonicalAuthorityHash.Span, authorityHash, ProductionMailboxTopologyError.SelectionMismatch, "Selection authority hash mismatch.");
        ProductionMailboxTopologyVerifier.Equal(proof.CanonicalTopologyHash.Span, topologyHash, ProductionMailboxTopologyError.SelectionMismatch, "Selection topology hash mismatch.");
        if (proof.AuthorityGeneration != authority.AuthorityGeneration || proof.TopologyGeneration != topology.TopologyGeneration)
            throw ProductionMailboxTopologyVerifier.Error(ProductionMailboxTopologyError.SelectionMismatch, "Selection generation mismatch.");
        var epoch = proof.Epoch == topology.CurrentEpoch.Epoch ? topology.CurrentEpoch :
            proof.Epoch == topology.NextEpoch.Epoch ? topology.NextEpoch :
            throw ProductionMailboxTopologyVerifier.Error(ProductionMailboxTopologyError.SelectionMismatch, "Selection epoch is outside PMT1 current/next.");
        if (proof.Generation != epoch.Generation)
            throw ProductionMailboxTopologyVerifier.Error(ProductionMailboxTopologyError.SelectionMismatch, "Selection epoch generation mismatch.");
        if (proof.IssuedAtUnixSeconds < epoch.NotBeforeUnixSeconds || proof.ExpiresAtUnixSeconds > epoch.NotAfterUnixSeconds)
            throw ProductionMailboxTopologyVerifier.Error(ProductionMailboxTopologyError.InvalidValidityWindow, "PMS1 lifetime exceeds its PMA epoch.");
        ProductionMailboxTopologyVerifier.Equal(proof.MembershipCommitment.Span, epoch.MembershipCommitment.Span, ProductionMailboxTopologyError.SelectionMismatch, "Selection membership mismatch.");
        ProductionMailboxTopologyVerifier.Equal(proof.TopologyPlacementCommitment.Span, epoch.TopologyPlacementCommitment.Span, ProductionMailboxTopologyError.SelectionMismatch, "Selection topology placement mismatch.");
        if (expectedMailboxPlacementCommitment.Length != 32 || expectedMailboxPlacementCommitment.IndexOfAnyExcept((byte)0) < 0)
            throw ProductionMailboxTopologyVerifier.Error(ProductionMailboxTopologyError.InvalidField, "Expected mailbox placement commitment is invalid.");
        ProductionMailboxTopologyVerifier.Equal(proof.MailboxPlacementCommitment.Span, expectedMailboxPlacementCommitment,
            ProductionMailboxTopologyError.SelectionMismatch, "Selection mailbox placement mismatch.");
        ProductionMailboxTopologyVerifier.Equal(proof.SelectionInputCommitment.Span, frozenExpectedSelectionInput,
            ProductionMailboxTopologyError.SelectionMismatch, "Selection input mismatch.");
        var selectedIds = ProductionMailboxReplicaSelection.Select(proof.NetworkId.Span, epoch, frozenExpectedSelectionInput);
        if (!signatureVerifier.Verify(authority.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxTopologyCodec.GetSelectionSigningBytes(proof), proof.IssuerSignature.Span))
            throw ProductionMailboxTopologyVerifier.Error(ProductionMailboxTopologyError.InvalidSignature, "PMS1 issuer signature is invalid.");
        var membershipVerifier = new MembershipRoutesMailboxReplicaProofVerifier();
        var resolved = new VerifiedProductionMailboxSelectedReplica[2];
        for (var i = 0; i < 2; i++)
        {
            ProductionMailboxTopologyVerifier.Equal(proof.Replicas[i].ReplicaId.Span, selectedIds[i].Span,
                ProductionMailboxTopologyError.SelectionMismatch, "Replica rank/order mismatch.");
            MailboxReplicaMembershipProof mip;
            try { mip = MailboxPeerReplicationCodec.DecodeMembershipProof(proof.Replicas[i].CanonicalMIP1Proof.Span); }
            catch (MailboxPeerReplicationException ex) { throw ProductionMailboxTopologyVerifier.Error(ProductionMailboxTopologyError.InvalidMembershipProof, ex.Message); }
            if (mip.Epoch != epoch.Epoch || !mip.ReplicaId.Span.SequenceEqual(proof.Replicas[i].ReplicaId.Span) ||
                !mip.MembershipCommitment.Span.SequenceEqual(epoch.MembershipCommitment.Span) ||
                !membershipVerifier.VerifyStorageReplica(mip, nowUnixSeconds))
                throw ProductionMailboxTopologyVerifier.Error(ProductionMailboxTopologyError.InvalidMembershipProof, "MIP1 does not prove the selected storage replica.");
            var node = epoch.Nodes.Single(n => n.NodeId.Span.SequenceEqual(mip.ReplicaId.Span));
            resolved[i] = new VerifiedProductionMailboxSelectedReplica
            {
                ReplicaId = mip.ReplicaId.ToArray(),
                CanonicalMIP1Proof = proof.Replicas[i].CanonicalMIP1Proof.ToArray(),
                HttpsEndpoint = new Uri(node.HttpsEndpoint, UriKind.Absolute),
                CurrentSpkiSha256 = node.CurrentSpkiSha256.ToArray(),
                NextSpkiSha256 = node.NextSpkiSha256.ToArray()
            };
        }
        return new VerifiedProductionMailboxSelection(proof, resolved, SHA256.HashData(frozenBytes));
    }
}
