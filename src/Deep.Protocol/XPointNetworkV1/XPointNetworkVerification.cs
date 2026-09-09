using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.XPointNetworkV1;

internal interface IXPointSignatureVerifier
{
    bool VerifyEd25519(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature);
}

internal interface IXPointClosureResolver
{
    XPointParsedRecord ResolveCore(XPointCoreReference reference);
    XPointParsedRecord ResolveArtifact(XPointArtifactReference reference);
    Xnd1Record ResolveNodeDescriptor(XPointBytes nodeId);
    bool IsNodeActiveAndUnrevoked(XPointBytes nodeId);
    XPointExternalEvidence ResolveExternalCore(XPointCoreReference reference);
    XPointExternalEvidence ResolveExternalArtifact(XPointArtifactReference reference);
}

internal sealed record XPointExternalEvidence(
    string Magic,
    XPointBytes NetworkId,
    XPointBytes TargetNodeId,
    ulong NotBefore,
    ulong ExpiresAt,
    XPointBytes DerivedHash,
    uint MaximumUncertaintySeconds,
    XPointCoreReference CurrentView);

internal sealed record XPointVerificationContext(
    IXPointClosureResolver Resolver,
    IXPointSignatureVerifier Signatures,
    XPointParsedRecord? AcceptedPredecessor = null,
    XPointBytes ReleasePinnedGenesisCoreHash = default,
    XPointProtectedNetworkLkg? ProtectedLkg = null);

internal sealed record XPointProtectedNetworkLkg(
    XPointBytes NetworkId,
    XPointCoreReference Head,
    ulong TreeSize,
    XPointBytes Root,
    XPointCoreReference View,
    ulong ViewGeneration,
    XPointCoreReference Authority);

internal enum XPointTransitionClassification
{
    Genesis,
    Identical,
    Successor,
    Stale,
    Fork,
    Unrelated,
}

internal static class XPointNetworkVerifier
{
    internal static void Verify(XPointParsedRecord record, XPointVerificationContext context)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(context);
        switch (record)
        {
            case Xna1Record value: VerifyXna(value, context); break;
            case Xvp1Record value: VerifyXvp(value, context); break;
            case Xnd1Record value: VerifyXnd(value, context); break;
            case Xnv1Record value: VerifyXnv(value, context); break;
            case Xnh1Record value: VerifyXnh(value, context); break;
            case Xnp1Record value: VerifyXnp(value, context); break;
            case Xnf1Record value: VerifyXnf(value, context); break;
            case Nfp1Record value: VerifyNfp(value, context); break;
            case Xcd1Record value: VerifyXcd(value, context); break;
            default: throw new InvalidOperationException();
        }
    }

    internal static XPointTransitionClassification Classify(
        XPointParsedRecord? accepted,
        XPointParsedRecord candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        if (accepted is null) return candidate.Definition.GenerationTag != 0 && candidate.Generation == 0
            ? XPointTransitionClassification.Genesis : XPointTransitionClassification.Unrelated;
        if (accepted.Kind != candidate.Kind || !SameLineage(accepted, candidate))
            return XPointTransitionClassification.Unrelated;
        if (accepted.CanonicalSpan.SequenceEqual(candidate.CanonicalSpan) ||
            accepted.Definition.GenerationTag != 0 && accepted.Generation == candidate.Generation && accepted.CoreHash.Equals(candidate.CoreHash))
            return XPointTransitionClassification.Identical;

        if (candidate is Xnp1Record or Nfp1Record)
            return XPointTransitionClassification.Fork;
        if (candidate.Generation < accepted.Generation) return XPointTransitionClassification.Stale;
        if (candidate.Generation == accepted.Generation) return XPointTransitionClassification.Fork;
        if (accepted.Generation == ulong.MaxValue || candidate.Generation != accepted.Generation + 1)
            return XPointTransitionClassification.Fork;
        if (!candidate.FieldSpan(candidate.Definition.PredecessorHashTag).SequenceEqual(accepted.CoreHash.Span))
            return XPointTransitionClassification.Fork;
        if (accepted is Xnd1Record oldNode && candidate is Xnd1Record newNode &&
            (!oldNode.IdentityPublicKey.Equals(newNode.IdentityPublicKey) || !oldNode.StakingIdentityHash.Equals(newNode.StakingIdentityHash)))
            return XPointTransitionClassification.Fork;
        if (accepted is Xnv1Record oldView && candidate is Xnv1Record newView && newView.FinalizedBlockHeight < oldView.FinalizedBlockHeight)
            return XPointTransitionClassification.Fork;
        if (accepted is Xnh1Record oldHead && candidate is Xnh1Record newHead &&
            (oldHead.TreeSize == ulong.MaxValue || newHead.TreeSize != oldHead.TreeSize + 1 ||
             oldHead.LatestViewGeneration == ulong.MaxValue || newHead.LatestViewGeneration != oldHead.LatestViewGeneration + 1))
            return XPointTransitionClassification.Fork;
        if (accepted is Xnf1Record oldCheckpoint && candidate is Xnf1Record newCheckpoint &&
            (BinaryPrimitives.ReadUInt64BigEndian(newCheckpoint.FieldSpan(8)) <= BinaryPrimitives.ReadUInt64BigEndian(oldCheckpoint.FieldSpan(8)) ||
             BinaryPrimitives.ReadUInt64BigEndian(newCheckpoint.FieldSpan(10)) <= BinaryPrimitives.ReadUInt64BigEndian(oldCheckpoint.FieldSpan(10))))
            return XPointTransitionClassification.Fork;
        return XPointTransitionClassification.Successor;
    }

    private static void VerifyXna(Xna1Record r, XPointVerificationContext c)
    {
        IReadOnlyList<XPointRootKeyEntry> keys;
        int threshold;
        if (r.AuthorityGeneration == 0)
        {
            if (c.AcceptedPredecessor is not null || c.ReleasePinnedGenesisCoreHash.Length != 32 ||
                !CryptographicOperations.FixedTimeEquals(c.ReleasePinnedGenesisCoreHash.Span, r.CoreHash.Span))
                Fail(XPointValidationStage.Closure, "GenesisReleasePinMismatch", "XNA genesis is not the release-pinned core.");
            keys = r.RootKeys;
            threshold = r.RootThreshold;
        }
        else
        {
            if (c.AcceptedPredecessor is not Xna1Record)
                Fail(XPointValidationStage.Transition, "PredecessorMismatch", "XNA successor does not name the exact accepted predecessor.");
            var predecessor = (Xna1Record)c.AcceptedPredecessor;
            RequireSuccessor(predecessor, r);
            if (!predecessor.NetworkId.Equals(r.NetworkId) || predecessor.NotBefore > r.IssuedAt ||
                r.IssuedAt > predecessor.ExpiresAt || r.NotBefore > predecessor.ExpiresAt)
                Fail(XPointValidationStage.Closure, "InvalidEffectiveTimeClosure", "XNA successor is outside predecessor authority time.");
            keys = predecessor.RootKeys;
            threshold = predecessor.RootThreshold;
        }
        VerifyThreshold(r.Signatures, keys.Select(k => (k.Id, k.PublicKey)).ToArray(), threshold,
            XPointNetworkCrypto.ComputeSigningInput(r), c.Signatures, "WrongAuthorizingThreshold");

        var dts = c.Resolver.ResolveExternalCore(r.CoreReference(12));
        if (dts.Magic != ProtocolMagic.DTS1 || !dts.NetworkId.Equals(r.NetworkId) ||
            !dts.DerivedHash.Equals(r.FieldBytes(13)) || r.UInt32(14) > dts.MaximumUncertaintySeconds)
            Fail(XPointValidationStage.Closure, "InvalidTimeSourcePolicy", "The DTS policy closure does not match XNA.");
    }

    private static void VerifyXvp(Xvp1Record r, XPointVerificationContext c)
    {
        VerifySuccessorIfPresent(r, c.AcceptedPredecessor);
        var xna = ResolveCore<Xna1Record>(c.Resolver, r.AuthorizingXna);
        RequireNetworkAndInterval(r, xna, r.IssuedAt, r.ExpiresAt);
        VerifyThreshold(r.Signatures, xna.RootKeys.Select(k => (k.Id, k.PublicKey)).ToArray(), xna.RootThreshold,
            XPointNetworkCrypto.ComputeSigningInput(r), c.Signatures, "WrongAuthorizingThreshold");
        var xcc = c.Resolver.ResolveExternalCore(r.CoreReference(13));
        if (xcc.Magic != ProtocolMagic.XCC1 || !xcc.NetworkId.Equals(r.NetworkId))
            Fail(XPointValidationStage.Closure, "InvalidPolicyClosure", "The carrier policy closure is invalid.");
    }

    private static void VerifyXnd(Xnd1Record r, XPointVerificationContext c)
    {
        VerifySuccessorIfPresent(r, c.AcceptedPredecessor);
        if (!c.Signatures.VerifyEd25519(r.IdentityPublicKey.Span,
                XPointNetworkCrypto.ComputeSigningInput(r), r.Signature.Span))
            Fail(XPointValidationStage.Signature, "InvalidNodeSignature", "The node identity signature is invalid.");
    }

    private static void VerifyXnv(Xnv1Record r, XPointVerificationContext c)
    {
        VerifySuccessorIfPresent(r, c.AcceptedPredecessor);
        if (c.AcceptedPredecessor is Xnv1Record prior && r.FinalizedBlockHeight < prior.FinalizedBlockHeight)
            Fail(XPointValidationStage.Transition, "FinalizedHeightRollback", "Finalized block height decreased.");
        var xna = ResolveCore<Xna1Record>(c.Resolver, r.AuthorizingXna);
        var xvp = ResolveCore<Xvp1Record>(c.Resolver, r.ActivePolicy);
        RequireNetworkAndInterval(r, xna, r.UInt64(19), r.ExpiresAt);
        if (!xna.DirectoryWitnessPolicyHash.Equals(r.DirectoryWitnessPolicyHash) ||
            !xvp.NetworkId.Equals(r.NetworkId) || !xvp.AuthorizingXna.Equals(r.AuthorizingXna) ||
            xvp.NotBefore > r.NotBefore || r.ExpiresAt > xvp.ExpiresAt)
            Fail(XPointValidationStage.Closure, "InvalidViewProjection", "XNA/XVP view closure is invalid.");
        VerifyThreshold(r.WitnessSignatures, xna.Witnesses.Select(k => (k.Id, k.PublicKey)).ToArray(), xna.WitnessThreshold,
            XPointNetworkCrypto.ComputeSigningInput(r), c.Signatures, "WrongWitnessThreshold",
            xna.Witnesses.ToDictionary(k => Convert.ToHexString(k.Id.Span), k => k.FailureDomainHash));

        var activeNodes = new List<Xnd1Record>();
        for (var offset = 0; offset < r.FieldSpan(12).Length; offset += 38)
            activeNodes.Add(ResolveArtifact<Xnd1Record>(c.Resolver, XPointNetworkCodec.DecodeArtifactReference(r.FieldSpan(12).Slice(offset,38))));
        if (activeNodes.Any(n => !n.NetworkId.Equals(r.NetworkId) || n.NotBefore > r.NotBefore || r.ExpiresAt > n.ExpiresAt))
            Fail(XPointValidationStage.Closure, "InvalidViewProjection", "An active node descriptor does not cover the view.");
        for (var i = 1; i < activeNodes.Count; i++)
            if (activeNodes[i-1].NodeId.Span.SequenceCompareTo(activeNodes[i].NodeId.Span) >= 0)
                Fail(XPointValidationStage.CanonicalList, "NonCanonicalListOrder", "XND artifact refs are not sorted by resolved node ID.");
        var revoked = Split(r.FieldSpan(14), 32).Select(Convert.ToHexString).ToHashSet(StringComparer.Ordinal);
        if (activeNodes.Any(n => revoked.Contains(Convert.ToHexString(n.NodeId.Span))) ||
            activeNodes.Aggregate((ushort)0, static (mask,n) => (ushort)(mask | n.RoleMask)) != xvp.EnabledRoleMask)
            Fail(XPointValidationStage.Closure, "InvalidViewProjection", "Active and revoked sets overlap or required roles are absent.");
        if (activeNodes.Any(n => !DescriptorCovers(n, r.NotBefore, r.ExpiresAt)))
            Fail(XPointValidationStage.Closure, "InvalidEffectiveTimeClosure", "Node origin/onion intervals do not cover the view.");

        for (var offset = 0; offset < r.FieldSpan(16).Length; offset += 38)
        {
            var reference = XPointNetworkCodec.DecodeCoreReference(r.FieldSpan(16).Slice(offset,38));
            if (reference.Magic == ProtocolMagic.XCD1)
            {
                var xcd = ResolveCore<Xcd1Record>(c.Resolver, reference);
                if (!xcd.NetworkId.Equals(r.NetworkId) || xcd.NotBefore > r.NotBefore || r.ExpiresAt > xcd.ExpiresAt ||
                    activeNodes.All(n => !n.NodeId.Equals(xcd.CallRelayNodeId)) ||
                    xcd.Replicas.Any(replica => activeNodes.All(n => !n.NodeId.Equals(replica.NodeId))))
                    Fail(XPointValidationStage.Closure, "InvalidCallRelayAuthority", "An XCD service is not closed by the view.");
                VerifyXcdAuthority(xcd, c.Signatures,
                    nodeId => activeNodes.SingleOrDefault(n => n.NodeId.Equals(nodeId)) ??
                        throw XPointNetworkCodec.Error(XPointValidationStage.Closure,"InvalidCallRelayReplicaClosure","XCD node is absent from the active view."));
            }
            else
            {
                var external = c.Resolver.ResolveExternalCore(reference);
                if (!external.NetworkId.Equals(r.NetworkId) || activeNodes.All(n => !n.NodeId.Equals(external.TargetNodeId)))
                    Fail(XPointValidationStage.Closure, "InvalidViewProjection", "An external service is not closed by the view.");
            }
        }
        for (var offset = 0; offset < r.FieldSpan(18).Length; offset += 38)
        {
            var external = c.Resolver.ResolveExternalArtifact(XPointNetworkCodec.DecodeArtifactReference(r.FieldSpan(18).Slice(offset,38)));
            if (external.Magic != ProtocolMagic.XCB1 || !external.NetworkId.Equals(r.NetworkId) ||
                activeNodes.All(n => !n.NodeId.Equals(external.TargetNodeId)))
                Fail(XPointValidationStage.Closure, "InvalidViewProjection", "A carrier binding is not closed by the view.");
        }
    }

    private static void VerifyXnh(Xnh1Record r, XPointVerificationContext c)
    {
        // A head lineage is append-only.  Do this before resolving its closure so a
        // caller that already has an accepted head cannot accidentally re-admit a
        // generation-zero head as a new genesis/rollback.
        VerifySuccessorIfPresent(r, c.AcceptedPredecessor);
        var xnv = ResolveCore<Xnv1Record>(c.Resolver, r.LatestView);
        var xna = ResolveCore<Xna1Record>(c.Resolver, r.AuthorizingXna);
        if (!xnv.NetworkId.Equals(r.NetworkId) || xnv.ViewGeneration != r.LatestViewGeneration ||
            !xnv.AuthorizingXna.Equals(r.AuthorizingXna) || !xnv.DirectoryWitnessPolicyHash.Equals(r.DirectoryWitnessPolicyHash) ||
            xna.NotBefore > r.ValidFrom || r.ValidUntil > xna.ExpiresAt || xnv.NotBefore > r.ValidFrom || r.ValidUntil > xnv.ExpiresAt)
            Fail(XPointValidationStage.Closure, "HeadViewMismatch", "The head/view/authority closure is invalid.");
        VerifyThreshold(r.WitnessSignatures, xna.Witnesses.Select(k => (k.Id,k.PublicKey)).ToArray(), xna.WitnessThreshold,
            XPointNetworkCrypto.ComputeSigningInput(r), c.Signatures, "WrongWitnessThreshold",
            xna.Witnesses.ToDictionary(k => Convert.ToHexString(k.Id.Span), k => k.FailureDomainHash));

        var leaf = BuildXnvLeaf(xnv);
        if (r.LogGeneration == 0)
        {
            if (!leaf.AsSpan().SequenceEqual(r.Root.Span))
                Fail(XPointValidationStage.Proof, "InvalidInclusionProof", "The genesis XNV leaf does not equal the one-leaf root.");
        }
        else
        {
            var prior = (Xnh1Record)c.AcceptedPredecessor!;
            if (prior.TreeSize == ulong.MaxValue || prior.LatestViewGeneration == ulong.MaxValue)
                Fail(XPointValidationStage.Transition, "ArithmeticOverflow", "The head successor arithmetic overflows.");
            if (r.TreeSize != prior.TreeSize + 1 || r.LatestViewGeneration != prior.LatestViewGeneration + 1 ||
                !xnv.FieldSpan(3).SequenceEqual(prior.LatestView.Hash.Span))
                Fail(XPointValidationStage.Transition, "PredecessorMismatch", "The head is not an exact one-leaf successor.");
            if (!ContainsNode(r.FieldSpan(14),leaf))
                Fail(XPointValidationStage.Proof,"InvalidConsistencyProof","The successor proof does not commit the exact appended XNV leaf.");
            XPointMerkleProofs.VerifyConsistency(prior.TreeSize, r.TreeSize, prior.Root.Span, r.Root.Span,
                r.FieldSpan(14), r.UInt8(13));
        }
    }

    private static void VerifyXnp(Xnp1Record r, XPointVerificationContext c)
    {
        var lkg = c.ProtectedLkg ?? throw XPointNetworkCodec.Error(XPointValidationStage.Closure, "MissingProtectedLkg", "Protected LKG is required.");
        if (!lkg.NetworkId.Equals(r.NetworkId) || !lkg.Head.Equals(r.CoreReference(2)) || lkg.TreeSize != r.SourceTreeSize ||
            !lkg.Root.Equals(r.FieldBytes(4)) || !lkg.View.Equals(r.CoreReference(5)) || lkg.ViewGeneration != r.SourceViewGeneration)
            Fail(XPointValidationStage.Closure, "InvalidSourceLkg", "The XNP source tuple is not the exact protected LKG.");
        var targetHead = ResolveCore<Xnh1Record>(c.Resolver, r.CoreReference(7));
        var targetView = ResolveCore<Xnv1Record>(c.Resolver, r.CoreReference(10));
        if (targetHead.TreeSize != r.TargetTreeSize || !targetHead.Root.Equals(r.FieldBytes(9)) ||
            !targetHead.LatestView.Equals(r.CoreReference(10)) || targetHead.LatestViewGeneration != r.TargetViewGeneration ||
            !targetHead.AuthorizingXna.Equals(targetView.AuthorizingXna) ||
            !targetHead.DirectoryWitnessPolicyHash.Equals(targetView.DirectoryWitnessPolicyHash))
            Fail(XPointValidationStage.Closure, "HeadViewMismatch", "The XNP target closure is invalid.");
        XPointMerkleProofs.VerifyInclusion(BuildXnvLeaf(targetView), r.UInt64(13), r.TargetTreeSize,
            r.FieldSpan(15), r.UInt8(14), r.FieldSpan(9));
        XPointMerkleProofs.VerifyConsistency(r.SourceTreeSize, r.TargetTreeSize, r.FieldSpan(4), r.FieldSpan(9),
            r.FieldSpan(17), r.UInt8(16));
    }

    private static void VerifyXnf(Xnf1Record r, XPointVerificationContext c, bool requireTransition = true)
    {
        if (requireTransition) VerifySuccessorIfPresent(r, c.AcceptedPredecessor);
        var xna = ResolveCore<Xna1Record>(c.Resolver, r.AuthorizingXna);
        var xnv = ResolveCore<Xnv1Record>(c.Resolver, r.TargetView);
        var xnh = ResolveCore<Xnh1Record>(c.Resolver, r.TargetHead);
        var targetGeneration = BinaryPrimitives.ReadUInt64BigEndian(r.FieldSpan(8));
        var targetTreeSize = BinaryPrimitives.ReadUInt64BigEndian(r.FieldSpan(10));
        if (!xnv.NetworkId.Equals(r.NetworkId) || !xnh.NetworkId.Equals(r.NetworkId) || targetGeneration != xnv.ViewGeneration ||
            !r.FieldSpan(8)[8..].SequenceEqual(xnv.CoreHash.Span) || targetTreeSize != xnh.TreeSize ||
            !r.FieldSpan(10)[8..].SequenceEqual(xnh.Root.Span) || !xnh.LatestView.Equals(r.TargetView) ||
            !xnv.AuthorizingXna.Equals(r.AuthorizingXna) || !xnh.AuthorizingXna.Equals(r.AuthorizingXna))
            Fail(XPointValidationStage.Closure, "InvalidForwardCheckpoint", "The forward checkpoint target closure is invalid.");
        VerifyThreshold(r.Signatures, xna.RootKeys.Select(k => (k.Id,k.PublicKey)).ToArray(), xna.RootThreshold,
            XPointNetworkCrypto.ComputeSigningInput(r), c.Signatures, "WrongAuthorizingThreshold");
        if (xna.NotBefore > r.UInt64(12) || r.UInt64(12) > xna.ExpiresAt)
            Fail(XPointValidationStage.Closure, "InvalidEffectiveTimeClosure", "XNF issuance is outside authority validity.");
        if (c.AcceptedPredecessor is Xnf1Record previous &&
            (targetGeneration <= BinaryPrimitives.ReadUInt64BigEndian(previous.FieldSpan(8)) || targetTreeSize <= BinaryPrimitives.ReadUInt64BigEndian(previous.FieldSpan(10))))
            Fail(XPointValidationStage.Transition, "NonAdvancingTarget", "XNF successor target does not strictly advance.");
    }

    private static void VerifyNfp(Nfp1Record r, XPointVerificationContext c)
    {
        var lkg = c.ProtectedLkg ?? throw XPointNetworkCodec.Error(XPointValidationStage.Closure, "MissingProtectedLkg", "Protected LKG is required.");
        if (!lkg.NetworkId.Equals(r.NetworkId) || lkg.ViewGeneration != r.SourceViewGeneration || !lkg.View.Equals(r.CoreReference(3)) ||
            lkg.TreeSize != r.SourceTreeSize || !lkg.Root.Equals(r.FieldBytes(5)))
            Fail(XPointValidationStage.Closure, "InvalidSourceLkg", "The NFP source tuple is not the exact protected LKG.");
        var authorities = ResolveCoreList<Xna1Record>(c.Resolver, r.FieldSpan(10));
        var checkpoints = ResolveCoreList<Xnf1Record>(c.Resolver, r.FieldSpan(12));
        if (authorities.Count == 0 || checkpoints.Count == 0 || !authorities[0].CoreReferenceValue.Equals(lkg.Authority))
            Fail(XPointValidationStage.Closure, "NonExactAuthorityChain", "The authority/checkpoint chain is incomplete.");
        for (var i = 1; i < authorities.Count; i++)
        {
            VerifyExactSuccessor(authorities[i-1],authorities[i]);
            VerifyXna(authorities[i],c with { AcceptedPredecessor=authorities[i-1] });
        }
        for (var i = 0; i < checkpoints.Count; i++)
        {
            if (i > 0) VerifyExactSuccessor(checkpoints[i-1],checkpoints[i]);
            VerifyXnf(checkpoints[i],c with { AcceptedPredecessor=i == 0 ? null : checkpoints[i-1] },requireTransition:i > 0);
        }
        var authorityIndex=0;
        foreach(var checkpoint in checkpoints)
        {
            if (!checkpoint.AuthorizingXna.Equals(authorities[authorityIndex].CoreReferenceValue))
            {
                authorityIndex++;
                if (authorityIndex >= authorities.Count || !checkpoint.AuthorizingXna.Equals(authorities[authorityIndex].CoreReferenceValue))
                    Fail(XPointValidationStage.Closure,"NonExactAuthorityChain","An XNF authority transition is missing or out of order.");
            }
        }
        if (authorityIndex != authorities.Count-1)
            Fail(XPointValidationStage.Closure,"NonExactAuthorityChain","The NFP authority list contains an unused authority.");
        var first = checkpoints[0];
        if (r.SourceViewGeneration < first.FirstCoveredGeneration || r.SourceViewGeneration > first.LastCoveredGeneration ||
            r.SourceLeafIndex != r.SourceViewGeneration - first.FirstCoveredGeneration || r.SourceLeafIndex >= first.CoveredHeadCount)
            Fail(XPointValidationStage.Proof, "InvalidForwardProofClosure", "The source index/range closure is invalid.");
        var sourceHeadLeaf = BuildCoveredHeadLeaf(r.SourceViewGeneration, r.CoreReference(3).Hash.Span, r.SourceTreeSize, r.FieldSpan(5));
        XPointMerkleProofs.VerifyInclusion(sourceHeadLeaf, r.SourceLeafIndex, first.CoveredHeadCount,
            r.FieldSpan(14), r.UInt8(13), first.FieldSpan(6));
        var last = checkpoints[^1];
        if (!last.TargetView.Equals(r.CoreReference(7)) || !last.TargetHead.Equals(r.CoreReference(8)))
            Fail(XPointValidationStage.Closure, "InvalidForwardCheckpoint", "The final checkpoint target does not equal NFP target refs.");
        var targetView=ResolveCore<Xnv1Record>(c.Resolver,r.CoreReference(7));
        var targetHead=ResolveCore<Xnh1Record>(c.Resolver,r.CoreReference(8));
        if (targetView.ViewGeneration <= r.SourceViewGeneration || !targetHead.LatestView.Equals(r.CoreReference(7)))
            Fail(XPointValidationStage.Proof,"InvalidForwardProofClosure","The NFP target is not a strictly newer matching head/view.");
        var dtt = c.Resolver.ResolveExternalCore(r.CoreReference(15));
        if (dtt.Magic != ProtocolMagic.DTT1 || !dtt.NetworkId.Equals(r.NetworkId) || !dtt.CurrentView.Equals(r.CoreReference(7)) ||
            dtt.NotBefore > targetHead.ValidUntil || targetHead.ValidFrom > dtt.ExpiresAt)
            Fail(XPointValidationStage.Proof, "InvalidForwardProofClosure", "The live DTT target closure is invalid.");
    }

    internal static void VerifyForwardTarget(
        Xnv1Record view,
        Xnh1Record head,
        Xna1Record authority,
        XPointVerificationContext context)
    {
        ArgumentNullException.ThrowIfNull(view);
        ArgumentNullException.ThrowIfNull(head);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(context);

        if (!view.NetworkId.Equals(authority.NetworkId) ||
            !head.NetworkId.Equals(authority.NetworkId) ||
            !view.AuthorizingXna.Equals(authority.CoreReferenceValue) ||
            !head.AuthorizingXna.Equals(authority.CoreReferenceValue) ||
            !view.DirectoryWitnessPolicyHash.Equals(authority.DirectoryWitnessPolicyHash) ||
            !head.DirectoryWitnessPolicyHash.Equals(authority.DirectoryWitnessPolicyHash) ||
            !head.LatestView.Equals(view.CoreReferenceValue) ||
            head.LatestViewGeneration != view.ViewGeneration ||
            view.ViewGeneration == ulong.MaxValue ||
            head.TreeSize != view.ViewGeneration + 1)
            Fail(XPointValidationStage.Closure, "HeadViewMismatch",
                "The reset target XNV1/XNH1/authority closure is inconsistent.");

        if (authority.NotBefore > view.NotBefore || view.ExpiresAt > authority.ExpiresAt ||
            authority.NotBefore > head.ValidFrom || head.ValidUntil > authority.ExpiresAt ||
            view.NotBefore > head.ValidFrom || head.ValidUntil > view.ExpiresAt)
            Fail(XPointValidationStage.Closure, "InvalidEffectiveTimeClosure",
                "The reset target is outside its exact authority or view interval.");

        VerifyThreshold(view.WitnessSignatures,
            authority.Witnesses.Select(static key => (key.Id, key.PublicKey)).ToArray(),
            authority.WitnessThreshold,
            XPointNetworkCrypto.ComputeSigningInput(view),
            context.Signatures,
            "WrongWitnessThreshold",
            authority.Witnesses.ToDictionary(
                static key => Convert.ToHexString(key.Id.Span),
                static key => key.FailureDomainHash));
        VerifyThreshold(head.WitnessSignatures,
            authority.Witnesses.Select(static key => (key.Id, key.PublicKey)).ToArray(),
            authority.WitnessThreshold,
            XPointNetworkCrypto.ComputeSigningInput(head),
            context.Signatures,
            "WrongWitnessThreshold",
            authority.Witnesses.ToDictionary(
                static key => Convert.ToHexString(key.Id.Span),
                static key => key.FailureDomainHash));
    }

    private static void VerifyXcd(Xcd1Record r, XPointVerificationContext c)
    {
        VerifySuccessorIfPresent(r, c.AcceptedPredecessor);
        if (!c.Resolver.IsNodeActiveAndUnrevoked(r.CallRelayNodeId) || r.Replicas.Any(x => !c.Resolver.IsNodeActiveAndUnrevoked(x.NodeId)))
            Fail(XPointValidationStage.Closure,"InvalidCallRelayReplicaClosure","An XCD node is not active and unrevoked.");
        VerifyXcdAuthority(r,c.Signatures,nodeId=>ResolveXndByNode(c.Resolver,nodeId));
    }

    private static void VerifyXcdAuthority(Xcd1Record r, IXPointSignatureVerifier signatures, Func<XPointBytes,Xnd1Record> resolveNode)
    {
        var target = resolveNode(r.CallRelayNodeId);
        VerifyCallRelayBinding(r, target, r.TargetRoleKeyGeneration, r.TargetRolePublicKey, r.NotBefore, r.ExpiresAt, false);
        var targetRole = target.FindRole(XPointNetworkRegistry.CallRelayRoleId)!;
        if (!signatures.VerifyEd25519(targetRole.PublicKey.Span,
                XPointNetworkCrypto.ComputeSigningInput(r), r.Signature.Span))
            Fail(XPointValidationStage.Signature, "InvalidCallRelayProofOfPossession", "The target CallRelay role-key signature is invalid.");

        var entryOffset = 0;
        foreach (var replica in r.Replicas)
        {
            var descriptor = resolveNode(replica.NodeId);
            VerifyCallRelayBinding(r, descriptor, replica.RoleKeyGeneration, replica.RolePublicKey, r.NotBefore, r.ExpiresAt, true);
            if (!descriptor.FailureDomainHash.Equals(replica.FailureDomainHash))
                Fail(XPointValidationStage.Closure, "InvalidCallRelayAuthority", "Replica failure-domain projection does not match XND.");
            var popPayload = new byte[16 + 32 + 8 + 32 + 136];
            var offset = 0;
            foreach (var tag in new[] { 1,2,3,4 })
            {
                r.FieldSpan(tag).CopyTo(popPayload.AsSpan(offset));
                offset += r.FieldSpan(tag).Length;
            }
            r.FieldSpan(8).Slice(entryOffset,136).CopyTo(popPayload.AsSpan(offset));
            var input = XPointNetworkCrypto.SignatureInput(XPointNetworkRegistry.XcdReplicaPopDomain,
                XPointNetworkRegistry.NetworkSuite, popPayload);
            if (!signatures.VerifyEd25519(replica.RolePublicKey.Span, input, replica.ProofOfPossession.Span))
                Fail(XPointValidationStage.Signature, "InvalidCallRelayProofOfPossession", "A replica CallRelay role-key proof is invalid.");
            entryOffset += 200;
        }
    }

    private static void VerifyCallRelayBinding(Xcd1Record r, Xnd1Record descriptor, ulong generation, XPointBytes key, ulong from, ulong until, bool replica)
    {
        var role = descriptor.FindRole(XPointNetworkRegistry.CallRelayRoleId);
        if (!descriptor.NetworkId.Equals(r.NetworkId) || (descriptor.RoleMask & (1 << XPointNetworkRegistry.CallRelayRoleId)) == 0 ||
            role is null || descriptor.NotBefore > from || until > descriptor.ExpiresAt)
            Fail(XPointValidationStage.Closure, replica ? "InvalidCallRelayReplicaClosure" : "CallRelayRoleKeyMismatch",
                "The XND CallRelay role/time closure is invalid.");
        if (role.Generation != generation || !role.PublicKey.Equals(key))
            Fail(XPointValidationStage.Closure, "CallRelayRoleKeyMismatch", "The XCD role key/generation is not the exact XND CallRelay entry.");
    }

    private static Xnd1Record ResolveXndByNode(IXPointClosureResolver resolver, XPointBytes nodeId)
    {
        var descriptor = resolver.ResolveNodeDescriptor(nodeId);
        if (!descriptor.NodeId.Equals(nodeId))
            Fail(XPointValidationStage.Reference, "ReferenceHashMismatch", "The node resolver returned a different node ID.");
        return descriptor;
    }

    private static void VerifySuccessorIfPresent(XPointParsedRecord current, XPointParsedRecord? prior)
    {
        if (current.Definition.GenerationTag == 0) return;
        if (current.Generation == 0)
        {
            if (prior is not null) Fail(XPointValidationStage.Transition, "PredecessorMismatch", "Genesis cannot have a predecessor.");
            return;
        }
        if (prior is null)
            Fail(XPointValidationStage.Transition, "PredecessorMismatch", "The record is not the exact accepted successor.");
        RequireSuccessor(prior,current);
        VerifyRecordSpecificSuccessor(prior,current);
    }

    private static void VerifyExactSuccessor(XPointParsedRecord prior, XPointParsedRecord current)
    {
        RequireSuccessor(prior,current);
        VerifyRecordSpecificSuccessor(prior,current);
    }

    internal static void RequireSuccessor(XPointParsedRecord prior, XPointParsedRecord current)
    {
        if (prior.Kind != current.Kind || !SameLineage(prior,current))
            Fail(XPointValidationStage.Transition, "PredecessorMismatch", "The successor lineage is different.");
        if (prior.Generation == ulong.MaxValue)
            Fail(XPointValidationStage.Transition, "ArithmeticOverflow", "The generation successor overflows.");
        if (current.Generation == prior.Generation && !current.CoreHash.Equals(prior.CoreHash))
            Fail(XPointValidationStage.Transition, "ForkDetected", "Different cores exist at one generation.");
        if (current.Generation != prior.Generation + 1)
            Fail(XPointValidationStage.Transition, "GenerationGap", "The successor generation is not exactly predecessor plus one.");
        if (!current.FieldSpan(current.Definition.PredecessorHashTag).SequenceEqual(prior.CoreHash.Span))
            Fail(XPointValidationStage.Transition, "PredecessorMismatch", "The successor names a different predecessor core.");
    }

    private static void VerifyRecordSpecificSuccessor(XPointParsedRecord prior, XPointParsedRecord current)
    {
        if (prior is Xnd1Record a && current is Xnd1Record b &&
            (!a.NodeId.Equals(b.NodeId) || !a.IdentityPublicKey.Equals(b.IdentityPublicKey) || !a.StakingIdentityHash.Equals(b.StakingIdentityHash)))
            Fail(XPointValidationStage.Transition, "LineageMismatch", "XND immutable lineage fields changed.");
        if (prior is Xcd1Record c && current is Xcd1Record d && !c.CallRelayNodeId.Equals(d.CallRelayNodeId))
            Fail(XPointValidationStage.Transition, "LineageMismatch", "XCD target node changed.");
    }

    private static bool SameLineage(XPointParsedRecord left, XPointParsedRecord right)
    {
        if (!left.NetworkId.Equals(right.NetworkId)) return false;
        return (left,right) switch
        {
            (Xnd1Record a, Xnd1Record b) => a.NodeId.Equals(b.NodeId),
            (Xcd1Record a, Xcd1Record b) => a.CallRelayNodeId.Equals(b.CallRelayNodeId),
            _ => true,
        };
    }

    private static void VerifyThreshold(
        IReadOnlyList<XPointSignatureEntry> receipts,
        IReadOnlyList<(XPointBytes Id, XPointBytes PublicKey)> keys,
        int threshold,
        ReadOnlySpan<byte> message,
        IXPointSignatureVerifier verifier,
        string thresholdError,
        IReadOnlyDictionary<string,XPointBytes>? failureDomains = null)
    {
        var valid = 0;
        var domains = new HashSet<string>(StringComparer.Ordinal);
        foreach (var receipt in receipts)
        {
            var key = keys.SingleOrDefault(k => k.Id.Equals(receipt.Id));
            if (key.Id.Length == 0)
                Fail(XPointValidationStage.Closure, "UnknownSigner", "A receipt signer is absent from the exact authority record.");
            if (!verifier.VerifyEd25519(key.PublicKey.Span, message, receipt.Signature.Span))
                Fail(XPointValidationStage.Signature, "InvalidSignature", "A threshold receipt signature is invalid.");
            valid++;
            if (failureDomains is not null && !domains.Add(Convert.ToHexString(failureDomains[Convert.ToHexString(receipt.Id.Span)].Span)))
                Fail(XPointValidationStage.Closure, thresholdError, "Witness receipts do not have distinct failure domains.");
        }
        if (valid < threshold) Fail(XPointValidationStage.Closure, thresholdError, "The exact authority threshold is not met.");
    }

    private static T ResolveCore<T>(IXPointClosureResolver resolver, XPointCoreReference reference) where T : XPointParsedRecord
    {
        var record = resolver.ResolveCore(reference);
        if (record is not T || record.Magic != reference.Magic || record.Definition.Version != reference.Version || !record.CoreHash.Equals(reference.Hash))
            Fail(XPointValidationStage.Reference, "ReferenceHashMismatch", "Resolved core bytes do not match the typed core reference.");
        return (T)record;
    }

    private static T ResolveArtifact<T>(IXPointClosureResolver resolver, XPointArtifactReference reference) where T : XPointParsedRecord
    {
        var record = resolver.ResolveArtifact(reference);
        if (record is not T || record.Magic != reference.Magic || record.Definition.Version != reference.Version ||
            !CryptographicOperations.FixedTimeEquals(XPointNetworkCrypto.ComputeArtifactHash(record), reference.Hash.Span))
            Fail(XPointValidationStage.Reference, "ReferenceHashMismatch", "Resolved canonical bytes do not match the typed artifact reference.");
        return (T)record;
    }

    private static List<T> ResolveCoreList<T>(IXPointClosureResolver resolver, ReadOnlySpan<byte> list) where T : XPointParsedRecord
    {
        var output = new List<T>(list.Length/38);
        for (var offset = 0; offset < list.Length; offset += 38)
            output.Add(ResolveCore<T>(resolver, XPointNetworkCodec.DecodeCoreReference(list.Slice(offset,38))));
        return output;
    }

    private static void RequireNetworkAndInterval(XPointParsedRecord child, Xna1Record authority, ulong from, ulong until)
    {
        if (!authority.NetworkId.Equals(child.NetworkId) || authority.NotBefore > from || until > authority.ExpiresAt)
            Fail(XPointValidationStage.Closure, "InvalidEffectiveTimeClosure", "Authority network/time closure is invalid.");
    }

    private static bool DescriptorCovers(Xnd1Record descriptor, ulong from, ulong until)
    {
        var origin = descriptor.Origins.Any(o =>
            (o.CurrentNotBefore <= from && until <= o.CurrentExpiresAt) ||
            (o.CurrentNotBefore <= from && o.NextExpiresAt >= until && o.NextNotBefore <= o.CurrentExpiresAt) ||
            (o.NextNotBefore <= from && until <= o.NextExpiresAt));
        var onion = descriptor.UInt64(23) <= from && descriptor.UInt64(28) >= until && descriptor.UInt64(27) <= descriptor.UInt64(24);
        return origin && onion;
    }

    private static byte[] BuildXnvLeaf(Xnv1Record record)
    {
        Span<byte> payload = stackalloc byte[72];
        BinaryPrimitives.WriteUInt64BigEndian(payload, record.ViewGeneration);
        record.FieldSpan(3).CopyTo(payload[8..40]);
        record.CoreHash.Span.CopyTo(payload[40..]);
        return XPointNetworkCrypto.Rfc6962Leaf(payload);
    }

    private static byte[] BuildCoveredHeadLeaf(ulong generation, ReadOnlySpan<byte> viewHash, ulong treeSize, ReadOnlySpan<byte> root)
    {
        Span<byte> payload = stackalloc byte[80];
        BinaryPrimitives.WriteUInt64BigEndian(payload, generation);
        viewHash.CopyTo(payload[8..40]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[40..48], treeSize);
        root.CopyTo(payload[48..80]);
        return XPointNetworkCrypto.Rfc6962Leaf(payload);
    }

    private static IEnumerable<byte[]> Split(ReadOnlySpan<byte> value, int width)
    {
        var output = new List<byte[]>(value.Length/width);
        for (var offset=0; offset<value.Length; offset+=width) output.Add(value.Slice(offset,width).ToArray());
        return output;
    }

    private static bool ContainsNode(ReadOnlySpan<byte> nodes,ReadOnlySpan<byte> expected)
    {
        for(var offset=0;offset<nodes.Length;offset+=32)
            if(CryptographicOperations.FixedTimeEquals(nodes.Slice(offset,32),expected))return true;
        return false;
    }

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(XPointValidationStage stage, string error, string message) =>
        throw XPointNetworkCodec.Error(stage,error,message);
}

internal static class XPointMerkleProofs
{
    internal static void VerifyInclusion(ReadOnlySpan<byte> leafHash, ulong leafIndex, ulong treeSize,
        ReadOnlySpan<byte> nodes, int nodeCount, ReadOnlySpan<byte> expectedRoot)
    {
        if (treeSize == 0 || leafIndex >= treeSize || nodes.Length != nodeCount * 32)
            Fail("InvalidInclusionProof");
        var fn = leafIndex;
        var sn = treeSize - 1;
        var hash = leafHash.ToArray();
        var consumed = 0;
        while (sn > 0)
        {
            if (consumed == nodeCount) Fail("InvalidInclusionProof");
            var node = nodes.Slice(consumed++ * 32,32);
            if ((fn & 1) == 1 || fn == sn)
            {
                hash = XPointNetworkCrypto.Rfc6962Inner(node,hash);
                while ((fn & 1) == 0 && fn != 0) { fn >>= 1; sn >>= 1; }
            }
            else hash = XPointNetworkCrypto.Rfc6962Inner(hash,node);
            fn >>= 1;
            sn >>= 1;
        }
        if (consumed != nodeCount || !CryptographicOperations.FixedTimeEquals(hash,expectedRoot)) Fail("InvalidInclusionProof");
    }

    internal static void VerifyConsistency(ulong oldSize, ulong newSize, ReadOnlySpan<byte> oldRoot,
        ReadOnlySpan<byte> newRoot, ReadOnlySpan<byte> nodes, int nodeCount)
    {
        if (oldSize == 0 || oldSize > newSize || nodes.Length != nodeCount*32) Fail("InvalidConsistencyProof");
        if (oldSize == newSize)
        {
            if (nodeCount != 0 || !CryptographicOperations.FixedTimeEquals(oldRoot,newRoot)) Fail("NonCanonicalProof");
            return;
        }
        var fn = oldSize - 1;
        var sn = newSize - 1;
        while ((fn & 1) == 1) { fn >>= 1; sn >>= 1; }
        var consumed = 0;
        byte[] first;
        byte[] second;
        if (fn == 0) first = second = oldRoot.ToArray();
        else
        {
            if (nodeCount == 0) Fail("InvalidConsistencyProof");
            first = second = nodes.Slice(consumed++*32,32).ToArray();
        }
        while (consumed < nodeCount)
        {
            if (sn == 0) Fail("NonCanonicalProof");
            var node = nodes.Slice(consumed++*32,32);
            if ((fn & 1) == 1 || fn == sn)
            {
                first = XPointNetworkCrypto.Rfc6962Inner(node,first);
                second = XPointNetworkCrypto.Rfc6962Inner(node,second);
                while ((fn & 1) == 0 && fn != 0) { fn >>= 1; sn >>= 1; }
            }
            else second = XPointNetworkCrypto.Rfc6962Inner(second,node);
            fn >>= 1;
            sn >>= 1;
        }
        if (sn != 0 || !CryptographicOperations.FixedTimeEquals(first,oldRoot) || !CryptographicOperations.FixedTimeEquals(second,newRoot))
            Fail("InvalidConsistencyProof");
    }

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string error) => throw XPointNetworkCodec.Error(XPointValidationStage.Proof,error,"The RFC-6962 proof is invalid or nonminimal.");
}
