using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

public static class ProductionMailboxSelectionSuccessorVerifier
{
    public static VerifiedProductionMailboxSelectionSuccessor VerifyDirectPromotion(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority oldAuthority,
        VerifiedProductionMailboxTopology oldTopology,
        VerifiedProductionMailboxAuthority newAuthority,
        VerifiedProductionMailboxTopology newTopology,
        ProductionMailboxSelectionSuccessorVerificationContext context,
        IProductionMailboxAuthoritySignatureVerifier authoritySignatureVerifier,
        IProductionMailboxTopologySignatureVerifier selectionSignatureVerifier,
        IProductionMailboxSelectionSuccessorSignatureVerifier successorSignatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(context);
        ValidateContextLengths(context);
        var frozenContext = Freeze(context);
        ValidateContext(frozenContext);
        var frozenEncoded = FreezeBounded(encoded);
        if (ProductionMailboxSelectionSuccessorCodec.Decode(frozenEncoded).Mode !=
            ProductionMailboxSelectionSuccessorMode.DirectPromotion)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                "This entry point accepts direct-promotion PSS1 only.");
        return VerifyCore(frozenEncoded, oldAuthority, oldTopology, newAuthority, newTopology,
            frozenContext,
            authoritySignatureVerifier, selectionSignatureVerifier, successorSignatureVerifier);
    }

    public static VerifiedProductionMailboxSelectionSuccessor VerifyOfflineCheckpoint(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority oldAuthority,
        VerifiedProductionMailboxTopology oldTopology,
        ReadOnlySpan<byte> canonicalNewTopology,
        ProductionMailboxSelectionSuccessorVerificationContext context,
        IProductionMailboxAuthoritySignatureVerifier authoritySignatureVerifier,
        IProductionMailboxTopologySignatureVerifier topologySignatureVerifier,
        IProductionMailboxSelectionSuccessorSignatureVerifier successorSignatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(oldAuthority);
        ArgumentNullException.ThrowIfNull(oldTopology);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(authoritySignatureVerifier);
        ArgumentNullException.ThrowIfNull(topologySignatureVerifier);
        ArgumentNullException.ThrowIfNull(successorSignatureVerifier);
        ValidateContextLengths(context);
        var frozenContext = Freeze(context);
        ValidateContext(frozenContext);
        var frozenEncoded = FreezeBounded(encoded);
        var proof = ProductionMailboxSelectionSuccessorCodec.Decode(frozenEncoded);
        if (proof.Mode != ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                "This entry point accepts offline-checkpoint PSS1 only.");
        Equal(proof.NetworkId.Span, frozenContext.ExpectedNetworkId.Span,
            ProductionMailboxSelectionSuccessorError.NetworkMismatch,
            "PSS1 expected network mismatch.");
        Equal(proof.MailboxOwnerEd25519PublicKey.Span,
            frozenContext.ExpectedMailboxOwnerEd25519PublicKey.Span,
            ProductionMailboxSelectionSuccessorError.OwnerMismatch,
            "PSS1 mailbox owner mismatch.");
        Equal(proof.BlindedMailboxId.Span, frozenContext.ExpectedBlindedMailboxId.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch,
            "PSS1 blinded mailbox mismatch.");
        Equal(proof.BlindedPlacementId.Span, frozenContext.ExpectedBlindedPlacementId.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch,
            "PSS1 blinded placement mismatch.");
        Equal(proof.OldCanonicalSelectionHash.Span,
            frozenContext.ExpectedOldCanonicalSelectionHash.Span,
            ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            "PSS1 does not bridge the caller's exact durable old-next PMS1.");
        VerifiedProductionMailboxAuthority currentAuthority;
        try
        {
            currentAuthority = VerifyEmbeddedNewAuthority(
                proof, oldAuthority, frozenContext, authoritySignatureVerifier);
        }
        catch (ProductionMailboxAuthorityException ex)
        {
            throw Error(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
                $"PSS1 embedded PMA1 checkpoint is invalid: {ex.Message}");
        }
        VerifiedProductionMailboxTopology currentTopology;
        try
        {
            currentTopology = ProductionMailboxTopologyVerifier.VerifyForwardCheckpoint(
                canonicalNewTopology, currentAuthority,
                new ProductionMailboxTopologyCheckpointVerificationContext
                {
                    LastCommittedTopologyGeneration =
                        oldTopology.Snapshot.TopologyGeneration,
                    NowUnixSeconds = frozenContext.NowUnixSeconds,
                    ClockSkewSeconds = frozenContext.ClockSkewSeconds
                }, topologySignatureVerifier);
        }
        catch (ProductionMailboxTopologyException ex)
        {
            throw Error(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
                $"PSS1 current PMT1 checkpoint is invalid: {ex.Message}");
        }
        return VerifyCore(frozenEncoded, oldAuthority, oldTopology, currentAuthority, currentTopology,
            frozenContext, authoritySignatureVerifier, topologySignatureVerifier,
            successorSignatureVerifier);
    }

    private static VerifiedProductionMailboxSelectionSuccessor VerifyCore(
        byte[] frozenBytes,
        VerifiedProductionMailboxAuthority oldAuthority,
        VerifiedProductionMailboxTopology oldTopology,
        VerifiedProductionMailboxAuthority newAuthority,
        VerifiedProductionMailboxTopology newTopology,
        ProductionMailboxSelectionSuccessorVerificationContext context,
        IProductionMailboxAuthoritySignatureVerifier authoritySignatureVerifier,
        IProductionMailboxTopologySignatureVerifier selectionSignatureVerifier,
        IProductionMailboxSelectionSuccessorSignatureVerifier successorSignatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(oldAuthority);
        ArgumentNullException.ThrowIfNull(oldTopology);
        ArgumentNullException.ThrowIfNull(newAuthority);
        ArgumentNullException.ThrowIfNull(newTopology);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(authoritySignatureVerifier);
        ArgumentNullException.ThrowIfNull(selectionSignatureVerifier);
        ArgumentNullException.ThrowIfNull(successorSignatureVerifier);
        var frozenContext = context;
        var proof = ProductionMailboxSelectionSuccessorCodec.Decode(frozenBytes);
        VerifyWindow(proof.IssuedAtUnixSeconds, proof.ExpiresAtUnixSeconds,
            frozenContext.NowUnixSeconds, frozenContext.ClockSkewSeconds, "PSS1");

        var oldAuthorityValue = oldAuthority.Authority;
        var newAuthorityValue = newAuthority.Authority;
        var oldAuthorityHash = oldAuthority.CanonicalAuthorityHash.ToArray();
        var newAuthorityHash = newAuthority.CanonicalAuthorityHash.ToArray();
        var oldTopologyValue = oldTopology.Snapshot;
        var newTopologyValue = newTopology.Snapshot;
        var oldTopologyHash = oldTopology.CanonicalTopologyHash.ToArray();
        var newTopologyHash = newTopology.CanonicalTopologyHash.ToArray();

        if (proof.Mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion)
            RejectTerminalDirectClosure(oldAuthorityValue, newAuthorityValue,
                oldTopologyValue, newTopologyValue);

        Equal(proof.NetworkId.Span, frozenContext.ExpectedNetworkId.Span,
            ProductionMailboxSelectionSuccessorError.NetworkMismatch, "PSS1 expected network mismatch.");
        Equal(proof.NetworkId.Span, oldAuthorityValue.NetworkId.Span,
            ProductionMailboxSelectionSuccessorError.NetworkMismatch, "PSS1 old network mismatch.");
        Equal(proof.NetworkId.Span, newAuthorityValue.NetworkId.Span,
            ProductionMailboxSelectionSuccessorError.NetworkMismatch, "PSS1 new network mismatch.");
        Equal(proof.MailboxOwnerEd25519PublicKey.Span,
            frozenContext.ExpectedMailboxOwnerEd25519PublicKey.Span,
            ProductionMailboxSelectionSuccessorError.OwnerMismatch, "PSS1 mailbox owner mismatch.");
        Equal(proof.BlindedMailboxId.Span, frozenContext.ExpectedBlindedMailboxId.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch, "PSS1 blinded mailbox mismatch.");
        Equal(proof.BlindedPlacementId.Span, frozenContext.ExpectedBlindedPlacementId.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch, "PSS1 blinded placement mismatch.");
        Equal(proof.OldCanonicalSelectionHash.Span,
            frozenContext.ExpectedOldCanonicalSelectionHash.Span,
            ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            "PSS1 does not bridge the caller's exact durable old-next PMS1.");
        var placement = new BlindedPlacementId(proof.BlindedPlacementId.Span);
        var expectedSelectionInput = ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(placement);
        Equal(proof.SelectionInputCommitment.Span, expectedSelectionInput,
            ProductionMailboxSelectionSuccessorError.RouteMismatch, "PSS1 selection input mismatch.");

        VerifiedProductionMailboxAuthority embeddedNewAuthority;
        try
        {
            embeddedNewAuthority = VerifyEmbeddedNewAuthority(
                proof, oldAuthority, frozenContext, authoritySignatureVerifier);
        }
        catch (ProductionMailboxAuthorityException ex)
        {
            throw Error(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
                $"PSS1 embedded PMA1 checkpoint is invalid: {ex.Message}");
        }
        var embeddedNewAuthorityHash = embeddedNewAuthority.CanonicalAuthorityHash.ToArray();
        Equal(proof.OldCanonicalAuthorityHash.Span, oldAuthorityHash,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor, "PSS1 old authority hash mismatch.");
        Equal(proof.NewCanonicalAuthorityHash.Span, newAuthorityHash,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor, "PSS1 new authority hash mismatch.");
        Equal(embeddedNewAuthorityHash, newAuthorityHash,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            "PSS1 embedded PMA1 does not match the supplied verified new authority.");
        BindTopologyClosure(oldTopologyValue, oldAuthorityValue, oldAuthorityHash, "old");
        BindTopologyClosure(newTopologyValue, newAuthorityValue, newAuthorityHash, "new");

        if (proof.OldTopologyGeneration != oldTopologyValue.TopologyGeneration ||
            proof.NewTopologyGeneration != newTopologyValue.TopologyGeneration)
            throw Error(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
                "PSS1 topology generation does not match its PMT1 closure.");
        Equal(proof.OldCanonicalTopologyHash.Span, oldTopologyHash,
            ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor, "PSS1 old topology hash mismatch.");
        Equal(proof.NewCanonicalTopologyHash.Span, newTopologyHash,
            ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor, "PSS1 new topology hash mismatch.");

        var decodedOldSelection = ProductionMailboxTopologyCodec.DecodeSelection(
            proof.OldCanonicalSelection.Span);
        var oldSelection = ProductionMailboxSelectionVerifier.Verify(
            proof.OldCanonicalSelection.Span, oldAuthority, oldTopology, placement,
            decodedOldSelection.IssuedAtUnixSeconds, frozenContext.ClockSkewSeconds,
            selectionSignatureVerifier);
        var newSelection = ProductionMailboxSelectionVerifier.Verify(
            proof.NewCanonicalSelection.Span, newAuthority, newTopology, placement,
            frozenContext.NowUnixSeconds, frozenContext.ClockSkewSeconds, selectionSignatureVerifier);
        var oldSelectionValue = oldSelection.Proof;
        var newSelectionValue = newSelection.Proof;
        var oldSelectionHash = oldSelection.CanonicalSelectionHash.ToArray();
        var newSelectionHash = newSelection.CanonicalSelectionHash.ToArray();
        Equal(proof.OldCanonicalSelectionHash.Span, oldSelectionHash,
            ProductionMailboxSelectionSuccessorError.SelectionMismatch, "PSS1 old PMS1 hash mismatch.");
        Equal(proof.NewCanonicalSelectionHash.Span, newSelectionHash,
            ProductionMailboxSelectionSuccessorError.SelectionMismatch, "PSS1 new PMS1 hash mismatch.");
        if (oldSelectionValue.Epoch != proof.OldEpoch ||
            oldSelectionValue.Generation != proof.OldEpochGeneration ||
            newSelectionValue.Epoch != proof.NewEpoch ||
            newSelectionValue.Generation != proof.NewEpochGeneration)
            throw Error(ProductionMailboxSelectionSuccessorError.EpochMismatch,
                "PSS1 epoch fields do not match the embedded selections.");

        if (proof.IssuedAtUnixSeconds < newSelectionValue.IssuedAtUnixSeconds ||
            proof.IssuedAtUnixSeconds > newSelectionValue.ExpiresAtUnixSeconds ||
            proof.ExpiresAtUnixSeconds > newSelectionValue.ExpiresAtUnixSeconds)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidValidityWindow,
                "PSS1 must be contained in the live new PMS1 window.");

        switch (proof.Mode)
        {
            case ProductionMailboxSelectionSuccessorMode.DirectPromotion:
                VerifyDirectPromotion(proof, oldAuthorityValue, oldAuthorityHash,
                    newAuthorityValue, oldTopologyValue, oldTopologyHash, newTopologyValue,
                    oldSelectionValue, newSelectionValue, oldSelection.Replicas, newSelection.Replicas);
                if (proof.IssuedAtUnixSeconds < oldSelectionValue.IssuedAtUnixSeconds ||
                    proof.IssuedAtUnixSeconds > oldSelectionValue.ExpiresAtUnixSeconds)
                    throw Error(ProductionMailboxSelectionSuccessorError.InvalidValidityWindow,
                        "Direct PSS1 issuance must also be contained in the old PMS1 window.");
                break;
            case ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint:
                VerifyOfflineCheckpoint(proof, oldAuthorityValue, newAuthorityValue,
                    oldTopologyValue, newTopologyValue, oldSelectionValue, newSelectionValue,
                    frozenContext.NowUnixSeconds);
                break;
            default:
                throw Error(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                    "PSS1 transition mode is unsupported.");
        }

        var newKey = newAuthorityValue.MailboxIssuerEd25519PublicKey.ToArray();
        var newSignature = proof.NewIssuerSignature.ToArray();
        var newSigningBytes = ProductionMailboxSelectionSuccessorCodec.GetNewIssuerSigningBytes(proof);
        if (proof.Mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion)
        {
            var oldKey = oldAuthorityValue.MailboxIssuerEd25519PublicKey.ToArray();
            var oldSignature = proof.OldIssuerSignature.ToArray();
            var oldSigningBytes =
                ProductionMailboxSelectionSuccessorCodec.GetOldIssuerSigningBytes(proof);
            if (!successorSignatureVerifier.Verify(oldKey, oldSigningBytes, oldSignature))
                throw Error(ProductionMailboxSelectionSuccessorError.InvalidOldIssuerSignature,
                    "PSS1 old-issuer signature is invalid.");
        }
        if (!successorSignatureVerifier.Verify(newKey, newSigningBytes, newSignature))
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidNewIssuerSignature,
                "PSS1 new-issuer signature is invalid.");
        return new VerifiedProductionMailboxSelectionSuccessor(
            proof, SHA256.HashData(frozenBytes), oldSelection, newSelection);
    }

    private static VerifiedProductionMailboxAuthority VerifyEmbeddedNewAuthority(
        ProductionMailboxSelectionSuccessorProof proof,
        VerifiedProductionMailboxAuthority oldAuthority,
        ProductionMailboxSelectionSuccessorVerificationContext context,
        IProductionMailboxAuthoritySignatureVerifier signatureVerifier)
    {
        var old = oldAuthority.Authority;
        return proof.Mode switch
        {
            ProductionMailboxSelectionSuccessorMode.DirectPromotion =>
                ProductionMailboxAuthorityVerifier.Verify(
                    ProductionMailboxAuthorityCodec.Decode(proof.CanonicalNewAuthority.Span),
                    new ProductionMailboxAuthorityVerificationContext
                    {
                        PinnedMrXPublicKeySha256 = context.PinnedMrXPublicKeySha256,
                        ExpectedNetworkId = context.ExpectedNetworkId,
                        LastCommittedGeneration = old.AuthorityGeneration,
                        LastCommittedAuthorityHash = oldAuthority.CanonicalAuthorityHash,
                        LastCommittedRevocationGeneration = old.Revocation.Generation,
                        LastCommittedRevocationHeadHash = old.Revocation.HeadHash,
                        LastCommittedRevocationSnapshotHash = old.Revocation.SnapshotHash,
                        NowUnixSeconds = context.NowUnixSeconds,
                        ClockSkewSeconds = context.ClockSkewSeconds
                    }, signatureVerifier),
            ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint =>
                ProductionMailboxAuthorityVerifier.VerifyForwardCheckpoint(
                    proof.CanonicalNewAuthority.Span,
                    new ProductionMailboxAuthorityCheckpointVerificationContext
                    {
                        PinnedMrXPublicKeySha256 = context.PinnedMrXPublicKeySha256,
                        ExpectedNetworkId = context.ExpectedNetworkId,
                        LastCommittedGeneration = old.AuthorityGeneration,
                        LastCommittedRevocationGeneration = old.Revocation.Generation,
                        LastCommittedRevocationHeadHash = old.Revocation.HeadHash,
                        LastCommittedRevocationSnapshotHash = old.Revocation.SnapshotHash,
                        NowUnixSeconds = context.NowUnixSeconds,
                        ClockSkewSeconds = context.ClockSkewSeconds
                    }, signatureVerifier),
            _ => throw Error(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                "PSS1 transition mode is unsupported.")
        };
    }

    private static void VerifyDirectPromotion(
        ProductionMailboxSelectionSuccessorProof proof,
        ProductionMailboxAuthority oldAuthority,
        ReadOnlySpan<byte> oldAuthorityHash,
        ProductionMailboxAuthority newAuthority,
        ProductionMailboxTopologySnapshot oldTopology,
        ReadOnlySpan<byte> oldTopologyHash,
        ProductionMailboxTopologySnapshot newTopology,
        ProductionMailboxSelectionProof oldSelection,
        ProductionMailboxSelectionProof newSelection,
        IReadOnlyList<VerifiedProductionMailboxSelectedReplica> oldReplicas,
        IReadOnlyList<VerifiedProductionMailboxSelectedReplica> newReplicas)
    {
        if (oldAuthority.AuthorityGeneration == ulong.MaxValue ||
            newAuthority.AuthorityGeneration != oldAuthority.AuthorityGeneration + 1)
            throw Error(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
                "Direct PSS1 requires the exact next PMA1 generation.");
        Equal(newAuthority.PreviousAuthorityHash.Span, oldAuthorityHash,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            "Direct PSS1 new PMA1 does not name the exact old PMA1 hash.");
        if (oldTopology.TopologyGeneration == ulong.MaxValue ||
            newTopology.TopologyGeneration != oldTopology.TopologyGeneration + 1)
            throw Error(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
                "Direct PSS1 requires the exact next PMT1 generation.");
        Equal(newTopology.PreviousTopologyHash.Span, oldTopologyHash,
            ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
            "Direct PSS1 new PMT1 does not name the exact old PMT1 hash.");
        BindPromotedEpoch(oldAuthority.NextEpoch, newAuthority.CurrentEpoch);
        if (proof.OldEpoch != oldAuthority.NextEpoch.Epoch ||
            proof.OldEpochGeneration != oldAuthority.NextEpoch.Generation ||
            proof.NewEpoch != newAuthority.CurrentEpoch.Epoch ||
            proof.NewEpochGeneration != newAuthority.CurrentEpoch.Generation ||
            oldSelection.Epoch != oldTopology.NextEpoch.Epoch ||
            newSelection.Epoch != newTopology.CurrentEpoch.Epoch)
            throw Error(ProductionMailboxSelectionSuccessorError.EpochMismatch,
                "Direct PSS1 must bridge old-next to the identical new-current epoch.");
        BindDirectSelectionRoute(oldSelection, newSelection);
        BindDirectResolvedReplicas(oldReplicas, newReplicas);
    }

    private static void RejectTerminalDirectClosure(
        ProductionMailboxAuthority oldAuthority,
        ProductionMailboxAuthority newAuthority,
        ProductionMailboxTopologySnapshot oldTopology,
        ProductionMailboxTopologySnapshot newTopology)
    {
        if (oldAuthority.Revocation.Generation == ulong.MaxValue ||
            newAuthority.Revocation.Generation == ulong.MaxValue)
            throw Error(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
                "Direct PSS1 cannot commit a terminal revocation generation.");
        if (oldTopology.TopologyGeneration == ulong.MaxValue ||
            newTopology.TopologyGeneration == ulong.MaxValue)
            throw Error(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
                "Direct PSS1 cannot commit a terminal topology generation.");
    }

    private static byte[] FreezeBounded(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < ProductionMailboxSelectionSuccessorConstants.FixedCoreLength +
                ProductionMailboxSelectionSuccessorConstants.SignatureBytes ||
            encoded.Length > ProductionMailboxSelectionSuccessorConstants.MaximumArtifactBytes)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength,
                "PSS1 length is outside its strict bounds.");
        return encoded.ToArray();
    }

    private static void VerifyOfflineCheckpoint(
        ProductionMailboxSelectionSuccessorProof proof,
        ProductionMailboxAuthority oldAuthority,
        ProductionMailboxAuthority newAuthority,
        ProductionMailboxTopologySnapshot oldTopology,
        ProductionMailboxTopologySnapshot newTopology,
        ProductionMailboxSelectionProof oldSelection,
        ProductionMailboxSelectionProof newSelection,
        ulong nowUnixSeconds)
    {
        var authorityAdvance = ForwardAdvance(oldAuthority.AuthorityGeneration,
            newAuthority.AuthorityGeneration,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor, "PMA1");
        var topologyAdvance = ForwardAdvance(oldTopology.TopologyGeneration,
            newTopology.TopologyGeneration,
            ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor, "PMT1");
        if (authorityAdvance == 1 && topologyAdvance == 1)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                "A one-generation transition must use direct-promotion mode.");
        if (newSelection.Epoch != newTopology.CurrentEpoch.Epoch ||
            newSelection.Generation != newTopology.CurrentEpoch.Generation ||
            newSelection.Epoch <= oldSelection.Epoch ||
            newSelection.Generation <= oldSelection.Generation)
            throw Error(ProductionMailboxSelectionSuccessorError.EpochMismatch,
                "Offline PSS1 must advance the durable old epoch to the current epoch.");
        if (oldSelection.Epoch != oldTopology.NextEpoch.Epoch ||
            oldSelection.Generation != oldTopology.NextEpoch.Generation)
            throw Error(ProductionMailboxSelectionSuccessorError.EpochMismatch,
                "Offline PSS1 durable old selection must be the retained old-next PMS1.");
        BindStableRoute(oldSelection, newSelection);
        if (nowUnixSeconds < oldSelection.IssuedAtUnixSeconds ||
            nowUnixSeconds - oldSelection.IssuedAtUnixSeconds >
                ProductionMailboxSelectionSuccessorConstants.MaximumOfflineCheckpointAgeSeconds)
            throw Error(ProductionMailboxSelectionSuccessorError.CheckpointAnchorExpired,
                "Offline PSS1 old PMS1 anchor is older than the 365-day policy.");
        if (proof.IssuedAtUnixSeconds < nowUnixSeconds &&
            nowUnixSeconds - proof.IssuedAtUnixSeconds >
                ProductionMailboxSelectionSuccessorConstants.MaximumLifetimeSeconds)
            throw Error(ProductionMailboxSelectionSuccessorError.Expired,
                "Offline PSS1 checkpoint is not fresh.");
    }

    private static ulong ForwardAdvance(ulong oldGeneration, ulong newGeneration,
        ProductionMailboxSelectionSuccessorError error, string name)
    {
        if (newGeneration <= oldGeneration)
            throw Error(error,
                $"Offline PSS1 {name} generation does not move forward.");
        return newGeneration - oldGeneration;
    }

    private static void BindPromotedEpoch(
        ProductionMailboxAuthorityEpoch oldNext,
        ProductionMailboxAuthorityEpoch newCurrent)
    {
        if (oldNext.Epoch != newCurrent.Epoch || oldNext.Generation != newCurrent.Generation ||
            oldNext.NotBeforeUnixSeconds != newCurrent.NotBeforeUnixSeconds ||
            oldNext.NotAfterUnixSeconds != newCurrent.NotAfterUnixSeconds)
            throw Error(ProductionMailboxSelectionSuccessorError.EpochMismatch,
                "PMA1 old-next and new-current epoch metadata differ.");
        Equal(oldNext.MembershipCommitment.Span, newCurrent.MembershipCommitment.Span,
            ProductionMailboxSelectionSuccessorError.EpochMismatch,
            "PMA1 promoted membership commitment differs.");
        Equal(oldNext.TopologyPlacementCommitment.Span, newCurrent.TopologyPlacementCommitment.Span,
            ProductionMailboxSelectionSuccessorError.EpochMismatch,
            "PMA1 promoted topology placement commitment differs.");
    }

    private static void BindTopologyClosure(
        ProductionMailboxTopologySnapshot topology,
        ProductionMailboxAuthority authority,
        ReadOnlySpan<byte> authorityHash,
        string name)
    {
        Equal(topology.NetworkId.Span, authority.NetworkId.Span,
            ProductionMailboxSelectionSuccessorError.NetworkMismatch,
            $"PSS1 {name} PMT1 network does not match PMA1.");
        if (topology.AuthorityGeneration != authority.AuthorityGeneration)
            throw Error(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
                $"PSS1 {name} PMT1 authority generation does not match PMA1.");
        Equal(topology.CanonicalAuthorityHash.Span, authorityHash,
            ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
            $"PSS1 {name} PMT1 authority hash does not match PMA1.");
    }

    private static void BindDirectSelectionRoute(
        ProductionMailboxSelectionProof oldSelection,
        ProductionMailboxSelectionProof newSelection)
    {
        Equal(oldSelection.MembershipCommitment.Span, newSelection.MembershipCommitment.Span,
            ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            "PMS1 membership commitment changed during promotion.");
        Equal(oldSelection.TopologyPlacementCommitment.Span, newSelection.TopologyPlacementCommitment.Span,
            ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            "PMS1 topology placement commitment changed during promotion.");
        Equal(oldSelection.MailboxPlacementCommitment.Span, newSelection.MailboxPlacementCommitment.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch,
            "PMS1 mailbox placement commitment changed during promotion.");
        Equal(oldSelection.SelectionInputCommitment.Span, newSelection.SelectionInputCommitment.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch,
            "PMS1 selection input changed during promotion.");
        if (oldSelection.Replicas.Count != ProductionMailboxTopologyConstants.ReplicaCount ||
            newSelection.Replicas.Count != ProductionMailboxTopologyConstants.ReplicaCount)
            throw Error(ProductionMailboxSelectionSuccessorError.ReplicaRouteMismatch,
                "PMS1 replica count changed during promotion.");
        for (var i = 0; i < ProductionMailboxTopologyConstants.ReplicaCount; i++)
        {
            Equal(oldSelection.Replicas[i].ReplicaId.Span, newSelection.Replicas[i].ReplicaId.Span,
                ProductionMailboxSelectionSuccessorError.ReplicaRouteMismatch,
                "PMS1 replica identity/order changed during promotion.");
            Equal(oldSelection.Replicas[i].CanonicalMIP1Proof.Span,
                newSelection.Replicas[i].CanonicalMIP1Proof.Span,
                ProductionMailboxSelectionSuccessorError.ReplicaRouteMismatch,
                "PMS1 replica membership proof changed during promotion.");
        }
    }

    private static void BindStableRoute(
        ProductionMailboxSelectionProof oldSelection,
        ProductionMailboxSelectionProof newSelection)
    {
        Equal(oldSelection.MailboxPlacementCommitment.Span, newSelection.MailboxPlacementCommitment.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch,
            "PMS1 mailbox placement commitment changed across checkpoint.");
        Equal(oldSelection.SelectionInputCommitment.Span, newSelection.SelectionInputCommitment.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch,
            "PMS1 selection input changed across checkpoint.");
    }

    private static void BindDirectResolvedReplicas(
        IReadOnlyList<VerifiedProductionMailboxSelectedReplica> oldReplicas,
        IReadOnlyList<VerifiedProductionMailboxSelectedReplica> newReplicas)
    {
        if (oldReplicas.Count != ProductionMailboxTopologyConstants.ReplicaCount ||
            newReplicas.Count != ProductionMailboxTopologyConstants.ReplicaCount)
            throw Error(ProductionMailboxSelectionSuccessorError.ReplicaRouteMismatch,
                "Resolved PMS1 replica count changed during promotion.");
        for (var i = 0; i < ProductionMailboxTopologyConstants.ReplicaCount; i++)
        {
            Equal(oldReplicas[i].ReplicaId.Span, newReplicas[i].ReplicaId.Span,
                ProductionMailboxSelectionSuccessorError.ReplicaRouteMismatch,
                "Resolved replica identity changed during promotion.");
            if (!StringComparer.Ordinal.Equals(
                    oldReplicas[i].HttpsEndpoint.AbsoluteUri,
                    newReplicas[i].HttpsEndpoint.AbsoluteUri))
                throw Error(ProductionMailboxSelectionSuccessorError.ReplicaRouteMismatch,
                    "Resolved replica endpoint changed during promotion.");
            var unchanged = FixedEqual(oldReplicas[i].CurrentSpkiSha256.Span,
                    newReplicas[i].CurrentSpkiSha256.Span) &&
                FixedEqual(oldReplicas[i].NextSpkiSha256.Span,
                    newReplicas[i].NextSpkiSha256.Span);
            var promoted = FixedEqual(oldReplicas[i].NextSpkiSha256.Span,
                    newReplicas[i].CurrentSpkiSha256.Span) &&
                !FixedEqual(oldReplicas[i].CurrentSpkiSha256.Span,
                    newReplicas[i].NextSpkiSha256.Span);
            if (!unchanged && !promoted)
                throw Error(ProductionMailboxSelectionSuccessorError.ReplicaRouteMismatch,
                    "Resolved SPKI pins neither overlap unchanged nor promote old-next to new-current.");
        }
    }

    private static bool FixedEqual(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static ProductionMailboxSelectionSuccessorVerificationContext Freeze(
        ProductionMailboxSelectionSuccessorVerificationContext context) => context with
    {
        ExpectedNetworkId = context.ExpectedNetworkId.ToArray(),
        ExpectedMailboxOwnerEd25519PublicKey = context.ExpectedMailboxOwnerEd25519PublicKey.ToArray(),
        ExpectedBlindedMailboxId = context.ExpectedBlindedMailboxId.ToArray(),
        ExpectedBlindedPlacementId = context.ExpectedBlindedPlacementId.ToArray(),
        PinnedMrXPublicKeySha256 = context.PinnedMrXPublicKeySha256.ToArray(),
        ExpectedOldCanonicalSelectionHash = context.ExpectedOldCanonicalSelectionHash.ToArray()
    };

    private static void ValidateContextLengths(
        ProductionMailboxSelectionSuccessorVerificationContext context)
    {
        if (context.ExpectedNetworkId.Length != 16 ||
            context.ExpectedMailboxOwnerEd25519PublicKey.Length != 32 ||
            context.ExpectedBlindedMailboxId.Length != 32 ||
            context.ExpectedBlindedPlacementId.Length != 32 ||
            context.PinnedMrXPublicKeySha256.Length != 32 ||
            context.ExpectedOldCanonicalSelectionHash.Length != 32)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField,
                "PSS1 verification context field length is invalid.");
    }

    private static void ValidateContext(ProductionMailboxSelectionSuccessorVerificationContext context)
    {
        FixedNonzero(context.ExpectedNetworkId, 16, "expected network ID");
        FixedNonzero(context.ExpectedMailboxOwnerEd25519PublicKey, 32, "expected mailbox owner key");
        FixedNonzero(context.ExpectedBlindedMailboxId, 32, "expected blinded mailbox ID");
        FixedNonzero(context.ExpectedBlindedPlacementId, 32, "expected blinded placement ID");
        FixedNonzero(context.PinnedMrXPublicKeySha256, 32, "pinned Mr. X public-key hash");
        FixedNonzero(context.ExpectedOldCanonicalSelectionHash, 32, "expected old PMS1 hash");
        if (context.NowUnixSeconds == 0 ||
            context.ClockSkewSeconds > ProductionMailboxSelectionSuccessorConstants.MaximumClockSkewSeconds)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField,
                "PSS1 verification time is incomplete or unsafe.");
    }

    private static void VerifyWindow(ulong from, ulong until, ulong now, uint skew, string name)
    {
        if (now < from && from - now > skew)
            throw Error(ProductionMailboxSelectionSuccessorError.NotYetValid, $"{name} is not yet valid.");
        if (now > until && now - until > skew)
            throw Error(ProductionMailboxSelectionSuccessorError.Expired, $"{name} has expired.");
    }

    private static void FixedNonzero(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField, $"{name} is invalid.");
    }

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected,
        ProductionMailboxSelectionSuccessorError error, string message)
    {
        if (actual.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw Error(error, message);
    }

    private static ProductionMailboxSelectionSuccessorException Error(
        ProductionMailboxSelectionSuccessorError error,
        string message) => new(error, message);
}
