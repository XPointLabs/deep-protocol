using System.Security.Cryptography;
using System.Buffers.Binary;
using System.Text;
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

    internal static VerifiedProductionMailboxSelectionSuccessor VerifyOfflineCheckpoint(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority oldAuthority,
        VerifiedProductionMailboxTopology oldTopology,
        ReadOnlySpan<byte> canonicalNewTopology,
        ProductionMailboxSelectionSuccessorVerificationContext context,
        IProductionMailboxAuthoritySignatureVerifier authoritySignatureVerifier,
        IProductionMailboxTopologySignatureVerifier topologySignatureVerifier,
        IProductionMailboxSelectionSuccessorSignatureVerifier successorSignatureVerifier)
    {
        var frozenEncoded = FreezeBounded(encoded);
        var frozenTopology = FreezeArtifact(canonicalNewTopology, 1,
            ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes, "PMT1");
        return VerifyOfflineCheckpointComponents(frozenEncoded, oldAuthority, oldTopology,
            frozenTopology, context, authoritySignatureVerifier,
            topologySignatureVerifier, successorSignatureVerifier).Successor;
    }

    public static VerifiedProductionMailboxOfflineCheckpointClosure VerifyOfflineCheckpointClosure(
        ReadOnlySpan<byte> encodedSuccessor,
        ReadOnlySpan<byte> canonicalNewAuthority,
        ReadOnlySpan<byte> canonicalNewRevocationSnapshot,
        ReadOnlySpan<byte> canonicalNewTopology,
        ReadOnlySpan<byte> canonicalOldSelection,
        ReadOnlySpan<byte> canonicalNewCurrentSelection,
        ReadOnlySpan<byte> canonicalNewNextSelection,
        VerifiedProductionMailboxAuthority oldAuthority,
        VerifiedProductionMailboxTopology oldTopology,
        ProductionMailboxOfflineCheckpointClosureVerificationContext context)
        => VerifyOfflineCheckpointClosureCore(
            encodedSuccessor, canonicalNewAuthority, canonicalNewRevocationSnapshot,
            canonicalNewTopology, canonicalOldSelection, canonicalNewCurrentSelection,
            canonicalNewNextSelection, oldAuthority, oldTopology, context,
            new SodiumProductionMailboxAuthoritySignatureVerifier(),
            new SodiumProductionMailboxRevocationSnapshotSignatureVerifier(),
            new SodiumProductionMailboxTopologySignatureVerifier(),
            new SodiumProductionMailboxSelectionSuccessorSignatureVerifier());

    internal static VerifiedProductionMailboxOfflineCheckpointClosure
        VerifyOfflineCheckpointClosureCore(
        ReadOnlySpan<byte> encodedSuccessor,
        ReadOnlySpan<byte> canonicalNewAuthority,
        ReadOnlySpan<byte> canonicalNewRevocationSnapshot,
        ReadOnlySpan<byte> canonicalNewTopology,
        ReadOnlySpan<byte> canonicalOldSelection,
        ReadOnlySpan<byte> canonicalNewCurrentSelection,
        ReadOnlySpan<byte> canonicalNewNextSelection,
        VerifiedProductionMailboxAuthority oldAuthority,
        VerifiedProductionMailboxTopology oldTopology,
        ProductionMailboxOfflineCheckpointClosureVerificationContext context,
        IProductionMailboxAuthoritySignatureVerifier authoritySignatureVerifier,
        IProductionMailboxRevocationSnapshotSignatureVerifier revocationSignatureVerifier,
        IProductionMailboxTopologySignatureVerifier topologySignatureVerifier,
        IProductionMailboxSelectionSuccessorSignatureVerifier successorSignatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(oldAuthority);
        ArgumentNullException.ThrowIfNull(oldTopology);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(authoritySignatureVerifier);
        ArgumentNullException.ThrowIfNull(revocationSignatureVerifier);
        ArgumentNullException.ThrowIfNull(topologySignatureVerifier);
        ArgumentNullException.ThrowIfNull(successorSignatureVerifier);

        ValidateClosureContextLengths(context);
        var frozenContext = Freeze(context);
        ValidateClosureContext(frozenContext);
        PreflightClosureArtifacts(encodedSuccessor, canonicalNewAuthority,
            canonicalNewRevocationSnapshot, canonicalNewTopology, canonicalOldSelection,
            canonicalNewCurrentSelection, canonicalNewNextSelection);
        var frozenSuccessor = encodedSuccessor.ToArray();
        var frozenAuthority = canonicalNewAuthority.ToArray();
        var frozenRevocations = canonicalNewRevocationSnapshot.ToArray();
        var frozenTopology = canonicalNewTopology.ToArray();
        var frozenOldSelection = canonicalOldSelection.ToArray();
        var frozenCurrentSelection = canonicalNewCurrentSelection.ToArray();
        var frozenNextSelection = canonicalNewNextSelection.ToArray();
        PreflightClosureArtifacts(frozenSuccessor, frozenAuthority, frozenRevocations,
            frozenTopology, frozenOldSelection, frozenCurrentSelection, frozenNextSelection);

        var proof = ProductionMailboxSelectionSuccessorCodec.Decode(frozenSuccessor);
        if (proof.Mode != ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                "This entry point accepts offline-checkpoint PSS1 only.");
        Equal(proof.CanonicalNewAuthority.Span, frozenAuthority,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            "PSS1 embedded PMA1 differs from the supplied complete closure.");
        Equal(proof.OldCanonicalSelection.Span, frozenOldSelection,
            ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            "PSS1 historical PMS1 differs from the caller's exact durable bytes.");
        Equal(proof.NewCanonicalSelection.Span, frozenCurrentSelection,
            ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            "PSS1 current PMS1 differs from the supplied complete closure.");
        Equal(SHA256.HashData(frozenOldSelection),
            frozenContext.ExpectedOldCanonicalSelectionHash.Span,
            ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            "Historical PMS1 hash differs from the protected LKG.");
        VerifyOldLkg(oldAuthority, oldTopology, frozenContext);

        var successorContext = new ProductionMailboxSelectionSuccessorVerificationContext
        {
            ExpectedNetworkId = frozenContext.ExpectedNetworkId,
            ExpectedMailboxOwnerEd25519PublicKey =
                frozenContext.ExpectedMailboxOwnerEd25519PublicKey,
            ExpectedBlindedMailboxId = frozenContext.ExpectedBlindedMailboxId,
            ExpectedBlindedPlacementId = frozenContext.ExpectedBlindedPlacementId,
            PinnedMrXPublicKeySha256 = frozenContext.PinnedMrXPublicKeySha256,
            ExpectedOldCanonicalSelectionHash =
                frozenContext.ExpectedOldCanonicalSelectionHash,
            NowUnixSeconds = frozenContext.VerifiedAtUnixSeconds,
            ClockSkewSeconds = frozenContext.ClockSkewSeconds
        };
        var components = VerifyOfflineCheckpointComponents(
            frozenSuccessor, oldAuthority, oldTopology, frozenTopology,
            successorContext, authoritySignatureVerifier, topologySignatureVerifier,
            successorSignatureVerifier);
        Equal(components.Authority.CanonicalAuthorityHash.Span, SHA256.HashData(frozenAuthority),
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            "Verified PMA1 hash differs from the complete closure.");
        Equal(components.Topology.CanonicalTopologyHash.Span, SHA256.HashData(frozenTopology),
            ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
            "Verified PMT1 hash differs from the complete closure.");
        Equal(components.Successor.NewSelection.CanonicalSelectionHash.Span,
            SHA256.HashData(frozenCurrentSelection),
            ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            "Verified current PMS1 hash differs from the complete closure.");

        VerifiedProductionMailboxRevocationSnapshot revocations;
        VerifiedProductionMailboxSelection nextSelection;
        try
        {
            revocations = ProductionMailboxRevocationSnapshotVerifier.Verify(
                frozenRevocations, components.Authority,
                frozenContext.VerifiedAtUnixSeconds, frozenContext.ClockSkewSeconds,
                revocationSignatureVerifier);
            nextSelection = ProductionMailboxSelectionVerifier.Verify(
                frozenNextSelection, components.Authority, components.Topology,
                new BlindedPlacementId(frozenContext.ExpectedBlindedPlacementId.Span),
                frozenContext.VerifiedAtUnixSeconds, frozenContext.ClockSkewSeconds,
                topologySignatureVerifier);
        }
        catch (ProductionMailboxRevocationSnapshotException ex)
        {
            throw Error(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
                $"Offline checkpoint PMR1 is invalid: {ex.Message}");
        }
        catch (ProductionMailboxTopologyException ex)
        {
            throw Error(ProductionMailboxSelectionSuccessorError.SelectionMismatch,
                $"Offline checkpoint next PMS1 is invalid: {ex.Message}");
        }
        var authorityValue = components.Authority.Authority;
        var topologyValue = components.Topology.Snapshot;
        if (nextSelection.Proof.Epoch != authorityValue.NextEpoch.Epoch ||
            nextSelection.Proof.Generation != authorityValue.NextEpoch.Generation ||
            nextSelection.Proof.Epoch != topologyValue.NextEpoch.Epoch ||
            nextSelection.Proof.Generation != topologyValue.NextEpoch.Generation)
            throw Error(ProductionMailboxSelectionSuccessorError.EpochMismatch,
                "Offline checkpoint next PMS1 is bound to the wrong epoch.");

        var anchor = new ProductionMailboxOfflineCheckpointCommitAnchor(
            frozenContext.PinnedMrXPublicKeySha256.Span,
            frozenContext.ExpectedNetworkId.Span,
            authorityValue.AuthorityGeneration,
            components.Authority.CanonicalAuthorityHash.Span,
            authorityValue.Revocation.Generation,
            authorityValue.Revocation.HeadHash.Span,
            authorityValue.Revocation.SnapshotHash.Span,
            topologyValue.TopologyGeneration,
            components.Topology.CanonicalTopologyHash.Span,
            components.Successor.NewSelection.CanonicalSelectionHash.Span,
            nextSelection.CanonicalSelectionHash.Span,
            frozenContext.VerifiedAtUnixSeconds);
        var transcript = BuildClosureTranscript(frozenSuccessor, frozenAuthority,
            frozenRevocations, frozenTopology, frozenOldSelection, frozenCurrentSelection,
            frozenNextSelection, frozenContext, anchor);
        return new VerifiedProductionMailboxOfflineCheckpointClosure(
            components.Successor, components.Authority, revocations, components.Topology,
            components.Successor.NewSelection, nextSelection, anchor,
            frozenSuccessor, frozenAuthority, frozenRevocations, frozenTopology,
            frozenOldSelection, frozenCurrentSelection, frozenNextSelection,
            transcript, SHA256.HashData(transcript));
    }

    private static OfflineCheckpointComponents VerifyOfflineCheckpointComponents(
        byte[] frozenEncoded,
        VerifiedProductionMailboxAuthority oldAuthority,
        VerifiedProductionMailboxTopology oldTopology,
        byte[] frozenNewTopology,
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
            currentTopology = ProductionMailboxTopologyVerifier.VerifyForwardCheckpointOwned(
                frozenNewTopology, currentAuthority,
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
        var successor = VerifyCore(frozenEncoded, oldAuthority, oldTopology, currentAuthority,
            currentTopology, frozenContext, authoritySignatureVerifier, topologySignatureVerifier,
            successorSignatureVerifier);
        return new OfflineCheckpointComponents(successor, currentAuthority, currentTopology);
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

    private static void PreflightClosureArtifacts(
        ReadOnlySpan<byte> successor,
        ReadOnlySpan<byte> authority,
        ReadOnlySpan<byte> revocations,
        ReadOnlySpan<byte> topology,
        ReadOnlySpan<byte> oldSelection,
        ReadOnlySpan<byte> currentSelection,
        ReadOnlySpan<byte> nextSelection)
    {
        // Check every scalar length before copying even the first field. A malformed late field
        // must not cause earlier multi-megabyte artifacts to be cloned.
        if (successor.Length < ProductionMailboxSelectionSuccessorConstants.FixedCoreLength +
                ProductionMailboxSelectionSuccessorConstants.SignatureBytes ||
            successor.Length > ProductionMailboxSelectionSuccessorConstants.MaximumArtifactBytes ||
            authority.Length is < 1 or > ProductionMailboxAuthorityConstants.MaximumArtifactBytes ||
            revocations.Length <
                ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials ||
            revocations.Length > ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes ||
            topology.Length is < 780 or >
                ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes ||
            oldSelection.Length is < 1 or >
                ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            currentSelection.Length is < 1 or >
                ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            nextSelection.Length is < 1 or >
                ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength,
                "Offline checkpoint closure artifact length is outside its strict bounds.");

        PreflightRevocationSnapshot(revocations);
        PreflightTopology(topology);
    }

    private static void PreflightRevocationSnapshot(ReadOnlySpan<byte> encoded)
    {
        const int countOffset = 152;
        var count = BinaryPrimitives.ReadUInt16LittleEndian(encoded.Slice(countOffset, 2));
        var expectedLength = checked(
            ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials +
            count * ProductionMailboxRevocationSnapshotConstants.RevokedGrantSerialBytes);
        if (count > ProductionMailboxRevocationSnapshotConstants.MaximumRevokedGrantSerials ||
            encoded.Length != expectedLength)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength,
                "PMR1 length does not match its bounded serial count.");
    }

    private static void PreflightTopology(ReadOnlySpan<byte> encoded)
    {
        var offset = 120;
        for (var epoch = 0; epoch < 2; epoch++)
        {
            SkipTopology(encoded, ref offset, 96);
            var count = ReadTopologyUInt16(encoded, ref offset);
            SkipTopology(encoded, ref offset, 2);
            if (count is < 2 or > ProductionMailboxTopologyConstants.MaximumNodesPerEpoch)
                throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength,
                    "PMT1 node count is outside its strict bounds.");
            for (var node = 0; node < count; node++)
            {
                SkipTopology(encoded, ref offset, 32);
                var endpointLength = ReadTopologyUInt16(encoded, ref offset);
                if (endpointLength is < 1 or > ProductionMailboxTopologyConstants.MaximumEndpointBytes)
                    throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength,
                        "PMT1 endpoint length is outside its strict bounds.");
                SkipTopology(encoded, ref offset, checked(endpointLength + 64));
            }
        }
        SkipTopology(encoded, ref offset, 64);
        if (offset != encoded.Length)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength,
                "PMT1 length does not match its bounded structure.");
    }

    private static ushort ReadTopologyUInt16(ReadOnlySpan<byte> encoded, ref int offset)
    {
        SkipTopology(encoded, ref offset, 2, advance: false);
        var value = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset, 2));
        offset += 2;
        return value;
    }

    private static void SkipTopology(
        ReadOnlySpan<byte> encoded, ref int offset, int count, bool advance = true)
    {
        if (offset < 0 || count < 0 || offset > encoded.Length - count)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength,
                "PMT1 is truncated or its count-derived length overflows.");
        if (advance) offset = checked(offset + count);
    }

    private static byte[] FreezeArtifact(
        ReadOnlySpan<byte> encoded, int minimumLength, int maximumLength, string name)
    {
        if (encoded.Length < minimumLength || encoded.Length > maximumLength)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength,
                $"{name} length is outside its strict bounds.");
        return encoded.ToArray();
    }

    private static void VerifyOldLkg(
        VerifiedProductionMailboxAuthority oldAuthority,
        VerifiedProductionMailboxTopology oldTopology,
        ProductionMailboxOfflineCheckpointClosureVerificationContext context)
    {
        var authority = oldAuthority.Authority;
        var topology = oldTopology.Snapshot;
        Equal(authority.NetworkId.Span, context.ExpectedNetworkId.Span,
            ProductionMailboxSelectionSuccessorError.NetworkMismatch,
            "Protected old PMA1 belongs to another network.");
        Equal(SHA256.HashData(authority.MrXApprovalEd25519PublicKey.Span),
            context.PinnedMrXPublicKeySha256.Span,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            "Protected old PMA1 is not rooted in the pinned Mr. X key.");
        if (authority.AuthorityGeneration != context.ExpectedOldAuthorityGeneration ||
            authority.Revocation.Generation != context.ExpectedOldRevocationGeneration)
            throw Error(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
                "Protected old PMA1 generation differs from the exact LKG.");
        Equal(oldAuthority.CanonicalAuthorityHash.Span,
            context.ExpectedOldCanonicalAuthorityHash.Span,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            "Protected old PMA1 hash differs from the exact LKG.");
        Equal(authority.Revocation.HeadHash.Span,
            context.ExpectedOldRevocationHeadHash.Span,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            "Protected old revocation head differs from the exact LKG.");
        Equal(authority.Revocation.SnapshotHash.Span,
            context.ExpectedOldRevocationSnapshotHash.Span,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            "Protected old revocation snapshot differs from the exact LKG.");
        if (topology.TopologyGeneration != context.ExpectedOldTopologyGeneration)
            throw Error(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
                "Protected old PMT1 generation differs from the exact LKG.");
        Equal(oldTopology.CanonicalTopologyHash.Span,
            context.ExpectedOldCanonicalTopologyHash.Span,
            ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
            "Protected old PMT1 hash differs from the exact LKG.");
        Equal(topology.NetworkId.Span, context.ExpectedNetworkId.Span,
            ProductionMailboxSelectionSuccessorError.NetworkMismatch,
            "Protected old PMT1 belongs to another network.");
        if (topology.AuthorityGeneration != authority.AuthorityGeneration)
            throw Error(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
                "Protected old PMT1 is not coupled to the protected old PMA1.");
        Equal(topology.CanonicalAuthorityHash.Span,
            oldAuthority.CanonicalAuthorityHash.Span,
            ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
            "Protected old PMT1 names another PMA1 hash.");
        var expectedSelectionInput = ProductionMailboxReplicaSelection
            .ComputeSelectionInputCommitment(
                new BlindedPlacementId(context.ExpectedBlindedPlacementId.Span));
        Equal(expectedSelectionInput, context.ExpectedSelectionInputCommitment.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch,
            "Protected route selection input differs from its placement.");
    }

    private static byte[] BuildClosureTranscript(
        ReadOnlySpan<byte> successor,
        ReadOnlySpan<byte> authority,
        ReadOnlySpan<byte> revocations,
        ReadOnlySpan<byte> topology,
        ReadOnlySpan<byte> oldSelection,
        ReadOnlySpan<byte> currentSelection,
        ReadOnlySpan<byte> nextSelection,
        ProductionMailboxOfflineCheckpointClosureVerificationContext context,
        ProductionMailboxOfflineCheckpointCommitAnchor anchor)
    {
        using var stream = new MemoryStream();
        stream.Write("POC1"u8);
        stream.WriteByte(1);
        WriteFramed(stream, successor);
        WriteFramed(stream, authority);
        WriteFramed(stream, revocations);
        WriteFramed(stream, topology);
        WriteFramed(stream, oldSelection);
        WriteFramed(stream, currentSelection);
        WriteFramed(stream, nextSelection);
        WriteFramed(stream, context.ExpectedNetworkId.Span);
        WriteFramed(stream, context.ExpectedMailboxOwnerEd25519PublicKey.Span);
        WriteFramed(stream, context.ExpectedBlindedMailboxId.Span);
        WriteFramed(stream, context.ExpectedBlindedPlacementId.Span);
        WriteFramed(stream, context.ExpectedSelectionInputCommitment.Span);
        WriteFramed(stream, context.PinnedMrXPublicKeySha256.Span);
        WriteUInt64(stream, context.ExpectedOldAuthorityGeneration);
        WriteFramed(stream, context.ExpectedOldCanonicalAuthorityHash.Span);
        WriteUInt64(stream, context.ExpectedOldRevocationGeneration);
        WriteFramed(stream, context.ExpectedOldRevocationHeadHash.Span);
        WriteFramed(stream, context.ExpectedOldRevocationSnapshotHash.Span);
        WriteUInt64(stream, context.ExpectedOldTopologyGeneration);
        WriteFramed(stream, context.ExpectedOldCanonicalTopologyHash.Span);
        WriteFramed(stream, context.ExpectedOldCanonicalSelectionHash.Span);
        WriteUInt64(stream, context.VerifiedAtUnixSeconds);
        WriteUInt32(stream, context.ClockSkewSeconds);
        WriteFramed(stream, anchor.MrXPublicKeySha256.Span);
        WriteFramed(stream, anchor.NetworkId.Span);
        WriteUInt64(stream, anchor.AuthorityGeneration);
        WriteFramed(stream, anchor.AuthorityHash.Span);
        WriteUInt64(stream, anchor.RevocationGeneration);
        WriteFramed(stream, anchor.RevocationHeadHash.Span);
        WriteFramed(stream, anchor.RevocationSnapshotHash.Span);
        WriteUInt64(stream, anchor.TopologyGeneration);
        WriteFramed(stream, anchor.TopologyHash.Span);
        WriteFramed(stream, anchor.CurrentSelectionHash.Span);
        WriteFramed(stream, anchor.NextSelectionHash.Span);
        WriteUInt64(stream, anchor.VerifiedAtUnixSeconds);
        return stream.ToArray();
    }

    private static void WriteFramed(Stream stream, ReadOnlySpan<byte> value)
    {
        WriteUInt32(stream, checked((uint)value.Length));
        stream.Write(value);
    }

    private static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> encoded = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(encoded, value);
        stream.Write(encoded);
    }

    private static void WriteUInt64(Stream stream, ulong value)
    {
        Span<byte> encoded = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        stream.Write(encoded);
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

    private static ProductionMailboxOfflineCheckpointClosureVerificationContext Freeze(
        ProductionMailboxOfflineCheckpointClosureVerificationContext context) => context with
    {
        ExpectedNetworkId = context.ExpectedNetworkId.ToArray(),
        ExpectedMailboxOwnerEd25519PublicKey =
            context.ExpectedMailboxOwnerEd25519PublicKey.ToArray(),
        ExpectedBlindedMailboxId = context.ExpectedBlindedMailboxId.ToArray(),
        ExpectedBlindedPlacementId = context.ExpectedBlindedPlacementId.ToArray(),
        ExpectedSelectionInputCommitment = context.ExpectedSelectionInputCommitment.ToArray(),
        PinnedMrXPublicKeySha256 = context.PinnedMrXPublicKeySha256.ToArray(),
        ExpectedOldCanonicalAuthorityHash =
            context.ExpectedOldCanonicalAuthorityHash.ToArray(),
        ExpectedOldRevocationHeadHash = context.ExpectedOldRevocationHeadHash.ToArray(),
        ExpectedOldRevocationSnapshotHash = context.ExpectedOldRevocationSnapshotHash.ToArray(),
        ExpectedOldCanonicalTopologyHash = context.ExpectedOldCanonicalTopologyHash.ToArray(),
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

    private static void ValidateClosureContextLengths(
        ProductionMailboxOfflineCheckpointClosureVerificationContext context)
    {
        if (context.ExpectedNetworkId.Length != 16 ||
            context.ExpectedMailboxOwnerEd25519PublicKey.Length != 32 ||
            context.ExpectedBlindedMailboxId.Length != 32 ||
            context.ExpectedBlindedPlacementId.Length != 32 ||
            context.ExpectedSelectionInputCommitment.Length != 32 ||
            context.PinnedMrXPublicKeySha256.Length != 32 ||
            context.ExpectedOldCanonicalAuthorityHash.Length != 32 ||
            context.ExpectedOldRevocationHeadHash.Length != 32 ||
            context.ExpectedOldRevocationSnapshotHash.Length != 32 ||
            context.ExpectedOldCanonicalTopologyHash.Length != 32 ||
            context.ExpectedOldCanonicalSelectionHash.Length != 32)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField,
                "Offline checkpoint closure context field length is invalid.");
    }

    private static void ValidateClosureContext(
        ProductionMailboxOfflineCheckpointClosureVerificationContext context)
    {
        FixedNonzero(context.ExpectedNetworkId, 16, "expected network ID");
        FixedNonzero(context.ExpectedMailboxOwnerEd25519PublicKey, 32,
            "expected mailbox owner key");
        FixedNonzero(context.ExpectedBlindedMailboxId, 32, "expected blinded mailbox ID");
        FixedNonzero(context.ExpectedBlindedPlacementId, 32,
            "expected blinded placement ID");
        FixedNonzero(context.ExpectedSelectionInputCommitment, 32,
            "expected selection input commitment");
        FixedNonzero(context.PinnedMrXPublicKeySha256, 32,
            "pinned Mr. X public-key hash");
        FixedNonzero(context.ExpectedOldCanonicalAuthorityHash, 32,
            "expected old PMA1 hash");
        FixedNonzero(context.ExpectedOldRevocationHeadHash, 32,
            "expected old revocation head hash");
        FixedNonzero(context.ExpectedOldRevocationSnapshotHash, 32,
            "expected old revocation snapshot hash");
        FixedNonzero(context.ExpectedOldCanonicalTopologyHash, 32,
            "expected old PMT1 hash");
        FixedNonzero(context.ExpectedOldCanonicalSelectionHash, 32,
            "expected old PMS1 hash");
        if (context.ExpectedOldAuthorityGeneration == 0 ||
            context.ExpectedOldRevocationGeneration == 0 ||
            context.ExpectedOldTopologyGeneration == 0 ||
            context.VerifiedAtUnixSeconds == 0 ||
            context.ClockSkewSeconds >
                ProductionMailboxSelectionSuccessorConstants.MaximumClockSkewSeconds)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField,
                "Offline checkpoint closure context is incomplete or unsafe.");
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

    private readonly record struct OfflineCheckpointComponents(
        VerifiedProductionMailboxSelectionSuccessor Successor,
        VerifiedProductionMailboxAuthority Authority,
        VerifiedProductionMailboxTopology Topology);
}
