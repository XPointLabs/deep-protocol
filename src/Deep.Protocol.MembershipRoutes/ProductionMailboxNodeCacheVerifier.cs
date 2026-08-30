using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

/// <summary>
/// Verifies an exact bounded PMC2 node-cache aggregate with production sodium. The result is only
/// evidence for caching: no RCD/RDA/RCR input is accepted and no full client activation capability
/// is returned.
/// </summary>
public static class ProductionMailboxNodeCacheVerifier
{
    public const int MaximumAggregateBytes = 8 * 1024 * 1024;
    private static ReadOnlySpan<byte> TranscriptDomain =>
        "Deep/production-mailbox/node-cache-transcript/v2"u8;

    public static VerifiedProductionMailboxNodeCacheClosure Verify(
        ProductionMailboxNodeCacheArtifacts artifacts,
        ProductionMailboxNodeCacheVerificationContext context) =>
        VerifyCore(artifacts, context,
            new SodiumProductionMailboxAuthoritySignatureVerifier(),
            new SodiumProductionMailboxRevocationSnapshotSignatureVerifier(),
            new SodiumProductionMailboxTopologySignatureVerifier(),
            new SodiumProductionMailboxSelectionSuccessorSignatureVerifier(),
            new SodiumProductionMailboxRouteSignatureVerifier());

    internal static VerifiedProductionMailboxNodeCacheClosure VerifyCore(
        ProductionMailboxNodeCacheArtifacts artifacts,
        ProductionMailboxNodeCacheVerificationContext context,
        IProductionMailboxAuthoritySignatureVerifier authorityVerifier,
        IProductionMailboxRevocationSnapshotSignatureVerifier revocationVerifier,
        IProductionMailboxTopologySignatureVerifier topologyVerifier,
        IProductionMailboxSelectionSuccessorSignatureVerifier successorVerifier,
        IProductionMailboxRouteSignatureVerifier routeVerifier)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.ControlPlane);
        ArgumentNullException.ThrowIfNull(authorityVerifier);
        ArgumentNullException.ThrowIfNull(revocationVerifier);
        ArgumentNullException.ThrowIfNull(topologyVerifier);
        ArgumentNullException.ThrowIfNull(successorVerifier);
        ArgumentNullException.ThrowIfNull(routeVerifier);
        Preflight(artifacts, context);
        var frozen = ProductionMailboxNodeCacheCopy.Clone(artifacts);
        var frozenContext = context with
        {
            ExpectedRouteDomainHash = context.ExpectedRouteDomainHash.ToArray(),
            ControlPlane = Freeze(context.ControlPlane)
        };
        Preflight(frozen, frozenContext);

        var pss = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            frozen.CanonicalSelectionSuccessorV2.Span);
        var closure = VerifyCurrentClosure(frozen, pss, frozenContext.ControlPlane,
            authorityVerifier, revocationVerifier, topologyVerifier, successorVerifier);
        var authority = closure.Authority;
        var revocations = closure.Revocations;
        var certificate = ProductionMailboxRouteCertificateVerifier.Verify(
            frozen.CanonicalRouteCertificate.Span, authority,
            frozenContext.ControlPlane.VerifiedAtUnixSeconds,
            frozenContext.ControlPlane.ClockSkewSeconds, routeVerifier);
        var routeDomain = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(
            certificate.Certificate);
        Equal(routeDomain, frozenContext.ExpectedRouteDomainHash.Span,
            "PMC2 PRC1 route-domain mismatch.");

        var rtcBytes = frozen.CanonicalTransitionContext.ToArray();
        var rtc = ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(rtcBytes);
        VerifyRtc(rtc, rtcBytes, pss, closure, authority, frozenContext);

        ulong authorizationFrom;
        ulong authorizationExpires;
        if (frozen.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
        {
            if (!frozen.CanonicalRevocationCheckpoint.IsEmpty ||
                rtc.CanonicalRevocationCheckpointHash.Span.IndexOfAnyExcept((byte)0) >= 0 ||
                rtc.TransitionSalt.Span.IndexOfAnyExcept((byte)0) >= 0 ||
                rtc.ContinuityTransitionCommitment.Span.IndexOfAnyExcept((byte)0) >= 0)
                throw new FormatException("PMC2 owner authorization carries delegated-only state.");
            var owner = ProductionMailboxRouteAuthorizationVerifier.VerifyOwnerAuthorization(
                frozen.CanonicalRouteAuthorization.Span, authority,
                new ProductionMailboxOwnerRouteAuthorizationVerificationContext
                {
                    ExpectedNetworkId = frozenContext.ControlPlane.ExpectedNetworkId.ToArray(),
                    ExpectedRouteDomainHash = frozenContext.ExpectedRouteDomainHash.ToArray(),
                    ExpectedPredecessorKind = rtc.PredecessorAuthorizationKind,
                    ExpectedPredecessorHash = rtc.PredecessorCanonicalRouteAuthorizationHash.ToArray(),
                    ExpectedPredecessorSequence = rtc.PredecessorRouteAuthorizationSequence,
                    NowUnixSeconds = frozenContext.ControlPlane.VerifiedAtUnixSeconds,
                    ClockSkewSeconds = frozenContext.ControlPlane.ClockSkewSeconds
                }, routeVerifier);
            Equal(ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
                    owner.Advertisement.Certificate), frozen.CanonicalRouteCertificate.Span,
                "PMC2 PRA2 does not embed the exact supplied PRC1 bytes.");
            authorizationFrom = owner.Advertisement.PublishedAtUnixSeconds;
            authorizationExpires = owner.Advertisement.ExpiresAtUnixSeconds;
        }
        else if (frozen.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
        {
            var checkpoint = VerifyNodeCheckpoint(frozen.CanonicalRevocationCheckpoint.Span,
                authority, revocations, rtc, frozenContext, routeVerifier);
            (authorizationFrom, authorizationExpires) = VerifyNodeActivation(
                frozen.CanonicalRouteAuthorization.Span,
                authority, revocations, certificate, checkpoint, rtc,
                frozenContext, routeVerifier);
        }
        else
            throw new FormatException("PMC2 authorization tag is invalid.");

        var authorizationHash = SHA256.HashData(frozen.CanonicalRouteAuthorization.Span);
        var certificateHash = SHA256.HashData(frozen.CanonicalRouteCertificate.Span);
        var rtcHash = ProductionMailboxRouteAuthorizationCodec.ComputeTransitionContextHash(rtc);
        var checkpointHash = frozen.CanonicalRevocationCheckpoint.IsEmpty
            ? new byte[32]
            : SHA256.HashData(frozen.CanonicalRevocationCheckpoint.Span);
        if (pss.NewAuthorizationKind != frozen.AuthorizationKind ||
            pss.PredecessorAuthorizationKind != rtc.PredecessorAuthorizationKind ||
            pss.PredecessorRouteAuthorizationSequence != rtc.PredecessorRouteAuthorizationSequence ||
            pss.NewRouteAuthorizationSequence != rtc.NewRouteAuthorizationSequence)
            throw new FormatException("PMC2 PSS2/RTC1 authorization tags or sequences differ.");
        Equal(pss.PredecessorCanonicalRouteAuthorizationHash.Span,
            rtc.PredecessorCanonicalRouteAuthorizationHash.Span,
            "PMC2 PSS2/RTC1 predecessor hash mismatch.");
        Equal(pss.FreshCanonicalRouteCertificateHash.Span, certificateHash,
            "PMC2 PSS2 PRC1 hash mismatch.");
        Equal(rtc.FreshCanonicalRouteCertificateHash.Span, certificateHash,
            "PMC2 RTC1 PRC1 hash mismatch.");
        Equal(pss.NewCanonicalRouteAuthorizationHash.Span, authorizationHash,
            "PMC2 PSS2 authorization hash mismatch.");
        Equal(pss.CanonicalTransitionContextHash.Span, rtcHash,
            "PMC2 PSS2 RTC1 hash mismatch.");
        Equal(pss.CanonicalRevocationCheckpointHash.Span, checkpointHash,
            "PMC2 PSS2 RCH1 hash mismatch.");
        Equal(rtc.CanonicalRevocationCheckpointHash.Span, checkpointHash,
            "PMC2 RTC1 RCH1 hash mismatch.");
        ProductionMailboxSelectionSuccessorVerifier.VerifyRouteSelectionContainment(
            pss.Selection, rtc, authorizationFrom, authorizationExpires,
            authority.Authority, revocations.Snapshot, closure.Topology.Snapshot);

        var expires = Min(authorizationExpires, rtc.ExpiresAtUnixSeconds,
            certificate.Certificate.ExpiresAtUnixSeconds, pss.Selection.ExpiresAtUnixSeconds,
            closure.CurrentSelection.Proof.ExpiresAtUnixSeconds,
            closure.NextSelection.Proof.ExpiresAtUnixSeconds,
            closure.Topology.Snapshot.ExpiresAtUnixSeconds,
            closure.Revocations.Snapshot.ExpiresAtUnixSeconds);
        var transcriptHash = BuildTranscriptHash(frozen);
        return new VerifiedProductionMailboxNodeCacheClosure(frozen, expires, transcriptHash)
        { Mode = pss.Selection.Mode };
    }

    private static NodeCacheCurrentClosure VerifyCurrentClosure(
        ProductionMailboxNodeCacheArtifacts artifacts,
        ProductionMailboxSelectionSuccessorV2Proof pss,
        ProductionMailboxNodeCacheControlPlaneContext context,
        IProductionMailboxAuthoritySignatureVerifier authorityVerifier,
        IProductionMailboxRevocationSnapshotSignatureVerifier revocationVerifier,
        IProductionMailboxTopologySignatureVerifier topologyVerifier,
        IProductionMailboxSelectionSuccessorSignatureVerifier successorVerifier)
    {
        var proof = pss.Selection;
        Equal(proof.CanonicalNewAuthority.Span, artifacts.CanonicalAuthority.Span,
            "PMC2 PSS2 embedded PMA1 differs from the supplied bytes.");
        Equal(proof.NewCanonicalSelection.Span, artifacts.CanonicalCurrentSelection.Span,
            "PMC2 PSS2 embedded current PMS1 differs from the supplied bytes.");
        Equal(SHA256.HashData(proof.OldCanonicalSelection.Span),
            context.ExpectedOldCanonicalSelectionHash.Span,
            "PMC2 PSS2 old PMS1 differs from protected state.");
        Equal(proof.NetworkId.Span, context.ExpectedNetworkId.Span, "PMC2 PSS2 network mismatch.");
        Equal(proof.MailboxOwnerEd25519PublicKey.Span,
            context.ExpectedMailboxOwnerEd25519PublicKey.Span, "PMC2 PSS2 owner mismatch.");
        Equal(proof.BlindedMailboxId.Span, context.ExpectedBlindedMailboxId.Span,
            "PMC2 PSS2 mailbox mismatch.");
        Equal(proof.BlindedPlacementId.Span, context.ExpectedBlindedPlacementId.Span,
            "PMC2 PSS2 placement mismatch.");
        Equal(proof.SelectionInputCommitment.Span, context.ExpectedSelectionInputCommitment.Span,
            "PMC2 PSS2 selection input mismatch.");
        Equal(proof.OldCanonicalAuthorityHash.Span, context.ExpectedOldCanonicalAuthorityHash.Span,
            "PMC2 PSS2 old PMA1 hash mismatch.");
        Equal(proof.OldCanonicalTopologyHash.Span, context.ExpectedOldCanonicalTopologyHash.Span,
            "PMC2 PSS2 old PMT1 hash mismatch.");
        if (proof.OldTopologyGeneration != context.ExpectedOldTopologyGeneration)
            throw new FormatException("PMC2 PSS2 old PMT1 generation mismatch.");

        VerifiedProductionMailboxAuthority authority;
        if (proof.Mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion)
        {
            if (proof.OldIssuerSignature.Span.IndexOfAnyExcept((byte)0) < 0)
                throw new FormatException("PMC2 direct PSS2 has an empty retired-issuer signature slot.");
            authority = ProductionMailboxAuthorityVerifier.Verify(
                ProductionMailboxAuthorityCodec.Decode(artifacts.CanonicalAuthority.Span),
                new ProductionMailboxAuthorityVerificationContext
                {
                    PinnedMrXPublicKeySha256 = context.PinnedMrXPublicKeySha256.ToArray(),
                    ExpectedNetworkId = context.ExpectedNetworkId.ToArray(),
                    LastCommittedGeneration = context.ExpectedOldAuthorityGeneration,
                    LastCommittedAuthorityHash = context.ExpectedOldCanonicalAuthorityHash.ToArray(),
                    LastCommittedRevocationGeneration = context.ExpectedOldRevocationGeneration,
                    LastCommittedRevocationHeadHash = context.ExpectedOldRevocationHeadHash.ToArray(),
                    LastCommittedRevocationSnapshotHash =
                        context.ExpectedOldRevocationSnapshotHash.ToArray(),
                    NowUnixSeconds = context.VerifiedAtUnixSeconds,
                    ClockSkewSeconds = context.ClockSkewSeconds
                }, authorityVerifier);
        }
        else if (proof.Mode == ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint)
        {
            if (proof.OldIssuerSignature.Span.IndexOfAnyExcept((byte)0) >= 0)
                throw new FormatException("PMC2 offline PSS2 has a non-zero retired-issuer slot.");
            authority = ProductionMailboxAuthorityVerifier.VerifyForwardCheckpoint(
                artifacts.CanonicalAuthority.Span,
                new ProductionMailboxAuthorityCheckpointVerificationContext
                {
                    PinnedMrXPublicKeySha256 = context.PinnedMrXPublicKeySha256.ToArray(),
                    ExpectedNetworkId = context.ExpectedNetworkId.ToArray(),
                    LastCommittedGeneration = context.ExpectedOldAuthorityGeneration,
                    LastCommittedRevocationGeneration = context.ExpectedOldRevocationGeneration,
                    LastCommittedRevocationHeadHash = context.ExpectedOldRevocationHeadHash.ToArray(),
                    LastCommittedRevocationSnapshotHash =
                        context.ExpectedOldRevocationSnapshotHash.ToArray(),
                    NowUnixSeconds = context.VerifiedAtUnixSeconds,
                    ClockSkewSeconds = context.ClockSkewSeconds
                }, authorityVerifier);
        }
        else
            throw new FormatException("PMC2 PSS2 transition mode is invalid.");

        VerifiedProductionMailboxTopology topology = proof.Mode ==
            ProductionMailboxSelectionSuccessorMode.DirectPromotion
            ? ProductionMailboxTopologyVerifier.Verify(artifacts.CanonicalTopology.Span, authority,
                new ProductionMailboxTopologyVerificationContext
                {
                    LastCommittedTopologyGeneration = context.ExpectedOldTopologyGeneration,
                    LastCommittedTopologyHash = context.ExpectedOldCanonicalTopologyHash.ToArray(),
                    NowUnixSeconds = context.VerifiedAtUnixSeconds,
                    ClockSkewSeconds = context.ClockSkewSeconds
                }, topologyVerifier)
            : ProductionMailboxTopologyVerifier.VerifyForwardCheckpoint(
                artifacts.CanonicalTopology.Span, authority,
                new ProductionMailboxTopologyCheckpointVerificationContext
                {
                    LastCommittedTopologyGeneration = context.ExpectedOldTopologyGeneration,
                    NowUnixSeconds = context.VerifiedAtUnixSeconds,
                    ClockSkewSeconds = context.ClockSkewSeconds
                }, topologyVerifier);
        var revocations = ProductionMailboxRevocationSnapshotVerifier.Verify(
            artifacts.CanonicalRevocations.Span, authority, context.VerifiedAtUnixSeconds,
            context.ClockSkewSeconds, revocationVerifier);
        var placement = new BlindedPlacementId(context.ExpectedBlindedPlacementId.Span);
        var current = ProductionMailboxSelectionVerifier.Verify(
            artifacts.CanonicalCurrentSelection.Span, authority, topology, placement,
            context.VerifiedAtUnixSeconds, context.ClockSkewSeconds, topologyVerifier);
        var decodedNext = ProductionMailboxTopologyCodec.DecodeSelection(
            artifacts.CanonicalNextSelection.Span);
        var nextVerificationTime = Math.Max(context.VerifiedAtUnixSeconds,
            decodedNext.IssuedAtUnixSeconds);
        var next = ProductionMailboxSelectionVerifier.Verify(
            artifacts.CanonicalNextSelection.Span, authority, topology, placement,
            nextVerificationTime, context.ClockSkewSeconds, topologyVerifier);

        Equal(proof.NewCanonicalAuthorityHash.Span, authority.CanonicalAuthorityHash.Span,
            "PMC2 PSS2 new PMA1 hash mismatch.");
        Equal(proof.NewCanonicalTopologyHash.Span, topology.CanonicalTopologyHash.Span,
            "PMC2 PSS2 new PMT1 hash mismatch.");
        Equal(proof.NewCanonicalSelectionHash.Span, current.CanonicalSelectionHash.Span,
            "PMC2 PSS2 current PMS1 hash mismatch.");
        if (proof.NewTopologyGeneration != topology.Snapshot.TopologyGeneration ||
            proof.NewEpoch != current.Proof.Epoch || proof.NewEpochGeneration != current.Proof.Generation ||
            current.Proof.Epoch != topology.Snapshot.CurrentEpoch.Epoch ||
            next.Proof.Epoch != topology.Snapshot.NextEpoch.Epoch ||
            proof.IssuedAtUnixSeconds < current.Proof.IssuedAtUnixSeconds ||
            proof.IssuedAtUnixSeconds < next.Proof.IssuedAtUnixSeconds ||
            proof.ExpiresAtUnixSeconds > current.Proof.ExpiresAtUnixSeconds ||
            proof.ExpiresAtUnixSeconds > next.Proof.ExpiresAtUnixSeconds)
            throw new FormatException("PMC2 PSS2 current/next PMS1 closure is inconsistent.");
        if (!successorVerifier.Verify(authority.Authority.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxSelectionSuccessorV2Codec.GetCurrentIssuerSigningBytes(pss),
                proof.NewIssuerSignature.Span))
            throw new FormatException("PMC2 PSS2 current-issuer signature is invalid.");
        return new(authority, revocations, topology, current, next);
    }

    private sealed record NodeCacheCurrentClosure(
        VerifiedProductionMailboxAuthority Authority,
        VerifiedProductionMailboxRevocationSnapshot Revocations,
        VerifiedProductionMailboxTopology Topology,
        VerifiedProductionMailboxSelection CurrentSelection,
        VerifiedProductionMailboxSelection NextSelection);

    private static void VerifyRtc(
        ProductionMailboxRouteTransitionContext rtc,
        ReadOnlySpan<byte> rtcBytes,
        ProductionMailboxSelectionSuccessorV2Proof pss,
        NodeCacheCurrentClosure closure,
        VerifiedProductionMailboxAuthority authority,
        ProductionMailboxNodeCacheVerificationContext context)
    {
        if (rtc.Mode != pss.Selection.Mode ||
            rtc.NewAuthorizationKind != pss.NewAuthorizationKind)
            throw new FormatException("PMC2 RTC1 transition mode or authorization kind is invalid.");
        Equal(rtc.NetworkId.Span, context.ControlPlane.ExpectedNetworkId.Span,
            "PMC2 RTC1 network mismatch.");
        Equal(rtc.RouteDomainHash.Span, context.ExpectedRouteDomainHash.Span,
            "PMC2 RTC1 route-domain mismatch.");
        Equal(rtc.OldCanonicalSelectionHash.Span,
            SHA256.HashData(pss.Selection.OldCanonicalSelection.Span),
            "PMC2 RTC1 old PMS1 hash mismatch.");
        Equal(rtc.NewCanonicalSelectionHash.Span,
            closure.CurrentSelection.CanonicalSelectionHash.Span,
            "PMC2 RTC1 current PMS1 hash mismatch.");
        Equal(rtc.CurrentCanonicalAuthorityHash.Span, authority.CanonicalAuthorityHash.Span,
            "PMC2 RTC1 PMA1 hash mismatch.");
        if (rtc.CurrentAuthorityGeneration != authority.Authority.AuthorityGeneration)
            throw new FormatException("PMC2 RTC1 PMA1 generation mismatch.");
        ProductionMailboxRouteAuthorizationVerifier.VerifyLive(rtc.NotBeforeUnixSeconds,
            rtc.ExpiresAtUnixSeconds, context.ControlPlane.VerifiedAtUnixSeconds,
            context.ControlPlane.ClockSkewSeconds, "PMC2 RTC1");
        Equal(ProductionMailboxRouteAuthorizationCodec.EncodeTransitionContext(rtc), rtcBytes,
            "PMC2 RTC1 is not canonical.");
    }

    private static ProductionMailboxRouteRevocationCheckpoint VerifyNodeCheckpoint(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxRevocationSnapshot revocations,
        ProductionMailboxRouteTransitionContext rtc,
        ProductionMailboxNodeCacheVerificationContext context,
        IProductionMailboxRouteSignatureVerifier verifier)
    {
        var frozen = encoded.ToArray();
        var value = ProductionMailboxRouteContinuityCodec.DecodeRevocationCheckpoint(frozen);
        var pma = authority.Authority;
        var pmr = revocations.Snapshot;
        Equal(value.NetworkId.Span, context.ControlPlane.ExpectedNetworkId.Span,
            "PMC2 RCH1 network mismatch.");
        Equal(value.RouteDomainHash.Span, context.ExpectedRouteDomainHash.Span,
            "PMC2 RCH1 route mismatch.");
        Equal(value.CurrentCanonicalAuthorityHash.Span, authority.CanonicalAuthorityHash.Span,
            "PMC2 RCH1 PMA1 hash mismatch.");
        Equal(value.CurrentIssuerEd25519PublicKey.Span, pma.MailboxIssuerEd25519PublicKey.Span,
            "PMC2 RCH1 issuer mismatch.");
        Equal(value.TransitionSalt.Span, rtc.TransitionSalt.Span, "PMC2 RCH1 salt mismatch.");
        Equal(value.ContinuityTransitionCommitment.Span, rtc.ContinuityTransitionCommitment.Span,
            "PMC2 RCH1 commitment mismatch.");
        if (value.CurrentAuthorityGeneration != pma.AuthorityGeneration ||
            pmr.AuthorityGeneration != pma.AuthorityGeneration ||
            pmr.RevocationGeneration != pma.Revocation.Generation ||
            value.Status != ProductionMailboxRouteRevocationStatus.Active ||
            value.CurrentOwnerRevocationGeneration != 0 ||
            value.CurrentOwnerRevocationHeadHash.Span.IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException("PMC2 RCH1 authority/revocation state is invalid.");
        ProductionMailboxRouteAuthorizationVerifier.VerifyLive(value.IssuedAtUnixSeconds,
            value.ExpiresAtUnixSeconds, context.ControlPlane.VerifiedAtUnixSeconds,
            context.ControlPlane.ClockSkewSeconds, "PMC2 RCH1");
        Contained(value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds,
            pma.MrXApproval.RolloutNotBeforeUnixSeconds, pma.MrXApproval.RolloutNotAfterUnixSeconds,
            "PMC2 RCH1/PMA1 rollout");
        Contained(value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds,
            pmr.IssuedAtUnixSeconds, pmr.ExpiresAtUnixSeconds, "PMC2 RCH1/PMR1");
        if (!verifier.Verify(pma.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxRouteContinuityCodec.GetRevocationCheckpointSigningBytes(value),
                value.CurrentIssuerSignature.Span))
            throw new FormatException("PMC2 RCH1 current-issuer signature is invalid.");
        return value;
    }

    private static (ulong IssuedAt, ulong ExpiresAt) VerifyNodeActivation(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxRevocationSnapshot revocations,
        VerifiedProductionMailboxRouteCertificate certificate,
        ProductionMailboxRouteRevocationCheckpoint checkpoint,
        ProductionMailboxRouteTransitionContext rtc,
        ProductionMailboxNodeCacheVerificationContext context,
        IProductionMailboxRouteSignatureVerifier verifier)
    {
        var frozen = encoded.ToArray();
        var value = ProductionMailboxRouteAuthorizationCodec.DecodeContinuityActivation(frozen);
        var pma = authority.Authority;
        var pmr = revocations.Snapshot;
        var prc = certificate.Certificate;
        Equal(value.NetworkId.Span, context.ControlPlane.ExpectedNetworkId.Span, "PMC2 RCA1 network mismatch.");
        Equal(value.RouteDomainHash.Span, context.ExpectedRouteDomainHash.Span, "PMC2 RCA1 route mismatch.");
        Equal(value.CurrentCanonicalAuthorityHash.Span, authority.CanonicalAuthorityHash.Span,
            "PMC2 RCA1 PMA1 mismatch.");
        Equal(value.CurrentIssuerEd25519PublicKey.Span, pma.MailboxIssuerEd25519PublicKey.Span,
            "PMC2 RCA1 issuer mismatch.");
        Equal(value.CurrentRevocationHeadHash.Span, pmr.RevocationHeadHash.Span,
            "PMC2 RCA1 PMR1 head mismatch.");
        Equal(value.CurrentRevocationSnapshotHash.Span, revocations.CanonicalSnapshotHash.Span,
            "PMC2 RCA1 PMR1 snapshot mismatch.");
        Equal(value.TransitionSalt.Span, checkpoint.TransitionSalt.Span, "PMC2 RCA1 salt mismatch.");
        Equal(value.ContinuityTransitionCommitment.Span, checkpoint.ContinuityTransitionCommitment.Span,
            "PMC2 RCA1 commitment mismatch.");
        Equal(value.CanonicalRevocationCheckpointHash.Span,
            SHA256.HashData(ProductionMailboxRouteContinuityCodec.EncodeRevocationCheckpoint(checkpoint)),
            "PMC2 RCA1 RCH1 mismatch.");
        Equal(value.FreshCanonicalRouteCertificateHash.Span, certificate.CanonicalCertificateHash.Span,
            "PMC2 RCA1 PRC1 mismatch.");
        Equal(value.CanonicalTransitionContextHash.Span,
            ProductionMailboxRouteAuthorizationCodec.ComputeTransitionContextHash(rtc),
            "PMC2 RCA1 RTC1 mismatch.");
        Equal(value.PredecessorCanonicalRouteAuthorizationHash.Span,
            rtc.PredecessorCanonicalRouteAuthorizationHash.Span,
            "PMC2 RCA1 predecessor mismatch.");
        Equal(prc.MailboxOwnerEd25519PublicKey.Span,
            context.ControlPlane.ExpectedMailboxOwnerEd25519PublicKey.Span, "PMC2 PRC1 owner mismatch.");
        Equal(prc.BlindedMailboxId.Span, context.ControlPlane.ExpectedBlindedMailboxId.Span,
            "PMC2 PRC1 mailbox mismatch.");
        Equal(prc.BlindedPlacementId.Span, context.ControlPlane.ExpectedBlindedPlacementId.Span,
            "PMC2 PRC1 placement mismatch.");
        Equal(prc.SelectionInputCommitment.Span, context.ControlPlane.ExpectedSelectionInputCommitment.Span,
            "PMC2 PRC1 selection input mismatch.");
        if (value.CurrentAuthorityGeneration != pma.AuthorityGeneration ||
            value.CurrentRevocationGeneration != pmr.RevocationGeneration ||
            value.PredecessorAuthorizationKind != rtc.PredecessorAuthorizationKind ||
            value.PredecessorRouteAuthorizationSequence != rtc.PredecessorRouteAuthorizationSequence ||
            value.ActivationSequence != rtc.NewRouteAuthorizationSequence ||
            rtc.NewAuthorizationKind != ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            throw new FormatException("PMC2 RCA1 scalar bindings are invalid.");
        ProductionMailboxRouteAuthorizationVerifier.VerifyLive(value.IssuedAtUnixSeconds,
            value.ExpiresAtUnixSeconds, context.ControlPlane.VerifiedAtUnixSeconds,
            context.ControlPlane.ClockSkewSeconds, "PMC2 RCA1");
        Contained(rtc.NotBeforeUnixSeconds, rtc.ExpiresAtUnixSeconds,
            value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds, "PMC2 RTC1/RCA1");
        Contained(value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds,
            checkpoint.IssuedAtUnixSeconds, checkpoint.ExpiresAtUnixSeconds, "PMC2 RCA1/RCH1");
        Contained(value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds,
            prc.IssuedAtUnixSeconds, prc.ExpiresAtUnixSeconds, "PMC2 RCA1/PRC1");
        Contained(value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds,
            pmr.IssuedAtUnixSeconds, pmr.ExpiresAtUnixSeconds, "PMC2 RCA1/PMR1");
        if (!verifier.Verify(pma.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxRouteAuthorizationCodec.GetContinuityActivationSigningBytes(value),
                value.CurrentIssuerSignature.Span))
            throw new FormatException("PMC2 RCA1 current-issuer signature is invalid.");
        return (value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds);
    }

    private static void Preflight(ProductionMailboxNodeCacheArtifacts value,
        ProductionMailboxNodeCacheVerificationContext context)
    {
        if (context.ExpectedRouteDomainHash.Length != 32 || context.ControlPlane is null)
            throw new FormatException("PMC2 verification context is incomplete.");
        PreflightControlPlane(context.ControlPlane);
        if (value.AuthorizationKind is not ProductionMailboxRouteAuthorizationKind.OwnerPRA2 and
            not ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            throw new FormatException("PMC2 authorization tag is invalid.");
        static void Bounded(ReadOnlyMemory<byte> bytes, int maximum, string name)
        {
            if (bytes.Length is <= 0 || bytes.Length > maximum)
                throw new FormatException($"PMC2 {name} length is outside its strict bound.");
        }
        Bounded(value.CanonicalAuthority, ProductionMailboxAuthorityConstants.MaximumArtifactBytes, ProtocolMagic.PMA1);
        Bounded(value.CanonicalRevocations, ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes, ProtocolMagic.PMR1);
        Bounded(value.CanonicalTopology, ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes, ProtocolMagic.PMT1);
        Bounded(value.CanonicalCurrentSelection, ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes,
            "current PMS1");
        Bounded(value.CanonicalNextSelection, ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes,
            "next PMS1");
        Bounded(value.CanonicalSelectionSuccessorV2,
            ProductionMailboxSelectionSuccessorV2Constants.MaximumArtifactBytes, ProtocolMagic.PSS2);
        PreflightPmr(value.CanonicalRevocations.Span);
        PreflightPmt(value.CanonicalTopology.Span);
        PreflightPms(value.CanonicalCurrentSelection.Span, "current PMS1");
        PreflightPms(value.CanonicalNextSelection.Span, "next PMS1");
        PreflightPss(value.CanonicalSelectionSuccessorV2.Span, value.AuthorizationKind);
        if (value.CanonicalRouteCertificate.Length !=
                ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength ||
            value.CanonicalTransitionContext.Length !=
                ProductionMailboxRouteAuthorizationConstants.CanonicalTransitionContextLength)
            throw new FormatException("PMC2 PRC1/RTC1 fixed length is invalid.");
        var delegated = value.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1;
        if (value.CanonicalRouteAuthorization.Length != (delegated
                ? ProductionMailboxRouteAuthorizationConstants.CanonicalContinuityActivationLength
                : ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length) ||
            value.CanonicalRevocationCheckpoint.Length != (delegated
                ? ProductionMailboxRouteContinuityConstants.CanonicalRevocationCheckpointLength
                : 0))
            throw new FormatException("PMC2 tagged route authorization shape is invalid.");
        long total = 0;
        foreach (var bytes in All(value))
            total = checked(total + bytes.Length);
        if (total > MaximumAggregateBytes)
            throw new FormatException("PMC2 aggregate exceeds 8 MiB.");
    }

    private static void PreflightControlPlane(ProductionMailboxNodeCacheControlPlaneContext value)
    {
        static void Fixed(ReadOnlyMemory<byte> bytes, int length, string name)
        {
            if (bytes.Length != length)
                throw new FormatException($"PMC2 control-plane {name} length is invalid.");
        }
        Fixed(value.ExpectedNetworkId, 16, "network");
        Fixed(value.ExpectedMailboxOwnerEd25519PublicKey, 32, "owner");
        Fixed(value.ExpectedBlindedMailboxId, 32, "mailbox");
        Fixed(value.ExpectedBlindedPlacementId, 32, "placement");
        Fixed(value.ExpectedSelectionInputCommitment, 32, "selection input");
        Fixed(value.PinnedMrXPublicKeySha256, 32, "Mr. X pin");
        Fixed(value.ExpectedOldCanonicalAuthorityHash, 32, "old PMA1 hash");
        Fixed(value.ExpectedOldRevocationHeadHash, 32, "old PMR1 head");
        Fixed(value.ExpectedOldRevocationSnapshotHash, 32, "old PMR1 snapshot");
        Fixed(value.ExpectedOldCanonicalTopologyHash, 32, "old PMT1 hash");
        Fixed(value.ExpectedOldCanonicalSelectionHash, 32, "old PMS1 hash");
        if (value.ExpectedOldAuthorityGeneration is 0 or ulong.MaxValue ||
            value.ExpectedOldRevocationGeneration is 0 or ulong.MaxValue ||
            value.ExpectedOldTopologyGeneration is 0 or ulong.MaxValue ||
            value.VerifiedAtUnixSeconds is 0 or ulong.MaxValue ||
            value.ClockSkewSeconds > ProductionMailboxRouteContinuityConstants.MaximumClockSkewSeconds)
            throw new FormatException("PMC2 control-plane scalars are invalid.");
    }

    private static void PreflightPmr(ReadOnlySpan<byte> encoded)
    {
        const int countOffset = 152;
        if (encoded.Length < ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials ||
            !encoded[..4].SequenceEqual(ProtocolMagicBytes.PMR1) ||
            encoded[4] != ProductionMailboxRevocationSnapshotConstants.Version ||
            encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException("PMC2 PMR1 framing is invalid.");
        var count = BinaryPrimitives.ReadUInt16LittleEndian(encoded.Slice(countOffset, 2));
        var expected = checked(ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials +
            count * ProductionMailboxRevocationSnapshotConstants.RevokedGrantSerialBytes);
        if (count > ProductionMailboxRevocationSnapshotConstants.MaximumRevokedGrantSerials ||
            encoded.Length != expected)
            throw new FormatException("PMC2 PMR1 count-derived length is invalid.");
    }

    private static void PreflightPmt(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < 780 || !encoded[..4].SequenceEqual(ProtocolMagicBytes.PMT1) || encoded[4] != 1 ||
            encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException("PMC2 PMT1 framing is invalid.");
        var offset = 120;
        ParsePmtEpoch(encoded, ref offset);
        ParsePmtEpoch(encoded, ref offset);
        if (offset != encoded.Length - 64)
            throw new FormatException("PMC2 PMT1 has truncated or trailing bytes.");
    }

    private static void ParsePmtEpoch(ReadOnlySpan<byte> encoded, ref int offset)
    {
        const int fixedBeforeNodes = 100;
        if (offset > encoded.Length - fixedBeforeNodes - 64)
            throw new FormatException("PMC2 PMT1 epoch header is truncated.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset + 96, 2));
        if (encoded.Slice(offset + 98, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            count is < 2 or > ProductionMailboxTopologyConstants.MaximumNodesPerEpoch)
            throw new FormatException("PMC2 PMT1 epoch count/reserved framing is invalid.");
        offset += fixedBeforeNodes;
        for (var index = 0; index < count; index++)
        {
            const int nodeFixed = 98;
            if (offset > encoded.Length - nodeFixed - 64)
                throw new FormatException("PMC2 PMT1 node header is truncated.");
            var endpointLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset + 32, 2));
            if (endpointLength is 0 or > ProductionMailboxTopologyConstants.MaximumEndpointBytes ||
                offset > encoded.Length - nodeFixed - endpointLength - 64)
                throw new FormatException("PMC2 PMT1 endpoint framing is invalid.");
            offset += nodeFixed + endpointLength;
        }
    }

    private static void PreflightPms(ReadOnlySpan<byte> encoded, string name)
    {
        const int headerLength = 272;
        if (encoded.Length < headerLength + 2 * 36 + 64 || !encoded[..4].SequenceEqual(ProtocolMagicBytes.PMS1) ||
            encoded[4] != 1 || encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded[268] != ProductionMailboxTopologyConstants.ReplicaCount ||
            encoded.Slice(269, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException($"PMC2 {name} framing is invalid.");
        var offset = headerLength;
        for (var index = 0; index < ProductionMailboxTopologyConstants.ReplicaCount; index++)
        {
            if (offset > encoded.Length - 36 - 64)
                throw new FormatException($"PMC2 {name} replica header is truncated.");
            var proofLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset + 32, 2));
            if (encoded.Slice(offset + 34, 2).IndexOfAnyExcept((byte)0) >= 0 || proofLength == 0 ||
                offset > encoded.Length - 36 - proofLength - 64)
                throw new FormatException($"PMC2 {name} replica proof framing is invalid.");
            offset += 36 + proofLength;
        }
        if (offset != encoded.Length - 64)
            throw new FormatException($"PMC2 {name} has truncated or trailing bytes.");
    }

    private static void PreflightPss(ReadOnlySpan<byte> encoded,
        ProductionMailboxRouteAuthorizationKind taggedKind)
    {
        const int lengthsOffset = 408;
        if (encoded.Length < ProductionMailboxSelectionSuccessorV2Constants.FixedCoreLength +
                ProductionMailboxSelectionSuccessorV2Constants.SignatureBytes ||
            !encoded[..4].SequenceEqual(ProtocolMagicBytes.PSS2) ||
            encoded[4] != ProductionMailboxSelectionSuccessorV2Constants.Version ||
            encoded[5] is not (byte)ProductionMailboxSelectionSuccessorMode.DirectPromotion and
                not (byte)ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint ||
            encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(414, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(450, 6).IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException("PMC2 PSS2 header framing is invalid.");
        var authorityLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(lengthsOffset, 2));
        var oldLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(lengthsOffset + 2, 2));
        var currentLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(lengthsOffset + 4, 2));
        var expected = checked(ProductionMailboxSelectionSuccessorV2Constants.FixedCoreLength +
            authorityLength + oldLength + currentLength +
            ProductionMailboxSelectionSuccessorV2Constants.SignatureBytes);
        if (authorityLength is 0 or > ProductionMailboxAuthorityConstants.MaximumArtifactBytes ||
            oldLength is 0 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            currentLength is 0 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            encoded.Length != expected || encoded[449] != (byte)taggedKind)
            throw new FormatException("PMC2 PSS2 count-derived/tagged framing is invalid.");
    }

    private static IEnumerable<ReadOnlyMemory<byte>> All(ProductionMailboxNodeCacheArtifacts value)
    {
        yield return value.CanonicalAuthority;
        yield return value.CanonicalRevocations;
        yield return value.CanonicalTopology;
        yield return value.CanonicalCurrentSelection;
        yield return value.CanonicalNextSelection;
        yield return value.CanonicalSelectionSuccessorV2;
        yield return value.CanonicalRouteCertificate;
        yield return value.CanonicalTransitionContext;
        yield return value.CanonicalRouteAuthorization;
        yield return value.CanonicalRevocationCheckpoint;
    }

    private static ProductionMailboxNodeCacheControlPlaneContext Freeze(
        ProductionMailboxNodeCacheControlPlaneContext value) => value with
    {
        ExpectedNetworkId = value.ExpectedNetworkId.ToArray(),
        ExpectedMailboxOwnerEd25519PublicKey = value.ExpectedMailboxOwnerEd25519PublicKey.ToArray(),
        ExpectedBlindedMailboxId = value.ExpectedBlindedMailboxId.ToArray(),
        ExpectedBlindedPlacementId = value.ExpectedBlindedPlacementId.ToArray(),
        ExpectedSelectionInputCommitment = value.ExpectedSelectionInputCommitment.ToArray(),
        PinnedMrXPublicKeySha256 = value.PinnedMrXPublicKeySha256.ToArray(),
        ExpectedOldCanonicalAuthorityHash = value.ExpectedOldCanonicalAuthorityHash.ToArray(),
        ExpectedOldRevocationHeadHash = value.ExpectedOldRevocationHeadHash.ToArray(),
        ExpectedOldRevocationSnapshotHash = value.ExpectedOldRevocationSnapshotHash.ToArray(),
        ExpectedOldCanonicalTopologyHash = value.ExpectedOldCanonicalTopologyHash.ToArray(),
        ExpectedOldCanonicalSelectionHash = value.ExpectedOldCanonicalSelectionHash.ToArray()
    };

    private static byte[] BuildTranscriptHash(ProductionMailboxNodeCacheArtifacts value)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(TranscriptDomain);
        hash.AppendData([(byte)value.AuthorizationKind]);
        foreach (var bytes in All(value))
            hash.AppendData(SHA256.HashData(bytes.Span));
        return hash.GetHashAndReset();
    }

    private static ulong Min(params ulong[] values) => values.Min();

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string message)
    {
        if (actual.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw new FormatException(message);
    }

    private static void Contained(ulong from, ulong until, ulong parentFrom, ulong parentUntil,
        string name)
    {
        if (from < parentFrom || until > parentUntil)
            throw new FormatException($"{name} lifetime escapes its parent.");
    }
}
