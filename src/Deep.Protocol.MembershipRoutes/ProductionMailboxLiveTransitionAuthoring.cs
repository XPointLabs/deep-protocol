using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

/// <summary>
/// Unified crypto-only live transition factory. Mode and authorization kind are selected by
/// distinct overloads, and RTC1/PRA2-or-RCH1+RCA1/PSS2 drafts are constructed internally.
/// </summary>
public static class ProductionMailboxLiveTransitionAuthoring
{
    public static ValueTask<VerifiedProductionMailboxLiveTransition> AuthorOwnerDirectAsync(
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor currentRoute,
        VerifiedProductionMailboxSelectionTransitionIntent selectionIntent,
        ProductionMailboxLiveTransitionWindow window,
        ProductionMailboxPra2Signer ownerSigner,
        ProductionMailboxPss2OldIssuerSigner oldIssuerSigner,
        ProductionMailboxPss2CurrentIssuerSigner currentIssuerSigner,
        CancellationToken cancellationToken = default) => AuthorOwnerAsync(anchor, currentRoute,
            selectionIntent, window, ProductionMailboxSelectionSuccessorMode.DirectPromotion,
            ownerSigner, oldIssuerSigner, currentIssuerSigner, cancellationToken);

    public static ValueTask<VerifiedProductionMailboxLiveTransition> AuthorOwnerOfflineAsync(
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor currentRoute,
        VerifiedProductionMailboxSelectionTransitionIntent selectionIntent,
        ProductionMailboxLiveTransitionWindow window,
        ProductionMailboxPra2Signer ownerSigner,
        ProductionMailboxPss2CurrentIssuerSigner currentIssuerSigner,
        CancellationToken cancellationToken = default) => AuthorOwnerAsync(anchor, currentRoute,
            selectionIntent, window, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            ownerSigner, null, currentIssuerSigner, cancellationToken);

    public static ValueTask<VerifiedProductionMailboxLiveTransition> AuthorDelegatedDirectAsync(
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor currentRoute,
        VerifiedProductionMailboxSelectionTransitionIntent selectionIntent,
        ProductionMailboxLiveTransitionWindow window,
        ProductionMailboxRch1Signer checkpointSigner,
        ProductionMailboxRca1Signer activationSigner,
        ProductionMailboxPss2OldIssuerSigner oldIssuerSigner,
        ProductionMailboxPss2CurrentIssuerSigner currentIssuerSigner,
        CancellationToken cancellationToken = default) => AuthorDelegatedAsync(anchor, currentRoute,
            selectionIntent, window,
            ProductionMailboxSelectionSuccessorMode.DirectPromotion, checkpointSigner,
            activationSigner, oldIssuerSigner, currentIssuerSigner, cancellationToken);

    public static ValueTask<VerifiedProductionMailboxLiveTransition> AuthorDelegatedOfflineAsync(
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor currentRoute,
        VerifiedProductionMailboxSelectionTransitionIntent selectionIntent,
        ProductionMailboxLiveTransitionWindow window,
        ProductionMailboxRch1Signer checkpointSigner,
        ProductionMailboxRca1Signer activationSigner,
        ProductionMailboxPss2CurrentIssuerSigner currentIssuerSigner,
        CancellationToken cancellationToken = default) => AuthorDelegatedAsync(anchor, currentRoute,
            selectionIntent, window,
            ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint, checkpointSigner,
            activationSigner, null, currentIssuerSigner, cancellationToken);

    private static async ValueTask<VerifiedProductionMailboxLiveTransition> AuthorOwnerAsync(
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor currentRoute,
        VerifiedProductionMailboxSelectionTransitionIntent intent,
        ProductionMailboxLiveTransitionWindow window,
        ProductionMailboxSelectionSuccessorMode expectedMode,
        ProductionMailboxPra2Signer signer,
        ProductionMailboxPss2OldIssuerSigner? oldIssuerSigner,
        ProductionMailboxPss2CurrentIssuerSigner currentIssuerSigner,
        CancellationToken cancellationToken)
    {
        ValidateCommon(anchor, currentRoute, intent, window, expectedMode);
        ArgumentNullException.ThrowIfNull(signer); ArgumentNullException.ThrowIfNull(currentIssuerSigner);
        var oldRolBytes = currentRoute.CanonicalCurrentRouteOriginLkg();
        var oldRol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(oldRolBytes);
        if (oldRol.AuthorizationSequence == ulong.MaxValue)
            throw new FormatException("Owner route predecessor is terminal.");
        var nextSequence = oldRol.AuthorizationSequence + 1;
        var rtc = CreateRtc(intent, oldRol, oldRolBytes, nextSequence,
            ProductionMailboxRouteAuthorizationKind.OwnerPRA2, window,
            new byte[32], new byte[32], new byte[32]);
        var rtcBytes = ProductionMailboxRouteAuthorizationCodec.EncodeTransitionContext(rtc);
        _ = ProductionMailboxRouteAuthorizationVerifier.VerifyTransitionContext(rtcBytes,
            oldRol.NetworkId.Span, oldRol.RouteDomainHash.Span,
            intent.TrustedOldSelectionHash, intent.TrustedCurrentSelectionHash,
            ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(oldRol),
            oldRol.RouteVerifiedAtUnixSeconds, oldRol.LocalCommitGeneration);
        var prc = intent.RouteCertificate.Certificate;
        var unsigned = new ProductionMailboxRouteAdvertisementV2
        {
            Certificate = prc,
            PredecessorAuthorizationKind = oldRol.AuthorizationKind,
            PredecessorCanonicalRouteAuthorizationHash = oldRol.CanonicalAuthorizationHash.ToArray(),
            PredecessorRouteAuthorizationSequence = oldRol.AuthorizationSequence,
            Sequence = nextSequence,
            PublishedAtUnixSeconds = window.AuthorizationIssuedAtUnixSeconds,
            ExpiresAtUnixSeconds = window.AuthorizationExpiresAtUnixSeconds,
            OwnerSignature = new byte[64]
        };
        var signingBytes = ProductionMailboxRouteAuthorizationCodec.GetAdvertisementV2SigningBytes(unsigned);
        var signature = new byte[64]; var request = new ProductionMailboxPra2SigningRequest(signingBytes,
            prc.MailboxOwnerEd25519PublicKey.Span);
        VerifiedProductionMailboxRouteAdvertisementV2 authorization;
        try
        {
            var written = await signer(request, signature, cancellationToken).ConfigureAwait(false);
            if (written != 64) throw new FormatException("PRA2 signer must write exactly 64 bytes.");
            var canonical = ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(
                unsigned with { OwnerSignature = signature.ToArray() });
            authorization = ProductionMailboxRouteAuthorizationVerifier.VerifyOwnerAuthorization(
                canonical, intent.CurrentAuthority,
                new ProductionMailboxOwnerRouteAuthorizationVerificationContext
                {
                    ExpectedNetworkId = oldRol.NetworkId.ToArray(),
                    ExpectedRouteDomainHash = oldRol.RouteDomainHash.ToArray(),
                    ExpectedPredecessorKind = oldRol.AuthorizationKind,
                    ExpectedPredecessorHash = oldRol.CanonicalAuthorizationHash.ToArray(),
                    ExpectedPredecessorSequence = oldRol.AuthorizationSequence,
                    NowUnixSeconds = window.NowUnixSeconds,
                    ClockSkewSeconds = window.ClockSkewSeconds
                });
        }
        finally
        {
            request.Clear(); CryptographicOperations.ZeroMemory(signingBytes);
            CryptographicOperations.ZeroMemory(signature);
        }
        return await CompleteAsync(anchor, currentRoute, intent, expectedMode, oldRolBytes,
            rtcBytes, authorization.CanonicalBytes, ReadOnlyMemory<byte>.Empty,
            authorization.CanonicalHash, nextSequence, oldIssuerSigner, currentIssuerSigner,
            window, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<VerifiedProductionMailboxLiveTransition> AuthorDelegatedAsync(
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor currentRoute,
        VerifiedProductionMailboxSelectionTransitionIntent intent,
        ProductionMailboxLiveTransitionWindow window,
        ProductionMailboxSelectionSuccessorMode expectedMode,
        ProductionMailboxRch1Signer checkpointSigner,
        ProductionMailboxRca1Signer activationSigner,
        ProductionMailboxPss2OldIssuerSigner? oldIssuerSigner,
        ProductionMailboxPss2CurrentIssuerSigner currentIssuerSigner,
        CancellationToken cancellationToken)
    {
        ValidateCommon(anchor, currentRoute, intent, window, expectedMode);
        ArgumentNullException.ThrowIfNull(checkpointSigner);
        ArgumentNullException.ThrowIfNull(activationSigner); ArgumentNullException.ThrowIfNull(currentIssuerSigner);
        ValidateBoundedWindow(window.CheckpointIssuedAtUnixSeconds,
            window.CheckpointExpiresAtUnixSeconds, intent.LiveNotBeforeUnixSeconds,
            intent.LiveExpiresAtUnixSeconds, window.NowUnixSeconds,
            window.ClockSkewSeconds, "RCH1");
        var oldRolBytes = currentRoute.CanonicalCurrentRouteOriginLkg();
        var salt = RandomNumberGenerator.GetBytes(32);
        try
        {
            var delegated = await AuthorDelegatedForCurrentRolAsync(anchor, intent, oldRolBytes,
                salt, window, checkpointSigner, activationSigner, cancellationToken)
                .ConfigureAwait(false);
            var activation = ProductionMailboxRouteAuthorizationCodec.DecodeContinuityActivation(
                delegated.CanonicalActivationBytes.Span);
            return await CompleteAsync(anchor, currentRoute, intent, expectedMode, oldRolBytes,
                delegated.CanonicalTransitionContextBytes, delegated.CanonicalActivationBytes,
                delegated.CanonicalCheckpointBytes, delegated.CanonicalActivationHash,
                activation.ActivationSequence, oldIssuerSigner, currentIssuerSigner, window,
                cancellationToken).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(salt); }
    }

    private static async ValueTask<VerifiedProductionMailboxDelegatedRouteAuthorization>
        AuthorDelegatedForCurrentRolAsync(VerifiedProductionMailboxHistoricalRouteAnchor anchor,
            VerifiedProductionMailboxSelectionTransitionIntent intent, ReadOnlyMemory<byte> oldRolBytes,
            ReadOnlyMemory<byte> salt, ProductionMailboxLiveTransitionWindow window,
            ProductionMailboxRch1Signer checkpointSigner, ProductionMailboxRca1Signer activationSigner,
            CancellationToken cancellationToken)
    {
        var enrollment = anchor.EnrollmentState.Enrollment;
        var delegation = enrollment.Delegation;
        var oldRol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(oldRolBytes.Span);
        if (!CryptographicOperations.FixedTimeEquals(oldRol.CanonicalDelegationHash.Span,
                enrollment.CanonicalDelegationHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(oldRol.CanonicalDelegationAcceptanceHash.Span,
                enrollment.CanonicalAcceptanceHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(oldRol.NetworkId.Span, delegation.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(oldRol.RouteDomainHash.Span, delegation.RouteDomainHash.Span))
            throw new FormatException("Current ROL1 differs from the sealed continuity enrollment.");
        // The sealed ROL/RHC chain is the predecessor authority, including a post-history Owner
        // predecessor. The original enrollment PRA2 must not pin later owner history.
        if (oldRol.AuthorizationSequence == ulong.MaxValue)
            throw new FormatException("Delegated route predecessor is terminal.");
        var nextSequence = oldRol.AuthorizationSequence + 1;
        if (nextSequence < delegation.FirstActivationSequence || nextSequence > delegation.LastActivationSequence)
            throw new FormatException("Delegated route sequence is outside the RCD1 range.");
        var authority = intent.CurrentAuthority.Authority;
        var revocations = intent.CurrentRevocations.Snapshot;
        var authorityHash = intent.CurrentAuthority.CanonicalAuthorityHash.ToArray();
        var revocationHash = intent.CurrentRevocations.CanonicalSnapshotHash.ToArray();
        var certificateHash = intent.RouteCertificate.CanonicalCertificateHash.ToArray();
        var oldRolHash = ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(oldRol);
        var commitment = ProductionMailboxRouteContinuityCodec.ComputeContinuityTransitionCommitment(
            salt.Span, oldRol.NetworkId.Span, oldRol.RouteDomainHash.Span,
            enrollment.CanonicalDelegationHash.Span, enrollment.CanonicalAcceptanceHash.Span,
            oldRolHash, oldRol.OwnerRevocationGeneration, oldRol.OwnerRevocationHeadHash.Span,
            authorityHash, certificateHash, oldRol.AuthorizationKind,
            oldRol.CanonicalAuthorizationHash.Span, oldRol.AuthorizationSequence, nextSequence);
        var unsignedRch = new ProductionMailboxRouteRevocationCheckpoint
        {
            NetworkId = oldRol.NetworkId.ToArray(), RouteDomainHash = oldRol.RouteDomainHash.ToArray(),
            CurrentAuthorityGeneration = authority.AuthorityGeneration,
            CurrentCanonicalAuthorityHash = authorityHash,
            CurrentIssuerEd25519PublicKey = authority.MailboxIssuerEd25519PublicKey.ToArray(),
            CurrentOwnerRevocationGeneration = oldRol.OwnerRevocationGeneration,
            CurrentOwnerRevocationHeadHash = oldRol.OwnerRevocationHeadHash.ToArray(),
            TransitionSalt = salt.ToArray(), ContinuityTransitionCommitment = commitment,
            Status = ProductionMailboxRouteRevocationStatus.Active,
            IssuedAtUnixSeconds = window.CheckpointIssuedAtUnixSeconds,
            ExpiresAtUnixSeconds = window.CheckpointExpiresAtUnixSeconds,
            CurrentIssuerSignature = Enumerable.Repeat((byte)0xA5, 64).ToArray()
        };
        var rchSigning = ProductionMailboxRouteContinuityCodec.GetRevocationCheckpointSigningBytes(unsignedRch);
        _ = ProductionMailboxRouteContinuityVerifier.VerifyRevocationCheckpoint(
            ProductionMailboxRouteContinuityCodec.EncodeRevocationCheckpoint(unsignedRch),
            intent.CurrentAuthority, intent.CurrentRevocations, enrollment.VerifiedDelegation,
            salt.Span, commitment, oldRol.OwnerRevocationGeneration, oldRol.OwnerRevocationHeadHash.Span,
            window.NowUnixSeconds, window.ClockSkewSeconds,
            new ExactTranscriptVerifier(authority.MailboxIssuerEd25519PublicKey.Span, rchSigning));
        var rchSignature = new byte[64];
        var rchRequest = new ProductionMailboxRch1SigningRequest(rchSigning);
        VerifiedProductionMailboxRouteRevocationCheckpoint verifiedRch;
        try
        {
            var written = await checkpointSigner(rchRequest, rchSignature, cancellationToken).ConfigureAwait(false);
            if (written != 64) throw new FormatException("RCH1 signer must write exactly 64 bytes.");
            verifiedRch = ProductionMailboxRouteContinuityVerifier.VerifyRevocationCheckpoint(
                ProductionMailboxRouteContinuityCodec.EncodeRevocationCheckpoint(unsignedRch with
                { CurrentIssuerSignature = rchSignature.ToArray() }),
                intent.CurrentAuthority, intent.CurrentRevocations, enrollment.VerifiedDelegation,
                salt.Span, commitment, oldRol.OwnerRevocationGeneration, oldRol.OwnerRevocationHeadHash.Span,
                window.NowUnixSeconds, window.ClockSkewSeconds,
                new SodiumProductionMailboxRouteSignatureVerifier());
        }
        finally
        {
            rchRequest.Clear(); CryptographicOperations.ZeroMemory(rchSigning);
            CryptographicOperations.ZeroMemory(rchSignature);
        }
        var rtc = CreateRtc(intent, oldRol, oldRolBytes.Span, nextSequence,
            ProductionMailboxRouteAuthorizationKind.DelegatedRCA1, window, salt.Span,
            commitment, verifiedRch.CanonicalHash.Span);
        var rtcBytes = ProductionMailboxRouteAuthorizationCodec.EncodeTransitionContext(rtc);
        var verifiedRtc = ProductionMailboxRouteAuthorizationVerifier.VerifyTransitionContext(
            rtcBytes, oldRol.NetworkId.Span, oldRol.RouteDomainHash.Span,
            intent.TrustedOldSelectionHash, intent.TrustedCurrentSelectionHash, oldRolHash,
            oldRol.RouteVerifiedAtUnixSeconds, oldRol.LocalCommitGeneration);
        var unsignedRca = new ProductionMailboxRouteContinuityActivation
        {
            NetworkId = oldRol.NetworkId.ToArray(), RouteDomainHash = oldRol.RouteDomainHash.ToArray(),
            CurrentAuthorityGeneration = authority.AuthorityGeneration,
            CurrentCanonicalAuthorityHash = authorityHash,
            CurrentIssuerEd25519PublicKey = authority.MailboxIssuerEd25519PublicKey.ToArray(),
            CurrentRevocationGeneration = revocations.RevocationGeneration,
            CurrentRevocationHeadHash = revocations.RevocationHeadHash.ToArray(),
            CurrentRevocationSnapshotHash = revocationHash, TransitionSalt = salt.ToArray(),
            ContinuityTransitionCommitment = commitment,
            CanonicalRevocationCheckpointHash = verifiedRch.CanonicalHash.ToArray(),
            FreshCanonicalRouteCertificateHash = certificateHash,
            CanonicalTransitionContextHash = verifiedRtc.CanonicalHash.ToArray(),
            PredecessorAuthorizationKind = oldRol.AuthorizationKind,
            PredecessorCanonicalRouteAuthorizationHash = oldRol.CanonicalAuthorizationHash.ToArray(),
            PredecessorRouteAuthorizationSequence = oldRol.AuthorizationSequence,
            ActivationSequence = nextSequence,
            IssuedAtUnixSeconds = window.AuthorizationIssuedAtUnixSeconds,
            ExpiresAtUnixSeconds = window.AuthorizationExpiresAtUnixSeconds,
            CurrentIssuerSignature = Enumerable.Repeat((byte)0xA5, 64).ToArray()
        };
        var rcaSigning = ProductionMailboxRouteAuthorizationCodec.GetContinuityActivationSigningBytes(unsignedRca);
        _ = ProductionMailboxRouteAuthorizationVerifier.VerifyDelegatedActivation(
            ProductionMailboxRouteAuthorizationCodec.EncodeContinuityActivation(unsignedRca),
            intent.CurrentAuthority, intent.CurrentRevocations, intent.RouteCertificate,
            verifiedRch, verifiedRtc, enrollment, window.NowUnixSeconds, window.ClockSkewSeconds,
            new ExactTranscriptVerifier(authority.MailboxIssuerEd25519PublicKey.Span, rcaSigning));
        var rcaSignature = new byte[64]; var rcaRequest = new ProductionMailboxRca1SigningRequest(rcaSigning);
        try
        {
            var written = await activationSigner(rcaRequest, rcaSignature, cancellationToken).ConfigureAwait(false);
            if (written != 64) throw new FormatException("RCA1 signer must write exactly 64 bytes.");
            var verifiedRca = ProductionMailboxRouteAuthorizationVerifier.VerifyDelegatedActivation(
                ProductionMailboxRouteAuthorizationCodec.EncodeContinuityActivation(unsignedRca with
                { CurrentIssuerSignature = rcaSignature.ToArray() }),
                intent.CurrentAuthority, intent.CurrentRevocations, intent.RouteCertificate,
                verifiedRch, verifiedRtc, enrollment, window.NowUnixSeconds, window.ClockSkewSeconds,
                new SodiumProductionMailboxRouteSignatureVerifier());
            return new(verifiedRch, verifiedRtc, verifiedRca);
        }
        finally
        {
            rcaRequest.Clear(); CryptographicOperations.ZeroMemory(rcaSigning);
            CryptographicOperations.ZeroMemory(rcaSignature);
        }
    }

    private static async ValueTask<VerifiedProductionMailboxLiveTransition> CompleteAsync(
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor currentRoute,
        VerifiedProductionMailboxSelectionTransitionIntent intent,
        ProductionMailboxSelectionSuccessorMode mode,
        byte[] oldRolBytes, ReadOnlyMemory<byte> rtcBytes, ReadOnlyMemory<byte> authorizationBytes,
        ReadOnlyMemory<byte> checkpointBytes, ReadOnlyMemory<byte> authorizationHash,
        ulong authorizationSequence, ProductionMailboxPss2OldIssuerSigner? oldSigner,
        ProductionMailboxPss2CurrentIssuerSigner currentSigner,
        ProductionMailboxLiveTransitionWindow window, CancellationToken cancellationToken)
    {
        var rtcHash = ProductionMailboxRouteAuthorizationCodec.ComputeTransitionContextHash(
            ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(rtcBytes.Span));
        var checkpointHash = checkpointBytes.IsEmpty ? new byte[32] : SHA256.HashData(checkpointBytes.Span);
        var authorizationKind = ProductionMailboxRouteAuthorizationKindFrom(checkpointBytes);
        var draft = BuildPss(intent, mode, oldRolBytes, rtcHash, authorizationHash.Span, checkpointHash,
            authorizationSequence, authorizationKind, window);
        var routeContext = new ProductionMailboxRouteSelectionTransitionVerificationContext
        {
            ExpectedRouteDomainHash = anchor.EnrollmentState.Enrollment.Delegation.RouteDomainHash.ToArray(),
            CanonicalOldRouteOriginLkg = oldRolBytes,
            ContinuityEnrollment = checkpointBytes.IsEmpty ? null : anchor.EnrollmentState.Enrollment
        };
        VerifiedProductionMailboxRouteSelectionTransition transition;
        if (mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion)
        {
            ArgumentNullException.ThrowIfNull(oldSigner);
            transition = await ProductionMailboxSelectionSuccessorAuthoring.AuthorDirectAsync(draft,
                ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(intent.RouteCertificate.Certificate),
                rtcBytes, authorizationBytes, checkpointBytes, intent.OldAuthority, intent.OldTopology,
                intent.CurrentAuthority, intent.CurrentRevocations, intent.CurrentTopology,
                DirectContext(intent, window), routeContext, oldSigner, currentSigner,
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            var next = intent.NextSelection ?? throw new FormatException("Offline transition lacks sealed next PMS1.");
            transition = await ProductionMailboxSelectionSuccessorAuthoring.AuthorOfflineAsync(draft,
                ProductionMailboxAuthorityCodec.Encode(intent.CurrentAuthority.Authority),
                ProductionMailboxRevocationSnapshotCodec.Encode(
                    intent.CurrentRevocations.Snapshot),
                ProductionMailboxTopologyCodec.Encode(intent.CurrentTopology.Snapshot),
                ProductionMailboxTopologyCodec.EncodeSelection(intent.OldSelection.Proof),
                ProductionMailboxTopologyCodec.EncodeSelection(intent.CurrentSelection.Proof),
                ProductionMailboxTopologyCodec.EncodeSelection(next.Proof),
                ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(intent.RouteCertificate.Certificate),
                rtcBytes, authorizationBytes, checkpointBytes, intent.OldAuthority, intent.OldTopology,
                OfflineContext(intent, window), routeContext, currentSigner, cancellationToken).ConfigureAwait(false);
        }
        var link = new ProductionMailboxRouteHistoryAuthoringLink
        {
            AuthorizationKind = transition.AuthorizationKind,
            CanonicalAuthority = ProductionMailboxAuthorityCodec.Encode(intent.CurrentAuthority.Authority),
            CanonicalRevocations = ProductionMailboxRevocationSnapshotCodec.Encode(
                intent.CurrentRevocations.Snapshot),
            CanonicalRouteCertificate = transition.CanonicalRouteCertificate,
            CanonicalRevocationCheckpoint = authorizationKind ==
                ProductionMailboxRouteAuthorizationKind.OwnerPRA2 ? ReadOnlyMemory<byte>.Empty :
                transition.CanonicalRevocationCheckpoint,
            CanonicalTransitionContext = authorizationKind ==
                ProductionMailboxRouteAuthorizationKind.OwnerPRA2 ? ReadOnlyMemory<byte>.Empty :
                transition.CanonicalTransitionContext,
            CanonicalAuthorization = transition.CanonicalRouteAuthorization
        };
        var history = ProductionMailboxRouteHistoryAuthoring.AuthorNextBatch(currentRoute, [link]);
        var plan = new ProductionMailboxLiveTransitionCommitPlan(oldRolBytes,
            intent.OldCanonicalSelectionHash.Span, currentRoute.CanonicalCheckpoint.Span,
            history.CanonicalBatch.Span, history.NextCursor.CanonicalCheckpoint.Span,
            transition.CanonicalNextRouteOriginLkg.Span, transition);
        return new VerifiedProductionMailboxLiveTransition(transition, plan, intent);
    }

    private static ProductionMailboxRouteAuthorizationKind ProductionMailboxRouteAuthorizationKindFrom(
        ReadOnlyMemory<byte> checkpoint) => checkpoint.IsEmpty
            ? ProductionMailboxRouteAuthorizationKind.OwnerPRA2
            : ProductionMailboxRouteAuthorizationKind.DelegatedRCA1;

    private static ProductionMailboxSelectionSuccessorV2Proof BuildPss(
        VerifiedProductionMailboxSelectionTransitionIntent intent,
        ProductionMailboxSelectionSuccessorMode mode, ReadOnlySpan<byte> oldRolBytes,
        ReadOnlySpan<byte> rtcHash,
        ReadOnlySpan<byte> authorizationHash, ReadOnlySpan<byte> checkpointHash,
        ulong authorizationSequence, ProductionMailboxRouteAuthorizationKind kind,
        ProductionMailboxLiveTransitionWindow window)
    {
        var old = intent.OldSelection.Proof; var current = intent.CurrentSelection.Proof;
        var predecessor = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(oldRolBytes);
        var delegation = intent.RouteCertificate.Certificate;
        return new ProductionMailboxSelectionSuccessorV2Proof
        {
            Selection = new ProductionMailboxSelectionSuccessorProof
            {
                Mode = mode, NetworkId = current.NetworkId.ToArray(), OldEpoch = old.Epoch,
                OldEpochGeneration = old.Generation, NewEpoch = current.Epoch,
                NewEpochGeneration = current.Generation,
                MailboxOwnerEd25519PublicKey = delegation.MailboxOwnerEd25519PublicKey.ToArray(),
                BlindedMailboxId = delegation.BlindedMailboxId.ToArray(),
                BlindedPlacementId = delegation.BlindedPlacementId.ToArray(),
                SelectionInputCommitment = delegation.SelectionInputCommitment.ToArray(),
                OldCanonicalAuthorityHash = old.CanonicalAuthorityHash.ToArray(),
                NewCanonicalAuthorityHash = current.CanonicalAuthorityHash.ToArray(),
                OldTopologyGeneration = old.TopologyGeneration,
                OldCanonicalTopologyHash = old.CanonicalTopologyHash.ToArray(),
                NewTopologyGeneration = current.TopologyGeneration,
                NewCanonicalTopologyHash = current.CanonicalTopologyHash.ToArray(),
                OldCanonicalSelectionHash = intent.OldCanonicalSelectionHash.ToArray(),
                NewCanonicalSelectionHash = intent.CurrentCanonicalSelectionHash.ToArray(),
                IssuedAtUnixSeconds = new[] { intent.LiveNotBeforeUnixSeconds,
                    current.IssuedAtUnixSeconds, window.RouteNotBeforeUnixSeconds,
                    window.AuthorizationIssuedAtUnixSeconds,
                    kind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1
                        ? window.CheckpointIssuedAtUnixSeconds : 0UL }.Max(),
                ExpiresAtUnixSeconds = new[] { intent.LiveExpiresAtUnixSeconds,
                    current.ExpiresAtUnixSeconds, window.RouteExpiresAtUnixSeconds,
                    window.AuthorizationExpiresAtUnixSeconds,
                    kind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1
                        ? window.CheckpointExpiresAtUnixSeconds : ulong.MaxValue }.Min(),
                CanonicalNewAuthority = ProductionMailboxAuthorityCodec.Encode(intent.CurrentAuthority.Authority),
                OldCanonicalSelection = ProductionMailboxTopologyCodec.EncodeSelection(old),
                NewCanonicalSelection = ProductionMailboxTopologyCodec.EncodeSelection(current),
                OldIssuerSignature = new byte[64], NewIssuerSignature = new byte[64]
            },
            CanonicalTransitionContextHash = rtcHash.ToArray(),
            PredecessorAuthorizationKind = predecessor.AuthorizationKind,
            NewAuthorizationKind = kind,
            PredecessorCanonicalRouteAuthorizationHash = predecessor.CanonicalAuthorizationHash.ToArray(),
            PredecessorRouteAuthorizationSequence = predecessor.AuthorizationSequence,
            FreshCanonicalRouteCertificateHash = intent.CanonicalRouteCertificateHash.ToArray(),
            NewCanonicalRouteAuthorizationHash = authorizationHash.ToArray(),
            NewRouteAuthorizationSequence = authorizationSequence,
            CanonicalRevocationCheckpointHash = checkpointHash.ToArray()
        };
    }

    private static ProductionMailboxRouteTransitionContext CreateRtc(
        VerifiedProductionMailboxSelectionTransitionIntent intent, ProductionMailboxRouteOriginLkg oldRol,
        ReadOnlySpan<byte> oldRolBytes, ulong nextSequence, ProductionMailboxRouteAuthorizationKind kind,
        ProductionMailboxLiveTransitionWindow window, ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> commitment, ReadOnlySpan<byte> checkpointHash) => new()
    {
        Mode = intent.Mode, PredecessorAuthorizationKind = oldRol.AuthorizationKind,
        NewAuthorizationKind = kind, NetworkId = oldRol.NetworkId.ToArray(),
        RouteDomainHash = oldRol.RouteDomainHash.ToArray(),
        OldCanonicalSelectionHash = intent.OldCanonicalSelectionHash.ToArray(),
        NewCanonicalSelectionHash = intent.CurrentCanonicalSelectionHash.ToArray(),
        PredecessorCanonicalRouteAuthorizationHash = oldRol.CanonicalAuthorizationHash.ToArray(),
        PredecessorRouteAuthorizationSequence = oldRol.AuthorizationSequence,
        FreshCanonicalRouteCertificateHash = intent.CanonicalRouteCertificateHash.ToArray(),
        NewRouteAuthorizationSequence = nextSequence, TransitionSalt = salt.ToArray(),
        ContinuityTransitionCommitment = commitment.ToArray(), CanonicalRevocationCheckpointHash = checkpointHash.ToArray(),
        CurrentCanonicalAuthorityHash = intent.CurrentAuthority.CanonicalAuthorityHash.ToArray(),
        CurrentAuthorityGeneration = intent.CurrentAuthority.Authority.AuthorityGeneration,
        SealedOldRouteOriginLkgHash = ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(oldRol),
        OldRouteVerifiedAtUnixSeconds = oldRol.RouteVerifiedAtUnixSeconds,
        OldLocalRouteCommitGeneration = oldRol.LocalCommitGeneration,
        NotBeforeUnixSeconds = window.RouteNotBeforeUnixSeconds,
        ExpiresAtUnixSeconds = window.RouteExpiresAtUnixSeconds
    };

    private static ProductionMailboxSelectionSuccessorVerificationContext DirectContext(
        VerifiedProductionMailboxSelectionTransitionIntent intent, ProductionMailboxLiveTransitionWindow window)
    {
        var route = intent.RouteCertificate.Certificate;
        return new() { ExpectedNetworkId = route.NetworkId.ToArray(),
            ExpectedMailboxOwnerEd25519PublicKey = route.MailboxOwnerEd25519PublicKey.ToArray(),
            ExpectedBlindedMailboxId = route.BlindedMailboxId.ToArray(),
            ExpectedBlindedPlacementId = route.BlindedPlacementId.ToArray(),
            PinnedMrXPublicKeySha256 = SHA256.HashData(intent.OldAuthority.Authority.MrXApprovalEd25519PublicKey.Span),
            ExpectedOldCanonicalSelectionHash = intent.OldCanonicalSelectionHash.ToArray(),
            NowUnixSeconds = window.NowUnixSeconds, ClockSkewSeconds = window.ClockSkewSeconds };
    }

    private static ProductionMailboxOfflineCheckpointClosureVerificationContext OfflineContext(
        VerifiedProductionMailboxSelectionTransitionIntent intent, ProductionMailboxLiveTransitionWindow window)
    {
        var route = intent.RouteCertificate.Certificate; var old = intent.OldAuthority.Authority;
        var oldTopology = intent.OldTopology.Snapshot;
        return new() { ExpectedNetworkId = route.NetworkId.ToArray(),
            ExpectedMailboxOwnerEd25519PublicKey = route.MailboxOwnerEd25519PublicKey.ToArray(),
            ExpectedBlindedMailboxId = route.BlindedMailboxId.ToArray(),
            ExpectedBlindedPlacementId = route.BlindedPlacementId.ToArray(),
            ExpectedSelectionInputCommitment = route.SelectionInputCommitment.ToArray(),
            PinnedMrXPublicKeySha256 = SHA256.HashData(old.MrXApprovalEd25519PublicKey.Span),
            ExpectedOldAuthorityGeneration = old.AuthorityGeneration,
            ExpectedOldCanonicalAuthorityHash = intent.OldAuthority.CanonicalAuthorityHash.ToArray(),
            ExpectedOldRevocationGeneration = old.Revocation.Generation,
            ExpectedOldRevocationHeadHash = old.Revocation.HeadHash.ToArray(),
            ExpectedOldRevocationSnapshotHash = old.Revocation.SnapshotHash.ToArray(),
            ExpectedOldTopologyGeneration = oldTopology.TopologyGeneration,
            ExpectedOldCanonicalTopologyHash = intent.OldTopology.CanonicalTopologyHash.ToArray(),
            ExpectedOldCanonicalSelectionHash = intent.OldCanonicalSelectionHash.ToArray(),
            VerifiedAtUnixSeconds = window.NowUnixSeconds, ClockSkewSeconds = window.ClockSkewSeconds };
    }

    private static void ValidateCommon(VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor cursor,
        VerifiedProductionMailboxSelectionTransitionIntent intent,
        ProductionMailboxLiveTransitionWindow window, ProductionMailboxSelectionSuccessorMode expectedMode)
    {
        ArgumentNullException.ThrowIfNull(anchor); ArgumentNullException.ThrowIfNull(cursor);
        ArgumentNullException.ThrowIfNull(intent); ArgumentNullException.ThrowIfNull(window);
        if (intent.Mode != expectedMode) throw new FormatException("Sealed transition mode differs from overload.");
        if (intent.CurrentRoute is null ||
            !CryptographicOperations.FixedTimeEquals(cursor.CanonicalCheckpoint.Span,
                intent.CurrentRoute.CanonicalCheckpoint.Span))
            throw new FormatException("Selection intent differs from the exact sealed RHC cursor.");
        if (!CryptographicOperations.FixedTimeEquals(cursor.Enrollment.CanonicalDelegationHash.Span,
                anchor.EnrollmentState.Enrollment.CanonicalDelegationHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(cursor.Enrollment.CanonicalAcceptanceHash.Span,
                anchor.EnrollmentState.Enrollment.CanonicalAcceptanceHash.Span))
            throw new FormatException("Route-history cursor differs from sealed enrollment anchor.");
        var checkpoint = cursor.Checkpoint.TrustedCheckpoint;
        var delegation = anchor.EnrollmentState.Enrollment.Delegation;
        var oldRol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(
            cursor.CanonicalCurrentRouteOriginLkg());
        var authority = intent.CurrentAuthority.Authority;
        var revocations = intent.CurrentRevocations.Snapshot;
        var certificate = intent.RouteCertificate.Certificate;
        if (checkpoint.CurrentAuthorityGeneration != authority.AuthorityGeneration ||
            checkpoint.CurrentRevocationGeneration != revocations.RevocationGeneration ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentCanonicalAuthorityHash.Span,
                intent.CurrentAuthority.CanonicalAuthorityHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRevocationHeadHash.Span,
                revocations.RevocationHeadHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRevocationSnapshotHash.Span,
                intent.CurrentRevocations.CanonicalSnapshotHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRouteOriginLkgHash.Span,
                ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(oldRol)) ||
            !CryptographicOperations.FixedTimeEquals(oldRol.NetworkId.Span, delegation.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(oldRol.RouteDomainHash.Span,
                delegation.RouteDomainHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(certificate.NetworkId.Span, delegation.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(certificate.MailboxOwnerEd25519PublicKey.Span,
                delegation.MailboxOwnerEd25519PublicKey.Span) ||
            !CryptographicOperations.FixedTimeEquals(certificate.BlindedMailboxId.Span,
                delegation.BlindedMailboxId.Span) ||
            !CryptographicOperations.FixedTimeEquals(certificate.BlindedPlacementId.Span,
                delegation.BlindedPlacementId.Span) ||
            !CryptographicOperations.FixedTimeEquals(certificate.SelectionInputCommitment.Span,
                delegation.SelectionInputCommitment.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(certificate),
                delegation.RouteDomainHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(intent.TrustedOldSelectionHash,
                intent.OldSelection.CanonicalSelectionHash.Span))
            throw new FormatException("Live transition sealed route/control/selection tuple is inconsistent.");
        ValidateBoundedWindow(window.RouteNotBeforeUnixSeconds, window.RouteExpiresAtUnixSeconds,
            intent.LiveNotBeforeUnixSeconds, intent.LiveExpiresAtUnixSeconds,
            window.NowUnixSeconds, window.ClockSkewSeconds, "RTC1");
        ValidateBoundedWindow(window.AuthorizationIssuedAtUnixSeconds,
            window.AuthorizationExpiresAtUnixSeconds, intent.LiveNotBeforeUnixSeconds,
            intent.LiveExpiresAtUnixSeconds, window.NowUnixSeconds,
            window.ClockSkewSeconds, "route authorization");
        ProductionMailboxRouteAuthorizationVerifier.ValidateClock(window.NowUnixSeconds, window.ClockSkewSeconds);
    }

    private static void ValidateBoundedWindow(ulong issuedAt, ulong expiresAt,
        ulong lowerBound, ulong upperBound, ulong now, uint skew, string name)
    {
        if (issuedAt == 0 || issuedAt == ulong.MaxValue || expiresAt <= issuedAt ||
            expiresAt == ulong.MaxValue || issuedAt < lowerBound || expiresAt > upperBound)
            throw new FormatException($"{name} window is outside the sealed live closure.");
        ProductionMailboxRouteCertificateVerifier.VerifyWindow(issuedAt, expiresAt, now, skew, name);
    }

    private sealed class ExactTranscriptVerifier : IProductionMailboxRouteSignatureVerifier
    {
        private readonly byte[] _key;
        private readonly byte[] _transcript;
        internal ExactTranscriptVerifier(ReadOnlySpan<byte> key, ReadOnlySpan<byte> transcript)
        { _key = key.ToArray(); _transcript = transcript.ToArray(); }
        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) => publicKey.SequenceEqual(_key) &&
            signingBytes.SequenceEqual(_transcript) && signature.Length == 64;
    }
}
