using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

/// <summary>
/// High-level current-issuer authoring boundary. Private keys remain behind capability-specific
/// callbacks; this type never exposes a generic signing or raw transcript construction API.
/// </summary>
public static class ProductionMailboxRouteIssuerAuthoring
{
    internal static async ValueTask<VerifiedProductionMailboxOwnerControlResponderCertificate>
        AuthorOwnerControlResponderCertificateAsync(
            VerifiedProductionMailboxRouteContinuityEnrollmentState enrollmentState,
            VerifiedProductionMailboxAuthority anchorAuthority,
            VerifiedProductionMailboxRevocationSnapshot anchorRevocations,
            VerifiedProductionMailboxRouteCertificate anchorCertificate,
            VerifiedProductionMailboxRouteAdvertisementV2 anchorAuthorization,
            ReadOnlyMemory<byte> responderEd25519PublicKey,
            ulong expiresAtUnixSeconds,
            ProductionMailboxOcr1Signer signer,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(enrollmentState); ArgumentNullException.ThrowIfNull(anchorAuthority);
        ArgumentNullException.ThrowIfNull(anchorRevocations); ArgumentNullException.ThrowIfNull(anchorCertificate);
        ArgumentNullException.ThrowIfNull(anchorAuthorization); ArgumentNullException.ThrowIfNull(signer);
        if (responderEd25519PublicKey.Length != 32)
            throw new FormatException("OCR1 responder key must be exact before copy.");
        var enrollment = enrollmentState.Enrollment;
        var delegation = enrollment.Delegation; var acceptance = enrollment.Acceptance;
        var value = new ProductionMailboxOwnerControlResponderCertificate
        {
            NetworkId = delegation.NetworkId.ToArray(),
            MailboxOwnerEd25519PublicKey = delegation.MailboxOwnerEd25519PublicKey.ToArray(),
            RouteDomainHash = delegation.RouteDomainHash.ToArray(),
            AnchorCanonicalAuthorityHash = anchorAuthority.CanonicalAuthorityHash.ToArray(),
            ResponderEd25519PublicKey = responderEd25519PublicKey.ToArray(),
            IssuedAtUnixSeconds = acceptance.AcceptedAtUnixSeconds,
            ExpiresAtUnixSeconds = expiresAtUnixSeconds, KeyGeneration = 1,
            PreviousCanonicalCertificateHash = new byte[32], AnchorIssuerSignature = new byte[64]
        };
        VerifyOcrHistoricalClosure(value with { AnchorIssuerSignature = Enumerable.Repeat((byte)0xA5, 64).ToArray() },
            ProductionMailboxOwnerControlTransportCodec.EncodeResponderCertificate(value with
            { AnchorIssuerSignature = Enumerable.Repeat((byte)0xA5, 64).ToArray() }), delegation,
            acceptance, anchorAuthority, anchorRevocations, anchorCertificate, anchorAuthorization,
            verifySignature: false);
        var signingBytes = ProductionMailboxOwnerControlTransportCodec.GetOcrSigningBytes(value);
        var signature = new byte[64];
        var request = new ProductionMailboxOcr1SigningRequest(signingBytes,
            anchorAuthority.Authority.MailboxIssuerEd25519PublicKey.Span);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var written = await signer(request, signature, cancellationToken).ConfigureAwait(false);
            if (written != 64) throw new FormatException("OCR1 issuer signer must write exactly 64 bytes.");
            var signed = value with { AnchorIssuerSignature = signature.ToArray() };
            var canonical = ProductionMailboxOwnerControlTransportCodec.EncodeResponderCertificate(signed);
            VerifyOcrHistoricalClosure(signed, canonical, delegation, acceptance, anchorAuthority,
                anchorRevocations, anchorCertificate, anchorAuthorization);
            return new(signed, canonical,
                ProductionMailboxOwnerControlTransportCodec.ComputeResponderCertificateHash(signed));
        }
        finally
        {
            request.Clear(); CryptographicOperations.ZeroMemory(signingBytes);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    internal static VerifiedProductionMailboxHistoricalRouteAnchor CreateHistoricalAnchor(
        VerifiedProductionMailboxRouteContinuityEnrollmentState enrollmentState,
        VerifiedProductionMailboxAuthority anchorAuthority,
        VerifiedProductionMailboxRevocationSnapshot anchorRevocations,
        VerifiedProductionMailboxRouteCertificate anchorCertificate,
        VerifiedProductionMailboxRouteAdvertisementV2 anchorAuthorization,
        VerifiedProductionMailboxOwnerControlResponderCertificate responderCertificate)
    {
        ArgumentNullException.ThrowIfNull(responderCertificate);
        var enrollment = enrollmentState.Enrollment;
        VerifyOcrHistoricalClosure(responderCertificate.Certificate, responderCertificate.CanonicalBytes.Span,
            enrollment.Delegation, enrollment.Acceptance, anchorAuthority, anchorRevocations,
            anchorCertificate, anchorAuthorization);
        return new(enrollmentState, anchorAuthority, anchorRevocations, anchorCertificate,
            anchorAuthorization, responderCertificate.Certificate, responderCertificate.CanonicalBytes.Span,
            responderCertificate.CanonicalHash.Span);
    }

    /// <summary>
    /// Restores one exact historical RCD1/RDA1/pre-ROL1/enrolled-ROL1/OCR1 composite. All
    /// canonical inputs and protected bindings are frozen and revalidated before a sealed anchor
    /// is returned; independently supplied handles never escape as later authoring authority.
    /// </summary>
    public static VerifiedProductionMailboxHistoricalRouteAnchor RestoreHistoricalAnchor(
        ReadOnlyMemory<byte> canonicalDelegation,
        ReadOnlyMemory<byte> canonicalAcceptance,
        ReadOnlyMemory<byte> canonicalPreDelegationRouteOriginLkg,
        ReadOnlyMemory<byte> canonicalEnrolledRouteOriginLkg,
        ReadOnlyMemory<byte> canonicalOwnerControlResponderCertificate,
        VerifiedProductionMailboxAuthority anchorAuthority,
        VerifiedProductionMailboxRevocationSnapshot anchorRevocations,
        VerifiedProductionMailboxRouteCertificate anchorCertificate,
        VerifiedProductionMailboxRouteAdvertisementV2 anchorAuthorization,
        ProductionMailboxRouteContinuityProtectedEnrollmentContext protectedState,
        uint clockSkewSeconds = 0)
    {
        ArgumentNullException.ThrowIfNull(anchorAuthority);
        ArgumentNullException.ThrowIfNull(anchorRevocations);
        ArgumentNullException.ThrowIfNull(anchorCertificate);
        ArgumentNullException.ThrowIfNull(anchorAuthorization);
        ArgumentNullException.ThrowIfNull(protectedState);
        if (canonicalDelegation.Length != 552 || canonicalAcceptance.Length != 320 ||
            canonicalPreDelegationRouteOriginLkg.Length != 224 || canonicalEnrolledRouteOriginLkg.Length != 224 ||
            canonicalOwnerControlResponderCertificate.Length != 272)
            throw new FormatException("Historical continuity anchor has a non-exact artifact length.");
        protectedState.ValidateOwned();
        var rcdBytes = canonicalDelegation.ToArray(); var rdaBytes = canonicalAcceptance.ToArray();
        var preBytes = canonicalPreDelegationRouteOriginLkg.ToArray();
        var enrolledBytes = canonicalEnrolledRouteOriginLkg.ToArray();
        var ocrBytes = canonicalOwnerControlResponderCertificate.ToArray();
        var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(rcdBytes);
        var acceptance = ProductionMailboxRouteContinuityCodec.DecodeDelegationAcceptance(rdaBytes);
        var pre = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(preBytes);
        var enrolled = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(enrolledBytes);
        var ocr = ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(ocrBytes);
        if (!rcdBytes.AsSpan().SequenceEqual(ProductionMailboxRouteContinuityCodec.EncodeDelegation(delegation)) ||
            !rdaBytes.AsSpan().SequenceEqual(ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(acceptance)) ||
            !preBytes.AsSpan().SequenceEqual(ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(pre)) ||
            !enrolledBytes.AsSpan().SequenceEqual(ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(enrolled)) ||
            !ocrBytes.AsSpan().SequenceEqual(ProductionMailboxOwnerControlTransportCodec.EncodeResponderCertificate(ocr)))
            throw new FormatException("Historical continuity anchor is not canonical.");
        VerifyPreDelegationRouteOrigin(delegation, pre);
        var context = EnrollmentContextFromFrozenDelegation(delegation,
            acceptance.AcceptedAtUnixSeconds, clockSkewSeconds);
        var enrollment = ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(rcdBytes, rdaBytes,
            anchorAuthority, anchorRevocations, anchorCertificate, anchorAuthorization, context);
        var expectedEnrolled = new ProductionMailboxRouteOriginLkg
        {
            NetworkId = pre.NetworkId.ToArray(), RouteDomainHash = pre.RouteDomainHash.ToArray(),
            AuthorizationKind = pre.AuthorizationKind,
            CanonicalAuthorizationHash = pre.CanonicalAuthorizationHash.ToArray(),
            AuthorizationSequence = pre.AuthorizationSequence,
            CanonicalDelegationHash = enrollment.CanonicalDelegationHash.ToArray(),
            CanonicalDelegationAcceptanceHash = enrollment.CanonicalAcceptanceHash.ToArray(),
            OwnerRevocationGeneration = 0, OwnerRevocationHeadHash = new byte[32],
            RouteVerifiedAtUnixSeconds = pre.RouteVerifiedAtUnixSeconds,
            LocalCommitGeneration = checked(pre.LocalCommitGeneration + 1)
        };
        if (!enrolledBytes.AsSpan().SequenceEqual(
                ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(expectedEnrolled)))
            throw new FormatException("Enrolled ROL1 is not the deterministic pre-ROL1 +1 result.");
        var state = new VerifiedProductionMailboxRouteContinuityEnrollmentState(enrollment, pre, enrolled);
        VerifyOcrHistoricalClosure(ocr, ocrBytes, delegation, acceptance, anchorAuthority,
            anchorRevocations, anchorCertificate, anchorAuthorization);
        var ocrHash = ProductionMailboxOwnerControlTransportCodec.ComputeResponderCertificateHash(ocr);
        EqualProtected(protectedState.NetworkId.Span, delegation.NetworkId.Span, "network");
        EqualProtected(protectedState.MailboxOwnerEd25519PublicKey.Span,
            delegation.MailboxOwnerEd25519PublicKey.Span, "owner");
        EqualProtected(protectedState.PinnedMrXPublicKeySha256.Span,
            delegation.PinnedMrXPublicKeySha256.Span, "Mr. X pin");
        EqualProtected(protectedState.BlindedMailboxId.Span, delegation.BlindedMailboxId.Span, "mailbox");
        EqualProtected(protectedState.BlindedPlacementId.Span, delegation.BlindedPlacementId.Span, "placement");
        EqualProtected(protectedState.RouteDomainHash.Span, delegation.RouteDomainHash.Span, "route domain");
        EqualProtected(protectedState.SelectionInputCommitment.Span,
            delegation.SelectionInputCommitment.Span, "selection");
        EqualProtected(protectedState.CanonicalDelegationHash.Span,
            enrollment.CanonicalDelegationHash.Span, "RCD1 hash");
        EqualProtected(protectedState.CanonicalAcceptanceHash.Span,
            enrollment.CanonicalAcceptanceHash.Span, "RDA1 hash");
        EqualProtected(protectedState.PreDelegationRouteOriginLkgHash.Span,
            state.PreDelegationRouteOriginLkgHash.Span, "pre ROL1 hash");
        EqualProtected(protectedState.EnrolledRouteOriginLkgHash.Span,
            state.EnrolledRouteOriginLkgHash.Span, "enrolled ROL1 hash");
        EqualProtected(protectedState.CanonicalOwnerControlResponderCertificate.Span, ocrBytes, "OCR1 bytes");
        EqualProtected(protectedState.CanonicalOwnerControlResponderCertificateHash.Span, ocrHash, "OCR1 hash");
        if (protectedState.AnchorAuthorityGeneration != delegation.AnchorAuthorityGeneration ||
            protectedState.AnchorAuthorizationKind != delegation.AnchorAuthorizationKind ||
            protectedState.AnchorRouteAuthorizationSequence != delegation.AnchorRouteAuthorizationSequence ||
            protectedState.RouteVerifiedAtUnixSeconds != delegation.RouteVerifiedAtUnixSeconds ||
            protectedState.AcceptedAtUnixSeconds != acceptance.AcceptedAtUnixSeconds ||
            protectedState.PreviousDelegationSequence != delegation.DelegationSequence - 1)
            throw new FormatException("Historical protected anchor scalar bindings differ.");
        EqualProtected(protectedState.AnchorCanonicalAuthorityHash.Span,
            delegation.AnchorCanonicalAuthorityHash.Span, "anchor PMA1 hash");
        EqualProtected(protectedState.AnchorCanonicalRouteCertificateHash.Span,
            delegation.AnchorCanonicalRouteCertificateHash.Span, "anchor PRC1 hash");
        EqualProtected(protectedState.AnchorCanonicalRouteAuthorizationHash.Span,
            delegation.AnchorCanonicalRouteAuthorizationHash.Span, "anchor PRA2 hash");
        EqualProtected(protectedState.PreviousCanonicalDelegationHash.Span,
            delegation.PreviousCanonicalDelegationHash.Span, "previous RCD1 hash");
        return new(state, anchorAuthority, anchorRevocations, anchorCertificate,
            anchorAuthorization, ocr, ocrBytes, ocrHash);
    }

    /// <summary>
    /// Verifies and freezes the owner-signed RCD1, predecessor ROL1 and exact historical anchor
    /// before Registry allocates a responder key or prepares durable transaction state.
    /// </summary>
    public static VerifiedProductionMailboxRouteContinuityGenesisIntent VerifyGenesisIntent(
        ReadOnlyMemory<byte> canonicalDelegation,
        ReadOnlyMemory<byte> canonicalPreDelegationRouteOriginLkg,
        VerifiedProductionMailboxAuthority anchorAuthority,
        VerifiedProductionMailboxRevocationSnapshot anchorRevocations,
        VerifiedProductionMailboxRouteCertificate anchorCertificate,
        VerifiedProductionMailboxRouteAdvertisementV2 anchorAuthorization,
        ulong nowUnixSeconds,
        uint clockSkewSeconds = 0) => VerifyGenesisIntentCore(
        canonicalDelegation, canonicalPreDelegationRouteOriginLkg, anchorAuthority,
        anchorRevocations, anchorCertificate, anchorAuthorization, nowUnixSeconds,
        clockSkewSeconds);

    /// <summary>
    /// Authors the exact RDA1/OCR1/genesis-RHC1 cryptographic tuple outside the caller's store.
    /// The returned plan is data only; it cannot attest persistence, CAS success or publication.
    /// </summary>
    public static async ValueTask<ProductionMailboxRouteContinuityGenesisCommitPlan>
        AuthorGenesisAsync(
            VerifiedProductionMailboxRouteContinuityGenesisIntent intent,
            ulong acceptedAtUnixSeconds,
            ulong authorNowUnixSeconds,
            ReadOnlyMemory<byte> responderEd25519PublicKey,
            ulong ocrExpiresAtUnixSeconds,
            ProductionMailboxRda1Signer acceptanceSigner,
            ProductionMailboxOcr1Signer responderCertificateSigner,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(acceptanceSigner);
        ArgumentNullException.ThrowIfNull(responderCertificateSigner);
        ProductionMailboxRouteAuthorizationVerifier.ValidateClock(
            authorNowUnixSeconds, intent.ClockSkewSeconds);
        if (responderEd25519PublicKey.Length != 32 ||
            responderEd25519PublicKey.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("Genesis OCR1 responder key must be exact and non-zero.");
        if (acceptedAtUnixSeconds is 0 or ulong.MaxValue ||
            acceptedAtUnixSeconds > authorNowUnixSeconds ||
            ocrExpiresAtUnixSeconds <= acceptedAtUnixSeconds ||
            ocrExpiresAtUnixSeconds == ulong.MaxValue ||
            ocrExpiresAtUnixSeconds - acceptedAtUnixSeconds >
                ProductionMailboxOwnerControlConstants.MaximumResponderCertificateLifetimeSeconds)
            throw new FormatException("Genesis authoritative time or OCR1 lifetime is invalid.");
        var frozenResponderKey = responderEd25519PublicKey.ToArray();

        // Repeat the complete owned owner/anchor closure at authoring time. Using authorNow as the
        // provisional acceptance time makes all anchor/RCD expiry checks strict; skew never extends
        // the action lifetime.
        var repeated = VerifyGenesisIntentCore(intent.CanonicalDelegation,
            intent.CanonicalPreDelegationRouteOriginLkg, intent.Authority, intent.Revocations,
            intent.RouteCertificate, intent.RouteAuthorization, authorNowUnixSeconds,
            intent.ClockSkewSeconds);
        EqualProtected(repeated.IntentHash.Span, intent.IntentHash.Span, "genesis intent hash");
        var delegationBytes = intent.CanonicalDelegation.ToArray();
        var preRolBytes = intent.CanonicalPreDelegationRouteOriginLkg.ToArray();
        var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(delegationBytes);
        var preRol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(preRolBytes);
        if (authorNowUnixSeconds >= delegation.ExpiresAtUnixSeconds ||
            authorNowUnixSeconds >= ocrExpiresAtUnixSeconds ||
            ocrExpiresAtUnixSeconds > delegation.ExpiresAtUnixSeconds)
            throw new FormatException("Genesis RCD1/OCR1 is not strictly live at authoring time.");

        var unsignedAcceptance = CreateAcceptance(delegation, acceptedAtUnixSeconds,
            PlaceholderSignature());
        var acceptanceSigningBytes = ProductionMailboxRouteContinuityCodec
            .GetDelegationAcceptanceSigningBytes(unsignedAcceptance);
        var historicalContext = EnrollmentContextFromFrozenDelegation(
            delegation, acceptedAtUnixSeconds, 0);
        var provisionalAcceptanceBytes = ProductionMailboxRouteContinuityCodec
            .EncodeDelegationAcceptance(unsignedAcceptance);
        var provisionalEnrollment = ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(
            delegationBytes, provisionalAcceptanceBytes, intent.Authority, intent.Revocations,
            intent.RouteCertificate, intent.RouteAuthorization, historicalContext,
            new ExactTranscriptAcceptingVerifier(
                intent.Authority.Authority.MailboxIssuerEd25519PublicKey.Span,
                acceptanceSigningBytes));
        var provisionalState = CreateEnrollmentState(provisionalEnrollment, preRol);
        var provisionalOcr = CreateOcr(provisionalState, intent.Authority,
            frozenResponderKey, ocrExpiresAtUnixSeconds, PlaceholderSignature());
        VerifyOcrHistoricalClosure(provisionalOcr,
            ProductionMailboxOwnerControlTransportCodec.EncodeResponderCertificate(provisionalOcr),
            delegation, provisionalEnrollment.Acceptance, intent.Authority, intent.Revocations,
            intent.RouteCertificate, intent.RouteAuthorization, verifySignature: false);

        var signature = new byte[ProductionMailboxRouteContinuityConstants.Ed25519SignatureLength];
        var request = new ProductionMailboxRda1SigningRequest(acceptanceSigningBytes);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var written = await acceptanceSigner(request, signature, cancellationToken)
                .ConfigureAwait(false);
            EnsureSignatureLength(written, ProtocolMagic.RDA1);
            var signedAcceptance = unsignedAcceptance with
            {
                AnchorIssuerSignature = signature.ToArray()
            };
            var acceptanceBytes = ProductionMailboxRouteContinuityCodec
                .EncodeDelegationAcceptance(signedAcceptance);
            var enrollment = ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(
                delegationBytes, acceptanceBytes, intent.Authority, intent.Revocations,
                intent.RouteCertificate, intent.RouteAuthorization, historicalContext);
            var enrollmentState = CreateEnrollmentState(enrollment, preRol);
            var verifiedOcr = await AuthorOwnerControlResponderCertificateAsync(
                enrollmentState, intent.Authority, intent.Revocations, intent.RouteCertificate,
                intent.RouteAuthorization, frozenResponderKey, ocrExpiresAtUnixSeconds,
                responderCertificateSigner, cancellationToken).ConfigureAwait(false);
            var anchor = CreateHistoricalAnchor(enrollmentState, intent.Authority,
                intent.Revocations, intent.RouteCertificate, intent.RouteAuthorization,
                verifiedOcr);
            var cursor = ProductionMailboxRouteHistoryAuthoring.CreateInitialCursor(
                enrollmentState, intent.Authority, intent.Revocations);
            var plan = new ProductionMailboxRouteContinuityGenesisCommitPlan(intent,
                enrollmentState, anchor, cursor, acceptanceBytes, verifiedOcr.CanonicalBytes.Span);

            // Reconstruct both sealed post-CAS capabilities from exact plan bytes and protected
            // exports before returning any caller-observable data.
            var restoredAnchor = RestoreHistoricalAnchor(plan.CanonicalDelegation,
                plan.CanonicalAcceptance, plan.ExpectedPreDelegationRouteOriginLkg,
                plan.CanonicalEnrolledRouteOriginLkg,
                plan.CanonicalOwnerControlResponderCertificate, intent.Authority,
                intent.Revocations, intent.RouteCertificate, intent.RouteAuthorization,
                plan.ToProtectedEnrollmentRestoreContext());
            _ = ProductionMailboxRouteHistoryAuthoring.RestoreCursor(
                plan.CanonicalInitialRouteHistoryCheckpoint.Span, restoredAnchor,
                plan.ToProtectedRouteHistoryRestoreContext());
            return plan;
        }
        finally
        {
            request.Clear();
            CryptographicOperations.ZeroMemory(acceptanceSigningBytes);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    internal static async ValueTask<VerifiedProductionMailboxRouteContinuityEnrollmentState>
        AcceptDelegationAsync(
            ReadOnlyMemory<byte> canonicalDelegation,
            ReadOnlyMemory<byte> canonicalPreDelegationRouteOriginLkg,
            VerifiedProductionMailboxAuthority anchorAuthority,
            VerifiedProductionMailboxRevocationSnapshot anchorRevocations,
            VerifiedProductionMailboxRouteCertificate anchorCertificate,
            VerifiedProductionMailboxRouteAdvertisementV2 anchorAuthorization,
            ulong acceptedAtUnixSeconds,
            ulong nowUnixSeconds,
            uint clockSkewSeconds,
            ProductionMailboxRda1Signer signer,
            ProductionMailboxRouteContinuityEnrollmentCommitter committer,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(anchorAuthority);
        ArgumentNullException.ThrowIfNull(anchorRevocations);
        ArgumentNullException.ThrowIfNull(anchorCertificate);
        ArgumentNullException.ThrowIfNull(anchorAuthorization);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(committer);
        if (canonicalDelegation.Length !=
            ProductionMailboxRouteContinuityConstants.CanonicalDelegationLength)
            throw ContinuityError(ProductionMailboxRouteContinuityError.InvalidLength,
                "RCD1 canonical length is invalid.");
        if (canonicalPreDelegationRouteOriginLkg.Length !=
            ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength)
            throw ContinuityError(ProductionMailboxRouteContinuityError.InvalidLength,
                "Pre-delegation ROL1 canonical length is invalid.");
        ProductionMailboxRouteAuthorizationVerifier.ValidateClock(nowUnixSeconds, clockSkewSeconds);

        // The sole caller-owned buffer is frozen before it is decoded or any callback is invoked.
        var delegationBytes = canonicalDelegation.ToArray();
        var preDelegationRouteOriginBytes = canonicalPreDelegationRouteOriginLkg.ToArray();
        var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(delegationBytes);
        var preDelegationRouteOrigin = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(
            preDelegationRouteOriginBytes);
        VerifyPreDelegationRouteOrigin(delegation, preDelegationRouteOrigin);
        var acceptance = new ProductionMailboxRouteDelegationAcceptance
        {
            NetworkId = delegation.NetworkId.ToArray(),
            RouteDomainHash = delegation.RouteDomainHash.ToArray(),
            CanonicalDelegationHash = SHA256.HashData(delegationBytes),
            AnchorAuthorityGeneration = delegation.AnchorAuthorityGeneration,
            AnchorCanonicalAuthorityHash = delegation.AnchorCanonicalAuthorityHash.ToArray(),
            AnchorCanonicalRouteCertificateHash = delegation.AnchorCanonicalRouteCertificateHash.ToArray(),
            AnchorAuthorizationKind = delegation.AnchorAuthorizationKind,
            AnchorCanonicalRouteAuthorizationHash =
                delegation.AnchorCanonicalRouteAuthorizationHash.ToArray(),
            AnchorRouteAuthorizationSequence = delegation.AnchorRouteAuthorizationSequence,
            PreDelegationRouteOriginLkgHash = delegation.PreDelegationRouteOriginLkgHash.ToArray(),
            RouteVerifiedAtUnixSeconds = delegation.RouteVerifiedAtUnixSeconds,
            AcceptedAtUnixSeconds = acceptedAtUnixSeconds,
            AnchorIssuerSignature = PlaceholderSignature()
        };
        var signingBytes = ProductionMailboxRouteContinuityCodec
            .GetDelegationAcceptanceSigningBytes(acceptance);
        var context = EnrollmentContextFromFrozenDelegation(
            delegation, nowUnixSeconds, clockSkewSeconds);

        // Verify the real owner signature and complete anchor closure before the issuer is called.
        // Only this exact prospective RDA1 transcript is provisionally accepted during preflight.
        var unsignedAcceptanceBytes = ProductionMailboxRouteContinuityCodec
            .EncodeDelegationAcceptance(acceptance);
        _ = ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(
            delegationBytes, unsignedAcceptanceBytes, anchorAuthority, anchorRevocations,
            anchorCertificate, anchorAuthorization, context,
            new ExactTranscriptAcceptingVerifier(
                anchorAuthority.Authority.MailboxIssuerEd25519PublicKey.Span, signingBytes));

        var signature = new byte[ProductionMailboxRouteContinuityConstants.Ed25519SignatureLength];
        var request = new ProductionMailboxRda1SigningRequest(signingBytes);
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment;
        byte[] signedBytes;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var written = await signer(request, signature, cancellationToken).ConfigureAwait(false);
            if (written != ProductionMailboxRouteContinuityConstants.Ed25519SignatureLength)
                throw ContinuityError(ProductionMailboxRouteContinuityError.InvalidLength,
                    $"RDA1 signer wrote {written} bytes; exactly 64 are required.");
            var signed = acceptance with { AnchorIssuerSignature = signature.ToArray() };
            signedBytes = ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(signed);
            enrollment = ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(
                delegationBytes, signedBytes, anchorAuthority, anchorRevocations, anchorCertificate,
                anchorAuthorization, context);
        }
        finally
        {
            request.Clear();
            CryptographicOperations.ZeroMemory(signingBytes);
            CryptographicOperations.ZeroMemory(signature);
        }
        var enrolledRouteOrigin = new ProductionMailboxRouteOriginLkg
        {
            NetworkId = preDelegationRouteOrigin.NetworkId.ToArray(),
            RouteDomainHash = preDelegationRouteOrigin.RouteDomainHash.ToArray(),
            AuthorizationKind = preDelegationRouteOrigin.AuthorizationKind,
            CanonicalAuthorizationHash = preDelegationRouteOrigin.CanonicalAuthorizationHash.ToArray(),
            AuthorizationSequence = preDelegationRouteOrigin.AuthorizationSequence,
            CanonicalDelegationHash = enrollment.CanonicalDelegationHash.ToArray(),
            CanonicalDelegationAcceptanceHash = enrollment.CanonicalAcceptanceHash.ToArray(),
            OwnerRevocationGeneration = 0,
            OwnerRevocationHeadHash = new byte[ProductionMailboxRouteContinuityConstants.HashLength],
            RouteVerifiedAtUnixSeconds = preDelegationRouteOrigin.RouteVerifiedAtUnixSeconds,
            LocalCommitGeneration = preDelegationRouteOrigin.LocalCommitGeneration + 1
        };
        var enrolledRouteOriginBytes = ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(
            enrolledRouteOrigin);
        var enrolledRouteOriginHash = ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(
            enrolledRouteOrigin);
        var commitPlan = new ProductionMailboxRouteContinuityEnrollmentCommitPlan(
            preDelegationRouteOriginBytes,
            ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(preDelegationRouteOrigin),
            preDelegationRouteOrigin.LocalCommitGeneration,
            delegation.DelegationSequence - 1,
            delegation.PreviousCanonicalDelegationHash.Span,
            delegationBytes, enrollment.CanonicalDelegationHash.Span,
            signedBytes, enrollment.CanonicalAcceptanceHash.Span,
            enrolledRouteOriginBytes, enrolledRouteOriginHash);
        cancellationToken.ThrowIfCancellationRequested();
        if (!await committer(commitPlan, cancellationToken).ConfigureAwait(false))
            throw ContinuityError(ProductionMailboxRouteContinuityError.InvalidField,
                "Atomic continuity enrollment CAS commit was rejected.");
        return new VerifiedProductionMailboxRouteContinuityEnrollmentState(
            enrollment, preDelegationRouteOrigin, enrolledRouteOrigin);
    }

    internal static VerifiedProductionMailboxSelectionTransitionIntent
        CreateSelectionTransitionIntent(
            ProductionMailboxSelectionSuccessorMode mode,
            VerifiedProductionMailboxAuthority oldAuthority,
            VerifiedProductionMailboxTopology oldTopology,
            VerifiedProductionMailboxSelection oldSelection,
            VerifiedProductionMailboxAuthority currentAuthority,
            VerifiedProductionMailboxRevocationSnapshot currentRevocations,
            VerifiedProductionMailboxTopology currentTopology,
            VerifiedProductionMailboxSelection currentSelection,
            VerifiedProductionMailboxRouteCertificate routeCertificate,
            ulong nowUnixSeconds,
            uint clockSkewSeconds)
    {
        ArgumentNullException.ThrowIfNull(oldAuthority);
        ArgumentNullException.ThrowIfNull(oldTopology);
        ArgumentNullException.ThrowIfNull(oldSelection);
        ArgumentNullException.ThrowIfNull(currentAuthority);
        ArgumentNullException.ThrowIfNull(currentRevocations);
        ArgumentNullException.ThrowIfNull(currentTopology);
        ArgumentNullException.ThrowIfNull(currentSelection);
        ArgumentNullException.ThrowIfNull(routeCertificate);
        if (!Enum.IsDefined(mode))
            throw SelectionError(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                "Selection transition intent mode is unsupported.");
        ProductionMailboxRouteAuthorizationVerifier.ValidateClock(nowUnixSeconds, clockSkewSeconds);

        // Freeze each verified observation once before any deeper production verification.
        var oldAuthorityValue = oldAuthority.Authority;
        var oldAuthorityHash = oldAuthority.CanonicalAuthorityHash.ToArray();
        var oldTopologyValue = oldTopology.Snapshot;
        var oldTopologyHash = oldTopology.CanonicalTopologyHash.ToArray();
        var oldSelectionValue = oldSelection.Proof;
        var oldSelectionHash = oldSelection.CanonicalSelectionHash.ToArray();
        var currentAuthorityValue = currentAuthority.Authority;
        var currentAuthorityHash = currentAuthority.CanonicalAuthorityHash.ToArray();
        var currentRevocationValue = currentRevocations.Snapshot;
        var currentRevocationHash = currentRevocations.CanonicalSnapshotHash.ToArray();
        var currentTopologyValue = currentTopology.Snapshot;
        var currentTopologyHash = currentTopology.CanonicalTopologyHash.ToArray();
        var currentSelectionValue = currentSelection.Proof;
        var currentSelectionHash = currentSelection.CanonicalSelectionHash.ToArray();
        var certificate = routeCertificate.Certificate;
        var certificateHash = routeCertificate.CanonicalCertificateHash.ToArray();
        var pinnedMrX = SHA256.HashData(oldAuthorityValue.MrXApprovalEd25519PublicKey.Span);

        EqualSelection(oldTopologyValue.NetworkId.Span, oldAuthorityValue.NetworkId.Span,
            ProductionMailboxSelectionSuccessorError.NetworkMismatch,
            "Selection intent old PMT1 network differs from old PMA1.");
        EqualSelection(oldTopologyValue.CanonicalAuthorityHash.Span, oldAuthorityHash,
            ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
            "Selection intent old PMT1 authority hash differs from old PMA1.");
        if (oldTopologyValue.AuthorityGeneration != oldAuthorityValue.AuthorityGeneration)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
                "Selection intent old PMT1 authority generation differs from old PMA1.");

        VerifiedProductionMailboxAuthority reverifiedAuthority;
        try
        {
            if (mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion)
            {
                reverifiedAuthority = ProductionMailboxAuthorityVerifier.Verify(
                    currentAuthorityValue,
                    new ProductionMailboxAuthorityVerificationContext
                    {
                        PinnedMrXPublicKeySha256 = pinnedMrX,
                        ExpectedNetworkId = oldAuthorityValue.NetworkId.ToArray(),
                        LastCommittedGeneration = oldAuthorityValue.AuthorityGeneration,
                        LastCommittedAuthorityHash = oldAuthorityHash,
                        LastCommittedRevocationGeneration = oldAuthorityValue.Revocation.Generation,
                        LastCommittedRevocationHeadHash = oldAuthorityValue.Revocation.HeadHash.ToArray(),
                        LastCommittedRevocationSnapshotHash =
                            oldAuthorityValue.Revocation.SnapshotHash.ToArray(),
                        NowUnixSeconds = nowUnixSeconds,
                        ClockSkewSeconds = clockSkewSeconds
                    }, new SodiumProductionMailboxAuthoritySignatureVerifier());
            }
            else
            {
                reverifiedAuthority = ProductionMailboxAuthorityVerifier.VerifyForwardCheckpoint(
                    ProductionMailboxAuthorityCodec.Encode(currentAuthorityValue),
                    new ProductionMailboxAuthorityCheckpointVerificationContext
                    {
                        PinnedMrXPublicKeySha256 = pinnedMrX,
                        ExpectedNetworkId = oldAuthorityValue.NetworkId.ToArray(),
                        LastCommittedGeneration = oldAuthorityValue.AuthorityGeneration,
                        LastCommittedRevocationGeneration = oldAuthorityValue.Revocation.Generation,
                        LastCommittedRevocationHeadHash = oldAuthorityValue.Revocation.HeadHash.ToArray(),
                        LastCommittedRevocationSnapshotHash =
                            oldAuthorityValue.Revocation.SnapshotHash.ToArray(),
                        NowUnixSeconds = nowUnixSeconds,
                        ClockSkewSeconds = clockSkewSeconds
                    }, new SodiumProductionMailboxAuthoritySignatureVerifier());
            }
        }
        catch (ProductionMailboxAuthorityException exception)
        {
            throw SelectionError(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
                $"Selection intent authority closure is invalid: {exception.Message}");
        }
        EqualSelection(reverifiedAuthority.CanonicalAuthorityHash.Span, currentAuthorityHash,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            "Selection intent current PMA1 capability differs from the exact verified successor.");
        BindCurrentTopology(currentAuthorityValue, currentAuthorityHash, currentTopologyValue,
            mode, oldTopologyValue, oldTopologyHash, nowUnixSeconds, clockSkewSeconds);
        VerifyCurrentRevocationClosure(currentAuthorityValue, currentAuthorityHash,
            currentRevocationValue, currentRevocationHash, nowUnixSeconds, clockSkewSeconds);
        BindCertificateToSelectionClosure(certificate, certificateHash, currentAuthorityValue,
            currentAuthorityHash);

        BindSelectionToClosure(oldSelectionValue, oldSelectionHash, oldAuthorityValue,
            oldAuthorityHash, oldTopologyValue, oldTopologyHash, "old");
        BindSelectionToClosure(currentSelectionValue, currentSelectionHash, currentAuthorityValue,
            currentAuthorityHash, currentTopologyValue, currentTopologyHash, "current");
        VerifySelectionWindow(currentSelectionValue.IssuedAtUnixSeconds,
            currentSelectionValue.ExpiresAtUnixSeconds, nowUnixSeconds, clockSkewSeconds,
            "current PMS1");
        VerifySelectionWindow(certificate.IssuedAtUnixSeconds, certificate.ExpiresAtUnixSeconds,
            nowUnixSeconds, clockSkewSeconds, "current PRC1");
        EqualSelection(oldSelectionValue.SelectionInputCommitment.Span,
            certificate.SelectionInputCommitment.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch,
            "Selection intent old PMS1 selection input differs from the route.");
        EqualSelection(currentSelectionValue.SelectionInputCommitment.Span,
            certificate.SelectionInputCommitment.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch,
            "Selection intent current PMS1 selection input differs from the route.");

        if (mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion)
            VerifyDirectSelectionIntent(oldAuthorityValue, currentAuthorityValue,
                oldTopologyValue, currentTopologyValue, oldSelectionValue, currentSelectionValue,
                oldSelection.Replicas, currentSelection.Replicas, nowUnixSeconds, clockSkewSeconds);
        else
            VerifyOfflineSelectionIntent(oldAuthorityValue, currentAuthorityValue,
                oldTopologyValue, currentTopologyValue, oldSelectionValue, currentSelectionValue,
                nowUnixSeconds);

        var liveNotBefore = new[]
        {
            currentSelectionValue.IssuedAtUnixSeconds, certificate.IssuedAtUnixSeconds,
            currentTopologyValue.IssuedAtUnixSeconds, currentRevocationValue.IssuedAtUnixSeconds,
            currentAuthorityValue.CurrentEpoch.NotBeforeUnixSeconds,
            currentAuthorityValue.MrXApproval.RolloutNotBeforeUnixSeconds
        }.Max();
        var liveExpiresAt = new[]
        {
            currentSelectionValue.ExpiresAtUnixSeconds, certificate.ExpiresAtUnixSeconds,
            currentTopologyValue.ExpiresAtUnixSeconds, currentRevocationValue.ExpiresAtUnixSeconds,
            currentAuthorityValue.CurrentEpoch.NotAfterUnixSeconds,
            currentAuthorityValue.MrXApproval.RolloutNotAfterUnixSeconds
        }.Min();
        if (mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion)
        {
            liveNotBefore = Math.Max(liveNotBefore, oldSelectionValue.IssuedAtUnixSeconds);
            liveExpiresAt = Math.Min(liveExpiresAt, oldSelectionValue.ExpiresAtUnixSeconds);
        }
        if (liveNotBefore >= liveExpiresAt)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.InvalidValidityWindow,
                "Selection transition intent has no common live authorization window.");
        return new VerifiedProductionMailboxSelectionTransitionIntent(
            mode, certificate.NetworkId.Span, certificate.SelectionInputCommitment.Span,
            oldSelectionHash, currentSelectionHash, currentAuthorityHash, currentRevocationHash,
            currentTopologyHash, certificateHash, liveNotBefore, liveExpiresAt,
            oldAuthority, oldTopology, oldSelection, currentAuthority, currentRevocations,
            currentTopology, currentSelection, routeCertificate);
    }

    public static VerifiedProductionMailboxSelectionTransitionIntent
        CreateDirectSelectionTransitionIntent(
            VerifiedProductionMailboxRouteHistoryCursor currentRoute,
            VerifiedProductionMailboxAuthority oldAuthority,
            VerifiedProductionMailboxTopology oldTopology,
            VerifiedProductionMailboxSelection oldSelection,
            VerifiedProductionMailboxAuthority currentAuthority,
            VerifiedProductionMailboxRevocationSnapshot currentRevocations,
            VerifiedProductionMailboxTopology currentTopology,
            VerifiedProductionMailboxSelection currentSelection,
            VerifiedProductionMailboxSelection nextSelection,
            VerifiedProductionMailboxRouteCertificate routeCertificate,
            ulong nowUnixSeconds, uint clockSkewSeconds)
    {
        var intent = CreateSelectionTransitionIntent(ProductionMailboxSelectionSuccessorMode.DirectPromotion,
            oldAuthority, oldTopology, oldSelection, currentAuthority, currentRevocations,
            currentTopology, currentSelection, routeCertificate, nowUnixSeconds, clockSkewSeconds);
        return BindNextSelection(intent, nextSelection, currentRoute, routeCertificate,
            currentAuthority, currentTopology, nowUnixSeconds, clockSkewSeconds);
    }

    public static VerifiedProductionMailboxSelectionTransitionIntent
        CreateOfflineSelectionTransitionIntent(
            VerifiedProductionMailboxRouteHistoryCursor currentRoute,
            VerifiedProductionMailboxAuthority oldAuthority,
            VerifiedProductionMailboxTopology oldTopology,
            VerifiedProductionMailboxSelection oldSelection,
            VerifiedProductionMailboxAuthority currentAuthority,
            VerifiedProductionMailboxRevocationSnapshot currentRevocations,
            VerifiedProductionMailboxTopology currentTopology,
            VerifiedProductionMailboxSelection currentSelection,
            VerifiedProductionMailboxSelection nextSelection,
            VerifiedProductionMailboxRouteCertificate routeCertificate,
            ulong nowUnixSeconds,
            uint clockSkewSeconds)
    {
        var intent = CreateSelectionTransitionIntent(
            ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            oldAuthority, oldTopology, oldSelection, currentAuthority, currentRevocations,
            currentTopology, currentSelection, routeCertificate, nowUnixSeconds, clockSkewSeconds);
        return BindNextSelection(intent, nextSelection, currentRoute, routeCertificate,
            currentAuthority, currentTopology, nowUnixSeconds, clockSkewSeconds);
    }

    private static VerifiedProductionMailboxSelectionTransitionIntent BindNextSelection(
        VerifiedProductionMailboxSelectionTransitionIntent intent,
        VerifiedProductionMailboxSelection nextSelection,
        VerifiedProductionMailboxRouteHistoryCursor currentRoute,
        VerifiedProductionMailboxRouteCertificate routeCertificate,
        VerifiedProductionMailboxAuthority currentAuthority,
        VerifiedProductionMailboxTopology currentTopology,
        ulong nowUnixSeconds, uint clockSkewSeconds)
    {
        ArgumentNullException.ThrowIfNull(nextSelection); ArgumentNullException.ThrowIfNull(currentRoute);
        var certificate = routeCertificate.Certificate;
        var canonicalNext = ProductionMailboxTopologyCodec.EncodeSelection(nextSelection.Proof);
        var reverified = ProductionMailboxSelectionVerifier.Verify(canonicalNext, currentAuthority,
            currentTopology, new BlindedPlacementId(certificate.BlindedPlacementId.Span),
            nowUnixSeconds, clockSkewSeconds, new SodiumProductionMailboxTopologySignatureVerifier());
        if (!CryptographicOperations.FixedTimeEquals(reverified.CanonicalSelectionHash.Span,
                nextSelection.CanonicalSelectionHash.Span) ||
            nextSelection.Proof.Epoch != currentTopology.Snapshot.NextEpoch.Epoch)
            throw new FormatException("Offline next PMS1 is not the exact verified next-epoch selection.");
        var checkpoint = currentRoute.Checkpoint.TrustedCheckpoint;
        var currentRol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(
            currentRoute.CanonicalCurrentRouteOriginLkg());
        if (!CryptographicOperations.FixedTimeEquals(checkpoint.CurrentCanonicalAuthorityHash.Span,
                currentAuthority.CanonicalAuthorityHash.Span) ||
            checkpoint.CurrentAuthorityGeneration != currentAuthority.Authority.AuthorityGeneration ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRevocationSnapshotHash.Span,
                intent.CurrentRevocations.CanonicalSnapshotHash.Span) ||
            checkpoint.CurrentRevocationGeneration != intent.CurrentRevocations.Snapshot.RevocationGeneration ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRevocationHeadHash.Span,
                intent.CurrentRevocations.Snapshot.RevocationHeadHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRouteOriginLkgHash.Span,
                ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(currentRol)) ||
            !CryptographicOperations.FixedTimeEquals(currentRol.NetworkId.Span, certificate.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(certificate.SelectionInputCommitment.Span,
                currentRoute.Enrollment.VerifiedDelegation.Delegation.SelectionInputCommitment.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(certificate),
                currentRol.RouteDomainHash.Span))
            throw new FormatException("Selection intent differs from its sealed current route/control plane.");
        return intent.WithNextSelection(nextSelection, currentRoute);
    }

    private static void VerifyOcrHistoricalClosure(
        ProductionMailboxOwnerControlResponderCertificate ocr, ReadOnlySpan<byte> canonicalOcr,
        ProductionMailboxRouteContinuityDelegation delegation,
        ProductionMailboxRouteDelegationAcceptance acceptance,
        VerifiedProductionMailboxAuthority authorityHandle,
        VerifiedProductionMailboxRevocationSnapshot revocationsHandle,
        VerifiedProductionMailboxRouteCertificate certificateHandle,
        VerifiedProductionMailboxRouteAdvertisementV2 authorizationHandle,
        bool verifySignature = true)
    {
        var authority = authorityHandle.Authority;
        var revocations = revocationsHandle.Snapshot;
        var certificate = certificateHandle.Certificate;
        var authorization = authorizationHandle.Advertisement;
        var issued = ocr.IssuedAtUnixSeconds; var expires = ocr.ExpiresAtUnixSeconds;
        if (issued != acceptance.AcceptedAtUnixSeconds || expires > delegation.ExpiresAtUnixSeconds ||
            issued < delegation.NotBeforeUnixSeconds || issued < authority.CurrentEpoch.NotBeforeUnixSeconds ||
            issued < authority.MrXApproval.RolloutNotBeforeUnixSeconds ||
            issued < authority.Revocation.IssuedAtUnixSeconds || issued < revocations.IssuedAtUnixSeconds ||
            issued < certificate.IssuedAtUnixSeconds || issued < authorization.PublishedAtUnixSeconds)
            throw new FormatException("OCR1 lifetime is outside the exact historical anchor windows.");
        EqualProtected(ocr.NetworkId.Span, delegation.NetworkId.Span, "OCR1 network");
        EqualProtected(ocr.MailboxOwnerEd25519PublicKey.Span,
            delegation.MailboxOwnerEd25519PublicKey.Span, "OCR1 owner");
        EqualProtected(ocr.RouteDomainHash.Span, delegation.RouteDomainHash.Span, "OCR1 route");
        EqualProtected(ocr.AnchorCanonicalAuthorityHash.Span,
            authorityHandle.CanonicalAuthorityHash.Span, "OCR1 PMA1 hash");
        EqualProtected(authorityHandle.CanonicalAuthorityHash.Span,
            delegation.AnchorCanonicalAuthorityHash.Span, "RCD1 anchor PMA1 hash");
        EqualProtected(certificateHandle.CanonicalCertificateHash.Span,
            delegation.AnchorCanonicalRouteCertificateHash.Span, "RCD1 anchor PRC1 hash");
        EqualProtected(authorizationHandle.CanonicalHash.Span,
            delegation.AnchorCanonicalRouteAuthorizationHash.Span, "RCD1 anchor PRA2 hash");
        EqualProtected(revocationsHandle.CanonicalSnapshotHash.Span,
            authority.Revocation.SnapshotHash.Span, "anchor PMR1 hash");
        if (authority.AuthorityGeneration != delegation.AnchorAuthorityGeneration ||
            authorization.AuthorizationKind() != delegation.AnchorAuthorizationKind ||
            authorization.Sequence != delegation.AnchorRouteAuthorizationSequence ||
            revocations.AuthorityGeneration != authority.AuthorityGeneration ||
            revocations.RevocationGeneration != authority.Revocation.Generation)
            throw new FormatException("OCR1 historical anchor generations or authorization differ from RCD1.");
        EqualProtected(authority.MailboxIssuerEd25519PublicKey.Span,
            certificate.IssuerEd25519PublicKey.Span, "OCR1 exact PMA1 issuer");
        var verifier = new SodiumProductionMailboxRouteSignatureVerifier();
        if (verifySignature && !verifier.Verify(authority.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxOwnerControlTransportCodec.GetOcrSigningBytes(ocr),
                ocr.AnchorIssuerSignature.Span))
            throw new FormatException("OCR1 anchor-issuer signature is invalid.");
        if (!canonicalOcr.SequenceEqual(ProductionMailboxOwnerControlTransportCodec.EncodeResponderCertificate(ocr)))
            throw new FormatException("OCR1 canonical re-encoding differs.");
    }

    private static void EqualProtected(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string name)
    {
        if (actual.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw new FormatException($"Historical protected {name} binding differs.");
    }

    internal static async ValueTask<VerifiedProductionMailboxDelegatedRouteAuthorization>
        AuthorDelegatedActivationAsync(
            VerifiedProductionMailboxRouteContinuityEnrollmentState enrollmentState,
            VerifiedProductionMailboxSelectionTransitionIntent selectionIntent,
            VerifiedProductionMailboxAuthority currentAuthority,
            VerifiedProductionMailboxRevocationSnapshot currentRevocations,
            VerifiedProductionMailboxRouteCertificate freshCertificate,
            VerifiedProductionMailboxRouteAdvertisementV2 predecessorAuthorization,
            ReadOnlyMemory<byte> transitionSalt,
            ulong checkpointIssuedAtUnixSeconds,
            ulong checkpointExpiresAtUnixSeconds,
            ulong transitionNotBeforeUnixSeconds,
            ulong transitionExpiresAtUnixSeconds,
            ulong activationIssuedAtUnixSeconds,
            ulong activationExpiresAtUnixSeconds,
            ulong nowUnixSeconds,
            uint clockSkewSeconds,
            ProductionMailboxRch1Signer checkpointSigner,
            ProductionMailboxRca1Signer activationSigner,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(enrollmentState);
        ArgumentNullException.ThrowIfNull(selectionIntent);
        ArgumentNullException.ThrowIfNull(currentAuthority);
        ArgumentNullException.ThrowIfNull(currentRevocations);
        ArgumentNullException.ThrowIfNull(freshCertificate);
        ArgumentNullException.ThrowIfNull(predecessorAuthorization);
        ArgumentNullException.ThrowIfNull(checkpointSigner);
        ArgumentNullException.ThrowIfNull(activationSigner);
        if (transitionSalt.Length != ProductionMailboxRouteAuthorizationConstants.HashLength)
            throw AuthorizationError(ProductionMailboxRouteAuthorizationError.InvalidLength,
                "RCH1 transition salt must be exactly 32 bytes.");
        ProductionMailboxRouteAuthorizationVerifier.ValidateClock(nowUnixSeconds, clockSkewSeconds);

        // Freeze every caller-observable value before either external callback.
        var enrollment = enrollmentState.Enrollment;
        var salt = transitionSalt.ToArray();
        var delegation = enrollment.Delegation;
        var acceptance = enrollment.Acceptance;
        var authority = currentAuthority.Authority;
        var revocations = currentRevocations.Snapshot;
        var certificate = freshCertificate.Certificate;
        var predecessor = predecessorAuthorization.Advertisement;
        var predecessorHash = predecessorAuthorization.CanonicalHash.ToArray();
        var oldSelectionHash = selectionIntent.OldCanonicalSelectionHash.ToArray();
        var newSelectionHash = selectionIntent.CurrentCanonicalSelectionHash.ToArray();
        var delegationHash = enrollment.CanonicalDelegationHash.ToArray();
        var acceptanceHash = enrollment.CanonicalAcceptanceHash.ToArray();
        var enrolledRouteOrigin = enrollmentState.EnrolledRouteOrigin;
        var oldRouteOriginHash = enrollmentState.EnrolledRouteOriginLkgHash.ToArray();
        var currentAuthorityHash = currentAuthority.CanonicalAuthorityHash.ToArray();
        var freshCertificateHash = freshCertificate.CanonicalCertificateHash.ToArray();
        var currentRevocationHash = currentRevocations.CanonicalSnapshotHash.ToArray();

        BindSelectionIntent(selectionIntent, currentAuthority, currentRevocations,
            freshCertificate, delegation, nowUnixSeconds, transitionNotBeforeUnixSeconds,
            transitionExpiresAtUnixSeconds);
        BindPredecessorToEnrollment(delegation, predecessorAuthorization);
        if (predecessor.Sequence == ulong.MaxValue)
            throw AuthorizationError(ProductionMailboxRouteAuthorizationError.InvalidField,
                "Delegated activation predecessor sequence cannot advance.");
        var activationSequence = predecessor.Sequence + 1;
        if (activationSequence < delegation.FirstActivationSequence ||
            activationSequence > delegation.LastActivationSequence)
            throw AuthorizationError(ProductionMailboxRouteAuthorizationError.InvalidField,
                "Delegated activation sequence is outside the owner-delegated range.");

        var zeroRevocationHead = new byte[ProductionMailboxRouteContinuityConstants.HashLength];
        var commitment = ProductionMailboxRouteContinuityCodec.ComputeContinuityTransitionCommitment(
            salt, delegation.NetworkId.Span, delegation.RouteDomainHash.Span,
            delegationHash, acceptanceHash, oldRouteOriginHash, 0, zeroRevocationHead,
            currentAuthorityHash, freshCertificateHash, predecessor.AuthorizationKind(),
            predecessorHash, predecessor.Sequence, activationSequence);

        var unsignedCheckpoint = new ProductionMailboxRouteRevocationCheckpoint
        {
            NetworkId = delegation.NetworkId.ToArray(),
            RouteDomainHash = delegation.RouteDomainHash.ToArray(),
            CurrentAuthorityGeneration = authority.AuthorityGeneration,
            CurrentCanonicalAuthorityHash = currentAuthorityHash,
            CurrentIssuerEd25519PublicKey = authority.MailboxIssuerEd25519PublicKey.ToArray(),
            CurrentOwnerRevocationGeneration = 0,
            CurrentOwnerRevocationHeadHash = zeroRevocationHead,
            TransitionSalt = salt,
            ContinuityTransitionCommitment = commitment,
            Status = ProductionMailboxRouteRevocationStatus.Active,
            IssuedAtUnixSeconds = checkpointIssuedAtUnixSeconds,
            ExpiresAtUnixSeconds = checkpointExpiresAtUnixSeconds,
            CurrentIssuerSignature = PlaceholderSignature()
        };
        var checkpointSigningBytes = ProductionMailboxRouteContinuityCodec
            .GetRevocationCheckpointSigningBytes(unsignedCheckpoint);
        var provisionalCheckpointBytes = ProductionMailboxRouteContinuityCodec
            .EncodeRevocationCheckpoint(unsignedCheckpoint);
        var provisionalCheckpoint = ProductionMailboxRouteContinuityVerifier.VerifyRevocationCheckpoint(
            provisionalCheckpointBytes, currentAuthority, currentRevocations,
            enrollment.VerifiedDelegation, salt, commitment, 0, zeroRevocationHead,
            nowUnixSeconds, clockSkewSeconds,
            new ExactTranscriptAcceptingVerifier(
                authority.MailboxIssuerEd25519PublicKey.Span, checkpointSigningBytes));

        var provisionalTransition = CreateTransition(
            selectionIntent.Mode, delegation, predecessor, predecessorHash,
            oldSelectionHash, newSelectionHash,
            freshCertificateHash, activationSequence, salt, commitment,
            provisionalCheckpoint.CanonicalHash.Span, currentAuthorityHash,
            authority.AuthorityGeneration, oldRouteOriginHash,
            enrolledRouteOrigin.LocalCommitGeneration,
            transitionNotBeforeUnixSeconds, transitionExpiresAtUnixSeconds);
        var provisionalTransitionBytes = ProductionMailboxRouteAuthorizationCodec
            .EncodeTransitionContext(provisionalTransition);
        var verifiedProvisionalTransition = ProductionMailboxRouteAuthorizationVerifier
            .VerifyTransitionContext(provisionalTransitionBytes, delegation.NetworkId.Span,
                delegation.RouteDomainHash.Span, oldSelectionHash, newSelectionHash,
                oldRouteOriginHash, enrolledRouteOrigin.RouteVerifiedAtUnixSeconds,
                enrolledRouteOrigin.LocalCommitGeneration);
        var provisionalActivation = CreateActivation(
            authority, revocations, currentAuthorityHash, currentRevocationHash,
            freshCertificateHash, provisionalCheckpoint.CanonicalHash.Span,
            ProductionMailboxRouteAuthorizationCodec.ComputeTransitionContextHash(provisionalTransition),
            predecessor, predecessorHash, activationSequence, salt, commitment,
            activationIssuedAtUnixSeconds, activationExpiresAtUnixSeconds);
        var provisionalActivationSigningBytes = ProductionMailboxRouteAuthorizationCodec
            .GetContinuityActivationSigningBytes(provisionalActivation);
        _ = ProductionMailboxRouteAuthorizationVerifier.VerifyDelegatedActivation(
            ProductionMailboxRouteAuthorizationCodec.EncodeContinuityActivation(provisionalActivation),
            currentAuthority, currentRevocations, freshCertificate, provisionalCheckpoint,
            verifiedProvisionalTransition, enrollment, nowUnixSeconds, clockSkewSeconds,
            new ExactTranscriptAcceptingVerifier(
                authority.MailboxIssuerEd25519PublicKey.Span, provisionalActivationSigningBytes));
        CryptographicOperations.ZeroMemory(provisionalActivationSigningBytes);

        var checkpointSignature = new byte[ProductionMailboxRouteContinuityConstants.Ed25519SignatureLength];
        var checkpointRequest = new ProductionMailboxRch1SigningRequest(checkpointSigningBytes);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var checkpointWritten = await checkpointSigner(
                checkpointRequest, checkpointSignature, cancellationToken).ConfigureAwait(false);
            EnsureSignatureLength(checkpointWritten, ProtocolMagic.RCH1);
            var checkpointArtifact = unsignedCheckpoint with
            {
                CurrentIssuerSignature = checkpointSignature.ToArray()
            };
            var checkpointBytes = ProductionMailboxRouteContinuityCodec
                .EncodeRevocationCheckpoint(checkpointArtifact);
            var verifiedCheckpoint = ProductionMailboxRouteContinuityVerifier.VerifyRevocationCheckpoint(
                checkpointBytes, currentAuthority, currentRevocations, enrollment.VerifiedDelegation,
                salt, commitment, 0, zeroRevocationHead, nowUnixSeconds, clockSkewSeconds,
                new SodiumProductionMailboxRouteSignatureVerifier());

            var transition = CreateTransition(
                selectionIntent.Mode, delegation, predecessor, predecessorHash,
                oldSelectionHash, newSelectionHash,
                freshCertificateHash, activationSequence, salt, commitment,
                verifiedCheckpoint.CanonicalHash.Span, currentAuthorityHash,
                authority.AuthorityGeneration, oldRouteOriginHash,
                enrolledRouteOrigin.LocalCommitGeneration,
                transitionNotBeforeUnixSeconds,
                transitionExpiresAtUnixSeconds);
            var transitionBytes = ProductionMailboxRouteAuthorizationCodec.EncodeTransitionContext(transition);
            var verifiedTransition = ProductionMailboxRouteAuthorizationVerifier.VerifyTransitionContext(
                transitionBytes, delegation.NetworkId.Span, delegation.RouteDomainHash.Span,
                oldSelectionHash, newSelectionHash, oldRouteOriginHash,
                enrolledRouteOrigin.RouteVerifiedAtUnixSeconds,
                enrolledRouteOrigin.LocalCommitGeneration);

            var unsignedActivation = CreateActivation(
                authority, revocations, currentAuthorityHash, currentRevocationHash,
                freshCertificateHash, verifiedCheckpoint.CanonicalHash.Span,
                verifiedTransition.CanonicalHash.Span, predecessor, predecessorHash,
                activationSequence, salt, commitment, activationIssuedAtUnixSeconds,
                activationExpiresAtUnixSeconds);
            var activationSigningBytes = ProductionMailboxRouteAuthorizationCodec
                .GetContinuityActivationSigningBytes(unsignedActivation);
            var activationSignature = new byte[ProductionMailboxRouteContinuityConstants.Ed25519SignatureLength];
            var activationRequest = new ProductionMailboxRca1SigningRequest(activationSigningBytes);
            try
            {
                var provisionalRealActivation = ProductionMailboxRouteAuthorizationCodec
                    .EncodeContinuityActivation(unsignedActivation);
                _ = ProductionMailboxRouteAuthorizationVerifier.VerifyDelegatedActivation(
                    provisionalRealActivation, currentAuthority, currentRevocations, freshCertificate,
                    verifiedCheckpoint, verifiedTransition, enrollment, nowUnixSeconds, clockSkewSeconds,
                    new ExactTranscriptAcceptingVerifier(
                        authority.MailboxIssuerEd25519PublicKey.Span, activationSigningBytes));

                cancellationToken.ThrowIfCancellationRequested();
                var activationWritten = await activationSigner(
                    activationRequest, activationSignature, cancellationToken).ConfigureAwait(false);
                EnsureSignatureLength(activationWritten, ProtocolMagic.RCA1);
                var activationArtifact = unsignedActivation with
                {
                    CurrentIssuerSignature = activationSignature.ToArray()
                };
                var activationBytes = ProductionMailboxRouteAuthorizationCodec
                    .EncodeContinuityActivation(activationArtifact);
                var verifiedActivation = ProductionMailboxRouteAuthorizationVerifier
                    .VerifyDelegatedActivation(activationBytes, currentAuthority, currentRevocations,
                        freshCertificate, verifiedCheckpoint, verifiedTransition, enrollment,
                        nowUnixSeconds, clockSkewSeconds,
                        new SodiumProductionMailboxRouteSignatureVerifier());
                return new VerifiedProductionMailboxDelegatedRouteAuthorization(
                    verifiedCheckpoint, verifiedTransition, verifiedActivation);
            }
            finally
            {
                activationRequest.Clear();
                CryptographicOperations.ZeroMemory(activationSigningBytes);
                CryptographicOperations.ZeroMemory(activationSignature);
            }
        }
        finally
        {
            checkpointRequest.Clear();
            CryptographicOperations.ZeroMemory(checkpointSigningBytes);
            CryptographicOperations.ZeroMemory(checkpointSignature);
        }
    }

    private static VerifiedProductionMailboxRouteContinuityGenesisIntent VerifyGenesisIntentCore(
        ReadOnlyMemory<byte> canonicalDelegation,
        ReadOnlyMemory<byte> canonicalPreDelegationRouteOriginLkg,
        VerifiedProductionMailboxAuthority anchorAuthority,
        VerifiedProductionMailboxRevocationSnapshot anchorRevocations,
        VerifiedProductionMailboxRouteCertificate anchorCertificate,
        VerifiedProductionMailboxRouteAdvertisementV2 anchorAuthorization,
        ulong nowUnixSeconds,
        uint clockSkewSeconds)
    {
        ArgumentNullException.ThrowIfNull(anchorAuthority);
        ArgumentNullException.ThrowIfNull(anchorRevocations);
        ArgumentNullException.ThrowIfNull(anchorCertificate);
        ArgumentNullException.ThrowIfNull(anchorAuthorization);
        if (canonicalDelegation.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalDelegationLength ||
            canonicalPreDelegationRouteOriginLkg.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength)
            throw ContinuityError(ProductionMailboxRouteContinuityError.InvalidLength,
                "Genesis RCD1/pre-ROL1 length is invalid.");
        ProductionMailboxRouteAuthorizationVerifier.ValidateClock(nowUnixSeconds, clockSkewSeconds);
        var delegationBytes = canonicalDelegation.ToArray();
        var preRolBytes = canonicalPreDelegationRouteOriginLkg.ToArray();
        var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(delegationBytes);
        var preRol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(preRolBytes);
        if (!delegationBytes.AsSpan().SequenceEqual(
                ProductionMailboxRouteContinuityCodec.EncodeDelegation(delegation)) ||
            !preRolBytes.AsSpan().SequenceEqual(
                ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(preRol)))
            throw new FormatException("Genesis RCD1/pre-ROL1 is not canonical.");
        VerifyPreDelegationRouteOrigin(delegation, preRol);

        var authorityBytes = ProductionMailboxAuthorityCodec.Encode(anchorAuthority.Authority);
        var revocationBytes = ProductionMailboxRevocationSnapshotCodec.Encode(
            anchorRevocations.Snapshot);
        var certificateBytes = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
            anchorCertificate.Certificate);
        var authorizationBytes = anchorAuthorization.CanonicalBytes.ToArray();
        EqualProtected(ProductionMailboxAuthorityCodec.ComputeCanonicalHash(
            anchorAuthority.Authority), anchorAuthority.CanonicalAuthorityHash.Span,
            "genesis PMA1 canonical hash");
        EqualProtected(ProductionMailboxRevocationSnapshotCodec.ComputeCanonicalHash(
            anchorRevocations.Snapshot), anchorRevocations.CanonicalSnapshotHash.Span,
            "genesis PMR1 canonical hash");
        EqualProtected(ProductionMailboxRouteAdvertisementCodec
            .ComputeCertificateCanonicalHash(anchorCertificate.Certificate),
            anchorCertificate.CanonicalCertificateHash.Span,
            "genesis PRC1 canonical hash");
        EqualProtected(ProductionMailboxRouteAuthorizationCodec
            .ComputeAdvertisementV2CanonicalHash(anchorAuthorization.Advertisement),
            anchorAuthorization.CanonicalHash.Span, "genesis PRA2 canonical hash");
        if (!authorizationBytes.AsSpan().SequenceEqual(
                ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(
                    anchorAuthorization.Advertisement)))
            throw new FormatException("Genesis PRA2 canonical bytes differ.");

        var provisionalAcceptance = CreateAcceptance(delegation, nowUnixSeconds,
            PlaceholderSignature());
        var signingBytes = ProductionMailboxRouteContinuityCodec
            .GetDelegationAcceptanceSigningBytes(provisionalAcceptance);
        try
        {
            _ = ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(delegationBytes,
                ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(
                    provisionalAcceptance), anchorAuthority, anchorRevocations,
                anchorCertificate, anchorAuthorization,
                EnrollmentContextFromFrozenDelegation(delegation, nowUnixSeconds,
                    clockSkewSeconds),
                new ExactTranscriptAcceptingVerifier(
                    anchorAuthority.Authority.MailboxIssuerEd25519PublicKey.Span,
                    signingBytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingBytes);
        }
        return new VerifiedProductionMailboxRouteContinuityGenesisIntent(delegationBytes,
            preRolBytes, authorityBytes, revocationBytes, certificateBytes, authorizationBytes,
            anchorAuthority, anchorRevocations, anchorCertificate, anchorAuthorization,
            nowUnixSeconds, clockSkewSeconds);
    }

    private static ProductionMailboxRouteDelegationAcceptance CreateAcceptance(
        ProductionMailboxRouteContinuityDelegation delegation,
        ulong acceptedAtUnixSeconds,
        ReadOnlyMemory<byte> signature) => new()
    {
        NetworkId = delegation.NetworkId.ToArray(),
        RouteDomainHash = delegation.RouteDomainHash.ToArray(),
        CanonicalDelegationHash = SHA256.HashData(
            ProductionMailboxRouteContinuityCodec.EncodeDelegation(delegation)),
        AnchorAuthorityGeneration = delegation.AnchorAuthorityGeneration,
        AnchorCanonicalAuthorityHash = delegation.AnchorCanonicalAuthorityHash.ToArray(),
        AnchorCanonicalRouteCertificateHash =
            delegation.AnchorCanonicalRouteCertificateHash.ToArray(),
        AnchorAuthorizationKind = delegation.AnchorAuthorizationKind,
        AnchorCanonicalRouteAuthorizationHash =
            delegation.AnchorCanonicalRouteAuthorizationHash.ToArray(),
        AnchorRouteAuthorizationSequence = delegation.AnchorRouteAuthorizationSequence,
        PreDelegationRouteOriginLkgHash = delegation.PreDelegationRouteOriginLkgHash.ToArray(),
        RouteVerifiedAtUnixSeconds = delegation.RouteVerifiedAtUnixSeconds,
        AcceptedAtUnixSeconds = acceptedAtUnixSeconds,
        AnchorIssuerSignature = signature.ToArray()
    };

    private static ProductionMailboxOwnerControlResponderCertificate CreateOcr(
        VerifiedProductionMailboxRouteContinuityEnrollmentState enrollmentState,
        VerifiedProductionMailboxAuthority anchorAuthority,
        ReadOnlySpan<byte> responderEd25519PublicKey,
        ulong expiresAtUnixSeconds,
        ReadOnlyMemory<byte> signature)
    {
        var delegation = enrollmentState.Enrollment.Delegation;
        return new ProductionMailboxOwnerControlResponderCertificate
        {
            NetworkId = delegation.NetworkId.ToArray(),
            MailboxOwnerEd25519PublicKey = delegation.MailboxOwnerEd25519PublicKey.ToArray(),
            RouteDomainHash = delegation.RouteDomainHash.ToArray(),
            AnchorCanonicalAuthorityHash = anchorAuthority.CanonicalAuthorityHash.ToArray(),
            ResponderEd25519PublicKey = responderEd25519PublicKey.ToArray(),
            IssuedAtUnixSeconds = enrollmentState.Enrollment.Acceptance.AcceptedAtUnixSeconds,
            ExpiresAtUnixSeconds = expiresAtUnixSeconds,
            KeyGeneration = 1,
            PreviousCanonicalCertificateHash = new byte[32],
            AnchorIssuerSignature = signature.ToArray()
        };
    }

    private static VerifiedProductionMailboxRouteContinuityEnrollmentState CreateEnrollmentState(
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment,
        ProductionMailboxRouteOriginLkg preRol)
    {
        var enrolled = new ProductionMailboxRouteOriginLkg
        {
            NetworkId = preRol.NetworkId.ToArray(),
            RouteDomainHash = preRol.RouteDomainHash.ToArray(),
            AuthorizationKind = preRol.AuthorizationKind,
            CanonicalAuthorizationHash = preRol.CanonicalAuthorizationHash.ToArray(),
            AuthorizationSequence = preRol.AuthorizationSequence,
            CanonicalDelegationHash = enrollment.CanonicalDelegationHash.ToArray(),
            CanonicalDelegationAcceptanceHash = enrollment.CanonicalAcceptanceHash.ToArray(),
            OwnerRevocationGeneration = 0,
            OwnerRevocationHeadHash = new byte[32],
            RouteVerifiedAtUnixSeconds = preRol.RouteVerifiedAtUnixSeconds,
            LocalCommitGeneration = checked(preRol.LocalCommitGeneration + 1)
        };
        return new VerifiedProductionMailboxRouteContinuityEnrollmentState(enrollment, preRol,
            enrolled);
    }

    private static ProductionMailboxRouteContinuityEnrollmentVerificationContext
        EnrollmentContextFromFrozenDelegation(
            ProductionMailboxRouteContinuityDelegation delegation,
            ulong nowUnixSeconds,
            uint clockSkewSeconds) => new()
        {
            ExpectedNetworkId = delegation.NetworkId.ToArray(),
            ExpectedPinnedMrXPublicKeySha256 = delegation.PinnedMrXPublicKeySha256.ToArray(),
            ExpectedRouteDomainHash = delegation.RouteDomainHash.ToArray(),
            ExpectedMailboxOwnerEd25519PublicKey = delegation.MailboxOwnerEd25519PublicKey.ToArray(),
            ExpectedBlindedMailboxId = delegation.BlindedMailboxId.ToArray(),
            ExpectedBlindedPlacementId = delegation.BlindedPlacementId.ToArray(),
            ExpectedSelectionInputCommitment = delegation.SelectionInputCommitment.ToArray(),
            ExpectedPreDelegationRouteOriginLkgHash =
                delegation.PreDelegationRouteOriginLkgHash.ToArray(),
            ExpectedRouteVerifiedAtUnixSeconds = delegation.RouteVerifiedAtUnixSeconds,
            LastDelegationSequence = delegation.DelegationSequence - 1,
            LastCanonicalDelegationHash = delegation.PreviousCanonicalDelegationHash.ToArray(),
            NowUnixSeconds = nowUnixSeconds,
            ClockSkewSeconds = clockSkewSeconds
        };

    private static void VerifyPreDelegationRouteOrigin(
        ProductionMailboxRouteContinuityDelegation delegation,
        ProductionMailboxRouteOriginLkg routeOrigin)
    {
        EqualContinuity(ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(routeOrigin),
            delegation.PreDelegationRouteOriginLkgHash.Span,
            "Pre-delegation ROL1 hash differs from RCD1.");
        EqualContinuity(routeOrigin.NetworkId.Span, delegation.NetworkId.Span,
            "Pre-delegation ROL1 network differs from RCD1.");
        EqualContinuity(routeOrigin.RouteDomainHash.Span, delegation.RouteDomainHash.Span,
            "Pre-delegation ROL1 route differs from RCD1.");
        EqualContinuity(routeOrigin.CanonicalAuthorizationHash.Span,
            delegation.AnchorCanonicalRouteAuthorizationHash.Span,
            "Pre-delegation ROL1 authorization differs from the RCD1 anchor.");
        if (routeOrigin.AuthorizationKind != delegation.AnchorAuthorizationKind ||
            routeOrigin.AuthorizationKind != ProductionMailboxRouteAuthorizationKind.OwnerPRA2 ||
            routeOrigin.AuthorizationSequence != delegation.AnchorRouteAuthorizationSequence ||
            routeOrigin.RouteVerifiedAtUnixSeconds != delegation.RouteVerifiedAtUnixSeconds ||
            routeOrigin.OwnerRevocationGeneration != 0 ||
            routeOrigin.LocalCommitGeneration == ulong.MaxValue ||
            routeOrigin.CanonicalDelegationHash.Span.IndexOfAnyExcept((byte)0) >= 0 ||
            routeOrigin.CanonicalDelegationAcceptanceHash.Span.IndexOfAnyExcept((byte)0) >= 0 ||
            routeOrigin.OwnerRevocationHeadHash.Span.IndexOfAnyExcept((byte)0) >= 0)
            throw ContinuityError(ProductionMailboxRouteContinuityError.InvalidField,
                "Pre-delegation ROL1 is not the exact nonterminal owner-only CAS state.");
    }

    private static void VerifyCurrentRevocationClosure(
        ProductionMailboxAuthority authority,
        ReadOnlySpan<byte> authorityHash,
        ProductionMailboxRevocationSnapshot revocation,
        ReadOnlySpan<byte> revocationHash,
        ulong now,
        uint skew)
    {
        EqualSelection(revocation.NetworkId.Span, authority.NetworkId.Span,
            ProductionMailboxSelectionSuccessorError.NetworkMismatch,
            "Selection intent PMR1 network differs from current PMA1.");
        EqualSelection(revocationHash, authority.Revocation.SnapshotHash.Span,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            "Selection intent PMR1 hash differs from current PMA1.");
        EqualSelection(revocation.RevocationHeadHash.Span, authority.Revocation.HeadHash.Span,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            "Selection intent PMR1 head differs from current PMA1.");
        if (revocation.AuthorityGeneration != authority.AuthorityGeneration ||
            revocation.RevocationGeneration != authority.Revocation.Generation)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
                "Selection intent PMR1 generation differs from current PMA1.");
        VerifySelectionWindow(revocation.IssuedAtUnixSeconds, revocation.ExpiresAtUnixSeconds,
            now, skew, "current PMR1");
        if (authorityHash.Length != ProductionMailboxRouteAuthorizationConstants.HashLength)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
                "Selection intent current PMA1 hash length is invalid.");
    }

    private static void BindCertificateToSelectionClosure(
        ProductionMailboxRouteCertificate certificate,
        ReadOnlySpan<byte> certificateHash,
        ProductionMailboxAuthority authority,
        ReadOnlySpan<byte> authorityHash)
    {
        EqualSelection(certificate.NetworkId.Span, authority.NetworkId.Span,
            ProductionMailboxSelectionSuccessorError.NetworkMismatch,
            "Selection intent PRC1 network differs from current PMA1.");
        EqualSelection(certificate.CanonicalAuthorityHash.Span, authorityHash,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            "Selection intent PRC1 authority differs from current PMA1.");
        EqualSelection(certificate.IssuerEd25519PublicKey.Span,
            authority.MailboxIssuerEd25519PublicKey.Span,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            "Selection intent PRC1 issuer differs from current PMA1.");
        if (certificate.AuthorityGeneration != authority.AuthorityGeneration ||
            certificateHash.Length != ProductionMailboxRouteAuthorizationConstants.HashLength)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
                "Selection intent PRC1 generation/hash is invalid.");
    }

    private static void BindCurrentTopology(
        ProductionMailboxAuthority authority,
        ReadOnlySpan<byte> authorityHash,
        ProductionMailboxTopologySnapshot topology,
        ProductionMailboxSelectionSuccessorMode mode,
        ProductionMailboxTopologySnapshot oldTopology,
        ReadOnlySpan<byte> oldTopologyHash,
        ulong now,
        uint skew)
    {
        EqualSelection(topology.NetworkId.Span, authority.NetworkId.Span,
            ProductionMailboxSelectionSuccessorError.NetworkMismatch,
            "Selection intent current PMT1 network differs from current PMA1.");
        EqualSelection(topology.CanonicalAuthorityHash.Span, authorityHash,
            ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
            "Selection intent current PMT1 authority hash differs from current PMA1.");
        if (topology.AuthorityGeneration != authority.AuthorityGeneration)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
                "Selection intent current PMT1 authority generation differs from current PMA1.");
        VerifySelectionWindow(topology.IssuedAtUnixSeconds, topology.ExpiresAtUnixSeconds,
            now, skew, "current PMT1");
        if (mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion)
        {
            if (oldTopology.TopologyGeneration == ulong.MaxValue ||
                topology.TopologyGeneration != oldTopology.TopologyGeneration + 1)
                throw SelectionError(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
                    "Direct selection intent requires exact PMT1 +1.");
            EqualSelection(topology.PreviousTopologyHash.Span, oldTopologyHash,
                ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
                "Direct selection intent current PMT1 does not name exact old PMT1.");
        }
        else if (topology.TopologyGeneration <= oldTopology.TopologyGeneration)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
                "Offline selection intent PMT1 did not move strictly forward.");
    }

    private static void BindSelectionToClosure(
        ProductionMailboxSelectionProof selection,
        ReadOnlySpan<byte> selectionHash,
        ProductionMailboxAuthority authority,
        ReadOnlySpan<byte> authorityHash,
        ProductionMailboxTopologySnapshot topology,
        ReadOnlySpan<byte> topologyHash,
        string name)
    {
        if (selectionHash.Length != ProductionMailboxSelectionSuccessorConstants.HashLength ||
            selectionHash.IndexOfAnyExcept((byte)0) < 0 ||
            selection.Algorithm != ProductionMailboxSelectionAlgorithm.RendezvousSha256V2)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.SelectionMismatch,
                $"Selection intent {name} PMS1 algorithm/hash is invalid.");
        EqualSelection(selection.NetworkId.Span, authority.NetworkId.Span,
            ProductionMailboxSelectionSuccessorError.NetworkMismatch,
            $"Selection intent {name} PMS1 network differs from PMA1.");
        EqualSelection(selection.CanonicalAuthorityHash.Span, authorityHash,
            ProductionMailboxSelectionSuccessorError.AuthorityNotSuccessor,
            $"Selection intent {name} PMS1 authority differs from PMA1.");
        EqualSelection(selection.CanonicalTopologyHash.Span, topologyHash,
            ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
            $"Selection intent {name} PMS1 topology differs from PMT1.");
        if (selection.AuthorityGeneration != authority.AuthorityGeneration ||
            selection.TopologyGeneration != topology.TopologyGeneration)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.SelectionMismatch,
                $"Selection intent {name} PMS1 closure generation differs.");
        var epoch = selection.Epoch == topology.CurrentEpoch.Epoch ? topology.CurrentEpoch :
            selection.Epoch == topology.NextEpoch.Epoch ? topology.NextEpoch :
            throw SelectionError(ProductionMailboxSelectionSuccessorError.EpochMismatch,
                $"Selection intent {name} PMS1 epoch is outside PMT1.");
        if (selection.Generation != epoch.Generation ||
            selection.IssuedAtUnixSeconds < topology.IssuedAtUnixSeconds ||
            selection.ExpiresAtUnixSeconds > topology.ExpiresAtUnixSeconds ||
            selection.IssuedAtUnixSeconds < epoch.NotBeforeUnixSeconds ||
            selection.ExpiresAtUnixSeconds > epoch.NotAfterUnixSeconds)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.InvalidValidityWindow,
                $"Selection intent {name} PMS1 escapes its PMT1/epoch closure.");
        EqualSelection(selection.MembershipCommitment.Span, epoch.MembershipCommitment.Span,
            ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            $"Selection intent {name} PMS1 membership differs from PMT1.");
        EqualSelection(selection.TopologyPlacementCommitment.Span,
            epoch.TopologyPlacementCommitment.Span,
            ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            $"Selection intent {name} PMS1 topology placement differs from PMT1.");
    }

    private static void VerifyDirectSelectionIntent(
        ProductionMailboxAuthority oldAuthority,
        ProductionMailboxAuthority currentAuthority,
        ProductionMailboxTopologySnapshot oldTopology,
        ProductionMailboxTopologySnapshot currentTopology,
        ProductionMailboxSelectionProof oldSelection,
        ProductionMailboxSelectionProof currentSelection,
        IReadOnlyList<VerifiedProductionMailboxSelectedReplica> oldReplicas,
        IReadOnlyList<VerifiedProductionMailboxSelectedReplica> currentReplicas,
        ulong now,
        uint skew)
    {
        BindOldTopology(oldAuthority, oldTopology);
        BindEpoch(oldAuthority.NextEpoch, currentAuthority.CurrentEpoch,
            "Direct selection intent PMA1 promoted epoch");
        BindTopologyEpoch(oldTopology.NextEpoch, currentTopology.CurrentEpoch,
            "Direct selection intent PMT1 promoted epoch");
        if (oldSelection.Epoch != oldTopology.NextEpoch.Epoch ||
            oldSelection.Generation != oldTopology.NextEpoch.Generation ||
            currentSelection.Epoch != currentTopology.CurrentEpoch.Epoch ||
            currentSelection.Generation != currentTopology.CurrentEpoch.Generation)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.EpochMismatch,
                "Direct selection intent does not bridge old-next to current-current PMS1.");
        VerifySelectionWindow(oldSelection.IssuedAtUnixSeconds, oldSelection.ExpiresAtUnixSeconds,
            now, skew, "direct old PMS1");
        EqualSelection(oldSelection.MembershipCommitment.Span,
            currentSelection.MembershipCommitment.Span,
            ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            "Direct selection intent membership changed.");
        EqualSelection(oldSelection.TopologyPlacementCommitment.Span,
            currentSelection.TopologyPlacementCommitment.Span,
            ProductionMailboxSelectionSuccessorError.SelectionMismatch,
            "Direct selection intent topology placement changed.");
        EqualSelection(oldSelection.MailboxPlacementCommitment.Span,
            currentSelection.MailboxPlacementCommitment.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch,
            "Direct selection intent mailbox placement changed.");
        EqualSelection(oldSelection.SelectionInputCommitment.Span,
            currentSelection.SelectionInputCommitment.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch,
            "Direct selection intent selection input changed.");
        if (oldReplicas.Count != ProductionMailboxTopologyConstants.ReplicaCount ||
            currentReplicas.Count != ProductionMailboxTopologyConstants.ReplicaCount)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.ReplicaRouteMismatch,
                "Direct selection intent replica count changed.");
        for (var index = 0; index < ProductionMailboxTopologyConstants.ReplicaCount; index++)
        {
            EqualSelection(oldReplicas[index].ReplicaId.Span,
                currentReplicas[index].ReplicaId.Span,
                ProductionMailboxSelectionSuccessorError.ReplicaRouteMismatch,
                "Direct selection intent replica identity/order changed.");
            EqualSelection(oldReplicas[index].CanonicalMIP1Proof.Span,
                currentReplicas[index].CanonicalMIP1Proof.Span,
                ProductionMailboxSelectionSuccessorError.ReplicaRouteMismatch,
                "Direct selection intent replica proof changed.");
        }
    }

    private static void VerifyOfflineSelectionIntent(
        ProductionMailboxAuthority oldAuthority,
        ProductionMailboxAuthority currentAuthority,
        ProductionMailboxTopologySnapshot oldTopology,
        ProductionMailboxTopologySnapshot currentTopology,
        ProductionMailboxSelectionProof oldSelection,
        ProductionMailboxSelectionProof currentSelection,
        ulong now)
    {
        BindOldTopology(oldAuthority, oldTopology);
        var authorityAdvance = ForwardAdvance(oldAuthority.AuthorityGeneration,
            currentAuthority.AuthorityGeneration, ProtocolMagic.PMA1);
        var topologyAdvance = ForwardAdvance(oldTopology.TopologyGeneration,
            currentTopology.TopologyGeneration, ProtocolMagic.PMT1);
        if (authorityAdvance == 1 && topologyAdvance == 1)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                "An exact +1 authority/topology transition must use DirectPromotion.");
        if (oldSelection.Epoch != oldTopology.NextEpoch.Epoch ||
            oldSelection.Generation != oldTopology.NextEpoch.Generation ||
            currentSelection.Epoch != currentTopology.CurrentEpoch.Epoch ||
            currentSelection.Generation != currentTopology.CurrentEpoch.Generation ||
            currentSelection.Epoch <= oldSelection.Epoch ||
            currentSelection.Generation <= oldSelection.Generation)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.EpochMismatch,
                "Offline selection intent does not strictly advance old-next to current-current PMS1.");
        EqualSelection(oldSelection.MailboxPlacementCommitment.Span,
            currentSelection.MailboxPlacementCommitment.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch,
            "Offline selection intent mailbox placement changed.");
        EqualSelection(oldSelection.SelectionInputCommitment.Span,
            currentSelection.SelectionInputCommitment.Span,
            ProductionMailboxSelectionSuccessorError.RouteMismatch,
            "Offline selection intent selection input changed.");
        if (now < oldSelection.IssuedAtUnixSeconds ||
            now - oldSelection.IssuedAtUnixSeconds >
            ProductionMailboxSelectionSuccessorConstants.MaximumOfflineCheckpointAgeSeconds)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.CheckpointAnchorExpired,
                "Offline selection intent old PMS1 anchor exceeds the bounded age policy.");
    }

    private static void BindOldTopology(
        ProductionMailboxAuthority authority,
        ProductionMailboxTopologySnapshot topology)
    {
        EqualSelection(topology.NetworkId.Span, authority.NetworkId.Span,
            ProductionMailboxSelectionSuccessorError.NetworkMismatch,
            "Selection intent old PMT1 network differs from old PMA1.");
        if (topology.AuthorityGeneration != authority.AuthorityGeneration)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.TopologyNotSuccessor,
                "Selection intent old PMT1 authority generation differs from old PMA1.");
    }

    private static void BindEpoch(
        ProductionMailboxAuthorityEpoch oldEpoch,
        ProductionMailboxAuthorityEpoch currentEpoch,
        string name)
    {
        if (oldEpoch.Epoch != currentEpoch.Epoch ||
            oldEpoch.Generation != currentEpoch.Generation ||
            oldEpoch.NotBeforeUnixSeconds != currentEpoch.NotBeforeUnixSeconds ||
            oldEpoch.NotAfterUnixSeconds != currentEpoch.NotAfterUnixSeconds)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.EpochMismatch,
                $"{name} metadata differs.");
        EqualSelection(oldEpoch.MembershipCommitment.Span, currentEpoch.MembershipCommitment.Span,
            ProductionMailboxSelectionSuccessorError.EpochMismatch,
            $"{name} membership differs.");
        EqualSelection(oldEpoch.TopologyPlacementCommitment.Span,
            currentEpoch.TopologyPlacementCommitment.Span,
            ProductionMailboxSelectionSuccessorError.EpochMismatch,
            $"{name} topology placement differs.");
    }

    private static void BindTopologyEpoch(
        ProductionMailboxTopologyEpoch oldEpoch,
        ProductionMailboxTopologyEpoch currentEpoch,
        string name)
    {
        if (oldEpoch.Epoch != currentEpoch.Epoch ||
            oldEpoch.Generation != currentEpoch.Generation ||
            oldEpoch.NotBeforeUnixSeconds != currentEpoch.NotBeforeUnixSeconds ||
            oldEpoch.NotAfterUnixSeconds != currentEpoch.NotAfterUnixSeconds)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.EpochMismatch,
                $"{name} metadata differs.");
        EqualSelection(oldEpoch.MembershipCommitment.Span, currentEpoch.MembershipCommitment.Span,
            ProductionMailboxSelectionSuccessorError.EpochMismatch,
            $"{name} membership differs.");
        EqualSelection(oldEpoch.TopologyPlacementCommitment.Span,
            currentEpoch.TopologyPlacementCommitment.Span,
            ProductionMailboxSelectionSuccessorError.EpochMismatch,
            $"{name} topology placement differs.");
    }

    private static ulong ForwardAdvance(ulong oldGeneration, ulong currentGeneration, string name)
    {
        if (currentGeneration <= oldGeneration)
            throw SelectionError(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                $"Offline selection intent {name} did not move strictly forward.");
        return currentGeneration - oldGeneration;
    }

    private static void VerifySelectionWindow(
        ulong from, ulong until, ulong now, uint skew, string name)
    {
        if ((now < from && from - now > skew) || (now > until && now - until > skew))
            throw SelectionError(ProductionMailboxSelectionSuccessorError.InvalidValidityWindow,
                $"Selection intent {name} is not live.");
    }

    private static ProductionMailboxRouteTransitionContext CreateTransition(
        ProductionMailboxSelectionSuccessorMode mode,
        ProductionMailboxRouteContinuityDelegation delegation,
        ProductionMailboxRouteAdvertisementV2 predecessor,
        ReadOnlySpan<byte> predecessorHash,
        ReadOnlySpan<byte> oldSelectionHash,
        ReadOnlySpan<byte> newSelectionHash,
        ReadOnlySpan<byte> freshCertificateHash,
        ulong activationSequence,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> commitment,
        ReadOnlySpan<byte> checkpointHash,
        ReadOnlySpan<byte> authorityHash,
        ulong authorityGeneration,
        ReadOnlySpan<byte> oldRouteOriginHash,
        ulong oldLocalRouteCommitGeneration,
        ulong notBefore,
        ulong expiresAt) => new()
        {
            Mode = mode,
            PredecessorAuthorizationKind = predecessor.AuthorizationKind(),
            NewAuthorizationKind = ProductionMailboxRouteAuthorizationKind.DelegatedRCA1,
            NetworkId = delegation.NetworkId.ToArray(),
            RouteDomainHash = delegation.RouteDomainHash.ToArray(),
            OldCanonicalSelectionHash = oldSelectionHash.ToArray(),
            NewCanonicalSelectionHash = newSelectionHash.ToArray(),
            PredecessorCanonicalRouteAuthorizationHash = predecessorHash.ToArray(),
            PredecessorRouteAuthorizationSequence = predecessor.Sequence,
            FreshCanonicalRouteCertificateHash = freshCertificateHash.ToArray(),
            NewRouteAuthorizationSequence = activationSequence,
            TransitionSalt = salt.ToArray(),
            ContinuityTransitionCommitment = commitment.ToArray(),
            CanonicalRevocationCheckpointHash = checkpointHash.ToArray(),
            CurrentCanonicalAuthorityHash = authorityHash.ToArray(),
            CurrentAuthorityGeneration = authorityGeneration,
            SealedOldRouteOriginLkgHash = oldRouteOriginHash.ToArray(),
            OldRouteVerifiedAtUnixSeconds = delegation.RouteVerifiedAtUnixSeconds,
            OldLocalRouteCommitGeneration = oldLocalRouteCommitGeneration,
            NotBeforeUnixSeconds = notBefore,
            ExpiresAtUnixSeconds = expiresAt
        };

    private static ProductionMailboxRouteContinuityActivation CreateActivation(
        ProductionMailboxAuthority authority,
        ProductionMailboxRevocationSnapshot revocations,
        ReadOnlySpan<byte> authorityHash,
        ReadOnlySpan<byte> revocationHash,
        ReadOnlySpan<byte> certificateHash,
        ReadOnlySpan<byte> checkpointHash,
        ReadOnlySpan<byte> transitionHash,
        ProductionMailboxRouteAdvertisementV2 predecessor,
        ReadOnlySpan<byte> predecessorHash,
        ulong activationSequence,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> commitment,
        ulong issuedAt,
        ulong expiresAt) => new()
        {
            NetworkId = authority.NetworkId.ToArray(),
            RouteDomainHash = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(
                predecessor.Certificate),
            CurrentAuthorityGeneration = authority.AuthorityGeneration,
            CurrentCanonicalAuthorityHash = authorityHash.ToArray(),
            CurrentIssuerEd25519PublicKey = authority.MailboxIssuerEd25519PublicKey.ToArray(),
            CurrentRevocationGeneration = revocations.RevocationGeneration,
            CurrentRevocationHeadHash = revocations.RevocationHeadHash.ToArray(),
            CurrentRevocationSnapshotHash = revocationHash.ToArray(),
            TransitionSalt = salt.ToArray(),
            ContinuityTransitionCommitment = commitment.ToArray(),
            CanonicalRevocationCheckpointHash = checkpointHash.ToArray(),
            FreshCanonicalRouteCertificateHash = certificateHash.ToArray(),
            CanonicalTransitionContextHash = transitionHash.ToArray(),
            PredecessorAuthorizationKind = predecessor.AuthorizationKind(),
            PredecessorCanonicalRouteAuthorizationHash = predecessorHash.ToArray(),
            PredecessorRouteAuthorizationSequence = predecessor.Sequence,
            ActivationSequence = activationSequence,
            IssuedAtUnixSeconds = issuedAt,
            ExpiresAtUnixSeconds = expiresAt,
            CurrentIssuerSignature = PlaceholderSignature()
        };

    private static void BindPredecessorToEnrollment(
        ProductionMailboxRouteContinuityDelegation delegation,
        VerifiedProductionMailboxRouteAdvertisementV2 predecessor)
    {
        var artifact = predecessor.Advertisement;
        Equal(predecessor.RouteDomainHash.Span, delegation.RouteDomainHash.Span,
            "Delegated predecessor route differs from the enrolled route.");
        Equal(predecessor.CanonicalHash.Span,
            delegation.AnchorCanonicalRouteAuthorizationHash.Span,
            "Delegated predecessor is not the exact enrolled owner authorization.");
        if (artifact.Sequence != delegation.AnchorRouteAuthorizationSequence)
            throw AuthorizationError(ProductionMailboxRouteAuthorizationError.InvalidField,
                "Delegated predecessor sequence differs from the enrolled owner authorization.");
    }

    private static void BindSelectionIntent(
        VerifiedProductionMailboxSelectionTransitionIntent intent,
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxRevocationSnapshot revocations,
        VerifiedProductionMailboxRouteCertificate certificate,
        ProductionMailboxRouteContinuityDelegation delegation,
        ulong now,
        ulong transitionNotBefore,
        ulong transitionExpiresAt)
    {
        Equal(intent.TrustedNetworkId, authority.Authority.NetworkId.Span,
            "Selection intent network differs from current PMA1.");
        Equal(intent.TrustedNetworkId, delegation.NetworkId.Span,
            "Selection intent network differs from the continuity enrollment.");
        Equal(intent.TrustedCurrentAuthorityHash, authority.CanonicalAuthorityHash.Span,
            "Selection intent current PMA1 differs from activation PMA1.");
        Equal(intent.TrustedCurrentRevocationHash, revocations.CanonicalSnapshotHash.Span,
            "Selection intent current PMR1 differs from activation PMR1.");
        Equal(intent.TrustedRouteCertificateHash, certificate.CanonicalCertificateHash.Span,
            "Selection intent PRC1 differs from activation PRC1.");
        Equal(intent.TrustedSelectionInputCommitment,
            certificate.Certificate.SelectionInputCommitment.Span,
            "Selection intent input differs from activation PRC1.");
        Equal(intent.TrustedSelectionInputCommitment, delegation.SelectionInputCommitment.Span,
            "Selection intent input differs from the continuity enrollment.");
        if (now < intent.LiveNotBeforeUnixSeconds || now >= intent.LiveExpiresAtUnixSeconds ||
            transitionNotBefore < intent.LiveNotBeforeUnixSeconds ||
            transitionExpiresAt > intent.LiveExpiresAtUnixSeconds)
            throw AuthorizationError(ProductionMailboxRouteAuthorizationError.InvalidValidityWindow,
                "RTC1 lifetime escapes the sealed selection-transition intent.");
    }

    private static void EnsureSignatureLength(int written, string name)
    {
        if (written != ProductionMailboxRouteAuthorizationConstants.Ed25519SignatureLength)
            throw AuthorizationError(ProductionMailboxRouteAuthorizationError.InvalidLength,
                $"{name} signer wrote {written} bytes; exactly 64 are required.");
    }

    private static byte[] PlaceholderSignature()
    {
        var signature = new byte[ProductionMailboxRouteAuthorizationConstants.Ed25519SignatureLength];
        signature.AsSpan().Fill(0xa5);
        return signature;
    }

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string message)
    {
        if (actual.Length != expected.Length ||
            !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw AuthorizationError(ProductionMailboxRouteAuthorizationError.InvalidField, message);
    }

    private static void EqualContinuity(
        ReadOnlySpan<byte> actual,
        ReadOnlySpan<byte> expected,
        string message)
    {
        if (actual.Length != expected.Length ||
            !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw ContinuityError(ProductionMailboxRouteContinuityError.InvalidField, message);
    }

    private static void EqualSelection(
        ReadOnlySpan<byte> actual,
        ReadOnlySpan<byte> expected,
        ProductionMailboxSelectionSuccessorError error,
        string message)
    {
        if (actual.Length != expected.Length ||
            !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw SelectionError(error, message);
    }

    private static ProductionMailboxRouteAuthorizationKind AuthorizationKind(
        this ProductionMailboxRouteAdvertisementV2 _) =>
        ProductionMailboxRouteAuthorizationKind.OwnerPRA2;

    private static ProductionMailboxRouteContinuityException ContinuityError(
        ProductionMailboxRouteContinuityError error,
        string message) => new(error, message);

    private static ProductionMailboxRouteAuthorizationException AuthorizationError(
        ProductionMailboxRouteAuthorizationError error,
        string message) => new(error, message);

    private static ProductionMailboxSelectionSuccessorException SelectionError(
        ProductionMailboxSelectionSuccessorError error,
        string message) => new(error, message);

    private sealed class ExactTranscriptAcceptingVerifier(
        ReadOnlySpan<byte> acceptedPublicKey,
        ReadOnlySpan<byte> acceptedSigningBytes) : IProductionMailboxRouteSignatureVerifier
    {
        private readonly byte[] _acceptedPublicKey = acceptedPublicKey.ToArray();
        private readonly byte[] _acceptedSigningBytes = acceptedSigningBytes.ToArray();
        private readonly SodiumProductionMailboxRouteSignatureVerifier _production = new();

        public bool Verify(
            ReadOnlySpan<byte> publicKey,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            if (publicKey.Length == _acceptedPublicKey.Length &&
                signingBytes.Length == _acceptedSigningBytes.Length &&
                CryptographicOperations.FixedTimeEquals(publicKey, _acceptedPublicKey) &&
                CryptographicOperations.FixedTimeEquals(signingBytes, _acceptedSigningBytes))
                return true;
            return _production.Verify(publicKey, signingBytes, signature);
        }
    }
}
