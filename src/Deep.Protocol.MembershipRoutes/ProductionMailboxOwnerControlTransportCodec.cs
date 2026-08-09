using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

/// <summary>
/// Canonical carry-only OCR1/PMCQ1/PMCR1/PMFA1 codecs. Decoding a frame never grants route,
/// activation, persistence, replay or publication authority.
/// </summary>
public static class ProductionMailboxOwnerControlTransportCodec
{
    private static ReadOnlySpan<byte> OcrMagic => "OCR1"u8;
    private static ReadOnlySpan<byte> RequestMagic => "PMCQ"u8;
    private static ReadOnlySpan<byte> ResponseMagic => "PMCR"u8;
    private static ReadOnlySpan<byte> FinalMagic => "PMFA"u8;
    private static ReadOnlySpan<byte> OcrSigningDomain =>
        "Deep/production-mailbox/owner-control-responder-certificate/v1"u8;
    private static ReadOnlySpan<byte> OcrHashDomain =>
        "Deep/production-mailbox/owner-control-responder-certificate-hash/v1"u8;
    private static ReadOnlySpan<byte> RequestSigningDomain =>
        "Deep/production-mailbox/owner-control-request/v1"u8;
    private static ReadOnlySpan<byte> RequestHashDomain =>
        "Deep/production-mailbox/owner-control-request-hash/v1"u8;
    private static ReadOnlySpan<byte> ResponseSigningDomain =>
        "Deep/production-mailbox/owner-control-response/v1"u8;
    private static ReadOnlySpan<byte> ResponseHashDomain =>
        "Deep/production-mailbox/owner-control-response-hash/v1"u8;

    public static ValueTask<VerifiedProductionMailboxOwnerControlRequest> AuthorOwnerDirectRequestAsync(
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor cursor, ReadOnlyMemory<byte> requestId,
        ulong issuedAt, ulong expiresAt, ProductionMailboxOwnerControlRequestSigner signer,
        CancellationToken cancellationToken = default) => AuthorRequestAsync(anchor, cursor, requestId,
            issuedAt, expiresAt, ProductionMailboxSelectionSuccessorMode.DirectPromotion,
            ProductionMailboxRouteAuthorizationKind.OwnerPRA2, signer, cancellationToken);

    public static ValueTask<VerifiedProductionMailboxOwnerControlRequest> AuthorOwnerOfflineRequestAsync(
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor cursor, ReadOnlyMemory<byte> requestId,
        ulong issuedAt, ulong expiresAt, ProductionMailboxOwnerControlRequestSigner signer,
        CancellationToken cancellationToken = default) => AuthorRequestAsync(anchor, cursor, requestId,
            issuedAt, expiresAt, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            ProductionMailboxRouteAuthorizationKind.OwnerPRA2, signer, cancellationToken);

    public static ValueTask<VerifiedProductionMailboxOwnerControlRequest> AuthorDelegatedDirectRequestAsync(
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor cursor, ReadOnlyMemory<byte> requestId,
        ulong issuedAt, ulong expiresAt, ProductionMailboxOwnerControlRequestSigner signer,
        CancellationToken cancellationToken = default) => AuthorRequestAsync(anchor, cursor, requestId,
            issuedAt, expiresAt, ProductionMailboxSelectionSuccessorMode.DirectPromotion,
            ProductionMailboxRouteAuthorizationKind.DelegatedRCA1, signer, cancellationToken);

    public static ValueTask<VerifiedProductionMailboxOwnerControlRequest> AuthorDelegatedOfflineRequestAsync(
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor cursor, ReadOnlyMemory<byte> requestId,
        ulong issuedAt, ulong expiresAt, ProductionMailboxOwnerControlRequestSigner signer,
        CancellationToken cancellationToken = default) => AuthorRequestAsync(anchor, cursor, requestId,
            issuedAt, expiresAt, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            ProductionMailboxRouteAuthorizationKind.DelegatedRCA1, signer, cancellationToken);

    public static VerifiedProductionMailboxOwnerControlRequest VerifyRequest(
        ReadOnlySpan<byte> canonicalRequest, VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor cursor, ulong nowUnixSeconds,
        uint clockSkewSeconds = 0)
    {
        ArgumentNullException.ThrowIfNull(anchor); ArgumentNullException.ThrowIfNull(cursor);
        if (canonicalRequest.Length != ProductionMailboxOwnerControlConstants.RequestLength)
            throw new FormatException("PMCQ1 must have exact length before ownership.");
        var request = DecodeRequest(canonicalRequest);
        BindRequest(request, anchor, cursor, nowUnixSeconds, clockSkewSeconds);
        var ocrHash = anchor.CanonicalOwnerControlResponderCertificateHash.ToArray();
        if (!new SodiumProductionMailboxRouteSignatureVerifier().Verify(
                request.MailboxOwnerEd25519PublicKey.Span,
                GetRequestSigningBytes(request, ocrHash), request.OwnerSignature.Span))
            throw new FormatException("PMCQ1 owner signature is invalid.");
        var bytes = canonicalRequest.ToArray();
        return new(request, bytes, ComputeRequestHash(request, ocrHash));
    }

    public static VerifiedProductionMailboxOwnerControlResponse VerifyResponse(
        ReadOnlySpan<byte> canonicalHeader, ReadOnlySpan<byte> payload,
        VerifiedProductionMailboxOwnerControlRequest request,
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        ulong nowUnixSeconds, uint clockSkewSeconds = 0)
    {
        var verifiedHeader = VerifyResponseHeader(canonicalHeader, request, anchor,
            nowUnixSeconds, clockSkewSeconds);
        return VerifyResponsePayload(verifiedHeader, payload);
    }

    public static VerifiedProductionMailboxOwnerControlResponseHeader VerifyResponseHeader(
        ReadOnlySpan<byte> canonicalHeader,
        VerifiedProductionMailboxOwnerControlRequest request,
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        ulong nowUnixSeconds, uint clockSkewSeconds = 0)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(anchor);
        if (canonicalHeader.Length != ProductionMailboxOwnerControlConstants.ResponseHeaderLength)
            throw new FormatException("PMCR1 header must be exact.");
        var response = DecodeResponseHeader(canonicalHeader);
        var req = request.Request;
        var expectedResponder = anchor.OwnerControlResponderCertificate.ResponderEd25519PublicKey.Span;
        if (!CryptographicOperations.FixedTimeEquals(response.ResponderEd25519PublicKey.Span, expectedResponder))
            throw new FormatException("PMCR1 responder differs from protected OCR1.");
        ValidateMessageWindow(response.IssuedAtUnixSeconds, response.ExpiresAtUnixSeconds,
            nowUnixSeconds, clockSkewSeconds, "PMCR1");
        if (response.IssuedAtUnixSeconds < request.Request.IssuedAtUnixSeconds ||
            response.ExpiresAtUnixSeconds > request.Request.ExpiresAtUnixSeconds ||
            response.ExpiresAtUnixSeconds > anchor.OwnerControlResponderCertificate.ExpiresAtUnixSeconds ||
            !CryptographicOperations.FixedTimeEquals(response.CanonicalRequestHash.Span,
                request.CanonicalHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(response.RequestId.Span,
                request.Request.RequestId.Span) || response.Mode != request.Mode ||
            response.AuthorizationKind != request.ExpectedAuthorizationKind ||
            !FixedEqual(response.NetworkId.Span, req.NetworkId.Span) ||
            !FixedEqual(response.RouteDomainHash.Span, req.RouteDomainHash.Span) ||
            !FixedEqual(response.PredecessorRouteOriginLkgHash.Span,
                req.PredecessorRouteOriginLkgHash.Span) ||
            !FixedEqual(response.CurrentRouteHistoryCheckpointHash.Span,
                req.CurrentRouteHistoryCheckpointHash.Span) ||
            response.CurrentRouteHistoryBatchSequence != req.CurrentRouteHistoryBatchSequence)
            throw new FormatException("PMCR1 differs from its exact live PMCQ1/OCR1 context.");
        if (response.Kind is ProductionMailboxOwnerControlResponseKind.NoChange or
                ProductionMailboxOwnerControlResponseKind.FinalActivation &&
            (!FixedEqual(response.NextRouteHistoryCheckpointHash.Span,
                response.CurrentRouteHistoryCheckpointHash.Span) ||
             response.NextRouteHistoryBatchSequence != response.CurrentRouteHistoryBatchSequence))
            throw new FormatException("PMCR1 terminal/no-change response may not advance RHC state.");
        if (!new SodiumProductionMailboxRouteSignatureVerifier().Verify(expectedResponder,
                GetResponseSigningBytes(response), response.ResponderSignature.Span))
            throw new FormatException("PMCR1 responder signature is invalid.");
        return new(response, canonicalHeader);
    }

    public static async ValueTask<VerifiedProductionMailboxOwnerControlResponse> ReadVerifiedResponsePayloadAsync(
        Stream source, VerifiedProductionMailboxOwnerControlResponseHeader verifiedHeader,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source); ArgumentNullException.ThrowIfNull(verifiedHeader);
        var length = checked((int)verifiedHeader.Response.PayloadLength);
        if (length == 0)
            return VerifyResponsePayload(verifiedHeader, ReadOnlySpan<byte>.Empty);
        var prefixLength = verifiedHeader.Kind == ProductionMailboxOwnerControlResponseKind.FinalActivation
            ? ProductionMailboxOwnerControlConstants.FinalActivationHeaderLength : 64;
        if (length < prefixLength)
            throw new FormatException("PMCR1 payload is shorter than its authenticated frame prefix.");
        var prefix = new byte[prefixLength];
        await ReadExactAsync(source, prefix, cancellationToken).ConfigureAwait(false);
        if (verifiedHeader.Kind == ProductionMailboxOwnerControlResponseKind.FinalActivation)
            PreflightFinalHeader(prefix, length, out _, out _, out _);
        else
        {
            var batchLength = PreflightHistoryLength(prefix);
            if (checked(batchLength +
                    ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength) != length)
                throw new FormatException("History count-derived length differs from authenticated PMCR1.");
        }
        var payload = new byte[length];
        prefix.CopyTo(payload, 0);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(prefix);
        var offset = prefixLength;
        while (offset < payload.Length)
        {
            var read = await source.ReadAsync(payload.AsMemory(offset), cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("PMCR1 payload ended before its declared length.");
            hash.AppendData(payload.AsSpan(offset, read));
            offset += read;
        }
        if (!FixedEqual(hash.GetHashAndReset(), verifiedHeader.Response.PayloadSha256.Span))
            throw new FormatException("PMCR1 streamed payload hash differs from authenticated header.");
        return VerifyResponsePayload(verifiedHeader, payload);
    }

    public static ValueTask<VerifiedProductionMailboxOwnerControlResponse> AuthorHistoryResponseAsync(
        VerifiedProductionMailboxOwnerControlRequest request,
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        ProductionMailboxRouteHistoryBatchCommitPlan history,
        ulong issuedAt, ulong expiresAt,
        ProductionMailboxOwnerControlResponseSigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(history);
        var req = request.Request;
        if (!FixedEqual(req.PredecessorRouteOriginLkgHash.Span,
                history.ExpectedCurrentRouteOriginLkgHash.Span) ||
            !FixedEqual(req.CurrentRouteHistoryCheckpointHash.Span,
                history.ExpectedCurrentCheckpointHash.Span) ||
            req.CurrentRouteHistoryBatchSequence != history.ExpectedCurrentBatchSequence)
            throw new FormatException("History plan differs from the exact PMCQ1 predecessor CAS tuple.");
        var payload = new byte[checked(history.CanonicalBatch.Length +
            history.NextCursor.CanonicalCheckpoint.Length)];
        history.CanonicalBatch.Span.CopyTo(payload);
        history.NextCursor.CanonicalCheckpoint.Span.CopyTo(payload.AsSpan(history.CanonicalBatch.Length));
        _ = DecodeHistoryPayload(payload);
        return AuthorResponseAsync(request, anchor, ProductionMailboxOwnerControlResponseKind.History,
            payload, history.NextCursor.CanonicalCheckpointHash,
            history.NextCursor.LastCommittedBatchSequence, issuedAt, expiresAt, signer,
            cancellationToken);
    }

    public static ValueTask<VerifiedProductionMailboxOwnerControlResponse> AuthorFinalActivationResponseAsync(
        VerifiedProductionMailboxOwnerControlRequest request,
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxLiveTransition transition,
        ulong issuedAt, ulong expiresAt,
        ProductionMailboxOwnerControlResponseSigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transition);
        var req = request.Request;
        var plan = transition.CommitPlan;
        var expectedRol = ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(
            ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(
                plan.ExpectedPredecessorRouteOriginLkg.Span));
        var expectedRhc = ProductionMailboxRouteContinuityCodec.ComputeRouteHistoryCheckpointHash(
            ProductionMailboxRouteContinuityCodec.DecodeRouteHistoryCheckpoint(
                plan.ExpectedRouteHistoryCheckpoint.Span));
        if (transition.Mode != req.Mode || transition.AuthorizationKind != req.ExpectedAuthorizationKind ||
            !FixedEqual(req.PredecessorRouteOriginLkgHash.Span, expectedRol) ||
            !FixedEqual(req.CurrentRouteHistoryCheckpointHash.Span, expectedRhc))
            throw new FormatException("Final transition plan differs from the exact PMCQ1 predecessor.");
        var intent = transition.Intent;
        var nextSelection = intent.NextSelection ??
            throw new FormatException("Final activation lacks the sealed next PMS1.");
        var payload = EncodeFinalActivation(new ProductionMailboxFinalActivationFrame
        {
            Mode = transition.Mode, AuthorizationKind = transition.AuthorizationKind,
            Artifacts = new ProductionMailboxNodeCacheArtifacts
            {
                AuthorizationKind = transition.AuthorizationKind,
                CanonicalAuthority = ProductionMailboxAuthorityCodec.Encode(intent.CurrentAuthority.Authority),
                CanonicalRevocations = ProductionMailboxRevocationSnapshotCodec.Encode(intent.CurrentRevocations.Snapshot),
                CanonicalTopology = ProductionMailboxTopologyCodec.Encode(intent.CurrentTopology.Snapshot),
                CanonicalCurrentSelection = ProductionMailboxTopologyCodec.EncodeSelection(intent.CurrentSelection.Proof),
                CanonicalNextSelection = ProductionMailboxTopologyCodec.EncodeSelection(nextSelection.Proof),
                CanonicalSelectionSuccessorV2 = transition.CommitPlan.CanonicalSelectionSuccessorV2,
                CanonicalRouteCertificate = transition.CommitPlan.CanonicalRouteCertificate,
                CanonicalTransitionContext = transition.CommitPlan.CanonicalTransitionContext,
                CanonicalRevocationCheckpoint = transition.CommitPlan.CanonicalRevocationCheckpoint,
                CanonicalRouteAuthorization = transition.CommitPlan.CanonicalRouteAuthorization
            }
        });
        return AuthorResponseAsync(request, anchor,
            ProductionMailboxOwnerControlResponseKind.FinalActivation, payload,
            req.CurrentRouteHistoryCheckpointHash,
            req.CurrentRouteHistoryBatchSequence, issuedAt, expiresAt, signer, cancellationToken);
    }

    public static ValueTask<VerifiedProductionMailboxOwnerControlResponse> AuthorNoChangeResponseAsync(
        VerifiedProductionMailboxOwnerControlRequest request,
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        ulong issuedAt, ulong expiresAt,
        ProductionMailboxOwnerControlResponseSigner signer,
        CancellationToken cancellationToken = default) => AuthorResponseAsync(request, anchor,
            ProductionMailboxOwnerControlResponseKind.NoChange, ReadOnlyMemory<byte>.Empty,
            request.Request.CurrentRouteHistoryCheckpointHash,
            request.Request.CurrentRouteHistoryBatchSequence, issuedAt, expiresAt, signer,
            cancellationToken);

    private static async ValueTask<VerifiedProductionMailboxOwnerControlResponse> AuthorResponseAsync(
        VerifiedProductionMailboxOwnerControlRequest request,
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        ProductionMailboxOwnerControlResponseKind kind, ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> nextRhcHash, ulong nextSequence, ulong issuedAt, ulong expiresAt,
        ProductionMailboxOwnerControlResponseSigner signer, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(anchor);
        ArgumentNullException.ThrowIfNull(signer);
        PreflightResponsePayload(kind, payload.Span);
        var req = request.Request; var responder = anchor.OwnerControlResponderCertificate.ResponderEd25519PublicKey;
        var response = new ProductionMailboxOwnerControlResponseHeader
        {
            Kind = kind, Mode = req.Mode, AuthorizationKind = req.ExpectedAuthorizationKind,
            IssuedAtUnixSeconds = issuedAt, ExpiresAtUnixSeconds = expiresAt,
            CanonicalRequestHash = request.CanonicalHash.ToArray(), RequestId = req.RequestId.ToArray(),
            NetworkId = req.NetworkId.ToArray(), RouteDomainHash = req.RouteDomainHash.ToArray(),
            PredecessorRouteOriginLkgHash = req.PredecessorRouteOriginLkgHash.ToArray(),
            CurrentRouteHistoryCheckpointHash = req.CurrentRouteHistoryCheckpointHash.ToArray(),
            NextRouteHistoryCheckpointHash = nextRhcHash.ToArray(),
            CurrentRouteHistoryBatchSequence = req.CurrentRouteHistoryBatchSequence,
            NextRouteHistoryBatchSequence = nextSequence,
            PayloadSha256 = SHA256.HashData(payload.Span), PayloadLength = checked((uint)payload.Length),
            ResponderEd25519PublicKey = responder.ToArray(), ResponderSignature = new byte[64]
        };
        if (issuedAt < req.IssuedAtUnixSeconds || expiresAt > req.ExpiresAtUnixSeconds ||
            expiresAt > anchor.OwnerControlResponderCertificate.ExpiresAtUnixSeconds)
            throw new FormatException("PMCR1 authoring window exceeds PMCQ1/OCR1.");
        var signingBytes = GetResponseSigningBytes(response); var signature = new byte[64];
        var signingRequest = new ProductionMailboxOwnerControlResponseSigningRequest(signingBytes, responder.Span);
        try
        {
            var written = await signer(signingRequest, signature, cancellationToken).ConfigureAwait(false);
            if (written != 64) throw new FormatException("PMCR1 responder signer must write exactly 64 bytes.");
            var signed = response with { ResponderSignature = signature.ToArray() };
            var header = EncodeResponseHeader(signed);
            return VerifyResponse(header, payload.Span, request, anchor, issuedAt, 0);
        }
        finally
        {
            signingRequest.Clear(); CryptographicOperations.ZeroMemory(signingBytes);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static async ValueTask<VerifiedProductionMailboxOwnerControlRequest> AuthorRequestAsync(
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor cursor, ReadOnlyMemory<byte> requestId,
        ulong issuedAt, ulong expiresAt, ProductionMailboxSelectionSuccessorMode mode,
        ProductionMailboxRouteAuthorizationKind kind,
        ProductionMailboxOwnerControlRequestSigner signer, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(anchor); ArgumentNullException.ThrowIfNull(cursor);
        ArgumentNullException.ThrowIfNull(signer);
        if (requestId.Length != 32) throw new FormatException("PMCQ1 request ID must be exact before copy.");
        var rol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(
            cursor.CanonicalCurrentRouteOriginLkg());
        var delegation = anchor.EnrollmentState.Enrollment.Delegation;
        var value = new ProductionMailboxOwnerControlRequest
        {
            Operation = ProductionMailboxOwnerControlOperation.AdvanceOrFinalize,
            Mode = mode, ExpectedAuthorizationKind = kind, IssuedAtUnixSeconds = issuedAt,
            ExpiresAtUnixSeconds = expiresAt, RequestId = requestId.ToArray(),
            NetworkId = delegation.NetworkId.ToArray(),
            MailboxOwnerEd25519PublicKey = delegation.MailboxOwnerEd25519PublicKey.ToArray(),
            RouteDomainHash = delegation.RouteDomainHash.ToArray(),
            SelectionInputCommitment = delegation.SelectionInputCommitment.ToArray(),
            PredecessorRouteOriginLkgHash = ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(rol),
            CurrentRouteHistoryCheckpointHash = cursor.CanonicalCheckpointHash.ToArray(),
            CurrentRouteHistoryBatchSequence = cursor.LastCommittedBatchSequence,
            PredecessorAuthorizationSequence = rol.AuthorizationSequence,
            PredecessorAuthorizationHash = rol.CanonicalAuthorizationHash.ToArray(),
            OwnerSignature = new byte[64]
        };
        BindRequest(value, anchor, cursor, issuedAt, 0);
        var ocrHash = anchor.CanonicalOwnerControlResponderCertificateHash.ToArray();
        var bytes = GetRequestSigningBytes(value, ocrHash); var signature = new byte[64];
        var signingRequest = new ProductionMailboxOwnerControlRequestSigningRequest(bytes,
            delegation.MailboxOwnerEd25519PublicKey.Span);
        try
        {
            var written = await signer(signingRequest, signature, cancellationToken).ConfigureAwait(false);
            if (written != 64) throw new FormatException("PMCQ1 owner signer must write exactly 64 bytes.");
            var signed = value with { OwnerSignature = signature.ToArray() };
            var canonical = EncodeRequest(signed);
            return VerifyRequest(canonical, anchor, cursor, issuedAt, 0);
        }
        finally
        {
            signingRequest.Clear(); CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static void BindRequest(ProductionMailboxOwnerControlRequest request,
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor cursor, ulong now, uint skew)
    {
        ValidateMessageWindow(request.IssuedAtUnixSeconds, request.ExpiresAtUnixSeconds, now, skew, "PMCQ1");
        var ocr = anchor.OwnerControlResponderCertificate;
        var delegation = anchor.EnrollmentState.Enrollment.Delegation;
        var rolBytes = cursor.CanonicalCurrentRouteOriginLkg();
        var rol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(rolBytes);
        if (request.ExpiresAtUnixSeconds > ocr.ExpiresAtUnixSeconds ||
            !FixedEqual(request.NetworkId.Span, delegation.NetworkId.Span) ||
            !FixedEqual(request.MailboxOwnerEd25519PublicKey.Span, delegation.MailboxOwnerEd25519PublicKey.Span) ||
            !FixedEqual(request.RouteDomainHash.Span, delegation.RouteDomainHash.Span) ||
            !FixedEqual(request.SelectionInputCommitment.Span, delegation.SelectionInputCommitment.Span) ||
            !FixedEqual(request.PredecessorRouteOriginLkgHash.Span,
                ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(rol)) ||
            !FixedEqual(request.CurrentRouteHistoryCheckpointHash.Span, cursor.CanonicalCheckpointHash.Span) ||
            request.CurrentRouteHistoryBatchSequence != cursor.LastCommittedBatchSequence ||
            request.PredecessorAuthorizationSequence != rol.AuthorizationSequence ||
            !FixedEqual(request.PredecessorAuthorizationHash.Span, rol.CanonicalAuthorizationHash.Span) ||
            !FixedEqual(cursor.Enrollment.CanonicalDelegationHash.Span,
                anchor.EnrollmentState.Enrollment.CanonicalDelegationHash.Span))
            throw new FormatException("PMCQ1 differs from sealed enrollment/route/RHC state.");
    }

    private static void PreflightResponsePayload(ProductionMailboxOwnerControlResponseKind kind,
        ReadOnlySpan<byte> payload)
    {
        if (kind == ProductionMailboxOwnerControlResponseKind.History) _ = DecodeHistoryPayload(payload);
        else if (kind == ProductionMailboxOwnerControlResponseKind.FinalActivation) _ = DecodeFinalActivation(payload);
        else if (kind == ProductionMailboxOwnerControlResponseKind.NoChange && !payload.IsEmpty)
            throw new FormatException("PMCR1 NoChange payload must be empty.");
    }

    private static VerifiedProductionMailboxOwnerControlResponse VerifyResponsePayload(
        VerifiedProductionMailboxOwnerControlResponseHeader verifiedHeader,
        ReadOnlySpan<byte> payload)
    {
        var response = verifiedHeader.Response;
        if (payload.Length != response.PayloadLength ||
            !FixedEqual(SHA256.HashData(payload), response.PayloadSha256.Span))
            throw new FormatException("PMCR1 payload length/hash differs from authenticated header.");
        if (response.Kind == ProductionMailboxOwnerControlResponseKind.FinalActivation)
        {
            var final = DecodeFinalActivation(payload);
            if (final.Mode != response.Mode || final.AuthorizationKind != response.AuthorizationKind)
                throw new FormatException("PMFA1 mode/authorization differs from PMCR1.");
        }
        else if (response.Kind == ProductionMailboxOwnerControlResponseKind.History)
        {
            var history = DecodeHistoryPayload(payload);
            var checkpoint = ProductionMailboxRouteContinuityCodec.DecodeRouteHistoryCheckpoint(
                history.UntrustedCanonicalRouteHistoryCheckpoint.Span);
            if (!FixedEqual(response.NextRouteHistoryCheckpointHash.Span,
                    ProductionMailboxRouteContinuityCodec.ComputeRouteHistoryCheckpointHash(checkpoint)) ||
                response.NextRouteHistoryBatchSequence != checkpoint.LastCommittedBatchSequence)
                throw new FormatException("PMCR1 history next tuple differs from its canonical RHC1 payload.");
        }
        else
        {
            PreflightResponsePayload(response.Kind, payload);
        }
        var ownedPayload = payload.ToArray();
        return new(response, verifiedHeader.CanonicalBytes.Span, ownedPayload,
            ComputeResponseHash(response, ownedPayload));
    }

    private static bool FixedEqual(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second) =>
        first.Length == second.Length && CryptographicOperations.FixedTimeEquals(first, second);

    public static byte[] EncodeResponderCertificate(
        ProductionMailboxOwnerControlResponderCertificate value)
    {
        var frozen = Freeze(value);
        ValidateOcr(frozen, requireSignature: true);
        return EncodeOcrCore(frozen, includeSignature: true);
    }

    public static ProductionMailboxOwnerControlResponderCertificate DecodeResponderCertificate(
        ReadOnlySpan<byte> encoded)
    {
        FixedFrame(encoded, OcrMagic, ProductionMailboxOwnerControlConstants.ResponderCertificateLength,
            "OCR1");
        var frozen = encoded.ToArray();
        var value = new ProductionMailboxOwnerControlResponderCertificate
        {
            NetworkId = frozen.AsMemory(8, 16).ToArray(),
            MailboxOwnerEd25519PublicKey = frozen.AsMemory(24, 32).ToArray(),
            RouteDomainHash = frozen.AsMemory(56, 32).ToArray(),
            AnchorCanonicalAuthorityHash = frozen.AsMemory(88, 32).ToArray(),
            ResponderEd25519PublicKey = frozen.AsMemory(120, 32).ToArray(),
            IssuedAtUnixSeconds = U64(frozen, 152),
            ExpiresAtUnixSeconds = U64(frozen, 160),
            KeyGeneration = U64(frozen, 168),
            PreviousCanonicalCertificateHash = frozen.AsMemory(176, 32).ToArray(),
            AnchorIssuerSignature = frozen.AsMemory(208, 64).ToArray()
        };
        ValidateOcr(value, requireSignature: true);
        if (!frozen.AsSpan().SequenceEqual(EncodeOcrCore(value, includeSignature: true)))
            throw new FormatException("OCR1 is not canonical.");
        return value;
    }

    public static byte[] ComputeResponderCertificateHash(
        ProductionMailboxOwnerControlResponderCertificate value)
    {
        var encoded = EncodeResponderCertificate(value);
        return Hash(OcrHashDomain, encoded);
    }

    public static ProductionMailboxOwnerControlRequest DecodeRequest(
        ReadOnlySpan<byte> encoded)
    {
        FixedFrame(encoded, RequestMagic, ProductionMailboxOwnerControlConstants.RequestLength,
            "PMCQ1");
        var frozen = encoded.ToArray();
        var value = new ProductionMailboxOwnerControlRequest
        {
            Operation = (ProductionMailboxOwnerControlOperation)frozen[5],
            Mode = (ProductionMailboxSelectionSuccessorMode)frozen[6],
            ExpectedAuthorizationKind = (ProductionMailboxRouteAuthorizationKind)frozen[7],
            IssuedAtUnixSeconds = U64(frozen, 8),
            ExpiresAtUnixSeconds = U64(frozen, 16),
            RequestId = frozen.AsMemory(24, 32).ToArray(),
            NetworkId = frozen.AsMemory(56, 16).ToArray(),
            MailboxOwnerEd25519PublicKey = frozen.AsMemory(72, 32).ToArray(),
            RouteDomainHash = frozen.AsMemory(104, 32).ToArray(),
            SelectionInputCommitment = frozen.AsMemory(136, 32).ToArray(),
            PredecessorRouteOriginLkgHash = frozen.AsMemory(168, 32).ToArray(),
            CurrentRouteHistoryCheckpointHash = frozen.AsMemory(200, 32).ToArray(),
            CurrentRouteHistoryBatchSequence = U64(frozen, 232),
            PredecessorAuthorizationSequence = U64(frozen, 240),
            PredecessorAuthorizationHash = frozen.AsMemory(248, 32).ToArray(),
            OwnerSignature = frozen.AsMemory(280, 64).ToArray()
        };
        ValidateRequest(value, requireSignature: true);
        if (!frozen.AsSpan().SequenceEqual(EncodeRequestCore(value, includeSignature: true)))
            throw new FormatException("PMCQ1 is not canonical.");
        return value;
    }

    public static ProductionMailboxOwnerControlResponseHeader DecodeResponseHeader(
        ReadOnlySpan<byte> encoded)
    {
        FixedFrame(encoded, ResponseMagic, ProductionMailboxOwnerControlConstants.ResponseHeaderLength,
            "PMCR1");
        var frozen = encoded.ToArray();
        var value = new ProductionMailboxOwnerControlResponseHeader
        {
            Kind = (ProductionMailboxOwnerControlResponseKind)frozen[5],
            Mode = (ProductionMailboxSelectionSuccessorMode)frozen[6],
            AuthorizationKind = (ProductionMailboxRouteAuthorizationKind)frozen[7],
            IssuedAtUnixSeconds = U64(frozen, 8),
            ExpiresAtUnixSeconds = U64(frozen, 16),
            CanonicalRequestHash = frozen.AsMemory(24, 32).ToArray(),
            RequestId = frozen.AsMemory(56, 32).ToArray(),
            NetworkId = frozen.AsMemory(88, 16).ToArray(),
            RouteDomainHash = frozen.AsMemory(104, 32).ToArray(),
            PredecessorRouteOriginLkgHash = frozen.AsMemory(136, 32).ToArray(),
            CurrentRouteHistoryCheckpointHash = frozen.AsMemory(168, 32).ToArray(),
            NextRouteHistoryCheckpointHash = frozen.AsMemory(200, 32).ToArray(),
            CurrentRouteHistoryBatchSequence = U64(frozen, 232),
            NextRouteHistoryBatchSequence = U64(frozen, 240),
            PayloadSha256 = frozen.AsMemory(248, 32).ToArray(),
            PayloadLength = U32(frozen, 280),
            ResponderEd25519PublicKey = frozen.AsMemory(288, 32).ToArray(),
            ResponderSignature = frozen.AsMemory(320, 64).ToArray()
        };
        ValidateResponse(value, requireSignature: true);
        if (!frozen.AsSpan().SequenceEqual(EncodeResponseCore(value, includeSignature: true)))
            throw new FormatException("PMCR1 is not canonical.");
        return value;
    }

    public static ProductionMailboxFinalActivationFrame DecodeFinalActivation(
        ReadOnlySpan<byte> encoded)
    {
        PreflightFinalActivation(encoded, out var lengths, out var kind, out var mode);
        var frozen = encoded.ToArray();
        var offset = ProductionMailboxOwnerControlConstants.FinalActivationHeaderLength;
        ReadOnlyMemory<byte> Take(int index)
        {
            var result = frozen.AsMemory(offset, lengths[index]).ToArray();
            offset += lengths[index];
            return result;
        }
        var artifacts = new ProductionMailboxNodeCacheArtifacts
        {
            AuthorizationKind = kind,
            CanonicalAuthority = Take(0),
            CanonicalRevocations = Take(1),
            CanonicalTopology = Take(2),
            CanonicalCurrentSelection = Take(3),
            CanonicalNextSelection = Take(4),
            CanonicalSelectionSuccessorV2 = Take(5),
            CanonicalRouteCertificate = Take(6),
            CanonicalTransitionContext = Take(7),
            CanonicalRevocationCheckpoint = Take(8),
            CanonicalRouteAuthorization = Take(9)
        };
        if (offset != frozen.Length)
            throw new FormatException("PMFA1 has trailing bytes.");
        ValidateFinalArtifacts(artifacts);
        return new ProductionMailboxFinalActivationFrame
        {
            Mode = mode,
            AuthorizationKind = kind,
            Artifacts = artifacts
        };
    }

    internal static async ValueTask<ProductionMailboxFinalActivationFrame> ReadFinalActivationAsync(
        Stream source, uint payloadLength, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (payloadLength < 48 || payloadLength > ProductionMailboxOwnerControlConstants.MaximumFinalActivationFrameBytes)
            throw new FormatException("PMFA1 streamed payload length is outside its bound.");
        var header = new byte[48];
        await ReadExactAsync(source, header, cancellationToken).ConfigureAwait(false);
        PreflightFinalHeader(header, checked((int)payloadLength), out var lengths, out var kind, out var mode);
        var items = new byte[10][];
        for (var index = 0; index < items.Length; index++)
        {
            items[index] = new byte[lengths[index]];
            await ReadExactAsync(source, items[index], cancellationToken).ConfigureAwait(false);
            if (index == 1) PreflightPmr(items[index]);
            else if (index == 2) PreflightPmt(items[index]);
            else if (index is 3 or 4) PreflightPms(items[index]);
            else if (index == 5) PreflightPss(items[index], kind, mode);
        }
        var artifacts = new ProductionMailboxNodeCacheArtifacts
        {
            AuthorizationKind = kind, CanonicalAuthority = items[0], CanonicalRevocations = items[1],
            CanonicalTopology = items[2], CanonicalCurrentSelection = items[3],
            CanonicalNextSelection = items[4], CanonicalSelectionSuccessorV2 = items[5],
            CanonicalRouteCertificate = items[6], CanonicalTransitionContext = items[7],
            CanonicalRevocationCheckpoint = items[8], CanonicalRouteAuthorization = items[9]
        };
        ValidateFinalArtifacts(artifacts);
        return new ProductionMailboxFinalActivationFrame
        { Mode = mode, AuthorizationKind = kind, Artifacts = artifacts };
    }

    public static ProductionMailboxOwnerControlHistoryFrame DecodeHistoryPayload(
        ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 64 + ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength ||
            payload.Length > ProductionMailboxOwnerControlConstants.MaximumHistoryFrameBytes)
            throw new FormatException("Owner-control history payload length is invalid.");
        var batchLength = PreflightHistoryLength(payload[..64]);
        if (checked(batchLength + ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength) !=
            payload.Length)
            throw new FormatException("Owner-control history payload count-derived length is invalid.");
        _ = ProductionMailboxRouteHistoryCodec.Decode(payload[..batchLength]);
        _ = ProductionMailboxRouteContinuityCodec.DecodeRouteHistoryCheckpoint(payload[batchLength..]);
        return new ProductionMailboxOwnerControlHistoryFrame
        {
            CanonicalRouteHistoryBatch = payload[..batchLength].ToArray(),
            UntrustedCanonicalRouteHistoryCheckpoint = payload[batchLength..].ToArray()
        };
    }

    internal static async ValueTask<ProductionMailboxOwnerControlHistoryFrame> ReadHistoryPayloadAsync(
        Stream source, uint payloadLength, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (payloadLength < 528 || payloadLength > ProductionMailboxOwnerControlConstants.MaximumHistoryFrameBytes)
            throw new FormatException("History streamed payload length is outside its bound.");
        var prefix = new byte[64];
        await ReadExactAsync(source, prefix, cancellationToken).ConfigureAwait(false);
        var batchLength = PreflightHistoryLength(prefix);
        if (checked(batchLength + 464) != payloadLength)
            throw new FormatException("History streamed count-derived length differs from PMCR1.");
        var batch = new byte[batchLength]; prefix.CopyTo(batch, 0);
        await ReadExactAsync(source, batch.AsMemory(64), cancellationToken).ConfigureAwait(false);
        var checkpoint = new byte[464];
        await ReadExactAsync(source, checkpoint, cancellationToken).ConfigureAwait(false);
        _ = ProductionMailboxRouteHistoryCodec.Decode(batch);
        _ = ProductionMailboxRouteContinuityCodec.DecodeRouteHistoryCheckpoint(checkpoint);
        return new() { CanonicalRouteHistoryBatch = batch,
            UntrustedCanonicalRouteHistoryCheckpoint = checkpoint };
    }

    internal static byte[] GetOcrSigningBytes(
        ProductionMailboxOwnerControlResponderCertificate value)
    {
        var frozen = Freeze(value);
        ValidateOcr(frozen, requireSignature: false);
        return [.. OcrSigningDomain, .. EncodeOcrCore(frozen, includeSignature: false).AsSpan(4)];
    }

    internal static byte[] EncodeRequest(ProductionMailboxOwnerControlRequest value)
    {
        var frozen = Freeze(value);
        ValidateRequest(frozen, requireSignature: true);
        return EncodeRequestCore(frozen, includeSignature: true);
    }

    internal static byte[] GetRequestSigningBytes(ProductionMailboxOwnerControlRequest value,
        ReadOnlySpan<byte> canonicalOcrHash)
    {
        FixedNonzero(canonicalOcrHash, 32, "OCR1 hash");
        var frozen = Freeze(value);
        ValidateRequest(frozen, requireSignature: false);
        return [.. RequestSigningDomain, .. EncodeRequestCore(frozen, includeSignature: false).AsSpan(4),
            .. canonicalOcrHash];
    }

    internal static byte[] ComputeRequestHash(ProductionMailboxOwnerControlRequest value,
        ReadOnlySpan<byte> canonicalOcrHash)
    {
        FixedNonzero(canonicalOcrHash, 32, "OCR1 hash");
        var encoded = EncodeRequest(value);
        return Hash(RequestHashDomain, encoded, canonicalOcrHash);
    }

    internal static byte[] EncodeResponseHeader(ProductionMailboxOwnerControlResponseHeader value)
    {
        var frozen = Freeze(value);
        ValidateResponse(frozen, requireSignature: true);
        return EncodeResponseCore(frozen, includeSignature: true);
    }

    internal static byte[] GetResponseSigningBytes(ProductionMailboxOwnerControlResponseHeader value)
    {
        var frozen = Freeze(value);
        ValidateResponse(frozen, requireSignature: false);
        return [.. ResponseSigningDomain, .. EncodeResponseCore(frozen, includeSignature: false).AsSpan(4)];
    }

    internal static byte[] ComputeResponseHash(ProductionMailboxOwnerControlResponseHeader value,
        ReadOnlySpan<byte> payload)
    {
        var encoded = EncodeResponseHeader(value);
        if (payload.Length != value.PayloadLength ||
            !SHA256.HashData(payload).AsSpan().SequenceEqual(value.PayloadSha256.Span))
            throw new FormatException("PMCR1 payload binding is invalid.");
        return Hash(ResponseHashDomain, encoded, payload);
    }

    internal static byte[] EncodeFinalActivation(ProductionMailboxFinalActivationFrame value)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(value.Artifacts);
        if (value.AuthorizationKind != value.Artifacts.AuthorizationKind)
            throw new FormatException("PMFA1 authorization tags differ.");
        var all = All(value.Artifacts);
        long aggregate = 0;
        foreach (var bytes in all)
            aggregate = checked(aggregate + bytes.Length);
        if (aggregate > ProductionMailboxOwnerControlConstants.MaximumFinalActivationArtifactBytes)
            throw new FormatException("PMFA1 artifact aggregate exceeds 8 MiB.");
        var output = new byte[checked(ProductionMailboxOwnerControlConstants.FinalActivationHeaderLength +
            (int)aggregate)];
        FinalMagic.CopyTo(output);
        output[4] = ProductionMailboxOwnerControlConstants.Version;
        output[5] = (byte)value.Mode;
        output[6] = (byte)value.AuthorizationKind;
        var offset = ProductionMailboxOwnerControlConstants.FinalActivationHeaderLength;
        for (var i = 0; i < all.Length; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(8 + i * 4, 4), checked((uint)all[i].Length));
            all[i].Span.CopyTo(output.AsSpan(offset));
            offset += all[i].Length;
        }
        PreflightFinalActivation(output, out _, out _, out _);
        return output;
    }

    internal static void ValidateMessageWindow(ulong issuedAt, ulong expiresAt, ulong now,
        uint clockSkewSeconds, string name)
    {
        if (clockSkewSeconds > ProductionMailboxOwnerControlConstants.MaximumMessageLifetimeSeconds ||
            issuedAt == 0 || issuedAt == ulong.MaxValue || expiresAt <= issuedAt ||
            expiresAt == ulong.MaxValue ||
            expiresAt - issuedAt > ProductionMailboxOwnerControlConstants.MaximumMessageLifetimeSeconds ||
            now == 0 || now == ulong.MaxValue || now >= expiresAt ||
            issuedAt > now && issuedAt - now > clockSkewSeconds)
            throw new FormatException($"{name} validity window is invalid or stale.");
    }

    private static byte[] EncodeOcrCore(ProductionMailboxOwnerControlResponderCertificate value,
        bool includeSignature)
    {
        var output = new byte[includeSignature ? 272 : 208];
        OcrMagic.CopyTo(output); output[4] = 1;
        Copy(value.NetworkId.Span, output, 8);
        Copy(value.MailboxOwnerEd25519PublicKey.Span, output, 24);
        Copy(value.RouteDomainHash.Span, output, 56);
        Copy(value.AnchorCanonicalAuthorityHash.Span, output, 88);
        Copy(value.ResponderEd25519PublicKey.Span, output, 120);
        W64(output, 152, value.IssuedAtUnixSeconds); W64(output, 160, value.ExpiresAtUnixSeconds);
        W64(output, 168, value.KeyGeneration);
        Copy(value.PreviousCanonicalCertificateHash.Span, output, 176);
        if (includeSignature) Copy(value.AnchorIssuerSignature.Span, output, 208);
        return output;
    }

    private static byte[] EncodeRequestCore(ProductionMailboxOwnerControlRequest value,
        bool includeSignature)
    {
        var output = new byte[includeSignature ? 344 : 280];
        RequestMagic.CopyTo(output); output[4] = 1; output[5] = (byte)value.Operation;
        output[6] = (byte)value.Mode; output[7] = (byte)value.ExpectedAuthorizationKind;
        W64(output, 8, value.IssuedAtUnixSeconds); W64(output, 16, value.ExpiresAtUnixSeconds);
        Copy(value.RequestId.Span, output, 24); Copy(value.NetworkId.Span, output, 56);
        Copy(value.MailboxOwnerEd25519PublicKey.Span, output, 72);
        Copy(value.RouteDomainHash.Span, output, 104); Copy(value.SelectionInputCommitment.Span, output, 136);
        Copy(value.PredecessorRouteOriginLkgHash.Span, output, 168);
        Copy(value.CurrentRouteHistoryCheckpointHash.Span, output, 200);
        W64(output, 232, value.CurrentRouteHistoryBatchSequence);
        W64(output, 240, value.PredecessorAuthorizationSequence);
        Copy(value.PredecessorAuthorizationHash.Span, output, 248);
        if (includeSignature) Copy(value.OwnerSignature.Span, output, 280);
        return output;
    }

    private static byte[] EncodeResponseCore(ProductionMailboxOwnerControlResponseHeader value,
        bool includeSignature)
    {
        var output = new byte[includeSignature ? 384 : 320];
        ResponseMagic.CopyTo(output); output[4] = 1; output[5] = (byte)value.Kind;
        output[6] = (byte)value.Mode; output[7] = (byte)value.AuthorizationKind;
        W64(output, 8, value.IssuedAtUnixSeconds); W64(output, 16, value.ExpiresAtUnixSeconds);
        Copy(value.CanonicalRequestHash.Span, output, 24); Copy(value.RequestId.Span, output, 56);
        Copy(value.NetworkId.Span, output, 88); Copy(value.RouteDomainHash.Span, output, 104);
        Copy(value.PredecessorRouteOriginLkgHash.Span, output, 136);
        Copy(value.CurrentRouteHistoryCheckpointHash.Span, output, 168);
        Copy(value.NextRouteHistoryCheckpointHash.Span, output, 200);
        W64(output, 232, value.CurrentRouteHistoryBatchSequence); W64(output, 240, value.NextRouteHistoryBatchSequence);
        Copy(value.PayloadSha256.Span, output, 248); W32(output, 280, value.PayloadLength);
        Copy(value.ResponderEd25519PublicKey.Span, output, 288);
        if (includeSignature) Copy(value.ResponderSignature.Span, output, 320);
        return output;
    }

    private static void ValidateOcr(ProductionMailboxOwnerControlResponderCertificate value,
        bool requireSignature)
    {
        ArgumentNullException.ThrowIfNull(value);
        FixedNonzero(value.NetworkId.Span, 16, "OCR1 network");
        FixedNonzero(value.MailboxOwnerEd25519PublicKey.Span, 32, "OCR1 owner");
        FixedNonzero(value.RouteDomainHash.Span, 32, "OCR1 route domain");
        FixedNonzero(value.AnchorCanonicalAuthorityHash.Span, 32, "OCR1 anchor PMA1 hash");
        FixedNonzero(value.ResponderEd25519PublicKey.Span, 32, "OCR1 responder");
        if (value.IssuedAtUnixSeconds == 0 || value.IssuedAtUnixSeconds == ulong.MaxValue ||
            value.ExpiresAtUnixSeconds <= value.IssuedAtUnixSeconds ||
            value.ExpiresAtUnixSeconds == ulong.MaxValue ||
            value.ExpiresAtUnixSeconds - value.IssuedAtUnixSeconds >
                ProductionMailboxOwnerControlConstants.MaximumResponderCertificateLifetimeSeconds ||
            value.KeyGeneration != 1 ||
            value.PreviousCanonicalCertificateHash.Length != 32 ||
            value.PreviousCanonicalCertificateHash.Span.IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException("OCR1 genesis or validity fields are invalid.");
        Fixed(value.AnchorIssuerSignature.Span, 64, "OCR1 anchor issuer signature");
        if (requireSignature && value.AnchorIssuerSignature.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("OCR1 signature is all zero.");
    }

    private static void ValidateRequest(ProductionMailboxOwnerControlRequest value, bool requireSignature)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Operation != ProductionMailboxOwnerControlOperation.AdvanceOrFinalize ||
            value.Mode is not ProductionMailboxSelectionSuccessorMode.DirectPromotion and
                not ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint ||
            value.ExpectedAuthorizationKind is not ProductionMailboxRouteAuthorizationKind.OwnerPRA2 and
                not ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            throw new FormatException("PMCQ1 operation, mode or authorization tag is invalid.");
        ScalarWindow(value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds, "PMCQ1");
        FixedNonzero(value.RequestId.Span, 32, "PMCQ1 request ID");
        FixedNonzero(value.NetworkId.Span, 16, "PMCQ1 network");
        FixedNonzero(value.MailboxOwnerEd25519PublicKey.Span, 32, "PMCQ1 owner");
        FixedNonzero(value.RouteDomainHash.Span, 32, "PMCQ1 route");
        FixedNonzero(value.SelectionInputCommitment.Span, 32, "PMCQ1 selection");
        FixedNonzero(value.PredecessorRouteOriginLkgHash.Span, 32, "PMCQ1 predecessor ROL");
        FixedNonzero(value.CurrentRouteHistoryCheckpointHash.Span, 32, "PMCQ1 current RHC");
        if (value.CurrentRouteHistoryBatchSequence == ulong.MaxValue ||
            value.PredecessorAuthorizationSequence == 0 || value.PredecessorAuthorizationSequence == ulong.MaxValue)
            throw new FormatException("PMCQ1 sequence is invalid.");
        FixedNonzero(value.PredecessorAuthorizationHash.Span, 32, "PMCQ1 predecessor authorization");
        Fixed(value.OwnerSignature.Span, 64, "PMCQ1 owner signature");
        if (requireSignature && value.OwnerSignature.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("PMCQ1 owner signature is all zero.");
    }

    private static void ValidateResponse(ProductionMailboxOwnerControlResponseHeader value,
        bool requireSignature)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!Enum.IsDefined(value.Kind) ||
            value.Mode is not ProductionMailboxSelectionSuccessorMode.DirectPromotion and
                not ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint ||
            value.AuthorizationKind is not ProductionMailboxRouteAuthorizationKind.OwnerPRA2 and
                not ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            throw new FormatException("PMCR1 result, mode or authorization tag is invalid.");
        ScalarWindow(value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds, "PMCR1");
        FixedNonzero(value.CanonicalRequestHash.Span, 32, "PMCR1 request hash");
        FixedNonzero(value.RequestId.Span, 32, "PMCR1 request ID");
        FixedNonzero(value.NetworkId.Span, 16, "PMCR1 network");
        FixedNonzero(value.RouteDomainHash.Span, 32, "PMCR1 route");
        FixedNonzero(value.PredecessorRouteOriginLkgHash.Span, 32, "PMCR1 predecessor ROL");
        FixedNonzero(value.CurrentRouteHistoryCheckpointHash.Span, 32, "PMCR1 current RHC");
        FixedNonzero(value.NextRouteHistoryCheckpointHash.Span, 32, "PMCR1 next RHC");
        if (value.CurrentRouteHistoryBatchSequence == ulong.MaxValue ||
            value.NextRouteHistoryBatchSequence == ulong.MaxValue ||
            (value.Kind == ProductionMailboxOwnerControlResponseKind.History &&
                value.NextRouteHistoryBatchSequence != checked(value.CurrentRouteHistoryBatchSequence + 1)))
            throw new FormatException("PMCR1 sequence relation is invalid.");
        FixedNonzero(value.PayloadSha256.Span, 32, "PMCR1 payload hash");
        var maximumPayload = value.Kind == ProductionMailboxOwnerControlResponseKind.History
            ? ProductionMailboxOwnerControlConstants.MaximumHistoryFrameBytes
            : value.Kind == ProductionMailboxOwnerControlResponseKind.FinalActivation
                ? ProductionMailboxOwnerControlConstants.MaximumFinalActivationFrameBytes : 0;
        if (value.PayloadLength > maximumPayload ||
            (value.Kind != ProductionMailboxOwnerControlResponseKind.NoChange && value.PayloadLength == 0))
            throw new FormatException("PMCR1 payload length is invalid.");
        FixedNonzero(value.ResponderEd25519PublicKey.Span, 32, "PMCR1 responder");
        Fixed(value.ResponderSignature.Span, 64, "PMCR1 responder signature");
        if (requireSignature && value.ResponderSignature.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("PMCR1 responder signature is all zero.");
    }

    private static void PreflightFinalActivation(ReadOnlySpan<byte> encoded, out int[] lengths,
        out ProductionMailboxRouteAuthorizationKind kind,
        out ProductionMailboxSelectionSuccessorMode mode)
    {
        if (encoded.Length < ProductionMailboxOwnerControlConstants.FinalActivationHeaderLength ||
            encoded.Length > ProductionMailboxOwnerControlConstants.MaximumFinalActivationFrameBytes ||
            !encoded[..4].SequenceEqual(FinalMagic) || encoded[4] != 1 || encoded[7] != 0)
            throw new FormatException("PMFA1 fixed header is invalid.");
        mode = (ProductionMailboxSelectionSuccessorMode)encoded[5];
        kind = (ProductionMailboxRouteAuthorizationKind)encoded[6];
        if (mode is not ProductionMailboxSelectionSuccessorMode.DirectPromotion and
                not ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint ||
            kind is not ProductionMailboxRouteAuthorizationKind.OwnerPRA2 and
                not ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            throw new FormatException("PMFA1 tags are invalid.");
        lengths = new int[10];
        long aggregate = 0;
        for (var i = 0; i < lengths.Length; i++)
        {
            var raw = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(8 + i * 4, 4));
            if (raw > int.MaxValue) throw new FormatException("PMFA1 length is not representable.");
            lengths[i] = (int)raw;
            aggregate = checked(aggregate + raw);
        }
        if (aggregate > ProductionMailboxOwnerControlConstants.MaximumFinalActivationArtifactBytes ||
            checked(ProductionMailboxOwnerControlConstants.FinalActivationHeaderLength + aggregate) != encoded.Length)
            throw new FormatException("PMFA1 aggregate length is invalid.");
        if (lengths[0] is <= 0 or > ProductionMailboxAuthorityConstants.MaximumArtifactBytes ||
            lengths[1] is <= 0 or > ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes ||
            lengths[2] is <= 0 or > ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes ||
            lengths[3] is <= 0 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            lengths[4] is <= 0 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            lengths[5] is <= 0 or > ProductionMailboxSelectionSuccessorV2Constants.MaximumArtifactBytes ||
            lengths[6] != ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength ||
            lengths[7] != ProductionMailboxRouteAuthorizationConstants.CanonicalTransitionContextLength ||
            lengths[8] != (kind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1 ? 320 : 0) ||
            lengths[9] != (kind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1 ? 496 : 448))
            throw new FormatException("PMFA1 artifact shape is invalid.");
        var offset = 48 + lengths[0];
        PreflightPmr(encoded.Slice(offset, lengths[1])); offset += lengths[1];
        PreflightPmt(encoded.Slice(offset, lengths[2])); offset += lengths[2];
        PreflightPms(encoded.Slice(offset, lengths[3])); offset += lengths[3];
        PreflightPms(encoded.Slice(offset, lengths[4])); offset += lengths[4];
        PreflightPss(encoded.Slice(offset, lengths[5]), kind, mode);
    }

    private static void PreflightFinalHeader(ReadOnlySpan<byte> header, int payloadLength,
        out int[] lengths, out ProductionMailboxRouteAuthorizationKind kind,
        out ProductionMailboxSelectionSuccessorMode mode)
    {
        if (header.Length != 48 || payloadLength > ProductionMailboxOwnerControlConstants.MaximumFinalActivationFrameBytes ||
            !header[..4].SequenceEqual(FinalMagic) || header[4] != 1 || header[7] != 0)
            throw new FormatException("PMFA1 streamed fixed header is invalid.");
        mode = (ProductionMailboxSelectionSuccessorMode)header[5];
        kind = (ProductionMailboxRouteAuthorizationKind)header[6];
        if (mode is not ProductionMailboxSelectionSuccessorMode.DirectPromotion and
                not ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint ||
            kind is not ProductionMailboxRouteAuthorizationKind.OwnerPRA2 and
                not ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            throw new FormatException("PMFA1 streamed tags are invalid.");
        lengths = new int[10]; long aggregate = 0;
        for (var i = 0; i < 10; i++)
        {
            var raw = BinaryPrimitives.ReadUInt32BigEndian(header.Slice(8 + i * 4, 4));
            if (raw > int.MaxValue) throw new FormatException("PMFA1 streamed length is not representable.");
            lengths[i] = (int)raw; aggregate = checked(aggregate + raw);
        }
        if (aggregate > ProductionMailboxOwnerControlConstants.MaximumFinalActivationArtifactBytes ||
            checked(48 + aggregate) != payloadLength ||
            lengths[0] is <= 0 or > ProductionMailboxAuthorityConstants.MaximumArtifactBytes ||
            lengths[1] is <= 0 or > ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes ||
            lengths[2] is <= 0 or > ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes ||
            lengths[3] is <= 0 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            lengths[4] is <= 0 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            lengths[5] is <= 0 or > ProductionMailboxSelectionSuccessorV2Constants.MaximumArtifactBytes ||
            lengths[6] != 304 || lengths[7] != 408 ||
            lengths[8] != (kind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1 ? 320 : 0) ||
            lengths[9] != (kind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1 ? 496 : 448))
            throw new FormatException("PMFA1 streamed aggregate/artifact shape is invalid.");
    }

    private static int PreflightHistoryLength(ReadOnlySpan<byte> header)
    {
        if (header.Length != 64 || !header[..4].SequenceEqual("RHB1"u8) || header[4] != 1 ||
            header.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            header.Slice(60, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException("RHB1 leading header is invalid.");
        var links = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(48, 2));
        var artifacts = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(50, 2));
        var table = BinaryPrimitives.ReadUInt32BigEndian(header.Slice(52, 4));
        var payload = BinaryPrimitives.ReadUInt32BigEndian(header.Slice(56, 4));
        var derivedTable = checked((uint)(links * 32 + artifacts * 40));
        if (links is 0 or > 16 || artifacts is 0 or > 128 || table != derivedTable ||
            payload > 8 * 1024 * 1024)
            throw new FormatException("RHB1 leading counts are invalid.");
        return checked(64 + (int)table + (int)payload);
    }

    private static void ValidateFinalArtifacts(ProductionMailboxNodeCacheArtifacts value)
    {
        _ = ProductionMailboxAuthorityCodec.Decode(value.CanonicalAuthority.Span);
        _ = ProductionMailboxRevocationSnapshotCodec.Decode(value.CanonicalRevocations.Span);
        _ = ProductionMailboxTopologyCodec.Decode(value.CanonicalTopology.Span);
        _ = ProductionMailboxTopologyCodec.DecodeSelection(value.CanonicalCurrentSelection.Span);
        _ = ProductionMailboxTopologyCodec.DecodeSelection(value.CanonicalNextSelection.Span);
        _ = ProductionMailboxSelectionSuccessorV2Codec.Decode(value.CanonicalSelectionSuccessorV2.Span);
        _ = ProductionMailboxRouteAdvertisementCodec.DecodeCertificate(value.CanonicalRouteCertificate.Span);
        _ = ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(value.CanonicalTransitionContext.Span);
        if (value.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
            _ = ProductionMailboxRouteAuthorizationCodec.DecodeAdvertisementV2(value.CanonicalRouteAuthorization.Span);
        else
        {
            _ = ProductionMailboxRouteContinuityCodec.DecodeRevocationCheckpoint(
                value.CanonicalRevocationCheckpoint.Span);
            _ = ProductionMailboxRouteAuthorizationCodec.DecodeContinuityActivation(
                value.CanonicalRouteAuthorization.Span);
        }
    }

    // Allocation-free nested structural parity with the production node-cache verifier.
    private static void PreflightPmr(ReadOnlySpan<byte> value)
    {
        if (value.Length < ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials ||
            !value[..4].SequenceEqual("PMR1"u8) || value[4] != 1 || value.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException("PMFA1 PMR1 framing is invalid.");
        var count = BinaryPrimitives.ReadUInt16LittleEndian(value.Slice(152, 2));
        var expected = checked(ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials +
            count * ProductionMailboxRevocationSnapshotConstants.RevokedGrantSerialBytes);
        if (count > ProductionMailboxRevocationSnapshotConstants.MaximumRevokedGrantSerials || value.Length != expected)
            throw new FormatException("PMFA1 PMR1 count-derived framing is invalid.");
    }

    private static void PreflightPmt(ReadOnlySpan<byte> value)
    {
        if (value.Length < 780 || !value[..4].SequenceEqual("PMT1"u8) || value[4] != 1 ||
            value.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException("PMFA1 PMT1 framing is invalid.");
        var offset = 120; PmtEpoch(value, ref offset); PmtEpoch(value, ref offset);
        if (offset != value.Length - 64) throw new FormatException("PMFA1 PMT1 trailing bytes.");
    }

    private static void PmtEpoch(ReadOnlySpan<byte> value, ref int offset)
    {
        if (offset > value.Length - 164) throw new FormatException("PMFA1 PMT1 epoch truncated.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(offset + 96, 2));
        if (count is < 2 or > ProductionMailboxTopologyConstants.MaximumNodesPerEpoch ||
            value.Slice(offset + 98, 2).IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException("PMFA1 PMT1 epoch count invalid.");
        offset += 100;
        for (var i = 0; i < count; i++)
        {
            if (offset > value.Length - 162) throw new FormatException("PMFA1 PMT1 node truncated.");
            var endpoint = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(offset + 32, 2));
            if (endpoint is 0 or > ProductionMailboxTopologyConstants.MaximumEndpointBytes ||
                offset > value.Length - 98 - endpoint - 64)
                throw new FormatException("PMFA1 PMT1 endpoint invalid.");
            offset += 98 + endpoint;
        }
    }

    private static void PreflightPms(ReadOnlySpan<byte> value)
    {
        if (value.Length < 272 + ProductionMailboxTopologyConstants.ReplicaCount * 36 + 64 ||
            !value[..4].SequenceEqual("PMS1"u8) || value[4] != 1 ||
            value.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            value[268] != ProductionMailboxTopologyConstants.ReplicaCount ||
            value.Slice(269, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException("PMFA1 PMS1 framing is invalid.");
        var offset = 272;
        for (var i = 0; i < ProductionMailboxTopologyConstants.ReplicaCount; i++)
        {
            if (offset > value.Length - 100) throw new FormatException("PMFA1 PMS1 replica truncated.");
            var proof = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(offset + 32, 2));
            if (proof == 0 || value.Slice(offset + 34, 2).IndexOfAnyExcept((byte)0) >= 0 ||
                offset > value.Length - 36 - proof - 64)
                throw new FormatException("PMFA1 PMS1 proof framing invalid.");
            offset += 36 + proof;
        }
        if (offset != value.Length - 64) throw new FormatException("PMFA1 PMS1 trailing bytes.");
    }

    private static void PreflightPss(ReadOnlySpan<byte> value,
        ProductionMailboxRouteAuthorizationKind kind, ProductionMailboxSelectionSuccessorMode mode)
    {
        if (value.Length < ProductionMailboxSelectionSuccessorV2Constants.FixedCoreLength +
                ProductionMailboxSelectionSuccessorV2Constants.SignatureBytes ||
            !value[..4].SequenceEqual("PSS2"u8) || value[4] != 2 || value[5] != (byte)mode ||
            value.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            value.Slice(414, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            value.Slice(450, 6).IndexOfAnyExcept((byte)0) >= 0 || value[449] != (byte)kind)
            throw new FormatException("PMFA1 PSS2 framing is invalid.");
        var pma = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(408, 2));
        var oldPms = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(410, 2));
        var currentPms = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(412, 2));
        var expected = checked(ProductionMailboxSelectionSuccessorV2Constants.FixedCoreLength + pma + oldPms +
            currentPms + ProductionMailboxSelectionSuccessorV2Constants.SignatureBytes);
        if (pma is 0 or > ProductionMailboxAuthorityConstants.MaximumArtifactBytes ||
            oldPms is 0 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            currentPms is 0 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            value.Length != expected)
            throw new FormatException("PMFA1 PSS2 count-derived framing invalid.");
    }

    private static ReadOnlyMemory<byte>[] All(ProductionMailboxNodeCacheArtifacts value) =>
    [
        value.CanonicalAuthority, value.CanonicalRevocations, value.CanonicalTopology,
        value.CanonicalCurrentSelection, value.CanonicalNextSelection,
        value.CanonicalSelectionSuccessorV2, value.CanonicalRouteCertificate,
        value.CanonicalTransitionContext, value.CanonicalRevocationCheckpoint,
        value.CanonicalRouteAuthorization
    ];

    private static void FixedFrame(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> magic,
        int length, string name)
    {
        if (encoded.Length != length || !encoded[..4].SequenceEqual(magic) || encoded[4] != 1)
            throw new FormatException($"{name} fixed header is invalid.");
        if ((name == "OCR1") && encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException("OCR1 reserved bytes must be zero.");
    }

    private static void ScalarWindow(ulong from, ulong until, string name)
    {
        if (from == 0 || from == ulong.MaxValue || until <= from || until == ulong.MaxValue ||
            until - from > ProductionMailboxOwnerControlConstants.MaximumMessageLifetimeSeconds)
            throw new FormatException($"{name} validity window is invalid.");
    }

    private static ProductionMailboxOwnerControlResponderCertificate Freeze(
        ProductionMailboxOwnerControlResponderCertificate value) => value with
    {
        NetworkId = value.NetworkId.ToArray(), MailboxOwnerEd25519PublicKey = value.MailboxOwnerEd25519PublicKey.ToArray(),
        RouteDomainHash = value.RouteDomainHash.ToArray(), AnchorCanonicalAuthorityHash = value.AnchorCanonicalAuthorityHash.ToArray(),
        ResponderEd25519PublicKey = value.ResponderEd25519PublicKey.ToArray(),
        PreviousCanonicalCertificateHash = value.PreviousCanonicalCertificateHash.ToArray(),
        AnchorIssuerSignature = value.AnchorIssuerSignature.ToArray()
    };

    private static ProductionMailboxOwnerControlRequest Freeze(ProductionMailboxOwnerControlRequest value) => value with
    {
        RequestId = value.RequestId.ToArray(), NetworkId = value.NetworkId.ToArray(),
        MailboxOwnerEd25519PublicKey = value.MailboxOwnerEd25519PublicKey.ToArray(),
        RouteDomainHash = value.RouteDomainHash.ToArray(), SelectionInputCommitment = value.SelectionInputCommitment.ToArray(),
        PredecessorRouteOriginLkgHash = value.PredecessorRouteOriginLkgHash.ToArray(),
        CurrentRouteHistoryCheckpointHash = value.CurrentRouteHistoryCheckpointHash.ToArray(),
        PredecessorAuthorizationHash = value.PredecessorAuthorizationHash.ToArray(), OwnerSignature = value.OwnerSignature.ToArray()
    };

    private static ProductionMailboxOwnerControlResponseHeader Freeze(
        ProductionMailboxOwnerControlResponseHeader value) => value with
    {
        CanonicalRequestHash = value.CanonicalRequestHash.ToArray(), RequestId = value.RequestId.ToArray(),
        NetworkId = value.NetworkId.ToArray(), RouteDomainHash = value.RouteDomainHash.ToArray(),
        PredecessorRouteOriginLkgHash = value.PredecessorRouteOriginLkgHash.ToArray(),
        CurrentRouteHistoryCheckpointHash = value.CurrentRouteHistoryCheckpointHash.ToArray(),
        NextRouteHistoryCheckpointHash = value.NextRouteHistoryCheckpointHash.ToArray(),
        PayloadSha256 = value.PayloadSha256.ToArray(), ResponderEd25519PublicKey = value.ResponderEd25519PublicKey.ToArray(),
        ResponderSignature = value.ResponderSignature.ToArray()
    };

    private static byte[] Hash(ReadOnlySpan<byte> domain, ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second = default)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domain); hash.AppendData(first); if (!second.IsEmpty) hash.AppendData(second);
        return hash.GetHashAndReset();
    }

    private static ulong U64(ReadOnlySpan<byte> input, int offset) =>
        BinaryPrimitives.ReadUInt64BigEndian(input.Slice(offset, 8));
    private static uint U32(ReadOnlySpan<byte> input, int offset) =>
        BinaryPrimitives.ReadUInt32BigEndian(input.Slice(offset, 4));
    private static void W64(Span<byte> output, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64BigEndian(output.Slice(offset, 8), value);
    private static void W32(Span<byte> output, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32BigEndian(output.Slice(offset, 4), value);
    private static void Copy(ReadOnlySpan<byte> value, Span<byte> output, int offset) =>
        value.CopyTo(output[offset..]);
    private static void Fixed(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length) throw new FormatException($"{name} length is invalid.");
    }
    private static void FixedNonzero(ReadOnlySpan<byte> value, int length, string name)
    {
        Fixed(value, length, name);
        if (value.IndexOfAnyExcept((byte)0) < 0) throw new FormatException($"{name} is all zero.");
    }

    private static async ValueTask ReadExactAsync(Stream source, Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await source.ReadAsync(destination[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("Owner-control frame is truncated.");
            offset += read;
        }
    }
}
