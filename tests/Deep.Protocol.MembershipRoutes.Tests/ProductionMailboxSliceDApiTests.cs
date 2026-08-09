using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class ProductionMailboxSliceDApiTests
{
    private const ulong Now = 1_800_000_000;
    [Fact]
    public void SecurityCapabilitiesAreSealedAndCallerDraftAuthorersAreNotPublic()
    {
        Assert.Empty(typeof(VerifiedProductionMailboxHistoricalRouteAnchor).GetConstructors());
        Assert.Empty(typeof(VerifiedProductionMailboxLiveTransition).GetConstructors());
        Assert.Empty(typeof(VerifiedProductionMailboxOwnerControlRequest).GetConstructors());
        Assert.Empty(typeof(VerifiedProductionMailboxOwnerControlResponse).GetConstructors());
        Assert.Empty(typeof(VerifiedProductionMailboxOwnerControlResponseHeader).GetConstructors());
        Assert.Empty(typeof(VerifiedProductionMailboxRouteContinuityGenesisIntent)
            .GetConstructors());
        Assert.Empty(typeof(ProductionMailboxRouteContinuityGenesisCommitPlan)
            .GetConstructors());
        Assert.DoesNotContain(typeof(ProductionMailboxSelectionSuccessorAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static), static method =>
            method.Name is "AuthorDirectAsync" or "AuthorOfflineAsync");
        Assert.DoesNotContain(typeof(ProductionMailboxRouteIssuerAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static), static method =>
            method.Name == "CreateSelectionTransitionIntent");
        var transport = typeof(ProductionMailboxOwnerControlTransportCodec).GetMethods(
            BindingFlags.Public | BindingFlags.Static);
        Assert.DoesNotContain(transport, static method =>
            method.Name is "ReadFinalActivationAsync" or "ReadHistoryPayloadAsync");
        Assert.Contains(transport, static method =>
            method.Name == "ReadVerifiedResponsePayloadAsync" &&
            method.GetParameters().Any(static parameter =>
                parameter.ParameterType == typeof(VerifiedProductionMailboxOwnerControlResponseHeader)));
        var issuer = typeof(ProductionMailboxRouteIssuerAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static);
        Assert.Single(issuer, static method => method.Name == "VerifyGenesisIntent");
        var genesis = Assert.Single(issuer, static method => method.Name == "AuthorGenesisAsync");
        Assert.DoesNotContain(genesis.GetParameters(), static parameter =>
            parameter.ParameterType.Name.Contains("Commit", StringComparison.Ordinal) ||
            parameter.ParameterType.Name.Contains("Store", StringComparison.Ordinal));
        Assert.DoesNotContain(issuer, static method => method.Name is
            "AcceptDelegationAsync" or "AuthorOwnerControlResponderCertificateAsync" or
            "CreateHistoricalAnchor");
    }

    [Fact]
    public void LiveTransitionSurfaceHasNoForgeableDurabilityOrGenericVerifierSeam()
    {
        var methods = typeof(ProductionMailboxLiveTransitionAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static);
        Assert.Equal(4, methods.Length);
        Assert.All(methods, static method =>
        {
            Assert.DoesNotContain(method.GetParameters(), static parameter =>
                parameter.ParameterType.Name.Contains("Committer", StringComparison.Ordinal) ||
                parameter.ParameterType.IsInterface && parameter.ParameterType.Name.Contains("Verifier", StringComparison.Ordinal));
            Assert.DoesNotContain(method.GetParameters(), static parameter =>
                parameter.ParameterType == typeof(ProductionMailboxSelectionSuccessorMode) ||
                parameter.ParameterType == typeof(ProductionMailboxRouteAuthorizationKind));
        });
        Assert.Equal(272, ProductionMailboxOwnerControlConstants.ResponderCertificateLength);
        Assert.Equal(344, ProductionMailboxOwnerControlConstants.RequestLength);
        Assert.Equal(384, ProductionMailboxOwnerControlConstants.ResponseHeaderLength);
        Assert.Equal(48, ProductionMailboxOwnerControlConstants.FinalActivationHeaderLength);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task AllFourLiveTransitionEntrypointsProduceVerifiedPlans(
        bool delegated, bool offline)
    {
        var f = await CreateLiveFixtureAsync(offline);
        var window = new ProductionMailboxLiveTransitionWindow
        {
            RouteNotBeforeUnixSeconds = Now, RouteExpiresAtUnixSeconds = Now + 80,
            CheckpointIssuedAtUnixSeconds = Now, CheckpointExpiresAtUnixSeconds = Now + 80,
            AuthorizationIssuedAtUnixSeconds = Now, AuthorizationExpiresAtUnixSeconds = Now + 80,
            NowUnixSeconds = Now, ClockSkewSeconds = 0
        };
        static ValueTask Sign(ProductionMailboxPss2OldIssuerSigningRequest request,
            Memory<byte> destination, CancellationToken _, byte[] key)
        { PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(), key).CopyTo(destination.Span); return ValueTask.CompletedTask; }
        static ValueTask SignCurrent(ProductionMailboxPss2CurrentIssuerSigningRequest request,
            Memory<byte> destination, CancellationToken _, byte[] key)
        { PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(), key).CopyTo(destination.Span); return ValueTask.CompletedTask; }

        VerifiedProductionMailboxLiveTransition result;
        if (!delegated && !offline)
            result = await ProductionMailboxLiveTransitionAuthoring.AuthorOwnerDirectAsync(
                f.Anchor, f.Cursor, f.Intent, window,
                (r,d,_) => Sign64(r.SigningBytes, d, f.OwnerKey),
                (r,d,c) => Sign(r,d,c,f.OldIssuerKey),
                (r,d,c) => SignCurrent(r,d,c,f.CurrentIssuerKey));
        else if (!delegated)
            result = await ProductionMailboxLiveTransitionAuthoring.AuthorOwnerOfflineAsync(
                f.Anchor, f.Cursor, f.Intent, window,
                (r,d,_) => Sign64(r.SigningBytes, d, f.OwnerKey),
                (r,d,c) => SignCurrent(r,d,c,f.CurrentIssuerKey));
        else if (!offline)
            result = await ProductionMailboxLiveTransitionAuthoring.AuthorDelegatedDirectAsync(
                f.Anchor, f.Cursor, f.Intent, window,
                (r,d,_) => Sign64(r.SigningBytes, d, f.CurrentIssuerKey),
                (r,d,_) => Sign64(r.SigningBytes, d, f.CurrentIssuerKey),
                (r,d,c) => Sign(r,d,c,f.OldIssuerKey),
                (r,d,c) => SignCurrent(r,d,c,f.CurrentIssuerKey));
        else
            result = await ProductionMailboxLiveTransitionAuthoring.AuthorDelegatedOfflineAsync(
                f.Anchor, f.Cursor, f.Intent, window,
                (r,d,_) => Sign64(r.SigningBytes, d, f.CurrentIssuerKey),
                (r,d,_) => Sign64(r.SigningBytes, d, f.CurrentIssuerKey),
                (r,d,c) => SignCurrent(r,d,c,f.CurrentIssuerKey));

        Assert.Equal(offline ? ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint :
            ProductionMailboxSelectionSuccessorMode.DirectPromotion, result.Mode);
        Assert.NotEqual(new byte[32], result.CommitPlan.PlanHash.ToArray());
        var rtc = ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(
            result.CommitPlan.CanonicalTransitionContext.Span);
        Assert.Equal(ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(
            ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(
                result.CommitPlan.ExpectedPredecessorRouteOriginLkg.Span)),
            rtc.SealedOldRouteOriginLkgHash.ToArray());
        var successor = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            result.CommitPlan.CanonicalSelectionSuccessorV2.Span);
        Assert.Equal(ProductionMailboxRouteAuthorizationCodec.ComputeTransitionContextHash(rtc),
            successor.CanonicalTransitionContextHash.ToArray());

        ValueTask<VerifiedProductionMailboxOwnerControlRequest> requestTask = (delegated, offline) switch
        {
            (false, false) => ProductionMailboxOwnerControlTransportCodec.AuthorOwnerDirectRequestAsync(
                f.Anchor, f.Cursor, Enumerable.Repeat((byte)51, 32).ToArray(), Now, Now + 60,
                (r,d,_) => Sign64(r.SigningBytes, d, f.OwnerKey)),
            (false, true) => ProductionMailboxOwnerControlTransportCodec.AuthorOwnerOfflineRequestAsync(
                f.Anchor, f.Cursor, Enumerable.Repeat((byte)52, 32).ToArray(), Now, Now + 60,
                (r,d,_) => Sign64(r.SigningBytes, d, f.OwnerKey)),
            (true, false) => ProductionMailboxOwnerControlTransportCodec.AuthorDelegatedDirectRequestAsync(
                f.Anchor, f.Cursor, Enumerable.Repeat((byte)53, 32).ToArray(), Now, Now + 60,
                (r,d,_) => Sign64(r.SigningBytes, d, f.OwnerKey)),
            _ => ProductionMailboxOwnerControlTransportCodec.AuthorDelegatedOfflineRequestAsync(
                f.Anchor, f.Cursor, Enumerable.Repeat((byte)54, 32).ToArray(), Now, Now + 60,
                (r,d,_) => Sign64(r.SigningBytes, d, f.OwnerKey))
        };
        var ownerRequest = await requestTask;
        var response = await ProductionMailboxOwnerControlTransportCodec.AuthorFinalActivationResponseAsync(
            ownerRequest, f.Anchor, result, Now, Now + 50,
            (r,d,_) => Sign64(r.SigningBytes, d, f.ResponderKey));
        var responseHeader = ProductionMailboxOwnerControlTransportCodec.DecodeResponseHeader(
            response.CanonicalHeader.Span);
        Assert.Equal(responseHeader.CurrentRouteHistoryCheckpointHash.ToArray(),
            responseHeader.NextRouteHistoryCheckpointHash.ToArray());
        Assert.Equal(responseHeader.CurrentRouteHistoryBatchSequence,
            responseHeader.NextRouteHistoryBatchSequence);
    }

    [Fact]
    public async Task LiveTransition_MixedCursorAndExpiredWindowRejectBeforeCallbacks()
    {
        var direct = await CreateLiveFixtureAsync(false);
        var other = await CreateLiveFixtureAsync(true);
        var callbacks = 0;
        var window = new ProductionMailboxLiveTransitionWindow
        {
            RouteNotBeforeUnixSeconds = Now, RouteExpiresAtUnixSeconds = Now + 80,
            CheckpointIssuedAtUnixSeconds = Now, CheckpointExpiresAtUnixSeconds = Now + 80,
            AuthorizationIssuedAtUnixSeconds = Now, AuthorizationExpiresAtUnixSeconds = Now + 80,
            NowUnixSeconds = Now, ClockSkewSeconds = 0
        };
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ProductionMailboxLiveTransitionAuthoring.AuthorOwnerDirectAsync(
                direct.Anchor, other.Cursor, direct.Intent, window,
                (_,_,_) => { callbacks++; return ValueTask.FromResult(64); },
                (_,_,_) => { callbacks++; return ValueTask.CompletedTask; },
                (_,_,_) => { callbacks++; return ValueTask.CompletedTask; }));
        Assert.Equal(0, callbacks);

        var sourceCertificate = direct.Intent.RouteCertificate.Certificate;
        var otherPlacement = new BlindedPlacementId(
            Enumerable.Repeat((byte)201, 32).ToArray());
        var unsignedOtherCertificate = sourceCertificate with
        {
            BlindedPlacementId = otherPlacement.Bytes.ToArray(),
            SelectionInputCommitment = ProductionMailboxReplicaSelection
                .ComputeSelectionInputCommitment(otherPlacement),
            IssuerSignature = new byte[64]
        };
        var otherCertificate = unsignedOtherCertificate with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteAdvertisementCodec.GetCertificateSigningBytes(
                    unsignedOtherCertificate), direct.CurrentIssuerKey)
        };
        var verifiedOtherCertificate = ProductionMailboxRouteCertificateVerifier.Verify(
            ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(otherCertificate),
            direct.Intent.CurrentAuthority, Now, 0,
            new SodiumProductionMailboxRouteSignatureVerifier());
        var hostileIntent = new VerifiedProductionMailboxSelectionTransitionIntent(
            direct.Intent.Mode, direct.Intent.TrustedNetworkId,
            otherCertificate.SelectionInputCommitment.Span,
            direct.Intent.TrustedOldSelectionHash, direct.Intent.TrustedCurrentSelectionHash,
            direct.Intent.TrustedCurrentAuthorityHash, direct.Intent.TrustedCurrentRevocationHash,
            direct.Intent.CurrentCanonicalTopologyHash.Span,
            verifiedOtherCertificate.CanonicalCertificateHash.Span,
            direct.Intent.LiveNotBeforeUnixSeconds, direct.Intent.LiveExpiresAtUnixSeconds,
            direct.Intent.OldAuthority, direct.Intent.OldTopology, direct.Intent.OldSelection,
            direct.Intent.CurrentAuthority, direct.Intent.CurrentRevocations,
            direct.Intent.CurrentTopology, direct.Intent.CurrentSelection,
            verifiedOtherCertificate, direct.Intent.NextSelection, direct.Cursor);
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ProductionMailboxLiveTransitionAuthoring.AuthorOwnerDirectAsync(
                direct.Anchor, direct.Cursor, hostileIntent, window,
                (_,_,_) => { callbacks++; return ValueTask.FromResult(64); },
                (_,_,_) => { callbacks++; return ValueTask.CompletedTask; },
                (_,_,_) => { callbacks++; return ValueTask.CompletedTask; }));
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ProductionMailboxLiveTransitionAuthoring.AuthorDelegatedDirectAsync(
                direct.Anchor, direct.Cursor, hostileIntent, window,
                (_,_,_) => { callbacks++; return ValueTask.FromResult(64); },
                (_,_,_) => { callbacks++; return ValueTask.FromResult(64); },
                (_,_,_) => { callbacks++; return ValueTask.CompletedTask; },
                (_,_,_) => { callbacks++; return ValueTask.CompletedTask; }));
        Assert.Equal(0, callbacks);
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ProductionMailboxLiveTransitionAuthoring.AuthorOwnerDirectAsync(
                direct.Anchor, direct.Cursor, direct.Intent, window with { NowUnixSeconds = Now + 81 },
                (_,_,_) => { callbacks++; return ValueTask.FromResult(64); },
                (_,_,_) => { callbacks++; return ValueTask.CompletedTask; },
                (_,_,_) => { callbacks++; return ValueTask.CompletedTask; }));
        Assert.Equal(0, callbacks);
    }

    [Fact]
    public async Task OcrExpiryMayOutliveRetiredPraWhileRemainingInsideRcd()
    {
        var fixture = await CreateLiveFixtureAsync(false);
        Assert.NotNull(fixture.Anchor);
    }

    private static ValueTask<int> Sign64(ReadOnlyMemory<byte> bytes, Memory<byte> destination,
        byte[] key)
    { PublicKeyAuth.SignDetached(bytes.ToArray(), key).CopyTo(destination.Span); return ValueTask.FromResult(64); }

    private static async Task<LiveFixture> CreateLiveFixtureAsync(bool offline)
    {
        var method = typeof(ProductionMailboxSelectionSuccessorTests).GetMethod("CreateFixture",
            BindingFlags.NonPublic | BindingFlags.Static)!;
        var raw = method.Invoke(null, [false,
            offline ? ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint :
                ProductionMailboxSelectionSuccessorMode.DirectPromotion,
            offline ? 3UL : 1UL, offline ? 3UL : 1UL, 5UL, false, true])!;
        T Get<T>(string name) => (T)raw.GetType().GetProperty(name)!.GetValue(raw)!;
        var oldAuthority = Get<VerifiedProductionMailboxAuthority>("OldAuthority");
        var oldTopology = Get<VerifiedProductionMailboxTopology>("OldTopology");
        var authority = Get<VerifiedProductionMailboxAuthority>("NewAuthority");
        var topology = Get<VerifiedProductionMailboxTopology>("NewTopology");
        var proof = Get<ProductionMailboxSelectionSuccessorProof>("Proof");
        var placement = Get<BlindedPlacementId>("Placement");
        var oldKey = Get<byte[]>("OldIssuerPrivateKey");
        var issuerKey = Get<byte[]>("NewIssuerPrivateKey");
        var ownerKey = Get<byte[]>("OwnerPrivateKey");
        var ownerPub = proof.MailboxOwnerEd25519PublicKey;
        var pmrBytes = Get<byte[]>("NewRevocationSnapshot");
        var revocations = ProductionMailboxRevocationSnapshotVerifier.Verify(pmrBytes,
            authority, Now, 0, new SodiumProductionMailboxRevocationSnapshotSignatureVerifier());
        var oldSelection = ProductionMailboxSelectionVerifier.Verify(proof.OldCanonicalSelection.Span,
            oldAuthority, oldTopology, placement, Now, 0,
            new SodiumProductionMailboxTopologySignatureVerifier());
        var currentSelection = ProductionMailboxSelectionVerifier.Verify(proof.NewCanonicalSelection.Span,
            authority, topology, placement, Now, 0,
            new SodiumProductionMailboxTopologySignatureVerifier());
        var nextSelection = ProductionMailboxSelectionVerifier.Verify(Get<byte[]>("NewNextSelection"),
            authority, topology, placement, Now, 0,
            new SodiumProductionMailboxTopologySignatureVerifier());
        var certificate = new ProductionMailboxRouteCertificate
        {
            NetworkId = authority.Authority.NetworkId.ToArray(),
            AuthorityGeneration = authority.Authority.AuthorityGeneration,
            CanonicalAuthorityHash = authority.CanonicalAuthorityHash.ToArray(),
            IssuerEd25519PublicKey = authority.Authority.MailboxIssuerEd25519PublicKey.ToArray(),
            MailboxOwnerEd25519PublicKey = ownerPub.ToArray(),
            BlindedMailboxId = proof.BlindedMailboxId.ToArray(),
            BlindedPlacementId = placement.Bytes.ToArray(),
            SelectionInputCommitment = proof.SelectionInputCommitment.ToArray(),
            IssuedAtUnixSeconds = Now - 1, ExpiresAtUnixSeconds = Now + 80,
            IssuerSignature = new byte[64]
        };
        certificate = certificate with { IssuerSignature = PublicKeyAuth.SignDetached(
            ProductionMailboxRouteAdvertisementCodec.GetCertificateSigningBytes(certificate), issuerKey) };
        var verifiedCertificate = ProductionMailboxRouteCertificateVerifier.Verify(
            ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(certificate), authority, Now, 0,
            new SodiumProductionMailboxRouteSignatureVerifier());
        var route = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(certificate);
        var pra = new ProductionMailboxRouteAdvertisementV2
        {
            Certificate = certificate, PredecessorAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            PredecessorCanonicalRouteAuthorizationHash = Enumerable.Repeat((byte)9, 32).ToArray(),
            PredecessorRouteAuthorizationSequence = 3, Sequence = 4,
            PublishedAtUnixSeconds = Now - 1, ExpiresAtUnixSeconds = Now + 40,
            OwnerSignature = new byte[64]
        };
        pra = pra with { OwnerSignature = PublicKeyAuth.SignDetached(
            ProductionMailboxRouteAuthorizationCodec.GetAdvertisementV2SigningBytes(pra), ownerKey) };
        var verifiedPra = ProductionMailboxRouteAuthorizationVerifier.VerifyOwnerAuthorization(
            ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(pra), authority,
            new ProductionMailboxOwnerRouteAuthorizationVerificationContext
            {
                ExpectedNetworkId = certificate.NetworkId, ExpectedRouteDomainHash = route,
                ExpectedPredecessorKind = pra.PredecessorAuthorizationKind,
                ExpectedPredecessorHash = pra.PredecessorCanonicalRouteAuthorizationHash,
                ExpectedPredecessorSequence = pra.PredecessorRouteAuthorizationSequence,
                NowUnixSeconds = Now, ClockSkewSeconds = 0
            }, new SodiumProductionMailboxRouteSignatureVerifier());
        var preRol = new ProductionMailboxRouteOriginLkg
        {
            NetworkId = certificate.NetworkId, RouteDomainHash = route,
            AuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            CanonicalAuthorizationHash = verifiedPra.CanonicalHash, AuthorizationSequence = 4,
            CanonicalDelegationHash = new byte[32], CanonicalDelegationAcceptanceHash = new byte[32],
            OwnerRevocationGeneration = 0, OwnerRevocationHeadHash = new byte[32],
            RouteVerifiedAtUnixSeconds = Now - 1, LocalCommitGeneration = 1
        };
        var mrXPin = SHA256.HashData(authority.Authority.MrXApprovalEd25519PublicKey.Span);
        var delegation = new ProductionMailboxRouteContinuityDelegation
        {
            NetworkId = certificate.NetworkId, PinnedMrXPublicKeySha256 = mrXPin,
            RouteDomainHash = route, MailboxOwnerEd25519PublicKey = ownerPub,
            BlindedMailboxId = certificate.BlindedMailboxId, BlindedPlacementId = certificate.BlindedPlacementId,
            SelectionInputCommitment = certificate.SelectionInputCommitment,
            AnchorAuthorityGeneration = authority.Authority.AuthorityGeneration,
            AnchorCanonicalAuthorityHash = authority.CanonicalAuthorityHash,
            AnchorCanonicalRouteCertificateHash = verifiedCertificate.CanonicalCertificateHash,
            AnchorAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            AnchorCanonicalRouteAuthorizationHash = verifiedPra.CanonicalHash,
            AnchorRouteAuthorizationSequence = 4,
            PreDelegationRouteOriginLkgHash = ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(preRol),
            RouteVerifiedAtUnixSeconds = preRol.RouteVerifiedAtUnixSeconds,
            Capability = ProductionMailboxRouteContinuityCapability.RouteContinuityOnly,
            DelegationSerial = Enumerable.Repeat((byte)8, 16).ToArray(), DelegationSequence = 1,
            PreviousCanonicalDelegationHash = new byte[32],
            MaximumAuthorityGeneration = authority.Authority.AuthorityGeneration + 1,
            FirstActivationSequence = 5, LastActivationSequence = 20,
            IssuedAtUnixSeconds = Now - 1, NotBeforeUnixSeconds = Now - 1,
            ExpiresAtUnixSeconds = Now + 80, OwnerSignature = new byte[64]
        };
        delegation = delegation with { OwnerSignature = PublicKeyAuth.SignDetached(
            ProductionMailboxRouteContinuityCodec.GetDelegationSigningBytes(delegation), ownerKey) };
        var enrollment = await ProductionMailboxRouteIssuerAuthoring.AcceptDelegationAsync(
            ProductionMailboxRouteContinuityCodec.EncodeDelegation(delegation),
            ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(preRol), authority,
            revocations, verifiedCertificate, verifiedPra, Now, Now, 0,
            (r,d,_) => Sign64(r.SigningBytes, d, issuerKey), static (_,_) => ValueTask.FromResult(true));
        var responder = PublicKeyAuth.GenerateKeyPair(Enumerable.Repeat((byte)77, 32).ToArray());
        var ocr = await ProductionMailboxRouteIssuerAuthoring.AuthorOwnerControlResponderCertificateAsync(
            enrollment, authority, revocations, verifiedCertificate, verifiedPra, responder.PublicKey,
            Now + 70, (r,d,_) => Sign64(r.SigningBytes, d, issuerKey));
        var anchor = ProductionMailboxRouteIssuerAuthoring.CreateHistoricalAnchor(enrollment,
            authority, revocations, verifiedCertificate, verifiedPra, ocr);
        var cursor = ProductionMailboxRouteHistoryAuthoring.CreateInitialCursor(enrollment, authority, revocations);
        var intent = offline
            ? ProductionMailboxRouteIssuerAuthoring.CreateOfflineSelectionTransitionIntent(cursor,
                oldAuthority, oldTopology, oldSelection, authority, revocations, topology,
                currentSelection, nextSelection, verifiedCertificate, Now, 0)
            : ProductionMailboxRouteIssuerAuthoring.CreateDirectSelectionTransitionIntent(cursor,
                oldAuthority, oldTopology, oldSelection, authority, revocations, topology,
                currentSelection, nextSelection, verifiedCertificate, Now, 0);
        return new(anchor, cursor, intent, oldKey, issuerKey, ownerKey, responder.PrivateKey);
    }

    private sealed record LiveFixture(VerifiedProductionMailboxHistoricalRouteAnchor Anchor,
        VerifiedProductionMailboxRouteHistoryCursor Cursor,
        VerifiedProductionMailboxSelectionTransitionIntent Intent,
        byte[] OldIssuerKey, byte[] CurrentIssuerKey, byte[] OwnerKey, byte[] ResponderKey);

}
