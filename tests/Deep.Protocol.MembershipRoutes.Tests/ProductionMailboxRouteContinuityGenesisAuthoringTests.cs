using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class ProductionMailboxRouteContinuityGenesisAuthoringTests
{
    [Fact]
    public async Task Genesis_AuthorsExactDefensiveDeterministicTupleAndRestores()
    {
        var f = RouteV2TestFixture.Create();
        var mutableRcd = ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation);
        var mutablePreRol = ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(
            f.PreDelegationRouteOriginLkg);
        var intent = ProductionMailboxRouteIssuerAuthoring.VerifyGenesisIntent(
            mutableRcd, mutablePreRol, f.Authority, f.RevocationSnapshot,
            f.VerifiedCertificate, f.VerifiedPra, RouteV2TestFixture.Now, 0);
        var intentHash = intent.IntentHash.ToArray();
        Assert.Equal(f.NetworkId, intent.NetworkId.ToArray());
        Assert.Equal(f.Delegation.MailboxOwnerEd25519PublicKey.ToArray(),
            intent.MailboxOwnerEd25519PublicKey.ToArray());
        Assert.Equal(f.RouteDomainHash, intent.RouteDomainHash.ToArray());
        Assert.Equal(f.Delegation.SelectionInputCommitment.ToArray(),
            intent.SelectionInputCommitment.ToArray());
        mutableRcd[0] ^= 0xff; mutablePreRol[0] ^= 0xff;
        var responder = PublicKeyAuth.GenerateKeyPair(RouteV2TestFixture.Bytes(221, 32));
        var order = new List<string>();

        var plan = await Author(intent, f, responder, RouteV2TestFixture.Now + 40,
            onRda: () => order.Add("RDA1"), onOcr: () => order.Add("OCR1"));
        Assert.Equal(["RDA1", "OCR1"], order);
        Assert.Equal(intentHash, intent.IntentHash.ToArray());
        Assert.Equal(ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation),
            plan.CanonicalDelegation.ToArray());
        Assert.Equal(intent.IntentHash.ToArray(), plan.GenesisIntentHash.ToArray());
        Assert.Equal(ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(
            f.PreDelegationRouteOriginLkg),
            plan.ExpectedPreDelegationRouteOriginLkg.ToArray());
        var enrolled = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(
            plan.CanonicalEnrolledRouteOriginLkg.Span);
        Assert.Equal(f.PreDelegationRouteOriginLkg.LocalCommitGeneration + 1,
            enrolled.LocalCommitGeneration);
        Assert.Equal(plan.CanonicalDelegationHash.ToArray(),
            enrolled.CanonicalDelegationHash.ToArray());
        Assert.Equal(plan.CanonicalAcceptanceHash.ToArray(),
            enrolled.CanonicalDelegationAcceptanceHash.ToArray());
        var checkpoint = ProductionMailboxRouteContinuityCodec.DecodeRouteHistoryCheckpoint(
            plan.CanonicalInitialRouteHistoryCheckpoint.Span);
        Assert.Equal(0UL, checkpoint.LastCommittedBatchSequence);
        Assert.Equal(0UL, checkpoint.CumulativeCommittedBatchCount);
        Assert.Equal(new byte[32], checkpoint.LastCommittedBatchHash.ToArray());
        Assert.Equal(plan.EnrolledRouteOriginLkgHash.ToArray(),
            checkpoint.CurrentRouteOriginLkgHash.ToArray());

        var enrollmentContext = plan.ToProtectedEnrollmentRestoreContext();
        var historyContext = plan.ToProtectedRouteHistoryRestoreContext();
        Assert.Equal(plan.CanonicalAcceptanceHash.ToArray(),
            enrollmentContext.CanonicalAcceptanceHash.ToArray());
        Assert.Equal(plan.CanonicalInitialRouteHistoryCheckpointHash.ToArray(),
            historyContext.CanonicalCheckpointHash.ToArray());
        var anchor = ProductionMailboxRouteIssuerAuthoring.RestoreHistoricalAnchor(
            plan.CanonicalDelegation, plan.CanonicalAcceptance,
            plan.ExpectedPreDelegationRouteOriginLkg,
            plan.CanonicalEnrolledRouteOriginLkg,
            plan.CanonicalOwnerControlResponderCertificate,
            f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra,
            enrollmentContext);
        var cursor = ProductionMailboxRouteHistoryAuthoring.RestoreCursor(
            plan.CanonicalInitialRouteHistoryCheckpoint.Span, anchor, historyContext);
        Assert.Equal(plan.CanonicalInitialRouteHistoryCheckpointHash.ToArray(),
            cursor.CanonicalCheckpointHash.ToArray());

        var exposed = plan.CanonicalAcceptance.ToArray(); exposed[0] ^= 0xff;
        var exposedPlanHash = plan.PlanHash.ToArray(); exposedPlanHash[0] ^= 0xff;
        var exposedContext = enrollmentContext.CanonicalOwnerControlResponderCertificate.ToArray();
        exposedContext[0] ^= 0xff;
        Assert.NotEqual(exposed, plan.CanonicalAcceptance.ToArray());
        Assert.NotEqual(exposedPlanHash, plan.PlanHash.ToArray());
        Assert.NotEqual(exposedContext,
            plan.ToProtectedEnrollmentRestoreContext()
                .CanonicalOwnerControlResponderCertificate.ToArray());

        var replay = await Author(intent, f, responder, RouteV2TestFixture.Now + 40);
        Assert.Equal(plan.PlanHash.ToArray(), replay.PlanHash.ToArray());
        Assert.Equal(plan.CanonicalAcceptance.ToArray(), replay.CanonicalAcceptance.ToArray());
        Assert.Equal(plan.CanonicalOwnerControlResponderCertificate.ToArray(),
            replay.CanonicalOwnerControlResponderCertificate.ToArray());

        var mutableResponder = RouteV2TestFixture.Bytes(225, 32);
        var expectedResponder = mutableResponder.ToArray();
        var mutationPlan = await ProductionMailboxRouteIssuerAuthoring.AuthorGenesisAsync(intent,
            RouteV2TestFixture.Now, RouteV2TestFixture.Now + 40, mutableResponder,
            RouteV2TestFixture.Now + 120,
            (request, destination, _) =>
            {
                mutableResponder[0] ^= 0xff;
                return Sign(request.SigningBytes, destination, f.IssuerPrivateKey);
            },
            (request, destination, _) => Sign(request.SigningBytes, destination,
                f.IssuerPrivateKey));
        var frozenOcr = ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(
            mutationPlan.CanonicalOwnerControlResponderCertificate.Span);
        Assert.Equal(expectedResponder, frozenOcr.ResponderEd25519PublicKey.ToArray());
        Assert.NotEqual(plan.PlanHash.ToArray(), mutationPlan.PlanHash.ToArray());
    }

    [Fact]
    public async Task Genesis_InvalidOwnerAnchorAndAuthorInputsRejectBeforeCallbacks()
    {
        var f = RouteV2TestFixture.Create();
        var invalidRcd = ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation);
        invalidRcd[^1] ^= 1;
        Assert.Throws<ProductionMailboxRouteContinuityException>(() =>
            ProductionMailboxRouteIssuerAuthoring.VerifyGenesisIntent(invalidRcd, PreRol(f),
                f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra,
                RouteV2TestFixture.Now, 0));
        var other = RouteV2TestFixture.Create(1);
        Assert.ThrowsAny<Exception>(() =>
            ProductionMailboxRouteIssuerAuthoring.VerifyGenesisIntent(
                ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation), PreRol(f),
                other.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra,
                RouteV2TestFixture.Now, 0));

        var intent = Intent(f);
        var rda = 0; var ocr = 0;
        static ValueTask<int> NeverRda(ProductionMailboxRda1SigningRequest _, Memory<byte> __,
            CancellationToken ___) => throw new Xunit.Sdk.XunitException("unexpected RDA callback");
        static ValueTask<int> NeverOcr(ProductionMailboxOcr1SigningRequest _, Memory<byte> __,
            CancellationToken ___) => throw new Xunit.Sdk.XunitException("unexpected OCR callback");
        var key = PublicKeyAuth.GenerateKeyPair(RouteV2TestFixture.Bytes(222, 32));
        async Task Reject(ulong acceptedAt, ulong now, ReadOnlyMemory<byte> responder,
            ulong expiry) => await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AuthorGenesisAsync(intent,
                acceptedAt, now, responder, expiry,
                (a,b,c) => { rda++; return NeverRda(a,b,c); },
                (a,b,c) => { ocr++; return NeverOcr(a,b,c); }));
        await Reject(RouteV2TestFixture.Now + 1, RouteV2TestFixture.Now,
            key.PublicKey, RouteV2TestFixture.Now + 50);
        await Reject(RouteV2TestFixture.Now, RouteV2TestFixture.Now,
            new byte[32], RouteV2TestFixture.Now + 50);
        await Reject(RouteV2TestFixture.Now,
            f.Delegation.ExpiresAtUnixSeconds, key.PublicKey,
            f.Delegation.ExpiresAtUnixSeconds);
        await Reject(RouteV2TestFixture.Now, RouteV2TestFixture.Now + 40,
            key.PublicKey, RouteV2TestFixture.Now + 40);
        Assert.Equal(0, rda); Assert.Equal(0, ocr);
    }

    [Fact]
    public async Task Genesis_SignerFailureCancellationAndRetryBoundariesFailClosed()
    {
        var f = RouteV2TestFixture.Create();
        var intent = Intent(f);
        var responder = PublicKeyAuth.GenerateKeyPair(RouteV2TestFixture.Bytes(223, 32));
        var ocrCalls = 0;
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AuthorGenesisAsync(intent,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now + 20,
                responder.PublicKey, RouteV2TestFixture.Now + 80,
                (_, destination, _) =>
                {
                    destination.Span.Fill(7); return ValueTask.FromResult(63);
                }, (_, _, _) => { ocrCalls++; return ValueTask.FromResult(64); }));
        Assert.Equal(0, ocrCalls);

        var wrong = PublicKeyAuth.GenerateKeyPair(RouteV2TestFixture.Bytes(224, 32));
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AuthorGenesisAsync(intent,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now + 20,
                responder.PublicKey, RouteV2TestFixture.Now + 80,
                (request, destination, _) =>
                {
                    PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(), wrong.PrivateKey)
                        .CopyTo(destination.Span);
                    return ValueTask.FromResult(64);
                }, (_, _, _) => { ocrCalls++; return ValueTask.FromResult(64); }));
        Assert.Equal(0, ocrCalls);

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AuthorGenesisAsync(intent,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now + 20,
                responder.PublicKey, RouteV2TestFixture.Now + 80,
                (request, destination, _) => Sign(request.SigningBytes, destination,
                    f.IssuerPrivateKey),
                (request, destination, _) => Sign(request.SigningBytes, destination,
                    wrong.PrivateKey)));

        using var cancellation = new CancellationTokenSource();
        ocrCalls = 0;
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AuthorGenesisAsync(intent,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now + 20,
                responder.PublicKey, RouteV2TestFixture.Now + 80,
                (request, destination, _) =>
                {
                    var result = Sign(request.SigningBytes, destination, f.IssuerPrivateKey);
                    cancellation.Cancel(); return result;
                }, (_, _, _) => { ocrCalls++; return ValueTask.FromResult(64); },
                cancellation.Token));
        Assert.Equal(0, ocrCalls);

        var retry = await Author(intent, f, responder, RouteV2TestFixture.Now + 100);
        Assert.Equal(RouteV2TestFixture.Now, retry.AcceptedAtUnixSeconds);
    }

    [Fact]
    public void Genesis_PublicSurfaceHasNoPartialCommitOrCapabilityConversion()
    {
        Assert.Empty(typeof(VerifiedProductionMailboxRouteContinuityGenesisIntent)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(ProductionMailboxRouteContinuityGenesisCommitPlan)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        var methods = typeof(ProductionMailboxRouteIssuerAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static);
        Assert.Single(methods, method => method.Name == "VerifyGenesisIntent");
        var author = Assert.Single(methods, method => method.Name == "AuthorGenesisAsync");
        Assert.DoesNotContain(author.GetParameters(), parameter =>
            parameter.ParameterType.Name.Contains("Commit", StringComparison.Ordinal) ||
            parameter.ParameterType.Name.Contains("Store", StringComparison.Ordinal));
        Assert.DoesNotContain(methods, method => method.Name is "AcceptDelegationAsync" or
            "AuthorOwnerControlResponderCertificateAsync" or "CreateHistoricalAnchor");
        Assert.DoesNotContain(typeof(ProductionMailboxRouteHistoryAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static), method =>
            method.Name == "CreateInitialCursor");
        var restore = Assert.Single(typeof(ProductionMailboxRouteHistoryAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static), method => method.Name == "RestoreCursor");
        Assert.Contains(restore.GetParameters(), parameter =>
            parameter.ParameterType == typeof(VerifiedProductionMailboxHistoricalRouteAnchor));
        Assert.DoesNotContain(typeof(ProductionMailboxRouteContinuityGenesisCommitPlan)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance), method =>
            method.ReturnType.Name.StartsWith("Verified", StringComparison.Ordinal) ||
            method.Name.Contains("Publish", StringComparison.Ordinal) ||
            method.Name is "Commit" or "CommitAsync");
    }

    private static VerifiedProductionMailboxRouteContinuityGenesisIntent Intent(
        RouteV2TestFixture f) => ProductionMailboxRouteIssuerAuthoring.VerifyGenesisIntent(
        ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation), PreRol(f),
        f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra,
        RouteV2TestFixture.Now, 0);

    private static byte[] PreRol(RouteV2TestFixture f) =>
        ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(
            f.PreDelegationRouteOriginLkg);

    private static ValueTask<ProductionMailboxRouteContinuityGenesisCommitPlan> Author(
        VerifiedProductionMailboxRouteContinuityGenesisIntent intent,
        RouteV2TestFixture f, KeyPair responder, ulong authorNow,
        Action? onRda = null, Action? onOcr = null) =>
        ProductionMailboxRouteIssuerAuthoring.AuthorGenesisAsync(intent,
            RouteV2TestFixture.Now, authorNow, responder.PublicKey,
            RouteV2TestFixture.Now + 120,
            (request, destination, _) =>
            {
                onRda?.Invoke();
                return Sign(request.SigningBytes, destination, f.IssuerPrivateKey);
            },
            (request, destination, _) =>
            {
                onOcr?.Invoke();
                return Sign(request.SigningBytes, destination, f.IssuerPrivateKey);
            });

    private static ValueTask<int> Sign(ReadOnlyMemory<byte> bytes,
        Memory<byte> destination, byte[] privateKey)
    {
        PublicKeyAuth.SignDetached(bytes.ToArray(), privateKey).CopyTo(destination.Span);
        return ValueTask.FromResult(64);
    }
}
