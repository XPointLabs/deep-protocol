using System.Reflection;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class ProductionMailboxRouteIssuerAuthoringTests
{
    [Fact]
    public async Task AcceptDelegation_FreezesInputAndReturnsProductionVerifiedExactRda()
    {
        var f = RouteV2TestFixture.Create();
        var mutableDelegation = ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation);
        var calls = 0;
        var order = new List<string>();
        Memory<byte> retainedDestination = default;
        ProductionMailboxRda1SigningRequest? retainedRequest = null;
        ProductionMailboxRouteContinuityEnrollmentCommitPlan? retainedPlan = null;

        var enrollment = await ProductionMailboxRouteIssuerAuthoring.AcceptDelegationAsync(
            mutableDelegation, PreDelegationRolBytes(f), f.Authority, f.RevocationSnapshot,
            f.VerifiedCertificate,
            f.VerifiedPra, RouteV2TestFixture.Now, RouteV2TestFixture.Now, 0,
            (request, destination, _) =>
            {
                calls++;
                order.Add("signer");
                retainedDestination = destination;
                retainedRequest = request;
                mutableDelegation[0] ^= 0xff;
                var exposed = request.SigningBytes.ToArray();
                var signature = PublicKeyAuth.SignDetached(exposed, f.IssuerPrivateKey);
                exposed[0] ^= 0xff;
                signature.CopyTo(destination.Span);
                return ValueTask.FromResult(signature.Length);
            }, (plan, _) =>
            {
                order.Add("committer");
                retainedPlan = plan;
                Assert.All(retainedDestination.ToArray(), static value => Assert.Equal(0, value));
                Assert.NotNull(retainedRequest);
                Assert.All(retainedRequest.SigningBytes.ToArray(),
                    static value => Assert.Equal(0, value));
                return ValueTask.FromResult(true);
            });

        Assert.Equal(1, calls);
        Assert.Equal(["signer", "committer"], order);
        Assert.All(retainedDestination.ToArray(), static value => Assert.Equal(0, value));
        Assert.NotNull(retainedRequest);
        Assert.All(retainedRequest.SigningBytes.ToArray(), static value => Assert.Equal(0, value));
        Assert.Equal(
            ProductionMailboxRouteContinuityCodec.EncodeDelegationAcceptance(f.Acceptance),
            enrollment.Enrollment.CanonicalAcceptanceBytes.ToArray());
        Assert.Equal(ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(
                f.PreDelegationRouteOriginLkg),
            enrollment.PreDelegationRouteOriginLkgHash.ToArray());
        var enrolledRol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(
            enrollment.CanonicalEnrolledRouteOriginLkg.Span);
        Assert.Equal(enrollment.Enrollment.CanonicalDelegationHash.ToArray(),
            enrolledRol.CanonicalDelegationHash.ToArray());
        Assert.Equal(enrollment.Enrollment.CanonicalAcceptanceHash.ToArray(),
            enrolledRol.CanonicalDelegationAcceptanceHash.ToArray());
        Assert.Equal(f.PreDelegationRouteOriginLkg.LocalCommitGeneration + 1,
            enrolledRol.LocalCommitGeneration);
        Assert.NotNull(retainedPlan);
        Assert.Equal(PreDelegationRolBytes(f), retainedPlan.ExpectedOldRouteOriginLkg.ToArray());
        Assert.Equal(f.PreDelegationRouteOriginLkg.LocalCommitGeneration,
            retainedPlan.ExpectedOldLocalCommitGeneration);
        Assert.Equal(f.Delegation.DelegationSequence - 1,
            retainedPlan.ExpectedPreviousDelegationSequence);
        var exposedPlan = retainedPlan.CanonicalEnrolledRouteOriginLkg.ToArray();
        exposedPlan[0] ^= 0xff;
        Assert.NotEqual(exposedPlan, retainedPlan.CanonicalEnrolledRouteOriginLkg.ToArray());
        var exposedResult = enrollment.CanonicalEnrolledRouteOriginLkg.ToArray();
        exposedResult[0] ^= 0xff;
        Assert.NotEqual(exposedResult, enrollment.CanonicalEnrolledRouteOriginLkg.ToArray());
    }

    [Fact]
    public async Task AcceptDelegation_InvalidOwnerClosureDoesNotInvokeSigner()
    {
        var f = RouteV2TestFixture.Create();
        var invalid = ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation);
        invalid[^1] ^= 1;
        var calls = 0;

        await Assert.ThrowsAsync<ProductionMailboxRouteContinuityException>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AcceptDelegationAsync(
                invalid, PreDelegationRolBytes(f), f.Authority, f.RevocationSnapshot,
                f.VerifiedCertificate, f.VerifiedPra,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now, 0,
                (_, _, _) =>
                {
                    calls++;
                    return ValueTask.FromResult(64);
                }, Commit));

        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task AcceptDelegation_RejectsRolHashMismatchAndNonOwnerOnlyCasBeforeSigner()
    {
        var f = RouteV2TestFixture.Create();
        var calls = 0;
        var mismatchedRol = f.PreDelegationRouteOriginLkg with
        {
            LocalCommitGeneration = f.PreDelegationRouteOriginLkg.LocalCommitGeneration + 1
        };
        await Assert.ThrowsAsync<ProductionMailboxRouteContinuityException>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AcceptDelegationAsync(
                ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation),
                ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(mismatchedRol),
                f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now, 0,
                (_, _, _) => { calls++; return ValueTask.FromResult(64); }, Commit));
        Assert.Equal(0, calls);

        var occupiedRol = f.PreDelegationRouteOriginLkg with
        {
            CanonicalDelegationHash = RouteV2TestFixture.Bytes(250, 32),
            CanonicalDelegationAcceptanceHash = RouteV2TestFixture.Bytes(251, 32)
        };
        var rebound = SignDelegation(f.Delegation with
        {
            PreDelegationRouteOriginLkgHash = ProductionMailboxRouteContinuityCodec
                .ComputeRouteOriginLkgHash(occupiedRol)
        }, f.OwnerPrivateKey);
        await Assert.ThrowsAsync<ProductionMailboxRouteContinuityException>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AcceptDelegationAsync(
                ProductionMailboxRouteContinuityCodec.EncodeDelegation(rebound),
                ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(occupiedRol),
                f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now, 0,
                (_, _, _) => { calls++; return ValueTask.FromResult(64); }, Commit));
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task AcceptDelegation_ShortOrWrongKeySignatureCannotYieldCapability()
    {
        var f = RouteV2TestFixture.Create();
        var bytes = ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation);

        await Assert.ThrowsAsync<ProductionMailboxRouteContinuityException>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AcceptDelegationAsync(
                bytes, PreDelegationRolBytes(f), f.Authority, f.RevocationSnapshot,
                f.VerifiedCertificate, f.VerifiedPra,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now, 0,
                (_, destination, _) =>
                {
                    destination.Span.Fill(7);
                    return ValueTask.FromResult(63);
                }, Commit));

        var wrong = PublicKeyAuth.GenerateKeyPair(RouteV2TestFixture.Bytes(240, 32));
        await Assert.ThrowsAsync<ProductionMailboxRouteContinuityException>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AcceptDelegationAsync(
                bytes, PreDelegationRolBytes(f), f.Authority, f.RevocationSnapshot,
                f.VerifiedCertificate, f.VerifiedPra,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now, 0,
                (request, destination, _) =>
                {
                    var signature = PublicKeyAuth.SignDetached(
                        request.SigningBytes.ToArray(), wrong.PrivateKey);
                    signature.CopyTo(destination.Span);
                    return ValueTask.FromResult(signature.Length);
                }, Commit));
    }

    [Fact]
    public async Task AcceptDelegation_CommitRejectionOrStaleCasReturnsNoCapability()
    {
        var f = RouteV2TestFixture.Create();
        var signerCalls = 0;
        var commitCalls = 0;
        ProductionMailboxRouteContinuityEnrollmentCommitPlan? observed = null;

        await Assert.ThrowsAsync<ProductionMailboxRouteContinuityException>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AcceptDelegationAsync(
                ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation),
                PreDelegationRolBytes(f), f.Authority, f.RevocationSnapshot,
                f.VerifiedCertificate, f.VerifiedPra, RouteV2TestFixture.Now,
                RouteV2TestFixture.Now, 0,
                (request, destination, _) =>
                {
                    signerCalls++;
                    Sign(request.SigningBytes.Span, f.IssuerPrivateKey, destination);
                    return ValueTask.FromResult(64);
                },
                (plan, _) =>
                {
                    commitCalls++;
                    observed = plan;
                    var protectedGenerationAlreadyAdvanced =
                        f.PreDelegationRouteOriginLkg.LocalCommitGeneration + 1;
                    return ValueTask.FromResult(
                        plan.ExpectedOldLocalCommitGeneration == protectedGenerationAlreadyAdvanced);
                }));

        Assert.Equal(1, signerCalls);
        Assert.Equal(1, commitCalls);
        Assert.NotNull(observed);
        Assert.Equal(f.Delegation.PreviousCanonicalDelegationHash.ToArray(),
            observed.ExpectedPreviousDelegationHash.ToArray());

        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await AuthorFixtureEnrollment(f, static (_, _) =>
                ValueTask.FromException<bool>(new OperationCanceledException())));
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await AuthorFixtureEnrollment(f, static (_, _) =>
                ValueTask.FromException<bool>(new InvalidOperationException("commit failed"))));
    }

    [Fact]
    public async Task DelegatedActivation_AuthorsExactRchRtcRcaAndReturnsDefensiveCapability()
    {
        var f = RouteV2TestFixture.Create();
        var enrollment = await AuthorFixtureEnrollment(f);
        var intentClosure = DirectIntentClosure.Create(f);
        var intent = intentClosure.CreateIntent(f);
        var mutableSalt = f.Salt.ToArray();
        var rchCalls = 0;
        var rcaCalls = 0;
        Memory<byte> retainedRchDestination = default;
        Memory<byte> retainedRcaDestination = default;

        var result = await ProductionMailboxRouteIssuerAuthoring.AuthorDelegatedActivationAsync(
            enrollment, intent, f.Authority, f.RevocationSnapshot, f.VerifiedCertificate,
            f.VerifiedPra, mutableSalt, RouteV2TestFixture.Now - 1,
            RouteV2TestFixture.Now + 100,
            RouteV2TestFixture.Now, RouteV2TestFixture.Now + 90,
            RouteV2TestFixture.Now, RouteV2TestFixture.Now + 95,
            RouteV2TestFixture.Now, 0,
            (request, destination, _) =>
            {
                rchCalls++;
                retainedRchDestination = destination;
                mutableSalt[0] ^= 0xff;
                Sign(request.SigningBytes.Span, f.IssuerPrivateKey, destination);
                return ValueTask.FromResult(64);
            },
            (request, destination, _) =>
            {
                rcaCalls++;
                retainedRcaDestination = destination;
                Sign(request.SigningBytes.Span, f.IssuerPrivateKey, destination);
                return ValueTask.FromResult(64);
            });

        Assert.Equal(1, rchCalls);
        Assert.Equal(1, rcaCalls);
        Assert.All(retainedRchDestination.ToArray(), static value => Assert.Equal(0, value));
        Assert.All(retainedRcaDestination.ToArray(), static value => Assert.Equal(0, value));
        Assert.Equal(320, result.CanonicalCheckpointBytes.Length);
        Assert.Equal(408, result.CanonicalTransitionContextBytes.Length);
        Assert.Equal(496, result.CanonicalActivationBytes.Length);
        var rtc = ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(
            result.CanonicalTransitionContextBytes.Span);
        Assert.Equal(intent.OldCanonicalSelectionHash.ToArray(),
            rtc.OldCanonicalSelectionHash.ToArray());
        Assert.Equal(intent.CurrentCanonicalSelectionHash.ToArray(),
            rtc.NewCanonicalSelectionHash.ToArray());
        Assert.Equal(f.VerifiedPra.CanonicalHash.ToArray(),
            rtc.PredecessorCanonicalRouteAuthorizationHash.ToArray());
        var exposed = result.CanonicalActivationBytes.ToArray();
        exposed[^1] ^= 1;
        Assert.NotEqual(exposed, result.CanonicalActivationBytes.ToArray());
    }

    [Fact]
    public async Task DelegatedActivation_PreflightFailureInvokesNoSigner_AndBadRchStopsRca()
    {
        var f = RouteV2TestFixture.Create();
        var enrollment = await AuthorFixtureEnrollment(f);
        var intent = DirectIntentClosure.Create(f).CreateIntent(f);
        var rchCalls = 0;
        var rcaCalls = 0;

        await Assert.ThrowsAsync<ProductionMailboxRouteAuthorizationException>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AuthorDelegatedActivationAsync(
                enrollment, intent, f.Authority, f.RevocationSnapshot, f.VerifiedCertificate,
                f.VerifiedPra, new byte[31], RouteV2TestFixture.Now - 1,
                RouteV2TestFixture.Now + 100,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now + 90,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now + 95,
                RouteV2TestFixture.Now, 0,
                (_, _, _) => { rchCalls++; return ValueTask.FromResult(64); },
                (_, _, _) => { rcaCalls++; return ValueTask.FromResult(64); }));
        Assert.Equal(0, rchCalls);
        Assert.Equal(0, rcaCalls);

        await Assert.ThrowsAsync<ProductionMailboxRouteAuthorizationException>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AuthorDelegatedActivationAsync(
                enrollment, intent, f.Authority, f.RevocationSnapshot, f.VerifiedCertificate,
                f.VerifiedPra, f.Salt, RouteV2TestFixture.Now - 1,
                RouteV2TestFixture.Now + 100,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now + 101,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now + 95,
                RouteV2TestFixture.Now, 0,
                (_, _, _) => { rchCalls++; return ValueTask.FromResult(64); },
                (_, _, _) => { rcaCalls++; return ValueTask.FromResult(64); }));
        Assert.Equal(0, rchCalls);
        Assert.Equal(0, rcaCalls);

        await Assert.ThrowsAsync<ProductionMailboxRouteContinuityException>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AuthorDelegatedActivationAsync(
                enrollment, intent, f.Authority, f.RevocationSnapshot, f.VerifiedCertificate,
                f.VerifiedPra, f.Salt, RouteV2TestFixture.Now - 1,
                RouteV2TestFixture.Now + 100,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now + 90,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now + 95,
                RouteV2TestFixture.Now, 0,
                (_, destination, _) =>
                {
                    rchCalls++;
                    destination.Span.Fill(9);
                    return ValueTask.FromResult(64);
                },
                (_, _, _) => { rcaCalls++; return ValueTask.FromResult(64); }));
        Assert.Equal(1, rchCalls);
        Assert.Equal(0, rcaCalls);
    }

    [Fact]
    public async Task SelectionIntentRejectsCrossMode_AndUnrelatedIntentInvokesNoSigner()
    {
        var f = RouteV2TestFixture.Create();
        var closure = DirectIntentClosure.Create(f);
        Assert.Throws<ProductionMailboxSelectionSuccessorException>(() =>
            closure.CreateIntent(f, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint));

        var unrelated = RouteV2TestFixture.Create(1);
        var unrelatedIntent = DirectIntentClosure.Create(unrelated).CreateIntent(unrelated);
        var enrollment = await AuthorFixtureEnrollment(f);
        var rchCalls = 0;
        var rcaCalls = 0;
        await Assert.ThrowsAsync<ProductionMailboxRouteAuthorizationException>(async () =>
            await ProductionMailboxRouteIssuerAuthoring.AuthorDelegatedActivationAsync(
                enrollment, unrelatedIntent, f.Authority, f.RevocationSnapshot,
                f.VerifiedCertificate, f.VerifiedPra, f.Salt,
                RouteV2TestFixture.Now - 1, RouteV2TestFixture.Now + 100,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now + 90,
                RouteV2TestFixture.Now, RouteV2TestFixture.Now + 95,
                RouteV2TestFixture.Now, 0,
                (_, _, _) => { rchCalls++; return ValueTask.FromResult(64); },
                (_, _, _) => { rcaCalls++; return ValueTask.FromResult(64); }));
        Assert.Equal(0, rchCalls);
        Assert.Equal(0, rcaCalls);
    }

    [Fact]
    public void SelectionIntentRejectsExpiredOrUnsupportedCurrentClosure()
    {
        var f = RouteV2TestFixture.Create();
        var closure = DirectIntentClosure.Create(f);
        var expiredSelection = new VerifiedProductionMailboxSelection(
            closure.CurrentSelection.Proof with
            {
                ExpiresAtUnixSeconds = RouteV2TestFixture.Now - 1
            }, closure.CurrentSelection.Replicas,
            closure.CurrentSelection.CanonicalSelectionHash.Span);
        Assert.Throws<ProductionMailboxSelectionSuccessorException>(() =>
            closure.CreateIntent(f, currentSelection: expiredSelection));

        var unsupportedSelection = new VerifiedProductionMailboxSelection(
            closure.CurrentSelection.Proof with
            {
                Algorithm = (ProductionMailboxSelectionAlgorithm)3
            }, closure.CurrentSelection.Replicas,
            closure.CurrentSelection.CanonicalSelectionHash.Span);
        Assert.Throws<ProductionMailboxSelectionSuccessorException>(() =>
            closure.CreateIntent(f, currentSelection: unsupportedSelection));

        var zeroHashSelection = new VerifiedProductionMailboxSelection(
            closure.CurrentSelection.Proof, closure.CurrentSelection.Replicas, new byte[32]);
        Assert.Throws<ProductionMailboxSelectionSuccessorException>(() =>
            closure.CreateIntent(f, currentSelection: zeroHashSelection));

        var expiredCertificate = new VerifiedProductionMailboxRouteCertificate(
            f.VerifiedCertificate.Certificate with
            {
                ExpiresAtUnixSeconds = RouteV2TestFixture.Now - 1
            }, f.VerifiedCertificate.CanonicalCertificateHash.Span);
        Assert.Throws<ProductionMailboxSelectionSuccessorException>(() =>
            closure.CreateIntent(f, routeCertificate: expiredCertificate));
    }

    [Fact]
    public void PublicSurfaceIsCapabilityScopedAndDoesNotExposeGenericSigning()
    {
        Assert.Empty(typeof(ProductionMailboxRda1SigningRequest).GetConstructors());
        Assert.Empty(typeof(ProductionMailboxRch1SigningRequest).GetConstructors());
        Assert.Empty(typeof(ProductionMailboxRca1SigningRequest).GetConstructors());
        Assert.Empty(typeof(ProductionMailboxRouteContinuityEnrollmentCommitPlan).GetConstructors());
        Assert.Empty(typeof(VerifiedProductionMailboxRouteContinuityEnrollmentState).GetConstructors());
        Assert.Empty(typeof(VerifiedProductionMailboxSelectionTransitionIntent).GetConstructors());
        Assert.Empty(typeof(VerifiedProductionMailboxDelegatedRouteAuthorization).GetConstructors());
        Assert.False(typeof(ProductionMailboxRouteContinuityEnrollmentCommitPlan).IsPublic);
        Assert.False(typeof(VerifiedProductionMailboxRouteContinuityEnrollmentState).IsPublic);
        Assert.Empty(typeof(VerifiedProductionMailboxRouteContinuityGenesisIntent)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(ProductionMailboxRouteContinuityGenesisCommitPlan)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.NotEqual(typeof(ProductionMailboxRda1Signer), typeof(ProductionMailboxRch1Signer));
        Assert.NotEqual(typeof(ProductionMailboxRch1Signer), typeof(ProductionMailboxRca1Signer));
        Assert.DoesNotContain(typeof(ProductionMailboxRouteIssuerAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static), static method =>
            method.Name.Contains("SigningBytes", StringComparison.Ordinal) ||
            method.GetParameters().Any(parameter =>
                typeof(IProductionMailboxRouteSignatureVerifier)
                    .IsAssignableFrom(parameter.ParameterType)));
        Assert.DoesNotContain(typeof(ProductionMailboxRouteIssuerAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static), static method =>
            method.Name is "AcceptDelegationAsync" or
                "AuthorOwnerControlResponderCertificateAsync" or "CreateHistoricalAnchor");
    }

    private static ValueTask<VerifiedProductionMailboxRouteContinuityEnrollmentState>
        AuthorFixtureEnrollment(RouteV2TestFixture f) =>
        AuthorFixtureEnrollment(f, Commit);

    private static ValueTask<VerifiedProductionMailboxRouteContinuityEnrollmentState>
        AuthorFixtureEnrollment(
            RouteV2TestFixture f,
            ProductionMailboxRouteContinuityEnrollmentCommitter committer) =>
        ProductionMailboxRouteIssuerAuthoring.AcceptDelegationAsync(
            ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation),
            PreDelegationRolBytes(f), f.Authority, f.RevocationSnapshot,
            f.VerifiedCertificate, f.VerifiedPra, RouteV2TestFixture.Now,
            RouteV2TestFixture.Now, 0,
            (request, destination, _) =>
            {
                Sign(request.SigningBytes.Span, f.IssuerPrivateKey, destination);
                return ValueTask.FromResult(64);
            }, committer);

    private static byte[] PreDelegationRolBytes(RouteV2TestFixture f) =>
        ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(
            f.PreDelegationRouteOriginLkg);

    private static ValueTask<bool> Commit(
        ProductionMailboxRouteContinuityEnrollmentCommitPlan _,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(true);
    }

    private sealed record DirectIntentClosure(
        VerifiedProductionMailboxAuthority OldAuthority,
        VerifiedProductionMailboxTopology OldTopology,
        VerifiedProductionMailboxSelection OldSelection,
        VerifiedProductionMailboxTopology CurrentTopology,
        VerifiedProductionMailboxSelection CurrentSelection)
    {
        internal VerifiedProductionMailboxSelectionTransitionIntent CreateIntent(
            RouteV2TestFixture f,
            ProductionMailboxSelectionSuccessorMode mode =
                ProductionMailboxSelectionSuccessorMode.DirectPromotion,
            VerifiedProductionMailboxSelection? currentSelection = null,
            VerifiedProductionMailboxRouteCertificate? routeCertificate = null) =>
            ProductionMailboxRouteIssuerAuthoring.CreateSelectionTransitionIntent(
                mode, OldAuthority, OldTopology, OldSelection, f.Authority,
                f.RevocationSnapshot, CurrentTopology, currentSelection ?? CurrentSelection,
                routeCertificate ?? f.VerifiedCertificate, RouteV2TestFixture.Now, 0);

        internal static DirectIntentClosure Create(RouteV2TestFixture f)
        {
            var currentAuthority = f.Authority.Authority;
            var oldAuthority = f.PreviousAuthority;
            var oldAuthorityValue = oldAuthority.Authority;
            var oldAuthorityHash = oldAuthority.CanonicalAuthorityHash.ToArray();

            var nodes = new[]
            {
                Node(210, "https://one.example.net/"),
                Node(220, "https://two.example.net/")
            };
            var oldTopologyHash = RouteV2TestFixture.Bytes(230, 32);
            var oldTopologyValue = new ProductionMailboxTopologySnapshot
            {
                NetworkId = f.NetworkId,
                AuthorityGeneration = oldAuthorityValue.AuthorityGeneration,
                CanonicalAuthorityHash = oldAuthorityHash,
                TopologyGeneration = 10,
                PreviousTopologyHash = RouteV2TestFixture.Bytes(229, 32),
                IssuedAtUnixSeconds = RouteV2TestFixture.Now - 20,
                ExpiresAtUnixSeconds = RouteV2TestFixture.Now + 300,
                CurrentEpoch = TopologyEpoch(oldAuthorityValue.CurrentEpoch, nodes),
                NextEpoch = TopologyEpoch(oldAuthorityValue.NextEpoch, nodes),
                IssuerSignature = RouteV2TestFixture.Bytes(231, 64)
            };
            var oldTopology = new VerifiedProductionMailboxTopology(
                oldTopologyValue, oldTopologyHash);
            var currentTopologyHash = RouteV2TestFixture.Bytes(232, 32);
            var currentTopologyValue = new ProductionMailboxTopologySnapshot
            {
                NetworkId = f.NetworkId,
                AuthorityGeneration = currentAuthority.AuthorityGeneration,
                CanonicalAuthorityHash = f.Authority.CanonicalAuthorityHash,
                TopologyGeneration = 11,
                PreviousTopologyHash = oldTopologyHash,
                IssuedAtUnixSeconds = RouteV2TestFixture.Now - 10,
                ExpiresAtUnixSeconds = RouteV2TestFixture.Now + 300,
                CurrentEpoch = TopologyEpoch(currentAuthority.CurrentEpoch, nodes),
                NextEpoch = TopologyEpoch(currentAuthority.NextEpoch, nodes),
                IssuerSignature = RouteV2TestFixture.Bytes(233, 64)
            };
            var currentTopology = new VerifiedProductionMailboxTopology(
                currentTopologyValue, currentTopologyHash);
            var replicas = new[]
            {
                Replica(nodes[0], 240),
                Replica(nodes[1], 241)
            };
            var oldSelection = Selection(f, oldAuthorityValue, oldAuthorityHash,
                oldTopologyValue, oldTopologyHash, oldTopologyValue.NextEpoch, replicas, 170);
            var currentSelection = Selection(f, currentAuthority,
                f.Authority.CanonicalAuthorityHash.Span, currentTopologyValue,
                currentTopologyHash, currentTopologyValue.CurrentEpoch, replicas, 171);
            return new DirectIntentClosure(oldAuthority, oldTopology, oldSelection,
                currentTopology, currentSelection);
        }

        private static VerifiedProductionMailboxSelection Selection(
            RouteV2TestFixture f,
            ProductionMailboxAuthority authority,
            ReadOnlySpan<byte> authorityHash,
            ProductionMailboxTopologySnapshot topology,
            ReadOnlySpan<byte> topologyHash,
            ProductionMailboxTopologyEpoch epoch,
            IReadOnlyList<VerifiedProductionMailboxSelectedReplica> replicas,
            byte hashSeed)
        {
            var proofReplicas = replicas.Select(replica => new ProductionMailboxSelectionReplica
            {
                ReplicaId = replica.ReplicaId.ToArray(),
                CanonicalMIP1Proof = replica.CanonicalMIP1Proof.ToArray()
            }).ToArray();
            var proof = new ProductionMailboxSelectionProof
            {
                Algorithm = ProductionMailboxSelectionAlgorithm.RendezvousSha256V2,
                NetworkId = f.NetworkId,
                AuthorityGeneration = authority.AuthorityGeneration,
                CanonicalAuthorityHash = authorityHash.ToArray(),
                TopologyGeneration = topology.TopologyGeneration,
                CanonicalTopologyHash = topologyHash.ToArray(),
                Epoch = epoch.Epoch,
                Generation = epoch.Generation,
                MembershipCommitment = epoch.MembershipCommitment.ToArray(),
                TopologyPlacementCommitment = epoch.TopologyPlacementCommitment.ToArray(),
                MailboxPlacementCommitment = RouteV2TestFixture.Bytes(204, 32),
                SelectionInputCommitment =
                    f.VerifiedCertificate.Certificate.SelectionInputCommitment,
                IssuedAtUnixSeconds = RouteV2TestFixture.Now - 1,
                ExpiresAtUnixSeconds = RouteV2TestFixture.Now + 100,
                Replicas = proofReplicas,
                IssuerSignature = RouteV2TestFixture.Bytes(242, 64)
            };
            return new VerifiedProductionMailboxSelection(
                proof, replicas, RouteV2TestFixture.Bytes(hashSeed, 32));
        }

        private static ProductionMailboxTopologyNode Node(byte seed, string endpoint) => new()
        {
            NodeId = RouteV2TestFixture.Bytes(seed, 32),
            HttpsEndpoint = endpoint,
            CurrentSpkiSha256 = RouteV2TestFixture.Bytes((byte)(seed + 1), 32),
            NextSpkiSha256 = RouteV2TestFixture.Bytes((byte)(seed + 2), 32)
        };

        private static ProductionMailboxTopologyEpoch TopologyEpoch(
            ProductionMailboxAuthorityEpoch epoch,
            IReadOnlyList<ProductionMailboxTopologyNode> nodes) => new()
        {
            Epoch = epoch.Epoch,
            Generation = epoch.Generation,
            MembershipCommitment = epoch.MembershipCommitment.ToArray(),
            TopologyPlacementCommitment = epoch.TopologyPlacementCommitment.ToArray(),
            NotBeforeUnixSeconds = epoch.NotBeforeUnixSeconds,
            NotAfterUnixSeconds = epoch.NotAfterUnixSeconds,
            Nodes = nodes
        };

        private static VerifiedProductionMailboxSelectedReplica Replica(
            ProductionMailboxTopologyNode node,
            byte proofSeed) => new()
        {
            ReplicaId = node.NodeId.ToArray(),
            CanonicalMIP1Proof = RouteV2TestFixture.Bytes(proofSeed, 64),
            HttpsEndpoint = new Uri(node.HttpsEndpoint),
            CurrentSpkiSha256 = node.CurrentSpkiSha256.ToArray(),
            NextSpkiSha256 = node.NextSpkiSha256.ToArray()
        };
    }

    private static void Sign(ReadOnlySpan<byte> signingBytes, byte[] privateKey, Memory<byte> destination)
    {
        var signature = PublicKeyAuth.SignDetached(signingBytes.ToArray(), privateKey);
        signature.CopyTo(destination.Span);
    }

    private static ProductionMailboxRouteContinuityDelegation SignDelegation(
        ProductionMailboxRouteContinuityDelegation value,
        byte[] privateKey)
    {
        var unsigned = value with { OwnerSignature = new byte[64] };
        return unsigned with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteContinuityCodec.GetDelegationSigningBytes(unsigned),
                privateKey)
        };
    }
}
