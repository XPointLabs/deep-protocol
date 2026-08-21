using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class DeploymentGovernanceOriginTests
{
    [Fact]
    public async Task SameAccount_PreservesResetAndCommitsExactPredecessorWithoutReservation()
    {
        var fixture = Fixture.Create();
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var account = PublicKeyAuth.GenerateKeyPair(); var reset = PublicKeyAuth.GenerateKeyPair();
        var accountHash = Fill(0xa1, 32);
        var identity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1),
            account.PublicKey, reset.PublicKey, 1, accountHash);
        var priorDcm = SignedDcm(identity, governance, account.PrivateKey, reset.PrivateKey,
            Fill(0xa2, 32), Fill(0xa3, 32));
        var current = Current(identity, priorDcm);
        var branch = RecoveryVerifier.CreateSameAccountCutoverBranch(governance, identity, current);
        var operationProvider = new SameOperationProvider();
        var signer = new OriginSigner(account.PrivateKey, reset.PrivateKey);
        var signed = await RecoveryVerifier.AuthorSameAccountCutoverManifestAsync(branch,
            operationProvider, new DcmProvider(fixture.Hmac),
            signer, fixture.Hmac, 101);
        var dcm = signed.Manifest.Record;

        Assert.Equal((byte)2, signed.SignedAuthoringReceipt.Span[8]);
        Assert.Equal(CutoverCodec.DecodeManifest(priorDcm).ResetId.ToArray(),
            dcm.FieldSpan(2).ToArray());
        Assert.Equal((ulong)2, Scalars.UInt64(dcm.FieldSpan(3)));
        Assert.Equal(current.TrustedDcmRef.ToArray(), dcm.FieldSpan(13).ToArray());
        Assert.Equal(
            [GenesisOriginSignerRole.ResetControl, GenesisOriginSignerRole.AccountPossession],
            signer.Roles);
        Assert.Equal(3, operationProvider.Calls);

        var components = new ComponentDistributor();
        var distributed = await RecoveryVerifier.DistributeSameAccountAsync(signed,
            operationProvider, new DistributionProvider(fixture.Hmac, accountHash),
            components, fixture.Hmac, 101);
        Assert.Equal((byte)2, distributed.DistributedReceipt.Span[8]);
        Assert.Equal(current.TrustedDcmRef.ToArray(),
            distributed.DistributedReceipt.Span.Slice(191, 38).ToArray());
        Assert.Equal(4, components.Deliveries);
    }

    [Fact]
    public async Task SameAccount_BypassesResetReservationAndFreezesExactDualSignedSuccessor()
    {
        var fixture = Fixture.Create();
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var account = PublicKeyAuth.GenerateKeyPair();
        var reset = PublicKeyAuth.GenerateKeyPair();
        var accountHash = Fill(0xa1, 32);
        var identity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1),
            account.PublicKey, reset.PublicKey, 1, accountHash);
        var priorDcm = SignedDcm(identity, governance, account.PrivateKey, reset.PrivateKey,
            Fill(0xa2, 32), Fill(0xa3, 32));
        var prior = CutoverCodec.DecodeManifest(priorDcm);
        var current = Current(identity, priorDcm);
        var branch = RecoveryVerifier.CreateSameAccountCutoverBranch(
            governance, identity, current);
        var operationProvider = new SameOperationProvider();
        var signer = new OriginSigner(account.PrivateKey, reset.PrivateKey);

        var signed = await RecoveryVerifier.AuthorSameAccountCutoverManifestAsync(
            branch, operationProvider, new DcmProvider(fixture.Hmac),
            signer, fixture.Hmac, 101);
        var dcm = signed.Manifest.Record;

        Assert.Equal(
            [GenesisOriginSignerRole.ResetControl, GenesisOriginSignerRole.AccountPossession],
            signer.Roles);
        Assert.Equal(2, signer.Requests.Count);
        Assert.Equal(signer.Requests[0].SigningBytes.ToArray(),
            signer.Requests[1].SigningBytes.ToArray());
        Assert.Equal(prior.ResetId.ToArray(), dcm.FieldSpan(2).ToArray());
        Assert.Equal(prior.ResetGeneration + 1, Scalars.UInt64(dcm.FieldSpan(3)));
        Assert.Equal(prior.AccountGeneration, Scalars.UInt64(dcm.FieldSpan(4)));
        Assert.Equal(current.TrustedDcmRef.ToArray(), dcm.FieldSpan(13).ToArray());
        Assert.Equal((byte)2, signed.SignedAuthoringReceipt.Span[8]);
        Assert.True(signed.NoAuthorityClaim);
        Assert.DoesNotContain(
            typeof(RecoveryVerifier).GetMethods(BindingFlags.Public | BindingFlags.Static)
                .Where(static method => method.Name ==
                    nameof(RecoveryVerifier.AuthorSameAccountCutoverManifestAsync))
                .SelectMany(static method => method.GetParameters()),
            static parameter => parameter.ParameterType ==
                typeof(GenesisResetReservationProvider));
    }

    [Fact]
    public async Task AccountReset_AuthorsGarDcmDraAndDistributesExactPair()
    {
        var fixture = Fixture.Create();
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var oldAccount = PublicKeyAuth.GenerateKeyPair();
        var oldReset = PublicKeyAuth.GenerateKeyPair();
        var newAccount = PublicKeyAuth.GenerateKeyPair();
        var newReset = PublicKeyAuth.GenerateKeyPair();
        var oldHash = Fill(0x91, 32); var newHash = Fill(0x92, 32);
        var oldIdentity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1),
            oldAccount.PublicKey, oldReset.PublicKey, 1, oldHash, terminal: true);
        var oldDcm = SignedDcm(oldIdentity, governance, oldAccount.PrivateKey,
            oldReset.PrivateKey, Fill(0x93, 32), Fill(0x94, 32));
        var verifiedOld = RecoveryVerifier.VerifyAccountResetOldCutover(oldIdentity, oldDcm);
        var newIdentity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1),
            newAccount.PublicKey, newReset.PublicKey, 2, newHash);
        var garProvider = new GarProvider(fixture.Hmac);
        var origin = await RecoveryVerifier.RestoreOrCreateAccountResetOriginAsync(
            verifiedOld, newIdentity, governance, 99, ResetReason.KeyCompromise,
            garProvider, fixture.Hmac, 100);
        var branch = RecoveryVerifier.CreateAccountResetCutoverBranch(origin);
        var reservationProvider = new ScopedReservationProvider(fixture.Hmac);
        var reservation = await RecoveryVerifier.RestoreOrReserveGenesisResetIdByScopeAsync(
            branch, reservationProvider, fixture.Hmac);
        var signedDcm = await RecoveryVerifier.AuthorCutoverManifestAsync(branch, reservation,
            reservationProvider, new DcmProvider(fixture.Hmac), new OriginSigner(newAccount.PrivateKey,
                newReset.PrivateKey), fixture.Hmac, 101);
        var resetSigner = new ResetSigner(oldReset.PrivateKey, newAccount.PrivateKey,
            newReset.PrivateKey);
        var signedReset = await RecoveryVerifier.AuthorAccountResetAsync(signedDcm,
            garProvider, new GraProvider(fixture.Hmac), resetSigner, fixture.Hmac, 101);

        Assert.Equal(1, garProvider.Mutations);
        Assert.Equal(3, garProvider.Reads);
        Assert.Equal(65, branch.ExactTranscript.Length);
        Assert.Equal((byte)3, signedDcm.SignedAuthoringReceipt.Span[8]);
        Assert.Equal(origin.OperationId.ToArray(),
            signedDcm.SignedAuthoringReceipt.Span.Slice(917, 32).ToArray());
        Assert.Equal(
            [GenesisOriginSignerRole.OldResetControl,
             GenesisOriginSignerRole.AccountPossession,
             GenesisOriginSignerRole.ResetControl], resetSigner.Roles);
        Assert.Equal(788, signedReset.Authorization.CanonicalBytes.Length);
        Assert.Equal((byte)2, signedReset.SignedResetAuthoringReceipt.Span[914]);

        var components = new ComponentDistributor(expectDra: true);
        var distributed = await RecoveryVerifier.DistributeAccountResetAsync(signedReset,
            reservationProvider, garProvider, new DistributionProvider(fixture.Hmac, newHash), components,
            fixture.Hmac, 101);
        Assert.Equal(4, components.Deliveries);
        Assert.Equal(4, components.Rereads);
        Assert.Equal((byte)3, distributed.DistributedReceipt.Span[8]);
        Assert.Equal((byte)0x0f, distributed.DistributedReceipt.Span[300]);
        Assert.NotEqual(new byte[38], distributed.DistributedReceipt.Span.Slice(229, 38).ToArray());
    }

    [Fact]
    public async Task AccountReset_GarAtomicallyRetainsEvidenceAndMintsExactPostHmacReceipt()
    {
        var fixture = Fixture.Create();
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var oldAccount = PublicKeyAuth.GenerateKeyPair();
        var oldReset = PublicKeyAuth.GenerateKeyPair();
        var newAccount = PublicKeyAuth.GenerateKeyPair();
        var newReset = PublicKeyAuth.GenerateKeyPair();
        var oldIdentity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1),
            oldAccount.PublicKey, oldReset.PublicKey, 1, Fill(0x91, 32), terminal: true);
        var oldDcm = SignedDcm(oldIdentity, governance, oldAccount.PrivateKey,
            oldReset.PrivateKey, Fill(0x93, 32), Fill(0x94, 32));
        var verifiedOld = RecoveryVerifier.VerifyAccountResetOldCutover(oldIdentity, oldDcm);
        var newIdentity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1),
            newAccount.PublicKey, newReset.PublicKey, 2, Fill(0x92, 32));
        var provider = new GarProvider(fixture.Hmac);

        var origin = await RecoveryVerifier.RestoreOrCreateAccountResetOriginAsync(
            verifiedOld, newIdentity, governance, 99, ResetReason.KeyCompromise,
            provider, fixture.Hmac, 100);
        var gar = provider.Canonical;

        Assert.Equal(1, provider.Mutations);
        Assert.Equal(1, provider.Reads);
        Assert.NotNull(provider.LastRequest);
        Assert.True(provider.LastRequest!.NoAuthorityClaim);
        Assert.NotEmpty(provider.LastRequest.RetainedEvidence);
        Assert.All(provider.LastRequest.RetainedEvidence,
            static evidence => Assert.NotEmpty(evidence.ToArray()));
        Assert.Equal(DeploymentGovernanceRecords.GarLength, gar.Length);
        Assert.Equal("GAR1"u8.ToArray(), gar.AsSpan(0, 4).ToArray());
        Assert.Equal((byte)1, gar[4]);
        Assert.Equal(new byte[3], gar.AsSpan(5, 3).ToArray());
        Assert.Equal(origin.ExactTranscript.ToArray(), gar.AsSpan(8, 588).ToArray());
        Assert.Equal(origin.OriginHash.ToArray(), gar.AsSpan(596, 32).ToArray());
        Assert.Equal((byte)1, gar[676]);
        Assert.Equal((byte)0, gar[677]);
        Assert.Equal(fixture.Hmac.Tag(gar.AsSpan(0, 710)), gar.AsSpan(710, 32).ToArray());
        Assert.Equal(DeploymentGovernanceRecords.GarReceiptHash(gar),
            origin.GarReceiptHash.ToArray());
        Assert.True(origin.NoAuthorityClaim);

        foreach (var mutate in new Action<byte[]>[]
                 {
                     value => value[0] ^= 1,
                     value => value[4] = 2,
                     value => value[5] = 1,
                     value => value[8] ^= 1,
                     value => value[676] = 0,
                     value => value[677] = 1
                 })
        {
            var malformed = gar.ToArray();
            mutate(malformed);
            Assert.Throws<RecordException>(() =>
                DeploymentGovernanceRecords.PreflightGar(malformed, 100));
        }
    }

    [Fact]
    public async Task FirstDeploymentDcmAuthoring_PersistsPreparedBeforeTwoSignersAndOneSignedCas()
    {
        var fixture = Fixture.Create();
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var account = PublicKeyAuth.GenerateKeyPair();
        var reset = PublicKeyAuth.GenerateKeyPair();
        var identity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1),
            account.PublicKey, reset.PublicKey);
        var branch = RecoveryVerifier.CreateFirstDeploymentCutoverBranch(governance, identity);
        var reservationProvider = new ScopedReservationProvider(fixture.Hmac);
        var reservation = await RecoveryVerifier.RestoreOrReserveGenesisResetIdByScopeAsync(
            branch, reservationProvider, fixture.Hmac);
        var authoring = new DcmProvider(fixture.Hmac);
        var signer = new OriginSigner(account.PrivateKey, reset.PrivateKey);

        var plan = await RecoveryVerifier.AuthorCutoverManifestAsync(branch, reservation,
            reservationProvider, authoring, signer, fixture.Hmac, 101);

        Assert.True(plan.NoAuthorityClaim);
        Assert.Equal(1, authoring.PreparedCalls);
        Assert.Equal(1, authoring.SignedCalls);
        Assert.Equal(
            [GenesisOriginSignerRole.ResetControl, GenesisOriginSignerRole.AccountPossession],
            signer.Roles);
        Assert.Equal(812, plan.Manifest.CanonicalBytes.Length);
        Assert.Equal(1031, plan.SignedAuthoringReceipt.Length);
        DeploymentGovernanceRecords.PreflightGdi(plan.SignedAuthoringReceipt.Span, 101);
        Assert.Equal((byte)2, plan.SignedAuthoringReceipt.Span[965]);

        var replaySigner = new OriginSigner(account.PrivateKey, reset.PrivateKey);
        var replay = await RecoveryVerifier.AuthorCutoverManifestAsync(branch, reservation,
            reservationProvider, new SignedReplayDcmProvider(plan.SignedAuthoringReceipt.ToArray()), replaySigner,
            fixture.Hmac, 101);
        Assert.Empty(replaySigner.Roles);
        Assert.Equal(plan.Manifest.CanonicalBytes.ToArray(), replay.Manifest.CanonicalBytes.ToArray());

        var distributionProvider = new DistributionProvider(fixture.Hmac);
        var components = new ComponentDistributor();
        var distributed = await RecoveryVerifier.DistributeCutoverManifestAsync(plan,
            reservationProvider, distributionProvider, components, fixture.Hmac, 101);
        Assert.True(distributed.NoAuthorityClaim);
        Assert.Equal(4, components.Deliveries);
        Assert.Equal(4, components.Rereads);
        Assert.Equal((byte)2, distributed.DistributedReceipt.Span[381]);
        Assert.Equal((byte)0x0f, distributed.DistributedReceipt.Span[300]);
        var replayComponents = new ComponentDistributor();
        var replayDistribution = await RecoveryVerifier.DistributeCutoverManifestAsync(plan,
            reservationProvider, new DistributedReplayProvider(distributed.DistributedReceipt.ToArray()),
            replayComponents, fixture.Hmac, 101);
        Assert.Equal(0, replayComponents.Deliveries);
        Assert.Equal(0, replayComponents.Rereads);
        Assert.Equal(distributed.DistributedReceipt.ToArray(),
            replayDistribution.DistributedReceipt.ToArray());
    }

    [Fact]
    public Task FirstDeployment_PublicPath_ReachesLocalCommittedThroughExactThreeWitnesses() =>
        RunFirstDeploymentToCommitAsync();

    [Fact]
    public Task FirstDeployment_ProcessLossReplay_RestoresPreJournalAndContinuesEveryPhase() =>
        RunFirstDeploymentToCommitAsync(exerciseReplayMatrix: true);

    [Fact]
    public Task FirstDeployment_PublicColdOpen_RestoresAndMaterializesCandidateDpl() =>
        RunFirstDeploymentToCommitAsync(exerciseColdOpen: true);

    [Fact]
    public Task FirstDeployment_PublicColdOpen_KeyMovementOnFinalRereadRejects() =>
        RunFirstDeploymentToCommitAsync(
            exerciseColdOpen: true,
            expectColdRegistryFailure: true);

    [Fact]
    public Task FirstDeployment_LocalCommittedBecomesFreshNormalCurrentCutover() =>
        RunFirstDeploymentToCommitAsync(exerciseFreshNormalRestore: true);

    [Fact]
    public Task FirstDeployment_DplMaterializationUsesOnlySealedRoleOneKey() =>
        RunFirstDeploymentToCommitAsync(verifyDedicatedDplKey: true);

    [Fact]
    public async Task FirstDeployment_GenesisDtcUsesExactZeroPredecessorBranch()
    {
        var fixture = Fixture.Create();
        var network = fixture.ReleaseRoot.Manifest.Record.FieldSpan(1).ToArray();
        var facts = await MembershipClosureIntegrationTests
            .CreateGenesisRoutingFactsAsync(network);
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var branch = RecoveryVerifier.CreateFirstDeploymentCutoverBranch(
            governance, facts.Identity);
        var reservationProvider = new ScopedReservationProvider(fixture.Hmac);
        var reservation = await RecoveryVerifier.RestoreOrReserveGenesisResetIdByScopeAsync(
            branch, reservationProvider, fixture.Hmac);
        var signed = await RecoveryVerifier.AuthorCutoverManifestAsync(
            branch, reservation, reservationProvider, new DcmProvider(fixture.Hmac),
            new OriginSigner(facts.AccountSigner.PrivateKey, facts.ResetSigner.PrivateKey),
            fixture.Hmac, 101);
        var distributed = await RecoveryVerifier.DistributeCutoverManifestAsync(
            signed, reservationProvider, new DistributionProvider(fixture.Hmac),
            new ComponentDistributor(), fixture.Hmac, 101);
        var baseIdentity = RecoveryVerifier.CreateGenesisBaseIdentityContext(
            facts.Identity, facts.Device, facts.Mailbox, facts.Router, distributed);
        var protectedKeyId = Fill(0xd3, 32);
        var witnesses = new List<KeyPair>();
        var verifiedHead = await IdentityAuthorityTests.VerifyGenesisReleaseHeadForEvidenceAsync(
            baseIdentity, fixture.ReleaseRoot, fixture.ReleaseRootSigner,
            protectedKeyId, fixture.Hmac, witnesses);
        var release = RecoveryVerifier.CreateGenesisReleaseContext(baseIdentity, verifiedHead);
        var scope = RecoveryVerifier.CreateGenesisTransactionScopeContext(
            baseIdentity, release, reservation, ComponentKind.Registry);
        var transaction = await RecoveryVerifier.RestoreOrReserveGenesisTransactionAsync(
            scope, new TransactionProvider(fixture.Hmac, protectedKeyId), fixture.Hmac);

        var identity = await RecoveryVerifier.AuthorGenesisIdentityContextAsync(
            scope, transaction, fixture.Hmac);
        var dtc = identity.DrtCatalog;

        Assert.Equal(234, dtc.Length);
        Assert.Equal("DTC2"u8.ToArray(), dtc[..4].ToArray());
        Assert.Equal((byte)2, dtc[4]);
        Assert.True(CanonicalGrammar.IsZero(dtc.Slice(64, 38)));
        Assert.True(CanonicalGrammar.IsZero(dtc.Slice(102, 32)));
        Assert.Equal(transaction.TransactionId.ToArray(), dtc.Slice(134, 32).ToArray());
        Assert.Equal(new byte[4], dtc.Slice(166, 4).ToArray());
        Assert.Equal(protectedKeyId, dtc.Slice(170, 32).ToArray());
        Assert.Equal(
            RecoveryContextFingerprint.GenesisIdentity(
                baseIdentity.Identity, baseIdentity.Device, baseIdentity.Mailbox,
                baseIdentity.Router, baseIdentity.Manifest, dtc),
            identity.Fingerprint.ToArray());
        Assert.True(identity.NoAuthorityClaim);
    }

    [Fact]
    public async Task FirstDeployment_GenesisIdentityContextBindsCurrentProtectedStoreAndExactDtcCatalog()
    {
        var fixture = Fixture.Create();
        var network = fixture.ReleaseRoot.Manifest.Record.FieldSpan(1).ToArray();
        var facts = await MembershipClosureIntegrationTests
            .CreateGenesisRoutingFactsAsync(network);
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var branch = RecoveryVerifier.CreateFirstDeploymentCutoverBranch(
            governance, facts.Identity);
        var reservationProvider = new ScopedReservationProvider(fixture.Hmac);
        var reservation = await RecoveryVerifier.RestoreOrReserveGenesisResetIdByScopeAsync(
            branch, reservationProvider, fixture.Hmac);
        var signed = await RecoveryVerifier.AuthorCutoverManifestAsync(
            branch, reservation, reservationProvider, new DcmProvider(fixture.Hmac),
            new OriginSigner(facts.AccountSigner.PrivateKey, facts.ResetSigner.PrivateKey),
            fixture.Hmac, 101);
        var distributed = await RecoveryVerifier.DistributeCutoverManifestAsync(
            signed, reservationProvider, new DistributionProvider(fixture.Hmac),
            new ComponentDistributor(), fixture.Hmac, 101);
        var baseIdentity = RecoveryVerifier.CreateGenesisBaseIdentityContext(
            facts.Identity, facts.Device, facts.Mailbox, facts.Router, distributed);
        var protectedKeyId = Fill(0xd3, 32);
        var witnesses = new List<KeyPair>();
        var verifiedHead = await IdentityAuthorityTests.VerifyGenesisReleaseHeadForEvidenceAsync(
            baseIdentity, fixture.ReleaseRoot, fixture.ReleaseRootSigner,
            protectedKeyId, fixture.Hmac, witnesses);
        var release = RecoveryVerifier.CreateGenesisReleaseContext(baseIdentity, verifiedHead);
        var scope = RecoveryVerifier.CreateGenesisTransactionScopeContext(
            baseIdentity, release, reservation, ComponentKind.Registry);
        var transaction = await RecoveryVerifier.RestoreOrReserveGenesisTransactionAsync(
            scope, new TransactionProvider(fixture.Hmac, protectedKeyId), fixture.Hmac);

        var identity = await RecoveryVerifier.AuthorGenesisIdentityContextAsync(
            scope, transaction, fixture.Hmac);
        var dtc = identity.DrtCatalog.ToArray();
        var recoveryTypes = baseIdentity.RecoveryRows.Select(static row => row.Type).ToArray();

        Assert.Equal(234, dtc.Length);
        Assert.Equal("DTC2"u8.ToArray(), dtc.AsSpan(0, 4).ToArray());
        Assert.Equal((byte)2, dtc[4]);
        Assert.Equal(baseIdentity.Network.ToArray(), dtc.AsSpan(6, 16).ToArray());
        Assert.Equal(baseIdentity.ResetId.ToArray(), dtc.AsSpan(22, 32).ToArray());
        Assert.Equal(protectedKeyId, dtc.AsSpan(170, 32).ToArray());
        Assert.Equal(fixture.Hmac.Tag(dtc.AsSpan(0, 202)), dtc.AsSpan(202, 32).ToArray());
        Assert.Equal(
            RecoveryContextFingerprint.GenesisIdentity(
                baseIdentity.Identity, baseIdentity.Device, baseIdentity.Mailbox,
                baseIdentity.Router, baseIdentity.Manifest, dtc),
            identity.Fingerprint.ToArray());
        Assert.Contains(ArtifactType.Dpa1, recoveryTypes);
        Assert.Contains(ArtifactType.Dpd1, recoveryTypes);
        Assert.Contains(ArtifactType.Dpm1, recoveryTypes);
        Assert.Contains(ArtifactType.Dnr1, recoveryTypes);
        Assert.Contains(ArtifactType.Dcm1, recoveryTypes);
        Assert.Contains(ArtifactType.Drs1, recoveryTypes);
        Assert.True(identity.IsCurrentProtectedStore);
        Assert.True(identity.NoAuthorityClaim);
    }

    [Fact]
    public async Task FirstDeployment_GenesisReleaseContextMatchesExactNonterminalAncestryTranscript()
    {
        var fixture = Fixture.Create();
        var network = fixture.ReleaseRoot.Manifest.Record.FieldSpan(1).ToArray();
        var facts = await MembershipClosureIntegrationTests
            .CreateGenesisRoutingFactsAsync(network);
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var branch = RecoveryVerifier.CreateFirstDeploymentCutoverBranch(
            governance, facts.Identity);
        var reservationProvider = new ScopedReservationProvider(fixture.Hmac);
        var reservation = await RecoveryVerifier.RestoreOrReserveGenesisResetIdByScopeAsync(
            branch, reservationProvider, fixture.Hmac);
        var signed = await RecoveryVerifier.AuthorCutoverManifestAsync(
            branch, reservation, reservationProvider, new DcmProvider(fixture.Hmac),
            new OriginSigner(facts.AccountSigner.PrivateKey, facts.ResetSigner.PrivateKey),
            fixture.Hmac, 101);
        var distributed = await RecoveryVerifier.DistributeCutoverManifestAsync(
            signed, reservationProvider, new DistributionProvider(fixture.Hmac),
            new ComponentDistributor(), fixture.Hmac, 101);
        var baseIdentity = RecoveryVerifier.CreateGenesisBaseIdentityContext(
            facts.Identity, facts.Device, facts.Mailbox, facts.Router, distributed);
        var protectedKeyId = Fill(0xd3, 32);
        var witnesses = new List<KeyPair>();
        var verifiedHead = await IdentityAuthorityTests.VerifyGenesisReleaseHeadForEvidenceAsync(
            baseIdentity, fixture.ReleaseRoot, fixture.ReleaseRootSigner,
            protectedKeyId, fixture.Hmac, witnesses);

        var release = RecoveryVerifier.CreateGenesisReleaseContext(baseIdentity, verifiedHead);
        var root = release.CurrentRoot;
        var ancestry = release.OrderedDwdAncestry;
        var latest = ancestry[^1];
        var whl = release.WitnessHeadHistoryLkg;
        var historyCount = BinaryPrimitives.ReadUInt16BigEndian(whl.Slice(156, 2));
        var history = whl.Slice(158, checked(historyCount * 342));
        var payload = new byte[
            16 + 32 + 38 + 8 + 32 + 38 + 38 + 1 + 1 + 8 + 38 + 8 + 32 +
            2 + 38 * root.Transitions.Count +
            2 + 38 * ancestry.Count + 2 + history.Length + 32];
        var offset = 0;
        Append(root.Manifest.NetworkId.Span);
        Append(baseIdentity.ResetId);
        Append(Reference(ArtifactType.Rrm1, root.Manifest.CanonicalBytes.Span));
        Append(U64(root.CurrentGeneration));
        Append(root.CurrentEd25519PublicKey.Span);
        Append(CanonicalGrammar.EncodeReference(root.CurrentTransitionReference));
        Append(new byte[38]);
        payload[offset++] = 0;
        payload[offset++] = 0;
        Append(U64(latest.Delegation.DelegationGeneration));
        Append(Reference(ArtifactType.Dwd1, latest.Delegation.CanonicalBytes.Span));
        Append(U64(latest.Delegation.WitnessEpoch));
        Append(release.CurrentReleaseRootAuthorityHead.Span);
        Append(U16(checked((ushort)root.Transitions.Count)));
        foreach (var transition in root.Transitions)
            Append(CanonicalGrammar.EncodeReference(transition));
        Append(U16(checked((ushort)ancestry.Count)));
        foreach (var fact in ancestry)
            Append(Reference(ArtifactType.Dwd1, fact.Delegation.CanonicalBytes.Span));
        Append(U16(historyCount));
        Append(history);
        Append(protectedKeyId);

        Assert.Equal(payload.Length, offset);
        Assert.Equal(
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V3/recovery-genesis-release-context", payload),
            release.Fingerprint.ToArray());
        Assert.Equal(ancestry.Count - 1, historyCount);
        Assert.Contains(release.RecoveryRows, static row => row.Type == ArtifactType.Rrm1);
        Assert.Contains(release.RecoveryRows, static row => row.Type == ArtifactType.Dwd1);
        Assert.DoesNotContain(release.RecoveryRows, static row => row.Type == ArtifactType.Krf1);
        Assert.DoesNotContain(release.RecoveryRows, static row => row.Type == ArtifactType.Dwt1);
        Assert.DoesNotContain(release.RecoveryRows, static row => row.Type == ArtifactType.Dcl1);
        Assert.Equal(protectedKeyId, release.ProtectedStateHmacKeyId.ToArray());
        Assert.True(release.NoAuthorityClaim);

        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(payload.AsSpan(offset));
            offset += value.Length;
        }
    }

    [Fact]
    public async Task FirstDeployment_PreExternalAuthorFreezesFourDcpOneDcsOneDctWithSixSignatures()
    {
        using var fixture = await CreateFirstPreExternalEvidenceAsync();
        var plan = fixture.Plan;

        Assert.Equal(6, fixture.Signer.Calls);
        Assert.Equal(
            [ArtifactType.Dcp1, ArtifactType.Dcp1, ArtifactType.Dcp1, ArtifactType.Dcp1,
             ArtifactType.Dcs1, ArtifactType.Dct1],
            fixture.Signer.Requests.Select(static request => request.ArtifactType));
        Assert.Equal(4, plan.ComponentCheckpoints.Count);
        for (var index = 0; index < plan.ComponentCheckpoints.Count; index++)
        {
            var checkpoint = plan.ComponentCheckpoints[index];
            var record = CanonicalGrammar.DecodeOwned(
                checkpoint.CanonicalBytes.Span, RecordDefinitions.Dcp1);
            Assert.Equal((ushort)(index + 1), checkpoint.ComponentKind);
            Assert.Equal((ulong)1, checkpoint.Sequence);
            Assert.True(CanonicalGrammar.IsZero(record.FieldSpan(5)));
            Assert.False(CanonicalGrammar.IsZero(record.FieldSpan(21)));
        }

        var deployment = CanonicalGrammar.DecodeOwned(
            plan.DeploymentSet.CanonicalBytes.Span, RecordDefinitions.Dcs1);
        Assert.Equal((ulong)1, plan.DeploymentSet.Sequence);
        Assert.True(CanonicalGrammar.IsZero(deployment.FieldSpan(5)));
        Assert.False(CanonicalGrammar.IsZero(deployment.FieldSpan(14)));

        var transaction = CanonicalGrammar.DecodeOwned(
            plan.Transaction.CanonicalBytes.Span, RecordDefinitions.Dct1);
        Assert.Equal((ulong)0, plan.Transaction.ExpectedSequence);
        Assert.True(CanonicalGrammar.IsZero(transaction.FieldSpan(4)));
        Assert.False(CanonicalGrammar.IsZero(transaction.FieldSpan(11)));
        Assert.True(plan.NoAuthorityClaim);
    }

    [Fact]
    public async Task FirstDeployment_CandidateCoreIsExact494PreExternalCycleFreeTranscript()
    {
        using var fixture = await CreateFirstPreExternalEvidenceAsync();
        var plan = fixture.Plan;
        var identity = plan.Identity;
        var input = new byte[494];
        var offset = 0;

        Append(identity.BaseIdentity.Network);
        Append(identity.BaseIdentity.ResetId);
        Append(U16((ushort)identity.Scope.ComponentKind));
        Append(identity.Scope.ComponentSubject);
        Append(U64(identity.BaseIdentity.AccountGeneration));
        Append(identity.Transaction.TransactionId);
        Append(fixture.Reservation.ReservationHash.Span);
        Append(plan.Candidate.ShadowStateHash.Span);
        Append(Reference(ArtifactType.Drc1, plan.Candidate.Capsule.CanonicalBytes.Span));
        foreach (var checkpoint in plan.ComponentCheckpoints)
            Append(Reference(ArtifactType.Dcp1, checkpoint.CanonicalBytes.Span));
        Append(Reference(ArtifactType.Dcs1, plan.DeploymentSet.CanonicalBytes.Span));
        Append(Reference(ArtifactType.Dct1, plan.Transaction.CanonicalBytes.Span));
        Append(U16(7));
        Append(plan.ArtifactInventoryHash.Span);
        Append(U64(plan.TotalBytes));

        Assert.Equal(494, offset);
        Assert.Equal(
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V4/genesis-author-candidate", input),
            plan.CandidateCoreFingerprint.ToArray());
        Assert.Equal(7, 1 + plan.ComponentCheckpoints.Count + 1 + 1);
        Assert.True(plan.NoAuthorityClaim);

        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(input.AsSpan(offset));
            offset += value.Length;
        }
    }

    [Fact]
    public async Task FirstDeployment_GenesisSourceJoinsExact492AndAnchor460()
    {
        var fixture = Fixture.Create();
        var network = fixture.ReleaseRoot.Manifest.Record.FieldSpan(1).ToArray();
        var facts = await MembershipClosureIntegrationTests
            .CreateGenesisRoutingFactsAsync(network);
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var branch = RecoveryVerifier.CreateFirstDeploymentCutoverBranch(
            governance, facts.Identity);
        var reservationProvider = new ScopedReservationProvider(fixture.Hmac);
        var reservation = await RecoveryVerifier.RestoreOrReserveGenesisResetIdByScopeAsync(
            branch, reservationProvider, fixture.Hmac);
        var signed = await RecoveryVerifier.AuthorCutoverManifestAsync(
            branch, reservation, reservationProvider, new DcmProvider(fixture.Hmac),
            new OriginSigner(facts.AccountSigner.PrivateKey, facts.ResetSigner.PrivateKey),
            fixture.Hmac, 101);
        var distributed = await RecoveryVerifier.DistributeCutoverManifestAsync(
            signed, reservationProvider, new DistributionProvider(fixture.Hmac),
            new ComponentDistributor(), fixture.Hmac, 101);
        var baseIdentity = RecoveryVerifier.CreateGenesisBaseIdentityContext(
            facts.Identity, facts.Device, facts.Mailbox, facts.Router, distributed);
        var protectedKeyId = Fill(0xd3, 32);
        var witnesses = new List<KeyPair>();
        var verifiedHead = await IdentityAuthorityTests.VerifyGenesisReleaseHeadForEvidenceAsync(
            baseIdentity, fixture.ReleaseRoot, fixture.ReleaseRootSigner,
            protectedKeyId, fixture.Hmac, witnesses);
        var release = RecoveryVerifier.CreateGenesisReleaseContext(baseIdentity, verifiedHead);
        var scope = RecoveryVerifier.CreateGenesisTransactionScopeContext(
            baseIdentity, release, reservation, ComponentKind.Registry);
        var transaction = await RecoveryVerifier.RestoreOrReserveGenesisTransactionAsync(
            scope, new TransactionProvider(fixture.Hmac, protectedKeyId), fixture.Hmac);
        var identity = await RecoveryVerifier.AuthorGenesisIdentityContextAsync(
            scope, transaction, fixture.Hmac);
        var intent = RecoveryVerifier.CreateGenesisComponentIntent(identity);
        var keyRegistry = new KeySetProvider();
        var keySet = await RecoveryVerifier.ReadGenesisProtectedKeySetAsync(
            identity, intent, keyRegistry);
        var protector = await RecoveryVerifier.ReadGenesisRecoveryProtectorAsync(
            identity, intent, keySet, new ProtectorProvider());
        var source = RecoveryVerifier.CreateGenesisCutoverSourceContext(
            identity, intent, release, keySet, protector);

        var dcm = baseIdentity.Manifest.Record;
        var drs = baseIdentity.Identity.Revocations.Snapshot.Record;
        var expectedSource = new byte[492];
        var sourceOffset = 0;
        AppendSource(baseIdentity.Network);
        AppendSource(baseIdentity.ResetId);
        AppendSource(U16((ushort)intent.ComponentKind));
        AppendSource(intent.ComponentSubject.Span);
        AppendSource(U64(baseIdentity.AccountGeneration));
        AppendSource(dcm.FieldSpan(3));
        AppendSource(CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Dcm1, dcm.CanonicalSpan)));
        AppendSource(drs.FieldSpan(4));
        AppendSource(U64(Scalars.UInt16(drs.FieldSpan(9))));
        AppendSource(drs.FieldSpan(11));
        AppendSource(CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Drs1, drs.CanonicalSpan)));
        AppendSource(release.LatestDwdReference);
        AppendSource(U64(release.LatestWitnessEpoch));
        AppendSource(intent.SchemaFingerprint.Span);
        AppendSource(keySet.DplKeyId);
        AppendSource(keySet.DwlKeyId);
        AppendSource(keySet.RrlKeyId);
        AppendSource(keySet.RibKeyId);
        AppendSource(keySet.MrlcKeyId);
        AppendSource(keySet.DxrKeyId);

        var expectedAnchor = new byte[460];
        var anchorOffset = 0;
        AppendAnchor(baseIdentity.Network);
        AppendAnchor(baseIdentity.ResetId);
        AppendAnchor(U16((ushort)intent.ComponentKind));
        AppendAnchor(intent.ComponentSubject.Span);
        AppendAnchor(U64(baseIdentity.AccountGeneration));
        AppendAnchor(CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Dcm1, dcm.CanonicalSpan)));
        AppendAnchor(CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Drs1, drs.CanonicalSpan)));
        AppendAnchor(release.LatestDwdReference);
        AppendAnchor(release.Fingerprint.Span);
        AppendAnchor(identity.Fingerprint.Span);
        AppendAnchor(source.SourceFingerprint.Span);
        AppendAnchor(transaction.TransactionId);
        AppendAnchor(protector.ProtectorKeyId);
        AppendAnchor(identity.ProtectedStateHmacKeyId);
        AppendAnchor(protector.RecoveryNonceLatchKeyId);
        AppendAnchor(intent.SchemaFingerprint.Span);

        Assert.Equal(492, sourceOffset);
        Assert.Equal(expectedSource, source.Source.ToArray());
        Assert.Equal(
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V2/recovery-genesis-cutover-source", expectedSource),
            source.SourceFingerprint.ToArray());
        Assert.Equal(460, anchorOffset);
        Assert.Equal(expectedAnchor, source.Anchor.ToArray());
        Assert.Equal(
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V2/recovery-genesis-cutover-anchor", expectedAnchor),
            source.GenesisAnchorHash.ToArray());
        Assert.Equal(1, keyRegistry.Calls);
        Assert.True(source.NoAuthorityClaim);

        void AppendSource(ReadOnlySpan<byte> value)
        {
            value.CopyTo(expectedSource.AsSpan(sourceOffset));
            sourceOffset += value.Length;
        }

        void AppendAnchor(ReadOnlySpan<byte> value)
        {
            value.CopyTo(expectedAnchor.AsSpan(anchorOffset));
            anchorOffset += value.Length;
        }
    }

    [Fact]
    public Task PreJournalExistingJournal_RejectsBeforeAuthenticatedOpen() =>
        RunFirstDeploymentToCommitAsync(exerciseReplayMatrix: true,
            preJournalInvalidCall: 1, expectPreJournalFailure: true,
            expectedPreJournalOpenCalls: 0);

    [Fact]
    public Task PreJournalJournalAppearsAfterOpen_ReturnsNoContinuation() =>
        RunFirstDeploymentToCommitAsync(exerciseReplayMatrix: true,
            preJournalInvalidCall: 3, expectPreJournalFailure: true,
            expectedPreJournalOpenCalls: 1);

    [Fact]
    public Task PreJournalSourceRevisionRollback_RejectsBeforeAuthenticatedOpen() =>
        RunFirstDeploymentToCommitAsync(exerciseReplayMatrix: true,
            preJournalRollbackCall: 2, expectPreJournalFailure: true,
            expectedPreJournalOpenCalls: 0);

    [Fact]
    public Task PreJournalArtifactReceiptMovementAfterOpen_ReturnsNoContinuation() =>
        RunFirstDeploymentToCommitAsync(exerciseReplayMatrix: true,
            artifactMoveOnRestoreCall: 2, expectPreJournalFailure: true,
            expectedPreJournalOpenCalls: 1);

    [Fact]
    public Task PreJournalExpiredArtifactReceipt_RejectsBeforeAuthenticatedOpen() =>
        RunFirstDeploymentToCommitAsync(exerciseReplayMatrix: true,
            preJournalNow: 200, expectPreJournalFailure: true,
            expectedPreJournalOpenCalls: 0);

    [Fact]
    public Task PreJournalPendingDisappearsAfterOpen_ReturnsNoContinuation() =>
        RunFirstDeploymentToCommitAsync(exerciseReplayMatrix: true,
            preJournalPendingDisappearOnCall: 4,
            expectSecondPreJournalFailure: true);

    [Fact]
    public Task KeySetMovementBeforeExternalCas_FailsWithZeroPublication() =>
        RunFirstDeploymentToCommitAsync(keySetMoveOnCall: 8, expectExternalFailure: true);

    [Fact]
    public Task ArtifactStoreMovementBeforeExternalCas_FailsWithZeroPublication() =>
        RunFirstDeploymentToCommitAsync(artifactMoveOnRestoreCall: 1,
            expectExternalFailure: true);

    [Fact]
    public Task KeySetMovementAfterExternalCas_RequiresReplayAndPublishesNoLocalState() =>
        RunFirstDeploymentToCommitAsync(keySetMoveOnCall: 9,
            expectExternalFailure: true, expectedExternalCalls: 1);

    [Fact]
    public Task ArtifactStoreMovementAfterExternalCas_RequiresReplayAndPublishesNoLocalState() =>
        RunFirstDeploymentToCommitAsync(artifactMoveOnRestoreCall: 2,
            expectExternalFailure: true, expectedExternalCalls: 1);

    [Fact]
    public Task KeySetMovementAfterLocalCas_RequiresReplayBeforeLocalCommittedJournal() =>
        RunFirstDeploymentToCommitAsync(keySetMoveOnCall: 30,
            expectLocalFailure: true);

    [Fact]
    public Task ArtifactStoreMovementAfterLocalCas_RequiresReplayBeforeLocalCommittedJournal() =>
        RunFirstDeploymentToCommitAsync(artifactMoveOnRestoreCall: 5,
            expectLocalFailure: true);

    [Fact]
    public Task WitnessHeadMovementBeforeReceiptAuthoring_FailsBeforeSelectedWitnessCalls() =>
        RunFirstDeploymentToCommitAsync(witnessHeadMoveOnCall: 1);

    [Fact]
    public Task WitnessHeadMovementBeforeExternalCas_FailsWithZeroPublication() =>
        RunFirstDeploymentToCommitAsync(witnessHeadMoveOnCall: 2,
            expectExternalFailure: true);

    [Fact]
    public Task WitnessHeadMovementAfterExternalCas_RequiresReplayAndNoLocalPublication() =>
        RunFirstDeploymentToCommitAsync(witnessHeadMoveOnCall: 3,
            expectExternalFailure: true, expectedExternalCalls: 1);

    [Fact]
    public Task QuorumExpiryAfterAssembly_FailsBeforeSelectionMutation() =>
        RunFirstDeploymentToCommitAsync(quorumCompletionNow: 150,
            expectQuorumCompletionFailure: true);

    private async Task RunFirstDeploymentToCommitAsync(
        int keySetMoveOnCall = 0,
        int artifactMoveOnRestoreCall = 0,
        bool expectExternalFailure = false,
        int expectedExternalCalls = 0,
        bool expectLocalFailure = false,
        int witnessHeadMoveOnCall = 0,
        ulong quorumCompletionNow = 104,
        bool expectQuorumCompletionFailure = false,
        bool exerciseReplayMatrix = false,
        int preJournalInvalidCall = 0,
        int preJournalRollbackCall = 0,
        bool expectPreJournalFailure = false,
        int expectedPreJournalOpenCalls = 0,
        ulong preJournalNow = 104,
        int preJournalPendingDisappearOnCall = 0,
        bool expectSecondPreJournalFailure = false,
        bool exerciseColdOpen = false,
        bool expectColdRegistryFailure = false,
        bool exerciseFreshNormalRestore = false,
        bool verifyDedicatedDplKey = false)
    {
        var fixture = Fixture.Create();
        var network = fixture.ReleaseRoot.Manifest.Record.FieldSpan(1).ToArray();
        var facts = await MembershipClosureIntegrationTests
            .CreateGenesisRoutingFactsAsync(network);
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var branch = RecoveryVerifier.CreateFirstDeploymentCutoverBranch(
            governance, facts.Identity);
        var reservationProvider = new ScopedReservationProvider(fixture.Hmac);
        var reservation = await RecoveryVerifier.RestoreOrReserveGenesisResetIdByScopeAsync(
            branch, reservationProvider, fixture.Hmac);
        var signed = await RecoveryVerifier.AuthorCutoverManifestAsync(
            branch, reservation, reservationProvider, new DcmProvider(fixture.Hmac),
            new OriginSigner(facts.AccountSigner.PrivateKey, facts.ResetSigner.PrivateKey),
            fixture.Hmac, 101);
        var distributed = await RecoveryVerifier.DistributeCutoverManifestAsync(
            signed, reservationProvider, new DistributionProvider(fixture.Hmac),
            new ComponentDistributor(), fixture.Hmac, 101);

        var result = RecoveryVerifier.CreateGenesisBaseIdentityContext(
            facts.Identity, facts.Device, facts.Mailbox, facts.Router, distributed);

        Assert.True(result.NoAuthorityClaim);
        Assert.Equal(network, result.Network.ToArray());
        Assert.Equal(reservation.ResetId.ToArray(), result.ResetId.ToArray());
        Assert.Contains(result.RecoveryRows, row => row.Type == ArtifactType.Pma1);
        Assert.Contains(result.RecoveryRows, row => row.Type == ArtifactType.Pmr1);
        Assert.DoesNotContain(result.RecoveryRows, row => row.Type == ArtifactType.Drt1);
        Assert.Equal(result.RecoveryRows.Count,
            result.RecoveryRows.Select(row => row.Type).Distinct().Count());

        var protectedKeyId = Fill(0xd3, 32);
        var witnessSigners = new List<KeyPair>();
        var verifiedHead = await IdentityAuthorityTests
            .VerifyGenesisReleaseHeadForEvidenceAsync(
                result, fixture.ReleaseRoot, fixture.ReleaseRootSigner,
                protectedKeyId, fixture.Hmac, witnessSigners);
        var release = RecoveryVerifier.CreateGenesisReleaseContext(result, verifiedHead);
        Assert.True(release.NoAuthorityClaim);
        Assert.Equal(result.ResetId.ToArray(), release.ResetId.ToArray());
        Assert.Contains(release.RecoveryRows, row => row.Type == ArtifactType.Rrm1);
        Assert.Contains(release.RecoveryRows, row => row.Type == ArtifactType.Dwd1);
        Assert.DoesNotContain(release.RecoveryRows, row => row.Type == ArtifactType.Dwt1);
        Assert.DoesNotContain(release.RecoveryRows, row => row.Type == ArtifactType.Dcl1);

        var transactionScope = RecoveryVerifier.CreateGenesisTransactionScopeContext(
            result, release, reservation, ComponentKind.Registry);
        var transactionProvider = new TransactionProvider(fixture.Hmac, protectedKeyId);
        var transaction = await RecoveryVerifier.RestoreOrReserveGenesisTransactionAsync(
            transactionScope, transactionProvider, fixture.Hmac);
        var identity = await RecoveryVerifier.AuthorGenesisIdentityContextAsync(
            transactionScope, transaction, fixture.Hmac);
        var intent = RecoveryVerifier.CreateGenesisComponentIntent(identity);
        var keyRegistry = new KeySetProvider(keySetMoveOnCall);
        var keySet = await RecoveryVerifier.ReadGenesisProtectedKeySetAsync(
            identity, intent, keyRegistry);
        var sealingProvider = new ProtectorProvider();
        var protector = await RecoveryVerifier.ReadGenesisRecoveryProtectorAsync(
            identity, intent, keySet, sealingProvider);
        var source = RecoveryVerifier.CreateGenesisCutoverSourceContext(
            identity, intent, release, keySet, protector);

        Assert.True(identity.NoAuthorityClaim);
        Assert.True(intent.NoAuthorityClaim);
        Assert.True(keySet.NoAuthorityClaim);
        Assert.True(protector.NoAuthorityClaim);
        Assert.True(source.NoAuthorityClaim);
        Assert.Equal(32, source.SourceFingerprint.Length);
        Assert.Equal(32, source.GenesisAnchorHash.Length);

        using var manifest = await RecoveryVerifier.AuthorGenesisRecoveryManifestAsync(
            identity, intent, release, source, fixture.Hmac);
        var recoveryShadow = manifest.TakeOrGet().Rsm.ToArray();
        var longLived = exerciseColdOpen || exerciseFreshNormalRestore;
        var sealCreatedAt = longLived ? 1008UL : 102UL;
        var sealRetainUntil = longLived ? 1200UL : 180UL;
        var checkpointIssuedAt = longLived ? 1009UL : 103UL;
        var checkpointExpiresAt = longLived ? 1100UL : 150UL;
        var receiptNow = longLived ? 1010UL : 103UL;
        var completionNow = longLived ? 1010UL : quorumCompletionNow;
        using var sealedCandidate = await RecoveryVerifier.SealGenesisCandidateAsync(
            manifest, identity, intent, source, protector, sealingProvider,
            new StoredLatch(), sealCreatedAt, sealRetainUntil);
        var cutoverSigner = new CutoverSigner(facts.ResetSigner.PrivateKey);
        var preExternal = await RecoveryVerifier.AuthorGenesisPreExternalArtifactsAsync(
            sealedCandidate, identity, release, reservation,
            cutoverSigner, Fill(0xd4, 32), checkpointIssuedAt, checkpointExpiresAt);
        Assert.True(preExternal.NoAuthorityClaim);
        Assert.Equal(4, preExternal.ComponentCheckpoints.Count);
        Assert.Equal(32, preExternal.ArtifactInventoryHash.Length);
        Assert.Equal(32, preExternal.CandidateCoreFingerprint.Length);
        Assert.True(preExternal.TotalBytes > 0);

        var artifactStore = new GenesisArtifactProvider(
            fixture.Hmac, identity, preExternal, artifactMoveOnRestoreCall,
            longLived ? 1200UL : 200UL);
        var artifactSet = await RecoveryVerifier.StoreGenesisArtifactSetAsync(
            preExternal, identity, artifactStore, fixture.Hmac);
        var quorumProvider = new GenesisQuorumProvider(
            fixture.Hmac, identity, preJournalPendingDisappearOnCall,
            longLived ? 1200UL : 200UL);
        var replayProvider = new ReplayRecoveryProvider();
        var replayLatch = new ExactReplayLatch();
        var preJournalHeads = new ZeroPreJournalHeads(
            preJournalInvalidCall, preJournalRollbackCall);
        if (exerciseReplayMatrix)
        {
            if (expectPreJournalFailure)
            {
                await Assert.ThrowsAsync<RecordException>(() =>
                    RecoveryVerifier.RestoreGenesisPreJournalAsync(
                        identity, intent, release, reservation, keySet, keyRegistry, protector,
                        sealingProvider, source, artifactStore, quorumProvider, preJournalHeads,
                        replayProvider, replayLatch, fixture.Hmac, preJournalNow).AsTask());
                Assert.Equal(expectedPreJournalOpenCalls, replayProvider.OpenCalls);
                Assert.Equal(expectedPreJournalOpenCalls, replayLatch.Calls);
                return;
            }
            else
            {
                var restored = await RecoveryVerifier.RestoreGenesisPreJournalAsync(
                    identity, intent, release, reservation, keySet, keyRegistry, protector,
                    sealingProvider, source, artifactStore, quorumProvider, preJournalHeads,
                    replayProvider, replayLatch, fixture.Hmac, preJournalNow);
                var afterGas = Assert.IsType<GenesisAfterGas>(restored);
                Assert.NotEmpty(afterGas.Candidate.Candidate.Manifest.ToArray());
                restored.Dispose();
                Assert.Throws<ObjectDisposedException>(() =>
                    afterGas.Candidate.Candidate.Manifest.ToArray());
            }
        }
        var selectedWitnessIds = Enumerable.Range(1, 3)
            .Select(index => (ReadOnlyMemory<byte>)Fill(checked((byte)index), 32)).ToArray();
        var pending = await RecoveryVerifier.RestoreOrCreateGenesisQuorumPendingAsync(
            preExternal, release, selectedWitnessIds, quorumProvider, fixture.Hmac);
        GenesisPreJournalRestorePlan? recoveredPlanOwner = null;
        if (exerciseReplayMatrix)
        {
            if (expectSecondPreJournalFailure)
            {
                await Assert.ThrowsAsync<RecordException>(() =>
                    RecoveryVerifier.RestoreGenesisPreJournalAsync(
                        identity, intent, release, reservation, keySet, keyRegistry, protector,
                        sealingProvider, source, artifactStore, quorumProvider, preJournalHeads,
                        replayProvider, replayLatch, fixture.Hmac, preJournalNow).AsTask());
                Assert.Equal(2, replayProvider.OpenCalls);
                Assert.Equal(2, replayLatch.Calls);
                return;
            }
            else
            {
                var restored = await RecoveryVerifier.RestoreGenesisPreJournalAsync(
                    identity, intent, release, reservation, keySet, keyRegistry, protector,
                    sealingProvider, source, artifactStore, quorumProvider, preJournalHeads,
                    replayProvider, replayLatch, fixture.Hmac, preJournalNow);
                var afterGqp = Assert.IsType<GenesisAfterGqp>(restored);
                recoveredPlanOwner = afterGqp;
                preExternal = afterGqp.Candidate;
                artifactSet = afterGqp.ArtifactSet;
                pending = afterGqp.Pending;
                Assert.Same(reservation, afterGqp.Reservation);
                Assert.Equal(6, preJournalHeads.Calls);
            }
        }
        using var recoveredPlanLifetime = recoveredPlanOwner;
        var journal = new GenesisJournalProvider(fixture.Hmac, identity);
        var created = await RecoveryVerifier.RestoreOrCreateGenesisAuthorCreatedAsync(
            preExternal, artifactSet, pending, reservation, journal, fixture.Hmac);
        if (exerciseReplayMatrix)
        {
            var restored = await RecoveryVerifier.RestoreGenesisAuthorReplayAsync(
                identity, intent, release, reservation, keySet, keyRegistry, protector,
                sealingProvider, source, artifactStore, quorumProvider, journal,
                new GenesisReplayHeads(journal), new FixedReplayTimePolicy(104, 40),
                replayProvider, replayLatch, fixture.Hmac);
            Assert.IsType<CreatedContinue>(restored);
        }
        var witnessHeadProvider = new CurrentGenesisWitnessHeadProvider(
            release, witnessHeadMoveOnCall);
        var witnessProvider = new GenesisWitnessProvider(
            witnessSigners, checkpointIssuedAt, checkpointExpiresAt);
        if (witnessHeadMoveOnCall == 1)
        {
            await Assert.ThrowsAsync<RecordException>(() =>
                RecoveryVerifier.AuthorDcnReceiptAsync(
                    created, release, witnessHeadProvider, witnessProvider, fixture.Hmac,
                    receiptNow)
                    .AsTask());
            Assert.Equal(1, witnessHeadProvider.Calls);
            Assert.Equal(0, witnessProvider.Calls);
            return;
        }
        var receiptSet = await RecoveryVerifier.AuthorDcnReceiptAsync(
            created, release, witnessHeadProvider, witnessProvider, fixture.Hmac,
            receiptNow);
        Assert.Equal(1, witnessHeadProvider.Calls);
        Assert.Equal(3, witnessProvider.Calls);
        var dcq = await RecoveryVerifier.VerifyAndAssembleDcqAsync(
            created, release, receiptSet, receiptNow);
        if (expectQuorumCompletionFailure)
        {
            await Assert.ThrowsAsync<RecordException>(() =>
                RecoveryVerifier.VerifyAndCompleteGenesisQuorumAsync(
                    preExternal, release, pending, dcq, quorumCompletionNow,
                    quorumProvider, fixture.Hmac).AsTask());
            Assert.Equal(0, quorumProvider.CompleteCalls);
            return;
        }
        var quorum = await RecoveryVerifier.VerifyAndCompleteGenesisQuorumAsync(
            preExternal, release, pending, dcq, completionNow,
            quorumProvider, fixture.Hmac);
        var hmacCallsBeforeMaterialization = fixture.Hmac.Requests.Count;
        var materialization = await RecoveryVerifier.MaterializeGenesisCandidateDplAsync(
            created, quorum, keySet, fixture.Hmac);
        if (verifyDedicatedDplKey)
        {
            var request = Assert.Single(
                fixture.Hmac.Requests.Skip(hmacCallsBeforeMaterialization));
            Assert.Equal("Deep/ProtectedState/V1/DPL1", request.Domain);
            Assert.Equal(keySet.DplKeyId.ToArray(), request.KeyId);
            Assert.NotEqual(identity.ProtectedStateHmacKeyId.ToArray(), request.KeyId);
            Assert.NotEqual(protector.RecoveryNonceLatchKeyId.ToArray(), request.KeyId);
            Assert.NotEqual(protector.ProtectorKeyId.ToArray(), request.KeyId);
            Assert.Equal(576, materialization.CanonicalCandidateDpl.Length);
            var dpl = CanonicalGrammar.DecodeOwned(
                materialization.CanonicalCandidateDpl.Span, RecordDefinitions.Dpl1);
            var unsignedDefinition = RecordDefinitions.Dpl1 with
            {
                Fields = RecordDefinitions.Dpl1.Fields.Take(17).ToArray(),
                MinimumLength = 12,
                OmittedSigningFieldIndexes = new HashSet<int>()
            };
            var unsigned = CanonicalGrammar.Encode(unsignedDefinition,
                Enumerable.Range(1, 17)
                    .Select(tag => (ReadOnlyMemory<byte>)dpl.FieldCopy(tag)).ToArray());
            Assert.Equal(fixture.Hmac.Tag(unsigned), dpl.FieldCopy(18));
        }
        if (exerciseColdOpen)
        {
            var decodedDcq = CanonicalGrammar.DecodeOwned(
                dcq.CanonicalBytes.Span, RecordDefinitions.Dcq1);
            foreach (var receipt in receiptSet.Receipts)
            {
                var leafPayload = new byte[116];
                decodedDcq.FieldSpan(2).CopyTo(leafPayload);
                decodedDcq.FieldSpan(3).CopyTo(leafPayload.AsSpan(32));
                decodedDcq.FieldSpan(4).CopyTo(leafPayload.AsSpan(40));
                decodedDcq.FieldSpan(5).CopyTo(leafPayload.AsSpan(78));
                Assert.Equal(WitnessTreeVerifier.Leaf(leafPayload),
                    receipt.Record.FieldCopy(18));
                WitnessTreeVerifier.VerifyInclusion(WitnessTreeVerifier.Leaf(leafPayload),
                    Scalars.UInt64(receipt.Record.FieldSpan(19)),
                    Scalars.UInt64(receipt.Record.FieldSpan(17)),
                    receipt.Record.FieldSpan(21), receipt.Record.FieldSpan(18));
            }
            var embeddedReceipts = decodedDcq.FieldSpan(10);
            var embeddedOffset = 0;
            for (var index = 0; index < 3; index++)
            {
                var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                    embeddedReceipts.Slice(embeddedOffset, 4)));
                embeddedOffset += 4;
                var embedded = CanonicalGrammar.DecodeOwned(
                    embeddedReceipts.Slice(embeddedOffset, length), RecordDefinitions.Dcn1);
                embeddedOffset += length;
                var leafPayload = new byte[116];
                decodedDcq.FieldSpan(2).CopyTo(leafPayload);
                decodedDcq.FieldSpan(3).CopyTo(leafPayload.AsSpan(32));
                decodedDcq.FieldSpan(4).CopyTo(leafPayload.AsSpan(40));
                decodedDcq.FieldSpan(5).CopyTo(leafPayload.AsSpan(78));
                WitnessTreeVerifier.VerifyInclusion(WitnessTreeVerifier.Leaf(leafPayload),
                    Scalars.UInt64(embedded.FieldSpan(19)),
                    Scalars.UInt64(embedded.FieldSpan(17)),
                    embedded.FieldSpan(21), embedded.FieldSpan(18));
            }
            var dcp = preExternal.ComponentCheckpoints.Single(checkpoint =>
                checkpoint.ComponentKind == (ushort)ComponentKind.Registry);
            var dcs = preExternal.DeploymentSet.CanonicalBytes.ToArray();
            var dcsReference = CanonicalGrammar.EncodeReference(
                CanonicalGrammar.ComputeReference(ArtifactType.Dcs1, dcs));
            var dcl = IdentityAuthorityTests.CreateFreshDclForEvidence(
                release.CurrentRoot, release.LatestDelegation, witnessSigners,
                release.CurrentReleaseRootAuthorityHead.Span,
                preExternal.DeploymentSubject.Span, dcsReference, 1010, 1020);
            var coldInput = ColdRecoveryInput.CreateNonterminal(
                fixture.ReleaseRoot.Pin, dcp.CanonicalBytes.Span, dcs,
                dcq.CanonicalBytes.Span, dcl,
                preExternal.Candidate.Capsule.CanonicalBytes.Span, recoveryShadow);
            var coldProvider = new ReplayRecoveryProvider();
            var coldRegistry = new ColdProviderRegistry(
                reservation.ResetId.ToArray(), protectedKeyId, Fill(0xb2, 32),
                expectColdRegistryFailure ? 3 : 0);
            var coldLatch = new ExactReplayLatch();
            if (expectColdRegistryFailure)
            {
                await Assert.ThrowsAsync<RecordException>(() =>
                    RecoveryVerifier.OpenColdAsync(
                        coldInput, coldProvider, coldRegistry, coldLatch,
                        fixture.Hmac, 1010).AsTask());
                Assert.Equal(1, coldProvider.OpenCalls);
                Assert.Equal(3, coldRegistry.Calls);
                Assert.Equal(2, coldLatch.Calls);
                return;
            }
            using var coldResult = await RecoveryVerifier.OpenColdAsync(
                coldInput, coldProvider, coldRegistry, coldLatch,
                fixture.Hmac, 1010);
            var coldCandidate = Assert.IsType<ColdRecoveryCandidate>(coldResult);
            Assert.True(coldCandidate.NoAuthorityClaim);
            Assert.Equal(dcp.CanonicalBytes.ToArray(),
                coldCandidate.ExternalCheckpoint.CanonicalDcp.ToArray());
            Assert.Equal(dcq.CanonicalBytes.ToArray(),
                coldCandidate.ExternalCheckpoint.CanonicalDcq.ToArray());
            var coldMaterialization = await RecoveryVerifier.MaterializeCandidateDplAsync(
                coldCandidate.Candidate, coldCandidate.ExternalCheckpoint, fixture.Hmac);
            Assert.Equal(materialization.CanonicalCandidateDpl.ToArray(),
                coldMaterialization.CanonicalCandidateDpl.ToArray());
            Assert.Equal(1, coldProvider.OpenCalls);
            Assert.Equal(3, coldRegistry.Calls);
            Assert.Equal(3, coldLatch.Calls);
        }
        var commit = new GenesisCommitCoordinator(
            materialization.CandidateDplArtifactReference.ToArray(),
            source.SourceFingerprint.ToArray());
        if (expectExternalFailure)
        {
            await Assert.ThrowsAsync<RecordException>(() =>
                RecoveryVerifier.CommitGenesisExternalAsync(
                    created, quorum, materialization, source, keyRegistry, sealingProvider,
                    reservationProvider, transactionProvider, artifactStore, quorumProvider,
                    witnessHeadProvider, commit, journal, fixture.Hmac).AsTask());
            Assert.Equal(expectedExternalCalls, commit.ExternalCalls);
            Assert.Equal(0, commit.LocalCalls);
            return;
        }

        GenesisAuthorExternalCommittedPlan external;
        if (exerciseReplayMatrix)
        {
            var restored = await RecoveryVerifier.RestoreGenesisAuthorReplayAsync(
                identity, intent, release, reservation, keySet, keyRegistry, protector,
                sealingProvider, source, artifactStore, quorumProvider, journal,
                new GenesisReplayHeads(journal, artifactSet, dcq.CanonicalBytes,
                    materialization, source, localInstalled: false),
                new FixedReplayTimePolicy(104, 40), replayProvider, replayLatch, fixture.Hmac);
            var catchUp = Assert.IsType<ExternalCatchUp>(restored);
            external = await RecoveryVerifier.ContinueGenesisReplayExternalAsync(
                catchUp, keyRegistry, journal, new FixedReplayTimePolicy(104, 40), fixture.Hmac);
        }
        else
        {
            external = await RecoveryVerifier.CommitGenesisExternalAsync(
                created, quorum, materialization, source, keyRegistry, sealingProvider,
                reservationProvider, transactionProvider, artifactStore, quorumProvider,
                witnessHeadProvider, commit, journal, fixture.Hmac);
        }
        if (expectLocalFailure)
        {
            await Assert.ThrowsAsync<RecordException>(() =>
                RecoveryVerifier.CommitGenesisLocalAsync(
                    external, keyRegistry, sealingProvider, reservationProvider,
                    transactionProvider, artifactStore, quorumProvider, commit, journal,
                    fixture.Hmac).AsTask());
            Assert.Equal(1, commit.ExternalCalls);
            Assert.Equal(1, commit.LocalCalls);
            return;
        }

        GenesisAuthorLocalCommittedPlan local;
        if (exerciseReplayMatrix)
        {
            var restored = await RecoveryVerifier.RestoreGenesisAuthorReplayAsync(
                identity, intent, release, reservation, keySet, keyRegistry, protector,
                sealingProvider, source, artifactStore, quorumProvider, journal,
                new GenesisReplayHeads(journal, artifactSet, dcq.CanonicalBytes,
                    materialization, source, localInstalled: false),
                new FixedReplayTimePolicy(104, 40), replayProvider, replayLatch, fixture.Hmac);
            var catchUp = Assert.IsType<LocalCatchUp>(restored);
            local = await RecoveryVerifier.ContinueGenesisReplayLocalAsync(
                catchUp, keyRegistry, commit, journal,
                new FixedReplayTimePolicy(104, 40), fixture.Hmac);
        }
        else
        {
            local = await RecoveryVerifier.CommitGenesisLocalAsync(
                external, keyRegistry, sealingProvider, reservationProvider,
                transactionProvider, artifactStore, quorumProvider, commit, journal,
                fixture.Hmac);
        }

        if (exerciseReplayMatrix)
        {
            var restored = await RecoveryVerifier.RestoreGenesisAuthorReplayAsync(
                identity, intent, release, reservation, keySet, keyRegistry, protector,
                sealingProvider, source, artifactStore, quorumProvider, journal,
                new GenesisReplayHeads(journal, artifactSet, dcq.CanonicalBytes,
                    materialization, source, localInstalled: true),
                new FixedReplayTimePolicy(104, 40), replayProvider, replayLatch, fixture.Hmac);
            Assert.IsType<NormalCurrentRequired>(restored);
            Assert.Equal(6, replayProvider.OpenCalls);
            Assert.Equal(6, replayLatch.Calls);
        }

        if (exerciseFreshNormalRestore)
        {
            var dcp = preExternal.ComponentCheckpoints.Single(checkpoint =>
                checkpoint.ComponentKind == (ushort)ComponentKind.Registry);
            var dcs = preExternal.DeploymentSet.CanonicalBytes.ToArray();
            var dcsReference = Reference(ArtifactType.Dcs1, dcs);
            var dcqBytes = dcq.CanonicalBytes.ToArray();
            var dcqReference = Reference(ArtifactType.Dcq1, dcqBytes);
            var dcl = IdentityAuthorityTests.CreateFreshDclForEvidence(
                release.CurrentRoot, release.LatestDelegation, witnessSigners,
                release.CurrentReleaseRootAuthorityHead.Span,
                preExternal.DeploymentSubject.Span, dcsReference, 1010, 1020);
            var freshRelease = new ReleaseRootRelativeVerifier().RestoreAncestryRelative(
                new ReleaseRootRestoreInput(
                    fixture.ReleaseRoot.Pin,
                    fixture.ReleaseRoot.Manifest.CanonicalBytes,
                    [],
                    [new WitnessAncestryInput(
                        release.LatestDelegation.Delegation.CanonicalBytes.Span,
                        new byte[288])],
                    freshDclCanonical: dcl),
                1010);
            var dwl = await CreateCurrentDwlAsync(
                release, preExternal, dcsReference, dcqReference, dcl,
                keySet.DwlKeyId.ToArray(), fixture.Hmac);
            var restore = new CurrentCutoverRestoreInput(
                result.Manifest.CanonicalBytes.Span,
                dcp.CanonicalBytes.Span,
                dcs,
                dcqBytes,
                dwl,
                dcl,
                materialization.CanonicalCandidateDpl.Span,
                keySet.DplKeyId,
                keySet.DwlKeyId,
                keySet.RrlKeyId,
                keySet.RibKeyId,
                keySet.MrlcKeyId,
                keySet.DxrKeyId,
                protector.RecoveryNonceLatchKeyId);
            var current = await new CurrentCutoverVerifier().RestoreCurrentAsync(
                restore, result.Identity, freshRelease, ComponentKind.Registry,
                1010, fixture.Hmac);

            Assert.True(current.NoAuthorityClaim);
            Assert.True(current.HasRecoveryClosure);
            Assert.Equal(materialization.CandidateDplArtifactReference.ToArray(),
                current.TrustedDplRef.ToArray());
            Assert.Equal(materialization.CanonicalCandidateDpl.ToArray(),
                current.TrustedDpl.ToArray());
            Assert.Equal(1020UL, current.LeaseExpiresAtUnixSeconds);
        }

        Assert.Equal(3, receiptSet.Receipts.Count);
        Assert.Equal(3, witnessProvider.Calls);
        Assert.Equal(3, quorumProvider.WitnessSelectionCount);
        Assert.Equal(exerciseReplayMatrix ? 0 : 1, commit.ExternalCalls);
        Assert.Equal(1, commit.LocalCalls);
        Assert.Equal(6, cutoverSigner.Calls);
        if (exerciseReplayMatrix) Assert.True(keyRegistry.Calls > 0);
        else Assert.Equal(43, keyRegistry.Calls);
        Assert.Equal(1, sealingProvider.SealCalls);
        Assert.Equal(1, sealingProvider.OpenCalls);
        Assert.Equal(1, sealingProvider.DeriveNonceCalls);
        Assert.Equal((byte)2, local.Journal.CanonicalJournal.Span[194]);
        Assert.Equal(materialization.CandidateDplArtifactReference.ToArray(),
            local.Journal.CanonicalJournal.Span.Slice(705, 38).ToArray());
    }

    private static async Task<PreExternalEvidenceFixture> CreateFirstPreExternalEvidenceAsync()
    {
        var fixture = Fixture.Create();
        var network = fixture.ReleaseRoot.Manifest.Record.FieldSpan(1).ToArray();
        var facts = await MembershipClosureIntegrationTests.CreateGenesisRoutingFactsAsync(network);
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var branch = RecoveryVerifier.CreateFirstDeploymentCutoverBranch(
            governance, facts.Identity);
        var reservationProvider = new ScopedReservationProvider(fixture.Hmac);
        var reservation = await RecoveryVerifier.RestoreOrReserveGenesisResetIdByScopeAsync(
            branch, reservationProvider, fixture.Hmac);
        var signed = await RecoveryVerifier.AuthorCutoverManifestAsync(
            branch, reservation, reservationProvider, new DcmProvider(fixture.Hmac),
            new OriginSigner(facts.AccountSigner.PrivateKey, facts.ResetSigner.PrivateKey),
            fixture.Hmac, 101);
        var distributed = await RecoveryVerifier.DistributeCutoverManifestAsync(
            signed, reservationProvider, new DistributionProvider(fixture.Hmac),
            new ComponentDistributor(), fixture.Hmac, 101);
        var baseIdentity = RecoveryVerifier.CreateGenesisBaseIdentityContext(
            facts.Identity, facts.Device, facts.Mailbox, facts.Router, distributed);
        var protectedKeyId = Fill(0xd3, 32);
        var witnessSigners = new List<KeyPair>();
        var verifiedHead = await IdentityAuthorityTests.VerifyGenesisReleaseHeadForEvidenceAsync(
            baseIdentity, fixture.ReleaseRoot, fixture.ReleaseRootSigner,
            protectedKeyId, fixture.Hmac, witnessSigners);
        var release = RecoveryVerifier.CreateGenesisReleaseContext(baseIdentity, verifiedHead);
        var transactionScope = RecoveryVerifier.CreateGenesisTransactionScopeContext(
            baseIdentity, release, reservation, ComponentKind.Registry);
        var transaction = await RecoveryVerifier.RestoreOrReserveGenesisTransactionAsync(
            transactionScope, new TransactionProvider(fixture.Hmac, protectedKeyId), fixture.Hmac);
        var identity = await RecoveryVerifier.AuthorGenesisIdentityContextAsync(
            transactionScope, transaction, fixture.Hmac);
        var intent = RecoveryVerifier.CreateGenesisComponentIntent(identity);
        var keySet = await RecoveryVerifier.ReadGenesisProtectedKeySetAsync(
            identity, intent, new KeySetProvider());
        var sealingProvider = new ProtectorProvider();
        var protector = await RecoveryVerifier.ReadGenesisRecoveryProtectorAsync(
            identity, intent, keySet, sealingProvider);
        var source = RecoveryVerifier.CreateGenesisCutoverSourceContext(
            identity, intent, release, keySet, protector);
        var manifest = await RecoveryVerifier.AuthorGenesisRecoveryManifestAsync(
            identity, intent, release, source, fixture.Hmac);
        try
        {
            var candidate = await RecoveryVerifier.SealGenesisCandidateAsync(
                manifest, identity, intent, source, protector, sealingProvider,
                new StoredLatch(), 102, 180);
            try
            {
                var signer = new CutoverSigner(facts.ResetSigner.PrivateKey);
                var plan = await RecoveryVerifier.AuthorGenesisPreExternalArtifactsAsync(
                    candidate, identity, release, reservation, signer,
                    Fill(0xd4, 32), 103, 150);
                return new PreExternalEvidenceFixture(
                    manifest, candidate, plan, reservation, signer);
            }
            catch
            {
                candidate.Dispose();
                throw;
            }
        }
        catch
        {
            manifest.Dispose();
            throw;
        }
    }

    private sealed class PreExternalEvidenceFixture(
        GenesisRecoveryManifestPlan manifest,
        SealedGenesisRecoveryCandidate candidate,
        GenesisPreExternalCandidatePlan plan,
        GenesisResetReservationResult reservation,
        CutoverSigner signer) : IDisposable
    {
        public GenesisPreExternalCandidatePlan Plan { get; } = plan;
        public GenesisResetReservationResult Reservation { get; } = reservation;
        public CutoverSigner Signer { get; } = signer;

        public void Dispose()
        {
            candidate.Dispose();
            manifest.Dispose();
        }
    }

    [Fact]
    public async Task GenesisDcsComponentRows_RejectMissingDuplicateUnsortedAndCrossFeedBeforeCallbacks()
    {
        using var fixture = await CreateFirstPreExternalEvidenceAsync();
        var checkpoint = fixture.Plan.ComponentCheckpoints.Single(value =>
            value.ComponentKind == (ushort)ComponentKind.Registry);
        var dcm = fixture.Plan.Identity.BaseIdentity.Manifest.Record;
        var dcp = checkpoint.Record;
        var dcmRef = Reference(ArtifactType.Dcm1, dcm.CanonicalSpan);
        var dcpRef = Reference(ArtifactType.Dcp1, dcp.CanonicalSpan);
        var original = CanonicalGrammar.DecodeOwned(
            fixture.Plan.DeploymentSet.CanonicalBytes.Span, RecordDefinitions.Dcs1);

        CurrentCutoverVerifier.VerifyComponentRows(
            original, dcm, dcmRef, dcp, dcpRef, ComponentKind.Registry);

        var selected = ((int)ComponentKind.Registry - 1) * 104;
        foreach (var mutate in new Action<byte[]>[]
                 {
                     // Missing/duplicate and unsorted closed-kind rows.
                     rows => rows.AsSpan(selected, 2).Clear(),
                     rows => rows.AsSpan(selected, 2).CopyTo(rows.AsSpan(selected + 104, 2)),
                     rows =>
                     {
                         var first = rows.AsSpan(0, 104).ToArray();
                         rows.AsSpan(104, 104).CopyTo(rows.AsSpan(0, 104));
                         first.CopyTo(rows.AsSpan(104, 104));
                     },
                     // The selected kind cannot borrow another subject, checkpoint or schema.
                     rows => rows[selected + 2] ^= 0x01,
                     rows => rows[selected + 34] ^= 0x01,
                     rows => rows[selected + 72] ^= 0x01,
                 })
        {
            var fields = Enumerable.Range(1, RecordDefinitions.Dcs1.Fields.Count)
                .Select(tag => (ReadOnlyMemory<byte>)original.FieldCopy(tag)).ToArray();
            var rows = fields[10].ToArray();
            mutate(rows);
            fields[10] = rows;
            var error = Assert.Throws<RecordException>(() =>
            {
                var canonical = CanonicalGrammar.Encode(RecordDefinitions.Dcs1, fields);
                var candidate = CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dcs1);
                CurrentCutoverVerifier.VerifyComponentRows(
                    candidate, dcm, dcmRef, dcp, dcpRef, ComponentKind.Registry);
            });
            Assert.Equal(RecordError.InvalidField, error.Error);
        }
    }

    [Fact]
    public async Task FirstDeploymentDcmIntent_UsesReservedResetGenerationOneAndZeroPredecessor()
    {
        var authored = await AuthorFirstOnlyAsync();
        var dcm = authored.Plan.Manifest.Record;

        Assert.Equal(authored.Reservation.ResetId.ToArray(), dcm.FieldSpan(2).ToArray());
        Assert.False(CanonicalGrammar.IsZero(dcm.FieldSpan(2)));
        Assert.Equal((ulong)1, Scalars.UInt64(dcm.FieldSpan(3)));
        Assert.Equal(authored.Branch.NewIdentity.Account.Certificate.AccountGeneration,
            Scalars.UInt64(dcm.FieldSpan(4)));
        Assert.True(CanonicalGrammar.IsZero(dcm.FieldSpan(13)));
        Assert.Equal(
            [GenesisOriginSignerRole.ResetControl, GenesisOriginSignerRole.AccountPossession],
            authored.Signer.Roles);
    }

    [Fact]
    public async Task SingleAuthorDcmPlan_IsExactDualSignedRelativeAndHasNoCommitCapability()
    {
        var authored = await AuthorFirstOnlyAsync();
        var plan = authored.Plan;

        Assert.True(plan.NoAuthorityClaim);
        Assert.Equal(812, plan.Manifest.CanonicalBytes.Length);
        Assert.Equal(DeploymentGovernanceRecords.GdiLength,
            plan.SignedAuthoringReceipt.Length);
        Assert.Equal(1, authored.Provider.PreparedCalls);
        Assert.Equal(1, authored.Provider.SignedCalls);
        Assert.Equal(2, authored.Signer.Roles.Count);
        Assert.True(typeof(GenesisSignedCutoverManifestPlan).IsSealed);
        Assert.Empty(typeof(GenesisSignedCutoverManifestPlan).GetConstructors(
            BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(typeof(GenesisSignedCutoverManifestPlan).GetMembers(
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly), member =>
            member.Name.Contains("Commit", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Publish", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Mutat", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task FirstDeploymentBranch_DerivesBootstrapScopeAndRestoresOneReservation()
    {
        var fixture = Fixture.Create();
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var identity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1));

        var branch = RecoveryVerifier.CreateFirstDeploymentCutoverBranch(governance, identity);
        var provider = new ScopedReservationProvider(fixture.Hmac);
        var reservation = await RecoveryVerifier.RestoreOrReserveGenesisResetIdByScopeAsync(
            branch, provider, fixture.Hmac);

        Assert.True(branch.NoAuthorityClaim);
        Assert.True(reservation.NoAuthorityClaim);
        Assert.Equal(1, provider.Calls);
        Assert.Equal(197, branch.ExactTranscript.Length);
        Assert.Equal(governance.DeploymentGovernanceBootstrapHash.ToArray(),
            branch.ExactTranscript.Slice(133, 32).ToArray());
        Assert.Equal(governance.DeploymentGovernanceBootstrapHash.ToArray(),
            branch.ExactTranscript.Slice(165, 32).ToArray());
        Assert.Equal(governance.DeploymentGovernanceBootstrapHash.ToArray(),
            branch.ReservationRequest.LogicalKey.Slice(17, 32).ToArray());
        Assert.Equal(32, reservation.ReservationHash.Length);
    }

    [Fact]
    public void ProtectedOriginRecords_EnforceExactLayoutsClosedPhasesAndBranchShapes()
    {
        var gar = OriginRecords.Gar();
        var preparedGdi = OriginRecords.Gdi(1, signed: false);
        var signedGdi = OriginRecords.Gdi(1, signed: true);
        var preparedGra = OriginRecords.Gra(signed: false);
        var signedGra = OriginRecords.Gra(signed: true);
        var committedGmd = OriginRecords.Gmd(1, 0, phase: 1);
        var distributedGmd = OriginRecords.Gmd(1, 0x0f, phase: 2);

        DeploymentGovernanceRecords.PreflightGar(gar, 100);
        DeploymentGovernanceRecords.PreflightGdi(preparedGdi, 100);
        DeploymentGovernanceRecords.PreflightGdi(signedGdi, 100);
        DeploymentGovernanceRecords.PreflightGra(preparedGra, 100);
        DeploymentGovernanceRecords.PreflightGra(signedGra, 100);
        DeploymentGovernanceRecords.PreflightGmd(committedGmd, 100);
        DeploymentGovernanceRecords.PreflightGmd(distributedGmd, 100);

        var partialPrepared = preparedGdi.ToArray();
        partialPrepared[73 + 684] = 1;
        Assert.Throws<RecordException>(() =>
            DeploymentGovernanceRecords.PreflightGdi(partialPrepared, 100));

        var sameWithoutPredecessor = OriginRecords.Gmd(2, 0, phase: 1);
        Array.Clear(sameWithoutPredecessor, 191, 38);
        Assert.Throws<RecordException>(() =>
            DeploymentGovernanceRecords.PreflightGmd(sameWithoutPredecessor, 100));

        var resetWithoutDra = OriginRecords.Gmd(3, 0, phase: 1);
        Array.Clear(resetWithoutDra, 229, 38);
        Assert.Throws<RecordException>(() =>
            DeploymentGovernanceRecords.PreflightGmd(resetWithoutDra, 100));

        var bitWithoutRevision = OriginRecords.Gmd(1, 1, phase: 1);
        Array.Clear(bitWithoutRevision, 301, 8);
        Assert.Throws<RecordException>(() =>
            DeploymentGovernanceRecords.PreflightGmd(bitWithoutRevision, 100));

        var distributedIncomplete = OriginRecords.Gmd(1, 7, phase: 2);
        Assert.Throws<RecordException>(() =>
            DeploymentGovernanceRecords.PreflightGmd(distributedIncomplete, 100));
    }

    [Fact]
    public void ProtectedOriginHashes_AreLengthFramedAndBranchClosed()
    {
        var gar = OriginRecords.Gar();
        var signedGdi = OriginRecords.Gdi(1, signed: true);
        var signedGra = OriginRecords.Gra(signed: true);
        var gdiHash = DeploymentGovernanceRecords.SignedGdiHash(signedGdi);
        var graHash = DeploymentGovernanceRecords.SignedGraHash(signedGra);

        Assert.Equal(32, DeploymentGovernanceRecords.GarReceiptHash(gar).Length);
        Assert.Equal(32, DeploymentGovernanceRecords.AuthorSetHash(3, gdiHash, graHash).Length);
        Assert.Equal(32, DeploymentGovernanceRecords.AuthorSetHash(1, gdiHash, new byte[32]).Length);
        Assert.Throws<RecordException>(() =>
            DeploymentGovernanceRecords.AuthorSetHash(1, gdiHash, graHash));
        Assert.Throws<RecordException>(() =>
            DeploymentGovernanceRecords.SignedGdiHash(signedGdi.AsSpan(1)));

        var first = new byte[197]; first[0] = 1;
        var same = new byte[203]; same[0] = 2;
        Assert.NotEqual(
            DeploymentGovernanceRecords.BranchHash(1, first),
            DeploymentGovernanceRecords.BranchHash(2, same));
        Assert.Throws<RecordException>(() =>
            DeploymentGovernanceRecords.BranchHash(3, first));
    }

    [Fact]
    public async Task ExactDgoDgi_RestoresSealedGovernanceWithTwoStableReads()
    {
        var fixture = Fixture.Create();
        var provider = new StableProvider(fixture.Dgo, fixture.Dgi);

        var restored = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, provider, fixture.Hmac, 100);

        Assert.True(restored.NoAuthorityClaim);
        Assert.Equal(1, provider.Mutations);
        Assert.Equal(1, provider.Reads);
        Assert.Equal((ulong)1, restored.SourceRevision);
        Assert.Equal((ulong)200, restored.RetainUntilUnixSeconds);
        Assert.Equal(fixture.BootstrapHash, restored.DeploymentGovernanceBootstrapHash);
        Assert.Equal(fixture.EnvironmentIndex, restored.EnvironmentIndex);
        Assert.Equal(32, restored.DeploymentGovernanceBootstrapHash.Length);
    }

    [Fact]
    public async Task EveryDuplicatedRrmAxisOrSignerSubstitutionRejects()
    {
        var fixture = Fixture.Create();
        foreach (var mutate in new Action<byte[]>[]
                 {
                     value => value[8] ^= 1,
                     value => value[31] ^= 1,
                     value => value[32] ^= 1,
                     value => value[71] ^= 1,
                     value => value[79] ^= 1,
                     value => value[250] ^= 1
                 })
        {
            var changed = fixture.Dgo.ToArray();
            mutate(changed);
            var provider = new StableProvider(changed, fixture.Dgi);
            await Assert.ThrowsAsync<RecordException>(() =>
                DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
                    fixture.ReleaseRoot, provider, fixture.Hmac, 100).AsTask());
            Assert.Equal(1, provider.Mutations);
            Assert.Equal(0, provider.Reads);
        }
    }

    [Fact]
    public async Task SourceMovementBetweenReadsRejectsWithoutMintingAContext()
    {
        var fixture = Fixture.Create();
        var changed = fixture.Dgi.ToArray();
        changed[85] ^= 1;
        var provider = new MovingProvider(fixture.Dgo, fixture.Dgi, changed);

        await Assert.ThrowsAsync<RecordException>(() =>
            DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
                fixture.ReleaseRoot, provider, fixture.Hmac, 100).AsTask());

        Assert.Equal(1, provider.Mutations);
        Assert.Equal(1, provider.Reads);
    }

    [Fact]
    public void DgoLayoutAndPin_Exact282MatchesOneSignedRrmTuple()
    {
        var fixture = Fixture.Create(verifyReleaseRoot: true);

        var relative = DeploymentGovernanceVerifier.VerifyRelative(
            fixture.ReleaseRoot, fixture.Dgo);
        var rrm = fixture.ReleaseRoot.Manifest.Record;

        Assert.Equal(DeploymentGovernanceRecords.DgoLength, relative.ExactDgo.Length);
        Assert.Equal("DGO1"u8.ToArray(), relative.ExactDgo.AsSpan(0, 4).ToArray());
        Assert.Equal((byte)1, relative.ExactDgo[4]);
        Assert.True(relative.ExactDgo.AsSpan(5, 3).IndexOfAnyExcept((byte)0) < 0);
        Assert.Equal(rrm.FieldSpan(1).ToArray(), relative.ExactDgo.AsSpan(8, 16).ToArray());
        Assert.Equal(rrm.FieldSpan(2).ToArray(), relative.ExactDgo.AsSpan(24, 8).ToArray());
        Assert.Equal(rrm.FieldSpan(3).ToArray(), relative.ExactDgo.AsSpan(32, 32).ToArray());
        Assert.Equal(rrm.FieldSpan(6).ToArray(), relative.ExactDgo.AsSpan(64, 8).ToArray());
        Assert.Equal(rrm.FieldSpan(7).ToArray(), relative.ExactDgo.AsSpan(72, 8).ToArray());
        Assert.Equal(fixture.ReleaseRoot.Pin.ManifestSignerEd25519PublicKey.ToArray(),
            relative.ExactDgo.AsSpan(250, 32).ToArray());
    }

    [Fact]
    public void DgoRrmSchemaBinding_RejectsEveryAxisSignerSchemaAndRowOrderSubstitution()
    {
        var fixture = Fixture.Create(verifyReleaseRoot: true);
        var substitutions = new (int Offset, int Other)[]
        {
            (8, -1), (24, -1), (32, -1), (64, -1), (72, -1), (250, -1),
            (82, 124)
        };

        foreach (var (offset, other) in substitutions)
        {
            var changed = fixture.Dgo.ToArray();
            if (other < 0) changed[offset] ^= 1;
            else
            {
                var row = changed.AsSpan(offset, 42).ToArray();
                changed.AsSpan(other, 42).CopyTo(changed.AsSpan(offset, 42));
                row.CopyTo(changed, other);
            }
            Assert.Throws<RecordException>(() =>
                DeploymentGovernanceVerifier.VerifyRelative(fixture.ReleaseRoot, changed));
        }

        var relative = DeploymentGovernanceVerifier.VerifyRelative(
            fixture.ReleaseRoot, fixture.Dgo);
        Assert.Equal(fixture.ReleaseRoot.Manifest.Record.FieldSpan(8).ToArray(),
            relative.DgoHash);
    }

    [Fact]
    public async Task BootstrapEnvironmentIndex_UsesOneRestoreOrCreateAndOneFreshReread()
    {
        var fixture = Fixture.Create(verifyReleaseRoot: true);
        var provider = new StableProvider(fixture.Dgo, fixture.Dgi);

        var context = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, provider, fixture.Hmac, 100);

        Assert.Equal(1, provider.Mutations);
        Assert.Equal(1, provider.Reads);
        Assert.Equal(fixture.EnvironmentIndex, provider.LastEnvironmentIndex);
        Assert.Equal(fixture.EnvironmentIndex, context.EnvironmentIndex.ToArray());
        Assert.Equal(fixture.BootstrapHash,
            context.DeploymentGovernanceBootstrapHash.ToArray());
    }

    [Fact]
    public void RelativeRrmAndGovernanceFacts_ExposeNoAuthorityOrRawConstruction()
    {
        var fixture = Fixture.Create(verifyReleaseRoot: true);
        var relative = DeploymentGovernanceVerifier.VerifyRelative(
            fixture.ReleaseRoot, fixture.Dgo);

        Assert.False(typeof(VerifiedDeploymentGovernanceRelative).IsPublic);
        Assert.True(typeof(VerifiedDeploymentGovernanceContext).IsSealed);
        Assert.Empty(typeof(VerifiedDeploymentGovernanceContext).GetConstructors(
            BindingFlags.Public | BindingFlags.Instance));
        Assert.True(fixture.ReleaseRoot.NoAuthorityClaim);
        Assert.DoesNotContain(typeof(VerifiedDeploymentGovernanceContext).GetMembers(
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly), member =>
            member.Name.Contains("Sign", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Commit", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Publish", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Mutat", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(fixture.Dgo, relative.ExactDgo);
    }

    [Fact]
    public async Task DgiRemint_Exact160OneMutationFreshRereadAndForkRejects()
    {
        var fixture = Fixture.Create(verifyReleaseRoot: true);
        var provider = new StableProvider(fixture.Dgo, fixture.Dgi);

        var context = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, provider, fixture.Hmac, 100);

        Assert.Equal(DeploymentGovernanceRecords.DgiLength, context.ExactDgi.Length);
        Assert.Equal(fixture.Dgi, context.ExactDgi.ToArray());
        Assert.Equal(1, provider.Mutations);
        Assert.Equal(1, provider.Reads);

        foreach (var mutate in new Action<byte[]>[]
                 {
                     value => value[0] ^= 1,
                     value => value[4] ^= 1,
                     value => value[5] = 1,
                     value => value[85] = 0,
                     value => value[94] = 0,
                     value => value[95] = 1
                 })
        {
            var malformed = fixture.Dgi.ToArray();
            mutate(malformed);
            Assert.Throws<RecordException>(() =>
                DeploymentGovernanceRecords.PreflightDgi(malformed, 100));
        }

        var moved = fixture.Dgi.ToArray();
        moved[85] ^= 1;
        var forked = new MovingProvider(fixture.Dgo, fixture.Dgi, moved);
        await Assert.ThrowsAsync<RecordException>(() =>
            DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
                fixture.ReleaseRoot, forked, fixture.Hmac, 100).AsTask());
        Assert.Equal(1, forked.Mutations);
        Assert.Equal(1, forked.Reads);
    }

    [Fact]
    public void BranchTranscripts_AreExactDistinctAndBootstrapSourced()
    {
        var fixture = Fixture.Create();
        var governance = new VerifiedDeploymentGovernanceContext(
            fixture.ReleaseRoot, fixture.Dgo, fixture.Dgi, fixture.BootstrapHash,
            fixture.EnvironmentIndex);
        var identity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1));
        var first = RecoveryVerifier.CreateFirstDeploymentCutoverBranch(governance, identity);
        var same = new byte[203];
        same[0] = 2;
        fixture.ReleaseRoot.Manifest.Record.FieldSpan(1).CopyTo(same.AsSpan(1, 16));
        Fill(0x31, 32).CopyTo(same, 171);
        var reset = new byte[65];
        reset[0] = 3;
        Fill(0x32, 32).CopyTo(reset, 1);
        fixture.BootstrapHash.CopyTo(reset, 33);

        Assert.Equal(197, first.ExactTranscript.Length);
        Assert.Equal(fixture.BootstrapHash, first.ExactTranscript.Slice(133, 32).ToArray());
        Assert.Equal(fixture.BootstrapHash, first.ExactTranscript.Slice(165, 32).ToArray());
        var firstHash = DeploymentGovernanceRecords.BranchHash(1, first.ExactTranscript);
        var sameHash = DeploymentGovernanceRecords.BranchHash(2, same);
        var resetHash = DeploymentGovernanceRecords.BranchHash(3, reset);
        Assert.Equal(3, new[] { Convert.ToHexString(firstHash), Convert.ToHexString(sameHash),
            Convert.ToHexString(resetHash) }.Distinct(StringComparer.Ordinal).Count());
        Assert.Throws<RecordException>(() =>
            DeploymentGovernanceRecords.BranchHash(2, first.ExactTranscript));
        Assert.Throws<RecordException>(() => DeploymentGovernanceRecords.BranchHash(1, same));
        Assert.Throws<RecordException>(() => DeploymentGovernanceRecords.BranchHash(2, reset));
    }

    [Fact]
    public async Task GdiPreparedSigned_UsesZeroThenCompleteSignaturesAndOneAtomicCas()
    {
        var authored = await AuthorFirstOnlyAsync();

        Assert.Equal(1, authored.Provider.PreparedCalls);
        Assert.Equal(1, authored.Provider.SignedCalls);
        Assert.NotNull(authored.Provider.PreparedRecord);
        Assert.NotNull(authored.Provider.SignedRecord);
        Assert.Equal((byte)1, authored.Provider.PreparedRecord![965]);
        var preparedDcm = CanonicalGrammar.DecodeOwned(
            authored.Provider.PreparedRecord.AsSpan(73, 812), RecordDefinitions.Dcm1);
        Assert.True(preparedDcm.FieldSpan(18).IndexOfAnyExcept((byte)0) < 0);
        Assert.True(preparedDcm.FieldSpan(19).IndexOfAnyExcept((byte)0) < 0);
        Assert.Equal((byte)2, authored.Provider.SignedRecord![965]);
        var signedDcm = CanonicalGrammar.DecodeOwned(
            authored.Provider.SignedRecord.AsSpan(73, 812), RecordDefinitions.Dcm1);
        Assert.True(signedDcm.FieldSpan(18).IndexOfAnyExcept((byte)0) >= 0);
        Assert.True(signedDcm.FieldSpan(19).IndexOfAnyExcept((byte)0) >= 0);
        Assert.Equal(authored.Plan.SignedAuthoringReceipt.ToArray(),
            authored.Provider.SignedRecord);
    }

    [Fact]
    public async Task StandaloneDcmRelative_FirstDeploymentVerifiesExactDualSignedPlanWithoutMutation()
    {
        var authored = await AuthorFirstOnlyAsync();

        var relative = RecoveryVerifier.VerifyCutoverManifestRelative(
            authored.Branch, authored.Reservation, authored.Plan.Manifest.CanonicalBytes.Span);

        Assert.True(relative.NoAuthorityClaim);
        Assert.Equal(812, relative.Manifest.CanonicalBytes.Length);
        Assert.Equal(authored.Plan.Manifest.CanonicalBytes.ToArray(),
            relative.Manifest.CanonicalBytes.ToArray());
        Assert.Empty(typeof(VerifiedCutoverManifestRelative).GetConstructors());
        Assert.DoesNotContain(typeof(VerifiedCutoverManifestRelative).GetProperties(),
            property => property.Name.Contains("Authority", StringComparison.OrdinalIgnoreCase) &&
                property.Name != nameof(VerifiedCutoverManifestRelative.NoAuthorityClaim));
        Assert.DoesNotContain(typeof(VerifiedCutoverManifestRelative).GetMethods(), method =>
            method.Name.Contains("Commit", StringComparison.OrdinalIgnoreCase) ||
            method.Name.Contains("Persist", StringComparison.OrdinalIgnoreCase) ||
            method.Name.Contains("Distribute", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task StandaloneDcmRelative_FirstIntentBindsReservationGenerationAndZeroPredecessor()
    {
        var authored = await AuthorFirstOnlyAsync();
        var relative = RecoveryVerifier.VerifyCutoverManifestRelative(
            authored.Branch, authored.Reservation, authored.Plan.Manifest.CanonicalBytes.Span);
        var dcm = relative.Manifest.Record;

        Assert.Equal(authored.Reservation.ResetId.ToArray(), dcm.FieldSpan(2).ToArray());
        Assert.Equal((ulong)1, Scalars.UInt64(dcm.FieldSpan(3)));
        Assert.True(CanonicalGrammar.IsZero(dcm.FieldSpan(13)));
        Assert.Equal(authored.Reservation.OperationId.ToArray(), dcm.FieldSpan(17).ToArray());
    }

    [Fact]
    public async Task StandaloneDcmRelative_SameAccountBindsCurrentResetSuccessorAndPredecessor()
    {
        var fixture = Fixture.Create();
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var account = PublicKeyAuth.GenerateKeyPair();
        var reset = PublicKeyAuth.GenerateKeyPair();
        var identity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1),
            account.PublicKey, reset.PublicKey, 1, Fill(0xb1, 32));
        var priorDcm = SignedDcm(identity, governance, account.PrivateKey, reset.PrivateKey,
            Fill(0xb2, 32), Fill(0xb3, 32));
        var current = Current(identity, priorDcm);
        var branch = RecoveryVerifier.CreateSameAccountCutoverBranch(governance, identity, current);
        var signed = await RecoveryVerifier.AuthorSameAccountCutoverManifestAsync(branch,
            new SameOperationProvider(), new DcmProvider(fixture.Hmac),
            new OriginSigner(account.PrivateKey, reset.PrivateKey), fixture.Hmac, 101);

        var relative = RecoveryVerifier.VerifyCutoverManifestRelative(
            branch, signed.Manifest.CanonicalBytes.Span);
        var dcm = relative.Manifest.Record;

        Assert.Equal(CutoverCodec.DecodeManifest(priorDcm).ResetId.ToArray(),
            dcm.FieldSpan(2).ToArray());
        Assert.Equal((ulong)2, Scalars.UInt64(dcm.FieldSpan(3)));
        Assert.Equal(current.TrustedDcmRef.ToArray(), dcm.FieldSpan(13).ToArray());
    }

    [Fact]
    public async Task StandaloneDcmRelative_CrossBranchAxesRejectBeforeSignatureValidation()
    {
        var authored = await AuthorFirstOnlyAsync();
        var signed = CanonicalGrammar.DecodeOwned(
            authored.Plan.Manifest.CanonicalBytes.Span, RecordDefinitions.Dcm1);

        foreach (var field in new[] { 2, 3, 4, 13 })
        {
            var fields = Enumerable.Range(1, 19)
                .Select(index => (ReadOnlyMemory<byte>)signed.FieldSpan(index).ToArray()).ToArray();
            fields[field - 1] = field == 13 ? Fill(0xd1, 38) :
                field is 3 or 4 ? U64(9) : Fill(0xd2, fields[field - 1].Length);
            var crossed = CanonicalGrammar.Encode(RecordDefinitions.Dcm1, fields);

            var error = Assert.Throws<RecordException>(() =>
                RecoveryVerifier.VerifyCutoverManifestRelative(
                    authored.Branch, authored.Reservation, crossed));
            Assert.Equal(RecordError.InvalidField, error.Error);
        }

        var wrongBranch = Assert.Throws<RecordException>(() =>
            RecoveryVerifier.VerifyCutoverManifestRelative(
                authored.Branch, authored.Plan.Manifest.CanonicalBytes.Span));
        Assert.Equal(RecordError.InvalidField, wrongBranch.Error);
    }

    [Fact]
    public async Task GdiSignerOrder_UsesOneFrozenTranscriptStableKeysAndZeroCallbackReplay()
    {
        var authored = await AuthorFirstOnlyAsync();

        Assert.Equal(
            [GenesisOriginSignerRole.ResetControl, GenesisOriginSignerRole.AccountPossession],
            authored.Signer.Roles);
        Assert.Equal(2, authored.Signer.Requests.Count);
        Assert.All(authored.Signer.Requests,
            request => Assert.Equal(ArtifactType.Dcm1, request.ArtifactType));
        Assert.Equal(authored.Signer.Requests[0].OperationId.ToArray(),
            authored.Signer.Requests[1].OperationId.ToArray());
        Assert.Equal(authored.Signer.Requests[0].SigningHash.ToArray(),
            authored.Signer.Requests[1].SigningHash.ToArray());
        Assert.Equal(authored.Signer.Requests[0].SigningBytes.ToArray(),
            authored.Signer.Requests[1].SigningBytes.ToArray());

        var replaySigner = new OriginSigner(authored.Account.PrivateKey,
            authored.Reset.PrivateKey);
        var replay = await RecoveryVerifier.AuthorCutoverManifestAsync(authored.Branch,
            authored.Reservation, authored.ReservationProvider,
            new SignedReplayDcmProvider(authored.Plan.SignedAuthoringReceipt.ToArray()),
            replaySigner, authored.Fixture.Hmac, 101);
        Assert.Empty(replaySigner.Requests);
        Assert.Equal(authored.Plan.Manifest.CanonicalBytes.ToArray(),
            replay.Manifest.CanonicalBytes.ToArray());
    }

    [Fact]
    public async Task DcmDualSignerMutationWrongKeyMalformedAndCancellationReturnNoPlan()
    {
        var valid = await AuthorFirstOnlyAsync();
        Assert.Equal(2, valid.Signer.Requests.Count);
        Assert.Equal(valid.Signer.Requests[0].SigningBytes.ToArray(),
            valid.Signer.Requests[1].SigningBytes.ToArray());
        Assert.Equal(valid.Signer.Requests[0].SigningHash.ToArray(),
            valid.Signer.Requests[1].SigningHash.ToArray());
        Assert.Equal(
            [GenesisOriginSignerRole.ResetControl, GenesisOriginSignerRole.AccountPossession],
            valid.Signer.Roles);
        Assert.Equal(812, valid.Plan.Manifest.CanonicalBytes.Length);

        foreach (var fault in Enum.GetValues<OriginSignerFault>())
        {
            GenesisSignedCutoverManifestPlan? escaped = null;
            var error = await Xunit.Record.ExceptionAsync(async () =>
                escaped = await AuthorFirstWithSignerAsync((account, reset) =>
                    new FaultingOriginSigner(account, reset, fault)));
            Assert.Null(escaped);
            Assert.NotNull(error);
            if (fault == OriginSignerFault.Cancel)
                Assert.IsAssignableFrom<OperationCanceledException>(error);
            else
                Assert.IsType<RecordException>(error);
        }
    }

    private static async Task<GenesisSignedCutoverManifestPlan> AuthorFirstWithSignerAsync(
        Func<byte[], byte[], GenesisOriginSigner> signerFactory)
    {
        var fixture = Fixture.Create();
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var account = PublicKeyAuth.GenerateKeyPair();
        var reset = PublicKeyAuth.GenerateKeyPair();
        var identity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1),
            account.PublicKey, reset.PublicKey);
        var branch = RecoveryVerifier.CreateFirstDeploymentCutoverBranch(governance, identity);
        var reservationProvider = new ScopedReservationProvider(fixture.Hmac);
        var reservation = await RecoveryVerifier.RestoreOrReserveGenesisResetIdByScopeAsync(
            branch, reservationProvider, fixture.Hmac);
        return await RecoveryVerifier.AuthorCutoverManifestAsync(branch, reservation,
            reservationProvider, new DcmProvider(fixture.Hmac),
            signerFactory(account.PrivateKey, reset.PrivateKey), fixture.Hmac, 101);
    }

    private static async Task<FirstAuthorFixture> AuthorFirstOnlyAsync()
    {
        var fixture = Fixture.Create();
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var account = PublicKeyAuth.GenerateKeyPair();
        var reset = PublicKeyAuth.GenerateKeyPair();
        var identity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1),
            account.PublicKey, reset.PublicKey);
        var branch = RecoveryVerifier.CreateFirstDeploymentCutoverBranch(governance, identity);
        var reservationProvider = new ScopedReservationProvider(fixture.Hmac);
        var reservation = await RecoveryVerifier.RestoreOrReserveGenesisResetIdByScopeAsync(
            branch, reservationProvider, fixture.Hmac);
        var provider = new DcmProvider(fixture.Hmac);
        var signer = new OriginSigner(account.PrivateKey, reset.PrivateKey);
        var plan = await RecoveryVerifier.AuthorCutoverManifestAsync(branch, reservation,
            reservationProvider, provider, signer, fixture.Hmac, 101);
        return new FirstAuthorFixture(fixture, account, reset, branch, reservation,
            reservationProvider, provider, signer, plan);
    }

    private sealed record FirstAuthorFixture(Fixture Fixture, KeyPair Account, KeyPair Reset,
        GenesisCutoverBranchContext Branch, GenesisResetReservationResult Reservation,
        ScopedReservationProvider ReservationProvider, DcmProvider Provider, OriginSigner Signer,
        GenesisSignedCutoverManifestPlan Plan);

    [Fact]
    public async Task GraPreparedSigned_UsesZeroThenCompleteSignaturesAndOneAtomicCas()
    {
        var authored = await AuthorResetThroughGraAsync();

        Assert.Equal(1, authored.Provider.PreparedCalls);
        Assert.Equal(1, authored.Provider.SignedCalls);
        Assert.NotNull(authored.Provider.PreparedRecord);
        Assert.NotNull(authored.Provider.SignedRecord);
        Assert.Equal((byte)1, authored.Provider.PreparedRecord![914]);
        var preparedDra = CanonicalGrammar.DecodeOwned(
            authored.Provider.PreparedRecord.AsSpan(78, 788), RecordDefinitions.Dra1);
        Assert.True(preparedDra.FieldSpan(19).IndexOfAnyExcept((byte)0) < 0);
        Assert.True(preparedDra.FieldSpan(20).IndexOfAnyExcept((byte)0) < 0);
        Assert.True(preparedDra.FieldSpan(21).IndexOfAnyExcept((byte)0) < 0);
        Assert.Equal((byte)2, authored.Provider.SignedRecord![914]);
        var signedDra = CanonicalGrammar.DecodeOwned(
            authored.Provider.SignedRecord.AsSpan(78, 788), RecordDefinitions.Dra1);
        Assert.True(signedDra.FieldSpan(19).IndexOfAnyExcept((byte)0) >= 0);
        Assert.True(signedDra.FieldSpan(20).IndexOfAnyExcept((byte)0) >= 0);
        Assert.True(signedDra.FieldSpan(21).IndexOfAnyExcept((byte)0) >= 0);
    }

    [Fact]
    public async Task GraSignerOrder_UsesOneFrozenTranscriptStableKeysAndZeroCallbackReplay()
    {
        var authored = await AuthorResetThroughGraAsync();

        Assert.Equal(
            [GenesisOriginSignerRole.OldResetControl,
             GenesisOriginSignerRole.AccountPossession,
             GenesisOriginSignerRole.ResetControl], authored.Signer.Roles);
        Assert.Equal(3, authored.Signer.Requests.Count);
        Assert.All(authored.Signer.Requests,
            request => Assert.Equal(ArtifactType.Dra1, request.ArtifactType));
        Assert.Single(authored.Signer.Requests.Select(request =>
            Convert.ToHexString(request.OperationId.Span)).Distinct(StringComparer.Ordinal));
        Assert.Single(authored.Signer.Requests.Select(request =>
            Convert.ToHexString(request.SigningHash.Span)).Distinct(StringComparer.Ordinal));
        Assert.Single(authored.Signer.Requests.Select(request =>
            Convert.ToHexString(request.SigningBytes.Span)).Distinct(StringComparer.Ordinal));

        var replaySigner = new ResetSigner(authored.OldReset.PrivateKey,
            authored.NewAccount.PrivateKey, authored.NewReset.PrivateKey);
        var replay = await RecoveryVerifier.AuthorAccountResetAsync(authored.SignedDcm,
            authored.GarProvider,
            new SignedReplayGraProvider(authored.Plan.SignedResetAuthoringReceipt.ToArray()),
            replaySigner, authored.Fixture.Hmac, 101);
        Assert.Empty(replaySigner.Requests);
        Assert.Equal(authored.Plan.Authorization.CanonicalBytes.ToArray(),
            replay.Authorization.CanonicalBytes.ToArray());
    }

    [Fact]
    public async Task StandaloneResetRelative_VerifiesNewDcmThenExactThreeSignatureDraWithoutMutation()
    {
        var authored = await AuthorResetThroughGraAsync();
        var relativeDcm = RecoveryVerifier.VerifyCutoverManifestRelative(
            authored.Branch, authored.Reservation,
            authored.SignedDcm.Manifest.CanonicalBytes.Span);

        var relativeDra = RecoveryVerifier.VerifyAccountResetRelative(
            authored.Origin, relativeDcm,
            authored.Plan.Authorization.CanonicalBytes.Span);

        Assert.True(relativeDcm.NoAuthorityClaim);
        Assert.True(relativeDra.NoAuthorityClaim);
        Assert.Same(relativeDcm, relativeDra.Cutover);
        Assert.Equal(788, relativeDra.Authorization.CanonicalBytes.Length);
        Assert.Equal(authored.Plan.Authorization.CanonicalBytes.ToArray(),
            relativeDra.Authorization.CanonicalBytes.ToArray());
        Assert.Empty(typeof(VerifiedAccountResetAuthorizationRelative).GetConstructors());
        Assert.DoesNotContain(typeof(VerifiedAccountResetAuthorizationRelative).GetMethods(),
            method => method.Name.Contains("Commit", StringComparison.OrdinalIgnoreCase) ||
                method.Name.Contains("Persist", StringComparison.OrdinalIgnoreCase) ||
                method.Name.Contains("Distribute", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ResetDraOldNewPop_BindsExactThreeAuthoritiesAndOneSignedCas()
    {
        var authored = await AuthorResetThroughGraAsync();
        var dra = authored.Plan.Authorization.Record;

        Assert.Equal(1, authored.Provider.PreparedCalls);
        Assert.Equal(1, authored.Provider.SignedCalls);
        Assert.Equal(
            [GenesisOriginSignerRole.OldResetControl,
             GenesisOriginSignerRole.AccountPossession,
             GenesisOriginSignerRole.ResetControl],
            authored.Signer.Roles);
        Assert.Equal(SHA256.HashData(authored.OldReset.PublicKey),
            dra.FieldSpan(16).ToArray());
        Assert.Equal(SHA256.HashData(authored.NewAccount.PublicKey),
            dra.FieldSpan(17).ToArray());
        Assert.Equal(SHA256.HashData(authored.NewReset.PublicKey),
            dra.FieldSpan(18).ToArray());
        Assert.Equal((byte)2, authored.Plan.SignedResetAuthoringReceipt.Span[914]);
    }

    [Fact]
    public async Task ResetOriginComplete_Exact588AndThreeSignatureRelativeCheckUseNoMutation()
    {
        var authored = await AuthorResetThroughGraAsync();
        var mutationsBefore = authored.GarProvider.Mutations;
        var transcript = authored.Origin.ExactTranscript.Span;
        var relativeDcm = RecoveryVerifier.VerifyCutoverManifestRelative(
            authored.Branch, authored.Reservation,
            authored.SignedDcm.Manifest.CanonicalBytes.Span);

        var relativeDra = RecoveryVerifier.VerifyAccountResetRelative(
            authored.Origin, relativeDcm,
            authored.Plan.Authorization.CanonicalBytes.Span);

        Assert.Equal(588, transcript.Length);
        Assert.Equal((ulong)1, BinaryPrimitives.ReadUInt64BigEndian(transcript.Slice(16, 8)));
        Assert.Equal((ulong)2, BinaryPrimitives.ReadUInt64BigEndian(transcript.Slice(304, 8)));
        Assert.Equal((ulong)99, BinaryPrimitives.ReadUInt64BigEndian(transcript.Slice(578, 8)));
        Assert.Equal((ushort)ResetReason.KeyCompromise,
            BinaryPrimitives.ReadUInt16BigEndian(transcript.Slice(586, 2)));
        Assert.False(CanonicalGrammar.IsZero(transcript.Slice(24, 32)));
        Assert.False(CanonicalGrammar.IsZero(transcript.Slice(272, 32)));
        Assert.False(CanonicalGrammar.IsZero(transcript.Slice(312, 32)));
        Assert.False(CanonicalGrammar.IsZero(transcript.Slice(514, 32)));
        Assert.True(relativeDra.NoAuthorityClaim);
        Assert.Equal(mutationsBefore, authored.GarProvider.Mutations);
    }

    [Fact]
    public async Task AccountTerminalFence_RejectsGenesisBranchButAllowsOnlyVerifiedResetOldSide()
    {
        var fixture = Fixture.Create();
        var governanceProvider = new StableProvider(fixture.Dgo, fixture.Dgi);
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, governanceProvider, fixture.Hmac, 100);
        var account = PublicKeyAuth.GenerateKeyPair();
        var reset = PublicKeyAuth.GenerateKeyPair();
        var terminal = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1),
            account.PublicKey, reset.PublicKey, 1, Fill(0xf1, 32), terminal: true);
        var oldDcm = SignedDcm(terminal, governance, account.PrivateKey, reset.PrivateKey,
            Fill(0xf2, 32), Fill(0xf3, 32));
        var readsBefore = governanceProvider.Reads;
        var mutationsBefore = governanceProvider.Mutations;
        var hmacBefore = fixture.Hmac.Requests.Count;

        var error = Assert.Throws<RecordException>(() =>
            RecoveryVerifier.CreateFirstDeploymentCutoverBranch(governance, terminal));
        var oldSide = RecoveryVerifier.VerifyAccountResetOldCutover(terminal, oldDcm);

        Assert.Equal(RecordError.InvalidField, error.Error);
        Assert.Equal(readsBefore, governanceProvider.Reads);
        Assert.Equal(mutationsBefore, governanceProvider.Mutations);
        Assert.Equal(hmacBefore, fixture.Hmac.Requests.Count);
        Assert.True(oldSide.NoAuthorityClaim);
        Assert.Empty(typeof(VerifiedAccountResetOldCutover)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public async Task StandaloneResetRelative_CrossFedDraAxisRejectsBeforeSignatureValidation()
    {
        var authored = await AuthorResetThroughGraAsync();
        var relativeDcm = RecoveryVerifier.VerifyCutoverManifestRelative(
            authored.Branch, authored.Reservation,
            authored.SignedDcm.Manifest.CanonicalBytes.Span);
        var signed = CanonicalGrammar.DecodeOwned(
            authored.Plan.Authorization.CanonicalBytes.Span, RecordDefinitions.Dra1);

        foreach (var field in new[] { 2, 5, 9, 12, 13, 14, 15 })
        {
            var fields = Enumerable.Range(1, 21)
                .Select(index => (ReadOnlyMemory<byte>)signed.FieldSpan(index).ToArray()).ToArray();
            fields[field - 1] = field is 2 or 9 or 13
                ? U64(77)
                : field == 15
                    ? new byte[] { 0, (byte)ResetReason.AdministrativeReset }
                    : Fill(0xe1, fields[field - 1].Length);
            var crossed = CanonicalGrammar.Encode(RecordDefinitions.Dra1, fields);

            var error = Assert.Throws<RecordException>(() =>
                RecoveryVerifier.VerifyAccountResetRelative(
                    authored.Origin, relativeDcm, crossed));
            Assert.Equal(RecordError.InvalidField, error.Error);
        }
    }

    [Fact]
    public async Task StandaloneRelativeVerifierApi_ExposesOnlyDcmDraDwhFactsWithoutGraphAuthority()
    {
        // Arrange the already verified DCM-relative prerequisite. The measured API boundary below
        // has no authoring, persistence, graph-restore, or consumer-mutation provider parameter.
        var authored = await AuthorResetThroughGraAsync();
        var relativeDcm = RecoveryVerifier.VerifyCutoverManifestRelative(
            authored.Branch, authored.Reservation,
            authored.SignedDcm.Manifest.CanonicalBytes.Span);

        var relativeDra = RecoveryVerifier.VerifyAccountResetRelative(
            authored.Origin, relativeDcm,
            authored.Plan.Authorization.CanonicalBytes.Span);
        var relativeDwh = await IdentityAuthorityTests
            .VerifyGenesisDwhRelativeForEvidenceAsync();

        Assert.True(relativeDcm.NoAuthorityClaim);
        Assert.True(relativeDra.NoAuthorityClaim);
        Assert.True(relativeDwh.NoAuthorityClaim);
        foreach (var type in new[]
        {
            typeof(VerifiedCutoverManifestRelative),
            typeof(VerifiedAccountResetAuthorizationRelative),
            typeof(VerifiedWitnessHeadHistoryRelative)
        })
        {
            Assert.True(type.IsSealed);
            Assert.Empty(type.GetConstructors());
            Assert.DoesNotContain(type.GetMethods(), method =>
                method.Name.Contains("Commit", StringComparison.OrdinalIgnoreCase) ||
                method.Name.Contains("Persist", StringComparison.OrdinalIgnoreCase) ||
                method.Name.Contains("Activate", StringComparison.OrdinalIgnoreCase) ||
                method.Name.Contains("Publish", StringComparison.OrdinalIgnoreCase));
        }

        var verifierMethods = typeof(RecoveryVerifier).GetMethods(BindingFlags.Public |
            BindingFlags.Static).Where(method => method.Name is
                nameof(RecoveryVerifier.VerifyCutoverManifestRelative) or
                nameof(RecoveryVerifier.VerifyAccountResetRelative) or
                nameof(RecoveryVerifier.VerifyWitnessHeadHistoryRelativeAsync)).ToArray();
        Assert.NotEmpty(verifierMethods);
        Assert.All(verifierMethods, method => Assert.DoesNotContain(method.GetParameters(),
            parameter => typeof(GenesisDcmAuthoringProvider).IsAssignableFrom(parameter.ParameterType) ||
                typeof(GenesisResetAuthoringProvider).IsAssignableFrom(parameter.ParameterType) ||
                typeof(GenesisManifestDistributionProvider).IsAssignableFrom(parameter.ParameterType)));
    }

    [Fact]
    public async Task GmdBitmapRevision_CrossBranchPreBitAndNonmonotonicAdvanceRejectWithOneCas()
    {
        var authored = await AuthorFirstOnlyAsync();

        var crossedHash = authored.Branch.BranchHash.ToArray(); crossedHash[0] ^= 1;
        var crossed = new DistributionProvider(authored.Fixture.Hmac,
            overrideBranchHash: crossedHash);
        var crossedComponents = new ComponentDistributor();
        await Assert.ThrowsAsync<RecordException>(() =>
            RecoveryVerifier.DistributeCutoverManifestAsync(authored.Plan,
                authored.ReservationProvider, crossed, crossedComponents,
                authored.Fixture.Hmac, 101).AsTask());
        Assert.Equal(1, crossed.CommitCalls);
        Assert.Equal(0, crossed.AdvanceCalls);
        Assert.Equal(0, crossedComponents.Deliveries);

        var preBit = new DistributionProvider(authored.Fixture.Hmac, initialBitmap: 1);
        var missingStoredTuple = new ComponentDistributor(missingRereadKind: ComponentKind.Registry);
        await Assert.ThrowsAsync<RecordException>(() =>
            RecoveryVerifier.DistributeCutoverManifestAsync(authored.Plan,
                authored.ReservationProvider, preBit, missingStoredTuple,
                authored.Fixture.Hmac, 101).AsTask());
        Assert.Equal(1, preBit.CommitCalls);
        Assert.Equal(0, preBit.AdvanceCalls);
        Assert.Equal(0, missingStoredTuple.Deliveries);
        Assert.Equal(1, missingStoredTuple.Rereads);

        var nonmonotonic = new DistributionProvider(authored.Fixture.Hmac,
            nonmonotonicAdvance: true);
        var oneDelivery = new ComponentDistributor();
        await Assert.ThrowsAsync<RecordException>(() =>
            RecoveryVerifier.DistributeCutoverManifestAsync(authored.Plan,
                authored.ReservationProvider, nonmonotonic, oneDelivery,
                authored.Fixture.Hmac, 101).AsTask());
        Assert.Equal(1, nonmonotonic.CommitCalls);
        Assert.Equal(1, nonmonotonic.AdvanceCalls);
        Assert.Equal(1, oneDelivery.Deliveries);
    }

    private static async Task<ResetAuthorFixture> AuthorResetThroughGraAsync()
    {
        var fixture = Fixture.Create();
        var governance = await DeploymentGovernanceVerifier.RestoreDeploymentGovernanceAsync(
            fixture.ReleaseRoot, new StableProvider(fixture.Dgo, fixture.Dgi), fixture.Hmac, 100);
        var oldAccount = PublicKeyAuth.GenerateKeyPair();
        var oldReset = PublicKeyAuth.GenerateKeyPair();
        var newAccount = PublicKeyAuth.GenerateKeyPair();
        var newReset = PublicKeyAuth.GenerateKeyPair();
        var oldIdentity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1),
            oldAccount.PublicKey, oldReset.PublicKey, 1, Fill(0x91, 32), terminal: true);
        var oldDcm = SignedDcm(oldIdentity, governance, oldAccount.PrivateKey,
            oldReset.PrivateKey, Fill(0x93, 32), Fill(0x94, 32));
        var oldCutover = RecoveryVerifier.VerifyAccountResetOldCutover(oldIdentity, oldDcm);
        var newIdentity = Identity(fixture.ReleaseRoot.Manifest.Record.FieldSpan(1),
            newAccount.PublicKey, newReset.PublicKey, 2, Fill(0x92, 32));
        var garProvider = new GarProvider(fixture.Hmac);
        var origin = await RecoveryVerifier.RestoreOrCreateAccountResetOriginAsync(
            oldCutover, newIdentity, governance, 99, ResetReason.KeyCompromise,
            garProvider, fixture.Hmac, 100);
        var branch = RecoveryVerifier.CreateAccountResetCutoverBranch(origin);
        var reservationProvider = new ScopedReservationProvider(fixture.Hmac);
        var reservation = await RecoveryVerifier.RestoreOrReserveGenesisResetIdByScopeAsync(
            branch, reservationProvider, fixture.Hmac);
        var signedDcm = await RecoveryVerifier.AuthorCutoverManifestAsync(branch, reservation,
            reservationProvider, new DcmProvider(fixture.Hmac),
            new OriginSigner(newAccount.PrivateKey, newReset.PrivateKey), fixture.Hmac, 101);
        var provider = new GraProvider(fixture.Hmac);
        var signer = new ResetSigner(oldReset.PrivateKey, newAccount.PrivateKey,
            newReset.PrivateKey);
        var plan = await RecoveryVerifier.AuthorAccountResetAsync(signedDcm, garProvider,
            provider, signer, fixture.Hmac, 101);
        return new ResetAuthorFixture(fixture, oldReset, newAccount, newReset, origin,
            branch, reservation, garProvider, signedDcm, provider, signer, plan);
    }

    private sealed record ResetAuthorFixture(Fixture Fixture, KeyPair OldReset,
        KeyPair NewAccount, KeyPair NewReset, AccountResetOriginContext Origin,
        GenesisCutoverBranchContext Branch, GenesisResetReservationResult Reservation,
        GarProvider GarProvider, GenesisSignedCutoverManifestPlan SignedDcm,
        GraProvider Provider, ResetSigner Signer, GenesisSignedAccountResetPlan Plan);

    private sealed record Fixture(
        ReleaseRootRelativeFact ReleaseRoot,
        KeyPair ReleaseRootSigner,
        byte[] Dgo,
        byte[] Dgi,
        byte[] BootstrapHash,
        byte[] EnvironmentIndex,
        TestHmac Hmac)
    {
        internal static Fixture Create(bool verifyReleaseRoot = false)
        {
            var network = Fill(0x11, 16);
            var environmentReset = Fill(0x12, 32);
            var signer = PublicKeyAuth.GenerateKeyPair();
            var releaseRootSigner = PublicKeyAuth.GenerateKeyPair();
            var signerPublic = signer.PublicKey;
            var signerKeyId = CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/release-manifest-key-id", signerPublic);
            var dgo = new byte[DeploymentGovernanceRecords.DgoLength];
            "DGO1"u8.CopyTo(dgo); dgo[4] = 1;
            network.CopyTo(dgo, 8);
            // manifestGeneration is canonically zero.
            environmentReset.CopyTo(dgo, 32);
            U64(100).CopyTo(dgo, 64);
            U64(15).CopyTo(dgo, 72);
            BinaryPrimitives.WriteUInt16BigEndian(dgo.AsSpan(80, 2), 4);
            for (var index = 0; index < 4; index++)
            {
                var row = dgo.AsSpan(82 + index * 42, 42);
                BinaryPrimitives.WriteUInt16BigEndian(row[..2], checked((ushort)(index + 1)));
                BinaryPrimitives.WriteUInt64BigEndian(row.Slice(2, 8), 1);
                row.Slice(10, 32).Fill(checked((byte)(0x20 + index)));
            }
            signerPublic.CopyTo(dgo, 250);
            var dgoHash = DeploymentGovernanceRecords.DgoHash(dgo);

            var fields = Minimum(RecordDefinitions.Rrm1);
            fields[0] = network;
            fields[1] = U64(0);
            fields[2] = environmentReset;
            fields[3] = U64(0);
            fields[4] = releaseRootSigner.PublicKey;
            fields[5] = U64(100);
            fields[6] = U64(15);
            fields[7] = dgoHash;
            fields[8] = signerKeyId;
            var unsignedRrm = CanonicalGrammar.Encode(RecordDefinitions.Rrm1, fields);
            fields[9] = PublicKeyAuth.SignDetached(CanonicalGrammar.GetSigningBytes(
                CanonicalGrammar.DecodeOwned(unsignedRrm, RecordDefinitions.Rrm1),
                "Deep/Cutover/V1/release-root-manifest"), signer.PrivateKey);
            var rrmBytes = CanonicalGrammar.Encode(RecordDefinitions.Rrm1, fields);
            var manifest = CutoverCodec.DecodeReleaseRootManifest(rrmBytes);
            var reference = CanonicalGrammar.ComputeReference(ArtifactType.Rrm1, rrmBytes);
            var pin = new ReleaseRootManifestPin(
                network, signerKeyId, signerPublic, 0, reference);
            var fact = verifyReleaseRoot
                ? new ReleaseRootRelativeVerifier().VerifyManifest(pin, rrmBytes, 100)
                : new ReleaseRootRelativeFact(
                    manifest, pin, 0, fields[4].Span, reference, [], [], null);

            var hmac = new TestHmac();
            var unsignedDgi = new byte[DeploymentGovernanceRecords.DgiLength - 32];
            "DGI1"u8.CopyTo(unsignedDgi); unsignedDgi[4] = 1;
            CanonicalGrammar.EncodeReference(reference).CopyTo(unsignedDgi, 8);
            dgoHash.CopyTo(unsignedDgi, 46);
            U64(1).CopyTo(unsignedDgi, 78);
            U64(200).CopyTo(unsignedDgi, 86);
            unsignedDgi[94] = 1;
            Fill(0x16, 32).CopyTo(unsignedDgi, 96);
            var dgi = new byte[DeploymentGovernanceRecords.DgiLength];
            unsignedDgi.CopyTo(dgi, 0);
            hmac.Tag(unsignedDgi).CopyTo(dgi, 128);
            var bootstrap = DeploymentGovernanceRecords.BootstrapHash(
                dgo, signerKeyId, dgoHash, CanonicalGrammar.EncodeReference(reference));
            var environmentIndex = DeploymentGovernanceRecords.EnvironmentIndex(
                network, environmentReset, signerKeyId);
            return new Fixture(fact, releaseRootSigner, dgo, dgi,
                bootstrap, environmentIndex, hmac);
        }
    }

    private static class OriginRecords
    {
        internal static byte[] Gar()
        {
            var value = Protected("GAR1", DeploymentGovernanceRecords.GarLength,
                DeploymentGovernanceRecords.GarKeyOffset);
            value.AsSpan(8, 588).Fill(0x21);
            DeploymentGovernanceRecords.HashU16(
                "Deep/Cutover/V10/account-reset-origin", value.AsSpan(8, 588)).CopyTo(value, 596);
            Fill(0x22, 32).CopyTo(value, 628);
            U64(1).CopyTo(value, 660); U64(200).CopyTo(value, 668);
            value[676] = 1;
            return value;
        }

        internal static byte[] Gdi(byte branch, bool signed)
        {
            var value = Protected("GDI1", DeploymentGovernanceRecords.GdiLength,
                DeploymentGovernanceRecords.GdiKeyOffset);
            value[8] = branch; Fill(0x31, 32).CopyTo(value, 9);
            if (branch != 2) Fill(0x32, 32).CopyTo(value, 41);
            Dcm(signed).CopyTo(value, 73);
            Fill(0x33, 32).CopyTo(value, 885); Fill(0x34, 32).CopyTo(value, 917);
            U64(1).CopyTo(value, 949); U64(200).CopyTo(value, 957);
            value[965] = signed ? (byte)2 : (byte)1;
            return value;
        }

        internal static byte[] Gra(bool signed)
        {
            var value = Protected("GRA1", DeploymentGovernanceRecords.GraLength,
                DeploymentGovernanceRecords.GraKeyOffset);
            Fill(0x41, 32).CopyTo(value, 8);
            Reference(ArtifactType.Dcm1, Dcm(true)).CopyTo(value, 40);
            Dra(signed).CopyTo(value, 78); Fill(0x42, 32).CopyTo(value, 866);
            U64(1).CopyTo(value, 898); U64(200).CopyTo(value, 906);
            value[914] = signed ? (byte)2 : (byte)1;
            return value;
        }

        internal static byte[] Gmd(byte branch, byte bitmap, byte phase)
        {
            var value = Protected("GMD1", DeploymentGovernanceRecords.GmdLength,
                DeploymentGovernanceRecords.GmdKeyOffset);
            value[8] = branch; Fill(0x51, 32).CopyTo(value, 9);
            Fill(0x52, 32).CopyTo(value, 41); U64(1).CopyTo(value, 73);
            Fill(0x53, 32).CopyTo(value, 81); Fill(0x54, 32).CopyTo(value, 113);
            U64(1).CopyTo(value, 145); Reference(ArtifactType.Dcm1, Dcm(true)).CopyTo(value, 153);
            if (branch == 2) Reference(ArtifactType.Dcm1, Dcm(true)).CopyTo(value, 191);
            if (branch == 3) Reference(ArtifactType.Dra1, Dra(true)).CopyTo(value, 229);
            Fill(0x55, 32).CopyTo(value, 267); value[299] = 4; value[300] = bitmap;
            for (var index = 0; index < 4; index++)
                if (((bitmap >> index) & 1) != 0) U64(checked((ulong)(index + 1))).CopyTo(value, 301 + index * 8);
            Fill(0x56, 32).CopyTo(value, 333); U64(1).CopyTo(value, 365);
            U64(200).CopyTo(value, 373); value[381] = phase;
            return value;
        }

        private static byte[] Dcm(bool signed)
        {
            var fields = Minimum(RecordDefinitions.Dcm1);
            if (signed) { fields[17] = Fill(0x61, 64); fields[18] = Fill(0x62, 64); }
            return CanonicalGrammar.Encode(RecordDefinitions.Dcm1, fields);
        }

        private static byte[] Dra(bool signed)
        {
            var fields = Minimum(RecordDefinitions.Dra1);
            fields[14] = new byte[] { 0, 1 };
            if (signed)
            {
                fields[18] = Fill(0x63, 64); fields[19] = Fill(0x64, 64);
                fields[20] = Fill(0x65, 64);
            }
            return CanonicalGrammar.Encode(RecordDefinitions.Dra1, fields);
        }

        private static byte[] Protected(string magic, int length, int keyOffset)
        {
            var value = new byte[length];
            System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0); value[4] = 1;
            Fill(0x71, 32).CopyTo(value, keyOffset);
            return value;
        }

        private static byte[] Reference(ArtifactType type, ReadOnlySpan<byte> canonical) =>
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, canonical));
    }

    private sealed class StableProvider(byte[] dgo, byte[] dgi) : DeploymentGovernanceProvider
    {
        public int Reads { get; private set; }
        public int Mutations { get; private set; }
        public byte[]? LastEnvironmentIndex { get; private set; }
        public override ValueTask<DeploymentGovernanceReadResult> RestoreOrCreateAsync(
            DeploymentGovernanceRequest request,
            CancellationToken cancellationToken)
        {
            Mutations++;
            return Result(request, cancellationToken);
        }

        public override ValueTask<DeploymentGovernanceReadResult> ReadAsync(
            DeploymentGovernanceRequest request,
            CancellationToken cancellationToken)
        {
            Reads++;
            return Result(request, cancellationToken);
        }

        private ValueTask<DeploymentGovernanceReadResult> Result(
            DeploymentGovernanceRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal(32, request.EnvironmentIndex.Length);
            LastEnvironmentIndex = request.EnvironmentIndex.ToArray();
            return ValueTask.FromResult(new DeploymentGovernanceReadResult(dgo, dgi, true));
        }
    }

    private sealed class MovingProvider(byte[] dgo, byte[] first, byte[] second)
        : DeploymentGovernanceProvider
    {
        public int Reads { get; private set; }
        public int Mutations { get; private set; }
        public override ValueTask<DeploymentGovernanceReadResult> RestoreOrCreateAsync(
            DeploymentGovernanceRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Mutations++;
            return ValueTask.FromResult(new DeploymentGovernanceReadResult(dgo, first, true));
        }

        public override ValueTask<DeploymentGovernanceReadResult> ReadAsync(
            DeploymentGovernanceRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Reads++;
            return ValueTask.FromResult(new DeploymentGovernanceReadResult(
                dgo, second, true));
        }
    }

    private sealed class TestHmac : IProtectedHmacProvider
    {
        public List<(string Domain, byte[] KeyId)> Requests { get; } = [];
        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add((request.Domain, request.ProtectedStateKeyId.ToArray()));
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(Tag(request.UnsignedCanonical.Span));
        }

        internal byte[] Tag(ReadOnlySpan<byte> unsigned) => SHA256.HashData(unsigned);
    }

    private sealed class GenesisArtifactProvider(
        TestHmac hmac,
        GenesisIdentityContext identity,
        GenesisPreExternalCandidatePlan plan,
        int moveOnRestoreCall = 0,
        ulong retainUntil = 200)
        : GenesisArtifactStore
    {
        private GenesisArtifactStoreReadResult? _stored;
        private int _restoreCalls;

        public override ValueTask<GenesisArtifactStoreReadResult> StoreOrRestoreAsync(
            GenesisArtifactStoreRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = new byte[GenesisProtectedRecords.GasLength];
            "GAS1"u8.CopyTo(value); value[4] = 1;
            request.ExactScope.Span.CopyTo(value.AsSpan(8));
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(130, 2), 7);
            var references = request.CanonicalArtifacts.Select((artifact, index) =>
            {
                var type = index switch
                {
                    0 => ArtifactType.Drc1,
                    >= 1 and <= 4 => ArtifactType.Dcp1,
                    5 => ArtifactType.Dcs1,
                    _ => ArtifactType.Dct1
                };
                return CanonicalGrammar.EncodeReference(
                    CanonicalGrammar.ComputeReference(type, artifact.Span));
            }).OrderBy(static value => value, ByteArrayComparer.Instance).ToArray();
            var inventory = new byte[2 + 7 * 38];
            BinaryPrimitives.WriteUInt16BigEndian(inventory, 7);
            for (var index = 0; index < references.Length; index++)
                references[index].CopyTo(inventory, 2 + index * 38);
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-artifact-inventory", inventory).CopyTo(value, 132);
            plan.CandidateCoreFingerprint.Span.CopyTo(value.AsSpan(164));
            var total = request.CanonicalArtifacts.Aggregate(0UL,
                static (sum, artifact) => checked(sum + (ulong)artifact.Length));
            U64(total).CopyTo(value, 196); U64(1).CopyTo(value, 204);
            U64(retainUntil).CopyTo(value, 212); value[220] = 1;
            identity.ProtectedStateHmacKeyId.CopyTo(value.AsSpan(221));
            hmac.Tag(value.AsSpan(0, value.Length - 32)).CopyTo(value, value.Length - 32);
            _stored = new GenesisArtifactStoreReadResult(
                value, request.CanonicalArtifacts, 1, healthy: true);
            return ValueTask.FromResult(_stored);
        }

        public override ValueTask<GenesisArtifactStoreReadResult> RestoreByScopeAsync(
            GenesisArtifactStoreLookupRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _restoreCalls++;
            Assert.NotNull(_stored);
            Assert.Equal(_stored!.CanonicalReceipt.Span.Slice(8, 122).ToArray(),
                request.ExactAuthorScope.ToArray());
            if (moveOnRestoreCall != 0 && _restoreCalls >= moveOnRestoreCall)
                return ValueTask.FromResult(new GenesisArtifactStoreReadResult(
                    _stored!.CanonicalReceipt.Span, _stored.CanonicalArtifacts,
                    checked(_stored.SourceRevision + 1), healthy: true));
            return ValueTask.FromResult(_stored!);
        }
    }

    private sealed class GenesisQuorumProvider(
        TestHmac hmac,
        GenesisIdentityContext identity,
        int disappearOnTryRestoreCall = 0,
        ulong retainUntil = 200)
        : GenesisQuorumStateProvider
    {
        public int WitnessSelectionCount { get; private set; }
        public int CompleteCalls { get; private set; }
        private GenesisQuorumPendingReadResult? _pending;
        private byte[]? _stableScope;
        private int _tryRestoreCalls;

        public override ValueTask<GenesisQuorumPendingReadResult> RestoreOrCreatePendingAsync(
            GenesisQuorumPendingRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            WitnessSelectionCount = 3;
            _stableScope = request.ExactStableScope.ToArray();
            var value = new byte[GenesisProtectedRecords.GqpLength];
            "GQP1"u8.CopyTo(value); value[4] = 1;
            request.ExactOperation.Span.CopyTo(value.AsSpan(8));
            request.OperationHash.Span.CopyTo(value.AsSpan(347));
            U64(1).CopyTo(value, 379); U64(retainUntil).CopyTo(value, 387); value[395] = 1;
            identity.ProtectedStateHmacKeyId.CopyTo(value.AsSpan(397));
            hmac.Tag(value.AsSpan(0, value.Length - 32)).CopyTo(value, value.Length - 32);
            _pending = new GenesisQuorumPendingReadResult(value, 1, true);
            return ValueTask.FromResult(_pending);
        }

        public override ValueTask<GenesisQuorumPendingReadResult> RestorePendingByScopeAsync(
            GenesisQuorumPendingLookupRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.NotNull(_pending);
            Assert.Equal(_stableScope, request.ExactStableScope.ToArray());
            return ValueTask.FromResult(_pending);
        }

        public override ValueTask<GenesisQuorumPendingReadResult?> TryRestorePendingByScopeAsync(
            GenesisQuorumPendingLookupRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _tryRestoreCalls++;
            if (_pending is not null)
                Assert.Equal(_stableScope, request.ExactStableScope.ToArray());
            if (disappearOnTryRestoreCall != 0 && _tryRestoreCalls >= disappearOnTryRestoreCall)
                return ValueTask.FromResult<GenesisQuorumPendingReadResult?>(null);
            return ValueTask.FromResult(_pending);
        }

        public override ValueTask<GenesisQuorumSelectionReadResult> CompleteAsync(
            GenesisQuorumSelectionRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CompleteCalls++;
            var value = new byte[GenesisProtectedRecords.GqsLength];
            request.UnsignedSelection.Span.CopyTo(value);
            hmac.Tag(value.AsSpan(0, value.Length - 32)).CopyTo(value, value.Length - 32);
            var revision = BinaryPrimitives.ReadUInt64BigEndian(value.AsSpan(499, 8));
            return ValueTask.FromResult(new GenesisQuorumSelectionReadResult(
                value, revision, true));
        }
    }

    private sealed class GenesisJournalProvider(TestHmac hmac, GenesisIdentityContext identity)
        : GenesisAuthorJournal
    {
        private GenesisAuthorJournalReadResult? _current;
        internal GenesisAuthorJournalReadResult Current => _current ??
            throw new InvalidOperationException("The test journal has not been created.");

        public override ValueTask<GenesisAuthorJournalReadResult> RestoreOrCreateCreatedAsync(
            GenesisAuthorJournalCreatedRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _current = Result(request.ImmutableCreatedTranscript.Span, 1);
            return ValueTask.FromResult(_current);
        }

        public override ValueTask<GenesisAuthorJournalReadResult> CompareExchangeAsync(
            GenesisAuthorJournalTransitionRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var revision = checked(BinaryPrimitives.ReadUInt64BigEndian(
                request.ExpectedJournal.Span.Slice(807, 8)) + 1);
            _current = Result(request.NextImmutableTranscript.Span, revision);
            return ValueTask.FromResult(_current);
        }

        public override ValueTask<GenesisAuthorJournalReadResult> RestoreByScopeAsync(
            GenesisAuthorJournalLookupRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.NotNull(_current);
            Assert.Equal(_current!.CanonicalJournal.Span.Slice(8, 154).ToArray(),
                request.ExactLookupScope.ToArray());
            return ValueTask.FromResult(_current);
        }

        private GenesisAuthorJournalReadResult Result(ReadOnlySpan<byte> prefix, ulong revision)
        {
            var value = new byte[GenesisProtectedRecords.GajLength];
            prefix.CopyTo(value); U64(revision).CopyTo(value, 807);
            identity.ProtectedStateHmacKeyId.CopyTo(value.AsSpan(816));
            hmac.Tag(value.AsSpan(0, value.Length - 32)).CopyTo(value, value.Length - 32);
            return new GenesisAuthorJournalReadResult(value, revision, true);
        }
    }

    private sealed class GenesisReplayHeads : GenesisReplayHeadProvider
    {
        private readonly GenesisJournalProvider _journal;
        private readonly ReadOnlyMemory<byte>[] _externalArtifacts;
        private readonly byte[] _dpl;
        private readonly byte[] _dplReference;
        private readonly byte[] _source;
        private readonly bool _externalInstalled;
        private readonly bool _localInstalled;

        internal GenesisReplayHeads(GenesisJournalProvider journal)
        {
            _journal = journal;
            _externalArtifacts = [];
            _dpl = [];
            _dplReference = new byte[38];
            _source = new byte[32];
        }

        internal GenesisReplayHeads(
            GenesisJournalProvider journal,
            VerifiedGenesisArtifactSet artifactSet,
            ReadOnlyMemory<byte> canonicalDcq,
            RecoveryMaterializationPlan materialization,
            GenesisCutoverSourceContext source,
            bool localInstalled)
        {
            _journal = journal;
            _externalArtifacts = artifactSet.Artifacts
                .Concat([canonicalDcq])
                .Select(static value => (ReadOnlyMemory<byte>)value.ToArray())
                .ToArray();
            _dpl = materialization.CanonicalCandidateDpl.ToArray();
            _dplReference = materialization.CandidateDplArtifactReference.ToArray();
            _source = source.SourceFingerprint.ToArray();
            _externalInstalled = true;
            _localInstalled = localInstalled;
        }

        public override ValueTask<GenesisReplayHeadReadResult> ReadLockedAsync(
            GenesisReplayScopeV1 scope,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.True(scope.NoAuthorityClaim);
            var external = _externalInstalled
                ? new GenesisReplayExternalHeadData(
                    1, _externalArtifacts, _dplReference, _source, 1, 150)
                : new GenesisReplayExternalHeadData(
                    0, [], new byte[38], new byte[32], 1, 0);
            var local = new GenesisReplayLocalHeadData(
                _localInstalled ? _dpl : [],
                _localInstalled ? _dplReference : new byte[38],
                _localInstalled ? _source : new byte[32],
                _localInstalled ? 2UL : 1UL,
                _journal.Current.CanonicalJournal.Span,
                _journal.Current.SourceRevision);
            return ValueTask.FromResult(new GenesisReplayHeadReadResult(
                external, local, external));
        }
    }

    private sealed class ZeroPreJournalHeads(
        int invalidCall = 0,
        int rollbackCall = 0) : GenesisPreJournalHeadProvider
    {
        public int Calls { get; private set; }

        public override ValueTask<GenesisPreJournalHeadReadResult> ReadAsync(
            GenesisPreJournalScopeV1 scope,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            Assert.True(scope.NoAuthorityClaim);
            var revision = rollbackCall == 0 || Calls < rollbackCall ? 2UL : 1UL;
            return ValueTask.FromResult(new GenesisPreJournalHeadReadResult(
                journalExists: Calls == invalidCall,
                externalSequence: 0,
                new byte[38], new byte[32], [], new byte[38], new byte[32],
                externalSourceRevision: revision,
                localSourceRevision: revision,
                journalSourceRevision: revision));
        }
    }

    private sealed class FixedReplayTimePolicy(ulong now, ulong timeout)
        : GenesisReplayTimePolicy
    {
        public override ulong GetUnixTimeSeconds() => now;
        public override ulong ReplayTimeoutSeconds => timeout;
    }

    private sealed class ReplayRecoveryProvider : RecoveryProtectorProvider
    {
        public int OpenCalls { get; private set; }

        public override ValueTask DeriveNonceAsync(
            RecoveryProviderRequest request,
            Memory<byte> derivedNonce24,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            derivedNonce24.Span.Fill(0xc1);
            return ValueTask.CompletedTask;
        }

        public override ValueTask OpenAsync(
            RecoveryProviderRequest request,
            Memory<byte> plaintextDestination,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            OpenCalls++;
            var ciphertext = request.Ciphertext.Span;
            Assert.Equal(ciphertext.Length, plaintextDestination.Length);
            for (var index = 0; index < ciphertext.Length; index++)
                plaintextDestination.Span[index] = checked((byte)(ciphertext[index] ^ 0x5a));
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ColdProviderRegistry(
        byte[] resetId, byte[] protectedHmacKeyId, byte[] nonceLatchKeyId,
        int moveOnCall = 0)
        : RecoveryProviderRegistry
    {
        public int Calls { get; private set; }

        public override ValueTask<RecoveryProviderRegistryReadResult> ReadAsync(
            RecoveryProviderRegistryRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            var selector = request.OperationSelector.Span;
            var scope = new byte[RecoveryProviderRegistryContext.ExactScopeLength];
            selector[..16].CopyTo(scope);
            resetId.CopyTo(scope, 16);
            selector.Slice(16, 32).CopyTo(scope.AsSpan(48));
            selector.Slice(48, 8).CopyTo(scope.AsSpan(80));
            BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(88, 2), 2);
            BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(90, 2),
                (ushort)RecoveryProtectedKeyKind.ProtectedStateHmac);
            protectedHmacKeyId.CopyTo(scope, 92);
            if (moveOnCall != 0 && Calls == moveOnCall)
                scope[92] ^= 1;
            BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(124, 2),
                (ushort)RecoveryProtectedKeyKind.RecoveryNonceLatch);
            nonceLatchKeyId.CopyTo(scope, 126);
            return ValueTask.FromResult(new RecoveryProviderRegistryReadResult(
                scope, 1, protectedStateHmacHealthy: true,
                recoveryNonceLatchHealthy: true));
        }
    }

    private sealed class ExactReplayLatch : RecoveryNonceLatch
    {
        public int Calls { get; private set; }
        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(RecoveryNonceLatchDecision.ExactReplay);
        }
    }

    private sealed class GenesisWitnessProvider(
        IReadOnlyList<KeyPair> signers,
        ulong issuedAt = 103,
        ulong expiresAt = 150)
        : GenesisWitnessReceiptProvider
    {
        public int Calls { get; private set; }
        public override ValueTask<GenesisWitnessReceiptReadResult> AppendOrRestoreAsync(
            GenesisWitnessReceiptRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++;
            Assert.Equal(7, request.CanonicalPreExternalArtifacts.Count);
            var fields = RecordDefinitions.Dcn1.Fields.Select(field =>
                new byte[field.MinimumLength]).ToArray();
            for (var index = 0; index < 14; index++)
                fields[index] = request.ExpectedFields1Through14[index].ToArray();
            var witnessIndex = fields[13][0] - 1;
            Assert.InRange(witnessIndex, 0, 2);
            fields[14] = U64(0);
            fields[15] = WitnessTreeVerifier.EmptyRoot(
                Scalars.UInt64(fields[6]), fields[13], request.MaximumTreeSize);
            fields[16] = U64(1);
            var leafPayload = new byte[116];
            fields[1].CopyTo(leafPayload, 0); fields[2].CopyTo(leafPayload, 32);
            fields[3].CopyTo(leafPayload, 40); fields[4].CopyTo(leafPayload, 78);
            fields[17] = WitnessTreeVerifier.Leaf(leafPayload);
            fields[18] = U64(0); fields[19] = new byte[] { 0 }; fields[20] = [];
            fields[21] = new byte[] { 0 }; fields[22] = [];
            fields[23] = U64(issuedAt); fields[24] = U64(expiresAt);
            fields[25] = new byte[] { (byte)DurabilityClass.FsyncReplicated };
            var unsigned = CanonicalGrammar.Encode(RecordDefinitions.Dcn1,
                fields.Select(static value => (ReadOnlyMemory<byte>)value).ToArray());
            fields[26] = PublicKeyAuth.SignDetached(CanonicalGrammar.GetSigningBytes(
                CanonicalGrammar.DecodeOwned(unsigned, RecordDefinitions.Dcn1),
                "Deep/Cutover/V1/witness-receipt"), signers[witnessIndex].PrivateKey);
            var canonical = CanonicalGrammar.Encode(RecordDefinitions.Dcn1,
                fields.Select(static value => (ReadOnlyMemory<byte>)value).ToArray());
            return ValueTask.FromResult(new GenesisWitnessReceiptReadResult(
                canonical, checked((ulong)(witnessIndex + 1)), true));
        }
    }

    private sealed class CurrentGenesisWitnessHeadProvider(
        GenesisReleaseContext release,
        int moveOnCall = 0)
        : GenesisWitnessHeadProvider
    {
        public int Calls { get; private set; }

        public override ValueTask<GenesisWitnessHeadReadResult> ReadCurrentAsync(
            GenesisWitnessHeadRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            Assert.Equal(release.Network.ToArray(), request.Network.ToArray());
            Assert.Equal(release.ResetId.ToArray(), request.ResetId.ToArray());
            Assert.Equal(release.LatestDwdReference.ToArray(),
                request.ExpectedDwdReference.ToArray());
            Assert.Equal(release.CurrentReleaseRootAuthorityHead.ToArray(),
                request.ExpectedReleaseRootAuthorityHead.ToArray());
            var dwd = release.LatestDelegation.Delegation.CanonicalBytes.ToArray();
            if (moveOnCall != 0 && Calls >= moveOnCall) dwd[100] ^= 0x01;
            return ValueTask.FromResult(new GenesisWitnessHeadReadResult(
                dwd,
                release.ReleaseRootLkg,
                release.WitnessHeadHistoryLkg,
                1,
                healthy: true));
        }
    }

    private sealed class GenesisCommitCoordinator(byte[] dplReference, byte[] source)
        : GenesisCutoverCommitCoordinator
    {
        public int ExternalCalls { get; private set; }
        public int LocalCalls { get; private set; }
        public override ValueTask<GenesisCutoverCommitReadResult> CompareExternalZeroToOneAsync(
            GenesisExternalCutoverCommitRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); ExternalCalls++;
            Assert.Equal(8, request.CanonicalArtifacts.Count);
            return ValueTask.FromResult(new GenesisCutoverCommitReadResult(
                true, dplReference, source, 1));
        }

        public override ValueTask<GenesisCutoverCommitReadResult> CompareLocalEmptyToCandidateAsync(
            GenesisLocalCutoverCommitRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); LocalCalls++;
            return ValueTask.FromResult(new GenesisCutoverCommitReadResult(
                true, dplReference, source, 2));
        }

        public override ValueTask<GenesisCutoverCommitReadResult> CompareReplayLocalAsync(
            GenesisReplayLocalCommitRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); LocalCalls++;
            var expectedDpl = request.ExpectedCurrentDpl.ToArray();
            var expectedSource = request.ExpectedCurrentSourceFingerprint.ToArray();
            Assert.True(expectedDpl.Length == 0 ||
                expectedDpl.AsSpan().SequenceEqual(request.CandidateDpl.Span));
            Assert.True(CanonicalGrammar.IsZero(expectedSource) ||
                expectedSource.AsSpan().SequenceEqual(request.CandidateSourceFingerprint.Span));
            return ValueTask.FromResult(new GenesisCutoverCommitReadResult(
                true, dplReference, source,
                expectedDpl.Length == 0
                    ? checked(request.ExpectedSourceRevision + 1)
                    : request.ExpectedSourceRevision));
        }
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static ByteArrayComparer Instance { get; } = new();
        public int Compare(byte[]? left, byte[]? right) => left is null ? -1 : right is null ? 1 :
            left.AsSpan().SequenceCompareTo(right);
    }

    private sealed class TransactionProvider(TestHmac hmac, byte[] protectedKeyId)
        : GenesisTransactionReservationProvider
    {
        public override ValueTask<GenesisTransactionReservationReadResult> RestoreOrReserveAsync(
            GenesisTransactionReservationRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = new byte[GenesisProtectedRecords.GtiLength];
            "GTI1"u8.CopyTo(value); value[4] = 1;
            request.ExactScope.Span.CopyTo(value.AsSpan(8));
            Fill(0xe1, 32).CopyTo(value, 130);
            U64(1).CopyTo(value, 162);
            U64(200).CopyTo(value, 170);
            protectedKeyId.CopyTo(value, 179);
            hmac.Tag(value.AsSpan(0, value.Length - 32)).CopyTo(value, 211);
            return ValueTask.FromResult(
                new GenesisTransactionReservationReadResult(value, healthy: true));
        }
    }

    private sealed class KeySetProvider(int moveOnCall = 0) : GenesisProtectedKeySetRegistry
    {
        public int Calls { get; private set; }
        public override ValueTask<GenesisProtectedKeySetReadResult> ReadAsync(
            GenesisProtectedKeySetRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++;
            var scope = new byte[GenesisProtectedKeySetContext.ExactScopeLength];
            request.ExactScopeAxes.Span.CopyTo(scope);
            BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(90, 2), 6);
            for (var index = 0; index < 6; index++)
            {
                BinaryPrimitives.WriteUInt16BigEndian(
                    scope.AsSpan(92 + index * 34, 2), checked((ushort)(index + 1)));
                scope.AsSpan(94 + index * 34, 32).Fill(checked((byte)(0xa1 + index)));
            }
            var revision = moveOnCall != 0 && Calls >= moveOnCall ? 2UL : 1UL;
            return ValueTask.FromResult(new GenesisProtectedKeySetReadResult(
                scope, revision, Enumerable.Repeat(true, 6).ToArray()));
        }
    }

    private sealed class ProtectorProvider : RecoverySealingProvider
    {
        public int DeriveNonceCalls { get; private set; }
        public int SealCalls { get; private set; }
        public int OpenCalls { get; private set; }
        public override ValueTask<GenesisRecoveryProtectorReadResult> ReadAsync(
            GenesisRecoveryProtectorRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new GenesisRecoveryProtectorReadResult(
                Fill(0xb1, 32), Fill(0xb2, 32), 1,
                protectorHealthy: true, latchHealthy: true));
        }

        public override ValueTask DeriveNonceAsync(
            RecoverySealRequest request, Memory<byte> derivedNonce24,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); DeriveNonceCalls++;
            derivedNonce24.Span.Fill(0xc1);
            return ValueTask.CompletedTask;
        }

        public override ValueTask SealAsync(
            RecoverySealRequest request, ReadOnlyMemory<byte> plaintext,
            Memory<byte> ciphertextDestination, Memory<byte> authenticationTag16,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); SealCalls++;
            for (var index = 0; index < plaintext.Length; index++)
                ciphertextDestination.Span[index] = checked((byte)(plaintext.Span[index] ^ 0x5a));
            SHA256.HashData(ciphertextDestination.Span)
                .AsSpan(0, 16).CopyTo(authenticationTag16.Span);
            return ValueTask.CompletedTask;
        }

        public override ValueTask OpenAsync(
            RecoverySealRequest request, ReadOnlyMemory<byte> ciphertext,
            ReadOnlyMemory<byte> authenticationTag16, Memory<byte> plaintextDestination,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); OpenCalls++;
            if (!CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(ciphertext.Span).AsSpan(0, 16),
                    authenticationTag16.Span))
                throw new RecordException(RecordError.InvalidSignature,
                    "The test ciphertext tag is invalid.");
            for (var index = 0; index < ciphertext.Length; index++)
                plaintextDestination.Span[index] = checked((byte)(ciphertext.Span[index] ^ 0x5a));
            return ValueTask.CompletedTask;
        }
    }

    private sealed class StoredLatch : RecoveryNonceLatch
    {
        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(RecoveryNonceLatchDecision.Stored);
        }
    }

    private sealed class CutoverSigner(byte[] resetPrivate) : GenesisCutoverSigner
    {
        public int Calls { get; private set; }
        public List<GenesisCutoverSigningRequest> Requests { get; } = [];
        public override ValueTask<int> SignAsync(
            GenesisCutoverSigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++; Requests.Add(request);
            var signature = PublicKeyAuth.SignDetached(
                request.SigningBytes.ToArray(), resetPrivate);
            signature.CopyTo(signature64);
            return ValueTask.FromResult(signature.Length);
        }
    }

    private sealed class ScopedReservationProvider(TestHmac hmac)
        : GenesisResetReservationProvider
    {
        public int Calls { get; private set; }

        public override ValueTask<GenesisResetReservationReadResult> RestoreOrReserveAsync(
            GenesisResetReservationRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++;
            var operation = Fill(0x72, 32);
            var key = Fill(0x73, 32);
            var grr = new byte[GenesisProtectedRecords.GrrLength];
            "GRR1"u8.CopyTo(grr); grr[4] = 1;
            request.Intent.Span.CopyTo(grr.AsSpan(8)); operation.CopyTo(grr, 243);
            Fill(0x74, 32).CopyTo(grr, 275); grr[307] = 1;
            U64(1).CopyTo(grr, 308); key.CopyTo(grr, GenesisProtectedRecords.GrrKeyOffset);
            hmac.Tag(grr.AsSpan(0, grr.Length - 32)).CopyTo(grr, grr.Length - 32);

            var gri = new byte[GenesisProtectedRecords.GriLength];
            "GRI1"u8.CopyTo(gri); gri[4] = 1;
            request.LogicalScopeHash.Span.CopyTo(gri.AsSpan(8));
            request.IntentHash.Span.CopyTo(gri.AsSpan(40)); operation.CopyTo(gri, 72);
            GenesisProtectedRecords.ReservationHash(grr).CopyTo(gri, 104);
            U64(1).CopyTo(gri, 136); U64(200).CopyTo(gri, 144);
            key.CopyTo(gri, GenesisProtectedRecords.GriKeyOffset);
            hmac.Tag(gri.AsSpan(0, gri.Length - 32)).CopyTo(gri, gri.Length - 32);
            return ValueTask.FromResult(new GenesisResetReservationReadResult(gri, grr, true));
        }
    }

    private sealed class DcmProvider(TestHmac hmac) : GenesisDcmAuthoringProvider
    {
        public int PreparedCalls { get; private set; }
        public int SignedCalls { get; private set; }
        public byte[]? PreparedRecord { get; private set; }
        public byte[]? SignedRecord { get; private set; }

        public override ValueTask<GenesisDcmAuthoringReadResult> RestoreOrCreatePreparedAsync(
            GenesisDcmPreparedRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); PreparedCalls++;
            var value = new byte[DeploymentGovernanceRecords.GdiLength];
            "GDI1"u8.CopyTo(value); value[4] = 1; value[8] = request.BranchKind;
            request.BranchHash.Span.CopyTo(value.AsSpan(9));
            request.ReservationHash.Span.CopyTo(value.AsSpan(41));
            request.PreparedDcm.Span.CopyTo(value.AsSpan(73));
            request.GovernanceHash.Span.CopyTo(value.AsSpan(885));
            request.OperationId.Span.CopyTo(value.AsSpan(917));
            U64(1).CopyTo(value, 949); U64(200).CopyTo(value, 957); value[965] = 1;
            request.ProtectedKeyId.Span.CopyTo(value.AsSpan(967));
            hmac.Tag(value.AsSpan(0, value.Length - 32)).CopyTo(value, value.Length - 32);
            PreparedRecord = value.ToArray();
            return ValueTask.FromResult(new GenesisDcmAuthoringReadResult(value, true));
        }

        public override ValueTask<GenesisDcmAuthoringReadResult> CompleteSignedAsync(
            GenesisDcmSignedRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); SignedCalls++;
            var value = request.PreparedRecord.ToArray();
            request.SignedDcm.Span.CopyTo(value.AsSpan(73));
            U64(2).CopyTo(value, 949); value[965] = 2;
            hmac.Tag(value.AsSpan(0, value.Length - 32)).CopyTo(value, value.Length - 32);
            SignedRecord = value.ToArray();
            return ValueTask.FromResult(new GenesisDcmAuthoringReadResult(value, true));
        }
    }

    private sealed class SignedReplayDcmProvider(byte[] signed) : GenesisDcmAuthoringProvider
    {
        public override ValueTask<GenesisDcmAuthoringReadResult> RestoreOrCreatePreparedAsync(
            GenesisDcmPreparedRequest request, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new GenesisDcmAuthoringReadResult(signed, true));

        public override ValueTask<GenesisDcmAuthoringReadResult> CompleteSignedAsync(
            GenesisDcmSignedRequest request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Signed replay must not perform a second CAS.");
    }

    private sealed class DistributionProvider(TestHmac hmac, byte[]? resetAccountHash = null,
        byte initialBitmap = 0, bool nonmonotonicAdvance = false,
        byte[]? overrideBranchHash = null)
        : GenesisManifestDistributionProvider
    {
        public int CommitCalls { get; private set; }
        public int AdvanceCalls { get; private set; }
        public override ValueTask<GenesisManifestDistributionReadResult> CommitBranchAndCreateAsync(
            GenesisManifestCommitRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); CommitCalls++;
            var gdi = request.SignedGdi.Span;
            var dcm = CanonicalGrammar.DecodeOwned(request.SignedDcm.Span, RecordDefinitions.Dcm1);
            var branch = request.VerifiedBranchTranscript.Span;
            var value = new byte[DeploymentGovernanceRecords.GmdLength];
            "GMD1"u8.CopyTo(value); value[4] = 1; value[8] = branch[0];
            (overrideBranchHash ?? gdi.Slice(9, 32).ToArray()).CopyTo(value.AsSpan(9));
            request.AuthorSetHash.Span.CopyTo(value.AsSpan(41));
            dcm.FieldSpan(4).CopyTo(value.AsSpan(73));
            (branch[0] == 1 ? branch.Slice(25, 32) : resetAccountHash ?? throw new InvalidOperationException())
                .CopyTo(value.AsSpan(81));
            dcm.FieldSpan(2).CopyTo(value.AsSpan(113)); dcm.FieldSpan(3).CopyTo(value.AsSpan(145));
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Dcm1, dcm.CanonicalSpan)).CopyTo(value, 153);
            if (branch[0] == 2) branch.Slice(133, 38).CopyTo(value.AsSpan(191));
            if (branch[0] == 3)
                CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                    ArtifactType.Dra1, request.SignedDra.Span)).CopyTo(value, 229);
            branch.Slice(branch[0] switch { 1 => 133, 2 => 171, _ => 33 }, 32)
                .CopyTo(value.AsSpan(267)); value[299] = 4;
            value[300] = initialBitmap;
            for (var index = 0; index < 4; index++)
                if ((initialBitmap & (1 << index)) != 0)
                    U64(checked((ulong)(101 + index))).CopyTo(value, 301 + index * 8);
            gdi.Slice(917, 32).CopyTo(value.AsSpan(333)); U64(1).CopyTo(value, 365);
            U64(200).CopyTo(value, 373); value[381] = 1;
            gdi.Slice(967, 32).CopyTo(value.AsSpan(383)); Tag(value);
            return ValueTask.FromResult(new GenesisManifestDistributionReadResult(value, true));
        }

        public override ValueTask<GenesisManifestDistributionReadResult> AdvanceDeliveryAsync(
            GenesisManifestDeliveryAdvanceRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); AdvanceCalls++;
            var value = request.CurrentGmd.ToArray();
            var index = (int)request.ComponentKind - 1;
            value[300] |= checked((byte)(1 << index));
            U64(request.ComponentSourceRevision).CopyTo(value, 301 + index * 8);
            var revision = BinaryPrimitives.ReadUInt64BigEndian(value.AsSpan(365, 8));
            if (!nonmonotonicAdvance)
                U64(checked(revision + 1)).CopyTo(value, 365);
            Tag(value);
            return ValueTask.FromResult(new GenesisManifestDistributionReadResult(value, true));
        }

        public override ValueTask<GenesisManifestDistributionReadResult> CompleteDistributedAsync(
            GenesisManifestDistributionCompleteRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = request.CurrentGmd.ToArray(); value[381] = 2;
            var revision = BinaryPrimitives.ReadUInt64BigEndian(value.AsSpan(365, 8));
            U64(checked(revision + 1)).CopyTo(value, 365); Tag(value);
            return ValueTask.FromResult(new GenesisManifestDistributionReadResult(value, true));
        }

        private void Tag(byte[] value) =>
            hmac.Tag(value.AsSpan(0, value.Length - 32)).CopyTo(value, value.Length - 32);
    }

    private sealed class ComponentDistributor(bool expectDra = false,
        ComponentKind? missingRereadKind = null) : GenesisComponentManifestDistributor
    {
        public int Deliveries { get; private set; }
        public int Rereads { get; private set; }
        public override ValueTask<GenesisComponentManifestResult> DeliverAsync(
            GenesisComponentManifestRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Deliveries++;
            Assert.Equal(expectDra ? 788 : 0, request.SignedDra.Length);
            return ValueTask.FromResult(new GenesisComponentManifestResult(
                checked((ulong)(100 + (int)request.ComponentKind)), true, true));
        }
        public override ValueTask<GenesisComponentManifestResult> RereadAsync(
            GenesisComponentManifestRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Rereads++;
            Assert.Equal(expectDra ? 788 : 0, request.SignedDra.Length);
            if (request.ComponentKind == missingRereadKind)
                return ValueTask.FromResult(new GenesisComponentManifestResult(0, false, true));
            return ValueTask.FromResult(new GenesisComponentManifestResult(
                checked((ulong)(100 + (int)request.ComponentKind)), true, true));
        }
    }

    private sealed class DistributedReplayProvider(byte[] distributed)
        : GenesisManifestDistributionProvider
    {
        public override ValueTask<GenesisManifestDistributionReadResult> CommitBranchAndCreateAsync(
            GenesisManifestCommitRequest request, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new GenesisManifestDistributionReadResult(distributed, true));
        public override ValueTask<GenesisManifestDistributionReadResult> AdvanceDeliveryAsync(
            GenesisManifestDeliveryAdvanceRequest request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Distributed replay must not advance a delivery bit.");
        public override ValueTask<GenesisManifestDistributionReadResult> CompleteDistributedAsync(
            GenesisManifestDistributionCompleteRequest request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Distributed replay must not repeat completion.");
    }

    private sealed class OriginSigner(byte[] accountPrivate, byte[] resetPrivate)
        : GenesisOriginSigner
    {
        public List<GenesisOriginSignerRole> Roles { get; } = [];
        public List<GenesisOriginSigningRequest> Requests { get; } = [];
        public override ValueTask<int> SignAsync(GenesisOriginSigningRequest request,
            Memory<byte> signature64, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Roles.Add(request.Role);
            Requests.Add(request);
            var privateKey = request.Role == GenesisOriginSignerRole.ResetControl
                ? resetPrivate : accountPrivate;
            PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(), privateKey)
                .CopyTo(signature64);
            return ValueTask.FromResult(64);
        }
    }

    private enum OriginSignerFault
    {
        WrongKey,
        ChangedBytes,
        MalformedLength,
        Cancel
    }

    private sealed class FaultingOriginSigner(
        byte[] accountPrivate,
        byte[] resetPrivate,
        OriginSignerFault fault) : GenesisOriginSigner
    {
        public override ValueTask<int> SignAsync(
            GenesisOriginSigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            if (fault == OriginSignerFault.Cancel)
                throw new OperationCanceledException("Signer operation cancelled.");
            var signingBytes = request.SigningBytes.ToArray();
            if (fault == OriginSignerFault.ChangedBytes)
                signingBytes[0] ^= 0x01;
            var privateKey = fault == OriginSignerFault.WrongKey
                ? PublicKeyAuth.GenerateKeyPair().PrivateKey
                : request.Role == GenesisOriginSignerRole.ResetControl
                    ? resetPrivate
                    : accountPrivate;
            PublicKeyAuth.SignDetached(signingBytes, privateKey).CopyTo(signature64);
            return ValueTask.FromResult(fault == OriginSignerFault.MalformedLength ? 63 : 64);
        }
    }

    private sealed class ResetSigner(byte[] oldResetPrivate, byte[] newAccountPrivate,
        byte[] newResetPrivate) : GenesisOriginSigner
    {
        public List<GenesisOriginSignerRole> Roles { get; } = [];
        public List<GenesisOriginSigningRequest> Requests { get; } = [];
        public override ValueTask<int> SignAsync(GenesisOriginSigningRequest request,
            Memory<byte> signature64, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Roles.Add(request.Role);
            Requests.Add(request);
            var key = request.Role switch
            {
                GenesisOriginSignerRole.OldResetControl => oldResetPrivate,
                GenesisOriginSignerRole.AccountPossession => newAccountPrivate,
                GenesisOriginSignerRole.ResetControl => newResetPrivate,
                _ => throw new InvalidOperationException()
            };
            PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(), key).CopyTo(signature64);
            return ValueTask.FromResult(64);
        }
    }

    private sealed class GarProvider(TestHmac hmac) : AccountResetOriginProvider
    {
        private byte[]? _gar;
        public int Mutations { get; private set; }
        public int Reads { get; private set; }
        public AccountResetOriginRequest? LastRequest { get; private set; }
        public byte[] Canonical => _gar?.ToArray() ?? [];
        public override ValueTask<AccountResetOriginReadResult> RestoreOrCreateAsync(
            AccountResetOriginRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Mutations++;
            LastRequest = request;
            if (_gar is null)
            {
                _gar = new byte[DeploymentGovernanceRecords.GarLength];
                "GAR1"u8.CopyTo(_gar); _gar[4] = 1;
                request.VerifiedOriginTranscript.Span.CopyTo(_gar.AsSpan(8));
                DeploymentGovernanceRecords.HashU16("Deep/Cutover/V10/account-reset-origin",
                    request.VerifiedOriginTranscript.Span).CopyTo(_gar, 596);
                Fill(0x95, 32).CopyTo(_gar, 628); U64(1).CopyTo(_gar, 660);
                U64(200).CopyTo(_gar, 668); _gar[676] = 1; Fill(0x16, 32).CopyTo(_gar, 678);
                hmac.Tag(_gar.AsSpan(0, _gar.Length - 32)).CopyTo(_gar, _gar.Length - 32);
            }
            return ValueTask.FromResult(new AccountResetOriginReadResult(_gar, true));
        }

        public override ValueTask<AccountResetOriginReadResult> ReadAsync(
            AccountResetOriginRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Reads++;
            Assert.NotNull(_gar);
            Assert.Equal(request.VerifiedOriginTranscript.ToArray(), _gar!.AsSpan(8, 588).ToArray());
            return ValueTask.FromResult(new AccountResetOriginReadResult(_gar, true));
        }
    }

    private sealed class SameOperationProvider : GenesisSameAccountOperationProvider
    {
        public int Calls { get; private set; }
        public override ValueTask<GenesisSameAccountOperationReadResult> RestoreOrCreateAsync(
            GenesisSameAccountOperationRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++;
            Assert.Equal(32, request.BranchHash.Length);
            Assert.Equal(38, request.CurrentDcmReference.Length);
            return ValueTask.FromResult(new GenesisSameAccountOperationReadResult(
                Fill(0xa4, 32), 1, true));
        }
    }

    private sealed class GraProvider(TestHmac hmac) : GenesisResetAuthoringProvider
    {
        public int PreparedCalls { get; private set; }
        public int SignedCalls { get; private set; }
        public byte[]? PreparedRecord { get; private set; }
        public byte[]? SignedRecord { get; private set; }
        public override ValueTask<GenesisResetAuthoringReadResult> RestoreOrCreatePreparedAsync(
            GenesisResetPreparedRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); PreparedCalls++;
            var value = new byte[DeploymentGovernanceRecords.GraLength];
            "GRA1"u8.CopyTo(value); value[4] = 1;
            request.GarReceiptHash.Span.CopyTo(value.AsSpan(8));
            request.NewDcmReference.Span.CopyTo(value.AsSpan(40));
            request.PreparedDra.Span.CopyTo(value.AsSpan(78));
            request.OperationId.Span.CopyTo(value.AsSpan(866)); U64(1).CopyTo(value, 898);
            U64(200).CopyTo(value, 906); value[914] = 1;
            request.ProtectedKeyId.Span.CopyTo(value.AsSpan(916));
            hmac.Tag(value.AsSpan(0, value.Length - 32)).CopyTo(value, value.Length - 32);
            PreparedRecord = value.ToArray();
            return ValueTask.FromResult(new GenesisResetAuthoringReadResult(value, true));
        }

        public override ValueTask<GenesisResetAuthoringReadResult> CompleteSignedAsync(
            GenesisResetSignedRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); SignedCalls++;
            var value = request.PreparedRecord.ToArray();
            request.SignedDra.Span.CopyTo(value.AsSpan(78)); U64(2).CopyTo(value, 898);
            value[914] = 2;
            hmac.Tag(value.AsSpan(0, value.Length - 32)).CopyTo(value, value.Length - 32);
            SignedRecord = value.ToArray();
            return ValueTask.FromResult(new GenesisResetAuthoringReadResult(value, true));
        }
    }

    private sealed class SignedReplayGraProvider(byte[] signed) : GenesisResetAuthoringProvider
    {
        public override ValueTask<GenesisResetAuthoringReadResult> RestoreOrCreatePreparedAsync(
            GenesisResetPreparedRequest request, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new GenesisResetAuthoringReadResult(signed, true));

        public override ValueTask<GenesisResetAuthoringReadResult> CompleteSignedAsync(
            GenesisResetSignedRequest request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Signed GRA replay must not repeat its CAS.");
    }

    private static VerifiedIdentityRelative Identity(ReadOnlySpan<byte> network,
        byte[]? accountPublic = null, byte[]? resetPublic = null, ulong generation = 1,
        byte[]? accountHash = null, bool terminal = false)
    {
        accountPublic ??= Fill(0x81, 32); resetPublic ??= Fill(0x84, 32);
        var dpaFields = Minimum(RecordDefinitions.Dpa1);
        dpaFields[0] = network.ToArray(); dpaFields[1] = U64(generation); dpaFields[2] = U64(1);
        dpaFields[4] = accountPublic; dpaFields[5] = Fill(0x82, 32);
        dpaFields[6] = Fill(0x83, 32); dpaFields[7] = Fill(0x84, 32);
        dpaFields[7] = resetPublic;
        dpaFields[8] = Fill(0x85, 32); dpaFields[9] = U64(1); dpaFields[10] = U64(1);
        dpaFields[11] = new byte[] { 0, 1 };
        var dpaRecord = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dpa1, dpaFields), RecordDefinitions.Dpa1);
        var certificate = new AccountCertificate(dpaRecord);
        accountHash ??= Fill(0x86, 32);
        var account = new VerifiedAccount(certificate, accountHash);

        var entries = new List<RevocationCatalogEntry>();
        var entryBytes = Array.Empty<byte>();
        var currentHead = new byte[32];
        if (terminal)
        {
            var targetFields = Minimum(RecordDefinitions.Drt1);
            targetFields[0] = accountHash; targetFields[1] = new byte[] { 3 };
            targetFields[2] = Fill(0x89, 32); targetFields[3] = U64(generation);
            targetFields[4] = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Dpa1, dpaRecord.CanonicalSpan)); targetFields[5] = U64(200);
            var target = new RevocationTarget(CanonicalGrammar.DecodeOwned(
                CanonicalGrammar.Encode(RecordDefinitions.Drt1, targetFields), RecordDefinitions.Drt1));
            entryBytes = new byte[62];
            entryBytes[0] = (byte)RevocationTargetKind.AccountTerminal;
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Drt1, target.Record.CanonicalSpan)).CopyTo(entryBytes, 1);
            BinaryPrimitives.WriteUInt64BigEndian(entryBytes.AsSpan(39), generation);
            BinaryPrimitives.WriteUInt64BigEndian(entryBytes.AsSpan(47), 98);
            BinaryPrimitives.WriteUInt16BigEndian(entryBytes.AsSpan(55),
                (ushort)RevocationReason.AccountShutdown);
            var headPayload = new byte[158];
            network.CopyTo(headPayload);
            accountHash.CopyTo(headPayload, 16);
            BinaryPrimitives.WriteUInt64BigEndian(headPayload.AsSpan(48), generation);
            entryBytes.CopyTo(headPayload, 96);
            currentHead = CanonicalGrammar.Sha256Domain(
                "Deep/IdentityAuth/V1/revocation-entry-head", headPayload);
            entries.Add(new RevocationCatalogEntry(target, 98,
                RevocationReason.AccountShutdown, dpaRecord.CanonicalSpan, default));
        }
        var drsFields = Minimum(RecordDefinitions.Drs1);
        drsFields[0] = network.ToArray(); drsFields[1] = accountHash; drsFields[2] = U64(generation);
        drsFields[3] = U64(1); drsFields[4] = U64(100); drsFields[7] = Fill(0x87, 32);
        drsFields[8] = terminal ? new byte[] { 0, 1 } : new byte[2];
        drsFields[9] = entryBytes;
        drsFields[10] = currentHead;
        var drsRecord = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Drs1, drsFields), RecordDefinitions.Drs1);
        var revocations = new VerifiedRevocationState(account,
            new RevocationSnapshot(drsRecord), new RevocationCatalog(entries));
        var keys = new[]
        {
            new VerifiedKeyAuthority(KeyScope.ReleaseRoot, 0, accountPublic, default, new byte[32], false),
            new VerifiedKeyAuthority(KeyScope.DeviceCertificateIssuer, 0, Fill(0x82, 32), default, new byte[32], false),
            new VerifiedKeyAuthority(KeyScope.AccountRevocation, 0, Fill(0x83, 32), default, new byte[32], false),
            new VerifiedKeyAuthority(KeyScope.ResetControl, 0, resetPublic, default, new byte[32], false)
        };
        return new VerifiedIdentityRelative(new VerifiedIdentityAuthority(account, revocations, keys));
    }

    private static byte[] SignedDcm(VerifiedIdentityRelative identity,
        VerifiedDeploymentGovernanceContext governance, byte[] accountPrivate, byte[] resetPrivate,
        byte[] resetId, byte[] nonce)
    {
        var dpa = identity.Account.Certificate; var drs = identity.Revocations.Snapshot;
        var fields = Minimum(RecordDefinitions.Dcm1);
        fields[0] = dpa.NetworkId; fields[1] = resetId; fields[2] = U64(1);
        fields[3] = U64(dpa.AccountGeneration); fields[4] = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Dpa1, dpa.CanonicalBytes.Span));
        fields[5] = U64(1); fields[6] = U64(0); fields[7] = Fill(0x96, 32);
        fields[8] = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Drs1, drs.CanonicalBytes.Span)); fields[9] = U64(0);
        fields[10] = SHA256.HashData(dpa.ResetControlEd25519PublicKey.Span);
        fields[12] = new byte[38]; fields[13] = U64(governance.ActivationAtUnixSeconds);
        fields[14] = governance.ComponentSchemaRows.ToArray(); fields[15] = U64(90); fields[16] = nonce;
        var prepared = CanonicalGrammar.Encode(RecordDefinitions.Dcm1, fields);
        var record = CanonicalGrammar.DecodeOwned(prepared, RecordDefinitions.Dcm1);
        var signing = CanonicalGrammar.GetSigningBytes(record, "Deep/Cutover/V1/manifest");
        fields[17] = PublicKeyAuth.SignDetached(signing, resetPrivate);
        fields[18] = PublicKeyAuth.SignDetached(signing, accountPrivate);
        return CanonicalGrammar.Encode(RecordDefinitions.Dcm1, fields);
    }

    private static CurrentCutoverRelative Current(VerifiedIdentityRelative identity,
        byte[] canonicalDcm)
    {
        var dcm = CanonicalGrammar.DecodeOwned(canonicalDcm, RecordDefinitions.Dcm1);
        var drs = identity.Revocations.Snapshot.Record;
        var dcpFields = Minimum(RecordDefinitions.Dcp1); dcpFields[2] = new byte[] { 0, 1 };
        var dcp = CanonicalGrammar.Encode(RecordDefinitions.Dcp1, dcpFields);
        var dplFields = Minimum(RecordDefinitions.Dpl1); dplFields[1] = new byte[] { 0, 1 };
        var dpl = CanonicalGrammar.Encode(RecordDefinitions.Dpl1, dplFields);
        var dcmRef = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Dcm1, canonicalDcm));
        var drsRef = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Drs1, drs.CanonicalSpan));
        return new CurrentCutoverRelative(dcm.FieldSpan(1), dcm.FieldSpan(2),
            ComponentKind.Registry, identity.Account.DeepAccountIdHash.Span,
            identity.Account.Certificate.AccountGeneration, Scalars.UInt64(dcm.FieldSpan(3)),
            dcmRef, Fill(0xb1, 38), Fill(0xb2, 38), Fill(0xb3, 38), Fill(0xb4, 38),
            Fill(0xb5, 38), Fill(0xb6, 38), Fill(0xb7, 32),
            identity.Revocations.Snapshot.Revision, identity.Revocations.Snapshot.EntryCount,
            identity.Revocations.Snapshot.CurrentHead.Span, drsRef, 200,
            Fill(0xb8, 32), Fill(0xb9, 32), Fill(0xba, 32), Fill(0xbb, 32),
            Fill(0xbc, 32), Fill(0xbd, 32), Fill(0xbe, 32),
            canonicalDcm, dcp, drs.CanonicalSpan, dpl);
    }

    private static ReadOnlyMemory<byte>[] Minimum(RecordDefinition definition) =>
        definition.Fields.Select(field =>
            (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();

    private static async ValueTask<byte[]> CreateCurrentDwlAsync(
        GenesisReleaseContext release,
        GenesisPreExternalCandidatePlan candidate,
        ReadOnlyMemory<byte> dcsReference,
        ReadOnlyMemory<byte> dcqReference,
        ReadOnlyMemory<byte> canonicalDcl,
        ReadOnlyMemory<byte> dwlKeyId,
        IProtectedHmacProvider hmacProvider)
    {
        var dcl = CanonicalGrammar.DecodeOwned(canonicalDcl.Span, RecordDefinitions.Dcl1);
        var receipts = new Dictionary<string, OwnedRecord>(StringComparer.Ordinal);
        var receiptBlob = dcl.FieldSpan(11);
        var receiptOffset = 0;
        while (receiptOffset < receiptBlob.Length)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                receiptBlob.Slice(receiptOffset, 4)));
            receiptOffset += 4;
            var receipt = CanonicalGrammar.DecodeOwned(
                receiptBlob.Slice(receiptOffset, length), RecordDefinitions.Dhl1);
            receiptOffset += length;
            receipts.Add(Convert.ToHexString(receipt.FieldSpan(13)), receipt);
        }

        var heads = new byte[288];
        for (var index = 0; index < release.LatestDelegation.Descriptors.Count; index++)
        {
            var descriptor = release.LatestDelegation.Descriptors[index];
            descriptor.WitnessId.Span.CopyTo(heads.AsSpan(index * 72, 32));
            if (receipts.TryGetValue(Convert.ToHexString(descriptor.WitnessId.Span),
                    out var receipt))
            {
                receipt.FieldSpan(16).CopyTo(heads.AsSpan(index * 72 + 32, 8));
                receipt.FieldSpan(17).CopyTo(heads.AsSpan(index * 72 + 40, 32));
            }
        }

        var fields = Minimum(RecordDefinitions.Dwl1);
        fields[0] = candidate.Identity.BaseIdentity.Network.ToArray();
        fields[1] = candidate.DeploymentSubject.ToArray();
        fields[2] = U64(release.LatestDelegation.Delegation.DelegationGeneration);
        fields[3] = release.LatestDwdReference.ToArray();
        fields[4] = dcl.FieldCopy(7);
        fields[5] = heads;
        fields[6] = U64(1);
        fields[7] = dcsReference.ToArray();
        fields[8] = dcqReference.ToArray();
        fields[9] = Reference(ArtifactType.Dcl1, canonicalDcl.Span);
        fields[10] = dcl.FieldCopy(13);
        fields[11] = new byte[1];
        fields[12] = new byte[7];
        var unsignedDefinition = RecordDefinitions.Dwl1 with
        {
            Fields = RecordDefinitions.Dwl1.Fields.Take(13).ToArray(),
            MinimumLength = 12,
            OmittedSigningFieldIndexes = new HashSet<int>()
        };
        var unsigned = CanonicalGrammar.Encode(unsignedDefinition, fields.Take(13).ToArray());
        fields[13] = await hmacProvider.ComputeTagAsync(
            new ProtectedHmacRequest(
                "Deep/ProtectedState/V1/DWL1",
                ArtifactRegistry.ProtectedHmacSha256,
                dwlKeyId.Span,
                unsigned),
            default);
        var canonical = CanonicalGrammar.Encode(RecordDefinitions.Dwl1, fields);
        Assert.Equal(708, canonical.Length);
        return canonical;
    }

    private static byte[] Reference(ArtifactType type, ReadOnlySpan<byte> canonical) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, canonical));

    private static byte[] Fill(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }
}
