namespace Deep.Protocol.Tests.DeepNative;

/// <summary>
/// Independently discoverable package-vector witnesses for frozen cases whose exact behavior
/// is already exercised by the focused protocol suites. These entry points keep one semantic
/// ID bound to one xUnit FQN without duplicating protocol semantics in a second fixture.
/// </summary>
public sealed class PackageVectorClosureTests
{
    [Fact]
    public Task IdentityDxpOperationSourceStages() =>
        new DxpReceiptTests().PendingAndVerified_ExactHmacAndFullTupleCas();

    [Fact]
    public async Task IdentityDxpSubjectProjectionCycleBreak()
    {
        new DxpReceiptTests().SubjectProjection_ZeroesOnlyTranscriptAndOmitsBothSignatures();
        await new DxpReceiptTests().PendingAndVerified_ExactHmacAndFullTupleCas();
    }

    [Fact]
    public void IdentityKrtRotateRevokeFork()
    {
        var suite = new IdentityAuthorityTests();
        suite.ReleaseRootManifestAndRotation_AreSealedRelativeFactsOnly();
        suite.GenesisDwdAndTerminalDwt_VerifyRelativeWitnessChain();
    }

    [Fact]
    public void IdentityOwnerRouterIdCollision()
    {
        new IdentityAuthorityTests().PublicRelativeDeviceAndMailbox_VerifyExactDxpDrsAndOwnerId();
        new DxpReceiptTests().RouterAndComponentSubjectsExcludeContainingReferencesAndSelfDerivedHashes();
    }

    [Fact]
    public async Task IdentityPopSubstitution()
    {
        new IdentityAuthorityTests().Dxp1_DeviceAndRouterEachDeriveTheSamePossessionProof();
        await new DxpReceiptTests().SubjectProjectionSubstitution_RejectsCallerRoleAndFullRecordBeforeAgreement();
    }

    [Fact]
    public Task MembershipPmaPmrPriorHeadSuccessor() =>
        new MembershipClosureIntegrationTests().MembershipSuccessor_ReusesExactRetainedAuthorityAndVerifiesOnlyTwoOnlineSignatures();

    [Fact]
    public Task RecoveryDrcCycleAndAead() =>
        new Drm3ContainerContractTests().RecoveryDrm3PinCoreCycleFree_OpensOnceAndRejectsLegacyVersions();

    [Fact]
    public Task RecoveryKdfNonceAdVectors() =>
        new RecoveryProviderTests().FrozenDrc_UsesTypedProviderAndExactNonceLatch();

    [Fact]
    public void RevocationKeyOnlyResign()
    {
        var suite = new IdentityAuthorityTests();
        suite.ReleaseRootManifestAndRotation_AreSealedRelativeFactsOnly();
        suite.MaximumRevocationSnapshot_RestoresZeroThrough1024PrefixHeadsWithOneSnapshotSignature();
    }

    [Fact]
    public void WitnessDwdEpochReuse() =>
        new IdentityAuthorityTests().ReleaseRotationAndWitnessSuccessor_RemainInactiveUntilBothActivationTimes();

    [Fact]
    public void RecoveryDrm2AllowlistDagBounds() =>
        new Drm3ContainerContractTests().ClosedProfile_RejectsForbiddenCandidateAndFuturePhaseRows();

    [Fact]
    public Task RecoveryMaterializeCandidateDplKeyReread() =>
        new DeploymentGovernanceOriginTests().FirstDeployment_PublicColdOpen_KeyMovementOnFinalRereadRejects();

    [Fact]
    public Task RecoveryDrm2PostGenesisFrontier() =>
        new RecoveryColdProtectedPayloadTests().ColdPayload_ReturnsCandidateOnlyAfterAllFourProtectedHmacsVerify();

    [Fact]
    public async Task RecoveryDrm2FrontierUnauthorizedCrossFeed()
    {
        await new RecoveryColdProtectedPayloadTests().ColdPayload_ChangedRsmInventoryBindingFailsAfterOneAeadBeforeHmac();
        new Drm3ContainerContractTests().RfcAndRpf_RejectUnknownAndCrossFedKinds();
    }

    [Fact]
    public void RecoveryDrm2MaxDrsDrtCatalog() =>
        new Drm3ContainerContractTests().Dtc2MaximumTargetAndHistoryTables_AcceptExact1024AndRejectMaxPlusOne();

    [Fact]
    public void RecoveryDrm2TerminalDpaTarget()
    {
        var suite = new Drm3ContainerContractTests();
        suite.DtcProtectedFact_NoActiveRowOrCapabilitySurface();
        suite.DtcTargetKind_RejectsArtifactTypeCrossFeedDuringStructuralPreflight();
    }

    [Fact]
    public async Task RecoveryDrm2TargetFactCrossFeed()
    {
        new Drm3ContainerContractTests().DtcProtectedHistory_StructuralAxisCrossFeedsRejectBeforeFactAcceptance();
        await new RecoveryColdProtectedPayloadTests().ColdPayload_WrongFinalProtectedHmacReturnsNoCandidate();
    }

    [Fact]
    public async Task RecoveryDrm2DraThreeFrontierKinds()
    {
        new Drm3ContainerContractTests().DraFrontierKinds_AreThreeDistinctClosedSlots();
        await new RecoveryColdProtectedPayloadTests().ColdPayload_ReturnsCandidateOnlyAfterAllFourProtectedHmacsVerify();
    }

    [Fact]
    public async Task RecoveryDrm2TargetSubjectCrossKind()
    {
        new Drm3ContainerContractTests().DtcTargetSubject_DomainOrPreimageSubstitutionChangesTheExactSubject();
        await new RecoveryColdProtectedPayloadTests().ColdPayload_ReturnsCandidateOnlyAfterAllFourProtectedHmacsVerify();
    }

    [Fact]
    public Task RecoveryContextSealedAuthorityValid() =>
        new Deep.Protocol.DeepNative.Batch2EvidenceTests().ExpectedContextPostOpen_BindsFourHmacIdsAndOldSourceBeforeAuthority();

    [Fact]
    public Task RecoveryContextWrongStaleCrossReset() =>
        new Deep.Protocol.DeepNative.Batch2EvidenceTests().ExpectedContextPreOpen_RejectsEveryDrcRsmAndProtectorAxisBeforeProvider();

    [Fact]
    public Task RecoveryContextMovementRace() =>
        new Deep.Protocol.DeepNative.Batch2EvidenceTests().ExpectedContextToctou_RejectsSelectorRegistryHealthAndLatchMovement();

    [Fact]
    public Task RecoveryContextColdRemint() =>
        new RecoveryProviderRegistryAmendmentTests().ColdPath_OrdersPreReadAeadHmacAndPostReadWithExactLatchReplay();

    [Fact]
    public async Task RecoveryContextColdRemintMissing()
    {
        await new RecoveryColdProtectedPayloadTests().ColdPayload_WrongSharedHsmKeyFailsClosedAfterOneAeadAndBeforeCandidate();
        await new RecoveryColdProtectedPayloadTests().ColdPayload_WrongFinalProtectedHmacReturnsNoCandidate();
    }

    [Fact]
    public Task RecoveryIdentityCatalogCanonical() =>
        new RecoveryColdProtectedPayloadTests().ColdPayload_ReturnsCandidateOnlyAfterAllFourProtectedHmacsVerify();

    [Fact]
    public async Task RecoveryIdentityCatalogHeadKeyCrossFeed()
    {
        await new RecoveryColdProtectedPayloadTests().ColdPayload_WrongSharedHsmKeyFailsClosedAfterOneAeadAndBeforeCandidate();
        new Drm3ContainerContractTests().DtcProtectedHistory_StructuralAxisCrossFeedsRejectBeforeFactAcceptance();
    }

    [Fact]
    public async Task RecoveryColdCutoverCheckpointConstructible()
    {
        await new RecoveryColdProtectedPayloadTests().ColdPayload_ReturnsCandidateOnlyAfterAllFourProtectedHmacsVerify();
        await new Deep.Protocol.DeepNative.RecoveryMaterializationExact10Tests().CanonicalExternalCheckpoint_AuthorsOneDataOnlyCandidateDpl();
    }

    [Fact]
    public async Task RecoveryColdCutoverCheckpointRfcCrossFeed()
    {
        await new RecoveryColdProtectedPayloadTests().ColdPayload_ChangedRsmInventoryBindingFailsAfterOneAeadBeforeHmac();
        await new Deep.Protocol.DeepNative.RecoveryMaterializationExact10Tests().ExternalTupleMutation_RejectsBeforeHmacCallback();
    }

    [Fact]
    public async Task RecoveryColdRfcDtcKeyIdMismatch()
    {
        await new RecoveryColdProtectedPayloadTests().ColdPayload_WrongSharedHsmKeyFailsClosedAfterOneAeadAndBeforeCandidate();
        new WitnessHeadHistoryContainerTests().SourceTupleAndProtectedKeyIdCrossFeed_RejectStructurally();
    }

    [Fact]
    public Task RecoveryDwhGenesisZeroInput() =>
        new IdentityAuthorityTests().StandaloneDwhRelative_GenesisMatchesVerifiedAncestryAndHasNoAuthoritySurface();

    [Fact]
    public void RecoveryDwhSuccessorRetainedReplacement()
    {
        new IdentityAuthorityTests().WitnessSuccessor_RetainedKeyChangeAndAllFourReplacementRejectBeforeSignatures();
        new WitnessHeadHistoryContainerTests().NonConsecutiveGenerationRejectsButRandomReferenceHashOrderIsAccepted();
    }

    [Fact]
    public async Task RecoveryDwhMax64History()
    {
        new WitnessHeadHistoryContainerTests().Maximum64_IsExact22120ByteStructuralContainer();
        await new IdentityAuthorityTests().StandaloneDwhRelative_GenesisMatchesVerifiedAncestryAndHasNoAuthoritySurface();
    }

    [Fact]
    public void RecoveryDwhOrderIdHeadHashCrossFeed()
    {
        var suite = new WitnessHeadHistoryContainerTests();
        suite.NonConsecutiveGenerationRejectsButRandomReferenceHashOrderIsAccepted();
        suite.DuplicateWitnessIdAndNonemptyZeroRoot_RejectStructurally();
        suite.SourceTupleAndProtectedKeyIdCrossFeed_RejectStructurally();
    }

    [Fact]
    public Task RecoveryDwhColdReceiptBeforeAuthority() =>
        new Deep.Protocol.DeepNative.GenesisAuthorReplayOpenExact15Tests().CrossFedAnchorSourceOrOldSource_RejectsOnlyAfterCryptoOpenAndFourHmacs();

    [Fact]
    public async Task RecoveryGenerationExistingConstructible()
    {
        new RecoverySchemaProfileTests().Rsm723_PredecessorUnionAcceptsOnlyExactExistingOrGenesisShape();
        await new Deep.Protocol.DeepNative.RecoveryMaterializationExact10Tests().CanonicalExternalCheckpoint_AuthorsOneDataOnlyCandidateDpl();
    }

    [Fact]
    public async Task RecoveryGenerationSelfCycleReject()
    {
        new RecoverySchemaProfileTests().Rsm723_PredecessorUnionAcceptsOnlyExactExistingOrGenesisShape();
        await new Drm3ContainerContractTests().RecoveryDrm3PinCoreCycleFree_OpensOnceAndRejectsLegacyVersions();
    }

    [Fact]
    public async Task RecoveryGenerationCrossDcpReject()
    {
        await new Deep.Protocol.DeepNative.RecoveryMaterializationExact10Tests().ExternalTupleMutation_RejectsBeforeHmacCallback();
        await new Deep.Protocol.DeepNative.RecoveryMaterializationExact10Tests().DcpDcsTransactionMismatch_RejectsBeforeHmacCallback();
    }

    [Fact]
    public Task RecoveryGenerationExactReplay() =>
        new Deep.Protocol.DeepNative.GenesisRecoverySealerExact15Tests().LatchPrecedesExactlyOneSealAndSelfOpen_AndExactRetryIsByteIdentical();

    [Fact]
    public Task RecoveryGenesisAnchorConstructible() =>
        new DeploymentGovernanceOriginTests().FirstDeployment_GenesisSourceJoinsExact492AndAnchor460();

    [Fact]
    public async Task RecoveryGenesisDescendantCrossFeed()
    {
        new RecoverySchemaProfileTests().Rsm723_PredecessorUnionAcceptsOnlyExactExistingOrGenesisShape();
        await new Deep.Protocol.DeepNative.GenesisAuthorReplayOpenExact15Tests().CrossFedAnchorSourceOrOldSource_RejectsOnlyAfterCryptoOpenAndFourHmacs();
    }

    [Fact]
    public Task RecoveryGenesisReleaseOrdinaryCrossFeed() =>
        new Deep.Protocol.DeepNative.GenesisAuthorReplayOpenExact15Tests().CrossFedAnchorSourceOrOldSource_RejectsOnlyAfterCryptoOpenAndFourHmacs();

    [Fact]
    public Task RecoveryExistingReleaseGenesisCrossFeed() =>
        new Deep.Protocol.DeepNative.GenesisAuthorReplayOpenExact15Tests().CrossFedGasGajOrDrc_RejectsBeforeAnyProviderCallback();

    [Fact]
    public async Task RecoveryGenesisReleaseStaleHead()
    {
        await new IdentityAuthorityTests().WitnessHeadHistoryLkg_ExactGenesisRoundTripAndKeyMismatchIsPreCallback();
        await new DeploymentGovernanceOriginTests().WitnessHeadMovementBeforeReceiptAuthoring_FailsBeforeSelectedWitnessCalls();
    }

    [Fact]
    public Task RecoveryGenesisReleaseDwtRace() =>
        new DeploymentGovernanceOriginTests().WitnessHeadMovementBeforeExternalCas_FailsWithZeroPublication();

    [Fact]
    public Task RecoveryGenesisReleaseDclSubstitution() =>
        new Deep.Protocol.DeepNative.GenesisAuthorReplayOpenExact15Tests().CrossFedAnchorSourceOrOldSource_RejectsOnlyAfterCryptoOpenAndFourHmacs();

    [Fact]
    public Task RecoveryGenesisReleaseForkLatch() =>
        new Deep.Protocol.DeepNative.GenesisRecoverySealerExact15Tests().ForkLatch_RejectsBeforeSealOrOpen();

    [Fact]
    public Task RecoveryGenesisComponentTableCrossFeed() =>
        new DeploymentGovernanceOriginTests().GenesisDcsComponentRows_RejectMissingDuplicateUnsortedAndCrossFeedBeforeCallbacks();

    [Fact]
    public async Task RecoveryGenesisAuthorOrder()
    {
        await new DeploymentGovernanceOriginTests().FirstDeployment_CandidateCoreIsExact494PreExternalCycleFreeTranscript();
        await new Deep.Protocol.DeepNative.GenesisAuthorReplayOpenExact15Tests().ProcessLossReplay_CryptoOpensExactlyOnceAndVerifiesFourContainers();
    }

    [Fact]
    public Task RecoveryGenesisFullConstructibilityDag() =>
        new GenesisFullDagEvidenceTests().PublicDrm20FirstDeployment_ReachesLocalCommittedWithDurableRereads();

    [Fact]
    public Task RecoveryGenesisAuthorReplayPhaseMatrix() =>
        new DeploymentGovernanceOriginTests().FirstDeployment_ProcessLossReplay_RestoresPreJournalAndContinuesEveryPhase();

    [Fact]
    public async Task RecoveryGenesisDcnDcqQuorumNoDurability()
    {
        new Deep.Protocol.DeepNative.GenesisProtectedRecordsExact15Tests().QuorumPendingAndSelection_RequireExactThreeStrictlyOrderedRows();
        await new Deep.Protocol.DeepNative.GenesisForwardStateExact15Tests().QuorumSelectionRequest_BindsGqsHeaderPendingIdsDcnRefsAndDcq();
    }

    [Fact]
    public void RecoveryGenesisReplayDispositionMatrix()
    {
        var suite = new Deep.Protocol.DeepNative.GenesisReplayDrm19Tests();
        suite.HeadDto_PreflightsEveryPositionalAndAggregateBoundBeforeCopy();
        suite.FinalStableTupleMatrix_IsExhaustiveAcrossAllTwentySevenStates();
    }

    [Fact]
    public Task RecoveryGenesisReplayExternalDplProvenance() =>
        new Deep.Protocol.DeepNative.GenesisAuthorReplayOpenExact15Tests().CrossFedGasGajOrDrc_RejectsBeforeAnyProviderCallback();

    [Fact]
    public void RecoveryDtc2CycleFreeDag() =>
        new Drm3ContainerContractTests().DtcProtectedFact_NoActiveRowOrCapabilitySurface();

    [Fact]
    public void RecoveryDtc2HistoryOrderTime()
    {
        var suite = new Drm3ContainerContractTests();
        suite.DtcProtectedHistory_OrdinalClosureRejectsMissingDuplicateUnusedAndOutOfRange();
        suite.DtcProtectedHistory_StructuralAxisCrossFeedsRejectBeforeFactAcceptance();
    }

    [Fact]
    public Task RecoveryGenesisTerminalReject() =>
        new DeploymentGovernanceOriginTests().AccountTerminalFence_RejectsGenesisBranchButAllowsOnlyVerifiedResetOldSide();
}
