using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisExternalCutoverCommitRequest
{
    private readonly ReadOnlyMemory<byte>[] _artifacts;
    private readonly byte[] _dpl;
    private readonly byte[] _source;
    internal GenesisExternalCutoverCommitRequest(
        IReadOnlyList<ReadOnlyMemory<byte>> artifacts,
        ReadOnlySpan<byte> candidateDpl,
        ReadOnlySpan<byte> candidateSource)
    {
        _artifacts = artifacts.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
        _dpl = candidateDpl.ToArray();
        _source = candidateSource.ToArray();
    }
    public IReadOnlyList<ReadOnlyMemory<byte>> CanonicalArtifacts =>
        Array.AsReadOnly(_artifacts.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    public ReadOnlyMemory<byte> CandidateDpl => _dpl.ToArray();
    public ReadOnlyMemory<byte> CandidateSourceFingerprint => _source.ToArray();
}

public sealed class GenesisLocalCutoverCommitRequest
{
    private readonly byte[] _dpl;
    private readonly byte[] _source;
    internal GenesisLocalCutoverCommitRequest(
        ReadOnlySpan<byte> candidateDpl,
        ReadOnlySpan<byte> candidateSource)
    { _dpl = candidateDpl.ToArray(); _source = candidateSource.ToArray(); }
    public ReadOnlyMemory<byte> CandidateDpl => _dpl.ToArray();
    public ReadOnlyMemory<byte> CandidateSourceFingerprint => _source.ToArray();
}

public sealed class GenesisReplayLocalCommitRequest
{
    private readonly byte[] _expectedDpl;
    private readonly byte[] _expectedSource;
    private readonly byte[] _candidateDpl;
    private readonly byte[] _candidateSource;
    internal GenesisReplayLocalCommitRequest(
        LocalCatchUp catchUp,
        ReadOnlySpan<byte> candidateDpl,
        ReadOnlySpan<byte> candidateSource)
    {
        if (candidateDpl.Length != 576 || candidateSource.Length != 32 ||
            catchUp.Snapshot.TrustedObservedTuple.Length != 519)
            Invalid("The replay local CAS request is not closed.");
        _expectedDpl = catchUp.LocalAlreadyInstalled
            ? candidateDpl.ToArray() : [];
        _expectedSource = catchUp.LocalAlreadyInstalled
            ? candidateSource.ToArray() : new byte[32];
        _candidateDpl = candidateDpl.ToArray();
        _candidateSource = candidateSource.ToArray();
        ExpectedSourceRevision = BinaryPrimitives.ReadUInt64BigEndian(
            catchUp.Snapshot.TrustedObservedTuple.Slice(511, 8));
        if (ExpectedSourceRevision == 0)
            Invalid("The replay local CAS revision is zero.");
    }
    public ReadOnlyMemory<byte> ExpectedCurrentDpl => _expectedDpl.ToArray();
    public ReadOnlyMemory<byte> ExpectedCurrentSourceFingerprint => _expectedSource.ToArray();
    public ulong ExpectedSourceRevision { get; }
    public ReadOnlyMemory<byte> CandidateDpl => _candidateDpl.ToArray();
    public ReadOnlyMemory<byte> CandidateSourceFingerprint => _candidateSource.ToArray();
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisCutoverCommitReadResult
{
    private readonly byte[] _dplReference;
    private readonly byte[] _source;
    public GenesisCutoverCommitReadResult(
        bool committed,
        ReadOnlySpan<byte> currentDplReference38,
        ReadOnlySpan<byte> currentSourceFingerprint32,
        ulong sourceRevision)
    {
        Committed = committed;
        _dplReference = currentDplReference38.ToArray();
        _source = currentSourceFingerprint32.ToArray();
        SourceRevision = sourceRevision;
    }
    public bool Committed { get; }
    public ReadOnlyMemory<byte> CurrentDplReference => _dplReference.ToArray();
    public ReadOnlyMemory<byte> CurrentSourceFingerprint => _source.ToArray();
    public ulong SourceRevision { get; }
}

public abstract class GenesisCutoverCommitCoordinator
{
    public abstract ValueTask<GenesisCutoverCommitReadResult> CompareExternalZeroToOneAsync(
        GenesisExternalCutoverCommitRequest request,
        CancellationToken cancellationToken);
    public abstract ValueTask<GenesisCutoverCommitReadResult> CompareLocalEmptyToCandidateAsync(
        GenesisLocalCutoverCommitRequest request,
        CancellationToken cancellationToken);

    public virtual ValueTask<GenesisCutoverCommitReadResult> CompareReplayLocalAsync(
        GenesisReplayLocalCommitRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("This coordinator does not support exact replay-local CAS.");
}

internal static class GenesisCutoverCommitVerifier
{
    internal static async ValueTask<GenesisAuthorExternalCommittedPlan>
        ContinueReplayExternalAsync(
        ExternalCatchUp catchUp,
        GenesisProtectedKeySetRegistry keyRegistry,
        GenesisAuthorJournal journal,
        GenesisReplayTimePolicy timePolicy,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(catchUp);
        ArgumentNullException.ThrowIfNull(keyRegistry);
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(timePolicy);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureReplayLease(catchUp.Snapshot, timePolicy);
        var identity = catchUp.Created.Candidate.Identity;
        var keyRequest = KeyRequest(identity);
        await RevalidateKeysAsync(catchUp.KeySet, keyRegistry, keyRequest, identity,
            cancellationToken).ConfigureAwait(false);
        EnsureReplayLease(catchUp.Snapshot, timePolicy);
        var nextPrefix = ExternalPrefix(catchUp.Created, catchUp.Quorum,
            catchUp.Materialization, catchUp.Source);
        var next = await journal.CompareExchangeAsync(
            new GenesisAuthorJournalTransitionRequest(
                catchUp.Created.Journal.CanonicalJournal.Span, nextPrefix),
            cancellationToken).ConfigureAwait(false);
        EnsureReplayLease(catchUp.Snapshot, timePolicy);
        var verified = await ValidateJournalTransition(
            catchUp.Created.Journal, next, nextPrefix, 1, identity,
            hmacProvider, cancellationToken).ConfigureAwait(false);
        EnsureReplayLease(catchUp.Snapshot, timePolicy);
        await RevalidateKeysAsync(catchUp.KeySet, keyRegistry, keyRequest, identity,
            cancellationToken).ConfigureAwait(false);
        EnsureReplayLease(catchUp.Snapshot, timePolicy);
        return new GenesisAuthorExternalCommittedPlan(
            catchUp.Created, catchUp.Quorum, catchUp.Materialization,
            catchUp.Source, verified.Snapshot, verified.Revision);
    }

    internal static async ValueTask<GenesisAuthorLocalCommittedPlan>
        ContinueReplayLocalAsync(
        LocalCatchUp catchUp,
        GenesisProtectedKeySetRegistry keyRegistry,
        GenesisCutoverCommitCoordinator coordinator,
        GenesisAuthorJournal journal,
        GenesisReplayTimePolicy timePolicy,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(catchUp);
        ArgumentNullException.ThrowIfNull(keyRegistry);
        ArgumentNullException.ThrowIfNull(coordinator);
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(timePolicy);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureReplayLease(catchUp.Snapshot, timePolicy);
        var external = catchUp.External;
        var identity = external.Created.Candidate.Identity;
        var keyRequest = KeyRequest(identity);
        await RevalidateKeysAsync(catchUp.KeySet, keyRegistry, keyRequest, identity,
            cancellationToken).ConfigureAwait(false);
        EnsureReplayLease(catchUp.Snapshot, timePolicy);
        var dpl = external.Materialization.CanonicalCandidateDpl.ToArray();
        var dplRef = external.Materialization.CandidateDplArtifactReference.ToArray();
        var source = external.Source.SourceFingerprint.ToArray();
        var request = new GenesisReplayLocalCommitRequest(catchUp, dpl, source);
        var commit = await coordinator.CompareReplayLocalAsync(
            request, cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureReplayLease(catchUp.Snapshot, timePolicy);
        if (commit is null || !commit.Committed ||
            commit.SourceRevision < request.ExpectedSourceRevision ||
            (!catchUp.LocalAlreadyInstalled &&
             commit.SourceRevision == request.ExpectedSourceRevision) ||
            !CanonicalGrammar.FixedEquals(commit.CurrentDplReference.Span, dplRef) ||
            !CanonicalGrammar.FixedEquals(
                commit.CurrentSourceFingerprint.Span, source))
            Invalid("The replay local empty-or-exact CAS did not retain the exact DPL.");
        await RevalidateKeysAsync(catchUp.KeySet, keyRegistry, keyRequest, identity,
            cancellationToken).ConfigureAwait(false);
        EnsureReplayLease(catchUp.Snapshot, timePolicy);
        var nextPrefix = LocalPrefix(external);
        var next = await journal.CompareExchangeAsync(
            new GenesisAuthorJournalTransitionRequest(
                external.Journal.CanonicalJournal.Span, nextPrefix), cancellationToken)
            .ConfigureAwait(false);
        EnsureReplayLease(catchUp.Snapshot, timePolicy);
        var verified = await ValidateJournalTransition(
            external.Journal, next, nextPrefix, 2, identity,
            hmacProvider, cancellationToken).ConfigureAwait(false);
        EnsureReplayLease(catchUp.Snapshot, timePolicy);
        await RevalidateKeysAsync(catchUp.KeySet, keyRegistry, keyRequest, identity,
            cancellationToken).ConfigureAwait(false);
        EnsureReplayLease(catchUp.Snapshot, timePolicy);
        return new GenesisAuthorLocalCommittedPlan(
            external, verified.Snapshot, verified.Revision);
    }

    internal static async ValueTask<GenesisAuthorExternalCommittedPlan> CommitExternalAsync(
        GenesisAuthorCreatedPlan created,
        GenesisVerifiedQuorumPlan quorum,
        RecoveryMaterializationPlan materialization,
        GenesisCutoverSourceContext source,
        GenesisProtectedKeySetRegistry keyRegistry,
        RecoverySealingProvider sealingProvider,
        GenesisResetReservationProvider resetReservationProvider,
        GenesisTransactionReservationProvider transactionProvider,
        GenesisArtifactStore artifactStore,
        GenesisQuorumStateProvider quorumProvider,
        GenesisWitnessHeadProvider witnessHeadProvider,
        GenesisCutoverCommitCoordinator coordinator,
        GenesisAuthorJournal journal,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(created);
        ArgumentNullException.ThrowIfNull(quorum);
        ArgumentNullException.ThrowIfNull(materialization);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(keyRegistry);
        ArgumentNullException.ThrowIfNull(sealingProvider);
        ArgumentNullException.ThrowIfNull(resetReservationProvider);
        ArgumentNullException.ThrowIfNull(transactionProvider);
        ArgumentNullException.ThrowIfNull(artifactStore);
        ArgumentNullException.ThrowIfNull(quorumProvider);
        ArgumentNullException.ThrowIfNull(witnessHeadProvider);
        ArgumentNullException.ThrowIfNull(coordinator);
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        var plan = created.Candidate;
        var dpl = materialization.CanonicalCandidateDpl.ToArray();
        var dplRef = materialization.CandidateDplArtifactReference.ToArray();
        if (dpl.Length != 576 || dplRef.Length != 38 ||
            !CanonicalGrammar.FixedEquals(dplRef,
                Reference(ArtifactType.Dpl1, dpl)) ||
            !CanonicalGrammar.FixedEquals(quorum.Selection.CanonicalSelection.Span.Slice(461, 38),
                Reference(ArtifactType.Dcq1, quorum.QuorumReceipt.CanonicalBytes.Span)))
            Invalid("The genesis external commit tuple is invalid.");
        await RevalidateForwardStateAsync(
            created, source, created.Journal, keyRegistry, sealingProvider,
            resetReservationProvider, transactionProvider, artifactStore,
            quorumProvider, journal, hmacProvider, cancellationToken).ConfigureAwait(false);
        await GenesisWitnessQuorumAuthor.VerifyCurrentHeadAsync(
            source.Release, witnessHeadProvider, hmacProvider, cancellationToken)
            .ConfigureAwait(false);
        var artifacts = created.ArtifactSet.Artifacts
            .Concat([quorum.QuorumReceipt.CanonicalBytes])
            .ToArray();
        var commit = await coordinator.CompareExternalZeroToOneAsync(
            new GenesisExternalCutoverCommitRequest(artifacts, dpl, source.SourceFingerprint.Span),
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (commit is null || !commit.Committed || commit.SourceRevision == 0 ||
            !CanonicalGrammar.FixedEquals(commit.CurrentDplReference.Span, dplRef) ||
            !CanonicalGrammar.FixedEquals(commit.CurrentSourceFingerprint.Span,
                source.SourceFingerprint.Span))
            Invalid("The external zero-to-one cutover did not install the exact candidate.");
        await GenesisWitnessQuorumAuthor.VerifyCurrentHeadAsync(
            source.Release, witnessHeadProvider, hmacProvider, cancellationToken)
            .ConfigureAwait(false);
        await RevalidateForwardStateAsync(
            created, source, created.Journal, keyRegistry, sealingProvider,
            resetReservationProvider, transactionProvider, artifactStore,
            quorumProvider, journal, hmacProvider, cancellationToken).ConfigureAwait(false);
        var nextPrefix = ExternalPrefix(created, quorum, materialization, source);
        var next = await journal.CompareExchangeAsync(
            new GenesisAuthorJournalTransitionRequest(
                created.Journal.CanonicalJournal.Span, nextPrefix), cancellationToken)
            .ConfigureAwait(false);
        var canonical = ValidateJournalTransition(
            created.Journal, next, nextPrefix, 1, plan.Identity, hmacProvider,
            cancellationToken);
        var verified = await canonical.ConfigureAwait(false);
        await RevalidateForwardStateAsync(
            created, source, verified.Snapshot, keyRegistry, sealingProvider,
            resetReservationProvider, transactionProvider, artifactStore,
            quorumProvider, journal, hmacProvider, cancellationToken).ConfigureAwait(false);
        return new GenesisAuthorExternalCommittedPlan(created, quorum, materialization,
            source, verified.Snapshot, verified.Revision);
    }

    internal static async ValueTask<GenesisAuthorLocalCommittedPlan> CommitLocalAsync(
        GenesisAuthorExternalCommittedPlan external,
        GenesisProtectedKeySetRegistry keyRegistry,
        RecoverySealingProvider sealingProvider,
        GenesisResetReservationProvider resetReservationProvider,
        GenesisTransactionReservationProvider transactionProvider,
        GenesisArtifactStore artifactStore,
        GenesisQuorumStateProvider quorumProvider,
        GenesisCutoverCommitCoordinator coordinator,
        GenesisAuthorJournal journal,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(external);
        ArgumentNullException.ThrowIfNull(keyRegistry);
        ArgumentNullException.ThrowIfNull(sealingProvider);
        ArgumentNullException.ThrowIfNull(resetReservationProvider);
        ArgumentNullException.ThrowIfNull(transactionProvider);
        ArgumentNullException.ThrowIfNull(artifactStore);
        ArgumentNullException.ThrowIfNull(quorumProvider);
        ArgumentNullException.ThrowIfNull(coordinator);
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        var dpl = external.Materialization.CanonicalCandidateDpl.ToArray();
        var dplRef = external.Materialization.CandidateDplArtifactReference.ToArray();
        var source = external.Source.SourceFingerprint.ToArray();
        await RevalidateForwardStateAsync(
            external.Created, external.Source, external.Journal, keyRegistry,
            sealingProvider, resetReservationProvider, transactionProvider,
            artifactStore, quorumProvider, journal, hmacProvider,
            cancellationToken).ConfigureAwait(false);
        var commit = await coordinator.CompareLocalEmptyToCandidateAsync(
            new GenesisLocalCutoverCommitRequest(dpl, source), cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (commit is null || !commit.Committed || commit.SourceRevision == 0 ||
            !CanonicalGrammar.FixedEquals(commit.CurrentDplReference.Span, dplRef) ||
            !CanonicalGrammar.FixedEquals(commit.CurrentSourceFingerprint.Span, source))
            Invalid("The local empty-to-candidate cutover did not install the exact candidate.");
        await RevalidateForwardStateAsync(
            external.Created, external.Source, external.Journal, keyRegistry,
            sealingProvider, resetReservationProvider, transactionProvider,
            artifactStore, quorumProvider, journal, hmacProvider,
            cancellationToken).ConfigureAwait(false);
        var nextPrefix = LocalPrefix(external);
        var next = await journal.CompareExchangeAsync(
            new GenesisAuthorJournalTransitionRequest(
                external.Journal.CanonicalJournal.Span, nextPrefix), cancellationToken)
            .ConfigureAwait(false);
        var verified = await ValidateJournalTransition(
            external.Journal, next, nextPrefix, 2,
            external.Created.Candidate.Identity, hmacProvider, cancellationToken)
            .ConfigureAwait(false);
        await RevalidateForwardStateAsync(
            external.Created, external.Source, verified.Snapshot, keyRegistry,
            sealingProvider, resetReservationProvider, transactionProvider,
            artifactStore, quorumProvider, journal, hmacProvider,
            cancellationToken).ConfigureAwait(false);
        return new GenesisAuthorLocalCommittedPlan(external, verified.Snapshot, verified.Revision);
    }

    private static async ValueTask RevalidateForwardStateAsync(
        GenesisAuthorCreatedPlan created,
        GenesisCutoverSourceContext source,
        GenesisAuthorJournalSnapshot expectedJournal,
        GenesisProtectedKeySetRegistry keyRegistry,
        RecoverySealingProvider sealingProvider,
        GenesisResetReservationProvider resetReservationProvider,
        GenesisTransactionReservationProvider transactionProvider,
        GenesisArtifactStore artifactStore,
        GenesisQuorumStateProvider quorumProvider,
        GenesisAuthorJournal journal,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var identity = created.Candidate.Identity;
        if (!ReferenceEquals(source.Identity, identity) ||
            !ReferenceEquals(source.Intent.Identity, identity) ||
            !ReferenceEquals(source.Release, identity.Scope.Release))
            Invalid("The forward cutover fence combines different sealed axes.");

        var keyRequest = KeyRequest(identity);
        async ValueTask RevalidateKeysAsync() => await source.KeySet.RevalidateAsync(
            keyRegistry, keyRequest, identity.ProtectedStateHmacKeyId.ToArray(),
            cancellationToken).ConfigureAwait(false);

        await RevalidateKeysAsync().ConfigureAwait(false);
        var protectorRequest = new GenesisRecoveryProtectorRequest(identity, source.Intent);
        await source.Protector.RevalidateAsync(
            sealingProvider, protectorRequest, identity.ProtectedStateHmacKeyId.ToArray(),
            source.KeySet, cancellationToken).ConfigureAwait(false);
        await RevalidateKeysAsync().ConfigureAwait(false);

        var currentTransaction = await GenesisReservationVerifier.RestoreTransactionAsync(
            transactionProvider, new GenesisTransactionReservationRequest(
                identity.Scope.ExactScope), hmacProvider, cancellationToken).ConfigureAwait(false);
        if (!CanonicalGrammar.FixedEquals(
                currentTransaction.Canonical, identity.Transaction.Canonical))
            Invalid("The genesis transaction reservation moved before final commit.");
        await RevalidateKeysAsync().ConfigureAwait(false);

        var reservation = identity.Scope.Reservation;
        var reservationRequest = reservation.Request;
        if (reservationRequest is null)
            Invalid("The genesis reset reservation has no sealed replay request.");
        var currentReservation = await GenesisReservationVerifier.RestoreResetAsync(
            resetReservationProvider, reservationRequest!, hmacProvider,
            cancellationToken).ConfigureAwait(false);
        if (!CanonicalGrammar.FixedEquals(
                currentReservation.IndexBytes, reservation.IndexBytes) ||
            !CanonicalGrammar.FixedEquals(
                currentReservation.ReservationBytes, reservation.ReservationBytes))
            Invalid("The genesis reset reservation moved before final commit.");
        await RevalidateKeysAsync().ConfigureAwait(false);

        var currentArtifacts = await GenesisArtifactSetVerifier.RestoreByScopeAsync(
            identity, artifactStore, hmacProvider, cancellationToken).ConfigureAwait(false);
        EnsureSameArtifactSet(currentArtifacts, created.ArtifactSet);
        await RevalidateKeysAsync().ConfigureAwait(false);

        var currentPending = await GenesisQuorumStateVerifier.RestorePendingByScopeAsync(
            currentArtifacts, identity, source.Release, quorumProvider, hmacProvider,
            cancellationToken).ConfigureAwait(false);
        if (!CanonicalGrammar.FixedEquals(
                currentPending.CanonicalPending.Span,
                created.QuorumPending.CanonicalPending.Span))
            Invalid("The genesis quorum Pending moved before final commit.");
        await RevalidateKeysAsync().ConfigureAwait(false);

        var currentJournal = await GenesisAuthorJournalVerifier.RestoreByScopeAsync(
            identity, reservation, journal, hmacProvider, cancellationToken)
            .ConfigureAwait(false);
        if (currentJournal.ForkLatched ||
            !CanonicalGrammar.FixedEquals(
                currentJournal.CanonicalJournal.Span,
                expectedJournal.CanonicalJournal.Span))
            Invalid("The genesis author journal moved before final commit.");
        await RevalidateKeysAsync().ConfigureAwait(false);
    }

    private static void EnsureSameArtifactSet(
        VerifiedGenesisArtifactSet actual,
        VerifiedGenesisArtifactSet expected)
    {
        if (actual.SourceRevision != expected.SourceRevision ||
            !CanonicalGrammar.FixedEquals(
                actual.Receipt.CanonicalReceipt.Span,
                expected.Receipt.CanonicalReceipt.Span) ||
            actual.Artifacts.Count != expected.Artifacts.Count)
            Invalid("The genesis artifact set moved before final commit.");
        for (var index = 0; index < actual.Artifacts.Count; index++)
            if (!CanonicalGrammar.FixedEquals(
                    actual.Artifacts[index].Span, expected.Artifacts[index].Span))
                Invalid("The genesis artifact bytes moved before final commit.");
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static async ValueTask<GenesisAuthorExternalCommittedPlan>
        CommitExternalStructuralTestAsync(
        GenesisAuthorCreatedPlan created,
        GenesisVerifiedQuorumPlan quorum,
        RecoveryMaterializationPlan materialization,
        GenesisCutoverSourceContext source,
        GenesisCutoverCommitCoordinator coordinator,
        GenesisAuthorJournal journal,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default)
    {
        var dpl = materialization.CanonicalCandidateDpl.ToArray();
        var dplRef = materialization.CandidateDplArtifactReference.ToArray();
        if (dpl.Length != 576 || dplRef.Length != 38 ||
            !CanonicalGrammar.FixedEquals(dplRef, Reference(ArtifactType.Dpl1, dpl)) ||
            !CanonicalGrammar.FixedEquals(
                quorum.Selection.CanonicalSelection.Span.Slice(461, 38),
                Reference(ArtifactType.Dcq1, quorum.QuorumReceipt.CanonicalBytes.Span)))
            Invalid("The structural genesis external commit tuple is invalid.");
        var artifacts = created.ArtifactSet.Artifacts
            .Concat([quorum.QuorumReceipt.CanonicalBytes]).ToArray();
        var commit = await coordinator.CompareExternalZeroToOneAsync(
            new GenesisExternalCutoverCommitRequest(
                artifacts, dpl, source.SourceFingerprint.Span), cancellationToken)
            .ConfigureAwait(false);
        if (commit is null || !commit.Committed || commit.SourceRevision == 0 ||
            !CanonicalGrammar.FixedEquals(commit.CurrentDplReference.Span, dplRef) ||
            !CanonicalGrammar.FixedEquals(
                commit.CurrentSourceFingerprint.Span, source.SourceFingerprint.Span))
            Invalid("The structural external cutover did not install the exact candidate.");
        var nextPrefix = ExternalPrefix(created, quorum, materialization, source);
        var next = await journal.CompareExchangeAsync(
            new GenesisAuthorJournalTransitionRequest(
                created.Journal.CanonicalJournal.Span, nextPrefix), cancellationToken)
            .ConfigureAwait(false);
        var verified = await ValidateJournalTransition(
            created.Journal, next, nextPrefix, 1, created.Candidate.Identity,
            hmacProvider, cancellationToken).ConfigureAwait(false);
        return new GenesisAuthorExternalCommittedPlan(
            created, quorum, materialization, source, verified.Snapshot, verified.Revision);
    }

    internal static async ValueTask<GenesisAuthorLocalCommittedPlan>
        CommitLocalStructuralTestAsync(
        GenesisAuthorExternalCommittedPlan external,
        GenesisCutoverCommitCoordinator coordinator,
        GenesisAuthorJournal journal,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default)
    {
        var dpl = external.Materialization.CanonicalCandidateDpl.ToArray();
        var dplRef = external.Materialization.CandidateDplArtifactReference.ToArray();
        var source = external.Source.SourceFingerprint.ToArray();
        var commit = await coordinator.CompareLocalEmptyToCandidateAsync(
            new GenesisLocalCutoverCommitRequest(dpl, source), cancellationToken)
            .ConfigureAwait(false);
        if (commit is null || !commit.Committed || commit.SourceRevision == 0 ||
            !CanonicalGrammar.FixedEquals(commit.CurrentDplReference.Span, dplRef) ||
            !CanonicalGrammar.FixedEquals(commit.CurrentSourceFingerprint.Span, source))
            Invalid("The structural local cutover did not install the exact candidate.");
        var nextPrefix = LocalPrefix(external);
        var next = await journal.CompareExchangeAsync(
            new GenesisAuthorJournalTransitionRequest(
                external.Journal.CanonicalJournal.Span, nextPrefix), cancellationToken)
            .ConfigureAwait(false);
        var verified = await ValidateJournalTransition(
            external.Journal, next, nextPrefix, 2, external.Created.Candidate.Identity,
            hmacProvider, cancellationToken).ConfigureAwait(false);
        return new GenesisAuthorLocalCommittedPlan(
            external, verified.Snapshot, verified.Revision);
    }
#endif

    internal static async ValueTask<(GenesisAuthorJournalSnapshot Snapshot, ulong Revision)>
        ValidateJournalTransition(
            GenesisAuthorJournalSnapshot expected,
            GenesisAuthorJournalReadResult returned,
            ReadOnlyMemory<byte> nextPrefix,
            byte phase,
            GenesisIdentityContext identity,
            IProtectedHmacProvider hmacProvider,
            CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (returned is null || !returned.Healthy || returned.SourceRevision == 0)
            Invalid("The genesis author journal transition is absent or unhealthy.");
        var canonical = returned!.CanonicalJournal.ToArray();
        try
        {
            GenesisProtectedRecords.PreflightGaj(canonical);
            var priorRevision = BinaryPrimitives.ReadUInt64BigEndian(
                expected.CanonicalJournal.Span.Slice(807, 8));
            if (phase != expected.Phase + 1 ||
                returned.SourceRevision != checked(priorRevision + 1) ||
                returned.SourceRevision != BinaryPrimitives.ReadUInt64BigEndian(
                    canonical.AsSpan(807, 8)) ||
                !CanonicalGrammar.FixedEquals(canonical.AsSpan(0, 807), nextPrefix.Span) ||
                !CanonicalGrammar.FixedEquals(canonical.AsSpan(816, 32),
                    identity.ProtectedStateHmacKeyId))
                Invalid("GAJ1 did not advance by one exact phase.");
            await GenesisProtectedRecords.VerifyAsync(
                "Deep/ProtectedState/V1/GAJ1", canonical,
                GenesisProtectedRecords.GajKeyOffset, hmacProvider, cancellationToken)
                .ConfigureAwait(false);
            return (new GenesisAuthorJournalSnapshot(canonical), returned.SourceRevision);
        }
        finally { Array.Clear(canonical); }
    }

    private static byte[] Reference(ArtifactType type, ReadOnlySpan<byte> canonical) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, canonical));

    private static byte[] ExternalPrefix(
        GenesisAuthorCreatedPlan created,
        GenesisVerifiedQuorumPlan quorum,
        RecoveryMaterializationPlan materialization,
        GenesisCutoverSourceContext source)
    {
        var nextPrefix = created.Journal.CanonicalJournal.Span[..807].ToArray();
        nextPrefix[194] = 1;
        quorum.Selection.SelectionHash.Span.CopyTo(nextPrefix.AsSpan(565));
        Reference(ArtifactType.Dcq1, quorum.QuorumReceipt.CanonicalBytes.Span)
            .CopyTo(nextPrefix, 597);
        materialization.CandidateDplArtifactReference.Span.CopyTo(nextPrefix.AsSpan(635));
        source.SourceFingerprint.Span.CopyTo(nextPrefix.AsSpan(673));
        return nextPrefix;
    }

    private static byte[] LocalPrefix(GenesisAuthorExternalCommittedPlan external)
    {
        var nextPrefix = external.Journal.CanonicalJournal.Span[..807].ToArray();
        nextPrefix[194] = 2;
        external.Materialization.CandidateDplArtifactReference.Span
            .CopyTo(nextPrefix.AsSpan(705));
        external.Source.SourceFingerprint.Span.CopyTo(nextPrefix.AsSpan(743));
        return nextPrefix;
    }

    private static GenesisProtectedKeySetRequest KeyRequest(GenesisIdentityContext identity) =>
        new(identity.BaseIdentity.Network, identity.BaseIdentity.ResetId,
            identity.Scope.ComponentKind, identity.Scope.ComponentSubject,
            identity.BaseIdentity.AccountGeneration);

    private static async ValueTask RevalidateKeysAsync(
        GenesisProtectedKeySetContext keySet,
        GenesisProtectedKeySetRegistry keyRegistry,
        GenesisProtectedKeySetRequest keyRequest,
        GenesisIdentityContext identity,
        CancellationToken cancellationToken) =>
        await keySet.RevalidateAsync(keyRegistry, keyRequest,
            identity.ProtectedStateHmacKeyId.ToArray(), cancellationToken)
            .ConfigureAwait(false);

    private static void EnsureReplayLease(
        VerifiedGenesisReplayHeadSnapshot snapshot,
        GenesisReplayTimePolicy timePolicy)
    {
        var now = timePolicy.GetUnixTimeSeconds();
        if (now == 0 || snapshot.EffectiveLeaseExpiryUnixSeconds == 0 ||
            now >= snapshot.EffectiveLeaseExpiryUnixSeconds)
            throw new RecordException(
                RecordError.Expired, "The genesis replay catch-up lease is expired.");
    }
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<GenesisAuthorExternalCommittedPlan>
        ContinueGenesisReplayExternalAsync(
        ExternalCatchUp catchUp,
        GenesisProtectedKeySetRegistry keyRegistry,
        GenesisAuthorJournal journal,
        GenesisReplayTimePolicy timePolicy,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default) =>
        await GenesisCutoverCommitVerifier.ContinueReplayExternalAsync(
            catchUp, keyRegistry, journal, timePolicy, hmacProvider, cancellationToken)
            .ConfigureAwait(false);

    public static async ValueTask<GenesisAuthorLocalCommittedPlan>
        ContinueGenesisReplayLocalAsync(
        LocalCatchUp catchUp,
        GenesisProtectedKeySetRegistry keyRegistry,
        GenesisCutoverCommitCoordinator coordinator,
        GenesisAuthorJournal journal,
        GenesisReplayTimePolicy timePolicy,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default) =>
        await GenesisCutoverCommitVerifier.ContinueReplayLocalAsync(
            catchUp, keyRegistry, coordinator, journal, timePolicy, hmacProvider,
            cancellationToken).ConfigureAwait(false);

    public static async ValueTask<GenesisAuthorExternalCommittedPlan> CommitGenesisExternalAsync(
        GenesisAuthorCreatedPlan created,
        GenesisVerifiedQuorumPlan quorum,
        RecoveryMaterializationPlan materialization,
        GenesisCutoverSourceContext source,
        GenesisProtectedKeySetRegistry keyRegistry,
        RecoverySealingProvider sealingProvider,
        GenesisResetReservationProvider resetReservationProvider,
        GenesisTransactionReservationProvider transactionProvider,
        GenesisArtifactStore artifactStore,
        GenesisQuorumStateProvider quorumProvider,
        GenesisWitnessHeadProvider witnessHeadProvider,
        GenesisCutoverCommitCoordinator coordinator,
        GenesisAuthorJournal journal,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default) =>
        await GenesisCutoverCommitVerifier.CommitExternalAsync(
            created, quorum, materialization, source, keyRegistry, sealingProvider,
            resetReservationProvider, transactionProvider, artifactStore, quorumProvider,
            witnessHeadProvider, coordinator, journal, hmacProvider, cancellationToken)
            .ConfigureAwait(false);

    public static async ValueTask<GenesisAuthorLocalCommittedPlan> CommitGenesisLocalAsync(
        GenesisAuthorExternalCommittedPlan external,
        GenesisProtectedKeySetRegistry keyRegistry,
        RecoverySealingProvider sealingProvider,
        GenesisResetReservationProvider resetReservationProvider,
        GenesisTransactionReservationProvider transactionProvider,
        GenesisArtifactStore artifactStore,
        GenesisQuorumStateProvider quorumProvider,
        GenesisCutoverCommitCoordinator coordinator,
        GenesisAuthorJournal journal,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default) =>
        await GenesisCutoverCommitVerifier.CommitLocalAsync(
            external, keyRegistry, sealingProvider, resetReservationProvider,
            transactionProvider, artifactStore, quorumProvider, coordinator,
            journal, hmacProvider, cancellationToken)
            .ConfigureAwait(false);
}
