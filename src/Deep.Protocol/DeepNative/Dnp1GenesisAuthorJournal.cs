using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisAuthorJournalCreatedRequest
{
    private readonly byte[] _immutablePrefix;
    internal GenesisAuthorJournalCreatedRequest(ReadOnlySpan<byte> immutablePrefix807)
    {
        if (immutablePrefix807.Length != 807 || immutablePrefix807[194] != 0)
            Invalid("The genesis Created journal request is not exact.");
        _immutablePrefix = immutablePrefix807.ToArray();
    }
    public ReadOnlyMemory<byte> ImmutableCreatedTranscript => _immutablePrefix.ToArray();
    internal ReadOnlySpan<byte> TrustedPrefix => _immutablePrefix;
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisAuthorJournalReadResult
{
    private readonly byte[] _canonical;
    public GenesisAuthorJournalReadResult(
        ReadOnlySpan<byte> canonicalGaj880,
        ulong sourceRevision,
        bool healthy)
    {
        _canonical = canonicalGaj880.ToArray();
        SourceRevision = sourceRevision;
        Healthy = healthy;
    }
    public ReadOnlyMemory<byte> CanonicalJournal => _canonical.ToArray();
    public ulong SourceRevision { get; }
    public bool Healthy { get; }
}

public abstract class GenesisAuthorJournal
{
    public abstract ValueTask<GenesisAuthorJournalReadResult> RestoreOrCreateCreatedAsync(
        GenesisAuthorJournalCreatedRequest request,
        CancellationToken cancellationToken);

    public virtual ValueTask<GenesisAuthorJournalReadResult> CompareExchangeAsync(
        GenesisAuthorJournalTransitionRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("This journal does not support phase transitions.");

    public virtual ValueTask<GenesisAuthorJournalReadResult> RestoreByScopeAsync(
        GenesisAuthorJournalLookupRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("This journal does not support scope-only restore.");

    public virtual ValueTask<GenesisReplayForkLatchReadResult> LatchReplayForkAsync(
        GenesisReplayForkLatchRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("This journal does not support atomic replay fork latching.");

    public virtual ValueTask<GenesisReplayForkLatchReadResult> RestoreReplayForkAsync(
        GenesisReplayScopeV1 scope,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("This journal does not support replay fork receipt restore.");
}

public sealed class GenesisAuthorJournalLookupRequest
{
    private readonly byte[] _scope;
    internal GenesisAuthorJournalLookupRequest(ReadOnlySpan<byte> exactScope154)
    {
        if (exactScope154.Length != 154)
            throw new RecordException(RecordError.InvalidField,
                "The genesis journal lookup scope is invalid.");
        _scope = exactScope154.ToArray();
    }
    public ReadOnlyMemory<byte> ExactLookupScope => _scope.ToArray();
}

public sealed class GenesisAuthorJournalTransitionRequest
{
    private readonly byte[] _expected;
    private readonly byte[] _nextPrefix;
    internal GenesisAuthorJournalTransitionRequest(
        ReadOnlySpan<byte> expectedGaj880,
        ReadOnlySpan<byte> nextPrefix807)
    {
        GenesisProtectedRecords.PreflightGaj(expectedGaj880);
        if (nextPrefix807.Length != 807 || nextPrefix807[194] != expectedGaj880[194] + 1)
            Invalid("The genesis journal transition is not the exact next phase.");
        _expected = expectedGaj880.ToArray();
        _nextPrefix = nextPrefix807.ToArray();
    }
    public ReadOnlyMemory<byte> ExpectedJournal => _expected.ToArray();
    public ReadOnlyMemory<byte> NextImmutableTranscript => _nextPrefix.ToArray();
    internal ReadOnlySpan<byte> TrustedNextPrefix => _nextPrefix;
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisAuthorCreatedPlan
{
    internal GenesisAuthorCreatedPlan(
        GenesisPreExternalCandidatePlan candidate,
        VerifiedGenesisArtifactSet artifactSet,
        GenesisQuorumPending quorumPending,
        GenesisAuthorJournalSnapshot journal,
        ulong journalRevision)
    {
        Candidate = candidate;
        ArtifactSet = artifactSet;
        QuorumPending = quorumPending;
        Journal = journal;
        JournalRevision = journalRevision;
    }
    public GenesisPreExternalCandidatePlan Candidate { get; }
    public VerifiedGenesisArtifactSet ArtifactSet { get; }
    public GenesisQuorumPending QuorumPending { get; }
    public GenesisAuthorJournalSnapshot Journal { get; }
    public ulong JournalRevision { get; }
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisAuthorExternalCommittedPlan
{
    internal GenesisAuthorExternalCommittedPlan(
        GenesisAuthorCreatedPlan created,
        GenesisVerifiedQuorumPlan quorum,
        RecoveryMaterializationPlan materialization,
        GenesisCutoverSourceContext source,
        GenesisAuthorJournalSnapshot journal,
        ulong journalRevision)
    {
        Created = created;
        Quorum = quorum;
        Materialization = materialization;
        Source = source;
        Journal = journal;
        JournalRevision = journalRevision;
    }
    public GenesisAuthorCreatedPlan Created { get; }
    public GenesisVerifiedQuorumPlan Quorum { get; }
    public RecoveryMaterializationPlan Materialization { get; }
    public GenesisAuthorJournalSnapshot Journal { get; }
    public ulong JournalRevision { get; }
    public bool NoAuthorityClaim => true;
    internal GenesisCutoverSourceContext Source { get; }
}

public sealed class GenesisAuthorLocalCommittedPlan
{
    internal GenesisAuthorLocalCommittedPlan(
        GenesisAuthorExternalCommittedPlan external,
        GenesisAuthorJournalSnapshot journal,
        ulong journalRevision)
    {
        External = external;
        Journal = journal;
        JournalRevision = journalRevision;
    }
    public GenesisAuthorExternalCommittedPlan External { get; }
    public GenesisAuthorJournalSnapshot Journal { get; }
    public ulong JournalRevision { get; }
    public bool NoAuthorityClaim => true;
}

public abstract class GenesisAuthorReplayState
{
    private protected GenesisAuthorReplayState(GenesisAuthorJournalSnapshot journal) =>
        Journal = journal;

    public GenesisAuthorJournalSnapshot Journal { get; }
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisCreatedReplayState : GenesisAuthorReplayState
{
    internal GenesisCreatedReplayState(GenesisAuthorJournalSnapshot journal) : base(journal) { }
}

public sealed class GenesisExternalCommittedReplayState : GenesisAuthorReplayState
{
    internal GenesisExternalCommittedReplayState(GenesisAuthorJournalSnapshot journal) :
        base(journal) { }
}

public sealed class GenesisCompletedReplayState : GenesisAuthorReplayState
{
    internal GenesisCompletedReplayState(GenesisAuthorJournalSnapshot journal) : base(journal) { }
    public bool RequiresFreshNormalCurrentRestore => true;
}

internal static class GenesisAuthorJournalVerifier
{
    internal static async ValueTask<GenesisAuthorCreatedPlan> RestoreOrCreateCreatedAsync(
        GenesisPreExternalCandidatePlan plan,
        VerifiedGenesisArtifactSet artifactSet,
        GenesisQuorumPending pending,
        GenesisResetReservationResult reservation,
        GenesisAuthorJournal journal,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(artifactSet);
        ArgumentNullException.ThrowIfNull(pending);
        ArgumentNullException.ThrowIfNull(reservation);
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        var identity = plan.Identity;
        if (!CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId, reservation.ResetId) ||
            !CanonicalGrammar.FixedEquals(artifactSet.Receipt.CanonicalReceipt.Span.Slice(8, 122),
                GenesisArtifactSetVerifier.AuthorScope(identity)) ||
            !CanonicalGrammar.FixedEquals(pending.CanonicalPending.Span.Slice(8, 16),
                identity.BaseIdentity.Network) ||
            !CanonicalGrammar.FixedEquals(pending.CanonicalPending.Span.Slice(24, 32),
                identity.BaseIdentity.ResetId))
            Invalid("The Created journal inputs combine different sealed axes.");

        var prefix = new byte[807];
        "GAJ1"u8.CopyTo(prefix); prefix[4] = 1;
        identity.BaseIdentity.Network.CopyTo(prefix.AsSpan(8));
        identity.BaseIdentity.ResetId.CopyTo(prefix.AsSpan(24));
        BinaryPrimitives.WriteUInt16BigEndian(prefix.AsSpan(56, 2),
            (ushort)identity.Scope.ComponentKind);
        identity.Scope.ComponentSubject.CopyTo(prefix.AsSpan(58));
        BinaryPrimitives.WriteUInt64BigEndian(prefix.AsSpan(90, 8),
            identity.BaseIdentity.AccountGeneration);
        identity.Transaction.TransactionId.CopyTo(prefix.AsSpan(98));
        reservation.OperationId.CopyTo(prefix.AsSpan(130));
        reservation.ReservationHash.Span.CopyTo(prefix.AsSpan(162));
        prefix[194] = 0;
        plan.Candidate.ShadowStateHash.Span.CopyTo(prefix.AsSpan(195));
        Reference(ArtifactType.Drc1, plan.Candidate.Capsule.Record).CopyTo(prefix, 227);
        for (var index = 0; index < 4; index++)
            Reference(ArtifactType.Dcp1, plan.ComponentCheckpoints[index].Record)
                .CopyTo(prefix, 265 + index * 38);
        Reference(ArtifactType.Dcs1, plan.DeploymentSet.Record).CopyTo(prefix, 417);
        Reference(ArtifactType.Dct1, plan.Transaction.Record).CopyTo(prefix, 455);
        artifactSet.Receipt.ReceiptHash.Span.CopyTo(prefix.AsSpan(493));
        pending.PendingHash.Span.CopyTo(prefix.AsSpan(525));
        BinaryPrimitives.WriteUInt64BigEndian(prefix.AsSpan(557, 8),
            BinaryPrimitives.ReadUInt64BigEndian(pending.CanonicalPending.Span.Slice(379, 8)));
        plan.CandidateCoreFingerprint.Span.CopyTo(prefix.AsSpan(775));

        var request = new GenesisAuthorJournalCreatedRequest(prefix);
        var returned = await journal.RestoreOrCreateCreatedAsync(request, cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (returned is null || !returned.Healthy || returned.SourceRevision == 0)
            Invalid("The genesis author journal is absent or unhealthy.");
        var canonical = returned!.CanonicalJournal.ToArray();
        try
        {
            GenesisProtectedRecords.PreflightGaj(canonical);
            if (!CanonicalGrammar.FixedEquals(canonical.AsSpan(0, 807), prefix) ||
                returned.SourceRevision != BinaryPrimitives.ReadUInt64BigEndian(
                    canonical.AsSpan(807, 8)) ||
                !CanonicalGrammar.FixedEquals(canonical.AsSpan(816, 32),
                    identity.ProtectedStateHmacKeyId))
                Invalid("GAJ1 Created differs from the sealed genesis author state.");
            await GenesisProtectedRecords.VerifyAsync(
                "Deep/ProtectedState/V1/GAJ1", canonical,
                GenesisProtectedRecords.GajKeyOffset, hmacProvider, cancellationToken)
                .ConfigureAwait(false);
            return new GenesisAuthorCreatedPlan(plan, artifactSet, pending,
                new GenesisAuthorJournalSnapshot(canonical), returned.SourceRevision);
        }
        finally
        {
            Array.Clear(prefix);
            Array.Clear(canonical);
        }
    }

    internal static async ValueTask<GenesisAuthorJournalSnapshot> RestoreByScopeAsync(
        GenesisIdentityContext identity,
        GenesisResetReservationResult reservation,
        GenesisAuthorJournal journal,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(reservation);
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        if (!CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId, reservation.ResetId))
            Invalid("The genesis journal restore reservation differs from identity.");
        var scope = new byte[154];
        GenesisArtifactSetVerifier.AuthorScope(identity).CopyTo(scope, 0);
        reservation.OperationId.CopyTo(scope.AsSpan(122));
        var returned = await journal.RestoreByScopeAsync(
            new GenesisAuthorJournalLookupRequest(scope), cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (returned is null || !returned.Healthy || returned.SourceRevision == 0)
            Invalid("The retained genesis author journal is absent or unhealthy.");
        var canonical = returned!.CanonicalJournal.ToArray();
        try
        {
            GenesisProtectedRecords.PreflightGaj(canonical);
            if (!CanonicalGrammar.FixedEquals(canonical.AsSpan(8, 122), scope.AsSpan(0, 122)) ||
                !CanonicalGrammar.FixedEquals(canonical.AsSpan(130, 32), reservation.OperationId) ||
                !CanonicalGrammar.FixedEquals(canonical.AsSpan(162, 32), reservation.ReservationHash.Span) ||
                returned.SourceRevision != BinaryPrimitives.ReadUInt64BigEndian(
                    canonical.AsSpan(807, 8)) ||
                !CanonicalGrammar.FixedEquals(canonical.AsSpan(816, 32),
                    identity.ProtectedStateHmacKeyId))
                Invalid("The retained GAJ1 differs from its sealed lookup scope.");
            await GenesisProtectedRecords.VerifyAsync(
                "Deep/ProtectedState/V1/GAJ1", canonical,
                GenesisProtectedRecords.GajKeyOffset, hmacProvider, cancellationToken)
                .ConfigureAwait(false);
            return new GenesisAuthorJournalSnapshot(canonical);
        }
        finally { Array.Clear(canonical); Array.Clear(scope); }
    }

    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static GenesisAuthorReplayState InspectGenesisAuthorReplayState(
        GenesisAuthorJournalSnapshot journal)
    {
        ArgumentNullException.ThrowIfNull(journal);
        return journal.Phase switch
        {
            0 => new GenesisCreatedReplayState(journal),
            1 => new GenesisExternalCommittedReplayState(journal),
            2 => new GenesisCompletedReplayState(journal),
            _ => throw new RecordException(RecordError.InvalidField,
                "The authenticated genesis author journal phase is invalid.")
        };
    }

    public static async ValueTask<GenesisAuthorCreatedPlan> RestoreOrCreateGenesisAuthorCreatedAsync(
        GenesisPreExternalCandidatePlan plan,
        VerifiedGenesisArtifactSet artifactSet,
        GenesisQuorumPending pending,
        GenesisResetReservationResult reservation,
        GenesisAuthorJournal journal,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default) =>
        await GenesisAuthorJournalVerifier.RestoreOrCreateCreatedAsync(
            plan, artifactSet, pending, reservation, journal, hmacProvider,
            cancellationToken).ConfigureAwait(false);

    public static async ValueTask<GenesisAuthorJournalSnapshot> RestoreGenesisAuthorJournalByScopeAsync(
        GenesisIdentityContext identity,
        GenesisResetReservationResult reservation,
        GenesisAuthorJournal journal,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default) =>
        await GenesisAuthorJournalVerifier.RestoreByScopeAsync(
            identity, reservation, journal, hmacProvider, cancellationToken)
            .ConfigureAwait(false);
}
