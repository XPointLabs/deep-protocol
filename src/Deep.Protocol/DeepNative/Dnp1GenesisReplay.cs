using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepNative;

/// <summary>Trusted consumer clock and timeout policy for one bounded replay invocation.</summary>
public abstract class GenesisReplayTimePolicy
{
    public abstract ulong GetUnixTimeSeconds();
    public abstract ulong ReplayTimeoutSeconds { get; }
}

/// <summary>
/// Nonserializable Protocol-minted scope for one locked genesis replay attempt.
/// Consumer implementations receive no raw scope or key identifiers.
/// </summary>
public sealed class GenesisReplayScopeV1
{
    private readonly byte[] _scope;
    internal GenesisReplayScopeV1(ReadOnlySpan<byte> scope122, int attempt, ulong deadline)
    {
        if (scope122.Length != 122 || attempt is < 1 or > 3 || deadline == 0)
            Invalid("The genesis replay head request is invalid.");
        _scope = scope122.ToArray();
        AttemptNumber = attempt;
        DeadlineUnixSeconds = deadline;
    }
    public int AttemptNumber { get; }
    public ulong DeadlineUnixSeconds { get; }
    public bool NoAuthorityClaim => true;
    internal ReadOnlySpan<byte> TrustedScope => _scope;
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

/// <summary>Untrusted external-head data. Protocol validates every byte before use.</summary>
public sealed class GenesisReplayExternalHeadData
{
    private const int DrcMinimumLength = 482;
    private const int DrcMaximumLength = 33_554_914;
    private const int DcpLength = 706;
    private const int DcsLength = 839;
    private const int DctLength = 414;
    private const int DcqMinimumLength = 375;
    private const int DcqMaximumLength = 8_805;
    private const int MaximumAggregateLength = 33_567_796;
    private readonly ReadOnlyMemory<byte>[] _artifacts;
    private readonly byte[] _dplReference;
    private readonly byte[] _source;

    public GenesisReplayExternalHeadData(
        ulong sequence,
        IReadOnlyList<ReadOnlyMemory<byte>> canonicalArtifacts,
        ReadOnlySpan<byte> dplReference38,
        ReadOnlySpan<byte> sourceFingerprint32,
        ulong sourceRevision,
        ulong leaseExpiryUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(canonicalArtifacts);
        if (dplReference38.Length != 38 || sourceFingerprint32.Length != 32)
            Invalid("The external replay head exceeds its closed bounds.");
        ReadOnlyMemory<byte>[] inspected;
        if (sequence == 0)
        {
            if (canonicalArtifacts.Count != 0)
                Invalid("The sequence-zero external replay head contains artifacts.");
            inspected = [];
        }
        else if (sequence == 1)
        {
            if (canonicalArtifacts.Count != 8)
                Invalid("The sequence-one external replay head is not exact-eight.");
            inspected = new ReadOnlyMemory<byte>[8];
            var total = 0;
            for (var index = 0; index < canonicalArtifacts.Count; index++)
            {
                inspected[index] = canonicalArtifacts[index];
                var length = inspected[index].Length;
                var valid = index switch
                {
                    0 => length is >= DrcMinimumLength and <= DrcMaximumLength,
                    >= 1 and <= 4 => length == DcpLength,
                    5 => length == DcsLength,
                    6 => length == DctLength,
                    7 => length is >= DcqMinimumLength and <= DcqMaximumLength,
                    _ => false
                };
                if (!valid)
                    Invalid("An external replay artifact violates its positional bound.");
                total = checked(total + length);
            }
            if (total > MaximumAggregateLength)
                Invalid("The external replay artifact tuple exceeds exact33567796.");
        }
        else
        {
            Invalid("The external replay head sequence is outside zero-or-one.");
            inspected = [];
        }
        Sequence = sequence;
        _artifacts = inspected.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
        _dplReference = dplReference38.ToArray();
        _source = sourceFingerprint32.ToArray();
        SourceRevision = sourceRevision;
        LeaseExpiryUnixSeconds = leaseExpiryUnixSeconds;
    }

    public ulong Sequence { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> CanonicalArtifacts =>
        Array.AsReadOnly(_artifacts.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    public ReadOnlyMemory<byte> DplReference => _dplReference.ToArray();
    public ReadOnlyMemory<byte> SourceFingerprint => _source.ToArray();
    public ulong SourceRevision { get; }
    public ulong LeaseExpiryUnixSeconds { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> TrustedArtifacts => _artifacts;
    internal ReadOnlySpan<byte> TrustedDplReference => _dplReference;
    internal ReadOnlySpan<byte> TrustedSource => _source;

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

/// <summary>Untrusted local DPL plus journal data read in the consumer's locked operation.</summary>
public sealed class GenesisReplayLocalHeadData
{
    private readonly byte[] _dpl;
    private readonly byte[] _dplReference;
    private readonly byte[] _source;
    private readonly byte[] _journal;

    public GenesisReplayLocalHeadData(
        ReadOnlySpan<byte> canonicalDpl,
        ReadOnlySpan<byte> dplReference38,
        ReadOnlySpan<byte> sourceFingerprint32,
        ulong sourceRevision,
        ReadOnlySpan<byte> canonicalGaj880,
        ulong journalSourceRevision)
    {
        if (canonicalDpl.Length is not (0 or 576) || dplReference38.Length != 38 ||
            sourceFingerprint32.Length != 32 || canonicalGaj880.Length != 880)
            Invalid("The local replay head is outside its closed shape.");
        _dpl = canonicalDpl.ToArray();
        _dplReference = dplReference38.ToArray();
        _source = sourceFingerprint32.ToArray();
        _journal = canonicalGaj880.ToArray();
        SourceRevision = sourceRevision;
        JournalSourceRevision = journalSourceRevision;
    }
    public ReadOnlyMemory<byte> CanonicalDpl => _dpl.ToArray();
    public ReadOnlyMemory<byte> DplReference => _dplReference.ToArray();
    public ReadOnlyMemory<byte> SourceFingerprint => _source.ToArray();
    public ulong SourceRevision { get; }
    public ReadOnlyMemory<byte> CanonicalJournal => _journal.ToArray();
    public ulong JournalSourceRevision { get; }
    internal ReadOnlySpan<byte> TrustedDpl => _dpl;
    internal ReadOnlySpan<byte> TrustedDplReference => _dplReference;
    internal ReadOnlySpan<byte> TrustedSource => _source;
    internal ReadOnlySpan<byte> TrustedJournal => _journal;
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisReplayHeadReadResult
{
    public GenesisReplayHeadReadResult(
        GenesisReplayExternalHeadData preliminaryExternal,
        GenesisReplayLocalHeadData local,
        GenesisReplayExternalHeadData authoritativeExternal)
    {
        PreliminaryExternal = preliminaryExternal ??
            throw new ArgumentNullException(nameof(preliminaryExternal));
        Local = local ?? throw new ArgumentNullException(nameof(local));
        AuthoritativeExternal = authoritativeExternal ??
            throw new ArgumentNullException(nameof(authoritativeExternal));
    }
    public GenesisReplayExternalHeadData PreliminaryExternal { get; }
    public GenesisReplayLocalHeadData Local { get; }
    public GenesisReplayExternalHeadData AuthoritativeExternal { get; }
}

/// <summary>
/// Performs preliminary external read, transactional GAJ/local read and authoritative external
/// read under one per-scope lock. Implementations must honor request deadline and cancellation
/// before and after each internal read.
/// </summary>
public abstract class GenesisReplayHeadProvider
{
    public abstract ValueTask<GenesisReplayHeadReadResult> ReadLockedAsync(
        GenesisReplayScopeV1 scope,
        CancellationToken cancellationToken);
}

public sealed class GenesisReplayForkLatchRequest
{
    private readonly byte[] _expectedJournal;
    private readonly byte[] _evidence;
    private readonly byte[] _evidenceHash;
    internal GenesisReplayForkLatchRequest(
        ReadOnlySpan<byte> expectedJournal880,
        ReadOnlySpan<byte> evidenceTranscript1056,
        ReadOnlySpan<byte> evidenceHash32,
        ulong effectiveLeaseExpiry,
        ulong invocationDeadline)
    {
        GenesisProtectedRecords.PreflightGaj(expectedJournal880);
        if (evidenceTranscript1056.Length != 1056 || evidenceHash32.Length != 32 ||
            evidenceTranscript1056[122] is < 1 or > 3 || invocationDeadline == 0)
            Invalid("The genesis replay fork-latch request is invalid.");
        _expectedJournal = expectedJournal880.ToArray();
        _evidence = evidenceTranscript1056.ToArray();
        _evidenceHash = evidenceHash32.ToArray();
        MutationDeadlineUnixSeconds = effectiveLeaseExpiry == 0
            ? invocationDeadline : Math.Min(effectiveLeaseExpiry, invocationDeadline);
        if (MutationDeadlineUnixSeconds == 0)
            Invalid("The genesis replay fork-latch deadline is zero.");
    }
    public ReadOnlyMemory<byte> ExpectedJournal => _expectedJournal.ToArray();
    public ReadOnlyMemory<byte> EvidenceTranscript => _evidence.ToArray();
    public ReadOnlyMemory<byte> EvidenceHash => _evidenceHash.ToArray();
    public ulong MutationDeadlineUnixSeconds { get; }
    public bool NoAuthorityClaim => true;
    internal ReadOnlySpan<byte> TrustedExpectedJournal => _expectedJournal;
    internal ReadOnlySpan<byte> TrustedEvidence => _evidence;
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisReplayForkLatchReadResult
{
    private readonly byte[] _gfl;
    private readonly byte[] _journal;
    public GenesisReplayForkLatchReadResult(
        ReadOnlySpan<byte> canonicalGfl1176,
        ReadOnlySpan<byte> canonicalGaj880,
        bool healthy)
    {
        _gfl = canonicalGfl1176.ToArray();
        _journal = canonicalGaj880.ToArray();
        Healthy = healthy;
    }
    public ReadOnlyMemory<byte> CanonicalForkLatch => _gfl.ToArray();
    public ReadOnlyMemory<byte> CanonicalJournal => _journal.ToArray();
    public bool Healthy { get; }
}

public abstract class GenesisReplayDisposition
{
    private protected GenesisReplayDisposition() { }
    public bool NoAuthorityClaim => true;
}

/// <summary>
/// Protocol-minted authentication result for one stable final replay tuple.
/// It deliberately exposes neither raw tuple bytes nor a public construction path.
/// </summary>
public sealed class VerifiedGenesisReplayHeadSnapshot
{
    private readonly byte[] _observedTuple;
    internal VerifiedGenesisReplayHeadSnapshot(
        ReadOnlySpan<byte> observedTuple519,
        ulong effectiveLeaseExpiryUnixSeconds)
    {
        if (observedTuple519.Length != 519)
            Invalid("The verified genesis replay tuple is not exact519.");
        _observedTuple = observedTuple519.ToArray();
        EffectiveLeaseExpiryUnixSeconds = effectiveLeaseExpiryUnixSeconds;
    }
    public bool NoAuthorityClaim => true;
    internal ReadOnlySpan<byte> TrustedObservedTuple => _observedTuple;
    internal ulong EffectiveLeaseExpiryUnixSeconds { get; }
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class CreatedContinue : GenesisReplayDisposition
{
    internal CreatedContinue(GenesisAuthorCreatedPlan created) => Created = created;
    public GenesisAuthorCreatedPlan Created { get; }
}

public sealed class ExternalCatchUp : GenesisReplayDisposition
{
    internal ExternalCatchUp(
        GenesisAuthorCreatedPlan created,
        GenesisVerifiedQuorumPlan quorum,
        RecoveryMaterializationPlan materialization,
        GenesisCutoverSourceContext source,
        GenesisProtectedKeySetContext keySet,
        VerifiedGenesisReplayHeadSnapshot snapshot)
    {
        Created = created;
        Quorum = quorum;
        Materialization = materialization;
        Source = source;
        KeySet = keySet;
        Snapshot = snapshot;
    }
    public GenesisAuthorCreatedPlan Created { get; }
    public GenesisVerifiedQuorumPlan Quorum { get; }
    public RecoveryMaterializationPlan Materialization { get; }
    internal GenesisProtectedKeySetContext KeySet { get; }
    internal GenesisCutoverSourceContext Source { get; }
    internal VerifiedGenesisReplayHeadSnapshot Snapshot { get; }
}

public sealed class LocalCatchUp : GenesisReplayDisposition
{
    internal LocalCatchUp(
        GenesisAuthorExternalCommittedPlan external,
        GenesisProtectedKeySetContext keySet,
        VerifiedGenesisReplayHeadSnapshot snapshot,
        bool localAlreadyInstalled)
    {
        External = external;
        KeySet = keySet;
        Snapshot = snapshot;
        LocalAlreadyInstalled = localAlreadyInstalled;
    }
    public GenesisAuthorExternalCommittedPlan External { get; }
    internal GenesisProtectedKeySetContext KeySet { get; }
    internal VerifiedGenesisReplayHeadSnapshot Snapshot { get; }
    internal bool LocalAlreadyInstalled { get; }
}

public sealed class NormalCurrentRequired : GenesisReplayDisposition
{
    internal NormalCurrentRequired() { }
    public bool RequiresFreshNormalCurrentRestore => true;
}

public sealed class ExternalCheckpointAhead : GenesisReplayDisposition
{
    internal ExternalCheckpointAhead() { }
}

internal static class GenesisReplayPrimitives
{
    internal static byte[] Scope(GenesisIdentityContext identity)
    {
        var scope = new byte[122];
        identity.BaseIdentity.Network.CopyTo(scope);
        identity.BaseIdentity.ResetId.CopyTo(scope.AsSpan(16));
        BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(48, 2),
            (ushort)identity.Scope.ComponentKind);
        identity.Scope.ComponentSubject.CopyTo(scope.AsSpan(50));
        BinaryPrimitives.WriteUInt64BigEndian(scope.AsSpan(82, 8),
            identity.BaseIdentity.AccountGeneration);
        identity.Transaction.TransactionId.CopyTo(scope.AsSpan(90));
        return scope;
    }

    internal static bool SameStableHead(
        GenesisReplayExternalHeadData left,
        GenesisReplayExternalHeadData right)
    {
        if (left.Sequence != right.Sequence ||
            !CanonicalGrammar.FixedEquals(left.TrustedDplReference, right.TrustedDplReference) ||
            !CanonicalGrammar.FixedEquals(left.TrustedSource, right.TrustedSource) ||
            left.TrustedArtifacts.Count != right.TrustedArtifacts.Count)
            return false;
        for (var index = 0; index < left.TrustedArtifacts.Count; index++)
            if (!CanonicalGrammar.FixedEquals(left.TrustedArtifacts[index].Span,
                    right.TrustedArtifacts[index].Span))
                return false;
        return true;
    }

    internal static bool StableForUse(
        GenesisReplayExternalHeadData preliminary,
        GenesisReplayExternalHeadData final) =>
        SameStableHead(preliminary, final) &&
        final.SourceRevision >= preliminary.SourceRevision &&
        final.LeaseExpiryUnixSeconds >= preliminary.LeaseExpiryUnixSeconds;

    internal static byte[] JournalHash(ReadOnlySpan<byte> canonicalGaj880)
    {
        Span<byte> framed = stackalloc byte[4 + GenesisProtectedRecords.GajLength];
        BinaryPrimitives.WriteUInt32BigEndian(framed, GenesisProtectedRecords.GajLength);
        canonicalGaj880.CopyTo(framed[4..]);
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V9/genesis-author-journal-hash", framed);
    }

    internal static byte[] EvidenceHash(ReadOnlySpan<byte> transcript1056)
    {
        var framed = new byte[4 + transcript1056.Length];
        BinaryPrimitives.WriteUInt32BigEndian(framed, checked((uint)transcript1056.Length));
        transcript1056.CopyTo(framed.AsSpan(4));
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V8/genesis-replay-fork-evidence", framed);
    }
}

internal enum GenesisReplayMatrixCase
{
    CreatedContinue,
    ExternalCatchUp,
    LocalCatchUp,
    NormalCurrentRequired,
    ExternalCheckpointAhead
}

internal static class GenesisReplayMatrix
{
    internal static GenesisReplayMatrixCase Classify(
        byte phase, int externalKind, int localKind) =>
        (phase, externalKind, localKind) switch
        {
            (0, 0, 0) => GenesisReplayMatrixCase.CreatedContinue,
            (0, 1, 0) => GenesisReplayMatrixCase.ExternalCatchUp,
            (1, 1, 0 or 1) => GenesisReplayMatrixCase.LocalCatchUp,
            (2, 1, 1) => GenesisReplayMatrixCase.NormalCurrentRequired,
            _ => GenesisReplayMatrixCase.ExternalCheckpointAhead
        };
}

internal static class GenesisReplayVerifier
{
    private const int MaximumAttempts = 3;
    private const ulong MaximumLinkedTimeoutSeconds = 4_294_967;

    internal static async ValueTask<GenesisReplayDisposition> RestoreAsync(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisResetReservationResult reservation,
        GenesisProtectedKeySetContext keySet,
        GenesisProtectedKeySetRegistry keyRegistry,
        GenesisRecoveryProtectorContext protector,
        RecoverySealingProvider sealingProvider,
        GenesisCutoverSourceContext source,
        GenesisArtifactStore artifactStore,
        GenesisQuorumStateProvider quorumProvider,
        GenesisAuthorJournal journalProvider,
        GenesisReplayHeadProvider headProvider,
        GenesisReplayTimePolicy timePolicy,
        RecoveryProtectorProvider recoveryProvider,
        RecoveryNonceLatch nonceLatch,
        IProtectedHmacProvider protectedHmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(reservation);
        ArgumentNullException.ThrowIfNull(keySet);
        ArgumentNullException.ThrowIfNull(keyRegistry);
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(sealingProvider);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(artifactStore);
        ArgumentNullException.ThrowIfNull(quorumProvider);
        ArgumentNullException.ThrowIfNull(journalProvider);
        ArgumentNullException.ThrowIfNull(headProvider);
        ArgumentNullException.ThrowIfNull(timePolicy);
        ArgumentNullException.ThrowIfNull(recoveryProvider);
        ArgumentNullException.ThrowIfNull(nonceLatch);
        ArgumentNullException.ThrowIfNull(protectedHmacProvider);
        cancellationToken.ThrowIfCancellationRequested();

        var started = timePolicy.GetUnixTimeSeconds();
        var timeout = timePolicy.ReplayTimeoutSeconds;
        if (started == 0 || timeout == 0 || timeout > MaximumLinkedTimeoutSeconds ||
            started > ulong.MaxValue - timeout)
            Invalid("The genesis replay absolute-deadline policy is invalid.");
        var deadline = started + timeout;
        var scope = GenesisReplayPrimitives.Scope(identity);
        using var deadlineCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadlineCancellation.CancelAfter(TimeSpan.FromSeconds(timeout));
        var invocationToken = deadlineCancellation.Token;

        for (var attempt = 1; attempt <= MaximumAttempts; attempt++)
        {
            CheckTime(timePolicy, started, deadline, invocationToken);
            var sealedScope = new GenesisReplayScopeV1(scope, attempt, deadline);
            var read = await ReadStableAttemptAsync(
                sealedScope, headProvider, invocationToken).ConfigureAwait(false);
            CheckTime(timePolicy, started, deadline, invocationToken);
            if (read is null) continue;

            var disposition = await VerifyStableAsync(
                identity, intent, release, reservation, keySet, keyRegistry,
                protector, sealingProvider, source, artifactStore, quorumProvider,
                journalProvider, sealedScope, read, timePolicy, started, deadline, recoveryProvider,
                nonceLatch, protectedHmacProvider, invocationToken)
                .ConfigureAwait(false);
            CheckTime(timePolicy, started, deadline, invocationToken);
            return disposition;
        }

        throw new RecordException(RecordError.Expired,
            "The genesis replay movement budget was exhausted without a stable disposition.");
    }

    internal static async ValueTask<GenesisReplayHeadReadResult?> ReadStableAttemptAsync(
        GenesisReplayScopeV1 sealedScope,
        GenesisReplayHeadProvider headProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sealedScope);
        ArgumentNullException.ThrowIfNull(headProvider);
        cancellationToken.ThrowIfCancellationRequested();
        var read = await headProvider.ReadLockedAsync(sealedScope, cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (read is null) Invalid("The locked genesis replay read returned no state.");
        return GenesisReplayPrimitives.StableForUse(
            read!.PreliminaryExternal, read.AuthoritativeExternal) ? read : null;
    }

    private static async ValueTask<GenesisReplayDisposition> VerifyStableAsync(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisResetReservationResult reservation,
        GenesisProtectedKeySetContext keySet,
        GenesisProtectedKeySetRegistry keyRegistry,
        GenesisRecoveryProtectorContext protector,
        RecoverySealingProvider sealingProvider,
        GenesisCutoverSourceContext source,
        GenesisArtifactStore artifactStore,
        GenesisQuorumStateProvider quorumProvider,
        GenesisAuthorJournal journalProvider,
        GenesisReplayScopeV1 sealedScope,
        GenesisReplayHeadReadResult read,
        GenesisReplayTimePolicy timePolicy,
        ulong started,
        ulong deadline,
        RecoveryProtectorProvider recoveryProvider,
        RecoveryNonceLatch nonceLatch,
        IProtectedHmacProvider protectedHmacProvider,
        CancellationToken cancellationToken)
    {
        var local = read.Local;
        var journal = await GenesisAuthorReplayVerifier.VerifyJournalSnapshotAsync(
            identity, reservation, local, protectedHmacProvider, cancellationToken)
            .ConfigureAwait(false);
        var keyRequest = new GenesisProtectedKeySetRequest(
            identity.BaseIdentity.Network, identity.BaseIdentity.ResetId,
            intent.ComponentKind, intent.ComponentSubject.Span,
            identity.BaseIdentity.AccountGeneration);
        var protectorRequest = new GenesisRecoveryProtectorRequest(identity, intent);
        if (journal.ForkLatched)
        {
            await VerifyRestoredForkLatchAsync(
                identity, journal, local, sealedScope, journalProvider, keySet,
                keyRegistry, keyRequest, protectedHmacProvider, cancellationToken)
                .ConfigureAwait(false);
            return new ExternalCheckpointAhead();
        }
        await keySet.RevalidateAsync(keyRegistry, keyRequest,
            identity.ProtectedStateHmacKeyId.ToArray(), cancellationToken)
            .ConfigureAwait(false);
        await protector.RevalidateAsync(sealingProvider, protectorRequest,
            identity.ProtectedStateHmacKeyId.ToArray(), keySet, cancellationToken)
            .ConfigureAwait(false);

        var artifacts = await GenesisArtifactSetVerifier.RestoreByScopeAsync(
            identity, artifactStore, protectedHmacProvider, cancellationToken)
            .ConfigureAwait(false);
        var pending = await GenesisQuorumStateVerifier.RestorePendingByScopeAsync(
            artifacts, identity, release, quorumProvider, protectedHmacProvider,
            cancellationToken).ConfigureAwait(false);
        GenesisAuthorReplayVerifier.VerifyJournalBindings(artifacts, pending, journal);
        var candidate = await RecoveryEngine.OpenGenesisAuthorReplayAsync(
            artifacts, journal, identity, intent, release, keySet, protector, source,
            recoveryProvider, nonceLatch, protectedHmacProvider, cancellationToken)
            .ConfigureAwait(false);
        GenesisPreExternalCandidatePlan? reconstructed = null;
        try
        {
            reconstructed = Reconstruct(candidate, artifacts, identity, intent, release, source);
            var created = new GenesisAuthorCreatedPlan(
                reconstructed, artifacts, pending, journal, local.JournalSourceRevision);
            var external = read.AuthoritativeExternal;
            ValidateClosedHeadShape(external, local);
            var now = timePolicy.GetUnixTimeSeconds();
            if (now < started || now >= deadline)
                throw new OperationCanceledException("The genesis replay deadline expired.");

            GenesisVerifiedQuorumPlan? quorum = null;
            RecoveryMaterializationPlan? materialization = null;
            var externalKind = external.Sequence == 0 ? 0 : 2;
            if (external.Sequence == 1)
            {
                if (external.TrustedArtifacts.Count != 8)
                    Invalid("The sequence-one external replay head is incomplete.");
                for (var index = 0; index < 7; index++)
                    if (!CanonicalGrammar.FixedEquals(
                            external.TrustedArtifacts[index].Span, artifacts.Artifacts[index].Span))
                        Invalid("The external replay artifact tuple is not the authenticated candidate.");
                quorum = await GenesisQuorumStateVerifier.VerifyAndCompleteRestoredAsync(
                    reconstructed, release, pending, external.TrustedArtifacts[7], now,
                    quorumProvider, protectedHmacProvider, cancellationToken)
                    .ConfigureAwait(false);
                await keySet.RevalidateAsync(keyRegistry, keyRequest,
                    identity.ProtectedStateHmacKeyId.ToArray(), cancellationToken)
                    .ConfigureAwait(false);
                materialization = await RecoveryVerifier.MaterializeGenesisReplayCandidateDplAsync(
                    candidate, artifacts, quorum, identity, keySet,
                    protectedHmacProvider, cancellationToken).ConfigureAwait(false);
                await keySet.RevalidateAsync(keyRegistry, keyRequest,
                    identity.ProtectedStateHmacKeyId.ToArray(), cancellationToken)
                    .ConfigureAwait(false);
                var expectedDplRef = materialization.CandidateDplArtifactReference.Span;
                externalKind = CanonicalGrammar.FixedEquals(
                                   external.TrustedDplReference, expectedDplRef) &&
                               CanonicalGrammar.FixedEquals(
                                   external.TrustedSource, source.SourceFingerprint.Span)
                    ? 1 : 2;
                if (journal.Phase != 0 &&
                    !JournalMatchesExternalCandidate(
                        journal, quorum, materialization, source))
                    externalKind = 2;
                var authenticatedLease = EffectiveLease(external);
                if (authenticatedLease == 0 || now >= authenticatedLease)
                    throw new RecordException(RecordError.Expired,
                        "The authoritative genesis replay lease is expired.");
            }

            var localKind = ValidateLocal(local, materialization, source, keySet);
            var effectiveLease = external.Sequence == 0 ? 0 : EffectiveLease(external);
            var observedTuple = ObservedTuple(external, local,
                journal.CanonicalJournal.Span, effectiveLease);
            var snapshot = new VerifiedGenesisReplayHeadSnapshot(
                observedTuple, effectiveLease);
            CryptographicOperations.ZeroMemory(observedTuple);
            var phase = journal.Phase;
            var matrixCase = GenesisReplayMatrix.Classify(
                phase, externalKind, localKind);
            if (matrixCase == GenesisReplayMatrixCase.CreatedContinue)
            {
                candidate.Dispose();
                candidate = null!;
                return new CreatedContinue(created);
            }
            if (matrixCase == GenesisReplayMatrixCase.ExternalCatchUp)
            {
                candidate.Dispose();
                candidate = null!;
                return new ExternalCatchUp(
                    created, quorum!, materialization!, source, keySet, snapshot);
            }
            if (matrixCase == GenesisReplayMatrixCase.LocalCatchUp)
            {
                var externalPlan = new GenesisAuthorExternalCommittedPlan(
                    created, quorum!, materialization!, source, journal,
                    local.JournalSourceRevision);
                candidate.Dispose();
                candidate = null!;
                return new LocalCatchUp(
                    externalPlan, keySet, snapshot, localKind == 1);
            }
            if (matrixCase == GenesisReplayMatrixCase.NormalCurrentRequired)
            {
                candidate.Dispose();
                candidate = null!;
                reconstructed.Candidate.Dispose();
                return new NormalCurrentRequired();
            }

            var reason = externalKind == 2 ? (byte)1 :
                localKind == 2 ? (byte)2 : (byte)3;
            await LatchForkAsync(identity, journal, snapshot, reason,
                journalProvider, keySet, keyRegistry, keyRequest,
                timePolicy, started, deadline, protectedHmacProvider, cancellationToken)
                .ConfigureAwait(false);
            candidate.Dispose();
            candidate = null!;
            reconstructed.Candidate.Dispose();
            return new ExternalCheckpointAhead();
        }
        catch
        {
            candidate?.Dispose();
            reconstructed?.Candidate.Dispose();
            throw;
        }
    }

    internal static GenesisPreExternalCandidatePlan Reconstruct(
        RecoveryCandidatePlan candidate,
        VerifiedGenesisArtifactSet artifacts,
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisCutoverSourceContext source)
    {
        var rsm = GenesisRecoveryManifestAuthor.BuildRsm(
            identity, intent, release, source, candidate.Manifest);
        var sealedCandidate = new SealedGenesisRecoveryCandidate(
            candidate.Capsule, candidate.Manifest.CanonicalSpan, rsm);
        try
        {
            var checkpoints = artifacts.Artifacts.Skip(1).Take(4).Select(value =>
                new ComponentCheckpoint(CanonicalGrammar.DecodeOwned(
                    value.Span, RecordDefinitions.Dcp1))).ToArray();
            var deployment = new DeploymentSet(CanonicalGrammar.DecodeOwned(
                artifacts.Artifacts[5].Span, RecordDefinitions.Dcs1));
            var transaction = new CasTranscript(CanonicalGrammar.DecodeOwned(
                artifacts.Artifacts[6].Span, RecordDefinitions.Dct1));
            var gas = artifacts.Receipt.CanonicalReceipt.Span;
            return new GenesisPreExternalCandidatePlan(
                sealedCandidate, identity, checkpoints, deployment, transaction,
                gas.Slice(132, 32), gas.Slice(164, 32),
                transaction.Record.FieldSpan(2), BinaryPrimitives.ReadUInt64BigEndian(
                    gas.Slice(196, 8)));
        }
        catch
        {
            sealedCandidate.Dispose();
            throw;
        }
        finally { CryptographicOperations.ZeroMemory(rsm); }
    }

    internal static void ValidateClosedHeadShape(
        GenesisReplayExternalHeadData external,
        GenesisReplayLocalHeadData local)
    {
        if (external.SourceRevision == 0 || local.SourceRevision == 0 ||
            local.JournalSourceRevision == 0)
            Invalid("A genesis replay source revision is zero.");
        if (external.Sequence == 0)
        {
            if (external.TrustedArtifacts.Count != 0 ||
                !CanonicalGrammar.IsZero(external.TrustedDplReference) ||
                !CanonicalGrammar.IsZero(external.TrustedSource) ||
                external.LeaseExpiryUnixSeconds != 0)
                Invalid("The sequence-zero external replay head is not canonical.");
        }
        else if (external.Sequence != 1 || external.TrustedArtifacts.Count != 8 ||
                 CanonicalGrammar.IsZero(external.TrustedDplReference) ||
                 CanonicalGrammar.IsZero(external.TrustedSource) ||
                 external.LeaseExpiryUnixSeconds == 0)
            Invalid("The sequence-one external replay head is not canonical.");

        if (local.TrustedDpl.Length == 0)
        {
            if (!CanonicalGrammar.IsZero(local.TrustedDplReference) ||
                !CanonicalGrammar.IsZero(local.TrustedSource))
                Invalid("The empty local replay head contains a DPL assertion.");
        }
        else if (CanonicalGrammar.IsZero(local.TrustedDplReference) ||
                 CanonicalGrammar.IsZero(local.TrustedSource))
            Invalid("The nonempty local replay head omits its DPL assertion.");
    }

    internal static int ValidateLocal(
        GenesisReplayLocalHeadData local,
        RecoveryMaterializationPlan? materialization,
        GenesisCutoverSourceContext source,
        GenesisProtectedKeySetContext keySet)
    {
        if (local.TrustedDpl.Length == 0) return 0;
        if (materialization is null) return 2;
        var expected = materialization.CanonicalCandidateDpl.Span;
        var reference = materialization.CandidateDplArtifactReference.Span;
        if (!CanonicalGrammar.FixedEquals(local.TrustedDpl, expected) ||
            !CanonicalGrammar.FixedEquals(local.TrustedDplReference, reference) ||
            !CanonicalGrammar.FixedEquals(local.TrustedSource, source.SourceFingerprint.Span))
            return 2;
        var dpl = CanonicalGrammar.DecodeOwned(local.TrustedDpl, RecordDefinitions.Dpl1);
        return CanonicalGrammar.FixedEquals(dpl.FieldSpan(18), expected.Slice(expected.Length - 32)) &&
               !CanonicalGrammar.IsZero(keySet.DplKeyId) ? 1 : 2;
    }

    private static bool JournalMatchesExternalCandidate(
        GenesisAuthorJournalSnapshot journal,
        GenesisVerifiedQuorumPlan quorum,
        RecoveryMaterializationPlan materialization,
        GenesisCutoverSourceContext source)
    {
        var canonical = journal.CanonicalJournal.Span;
        return CanonicalGrammar.FixedEquals(
                   canonical.Slice(565, 32), quorum.Selection.SelectionHash.Span) &&
               CanonicalGrammar.FixedEquals(canonical.Slice(597, 38), Reference(
                   ArtifactType.Dcq1, quorum.QuorumReceipt.CanonicalBytes.Span)) &&
               CanonicalGrammar.FixedEquals(canonical.Slice(635, 38),
                   materialization.CandidateDplArtifactReference.Span) &&
               CanonicalGrammar.FixedEquals(canonical.Slice(673, 32),
                   source.SourceFingerprint.Span);
    }

    private static ulong EffectiveLease(GenesisReplayExternalHeadData external)
    {
        var minimum = external.LeaseExpiryUnixSeconds;
        for (var index = 1; index <= 4; index++)
        {
            var dcp = CanonicalGrammar.DecodeOwned(
                external.TrustedArtifacts[index].Span, RecordDefinitions.Dcp1);
            minimum = Math.Min(minimum, Scalars.UInt64(dcp.FieldSpan(14)));
        }
        var dcs = CanonicalGrammar.DecodeOwned(
            external.TrustedArtifacts[5].Span, RecordDefinitions.Dcs1);
        var dct = CanonicalGrammar.DecodeOwned(
            external.TrustedArtifacts[6].Span, RecordDefinitions.Dct1);
        var dcq = CanonicalGrammar.DecodeOwned(
            external.TrustedArtifacts[7].Span, RecordDefinitions.Dcq1);
        minimum = Math.Min(minimum, Scalars.UInt64(dcs.FieldSpan(13)));
        minimum = Math.Min(minimum, Scalars.UInt64(dct.FieldSpan(9)));
        minimum = Math.Min(minimum, Scalars.UInt64(dcq.FieldSpan(12)));
        return minimum;
    }

    internal static async ValueTask VerifyRestoredForkLatchAsync(
        GenesisIdentityContext identity,
        GenesisAuthorJournalSnapshot journal,
        GenesisReplayLocalHeadData local,
        GenesisReplayScopeV1 sealedScope,
        GenesisAuthorJournal provider,
        GenesisProtectedKeySetContext keySet,
        GenesisProtectedKeySetRegistry keyRegistry,
        GenesisProtectedKeySetRequest keyRequest,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        await keySet.RevalidateAsync(keyRegistry, keyRequest,
            identity.ProtectedStateHmacKeyId.ToArray(), cancellationToken)
            .ConfigureAwait(false);
        var returned = await provider.RestoreReplayForkAsync(
            sealedScope, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (returned is null || !returned.Healthy)
            Invalid("The durable genesis replay fork receipt is absent or unhealthy.");
        var gfl = returned!.CanonicalForkLatch.ToArray();
        var latchedJournal = returned.CanonicalJournal.ToArray();
        byte[]? reconstructedPrior = null;
        byte[]? priorUnsigned = null;
        byte[]? expectedJournalHash = null;
        try
        {
            GenesisProtectedRecords.PreflightGfl(gfl);
            GenesisProtectedRecords.PreflightGaj(
                latchedJournal, requireUnlatched: false);
            if (!CanonicalGrammar.FixedEquals(
                    latchedJournal, local.TrustedJournal) ||
                !CanonicalGrammar.FixedEquals(
                    latchedJournal, journal.CanonicalJournal.Span))
                Invalid("The restored GFL1 does not accompany the locked GAJ1.");
            await GenesisProtectedRecords.VerifyAsync(
                "Deep/ProtectedState/V1/GFL1", gfl,
                GenesisProtectedRecords.GflKeyOffset, hmacProvider, cancellationToken)
                .ConfigureAwait(false);
            await GenesisProtectedRecords.VerifyAsync(
                "Deep/ProtectedState/V1/GAJ1", latchedJournal,
                GenesisProtectedRecords.GajKeyOffset, hmacProvider, cancellationToken)
                .ConfigureAwait(false);

            var transcript = gfl.AsSpan(8, 1056);
            var evidenceHash = GenesisReplayPrimitives.EvidenceHash(transcript);
            var currentRevision = BinaryPrimitives.ReadUInt64BigEndian(
                latchedJournal.AsSpan(807, 8));
            var expectedRevision = BinaryPrimitives.ReadUInt64BigEndian(
                transcript.Slice(155, 8));
            if (!CanonicalGrammar.FixedEquals(
                    transcript[..122], sealedScope.TrustedScope) ||
                !CanonicalGrammar.FixedEquals(gfl.AsSpan(1064, 32), evidenceHash) ||
                expectedRevision == ulong.MaxValue ||
                currentRevision != expectedRevision + 1 ||
                BinaryPrimitives.ReadUInt64BigEndian(gfl.AsSpan(1096, 8)) !=
                    currentRevision ||
                latchedJournal[815] != 1 ||
                !CanonicalGrammar.FixedEquals(
                    gfl.AsSpan(1112, 32), latchedJournal.AsSpan(816, 32)) ||
                !CanonicalGrammar.FixedEquals(
                    transcript.Slice(163, 374), ExpectedSlots(latchedJournal)))
                Invalid("The durable GFL1 receipt differs from the latched GAJ1.");

            var observed = transcript.Slice(537, 519);
            expectedJournalHash = transcript.Slice(123, 32).ToArray();
            ValidateRestoredObservedTuple(
                observed, latchedJournal, expectedJournalHash);
            var observedAt = BinaryPrimitives.ReadUInt64BigEndian(gfl.AsSpan(1104, 8));
            var observedLease = BinaryPrimitives.ReadUInt64BigEndian(observed.Slice(503, 8));
            if (observedAt == 0 ||
                (observed[0] == 1 && observedAt >= observedLease))
                Invalid("The durable GFL1 receipt time is outside its observed lease.");

            priorUnsigned = latchedJournal.AsSpan(0, 848).ToArray();
            BinaryPrimitives.WriteUInt64BigEndian(
                priorUnsigned.AsSpan(807, 8), expectedRevision);
            priorUnsigned[815] = 0;
            reconstructedPrior = await GenesisProtectedRecords.AuthorAsync(
                "Deep/ProtectedState/V1/GAJ1", priorUnsigned,
                priorUnsigned.AsMemory(816, 32), GenesisProtectedRecords.GajLength,
                hmacProvider, cancellationToken).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(priorUnsigned);
            if (!CanonicalGrammar.FixedEquals(
                    expectedJournalHash,
                    GenesisReplayPrimitives.JournalHash(reconstructedPrior)))
                Invalid("GFL1 does not bind the exact pre-latch GAJ1 hash.");
            await keySet.RevalidateAsync(keyRegistry, keyRequest,
                identity.ProtectedStateHmacKeyId.ToArray(), cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            if (reconstructedPrior is not null)
                CryptographicOperations.ZeroMemory(reconstructedPrior);
            if (priorUnsigned is not null)
                CryptographicOperations.ZeroMemory(priorUnsigned);
            if (expectedJournalHash is not null)
                CryptographicOperations.ZeroMemory(expectedJournalHash);
            CryptographicOperations.ZeroMemory(gfl);
            CryptographicOperations.ZeroMemory(latchedJournal);
        }
    }

    internal static async ValueTask LatchForkAsync(
        GenesisIdentityContext identity,
        GenesisAuthorJournalSnapshot journal,
        VerifiedGenesisReplayHeadSnapshot snapshot,
        byte reason,
        GenesisAuthorJournal provider,
        GenesisProtectedKeySetContext keySet,
        GenesisProtectedKeySetRegistry keyRegistry,
        GenesisProtectedKeySetRequest keyRequest,
        GenesisReplayTimePolicy timePolicy,
        ulong started,
        ulong invocationDeadline,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        var journalBytes = journal.CanonicalJournal.ToArray();
        var observed = snapshot.TrustedObservedTuple.ToArray();
        var slots = ExpectedSlots(journalBytes);
        var transcript = new byte[1056];
        GenesisReplayPrimitives.Scope(identity).CopyTo(transcript, 0);
        transcript[122] = reason;
        GenesisReplayPrimitives.JournalHash(journalBytes).CopyTo(transcript, 123);
        journalBytes.AsSpan(807, 8).CopyTo(transcript.AsSpan(155));
        slots.CopyTo(transcript, 163);
        observed.CopyTo(transcript, 537);
        var evidenceHash = GenesisReplayPrimitives.EvidenceHash(transcript);
        var expectedRevision = BinaryPrimitives.ReadUInt64BigEndian(
            journalBytes.AsSpan(807, 8));
        if (expectedRevision == ulong.MaxValue)
            Invalid("A maximum-revision genesis journal cannot be fork-latched.");
        await keySet.RevalidateAsync(keyRegistry, keyRequest,
            identity.ProtectedStateHmacKeyId.ToArray(), cancellationToken)
            .ConfigureAwait(false);
        CheckTime(timePolicy, started, invocationDeadline, cancellationToken);
        var returned = await provider.LatchReplayForkAsync(
            new GenesisReplayForkLatchRequest(journalBytes, transcript, evidenceHash,
                snapshot.EffectiveLeaseExpiryUnixSeconds, invocationDeadline),
            cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (returned is null || !returned.Healthy)
            Invalid("The atomic genesis replay fork latch is absent or unhealthy.");
        var gfl = returned!.CanonicalForkLatch.ToArray();
        var latchedJournal = returned.CanonicalJournal.ToArray();
        try
        {
            GenesisProtectedRecords.PreflightGfl(gfl);
            GenesisProtectedRecords.PreflightGaj(latchedJournal, requireUnlatched: false);
            if (!CanonicalGrammar.FixedEquals(gfl.AsSpan(8, 1056), transcript) ||
                !CanonicalGrammar.FixedEquals(gfl.AsSpan(1064, 32), evidenceHash) ||
                BinaryPrimitives.ReadUInt64BigEndian(gfl.AsSpan(1096, 8)) != expectedRevision + 1 ||
                !CanonicalGrammar.FixedEquals(gfl.AsSpan(1112, 32), journalBytes.AsSpan(816, 32)) ||
                !CanonicalGrammar.FixedEquals(latchedJournal.AsSpan(0, 807), journalBytes.AsSpan(0, 807)) ||
                BinaryPrimitives.ReadUInt64BigEndian(latchedJournal.AsSpan(807, 8)) != expectedRevision + 1 ||
                latchedJournal[815] != 1 ||
                !CanonicalGrammar.FixedEquals(latchedJournal.AsSpan(816, 32),
                    journalBytes.AsSpan(816, 32)))
                Invalid("GFL1 and the fork-latched GAJ1 are not one exact atomic transition.");
            var observedAt = BinaryPrimitives.ReadUInt64BigEndian(gfl.AsSpan(1104, 8));
            var mutationDeadline = snapshot.EffectiveLeaseExpiryUnixSeconds == 0
                ? invocationDeadline
                : Math.Min(snapshot.EffectiveLeaseExpiryUnixSeconds, invocationDeadline);
            if (observedAt == 0 || observedAt >= mutationDeadline)
                Invalid("GFL1 was observed at or after its atomic mutation deadline.");
            await GenesisProtectedRecords.VerifyAsync(
                "Deep/ProtectedState/V1/GFL1", gfl, GenesisProtectedRecords.GflKeyOffset,
                hmacProvider, cancellationToken).ConfigureAwait(false);
            await GenesisProtectedRecords.VerifyAsync(
                "Deep/ProtectedState/V1/GAJ1", latchedJournal,
                GenesisProtectedRecords.GajKeyOffset, hmacProvider, cancellationToken)
                .ConfigureAwait(false);
            await keySet.RevalidateAsync(keyRegistry, keyRequest,
                identity.ProtectedStateHmacKeyId.ToArray(), cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(gfl);
            CryptographicOperations.ZeroMemory(latchedJournal);
            CryptographicOperations.ZeroMemory(journalBytes);
            CryptographicOperations.ZeroMemory(observed);
            CryptographicOperations.ZeroMemory(slots);
            CryptographicOperations.ZeroMemory(transcript);
            CryptographicOperations.ZeroMemory(evidenceHash);
        }
    }

    private static void ValidateRestoredObservedTuple(
        ReadOnlySpan<byte> observed,
        ReadOnlySpan<byte> latchedJournal,
        ReadOnlySpan<byte> expectedJournalHash)
    {
        var currentRevision = BinaryPrimitives.ReadUInt64BigEndian(
            latchedJournal.Slice(807, 8));
        if (observed.Length != 519 || observed[0] > 1 || observed[383] > 1 ||
            observed[454] != latchedJournal[194] ||
            currentRevision == 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(observed.Slice(455, 8)) !=
                currentRevision - 1 ||
            !CanonicalGrammar.FixedEquals(observed.Slice(463, 32), expectedJournalHash) ||
            BinaryPrimitives.ReadUInt64BigEndian(observed.Slice(495, 8)) == 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(observed.Slice(511, 8)) == 0)
            Invalid("The GFL1 observed tuple is not canonical.");
        var sequence = BinaryPrimitives.ReadUInt64BigEndian(observed.Slice(1, 8));
        var lease = BinaryPrimitives.ReadUInt64BigEndian(observed.Slice(503, 8));
        if (observed[0] == 0)
        {
            if (sequence != 0 || !CanonicalGrammar.IsZero(observed.Slice(9, 374)) ||
                lease != 0)
                Invalid("The GFL1 external-zero tuple is not canonical.");
        }
        else
        {
            if (sequence != 1 || lease == 0 ||
                CanonicalGrammar.IsZero(observed.Slice(351, 32)))
                Invalid("The GFL1 external-one tuple is incomplete.");
            for (var index = 0; index < 9; index++)
                if (CanonicalGrammar.IsZero(observed.Slice(9 + index * 38, 38)))
                    Invalid("The GFL1 external-one tuple has an empty candidate slot.");
        }
        if (observed[383] == 0)
        {
            if (!CanonicalGrammar.IsZero(observed.Slice(384, 70)))
                Invalid("The GFL1 local-zero tuple is not canonical.");
        }
        else if (CanonicalGrammar.IsZero(observed.Slice(384, 38)) ||
                 CanonicalGrammar.IsZero(observed.Slice(422, 32)))
            Invalid("The GFL1 local-one tuple is incomplete.");
    }

    internal static byte[] ExpectedSlots(ReadOnlySpan<byte> journal)
    {
        var output = new byte[374];
        journal.Slice(227, 266).CopyTo(output);
        if (journal[194] != 0) journal.Slice(597, 108).CopyTo(output.AsSpan(266));
        return output;
    }

    private static byte[] ObservedTuple(
        GenesisReplayExternalHeadData external,
        GenesisReplayLocalHeadData local,
        ReadOnlySpan<byte> journal,
        ulong effectiveLeaseExpiry)
    {
        var output = new byte[519]; var offset = 0;
        output[offset++] = external.Sequence == 0 ? (byte)0 : (byte)1;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset, 8), external.Sequence); offset += 8;
        if (external.Sequence == 1)
        {
            for (var index = 0; index < 7; index++)
            {
                var type = index switch
                {
                    0 => ArtifactType.Drc1, >= 1 and <= 4 => ArtifactType.Dcp1,
                    5 => ArtifactType.Dcs1, _ => ArtifactType.Dct1
                };
                Reference(type, external.TrustedArtifacts[index].Span).CopyTo(output, offset);
                offset += 38;
            }
            Reference(ArtifactType.Dcq1, external.TrustedArtifacts[7].Span).CopyTo(output, offset);
            offset += 38;
            external.TrustedDplReference.CopyTo(output.AsSpan(offset)); offset += 38;
            external.TrustedSource.CopyTo(output.AsSpan(offset)); offset += 32;
        }
        else offset += 374;
        output[offset++] = local.TrustedDpl.Length == 0 ? (byte)0 : (byte)1;
        local.TrustedDplReference.CopyTo(output.AsSpan(offset)); offset += 38;
        local.TrustedSource.CopyTo(output.AsSpan(offset)); offset += 32;
        output[offset++] = journal[194];
        journal.Slice(807, 8).CopyTo(output.AsSpan(offset)); offset += 8;
        GenesisReplayPrimitives.JournalHash(journal).CopyTo(output, offset); offset += 32;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset, 8), external.SourceRevision); offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(
            output.AsSpan(offset, 8), effectiveLeaseExpiry); offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset, 8), local.SourceRevision); offset += 8;
        if (offset != output.Length) Invalid("The genesis replay observed tuple width drifted.");
        return output;
    }

    private static byte[] Reference(ArtifactType type, ReadOnlySpan<byte> canonical) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, canonical));

    private static void CheckTime(
        GenesisReplayTimePolicy policy,
        ulong started,
        ulong deadline,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var now = policy.GetUnixTimeSeconds();
        if (now < started || now >= deadline)
            throw new OperationCanceledException("The genesis replay deadline expired.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<GenesisReplayDisposition> RestoreGenesisAuthorReplayAsync(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisResetReservationResult reservation,
        GenesisProtectedKeySetContext keySet,
        GenesisProtectedKeySetRegistry keyRegistry,
        GenesisRecoveryProtectorContext protector,
        RecoverySealingProvider sealingProvider,
        GenesisCutoverSourceContext source,
        GenesisArtifactStore artifactStore,
        GenesisQuorumStateProvider quorumProvider,
        GenesisAuthorJournal journalProvider,
        GenesisReplayHeadProvider headProvider,
        GenesisReplayTimePolicy timePolicy,
        RecoveryProtectorProvider recoveryProvider,
        RecoveryNonceLatch nonceLatch,
        IProtectedHmacProvider protectedHmacProvider,
        CancellationToken cancellationToken = default) =>
        await GenesisReplayVerifier.RestoreAsync(
            identity, intent, release, reservation, keySet, keyRegistry, protector,
            sealingProvider, source, artifactStore, quorumProvider, journalProvider,
            headProvider, timePolicy, recoveryProvider, nonceLatch,
            protectedHmacProvider, cancellationToken).ConfigureAwait(false);
}
