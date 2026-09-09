using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.MessagingCrypto;

public enum ExactDpe2DurableDirection : byte
{
    Send = 1,
    Receive = 2,
}

public enum ExactDpe2DurableCommitDisposition : byte
{
    Committed = 1,
    ExactReplay = 2,
    CasConflict = 3,
    ForkLatched = 4,
    RollbackLatched = 5,
}

public enum ExactDpe2ReceiveReplayDisposition : byte
{
    Fresh = 1,
    ExactReplay = 2,
}

public enum ExactDpe2ReceiveSuccessOutcome : byte
{
    Fresh = 1,
    OutOfOrderSkippedKey = 2,
    ExactReplay = 3,
}

/// <summary>
/// Store-owned snapshot used only to bind a protocol-prepared transition to
/// the exact protected predecessor and journal head. It cannot carry a next
/// TRS1 state or authorize a mutation.
/// </summary>
public sealed class ExactDpe2DurableTransitionContext
{
    private readonly byte[] _expectedStateCommitment;
    private readonly byte[] _latestProtectedCommitment;
    private readonly byte[] _journalPredecessor;
    private readonly byte[] _retentionCommitment;

    public ExactDpe2DurableTransitionContext(
        ulong expectedStateGeneration,
        ReadOnlySpan<byte> expectedStateCommitment,
        ulong latestProtectedGeneration,
        ReadOnlySpan<byte> latestProtectedCommitment,
        ulong expectedJournalGeneration,
        ReadOnlySpan<byte> journalPredecessor,
        ReadOnlySpan<byte> retentionCommitment,
        ExactDpe2ReceiveReplayDisposition receiveReplayDisposition =
            ExactDpe2ReceiveReplayDisposition.Fresh)
    {
        MessagingCryptoValidation.NonZeroExact(
            expectedStateCommitment, 32, nameof(expectedStateCommitment));
        MessagingCryptoValidation.NonZeroExact(
            latestProtectedCommitment, 32, nameof(latestProtectedCommitment));
        MessagingCryptoValidation.NonZeroExact(
            journalPredecessor, 32, nameof(journalPredecessor));
        MessagingCryptoValidation.NonZeroExact(
            retentionCommitment, 32, nameof(retentionCommitment));
        if (latestProtectedGeneration < expectedStateGeneration)
            throw new ArgumentOutOfRangeException(
                nameof(latestProtectedGeneration),
                "The protected checkpoint cannot precede the expected TRS1 state.");
        if (!Enum.IsDefined(receiveReplayDisposition))
            throw new ArgumentOutOfRangeException(nameof(receiveReplayDisposition));

        ExpectedStateGeneration = expectedStateGeneration;
        LatestProtectedGeneration = latestProtectedGeneration;
        ExpectedJournalGeneration = expectedJournalGeneration;
        ReceiveReplayDisposition = receiveReplayDisposition;
        _expectedStateCommitment = expectedStateCommitment.ToArray();
        _latestProtectedCommitment = latestProtectedCommitment.ToArray();
        _journalPredecessor = journalPredecessor.ToArray();
        _retentionCommitment = retentionCommitment.ToArray();
    }

    public ulong ExpectedStateGeneration { get; }
    public ulong LatestProtectedGeneration { get; }
    public ulong ExpectedJournalGeneration { get; }
    public ExactDpe2ReceiveReplayDisposition ReceiveReplayDisposition { get; }
    public ReadOnlyMemory<byte> ExpectedStateCommitment => _expectedStateCommitment.ToArray();
    public ReadOnlyMemory<byte> LatestProtectedCommitment => _latestProtectedCommitment.ToArray();
    public ReadOnlyMemory<byte> JournalPredecessor => _journalPredecessor.ToArray();
    public ReadOnlyMemory<byte> RetentionCommitment => _retentionCommitment.ToArray();

    internal ReadOnlySpan<byte> ExpectedStateCommitmentSpan => _expectedStateCommitment;
    internal ReadOnlySpan<byte> LatestProtectedCommitmentSpan => _latestProtectedCommitment;
    internal ReadOnlySpan<byte> JournalPredecessorSpan => _journalPredecessor;
    internal ReadOnlySpan<byte> RetentionCommitmentSpan => _retentionCommitment;
}

/// <summary>
/// Protocol-owned, immutable input to the durable store. The constructor is
/// intentionally not public: callers can persist or reject this exact plan,
/// but cannot substitute a next TRS1 state or deletion/replay/PQ evidence.
/// The authority must not retain the object after its callback completes.
/// </summary>
public sealed class ExactDpe2DurablePersistencePlan : IDisposable
{
    private readonly object _gate = new();
    private byte[]? _operationId;
    private byte[]? _replayToken;
    private byte[]? _exactHeaderHash;
    private byte[]? _exactEnvelopeHash;
    private byte[]? _exactEnvelope;
    private byte[]? _journalPredecessor;
    private byte[]? _priorTrs1;
    private byte[]? _nextTrs1;
    private byte[]? _priorStateCommitment;
    private byte[]? _nextStateCommitment;
    private byte[]? _checkpointPriorCommitment;
    private byte[]? _deletionManifestCommitment;
    private byte[]? _messageKeyDeletionEvidence;
    private byte[]? _replayEvidenceCommitment;
    private byte[]? _deduplicationMutationCommitment;
    private byte[]? _pqFenceMutationCommitment;
    private byte[]? _terminalStateCommitment;

    internal ExactDpe2DurablePersistencePlan(
        ExactDpe2DurableDirection direction,
        ulong priorStateGeneration,
        ulong nextStateGeneration,
        ulong checkpointPriorGeneration,
        ulong expectedJournalGeneration,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactHeaderHash,
        ReadOnlySpan<byte> exactEnvelopeHash,
        ReadOnlySpan<byte> exactEnvelope,
        ReadOnlySpan<byte> journalPredecessor,
        ReadOnlySpan<byte> priorTrs1,
        ReadOnlySpan<byte> nextTrs1,
        ReadOnlySpan<byte> priorStateCommitment,
        ReadOnlySpan<byte> nextStateCommitment,
        ReadOnlySpan<byte> checkpointPriorCommitment,
        ReadOnlySpan<byte> deletionManifestCommitment,
        ReadOnlySpan<byte> messageKeyDeletionEvidence,
        ReadOnlySpan<byte> replayEvidenceCommitment,
        ReadOnlySpan<byte> deduplicationMutationCommitment,
        ReadOnlySpan<byte> pqFenceMutationCommitment,
        ReadOnlySpan<byte> terminalStateCommitment,
        bool messageKeyDeletedAfterAuthenticatedEnvelopeOperation,
        bool hasStateMutation)
    {
        if (!Enum.IsDefined(direction)) throw new ArgumentOutOfRangeException(nameof(direction));
        NonZero32(operationId, nameof(operationId));
        NonZero32(exactHeaderHash, nameof(exactHeaderHash));
        NonZero32(exactEnvelopeHash, nameof(exactEnvelopeHash));
        NonZero32(journalPredecessor, nameof(journalPredecessor));
        NonZero32(priorStateCommitment, nameof(priorStateCommitment));
        NonZero32(checkpointPriorCommitment, nameof(checkpointPriorCommitment));
        NonZero32(deletionManifestCommitment, nameof(deletionManifestCommitment));
        NonZero32(replayEvidenceCommitment, nameof(replayEvidenceCommitment));
        ValidateBoundedTrs1(priorTrs1, nameof(priorTrs1));
        if (exactEnvelope.Length is < 4_513 or > 50_705)
            throw new ArgumentOutOfRangeException(nameof(exactEnvelope));

        if (hasStateMutation)
        {
            if (nextStateGeneration != checked(priorStateGeneration + 1))
                throw new ArgumentOutOfRangeException(nameof(nextStateGeneration));
            ValidateBoundedTrs1(nextTrs1, nameof(nextTrs1));
            NonZero32(nextStateCommitment, nameof(nextStateCommitment));
            NonZero32(messageKeyDeletionEvidence, nameof(messageKeyDeletionEvidence));
            if (!messageKeyDeletedAfterAuthenticatedEnvelopeOperation)
                throw new ArgumentException(
                    "A fresh DPE2 transition must prove message-key deletion.",
                    nameof(messageKeyDeletedAfterAuthenticatedEnvelopeOperation));
        }
        else if (!nextTrs1.IsEmpty || !nextStateCommitment.IsEmpty ||
                 !messageKeyDeletionEvidence.IsEmpty || nextStateGeneration != priorStateGeneration)
        {
            throw new ArgumentException("An exact replay cannot carry a state mutation.");
        }
        ValidateOptional32(deduplicationMutationCommitment, nameof(deduplicationMutationCommitment));
        ValidateOptional32(pqFenceMutationCommitment, nameof(pqFenceMutationCommitment));
        ValidateOptional32(terminalStateCommitment, nameof(terminalStateCommitment));

        Direction = direction;
        PriorStateGeneration = priorStateGeneration;
        NextStateGeneration = nextStateGeneration;
        CheckpointPriorGeneration = checkpointPriorGeneration;
        ExpectedJournalGeneration = expectedJournalGeneration;
        HasStateMutation = hasStateMutation;
        MessageKeyDeletedAfterAuthenticatedEnvelopeOperation =
            messageKeyDeletedAfterAuthenticatedEnvelopeOperation;
        _operationId = operationId.ToArray();
        _replayToken = exactEnvelopeHash.ToArray();
        _exactHeaderHash = exactHeaderHash.ToArray();
        _exactEnvelopeHash = exactEnvelopeHash.ToArray();
        _exactEnvelope = exactEnvelope.ToArray();
        _journalPredecessor = journalPredecessor.ToArray();
        _priorTrs1 = priorTrs1.ToArray();
        _nextTrs1 = nextTrs1.ToArray();
        _priorStateCommitment = priorStateCommitment.ToArray();
        _nextStateCommitment = nextStateCommitment.ToArray();
        _checkpointPriorCommitment = checkpointPriorCommitment.ToArray();
        _deletionManifestCommitment = deletionManifestCommitment.ToArray();
        _messageKeyDeletionEvidence = messageKeyDeletionEvidence.ToArray();
        _replayEvidenceCommitment = replayEvidenceCommitment.ToArray();
        _deduplicationMutationCommitment = deduplicationMutationCommitment.ToArray();
        _pqFenceMutationCommitment = pqFenceMutationCommitment.ToArray();
        _terminalStateCommitment = terminalStateCommitment.ToArray();
    }

    public ExactDpe2DurableDirection Direction { get; }
    public ulong PriorStateGeneration { get; }
    public ulong NextStateGeneration { get; }
    public ulong CheckpointPriorGeneration { get; }
    public ulong ExpectedJournalGeneration { get; }
    public bool HasStateMutation { get; }
    public bool MessageKeyDeletedAfterAuthenticatedEnvelopeOperation { get; }
    public ReadOnlyMemory<byte> OperationId => Copy(_operationId);
    public ReadOnlyMemory<byte> ReplayToken => Copy(_replayToken);
    public ReadOnlyMemory<byte> ExactHeaderHash => Copy(_exactHeaderHash);
    public ReadOnlyMemory<byte> ExactEnvelopeHash => Copy(_exactEnvelopeHash);
    public ReadOnlyMemory<byte> ExactEnvelope => Copy(_exactEnvelope);
    public ReadOnlyMemory<byte> JournalPredecessor => Copy(_journalPredecessor);
    public ReadOnlyMemory<byte> PriorTrs1 => Copy(_priorTrs1);
    public ReadOnlyMemory<byte> NextTrs1 => Copy(_nextTrs1);
    public ReadOnlyMemory<byte> PriorStateCommitment => Copy(_priorStateCommitment);
    public ReadOnlyMemory<byte> NextStateCommitment => Copy(_nextStateCommitment);
    public ReadOnlyMemory<byte> CheckpointPriorCommitment => Copy(_checkpointPriorCommitment);
    public ReadOnlyMemory<byte> DeletionManifestCommitment => Copy(_deletionManifestCommitment);
    public ReadOnlyMemory<byte> MessageKeyDeletionEvidence => Copy(_messageKeyDeletionEvidence);
    public ReadOnlyMemory<byte> ReplayEvidenceCommitment => Copy(_replayEvidenceCommitment);
    public ReadOnlyMemory<byte> DeduplicationMutationCommitment => Copy(_deduplicationMutationCommitment);
    public ReadOnlyMemory<byte> PqFenceMutationCommitment => Copy(_pqFenceMutationCommitment);
    public ReadOnlyMemory<byte> TerminalStateCommitment => Copy(_terminalStateCommitment);

    public void Dispose()
    {
        lock (_gate)
        {
            Zero(ref _operationId); Zero(ref _replayToken); Zero(ref _exactHeaderHash);
            Zero(ref _exactEnvelopeHash); Zero(ref _exactEnvelope); Zero(ref _journalPredecessor);
            Zero(ref _priorTrs1); Zero(ref _nextTrs1); Zero(ref _priorStateCommitment);
            Zero(ref _nextStateCommitment); Zero(ref _checkpointPriorCommitment);
            Zero(ref _deletionManifestCommitment);
            Zero(ref _messageKeyDeletionEvidence); Zero(ref _replayEvidenceCommitment);
            Zero(ref _deduplicationMutationCommitment); Zero(ref _pqFenceMutationCommitment);
            Zero(ref _terminalStateCommitment);
        }
    }

    private ReadOnlyMemory<byte> Copy(byte[]? value)
    {
        lock (_gate)
            return (value ?? throw new ObjectDisposedException(nameof(ExactDpe2DurablePersistencePlan)))
                .ToArray();
    }

    private static void NonZero32(ReadOnlySpan<byte> value, string name) =>
        MessagingCryptoValidation.NonZeroExact(value, 32, name);

    private static void ValidateOptional32(ReadOnlySpan<byte> value, string name)
    {
        if (!value.IsEmpty) NonZero32(value, name);
    }

    private static void ValidateBoundedTrs1(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length is < 600 or > MessagingCryptoConstants.MaximumDurableRatchetStateBytes)
            throw new ArgumentOutOfRangeException(name, "TRS1 is outside the closed 2 MiB bound.");
    }

    private static void Zero(ref byte[]? value)
    {
        var owned = Interlocked.Exchange(ref value, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }
}

/// <summary>
/// Trusted durable boundary. Returning Committed or ExactReplay is an
/// assertion that this exact protocol-created plan was atomically committed,
/// or was found byte-identical in the durable journal. Conflicts and latches
/// must be returned explicitly. Throwing keeps the prepared object retryable.
/// </summary>
public interface IExactDpe2DurableTransactionAuthority
{
    ValueTask<ExactDpe2DurableCommitReceipt> CommitAsync(
        ExactDpe2DurablePersistencePlan plan,
        ExactDpe2DurableCommitCompletion completion,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Attempt-scoped receipt factory passed only with the exact immutable plan.
/// A trusted authority calls Complete after its atomic journal transaction has
/// committed (or after it has found the same exact journal row). Receipts from
/// another plan or callback attempt are rejected by object-capability binding.
/// </summary>
public sealed class ExactDpe2DurableCommitCompletion
{
    private readonly ExactDpe2DurablePersistencePlan _plan;
    private readonly object _attempt = new();
    private int _consumed;

    internal ExactDpe2DurableCommitCompletion(ExactDpe2DurablePersistencePlan plan) =>
        _plan = plan ?? throw new ArgumentNullException(nameof(plan));

    public ExactDpe2DurableCommitReceipt Complete(ExactDpe2DurableCommitDisposition disposition)
    {
        if (!Enum.IsDefined(disposition)) throw new ArgumentOutOfRangeException(nameof(disposition));
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new InvalidOperationException("The durable completion is single-use.");
        return new ExactDpe2DurableCommitReceipt(_plan, _attempt, disposition);
    }

    internal object Attempt => _attempt;
}

public sealed class ExactDpe2DurableCommitReceipt
{
    private readonly ExactDpe2DurablePersistencePlan _plan;
    private readonly object _attempt;
    private int _consumed;

    internal ExactDpe2DurableCommitReceipt(
        ExactDpe2DurablePersistencePlan plan,
        object attempt,
        ExactDpe2DurableCommitDisposition disposition)
    {
        _plan = plan;
        _attempt = attempt;
        Disposition = disposition;
    }

    public ExactDpe2DurableCommitDisposition Disposition { get; }

    internal ExactDpe2DurableCommitDisposition ConsumeAndVerify(
        ExactDpe2DurablePersistencePlan expectedPlan,
        ExactDpe2DurableCommitCompletion expectedCompletion)
    {
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new CryptographicException("The durable commit receipt is single-use.");
        if (!ReferenceEquals(_plan, expectedPlan) ||
            !ReferenceEquals(_attempt, expectedCompletion.Attempt))
            throw new CryptographicException(
                "The durable commit receipt belongs to another exact plan or callback attempt.");
        return Disposition;
    }
}

public sealed class ExactDpe2SendSuccessCapability : IDisposable
{
    private byte[]? _exactEnvelope;
    private byte[]? _operationId;
    private byte[]? _exactEnvelopeHash;

    internal ExactDpe2SendSuccessCapability(
        byte[] exactEnvelope,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactEnvelopeHash)
    {
        _exactEnvelope = exactEnvelope;
        _operationId = operationId.ToArray();
        _exactEnvelopeHash = exactEnvelopeHash.ToArray();
    }

    public ReadOnlyMemory<byte> OperationId => Copy(_operationId);
    public ReadOnlyMemory<byte> ExactEnvelopeHash => Copy(_exactEnvelopeHash);

    public byte[] TakeExactEnvelope() =>
        Interlocked.Exchange(ref _exactEnvelope, null) ??
        throw new InvalidOperationException("The exact DPE2 envelope was already consumed.");

    public void Dispose()
    {
        Zero(ref _exactEnvelope); Zero(ref _operationId); Zero(ref _exactEnvelopeHash);
    }

    private static ReadOnlyMemory<byte> Copy(byte[]? value) =>
        (value ?? throw new ObjectDisposedException(nameof(ExactDpe2SendSuccessCapability))).ToArray();

    private static void Zero(ref byte[]? value)
    {
        var owned = Interlocked.Exchange(ref value, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }
}

public sealed class ExactDpe2ReceiveSuccessCapability : IDisposable
{
    private byte[]? _exactDmc2;
    private byte[]? _operationId;
    private byte[]? _exactEnvelopeHash;

    internal ExactDpe2ReceiveSuccessCapability(
        ExactDpe2ReceiveSuccessOutcome outcome,
        byte[]? exactDmc2,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactEnvelopeHash)
    {
        Outcome = outcome;
        _exactDmc2 = exactDmc2;
        _operationId = operationId.ToArray();
        _exactEnvelopeHash = exactEnvelopeHash.ToArray();
    }

    public ExactDpe2ReceiveSuccessOutcome Outcome { get; }
    public bool HasAuthenticatedDmc2 => Volatile.Read(ref _exactDmc2) is not null;
    public ReadOnlyMemory<byte> OperationId => Copy(_operationId);
    public ReadOnlyMemory<byte> ExactEnvelopeHash => Copy(_exactEnvelopeHash);

    public byte[] TakeAuthenticatedDmc2() =>
        Interlocked.Exchange(ref _exactDmc2, null) ??
        throw new InvalidOperationException("No committed authenticated DMC2 is available.");

    public void Dispose()
    {
        Zero(ref _exactDmc2); Zero(ref _operationId); Zero(ref _exactEnvelopeHash);
    }

    private static ReadOnlyMemory<byte> Copy(byte[]? value) =>
        (value ?? throw new ObjectDisposedException(nameof(ExactDpe2ReceiveSuccessCapability))).ToArray();

    private static void Zero(ref byte[]? value)
    {
        var owned = Interlocked.Exchange(ref value, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }
}

public sealed class ExactDpe2PreparedSend : IDisposable
{
    private readonly object _gate = new();
    private ExactDpe2SendTransitionPlan? _transition;
    private ExactDpe2DurablePersistencePlan? _persistence;
    private bool _inFlight;
    private bool _disposeRequested;

    internal ExactDpe2PreparedSend(
        ExactDpe2SendTransitionPlan transition,
        ExactDpe2DurablePersistencePlan persistence)
    {
        _transition = transition;
        _persistence = persistence;
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal ExactDpe2DurablePersistencePlan PersistencePlanForTests
    {
        get { lock (_gate) return _persistence ?? throw Unavailable(); }
    }
#endif

    public async ValueTask<ExactDpe2SendSuccessCapability> CommitAsync(
        IExactDpe2DurableTransactionAuthority authority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ExactDpe2SendTransitionPlan transition;
        ExactDpe2DurablePersistencePlan persistence;
        lock (_gate)
        {
            if (_inFlight) throw new InvalidOperationException("A durable commit callback is already in flight.");
            transition = _transition ?? throw Unavailable();
            persistence = _persistence ?? throw Unavailable();
            _inFlight = true;
        }

        try
        {
            var completion = new ExactDpe2DurableCommitCompletion(persistence);
            var receipt = await authority.CommitAsync(
                persistence, completion, cancellationToken).ConfigureAwait(false);
            var disposition = (receipt ?? throw new CryptographicException(
                    "The durable authority returned no commit receipt."))
                .ConsumeAndVerify(persistence, completion);
            if (disposition is not (ExactDpe2DurableCommitDisposition.Committed or
                                    ExactDpe2DurableCommitDisposition.ExactReplay))
            {
                Abort();
                throw TerminalDisposition(disposition);
            }

            var ratchetSuccess = ExactDpe2DurableReceiptFactory.Create(transition);
            var sendSuccess = DurableExactDpe2SendSuccessCapability.CreateFromProductionAuthority(
                ratchetSuccess,
                transition.OperationId.Span,
                transition.ExactEnvelopeHash.Span);
            using var commit = transition.Commit(sendSuccess);
            using var next = commit.TakeNextState();
            var envelope = commit.TakeExactEnvelope();
            ExactDpe2SendSuccessCapability? result = null;
            try
            {
                result = new ExactDpe2SendSuccessCapability(
                    envelope,
                    transition.OperationId.Span,
                    transition.ExactEnvelopeHash.Span);
                envelope = null!;
                Complete();
                return result;
            }
            catch
            {
                result?.Dispose();
                throw;
            }
            finally
            {
                if (envelope is not null) CryptographicOperations.ZeroMemory(envelope);
            }
        }
        catch
        {
            EndAttempt();
            throw;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposeRequested = true;
            if (!_inFlight) DisposeOwned();
        }
    }

    private void Complete()
    {
        lock (_gate)
        {
            _inFlight = false;
            DisposeOwned();
        }
    }

    private void EndAttempt()
    {
        lock (_gate)
        {
            _inFlight = false;
            if (_disposeRequested) DisposeOwned();
        }
    }

    private void Abort()
    {
        lock (_gate)
        {
            _inFlight = false;
            _disposeRequested = true;
            DisposeOwned();
        }
    }

    private void DisposeOwned()
    {
        Interlocked.Exchange(ref _transition, null)?.Dispose();
        Interlocked.Exchange(ref _persistence, null)?.Dispose();
    }

    private static InvalidOperationException Unavailable() =>
        new("The prepared exact DPE2 send transition is unavailable.");

    private static CryptographicException TerminalDisposition(ExactDpe2DurableCommitDisposition disposition) =>
        new($"The durable authority rejected the exact DPE2 send transition: {disposition}.");
}

public sealed class ExactDpe2PreparedReceive : IDisposable
{
    private readonly object _gate = new();
    private ExactDpe2ReceiveTransitionPlan? _transition;
    private ExactDpe2DurablePersistencePlan? _persistence;
    private bool _inFlight;
    private bool _disposeRequested;

    internal ExactDpe2PreparedReceive(
        ExactDpe2ReceiveTransitionPlan transition,
        ExactDpe2DurablePersistencePlan persistence)
    {
        _transition = transition;
        _persistence = persistence;
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal ExactDpe2DurablePersistencePlan PersistencePlanForTests
    {
        get { lock (_gate) return _persistence ?? throw Unavailable(); }
    }
#endif

    public async ValueTask<ExactDpe2ReceiveSuccessCapability> CommitAsync(
        IExactDpe2DurableTransactionAuthority authority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ExactDpe2ReceiveTransitionPlan transition;
        ExactDpe2DurablePersistencePlan persistence;
        lock (_gate)
        {
            if (_inFlight) throw new InvalidOperationException("A durable commit callback is already in flight.");
            transition = _transition ?? throw Unavailable();
            persistence = _persistence ?? throw Unavailable();
            _inFlight = true;
        }

        try
        {
            var completion = new ExactDpe2DurableCommitCompletion(persistence);
            var receipt = await authority.CommitAsync(
                persistence, completion, cancellationToken).ConfigureAwait(false);
            var disposition = (receipt ?? throw new CryptographicException(
                    "The durable authority returned no commit receipt."))
                .ConsumeAndVerify(persistence, completion);
            if (transition.Outcome == RatchetPlanOutcome.ExactReplay)
            {
                if (disposition != ExactDpe2DurableCommitDisposition.ExactReplay)
                {
                    Abort();
                    throw TerminalDisposition(disposition);
                }
                using var replay = transition.ConsumeExactReplay();
                var result = new ExactDpe2ReceiveSuccessCapability(
                    ExactDpe2ReceiveSuccessOutcome.ExactReplay,
                    null,
                    transition.OperationId.Span,
                    transition.ExactEnvelopeHash.Span);
                Complete();
                return result;
            }

            if (disposition is not (ExactDpe2DurableCommitDisposition.Committed or
                                    ExactDpe2DurableCommitDisposition.ExactReplay))
            {
                Abort();
                throw TerminalDisposition(disposition);
            }
            var ratchetSuccess = ExactDpe2DurableReceiptFactory.Create(transition);
            using var commit = transition.Commit(ratchetSuccess);
            using var next = commit.TakeNextState();
            var exactDmc2 = commit.TakeAuthenticatedDmc2();
            ExactDpe2ReceiveSuccessCapability? resultCapability = null;
            try
            {
                resultCapability = new ExactDpe2ReceiveSuccessCapability(
                    commit.Outcome == RatchetPlanOutcome.OutOfOrderSkippedKey
                        ? ExactDpe2ReceiveSuccessOutcome.OutOfOrderSkippedKey
                        : ExactDpe2ReceiveSuccessOutcome.Fresh,
                    exactDmc2,
                    transition.OperationId.Span,
                    transition.ExactEnvelopeHash.Span);
                exactDmc2 = null!;
                Complete();
                return resultCapability;
            }
            catch
            {
                resultCapability?.Dispose();
                throw;
            }
            finally
            {
                if (exactDmc2 is not null) CryptographicOperations.ZeroMemory(exactDmc2);
            }
        }
        catch
        {
            EndAttempt();
            throw;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposeRequested = true;
            if (!_inFlight) DisposeOwned();
        }
    }

    private void Complete()
    {
        lock (_gate)
        {
            _inFlight = false;
            DisposeOwned();
        }
    }

    private void EndAttempt()
    {
        lock (_gate)
        {
            _inFlight = false;
            if (_disposeRequested) DisposeOwned();
        }
    }

    private void Abort()
    {
        lock (_gate)
        {
            _inFlight = false;
            _disposeRequested = true;
            DisposeOwned();
        }
    }

    private void DisposeOwned()
    {
        Interlocked.Exchange(ref _transition, null)?.Dispose();
        Interlocked.Exchange(ref _persistence, null)?.Dispose();
    }

    private static InvalidOperationException Unavailable() =>
        new("The prepared exact DPE2 receive transition is unavailable.");

    private static CryptographicException TerminalDisposition(ExactDpe2DurableCommitDisposition disposition) =>
        new($"The durable authority rejected the exact DPE2 receive transition: {disposition}.");
}

/// <summary>
/// Production facade connecting canonical DPE2 transitions to caller-owned
/// durable storage without exposing ratchet state mutation APIs.
/// </summary>
public static class ExactDpe2DurableTransactionProducer
{
    public static ExactDpe2PreparedSend PrepareSend(
        ReadOnlySpan<byte> exactPriorTrs1,
        ExactDpe2DurableTransitionContext context,
        ReadOnlySpan<byte> exactDmc2,
        ReadOnlySpan<byte> expectedNetworkId,
        ReadOnlySpan<byte> operationId)
    {
        ArgumentNullException.ThrowIfNull(context);
        _ = ExactDpe2Padding.SelectSmallestBucket(exactDmc2.Length);
        using var state = TripleRatchetDurableStateCodec.Decode(exactPriorTrs1);
        using var provider = ManagedTripleRatchetComponentProvider.CreateApproved(
            DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess());
        return PrepareSendCore(
            exactPriorTrs1, state, provider, context, exactDmc2, expectedNetworkId, operationId);
    }

    public static ExactDpe2PreparedReceive PrepareReceive(
        ReadOnlySpan<byte> exactPriorTrs1,
        ExactDpe2DurableTransitionContext context,
        ReadOnlySpan<byte> exactDpe2)
    {
        ArgumentNullException.ThrowIfNull(context);
        var decoded = Dpe2Codec.Decode(exactDpe2);
        if (!Dpe2Codec.Encode(decoded).AsSpan().SequenceEqual(exactDpe2))
            throw new CryptographicException("The DPE2 input is not canonical.");
        using var state = TripleRatchetDurableStateCodec.Decode(exactPriorTrs1);
        using var provider = ManagedTripleRatchetComponentProvider.CreateApproved(
            DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess());
        return PrepareReceiveCore(exactPriorTrs1, state, provider, context, exactDpe2);
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static ExactDpe2PreparedSend PrepareSendForTests(
        ReadOnlySpan<byte> exactPriorTrs1,
        TripleRatchetState state,
        ITripleRatchetComponentProvider provider,
        ExactDpe2DurableTransitionContext context,
        ReadOnlySpan<byte> exactDmc2,
        ReadOnlySpan<byte> expectedNetworkId,
        ReadOnlySpan<byte> operationId) =>
        PrepareSendCore(
            exactPriorTrs1, state, provider, context, exactDmc2, expectedNetworkId, operationId);

    internal static ExactDpe2PreparedReceive PrepareReceiveForTests(
        ReadOnlySpan<byte> exactPriorTrs1,
        TripleRatchetState state,
        ITripleRatchetComponentProvider provider,
        ExactDpe2DurableTransitionContext context,
        ReadOnlySpan<byte> exactDpe2) =>
        PrepareReceiveCore(exactPriorTrs1, state, provider, context, exactDpe2);
#endif

    private static ExactDpe2PreparedSend PrepareSendCore(
        ReadOnlySpan<byte> exactPriorTrs1,
        TripleRatchetState state,
        ITripleRatchetComponentProvider provider,
        ExactDpe2DurableTransitionContext context,
        ReadOnlySpan<byte> exactDmc2,
        ReadOnlySpan<byte> expectedNetworkId,
        ReadOnlySpan<byte> operationId)
    {
        _ = ExactDpe2Padding.SelectSmallestBucket(exactDmc2.Length);
        ValidatePriorState(exactPriorTrs1, state, context);
        var lease = CreateLease(context);
        ExactDpe2SendTransitionPlan? transition = null;
        ExactDpe2DurablePersistencePlan? persistence = null;
        byte[]? nextTrs1 = null;
        byte[]? exactEnvelope = null;
        try
        {
            transition = ExactDpe2SendTransitionPlan.Prepare(
                exactDmc2,
                expectedNetworkId,
                state,
                provider,
                lease,
                operationId,
                context.JournalPredecessorSpan);
            RequireFreshDeletionEvidence(transition.MessageKeyDeletedAfterEnvelopeCrypto,
                transition.DeletionObligations);
            nextTrs1 = transition.ExportProposedDurableState();
            exactEnvelope = transition.CopyExactEnvelopeForPersistence();
            persistence = CreatePersistencePlan(
                ExactDpe2DurableDirection.Send,
                state.StorageGeneration,
                context,
                transition.OperationId.Span,
                transition.ExactHeaderHash.Span,
                transition.ExactEnvelopeHash.Span,
                exactEnvelope,
                exactPriorTrs1,
                nextTrs1,
                transition.DatabaseCas.PredecessorCommitment.Span,
                transition.ProposedStateCommitment.Span,
                transition.DeletionManifestCommitment.Span,
                transition.ExactEnvelopeHash.Span,
                [],
                transition.PqFenceMutationCommitment.Span,
                transition.TerminalStateCommitment.Span,
                messageKeyDeleted: true,
                hasStateMutation: true);
            var prepared = new ExactDpe2PreparedSend(transition, persistence);
            transition = null;
            persistence = null;
            return prepared;
        }
        finally
        {
            transition?.Dispose();
            persistence?.Dispose();
            if (nextTrs1 is not null) CryptographicOperations.ZeroMemory(nextTrs1);
            if (exactEnvelope is not null) CryptographicOperations.ZeroMemory(exactEnvelope);
        }
    }

    private static ExactDpe2PreparedReceive PrepareReceiveCore(
        ReadOnlySpan<byte> exactPriorTrs1,
        TripleRatchetState state,
        ITripleRatchetComponentProvider provider,
        ExactDpe2DurableTransitionContext context,
        ReadOnlySpan<byte> exactDpe2)
    {
        ValidatePriorState(exactPriorTrs1, state, context);
        var lease = CreateLease(context);
        ExactDpe2ReceiveTransitionPlan? transition = null;
        ExactDpe2DurablePersistencePlan? persistence = null;
        byte[]? nextTrs1 = null;
        byte[]? exactEnvelope = null;
        try
        {
            transition = ExactDpe2ReceiveTransitionPlan.Prepare(
                exactDpe2,
                state,
                provider,
                lease,
                context.ReceiveReplayDisposition == ExactDpe2ReceiveReplayDisposition.ExactReplay
                    ? RatchetDeduplicationOutcome.ExactReplay
                    : RatchetDeduplicationOutcome.Fresh,
                context.ExpectedJournalGeneration,
                context.JournalPredecessorSpan,
                context.RetentionCommitmentSpan);
            exactEnvelope = transition.CopyExactEnvelopeForPersistence();
            var hasMutation = transition.Outcome != RatchetPlanOutcome.ExactReplay;
            if (hasMutation)
            {
                RequireFreshDeletionEvidence(transition.MessageKeyDeletedAfterEnvelopeCrypto,
                    transition.DeletionObligations);
                nextTrs1 = transition.ExportProposedDurableState();
            }

            persistence = CreatePersistencePlan(
                ExactDpe2DurableDirection.Receive,
                state.StorageGeneration,
                context,
                transition.OperationId.Span,
                transition.ExactHeaderHash.Span,
                transition.ExactEnvelopeHash.Span,
                exactEnvelope,
                exactPriorTrs1,
                nextTrs1 ?? [],
                transition.DatabaseCas.PredecessorCommitment.Span,
                transition.ProposedStateCommitment.Span,
                transition.DeletionManifestCommitment.Span,
                transition.ExactEnvelopeHash.Span,
                transition.DeduplicationMutationCommitment.Span,
                transition.PqFenceMutationCommitment.Span,
                transition.TerminalStateCommitment.Span,
                messageKeyDeleted: hasMutation,
                hasStateMutation: hasMutation);
            var prepared = new ExactDpe2PreparedReceive(transition, persistence);
            transition = null;
            persistence = null;
            return prepared;
        }
        finally
        {
            transition?.Dispose();
            persistence?.Dispose();
            if (nextTrs1 is not null) CryptographicOperations.ZeroMemory(nextTrs1);
            if (exactEnvelope is not null) CryptographicOperations.ZeroMemory(exactEnvelope);
        }
    }

    private static RatchetPersistenceLease CreateLease(ExactDpe2DurableTransitionContext context) =>
        RatchetPersistenceLease.CreateForProductionAuthority(
            context.ExpectedStateGeneration,
            context.ExpectedStateCommitmentSpan,
            context.LatestProtectedGeneration,
            context.LatestProtectedCommitmentSpan);

    private static ExactDpe2DurablePersistencePlan CreatePersistencePlan(
        ExactDpe2DurableDirection direction,
        ulong priorGeneration,
        ExactDpe2DurableTransitionContext context,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactHeaderHash,
        ReadOnlySpan<byte> exactEnvelopeHash,
        ReadOnlySpan<byte> exactEnvelope,
        ReadOnlySpan<byte> priorTrs1,
        ReadOnlySpan<byte> nextTrs1,
        ReadOnlySpan<byte> priorCommitment,
        ReadOnlySpan<byte> nextCommitment,
        ReadOnlySpan<byte> deletionManifest,
        ReadOnlySpan<byte> replayEvidence,
        ReadOnlySpan<byte> deduplicationMutation,
        ReadOnlySpan<byte> pqFenceMutation,
        ReadOnlySpan<byte> terminalCommitment,
        bool messageKeyDeleted,
        bool hasStateMutation) =>
        new(
            direction,
            priorGeneration,
            hasStateMutation ? checked(priorGeneration + 1) : priorGeneration,
            context.LatestProtectedGeneration,
            context.ExpectedJournalGeneration,
            operationId,
            exactHeaderHash,
            exactEnvelopeHash,
            exactEnvelope,
            context.JournalPredecessorSpan,
            priorTrs1,
            nextTrs1,
            priorCommitment,
            nextCommitment,
            context.LatestProtectedCommitmentSpan,
            deletionManifest,
            messageKeyDeleted ? deletionManifest : [],
            replayEvidence,
            deduplicationMutation,
            pqFenceMutation,
            terminalCommitment,
            messageKeyDeleted,
            hasStateMutation);

    private static void ValidatePriorState(
        ReadOnlySpan<byte> exactPriorTrs1,
        TripleRatchetState state,
        ExactDpe2DurableTransitionContext context)
    {
        if (exactPriorTrs1.Length is < 600 or > MessagingCryptoConstants.MaximumDurableRatchetStateBytes)
            throw new MessagingCryptoException(
                MessagingCryptoError.StateLimitExceeded,
                "TRS1 is outside the closed 2 MiB persistence bound.");
        if (state.StorageGeneration != context.ExpectedStateGeneration ||
            !MessagingCryptoValidation.FixedEquals(
                state.StateCommitment.Span,
                context.ExpectedStateCommitmentSpan))
            throw new MessagingCryptoException(
                MessagingCryptoError.CasConflict,
                "The supplied TRS1 bytes differ from the durable authority predecessor.");
    }

    private static void RequireFreshDeletionEvidence(
        bool messageKeyDeleted,
        IReadOnlyList<RatchetDeletionKind> deletions)
    {
        if (!messageKeyDeleted || !deletions.Contains(RatchetDeletionKind.MessageKeyAfterUse) ||
            !deletions.Contains(RatchetDeletionKind.PreviousStateAfterCommit))
            throw new MessagingCryptoException(
                MessagingCryptoError.TransitionRejected,
                "The exact DPE2 transition lacks mandatory deletion evidence.");
    }
}

internal static class ExactDpe2DurableReceiptFactory
{
    internal static DurableRatchetTransactionSuccessCapability Create(
        ExactDpe2SendTransitionPlan plan)
    {
        var generation = plan.ProposedGeneration ?? throw MissingGeneration();
        var receipt = ExactRatchetJournalReceipt.CreateForProductionAuthority(
            plan.OperationId.Span,
            plan.JournalPredecessor.Span,
            plan.DatabaseCas,
            plan.CheckpointCas,
            generation,
            plan.ProposedStateCommitment.Span,
            plan.TerminalStateCommitment.Span,
            plan.DeletionManifestCommitment.Span,
            [],
            plan.PqFenceMutationCommitment.Span);
        return DurableRatchetTransactionSuccessCapability.CreateFromProductionAuthority(receipt);
    }

    internal static DurableRatchetTransactionSuccessCapability Create(
        ExactDpe2ReceiveTransitionPlan plan)
    {
        var generation = plan.ProposedGeneration ?? throw MissingGeneration();
        var receipt = ExactRatchetJournalReceipt.CreateForProductionAuthority(
            plan.OperationId.Span,
            plan.JournalPredecessor.Span,
            plan.DatabaseCas,
            plan.CheckpointCas,
            generation,
            plan.ProposedStateCommitment.Span,
            plan.TerminalStateCommitment.Span,
            plan.DeletionManifestCommitment.Span,
            plan.DeduplicationMutationCommitment.Span,
            plan.PqFenceMutationCommitment.Span);
        return DurableRatchetTransactionSuccessCapability.CreateFromProductionAuthority(receipt);
    }

    private static MessagingCryptoException MissingGeneration() => new(
        MessagingCryptoError.TransitionRejected,
        "A fresh exact DPE2 transition has no successor generation.");
}
