using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.MessagingCrypto;

public enum ExactBraidRecoveryDurableDirection : byte { Send = 1, Receive = 2 }

/// <summary>
/// Closed, wipeable persistence input. No message key, DMC2 or data-fence evidence
/// exists for a public Braid control. Copies containing TRS1 belong to the trusted
/// store and must be cleared after its callback.
/// </summary>
public sealed class ExactBraidRecoveryPersistencePlan : IDisposable
{
    private enum Field
    {
        Operation, Control, ControlHash, HeaderHash, PriorTrs, NextTrs,
        PriorCommitment, NextCommitment, CheckpointCommitment, Journal, Retention, Deletion,
    }
    private readonly object gate = new();
    private byte[][]? fields;

    internal ExactBraidRecoveryPersistencePlan(ExactBraidRecoveryDurableDirection direction,
        TripleRatchetState prior, TripleRatchetState? next,
        ExactDpe2DurableTransitionContext context, ReadOnlySpan<byte> priorTrs,
        ReadOnlySpan<byte> nextTrs, UnverifiedDbr2Record control)
    {
        Direction = direction;
        PriorStateGeneration = prior.StorageGeneration;
        NextStateGeneration = next?.StorageGeneration ?? prior.StorageGeneration;
        CheckpointPriorGeneration = context.LatestProtectedGeneration;
        ExpectedJournalGeneration = context.ExpectedJournalGeneration;
        HasStateMutation = next is not null;
        var projection = Dbr2Codec.GetAuthenticationInput(control);
        byte[] deletion = [];
        try
        {
            if (next is not null)
            {
                Span<byte> manifest = stackalloc byte[5];
                BinaryPrimitives.WriteUInt32BigEndian(manifest, 1);
                manifest[4] = checked((byte)RatchetDeletionKind.PreviousStateAfterCommit);
                deletion = MessagingKdf.Sha256Domain("Deep/Messaging/V2/deletion-manifest", manifest);
            }
            fields = [control.OperationId.ToArray(), control.Exact.ToArray(), SHA256.HashData(control.Exact),
                SHA256.HashData(projection), priorTrs.ToArray(), nextTrs.ToArray(),
                prior.StateCommitment.ToArray(), next?.StateCommitment.ToArray() ?? [],
                context.LatestProtectedCommitmentSpan.ToArray(), context.JournalPredecessorSpan.ToArray(),
                context.RetentionCommitmentSpan.ToArray(), deletion];
            deletion = [];
        }
        finally { CryptographicOperations.ZeroMemory(projection); CryptographicOperations.ZeroMemory(deletion); }
    }

    public ExactBraidRecoveryDurableDirection Direction { get; }
    public ulong PriorStateGeneration { get; }
    public ulong NextStateGeneration { get; }
    public ulong CheckpointPriorGeneration { get; }
    public ulong ExpectedJournalGeneration { get; }
    public bool HasStateMutation { get; }
    public ReadOnlyMemory<byte> OperationId => Copy(Field.Operation);
    public ReadOnlyMemory<byte> ExactControl => Copy(Field.Control);
    public ReadOnlyMemory<byte> ExactControlHash => Copy(Field.ControlHash);
    public ReadOnlyMemory<byte> ExactHeaderHash => Copy(Field.HeaderHash);
    public ReadOnlyMemory<byte> PriorTrs1 => Copy(Field.PriorTrs);
    public ReadOnlyMemory<byte> NextTrs1 => Copy(Field.NextTrs);
    public ReadOnlyMemory<byte> PriorStateCommitment => Copy(Field.PriorCommitment);
    public ReadOnlyMemory<byte> NextStateCommitment => Copy(Field.NextCommitment);
    public ReadOnlyMemory<byte> CheckpointPriorCommitment => Copy(Field.CheckpointCommitment);
    public ReadOnlyMemory<byte> JournalPredecessor => Copy(Field.Journal);
    public ReadOnlyMemory<byte> RetentionCommitment => Copy(Field.Retention);
    public ReadOnlyMemory<byte> DeletionManifestCommitment => Copy(Field.Deletion);

    private byte[] Copy(Field field)
    {
        lock (gate) return (fields ?? throw new ObjectDisposedException(nameof(ExactBraidRecoveryPersistencePlan)))
            [(int)field].ToArray();
    }
    public void Dispose()
    {
        lock (gate)
        {
            if (fields is null) return;
            foreach (var value in fields) CryptographicOperations.ZeroMemory(value);
            fields = null;
        }
    }
}

/// <summary>The trusted owner must commit/reconcile SQL and its independent floor
/// and verify the exact retained row before completing this callback.</summary>
public interface IExactBraidRecoveryDurableTransactionAuthority
{
    ValueTask<ExactBraidRecoveryCommitReceipt> CommitAsync(ExactBraidRecoveryPersistencePlan plan,
        ExactBraidRecoveryCommitCompletion completion, CancellationToken cancellationToken = default);
}

public sealed class ExactBraidRecoveryCommitCompletion
{
    private readonly ExactBraidRecoveryPersistencePlan plan;
    internal object Attempt { get; } = new();
    private int consumed;
    internal ExactBraidRecoveryCommitCompletion(ExactBraidRecoveryPersistencePlan plan) => this.plan = plan;
    public ExactBraidRecoveryCommitReceipt Complete(ExactDpe2DurableCommitDisposition disposition)
    {
        if (!Enum.IsDefined(disposition)) throw new ArgumentOutOfRangeException(nameof(disposition));
        if (Interlocked.CompareExchange(ref consumed, 1, 0) != 0)
            throw new InvalidOperationException("The control durable completion is single-use.");
        return new(plan, Attempt, disposition);
    }
}

public sealed class ExactBraidRecoveryCommitReceipt
{
    private readonly ExactBraidRecoveryPersistencePlan plan;
    private readonly object attempt;
    private int consumed;
    internal ExactBraidRecoveryCommitReceipt(ExactBraidRecoveryPersistencePlan plan, object attempt,
        ExactDpe2DurableCommitDisposition disposition)
    { this.plan = plan; this.attempt = attempt; Disposition = disposition; }
    public ExactDpe2DurableCommitDisposition Disposition { get; }
    internal ExactDpe2DurableCommitDisposition Consume(ExactBraidRecoveryPersistencePlan expected,
        ExactBraidRecoveryCommitCompletion completion)
    {
        if (Interlocked.CompareExchange(ref consumed, 1, 0) != 0 ||
            !ReferenceEquals(plan, expected) || !ReferenceEquals(attempt, completion.Attempt))
            throw new CryptographicException("Control receipt is consumed or belongs to another plan/callback attempt.");
        return Disposition;
    }
}

/// <summary>Local durable success only; no application message or automatic ACK.</summary>
public sealed class ExactBraidRecoverySuccessCapability : IDisposable
{
    private readonly object gate = new();
    private byte[]? operation, hash, control;
    internal ExactBraidRecoverySuccessCapability(ExactBraidRecoveryPersistencePlan plan, bool replay)
    {
        Direction = plan.Direction; IsExactReplay = replay;
        operation = plan.OperationId.ToArray(); hash = plan.ExactControlHash.ToArray();
        if (Direction == ExactBraidRecoveryDurableDirection.Send) control = plan.ExactControl.ToArray();
    }
    public ExactBraidRecoveryDurableDirection Direction { get; }
    public bool IsExactReplay { get; }
    public ReadOnlyMemory<byte> OperationId { get { lock (gate) return Copy(operation); } }
    public ReadOnlyMemory<byte> ExactControlHash { get { lock (gate) return Copy(hash); } }
    public byte[] TakeExactControl()
    {
        lock (gate)
        {
            _ = operation ?? throw new ObjectDisposedException(nameof(ExactBraidRecoverySuccessCapability));
            var result = control ?? throw new InvalidOperationException("No unconsumed committed send control is available.");
            control = null; return result;
        }
    }
    private static byte[] Copy(byte[]? value) =>
        (value ?? throw new ObjectDisposedException(nameof(ExactBraidRecoverySuccessCapability))).ToArray();
    public void Dispose()
    {
        lock (gate)
        {
            if (operation is not null) CryptographicOperations.ZeroMemory(operation);
            if (hash is not null) CryptographicOperations.ZeroMemory(hash);
            if (control is not null) CryptographicOperations.ZeroMemory(control);
            operation = hash = control = null;
        }
    }
}

public sealed class ExactBraidRecoveryPreparedTransition : IDisposable
{
    private readonly object gate = new();
    private ExactBraidRecoveryPersistencePlan? plan;
    private bool inFlight, disposeRequested;
    internal ExactBraidRecoveryPreparedTransition(ExactBraidRecoveryPersistencePlan plan) => this.plan = plan;

    public async ValueTask<ExactBraidRecoverySuccessCapability> CommitAsync(
        IExactBraidRecoveryDurableTransactionAuthority authority, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        cancellationToken.ThrowIfCancellationRequested();
        ExactBraidRecoveryPersistencePlan current;
        lock (gate)
        {
            if (inFlight) throw new InvalidOperationException("Control commit is already in flight.");
            current = plan ?? throw new ObjectDisposedException(nameof(ExactBraidRecoveryPreparedTransition));
            inFlight = true;
        }
        try
        {
            var completion = new ExactBraidRecoveryCommitCompletion(current);
            var receipt = await authority.CommitAsync(current, completion, cancellationToken).ConfigureAwait(false);
            var disposition = (receipt ?? throw new CryptographicException("Control durable receipt is missing."))
                .Consume(current, completion);
            if (disposition is not (ExactDpe2DurableCommitDisposition.Committed or ExactDpe2DurableCommitDisposition.ExactReplay) ||
                (!current.HasStateMutation && disposition != ExactDpe2DurableCommitDisposition.ExactReplay))
            {
                lock (gate) disposeRequested = true;
                throw new CryptographicException("Control durable authority rejected the exact transition.");
            }
            var result = new ExactBraidRecoverySuccessCapability(current,
                disposition == ExactDpe2DurableCommitDisposition.ExactReplay);
            lock (gate) disposeRequested = true;
            return result;
        }
        finally
        {
            lock (gate)
            {
                inFlight = false;
                if (disposeRequested) { plan?.Dispose(); plan = null; }
            }
        }
    }
    public void Dispose()
    {
        lock (gate)
        {
            disposeRequested = true;
            if (!inFlight) { plan?.Dispose(); plan = null; }
        }
    }
}

/// <summary>DR-0113 closed custody target. SQL/transport activation remains gated.</summary>
public static class ExactBraidRecoveryDurableTransactionProducer
{
    public static ExactBraidRecoveryPreparedTransition PrepareSend(ReadOnlySpan<byte> exactPriorTrs1,
        ExactDpe2DurableTransitionContext context, ReadOnlySpan<byte> expectedNetworkId, ReadOnlySpan<byte> operationId)
    {
        ArgumentNullException.ThrowIfNull(context);
        MessagingCryptoValidation.NonZeroExact(expectedNetworkId, 16, nameof(expectedNetworkId));
        MessagingCryptoValidation.NonZeroExact(operationId, 32, nameof(operationId));
        if (context.ReceiveReplayDisposition != ExactDpe2ReceiveReplayDisposition.Fresh)
            throw Rejected("Send retry must use the original verified durable control row.");
        using var prior = TripleRatchetDurableStateCodec.Decode(exactPriorTrs1);
        ValidatePrior(prior, context, true);
        using var provider = ManagedTripleRatchetComponentProvider.CreateApproved(DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess());
        using var candidate = prior.PrepareBraidRecoverySend(provider, expectedNetworkId, operationId);
        return PrepareFresh(ExactBraidRecoveryDurableDirection.Send, prior, candidate, context, exactPriorTrs1);
    }

    public static ExactBraidRecoveryPreparedTransition PrepareReceive(ReadOnlySpan<byte> exactPriorTrs1,
        ExactDpe2DurableTransitionContext context, ReadOnlySpan<byte> expectedNetworkId, ReadOnlySpan<byte> exactControl)
    {
        ArgumentNullException.ThrowIfNull(context);
        MessagingCryptoValidation.NonZeroExact(expectedNetworkId, 16, nameof(expectedNetworkId));
        var frame = Dbr2Codec.Decode(exactControl);
        using var prior = TripleRatchetDurableStateCodec.Decode(exactPriorTrs1);
        var replay = context.ReceiveReplayDisposition == ExactDpe2ReceiveReplayDisposition.ExactReplay;
        ValidatePrior(prior, context, !replay);
        if (!MessagingCryptoValidation.FixedEquals(expectedNetworkId, frame.NetworkId.Span) ||
            !MessagingCryptoValidation.FixedEquals(prior.Binding.SessionId.Span, frame.SessionId.Span) ||
            !MessagingCryptoValidation.FixedEquals(prior.Binding.RemoteDeviceId.Span, frame.SenderDeviceId.Span) ||
            !MessagingCryptoValidation.FixedEquals(prior.Binding.LocalDeviceId.Span, frame.RecipientDeviceId.Span))
            throw Rejected("Control scope/direction differs from the current owned session.");
        if (replay)
            return new(new(ExactBraidRecoveryDurableDirection.Receive, prior, null, context, exactPriorTrs1, [], frame));
        using var provider = ManagedTripleRatchetComponentProvider.CreateApproved(DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess());
        using var candidate = prior.PrepareBraidRecoveryReceive(provider, expectedNetworkId, exactControl);
        if (candidate.IsExactReplay)
            throw Rejected("Native control replay lacks its matching durable retained-operation disposition.");
        return PrepareFresh(ExactBraidRecoveryDurableDirection.Receive, prior, candidate, context, exactPriorTrs1);
    }

    private static ExactBraidRecoveryPreparedTransition PrepareFresh(ExactBraidRecoveryDurableDirection direction,
        TripleRatchetState prior, TripleRatchetBraidRecoveryCandidate candidate,
        ExactDpe2DurableTransitionContext context, ReadOnlySpan<byte> exactPriorTrs1)
    {
        using var next = candidate.TakeNextState();
        var encoded = TripleRatchetDurableStateCodec.Encode(next);
        try { return new(new(direction, prior, next, context, exactPriorTrs1, encoded, candidate.Control)); }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }
    public static VerifiedBraidRecoveryObsoleteControl? TryVerifyObsoleteControl(ReadOnlySpan<byte> exactPriorTrs1,
        ExactDpe2DurableTransitionContext context, ReadOnlySpan<byte> expectedNetworkId, ReadOnlySpan<byte> exactControl)
    {
        ArgumentNullException.ThrowIfNull(context);
        MessagingCryptoValidation.NonZeroExact(expectedNetworkId, 16, nameof(expectedNetworkId));
        if (context.ReceiveReplayDisposition != ExactDpe2ReceiveReplayDisposition.Fresh)
            throw Rejected("Obsolete disposal cannot replace exact durable receive replay.");
        var frame = Dbr2Codec.Decode(exactControl);
        using var prior = TripleRatchetDurableStateCodec.Decode(exactPriorTrs1);
        ValidatePrior(prior, context, false);
        using var provider = ManagedTripleRatchetComponentProvider.CreateApproved(DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess());
        if (!prior.TryVerifyObsoleteBraidRecoveryControl(provider, expectedNetworkId, frame)) return null;
        return new(prior.StorageGeneration, prior.StateCommitment.Span, frame.BraidEpoch, SHA256.HashData(exactControl));
    }

    private static void ValidatePrior(TripleRatchetState prior, ExactDpe2DurableTransitionContext context, bool fresh)
    {
        if (prior.StorageGeneration != context.ExpectedStateGeneration ||
            !MessagingCryptoValidation.FixedEquals(prior.StateCommitment.Span, context.ExpectedStateCommitmentSpan) ||
            context.LatestProtectedGeneration != context.ExpectedStateGeneration ||
            !MessagingCryptoValidation.FixedEquals(context.LatestProtectedCommitmentSpan, context.ExpectedStateCommitmentSpan))
            throw new MessagingCryptoException(MessagingCryptoError.CasConflict, "Control predecessor differs from the stable protected state.");
        if (fresh && (prior.StorageGeneration == ulong.MaxValue || context.ExpectedJournalGeneration >= long.MaxValue))
            throw Rejected("Control state/journal increment capacity is exhausted.");
    }
    private static MessagingCryptoException Rejected(string message) => new(MessagingCryptoError.TransitionRejected, message);
}
