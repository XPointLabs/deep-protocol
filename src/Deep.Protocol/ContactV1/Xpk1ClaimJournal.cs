using System.Security.Cryptography;

namespace Deep.Protocol.ContactV1;

public enum Xpk1ClaimJournalDisposition
{
    Staged = 1,
    ExactRetry = 2,
    ResultRecorded = 3,
    TerminalExactReplay = 4,
    ScopeRejected = 5,
    ForkLatched = 6,
}

/// <summary>
/// Immutable protocol state for one durable exact-XPK1 operation. Persistence
/// remains consumer-owned; Protocol alone classifies exact retries, byte drift,
/// and terminal XPC1 results.
/// </summary>
public sealed class Xpk1ClaimJournalState
{
    private readonly byte[] _exactRequest;
    private readonly byte[]? _storedResultWire;

    private Xpk1ClaimJournalState(
        Xpk1Request request,
        ReadOnlySpan<byte> exactRequest,
        ReadOnlySpan<byte> storedResultWire,
        Xpc1Status? storedStatus,
        bool forkLatched)
    {
        Request = request;
        _exactRequest = exactRequest.ToArray();
        _storedResultWire = storedResultWire.IsEmpty ? null : storedResultWire.ToArray();
        StoredStatus = storedStatus;
        IsForkLatched = forkLatched;
    }

    public Xpk1Request Request { get; }
    public ReadOnlyMemory<byte> ExactRequest => _exactRequest.ToArray();
    public ReadOnlyMemory<byte> OperationId => Request.OperationId;
    public ReadOnlyMemory<byte> ServiceCapability => Request.ServiceCapability;
    public ReadOnlyMemory<byte> Xps1Hash => Request.Xps1Hash;
    public ReadOnlyMemory<byte> RequestHash => Request.RequestHash;
    public ReadOnlyMemory<byte> StoredResultWire => _storedResultWire?.ToArray() ?? ReadOnlyMemory<byte>.Empty;
    public Xpc1Status? StoredStatus { get; }
    public bool HasStoredResult => _storedResultWire is not null;
    public bool IsTerminal => StoredStatus is not null && !IsRetryable(StoredStatus.Value);
    public bool IsForkLatched { get; }
    public bool CanDispatchExactRequest => !IsForkLatched && !IsTerminal;

    public static Xpk1ClaimJournalState Stage(ReadOnlySpan<byte> exactXpk1)
    {
        var request = Xpk1Codec.Decode(exactXpk1);
        if (!request.CanonicalBytes.Span.SequenceEqual(exactXpk1))
            throw new CryptographicException("The claim journal requires exact canonical XPK1 bytes.");
        return new Xpk1ClaimJournalState(request, exactXpk1, [], null, false);
    }

    public static Xpk1ClaimJournalState RestoreFailure(
        ReadOnlySpan<byte> exactXpk1,
        ReadOnlySpan<byte> exactXpc1Wire)
    {
        var state = Stage(exactXpk1);
        var result = Xpc1Codec.Decode(exactXpc1Wire, exactXpk1);
        if (result.Status is Xpc1Status.Claimed or Xpc1Status.Replay)
            throw new CryptographicException("A successful XPC1 must be restored through a verified claim receipt.");
        return state.RecordFailureResult(result).NextState;
    }

    public static Xpk1ClaimJournalState RestoreVerifiedClaim(
        ReadOnlySpan<byte> exactXpk1,
        ReadOnlySpan<byte> exactXpc1Wire,
        VerifiedXpc1PreKeyClaimReceipt verifiedReceipt)
    {
        ArgumentNullException.ThrowIfNull(verifiedReceipt);
        var state = Stage(exactXpk1);
        var result = Xpc1Codec.Decode(exactXpc1Wire, exactXpk1);
        return state.RecordVerifiedClaimResult(result, verifiedReceipt).NextState;
    }

    public Xpk1ClaimJournalTransition ApplyRequest(ReadOnlySpan<byte> exactXpk1)
    {
        var candidate = Xpk1Codec.Decode(exactXpk1);
        if (!candidate.CanonicalBytes.Span.SequenceEqual(exactXpk1))
            throw new CryptographicException("The claim journal requires exact canonical XPK1 bytes.");
        if (!Fixed(candidate.OperationId.Span, Request.OperationId.Span))
            return Transition(Xpk1ClaimJournalDisposition.ScopeRejected, this, false, false);
        if (IsForkLatched)
            return Transition(Xpk1ClaimJournalDisposition.ForkLatched, this, false, false);
        if (!_exactRequest.AsSpan().SequenceEqual(exactXpk1))
            return Fork();
        if (IsTerminal)
            return Transition(Xpk1ClaimJournalDisposition.TerminalExactReplay, this, false, true);
        return Transition(Xpk1ClaimJournalDisposition.ExactRetry, this, false, false);
    }

    public Xpk1ClaimJournalTransition RecordFailureResult(Xpc1Result result)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (result.Status is Xpc1Status.Claimed or Xpc1Status.Replay)
            throw new CryptographicException("A successful XPC1 requires a verified claim receipt.");
        return RecordResultCore(result);
    }

    public Xpk1ClaimJournalTransition RecordVerifiedClaimResult(
        Xpc1Result result,
        VerifiedXpc1PreKeyClaimReceipt verifiedReceipt)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(verifiedReceipt);
        if (result.Status is not (Xpc1Status.Claimed or Xpc1Status.Replay))
            throw new CryptographicException("The verified claim receipt does not apply to a non-success XPC1.");
        verifiedReceipt.RequireExactJournalResult(Request, result);
        return RecordResultCore(result);
    }

    private Xpk1ClaimJournalTransition RecordResultCore(Xpc1Result result)
    {
        if (IsForkLatched)
            return Transition(Xpk1ClaimJournalDisposition.ForkLatched, this, false, false);

        var decoded = Xpc1Codec.Decode(result.WireBytes.Span, _exactRequest);
        if (!decoded.CanonicalBytes.Span.SequenceEqual(result.CanonicalBytes.Span) ||
            !decoded.WireBytes.Span.SequenceEqual(result.WireBytes.Span))
            throw new CryptographicException("The XPC1 result is not the exact result for the journaled XPK1.");

        if (_storedResultWire is not null)
        {
            if (_storedResultWire.AsSpan().SequenceEqual(result.WireBytes.Span))
            {
                return Transition(
                    IsTerminal ? Xpk1ClaimJournalDisposition.TerminalExactReplay : Xpk1ClaimJournalDisposition.ExactRetry,
                    this,
                    false,
                    IsTerminal);
            }
            if (IsTerminal)
                return Fork();
        }

        var next = new Xpk1ClaimJournalState(
            Request, _exactRequest, result.WireBytes.Span, result.Status, false);
        return Transition(Xpk1ClaimJournalDisposition.ResultRecorded, next, true, false);
    }

    private Xpk1ClaimJournalTransition Fork()
    {
        var next = new Xpk1ClaimJournalState(
            Request, _exactRequest, _storedResultWire ?? [], StoredStatus, true);
        return Transition(Xpk1ClaimJournalDisposition.ForkLatched, next, true, false);
    }

    private static Xpk1ClaimJournalTransition Transition(
        Xpk1ClaimJournalDisposition disposition,
        Xpk1ClaimJournalState next,
        bool requiresDurableWrite,
        bool requiresStoredResult) =>
        new(disposition, next, requiresDurableWrite, requiresStoredResult);

    private static bool IsRetryable(Xpc1Status status) =>
        status is Xpc1Status.RateLimited or Xpc1Status.OutcomeUnknown;

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public sealed class Xpk1ClaimJournalTransition
{
    internal Xpk1ClaimJournalTransition(
        Xpk1ClaimJournalDisposition disposition,
        Xpk1ClaimJournalState nextState,
        bool requiresDurableWrite,
        bool requiresStoredResult)
    {
        Disposition = disposition;
        NextState = nextState;
        RequiresDurableWrite = requiresDurableWrite;
        RequiresStoredResult = requiresStoredResult;
    }

    public Xpk1ClaimJournalDisposition Disposition { get; }
    public Xpk1ClaimJournalState NextState { get; }
    public bool RequiresDurableWrite { get; }
    public bool RequiresStoredResult { get; }
    public bool CanDispatchExactRequest =>
        Disposition == Xpk1ClaimJournalDisposition.ExactRetry ||
        Disposition == Xpk1ClaimJournalDisposition.ResultRecorded && NextState.CanDispatchExactRequest;
}
