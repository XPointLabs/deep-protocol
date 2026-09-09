using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.MessagingCrypto;

internal readonly record struct RatchetEcChainId(ulong A, ulong B, ulong C, ulong D)
{
    internal const int EncodedSize = 32;

    internal static RatchetEcChainId FromPublicKey(ReadOnlySpan<byte> publicKey)
    {
        MessagingCryptoValidation.NonZeroExact(publicKey, EncodedSize, nameof(publicKey));
        return Read(publicKey);
    }

    internal static RatchetEcChainId Read(ReadOnlySpan<byte> source)
    {
        MessagingCryptoValidation.Exact(source, EncodedSize, nameof(source));
        return new RatchetEcChainId(
            BinaryPrimitives.ReadUInt64BigEndian(source),
            BinaryPrimitives.ReadUInt64BigEndian(source[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(source[16..]),
            BinaryPrimitives.ReadUInt64BigEndian(source[24..]));
    }

    internal bool IsZero => (A | B | C | D) == 0;

    internal void Write(Span<byte> destination)
    {
        if (destination.Length != EncodedSize)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The ratchet public-key identity destination must be exactly 32 bytes.");
        BinaryPrimitives.WriteUInt64BigEndian(destination, A);
        BinaryPrimitives.WriteUInt64BigEndian(destination[8..], B);
        BinaryPrimitives.WriteUInt64BigEndian(destination[16..], C);
        BinaryPrimitives.WriteUInt64BigEndian(destination[24..], D);
    }

    internal byte[] ToArray()
    {
        var encoded = new byte[EncodedSize];
        Write(encoded);
        return encoded;
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static RatchetEcChainId DarkDefaultForTests => new(
        0x5D5D5D5D5D5D5D5D,
        0x5D5D5D5D5D5D5D5D,
        0x5D5D5D5D5D5D5D5D,
        0x5D5D5D5D5D5D5D5D);
#endif
}

internal readonly record struct RatchetCounterTuple(
    RatchetEcChainId EcChain,
    ulong EcN,
    ulong SckaEpoch,
    ulong SckaN)
{
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal RatchetCounterTuple(ulong ecN, ulong sckaEpoch, ulong sckaN)
        : this(RatchetEcChainId.DarkDefaultForTests, ecN, sckaEpoch, sckaN)
    {
    }
#endif
}

internal readonly record struct RatchetEcChainCursor(RatchetEcChainId Chain, ulong NextN);
internal readonly record struct PqInjectionSchedule(int MessagesSinceFreshContribution, int MaximumMessagesWithoutFreshContribution);
internal enum RatchetPlanOutcome { Fresh, OutOfOrderSkippedKey, ExactReplay, RollbackLatched }
internal enum RatchetDeletionKind
{
    MessageKeyAfterUse,
    PreviousStateAfterCommit,
    ConsumedSkippedKeyAfterCommit,
    ProviderTransitionSecrets,
    AllSessionSecretsAfterRollbackLatch,
}

internal sealed class PqStepEvidence
{
    private readonly byte[] _priorStateCommitment;
    private readonly byte[] _nextStateCommitment;

    internal PqStepEvidence(
        ReadOnlySpan<byte> priorStateCommitment,
        ReadOnlySpan<byte> nextStateCommitment,
        bool hasFreshContribution)
    {
        MessagingCryptoValidation.NonZeroExact(priorStateCommitment, 32, nameof(priorStateCommitment));
        MessagingCryptoValidation.NonZeroExact(nextStateCommitment, 32, nameof(nextStateCommitment));
        if (MessagingCryptoValidation.FixedEquals(priorStateCommitment, nextStateCommitment))
            throw new MessagingCryptoException(
                MessagingCryptoError.PqEvidenceRejected,
                "A PQ step must advance its state commitment.");
        _priorStateCommitment = priorStateCommitment.ToArray();
        _nextStateCommitment = nextStateCommitment.ToArray();
        HasFreshContribution = hasFreshContribution;
    }

    internal bool HasFreshContribution { get; }
    internal ReadOnlySpan<byte> PriorStateCommitment => _priorStateCommitment;
    internal ReadOnlySpan<byte> NextStateCommitment => _nextStateCommitment;
    internal PqStepEvidence Clone() => new(_priorStateCommitment, _nextStateCommitment, HasFreshContribution);
}

internal sealed class RatchetComponentKeyMaterial : IDisposable
{
    private readonly SecretBuffer _ecMessageKey;
    private readonly SecretBuffer _pqMessageKey;

    internal RatchetComponentKeyMaterial(
        RatchetCounterTuple counters,
        ReadOnlySpan<byte> ecMessageKey,
        ReadOnlySpan<byte> pqMessageKey,
        PqStepEvidence pqEvidence)
    {
        if (counters.EcChain.IsZero)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "A ratchet component key must identify its nonzero X25519 chain key.");
        MessagingCryptoValidation.NonZeroExact(ecMessageKey, 32, nameof(ecMessageKey));
        MessagingCryptoValidation.NonZeroExact(pqMessageKey, 32, nameof(pqMessageKey));
        ArgumentNullException.ThrowIfNull(pqEvidence);
        Counters = counters;
        PqEvidence = pqEvidence;
        _ecMessageKey = SecretBuffer.ImportExact(ecMessageKey, 32, nameof(ecMessageKey));
        try
        {
            _pqMessageKey = SecretBuffer.ImportExact(pqMessageKey, 32, nameof(pqMessageKey));
        }
        catch
        {
            _ecMessageKey.Dispose();
            throw;
        }
    }

    internal RatchetCounterTuple Counters { get; }
    internal PqStepEvidence PqEvidence { get; }

    internal byte[] Derive(ReadOnlySpan<byte> sessionId, ReadOnlySpan<byte> headerHash)
    {
        byte[]? ec = null;
        byte[]? pq = null;
        try
        {
            ec = _ecMessageKey.Copy();
            pq = _pqMessageKey.Copy();
            return MessagingKdf.DeriveCombinedMessageKey(
                sessionId, Counters.EcN, Counters.SckaEpoch, Counters.SckaN,
                headerHash, ec, pq);
        }
        finally
        {
            if (ec is not null) CryptographicOperations.ZeroMemory(ec);
            if (pq is not null) CryptographicOperations.ZeroMemory(pq);
        }
    }

    internal SkippedComponentKey CloneForSkipped()
    {
        SecretBuffer? ec = null;
        SecretBuffer? pq = null;
        try
        {
            ec = _ecMessageKey.Clone();
            pq = _pqMessageKey.Clone();
            var clone = new SkippedComponentKey(Counters, ec, pq, PqEvidence.Clone());
            ec = null;
            pq = null;
            return clone;
        }
        finally
        {
            ec?.Dispose();
            pq?.Dispose();
        }
    }

    internal byte[] ComputeTupleCommitment(ReadOnlySpan<byte> bindingCommitment) =>
        ComputePqTupleCommitment(bindingCommitment, Counters, PqEvidence.NextStateCommitment);

    internal byte[] ComputePqKeyReuseCommitment()
    {
        var pq = _pqMessageKey.Copy();
        try
        {
            return MessagingKdf.Sha256Domain("Deep/Messaging/V2/pq-key-reuse", pq);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pq);
        }
    }

    internal static byte[] ComputePqTupleCommitment(
        ReadOnlySpan<byte> bindingCommitment,
        RatchetCounterTuple counters,
        ReadOnlySpan<byte> nextPqCommitment)
    {
        Span<byte> value = stackalloc byte[32 + 8 + 8 + 8 + 32];
        bindingCommitment.CopyTo(value);
        BinaryPrimitives.WriteUInt64BigEndian(value[32..], counters.EcN);
        BinaryPrimitives.WriteUInt64BigEndian(value[40..], counters.SckaEpoch);
        BinaryPrimitives.WriteUInt64BigEndian(value[48..], counters.SckaN);
        nextPqCommitment.CopyTo(value[56..]);
        return MessagingKdf.Sha256Domain("Deep/Messaging/V2/pq-tuple", value);
    }

    public void Dispose()
    {
        _ecMessageKey.Dispose();
        _pqMessageKey.Dispose();
    }
}

internal interface ITripleRatchetComponentProvider
{
    RatchetComponentTransition PrepareSend(
        ReadOnlySpan<byte> currentOpaqueState,
        RatchetEcChainCursor sendCursor,
        ReadOnlySpan<byte> networkId,
        PqInjectionSchedule pqSchedule);

    RatchetComponentTransition PrepareReceive(
        ReadOnlySpan<byte> currentOpaqueState,
        RatchetEcChainCursor receiveCursor,
        RatchetCounterTuple target,
        ReadOnlySpan<byte> exactDtr2,
        PqInjectionSchedule pqSchedule);
}

internal sealed class RatchetComponentTransition : IDisposable
{
    private SecretBuffer? _nextOpaqueState;
    private List<RatchetComponentKeyMaterial>? _messageKeys;
    private byte[]? _exactSendDtr2;

    internal RatchetComponentTransition(
        ReadOnlySpan<byte> nextOpaqueState,
        RatchetComponentKeyMaterial[] messageKeys,
        ReadOnlySpan<byte> exactSendDtr2 = default)
    {
        ArgumentNullException.ThrowIfNull(messageKeys);
        SecretBuffer? nextState = null;
        try
        {
            if (nextOpaqueState.Length is < 1 or > MessagingCryptoConstants.MaximumOpaqueProviderStateBytes)
                throw new MessagingCryptoException(
                    MessagingCryptoError.StateLimitExceeded,
                    "The provider state is empty or exceeds the dark component bound.");
            if (messageKeys.Length is < 1 or > MessagingCryptoConstants.MaximumForwardGap + 1 ||
                messageKeys.Any(static key => key is null))
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "The provider returned an invalid or unbounded exact owned key collection.");
            nextState = SecretBuffer.ImportBounded(
                nextOpaqueState, 1, MessagingCryptoConstants.MaximumOpaqueProviderStateBytes, nameof(nextOpaqueState));
            _messageKeys = new List<RatchetComponentKeyMaterial>(messageKeys);
            _nextOpaqueState = nextState;
            if (!exactSendDtr2.IsEmpty)
            {
                var parsed = Dtr2Codec.DecodeEmbedded(exactSendDtr2);
                var canonical = Dtr2Codec.EncodeEmbedded(parsed);
                if (!canonical.AsSpan().SequenceEqual(exactSendDtr2))
                    throw new MessagingCryptoException(
                        MessagingCryptoError.TransitionRejected,
                        "The provider returned a non-canonical DTR2 send header.");
                _exactSendDtr2 = canonical;
            }
            nextState = null;
        }
        catch
        {
            nextState?.Dispose();
            foreach (var key in messageKeys) key?.Dispose();
            throw;
        }
    }

    internal SecretBuffer TakeNextState() => Interlocked.Exchange(ref _nextOpaqueState, null) ??
        throw new MessagingCryptoException(MessagingCryptoError.CapabilityConsumed, "Provider state was transferred.");

    internal List<RatchetComponentKeyMaterial> TakeMessageKeys() =>
        Interlocked.Exchange(ref _messageKeys, null) ??
        throw new MessagingCryptoException(MessagingCryptoError.CapabilityConsumed, "Provider keys were transferred.");

    internal bool HasExactSendDtr2 => _exactSendDtr2 is not null;

    internal byte[] TakeExactSendDtr2() => Interlocked.Exchange(ref _exactSendDtr2, null) ??
        throw new MessagingCryptoException(
            MessagingCryptoError.TransitionRejected,
            "The provider transition has no exact canonical DTR2 send header.");

    public void Dispose()
    {
        Interlocked.Exchange(ref _nextOpaqueState, null)?.Dispose();
        var keys = Interlocked.Exchange(ref _messageKeys, null);
        var header = Interlocked.Exchange(ref _exactSendDtr2, null);
        if (header is not null) CryptographicOperations.ZeroMemory(header);
        if (keys is null) return;
        foreach (var key in keys) key.Dispose();
    }
}

internal sealed class SkippedComponentKey : IDisposable
{
    internal SkippedComponentKey(
        RatchetCounterTuple counters,
        SecretBuffer ec,
        SecretBuffer pq,
        PqStepEvidence evidence)
    {
        Counters = counters;
        Ec = ec;
        Pq = pq;
        Evidence = evidence;
    }

    internal RatchetCounterTuple Counters { get; }
    internal SecretBuffer Ec { get; }
    internal SecretBuffer Pq { get; }
    internal PqStepEvidence Evidence { get; }

    internal byte[] Derive(ReadOnlySpan<byte> sessionId, ReadOnlySpan<byte> headerHash)
    {
        byte[]? ec = null;
        byte[]? pq = null;
        try
        {
            ec = Ec.Copy();
            pq = Pq.Copy();
            return MessagingKdf.DeriveCombinedMessageKey(
                sessionId, Counters.EcN, Counters.SckaEpoch, Counters.SckaN,
                headerHash, ec, pq);
        }
        finally
        {
            if (ec is not null) CryptographicOperations.ZeroMemory(ec);
            if (pq is not null) CryptographicOperations.ZeroMemory(pq);
        }
    }

    internal SkippedComponentKey Clone()
    {
        SecretBuffer? ec = null;
        SecretBuffer? pq = null;
        try
        {
            ec = Ec.Clone();
            pq = Pq.Clone();
            var clone = new SkippedComponentKey(Counters, ec, pq, Evidence.Clone());
            ec = null;
            pq = null;
            return clone;
        }
        finally
        {
            ec?.Dispose();
            pq?.Dispose();
        }
    }

    internal byte[] TupleCommitment(ReadOnlySpan<byte> bindingCommitment) =>
        RatchetComponentKeyMaterial.ComputePqTupleCommitment(
            bindingCommitment, Counters, Evidence.NextStateCommitment);

    internal byte[] StateCommitment(ReadOnlySpan<byte> bindingCommitment)
    {
        byte[]? ec = null;
        byte[]? pq = null;
        byte[]? tuple = null;
        Span<byte> input = stackalloc byte[96];
        try
        {
            ec = Ec.Copy();
            pq = Pq.Copy();
            tuple = TupleCommitment(bindingCommitment);
            tuple.CopyTo(input);
            SHA256.HashData(ec, input[32..64]);
            SHA256.HashData(pq, input[64..]);
            return MessagingKdf.Sha256Domain("Deep/Messaging/V2/skipped-state", input);
        }
        finally
        {
            if (ec is not null) CryptographicOperations.ZeroMemory(ec);
            if (pq is not null) CryptographicOperations.ZeroMemory(pq);
            if (tuple is not null) CryptographicOperations.ZeroMemory(tuple);
            CryptographicOperations.ZeroMemory(input);
        }
    }

    public void Dispose()
    {
        Ec.Dispose();
        Pq.Dispose();
    }
}

internal sealed class RatchetDeduplicationMutation
{
    private readonly byte[] _stateBindingCommitment;
    private readonly byte[] _sessionId;
    private readonly byte[] _operationId;
    private readonly byte[] _exactHeaderHash;
    private readonly byte[] _envelopeHash;
    private readonly byte[] _journalPredecessor;
    private readonly byte[] _retentionCommitment;
    private readonly byte[][] _consumedPqTupleCommitments;
    private readonly byte[] _commitment;

    internal RatchetDeduplicationMutation(
        RatchetDeduplicationData lease,
        IEnumerable<byte[]> consumedPqTupleCommitments)
    {
        _stateBindingCommitment = lease.StateBindingCommitment.ToArray();
        _sessionId = lease.SessionId.ToArray();
        Target = lease.Target;
        _operationId = lease.OperationId.ToArray();
        _exactHeaderHash = lease.ExactHeaderHash.ToArray();
        _envelopeHash = lease.EnvelopeHash.ToArray();
        ExpectedJournalGeneration = lease.JournalGeneration;
        _journalPredecessor = lease.JournalPredecessor.ToArray();
        _retentionCommitment = lease.RetentionCommitment.ToArray();
        _consumedPqTupleCommitments = consumedPqTupleCommitments.Select(static value => value.ToArray()).ToArray();
        if (_consumedPqTupleCommitments.Length == 0 ||
            _consumedPqTupleCommitments.Any(static value =>
                value.Length != 32 || MessagingCryptoValidation.IsZero(value)) ||
            _consumedPqTupleCommitments.Select(Convert.ToHexString)
                .Distinct(StringComparer.Ordinal).Count() != _consumedPqTupleCommitments.Length)
            throw new MessagingCryptoException(
                MessagingCryptoError.ReplayConflict,
                "A dedup mutation requires unique nonzero consumed PQ tuple commitments.");
        _commitment = ComputeCommitment();
    }

    internal RatchetCounterTuple Target { get; }
    internal ulong ExpectedJournalGeneration { get; }
    internal ReadOnlyMemory<byte> OperationId => _operationId.ToArray();
    internal ReadOnlyMemory<byte> EnvelopeHash => _envelopeHash.ToArray();
    internal ReadOnlyMemory<byte> JournalPredecessor => _journalPredecessor.ToArray();
    internal ReadOnlyMemory<byte> RetentionCommitment => _retentionCommitment.ToArray();
    internal IReadOnlyList<ReadOnlyMemory<byte>> ConsumedPqTupleCommitments =>
        _consumedPqTupleCommitments.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
    internal ReadOnlyMemory<byte> Commitment => _commitment.ToArray();

    private byte[] ComputeCommitment()
    {
        var input = new byte[
            32 + 32 + 24 + 32 + 32 + 32 + 8 + 32 + 32 + 4 +
            _consumedPqTupleCommitments.Length * 32];
        var offset = 0;
        _stateBindingCommitment.CopyTo(input, offset); offset += 32;
        _sessionId.CopyTo(input, offset); offset += 32;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset), Target.EcN); offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset), Target.SckaEpoch); offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset), Target.SckaN); offset += 8;
        _operationId.CopyTo(input, offset); offset += 32;
        _exactHeaderHash.CopyTo(input, offset); offset += 32;
        _envelopeHash.CopyTo(input, offset); offset += 32;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset), ExpectedJournalGeneration); offset += 8;
        _journalPredecessor.CopyTo(input, offset); offset += 32;
        _retentionCommitment.CopyTo(input, offset); offset += 32;
        BinaryPrimitives.WriteUInt32BigEndian(
            input.AsSpan(offset), checked((uint)_consumedPqTupleCommitments.Length));
        offset += 4;
        foreach (var tuple in _consumedPqTupleCommitments)
        {
            tuple.CopyTo(input, offset);
            offset += 32;
        }
        try
        {
            return MessagingKdf.Sha256Domain("Deep/Messaging/V2/dedup-mutation", input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }
}

internal sealed class RatchetPqFenceMutation
{
    private readonly byte[][] _pqKeyCommitments;
    private readonly byte[] _commitment;

    internal RatchetPqFenceMutation(IEnumerable<byte[]> pqKeyCommitments)
    {
        ArgumentNullException.ThrowIfNull(pqKeyCommitments);
        _pqKeyCommitments = pqKeyCommitments.Select(static value => value.ToArray()).ToArray();
        if (_pqKeyCommitments.Length == 0 ||
            _pqKeyCommitments.Any(static value => value.Length != 32 || MessagingCryptoValidation.IsZero(value)) ||
            _pqKeyCommitments.Select(Convert.ToHexString).Distinct(StringComparer.Ordinal).Count() != _pqKeyCommitments.Length)
            throw new MessagingCryptoException(
                MessagingCryptoError.PqEvidenceRejected,
                "The durable PQ-key fence mutation is empty, malformed, or reuses a key commitment.");
        var input = new byte[4 + _pqKeyCommitments.Length * 32];
        BinaryPrimitives.WriteUInt32BigEndian(input, checked((uint)_pqKeyCommitments.Length));
        for (var index = 0; index < _pqKeyCommitments.Length; index++)
            _pqKeyCommitments[index].CopyTo(input, 4 + index * 32);
        _commitment = MessagingKdf.Sha256Domain("Deep/Messaging/V2/pq-key-fence-mutation", input);
        CryptographicOperations.ZeroMemory(input);
    }

    internal IReadOnlyList<ReadOnlyMemory<byte>> PqKeyCommitments =>
        _pqKeyCommitments.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
    internal ReadOnlyMemory<byte> Commitment => _commitment.ToArray();
}

internal sealed partial class TripleRatchetState : IDisposable
{
    private readonly object _lifecycleSync = new();
    private readonly SecretBuffer? _componentState;
    private readonly Dictionary<RatchetCounterTuple, SkippedComponentKey> _skipped;
    private readonly byte[] _receivePqStateCommitment;
    private readonly byte[] _sendPqStateCommitment;
    private readonly byte[] _stateCommitment;
    private readonly int _maximumMessagesWithoutPqInjection;
    private bool _disposed;

    private TripleRatchetState(
        RatchetStateBinding binding,
        SecretBuffer? componentState,
        RatchetEcChainId receiveEcChain,
        ulong nextExpectedReceiveEcN,
        RatchetEcChainId sendEcChain,
        ulong nextSendEcN,
        ulong storageGeneration,
        int receiveMessagesSincePqInjection,
        int sendMessagesSincePqInjection,
        RatchetCounterTuple receivePqFrontier,
        RatchetCounterTuple sendPqFrontier,
        byte[] receivePqStateCommitment,
        byte[] sendPqStateCommitment,
        int maximumMessagesWithoutPqInjection,
        Dictionary<RatchetCounterTuple, SkippedComponentKey> skipped,
        bool isTerminallyLatched)
    {
        Binding = binding;
        _componentState = componentState;
        ReceiveEcChain = receiveEcChain;
        NextExpectedReceiveEcN = nextExpectedReceiveEcN;
        SendEcChain = sendEcChain;
        NextSendEcN = nextSendEcN;
        StorageGeneration = storageGeneration;
        ReceiveMessagesSincePqInjection = receiveMessagesSincePqInjection;
        SendMessagesSincePqInjection = sendMessagesSincePqInjection;
        ReceivePqFrontier = receivePqFrontier;
        SendPqFrontier = sendPqFrontier;
        _receivePqStateCommitment = receivePqStateCommitment;
        _sendPqStateCommitment = sendPqStateCommitment;
        _maximumMessagesWithoutPqInjection = maximumMessagesWithoutPqInjection;
        _skipped = skipped;
        IsTerminallyLatched = isTerminallyLatched;
        try
        {
            ValidateDurableStateShape();
            _stateCommitment = ComputeStateCommitment();
        }
        catch
        {
            _componentState?.Dispose();
            foreach (var retained in _skipped.Values) retained.Dispose();
            throw;
        }
    }

    internal RatchetStateBinding Binding { get; }
    internal RatchetEcChainId ReceiveEcChain { get; }
    internal ulong NextExpectedReceiveEcN { get; }
    internal RatchetEcChainId SendEcChain { get; }
    internal ulong NextSendEcN { get; }
    internal ulong StorageGeneration { get; }
    internal int ReceiveMessagesSincePqInjection { get; }
    internal int SendMessagesSincePqInjection { get; }
    internal RatchetCounterTuple ReceivePqFrontier { get; }
    internal RatchetCounterTuple SendPqFrontier { get; }
    internal int SkippedKeyCount => _skipped.Count;
    internal bool IsTerminallyLatched { get; }
    internal ReadOnlyMemory<byte> StateCommitment => _stateCommitment.ToArray();

    internal static TripleRatchetState Create(
        RatchetStateBinding binding,
        ReadOnlySpan<byte> initialOpaqueComponentState,
        ReadOnlySpan<byte> initialReceiveEcRatchetPublicKey,
        ReadOnlySpan<byte> initialSendEcRatchetPublicKey,
        ReadOnlySpan<byte> initialReceivePqStateCommitment,
        ReadOnlySpan<byte> initialSendPqStateCommitment,
        ulong nextExpectedReceiveEcN,
        ulong nextSendEcN,
        ulong storageGeneration,
        int maximumMessagesWithoutPqInjection)
    {
        ArgumentNullException.ThrowIfNull(binding);
        var receiveEcChain = RatchetEcChainId.FromPublicKey(initialReceiveEcRatchetPublicKey);
        var sendEcChain = RatchetEcChainId.FromPublicKey(initialSendEcRatchetPublicKey);
        if (initialOpaqueComponentState.Length is < 1 or > MessagingCryptoConstants.MaximumOpaqueProviderStateBytes)
            throw new MessagingCryptoException(MessagingCryptoError.StateLimitExceeded, "Invalid opaque provider state size.");
        MessagingCryptoValidation.NonZeroExact(initialReceivePqStateCommitment, 32, nameof(initialReceivePqStateCommitment));
        MessagingCryptoValidation.NonZeroExact(initialSendPqStateCommitment, 32, nameof(initialSendPqStateCommitment));
        if (maximumMessagesWithoutPqInjection is < 1 or > MessagingCryptoConstants.MaximumForwardGap)
            throw new MessagingCryptoException(MessagingCryptoError.InvalidInput, "PQ injection interval must be 1..2048.");
        _ = ComputeDurableEncodedLength(initialOpaqueComponentState.Length, 0);
        SecretBuffer? component = null;
        try
        {
            component = SecretBuffer.ImportBounded(
                initialOpaqueComponentState, 1,
                MessagingCryptoConstants.MaximumOpaqueProviderStateBytes,
                nameof(initialOpaqueComponentState));
            var state = new TripleRatchetState(
                binding,
                component,
                receiveEcChain,
                nextExpectedReceiveEcN,
                sendEcChain,
                nextSendEcN,
                storageGeneration,
                0,
                0,
                default,
                default,
                initialReceivePqStateCommitment.ToArray(),
                initialSendPqStateCommitment.ToArray(),
                maximumMessagesWithoutPqInjection,
                [],
                false);
            component = null;
            return state;
        }
        finally
        {
            component?.Dispose();
        }
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static TripleRatchetState Create(
        RatchetStateBinding binding,
        ReadOnlySpan<byte> initialOpaqueComponentState,
        ReadOnlySpan<byte> initialReceivePqStateCommitment,
        ReadOnlySpan<byte> initialSendPqStateCommitment,
        ulong nextExpectedReceiveEcN,
        ulong nextSendEcN,
        ulong storageGeneration,
        int maximumMessagesWithoutPqInjection)
    {
        Span<byte> ecRatchetPublicKey = stackalloc byte[32];
        ecRatchetPublicKey.Fill(0x5D);
        return Create(
            binding,
            initialOpaqueComponentState,
            ecRatchetPublicKey,
            ecRatchetPublicKey,
            initialReceivePqStateCommitment,
            initialSendPqStateCommitment,
            nextExpectedReceiveEcN,
            nextSendEcN,
            storageGeneration,
            maximumMessagesWithoutPqInjection);
    }
#endif

    internal TripleRatchetTransitionPlan PrepareReceive(
        ITripleRatchetComponentProvider provider,
        RatchetPersistenceLease persistenceLease,
        RatchetDeduplicationLease deduplicationLease,
        RatchetCounterTuple target,
        ReadOnlySpan<byte> exactDtr2,
        ReadOnlySpan<byte> canonicalHeaderHash,
        ReadOnlySpan<byte> canonicalEnvelopeHash)
    {
        lock (_lifecycleSync)
        {
            ThrowIfUnavailable();
            ArgumentNullException.ThrowIfNull(provider);
            ArgumentNullException.ThrowIfNull(deduplicationLease);
#if !DEEP_PROTOCOL_RECOVERY_TEST_SEAM
            if (exactDtr2.IsEmpty)
                throw new MessagingCryptoException(
                    MessagingCryptoError.InvalidInput,
                    "A production receive transition requires the exact canonical DTR2 provider input.");
#endif
            MessagingCryptoValidation.NonZeroExact(canonicalHeaderHash, 32, nameof(canonicalHeaderHash));
            MessagingCryptoValidation.NonZeroExact(canonicalEnvelopeHash, 32, nameof(canonicalEnvelopeHash));
            var persistence = ValidatePersistenceForActiveTransition(persistenceLease);
            var dedup = deduplicationLease.Consume();
            ValidateDeduplicationBinding(dedup, target, canonicalHeaderHash, canonicalEnvelopeHash);
            var databaseCas = new PersistenceCasExpectation(StorageGeneration, _stateCommitment);
            var checkpointCas = new CheckpointCasExpectation(
                persistence.LatestProtectedGeneration,
                persistence.LatestProtectedCommitment);
            if (dedup.Outcome == RatchetDeduplicationOutcome.ExactReplay)
                return TripleRatchetTransitionPlan.ExactReplay(
                    dedup.OperationId, dedup.JournalPredecessor, databaseCas, checkpointCas);

            if (_skipped.TryGetValue(target, out var skipped))
                return PrepareSkippedReceive(
                    target, skipped, canonicalHeaderHash, dedup, databaseCas, checkpointCas);
        var previousSendingChainLength = 0UL;
        if (!exactDtr2.IsEmpty)
        {
            var exactHeader = Dtr2Codec.DecodeEmbedded(exactDtr2);
            var exactTarget = new RatchetCounterTuple(
                RatchetEcChainId.FromPublicKey(exactHeader.EcRatchetPublicKey.Span),
                exactHeader.EcMessageNumber,
                exactHeader.SckaSendingEpoch,
                exactHeader.SckaMessageNumber);
            if (exactTarget != target)
                throw new MessagingCryptoException(
                    MessagingCryptoError.ReplayConflict,
                    "The authenticated target differs from the exact DTR2 ratchet coordinate.");
            previousSendingChainLength = exactHeader.EcPreviousSendingChainLength;
        }
        if (target.EcN == ulong.MaxValue)
            throw new MessagingCryptoException(MessagingCryptoError.ForwardGapExceeded, "Receive counter is exhausted.");
        var changesEcChain = target.EcChain != ReceiveEcChain;
        ulong oldChainGap;
        ulong gap;
        if (!changesEcChain)
        {
            if (target.EcN < NextExpectedReceiveEcN)
                throw new MessagingCryptoException(
                    MessagingCryptoError.Replay,
                    "The ratchet coordinate was consumed or retired.");
            oldChainGap = 0;
            gap = target.EcN - NextExpectedReceiveEcN;
        }
        else
        {
            if (previousSendingChainLength < NextExpectedReceiveEcN)
                throw new MessagingCryptoException(
                    MessagingCryptoError.ReplayConflict,
                    "A successor EC chain advertises a previous-chain length behind the committed receive cursor.");
            oldChainGap = previousSendingChainLength - NextExpectedReceiveEcN;
            gap = checked(oldChainGap + target.EcN);
        }
        if (gap > MessagingCryptoConstants.MaximumForwardGap)
            throw new MessagingCryptoException(MessagingCryptoError.ForwardGapExceeded, "Forward gap exceeds 2048.");
        if ((ulong)_skipped.Count + gap > MessagingCryptoConstants.MaximumSkippedKeys)
            throw new MessagingCryptoException(MessagingCryptoError.SkippedKeyLimitExceeded, "Skipped-key limit would exceed 2048.");

        var ownedExactDtr2 = exactDtr2.ToArray();
        using var transition = _componentState!.Use(state => provider.PrepareReceive(
            state,
            new RatchetEcChainCursor(ReceiveEcChain, NextExpectedReceiveEcN),
            target,
            ownedExactDtr2,
            new PqInjectionSchedule(ReceiveMessagesSincePqInjection, _maximumMessagesWithoutPqInjection)));
        if (transition is null)
            throw new MessagingCryptoException(MessagingCryptoError.TransitionRejected, "Provider returned no transition.");
        var keys = transition.TakeMessageKeys();
        try
        {
            ValidateReceiveKeys(
                keys, target, gap, changesEcChain, previousSendingChainLength, oldChainGap);
            var pqResult = ValidatePqSequence(
                keys,
                _receivePqStateCommitment,
                ReceivePqFrontier,
                ReceiveMessagesSincePqInjection);
            var pqFence = new RatchetPqFenceMutation(
                keys.Select(static key => key.ComputePqKeyReuseCommitment()));
            var targetKey = keys[^1].Derive(Binding.SessionId.Span, canonicalHeaderHash);
            Dictionary<RatchetCounterTuple, SkippedComponentKey>? nextSkipped = null;
            SecretBuffer? nextComponent = null;
            TripleRatchetState? next = null;
            var ownershipTransferred = false;
            try
            {
                nextSkipped = CloneSkipped();
                for (var index = 0; index < keys.Count - 1; index++)
                    nextSkipped.Add(keys[index].Counters, keys[index].CloneForSkipped());
                nextComponent = transition.TakeNextState();
                next = new TripleRatchetState(
                    Binding, nextComponent,
                    target.EcChain, checked(target.EcN + 1),
                    SendEcChain, NextSendEcN,
                    checked(StorageGeneration + 1), pqResult.MessagesSinceFresh,
                    SendMessagesSincePqInjection, pqResult.Frontier, SendPqFrontier,
                    pqResult.StateCommitment, _sendPqStateCommitment.ToArray(),
                    _maximumMessagesWithoutPqInjection, nextSkipped, false);
                nextComponent = null;
                nextSkipped = null;
                MessagingCryptoFaultInjection.OwnedDisposable("ratchet.receive.next-state", next);
                MessagingCryptoFaultInjection.Point("ratchet.receive.before-dedup-plan");
                var dedupMutation = new RatchetDeduplicationMutation(
                    dedup,
                    [keys[^1].ComputeTupleCommitment(Binding.Commitment.Span)]);
                var plan = TripleRatchetTransitionPlan.Fresh(
                    RatchetPlanOutcome.Fresh, dedup.OperationId, dedup.JournalPredecessor,
                    databaseCas, checkpointCas,
                    next, targetKey, dedupMutation, pqFence,
                    [RatchetDeletionKind.MessageKeyAfterUse,
                     RatchetDeletionKind.PreviousStateAfterCommit,
                     RatchetDeletionKind.ProviderTransitionSecrets]);
                ownershipTransferred = true;
                next = null;
                return plan;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(targetKey);
                if (!ownershipTransferred) next?.Dispose();
                nextComponent?.Dispose();
                DisposeSkipped(nextSkipped);
            }
        }
        finally
        {
            foreach (var key in keys) key.Dispose();
        }
        }
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal TripleRatchetTransitionPlan PrepareReceive(
        ITripleRatchetComponentProvider provider,
        RatchetPersistenceLease persistenceLease,
        RatchetDeduplicationLease deduplicationLease,
        RatchetCounterTuple target,
        ReadOnlySpan<byte> canonicalHeaderHash,
        ReadOnlySpan<byte> canonicalEnvelopeHash) =>
        PrepareReceive(
            provider,
            persistenceLease,
            deduplicationLease,
            target,
            ReadOnlySpan<byte>.Empty,
            canonicalHeaderHash,
            canonicalEnvelopeHash);
#endif

    internal TripleRatchetTransitionPlan PrepareExactDpe2Send(
        ITripleRatchetComponentProvider provider,
        RatchetPersistenceLease persistenceLease,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> journalPredecessor) =>
        PrepareSendCore(
            provider,
            persistenceLease,
            networkId,
            operationId,
            journalPredecessor,
            ReadOnlySpan<byte>.Empty,
            requireProviderHeader: true);

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal TripleRatchetTransitionPlan PrepareSend(
        ITripleRatchetComponentProvider provider,
        RatchetPersistenceLease persistenceLease,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> journalPredecessor,
        ReadOnlySpan<byte> canonicalHeaderHash) =>
        PrepareSendCore(
            provider,
            persistenceLease,
            ReadOnlySpan<byte>.Empty,
            operationId,
            journalPredecessor,
            canonicalHeaderHash,
            requireProviderHeader: false);
#endif

    private TripleRatchetTransitionPlan PrepareSendCore(
        ITripleRatchetComponentProvider provider,
        RatchetPersistenceLease persistenceLease,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> journalPredecessor,
        ReadOnlySpan<byte> testHeaderHash,
        bool requireProviderHeader)
    {
        lock (_lifecycleSync)
        {
        ThrowIfUnavailable();
        ArgumentNullException.ThrowIfNull(provider);
        MessagingCryptoValidation.NonZeroExact(operationId, 32, nameof(operationId));
        MessagingCryptoValidation.NonZeroExact(journalPredecessor, 32, nameof(journalPredecessor));
        if (requireProviderHeader)
            MessagingCryptoValidation.NonZeroExact(networkId, 16, nameof(networkId));
        else
            MessagingCryptoValidation.NonZeroExact(testHeaderHash, 32, nameof(testHeaderHash));
        var persistence = ValidatePersistenceForActiveTransition(persistenceLease);
        var databaseCas = new PersistenceCasExpectation(StorageGeneration, _stateCommitment);
        var checkpointCas = new CheckpointCasExpectation(
            persistence.LatestProtectedGeneration,
            persistence.LatestProtectedCommitment);
        var ownedNetworkId = networkId.ToArray();
        using var transition = _componentState!.Use(state => provider.PrepareSend(
            state,
            new RatchetEcChainCursor(SendEcChain, NextSendEcN),
            ownedNetworkId,
            new PqInjectionSchedule(SendMessagesSincePqInjection, _maximumMessagesWithoutPqInjection)));
        if (transition is null)
            throw new MessagingCryptoException(MessagingCryptoError.TransitionRejected, "Provider returned no transition.");
        var keys = transition.TakeMessageKeys();
        try
        {
            if (keys.Count != 1)
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "A send transition must return exactly the next EC key.");
            var sendChangesEcChain = keys[0].Counters.EcChain != SendEcChain;
            if (sendChangesEcChain
                    ? keys[0].Counters.EcN != 0
                    : keys[0].Counters.EcN != NextSendEcN)
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "The send transition did not advance the exact current or successor EC chain.");
            if (keys[0].Counters.EcN == ulong.MaxValue)
                throw new MessagingCryptoException(
                    MessagingCryptoError.StateLimitExceeded,
                    "The provider returned an exhausted send counter.");
            byte[]? exactSendDtr2 = null;
            byte[]? canonicalHeaderHash = null;
            if (requireProviderHeader)
            {
                if (!transition.HasExactSendDtr2)
                    throw new MessagingCryptoException(
                        MessagingCryptoError.TransitionRejected,
                        "The production send provider returned no exact canonical DTR2 header.");
                exactSendDtr2 = transition.TakeExactSendDtr2();
                var header = Dtr2Codec.DecodeEmbedded(exactSendDtr2);
                var headerEcChain = RatchetEcChainId.FromPublicKey(header.EcRatchetPublicKey.Span);
                if (!MessagingCryptoValidation.FixedEquals(header.NetworkId.Span, networkId) ||
                    headerEcChain != keys[0].Counters.EcChain ||
                    header.EcMessageNumber != keys[0].Counters.EcN ||
                    header.SckaSendingEpoch != keys[0].Counters.SckaEpoch ||
                    header.SckaMessageNumber != keys[0].Counters.SckaN ||
                    sendChangesEcChain && header.EcPreviousSendingChainLength != NextSendEcN)
                    throw new MessagingCryptoException(
                        MessagingCryptoError.TransitionRejected,
                        "The provider DTR2 network or key counters differ from its ratchet transition.");
                canonicalHeaderHash = MessagingWireCryptographicInputs.ComputeDtr2HeaderHash(header);
            }
            else
            {
                if (transition.HasExactSendDtr2)
                    throw new MessagingCryptoException(
                        MessagingCryptoError.TransitionRejected,
                        "The header-less test seam cannot accept a provider-owned DTR2 header.");
                canonicalHeaderHash = testHeaderHash.ToArray();
            }
            var pqResult = ValidatePqSequence(
                keys, _sendPqStateCommitment, SendPqFrontier, SendMessagesSincePqInjection);
            var pqFence = new RatchetPqFenceMutation(
                keys.Select(static key => key.ComputePqKeyReuseCommitment()));
            var messageKey = keys[0].Derive(Binding.SessionId.Span, canonicalHeaderHash);
            Dictionary<RatchetCounterTuple, SkippedComponentKey>? nextSkipped = null;
            SecretBuffer? nextComponent = null;
            try
            {
                nextSkipped = CloneSkipped();
                nextComponent = transition.TakeNextState();
                var next = new TripleRatchetState(
                    Binding, nextComponent,
                    ReceiveEcChain, NextExpectedReceiveEcN,
                    keys[0].Counters.EcChain, checked(keys[0].Counters.EcN + 1),
                    checked(StorageGeneration + 1), ReceiveMessagesSincePqInjection,
                    pqResult.MessagesSinceFresh, ReceivePqFrontier, pqResult.Frontier,
                    _receivePqStateCommitment.ToArray(), pqResult.StateCommitment,
                    _maximumMessagesWithoutPqInjection, nextSkipped, false);
                nextComponent = null;
                nextSkipped = null;
                return TripleRatchetTransitionPlan.Fresh(
                    RatchetPlanOutcome.Fresh, operationId, journalPredecessor,
                    databaseCas, checkpointCas,
                    next, messageKey, null, pqFence,
                    [RatchetDeletionKind.MessageKeyAfterUse,
                     RatchetDeletionKind.PreviousStateAfterCommit,
                     RatchetDeletionKind.ProviderTransitionSecrets],
                    exactSendDtr2 ?? []);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(messageKey);
                if (canonicalHeaderHash is not null)
                    CryptographicOperations.ZeroMemory(canonicalHeaderHash);
                if (exactSendDtr2 is not null)
                    CryptographicOperations.ZeroMemory(exactSendDtr2);
                nextComponent?.Dispose();
                DisposeSkipped(nextSkipped);
            }
        }
        finally
        {
            foreach (var key in keys) key.Dispose();
        }
        }
    }

    internal TripleRatchetTransitionPlan PrepareRollbackLatch(
        RatchetPersistenceLease persistenceLease,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> journalPredecessor)
    {
        lock (_lifecycleSync)
        {
        ThrowIfDisposed();
        MessagingCryptoValidation.NonZeroExact(operationId, 32, nameof(operationId));
        MessagingCryptoValidation.NonZeroExact(journalPredecessor, 32, nameof(journalPredecessor));
        if (IsTerminallyLatched)
            throw new MessagingCryptoException(MessagingCryptoError.TerminallyLatched, "Session is already latched.");
        var data = persistenceLease.Consume();
        ValidateExpectedState(data);
        if (data.LatestProtectedGeneration <= StorageGeneration)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "A rollback latch requires a strictly newer protected checkpoint.");
        var databaseCas = new PersistenceCasExpectation(
            StorageGeneration,
            _stateCommitment);
        var checkpointCas = new CheckpointCasExpectation(
            data.LatestProtectedGeneration,
            data.LatestProtectedCommitment);
        var next = new TripleRatchetState(
            Binding, null,
            ReceiveEcChain, NextExpectedReceiveEcN,
            SendEcChain, NextSendEcN,
            checked(data.LatestProtectedGeneration + 1), ReceiveMessagesSincePqInjection,
            SendMessagesSincePqInjection, ReceivePqFrontier, SendPqFrontier,
            _receivePqStateCommitment.ToArray(), _sendPqStateCommitment.ToArray(),
            _maximumMessagesWithoutPqInjection, [], true);
        return TripleRatchetTransitionPlan.Fresh(
            RatchetPlanOutcome.RollbackLatched, operationId, journalPredecessor,
            databaseCas, checkpointCas,
            next, null, null, null,
            [RatchetDeletionKind.PreviousStateAfterCommit,
              RatchetDeletionKind.AllSessionSecretsAfterRollbackLatch]);
        }
    }

    public void Dispose()
    {
        lock (_lifecycleSync)
        {
            if (_disposed) return;
            _disposed = true;
            _componentState?.Dispose();
            foreach (var skipped in _skipped.Values) skipped.Dispose();
        }
    }

    private TripleRatchetTransitionPlan PrepareSkippedReceive(
        RatchetCounterTuple target,
        SkippedComponentKey skipped,
        ReadOnlySpan<byte> headerHash,
        RatchetDeduplicationData dedup,
        PersistenceCasExpectation databaseCas,
        CheckpointCasExpectation checkpointCas)
    {
        var messageKey = skipped.Derive(Binding.SessionId.Span, headerHash);
        Dictionary<RatchetCounterTuple, SkippedComponentKey>? nextSkipped = null;
        SecretBuffer? nextComponent = null;
        TripleRatchetState? next = null;
        var ownershipTransferred = false;
        try
        {
            nextSkipped = CloneSkipped(target);
            nextComponent = _componentState!.Clone();
            next = new TripleRatchetState(
                Binding, nextComponent,
                ReceiveEcChain, NextExpectedReceiveEcN,
                SendEcChain, NextSendEcN,
                checked(StorageGeneration + 1), ReceiveMessagesSincePqInjection,
                SendMessagesSincePqInjection, ReceivePqFrontier, SendPqFrontier,
                _receivePqStateCommitment.ToArray(), _sendPqStateCommitment.ToArray(),
                _maximumMessagesWithoutPqInjection, nextSkipped, false);
            nextComponent = null;
            nextSkipped = null;
            MessagingCryptoFaultInjection.OwnedDisposable("ratchet.skipped.next-state", next);
            MessagingCryptoFaultInjection.Point("ratchet.skipped.before-dedup-plan");
            var mutation = new RatchetDeduplicationMutation(
                dedup,
                [skipped.TupleCommitment(Binding.Commitment.Span)]);
            var plan = TripleRatchetTransitionPlan.Fresh(
                RatchetPlanOutcome.OutOfOrderSkippedKey,
                dedup.OperationId, dedup.JournalPredecessor,
                databaseCas, checkpointCas,
                next, messageKey, mutation, null,
                [RatchetDeletionKind.MessageKeyAfterUse,
                 RatchetDeletionKind.ConsumedSkippedKeyAfterCommit,
                 RatchetDeletionKind.PreviousStateAfterCommit]);
            ownershipTransferred = true;
            next = null;
            return plan;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageKey);
            if (!ownershipTransferred) next?.Dispose();
            nextComponent?.Dispose();
            DisposeSkipped(nextSkipped);
        }
    }

    private PqValidationResult ValidatePqSequence(
        IReadOnlyList<RatchetComponentKeyMaterial> keys,
        ReadOnlySpan<byte> initialCommitment,
        RatchetCounterTuple initialFrontier,
        int initialMessagesSinceFresh)
    {
        var expectedCommitment = initialCommitment.ToArray();
        var frontier = initialFrontier;
        var messagesSinceFresh = initialMessagesSinceFresh;
        var tuples = new HashSet<(ulong Epoch, ulong N)>();
        try
        {
            foreach (var key in keys)
            {
                if (!MessagingCryptoValidation.FixedEquals(
                        key.PqEvidence.PriorStateCommitment, expectedCommitment))
                    throw new MessagingCryptoException(
                        MessagingCryptoError.PqEvidenceRejected,
                        "PQ step predecessor does not match the sealed direction state.");
                var tuple = (key.Counters.SckaEpoch, key.Counters.SckaN);
                if (!tuples.Add(tuple) || !IsStrictlyAfter(tuple, (frontier.SckaEpoch, frontier.SckaN)))
                    throw new MessagingCryptoException(
                        MessagingCryptoError.PqEvidenceRejected,
                        "A PQ tuple was reused or moved backwards.");
                if (messagesSinceFresh >= _maximumMessagesWithoutPqInjection &&
                    !key.PqEvidence.HasFreshContribution)
                    throw new MessagingCryptoException(
                        MessagingCryptoError.PqInjectionRequired,
                        "A receive/send gap step omitted mandatory fresh PQ contribution.");
                messagesSinceFresh = key.PqEvidence.HasFreshContribution
                    ? 0
                    : checked(messagesSinceFresh + 1);
                CryptographicOperations.ZeroMemory(expectedCommitment);
                expectedCommitment = key.PqEvidence.NextStateCommitment.ToArray();
                frontier = key.Counters;
            }
            var result = new PqValidationResult(expectedCommitment, frontier, messagesSinceFresh);
            expectedCommitment = [];
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedCommitment);
        }
    }

    private void ValidateReceiveKeys(
        IReadOnlyList<RatchetComponentKeyMaterial> keys,
        RatchetCounterTuple target,
        ulong gap,
        bool changesEcChain,
        ulong previousSendingChainLength,
        ulong oldChainGap)
    {
        if ((ulong)keys.Count != gap + 1)
            throw new MessagingCryptoException(
                MessagingCryptoError.TransitionRejected,
                "Provider did not return each skipped and target step.");
        if (!changesEcChain)
        {
            for (var index = 0; index < keys.Count; index++)
            {
                if (keys[index].Counters.EcChain != ReceiveEcChain ||
                    keys[index].Counters.EcN != checked(NextExpectedReceiveEcN + (ulong)index))
                    throw new MessagingCryptoException(
                        MessagingCryptoError.TransitionRejected,
                        "Provider EC counters are not contiguous in the current receive chain.");
            }
        }
        else
        {
            for (var index = 0UL; index < oldChainGap; index++)
            {
                var key = keys[checked((int)index)].Counters;
                if (key.EcChain != ReceiveEcChain ||
                    key.EcN != checked(NextExpectedReceiveEcN + index) ||
                    key.EcN >= previousSendingChainLength)
                    throw new MessagingCryptoException(
                        MessagingCryptoError.TransitionRejected,
                        "Provider old-chain skipped keys do not match DTR2 PN.");
            }
            for (var index = oldChainGap; index < (ulong)keys.Count; index++)
            {
                var key = keys[checked((int)index)].Counters;
                if (key.EcChain != target.EcChain || key.EcN != index - oldChainGap)
                    throw new MessagingCryptoException(
                        MessagingCryptoError.TransitionRejected,
                        "Provider successor-chain keys are not contiguous from message zero.");
            }
        }
        if (keys[^1].Counters != target)
            throw new MessagingCryptoException(
                MessagingCryptoError.TransitionRejected,
                "Provider transition does not terminate at the authenticated target.");
    }

    private RatchetPersistenceData ValidatePersistenceForActiveTransition(RatchetPersistenceLease lease)
    {
        ArgumentNullException.ThrowIfNull(lease);
        var data = lease.Consume();
        ValidateExpectedState(data);
        if (data.LatestProtectedGeneration > StorageGeneration)
            throw new MessagingCryptoException(
                MessagingCryptoError.RollbackDetected,
                "A newer protected checkpoint exists; only a terminal rollback latch is allowed.");
        if (data.LatestProtectedGeneration < StorageGeneration)
            throw new MessagingCryptoException(
                MessagingCryptoError.CasConflict,
                "The persistence lease was issued from a stale protected checkpoint.");
        if (!MessagingCryptoValidation.FixedEquals(
                data.LatestProtectedCommitment,
                _stateCommitment))
            throw new MessagingCryptoException(
                MessagingCryptoError.CasConflict,
                "The protected checkpoint commitment differs from this state.");
        return data;
    }

    private void ValidateDeduplicationBinding(
        RatchetDeduplicationData dedup,
        RatchetCounterTuple target,
        ReadOnlySpan<byte> canonicalHeaderHash,
        ReadOnlySpan<byte> canonicalEnvelopeHash)
    {
        if (!MessagingCryptoValidation.FixedEquals(
                dedup.StateBindingCommitment, Binding.Commitment.Span) ||
            !MessagingCryptoValidation.FixedEquals(dedup.SessionId, Binding.SessionId.Span) ||
            dedup.Target != target ||
            !MessagingCryptoValidation.FixedEquals(dedup.ExactHeaderHash, canonicalHeaderHash) ||
            !MessagingCryptoValidation.FixedEquals(dedup.EnvelopeHash, canonicalEnvelopeHash))
            throw new MessagingCryptoException(
                MessagingCryptoError.ReplayConflict,
                "The durable deduplication lease is bound to another session, counter, header, or envelope.");
    }

    private void ValidateExpectedState(RatchetPersistenceData data)
    {
        if (data.ExpectedGeneration != StorageGeneration ||
            !MessagingCryptoValidation.FixedEquals(data.ExpectedStateCommitment, _stateCommitment))
            throw new MessagingCryptoException(
                MessagingCryptoError.CasConflict,
                "The persistence lease does not bind this exact state predecessor.");
    }

    private byte[] ComputeStateCommitment()
    {
        var component = _componentState?.Copy();
        byte[]? componentHash = null;
        try
        {
            componentHash = component is null ? new byte[32] : SHA256.HashData(component);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData(Binding.Commitment.Span);
            Span<byte> counters = stackalloc byte[213];
            BinaryPrimitives.WriteUInt64BigEndian(counters, StorageGeneration);
            ReceiveEcChain.Write(counters[8..40]);
            BinaryPrimitives.WriteUInt64BigEndian(counters[40..], NextExpectedReceiveEcN);
            SendEcChain.Write(counters[48..80]);
            BinaryPrimitives.WriteUInt64BigEndian(counters[80..], NextSendEcN);
            WriteCommitmentCounter(counters[88..144], ReceivePqFrontier);
            WriteCommitmentCounter(counters[144..200], SendPqFrontier);
            BinaryPrimitives.WriteInt32BigEndian(counters[200..], ReceiveMessagesSincePqInjection);
            BinaryPrimitives.WriteInt32BigEndian(counters[204..], SendMessagesSincePqInjection);
            BinaryPrimitives.WriteInt32BigEndian(counters[208..], _maximumMessagesWithoutPqInjection);
            counters[212] = IsTerminallyLatched ? (byte)1 : (byte)0;
            hash.AppendData(counters);
            hash.AppendData(_receivePqStateCommitment);
            hash.AppendData(_sendPqStateCommitment);
            hash.AppendData(componentHash);
            foreach (var item in _skipped.OrderBy(static item => item.Key.EcN)
                         .ThenBy(static item => item.Key.SckaEpoch)
                         .ThenBy(static item => item.Key.SckaN))
            {
                var skippedCommitment = item.Value.StateCommitment(Binding.Commitment.Span);
                hash.AppendData(skippedCommitment);
                CryptographicOperations.ZeroMemory(skippedCommitment);
            }
            return hash.GetHashAndReset();
        }
        finally
        {
            if (component is not null) CryptographicOperations.ZeroMemory(component);
            if (componentHash is not null) CryptographicOperations.ZeroMemory(componentHash);
        }
    }

    private static void WriteCommitmentCounter(Span<byte> destination, RatchetCounterTuple counters)
    {
        counters.EcChain.Write(destination[..32]);
        BinaryPrimitives.WriteUInt64BigEndian(destination[32..], counters.EcN);
        BinaryPrimitives.WriteUInt64BigEndian(destination[40..], counters.SckaEpoch);
        BinaryPrimitives.WriteUInt64BigEndian(destination[48..], counters.SckaN);
    }

    private Dictionary<RatchetCounterTuple, SkippedComponentKey> CloneSkipped(
        RatchetCounterTuple? except = null)
    {
        var copy = new Dictionary<RatchetCounterTuple, SkippedComponentKey>();
        try
        {
            foreach (var item in _skipped)
            {
                if (except.HasValue && item.Key == except.Value) continue;
                copy.Add(item.Key, item.Value.Clone());
            }
            return copy;
        }
        catch
        {
            DisposeSkipped(copy);
            throw;
        }
    }

    private static void DisposeSkipped(Dictionary<RatchetCounterTuple, SkippedComponentKey>? skipped)
    {
        if (skipped is null) return;
        foreach (var value in skipped.Values) value.Dispose();
    }

    private static bool IsStrictlyAfter((ulong Epoch, ulong N) value, (ulong Epoch, ulong N) prior) =>
        value.Epoch > prior.Epoch || value.Epoch == prior.Epoch && value.N > prior.N;

    private void ThrowIfUnavailable()
    {
        ThrowIfDisposed();
        if (IsTerminallyLatched)
            throw new MessagingCryptoException(
                MessagingCryptoError.TerminallyLatched,
                "A terminally latched session cannot produce transitions.");
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new MessagingCryptoException(MessagingCryptoError.ObjectDisposed, "Ratchet state is disposed.");
    }

    private sealed record PqValidationResult(
        byte[] StateCommitment,
        RatchetCounterTuple Frontier,
        int MessagesSinceFresh);
}

internal sealed class TripleRatchetCommit : IDisposable
{
    private TripleRatchetState? _nextState;
    private MessageKeyLease? _messageKey;

    internal TripleRatchetCommit(
        RatchetPlanOutcome outcome,
        PersistenceCasExpectation databaseCas,
        CheckpointCasExpectation checkpointCas,
        TripleRatchetState? nextState,
        MessageKeyLease? messageKey,
        RatchetDeduplicationMutation? deduplicationMutation,
        RatchetPqFenceMutation? pqFenceMutation,
        IReadOnlyList<RatchetDeletionKind> deletions)
    {
        Outcome = outcome;
        DatabaseCas = databaseCas;
        CheckpointCas = checkpointCas;
        _nextState = nextState;
        _messageKey = messageKey;
        DeduplicationMutation = deduplicationMutation;
        PqFenceMutation = pqFenceMutation;
        DeletionObligations = deletions;
    }

    internal RatchetPlanOutcome Outcome { get; }
    internal PersistenceCasExpectation DatabaseCas { get; }
    internal CheckpointCasExpectation CheckpointCas { get; }
    internal RatchetDeduplicationMutation? DeduplicationMutation { get; }
    internal RatchetPqFenceMutation? PqFenceMutation { get; }
    internal IReadOnlyList<RatchetDeletionKind> DeletionObligations { get; }
    internal bool HasNextState => _nextState is not null;
    internal bool HasMessageKey => _messageKey is not null;

    internal TripleRatchetState TakeNextState() => Interlocked.Exchange(ref _nextState, null) ??
        throw new MessagingCryptoException(MessagingCryptoError.CapabilityConsumed, "Next state is unavailable.");

    internal MessageKeyLease TakeMessageKey() => Interlocked.Exchange(ref _messageKey, null) ??
        throw new MessagingCryptoException(MessagingCryptoError.CapabilityConsumed, "Message key is unavailable.");

    public void Dispose()
    {
        Interlocked.Exchange(ref _nextState, null)?.Dispose();
        Interlocked.Exchange(ref _messageKey, null)?.Dispose();
    }
}

internal sealed class TripleRatchetTransitionPlan : IDisposable
{
    private readonly object _lifecycleSync = new();
    private readonly byte[] _operationId;
    private readonly byte[] _journalPredecessor;
    private readonly byte[] _deletionManifestCommitment;
    private readonly byte[]? _exactSendDtr2;
    private TripleRatchetState? _nextState;
    private MessageKeyLease? _messageKey;
    private int _messageKeyAuthenticationUse;
    private int _state;

    private TripleRatchetTransitionPlan(
        RatchetPlanOutcome outcome,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> journalPredecessor,
        PersistenceCasExpectation databaseCas,
        CheckpointCasExpectation checkpointCas,
        TripleRatchetState? nextState,
        MessageKeyLease? messageKey,
        RatchetDeduplicationMutation? deduplicationMutation,
        RatchetPqFenceMutation? pqFenceMutation,
        IReadOnlyList<RatchetDeletionKind> deletions,
        ReadOnlySpan<byte> exactSendDtr2)
    {
        Outcome = outcome;
        MessagingCryptoValidation.NonZeroExact(operationId, 32, nameof(operationId));
        MessagingCryptoValidation.NonZeroExact(journalPredecessor, 32, nameof(journalPredecessor));
        _operationId = operationId.ToArray();
        _journalPredecessor = journalPredecessor.ToArray();
        DatabaseCas = databaseCas;
        CheckpointCas = checkpointCas;
        _nextState = nextState;
        _messageKey = messageKey;
        DeduplicationMutation = deduplicationMutation;
        PqFenceMutation = pqFenceMutation;
        DeletionObligations = deletions;
        _exactSendDtr2 = exactSendDtr2.IsEmpty ? null : exactSendDtr2.ToArray();
        MessagingCryptoFaultInjection.Point("ratchet.plan.after-owner-assignment");
        _deletionManifestCommitment = ComputeDeletionManifest(deletions);
    }

    internal RatchetPlanOutcome Outcome { get; }
    internal PersistenceCasExpectation DatabaseCas { get; }
    internal CheckpointCasExpectation CheckpointCas { get; }
    internal RatchetDeduplicationMutation? DeduplicationMutation { get; }
    internal RatchetPqFenceMutation? PqFenceMutation { get; }
    internal IReadOnlyList<RatchetDeletionKind> DeletionObligations { get; }
    internal ReadOnlyMemory<byte> OperationId => _operationId.ToArray();
    internal ReadOnlyMemory<byte> JournalPredecessor => _journalPredecessor.ToArray();
    internal ReadOnlyMemory<byte> DeletionManifestCommitment => _deletionManifestCommitment.ToArray();
    internal ReadOnlyMemory<byte> DeduplicationMutationCommitment =>
        DeduplicationMutation?.Commitment ?? ReadOnlyMemory<byte>.Empty;
    internal ReadOnlyMemory<byte> PqFenceMutationCommitment =>
        PqFenceMutation?.Commitment ?? ReadOnlyMemory<byte>.Empty;
    internal ReadOnlyMemory<byte> TerminalStateCommitment =>
        Outcome == RatchetPlanOutcome.RollbackLatched
            ? ProposedStateCommitment
            : ReadOnlyMemory<byte>.Empty;
    internal ulong? ProposedGeneration => _nextState?.StorageGeneration;
    internal ReadOnlyMemory<byte> ProposedStateCommitment =>
        _nextState?.StateCommitment ?? ReadOnlyMemory<byte>.Empty;
    internal ReadOnlyMemory<byte> ExactSendDtr2 =>
        _exactSendDtr2?.ToArray() ?? ReadOnlyMemory<byte>.Empty;

    internal bool MessageKeyDeletedAfterEnvelopeCrypto =>
        Volatile.Read(ref _messageKeyAuthenticationUse) == 1 && _messageKey is null;

    internal byte[] ExportProposedDurableState()
    {
        lock (_lifecycleSync)
        {
            if (_state != 0 || _nextState is null || Outcome == RatchetPlanOutcome.ExactReplay)
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "No sealed successor state is available for durable persistence.");
            return TripleRatchetDurableStateCodec.Encode(_nextState);
        }
    }

    internal static TripleRatchetTransitionPlan Fresh(
        RatchetPlanOutcome outcome,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> journalPredecessor,
        PersistenceCasExpectation databaseCas,
        CheckpointCasExpectation checkpointCas,
        TripleRatchetState nextState,
        ReadOnlySpan<byte> messageKey,
        RatchetDeduplicationMutation? deduplicationMutation,
        RatchetPqFenceMutation? pqFenceMutation,
        IReadOnlyList<RatchetDeletionKind> deletions,
        ReadOnlySpan<byte> exactSendDtr2 = default)
    {
        MessageKeyLease? ownedMessageKey = null;
        var ownershipTransferred = false;
        try
        {
            ownedMessageKey = messageKey.IsEmpty ? null : new MessageKeyLease(messageKey);
            if (ownedMessageKey is not null)
                MessagingCryptoFaultInjection.OwnedDisposable(
                    "ratchet.plan.message-key", ownedMessageKey);
            MessagingCryptoFaultInjection.OwnedDisposable(
                "ratchet.plan.next-state", nextState);
            var plan = new TripleRatchetTransitionPlan(
                outcome, operationId, journalPredecessor, databaseCas, checkpointCas, nextState,
                ownedMessageKey,
                deduplicationMutation, pqFenceMutation, deletions, exactSendDtr2);
            ownershipTransferred = true;
            ownedMessageKey = null;
            return plan;
        }
        finally
        {
            if (!ownershipTransferred)
            {
                ownedMessageKey?.Dispose();
                nextState.Dispose();
            }
        }
    }

    internal static TripleRatchetTransitionPlan ExactReplay(
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> journalPredecessor,
        PersistenceCasExpectation databaseCas,
        CheckpointCasExpectation checkpointCas) =>
        new(RatchetPlanOutcome.ExactReplay, operationId, journalPredecessor,
            databaseCas, checkpointCas, null, null, null, null, [], []);

    internal TResult UseMessageKeyForEnvelopeCrypto<TResult>(MessagingSecretFunc<TResult> cryptographicOperation)
    {
        ArgumentNullException.ThrowIfNull(cryptographicOperation);
        lock (_lifecycleSync)
        {
            if (_state != 0)
                throw new MessagingCryptoException(
                    MessagingCryptoError.CapabilityConsumed,
                    "The ratchet transition plan is no longer available for envelope cryptography.");
            var key = _messageKey ?? throw new MessagingCryptoException(
                MessagingCryptoError.TransitionRejected,
                "This ratchet transition has no message key for envelope cryptography.");
            if (Interlocked.CompareExchange(ref _messageKeyAuthenticationUse, 1, 0) != 0)
                throw new MessagingCryptoException(
                    MessagingCryptoError.CapabilityConsumed,
                    "The ratchet message key was already used for envelope cryptography.");
            return key.Use(cryptographicOperation);
        }
    }

    internal void DeleteMessageKeyAfterEnvelopeCrypto()
    {
        lock (_lifecycleSync)
        {
            if (_state != 0 || Volatile.Read(ref _messageKeyAuthenticationUse) != 1)
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "The ratchet message key cannot be deleted before its single envelope operation.");
            Interlocked.Exchange(ref _messageKey, null)?.Dispose();
        }
    }

    internal TripleRatchetCommit Commit(DurableRatchetTransactionSuccessCapability durableTransactionSuccess)
    {
        ArgumentNullException.ThrowIfNull(durableTransactionSuccess);
        lock (_lifecycleSync)
        {
            if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
                throw new MessagingCryptoException(
                    MessagingCryptoError.CapabilityConsumed,
                    "The ratchet transition plan is single-consumer.");
            var next = Interlocked.Exchange(ref _nextState, null);
            var key = Interlocked.Exchange(ref _messageKey, null);
            try
            {
                if (Outcome == RatchetPlanOutcome.ExactReplay || next is null)
                    throw new MessagingCryptoException(
                        MessagingCryptoError.TransitionRejected,
                        "An exact replay has no durable ratchet state transition.");
                var terminalCommitment = Outcome == RatchetPlanOutcome.RollbackLatched
                    ? next.StateCommitment
                    : ReadOnlyMemory<byte>.Empty;
                durableTransactionSuccess.ConsumeAndVerify(
                    _operationId,
                    _journalPredecessor,
                    DatabaseCas,
                    CheckpointCas,
                    next.StorageGeneration,
                    next.StateCommitment.Span,
                    terminalCommitment.Span,
                    _deletionManifestCommitment,
                    DeduplicationMutationCommitment.Span,
                    PqFenceMutationCommitment.Span);
                var commit = new TripleRatchetCommit(
                    Outcome, DatabaseCas, CheckpointCas, next, key,
                    DeduplicationMutation, PqFenceMutation, DeletionObligations);
                next = null;
                key = null;
                return commit;
            }
            finally
            {
                next?.Dispose();
                key?.Dispose();
            }
        }
    }

    internal TripleRatchetCommit ConsumeExactReplay()
    {
        lock (_lifecycleSync)
        {
            if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
                throw new MessagingCryptoException(
                    MessagingCryptoError.CapabilityConsumed,
                    "The ratchet transition plan is single-consumer.");
            if (Outcome != RatchetPlanOutcome.ExactReplay || _nextState is not null || _messageKey is not null)
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "Only an exact replay can bypass a durable state transition.");
            return new TripleRatchetCommit(
                Outcome, DatabaseCas, CheckpointCas, null, null, null, null, DeletionObligations);
        }
    }

    public void Dispose()
    {
        lock (_lifecycleSync)
        {
            if (Interlocked.Exchange(ref _state, 2) != 0) return;
            Interlocked.Exchange(ref _nextState, null)?.Dispose();
            Interlocked.Exchange(ref _messageKey, null)?.Dispose();
            if (_exactSendDtr2 is not null) CryptographicOperations.ZeroMemory(_exactSendDtr2);
        }
    }

    private static byte[] ComputeDeletionManifest(IReadOnlyList<RatchetDeletionKind> deletions)
    {
        ArgumentNullException.ThrowIfNull(deletions);
        var values = deletions.Select(static value => checked((byte)value)).ToArray();
        if (values.Distinct().Count() != values.Length)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The deletion manifest cannot contain duplicate obligations.");
        var input = new byte[4 + values.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, checked((uint)values.Length));
        values.CopyTo(input, 4);
        try
        {
            return MessagingKdf.Sha256Domain("Deep/Messaging/V2/deletion-manifest", input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }
}

internal enum CanonicalSessionSelection { First, Second, Same }
internal static class SimultaneousInitiationConvergence
{
    internal static CanonicalSessionSelection SelectCanonical(
        ReadOnlySpan<byte> firstAuthenticatedSessionId,
        ReadOnlySpan<byte> secondAuthenticatedSessionId)
    {
        MessagingCryptoValidation.NonZeroExact(firstAuthenticatedSessionId, 32, nameof(firstAuthenticatedSessionId));
        MessagingCryptoValidation.NonZeroExact(secondAuthenticatedSessionId, 32, nameof(secondAuthenticatedSessionId));
        for (var index = 0; index < 32; index++)
        {
            if (firstAuthenticatedSessionId[index] < secondAuthenticatedSessionId[index]) return CanonicalSessionSelection.First;
            if (firstAuthenticatedSessionId[index] > secondAuthenticatedSessionId[index]) return CanonicalSessionSelection.Second;
        }
        return CanonicalSessionSelection.Same;
    }
}
