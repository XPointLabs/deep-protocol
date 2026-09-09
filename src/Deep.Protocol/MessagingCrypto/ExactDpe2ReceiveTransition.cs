using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.MessagingCrypto;

internal sealed class ExactDpe2ReceiveBinding
{
    private readonly byte[] _operationId;
    private readonly byte[] _headerHash;
    private readonly byte[] _envelopeHash;
    private readonly byte[] _nonce;
    private readonly byte[] _associatedData;
    private readonly byte[] _ciphertext;
    private readonly byte[] _exactDtr2;

    private ExactDpe2ReceiveBinding(Dpe2Record record, RatchetStateBinding stateBinding)
    {
        stateBinding.RequireIncomingEnvelope(
            record.SessionId.Span,
            record.SenderDeviceId.Span,
            record.RecipientDeviceId.Span);
        Record = record;
        Target = new RatchetCounterTuple(
            RatchetEcChainId.FromPublicKey(record.RatchetHeader.EcRatchetPublicKey.Span),
            record.RatchetHeader.EcMessageNumber,
            record.RatchetHeader.SckaSendingEpoch,
            record.RatchetHeader.SckaMessageNumber);
        _operationId = record.OperationId.ToArray();
        _headerHash = MessagingWireCryptographicInputs.ComputeDpe2HeaderHash(record);
        _envelopeHash = MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(record);
        _nonce = MessagingWireCryptographicInputs.DeriveDpe2Nonce(record);
        _associatedData = MessagingWireCryptographicInputs.GetDpe2AeadAssociatedData(record);
        _exactDtr2 = Dtr2Codec.EncodeEmbedded(record.RatchetHeader);
        _ciphertext = new byte[record.Ciphertext.Length];
        record.Ciphertext.CopyCiphertextTo(_ciphertext);
    }

    internal Dpe2Record Record { get; }
    internal RatchetCounterTuple Target { get; }
    internal ReadOnlySpan<byte> HeaderHash => _headerHash;
    internal ReadOnlySpan<byte> EnvelopeHash => _envelopeHash;
    internal ReadOnlySpan<byte> ExactDtr2 => _exactDtr2;

    internal static ExactDpe2ReceiveBinding Decode(
        ReadOnlySpan<byte> exactDpe2,
        RatchetStateBinding stateBinding)
    {
        ArgumentNullException.ThrowIfNull(stateBinding);
        var record = Dpe2Codec.Decode(exactDpe2);
        var canonical = Dpe2Codec.Encode(record);
        if (!canonical.AsSpan().SequenceEqual(exactDpe2))
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The DPE2 envelope is not the exact canonical encoding.");
        return new ExactDpe2ReceiveBinding(record, stateBinding);
    }

    internal RatchetDeduplicationLease CreateDeduplicationLease(
        RatchetDeduplicationOutcome outcome,
        RatchetStateBinding stateBinding,
        ulong journalGeneration,
        ReadOnlySpan<byte> journalPredecessor,
        ReadOnlySpan<byte> retentionCommitment) =>
        RatchetDeduplicationLease.CreateForExactEnvelope(
            outcome,
            stateBinding.Commitment.Span,
            Record.SessionId.Span,
            Target,
            _operationId,
            _headerHash,
            _envelopeHash,
            journalGeneration,
            journalPredecessor,
            retentionCommitment);

    internal byte[] AuthenticateAndValidate(ReadOnlySpan<byte> key)
    {
        byte[]? keyCopy = null;
        byte[]? paddedPlaintext = null;
        byte[]? exactDmc2 = null;
        try
        {
            keyCopy = key.ToArray();
            try
            {
                paddedPlaintext = SecretAeadXChaCha20Poly1305.Decrypt(
                    _ciphertext,
                    _nonce,
                    keyCopy,
                    _associatedData);
            }
            catch (CryptographicException exception)
            {
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "DPE2 envelope authentication failed.",
                    exception);
            }

            var dmc2Length = ExactDpe2Padding.ValidateAndGetDmc2Length(paddedPlaintext);
            exactDmc2 = paddedPlaintext.AsSpan(0, dmc2Length).ToArray();
            ParsedDmc2 parsed;
            try
            {
                parsed = ApplicationCoreCodec.DecodeDmc2(exactDmc2);
            }
            catch (ApplicationCoreFormatException exception)
            {
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "The authenticated DPE2 plaintext is not one canonical DMC2 record.",
                    exception);
            }

            if (!MessagingCryptoValidation.FixedEquals(parsed.NetworkId.Span, Record.NetworkId.Span) ||
                !MessagingCryptoValidation.FixedEquals(parsed.SenderDeviceId.Span, Record.SenderDeviceId.Span))
                throw new MessagingCryptoException(
                    MessagingCryptoError.ReplayConflict,
                    "The authenticated DMC2 network or sender device differs from the exact DPE2 envelope.");
            var authenticated = exactDmc2;
            exactDmc2 = null;
            return authenticated;
        }
        finally
        {
            if (keyCopy is not null) CryptographicOperations.ZeroMemory(keyCopy);
            if (paddedPlaintext is not null) CryptographicOperations.ZeroMemory(paddedPlaintext);
            if (exactDmc2 is not null) CryptographicOperations.ZeroMemory(exactDmc2);
        }
    }

}

internal sealed class ExactDpe2ReceiveCommit : IDisposable
{
    private TripleRatchetState? _nextState;
    private byte[]? _exactDmc2;

    internal ExactDpe2ReceiveCommit(
        RatchetPlanOutcome outcome,
        TripleRatchetState? nextState,
        byte[]? exactDmc2)
    {
        Outcome = outcome;
        _nextState = nextState;
        _exactDmc2 = exactDmc2;
    }

    internal RatchetPlanOutcome Outcome { get; }
    internal bool HasMessage => _exactDmc2 is not null;
    internal bool HasNextState => _nextState is not null;

    internal ParsedDmc2 TakeAuthenticatedMessage()
    {
        var exactDmc2 = TakeAuthenticatedDmc2();
        try
        {
            return ApplicationCoreCodec.DecodeDmc2(exactDmc2);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactDmc2);
        }
    }

    internal byte[] TakeAuthenticatedDmc2() =>
        Interlocked.Exchange(ref _exactDmc2, null) ?? throw new MessagingCryptoException(
            MessagingCryptoError.CapabilityConsumed,
            "No committed authenticated DPE2 message is available.");

    internal TripleRatchetState TakeNextState() =>
        Interlocked.Exchange(ref _nextState, null) ?? throw new MessagingCryptoException(
            MessagingCryptoError.CapabilityConsumed,
            "No committed next ratchet state is available.");

    public void Dispose()
    {
        Interlocked.Exchange(ref _nextState, null)?.Dispose();
        var exactDmc2 = Interlocked.Exchange(ref _exactDmc2, null);
        if (exactDmc2 is not null) CryptographicOperations.ZeroMemory(exactDmc2);
    }
}

internal sealed class ExactDpe2ReceiveTransitionPlan : IDisposable
{
    private readonly object _lifecycleSync = new();
    private readonly TripleRatchetTransitionPlan _ratchetPlan;
    private readonly byte[] _exactEnvelope;
    private readonly byte[] _exactHeaderHash;
    private readonly byte[] _exactEnvelopeHash;
    private byte[]? _authenticatedMessage;
    private int _consumed;

    private ExactDpe2ReceiveTransitionPlan(
        TripleRatchetTransitionPlan ratchetPlan,
        ReadOnlySpan<byte> exactEnvelope,
        ReadOnlySpan<byte> exactHeaderHash,
        ReadOnlySpan<byte> exactEnvelopeHash,
        byte[]? authenticatedMessage)
    {
        _ratchetPlan = ratchetPlan;
        _exactEnvelope = exactEnvelope.ToArray();
        _exactHeaderHash = exactHeaderHash.ToArray();
        _exactEnvelopeHash = exactEnvelopeHash.ToArray();
        _authenticatedMessage = authenticatedMessage;
    }

    internal RatchetPlanOutcome Outcome => _ratchetPlan.Outcome;
    internal bool HasAuthenticatedMessagePendingCommit => _authenticatedMessage is not null;
    internal ReadOnlyMemory<byte> OperationId => _ratchetPlan.OperationId;
    internal ReadOnlyMemory<byte> ExactHeaderHash => _exactHeaderHash.ToArray();
    internal ReadOnlyMemory<byte> ExactEnvelopeHash => _exactEnvelopeHash.ToArray();
    internal ReadOnlyMemory<byte> JournalPredecessor => _ratchetPlan.JournalPredecessor;
    internal ReadOnlyMemory<byte> ProposedStateCommitment => _ratchetPlan.ProposedStateCommitment;
    internal ReadOnlyMemory<byte> DeletionManifestCommitment => _ratchetPlan.DeletionManifestCommitment;
    internal ReadOnlyMemory<byte> DeduplicationMutationCommitment => _ratchetPlan.DeduplicationMutationCommitment;
    internal ReadOnlyMemory<byte> PqFenceMutationCommitment => _ratchetPlan.PqFenceMutationCommitment;
    internal ReadOnlyMemory<byte> TerminalStateCommitment => _ratchetPlan.TerminalStateCommitment;
    internal ulong? ProposedGeneration => _ratchetPlan.ProposedGeneration;
    internal PersistenceCasExpectation DatabaseCas => _ratchetPlan.DatabaseCas;
    internal CheckpointCasExpectation CheckpointCas => _ratchetPlan.CheckpointCas;
    internal IReadOnlyList<RatchetDeletionKind> DeletionObligations => _ratchetPlan.DeletionObligations;
    internal bool MessageKeyDeletedAfterEnvelopeCrypto => _ratchetPlan.MessageKeyDeletedAfterEnvelopeCrypto;

    internal byte[] CopyExactEnvelopeForPersistence() => _exactEnvelope.ToArray();
    internal byte[] ExportProposedDurableState() => _ratchetPlan.ExportProposedDurableState();

    internal static ExactDpe2ReceiveTransitionPlan Prepare(
        ReadOnlySpan<byte> exactDpe2,
        TripleRatchetState state,
        ITripleRatchetComponentProvider provider,
        RatchetPersistenceLease persistenceLease,
        RatchetDeduplicationOutcome deduplicationOutcome,
        ulong journalGeneration,
        ReadOnlySpan<byte> journalPredecessor,
        ReadOnlySpan<byte> retentionCommitment)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(persistenceLease);
        var binding = ExactDpe2ReceiveBinding.Decode(exactDpe2, state.Binding);
        var deduplicationLease = binding.CreateDeduplicationLease(
            deduplicationOutcome,
            state.Binding,
            journalGeneration,
            journalPredecessor,
            retentionCommitment);
        TripleRatchetTransitionPlan? ratchetPlan = null;
        byte[]? authenticatedMessage = null;
        try
        {
            ratchetPlan = state.PrepareReceive(
                provider,
                persistenceLease,
                deduplicationLease,
                binding.Target,
                binding.ExactDtr2,
                binding.HeaderHash,
                binding.EnvelopeHash);
            if (ratchetPlan.Outcome == RatchetPlanOutcome.ExactReplay)
            {
                var replay = new ExactDpe2ReceiveTransitionPlan(
                    ratchetPlan,
                    exactDpe2,
                    binding.HeaderHash,
                    binding.EnvelopeHash,
                    null);
                ratchetPlan = null;
                return replay;
            }

            authenticatedMessage = ratchetPlan.UseMessageKeyForEnvelopeCrypto(key =>
                binding.AuthenticateAndValidate(key));
            ratchetPlan.DeleteMessageKeyAfterEnvelopeCrypto();
            var plan = new ExactDpe2ReceiveTransitionPlan(
                ratchetPlan,
                exactDpe2,
                binding.HeaderHash,
                binding.EnvelopeHash,
                authenticatedMessage);
            ratchetPlan = null;
            authenticatedMessage = null;
            return plan;
        }
        finally
        {
            ratchetPlan?.Dispose();
            if (authenticatedMessage is not null)
                CryptographicOperations.ZeroMemory(authenticatedMessage);
        }
    }

    internal ExactDpe2ReceiveCommit Commit(
        DurableRatchetTransactionSuccessCapability durableTransactionSuccess)
    {
        ArgumentNullException.ThrowIfNull(durableTransactionSuccess);
        lock (_lifecycleSync)
        {
            if (_authenticatedMessage is null || Outcome == RatchetPlanOutcome.ExactReplay)
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "Only a freshly authenticated DPE2 transition can commit durable state.");
            if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
                throw new MessagingCryptoException(
                    MessagingCryptoError.CapabilityConsumed,
                    "The exact DPE2 receive transition is single-consumer.");
            byte[]? message = Interlocked.Exchange(ref _authenticatedMessage, null);
            TripleRatchetState? nextState = null;
            try
            {
                using var ratchetCommit = _ratchetPlan.Commit(durableTransactionSuccess);
                nextState = ratchetCommit.TakeNextState();
                var commit = new ExactDpe2ReceiveCommit(Outcome, nextState, message);
                nextState = null;
                message = null;
                return commit;
            }
            finally
            {
                nextState?.Dispose();
                if (message is not null) CryptographicOperations.ZeroMemory(message);
            }
        }
    }

    internal ExactDpe2ReceiveCommit ConsumeExactReplay()
    {
        lock (_lifecycleSync)
        {
            if (Outcome != RatchetPlanOutcome.ExactReplay || _authenticatedMessage is not null)
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "Only an exact DPE2 replay can bypass authentication and durable state advancement.");
            if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
                throw new MessagingCryptoException(
                    MessagingCryptoError.CapabilityConsumed,
                    "The exact DPE2 receive transition is single-consumer.");
            using var replay = _ratchetPlan.ConsumeExactReplay();
            return new ExactDpe2ReceiveCommit(RatchetPlanOutcome.ExactReplay, null, null);
        }
    }

    public void Dispose()
    {
        lock (_lifecycleSync)
        {
            if (Interlocked.Exchange(ref _consumed, 2) == 2) return;
            var message = Interlocked.Exchange(ref _authenticatedMessage, null);
            if (message is not null) CryptographicOperations.ZeroMemory(message);
            _ratchetPlan.Dispose();
        }
    }
}
