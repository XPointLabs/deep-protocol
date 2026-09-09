using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.MessagingCrypto;

internal sealed class DurableExactDpe2SendSuccessCapability
{
    private readonly DurableRatchetTransactionSuccessCapability _ratchetSuccess;
    private readonly byte[] _operationId;
    private readonly byte[] _exactEnvelopeHash;
    private int _consumed;

    private DurableExactDpe2SendSuccessCapability(
        DurableRatchetTransactionSuccessCapability ratchetSuccess,
        byte[] operationId,
        byte[] exactEnvelopeHash)
    {
        _ratchetSuccess = ratchetSuccess;
        _operationId = operationId;
        _exactEnvelopeHash = exactEnvelopeHash;
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static DurableExactDpe2SendSuccessCapability CreateDarkForTests(
        DurableRatchetTransactionSuccessCapability ratchetSuccess,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactEnvelopeHash,
        bool exactEnvelopeAndRatchetCommittedAtomically)
    {
        ArgumentNullException.ThrowIfNull(ratchetSuccess);
        MessagingCryptoValidation.NonZeroExact(operationId, 32, nameof(operationId));
        MessagingCryptoValidation.NonZeroExact(exactEnvelopeHash, 32, nameof(exactEnvelopeHash));
        if (!exactEnvelopeAndRatchetCommittedAtomically)
            throw new MessagingCryptoException(
                MessagingCryptoError.CasConflict,
                "The exact DPE2 outbox row and ratchet transition were not committed atomically.");
        return new DurableExactDpe2SendSuccessCapability(
            ratchetSuccess,
            operationId.ToArray(),
            exactEnvelopeHash.ToArray());
    }
#endif

    internal static DurableExactDpe2SendSuccessCapability CreateFromProductionAuthority(
        DurableRatchetTransactionSuccessCapability ratchetSuccess,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactEnvelopeHash)
    {
        ArgumentNullException.ThrowIfNull(ratchetSuccess);
        MessagingCryptoValidation.NonZeroExact(operationId, 32, nameof(operationId));
        MessagingCryptoValidation.NonZeroExact(exactEnvelopeHash, 32, nameof(exactEnvelopeHash));
        return new DurableExactDpe2SendSuccessCapability(
            ratchetSuccess,
            operationId.ToArray(),
            exactEnvelopeHash.ToArray());
    }

    internal DurableRatchetTransactionSuccessCapability ConsumeAndVerify(
        ReadOnlySpan<byte> expectedOperationId,
        ReadOnlySpan<byte> expectedExactEnvelopeHash)
    {
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.CapabilityConsumed,
                "The durable exact DPE2 send capability is single-use.");
        if (!MessagingCryptoValidation.FixedEquals(_operationId, expectedOperationId) ||
            !MessagingCryptoValidation.FixedEquals(_exactEnvelopeHash, expectedExactEnvelopeHash))
            throw new MessagingCryptoException(
                MessagingCryptoError.CasConflict,
                "The durable send receipt does not bind this exact DPE2 envelope.");
        return _ratchetSuccess;
    }
}

internal static class ExactDpe2Padding
{
    internal static int SelectSmallestBucket(int dmc2Length)
    {
        if (dmc2Length is < 282 or > 33082)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The canonical DMC2 length is outside the frozen envelope bounds.");
        return checked(dmc2Length + 4) switch
        {
            <= 4096 => 4096,
            <= 16384 => 16384,
            <= 32768 => 32768,
            <= 49136 => 49136,
            _ => throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The canonical DMC2 does not fit a frozen padding bucket."),
        };
    }

    internal static byte[] Create(ReadOnlySpan<byte> exactDmc2)
    {
        var bucket = SelectSmallestBucket(exactDmc2.Length);
        var padded = new byte[bucket];
        RandomNumberGenerator.Fill(padded);
        exactDmc2.CopyTo(padded);
        BinaryPrimitives.WriteUInt32BigEndian(
            padded.AsSpan(bucket - 4),
            checked((uint)exactDmc2.Length));
        return padded;
    }

    internal static int ValidateAndGetDmc2Length(ReadOnlySpan<byte> paddedPlaintext)
    {
        if (paddedPlaintext.Length is not (4096 or 16384 or 32768 or 49136))
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The authenticated DPE2 plaintext does not use a frozen padding bucket.");
        var dmc2Length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(paddedPlaintext[^4..]));
        if (dmc2Length > paddedPlaintext.Length - 4 ||
            SelectSmallestBucket(dmc2Length) != paddedPlaintext.Length)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The authenticated DPE2 plaintext has an invalid length trailer or padding bucket.");
        return dmc2Length;
    }
}

internal sealed class ExactDpe2SendCommit : IDisposable
{
    private TripleRatchetState? _nextState;
    private byte[]? _exactEnvelope;

    internal ExactDpe2SendCommit(TripleRatchetState nextState, byte[] exactEnvelope)
    {
        _nextState = nextState;
        _exactEnvelope = exactEnvelope;
    }

    internal bool HasNextState => _nextState is not null;
    internal bool HasExactEnvelope => _exactEnvelope is not null;

    internal TripleRatchetState TakeNextState() =>
        Interlocked.Exchange(ref _nextState, null) ?? throw new MessagingCryptoException(
            MessagingCryptoError.CapabilityConsumed,
            "No committed next send state is available.");

    internal byte[] TakeExactEnvelope() =>
        Interlocked.Exchange(ref _exactEnvelope, null) ?? throw new MessagingCryptoException(
            MessagingCryptoError.CapabilityConsumed,
            "No committed exact DPE2 envelope is available.");

    public void Dispose()
    {
        Interlocked.Exchange(ref _nextState, null)?.Dispose();
        var envelope = Interlocked.Exchange(ref _exactEnvelope, null);
        if (envelope is not null) CryptographicOperations.ZeroMemory(envelope);
    }
}

internal sealed class ExactDpe2SendTransitionPlan : IDisposable
{
    private readonly object _lifecycleSync = new();
    private readonly TripleRatchetTransitionPlan _ratchetPlan;
    private readonly byte[] _operationId;
    private readonly byte[] _exactHeaderHash;
    private readonly byte[] _exactEnvelopeHash;
    private byte[]? _exactEnvelope;
    private int _consumed;

    private ExactDpe2SendTransitionPlan(
        TripleRatchetTransitionPlan ratchetPlan,
        ReadOnlySpan<byte> operationId,
        byte[] exactEnvelope,
        byte[] exactHeaderHash,
        byte[] exactEnvelopeHash)
    {
        _ratchetPlan = ratchetPlan;
        _operationId = operationId.ToArray();
        _exactEnvelope = exactEnvelope;
        _exactHeaderHash = exactHeaderHash;
        _exactEnvelopeHash = exactEnvelopeHash;
    }

    internal ReadOnlyMemory<byte> OperationId => _operationId.ToArray();
    internal ReadOnlyMemory<byte> ExactHeaderHash => _exactHeaderHash.ToArray();
    internal ReadOnlyMemory<byte> ExactEnvelopeHash => _exactEnvelopeHash.ToArray();
    internal ReadOnlyMemory<byte> JournalPredecessor => _ratchetPlan.JournalPredecessor;
    internal ReadOnlyMemory<byte> ProposedStateCommitment => _ratchetPlan.ProposedStateCommitment;
    internal ReadOnlyMemory<byte> DeletionManifestCommitment => _ratchetPlan.DeletionManifestCommitment;
    internal ReadOnlyMemory<byte> PqFenceMutationCommitment => _ratchetPlan.PqFenceMutationCommitment;
    internal ReadOnlyMemory<byte> TerminalStateCommitment => _ratchetPlan.TerminalStateCommitment;
    internal ulong? ProposedGeneration => _ratchetPlan.ProposedGeneration;
    internal PersistenceCasExpectation DatabaseCas => _ratchetPlan.DatabaseCas;
    internal CheckpointCasExpectation CheckpointCas => _ratchetPlan.CheckpointCas;
    internal IReadOnlyList<RatchetDeletionKind> DeletionObligations => _ratchetPlan.DeletionObligations;
    internal bool MessageKeyDeletedAfterEnvelopeCrypto => _ratchetPlan.MessageKeyDeletedAfterEnvelopeCrypto;

    internal byte[] CopyExactEnvelopeForPersistence()
    {
        lock (_lifecycleSync)
        {
            if (_consumed != 0 || _exactEnvelope is null)
                throw new MessagingCryptoException(
                    MessagingCryptoError.CapabilityConsumed,
                    "The sealed exact DPE2 envelope is unavailable for persistence.");
            return _exactEnvelope.ToArray();
        }
    }

    internal byte[] ExportProposedDurableState() => _ratchetPlan.ExportProposedDurableState();

    internal static ExactDpe2SendTransitionPlan Prepare(
        ReadOnlySpan<byte> exactDmc2,
        ReadOnlySpan<byte> expectedNetworkId,
        TripleRatchetState state,
        ITripleRatchetComponentProvider provider,
        RatchetPersistenceLease persistenceLease,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> journalPredecessor)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(persistenceLease);
        MessagingCryptoValidation.NonZeroExact(expectedNetworkId, 16, nameof(expectedNetworkId));
        MessagingCryptoValidation.NonZeroExact(operationId, 32, nameof(operationId));
        MessagingCryptoValidation.NonZeroExact(journalPredecessor, 32, nameof(journalPredecessor));

        ParsedDmc2 parsed;
        try
        {
            parsed = ApplicationCoreCodec.DecodeDmc2(exactDmc2);
        }
        catch (ApplicationCoreFormatException exception)
        {
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The send plaintext is not one exact canonical DMC2 record.",
                exception);
        }
        if (!parsed.CanonicalBytes.Span.SequenceEqual(exactDmc2) ||
            !MessagingCryptoValidation.FixedEquals(parsed.NetworkId.Span, expectedNetworkId) ||
            !MessagingCryptoValidation.FixedEquals(parsed.SenderDeviceId.Span, state.Binding.LocalDeviceId.Span))
            throw new MessagingCryptoException(
                MessagingCryptoError.ReplayConflict,
                "The DMC2 network or sender device differs from the committed send state.");

        TripleRatchetTransitionPlan? ratchetPlan = null;
        byte[]? padded = null;
        byte[]? ciphertext = null;
        byte[]? exactEnvelope = null;
        byte[]? headerHash = null;
        byte[]? envelopeHash = null;
        try
        {
            ratchetPlan = state.PrepareExactDpe2Send(
                provider,
                persistenceLease,
                expectedNetworkId,
                operationId,
                journalPredecessor);
            var exactDtr2 = ratchetPlan.ExactSendDtr2.ToArray();
            if (exactDtr2.Length == 0)
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "The exact send transition has no canonical DTR2 header.");
            var dtr2 = Dtr2Codec.DecodeEmbedded(exactDtr2);
            var sessionId = state.Binding.SessionId;
            var senderDeviceId = state.Binding.LocalDeviceId;
            var recipientDeviceId = state.Binding.RemoteDeviceId;
            state.Binding.RequireOutgoingEnvelope(
                sessionId.Span,
                senderDeviceId.Span,
                recipientDeviceId.Span);
            var bucket = ExactDpe2Padding.SelectSmallestBucket(exactDmc2.Length);
            var placeholder = new Dpe2Record(
                expectedNetworkId,
                sessionId.Span,
                senderDeviceId.Span,
                recipientDeviceId.Span,
                operationId,
                dtr2,
                Dpe2Ciphertext.Import(new byte[bucket + 16]));
            headerHash = MessagingWireCryptographicInputs.ComputeDpe2HeaderHash(placeholder);
            padded = ExactDpe2Padding.Create(exactDmc2);
            ciphertext = ratchetPlan.UseMessageKeyForEnvelopeCrypto(key =>
                EncryptExact(placeholder, padded, key));
            ratchetPlan.DeleteMessageKeyAfterEnvelopeCrypto();
            var envelope = new Dpe2Record(
                expectedNetworkId,
                sessionId.Span,
                senderDeviceId.Span,
                recipientDeviceId.Span,
                operationId,
                dtr2,
                Dpe2Ciphertext.Import(ciphertext));
            exactEnvelope = Dpe2Codec.Encode(envelope);
            envelopeHash = MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(envelope);
            if (!MessagingCryptoValidation.FixedEquals(
                    headerHash,
                    MessagingWireCryptographicInputs.ComputeDtr2HeaderHash(dtr2)))
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "The exact DPE2 header hash diverged from the provider DTR2 transcript.");
            var plan = new ExactDpe2SendTransitionPlan(
                ratchetPlan,
                operationId,
                exactEnvelope,
                headerHash,
                envelopeHash);
            ratchetPlan = null;
            exactEnvelope = null;
            headerHash = null;
            envelopeHash = null;
            return plan;
        }
        finally
        {
            ratchetPlan?.Dispose();
            if (padded is not null) CryptographicOperations.ZeroMemory(padded);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
            if (exactEnvelope is not null) CryptographicOperations.ZeroMemory(exactEnvelope);
            if (headerHash is not null) CryptographicOperations.ZeroMemory(headerHash);
            if (envelopeHash is not null) CryptographicOperations.ZeroMemory(envelopeHash);
        }
    }

    internal ExactDpe2SendCommit Commit(DurableExactDpe2SendSuccessCapability durableSuccess)
    {
        ArgumentNullException.ThrowIfNull(durableSuccess);
        lock (_lifecycleSync)
        {
            if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
                throw new MessagingCryptoException(
                    MessagingCryptoError.CapabilityConsumed,
                    "The exact DPE2 send transition is single-consumer.");
            var exactEnvelope = Interlocked.Exchange(ref _exactEnvelope, null);
            TripleRatchetState? nextState = null;
            try
            {
                if (exactEnvelope is null)
                    throw new MessagingCryptoException(
                        MessagingCryptoError.TransitionRejected,
                        "The sealed exact DPE2 send mutation is unavailable.");
                var ratchetSuccess = durableSuccess.ConsumeAndVerify(_operationId, _exactEnvelopeHash);
                using var ratchetCommit = _ratchetPlan.Commit(ratchetSuccess);
                nextState = ratchetCommit.TakeNextState();
                var commit = new ExactDpe2SendCommit(nextState, exactEnvelope);
                nextState = null;
                exactEnvelope = null;
                return commit;
            }
            finally
            {
                nextState?.Dispose();
                if (exactEnvelope is not null) CryptographicOperations.ZeroMemory(exactEnvelope);
                _ratchetPlan.Dispose();
            }
        }
    }

    public void Dispose()
    {
        lock (_lifecycleSync)
        {
            if (Interlocked.Exchange(ref _consumed, 2) == 2) return;
            var envelope = Interlocked.Exchange(ref _exactEnvelope, null);
            if (envelope is not null) CryptographicOperations.ZeroMemory(envelope);
            _ratchetPlan.Dispose();
        }
    }

    private static byte[] EncryptExact(
        Dpe2Record header,
        ReadOnlySpan<byte> paddedPlaintext,
        ReadOnlySpan<byte> messageKey)
    {
        byte[]? plaintext = null;
        byte[]? key = null;
        try
        {
            plaintext = paddedPlaintext.ToArray();
            key = messageKey.ToArray();
            return SecretAeadXChaCha20Poly1305.Encrypt(
                plaintext,
                MessagingWireCryptographicInputs.DeriveDpe2Nonce(header),
                key,
                MessagingWireCryptographicInputs.GetDpe2AeadAssociatedData(header));
        }
        catch (CryptographicException exception)
        {
            throw new MessagingCryptoException(
                MessagingCryptoError.TransitionRejected,
                "DPE2 envelope encryption failed.",
                exception);
        }
        finally
        {
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
        }
    }
}
