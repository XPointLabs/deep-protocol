using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.MessagingCrypto;

internal sealed class RatchetStateBinding
{
    internal const int DurableEncodingSize = 240;

    private readonly byte[] _sessionId;
    private readonly byte[] _transcriptHash;
    private readonly byte[] _localDeviceId;
    private readonly byte[] _remoteDeviceId;
    private readonly byte[] _localDirectoryHead;
    private readonly byte[] _remoteDirectoryHead;
    private readonly byte[] _commitment;

    internal RatchetStateBinding(
        ushort suite,
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> transcriptHash,
        ReadOnlySpan<byte> localDeviceId,
        ulong localDeviceGeneration,
        ReadOnlySpan<byte> localDirectoryHead,
        ReadOnlySpan<byte> remoteDeviceId,
        ulong remoteDeviceGeneration,
        ReadOnlySpan<byte> remoteDirectoryHead)
    {
        if (suite != MessagingCryptoConstants.Suite ||
            localDeviceGeneration == 0 || remoteDeviceGeneration == 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The suite and both device generations must be the closed active values.");
        MessagingCryptoValidation.NonZeroExact(sessionId, 32, nameof(sessionId));
        MessagingCryptoValidation.NonZeroExact(transcriptHash, 64, nameof(transcriptHash));
        MessagingCryptoValidation.NonZeroExact(localDeviceId, 32, nameof(localDeviceId));
        MessagingCryptoValidation.NonZeroExact(remoteDeviceId, 32, nameof(remoteDeviceId));
        MessagingCryptoValidation.NonZeroExact(localDirectoryHead, 32, nameof(localDirectoryHead));
        MessagingCryptoValidation.NonZeroExact(remoteDirectoryHead, 32, nameof(remoteDirectoryHead));

        Suite = suite;
        LocalDeviceGeneration = localDeviceGeneration;
        RemoteDeviceGeneration = remoteDeviceGeneration;
        _sessionId = sessionId.ToArray();
        _transcriptHash = transcriptHash.ToArray();
        _localDeviceId = localDeviceId.ToArray();
        _remoteDeviceId = remoteDeviceId.ToArray();
        _localDirectoryHead = localDirectoryHead.ToArray();
        _remoteDirectoryHead = remoteDirectoryHead.ToArray();
        _commitment = ComputeCommitment();
    }

    internal ushort Suite { get; }
    internal ulong LocalDeviceGeneration { get; }
    internal ulong RemoteDeviceGeneration { get; }
    internal ReadOnlyMemory<byte> SessionId => _sessionId.ToArray();
    internal ReadOnlyMemory<byte> LocalDeviceId => _localDeviceId.ToArray();
    internal ReadOnlyMemory<byte> RemoteDeviceId => _remoteDeviceId.ToArray();
    internal ReadOnlyMemory<byte> TranscriptHash => _transcriptHash.ToArray();
    internal ReadOnlyMemory<byte> Commitment => _commitment.ToArray();

    internal void WriteDurableEncoding(Span<byte> destination)
    {
        if (destination.Length != DurableEncodingSize)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The durable state-binding destination has the wrong exact length.");

        var offset = 0;
        _sessionId.CopyTo(destination[offset..]); offset += 32;
        _transcriptHash.CopyTo(destination[offset..]); offset += 64;
        _localDeviceId.CopyTo(destination[offset..]); offset += 32;
        BinaryPrimitives.WriteUInt64BigEndian(destination[offset..], LocalDeviceGeneration); offset += 8;
        _localDirectoryHead.CopyTo(destination[offset..]); offset += 32;
        _remoteDeviceId.CopyTo(destination[offset..]); offset += 32;
        BinaryPrimitives.WriteUInt64BigEndian(destination[offset..], RemoteDeviceGeneration); offset += 8;
        _remoteDirectoryHead.CopyTo(destination[offset..]);
    }

    internal bool MatchesTranscript(ReadOnlySpan<byte> transcriptHash) =>
        MessagingCryptoValidation.FixedEquals(_transcriptHash, transcriptHash);

    internal void RequireVerifiedHandshake(
        VerifiedDph2Initiation initiation,
        bool localIsInitiator)
    {
        ArgumentNullException.ThrowIfNull(initiation);
        var dph2 = initiation.Record;
        var dpk2 = initiation.Offering.Record;
        var expectedLocalDevice = localIsInitiator
            ? dph2.InitiatorDeviceIdSpan
            : dph2.ResponderDeviceIdSpan;
        var expectedRemoteDevice = localIsInitiator
            ? dph2.ResponderDeviceIdSpan
            : dph2.InitiatorDeviceIdSpan;
        var expectedLocalGeneration = localIsInitiator
            ? dph2.InitiatorDeviceGeneration
            : dph2.ResponderDeviceGeneration;
        var expectedRemoteGeneration = localIsInitiator
            ? dph2.ResponderDeviceGeneration
            : dph2.InitiatorDeviceGeneration;

        if (!MessagingCryptoValidation.FixedEquals(_sessionId, dph2.SessionIdSpan) ||
            !MessagingCryptoValidation.FixedEquals(_transcriptHash, initiation.TranscriptHash.Span) ||
            !MessagingCryptoValidation.FixedEquals(_localDeviceId, expectedLocalDevice) ||
            !MessagingCryptoValidation.FixedEquals(_remoteDeviceId, expectedRemoteDevice) ||
            LocalDeviceGeneration != expectedLocalGeneration ||
            RemoteDeviceGeneration != expectedRemoteGeneration)
        {
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The ratchet state binding differs from the verified DPH2 session or directional device closure.");
        }

        var responderDirectoryHead = localIsInitiator
            ? _remoteDirectoryHead
            : _localDirectoryHead;
        if (!MessagingCryptoValidation.FixedEquals(
                responderDirectoryHead,
                dpk2.DeviceDirectoryHeadHashSpan))
        {
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The ratchet state binding differs from the verified DPK2 responder directory head.");
        }
    }

    internal void RequireIncomingEnvelope(
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> senderDeviceId,
        ReadOnlySpan<byte> recipientDeviceId)
    {
        MessagingCryptoValidation.NonZeroExact(sessionId, 32, nameof(sessionId));
        MessagingCryptoValidation.NonZeroExact(senderDeviceId, 32, nameof(senderDeviceId));
        MessagingCryptoValidation.NonZeroExact(recipientDeviceId, 32, nameof(recipientDeviceId));
        if (!MessagingCryptoValidation.FixedEquals(_sessionId, sessionId) ||
            !MessagingCryptoValidation.FixedEquals(_remoteDeviceId, senderDeviceId) ||
            !MessagingCryptoValidation.FixedEquals(_localDeviceId, recipientDeviceId))
            throw new MessagingCryptoException(
                MessagingCryptoError.ReplayConflict,
                "The exact DPE2 session or directional device binding differs from the committed ratchet state.");
    }

    internal void RequireOutgoingEnvelope(
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> senderDeviceId,
        ReadOnlySpan<byte> recipientDeviceId)
    {
        MessagingCryptoValidation.NonZeroExact(sessionId, 32, nameof(sessionId));
        MessagingCryptoValidation.NonZeroExact(senderDeviceId, 32, nameof(senderDeviceId));
        MessagingCryptoValidation.NonZeroExact(recipientDeviceId, 32, nameof(recipientDeviceId));
        if (!MessagingCryptoValidation.FixedEquals(_sessionId, sessionId) ||
            !MessagingCryptoValidation.FixedEquals(_localDeviceId, senderDeviceId) ||
            !MessagingCryptoValidation.FixedEquals(_remoteDeviceId, recipientDeviceId))
            throw new MessagingCryptoException(
                MessagingCryptoError.ReplayConflict,
                "The exact DPE2 session or directional device binding differs from the committed send ratchet state.");
    }

    private byte[] ComputeCommitment()
    {
        Span<byte> fixedFields = stackalloc byte[2 + 32 + 64 + 32 + 8 + 32 + 32 + 8 + 32];
        BinaryPrimitives.WriteUInt16BigEndian(fixedFields, Suite);
        var offset = 2;
        _sessionId.CopyTo(fixedFields[offset..]); offset += 32;
        _transcriptHash.CopyTo(fixedFields[offset..]); offset += 64;
        _localDeviceId.CopyTo(fixedFields[offset..]); offset += 32;
        BinaryPrimitives.WriteUInt64BigEndian(fixedFields[offset..], LocalDeviceGeneration); offset += 8;
        _localDirectoryHead.CopyTo(fixedFields[offset..]); offset += 32;
        _remoteDeviceId.CopyTo(fixedFields[offset..]); offset += 32;
        BinaryPrimitives.WriteUInt64BigEndian(fixedFields[offset..], RemoteDeviceGeneration); offset += 8;
        _remoteDirectoryHead.CopyTo(fixedFields[offset..]);
        return MessagingKdf.Sha256Domain("Deep/Messaging/V2/state-binding", fixedFields);
    }
}

internal sealed class VerifiedHybridTranscriptCapability
{
    private readonly byte[] _exactDpk2;
    private readonly byte[] _headerWithoutPayload;
    private readonly byte[] _mlKemCiphertext;
    private readonly byte[]? _fullDph2ReplayHash;
    private readonly byte[]? _x25519PreKeyId;
    private readonly byte[] _mlKemPreKeyId;
    private int _consumed;

    private VerifiedHybridTranscriptCapability(
        byte[] exactDpk2,
        byte[] headerWithoutPayload,
        byte[] mlKemCiphertext,
        byte[]? fullDph2ReplayHash,
        byte[]? x25519PreKeyId,
        byte[] mlKemPreKeyId,
        RatchetStateBinding stateBinding)
    {
        _exactDpk2 = exactDpk2;
        _headerWithoutPayload = headerWithoutPayload;
        _mlKemCiphertext = mlKemCiphertext;
        _fullDph2ReplayHash = fullDph2ReplayHash;
        _x25519PreKeyId = x25519PreKeyId;
        _mlKemPreKeyId = mlKemPreKeyId;
        StateBinding = stateBinding;
    }

    internal RatchetStateBinding StateBinding { get; }

    internal static VerifiedHybridTranscriptCapability FromVerifiedInitiation(
        VerifiedDph2Initiation initiation,
        RatchetStateBinding stateBinding,
        bool localIsInitiator)
    {
        ArgumentNullException.ThrowIfNull(initiation);
        ArgumentNullException.ThrowIfNull(stateBinding);
        stateBinding.RequireVerifiedHandshake(initiation, localIsInitiator);

        var dph2 = initiation.Record;
        var dpk2 = initiation.Offering.Record;
        var expectedOneTimeId = dpk2.MlKemKind == Dpk2PrekeyKind.OneTime
            ? dpk2.OneTimeX25519PrekeyIdSpan.ToArray()
            : null;
        return new VerifiedHybridTranscriptCapability(
            Dpk2Codec.Encode(dpk2),
            Dph2Codec.GetHandshakeHeader(dph2),
            dph2.ActualMlKem768CiphertextSpan.ToArray(),
            localIsInitiator ? null : initiation.FullReplayHash.ToArray(),
            expectedOneTimeId,
            dpk2.MlKemPrekeyIdSpan.ToArray(),
            stateBinding);
    }

    // Test-only pre-frozen seam retained for fault-injection coverage. Production
    // handshake code must use FromVerifiedInitiation and can never substitute
    // caller-selected DPK2/DPH2 bytes for MessagingWire verification output.
    internal static VerifiedHybridTranscriptCapability CreateInitiatorDarkForTests(
        ReadOnlySpan<byte> exactDpk2,
        ReadOnlySpan<byte> headerWithoutPayload,
        ReadOnlySpan<byte> actualMlKemCiphertext,
        ReadOnlySpan<byte> x25519PreKeyId,
        ReadOnlySpan<byte> mlKemPreKeyId,
        RatchetStateBinding stateBinding)
    {
        ArgumentNullException.ThrowIfNull(stateBinding);
        if (exactDpk2.IsEmpty || exactDpk2.Length > 65_535 ||
            headerWithoutPayload.IsEmpty || headerWithoutPayload.Length > 65_535)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "Dark transcript records must be non-empty and at most 65,535 bytes.");
        MessagingCryptoValidation.Exact(
            actualMlKemCiphertext,
            MessagingCryptoConstants.MlKem768CiphertextSize,
            nameof(actualMlKemCiphertext));
        if (!x25519PreKeyId.IsEmpty)
            MessagingCryptoValidation.NonZeroExact(x25519PreKeyId, 32, nameof(x25519PreKeyId));
        MessagingCryptoValidation.NonZeroExact(mlKemPreKeyId, 32, nameof(mlKemPreKeyId));
        if (headerWithoutPayload.IndexOf(actualMlKemCiphertext) < 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The exact ML-KEM ciphertext is not bound into the supplied header bytes.");
        return new VerifiedHybridTranscriptCapability(
            exactDpk2.ToArray(),
            headerWithoutPayload.ToArray(),
            actualMlKemCiphertext.ToArray(),
            null,
            x25519PreKeyId.IsEmpty ? null : x25519PreKeyId.ToArray(),
            mlKemPreKeyId.ToArray(),
            stateBinding);
    }

    internal static VerifiedHybridTranscriptCapability CreateResponderDarkForTests(
        ReadOnlySpan<byte> exactDpk2,
        ReadOnlySpan<byte> headerWithoutPayload,
        ReadOnlySpan<byte> exactFullDph2,
        ReadOnlySpan<byte> actualMlKemCiphertext,
        ReadOnlySpan<byte> x25519PreKeyId,
        ReadOnlySpan<byte> mlKemPreKeyId,
        RatchetStateBinding stateBinding)
    {
        if (exactFullDph2.IsEmpty || exactFullDph2.Length > 65_535)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The exact full DPH2 record must be non-empty and at most 65,535 bytes.");
        var transcript = CreateInitiatorDarkForTests(
            exactDpk2,
            headerWithoutPayload,
            actualMlKemCiphertext,
            x25519PreKeyId,
            mlKemPreKeyId,
            stateBinding);
        return new VerifiedHybridTranscriptCapability(
            transcript._exactDpk2,
            transcript._headerWithoutPayload,
            transcript._mlKemCiphertext,
            MessagingKdf.Sha256Domain("Deep/Messaging/V2/exact-dph2-replay", exactFullDph2),
            transcript._x25519PreKeyId,
            transcript._mlKemPreKeyId,
            transcript.StateBinding);
    }

    internal VerifiedHybridTranscriptData Consume(ReadOnlySpan<byte> expectedCiphertext)
    {
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.CapabilityConsumed,
                "The verified transcript capability is single-use.");
        if (!MessagingCryptoValidation.FixedEquals(_mlKemCiphertext, expectedCiphertext))
            throw new MessagingCryptoException(
                MessagingCryptoError.PreKeyConflict,
                "The ML-KEM ciphertext differs from the verified transcript binding.");
        var transcriptHash = ComputeTranscriptHash();
        if (!StateBinding.MatchesTranscript(transcriptHash))
        {
            CryptographicOperations.ZeroMemory(transcriptHash);
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The transcript differs from the sealed state binding.");
        }
        return new VerifiedHybridTranscriptData(
            transcriptHash,
            _mlKemCiphertext.ToArray(),
            null,
            _x25519PreKeyId?.ToArray(),
            _mlKemPreKeyId.ToArray(),
            StateBinding);
    }

    internal VerifiedHybridTranscriptData ConsumeBoundForResponder()
    {
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.CapabilityConsumed,
                "The verified transcript capability is single-use.");
        var transcriptHash = ComputeTranscriptHash();
        if (!StateBinding.MatchesTranscript(transcriptHash))
        {
            CryptographicOperations.ZeroMemory(transcriptHash);
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The transcript differs from the sealed state binding.");
        }
        if (_fullDph2ReplayHash is null)
        {
            CryptographicOperations.ZeroMemory(transcriptHash);
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "A responder transcript capability must bind the exact full DPH2 record.");
        }
        return new VerifiedHybridTranscriptData(
            transcriptHash,
            _mlKemCiphertext.ToArray(),
            _fullDph2ReplayHash.ToArray(),
            _x25519PreKeyId?.ToArray(),
            _mlKemPreKeyId.ToArray(),
            StateBinding);
    }

    private byte[] ComputeTranscriptHash()
    {
        var label = Encoding.ASCII.GetBytes("Deep/Messaging/V2/handshake-transcript");
        var payloadLength = checked(4 + _exactDpk2.Length + 4 + _headerWithoutPayload.Length);
        Span<byte> length = stackalloc byte[4];
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        hash.AppendData(label);
        hash.AppendData([0]);
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)payloadLength));
        hash.AppendData(length);
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)_exactDpk2.Length));
        hash.AppendData(length);
        hash.AppendData(_exactDpk2);
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)_headerWithoutPayload.Length));
        hash.AppendData(length);
        hash.AppendData(_headerWithoutPayload);
        return hash.GetHashAndReset();
    }
}

internal sealed record VerifiedHybridTranscriptData(
    byte[] TranscriptHash,
    byte[] MlKemCiphertext,
    byte[]? FullDph2ReplayHash,
    byte[]? X25519PreKeyId,
    byte[] MlKemPreKeyId,
    RatchetStateBinding StateBinding);

internal sealed class VerifiedPreKeyClaimCapability
{
    private readonly byte[] _claimId;
    private readonly byte[] _sessionId;
    private readonly byte[] _initiationHash;
    private readonly byte[]? _x25519PreKeyId;
    private readonly byte[] _mlKemPreKeyId;
    private int _consumed;

    private VerifiedPreKeyClaimCapability(
        byte[] claimId,
        byte[] sessionId,
        byte[] initiationHash,
        byte[]? x25519PreKeyId,
        byte[] mlKemPreKeyId)
    {
        _claimId = claimId;
        _sessionId = sessionId;
        _initiationHash = initiationHash;
        _x25519PreKeyId = x25519PreKeyId;
        _mlKemPreKeyId = mlKemPreKeyId;
    }

    internal static VerifiedPreKeyClaimCapability CreateDarkForTests(
        ReadOnlySpan<byte> claimId,
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> initiationHash,
        ReadOnlySpan<byte> x25519PreKeyId,
        ReadOnlySpan<byte> mlKemPreKeyId)
    {
        MessagingCryptoValidation.NonZeroExact(claimId, 32, nameof(claimId));
        MessagingCryptoValidation.NonZeroExact(sessionId, 32, nameof(sessionId));
        MessagingCryptoValidation.NonZeroExact(initiationHash, 32, nameof(initiationHash));
        if (!x25519PreKeyId.IsEmpty)
            MessagingCryptoValidation.NonZeroExact(x25519PreKeyId, 32, nameof(x25519PreKeyId));
        MessagingCryptoValidation.NonZeroExact(mlKemPreKeyId, 32, nameof(mlKemPreKeyId));
        return new VerifiedPreKeyClaimCapability(
            claimId.ToArray(), sessionId.ToArray(), initiationHash.ToArray(),
            x25519PreKeyId.IsEmpty ? null : x25519PreKeyId.ToArray(), mlKemPreKeyId.ToArray());
    }

    /// <summary>
    /// Sole production bridge from the Contact-owned witnessed XPC1 receipt and
    /// its exact verified DPH2 initiation into the single-use prekey state gate.
    /// </summary>
    internal static VerifiedPreKeyClaimCapability CreateFromVerifiedXpc1(
        VerifiedXpc1PreKeyClaimReceipt claim,
        VerifiedDph2Initiation initiation)
    {
        ArgumentNullException.ThrowIfNull(claim);
        ArgumentNullException.ThrowIfNull(initiation);
        using var handoff = claim.BindForInitialSession(initiation);
        return CreateFromVerifiedInitialSession(handoff);
    }

    internal static VerifiedPreKeyClaimCapability CreateFromVerifiedInitialSession(
        VerifiedInitialSessionPreKeyClaim handoff)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        using var binding = handoff.ConsumeForProtocolHandshake();
        return new VerifiedPreKeyClaimCapability(
            binding.OperationId.ToArray(),
            binding.SessionId.ToArray(),
            binding.Dph2FullReplayHash.ToArray(),
            binding.Kind == Dpk2PrekeyKind.OneTime
                ? binding.X25519PreKeyId.ToArray()
                : null,
            binding.MlKemPreKeyId.ToArray());
    }

    internal VerifiedPreKeyClaimData Consume()
    {
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.CapabilityConsumed,
                "The verified prekey claim capability is single-use.");
        return new VerifiedPreKeyClaimData(
            _claimId.ToArray(), _sessionId.ToArray(), _initiationHash.ToArray(),
            _x25519PreKeyId?.ToArray(), _mlKemPreKeyId.ToArray());
    }
}

internal sealed record VerifiedPreKeyClaimData(
    byte[] ClaimId,
    byte[] SessionId,
    byte[] InitiationHash,
    byte[]? X25519PreKeyId,
    byte[] MlKemPreKeyId);

internal enum RatchetDeduplicationOutcome { Fresh, ExactReplay }

internal sealed class RatchetDeduplicationLease
{
    private readonly byte[] _stateBindingCommitment;
    private readonly byte[] _sessionId;
    private readonly byte[] _operationId;
    private readonly byte[] _exactHeaderHash;
    private readonly byte[] _envelopeHash;
    private readonly byte[] _journalPredecessor;
    private readonly byte[] _retentionCommitment;
    private int _consumed;

    private RatchetDeduplicationLease(
        RatchetDeduplicationOutcome outcome,
        byte[] stateBindingCommitment,
        byte[] sessionId,
        RatchetCounterTuple target,
        byte[] operationId,
        byte[] exactHeaderHash,
        byte[] envelopeHash,
        ulong journalGeneration,
        byte[] journalPredecessor,
        byte[] retentionCommitment)
    {
        Outcome = outcome;
        _stateBindingCommitment = stateBindingCommitment;
        _sessionId = sessionId;
        Target = target;
        _operationId = operationId;
        _exactHeaderHash = exactHeaderHash;
        _envelopeHash = envelopeHash;
        JournalGeneration = journalGeneration;
        _journalPredecessor = journalPredecessor;
        _retentionCommitment = retentionCommitment;
    }

    internal RatchetDeduplicationOutcome Outcome { get; }
    internal RatchetCounterTuple Target { get; }
    internal ulong JournalGeneration { get; }

    internal static RatchetDeduplicationLease CreateDarkForTests(
        RatchetDeduplicationOutcome outcome,
        ReadOnlySpan<byte> stateBindingCommitment,
        ReadOnlySpan<byte> sessionId,
        RatchetCounterTuple target,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactHeaderHash,
        ReadOnlySpan<byte> envelopeHash,
        ulong journalGeneration,
        ReadOnlySpan<byte> journalPredecessor,
        ReadOnlySpan<byte> retentionCommitment,
        bool coversEntireSessionAndMailboxReplayHorizon)
    {
        MessagingCryptoValidation.NonZeroExact(
            stateBindingCommitment, 32, nameof(stateBindingCommitment));
        MessagingCryptoValidation.NonZeroExact(sessionId, 32, nameof(sessionId));
        MessagingCryptoValidation.NonZeroExact(operationId, 32, nameof(operationId));
        MessagingCryptoValidation.NonZeroExact(exactHeaderHash, 32, nameof(exactHeaderHash));
        MessagingCryptoValidation.NonZeroExact(envelopeHash, 32, nameof(envelopeHash));
        MessagingCryptoValidation.NonZeroExact(journalPredecessor, 32, nameof(journalPredecessor));
        MessagingCryptoValidation.NonZeroExact(retentionCommitment, 32, nameof(retentionCommitment));
        if (!coversEntireSessionAndMailboxReplayHorizon)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "Dedup retention must cover the complete session and mailbox replay horizon.");
        return CreateForExactEnvelope(
            outcome, stateBindingCommitment.ToArray(), sessionId.ToArray(), target,
            operationId.ToArray(), exactHeaderHash.ToArray(), envelopeHash.ToArray(), journalGeneration,
            journalPredecessor.ToArray(), retentionCommitment.ToArray());
    }

    internal static RatchetDeduplicationLease CreateForExactEnvelope(
        RatchetDeduplicationOutcome outcome,
        ReadOnlySpan<byte> stateBindingCommitment,
        ReadOnlySpan<byte> sessionId,
        RatchetCounterTuple target,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactHeaderHash,
        ReadOnlySpan<byte> envelopeHash,
        ulong journalGeneration,
        ReadOnlySpan<byte> journalPredecessor,
        ReadOnlySpan<byte> retentionCommitment)
    {
        MessagingCryptoValidation.NonZeroExact(
            stateBindingCommitment, 32, nameof(stateBindingCommitment));
        MessagingCryptoValidation.NonZeroExact(sessionId, 32, nameof(sessionId));
        MessagingCryptoValidation.NonZeroExact(operationId, 32, nameof(operationId));
        MessagingCryptoValidation.NonZeroExact(exactHeaderHash, 32, nameof(exactHeaderHash));
        MessagingCryptoValidation.NonZeroExact(envelopeHash, 32, nameof(envelopeHash));
        MessagingCryptoValidation.NonZeroExact(journalPredecessor, 32, nameof(journalPredecessor));
        MessagingCryptoValidation.NonZeroExact(retentionCommitment, 32, nameof(retentionCommitment));
        return new RatchetDeduplicationLease(
            outcome,
            stateBindingCommitment.ToArray(),
            sessionId.ToArray(),
            target,
            operationId.ToArray(),
            exactHeaderHash.ToArray(),
            envelopeHash.ToArray(),
            journalGeneration,
            journalPredecessor.ToArray(),
            retentionCommitment.ToArray());
    }

    internal RatchetDeduplicationData Consume()
    {
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.CapabilityConsumed,
                "The durable deduplication lease is single-use.");
        return new RatchetDeduplicationData(
            Outcome, _stateBindingCommitment.ToArray(), _sessionId.ToArray(), Target,
            _operationId.ToArray(), _exactHeaderHash.ToArray(), _envelopeHash.ToArray(), JournalGeneration,
            _journalPredecessor.ToArray(), _retentionCommitment.ToArray());
    }
}

internal sealed record RatchetDeduplicationData(
    RatchetDeduplicationOutcome Outcome,
    byte[] StateBindingCommitment,
    byte[] SessionId,
    RatchetCounterTuple Target,
    byte[] OperationId,
    byte[] ExactHeaderHash,
    byte[] EnvelopeHash,
    ulong JournalGeneration,
    byte[] JournalPredecessor,
    byte[] RetentionCommitment);

internal sealed class RatchetPersistenceLease
{
    private readonly byte[] _expectedStateCommitment;
    private readonly byte[] _latestProtectedCommitment;
    private int _consumed;

    private RatchetPersistenceLease(
        ulong expectedGeneration,
        byte[] expectedStateCommitment,
        ulong latestProtectedGeneration,
        byte[] latestProtectedCommitment)
    {
        ExpectedGeneration = expectedGeneration;
        _expectedStateCommitment = expectedStateCommitment;
        LatestProtectedGeneration = latestProtectedGeneration;
        _latestProtectedCommitment = latestProtectedCommitment;
    }

    internal ulong ExpectedGeneration { get; }
    internal ulong LatestProtectedGeneration { get; }

    internal static RatchetPersistenceLease CreateDarkForTests(
        ulong expectedGeneration,
        ReadOnlySpan<byte> expectedStateCommitment,
        ulong latestProtectedGeneration,
        ReadOnlySpan<byte> latestProtectedCommitment) =>
        CreateForProductionAuthority(
            expectedGeneration,
            expectedStateCommitment,
            latestProtectedGeneration,
            latestProtectedCommitment);

    internal static RatchetPersistenceLease CreateForProductionAuthority(
        ulong expectedGeneration,
        ReadOnlySpan<byte> expectedStateCommitment,
        ulong latestProtectedGeneration,
        ReadOnlySpan<byte> latestProtectedCommitment)
    {
        MessagingCryptoValidation.NonZeroExact(expectedStateCommitment, 32, nameof(expectedStateCommitment));
        MessagingCryptoValidation.NonZeroExact(latestProtectedCommitment, 32, nameof(latestProtectedCommitment));
        if (latestProtectedGeneration < expectedGeneration)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The protected checkpoint generation cannot precede the expected state.");
        return new RatchetPersistenceLease(
            expectedGeneration, expectedStateCommitment.ToArray(), latestProtectedGeneration,
            latestProtectedCommitment.ToArray());
    }

    internal RatchetPersistenceData Consume()
    {
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.CapabilityConsumed,
                "The protected-state lease is single-use.");
        return new RatchetPersistenceData(
            ExpectedGeneration, _expectedStateCommitment.ToArray(), LatestProtectedGeneration,
            _latestProtectedCommitment.ToArray());
    }
}

internal sealed record RatchetPersistenceData(
    ulong ExpectedGeneration,
    byte[] ExpectedStateCommitment,
    ulong LatestProtectedGeneration,
    byte[] LatestProtectedCommitment);

internal sealed class DurableDatabaseCasSuccessCapability
{
    private readonly byte[] _databasePredecessorCommitment;
    private readonly byte[] _committedStateCommitment;
    private int _consumed;

    private DurableDatabaseCasSuccessCapability(
        ulong databaseExpectedGeneration,
        byte[] databasePredecessorCommitment,
        ulong committedGeneration,
        byte[] committedStateCommitment)
    {
        DatabaseExpectedGeneration = databaseExpectedGeneration;
        _databasePredecessorCommitment = databasePredecessorCommitment;
        CommittedGeneration = committedGeneration;
        _committedStateCommitment = committedStateCommitment;
    }

    internal ulong DatabaseExpectedGeneration { get; }
    internal ulong CommittedGeneration { get; }

    internal static DurableDatabaseCasSuccessCapability CreateDarkForTests(
        PersistenceCasExpectation databaseExpectation,
        ulong committedGeneration,
        ReadOnlySpan<byte> committedStateCommitment,
        bool durableDatabaseCasSucceeded)
    {
        ArgumentNullException.ThrowIfNull(databaseExpectation);
        MessagingCryptoValidation.NonZeroExact(
            committedStateCommitment, 32, nameof(committedStateCommitment));
        if (!durableDatabaseCasSucceeded || committedGeneration <= databaseExpectation.ExpectedGeneration)
            throw new MessagingCryptoException(
                MessagingCryptoError.CasConflict,
                "A durable database CAS success capability cannot be minted for a failed transition.");
        return new DurableDatabaseCasSuccessCapability(
            databaseExpectation.ExpectedGeneration,
            databaseExpectation.PredecessorCommitment.ToArray(),
            committedGeneration,
            committedStateCommitment.ToArray());
    }

    internal void ConsumeAndVerify(
        PersistenceCasExpectation expectedDatabase,
        ulong expectedCommittedGeneration,
        ReadOnlySpan<byte> expectedCommittedStateCommitment)
    {
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.CapabilityConsumed,
                "The durable database CAS success capability is single-use.");
        if (DatabaseExpectedGeneration != expectedDatabase.ExpectedGeneration ||
            !MessagingCryptoValidation.FixedEquals(
                _databasePredecessorCommitment,
                expectedDatabase.PredecessorCommitment.Span) ||
            CommittedGeneration != expectedCommittedGeneration ||
            !MessagingCryptoValidation.FixedEquals(
                _committedStateCommitment,
                expectedCommittedStateCommitment))
            throw new MessagingCryptoException(
                MessagingCryptoError.CasConflict,
                "The durable database CAS success does not bind this exact transition.");
    }
}

internal sealed class CheckpointCasExpectation
{
    private readonly byte[] _predecessorCommitment;

    internal CheckpointCasExpectation(ulong expectedGeneration, ReadOnlySpan<byte> predecessorCommitment)
    {
        MessagingCryptoValidation.NonZeroExact(predecessorCommitment, 32, nameof(predecessorCommitment));
        ExpectedGeneration = expectedGeneration;
        _predecessorCommitment = predecessorCommitment.ToArray();
    }

    internal ulong ExpectedGeneration { get; }
    internal ReadOnlyMemory<byte> PredecessorCommitment => _predecessorCommitment.ToArray();
}

internal sealed class ExactRatchetJournalReceipt
{
    private readonly ExactRatchetJournalReceiptData _data;
    private int _consumed;

    private ExactRatchetJournalReceipt(ExactRatchetJournalReceiptData data) => _data = data;

    internal static ExactRatchetJournalReceipt CreateDarkForTests(
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> journalPredecessor,
        PersistenceCasExpectation databaseExpectation,
        CheckpointCasExpectation checkpointExpectation,
        ulong committedGeneration,
        ReadOnlySpan<byte> committedStateCommitment,
        ReadOnlySpan<byte> terminalStateCommitment,
        ReadOnlySpan<byte> deletionManifestCommitment,
        ReadOnlySpan<byte> deduplicationMutationCommitment,
        ReadOnlySpan<byte> pqFenceMutationCommitment,
        bool durablyCommitted)
    {
        if (!durablyCommitted)
            throw new MessagingCryptoException(
                MessagingCryptoError.CasConflict,
                "An exact ratchet journal receipt requires one durable advancing transaction.");
        return CreateForProductionAuthority(
            operationId,
            journalPredecessor,
            databaseExpectation,
            checkpointExpectation,
            committedGeneration,
            committedStateCommitment,
            terminalStateCommitment,
            deletionManifestCommitment,
            deduplicationMutationCommitment,
            pqFenceMutationCommitment);
    }

    internal static ExactRatchetJournalReceipt CreateForProductionAuthority(
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> journalPredecessor,
        PersistenceCasExpectation databaseExpectation,
        CheckpointCasExpectation checkpointExpectation,
        ulong committedGeneration,
        ReadOnlySpan<byte> committedStateCommitment,
        ReadOnlySpan<byte> terminalStateCommitment,
        ReadOnlySpan<byte> deletionManifestCommitment,
        ReadOnlySpan<byte> deduplicationMutationCommitment,
        ReadOnlySpan<byte> pqFenceMutationCommitment)
    {
        MessagingCryptoValidation.NonZeroExact(operationId, 32, nameof(operationId));
        MessagingCryptoValidation.NonZeroExact(journalPredecessor, 32, nameof(journalPredecessor));
        ArgumentNullException.ThrowIfNull(databaseExpectation);
        ArgumentNullException.ThrowIfNull(checkpointExpectation);
        MessagingCryptoValidation.NonZeroExact(
            committedStateCommitment, 32, nameof(committedStateCommitment));
        MessagingCryptoValidation.NonZeroExact(
            deletionManifestCommitment, 32, nameof(deletionManifestCommitment));
        ValidateOptionalCommitment(terminalStateCommitment, nameof(terminalStateCommitment));
        ValidateOptionalCommitment(deduplicationMutationCommitment, nameof(deduplicationMutationCommitment));
        ValidateOptionalCommitment(pqFenceMutationCommitment, nameof(pqFenceMutationCommitment));
        if (committedGeneration <= databaseExpectation.ExpectedGeneration ||
            committedGeneration <= checkpointExpectation.ExpectedGeneration)
            throw new MessagingCryptoException(
                MessagingCryptoError.CasConflict,
                "An exact ratchet journal receipt requires one durable advancing transaction.");

        return new ExactRatchetJournalReceipt(new ExactRatchetJournalReceiptData(
            operationId.ToArray(),
            journalPredecessor.ToArray(),
            databaseExpectation.ExpectedGeneration,
            databaseExpectation.PredecessorCommitment.ToArray(),
            committedGeneration,
            committedStateCommitment.ToArray(),
            checkpointExpectation.ExpectedGeneration,
            checkpointExpectation.PredecessorCommitment.ToArray(),
            committedGeneration,
            committedStateCommitment.ToArray(),
            terminalStateCommitment.IsEmpty ? null : terminalStateCommitment.ToArray(),
            deletionManifestCommitment.ToArray(),
            deduplicationMutationCommitment.IsEmpty ? null : deduplicationMutationCommitment.ToArray(),
            pqFenceMutationCommitment.IsEmpty ? null : pqFenceMutationCommitment.ToArray()));
    }

    internal ExactRatchetJournalReceiptData Consume()
    {
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.CapabilityConsumed,
                "The exact ratchet journal receipt is single-use.");
        return _data.Copy();
    }

    private static void ValidateOptionalCommitment(ReadOnlySpan<byte> value, string name)
    {
        if (!value.IsEmpty) MessagingCryptoValidation.NonZeroExact(value, 32, name);
    }
}

internal sealed record ExactRatchetJournalReceiptData(
    byte[] OperationId,
    byte[] JournalPredecessor,
    ulong DatabasePreGeneration,
    byte[] DatabasePreCommitment,
    ulong DatabasePostGeneration,
    byte[] DatabasePostCommitment,
    ulong CheckpointPreGeneration,
    byte[] CheckpointPreCommitment,
    ulong CheckpointPostGeneration,
    byte[] CheckpointPostCommitment,
    byte[]? TerminalStateCommitment,
    byte[] DeletionManifestCommitment,
    byte[]? DeduplicationMutationCommitment,
    byte[]? PqFenceMutationCommitment)
{
    internal ExactRatchetJournalReceiptData Copy() => new(
        OperationId.ToArray(), JournalPredecessor.ToArray(),
        DatabasePreGeneration, DatabasePreCommitment.ToArray(),
        DatabasePostGeneration, DatabasePostCommitment.ToArray(),
        CheckpointPreGeneration, CheckpointPreCommitment.ToArray(),
        CheckpointPostGeneration, CheckpointPostCommitment.ToArray(),
        TerminalStateCommitment?.ToArray(), DeletionManifestCommitment.ToArray(),
        DeduplicationMutationCommitment?.ToArray(), PqFenceMutationCommitment?.ToArray());
}

internal sealed class DurableRatchetTransactionSuccessCapability
{
    private readonly ExactRatchetJournalReceiptData _receipt;
    private int _consumed;

    private DurableRatchetTransactionSuccessCapability(ExactRatchetJournalReceiptData receipt) =>
        _receipt = receipt;

    internal static DurableRatchetTransactionSuccessCapability CreateDarkForTests(
        ExactRatchetJournalReceipt receipt,
        bool atomicTransactionCommitted)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        if (!atomicTransactionCommitted)
            throw new MessagingCryptoException(
                MessagingCryptoError.CasConflict,
                "The unified ratchet transaction did not commit atomically.");
        return new DurableRatchetTransactionSuccessCapability(receipt.Consume());
    }

    internal static DurableRatchetTransactionSuccessCapability CreateFromProductionAuthority(
        ExactRatchetJournalReceipt receipt) =>
        new((receipt ?? throw new ArgumentNullException(nameof(receipt))).Consume());

    internal void ConsumeAndVerify(
        ReadOnlySpan<byte> expectedOperationId,
        ReadOnlySpan<byte> expectedJournalPredecessor,
        PersistenceCasExpectation expectedDatabase,
        CheckpointCasExpectation expectedCheckpoint,
        ulong expectedCommittedGeneration,
        ReadOnlySpan<byte> expectedCommittedStateCommitment,
        ReadOnlySpan<byte> expectedTerminalStateCommitment,
        ReadOnlySpan<byte> expectedDeletionManifestCommitment,
        ReadOnlySpan<byte> expectedDeduplicationMutationCommitment,
        ReadOnlySpan<byte> expectedPqFenceMutationCommitment)
    {
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.CapabilityConsumed,
                "The unified ratchet transaction success capability is single-use.");

        if (!MessagingCryptoValidation.FixedEquals(_receipt.OperationId, expectedOperationId) ||
            !MessagingCryptoValidation.FixedEquals(_receipt.JournalPredecessor, expectedJournalPredecessor) ||
            _receipt.DatabasePreGeneration != expectedDatabase.ExpectedGeneration ||
            !MessagingCryptoValidation.FixedEquals(
                _receipt.DatabasePreCommitment, expectedDatabase.PredecessorCommitment.Span) ||
            _receipt.DatabasePostGeneration != expectedCommittedGeneration ||
            !MessagingCryptoValidation.FixedEquals(
                _receipt.DatabasePostCommitment, expectedCommittedStateCommitment) ||
            _receipt.CheckpointPreGeneration != expectedCheckpoint.ExpectedGeneration ||
            !MessagingCryptoValidation.FixedEquals(
                _receipt.CheckpointPreCommitment, expectedCheckpoint.PredecessorCommitment.Span) ||
            _receipt.CheckpointPostGeneration != expectedCommittedGeneration ||
            !MessagingCryptoValidation.FixedEquals(
                _receipt.CheckpointPostCommitment, expectedCommittedStateCommitment) ||
            !OptionalMatches(_receipt.TerminalStateCommitment, expectedTerminalStateCommitment) ||
            !MessagingCryptoValidation.FixedEquals(
                _receipt.DeletionManifestCommitment, expectedDeletionManifestCommitment) ||
            !OptionalMatches(_receipt.DeduplicationMutationCommitment, expectedDeduplicationMutationCommitment) ||
            !OptionalMatches(_receipt.PqFenceMutationCommitment, expectedPqFenceMutationCommitment))
            throw new MessagingCryptoException(
                MessagingCryptoError.CasConflict,
                "The durable transaction receipt does not bind this exact ratchet transition.");
    }

    private static bool OptionalMatches(byte[]? actual, ReadOnlySpan<byte> expected) =>
        expected.IsEmpty
            ? actual is null
            : actual is not null && MessagingCryptoValidation.FixedEquals(actual, expected);
}
