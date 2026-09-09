using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Protocol.MessagingWire;

public sealed class Dpk2ResolvedDevice
{
    private readonly byte[] _signingKey;
    private readonly byte[] _agreementKey;

    public Dpk2ResolvedDevice(ReadOnlySpan<byte> signingKey, ReadOnlySpan<byte> agreementKey)
    {
        RequireKey(signingKey, nameof(signingKey));
        RequireKey(agreementKey, nameof(agreementKey));
        _signingKey = signingKey.ToArray();
        _agreementKey = agreementKey.ToArray();
    }

    public ReadOnlyMemory<byte> SigningKey => _signingKey.ToArray();
    public ReadOnlyMemory<byte> AgreementKey => _agreementKey.ToArray();

    private static void RequireKey(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || MessagingWireFraming.IsZero(value))
            throw VerificationError(MessagingWirePrevalidationStage.HashProjection,
                $"Resolved {name} is invalid.");
    }

    private static MessagingWireFormatException VerificationError(
        MessagingWirePrevalidationStage stage, string message) =>
        MessagingWireFraming.Error(stage, MessagingWireRejection.DerivedValueMismatch, message);
}

public interface IDpk2VerificationCallbacks
{
    Dpk2ResolvedDevice ResolveActiveDevice(Dpk2Record offering);
    bool VerifyEd25519(
        ReadOnlyMemory<byte> publicKey,
        ReadOnlyMemory<byte> signatureInput,
        ReadOnlyMemory<byte> signature);
}

public sealed class VerifiedDpk2Offering
{
    internal VerifiedDpk2Offering(Dpk2Record record, byte[] exactHash)
    {
        Record = record;
        _exactHash = exactHash.ToArray();
    }

    internal Dpk2Record Record { get; }
    public ReadOnlyMemory<byte> ExactHash => _exactHash.ToArray();
    public ReadOnlyMemory<byte> NetworkId => Record.NetworkId;
    public ReadOnlyMemory<byte> ResponderAccountId => Record.ResponderAccountId;
    public ReadOnlyMemory<byte> ResponderDeviceId => Record.ResponderDeviceId;
    public ulong ResponderDeviceGeneration => Record.ResponderDeviceGeneration;
    public ReadOnlyMemory<byte> ExactBytes => Dpk2Codec.Encode(Record);
    private readonly byte[] _exactHash;
}

internal sealed class Dpk2VerificationPlan
{
    private readonly byte[] _x25519Input;
    private readonly byte[] _mlKemInput;
    private readonly byte[] _bundleInput;
    private readonly byte[] _exactHash;

    private Dpk2VerificationPlan(Dpk2Record record)
    {
        Record = record;
        _x25519Input = MessagingWireCryptographicInputs.GetX25519SignedPrekeySignatureInput(record);
        _mlKemInput = MessagingWireCryptographicInputs.GetMlKemPrekeySignatureInput(record);
        _bundleInput = MessagingWireCryptographicInputs.GetPrekeyBundleSignatureInput(record);
        _exactHash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(record);
    }

    internal Dpk2Record Record { get; }
    internal ReadOnlyMemory<byte> ExactHash => _exactHash.ToArray();

    internal static Dpk2VerificationPlan Create(Dpk2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return new Dpk2VerificationPlan(record);
    }

    internal VerifiedDpk2Offering Verify(IDpk2VerificationCallbacks callbacks)
    {
        ArgumentNullException.ThrowIfNull(callbacks);
        var resolved = callbacks.ResolveActiveDevice(Record);
        if (!CryptographicOperations.FixedTimeEquals(
                resolved.AgreementKey.Span, Record.DeviceAgreementPublicKey.Span))
            Reject(MessagingWirePrevalidationStage.HashProjection,
                "DPK2 agreement key differs from the exact active device closure.");
        var key = resolved.SigningKey;
        if (!callbacks.VerifyEd25519(key, _x25519Input, Record.SignedX25519PrekeySignature) ||
            !callbacks.VerifyEd25519(key, _mlKemInput, Record.MlKemPrekeySignature) ||
            !callbacks.VerifyEd25519(key, _bundleInput, Record.BundleSignature))
            Reject(MessagingWirePrevalidationStage.CryptographicVerification,
                "A DPK2 device signature was rejected.");
        return new VerifiedDpk2Offering(Record, _exactHash.ToArray());
    }

    private static void Reject(MessagingWirePrevalidationStage stage, string message) =>
        throw MessagingWireFraming.Error(stage, MessagingWireRejection.CallbackRejected, message);
}

public sealed class Dph2ResolvedInitiator
{
    private readonly byte[] _agreementKey;
    private readonly byte[] _deviceDirectoryHeadHash;

    public Dph2ResolvedInitiator(
        ReadOnlySpan<byte> agreementKey,
        ReadOnlySpan<byte> deviceDirectoryHeadHash)
    {
        if (agreementKey.Length != 32 || MessagingWireFraming.IsZero(agreementKey))
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.HashProjection,
                MessagingWireRejection.DerivedValueMismatch,
                "Resolved initiator agreement key is invalid.");
        if (deviceDirectoryHeadHash.Length != 32 || MessagingWireFraming.IsZero(deviceDirectoryHeadHash))
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.HashProjection,
                MessagingWireRejection.DerivedValueMismatch,
                "Resolved initiator device-directory head is invalid.");
        _agreementKey = agreementKey.ToArray();
        _deviceDirectoryHeadHash = deviceDirectoryHeadHash.ToArray();
    }

    public ReadOnlyMemory<byte> AgreementKey => _agreementKey.ToArray();
    public ReadOnlyMemory<byte> DeviceDirectoryHeadHash => _deviceDirectoryHeadHash.ToArray();
}

public sealed class Dph2ClaimVerification
{
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ReadOnlyMemory<byte> ReceiptHash { get; init; }
    public required ReadOnlyMemory<byte> ExactDpk2Hash { get; init; }
    public required ReadOnlyMemory<byte> SelectedOneTimeIdOrZero { get; init; }
    public required ReadOnlyMemory<byte> SenderEphemeralCommitment { get; init; }
    public required ReadOnlyMemory<byte> SessionId { get; init; }
    public required ushort LastResortUseCounter { get; init; }
}

public interface IDph2VerificationCallbacks
{
    Dph2ResolvedInitiator ResolveInitiator(Dph2Record initiation);
    bool VerifyExactClaim(Dph2ClaimVerification claim);
}

public sealed class VerifiedDph2Initiation
{
    private readonly byte[] _transcriptHash;
    private readonly byte[] _fullReplayHash;
    private readonly byte[] _claimBinding;
    private readonly byte[] _initiatorDeviceDirectoryHeadHash;

    internal VerifiedDph2Initiation(
        Dph2Record record,
        VerifiedDpk2Offering offering,
        ReadOnlySpan<byte> transcriptHash,
        ReadOnlySpan<byte> fullReplayHash,
        ReadOnlySpan<byte> claimBinding,
        ReadOnlySpan<byte> initiatorDeviceDirectoryHeadHash)
    {
        if (initiatorDeviceDirectoryHeadHash.Length != 32 ||
            MessagingWireFraming.IsZero(initiatorDeviceDirectoryHeadHash))
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.HashProjection,
                MessagingWireRejection.DerivedValueMismatch,
                "Verified initiator device-directory head is invalid.");
        Record = record;
        Offering = offering;
        _transcriptHash = transcriptHash.ToArray();
        _fullReplayHash = fullReplayHash.ToArray();
        _claimBinding = claimBinding.ToArray();
        _initiatorDeviceDirectoryHeadHash = initiatorDeviceDirectoryHeadHash.ToArray();
    }

    internal Dph2Record Record { get; }
    internal VerifiedDpk2Offering Offering { get; }
    public ReadOnlyMemory<byte> TranscriptHash => _transcriptHash.ToArray();
    public ReadOnlyMemory<byte> FullReplayHash => _fullReplayHash.ToArray();
    public ReadOnlyMemory<byte> ClaimBinding => _claimBinding.ToArray();
    public ReadOnlyMemory<byte> NetworkId => Record.NetworkId;
    public ReadOnlyMemory<byte> ClaimOperationId => Record.ClaimOperationId;
    public ReadOnlyMemory<byte> SessionId => Record.SessionId;
    public ReadOnlyMemory<byte> ExactBytes => Dph2Codec.Encode(Record);
    internal ReadOnlySpan<byte> InitiatorDeviceDirectoryHeadHashSpan =>
        _initiatorDeviceDirectoryHeadHash;
}

internal sealed class Dph2VerificationPlan
{
    private readonly byte[] _transcriptHash;
    private readonly byte[] _fullReplayHash;
    private readonly byte[] _claimBinding;
    private readonly byte[] _senderCommitment;

    private Dph2VerificationPlan(Dph2Record record, VerifiedDpk2Offering offering)
    {
        Record = record;
        Offering = offering;
        Dph2Codec.ValidateSelection(record, offering.Record);
        _senderCommitment = MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(record);
        _transcriptHash = MessagingWireCryptographicInputs.ComputeDph2TranscriptHash(offering.Record, record);
        _fullReplayHash = MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(record);
        _claimBinding = MessagingWireCryptographicInputs.ComputeDph2ClaimBinding(record);
    }

    internal Dph2Record Record { get; }
    internal VerifiedDpk2Offering Offering { get; }

    internal static Dph2VerificationPlan Create(Dph2Record record, VerifiedDpk2Offering offering)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(offering);
        return new Dph2VerificationPlan(record, offering);
    }

    internal VerifiedDph2Initiation Verify(IDph2VerificationCallbacks callbacks)
    {
        ArgumentNullException.ThrowIfNull(callbacks);
        var initiator = callbacks.ResolveInitiator(Record);
        if (!CryptographicOperations.FixedTimeEquals(
                initiator.AgreementKey.Span, Record.InitiatorDeviceAgreementPublicKey.Span))
            Reject(MessagingWirePrevalidationStage.HashProjection,
                "DPH2 initiator key differs from the exact active device closure.");
        if (!callbacks.VerifyExactClaim(new Dph2ClaimVerification
            {
                OperationId = Record.ClaimOperationId,
                ReceiptHash = Record.ClaimReceiptHash,
                ExactDpk2Hash = Record.ExactDpk2Hash,
                SelectedOneTimeIdOrZero = Record.SelectedPrekey.OneTimeX25519PrekeyIdOrZero,
                SenderEphemeralCommitment = _senderCommitment.ToArray(),
                SessionId = Record.SessionId,
                LastResortUseCounter = Record.LastResortUseCounter,
            }))
            Reject(MessagingWirePrevalidationStage.HashProjection,
                "DPH2 exact XPC1 claim was rejected.");
        return new VerifiedDph2Initiation(
            Record,
            Offering,
            _transcriptHash,
            _fullReplayHash,
            _claimBinding,
            initiator.DeviceDirectoryHeadHash.Span);
    }

    private static void Reject(MessagingWirePrevalidationStage stage, string message) =>
        throw MessagingWireFraming.Error(stage, MessagingWireRejection.CallbackRejected, message);
}

public interface IDtr2VerificationCallbacks
{
    bool VerifyBraidMessage(Dtr2Record header);
}

public sealed class VerifiedDtr2Header
{
    internal VerifiedDtr2Header(Dtr2Record record, byte[] headerHash)
    {
        Record = record;
        _headerHash = headerHash.ToArray();
    }

    internal Dtr2Record Record { get; }
    public ReadOnlyMemory<byte> HeaderHash => _headerHash.ToArray();
    public ReadOnlyMemory<byte> ExactBytes => Dtr2Codec.EncodeEmbedded(Record);
    private readonly byte[] _headerHash;
}

internal sealed class Dtr2VerificationPlan
{
    private readonly byte[] _headerHash;

    private Dtr2VerificationPlan(Dtr2Record record)
    {
        Record = record;
        _headerHash = MessagingWireCryptographicInputs.Sha256Domain(
            MessagingWireCryptographicInputs.RatchetHeaderDomain,
            Dtr2Codec.EncodeEmbedded(record));
    }

    internal Dtr2Record Record { get; }

    internal static Dtr2VerificationPlan Create(Dtr2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return new Dtr2VerificationPlan(record);
    }

    internal VerifiedDtr2Header Verify(IDtr2VerificationCallbacks callbacks)
    {
        ArgumentNullException.ThrowIfNull(callbacks);
        if (!callbacks.VerifyBraidMessage(Record))
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.CryptographicVerification,
                MessagingWireRejection.CallbackRejected,
                "DTR2 Braid authentication/state verification failed.");
        return new VerifiedDtr2Header(Record, _headerHash.ToArray());
    }
}

public sealed class Dpe2AuthenticationVerification
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ReadOnlyMemory<byte> SessionId { get; init; }
    public required ReadOnlyMemory<byte> SenderDeviceId { get; init; }
    public required ReadOnlyMemory<byte> RecipientDeviceId { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ReadOnlyMemory<byte> Ciphertext { get; init; }
    public required ReadOnlyMemory<byte> Nonce { get; init; }
    public required ReadOnlyMemory<byte> AssociatedData { get; init; }
    public required ReadOnlyMemory<byte> ExactEnvelopeHash { get; init; }
}

public interface IDpe2VerificationCallbacks
{
    void AuthenticateExactEnvelope(
        Dpe2AuthenticationVerification verification,
        Dpe2AuthenticationOutput output);
}

/// <summary>
/// A single-use protocol-owned sink for the result of exact DPE2 AEAD and
/// ratchet-session authentication. Consumers receive this instance only while
/// the protocol verifier is executing; they cannot construct a verified
/// envelope or retain a reusable authority capability from raw spans.
/// </summary>
public sealed class Dpe2AuthenticationOutput : IDisposable
{
    private readonly object _sync = new();
    private byte[]? _plaintext;
    private byte[]? _networkId;
    private byte[]? _sessionId;
    private byte[]? _senderAccountId;
    private byte[]? _senderDeviceId;
    private byte[]? _conversationId;
    private int _disposed;

    internal Dpe2AuthenticationOutput()
    {
    }

    public void AcceptAuthenticatedPlaintext(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> sessionId32,
        ReadOnlySpan<byte> senderAccountId32,
        ReadOnlySpan<byte> senderDeviceId32,
        ReadOnlySpan<byte> conversationId32)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_plaintext is not null)
                AuthenticationError("A DPE2 authentication callback completed more than once.");
            if (plaintext.Length is < 282 or > 33082)
                AuthenticationError("Authenticated DPE2 plaintext is outside the bounded DMC2 size range.");
            RequireFact(networkId16, 16, nameof(networkId16));
            RequireFact(sessionId32, 32, nameof(sessionId32));
            RequireFact(senderAccountId32, 32, nameof(senderAccountId32));
            RequireFact(senderDeviceId32, 32, nameof(senderDeviceId32));
            RequireFact(conversationId32, 32, nameof(conversationId32));

            _plaintext = plaintext.ToArray();
            _networkId = networkId16.ToArray();
            _sessionId = sessionId32.ToArray();
            _senderAccountId = senderAccountId32.ToArray();
            _senderDeviceId = senderDeviceId32.ToArray();
            _conversationId = conversationId32.ToArray();
        }
    }

    internal Dpe2AuthenticatedFacts Complete(Dpe2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_plaintext is null || _networkId is null || _sessionId is null ||
                _senderAccountId is null || _senderDeviceId is null || _conversationId is null)
                AuthenticationError("The DPE2 authentication callback did not provide authenticated plaintext and session facts.");
            if (!Fixed(_networkId, record.NetworkIdSpan) ||
                !Fixed(_sessionId, record.SessionIdSpan) ||
                !Fixed(_senderDeviceId, record.SenderDeviceIdSpan))
                AuthenticationError("Authenticated DPE2 network, session, or sender device differs from the exact envelope.");

            var result = new Dpe2AuthenticatedFacts(
                _plaintext,
                _senderAccountId,
                _senderDeviceId,
                _conversationId);
            _plaintext = null;
            _senderAccountId = null;
            _senderDeviceId = null;
            _conversationId = null;
            ZeroAndRelease(ref _networkId);
            ZeroAndRelease(ref _sessionId);
            _disposed = 1;
            return result;
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            ZeroAndRelease(ref _plaintext);
            ZeroAndRelease(ref _networkId);
            ZeroAndRelease(ref _sessionId);
            ZeroAndRelease(ref _senderAccountId);
            ZeroAndRelease(ref _senderDeviceId);
            ZeroAndRelease(ref _conversationId);
        }
    }

    private static void RequireFact(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || MessagingWireFraming.IsZero(value))
            AuthenticationError($"Authenticated {name} is not an exact nonzero protocol fact.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void ZeroAndRelease(ref byte[]? value)
    {
        if (value is not null)
            CryptographicOperations.ZeroMemory(value);
        value = null;
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed != 0, this);

    [DoesNotReturn]
    private static void AuthenticationError(string message) =>
        throw MessagingWireFraming.Error(
            MessagingWirePrevalidationStage.CryptographicVerification,
            MessagingWireRejection.CallbackRejected,
            message);
}

internal delegate TResult Dpe2AuthenticatedPlaintextReader<TResult>(ReadOnlySpan<byte> plaintext);

internal sealed class Dpe2AuthenticatedFacts : IDisposable
{
    private byte[]? _plaintext;
    private byte[]? _senderAccountId;
    private byte[]? _senderDeviceId;
    private byte[]? _conversationId;
    private int _disposed;

    internal Dpe2AuthenticatedFacts(
        byte[] plaintext,
        byte[] senderAccountId,
        byte[] senderDeviceId,
        byte[] conversationId)
    {
        _plaintext = plaintext;
        _senderAccountId = senderAccountId;
        _senderDeviceId = senderDeviceId;
        _conversationId = conversationId;
    }

    internal TResult UsePlaintext<TResult>(Dpe2AuthenticatedPlaintextReader<TResult> reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ThrowIfDisposed();
        return reader(_plaintext!);
    }

    internal byte[] CopySenderAccountId() => Copy(_senderAccountId);
    internal byte[] CopySenderDeviceId() => Copy(_senderDeviceId);
    internal byte[] CopyConversationId() => Copy(_conversationId);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        ZeroAndRelease(ref _plaintext);
        ZeroAndRelease(ref _senderAccountId);
        ZeroAndRelease(ref _senderDeviceId);
        ZeroAndRelease(ref _conversationId);
    }

    private byte[] Copy(byte[]? value)
    {
        ThrowIfDisposed();
        return value!.ToArray();
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed != 0, this);

    private static void ZeroAndRelease(ref byte[]? value)
    {
        if (value is not null)
            CryptographicOperations.ZeroMemory(value);
        value = null;
    }
}

internal sealed class Dpe2VerificationPlan
{
    private readonly byte[] _headerHash;
    private readonly byte[] _nonce;
    private readonly byte[] _aad;
    private readonly byte[] _exactEnvelopeHash;

    private Dpe2VerificationPlan(Dpe2Record record, VerifiedDtr2Header verifiedHeader)
    {
        Record = record;
        if (!Dtr2Codec.EncodeEmbedded(record.RatchetHeader)
                .AsSpan().SequenceEqual(Dtr2Codec.EncodeEmbedded(verifiedHeader.Record)))
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.HashProjection,
                MessagingWireRejection.DerivedValueMismatch,
                "DPE2 does not contain the verified DTR2 header.");
        _headerHash = verifiedHeader.HeaderHash.ToArray();
        _nonce = MessagingWireCryptographicInputs.DeriveDpe2Nonce(record);
        _aad = MessagingWireCryptographicInputs.GetDpe2AeadAssociatedData(record);
        _exactEnvelopeHash = MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(record);
    }

    internal Dpe2Record Record { get; }

    internal static Dpe2VerificationPlan Create(Dpe2Record record, VerifiedDtr2Header verifiedHeader)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(verifiedHeader);
        return new Dpe2VerificationPlan(record, verifiedHeader);
    }

    internal SecretBuffer DeriveMessageKey(
        ReadOnlySpan<byte> ecMessageKey,
        ReadOnlySpan<byte> pqMessageKey)
    {
        RequireMessageKey(ecMessageKey, nameof(ecMessageKey));
        RequireMessageKey(pqMessageKey, nameof(pqMessageKey));

        byte[]? salt = null;
        byte[]? ecOwned = null;
        byte[]? pqOwned = null;
        byte[]? hybridIkm = null;
        byte[]? ecNumber = null;
        byte[]? sckaEpoch = null;
        byte[]? sckaNumber = null;
        byte[]? protocolInfo = null;
        byte[]? info = null;
        Span<byte> prk = stackalloc byte[64];
        Span<byte> output = stackalloc byte[32];
        try
        {
            salt = MessagingWireCryptographicInputs.Sha512Domain(
                "Deep/Messaging/V2/triple-ratchet-salt",
                Record.SessionIdSpan);
            ecOwned = ecMessageKey.ToArray();
            pqOwned = pqMessageKey.ToArray();
            protocolInfo = Encoding.ASCII.GetBytes(MessagingKdf.TripleRatchetProtocolInfo);
            hybridIkm = MessagingWireCryptographicInputs.Context(
                "Deep/Messaging/V2/hybrid-message-ikm",
                protocolInfo,
                ecOwned,
                pqOwned);

            ecNumber = U64(Record.RatchetHeader.EcMessageNumber);
            sckaEpoch = U64(Record.RatchetHeader.SckaSendingEpoch);
            sckaNumber = U64(Record.RatchetHeader.SckaMessageNumber);
            info = MessagingWireCryptographicInputs.Context(
                "Deep/Messaging/V2/message-key",
                protocolInfo,
                Record.SessionIdMemory,
                ecNumber,
                sckaEpoch,
                sckaNumber,
                _headerHash);

            if (HKDF.Extract(HashAlgorithmName.SHA512, hybridIkm, salt, prk) != prk.Length)
                throw new CryptographicException("HKDF extract returned an unexpected length.");
            HKDF.Expand(HashAlgorithmName.SHA512, prk, output, info);
            return SecretBuffer.ImportExact(output, output.Length, "messageKey");
        }
        finally
        {
            Zero(salt);
            Zero(ecOwned);
            Zero(pqOwned);
            Zero(hybridIkm);
            Zero(ecNumber);
            Zero(sckaEpoch);
            Zero(sckaNumber);
            Zero(protocolInfo);
            Zero(info);
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(output);
        }
    }

    internal VerifiedDpe2Envelope Verify(IDpe2VerificationCallbacks callbacks)
    {
        ArgumentNullException.ThrowIfNull(callbacks);
        var ciphertext = new byte[Record.Ciphertext.Length];
        Record.Ciphertext.CopyCiphertextTo(ciphertext);
        using var output = new Dpe2AuthenticationOutput();
        Dpe2AuthenticatedFacts? authenticated = null;
        try
        {
            callbacks.AuthenticateExactEnvelope(new Dpe2AuthenticationVerification
                {
                    NetworkId = Record.NetworkId,
                    SessionId = Record.SessionId,
                    SenderDeviceId = Record.SenderDeviceId,
                    RecipientDeviceId = Record.RecipientDeviceId,
                    OperationId = Record.OperationId,
                    Ciphertext = ciphertext,
                    Nonce = _nonce.ToArray(),
                    AssociatedData = _aad.ToArray(),
                    ExactEnvelopeHash = _exactEnvelopeHash.ToArray(),
                }, output);
            authenticated = output.Complete(Record);
            var verified = new VerifiedDpe2Envelope(
                Record,
                _nonce,
                _aad,
                _exactEnvelopeHash,
                authenticated);
            authenticated = null;
            return verified;
        }
        finally
        {
            authenticated?.Dispose();
        }
    }

    private static byte[] U64(ulong value)
    {
        var encoded = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        return encoded;
    }

    private static void RequireMessageKey(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || MessagingWireFraming.IsZero(value))
            throw MessagingWireFraming.Error(
                MessagingWirePrevalidationStage.HashProjection,
                MessagingWireRejection.DerivedValueMismatch,
                $"{name} must be exactly 32 nonzero bytes.");
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
            CryptographicOperations.ZeroMemory(value);
    }
}

public sealed class VerifiedDpe2Envelope : IDisposable
{
    private readonly object _sync = new();
    private readonly Dpe2Record _record;
    private readonly byte[] _nonce;
    private readonly byte[] _associatedData;
    private readonly byte[] _fullReplayHash;
    private readonly Dpe2AuthenticatedFacts _authenticated;
    private int _disposed;

    internal VerifiedDpe2Envelope(
        Dpe2Record record,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> fullReplayHash,
        Dpe2AuthenticatedFacts authenticated)
    {
        _record = record;
        _nonce = nonce.ToArray();
        _associatedData = associatedData.ToArray();
        _fullReplayHash = fullReplayHash.ToArray();
        _authenticated = authenticated;
    }

    internal Dpe2Record Record => Use(static record => record, _record);
    public ReadOnlyMemory<byte> NetworkId => Use(static record => record.NetworkId, _record);
    public ReadOnlyMemory<byte> SessionId => Use(static record => record.SessionId, _record);
    public ReadOnlyMemory<byte> OperationId => Use(static record => record.OperationId, _record);
    public ReadOnlyMemory<byte> Nonce => Copy(_nonce);
    public ReadOnlyMemory<byte> AssociatedData => Copy(_associatedData);
    public ReadOnlyMemory<byte> FullReplayHash => Copy(_fullReplayHash);
    public ReadOnlyMemory<byte> SenderAccountId => CopyAuthenticated(static facts => facts.CopySenderAccountId());
    public ReadOnlyMemory<byte> SenderDeviceId => CopyAuthenticated(static facts => facts.CopySenderDeviceId());
    public ReadOnlyMemory<byte> ConversationId => CopyAuthenticated(static facts => facts.CopyConversationId());
    public ReadOnlyMemory<byte> ExactBytes => Use(static record => (ReadOnlyMemory<byte>)Dpe2Codec.Encode(record), _record);

    internal TResult UseAuthenticatedPlaintext<TResult>(Dpe2AuthenticatedPlaintextReader<TResult> reader)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            return _authenticated.UsePlaintext(reader);
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            CryptographicOperations.ZeroMemory(_nonce);
            CryptographicOperations.ZeroMemory(_associatedData);
            CryptographicOperations.ZeroMemory(_fullReplayHash);
            _authenticated.Dispose();
        }
    }

    private ReadOnlyMemory<byte> Copy(byte[] value) => Use(static bytes => (ReadOnlyMemory<byte>)bytes.ToArray(), value);

    private ReadOnlyMemory<byte> CopyAuthenticated(Func<Dpe2AuthenticatedFacts, byte[]> copy) =>
        Use(facts => (ReadOnlyMemory<byte>)copy(facts), _authenticated);

    private TResult Use<TSource, TResult>(Func<TSource, TResult> action, TSource source)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            return action(source);
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed != 0, this);
}

/// <summary>
/// The only public transition from syntactically parsed messaging records to
/// protocol-verified capabilities. Constructors for the capability types are
/// intentionally not public, so raw records cannot masquerade as verified.
/// </summary>
public static class MessagingWireVerification
{
    public static VerifiedDpk2Offering VerifyDpk2(
        ReadOnlySpan<byte> exactDpk2,
        IDpk2VerificationCallbacks callbacks)
    {
        ArgumentNullException.ThrowIfNull(callbacks);
        return Dpk2VerificationPlan.Create(Dpk2Codec.Decode(exactDpk2)).Verify(callbacks);
    }

    public static VerifiedDph2Initiation VerifyDph2(
        ReadOnlySpan<byte> exactDph2,
        VerifiedDpk2Offering exactOffering,
        IDph2VerificationCallbacks callbacks)
    {
        ArgumentNullException.ThrowIfNull(exactOffering);
        ArgumentNullException.ThrowIfNull(callbacks);
        var record = Dph2Codec.Decode(exactDph2);
        return Dph2VerificationPlan.Create(record, exactOffering).Verify(callbacks);
    }

    public static VerifiedDtr2Header VerifyEmbeddedDtr2(
        ReadOnlySpan<byte> exactDtr2,
        IDtr2VerificationCallbacks callbacks)
    {
        ArgumentNullException.ThrowIfNull(callbacks);
        return Dtr2VerificationPlan.Create(Dtr2Codec.DecodeEmbedded(exactDtr2)).Verify(callbacks);
    }

    public static VerifiedDpe2Envelope VerifyDpe2(
        ReadOnlySpan<byte> exactDpe2,
        IDtr2VerificationCallbacks ratchetCallbacks,
        IDpe2VerificationCallbacks envelopeCallbacks)
    {
        ArgumentNullException.ThrowIfNull(ratchetCallbacks);
        ArgumentNullException.ThrowIfNull(envelopeCallbacks);
        var record = Dpe2Codec.Decode(exactDpe2);
        var verifiedHeader = Dtr2VerificationPlan.Create(record.RatchetHeader).Verify(ratchetCallbacks);
        return Dpe2VerificationPlan.Create(record, verifiedHeader).Verify(envelopeCallbacks);
    }

    public static void RequireExactDph2Replay(
        VerifiedDph2Initiation retained,
        VerifiedDph2Initiation candidate)
    {
        ArgumentNullException.ThrowIfNull(retained);
        ArgumentNullException.ThrowIfNull(candidate);
        var sameOperation = Fixed(retained.ClaimOperationId.Span, candidate.ClaimOperationId.Span);
        var sameSession = Fixed(retained.SessionId.Span, candidate.SessionId.Span);
        if ((sameOperation || sameSession) &&
            (!sameOperation || !sameSession ||
             !Fixed(retained.FullReplayHash.Span, candidate.FullReplayHash.Span)))
        {
            RejectChangedReplay("DPH2 claim/session replay changed exact bytes.");
        }
    }

    public static void RequireExactDpe2Replay(
        VerifiedDpe2Envelope retained,
        VerifiedDpe2Envelope candidate)
    {
        ArgumentNullException.ThrowIfNull(retained);
        ArgumentNullException.ThrowIfNull(candidate);
        if (Fixed(retained.OperationId.Span, candidate.OperationId.Span) &&
            !Fixed(retained.FullReplayHash.Span, candidate.FullReplayHash.Span))
        {
            RejectChangedReplay("DPE2 operation replay changed exact bytes.");
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void RejectChangedReplay(string message) =>
        throw MessagingWireFraming.Error(
            MessagingWirePrevalidationStage.HashProjection,
            MessagingWireRejection.CrossFieldMismatch,
            message);
}
