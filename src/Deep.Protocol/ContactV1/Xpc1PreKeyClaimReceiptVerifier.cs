using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV1;

public sealed class Xpc1PreKeyClaimReceiptException : CryptographicException
{
    internal Xpc1PreKeyClaimReceiptException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Non-serializable proof that one exact XPK1 was durably claimed by the two
/// current PreKeyClaim replicas and returned the exact recipient-bound DPK2.
/// It deliberately exposes identifiers and hashes, never receipt bytes or keys.
/// </summary>
public sealed class VerifiedXpc1PreKeyClaimReceipt
{
    private readonly VerifiedDpk2Offering _offering;
    private readonly byte[] _networkId;
    private readonly byte[] _operationId;
    private readonly byte[] _requestHash;
    private readonly byte[] _claimReceiptHash;
    private readonly byte[] _exactDpk2Hash;
    private readonly byte[] _xpi1Hash;
    private readonly byte[] _responderAccountId;
    private readonly byte[] _responderDeviceId;
    private readonly byte[] _signedX25519PrekeyId;
    private readonly byte[] _selectedOneTimePrekeyId;
    private readonly byte[] _mlKemPrekeyId;
    private readonly byte[] _senderEphemeralCommitment;
    private readonly byte[] _fullExactReplayHash;
    private readonly byte[] _exactXpk1;
    private readonly byte[] _exactXpc1Wire;
    private readonly byte[][] _replicaNodeIds;
    private int _handshakeConsumed;

    internal VerifiedXpc1PreKeyClaimReceipt(
        Xpk1Request request,
        Xpc1Result result,
        Dpk2Record dpk2,
        ReadOnlySpan<byte> exactDpk2Hash,
        ReadOnlySpan<byte> fullExactReplayHash,
        IReadOnlyList<VerifiedNetworkNode> replicas)
    {
        _offering = new VerifiedDpk2Offering(dpk2, exactDpk2Hash.ToArray());
        _networkId = request.NetworkId.ToArray();
        _operationId = request.OperationId.ToArray();
        _requestHash = request.RequestHash.ToArray();
        _claimReceiptHash = result.Field(18).ToArray();
        _exactDpk2Hash = exactDpk2Hash.ToArray();
        _xpi1Hash = Xpi1Codec.ComputeHash(result.FieldSpan(26));
        _responderAccountId = dpk2.ResponderAccountId.ToArray();
        _responderDeviceId = dpk2.ResponderDeviceId.ToArray();
        ResponderDeviceGeneration = dpk2.ResponderDeviceGeneration;
        _signedX25519PrekeyId = dpk2.SignedX25519PrekeyId.ToArray();
        _selectedOneTimePrekeyId = result.Field(17).ToArray();
        _mlKemPrekeyId = dpk2.MlKemPrekeyId.ToArray();
        _senderEphemeralCommitment = request.SenderEphemeralCommitment.ToArray();
        _fullExactReplayHash = fullExactReplayHash.ToArray();
        _exactXpk1 = request.CanonicalBytes.ToArray();
        _exactXpc1Wire = result.WireBytes.ToArray();
        PrekeyKind = dpk2.MlKemKind;
        ServiceGeneration = ServiceWire.U64(result.FieldSpan(21));
        PrekeyExpiresAtUnixSeconds = ServiceWire.U64(result.FieldSpan(22));
        LastResortUseCounter = ServiceWire.U16(result.FieldSpan(23));
        ClaimCommitGeneration = ServiceWire.U64(result.FieldSpan(24));
        InventoryEpoch = Xpi1Codec.Decode(result.FieldSpan(26)).InventoryEpoch;
        InventoryIndex = ServiceWire.U16(result.FieldSpan(27));
        ServerTimeUnixSeconds = result.ServerTimeUnixSeconds;
        Status = result.Status;
        _replicaNodeIds = replicas
            .OrderBy(static replica => replica.NodeId, ByteArrayComparer.Instance)
            .Select(static replica => replica.NodeId.ToArray())
            .ToArray();
    }


    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    /// <summary>
    /// The exact DPK2 selected and authenticated by this XPC1 receipt. This is
    /// public pre-key material; the corresponding secrets remain solely with
    /// the responder's pre-key owner.
    /// </summary>
    public VerifiedDpk2Offering Offering => _offering;
    public ReadOnlyMemory<byte> OperationId => _operationId.ToArray();
    public ReadOnlyMemory<byte> RequestHash => _requestHash.ToArray();
    public ReadOnlyMemory<byte> ClaimReceiptHash => _claimReceiptHash.ToArray();
    public ReadOnlyMemory<byte> ExactDpk2Hash => _exactDpk2Hash.ToArray();
    public ReadOnlyMemory<byte> Xpi1Hash => _xpi1Hash.ToArray();
    public ReadOnlyMemory<byte> ResponderAccountId => _responderAccountId.ToArray();
    public ReadOnlyMemory<byte> ResponderDeviceId => _responderDeviceId.ToArray();
    public ulong ResponderDeviceGeneration { get; }
    public ReadOnlyMemory<byte> SignedX25519PrekeyId => _signedX25519PrekeyId.ToArray();
    public ReadOnlyMemory<byte> SelectedOneTimePrekeyId => _selectedOneTimePrekeyId.ToArray();
    public ReadOnlyMemory<byte> MlKemPrekeyId => _mlKemPrekeyId.ToArray();
    public Dpk2PrekeyKind PrekeyKind { get; }
    public ulong ServiceGeneration { get; }
    public ulong PrekeyExpiresAtUnixSeconds { get; }
    public ushort LastResortUseCounter { get; }
    public ulong ClaimCommitGeneration { get; }
    public ulong InventoryEpoch { get; }
    public ushort InventoryIndex { get; }
    public ulong ServerTimeUnixSeconds { get; }
    public Xpc1Status Status { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ReplicaNodeIds =>
        Array.AsReadOnly(_replicaNodeIds.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());

    /// <summary>
    /// Exact transport evidence for the encrypted DPH2 initial payload. The
    /// recovery-test seam has no signed service transcript and must not be
    /// usable for production authoring of that payload.
    /// </summary>
    internal (byte[] Xpk1, byte[] Xpc1Wire) CopyEncryptedInitialClaimTranscript()
    {
        if (_exactXpk1.Length == 0 || _exactXpc1Wire.Length == 0)
            throw new CryptographicException("The verified claim has no exact XPK1/XPC1 wire transcript.");
        return (_exactXpk1.ToArray(), _exactXpc1Wire.ToArray());
    }


    /// <summary>
    /// Binds this witnessed claim to the exact verified responder-side DPH2 and
    /// transfers it into the two-lane initial-session boundary. The returned
    /// capability can be constructed only by this verifier: one lane authorizes
    /// the device-wide private pre-key owner, while the other remains reserved
    /// for Protocol's handshake state machine.
    /// </summary>
    public VerifiedInitialSessionPreKeyClaim BindForInitialSession(
        VerifiedDph2Initiation initiation)
    {
        var binding = ConsumeForHandshake(initiation);
        return new VerifiedInitialSessionPreKeyClaim(
            PrekeyKind,
            LastResortUseCounter,
            _operationId,
            binding.SessionId,
            _exactDpk2Hash,
            binding.Xpc1FullReplayHash,
            binding.Dph2FullReplayHash,
            PrekeyKind == Dpk2PrekeyKind.OneTime ? _selectedOneTimePrekeyId : [],
            _mlKemPrekeyId,
            initiation);
    }

    internal VerifiedXpc1Dph2Binding ConsumeForHandshake(VerifiedDph2Initiation initiation)
    {
        ArgumentNullException.ThrowIfNull(initiation);
        RequireMatchesDph2Header(initiation.Record);
        if (Interlocked.CompareExchange(ref _handshakeConsumed, 1, 0) != 0)
            Fail("ClaimCapabilityConsumed", "The verified XPC1 claim capability is single-use at the handshake boundary.");
        return new VerifiedXpc1Dph2Binding(
            initiation.Record.SessionId.Span,
            _requestHash,
            _fullExactReplayHash,
            initiation.FullReplayHash.Span);
    }

    /// <summary>
    /// Rechecks the immutable tags 1..19 that XPC1 authenticated without
    /// consuming the claim. This exists for the initiator's pre-encryption
    /// transcript pass; only <see cref="ConsumeForHandshake"/> can spend the
    /// receipt after the final tag-20 ciphertext has been verified.
    /// </summary>
    internal void RequireMatchesDph2Header(Dph2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var senderCommitment = MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(record);
        try
        {
            if (!Fixed(_networkId, record.NetworkId.Span) ||
                !Fixed(_responderAccountId, record.ResponderAccountId.Span) ||
                !Fixed(_responderDeviceId, record.ResponderDeviceId.Span) ||
                ResponderDeviceGeneration != record.ResponderDeviceGeneration ||
                !Fixed(_operationId, record.ClaimOperationId.Span) ||
                !Fixed(_claimReceiptHash, record.ClaimReceiptHash.Span) ||
                !Fixed(_exactDpk2Hash, record.ExactDpk2Hash.Span) ||
                !Fixed(_signedX25519PrekeyId, record.SelectedPrekey.SignedX25519PrekeyId.Span) ||
                !Fixed(_selectedOneTimePrekeyId, record.SelectedPrekey.OneTimeX25519PrekeyIdOrZero.Span) ||
                !Fixed(_mlKemPrekeyId, record.SelectedPrekey.MlKemPrekeyId.Span) ||
                PrekeyKind != record.SelectedPrekey.Kind ||
                LastResortUseCounter != record.LastResortUseCounter ||
                !Fixed(_senderEphemeralCommitment, senderCommitment))
                Fail("Dph2ClaimBindingMismatch", "DPH2 does not reproduce the exact verified XPC1 claim closure.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(senderCommitment);
        }
    }

    internal static void RequireExactReplay(
        VerifiedXpc1PreKeyClaimReceipt retained,
        VerifiedXpc1PreKeyClaimReceipt candidate)
    {
        ArgumentNullException.ThrowIfNull(retained);
        ArgumentNullException.ThrowIfNull(candidate);
        if (!Fixed(retained._operationId, candidate._operationId) ||
            !Fixed(retained._requestHash, candidate._requestHash) ||
            !Fixed(retained._fullExactReplayHash, candidate._fullExactReplayHash))
            Fail("ChangedClaimReplay", "An XPC1 replay changed its operation, request, or exact canonical result.");
    }

    internal void RequireExactJournalResult(Xpk1Request request, Xpc1Result result)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(result);
        var fullReplayHash = Xpc1PreKeyClaimReceiptVerifier.ComputeFullExactReplayHash(request, result);
        try
        {
            if (!Fixed(_operationId, request.OperationId.Span) ||
                !Fixed(_requestHash, request.RequestHash.Span) ||
                !Fixed(_operationId, result.OperationId.Span) ||
                !Fixed(_requestHash, result.RequestHash.Span) ||
                !Fixed(_claimReceiptHash, result.Field(18).Span) ||
                !Fixed(_fullExactReplayHash, fullReplayHash))
                Fail("ChangedClaimReplay", "The verified XPC1 receipt does not bind the exact journal result.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fullReplayHash);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new Xpc1PreKeyClaimReceiptException(code, message);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}


internal sealed class VerifiedXpc1Dph2Binding
{
    private readonly byte[] _sessionId;
    private readonly byte[] _requestHash;
    private readonly byte[] _xpc1FullReplayHash;
    private readonly byte[] _dph2FullReplayHash;

    internal VerifiedXpc1Dph2Binding(
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> requestHash,
        ReadOnlySpan<byte> xpc1FullReplayHash,
        ReadOnlySpan<byte> dph2FullReplayHash)
    {
        _sessionId = sessionId.ToArray();
        _requestHash = requestHash.ToArray();
        _xpc1FullReplayHash = xpc1FullReplayHash.ToArray();
        _dph2FullReplayHash = dph2FullReplayHash.ToArray();
    }

    internal ReadOnlySpan<byte> SessionId => _sessionId;
    internal ReadOnlySpan<byte> RequestHash => _requestHash;
    internal ReadOnlySpan<byte> Xpc1FullReplayHash => _xpc1FullReplayHash;
    internal ReadOnlySpan<byte> Dph2FullReplayHash => _dph2FullReplayHash;
}

public static class Xpc1PreKeyClaimReceiptVerifier
{
    private const string ReceiptSignatureDomain = "Deep/ContactResolver/V1/prekey-claim-commit";
    private const string ExactReplayDomain = "Deep/ContactResolver/V1/exact-prekey-claim-replay";
    private const int ReceiptCount = 2;
    private const int ReceiptWidth = 96;
    private const int ReceiptContainerLength = 1 + (ReceiptCount * ReceiptWidth);
    private const int ReceiptTranscriptLength = 138;

    private static void VerifyDpk2Signatures(Dpk2Record dpk2, ReadOnlySpan<byte> signingKey)
    {
        var x25519Input = MessagingWireCryptographicInputs.GetX25519SignedPrekeySignatureInput(dpk2);
        var mlKemInput = MessagingWireCryptographicInputs.GetMlKemPrekeySignatureInput(dpk2);
        var bundleInput = MessagingWireCryptographicInputs.GetPrekeyBundleSignatureInput(dpk2);
        try
        {
            if (!VerifyEd25519(signingKey, x25519Input, dpk2.SignedX25519PrekeySignature.Span) ||
                !VerifyEd25519(signingKey, mlKemInput, dpk2.MlKemPrekeySignature.Span) ||
                !VerifyEd25519(signingKey, bundleInput, dpk2.BundleSignature.Span))
                Fail("Dpk2SignatureInvalid", "The exact DPK2 signatures do not verify under the recipient DPD1 key.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(x25519Input);
            CryptographicOperations.ZeroMemory(mlKemInput);
            CryptographicOperations.ZeroMemory(bundleInput);
        }
    }

    private static void VerifyReplicaReceipts(
        Xpk1Request request,
        Xpc1Result result,
        ReadOnlySpan<byte> exactDpk2Hash,
        Xpi1Record manifest,
        IReadOnlyList<VerifiedNetworkNode> selectedReplicas)
    {
        if (selectedReplicas.Count != ReceiptCount)
            Fail("ReplicaSetMismatch", "The exact ClaimPreKey placement must select exactly two replicas.");
        var replicas = selectedReplicas.OrderBy(static replica => replica.NodeId, ByteArrayComparer.Instance).ToArray();
        if (Fixed(replicas[0].NodeId, replicas[1].NodeId) ||
            Fixed(replicas[0].FailureDomainHash, replicas[1].FailureDomainHash))
            Fail("ReplicaDiversityInvalid", "Claim replicas must have distinct identities and failure domains.");

        var receipts = result.FieldSpan(25);
        if (receipts.Length != ReceiptContainerLength || receipts[0] != ReceiptCount)
            Fail("ReplicaReceiptShapeInvalid", "XPC1 must contain exactly two canonical replica receipts.");

        var transcript = new byte[ReceiptTranscriptLength];
        byte[]? signatureInput = null;
        try
        {
            request.RequestHash.Span.CopyTo(transcript);
            exactDpk2Hash.CopyTo(transcript.AsSpan(32));
            var xpi1Hash = Xpi1Codec.ComputeHash(manifest.CanonicalBytes.Span);
            xpi1Hash.CopyTo(transcript.AsSpan(64));
            result.FieldSpan(17).CopyTo(transcript.AsSpan(96));
            BinaryPrimitives.WriteUInt64BigEndian(transcript.AsSpan(128), ServiceWire.U64(result.FieldSpan(24)));
            BinaryPrimitives.WriteUInt16BigEndian(transcript.AsSpan(136), ServiceWire.U16(result.FieldSpan(23)));
            CryptographicOperations.ZeroMemory(xpi1Hash);
            signatureInput = ContactCodec.SignatureInput(ReceiptSignatureDomain, transcript);

            for (var index = 0; index < ReceiptCount; index++)
            {
                var row = receipts.Slice(1 + (index * ReceiptWidth), ReceiptWidth);
                var identityKey = replicas[index].IdentityPublicKey;
                if (!Fixed(row[..32], replicas[index].NodeId) || identityKey is not { Length: 32 } ||
                    !VerifyEd25519(identityKey, signatureInput, row[32..]))
                    Fail("ReplicaSignatureInvalid", "An XPC1 receipt is not signed by the exact selected replica identity key.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(transcript);
            if (signatureInput is not null) CryptographicOperations.ZeroMemory(signatureInput);
        }
    }

    internal static byte[] ComputeFullExactReplayHash(Xpk1Request request, Xpc1Result result)
    {
        var requestBytes = request.CanonicalBytes.Span;
        var resultBytes = result.CanonicalBytes.Span;
        var tuple = new byte[checked(8 + requestBytes.Length + resultBytes.Length)];
        BinaryPrimitives.WriteUInt32BigEndian(tuple, checked((uint)requestBytes.Length));
        requestBytes.CopyTo(tuple.AsSpan(4));
        var offset = 4 + requestBytes.Length;
        BinaryPrimitives.WriteUInt32BigEndian(tuple.AsSpan(offset), checked((uint)resultBytes.Length));
        resultBytes.CopyTo(tuple.AsSpan(offset + 4));
        try
        {
            return ContactCodec.Sha256Domain(ExactReplayDomain, tuple);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tuple);
        }
    }

    private static bool VerifyEd25519(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64) return false;
        try { return PublicKeyAuth.VerifyDetached(signature.ToArray(), message.ToArray(), publicKey.ToArray()); }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException) { return false; }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static bool MatchesArtifactReference(
        ReadOnlySpan<byte> reference,
        ReadOnlySpan<char> magic,
        ReadOnlySpan<byte> hash) =>
        reference.Length == 38 && hash.Length == 32 &&
        reference[..4].SequenceEqual(System.Text.Encoding.ASCII.GetBytes(magic.ToString())) &&
        BinaryPrimitives.ReadUInt16BigEndian(reference[4..6]) == 1 &&
        Fixed(reference[6..], hash);

    private static bool MatchesApplicationArtifactReference(
        ReadOnlySpan<byte> contactReference,
        ReadOnlySpan<char> magic,
        ReadOnlySpan<byte> applicationReference) =>
        applicationReference.Length == 38 &&
        contactReference.Length == 38 &&
        contactReference[..4].SequenceEqual(System.Text.Encoding.ASCII.GetBytes(magic.ToString())) &&
        BinaryPrimitives.ReadUInt16BigEndian(contactReference[4..6]) == 1 &&
        Fixed(contactReference[6..], applicationReference[6..]);

    [DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new Xpc1PreKeyClaimReceiptException(code, message);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
