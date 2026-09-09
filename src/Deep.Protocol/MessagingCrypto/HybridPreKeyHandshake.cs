using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Deep.Protocol.Identity;
using Sodium;

namespace Deep.Protocol.MessagingCrypto;

// Internal cryptographic engine. Frozen DPK2/DPH2 values enter only through
// VerifiedHybridTranscriptCapability.FromVerifiedInitiation. A public runtime
// producer remains fail-closed until the readiness report's authority and
// atomic-persistence blockers are implemented; no raw-key/provider entrypoint
// may be added as a shortcut.
internal interface IMlKem768Provider
{
    string ProviderIdentifier { get; }
    int DecapsulationKeySize { get; }
    bool EncapsulationKeyMatchesDecapsulationKey(
        ReadOnlySpan<byte> encapsulationKey,
        ReadOnlySpan<byte> decapsulationKey);
    void Encapsulate(ReadOnlySpan<byte> encapsulationKey, Span<byte> ciphertext, Span<byte> sharedSecret);
    void Decapsulate(ReadOnlySpan<byte> decapsulationKey, ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret);
}

internal sealed class HybridInitiatorKeyMaterial : IDisposable
{
    private readonly SecretBuffer _identityPrivate;
    private readonly SecretBuffer _ephemeralPrivate;

    private HybridInitiatorKeyMaterial(SecretBuffer identityPrivate, SecretBuffer ephemeralPrivate)
    {
        _identityPrivate = identityPrivate;
        _ephemeralPrivate = ephemeralPrivate;
    }

    internal static HybridInitiatorKeyMaterial Import(
        ReadOnlySpan<byte> identityPrivate,
        ReadOnlySpan<byte> ephemeralPrivate)
    {
        // Validate the complete input shape before the first owned allocation.
        MessagingCryptoValidation.NonZeroExact(identityPrivate, 32, nameof(identityPrivate));
        MessagingCryptoValidation.NonZeroExact(ephemeralPrivate, 32, nameof(ephemeralPrivate));
        var identity = SecretBuffer.ImportExact(identityPrivate, 32, nameof(identityPrivate));
        try
        {
            var ephemeral = SecretBuffer.ImportExact(ephemeralPrivate, 32, nameof(ephemeralPrivate));
            return new HybridInitiatorKeyMaterial(identity, ephemeral);
        }
        catch
        {
            identity.Dispose();
            throw;
        }
    }

    internal (byte[] Identity, byte[] Ephemeral) CopyForOperation()
    {
        var identity = _identityPrivate.Copy();
        try
        {
            return (identity, _ephemeralPrivate.Copy());
        }
        catch
        {
            CryptographicOperations.ZeroMemory(identity);
            throw;
        }
    }

    public void Dispose()
    {
        _identityPrivate.Dispose();
        _ephemeralPrivate.Dispose();
    }
}

internal sealed class HybridResponderStaticKeyMaterial : IDisposable
{
    private readonly SecretBuffer _identityPrivate;
    private readonly SecretBuffer _signedPreKeyPrivate;

    private HybridResponderStaticKeyMaterial(SecretBuffer identityPrivate, SecretBuffer signedPreKeyPrivate)
    {
        _identityPrivate = identityPrivate;
        _signedPreKeyPrivate = signedPreKeyPrivate;
    }

    internal static HybridResponderStaticKeyMaterial Import(
        ReadOnlySpan<byte> identityPrivate,
        ReadOnlySpan<byte> signedPreKeyPrivate)
    {
        MessagingCryptoValidation.NonZeroExact(identityPrivate, 32, nameof(identityPrivate));
        MessagingCryptoValidation.NonZeroExact(signedPreKeyPrivate, 32, nameof(signedPreKeyPrivate));
        var identity = SecretBuffer.ImportExact(identityPrivate, 32, nameof(identityPrivate));
        try
        {
            var signedPreKey = SecretBuffer.ImportExact(signedPreKeyPrivate, 32, nameof(signedPreKeyPrivate));
            return new HybridResponderStaticKeyMaterial(identity, signedPreKey);
        }
        catch
        {
            identity.Dispose();
            throw;
        }
    }

    internal (byte[] Identity, byte[] SignedPreKey) CopyForOperation()
    {
        var identity = _identityPrivate.Copy();
        try
        {
            return (identity, _signedPreKeyPrivate.Copy());
        }
        catch
        {
            CryptographicOperations.ZeroMemory(identity);
            throw;
        }
    }

    public void Dispose()
    {
        _identityPrivate.Dispose();
        _signedPreKeyPrivate.Dispose();
    }
}

internal sealed class PreparedHybridInitiation : IDisposable
{
    private SecretBuffer? _dh1;
    private SecretBuffer? _dh2;
    private SecretBuffer? _dh3;
    private SecretBuffer? _dh4;
    private SecretBuffer? _pq;
    private byte[]? _ciphertext;
    private int _state;

    internal PreparedHybridInitiation(
        ReadOnlySpan<byte> dh1,
        ReadOnlySpan<byte> dh2,
        ReadOnlySpan<byte> dh3,
        ReadOnlySpan<byte> dh4,
        ReadOnlySpan<byte> pq,
        ReadOnlySpan<byte> ciphertext)
    {
        MessagingCryptoValidation.NonZeroExact(dh1, 32, nameof(dh1));
        MessagingCryptoValidation.NonZeroExact(dh2, 32, nameof(dh2));
        MessagingCryptoValidation.NonZeroExact(dh3, 32, nameof(dh3));
        if (!dh4.IsEmpty) MessagingCryptoValidation.NonZeroExact(dh4, 32, nameof(dh4));
        MessagingCryptoValidation.NonZeroExact(pq, 32, nameof(pq));
        MessagingCryptoValidation.Exact(ciphertext, 1088, nameof(ciphertext));
        SecretBuffer? ownedDh1 = null, ownedDh2 = null, ownedDh3 = null, ownedDh4 = null, ownedPq = null;
        try
        {
            ownedDh1 = SecretBuffer.ImportExact(dh1, 32, nameof(dh1));
            ownedDh2 = SecretBuffer.ImportExact(dh2, 32, nameof(dh2));
            ownedDh3 = SecretBuffer.ImportExact(dh3, 32, nameof(dh3));
            ownedDh4 = dh4.IsEmpty ? null : SecretBuffer.ImportExact(dh4, 32, nameof(dh4));
            ownedPq = SecretBuffer.ImportExact(pq, 32, nameof(pq));
            _ciphertext = ciphertext.ToArray();
            _dh1 = ownedDh1; ownedDh1 = null;
            _dh2 = ownedDh2; ownedDh2 = null;
            _dh3 = ownedDh3; ownedDh3 = null;
            _dh4 = ownedDh4; ownedDh4 = null;
            _pq = ownedPq; ownedPq = null;
        }
        finally
        {
            ownedDh1?.Dispose();
            ownedDh2?.Dispose();
            ownedDh3?.Dispose();
            ownedDh4?.Dispose();
            ownedPq?.Dispose();
        }
    }

    internal ReadOnlyMemory<byte> Ciphertext => _ciphertext?.ToArray() ?? throw Consumed();

    internal PreparedHybridInitiationData Consume()
    {
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0) throw Consumed();
        byte[]? dh1 = null, dh2 = null, dh3 = null, dh4 = null, pq = null;
        try
        {
            dh1 = _dh1!.Copy();
            dh2 = _dh2!.Copy();
            dh3 = _dh3!.Copy();
            dh4 = _dh4?.Copy();
            pq = _pq!.Copy();
            var ciphertext = _ciphertext!;
            DisposeOwned();
            _ciphertext = null;
            var result = new PreparedHybridInitiationData(dh1, dh2, dh3, dh4, pq, ciphertext);
            dh1 = dh2 = dh3 = dh4 = pq = null;
            return result;
        }
        finally
        {
            if (dh1 is not null) CryptographicOperations.ZeroMemory(dh1);
            if (dh2 is not null) CryptographicOperations.ZeroMemory(dh2);
            if (dh3 is not null) CryptographicOperations.ZeroMemory(dh3);
            if (dh4 is not null) CryptographicOperations.ZeroMemory(dh4);
            if (pq is not null) CryptographicOperations.ZeroMemory(pq);
            DisposeOwned();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _state, 2) == 0) DisposeOwned();
    }

    private void DisposeOwned()
    {
        _dh1?.Dispose(); _dh1 = null;
        _dh2?.Dispose(); _dh2 = null;
        _dh3?.Dispose(); _dh3 = null;
        _dh4?.Dispose(); _dh4 = null;
        _pq?.Dispose(); _pq = null;
    }

    private static MessagingCryptoException Consumed() => new(
        MessagingCryptoError.CapabilityConsumed,
        "The prepared hybrid initiation is single-use.");
}

internal sealed class PreparedHybridInitiationData : IDisposable
{
    internal PreparedHybridInitiationData(
        byte[] dh1, byte[] dh2, byte[] dh3, byte[]? dh4, byte[] pq, byte[] ciphertext)
    {
        Dh1 = dh1; Dh2 = dh2; Dh3 = dh3; Dh4 = dh4; Pq = pq; Ciphertext = ciphertext;
    }

    internal byte[] Dh1 { get; }
    internal byte[] Dh2 { get; }
    internal byte[] Dh3 { get; }
    internal byte[]? Dh4 { get; }
    internal byte[] Pq { get; }
    internal byte[] Ciphertext { get; }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(Dh1);
        CryptographicOperations.ZeroMemory(Dh2);
        CryptographicOperations.ZeroMemory(Dh3);
        if (Dh4 is not null) CryptographicOperations.ZeroMemory(Dh4);
        CryptographicOperations.ZeroMemory(Pq);
    }
}

internal sealed class HybridHandshakeSecrets : IDisposable
{
    private readonly byte[] _transcriptHash;
    private readonly SecretBuffer _ecRoot;
    private readonly SecretBuffer _spqrRoot;
    private readonly SecretBuffer _initialAeadKey;
    private int _tripleRatchetSeedClaimed;

    internal HybridHandshakeSecrets(
        ReadOnlySpan<byte> transcriptHash,
        RatchetStateBinding stateBinding,
        ReadOnlySpan<byte> ecRoot,
        ReadOnlySpan<byte> spqrRoot,
        ReadOnlySpan<byte> initialAeadKey)
    {
        MessagingCryptoValidation.NonZeroExact(transcriptHash, 64, nameof(transcriptHash));
        ArgumentNullException.ThrowIfNull(stateBinding);
        MessagingCryptoValidation.NonZeroExact(ecRoot, 32, nameof(ecRoot));
        MessagingCryptoValidation.NonZeroExact(spqrRoot, 32, nameof(spqrRoot));
        MessagingCryptoValidation.NonZeroExact(initialAeadKey, 32, nameof(initialAeadKey));
        _transcriptHash = transcriptHash.ToArray();
        StateBinding = stateBinding;
        SecretBuffer? ec = null, spqr = null, initial = null;
        try
        {
            ec = SecretBuffer.ImportExact(ecRoot, 32, nameof(ecRoot));
            MessagingCryptoFaultInjection.OwnedSecret("handshake-secrets.ec", ec);
            spqr = SecretBuffer.ImportExact(spqrRoot, 32, nameof(spqrRoot));
            MessagingCryptoFaultInjection.OwnedSecret("handshake-secrets.spqr", spqr);
            initial = SecretBuffer.ImportExact(initialAeadKey, 32, nameof(initialAeadKey));
            MessagingCryptoFaultInjection.OwnedSecret("handshake-secrets.initial", initial);
            _ecRoot = ec; ec = null;
            _spqrRoot = spqr; spqr = null;
            _initialAeadKey = initial; initial = null;
        }
        finally
        {
            ec?.Dispose();
            spqr?.Dispose();
            initial?.Dispose();
        }
    }

    internal RatchetStateBinding StateBinding { get; }
    internal ReadOnlyMemory<byte> TranscriptHash => _transcriptHash.ToArray();
    internal void UseEcRoot(MessagingSecretAction action) => _ecRoot.Use(action);
    internal void UseSpqrRoot(MessagingSecretAction action) => _spqrRoot.Use(action);
    internal void UseInitialAeadKey(MessagingSecretAction action) => _initialAeadKey.Use(action);

    internal VerifiedTripleRatchetSeedCapability ClaimTripleRatchetSeed()
    {
        if (Interlocked.CompareExchange(ref _tripleRatchetSeedClaimed, 1, 0) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.CapabilityConsumed,
                "The verified handshake Triple-Ratchet seed was already claimed.");
        return VerifiedTripleRatchetSeedCapability.CreateFromVerifiedRoots(
            StateBinding,
            _ecRoot,
            _spqrRoot);
    }

    public void Dispose()
    {
        _ecRoot.Dispose();
        _spqrRoot.Dispose();
        _initialAeadKey.Dispose();
    }
}

internal static class HybridPreKeyHandshake
{
    internal static PreparedHybridInitiation PrepareInitiation(
        LocalDeviceX25519AgreementLease initiatorIdentityAgreement,
        ReadOnlySpan<byte> operationBinding,
        ReadOnlySpan<byte> initiatorEphemeralPrivate,
        ReadOnlySpan<byte> responderIdentityPublic,
        ReadOnlySpan<byte> responderSignedPreKeyPublic,
        ReadOnlySpan<byte> responderOneTimePreKeyPublic,
        ReadOnlySpan<byte> responderMlKemEncapsulationKey,
        IMlKem768Provider mlKem)
    {
        ArgumentNullException.ThrowIfNull(initiatorIdentityAgreement);
        ValidateProvider(mlKem);
        MessagingCryptoValidation.NonZeroExact(
            operationBinding, 32, nameof(operationBinding));
        MessagingCryptoValidation.NonZeroExact(
            initiatorEphemeralPrivate, 32, nameof(initiatorEphemeralPrivate));
        MessagingCryptoValidation.NonZeroExact(
            responderIdentityPublic, 32, nameof(responderIdentityPublic));
        MessagingCryptoValidation.NonZeroExact(
            responderSignedPreKeyPublic, 32, nameof(responderSignedPreKeyPublic));
        if (!responderOneTimePreKeyPublic.IsEmpty)
        {
            MessagingCryptoValidation.NonZeroExact(
                responderOneTimePreKeyPublic, 32, nameof(responderOneTimePreKeyPublic));
        }
        MessagingCryptoValidation.Exact(
            responderMlKemEncapsulationKey, 1184, nameof(responderMlKemEncapsulationKey));

        var ephemeralPrivate = initiatorEphemeralPrivate.ToArray();
        var identityPublic = responderIdentityPublic.ToArray();
        var signedPublic = responderSignedPreKeyPublic.ToArray();
        var oneTimePublic = responderOneTimePreKeyPublic.ToArray();
        var mlKemPublic = responderMlKemEncapsulationKey.ToArray();
        byte[]? dh1 = null, dh2 = null, dh3 = null, dh4 = null;
        byte[]? pq = null;
        byte[]? ciphertext = null;
        try
        {
            MessagingCryptoFaultInjection.ManagedSecret(
                "initiator.ephemeral-private", ephemeralPrivate);
            using (var ownedDh1 = initiatorIdentityAgreement.AgreeOnceForExpectedPeer(
                       LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                       operationBinding,
                       signedPublic))
            {
                dh1 = ownedDh1.Consume(static secret => secret.ToArray());
            }
            pq = new byte[32];
            ciphertext = new byte[1088];
            dh2 = Agree(ephemeralPrivate, identityPublic);
            dh3 = Agree(ephemeralPrivate, signedPublic);
            if (oneTimePublic.Length != 0) dh4 = Agree(ephemeralPrivate, oneTimePublic);
            mlKem.Encapsulate(mlKemPublic, ciphertext, pq);
            MessagingCryptoValidation.NonZeroExact(pq, 32, nameof(pq));
            MessagingCryptoFaultInjection.ManagedSecret("initiator.pq", pq);
            return new PreparedHybridInitiation(dh1, dh2, dh3, dh4 ?? [], pq, ciphertext);
        }
        catch (MessagingCryptoException) { throw; }
        catch (Exception exception)
        {
            throw new MessagingCryptoException(
                MessagingCryptoError.ProviderFailure,
                "The approved ML-KEM provider rejected encapsulation.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ephemeralPrivate);
            CryptographicOperations.ZeroMemory(identityPublic);
            CryptographicOperations.ZeroMemory(signedPublic);
            CryptographicOperations.ZeroMemory(oneTimePublic);
            CryptographicOperations.ZeroMemory(mlKemPublic);
            if (dh1 is not null) CryptographicOperations.ZeroMemory(dh1);
            if (dh2 is not null) CryptographicOperations.ZeroMemory(dh2);
            if (dh3 is not null) CryptographicOperations.ZeroMemory(dh3);
            if (dh4 is not null) CryptographicOperations.ZeroMemory(dh4);
            if (pq is not null) CryptographicOperations.ZeroMemory(pq);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    internal static PreparedHybridInitiation PrepareInitiation(
        HybridInitiatorKeyMaterial initiator,
        ReadOnlySpan<byte> responderIdentityPublic,
        ReadOnlySpan<byte> responderSignedPreKeyPublic,
        ReadOnlySpan<byte> responderOneTimePreKeyPublic,
        ReadOnlySpan<byte> responderMlKemEncapsulationKey,
        IMlKem768Provider mlKem)
    {
        ArgumentNullException.ThrowIfNull(initiator);
        ValidateProvider(mlKem);
        MessagingCryptoValidation.NonZeroExact(responderIdentityPublic, 32, nameof(responderIdentityPublic));
        MessagingCryptoValidation.NonZeroExact(responderSignedPreKeyPublic, 32, nameof(responderSignedPreKeyPublic));
        if (!responderOneTimePreKeyPublic.IsEmpty)
            MessagingCryptoValidation.NonZeroExact(responderOneTimePreKeyPublic, 32, nameof(responderOneTimePreKeyPublic));
        MessagingCryptoValidation.Exact(
            responderMlKemEncapsulationKey, 1184, nameof(responderMlKemEncapsulationKey));

        var identityPublic = responderIdentityPublic.ToArray();
        var signedPublic = responderSignedPreKeyPublic.ToArray();
        var oneTimePublic = responderOneTimePreKeyPublic.ToArray();
        var mlKemPublic = responderMlKemEncapsulationKey.ToArray();
        var (identityPrivate, ephemeralPrivate) = initiator.CopyForOperation();
        byte[]? dh1 = null, dh2 = null, dh3 = null, dh4 = null;
        byte[]? pq = null;
        byte[]? ciphertext = null;
        try
        {
            MessagingCryptoFaultInjection.ManagedSecret("initiator.identity-private", identityPrivate);
            MessagingCryptoFaultInjection.ManagedSecret("initiator.ephemeral-private", ephemeralPrivate);
            pq = new byte[32];
            ciphertext = new byte[1088];
            dh1 = Agree(identityPrivate, signedPublic);
            dh2 = Agree(ephemeralPrivate, identityPublic);
            dh3 = Agree(ephemeralPrivate, signedPublic);
            if (oneTimePublic.Length != 0) dh4 = Agree(ephemeralPrivate, oneTimePublic);
            mlKem.Encapsulate(mlKemPublic, ciphertext, pq);
            MessagingCryptoValidation.NonZeroExact(pq, 32, nameof(pq));
            MessagingCryptoFaultInjection.ManagedSecret("initiator.pq", pq);
            return new PreparedHybridInitiation(dh1, dh2, dh3, dh4 ?? [], pq, ciphertext);
        }
        catch (MessagingCryptoException) { throw; }
        catch (Exception exception)
        {
            throw new MessagingCryptoException(
                MessagingCryptoError.ProviderFailure,
                "The ML-KEM provider rejected encapsulation.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(identityPrivate);
            CryptographicOperations.ZeroMemory(ephemeralPrivate);
            CryptographicOperations.ZeroMemory(identityPublic);
            CryptographicOperations.ZeroMemory(signedPublic);
            CryptographicOperations.ZeroMemory(oneTimePublic);
            CryptographicOperations.ZeroMemory(mlKemPublic);
            if (dh1 is not null) CryptographicOperations.ZeroMemory(dh1);
            if (dh2 is not null) CryptographicOperations.ZeroMemory(dh2);
            if (dh3 is not null) CryptographicOperations.ZeroMemory(dh3);
            if (dh4 is not null) CryptographicOperations.ZeroMemory(dh4);
            if (pq is not null) CryptographicOperations.ZeroMemory(pq);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    internal static HybridHandshakeSecrets CompleteInitiation(
        PreparedHybridInitiation prepared,
        VerifiedHybridTranscriptCapability verifiedTranscript)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(verifiedTranscript);
        using var data = prepared.Consume();
        var transcript = verifiedTranscript.Consume(data.Ciphertext);
        try
        {
            return Derive(
                transcript.TranscriptHash, transcript.StateBinding,
                data.Dh1, data.Dh2, data.Dh3, data.Dh4, data.Pq);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(transcript.TranscriptHash);
        }
    }

    internal static HybridHandshakeSecrets AcceptInitiation(
        HybridResponderStaticKeyMaterial responder,
        ClaimedHybridPreKeyLease claimedPreKeys,
        ReadOnlySpan<byte> initiatorIdentityPublic,
        ReadOnlySpan<byte> initiatorEphemeralPublic,
        VerifiedHybridTranscriptCapability verifiedTranscript,
        IMlKem768Provider mlKem)
    {
        ArgumentNullException.ThrowIfNull(responder);
        ArgumentNullException.ThrowIfNull(claimedPreKeys);
        ArgumentNullException.ThrowIfNull(verifiedTranscript);
        ValidateProvider(mlKem);
        MessagingCryptoValidation.NonZeroExact(initiatorIdentityPublic, 32, nameof(initiatorIdentityPublic));
        MessagingCryptoValidation.NonZeroExact(initiatorEphemeralPublic, 32, nameof(initiatorEphemeralPublic));
        byte[]? initiatorIdentity = null, initiatorEphemeral = null;
        byte[]? identityPrivate = null, signedPrivate = null;
        ClaimedHybridPreKeyData? claimed = null;
        VerifiedHybridTranscriptData? transcript = null;
        byte[]? dh1 = null, dh2 = null, dh3 = null, dh4 = null;
        var pq = new byte[32];
        try
        {
            claimed = claimedPreKeys.ConsumeForHandshake();
            transcript = verifiedTranscript.ConsumeBoundForResponder();
            if (transcript.FullDph2ReplayHash is null)
                throw new MessagingCryptoException(
                    MessagingCryptoError.InvalidInput,
                    "The responder initiation lacks an exact full-DPH2 replay hash.");
            if (!MessagingCryptoValidation.FixedEquals(
                    claimed.SessionId,
                    transcript.StateBinding.SessionId.Span) ||
                !MessagingCryptoValidation.FixedEquals(
                    claimed.InitiationHash,
                    transcript.FullDph2ReplayHash) ||
                !OptionalEquals(claimed.X25519PreKeyId, transcript.X25519PreKeyId) ||
                !MessagingCryptoValidation.FixedEquals(
                    claimed.MlKemPreKeyId,
                    transcript.MlKemPreKeyId))
                throw new MessagingCryptoException(
                    MessagingCryptoError.PreKeyConflict,
                    "The claimed hybrid prekeys are not bound to this verified initiation.");
            if (claimed.MlKemDecapsulationKey.Length != mlKem.DecapsulationKeySize)
                throw new MessagingCryptoException(
                    MessagingCryptoError.InvalidInput,
                    "The claimed ML-KEM key does not match the selected provider representation.");
            initiatorIdentity = initiatorIdentityPublic.ToArray();
            initiatorEphemeral = initiatorEphemeralPublic.ToArray();
            (identityPrivate, signedPrivate) = responder.CopyForOperation();
            dh1 = Agree(signedPrivate, initiatorIdentity);
            dh2 = Agree(identityPrivate, initiatorEphemeral);
            dh3 = Agree(signedPrivate, initiatorEphemeral);
            if (claimed.X25519PrivateKey is not null)
                dh4 = Agree(claimed.X25519PrivateKey, initiatorEphemeral);
            mlKem.Decapsulate(claimed.MlKemDecapsulationKey, transcript.MlKemCiphertext, pq);
            MessagingCryptoValidation.NonZeroExact(pq, 32, nameof(pq));
            return Derive(
                transcript.TranscriptHash, transcript.StateBinding,
                dh1, dh2, dh3, dh4, pq);
        }
        catch (MessagingCryptoException) { throw; }
        catch (Exception exception)
        {
            throw new MessagingCryptoException(
                MessagingCryptoError.ProviderFailure,
                "The ML-KEM provider rejected decapsulation.", exception);
        }
        finally
        {
            if (identityPrivate is not null) CryptographicOperations.ZeroMemory(identityPrivate);
            if (signedPrivate is not null) CryptographicOperations.ZeroMemory(signedPrivate);
            if (initiatorIdentity is not null) CryptographicOperations.ZeroMemory(initiatorIdentity);
            if (initiatorEphemeral is not null) CryptographicOperations.ZeroMemory(initiatorEphemeral);
            if (dh1 is not null) CryptographicOperations.ZeroMemory(dh1);
            if (dh2 is not null) CryptographicOperations.ZeroMemory(dh2);
            if (dh3 is not null) CryptographicOperations.ZeroMemory(dh3);
            if (dh4 is not null) CryptographicOperations.ZeroMemory(dh4);
            CryptographicOperations.ZeroMemory(pq);
            claimed?.Dispose();
            if (transcript is not null)
            {
                CryptographicOperations.ZeroMemory(transcript.TranscriptHash);
                CryptographicOperations.ZeroMemory(transcript.MlKemCiphertext);
                if (transcript.FullDph2ReplayHash is not null)
                    CryptographicOperations.ZeroMemory(transcript.FullDph2ReplayHash);
            }
        }
    }

    private static HybridHandshakeSecrets Derive(
        ReadOnlySpan<byte> transcriptHash,
        RatchetStateBinding stateBinding,
        ReadOnlySpan<byte> dh1,
        ReadOnlySpan<byte> dh2,
        ReadOnlySpan<byte> dh3,
        byte[]? dh4,
        ReadOnlySpan<byte> pq)
    {
        var ikm = new byte[dh4 is null ? 128 : 160];
        Span<byte> prk = stackalloc byte[64];
        try
        {
            dh1.CopyTo(ikm); dh2.CopyTo(ikm.AsSpan(32)); dh3.CopyTo(ikm.AsSpan(64));
            var pqOffset = 96;
            if (dh4 is not null) { dh4.CopyTo(ikm, 96); pqOffset = 128; }
            pq.CopyTo(ikm.AsSpan(pqOffset));
            if (HKDF.Extract(HashAlgorithmName.SHA512, ikm, transcriptHash, prk) != prk.Length)
                throw new CryptographicException("HKDF extract returned an unexpected length.");
            byte[]? ec = null, spqr = null, initial = null;
            try
            {
                ec = Expand(prk, "Deep/Messaging/V2/ec-root", transcriptHash);
                MessagingCryptoFaultInjection.ManagedSecret("derive.ec-root", ec);
                spqr = Expand(prk, "Deep/Messaging/V2/spqr-root", transcriptHash);
                MessagingCryptoFaultInjection.ManagedSecret("derive.spqr-root", spqr);
                initial = Expand(prk, "Deep/Messaging/V2/initial-aead", transcriptHash);
                MessagingCryptoFaultInjection.ManagedSecret("derive.initial-aead", initial);
                return new HybridHandshakeSecrets(transcriptHash, stateBinding, ec, spqr, initial);
            }
            finally
            {
                if (ec is not null) CryptographicOperations.ZeroMemory(ec);
                if (spqr is not null) CryptographicOperations.ZeroMemory(spqr);
                if (initial is not null) CryptographicOperations.ZeroMemory(initial);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
            CryptographicOperations.ZeroMemory(prk);
        }
    }

    private static byte[] Expand(ReadOnlySpan<byte> prk, string label, ReadOnlySpan<byte> transcriptHash)
    {
        var domain = Encoding.ASCII.GetBytes(label);
        var info = new byte[domain.Length + 1 + 4 + transcriptHash.Length];
        domain.CopyTo(info, 0);
        BinaryPrimitives.WriteUInt32BigEndian(info.AsSpan(domain.Length + 1), (uint)transcriptHash.Length);
        transcriptHash.CopyTo(info.AsSpan(domain.Length + 5));
        var result = new byte[32];
        var completed = false;
        try
        {
            HKDF.Expand(HashAlgorithmName.SHA512, prk, result, info);
            MessagingCryptoFaultInjection.ManagedSecret($"expand.{label}", result);
            completed = true;
            return result;
        }
        finally
        {
            if (!completed) CryptographicOperations.ZeroMemory(result);
            CryptographicOperations.ZeroMemory(info);
        }
    }

    private static byte[] Agree(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        if (MessagingCryptoValidation.IsZero(publicKey))
            throw new MessagingCryptoException(
                MessagingCryptoError.AllZeroSharedSecret,
                "An all-zero X25519 public key is forbidden.");
        var privateCopy = privateKey.ToArray();
        var publicCopy = publicKey.ToArray();
        try
        {
            var secret = ScalarMult.Mult(privateCopy, publicCopy);
            if (secret.Length == 32 && !MessagingCryptoValidation.IsZero(secret)) return secret;
            CryptographicOperations.ZeroMemory(secret);
            throw new MessagingCryptoException(
                MessagingCryptoError.AllZeroSharedSecret,
                "X25519 produced an all-zero shared secret.");
        }
        catch (MessagingCryptoException) { throw; }
        catch (Exception exception)
        {
            throw new MessagingCryptoException(
                MessagingCryptoError.ProviderFailure, "X25519 agreement failed.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateCopy);
            CryptographicOperations.ZeroMemory(publicCopy);
        }
    }

    private static void ValidateProvider(IMlKem768Provider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        if (string.IsNullOrWhiteSpace(provider.ProviderIdentifier) ||
            provider.DecapsulationKeySize is < 1 or > 4096)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The dark ML-KEM provider metadata is invalid.");
    }

    private static bool OptionalEquals(byte[]? left, byte[]? right) =>
        left is null && right is null ||
        left is not null && right is not null && MessagingCryptoValidation.FixedEquals(left, right);
}
