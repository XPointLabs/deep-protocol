using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.MessagingCrypto;

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
internal delegate TripleRatchetState ResponderInitialRatchetStateFactory(
    VerifiedTripleRatchetSeedCapability seed,
    ReadOnlySpan<byte> signedPreKeyPrivate,
    ReadOnlySpan<byte> signedPreKeyPublic,
    ReadOnlySpan<byte> initiatorInitialRatchetPublic,
    int maximumMessagesWithoutPqInjection);
#endif

/// <summary>
/// Production responder boundary that turns one verifier-minted, single-use
/// ContactV1 claim handoff into the exact initial TRS1 state. The returned
/// plaintext is secret state and must be sealed immediately by the caller's
/// authenticated atomic store.
/// </summary>
public sealed class ManagedResponderInitialSessionFactory : IDisposable
{
    private readonly object _gate = new();
    private SecretBuffer? _responderIdentityPrivate;
    private SecretBuffer? _responderSignedPreKeyPrivate;
    private readonly int _maximumMessagesWithoutPqInjection;
    private bool _disposed;

    /// <summary>
    /// Creates a responder factory whose rotating DPK2 secrets must be supplied
    /// through a restored opaque capability for each initial session.
    /// </summary>
    public ManagedResponderInitialSessionFactory(
        ReadOnlySpan<byte> responderIdentityPrivateScalar,
        int maximumMessagesWithoutPqInjection)
    {
        ValidateMaximum(maximumMessagesWithoutPqInjection);
        MessagingCryptoValidation.NonZeroExact(
            responderIdentityPrivateScalar,
            MessagingCryptoConstants.X25519KeySize,
            nameof(responderIdentityPrivateScalar));
        _responderIdentityPrivate = SecretBuffer.ImportExact(
            responderIdentityPrivateScalar,
            MessagingCryptoConstants.X25519KeySize,
            nameof(responderIdentityPrivateScalar));
        MessagingCryptoFaultInjection.OwnedSecret(
            "initial-session.factory.identity-private", _responderIdentityPrivate);
        _maximumMessagesWithoutPqInjection = maximumMessagesWithoutPqInjection;
    }

    public ManagedResponderInitialSessionFactory(
        ReadOnlySpan<byte> responderIdentityPrivateScalar,
        ReadOnlySpan<byte> responderSignedPreKeyPrivateScalar,
        int maximumMessagesWithoutPqInjection)
    {
        ValidateMaximum(maximumMessagesWithoutPqInjection);

        SecretBuffer? identity = null;
        SecretBuffer? signedPreKey = null;
        try
        {
            MessagingCryptoValidation.NonZeroExact(
                responderIdentityPrivateScalar,
                MessagingCryptoConstants.X25519KeySize,
                nameof(responderIdentityPrivateScalar));
            MessagingCryptoValidation.NonZeroExact(
                responderSignedPreKeyPrivateScalar,
                MessagingCryptoConstants.X25519KeySize,
                nameof(responderSignedPreKeyPrivateScalar));
            identity = SecretBuffer.ImportExact(
                responderIdentityPrivateScalar,
                MessagingCryptoConstants.X25519KeySize,
                nameof(responderIdentityPrivateScalar));
            MessagingCryptoFaultInjection.OwnedSecret(
                "initial-session.factory.identity-private", identity);
            signedPreKey = SecretBuffer.ImportExact(
                responderSignedPreKeyPrivateScalar,
                MessagingCryptoConstants.X25519KeySize,
                nameof(responderSignedPreKeyPrivateScalar));
            MessagingCryptoFaultInjection.OwnedSecret(
                "initial-session.factory.signed-prekey-private", signedPreKey);
            _responderIdentityPrivate = identity;
            _responderSignedPreKeyPrivate = signedPreKey;
            _maximumMessagesWithoutPqInjection = maximumMessagesWithoutPqInjection;
            identity = null;
            signedPreKey = null;
        }
        finally
        {
            identity?.Dispose();
            signedPreKey?.Dispose();
        }
    }

    /// <summary>
    /// Consumes only Protocol's lane of <paramref name="verifiedClaim"/>. The
    /// device-owner lane remains independent. Every invocation, including a
    /// rejected key mismatch, permanently consumes the Protocol lane.
    /// </summary>
    public byte[] CreateExactTrs1(
        VerifiedInitialSessionPreKeyClaim verifiedClaim,
        ReadOnlySpan<byte> claimedOneTimeX25519PrivateScalar,
        ReadOnlySpan<byte> claimedMlKemDecapsulationSecret) =>
        CreateExactTrs1Core(
            verifiedClaim,
            claimedOneTimeX25519PrivateScalar,
            claimedMlKemDecapsulationSecret,
            restoredPreKeys: null,
            testMlKem: null,
            testStateFactory: null);

    /// <summary>
    /// Consumes the verifier-minted claim and an exact-DPK2-bound restored
    /// capability to create TRS1 without exposing persisted pre-key secrets.
    /// </summary>
    public byte[] CreateExactTrs1(
        VerifiedInitialSessionPreKeyClaim verifiedClaim,
        RestoredDpk2PreKeySecretCapability restoredPreKeys)
    {
        ArgumentNullException.ThrowIfNull(restoredPreKeys);
        return CreateExactTrs1Core(
            verifiedClaim,
            ReadOnlySpan<byte>.Empty,
            ReadOnlySpan<byte>.Empty,
            restoredPreKeys,
            testMlKem: null,
            testStateFactory: null);
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal byte[] CreateExactTrs1ForTests(
        VerifiedInitialSessionPreKeyClaim verifiedClaim,
        ReadOnlySpan<byte> claimedOneTimeX25519PrivateScalar,
        ReadOnlySpan<byte> claimedMlKemDecapsulationSecret,
        IMlKem768Provider mlKem,
        ResponderInitialRatchetStateFactory stateFactory) =>
        CreateExactTrs1Core(
            verifiedClaim,
            claimedOneTimeX25519PrivateScalar,
            claimedMlKemDecapsulationSecret,
            restoredPreKeys: null,
            mlKem ?? throw new ArgumentNullException(nameof(mlKem)),
            stateFactory ?? throw new ArgumentNullException(nameof(stateFactory)));

    internal byte[] CreateExactTrs1ForTests(
        VerifiedInitialSessionPreKeyClaim verifiedClaim,
        RestoredDpk2PreKeySecretCapability restoredPreKeys,
        IMlKem768Provider mlKem,
        ResponderInitialRatchetStateFactory stateFactory)
    {
        ArgumentNullException.ThrowIfNull(restoredPreKeys);
        return CreateExactTrs1Core(
            verifiedClaim,
            ReadOnlySpan<byte>.Empty,
            ReadOnlySpan<byte>.Empty,
            restoredPreKeys,
            mlKem ?? throw new ArgumentNullException(nameof(mlKem)),
            stateFactory ?? throw new ArgumentNullException(nameof(stateFactory)));
    }
#endif

    private byte[] CreateExactTrs1Core(
        VerifiedInitialSessionPreKeyClaim verifiedClaim,
        ReadOnlySpan<byte> claimedOneTimeX25519PrivateScalar,
        ReadOnlySpan<byte> claimedMlKemDecapsulationSecret,
        RestoredDpk2PreKeySecretCapability? restoredPreKeys,
        IMlKem768Provider? testMlKem,
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
        ResponderInitialRatchetStateFactory? testStateFactory)
#else
        object? testStateFactory)
#endif
    {
        ArgumentNullException.ThrowIfNull(verifiedClaim);
        using var claim = verifiedClaim.ConsumeForProtocolHandshake();
        using var restoredMaterial = restoredPreKeys?.ConsumeForHandshake(claim);

        byte[]? identityPrivate = null;
        byte[]? signedPreKeyPrivate = null;
        SecretBuffer? oneTimePrivate = null;
        SecretBuffer? mlKemPrivate = null;
        byte[]? exactTrs1 = null;
        IDisposable? ownedMlKem = null;
        var ownershipTransferred = false;
        try
        {
            identityPrivate = CopyIdentitySecret();
            signedPreKeyPrivate = restoredMaterial is null
                ? CopySignedPreKeySecret()
                : restoredMaterial.SignedPrivate.ToArray();
            var oneTimeSecret = restoredMaterial?.OneTimePrivate is { } restoredOneTime
                ? restoredOneTime.AsSpan()
                : claimedOneTimeX25519PrivateScalar;
            var mlKemSecret = restoredMaterial is null
                ? claimedMlKemDecapsulationSecret
                : restoredMaterial.MlKemSecret.AsSpan();
            var initiation = claim.Initiation;
            var dph2 = initiation.Record;
            var dpk2 = initiation.Offering.Record;
            RequireExactClaimBinding(claim, initiation);
            RequirePrivateMatchesPublic(
                identityPrivate,
                dpk2.DeviceAgreementPublicKeySpan,
                "The responder identity scalar differs from the verified DPK2 device agreement key.");
            RequirePrivateMatchesPublic(
                signedPreKeyPrivate,
                dpk2.SignedX25519PrekeyPublicSpan,
                "The responder signed-prekey scalar differs from the verified DPK2 signed prekey.");

            if (claim.Kind == Dpk2PrekeyKind.OneTime)
            {
                MessagingCryptoValidation.NonZeroExact(
                    oneTimeSecret,
                    MessagingCryptoConstants.X25519KeySize,
                    nameof(claimedOneTimeX25519PrivateScalar));
                RequirePrivateMatchesPublic(
                    oneTimeSecret,
                    dpk2.OneTimeX25519PrekeyPublicSpan,
                    "The claimed one-time X25519 scalar differs from the verified DPK2 prekey.");
                oneTimePrivate = SecretBuffer.ImportExact(
                    oneTimeSecret,
                    MessagingCryptoConstants.X25519KeySize,
                    nameof(claimedOneTimeX25519PrivateScalar));
            }
            else if (!oneTimeSecret.IsEmpty)
            {
                throw Conflict("A last-resort claim cannot carry a one-time X25519 scalar.");
            }

            var mlKem = testMlKem;
            if (mlKem is null)
            {
                var approved = DeepMlKemNativeProvider.LoadApprovedForCurrentProcess();
                mlKem = approved;
                ownedMlKem = approved;
            }
            MessagingCryptoValidation.Exact(
                mlKemSecret,
                mlKem.DecapsulationKeySize,
                nameof(claimedMlKemDecapsulationSecret));
            if (MessagingCryptoValidation.IsZero(mlKemSecret))
                throw new MessagingCryptoException(
                    MessagingCryptoError.InvalidInput,
                    "The claimed ML-KEM decapsulation secret cannot be all-zero.");
            if (!mlKem.EncapsulationKeyMatchesDecapsulationKey(
                    dpk2.MlKem768EncapsulationKeySpan,
                    mlKemSecret))
                throw Conflict(
                    "The claimed ML-KEM decapsulation secret differs from the verified DPK2 prekey.");
            mlKemPrivate = SecretBuffer.ImportExact(
                mlKemSecret,
                mlKem.DecapsulationKeySize,
                nameof(claimedMlKemDecapsulationSecret));

            var claimData = new VerifiedPreKeyClaimData(
                claim.OperationId.ToArray(),
                claim.SessionId.ToArray(),
                claim.Dph2FullReplayHash.ToArray(),
                claim.Kind == Dpk2PrekeyKind.OneTime ? claim.X25519PreKeyId.ToArray() : null,
                claim.MlKemPreKeyId.ToArray());
            using var claimedPreKeys = new ClaimedHybridPreKeyLease(
                oneTimePrivate,
                mlKemPrivate,
                claimData);
            using var responderKeys = HybridResponderStaticKeyMaterial.Import(
                identityPrivate,
                signedPreKeyPrivate);
            var stateBinding = CreateResponderStateBinding(initiation);
            var transcript = VerifiedHybridTranscriptCapability.FromVerifiedInitiation(
                initiation,
                stateBinding,
                localIsInitiator: false);
            using var handshake = HybridPreKeyHandshake.AcceptInitiation(
                responderKeys,
                claimedPreKeys,
                dph2.InitiatorDeviceAgreementPublicKeySpan,
                dph2.InitiatorEphemeralX25519PublicKeySpan,
                transcript,
                mlKem);
            using var seed = VerifiedTripleRatchetSeedCapability.FromVerifiedHandshake(handshake);
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
            using var state = testStateFactory is null
                ? InitializeApprovedState(
                    seed,
                    signedPreKeyPrivate,
                    dpk2.SignedX25519PrekeyPublicSpan,
                    dph2.InitiatorInitialRatchetX25519PublicKeySpan)
                : testStateFactory(
                    seed,
                    signedPreKeyPrivate,
                    dpk2.SignedX25519PrekeyPublicSpan,
                    dph2.InitiatorInitialRatchetX25519PublicKeySpan,
                    _maximumMessagesWithoutPqInjection);
#else
            using var state = InitializeApprovedState(
                seed,
                signedPreKeyPrivate,
                dpk2.SignedX25519PrekeyPublicSpan,
                dph2.InitiatorInitialRatchetX25519PublicKeySpan);
#endif
            exactTrs1 = TripleRatchetDurableStateCodec.Encode(state);
            ownershipTransferred = true;
            return exactTrs1;
        }
        finally
        {
            if (!ownershipTransferred && exactTrs1 is not null)
                CryptographicOperations.ZeroMemory(exactTrs1);
            oneTimePrivate?.Dispose();
            mlKemPrivate?.Dispose();
            ownedMlKem?.Dispose();
            Zero(identityPrivate);
            Zero(signedPreKeyPrivate);
        }
    }

    private TripleRatchetState InitializeApprovedState(
        VerifiedTripleRatchetSeedCapability seed,
        ReadOnlySpan<byte> signedPreKeyPrivate,
        ReadOnlySpan<byte> signedPreKeyPublic,
        ReadOnlySpan<byte> initiatorInitialRatchetPublic)
    {
        using var braidRuntime = DeepMlKemBraidProductionRuntime.CreateApprovedForCurrentProcess();
        using var componentProvider = braidRuntime.OpenTripleRatchetComponentProvider();
        return componentProvider.InitializeBob(
            seed,
            signedPreKeyPrivate,
            signedPreKeyPublic,
            initiatorInitialRatchetPublic,
            storageGeneration: 1,
            _maximumMessagesWithoutPqInjection);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
                return;
            _disposed = true;
            _responderIdentityPrivate?.Dispose();
            _responderSignedPreKeyPrivate?.Dispose();
            _responderIdentityPrivate = null;
            _responderSignedPreKeyPrivate = null;
        }
        GC.SuppressFinalize(this);
    }

    private byte[] CopyIdentitySecret()
    {
        lock (_gate)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ManagedResponderInitialSessionFactory));
            return _responderIdentityPrivate!.Copy();
        }
    }

    private byte[] CopySignedPreKeySecret()
    {
        lock (_gate)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ManagedResponderInitialSessionFactory));
            return _responderSignedPreKeyPrivate?.Copy() ??
                throw new InvalidOperationException(
                    "This responder factory requires an opaque restored DPK2 capability.");
        }
    }

    private static void ValidateMaximum(int maximumMessagesWithoutPqInjection)
    {
        if (maximumMessagesWithoutPqInjection is < 1 or > MessagingCryptoConstants.MaximumForwardGap)
            throw new ArgumentOutOfRangeException(
                nameof(maximumMessagesWithoutPqInjection),
                "The PQ injection interval must be 1..2048 messages.");
    }

    private static RatchetStateBinding CreateResponderStateBinding(
        VerifiedDph2Initiation initiation)
    {
        var dph2 = initiation.Record;
        var dpk2 = initiation.Offering.Record;
        return new RatchetStateBinding(
            MessagingCryptoConstants.Suite,
            dph2.SessionIdSpan,
            initiation.TranscriptHash.Span,
            dph2.ResponderDeviceIdSpan,
            dph2.ResponderDeviceGeneration,
            dpk2.DeviceDirectoryHeadHashSpan,
            dph2.InitiatorDeviceIdSpan,
            dph2.InitiatorDeviceGeneration,
            initiation.InitiatorDeviceDirectoryHeadHashSpan);
    }

    private static void RequireExactClaimBinding(
        VerifiedInitialSessionPreKeyClaim.ProtocolClaimPayload claim,
        VerifiedDph2Initiation initiation)
    {
        var dph2 = initiation.Record;
        var dpk2 = initiation.Offering.Record;
        var exactDpk2Hash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(dpk2);
        var expectedOneTimeId = claim.Kind == Dpk2PrekeyKind.OneTime
            ? dpk2.OneTimeX25519PrekeyIdSpan
            : ReadOnlySpan<byte>.Empty;
        try
        {
            if (!Fixed(claim.OperationId, dph2.ClaimOperationIdSpan) ||
                !Fixed(claim.SessionId, dph2.SessionIdSpan) ||
                !Fixed(claim.ExactDpk2Hash, exactDpk2Hash) ||
                !Fixed(claim.ExactDpk2Hash, dph2.ExactDpk2HashSpan) ||
                !Fixed(claim.Dph2FullReplayHash, initiation.FullReplayHash.Span) ||
                !Fixed(claim.X25519PreKeyId, expectedOneTimeId) ||
                !Fixed(claim.MlKemPreKeyId, dpk2.MlKemPrekeyIdSpan) ||
                claim.Kind != dpk2.MlKemKind ||
                claim.Kind != dph2.SelectedPrekey.Kind ||
                claim.LastResortUseCounter != dph2.LastResortUseCounter)
                throw Conflict(
                    "The verified initial-session handoff differs from its exact DPH2/DPK2 closure.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactDpk2Hash);
        }
    }

    private static void RequirePrivateMatchesPublic(
        ReadOnlySpan<byte> privateScalar,
        ReadOnlySpan<byte> expectedPublic,
        string message)
    {
        var scalar = privateScalar.ToArray();
        byte[]? actualPublic = null;
        try
        {
            actualPublic = ScalarMult.Base(scalar);
            if (!Fixed(actualPublic, expectedPublic))
                throw Conflict(message);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scalar);
            Zero(actualPublic);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static MessagingCryptoException Conflict(string message) =>
        new(MessagingCryptoError.PreKeyConflict, message);

    private static void Zero(byte[]? value)
    {
        if (value is not null)
            CryptographicOperations.ZeroMemory(value);
    }
}
