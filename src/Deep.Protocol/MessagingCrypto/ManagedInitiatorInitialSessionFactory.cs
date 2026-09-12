using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.MessagingCrypto;

internal delegate void InitiatorInitialSessionEntropyCore(Span<byte> destination);

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
internal delegate TripleRatchetState InitiatorInitialRatchetStateFactory(
    VerifiedTripleRatchetSeedCapability seed,
    ReadOnlySpan<byte> initialRatchetPrivate,
    ReadOnlySpan<byte> initialRatchetPublic,
    ReadOnlySpan<byte> responderSignedPreKeyPublic,
    int maximumMessagesWithoutPqInjection);

internal delegate void InitiatorInitialSessionEntropy(Span<byte> destination);
#endif

/// <summary>
/// Production entry point for the two-phase DPH2 initiator closure. Fresh
/// ephemeral material is created before XPK1, while the exact DPH2/TRS1 pair
/// can be completed only with the matching verified XPC1 receipt.
/// </summary>
public sealed class ManagedInitiatorInitialSessionFactory
{
    private readonly int _maximumMessagesWithoutPqInjection;

    public ManagedInitiatorInitialSessionFactory(int maximumMessagesWithoutPqInjection)
    {
        if (maximumMessagesWithoutPqInjection is < 1 or > MessagingCryptoConstants.MaximumForwardGap)
            throw new ArgumentOutOfRangeException(
                nameof(maximumMessagesWithoutPqInjection),
                "The PQ injection interval must be 1..2048 messages.");
        _maximumMessagesWithoutPqInjection = maximumMessagesWithoutPqInjection;
    }

    /// <summary>
    /// Creates the public correlation values which must be committed by XPK1
    /// before the resolver selects and returns an exact DPK2 offering. No
    /// device agreement is performed and no native PQ provider is loaded in
    /// this phase.
    /// </summary>
    public InitiatorDph2PreKeyClaim BeginClaim(
        LocalDeviceX25519AgreementAuthority localAuthority,
        Dmd1LineageState exactCurrentDirectory)
    {
        ArgumentNullException.ThrowIfNull(localAuthority);
        ArgumentNullException.ThrowIfNull(exactCurrentDirectory);
        var directory = localAuthority
            .RequireActiveDirectoryForProtocolOperation(exactCurrentDirectory)
            .Record;
        var operationId = RandomNonzero32();
        return BeginClaimCore(
            InitiatorAgreementFacts.FromAuthority(
                localAuthority,
                directory.DirectoryGeneration,
                directory.RecordHash.Span,
                operationId),
            FillProductionEntropy);
    }

    /// <summary>
    /// Consumes a pre-XPK1 claim and the matching operation-bound device lease
    /// after XPC1 has returned a verifier-minted exact DPK2 offering.
    /// </summary>
    public InitiatorDph2ClaimPreparation CompleteClaim(
        InitiatorDph2PreKeyClaim startedClaim,
        VerifiedDpk2Offering verifiedOffering,
        LocalDeviceX25519AgreementLease deviceAgreementLease)
    {
        ArgumentNullException.ThrowIfNull(startedClaim);
        ArgumentNullException.ThrowIfNull(verifiedOffering);
        ArgumentNullException.ThrowIfNull(deviceAgreementLease);

        DeepMlKemNativeProvider? mlKem = null;
        DeepMlKemBraidProductionRuntime? braid = null;
        InitiatorDph2PreKeyClaimMaterial? material = null;
        try
        {
            // Provider readiness is checked before either one-shot authority is
            // consumed. A missing approved binary cannot burn the durable
            // device-agreement operation or the pre-XPK1 entropy.
            mlKem = DeepMlKemNativeProvider.LoadApprovedForCurrentProcess();
            braid = DeepMlKemBraidProductionRuntime.CreateApprovedForCurrentProcess();
            material = startedClaim.Consume();
            var result = PrepareStartedWithLease(
                material,
                verifiedOffering,
                deviceAgreementLease,
                mlKem,
                mlKem,
                braid,
                stateFactory: null,
                FillProductionEntropy);
            material = null;
            mlKem = null;
            braid = null;
            return result;
        }
        finally
        {
            material?.Dispose();
            mlKem?.Dispose();
            braid?.Dispose();
        }
    }

    /// <summary>
    /// Consumes one operation-bound device-agreement lease and owns fresh
    /// initiator ephemeral/tag-18 keys. The returned commitment is the only
    /// public value that must be placed in XPK1.
    /// </summary>
    public InitiatorDph2ClaimPreparation PrepareClaim(
        VerifiedDpk2Offering verifiedOffering,
        LocalDeviceX25519AgreementLease deviceAgreementLease)
    {
        ArgumentNullException.ThrowIfNull(verifiedOffering);
        ArgumentNullException.ThrowIfNull(deviceAgreementLease);
        if (deviceAgreementLease.Purpose != LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1)
            throw new CryptographicException("The local device agreement lease has the wrong DPH2 purpose.");

        DeepMlKemNativeProvider? mlKem = null;
        DeepMlKemBraidProductionRuntime? braid = null;
        try
        {
            // Both assets are opened before the lease is spent or XPK1 is sent.
            // Candidate-only or absent assets therefore fail closed.
            mlKem = DeepMlKemNativeProvider.LoadApprovedForCurrentProcess();
            braid = DeepMlKemBraidProductionRuntime.CreateApprovedForCurrentProcess();
            var result = PrepareWithLease(
                verifiedOffering,
                deviceAgreementLease,
                mlKem,
                mlKem,
                braid,
                stateFactory: null,
                FillProductionEntropy);
            mlKem = null;
            braid = null;
            return result;
        }
        finally
        {
            mlKem?.Dispose();
            braid?.Dispose();
        }
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal InitiatorDph2ClaimPreparation PrepareClaimForTests(
        VerifiedDpk2Offering verifiedOffering,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> exactDpd1Hash,
        ulong directoryGeneration,
        ReadOnlySpan<byte> exactDirectoryHash,
        ReadOnlySpan<byte> agreementPrivateScalar,
        ReadOnlySpan<byte> operationBinding,
        IMlKem768Provider mlKem,
        InitiatorInitialRatchetStateFactory stateFactory,
        InitiatorInitialSessionEntropy entropy)
    {
        ArgumentNullException.ThrowIfNull(verifiedOffering);
        ArgumentNullException.ThrowIfNull(mlKem);
        ArgumentNullException.ThrowIfNull(stateFactory);
        ArgumentNullException.ThrowIfNull(entropy);
        var agreement = TestAgreement.Import(
            networkId,
            accountId,
            deviceId,
            deviceGeneration,
            exactDpd1Hash,
            directoryGeneration,
            exactDirectoryHash,
            agreementPrivateScalar,
            operationBinding);
        try
        {
            return PrepareCore(
                verifiedOffering,
                agreement.Facts,
                mlKem,
                mlKemOwner: null,
                braidRuntime: null,
                stateFactory,
                destination => entropy(destination),
                (ephemeralPrivate, offering) => agreement.Prepare(
                    ephemeralPrivate,
                    offering,
                    mlKem));
        }
        finally
        {
            agreement.Dispose();
        }
    }
#endif

    private InitiatorDph2ClaimPreparation PrepareWithLease(
        VerifiedDpk2Offering verifiedOffering,
        LocalDeviceX25519AgreementLease lease,
        IMlKem768Provider mlKem,
        IDisposable mlKemOwner,
        DeepMlKemBraidProductionRuntime braidRuntime,
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
        InitiatorInitialRatchetStateFactory? stateFactory,
#else
        object? stateFactory,
#endif
        InitiatorInitialSessionEntropyCore entropy)
    {
        var facts = InitiatorAgreementFacts.FromLease(lease);
        try
        {
            return PrepareCore(
                verifiedOffering,
                facts,
                mlKem,
                mlKemOwner,
                braidRuntime,
                stateFactory,
                entropy,
                (ephemeralPrivate, offering) => HybridPreKeyHandshake.PrepareInitiation(
                    lease,
                    facts.OperationBinding,
                    ephemeralPrivate,
                    offering.DeviceAgreementPublicKeySpan,
                    offering.SignedX25519PrekeyPublicSpan,
                    offering.OneTimeX25519PrekeyPublicSpan,
                    offering.MlKem768EncapsulationKeySpan,
                    mlKem));
        }
        finally
        {
            lease.Dispose();
        }
    }

    private InitiatorDph2ClaimPreparation PrepareStartedWithLease(
        InitiatorDph2PreKeyClaimMaterial material,
        VerifiedDpk2Offering verifiedOffering,
        LocalDeviceX25519AgreementLease lease,
        IMlKem768Provider mlKem,
        IDisposable mlKemOwner,
        DeepMlKemBraidProductionRuntime braidRuntime,
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
        InitiatorInitialRatchetStateFactory? stateFactory,
#else
        object? stateFactory,
#endif
        InitiatorInitialSessionEntropyCore entropy)
    {
        var transferred = false;
        PreparedHybridInitiation? prepared = null;
        byte[]? ephemeralPrivate = null;
        byte[]? ratchetPrivate = null;
        try
        {
            var leased = InitiatorAgreementFacts.FromLease(lease);
            material.Local.RequireSame(leased);
            RequireOfferingAndLocalBinding(verifiedOffering, verifiedOffering.Record, leased);
            ephemeralPrivate = material.CopyEphemeralPrivate();
            prepared = HybridPreKeyHandshake.PrepareInitiation(
                lease,
                leased.OperationBinding,
                ephemeralPrivate,
                verifiedOffering.Record.DeviceAgreementPublicKeySpan,
                verifiedOffering.Record.SignedX25519PrekeyPublicSpan,
                verifiedOffering.Record.OneTimeX25519PrekeyPublicSpan,
                verifiedOffering.Record.MlKem768EncapsulationKeySpan,
                mlKem);
            ratchetPrivate = material.CopyInitialRatchetPrivate();
            var result = new InitiatorDph2ClaimPreparation(
                verifiedOffering,
                leased,
                prepared,
                material.EphemeralPublic,
                ratchetPrivate,
                material.InitialRatchetPublic,
                material.SenderEphemeralCommitment,
                mlKem,
                mlKemOwner,
                braidRuntime,
                stateFactory,
                entropy,
                _maximumMessagesWithoutPqInjection);
            prepared = null;
            mlKemOwner = null!;
            braidRuntime = null!;
            transferred = true;
            return result;
        }
        finally
        {
            prepared?.Dispose();
            lease.Dispose();
            if (!transferred)
            {
                mlKemOwner?.Dispose();
                braidRuntime?.Dispose();
            }
            material.Dispose();
            Zero(ephemeralPrivate);
            Zero(ratchetPrivate);
        }
    }

    private static InitiatorDph2PreKeyClaim BeginClaimCore(
        InitiatorAgreementFacts local,
        InitiatorInitialSessionEntropyCore entropy)
    {
        byte[]? ephemeralPrivate = null;
        byte[]? ephemeralPublic = null;
        byte[]? ratchetPrivate = null;
        byte[]? ratchetPublic = null;
        byte[]? senderCommitment = null;
        try
        {
            (ephemeralPrivate, ephemeralPublic) = GenerateX25519KeyPair(entropy);
            (ratchetPrivate, ratchetPublic) = GenerateX25519KeyPair(entropy);
            senderCommitment = MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(
                local.NetworkId,
                local.AccountId,
                local.DeviceId,
                Dpd1Reference(local.ExactDpd1Hash),
                local.AgreementPublicKey,
                ephemeralPublic,
                ratchetPublic);
            var result = new InitiatorDph2PreKeyClaim(
                local,
                ephemeralPrivate,
                ephemeralPublic,
                ratchetPrivate,
                ratchetPublic,
                senderCommitment);
            ephemeralPrivate = null;
            ratchetPrivate = null;
            return result;
        }
        finally
        {
            Zero(ephemeralPrivate);
            Zero(ephemeralPublic);
            Zero(ratchetPrivate);
            Zero(ratchetPublic);
            Zero(senderCommitment);
        }
    }

    private InitiatorDph2ClaimPreparation PrepareCore(
        VerifiedDpk2Offering verifiedOffering,
        InitiatorAgreementFacts local,
        IMlKem768Provider mlKem,
        IDisposable? mlKemOwner,
        DeepMlKemBraidProductionRuntime? braidRuntime,
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
        InitiatorInitialRatchetStateFactory? stateFactory,
#else
        object? stateFactory,
#endif
        InitiatorInitialSessionEntropyCore entropy,
        Func<byte[], Dpk2Record, PreparedHybridInitiation> prepareHybrid)
    {
        var offering = verifiedOffering.Record;
        RequireOfferingAndLocalBinding(verifiedOffering, offering, local);

        byte[]? ephemeralPrivate = null;
        byte[]? ephemeralPublic = null;
        byte[]? ratchetPrivate = null;
        byte[]? ratchetPublic = null;
        byte[]? senderCommitment = null;
        PreparedHybridInitiation? prepared = null;
        var transferred = false;
        try
        {
            (ephemeralPrivate, ephemeralPublic) = GenerateX25519KeyPair(entropy);
            (ratchetPrivate, ratchetPublic) = GenerateX25519KeyPair(entropy);
            prepared = prepareHybrid(ephemeralPrivate, offering);
            senderCommitment = MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(
                local.NetworkId,
                local.AccountId,
                local.DeviceId,
                Dpd1Reference(local.ExactDpd1Hash),
                local.AgreementPublicKey,
                ephemeralPublic,
                ratchetPublic);
            var result = new InitiatorDph2ClaimPreparation(
                verifiedOffering,
                local,
                prepared,
                ephemeralPublic,
                ratchetPrivate,
                ratchetPublic,
                senderCommitment,
                mlKem,
                mlKemOwner,
                braidRuntime,
                stateFactory,
                entropy,
                _maximumMessagesWithoutPqInjection);
            prepared = null;
            mlKemOwner = null;
            braidRuntime = null;
            transferred = true;
            return result;
        }
        finally
        {
            prepared?.Dispose();
            if (!transferred)
            {
                mlKemOwner?.Dispose();
                braidRuntime?.Dispose();
            }
            Zero(ephemeralPrivate);
            Zero(ephemeralPublic);
            Zero(ratchetPrivate);
            Zero(ratchetPublic);
            Zero(senderCommitment);
        }
    }

    private static void RequireOfferingAndLocalBinding(
        VerifiedDpk2Offering verifiedOffering,
        Dpk2Record offering,
        InitiatorAgreementFacts local)
    {
        if (!Fixed(verifiedOffering.ExactHash.Span,
                MessagingWireCryptographicInputs.ComputeExactDpk2Hash(offering)) ||
            !Fixed(local.NetworkId, offering.NetworkIdSpan))
            throw new CryptographicException("The verified DPK2 and local device lease are from different closures.");
        if (offering.MlKemKind == Dpk2PrekeyKind.OneTime &&
            offering.OneTimeX25519PrekeyPublicSpan.IsEmpty)
            throw new CryptographicException("The verified one-time DPK2 lacks its X25519 prekey.");
    }

    private static (byte[] Private, byte[] Public) GenerateX25519KeyPair(
        InitiatorInitialSessionEntropyCore entropy)
    {
        var privateKey = new byte[32];
        byte[]? publicKey = null;
        try
        {
            do entropy(privateKey); while (MessagingCryptoValidation.IsZero(privateKey));
            publicKey = ScalarMult.Base(privateKey);
            MessagingCryptoValidation.NonZeroExact(publicKey, 32, nameof(publicKey));
            return (privateKey, publicKey);
        }
        catch
        {
            Zero(privateKey);
            Zero(publicKey);
            throw;
        }
    }

    private static byte[] Dpd1Reference(ReadOnlySpan<byte> hash)
    {
        MessagingCryptoValidation.NonZeroExact(hash, 32, nameof(hash));
        var reference = new byte[38];
        "DPD1"u8.CopyTo(reference);
        BinaryPrimitives.WriteUInt16BigEndian(reference.AsSpan(4), 1);
        hash.CopyTo(reference.AsSpan(6));
        return reference;
    }

    private static void FillProductionEntropy(Span<byte> destination) =>
        RandomNumberGenerator.Fill(destination);

    private static byte[] RandomNonzero32()
    {
        var value = new byte[32];
        do RandomNumberGenerator.Fill(value);
        while (MessagingCryptoValidation.IsZero(value));
        return value;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    private sealed class TestAgreement : IDisposable
    {
        private readonly SecretBuffer _privateScalar;
        private int _consumed;

        private TestAgreement(InitiatorAgreementFacts facts, SecretBuffer privateScalar)
        {
            Facts = facts;
            _privateScalar = privateScalar;
        }

        internal InitiatorAgreementFacts Facts { get; }

        internal static TestAgreement Import(
            ReadOnlySpan<byte> networkId,
            ReadOnlySpan<byte> accountId,
            ReadOnlySpan<byte> deviceId,
            ulong deviceGeneration,
            ReadOnlySpan<byte> exactDpd1Hash,
            ulong directoryGeneration,
            ReadOnlySpan<byte> exactDirectoryHash,
            ReadOnlySpan<byte> agreementPrivateScalar,
            ReadOnlySpan<byte> operationBinding)
        {
            var privateCopy = agreementPrivateScalar.ToArray();
            byte[]? publicKey = null;
            try
            {
                MessagingCryptoValidation.NonZeroExact(privateCopy, 32, nameof(agreementPrivateScalar));
                publicKey = ScalarMult.Base(privateCopy);
                var facts = new InitiatorAgreementFacts(
                    networkId,
                    accountId,
                    deviceId,
                    deviceGeneration,
                    exactDpd1Hash,
                    directoryGeneration,
                    exactDirectoryHash,
                    publicKey,
                    operationBinding);
                return new TestAgreement(
                    facts,
                    SecretBuffer.ImportExact(privateCopy, 32, nameof(agreementPrivateScalar)));
            }
            finally
            {
                Zero(privateCopy);
                Zero(publicKey);
            }
        }

        internal PreparedHybridInitiation Prepare(
            ReadOnlySpan<byte> ephemeralPrivate,
            Dpk2Record offering,
            IMlKem768Provider mlKem)
        {
            if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
                throw new InvalidOperationException("The recovery-test agreement is single-use.");
            var identityPrivate = _privateScalar.Copy();
            try
            {
                using var initiator = HybridInitiatorKeyMaterial.Import(
                    identityPrivate, ephemeralPrivate);
                return HybridPreKeyHandshake.PrepareInitiation(
                    initiator,
                    offering.DeviceAgreementPublicKeySpan,
                    offering.SignedX25519PrekeyPublicSpan,
                    offering.OneTimeX25519PrekeyPublicSpan,
                    offering.MlKem768EncapsulationKeySpan,
                    mlKem);
            }
            finally
            {
                Zero(identityPrivate);
            }
        }

        public void Dispose() => _privateScalar.Dispose();
    }
#endif
}

/// <summary>
/// Single-use owner of the fresh public correlation and private ephemeral
/// material created before XPK1. It deliberately has no responder identity or
/// pre-key because those are selected and authenticated by XPC1.
/// </summary>
public sealed class InitiatorDph2PreKeyClaim : IDisposable
{
    private readonly object _gate = new();
    private readonly InitiatorAgreementFacts _local;
    private readonly byte[] _senderCommitment;
    private SecretBuffer? _ephemeralPrivate;
    private SecretBuffer? _initialRatchetPrivate;
    private byte[]? _ephemeralPublic;
    private byte[]? _initialRatchetPublic;
    private int _state;

    internal InitiatorDph2PreKeyClaim(
        InitiatorAgreementFacts local,
        ReadOnlySpan<byte> ephemeralPrivate,
        ReadOnlySpan<byte> ephemeralPublic,
        ReadOnlySpan<byte> initialRatchetPrivate,
        ReadOnlySpan<byte> initialRatchetPublic,
        ReadOnlySpan<byte> senderCommitment)
    {
        _local = local ?? throw new ArgumentNullException(nameof(local));
        _ephemeralPrivate = SecretBuffer.ImportExact(
            ephemeralPrivate, 32, nameof(ephemeralPrivate));
        _initialRatchetPrivate = SecretBuffer.ImportExact(
            initialRatchetPrivate, 32, nameof(initialRatchetPrivate));
        MessagingCryptoFaultInjection.OwnedSecret(
            "initial-session.preclaim-ephemeral-private", _ephemeralPrivate);
        MessagingCryptoFaultInjection.OwnedSecret(
            "initial-session.preclaim-ratchet-private", _initialRatchetPrivate);
        _ephemeralPublic = ephemeralPublic.ToArray();
        _initialRatchetPublic = initialRatchetPublic.ToArray();
        _senderCommitment = senderCommitment.ToArray();
    }

    ~InitiatorDph2PreKeyClaim() => DisposeCore();

    public ReadOnlyMemory<byte> NetworkId => _local.NetworkId.ToArray();
    public ReadOnlyMemory<byte> ClaimOperationId => _local.OperationBinding.ToArray();
    public ReadOnlyMemory<byte> SenderEphemeralCommitment => _senderCommitment.ToArray();

    internal InitiatorDph2PreKeyClaimMaterial Consume()
    {
        lock (_gate)
        {
            if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
                throw new InvalidOperationException("The pre-XPK1 DPH2 claim is single-use.");
            var ephemeral = Interlocked.Exchange(ref _ephemeralPrivate, null)
                ?? throw new ObjectDisposedException(nameof(InitiatorDph2PreKeyClaim));
            var ratchet = Interlocked.Exchange(ref _initialRatchetPrivate, null)
                ?? throw new ObjectDisposedException(nameof(InitiatorDph2PreKeyClaim));
            var ephemeralPublic = Interlocked.Exchange(ref _ephemeralPublic, null)!;
            var ratchetPublic = Interlocked.Exchange(ref _initialRatchetPublic, null)!;
            return new InitiatorDph2PreKeyClaimMaterial(
                _local,
                ephemeral,
                ephemeralPublic,
                ratchet,
                ratchetPublic,
                _senderCommitment);
        }
    }

    public void Dispose()
    {
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    private void DisposeCore()
    {
        lock (_gate)
        {
            if (Interlocked.Exchange(ref _state, 2) == 2) return;
            Interlocked.Exchange(ref _ephemeralPrivate, null)?.Dispose();
            Interlocked.Exchange(ref _initialRatchetPrivate, null)?.Dispose();
            var ephemeral = Interlocked.Exchange(ref _ephemeralPublic, null);
            var ratchet = Interlocked.Exchange(ref _initialRatchetPublic, null);
            if (ephemeral is not null) CryptographicOperations.ZeroMemory(ephemeral);
            if (ratchet is not null) CryptographicOperations.ZeroMemory(ratchet);
        }
    }
}

internal sealed class InitiatorDph2PreKeyClaimMaterial : IDisposable
{
    private SecretBuffer? _ephemeralPrivate;
    private SecretBuffer? _initialRatchetPrivate;
    private byte[]? _ephemeralPublic;
    private byte[]? _initialRatchetPublic;
    private byte[]? _senderCommitment;

    internal InitiatorDph2PreKeyClaimMaterial(
        InitiatorAgreementFacts local,
        SecretBuffer ephemeralPrivate,
        byte[] ephemeralPublic,
        SecretBuffer initialRatchetPrivate,
        byte[] initialRatchetPublic,
        ReadOnlySpan<byte> senderCommitment)
    {
        Local = local;
        _ephemeralPrivate = ephemeralPrivate;
        _ephemeralPublic = ephemeralPublic;
        _initialRatchetPrivate = initialRatchetPrivate;
        _initialRatchetPublic = initialRatchetPublic;
        _senderCommitment = senderCommitment.ToArray();
    }

    internal InitiatorAgreementFacts Local { get; }
    internal ReadOnlySpan<byte> EphemeralPublic => Value(_ephemeralPublic);
    internal ReadOnlySpan<byte> InitialRatchetPublic => Value(_initialRatchetPublic);
    internal ReadOnlySpan<byte> SenderEphemeralCommitment => Value(_senderCommitment);
    internal byte[] CopyEphemeralPrivate() =>
        (_ephemeralPrivate ?? throw new ObjectDisposedException(GetType().Name)).Copy();
    internal byte[] CopyInitialRatchetPrivate() =>
        (_initialRatchetPrivate ?? throw new ObjectDisposedException(GetType().Name)).Copy();

    public void Dispose()
    {
        Interlocked.Exchange(ref _ephemeralPrivate, null)?.Dispose();
        Interlocked.Exchange(ref _initialRatchetPrivate, null)?.Dispose();
        Zero(Interlocked.Exchange(ref _ephemeralPublic, null));
        Zero(Interlocked.Exchange(ref _initialRatchetPublic, null));
        Zero(Interlocked.Exchange(ref _senderCommitment, null));
    }

    private static byte[] Value(byte[]? value) =>
        value ?? throw new ObjectDisposedException(nameof(InitiatorDph2PreKeyClaimMaterial));
    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}

/// <summary>
/// Single-use owner of the verified DPK2-bound DPH2 initiator material. It
/// exposes only public claim correlation data.
/// </summary>
public sealed class InitiatorDph2ClaimPreparation : IDisposable
{
    private readonly object _gate = new();
    private readonly VerifiedDpk2Offering _offering;
    private readonly InitiatorAgreementFacts _local;
    private readonly byte[] _senderCommitment;
    private PreparedHybridInitiation? _prepared;
    private SecretBuffer? _initialRatchetPrivate;
    private byte[]? _ephemeralPublic;
    private byte[]? _initialRatchetPublic;
    private readonly IMlKem768Provider _mlKem;
    private IDisposable? _mlKemOwner;
    private DeepMlKemBraidProductionRuntime? _braidRuntime;
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    private readonly InitiatorInitialRatchetStateFactory? _stateFactory;
#endif
    private readonly InitiatorInitialSessionEntropyCore _entropy;
    private readonly int _maximumMessagesWithoutPqInjection;
    private int _state;

    internal InitiatorDph2ClaimPreparation(
        VerifiedDpk2Offering offering,
        InitiatorAgreementFacts local,
        PreparedHybridInitiation prepared,
        ReadOnlySpan<byte> ephemeralPublic,
        ReadOnlySpan<byte> initialRatchetPrivate,
        ReadOnlySpan<byte> initialRatchetPublic,
        ReadOnlySpan<byte> senderCommitment,
        IMlKem768Provider mlKem,
        IDisposable? mlKemOwner,
        DeepMlKemBraidProductionRuntime? braidRuntime,
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
        InitiatorInitialRatchetStateFactory? stateFactory,
#else
        object? stateFactory,
#endif
        InitiatorInitialSessionEntropyCore entropy,
        int maximumMessagesWithoutPqInjection)
    {
        _offering = offering;
        _local = local;
        _prepared = prepared;
        _ephemeralPublic = ephemeralPublic.ToArray();
        _initialRatchetPrivate = SecretBuffer.ImportExact(
            initialRatchetPrivate, 32, nameof(initialRatchetPrivate));
        MessagingCryptoFaultInjection.OwnedSecret(
            "initial-session.initiator-ratchet-private", _initialRatchetPrivate);
        _initialRatchetPublic = initialRatchetPublic.ToArray();
        _senderCommitment = senderCommitment.ToArray();
        _mlKem = mlKem;
        _mlKemOwner = mlKemOwner;
        _braidRuntime = braidRuntime;
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
        _stateFactory = stateFactory;
#else
        _ = stateFactory;
#endif
        _entropy = entropy;
        _maximumMessagesWithoutPqInjection = maximumMessagesWithoutPqInjection;
    }

    ~InitiatorDph2ClaimPreparation() => DisposeCore();

    public ReadOnlyMemory<byte> NetworkId => _local.NetworkId.ToArray();
    public ReadOnlyMemory<byte> ClaimOperationId => _local.OperationBinding.ToArray();
    public ReadOnlyMemory<byte> ResponderAccountId => _offering.ResponderAccountId;
    public ReadOnlyMemory<byte> ResponderDeviceId => _offering.ResponderDeviceId;
    public ReadOnlyMemory<byte> SenderEphemeralCommitment => _senderCommitment.ToArray();

    /// <summary>
    /// Consumes the preparation on every attempt. The exact SessionInit DMC2
    /// is mandatory; a second canonical DMC2 event is optional.
    /// </summary>
    public InitiatorInitialSessionCommitCapability Complete(
        VerifiedXpc1PreKeyClaimReceipt verifiedClaim,
        ReadOnlySpan<byte> exactSessionInitDmc2,
        ReadOnlySpan<byte> exactFirstApplicationDmc2 = default)
    {
        ArgumentNullException.ThrowIfNull(verifiedClaim);
        lock (_gate)
        {
            if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
                throw new InvalidOperationException("The DPH2 claim preparation is single-use.");
            try
            {
                return CompleteCore(verifiedClaim, exactSessionInitDmc2, exactFirstApplicationDmc2);
            }
            finally
            {
                DisposeOwned();
            }
        }
    }

    private InitiatorInitialSessionCommitCapability CompleteCore(
        VerifiedXpc1PreKeyClaimReceipt claim,
        ReadOnlySpan<byte> exactSessionInitDmc2,
        ReadOnlySpan<byte> exactFirstApplicationDmc2)
    {
        RequireClaimPublicBinding(claim);
        var sessionInit = ValidateInitialDmc2(exactSessionInitDmc2, exactFirstApplicationDmc2);
        var payload = EncodeInitialPayload(exactSessionInitDmc2, exactFirstApplicationDmc2, _entropy);
        byte[]? nonce = null;
        byte[]? mlKemCiphertext = null;
        byte[]? zeroCiphertext = null;
        byte[]? ciphertext = null;
        byte[]? exactDph2 = null;
        byte[]? exactTrs1 = null;
        byte[]? initialPrivate = null;
        byte[]? decrypted = null;
        HybridHandshakeSecrets? handshake = null;
        TripleRatchetState? ratchet = null;
        try
        {
            nonce = new byte[24];
            _entropy(nonce);
            mlKemCiphertext = _prepared!.Ciphertext.ToArray();
            zeroCiphertext = new byte[payload.Length + 16];
            var provisional = CreateRecord(claim, nonce, mlKemCiphertext, zeroCiphertext);
            var callbacks = new InitiatorVerificationCallbacks(_local, claim);
            var provisionalVerified = MessagingWireVerification.VerifyDph2(
                Dph2Codec.Encode(provisional), _offering, callbacks);
            var stateBinding = CreateInitiatorStateBinding(provisionalVerified);
            var transcript = VerifiedHybridTranscriptCapability.FromVerifiedInitiation(
                provisionalVerified, stateBinding, localIsInitiator: true);
            handshake = HybridPreKeyHandshake.CompleteInitiation(_prepared!, transcript);
            ciphertext = EncryptInitialPayload(provisional, payload, handshake);
            var finalRecord = CreateRecord(claim, nonce, mlKemCiphertext, ciphertext);
            exactDph2 = Dph2Codec.Encode(finalRecord);
            var verified = MessagingWireVerification.VerifyDph2(exactDph2, _offering, callbacks);
            _ = claim.ConsumeForHandshake(verified);
            RequireSameTranscript(provisionalVerified, verified);

            decrypted = DecryptInitialPayload(finalRecord, handshake);
            if (!Fixed(payload, decrypted))
                throw new CryptographicException("The self-verified DPH2 initial payload changed during encryption.");
            VerifyDecodedInitialPayload(decrypted, sessionInit);

            initialPrivate = _initialRatchetPrivate!.Copy();
            using var seed = VerifiedTripleRatchetSeedCapability.FromVerifiedHandshake(handshake);
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
            ratchet = _stateFactory is null
                ? InitializeApprovedState(seed, initialPrivate, finalRecord)
                : _stateFactory(
                    seed,
                    initialPrivate,
                    _initialRatchetPublic!,
                    _offering.Record.SignedX25519PrekeyPublicSpan,
                    _maximumMessagesWithoutPqInjection);
#else
            ratchet = InitializeApprovedState(seed, initialPrivate, finalRecord);
#endif
            exactTrs1 = TripleRatchetDurableStateCodec.Encode(ratchet);
            VerifyExactInitialTrs1(exactTrs1, verified);
            var result = new InitiatorInitialSessionCommitCapability(
                exactDph2,
                exactTrs1,
                verified.SessionId.Span,
                verified.ClaimOperationId.Span,
                verified.FullReplayHash.Span,
                verified.ClaimBinding.Span);
            exactDph2 = null;
            exactTrs1 = null;
            return result;
        }
        finally
        {
            ratchet?.Dispose();
            handshake?.Dispose();
            Zero(payload);
            Zero(nonce);
            Zero(mlKemCiphertext);
            Zero(zeroCiphertext);
            Zero(ciphertext);
            Zero(exactDph2);
            Zero(exactTrs1);
            Zero(initialPrivate);
            Zero(decrypted);
        }
    }

    private ParsedDmc2 ValidateInitialDmc2(
        ReadOnlySpan<byte> exactSessionInitDmc2,
        ReadOnlySpan<byte> exactFirstApplicationDmc2)
    {
        var session = ApplicationCoreCodec.DecodeDmc2(exactSessionInitDmc2);
        if (session.ParsedPayload is not SessionInitDmc2Payload init ||
            !Fixed(session.NetworkId.Span, _local.NetworkId) ||
            !Fixed(session.SenderAccountId.Span, _local.AccountId) ||
            !Fixed(session.SenderDeviceId.Span, _local.DeviceId) ||
            !Fixed(init.SenderDmd1Hash.Span, _local.ExactDirectoryHash) ||
            init.SenderDirectory.DirectoryGeneration != _local.DirectoryGeneration ||
            !Fixed(init.SenderDirectory.RecordHash.Span, _local.ExactDirectoryHash))
            throw new CryptographicException("SessionInit DMC2 is not bound to the local verified device directory.");

        var localEntry = init.SenderDirectory.ActiveDevices.SingleOrDefault(entry =>
            entry.DeviceId.Span.SequenceEqual(_local.DeviceId));
        if (localEntry is null ||
            localEntry.Dpd1Reference.TypeCode != (ushort)Deep.Protocol.DeepNative.ArtifactType.Dpd1 ||
            !Fixed(localEntry.Dpd1Reference.CanonicalHash.Span, _local.ExactDpd1Hash))
            throw new CryptographicException("SessionInit DMC2 does not contain the exact local DPD1 generation.");

        if (!exactFirstApplicationDmc2.IsEmpty)
        {
            var first = ApplicationCoreCodec.DecodeDmc2(exactFirstApplicationDmc2);
            if (first.ContentKind == Dmc2ContentKind.SessionInit ||
                !Fixed(first.NetworkId.Span, session.NetworkId.Span) ||
                !Fixed(first.SenderAccountId.Span, session.SenderAccountId.Span) ||
                !Fixed(first.SenderDeviceId.Span, session.SenderDeviceId.Span) ||
                !Fixed(first.ConversationId.Span, session.ConversationId.Span) ||
                Fixed(first.LogicalMessageId.Span, session.LogicalMessageId.Span) ||
                first.SenderClientSequence <= session.SenderClientSequence ||
                first.CreatedAtUnixMilliseconds < session.CreatedAtUnixMilliseconds)
                throw new CryptographicException("The first DMC2 event is not the same immutable initiator conversation stream.");
        }
        return session;
    }

    private void RequireClaimPublicBinding(VerifiedXpc1PreKeyClaimReceipt claim)
    {
        var offering = _offering.Record;
        if (!Fixed(claim.NetworkId.Span, _local.NetworkId) ||
            !Fixed(claim.OperationId.Span, _local.OperationBinding) ||
            !Fixed(claim.ExactDpk2Hash.Span, _offering.ExactHash.Span) ||
            !Fixed(claim.ResponderAccountId.Span, offering.ResponderAccountIdSpan) ||
            !Fixed(claim.ResponderDeviceId.Span, offering.ResponderDeviceIdSpan) ||
            claim.ResponderDeviceGeneration != offering.ResponderDeviceGeneration ||
            !Fixed(claim.SignedX25519PrekeyId.Span, offering.SignedX25519PrekeyIdSpan) ||
            !Fixed(claim.MlKemPrekeyId.Span, offering.MlKemPrekeyIdSpan) ||
            claim.PrekeyKind != offering.MlKemKind ||
            (claim.PrekeyKind == Dpk2PrekeyKind.OneTime &&
             !Fixed(claim.SelectedOneTimePrekeyId.Span, offering.OneTimeX25519PrekeyIdSpan)) ||
            (claim.PrekeyKind == Dpk2PrekeyKind.LastResort &&
             (claim.LastResortUseCounter is < 1 or > 64 ||
              claim.LastResortUseCounter > offering.ReuseLimit)))
            throw new CryptographicException("The verified XPC1 receipt does not bind this prepared DPK2 initiation.");
    }

    private Dph2Record CreateRecord(
        VerifiedXpc1PreKeyClaimReceipt claim,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> mlKemCiphertext,
        ReadOnlySpan<byte> initialCiphertext)
    {
        var offering = _offering.Record;
        var selected = offering.MlKemKind == Dpk2PrekeyKind.OneTime
            ? Dph2SelectedPrekey.OneTime(
                offering.SignedX25519PrekeyIdSpan,
                offering.OneTimeX25519PrekeyIdSpan,
                offering.MlKemPrekeyIdSpan)
            : Dph2SelectedPrekey.LastResort(
                offering.SignedX25519PrekeyIdSpan,
                offering.MlKemPrekeyIdSpan);
        return new Dph2Record(
            _local.NetworkId,
            _local.AccountId,
            _local.DeviceId,
            _local.DeviceGeneration,
            Dpd1Reference(_local.ExactDpd1Hash),
            offering.ResponderAccountIdSpan,
            offering.ResponderDeviceIdSpan,
            offering.ResponderDeviceGeneration,
            _offering.ExactHash.Span,
            _local.OperationBinding,
            claim.ClaimReceiptHash.Span,
            claim.LastResortUseCounter,
            _local.AgreementPublicKey,
            _ephemeralPublic!,
            selected,
            mlKemCiphertext,
            _initialRatchetPublic!,
            nonce,
            Dph2InitialCiphertext.Import(initialCiphertext));
    }

    private RatchetStateBinding CreateInitiatorStateBinding(VerifiedDph2Initiation initiation) =>
        new(
            MessagingCryptoConstants.Suite,
            initiation.Record.SessionIdSpan,
            initiation.TranscriptHash.Span,
            _local.DeviceId,
            _local.DeviceGeneration,
            _local.ExactDirectoryHash,
            _offering.Record.ResponderDeviceIdSpan,
            _offering.Record.ResponderDeviceGeneration,
            _offering.Record.DeviceDirectoryHeadHashSpan);

    private TripleRatchetState InitializeApprovedState(
        VerifiedTripleRatchetSeedCapability seed,
        ReadOnlySpan<byte> initialPrivate,
        Dph2Record record)
    {
        using var componentProvider = _braidRuntime!.OpenTripleRatchetComponentProvider();
        return componentProvider.InitializeAlice(
            seed,
            initialPrivate,
            record.InitiatorInitialRatchetX25519PublicKeySpan,
            _offering.Record.SignedX25519PrekeyPublicSpan,
            storageGeneration: 1,
            _maximumMessagesWithoutPqInjection);
    }

    private byte[] EncryptInitialPayload(
        Dph2Record header,
        ReadOnlySpan<byte> paddedPlaintext,
        HybridHandshakeSecrets handshake)
    {
        byte[]? plaintext = null;
        byte[]? key = null;
        byte[]? nonce = null;
        byte[]? aad = null;
        try
        {
            plaintext = paddedPlaintext.ToArray();
            handshake.UseInitialAeadKey(secret => key = secret.ToArray());
            nonce = header.InitialPayloadNonce.ToArray();
            aad = MessagingWireCryptographicInputs.GetDph2InitialAeadAssociatedData(
                _offering.Record, header);
            return SecretAeadXChaCha20Poly1305.Encrypt(plaintext, nonce, key!, aad);
        }
        catch (CryptographicException exception)
        {
            throw new MessagingCryptoException(
                MessagingCryptoError.TransitionRejected,
                "DPH2 initial payload encryption failed.", exception);
        }
        finally
        {
            Zero(plaintext); Zero(key); Zero(nonce); Zero(aad);
        }
    }

    private byte[] DecryptInitialPayload(Dph2Record record, HybridHandshakeSecrets handshake)
    {
        byte[]? ciphertext = null;
        byte[]? key = null;
        byte[]? nonce = null;
        byte[]? aad = null;
        try
        {
            ciphertext = new byte[record.InitialCiphertext.Length];
            record.InitialCiphertext.CopyCiphertextTo(ciphertext);
            handshake.UseInitialAeadKey(secret => key = secret.ToArray());
            nonce = record.InitialPayloadNonce.ToArray();
            aad = MessagingWireCryptographicInputs.GetDph2InitialAeadAssociatedData(
                _offering.Record, record);
            return SecretAeadXChaCha20Poly1305.Decrypt(ciphertext, nonce, key!, aad);
        }
        finally
        {
            Zero(ciphertext); Zero(key); Zero(nonce); Zero(aad);
        }
    }

    private static byte[] EncodeInitialPayload(
        ReadOnlySpan<byte> sessionInit,
        ReadOnlySpan<byte> firstApplication,
        InitiatorInitialSessionEntropyCore entropy)
    {
        var unpaddedLength = checked(1 + 4 + sessionInit.Length +
            (firstApplication.IsEmpty ? 0 : 4 + firstApplication.Length));
        var bucket = new[] { 4096, 16384, 32768 }
            .FirstOrDefault(candidate => unpaddedLength + 4 <= candidate);
        if (bucket == 0)
            throw new CryptographicException("The exact initial DMC2 payload exceeds the largest DPH2 bucket.");
        var output = new byte[bucket];
        entropy(output);
        var offset = 0;
        output[offset++] = firstApplication.IsEmpty ? (byte)1 : (byte)2;
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset), checked((uint)sessionInit.Length));
        offset += 4;
        sessionInit.CopyTo(output.AsSpan(offset));
        offset += sessionInit.Length;
        if (!firstApplication.IsEmpty)
        {
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset), checked((uint)firstApplication.Length));
            offset += 4;
            firstApplication.CopyTo(output.AsSpan(offset));
            offset += firstApplication.Length;
        }
        if (offset != unpaddedLength)
            throw new InvalidOperationException("The DPH2 initial payload length arithmetic diverged.");
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(bucket - 4), checked((uint)unpaddedLength));
        return output;
    }

    private static void VerifyDecodedInitialPayload(ReadOnlySpan<byte> padded, ParsedDmc2 expectedSession)
    {
        if (padded.Length is not (4096 or 16384 or 32768))
            throw new CryptographicException("The decrypted DPH2 payload has an invalid bucket.");
        var unpaddedLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(padded[^4..]));
        if (unpaddedLength is < 1 or > 32764 || unpaddedLength > padded.Length - 4)
            throw new CryptographicException("The decrypted DPH2 payload length is invalid.");
        var body = padded[..unpaddedLength];
        var count = body[0];
        if (count is not (1 or 2))
            throw new CryptographicException("The decrypted DPH2 event count is invalid.");
        var offset = 1;
        var decodedSession = DecodeLp32Dmc2(body, ref offset);
        if (decodedSession.ContentKind != Dmc2ContentKind.SessionInit ||
            !decodedSession.CanonicalBytes.Span.SequenceEqual(expectedSession.CanonicalBytes.Span))
            throw new CryptographicException("The decrypted DPH2 SessionInit is not exact.");
        if (count == 2) _ = DecodeLp32Dmc2(body, ref offset);
        if (offset != body.Length)
            throw new CryptographicException("The decrypted DPH2 payload contains trailing event bytes.");
    }

    private static ParsedDmc2 DecodeLp32Dmc2(ReadOnlySpan<byte> body, ref int offset)
    {
        if (body.Length - offset < 4)
            throw new CryptographicException("The decrypted DPH2 LP32 event is truncated.");
        var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(body.Slice(offset, 4)));
        offset += 4;
        if (length < 282 || length > 33082 || body.Length - offset < length)
            throw new CryptographicException("The decrypted DPH2 DMC2 length is invalid.");
        var result = ApplicationCoreCodec.DecodeDmc2(body.Slice(offset, length));
        offset += length;
        return result;
    }

    private static void RequireSameTranscript(
        VerifiedDph2Initiation provisional,
        VerifiedDph2Initiation final)
    {
        if (!Fixed(provisional.SessionId.Span, final.SessionId.Span) ||
            !Fixed(provisional.TranscriptHash.Span, final.TranscriptHash.Span) ||
            !Dph2Codec.GetHandshakeHeader(provisional.Record).AsSpan()
                .SequenceEqual(Dph2Codec.GetHandshakeHeader(final.Record)))
            throw new CryptographicException("The final DPH2 changed its verified handshake transcript.");
    }

    private void VerifyExactInitialTrs1(
        ReadOnlySpan<byte> exactTrs1,
        VerifiedDph2Initiation initiation)
    {
        using var decoded = TripleRatchetDurableStateCodec.Decode(exactTrs1);
        byte[]? canonical = null;
        try
        {
            canonical = TripleRatchetDurableStateCodec.Encode(decoded);
            if (!canonical.AsSpan().SequenceEqual(exactTrs1) ||
                decoded.StorageGeneration != 1 ||
                !Fixed(decoded.Binding.SessionId.Span, initiation.SessionId.Span) ||
                !Fixed(decoded.Binding.TranscriptHash.Span, initiation.TranscriptHash.Span) ||
                !Fixed(decoded.Binding.LocalDeviceId.Span, _local.DeviceId) ||
                !Fixed(decoded.Binding.RemoteDeviceId.Span, _offering.Record.ResponderDeviceIdSpan))
                throw new CryptographicException("The initial TRS1 failed its canonical protocol self-verification.");
        }
        finally
        {
            Zero(canonical);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (Interlocked.Exchange(ref _state, 2) == 2) return;
            DisposeOwned();
        }
        GC.SuppressFinalize(this);
    }

    private void DisposeCore()
    {
        lock (_gate)
        {
            if (Interlocked.Exchange(ref _state, 2) == 2) return;
            DisposeOwned();
        }
    }

    private void DisposeOwned()
    {
        Interlocked.Exchange(ref _prepared, null)?.Dispose();
        Interlocked.Exchange(ref _initialRatchetPrivate, null)?.Dispose();
        Zero(Interlocked.Exchange(ref _ephemeralPublic, null));
        Zero(Interlocked.Exchange(ref _initialRatchetPublic, null));
        Interlocked.Exchange(ref _mlKemOwner, null)?.Dispose();
        Interlocked.Exchange(ref _braidRuntime, null)?.Dispose();
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static byte[] Dpd1Reference(ReadOnlySpan<byte> hash)
    {
        var reference = new byte[38];
        "DPD1"u8.CopyTo(reference);
        BinaryPrimitives.WriteUInt16BigEndian(reference.AsSpan(4), 1);
        hash.CopyTo(reference.AsSpan(6));
        return reference;
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }

    private sealed class InitiatorVerificationCallbacks(
        InitiatorAgreementFacts local,
        VerifiedXpc1PreKeyClaimReceipt claim) : IDph2VerificationCallbacks
    {
        public Dph2ResolvedInitiator ResolveInitiator(Dph2Record initiation)
        {
            if (!Fixed(initiation.NetworkId.Span, local.NetworkId) ||
                !Fixed(initiation.InitiatorAccountId.Span, local.AccountId) ||
                !Fixed(initiation.InitiatorDeviceId.Span, local.DeviceId) ||
                initiation.InitiatorDeviceGeneration != local.DeviceGeneration ||
                !Fixed(initiation.InitiatorDpd1Ref.Span, Dpd1Reference(local.ExactDpd1Hash)))
                throw new CryptographicException("The authored DPH2 changed the local device closure.");
            return new Dph2ResolvedInitiator(local.AgreementPublicKey, local.ExactDirectoryHash);
        }

        public bool VerifyExactClaim(Dph2ClaimVerification verification)
        {
            _ = verification;
            claim.RequireMatchesDph2Header(_current ??
                throw new InvalidOperationException("The current DPH2 record was not captured."));
            return true;
        }

        private Dph2Record? _current;

        Dph2ResolvedInitiator IDph2VerificationCallbacks.ResolveInitiator(Dph2Record initiation)
        {
            _current = initiation;
            return ResolveInitiator(initiation);
        }
    }

}

/// <summary>
/// Single-use transfer of the exact network DPH2 and plaintext durable TRS1 to
/// the caller's authenticated atomic store.
/// </summary>
public sealed class InitiatorInitialSessionCommitCapability : IDisposable
{
    private byte[]? _exactDph2;
    private byte[]? _exactTrs1;
    private readonly byte[] _sessionId;
    private readonly byte[] _operationId;
    private readonly byte[] _fullReplayHash;
    private readonly byte[] _claimBinding;
    private int _consumed;

    internal InitiatorInitialSessionCommitCapability(
        byte[] exactDph2,
        byte[] exactTrs1,
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> fullReplayHash,
        ReadOnlySpan<byte> claimBinding)
    {
        _exactDph2 = exactDph2;
        _exactTrs1 = exactTrs1;
        _sessionId = sessionId.ToArray();
        _operationId = operationId.ToArray();
        _fullReplayHash = fullReplayHash.ToArray();
        _claimBinding = claimBinding.ToArray();
    }

    ~InitiatorInitialSessionCommitCapability() => Dispose();

    public ReadOnlyMemory<byte> SessionId => _sessionId.ToArray();
    public ReadOnlyMemory<byte> ClaimOperationId => _operationId.ToArray();
    public ReadOnlyMemory<byte> FullDph2ReplayHash => _fullReplayHash.ToArray();
    public ReadOnlyMemory<byte> ClaimBinding => _claimBinding.ToArray();

    public InitiatorInitialSessionAtomicStorePayload ConsumeForAtomicStore()
    {
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new InvalidOperationException("The initial-session commit capability is single-use.");
        var dph2 = Interlocked.Exchange(ref _exactDph2, null) ??
            throw new ObjectDisposedException(nameof(InitiatorInitialSessionCommitCapability));
        var trs1 = Interlocked.Exchange(ref _exactTrs1, null);
        if (trs1 is null)
        {
            CryptographicOperations.ZeroMemory(dph2);
            throw new ObjectDisposedException(nameof(InitiatorInitialSessionCommitCapability));
        }
        return new InitiatorInitialSessionAtomicStorePayload(dph2, trs1);
    }

    public void Dispose()
    {
        Zero(Interlocked.Exchange(ref _exactDph2, null));
        Zero(Interlocked.Exchange(ref _exactTrs1, null));
        GC.SuppressFinalize(this);
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}

public sealed class InitiatorInitialSessionAtomicStorePayload : IDisposable
{
    private byte[]? _exactDph2;
    private byte[]? _exactTrs1;

    internal InitiatorInitialSessionAtomicStorePayload(byte[] exactDph2, byte[] exactTrs1)
    {
        _exactDph2 = exactDph2;
        _exactTrs1 = exactTrs1;
    }

    ~InitiatorInitialSessionAtomicStorePayload() => Dispose();

    public int ExactDph2Length => Value(_exactDph2).Length;
    public int ExactTrs1Length => Value(_exactTrs1).Length;
    public ReadOnlyMemory<byte> ExactDph2 => Value(_exactDph2).ToArray();
    public ReadOnlyMemory<byte> ExactTrs1 => Value(_exactTrs1).ToArray();

    public void Dispose()
    {
        Zero(Interlocked.Exchange(ref _exactDph2, null));
        Zero(Interlocked.Exchange(ref _exactTrs1, null));
        GC.SuppressFinalize(this);
    }

    private static byte[] Value(byte[]? value) =>
        value ?? throw new ObjectDisposedException(nameof(InitiatorInitialSessionAtomicStorePayload));

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}

internal sealed class InitiatorAgreementFacts
{
    internal InitiatorAgreementFacts(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> exactDpd1Hash,
        ulong directoryGeneration,
        ReadOnlySpan<byte> exactDirectoryHash,
        ReadOnlySpan<byte> agreementPublicKey,
        ReadOnlySpan<byte> operationBinding)
    {
        MessagingCryptoValidation.NonZeroExact(networkId, 16, nameof(networkId));
        MessagingCryptoValidation.NonZeroExact(accountId, 32, nameof(accountId));
        MessagingCryptoValidation.NonZeroExact(deviceId, 32, nameof(deviceId));
        MessagingCryptoValidation.NonZeroExact(exactDpd1Hash, 32, nameof(exactDpd1Hash));
        MessagingCryptoValidation.NonZeroExact(exactDirectoryHash, 32, nameof(exactDirectoryHash));
        MessagingCryptoValidation.NonZeroExact(agreementPublicKey, 32, nameof(agreementPublicKey));
        MessagingCryptoValidation.NonZeroExact(operationBinding, 32, nameof(operationBinding));
        if (deviceGeneration == 0 || directoryGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(deviceGeneration));
        NetworkId = networkId.ToArray();
        AccountId = accountId.ToArray();
        DeviceId = deviceId.ToArray();
        DeviceGeneration = deviceGeneration;
        ExactDpd1Hash = exactDpd1Hash.ToArray();
        DirectoryGeneration = directoryGeneration;
        ExactDirectoryHash = exactDirectoryHash.ToArray();
        AgreementPublicKey = agreementPublicKey.ToArray();
        OperationBinding = operationBinding.ToArray();
    }

    internal byte[] NetworkId { get; }
    internal byte[] AccountId { get; }
    internal byte[] DeviceId { get; }
    internal ulong DeviceGeneration { get; }
    internal byte[] ExactDpd1Hash { get; }
    internal ulong DirectoryGeneration { get; }
    internal byte[] ExactDirectoryHash { get; }
    internal byte[] AgreementPublicKey { get; }
    internal byte[] OperationBinding { get; }

    internal static InitiatorAgreementFacts FromAuthority(
        LocalDeviceX25519AgreementAuthority authority,
        ulong directoryGeneration,
        ReadOnlySpan<byte> exactDirectoryHash,
        ReadOnlySpan<byte> operationBinding)
    {
        ArgumentNullException.ThrowIfNull(authority);
        return new InitiatorAgreementFacts(
            authority.NetworkId.Span,
            authority.AccountId.Span,
            authority.DeviceId.Span,
            authority.DeviceGeneration,
            authority.ExactDpd1Hash.Span,
            directoryGeneration,
            exactDirectoryHash,
            authority.AgreementPublicKey.Span,
            operationBinding);
    }

    internal static InitiatorAgreementFacts FromLease(LocalDeviceX25519AgreementLease lease) =>
        new(
            lease.NetworkId.Span,
            lease.AccountId.Span,
            lease.DeviceId.Span,
            lease.DeviceGeneration,
            lease.ExactDpd1Hash.Span,
            lease.DirectoryGeneration,
            lease.ExactDirectoryHash.Span,
            lease.AgreementPublicKey.Span,
            lease.OperationBinding.Span);

    internal void RequireSame(InitiatorAgreementFacts other)
    {
        ArgumentNullException.ThrowIfNull(other);
        if (DeviceGeneration != other.DeviceGeneration ||
            DirectoryGeneration != other.DirectoryGeneration ||
            !Fixed(NetworkId, other.NetworkId) ||
            !Fixed(AccountId, other.AccountId) ||
            !Fixed(DeviceId, other.DeviceId) ||
            !Fixed(ExactDpd1Hash, other.ExactDpd1Hash) ||
            !Fixed(ExactDirectoryHash, other.ExactDirectoryHash) ||
            !Fixed(AgreementPublicKey, other.AgreementPublicKey) ||
            !Fixed(OperationBinding, other.OperationBinding))
        {
            throw new CryptographicException(
                "The device-agreement lease does not match the exact pre-XPK1 claim.");
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
