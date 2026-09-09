using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.MessagingCrypto;

/// <summary>
/// Public, non-secret context for authoring one DPK2 member of an exact
/// pre-key inventory epoch. Identity and device fields are derived from the
/// protocol-verified current directory rather than accepted from the caller.
/// </summary>
public sealed class Dpk2AuthoringContext
{
    public Dpk2AuthoringContext(
        Dmd1LineageState currentDirectory,
        ulong prekeyServiceGeneration,
        ulong inventoryEpoch,
        ulong policyGeneration,
        ulong notBeforeUnixSeconds,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds)
    {
        CurrentDirectory = currentDirectory ?? throw new ArgumentNullException(nameof(currentDirectory));
        if (prekeyServiceGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(prekeyServiceGeneration));
        if (inventoryEpoch == 0)
            throw new ArgumentOutOfRangeException(nameof(inventoryEpoch));
        if (policyGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(policyGeneration));
        if (issuedAtUnixSeconds > notBeforeUnixSeconds ||
            notBeforeUnixSeconds >= expiresAtUnixSeconds ||
            expiresAtUnixSeconds - notBeforeUnixSeconds > 2_592_000)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expiresAtUnixSeconds),
                "DPK2 requires issuedAt <= notBefore < expiresAt and a window of at most 30 days.");
        }

        PrekeyServiceGeneration = prekeyServiceGeneration;
        InventoryEpoch = inventoryEpoch;
        PolicyGeneration = policyGeneration;
        NotBeforeUnixSeconds = notBeforeUnixSeconds;
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }

    public Dmd1LineageState CurrentDirectory { get; }
    public ulong PrekeyServiceGeneration { get; }
    public ulong InventoryEpoch { get; }
    public ulong PolicyGeneration { get; }
    public ulong NotBeforeUnixSeconds { get; }
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
}

/// <summary>
/// Device-owned production author for frozen suite 0x0201 DPK2 offerings.
/// It has no public constructor and accepts neither private keys nor a crypto
/// provider from its caller.
/// </summary>
public sealed class Dpk2AuthoringAuthority : IDisposable
{
    private readonly object _gate = new();
    private readonly LocalDeviceX25519AgreementAuthority _deviceAgreement;
    private readonly SecretBuffer _deviceSigningSeed;
    private readonly IIdentityAuthoringRandom _random;
    private IDpk2MlKemKeyGenerator? _mlKem;
    private int _disposed;

    internal Dpk2AuthoringAuthority(
        LocalDeviceX25519AgreementAuthority deviceAgreement,
        ReadOnlySpan<byte> deviceSigningSeed,
        IIdentityAuthoringRandom random,
        IDpk2MlKemKeyGenerator mlKem)
    {
        _deviceAgreement = deviceAgreement ?? throw new ArgumentNullException(nameof(deviceAgreement));
        _random = random ?? throw new ArgumentNullException(nameof(random));
        _mlKem = mlKem ?? throw new ArgumentNullException(nameof(mlKem));
        _deviceSigningSeed = SecretBuffer.ImportExact(
            deviceSigningSeed,
            DeepIdentityCrypto.Ed25519SeedSize,
            nameof(deviceSigningSeed));
    }

    ~Dpk2AuthoringAuthority() => DisposeCore();

    public ReadOnlyMemory<byte> DeviceId => _deviceAgreement.DeviceId;
    public ulong DeviceGeneration => _deviceAgreement.DeviceGeneration;

    public AuthoredDpk2Offering AuthorOneTime(Dpk2AuthoringContext context) =>
        Author(context, Dpk2PrekeyKind.OneTime, reuseLimit: 0);

    public AuthoredDpk2Offering AuthorLastResort(
        Dpk2AuthoringContext context,
        ushort reuseLimit)
    {
        if (reuseLimit is < 1 or > 64)
            throw new ArgumentOutOfRangeException(nameof(reuseLimit), "A last-resort reuse limit must be 1..64.");
        return Author(context, Dpk2PrekeyKind.LastResort, reuseLimit);
    }

    public void Dispose()
    {
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    private AuthoredDpk2Offering Author(
        Dpk2AuthoringContext context,
        Dpk2PrekeyKind kind,
        ushort reuseLimit)
    {
        ArgumentNullException.ThrowIfNull(context);
        lock (_gate)
        {
            ThrowIfDisposed();
            var directory = _deviceAgreement.RequireActiveDirectoryForProtocolOperation(
                context.CurrentDirectory);
            var certificate = directory.Identity.ActiveDevices.Single(device =>
                device.Certificate.DeviceId.Span.SequenceEqual(_deviceAgreement.DeviceId.Span)).Certificate;

            byte[]? bundleId = null;
            byte[]? signedId = null;
            byte[]? signedPrivate = null;
            byte[]? signedPublic = null;
            byte[]? oneTimeId = null;
            byte[]? oneTimePrivate = null;
            byte[]? oneTimePublic = null;
            byte[]? mlKemId = null;
            byte[]? mlKemPublic = null;
            byte[]? mlKemSecret = null;
            byte[]? xSignature = null;
            byte[]? mlKemSignature = null;
            byte[]? bundleSignature = null;
            byte[]? exact = null;
            byte[]? exactHash = null;
            Dpk2PreKeySecretCapability? capability = null;
            try
            {
                bundleId = RandomNonzero32();
                signedId = RandomNonzero32();
                signedPrivate = RandomNonzero32();
                signedPublic = DeepIdentityCrypto.DeriveX25519PublicKey(signedPrivate);
                if (kind == Dpk2PrekeyKind.OneTime)
                {
                    oneTimeId = RandomNonzero32();
                    oneTimePrivate = RandomNonzero32();
                    oneTimePublic = DeepIdentityCrypto.DeriveX25519PublicKey(oneTimePrivate);
                }
                else
                {
                    oneTimeId = [];
                    oneTimePrivate = [];
                    oneTimePublic = [];
                }

                mlKemId = RandomNonzero32();
                using (var generated = _mlKem!.Generate())
                {
                    mlKemPublic = generated.EncapsulationKey.ToArray();
                    generated.UseDecapsulationKey(secret => mlKemSecret = secret.ToArray());
                    if (!_mlKem.EncapsulationKeyMatchesDecapsulationKey(mlKemPublic, mlKemSecret))
                        throw new CryptographicException("The generated ML-KEM key pair failed its ownership check.");
                }

                var dpd1Reference = Dpd1Reference(certificate.CanonicalHash.Span);
                var unsigned = CreateRecord(
                    directory, certificate, context, kind, reuseLimit,
                    bundleId, signedId, signedPublic,
                    oneTimeId, oneTimePublic, mlKemId, mlKemPublic,
                    new byte[64], new byte[64], new byte[64], dpd1Reference);
                xSignature = Sign(MessagingWireCryptographicInputs.GetX25519SignedPrekeySignatureInput(unsigned));
                mlKemSignature = Sign(MessagingWireCryptographicInputs.GetMlKemPrekeySignatureInput(unsigned));
                var partiallySigned = CreateRecord(
                    directory, certificate, context, kind, reuseLimit,
                    bundleId, signedId, signedPublic,
                    oneTimeId, oneTimePublic, mlKemId, mlKemPublic,
                    xSignature, mlKemSignature, new byte[64], dpd1Reference);
                bundleSignature = Sign(MessagingWireCryptographicInputs.GetPrekeyBundleSignatureInput(partiallySigned));
                var record = CreateRecord(
                    directory, certificate, context, kind, reuseLimit,
                    bundleId, signedId, signedPublic,
                    oneTimeId, oneTimePublic, mlKemId, mlKemPublic,
                    xSignature, mlKemSignature, bundleSignature, dpd1Reference);
                exact = Dpk2Codec.Encode(record);
                exactHash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(record);

                capability = new Dpk2PreKeySecretCapability(
                    record,
                    _deviceAgreement.AccountGeneration,
                    exactHash,
                    signedPrivate,
                    oneTimePrivate,
                    mlKemSecret);
                var result = new AuthoredDpk2Offering(record, exact, exactHash, capability);
                capability = null;
                return result;
            }
            finally
            {
                capability?.Dispose();
                Zero(bundleId); Zero(signedId); Zero(signedPrivate); Zero(signedPublic);
                Zero(oneTimeId); Zero(oneTimePrivate); Zero(oneTimePublic);
                Zero(mlKemId); Zero(mlKemPublic); Zero(mlKemSecret);
                Zero(xSignature); Zero(mlKemSignature); Zero(bundleSignature);
                Zero(exact); Zero(exactHash);
            }
        }
    }

    private Dpk2Record CreateRecord(
        VerifiedDmd1 directory,
        Deep.Protocol.DeepNative.DeviceCertificate certificate,
        Dpk2AuthoringContext context,
        Dpk2PrekeyKind kind,
        ushort reuseLimit,
        ReadOnlySpan<byte> bundleId,
        ReadOnlySpan<byte> signedId,
        ReadOnlySpan<byte> signedPublic,
        ReadOnlySpan<byte> oneTimeId,
        ReadOnlySpan<byte> oneTimePublic,
        ReadOnlySpan<byte> mlKemId,
        ReadOnlySpan<byte> mlKemPublic,
        ReadOnlySpan<byte> xSignature,
        ReadOnlySpan<byte> mlKemSignature,
        ReadOnlySpan<byte> bundleSignature,
        ReadOnlySpan<byte> dpd1Reference) =>
        new(
            directory.Record.NetworkId.Span,
            directory.Record.DeepAccountId.Span,
            certificate.DeviceId.Span,
            certificate.DeviceGeneration,
            dpd1Reference,
            directory.Record.DirectoryGeneration,
            directory.Record.RecordHash.Span,
            context.PrekeyServiceGeneration,
            context.InventoryEpoch,
            bundleId,
            context.PolicyGeneration,
            context.NotBeforeUnixSeconds,
            context.IssuedAtUnixSeconds,
            context.ExpiresAtUnixSeconds,
            _deviceAgreement.AgreementPublicKey.Span,
            signedId,
            signedPublic,
            xSignature,
            oneTimeId,
            oneTimePublic,
            mlKemId,
            mlKemPublic,
            kind,
            reuseLimit,
            mlKemSignature,
            bundleSignature);

    private byte[] Sign(byte[] signingInput)
    {
        var signature = new byte[OwnedSodiumEd25519.SignatureSize];
        var temporaryPublic = new byte[OwnedSodiumEd25519.PublicKeySize];
        var temporarySecret = new byte[OwnedSodiumEd25519.SecretKeySize];
        try
        {
            _deviceSigningSeed.Use(seed => OwnedSodiumEd25519.SignDetached(
                seed, signingInput, signature, temporaryPublic, temporarySecret));
            return signature;
        }
        catch
        {
            Zero(signature);
            throw;
        }
        finally
        {
            Zero(signingInput);
            Zero(temporaryPublic);
            Zero(temporarySecret);
        }
    }

    private byte[] RandomNonzero32()
    {
        var value = new byte[32];
        do _random.Fill(value); while (DeepIdentityCrypto.IsAllZero(value));
        return value;
    }

    private static byte[] Dpd1Reference(ReadOnlySpan<byte> hash)
    {
        var result = new byte[38];
        Encoding.ASCII.GetBytes("DPD1").CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }

    private void DisposeCore()
    {
        lock (_gate)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _deviceSigningSeed.Dispose();
            _deviceAgreement.Dispose();
            Interlocked.Exchange(ref _mlKem, null)?.Dispose();
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed != 0, this);
    private static void Zero(byte[]? value) { if (value is not null) CryptographicOperations.ZeroMemory(value); }
}

/// <summary>Canonical DPK2 plus exclusive ownership of its local secret capability.</summary>
public sealed class AuthoredDpk2Offering : IDisposable
{
    private readonly Dpk2Record _record;
    private readonly byte[] _exact;
    private readonly byte[] _hash;
    private Dpk2PreKeySecretCapability? _secret;

    internal AuthoredDpk2Offering(
        Dpk2Record record,
        ReadOnlySpan<byte> exact,
        ReadOnlySpan<byte> hash,
        Dpk2PreKeySecretCapability secret)
    {
        _record = record;
        _exact = exact.ToArray();
        _hash = hash.ToArray();
        _secret = secret;
    }

    ~AuthoredDpk2Offering() => Dispose();

    public Dpk2Record Record => _record;
    public ReadOnlyMemory<byte> ExactDpk2 => _exact.ToArray();
    public ReadOnlyMemory<byte> ExactDpk2Hash => _hash.ToArray();

    public Dpk2PreKeySecretCapability TakeSecretCapability() =>
        Interlocked.Exchange(ref _secret, null) ??
        throw new InvalidOperationException("The DPK2 secret capability is no longer available.");

    /// <summary>
    /// Atomically transfers and seals the offering's private pre-key material.
    /// The private capability is burned even when sealing fails.
    /// </summary>
    public Dpk2PreKeyPersistenceBlob SealSecretForPersistence(
        Dpk2PreKeyPersistenceProtector protector,
        Dpk2PreKeyPersistenceScope scope)
    {
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(scope);
        using var secret = TakeSecretCapability();
        return secret.SealForPersistence(protector, _exact, scope);
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _secret, null)?.Dispose();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Opaque owner of the local private material for one exact authored DPK2.
/// It exposes identifiers and bindings only; raw keys can be transferred only
/// to protocol-internal persistence/handshake owners.
/// </summary>
public sealed class Dpk2PreKeySecretCapability : IDisposable
{
    private readonly byte[] _networkId;
    private readonly byte[] _accountId;
    private readonly ulong _accountGeneration;
    private readonly byte[] _deviceId;
    private readonly ulong _deviceGeneration;
    private readonly byte[] _dpd1Reference;
    private readonly byte[] _exactHash;
    private readonly byte[] _signedPreKeyId;
    private readonly byte[] _oneTimePreKeyId;
    private readonly byte[] _mlKemPreKeyId;
    private SecretBuffer? _signedPrivate;
    private SecretBuffer? _oneTimePrivate;
    private SecretBuffer? _mlKemSecret;
    private int _disposed;

    internal Dpk2PreKeySecretCapability(
        Dpk2Record record,
        ulong accountGeneration,
        ReadOnlySpan<byte> exactHash,
        ReadOnlySpan<byte> signedPrivate,
        ReadOnlySpan<byte> oneTimePrivate,
        ReadOnlySpan<byte> mlKemSecret)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (accountGeneration == 0) throw new ArgumentOutOfRangeException(nameof(accountGeneration));
        _networkId = record.NetworkId.ToArray();
        _accountId = record.ResponderAccountId.ToArray();
        _accountGeneration = accountGeneration;
        _deviceId = record.ResponderDeviceId.ToArray();
        _deviceGeneration = record.ResponderDeviceGeneration;
        _dpd1Reference = record.ResponderDpd1Ref.ToArray();
        _exactHash = exactHash.ToArray();
        _signedPreKeyId = record.SignedX25519PrekeyId.ToArray();
        _oneTimePreKeyId = record.OneTimeX25519PrekeyId.ToArray();
        _mlKemPreKeyId = record.MlKemPrekeyId.ToArray();
        Kind = record.MlKemKind;
        ReuseLimit = record.ReuseLimit;
        _signedPrivate = SecretBuffer.ImportExact(signedPrivate, 32, nameof(signedPrivate));
        _oneTimePrivate = oneTimePrivate.IsEmpty
            ? null
            : SecretBuffer.ImportExact(oneTimePrivate, 32, nameof(oneTimePrivate));
        _mlKemSecret = SecretBuffer.ImportBounded(mlKemSecret, 1, 4096, nameof(mlKemSecret));
    }

    ~Dpk2PreKeySecretCapability() => Dispose();

    public Dpk2PrekeyKind Kind { get; }
    public ushort ReuseLimit { get; }
    public ReadOnlyMemory<byte> ExactDpk2Hash => _exactHash.ToArray();
    public ReadOnlyMemory<byte> SignedX25519PreKeyId => _signedPreKeyId.ToArray();
    public ReadOnlyMemory<byte> OneTimeX25519PreKeyId => _oneTimePreKeyId.ToArray();
    public ReadOnlyMemory<byte> MlKemPreKeyId => _mlKemPreKeyId.ToArray();

    /// <summary>
    /// Consumes this capability and returns only authenticated ciphertext.
    /// Raw private material never crosses the Protocol assembly boundary.
    /// </summary>
    public Dpk2PreKeyPersistenceBlob SealForPersistence(
        Dpk2PreKeyPersistenceProtector protector,
        ReadOnlyMemory<byte> exactDpk2,
        Dpk2PreKeyPersistenceScope scope)
    {
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(scope);
        return protector.SealAndConsume(this, exactDpk2.Span, scope);
    }

    internal void RequirePersistenceBinding(
        Dpk2Record record,
        ReadOnlySpan<byte> exactHash,
        Dpk2PreKeyPersistenceScope scope)
    {
        if (!scope.Matches(record) ||
            scope.AccountGeneration != _accountGeneration ||
            scope.DeviceGeneration != _deviceGeneration ||
            !Dpk2PreKeyPersistenceScope.Fixed(_networkId, scope.NetworkIdSpan) ||
            !Dpk2PreKeyPersistenceScope.Fixed(_accountId, scope.AccountIdSpan) ||
            !Dpk2PreKeyPersistenceScope.Fixed(_deviceId, scope.DeviceIdSpan) ||
            !Dpk2PreKeyPersistenceScope.Fixed(_dpd1Reference, scope.Dpd1ReferenceSpan) ||
            !Dpk2PreKeyPersistenceScope.Fixed(_exactHash, exactHash) ||
            Kind != record.MlKemKind || ReuseLimit != record.ReuseLimit ||
            !Dpk2PreKeyPersistenceScope.Fixed(_signedPreKeyId, record.SignedX25519PrekeyId.Span) ||
            !Dpk2PreKeyPersistenceScope.Fixed(_oneTimePreKeyId, record.OneTimeX25519PrekeyId.Span) ||
            !Dpk2PreKeyPersistenceScope.Fixed(_mlKemPreKeyId, record.MlKemPrekeyId.Span))
            throw new CryptographicException(
                "The DPK2 secret capability does not match the exact offering and persistence scope.");
    }

    internal OwnedDpk2PreKeyMaterial ConsumeForProtocolOwner()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
            throw new InvalidOperationException("The DPK2 secret capability has already been consumed.");
        try
        {
            return new OwnedDpk2PreKeyMaterial(
                _signedPrivate!.Copy(),
                _oneTimePrivate?.Copy(),
                _mlKemSecret!.Copy());
        }
        finally
        {
            DisposeSecrets();
            GC.SuppressFinalize(this);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0) DisposeSecrets();
        GC.SuppressFinalize(this);
    }

    private void DisposeSecrets()
    {
        Interlocked.Exchange(ref _signedPrivate, null)?.Dispose();
        Interlocked.Exchange(ref _oneTimePrivate, null)?.Dispose();
        Interlocked.Exchange(ref _mlKemSecret, null)?.Dispose();
    }
}

internal sealed class OwnedDpk2PreKeyMaterial : IDisposable
{
    internal OwnedDpk2PreKeyMaterial(byte[] signedPrivate, byte[]? oneTimePrivate, byte[] mlKemSecret)
    {
        SignedPrivate = signedPrivate;
        OneTimePrivate = oneTimePrivate;
        MlKemSecret = mlKemSecret;
    }

    internal byte[] SignedPrivate { get; }
    internal byte[]? OneTimePrivate { get; }
    internal byte[] MlKemSecret { get; }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(SignedPrivate);
        if (OneTimePrivate is not null) CryptographicOperations.ZeroMemory(OneTimePrivate);
        CryptographicOperations.ZeroMemory(MlKemSecret);
    }
}

internal interface IDpk2MlKemKeyGenerator : IDisposable
{
    OwnedMlKem768KeyPair Generate();
    bool EncapsulationKeyMatchesDecapsulationKey(
        ReadOnlySpan<byte> encapsulationKey,
        ReadOnlySpan<byte> decapsulationKey);
}

internal sealed class ApprovedDpk2MlKemKeyGenerator : IDpk2MlKemKeyGenerator
{
    private readonly object _gate = new();
    private DeepMlKemNativeProvider? _provider;
    private bool _disposed;

    public OwnedMlKem768KeyPair Generate()
    {
        lock (_gate) return Provider().GenerateKeyPair();
    }

    public bool EncapsulationKeyMatchesDecapsulationKey(
        ReadOnlySpan<byte> encapsulationKey,
        ReadOnlySpan<byte> decapsulationKey)
    {
        lock (_gate) return Provider().EncapsulationKeyMatchesDecapsulationKey(
            encapsulationKey, decapsulationKey);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _provider?.Dispose();
            _provider = null;
        }
    }

    private DeepMlKemNativeProvider Provider()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _provider ??= DeepMlKemNativeProvider.LoadApprovedForCurrentProcess();
    }
}
