using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Identity;

/// <summary>
/// Closed uses of the long-lived device identity-agreement key in the frozen
/// DPH2 hybrid handshake. A new purpose requires a reviewed protocol change.
/// </summary>
public enum LocalDeviceX25519AgreementPurpose : byte
{
    Dph2InitiatorDh1 = 1,
    Dph2ResponderDh2 = 2,
}

/// <summary>
/// Long-lived, non-exportable owner of one verified device-generation X25519 agreement key.
/// It has no public constructor or raw agreement method. A holder can open only
/// an operation-bound lease after supplying an unforked exact DMD1 lineage head
/// in which that exact DPD1 generation is active.
/// </summary>
public sealed class LocalDeviceX25519AgreementAuthority : IDisposable
{
    private readonly object _sync = new();
    private readonly byte[] _networkId;
    private readonly byte[] _accountId;
    private readonly byte[] _deviceId;
    private readonly byte[] _dpd1Hash;
    private readonly byte[] _dpa1Hash;
    private readonly byte[] _drs1Hash;
    private readonly byte[] _agreementPublicKey;
    private readonly VerifiedDeviceRelative _verifiedDevice;
    private byte[]? _agreementPrivateScalar;

    private LocalDeviceX25519AgreementAuthority(
        VerifiedDeviceRelative verifiedDevice,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> dpd1Hash,
        ReadOnlySpan<byte> dpa1Hash,
        ReadOnlySpan<byte> drs1Hash,
        ReadOnlySpan<byte> agreementPublicKey,
        ReadOnlySpan<byte> agreementPrivateScalar)
    {
        _verifiedDevice = verifiedDevice;
        _networkId = networkId.ToArray();
        _accountId = accountId.ToArray();
        AccountGeneration = accountGeneration;
        _deviceId = deviceId.ToArray();
        DeviceGeneration = deviceGeneration;
        _dpd1Hash = dpd1Hash.ToArray();
        _dpa1Hash = dpa1Hash.ToArray();
        _drs1Hash = drs1Hash.ToArray();
        _agreementPublicKey = agreementPublicKey.ToArray();
        _agreementPrivateScalar = agreementPrivateScalar.ToArray();
    }

    ~LocalDeviceX25519AgreementAuthority() => DisposeCore();

    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> AccountId => _accountId.ToArray();
    public ulong AccountGeneration { get; }
    public ReadOnlyMemory<byte> DeviceId => _deviceId.ToArray();
    public ulong DeviceGeneration { get; }
    public ReadOnlyMemory<byte> ExactDpd1Hash => _dpd1Hash.ToArray();
    public ReadOnlyMemory<byte> AgreementPublicKey => _agreementPublicKey.ToArray();

    internal static LocalDeviceX25519AgreementAuthority Create(
        VerifiedDeviceRelative verifiedDevice,
        DeviceId32 localDeviceId,
        DeviceX25519PublicKey32 localAgreementPublicKey,
        ReadOnlySpan<byte> localAgreementPrivateScalar)
    {
        ArgumentNullException.ThrowIfNull(verifiedDevice);
        ArgumentNullException.ThrowIfNull(localDeviceId);
        ArgumentNullException.ThrowIfNull(localAgreementPublicKey);
        var certificate = verifiedDevice.Certificate;
        if (!localDeviceId.Matches(certificate.DeviceId.Span) ||
            !localAgreementPublicKey.Matches(certificate.DeviceX25519PublicKey.Span) ||
            certificate.DeviceGeneration == 0 ||
            certificate.AccountGeneration == 0)
        {
            Reject("Local device secrets do not match the exact verified DPD1 capability.");
        }

        var identity = verifiedDevice.Identity;
        var verified = verifiedDevice.Device;
        if (!certificate.NetworkId.Span.SequenceEqual(identity.Account.Certificate.NetworkId.Span) ||
            !certificate.AccountHash.Span.SequenceEqual(identity.Account.DeepAccountIdHash.Span) ||
            certificate.AccountGeneration != identity.Account.Certificate.AccountGeneration ||
            identity.IsTerminal || identity.ForkLatched ||
            !SameArtifact(verified.Revocations.Snapshot, identity.Revocations.Snapshot) ||
            verified.Revocations.Catalog.Contains(ArtifactType.Dpd1, certificate.CanonicalHash.Span))
        {
            Reject("The verified DPD1 is not live in its exact unforked DPA1/DRS1 identity closure.");
        }

        if (!DeepIdentityCrypto.X25519PublicKeyMatchesPrivateScalar(
                localAgreementPrivateScalar,
                certificate.DeviceX25519PublicKey.Span))
        {
            Reject("The local X25519 private scalar does not match the exact verified DPD1 public key.");
        }

        return new LocalDeviceX25519AgreementAuthority(
            verifiedDevice,
            certificate.NetworkId.Span,
            certificate.AccountHash.Span,
            certificate.AccountGeneration,
            certificate.DeviceId.Span,
            certificate.DeviceGeneration,
            certificate.CanonicalHash.Span,
            identity.Account.Certificate.CanonicalHash.Span,
            identity.Revocations.Snapshot.CanonicalHash.Span,
            certificate.DeviceX25519PublicKey.Span,
            localAgreementPrivateScalar);
    }

    public LocalDeviceX25519AgreementLease OpenOperation(
        Dmd1LineageState exactCurrentDirectory,
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlySpan<byte> operationBinding,
        ReadOnlySpan<byte> peerPublicKey)
    {
        ArgumentNullException.ThrowIfNull(exactCurrentDirectory);
        ValidatePurposeAndOperation(purpose, operationBinding);
        ValidatePeerPublicKey(peerPublicKey);
        lock (_sync)
        {
            ThrowIfDisposed();
            // Dmd1LineageState proves the exact verified lineage/fork state. The
            // durable store remains responsible for current-LKG freshness and
            // burning the operation before redeeming this one-shot capability.
            ValidateActiveDirectory(exactCurrentDirectory);
            var exactActiveDirectory = exactCurrentDirectory.Head;
            return new LocalDeviceX25519AgreementLease(
                Agree,
                purpose,
                operationBinding,
                peerPublicKey,
                _networkId,
                _accountId,
                AccountGeneration,
                _deviceId,
                DeviceGeneration,
                _dpd1Hash,
                _agreementPublicKey,
                exactActiveDirectory.Record.DirectoryGeneration,
                exactActiveDirectory.Record.RecordHash.Span);
        }
    }

    private LocalDeviceX25519SharedSecret Agree(ReadOnlySpan<byte> peerPublicKey)
    {
        ValidatePeerPublicKey(peerPublicKey);
        lock (_sync)
        {
            ThrowIfDisposed();
            Span<byte> shared = stackalloc byte[DeepIdentityCrypto.X25519PublicKeySize];
            try
            {
                OwnedSodiumX25519.Agree(_agreementPrivateScalar!, peerPublicKey, shared);
                return LocalDeviceX25519SharedSecret.Create(shared);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(shared);
            }
        }
    }

    internal VerifiedDmd1 RequireActiveDirectoryForProtocolOperation(
        Dmd1LineageState exactCurrentDirectory)
    {
        ArgumentNullException.ThrowIfNull(exactCurrentDirectory);
        lock (_sync)
        {
            ThrowIfDisposed();
            ValidateActiveDirectory(exactCurrentDirectory);
            return exactCurrentDirectory.Head;
        }
    }

    public void Dispose()
    {
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    private void ValidateActiveDirectory(Dmd1LineageState directoryState)
    {
        if (directoryState.ForkLatched || _verifiedDevice.Identity.ForkLatched ||
            _verifiedDevice.Identity.IsTerminal)
        {
            Reject("A forked or terminal identity/directory cannot authorize device agreement.");
        }

        var directory = directoryState.Head;
        var record = directory.Record;
        if (record.MinimumMessagingSuite != 0x0201 ||
            record.DirectoryGeneration == 0 ||
            !record.NetworkId.Span.SequenceEqual(_networkId) ||
            !record.DeepAccountId.Span.SequenceEqual(_accountId) ||
            record.AccountGeneration != AccountGeneration ||
            !directory.Identity.Account.Certificate.CanonicalHash.Span.SequenceEqual(_dpa1Hash) ||
            !directory.Identity.Revocations.Snapshot.CanonicalHash.Span.SequenceEqual(_drs1Hash) ||
            !SameArtifact(_verifiedDevice.Identity.Revocations.Snapshot,
                directory.Identity.Revocations.Snapshot) ||
            !SameArtifact(_verifiedDevice.Device.Revocations.Snapshot,
                directory.Identity.Revocations.Snapshot) ||
            _verifiedDevice.Identity.Revocations.Catalog.Contains(ArtifactType.Dpd1, _dpd1Hash) ||
            directory.Identity.Revocations.Catalog.Contains(ArtifactType.Dpd1, _dpd1Hash))
        {
            Reject("The verified DMD1 is not the authority account bound to this device key.");
        }

        var matchingEntry = record.ActiveDevices.SingleOrDefault(entry =>
            entry.DeviceId.Span.SequenceEqual(_deviceId));
        if (matchingEntry is null ||
            matchingEntry.Dpd1Reference.TypeCode != (ushort)ArtifactType.Dpd1 ||
            matchingEntry.Dpd1Reference.CanonicalLength != 776 ||
            !matchingEntry.Dpd1Reference.CanonicalHash.Span.SequenceEqual(_dpd1Hash))
        {
            Reject("The verified DMD1 does not contain the exact DPD1 generation as an active device.");
        }

        var activeDevice = directory.Identity.ActiveDevices.SingleOrDefault(device =>
            device.Certificate.DeviceId.Span.SequenceEqual(_deviceId));
        if (activeDevice is null ||
            !activeDevice.Certificate.CanonicalHash.Span.SequenceEqual(_dpd1Hash) ||
            !activeDevice.Certificate.DeviceX25519PublicKey.Span.SequenceEqual(_agreementPublicKey) ||
            activeDevice.Certificate.DeviceGeneration != DeviceGeneration ||
            !activeDevice.Certificate.AccountHash.Span.SequenceEqual(_accountId) ||
            !activeDevice.Certificate.NetworkId.Span.SequenceEqual(_networkId))
        {
            Reject("The verified DMD1 identity closure changed the active device certificate or agreement key.");
        }
    }

    private void DisposeCore()
    {
        lock (_sync)
        {
            if (_agreementPrivateScalar is null)
                return;
            CryptographicOperations.ZeroMemory(_agreementPrivateScalar);
            _agreementPrivateScalar = null;
        }
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(_agreementPrivateScalar is null, this);

    internal static void ValidatePurposeAndOperation(
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlySpan<byte> operationBinding)
    {
        if (purpose is not (LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1 or
            LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2))
        {
            throw new ArgumentOutOfRangeException(nameof(purpose), "The device agreement purpose is not frozen.");
        }
        if (operationBinding.Length != 32 || DeepIdentityCrypto.IsAllZero(operationBinding))
        {
            throw new ArgumentException("The handshake operation binding must be a non-zero 32-byte value.", nameof(operationBinding));
        }
    }

    internal static void ValidatePeerPublicKey(ReadOnlySpan<byte> peerPublicKey)
    {
        if (peerPublicKey.Length != 32 || DeepIdentityCrypto.IsAllZero(peerPublicKey))
        {
            throw new ArgumentException("The peer X25519 public key must be a non-zero 32-byte value.", nameof(peerPublicKey));
        }
    }

    private static void Reject(string message) =>
        throw new RecordException(RecordError.InvalidTransition, message);

    private static bool SameArtifact(CanonicalIdentityArtifact left, CanonicalIdentityArtifact right) =>
        left.ArtifactType == right.ArtifactType &&
        left.CanonicalBytes.Length == right.CanonicalBytes.Length &&
        left.CanonicalHash.Span.SequenceEqual(right.CanonicalHash.Span);
}

/// <summary>
/// One exact DPH2 operation authorization. It carries no private key and has no
/// public agreement method; the protocol consumes it once inside this assembly.
/// </summary>
public sealed class LocalDeviceX25519AgreementLease : IDisposable
{
    private readonly object _sync = new();
    private LocalDeviceX25519AgreementOperation? _agree;
    private readonly byte[] _operationBinding;
    private readonly byte[] _directoryHash;
    private readonly byte[] _peerPublicKey;
    private readonly byte[] _networkId;
    private readonly byte[] _accountId;
    private readonly byte[] _deviceId;
    private readonly byte[] _dpd1Hash;
    private readonly byte[] _agreementPublicKey;
    private int _state;

    internal LocalDeviceX25519AgreementLease(
        LocalDeviceX25519AgreementOperation agree,
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlySpan<byte> operationBinding,
        ReadOnlySpan<byte> peerPublicKey,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> dpd1Hash,
        ReadOnlySpan<byte> agreementPublicKey,
        ulong directoryGeneration,
        ReadOnlySpan<byte> directoryHash)
    {
        _agree = agree ?? throw new ArgumentNullException(nameof(agree));
        Purpose = purpose;
        _operationBinding = operationBinding.ToArray();
        _peerPublicKey = peerPublicKey.ToArray();
        _networkId = networkId.ToArray();
        _accountId = accountId.ToArray();
        AccountGeneration = accountGeneration;
        _deviceId = deviceId.ToArray();
        DeviceGeneration = deviceGeneration;
        _dpd1Hash = dpd1Hash.ToArray();
        _agreementPublicKey = agreementPublicKey.ToArray();
        DirectoryGeneration = directoryGeneration;
        _directoryHash = directoryHash.ToArray();
    }

    public LocalDeviceX25519AgreementPurpose Purpose { get; }
    public ReadOnlyMemory<byte> OperationBinding => _operationBinding.ToArray();
    public ulong DirectoryGeneration { get; }
    public ReadOnlyMemory<byte> ExactDirectoryHash => _directoryHash.ToArray();
    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> AccountId => _accountId.ToArray();
    public ulong AccountGeneration { get; }
    public ReadOnlyMemory<byte> DeviceId => _deviceId.ToArray();
    public ulong DeviceGeneration { get; }
    public ReadOnlyMemory<byte> ExactDpd1Hash => _dpd1Hash.ToArray();
    public ReadOnlyMemory<byte> AgreementPublicKey => _agreementPublicKey.ToArray();

    internal LocalDeviceX25519SharedSecret AgreeOnce(
        LocalDeviceX25519AgreementPurpose expectedPurpose,
        ReadOnlySpan<byte> expectedOperationBinding) =>
        AgreeOnceCore(expectedPurpose, expectedOperationBinding, default, requireExpectedPeer: false);

    internal LocalDeviceX25519SharedSecret AgreeOnceForExpectedPeer(
        LocalDeviceX25519AgreementPurpose expectedPurpose,
        ReadOnlySpan<byte> expectedOperationBinding,
        ReadOnlySpan<byte> expectedPeerPublicKey)
    {
        LocalDeviceX25519AgreementAuthority.ValidatePeerPublicKey(expectedPeerPublicKey);
        return AgreeOnceCore(
            expectedPurpose,
            expectedOperationBinding,
            expectedPeerPublicKey,
            requireExpectedPeer: true);
    }

    private LocalDeviceX25519SharedSecret AgreeOnceCore(
        LocalDeviceX25519AgreementPurpose expectedPurpose,
        ReadOnlySpan<byte> expectedOperationBinding,
        ReadOnlySpan<byte> expectedPeerPublicKey,
        bool requireExpectedPeer)
    {
        LocalDeviceX25519AgreementAuthority.ValidatePurposeAndOperation(
            expectedPurpose, expectedOperationBinding);
        lock (_sync)
        {
            if (_state != 0)
                throw new InvalidOperationException("The device agreement lease is no longer available.");
            if (expectedPurpose != Purpose ||
                !CryptographicOperations.FixedTimeEquals(_operationBinding, expectedOperationBinding) ||
                (requireExpectedPeer &&
                 !CryptographicOperations.FixedTimeEquals(_peerPublicKey, expectedPeerPublicKey)))
            {
                throw new RecordException(
                    RecordError.InvalidTransition,
                    "The device agreement lease is bound to another handshake operation, purpose, or peer key.");
            }
            _state = 1;
            var agree = _agree ?? throw new InvalidOperationException(
                "The device agreement lease lost its authority binding.");
            try
            {
                return agree(_peerPublicKey);
            }
            finally
            {
                _agree = null;
                ZeroBindings();
                _state = 2;
            }
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_state == 2)
                return;
            _state = 2;
            _agree = null;
            ZeroBindings();
        }
    }

    private void ZeroBindings()
    {
        CryptographicOperations.ZeroMemory(_operationBinding);
        CryptographicOperations.ZeroMemory(_directoryHash);
        CryptographicOperations.ZeroMemory(_peerPublicKey);
        CryptographicOperations.ZeroMemory(_networkId);
        CryptographicOperations.ZeroMemory(_accountId);
        CryptographicOperations.ZeroMemory(_deviceId);
        CryptographicOperations.ZeroMemory(_dpd1Hash);
        CryptographicOperations.ZeroMemory(_agreementPublicKey);
    }
}

internal delegate LocalDeviceX25519SharedSecret LocalDeviceX25519AgreementOperation(
    ReadOnlySpan<byte> peerPublicKey);

internal delegate TResult LocalDeviceX25519SharedSecretReader<TResult>(ReadOnlySpan<byte> sharedSecret);

internal sealed class LocalDeviceX25519SharedSecret : IDisposable
{
    private readonly object _sync = new();
    private byte[]? _sharedSecret;

    private LocalDeviceX25519SharedSecret(ReadOnlySpan<byte> sharedSecret) =>
        _sharedSecret = sharedSecret.ToArray();

    ~LocalDeviceX25519SharedSecret() => DisposeCore();

    internal static LocalDeviceX25519SharedSecret Create(ReadOnlySpan<byte> sharedSecret)
    {
        if (sharedSecret.Length != 32 || DeepIdentityCrypto.IsAllZero(sharedSecret))
            throw new CryptographicException("X25519 produced an invalid shared secret.");
        return new LocalDeviceX25519SharedSecret(sharedSecret);
    }

    internal TResult Consume<TResult>(LocalDeviceX25519SharedSecretReader<TResult> reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        byte[] owned;
        lock (_sync)
        {
            owned = _sharedSecret ?? throw new ObjectDisposedException(nameof(LocalDeviceX25519SharedSecret));
            _sharedSecret = null;
        }
        try
        {
            return reader(owned);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(owned);
            GC.SuppressFinalize(this);
        }
    }

    public void Dispose()
    {
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    private void DisposeCore()
    {
        lock (_sync)
        {
            if (_sharedSecret is null)
                return;
            CryptographicOperations.ZeroMemory(_sharedSecret);
            _sharedSecret = null;
        }
    }
}
