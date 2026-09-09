using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepNative;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Protocol.Identity;

/// <summary>
/// Owns an exact persisted local-device secret payload until it is either restored
/// into protocol-owned device secrets or disposed. This payload never represents
/// DPD1/DXR1 authority.
/// </summary>
public sealed class OwnedPersistedDeviceIdentitySecrets : IDisposable
{
    private readonly object sync = new();
    private byte[]? signingSeed;
    private byte[]? agreementPrivateScalar;
    private byte[]? deviceId;
    private byte[]? revocationHandle;
    private int disposed;

    private OwnedPersistedDeviceIdentitySecrets(
        byte[] signingSeed32,
        byte[] agreementPrivateScalar32,
        byte[] deviceId32,
        byte[] revocationHandle32)
    {
        signingSeed = signingSeed32;
        agreementPrivateScalar = agreementPrivateScalar32;
        deviceId = deviceId32;
        revocationHandle = revocationHandle32;
    }

    /// <summary>
    /// Consumes four exact 32-byte arrays into private protocol-owned copies.
    /// Every supplied array is zeroed on both success and failure.
    /// </summary>
    public static OwnedPersistedDeviceIdentitySecrets TakeOwnership(
        byte[] signingSeed32,
        byte[] agreementPrivateScalar32,
        byte[] deviceId32,
        byte[] revocationHandle32)
    {
        byte[]? ownedSigning = null;
        byte[]? ownedAgreement = null;
        byte[]? ownedDeviceId = null;
        byte[]? ownedRevocation = null;
        try
        {
            ArgumentNullException.ThrowIfNull(signingSeed32);
            ArgumentNullException.ThrowIfNull(agreementPrivateScalar32);
            ArgumentNullException.ThrowIfNull(deviceId32);
            ArgumentNullException.ThrowIfNull(revocationHandle32);
            if (signingSeed32.Length != 32 || agreementPrivateScalar32.Length != 32 ||
                deviceId32.Length != 32 || revocationHandle32.Length != 32 ||
                DeepIdentityCrypto.IsAllZero(signingSeed32) ||
                DeepIdentityCrypto.IsAllZero(agreementPrivateScalar32) ||
                DeepIdentityCrypto.IsAllZero(deviceId32) ||
                DeepIdentityCrypto.IsAllZero(revocationHandle32) ||
                ReferenceEquals(signingSeed32, agreementPrivateScalar32) ||
                ReferenceEquals(signingSeed32, deviceId32) ||
                ReferenceEquals(signingSeed32, revocationHandle32) ||
                ReferenceEquals(agreementPrivateScalar32, deviceId32) ||
                ReferenceEquals(agreementPrivateScalar32, revocationHandle32) ||
                ReferenceEquals(deviceId32, revocationHandle32))
                throw new ArgumentException(
                    "Persisted device identity values must be distinct nonzero 32-byte arrays.");

            ownedSigning = signingSeed32.ToArray();
            ownedAgreement = agreementPrivateScalar32.ToArray();
            ownedDeviceId = deviceId32.ToArray();
            ownedRevocation = revocationHandle32.ToArray();
            var result = new OwnedPersistedDeviceIdentitySecrets(
                ownedSigning, ownedAgreement, ownedDeviceId, ownedRevocation);
            ownedSigning = ownedAgreement = ownedDeviceId = ownedRevocation = null;
            return result;
        }
        finally
        {
            Zero(ownedSigning);
            Zero(ownedAgreement);
            Zero(ownedDeviceId);
            Zero(ownedRevocation);
            Zero(signingSeed32);
            Zero(agreementPrivateScalar32);
            Zero(deviceId32);
            Zero(revocationHandle32);
        }
    }

    /// <summary>
    /// Copies the owned payload into caller-provided exact 32-byte buffers for
    /// protected persistence. The caller owns and must zero those output buffers.
    /// </summary>
    public void CopyTo(
        Span<byte> signingSeed32,
        Span<byte> agreementPrivateScalar32,
        Span<byte> deviceId32,
        Span<byte> revocationHandle32)
    {
        if (signingSeed32.Length != 32 || agreementPrivateScalar32.Length != 32 ||
            deviceId32.Length != 32 || revocationHandle32.Length != 32 ||
            signingSeed32.Overlaps(agreementPrivateScalar32) ||
            signingSeed32.Overlaps(deviceId32) ||
            signingSeed32.Overlaps(revocationHandle32) ||
            agreementPrivateScalar32.Overlaps(deviceId32) ||
            agreementPrivateScalar32.Overlaps(revocationHandle32) ||
            deviceId32.Overlaps(revocationHandle32))
            throw new ArgumentException("Every persisted device identity destination must be 32 bytes.");
        lock (sync)
        {
            ThrowIfDisposed();
            signingSeed!.CopyTo(signingSeed32);
            agreementPrivateScalar!.CopyTo(agreementPrivateScalar32);
            deviceId!.CopyTo(deviceId32);
            revocationHandle!.CopyTo(revocationHandle32);
        }
    }

    internal (byte[] SigningSeed, byte[] AgreementPrivateScalar, byte[] DeviceId,
        byte[] RevocationHandle) CopyAndDispose()
    {
        byte[]? signing = null;
        byte[]? agreement = null;
        byte[]? id = null;
        byte[]? revocation = null;
        lock (sync)
        {
            ThrowIfDisposed();
            try
            {
                signing = signingSeed!.ToArray();
                agreement = agreementPrivateScalar!.ToArray();
                id = deviceId!.ToArray();
                revocation = revocationHandle!.ToArray();
                DisposeCore();
                var result = (signing, agreement, id, revocation);
                signing = agreement = id = revocation = null;
                return result;
            }
            finally
            {
                DisposeCore();
                Zero(signing);
                Zero(agreement);
                Zero(id);
                Zero(revocation);
            }
        }
    }

    public void Dispose()
    {
        lock (sync) DisposeCore();
    }

    private void DisposeCore()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        Zero(signingSeed);
        Zero(agreementPrivateScalar);
        Zero(deviceId);
        Zero(revocationHandle);
        signingSeed = agreementPrivateScalar = deviceId = revocationHandle = null;
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed != 0, this);
}

/// <summary>Owns one independently generated Ed25519/X25519 device key pair.</summary>
public sealed class OwnedGenesisDeviceSecrets : IDisposable
{
    private readonly object sync = new();
    private readonly byte[] signingSeed;
    private readonly byte[] agreementPrivateScalar;
    private int disposed;

    public OwnedGenesisDeviceSecrets()
        : this(SystemIdentityAuthoringRandom.Instance)
    {
    }

    internal OwnedGenesisDeviceSecrets(IIdentityAuthoringRandom random)
    {
        ArgumentNullException.ThrowIfNull(random);
        byte[]? localSigning = null;
        byte[]? localAgreement = null;
        byte[]? signingPublic = null;
        byte[]? agreementPublic = null;
        byte[]? deviceId = null;
        byte[]? revocationHandle = null;
        try
        {
            localSigning = RandomNonzero(random, 32);
            localAgreement = RandomNonzero(random, 32);
            signingPublic = DeepIdentityCrypto.DeriveEd25519PublicKey(localSigning);
            agreementPublic = DeepIdentityCrypto.DeriveX25519PublicKey(localAgreement);
            if (CryptographicOperations.FixedTimeEquals(signingPublic, agreementPublic))
                throw new CryptographicException("Device Ed25519 and X25519 public keys collided.");

            var typedSigningPublic = DeviceEd25519PublicKey32.FromVerifiedBytes(signingPublic);
            var typedAgreementPublic = DeviceX25519PublicKey32.FromVerifiedBytes(agreementPublic);
            deviceId = RandomNonzero(random, 32);
            revocationHandle = RandomNonzero(random, 32);
            var typedDeviceId = DeviceId32.FromPersistedBytes(deviceId);
            var typedRevocationHandle = DeviceRevocationHandle32.FromPersistedBytes(revocationHandle);

            signingSeed = localSigning;
            localSigning = null;
            agreementPrivateScalar = localAgreement;
            localAgreement = null;
            SigningPublicKey = typedSigningPublic;
            AgreementPublicKey = typedAgreementPublic;
            DeviceId = typedDeviceId;
            RevocationHandle = typedRevocationHandle;
        }
        finally
        {
            Zero(localSigning);
            Zero(localAgreement);
            Zero(signingPublic);
            Zero(agreementPublic);
            Zero(deviceId);
            Zero(revocationHandle);
        }
    }

    internal OwnedGenesisDeviceSecrets(
        ReadOnlySpan<byte> signingSeed32,
        ReadOnlySpan<byte> agreementPrivateScalar32,
        ReadOnlySpan<byte> deviceId32,
        ReadOnlySpan<byte> revocationHandle32)
    {
        byte[]? localSigning = null;
        byte[]? localAgreement = null;
        byte[]? signingPublic = null;
        byte[]? agreementPublic = null;
        try
        {
            localSigning = RequireSecret(signingSeed32, nameof(signingSeed32));
            localAgreement = RequireSecret(
                agreementPrivateScalar32, nameof(agreementPrivateScalar32));
            signingPublic = DeepIdentityCrypto.DeriveEd25519PublicKey(localSigning);
            agreementPublic = DeepIdentityCrypto.DeriveX25519PublicKey(localAgreement);
            if (CryptographicOperations.FixedTimeEquals(signingPublic, agreementPublic))
                throw new CryptographicException("Device Ed25519 and X25519 public keys collided.");
            var typedSigningPublic = DeviceEd25519PublicKey32.FromVerifiedBytes(signingPublic);
            var typedAgreementPublic = DeviceX25519PublicKey32.FromVerifiedBytes(agreementPublic);
            var typedDeviceId = DeviceId32.FromPersistedBytes(deviceId32);
            var typedRevocationHandle = DeviceRevocationHandle32.FromPersistedBytes(revocationHandle32);

            signingSeed = localSigning;
            localSigning = null;
            agreementPrivateScalar = localAgreement;
            localAgreement = null;
            SigningPublicKey = typedSigningPublic;
            AgreementPublicKey = typedAgreementPublic;
            DeviceId = typedDeviceId;
            RevocationHandle = typedRevocationHandle;
        }
        finally
        {
            Zero(localSigning);
            Zero(localAgreement);
            Zero(signingPublic);
            Zero(agreementPublic);
        }
    }

    public DeviceId32 DeviceId { get; }
    public DeviceEd25519PublicKey32 SigningPublicKey { get; }
    public DeviceX25519PublicKey32 AgreementPublicKey { get; }
    public DeviceRevocationHandle32 RevocationHandle { get; }

    public LocalDeviceIdentityIntent CreateLocalIntent(
        DeepAccountIdentityCapability accountIdentity)
    {
        ArgumentNullException.ThrowIfNull(accountIdentity);
        lock (sync)
        {
            ThrowIfDisposed();
            return new LocalDeviceIdentityIntent(
                accountIdentity, DeviceId, 1, SigningPublicKey,
                AgreementPublicKey, RevocationHandle);
        }
    }

    /// <summary>
    /// Creates a separately owned copy for protected persistence. Neither this
    /// payload nor a restored local intent carries DPD1/DXR1 authority.
    /// </summary>
    public OwnedPersistedDeviceIdentitySecrets ExportOwnedPersistenceCopy()
    {
        lock (sync)
        {
            ThrowIfDisposed();
            byte[]? signing = null;
            byte[]? agreement = null;
            byte[]? id = null;
            byte[]? revocation = null;
            try
            {
                signing = signingSeed.ToArray();
                agreement = agreementPrivateScalar.ToArray();
                id = DeviceId.Bytes.ToArray();
                revocation = RevocationHandle.Bytes.ToArray();
                var result = OwnedPersistedDeviceIdentitySecrets.TakeOwnership(
                    signing, agreement, id, revocation);
                signing = agreement = id = revocation = null;
                return result;
            }
            finally
            {
                Zero(signing);
                Zero(agreement);
                Zero(id);
                Zero(revocation);
            }
        }
    }

    /// <summary>
    /// Consumes a persisted owned payload and restores protocol-owned local
    /// device secrets. The consumed payload is zeroed even if restoration fails.
    /// </summary>
    public static OwnedGenesisDeviceSecrets RestoreFromPersistedOwnedSecrets(
        OwnedPersistedDeviceIdentitySecrets persistedOwnedSecrets)
    {
        ArgumentNullException.ThrowIfNull(persistedOwnedSecrets);
        var values = persistedOwnedSecrets.CopyAndDispose();
        try
        {
            return new OwnedGenesisDeviceSecrets(
                values.SigningSeed,
                values.AgreementPrivateScalar,
                values.DeviceId,
                values.RevocationHandle);
        }
        finally
        {
            Zero(values.SigningSeed);
            Zero(values.AgreementPrivateScalar);
            Zero(values.DeviceId);
            Zero(values.RevocationHandle);
        }
    }

    /// <summary>
    /// Opens the production DPK2 authoring boundary for this exact verified
    /// device. Private signing/agreement material stays protocol-owned; every
    /// authoring operation must additionally present a current unforked DMD1.
    /// </summary>
    public Dpk2AuthoringAuthority CreateDpk2AuthoringAuthority(
        VerifiedDeviceRelative verifiedDevice)
    {
        ArgumentNullException.ThrowIfNull(verifiedDevice);
        lock (sync)
        {
            ThrowIfDisposed();
            return CreateDpk2AuthoringAuthority(
                verifiedDevice,
                SystemIdentityAuthoringRandom.Instance,
                new ApprovedDpk2MlKemKeyGenerator());
        }
    }

    internal Dpk2AuthoringAuthority CreateDpk2AuthoringAuthority(
        VerifiedDeviceRelative verifiedDevice,
        IIdentityAuthoringRandom random,
        IDpk2MlKemKeyGenerator mlKem)
    {
        ArgumentNullException.ThrowIfNull(verifiedDevice);
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(mlKem);
        lock (sync)
        {
            ThrowIfDisposed();
            LocalDeviceX25519AgreementAuthority? agreement = null;
            try
            {
                if (!SigningPublicKey.Matches(verifiedDevice.Certificate.DeviceEd25519PublicKey.Span) ||
                    !DeepIdentityCrypto.Ed25519PublicKeyMatchesSeed(
                        signingSeed,
                        verifiedDevice.Certificate.DeviceEd25519PublicKey.Span))
                {
                    throw new RecordException(
                        RecordError.InvalidTransition,
                        "Local device signing secrets do not match the exact verified DPD1 capability.");
                }

                agreement = CreateAgreementAuthority(verifiedDevice);
                var authority = new Dpk2AuthoringAuthority(agreement, signingSeed, random, mlKem);
                agreement = null;
                return authority;
            }
            catch
            {
                agreement?.Dispose();
                mlKem.Dispose();
                throw;
            }
        }
    }

    internal byte[] SignGenesisDeviceCertificate(
        Dnp1IdentityAuthoringV1.GenesisDeviceCertificateSigningIntent intent)
    {
        ArgumentNullException.ThrowIfNull(intent);
        lock (sync)
        {
            ThrowIfDisposed();
            if (!ReferenceEquals(intent.Device, this))
                throw new RecordException(
                    RecordError.InvalidField,
                    "DPD1 signing intent belongs to another device authority.");

            byte[]? signingBytes = null;
            byte[]? signature = null;
            try
            {
                signingBytes = CanonicalGrammar.GetSigningBytes(
                    intent.Record,
                    "Deep/IdentityAuth/V1/device-certificate");
                signature = new byte[OwnedSodiumEd25519.SignatureSize];
                Span<byte> temporaryPublic = stackalloc byte[OwnedSodiumEd25519.PublicKeySize];
                Span<byte> temporarySecret = stackalloc byte[OwnedSodiumEd25519.SecretKeySize];
                OwnedSodiumEd25519.SignDetached(
                    signingSeed, signingBytes, signature,
                    temporaryPublic, temporarySecret);
                var result = signature;
                signature = null;
                return result;
            }
            finally
            {
                Zero(signingBytes);
                Zero(signature);
            }
        }
    }

    internal (byte[] Proof, byte[] TranscriptHash) CreatePossessionProof(
        ReadOnlySpan<byte> transcript)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            return X25519PossessionVerifier.CreateProof(transcript, agreementPrivateScalar);
        }
    }

    internal LocalDeviceX25519AgreementAuthority CreateAgreementAuthority(
        VerifiedDeviceRelative verifiedDevice)
    {
        ArgumentNullException.ThrowIfNull(verifiedDevice);
        lock (sync)
        {
            ThrowIfDisposed();
            return LocalDeviceX25519AgreementAuthority.Create(
                verifiedDevice,
                DeviceId,
                AgreementPublicKey,
                agreementPrivateScalar);
        }
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            CryptographicOperations.ZeroMemory(signingSeed);
            CryptographicOperations.ZeroMemory(agreementPrivateScalar);
        }
    }

    private static byte[] RandomNonzero(IIdentityAuthoringRandom random, int length)
    {
        var value = new byte[length];
        do random.Fill(value); while (DeepIdentityCrypto.IsAllZero(value));
        return value;
    }

    private static byte[] RequireSecret(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || DeepIdentityCrypto.IsAllZero(value))
            throw new ArgumentException("Device secret must be a nonzero 32-byte value.", name);
        return value.ToArray();
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed != 0, this);
}

public sealed class GenesisAccountAuthoringResult
{
    private readonly byte[] dpa;
    private readonly byte[] drs;

    internal GenesisAccountAuthoringResult(
        VerifiedIdentityRelative identity,
        DeepAccountIdentityCapability accountIdentity,
        ReadOnlySpan<byte> canonicalDpa1,
        ReadOnlySpan<byte> canonicalDrs1)
    {
        Identity = identity;
        AccountIdentity = accountIdentity;
        dpa = canonicalDpa1.ToArray();
        drs = canonicalDrs1.ToArray();
    }

    internal VerifiedIdentityRelative Identity { get; }
    public DeepAccountIdentityCapability AccountIdentity { get; }
    public ReadOnlyMemory<byte> CanonicalDpa1 => dpa.ToArray();
    public ReadOnlyMemory<byte> CanonicalDrs1 => drs.ToArray();
    public bool NoAuthorityClaim => true;
}

public enum GenesisDeviceIssuanceStatus : byte
{
    PendingCurrentDrs = 1,
    Issued = 2
}

public sealed class PendingGenesisDeviceIntent
{
    internal PendingGenesisDeviceIntent(
        DeepAccountIdentityCapability account,
        OwnedGenesisDeviceSecrets device)
    {
        LocalIntent = device.CreateLocalIntent(account);
    }

    public LocalDeviceIdentityIntent LocalIntent { get; }
    public DeepAccountIdentityCapability AccountIdentity => LocalIntent.AccountIdentity;
    public DeviceId32 DeviceId => LocalIntent.DeviceId;
    public ulong DeviceGeneration => LocalIntent.DeviceGeneration;
    public DeviceEd25519PublicKey32 SigningPublicKey => LocalIntent.SigningPublicKey;
    public DeviceX25519PublicKey32 AgreementPublicKey => LocalIntent.AgreementPublicKey;
    public DeviceRevocationHandle32 RevocationHandle => LocalIntent.RevocationHandle;
    public bool RequiresCurrentDrs => true;
    public bool NoAuthorityClaim => true;
}

public sealed class DurableDxpVerifiedReceipt
{
    private readonly byte[] canonical;

    internal DurableDxpVerifiedReceipt(ReadOnlySpan<byte> canonicalDxr1, ulong sourceRevision)
    {
        canonical = canonicalDxr1.ToArray();
        SourceRevision = sourceRevision;
    }

    public ReadOnlyMemory<byte> CanonicalDxr1 => canonical.ToArray();
    public ulong SourceRevision { get; }
    public bool NoAuthorityClaim => true;
}

public sealed class DurableDeviceSubjectCasReceipt
{
    private readonly byte[] subjectKey;
    private readonly byte[] expectedPredecessor;
    private readonly byte[] subjectHead;

    internal DurableDeviceSubjectCasReceipt(
        ReadOnlySpan<byte> deviceSubjectKey88,
        ReadOnlySpan<byte> expectedPredecessor38,
        ReadOnlySpan<byte> subjectHead38,
        ulong subjectRevision)
    {
        if (deviceSubjectKey88.Length != 88 || expectedPredecessor38.Length != 38 ||
            subjectHead38.Length != 38 ||
            CanonicalGrammar.IsZero(deviceSubjectKey88) ||
            CanonicalGrammar.IsZero(subjectHead38) || subjectRevision == 0)
            Invalid("The durable device-subject CAS receipt is malformed.");
        subjectKey = deviceSubjectKey88.ToArray();
        expectedPredecessor = expectedPredecessor38.ToArray();
        subjectHead = subjectHead38.ToArray();
        SubjectRevision = subjectRevision;
    }

    public ReadOnlyMemory<byte> DeviceSubjectKey => subjectKey.ToArray();
    public bool ExpectedSubjectAbsent => CanonicalGrammar.IsZero(expectedPredecessor);
    public ReadOnlyMemory<byte> ExpectedPredecessor => expectedPredecessor.ToArray();
    public ReadOnlyMemory<byte> SubjectHead => subjectHead.ToArray();
    public ulong SubjectRevision { get; }
    public bool NoAuthorityClaim => true;

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidTransition, message);
}

public sealed class IssuedGenesisDevice
{
    private readonly byte[] dpd;
    private readonly byte[] transcriptHash;

    internal IssuedGenesisDevice(
        VerifiedDeviceRelative verified,
        ReadOnlySpan<byte> canonicalDpd1,
        ReadOnlySpan<byte> x25519PopTranscriptHash32,
        DurableDxpVerifiedReceipt durableReceipt,
        DurableDeviceSubjectCasReceipt subjectCasReceipt)
    {
        Verified = verified;
        dpd = canonicalDpd1.ToArray();
        transcriptHash = x25519PopTranscriptHash32.ToArray();
        DurableReceipt = durableReceipt;
        SubjectCasReceipt = subjectCasReceipt;
    }

    /// <summary>
    /// The verifier-minted device fact released only after the DPD1/DXP1/DXR1
    /// durable subject CAS has reached its exact verified result.
    /// </summary>
    public VerifiedDeviceRelative Verified { get; }
    public ReadOnlyMemory<byte> CanonicalDpd1 => dpd.ToArray();
    public ReadOnlyMemory<byte> X25519PopTranscriptHash => transcriptHash.ToArray();
    public DurableDxpVerifiedReceipt DurableReceipt { get; }
    public DurableDeviceSubjectCasReceipt SubjectCasReceipt { get; }
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisDeviceIssuanceResult
{
    private GenesisDeviceIssuanceResult(
        GenesisDeviceIssuanceStatus status,
        PendingGenesisDeviceIntent? pending,
        IssuedGenesisDevice? issued)
    {
        Status = status;
        PendingIntent = pending;
        IssuedDevice = issued;
    }

    public GenesisDeviceIssuanceStatus Status { get; }
    public PendingGenesisDeviceIntent? PendingIntent { get; }
    public IssuedGenesisDevice? IssuedDevice { get; }
    public bool NoAuthorityClaim => true;

    internal static GenesisDeviceIssuanceResult Pending(PendingGenesisDeviceIntent pending) =>
        new(GenesisDeviceIssuanceStatus.PendingCurrentDrs, pending, null);

    internal static GenesisDeviceIssuanceResult Issued(IssuedGenesisDevice issued) =>
        new(GenesisDeviceIssuanceStatus.Issued, null, issued);
}

public sealed class DxpPersistenceProfileRequest
{
    private readonly DxpIdentityIssuanceSource source;
    internal DxpPersistenceProfileRequest(DxpIdentityIssuanceSource source) => this.source = source;
    internal DxpIdentityIssuanceSource Source => source;
    public ReadOnlyMemory<byte> IdentityIssuanceSource => source.IdentityIssuanceSource;
    public ReadOnlyMemory<byte> IssuanceScope => source.IssuanceScope;
    public bool NoAuthorityClaim => true;
}

public sealed class UntrustedDxpPersistenceProfileReadResult
{
    private readonly byte[] catalogKeyId;
    private readonly byte[] dxrKeyId;
    private readonly byte[] nonceIndexKeyId;

    public UntrustedDxpPersistenceProfileReadResult(
        ReadOnlySpan<byte> identityCatalogKeyId32,
        ReadOnlySpan<byte> dxrKeyId32,
        ReadOnlySpan<byte> nonceIndexKeyId32,
        ulong sourceRevision)
    {
        if (identityCatalogKeyId32.Length != 32 || dxrKeyId32.Length != 32 ||
            nonceIndexKeyId32.Length != 32)
            throw new ArgumentException(
                "Every DXP persistence profile key ID must have exact length 32.");
        catalogKeyId = identityCatalogKeyId32.ToArray();
        dxrKeyId = dxrKeyId32.ToArray();
        nonceIndexKeyId = nonceIndexKeyId32.ToArray();
        SourceRevision = sourceRevision;
    }

    public ReadOnlyMemory<byte> IdentityCatalogKeyId => catalogKeyId.ToArray();
    public ReadOnlyMemory<byte> DxrKeyId => dxrKeyId.ToArray();
    public ReadOnlyMemory<byte> NonceIndexKeyId => nonceIndexKeyId.ToArray();
    public ulong SourceRevision { get; }
}

public sealed class DxpNonceLedgerRequest
{
    private readonly DxpIdentityIssuanceSource source;
    private readonly byte[] nonce;

    internal DxpNonceLedgerRequest(DxpIdentityIssuanceSource source, ReadOnlySpan<byte> nonce32)
    {
        this.source = source;
        nonce = nonce32.ToArray();
    }

    internal DxpIdentityIssuanceSource Source => source;
    public byte SourceKind => (byte)source.Kind;
    public byte Role => (byte)source.Role;
    public ReadOnlyMemory<byte> Network => source.Network.ToArray();
    public ReadOnlyMemory<byte> IssuanceScope => source.IssuanceScope;
    public ReadOnlyMemory<byte> Nonce => nonce.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class UntrustedDxpNonceLedgerReadResult
{
    private readonly byte[] ledgerKey;
    private readonly byte[] indexKeyId;

    public UntrustedDxpNonceLedgerReadResult(
        ReadOnlySpan<byte> nonceLedgerKey32,
        ReadOnlySpan<byte> nonceIndexKeyId32)
    {
        if (nonceLedgerKey32.Length != 32 || nonceIndexKeyId32.Length != 32)
            throw new ArgumentException(
                "Every DXP nonce-ledger callback value must have exact length 32.");
        ledgerKey = nonceLedgerKey32.ToArray();
        indexKeyId = nonceIndexKeyId32.ToArray();
    }

    public ReadOnlyMemory<byte> NonceLedgerKey => ledgerKey.ToArray();
    public ReadOnlyMemory<byte> NonceIndexKeyId => indexKeyId.ToArray();
}

public sealed class DxpProtectedTagRequest
{
    private readonly byte[] keyId;
    private readonly byte[] unsignedCanonical;
    private readonly string domain;

    internal DxpProtectedTagRequest(
        ReadOnlySpan<byte> protectedStateKeyId32,
        ReadOnlySpan<byte> unsignedCanonicalDxr1,
        string? protectedDomain = null)
    {
        if (protectedStateKeyId32.Length != 32 ||
            CanonicalGrammar.IsZero(protectedStateKeyId32) ||
            unsignedCanonicalDxr1.IsEmpty || unsignedCanonicalDxr1.Length > 4096)
            throw new RecordException(RecordError.InvalidLength,
                "The protected DXP tag request is malformed.");
        keyId = protectedStateKeyId32.ToArray();
        unsignedCanonical = unsignedCanonicalDxr1.ToArray();
        domain = protectedDomain ?? DxpReceiptVerifier.ProtectedDomain;
    }

    public string Domain => domain;
    public ushort Suite => ArtifactRegistry.ProtectedHmacSha256;
    public ReadOnlyMemory<byte> ProtectedStateKeyId => keyId.ToArray();
    public ReadOnlyMemory<byte> UnsignedCanonicalDxr1 => unsignedCanonical.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class DxpPersistenceScopeRequest
{
    private readonly byte[] operationId;
    private readonly byte[] sourceFingerprint;

    internal DxpPersistenceScopeRequest(
        ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> sourceFingerprint32)
    {
        operationId = operationId32.ToArray();
        sourceFingerprint = sourceFingerprint32.ToArray();
    }

    public ReadOnlyMemory<byte> OperationId => operationId.ToArray();
    public ReadOnlyMemory<byte> SourceFingerprint => sourceFingerprint.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class DxpDeviceSubjectRequest
{
    private readonly DxpIdentityIssuanceSource source;
    private readonly byte[] subjectKey;

    internal DxpDeviceSubjectRequest(
        DxpIdentityIssuanceSource source,
        ReadOnlySpan<byte> deviceSubjectKey88)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (deviceSubjectKey88.Length != 88 || CanonicalGrammar.IsZero(deviceSubjectKey88))
            throw new RecordException(RecordError.InvalidField,
                "The device-subject replay key is malformed.");
        this.source = source;
        subjectKey = deviceSubjectKey88.ToArray();
    }

    internal DxpIdentityIssuanceSource Source => source;
    public ReadOnlyMemory<byte> IdentityIssuanceSource => source.IdentityIssuanceSource;
    public ReadOnlyMemory<byte> IssuanceScope => source.IssuanceScope;
    public ReadOnlyMemory<byte> DeviceSubjectKey => subjectKey.ToArray();
    public bool NoAuthorityClaim => true;
}

/// <summary>
/// Exact protected operation material required to reconcile one sealed device
/// subject after a crash. Its persisted profile snapshot is HMAC-bound and cannot
/// be replaced by the adapter's current profile.
/// </summary>
public sealed class DxpReplayMaterial
{
    private readonly byte[] pendingDxr;
    private readonly byte[] verifiedDxr;
    private readonly byte[] canonicalDpd;
    private readonly byte[] exactDxp;
    private readonly byte[] subjectKey;
    private readonly byte[] expectedPredecessor;
    private readonly byte[] newSubjectHead;
    private readonly byte[] identityCatalogKeyId;
    private readonly byte[] dxrKeyId;
    private readonly byte[] nonceIndexKeyId;
    private readonly byte[] protectedTag;

    public DxpReplayMaterial(
        ReadOnlySpan<byte> canonicalPendingDxr1,
        ReadOnlySpan<byte> canonicalVerifiedDxr1,
        ReadOnlySpan<byte> canonicalDpd1,
        ReadOnlySpan<byte> exactDxp1,
        ReadOnlySpan<byte> deviceSubjectKey88,
        ReadOnlySpan<byte> expectedSubjectPredecessor38,
        ReadOnlySpan<byte> newSubjectHead38,
        ReadOnlySpan<byte> identityCatalogKeyId32,
        ReadOnlySpan<byte> dxrKeyId32,
        ReadOnlySpan<byte> nonceIndexKeyId32,
        ulong profileSourceRevision,
        ReadOnlySpan<byte> protectedTag32)
    {
        if (canonicalPendingDxr1.Length != 573 || canonicalVerifiedDxr1.Length != 573 ||
            canonicalDpd1.Length != 776 || exactDxp1.Length != 168 ||
            deviceSubjectKey88.Length != 88 || expectedSubjectPredecessor38.Length != 38 ||
            newSubjectHead38.Length != 38 || identityCatalogKeyId32.Length != 32 ||
            dxrKeyId32.Length != 32 || nonceIndexKeyId32.Length != 32 ||
            profileSourceRevision == 0 || protectedTag32.Length != 32)
            throw new ArgumentException("The DXP replay material has a hostile or nonexact size.");
        if (CanonicalGrammar.IsZero(deviceSubjectKey88) ||
            CanonicalGrammar.IsZero(newSubjectHead38) ||
            CanonicalGrammar.IsZero(identityCatalogKeyId32) ||
            CanonicalGrammar.IsZero(dxrKeyId32) ||
            CanonicalGrammar.IsZero(nonceIndexKeyId32) ||
            CanonicalGrammar.IsZero(protectedTag32) ||
            CanonicalGrammar.FixedEquals(identityCatalogKeyId32, dxrKeyId32) ||
            CanonicalGrammar.FixedEquals(identityCatalogKeyId32, nonceIndexKeyId32) ||
            CanonicalGrammar.FixedEquals(dxrKeyId32, nonceIndexKeyId32))
            throw new ArgumentException("The DXP replay material has invalid protected-state roles.");
        pendingDxr = canonicalPendingDxr1.ToArray();
        verifiedDxr = canonicalVerifiedDxr1.ToArray();
        canonicalDpd = canonicalDpd1.ToArray();
        exactDxp = exactDxp1.ToArray();
        subjectKey = deviceSubjectKey88.ToArray();
        expectedPredecessor = expectedSubjectPredecessor38.ToArray();
        newSubjectHead = newSubjectHead38.ToArray();
        identityCatalogKeyId = identityCatalogKeyId32.ToArray();
        dxrKeyId = dxrKeyId32.ToArray();
        nonceIndexKeyId = nonceIndexKeyId32.ToArray();
        ProfileSourceRevision = profileSourceRevision;
        protectedTag = protectedTag32.ToArray();
    }

    public ReadOnlyMemory<byte> CanonicalPendingDxr1 => pendingDxr.ToArray();
    public ReadOnlyMemory<byte> CanonicalVerifiedDxr1 => verifiedDxr.ToArray();
    public ReadOnlyMemory<byte> CanonicalDpd1 => canonicalDpd.ToArray();
    public ReadOnlyMemory<byte> ExactDxp1 => exactDxp.ToArray();
    public ReadOnlyMemory<byte> DeviceSubjectKey => subjectKey.ToArray();
    public ReadOnlyMemory<byte> ExpectedSubjectPredecessor => expectedPredecessor.ToArray();
    public ReadOnlyMemory<byte> NewSubjectHead => newSubjectHead.ToArray();
    public ReadOnlyMemory<byte> IdentityCatalogKeyId => identityCatalogKeyId.ToArray();
    public ReadOnlyMemory<byte> DxrKeyId => dxrKeyId.ToArray();
    public ReadOnlyMemory<byte> NonceIndexKeyId => nonceIndexKeyId.ToArray();
    public ulong ProfileSourceRevision { get; }
    public ReadOnlyMemory<byte> ProtectedTag => protectedTag.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class DxpPendingWriteRequest
{
    internal DxpPendingWriteRequest(DxpReplayMaterial material, DxpPersistenceScopeRequest scope)
    {
        Material = material ?? throw new ArgumentNullException(nameof(material));
        Scope = scope;
    }
    public ReadOnlyMemory<byte> CanonicalDxr1 => Material.CanonicalPendingDxr1;
    public DxpReplayMaterial Material { get; }
    public DxpPersistenceScopeRequest Scope { get; }
    public bool NoAuthorityClaim => true;
}

public sealed class DxpVerifiedCasRequest
{
    internal DxpVerifiedCasRequest(
        DxpReplayMaterial material,
        ulong expectedSourceRevision,
        DxpPersistenceScopeRequest scope)
    {
        Material = material ?? throw new ArgumentNullException(nameof(material));
        ExpectedSourceRevision = expectedSourceRevision;
        Scope = scope;
    }
    public ReadOnlyMemory<byte> CurrentDxr1 => Material.CanonicalPendingDxr1;
    public ReadOnlyMemory<byte> NextDxr1 => Material.CanonicalVerifiedDxr1;
    public ReadOnlyMemory<byte> ExpectedSubjectPredecessor => Material.ExpectedSubjectPredecessor;
    public bool ExpectedDeviceSubjectAbsent =>
        CanonicalGrammar.IsZero(Material.ExpectedSubjectPredecessor.Span);
    public ReadOnlyMemory<byte> CanonicalDpd1 => Material.CanonicalDpd1;
    public ReadOnlyMemory<byte> DeviceSubjectKey => Material.DeviceSubjectKey;
    public ReadOnlyMemory<byte> NewSubjectHead => Material.NewSubjectHead;
    public DxpReplayMaterial Material { get; }
    public ulong ExpectedSourceRevision { get; }
    public DxpPersistenceScopeRequest Scope { get; }
    public bool NoAuthorityClaim => true;
}

public sealed class DxpAbortedCasRequest
{
    private readonly byte[] current;
    private readonly byte[] aborted;
    private readonly byte[] subjectKey;

    internal DxpAbortedCasRequest(
        ReadOnlySpan<byte> currentPendingDxr1,
        ReadOnlySpan<byte> abortedDxr1,
        ReadOnlySpan<byte> deviceSubjectKey88,
        ulong expectedSourceRevision,
        DxpPersistenceScopeRequest scope)
    {
        if (deviceSubjectKey88.Length != 88 || CanonicalGrammar.IsZero(deviceSubjectKey88))
            throw new ArgumentException("The aborted CAS device-subject key is malformed.",
                nameof(deviceSubjectKey88));
        current = currentPendingDxr1.ToArray();
        aborted = abortedDxr1.ToArray();
        subjectKey = deviceSubjectKey88.ToArray();
        ExpectedSourceRevision = expectedSourceRevision;
        Scope = scope;
    }

    public ReadOnlyMemory<byte> CurrentDxr1 => current.ToArray();
    public ReadOnlyMemory<byte> AbortedDxr1 => aborted.ToArray();
    public ReadOnlyMemory<byte> DeviceSubjectKey => subjectKey.ToArray();
    public ulong ExpectedSourceRevision { get; }
    public DxpPersistenceScopeRequest Scope { get; }
    public bool NoAuthorityClaim => true;
}

public sealed class UntrustedDxpReplayReadResult
{
    private readonly byte[] current;

    public UntrustedDxpReplayReadResult(
        ReadOnlySpan<byte> currentCanonicalDxr1,
        ulong dxrSourceRevision,
        DxpReplayMaterial? material,
        ulong subjectRevision)
    {
        if (currentCanonicalDxr1.Length != 573)
            throw new ArgumentException("The current DXR1 must have exact length 573.", nameof(currentCanonicalDxr1));
        current = currentCanonicalDxr1.ToArray();
        DxrSourceRevision = dxrSourceRevision;
        Material = material;
        SubjectRevision = subjectRevision;
    }

    public ReadOnlyMemory<byte> CurrentCanonicalDxr1 => current.ToArray();
    public ulong DxrSourceRevision { get; }
    public DxpReplayMaterial? Material { get; }
    public ulong SubjectRevision { get; }
}

/// <summary>
/// Consumer adapter for protected DXP persistence. Reserve atomically installs one
/// exact replay material tuple and unique nonce selector for a sealed issuance scope.
/// Verified CAS atomically compares Pending DXR1 plus expected subject absence or
/// predecessor, installs canonical DPD1 and its new subject head, and advances DXR1.
/// Returning means all exact bytes are durably fsynced; Protocol rereads and
/// cryptographically verifies the complete winner before minting sealed evidence.
/// Protected-tag lookup must retain replay-material key IDs through retained-until;
/// rotating the current profile must not make a Verified operation unreadable.
/// </summary>
public abstract class Dnp1IdentityIssuancePersistence
{
    protected abstract ValueTask<UntrustedDxpPersistenceProfileReadResult> ReadProfileCoreAsync(
        DxpPersistenceProfileRequest request, CancellationToken cancellationToken);
    protected abstract ValueTask<UntrustedDxpNonceLedgerReadResult> DeriveNonceLedgerCoreAsync(
        DxpNonceLedgerRequest request, CancellationToken cancellationToken);
    protected abstract ValueTask<ReadOnlyMemory<byte>> ComputeDxrTagCoreAsync(
        DxpProtectedTagRequest request, CancellationToken cancellationToken);
    protected abstract ValueTask<UntrustedDxpReplayReadResult?> ReadByDeviceSubjectCoreAsync(
        DxpDeviceSubjectRequest request, CancellationToken cancellationToken);
    protected abstract ValueTask<UntrustedDxpReplayReadResult> ReservePendingCoreAsync(
        DxpPendingWriteRequest request, CancellationToken cancellationToken);
    protected abstract ValueTask<UntrustedDxpReplayReadResult> CompareExchangeVerifiedCoreAsync(
        DxpVerifiedCasRequest request, CancellationToken cancellationToken);
    protected abstract ValueTask<UntrustedDxpReplayReadResult> CompareExchangeAbortedCoreAsync(
        DxpAbortedCasRequest request, CancellationToken cancellationToken);

    internal ValueTask<UntrustedDxpPersistenceProfileReadResult> ReadProfileAsync(
        DxpPersistenceProfileRequest request, CancellationToken cancellationToken) =>
        ReadProfileCoreAsync(request, cancellationToken);
    internal ValueTask<UntrustedDxpNonceLedgerReadResult> DeriveNonceLedgerAsync(
        DxpNonceLedgerRequest request, CancellationToken cancellationToken) =>
        DeriveNonceLedgerCoreAsync(request, cancellationToken);
    internal ValueTask<ReadOnlyMemory<byte>> ComputeDxrTagAsync(
        DxpProtectedTagRequest request, CancellationToken cancellationToken) =>
        ComputeDxrTagCoreAsync(request, cancellationToken);
    internal ValueTask<UntrustedDxpReplayReadResult?> ReadByDeviceSubjectAsync(
        DxpDeviceSubjectRequest request, CancellationToken cancellationToken) =>
        ReadByDeviceSubjectCoreAsync(request, cancellationToken);
    internal ValueTask<UntrustedDxpReplayReadResult> ReservePendingAsync(
        DxpPendingWriteRequest request, CancellationToken cancellationToken) =>
        ReservePendingCoreAsync(request, cancellationToken);
    internal ValueTask<UntrustedDxpReplayReadResult> CompareExchangeVerifiedAsync(
        DxpVerifiedCasRequest request, CancellationToken cancellationToken) =>
        CompareExchangeVerifiedCoreAsync(request, cancellationToken);
    internal ValueTask<UntrustedDxpReplayReadResult> CompareExchangeAbortedAsync(
        DxpAbortedCasRequest request, CancellationToken cancellationToken) =>
        CompareExchangeAbortedCoreAsync(request, cancellationToken);

    internal IProtectedHmacProvider HmacVerifier => new PersistenceHmacProvider(this);

    private sealed class PersistenceHmacProvider(Dnp1IdentityIssuancePersistence owner)
        : IProtectedHmacProvider
    {
        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request,
            CancellationToken cancellationToken) =>
            owner.ComputeDxrTagAsync(new DxpProtectedTagRequest(
                request.ProtectedStateKeyId.Span, request.UnsignedCanonical.Span), cancellationToken);
    }
}

internal interface IIdentityAuthoringRandom
{
    void Fill(Span<byte> destination);
}

internal sealed class SystemIdentityAuthoringRandom : IIdentityAuthoringRandom
{
    internal static readonly SystemIdentityAuthoringRandom Instance = new();
    private SystemIdentityAuthoringRandom() { }
    public void Fill(Span<byte> destination) => RandomNumberGenerator.Fill(destination);
}

/// <summary>Typed offline author for the frozen DNP1 classical identity generation.</summary>
public static class Dnp1IdentityAuthoringV1
{
    private const string AccountDomain = "Deep/IdentityAuth/V1/account-certificate";
    private const string RevocationDomain = "Deep/IdentityAuth/V1/revocation-snapshot";
    private const string DeviceDomain = "Deep/IdentityAuth/V1/device-certificate";

    internal sealed class GenesisAccountCertificateSigningIntent
    {
        private GenesisAccountCertificateSigningIntent(
            DeepRecoveryAccountCapabilities authority,
            OwnedRecord record)
        {
            Authority = authority;
            Record = record;
        }

        internal DeepRecoveryAccountCapabilities Authority { get; }
        internal OwnedRecord Record { get; }

        internal static GenesisAccountCertificateSigningIntent Create(
            DeepRecoveryAccountCapabilities authority,
            OwnedRecord record,
            ReadOnlySpan<byte> revocationHandle,
            ulong createdAtUnixSeconds,
            ulong policyGeneration)
        {
            ValidateGenesisAccountCertificateIntent(
                authority, record, revocationHandle, createdAtUnixSeconds, policyGeneration);
            return new GenesisAccountCertificateSigningIntent(authority, record);
        }
    }

    internal sealed class GenesisRevocationSnapshotSigningIntent
    {
        private GenesisRevocationSnapshotSigningIntent(
            DeepRecoveryAccountCapabilities authority,
            OwnedRecord record)
        {
            Authority = authority;
            Record = record;
        }

        internal DeepRecoveryAccountCapabilities Authority { get; }
        internal OwnedRecord Record { get; }

        internal static GenesisRevocationSnapshotSigningIntent Create(
            DeepRecoveryAccountCapabilities authority,
            OwnedRecord record,
            VerifiedAccount account,
            ulong issuedAtUnixSeconds)
        {
            ValidateGenesisRevocationSnapshotIntent(
                authority, record, account, issuedAtUnixSeconds);
            return new GenesisRevocationSnapshotSigningIntent(authority, record);
        }
    }

    internal sealed class GenesisDeviceCertificateSigningIntent
    {
        private GenesisDeviceCertificateSigningIntent(
            DeepRecoveryAccountCapabilities authority,
            OwnedGenesisDeviceSecrets device,
            OwnedRecord record)
        {
            Authority = authority;
            Device = device;
            Record = record;
        }

        internal DeepRecoveryAccountCapabilities Authority { get; }
        internal OwnedGenesisDeviceSecrets Device { get; }
        internal OwnedRecord Record { get; }

        internal static GenesisDeviceCertificateSigningIntent Create(
            DeepRecoveryAccountCapabilities authority,
            OwnedGenesisDeviceSecrets device,
            OwnedRecord record,
            VerifiedIdentityRelative identity,
            ReadOnlySpan<byte> transcriptHash,
            ulong issuedAtUnixSeconds,
            ulong expiresAtUnixSeconds)
        {
            ValidateGenesisDeviceCertificateIntent(
                authority, device, record, identity, transcriptHash,
                issuedAtUnixSeconds, expiresAtUnixSeconds);
            return new GenesisDeviceCertificateSigningIntent(authority, device, record);
        }
    }

    public static GenesisAccountAuthoringResult AuthorGenesisAccount(
        DeepRecoveryAccountCapabilities accountSecrets,
        ulong createdAtUnixSeconds,
        ulong policyGeneration = 1) =>
        AuthorGenesisAccount(accountSecrets, createdAtUnixSeconds, policyGeneration,
            SystemIdentityAuthoringRandom.Instance);

    public static async ValueTask<GenesisDeviceIssuanceResult> IssueGenesisDeviceAsync(
        DeepRecoveryAccountCapabilities accountSecrets,
        GenesisAccountAuthoringResult? currentAccount,
        OwnedGenesisDeviceSecrets deviceSecrets,
        Dnp1IdentityIssuancePersistence? persistence,
        ulong issuedAtUnixSeconds,
        ulong deviceExpiresAtUnixSeconds,
        ulong retainedUntilUnixSeconds,
        CancellationToken cancellationToken = default) =>
        await IssueGenesisDeviceAsync(
            accountSecrets, currentAccount, deviceSecrets, persistence,
            issuedAtUnixSeconds, deviceExpiresAtUnixSeconds, retainedUntilUnixSeconds,
            SystemIdentityAuthoringRandom.Instance, cancellationToken).ConfigureAwait(false);

    internal static GenesisAccountAuthoringResult AuthorGenesisAccount(
        DeepRecoveryAccountCapabilities accountSecrets,
        ulong createdAtUnixSeconds,
        ulong policyGeneration,
        IIdentityAuthoringRandom random)
    {
        ArgumentNullException.ThrowIfNull(accountSecrets);
        ArgumentNullException.ThrowIfNull(random);
        if (accountSecrets.AccountGeneration != 1 || createdAtUnixSeconds == 0 || policyGeneration == 0)
            throw new ArgumentException("Genesis DPA1 requires generation one and nonzero time/policy.");

        byte[]? accountPublic = null;
        byte[]? issuerPublic = null;
        byte[]? revocationPublic = null;
        byte[]? resetPublic = null;
        byte[]? revocationHandle = null;
        var signatures = new byte[4][];
        try
        {
            accountPublic = accountSecrets.AccountSigningPublicKey.ToArray();
            issuerPublic = accountSecrets.DeviceIssuerSigningPublicKey.ToArray();
            revocationPublic = accountSecrets.AccountRevocationSigningPublicKey.ToArray();
            resetPublic = accountSecrets.ResetControlSigningPublicKey.ToArray();
            revocationHandle = RandomNonzero(random, 32);
            var fields = Minimum(RecordDefinitions.Dpa1);
            fields[0] = accountSecrets.NetworkId;
            fields[1] = U64(1); fields[2] = U64(1); fields[3] = new byte[38];
            fields[4] = accountPublic; fields[5] = issuerPublic;
            fields[6] = revocationPublic; fields[7] = resetPublic;
            fields[8] = revocationHandle; fields[9] = U64(createdAtUnixSeconds);
            fields[10] = U64(policyGeneration);
            fields[11] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
            var carrier = CanonicalGrammar.Encode(RecordDefinitions.Dpa1, fields);
            var record = CanonicalGrammar.DecodeOwned(carrier, RecordDefinitions.Dpa1);
            var accountSigningIntent = GenesisAccountCertificateSigningIntent.Create(
                accountSecrets,
                record,
                revocationHandle,
                createdAtUnixSeconds,
                policyGeneration);
            var accountSignatures = accountSecrets.SignGenesisAccountCertificate(
                accountSigningIntent);
            signatures[0] = accountSignatures.Account;
            signatures[1] = accountSignatures.DeviceIssuer;
            signatures[2] = accountSignatures.Revocation;
            signatures[3] = accountSignatures.Reset;
            for (var index = 0; index < 4; index++) fields[12 + index] = signatures[index];
            var dpa = CanonicalGrammar.Encode(RecordDefinitions.Dpa1, fields);
            if (dpa.Length != 644) Invalid("The authored DPA1 length is not exact644.");
            var verifiedAccount = IdentityVerifier.VerifyAccountCertificate(dpa);

            var drsFields = Minimum(RecordDefinitions.Drs1);
            drsFields[0] = verifiedAccount.Certificate.NetworkId;
            drsFields[1] = verifiedAccount.DeepAccountIdHash;
            drsFields[2] = U64(1); drsFields[3] = U64(1);
            drsFields[4] = U64(createdAtUnixSeconds);
            drsFields[5] = U64(0); drsFields[6] = new byte[38];
            drsFields[7] = IdentityAuthorityVerifier.ComputeKeyHash(
                verifiedAccount.Certificate.NetworkId.Span,
                KeyScope.AccountRevocation,
                verifiedAccount.DeepAccountIdHash.Span,
                1,
                revocationPublic);
            drsFields[8] = U16(0); drsFields[9] = Array.Empty<byte>();
            drsFields[10] = new byte[32];
            var drsCarrier = CanonicalGrammar.Encode(RecordDefinitions.Drs1, drsFields);
            var drsRecord = CanonicalGrammar.DecodeOwned(drsCarrier, RecordDefinitions.Drs1);
            var revocationSigningIntent = GenesisRevocationSnapshotSigningIntent.Create(
                accountSecrets,
                drsRecord,
                verifiedAccount,
                createdAtUnixSeconds);
            drsFields[11] = accountSecrets.SignGenesisRevocationSnapshot(
                revocationSigningIntent);
            var drs = CanonicalGrammar.Encode(RecordDefinitions.Drs1, drsFields);
            if (drs.Length != 356) Invalid("The authored initial DRS1 length is not exact356.");
            var identity = new IdentityRelativeVerifier().VerifyGenesis(
                dpa, drs, [], createdAtUnixSeconds);
            return new GenesisAccountAuthoringResult(
                identity, accountSecrets.AccountIdentity, dpa, drs);
        }
        finally
        {
            Zero(accountPublic); Zero(issuerPublic); Zero(revocationPublic); Zero(resetPublic);
            Zero(revocationHandle);
            foreach (var signature in signatures) Zero(signature);
        }
    }

    internal static async ValueTask<GenesisDeviceIssuanceResult> IssueGenesisDeviceAsync(
        DeepRecoveryAccountCapabilities accountSecrets,
        GenesisAccountAuthoringResult? currentAccount,
        OwnedGenesisDeviceSecrets deviceSecrets,
        Dnp1IdentityIssuancePersistence? persistence,
        ulong issuedAtUnixSeconds,
        ulong deviceExpiresAtUnixSeconds,
        ulong retainedUntilUnixSeconds,
        IIdentityAuthoringRandom random,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accountSecrets);
        ArgumentNullException.ThrowIfNull(deviceSecrets);
        ArgumentNullException.ThrowIfNull(random);
        cancellationToken.ThrowIfCancellationRequested();
        if (accountSecrets.AccountGeneration != 1)
            throw new ArgumentException("Genesis device issuance requires account generation one.");
        if (currentAccount is null)
            return GenesisDeviceIssuanceResult.Pending(
                new PendingGenesisDeviceIntent(accountSecrets.AccountIdentity, deviceSecrets));
        ArgumentNullException.ThrowIfNull(persistence);
        if (!currentAccount.AccountIdentity.Equals(accountSecrets.AccountIdentity))
            Invalid("Account authoring evidence and account secret roles are cross-sourced.");
        if (issuedAtUnixSeconds == 0 || deviceExpiresAtUnixSeconds <= issuedAtUnixSeconds ||
            retainedUntilUnixSeconds < deviceExpiresAtUnixSeconds)
            throw new ArgumentException("The device issuance/expiry/retention window is invalid.");
        var dxpExpiresAt = checked(issuedAtUnixSeconds + 300);

        byte[]? operationId = null;
        byte[]? issuerPrivate = null;
        byte[]? issuerPublic = null;
        byte[]? nonce = null;
        byte[]? projection = null;
        byte[]? projectionHash = null;
        byte[]? transcript = null;
        byte[]? proof = null;
        byte[]? transcriptHash = null;
        byte[]? deviceSignature = null;
        byte[]? issuerSignature = null;
        try
        {
            var identity = currentAccount.Identity;
            var account = identity.Account;
            var drs = identity.Revocations.Snapshot;
            var source = new DxpIdentityIssuanceSourceVerifier()
                .CreateOfflineAccountDeviceGenesis(identity);
            var deviceSubjectKey = CreateDeviceSubjectKey(
                account.Certificate.NetworkId.Span,
                account.DeepAccountIdHash.Span,
                deviceSecrets.DeviceId.Bytes.Span,
                1);
            var replayRequest = new DxpDeviceSubjectRequest(source, deviceSubjectKey);
            var existing = await persistence.ReadByDeviceSubjectAsync(
                replayRequest, cancellationToken).ConfigureAwait(false);
            if (existing is not null)
                return await ReconcileAsync(
                    persistence, identity, source, replayRequest,
                    existing, deviceSecrets, cancellationToken)
                    .ConfigureAwait(false);

            // A durable subject winner is reconciled entirely from its authenticated,
            // retained profile snapshot above. Only a genuinely new operation may
            // depend on the adapter's current profile.
            var profile = await persistence.ReadProfileAsync(
                new DxpPersistenceProfileRequest(source), cancellationToken).ConfigureAwait(false);
            ValidateProfile(profile);

            var dpdFields = Minimum(RecordDefinitions.Dpd1);
            dpdFields[0] = account.Certificate.NetworkId;
            dpdFields[1] = account.DeepAccountIdHash;
            dpdFields[2] = U64(1); dpdFields[3] = deviceSecrets.DeviceId.Bytes;
            dpdFields[4] = U64(1); dpdFields[5] = deviceSecrets.SigningPublicKey.Bytes;
            dpdFields[6] = deviceSecrets.AgreementPublicKey.Bytes;
            dpdFields[7] = deviceSecrets.RevocationHandle.Bytes;
            dpdFields[8] = U64(0); dpdFields[9] = new byte[38];
            dpdFields[10] = IdentityAuthorityVerifier.ComputeKeyHash(
                account.Certificate.NetworkId.Span,
                KeyScope.DeviceCertificateIssuer,
                account.DeepAccountIdHash.Span,
                1,
                account.Certificate.DeviceIssuerEd25519PublicKey.Span);
            dpdFields[11] = U64(drs.Revision);
            dpdFields[12] = Reference(ArtifactType.Drs1, drs.CanonicalBytes.Span);
            dpdFields[13] = U64(drs.EntryCount); dpdFields[14] = drs.CurrentHead;
            dpdFields[15] = U64(issuedAtUnixSeconds);
            dpdFields[16] = U64(deviceExpiresAtUnixSeconds);
            dpdFields[17] = U64((ulong)DeviceCapabilities.MailboxRoleIssuer);
            dpdFields[18] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
            dpdFields[19] = new byte[38]; dpdFields[20] = new byte[32];
            var preRecord = CanonicalGrammar.DecodeOwned(
                CanonicalGrammar.Encode(RecordDefinitions.Dpd1, dpdFields),
                RecordDefinitions.Dpd1);
            projection = DxpSubjectProjection.EncodeDevice(preRecord);
            if (projection.Length != 632) Invalid("The DPD1 preprojection is not exact632.");
            projectionHash = DxpSubjectProjection.HashDevice(preRecord);

            operationId = RandomNonzero(random, 32);
            issuerPrivate = RandomNonzero(random, 32);
            issuerPublic = DeepIdentityCrypto.DeriveX25519PublicKey(issuerPrivate);
            nonce = RandomNonzero(random, 32);
            transcript = CreateDxp(
                account.Certificate.NetworkId.Span,
                projectionHash,
                deviceSecrets.AgreementPublicKey.Bytes.Span,
                issuerPublic,
                nonce,
                issuedAtUnixSeconds,
                dxpExpiresAt);
            var ledger = await persistence.DeriveNonceLedgerAsync(
                new DxpNonceLedgerRequest(source, nonce), cancellationToken).ConfigureAwait(false);
            ValidateLedger(ledger, profile);

            (proof, transcriptHash) = deviceSecrets.CreatePossessionProof(transcript);
            var verifiedPossession = X25519PossessionVerifier.Verify(
                transcript,
                proof,
                issuerPrivate,
                X25519PossessionRole.Device,
                account.Certificate.NetworkId.Span,
                projectionHash,
                deviceSecrets.AgreementPublicKey.Bytes.Span,
                issuedAtUnixSeconds);
            if (!CanonicalGrammar.FixedEquals(
                    verifiedPossession.TranscriptHash.Span, transcriptHash))
                Invalid("The locally verified DXP1 transcript hash changed before issuance.");
            Zero(issuerPrivate); issuerPrivate = null;
            Zero(proof); proof = null;
            dpdFields[20] = transcriptHash;
            var signingRecord = CanonicalGrammar.DecodeOwned(
                CanonicalGrammar.Encode(RecordDefinitions.Dpd1, dpdFields),
                RecordDefinitions.Dpd1);
            var deviceSigningIntent = GenesisDeviceCertificateSigningIntent.Create(
                accountSecrets,
                deviceSecrets,
                signingRecord,
                identity,
                transcriptHash,
                issuedAtUnixSeconds,
                deviceExpiresAtUnixSeconds);
            deviceSignature = deviceSecrets.SignGenesisDeviceCertificate(deviceSigningIntent);
            issuerSignature = accountSecrets.SignGenesisDeviceCertificateAsIssuer(
                deviceSigningIntent);
            dpdFields[21] = deviceSignature; dpdFields[22] = issuerSignature;
            var dpd = CanonicalGrammar.Encode(RecordDefinitions.Dpd1, dpdFields);
            if (dpd.Length != 776) Invalid("The authored DPD1 length is not exact776.");
            var dpdRecord = CanonicalGrammar.DecodeOwned(dpd, RecordDefinitions.Dpd1);
            if (!CanonicalGrammar.FixedEquals(
                    DxpSubjectProjection.HashDevice(dpdRecord), projectionHash))
                Invalid("The final DPD1 changed its exact preprojection.");
            var subjectRef = Reference(ArtifactType.Dpd1, dpd);
            var pendingSource = new DxpOperationSource(
                source, 0, projectionHash, new byte[38], new byte[32], new byte[38],
                profile.IdentityCatalogKeyId.Span, profile.DxrKeyId.Span,
                profile.NonceIndexKeyId.Span);
            var verifiedSource = new DxpOperationSource(
                source, 1, projectionHash, new byte[38], transcriptHash, subjectRef,
                profile.IdentityCatalogKeyId.Span, profile.DxrKeyId.Span,
                profile.NonceIndexKeyId.Span);
            var pendingCanonical = await CreateDxrAsync(
                persistence, DxpReceiptPhase.Pending, operationId, projectionHash,
                transcript, ledger.NonceLedgerKey, new byte[32], new byte[38],
                pendingSource, profile.DxrKeyId, 0, retainedUntilUnixSeconds,
                cancellationToken).ConfigureAwait(false);
            var verifiedCanonical = await CreateDxrAsync(
                persistence, DxpReceiptPhase.Verified, operationId, projectionHash,
                transcript, ledger.NonceLedgerKey, transcriptHash, subjectRef,
                verifiedSource, profile.DxrKeyId, issuedAtUnixSeconds,
                retainedUntilUnixSeconds, cancellationToken).ConfigureAwait(false);
            var replayTag = await ComputeReplayMaterialTagAsync(
                persistence, profile.DxrKeyId, pendingCanonical, verifiedCanonical,
                dpd, transcript, deviceSubjectKey, new byte[38], subjectRef,
                profile.IdentityCatalogKeyId, profile.NonceIndexKeyId,
                profile.SourceRevision,
                cancellationToken).ConfigureAwait(false);
            var material = new DxpReplayMaterial(
                pendingCanonical, verifiedCanonical, dpd, transcript,
                deviceSubjectKey, new byte[38], subjectRef,
                profile.IdentityCatalogKeyId.Span, profile.DxrKeyId.Span,
                profile.NonceIndexKeyId.Span, profile.SourceRevision, replayTag);
            var scope = new DxpPersistenceScopeRequest(operationId, pendingSource.Fingerprint.Span);
            var reserved = await persistence.ReservePendingAsync(
                new DxpPendingWriteRequest(material, scope), cancellationToken)
                .ConfigureAwait(false);
            return await ReconcileAsync(
                persistence, identity, source, replayRequest,
                reserved, deviceSecrets, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            Zero(operationId); Zero(issuerPrivate); Zero(issuerPublic); Zero(nonce);
            Zero(projection); Zero(projectionHash); Zero(transcript); Zero(proof);
            Zero(transcriptHash); Zero(deviceSignature); Zero(issuerSignature);
        }
    }

    private const string ReplayMaterialDomain =
        "Deep/ProtectedState/V2/DXP1-replay-material";

    private static async ValueTask<GenesisDeviceIssuanceResult> ReconcileAsync(
        Dnp1IdentityIssuancePersistence persistence,
        VerifiedIdentityRelative identity,
        DxpIdentityIssuanceSource source,
        DxpDeviceSubjectRequest replayRequest,
        UntrustedDxpReplayReadResult replay,
        OwnedGenesisDeviceSecrets deviceSecrets,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(replay);
        if (replay.Material is null)
        {
            if (CurrentPhase(replay.CurrentCanonicalDxr1.Span) == DxpReceiptPhase.Aborted)
                Invalid("The durable DXP operation is Aborted and cannot be regenerated.");
            Invalid("A non-Aborted durable DXP operation lost its exact replay material.");
        }
        var material = replay.Material!;
        var pendingCanonical = material.CanonicalPendingDxr1.ToArray();
        var verifiedCanonical = material.CanonicalVerifiedDxr1.ToArray();
        var dpd = material.CanonicalDpd1.ToArray();
        var dxp = material.ExactDxp1.ToArray();
        var subjectKey = material.DeviceSubjectKey.ToArray();
        var predecessor = material.ExpectedSubjectPredecessor.ToArray();
        var subjectHead = material.NewSubjectHead.ToArray();
        try
        {
            var operationProfile = new UntrustedDxpPersistenceProfileReadResult(
                material.IdentityCatalogKeyId.Span,
                material.DxrKeyId.Span,
                material.NonceIndexKeyId.Span,
                material.ProfileSourceRevision);
            ValidateProfile(operationProfile);
            if (!CanonicalGrammar.FixedEquals(subjectKey, replayRequest.DeviceSubjectKey.Span) ||
                !CanonicalGrammar.IsZero(predecessor))
                Invalid("The replay material belongs to a different device subject or predecessor.");
            await VerifyReplayMaterialTagAsync(
                persistence, operationProfile.DxrKeyId, material, cancellationToken).ConfigureAwait(false);

            var dpdRecord = CanonicalGrammar.DecodeOwned(dpd, RecordDefinitions.Dpd1);
            var expectedSubjectKey = CreateDeviceSubjectKey(
                dpdRecord.FieldSpan(1), dpdRecord.FieldSpan(2),
                dpdRecord.FieldSpan(4), BinaryPrimitives.ReadUInt64BigEndian(dpdRecord.FieldSpan(5)));
            if (!CanonicalGrammar.FixedEquals(subjectKey, expectedSubjectKey) ||
                !CanonicalGrammar.FixedEquals(dpdRecord.FieldSpan(1), source.Network) ||
                !CanonicalGrammar.FixedEquals(dpdRecord.FieldSpan(2), source.AccountHash) ||
                !CanonicalGrammar.FixedEquals(dpdRecord.FieldSpan(4), deviceSecrets.DeviceId.Bytes.Span) ||
                !CanonicalGrammar.FixedEquals(dpdRecord.FieldSpan(6), deviceSecrets.SigningPublicKey.Bytes.Span) ||
                !CanonicalGrammar.FixedEquals(dpdRecord.FieldSpan(7), deviceSecrets.AgreementPublicKey.Bytes.Span) ||
                !CanonicalGrammar.FixedEquals(dpdRecord.FieldSpan(8), deviceSecrets.RevocationHandle.Bytes.Span))
                Invalid("The durable replay material changed the sealed local device intent.");
            var expectedHead = Reference(ArtifactType.Dpd1, dpd);
            if (!CanonicalGrammar.FixedEquals(subjectHead, expectedHead))
                Invalid("The durable replay material has the wrong DPD1 subject head.");

            var projectionHash = DxpSubjectProjection.HashDevice(dpdRecord);
            var pendingRecord = CanonicalGrammar.DecodeOwned(pendingCanonical, RecordDefinitions.Dxr1);
            var verifiedRecord = CanonicalGrammar.DecodeOwned(verifiedCanonical, RecordDefinitions.Dxr1);
            var expectedDxp = CreateDxp(
                pendingRecord.FieldSpan(3), projectionHash, pendingRecord.FieldSpan(6),
                pendingRecord.FieldSpan(7), pendingRecord.FieldSpan(8),
                BinaryPrimitives.ReadUInt64BigEndian(pendingRecord.FieldSpan(10)),
                BinaryPrimitives.ReadUInt64BigEndian(pendingRecord.FieldSpan(11)));
            if (!CanonicalGrammar.FixedEquals(dxp, expectedDxp) ||
                !CanonicalGrammar.FixedEquals(projectionHash, pendingRecord.FieldSpan(5)) ||
                !CanonicalGrammar.FixedEquals(projectionHash, verifiedRecord.FieldSpan(5)) ||
                !CanonicalGrammar.FixedEquals(dpdRecord.FieldSpan(21), verifiedRecord.FieldSpan(13)) ||
                !CanonicalGrammar.FixedEquals(subjectHead, verifiedRecord.FieldSpan(14)) ||
                BinaryPrimitives.ReadUInt64BigEndian(dpdRecord.FieldSpan(16)) !=
                    BinaryPrimitives.ReadUInt64BigEndian(verifiedRecord.FieldSpan(12)))
                Invalid("The DPD1, DXP1 and DXR1 replay tuple is not exact.");
            var persistedVerificationTime =
                BinaryPrimitives.ReadUInt64BigEndian(verifiedRecord.FieldSpan(12));

            var pendingSource = new DxpOperationSource(
                source, 0, projectionHash, predecessor, new byte[32], new byte[38],
                operationProfile.IdentityCatalogKeyId.Span, operationProfile.DxrKeyId.Span,
                operationProfile.NonceIndexKeyId.Span);
            var verifiedSource = new DxpOperationSource(
                source, 1, projectionHash, predecessor, dpdRecord.FieldSpan(21), subjectHead,
                operationProfile.IdentityCatalogKeyId.Span, operationProfile.DxrKeyId.Span,
                operationProfile.NonceIndexKeyId.Span);
            var verifier = new DxpReceiptVerifier();
            var pendingReceipt = await verifier.RestoreAsync(
                pendingCanonical, pendingSource, persistence.HmacVerifier, cancellationToken)
                .ConfigureAwait(false);
            var verifiedReceipt = await verifier.RestoreAsync(
                verifiedCanonical, verifiedSource, persistence.HmacVerifier, cancellationToken)
                .ConfigureAwait(false);
            verifier.VerifyFinalCas(pendingReceipt, verifiedReceipt, pendingSource, verifiedSource);
            _ = new IdentityRelativeVerifier().RestoreDevice(
                identity, dpd, verifiedReceipt, persistedVerificationTime);

            var scope = new DxpPersistenceScopeRequest(
                pendingRecord.FieldSpan(4), pendingSource.Fingerprint.Span);
            var phase = CurrentPhase(replay.CurrentCanonicalDxr1.Span);
            if (phase == DxpReceiptPhase.Aborted)
                Invalid("The durable DXP operation is Aborted and cannot be regenerated.");
            if (phase == DxpReceiptPhase.Pending)
            {
                if (replay.DxrSourceRevision == 0 || replay.SubjectRevision != 0 ||
                    !CanonicalGrammar.FixedEquals(
                        replay.CurrentCanonicalDxr1.Span, pendingCanonical))
                    Invalid("The durable Pending replay state is malformed.");
                var currentProfile = await persistence.ReadProfileAsync(
                    new DxpPersistenceProfileRequest(source), cancellationToken).ConfigureAwait(false);
                try
                {
                    ValidateSameProfile(operationProfile, currentProfile);
                    replay = await persistence.CompareExchangeVerifiedAsync(
                        new DxpVerifiedCasRequest(material, replay.DxrSourceRevision, scope),
                        cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch
                {
                    var raced = await persistence.ReadByDeviceSubjectAsync(
                        replayRequest, CancellationToken.None).ConfigureAwait(false);
                    if (raced is not null &&
                        CurrentPhase(raced.CurrentCanonicalDxr1.Span) == DxpReceiptPhase.Verified)
                    {
                        replay = raced;
                    }
                    else
                    {
                        await TryAbortPendingAsync(
                            persistence, replay, pendingRecord, pendingSource, scope,
                            cancellationToken: CancellationToken.None).ConfigureAwait(false);
                        throw;
                    }
                }
            }

            ValidateExactReplay(replay, material, verifiedCanonical);
            var final = await persistence.ReadByDeviceSubjectAsync(
                replayRequest, cancellationToken).ConfigureAwait(false);
            if (final is null)
                throw new RecordException(RecordError.InvalidTransition,
                    "The durable device subject disappeared after its atomic CAS.");
            ValidateExactReplay(final, material, verifiedCanonical);
            var finalReceipt = await verifier.RestoreAsync(
                final.CurrentCanonicalDxr1, verifiedSource,
                persistence.HmacVerifier, cancellationToken).ConfigureAwait(false);
            var verifiedDevice = new IdentityRelativeVerifier().RestoreDevice(
                identity, dpd, finalReceipt, persistedVerificationTime);
            var durable = new DurableDxpVerifiedReceipt(
                final.CurrentCanonicalDxr1.Span, final.DxrSourceRevision);
            var subjectReceipt = new DurableDeviceSubjectCasReceipt(
                subjectKey, predecessor, subjectHead, final.SubjectRevision);
            return GenesisDeviceIssuanceResult.Issued(new IssuedGenesisDevice(
                verifiedDevice, dpd, dpdRecord.FieldSpan(21), durable, subjectReceipt));
        }
        finally
        {
            Zero(pendingCanonical); Zero(verifiedCanonical); Zero(dpd); Zero(dxp);
            Zero(subjectKey); Zero(predecessor); Zero(subjectHead);
        }
    }

    private static void ValidateExactReplay(
        UntrustedDxpReplayReadResult replay,
        DxpReplayMaterial expectedMaterial,
        ReadOnlySpan<byte> expectedVerifiedDxr1)
    {
        if (replay.DxrSourceRevision == 0 || replay.SubjectRevision == 0 ||
            CurrentPhase(replay.CurrentCanonicalDxr1.Span) != DxpReceiptPhase.Verified ||
            !CanonicalGrammar.FixedEquals(
                replay.CurrentCanonicalDxr1.Span, expectedVerifiedDxr1) ||
            replay.Material is null || !SameMaterial(replay.Material, expectedMaterial))
            Invalid("The atomic DPD1/DXR1 subject CAS did not exact-replay its winner.");
    }

    private static bool SameMaterial(DxpReplayMaterial left, DxpReplayMaterial right) =>
        CanonicalGrammar.FixedEquals(left.CanonicalPendingDxr1.Span, right.CanonicalPendingDxr1.Span) &&
        CanonicalGrammar.FixedEquals(left.CanonicalVerifiedDxr1.Span, right.CanonicalVerifiedDxr1.Span) &&
        CanonicalGrammar.FixedEquals(left.CanonicalDpd1.Span, right.CanonicalDpd1.Span) &&
        CanonicalGrammar.FixedEquals(left.ExactDxp1.Span, right.ExactDxp1.Span) &&
        CanonicalGrammar.FixedEquals(left.DeviceSubjectKey.Span, right.DeviceSubjectKey.Span) &&
        CanonicalGrammar.FixedEquals(left.ExpectedSubjectPredecessor.Span, right.ExpectedSubjectPredecessor.Span) &&
        CanonicalGrammar.FixedEquals(left.NewSubjectHead.Span, right.NewSubjectHead.Span) &&
        CanonicalGrammar.FixedEquals(left.IdentityCatalogKeyId.Span, right.IdentityCatalogKeyId.Span) &&
        CanonicalGrammar.FixedEquals(left.DxrKeyId.Span, right.DxrKeyId.Span) &&
        CanonicalGrammar.FixedEquals(left.NonceIndexKeyId.Span, right.NonceIndexKeyId.Span) &&
        left.ProfileSourceRevision == right.ProfileSourceRevision &&
        CanonicalGrammar.FixedEquals(left.ProtectedTag.Span, right.ProtectedTag.Span);

    private static DxpReceiptPhase CurrentPhase(ReadOnlySpan<byte> canonical)
    {
        CanonicalGrammar.Preflight(canonical, RecordDefinitions.Dxr1);
        var phase = CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dxr1).FieldSpan(1)[0];
        if (phase > (byte)DxpReceiptPhase.Aborted)
            Invalid("The durable DXR1 phase is unknown.");
        return (DxpReceiptPhase)phase;
    }

    private static async ValueTask TryAbortPendingAsync(
        Dnp1IdentityIssuancePersistence persistence,
        UntrustedDxpReplayReadResult replay,
        OwnedRecord pendingRecord,
        DxpOperationSource pendingSource,
        DxpPersistenceScopeRequest scope,
        CancellationToken cancellationToken)
    {
        try
        {
            var aborted = await CreateDxrAsync(
                persistence, DxpReceiptPhase.Aborted,
                pendingRecord.FieldSpan(4).ToArray(), pendingRecord.FieldSpan(5).ToArray(),
                CreateDxp(
                    pendingRecord.FieldSpan(3), pendingRecord.FieldSpan(5),
                    pendingRecord.FieldSpan(6), pendingRecord.FieldSpan(7),
                    pendingRecord.FieldSpan(8),
                    BinaryPrimitives.ReadUInt64BigEndian(pendingRecord.FieldSpan(10)),
                    BinaryPrimitives.ReadUInt64BigEndian(pendingRecord.FieldSpan(11))),
                pendingRecord.FieldSpan(9).ToArray(), new byte[32], new byte[38],
                pendingSource, pendingRecord.FieldSpan(16).ToArray(), 0,
                BinaryPrimitives.ReadUInt64BigEndian(pendingRecord.FieldSpan(18)),
                cancellationToken).ConfigureAwait(false);
            var result = await persistence.CompareExchangeAbortedAsync(
                new DxpAbortedCasRequest(
                    replay.CurrentCanonicalDxr1.Span, aborted,
                    replay.Material!.DeviceSubjectKey.Span,
                    replay.DxrSourceRevision, scope), cancellationToken).ConfigureAwait(false);
            if (result.Material is not null || result.SubjectRevision != 0 ||
                CurrentPhase(result.CurrentCanonicalDxr1.Span) != DxpReceiptPhase.Aborted)
                Invalid("The aborted CAS did not durably tombstone its device subject.");
            await new DxpReceiptVerifier().RestoreAsync(
                result.CurrentCanonicalDxr1, pendingSource,
                persistence.HmacVerifier, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // The original failure remains authoritative. A surviving authenticated
            // Pending row is reconciled by the next exact scope lookup.
        }
    }

    private static async ValueTask VerifyReplayMaterialTagAsync(
        Dnp1IdentityIssuancePersistence persistence,
        ReadOnlyMemory<byte> dxrKeyId32,
        DxpReplayMaterial material,
        CancellationToken cancellationToken)
    {
        var expected = await ComputeReplayMaterialTagAsync(
            persistence, dxrKeyId32,
            material.CanonicalPendingDxr1, material.CanonicalVerifiedDxr1,
            material.CanonicalDpd1, material.ExactDxp1,
            material.DeviceSubjectKey, material.ExpectedSubjectPredecessor,
            material.NewSubjectHead, material.IdentityCatalogKeyId,
            material.NonceIndexKeyId, material.ProfileSourceRevision,
            cancellationToken).ConfigureAwait(false);
        try
        {
            if (!CanonicalGrammar.FixedEquals(expected, material.ProtectedTag.Span))
                throw new RecordException(RecordError.InvalidSignature,
                    "The DXP replay-material protected tag is invalid.");
        }
        finally
        {
            Zero(expected);
        }
    }

    private static async ValueTask<byte[]> ComputeReplayMaterialTagAsync(
        Dnp1IdentityIssuancePersistence persistence,
        ReadOnlyMemory<byte> dxrKeyId32,
        ReadOnlyMemory<byte> pendingDxr1,
        ReadOnlyMemory<byte> verifiedDxr1,
        ReadOnlyMemory<byte> canonicalDpd1,
        ReadOnlyMemory<byte> exactDxp1,
        ReadOnlyMemory<byte> subjectKey88,
        ReadOnlyMemory<byte> predecessor38,
        ReadOnlyMemory<byte> subjectHead38,
        ReadOnlyMemory<byte> identityCatalogKeyId32,
        ReadOnlyMemory<byte> nonceIndexKeyId32,
        ulong profileSourceRevision,
        CancellationToken cancellationToken)
    {
        var transcript = new byte[
            4 + 573 + 4 + 573 + 4 + 776 + 4 + 168 + 88 + 38 + 38 +
            32 + 32 + 32 + 8];
        var offset = 0;
        PutLengthPrefixed(pendingDxr1.Span); PutLengthPrefixed(verifiedDxr1.Span);
        PutLengthPrefixed(canonicalDpd1.Span); PutLengthPrefixed(exactDxp1.Span);
        Put(subjectKey88.Span); Put(predecessor38.Span); Put(subjectHead38.Span);
        Put(identityCatalogKeyId32.Span); Put(dxrKeyId32.Span);
        Put(nonceIndexKeyId32.Span);
        Span<byte> revision = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(revision, profileSourceRevision);
        Put(revision);
        if (offset != transcript.Length)
            Invalid("The DXP replay-material transcript length is invalid.");
        byte[]? returned = null;
        try
        {
            returned = (await persistence.ComputeDxrTagAsync(
                new DxpProtectedTagRequest(dxrKeyId32.Span, transcript, ReplayMaterialDomain),
                cancellationToken).ConfigureAwait(false)).ToArray();
            if (returned.Length != 32 || CanonicalGrammar.IsZero(returned))
                Invalid("The DXP replay-material protected tag callback is invalid.");
            var result = returned;
            returned = null;
            return result;
        }
        finally
        {
            Zero(transcript);
            Zero(returned);
        }

        void PutLengthPrefixed(ReadOnlySpan<byte> value)
        {
            BinaryPrimitives.WriteUInt32BigEndian(transcript.AsSpan(offset, 4), checked((uint)value.Length));
            offset += 4;
            Put(value);
        }
        void Put(ReadOnlySpan<byte> value)
        {
            value.CopyTo(transcript.AsSpan(offset));
            offset += value.Length;
        }
    }

    private static byte[] CreateDeviceSubjectKey(
        ReadOnlySpan<byte> network16,
        ReadOnlySpan<byte> accountHash32,
        ReadOnlySpan<byte> deviceId32,
        ulong deviceGeneration)
    {
        if (network16.Length != 16 || accountHash32.Length != 32 ||
            deviceId32.Length != 32 || deviceGeneration == 0)
            Invalid("The device-subject key input is malformed.");
        var key = new byte[88];
        network16.CopyTo(key); accountHash32.CopyTo(key.AsSpan(16));
        deviceId32.CopyTo(key.AsSpan(48));
        BinaryPrimitives.WriteUInt64BigEndian(key.AsSpan(80), deviceGeneration);
        return key;
    }

    private static async ValueTask<byte[]> CreateDxrAsync(
        Dnp1IdentityIssuancePersistence persistence,
        DxpReceiptPhase phase,
        ReadOnlyMemory<byte> operationId32,
        ReadOnlyMemory<byte> projectionHash32,
        ReadOnlyMemory<byte> transcript168,
        ReadOnlyMemory<byte> ledgerKey32,
        ReadOnlyMemory<byte> transcriptHash32,
        ReadOnlyMemory<byte> subjectRef38,
        DxpOperationSource source,
        ReadOnlyMemory<byte> dxrKeyId32,
        ulong verifiedAt,
        ulong retainedUntil,
        CancellationToken cancellationToken)
    {
        var fields = Minimum(RecordDefinitions.Dxr1);
        fields[0] = new byte[] { (byte)phase };
        fields[1] = new byte[] { (byte)X25519PossessionRole.Device };
        fields[2] = transcript168.Slice(8, 16).ToArray(); fields[3] = operationId32.ToArray();
        fields[4] = projectionHash32.ToArray(); fields[5] = transcript168.Slice(56, 32).ToArray();
        fields[6] = transcript168.Slice(88, 32).ToArray(); fields[7] = transcript168.Slice(120, 32).ToArray();
        fields[8] = ledgerKey32.ToArray(); fields[9] = transcript168.Slice(152, 8).ToArray();
        fields[10] = transcript168.Slice(160, 8).ToArray(); fields[11] = U64(verifiedAt);
        fields[12] = transcriptHash32.ToArray(); fields[13] = subjectRef38.ToArray();
        fields[14] = source.Fingerprint; fields[15] = dxrKeyId32.ToArray();
        fields[16] = new byte[] { 0 };
        fields[17] = U64(retainedUntil); fields[18] = new byte[32];
        var carrier = CanonicalGrammar.Encode(RecordDefinitions.Dxr1, fields);
        var record = CanonicalGrammar.DecodeOwned(carrier, RecordDefinitions.Dxr1);
        var unsigned = DxpReceiptVerifier.Unsigned(record);
        var tag = (await persistence.ComputeDxrTagAsync(
            new DxpProtectedTagRequest(dxrKeyId32.Span, unsigned), cancellationToken)
            .ConfigureAwait(false)).ToArray();
        if (tag.Length != 32 || CanonicalGrammar.IsZero(tag))
            Invalid("The DXR1 protected tag callback returned an invalid tag.");
        fields[18] = tag;
        var canonical = CanonicalGrammar.Encode(RecordDefinitions.Dxr1, fields);
        if (canonical.Length != 573) Invalid("The authored DXR1 length is not exact573.");
        return canonical;
    }

    private static byte[] CreateDxp(
        ReadOnlySpan<byte> network16,
        ReadOnlySpan<byte> projectionHash32,
        ReadOnlySpan<byte> holderPublic32,
        ReadOnlySpan<byte> issuerPublic32,
        ReadOnlySpan<byte> nonce32,
        ulong issuedAt,
        ulong expiresAt)
    {
        var transcript = new byte[X25519PossessionVerifier.TranscriptLength];
        ProtocolMagicBytes.DXP1.CopyTo(transcript);
        transcript[4] = 1; transcript[5] = (byte)X25519PossessionRole.Device;
        network16.CopyTo(transcript.AsSpan(8));
        projectionHash32.CopyTo(transcript.AsSpan(24));
        holderPublic32.CopyTo(transcript.AsSpan(56));
        issuerPublic32.CopyTo(transcript.AsSpan(88));
        nonce32.CopyTo(transcript.AsSpan(120));
        BinaryPrimitives.WriteUInt64BigEndian(transcript.AsSpan(152, 8), issuedAt);
        BinaryPrimitives.WriteUInt64BigEndian(transcript.AsSpan(160, 8), expiresAt);
        return transcript;
    }

    private static void ValidateProfile(UntrustedDxpPersistenceProfileReadResult profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var values = new[]
        {
            profile.IdentityCatalogKeyId.ToArray(),
            profile.DxrKeyId.ToArray(),
            profile.NonceIndexKeyId.ToArray()
        };
        if (profile.SourceRevision == 0 || values.Any(static value =>
                value.Length != 32 || CanonicalGrammar.IsZero(value)))
            Invalid("The DXP persistence profile is malformed.");
        for (var index = 0; index < values.Length; index++)
            for (var other = 0; other < index; other++)
                if (CanonicalGrammar.FixedEquals(values[index], values[other]))
                    Invalid("The DXP persistence key roles are not separated.");
    }

    private static void ValidateGenesisAccountCertificateIntent(
        DeepRecoveryAccountCapabilities authority,
        OwnedRecord record,
        ReadOnlySpan<byte> revocationHandle,
        ulong createdAtUnixSeconds,
        ulong policyGeneration)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(record);
        if (authority.AccountGeneration != 1
            || createdAtUnixSeconds == 0
            || policyGeneration == 0
            || revocationHandle.Length != 32
            || CanonicalGrammar.IsZero(revocationHandle)
            || !ReferenceEquals(record.Definition, RecordDefinitions.Dpa1)
            || record.CanonicalSpan.Length != 644
            || !Same(record.FieldSpan(1), authority.NetworkId.Span)
            || !ExactU64(record.FieldSpan(2), 1)
            || !ExactU64(record.FieldSpan(3), 1)
            || !CanonicalGrammar.IsZero(record.FieldSpan(4))
            || !Same(record.FieldSpan(5), authority.AccountSigningPublicKey.Span)
            || !Same(record.FieldSpan(6), authority.DeviceIssuerSigningPublicKey.Span)
            || !Same(record.FieldSpan(7), authority.AccountRevocationSigningPublicKey.Span)
            || !Same(record.FieldSpan(8), authority.ResetControlSigningPublicKey.Span)
            || !Same(record.FieldSpan(9), revocationHandle)
            || !ExactU64(record.FieldSpan(10), createdAtUnixSeconds)
            || !ExactU64(record.FieldSpan(11), policyGeneration)
            || !ExactU16(record.FieldSpan(12), ArtifactRegistry.IdentityAuthV1Ed25519)
            || !CanonicalGrammar.IsZero(record.FieldSpan(13))
            || !CanonicalGrammar.IsZero(record.FieldSpan(14))
            || !CanonicalGrammar.IsZero(record.FieldSpan(15))
            || !CanonicalGrammar.IsZero(record.FieldSpan(16)))
            Invalid("DPA1 signing intent is not the exact closed genesis account certificate.");
    }

    private static void ValidateGenesisRevocationSnapshotIntent(
        DeepRecoveryAccountCapabilities authority,
        OwnedRecord record,
        VerifiedAccount account,
        ulong issuedAtUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(account);
        byte[]? expectedKeyHash = null;
        try
        {
            expectedKeyHash = IdentityAuthorityVerifier.ComputeKeyHash(
                account.Certificate.NetworkId.Span,
                KeyScope.AccountRevocation,
                account.DeepAccountIdHash.Span,
                1,
                account.Certificate.RevocationEd25519PublicKey.Span);
            if (authority.AccountGeneration != 1
                || issuedAtUnixSeconds == 0
                || !authority.AccountIdentity.AccountId.Matches(account.DeepAccountIdHash.Span)
                || !ReferenceEquals(record.Definition, RecordDefinitions.Drs1)
                || record.CanonicalSpan.Length != 356
                || !Same(record.FieldSpan(1), authority.NetworkId.Span)
                || !Same(record.FieldSpan(2), account.DeepAccountIdHash.Span)
                || !ExactU64(record.FieldSpan(3), 1)
                || !ExactU64(record.FieldSpan(4), 1)
                || !ExactU64(record.FieldSpan(5), issuedAtUnixSeconds)
                || !ExactU64(record.FieldSpan(6), 0)
                || !CanonicalGrammar.IsZero(record.FieldSpan(7))
                || !Same(record.FieldSpan(8), expectedKeyHash)
                || !ExactU16(record.FieldSpan(9), 0)
                || !record.FieldSpan(10).IsEmpty
                || !CanonicalGrammar.IsZero(record.FieldSpan(11))
                || !CanonicalGrammar.IsZero(record.FieldSpan(12)))
                Invalid("DRS1 signing intent is not the exact closed genesis revocation snapshot.");
        }
        finally
        {
            Zero(expectedKeyHash);
        }
    }

    private static void ValidateGenesisDeviceCertificateIntent(
        DeepRecoveryAccountCapabilities authority,
        OwnedGenesisDeviceSecrets device,
        OwnedRecord record,
        VerifiedIdentityRelative identity,
        ReadOnlySpan<byte> transcriptHash,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(identity);
        var account = identity.Account;
        var drs = identity.Revocations.Snapshot;
        byte[]? expectedIssuerKeyHash = null;
        byte[]? expectedDrsReference = null;
        try
        {
            expectedIssuerKeyHash = IdentityAuthorityVerifier.ComputeKeyHash(
                account.Certificate.NetworkId.Span,
                KeyScope.DeviceCertificateIssuer,
                account.DeepAccountIdHash.Span,
                1,
                account.Certificate.DeviceIssuerEd25519PublicKey.Span);
            expectedDrsReference = Reference(ArtifactType.Drs1, drs.CanonicalBytes.Span);
            if (authority.AccountGeneration != 1
                || identity.IsTerminal
                || identity.ForkLatched
                || issuedAtUnixSeconds == 0
                || expiresAtUnixSeconds <= issuedAtUnixSeconds
                || transcriptHash.Length != 32
                || CanonicalGrammar.IsZero(transcriptHash)
                || !authority.AccountIdentity.AccountId.Matches(account.DeepAccountIdHash.Span)
                || !ReferenceEquals(record.Definition, RecordDefinitions.Dpd1)
                || record.CanonicalSpan.Length != 776
                || !Same(record.FieldSpan(1), authority.NetworkId.Span)
                || !Same(record.FieldSpan(2), account.DeepAccountIdHash.Span)
                || !ExactU64(record.FieldSpan(3), 1)
                || !Same(record.FieldSpan(4), device.DeviceId.Bytes.Span)
                || !ExactU64(record.FieldSpan(5), 1)
                || !Same(record.FieldSpan(6), device.SigningPublicKey.Bytes.Span)
                || !Same(record.FieldSpan(7), device.AgreementPublicKey.Bytes.Span)
                || !Same(record.FieldSpan(8), device.RevocationHandle.Bytes.Span)
                || !ExactU64(record.FieldSpan(9), 0)
                || !CanonicalGrammar.IsZero(record.FieldSpan(10))
                || !Same(record.FieldSpan(11), expectedIssuerKeyHash)
                || !ExactU64(record.FieldSpan(12), drs.Revision)
                || !Same(record.FieldSpan(13), expectedDrsReference)
                || !ExactU64(record.FieldSpan(14), drs.EntryCount)
                || !Same(record.FieldSpan(15), drs.CurrentHead.Span)
                || !ExactU64(record.FieldSpan(16), issuedAtUnixSeconds)
                || !ExactU64(record.FieldSpan(17), expiresAtUnixSeconds)
                || !ExactU64(record.FieldSpan(18), (ulong)DeviceCapabilities.MailboxRoleIssuer)
                || !ExactU16(record.FieldSpan(19), ArtifactRegistry.IdentityAuthV1Ed25519)
                || !CanonicalGrammar.IsZero(record.FieldSpan(20))
                || !Same(record.FieldSpan(21), transcriptHash)
                || !CanonicalGrammar.IsZero(record.FieldSpan(22))
                || !CanonicalGrammar.IsZero(record.FieldSpan(23)))
                Invalid("DPD1 signing intent is not the exact closed genesis device certificate.");
        }
        finally
        {
            Zero(expectedIssuerKeyHash);
            Zero(expectedDrsReference);
        }
    }

    private static bool Same(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static bool ExactU64(ReadOnlySpan<byte> value, ulong expected) =>
        value.Length == sizeof(ulong) && BinaryPrimitives.ReadUInt64BigEndian(value) == expected;

    private static bool ExactU16(ReadOnlySpan<byte> value, ushort expected) =>
        value.Length == sizeof(ushort) && BinaryPrimitives.ReadUInt16BigEndian(value) == expected;

    private static void ValidateLedger(
        UntrustedDxpNonceLedgerReadResult ledger,
        UntrustedDxpPersistenceProfileReadResult profile)
    {
        ArgumentNullException.ThrowIfNull(ledger);
        if (ledger.NonceLedgerKey.Length != 32 ||
            CanonicalGrammar.IsZero(ledger.NonceLedgerKey.Span) ||
            !CanonicalGrammar.FixedEquals(
                ledger.NonceIndexKeyId.Span, profile.NonceIndexKeyId.Span))
            Invalid("The nonce ledger result is not bound to the exact persistence profile.");
    }

    private static void ValidateSameProfile(
        UntrustedDxpPersistenceProfileReadResult expected,
        UntrustedDxpPersistenceProfileReadResult actual)
    {
        ValidateProfile(actual);
        if (actual.SourceRevision != expected.SourceRevision ||
            !CanonicalGrammar.FixedEquals(
                actual.IdentityCatalogKeyId.Span, expected.IdentityCatalogKeyId.Span) ||
            !CanonicalGrammar.FixedEquals(actual.DxrKeyId.Span, expected.DxrKeyId.Span) ||
            !CanonicalGrammar.FixedEquals(
                actual.NonceIndexKeyId.Span, expected.NonceIndexKeyId.Span))
            Invalid("The DXP persistence profile moved during identity issuance.");
    }

    private static ReadOnlyMemory<byte>[] Minimum(RecordDefinition definition) =>
        definition.Fields.Select(static field =>
            (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();

    private static byte[] Reference(ArtifactType type, ReadOnlySpan<byte> canonical) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, canonical));

    private static byte[] RandomNonzero(IIdentityAuthoringRandom random, int length)
    {
        var value = new byte[length];
        do random.Fill(value); while (CanonicalGrammar.IsZero(value));
        return value;
    }

    private static byte[] U16(ushort value)
    {
        var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes;
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes;
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidTransition, message);
}
