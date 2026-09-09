using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.MessagingCrypto;

/// <summary>
/// Public, non-secret storage scope for one local device's DPK2 secrets. The
/// exact DPD1 reference binds the account generation through the verified
/// identity closure used when the DPK2 was authored.
/// </summary>
public sealed class Dpk2PreKeyPersistenceScope
{
    private readonly byte[] _networkId;
    private readonly byte[] _accountId;
    private readonly byte[] _deviceId;
    private readonly byte[] _dpd1Reference;

    public Dpk2PreKeyPersistenceScope(
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> accountId32,
        ulong accountGeneration,
        ReadOnlySpan<byte> deviceId32,
        ulong deviceGeneration,
        ReadOnlySpan<byte> exactDpd1Reference38)
    {
        RequireNonZero(networkId16, 16, nameof(networkId16));
        RequireNonZero(accountId32, 32, nameof(accountId32));
        RequireNonZero(deviceId32, 32, nameof(deviceId32));
        if (accountGeneration == 0) throw new ArgumentOutOfRangeException(nameof(accountGeneration));
        if (deviceGeneration == 0) throw new ArgumentOutOfRangeException(nameof(deviceGeneration));
        if (exactDpd1Reference38.Length != 38 ||
            !exactDpd1Reference38[..4].SequenceEqual("DPD1"u8) ||
            BinaryPrimitives.ReadUInt16BigEndian(exactDpd1Reference38[4..6]) != 1 ||
            exactDpd1Reference38[6..].IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The exact DPD1 reference must be canonical v1.", nameof(exactDpd1Reference38));

        _networkId = networkId16.ToArray();
        _accountId = accountId32.ToArray();
        AccountGeneration = accountGeneration;
        _deviceId = deviceId32.ToArray();
        DeviceGeneration = deviceGeneration;
        _dpd1Reference = exactDpd1Reference38.ToArray();
    }

    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> AccountId => _accountId.ToArray();
    public ulong AccountGeneration { get; }
    public ReadOnlyMemory<byte> DeviceId => _deviceId.ToArray();
    public ulong DeviceGeneration { get; }
    public ReadOnlyMemory<byte> ExactDpd1Reference => _dpd1Reference.ToArray();

    internal ReadOnlySpan<byte> NetworkIdSpan => _networkId;
    internal ReadOnlySpan<byte> AccountIdSpan => _accountId;
    internal ReadOnlySpan<byte> DeviceIdSpan => _deviceId;
    internal ReadOnlySpan<byte> Dpd1ReferenceSpan => _dpd1Reference;

    internal bool Matches(Dpk2Record record) =>
        record.ResponderDeviceGeneration == DeviceGeneration &&
        Fixed(_networkId, record.NetworkId.Span) &&
        Fixed(_accountId, record.ResponderAccountId.Span) &&
        Fixed(_deviceId, record.ResponderDeviceId.Span) &&
        Fixed(_dpd1Reference, record.ResponderDpd1Ref.Span);

    private static void RequireNonZero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
    }

    internal static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// Canonical, bounded ciphertext for one exact DPK2 secret set. It exposes
/// only authenticated ciphertext bytes and has no public constructor.
/// </summary>
public sealed class Dpk2PreKeyPersistenceBlob
{
    private readonly byte[] _canonical;

    internal Dpk2PreKeyPersistenceBlob(byte[] canonical) => _canonical = canonical;

    public const int MaximumCanonicalBytes = 4_481;
    public ReadOnlyMemory<byte> CanonicalBytes => _canonical.ToArray();

    public static Dpk2PreKeyPersistenceBlob Decode(ReadOnlyMemory<byte> exactCanonicalBlob)
    {
        Dpk2PreKeyPersistenceCodec.ValidateCanonical(exactCanonicalBlob.Span);
        return new Dpk2PreKeyPersistenceBlob(exactCanonicalBlob.ToArray());
    }

    internal ReadOnlySpan<byte> CanonicalSpan => _canonical;
}

/// <summary>
/// Caller-keyed at-rest protection boundary. The supplied key is copied into a
/// zeroizing owner and is never exposed by a property, callback, or provider.
/// </summary>
public sealed class Dpk2PreKeyPersistenceProtector : IDisposable
{
    private SecretBuffer? _atRestKey;
    private int _disposed;

    public Dpk2PreKeyPersistenceProtector(ReadOnlySpan<byte> atRestKey32)
    {
        if (atRestKey32.Length != 32 || atRestKey32.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The DPK2 at-rest key must be non-zero 32 bytes.", nameof(atRestKey32));
        _atRestKey = SecretBuffer.ImportExact(atRestKey32, 32, nameof(atRestKey32));
    }

    ~Dpk2PreKeyPersistenceProtector() => DisposeCore();

    public RestoredDpk2PreKeySecretCapability Restore(
        Dpk2PreKeyPersistenceBlob blob,
        ReadOnlyMemory<byte> exactDpk2,
        Dpk2PreKeyPersistenceScope scope)
    {
        ArgumentNullException.ThrowIfNull(blob);
        ArgumentNullException.ThrowIfNull(scope);
        var key = Key();
        try
        {
            return Dpk2PreKeyPersistenceCodec.Restore(
                blob.CanonicalSpan, exactDpk2.Span, scope, key);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    internal Dpk2PreKeyPersistenceBlob SealAndConsume(
        Dpk2PreKeySecretCapability capability,
        ReadOnlySpan<byte> exactDpk2,
        Dpk2PreKeyPersistenceScope scope)
    {
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentNullException.ThrowIfNull(scope);
        using var material = capability.ConsumeForProtocolOwner();
        var key = Key();
        try
        {
            return Dpk2PreKeyPersistenceCodec.Seal(
                capability, material, exactDpk2, scope, key);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    public void Dispose()
    {
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    private byte[] Key()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return _atRestKey!.Copy();
    }

    private void DisposeCore()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        Interlocked.Exchange(ref _atRestKey, null)?.Dispose();
    }
}

/// <summary>
/// Restored, exact-DPK2-bound secret capability. It is non-serializable,
/// single-use, and exposes only public identifiers.
/// </summary>
public sealed class RestoredDpk2PreKeySecretCapability : IDisposable
{
    private readonly byte[] _exactDpk2Hash;
    private readonly byte[] _signedPreKeyId;
    private readonly byte[] _oneTimePreKeyId;
    private readonly byte[] _mlKemPreKeyId;
    private SecretBuffer? _signedPrivate;
    private SecretBuffer? _oneTimePrivate;
    private SecretBuffer? _mlKemSecret;
    private int _consumed;

    internal RestoredDpk2PreKeySecretCapability(
        Dpk2Record record,
        ReadOnlySpan<byte> exactDpk2Hash,
        ReadOnlySpan<byte> signedPrivate,
        ReadOnlySpan<byte> oneTimePrivate,
        ReadOnlySpan<byte> mlKemSecret)
    {
        _exactDpk2Hash = exactDpk2Hash.ToArray();
        _signedPreKeyId = record.SignedX25519PrekeyId.ToArray();
        _oneTimePreKeyId = record.OneTimeX25519PrekeyId.ToArray();
        _mlKemPreKeyId = record.MlKemPrekeyId.ToArray();
        Kind = record.MlKemKind;
        ReuseLimit = record.ReuseLimit;
        SecretBuffer? signed = null;
        SecretBuffer? oneTime = null;
        SecretBuffer? mlKem = null;
        try
        {
            RequirePrivateMatchesPublic(signedPrivate, record.SignedX25519PrekeyPublic.Span);
            signed = SecretBuffer.ImportExact(signedPrivate, 32, nameof(signedPrivate));
            MessagingCryptoFaultInjection.OwnedSecret(
                "dpk2.persistence.restored-signed-private", signed);
            if (Kind == Dpk2PrekeyKind.OneTime)
            {
                RequirePrivateMatchesPublic(oneTimePrivate, record.OneTimeX25519PrekeyPublic.Span);
                oneTime = SecretBuffer.ImportExact(oneTimePrivate, 32, nameof(oneTimePrivate));
                MessagingCryptoFaultInjection.OwnedSecret(
                    "dpk2.persistence.restored-one-time-private", oneTime);
            }
            else if (!oneTimePrivate.IsEmpty)
            {
                throw new CryptographicException("A last-resort DPK2 blob contains a one-time X25519 scalar.");
            }
            if (mlKemSecret.Length is < 1 or > 4096 || mlKemSecret.IndexOfAnyExcept((byte)0) < 0)
                throw new CryptographicException("The restored ML-KEM secret is outside its closed bounds.");
            mlKem = SecretBuffer.ImportBounded(mlKemSecret, 1, 4096, nameof(mlKemSecret));
            MessagingCryptoFaultInjection.OwnedSecret(
                "dpk2.persistence.restored-ml-kem-secret", mlKem);
            _signedPrivate = signed;
            _oneTimePrivate = oneTime;
            _mlKemSecret = mlKem;
            signed = null;
            oneTime = null;
            mlKem = null;
        }
        finally
        {
            signed?.Dispose();
            oneTime?.Dispose();
            mlKem?.Dispose();
        }
    }

    ~RestoredDpk2PreKeySecretCapability() => DisposeCore();

    public Dpk2PrekeyKind Kind { get; }
    public ushort ReuseLimit { get; }
    public ReadOnlyMemory<byte> ExactDpk2Hash => _exactDpk2Hash.ToArray();
    public ReadOnlyMemory<byte> SignedX25519PreKeyId => _signedPreKeyId.ToArray();
    public ReadOnlyMemory<byte> OneTimeX25519PreKeyId => _oneTimePreKeyId.ToArray();
    public ReadOnlyMemory<byte> MlKemPreKeyId => _mlKemPreKeyId.ToArray();

    internal OwnedDpk2PreKeyMaterial ConsumeForHandshake(
        VerifiedInitialSessionPreKeyClaim.ProtocolClaimPayload claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new InvalidOperationException("The restored DPK2 secret capability is no longer available.");

        byte[]? signed = null;
        byte[]? oneTime = null;
        byte[]? mlKem = null;
        try
        {
            if (claim.Kind != Kind ||
                !Dpk2PreKeyPersistenceScope.Fixed(_exactDpk2Hash, claim.ExactDpk2Hash) ||
                !Dpk2PreKeyPersistenceScope.Fixed(_signedPreKeyId,
                    claim.Initiation.Offering.Record.SignedX25519PrekeyId.Span) ||
                !Dpk2PreKeyPersistenceScope.Fixed(_oneTimePreKeyId,
                    claim.Kind == Dpk2PrekeyKind.OneTime ? claim.X25519PreKeyId : []) ||
                !Dpk2PreKeyPersistenceScope.Fixed(_mlKemPreKeyId, claim.MlKemPreKeyId))
                throw new CryptographicException("The restored DPK2 secrets do not match the verifier-minted claim.");

            signed = _signedPrivate!.Copy();
            oneTime = _oneTimePrivate?.Copy();
            mlKem = _mlKemSecret!.Copy();
            var result = new OwnedDpk2PreKeyMaterial(signed, oneTime, mlKem);
            signed = null;
            oneTime = null;
            mlKem = null;
            return result;
        }
        finally
        {
            if (signed is not null) CryptographicOperations.ZeroMemory(signed);
            if (oneTime is not null) CryptographicOperations.ZeroMemory(oneTime);
            if (mlKem is not null) CryptographicOperations.ZeroMemory(mlKem);
            DisposeSecrets();
            GC.SuppressFinalize(this);
        }
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _consumed, 1);
        DisposeSecrets();
        GC.SuppressFinalize(this);
    }

    private void DisposeCore()
    {
        Interlocked.Exchange(ref _consumed, 1);
        DisposeSecrets();
    }

    private void DisposeSecrets()
    {
        Interlocked.Exchange(ref _signedPrivate, null)?.Dispose();
        Interlocked.Exchange(ref _oneTimePrivate, null)?.Dispose();
        Interlocked.Exchange(ref _mlKemSecret, null)?.Dispose();
    }

    private static void RequirePrivateMatchesPublic(
        ReadOnlySpan<byte> privateScalar,
        ReadOnlySpan<byte> expectedPublic)
    {
        if (privateScalar.Length != 32 || privateScalar.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException("The restored X25519 scalar is invalid.");
        var scalar = privateScalar.ToArray();
        byte[]? actual = null;
        try
        {
            actual = ScalarMult.Base(scalar);
            if (!Dpk2PreKeyPersistenceScope.Fixed(actual, expectedPublic))
                throw new CryptographicException("The restored X25519 scalar does not own its exact DPK2 public key.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scalar);
            if (actual is not null) CryptographicOperations.ZeroMemory(actual);
        }
    }
}

internal static class Dpk2PreKeyPersistenceCodec
{
    private const byte Version = 1;
    private const byte Algorithm = 1;
    private const int HeaderBytes = 301;
    private const int NonceOffset = 8;
    private const int NonceBytes = 24;
    private const int NetworkOffset = 32;
    private const int AccountOffset = 48;
    private const int AccountGenerationOffset = 80;
    private const int DeviceOffset = 88;
    private const int DeviceGenerationOffset = 120;
    private const int Dpd1ReferenceOffset = 128;
    private const int ExactDpk2HashOffset = 166;
    private const int KindOffset = 198;
    private const int ReuseLimitOffset = 199;
    private const int SignedPreKeyIdOffset = 201;
    private const int OneTimePreKeyIdOffset = 233;
    private const int MlKemPreKeyIdOffset = 265;
    private const int CiphertextLengthOffset = 297;
    private const int AeadTagBytes = 16;
    private const int PlaintextFixedBytes = 68;
    private const int MinimumCiphertextBytes = PlaintextFixedBytes + 1 + AeadTagBytes;
    private const int MaximumCiphertextBytes = PlaintextFixedBytes + 4096 + AeadTagBytes;
    private const string KeyDomain = "Deep/Messaging/V2/dpk2-prekey-persistence-key";

    internal static Dpk2PreKeyPersistenceBlob Seal(
        Dpk2PreKeySecretCapability capability,
        OwnedDpk2PreKeyMaterial material,
        ReadOnlySpan<byte> exactDpk2,
        Dpk2PreKeyPersistenceScope scope,
        ReadOnlySpan<byte> atRestKey)
    {
        var (record, exactHash) = DecodeExactDpk2(exactDpk2);
        capability.RequirePersistenceBinding(record, exactHash, scope);
        var plaintext = new byte[checked(PlaintextFixedBytes + material.MlKemSecret.Length)];
        var header = new byte[HeaderBytes];
        var nonce = new byte[NonceBytes];
        byte[]? derivedKey = null;
        byte[]? ciphertext = null;
        try
        {
            plaintext[0] = Version;
            plaintext[1] = (byte)record.MlKemKind;
            BinaryPrimitives.WriteUInt16BigEndian(plaintext.AsSpan(2), checked((ushort)material.MlKemSecret.Length));
            material.SignedPrivate.CopyTo(plaintext, 4);
            if (material.OneTimePrivate is not null) material.OneTimePrivate.CopyTo(plaintext, 36);
            material.MlKemSecret.CopyTo(plaintext, PlaintextFixedBytes);

            RandomNumberGenerator.Fill(nonce);
            WriteHeader(header, nonce, scope, record, exactHash, checked(plaintext.Length + AeadTagBytes));
            derivedKey = DeriveKey(atRestKey, header);
            ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(plaintext, nonce, derivedKey, header);
            if (ciphertext.Length != plaintext.Length + AeadTagBytes)
                throw new CryptographicException("DPK2 persistence AEAD returned an unexpected length.");
            var canonical = new byte[checked(HeaderBytes + ciphertext.Length)];
            header.CopyTo(canonical, 0);
            ciphertext.CopyTo(canonical, HeaderBytes);
            ValidateCanonical(canonical);
            return new Dpk2PreKeyPersistenceBlob(canonical);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactHash);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(header);
            CryptographicOperations.ZeroMemory(nonce);
            if (derivedKey is not null) CryptographicOperations.ZeroMemory(derivedKey);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    internal static RestoredDpk2PreKeySecretCapability Restore(
        ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> exactDpk2,
        Dpk2PreKeyPersistenceScope scope,
        ReadOnlySpan<byte> atRestKey)
    {
        ValidateCanonical(canonical);
        var (record, exactHash) = DecodeExactDpk2(exactDpk2);
        byte[]? nonce = null;
        byte[]? header = null;
        byte[]? ciphertext = null;
        byte[]? derivedKey = null;
        byte[]? plaintext = null;
        try
        {
            RequireHeaderBinding(canonical, record, exactHash, scope);
            nonce = canonical.Slice(NonceOffset, NonceBytes).ToArray();
            header = canonical[..HeaderBytes].ToArray();
            ciphertext = canonical[HeaderBytes..].ToArray();
            derivedKey = DeriveKey(atRestKey, header);
            try
            {
                plaintext = SecretAeadXChaCha20Poly1305.Decrypt(ciphertext, nonce, derivedKey, header);
            }
            catch (Exception exception) when (exception is CryptographicException or ArgumentException)
            {
                throw new CryptographicException("DPK2 persistence blob authentication failed.", exception);
            }
            if (plaintext.Length < PlaintextFixedBytes + 1 ||
                plaintext.Length > PlaintextFixedBytes + 4096 ||
                plaintext[0] != Version || plaintext[1] != (byte)record.MlKemKind)
                throw new CryptographicException("DPK2 persistence plaintext has an invalid canonical shape.");
            var mlKemLength = BinaryPrimitives.ReadUInt16BigEndian(plaintext.AsSpan(2));
            if (mlKemLength is < 1 or > 4096 || plaintext.Length != PlaintextFixedBytes + mlKemLength)
                throw new CryptographicException("DPK2 persistence ML-KEM secret length is invalid.");
            var oneTime = record.MlKemKind == Dpk2PrekeyKind.OneTime
                ? plaintext.AsSpan(36, 32)
                : ReadOnlySpan<byte>.Empty;
            if (record.MlKemKind == Dpk2PrekeyKind.LastResort &&
                plaintext.AsSpan(36, 32).IndexOfAnyExcept((byte)0) >= 0)
                throw new CryptographicException("Last-resort persistence plaintext contains a one-time secret.");
            return new RestoredDpk2PreKeySecretCapability(
                record, exactHash, plaintext.AsSpan(4, 32), oneTime,
                plaintext.AsSpan(PlaintextFixedBytes, mlKemLength));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactHash);
            if (nonce is not null) CryptographicOperations.ZeroMemory(nonce);
            if (header is not null) CryptographicOperations.ZeroMemory(header);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
            if (derivedKey is not null) CryptographicOperations.ZeroMemory(derivedKey);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    internal static void ValidateCanonical(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length < HeaderBytes + MinimumCiphertextBytes ||
            canonical.Length > Dpk2PreKeyPersistenceBlob.MaximumCanonicalBytes)
            throw new CryptographicException("DPK2 persistence blob length is outside its closed bounds.");
        if (canonical[0] != Version || canonical[1] != Algorithm ||
            canonical[2] != 0 || canonical[3] != 0 ||
            BinaryPrimitives.ReadUInt32BigEndian(canonical[4..8]) != canonical.Length)
            throw new CryptographicException("DPK2 persistence blob header is not canonical v1.");
        if (canonical.Slice(NetworkOffset, 16).IndexOfAnyExcept((byte)0) < 0 ||
            canonical.Slice(AccountOffset, 32).IndexOfAnyExcept((byte)0) < 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(AccountGenerationOffset, 8)) == 0 ||
            canonical.Slice(DeviceOffset, 32).IndexOfAnyExcept((byte)0) < 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(DeviceGenerationOffset, 8)) == 0 ||
            !canonical.Slice(Dpd1ReferenceOffset, 4).SequenceEqual("DPD1"u8) ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(Dpd1ReferenceOffset + 4, 2)) != 1 ||
            canonical.Slice(Dpd1ReferenceOffset + 6, 32).IndexOfAnyExcept((byte)0) < 0 ||
            canonical.Slice(ExactDpk2HashOffset, 32).IndexOfAnyExcept((byte)0) < 0 ||
            canonical.Slice(SignedPreKeyIdOffset, 32).IndexOfAnyExcept((byte)0) < 0 ||
            canonical.Slice(MlKemPreKeyIdOffset, 32).IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException("DPK2 persistence blob binding is invalid.");
        var kind = (Dpk2PrekeyKind)canonical[KindOffset];
        var reuseLimit = BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(ReuseLimitOffset, 2));
        var oneTimeId = canonical.Slice(OneTimePreKeyIdOffset, 32);
        if (kind == Dpk2PrekeyKind.OneTime)
        {
            if (reuseLimit != 0 || oneTimeId.IndexOfAnyExcept((byte)0) < 0)
                throw new CryptographicException("One-time DPK2 persistence binding is invalid.");
        }
        else if (kind == Dpk2PrekeyKind.LastResort)
        {
            if (reuseLimit is < 1 or > 64 || oneTimeId.IndexOfAnyExcept((byte)0) >= 0)
                throw new CryptographicException("Last-resort DPK2 persistence binding is invalid.");
        }
        else
        {
            throw new CryptographicException("DPK2 persistence kind is invalid.");
        }
        var ciphertextLength = BinaryPrimitives.ReadUInt32BigEndian(
            canonical.Slice(CiphertextLengthOffset, 4));
        if (ciphertextLength is < MinimumCiphertextBytes or > MaximumCiphertextBytes ||
            ciphertextLength != canonical.Length - HeaderBytes)
            throw new CryptographicException("DPK2 persistence ciphertext length is invalid.");
    }

    private static void WriteHeader(
        Span<byte> header,
        ReadOnlySpan<byte> nonce,
        Dpk2PreKeyPersistenceScope scope,
        Dpk2Record record,
        ReadOnlySpan<byte> exactHash,
        int ciphertextLength)
    {
        header.Clear();
        header[0] = Version;
        header[1] = Algorithm;
        BinaryPrimitives.WriteUInt32BigEndian(header[4..8], checked((uint)(HeaderBytes + ciphertextLength)));
        nonce.CopyTo(header.Slice(NonceOffset, NonceBytes));
        scope.NetworkIdSpan.CopyTo(header.Slice(NetworkOffset, 16));
        scope.AccountIdSpan.CopyTo(header.Slice(AccountOffset, 32));
        BinaryPrimitives.WriteUInt64BigEndian(header.Slice(AccountGenerationOffset, 8), scope.AccountGeneration);
        scope.DeviceIdSpan.CopyTo(header.Slice(DeviceOffset, 32));
        BinaryPrimitives.WriteUInt64BigEndian(header.Slice(DeviceGenerationOffset, 8), scope.DeviceGeneration);
        scope.Dpd1ReferenceSpan.CopyTo(header.Slice(Dpd1ReferenceOffset, 38));
        exactHash.CopyTo(header.Slice(ExactDpk2HashOffset, 32));
        header[KindOffset] = (byte)record.MlKemKind;
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(ReuseLimitOffset, 2), record.ReuseLimit);
        record.SignedX25519PrekeyId.Span.CopyTo(header.Slice(SignedPreKeyIdOffset, 32));
        if (record.MlKemKind == Dpk2PrekeyKind.OneTime)
            record.OneTimeX25519PrekeyId.Span.CopyTo(header.Slice(OneTimePreKeyIdOffset, 32));
        record.MlKemPrekeyId.Span.CopyTo(header.Slice(MlKemPreKeyIdOffset, 32));
        BinaryPrimitives.WriteUInt32BigEndian(header.Slice(CiphertextLengthOffset, 4), checked((uint)ciphertextLength));
    }

    private static void RequireHeaderBinding(
        ReadOnlySpan<byte> canonical,
        Dpk2Record record,
        ReadOnlySpan<byte> exactHash,
        Dpk2PreKeyPersistenceScope scope)
    {
        if (!scope.Matches(record) ||
            !Dpk2PreKeyPersistenceScope.Fixed(canonical.Slice(NetworkOffset, 16), scope.NetworkIdSpan) ||
            !Dpk2PreKeyPersistenceScope.Fixed(canonical.Slice(AccountOffset, 32), scope.AccountIdSpan) ||
            BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(AccountGenerationOffset, 8)) != scope.AccountGeneration ||
            !Dpk2PreKeyPersistenceScope.Fixed(canonical.Slice(DeviceOffset, 32), scope.DeviceIdSpan) ||
            BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(DeviceGenerationOffset, 8)) != scope.DeviceGeneration ||
            !Dpk2PreKeyPersistenceScope.Fixed(canonical.Slice(Dpd1ReferenceOffset, 38), scope.Dpd1ReferenceSpan) ||
            !Dpk2PreKeyPersistenceScope.Fixed(canonical.Slice(ExactDpk2HashOffset, 32), exactHash) ||
            canonical[KindOffset] != (byte)record.MlKemKind ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(ReuseLimitOffset, 2)) != record.ReuseLimit ||
            !Dpk2PreKeyPersistenceScope.Fixed(canonical.Slice(SignedPreKeyIdOffset, 32), record.SignedX25519PrekeyId.Span) ||
            !Dpk2PreKeyPersistenceScope.Fixed(canonical.Slice(OneTimePreKeyIdOffset, 32),
                record.MlKemKind == Dpk2PrekeyKind.OneTime ? record.OneTimeX25519PrekeyId.Span : new byte[32]) ||
            !Dpk2PreKeyPersistenceScope.Fixed(canonical.Slice(MlKemPreKeyIdOffset, 32), record.MlKemPrekeyId.Span))
            throw new CryptographicException("DPK2 persistence blob does not match the exact key, scope, or DPK2 binding.");
    }

    private static (Dpk2Record Record, byte[] ExactHash) DecodeExactDpk2(ReadOnlySpan<byte> exactDpk2)
    {
        var record = Dpk2Codec.Decode(exactDpk2);
        var canonical = Dpk2Codec.Encode(record);
        try
        {
            if (!canonical.AsSpan().SequenceEqual(exactDpk2))
                throw new CryptographicException("The supplied DPK2 bytes are not exact canonical bytes.");
        }
        finally { CryptographicOperations.ZeroMemory(canonical); }
        return (record, MessagingWireCryptographicInputs.ComputeExactDpk2Hash(record));
    }

    private static byte[] DeriveKey(ReadOnlySpan<byte> atRestKey, ReadOnlySpan<byte> header)
    {
        if (atRestKey.Length != 32 || atRestKey.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException("The DPK2 at-rest key is invalid.");
        var label = Encoding.ASCII.GetBytes(KeyDomain);
        var input = new byte[checked(label.Length + 1 + header.Length)];
        var key = atRestKey.ToArray();
        try
        {
            label.CopyTo(input, 0);
            header.CopyTo(input.AsSpan(label.Length + 1));
            return HMACSHA256.HashData(key, input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(label);
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
