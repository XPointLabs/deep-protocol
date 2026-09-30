using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.MessagingCrypto;

/// <summary>Non-secret, exact local database/intent scope. This is not
/// account, claim, device agreement or dispatch authority.</summary>
public sealed class InitiatorDph2PreKeyClaimPersistenceScope
{
    private readonly byte[] instance, intent;

    public InitiatorDph2PreKeyClaimPersistenceScope(ReadOnlySpan<byte> databaseInstanceId32,
        ReadOnlySpan<byte> logicalIntentId32)
    {
        MessagingCryptoValidation.Exact(databaseInstanceId32, 32, nameof(databaseInstanceId32));
        MessagingCryptoValidation.Exact(logicalIntentId32, 32, nameof(logicalIntentId32));
        instance = databaseInstanceId32.ToArray();
        intent = logicalIntentId32.ToArray();
        MessagingCryptoValidation.NonZeroExact(instance, 32, nameof(databaseInstanceId32));
        MessagingCryptoValidation.NonZeroExact(intent, 32, nameof(logicalIntentId32));
    }

    public ReadOnlyMemory<byte> DatabaseInstanceId => instance.ToArray();
    public ReadOnlyMemory<byte> LogicalIntentId => intent.ToArray();
    internal ReadOnlySpan<byte> InstanceSpan => instance;
    internal ReadOnlySpan<byte> IntentSpan => intent;
}

/// <summary>Bounded local ciphertext. Structural Decode grants no authority;
/// authentication and current identity checks happen only during restore.</summary>
public sealed class InitiatorDph2PreKeyClaimPersistenceBlob
{
    private readonly byte[] canonical;
    internal InitiatorDph2PreKeyClaimPersistenceBlob(byte[] value) => canonical = value;
    public const int CanonicalByteCount = 2552;
    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();

    public static InitiatorDph2PreKeyClaimPersistenceBlob Decode(ReadOnlyMemory<byte> exactBlob)
    {
        if (exactBlob.Length != CanonicalByteCount)
            throw new CryptographicException("The sealed preclaim has no canonical size.");
        var owned = exactBlob.ToArray();
        InitiatorDph2PreKeyClaimPersistenceCodec.Validate(owned);
        return new(owned);
    }

    internal ReadOnlySpan<byte> CanonicalSpan => canonical;
}

/// <summary>Zeroizing at-rest key owner for pre-XPK1 secrets. Does not mint or
/// replay a device agreement lease, consume a remote prekey or dispatch DPH2.</summary>
public sealed class InitiatorDph2PreKeyClaimPersistenceProtector : IDisposable
{
    private SecretBuffer? key;
    private int disposed;

    public InitiatorDph2PreKeyClaimPersistenceProtector(ReadOnlySpan<byte> atRestKey32)
    {
        MessagingCryptoValidation.Exact(atRestKey32, 32, nameof(atRestKey32));
        var owned = atRestKey32.ToArray();
        try
        {
            MessagingCryptoValidation.NonZeroExact(owned, 32, nameof(atRestKey32));
            key = SecretBuffer.ImportExact(owned, 32, nameof(atRestKey32));
        }
        finally { CryptographicOperations.ZeroMemory(owned); }
    }

    ~InitiatorDph2PreKeyClaimPersistenceProtector() => DisposeCore();

    public InitiatorDph2PreKeyClaimPersistenceBlob SealAndConsume(
        InitiatorDph2PreKeyClaim startedClaim, InitiatorDph2PreKeyClaimPersistenceScope scope)
    {
        ArgumentNullException.ThrowIfNull(startedClaim);
        ArgumentNullException.ThrowIfNull(scope);
        using var material = startedClaim.Consume();
        var ownedKey = CopyKey();
        try
        {
            var blob = InitiatorDph2PreKeyClaimPersistenceCodec.Seal(material, scope, ownedKey);
            ThrowIfDisposed();
            return blob;
        }
        finally { CryptographicOperations.ZeroMemory(ownedKey); }
    }

    public async ValueTask<InitiatorDph2PreKeyClaim> RestoreCurrentAsync(
        InitiatorDph2PreKeyClaimPersistenceBlob blob,
        InitiatorDph2PreKeyClaimPersistenceScope scope,
        LocalDeviceX25519AgreementAuthority localAuthority,
        Dmd1LineageState exactCurrentDirectory,
        VerifiedDeepIdV2DirectoryFreshness currentAccount,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(blob);
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(localAuthority);
        ArgumentNullException.ThrowIfNull(exactCurrentDirectory);
        ArgumentNullException.ThrowIfNull(currentAccount);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        cancellationToken.ThrowIfCancellationRequested();
        var ownedKey = CopyKey();
        InitiatorDph2PreKeyClaim? restored = null;
        try
        {
            var local = InitiatorDph2PreKeyClaimPersistenceCodec.ReadLocal(blob.CanonicalSpan, scope);
            var initial = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            local.RequireSame(InitiatorAgreementFacts.FromCurrent(localAuthority, exactCurrentDirectory,
                currentAccount, initial.BootId.Span, initial.SampleSeconds, local.OperationBinding));
            restored = InitiatorDph2PreKeyClaimPersistenceCodec.Restore(blob.CanonicalSpan, local, ownedKey);
            var final = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (!Fixed(initial.BootId.Span, final.BootId.Span) || final.SampleSeconds < initial.SampleSeconds)
                throw new CryptographicException("The preclaim restore clock changed boot or moved backwards.");
            restored.RequireCurrentInitiator(localAuthority, exactCurrentDirectory, currentAccount,
                final.BootId.Span, final.SampleSeconds);
            var result = restored;
            restored = null;
            return result;
        }
        finally
        {
            restored?.Dispose();
            CryptographicOperations.ZeroMemory(ownedKey);
        }
    }

    private byte[] CopyKey()
    {
        ThrowIfDisposed();
        return (key ?? throw new ObjectDisposedException(GetType().Name)).Copy();
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    public void Dispose() { DisposeCore(); GC.SuppressFinalize(this); }
    private void DisposeCore()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0) Interlocked.Exchange(ref key, null)?.Dispose();
    }
}

internal static class InitiatorDph2PreKeyClaimPersistenceCodec
{
    private const int HeaderBytes = 2472, NonceOffset = 2448;
    private const string KeyDomain = "Deep/Messaging/V2/dph2-preclaim-persistence-key";

    internal static void Validate(ReadOnlySpan<byte> value)
    {
        if (value.Length != InitiatorDph2PreKeyClaimPersistenceBlob.CanonicalByteCount ||
            !value[..4].SequenceEqual("IPK2"u8) || value[4] != 1 || value[5] != 1 ||
            value[6] != 0 || value[7] != 0 || BinaryPrimitives.ReadUInt32BigEndian(value[8..12]) != value.Length)
            throw new CryptographicException("The sealed preclaim has no canonical local format.");
        foreach (var offset in new[] { 12, 44, 92, 124, 164, 204, 2288, 2320, 2352, 2384, 2416 })
            MessagingCryptoValidation.NonZeroExact(value.Slice(offset, 32), 32, "preclaim binding");
        MessagingCryptoValidation.NonZeroExact(value.Slice(76, 16), 16, "preclaim network");
        if (BinaryPrimitives.ReadUInt64BigEndian(value.Slice(156, 8)) == 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(value.Slice(196, 8)) == 0)
            throw new CryptographicException("The sealed preclaim generations are zero.");
        _ = DeepIdV2Codec.DecodeDid2(value.Slice(236, 2052));
    }

    internal static InitiatorAgreementFacts ReadLocal(ReadOnlySpan<byte> value,
        InitiatorDph2PreKeyClaimPersistenceScope scope)
    {
        Validate(value);
        if (!Fixed(value.Slice(12, 32), scope.InstanceSpan) || !Fixed(value.Slice(44, 32), scope.IntentSpan))
            throw new CryptographicException("The sealed preclaim belongs to another database or intent.");
        return new(value.Slice(76, 16), value.Slice(92, 32), value.Slice(124, 32),
            BinaryPrimitives.ReadUInt64BigEndian(value.Slice(156, 8)), value.Slice(164, 32),
            BinaryPrimitives.ReadUInt64BigEndian(value.Slice(196, 8)), value.Slice(204, 32),
            value.Slice(236, 2052), value.Slice(2288, 32), value.Slice(2320, 32));
    }

    internal static InitiatorDph2PreKeyClaimPersistenceBlob Seal(InitiatorDph2PreKeyClaimMaterial material,
        InitiatorDph2PreKeyClaimPersistenceScope scope, ReadOnlySpan<byte> key)
    {
        var value = new byte[InitiatorDph2PreKeyClaimPersistenceBlob.CanonicalByteCount];
        var plaintext = new byte[64];
        byte[]? ephemeral = null, ratchet = null, derived = null, ciphertext = null;
        try
        {
            "IPK2"u8.CopyTo(value); value[4] = 1; value[5] = 1;
            BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(8, 4), checked((uint)value.Length));
            scope.InstanceSpan.CopyTo(value.AsSpan(12)); scope.IntentSpan.CopyTo(value.AsSpan(44));
            var local = material.Local;
            local.NetworkId.CopyTo(value, 76); local.AccountId.CopyTo(value, 92); local.DeviceId.CopyTo(value, 124);
            BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(156, 8), local.DeviceGeneration);
            local.ExactDpd1Hash.CopyTo(value, 164);
            BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(196, 8), local.DirectoryGeneration);
            local.ExactDirectoryHash.CopyTo(value, 204); local.ExactDid2.CopyTo(value, 236);
            local.AgreementPublicKey.CopyTo(value, 2288); local.OperationBinding.CopyTo(value, 2320);
            material.SenderEphemeralCommitment.CopyTo(value.AsSpan(2352));
            material.EphemeralPublic.CopyTo(value.AsSpan(2384));
            material.InitialRatchetPublic.CopyTo(value.AsSpan(2416));
            RandomNumberGenerator.Fill(value.AsSpan(NonceOffset, 24));
            Validate(value);
            ephemeral = material.CopyEphemeralPrivate(); ratchet = material.CopyInitialRatchetPrivate();
            ephemeral.CopyTo(plaintext, 0); ratchet.CopyTo(plaintext, 32);
            RequirePlaintext(value, plaintext);
            derived = DeriveKey(key, value.AsSpan(0, HeaderBytes));
            ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(plaintext, value.AsSpan(NonceOffset, 24).ToArray(),
                derived, value.AsSpan(0, HeaderBytes).ToArray());
            if (ciphertext.Length != 80) throw new CryptographicException("The sealed preclaim AEAD size is invalid.");
            ciphertext.CopyTo(value, HeaderBytes);
            return new(value);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            Zero(ephemeral); Zero(ratchet); Zero(derived); Zero(ciphertext);
        }
    }

    internal static InitiatorDph2PreKeyClaim Restore(ReadOnlySpan<byte> value,
        InitiatorAgreementFacts local, ReadOnlySpan<byte> key)
    {
        var header = value[..HeaderBytes].ToArray();
        var ciphertext = value[HeaderBytes..].ToArray();
        var nonce = value.Slice(NonceOffset, 24).ToArray();
        byte[]? derived = null, plaintext = null;
        try
        {
            derived = DeriveKey(key, header);
            plaintext = SecretAeadXChaCha20Poly1305.Decrypt(ciphertext, nonce, derived, header);
            RequirePlaintext(value, plaintext);
            return new(local, plaintext.AsSpan(0, 32), value.Slice(2384, 32),
                plaintext.AsSpan(32, 32), value.Slice(2416, 32), value.Slice(2352, 32));
        }
        finally
        {
            Zero(derived); Zero(plaintext);
            CryptographicOperations.ZeroMemory(header); CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    private static void RequirePlaintext(ReadOnlySpan<byte> header, ReadOnlySpan<byte> plaintext)
    {
        if (plaintext.Length != 64) throw new CryptographicException("The sealed preclaim plaintext size is invalid.");
        MessagingCryptoValidation.NonZeroExact(plaintext[..32], 32, "ephemeral scalar");
        MessagingCryptoValidation.NonZeroExact(plaintext[32..], 32, "ratchet scalar");
        var ephemeralPublic = new byte[32]; var ratchetPublic = new byte[32];
        byte[]? commitment = null;
        try
        {
            OwnedSodiumX25519.DerivePublicKey(plaintext[..32], ephemeralPublic);
            OwnedSodiumX25519.DerivePublicKey(plaintext[32..], ratchetPublic);
            var dpd = ApplicationCoreCodec.CreateArtifactReference(
                (ushort)Deep.Protocol.DeepNative.ArtifactType.Dpd1,
                checked((uint)Deep.Protocol.DeepNative.RecordDefinitions.Dpd1.MinimumLength), header.Slice(164, 32));
            commitment = MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(header.Slice(76, 16),
                header.Slice(92, 32), header.Slice(124, 32), dpd.CanonicalBytes.Span, header.Slice(236, 2052),
                header.Slice(2288, 32), ephemeralPublic, ratchetPublic);
            if (!Fixed(ephemeralPublic, header.Slice(2384, 32)) || !Fixed(ratchetPublic, header.Slice(2416, 32)) ||
                !Fixed(commitment, header.Slice(2352, 32)))
                throw new CryptographicException("The sealed preclaim secrets and public commitment differ.");
        }
        finally { Zero(commitment); CryptographicOperations.ZeroMemory(ephemeralPublic); CryptographicOperations.ZeroMemory(ratchetPublic); }
    }

    private static byte[] DeriveKey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> header)
    {
        var label = Encoding.ASCII.GetBytes(KeyDomain);
        var input = new byte[label.Length + 1 + header.Length];
        try
        {
            label.CopyTo(input, 0); header.CopyTo(input.AsSpan(label.Length + 1));
            return HMACSHA256.HashData(key, input);
        }
        finally { CryptographicOperations.ZeroMemory(input); CryptographicOperations.ZeroMemory(label); }
    }

    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static void Zero(byte[]? value) { if (value is not null) CryptographicOperations.ZeroMemory(value); }
}
