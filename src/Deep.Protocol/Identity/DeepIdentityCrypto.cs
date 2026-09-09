using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Deep.Protocol.Identity;

/// <summary>
/// Protocol-owned derivation and validation for independent identity keys.
/// Secret inputs are never returned and Ed25519/X25519 key conversion is not supported.
/// </summary>
public static class DeepIdentityCrypto
{
    public const int Ed25519SeedSize = 32;
    public const int Ed25519PublicKeySize = 32;
    public const int X25519PrivateKeySize = 32;
    public const int X25519PublicKeySize = 32;

    public static byte[] DeriveEd25519PublicKey(ReadOnlySpan<byte> seed)
    {
        ValidateSecret(seed, Ed25519SeedSize, nameof(seed), "Ed25519 seed");

        var publicKey = new byte[Ed25519PublicKeySize];
        Span<byte> temporarySecretKey = stackalloc byte[OwnedSodiumEd25519.SecretKeySize];
        OwnedSodiumEd25519.DerivePublicKey(seed, publicKey, temporarySecretKey);
        return publicKey;
    }

    public static bool Ed25519PublicKeyMatchesSeed(
        ReadOnlySpan<byte> seed,
        ReadOnlySpan<byte> expectedPublicKey)
    {
        ValidateSecret(seed, Ed25519SeedSize, nameof(seed), "Ed25519 seed");
        ValidatePublicKey(
            expectedPublicKey,
            Ed25519PublicKeySize,
            nameof(expectedPublicKey),
            "Ed25519 public key");

        Span<byte> actualPublicKey = stackalloc byte[Ed25519PublicKeySize];
        Span<byte> temporarySecretKey = stackalloc byte[OwnedSodiumEd25519.SecretKeySize];
        try
        {
            OwnedSodiumEd25519.DerivePublicKey(seed, actualPublicKey, temporarySecretKey);
            return CryptographicOperations.FixedTimeEquals(actualPublicKey, expectedPublicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualPublicKey);
        }
    }

    public static byte[] DeriveX25519PublicKey(ReadOnlySpan<byte> privateScalar)
    {
        ValidateSecret(privateScalar, X25519PrivateKeySize, nameof(privateScalar), "X25519 private scalar");

        var publicKey = new byte[X25519PublicKeySize];
        OwnedSodiumX25519.DerivePublicKey(privateScalar, publicKey);
        return publicKey;
    }

    public static bool X25519PublicKeyMatchesPrivateScalar(
        ReadOnlySpan<byte> privateScalar,
        ReadOnlySpan<byte> expectedPublicKey)
    {
        ValidateSecret(
            privateScalar,
            X25519PrivateKeySize,
            nameof(privateScalar),
            "X25519 private scalar");
        ValidatePublicKey(
            expectedPublicKey,
            X25519PublicKeySize,
            nameof(expectedPublicKey),
            "X25519 public key");

        Span<byte> actualPublicKey = stackalloc byte[X25519PublicKeySize];
        try
        {
            OwnedSodiumX25519.DerivePublicKey(privateScalar, actualPublicKey);
            return CryptographicOperations.FixedTimeEquals(actualPublicKey, expectedPublicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualPublicKey);
        }
    }

    private static void ValidateSecret(ReadOnlySpan<byte> value, int size, string name, string description)
    {
        if (value.Length != size)
        {
            throw new ArgumentException($"{description} must contain exactly {size} bytes.", name);
        }

        if (IsAllZero(value))
        {
            throw new ArgumentException($"{description} must be non-zero.", name);
        }
    }

    private static void ValidatePublicKey(ReadOnlySpan<byte> value, int size, string name, string description)
    {
        if (value.Length != size)
        {
            throw new ArgumentException($"{description} must contain exactly {size} bytes.", name);
        }

        if (IsAllZero(value))
        {
            throw new ArgumentException($"{description} must be non-zero.", name);
        }
    }

    internal static bool IsAllZero(ReadOnlySpan<byte> value)
    {
        var combined = 0;
        foreach (var item in value)
        {
            combined |= item;
        }

        return combined == 0;
    }
}

internal static class OwnedSodiumEd25519
{
    internal const int PublicKeySize = 32;
    internal const int SecretKeySize = 64;
    internal const int SignatureSize = 64;

    internal static void DerivePublicKey(
        ReadOnlySpan<byte> seed,
        Span<byte> publicKey,
        Span<byte> temporarySecretKey)
    {
        try
        {
            ValidateBuffers(seed, publicKey, temporarySecretKey);
            publicKey.Clear();
            temporarySecretKey.Clear();
            SodiumIdentityNative.EnsureInitialized();
            if (SodiumIdentityNative.Ed25519SeedKeyPair(publicKey, temporarySecretKey, seed) != 0
                || DeepIdentityCrypto.IsAllZero(publicKey))
            {
                publicKey.Clear();
                throw new CryptographicException("libsodium failed to derive an Ed25519 public key.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(temporarySecretKey);
        }
    }

    internal static void SignDetached(
        ReadOnlySpan<byte> seed,
        ReadOnlySpan<byte> message,
        Span<byte> signature,
        Span<byte> temporaryPublicKey,
        Span<byte> temporarySecretKey)
    {
        try
        {
            ValidateBuffers(seed, temporaryPublicKey, temporarySecretKey);
            if (message.IsEmpty)
            {
                throw new ArgumentException("The Ed25519 message must be non-empty.", nameof(message));
            }
            if (signature.Length != SignatureSize)
            {
                throw new ArgumentException($"Ed25519 signature output must contain exactly {SignatureSize} bytes.", nameof(signature));
            }

            signature.Clear();
            temporaryPublicKey.Clear();
            temporarySecretKey.Clear();
            SodiumIdentityNative.EnsureInitialized();
            if (SodiumIdentityNative.Ed25519SeedKeyPair(temporaryPublicKey, temporarySecretKey, seed) != 0
                || DeepIdentityCrypto.IsAllZero(temporaryPublicKey)
                || SodiumIdentityNative.Ed25519SignDetached(signature, message, temporarySecretKey) != 0
                || DeepIdentityCrypto.IsAllZero(signature))
            {
                signature.Clear();
                throw new CryptographicException("libsodium failed to create an Ed25519 signature.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(temporarySecretKey);
            CryptographicOperations.ZeroMemory(temporaryPublicKey);
        }
    }

    private static void ValidateBuffers(
        ReadOnlySpan<byte> seed,
        Span<byte> publicKey,
        Span<byte> temporarySecretKey)
    {
        if (seed.Length != DeepIdentityCrypto.Ed25519SeedSize || DeepIdentityCrypto.IsAllZero(seed))
        {
            throw new ArgumentException("Ed25519 seed must be a non-zero 32-byte value.", nameof(seed));
        }
        if (publicKey.Length != PublicKeySize)
        {
            throw new ArgumentException($"Ed25519 public-key output must contain exactly {PublicKeySize} bytes.", nameof(publicKey));
        }
        if (temporarySecretKey.Length != SecretKeySize)
        {
            throw new ArgumentException($"Ed25519 temporary secret-key buffer must contain exactly {SecretKeySize} bytes.", nameof(temporarySecretKey));
        }
    }
}

internal static class OwnedSodiumX25519
{
    internal static void DerivePublicKey(ReadOnlySpan<byte> privateScalar, Span<byte> publicKey)
    {
        if (privateScalar.Length != DeepIdentityCrypto.X25519PrivateKeySize
            || DeepIdentityCrypto.IsAllZero(privateScalar))
        {
            throw new ArgumentException("X25519 private scalar must be a non-zero 32-byte value.", nameof(privateScalar));
        }
        if (publicKey.Length != DeepIdentityCrypto.X25519PublicKeySize)
        {
            throw new ArgumentException("X25519 public-key output must contain exactly 32 bytes.", nameof(publicKey));
        }

        publicKey.Clear();
        SodiumIdentityNative.EnsureInitialized();
        if (SodiumIdentityNative.X25519Base(publicKey, privateScalar) != 0
            || DeepIdentityCrypto.IsAllZero(publicKey))
        {
            publicKey.Clear();
            throw new CryptographicException("libsodium failed to derive an X25519 public key.");
        }
    }

    internal static void Agree(
        ReadOnlySpan<byte> privateScalar,
        ReadOnlySpan<byte> peerPublicKey,
        Span<byte> sharedSecret)
    {
        if (privateScalar.Length != DeepIdentityCrypto.X25519PrivateKeySize
            || DeepIdentityCrypto.IsAllZero(privateScalar))
        {
            throw new ArgumentException("X25519 private scalar must be a non-zero 32-byte value.", nameof(privateScalar));
        }
        if (peerPublicKey.Length != DeepIdentityCrypto.X25519PublicKeySize
            || DeepIdentityCrypto.IsAllZero(peerPublicKey))
        {
            throw new ArgumentException("X25519 peer public key must be a non-zero 32-byte value.", nameof(peerPublicKey));
        }
        if (sharedSecret.Length != DeepIdentityCrypto.X25519PublicKeySize)
        {
            throw new ArgumentException("X25519 shared-secret output must contain exactly 32 bytes.", nameof(sharedSecret));
        }

        sharedSecret.Clear();
        SodiumIdentityNative.EnsureInitialized();
        if (SodiumIdentityNative.X25519(sharedSecret, privateScalar, peerPublicKey) != 0
            || DeepIdentityCrypto.IsAllZero(sharedSecret))
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw new CryptographicException("libsodium rejected the X25519 agreement.");
        }
    }
}

internal static class SodiumIdentityNative
{
    private const string LibraryName = "libsodium";
    private static readonly int InitializationResult = SodiumInit();

    internal static void EnsureInitialized()
    {
        if (InitializationResult < 0)
        {
            throw new CryptographicException("libsodium initialization failed.");
        }
    }

    internal static int Ed25519SeedKeyPair(
        Span<byte> publicKey,
        Span<byte> secretKey,
        ReadOnlySpan<byte> seed)
    {
        ref var publicKeyReference = ref MemoryMarshal.GetReference(publicKey);
        ref var secretKeyReference = ref MemoryMarshal.GetReference(secretKey);
        ref var seedReference = ref MemoryMarshal.GetReference(seed);
        return CryptoSignEd25519SeedKeyPair(
            ref publicKeyReference,
            ref secretKeyReference,
            ref seedReference);
    }

    internal static int Ed25519SignDetached(
        Span<byte> signature,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> secretKey)
    {
        ref var signatureReference = ref MemoryMarshal.GetReference(signature);
        ref var messageReference = ref MemoryMarshal.GetReference(message);
        ref var secretKeyReference = ref MemoryMarshal.GetReference(secretKey);
        return CryptoSignEd25519Detached(
            ref signatureReference,
            IntPtr.Zero,
            ref messageReference,
            checked((ulong)message.Length),
            ref secretKeyReference);
    }

    internal static int X25519Base(Span<byte> publicKey, ReadOnlySpan<byte> privateScalar)
    {
        ref var publicKeyReference = ref MemoryMarshal.GetReference(publicKey);
        ref var privateScalarReference = ref MemoryMarshal.GetReference(privateScalar);
        return CryptoScalarMultCurve25519Base(ref publicKeyReference, ref privateScalarReference);
    }

    internal static int X25519(
        Span<byte> sharedSecret,
        ReadOnlySpan<byte> privateScalar,
        ReadOnlySpan<byte> peerPublicKey)
    {
        ref var sharedSecretReference = ref MemoryMarshal.GetReference(sharedSecret);
        ref var privateScalarReference = ref MemoryMarshal.GetReference(privateScalar);
        ref var peerPublicKeyReference = ref MemoryMarshal.GetReference(peerPublicKey);
        return CryptoScalarMultCurve25519(
            ref sharedSecretReference,
            ref privateScalarReference,
            ref peerPublicKeyReference);
    }

    [DllImport(LibraryName, EntryPoint = "sodium_init", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int SodiumInit();

    [DllImport(LibraryName, EntryPoint = "crypto_sign_ed25519_seed_keypair", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int CryptoSignEd25519SeedKeyPair(
        ref byte publicKey,
        ref byte secretKey,
        ref byte seed);

    [DllImport(LibraryName, EntryPoint = "crypto_sign_ed25519_detached", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int CryptoSignEd25519Detached(
        ref byte signature,
        IntPtr signatureLength,
        ref byte message,
        ulong messageLength,
        ref byte secretKey);

    [DllImport(LibraryName, EntryPoint = "crypto_scalarmult_curve25519_base", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int CryptoScalarMultCurve25519Base(
        ref byte publicKey,
        ref byte privateScalar);

    [DllImport(LibraryName, EntryPoint = "crypto_scalarmult_curve25519", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int CryptoScalarMultCurve25519(
        ref byte sharedSecret,
        ref byte privateScalar,
        ref byte peerPublicKey);
}
