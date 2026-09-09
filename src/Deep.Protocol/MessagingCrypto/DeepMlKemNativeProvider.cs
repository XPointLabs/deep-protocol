using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Deep.Protocol.MessagingCrypto;

internal sealed class OwnedMlKem768KeyPair : IDisposable
{
    private readonly SecretBuffer _decapsulationKey;
    private readonly byte[] _encapsulationKey;
    private int _disposed;

    internal OwnedMlKem768KeyPair(byte[] encapsulationKey, ReadOnlySpan<byte> decapsulationKey)
    {
        MessagingCryptoValidation.Exact(
            encapsulationKey,
            MessagingCryptoConstants.MlKem768EncapsulationKeySize,
            nameof(encapsulationKey));
        _encapsulationKey = encapsulationKey;
        _decapsulationKey = SecretBuffer.ImportExact(
            decapsulationKey,
            DeepMlKemNativeProvider.CompactDecapsulationKeySize,
            nameof(decapsulationKey));
    }

    internal ReadOnlyMemory<byte> EncapsulationKey
    {
        get
        {
            ThrowIfDisposed();
            return _encapsulationKey.ToArray();
        }
    }

    internal void UseDecapsulationKey(MessagingSecretAction action)
    {
        ThrowIfDisposed();
        _decapsulationKey.Use(action);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _decapsulationKey.Dispose();
        CryptographicOperations.ZeroMemory(_encapsulationKey);
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.ObjectDisposed,
                "The ML-KEM key pair has been disposed.");
    }
}

/// <summary>
/// Dark production-candidate binding for the reviewed Deep ML-KEM C ABI.
/// The release-generated RID allowlist owns path, size, digest and ABI. Assets
/// load only below the trusted package application base; no caller path, PATH
/// search or caller-selected digest is accepted.
/// </summary>
internal sealed class DeepMlKemNativeProvider : IMlKem768Provider, IDisposable
{
    internal const int KeygenRandomSize = 64;
    internal const int CompactDecapsulationKeySize = 64;
    internal const int EncapsulationRandomSize = 32;
    internal const string Identifier = "mlkem-native/v2.0.0/portable-c/deep-abi-v1";

    private const int Ok = 0;
    private const int MaximumStatus = 5;
    private readonly object _gate = new();
    private readonly SafeNativeLibraryHandle _library;
    private readonly SizeFunction _keygenRandomSize;
    private readonly SizeFunction _decapsulationKeySize;
    private readonly SizeFunction _encapsulationKeySize;
    private readonly SizeFunction _encapsulationRandomSize;
    private readonly SizeFunction _ciphertextSize;
    private readonly SizeFunction _sharedSecretSize;
    private readonly KeyPairFunction _keyPairFromRandom;
    private readonly EncapsulateFunction _encapsulate;
    private readonly DecapsulateFunction _decapsulate;
    private readonly ZeroFunction _zero;
    private int _disposed;

    private DeepMlKemNativeProvider(SafeNativeLibraryHandle library)
    {
        _library = library;
        try
        {
            _keygenRandomSize = Export<SizeFunction>("deep_mlkem_v1_keygen_random_size");
            _decapsulationKeySize = Export<SizeFunction>("deep_mlkem_v1_decapsulation_key_size");
            _encapsulationKeySize = Export<SizeFunction>("deep_mlkem_v1_encapsulation_key_size");
            _encapsulationRandomSize = Export<SizeFunction>("deep_mlkem_v1_encapsulation_random_size");
            _ciphertextSize = Export<SizeFunction>("deep_mlkem_v1_ciphertext_size");
            _sharedSecretSize = Export<SizeFunction>("deep_mlkem_v1_shared_secret_size");
            _keyPairFromRandom = Export<KeyPairFunction>("deep_mlkem_v1_keypair_from_random");
            _encapsulate = Export<EncapsulateFunction>("deep_mlkem_v1_encapsulate");
            _decapsulate = Export<DecapsulateFunction>("deep_mlkem_v1_decapsulate");
            _zero = Export<ZeroFunction>("deep_mlkem_v1_zero");
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
            DeepMlKemNativeProviderTestHooks.BeforeValidateAbi();
#endif
            ValidateAbi();
        }
        catch
        {
            throw;
        }
    }

    public string ProviderIdentifier => Identifier;
    public int DecapsulationKeySize => CompactDecapsulationKeySize;

    internal static DeepMlKemNativeProvider LoadApprovedForCurrentProcess()
    {
#if DEEP_MLKEM_ANDROID_PROBE
        var approved = DeepMlKemAndroidProbeApprovedAssets.ForCurrentProcess();
#else
        var approved = DeepMlKemApprovedAssets.ForCurrentProcess();
#endif
        ValidateApprovedAssetIdentity(approved);
        var applicationRoot = Path.GetFullPath(AppContext.BaseDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var path = Path.GetFullPath(Path.Combine(
            applicationRoot,
            approved.RelativePath.Replace('/', Path.DirectorySeparatorChar)));
        var requiredPrefix = applicationRoot + Path.DirectorySeparatorChar;
        if (!path.StartsWith(requiredPrefix, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("The approved ML-KEM asset escaped the application root.");
        RejectReparsePoints(applicationRoot, path);

        using var assetLock = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.SequentialScan);
        Span<byte> before = stackalloc byte[32];
        Span<byte> after = stackalloc byte[32];
        try
        {
            if (assetLock.Length != approved.Bytes)
                throw new CryptographicException("The ML-KEM native asset size is not release-approved.");
            byte[] approvedHash;
            try { approvedHash = Convert.FromHexString(approved.Sha256); }
            catch (FormatException exception)
            {
                throw new CryptographicException("The generated ML-KEM asset digest is invalid.", exception);
            }
            if (approvedHash.Length != 32)
                throw new CryptographicException("The generated ML-KEM asset digest is invalid.");
            SHA256.HashData(assetLock, before);
            assetLock.Position = 0;
            if (!CryptographicOperations.FixedTimeEquals(before, approvedHash))
                throw new CryptographicException("The ML-KEM native asset digest is not release-approved.");

            var handle = new SafeNativeLibraryHandle(NativeLibrary.Load(path));
            try
            {
                SHA256.HashData(assetLock, after);
                if (!CryptographicOperations.FixedTimeEquals(before, after))
                    throw new CryptographicException("The ML-KEM native asset changed while it was loaded.");
                return new DeepMlKemNativeProvider(handle);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(before);
            CryptographicOperations.ZeroMemory(after);
        }
    }

    internal static void ValidateApprovedAssetIdentity(DeepMlKemApprovedAsset approved)
    {
        ArgumentNullException.ThrowIfNull(approved);
        if (!string.Equals(approved.Abi, Identifier, StringComparison.Ordinal))
            throw new CryptographicException("The approved ML-KEM asset has an unexpected ABI identity.");
    }

    internal unsafe OwnedMlKem768KeyPair GenerateKeyPair()
    {
        Span<byte> random = stackalloc byte[KeygenRandomSize];
        var publicKey = new byte[MessagingCryptoConstants.MlKem768EncapsulationKeySize];
        Span<byte> secretKey = stackalloc byte[CompactDecapsulationKeySize];
        try
        {
            RandomNumberGenerator.Fill(random);
            lock (_gate)
            {
                ThrowIfDisposed();
                fixed (byte* randomPointer = random)
                fixed (byte* publicPointer = publicKey)
                fixed (byte* secretPointer = secretKey)
                    EnsureSuccess(_keyPairFromRandom(
                        randomPointer, (nuint)KeygenRandomSize,
                        publicPointer, (nuint)publicKey.Length,
                        secretPointer, (nuint)secretKey.Length));
            }
            return new OwnedMlKem768KeyPair(publicKey, secretKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(publicKey);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
            CryptographicOperations.ZeroMemory(secretKey);
        }
    }

    public unsafe bool EncapsulationKeyMatchesDecapsulationKey(
        ReadOnlySpan<byte> encapsulationKey,
        ReadOnlySpan<byte> decapsulationKey)
    {
        MessagingCryptoValidation.Exact(
            encapsulationKey,
            MessagingCryptoConstants.MlKem768EncapsulationKeySize,
            nameof(encapsulationKey));
        MessagingCryptoValidation.Exact(
            decapsulationKey,
            CompactDecapsulationKeySize,
            nameof(decapsulationKey));
        var derived = new byte[MessagingCryptoConstants.MlKem768EncapsulationKeySize];
        Span<byte> ignoredSecret = stackalloc byte[CompactDecapsulationKeySize];
        try
        {
            lock (_gate)
            {
                ThrowIfDisposed();
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
                DeepMlKemNativeProviderTestHooks.BeforeNativeCall();
#endif
                fixed (byte* randomPointer = decapsulationKey)
                fixed (byte* publicPointer = derived)
                fixed (byte* secretPointer = ignoredSecret)
                    EnsureSuccess(_keyPairFromRandom(
                        randomPointer, (nuint)decapsulationKey.Length,
                        publicPointer, (nuint)derived.Length,
                        secretPointer, (nuint)ignoredSecret.Length));
            }
            return CryptographicOperations.FixedTimeEquals(encapsulationKey, derived);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derived);
            CryptographicOperations.ZeroMemory(ignoredSecret);
        }
    }

    public unsafe void Encapsulate(
        ReadOnlySpan<byte> encapsulationKey,
        Span<byte> ciphertext,
        Span<byte> sharedSecret)
    {
        ciphertext.Clear();
        sharedSecret.Clear();
        MessagingCryptoValidation.Exact(
            encapsulationKey,
            MessagingCryptoConstants.MlKem768EncapsulationKeySize,
            nameof(encapsulationKey));
        MessagingCryptoValidation.Exact(
            ciphertext,
            MessagingCryptoConstants.MlKem768CiphertextSize,
            nameof(ciphertext));
        MessagingCryptoValidation.Exact(
            sharedSecret,
            MessagingCryptoConstants.MlKem768SharedSecretSize,
            nameof(sharedSecret));
        Span<byte> random = stackalloc byte[EncapsulationRandomSize];
        try
        {
            RejectOverlap(encapsulationKey, ciphertext, sharedSecret);
            RandomNumberGenerator.Fill(random);
            lock (_gate)
            {
                ThrowIfDisposed();
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
                DeepMlKemNativeProviderTestHooks.BeforeNativeCall();
#endif
                fixed (byte* publicPointer = encapsulationKey)
                fixed (byte* randomPointer = random)
                fixed (byte* ciphertextPointer = ciphertext)
                fixed (byte* secretPointer = sharedSecret)
                    EnsureSuccess(_encapsulate(
                        publicPointer, (nuint)encapsulationKey.Length,
                        randomPointer, (nuint)random.Length,
                        ciphertextPointer, (nuint)ciphertext.Length,
                        secretPointer, (nuint)sharedSecret.Length));
            }
        }
        catch
        {
            ciphertext.Clear();
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
        }
    }

    public unsafe void Decapsulate(
        ReadOnlySpan<byte> decapsulationKey,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> sharedSecret)
    {
        sharedSecret.Clear();
        MessagingCryptoValidation.Exact(decapsulationKey, CompactDecapsulationKeySize, nameof(decapsulationKey));
        MessagingCryptoValidation.Exact(
            ciphertext,
            MessagingCryptoConstants.MlKem768CiphertextSize,
            nameof(ciphertext));
        MessagingCryptoValidation.Exact(
            sharedSecret,
            MessagingCryptoConstants.MlKem768SharedSecretSize,
            nameof(sharedSecret));
        if (decapsulationKey.Overlaps(ciphertext) ||
            decapsulationKey.Overlaps(sharedSecret) || ciphertext.Overlaps(sharedSecret))
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "ML-KEM input and output buffers must not overlap.");

        try
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                fixed (byte* keyPointer = decapsulationKey)
                fixed (byte* ciphertextPointer = ciphertext)
                fixed (byte* secretPointer = sharedSecret)
                    EnsureSuccess(_decapsulate(
                        keyPointer, (nuint)decapsulationKey.Length,
                        ciphertextPointer, (nuint)ciphertext.Length,
                        secretPointer, (nuint)sharedSecret.Length));
            }
        }
        catch
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        lock (_gate)
        {
            _library.Dispose();
        }
    }

    private T Export<T>(string name) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(
            NativeLibrary.GetExport(_library.DangerousGetHandle(), name));

    private void ValidateAbi()
    {
        if (_keygenRandomSize() != KeygenRandomSize ||
            _decapsulationKeySize() != CompactDecapsulationKeySize ||
            _encapsulationKeySize() != MessagingCryptoConstants.MlKem768EncapsulationKeySize ||
            _encapsulationRandomSize() != EncapsulationRandomSize ||
            _ciphertextSize() != MessagingCryptoConstants.MlKem768CiphertextSize ||
            _sharedSecretSize() != MessagingCryptoConstants.MlKem768SharedSecretSize)
            throw new CryptographicException("The native ML-KEM ABI reports unexpected parameter sizes.");

        Span<byte> probe = stackalloc byte[1] { 0xa5 };
        unsafe
        {
            fixed (byte* pointer = probe)
                EnsureSuccess(_zero(pointer, 1u));
        }
        if (probe[0] != 0)
            throw new CryptographicException("The native ML-KEM zeroization primitive failed its load-time probe.");
    }

    private static void RejectOverlap(
        ReadOnlySpan<byte> input,
        Span<byte> firstOutput,
        Span<byte> secondOutput)
    {
        if (input.Overlaps(firstOutput) || input.Overlaps(secondOutput) || firstOutput.Overlaps(secondOutput))
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "ML-KEM input and output buffers must not overlap.");
    }

    private static void EnsureSuccess(int status)
    {
        if (status == Ok) return;
        var detail = status is > Ok and <= MaximumStatus ? status : -1;
        throw new MessagingCryptoException(
            MessagingCryptoError.ProviderFailure,
            $"The ML-KEM provider rejected the operation (closed status {detail}).");
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0 || _library.IsInvalid || _library.IsClosed)
            throw new MessagingCryptoException(
                MessagingCryptoError.ObjectDisposed,
                "The ML-KEM provider has been disposed.");
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint SizeFunction();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int KeyPairFunction(
        byte* random, nuint randomLength,
        byte* encapsulationKey, nuint encapsulationKeyLength,
        byte* decapsulationKey, nuint decapsulationKeyLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int EncapsulateFunction(
        byte* encapsulationKey, nuint encapsulationKeyLength,
        byte* random, nuint randomLength,
        byte* ciphertext, nuint ciphertextLength,
        byte* sharedSecret, nuint sharedSecretLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int DecapsulateFunction(
        byte* decapsulationKey, nuint decapsulationKeyLength,
        byte* ciphertext, nuint ciphertextLength,
        byte* sharedSecret, nuint sharedSecretLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int ZeroFunction(byte* buffer, nuint bufferLength);

    private static void RejectReparsePoints(string applicationRoot, string assetPath)
    {
        var current = applicationRoot;
        if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            throw new CryptographicException("The ML-KEM application root must not be a reparse point.");
        var relative = Path.GetRelativePath(applicationRoot, assetPath);
        foreach (var segment in relative.Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException("The ML-KEM asset path must not contain reparse points.");
        }
    }

    private sealed class SafeNativeLibraryHandle : SafeHandle
    {
        internal SafeNativeLibraryHandle(nint handle) : base(0, true) => SetHandle(handle);
        public override bool IsInvalid => handle == 0 || handle == -1;

        protected override bool ReleaseHandle()
        {
            NativeLibrary.Free(handle);
            handle = 0;
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
            DeepMlKemNativeProviderTestHooks.HandleReleased();
#endif
            return true;
        }
    }
}

/// <summary>
/// Production-owned dark composition boundary. It owns the exact approved
/// provider and never accepts an IMlKem768Provider from its caller. The generic
/// provider seam remains available only to internal dark protocol tests.
/// </summary>
internal sealed class DeepMlKemProductionRuntime : IDisposable
{
    private readonly DeepMlKemNativeProvider _provider;

    private DeepMlKemProductionRuntime(DeepMlKemNativeProvider provider) => _provider = provider;

    internal static DeepMlKemProductionRuntime CreateApprovedForCurrentProcess() =>
        new(DeepMlKemNativeProvider.LoadApprovedForCurrentProcess());

    internal OwnedMlKem768KeyPair GenerateKeyPair() => _provider.GenerateKeyPair();

    internal PreparedHybridInitiation PrepareInitiation(
        HybridInitiatorKeyMaterial initiator,
        ReadOnlySpan<byte> responderIdentityPublic,
        ReadOnlySpan<byte> responderSignedPreKeyPublic,
        ReadOnlySpan<byte> responderOneTimePreKeyPublic,
        ReadOnlySpan<byte> responderMlKemEncapsulationKey) =>
        HybridPreKeyHandshake.PrepareInitiation(
            initiator,
            responderIdentityPublic,
            responderSignedPreKeyPublic,
            responderOneTimePreKeyPublic,
            responderMlKemEncapsulationKey,
            _provider);

    internal HybridHandshakeSecrets AcceptInitiation(
        HybridResponderStaticKeyMaterial responder,
        ClaimedHybridPreKeyLease claimedPreKeys,
        ReadOnlySpan<byte> initiatorIdentityPublic,
        ReadOnlySpan<byte> initiatorEphemeralPublic,
        VerifiedHybridTranscriptCapability verifiedTranscript) =>
        HybridPreKeyHandshake.AcceptInitiation(
            responder,
            claimedPreKeys,
            initiatorIdentityPublic,
            initiatorEphemeralPublic,
            verifiedTranscript,
            _provider);

    public void Dispose() => _provider.Dispose();
}

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
internal static class DeepMlKemNativeProviderTestHooks
{
    private static readonly object Sync = new();
    private static HookSet? _current;

    internal static IDisposable Install(
        Action? beforeNativeCall = null,
        Action? beforeValidateAbi = null,
        Action? handleReleased = null)
    {
        var hooks = new HookSet(beforeNativeCall, beforeValidateAbi, handleReleased);
        lock (Sync)
        {
            if (_current is not null)
                throw new InvalidOperationException("Deep ML-KEM test hooks are already installed.");
            _current = hooks;
        }
        return new HookLease(hooks);
    }

    internal static void BeforeNativeCall() => Snapshot()?.BeforeNativeCall?.Invoke();
    internal static void BeforeValidateAbi() => Snapshot()?.BeforeValidateAbi?.Invoke();
    internal static void HandleReleased() => Snapshot()?.HandleReleased?.Invoke();

    private static HookSet? Snapshot()
    {
        lock (Sync) return _current;
    }

    private sealed record HookSet(
        Action? BeforeNativeCall,
        Action? BeforeValidateAbi,
        Action? HandleReleased);

    private sealed class HookLease(HookSet hooks) : IDisposable
    {
        private HookSet? _hooks = hooks;

        public void Dispose()
        {
            var owned = Interlocked.Exchange(ref _hooks, null);
            if (owned is null) return;
            lock (Sync)
            {
                if (ReferenceEquals(_current, owned)) _current = null;
            }
        }
    }
}
#endif
