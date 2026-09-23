using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Deep.Protocol.ApplicationCore;

internal sealed record DeepMlDsa65CandidateAsset(
    string RelativePath, long Bytes, string Sha256);

/// <summary>
/// Candidate bits tied to native-mldsa-candidate CI run 35858379369 and the
/// physical Android API 31 probe. These are not a release approval.
/// </summary>
internal static class DeepMlDsa65CandidateAssets
{
    internal static DeepMlDsa65CandidateAsset ForCurrentProcess()
    {
        if (OperatingSystem.IsWindows() &&
            RuntimeInformation.ProcessArchitecture == Architecture.X64)
            return new("runtimes/win-x64/native/deep_mldsa.dll", 139264,
                "ee20d61aa6b0acbd048fbe9f2554b344657bfe6c412ebb7be6dd5632ea14e7d5");
        if (OperatingSystem.IsWindows() &&
            RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
            return new("runtimes/win-arm64/native/deep_mldsa.dll", 162816,
                "e9595b899e85ebf489f2b27d00ba8bf04fb33c4deb91806c4d8f8df97de1e9d3");
        if (OperatingSystem.IsAndroid() &&
            RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
            return new("runtimes/android-arm64/native/libdeep_mldsa.so", 79112,
                "6e46e4df970f5376416af3c50fb39e580487a616d2541aa26d1d90eddf918cc9");
        throw new PlatformNotSupportedException(
            "No checked Deep ML-DSA candidate asset exists for this process RID.");
    }
}

/// <summary>
/// Narrow, exact-asset native binding. It does not persist an expanded private
/// key; callers retain the 32-byte seed only in protected account storage.
/// </summary>
internal sealed unsafe class DeepMlDsa65NativeProvider : IDeepMlDsa65Verifier, IDisposable
{
    internal const int SeedSize = 32;
    internal const int PublicKeySize = 1952;
    internal const int SignatureSize = 3309;
    private readonly object gate = new();
    private readonly SafeNativeLibraryHandle library;
    private readonly SizeFunction seedSize;
    private readonly SizeFunction publicKeySize;
    private readonly SizeFunction signatureSize;
    private readonly SizeFunction signRandomSize;
    private readonly PublicFromSeedFunction publicFromSeed;
    private readonly SignFromSeedFunction signFromSeed;
    private readonly VerifyFunction verify;
    private readonly ZeroFunction zero;
    private bool disposed;

    private DeepMlDsa65NativeProvider(SafeNativeLibraryHandle library)
    {
        this.library = library;
        seedSize = Export<SizeFunction>("deep_mldsa_v1_seed_size");
        publicKeySize = Export<SizeFunction>("deep_mldsa_v1_public_key_size");
        signatureSize = Export<SizeFunction>("deep_mldsa_v1_signature_size");
        signRandomSize = Export<SizeFunction>("deep_mldsa_v1_sign_random_size");
        publicFromSeed = Export<PublicFromSeedFunction>("deep_mldsa_v1_public_from_seed");
        signFromSeed = Export<SignFromSeedFunction>("deep_mldsa_v1_sign_from_seed");
        verify = Export<VerifyFunction>("deep_mldsa_v1_verify");
        zero = Export<ZeroFunction>("deep_mldsa_v1_zero");
        if (seedSize() != SeedSize || publicKeySize() != PublicKeySize ||
            signatureSize() != SignatureSize || signRandomSize() != SeedSize)
            throw new CryptographicException("The Deep ML-DSA candidate ABI reports unexpected sizes.");
        Span<byte> zeroProbe = stackalloc byte[1] { 0xa5 };
        fixed (byte* pointer = zeroProbe)
        {
            if (zero(pointer, 1) != 0 || zeroProbe[0] != 0)
                throw new CryptographicException("The Deep ML-DSA native zeroization probe failed.");
        }
    }

    internal static DeepMlDsa65NativeProvider LoadCandidateForCurrentProcess()
    {
        var asset = DeepMlDsa65CandidateAssets.ForCurrentProcess();
        var root = Path.GetFullPath(AppContext.BaseDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var path = Path.GetFullPath(Path.Combine(
            root, asset.RelativePath.Replace('/', Path.DirectorySeparatorChar)));
        if (!path.StartsWith(root + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("The ML-DSA native asset escaped the application root.");
        RejectReparsePoints(root, path);
        using var assetLock = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.SequentialScan);
        if (assetLock.Length != asset.Bytes)
            throw new CryptographicException("The ML-DSA native asset size differs from build evidence.");
        Span<byte> before = stackalloc byte[32];
        Span<byte> after = stackalloc byte[32];
        var approvedHash = Convert.FromHexString(asset.Sha256);
        try
        {
            SHA256.HashData(assetLock, before);
            if (!CryptographicOperations.FixedTimeEquals(before, approvedHash))
                throw new CryptographicException("The ML-DSA native asset digest differs from build evidence.");
            assetLock.Position = 0;
            var handle = new SafeNativeLibraryHandle(NativeLibrary.Load(path));
            try
            {
                SHA256.HashData(assetLock, after);
                if (!CryptographicOperations.FixedTimeEquals(before, after))
                    throw new CryptographicException("The ML-DSA native asset changed while loading.");
                return new DeepMlDsa65NativeProvider(handle);
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
            CryptographicOperations.ZeroMemory(approvedHash);
        }
    }

    internal byte[] DerivePublicKey(ReadOnlySpan<byte> seed32)
    {
        RequireSeed(seed32);
        var publicKey = new byte[PublicKeySize];
        lock (gate)
        {
            ThrowIfDisposed();
            fixed (byte* seedPointer = seed32)
            fixed (byte* publicPointer = publicKey)
            {
                if (publicFromSeed(seedPointer, SeedSize, publicPointer, PublicKeySize) != 0)
                {
                    CryptographicOperations.ZeroMemory(publicKey);
                    throw new CryptographicException("Deep ML-DSA public-key derivation failed closed.");
                }
            }
        }
        return publicKey;
    }

    internal byte[] Sign(
        ReadOnlySpan<byte> seed32, ReadOnlySpan<byte> context,
        ReadOnlySpan<byte> message)
    {
        RequireSeed(seed32);
        if (context.IsEmpty || context.Length > 255 || message.IsEmpty || message.Length > 65535)
            throw new ArgumentException("Deep ML-DSA context/message length is outside the closed profile.");
        Span<byte> randomness = stackalloc byte[SeedSize];
        var signature = new byte[SignatureSize];
        try
        {
            RandomNumberGenerator.Fill(randomness);
            lock (gate)
            {
                ThrowIfDisposed();
                fixed (byte* seedPointer = seed32)
                fixed (byte* randomPointer = randomness)
                fixed (byte* contextPointer = context)
                fixed (byte* messagePointer = message)
                fixed (byte* signaturePointer = signature)
                {
                    if (signFromSeed(seedPointer, SeedSize, randomPointer, SeedSize,
                            contextPointer, (nuint)context.Length,
                            messagePointer, (nuint)message.Length,
                            signaturePointer, SignatureSize) != 0)
                    {
                        CryptographicOperations.ZeroMemory(signature);
                        throw new CryptographicException("Deep ML-DSA signing failed closed.");
                    }
                }
            }
            return signature;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(randomness);
        }
    }

    public bool Verify(ReadOnlySpan<byte> publicKey1952, ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature3309)
    {
        if (publicKey1952.Length != PublicKeySize || signature3309.Length != SignatureSize ||
            context.IsEmpty || context.Length > 255 || message.IsEmpty || message.Length > 65535)
            return false;
        lock (gate)
        {
            ThrowIfDisposed();
            fixed (byte* publicPointer = publicKey1952)
            fixed (byte* contextPointer = context)
            fixed (byte* messagePointer = message)
            fixed (byte* signaturePointer = signature3309)
            {
                var status = verify(publicPointer, PublicKeySize,
                    contextPointer, (nuint)context.Length,
                    messagePointer, (nuint)message.Length,
                    signaturePointer, SignatureSize);
                if (status == 0) return true;
                if (status == 4) return false;
                throw new CryptographicException($"Deep ML-DSA verification failed closed ({status}).");
            }
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            library.Dispose();
        }
    }

    private T Export<T>(string name) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(
            NativeLibrary.GetExport(library.DangerousGetHandle(), name));

    private void ThrowIfDisposed()
    {
        if (disposed || library.IsClosed || library.IsInvalid)
            throw new ObjectDisposedException(nameof(DeepMlDsa65NativeProvider));
    }

    private static void RequireSeed(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != SeedSize || Deep.Protocol.Identity.DeepIdentityCrypto.IsAllZero(seed))
            throw new ArgumentException("Deep ML-DSA seed must be a nonzero 32-byte value.", nameof(seed));
    }

    private static void RejectReparsePoints(string root, string path)
    {
        var current = root;
        if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            throw new CryptographicException("The ML-DSA application root is a reparse point.");
        foreach (var segment in Path.GetRelativePath(root, path).Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException("The ML-DSA asset path contains a reparse point.");
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint SizeFunction();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int PublicFromSeedFunction(
        byte* seed, nuint seedLength, byte* publicKey, nuint publicKeyLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int SignFromSeedFunction(
        byte* seed, nuint seedLength, byte* random, nuint randomLength,
        byte* context, nuint contextLength, byte* message, nuint messageLength,
        byte* signature, nuint signatureLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int VerifyFunction(
        byte* publicKey, nuint publicKeyLength, byte* context, nuint contextLength,
        byte* message, nuint messageLength, byte* signature, nuint signatureLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int ZeroFunction(byte* buffer, nuint bufferLength);

    private sealed class SafeNativeLibraryHandle : SafeHandle
    {
        internal SafeNativeLibraryHandle(nint nativeHandle) : base(0, true) => SetHandle(nativeHandle);
        public override bool IsInvalid => handle == 0 || handle == -1;
        protected override bool ReleaseHandle()
        {
            NativeLibrary.Free(handle);
            handle = 0;
            return true;
        }
    }
}
