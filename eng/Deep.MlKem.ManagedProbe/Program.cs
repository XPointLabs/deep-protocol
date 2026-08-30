using System.Reflection;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal static class Program
{
    private const int Ok = 0;
    private const int InvalidLength = 2;
    private const int InvalidPublicKey = 4;

    private static readonly string[] ExpectedExports =
    [
        "deep_mlkem_v1_keygen_random_size",
        "deep_mlkem_v1_decapsulation_key_size",
        "deep_mlkem_v1_encapsulation_key_size",
        "deep_mlkem_v1_encapsulation_random_size",
        "deep_mlkem_v1_ciphertext_size",
        "deep_mlkem_v1_shared_secret_size",
        "deep_mlkem_v1_keypair_from_random",
        "deep_mlkem_v1_encapsulate",
        "deep_mlkem_v1_decapsulate",
        "deep_mlkem_v1_zero"
    ];

    private static readonly byte[] Seed = Convert.FromHexString(
        "934D60B35624D740B30A7F227AF2AE7C678E4E04E13C5F509EADE2B79AEA77E2" +
        "3E2A2EA6C9C476FC4937B013C993A793D6C0AB9960695BA838F649DA539CA3D0");

    private static readonly byte[] EncapsulationRandom = Convert.FromHexString(
        "934D60B35624D740B30A7F227AF2AE7C678E4E04E13C5F509EADE2B79AEA77E2");

    private static readonly byte[] ExpectedShared = Convert.FromHexString(
        "0B1B32BE26247CBCBE0916F8B0B729699C32A96D51EFA4A4CD5B289239C8207E");

    private static readonly byte[] ExpectedRejected = Convert.FromHexString(
        "7C1FB93A17533023688DF83E8842ABC55A8AC0E6B8FF7C85DBD3D0A67D8255B4");

    public static int Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("Usage: Deep.MlKem.ManagedProbe <absolute-path-to-deep_mlkem.dll>");
            return 2;
        }

        try
        {
            NativeMethods.Initialize(Path.GetFullPath(args[0]));
            CheckLoadAndKnownExportSurface();
            CheckSizes();
            CheckKnownAnswerAndRoundTrip();
            CheckInvalidPublicKeyFailure();
            CheckImplicitRejection();
            CheckNativeAndOwnedZeroization();
            Console.WriteLine("Deep ML-KEM managed runtime ABI probe passed.");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
        finally
        {
            NativeMethods.Shutdown();
            CryptographicOperations.ZeroMemory(Seed);
            CryptographicOperations.ZeroMemory(EncapsulationRandom);
        }
    }

    private static void CheckLoadAndKnownExportSurface()
    {
        foreach (string export in ExpectedExports)
        {
            Check(NativeMethods.HasExport(export), $"missing Deep export: {export}");
        }

        foreach (string forbidden in new[]
        {
            "mlkem768_keypair_derand",
            "mlkem768_enc_derand",
            "mlkem768_dec",
            "deep_vendor_mlkem768_keypair_derand",
            "deep_mlkem_provider_zeroize"
        })
        {
            Check(!NativeMethods.HasExport(forbidden), $"provider symbol escaped runtime ABI: {forbidden}");
        }
    }

    private static void CheckSizes()
    {
        Check(NativeMethods.KeygenRandomSize() == 64, "keygen random size");
        Check(NativeMethods.DecapsulationKeySize() == 64, "decapsulation key size");
        Check(NativeMethods.EncapsulationKeySize() == 1184, "encapsulation key size");
        Check(NativeMethods.EncapsulationRandomSize() == 32, "encapsulation random size");
        Check(NativeMethods.CiphertextSize() == 1088, "ciphertext size");
        Check(NativeMethods.SharedSecretSize() == 32, "shared-secret size");
    }

    private static void CheckKnownAnswerAndRoundTrip()
    {
        using MlKemKeyPair keyPair = MlKemProvider.KeyPairFromRandom(Seed);
        Check(CryptographicOperations.FixedTimeEquals(keyPair.Secret.Bytes, Seed), "compact d||z KAT");
        CheckSha256(keyPair.PublicKey.Span, "C45A699A9EFCB1A799578CE95F24B063B0B9DDC0879AFDB3967FD9E1E3E8C247", "public-key KAT");

        using MlKemEncapsulation encapsulation = MlKemProvider.Encapsulate(keyPair.PublicKey, EncapsulationRandom);
        CheckSha256(encapsulation.Ciphertext.Span, "0B99B2AF81971943E4EF6E6F17F42BE4F3CAA9FEA18DA0F63DF1D43639A74743", "ciphertext KAT");
        Check(CryptographicOperations.FixedTimeEquals(encapsulation.Secret.Bytes, ExpectedShared), "encapsulation secret KAT");

        using OwnedSecret decapsulated = MlKemProvider.Decapsulate(keyPair.Secret, encapsulation.Ciphertext);
        Check(CryptographicOperations.FixedTimeEquals(decapsulated.Bytes, ExpectedShared), "decapsulation KAT/roundtrip");
    }

    private static unsafe void CheckInvalidPublicKeyFailure()
    {
        using MlKemKeyPair keyPair = MlKemProvider.KeyPairFromRandom(Seed);
        byte[] invalidKey = keyPair.PublicKey.ToArray();
        invalidKey[0] = 0xff;
        invalidKey[1] = (byte)((invalidKey[1] & 0xf0) | 0x0f);
        byte[] ciphertext = Enumerable.Repeat((byte)0xa5, 1088).ToArray();
        byte[] shared = Enumerable.Repeat((byte)0xa5, 32).ToArray();

        fixed (byte* publicPointer = invalidKey)
        fixed (byte* randomPointer = EncapsulationRandom)
        fixed (byte* ciphertextPointer = ciphertext)
        fixed (byte* sharedPointer = shared)
        {
            int status = NativeMethods.Encapsulate(
                publicPointer, (nuint)invalidKey.Length,
                randomPointer, (nuint)EncapsulationRandom.Length,
                ciphertextPointer, (nuint)ciphertext.Length,
                sharedPointer, (nuint)shared.Length);
            Check(status == InvalidPublicKey, "invalid public-key status");
        }

        Check(ciphertext.All(value => value == 0xa5), "invalid public key changed ciphertext output");
        Check(shared.All(value => value == 0xa5), "invalid public key changed secret output");

        bool threw = false;
        try
        {
            using MlKemEncapsulation ignored = MlKemProvider.Encapsulate(invalidKey, EncapsulationRandom);
        }
        catch (MlKemException exception) when (exception.Status == InvalidPublicKey)
        {
            threw = true;
        }
        Check(threw, "safe wrapper did not surface invalid public key");
        CryptographicOperations.ZeroMemory(shared);
    }

    private static void CheckImplicitRejection()
    {
        using MlKemKeyPair keyPair = MlKemProvider.KeyPairFromRandom(Seed);
        using MlKemEncapsulation encapsulation = MlKemProvider.Encapsulate(keyPair.PublicKey, EncapsulationRandom);
        byte[] mutated = encapsulation.Ciphertext.ToArray();
        mutated[0] ^= 0x80;
        using OwnedSecret rejected = MlKemProvider.Decapsulate(keyPair.Secret, mutated);
        Check(CryptographicOperations.FixedTimeEquals(rejected.Bytes, ExpectedRejected), "exact J(z||mutated-c) rejection secret");
    }

    private static unsafe void CheckNativeAndOwnedZeroization()
    {
        byte[] native = Enumerable.Repeat((byte)0xa5, 73).ToArray();
        fixed (byte* pointer = native)
        {
            Check(NativeMethods.Zero(pointer, (nuint)native.Length) == Ok, "native zero status");
            Check(NativeMethods.Zero(pointer, 0) == InvalidLength, "native zero empty status");
        }
        Check(native.All(value => value == 0), "native zero contents");

        byte[] observed = Enumerable.Repeat((byte)0xa5, 32).ToArray();
        var owned = new OwnedSecret(observed);
        owned.Dispose();
        Check(observed.All(value => value == 0), "owned managed secret was not zeroized");
        bool disposedRejected = false;
        try
        {
            _ = owned.Bytes.Length;
        }
        catch (ObjectDisposedException)
        {
            disposedRejected = true;
        }
        Check(disposedRejected, "disposed secret remained readable");
    }

    private static void CheckSha256(ReadOnlySpan<byte> value, string expectedHex, string label)
    {
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(value, digest);
        Check(CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(expectedHex)), label);
        CryptographicOperations.ZeroMemory(digest);
    }

    private static void Check(bool condition, string label)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"Probe assertion failed: {label}");
        }
    }
}

internal sealed class MlKemException(int status) : CryptographicException($"Deep ML-KEM failed with status {status}.")
{
    public int Status { get; } = status;
}

internal sealed class OwnedSecret : IDisposable
{
    private byte[]? _bytes;

    internal OwnedSecret(byte[] bytes) => _bytes = bytes;

    public ReadOnlySpan<byte> Bytes => _bytes ?? throw new ObjectDisposedException(nameof(OwnedSecret));

    public void Dispose()
    {
        byte[]? bytes = Interlocked.Exchange(ref _bytes, null);
        if (bytes is not null)
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}

internal sealed class MlKemKeyPair(byte[] publicKey, OwnedSecret secret) : IDisposable
{
    public ReadOnlyMemory<byte> PublicKey { get; } = publicKey;
    public OwnedSecret Secret { get; } = secret;
    public void Dispose() => Secret.Dispose();
}

internal sealed class MlKemEncapsulation(byte[] ciphertext, OwnedSecret secret) : IDisposable
{
    public ReadOnlyMemory<byte> Ciphertext { get; } = ciphertext;
    public OwnedSecret Secret { get; } = secret;
    public void Dispose() => Secret.Dispose();
}

internal static class MlKemProvider
{
    public static unsafe MlKemKeyPair KeyPairFromRandom(ReadOnlySpan<byte> random)
    {
        if (random.Length != 64) throw new ArgumentException("Expected 64-byte Deep compact key seed d||z.", nameof(random));
        byte[] publicKey = new byte[1184];
        byte[] secret = new byte[64];
        int status;
        fixed (byte* randomPointer = random)
        fixed (byte* publicPointer = publicKey)
        fixed (byte* secretPointer = secret)
        {
            status = NativeMethods.KeyPairFromRandom(randomPointer, 64, publicPointer, 1184, secretPointer, 64);
        }
        if (status != 0)
        {
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(secret);
            throw new MlKemException(status);
        }
        return new MlKemKeyPair(publicKey, new OwnedSecret(secret));
    }

    public static unsafe MlKemEncapsulation Encapsulate(ReadOnlyMemory<byte> publicKey, ReadOnlySpan<byte> random)
    {
        if (publicKey.Length != 1184) throw new ArgumentException("Expected 1184-byte public key.", nameof(publicKey));
        if (random.Length != 32) throw new ArgumentException("Expected 32-byte encapsulation random.", nameof(random));
        byte[] ciphertext = new byte[1088];
        byte[] secret = new byte[32];
        int status;
        using MemoryHandle publicHandle = publicKey.Pin();
        fixed (byte* randomPointer = random)
        fixed (byte* ciphertextPointer = ciphertext)
        fixed (byte* secretPointer = secret)
        {
            status = NativeMethods.Encapsulate((byte*)publicHandle.Pointer, 1184, randomPointer, 32, ciphertextPointer, 1088, secretPointer, 32);
        }
        if (status != 0)
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(secret);
            throw new MlKemException(status);
        }
        return new MlKemEncapsulation(ciphertext, new OwnedSecret(secret));
    }

    public static unsafe OwnedSecret Decapsulate(OwnedSecret decapsulationKey, ReadOnlyMemory<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(decapsulationKey);
        if (decapsulationKey.Bytes.Length != 64) throw new ArgumentException("Expected 64-byte Deep compact key seed d||z.", nameof(decapsulationKey));
        if (ciphertext.Length != 1088) throw new ArgumentException("Expected 1088-byte ciphertext.", nameof(ciphertext));
        byte[] secret = new byte[32];
        int status;
        ReadOnlySpan<byte> key = decapsulationKey.Bytes;
        using MemoryHandle ciphertextHandle = ciphertext.Pin();
        fixed (byte* keyPointer = key)
        fixed (byte* secretPointer = secret)
        {
            status = NativeMethods.Decapsulate(keyPointer, 64, (byte*)ciphertextHandle.Pointer, 1088, secretPointer, 32);
        }
        if (status != 0)
        {
            CryptographicOperations.ZeroMemory(secret);
            throw new MlKemException(status);
        }
        return new OwnedSecret(secret);
    }
}

internal static partial class NativeMethods
{
    private const string LibraryName = "deep_mlkem";
    private static nint _handle;

    internal static void Initialize(string path)
    {
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path))
        {
            throw new FileNotFoundException("Deep ML-KEM runtime is absent.", path);
        }
        _handle = NativeLibrary.Load(path);
        NativeLibrary.SetDllImportResolver(typeof(NativeMethods).Assembly, Resolve);
    }

    internal static bool HasExport(string name) => NativeLibrary.TryGetExport(_handle, name, out _);

    internal static void Shutdown()
    {
        nint handle = Interlocked.Exchange(ref _handle, 0);
        if (handle != 0) NativeLibrary.Free(handle);
    }

    private static nint Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath) =>
        libraryName == LibraryName ? _handle : 0;

    [LibraryImport(LibraryName, EntryPoint = "deep_mlkem_v1_keygen_random_size")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial nuint KeygenRandomSize();

    [LibraryImport(LibraryName, EntryPoint = "deep_mlkem_v1_decapsulation_key_size")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial nuint DecapsulationKeySize();

    [LibraryImport(LibraryName, EntryPoint = "deep_mlkem_v1_encapsulation_key_size")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial nuint EncapsulationKeySize();

    [LibraryImport(LibraryName, EntryPoint = "deep_mlkem_v1_encapsulation_random_size")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial nuint EncapsulationRandomSize();

    [LibraryImport(LibraryName, EntryPoint = "deep_mlkem_v1_ciphertext_size")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial nuint CiphertextSize();

    [LibraryImport(LibraryName, EntryPoint = "deep_mlkem_v1_shared_secret_size")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial nuint SharedSecretSize();

    [LibraryImport(LibraryName, EntryPoint = "deep_mlkem_v1_keypair_from_random")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int KeyPairFromRandom(byte* random, nuint randomLength, byte* publicKey, nuint publicKeyLength, byte* secret, nuint secretLength);

    [LibraryImport(LibraryName, EntryPoint = "deep_mlkem_v1_encapsulate")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int Encapsulate(byte* publicKey, nuint publicKeyLength, byte* random, nuint randomLength, byte* ciphertext, nuint ciphertextLength, byte* secret, nuint secretLength);

    [LibraryImport(LibraryName, EntryPoint = "deep_mlkem_v1_decapsulate")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int Decapsulate(byte* secretKey, nuint secretKeyLength, byte* ciphertext, nuint ciphertextLength, byte* secret, nuint secretLength);

    [LibraryImport(LibraryName, EntryPoint = "deep_mlkem_v1_zero")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int Zero(byte* buffer, nuint bufferLength);
}
