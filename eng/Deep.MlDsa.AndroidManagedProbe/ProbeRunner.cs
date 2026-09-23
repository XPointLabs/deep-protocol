using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Android.Content.Res;
using Deep.Protocol.Identity;

namespace Deep.MlDsa.AndroidManagedProbe;

internal static class ProbeRunner
{
    private const string AssetName = "deep-mldsa/libdeep_mldsa.so";
    private const string ExpectedAssetHash =
        "6e46e4df970f5376416af3c50fb39e580487a616d2541aa26d1d90eddf918cc9";
    private const string ExpectedPublicHash =
        "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9";
    private const string ExpectedSignatureHash =
        "e8a6098e794cff6a62f2c3bceb0f2d4898d3630300f34264770e2845d321683a";

    internal static string Run(AssetManager? assets)
    {
        var step = "stage";
        try
        {
            ArgumentNullException.ThrowIfNull(assets);
            var path = Stage(assets);
            step = "load";
            var handle = NativeLibrary.Load(path);
            try
            {
                step = "abi";
                var publicSize = Bind<SizeFunction>(handle, "deep_mldsa_v1_public_key_size");
                var signatureSize = Bind<SizeFunction>(handle, "deep_mldsa_v1_signature_size");
                var publicFromSeed = Bind<PublicFromSeedFunction>(handle, "deep_mldsa_v1_public_from_seed");
                var sign = Bind<SignFromSeedFunction>(handle, "deep_mldsa_v1_sign_from_seed");
                var verify = Bind<VerifyFunction>(handle, "deep_mldsa_v1_verify");
                var zero = Bind<ZeroFunction>(handle, "deep_mldsa_v1_zero");
                if (publicSize() != 1952 || signatureSize() != 3309)
                    throw new CryptographicException("Unexpected ML-DSA-65 ABI sizes.");
                step = "transcript";
                CheckTranscript(publicFromSeed, sign, verify, zero);
                step = "acvp";
                var acvp = AcvpRunner.Run(assets, handle);
                step = "did2-managed";
                CheckManagedDid2Root();
                return Report(true, null, acvp);
            }
            finally { NativeLibrary.Free(handle); }
        }
        catch (Exception exception)
        {
            return Report(false, $"{step}:{exception.GetType().Name}", default);
        }
    }

    private static string Stage(AssetManager assets)
    {
        var directory = Path.Combine(
            AppContext.BaseDirectory, "runtimes", "android-arm64", "native");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "libdeep_mldsa.so");
        var temporary = path + ".staging";
        try
        {
            using var source = assets.Open(AssetName, Access.Streaming);
            using (var destination = new FileStream(temporary, FileMode.Create,
                       FileAccess.Write, FileShare.None, 16384, FileOptions.WriteThrough))
            {
                source.CopyTo(destination);
                destination.Flush(flushToDisk: true);
            }
            var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(temporary)))
                .ToLowerInvariant();
            if (!StringComparer.Ordinal.Equals(actual, ExpectedAssetHash))
                throw new CryptographicException("Packaged candidate asset mismatch.");
            File.Move(temporary, path, overwrite: true);
            return path;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static void CheckManagedDid2Root()
    {
        const string publicPhrase =
            "abandon abandon abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon abandon abandon art";
        using var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(
            Encoding.ASCII.GetBytes(publicPhrase));
        var did = DeepIdV2Root.DeriveDid2(phrase);
        if (did.CanonicalBytes.Length != 2036 || did.Text.Length != 90 ||
            !StringComparer.Ordinal.Equals(
                Convert.ToHexString(SHA256.HashData(did.CanonicalBytes.Span)).ToLowerInvariant(),
                "054709aba16d7e1a4d8eeb44cbb4b5096a06b0915ce14b32e9fdb6be8968bcd6") ||
            !StringComparer.Ordinal.Equals(
                Convert.ToHexString(did.RecordHash.Span).ToLowerInvariant(),
                "bea14bedff9a97c5108a5eebc3c4443192de68ea5db3270f29cf4b42da63b123"))
            throw new CryptographicException("Managed DID2 root transcript differs from pinned vector.");
    }

    private static unsafe void CheckTranscript(
        PublicFromSeedFunction publicFromSeed,
        SignFromSeedFunction sign,
        VerifyFunction verify,
        ZeroFunction zero)
    {
        var seed = Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray();
        var random = new byte[32]; // Deterministic test vector only; never account signing.
        var context = new byte[1]; // Non-null pointer with a zero-length FIPS 204 context.
        var message = Encoding.ASCII.GetBytes("Deep/PQRoot/signature-differential/v1");
        var publicKey = new byte[1952];
        var signature = new byte[3309];
        try
        {
            fixed (byte* seedPtr = seed, randomPtr = random, contextPtr = context,
                   messagePtr = message, publicPtr = publicKey, signaturePtr = signature)
            {
                if (publicFromSeed(seedPtr, (nuint)seed.Length, publicPtr,
                        (nuint)publicKey.Length) != 0)
                    throw new CryptographicException("Native public-key derivation failed.");
                if (!HashMatches(publicKey, ExpectedPublicHash))
                    throw new CryptographicException("Public-key vector mismatch.");
                if (sign(seedPtr, (nuint)seed.Length, randomPtr, (nuint)random.Length,
                        contextPtr, 0, messagePtr, (nuint)message.Length,
                        signaturePtr, (nuint)signature.Length) != 0)
                    throw new CryptographicException("Native signing failed.");
                if (!HashMatches(signature, ExpectedSignatureHash))
                    throw new CryptographicException("Signature vector mismatch.");
                if (verify(publicPtr, (nuint)publicKey.Length, contextPtr, 0,
                        messagePtr, (nuint)message.Length, signaturePtr,
                        (nuint)signature.Length) != 0)
                    throw new CryptographicException("Native verification failed.");
                message[0] ^= 1;
                if (verify(publicPtr, (nuint)publicKey.Length, contextPtr, 0,
                        messagePtr, (nuint)message.Length, signaturePtr,
                        (nuint)signature.Length) != 4)
                    throw new CryptographicException("Tampered message was accepted.");
                message[0] ^= 1;
                if (zero(seedPtr, (nuint)seed.Length) != 0 ||
                    seed.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
                    throw new CryptographicException("Native seed zeroization failed.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(random);
            CryptographicOperations.ZeroMemory(context);
            CryptographicOperations.ZeroMemory(message);
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static bool HashMatches(byte[] data, string expected) =>
        StringComparer.Ordinal.Equals(
            Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant(), expected);

    private static T Bind<T>(nint handle, string name) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(handle, name));

    private static string Report(bool success, string? error, AcvpResult acvp) => JsonSerializer.Serialize(new
    {
        schemaVersion = 1,
        probe = "Deep.MlDsa.AndroidManagedProbe",
        platform = "android-arm64",
        candidateOnly = true,
        acvpKeyGen = acvp.KeyGen,
        acvpSigGen = acvp.SigGen,
        acvpSigVer = acvp.SigVer,
        acvpPositive = acvp.Positive,
        acvpNegative = acvp.Negative,
        success,
        error
    });

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint SizeFunction();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int PublicFromSeedFunction(
        byte* seed, nuint seedLength, byte* publicKey, nuint publicLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int SignFromSeedFunction(
        byte* seed, nuint seedLength, byte* random, nuint randomLength,
        byte* context, nuint contextLength, byte* message, nuint messageLength,
        byte* signature, nuint signatureLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int VerifyFunction(
        byte* publicKey, nuint publicLength, byte* context, nuint contextLength,
        byte* message, nuint messageLength, byte* signature, nuint signatureLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int ZeroFunction(byte* buffer, nuint length);
}
