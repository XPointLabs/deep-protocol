using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Android.Content.Res;
using Android.OS;
using Deep.Protocol.MessagingCrypto;

namespace Deep.MlKemBraid.AndroidManagedProbe;

internal static class ProbeRunner
{
    private const string PackagedAssetName = "deep-mlkem-braid/libdeep_mlkem_braid.so";

    internal static string Run(AssetManager? assets)
    {
        var checks = new ProbeChecks();
        var error = "asset_staging_failed";
        try
        {
            ArgumentNullException.ThrowIfNull(assets);
            var candidate = DeepMlKemBraidApprovedAssets.AndroidArm64ProbeCandidate;
            Stage(assets, candidate);
            checks.AssetDigestValidated = true;

            error = "production_allowlist_not_closed";
            try
            {
                using var unexpected = DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess();
                throw new CryptographicException("Candidate unexpectedly entered the production allowlist.");
            }
            catch (PlatformNotSupportedException)
            {
                checks.ProductionAllowlistClosed = true;
            }

            error = "candidate_load_failed";
            using var provider = DeepMlKemBraidNativeProvider.LoadAndroidArm64CandidateForProbe();
            checks.AbiLoaded = true;

            error = "roundtrip_failed";
            checks.RoundTrip = RoundTrip(provider, checks);
            if (!checks.RoundTrip) throw new CryptographicException("Shared-secret mismatch.");

            error = "single_use_failed";
            checks.SingleUse = SingleUse(provider);
            if (!checks.SingleUse) throw new CryptographicException("Opaque state was not single-use.");

            error = "concurrency_failed";
            checks.ConcurrentSingleConsumer = ConcurrentSingleConsumer(provider);
            if (!checks.ConcurrentSingleConsumer)
                throw new CryptographicException("Concurrent Encaps2 did not have exactly one consumer.");

            error = "performance_probe_failed";
            checks.TenRoundTripsMilliseconds = MeasureTenRoundTrips(provider);
            checks.PerformanceCompleted = true;

            provider.Dispose();
            error = "disposed_provider_not_closed";
            try
            {
                using var unexpected = provider.GenerateKeyPair();
                throw new CryptographicException("Disposed provider accepted key generation.");
            }
            catch (MessagingCryptoException exception)
                when (exception.Error == MessagingCryptoError.ObjectDisposed)
            {
                checks.DisposedProviderClosed = true;
            }

            return Report(true, null, checks);
        }
        catch (Exception exception)
        {
            var closedFailure = exception is MessagingCryptoException crypto
                ? $"{exception.GetType().Name}:{crypto.Error}"
                : exception.GetType().Name;
            return Report(false, $"{error}:{closedFailure}", checks);
        }
    }

    private static bool RoundTrip(
        DeepMlKemBraidNativeProvider provider,
        ProbeChecks? checks = null)
    {
        var keygenRandom = Sequence(64, 0x10);
        using var keys = provider.GenerateKeyPairFromRandomForTests(keygenRandom);
        var seed = keys.EncapsulationKeySeed.ToArray();
        var hash = keys.EncapsulationKeyHash.ToArray();
        var vector = keys.EncapsulationKeyVector.ToArray();
        var ct1 = new byte[DeepMlKemBraidNativeProvider.Ciphertext1Size];
        var ct2 = new byte[DeepMlKemBraidNativeProvider.Ciphertext2Size];
        var sender = new byte[DeepMlKemBraidNativeProvider.SharedSecretSize];
        var recipient = new byte[DeepMlKemBraidNativeProvider.SharedSecretSize];
        var encapsulationRandom = Sequence(32, 0x90);
        try
        {
            using var state = provider.Encapsulate1FromRandom(
                seed, hash, encapsulationRandom, ct1);
            provider.Encapsulate2(state, seed, vector, ct2, sender);
            var ciphertext = ct1.Concat(ct2).ToArray();
            try
            {
                keys.UseDecapsulationKey(key => provider.Decapsulate(key, ciphertext, recipient));
                var equal = CryptographicOperations.FixedTimeEquals(sender, recipient);
                var senderNonZero = sender.AsSpan().IndexOfAnyExcept((byte)0) >= 0;
                var recipientNonZero = recipient.AsSpan().IndexOfAnyExcept((byte)0) >= 0;
                if (checks is not null)
                {
                    checks.Ciphertext1NonZero = ct1.AsSpan().IndexOfAnyExcept((byte)0) >= 0;
                    checks.Ciphertext2NonZero = ct2.AsSpan().IndexOfAnyExcept((byte)0) >= 0;
                    checks.SenderSecretNonZero = senderNonZero;
                    checks.RecipientSecretNonZero = recipientNonZero;
                    checks.SecretsEqual = equal;
                }
                return equal && senderNonZero && recipientNonZero;
            }
            finally { CryptographicOperations.ZeroMemory(ciphertext); }
        }
        finally
        {
            Zero(keygenRandom, encapsulationRandom, seed, hash, vector, ct1, ct2, sender, recipient);
        }
    }

    private static bool SingleUse(DeepMlKemBraidNativeProvider provider)
    {
        using var keys = provider.GenerateKeyPair();
        var seed = keys.EncapsulationKeySeed.ToArray();
        var hash = keys.EncapsulationKeyHash.ToArray();
        var vector = keys.EncapsulationKeyVector.ToArray();
        try
        {
            using var state = provider.Encapsulate1(
                seed, hash, new byte[DeepMlKemBraidNativeProvider.Ciphertext1Size]);
            provider.Encapsulate2(
                state, seed, vector,
                new byte[DeepMlKemBraidNativeProvider.Ciphertext2Size],
                new byte[DeepMlKemBraidNativeProvider.SharedSecretSize]);
            try
            {
                provider.Encapsulate2(
                    state, seed, vector,
                    new byte[DeepMlKemBraidNativeProvider.Ciphertext2Size],
                    new byte[DeepMlKemBraidNativeProvider.SharedSecretSize]);
                return false;
            }
            catch (MessagingCryptoException exception)
            {
                return exception.Error == MessagingCryptoError.CapabilityConsumed;
            }
        }
        finally { Zero(seed, hash, vector); }
    }

    private static bool ConcurrentSingleConsumer(DeepMlKemBraidNativeProvider provider)
    {
        using var keys = provider.GenerateKeyPair();
        var seed = keys.EncapsulationKeySeed.ToArray();
        var hash = keys.EncapsulationKeyHash.ToArray();
        var vector = keys.EncapsulationKeyVector.ToArray();
        try
        {
            using var state = provider.Encapsulate1(
                seed, hash, new byte[DeepMlKemBraidNativeProvider.Ciphertext1Size]);
            using var start = new ManualResetEventSlim();
            Task<MessagingCryptoError?> Invoke() => Task.Run<MessagingCryptoError?>(() =>
            {
                start.Wait();
                try
                {
                    provider.Encapsulate2(
                        state, seed, vector,
                        new byte[DeepMlKemBraidNativeProvider.Ciphertext2Size],
                        new byte[DeepMlKemBraidNativeProvider.SharedSecretSize]);
                    return null;
                }
                catch (MessagingCryptoException exception) { return exception.Error; }
            });
            var first = Invoke();
            var second = Invoke();
            start.Set();
            Task.WaitAll(first, second);
            var results = new[] { first.Result, second.Result };
            return results.Count(static value => value is null) == 1 &&
                   results.Count(static value => value == MessagingCryptoError.CapabilityConsumed) == 1;
        }
        finally { Zero(seed, hash, vector); }
    }

    private static double MeasureTenRoundTrips(DeepMlKemBraidNativeProvider provider)
    {
        var stopwatch = Stopwatch.StartNew();
        for (var iteration = 0; iteration < 10; iteration++)
        {
            if (!RoundTrip(provider)) throw new CryptographicException("Repeated roundtrip failed.");
        }
        stopwatch.Stop();
        return Math.Round(stopwatch.Elapsed.TotalMilliseconds, 3);
    }

    private static void Stage(AssetManager assets, DeepMlKemBraidApprovedAsset candidate)
    {
        var destination = Path.Combine(
            AppContext.BaseDirectory,
            candidate.RelativePath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var temporary = destination + ".staging";
        var buffer = new byte[16 * 1024];
        byte[]? actual = null;
        try
        {
            using var source = assets.Open(PackagedAssetName, Access.Streaming);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using (var output = new FileStream(
                       temporary, FileMode.Create, FileAccess.Write, FileShare.None,
                       buffer.Length, FileOptions.WriteThrough))
            {
                long bytes = 0;
                int read;
                while ((read = source.Read(buffer, 0, buffer.Length)) != 0)
                {
                    output.Write(buffer, 0, read);
                    hash.AppendData(buffer, 0, read);
                    bytes = checked(bytes + read);
                }
                output.Flush(flushToDisk: true);
                if (bytes != candidate.Bytes) throw new CryptographicException("Asset size mismatch.");
            }
            actual = hash.GetHashAndReset();
            var expected = Convert.FromHexString(candidate.Sha256);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(actual, expected))
                    throw new CryptographicException("Asset digest mismatch.");
            }
            finally { CryptographicOperations.ZeroMemory(expected); }
            File.Move(temporary, destination, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            if (actual is not null) CryptographicOperations.ZeroMemory(actual);
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static string Report(bool success, string? error, ProbeChecks checks) =>
        JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            evidenceScope = "android_arm64_managed_wrapper_probe_only",
            success,
            error,
            secretsEmitted = false,
            runtime = new
            {
                framework = RuntimeInformation.FrameworkDescription,
                architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
                androidApi = (int)Build.VERSION.SdkInt,
            },
            checks,
        });

    private static void Zero(params byte[][] values)
    {
        foreach (var value in values) CryptographicOperations.ZeroMemory(value);
    }

    private static byte[] Sequence(int length, byte start) =>
        Enumerable.Range(0, length).Select(value => unchecked((byte)(start + value))).ToArray();
}

internal sealed class ProbeChecks
{
    public bool AssetDigestValidated { get; set; }
    public bool ProductionAllowlistClosed { get; set; }
    public bool AbiLoaded { get; set; }
    public bool RoundTrip { get; set; }
    public bool Ciphertext1NonZero { get; set; }
    public bool Ciphertext2NonZero { get; set; }
    public bool SenderSecretNonZero { get; set; }
    public bool RecipientSecretNonZero { get; set; }
    public bool SecretsEqual { get; set; }
    public bool SingleUse { get; set; }
    public bool ConcurrentSingleConsumer { get; set; }
    public bool PerformanceCompleted { get; set; }
    public double TenRoundTripsMilliseconds { get; set; }
    public bool DisposedProviderClosed { get; set; }
}
