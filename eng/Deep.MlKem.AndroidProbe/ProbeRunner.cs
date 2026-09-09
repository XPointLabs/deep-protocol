using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Android.Content.Res;
using Android.OS;
using Deep.Protocol.MessagingCrypto;

namespace Deep.MlKem.AndroidProbe;

internal static class ProbeRunner
{
    private const string PackagedAssetName = "deep-mlkem/libdeep_mlkem.so";

    internal static string Run(AssetManager? assets)
    {
        ArgumentNullException.ThrowIfNull(assets);
        var approved = DeepMlKemAndroidProbeApprovedAssets.AndroidArm64;
        var checks = new ProbeChecks();
        var errorCode = "asset_package_validation_failed";

        try
        {
            StagePackagedAsset(assets, approved);
            checks.PackagedAssetValidated = true;

            errorCode = "approved_identity_validation_failed";
            DeepMlKemNativeProvider.ValidateApprovedAssetIdentity(approved);
            checks.ApprovedIdentityValidated = true;
            checks.DriftedApprovedIdentityRejected = RejectsDriftedIdentity(approved);
            if (!checks.DriftedApprovedIdentityRejected)
                throw new CryptographicException("Drifted ML-KEM ABI identity was accepted.");

            errorCode = "initial_provider_roundtrip_failed";
            var provider = DeepMlKemNativeProvider.LoadApprovedForCurrentProcess();
            try
            {
                checks.InitialProviderRoundTrip = RoundTrip(provider);
                if (!checks.InitialProviderRoundTrip)
                    throw new CryptographicException("ML-KEM shared-secret mismatch.");
            }
            finally
            {
                provider.Dispose();
            }

            errorCode = "disposed_provider_not_closed";
            checks.DisposedProviderRejected = RejectsDisposedProvider(provider);
            provider.Dispose();
            if (!checks.DisposedProviderRejected)
                throw new CryptographicException("Disposed provider accepted an operation.");

            errorCode = "provider_reload_roundtrip_failed";
            using (var reloadedProvider = DeepMlKemNativeProvider.LoadApprovedForCurrentProcess())
            {
                checks.ProviderReloadRoundTrip = RoundTrip(reloadedProvider);
            }
            if (!checks.ProviderReloadRoundTrip)
                throw new CryptographicException("Reloaded provider shared-secret mismatch.");

            errorCode = "production_runtime_load_failed";
            var runtime = DeepMlKemProductionRuntime.CreateApprovedForCurrentProcess();
            try
            {
                using var keyPair = runtime.GenerateKeyPair();
                checks.ProductionRuntimeLoaded =
                    keyPair.EncapsulationKey.Length == MessagingCryptoConstants.MlKem768EncapsulationKeySize;
            }
            finally
            {
                runtime.Dispose();
            }
            if (!checks.ProductionRuntimeLoaded)
                throw new CryptographicException("Production runtime returned an unexpected key size.");

            errorCode = "disposed_production_runtime_not_closed";
            checks.DisposedProductionRuntimeRejected = RejectsDisposedRuntime(runtime);
            runtime.Dispose();
            if (!checks.DisposedProductionRuntimeRejected)
                throw new CryptographicException("Disposed production runtime accepted an operation.");

            errorCode = "production_runtime_reload_failed";
            using (var reloadedRuntime = DeepMlKemProductionRuntime.CreateApprovedForCurrentProcess())
            using (var keyPair = reloadedRuntime.GenerateKeyPair())
            {
                checks.ProductionRuntimeReloaded =
                    keyPair.EncapsulationKey.Length == MessagingCryptoConstants.MlKem768EncapsulationKeySize;
            }
            if (!checks.ProductionRuntimeReloaded)
                throw new CryptographicException("Reloaded production runtime returned an unexpected key size.");

            return Serialize(CreateReport(success: true, errorCode: null, approved, checks));
        }
        catch
        {
            return Serialize(CreateReport(success: false, errorCode, approved, checks));
        }
    }

    private static ProbeReport CreateReport(
        bool success,
        string? errorCode,
        DeepMlKemApprovedAsset approved,
        ProbeChecks checks) => new(
            SchemaVersion: 1,
            EvidenceScope: "android_runtime_probe_only",
            Success: success,
            ErrorCode: errorCode,
            ProviderIdentifier: DeepMlKemNativeProvider.Identifier,
            ApprovalScope: "probe_build_only",
            Asset: new ProbeAsset(
                RuntimeIdentifier: approved.RuntimeIdentifier,
                Bytes: approved.Bytes,
                Sha256: approved.Sha256),
            Runtime: new ProbeRuntime(
                Framework: RuntimeInformation.FrameworkDescription,
                ProcessArchitecture: RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
                AndroidApiLevel: (int)Build.VERSION.SdkInt),
            Checks: checks);

    private static string Serialize(ProbeReport report)
    {
        try
        {
            return JsonSerializer.Serialize(report, ProbeJsonContext.Default.ProbeReport);
        }
        catch
        {
            return "{\"schemaVersion\":1,\"evidenceScope\":\"android_runtime_probe_only\",\"success\":false,\"errorCode\":\"serialization_failed\"}";
        }
    }

    private static void StagePackagedAsset(AssetManager assets, DeepMlKemApprovedAsset approved)
    {
        var destination = Path.Combine(
            AppContext.BaseDirectory,
            approved.RelativePath.Replace('/', Path.DirectorySeparatorChar));
        var directory = Path.GetDirectoryName(destination)
            ?? throw new CryptographicException("Approved asset destination is invalid.");
        Directory.CreateDirectory(directory);
        var temporary = destination + ".staging";
        byte[]? digest = null;
        var buffer = new byte[16 * 1024];

        try
        {
            using var source = assets.Open(PackagedAssetName, Access.Streaming);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using (var output = new FileStream(
                       temporary,
                       FileMode.Create,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: buffer.Length,
                       FileOptions.WriteThrough))
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
                if (bytes != approved.Bytes)
                    throw new CryptographicException("Packaged ML-KEM asset length mismatch.");
            }

            digest = hash.GetHashAndReset();
            var expected = Convert.FromHexString(approved.Sha256);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(digest, expected))
                    throw new CryptographicException("Packaged ML-KEM asset digest mismatch.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expected);
            }

            File.Move(temporary, destination, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            if (digest is not null)
                CryptographicOperations.ZeroMemory(digest);
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    private static bool RoundTrip(DeepMlKemNativeProvider provider)
    {
        using var keyPair = provider.GenerateKeyPair();
        var encapsulationKey = keyPair.EncapsulationKey.ToArray();
        var ciphertext = new byte[MessagingCryptoConstants.MlKem768CiphertextSize];
        var senderSecret = new byte[MessagingCryptoConstants.MlKem768SharedSecretSize];
        var recipientSecret = new byte[MessagingCryptoConstants.MlKem768SharedSecretSize];
        try
        {
            provider.Encapsulate(encapsulationKey, ciphertext, senderSecret);
            keyPair.UseDecapsulationKey(key => provider.Decapsulate(key, ciphertext, recipientSecret));
            return CryptographicOperations.FixedTimeEquals(senderSecret, recipientSecret) &&
                   senderSecret.AsSpan().IndexOfAnyExcept((byte)0) >= 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encapsulationKey);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(senderSecret);
            CryptographicOperations.ZeroMemory(recipientSecret);
        }
    }

    private static bool RejectsDisposedProvider(DeepMlKemNativeProvider provider)
    {
        try
        {
            using var keyPair = provider.GenerateKeyPair();
            return false;
        }
        catch (MessagingCryptoException exception)
        {
            return exception.Error == MessagingCryptoError.ObjectDisposed;
        }
    }

    private static bool RejectsDriftedIdentity(DeepMlKemApprovedAsset approved)
    {
        try
        {
            DeepMlKemNativeProvider.ValidateApprovedAssetIdentity(
                approved with { Abi = "mlkem-native/drifted-abi" });
            return false;
        }
        catch (CryptographicException)
        {
            return true;
        }
    }

    private static bool RejectsDisposedRuntime(DeepMlKemProductionRuntime runtime)
    {
        try
        {
            using var keyPair = runtime.GenerateKeyPair();
            return false;
        }
        catch (MessagingCryptoException exception)
        {
            return exception.Error == MessagingCryptoError.ObjectDisposed;
        }
    }
}

internal sealed record ProbeReport(
    int SchemaVersion,
    string EvidenceScope,
    bool Success,
    string? ErrorCode,
    string ProviderIdentifier,
    string ApprovalScope,
    ProbeAsset Asset,
    ProbeRuntime Runtime,
    ProbeChecks Checks);

internal sealed record ProbeAsset(string RuntimeIdentifier, long Bytes, string Sha256);

internal sealed record ProbeRuntime(string Framework, string ProcessArchitecture, int AndroidApiLevel);

internal sealed class ProbeChecks
{
    public bool PackagedAssetValidated { get; set; }
    public bool ApprovedIdentityValidated { get; set; }
    public bool DriftedApprovedIdentityRejected { get; set; }
    public bool InitialProviderRoundTrip { get; set; }
    public bool DisposedProviderRejected { get; set; }
    public bool ProviderReloadRoundTrip { get; set; }
    public bool ProductionRuntimeLoaded { get; set; }
    public bool DisposedProductionRuntimeRejected { get; set; }
    public bool ProductionRuntimeReloaded { get; set; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = false)]
[JsonSerializable(typeof(ProbeReport))]
internal partial class ProbeJsonContext : JsonSerializerContext;
