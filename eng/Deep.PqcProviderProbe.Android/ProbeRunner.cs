using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Android.OS;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using BcArrays = Org.BouncyCastle.Utilities.Arrays;

namespace Deep.PqcProviderProbe.Android;

internal static class ProbeRunner
{
    private const int WarmupIterations = 5;
    private const int MeasurementIterations = 30;
    private const int MlKemQ = 3329;
    private const int ExpectedPublicKeyBytes = 1184;
    private const int ExpectedPrivateKeyBytes = 2400;
    private const int ExpectedCiphertextBytes = 1088;
    private const int ExpectedSecretBytes = 32;

    private static readonly MLKemParameters Parameters = MLKemParameters.ml_kem_768;
    private static readonly ProviderMetadata Provider = new(
        Package: "BouncyCastle.Cryptography",
        PackageVersion: "2.7.0",
        ParameterSet: "ML-KEM-768",
        UpstreamExperimental: true,
        PrivateKeyImplementsIDisposable: false,
        KemObjectsImplementIDisposable: false,
        PublicZeroizationApiAvailable: true,
        PublicZeroizationApi: "Org.BouncyCastle.Utilities.Arrays.ZeroMemory(byte[])",
        ProbeClearsOwnedTemporaryBuffers: true);

    internal static string Run()
    {
        ProbeReport report;
        try
        {
            report = Execute();
        }
        catch
        {
            report = new ProbeReport(
                SchemaVersion: "1.1",
                Success: false,
                ProductionEligible: false,
                ProductionBlockers: ["provider_failure"],
                ErrorCode: "provider_failure",
                Provider,
                Bounds: new ProbeBounds(WarmupIterations, MeasurementIterations),
                Runtime: RuntimeMetadata.Create(),
                Validation: null,
                Correctness: false,
                KeyGeneration: null,
                Encapsulation: null,
                Decapsulation: null,
                Resources: null);
        }

        try
        {
            return JsonSerializer.Serialize(report, ProbeJsonContext.Default.ProbeReport);
        }
        catch
        {
            return "{\"schemaVersion\":\"1.1\",\"success\":false,\"productionEligible\":false,\"productionBlockers\":[\"serialization_failure\"],\"errorCode\":\"serialization_failure\"}";
        }
    }

    private static ProbeReport Execute()
    {
        byte[]? publicEncoding = null;
        byte[]? privateEncoding = null;
        byte[]? ciphertext = null;
        byte[]? encapsulatedSecret = null;
        byte[]? decapsulatedSecret = null;
        byte[]? encapsulationBuffer = null;
        byte[]? encapsulationSecretBuffer = null;
        byte[]? decapsulationSecretBuffer = null;

        var workingSetBefore = TryGetWorkingSet();
        var managedHeapBefore = GC.GetTotalMemory(forceFullCollection: false);

        try
        {
            var random = new SecureRandom();
            var keyPair = GenerateKeyPair(random);
            var publicKey = (MLKemPublicKeyParameters)keyPair.Public;
            var privateKey = (MLKemPrivateKeyParameters)keyPair.Private;

            publicEncoding = publicKey.GetEncoded();
            privateEncoding = privateKey.GetEncoded();
            if (publicEncoding.Length != ExpectedPublicKeyBytes ||
                privateEncoding.Length != ExpectedPrivateKeyBytes)
            {
                throw new InvalidOperationException("Unexpected ML-KEM-768 key size.");
            }

            var importedPublic = MLKemPublicKeyParameters.FromEncoding(Parameters, publicEncoding);
            var importedPrivate = MLKemPrivateKeyParameters.FromEncoding(Parameters, privateEncoding);
            var validation = new ValidationChecks(
                PublicLengthRejected: RejectsPublicLengths(publicEncoding),
                PublicModulusRejected: RejectsPublicModulus(publicEncoding),
                PrivateLengthRejected: RejectsPrivateLengths(privateEncoding),
                PrivateEmbeddedPublicModulusMutationRejected:
                    RejectsPrivateModulus(privateEncoding, embeddedPublicKey: true),
                PrivateCoefficientModulusMutationRejected:
                    RejectsPrivateModulus(privateEncoding, embeddedPublicKey: false));

            var encapsulator = new MLKemEncapsulator(Parameters);
            encapsulator.Init(importedPublic);
            var decapsulator = new MLKemDecapsulator(Parameters);
            decapsulator.Init(importedPrivate);

            if (encapsulator.EncapsulationLength != ExpectedCiphertextBytes ||
                encapsulator.SecretLength != ExpectedSecretBytes ||
                decapsulator.EncapsulationLength != ExpectedCiphertextBytes ||
                decapsulator.SecretLength != ExpectedSecretBytes)
            {
                throw new InvalidOperationException("Unexpected ML-KEM-768 operation size.");
            }

            ciphertext = new byte[encapsulator.EncapsulationLength];
            encapsulatedSecret = new byte[encapsulator.SecretLength];
            decapsulatedSecret = new byte[decapsulator.SecretLength];
            encapsulator.Encapsulate(ciphertext, encapsulatedSecret);
            decapsulator.Decapsulate(ciphertext, decapsulatedSecret);
            var correctness = CryptographicOperations.FixedTimeEquals(
                encapsulatedSecret, decapsulatedSecret);

            WarmUp(random, encapsulator, decapsulator, ciphertext);
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            var workingSetAfterWarmup = TryGetWorkingSet();
            var managedHeapAfterWarmup = GC.GetTotalMemory(forceFullCollection: false);

            var keyGenerationMetrics = Measure(() =>
            {
                var generated = GenerateKeyPair(random);
                GC.KeepAlive(generated);
            });

            encapsulationBuffer = new byte[encapsulator.EncapsulationLength];
            encapsulationSecretBuffer = new byte[encapsulator.SecretLength];
            var encapsulationMetrics = Measure(() =>
            {
                encapsulator.Encapsulate(encapsulationBuffer, encapsulationSecretBuffer);
                CryptographicOperations.ZeroMemory(encapsulationSecretBuffer);
            });

            decapsulationSecretBuffer = new byte[decapsulator.SecretLength];
            var decapsulationMetrics = Measure(() =>
            {
                decapsulator.Decapsulate(ciphertext, decapsulationSecretBuffer);
                CryptographicOperations.ZeroMemory(decapsulationSecretBuffer);
            });

            var resources = new ResourceMetrics(
                WorkingSetAvailable: workingSetBefore.HasValue && workingSetAfterWarmup.HasValue,
                WorkingSetBeforeBytes: workingSetBefore,
                WorkingSetAfterWarmupBytes: workingSetAfterWarmup,
                WorkingSetAfterMeasurementsBytes: TryGetWorkingSet(),
                ManagedHeapBeforeBytes: managedHeapBefore,
                ManagedHeapAfterWarmupBytes: managedHeapAfterWarmup,
                ManagedHeapAfterMeasurementsBytes: GC.GetTotalMemory(forceFullCollection: false));

            var success = correctness && validation.RequiredChecksPassed;
            var productionBlockers = new List<string>(3);
            if (Provider.UpstreamExperimental)
                productionBlockers.Add("upstream_experimental");
            if (!Provider.PrivateKeyImplementsIDisposable)
                productionBlockers.Add("private_key_not_zeroizable");
            if (!validation.PrivateCoefficientModulusMutationRejected)
                productionBlockers.Add("private_coefficient_mutation_accepted");
            var productionEligible = success && productionBlockers.Count == 0;
            return new ProbeReport(
                SchemaVersion: "1.1",
                Success: success,
                ProductionEligible: productionEligible,
                ProductionBlockers: productionBlockers,
                ErrorCode: success ? null : correctness
                    ? "required_malformed_input_rejection_failed"
                    : "correctness_failed",
                Provider,
                Bounds: new ProbeBounds(WarmupIterations, MeasurementIterations),
                Runtime: RuntimeMetadata.Create(),
                Validation: validation,
                Correctness: correctness,
                KeyGeneration: keyGenerationMetrics,
                Encapsulation: encapsulationMetrics,
                Decapsulation: decapsulationMetrics,
                Resources: resources);
        }
        finally
        {
            Zero(publicEncoding);
            Zero(privateEncoding);
            Zero(ciphertext);
            Zero(encapsulatedSecret);
            Zero(decapsulatedSecret);
            Zero(encapsulationBuffer);
            Zero(encapsulationSecretBuffer);
            Zero(decapsulationSecretBuffer);
        }
    }

    private static AsymmetricCipherKeyPair GenerateKeyPair(SecureRandom random)
    {
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(random, Parameters));
        return generator.GenerateKeyPair();
    }

    private static void WarmUp(
        SecureRandom random,
        MLKemEncapsulator encapsulator,
        MLKemDecapsulator decapsulator,
        byte[] validCiphertext)
    {
        var ciphertext = new byte[encapsulator.EncapsulationLength];
        var encapsulatedSecret = new byte[encapsulator.SecretLength];
        var decapsulatedSecret = new byte[decapsulator.SecretLength];
        try
        {
            for (var iteration = 0; iteration < WarmupIterations; iteration++)
            {
                var generated = GenerateKeyPair(random);
                GC.KeepAlive(generated);
                encapsulator.Encapsulate(ciphertext, encapsulatedSecret);
                decapsulator.Decapsulate(validCiphertext, decapsulatedSecret);
                CryptographicOperations.ZeroMemory(encapsulatedSecret);
                CryptographicOperations.ZeroMemory(decapsulatedSecret);
            }
        }
        finally
        {
            Zero(ciphertext);
            Zero(encapsulatedSecret);
            Zero(decapsulatedSecret);
        }
    }

    private static OperationMetrics Measure(Action operation)
    {
        var microseconds = new double[MeasurementIterations];
        var hasAllocationStart = TryGetThreadAllocations(out var allocationStart);
        for (var iteration = 0; iteration < MeasurementIterations; iteration++)
        {
            var started = Stopwatch.GetTimestamp();
            operation();
            var elapsed = Stopwatch.GetTimestamp() - started;
            microseconds[iteration] = elapsed * 1_000_000d / Stopwatch.Frequency;
        }

        long? allocatedBytesPerOperation = null;
        if (hasAllocationStart && TryGetThreadAllocations(out var allocationEnd))
        {
            allocatedBytesPerOperation = Math.Max(
                0,
                (allocationEnd - allocationStart) / MeasurementIterations);
        }

        Array.Sort(microseconds);
        var median = microseconds.Length % 2 == 0
            ? (microseconds[(microseconds.Length / 2) - 1] + microseconds[microseconds.Length / 2]) / 2d
            : microseconds[microseconds.Length / 2];
        var p95Index = Math.Clamp(
            (int)Math.Ceiling(microseconds.Length * 0.95d) - 1,
            0,
            microseconds.Length - 1);
        return new OperationMetrics(
            MedianMicroseconds: Math.Round(median, 3),
            P95Microseconds: Math.Round(microseconds[p95Index], 3),
            ManagedAllocatedBytesPerOperation: allocatedBytesPerOperation);
    }

    private static bool RejectsPublicLengths(byte[] valid)
    {
        var shorter = valid.AsSpan(0, valid.Length - 1).ToArray();
        var longer = new byte[valid.Length + 1];
        valid.CopyTo(longer, 0);
        try
        {
            return Rejects(() => MLKemPublicKeyParameters.FromEncoding(Parameters, shorter)) &&
                   Rejects(() => MLKemPublicKeyParameters.FromEncoding(Parameters, longer));
        }
        finally
        {
            Zero(shorter);
            Zero(longer);
        }
    }

    private static bool RejectsPrivateLengths(byte[] valid)
    {
        var shorter = valid.AsSpan(0, valid.Length - 1).ToArray();
        var longer = new byte[valid.Length + 1];
        valid.CopyTo(longer, 0);
        try
        {
            return Rejects(() => MLKemPrivateKeyParameters.FromEncoding(Parameters, shorter)) &&
                   Rejects(() => MLKemPrivateKeyParameters.FromEncoding(Parameters, longer));
        }
        finally
        {
            Zero(shorter);
            Zero(longer);
        }
    }

    private static bool RejectsPublicModulus(byte[] valid)
    {
        var malformed = valid.ToArray();
        try
        {
            SetFirstPackedCoefficient(malformed, offset: 0, MlKemQ);
            return Rejects(() => MLKemPublicKeyParameters.FromEncoding(Parameters, malformed));
        }
        finally
        {
            Zero(malformed);
        }
    }

    private static bool RejectsPrivateModulus(byte[] valid, bool embeddedPublicKey)
    {
        var malformed = valid.ToArray();
        try
        {
            var offset = embeddedPublicKey
                ? ExpectedPrivateKeyBytes - ExpectedPublicKeyBytes - 64
                : 0;
            SetFirstPackedCoefficient(malformed, offset, MlKemQ);
            return Rejects(() => MLKemPrivateKeyParameters.FromEncoding(Parameters, malformed));
        }
        finally
        {
            Zero(malformed);
        }
    }

    private static void SetFirstPackedCoefficient(byte[] encoded, int offset, int coefficient)
    {
        encoded[offset] = (byte)coefficient;
        encoded[offset + 1] = (byte)((encoded[offset + 1] & 0xf0) | ((coefficient >> 8) & 0x0f));
    }

    private static bool Rejects(Action import)
    {
        try
        {
            import();
            return false;
        }
        catch (ArgumentException)
        {
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static long? TryGetWorkingSet()
    {
        try
        {
            return System.Environment.WorkingSet;
        }
        catch
        {
            return null;
        }
    }

    private static bool TryGetThreadAllocations(out long allocatedBytes)
    {
        try
        {
            allocatedBytes = GC.GetAllocatedBytesForCurrentThread();
            return true;
        }
        catch
        {
            allocatedBytes = 0;
            return false;
        }
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
            BcArrays.ZeroMemory(value);
    }
}

internal sealed record ProbeReport(
    string SchemaVersion,
    bool Success,
    bool ProductionEligible,
    IReadOnlyList<string> ProductionBlockers,
    string? ErrorCode,
    ProviderMetadata Provider,
    ProbeBounds Bounds,
    RuntimeMetadata Runtime,
    ValidationChecks? Validation,
    bool Correctness,
    OperationMetrics? KeyGeneration,
    OperationMetrics? Encapsulation,
    OperationMetrics? Decapsulation,
    ResourceMetrics? Resources);

internal sealed record ProviderMetadata(
    string Package,
    string PackageVersion,
    string ParameterSet,
    bool UpstreamExperimental,
    bool PrivateKeyImplementsIDisposable,
    bool KemObjectsImplementIDisposable,
    bool PublicZeroizationApiAvailable,
    string PublicZeroizationApi,
    bool ProbeClearsOwnedTemporaryBuffers);

internal sealed record ProbeBounds(int WarmupIterations, int MeasurementIterations);

internal sealed record RuntimeMetadata(
    string Framework,
    string ProcessArchitecture,
    int AndroidApiLevel,
    int ProcessorCount)
{
    internal static RuntimeMetadata Create() => new(
        RuntimeInformation.FrameworkDescription,
        RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
        (int)Build.VERSION.SdkInt,
        System.Environment.ProcessorCount);
}

internal sealed record ValidationChecks(
    bool PublicLengthRejected,
    bool PublicModulusRejected,
    bool PrivateLengthRejected,
    bool PrivateEmbeddedPublicModulusMutationRejected,
    bool PrivateCoefficientModulusMutationRejected)
{
    internal bool RequiredChecksPassed =>
        PublicLengthRejected &&
        PublicModulusRejected &&
        PrivateLengthRejected &&
        PrivateEmbeddedPublicModulusMutationRejected;
}

internal sealed record OperationMetrics(
    double MedianMicroseconds,
    double P95Microseconds,
    long? ManagedAllocatedBytesPerOperation);

internal sealed record ResourceMetrics(
    bool WorkingSetAvailable,
    long? WorkingSetBeforeBytes,
    long? WorkingSetAfterWarmupBytes,
    long? WorkingSetAfterMeasurementsBytes,
    long ManagedHeapBeforeBytes,
    long ManagedHeapAfterWarmupBytes,
    long ManagedHeapAfterMeasurementsBytes);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = false)]
[JsonSerializable(typeof(ProbeReport))]
internal partial class ProbeJsonContext : JsonSerializerContext
{
}
