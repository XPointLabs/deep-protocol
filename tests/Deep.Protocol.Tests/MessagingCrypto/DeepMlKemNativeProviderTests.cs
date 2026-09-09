using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class DeepMlKemNativeProviderTests
{
    [Fact(Skip = "Executed by the explicit Windows ML-KEM wrapper evidence harness.")]
    public void Windows_ReviewedAssetRoundTripsAndImplicitlyRejectsMutation()
    {
        RequireWindowsAndStageApprovedAsset();
        using var provider = DeepMlKemNativeProvider.LoadApprovedForCurrentProcess();
        using var keyPair = provider.GenerateKeyPair();
        var publicKey = keyPair.EncapsulationKey.ToArray();
        var ciphertext = new byte[MessagingCryptoConstants.MlKem768CiphertextSize];
        var senderSecret = new byte[MessagingCryptoConstants.MlKem768SharedSecretSize];
        var recipientSecret = new byte[MessagingCryptoConstants.MlKem768SharedSecretSize];
        var rejectedSecret = new byte[MessagingCryptoConstants.MlKem768SharedSecretSize];
        try
        {
            keyPair.UseDecapsulationKey(key =>
            {
                Assert.True(provider.EncapsulationKeyMatchesDecapsulationKey(publicKey, key));
                var changedKey = key.ToArray();
                try
                {
                    changedKey[0] ^= 0x80;
                    Assert.False(provider.EncapsulationKeyMatchesDecapsulationKey(publicKey, changedKey));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(changedKey);
                }
            });
            provider.Encapsulate(publicKey, ciphertext, senderSecret);
            keyPair.UseDecapsulationKey(key => provider.Decapsulate(key, ciphertext, recipientSecret));
            Assert.True(CryptographicOperations.FixedTimeEquals(senderSecret, recipientSecret));
            Assert.Contains(senderSecret, static value => value != 0);

            ciphertext[17] ^= 0x80;
            keyPair.UseDecapsulationKey(key => provider.Decapsulate(key, ciphertext, rejectedSecret));
            Assert.False(CryptographicOperations.FixedTimeEquals(senderSecret, rejectedSecret));
            Assert.Contains(rejectedSecret, static value => value != 0);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(senderSecret);
            CryptographicOperations.ZeroMemory(recipientSecret);
            CryptographicOperations.ZeroMemory(rejectedSecret);
        }
    }

    [Fact(Skip = "Executed by the explicit Windows ML-KEM wrapper evidence harness.")]
    public void Windows_DigestMismatchAndOverlappingBuffersFailClosed()
    {
        var approved = RequireWindowsAndStageApprovedAsset(corrupt: true);
        Assert.Throws<CryptographicException>(DeepMlKemNativeProvider.LoadApprovedForCurrentProcess);
        approved = RequireWindowsAndStageApprovedAsset();
        using var provider = DeepMlKemNativeProvider.LoadApprovedForCurrentProcess();
        DeepMlKemNativeProvider.ValidateApprovedAssetIdentity(approved);
        var driftedAbi = approved with { Abi = "mlkem-native/drifted-abi" };
        Assert.Throws<CryptographicException>(() =>
            DeepMlKemNativeProvider.ValidateApprovedAssetIdentity(driftedAbi));
        var backing = new byte[2400];
        var error = Assert.Throws<MessagingCryptoException>(() => provider.Encapsulate(
            backing.AsSpan(0, MessagingCryptoConstants.MlKem768EncapsulationKeySize),
            backing.AsSpan(100, MessagingCryptoConstants.MlKem768CiphertextSize),
            backing.AsSpan(2200, MessagingCryptoConstants.MlKem768SharedSecretSize)));
        Assert.Equal(MessagingCryptoError.InvalidInput, error.Error);

        var overlappingInputs = new byte[DeepMlKemNativeProvider.CompactDecapsulationKeySize +
                                         MessagingCryptoConstants.MlKem768CiphertextSize];
        var output = Enumerable.Repeat((byte)0xa5, MessagingCryptoConstants.MlKem768SharedSecretSize).ToArray();
        error = Assert.Throws<MessagingCryptoException>(() => provider.Decapsulate(
            overlappingInputs.AsSpan(0, DeepMlKemNativeProvider.CompactDecapsulationKeySize),
            overlappingInputs.AsSpan(1, MessagingCryptoConstants.MlKem768CiphertextSize),
            output));
        Assert.Equal(MessagingCryptoError.InvalidInput, error.Error);
        Assert.All(output, static value => Assert.Equal(0, value));

        var clearedCiphertext = Enumerable.Repeat(
            (byte)0xa5,
            MessagingCryptoConstants.MlKem768CiphertextSize).ToArray();
        var clearedSecret = Enumerable.Repeat(
            (byte)0xa5,
            MessagingCryptoConstants.MlKem768SharedSecretSize).ToArray();
        error = Assert.Throws<MessagingCryptoException>(() => provider.Encapsulate(
            new byte[MessagingCryptoConstants.MlKem768EncapsulationKeySize - 1],
            clearedCiphertext,
            clearedSecret));
        Assert.Equal(MessagingCryptoError.InvalidInput, error.Error);
        Assert.All(clearedCiphertext, static value => Assert.Equal(0, value));
        Assert.All(clearedSecret, static value => Assert.Equal(0, value));
    }

    [Fact(Skip = "Executed by the explicit Windows ML-KEM wrapper evidence harness.")]
    public async Task Windows_DisposeIsIdempotentAndOperationsFailClosed()
    {
        RequireWindowsAndStageApprovedAsset();
        var provider = DeepMlKemNativeProvider.LoadApprovedForCurrentProcess();
        provider.Dispose();
        provider.Dispose();
        var error = Assert.Throws<MessagingCryptoException>(() => provider.Encapsulate(
            new byte[MessagingCryptoConstants.MlKem768EncapsulationKeySize],
            new byte[MessagingCryptoConstants.MlKem768CiphertextSize],
            new byte[MessagingCryptoConstants.MlKem768SharedSecretSize]));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, error.Error);

        var enteredNativeBoundary = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using (var releaseNativeBoundary = new ManualResetEventSlim())
        {
            var disposeStarted = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            using (DeepMlKemNativeProviderTestHooks.Install(beforeNativeCall: () =>
                   {
                       enteredNativeBoundary.TrySetResult();
                       releaseNativeBoundary.Wait();
                   }))
            {
                var concurrent = DeepMlKemNativeProvider.LoadApprovedForCurrentProcess();
                using var keyPair = concurrent.GenerateKeyPair();
                var publicKey = keyPair.EncapsulationKey.ToArray();
                try
                {
                    var operation = Task.Run(() => concurrent.Encapsulate(
                        publicKey,
                        new byte[MessagingCryptoConstants.MlKem768CiphertextSize],
                        new byte[MessagingCryptoConstants.MlKem768SharedSecretSize]));
                    await enteredNativeBoundary.Task.WaitAsync(TimeSpan.FromSeconds(5));
                    var dispose = Task.Run(() =>
                    {
                        disposeStarted.TrySetResult();
                        concurrent.Dispose();
                    });
                    await disposeStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
                    Assert.NotSame(dispose, await Task.WhenAny(dispose, Task.Delay(100)));
                    releaseNativeBoundary.Set();
                    await Task.WhenAll(operation, dispose);
                    concurrent.Dispose();
                }
                finally
                {
                    releaseNativeBoundary.Set();
                    concurrent.Dispose();
                    CryptographicOperations.ZeroMemory(publicKey);
                }
            }
        }

        var constructorReleaseCount = 0;
        using (DeepMlKemNativeProviderTestHooks.Install(
                   beforeValidateAbi: static () => throw new InvalidOperationException("injected ABI-construction fault"),
                   handleReleased: () => Interlocked.Increment(ref constructorReleaseCount)))
        {
            Assert.Throws<InvalidOperationException>(DeepMlKemNativeProvider.LoadApprovedForCurrentProcess);
            Assert.Equal(1, Volatile.Read(ref constructorReleaseCount));
            GC.Collect();
            GC.WaitForPendingFinalizers();
            Assert.Equal(1, Volatile.Read(ref constructorReleaseCount));
        }

        var finalizerReleaseCount = 0;
        using (DeepMlKemNativeProviderTestHooks.Install(
                   handleReleased: () => Interlocked.Increment(ref finalizerReleaseCount)))
        {
            var abandoned = CreateAbandonedProvider();
            for (var attempt = 0; attempt < 10 &&
                 (abandoned.IsAlive || Volatile.Read(ref finalizerReleaseCount) == 0); attempt++)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
            }
            Assert.False(abandoned.IsAlive);
            Assert.Equal(1, Volatile.Read(ref finalizerReleaseCount));
        }

        using (var production = DeepMlKemProductionRuntime.CreateApprovedForCurrentProcess())
        using (var generated = production.GenerateKeyPair())
        {
            Assert.Equal(
                MessagingCryptoConstants.MlKem768EncapsulationKeySize,
                generated.EncapsulationKey.Length);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference CreateAbandonedProvider()
    {
        var provider = DeepMlKemNativeProvider.LoadApprovedForCurrentProcess();
        return new WeakReference(provider);
    }

    private static DeepMlKemApprovedAsset RequireWindowsAndStageApprovedAsset(
        bool corrupt = false)
    {
        Assert.True(OperatingSystem.IsWindows());
        var approved = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => DeepMlKemApprovedAssets.WindowsX64,
            Architecture.Arm64 => DeepMlKemApprovedAssets.WindowsArm64,
            _ => throw new PlatformNotSupportedException(
                "The reviewed Windows ML-KEM assets support x64 and arm64.")
        };
        var source = FindReviewedWindowsAsset(approved);
        var destination = Path.Combine(
            AppContext.BaseDirectory,
            approved.RelativePath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        if (!corrupt && File.Exists(destination))
        {
            var digest = SHA256.HashData(File.ReadAllBytes(destination));
            if (CryptographicOperations.FixedTimeEquals(
                    digest,
                    Convert.FromHexString(approved.Sha256)))
                return approved;
        }
        File.Copy(source, destination, overwrite: true);
        if (corrupt)
        {
            using var stream = new FileStream(destination, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            stream.Position = 100;
            var value = stream.ReadByte();
            stream.Position = 100;
            stream.WriteByte(checked((byte)(value ^ 0x80)));
            stream.Flush(flushToDisk: true);
        }
        return approved;
    }

    private static string FindReviewedWindowsAsset(DeepMlKemApprovedAsset approved)
    {
        var explicitPath = Environment.GetEnvironmentVariable("DEEP_MLKEM_TEST_ASSET");
        if (!string.IsNullOrWhiteSpace(explicitPath) && File.Exists(explicitPath))
            return Path.GetFullPath(explicitPath);
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(
                current.FullName,
                "src", "Deep.Protocol",
                approved.RelativePath.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(candidate)) return candidate;
            current = current.Parent;
        }
        throw new FileNotFoundException(
            $"The reviewed {approved.RuntimeIdentifier} Deep ML-KEM asset is absent.");
    }
}
