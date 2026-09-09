using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class DeepMlKemBraidNativeProviderTests
{
    [Theory]
    [InlineData("", "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A")]
    [InlineData("616263", "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532")]
    public void PortableSha3MatchesNistVectors(string inputHex, string expectedHex)
    {
        var input = Convert.FromHexString(inputHex);
        var actual = PortableSha3_256.HashConcat(input, []);
        try { Assert.Equal(expectedHex, Convert.ToHexString(actual)); }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(135)]
    [InlineData(136)]
    [InlineData(137)]
    [InlineData(1184)]
    public void PortableSha3MatchesPlatformAcrossRateBoundaries(int length)
    {
        var input = Sequence(length, 0x29);
        var portable = PortableSha3_256.HashConcat(input.AsSpan(0, length / 2), input.AsSpan(length / 2));
        var platform = SHA3_256.HashData(input);
        try { Assert.Equal(platform, portable); }
        finally { Zero(input, portable, platform); }
    }

    [Fact]
    public void AbiIdentitySizesAndProductionApprovalFailClosed()
    {
        var wrongIdentity = new RecordingAbi();
        Assert.Throws<CryptographicException>(() =>
            new DeepMlKemBraidNativeProvider(wrongIdentity, "unreviewed/provider"));
        Assert.Equal(1, wrongIdentity.DisposeCount);

        var wrongSizes = new RecordingAbi { Ciphertext2Size = 127 };
        Assert.Throws<CryptographicException>(() =>
            new DeepMlKemBraidNativeProvider(wrongSizes, DeepMlKemBraidNativeProvider.Identifier));
        Assert.Equal(1, wrongSizes.DisposeCount);

        DeepMlKemBraidNativeProvider.ValidateApprovedAssetIdentity(
            DeepMlKemBraidApprovedAssets.WindowsX64Candidate,
            requireProductionApproval: false);
        Assert.Equal(526336, DeepMlKemBraidApprovedAssets.WindowsX64Candidate.Bytes);
        Assert.Equal(
            "41ba8b15429bfc55b6a66cdadbb1ad3372dfc98a9f2bd1bce75a86d54426cd25",
            DeepMlKemBraidApprovedAssets.WindowsX64Candidate.Sha256);
        Assert.False(DeepMlKemBraidApprovedAssets.WindowsX64Candidate.ApprovedForProduction);
        Assert.Throws<CryptographicException>(() =>
            DeepMlKemBraidNativeProvider.ValidateApprovedAssetIdentity(
                DeepMlKemBraidApprovedAssets.WindowsX64Candidate,
                requireProductionApproval: true));
        Assert.Throws<PlatformNotSupportedException>(
            DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess);
    }

    [Fact]
    public void OwnedStateIsSingleUseAndDisposeZeroesAllOwnedKeyMaterial()
    {
        var abi = new RecordingAbi();
        using var provider = new DeepMlKemBraidNativeProvider(
            abi,
            DeepMlKemBraidNativeProvider.Identifier);
        var keyPair = provider.GenerateKeyPairFromRandomForTests(Fill(0x11, 64));
        var vector = keyPair.EncapsulationKeyVector.ToArray();
        var seed = keyPair.EncapsulationKeySeed.ToArray();
        var hash = keyPair.EncapsulationKeyHash.ToArray();
        var ciphertext1 = new byte[DeepMlKemBraidNativeProvider.Ciphertext1Size];
        using var state = provider.Encapsulate1FromRandom(
            seed, hash, Fill(0x22, 32), ciphertext1);
        var ciphertext2 = new byte[DeepMlKemBraidNativeProvider.Ciphertext2Size];
        var senderSecret = new byte[DeepMlKemBraidNativeProvider.SharedSecretSize];
        var recipientSecret = new byte[DeepMlKemBraidNativeProvider.SharedSecretSize];
        try
        {
            provider.Encapsulate2(state, seed, vector, ciphertext2, senderSecret);
            var standardCiphertext = ciphertext1.Concat(ciphertext2).ToArray();
            try
            {
                keyPair.UseDecapsulationKey(key =>
                    provider.Decapsulate(key, standardCiphertext, recipientSecret));
                Assert.True(CryptographicOperations.FixedTimeEquals(senderSecret, recipientSecret));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(standardCiphertext);
            }

            var replayError = Assert.Throws<MessagingCryptoException>(() =>
                provider.Encapsulate2(
                    state, seed, vector,
                    new byte[DeepMlKemBraidNativeProvider.Ciphertext2Size],
                    new byte[DeepMlKemBraidNativeProvider.SharedSecretSize]));
            Assert.Equal(MessagingCryptoError.CapabilityConsumed, replayError.Error);
            Assert.Equal(1, abi.Encapsulate2Count);

            var ownedArrays = GetOwnedPublicArrays(keyPair);
            Assert.All(ownedArrays, static value => Assert.Contains(value, static item => item != 0));
            keyPair.Dispose();
            keyPair.Dispose();
            Assert.All(ownedArrays, static value => Assert.All(value, static item => Assert.Equal(0, item)));
            var disposedError = Assert.Throws<MessagingCryptoException>(() =>
                _ = keyPair.EncapsulationKeyVector);
            Assert.Equal(MessagingCryptoError.ObjectDisposed, disposedError.Error);
        }
        finally
        {
            keyPair.Dispose();
            CryptographicOperations.ZeroMemory(vector);
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(ciphertext1);
            CryptographicOperations.ZeroMemory(ciphertext2);
            CryptographicOperations.ZeroMemory(senderSecret);
            CryptographicOperations.ZeroMemory(recipientSecret);
        }
    }

    [Fact]
    public async Task ConcurrentEncaps2HasExactlyOneManagedConsumer()
    {
        var abi = new RecordingAbi();
        using var provider = new DeepMlKemBraidNativeProvider(
            abi,
            DeepMlKemBraidNativeProvider.Identifier);
        using var keyPair = provider.GenerateKeyPairFromRandomForTests(Fill(0x31, 64));
        var seed = keyPair.EncapsulationKeySeed.ToArray();
        var hash = keyPair.EncapsulationKeyHash.ToArray();
        var vector = keyPair.EncapsulationKeyVector.ToArray();
        using var state = provider.Encapsulate1FromRandom(
            seed,
            hash,
            Fill(0x42, 32),
            new byte[DeepMlKemBraidNativeProvider.Ciphertext1Size]);
        try
        {
            using var start = new ManualResetEventSlim();
            Task<MessagingCryptoError?> Invoke() => Task.Run<MessagingCryptoError?>(() =>
            {
                start.Wait();
                try
                {
                    provider.Encapsulate2(
                        state,
                        seed,
                        vector,
                        new byte[DeepMlKemBraidNativeProvider.Ciphertext2Size],
                        new byte[DeepMlKemBraidNativeProvider.SharedSecretSize]);
                    return null;
                }
                catch (MessagingCryptoException exception)
                {
                    return exception.Error;
                }
            });

            var first = Invoke();
            var second = Invoke();
            start.Set();
            var results = await Task.WhenAll(first, second);
            Assert.Equal(1, results.Count(static result => result is null));
            Assert.Equal(1, results.Count(static result => result == MessagingCryptoError.CapabilityConsumed));
            Assert.Equal(1, abi.Encapsulate2Count);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(vector);
        }
    }

    [Fact]
    public void CallerEntropyRecreatesEncaps1StateWithoutSerializingNativeHandle()
    {
        using var provider = new DeepMlKemBraidNativeProvider(
            new RecordingAbi(),
            DeepMlKemBraidNativeProvider.Identifier);
        using var keyPair = provider.GenerateKeyPairFromRandomForTests(Fill(0x61, 64));
        var seed = keyPair.EncapsulationKeySeed.ToArray();
        var hash = keyPair.EncapsulationKeyHash.ToArray();
        var vector = keyPair.EncapsulationKeyVector.ToArray();
        var entropy = Fill(0x62, DeepMlKemBraidNativeProvider.EncapsulationRandomSize);
        var firstCiphertext = new byte[DeepMlKemBraidNativeProvider.Ciphertext1Size];
        var restoredCiphertext = new byte[DeepMlKemBraidNativeProvider.Ciphertext1Size];
        var ciphertext2 = new byte[DeepMlKemBraidNativeProvider.Ciphertext2Size];
        var sharedSecret = new byte[DeepMlKemBraidNativeProvider.SharedSecretSize];
        try
        {
            using (provider.Encapsulate1FromRandom(seed, hash, entropy, firstCiphertext))
            {
                // Simulate a crash boundary: the process-local handle is
                // discarded while only caller-owned entropy remains durable.
            }
            using var restored = provider.Encapsulate1FromRandom(
                seed, hash, entropy, restoredCiphertext);
            Assert.Equal(firstCiphertext, restoredCiphertext);
            provider.Encapsulate2(restored, seed, vector, ciphertext2, sharedSecret);
            Assert.False(MessagingCryptoValidation.IsZero(sharedSecret));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(vector);
            CryptographicOperations.ZeroMemory(entropy);
            CryptographicOperations.ZeroMemory(firstCiphertext);
            CryptographicOperations.ZeroMemory(restoredCiphertext);
            CryptographicOperations.ZeroMemory(ciphertext2);
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    [Fact]
    public void BoundaryFailureFreesUnconsumedHandleAndClearsOutputs()
    {
        var abi = new RecordingAbi { ThrowBeforeEncapsulate2 = true };
        using var provider = new DeepMlKemBraidNativeProvider(
            abi,
            DeepMlKemBraidNativeProvider.Identifier);
        using var keyPair = provider.GenerateKeyPairFromRandomForTests(Fill(0x51, 64));
        var seed = keyPair.EncapsulationKeySeed.ToArray();
        var hash = keyPair.EncapsulationKeyHash.ToArray();
        var vector = keyPair.EncapsulationKeyVector.ToArray();
        var ciphertext1 = new byte[DeepMlKemBraidNativeProvider.Ciphertext1Size];
        using var state = provider.Encapsulate1FromRandom(
            seed, hash, Fill(0x62, 32), ciphertext1);
        var ciphertext2 = Fill(0xa5, DeepMlKemBraidNativeProvider.Ciphertext2Size);
        var secret = Fill(0xa5, DeepMlKemBraidNativeProvider.SharedSecretSize);
        try
        {
            var error = Assert.Throws<MessagingCryptoException>(() =>
                provider.Encapsulate2(state, seed, vector, ciphertext2, secret));
            Assert.Equal(MessagingCryptoError.ProviderFailure, error.Error);
            Assert.Equal(1, abi.StateFreeCount);
            Assert.All(ciphertext2, static value => Assert.Equal(0, value));
            Assert.All(secret, static value => Assert.Equal(0, value));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(vector);
            CryptographicOperations.ZeroMemory(ciphertext1);
            CryptographicOperations.ZeroMemory(ciphertext2);
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    [Fact]
    public void NativeStateCapacityFailureIsFailClosedAndClearsCiphertext()
    {
        var abi = new RecordingAbi { Encapsulate1Status = 7 };
        using var provider = new DeepMlKemBraidNativeProvider(
            abi,
            DeepMlKemBraidNativeProvider.Identifier);
        using var keyPair = provider.GenerateKeyPairFromRandomForTests(Fill(0x63, 64));
        var seed = keyPair.EncapsulationKeySeed.ToArray();
        var hash = keyPair.EncapsulationKeyHash.ToArray();
        var ciphertext1 = Fill(0xa5, DeepMlKemBraidNativeProvider.Ciphertext1Size);
        try
        {
            var error = Assert.Throws<MessagingCryptoException>(() =>
                provider.Encapsulate1FromRandom(seed, hash, Fill(0x64, 32), ciphertext1));
            Assert.Equal(MessagingCryptoError.ProviderFailure, error.Error);
            Assert.All(ciphertext1, static value => Assert.Equal(0, value));
            Assert.Equal(0, abi.ActiveStateCount);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(ciphertext1);
        }
    }

    [Fact]
    public void AbandonedStatesAreFreedExactlyOnceByStateOrProviderDispose()
    {
        var abi = new RecordingAbi();
        var provider = new DeepMlKemBraidNativeProvider(
            abi,
            DeepMlKemBraidNativeProvider.Identifier);
        using var keyPair = provider.GenerateKeyPairFromRandomForTests(Fill(0x71, 64));
        var seed = keyPair.EncapsulationKeySeed.ToArray();
        var hash = keyPair.EncapsulationKeyHash.ToArray();
        try
        {
            var first = provider.Encapsulate1FromRandom(
                seed, hash, Fill(0x72, 32),
                new byte[DeepMlKemBraidNativeProvider.Ciphertext1Size]);
            var second = provider.Encapsulate1FromRandom(
                seed, hash, Fill(0x73, 32),
                new byte[DeepMlKemBraidNativeProvider.Ciphertext1Size]);
            first.Dispose();
            first.Dispose();
            Assert.Equal(1, abi.StateFreeCount);
            provider.Dispose();
            provider.Dispose();
            second.Dispose();
            Assert.Equal(2, abi.StateFreeCount);
            Assert.Equal(1, abi.DisposeCount);
        }
        finally
        {
            provider.Dispose();
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    [Fact]
    public void AbandonedProviderFinalizerReleasesTrackedNativeState()
    {
        var abi = new RecordingAbi();
        var abandoned = CreateAbandonedProviderWithState(abi);
        for (var attempt = 0; attempt < 10 && abandoned.IsAlive; attempt++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }
        Assert.False(abandoned.IsAlive);
        Assert.Equal(1, abi.StateFreeCount);
        Assert.Equal(1, abi.DisposeCount);
    }

    [Fact]
    public void KeyPairConstructionAbortDisposesOwnedDecapsulationKey()
    {
        SecretBuffer? captured = null;
        using (MessagingCryptoFaultInjection.InstallDarkForTests(
                   new MessagingCryptoFaultProbe
                   {
                       OwnedSecret = (name, value) =>
                       {
                           if (name != "braid.native.decapsulation-key") return;
                           captured = value;
                           throw new InvalidOperationException("injected key-pair construction abort");
                       },
                   }))
        {
            Assert.Throws<InvalidOperationException>(() =>
                new OwnedDeepMlKemBraidKeyPair(
                    Fill(0x81, DeepMlKemBraidNativeProvider.DecapsulationKeySize),
                    Fill(0x82, DeepMlKemBraidNativeProvider.EncapsulationKeyVectorSize),
                    Fill(0x83, DeepMlKemBraidNativeProvider.EncapsulationKeySeedSize),
                    Fill(0x84, DeepMlKemBraidNativeProvider.EncapsulationKeyHashSize)));
        }

        Assert.NotNull(captured);
        var error = Assert.Throws<MessagingCryptoException>(() => captured!.Use(static _ => { }));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, error.Error);
    }

    [Fact(Skip = "Executed by the explicit Windows x64 incremental Braid wrapper evidence harness.")]
    public void WindowsX64_IncrementalWrapperInteropsWithStandardProviderBothDirections()
    {
        RequireWindowsX64AndStageAssets();
        using var braid = DeepMlKemBraidNativeProvider.LoadCandidateForTests(
            DeepMlKemBraidApprovedAssets.WindowsX64Candidate);
        using var standard = DeepMlKemNativeProvider.LoadApprovedForCurrentProcess();

        using var braidKeys = braid.GenerateKeyPairFromRandomForTests(Sequence(64, 0x00));
        var braidVector = braidKeys.EncapsulationKeyVector.ToArray();
        var braidSeed = braidKeys.EncapsulationKeySeed.ToArray();
        var standardPublic = braidVector.Concat(braidSeed).ToArray();
        var standardCiphertext = new byte[DeepMlKemBraidNativeProvider.CiphertextSize];
        var standardSenderSecret = new byte[DeepMlKemBraidNativeProvider.SharedSecretSize];
        var braidRecipientSecret = new byte[DeepMlKemBraidNativeProvider.SharedSecretSize];
        try
        {
            standard.Encapsulate(standardPublic, standardCiphertext, standardSenderSecret);
            braidKeys.UseDecapsulationKey(key =>
                braid.Decapsulate(key, standardCiphertext, braidRecipientSecret));
            Assert.True(CryptographicOperations.FixedTimeEquals(
                standardSenderSecret, braidRecipientSecret));

            using var standardKeys = standard.GenerateKeyPair();
            var publicKey = standardKeys.EncapsulationKey.ToArray();
            var vector = publicKey.AsSpan(0, 1152).ToArray();
            var seed = publicKey.AsSpan(1152, 32).ToArray();
            var hash = ManagedMlKemBraidAuthenticator.ComputeEncapsulationKeyHash(seed, vector);
            var ct1 = new byte[DeepMlKemBraidNativeProvider.Ciphertext1Size];
            var ct2 = new byte[DeepMlKemBraidNativeProvider.Ciphertext2Size];
            var braidSenderSecret = new byte[DeepMlKemBraidNativeProvider.SharedSecretSize];
            var standardRecipientSecret = new byte[DeepMlKemBraidNativeProvider.SharedSecretSize];
            try
            {
                using var state = braid.Encapsulate1FromRandom(
                    seed, hash, Sequence(32, 0xa0), ct1);
                braid.Encapsulate2(state, seed, vector, ct2, braidSenderSecret);
                var ciphertext = ct1.Concat(ct2).ToArray();
                try
                {
                    standardKeys.UseDecapsulationKey(key =>
                        standard.Decapsulate(key, ciphertext, standardRecipientSecret));
                    Assert.True(CryptographicOperations.FixedTimeEquals(
                        braidSenderSecret, standardRecipientSecret));
                }
                finally { CryptographicOperations.ZeroMemory(ciphertext); }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicKey);
                CryptographicOperations.ZeroMemory(vector);
                CryptographicOperations.ZeroMemory(seed);
                CryptographicOperations.ZeroMemory(hash);
                CryptographicOperations.ZeroMemory(ct1);
                CryptographicOperations.ZeroMemory(ct2);
                CryptographicOperations.ZeroMemory(braidSenderSecret);
                CryptographicOperations.ZeroMemory(standardRecipientSecret);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(braidVector);
            CryptographicOperations.ZeroMemory(braidSeed);
            CryptographicOperations.ZeroMemory(standardPublic);
            CryptographicOperations.ZeroMemory(standardCiphertext);
            CryptographicOperations.ZeroMemory(standardSenderSecret);
            CryptographicOperations.ZeroMemory(braidRecipientSecret);
        }
    }

    [Fact(Skip = "Executed by the explicit Windows x64 incremental Braid wrapper evidence harness.")]
    public void WindowsX64_DigestAndProductionApprovalAreFailClosed()
    {
        RequireWindowsX64AndStageAssets(corruptBraid: true);
        Assert.Throws<CryptographicException>(() =>
            DeepMlKemBraidNativeProvider.LoadCandidateForTests(
                DeepMlKemBraidApprovedAssets.WindowsX64Candidate));
        RequireWindowsX64AndStageAssets();
        Assert.Throws<CryptographicException>(() =>
            DeepMlKemBraidDynamicAbi.LoadApproved(
                DeepMlKemBraidApprovedAssets.WindowsX64Candidate));
    }

    [Fact(Skip = "Executed by the explicit Windows x64 incremental Braid wrapper evidence harness.")]
    public async Task WindowsX64_RealNativeStateIsSingleConsumerUnderContention()
    {
        RequireWindowsX64AndStageAssets();
        using var provider = DeepMlKemBraidNativeProvider.LoadCandidateForTests(
            DeepMlKemBraidApprovedAssets.WindowsX64Candidate);
        using var keys = provider.GenerateKeyPairFromRandomForTests(Sequence(64, 0x20));
        var seed = keys.EncapsulationKeySeed.ToArray();
        var hash = keys.EncapsulationKeyHash.ToArray();
        var vector = keys.EncapsulationKeyVector.ToArray();
        using var state = provider.Encapsulate1FromRandom(
            seed, hash, Sequence(32, 0x40),
            new byte[DeepMlKemBraidNativeProvider.Ciphertext1Size]);
        try
        {
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
            var results = await Task.WhenAll(first, second);
            Assert.Equal(1, results.Count(static value => value is null));
            Assert.Equal(1, results.Count(static value => value == MessagingCryptoError.CapabilityConsumed));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(vector);
        }
    }

    private static byte[][] GetOwnedPublicArrays(OwnedDeepMlKemBraidKeyPair keyPair) =>
        new[] { "_encapsulationKeyVector", "_encapsulationKeySeed", "_encapsulationKeyHash" }
            .Select(name => (byte[])typeof(OwnedDeepMlKemBraidKeyPair)
                .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!
                .GetValue(keyPair)!)
            .ToArray();

    [System.Runtime.CompilerServices.MethodImpl(
        System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static WeakReference CreateAbandonedProviderWithState(RecordingAbi abi)
    {
        var provider = new DeepMlKemBraidNativeProvider(
            abi,
            DeepMlKemBraidNativeProvider.Identifier);
        using var keys = provider.GenerateKeyPairFromRandomForTests(Fill(0x91, 64));
        var seed = keys.EncapsulationKeySeed.ToArray();
        var hash = keys.EncapsulationKeyHash.ToArray();
        try
        {
            _ = provider.Encapsulate1FromRandom(
                seed, hash, Fill(0x92, 32),
                new byte[DeepMlKemBraidNativeProvider.Ciphertext1Size]);
            return new WeakReference(provider);
        }
        finally { Zero(seed, hash); }
    }

    private static void RequireWindowsX64AndStageAssets(bool corruptBraid = false)
    {
        Assert.True(OperatingSystem.IsWindows());
        Assert.Equal(Architecture.X64, RuntimeInformation.ProcessArchitecture);
        Stage(
            FindAsset("DEEP_MLKEM_BRAID_TEST_ASSET", "native", "Deep.MlKemBraid", "target",
                "x86_64-pc-windows-msvc", "release", "deep_mlkem_braid.dll"),
            DeepMlKemBraidApprovedAssets.WindowsX64Candidate.RelativePath,
            corruptBraid);
        Stage(
            FindAsset("DEEP_MLKEM_TEST_ASSET", "native", "Deep.MlKem", "artifacts",
                "windows-x64", "deep_mlkem.dll"),
            DeepMlKemApprovedAssets.WindowsX64.RelativePath,
            corrupt: false);
    }

    private static void Stage(string source, string relativePath, bool corrupt)
    {
        var destination = Path.Combine(
            AppContext.BaseDirectory,
            relativePath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        if (!corrupt && File.Exists(destination))
        {
            var sourceHash = SHA256.HashData(File.ReadAllBytes(source));
            var destinationHash = SHA256.HashData(File.ReadAllBytes(destination));
            try
            {
                if (CryptographicOperations.FixedTimeEquals(sourceHash, destinationHash)) return;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sourceHash);
                CryptographicOperations.ZeroMemory(destinationHash);
            }
        }
        File.Copy(source, destination, overwrite: true);
        if (!corrupt) return;
        using var stream = new FileStream(destination, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        stream.Position = 128;
        var value = stream.ReadByte();
        stream.Position = 128;
        stream.WriteByte(checked((byte)(value ^ 0x80)));
        stream.Flush(flushToDisk: true);
    }

    private static string FindAsset(string environmentName, params string[] relativeParts)
    {
        var explicitPath = Environment.GetEnvironmentVariable(environmentName);
        if (!string.IsNullOrWhiteSpace(explicitPath) && File.Exists(explicitPath))
            return Path.GetFullPath(explicitPath);
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine([current.FullName, .. relativeParts]);
            if (File.Exists(candidate)) return candidate;
            current = current.Parent;
        }
        throw new FileNotFoundException($"The reviewed native asset for {environmentName} is absent.");
    }

    private static byte[] Fill(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private static byte[] Sequence(int length, byte start) =>
        Enumerable.Range(0, length).Select(value => unchecked((byte)(start + value))).ToArray();

    private static void Zero(params byte[][] values)
    {
        foreach (var value in values)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private sealed class RecordingAbi : IDeepMlKemBraidAbi
    {
        private readonly HashSet<ulong> _states = [];
        private ulong _nextHandle = 1;

        public nuint KeygenRandomSize { get; set; } = 64;
        public nuint DecapsulationKeySize { get; set; } = 2400;
        public nuint EncapsulationKeySeedSize { get; set; } = 32;
        public nuint EncapsulationKeyHashSize { get; set; } = 32;
        public nuint EncapsulationKeyVectorSize { get; set; } = 1152;
        public nuint EncapsulationRandomSize { get; set; } = 32;
        public nuint Ciphertext1Size { get; set; } = 960;
        public nuint Ciphertext2Size { get; set; } = 128;
        public nuint SharedSecretSize { get; set; } = 32;
        public bool ThrowBeforeEncapsulate2 { get; set; }
        public int Encapsulate1Status { get; set; }
        public int Encapsulate2Count { get; private set; }
        public int StateFreeCount { get; private set; }
        public int DisposeCount { get; private set; }
        public int ActiveStateCount => _states.Count;

        public int KeyPairFromRandom(
            ReadOnlySpan<byte> random,
            Span<byte> decapsulationKey,
            Span<byte> encapsulationKeyVector,
            Span<byte> encapsulationKeySeed,
            Span<byte> encapsulationKeyHash)
        {
            decapsulationKey.Fill(0xd1);
            encapsulationKeyVector.Fill(0xe2);
            encapsulationKeySeed.Fill(0xf3);
            var hash = ManagedMlKemBraidAuthenticator.ComputeEncapsulationKeyHash(
                encapsulationKeySeed,
                encapsulationKeyVector);
            try { hash.CopyTo(encapsulationKeyHash); }
            finally { CryptographicOperations.ZeroMemory(hash); }
            return 0;
        }

        public int KeyPairGenerate(
            Span<byte> decapsulationKey,
            Span<byte> encapsulationKeyVector,
            Span<byte> encapsulationKeySeed,
            Span<byte> encapsulationKeyHash) =>
            KeyPairFromRandom([], decapsulationKey, encapsulationKeyVector, encapsulationKeySeed,
                encapsulationKeyHash);

        public int Encapsulate1FromRandom(
            ReadOnlySpan<byte> encapsulationKeySeed,
            ReadOnlySpan<byte> encapsulationKeyHash,
            ReadOnlySpan<byte> random,
            Span<byte> ciphertext1,
            out ulong ownedState)
        {
            ciphertext1.Fill(0xc1);
            if (Encapsulate1Status != 0)
            {
                ownedState = 0;
                return Encapsulate1Status;
            }
            ownedState = _nextHandle++;
            _states.Add(ownedState);
            return 0;
        }

        public int Encapsulate1Generate(
            ReadOnlySpan<byte> encapsulationKeySeed,
            ReadOnlySpan<byte> encapsulationKeyHash,
            Span<byte> ciphertext1,
            out ulong ownedState) =>
            Encapsulate1FromRandom(encapsulationKeySeed, encapsulationKeyHash, [], ciphertext1,
                out ownedState);

        public int Encapsulate2(
            ulong ownedState,
            ReadOnlySpan<byte> encapsulationKeySeed,
            ReadOnlySpan<byte> encapsulationKeyVector,
            Span<byte> ciphertext2,
            Span<byte> sharedSecret)
        {
            Encapsulate2Count++;
            if (ThrowBeforeEncapsulate2)
                throw new InvalidOperationException("injected managed ABI boundary failure");
            if (!_states.Remove(ownedState)) return 4;
            ciphertext2.Fill(0xc2);
            sharedSecret.Fill(0x5a);
            return 0;
        }

        public int Decapsulate(
            ReadOnlySpan<byte> decapsulationKey,
            ReadOnlySpan<byte> ciphertext1,
            ReadOnlySpan<byte> ciphertext2,
            Span<byte> sharedSecret)
        {
            sharedSecret.Fill(0x5a);
            return 0;
        }

        public int StateFree(ulong ownedState)
        {
            StateFreeCount++;
            return _states.Remove(ownedState) ? 0 : 4;
        }

        public int Zero(Span<byte> buffer)
        {
            buffer.Clear();
            return 0;
        }

        public void Dispose() => DisposeCount++;
    }
}
