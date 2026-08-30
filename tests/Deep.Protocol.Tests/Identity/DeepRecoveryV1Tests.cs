using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.Identity;
using Sodium;

namespace Deep.Protocol.Tests.Identity;

public sealed class DeepRecoveryV1Tests
{
    private const string WordListResource = "Deep.Protocol.Identity.Resources.Bip39.english.txt";
    private const string VectorResource = "Deep.Protocol.Tests.Identity.deep-recovery-v1.vector.json";

    [Fact]
    public void EncodeEntropy_MatchesOfficialBip39TwentyFourWordShape()
    {
        var vector = LoadVector();
        var entropy = Convert.FromHexString(vector.Entropy);
        try
        {
            var phrase = DeepRecoveryV1.EncodeEntropy(entropy);
            Assert.Equal(vector.Mnemonic, phrase);
            Assert.Equal(DeepRecoveryV1.WordCount, phrase.Split(' ').Length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    [Fact]
    public void Verify_NormalizesCaseAndUnicodeWhitespace()
    {
        var vector = LoadVector();
        var mixed = "\t" + vector.Mnemonic
            .ToUpperInvariant()
            .Replace(" ", "\r\n\u00a0", StringComparison.Ordinal) + "\u00a0";

        using var verified = DeepRecoveryV1.Verify(mixed);

        Assert.Equal(vector.Mnemonic, verified.CanonicalPhrase);
    }

    [Theory]
    [InlineData("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")]
    [InlineData("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")]
    public void Verify_RejectsTwelveAndThirteenWordPhrases(string phrase)
    {
        var exception = Assert.Throws<ArgumentException>(() => DeepRecoveryV1.Verify(phrase));

        Assert.Contains("exactly 24 words", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Verify_RejectsUnknownWordBeforeDerivation()
    {
        var words = LoadVector().Mnemonic.Split(' ');
        words[7] = "notaword";

        var exception = Assert.Throws<ArgumentException>(() => DeepRecoveryV1.Verify(string.Join(' ', words)));

        Assert.Contains("unknown", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_RejectsOversizedInputBeforeNormalization()
    {
        var exception = Assert.Throws<ArgumentException>(() => DeepRecoveryV1.Verify(new string('a', 1025)));

        Assert.Contains("too large", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_RejectsChecksumMutation()
    {
        var words = LoadVector().Mnemonic.Split(' ');
        words[^1] = "zoo";

        var exception = Assert.Throws<ArgumentException>(() => DeepRecoveryV1.Verify(string.Join(' ', words)));

        Assert.Contains("checksum", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DeriveAccountCapabilities_MatchesIndependentPythonVector()
    {
        var vector = LoadVector();
        using var phrase = DeepRecoveryV1.Verify(vector.Mnemonic);
        using var capabilities = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase,
            Convert.FromHexString(vector.NetworkId),
            ulong.Parse(vector.AccountGeneration, System.Globalization.CultureInfo.InvariantCulture));

        Assert.Equal(vector.AccountSigningSeed, Hex(capabilities.SnapshotAccountSigningSeed()));
        Assert.Equal(vector.DeviceIssuerSigningSeed, Hex(capabilities.SnapshotDeviceIssuerSigningSeed()));
        Assert.Equal(vector.AccountRevocationSigningSeed, Hex(capabilities.SnapshotAccountRevocationSigningSeed()));
        Assert.Equal(vector.ResetControlSigningSeed, Hex(capabilities.SnapshotResetControlSigningSeed()));
        Assert.Equal(vector.AddressSigningSeed, Hex(capabilities.SnapshotAddressSigningSeed()));
        Assert.Equal(vector.AddressReadCapability, Hex(capabilities.SnapshotAddressReadCapability()));
        Assert.Equal(vector.BackupWrappingSeed, Hex(capabilities.SnapshotBackupWrappingSeed()));
        Assert.Equal(Convert.FromHexString(vector.NetworkId), capabilities.NetworkId.ToArray());
    }

    [Fact]
    public void DeriveAccountCapabilities_SeparatesRolesNetworkAndGeneration_WhileAddressIsPermanent()
    {
        var vector = LoadVector();
        using var phrase = DeepRecoveryV1.Verify(vector.Mnemonic);
        var network = Convert.FromHexString(vector.NetworkId);
        using var generationOne = DeepRecoveryV1.DeriveAccountCapabilities(phrase, network, 1);
        using var generationTwo = DeepRecoveryV1.DeriveAccountCapabilities(phrase, network, 2);
        network[0] ^= 0xff;
        using var otherNetwork = DeepRecoveryV1.DeriveAccountCapabilities(phrase, network, 1);

        var roleSeedHex = new[]
        {
            Hex(generationOne.SnapshotAccountSigningSeed()),
            Hex(generationOne.SnapshotDeviceIssuerSigningSeed()),
            Hex(generationOne.SnapshotAccountRevocationSigningSeed()),
            Hex(generationOne.SnapshotResetControlSigningSeed()),
            Hex(generationOne.SnapshotAddressSigningSeed()),
            Hex(generationOne.SnapshotBackupWrappingSeed())
        };
        Assert.Equal(roleSeedHex.Length, roleSeedHex.Distinct(StringComparer.Ordinal).Count());
        Assert.NotEqual(roleSeedHex[0], Hex(generationTwo.SnapshotAccountSigningSeed()));
        Assert.NotEqual(roleSeedHex[0], Hex(otherNetwork.SnapshotAccountSigningSeed()));
        Assert.Equal(
            Hex(generationOne.SnapshotAddressSigningSeed()),
            Hex(generationTwo.SnapshotAddressSigningSeed()));
        Assert.Equal(
            Hex(generationOne.SnapshotAddressReadCapability()),
            Hex(otherNetwork.SnapshotAddressReadCapability()));
    }

    [Fact]
    public void DeriveAccountCapabilities_RejectsZeroGenerationWrongNetworkAndDisposedPhrase()
    {
        using var live = DeepRecoveryV1.Generate();
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            DeepRecoveryV1.DeriveAccountCapabilities(live, new byte[DeepRecoveryV1.NetworkIdSize], 0));
        Assert.Throws<ArgumentException>(() =>
            DeepRecoveryV1.DeriveAccountCapabilities(live, new byte[15], 1));

        var disposed = DeepRecoveryV1.Generate();
        disposed.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            DeepRecoveryV1.DeriveAccountCapabilities(disposed, new byte[DeepRecoveryV1.NetworkIdSize], 1));
    }

    [Fact]
    public void AccountCapabilities_ReturnDefensiveNetworkAndPublicKeyCopies()
    {
        using var phrase = DeepRecoveryV1.Generate();
        var network = Enumerable.Range(0, DeepRecoveryV1.NetworkIdSize).Select(static value => (byte)value).ToArray();
        using var capabilities = DeepRecoveryV1.DeriveAccountCapabilities(phrase, network, 7);

        network[0] ^= 0xff;
        var firstNetwork = capabilities.NetworkId.ToArray();
        firstNetwork[1] ^= 0xff;
        var firstKey = capabilities.AccountSigningPublicKey.ToArray();
        firstKey[0] ^= 0xff;
        var firstReadCapability = capabilities.AddressReadCapability.ToArray();
        firstReadCapability[0] ^= 0xff;

        Assert.Equal(0, capabilities.NetworkId.Span[0]);
        Assert.Equal(1, capabilities.NetworkId.Span[1]);
        Assert.NotEqual(firstKey, capabilities.AccountSigningPublicKey.ToArray());
        Assert.NotEqual(firstReadCapability, capabilities.AddressReadCapability.ToArray());
    }

    [Fact]
    public void RoleSpecificSigningCapabilities_UseIndependentEd25519Keys()
    {
        using var phrase = DeepRecoveryV1.Verify(LoadVector().Mnemonic);
        using var capabilities = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase,
            Convert.FromHexString(LoadVector().NetworkId),
            1);
        var message = SHA256.HashData("bounded identity authoring input"u8);

        var accountSignature = capabilities.SignAccount(message);
        var deviceSignature = capabilities.SignDeviceCertificate(message);

        Assert.True(PublicKeyAuth.VerifyDetached(
            accountSignature, message, capabilities.AccountSigningPublicKey.ToArray()));
        Assert.True(PublicKeyAuth.VerifyDetached(
            deviceSignature, message, capabilities.DeviceIssuerSigningPublicKey.ToArray()));
        Assert.False(PublicKeyAuth.VerifyDetached(
            accountSignature, message, capabilities.DeviceIssuerSigningPublicKey.ToArray()));
        Assert.False(PublicKeyAuth.VerifyDetached(
            deviceSignature, message, capabilities.AccountSigningPublicKey.ToArray()));
    }

    [Fact]
    public void RoleSpecificSigningCapabilities_RejectEmptyAndOversizedInputBeforeAllocation()
    {
        using var phrase = DeepRecoveryV1.Verify(LoadVector().Mnemonic);
        using var capabilities = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase,
            Convert.FromHexString(LoadVector().NetworkId),
            1);

        Assert.Throws<ArgumentException>(() => capabilities.SignAccount([]));
        Assert.Throws<ArgumentException>(() => capabilities.SignAccount(new byte[(64 * 1024) + 1]));
    }

    [Fact]
    public void Generate_ReturnsRoundTrippableTwentyFourWordPhrase()
    {
        using var generated = DeepRecoveryV1.Generate();
        var phrase = generated.CanonicalPhrase;
        using var reparsed = DeepRecoveryV1.Verify(phrase);

        Assert.Equal(DeepRecoveryV1.WordCount, phrase.Split(' ').Length);
        Assert.Equal(phrase, reparsed.CanonicalPhrase);
    }

    [Fact]
    public void DisposingCapabilities_ZeroesEveryOwnedSecretBuffer()
    {
        var vector = LoadVector();
        var phrase = DeepRecoveryV1.Verify(vector.Mnemonic);
        var phraseEntropy = GetBuffer(phrase, "entropy");
        var capabilities = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase,
            Convert.FromHexString(vector.NetworkId),
            1);
        var capabilityBuffers = new[]
        {
            GetBuffer(capabilities, "accountSigningSeed"),
            GetBuffer(capabilities, "deviceIssuerSigningSeed"),
            GetBuffer(capabilities, "accountRevocationSigningSeed"),
            GetBuffer(capabilities, "resetControlSigningSeed"),
            GetBuffer(capabilities, "addressSigningSeed"),
            GetBuffer(capabilities, "addressReadCapability"),
            GetBuffer(capabilities, "backupWrappingSeed")
        };

        Assert.All(capabilityBuffers, static buffer => Assert.Contains(buffer, static value => value != 0));
        phrase.Dispose();
        capabilities.Dispose();

        Assert.All(phraseEntropy, static value => Assert.Equal(0, value));
        Assert.All(capabilityBuffers.SelectMany(static value => value), static value => Assert.Equal(0, value));
        Assert.Throws<ObjectDisposedException>(() => _ = phrase.CanonicalPhrase);
        Assert.Throws<ObjectDisposedException>(() => _ = capabilities.NetworkId);
        Assert.Throws<ObjectDisposedException>(() => _ = capabilities.AddressReadCapability);
        Assert.Throws<ObjectDisposedException>(() => capabilities.SignAccount([1]));
    }

    [Fact]
    public void PublicSurface_IsSealedAndExportsNoRawOrPqOrKeyConversionSurface()
    {
        Assert.True(typeof(VerifiedDeepRecoveryPhrase).IsSealed);
        Assert.True(typeof(DeepRecoveryAccountCapabilities).IsSealed);
        Assert.Empty(typeof(VerifiedDeepRecoveryPhrase).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(DeepRecoveryAccountCapabilities).GetConstructors(BindingFlags.Public | BindingFlags.Instance));

        var publicMembers = typeof(DeepRecoveryAccountCapabilities)
            .GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(static member => member.Name)
            .ToArray();
        Assert.DoesNotContain(publicMembers, static name => name.Contains("Seed", StringComparison.Ordinal));
        Assert.DoesNotContain(publicMembers, static name => name.Contains("Entropy", StringComparison.Ordinal));
        Assert.DoesNotContain(publicMembers, static name => name.Contains("Pq", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(publicMembers, static name => name.Contains("X25519", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(publicMembers, static name => name.Contains("Convert", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("Deep.Protocol.Identity", typeof(DeepRecoveryV1).Namespace);
    }

    [Fact]
    public void EmbeddedWordList_MatchesPinnedOfficialAsset()
    {
        using var stream = typeof(DeepRecoveryV1).Assembly.GetManifestResourceStream(WordListResource);
        Assert.NotNull(stream);
        using var memory = new MemoryStream();
        stream!.CopyTo(memory);
        var canonical = System.Text.Encoding.UTF8.GetString(memory.ToArray()).Replace("\r\n", "\n", StringComparison.Ordinal);
        if (!canonical.EndsWith('\n'))
        {
            canonical += "\n";
        }

        var hash = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical)));

        Assert.Equal("2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", hash);
        Assert.Equal(2048, canonical.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);
    }

    private static byte[] GetBuffer(object instance, string name) =>
        Assert.IsType<byte[]>(instance.GetType()
            .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(instance));

    private static string Hex(byte[] value)
    {
        try
        {
            return Convert.ToHexStringLower(value);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private static RecoveryVector LoadVector()
    {
        using var stream = typeof(DeepRecoveryV1Tests).Assembly.GetManifestResourceStream(VectorResource);
        Assert.NotNull(stream);
        return JsonSerializer.Deserialize<RecoveryVector>(
            stream!,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidOperationException("Recovery vector is empty.");
    }

    private sealed record RecoveryVector(
        string AccountGeneration,
        string AccountRevocationSigningSeed,
        string AccountSigningSeed,
        string AddressReadCapability,
        string AddressSigningSeed,
        string BackupWrappingSeed,
        string Bip39Seed,
        string DeviceIssuerSigningSeed,
        string Entropy,
        string Mnemonic,
        string NetworkId,
        string ResetControlSigningSeed);
}
