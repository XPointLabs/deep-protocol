using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

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
            using var verified = DeepRecoveryV1.VerifyCanonicalUtf8(
                Encoding.ASCII.GetBytes(vector.Mnemonic));
            var phrase = new byte[verified.CanonicalUtf8Length];
            Assert.Equal(phrase.Length, verified.WriteCanonicalUtf8(phrase));
            Assert.Equal(Encoding.ASCII.GetBytes(vector.Mnemonic), phrase);
            Assert.Equal(DeepRecoveryV1.WordCount - 1, phrase.Count(static value => value == (byte)' '));
            CryptographicOperations.ZeroMemory(phrase);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    [Fact]
    public void VerifyCanonicalUtf8_RejectsCaseAndNonAsciiWhitespace()
    {
        var vector = LoadVector();
        var mixed = "\t" + vector.Mnemonic
            .ToUpperInvariant()
            .Replace(" ", "\r\n\u00a0", StringComparison.Ordinal) + "\u00a0";

        Assert.Throws<ArgumentException>(() =>
            DeepRecoveryV1.VerifyCanonicalUtf8(Encoding.UTF8.GetBytes(mixed)));
    }

    [Theory]
    [InlineData(" abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")]
    [InlineData("abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")]
    [InlineData("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art ")]
    [InlineData("Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")]
    public void VerifyCanonicalUtf8_RejectsEveryNonCanonicalAsciiForm(string value)
    {
        Assert.Throws<ArgumentException>(() =>
            DeepRecoveryV1.VerifyCanonicalUtf8(Encoding.ASCII.GetBytes(value)));
    }

    [Fact]
    public void WriteCanonicalUtf8_ShortDestinationIsRejectedBeforeMutation()
    {
        using var phrase = VerifyVector(LoadVector().Mnemonic);
        var destination = Enumerable.Repeat((byte)0xa5, phrase.CanonicalUtf8Length - 1).ToArray();

        Assert.Throws<ArgumentException>(() => phrase.WriteCanonicalUtf8(destination));

        Assert.All(destination, static value => Assert.Equal(0xa5, value));
        CryptographicOperations.ZeroMemory(destination);
    }

    [Fact]
    public void UseCanonicalUtf8_ThrowKeepsPhraseUsableAndNeverExportsAString()
    {
        using var phrase = VerifyVector(LoadVector().Mnemonic);

        Assert.Throws<InjectedConsumerException>(() =>
            phrase.UseCanonicalUtf8(static _ => throw new InjectedConsumerException()));

        var encoded = new byte[phrase.CanonicalUtf8Length];
        phrase.WriteCanonicalUtf8(encoded);
        Assert.Equal(Encoding.ASCII.GetBytes(LoadVector().Mnemonic), encoded);
        CryptographicOperations.ZeroMemory(encoded);
    }

    [Theory]
    [InlineData("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")]
    [InlineData("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")]
    public void Verify_RejectsTwelveAndThirteenWordPhrases(string phrase)
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            DeepRecoveryV1.VerifyCanonicalUtf8(Encoding.ASCII.GetBytes(phrase)));

        Assert.Contains("exactly 24 words", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Verify_RejectsUnknownWordBeforeDerivation()
    {
        var words = LoadVector().Mnemonic.Split(' ');
        words[7] = "notaword";

        var exception = Assert.Throws<ArgumentException>(() =>
            DeepRecoveryV1.VerifyCanonicalUtf8(Encoding.ASCII.GetBytes(string.Join(' ', words))));

        Assert.Contains("unknown", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_RejectsOversizedInputBeforeNormalization()
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            DeepRecoveryV1.VerifyCanonicalUtf8(new byte[DeepRecoveryV1.MaxCanonicalUtf8Length + 1]));

        Assert.Contains("too large", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_RejectsChecksumMutation()
    {
        var words = LoadVector().Mnemonic.Split(' ');
        words[^1] = "zoo";

        var exception = Assert.Throws<ArgumentException>(() =>
            DeepRecoveryV1.VerifyCanonicalUtf8(Encoding.ASCII.GetBytes(string.Join(' ', words))));

        Assert.Contains("checksum", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DeriveAccountCapabilities_MatchesIndependentPythonVector()
    {
        var vector = LoadVector();
        using var phrase = VerifyVector(vector.Mnemonic);
        using var capabilities = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase,
            Convert.FromHexString(vector.NetworkId),
            ulong.Parse(vector.AccountGeneration, System.Globalization.CultureInfo.InvariantCulture));

        Assert.Equal(vector.AccountSigningSeed, Hex(SnapshotBuffer(capabilities, "accountSigningSeed")));
        Assert.Equal(vector.DeviceIssuerSigningSeed, Hex(SnapshotBuffer(capabilities, "deviceIssuerSigningSeed")));
        Assert.Equal(vector.AccountRevocationSigningSeed, Hex(SnapshotBuffer(capabilities, "accountRevocationSigningSeed")));
        Assert.Equal(vector.ResetControlSigningSeed, Hex(SnapshotBuffer(capabilities, "resetControlSigningSeed")));
        Assert.Equal(vector.AddressSigningSeed, Hex(SnapshotBuffer(capabilities, "addressSigningSeed")));
        Assert.Equal(vector.AddressReadCapability, Hex(SnapshotBuffer(capabilities, "addressReadCapability")));
        Assert.Equal(vector.BackupWrappingSeed, Hex(SnapshotBuffer(capabilities, "backupWrappingSeed")));
        Assert.Equal(Convert.FromHexString(vector.NetworkId), capabilities.NetworkId.ToArray());
    }

    [Fact]
    public void DeriveAccountCapabilities_SeparatesRolesNetworkAndGeneration_WhileAddressIsPermanent()
    {
        var vector = LoadVector();
        using var phrase = VerifyVector(vector.Mnemonic);
        var network = Convert.FromHexString(vector.NetworkId);
        using var generationOne = DeepRecoveryV1.DeriveAccountCapabilities(phrase, network, 1);
        using var generationTwo = DeepRecoveryV1.DeriveAccountCapabilities(phrase, network, 2);
        network[0] ^= 0xff;
        using var otherNetwork = DeepRecoveryV1.DeriveAccountCapabilities(phrase, network, 1);

        var roleSeedHex = new[]
        {
            Hex(SnapshotBuffer(generationOne, "accountSigningSeed")),
            Hex(SnapshotBuffer(generationOne, "deviceIssuerSigningSeed")),
            Hex(SnapshotBuffer(generationOne, "accountRevocationSigningSeed")),
            Hex(SnapshotBuffer(generationOne, "resetControlSigningSeed")),
            Hex(SnapshotBuffer(generationOne, "addressSigningSeed")),
            Hex(SnapshotBuffer(generationOne, "backupWrappingSeed"))
        };
        Assert.Equal(roleSeedHex.Length, roleSeedHex.Distinct(StringComparer.Ordinal).Count());
        Assert.NotEqual(roleSeedHex[0], Hex(SnapshotBuffer(generationTwo, "accountSigningSeed")));
        Assert.NotEqual(roleSeedHex[0], Hex(SnapshotBuffer(otherNetwork, "accountSigningSeed")));
        Assert.Equal(
            Hex(SnapshotBuffer(generationOne, "addressSigningSeed")),
            Hex(SnapshotBuffer(generationTwo, "addressSigningSeed")));
        Assert.Equal(
            Hex(SnapshotBuffer(generationOne, "addressReadCapability")),
            Hex(SnapshotBuffer(otherNetwork, "addressReadCapability")));
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
    public void RecoveryCapability_HasNoAssemblyVisibleGenericSigningSurface()
    {
        var callableFromFriend = typeof(DeepRecoveryAccountCapabilities)
            .GetMethods(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
            .Where(static method => method.IsAssembly || method.IsFamilyOrAssembly)
            .Where(static method => method.Name.StartsWith("Sign", StringComparison.Ordinal))
            .ToArray();

        Assert.Equal(
            new[]
            {
                "SignGenesisAccountCertificate",
                "SignGenesisDeviceCertificateAsIssuer",
                "SignGenesisRevocationSnapshot"
            },
            callableFromFriend.Select(static method => method.Name).Order().ToArray());
        Assert.All(callableFromFriend, static method =>
            Assert.Contains(method.GetParameters(), static parameter =>
                parameter.ParameterType.Name.EndsWith("SigningIntent", StringComparison.Ordinal)));
        Assert.DoesNotContain(callableFromFriend, static method =>
            method.GetParameters().Any(static parameter =>
                parameter.ParameterType.Name == "OwnedRecord"
                || parameter.ParameterType == typeof(ReadOnlySpan<byte>)
                || parameter.ParameterType == typeof(byte[])));
    }

    [Fact]
    public void Generate_ReturnsRoundTrippableTwentyFourWordPhrase()
    {
        using var generated = DeepRecoveryV1.Generate();
        var phrase = new byte[generated.CanonicalUtf8Length];
        generated.WriteCanonicalUtf8(phrase);
        using var reparsed = DeepRecoveryV1.VerifyCanonicalUtf8(phrase);
        var roundTrip = new byte[reparsed.CanonicalUtf8Length];
        reparsed.WriteCanonicalUtf8(roundTrip);

        Assert.Equal(DeepRecoveryV1.WordCount - 1, phrase.Count(static value => value == (byte)' '));
        Assert.Equal(phrase, roundTrip);
        CryptographicOperations.ZeroMemory(phrase);
        CryptographicOperations.ZeroMemory(roundTrip);
    }

    [Fact]
    public void DisposingCapabilities_ZeroesEveryOwnedSecretBuffer()
    {
        var vector = LoadVector();
        var phrase = VerifyVector(vector.Mnemonic);
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
        Assert.Throws<ObjectDisposedException>(() => _ = phrase.CanonicalUtf8Length);
        Assert.Throws<ObjectDisposedException>(() => _ = capabilities.NetworkId);
        Assert.Throws<ObjectDisposedException>(() => _ = capabilities.AddressReadCapability);
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
        var dmdAuthor = Assert.Single(
            typeof(DeepRecoveryAccountCapabilities).GetMethods(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly),
            static method => method.Name == nameof(DeepRecoveryAccountCapabilities.AuthorGenesisDmd1));
        Assert.Equal(typeof(Dmd1LineageState), dmdAuthor.ReturnType);
        Assert.Equal(
            [typeof(VerifiedApplicationIdentityClosure), typeof(ulong)],
            dmdAuthor.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.DoesNotContain(
            typeof(VerifiedDeepRecoveryPhrase).GetMembers(BindingFlags.Public | BindingFlags.Instance),
            static member => member.Name.Contains("Phrase", StringComparison.Ordinal)
                || member is PropertyInfo { PropertyType: { } type } && type == typeof(string));
        Assert.DoesNotContain(
            typeof(DeepRecoveryV1).GetMethods(BindingFlags.Public | BindingFlags.Static),
            static method => method.GetParameters().Any(parameter => parameter.ParameterType == typeof(string))
                || method.ReturnType == typeof(string));
        Assert.DoesNotContain(
            typeof(DeepRecoveryV1).GetMethods(
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static),
            static method => method.Name == "Verify"
                && method.GetParameters().Any(parameter =>
                    parameter.ParameterType == typeof(string)));
        Assert.DoesNotContain(
            typeof(VerifiedDeepRecoveryPhrase).GetMethods(
                BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly),
            static method => method.IsAssembly &&
                (method.Name.Contains("Copy", StringComparison.Ordinal)
                    || method.Name.Contains("Snapshot", StringComparison.Ordinal)
                    || method.Name.Contains("Entropy", StringComparison.Ordinal)));
        Assert.DoesNotContain(
            typeof(DeepRecoveryAccountCapabilities).GetMethods(
                BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly),
            static method => method.IsAssembly
                && method.Name.StartsWith("Snapshot", StringComparison.Ordinal));
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

    private static byte[] SnapshotBuffer(object instance, string name) =>
        GetBuffer(instance, name).ToArray();

    private static VerifiedDeepRecoveryPhrase VerifyVector(string mnemonic)
    {
        var encoded = Encoding.ASCII.GetBytes(mnemonic);
        try
        {
            return DeepRecoveryV1.VerifyCanonicalUtf8(encoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

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

    private sealed class InjectedConsumerException : Exception;
}
