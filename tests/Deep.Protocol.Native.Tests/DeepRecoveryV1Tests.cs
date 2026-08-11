using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.Native;

namespace Deep.Protocol.Native.Tests;

public sealed class DeepRecoveryV1Tests
{
    private const string WordListResource = "Deep.Protocol.Native.Resources.Bip39.english.txt";
    private const string VectorResource = "Deep.Protocol.Native.Tests.deep-recovery-v1.vector.json";

    [Fact]
    public void EncodeEntropy_MatchesOfficialBip39TwentyFourWordShape()
    {
        var vector = LoadVector();
        var entropy = Convert.FromHexString(vector.Entropy);

        var phrase = DeepRecoveryV1.EncodeEntropy(entropy);

        Assert.Equal(vector.Mnemonic, phrase);
        Assert.Equal(24, phrase.Split(' ').Length);
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

    [Fact]
    public void Verify_RejectsValidLengthTwelveWordWalletMnemonic()
    {
        const string twelveWords =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        var exception = Assert.Throws<ArgumentException>(() => DeepRecoveryV1.Verify(twelveWords));

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
    public void Verify_RejectsChecksumMutation()
    {
        var words = LoadVector().Mnemonic.Split(' ');
        words[^1] = "zoo";

        var exception = Assert.Throws<ArgumentException>(() => DeepRecoveryV1.Verify(string.Join(' ', words)));

        Assert.Contains("checksum", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DeriveAccountMaterial_MatchesIndependentPythonVector()
    {
        var vector = LoadVector();
        using var phrase = DeepRecoveryV1.Verify(vector.Mnemonic);
        using var material = DeepRecoveryV1.DeriveAccountMaterial(
            phrase,
            Convert.FromHexString(vector.NetworkId),
            ulong.Parse(vector.AccountGeneration, System.Globalization.CultureInfo.InvariantCulture));

        Assert.Equal(vector.AccountSigningSeed, Hex(material.SnapshotAccountSigningSeed()));
        Assert.Equal(vector.AccountPqSigningSeed, Hex(material.SnapshotAccountPqSigningSeed()));
        Assert.Equal(vector.RecoveryAuthorizationSeed, Hex(material.SnapshotRecoveryAuthorizationSeed()));
        Assert.Equal(vector.BackupWrappingSeed, Hex(material.SnapshotBackupWrappingSeed()));
        Assert.Equal(Convert.FromHexString(vector.NetworkId), material.NetworkId.ToArray());
    }

    [Fact]
    public void DeriveAccountMaterial_SeparatesRolesNetworkAndGeneration()
    {
        var vector = LoadVector();
        using var phrase = DeepRecoveryV1.Verify(vector.Mnemonic);
        var network = Convert.FromHexString(vector.NetworkId);
        using var generationOne = DeepRecoveryV1.DeriveAccountMaterial(phrase, network, 1);
        using var generationTwo = DeepRecoveryV1.DeriveAccountMaterial(phrase, network, 2);
        network[0] ^= 0xff;
        using var otherNetwork = DeepRecoveryV1.DeriveAccountMaterial(phrase, network, 1);

        var roleSeeds = new[]
        {
            generationOne.SnapshotAccountSigningSeed(),
            generationOne.SnapshotAccountPqSigningSeed(),
            generationOne.SnapshotRecoveryAuthorizationSeed(),
            generationOne.SnapshotBackupWrappingSeed()
        };
        var roleSeedHex = roleSeeds.Select(Hex).ToArray();
        Assert.Equal(roleSeedHex.Length, roleSeedHex.Distinct(StringComparer.Ordinal).Count());
        Assert.NotEqual(roleSeedHex[0], Hex(generationTwo.SnapshotAccountSigningSeed()));
        Assert.NotEqual(roleSeedHex[0], Hex(otherNetwork.SnapshotAccountSigningSeed()));
    }

    [Fact]
    public void DeriveAccountMaterial_RejectsWrongNetworkLengthAndDisposedPhrase()
    {
        using var live = DeepRecoveryV1.Generate();
        Assert.Throws<ArgumentException>(() => DeepRecoveryV1.DeriveAccountMaterial(live, new byte[15], 1));

        var disposed = DeepRecoveryV1.Generate();
        disposed.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            DeepRecoveryV1.DeriveAccountMaterial(disposed, new byte[DeepRecoveryV1.NetworkIdSize], 1));
    }

    [Fact]
    public void AccountMaterial_ReturnsDefensiveNetworkIdCopy()
    {
        using var phrase = DeepRecoveryV1.Generate();
        var network = Enumerable.Range(0, DeepRecoveryV1.NetworkIdSize).Select(static value => (byte)value).ToArray();
        using var material = DeepRecoveryV1.DeriveAccountMaterial(phrase, network, 7);

        network[0] ^= 0xff;
        var first = material.NetworkId.ToArray();
        first[1] ^= 0xff;
        var second = material.NetworkId.ToArray();

        Assert.Equal(0, second[0]);
        Assert.Equal(1, second[1]);
    }

    [Fact]
    public void Generate_ReturnsRoundTrippableTwentyFourWordPhrase()
    {
        using var generated = DeepRecoveryV1.Generate();
        var phrase = generated.CanonicalPhrase;
        using var reparsed = DeepRecoveryV1.Verify(phrase);

        Assert.Equal(24, phrase.Split(' ').Length);
        Assert.Equal(phrase, reparsed.CanonicalPhrase);
    }

    [Fact]
    public void DisposingCapabilities_ZeroesOwnedSecretBuffers()
    {
        var vector = LoadVector();
        var phrase = DeepRecoveryV1.Verify(vector.Mnemonic);
        var phraseEntropy = GetBuffer(phrase, "entropy");
        var material = DeepRecoveryV1.DeriveAccountMaterial(
            phrase,
            Convert.FromHexString(vector.NetworkId),
            1);
        var materialBuffers = new[]
        {
            GetBuffer(material, "accountSigningSeed"),
            GetBuffer(material, "accountPqSigningSeed"),
            GetBuffer(material, "recoveryAuthorizationSeed"),
            GetBuffer(material, "backupWrappingSeed")
        };

        Assert.Equal(DeepRecoveryV1.EntropySize, phraseEntropy.Length);
        Assert.All(materialBuffers, static buffer => Assert.Contains(buffer, static value => value != 0));

        phrase.Dispose();
        material.Dispose();

        Assert.All(phraseEntropy, static value => Assert.Equal(0, value));
        Assert.All(materialBuffers.SelectMany(static value => value), static value => Assert.Equal(0, value));
        Assert.Throws<ObjectDisposedException>(() => _ = phrase.CanonicalPhrase);
        Assert.Throws<ObjectDisposedException>(() => _ = material.NetworkId);
    }

    [Fact]
    public void PublicSurface_DoesNotExportRoleSeedsOrConstructors()
    {
        Assert.Empty(typeof(VerifiedDeepRecoveryPhrase).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(DeepRecoveryAccountMaterial).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(
            typeof(DeepRecoveryAccountMaterial).GetProperties(BindingFlags.Public | BindingFlags.Instance),
            static property => property.Name.Contains("Seed", StringComparison.Ordinal));
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
        string AccountPqSigningSeed,
        string AccountSigningSeed,
        string BackupWrappingSeed,
        string Bip39Seed,
        string Entropy,
        string Mnemonic,
        string NetworkId,
        string RecoveryAuthorizationSeed);
}
