using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Sodium;

namespace Deep.Protocol.Identity;

public static class DeepRecoveryV1
{
    public const int EntropySize = 32;
    public const int WordCount = 24;
    public const int NetworkIdSize = 16;
    public const int RoleSeedSize = 32;

    private const int AggregateSize = 33;
    private const int BitsPerWord = 11;
    private const int Bip39Rounds = 2048;
    private const int Bip39SeedSize = 64;
    private const int MaxPhraseCharacters = 1024;
    private const string WordListResource = "Deep.Protocol.Identity.Resources.Bip39.english.txt";
    private const string WordListSha256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

    private static readonly string[] WordList = LoadWordList();
    private static readonly IReadOnlyDictionary<string, int> WordIndexes = WordList
        .Select(static (word, index) => new KeyValuePair<string, int>(word, index))
        .ToDictionary(static pair => pair.Key, static pair => pair.Value, StringComparer.Ordinal);

    public static VerifiedDeepRecoveryPhrase Generate()
    {
        var entropy = RandomNumberGenerator.GetBytes(EntropySize);
        try
        {
            return new VerifiedDeepRecoveryPhrase(entropy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    public static VerifiedDeepRecoveryPhrase Verify(string phrase)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(phrase);
        if (phrase.Length > MaxPhraseCharacters)
        {
            throw new ArgumentException("DeepRecoveryV1 phrase input is too large.", nameof(phrase));
        }
        var entropy = DecodePhrase(phrase);
        try
        {
            return new VerifiedDeepRecoveryPhrase(entropy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    public static DeepRecoveryAccountCapabilities DeriveAccountCapabilities(
        VerifiedDeepRecoveryPhrase phrase,
        ReadOnlySpan<byte> networkId,
        ulong accountGeneration)
    {
        ArgumentNullException.ThrowIfNull(phrase);
        if (networkId.Length != NetworkIdSize)
        {
            throw new ArgumentException($"Network ID must contain exactly {NetworkIdSize} bytes.", nameof(networkId));
        }
        if (accountGeneration == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(accountGeneration), "Account generation starts at one.");
        }

        var canonicalPhrase = phrase.GetCanonicalPhrase();
        byte[]? mnemonicBytes = null;
        byte[]? saltBytes = null;
        byte[]? bip39Seed = null;
        byte[]? extractSalt = null;
        byte[]? recoveryPrk = null;
        byte[]? context = null;
        byte[]? accountSigningSeed = null;
        byte[]? deviceIssuerSigningSeed = null;
        byte[]? accountRevocationSigningSeed = null;
        byte[]? resetControlSigningSeed = null;
        byte[]? addressSigningSeed = null;
        byte[]? addressReadCapability = null;
        byte[]? backupWrappingSeed = null;

        try
        {
            mnemonicBytes = Encoding.UTF8.GetBytes(canonicalPhrase.Normalize(NormalizationForm.FormKD));
            saltBytes = Encoding.UTF8.GetBytes("mnemonic");
            bip39Seed = Rfc2898DeriveBytes.Pbkdf2(
                mnemonicBytes,
                saltBytes,
                Bip39Rounds,
                HashAlgorithmName.SHA512,
                Bip39SeedSize);

            extractSalt = SHA512.HashData(Encoding.ASCII.GetBytes("Deep/Recovery/V1/extract"));
            recoveryPrk = new byte[SHA512.HashSizeInBytes];
            var extracted = HKDF.Extract(
                HashAlgorithmName.SHA512,
                bip39Seed,
                extractSalt,
                recoveryPrk);
            if (extracted != recoveryPrk.Length)
            {
                throw new CryptographicException("HKDF extract returned an unexpected length.");
            }

            context = new byte[NetworkIdSize + sizeof(ulong)];
            networkId.CopyTo(context);
            BinaryPrimitives.WriteUInt64BigEndian(context.AsSpan(NetworkIdSize), accountGeneration);

            accountSigningSeed = ExpandRoleSeed(
                recoveryPrk,
                "Deep/Recovery/V1/account-signing-seed",
                context);
            deviceIssuerSigningSeed = ExpandRoleSeed(
                recoveryPrk,
                "Deep/Recovery/V1/device-issuer-signing-seed",
                context);
            accountRevocationSigningSeed = ExpandRoleSeed(
                recoveryPrk,
                "Deep/Recovery/V1/revocation-signing-seed",
                context);
            resetControlSigningSeed = ExpandRoleSeed(
                recoveryPrk,
                "Deep/Recovery/V1/reset-control-signing-seed",
                context);
            backupWrappingSeed = ExpandRoleSeed(
                recoveryPrk,
                "Deep/Recovery/V1/backup-wrapping-seed",
                context);
            var addressContext = Encoding.ASCII.GetBytes("DeepGlobalAddressV1");
            try
            {
                addressSigningSeed = ExpandRoleSeed(
                    recoveryPrk,
                    "Deep/Recovery/V1/public-address-signing-seed",
                    addressContext);
                addressReadCapability = ExpandRoleSeed(
                    recoveryPrk,
                    "Deep/Recovery/V1/public-address-read-capability",
                    addressContext,
                    16);
            }
            finally
            {
                Zero(addressContext);
            }

            var material = new DeepRecoveryAccountCapabilities(
                networkId,
                accountGeneration,
                accountSigningSeed,
                deviceIssuerSigningSeed,
                accountRevocationSigningSeed,
                resetControlSigningSeed,
                addressSigningSeed,
                addressReadCapability,
                backupWrappingSeed);
            accountSigningSeed = null;
            deviceIssuerSigningSeed = null;
            accountRevocationSigningSeed = null;
            resetControlSigningSeed = null;
            addressSigningSeed = null;
            addressReadCapability = null;
            backupWrappingSeed = null;
            return material;
        }
        finally
        {
            Zero(mnemonicBytes);
            Zero(saltBytes);
            Zero(bip39Seed);
            Zero(extractSalt);
            Zero(recoveryPrk);
            Zero(context);
            Zero(accountSigningSeed);
            Zero(deviceIssuerSigningSeed);
            Zero(accountRevocationSigningSeed);
            Zero(resetControlSigningSeed);
            Zero(addressSigningSeed);
            Zero(addressReadCapability);
            Zero(backupWrappingSeed);
        }
    }

    internal static string EncodeEntropy(ReadOnlySpan<byte> entropy)
    {
        if (entropy.Length != EntropySize)
        {
            throw new ArgumentException($"Recovery entropy must contain exactly {EntropySize} bytes.", nameof(entropy));
        }

        Span<byte> checksum = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(entropy, checksum);
        var words = new string[WordCount];
        for (var word = 0; word < WordCount; word++)
        {
            var index = 0;
            for (var bit = 0; bit < BitsPerWord; bit++)
            {
                var sourceBit = (word * BitsPerWord) + bit;
                var value = sourceBit < EntropySize * 8
                    ? (entropy[sourceBit / 8] >> (7 - (sourceBit % 8))) & 1
                    : (checksum[0] >> (7 - (sourceBit - (EntropySize * 8)))) & 1;
                index = (index << 1) | value;
            }

            words[word] = WordList[index];
        }

        CryptographicOperations.ZeroMemory(checksum);
        return string.Join(' ', words);
    }

    private static byte[] DecodePhrase(string phrase)
    {
        var canonical = NormalizePhrase(phrase);
        var words = canonical.Split(' ', StringSplitOptions.None);
        if (words.Length != WordCount)
        {
            throw new ArgumentException($"DeepRecoveryV1 requires exactly {WordCount} words.", nameof(phrase));
        }

        var aggregate = new byte[AggregateSize];
        byte[]? entropy = null;
        Span<byte> expectedChecksum = stackalloc byte[SHA256.HashSizeInBytes];
        try
        {
            var targetBit = 0;
            foreach (var word in words)
            {
                if (!WordIndexes.TryGetValue(word, out var index))
                {
                    throw new ArgumentException("DeepRecoveryV1 contains an unknown English BIP-39 word.", nameof(phrase));
                }

                for (var bit = BitsPerWord - 1; bit >= 0; bit--)
                {
                    if ((index & (1 << bit)) != 0)
                    {
                        aggregate[targetBit / 8] |= (byte)(1 << (7 - (targetBit % 8)));
                    }

                    targetBit++;
                }
            }

            entropy = aggregate.AsSpan(0, EntropySize).ToArray();
            SHA256.HashData(entropy, expectedChecksum);
            Span<byte> actualChecksum = stackalloc byte[1] { aggregate[EntropySize] };
            if (!CryptographicOperations.FixedTimeEquals(actualChecksum, expectedChecksum[..1]))
            {
                throw new ArgumentException("DeepRecoveryV1 checksum is invalid.", nameof(phrase));
            }

            var result = entropy;
            entropy = null;
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aggregate);
            CryptographicOperations.ZeroMemory(expectedChecksum);
            Zero(entropy);
        }
    }

    private static string NormalizePhrase(string phrase)
    {
        var normalized = phrase.Normalize(NormalizationForm.FormKD);
        var words = normalized
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(static word => word.ToLowerInvariant())
            .ToArray();
        return string.Join(' ', words);
    }

    private static byte[] ExpandRoleSeed(
        ReadOnlySpan<byte> prk,
        string domain,
        ReadOnlySpan<byte> context,
        int outputLength = RoleSeedSize)
    {
        var domainBytes = Encoding.ASCII.GetBytes(domain);
        byte[]? info = null;
        try
        {
            info = new byte[domainBytes.Length + 1 + sizeof(uint) + context.Length];
            domainBytes.CopyTo(info, 0);
            BinaryPrimitives.WriteUInt32BigEndian(info.AsSpan(domainBytes.Length + 1), checked((uint)context.Length));
            context.CopyTo(info.AsSpan(domainBytes.Length + 1 + sizeof(uint)));

            var output = new byte[outputLength];
            HKDF.Expand(HashAlgorithmName.SHA512, prk, output, info);
            return output;
        }
        finally
        {
            Zero(domainBytes);
            Zero(info);
        }
    }

    private static string[] LoadWordList()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(WordListResource)
            ?? throw new InvalidOperationException("The canonical English BIP-39 word list is missing.");
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var text = reader.ReadToEnd().Replace("\r\n", "\n", StringComparison.Ordinal);
        if (!text.EndsWith('\n'))
        {
            text += "\n";
        }
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        var words = text
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (!StringComparer.Ordinal.Equals(hash, WordListSha256)
            || words.Length != 2048
            || words.Distinct(StringComparer.Ordinal).Count() != words.Length
            || words.Any(static word => word.Length == 0 || word.Any(static character => character is < 'a' or > 'z'))
            || !words.SequenceEqual(words.OrderBy(static word => word, StringComparer.Ordinal), StringComparer.Ordinal))
        {
            throw new InvalidOperationException("The embedded English BIP-39 word list is malformed.");
        }

        return words;
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}

public sealed class VerifiedDeepRecoveryPhrase : IDisposable
{
    private readonly object sync = new();
    private readonly byte[] entropy;
    private int disposed;

    internal VerifiedDeepRecoveryPhrase(ReadOnlySpan<byte> entropy)
    {
        if (entropy.Length != DeepRecoveryV1.EntropySize)
        {
            throw new ArgumentException("Invalid DeepRecoveryV1 entropy length.", nameof(entropy));
        }

        this.entropy = entropy.ToArray();
    }

    public string CanonicalPhrase
    {
        get
        {
            lock (sync)
            {
                ThrowIfDisposed();
                return DeepRecoveryV1.EncodeEntropy(entropy);
            }
        }
    }

    internal string GetCanonicalPhrase()
    {
        lock (sync)
        {
            ThrowIfDisposed();
            return DeepRecoveryV1.EncodeEntropy(entropy);
        }
    }

    internal byte[] SnapshotEntropy()
    {
        lock (sync)
        {
            ThrowIfDisposed();
            return entropy.ToArray();
        }
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0)
            {
                CryptographicOperations.ZeroMemory(entropy);
            }
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed != 0, this);
}

public sealed class DeepRecoveryAccountCapabilities : IDisposable
{
    private const int MaxCanonicalSigningBytes = 64 * 1024;
    private readonly object sync = new();
    private readonly byte[] networkId;
    private readonly byte[] accountSigningSeed;
    private readonly byte[] deviceIssuerSigningSeed;
    private readonly byte[] accountRevocationSigningSeed;
    private readonly byte[] resetControlSigningSeed;
    private readonly byte[] addressSigningSeed;
    private readonly byte[] addressReadCapability;
    private readonly byte[] backupWrappingSeed;
    private int disposed;

    internal DeepRecoveryAccountCapabilities(
        ReadOnlySpan<byte> networkId,
        ulong accountGeneration,
        byte[] accountSigningSeed,
        byte[] deviceIssuerSigningSeed,
        byte[] accountRevocationSigningSeed,
        byte[] resetControlSigningSeed,
        byte[] addressSigningSeed,
        byte[] addressReadCapability,
        byte[] backupWrappingSeed)
    {
        this.networkId = networkId.ToArray();
        AccountGeneration = accountGeneration;
        this.accountSigningSeed = RequireSeed(accountSigningSeed, nameof(accountSigningSeed));
        this.deviceIssuerSigningSeed = RequireSeed(deviceIssuerSigningSeed, nameof(deviceIssuerSigningSeed));
        this.accountRevocationSigningSeed = RequireSeed(accountRevocationSigningSeed, nameof(accountRevocationSigningSeed));
        this.resetControlSigningSeed = RequireSeed(resetControlSigningSeed, nameof(resetControlSigningSeed));
        this.addressSigningSeed = RequireSeed(addressSigningSeed, nameof(addressSigningSeed));
        this.addressReadCapability = RequireLength(addressReadCapability, 16, nameof(addressReadCapability));
        this.backupWrappingSeed = RequireSeed(backupWrappingSeed, nameof(backupWrappingSeed));
    }

    public ulong AccountGeneration { get; }

    public ReadOnlyMemory<byte> NetworkId
    {
        get
        {
            lock (sync)
            {
                ThrowIfDisposed();
                return networkId.ToArray();
            }
        }
    }

    internal byte[] SnapshotAccountSigningSeed() => Snapshot(accountSigningSeed);

    internal byte[] SnapshotDeviceIssuerSigningSeed() => Snapshot(deviceIssuerSigningSeed);

    internal byte[] SnapshotAccountRevocationSigningSeed() => Snapshot(accountRevocationSigningSeed);

    internal byte[] SnapshotResetControlSigningSeed() => Snapshot(resetControlSigningSeed);

    internal byte[] SnapshotAddressSigningSeed() => Snapshot(addressSigningSeed);

    internal byte[] SnapshotAddressReadCapability() => Snapshot(addressReadCapability);

    internal byte[] SnapshotBackupWrappingSeed() => Snapshot(backupWrappingSeed);

    public ReadOnlyMemory<byte> AccountSigningPublicKey => PublicKey(accountSigningSeed);

    public ReadOnlyMemory<byte> DeviceIssuerSigningPublicKey => PublicKey(deviceIssuerSigningSeed);

    public ReadOnlyMemory<byte> AccountRevocationSigningPublicKey => PublicKey(accountRevocationSigningSeed);

    public ReadOnlyMemory<byte> ResetControlSigningPublicKey => PublicKey(resetControlSigningSeed);

    public ReadOnlyMemory<byte> AddressSigningPublicKey => PublicKey(addressSigningSeed);

    public ReadOnlyMemory<byte> AddressReadCapability
    {
        get
        {
            lock (sync)
            {
                ThrowIfDisposed();
                return addressReadCapability.ToArray();
            }
        }
    }

    public byte[] SignAccount(ReadOnlySpan<byte> canonicalSigningBytes) =>
        Sign(canonicalSigningBytes, accountSigningSeed);

    public byte[] SignDeviceCertificate(ReadOnlySpan<byte> canonicalSigningBytes) =>
        Sign(canonicalSigningBytes, deviceIssuerSigningSeed);

    public byte[] SignAccountRevocation(ReadOnlySpan<byte> canonicalSigningBytes) =>
        Sign(canonicalSigningBytes, accountRevocationSigningSeed);

    public byte[] SignResetControl(ReadOnlySpan<byte> canonicalSigningBytes) =>
        Sign(canonicalSigningBytes, resetControlSigningSeed);

    public byte[] SignAddressBinding(ReadOnlySpan<byte> canonicalSigningBytes) =>
        Sign(canonicalSigningBytes, addressSigningSeed);

    public void Dispose()
    {
        lock (sync)
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }

            CryptographicOperations.ZeroMemory(networkId);
            CryptographicOperations.ZeroMemory(accountSigningSeed);
            CryptographicOperations.ZeroMemory(deviceIssuerSigningSeed);
            CryptographicOperations.ZeroMemory(accountRevocationSigningSeed);
            CryptographicOperations.ZeroMemory(resetControlSigningSeed);
            CryptographicOperations.ZeroMemory(addressSigningSeed);
            CryptographicOperations.ZeroMemory(addressReadCapability);
            CryptographicOperations.ZeroMemory(backupWrappingSeed);
        }
    }

    private byte[] Snapshot(byte[] value)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            return value.ToArray();
        }
    }

    private ReadOnlyMemory<byte> PublicKey(byte[] seed)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            using var keyPair = PublicKeyAuth.GenerateKeyPair(seed);
            try
            {
                return keyPair.PublicKey.ToArray();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyPair.PrivateKey);
            }
        }
    }

    private byte[] Sign(ReadOnlySpan<byte> canonicalSigningBytes, byte[] seed)
    {
        if (canonicalSigningBytes.IsEmpty || canonicalSigningBytes.Length > MaxCanonicalSigningBytes)
        {
            throw new ArgumentException(
                $"Canonical signing bytes must contain 1..{MaxCanonicalSigningBytes} bytes.",
                nameof(canonicalSigningBytes));
        }
        lock (sync)
        {
            ThrowIfDisposed();
            var message = canonicalSigningBytes.ToArray();
            using var keyPair = PublicKeyAuth.GenerateKeyPair(seed);
            try
            {
                return PublicKeyAuth.SignDetached(message, keyPair.PrivateKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(message);
                CryptographicOperations.ZeroMemory(keyPair.PrivateKey);
            }
        }
    }

    private static byte[] RequireSeed(byte[] value, string name) =>
        RequireLength(value, DeepRecoveryV1.RoleSeedSize, name);

    private static byte[] RequireLength(byte[] value, int expectedLength, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        if (value.Length != expectedLength)
        {
            throw new ArgumentException("Recovery capability has an invalid length.", name);
        }

        return value;
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed != 0, this);
}
