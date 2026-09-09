using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Identity;

public static class DeepRecoveryV1
{
    public const int EntropySize = 32;
    public const int WordCount = 24;
    public const int NetworkIdSize = 16;
    public const int RoleSeedSize = 32;
    public const int MaxCanonicalUtf8Length = 215;

    private const int AggregateSize = 33;
    private const int BitsPerWord = 11;
    private const int Bip39Rounds = 2048;
    private const int Bip39SeedSize = 64;
    private const string WordListResource = "Deep.Protocol.Identity.Resources.Bip39.english.txt";
    private const string WordListSha256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

    private static readonly string[] WordList = LoadWordList();
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

    public static VerifiedDeepRecoveryPhrase VerifyCanonicalUtf8(
        ReadOnlySpan<byte> canonicalPhraseUtf8)
    {
        if (canonicalPhraseUtf8.IsEmpty || canonicalPhraseUtf8.Length > MaxCanonicalUtf8Length)
        {
            throw new ArgumentException(
                "DeepRecoveryV1 canonical UTF-8 input is empty or too large.",
                nameof(canonicalPhraseUtf8));
        }
        var entropy = DecodeCanonicalUtf8(canonicalPhraseUtf8);
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
            phrase.UseCanonicalUtf8(bytes => mnemonicBytes = bytes.ToArray());
            if (mnemonicBytes is null)
                throw new CryptographicException("Recovery phrase export did not complete.");
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

    internal static int GetCanonicalUtf8Length(ReadOnlySpan<byte> entropy)
    {
        ValidateEntropy(entropy);
        Span<byte> checksum = stackalloc byte[SHA256.HashSizeInBytes];
        try
        {
            SHA256.HashData(entropy, checksum);
            var length = WordCount - 1;
            for (var word = 0; word < WordCount; word++)
            {
                length = checked(length + WordList[ReadWordIndex(entropy, checksum, word)].Length);
            }
            return length;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(checksum);
        }
    }

    internal static int WriteCanonicalUtf8(
        ReadOnlySpan<byte> entropy,
        Span<byte> destination)
    {
        ValidateEntropy(entropy);
        Span<byte> checksum = stackalloc byte[SHA256.HashSizeInBytes];
        try
        {
            SHA256.HashData(entropy, checksum);
            var required = 0;
            for (var word = 0; word < WordCount; word++)
            {
                required = checked(required + WordList[ReadWordIndex(entropy, checksum, word)].Length);
            }
            required = checked(required + WordCount - 1);
            if (destination.Length < required)
            {
                throw new ArgumentException(
                    $"Canonical recovery destination must contain at least {required} bytes.",
                    nameof(destination));
            }

            var offset = 0;
            for (var word = 0; word < WordCount; word++)
            {
                if (word != 0)
                {
                    destination[offset++] = (byte)' ';
                }
                var value = WordList[ReadWordIndex(entropy, checksum, word)];
                foreach (var character in value)
                {
                    destination[offset++] = checked((byte)character);
                }
            }
            return offset;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(checksum);
        }
    }

    private static byte[] DecodeCanonicalUtf8(ReadOnlySpan<byte> phrase)
    {
        var aggregate = new byte[AggregateSize];
        byte[]? entropy = null;
        Span<byte> expectedChecksum = stackalloc byte[SHA256.HashSizeInBytes];
        try
        {
            var targetBit = 0;
            var offset = 0;
            for (var wordNumber = 0; wordNumber < WordCount; wordNumber++)
            {
                var end = phrase[offset..].IndexOf((byte)' ');
                if (end < 0)
                {
                    end = phrase.Length - offset;
                }
                if (end == 0 || (wordNumber < WordCount - 1 && offset + end >= phrase.Length))
                {
                    throw new ArgumentException(
                        $"DeepRecoveryV1 requires exactly {WordCount} words: lowercase ASCII with single spaces.",
                        nameof(phrase));
                }
                if (wordNumber == WordCount - 1 && offset + end != phrase.Length)
                {
                    throw new ArgumentException(
                        $"DeepRecoveryV1 requires exactly {WordCount} words: lowercase ASCII with single spaces.",
                        nameof(phrase));
                }

                var word = phrase.Slice(offset, end);
                if (word.IndexOfAnyExceptInRange((byte)'a', (byte)'z') >= 0)
                {
                    throw new ArgumentException(
                        "DeepRecoveryV1 canonical words must contain strict lowercase ASCII letters.",
                        nameof(phrase));
                }
                var index = FindWordIndex(word);
                if (index < 0)
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
                offset += end + (wordNumber < WordCount - 1 ? 1 : 0);
            }

            if (offset != phrase.Length)
            {
                throw new ArgumentException(
                    $"DeepRecoveryV1 requires exactly {WordCount} words: lowercase ASCII with single spaces.",
                    nameof(phrase));
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

    private static int FindWordIndex(ReadOnlySpan<byte> word)
    {
        var low = 0;
        var high = WordList.Length - 1;
        while (low <= high)
        {
            var middle = low + ((high - low) / 2);
            var comparison = CompareAscii(word, WordList[middle]);
            if (comparison == 0)
            {
                return middle;
            }
            if (comparison < 0)
            {
                high = middle - 1;
            }
            else
            {
                low = middle + 1;
            }
        }
        return -1;
    }

    private static int CompareAscii(ReadOnlySpan<byte> left, string right)
    {
        var common = Math.Min(left.Length, right.Length);
        for (var index = 0; index < common; index++)
        {
            var comparison = left[index].CompareTo(checked((byte)right[index]));
            if (comparison != 0)
            {
                return comparison;
            }
        }
        return left.Length.CompareTo(right.Length);
    }

    private static int ReadWordIndex(
        ReadOnlySpan<byte> entropy,
        ReadOnlySpan<byte> checksum,
        int word)
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
        return index;
    }

    private static void ValidateEntropy(ReadOnlySpan<byte> entropy)
    {
        if (entropy.Length != EntropySize)
        {
            throw new ArgumentException(
                $"Recovery entropy must contain exactly {EntropySize} bytes.",
                nameof(entropy));
        }
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
            try
            {
                HKDF.Expand(HashAlgorithmName.SHA512, prk, output, info);
                return output;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(output);
                throw;
            }
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

    public int CanonicalUtf8Length
    {
        get
        {
            lock (sync)
            {
                ThrowIfDisposed();
                return DeepRecoveryV1.GetCanonicalUtf8Length(entropy);
            }
        }
    }

    public int WriteCanonicalUtf8(Span<byte> destination)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            return DeepRecoveryV1.WriteCanonicalUtf8(entropy, destination);
        }
    }

    public void UseCanonicalUtf8(DeepRecoveryCanonicalUtf8Consumer consumer)
    {
        ArgumentNullException.ThrowIfNull(consumer);
        byte[]? encoded = null;
        lock (sync)
        {
            ThrowIfDisposed();
            encoded = GC.AllocateUninitializedArray<byte>(
                DeepRecoveryV1.GetCanonicalUtf8Length(entropy));
            try
            {
                var written = DeepRecoveryV1.WriteCanonicalUtf8(entropy, encoded);
                consumer(encoded.AsSpan(0, written));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }
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

public delegate void DeepRecoveryCanonicalUtf8Consumer(
    ReadOnlySpan<byte> canonicalPhraseUtf8);

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
        byte[]? networkCopy = null;
        var ownershipTransferred = false;
        try
        {
            if (networkId.Length != 16 || DeepIdentityCrypto.IsAllZero(networkId))
                throw new ArgumentException(
                    "Recovery capability network must be a nonzero 16-byte value.", nameof(networkId));
            if (accountGeneration == 0)
                throw new ArgumentOutOfRangeException(nameof(accountGeneration));
            RequireSeed(accountSigningSeed, nameof(accountSigningSeed));
            RequireSeed(deviceIssuerSigningSeed, nameof(deviceIssuerSigningSeed));
            RequireSeed(accountRevocationSigningSeed, nameof(accountRevocationSigningSeed));
            RequireSeed(resetControlSigningSeed, nameof(resetControlSigningSeed));
            RequireSeed(addressSigningSeed, nameof(addressSigningSeed));
            RequireLength(addressReadCapability, 16, nameof(addressReadCapability));
            RequireSeed(backupWrappingSeed, nameof(backupWrappingSeed));

            networkCopy = networkId.ToArray();
            this.networkId = networkCopy;
            AccountGeneration = accountGeneration;
            this.accountSigningSeed = accountSigningSeed;
            this.deviceIssuerSigningSeed = deviceIssuerSigningSeed;
            this.accountRevocationSigningSeed = accountRevocationSigningSeed;
            this.resetControlSigningSeed = resetControlSigningSeed;
            this.addressSigningSeed = addressSigningSeed;
            this.addressReadCapability = addressReadCapability;
            this.backupWrappingSeed = backupWrappingSeed;
            ownershipTransferred = true;
            networkCopy = null;
        }
        finally
        {
            if (!ownershipTransferred)
            {
                ZeroOwned(accountSigningSeed);
                ZeroOwned(deviceIssuerSigningSeed);
                ZeroOwned(accountRevocationSigningSeed);
                ZeroOwned(resetControlSigningSeed);
                ZeroOwned(addressSigningSeed);
                ZeroOwned(addressReadCapability);
                ZeroOwned(backupWrappingSeed);
            }
            ZeroOwned(networkCopy);
        }
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

    public ReadOnlyMemory<byte> AccountSigningPublicKey => PublicKey(accountSigningSeed);

    public DeepAccountIdentityCapability AccountIdentity =>
        DeepAccountIdentityCapability.FromRecoveryCapabilities(this);

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

    /// <summary>
    /// Authors, verifies, and starts the exact generation-one DMD1 lineage for
    /// a verifier-minted genesis identity closure. The device-issuer seed never
    /// leaves this capability and cannot sign caller-supplied bytes.
    /// </summary>
    public Dmd1LineageState AuthorGenesisDmd1(
        VerifiedApplicationIdentityClosure identity,
        ulong issuedAtUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (issuedAtUnixSeconds == 0)
            throw new ArgumentOutOfRangeException(nameof(issuedAtUnixSeconds));

        lock (sync)
        {
            ThrowIfDisposed();
            var account = identity.Account;
            var revocations = identity.Revocations;
            byte[]? issuerPublic = null;
            byte[]? signatureInput = null;
            byte[]? signature = null;
            try
            {
                issuerPublic = DeepIdentityCrypto.DeriveEd25519PublicKey(deviceIssuerSigningSeed);
                if (AccountGeneration != 1 ||
                    account.Certificate.AccountGeneration != AccountGeneration ||
                    revocations.Snapshot.AccountGeneration != AccountGeneration ||
                    revocations.Snapshot.Revision != 1 ||
                    revocations.Snapshot.EntryCount != 0 ||
                    revocations.Snapshot.CurrentHead.Span.IndexOfAnyExcept((byte)0) >= 0 ||
                    !networkId.AsSpan().SequenceEqual(account.Certificate.NetworkId.Span) ||
                    !networkId.AsSpan().SequenceEqual(revocations.Snapshot.NetworkId.Span) ||
                    !account.DeepAccountIdHash.Span.SequenceEqual(revocations.Snapshot.AccountHash.Span) ||
                    !issuerPublic.AsSpan().SequenceEqual(
                        account.Certificate.DeviceIssuerEd25519PublicKey.Span))
                {
                    throw new RecordException(
                        RecordError.InvalidTransition,
                        "Genesis DMD1 authoring requires the exact matching generation-one DPA1/DRS1 authority.");
                }

                var devices = identity.ActiveDevices
                    .OrderBy(static device => device.Certificate.DeviceId.ToArray(), ByteArrayComparer.Instance)
                    .ToArray();
                if (devices.Length is < 1 or > 16)
                    throw new RecordException(
                        RecordError.InvalidLength,
                        "Genesis DMD1 authoring requires one through sixteen verified devices.");
                var entries = devices.Select(static device => new DeviceDirectoryEntry(
                    device.Certificate.DeviceId.Span,
                    ApplicationCoreCodec.CreateArtifactReference(
                        (ushort)ArtifactType.Dpd1,
                        checked((uint)device.Certificate.CanonicalBytes.Length),
                        device.Certificate.CanonicalHash.Span))).ToArray();
                var dpaReference = ApplicationCoreCodec.CreateArtifactReference(
                    (ushort)ArtifactType.Dpa1,
                    checked((uint)account.Certificate.CanonicalBytes.Length),
                    account.Certificate.CanonicalHash.Span);
                var drsReference = ApplicationCoreCodec.CreateArtifactReference(
                    (ushort)ArtifactType.Drs1,
                    checked((uint)revocations.Snapshot.CanonicalBytes.Length),
                    revocations.Snapshot.CanonicalHash.Span);
                var unsigned = ApplicationCoreCodec.AuthorDmd1(
                    networkId,
                    account.DeepAccountIdHash.Span,
                    AccountGeneration,
                    dpaReference,
                    drsReference,
                    directoryGeneration: 1,
                    new byte[32],
                    entries,
                    issuedAtUnixSeconds,
                    new byte[64]);
                signatureInput = unsigned.SignatureInput.ToArray();
                signature = new byte[OwnedSodiumEd25519.SignatureSize];
                Span<byte> temporaryPublic = stackalloc byte[OwnedSodiumEd25519.PublicKeySize];
                Span<byte> temporarySecret = stackalloc byte[OwnedSodiumEd25519.SecretKeySize];
                OwnedSodiumEd25519.SignDetached(
                    deviceIssuerSigningSeed,
                    signatureInput,
                    signature,
                    temporaryPublic,
                    temporarySecret);
                var parsed = ApplicationCoreCodec.AuthorDmd1(
                    networkId,
                    account.DeepAccountIdHash.Span,
                    AccountGeneration,
                    dpaReference,
                    drsReference,
                    directoryGeneration: 1,
                    new byte[32],
                    entries,
                    issuedAtUnixSeconds,
                    signature);
                var verified = ApplicationCoreVerifier.VerifyDmd1(parsed, identity);
                return ApplicationCoreVerifier.StartDmd1Lineage(verified).Next;
            }
            finally
            {
                ZeroOwned(issuerPublic);
                ZeroOwned(signatureInput);
                ZeroOwned(signature);
            }
        }
    }

    internal (byte[] Account, byte[] DeviceIssuer, byte[] Revocation, byte[] Reset)
        SignGenesisAccountCertificate(
            Dnp1IdentityAuthoringV1.GenesisAccountCertificateSigningIntent intent)
    {
        ArgumentNullException.ThrowIfNull(intent);
        lock (sync)
        {
            ThrowIfDisposed();
            if (!ReferenceEquals(intent.Authority, this))
                throw new RecordException(
                    RecordError.InvalidField,
                    "DPA1 signing intent belongs to another recovery authority.");
            return (
                SignRecord(intent.Record, "Deep/IdentityAuth/V1/account-certificate", accountSigningSeed),
                SignRecord(intent.Record, "Deep/IdentityAuth/V1/account-certificate", deviceIssuerSigningSeed),
                SignRecord(intent.Record, "Deep/IdentityAuth/V1/account-certificate", accountRevocationSigningSeed),
                SignRecord(intent.Record, "Deep/IdentityAuth/V1/account-certificate", resetControlSigningSeed));
        }
    }

    internal byte[] SignGenesisRevocationSnapshot(
        Dnp1IdentityAuthoringV1.GenesisRevocationSnapshotSigningIntent intent)
    {
        ArgumentNullException.ThrowIfNull(intent);
        lock (sync)
        {
            ThrowIfDisposed();
            if (!ReferenceEquals(intent.Authority, this))
                throw new RecordException(
                    RecordError.InvalidField,
                    "DRS1 signing intent belongs to another recovery authority.");
            return SignRecord(
                intent.Record,
                "Deep/IdentityAuth/V1/revocation-snapshot",
                accountRevocationSigningSeed);
        }
    }

    internal byte[] SignGenesisDeviceCertificateAsIssuer(
        Dnp1IdentityAuthoringV1.GenesisDeviceCertificateSigningIntent intent)
    {
        ArgumentNullException.ThrowIfNull(intent);
        lock (sync)
        {
            ThrowIfDisposed();
            if (!ReferenceEquals(intent.Authority, this))
                throw new RecordException(
                    RecordError.InvalidField,
                    "DPD1 signing intent belongs to another recovery authority.");
            return SignRecord(
                intent.Record,
                "Deep/IdentityAuth/V1/device-certificate",
                deviceIssuerSigningSeed);
        }
    }

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

    private ReadOnlyMemory<byte> PublicKey(byte[] seed)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            return DeepIdentityCrypto.DeriveEd25519PublicKey(seed);
        }
    }

    private byte[] SignRecord(OwnedRecord record, string domain, byte[] seed)
    {
        byte[]? canonicalSigningBytes = null;
        byte[]? signature = null;
        lock (sync)
        {
            ThrowIfDisposed();
            try
            {
                canonicalSigningBytes = CanonicalGrammar.GetSigningBytes(record, domain);
                if (canonicalSigningBytes.Length is < 1 or > MaxCanonicalSigningBytes)
                    throw new RecordException(
                        RecordError.InvalidLength,
                        "Identity signing projection is outside its bound.");
                signature = new byte[OwnedSodiumEd25519.SignatureSize];
                Span<byte> temporaryPublicKey = stackalloc byte[OwnedSodiumEd25519.PublicKeySize];
                Span<byte> temporarySecretKey = stackalloc byte[OwnedSodiumEd25519.SecretKeySize];
                OwnedSodiumEd25519.SignDetached(
                    seed,
                    canonicalSigningBytes,
                    signature,
                    temporaryPublicKey,
                    temporarySecretKey);
                var result = signature;
                signature = null;
                return result;
            }
            finally
            {
                ZeroOwned(canonicalSigningBytes);
                ZeroOwned(signature);
            }
        }
    }


    private static void ZeroOwned(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }

    private static byte[] RequireSeed(byte[] value, string name)
    {
        RequireLength(value, DeepRecoveryV1.RoleSeedSize, name);
        if (DeepIdentityCrypto.IsAllZero(value))
            throw new ArgumentException("Recovery capability seed must be nonzero.", name);
        return value;
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }

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
