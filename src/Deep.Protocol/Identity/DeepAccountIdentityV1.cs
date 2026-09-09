using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Identity;

/// <summary>
/// A DNP1 network identifier with its exact 16-byte, non-zero invariant.
/// </summary>
public sealed class DeepNetworkId16 : IEquatable<DeepNetworkId16>
{
    public const int Size = 16;

    private readonly byte[] value;

    private DeepNetworkId16(ReadOnlySpan<byte> value)
    {
        FixedIdentityValue.ValidateNonzero(value, Size, nameof(value));
        this.value = value.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => value.ToArray();

    public static DeepNetworkId16 FromVerifiedBytes(ReadOnlySpan<byte> value) => new(value);

    public void CopyTo(Span<byte> destination) => FixedIdentityValue.CopyTo(value, destination);

    public bool Matches(ReadOnlySpan<byte> candidate) => FixedIdentityValue.Matches(value, candidate);

    public bool Equals(DeepNetworkId16? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(value, other.value);

    public override bool Equals(object? obj) => Equals(obj as DeepNetworkId16);

    public override int GetHashCode() => FixedIdentityValue.GetHashCode(value);

    public override string ToString() => nameof(DeepNetworkId16);
}

/// <summary>
/// A verified Ed25519 account public key with its exact 32-byte, non-zero invariant.
/// </summary>
public sealed class AccountEd25519PublicKey32 : IEquatable<AccountEd25519PublicKey32>
{
    public const int Size = 32;

    private readonly byte[] value;

    private AccountEd25519PublicKey32(ReadOnlySpan<byte> value)
    {
        FixedIdentityValue.ValidateNonzero(value, Size, nameof(value));
        this.value = value.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => value.ToArray();

    public static AccountEd25519PublicKey32 FromVerifiedBytes(ReadOnlySpan<byte> value) => new(value);

    public void CopyTo(Span<byte> destination) => FixedIdentityValue.CopyTo(value, destination);

    public bool Matches(ReadOnlySpan<byte> candidate) => FixedIdentityValue.Matches(value, candidate);

    public bool Equals(AccountEd25519PublicKey32? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(value, other.value);

    public override bool Equals(object? obj) => Equals(obj as AccountEd25519PublicKey32);

    public override int GetHashCode() => FixedIdentityValue.GetHashCode(value);

    public override string ToString() => nameof(AccountEd25519PublicKey32);
}

/// <summary>
/// The network-scoped 32-byte Deep account identifier. Instances are produced only
/// as part of a verified account identity capability; there is no raw-byte parser.
/// </summary>
public sealed class DeepAccountId32 : IEquatable<DeepAccountId32>
{
    public const int Size = 32;

    private readonly byte[] value;

    internal DeepAccountId32(ReadOnlySpan<byte> value)
    {
        FixedIdentityValue.ValidateNonzero(value, Size, nameof(value));
        this.value = value.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => value.ToArray();

    public void CopyTo(Span<byte> destination) => FixedIdentityValue.CopyTo(value, destination);

    public bool Matches(ReadOnlySpan<byte> candidate) => FixedIdentityValue.Matches(value, candidate);

    public bool Equals(DeepAccountId32? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(value, other.value);

    public override bool Equals(object? obj) => Equals(obj as DeepAccountId32);

    public override int GetHashCode() => FixedIdentityValue.GetHashCode(value);

    public override string ToString() => nameof(DeepAccountId32);
}

/// <summary>
/// A sealed set of typed, verified inputs and their canonical DNP1 account ID.
/// </summary>
public sealed class DeepAccountIdentityCapability : IEquatable<DeepAccountIdentityCapability>
{
    private const string AccountIdDomain = "Deep/IdentityAuth/V1/account-id";

    private DeepAccountIdentityCapability(
        DeepNetworkId16 networkId,
        ulong accountGeneration,
        AccountEd25519PublicKey32 accountSigningPublicKey)
    {
        NetworkId = networkId;
        AccountGeneration = accountGeneration;
        AccountSigningPublicKey = accountSigningPublicKey;
        AccountId = DeriveAccountId(networkId, accountGeneration, accountSigningPublicKey);
    }

    public DeepNetworkId16 NetworkId { get; }

    public ulong AccountGeneration { get; }

    public AccountEd25519PublicKey32 AccountSigningPublicKey { get; }

    public DeepAccountId32 AccountId { get; }

    public bool Equals(DeepAccountIdentityCapability? other) =>
        other is not null
        && AccountGeneration == other.AccountGeneration
        && NetworkId.Equals(other.NetworkId)
        && AccountSigningPublicKey.Equals(other.AccountSigningPublicKey)
        && AccountId.Equals(other.AccountId);

    public override bool Equals(object? obj) => Equals(obj as DeepAccountIdentityCapability);

    public override int GetHashCode() => HashCode.Combine(
        NetworkId,
        AccountGeneration,
        AccountSigningPublicKey,
        AccountId);

    public static DeepAccountIdentityCapability FromRecoveryCapabilities(
        DeepRecoveryAccountCapabilities capabilities)
    {
        ArgumentNullException.ThrowIfNull(capabilities);
        byte[]? networkId = null;
        byte[]? publicKey = null;
        try
        {
            networkId = capabilities.NetworkId.ToArray();
            publicKey = capabilities.AccountSigningPublicKey.ToArray();
            return FromVerifiedInputs(
                DeepNetworkId16.FromVerifiedBytes(networkId),
                capabilities.AccountGeneration,
                AccountEd25519PublicKey32.FromVerifiedBytes(publicKey));
        }
        finally
        {
            if (networkId is not null) CryptographicOperations.ZeroMemory(networkId);
            if (publicKey is not null) CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    public static DeepAccountIdentityCapability FromVerifiedInputs(
        DeepNetworkId16 networkId,
        ulong accountGeneration,
        AccountEd25519PublicKey32 accountSigningPublicKey)
    {
        ArgumentNullException.ThrowIfNull(networkId);
        ArgumentNullException.ThrowIfNull(accountSigningPublicKey);
        if (accountGeneration == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(accountGeneration),
                "Account generation starts at one.");
        }

        return new DeepAccountIdentityCapability(networkId, accountGeneration, accountSigningPublicKey);
    }

    private static DeepAccountId32 DeriveAccountId(
        DeepNetworkId16 networkId,
        ulong accountGeneration,
        AccountEd25519PublicKey32 accountSigningPublicKey)
    {
        Span<byte> payload = stackalloc byte[DeepNetworkId16.Size + sizeof(ulong) + AccountEd25519PublicKey32.Size];
        networkId.CopyTo(payload[..DeepNetworkId16.Size]);
        BinaryPrimitives.WriteUInt64BigEndian(payload.Slice(DeepNetworkId16.Size, sizeof(ulong)), accountGeneration);
        accountSigningPublicKey.CopyTo(payload[(DeepNetworkId16.Size + sizeof(ulong))..]);

        var hash = CanonicalGrammar.Sha256Domain(AccountIdDomain, payload);
        try
        {
            return new DeepAccountId32(hash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(payload);
        }
    }
}

/// <summary>
/// A random, non-zero 32-byte device identifier. It has no textual encoding and
/// is independent of every device public key.
/// </summary>
public sealed class DeviceId32 : IEquatable<DeviceId32>
{
    public const int Size = 32;

    private readonly byte[] value;

    private DeviceId32(ReadOnlySpan<byte> value)
    {
        FixedIdentityValue.ValidateNonzero(value, Size, nameof(value));
        this.value = value.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => value.ToArray();

    internal static DeviceId32 Generate()
    {
        Span<byte> value = stackalloc byte[Size];
        do
        {
            RandomNumberGenerator.Fill(value);
        }
        while (FixedIdentityValue.IsZero(value));

        var result = new DeviceId32(value);
        CryptographicOperations.ZeroMemory(value);
        return result;
    }

    /// <summary>
    /// Rehydrates an identifier that was originally returned by <see cref="Generate"/>.
    /// This validates its shape, but cannot retrospectively prove the source of randomness.
    /// </summary>
    internal static DeviceId32 FromPersistedBytes(ReadOnlySpan<byte> value) => new(value);

    public void CopyTo(Span<byte> destination) => FixedIdentityValue.CopyTo(value, destination);

    public bool Matches(ReadOnlySpan<byte> candidate) => FixedIdentityValue.Matches(value, candidate);

    public bool Equals(DeviceId32? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(value, other.value);

    public override bool Equals(object? obj) => Equals(obj as DeviceId32);

    public override int GetHashCode() => FixedIdentityValue.GetHashCode(value);

    public override string ToString() => nameof(DeviceId32);
}

internal static class FixedIdentityValue
{
    internal static void ValidateNonzero(ReadOnlySpan<byte> value, int size, string parameterName)
    {
        if (value.Length != size)
        {
            throw new ArgumentException($"Value must contain exactly {size} bytes.", parameterName);
        }
        if (IsZero(value))
        {
            throw new ArgumentException("Value must not be all zero.", parameterName);
        }
    }

    internal static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;

    internal static bool Matches(ReadOnlySpan<byte> value, ReadOnlySpan<byte> candidate) =>
        candidate.Length == value.Length && CryptographicOperations.FixedTimeEquals(value, candidate);

    internal static void CopyTo(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        if (destination.Length < value.Length)
        {
            throw new ArgumentException(
                $"Destination must contain at least {value.Length} bytes.",
                nameof(destination));
        }
        value.CopyTo(destination);
    }

    internal static int GetHashCode(ReadOnlySpan<byte> value)
    {
        var hash = new HashCode();
        foreach (var item in value)
        {
            hash.Add(item);
        }
        return hash.ToHashCode();
    }
}
