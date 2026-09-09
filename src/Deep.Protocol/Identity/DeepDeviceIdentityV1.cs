using System.Security.Cryptography;

namespace Deep.Protocol.Identity;

/// <summary>A role-typed Ed25519 device identity public key.</summary>
public sealed class DeviceEd25519PublicKey32 : IEquatable<DeviceEd25519PublicKey32>
{
    public const int Size = 32;
    private readonly byte[] value;

    private DeviceEd25519PublicKey32(ReadOnlySpan<byte> value)
    {
        FixedIdentityValue.ValidateNonzero(value, Size, nameof(value));
        this.value = value.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => value.ToArray();
    internal static DeviceEd25519PublicKey32 FromVerifiedBytes(ReadOnlySpan<byte> value) => new(value);
    public void CopyTo(Span<byte> destination) => FixedIdentityValue.CopyTo(value, destination);
    public bool Matches(ReadOnlySpan<byte> candidate) => FixedIdentityValue.Matches(value, candidate);
    public bool Equals(DeviceEd25519PublicKey32? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(value, other.value);
    public override bool Equals(object? obj) => Equals(obj as DeviceEd25519PublicKey32);
    public override int GetHashCode() => FixedIdentityValue.GetHashCode(value);
    public override string ToString() => nameof(DeviceEd25519PublicKey32);
}

/// <summary>A role-typed X25519 device identity public key.</summary>
public sealed class DeviceX25519PublicKey32 : IEquatable<DeviceX25519PublicKey32>
{
    public const int Size = 32;
    private readonly byte[] value;

    private DeviceX25519PublicKey32(ReadOnlySpan<byte> value)
    {
        FixedIdentityValue.ValidateNonzero(value, Size, nameof(value));
        this.value = value.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => value.ToArray();
    internal static DeviceX25519PublicKey32 FromVerifiedBytes(ReadOnlySpan<byte> value) => new(value);
    public void CopyTo(Span<byte> destination) => FixedIdentityValue.CopyTo(value, destination);
    public bool Matches(ReadOnlySpan<byte> candidate) => FixedIdentityValue.Matches(value, candidate);
    public bool Equals(DeviceX25519PublicKey32? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(value, other.value);
    public override bool Equals(object? obj) => Equals(obj as DeviceX25519PublicKey32);
    public override int GetHashCode() => FixedIdentityValue.GetHashCode(value);
    public override string ToString() => nameof(DeviceX25519PublicKey32);
}

/// <summary>A role-typed X25519 signed-prekey public key, distinct from the device identity key.</summary>
public sealed class DevicePrekeyX25519PublicKey32 : IEquatable<DevicePrekeyX25519PublicKey32>
{
    public const int Size = 32;
    private readonly byte[] value;

    private DevicePrekeyX25519PublicKey32(ReadOnlySpan<byte> value)
    {
        FixedIdentityValue.ValidateNonzero(value, Size, nameof(value));
        this.value = value.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => value.ToArray();
    internal static DevicePrekeyX25519PublicKey32 FromVerifiedBytes(ReadOnlySpan<byte> value) => new(value);
    public void CopyTo(Span<byte> destination) => FixedIdentityValue.CopyTo(value, destination);
    public bool Matches(ReadOnlySpan<byte> candidate) => FixedIdentityValue.Matches(value, candidate);
    public bool Equals(DevicePrekeyX25519PublicKey32? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(value, other.value);
    public override bool Equals(object? obj) => Equals(obj as DevicePrekeyX25519PublicKey32);
    public override int GetHashCode() => FixedIdentityValue.GetHashCode(value);
    public override string ToString() => nameof(DevicePrekeyX25519PublicKey32);
}

/// <summary>
/// The random DPD1 revocation handle. It is independent of the device ID and keys.
/// </summary>
public sealed class DeviceRevocationHandle32 : IEquatable<DeviceRevocationHandle32>
{
    public const int Size = 32;
    private readonly byte[] value;

    private DeviceRevocationHandle32(ReadOnlySpan<byte> value)
    {
        FixedIdentityValue.ValidateNonzero(value, Size, nameof(value));
        this.value = value.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => value.ToArray();

    internal static DeviceRevocationHandle32 Generate()
    {
        Span<byte> value = stackalloc byte[Size];
        do
        {
            RandomNumberGenerator.Fill(value);
        }
        while (FixedIdentityValue.IsZero(value));

        var result = new DeviceRevocationHandle32(value);
        CryptographicOperations.ZeroMemory(value);
        return result;
    }

    internal static DeviceRevocationHandle32 FromPersistedBytes(ReadOnlySpan<byte> value) => new(value);
    public void CopyTo(Span<byte> destination) => FixedIdentityValue.CopyTo(value, destination);
    public bool Matches(ReadOnlySpan<byte> candidate) => FixedIdentityValue.Matches(value, candidate);
    public bool Equals(DeviceRevocationHandle32? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(value, other.value);
    public override bool Equals(object? obj) => Equals(obj as DeviceRevocationHandle32);
    public override int GetHashCode() => FixedIdentityValue.GetHashCode(value);
    public override string ToString() => nameof(DeviceRevocationHandle32);
}

/// <summary>
/// A local, non-authoritative device identity intent. It cannot be converted to
/// a remote device capability without exact DPD1, Verified DXR1 and subject-head CAS evidence.
/// </summary>
public sealed class LocalDeviceIdentityIntent : IEquatable<LocalDeviceIdentityIntent>
{
    internal LocalDeviceIdentityIntent(
        DeepAccountIdentityCapability accountIdentity,
        DeviceId32 deviceId,
        ulong deviceGeneration,
        DeviceEd25519PublicKey32 signingPublicKey,
        DeviceX25519PublicKey32 agreementPublicKey,
        DeviceRevocationHandle32 revocationHandle)
    {
        AccountIdentity = accountIdentity;
        DeviceId = deviceId;
        DeviceGeneration = deviceGeneration;
        SigningPublicKey = signingPublicKey;
        AgreementPublicKey = agreementPublicKey;
        RevocationHandle = revocationHandle;
    }

    public DeepAccountIdentityCapability AccountIdentity { get; }
    public DeviceId32 DeviceId { get; }
    public ulong DeviceGeneration { get; }
    public DeviceEd25519PublicKey32 SigningPublicKey { get; }
    public DeviceX25519PublicKey32 AgreementPublicKey { get; }
    public DeviceRevocationHandle32 RevocationHandle { get; }
    public bool NoAuthorityClaim => true;

    public bool Equals(LocalDeviceIdentityIntent? other) =>
        other is not null && DeviceGeneration == other.DeviceGeneration &&
        AccountIdentity.Equals(other.AccountIdentity) && DeviceId.Equals(other.DeviceId) &&
        SigningPublicKey.Equals(other.SigningPublicKey) &&
        AgreementPublicKey.Equals(other.AgreementPublicKey) &&
        RevocationHandle.Equals(other.RevocationHandle);

    public override bool Equals(object? obj) => Equals(obj as LocalDeviceIdentityIntent);
    public override int GetHashCode() => HashCode.Combine(
        AccountIdentity, DeviceId, DeviceGeneration, SigningPublicKey,
        AgreementPublicKey, RevocationHandle);
}
