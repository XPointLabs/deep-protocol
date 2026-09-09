using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.Identity;

namespace Deep.Protocol.Tests.Identity;

public sealed class DeepAccountIdentityV1Tests
{
    private const string Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    private const string NetworkHex = "000102030405060708090a0b0c0d0e0f";
    private const string AccountPublicKeyHex = "585ed78681d31c3ed453135171c77bcec77951625baa5b9423a52ad30843ce8b";
    private const string AccountIdHex = "b73445631725f31288201a1e53ec80e3d52cdd37f2a353edbf419013d53c3c10";

    [Fact]
    public void RecoveryCapability_MatchesIndependentRfc8032AndSha256DVector()
    {
        using var phrase = VerifyMnemonic();
        using var recovery = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase,
            Convert.FromHexString(NetworkHex),
            1);

        var identity = recovery.AccountIdentity;

        Assert.Equal(NetworkHex, Hex(identity.NetworkId.Bytes.Span));
        Assert.Equal(1UL, identity.AccountGeneration);
        Assert.Equal(AccountPublicKeyHex, Hex(identity.AccountSigningPublicKey.Bytes.Span));
        Assert.Equal(AccountIdHex, Hex(identity.AccountId.Bytes.Span));
    }

    private static VerifiedDeepRecoveryPhrase VerifyMnemonic()
    {
        var utf8 = Encoding.ASCII.GetBytes(Mnemonic);
        try
        {
            return DeepRecoveryV1.VerifyCanonicalUtf8(utf8);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
        }
    }

    [Fact]
    public void VerifiedTypedInputs_MatchTheIndependentSha256DVector()
    {
        var identity = DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(Convert.FromHexString(NetworkHex)),
            1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Convert.FromHexString(AccountPublicKeyHex)));

        Assert.Equal(AccountIdHex, Hex(identity.AccountId.Bytes.Span));
    }

    [Fact]
    public void TypedValues_ReturnDefensiveCopiesAndUseValueEquality()
    {
        var networkBytes = Convert.FromHexString(NetworkHex);
        var publicKeyBytes = Convert.FromHexString(AccountPublicKeyHex);
        var network = DeepNetworkId16.FromVerifiedBytes(networkBytes);
        var publicKey = AccountEd25519PublicKey32.FromVerifiedBytes(publicKeyBytes);
        var identity = DeepAccountIdentityCapability.FromVerifiedInputs(network, 1, publicKey);

        networkBytes[0] ^= 0xff;
        publicKeyBytes[0] ^= 0xff;
        var networkCopy = network.Bytes.ToArray();
        var accountIdCopy = identity.AccountId.Bytes.ToArray();
        networkCopy[0] ^= 0xff;
        accountIdCopy[0] ^= 0xff;

        Assert.Equal(NetworkHex, Hex(network.Bytes.Span));
        Assert.Equal(AccountPublicKeyHex, Hex(publicKey.Bytes.Span));
        Assert.Equal(AccountIdHex, Hex(identity.AccountId.Bytes.Span));
        Assert.True(identity.AccountId.Matches(Convert.FromHexString(AccountIdHex)));
        Assert.False(identity.AccountId.Matches(new byte[31]));
        Assert.Equal(network, DeepNetworkId16.FromVerifiedBytes(Convert.FromHexString(NetworkHex)));
        Assert.Equal(identity.AccountId, DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(Convert.FromHexString(NetworkHex)),
            1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Convert.FromHexString(AccountPublicKeyHex))).AccountId);
    }

    [Fact]
    public void AccountIdentity_RejectsWrongLengthsZeroValuesAndZeroGeneration()
    {
        Assert.Throws<ArgumentException>(() => DeepNetworkId16.FromVerifiedBytes(new byte[15]));
        Assert.Throws<ArgumentException>(() => DeepNetworkId16.FromVerifiedBytes(new byte[16]));
        Assert.Throws<ArgumentException>(() => AccountEd25519PublicKey32.FromVerifiedBytes(new byte[31]));
        Assert.Throws<ArgumentException>(() => AccountEd25519PublicKey32.FromVerifiedBytes(new byte[32]));

        var network = DeepNetworkId16.FromVerifiedBytes(Convert.FromHexString(NetworkHex));
        var publicKey = AccountEd25519PublicKey32.FromVerifiedBytes(Convert.FromHexString(AccountPublicKeyHex));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            DeepAccountIdentityCapability.FromVerifiedInputs(network, 0, publicKey));
    }

    [Fact]
    public void DeepAccountId_HasNoPublicRawByteFactoryOrConstructor()
    {
        Assert.Empty(typeof(DeepAccountId32).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(
            typeof(DeepAccountId32).GetMethods(BindingFlags.Public | BindingFlags.Static),
            static method => method.ReturnType == typeof(DeepAccountId32));
    }

    [Fact]
    public void DeviceId_GeneratesIndependentNonzeroValuesWithoutTextEncoding()
    {
        var first = DeviceId32.Generate();
        var second = DeviceId32.Generate();

        Assert.Equal(DeviceId32.Size, first.Bytes.Length);
        Assert.Contains(first.Bytes.Span.ToArray(), static value => value != 0);
        Assert.NotEqual(first, second);
        Assert.Equal(nameof(DeviceId32), first.ToString());
    }

    [Fact]
    public void DeviceId_PersistedRoundTripIsStrictAndDefensive()
    {
        var source = Enumerable.Range(1, DeviceId32.Size).Select(static value => checked((byte)value)).ToArray();
        var expected = source.ToArray();
        var deviceId = DeviceId32.FromPersistedBytes(source);
        source[0] ^= 0xff;
        var exposed = deviceId.Bytes.ToArray();
        exposed[1] ^= 0xff;
        Span<byte> copied = stackalloc byte[DeviceId32.Size];
        deviceId.CopyTo(copied);

        Assert.Equal(expected, deviceId.Bytes.ToArray());
        Assert.Equal(expected, copied.ToArray());
        Assert.True(deviceId.Matches(expected));
        Assert.False(deviceId.Matches(new byte[DeviceId32.Size]));
        Assert.Equal(deviceId, DeviceId32.FromPersistedBytes(expected));
        Assert.Throws<ArgumentException>(() => DeviceId32.FromPersistedBytes(new byte[31]));
        Assert.Throws<ArgumentException>(() => DeviceId32.FromPersistedBytes(new byte[32]));
    }

    [Fact]
    public void CopyTo_RejectsShortDestinations()
    {
        var identity = DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(Convert.FromHexString(NetworkHex)),
            1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Convert.FromHexString(AccountPublicKeyHex)));
        var destination = new byte[31];

        Assert.Throws<ArgumentException>(() => identity.AccountId.CopyTo(destination));
    }

    [Fact]
    public void LocalDeviceIntent_BindsIndependentTypedKeysGenerationAndRandomHandles()
    {
        var account = DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(Convert.FromHexString(NetworkHex)),
            1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Convert.FromHexString(AccountPublicKeyHex)));
        using var firstSecrets = new OwnedGenesisDeviceSecrets();
        using var secondSecrets = new OwnedGenesisDeviceSecrets();
        var first = firstSecrets.CreateLocalIntent(account);
        var second = secondSecrets.CreateLocalIntent(account);

        Assert.Equal(1UL, first.DeviceGeneration);
        Assert.Equal(account, first.AccountIdentity);
        Assert.NotEqual(first.DeviceId, second.DeviceId);
        Assert.NotEqual(first.RevocationHandle, second.RevocationHandle);
        Assert.NotEqual(first.SigningPublicKey, second.SigningPublicKey);
        Assert.NotEqual(first.AgreementPublicKey, second.AgreementPublicKey);
        Assert.False(first.DeviceId.Matches(first.RevocationHandle.Bytes.Span));
        Assert.True(first.NoAuthorityClaim);
    }

    [Fact]
    public void GenesisSpecificIssuedDeviceCapability_IsAbsent()
    {
        Assert.Null(typeof(LocalDeviceIdentityIntent).Assembly.GetType(
            "Deep.Protocol.Identity.DeepDeviceIdentityCapability",
            throwOnError: false,
            ignoreCase: false));
    }

    private static string Hex(ReadOnlySpan<byte> value) => Convert.ToHexStringLower(value);
}
