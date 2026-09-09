using System.Security.Cryptography;
using Deep.Protocol.Identity;
using Sodium;

namespace Deep.Protocol.Tests.Identity;

public sealed class DeepIdentityCryptoTests
{
    [Fact]
    public void Ed25519PublicKey_MatchesRfc8032VectorAndVerifiesSeed()
    {
        var seed = Convert.FromHexString(
            "9d61b19deffd5a60ba844af492ec2cc4" +
            "4449c5697b326919703bac031cae7f60");
        var expected = Convert.FromHexString(
            "d75a980182b10ab7d54bfed3c964073a" +
            "0ee172f3daa62325af021a68f707511a");
        try
        {
            var actual = DeepIdentityCrypto.DeriveEd25519PublicKey(seed);

            Assert.Equal(expected, actual);
            Assert.True(DeepIdentityCrypto.Ed25519PublicKeyMatchesSeed(seed, expected));
            expected[0] ^= 0x01;
            Assert.False(DeepIdentityCrypto.Ed25519PublicKeyMatchesSeed(seed, expected));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    [Fact]
    public void X25519PublicKey_MatchesRfc7748VectorAndVerifiesScalar()
    {
        var scalar = Convert.FromHexString(
            "77076d0a7318a57d3c16c17251b26645" +
            "df4c2f87ebc0992ab177fba51db92c2a");
        var expected = Convert.FromHexString(
            "8520f0098930a754748b7ddcb43ef75a" +
            "0dbf3a0d26381af4eba4a98eaa9b4e6a");
        try
        {
            var actual = DeepIdentityCrypto.DeriveX25519PublicKey(scalar);

            Assert.Equal(expected, actual);
            Assert.True(DeepIdentityCrypto.X25519PublicKeyMatchesPrivateScalar(scalar, expected));
            expected[0] ^= 0x01;
            Assert.False(DeepIdentityCrypto.X25519PublicKeyMatchesPrivateScalar(scalar, expected));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scalar);
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void PublicDerivation_RejectsWrongSecretLengths(int length)
    {
        Assert.Throws<ArgumentException>(() => DeepIdentityCrypto.DeriveEd25519PublicKey(new byte[length]));
        Assert.Throws<ArgumentException>(() => DeepIdentityCrypto.DeriveX25519PublicKey(new byte[length]));
    }

    [Fact]
    public void PublicDerivationAndVerification_RejectAllZeroValues()
    {
        var nonzero = Enumerable.Repeat((byte)0x5a, 32).ToArray();
        try
        {
            Assert.Throws<ArgumentException>(() => DeepIdentityCrypto.DeriveEd25519PublicKey(new byte[32]));
            Assert.Throws<ArgumentException>(() => DeepIdentityCrypto.DeriveX25519PublicKey(new byte[32]));
            Assert.Throws<ArgumentException>(() =>
                DeepIdentityCrypto.Ed25519PublicKeyMatchesSeed(nonzero, new byte[32]));
            Assert.Throws<ArgumentException>(() =>
                DeepIdentityCrypto.X25519PublicKeyMatchesPrivateScalar(nonzero, new byte[32]));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonzero);
        }
    }

    [Fact]
    public void OwnedEd25519Derivation_ZeroesCallerOwnedSecretKeyBuffer()
    {
        var seed = Enumerable.Repeat((byte)0x33, 32).ToArray();
        var publicKey = new byte[OwnedSodiumEd25519.PublicKeySize];
        var temporarySecretKey = Enumerable.Repeat((byte)0xa5, OwnedSodiumEd25519.SecretKeySize).ToArray();
        try
        {
            OwnedSodiumEd25519.DerivePublicKey(seed, publicKey, temporarySecretKey);

            Assert.Contains(publicKey, static value => value != 0);
            Assert.All(temporarySecretKey, static value => Assert.Equal(0, value));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(temporarySecretKey);
        }
    }

    [Fact]
    public void OwnedEd25519Derivation_ZeroesSecretBufferWhenValidationFails()
    {
        var temporarySecretKey = Enumerable.Repeat((byte)0xa5, OwnedSodiumEd25519.SecretKeySize).ToArray();
        try
        {
            Assert.Throws<ArgumentException>(() => OwnedSodiumEd25519.DerivePublicKey(
                new byte[DeepIdentityCrypto.Ed25519SeedSize],
                new byte[OwnedSodiumEd25519.PublicKeySize],
                temporarySecretKey));

            Assert.All(temporarySecretKey, static value => Assert.Equal(0, value));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(temporarySecretKey);
        }
    }

    [Fact]
    public void OwnedEd25519Signing_ZeroesBothCallerOwnedTemporaryBuffers()
    {
        var seed = Convert.FromHexString(
            "4ccd089b28ff96da9db6c346ec114e0f" +
            "5b8a319f35aba624da8cf6ed4fb8a6fb");
        var message = new byte[] { 0x72 };
        var expectedSignature = Convert.FromHexString(
            "92a009a9f0d4cab8720e820b5f642540" +
            "a2b27b5416503f8fb3762223ebdb69da" +
            "085ac1e43e15996e458f3613d0f11d8c" +
            "387b2eaeb4302aeeb00d291612bb0c00");
        var signature = new byte[OwnedSodiumEd25519.SignatureSize];
        var temporaryPublicKey = Enumerable.Repeat((byte)0xa5, OwnedSodiumEd25519.PublicKeySize).ToArray();
        var temporarySecretKey = Enumerable.Repeat((byte)0xa5, OwnedSodiumEd25519.SecretKeySize).ToArray();
        try
        {
            OwnedSodiumEd25519.SignDetached(
                seed,
                message,
                signature,
                temporaryPublicKey,
                temporarySecretKey);

            var publicKey = DeepIdentityCrypto.DeriveEd25519PublicKey(seed);
            Assert.Equal(expectedSignature, signature);
            Assert.True(PublicKeyAuth.VerifyDetached(signature, message, publicKey));
            Assert.All(temporaryPublicKey, static value => Assert.Equal(0, value));
            Assert.All(temporarySecretKey, static value => Assert.Equal(0, value));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(message);
            CryptographicOperations.ZeroMemory(expectedSignature);
            CryptographicOperations.ZeroMemory(signature);
            CryptographicOperations.ZeroMemory(temporaryPublicKey);
            CryptographicOperations.ZeroMemory(temporarySecretKey);
        }
    }

    [Fact]
    public void OwnedEd25519Signing_ZeroesTemporaryBuffersWhenValidationFails()
    {
        var seed = Enumerable.Repeat((byte)0x55, 32).ToArray();
        var temporaryPublicKey = Enumerable.Repeat((byte)0xa5, OwnedSodiumEd25519.PublicKeySize).ToArray();
        var temporarySecretKey = Enumerable.Repeat((byte)0xa5, OwnedSodiumEd25519.SecretKeySize).ToArray();
        try
        {
            Assert.Throws<ArgumentException>(() => OwnedSodiumEd25519.SignDetached(
                seed,
                ReadOnlySpan<byte>.Empty,
                new byte[OwnedSodiumEd25519.SignatureSize],
                temporaryPublicKey,
                temporarySecretKey));

            Assert.All(temporaryPublicKey, static value => Assert.Equal(0, value));
            Assert.All(temporarySecretKey, static value => Assert.Equal(0, value));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(temporaryPublicKey);
            CryptographicOperations.ZeroMemory(temporarySecretKey);
        }
    }

    [Fact]
    public void PublicSurface_ContainsNoPrivateKeyOrEdToXConversionMethod()
    {
        var methods = typeof(DeepIdentityCrypto).GetMethods(
            System.Reflection.BindingFlags.Public |
            System.Reflection.BindingFlags.Static |
            System.Reflection.BindingFlags.DeclaredOnly);

        Assert.DoesNotContain(methods, static method =>
            method.ReturnType == typeof(byte[]) &&
            method.Name.Contains("Private", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(methods, static method =>
            method.Name.Contains("Convert", StringComparison.OrdinalIgnoreCase));
    }
}
