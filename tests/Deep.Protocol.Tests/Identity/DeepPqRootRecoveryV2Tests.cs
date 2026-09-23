using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.Identity;

namespace Deep.Protocol.Tests.Identity;

public sealed class DeepPqRootRecoveryV2Tests
{
    private const string ZeroEntropyPhrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon " +
        "abandon abandon abandon abandon abandon abandon abandon abandon " +
        "abandon abandon abandon abandon abandon abandon abandon art";

    [Fact]
    public void RootDerivation_MatchesIndependentPythonDigestVector()
    {
        using var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(
            Encoding.ASCII.GetBytes(ZeroEntropyPhrase));
        var called = false;

        DeepPqRootRecoveryV2.UseRootMaterial(phrase, (ed, pq, capability) =>
        {
            called = true;
            Assert.Equal(32, ed.Length);
            Assert.Equal(32, pq.Length);
            Assert.Equal(16, capability.Length);
            Assert.Equal(
                "8d2ac3afb8ca7baacf03b18edb61b80bb006e01f06c4b7c448d575982aefc571",
                Convert.ToHexStringLower(SHA256.HashData(ed)));
            Assert.Equal(
                "4db2d658dcbeae33831ae7db06f79ac49be13c2abeb7d470f7a6138cbcc87c8e",
                Convert.ToHexStringLower(SHA256.HashData(pq)));
            Assert.Equal(
                "42381d6d25d37d5d1a93517eabd0b64eab462d81f5f258435b00aa0e084f8522",
                Convert.ToHexStringLower(SHA256.HashData(capability)));
        });

        Assert.True(called);
    }

    [Fact]
    public void RootDerivation_IsStableAcrossCalls_AndSeparatedFromOldAddressSeed()
    {
        using var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(
            Encoding.ASCII.GetBytes(ZeroEntropyPhrase));
        var network = new byte[16];
        network[0] = 1;
        using var oldCapabilities = DeepRecoveryV1.DeriveAccountCapabilities(phrase, network, 1);
        byte[]? firstDigest = null;
        DeepPqRootRecoveryV2.UseRootMaterial(phrase, (ed, pq, capability) =>
        {
            var combined = Combine(ed, pq, capability);
            try { firstDigest = SHA256.HashData(combined); }
            finally { CryptographicOperations.ZeroMemory(combined); }
        });

        DeepPqRootRecoveryV2.UseRootMaterial(phrase, (ed, pq, capability) =>
        {
            var combined = Combine(ed, pq, capability);
            try
            {
                var secondDigest = SHA256.HashData(combined);
                try { Assert.Equal(firstDigest, secondDigest); }
                finally { CryptographicOperations.ZeroMemory(secondDigest); }
            }
            finally { CryptographicOperations.ZeroMemory(combined); }
            Assert.False(capability.SequenceEqual(oldCapabilities.AddressReadCapability.Span));
            var newEdPublicKey = DeepIdentityCrypto.DeriveEd25519PublicKey(ed);
            try
            {
                Assert.False(newEdPublicKey.AsSpan().SequenceEqual(
                    oldCapabilities.AddressSigningPublicKey.Span));
            }
            finally { CryptographicOperations.ZeroMemory(newEdPublicKey); }
        });

        Assert.NotNull(firstDigest);
        CryptographicOperations.ZeroMemory(firstDigest);
    }

    [Fact]
    public void RootDerivation_RejectsDisposedPhrase_BeforeConsumer()
    {
        var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(Encoding.ASCII.GetBytes(ZeroEntropyPhrase));
        phrase.Dispose();
        var called = false;

        Assert.Throws<ObjectDisposedException>(() =>
            DeepPqRootRecoveryV2.UseRootMaterial(phrase, (_, _, _) => called = true));
        Assert.False(called);
    }

    private static byte[] Combine(
        ReadOnlySpan<byte> ed,
        ReadOnlySpan<byte> pq,
        ReadOnlySpan<byte> capability)
    {
        var result = new byte[ed.Length + pq.Length + capability.Length];
        ed.CopyTo(result);
        pq.CopyTo(result.AsSpan(ed.Length));
        capability.CopyTo(result.AsSpan(ed.Length + pq.Length));
        return result;
    }
}
