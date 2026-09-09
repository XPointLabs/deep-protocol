using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class PermanentContactResolutionTests
{
    [Fact]
    public void Derive_MatchesIndependentNormativeConstruction()
    {
        var network = Bytes(16, 0x11);
        var addressKey = Bytes(32, 0x22);
        var capability = Bytes(16, 0x33);
        var did = ApplicationCoreCodec.AuthorDid1(addressKey, capability);

        using var derived = PermanentContactResolutionDerivation.Derive(network, did);

        Assert.Equal(
            Sha256Domain(
                "Deep/ContactResolver/V1/permanent-locator",
                network.Concat(addressKey).ToArray()),
            derived.LocatorHash.ToArray());
        derived.UseResolverKey(key =>
        {
            Assert.Equal(ExpectedResolverKey(network, addressKey, capability), key.ToArray());
            return 0;
        });
    }

    [Fact]
    public void Derive_IsNetworkScopedWhilePermanentDidRemainsUnchanged()
    {
        var did = ApplicationCoreCodec.AuthorDid1(Bytes(32, 0x42), Bytes(16, 0x43));
        using var first = PermanentContactResolutionDerivation.Derive(Bytes(16, 0x01), did);
        using var second = PermanentContactResolutionDerivation.Derive(Bytes(16, 0x02), did);

        Assert.Equal(90, did.Text.Length);
        Assert.NotEqual(first.LocatorHash.ToArray(), second.LocatorHash.ToArray());
        var firstKey = first.UseResolverKey(static key => key.ToArray());
        var secondKey = second.UseResolverKey(static key => key.ToArray());
        try { Assert.NotEqual(firstKey, secondKey); }
        finally
        {
            CryptographicOperations.ZeroMemory(firstKey);
            CryptographicOperations.ZeroMemory(secondKey);
        }
    }

    [Fact]
    public void ResolverKey_IsUnavailableAfterDisposeAndLocatorIsDefensive()
    {
        var value = PermanentContactResolutionDerivation.Derive(
            Bytes(16, 0x51),
            ApplicationCoreCodec.AuthorDid1(Bytes(32, 0x52), Bytes(16, 0x53)));
        var locator = value.LocatorHash.ToArray();
        locator[0] ^= 0xff;
        Assert.NotEqual(locator, value.LocatorHash.ToArray());

        value.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
            value.UseResolverKey(static _ => 0));
    }

    [Theory]
    [InlineData(15)]
    [InlineData(17)]
    public void InvalidNetworkRejects(int length)
    {
        var did = ApplicationCoreCodec.AuthorDid1(Bytes(32, 0x61), Bytes(16, 0x62));
        Assert.Throws<ArgumentException>(() =>
            PermanentContactResolutionDerivation.Derive(new byte[length], did));
    }

    private static byte[] ExpectedResolverKey(byte[] network, byte[] addressKey, byte[] capability)
    {
        var salt = Sha512Domain("Deep/ContactResolver/V1/public-read-salt", network);
        var prk = new byte[64];
        var label = Encoding.ASCII.GetBytes("Deep/ContactResolver/V1/public-read-key");
        var info = new byte[label.Length + 1 + 4 + addressKey.Length];
        var result = new byte[32];
        try
        {
            Assert.Equal(64, HKDF.Extract(HashAlgorithmName.SHA512, capability, salt, prk));
            label.CopyTo(info, 0);
            BinaryPrimitives.WriteUInt32BigEndian(info.AsSpan(label.Length + 1), 32);
            addressKey.CopyTo(info, label.Length + 5);
            HKDF.Expand(HashAlgorithmName.SHA512, prk, result, info);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(info);
        }
    }

    private static byte[] Sha256Domain(string domain, byte[] payload) =>
        HashDomain(domain, payload, SHA256.HashData);

    private static byte[] Sha512Domain(string domain, byte[] payload) =>
        HashDomain(domain, payload, SHA512.HashData);

    private static byte[] HashDomain(string domain, byte[] payload, Func<byte[], byte[]> hash)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var input = new byte[label.Length + 5 + payload.Length];
        label.CopyTo(input, 0);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(label.Length + 1), checked((uint)payload.Length));
        payload.CopyTo(input, label.Length + 5);
        return hash(input);
    }

    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
}
