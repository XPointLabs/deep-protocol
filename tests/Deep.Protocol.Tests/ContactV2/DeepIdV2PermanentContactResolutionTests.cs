using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2PermanentContactResolutionTests
{
    [Fact]
    public void Did2HashAndPrivateCapabilityDeriveExactNetworkScopedMaterial()
    {
        var network = Bytes(16, 0x11);
        var capability = Bytes(16, 0x31);
        var did = DeepIdV2Codec.AuthorDid2(
            Bytes(32, 0x21), Bytes(1952, 0x22), capability);
        var didHash = did.RecordHash.ToArray();

        using var resolution = DeepIdV2PermanentContactResolutionDerivation.Derive(
            network, did, capability);

        Assert.False(DeepIdV2PermanentContactResolutionDerivation.RuntimeActivation);
        Assert.Equal(DomainHash(HashAlgorithmName.SHA256,
            "Deep/ContactResolver/V2/permanent-locator",
            network.Concat(didHash).ToArray()), resolution.LocatorHash.ToArray());
        var salt = DomainHash(HashAlgorithmName.SHA512,
            "Deep/ContactResolver/V2/public-read-salt", network);
        var prk = HKDF.Extract(HashAlgorithmName.SHA512, capability, salt);
        var info = Encoding.ASCII.GetBytes(
            "Deep/ContactResolver/V2/public-read-key")
            .Concat(new byte[] { 0, 0, 0, 0, 32 }).Concat(didHash).ToArray();
        var expectedKey = HKDF.Expand(HashAlgorithmName.SHA512, prk, 32, info);
        try
        {
            resolution.UseResolverKey(key =>
            {
                Assert.True(key.SequenceEqual(expectedKey));
                return 0;
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(info);
            CryptographicOperations.ZeroMemory(expectedKey);
        }
    }

    [Fact]
    public void WrongCapabilityOrNetworkRejectsBeforeKeyUse()
    {
        var capability = Bytes(16, 0x31);
        var did = DeepIdV2Codec.AuthorDid2(
            Bytes(32, 0x21), Bytes(1952, 0x22), capability);
        Assert.Throws<CryptographicException>(() =>
            DeepIdV2PermanentContactResolutionDerivation.Derive(
                Bytes(16, 0x11), did, Bytes(16, 0x32)));
        Assert.Throws<CryptographicException>(() =>
            DeepIdV2PermanentContactResolutionDerivation.Derive(
                Bytes(16, 0x11), did, new byte[16]));
        Assert.Throws<ArgumentException>(() =>
            DeepIdV2PermanentContactResolutionDerivation.Derive(
                new byte[16], did, capability));
        Assert.Throws<ArgumentException>(() =>
            DeepIdV2PermanentContactResolutionDerivation.Derive(
                Bytes(15, 0x11), did, capability));
    }

    [Fact]
    public void DifferentNetworkAndDid2CannotShareLocatorOrReadKey()
    {
        var capability = Bytes(16, 0x31);
        var did = DeepIdV2Codec.AuthorDid2(
            Bytes(32, 0x21), Bytes(1952, 0x22), capability);
        var anotherDid = DeepIdV2Codec.AuthorDid2(
            Bytes(32, 0x23), Bytes(1952, 0x22), capability);
        using var first = DeepIdV2PermanentContactResolutionDerivation.Derive(
            Bytes(16, 0x11), did, capability);
        using var second = DeepIdV2PermanentContactResolutionDerivation.Derive(
            Bytes(16, 0x12), did, capability);
        using var third = DeepIdV2PermanentContactResolutionDerivation.Derive(
            Bytes(16, 0x11), anotherDid, capability);
        Assert.NotEqual(first.LocatorHash.ToArray(), second.LocatorHash.ToArray());
        Assert.NotEqual(first.LocatorHash.ToArray(), third.LocatorHash.ToArray());
        var key = first.UseResolverKey(static value => value.ToArray());
        try
        {
            Assert.False(second.UseResolverKey(value => value.SequenceEqual(key)));
            Assert.False(third.UseResolverKey(value => value.SequenceEqual(key)));
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    [Fact]
    public void LocatorIsDefensiveAndDisposedKeyCannotBeRead()
    {
        var capability = Bytes(16, 0x31);
        var did = DeepIdV2Codec.AuthorDid2(
            Bytes(32, 0x21), Bytes(1952, 0x22), capability);
        var resolution = DeepIdV2PermanentContactResolutionDerivation.Derive(
            Bytes(16, 0x11), did, capability);
        var locator = resolution.LocatorHash.ToArray();
        locator[0] ^= 0xff;
        Assert.NotEqual(locator, resolution.LocatorHash.ToArray());
        resolution.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            resolution.UseResolverKey(static _ => 0));
    }

    private static byte[] DomainHash(HashAlgorithmName algorithm,
        string domain, byte[] value)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var input = new byte[label.Length + 5 + value.Length];
        label.CopyTo(input, 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            input.AsSpan(label.Length + 1), (uint)value.Length);
        value.CopyTo(input, label.Length + 5);
        return algorithm == HashAlgorithmName.SHA256
            ? SHA256.HashData(input) : SHA512.HashData(input);
    }

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();
}
