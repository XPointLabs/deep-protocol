using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV1;

public delegate TResult ContactResolverKeyReader<TResult>(ReadOnlySpan<byte> resolverKey);

/// <summary>
/// Owns the transport-specific material derived locally from one permanent,
/// transport-independent Deep ID. The resolver key is callback-only and is
/// wiped when this value is disposed.
/// </summary>
public sealed class PermanentContactResolution : IDisposable
{
    private readonly object gate = new();
    private readonly byte[] locatorHash;
    private byte[]? resolverKey;

    internal PermanentContactResolution(
        ReadOnlySpan<byte> locatorHash32,
        ReadOnlySpan<byte> resolverKey32)
    {
        if (locatorHash32.Length != 32 || locatorHash32.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The permanent locator must be 32 nonzero bytes.", nameof(locatorHash32));
        if (resolverKey32.Length != 32 || resolverKey32.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The public resolver key must be 32 nonzero bytes.", nameof(resolverKey32));
        locatorHash = locatorHash32.ToArray();
        resolverKey = resolverKey32.ToArray();
    }

    public ReadOnlyMemory<byte> LocatorHash => locatorHash.ToArray();

    public TResult UseResolverKey<TResult>(ContactResolverKeyReader<TResult> reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        lock (gate)
        {
            return reader(resolverKey
                ?? throw new ObjectDisposedException(nameof(PermanentContactResolution)));
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            var owned = resolverKey;
            resolverKey = null;
            if (owned is not null)
                CryptographicOperations.ZeroMemory(owned);
        }
    }
}

public static class PermanentContactResolutionDerivation
{
    private const string LocatorDomain = "Deep/ContactResolver/V1/permanent-locator";
    private const string ReadSaltDomain = "Deep/ContactResolver/V1/public-read-salt";
    private const string ReadKeyDomain = "Deep/ContactResolver/V1/public-read-key";

    public static PermanentContactResolution Derive(
        ReadOnlySpan<byte> networkId16,
        ParsedDid1 permanentDeepId)
    {
        ArgumentNullException.ThrowIfNull(permanentDeepId);
        if (networkId16.Length != 16 || networkId16.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Network ID must be exactly 16 nonzero bytes.", nameof(networkId16));

        var addressPublicKey = permanentDeepId.AddressPublicKey.ToArray();
        var readCapability = permanentDeepId.ResolverReadCapability.ToArray();
        byte[]? locatorInput = null;
        byte[]? salt = null;
        byte[]? info = null;
        byte[]? prk = null;
        byte[]? resolverKey = null;
        try
        {
            locatorInput = new byte[48];
            networkId16.CopyTo(locatorInput);
            addressPublicKey.CopyTo(locatorInput, 16);
            var locator = Sha256Domain(LocatorDomain, locatorInput);

            salt = Sha512Domain(ReadSaltDomain, networkId16);
            prk = new byte[64];
            if (HKDF.Extract(HashAlgorithmName.SHA512, readCapability, salt, prk) != prk.Length)
                throw new CryptographicException("HKDF extract returned an unexpected length.");

            var label = Encoding.ASCII.GetBytes(ReadKeyDomain);
            info = new byte[label.Length + 1 + 4 + addressPublicKey.Length];
            label.CopyTo(info, 0);
            BinaryPrimitives.WriteUInt32BigEndian(
                info.AsSpan(label.Length + 1, 4),
                checked((uint)addressPublicKey.Length));
            addressPublicKey.CopyTo(info, label.Length + 5);

            resolverKey = new byte[32];
            HKDF.Expand(HashAlgorithmName.SHA512, prk, resolverKey, info);
            var result = new PermanentContactResolution(locator, resolverKey);
            CryptographicOperations.ZeroMemory(locator);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(addressPublicKey);
            CryptographicOperations.ZeroMemory(readCapability);
            Zero(locatorInput);
            Zero(salt);
            Zero(info);
            Zero(prk);
            Zero(resolverKey);
        }
    }

    private static byte[] Sha256Domain(string domain, ReadOnlySpan<byte> payload) =>
        HashDomain(domain, payload, SHA256.HashData, 32);

    private static byte[] Sha512Domain(string domain, ReadOnlySpan<byte> payload) =>
        HashDomain(domain, payload, SHA512.HashData, 64);

    private static byte[] HashDomain(
        string domain,
        ReadOnlySpan<byte> payload,
        Func<byte[], byte[]> hash,
        int expectedLength)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var preimage = new byte[checked(label.Length + 5 + payload.Length)];
        try
        {
            label.CopyTo(preimage, 0);
            BinaryPrimitives.WriteUInt32BigEndian(
                preimage.AsSpan(label.Length + 1, 4),
                checked((uint)payload.Length));
            payload.CopyTo(preimage.AsSpan(label.Length + 5));
            var result = hash(preimage);
            if (result.Length != expectedLength)
                throw new CryptographicException("Domain hash returned an unexpected length.");
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(preimage);
        }
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
            CryptographicOperations.ZeroMemory(value);
    }
}
