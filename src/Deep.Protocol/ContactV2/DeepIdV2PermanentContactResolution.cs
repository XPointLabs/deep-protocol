using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Protocol.ContactV2;

internal delegate TResult DeepIdV2ResolverKeyReader<TResult>(ReadOnlySpan<byte> resolverKey);

/// <summary>
/// Locally derived DID2 resolver material. The read key is never exposed as a
/// property and is wiped on disposal; this value grants no publication authority.
/// </summary>
internal sealed class DeepIdV2PermanentContactResolution : IDisposable
{
    private readonly object gate = new();
    private readonly byte[] locatorHash;
    private byte[]? resolverKey;

    internal DeepIdV2PermanentContactResolution(byte[] locatorHash, byte[] resolverKey)
    {
        this.locatorHash = locatorHash.ToArray();
        this.resolverKey = resolverKey.ToArray();
    }

    public ReadOnlyMemory<byte> LocatorHash => locatorHash.ToArray();

    public TResult UseResolverKey<TResult>(DeepIdV2ResolverKeyReader<TResult> reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        lock (gate)
            return reader(resolverKey ?? throw new ObjectDisposedException(
                nameof(DeepIdV2PermanentContactResolution)));
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

/// <summary>
/// DID2-only, transport-specific derivation from the exact public credential
/// and a separately held resolver capability. DID2 alone cannot yield the key.
/// </summary>
internal static class DeepIdV2PermanentContactResolutionDerivation
{
    public static bool RuntimeActivation => false;

    public static DeepIdV2PermanentContactResolution Derive(
        ReadOnlySpan<byte> networkId16, ParsedDid2 did2,
        ReadOnlySpan<byte> resolverReadCapability16)
    {
        ArgumentNullException.ThrowIfNull(did2);
        if (networkId16.Length != 16 || IsZero(networkId16))
            throw new ArgumentException("Network ID must be 16 nonzero bytes.",
                nameof(networkId16));
        if (!did2.MatchesResolverReadCapability(resolverReadCapability16))
            throw new CryptographicException(
                "The resolver capability does not match the exact DID2 commitment.");

        return DeriveCore(networkId16, did2.RecordHash.Span, resolverReadCapability16);
    }

    internal static DeepIdV2PermanentContactResolution DeriveFromDescriptor(
        ReadOnlySpan<byte> networkId16, DeepPermanentIdV2 descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (networkId16.Length != 16 || IsZero(networkId16))
            throw new ArgumentException("An exact nonzero network is required.", nameof(networkId16));
        var capability = descriptor.ResolverReadCapability.ToArray();
        try { return DeriveCore(networkId16, descriptor.ExactDid2Hash.Span, capability); }
        finally { CryptographicOperations.ZeroMemory(capability); }
    }

    private static DeepIdV2PermanentContactResolution DeriveCore(
        ReadOnlySpan<byte> networkId16, ReadOnlySpan<byte> did2Hash,
        ReadOnlySpan<byte> resolverReadCapability16)
    {
        var didHash = did2Hash.ToArray();
        byte[]? salt = null;
        byte[]? prk = null;
        byte[]? info = null;
        byte[]? key = null;
        try
        {
            var locator = ComputeLocator(networkId16, didHash);
            try
            {
                salt = Sha512Domain(
                    "Deep/ContactResolver/V2/public-read-salt", networkId16);
                prk = new byte[64];
                if (HKDF.Extract(HashAlgorithmName.SHA512,
                        resolverReadCapability16, salt, prk) != prk.Length)
                    throw new CryptographicException("HKDF extract length is invalid.");
                var label = Encoding.ASCII.GetBytes(
                    "Deep/ContactResolver/V2/public-read-key");
                info = new byte[label.Length + 1 + 4 + didHash.Length];
                label.CopyTo(info, 0);
                BinaryPrimitives.WriteUInt32BigEndian(
                    info.AsSpan(label.Length + 1, 4), (uint)didHash.Length);
                didHash.CopyTo(info, label.Length + 5);
                key = new byte[32];
                HKDF.Expand(HashAlgorithmName.SHA512, prk, key, info);
                return new DeepIdV2PermanentContactResolution(locator, key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(locator);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(didHash);
            if (salt is not null) CryptographicOperations.ZeroMemory(salt);
            if (prk is not null) CryptographicOperations.ZeroMemory(prk);
            if (info is not null) CryptographicOperations.ZeroMemory(info);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
        }
    }

    // Public reachability identifier only: this never derives a resolver key.
    // Keep bootstrap resolution and private authenticated reply routes on the
    // same existing domain rather than duplicating a second hash algorithm.
    internal static byte[] ComputeLocator(ReadOnlySpan<byte> networkId16, ReadOnlySpan<byte> did2Hash32)
    {
        if (networkId16.Length != 16 || IsZero(networkId16) || did2Hash32.Length != 32 || IsZero(did2Hash32))
            throw new ArgumentException("The permanent locator requires an exact nonzero network and DID2 hash.");
        Span<byte> material = stackalloc byte[48];
        networkId16.CopyTo(material); did2Hash32.CopyTo(material[16..]);
        return ApplicationCoreFormat.Sha256Domain("Deep/ContactResolver/V2/permanent-locator", material);
    }

    private static byte[] Sha512Domain(string label, ReadOnlySpan<byte> value)
    {
        var ascii = Encoding.ASCII.GetBytes(label);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        hash.AppendData(ascii);
        hash.AppendData([0]);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)value.Length);
        hash.AppendData(length);
        hash.AppendData(value);
        return hash.GetHashAndReset();
    }

    private static bool IsZero(ReadOnlySpan<byte> bytes)
    {
        byte combined = 0;
        foreach (var value in bytes) combined |= value;
        return combined == 0;
    }
}
