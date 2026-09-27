using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Sodium;

namespace Deep.Protocol.ContactV2;

internal delegate void DeepIdV2ResolverNonceEntropy(Span<byte> nonce24);

/// <summary>
/// DID2-only cryptographic object framing. Opening returns a parsed DCR1 V2,
/// never directory freshness, publication or contact authority.
/// </summary>
internal static class DeepIdV2ResolverObjectProtection
{
    private const int NonceLength = 24;
    private const int TagLength = 16;
    private const int MinimumProtectedLength =
        NonceLength + TagLength + 62 + DeepIdV2ContactBundleCodec.MinimumLength + 1;
    private const int MaximumProtectedLength =
        NonceLength + TagLength + DeepIdV2ResolverClosureCodec.MaximumLength;

    public static bool RuntimeActivation => false;

    public static byte[] Seal(ParsedDcr1V2 closure, ReadOnlySpan<byte> networkId16,
        ParsedDid2 did2, DeepIdV2PermanentContactResolution resolution) =>
        SealCore(closure, networkId16, did2, resolution,
            static nonce => RandomNumberGenerator.Fill(nonce));

    internal static byte[] SealCore(ParsedDcr1V2 closure,
        ReadOnlySpan<byte> networkId16, ParsedDid2 did2,
        DeepIdV2PermanentContactResolution resolution,
        DeepIdV2ResolverNonceEntropy entropy)
    {
        ArgumentNullException.ThrowIfNull(closure);
        ArgumentNullException.ThrowIfNull(resolution);
        ArgumentNullException.ThrowIfNull(entropy);
        var aad = CreateAad(networkId16, did2);
        var plaintext = closure.CanonicalBytes.ToArray();
        var nonce = new byte[NonceLength];
        byte[]? ciphertext = null;
        try
        {
            RequireResolutionContext(resolution, networkId16, did2);
            RequireExactBundle(closure, networkId16, did2);
            entropy(nonce);
            ciphertext = resolution.UseResolverKey(key =>
            {
                var ownedKey = key.ToArray();
                try
                {
                    return SecretAeadXChaCha20Poly1305.Encrypt(
                        plaintext, nonce, ownedKey, aad);
                }
                finally { CryptographicOperations.ZeroMemory(ownedKey); }
            });
            if (ciphertext.Length != plaintext.Length + TagLength)
                throw new CryptographicException("DCR1 V2 ciphertext size is invalid.");
            var protectedBytes = new byte[NonceLength + ciphertext.Length];
            nonce.CopyTo(protectedBytes, 0);
            ciphertext.CopyTo(protectedBytes, NonceLength);
            return protectedBytes;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(nonce);
            if (ciphertext is not null)
                CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public static ParsedDcr1V2 Open(ReadOnlySpan<byte> protectedBytes,
        ReadOnlySpan<byte> networkId16, ParsedDid2 did2,
        DeepIdV2PermanentContactResolution resolution)
    {
        ArgumentNullException.ThrowIfNull(resolution);
        if (protectedBytes.Length is < MinimumProtectedLength or > MaximumProtectedLength)
            throw new CryptographicException("Protected DCR1 V2 size is invalid.");
        var aad = CreateAad(networkId16, did2);
        var nonce = protectedBytes[..NonceLength].ToArray();
        var ciphertext = protectedBytes[NonceLength..].ToArray();
        byte[]? plaintext = null;
        try
        {
            RequireResolutionContext(resolution, networkId16, did2);
            try
            {
                plaintext = resolution.UseResolverKey(key =>
                {
                    var ownedKey = key.ToArray();
                    try
                    {
                        return SecretAeadXChaCha20Poly1305.Decrypt(
                            ciphertext, nonce, ownedKey, aad);
                    }
                    finally { CryptographicOperations.ZeroMemory(ownedKey); }
                });
            }
            catch (Exception exception) when (exception is CryptographicException or
                ArgumentException)
            {
                throw new CryptographicException(
                    "DCR1 V2 object authentication failed.", exception);
            }
            var closure = DeepIdV2ResolverClosureCodec.Decode(plaintext);
            RequireExactBundle(closure, networkId16, did2);
            return closure;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            if (plaintext is not null)
                CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static byte[] CreateAad(ReadOnlySpan<byte> networkId16, ParsedDid2 did2)
    {
        ArgumentNullException.ThrowIfNull(did2);
        if (networkId16.Length != 16 ||
            networkId16.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Network ID must be 16 nonzero bytes.",
                nameof(networkId16));
        var aad = new byte[48];
        networkId16.CopyTo(aad);
        did2.RecordHash.Span.CopyTo(aad.AsSpan(16));
        return aad;
    }

    private static void RequireExactBundle(ParsedDcr1V2 closure,
        ReadOnlySpan<byte> networkId16, ParsedDid2 did2)
    {
        if (!closure.Bundle.Field(1).Span.SequenceEqual(networkId16) ||
            !closure.Bundle.Field(22).Span.SequenceEqual(did2.RecordHash.Span) ||
            !closure.Bundle.Field(23).Span.SequenceEqual(did2.CanonicalBytes.Span))
            throw new CryptographicException(
                "DCR1 V2 is not bound to the exact network and DID2.");
    }

    private static void RequireResolutionContext(
        DeepIdV2PermanentContactResolution resolution,
        ReadOnlySpan<byte> networkId16, ParsedDid2 did2)
    {
        Span<byte> input = stackalloc byte[48];
        networkId16.CopyTo(input);
        did2.RecordHash.Span.CopyTo(input[16..]);
        var expected = ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V2/permanent-locator", input);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    resolution.LocatorHash.Span, expected))
                throw new CryptographicException(
                    "The resolver material belongs to another DID2 or network.");
        }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }
}
