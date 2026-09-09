using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Sodium;

namespace Deep.Protocol.ContactV1;

internal delegate void Dcr1NonceEntropy(Span<byte> destination24);

/// <summary>
/// Exact CONTACT-CODEC object protection for resolver-stored DCR1 bytes. This
/// is cryptographic framing only and grants no resolver/network authority.
/// </summary>
public static class Dcr1ObjectProtectionCodec
{
    private const int NonceBytes = 24;
    private const int TagBytes = 16;
    private const int KeyBytes = 32;
    private const int MaximumDcr1Bytes = 65_535;
    private const int MaximumProtectedBytes = NonceBytes + MaximumDcr1Bytes + TagBytes;

    public static byte[] SealPermanent(
        ContactRecord exactDcr1,
        ReadOnlySpan<byte> networkId16,
        ParsedDid1 exactPermanentDeepId,
        PermanentContactResolution resolution)
    {
        return SealPermanentCore(
            exactDcr1, networkId16, exactPermanentDeepId, resolution,
            static destination => RandomNumberGenerator.Fill(destination));
    }

    public static ContactRecord OpenPermanent(
        ReadOnlySpan<byte> nonceAndCiphertext,
        ReadOnlySpan<byte> networkId16,
        ParsedDid1 exactPermanentDeepId,
        PermanentContactResolution resolution)
    {
        ArgumentNullException.ThrowIfNull(exactPermanentDeepId);
        ArgumentNullException.ThrowIfNull(resolution);
        ValidateNetwork(networkId16);
        var aad = PermanentAad(networkId16, exactPermanentDeepId);
        var protectedOwned = nonceAndCiphertext.ToArray();
        var networkOwned = networkId16.ToArray();
        try
        {
            return resolution.UseResolverKey(key => OpenCore(protectedOwned, key, aad, networkOwned));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
            CryptographicOperations.ZeroMemory(protectedOwned);
            CryptographicOperations.ZeroMemory(networkOwned);
        }
    }

    public static byte[] SealOneTime(ContactRecord exactDcr1, ContactRecord exactDia1)
    {
        return SealOneTimeCore(
            exactDcr1, exactDia1,
            static destination => RandomNumberGenerator.Fill(destination));
    }

    public static ContactRecord OpenOneTime(
        ReadOnlySpan<byte> nonceAndCiphertext,
        ContactRecord exactDia1)
    {
        ValidateDia1(exactDia1);
        var key = exactDia1.Field(6).ToArray();
        var aad = OneTimeAad(exactDia1);
        try
        {
            return OpenCore(nonceAndCiphertext, key, aad, exactDia1.FieldSpan(1));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    internal static byte[] SealPermanentCore(
        ContactRecord exactDcr1,
        ReadOnlySpan<byte> networkId16,
        ParsedDid1 exactPermanentDeepId,
        PermanentContactResolution resolution,
        Dcr1NonceEntropy entropy)
    {
        ArgumentNullException.ThrowIfNull(exactPermanentDeepId);
        ArgumentNullException.ThrowIfNull(resolution);
        ArgumentNullException.ThrowIfNull(entropy);
        ValidateDcr1Network(exactDcr1, networkId16);
        var aad = PermanentAad(networkId16, exactPermanentDeepId);
        try
        {
            return resolution.UseResolverKey(key => SealCore(exactDcr1, key, aad, entropy));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    internal static byte[] SealOneTimeCore(
        ContactRecord exactDcr1,
        ContactRecord exactDia1,
        Dcr1NonceEntropy entropy)
    {
        ArgumentNullException.ThrowIfNull(entropy);
        ValidateDia1(exactDia1);
        ValidateDcr1Network(exactDcr1, exactDia1.FieldSpan(1));
        var key = exactDia1.Field(6).ToArray();
        var aad = OneTimeAad(exactDia1);
        try
        {
            return SealCore(exactDcr1, key, aad, entropy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static byte[] SealCore(
        ContactRecord exactDcr1,
        ReadOnlySpan<byte> sourceKey32,
        ReadOnlySpan<byte> aad,
        Dcr1NonceEntropy entropy)
    {
        var plaintext = exactDcr1.CanonicalBytes.ToArray();
        var key = sourceKey32.ToArray();
        var nonce = new byte[NonceBytes];
        byte[]? ciphertext = null;
        try
        {
            if (key.Length != KeyBytes || ServiceWire.IsZero(key))
                throw new CryptographicException("The DCR1 object key is invalid.");
            entropy(nonce);
            ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(
                plaintext, nonce, key, aad.ToArray());
            if (ciphertext.Length != plaintext.Length + TagBytes)
                throw new CryptographicException("XChaCha20-Poly1305 returned an unexpected length.");
            var result = new byte[checked(NonceBytes + ciphertext.Length)];
            nonce.CopyTo(result, 0);
            ciphertext.CopyTo(result, NonceBytes);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
            if (ciphertext is not null)
                CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private static ContactRecord OpenCore(
        ReadOnlySpan<byte> protectedBytes,
        ReadOnlySpan<byte> sourceKey32,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> expectedNetworkId16)
    {
        if (protectedBytes.Length is < NonceBytes + TagBytes + 1 or > MaximumProtectedBytes)
            throw new ContactFormatException(ContactValidationStage.Length, "ProtectedDcr1LengthOutOfRange");
        var nonce = protectedBytes[..NonceBytes].ToArray();
        var ciphertext = protectedBytes[NonceBytes..].ToArray();
        var key = sourceKey32.ToArray();
        byte[]? plaintext = null;
        try
        {
            if (key.Length != KeyBytes || ServiceWire.IsZero(key))
                throw new CryptographicException("The DCR1 object key is invalid.");
            try
            {
                plaintext = SecretAeadXChaCha20Poly1305.Decrypt(
                    ciphertext, nonce, key, aad.ToArray());
            }
            catch (Exception exception) when (exception is CryptographicException or ArgumentException)
            {
                _ = exception;
                throw new ContactFormatException(
                    ContactValidationStage.Signature, "Dcr1ObjectAuthenticationFailed");
            }
            var record = ContactCodec.Decode(ProtocolMagic.DCR1, plaintext);
            ValidateDcr1Network(record, expectedNetworkId16);
            return record;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(key);
            if (plaintext is not null)
                CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static byte[] PermanentAad(ReadOnlySpan<byte> networkId16, ParsedDid1 did1)
    {
        ValidateNetwork(networkId16);
        var exactDid1 = did1.CanonicalBytes.ToArray();
        var aad = new byte[checked(16 + exactDid1.Length)];
        networkId16.CopyTo(aad);
        exactDid1.CopyTo(aad, 16);
        CryptographicOperations.ZeroMemory(exactDid1);
        return aad;
    }

    private static byte[] OneTimeAad(ContactRecord dia1)
    {
        var aad = dia1.CanonicalBytes.ToArray();
        var offset = FindFieldOffset(aad, 6, KeyBytes);
        CryptographicOperations.ZeroMemory(aad.AsSpan(offset, KeyBytes));
        return aad;
    }

    private static int FindFieldOffset(ReadOnlySpan<byte> record, ushort wantedTag, int exactLength)
    {
        var count = BinaryPrimitives.ReadUInt16BigEndian(record[8..10]);
        var offset = 12;
        for (var index = 0; index < count; index++)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(offset, 2));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(record.Slice(offset + 4, 4)));
            offset += 8;
            if (tag == wantedTag)
            {
                if (length != exactLength)
                    throw new ContactFormatException(ContactValidationStage.Bounds, "InvalidDia1KeyLength");
                return offset;
            }
            offset += length;
        }
        throw new ContactFormatException(ContactValidationStage.FieldScan, "MissingDia1Key");
    }

    private static void ValidateDia1(ContactRecord dia1)
    {
        ArgumentNullException.ThrowIfNull(dia1);
        if (!StringComparer.Ordinal.Equals(dia1.Magic, ProtocolMagic.DIA1))
            throw new ContactFormatException(ContactValidationStage.Header, "WrongInvitationType");
    }

    private static void ValidateDcr1Network(ContactRecord dcr1, ReadOnlySpan<byte> networkId16)
    {
        ArgumentNullException.ThrowIfNull(dcr1);
        ValidateNetwork(networkId16);
        if (!StringComparer.Ordinal.Equals(dcr1.Magic, ProtocolMagic.DCR1))
            throw new ContactFormatException(ContactValidationStage.Header, "WrongResolverObjectType");
        if (!dcr1.FieldSpan(1).SequenceEqual(networkId16))
            throw new ContactFormatException(ContactValidationStage.Closure, "Dcr1NetworkMismatch");
    }

    private static void ValidateNetwork(ReadOnlySpan<byte> networkId16)
    {
        if (networkId16.Length != 16 || ServiceWire.IsZero(networkId16))
            throw new ArgumentException("Network ID must be exactly 16 nonzero bytes.", nameof(networkId16));
    }
}
