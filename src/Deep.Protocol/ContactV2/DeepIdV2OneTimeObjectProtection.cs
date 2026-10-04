using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Parsed DID2-only invitation protection, not currentness or redemption authority.</summary>
internal static class DeepIdV2OneTimeObjectProtection
{
    internal static byte[] CreateInvitation(ParsedDcr1V2 closure)
    {
        RequireOneTimeBundle(closure);
        byte[][] fields = [closure.Bundle.Field(1).ToArray(), RandomNonzero(32), [2], [0, 1],
            RandomNonzero(16), RandomNonzero(32), SHA256.HashData(closure.Bundle.CanonicalBytes.Span),
            closure.Bundle.Field(18).ToArray(), [0, 1]];
        try { return ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.DIA1, fields.Select(x => (ReadOnlyMemory<byte>)x).ToArray()).CanonicalBytes.ToArray(); }
        finally { foreach (var field in fields) CryptographicOperations.ZeroMemory(field); }
    }

    internal static byte[] ComputeLocator(ReadOnlySpan<byte> invitation) =>
        ContactCodec.Sha256Domain("Deep/ContactResolver/V1/one-time-locator",
            ContactCodec.Decode(ProtocolMagic.DIA1, invitation).Field(5).Span);

    internal static byte[] Seal(ParsedDcr1V2 closure, ReadOnlySpan<byte> invitation)
    {
        var parsed = ContactCodec.Decode(ProtocolMagic.DIA1, invitation);
        RequireBinding(closure, parsed);
        var aad = RedactedAad(invitation);
        var key = parsed.Field(6).ToArray();
        var nonce = RandomNumberGenerator.GetBytes(24);
        var plaintext = closure.CanonicalBytes.ToArray();
        byte[]? encrypted = null;
        try
        {
            encrypted = SecretAeadXChaCha20Poly1305.Encrypt(plaintext, nonce, key, aad);
            if (encrypted.Length != plaintext.Length + 16)
                throw new CryptographicException("One-time object ciphertext length is invalid.");
            var result = new byte[encrypted.Length + 24];
            nonce.CopyTo(result, 0); encrypted.CopyTo(result, 24); return result;
        }
        finally
        {
            foreach (var value in new[] { aad, key, nonce, plaintext }) CryptographicOperations.ZeroMemory(value);
            if (encrypted is not null) CryptographicOperations.ZeroMemory(encrypted);
        }
    }

    internal static ParsedDcr1V2 Open(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> invitation)
    {
        if (ciphertext.Length < 40 + 62 + DeepIdV2ContactBundleCodec.MinimumLength + 1 ||
            ciphertext.Length > 40 + DeepIdV2ResolverClosureCodec.MaximumLength)
            throw new CryptographicException("Protected one-time object size is invalid.");
        var parsed = ContactCodec.Decode(ProtocolMagic.DIA1, invitation);
        var aad = RedactedAad(invitation); var key = parsed.Field(6).ToArray();
        var nonce = ciphertext[..24].ToArray(); var encrypted = ciphertext[24..].ToArray();
        byte[]? plaintext = null;
        try
        {
            try { plaintext = SecretAeadXChaCha20Poly1305.Decrypt(encrypted, nonce, key, aad); }
            catch (Exception error) when (error is CryptographicException or ArgumentException)
            { throw new CryptographicException("One-time object authentication failed.", error); }
            var closure = DeepIdV2ResolverClosureCodec.Decode(plaintext);
            RequireBinding(closure, parsed); return closure;
        }
        finally
        {
            foreach (var value in new[] { aad, key, nonce, encrypted }) CryptographicOperations.ZeroMemory(value);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    // Existing exact DIA1 TLV grammar: preserve every byte except tag 6's value.
    // This is AEAD AAD only, never a parseable invitation or witness authority.
    private static byte[] RedactedAad(ReadOnlySpan<byte> invitation)
    {
        var result = invitation.ToArray(); var offset = 12;
        for (var tag = 1; tag <= 9; tag++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(result.AsSpan(offset + 4, 4)));
            offset += 8;
            if (tag == 6) result.AsSpan(offset, length).Clear();
            offset += length;
        }
        return result;
    }

    private static void RequireBinding(ParsedDcr1V2 closure, ContactRecord invitation)
    {
        RequireOneTimeBundle(closure);
        if (!Fixed(invitation.Field(1).Span, closure.Bundle.Field(1).Span) ||
            !Fixed(invitation.Field(7).Span, SHA256.HashData(closure.Bundle.CanonicalBytes.Span)) ||
            !Fixed(invitation.Field(8).Span, closure.Bundle.Field(18).Span))
            throw new CryptographicException("One-time invitation differs from its exact network, bundle or expiry.");
    }

    private static void RequireOneTimeBundle(ParsedDcr1V2 closure)
    {
        ArgumentNullException.ThrowIfNull(closure);
        var bundle = closure.Bundle;
        var invite = DeepIdV2InviteRendezvousCodec.Decode(bundle.Field(14).Span[40..]);
        var issued = BinaryPrimitives.ReadUInt64BigEndian(bundle.Field(17).Span);
        var expiry = BinaryPrimitives.ReadUInt64BigEndian(bundle.Field(18).Span);
        if (invite.Field(9).Span[0] != 2 ||
            BinaryPrimitives.ReadUInt32BigEndian(invite.Field(10).Span) != 1 ||
            BinaryPrimitives.ReadUInt32BigEndian(bundle.Field(16).Span) != 10 ||
            BinaryPrimitives.ReadUInt64BigEndian(bundle.Field(8).Span) != 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(invite.Field(3).Span) != 0 ||
            expiry <= issued || expiry - issued > 2_592_000)
            throw new CryptographicException("A new bounded one-time DID2 object is required.");
    }

    private static byte[] RandomNonzero(int length)
    { var result = new byte[length]; do RandomNumberGenerator.Fill(result); while (result.AsSpan().IndexOfAnyExcept((byte)0) < 0); return result; }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
