using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>
/// Root-authorized clean-break PMA2 capability. It authorizes only the two
/// role-separated MCG3 issuer keys and the mailbox-directory policy; it carries
/// no endpoint, release certificate, account, device, holder, or route.
/// </summary>
public sealed class VerifiedMailboxAuthorityV2
{
    private readonly ContactRecord record;
    private readonly byte[] depositIssuerPublicKey;
    private readonly byte[] retrieveIssuerPublicKey;

    internal VerifiedMailboxAuthorityV2(ContactRecord record)
    {
        this.record = record;
        depositIssuerPublicKey = record.Field(5).ToArray();
        retrieveIssuerPublicKey = record.Field(6).ToArray();
        Generation = BinaryPrimitives.ReadUInt64BigEndian(record.Field(2).Span);
        MinimumGrantGeneration = BinaryPrimitives.ReadUInt64BigEndian(record.Field(7).Span);
        MaximumGrantLifetimeSeconds = BinaryPrimitives.ReadUInt32BigEndian(record.Field(8).Span);
        NotBeforeUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(record.Field(11).Span);
        ExpiresAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(record.Field(12).Span);
    }

    public ReadOnlyMemory<byte> NetworkId => record.Field(1).ToArray();
    public ulong Generation { get; }
    public ulong MinimumGrantGeneration { get; }
    public uint MaximumGrantLifetimeSeconds { get; }
    public ulong NotBeforeUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> ExactPma2 => record.CanonicalBytes.ToArray();
    public ReadOnlyMemory<byte> CoreHash => record.CoreHash.ToArray();

    /// <summary>
    /// Proves that an exact PMT2 names this root-authorized PMA2 and the same
    /// network. Decoding alone is never treated as authority.
    /// </summary>
    public bool BindsProjection(ReadOnlySpan<byte> exactPmt2)
    {
        try
        {
            var projection = ContactCodec.Decode(ProtocolMagic.PMT2, exactPmt2);
            var expected = XPointNetworkCodec.EncodeCoreReference(
                ProtocolMagic.PMA2, record.CoreHash.Span);
            return Fixed(projection.Field(1).Span, record.Field(1).Span) &&
                Fixed(projection.Field(4).Span, expected);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return false;
        }
    }

    public MailboxCapabilityIssuerAuthority ResolveIssuer(
        MailboxCapabilityDomain domain) => new()
    {
        PublicKey = domain switch
        {
            MailboxCapabilityDomain.Deposit => depositIssuerPublicKey.ToArray(),
            MailboxCapabilityDomain.Retrieve => retrieveIssuerPublicKey.ToArray(),
            _ => throw new ArgumentOutOfRangeException(nameof(domain)),
        },
        Domain = domain,
        AllowedLifecycle = MailboxCapabilityLifecycle.Active,
        MinimumGeneration = MinimumGrantGeneration,
        MaximumGeneration = ulong.MaxValue,
        ValidFromUnixSeconds = NotBeforeUnixSeconds,
        ValidUntilUnixSeconds = ExpiresAtUnixSeconds,
    };

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public static class MailboxAuthorityV2Verifier
{
    public static VerifiedMailboxAuthorityV2 Verify(
        VerifiedXPointNetworkAuthority networkAuthority,
        ReadOnlySpan<byte> exactPma2,
        ulong trustedLowerUnixSeconds,
        ulong trustedUpperUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(networkAuthority);
        if (trustedLowerUnixSeconds > trustedUpperUnixSeconds)
            throw new CryptographicException("The PMA2 trusted-time interval is invalid.");
        var record = ContactCodec.Decode(ProtocolMagic.PMA2, exactPma2);
        if (BinaryPrimitives.ReadUInt16BigEndian(record.Field(9).Span) != 2)
            throw new CryptographicException("PMA2 does not authorize the current selection-bound mailbox algorithm.");
        VerifyRecord(networkAuthority, record, trustedLowerUnixSeconds, trustedUpperUnixSeconds);
        return new VerifiedMailboxAuthorityV2(record);
    }

    // Only predecessor authentication for the root-signed successor author.
    // This deliberately returns no current issuer, host, holder or dispatch authority.
    internal static void VerifyHistoricalLineage(VerifiedXPointNetworkAuthority networkAuthority,
        ReadOnlySpan<byte> exactPma2, ulong trustedLowerUnixSeconds, ulong trustedUpperUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(networkAuthority);
        var record = ContactCodec.Decode(ProtocolMagic.PMA2, exactPma2);
        var ancestor = XPointOnionCapabilityProducer.RequireHistoricalAuthority(networkAuthority, record.FieldSpan(13));
        VerifyBindings(record, ancestor.NetworkId.Span,
            XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNA1, ancestor.CoreHash.Span),
            ancestor.DirectoryWitnessPolicyHash.Span, ancestor.NotBefore, ancestor.ExpiresAt,
            trustedLowerUnixSeconds, trustedUpperUnixSeconds);
        VerifyRootThreshold(record, ancestor.RootThreshold, ancestor.RootKeys.Select(static key =>
            new XPointNetworkRootKey(key.Id.Span, key.Generation, key.PublicKey.Span)).ToArray());
    }

    private static void VerifyRecord(VerifiedXPointNetworkAuthority networkAuthority,
        ContactRecord record, ulong trustedLowerUnixSeconds, ulong trustedUpperUnixSeconds)
    {
        VerifyBindings(record, networkAuthority.NetworkId.Span, networkAuthority.AuthorityCoreReference.Span,
            networkAuthority.DirectoryWitnessPolicyHash.Span, networkAuthority.NotBefore, networkAuthority.ExpiresAt,
            trustedLowerUnixSeconds, trustedUpperUnixSeconds);
        VerifyRootThreshold(record, networkAuthority.RootThreshold, networkAuthority.RootKeys);
    }

    private static void VerifyBindings(ContactRecord record, ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> authorityReference, ReadOnlySpan<byte> witnessPolicyHash, ulong notBefore, ulong expiresAt,
        ulong trustedLowerUnixSeconds, ulong trustedUpperUnixSeconds)
    {
        if (trustedLowerUnixSeconds > trustedUpperUnixSeconds)
            throw new CryptographicException("The PMA2 trusted-time interval is invalid.");
        if (!Fixed(record.Field(1).Span, networkId) ||
            !Fixed(record.Field(13).Span, authorityReference) ||
            !Fixed(record.Field(14).Span, witnessPolicyHash) ||
            BinaryPrimitives.ReadUInt64BigEndian(record.Field(11).Span) > trustedLowerUnixSeconds ||
            trustedUpperUnixSeconds >= BinaryPrimitives.ReadUInt64BigEndian(record.Field(12).Span) ||
            BinaryPrimitives.ReadUInt64BigEndian(record.Field(11).Span) < notBefore ||
            BinaryPrimitives.ReadUInt64BigEndian(record.Field(12).Span) > expiresAt)
            throw new CryptographicException(
                "PMA2 is outside its exact XNA1 authority and authenticated interval.");
    }

    private static void VerifyRootThreshold(
        ContactRecord record,
        byte threshold, IReadOnlyList<XPointNetworkRootKey> rootKeys)
    {
        var rows = record.Field(16).Span;
        var count = record.Field(15).Span[0];
        if (rows.Length != count * 96 || count < threshold)
            throw new CryptographicException("PMA2 does not meet the XNA1 root threshold.");
        var keys = rootKeys.ToDictionary(
            static key => Convert.ToHexString(key.Id.Span),
            StringComparer.Ordinal);
        var valid = 0;
        for (var index = 0; index < count; index++)
        {
            var row = rows.Slice(index * 96, 96);
            if (!keys.TryGetValue(Convert.ToHexString(row[..32]), out var key) ||
                !VerifyEd25519(key.Ed25519PublicKey.Span,
                    record.SignatureInput.Span, row[32..]))
                throw new CryptographicException("PMA2 contains an unknown or invalid root receipt.");
            valid++;
        }
        if (valid < threshold)
            throw new CryptographicException("PMA2 does not meet the XNA1 root threshold.");
    }

    private static bool VerifyEd25519(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        try
        {
            return PublicKeyAuth.VerifyDetached(
                signature.ToArray(), message.ToArray(), key.ToArray());
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return false;
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
