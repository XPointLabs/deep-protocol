using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.ContactV1;

public sealed class ContactRouteAdvertisementAuthoringRequest
{
    private readonly byte[] antiSpamPolicyHash;
    private readonly byte[] metadataSealingKeyId;
    private readonly byte[] metadataSealingPublicKey;

    public ContactRouteAdvertisementAuthoringRequest(
        VerifiedContactRouteProposalAuthority authority,
        uint maximumAcceptedHellos,
        ReadOnlySpan<byte> antiSpamPolicyHash,
        ReadOnlySpan<byte> metadataSealingKeyId,
        ReadOnlySpan<byte> metadataSealingX25519PublicKey,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds)
    {
        Authority = authority ?? throw new ArgumentNullException(nameof(authority));
        if (maximumAcceptedHellos is < 1 or > 65_535)
            throw new ArgumentOutOfRangeException(nameof(maximumAcceptedHellos));
        this.antiSpamPolicyHash = Required32(antiSpamPolicyHash, nameof(antiSpamPolicyHash));
        this.metadataSealingKeyId = Required32(metadataSealingKeyId, nameof(metadataSealingKeyId));
        this.metadataSealingPublicKey = Required32(
            metadataSealingX25519PublicKey, nameof(metadataSealingX25519PublicKey));
        if (issuedAtUnixSeconds == 0 || issuedAtUnixSeconds >= expiresAtUnixSeconds ||
            expiresAtUnixSeconds - issuedAtUnixSeconds > 2_592_000 ||
            issuedAtUnixSeconds > authority.TrustedLowerUnixSeconds ||
            expiresAtUnixSeconds <= authority.TrustedUpperUnixSeconds ||
            issuedAtUnixSeconds < authority.NotBeforeUnixSeconds ||
            expiresAtUnixSeconds > authority.ExpiresAtUnixSeconds)
            throw new ArgumentOutOfRangeException(nameof(expiresAtUnixSeconds));
        MaximumAcceptedHellos = maximumAcceptedHellos;
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }

    public VerifiedContactRouteProposalAuthority Authority { get; }
    public uint MaximumAcceptedHellos { get; }
    public ReadOnlyMemory<byte> AntiSpamPolicyHash => antiSpamPolicyHash.ToArray();
    public ReadOnlyMemory<byte> MetadataSealingKeyId => metadataSealingKeyId.ToArray();
    public ReadOnlyMemory<byte> MetadataSealingX25519PublicKey =>
        metadataSealingPublicKey.ToArray();
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }

    private static byte[] Required32(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly 32 non-zero bytes.", name);
        return value.ToArray();
    }
}

public sealed class AuthoredContactRouteAdvertisement
{
    private readonly byte[] exactXra1;
    private readonly byte[] placementInput;

    internal AuthoredContactRouteAdvertisement(
        ContactRecord record,
        ReadOnlySpan<byte> placementInput)
    {
        Record = record;
        exactXra1 = record.CanonicalBytes.ToArray();
        this.placementInput = placementInput.ToArray();
    }

    public ContactRecord Record { get; }
    public ReadOnlyMemory<byte> ExactXra1 => exactXra1.ToArray();
    public ReadOnlyMemory<byte> PlacementInput => placementInput.ToArray();
}

/// <summary>
/// Rehydrates the device-authored XRA1 capability at a remote threshold-authority
/// boundary. Raw XRA1 bytes become usable only after they match the exact current
/// proposal capability and their device signature verifies.
/// </summary>
public static class ContactRouteAdvertisementVerifier
{
    public static AuthoredContactRouteAdvertisement VerifyExact(
        VerifiedContactRouteProposalAuthority authority,
        ReadOnlyMemory<byte> exactXra1)
    {
        ArgumentNullException.ThrowIfNull(authority);
        if (exactXra1.Length != 550)
            throw new ContactPublicationAuthoringException(
                "InvalidRouteAdvertisementSize",
                "The exact XRA1 proposal must be exactly 550 bytes.");
        try
        {
            var record = ContactCodec.Decode(ProtocolMagic.XRA1, exactXra1.Span);
            Validate(authority, record);
            return new AuthoredContactRouteAdvertisement(record, record.Field(6).Span);
        }
        catch (ContactPublicationAuthoringException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or
            CryptographicException or OverflowException)
        {
            throw new ContactPublicationAuthoringException(
                "InvalidRouteAdvertisementInput",
                "The exact XRA1 proposal is malformed or unauthorized.", exception);
        }
    }

    internal static void Validate(
        VerifiedContactRouteProposalAuthority authority,
        ContactRecord record)
    {
        if (!StringComparer.Ordinal.Equals(record.Magic, ProtocolMagic.XRA1) ||
            !Fixed(record.Field(1).Span, authority.NetworkId.Span) ||
            !Fixed(record.Field(5).Span, authority.Pmt2ArtifactReference.Span) ||
            !Fixed(record.Field(14).Span, authority.RecipientDeviceId.Span) ||
            !Fixed(record.Field(15).Span, authority.RecipientDpd1Reference.Span) ||
            BinaryPrimitives.ReadUInt64BigEndian(record.Field(12).Span) >
                authority.TrustedLowerUnixSeconds ||
            BinaryPrimitives.ReadUInt64BigEndian(record.Field(13).Span) <=
                authority.TrustedUpperUnixSeconds)
            throw new ContactPublicationAuthoringException(
                "RouteAdvertisementMismatch",
                "The XRA1 proposal does not bind the exact current proposal authority.");
        ContactCodec.VerifyDeviceSignature(record, authority.RecipientDevicePublicKey.Span);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// Authors only the device-owned XRA1 proposal. Selection, replica and live
/// route authority remain absent until the directory threshold returns PMS2,
/// XRC1 and XSS1 for these exact bytes.
/// </summary>
public static class ContactRouteAdvertisementAuthor
{
    public static async ValueTask<AuthoredContactRouteAdvertisement> AuthorGenesisAsync(
        ContactRouteAdvertisementAuthoringRequest request,
        IContactDeviceCustodySigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(signer);
        cancellationToken.ThrowIfCancellationRequested();
        var authority = request.Authority;
        if (!Fixed(signer.DeviceId.Span, authority.RecipientDeviceId.Span) ||
            !Fixed(signer.Ed25519PublicKey.Span, authority.RecipientDevicePublicKey.Span) ||
            signer.CustodyDomainHash.Length != 32 ||
            signer.CustodyDomainHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ContactPublicationAuthoringException(
                "CustodySignerMismatch",
                "The XRA1 custody signer does not bind the verified recipient device.");

        var authorizationId = RandomNonZero32();
        var placementInput = RandomNonZero32();
        try
        {
            var fields = new ReadOnlyMemory<byte>[]
            {
                authority.NetworkId,
                authorizationId,
                U64(0),
                new byte[32],
                authority.Pmt2ArtifactReference,
                placementInput,
                U16(1),
                U32(request.MaximumAcceptedHellos),
                request.AntiSpamPolicyHash,
                request.MetadataSealingKeyId,
                request.MetadataSealingX25519PublicKey,
                U64(request.IssuedAtUnixSeconds),
                U64(request.ExpiresAtUnixSeconds),
                authority.RecipientDeviceId,
                authority.RecipientDpd1Reference,
                PlaceholderSignature(),
            };
            var provisional = ContactCodec.AuthorForOperationalAuthority(
                ProtocolMagic.XRA1, fields);
            var signingRequest = new ContactDeviceSigningRequest(
                ContactDeviceSignaturePurpose.RouteAdvertisement,
                authority.NetworkId.Span,
                authority.RecipientAccountIdSpan,
                authority.RecipientDeviceId.Span,
                signer.CustodyDomainHash.Span,
                provisional.SignatureInput.Span);
            var signature = new byte[64];
            try
            {
                var written = await signer.SignAsync(
                    signingRequest, signature, cancellationToken).ConfigureAwait(false);
                if (written != signature.Length ||
                    signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                    !PublicKeyAuth.VerifyDetached(
                        signature, provisional.SignatureInput.ToArray(),
                        authority.RecipientDevicePublicKey.ToArray()))
                    throw new ContactPublicationAuthoringException(
                        "InvalidCustodySignature",
                        "The XRA1 custody signer returned an invalid signature.");
                fields[15] = signature.ToArray();
                var exact = ContactCodec.AuthorForOperationalAuthority(
                    ProtocolMagic.XRA1, fields);
                return new AuthoredContactRouteAdvertisement(exact, placementInput);
            }
            finally
            {
                signingRequest.Clear();
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ContactPublicationAuthoringException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or
            CryptographicException or OverflowException)
        {
            throw new ContactPublicationAuthoringException(
                "InvalidRouteAdvertisementInput",
                "The exact XRA1 authoring inputs are invalid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authorizationId);
            CryptographicOperations.ZeroMemory(placementInput);
        }
    }

    private static byte[] RandomNonZero32()
    {
        var value = new byte[32];
        do RandomNumberGenerator.Fill(value);
        while (value.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return value;
    }

    private static byte[] PlaceholderSignature()
    {
        var value = new byte[64];
        value[^1] = 1;
        return value;
    }

    private static byte[] U16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    private static byte[] U32(uint value)
    {
        var result = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
