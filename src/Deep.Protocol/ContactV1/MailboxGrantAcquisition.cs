using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.ContactV1;

public enum MailboxGrantAcquisitionResultCode : ushort
{
    Success = 1,
    UnknownOrExpired = 2,
    RateLimited = 3,
    Unavailable = 4,
    Conflict = 5,
}

/// <summary>
/// Narrow custody boundary for a random, reachability-scoped mailbox holder
/// key. It cannot expose account, device, recovery, or general signing APIs.
/// </summary>
public interface IReachabilityMailboxHolderSigner
{
    ReadOnlyMemory<byte> Ed25519PublicKey { get; }

    ValueTask<int> SignMailboxGrantRequestAsync(
        ReadOnlyMemory<byte> exactSigningInput,
        Memory<byte> signature64,
        CancellationToken cancellationToken);
}

public sealed class AuthoredMailboxGrantRequest
{
    internal AuthoredMailboxGrantRequest(ContactRecord record)
    {
        Record = record;
    }

    public ContactRecord Record { get; }
    public ReadOnlyMemory<byte> ExactXmg1 => Record.CanonicalBytes.ToArray();
    public ReadOnlyMemory<byte> OperationId => Record.Field(2);
    public ReadOnlyMemory<byte> LocatorHash => Record.Field(3);
    public ReadOnlyMemory<byte> HolderPublicKey => Record.Field(5);
    public MailboxCapabilityDomain Domain => (MailboxCapabilityDomain)Record.Field(6).Span[0];
}

/// <summary>
/// Authors exact XMG1 requests without a Session-derived identity. Deposit uses
/// the recipient-shared XRR1 capability; Retrieve uses only the owner capability
/// carried by the signed XPU1 publication and never exposed in the route bundle.
/// </summary>
public static class MailboxGrantRequestAuthor
{
    public static ValueTask<AuthoredMailboxGrantRequest> AuthorDepositAsync(
        VerifiedContactRouteClosure route,
        ReadOnlyMemory<byte> locatorHash,
        IReachabilityMailboxHolderSigner signer,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(route);
        return AuthorAsync(
            route,
            locatorHash,
            route.Reachability.Field(10),
            MailboxCapabilityDomain.Deposit,
            signer,
            issuedAtUnixSeconds,
            expiresAtUnixSeconds,
            cancellationToken);
    }

    public static ValueTask<AuthoredMailboxGrantRequest> AuthorRetrieveAsync(
        VerifiedContactRouteClosure ownedRoute,
        ReadOnlyMemory<byte> locatorHash,
        ReadOnlyMemory<byte> ownerRetrieveCapability,
        IReachabilityMailboxHolderSigner signer,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ownedRoute);
        return AuthorAsync(
            ownedRoute,
            locatorHash,
            ownerRetrieveCapability,
            MailboxCapabilityDomain.Retrieve,
            signer,
            issuedAtUnixSeconds,
            expiresAtUnixSeconds,
            cancellationToken);
    }

    private static async ValueTask<AuthoredMailboxGrantRequest> AuthorAsync(
        VerifiedContactRouteClosure route,
        ReadOnlyMemory<byte> locatorHash,
        ReadOnlyMemory<byte> capability,
        MailboxCapabilityDomain domain,
        IReachabilityMailboxHolderSigner signer,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(route);
        ArgumentNullException.ThrowIfNull(signer);
        cancellationToken.ThrowIfCancellationRequested();
        if (locatorHash.Length != 32 || locatorHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The resolver locator hash must be exactly 32 non-zero bytes.", nameof(locatorHash));
        if (capability.Length != 32 || capability.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The mailbox grant capability must be exactly 32 non-zero bytes.", nameof(capability));
        if (signer.Ed25519PublicKey.Length != 32 ||
            signer.Ed25519PublicKey.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The mailbox holder public key must be exactly 32 non-zero bytes.", nameof(signer));
        if (issuedAtUnixSeconds == 0 || expiresAtUnixSeconds <= issuedAtUnixSeconds ||
            expiresAtUnixSeconds - issuedAtUnixSeconds > 300)
            throw new ArgumentOutOfRangeException(nameof(expiresAtUnixSeconds));

        var operationId = RandomNonZero32();
        var nonce = RandomNonZero32();
        var signature = new byte[64];
        try
        {
            ReadOnlyMemory<byte>[] fields =
            [
                route.Reachability.Field(1),
                operationId,
                locatorHash.ToArray(),
                capability.ToArray(),
                signer.Ed25519PublicKey.ToArray(),
                new byte[] { (byte)domain },
                ContactCodec.ArtifactReference(ProtocolMagic.PMT2, route.Projection).CanonicalBytes,
                route.Selection.ArtifactHash,
                U64(issuedAtUnixSeconds),
                U64(expiresAtUnixSeconds),
                nonce,
                PlaceholderSignature(),
            ];
            var unsigned = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XMG1, fields);
            var written = await signer.SignMailboxGrantRequestAsync(
                unsigned.SignatureInput,
                signature,
                cancellationToken).ConfigureAwait(false);
            if (written != 64 || signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !PublicKeyAuth.VerifyDetached(
                    signature,
                    unsigned.SignatureInput.ToArray(),
                    signer.Ed25519PublicKey.ToArray()))
                throw new CryptographicException("The mailbox holder returned an invalid XMG1 proof of possession.");
            fields[11] = signature.ToArray();
            var exact = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XMG1, fields);
            ContactCodec.VerifyMailboxGrantHolderSignature(exact);
            return new AuthoredMailboxGrantRequest(exact);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(operationId);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static byte[] RandomNonZero32()
    {
        var result = new byte[32];
        do RandomNumberGenerator.Fill(result);
        while (result.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return result;
    }

    private static byte[] PlaceholderSignature()
    {
        var result = new byte[64];
        result[^1] = 1;
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }
}

public static class MailboxGrantRequestVerifier
{
    public static ContactRecord VerifyDeposit(
        ReadOnlySpan<byte> exactXmg1,
        ParsedContactRouteClosure route,
        ulong nowUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(route);
        return Verify(
            exactXmg1,
            route,
            route.Reachability.Field(10).Span,
            MailboxCapabilityDomain.Deposit,
            nowUnixSeconds);
    }

    public static ContactRecord VerifyRetrieve(
        ReadOnlySpan<byte> exactXmg1,
        ParsedContactRouteClosure route,
        ReadOnlySpan<byte> ownerRetrieveCapability,
        ulong nowUnixSeconds) => Verify(
            exactXmg1,
            route,
            ownerRetrieveCapability,
            MailboxCapabilityDomain.Retrieve,
            nowUnixSeconds);

    private static ContactRecord Verify(
        ReadOnlySpan<byte> exactXmg1,
        ParsedContactRouteClosure route,
        ReadOnlySpan<byte> expectedCapability,
        MailboxCapabilityDomain expectedDomain,
        ulong nowUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(route);
        if (expectedCapability.Length != 32 || expectedCapability.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The expected mailbox grant capability is invalid.", nameof(expectedCapability));
        var request = ContactCodec.Decode(ProtocolMagic.XMG1, exactXmg1);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        if (!Fixed(request.Field(1).Span, route.Reachability.Field(1).Span) ||
            !Fixed(request.Field(4).Span, expectedCapability) ||
            request.Field(6).Span[0] != (byte)expectedDomain ||
            !Fixed(request.Field(7).Span,
                ContactCodec.ArtifactReference(ProtocolMagic.PMT2, route.Projection).CanonicalBytes.Span) ||
            !Fixed(request.Field(8).Span, route.Selection.ArtifactHash.Span) ||
            nowUnixSeconds < U64(request.Field(9).Span) ||
            nowUnixSeconds >= U64(request.Field(10).Span))
            throw new ContactFormatException(ContactValidationStage.Closure, "MailboxGrantRequestRouteBindingMismatch");
        return request;
    }

    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public static class MailboxGrantResultAuthor
{
    public static ContactRecord AuthorSuccess(
        ContactRecord request,
        ReadOnlySpan<byte> exactRouteClosure,
        MailboxAuthenticatedGrant current,
        ulong serverTimeUnixSeconds,
        ulong expiresAtUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(current);
        var route = ContactRouteClosureCodec.Decode(exactRouteClosure);
        var result = Author(
            request,
            MailboxGrantAcquisitionResultCode.Success,
            serverTimeUnixSeconds,
            expiresAtUnixSeconds,
            SHA256.HashData(route.ExactBytes.Span),
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(current));
        ContactCodec.ValidateMailboxGrantResultBinding(request, result);
        ContactCodec.ValidateMailboxGrantResultRouteBinding(result, route);
        return result;
    }

    public static ContactRecord AuthorFailure(
        ContactRecord request,
        MailboxGrantAcquisitionResultCode code,
        ulong serverTimeUnixSeconds,
        ulong expiresAtUnixSeconds)
    {
        if (code == MailboxGrantAcquisitionResultCode.Success)
            throw new ArgumentOutOfRangeException(nameof(code));
        return Author(
            request,
            code,
            serverTimeUnixSeconds,
            expiresAtUnixSeconds,
            new byte[32],
            ReadOnlyMemory<byte>.Empty);
    }

    private static ContactRecord Author(
        ContactRecord request,
        MailboxGrantAcquisitionResultCode code,
        ulong serverTimeUnixSeconds,
        ulong expiresAtUnixSeconds,
        ReadOnlyMemory<byte> routeClosureHash,
        ReadOnlyMemory<byte> current)
    {
        if (!StringComparer.Ordinal.Equals(request.Magic, ProtocolMagic.XMG1))
            throw new ArgumentException("The mailbox grant result requires an exact XMG1 request.", nameof(request));
        if (serverTimeUnixSeconds == 0 || expiresAtUnixSeconds <= serverTimeUnixSeconds ||
            expiresAtUnixSeconds - serverTimeUnixSeconds > 300)
            throw new ArgumentOutOfRangeException(nameof(expiresAtUnixSeconds));
        var result = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XMC1,
        [
            request.Field(1),
            request.Field(2),
            U16((ushort)code),
            U64(serverTimeUnixSeconds),
            SHA256.HashData(request.CanonicalBytes.Span),
            U64(expiresAtUnixSeconds),
            routeClosureHash,
            current,
        ]);
        ContactCodec.ValidateMailboxGrantResultBinding(request, result);
        return result;
    }

    private static byte[] U16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }
}
