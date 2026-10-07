using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

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
    public ReadOnlyMemory<byte> ExactXmg2 => Record.CanonicalBytes.ToArray();
    public ReadOnlyMemory<byte> OperationId => Record.Field(2);
    public ReadOnlyMemory<byte> LocatorHash => Record.Field(3);
    public ReadOnlyMemory<byte> HolderPublicKey => Record.Field(5);
    public MailboxCapabilityDomain Domain => (MailboxCapabilityDomain)Record.Field(6).Span[0];
}


public static class MailboxGrantRequestVerifier
{
    public static ContactRecord VerifyDeposit(
        ReadOnlySpan<byte> exactXmg2,
        ParsedContactRouteClosure route,
        ulong nowUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(route);
        return Verify(
            exactXmg2,
            route,
            route.Reachability.Field(10).Span,
            MailboxCapabilityDomain.Deposit,
            nowUnixSeconds);
    }

    public static ContactRecord VerifyRetrieve(
        ReadOnlySpan<byte> exactXmg2,
        ParsedContactRouteClosure route,
        ReadOnlySpan<byte> ownerRetrieveCapability,
        ulong nowUnixSeconds) => Verify(
            exactXmg2,
            route,
            ownerRetrieveCapability,
            MailboxCapabilityDomain.Retrieve,
            nowUnixSeconds);

    private static ContactRecord Verify(
        ReadOnlySpan<byte> exactXmg2,
        ParsedContactRouteClosure route,
        ReadOnlySpan<byte> expectedCapability,
        MailboxCapabilityDomain expectedDomain,
        ulong nowUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(route);
        if (expectedCapability.Length != 32 || expectedCapability.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The expected mailbox grant capability is invalid.", nameof(expectedCapability));
        var request = ContactCodec.Decode(ProtocolMagic.XMG2, exactXmg2);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        if (!Fixed(request.Field(1).Span, route.Reachability.Field(1).Span) ||
            !Fixed(request.Field(4).Span, expectedCapability) ||
            request.Field(6).Span[0] != (byte)expectedDomain ||
            !Fixed(request.Field(7).Span,
                ContactCodec.ArtifactReference(ProtocolMagic.PMT2, route.Projection).CanonicalBytes.Span) ||
            !Fixed(request.Field(8).Span, route.Selection.ArtifactHash.Span) ||
            !Fixed(request.Field(11).Span, route.ExactHash.Span) ||
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
        if (!StringComparer.Ordinal.Equals(request.Magic, ProtocolMagic.XMG2))
            throw new ArgumentException("The mailbox grant result requires an exact XMG2 request.", nameof(request));
        if (serverTimeUnixSeconds == 0 || expiresAtUnixSeconds <= serverTimeUnixSeconds ||
            expiresAtUnixSeconds - serverTimeUnixSeconds > 300)
            throw new ArgumentOutOfRangeException(nameof(expiresAtUnixSeconds));
        var result = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XMC2,
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
