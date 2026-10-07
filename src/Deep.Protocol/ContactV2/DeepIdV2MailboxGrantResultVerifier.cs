using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Exact issuer-authenticated DID2 grant evidence. Not protected holder
/// custody, installation, dispatch, delivery or ACK authority.</summary>
public sealed class VerifiedDeepIdV2MailboxGrant
{
    private readonly VerifiedDeepIdV2ContactRouteClosure route;
    private readonly ContactRecord pma;
    private readonly ContactRecord request;
    private readonly ContactRecord response;
    private readonly DeepIdV2ContactRouteTimeWindow verifiedAt;

    internal VerifiedDeepIdV2MailboxGrant(VerifiedDeepIdV2ContactRouteClosure route,
        ContactRecord pma, ContactRecord request, ContactRecord response,
        DeepIdV2ContactRouteTimeWindow verifiedAt)
    { this.route = route; this.pma = pma; this.request = request; this.response = response; this.verifiedAt = verifiedAt; }

    public ReadOnlyMemory<byte> ExactXmg2 => request.CanonicalBytes.ToArray();
    public ReadOnlyMemory<byte> ExactXmc2 => response.CanonicalBytes.ToArray();
    public ReadOnlyMemory<byte> ExactGrant => response.Field(8).ToArray();
    public ReadOnlyMemory<byte> ExactPma2 => pma.CanonicalBytes.ToArray();
    public ReadOnlyMemory<byte> MembershipCommitment => route.Route.Projection.ArtifactHash.ToArray();
    public MailboxCapabilityDomain Domain => (MailboxCapabilityDomain)request.Field(6).Span[0];

    /// <summary>Rechecks exact retained evidence; never refreshes expired issuer,
    /// topology or recipient proof, nor adopts a new grant/route.</summary>
    public async ValueTask EnsureCurrentAsync(CancellationToken cancellationToken = default)
    {
        var current = await route.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
        DeepIdV2MailboxGrantResultVerifier.RequireContinuous(verifiedAt, current);
        DeepIdV2MailboxGrantResultVerifier.RequireGrant(route, pma, response, current);
        cancellationToken.ThrowIfCancellationRequested();
    }
}

/// <summary>Direct DID2 result verification under independent current route,
/// root-signed issuer policy and exact NETCODEC mailbox projection.</summary>
public static class DeepIdV2MailboxGrantResultVerifier
{
    /// <summary>Independently verifies a retained winner under current DID2
    /// authority. Historical envelope expiry is not current grant expiry;
    /// this does not restore holder custody or authorize dispatch.</summary>
    public static async ValueTask<VerifiedDeepIdV2MailboxGrant> VerifyRetainedSuccessAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ReadOnlyMemory<byte> exactXmg2,
        ReadOnlyMemory<byte> exactXmc2, ReadOnlyMemory<byte> exactPma2,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(route); cancellationToken.ThrowIfCancellationRequested();
        if (exactXmg2.Length != 435 || exactXmc2.Length != 510 || exactPma2.Length is < 12 or > 65_535)
            throw new CryptographicException("Retained mailbox success requires bounded exact records.");
        var request = ContactCodec.Decode(ProtocolMagic.XMG2, exactXmg2.Span);
        var response = ContactCodec.Decode(ProtocolMagic.XMC2, exactXmc2.Span);
        var pma = ContactCodec.Decode(ProtocolMagic.PMA2, exactPma2.Span);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        ContactCodec.ValidateMailboxGrantResultBinding(request, response);
        RequireRequestScope(route, request);
        RequireHistoricalEnvelope(request, response);
        var first = await route.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
        if (U64(response.Field(4).Span) > first.UpperUnixSeconds)
            throw new CryptographicException("Retained mailbox response is future-dated.");
        RequireGrant(route, pma, response, first);
        var final = await route.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
        RequireContinuous(first, final); RequireGrant(route, pma, response, final);
        if (U64(response.Field(4).Span) > final.UpperUnixSeconds)
            throw new CryptographicException("Retained mailbox response is future-dated.");
        cancellationToken.ThrowIfCancellationRequested(); return new(route, pma, request, response, final);
    }

    public static async ValueTask<VerifiedDeepIdV2MailboxGrant> VerifySuccessAsync(
        VerifiedDeepIdV2ContactRouteClosure route, AuthoredMailboxGrantRequest authoredRequest,
        ReadOnlyMemory<byte> exactXmc2, ReadOnlyMemory<byte> exactPma2,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(authoredRequest);
        cancellationToken.ThrowIfCancellationRequested();
        if (exactXmc2.Length != 510 || exactPma2.Length is < 12 or > 65_535)
            throw new CryptographicException("Mailbox acquisition requires bounded exact success and issuer records.");
        // Canonical decoders own every input before the first asynchronous clock read.
        var request = ContactCodec.Decode(ProtocolMagic.XMG2, authoredRequest.ExactXmg2.Span);
        var response = ContactCodec.Decode(ProtocolMagic.XMC2, exactXmc2.Span);
        var pma = ContactCodec.Decode(ProtocolMagic.PMA2, exactPma2.Span);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        ContactCodec.ValidateMailboxGrantResultBinding(request, response);
        ContactCodec.ValidateMailboxGrantResultRouteBinding(response, route.Route);
        var first = await route.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
        RequireAcquisition(route, request, response, first);
        RequireGrant(route, pma, response, first);
        var final = await route.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
        RequireContinuous(first, final);
        RequireAcquisition(route, request, response, final);
        RequireGrant(route, pma, response, final);
        cancellationToken.ThrowIfCancellationRequested();
        return new(route, pma, request, response, final);
    }

    private static void RequireAcquisition(VerifiedDeepIdV2ContactRouteClosure route,
        ContactRecord request, ContactRecord response, DeepIdV2ContactRouteTimeWindow current)
    {
        RequireRequestScope(route, request);
        RequireHistoricalEnvelope(request, response);
        var start = U64(request.Field(9).Span); var expiry = U64(request.Field(10).Span);
        var serverTime = U64(response.Field(4).Span);
        Covers(current, start, expiry);
        // A server timestamp is a paired-envelope bound, never independent trusted time.
        if (serverTime > current.UpperUnixSeconds || current.UpperUnixSeconds >= U64(response.Field(6).Span))
            throw new CryptographicException("Mailbox acquisition response is future-dated or expired.");
    }

    internal static void RequireRequestScope(VerifiedDeepIdV2ContactRouteClosure route, ContactRecord request)
    {
        var records = route.Route;
        var domain = (MailboxCapabilityDomain)request.Field(6).Span[0];
        var depositCapability = records.Reachability.Field(10);
        if (!Fixed(request.Field(1).Span, route.Network.NetworkId.Span) ||
            !Fixed(request.Field(7).Span, ContactCodec.ArtifactReference(ProtocolMagic.PMT2, records.Projection).CanonicalBytes.Span) ||
            !Fixed(request.Field(8).Span, records.Selection.ArtifactHash.Span) ||
            !Fixed(request.Field(11).Span, records.ExactHash.Span) ||
            (domain == MailboxCapabilityDomain.Deposit && !Fixed(request.Field(4).Span, depositCapability.Span)) ||
            (domain == MailboxCapabilityDomain.Retrieve && Fixed(request.Field(4).Span, depositCapability.Span)))
            throw new CryptographicException("Mailbox acquisition differs from the exact current route and role.");
        var start = U64(request.Field(9).Span); var expiry = U64(request.Field(10).Span);
        var maximumExpiry = new[] { route.Network.MaximumRecordExpiryUnixSeconds,
            U64(records.Reachability.Field(17).Span), U64(records.Authorization.Field(13).Span),
            U64(records.Route.Field(18).Span), U64(records.Successor.Field(11).Span),
            U64(records.Projection.Field(12).Span), U64(records.Selection.Field(9).Span) }.Min();
        if (expiry <= start || expiry - start > 120 || expiry > maximumExpiry)
            throw new CryptographicException("Retained mailbox request exceeds its original acquisition/route bounds.");
    }

    private static void RequireHistoricalEnvelope(ContactRecord request, ContactRecord response)
    {
        var start = U64(request.Field(9).Span); var expiry = U64(request.Field(10).Span);
        var serverTime = U64(response.Field(4).Span);
        if (serverTime < start || serverTime >= expiry)
            throw new CryptographicException("Mailbox response time is outside its request envelope.");
    }

    internal static void RequireGrant(VerifiedDeepIdV2ContactRouteClosure route,
        ContactRecord pma, ContactRecord response, DeepIdV2ContactRouteTimeWindow current)
    {
        var policy = MailboxAuthorityV2Verifier.Verify(route.NetworkAuthority, pma.CanonicalBytes.Span,
            current.LowerUnixSeconds, current.UpperUnixSeconds);
        var records = route.Route;
        if (!policy.BindsProjection(records.Projection.CanonicalBytes.Span))
            throw new CryptographicException("Mailbox issuer is not bound by the exact current PMT2.");
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(response.Field(8).Span);
        var issuer = policy.ResolveIssuer(grant.Domain);
        var maximumExpiry = new[] { route.Network.MaximumRecordExpiryUnixSeconds, policy.ExpiresAtUnixSeconds,
            U64(records.Reachability.Field(17).Span), U64(records.Authorization.Field(13).Span),
            U64(records.Route.Field(18).Span), U64(records.Successor.Field(11).Span),
            U64(records.Projection.Field(12).Span), U64(records.Selection.Field(9).Span) }.Min();
        if (grant.Lifecycle != MailboxCapabilityLifecycle.Active ||
            !Fixed(grant.NetworkId.Span, route.Network.NetworkId.Span) ||
            !Fixed(grant.MembershipCommitment.Span, records.Projection.ArtifactHash.Span) ||
            grant.Epoch != U64(records.Selection.Field(4).Span) ||
            !Fixed(grant.IssuerPublicKey.Span, issuer.PublicKey.Span) ||
            grant.Generation < policy.MinimumGrantGeneration ||
            grant.NotBeforeUnixSeconds < issuer.ValidFromUnixSeconds ||
            grant.ExpiresAtUnixSeconds > maximumExpiry ||
            grant.ExpiresAtUnixSeconds - grant.NotBeforeUnixSeconds > policy.MaximumGrantLifetimeSeconds ||
            !PublicKeyAuth.VerifyDetached(grant.IssuerSignature.ToArray(),
                MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant), issuer.PublicKey.ToArray()))
            throw new CryptographicException("Mailbox grant is outside current root-authorized issuer/topology scope.");
        ContactCodec.ValidateMailboxGrantResultRouteBinding(response, records);
        Covers(current, grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds);
    }

    internal static void RequireContinuous(DeepIdV2ContactRouteTimeWindow before, DeepIdV2ContactRouteTimeWindow after)
    {
        if (!Fixed(before.BootId.Span, after.BootId.Span) || after.MonotonicSample < before.MonotonicSample)
            throw new CryptographicException("Mailbox verification crossed a protected clock discontinuity.");
    }
    private static void Covers(DeepIdV2ContactRouteTimeWindow current, ulong start, ulong expiry)
    {
        if (current.LowerUnixSeconds > current.UpperUnixSeconds || start > current.LowerUnixSeconds || current.UpperUnixSeconds >= expiry)
            throw new CryptographicException("Mailbox evidence does not cover the complete authenticated time interval.");
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
}
