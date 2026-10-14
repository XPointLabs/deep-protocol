using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Independently current private delivery route. Does not carry or
/// renew an invitation, authenticate an event, establish consent/publication,
/// enroll a holder or authorize dispatch.</summary>
public sealed class VerifiedDeepIdV2UpdatedMailboxRoute : VerifiedDeepIdV2MailboxRouteClosure
{
    private readonly OnionTrustedTimeAuthority time;
    private readonly ulong eventExpiryMilliseconds;
    internal VerifiedDeepIdV2UpdatedMailboxRoute(ParsedContactRouteClosure route,
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, OnionTrustedTimeAuthority time, ulong eventExpiryMilliseconds)
    { Route = route; Recipient = recipient; Network = network; NetworkAuthority = authority; this.time = time; this.eventExpiryMilliseconds = eventExpiryMilliseconds; }

    public override ParsedContactRouteClosure Route { get; }
    public override DeepIdV2CurrentContactAuthorization Recipient { get; }
    public override VerifiedOnionNetworkContext Network { get; }
    public override VerifiedXPointNetworkAuthority NetworkAuthority { get; }

    public override async ValueTask<DeepIdV2ContactRouteTimeWindow> ReadCurrentTimeAsync(
        CancellationToken cancellationToken = default)
    {
        var first = await DeepIdV2RouteContext.ReadAsync(Recipient, Network, NetworkAuthority,
            time, cancellationToken).ConfigureAwait(false);
        DeepIdV2ContactRouteUpdateVerifier.RequireCurrentRoute(Route, first);
        if (checked(first.Upper * 1000) >= eventExpiryMilliseconds)
            throw new CryptographicException("Expired private route update is not current delivery authority.");
        var final = await first.RecheckAsync(cancellationToken).ConfigureAwait(false);
        DeepIdV2ContactRouteUpdateVerifier.RequireCurrentRoute(Route, final);
        if (checked(final.Upper * 1000) >= eventExpiryMilliseconds)
            throw new CryptographicException("Expired private route update is not current delivery authority.");
        cancellationToken.ThrowIfCancellationRequested();
        return new(final.Lower, final.Upper, final.Reading);
    }
}

/// <summary>Bounded independent route metadata verification. Previous event
/// hashes/selectors are comparison inputs, not native/event authentication.
/// Shared must separately derive their exact ordered custody under its lease.</summary>
public static class DeepIdV2ContactRouteUpdateVerifier
{
    public static async ValueTask<VerifiedDeepIdV2UpdatedMailboxRoute> VerifyCurrentSuccessorAsync(
        ParsedDeepIdV2ContactMailboxRoute originalPackage, VerifiedDeepIdV2DirectoryFreshness peer,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority time, ReadOnlyMemory<byte> exactPreviousRoute,
        ReadOnlyMemory<byte> previousEventHash32, ReadOnlyMemory<byte> relationship32,
        ReadOnlyMemory<byte> conversation32, ReadOnlyMemory<byte> exactDmc2,
        CancellationToken cancellationToken = default)
    {
        var verified = await VerifyAsync(originalPackage, peer, network, authority, time,
            exactPreviousRoute, previousEventHash32, relationship32, conversation32,
            exactDmc2, current: true, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return new(verified.Route, verified.Recipient, network, authority, time, verified.EventExpiryMilliseconds);
    }

    /// <summary>Historical signatures, scope, creation containment and exact
    /// lineage only; no currentness/renewal/grant/dispatch/deletion capability.</summary>
    public static async ValueTask<ParsedContactRouteClosure> RequireRetainedSuccessorFactsAsync(
        ParsedDeepIdV2ContactMailboxRoute originalPackage, VerifiedDeepIdV2DirectoryFreshness peer,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority time, ReadOnlyMemory<byte> exactPreviousRoute,
        ReadOnlyMemory<byte> previousEventHash32, ReadOnlyMemory<byte> relationship32,
        ReadOnlyMemory<byte> conversation32, ReadOnlyMemory<byte> exactDmc2,
        CancellationToken cancellationToken = default)
    {
        var verified = await VerifyAsync(originalPackage, peer, network, authority, time,
            exactPreviousRoute, previousEventHash32, relationship32, conversation32,
            exactDmc2, current: false, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested(); return verified.Route;
    }

    private static async ValueTask<(ParsedContactRouteClosure Route, DeepIdV2CurrentContactAuthorization Recipient, ulong EventExpiryMilliseconds)> VerifyAsync(
        ParsedDeepIdV2ContactMailboxRoute original, VerifiedDeepIdV2DirectoryFreshness peer,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority time, ReadOnlyMemory<byte> exactPrevious,
        ReadOnlyMemory<byte> previousHash, ReadOnlyMemory<byte> relationship,
        ReadOnlyMemory<byte> conversation, ReadOnlyMemory<byte> exactEvent,
        bool current, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(original); ArgumentNullException.ThrowIfNull(peer);
        ArgumentNullException.ThrowIfNull(network); ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(time); ct.ThrowIfCancellationRequested();
        RequireSelector(previousHash.Span); RequireSelector(relationship.Span); RequireSelector(conversation.Span);
        if (exactPrevious.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes ||
            exactEvent.Length is < 4497 or > 23649)
            throw new CryptographicException("Private route-update input exceeds its exact closed bounds.");
        // All caller-owned buffers become immutable bounded records/selectors
        // before the first asynchronous clock/current-authority operation.
        var previous = ContactRouteClosureCodec.Decode(exactPrevious.Span);
        var message = ApplicationCoreCodec.DecodeDmc2(exactEvent.Span);
        if (message.ContentKind != Dmc2ContentKind.ContactRouteUpdate ||
            message.ParsedPayload is not ContactRouteUpdateDmc2Payload update ||
            message.Flags != Dmc2Flags.None || message.ReplyToLogicalMessageId.Length != 0 ||
            message.ExpiresAtUnixMilliseconds == 0)
        {
            if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose();
            throw new CryptographicException("Private route update requires the exact closed DMC2 control kind.");
        }
        var predecessorHash = previousHash.ToArray(); var relationshipId = relationship.ToArray(); var conversationId = conversation.ToArray();
        try
        {
            var bytes = ContactRouteClosureCodec.EncodeRecords([update.Reachability, update.Authorization,
                update.Route, update.Successor, update.MailboxProjection, update.MailboxSelection]);
            ParsedContactRouteClosure route;
            try { route = ContactRouteClosureCodec.Decode(bytes); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
            var checkpoint = peer.CurrentCheckpoint ?? throw new CryptographicException("Private route update lost its current peer.");
            var delegation = DeepIdV2ContactAuthorizationCodec.Verify(original.Authorization, checkpoint.Binding, checkpoint.Directory);
            var reading = await time.ReadCurrentAsync(ct).ConfigureAwait(false);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(peer, delegation, reading.BootId.Span, reading.SampleSeconds);
            await DeepIdV2ContactRouteVerifier.RequireRetainedEventRouteFactsAsync(recipient, network, authority,
                original.Invite.CanonicalBytes, original.Route.ExactBytes, time, ct).ConfigureAwait(false);
            var first = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, time, ct).ConfigureAwait(false);
            Require(first);
            Require(await first.RecheckAsync(ct).ConfigureAwait(false));
            ct.ThrowIfCancellationRequested(); return (route, recipient, message.ExpiresAtUnixMilliseconds);

            void Require(DeepIdV2RouteContext context)
            {
                if (!Fixed(message.NetworkId.Span, network.NetworkId.Span) ||
                    !Fixed(message.SenderAccountId.Span, context.Recipient.Authorization.Binding.Record.DeepAccountId.Span) ||
                    !Fixed(message.SenderDeviceId.Span, context.Device.Certificate.DeviceId.Span) ||
                    !Fixed(message.ConversationId.Span, conversationId) ||
                    !Fixed(update.RelationshipId.Span, relationshipId) ||
                    !Fixed(update.PredecessorRouteUpdateHash.Span, predecessorHash))
                    throw new CryptographicException("Private route update differs from the actual peer, relationship or predecessor.");
                RequireOriginalScope(original.Route, previous);
                RequireHistoricalRoute(previous, context);
                RequireTransition(original.Invite, previous, route);
                RequireHistoricalRoute(route, context);
                var created = message.CreatedAtUnixMilliseconds / 1000;
                if (message.CreatedAtUnixMilliseconds > checked(context.Upper * 1000) ||
                    !CoversCreation(route, created))
                    throw new CryptographicException("Private route update lies outside its original signed creation interval.");
                if (current)
                {
                    RequireCurrentRoute(route, context);
                    if (checked(context.Upper * 1000) >= message.ExpiresAtUnixMilliseconds)
                        throw new CryptographicException("Expired private route update is not current delivery authority.");
                }
            }
        }
        finally
        { CryptographicOperations.ZeroMemory(predecessorHash); CryptographicOperations.ZeroMemory(relationshipId); CryptographicOperations.ZeroMemory(conversationId); }
    }

    internal static void RequireCurrentRoute(ParsedContactRouteClosure route, DeepIdV2RouteContext current)
    {
        if (!Fixed(route.Projection.CanonicalBytes.Span, current.Pmt.CanonicalBytes.Span))
            throw new CryptographicException("Private delivery route changes the exact current projection.");
        current.RequireAdvertisement(route.Authorization);
        current.RequireThreshold(route.Authorization, route.Selection, route.Route, route.Successor, requireCurrentDirectory: false);
        RequireDeviceRouteScope(route, current);
        current.Covers(U64(route.Reachability.Field(16).Span), U64(route.Reachability.Field(17).Span), DeepIdV2RouteTimeArtifact.Xrr1);
        ContactCodec.VerifyDeviceSignature(route.Reachability, current.Device.Certificate.DeviceEd25519PublicKey.Span);
    }

    private static void RequireHistoricalRoute(ParsedContactRouteClosure route, DeepIdV2RouteContext current)
    {
        if (!current.Network.Closure!.RetainedPmts.Any(pmt => Fixed(pmt.CanonicalBytes.Span, route.Projection.CanonicalBytes.Span)))
            throw new CryptographicException("Private route history lost its protected projection lineage.");
        var ancestor = XPointOnionCapabilityProducer.RequireRetainedProjectionAuthority(current.Network, current.Authority, route.Projection);
        XPointOnionCapabilityProducer.VerifyContactThreshold(route.Projection, ancestor);
        current.RequireRetainedAdvertisementFacts(route.Authorization, route.Projection);
        RequireDeviceRouteScope(route, current);
        if (!Fixed(route.Route.Field(19).Span, route.Successor.Field(12).Span))
            throw new CryptographicException("Private route history changes its directory issuance anchor.");
        ContactCodec.VerifyDeviceSignature(route.Reachability, current.Device.Certificate.DeviceEd25519PublicKey.Span);
        foreach (var (record, signatureTag, issueTag, expiryTag) in new[] {
            (route.Selection, 11, 8, 9), (route.Route, 21, 16, 18), (route.Successor, 14, 10, 11) })
        {
            DeepIdV2RouteContext.VerifyWitnesses(record, signatureTag, ancestor);
            if (U64(record.Field(issueTag).Span) > current.Lower || U64(record.Field(issueTag).Span) < ancestor.NotBefore ||
                U64(record.Field(expiryTag).Span) > ancestor.ExpiresAt)
                throw new CryptographicException("Private route history exceeds its original witness authority.");
        }
        if (U64(route.Reachability.Field(15).Span) > current.Lower)
            throw new CryptographicException("Private route history is issued after trusted current time.");
    }

    private static void RequireDeviceRouteScope(ParsedContactRouteClosure route, DeepIdV2RouteContext current)
    {
        if (!Fixed(route.Reachability.Field(18).Span, current.DeviceReference.Span) ||
            !Fixed(route.Reachability.Field(10).Span, route.Route.Field(10).Span) ||
            !Fixed(route.Reachability.Field(11).Span, route.Authorization.Field(9).Span) ||
            !Fixed(route.Reachability.Field(13).Span, route.Authorization.Field(8).Span))
            throw new CryptographicException("Private route differs from its independently current device and signed capabilities.");
    }

    private static void RequireOriginalScope(ParsedContactRouteClosure original, ParsedContactRouteClosure previous)
    {
        foreach (var tag in new[] { 1, 2, 5, 6, 7, 8, 14, 15 })
            if (!Fixed(original.Authorization.Field(tag).Span, previous.Authorization.Field(tag).Span))
                throw new CryptographicException("Private route predecessor changes its original reachability scope.");
        foreach (var tag in new[] { 1, 2, 6, 10, 14, 15 })
            if (!Fixed(original.Route.Field(tag).Span, previous.Route.Field(tag).Span))
                throw new CryptographicException("Private route predecessor changes its original route scope.");
        foreach (var tag in new[] { 1, 2, 10, 12, 13, 14, 18 })
            if (!Fixed(original.Reachability.Field(tag).Span, previous.Reachability.Field(tag).Span))
                throw new CryptographicException("Private route predecessor changes its original signed recipient scope.");
    }

    private static void RequireTransition(ParsedXir1V2 originalInvite, ParsedContactRouteClosure previous, ParsedContactRouteClosure next)
    {
        // Reuse the single DR72 same-scope XRA/XRC/XSS/PMS transition checks.
        // This internal selector exposes no invitation or current capability.
        new VerifiedDeepIdV2ContactRoutePredecessor(originalInvite, previous).RequireThresholdSuccessor(next.Authorization,
            new ParsedDeepIdV2RouteThreshold(next.Selection.CanonicalBytes.Span, next.Route.CanonicalBytes.Span, next.Successor.CanonicalBytes.Span));
        VerifiedDeepIdV2ContactRoutePredecessor.RequireIncrement(previous.Reachability.Field(3).Span, next.Reachability.Field(3).Span);
        if (!Fixed(previous.Reachability.CoreHash.Span, next.Reachability.Field(4).Span) ||
            U64(next.Reachability.Field(15).Span) < U64(previous.Reachability.Field(15).Span) ||
            U64(next.Reachability.Field(17).Span) <= U64(previous.Reachability.Field(17).Span))
            throw new CryptographicException("Private reachability update does not advance its exact signed predecessor.");
        foreach (var tag in new[] { 1, 2, 10, 12, 13, 14, 18 })
            if (!Fixed(previous.Reachability.Field(tag).Span, next.Reachability.Field(tag).Span))
                throw new CryptographicException("Private reachability successor changes retained scope.");
    }

    private static bool CoversCreation(ParsedContactRouteClosure route, ulong created) =>
        new[] { (route.Authorization, 12, 13), (route.Reachability, 16, 17),
            (route.Selection, 8, 9), (route.Route, 17, 18), (route.Successor, 10, 11), (route.Projection, 11, 12) }
        .All(part => U64(part.Item1.Field(part.Item2).Span) <= created && created < U64(part.Item1.Field(part.Item3).Span));
    private static ulong U64(ReadOnlySpan<byte> value) => DeepIdV2RouteContext.U64(value);
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => DeepIdV2RouteContext.Fixed(a, b);
    private static void RequireSelector(ReadOnlySpan<byte> value)
    { if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0) throw new CryptographicException("Private route update requires an exact nonzero selector."); }
}
