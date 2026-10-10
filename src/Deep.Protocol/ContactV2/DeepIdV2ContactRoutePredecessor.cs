using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Authenticated historical lineage input only. No current route,
/// publication, dispatch, signing or grant authority is exposed.</summary>
public sealed class VerifiedDeepIdV2ContactRoutePredecessor
{
    internal VerifiedDeepIdV2ContactRoutePredecessor(ParsedXir1V2 invite, ParsedContactRouteClosure route)
    { Invite = invite; Route = route; }
    internal ParsedXir1V2 Invite { get; }
    internal ParsedContactRouteClosure Route { get; }
    public ReadOnlyMemory<byte> ExactXir1V2 => Invite.CanonicalBytes;
    public ReadOnlyMemory<byte> ExactRouteClosure => Route.ExactBytes;

    internal void RequireAtCurrentContext(DeepIdV2RouteContext current) =>
        DeepIdV2ContactRouteVerifier.RequirePredecessorBindings(Invite, Route, current);

    internal void RequireAdvertisementSuccessor(ContactRecord next)
    {
        var prior = Route.Authorization;
        RequireIncrement(prior.Field(3).Span, next.Field(3).Span);
        if (!DeepIdV2RouteContext.Fixed(prior.CoreHash.Span, next.Field(4).Span) ||
            DeepIdV2RouteContext.U64(next.Field(12).Span) < DeepIdV2RouteContext.U64(prior.Field(12).Span) ||
            DeepIdV2RouteContext.U64(next.Field(13).Span) <= DeepIdV2RouteContext.U64(prior.Field(13).Span))
            throw new CryptographicException("Reachability successor does not advance its exact retained predecessor.");
        foreach (var tag in new[] { 1, 2, 5, 6, 7, 8, 14, 15 })
            if (!DeepIdV2RouteContext.Fixed(prior.Field(tag).Span, next.Field(tag).Span))
                throw new CryptographicException("Reachability successor changes its retained scope.");
    }

    internal void RequireThresholdSuccessor(ContactRecord nextXra, ParsedDeepIdV2RouteThreshold next)
    {
        RequireAdvertisementSuccessor(nextXra);
        var prior = Route.Route; var xrc = next.LiveRoute; var xss = next.Successor;
        RequireIncrement(prior.Field(3).Span, xrc.Field(3).Span);
        if (!DeepIdV2RouteContext.Fixed(prior.CoreHash.Span, xrc.Field(4).Span) ||
            !DeepIdV2RouteContext.Fixed(prior.CoreHash.Span, xss.Field(4).Span) ||
            !DeepIdV2RouteContext.Fixed(ContactCodec.ArtifactReference(ProtocolMagic.XRC1, prior).CanonicalBytes.Span, xss.Field(6).Span) ||
            DeepIdV2RouteContext.U64(xrc.Field(16).Span) < DeepIdV2RouteContext.U64(prior.Field(16).Span) ||
            DeepIdV2RouteContext.U64(xrc.Field(18).Span) <= DeepIdV2RouteContext.U64(prior.Field(18).Span))
            throw new CryptographicException("Threshold successor differs from exact retained route lineage.");
        foreach (var tag in new[] { 1, 2, 6, 10, 14, 15 })
            if (!DeepIdV2RouteContext.Fixed(prior.Field(tag).Span, xrc.Field(tag).Span))
                throw new CryptographicException("Threshold successor changes its retained route or capabilities.");
        var previousSelection = Route.Selection;
        foreach (var tag in Enumerable.Range(1, 7))
            if (!DeepIdV2RouteContext.Fixed(previousSelection.Field(tag).Span, next.Selection.Field(tag).Span))
                throw new CryptographicException("Selection renewal changes its exact placement projection.");
        if (!DeepIdV2RouteContext.Fixed(previousSelection.CanonicalBytes.Span, next.Selection.CanonicalBytes.Span) &&
            (DeepIdV2RouteContext.U64(next.Selection.Field(8).Span) < DeepIdV2RouteContext.U64(previousSelection.Field(8).Span) ||
             DeepIdV2RouteContext.U64(next.Selection.Field(9).Span) <= DeepIdV2RouteContext.U64(previousSelection.Field(9).Span)))
            throw new CryptographicException("Selection renewal does not advance its signed validity envelope.");
    }

    internal static void RequireIncrement(ReadOnlySpan<byte> prior, ReadOnlySpan<byte> next)
    {
        var generation = DeepIdV2RouteContext.U64(prior);
        if (generation == ulong.MaxValue || DeepIdV2RouteContext.U64(next) != generation + 1)
            throw new CryptographicException("A successor must advance its retained generation exactly once.");
    }
}

public static partial class DeepIdV2ContactRouteVerifier
{
    /// <summary>Checks a current exact candidate against authenticated retained
    /// lineage before any durable reservation or witness callback. No signing,
    /// mutation or dispatch authority is returned.</summary>
    public static async ValueTask VerifyAdvertisementSuccessorAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, VerifiedDeepIdV2ContactRoutePredecessor predecessor,
        ReadOnlyMemory<byte> exactXra1, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor); cancellationToken.ThrowIfCancellationRequested();
        if (exactXra1.Length != 550) throw new CryptographicException("XRA1 must have its exact bounded size.");
        var xra = ContactCodec.Decode(ProtocolMagic.XRA1, exactXra1.Span);
        predecessor.RequireAdvertisementSuccessor(xra);
        var first = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, trustedTime,
            cancellationToken).ConfigureAwait(false);
        Require(first);
        Require(await first.RecheckAsync(cancellationToken).ConfigureAwait(false));
        cancellationToken.ThrowIfCancellationRequested();
        void Require(DeepIdV2RouteContext current)
        { predecessor.RequireAtCurrentContext(current); current.RequireAdvertisement(xra); }
    }

    /// <summary>Authenticates exact historical route input against independently
    /// current DID2/network authority. Expiry is not extended and no live route
    /// or mutation permission is returned.</summary>
    public static async ValueTask<VerifiedDeepIdV2ContactRoutePredecessor> VerifyPredecessorAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ReadOnlyMemory<byte> exactXir1V2,
        ReadOnlyMemory<byte> exactSixRecordClosure, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (exactXir1V2.Length != DeepIdV2InviteRendezvousCodec.CanonicalLength ||
            exactSixRecordClosure.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes)
            throw new CryptographicException("The predecessor sizes are outside their exact bounds.");
        var invite = DeepIdV2InviteRendezvousCodec.Decode(exactXir1V2.Span);
        var route = ContactRouteClosureCodec.Decode(exactSixRecordClosure.Span);
        var first = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority,
            trustedTime, cancellationToken).ConfigureAwait(false);
        RequirePredecessorBindings(invite, route, first);
        var final = await first.RecheckAsync(cancellationToken).ConfigureAwait(false);
        RequirePredecessorBindings(invite, route, final);
        cancellationToken.ThrowIfCancellationRequested(); return new(invite, route);
    }

    internal static void RequirePredecessorBindings(ParsedXir1V2 invite,
        ParsedContactRouteClosure route, DeepIdV2RouteContext current)
    {
        if (!DeepIdV2RouteContext.Fixed(route.Projection.CanonicalBytes.Span, current.Pmt.CanonicalBytes.Span))
            throw new CryptographicException("Historical route rollover requires a separately authorized PMT transition.");
        current.RequireAdvertisementPredecessor(route.Authorization);
        RequireHistoricalRouteBindings(invite, route, current, current.PmtReference.Span);
    }

    /// <summary>Original route facts for independently native-committed contact
    /// events only. Requires the exact original PMT in the current protected
    /// lineage; returns no renewal predecessor, route, grant or dispatch authority.</summary>
    public static async ValueTask RequireRetainedEventRouteFactsAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ReadOnlyMemory<byte> exactXir1V2,
        ReadOnlyMemory<byte> exactSixRecordClosure, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (exactXir1V2.Length != DeepIdV2InviteRendezvousCodec.CanonicalLength ||
            exactSixRecordClosure.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes)
            throw new CryptographicException("Retained event route sizes are outside their exact bounds.");
        var invite = DeepIdV2InviteRendezvousCodec.Decode(exactXir1V2.Span);
        var route = ContactRouteClosureCodec.Decode(exactSixRecordClosure.Span);
        var first = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, trustedTime, cancellationToken).ConfigureAwait(false);
        Require(first);
        Require(await first.RecheckAsync(cancellationToken).ConfigureAwait(false));
        cancellationToken.ThrowIfCancellationRequested();

        void Require(DeepIdV2RouteContext current)
        {
            if (current.Network.ProtectedLkg is not { } floor ||
                !DeepIdV2RouteContext.Fixed(floor.AuthorityCoreReference.Span, current.Authority.AuthorityCoreReference.Span) ||
                !current.Network.Closure!.RetainedPmts.Any(pmt => DeepIdV2RouteContext.Fixed(pmt.CanonicalBytes.Span, route.Projection.CanonicalBytes.Span)))
                throw new CryptographicException("Retained event projection is absent from the exact protected authority lineage.");
            var ancestor = XPointOnionCapabilityProducer.RequireRetainedProjectionAuthority(current.Network, current.Authority, route.Projection);
            try { XPointOnionCapabilityProducer.VerifyContactThreshold(route.Projection, ancestor); }
            catch (OnionBoundaryException error) { throw new CryptographicException("Retained event projection threshold is invalid.", error); }
            current.RequireRetainedAdvertisementFacts(route.Authorization, route.Projection);
            RequireHistoricalRouteBindings(invite, route, current,
                ContactCodec.ArtifactReference(ProtocolMagic.PMT2, route.Projection).CanonicalBytes.Span, ancestor);
        }
    }

    private static void RequireHistoricalRouteBindings(ParsedXir1V2 invite,
        ParsedContactRouteClosure route, DeepIdV2RouteContext current, ReadOnlySpan<byte> originalPmtReference,
        Xna1Record? originalSignatureAuthority = null)
    {
        if (!DeepIdV2RouteContext.Fixed(route.Route.Field(19).Span, route.Successor.Field(12).Span))
            throw new CryptographicException("Historical threshold records disagree on their directory issuance anchor.");
        RequireIdentityBindings(invite, route, current.Network.NetworkId.Span,
            originalPmtReference, current.DeviceReference.Span, current.DcaReference.Span);
        // Decoding independently validates the exact six-record graph. These
        // signatures authenticate history, not a current route's expired window.
        if (originalSignatureAuthority is null)
        {
            DeepIdV2RouteContext.VerifyWitnesses(route.Selection, 11, current.Authority);
            DeepIdV2RouteContext.VerifyWitnesses(route.Route, 21, current.Authority);
            DeepIdV2RouteContext.VerifyWitnesses(route.Successor, 14, current.Authority);
        }
        else
        {
            DeepIdV2RouteContext.VerifyWitnesses(route.Selection, 11, originalSignatureAuthority);
            DeepIdV2RouteContext.VerifyWitnesses(route.Route, 21, originalSignatureAuthority);
            DeepIdV2RouteContext.VerifyWitnesses(route.Successor, 14, originalSignatureAuthority);
            foreach (var (record, issuedTag, expiryTag) in new[] { (route.Selection, 8, 9), (route.Route, 16, 18), (route.Successor, 10, 11) })
                if (DeepIdV2RouteContext.U64(record.Field(issuedTag).Span) < originalSignatureAuthority.NotBefore ||
                    DeepIdV2RouteContext.U64(record.Field(expiryTag).Span) > originalSignatureAuthority.ExpiresAt)
                    throw new CryptographicException("Historical threshold route is outside its original authority interval.");
        }
        ContactCodec.VerifyDeviceSignature(route.Reachability, current.Device.Certificate.DeviceEd25519PublicKey.Span);
        foreach (var (record, issueTag) in new[] { (route.Selection, 8), (route.Route, 16),
                     (route.Successor, 10), (route.Reachability, 15) })
            if (DeepIdV2RouteContext.U64(record.Field(issueTag).Span) > current.Lower)
                throw new CryptographicException("Historical route is issued after current trusted time.");
        var issue = DeepIdV2RouteContext.U64(invite.Field(13).Span);
        if (issue > current.Lower || invite.Field(9).Span[0] != 1 ||
            !DeepIdV2RouteContext.Fixed(invite.Field(11).Span, route.Reachability.Field(14).Span))
            throw new CryptographicException("Only the exact historical reusable route can be renewed.");
        // A signed issue timestamp checks original scope/signature containment
        // only. It is never supplied to current route/dispatch verification.
        DeepIdV2InviteRendezvousCodec.VerifyIssuerAndDca1(invite, current.Recipient.Authorization, issue);
    }
}
