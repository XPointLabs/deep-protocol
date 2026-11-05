using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Independently verified C/P facts only. No current route, consent,
/// publication, dispatch or durable adoption permission is exposed.</summary>
public sealed class VerifiedDeepIdV2ContactRouteHistory
{
    internal VerifiedDeepIdV2ContactRouteHistory(ParsedDmc2 original, ParsedDeepIdV2ContactMailboxRoute package,
        ParsedXir1V2 invite, ParsedContactRouteClosure completed, ContactRecord proposal,
        ParsedDeepIdV2RouteThreshold threshold, DeepIdV2ContactRouteRecordedPair? proposalOriginal)
    { Original = original; Package = package; Invite = invite; Completed = completed;
        Proposal = proposal; Threshold = threshold; ProposalOriginal = proposalOriginal; }
    internal ParsedDmc2 Original { get; }
    internal ParsedDeepIdV2ContactMailboxRoute Package { get; }
    internal ParsedXir1V2 Invite { get; }
    internal ParsedContactRouteClosure Completed { get; }
    internal ContactRecord Proposal { get; }
    internal ParsedDeepIdV2RouteThreshold Threshold { get; }
    internal DeepIdV2ContactRouteRecordedPair? ProposalOriginal { get; }
    /// <summary>Exact authenticated cursor; not locally adopted progress.</summary>
    public ReadOnlyMemory<byte> Cursor => DeepIdV2ContactRouteHistoryCodec.Cursor(Completed, Proposal, Threshold.LiveRoute);
    /// <summary>Exact historical C XIR, including its independent object lineage.</summary>
    public ReadOnlyMemory<byte> ExactCompletedXir1V2 => Invite.CanonicalBytes;
    /// <summary>Exact historical six-record C closure, without live authority.</summary>
    public ReadOnlyMemory<byte> ExactCompletedRoute => Completed.ExactBytes;
    /// <summary>Original native relationship-anchor selector.</summary>
    public ReadOnlyMemory<byte> OriginalAnchorHash => SHA256.HashData(Original.CanonicalBytes.Span);
    internal ReadOnlyMemory<byte> Relationship => Original.ParsedPayload switch {
        ContactHelloDmc2Payload hello => hello.RelationshipId,
        ContactAcceptDmc2Payload accept => accept.RelationshipId,
        _ => throw new CryptographicException("History lost its original relationship anchor.") };
}

/// <summary>One independently verified immutable original step; no current or native authority.</summary>
public sealed class VerifiedDeepIdV2ContactRouteHistoryStep
{
    internal VerifiedDeepIdV2ContactRouteHistoryStep(VerifiedDeepIdV2ContactRouteHistory before,
        VerifiedDeepIdV2ContactRouteHistory after, ParsedDeepIdV2ContactRouteHistoryAtom atom)
    { Before = before; After = after; Atom = atom; }
    internal VerifiedDeepIdV2ContactRouteHistory Before { get; }
    internal ParsedDeepIdV2ContactRouteHistoryAtom Atom { get; }
    /// <summary>Authenticated historical endpoint. Persist through the native owner before using as progress.</summary>
    public VerifiedDeepIdV2ContactRouteHistory After { get; }
}

/// <summary>Bounded historical page verification separated from current promotion.</summary>
public static partial class DeepIdV2ContactRouteUpdateVerifier
{
    /// <summary>Seeds C/P at the actual original Hello/Accept generation. The caller must
    /// select the original from authenticated native custody and independently enforce consent.</summary>
    public static async ValueTask<VerifiedDeepIdV2ContactRouteHistory> VerifyHistoryAnchorAsync(
        ReadOnlyMemory<byte> exactOriginalDmc2, VerifiedDeepIdV2DirectoryFreshness peer,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority time, CancellationToken cancellationToken = default)
    {
        var original = ApplicationCoreCodec.DecodeDmc2(exactOriginalDmc2.Span);
        var package = original.ParsedPayload switch {
            ContactHelloDmc2Payload hello => hello.MailboxRoute,
            ContactAcceptDmc2Payload accept => accept.MailboxRoute,
            _ => throw new CryptographicException("History bootstrap requires the exact original Hello/Accept, including XIR.") };
        var state = new VerifiedDeepIdV2ContactRouteHistory(original, package, package.Invite, package.Route,
            package.Route.Authorization, new(package.Route.Selection.CanonicalBytes.Span,
                package.Route.Route.CanonicalBytes.Span, package.Route.Successor.CanonicalBytes.Span), null);
        await WithHistoryContextAsync(state, peer, network, authority, time, _ => { }, cancellationToken).ConfigureAwait(false);
        return state;
    }

    /// <summary>Reconstitutes bounded historical facts from an already qualified native
    /// checkpoint, never from remote progress or a staged candidate. The native owner must
    /// authenticate actual decision/source refs, root and floor before this call and recheck
    /// them after callbacks. Their committed qualification supplies past adjacency and C's
    /// original issuance proof; this method never admits new progress or current permission.</summary>
    /// <param name="exactOriginalHelloOrAcceptDmc2">Actual immutable native relationship original.</param>
    /// <param name="exactCompletedXir1V2">Exact C XIR selected by the authenticated decision.</param>
    /// <param name="exactCompletedRoute">Exact six-record C closure selected by that decision.</param>
    /// <param name="retainedProposal">Exact selected P original exchange; null only for the original C/P seed.</param>
    /// <param name="peer">Independently current peer directory proof.</param>
    /// <param name="network">Independently verified current network and retained public authority.</param>
    /// <param name="authority">Current network authority.</param>
    /// <param name="time">Protected trusted-time authority.</param>
    /// <param name="cancellationToken">Cancellation before any returned fact.</param>
    /// <returns>Historical facts only; no step, adoption, publication, route or dispatch authority.</returns>
    public static async ValueTask<VerifiedDeepIdV2ContactRouteHistory> VerifyRetainedHistoryCheckpointFactsAsync(
        ReadOnlyMemory<byte> exactOriginalHelloOrAcceptDmc2, ReadOnlyMemory<byte> exactCompletedXir1V2,
        ReadOnlyMemory<byte> exactCompletedRoute, DeepIdV2ContactRouteRecordedPair? retainedProposal,
        VerifiedDeepIdV2DirectoryFreshness peer, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, OnionTrustedTimeAuthority time,
        CancellationToken cancellationToken = default)
    {
        // Every caller-owned byte buffer is bounded and copied before the first await.
        var state = ParseRetainedHistoryCheckpoint(exactOriginalHelloOrAcceptDmc2.Span,
            exactCompletedXir1V2.Span, exactCompletedRoute.Span, retainedProposal);
        var pair = state.ProposalOriginal;
        var anchorInvite = pair is null ? null : DeepIdV2InviteRendezvousCodec.Decode(pair.Request.ExactPredecessorXir1V2.Span);
        var anchorRoute = pair is null ? null : ContactRouteClosureCodec.Decode(pair.Request.ExactPredecessorRouteClosure.Span);
        await WithHistoryContextAsync(state, peer, network, authority, time, current => {
            if (pair is null) return;
            RequireHistoricalRoute(anchorRoute!, current);
            DeepIdV2ContactRouteVerifier.RequireHistoricalRouteBindings(anchorInvite!, anchorRoute!, current,
                ContactCodec.ArtifactReference(ProtocolMagic.PMT2, anchorRoute!.Projection).CanonicalBytes.Span);
            VerifiedDeepIdV2ContactRouteRecordedHistory.RequireIntrinsicPairFacts(pair, anchorRoute!, current);
        }, cancellationToken).ConfigureAwait(false);
        return state;
    }

    // Structural preparation alone is internal and never escapes the public verifier
    // before signature/current-authority rechecks. It grants no native adoption permission.
    internal static VerifiedDeepIdV2ContactRouteHistory ParseRetainedHistoryCheckpoint(
        ReadOnlySpan<byte> exactOriginal, ReadOnlySpan<byte> exactInvite, ReadOnlySpan<byte> exactRoute,
        DeepIdV2ContactRouteRecordedPair? retainedProposal)
    {
        if (exactInvite.Length != DeepIdV2InviteRendezvousCodec.CanonicalLength ||
            exactRoute.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes)
            throw new CryptographicException("Retained checkpoint exceeds its exact completed record bounds.");
        var original = ApplicationCoreCodec.DecodeDmc2(exactOriginal);
        var package = original.ParsedPayload switch {
            ContactHelloDmc2Payload hello => hello.MailboxRoute,
            ContactAcceptDmc2Payload accept => accept.MailboxRoute,
            _ => throw new CryptographicException("Retained checkpoint requires the actual original Hello/Accept.") };
        var invite = DeepIdV2InviteRendezvousCodec.Decode(exactInvite);
        var route = ContactRouteClosureCodec.Decode(exactRoute);
        RequireCheckpointScope(package, invite, route);
        var generation = U64(route.Reachability.Field(3).Span);
        var originalGeneration = U64(package.Route.Reachability.Field(3).Span);
        var seed = Fixed(invite.CanonicalBytes.Span, package.Invite.CanonicalBytes.Span) && Fixed(route.ExactBytes.Span, package.Route.ExactBytes.Span);
        if (generation < originalGeneration || generation == originalGeneration && !seed)
            throw new CryptographicException("Retained checkpoint substituted its original completed generation.");
        if (retainedProposal is null)
        {
            if (!seed) throw new CryptographicException("Retained checkpoint lost its adopted proposal source; it cannot bootstrap again.");
            return new(original, package, invite, route, route.Authorization,
                new(route.Selection.CanonicalBytes.Span, route.Route.CanonicalBytes.Span, route.Successor.CanonicalBytes.Span), null);
        }
        var pair = new DeepIdV2ContactRouteRecordedPair(retainedProposal.ExactRequest.Span, retainedProposal.ExactResponse.Span);
        var anchorInvite = DeepIdV2InviteRendezvousCodec.Decode(pair.Request.ExactPredecessorXir1V2.Span);
        var anchorRoute = ContactRouteClosureCodec.Decode(pair.Request.ExactPredecessorRouteClosure.Span);
        RequireCheckpointScope(package, anchorInvite, anchorRoute);
        var anchorGeneration = U64(anchorRoute.Reachability.Field(3).Span);
        if (anchorGeneration < originalGeneration || anchorGeneration > generation ||
            anchorGeneration == generation && (!Fixed(anchorInvite.CanonicalBytes.Span, invite.CanonicalBytes.Span) || !Fixed(anchorRoute.ExactBytes.Span, route.ExactBytes.Span)))
            throw new CryptographicException("Retained proposal substituted its authenticated completed anchor.");
        var proposal = ContactCodec.Decode(ProtocolMagic.XRA1, pair.Request.ExactXra1.Span);
        var threshold = VerifiedDeepIdV2ContactRouteRecordedHistory.Threshold(pair);
        var proposalGeneration = U64(proposal.Field(3).Span);
        if (!Fixed(pair.Request.ExactDca1.Span, package.Authorization.CanonicalBytes.Span) ||
            proposalGeneration <= U64(package.Route.Authorization.Field(3).Span) ||
            proposalGeneration < U64(route.Authorization.Field(3).Span))
            throw new CryptographicException("Retained checkpoint changed its original delegation or proposal progress.");
        if (proposalGeneration == U64(route.Authorization.Field(3).Span) &&
            (!Fixed(proposal.CanonicalBytes.Span, route.Authorization.CanonicalBytes.Span) ||
             !Fixed(threshold.Selection.CanonicalBytes.Span, route.Selection.CanonicalBytes.Span) ||
             !Fixed(threshold.LiveRoute.CanonicalBytes.Span, route.Route.CanonicalBytes.Span) ||
             !Fixed(threshold.Successor.CanonicalBytes.Span, route.Successor.CanonicalBytes.Span)))
            throw new CryptographicException("Retained checkpoint changed its exact completed proposal original.");
        ContactCodec.ValidateThresholdRouteGraph(proposal, threshold.LiveRoute, threshold.Successor, anchorRoute.Projection, threshold.Selection);
        return new(original, package, invite, route, proposal, threshold, pair);
    }

    private static void RequireCheckpointScope(ParsedDeepIdV2ContactMailboxRoute original,
        ParsedXir1V2 invite, ParsedContactRouteClosure route)
    {
        RequireOriginalScope(original.Route, route);
        if (!Fixed(invite.Field(3).Span, route.Reachability.Field(3).Span))
            throw new CryptographicException("Retained checkpoint XIR/XRR generations differ.");
        foreach (var tag in new[] { 1, 2, 5, 6, 9, 10, 11, 12, 15, 16 })
            if (!Fixed(original.Invite.Field(tag).Span, invite.Field(tag).Span))
                throw new CryptographicException("Retained checkpoint changed its original reusable invite scope.");
        if (invite.Field(9).Span[0] != 1) throw new CryptographicException("Retained checkpoint requires reusable invitation policy.");
        DeepIdV2ContactRouteVerifier.RequireIdentityBindings(invite, route, original.Authorization.NetworkId.Span,
            ContactCodec.ArtifactReference(ProtocolMagic.PMT2, route.Projection).CanonicalBytes.Span,
            original.Invite.Field(15).Span, original.Invite.Field(16).Span);
    }

    /// <summary>Verifies one retained ordinary exchange against exact C/P. The producer
    /// compares the reconstructed canonical request to its protected original before returning any step.</summary>
    public static async ValueTask<VerifiedDeepIdV2ContactRouteHistoryStep> VerifyOriginalHistoryStepAsync(
        VerifiedDeepIdV2ContactRouteHistory before, ReadOnlyMemory<byte> exactOriginalRequest,
        ReadOnlyMemory<byte> exactOriginalResponse, ReadOnlyMemory<byte> exactCompletedXir1V2,
        ReadOnlyMemory<byte> exactCompletedRoute, VerifiedDeepIdV2DirectoryFreshness peer,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority time, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(before);
        var pair = new DeepIdV2ContactRouteRecordedPair(exactOriginalRequest.Span, exactOriginalResponse.Span);
        var atom = OriginalAtom(pair, exactCompletedXir1V2.Span, exactCompletedRoute.Span);
        var reconstructed = ContactRouteAuthorityWireCodec.EncodeRequest(atom.Reconstruct(before.Invite, before.Completed));
        if (!Fixed(reconstructed, pair.ExactRequest.Span))
            throw new CryptographicException("History producer substituted the exact retained ordinary request.");
        VerifiedDeepIdV2ContactRouteHistory? after = null;
        await WithHistoryContextAsync(before, peer, network, authority, time,
            current => after = AdvanceHistory(before, atom, current), cancellationToken).ConfigureAwait(false);
        return new(before, after!, atom);
    }

    /// <summary>Independently checks each public adjacent step. No private announcement
    /// predecessor is required. A future left endpoint must be staged by the native owner.</summary>
    public static async ValueTask<VerifiedDeepIdV2ContactRouteHistory> VerifyHistoryPageAsync(
        VerifiedDeepIdV2ContactRouteHistory before, ReadOnlyMemory<byte> exactDmc2,
        VerifiedDeepIdV2DirectoryFreshness peer, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, OnionTrustedTimeAuthority time,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(before);
        var message = ApplicationCoreCodec.DecodeDmc2(exactDmc2.Span);
        var payload = RequireHistoryMessage(before, message);
        if (payload.Mode == DeepIdV2ContactRouteHistoryMode.HistoryRequest)
            throw new CryptographicException("A remote request cursor cannot advance local history.");
        RequireHistoryLeft(before, payload);
        VerifiedDeepIdV2ContactRouteHistory? after = null;
        await WithHistoryContextAsync(before, peer, network, authority, time, current => {
            var state = before;
            foreach (var atom in payload.Atoms) state = AdvanceHistory(state, atom, current);
            if (!Fixed(state.Cursor.Span, payload.RightCursor.Span))
                throw new CryptographicException("History page right cursor differs from its exact computed endpoint.");
            after = state;
        }, cancellationToken).ConfigureAwait(false);
        return after!;
    }

    /// <summary>Verifies exactly one selected adjacent atom, not a whole page. The
    /// one-based index matches native Source96. Earlier parsed atoms only compare
    /// against already native-qualified before facts; they are never newly admitted.
    /// The native owner must bind the actual original/index and before/after fences.</summary>
    public static async ValueTask<VerifiedDeepIdV2ContactRouteHistoryStep> VerifyHistoryAtomAsync(
        VerifiedDeepIdV2ContactRouteHistory before, ReadOnlyMemory<byte> exactDmc2, byte atomIndex,
        VerifiedDeepIdV2DirectoryFreshness peer, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, OnionTrustedTimeAuthority time,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(before);
        var message = ApplicationCoreCodec.DecodeDmc2(exactDmc2.Span);
        var payload = RequireHistoryMessage(before, message);
        RequireHistoryAtomPrefix(before, payload, atomIndex);
        var selected = payload.Atoms[atomIndex - 1];
        VerifiedDeepIdV2ContactRouteHistory? after = null;
        await WithHistoryContextAsync(before, peer, network, authority, time, current => {
            var state = AdvanceHistory(before, selected, current);
            if (atomIndex == payload.Atoms.Count && !Fixed(state.Cursor.Span, payload.RightCursor.Span))
                throw new CryptographicException("Final selected history atom differs from the page's computed right cursor.");
            after = state;
        }, cancellationToken).ConfigureAwait(false);
        return new(before, after!, selected);
    }

    internal static void RequireHistoryAtomPrefix(VerifiedDeepIdV2ContactRouteHistory before,
        ContactRouteHistoryDmc2Payload payload, byte atomIndex)
    {
        if (atomIndex is < 1 or > 3 || atomIndex > payload.Atoms.Count ||
            payload.Mode is not (DeepIdV2ContactRouteHistoryMode.Evidence or DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement))
            throw new CryptographicException("Selected history atom index is outside the closed evidence page.");
        if (atomIndex == 1) { RequireHistoryLeft(before, payload); return; }
        var cursor = payload.LeftCursor.ToArray(); var invite = payload.ExactLeftXir1V2;
        ParsedContactRouteClosure? lastCompleted = null;
        for (var index = 0; index < atomIndex - 1; index++)
        {
            var preceding = payload.Atoms[index];
            var xra = ContactCodec.Decode(ProtocolMagic.XRA1, preceding.ExactXra1.Span);
            var xrc = ContactCodec.Decode(ProtocolMagic.XRC1, preceding.Response.ExactXrc1.Span);
            xra.Field(3).Span.CopyTo(cursor.AsSpan(40)); xra.CoreHash.Span.CopyTo(cursor.AsSpan(48)); xrc.CoreHash.Span.CopyTo(cursor.AsSpan(80));
            if (!preceding.IsCompleted) continue;
            lastCompleted = preceding.CompletedRoute; invite = preceding.Invite.CanonicalBytes;
            lastCompleted.Reachability.Field(3).Span.CopyTo(cursor); lastCompleted.Reachability.CoreHash.Span.CopyTo(cursor.AsSpan(8));
        }
        if (!Fixed(cursor, before.Cursor.Span) || !Fixed(invite.Span, before.Invite.CanonicalBytes.Span) ||
            lastCompleted is not null && !Fixed(lastCompleted.ExactBytes.Span, before.Completed.ExactBytes.Span))
            throw new CryptographicException("Selected history atom prefix differs from exact already-qualified C/P facts.");
        var previous = payload.Atoms[atomIndex - 2];
        var pair = before.ProposalOriginal ?? throw new CryptographicException("Selected history atom prefix lost its qualified proposal original.");
        if (!Fixed(previous.ExactXra1.Span, before.Proposal.CanonicalBytes.Span) ||
            !Fixed(previous.Response.ExactPms2.Span, before.Threshold.Selection.CanonicalBytes.Span) ||
            !Fixed(previous.Response.ExactXrc1.Span, before.Threshold.LiveRoute.CanonicalBytes.Span) ||
            !Fixed(previous.Response.ExactXss1.Span, before.Threshold.Successor.CanonicalBytes.Span))
            throw new CryptographicException("Selected history atom prefix changed its exact already-qualified proposal records.");
        // P's original request may be anchored to an older C than the current
        // checkpoint. Reconstruct against that exact retained original anchor.
        var originalInvite = DeepIdV2InviteRendezvousCodec.Decode(pair.Request.ExactPredecessorXir1V2.Span);
        var originalRoute = ContactRouteClosureCodec.Decode(pair.Request.ExactPredecessorRouteClosure.Span);
        if (!Fixed(ContactRouteAuthorityWireCodec.EncodeRequest(previous.Reconstruct(originalInvite, originalRoute)), pair.ExactRequest.Span) ||
            !Fixed(previous.ExactResponse.Span, pair.ExactResponse.Span))
            throw new CryptographicException("Selected history atom prefix changed its exact original proposal exchange.");
    }

    /// <summary>Matches a request only to independently authenticated local originals.
    /// It returns no checkpoint, publication, signing or mutation authority.</summary>
    public static void RequireHistoryRequestMatch(VerifiedDeepIdV2ContactRouteHistory selectedOriginals,
        ContactRouteHistoryDmc2Payload request)
    {
        ArgumentNullException.ThrowIfNull(selectedOriginals); ArgumentNullException.ThrowIfNull(request);
        if (request.Mode != DeepIdV2ContactRouteHistoryMode.HistoryRequest ||
            !Fixed(request.RelationshipId.Span, selectedOriginals.Relationship.Span) ||
            !Fixed(request.OriginalAnchorHash.Span, selectedOriginals.OriginalAnchorHash.Span))
            throw new CryptographicException("History request differs from retained relationship originals.");
        RequireHistoryLeft(selectedOriginals, request);
    }

    /// <summary>Authenticates a remote mode4 event against independently current
    /// requester account/device authority. Native authentication and consent remain required.</summary>
    public static async ValueTask RequireCurrentHistoryRequestAsync(VerifiedDeepIdV2ContactRouteHistory selectedOriginals,
        ReadOnlyMemory<byte> exactRequestDmc2, DeepIdV2CurrentContactAuthorization requester,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority time, CancellationToken cancellationToken = default)
    {
        var message = ApplicationCoreCodec.DecodeDmc2(exactRequestDmc2.Span);
        if (message.ParsedPayload is not ContactRouteHistoryDmc2Payload payload)
            throw new CryptographicException("A history request requires the closed count8 payload.");
        RequireHistoryRequestMatch(selectedOriginals, payload);
        var first = await DeepIdV2RouteContext.ReadAsync(requester, network, authority, time, cancellationToken).ConfigureAwait(false);
        Require(first); Require(await first.RecheckAsync(cancellationToken).ConfigureAwait(false)); cancellationToken.ThrowIfCancellationRequested();
        void Require(DeepIdV2RouteContext current)
        {
            if (!Fixed(message.NetworkId.Span, network.NetworkId.Span) ||
                !Fixed(message.ConversationId.Span, selectedOriginals.Original.ConversationId.Span) ||
                !Fixed(message.SenderAccountId.Span, requester.Authorization.Binding.Record.DeepAccountId.Span) ||
                !Fixed(message.SenderDeviceId.Span, current.Device.Certificate.DeviceId.Span) ||
                message.CreatedAtUnixMilliseconds > checked(current.Upper * 1000) ||
                message.ExpiresAtUnixMilliseconds == 0 || checked(current.Upper * 1000) >= message.ExpiresAtUnixMilliseconds)
                throw new CryptographicException("History request changed its current authenticated requester or event interval.");
        }
    }

    /// <summary>Matches late or current response correlation to an exact retained
    /// native request original. Matching grants no progress or current permission.</summary>
    public static void RequireHistoryResponseCorrelation(ContactRouteHistoryDmc2Payload response,
        ReadOnlySpan<byte> exactRetainedRequestDmc2)
    {
        ArgumentNullException.ThrowIfNull(response);
        var message = ApplicationCoreCodec.DecodeDmc2(exactRetainedRequestDmc2);
        if (message.ParsedPayload is not ContactRouteHistoryDmc2Payload request ||
            request.Mode != DeepIdV2ContactRouteHistoryMode.HistoryRequest || response.Mode == DeepIdV2ContactRouteHistoryMode.HistoryRequest ||
            !Fixed(response.RequestEventHash.Span, SHA256.HashData(message.CanonicalBytes.Span)) ||
            !Fixed(response.RelationshipId.Span, request.RelationshipId.Span) ||
            !Fixed(response.OriginalAnchorHash.Span, request.OriginalAnchorHash.Span) ||
            !Fixed(response.LeftCursor.Span, request.LeftCursor.Span) ||
            !Fixed(response.ExactLeftXir1V2.Span, request.ExactLeftXir1V2.Span))
            throw new CryptographicException("History response lost its exact retained native request correlation.");
    }

    /// <summary>Fresh independent current qualification of an already authenticated endpoint
    /// announcement. The native owner still enforces consent, monotonic L and decision custody.</summary>
    public static async ValueTask<VerifiedDeepIdV2UpdatedMailboxRoute> VerifyCurrentHistoryAnnouncementAsync(
        VerifiedDeepIdV2ContactRouteHistory endpoint, ReadOnlyMemory<byte> exactDmc2,
        VerifiedDeepIdV2DirectoryFreshness peer, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, OnionTrustedTimeAuthority time,
        CancellationToken cancellationToken = default)
    {
        var message = RequireEndpointAnnouncement(endpoint, exactDmc2);
        DeepIdV2CurrentContactAuthorization? recipient = null;
        await WithHistoryContextAsync(endpoint, peer, network, authority, time, current => {
            RequireCurrentRoute(endpoint.Completed, current);
            RequireCurrentHistoryAnnouncementWindow(endpoint.Completed, message.CreatedAtUnixMilliseconds,
                message.ExpiresAtUnixMilliseconds, current.Upper);
            recipient = current.Recipient;
        }, cancellationToken).ConfigureAwait(false);
        return new(endpoint.Completed, recipient!, network, authority, time, message.ExpiresAtUnixMilliseconds);
    }

    /// <summary>Reads only whether an authenticated announcement is expired for maintenance scheduling. Other invalid windows or current authority failures reject; the result grants no delivery or reintroduction permission.</summary>
    /// <param name="endpoint">Independently verified exact historical endpoint.</param>
    /// <param name="exactDmc2">The caller's authenticated native announcement.</param>
    /// <param name="peer">Independently current peer freshness.</param>
    /// <param name="network">Current verified network context.</param>
    /// <param name="authority">The verified network authority.</param>
    /// <param name="time">Independent trusted time.</param>
    /// <param name="cancellationToken">Cancellation for this read.</param>
    /// <returns>True only for announcement expiry after every other check passes. Neither result is effect permission.</returns>
    public static async ValueTask<bool> IsVerifiedHistoryAnnouncementExpiredForMaintenanceAsync(
        VerifiedDeepIdV2ContactRouteHistory endpoint, ReadOnlyMemory<byte> exactDmc2,
        VerifiedDeepIdV2DirectoryFreshness peer, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, OnionTrustedTimeAuthority time,
        CancellationToken cancellationToken = default)
    {
        var message = RequireEndpointAnnouncement(endpoint, exactDmc2); var expired = false;
        await WithHistoryContextAsync(endpoint, peer, network, authority, time, current =>
        {
            RequireCurrentRoute(endpoint.Completed, current);
            var upper = checked(current.Upper * 1000);
            if (message.CreatedAtUnixMilliseconds > upper)
                ThrowAnnouncementWindowFailure("FutureCreation");
            // Expiry alone must never conceal a creation outside the exact
            // signed route. Diagnostic exception.Data is not consulted here.
            if (!CoversCreation(endpoint.Completed, message.CreatedAtUnixMilliseconds / 1000))
                ThrowAnnouncementWindowFailure("CreationOutsideSignedRoute");
            expired |= upper >= message.ExpiresAtUnixMilliseconds;
        }, cancellationToken).ConfigureAwait(false);
        return expired;
    }

    private static ParsedDmc2 RequireEndpointAnnouncement(VerifiedDeepIdV2ContactRouteHistory endpoint,
        ReadOnlyMemory<byte> exactDmc2)
    {
        var message = ApplicationCoreCodec.DecodeDmc2(exactDmc2.Span);
        var payload = RequireHistoryMessage(endpoint, message);
        if (payload.Mode is not (DeepIdV2ContactRouteHistoryMode.Announcement or DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement) ||
            !Fixed(payload.RightCursor.Span, endpoint.Cursor.Span))
            throw new CryptographicException("Announcement has no independently verified exact endpoint.");
        return message;
    }

    // Denial diagnostics only. The actual caller first authenticates the
    // history/endpoint/current context; this pure predicate grants no authority.
    internal static void RequireCurrentHistoryAnnouncementWindow(ParsedContactRouteClosure completed,
        ulong createdMilliseconds, ulong expiresMilliseconds, ulong currentUpperSeconds)
    {
        var created = createdMilliseconds / 1000;
        // Preserve the original ordered, short-circuit checks and overflow.
        var failure = createdMilliseconds > checked(currentUpperSeconds * 1000) ? "FutureCreation" :
            checked(currentUpperSeconds * 1000) >= expiresMilliseconds ? "ExpiredAnnouncement" :
            !CoversCreation(completed, created) ? "CreationOutsideSignedRoute" : null;
        if (failure is not null)
            ThrowAnnouncementWindowFailure(failure);
    }

    private static void ThrowAnnouncementWindowFailure(string failure)
    {
        var error = new CryptographicException("Announcement is outside its own or the signed route's current windows.");
        error.Data["Deep.ContactRouteHistoryAnnouncement.Check"] = failure;
        throw error;
    }

    private static async ValueTask WithHistoryContextAsync(VerifiedDeepIdV2ContactRouteHistory state,
        VerifiedDeepIdV2DirectoryFreshness peer, VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority time, Action<DeepIdV2RouteContext> require, CancellationToken ct)
    {
        var checkpoint = peer.CurrentCheckpoint ?? throw new CryptographicException("History verification lost current peer authority.");
        var delegation = DeepIdV2ContactAuthorizationCodec.Verify(state.Package.Authorization, checkpoint.Binding, checkpoint.Directory);
        var reading = await time.ReadCurrentAsync(ct).ConfigureAwait(false);
        var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(peer, delegation, reading.BootId.Span, reading.SampleSeconds);
        var current = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, time, ct).ConfigureAwait(false);
        Require(current); Require(await current.RecheckAsync(ct).ConfigureAwait(false)); ct.ThrowIfCancellationRequested();
        void Require(DeepIdV2RouteContext context)
        {
            if (!Fixed(state.Original.NetworkId.Span, network.NetworkId.Span) ||
                !Fixed(state.Original.SenderAccountId.Span, context.Recipient.Authorization.Binding.Record.DeepAccountId.Span) ||
                !Fixed(state.Original.SenderDeviceId.Span, context.Device.Certificate.DeviceId.Span))
                throw new CryptographicException("History changed its actual original peer/device/network.");
            RequireOriginalScope(state.Package.Route, state.Completed);
            RequireHistoricalRoute(state.Completed, context);
            DeepIdV2ContactRouteVerifier.RequireHistoricalRouteBindings(state.Invite, state.Completed, context,
                ContactCodec.ArtifactReference(ProtocolMagic.PMT2, state.Completed.Projection).CanonicalBytes.Span);
            if (!Fixed(state.Invite.Field(3).Span, state.Completed.Reachability.Field(3).Span))
                throw new CryptographicException("Completed XIR/XRR generations differ.");
            require(context);
        }
    }

    private static VerifiedDeepIdV2ContactRouteHistory AdvanceHistory(VerifiedDeepIdV2ContactRouteHistory before,
        ParsedDeepIdV2ContactRouteHistoryAtom atom, DeepIdV2RouteContext current)
    {
        var request = atom.Reconstruct(before.Invite, before.Completed);
        var pair = new DeepIdV2ContactRouteRecordedPair(ContactRouteAuthorityWireCodec.EncodeRequest(request), atom.ExactResponse.Span);
        var xra = ContactCodec.Decode(ProtocolMagic.XRA1, atom.ExactXra1.Span);
        var threshold = VerifiedDeepIdV2ContactRouteRecordedHistory.Threshold(pair);
        var sameProposal = Fixed(xra.CanonicalBytes.Span, before.Proposal.CanonicalBytes.Span) &&
            Fixed(threshold.LiveRoute.CanonicalBytes.Span, before.Threshold.LiveRoute.CanonicalBytes.Span) &&
            Fixed(threshold.Selection.CanonicalBytes.Span, before.Threshold.Selection.CanonicalBytes.Span) &&
            Fixed(threshold.Successor.CanonicalBytes.Span, before.Threshold.Successor.CanonicalBytes.Span);
        if (sameProposal)
        {
            RequireExactProposalOverlap(atom.IsCompleted, before.ProposalOriginal, pair);
        }
        else
        {
            var prior = new VerifiedDeepIdV2ContactRoutePredecessor(before.Invite, before.Completed, before.Proposal, before.Threshold);
            new VerifiedDeepIdV2ContactRouteRecordedHistory(prior, [pair]).RequireFacts(current, requireExpired: false);
        }
        var invite = before.Invite; var route = before.Completed;
        if (atom.IsCompleted)
        {
            invite = atom.Invite; route = atom.CompletedRoute;
            RequireCompletedHistorySuccessor(before.Invite, before.Completed, invite, route);
            RequireOriginalScope(before.Package.Route, route); RequireHistoricalRoute(route, current);
            DeepIdV2ContactRouteVerifier.RequireHistoricalRouteBindings(invite, route, current,
                ContactCodec.ArtifactReference(ProtocolMagic.PMT2, route.Projection).CanonicalBytes.Span);
        }
        return new(before.Original, before.Package, invite, route, xra, threshold, pair);
    }

    internal static void RequireExactProposalOverlap(bool completed, DeepIdV2ContactRouteRecordedPair? previous,
        DeepIdV2ContactRouteRecordedPair next)
    {
        if (!completed || previous is null || !Fixed(previous.ExactRequest.Span, next.ExactRequest.Span) ||
            !Fixed(previous.ExactResponse.Span, next.ExactResponse.Span))
            throw new CryptographicException("History overlap must equal the exact previously verified proposal original.");
    }

    internal static void RequireCompletedHistorySuccessor(ParsedXir1V2 previousInvite, ParsedContactRouteClosure previous,
        ParsedXir1V2 nextInvite, ParsedContactRouteClosure next)
    {
        VerifiedDeepIdV2ContactRoutePredecessor.RequireIncrement(previousInvite.Field(3).Span, nextInvite.Field(3).Span);
        VerifiedDeepIdV2ContactRoutePredecessor.RequireIncrement(previous.Reachability.Field(3).Span, next.Reachability.Field(3).Span);
        if (!Fixed(nextInvite.Field(3).Span, next.Reachability.Field(3).Span) ||
            !Fixed(previousInvite.ObjectHash.Span, nextInvite.Field(4).Span) ||
            !Fixed(previous.Reachability.CoreHash.Span, next.Reachability.Field(4).Span) ||
            U64(next.Reachability.Field(15).Span) < U64(previous.Reachability.Field(15).Span) ||
            U64(next.Reachability.Field(17).Span) <= U64(previous.Reachability.Field(17).Span))
            throw new CryptographicException("Completed history changed its distinct XIR/XRR predecessor domains.");
        foreach (var tag in new[] { 1, 2, 5, 6, 9, 10, 11, 12, 15, 16 })
            if (!Fixed(previousInvite.Field(tag).Span, nextInvite.Field(tag).Span))
                throw new CryptographicException("Completed history changed its original reusable invite scope.");
        if (nextInvite.Field(9).Span[0] != 1) throw new CryptographicException("History requires reusable invitation policy.");
        foreach (var tag in new[] { 1, 2, 10, 12, 13, 14, 18 })
            if (!Fixed(previous.Reachability.Field(tag).Span, next.Reachability.Field(tag).Span))
                throw new CryptographicException("Completed history changed its signed recipient scope.");
    }

    internal static ParsedDeepIdV2ContactRouteHistoryAtom OriginalAtom(DeepIdV2ContactRouteRecordedPair pair,
        ReadOnlySpan<byte> invite, ReadOnlySpan<byte> closure)
    {
        var completed = !invite.IsEmpty || !closure.IsEmpty;
        if (completed && (invite.Length != 611 || closure.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes))
            throw new FormatException("Completed history requires both exact bounded originals.");
        var route = completed ? ContactRouteClosureCodec.Decode(closure) : null;
        var bytes = new byte[checked(1132 + pair.ExactResponse.Length + (completed ? 1258 + route!.Projection.CanonicalBytes.Length : 0))];
        bytes[0] = completed ? (byte)2 : (byte)1; var request = pair.Request;
        request.RequestNonce.Span.CopyTo(bytes.AsSpan(1)); BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(33), request.MinimumAdh1Generation);
        request.MinimumAdh1CoreHash.Span.CopyTo(bytes.AsSpan(41)); request.ExactDca1.Span.CopyTo(bytes.AsSpan(73));
        request.DirectoryLookupKey.Span.CopyTo(bytes.AsSpan(546)); request.ExactXra1.Span.CopyTo(bytes.AsSpan(578));
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(1128), checked((uint)pair.ExactResponse.Length)); pair.ExactResponse.Span.CopyTo(bytes.AsSpan(1132));
        if (completed)
        {
            var offset = 1132 + pair.ExactResponse.Length; invite.CopyTo(bytes.AsSpan(offset));
            route!.Reachability.CanonicalBytes.Span.CopyTo(bytes.AsSpan(offset + 611));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 1254), checked((uint)route.Projection.CanonicalBytes.Length));
            route.Projection.CanonicalBytes.Span.CopyTo(bytes.AsSpan(offset + 1258));
        }
        var result = DeepIdV2ContactRouteHistoryCodec.DecodeAtom(bytes, request.NetworkId.Span);
        if (completed && !Fixed(result.CompletedRoute.ExactBytes.Span, closure))
            throw new CryptographicException("History producer substituted its exact completed closure.");
        return result;
    }

    private static ContactRouteHistoryDmc2Payload RequireHistoryMessage(VerifiedDeepIdV2ContactRouteHistory state, ParsedDmc2 message)
    {
        if (message.ParsedPayload is not ContactRouteHistoryDmc2Payload payload || message.Flags != Dmc2Flags.None ||
            message.ReplyToLogicalMessageId.Length != 0 || message.ExpiresAtUnixMilliseconds == 0 ||
            !Fixed(message.NetworkId.Span, state.Original.NetworkId.Span) ||
            !Fixed(message.SenderAccountId.Span, state.Original.SenderAccountId.Span) ||
            !Fixed(message.SenderDeviceId.Span, state.Original.SenderDeviceId.Span) ||
            !Fixed(message.ConversationId.Span, state.Original.ConversationId.Span) ||
            !Fixed(payload.RelationshipId.Span, state.Relationship.Span) ||
            !Fixed(payload.OriginalAnchorHash.Span, state.OriginalAnchorHash.Span))
            throw new CryptographicException("History control changed its actual original relationship or peer.");
        return payload;
    }
    internal static void RequireHistoryLeft(VerifiedDeepIdV2ContactRouteHistory state, ContactRouteHistoryDmc2Payload payload)
    {
        if (!Fixed(payload.LeftCursor.Span, state.Cursor.Span) || !Fixed(payload.ExactLeftXir1V2.Span, state.Invite.CanonicalBytes.Span))
            throw new CryptographicException("History left endpoint is not the exact independently authenticated C/P source.");
    }
}
