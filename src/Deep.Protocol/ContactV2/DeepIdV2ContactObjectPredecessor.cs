using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Authenticated immutable historical object only, not current
/// publication, dispatch, a signing service or a mailbox grant.</summary>
public sealed class VerifiedDeepIdV2ContactObjectPredecessor
{
    private readonly byte[] ciphertextHash, locator;
    internal VerifiedDeepIdV2ContactObjectPredecessor(VerifiedDeepIdV2ContactRoutePredecessor route,
        ParsedDcr1V2 closure, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> locator)
    { Route = route; Closure = closure; ciphertextHash = SHA256.HashData(ciphertext); this.locator = locator.ToArray(); }
    internal VerifiedDeepIdV2ContactRoutePredecessor Route { get; }
    public ParsedDcr1V2 Closure { get; }
    public ReadOnlyMemory<byte> CiphertextHash => ciphertextHash.ToArray();
    public ReadOnlyMemory<byte> LocatorHash => locator.ToArray();

    internal void RequireAtCurrentContext(DeepIdV2RouteContext current)
    {
        Route.RequireAtCurrentContext(current);
        DeepIdV2ContactObjectAuthor.RequireHistoricalObject(Route, Closure, current);
    }

    internal void RequireSuccessorRoute(VerifiedDeepIdV2ContactRouteClosure next,
        DeepIdV2ContactRouteTimeWindow window, CancellationToken ct)
    {
        RequireAtCurrentContext(next.VerifyContextAtWindow(window, ct));
        Route.RequireThresholdSuccessor(next.Route.Authorization,
            new(next.Route.Selection.CanonicalBytes.Span, next.Route.Route.CanonicalBytes.Span,
                next.Route.Successor.CanonicalBytes.Span));
        VerifiedDeepIdV2ContactRoutePredecessor.RequireIncrement(Route.Invite.Field(3).Span, next.Invite.Field(3).Span);
        if (!DeepIdV2RouteContext.Fixed(Route.Invite.Field(2).Span, next.Invite.Field(2).Span) ||
            !DeepIdV2RouteContext.Fixed(Route.Invite.ObjectHash.Span, next.Invite.Field(4).Span))
            throw new CryptographicException("Contact successor changed its exact reusable invite lineage.");
    }

    internal void RequireSuccessorBundle(VerifiedDeepIdV2ContactRouteClosure next, ParsedDcb1V2 bundle,
        DeepIdV2ContactRouteTimeWindow window, CancellationToken ct)
    {
        RequireSuccessorRoute(next, window, ct);
        var prior = Closure.Bundle;
        VerifiedDeepIdV2ContactRoutePredecessor.RequireIncrement(prior.Field(8).Span, bundle.Field(8).Span);
        if (!DeepIdV2RouteContext.Fixed(prior.ObjectHash.Span, bundle.Field(9).Span) ||
            DeepIdV2RouteContext.U64(bundle.Field(17).Span) < DeepIdV2RouteContext.U64(prior.Field(17).Span) ||
            DeepIdV2RouteContext.U64(bundle.Field(18).Span) <= DeepIdV2RouteContext.U64(prior.Field(18).Span))
            throw new CryptographicException("Contact successor does not advance its exact signed predecessor.");
        foreach (var tag in new[] { 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 15, 16, 22, 23, 24 })
            if (!DeepIdV2RouteContext.Fixed(prior.Field(tag).Span, bundle.Field(tag).Span))
                throw new CryptographicException("Contact successor requires separate identity, service, profile or policy rollover.");
        if (!DeepIdV2RouteContext.Fixed(bundle.Field(14).Span[40..], next.ExactXir1V2.Span) ||
            DeepIdV2RouteContext.U64(bundle.Field(8).Span) != DeepIdV2RouteContext.U64(next.Invite.Field(3).Span))
            throw new CryptographicException("Contact successor does not bind its exact current route generation.");
    }

    internal void RequireSuccessorObject(VerifiedDeepIdV2ContactRouteClosure next, ParsedDcr1V2 closure,
        DeepIdV2ContactRouteTimeWindow window, CancellationToken ct) =>
        RequireSuccessorBundle(next, closure.Bundle, window, ct);
}

public static partial class DeepIdV2ContactObjectAuthor
{
    public static ValueTask<AuthoredDeepIdV2ContactObject> AuthorRetainedSuccessorAsync(
        VerifiedDeepIdV2ContactRouteClosure route, VerifiedDeepIdV2ContactRouteIssuance issuance,
        VerifiedDeepIdV2ContactObjectPredecessor predecessor, OwnedGenesisDeviceSecrets device,
        IReadOnlyList<ParsedXps1V2> preKeyServices, string profileName,
        ReadOnlyMemory<byte> resolverReadCapability16, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuance); ArgumentNullException.ThrowIfNull(predecessor);
        return AuthorGenesisCoreAsync(route, device, preKeyServices, profileName, resolverReadCapability16,
            issuance, predecessor, cancellationToken);
    }

    public static async ValueTask<VerifiedDeepIdV2ContactObjectPredecessor> VerifyPredecessorAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, VerifiedDeepIdV2ContactRoutePredecessor predecessor,
        ReadOnlyMemory<byte> exactDcr1, ReadOnlyMemory<byte> protectedDcr1,
        ReadOnlyMemory<byte> resolverReadCapability16, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor); cancellationToken.ThrowIfCancellationRequested();
        if (resolverReadCapability16.Length != 16 || exactDcr1.Length is < 1 or > DeepIdV2ResolverClosureCodec.MaximumLength ||
            protectedDcr1.Length != exactDcr1.Length + 40)
            throw new CryptographicException("Historical object inputs exceed their exact bounds.");
        var closure = DeepIdV2ResolverClosureCodec.Decode(exactDcr1.Span);
        var cipher = protectedDcr1.ToArray(); var capability = resolverReadCapability16.ToArray();
        try
        {
            using var resolution = DeepIdV2PermanentContactResolutionDerivation.Derive(network.NetworkId.Span,
                recipient.Authorization.Binding.DeepId, capability);
            var opened = DeepIdV2ResolverObjectProtection.Open(cipher, network.NetworkId.Span,
                recipient.Authorization.Binding.DeepId, resolution);
            if (!Fixed(opened.CanonicalBytes.Span, closure.CanonicalBytes.Span))
                throw new CryptographicException("Historical ciphertext differs from its exact signed contact object.");
            var first = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, trustedTime, cancellationToken).ConfigureAwait(false);
            predecessor.RequireAtCurrentContext(first); RequireHistoricalObject(predecessor, closure, first);
            var final = await first.RecheckAsync(cancellationToken).ConfigureAwait(false);
            predecessor.RequireAtCurrentContext(final); RequireHistoricalObject(predecessor, closure, final);
            cancellationToken.ThrowIfCancellationRequested();
            return new(predecessor, closure, cipher, resolution.LocatorHash.Span);
        }
        finally { CryptographicOperations.ZeroMemory(cipher); CryptographicOperations.ZeroMemory(capability); }
    }

    internal static void RequireHistoricalObject(VerifiedDeepIdV2ContactRoutePredecessor route,
        ParsedDcr1V2 closure, DeepIdV2RouteContext current)
    {
        var bundle = closure.Bundle; var issued = U64(bundle.Field(17).Span);
        var minimumGeneration = U64(bundle.Field(21).Span);
        var floor = current.Recipient.Freshness.NextProtectedLkg;
        if (!Fixed(bundle.Field(14).Span[40..], route.ExactXir1V2.Span) ||
            !Fixed(bundle.Field(21).Span[8..], route.Route.Route.Field(19).Span[6..]) ||
            U64(bundle.Field(8).Span) != U64(route.Invite.Field(3).Span) ||
            BinaryPrimitives.ReadUInt32BigEndian(bundle.Field(16).Span) != 9 || issued > current.Lower ||
            minimumGeneration > floor.LogGeneration ||
            (minimumGeneration == floor.LogGeneration && !Fixed(bundle.Field(21).Span[8..], floor.CoreHash.Span)))
            throw new CryptographicException("Historical contact object differs from its authenticated reusable route.");
        // Original signed scope is not a current clock, proof or dispatch window.
        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(closure, current.Recipient.Authorization, issued);
    }
}
