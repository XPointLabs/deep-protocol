using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Authenticated exact retained issuance, not current route, dispatch,
/// signing, publication or ancestry authority. No caller construction path.</summary>
public sealed class VerifiedDeepIdV2ContactRouteIssuance
{
    private readonly byte[] authorityReference;
    internal VerifiedDeepIdV2ContactRouteIssuance(ContactRouteAuthorityWireRequest request,
        ParsedDeepIdV2RouteThreshold threshold, AccountDirectoryProtectedLkg head,
        ReadOnlySpan<byte> authorityReference)
    { Request = request; Threshold = threshold; IssuanceHead = head; this.authorityReference = authorityReference.ToArray(); }
    public ContactRouteAuthorityWireRequest Request { get; }
    public ParsedDeepIdV2RouteThreshold Threshold { get; }
    public ReadOnlyMemory<byte> ExactIssuanceAdh1 => IssuanceHead.ExactAdh1;
    internal AccountDirectoryProtectedLkg IssuanceHead { get; }

    internal void RequireAtCurrentContext(DeepIdV2RouteContext current)
    {
        var floor = current.Recipient.Freshness.NextProtectedLkg;
        var head = IssuanceHead.Head;
        if (!DeepIdV2RouteContext.Fixed(authorityReference, current.Authority.AuthorityCoreReference.Span) ||
            !DeepIdV2RouteContext.Fixed(head.ExactXnaAuthorityCoreReference.Span, authorityReference) ||
            !DeepIdV2RouteContext.Fixed(head.WitnessPolicyHash.Span, current.Authority.DirectoryWitnessPolicyHash.Span) ||
            !DeepIdV2RouteContext.Fixed(Request.NetworkId.Span, current.Network.NetworkId.Span) ||
            !DeepIdV2RouteContext.Fixed(Request.ExactDca1.Span, current.Recipient.Authorization.Record.CanonicalBytes.Span) ||
            !DeepIdV2RouteContext.Fixed(Request.DirectoryLookupKey.Span, current.Recipient.Freshness.QueriedDirectoryLeafKey.Span) ||
            head.LogGeneration < Request.MinimumAdh1Generation || head.LogGeneration > floor.LogGeneration ||
            (head.LogGeneration == Request.MinimumAdh1Generation &&
             !DeepIdV2RouteContext.Fixed(IssuanceHead.CoreHash.Span, Request.MinimumAdh1CoreHash.Span)) ||
            (head.LogGeneration == floor.LogGeneration &&
             !DeepIdV2RouteContext.Fixed(IssuanceHead.CoreHash.Span, floor.CoreHash.Span)))
            throw new CryptographicException("Retained route issuance differs from the exact request, current authority or verified bounds.");
        var xrc = Threshold.LiveRoute; var xss = Threshold.Successor;
        var reference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.ADH1, IssuanceHead.CoreHash.Span);
        if (!DeepIdV2RouteContext.Fixed(reference, xrc.Field(19).Span) ||
            !DeepIdV2RouteContext.Fixed(reference, xss.Field(12).Span) ||
            DeepIdV2RouteContext.U64(xrc.Field(16).Span) < head.ValidFrom ||
            DeepIdV2RouteContext.U64(xrc.Field(16).Span) >= head.ValidUntil ||
            DeepIdV2RouteContext.U64(xss.Field(10).Span) < head.ValidFrom ||
            DeepIdV2RouteContext.U64(xss.Field(10).Span) >= head.ValidUntil)
            throw new CryptographicException("Retained threshold does not bind its authenticated issuance head/time.");
        var xra = ContactCodec.Decode(ProtocolMagic.XRA1, Request.ExactXra1.Span);
        current.RequireAdvertisement(xra);
        current.RequireThreshold(xra, Threshold.Selection, xrc, xss, requireCurrentDirectory: false);
    }

    internal void RequireExactRoute(VerifiedDeepIdV2ContactRouteClosure route)
    {
        if (!DeepIdV2RouteContext.Fixed(Request.ExactDca1.Span, route.Recipient.Authorization.Record.CanonicalBytes.Span) ||
            !DeepIdV2RouteContext.Fixed(authorityReference, route.NetworkAuthority.AuthorityCoreReference.Span) ||
            !DeepIdV2RouteContext.Fixed(Request.ExactXra1.Span, route.Route.Authorization.CanonicalBytes.Span) ||
            !DeepIdV2RouteContext.Fixed(Threshold.Selection.CanonicalBytes.Span, route.Route.Selection.CanonicalBytes.Span) ||
            !DeepIdV2RouteContext.Fixed(Threshold.LiveRoute.CanonicalBytes.Span, route.Route.Route.CanonicalBytes.Span) ||
            !DeepIdV2RouteContext.Fixed(Threshold.Successor.CanonicalBytes.Span, route.Route.Successor.CanonicalBytes.Span))
            throw new CryptographicException("The completed route differs from its closed retained issuance.");
        var floor = route.Recipient.Freshness.NextProtectedLkg;
        if (IssuanceHead.LogGeneration > floor.LogGeneration ||
            (IssuanceHead.LogGeneration == floor.LogGeneration && !DeepIdV2RouteContext.Fixed(IssuanceHead.CoreHash.Span, floor.CoreHash.Span)))
            throw new CryptographicException("Retained issuance exceeds the completed route's independently verified floor.");
    }
}

public static partial class DeepIdV2ContactRouteVerifier
{
    public static async ValueTask<VerifiedDeepIdV2ContactRouteIssuance> VerifyRetainedThresholdAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ContactRouteAuthorityWireRequest exactPendingRequest,
        ParsedDeepIdV2RouteThreshold threshold, ReadOnlyMemory<byte> exactIssuanceAdh1,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority); ArgumentNullException.ThrowIfNull(exactPendingRequest);
        ArgumentNullException.ThrowIfNull(threshold); cancellationToken.ThrowIfCancellationRequested();
        if (exactIssuanceAdh1.Length is < 1 or > 4096)
            throw new CryptographicException("Retained issuance ADH1 is outside its bounded canonical size.");
        // Authenticate and own every mutable input before the first clock callback.
        var request = ContactRouteAuthorityWireCodec.DecodeRequest(ContactRouteAuthorityWireCodec.EncodeRequest(exactPendingRequest));
        var records = new ParsedDeepIdV2RouteThreshold(threshold.Selection.CanonicalBytes.Span,
            threshold.LiveRoute.CanonicalBytes.Span, threshold.Successor.CanonicalBytes.Span);
        var head = AccountDirectoryProtectedLkgFactory.Restore(authority, exactIssuanceAdh1,
            records.LiveRoute.Field(19).Span[6..]);
        if (head.Head.MinimumReader != 2)
            throw new CryptographicException("Retained DID2 issuance requires the supported directory reader generation.");
        var result = new VerifiedDeepIdV2ContactRouteIssuance(request, records, head, authority.AuthorityCoreReference.Span);
        var first = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, trustedTime, cancellationToken).ConfigureAwait(false);
        result.RequireAtCurrentContext(first);
        result.RequireAtCurrentContext(await first.RecheckAsync(cancellationToken).ConfigureAwait(false));
        cancellationToken.ThrowIfCancellationRequested(); return result;
    }
}

public static partial class DeepIdV2ContactRouteAuthor
{
    public static ValueTask<VerifiedDeepIdV2ContactRouteClosure> CompleteRetainedGenesisAsync(
        DeepIdV2CurrentContactAuthorization currentAuthorization, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority networkAuthority, OwnedGenesisDeviceSecrets deviceSecrets,
        VerifiedDeepIdV2ContactRouteIssuance issuance, ushort minimumReader,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuance);
        return CompleteCoreAsync(currentAuthorization, network, networkAuthority, deviceSecrets,
            issuance.Request.ExactXra1, issuance.Threshold, minimumReader, trustedTime, null, cancellationToken, issuance);
    }

    public static ValueTask<VerifiedDeepIdV2ContactRouteClosure> CompleteRetainedSuccessorAsync(
        DeepIdV2CurrentContactAuthorization currentAuthorization, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority networkAuthority, OwnedGenesisDeviceSecrets deviceSecrets,
        VerifiedDeepIdV2ContactRoutePredecessor predecessor, VerifiedDeepIdV2ContactRouteIssuance issuance,
        ushort minimumReader, OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor); ArgumentNullException.ThrowIfNull(issuance);
        return CompleteCoreAsync(currentAuthorization, network, networkAuthority, deviceSecrets,
            issuance.Request.ExactXra1, issuance.Threshold, minimumReader, trustedTime, predecessor, cancellationToken, issuance);
    }
}
