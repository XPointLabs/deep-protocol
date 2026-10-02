using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

internal interface IVerifiedDeepIdV2PublicationLineage
{
    void RequireSuccessor(VerifiedDeepIdV2ContactRouteClosure next,
        ContactPublicationAuthorityWireRequest request, DeepIdV2ContactRouteTimeWindow window, CancellationToken ct);
}

/// <summary>Authenticated issuer-side signed history and both replica receipts.
/// Not client decryption evidence, current dispatch, signing or reservation authority.</summary>
public sealed class VerifiedDeepIdV2PublicationIssuerPredecessor : IVerifiedDeepIdV2PublicationLineage
{
    private readonly VerifiedDeepIdV2ContactRoutePredecessor route;
    private readonly ParsedDcr1V2 closure;
    private readonly ContactPublicationAuthorityWireRequest owned;
    private readonly Xpu1Request request;
    private readonly Xpo1Result result;

    internal VerifiedDeepIdV2PublicationIssuerPredecessor(VerifiedDeepIdV2ContactRoutePredecessor route,
        ParsedDcr1V2 closure, ContactPublicationAuthorityWireRequest owned, Xpu1Request request, Xpo1Result result)
    { this.route = route; this.closure = closure; this.owned = owned; this.request = request; this.result = result; }

    public ulong Generation => owned.Generation;

    internal void RequireAtCurrentContext(DeepIdV2RouteContext current) =>
        DeepIdV2PublicationCommitVerifier.RequireHistoricalPublication(route, closure, owned, request, result, current);

    void IVerifiedDeepIdV2PublicationLineage.RequireSuccessor(VerifiedDeepIdV2ContactRouteClosure next,
        ContactPublicationAuthorityWireRequest candidate, DeepIdV2ContactRouteTimeWindow window, CancellationToken ct)
    {
        RequireAtCurrentContext(next.VerifyContextAtWindow(window, ct));
        DeepIdV2ContactObjectLineage.RequireSuccessorRoute(route, next);
        DeepIdV2ContactObjectLineage.RequireSuccessorBundle(closure.Bundle, next,
            DeepIdV2ResolverClosureCodec.Decode(candidate.ExactDcr1.Span).Bundle);
        DeepIdV2PublicationCommitVerifier.RequirePublicationSuccessor(owned, result, candidate);
    }
}

public static partial class DeepIdV2PublicationCommitVerifier
{
    /// <summary>Authenticates signed publisher history and replicas without a resolver capability.
    /// Does not verify ciphertext/plaintext equivalence and cannot mint client object evidence.</summary>
    public static async ValueTask<VerifiedDeepIdV2PublicationIssuerPredecessor> VerifyIssuerPredecessorAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ContactPublicationAuthorityWireRequest ownedRequest,
        ReadOnlyMemory<byte> exactXpu1, ReadOnlyMemory<byte> exactXpo1,
        OnionTrustedTimeAuthority time, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(ownedRequest); ct.ThrowIfCancellationRequested();
        if (exactXpu1.Length is < DeepIdV2ContactPublicationCodec.MinimumXpuLength or > DeepIdV2ContactPublicationCodec.MaximumXpuLength ||
            exactXpo1.Length is < 256 or > MaximumResultBytes)
            throw new CryptographicException("Issuer publication history exceeds its exact bounds.");
        // All parsed records own their input before any clock callback.
        var owned = ContactPublicationAuthorityWireCodec.DecodeRequest(ContactPublicationAuthorityWireCodec.EncodeRequest(ownedRequest));
        var closure = DeepIdV2ResolverClosureCodec.Decode(owned.ExactDcr1.Span);
        var request = Xpu1Codec.Decode(exactXpu1.Span);
        var result = Xpo1Codec.Decode(exactXpo1.Span, request.CanonicalBytes.Span);
        ContactPublicationAuthorityWireCodec.RequireExactBody(owned, request.CanonicalBytes.Span);
        var route = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(recipient, network, authority,
            closure.Bundle.Field(14).Slice(40), owned.ExactRouteClosure, time, ct).ConfigureAwait(false);
        var predecessor = new VerifiedDeepIdV2PublicationIssuerPredecessor(route, closure, owned, request, result);
        var first = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, time, ct).ConfigureAwait(false);
        predecessor.RequireAtCurrentContext(first);
        predecessor.RequireAtCurrentContext(await first.RecheckAsync(ct).ConfigureAwait(false));
        ct.ThrowIfCancellationRequested(); return predecessor;
    }
}

public static partial class DeepIdV2PublicationAuthorityAuthor
{
    public static ValueTask VerifyIssuerSuccessorRequestAsync(VerifiedDeepIdV2ContactRouteClosure route,
        ContactPublicationAuthorityWireRequest request, VerifiedDeepIdV2PublicationIssuerPredecessor predecessor,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor);
        return VerifyRequestCoreAsync(route, request, predecessor, ct);
    }

    public static ValueTask<VerifiedDeepIdV2PublicationAuthorization> AuthorIssuerThresholdSuccessorAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest request,
        VerifiedDeepIdV2PublicationIssuerPredecessor predecessor,
        IReadOnlyList<IXpa1PublicationAuthorizationWitnessSigner> witnesses, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor);
        return AuthorThresholdCoreAsync(route, request, witnesses, predecessor, ct);
    }

    public static ValueTask<VerifiedDeepIdV2PublicationAuthorization> VerifyIssuerSuccessorResponseAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest request,
        VerifiedDeepIdV2PublicationIssuerPredecessor predecessor, ReadOnlyMemory<byte> exactXpu1, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor);
        return VerifyResponseCoreAsync(route, request, exactXpu1, predecessor, ct);
    }
}
