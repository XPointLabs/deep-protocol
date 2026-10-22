using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

public sealed partial class VerifiedMailboxHostAuthorityV2
{
    /// <summary>Authenticates original signed Retrieve facts through current
    /// protected history. Returns no live grant, dispatch, expiry closure,
    /// absence, result materialization or deletion authority.</summary>
    public async ValueTask RequireOriginalRetainedReadGrantAsync(
        ReadOnlyMemory<byte> exactOriginalPma2, ReadOnlyMemory<byte> exactOriginalRoute,
        ReadOnlyMemory<byte> exactXmg2, ReadOnlyMemory<byte> exactXmc2,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (exactOriginalPma2.Length is < 497 or > 1_169 || exactXmg2.Length != 435 || exactXmc2.Length != 510)
            throw new CryptographicException("Original Retrieve evidence exceeds its exact bounds.");
        // All caller-owned bytes are captured before the first clock callback.
        var policy = ContactCodec.Decode(ProtocolMagic.PMA2, exactOriginalPma2.Span);
        var route = CaptureRetainedRoute(exactOriginalRoute);
        var request = ContactCodec.Decode(ProtocolMagic.XMG2, exactXmg2.Span);
        var response = ContactCodec.Decode(ProtocolMagic.XMC2, exactXmc2.Span);
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(response.Field(8).Span);
        await RequireOriginalReadNamespacesAsync(policy, route.Projection, cancellationToken).ConfigureAwait(false);
        RequireRetainedRouteScope(request, route, RetainedRouteHorizonCeiling(route));
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        ContactCodec.ValidateMailboxGrantResultBinding(request, response);
        ContactCodec.ValidateMailboxGrantResultRouteBinding(response, route);
        var issuer = policy.Field(6);
        var start = BinaryPrimitives.ReadUInt64BigEndian(request.Field(9).Span);
        var expiry = BinaryPrimitives.ReadUInt64BigEndian(request.Field(10).Span);
        var issued = BinaryPrimitives.ReadUInt64BigEndian(response.Field(4).Span);
        var ceiling = Math.Min(BinaryPrimitives.ReadUInt64BigEndian(policy.Field(12).Span),
            RetainedRouteHorizonCeiling(route));
        if (grant.Domain != MailboxCapabilityDomain.Retrieve || grant.Lifecycle != MailboxCapabilityLifecycle.Active ||
            !Fixed(grant.NetworkId.Span, network.NetworkId.Span) ||
            !Fixed(grant.IssuerPublicKey.Span, issuer.Span) ||
            !Fixed(grant.HolderPublicKey.Span, request.Field(5).Span) ||
            !Fixed(grant.MembershipCommitment.Span, route.Projection.ArtifactHash.Span) ||
            grant.Epoch != BinaryPrimitives.ReadUInt64BigEndian(route.Selection.Field(4).Span) ||
            !Fixed(grant.SelectionInput.Span, route.Selection.Field(3).Span) ||
            !Fixed(grant.PlacementCommitment.Span, MailboxPlacementCommitment.Compute(new(route.Reachability.Field(10).Span))) ||
            grant.Generation < BinaryPrimitives.ReadUInt64BigEndian(policy.Field(7).Span) ||
            grant.NotBeforeUnixSeconds < Math.Max(start, BinaryPrimitives.ReadUInt64BigEndian(policy.Field(11).Span)) ||
            grant.ExpiresAtUnixSeconds > ceiling ||
            grant.ExpiresAtUnixSeconds - grant.NotBeforeUnixSeconds > BinaryPrimitives.ReadUInt32BigEndian(policy.Field(8).Span) ||
            expiry <= start || expiry - start > 120 ||
            BinaryPrimitives.ReadUInt64BigEndian(response.Field(6).Span) != expiry ||
            issued < grant.NotBeforeUnixSeconds || issued < start || issued >= expiry || issued >= grant.ExpiresAtUnixSeconds ||
            !PublicKeyAuth.VerifyDetached(grant.IssuerSignature.ToArray(),
                MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant), issuer.ToArray()))
            throw new CryptographicException("Original Retrieve differs from its signed policy/request/route interval.");
        _ = await ReadAsync(cancellationToken).ConfigureAwait(false);
        await RequireOriginalReadNamespacesAsync(policy, route.Projection, cancellationToken).ConfigureAwait(false);
        RequireRetainedRouteScope(request, route, RetainedRouteHorizonCeiling(route));
        cancellationToken.ThrowIfCancellationRequested();
    }

    // Original issuance and original assignment can name different signed
    // PMA2 generations. Both exact joins must independently authenticate in
    // THIS current protected history. No raw-record or current-issuer fallback.
    private async ValueTask RequireOriginalReadNamespacesAsync(ContactRecord issuance,
        ContactRecord originalProjection, CancellationToken cancellationToken)
    {
        var issuanceReference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.PMA2, issuance.CoreHash.Span);
        if (Fixed(originalProjection.Field(4).Span, issuanceReference))
        {
            await RequireOriginalNamespaceAsync(issuance.CanonicalBytes, originalProjection.CanonicalBytes, cancellationToken).ConfigureAwait(false);
            return;
        }
        var issuanceProjection = network.Closure!.RetainedPmts.FirstOrDefault(candidate =>
            Fixed(candidate.Field(4).Span, issuanceReference)) ??
            throw new CryptographicException("Original Retrieve issuance policy is absent from exact protected projection history.");
        var routePolicy = issuerHistory.FirstOrDefault(candidate =>
            Fixed(XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.PMA2, candidate.CoreHash.Span), originalProjection.Field(4).Span)) ??
            throw new CryptographicException("Original Retrieve assignment policy is absent from authenticated issuer history.");
        await RequireOriginalNamespaceAsync(issuance.CanonicalBytes, issuanceProjection.CanonicalBytes, cancellationToken).ConfigureAwait(false);
        await RequireOriginalNamespaceAsync(routePolicy.CanonicalBytes, originalProjection.CanonicalBytes, cancellationToken).ConfigureAwait(false);
    }
}
