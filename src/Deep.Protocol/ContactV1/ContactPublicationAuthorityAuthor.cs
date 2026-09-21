using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV1;

/// <summary>
/// Publisher-authenticated, verifier-bound request for one threshold XPA1.
/// The retained capabilities are process-local and are never serialized.
/// </summary>
public sealed class AuthoredContactPublicationAuthorityRequest
{
    internal AuthoredContactPublicationAuthorityRequest(
        ContactPublicationAuthorityWireRequest wireRequest,
        AuthoredPermanentContactPublication publication,
        AuthoredPermanentContactRoute route)
    {
        WireRequest = wireRequest;
        Publication = publication;
        Route = route;
    }

    public ContactPublicationAuthorityWireRequest WireRequest { get; }
    internal AuthoredPermanentContactPublication Publication { get; }
    internal AuthoredPermanentContactRoute Route { get; }

    public ValueTask<AuthoredPermanentAddressPublication> VerifyResponseAsync(
        ReadOnlyMemory<byte> exactXpu1,
        CancellationToken cancellationToken = default) =>
        ContactPublicationAuthorityVerifier.VerifyExactAsync(
            this, exactXpu1, cancellationToken);
}

public static class ContactPublicationAuthorityAuthor
{
    public static async ValueTask<AuthoredContactPublicationAuthorityRequest> AuthorAsync(
        AuthoredPermanentContactPublication publication,
        AuthoredPermanentContactRoute route,
        IContactDeviceCustodySigner signer,
        ReadOnlyMemory<byte> requestNonce,
        ReadOnlyMemory<byte> operationId,
        ReadOnlyMemory<byte> predecessorObjectHash,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        ulong effectiveExpiresAtUnixSeconds,
        ReadOnlyMemory<byte> ownerRetrieveCapability,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publication);
        ArgumentNullException.ThrowIfNull(route);
        ArgumentNullException.ThrowIfNull(signer);
        cancellationToken.ThrowIfCancellationRequested();
        var contact = publication.Verified;
        var bundle = contact.Bundle;
        var publisherDeviceId = bundle.Field(10);
        var publisher = contact.Directory.Identity.ActiveDevices.SingleOrDefault(device =>
            Fixed(device.Certificate.DeviceId.Span, publisherDeviceId.Span)) ??
            throw new ContactPublicationAuthoringException(
                "PublisherNotActive", "The permanent Contact publisher is not active.");
        if (!Fixed(signer.DeviceId.Span, publisherDeviceId.Span) ||
            !Fixed(signer.Ed25519PublicKey.Span,
                publisher.Certificate.DeviceEd25519PublicKey.Span) ||
            signer.CustodyDomainHash.Length != 32 ||
            signer.CustodyDomainHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ContactPublicationAuthoringException(
                "CustodySignerMismatch",
                "The publication custody signer does not bind the verified publisher device.");
        if (!Fixed(route.Verified.Invite.CanonicalBytes.Span,
                bundle.Field(14).Span.Slice(40, 611)) ||
            !Fixed(route.ExactRouteClosure.Span,
                ContactRouteClosureCodec.Encode(route.Verified)) ||
            !Fixed(route.Verified.Authority.NetworkId.Span, bundle.Field(1).Span))
            throw new ContactPublicationAuthoringException(
                "PublicationRouteMismatch",
                "The publication and route do not share one verified Contact closure.");
        var ciphertextHash = SHA256.HashData(publication.ProtectedDcr1.Span);
        var routeHash = SHA256.HashData(route.ExactRouteClosure.Span);
        var signingInput = Xpa1PublicationAuthorizationAuthor.CreatePublisherSigningInput(
            publication.LocatorHash.Span,
            contact.ResolverResponse.ArtifactHash.Span,
            ciphertextHash,
            routeHash,
            publication.Generation,
            predecessorObjectHash.Span,
            effectiveExpiresAtUnixSeconds,
            ownerRetrieveCapability.Span);
        var signature = new byte[64];
        var signingRequest = new ContactDeviceSigningRequest(
            ContactDeviceSignaturePurpose.PermanentAddressPublication,
            bundle.Field(1).Span,
            bundle.Field(2).Span,
            publisherDeviceId.Span,
            signer.CustodyDomainHash.Span,
            signingInput);
        try
        {
            var written = await signer.SignAsync(
                signingRequest, signature, cancellationToken).ConfigureAwait(false);
            if (written != signature.Length ||
                signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !PublicKeyAuth.VerifyDetached(
                    signature, signingInput,
                    publisher.Certificate.DeviceEd25519PublicKey.ToArray()))
                throw new ContactPublicationAuthoringException(
                    "InvalidCustodySignature",
                    "The custody signer returned an invalid publication signature.");
            var freshness = contact.Freshness;
            var wire = new ContactPublicationAuthorityWireRequest(
                bundle.Field(1).Span,
                requestNonce.Span,
                freshness.DirectoryLeafKey.Span,
                freshness.AdhGeneration,
                freshness.ExactAdh1CoreHash.Span,
                contact.Authorization.Verified.Record.CanonicalBytes.Span,
                contact.ResolverResponse.CanonicalBytes.Span,
                route.ExactRouteClosure.Span,
                operationId.Span,
                publication.Generation,
                predecessorObjectHash.Span,
                publication.ProtectedDcr1.Span,
                issuedAtUnixSeconds,
                expiresAtUnixSeconds,
                effectiveExpiresAtUnixSeconds,
                ownerRetrieveCapability.Span,
                signature);
            return new AuthoredContactPublicationAuthorityRequest(wire, publication, route);
        }
        finally
        {
            signingRequest.Clear();
            CryptographicOperations.ZeroMemory(signature);
            CryptographicOperations.ZeroMemory(signingInput);
            CryptographicOperations.ZeroMemory(ciphertextHash);
            CryptographicOperations.ZeroMemory(routeHash);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public static class ContactPublicationAuthorityVerifier
{
    public static async ValueTask<AuthoredPermanentAddressPublication> VerifyExactAsync(
        AuthoredContactPublicationAuthorityRequest authoredRequest,
        ReadOnlyMemory<byte> exactXpu1,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authoredRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var wire = authoredRequest.WireRequest;
        var publication = authoredRequest.Publication;
        var route = authoredRequest.Route.Verified;
        try
        {
            var request = Xpu1Codec.Decode(exactXpu1.Span);
            if (!Fixed(request.NetworkId.Span, wire.NetworkId.Span) ||
                !Fixed(request.OperationId.Span, wire.OperationId.Span) ||
                request.Generation != wire.Generation ||
                !Fixed(request.PredecessorObjectHash.Span,
                    wire.PredecessorObjectHash.Span) ||
                !Fixed(request.ObjectCiphertext.Span, wire.ObjectCiphertext.Span) ||
                request.IssuedAtUnixSeconds != wire.IssuedAtUnixSeconds ||
                request.ExpiresAtUnixSeconds != wire.ExpiresAtUnixSeconds ||
                request.EffectiveExpiresAtUnixSeconds != wire.EffectiveExpiresAtUnixSeconds ||
                !Fixed(request.OwnerRetrieveCapability.Span,
                    wire.OwnerRetrieveCapability.Span) ||
                !Fixed(request.ExactRouteClosure.Span, wire.ExactRouteClosure.Span) ||
                !Fixed(request.LocatorHash.Span, publication.LocatorHash.Span) ||
                !Fixed(request.Xir1Hash.Span, route.Invite.ArtifactHash.Span))
                throw new Xpa1PublicationAuthorizationException(
                    "PublicationResponseMismatch",
                    "The exact XPU1 response does not bind the publisher-authored request.");
            var authority = route.Authority;
            var placement = ContactServicePlacementFactory.Create(
                authority.SourceNetwork,
                ContactServiceRequestKind.PublishInvite,
                publication.LocatorHash);
            var verified = await Xpa1PublicationAuthorizationVerifier.VerifyAsync(
                request,
                authority.SourceAuthority,
                authority.SourceFreshness,
                placement,
                authority.SourceTrustedTimeAuthority,
                cancellationToken).ConfigureAwait(false);
            return new AuthoredPermanentAddressPublication(
                request.ExactXpa1.Span,
                request,
                verified,
                authority.RecipientAccountId.Span);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Xpa1PublicationAuthorizationException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or
            CryptographicException or InvalidOperationException or OverflowException)
        {
            throw new Xpa1PublicationAuthorizationException(
                "InvalidPublicationAuthorityResponse",
                "The exact XPU1 publication-authority response failed closed.",
                exception);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
