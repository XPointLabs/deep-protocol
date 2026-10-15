using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Current owner-authenticated read of an existing original winner.
/// No witness signing, reservation, mutation, commit or noncommit authority.</summary>
public static class DeepIdV2PublicationWinnerReadAuthor
{
    public static async ValueTask<PublicationWinnerReadWireRequest> AuthorRequestAsync(
        VerifiedDeepIdV2ContactRouteClosure route, AuthoredDeepIdV2ContactObject contact,
        ContactPublicationAuthorityWireRequest original, OwnedGenesisDeviceSecrets device, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(contact);
        ArgumentNullException.ThrowIfNull(original); ArgumentNullException.ThrowIfNull(device); ct.ThrowIfCancellationRequested();
        original = ContactPublicationAuthorityWireCodec.DecodeRequest(ContactPublicationAuthorityWireCodec.EncodeRequest(original));
        contact = new(DeepIdV2ResolverClosureCodec.Decode(contact.Closure.CanonicalBytes.Span),
            contact.ProtectedDcr1.ToArray(), contact.LocatorHash.ToArray());
        await DeepIdV2PublicationCommitVerifier.VerifyOwnedPendingRequestForReadAsync(route, contact, original, ct).ConfigureAwait(false);
        var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        var nonce = new byte[32]; do RandomNumberGenerator.Fill(nonce); while (nonce.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        var signature = new byte[64]; signature[^1] = 1;
        try
        {
            var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.CoordinateContact,
                DeepIdV2PublicationWinnerReadWireCodec.GatewayShard(route.Network.NetworkId.Span, nonce));
            var floor = route.Recipient.Freshness.NextProtectedLkg;
            var expires = Ceiling(route, original, first.LowerUnixSeconds, placement);
            var candidate = DeepIdV2PublicationWinnerReadWireCodec.EncodeRequest(route.Network.NetworkId.Span, nonce,
                original.RequestNonce.Span, original.DirectoryLookupKey.Span, floor.LogGeneration, floor.CoreHash.Span,
                DeepIdV2PublicationWinnerReadWireCodec.HashOriginalRequest(original), placement.ViewHash.Span,
                first.LowerUnixSeconds, expires, signature);
            RequireRequest(route, original, candidate, first);
            CryptographicOperations.ZeroMemory(signature);
            signature = device.SignCurrentPublicationWinnerReadRequest(candidate, route.Recipient.Authorization, original);
            var signed = DeepIdV2PublicationWinnerReadWireCodec.EncodeRequest(route.Network.NetworkId.Span, nonce,
                original.RequestNonce.Span, original.DirectoryLookupKey.Span, floor.LogGeneration, floor.CoreHash.Span,
                DeepIdV2PublicationWinnerReadWireCodec.HashOriginalRequest(original), placement.ViewHash.Span,
                first.LowerUnixSeconds, expires, signature);
            await DeepIdV2PublicationCommitVerifier.VerifyOwnedPendingRequestForReadAsync(route, contact, original, ct).ConfigureAwait(false);
            var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false); Continuous(first, final);
            RequireRequest(route, original, signed, final); VerifyPublisher(route, signed);
            ct.ThrowIfCancellationRequested(); return signed;
        }
        finally { CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(signature); }
    }

    public static async ValueTask VerifyIssuerRequestAsync(VerifiedDeepIdV2IssuerPublicationIntent intent,
        PublicationWinnerReadWireRequest candidate, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(intent); ArgumentNullException.ThrowIfNull(candidate); ct.ThrowIfCancellationRequested();
        var request = DeepIdV2PublicationWinnerReadWireCodec.DecodeRequest(candidate.CanonicalBytes.Span);
        _ = await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(intent.Route, intent.OwnedRequest,
            intent.Request.CanonicalBytes, ct).ConfigureAwait(false);
        var first = await intent.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequireRequest(intent.Route, intent.OwnedRequest, request, first); VerifyPublisher(intent.Route, request);
        var final = await intent.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false); Continuous(first, final);
        RequireRequest(intent.Route, intent.OwnedRequest, request, final); ct.ThrowIfCancellationRequested();
    }

    public static async ValueTask<VerifiedDeepIdV2OwnedPublicationIntent> VerifyOwnedResponseAsync(
        VerifiedDeepIdV2ContactRouteClosure route, AuthoredDeepIdV2ContactObject contact,
        ContactPublicationAuthorityWireRequest original, PublicationWinnerReadWireRequest candidate,
        ReadOnlyMemory<byte> exactResponse, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(contact);
        ArgumentNullException.ThrowIfNull(original); ArgumentNullException.ThrowIfNull(candidate); ct.ThrowIfCancellationRequested();
        original = ContactPublicationAuthorityWireCodec.DecodeRequest(ContactPublicationAuthorityWireCodec.EncodeRequest(original));
        contact = new(DeepIdV2ResolverClosureCodec.Decode(contact.Closure.CanonicalBytes.Span),
            contact.ProtectedDcr1.ToArray(), contact.LocatorHash.ToArray());
        var request = DeepIdV2PublicationWinnerReadWireCodec.DecodeRequest(candidate.CanonicalBytes.Span);
        var response = DeepIdV2PublicationWinnerReadWireCodec.DecodeResponse(request, exactResponse.Span);
        var winner = ContactPublicationAuthorityWireCodec.DecodeResponse(original, response);
        var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequireRequest(route, original, request, first); VerifyPublisher(route, request);
        var intent = await DeepIdV2PublicationCommitVerifier.VerifyOwnedRetainedIntentAsync(route, contact, original,
            winner.ExactXpu1, ct).ConfigureAwait(false);
        var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false); Continuous(first, final);
        RequireRequest(route, original, request, final); ct.ThrowIfCancellationRequested(); return intent;
    }

    private static void RequireRequest(VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest original,
        PublicationWinnerReadWireRequest request, DeepIdV2ContactRouteTimeWindow window)
    {
        var floor = route.Recipient.Freshness.NextProtectedLkg;
        var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.CoordinateContact, request.GatewayShard);
        if (original.PublicationKind != 1 || !Fixed(request.NetworkId.Span, route.Network.NetworkId.Span) ||
            !Fixed(request.DirectoryLookupKey.Span, original.DirectoryLookupKey.Span) ||
            !Fixed(request.OriginalCoordinationNonce.Span, original.RequestNonce.Span) ||
            !Fixed(request.OriginalCoordinationRequestHash.Span, DeepIdV2PublicationWinnerReadWireCodec.HashOriginalRequest(original)) ||
            !Fixed(request.ViewHash.Span, placement.ViewHash.Span) || request.MinimumDirectoryGeneration > floor.LogGeneration ||
            (request.MinimumDirectoryGeneration == floor.LogGeneration && !Fixed(request.MinimumDirectoryHash.Span, floor.CoreHash.Span)) ||
            request.IssuedAtUnixSeconds > window.LowerUnixSeconds || window.UpperUnixSeconds >= request.ExpiresAtUnixSeconds ||
            request.ExpiresAtUnixSeconds > Ceiling(route, original, request.IssuedAtUnixSeconds, placement))
            throw new CryptographicException("Publication winner read is not exact current owned request scope.");
    }

    private static ulong Ceiling(VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest original,
        ulong start, VerifiedContactServicePlacement placement)
    {
        var proof = route.Recipient.Freshness;
        var proofCeiling = checked(proof.TrustedLowerUnixSeconds + proof.FreshnessDeadlineMonotonicSeconds - proof.MonotonicSample);
        return new[] { checked(start + 120), proofCeiling, proof.NextProtectedLkg.Head.ValidUntil, placement.ValidUntilUnixSeconds,
            route.Network.MaximumRecordExpiryUnixSeconds, route.NetworkAuthority.ExpiresAt, original.EffectiveExpiresAtUnixSeconds,
            route.Recipient.Authorization.Record.ExpiresAtUnixSeconds, U64(route.Route.Authorization.Field(13).Span),
            U64(route.Route.Selection.Field(9).Span), U64(route.Route.Route.Field(18).Span), U64(route.Route.Successor.Field(11).Span),
            U64(route.Route.Reachability.Field(17).Span) }.Min();
    }
    private static void VerifyPublisher(VerifiedDeepIdV2ContactRouteClosure route, PublicationWinnerReadWireRequest request)
    {
        var dca = route.Recipient.Authorization;
        var device = dca.Binding.Identity.ActiveDevices.Single(value => Fixed(value.Certificate.DeviceId.Span, dca.Record.PublisherDeviceId.Span));
        var input = request.SigningInput.ToArray();
        try
        {
            if (!PublicKeyAuth.VerifyDetached(request.PublisherSignature.ToArray(), input, device.Certificate.DeviceEd25519PublicKey.ToArray()))
                throw new CryptographicException("Current publisher did not sign the exact winner read request.");
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }
    private static void Continuous(DeepIdV2ContactRouteTimeWindow first, DeepIdV2ContactRouteTimeWindow final)
    {
        if (!Fixed(first.BootId.Span, final.BootId.Span) || final.MonotonicSample < first.MonotonicSample ||
            final.LowerUnixSeconds < first.LowerUnixSeconds || final.UpperUnixSeconds < first.UpperUnixSeconds)
            throw new CryptographicException("Publication winner read crossed protected clock continuity.");
    }
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
