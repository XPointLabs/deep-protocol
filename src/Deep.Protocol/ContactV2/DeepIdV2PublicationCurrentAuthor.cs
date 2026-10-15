using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Current publisher authority over exact immutable reusable intent.
/// Not a journal winner, replica commitment or permission to replace a fence.</summary>
public sealed class VerifiedDeepIdV2PublicationSubmission
{
    internal VerifiedDeepIdV2PublicationSubmission(VerifiedDeepIdV2ContactRouteClosure route,
        PublicationCurrentWireRequest request, VerifiedDeepIdV2PublicationIssuerPredecessor? predecessor)
    { Route = route; Request = request; Predecessor = predecessor; }
    internal VerifiedDeepIdV2ContactRouteClosure Route { get; }
    internal PublicationCurrentWireRequest Request { get; }
    internal VerifiedDeepIdV2PublicationIssuerPredecessor? Predecessor { get; }
}

/// <summary>One fresh publisher-signed submission for initial, pending and
/// completed reusable intents. No caller time, signing-purpose or reset switch.</summary>
public static partial class DeepIdV2PublicationCurrentAuthor
{
    public static async ValueTask<PublicationCurrentWireRequest> AuthorOwnedRequestAsync(
        VerifiedDeepIdV2ContactRouteClosure route, AuthoredDeepIdV2ContactObject contact,
        ContactPublicationAuthorityWireRequest candidate, OwnedGenesisDeviceSecrets device, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(contact);
        ArgumentNullException.ThrowIfNull(candidate); ArgumentNullException.ThrowIfNull(device); ct.ThrowIfCancellationRequested();
        var original = CaptureOriginal(candidate);
        contact = new(DeepIdV2ResolverClosureCodec.Decode(contact.Closure.CanonicalBytes.Span),
            contact.ProtectedDcr1.ToArray(), contact.LocatorHash.ToArray());
        await DeepIdV2PublicationCommitVerifier.VerifyOwnedPendingRequestAsync(route, contact, original, ct).ConfigureAwait(false);
        var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        var nonce = new byte[32]; do RandomNumberGenerator.Fill(nonce); while (nonce.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        var signature = new byte[64]; signature[^1] = 1;
        try
        {
            var floor = route.Recipient.Freshness.NextProtectedLkg;
            var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite, original.LocatorHash);
            var expiry = CurrentCeiling(route, original, first.LowerUnixSeconds, nonce);
            var request = DeepIdV2PublicationCurrentWireCodec.EncodeRequest(route.Network.NetworkId.Span, nonce,
                original.DirectoryLookupKey.Span, floor.LogGeneration, floor.CoreHash.Span, placement.ViewHash.Span,
                first.LowerUnixSeconds, expiry, original, signature);
            RequireCurrentScope(route, request, first);
            CryptographicOperations.ZeroMemory(signature);
            signature = device.SignCurrentPublicationSubmission(request, route.Recipient.Authorization, original);
            var signed = DeepIdV2PublicationCurrentWireCodec.EncodeRequest(route.Network.NetworkId.Span, nonce,
                original.DirectoryLookupKey.Span, floor.LogGeneration, floor.CoreHash.Span, placement.ViewHash.Span,
                first.LowerUnixSeconds, expiry, original, signature);
            await DeepIdV2PublicationCommitVerifier.VerifyOwnedPendingRequestAsync(route, contact, original, ct).ConfigureAwait(false);
            var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false); RequireContinuous(first, final);
            RequireCurrentScope(route, signed, final); VerifyCurrentPublisher(route, signed);
            ct.ThrowIfCancellationRequested(); return signed;
        }
        finally { CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(signature); }
    }

    public static async ValueTask<VerifiedDeepIdV2PublicationSubmission> VerifyIssuerRequestAsync(
        VerifiedDeepIdV2ContactRouteClosure route, PublicationCurrentWireRequest candidate,
        VerifiedDeepIdV2PublicationIssuerPredecessor? predecessor = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(candidate); ct.ThrowIfCancellationRequested();
        var request = DeepIdV2PublicationCurrentWireCodec.DecodeRequest(candidate.CanonicalBytes.Span);
        var submission = new VerifiedDeepIdV2PublicationSubmission(route, request, predecessor);
        await RecheckIssuerSubmissionAsync(submission, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); return submission;
    }

    public static async ValueTask<VerifiedXpa1PublicationAuthorization> VerifyOwnedResponseAsync(
        VerifiedDeepIdV2ContactRouteClosure route, AuthoredDeepIdV2ContactObject contact,
        ContactPublicationAuthorityWireRequest candidate, PublicationCurrentWireRequest currentRequest,
        ReadOnlyMemory<byte> exactResponse, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(contact);
        ArgumentNullException.ThrowIfNull(candidate); ArgumentNullException.ThrowIfNull(currentRequest); ct.ThrowIfCancellationRequested();
        var original = CaptureOriginal(candidate);
        contact = new(DeepIdV2ResolverClosureCodec.Decode(contact.Closure.CanonicalBytes.Span),
            contact.ProtectedDcr1.ToArray(), contact.LocatorHash.ToArray());
        var request = DeepIdV2PublicationCurrentWireCodec.DecodeRequest(currentRequest.CanonicalBytes.Span);
        RequireSameOriginal(original, request.OriginalRequest);
        var lease = DeepIdV2PublicationCurrentWireCodec.DecodeResponse(request, exactResponse.Span);
        var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequireCurrentScope(route, request, first); VerifyCurrentPublisher(route, request);
        _ = await DeepIdV2PublicationCommitVerifier.VerifyOwnedRetainedIntentAsync(route, contact, original,
            lease.OriginalRequest.CanonicalBytes, ct).ConfigureAwait(false);
        var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite, original.LocatorHash);
        var authorization = await DeepIdV2PublicationLeaseVerifier.VerifyAsync(lease, route.NetworkAuthority,
            route.Recipient.Freshness, placement, route.TrustedPublicationTime, ct).ConfigureAwait(false);
        var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false); RequireContinuous(first, final);
        RequireCurrentScope(route, request, final);
        ct.ThrowIfCancellationRequested(); return authorization;
    }

    private static async ValueTask RecheckIssuerSubmissionAsync(VerifiedDeepIdV2PublicationSubmission submission, CancellationToken ct)
    {
        var route = submission.Route; var request = submission.Request;
        await DeepIdV2PublicationCommitVerifier.VerifyIssuerPendingRequestAsync(route, request.OriginalRequest,
            submission.Predecessor, ct).ConfigureAwait(false);
        var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequireCurrentScope(route, request, first); VerifyCurrentPublisher(route, request);
        var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false); RequireContinuous(first, final);
        RequireCurrentScope(route, request, final); ct.ThrowIfCancellationRequested();
    }

    private static void RequireCurrentScope(VerifiedDeepIdV2ContactRouteClosure route, PublicationCurrentWireRequest request,
        DeepIdV2ContactRouteTimeWindow current)
    {
        var original = request.OriginalRequest; var floor = route.Recipient.Freshness.NextProtectedLkg;
        var publication = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite, original.LocatorHash);
        var gateway = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.CoordinateContact, request.GatewayShard);
        if (!Fixed(request.NetworkId.Span, route.Network.NetworkId.Span) ||
            !Fixed(original.ExactDca1.Span, route.Recipient.Authorization.Record.CanonicalBytes.Span) ||
            !Fixed(request.DirectoryLookupKey.Span, route.Recipient.Freshness.QueriedDirectoryLeafKey.Span) ||
            !Fixed(request.ViewHash.Span, publication.ViewHash.Span) || !Fixed(request.ViewHash.Span, gateway.ViewHash.Span) ||
            request.MinimumDirectoryGeneration < original.MinimumAdh1Generation ||
            (request.MinimumDirectoryGeneration == original.MinimumAdh1Generation && !Fixed(request.MinimumDirectoryHash.Span, original.MinimumAdh1CoreHash.Span)) ||
            request.MinimumDirectoryGeneration > floor.LogGeneration ||
            (request.MinimumDirectoryGeneration == floor.LogGeneration && !Fixed(request.MinimumDirectoryHash.Span, floor.CoreHash.Span)) ||
            request.IssuedAtUnixSeconds > current.LowerUnixSeconds || current.UpperUnixSeconds >= request.ExpiresAtUnixSeconds ||
            request.ExpiresAtUnixSeconds > CurrentCeiling(route, original, request.IssuedAtUnixSeconds, request.RequestNonce.Span))
            throw new CryptographicException("Current publication does not bind exact live owner, original intent and carriage authority.");
    }

    private static ulong CurrentCeiling(VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest original,
        ulong start, ReadOnlySpan<byte> nonce)
    {
        var proof = route.Recipient.Freshness;
        var publication = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite, original.LocatorHash);
        var gateway = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.CoordinateContact,
            DeepIdV2PublicationCurrentWireCodec.GatewayShard(route.Network.NetworkId.Span, nonce));
        var proofCeiling = checked(proof.TrustedLowerUnixSeconds + proof.FreshnessDeadlineMonotonicSeconds - proof.MonotonicSample);
        return new[] { checked(start + 120), proofCeiling, proof.NextProtectedLkg.Head.ValidUntil,
            publication.ValidUntilUnixSeconds, gateway.ValidUntilUnixSeconds, route.Network.MaximumRecordExpiryUnixSeconds,
            route.NetworkAuthority.ExpiresAt, original.EffectiveExpiresAtUnixSeconds, route.Recipient.Authorization.Record.ExpiresAtUnixSeconds,
            U64(route.Route.Authorization.Field(13).Span), U64(route.Route.Selection.Field(9).Span),
            U64(route.Route.Route.Field(18).Span), U64(route.Route.Successor.Field(11).Span), U64(route.Route.Reachability.Field(17).Span) }.Min();
    }

    private static void VerifyCurrentPublisher(VerifiedDeepIdV2ContactRouteClosure route, PublicationCurrentWireRequest request)
    {
        var dca = route.Recipient.Authorization;
        var device = dca.Binding.Identity.ActiveDevices.Single(value => Fixed(value.Certificate.DeviceId.Span, dca.Record.PublisherDeviceId.Span));
        var input = request.SigningInput.ToArray();
        try
        {
            if (!PublicKeyAuth.VerifyDetached(request.PublisherSignature.ToArray(), input, device.Certificate.DeviceEd25519PublicKey.ToArray()))
                throw new CryptographicException("Current publisher did not sign the exact complete publication submission.");
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }
    private static ContactPublicationAuthorityWireRequest CaptureOriginal(ContactPublicationAuthorityWireRequest original)
    {
        var exact = ContactPublicationAuthorityWireCodec.EncodeRequest(original);
        try { return ContactPublicationAuthorityWireCodec.DecodeRequest(exact); }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }
    private static void RequireSameOriginal(ContactPublicationAuthorityWireRequest left, ContactPublicationAuthorityWireRequest right)
    {
        var a = ContactPublicationAuthorityWireCodec.EncodeRequest(left); var b = ContactPublicationAuthorityWireCodec.EncodeRequest(right);
        try { if (!Fixed(a, b)) throw new CryptographicException("Current publication replaced the exact original publisher intent."); }
        finally { CryptographicOperations.ZeroMemory(a); CryptographicOperations.ZeroMemory(b); }
    }
    private static void RequireContinuous(DeepIdV2ContactRouteTimeWindow first, DeepIdV2ContactRouteTimeWindow final)
    {
        if (!Fixed(first.BootId.Span, final.BootId.Span) || final.MonotonicSample < first.MonotonicSample ||
            final.LowerUnixSeconds < first.LowerUnixSeconds || final.UpperUnixSeconds < first.UpperUnixSeconds)
            throw new CryptographicException("Current publication crossed protected clock continuity.");
    }
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
