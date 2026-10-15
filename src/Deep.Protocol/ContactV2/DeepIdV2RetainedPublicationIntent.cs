using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Authenticated original owned intent under an independently live
/// route/object. Not commit, noncommit, signing, dispatch or fence authority.</summary>
public sealed class VerifiedDeepIdV2OwnedPublicationIntent
{
    internal VerifiedDeepIdV2OwnedPublicationIntent(VerifiedDeepIdV2ContactRouteClosure route,
        AuthoredDeepIdV2ContactObject contact, ContactPublicationAuthorityWireRequest owned, Xpu1Request request)
    { Route = route; Contact = contact; OwnedRequest = owned; Request = request; }

    public ulong Generation => Request.Generation;
    public ReadOnlyMemory<byte> RequestHash => Request.RequestHash.ToArray();
    internal VerifiedDeepIdV2ContactRouteClosure Route { get; }
    internal AuthoredDeepIdV2ContactObject Contact { get; }
    internal ContactPublicationAuthorityWireRequest OwnedRequest { get; }
    internal Xpu1Request Request { get; }
}

/// <summary>Authenticated signed publisher intent, without client decryption
/// evidence. Not a journal winner, commit, signing or mutation authority.</summary>
public sealed class VerifiedDeepIdV2IssuerPublicationIntent
{
    internal VerifiedDeepIdV2IssuerPublicationIntent(VerifiedDeepIdV2ContactRouteClosure route,
        ContactPublicationAuthorityWireRequest owned, Xpu1Request request)
    { Route = route; OwnedRequest = owned; Request = request; }

    public ulong Generation => Request.Generation;
    public ReadOnlyMemory<byte> RequestHash => Request.RequestHash.ToArray();
    internal VerifiedDeepIdV2ContactRouteClosure Route { get; }
    internal ContactPublicationAuthorityWireRequest OwnedRequest { get; }
    internal Xpu1Request Request { get; }
}

public static partial class DeepIdV2PublicationCommitVerifier
{
    // Read precondition only. This cannot provide original XPA, commitment or
    // dispatch authority before the independently authenticated winner returns.
    internal static async ValueTask VerifyOwnedPendingRequestForReadAsync(
        VerifiedDeepIdV2ContactRouteClosure route, AuthoredDeepIdV2ContactObject contact,
        ContactPublicationAuthorityWireRequest candidate, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(contact);
        ArgumentNullException.ThrowIfNull(candidate); ct.ThrowIfCancellationRequested();
        var owned = CopyRetainedIntentRequest(candidate);
        var captured = new PublicationObject(DeepIdV2ResolverClosureCodec.Decode(contact.Closure.CanonicalBytes.Span),
            contact.ProtectedDcr1.ToArray(), contact.LocatorHash.ToArray(), new byte[16], 1);
        var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequirePendingOwnedRequest(route, captured, owned);
        RequireCurrentObject(route, captured, owned, first);
        var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        if (!Fixed(first.BootId.Span, final.BootId.Span) || final.MonotonicSample < first.MonotonicSample ||
            final.LowerUnixSeconds < first.LowerUnixSeconds || final.UpperUnixSeconds < first.UpperUnixSeconds)
            throw new CryptographicException("Publication winner read crossed protected time continuity.");
        RequireCurrentObject(route, captured, owned, final); ct.ThrowIfCancellationRequested();
    }

    private static void RequirePendingOwnedRequest(VerifiedDeepIdV2ContactRouteClosure route,
        PublicationObject contact, ContactPublicationAuthorityWireRequest owned)
    {
        var dca = route.Recipient.Authorization; var bundle = contact.Closure.Bundle;
        var minimum = bundle.Field(21).Span;
        if (owned.PublicationKind != 1 || !Fixed(owned.NetworkId.Span, route.Network.NetworkId.Span) ||
            !Fixed(owned.ExactDca1.Span, dca.Record.CanonicalBytes.Span) ||
            !Fixed(owned.DirectoryLookupKey.Span, route.Recipient.Freshness.QueriedDirectoryLeafKey.Span) ||
            !Fixed(owned.ExactDcr1.Span, contact.Closure.CanonicalBytes.Span) ||
            !Fixed(owned.ObjectCiphertext.Span, contact.ProtectedDcr1.Span) ||
            !Fixed(owned.ExactRouteClosure.Span, route.ExactRouteClosure.Span) ||
            !Fixed(bundle.Field(14).Span[40..], route.ExactXir1V2.Span) ||
            !Fixed(owned.LocatorHash.Span, contact.LocatorHash.Span) ||
            owned.Generation != BinaryPrimitives.ReadUInt64BigEndian(bundle.Field(8).Span) ||
            owned.Generation != BinaryPrimitives.ReadUInt64BigEndian(route.Invite.Field(3).Span) ||
            route.Invite.Field(9).Span[0] != 1 || BinaryPrimitives.ReadUInt32BigEndian(bundle.Field(16).Span) != 9 ||
            BinaryPrimitives.ReadUInt32BigEndian(route.Invite.Field(10).Span) != 0 ||
            owned.MinimumAdh1Generation != BinaryPrimitives.ReadUInt64BigEndian(minimum) ||
            !Fixed(owned.MinimumAdh1CoreHash.Span, minimum[8..]) ||
            owned.IssuedAtUnixSeconds < BinaryPrimitives.ReadUInt64BigEndian(bundle.Field(17).Span) ||
            owned.ExpiresAtUnixSeconds <= owned.IssuedAtUnixSeconds || owned.ExpiresAtUnixSeconds - owned.IssuedAtUnixSeconds > 120 ||
            owned.ExpiresAtUnixSeconds > owned.EffectiveExpiresAtUnixSeconds ||
            owned.ExpiresAtUnixSeconds > BinaryPrimitives.ReadUInt64BigEndian(bundle.Field(18).Span))
            throw new CryptographicException("Publication winner read differs from exact owned reusable request custody.");
        var device = dca.Binding.Identity.ActiveDevices.Single(value =>
            Fixed(value.Certificate.DeviceId.Span, dca.Record.PublisherDeviceId.Span));
        var input = ContactPublicationAuthorityWireCodec.CreatePublisherSigningInput(owned);
        try
        {
            if (!Sodium.PublicKeyAuth.VerifyDetached(owned.PublisherSignature.ToArray(), input,
                device.Certificate.DeviceEd25519PublicKey.ToArray()))
                throw new CryptographicException("Original publication request publisher signature is invalid.");
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    /// <summary>Authenticates exact original intent without inventing replica
    /// receipts or renewing its expired request/XPA. Current reusable object
    /// custody and route remain mandatory.</summary>
    public static async ValueTask<VerifiedDeepIdV2OwnedPublicationIntent> VerifyOwnedRetainedIntentAsync(
        VerifiedDeepIdV2ContactRouteClosure route, AuthoredDeepIdV2ContactObject contact,
        ContactPublicationAuthorityWireRequest ownedRequest, ReadOnlyMemory<byte> exactXpu1,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(contact);
        RequireRetainedIntentBounds(ownedRequest, exactXpu1, ct);
        // Capture every input before the route's first external clock callback.
        var ownedContact = new AuthoredDeepIdV2ContactObject(
            DeepIdV2ResolverClosureCodec.Decode(contact.Closure.CanonicalBytes.Span),
            contact.ProtectedDcr1.ToArray(), contact.LocatorHash.ToArray());
        var owned = CopyRetainedIntentRequest(ownedRequest);
        var request = Xpu1Codec.Decode(exactXpu1.Span);
        await RequireRetainedIntentAsync(route, new(ownedContact.Closure, ownedContact.ProtectedDcr1,
            ownedContact.LocatorHash, new byte[16], 1), owned, request, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); return new(route, ownedContact, owned, request);
    }

    /// <summary>Verifies current signed public object/support and exact original
    /// publisher/XPA/placement. Receives no resolver capability and cannot prove
    /// decryption, a permanent journal winner or any replica outcome.</summary>
    public static async ValueTask<VerifiedDeepIdV2IssuerPublicationIntent> VerifyIssuerRetainedIntentAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest ownedRequest,
        ReadOnlyMemory<byte> exactXpu1, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(route);
        RequireRetainedIntentBounds(ownedRequest, exactXpu1, ct);
        var owned = CopyRetainedIntentRequest(ownedRequest);
        var request = Xpu1Codec.Decode(exactXpu1.Span);
        var contact = DeepIdV2ResolverClosureCodec.Decode(owned.ExactDcr1.Span);
        await RequireRetainedIntentAsync(route, new(contact, owned.ObjectCiphertext,
            owned.LocatorHash, new byte[16], 1), owned, request, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); return new(route, owned, request);
    }

    private static void RequireRetainedIntentBounds(ContactPublicationAuthorityWireRequest owned,
        ReadOnlyMemory<byte> exactXpu1, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(owned); ct.ThrowIfCancellationRequested();
        if (exactXpu1.Length is < DeepIdV2ContactPublicationCodec.MinimumXpuLength or
            > DeepIdV2ContactPublicationCodec.MaximumXpuLength)
            throw new CryptographicException("Retained publication intent exceeds its exact bound.");
    }

    private static ContactPublicationAuthorityWireRequest CopyRetainedIntentRequest(
        ContactPublicationAuthorityWireRequest request) =>
        ContactPublicationAuthorityWireCodec.DecodeRequest(ContactPublicationAuthorityWireCodec.EncodeRequest(request));

    private static async ValueTask RequireRetainedIntentAsync(VerifiedDeepIdV2ContactRouteClosure route,
        PublicationObject contact, ContactPublicationAuthorityWireRequest owned, Xpu1Request request, CancellationToken ct)
    {
        ContactPublicationAuthorityWireCodec.RequireExactBody(owned, request.CanonicalBytes.Span);
        RequireOwned(route, contact, owned, request);
        var parsed = DeepIdV2ContactPublicationCodec.DecodeXpu1(request.CanonicalBytes.Span);
        var xpa = parsed.Authorization;
        if (owned.PublicationKind != 1 || request.UsageLimit != 0 ||
            request.IssuedAtUnixSeconds < BinaryPrimitives.ReadUInt64BigEndian(contact.Closure.Bundle.Field(17).Span) ||
            request.ExpiresAtUnixSeconds > BinaryPrimitives.ReadUInt64BigEndian(contact.Closure.Bundle.Field(18).Span) ||
            BinaryPrimitives.ReadUInt64BigEndian(xpa.Field(15).Span) != request.IssuedAtUnixSeconds ||
            BinaryPrimitives.ReadUInt64BigEndian(xpa.Field(16).Span) != request.IssuedAtUnixSeconds ||
            BinaryPrimitives.ReadUInt64BigEndian(xpa.Field(17).Span) != request.ExpiresAtUnixSeconds)
            throw new CryptographicException("Retained reusable intent has inconsistent original signed windows.");

        var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequireCurrentObject(route, contact, owned, first);
        var placement = ContactServicePlacementFactory.RequireOriginalPublicationPlacement(
            route.Network, route.NetworkAuthority, request);
        DeepIdV2Xpa1WitnessThresholdVerifier.RequireOriginalThreshold(xpa, placement.Issuer);
        var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        if (!Fixed(first.BootId.Span, final.BootId.Span) || final.MonotonicSample < first.MonotonicSample ||
            final.LowerUnixSeconds < first.LowerUnixSeconds || final.UpperUnixSeconds < first.UpperUnixSeconds)
            throw new CryptographicException("Retained publication intent crossed protected time continuity.");
        RequireCurrentObject(route, contact, owned, final);
        ct.ThrowIfCancellationRequested();
    }
}
