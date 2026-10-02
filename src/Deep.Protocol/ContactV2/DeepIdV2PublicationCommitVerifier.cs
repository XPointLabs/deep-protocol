using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Exact two-replica durable-commit evidence, not client persistence,
/// permission to dispatch, contact consent, a mailbox grant or delivery.</summary>
public sealed class VerifiedDeepIdV2PublicationCommit
{
    private readonly byte[] xpo, requestHash, objectHash;
    internal VerifiedDeepIdV2PublicationCommit(Xpu1Request request, Xpo1Result result)
    {
        xpo = result.WireBytes.ToArray(); requestHash = request.RequestHash.ToArray();
        objectHash = request.ObjectCiphertextHash.ToArray(); Generation = request.Generation;
    }
    public ReadOnlyMemory<byte> ExactXpo1 => xpo.ToArray();
    public ReadOnlyMemory<byte> RequestHash => requestHash.ToArray();
    public ReadOnlyMemory<byte> ObjectCiphertextHash => objectHash.ToArray();
    public ulong Generation { get; }
}

public static class DeepIdV2PublicationCommitVerifier
{
    public const int MaximumResultBytes = 16_384;

    /// <summary>Verifies a signed historical commit under the exact current
    /// owned identity/route. Expired XPA is not renewed or dispatch-authorized.</summary>
    public static async ValueTask<VerifiedDeepIdV2PublicationCommit> VerifyCommittedAsync(
        VerifiedDeepIdV2ContactRouteClosure route, AuthoredDeepIdV2ContactObject contact,
        ContactPublicationAuthorityWireRequest ownedRequest, ReadOnlyMemory<byte> exactXpu1,
        ReadOnlyMemory<byte> exactXpo1, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(contact);
        ArgumentNullException.ThrowIfNull(ownedRequest); ct.ThrowIfCancellationRequested();
        if (exactXpo1.Length is < 256 or > MaximumResultBytes)
            throw new CryptographicException("Publication commit result exceeds its closed bound.");
        // Own/parse all untrusted response bytes before the first clock callback.
        var request = Xpu1Codec.Decode(exactXpu1.Span);
        var parsed = DeepIdV2ContactPublicationCodec.DecodeXpu1(request.CanonicalBytes.Span);
        var result = Xpo1Codec.Decode(exactXpo1.Span, request.CanonicalBytes.Span);
        ContactPublicationAuthorityWireCodec.RequireExactBody(ownedRequest, request.CanonicalBytes.Span);
        RequireOwned(route, contact, ownedRequest, request);
        RequireResult(request, result);
        var first = await route.ReadPublicationClockAsync(ct).ConfigureAwait(false);
        var window = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequireCurrentObject(route, contact, ownedRequest, window);
        _ = DeepIdV2Xpa1WitnessThresholdVerifier.Verify(parsed.Authorization, route.NetworkAuthority);
        var placement = ContactServicePlacementFactory.Create(route.Network,
            ContactServiceRequestKind.PublishInvite, request.LocatorHash);
        if (!Fixed(placement.ViewHash.Span, request.ViewHash.Span) ||
            !Fixed(placement.PlacementHash.Span, request.PlacementHash.Span))
            throw new CryptographicException("Retained publication uses another current placement.");
        VerifyReceipts(request, result, placement);
        await route.EnsureCurrentAsync(ct).ConfigureAwait(false);
        var releaseWindow = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        if (releaseWindow.LowerUnixSeconds < window.LowerUnixSeconds ||
            releaseWindow.UpperUnixSeconds < window.UpperUnixSeconds)
            throw new CryptographicException("Publication commit crossed a trusted time discontinuity.");
        RequireCurrentObject(route, contact, ownedRequest, releaseWindow);
        var final = await route.ReadPublicationClockAsync(ct).ConfigureAwait(false);
        if (!Fixed(first.BootId.Span, final.BootId.Span) || final.SampleSeconds < first.SampleSeconds)
            throw new CryptographicException("Publication commit crossed protected clock continuity.");
        var finalWindow = route.VerifyAtReading(final, ct);
        if (finalWindow.LowerUnixSeconds < releaseWindow.LowerUnixSeconds ||
            finalWindow.UpperUnixSeconds < releaseWindow.UpperUnixSeconds)
            throw new CryptographicException("Publication commit reversed its release-time interval.");
        RequireCurrentObject(route, contact, ownedRequest, finalWindow);
        ct.ThrowIfCancellationRequested(); return new(request, result);
    }

    private static void RequireCurrentObject(VerifiedDeepIdV2ContactRouteClosure route,
        AuthoredDeepIdV2ContactObject contact, ContactPublicationAuthorityWireRequest request,
        DeepIdV2ContactRouteTimeWindow window)
    {
        DeepIdV2ContactRouteVerifier.RequireBundleIssuanceAnchor(route, contact.Closure.Bundle);
        if (BinaryPrimitives.ReadUInt64BigEndian(contact.Closure.Bundle.Field(17).Span) > window.LowerUnixSeconds ||
            request.IssuedAtUnixSeconds > window.LowerUnixSeconds)
            throw new CryptographicException("Historical publication is not yet valid throughout current trusted time.");
        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(contact.Closure,
            route.Recipient.Authorization, window.UpperUnixSeconds);
    }

    private static void RequireOwned(VerifiedDeepIdV2ContactRouteClosure route,
        AuthoredDeepIdV2ContactObject contact, ContactPublicationAuthorityWireRequest owned, Xpu1Request request)
    {
        var dca = route.Recipient.Authorization; var minimum = contact.Closure.Bundle.Field(21).Span;
        if (!Fixed(owned.NetworkId.Span, route.Network.NetworkId.Span) ||
            !Fixed(owned.ExactDca1.Span, dca.Record.CanonicalBytes.Span) ||
            !Fixed(owned.DirectoryLookupKey.Span, route.Recipient.Freshness.QueriedDirectoryLeafKey.Span) ||
            !Fixed(owned.ExactDcr1.Span, contact.Closure.CanonicalBytes.Span) ||
            !Fixed(owned.ObjectCiphertext.Span, contact.ProtectedDcr1.Span) ||
            !Fixed(owned.ExactRouteClosure.Span, route.ExactRouteClosure.Span) ||
            !Fixed(contact.Closure.Bundle.Field(14).Span[40..], route.ExactXir1V2.Span) ||
            !Fixed(request.LocatorHash.Span, contact.LocatorHash.Span) ||
            owned.Generation != 0 || request.Generation != 0 || request.UsageLimit != 0 ||
            owned.PredecessorObjectHash.Span.IndexOfAnyExcept((byte)0) >= 0 ||
            owned.ExpiresAtUnixSeconds <= owned.IssuedAtUnixSeconds ||
            owned.ExpiresAtUnixSeconds - owned.IssuedAtUnixSeconds > 120 ||
            owned.MinimumAdh1Generation != BinaryPrimitives.ReadUInt64BigEndian(minimum) ||
            !Fixed(owned.MinimumAdh1CoreHash.Span, minimum[8..]))
            throw new CryptographicException("Publication commit differs from exact owned DID2 object custody.");
        var device = dca.Binding.Identity.ActiveDevices.Single(value =>
            Fixed(value.Certificate.DeviceId.Span, dca.Record.PublisherDeviceId.Span));
        var input = ContactPublicationAuthorityWireCodec.CreatePublisherSigningInput(owned);
        try
        {
            if (!PublicKeyAuth.VerifyDetached(owned.PublisherSignature.ToArray(), input,
                device.Certificate.DeviceEd25519PublicKey.ToArray()))
                throw new CryptographicException("Retained publication publisher signature is invalid.");
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    private static void RequireResult(Xpu1Request request, Xpo1Result result)
    {
        if (result.Status is not (Xpo1Status.Committed or Xpo1Status.ExactReplay) ||
            result.MutationOutcome != ContactServiceMutationOutcome.DurablyCommitted ||
            BinaryPrimitives.ReadUInt64BigEndian(result.Field(16).Span) != request.Generation ||
            !Fixed(result.Field(17).Span, request.ObjectCiphertextHash.Span) ||
            BinaryPrimitives.ReadUInt64BigEndian(result.Field(18).Span) != checked(request.Generation + 1))
            throw new CryptographicException("Publication response is not the exact durable commit.");
    }

    private static void VerifyReceipts(Xpu1Request request, Xpo1Result result, VerifiedContactServicePlacement placement)
    {
        var tuple = new byte[72]; request.RequestHash.Span.CopyTo(tuple);
        request.ObjectCiphertextHash.Span.CopyTo(tuple.AsSpan(32)); result.Field(18).Span.CopyTo(tuple.AsSpan(64));
        var input = ContactCodec.SignatureInput("Deep/ContactResolver/V1/publish-commit", tuple);
        var rows = result.Field(19).ToArray();
        try
        {
            var selected = placement.RankedReplicaNodeIds.Select(value => Convert.ToHexString(value.Span))
                .ToHashSet(StringComparer.Ordinal);
            if (selected.Count != 2 || rows.Length != 193 || rows[0] != 2)
                throw new CryptographicException("Publication commit requires both selected replicas.");
            for (var i = 0; i < 2; i++)
            {
                var id = rows.AsSpan(1 + i * 96, 32);
                if (!selected.Remove(Convert.ToHexString(id)) ||
                    !PublicKeyAuth.VerifyDetached(rows.AsSpan(33 + i * 96, 64).ToArray(), input, id.ToArray()))
                    throw new CryptographicException("Publication commit replica selection or signature is invalid.");
            }
            if (selected.Count != 0) throw new CryptographicException("Publication commit lacks a selected replica.");
        }
        finally { CryptographicOperations.ZeroMemory(input); CryptographicOperations.ZeroMemory(tuple); }
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
