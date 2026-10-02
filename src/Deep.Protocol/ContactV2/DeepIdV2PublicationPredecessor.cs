using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Authenticated historical two-replica publication lineage only.
/// Not current publication, dispatch, a server reservation or client CAS.</summary>
public sealed class VerifiedDeepIdV2PublicationPredecessor
{
    internal VerifiedDeepIdV2PublicationPredecessor(VerifiedDeepIdV2ContactObjectPredecessor contact,
        ContactPublicationAuthorityWireRequest owned, Xpu1Request request, Xpo1Result result)
    { Object = contact; OwnedRequest = owned; Request = request; Result = result; }
    public VerifiedDeepIdV2ContactObjectPredecessor Object { get; }
    public ulong Generation => OwnedRequest.Generation;
    internal ContactPublicationAuthorityWireRequest OwnedRequest { get; }
    internal Xpu1Request Request { get; }
    internal Xpo1Result Result { get; }

    internal void RequireAtCurrentContext(DeepIdV2RouteContext current) =>
        DeepIdV2PublicationCommitVerifier.RequireHistoricalPublication(this, current);

    internal void RequireSuccessor(VerifiedDeepIdV2ContactRouteClosure next,
        ContactPublicationAuthorityWireRequest request, DeepIdV2ContactRouteTimeWindow window, CancellationToken ct)
    {
        RequireAtCurrentContext(next.VerifyContextAtWindow(window, ct));
        var closure = DeepIdV2ResolverClosureCodec.Decode(request.ExactDcr1.Span);
        Object.RequireSuccessorObject(next, closure, window, ct);
        if (Generation == ulong.MaxValue || request.Generation != Generation + 1 ||
            !DeepIdV2RouteContext.Fixed(request.PredecessorObjectHash.Span, Object.CiphertextHash.Span) ||
            !DeepIdV2RouteContext.Fixed(request.OwnerRetrieveCapability.Span, OwnedRequest.OwnerRetrieveCapability.Span))
            throw new CryptographicException("Publication successor differs from its exact committed predecessor or owner custody.");
    }
}

public static partial class DeepIdV2PublicationAuthorityAuthor
{
    public static ValueTask<AuthoredDeepIdV2PublicationRequest> AuthorSuccessorRequestAsync(
        VerifiedDeepIdV2ContactRouteClosure route, AuthoredDeepIdV2ContactObject contact,
        Deep.Protocol.Identity.OwnedGenesisDeviceSecrets device, VerifiedDeepIdV2PublicationPredecessor predecessor,
        ReadOnlyMemory<byte> requestNonce32, ReadOnlyMemory<byte> operationId32, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor);
        return AuthorRequestCoreAsync(route, contact, device, requestNonce32, operationId32,
            predecessor.OwnedRequest.OwnerRetrieveCapability, predecessor, ct);
    }

    public static ValueTask VerifySuccessorRequestAsync(VerifiedDeepIdV2ContactRouteClosure route,
        ContactPublicationAuthorityWireRequest request, VerifiedDeepIdV2PublicationPredecessor predecessor,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor);
        return VerifyRequestCoreAsync(route, request, predecessor, ct);
    }

    public static ValueTask<VerifiedDeepIdV2PublicationAuthorization> AuthorThresholdSuccessorAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest request,
        VerifiedDeepIdV2PublicationPredecessor predecessor,
        IReadOnlyList<IXpa1PublicationAuthorizationWitnessSigner> witnesses, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor);
        return AuthorThresholdCoreAsync(route, request, witnesses, predecessor, ct);
    }

    public static ValueTask<VerifiedDeepIdV2PublicationAuthorization> VerifySuccessorResponseAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest request,
        VerifiedDeepIdV2PublicationPredecessor predecessor, ReadOnlyMemory<byte> exactXpu1, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor);
        return VerifyResponseCoreAsync(route, request, exactXpu1, predecessor, ct);
    }
}

public static partial class DeepIdV2PublicationCommitVerifier
{
    public static async ValueTask<VerifiedDeepIdV2PublicationPredecessor> VerifyPredecessorAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, VerifiedDeepIdV2ContactObjectPredecessor contact,
        ContactPublicationAuthorityWireRequest ownedRequest, ReadOnlyMemory<byte> exactXpu1,
        ReadOnlyMemory<byte> exactXpo1, OnionTrustedTimeAuthority time, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(contact); ArgumentNullException.ThrowIfNull(ownedRequest);
        ct.ThrowIfCancellationRequested();
        if (exactXpu1.Length is < DeepIdV2ContactPublicationCodec.MinimumXpuLength or > DeepIdV2ContactPublicationCodec.MaximumXpuLength ||
            exactXpo1.Length is < 256 or > MaximumResultBytes)
            throw new CryptographicException("Historical publication exceeds its exact bounds.");
        var owned = ContactPublicationAuthorityWireCodec.DecodeRequest(ContactPublicationAuthorityWireCodec.EncodeRequest(ownedRequest));
        var request = Xpu1Codec.Decode(exactXpu1.Span);
        var result = Xpo1Codec.Decode(exactXpo1.Span, request.CanonicalBytes.Span);
        ContactPublicationAuthorityWireCodec.RequireExactBody(owned, request.CanonicalBytes.Span);
        var predecessor = new VerifiedDeepIdV2PublicationPredecessor(contact, owned, request, result);
        var first = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, time, ct).ConfigureAwait(false);
        RequireHistoricalPublication(predecessor, first);
        var final = await first.RecheckAsync(ct).ConfigureAwait(false);
        RequireHistoricalPublication(predecessor, final);
        ct.ThrowIfCancellationRequested(); return predecessor;
    }

    internal static void RequireHistoricalPublication(VerifiedDeepIdV2PublicationPredecessor predecessor,
        DeepIdV2RouteContext current)
    {
        var contact = predecessor.Object; var owned = predecessor.OwnedRequest;
        var request = predecessor.Request; var result = predecessor.Result;
        contact.RequireAtCurrentContext(current);
        var minimum = contact.Closure.Bundle.Field(21).Span;
        if (!Fixed(owned.NetworkId.Span, current.Network.NetworkId.Span) ||
            !Fixed(owned.ExactDca1.Span, current.Recipient.Authorization.Record.CanonicalBytes.Span) ||
            !Fixed(owned.DirectoryLookupKey.Span, current.Recipient.Freshness.QueriedDirectoryLeafKey.Span) ||
            !Fixed(owned.ExactDcr1.Span, contact.Closure.CanonicalBytes.Span) ||
            !Fixed(SHA256.HashData(owned.ObjectCiphertext.Span), contact.CiphertextHash.Span) ||
            !Fixed(owned.ExactRouteClosure.Span, contact.Route.ExactRouteClosure.Span) ||
            !Fixed(request.LocatorHash.Span, contact.LocatorHash.Span) || request.UsageLimit != 0 ||
            owned.Generation != BinaryPrimitives.ReadUInt64BigEndian(contact.Closure.Bundle.Field(8).Span) ||
            owned.IssuedAtUnixSeconds > current.Lower ||
            owned.MinimumAdh1Generation != BinaryPrimitives.ReadUInt64BigEndian(minimum) ||
            !Fixed(owned.MinimumAdh1CoreHash.Span, minimum[8..]))
            throw new CryptographicException("Historical publication differs from exact authenticated object custody.");
        var input = ContactPublicationAuthorityWireCodec.CreatePublisherSigningInput(owned);
        try
        {
            if (!PublicKeyAuth.VerifyDetached(owned.PublisherSignature.ToArray(), input,
                current.Device.Certificate.DeviceEd25519PublicKey.ToArray()))
                throw new CryptographicException("Historical publication publisher signature is invalid.");
        }
        finally { CryptographicOperations.ZeroMemory(input); }
        var parsed = DeepIdV2ContactPublicationCodec.DecodeXpu1(request.CanonicalBytes.Span);
        _ = DeepIdV2Xpa1WitnessThresholdVerifier.Verify(parsed.Authorization, current.Authority);
        RequireResult(request, result);
        var placement = ContactServicePlacementFactory.Create(current.Network,
            ContactServiceRequestKind.PublishInvite, request.LocatorHash);
        if (!Fixed(placement.ViewHash.Span, request.ViewHash.Span) || !Fixed(placement.PlacementHash.Span, request.PlacementHash.Span))
            throw new CryptographicException("Historical publication requires separately authorized placement rollover.");
        VerifyReceipts(request, result, placement);
    }
}
