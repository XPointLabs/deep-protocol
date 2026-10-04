using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Owned candidate only; the caller must retain exact bytes before dispatch.</summary>
public sealed class AuthoredDeepIdV2PublicationRequest
{
    internal AuthoredDeepIdV2PublicationRequest(ContactPublicationAuthorityWireRequest wire,
        VerifiedDeepIdV2ContactRouteClosure route, VerifiedDeepIdV2PublicationPredecessor? predecessor = null)
    { WireRequest = wire; Route = route; Predecessor = predecessor; }
    public ContactPublicationAuthorityWireRequest WireRequest { get; }
    internal VerifiedDeepIdV2ContactRouteClosure Route { get; }
    internal VerifiedDeepIdV2PublicationPredecessor? Predecessor { get; }
    public ValueTask<VerifiedDeepIdV2PublicationAuthorization> VerifyResponseAsync(
        ReadOnlyMemory<byte> exactXpu1, CancellationToken ct = default) =>
        DeepIdV2PublicationAuthorityAuthor.VerifyResponseCoreAsync(Route, WireRequest, exactXpu1, Predecessor, ct);
}

/// <summary>Exact current threshold authorization; not a replica commit, grant or delivery.</summary>
public sealed class VerifiedDeepIdV2PublicationAuthorization
{
    private readonly byte[] xpu;
    internal VerifiedDeepIdV2PublicationAuthorization(byte[] exactXpu) { xpu = exactXpu.ToArray(); }
    public ReadOnlyMemory<byte> ExactXpu1 => xpu.ToArray();
}

/// <summary>DID2-only owned request and threshold authoring. No caller-selected clock.</summary>
public static partial class DeepIdV2PublicationAuthorityAuthor
{
    public static ValueTask<AuthoredDeepIdV2PublicationRequest> AuthorGenesisRequestAsync(
        VerifiedDeepIdV2ContactRouteClosure route, AuthoredDeepIdV2ContactObject contact,
        OwnedGenesisDeviceSecrets device, ReadOnlyMemory<byte> requestNonce32,
        ReadOnlyMemory<byte> operationId32, ReadOnlyMemory<byte> ownerRetrieveCapability32,
        CancellationToken ct = default) =>
        AuthorRequestCoreAsync(route, contact, device, requestNonce32, operationId32, ownerRetrieveCapability32, null, ct);

    public static ValueTask<AuthoredDeepIdV2PublicationRequest> AuthorOneTimeGenesisRequestAsync(
        VerifiedDeepIdV2ContactRouteClosure route, AuthoredDeepIdV2OneTimeContactObject contact,
        OwnedGenesisDeviceSecrets device, ReadOnlyMemory<byte> requestNonce32,
        ReadOnlyMemory<byte> operationId32, ReadOnlyMemory<byte> ownerRetrieveCapability32,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(contact); ArgumentNullException.ThrowIfNull(route);
        if (route.Invite.Field(9).Span[0] != 2)
            throw new CryptographicException("One-time request author requires the exact kind-2 route.");
        return AuthorRequestBodyCoreAsync(route, contact.Closure, contact.ProtectedDcr1, contact.PublicLocator,
            device, requestNonce32, operationId32, ownerRetrieveCapability32, null, ct);
    }

    private static ValueTask<AuthoredDeepIdV2PublicationRequest> AuthorRequestCoreAsync(
        VerifiedDeepIdV2ContactRouteClosure route, AuthoredDeepIdV2ContactObject contact,
        OwnedGenesisDeviceSecrets device, ReadOnlyMemory<byte> requestNonce32,
        ReadOnlyMemory<byte> operationId32, ReadOnlyMemory<byte> ownerRetrieveCapability32,
        VerifiedDeepIdV2PublicationPredecessor? predecessor, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(contact); ArgumentNullException.ThrowIfNull(route);
        if (route.Invite.Field(9).Span[0] != 1)
            throw new CryptographicException("Reusable request author requires the exact kind-1 route.");
        return AuthorRequestBodyCoreAsync(route, contact.Closure, contact.ProtectedDcr1, new byte[16],
            device, requestNonce32, operationId32, ownerRetrieveCapability32, predecessor, ct);
    }

    private static async ValueTask<AuthoredDeepIdV2PublicationRequest> AuthorRequestBodyCoreAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ParsedDcr1V2 exactClosure,
        ReadOnlyMemory<byte> protectedDcr1, ReadOnlyMemory<byte> publicLocator,
        OwnedGenesisDeviceSecrets device, ReadOnlyMemory<byte> requestNonce32,
        ReadOnlyMemory<byte> operationId32, ReadOnlyMemory<byte> ownerRetrieveCapability32,
        VerifiedDeepIdV2PublicationPredecessor? predecessor, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(exactClosure);
        ArgumentNullException.ThrowIfNull(device); ct.ThrowIfCancellationRequested();
        Require32(requestNonce32.Span); Require32(operationId32.Span); Require32(ownerRetrieveCapability32.Span);
        var nonce = requestNonce32.ToArray(); var operation = operationId32.ToArray();
        var owner = ownerRetrieveCapability32.ToArray();
        var closure = DeepIdV2ResolverClosureCodec.Decode(exactClosure.CanonicalBytes.Span);
        var ciphertext = protectedDcr1.ToArray(); var locator = publicLocator.ToArray();
        try
        {
            var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
            if (predecessor is null && U64(closure.Bundle.Field(8).Span) != 0)
                throw new CryptographicException("Genesis publication cannot replace a nonzero contact generation.");
            var expiry = RequestExpiry(route, first.LowerUnixSeconds);
            var placeholder = new byte[64]; placeholder[^1] = 1;
            var freshness = route.Recipient.Freshness;
            var minimum = closure.Bundle.Field(21);
            var wire = new ContactPublicationAuthorityWireRequest(route.Network.NetworkId.Span, nonce,
                freshness.QueriedDirectoryLeafKey.Span, U64(minimum.Span),
                minimum.Span[8..], route.Recipient.Authorization.Record.CanonicalBytes.Span,
                closure.CanonicalBytes.Span, route.ExactRouteClosure.Span, operation,
                U64(closure.Bundle.Field(8).Span),
                predecessor is null ? new byte[32] : predecessor.Object.CiphertextHash.ToArray(),
                ciphertext, first.LowerUnixSeconds, expiry,
                U64(closure.Bundle.Field(18).Span), owner, placeholder,
                predecessor is null ? ReadOnlySpan<byte>.Empty : predecessor.Result.WireBytes.Span, locator);
            RequirePlaintext(route, wire, first, predecessor, ct);
            var signature = device.SignCurrentContactPublicationRequest(wire, route.Recipient.Authorization);
            try
            {
                var signed = CopyWithSignature(wire, signature);
                var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
                Continuous(first, final); RequirePlaintext(route, signed, final, predecessor, ct); VerifyPublisher(route, signed);
                ct.ThrowIfCancellationRequested(); return new(signed, route, predecessor);
            }
            finally { CryptographicOperations.ZeroMemory(signature); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(operation);
            CryptographicOperations.ZeroMemory(owner);
            CryptographicOperations.ZeroMemory(ciphertext); CryptographicOperations.ZeroMemory(locator);
        }
    }

    /// <summary>Reverify untrusted exact request before custody/journal callbacks.</summary>
    public static ValueTask VerifyRequestAsync(VerifiedDeepIdV2ContactRouteClosure route,
        ContactPublicationAuthorityWireRequest request, CancellationToken ct = default) =>
        VerifyRequestCoreAsync(route, request, null, ct);

    private static async ValueTask VerifyRequestCoreAsync(VerifiedDeepIdV2ContactRouteClosure route,
        ContactPublicationAuthorityWireRequest request, IVerifiedDeepIdV2PublicationLineage? predecessor, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(request);
        ct.ThrowIfCancellationRequested();
        var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequirePlaintext(route, request, first, predecessor, ct); VerifyPublisher(route, request);
        var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        Continuous(first, final); RequirePlaintext(route, request, final, predecessor, ct);
        ct.ThrowIfCancellationRequested();
    }

    public static ValueTask<VerifiedDeepIdV2PublicationAuthorization> AuthorThresholdAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest request,
        IReadOnlyList<IXpa1PublicationAuthorizationWitnessSigner> witnesses, CancellationToken ct = default) =>
        AuthorThresholdCoreAsync(route, request, witnesses, null, ct);

    private static async ValueTask<VerifiedDeepIdV2PublicationAuthorization> AuthorThresholdCoreAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest request,
        IReadOnlyList<IXpa1PublicationAuthorizationWitnessSigner> witnesses,
        IVerifiedDeepIdV2PublicationLineage? predecessor, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(witnesses); ct.ThrowIfCancellationRequested();
        var count = witnesses.Count;
        if (count is < 2 or > 32) throw new CryptographicException("Publication witness count is invalid.");
        // Capture identities before the first external custody callback.
        var signers = new (IXpa1PublicationAuthorizationWitnessSigner Signer, byte[] Id, byte[] Key)[count];
        var ids = new HashSet<string>(StringComparer.Ordinal); var domains = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < count; i++)
        {
            var signer = witnesses[i] ?? throw new CryptographicException("Publication witness is absent.");
            var id = signer.WitnessId.ToArray(); Require32(id);
            if (!ids.Add(Convert.ToHexString(id))) throw new CryptographicException("Duplicate publication witness.");
            var key = route.NetworkAuthority.WitnessKeys.SingleOrDefault(value => Fixed(value.Id.Span, id)) ??
                throw new CryptographicException("Unknown publication witness.");
            domains.Add(Convert.ToHexString(key.FailureDomainHash.Span));
            signers[i] = (signer, id, key.Ed25519PublicKey.ToArray());
        }
        if (count < route.NetworkAuthority.WitnessThreshold || domains.Count < route.NetworkAuthority.WitnessThreshold)
            throw new CryptographicException("Publication witness failure-domain threshold is not met.");
        Array.Sort(signers, (a, b) => a.Id.AsSpan().SequenceCompareTo(b.Id));
        var prior = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        await VerifyRequestCoreAsync(route, request, predecessor, ct).ConfigureAwait(false);
        var closure = DeepIdV2ResolverClosureCodec.Decode(request.ExactDcr1.Span); var bundle = closure.Bundle;
        var locator = request.LocatorHash.ToArray();
        var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite, locator);
        var usage = request.PublicationKind == 1 ? new byte[4] : new byte[] { 0, 0, 0, 1 };
        ReadOnlyMemory<byte>[] body = [request.NetworkId, request.OperationId, placement.ViewHash, placement.PlacementHash,
            U64Bytes(request.IssuedAtUnixSeconds), U64Bytes(request.ExpiresAtUnixSeconds), locator,
            SHA256.HashData(bundle.Field(14).Span[40..]), U64Bytes(request.Generation), request.PredecessorObjectHash,
            SHA256.HashData(request.ObjectCiphertext.Span), request.ObjectCiphertext, usage,
            U64Bytes(request.EffectiveExpiresAtUnixSeconds), SHA256.HashData(request.ExactRouteClosure.Span),
            request.ExactRouteClosure, new byte[594 + count * 96], request.OwnerRetrieveCapability];
        var hash = DeepIdV2ContactPublicationCodec.ComputeAuthorizedBodyHash(Encode(ProtocolMagicBytes.XPU1,
            DeepIdV2ContactPublicationCodec.XpuTags.ToArray(), body));
        var identity = new byte[96]; request.OperationId.Span.CopyTo(identity);
        var issuanceHead = route.Recipient.Freshness.NextProtectedLkg.CoreHash;
        hash.CopyTo(identity, 32); issuanceHead.Span.CopyTo(identity.AsSpan(64));
        byte[][] xpa = [request.NetworkId.ToArray(), ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V2/publication-authorization-id", identity), request.OperationId.ToArray(), locator,
            [request.PublicationKind], SHA256.HashData(closure.CanonicalBytes.Span), SHA256.HashData(bundle.CanonicalBytes.Span),
            body[7].ToArray(), U64Bytes(request.Generation), request.PredecessorObjectHash.ToArray(), body[10].ToArray(), usage,
            U64Bytes(request.EffectiveExpiresAtUnixSeconds), PolicyHash(request.ExactDca1.Span),
            U64Bytes(request.IssuedAtUnixSeconds), U64Bytes(request.IssuedAtUnixSeconds), U64Bytes(request.ExpiresAtUnixSeconds),
            issuanceHead.ToArray(), hash, [checked((byte)count)], new byte[count * 96]];
        var input = DeepIdV2ContactPublicationCodec.CreateWitnessSigningInput(xpa);
        try
        {
            for (var i = 0; i < count; i++)
            {
                var before = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
                Continuous(prior, before); prior = before;
                RequirePlaintext(route, request, prior, predecessor, ct);
                var signer = signers[i];
                if (!Fixed(signer.Signer.WitnessId.Span, signer.Id)) throw new CryptographicException("Witness identity changed.");
                var returned = await signer.Signer.SignXpa1Async(input.ToArray(), ct).ConfigureAwait(false);
                var signature = returned.ToArray();
                try
                {
                    ct.ThrowIfCancellationRequested();
                    var current = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
                    Continuous(prior, current); RequirePlaintext(route, request, current, predecessor, ct); prior = current;
                    if (!Fixed(signer.Signer.WitnessId.Span, signer.Id) || signature.Length != 64 ||
                        !PublicKeyAuth.VerifyDetached(signature, input, signer.Key))
                        throw new CryptographicException("Publication witness returned an invalid signature or substituted identity.");
                    signer.Id.CopyTo(xpa[20], i * 96); signature.CopyTo(xpa[20], i * 96 + 32);
                }
                finally { CryptographicOperations.ZeroMemory(signature); }
            }
            body[16] = Encode(ProtocolMagicBytes.XPA1, DeepIdV2ContactPublicationCodec.XpaTags.ToArray(),
                xpa.Select(value => (ReadOnlyMemory<byte>)value).ToArray());
            return await VerifyResponseCoreAsync(route, request, Encode(ProtocolMagicBytes.XPU1,
                DeepIdV2ContactPublicationCodec.XpuTags.ToArray(), body), predecessor, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    public static ValueTask<VerifiedDeepIdV2PublicationAuthorization> VerifyResponseAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest request,
        ReadOnlyMemory<byte> exactXpu1, CancellationToken ct = default) =>
        VerifyResponseCoreAsync(route, request, exactXpu1, null, ct);

    internal static async ValueTask<VerifiedDeepIdV2PublicationAuthorization> VerifyResponseCoreAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest request,
        ReadOnlyMemory<byte> exactXpu1, IVerifiedDeepIdV2PublicationLineage? predecessor, CancellationToken ct)
    {
        // Parse/copy before clock awaits. A parsed response is not a capability.
        var parsed = DeepIdV2ContactPublicationCodec.DecodeXpu1(exactXpu1.Span);
        await VerifyRequestCoreAsync(route, request, predecessor, ct).ConfigureAwait(false);
        ContactPublicationAuthorityWireCodec.RequireExactBody(request, parsed.CanonicalBytes.Span);
        var locator = parsed.Field(16);
        var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite, locator);
        if (!Fixed(parsed.Field(3).Span, placement.ViewHash.Span) ||
            !Fixed(parsed.Field(4).Span, placement.PlacementHash.Span) || request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds)
            throw new CryptographicException("Publication response changed exact current placement.");
        var reading = await route.ReadPublicationClockAsync(ct).ConfigureAwait(false);
        _ = DeepIdV2Xpa1CurrentDirectoryWitnessVerifier.Verify(parsed, route.NetworkAuthority,
            route.Recipient.Freshness, reading.BootId.Span, reading.SampleSeconds);
        await VerifyRequestCoreAsync(route, request, predecessor, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); return new(parsed.CanonicalBytes.ToArray());
    }

    private static void RequirePlaintext(VerifiedDeepIdV2ContactRouteClosure route,
        ContactPublicationAuthorityWireRequest request, DeepIdV2ContactRouteTimeWindow current,
        IVerifiedDeepIdV2PublicationLineage? predecessor, CancellationToken ct)
    {
        var dca = route.Recipient.Authorization; var freshness = route.Recipient.Freshness;
        var closure = DeepIdV2ResolverClosureCodec.Decode(request.ExactDcr1.Span); var bundle = closure.Bundle;
        DeepIdV2ContactRouteVerifier.RequireBundleIssuanceAnchor(route, bundle);
        if (!Fixed(request.ExactDca1.Span, dca.Record.CanonicalBytes.Span) ||
            !Fixed(request.NetworkId.Span, route.Network.NetworkId.Span) ||
            !Fixed(request.DirectoryLookupKey.Span, freshness.QueriedDirectoryLeafKey.Span) ||
            request.MinimumAdh1Generation != U64(bundle.Field(21).Span) ||
            !Fixed(request.MinimumAdh1CoreHash.Span, bundle.Field(21).Span[8..]) ||
            !Fixed(request.ExactRouteClosure.Span, route.ExactRouteClosure.Span) ||
            !Fixed(bundle.Field(14).Span[40..], route.ExactXir1V2.Span) ||
            request.Generation != U64(bundle.Field(8).Span) || request.Generation != U64(route.Invite.Field(3).Span) ||
            (predecessor is null && (request.Generation != 0 || request.PredecessorObjectHash.Span.IndexOfAnyExcept((byte)0) >= 0)) ||
            route.Invite.Field(9).Span[0] != request.PublicationKind ||
            BinaryPrimitives.ReadUInt32BigEndian(bundle.Field(16).Span) != (request.PublicationKind == 1 ? 9u : 10u) ||
            request.PublicationKind == 2 && (predecessor is not null || request.Generation != 0) ||
            request.IssuedAtUnixSeconds > current.LowerUnixSeconds || current.UpperUnixSeconds >= request.ExpiresAtUnixSeconds ||
            request.ExpiresAtUnixSeconds > RequestExpiry(route, request.IssuedAtUnixSeconds))
            throw new CryptographicException("Publication request is not exact current owned DID2 lineage.");
        predecessor?.RequireSuccessor(route, request, current, ct);
        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(closure, dca, current.UpperUnixSeconds);
    }

    private static void VerifyPublisher(VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest request)
    {
        var dca = route.Recipient.Authorization;
        var device = dca.Binding.Identity.ActiveDevices.Single(value => Fixed(value.Certificate.DeviceId.Span, dca.Record.PublisherDeviceId.Span));
        var input = ContactPublicationAuthorityWireCodec.CreatePublisherSigningInput(request);
        try
        {
            if (!PublicKeyAuth.VerifyDetached(request.PublisherSignature.ToArray(), input, device.Certificate.DeviceEd25519PublicKey.ToArray()))
                throw new CryptographicException("The publisher did not sign the complete exact V4 request.");
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    private static ulong RequestExpiry(VerifiedDeepIdV2ContactRouteClosure route, ulong start)
    {
        var freshness = route.Recipient.Freshness;
        var proofUpper = checked(freshness.TrustedLowerUnixSeconds +
            (freshness.FreshnessDeadlineMonotonicSeconds - freshness.MonotonicSample));
        var records = route.Route;
        return new[] { checked(start + 120), proofUpper, freshness.NextProtectedLkg.Head.ValidUntil,
            route.Network.MaximumRecordExpiryUnixSeconds, route.NetworkAuthority.ExpiresAt,
            U64(records.Reachability.Field(17).Span), U64(records.Authorization.Field(13).Span),
            U64(records.Route.Field(18).Span), U64(records.Successor.Field(11).Span),
            U64(records.Projection.Field(12).Span), U64(records.Selection.Field(9).Span),
            route.Recipient.Authorization.Record.ExpiresAtUnixSeconds }.Min();
    }
    private static ContactPublicationAuthorityWireRequest CopyWithSignature(ContactPublicationAuthorityWireRequest r, byte[] sig) =>
        new(r.NetworkId.Span, r.RequestNonce.Span, r.DirectoryLookupKey.Span, r.MinimumAdh1Generation,
            r.MinimumAdh1CoreHash.Span, r.ExactDca1.Span, r.ExactDcr1.Span, r.ExactRouteClosure.Span,
            r.OperationId.Span, r.Generation, r.PredecessorObjectHash.Span, r.ObjectCiphertext.Span,
            r.IssuedAtUnixSeconds, r.ExpiresAtUnixSeconds, r.EffectiveExpiresAtUnixSeconds, r.OwnerRetrieveCapability.Span, sig, r.ExactPriorXpo1.Span, r.OneTimeLocator.Span);
    private static byte[] Encode(ReadOnlySpan<byte> magic, ushort[] tags, ReadOnlyMemory<byte>[] fields)
    {
        var bytes = new byte[12 + fields.Sum(value => 8 + value.Length)];
        var writer = new ApplicationRecordWriter(bytes, magic, checked((ushort)tags.Length), 2, DeepIdV2Codec.Suite);
        for (var i = 0; i < tags.Length; i++) writer.Write(tags[i], fields[i].Span);
        writer.Complete(); return bytes;
    }
    private static byte[] PolicyHash(ReadOnlySpan<byte> dca) => ApplicationCoreFormat.Sha256Domain("Deep/ContactResolver/V2/publication-policy", dca);
    private static byte[] U64Bytes(ulong n) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, n); return bytes; }
    private static ulong U64(ReadOnlySpan<byte> n) => BinaryPrimitives.ReadUInt64BigEndian(n);
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static void Require32(ReadOnlySpan<byte> b) { if (b.Length != 32 || b.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("An exact nonzero 32-byte field is required."); }
    private static void Continuous(DeepIdV2ContactRouteTimeWindow first, DeepIdV2ContactRouteTimeWindow final)
    { if (final.LowerUnixSeconds < first.LowerUnixSeconds || final.UpperUnixSeconds < first.UpperUnixSeconds) throw new CryptographicException("Publication crossed a trusted clock discontinuity."); }
}
