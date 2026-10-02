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
        VerifiedDeepIdV2ContactRouteClosure route) { WireRequest = wire; Route = route; }
    public ContactPublicationAuthorityWireRequest WireRequest { get; }
    internal VerifiedDeepIdV2ContactRouteClosure Route { get; }
    public ValueTask<VerifiedDeepIdV2PublicationAuthorization> VerifyResponseAsync(
        ReadOnlyMemory<byte> exactXpu1, CancellationToken ct = default) =>
        DeepIdV2PublicationAuthorityAuthor.VerifyResponseAsync(Route, WireRequest, exactXpu1, ct);
}

/// <summary>Exact current threshold authorization; not a replica commit, grant or delivery.</summary>
public sealed class VerifiedDeepIdV2PublicationAuthorization
{
    private readonly byte[] xpu;
    internal VerifiedDeepIdV2PublicationAuthorization(byte[] exactXpu) { xpu = exactXpu.ToArray(); }
    public ReadOnlyMemory<byte> ExactXpu1 => xpu.ToArray();
}

/// <summary>DID2-only owned request and threshold authoring. No caller-selected clock.</summary>
public static class DeepIdV2PublicationAuthorityAuthor
{
    public static async ValueTask<AuthoredDeepIdV2PublicationRequest> AuthorGenesisRequestAsync(
        VerifiedDeepIdV2ContactRouteClosure route, AuthoredDeepIdV2ContactObject contact,
        OwnedGenesisDeviceSecrets device, ReadOnlyMemory<byte> requestNonce32,
        ReadOnlyMemory<byte> operationId32, ReadOnlyMemory<byte> ownerRetrieveCapability32,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(contact);
        ArgumentNullException.ThrowIfNull(device); ct.ThrowIfCancellationRequested();
        Require32(requestNonce32.Span); Require32(operationId32.Span); Require32(ownerRetrieveCapability32.Span);
        var nonce = requestNonce32.ToArray(); var operation = operationId32.ToArray();
        var owner = ownerRetrieveCapability32.ToArray();
        try
        {
            var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
            var expiry = RequestExpiry(route, first.LowerUnixSeconds);
            var placeholder = new byte[64]; placeholder[^1] = 1;
            var freshness = route.Recipient.Freshness;
            var wire = new ContactPublicationAuthorityWireRequest(route.Network.NetworkId.Span, nonce,
                freshness.QueriedDirectoryLeafKey.Span, freshness.NextProtectedLkg.LogGeneration,
                freshness.NextProtectedLkg.CoreHash.Span, route.Recipient.Authorization.Record.CanonicalBytes.Span,
                contact.Closure.CanonicalBytes.Span, route.ExactRouteClosure.Span, operation,
                0, new byte[32], contact.ProtectedDcr1.Span, first.LowerUnixSeconds, expiry,
                U64(contact.Closure.Bundle.Field(18).Span), owner, placeholder);
            RequirePlaintext(route, wire, first);
            var signature = device.SignCurrentContactPublicationRequest(wire, route.Recipient.Authorization);
            try
            {
                var signed = CopyWithSignature(wire, signature);
                var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
                Continuous(first, final); RequirePlaintext(route, signed, final); VerifyPublisher(route, signed);
                ct.ThrowIfCancellationRequested(); return new(signed, route);
            }
            finally { CryptographicOperations.ZeroMemory(signature); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(operation);
            CryptographicOperations.ZeroMemory(owner);
        }
    }

    /// <summary>Reverify untrusted exact request before custody/journal callbacks.</summary>
    public static async ValueTask VerifyRequestAsync(VerifiedDeepIdV2ContactRouteClosure route,
        ContactPublicationAuthorityWireRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(request);
        ct.ThrowIfCancellationRequested();
        var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequirePlaintext(route, request, first); VerifyPublisher(route, request);
        var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        Continuous(first, final); RequirePlaintext(route, request, final);
        ct.ThrowIfCancellationRequested();
    }

    public static async ValueTask<VerifiedDeepIdV2PublicationAuthorization> AuthorThresholdAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest request,
        IReadOnlyList<IXpa1PublicationAuthorizationWitnessSigner> witnesses, CancellationToken ct = default)
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
        await VerifyRequestAsync(route, request, ct).ConfigureAwait(false);
        var closure = DeepIdV2ResolverClosureCodec.Decode(request.ExactDcr1.Span); var bundle = closure.Bundle;
        var locator = Locator(request.NetworkId.Span, bundle.Field(22).Span);
        var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite, locator);
        ReadOnlyMemory<byte>[] body = [request.NetworkId, request.OperationId, placement.ViewHash, placement.PlacementHash,
            U64Bytes(request.IssuedAtUnixSeconds), U64Bytes(request.ExpiresAtUnixSeconds), locator,
            SHA256.HashData(bundle.Field(14).Span[40..]), U64Bytes(request.Generation), request.PredecessorObjectHash,
            SHA256.HashData(request.ObjectCiphertext.Span), request.ObjectCiphertext, new byte[4],
            U64Bytes(request.EffectiveExpiresAtUnixSeconds), SHA256.HashData(request.ExactRouteClosure.Span),
            request.ExactRouteClosure, new byte[594 + count * 96], request.OwnerRetrieveCapability];
        var hash = DeepIdV2ContactPublicationCodec.ComputeAuthorizedBodyHash(Encode(ProtocolMagicBytes.XPU1,
            DeepIdV2ContactPublicationCodec.XpuTags.ToArray(), body));
        var identity = new byte[96]; request.OperationId.Span.CopyTo(identity);
        hash.CopyTo(identity, 32); request.MinimumAdh1CoreHash.Span.CopyTo(identity.AsSpan(64));
        byte[][] xpa = [request.NetworkId.ToArray(), ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V2/publication-authorization-id", identity), request.OperationId.ToArray(), locator,
            [1], SHA256.HashData(closure.CanonicalBytes.Span), SHA256.HashData(bundle.CanonicalBytes.Span),
            body[7].ToArray(), U64Bytes(0), new byte[32], body[10].ToArray(), new byte[4],
            U64Bytes(request.EffectiveExpiresAtUnixSeconds), PolicyHash(request.ExactDca1.Span),
            U64Bytes(request.IssuedAtUnixSeconds), U64Bytes(request.IssuedAtUnixSeconds), U64Bytes(request.ExpiresAtUnixSeconds),
            request.MinimumAdh1CoreHash.ToArray(), hash, [checked((byte)count)], new byte[count * 96]];
        var input = DeepIdV2ContactPublicationCodec.CreateWitnessSigningInput(xpa);
        try
        {
            for (var i = 0; i < count; i++)
            {
                var before = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
                Continuous(prior, before); prior = before;
                RequirePlaintext(route, request, prior);
                var signer = signers[i];
                if (!Fixed(signer.Signer.WitnessId.Span, signer.Id)) throw new CryptographicException("Witness identity changed.");
                var returned = await signer.Signer.SignXpa1Async(input.ToArray(), ct).ConfigureAwait(false);
                var signature = returned.ToArray();
                try
                {
                    ct.ThrowIfCancellationRequested();
                    var current = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
                    Continuous(prior, current); RequirePlaintext(route, request, current); prior = current;
                    if (!Fixed(signer.Signer.WitnessId.Span, signer.Id) || signature.Length != 64 ||
                        !PublicKeyAuth.VerifyDetached(signature, input, signer.Key))
                        throw new CryptographicException("Publication witness returned an invalid signature or substituted identity.");
                    signer.Id.CopyTo(xpa[20], i * 96); signature.CopyTo(xpa[20], i * 96 + 32);
                }
                finally { CryptographicOperations.ZeroMemory(signature); }
            }
            body[16] = Encode(ProtocolMagicBytes.XPA1, DeepIdV2ContactPublicationCodec.XpaTags.ToArray(),
                xpa.Select(value => (ReadOnlyMemory<byte>)value).ToArray());
            return await VerifyResponseAsync(route, request, Encode(ProtocolMagicBytes.XPU1,
                DeepIdV2ContactPublicationCodec.XpuTags.ToArray(), body), ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    public static async ValueTask<VerifiedDeepIdV2PublicationAuthorization> VerifyResponseAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest request,
        ReadOnlyMemory<byte> exactXpu1, CancellationToken ct = default)
    {
        // Parse/copy before clock awaits. A parsed response is not a capability.
        var parsed = DeepIdV2ContactPublicationCodec.DecodeXpu1(exactXpu1.Span);
        await VerifyRequestAsync(route, request, ct).ConfigureAwait(false);
        ContactPublicationAuthorityWireCodec.RequireExactBody(request, parsed.CanonicalBytes.Span);
        var locator = parsed.Field(16);
        var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite, locator);
        if (!Fixed(parsed.Field(3).Span, placement.ViewHash.Span) ||
            !Fixed(parsed.Field(4).Span, placement.PlacementHash.Span) || request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds)
            throw new CryptographicException("Publication response changed exact current placement.");
        var reading = await route.ReadPublicationClockAsync(ct).ConfigureAwait(false);
        _ = DeepIdV2Xpa1CurrentDirectoryWitnessVerifier.Verify(parsed, route.NetworkAuthority,
            route.Recipient.Freshness, reading.BootId.Span, reading.SampleSeconds);
        await VerifyRequestAsync(route, request, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); return new(parsed.CanonicalBytes.ToArray());
    }

    private static void RequirePlaintext(VerifiedDeepIdV2ContactRouteClosure route,
        ContactPublicationAuthorityWireRequest request, DeepIdV2ContactRouteTimeWindow current)
    {
        var dca = route.Recipient.Authorization; var freshness = route.Recipient.Freshness;
        var closure = DeepIdV2ResolverClosureCodec.Decode(request.ExactDcr1.Span); var bundle = closure.Bundle;
        if (!Fixed(request.ExactDca1.Span, dca.Record.CanonicalBytes.Span) ||
            !Fixed(request.NetworkId.Span, route.Network.NetworkId.Span) ||
            !Fixed(request.DirectoryLookupKey.Span, freshness.QueriedDirectoryLeafKey.Span) ||
            request.MinimumAdh1Generation != freshness.NextProtectedLkg.LogGeneration ||
            !Fixed(request.MinimumAdh1CoreHash.Span, freshness.NextProtectedLkg.CoreHash.Span) ||
            !Fixed(request.ExactRouteClosure.Span, route.ExactRouteClosure.Span) ||
            !Fixed(bundle.Field(14).Span[40..], route.ExactXir1V2.Span) ||
            request.Generation != 0 || U64(bundle.Field(8).Span) != 0 || U64(route.Invite.Field(3).Span) != 0 ||
            request.PredecessorObjectHash.Span.IndexOfAnyExcept((byte)0) >= 0 ||
            BinaryPrimitives.ReadUInt32BigEndian(bundle.Field(16).Span) != 9 ||
            request.IssuedAtUnixSeconds > current.LowerUnixSeconds || current.UpperUnixSeconds >= request.ExpiresAtUnixSeconds ||
            request.ExpiresAtUnixSeconds > RequestExpiry(route, request.IssuedAtUnixSeconds))
            throw new CryptographicException("Publication request is not exact current owned reusable DID2 genesis.");
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
                throw new CryptographicException("The publisher did not sign the complete exact V2 request.");
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
            r.IssuedAtUnixSeconds, r.ExpiresAtUnixSeconds, r.EffectiveExpiresAtUnixSeconds, r.OwnerRetrieveCapability.Span, sig);
    private static byte[] Encode(ReadOnlySpan<byte> magic, ushort[] tags, ReadOnlyMemory<byte>[] fields)
    {
        var bytes = new byte[12 + fields.Sum(value => 8 + value.Length)];
        var writer = new ApplicationRecordWriter(bytes, magic, checked((ushort)tags.Length), 2, DeepIdV2Codec.Suite);
        for (var i = 0; i < tags.Length; i++) writer.Write(tags[i], fields[i].Span);
        writer.Complete(); return bytes;
    }
    private static byte[] Locator(ReadOnlySpan<byte> network, ReadOnlySpan<byte> didHash)
    { var bytes = new byte[48]; network.CopyTo(bytes); didHash.CopyTo(bytes.AsSpan(16)); return ApplicationCoreFormat.Sha256Domain("Deep/ContactResolver/V2/permanent-locator", bytes); }
    private static byte[] PolicyHash(ReadOnlySpan<byte> dca) => ApplicationCoreFormat.Sha256Domain("Deep/ContactResolver/V2/publication-policy", dca);
    private static byte[] U64Bytes(ulong n) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, n); return bytes; }
    private static ulong U64(ReadOnlySpan<byte> n) => BinaryPrimitives.ReadUInt64BigEndian(n);
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static void Require32(ReadOnlySpan<byte> b) { if (b.Length != 32 || b.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("An exact nonzero 32-byte field is required."); }
    private static void Continuous(DeepIdV2ContactRouteTimeWindow first, DeepIdV2ContactRouteTimeWindow final)
    { if (final.LowerUnixSeconds < first.LowerUnixSeconds || final.UpperUnixSeconds < first.UpperUnixSeconds) throw new CryptographicException("Publication crossed a trusted clock discontinuity."); }
}
