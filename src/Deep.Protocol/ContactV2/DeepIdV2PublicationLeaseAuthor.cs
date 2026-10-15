using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Closed artifact-specific current witness signing request. No public
/// constructor, caller-selected signing purpose or authority conversion.</summary>
public sealed class PublicationLeaseSigningRequest
{
    private readonly byte[] input, network, hash;
    internal PublicationLeaseSigningRequest(ReadOnlySpan<byte> network, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> input)
    { this.network = network.ToArray(); this.hash = hash.ToArray(); this.input = input.ToArray(); }
    public ReadOnlyMemory<byte> NetworkId => network.ToArray();
    public ReadOnlyMemory<byte> OriginalRequestHash => hash.ToArray();
    public ReadOnlyMemory<byte> SigningInput => input.ToArray();
}

public interface IDeepIdV2PublicationLeaseWitnessSigner
{
    ReadOnlyMemory<byte> WitnessId { get; }
    ValueTask<ReadOnlyMemory<byte>> SignPublicationLeaseAsync(PublicationLeaseSigningRequest request, CancellationToken ct);
}

/// <summary>Fresh current permission over one immutable original intent.
/// Caller owns account/winner durability; no new generation or cipher is authored.</summary>
public static class DeepIdV2PublicationLeaseAuthor
{
    public static async ValueTask<PublicationLeaseWireRequest> AuthorRequestAsync(
        VerifiedDeepIdV2OwnedPublicationIntent intent, OwnedGenesisDeviceSecrets device, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(intent); ArgumentNullException.ThrowIfNull(device); ct.ThrowIfCancellationRequested();
        _ = await RecheckOwnedAsync(intent, ct).ConfigureAwait(false);
        var route = intent.Route;
        var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        var nonce = new byte[32]; var signature = new byte[64]; signature[^1] = 1;
        do RandomNumberGenerator.Fill(nonce); while (nonce.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        try
        {
            var fresh = route.Recipient.Freshness;
            var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite,
                intent.Request.LocatorHash);
            var expires = LeaseCeiling(route, intent.OwnedRequest, first.LowerUnixSeconds, placement);
            var candidate = DeepIdV2PublicationLeaseWireCodec.EncodeRequest(route.Network.NetworkId.Span, nonce,
                intent.OwnedRequest.RequestNonce.Span, intent.OwnedRequest.DirectoryLookupKey.Span,
                fresh.NextProtectedLkg.LogGeneration, fresh.NextProtectedLkg.CoreHash.Span, intent.Request.RequestHash.Span,
                placement.ViewHash.Span, first.LowerUnixSeconds, expires, signature);
            RequireRequest(route, intent.OwnedRequest, intent.Request, candidate, first);
            CryptographicOperations.ZeroMemory(signature);
            signature = device.SignCurrentPublicationLeaseRequest(candidate, intent);
            var signed = DeepIdV2PublicationLeaseWireCodec.EncodeRequest(route.Network.NetworkId.Span, nonce,
                intent.OwnedRequest.RequestNonce.Span, intent.OwnedRequest.DirectoryLookupKey.Span,
                fresh.NextProtectedLkg.LogGeneration, fresh.NextProtectedLkg.CoreHash.Span, intent.Request.RequestHash.Span,
                placement.ViewHash.Span, first.LowerUnixSeconds, expires, signature);
            _ = await RecheckOwnedAsync(intent, ct).ConfigureAwait(false);
            var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false); Continuous(first, final);
            RequireRequest(route, intent.OwnedRequest, intent.Request, signed, final); VerifyPublisher(route, signed);
            ct.ThrowIfCancellationRequested(); return signed;
        }
        finally { CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(signature); }
    }

    public static async ValueTask VerifyIssuerRequestAsync(VerifiedDeepIdV2IssuerPublicationIntent intent,
        PublicationLeaseWireRequest candidate, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(intent); ArgumentNullException.ThrowIfNull(candidate); ct.ThrowIfCancellationRequested();
        var request = DeepIdV2PublicationLeaseWireCodec.DecodeRequest(candidate.CanonicalBytes.Span);
        _ = await RecheckIssuerAsync(intent, ct).ConfigureAwait(false);
        var first = await intent.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequireRequest(intent.Route, intent.OwnedRequest, intent.Request, request, first); VerifyPublisher(intent.Route, request);
        var final = await intent.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false); Continuous(first, final);
        RequireRequest(intent.Route, intent.OwnedRequest, intent.Request, request, final); ct.ThrowIfCancellationRequested();
    }

    public static async ValueTask<ParsedDeepIdV2PublicationLease> AuthorThresholdAsync(
        VerifiedDeepIdV2IssuerPublicationIntent intent, PublicationLeaseWireRequest candidate,
        IReadOnlyList<IDeepIdV2PublicationLeaseWitnessSigner> witnesses, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(intent); ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(witnesses); ct.ThrowIfCancellationRequested();
        var request = DeepIdV2PublicationLeaseWireCodec.DecodeRequest(candidate.CanonicalBytes.Span);
        var count = witnesses.Count;
        if (count is < 2 or > 32) throw new CryptographicException("Publication lease witness count is invalid.");
        var authority = intent.Route.NetworkAuthority;
        var captured = new (IDeepIdV2PublicationLeaseWitnessSigner Signer, byte[] Id, byte[] Key)[count];
        var ids = new HashSet<string>(StringComparer.Ordinal); var domains = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < count; index++)
        {
            var signer = witnesses[index] ?? throw new CryptographicException("Publication lease witness is absent.");
            var id = signer.WitnessId.ToArray();
            if (id.Length != 32 || !ids.Add(Convert.ToHexString(id)))
                throw new CryptographicException("Publication lease witness identity is invalid or duplicated.");
            var key = authority.WitnessKeys.SingleOrDefault(value => Fixed(value.Id.Span, id)) ??
                throw new CryptographicException("Publication lease witness is not currently authorized.");
            domains.Add(Convert.ToHexString(key.FailureDomainHash.Span));
            captured[index] = (signer, id, key.Ed25519PublicKey.ToArray());
        }
        if (count < authority.WitnessThreshold || domains.Count < authority.WitnessThreshold)
            throw new CryptographicException("Publication lease lacks current independent witness threshold.");
        Array.Sort(captured, (left, right) => left.Id.AsSpan().SequenceCompareTo(right.Id));
        await VerifyIssuerRequestAsync(intent, request, ct).ConfigureAwait(false);
        var placement = ContactServicePlacementFactory.Create(intent.Route.Network,
            ContactServiceRequestKind.PublishInvite, intent.Request.LocatorHash);
        ReadOnlyMemory<byte>[] fields = [request.NetworkId, intent.Request.RequestHash, placement.ViewHash, placement.PlacementHash,
            U64(request.IssuedAtUnixSeconds), U64(request.ExpiresAtUnixSeconds),
            intent.Route.Recipient.Freshness.NextProtectedLkg.CoreHash, request.RequestNonce, intent.Request.CanonicalBytes, new byte[] { (byte)count }];
        var input = DeepIdV2PublicationLeaseCodec.UnsignedSigningInput(fields);
        var rows = new byte[count * 96];
        var signing = new PublicationLeaseSigningRequest(request.NetworkId.Span, intent.Request.RequestHash.Span, input);
        try
        {
            var first = await intent.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
            for (var index = 0; index < captured.Length; index++)
            {
                await VerifyIssuerRequestAsync(intent, request, ct).ConfigureAwait(false);
                var signature = (await captured[index].Signer.SignPublicationLeaseAsync(signing, ct).ConfigureAwait(false)).ToArray();
                try
                {
                    if (signature.Length != 64 || !PublicKeyAuth.VerifyDetached(signature, input, captured[index].Key))
                        throw new CryptographicException("Publication lease custody returned an invalid current signature.");
                    captured[index].Id.CopyTo(rows, index * 96); signature.CopyTo(rows, index * 96 + 32);
                }
                finally { CryptographicOperations.ZeroMemory(signature); }
                await VerifyIssuerRequestAsync(intent, request, ct).ConfigureAwait(false);
            }
            var lease = DeepIdV2PublicationLeaseCodec.Decode(DeepIdV2PublicationLeaseCodec.Encode([..fields, rows]));
            var final = await intent.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false); Continuous(first, final);
            await VerifyIssuerRequestAsync(intent, request, ct).ConfigureAwait(false);
            _ = await DeepIdV2PublicationLeaseVerifier.VerifyAsync(lease, authority, intent.Route.Recipient.Freshness,
                placement, intent.Route.TrustedPublicationTime, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); return lease;
        }
        finally { CryptographicOperations.ZeroMemory(input); CryptographicOperations.ZeroMemory(rows); }
    }

    public static async ValueTask<VerifiedXpa1PublicationAuthorization> VerifyOwnedResponseAsync(
        VerifiedDeepIdV2OwnedPublicationIntent intent, PublicationLeaseWireRequest candidate,
        ReadOnlyMemory<byte> exactLease, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(intent); ArgumentNullException.ThrowIfNull(candidate); ct.ThrowIfCancellationRequested();
        var request = DeepIdV2PublicationLeaseWireCodec.DecodeRequest(candidate.CanonicalBytes.Span);
        var lease = DeepIdV2PublicationLeaseCodec.Decode(exactLease.Span);
        DeepIdV2PublicationLeaseWireCodec.RequirePair(request, lease);
        if (!Fixed(intent.Request.CanonicalBytes.Span, lease.OriginalRequest.CanonicalBytes.Span))
            throw new CryptographicException("Publication lease replaced the exact protected original XPU.");
        _ = await RecheckOwnedAsync(intent, ct).ConfigureAwait(false);
        var first = await intent.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequireRequest(intent.Route, intent.OwnedRequest, intent.Request, request, first); VerifyPublisher(intent.Route, request);
        var placement = ContactServicePlacementFactory.Create(intent.Route.Network,
            ContactServiceRequestKind.PublishInvite, intent.Request.LocatorHash);
        var result = await DeepIdV2PublicationLeaseVerifier.VerifyAsync(lease, intent.Route.NetworkAuthority,
            intent.Route.Recipient.Freshness, placement, intent.Route.TrustedPublicationTime, ct).ConfigureAwait(false);
        var final = await intent.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false); Continuous(first, final);
        RequireRequest(intent.Route, intent.OwnedRequest, intent.Request, request, final);
        ct.ThrowIfCancellationRequested(); return result;
    }

    private static ValueTask<VerifiedDeepIdV2OwnedPublicationIntent> RecheckOwnedAsync(
        VerifiedDeepIdV2OwnedPublicationIntent intent, CancellationToken ct) =>
        DeepIdV2PublicationCommitVerifier.VerifyOwnedRetainedIntentAsync(intent.Route, intent.Contact,
            intent.OwnedRequest, intent.Request.CanonicalBytes, ct);
    private static ValueTask<VerifiedDeepIdV2IssuerPublicationIntent> RecheckIssuerAsync(
        VerifiedDeepIdV2IssuerPublicationIntent intent, CancellationToken ct) =>
        DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(intent.Route,
            intent.OwnedRequest, intent.Request.CanonicalBytes, ct);

    private static void RequireRequest(VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest owned,
        Xpu1Request original, PublicationLeaseWireRequest request, DeepIdV2ContactRouteTimeWindow window)
    {
        var freshness = route.Recipient.Freshness; var floor = freshness.NextProtectedLkg;
        var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite, original.LocatorHash);
        if (!Fixed(request.NetworkId.Span, route.Network.NetworkId.Span) || !Fixed(request.DirectoryLookupKey.Span, owned.DirectoryLookupKey.Span) ||
            !Fixed(request.OriginalCoordinationNonce.Span, owned.RequestNonce.Span) || !Fixed(request.OriginalRequestHash.Span, original.RequestHash.Span) ||
            !Fixed(request.ViewHash.Span, placement.ViewHash.Span) || request.MinimumDirectoryGeneration > floor.LogGeneration ||
            (request.MinimumDirectoryGeneration == floor.LogGeneration && !Fixed(request.MinimumDirectoryHash.Span, floor.CoreHash.Span)) ||
            request.IssuedAtUnixSeconds > window.LowerUnixSeconds || window.UpperUnixSeconds >= request.ExpiresAtUnixSeconds)
            throw new CryptographicException("Publication lease request is not exact current owned original intent.");
        if (request.ExpiresAtUnixSeconds > LeaseCeiling(route, owned, request.IssuedAtUnixSeconds, placement))
            throw new CryptographicException("Publication lease request exceeds current authority or inner resources.");
    }

    private static ulong LeaseCeiling(VerifiedDeepIdV2ContactRouteClosure route, ContactPublicationAuthorityWireRequest owned,
        ulong start, VerifiedContactServicePlacement placement)
    {
        var proof = route.Recipient.Freshness;
        var proofCeiling = checked(proof.TrustedLowerUnixSeconds + (proof.FreshnessDeadlineMonotonicSeconds - proof.MonotonicSample));
        return new[] { checked(start + 120), proofCeiling, proof.NextProtectedLkg.Head.ValidUntil,
            placement.ValidUntilUnixSeconds, route.Network.MaximumRecordExpiryUnixSeconds, route.NetworkAuthority.ExpiresAt,
            route.Recipient.Authorization.Record.ExpiresAtUnixSeconds, owned.EffectiveExpiresAtUnixSeconds,
            U64(route.Route.Authorization.Field(13).Span), U64(route.Route.Selection.Field(9).Span),
            U64(route.Route.Route.Field(18).Span), U64(route.Route.Successor.Field(11).Span), U64(route.Route.Reachability.Field(17).Span) }.Min();
    }
    private static void VerifyPublisher(VerifiedDeepIdV2ContactRouteClosure route, PublicationLeaseWireRequest request)
    {
        var dca = route.Recipient.Authorization;
        var device = dca.Binding.Identity.ActiveDevices.Single(value => Fixed(value.Certificate.DeviceId.Span, dca.Record.PublisherDeviceId.Span));
        var input = request.SigningInput.ToArray();
        try
        {
            if (!PublicKeyAuth.VerifyDetached(request.PublisherSignature.ToArray(), input, device.Certificate.DeviceEd25519PublicKey.ToArray()))
                throw new CryptographicException("Current owner did not sign the exact publication lease request.");
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }
    private static void Continuous(DeepIdV2ContactRouteTimeWindow first, DeepIdV2ContactRouteTimeWindow final)
    {
        if (!Fixed(first.BootId.Span, final.BootId.Span) || final.MonotonicSample < first.MonotonicSample ||
            final.LowerUnixSeconds < first.LowerUnixSeconds || final.UpperUnixSeconds < first.UpperUnixSeconds)
            throw new CryptographicException("Publication lease authoring crossed protected time continuity.");
    }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
