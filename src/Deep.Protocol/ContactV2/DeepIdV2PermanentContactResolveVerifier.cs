using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Bounded descriptor-authenticated decryption only. Not verified
/// identity, current directory, a published contact, consent or mailbox authority.</summary>
public sealed class ParsedDeepIdV2PermanentContactCandidate
{
    internal ParsedDeepIdV2PermanentContactCandidate(DeepPermanentIdV2 address,
        Xiq1Request request, Xis1Result result, ParsedDcr1V2 contact)
    { Address = address; Request = request; Result = result; Contact = contact; ExactDid2 = DeepIdV2Codec.DecodeDid2(contact.Bundle.Field(23).Span); }
    public DeepPermanentIdV2 Address { get; }
    public Xiq1Request Request { get; }
    public Xis1Result Result { get; }
    public ParsedDcr1V2 Contact { get; }
    public ParsedDid2 ExactDid2 { get; }
}

/// <summary>Current DID2 identity/support and two-replica permanent read.
/// Not account persistence, acceptance, a prekey claim, a grant or delivery.</summary>
public sealed class VerifiedDeepIdV2PermanentContactResolveClosure
{
    internal VerifiedDeepIdV2PermanentContactResolveClosure(
        ParsedDeepIdV2PermanentContactCandidate candidate, VerifiedDeepIdV2ContactRouteClosure route,
        VerifiedDevice publisher, VerifiedContactServicePlacement placement)
    { Candidate = candidate; Route = route; PublisherDevice = publisher; Placement = placement; }
    public ParsedDeepIdV2PermanentContactCandidate Candidate { get; }
    public ParsedDcr1V2 Contact => Candidate.Contact;
    public VerifiedDeepIdV2ContactRouteClosure Route { get; }
    public DeepIdV2CurrentContactAuthorization Authorization => Route.Recipient;
    public VerifiedDevice PublisherDevice { get; }
    public VerifiedContactServicePlacement Placement { get; }
    public ulong PublicationGeneration => U64(Candidate.Result.Field(16).Span);
    public ulong PublicationExpiresAtUnixSeconds => U64(Candidate.Result.Field(17).Span);
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
}

public static class DeepIdV2PermanentContactResolveVerifier
{
    public const int ExactRequestBytes = 312;
    public const int MaximumResultBytes = 131_072;

    public static ParsedDeepIdV2PermanentContactCandidate OpenCandidate(
        DeepPermanentIdV2 descriptor, ReadOnlyMemory<byte> exactXiq1, ReadOnlyMemory<byte> exactXis1)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (exactXiq1.Length != ExactRequestBytes || exactXis1.Length is < 256 or > MaximumResultBytes)
            throw new CryptographicException("Permanent DID2 resolver framing exceeds its closed bounds.");
        var request = Xiq1Codec.Decode(exactXiq1.Span);
        var result = Xis1Codec.Decode(exactXis1.Span, request.CanonicalBytes.Span);
        if (result.Status != Xis1Status.Success || result.MutationOutcome != ContactServiceMutationOutcome.None ||
            result.RetryAfterSeconds != 0 || result.Field(22).Length != 193 || !result.Field(23).IsEmpty ||
            request.RequestedGeneration != 0 || U64(result.Field(16).Span) != 0)
            throw new CryptographicException("Only a non-consuming DID2 reusable genesis read is accepted.");
        using var resolution = DeepIdV2PermanentContactResolutionDerivation.DeriveFromDescriptor(request.NetworkId.Span, descriptor);
        if (!Fixed(resolution.LocatorHash.Span, request.LocatorHash.Span))
            throw new CryptographicException("Permanent read uses another descriptor/network locator.");
        var contact = DeepIdV2ResolverObjectProtection.OpenForDescriptor(
            result.Field(19).Span, request.NetworkId.Span, descriptor, resolution);
        var bundle = contact.Bundle;
        if (U64(bundle.Field(8).Span) != U64(result.Field(16).Span) ||
            U64(bundle.Field(18).Span) != U64(result.Field(17).Span) ||
            BinaryPrimitives.ReadUInt32BigEndian(bundle.Field(16).Span) != 9 ||
            DeepIdV2InviteRendezvousCodec.Decode(bundle.Field(14).Span[40..]).Field(9).Span[0] != 1)
            throw new CryptographicException("Resolved publication differs from the exact signed reusable object.");
        return new(descriptor, request, result, contact);
    }

    public static async ValueTask<VerifiedDeepIdV2PermanentContactResolveClosure> VerifyAsync(
        ParsedDeepIdV2PermanentContactCandidate candidate, VerifiedDeepIdV2DirectoryFreshness freshness,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority trustedTime, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(candidate); ArgumentNullException.ThrowIfNull(freshness);
        ArgumentNullException.ThrowIfNull(network); ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(trustedTime); ct.ThrowIfCancellationRequested();
        var checkpoint = freshness.CurrentCheckpoint ??
            throw new CryptographicException("Permanent contact requires a current DID2 directory checkpoint.");
        if (!candidate.Address.MatchesExactCredential(checkpoint.Binding.DeepId) ||
            !Fixed(candidate.ExactDid2.CanonicalBytes.Span, checkpoint.Binding.DeepId.CanonicalBytes.Span) ||
            !Fixed(candidate.Request.NetworkId.Span, network.NetworkId.Span))
            throw new CryptographicException("Current directory does not bind the exact requested DID2.");
        var parsedDca = DeepIdV2ContactAuthorizationCodec.Decode(candidate.Contact.Bundle.Field(6).Span);
        var dca = DeepIdV2ContactAuthorizationCodec.Verify(parsedDca, checkpoint.Binding, checkpoint.Directory);
        var first = await trustedTime.ReadCurrentAsync(ct).ConfigureAwait(false);
        var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(freshness, dca, first.BootId.Span, first.SampleSeconds);
        var context = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, trustedTime, ct).ConfigureAwait(false);
        if (!Fixed(first.BootId.Span, context.Reading.BootId.Span) || context.Reading.SampleSeconds < first.SampleSeconds)
            throw new CryptographicException("Permanent resolution crossed its initial monotonic sample.");
        RequireTime(candidate, context.Lower, context.Upper);
        var placement = ContactServicePlacementFactory.Create(network, ContactServiceRequestKind.ResolveInvite, candidate.Request.LocatorHash);
        if (!Fixed(placement.ViewHash.Span, candidate.Request.ViewHash.Span) ||
            !Fixed(placement.PlacementHash.Span, candidate.Request.PlacementHash.Span) ||
            candidate.Request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds)
            throw new CryptographicException("Permanent resolver request uses another current placement.");
        VerifyReceipts(candidate, placement);
        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(candidate.Contact, dca, context.Upper);
        var route = await DeepIdV2ContactRouteVerifier.VerifyAsync(recipient, network, authority,
            candidate.Contact.Bundle.Field(14)[40..], candidate.Result.Field(21), trustedTime, ct).ConfigureAwait(false);
        var release = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        DeepIdV2ContactRouteVerifier.RequireBundleIssuanceAnchor(route, candidate.Contact.Bundle);
        if (release.LowerUnixSeconds < context.Lower || release.UpperUnixSeconds < context.Upper)
            throw new CryptographicException("Permanent resolution crossed trusted time continuity.");
        RequireTime(candidate, release.LowerUnixSeconds, release.UpperUnixSeconds);
        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(candidate.Contact, dca, release.UpperUnixSeconds);
        var final = await trustedTime.ReadCurrentAsync(ct).ConfigureAwait(false);
        if (!Fixed(first.BootId.Span, final.BootId.Span) || final.SampleSeconds < first.SampleSeconds)
            throw new CryptographicException("Permanent resolution crossed monotonic continuity.");
        var finalContext = DeepIdV2RouteContext.VerifyAtReading(recipient, network, authority, trustedTime, final, ct);
        if (finalContext.Lower < release.LowerUnixSeconds || finalContext.Upper < release.UpperUnixSeconds)
            throw new CryptographicException("Permanent resolution reversed its release-time interval.");
        DeepIdV2ContactRouteVerifier.RequireBindings(route.Invite, route.Route, finalContext);
        RequireTime(candidate, finalContext.Lower, finalContext.Upper);
        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(candidate.Contact, dca, finalContext.Upper);
        var publisher = checkpoint.Binding.Identity.ActiveDevices.Single(value =>
            Fixed(value.Certificate.DeviceId.Span, parsedDca.PublisherDeviceId.Span));
        ct.ThrowIfCancellationRequested(); return new(candidate, route, publisher, placement);
    }

    private static void RequireTime(ParsedDeepIdV2PermanentContactCandidate candidate, ulong lower, ulong upper)
    {
        var request = candidate.Request; var bundle = candidate.Contact.Bundle;
        if (lower > upper || request.IssuedAtUnixSeconds > lower || upper >= request.ExpiresAtUnixSeconds ||
            request.ExpiresAtUnixSeconds - request.IssuedAtUnixSeconds > 120 ||
            U64(bundle.Field(17).Span) > lower || upper >= U64(bundle.Field(18).Span))
            throw new CryptographicException("Permanent read/object does not cover the complete current trusted interval.");
        // XIS serverTime is unsigned by the neutral read transcript. Never use
        // it to mint/extend identity or freshness, even when it looks plausible.
    }

    private static void VerifyReceipts(ParsedDeepIdV2PermanentContactCandidate candidate, VerifiedContactServicePlacement placement)
    {
        var request = candidate.Request; var result = candidate.Result;
        var tuple = new byte[144]; request.RequestHash.Span.CopyTo(tuple);
        request.LocatorHash.Span.CopyTo(tuple.AsSpan(32)); result.Field(16).Span.CopyTo(tuple.AsSpan(64));
        result.Field(17).Span.CopyTo(tuple.AsSpan(72)); result.Field(18).Span.CopyTo(tuple.AsSpan(80));
        result.Field(20).Span.CopyTo(tuple.AsSpan(112));
        var input = ContactCodec.SignatureInput("Deep/ContactResolver/V1/resolve-read", tuple);
        var rows = result.Field(22).ToArray();
        try
        {
            var selected = placement.RankedReplicaNodeIds.Select(id => Convert.ToHexString(id.Span)).ToHashSet(StringComparer.Ordinal);
            if (selected.Count != 2 || rows.Length != 193 || rows[0] != 2)
                throw new CryptographicException("Permanent read needs both distinct selected resolvers.");
            for (var i = 0; i < 2; i++)
            {
                var id = rows.AsSpan(1 + i * 96, 32);
                if (!selected.Remove(Convert.ToHexString(id)) ||
                    !PublicKeyAuth.VerifyDetached(rows.AsSpan(33 + i * 96, 64).ToArray(), input,
                        placement.Network.ResolveNodeIdentityPublicKey(id.ToArray()).ToArray()))
                    throw new CryptographicException("Permanent read replica selection/signature is invalid.");
            }
            if (selected.Count != 0) throw new CryptographicException("Permanent read lacks a selected resolver.");
        }
        finally { CryptographicOperations.ZeroMemory(tuple); CryptographicOperations.ZeroMemory(input); }
    }
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
