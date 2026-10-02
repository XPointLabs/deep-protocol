using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Immutable untrusted private route framing. Parsing is not message
/// authentication, publication, contact consent, a grant or dispatch authority.</summary>
public sealed class ParsedDeepIdV2ContactMailboxRoute
{
    private readonly byte[] exact;
    internal ParsedDeepIdV2ContactMailboxRoute(ReadOnlySpan<byte> exact,
        ParsedDca1V2 authorization, ParsedXir1V2 invite, ParsedContactRouteClosure route)
    { this.exact = exact.ToArray(); Authorization = authorization; Invite = invite; Route = route; }
    public ReadOnlyMemory<byte> ExactBytes => exact.ToArray();
    public ParsedDca1V2 Authorization { get; }
    public ParsedXir1V2 Invite { get; }
    public ParsedContactRouteClosure Route { get; }
}

/// <summary>DR-0062 private substructure only; not a standalone service record
/// or an activation of a changed Hello/Accept wire.</summary>
public static class DeepIdV2ContactMailboxRouteCodec
{
    public const int PrefixBytes = 1092;
    public const int MinimumBytes = PrefixBytes + ContactRouteClosureCodec.MinimumEncodedBytes;
    public const int MaximumBytes = PrefixBytes + ContactRouteClosureCodec.MaximumEncodedBytes;

    /// <summary>Frames already verified records. The runtime must still obtain
    /// them from its actual own publication; this does not attest their origin.</summary>
    public static byte[] Encode(VerifiedDeepIdV2ContactRouteClosure route)
    {
        ArgumentNullException.ThrowIfNull(route);
        var closure = route.ExactRouteClosure;
        var exact = new byte[checked(PrefixBytes + closure.Length)];
        BinaryPrimitives.WriteUInt16BigEndian(exact, 2);
        route.Recipient.Authorization.Record.CanonicalBytes.Span.CopyTo(exact.AsSpan(4, 473));
        route.ExactXir1V2.Span.CopyTo(exact.AsSpan(477, 611));
        BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(1088, 4), checked((uint)closure.Length));
        closure.Span.CopyTo(exact.AsSpan(PrefixBytes));
        _ = Decode(exact);
        return exact;
    }

    public static ParsedDeepIdV2ContactMailboxRoute Decode(ReadOnlySpan<byte> exact)
    {
        // Bound all framing before inner codecs can allocate any record copies.
        if (exact.Length is < MinimumBytes or > MaximumBytes ||
            BinaryPrimitives.ReadUInt16BigEndian(exact) != 2 ||
            BinaryPrimitives.ReadUInt16BigEndian(exact[2..]) != 0 ||
            BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(1088, 4)) != exact.Length - PrefixBytes)
            throw new CryptographicException("The private DID2 mailbox route has noncanonical framing.");
        var dca = DeepIdV2ContactAuthorizationCodec.Decode(exact.Slice(4, 473));
        var invite = DeepIdV2InviteRendezvousCodec.Decode(exact.Slice(477, 611));
        var route = ContactRouteClosureCodec.Decode(exact[PrefixBytes..]);
        var dcaReference = new ContactArtifactReference(ProtocolMagic.DCA1, 2, dca.RecordHash.Span);
        var advertisementReference = ContactCodec.ArtifactReference(ProtocolMagic.XRA1, route.Authorization);
        if (!Fixed(dca.NetworkId.Span, invite.Field(1).Span) ||
            !Fixed(dca.NetworkId.Span, route.Reachability.Field(1).Span) ||
            !Fixed(dca.PublisherDeviceId.Span, route.Authorization.Field(14).Span) ||
            !Fixed(invite.Field(16).Span, dcaReference.CanonicalBytes.Span) ||
            !Fixed(invite.Field(18).Span, advertisementReference.CanonicalBytes.Span))
            throw new CryptographicException("The private DID2 mailbox route mixes delegation, invite or route scope.");
        return new(exact, dca, invite, route);
    }

    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}

/// <summary>Current peer-relative route verification, not authenticated event
/// origin, publication, consent, holder custody or a dispatch/ACK capability.</summary>
public sealed class VerifiedDeepIdV2ContactMailboxRoute
{
    private readonly byte[] locator;
    internal VerifiedDeepIdV2ContactMailboxRoute(ParsedDeepIdV2ContactMailboxRoute package,
        VerifiedDeepIdV2ContactRouteClosure route, byte[] locator)
    { Package = package; Route = route; this.locator = locator.ToArray(); }
    public ParsedDeepIdV2ContactMailboxRoute Package { get; }
    public VerifiedDeepIdV2ContactRouteClosure Route { get; }
    public ReadOnlyMemory<byte> LocatorHash => locator.ToArray();
}

public static class DeepIdV2ContactMailboxRouteVerifier
{
    public static async ValueTask<VerifiedDeepIdV2ContactMailboxRoute> VerifyAsync(
        ParsedDeepIdV2ContactMailboxRoute package, VerifiedDeepIdV2DirectoryFreshness currentPeerFreshness,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(package); ArgumentNullException.ThrowIfNull(currentPeerFreshness);
        ArgumentNullException.ThrowIfNull(network); ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(trustedTime); cancellationToken.ThrowIfCancellationRequested();
        var checkpoint = currentPeerFreshness.CurrentCheckpoint ??
            throw new CryptographicException("A private mailbox route requires an independent current DID2 peer checkpoint.");
        var dca = DeepIdV2ContactAuthorizationCodec.Verify(package.Authorization, checkpoint.Binding, checkpoint.Directory);
        var first = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(currentPeerFreshness, dca,
            first.BootId.Span, first.SampleSeconds);
        var route = await DeepIdV2ContactRouteVerifier.VerifyAsync(recipient, network, authority,
            package.Invite.CanonicalBytes, package.Route.ExactBytes, trustedTime, cancellationToken).ConfigureAwait(false);
        var final = await route.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
        if (final.MonotonicSample < first.SampleSeconds ||
            !CryptographicOperations.FixedTimeEquals(final.BootId.Span, first.BootId.Span))
            throw new CryptographicException("Private mailbox route verification crossed a protected clock discontinuity.");
        cancellationToken.ThrowIfCancellationRequested();
        var locator = DeepIdV2PermanentContactResolutionDerivation.ComputeLocator(network.NetworkId.Span,
            checkpoint.Binding.DeepId.RecordHash.Span);
        return new(package, route, locator);
    }
}
