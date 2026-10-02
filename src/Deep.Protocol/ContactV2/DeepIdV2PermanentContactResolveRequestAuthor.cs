using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

public static class DeepIdV2PermanentContactResolveRequestAuthor
{
    public static async ValueTask<Xiq1Request> AuthorAsync(DeepPermanentIdV2 descriptor,
        DeepIdV2CurrentContactAuthorization requester, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, OnionTrustedTimeAuthority trustedTime,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor); ArgumentNullException.ThrowIfNull(requester);
        ArgumentNullException.ThrowIfNull(network); ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(trustedTime); ct.ThrowIfCancellationRequested();
        using var resolution = DeepIdV2PermanentContactResolutionDerivation.DeriveFromDescriptor(network.NetworkId.Span, descriptor);
        var first = await DeepIdV2RouteContext.ReadAsync(requester, network, authority, trustedTime, ct).ConfigureAwait(false);
        var placement = ContactServicePlacementFactory.Create(network, ContactServiceRequestKind.ResolveInvite, resolution.LocatorHash);
        var expiry = new[] { checked(first.Lower + 120), placement.ValidUntilUnixSeconds,
            network.MaximumRecordExpiryUnixSeconds, authority.ExpiresAt, requester.Authorization.Record.ExpiresAtUnixSeconds }.Min();
        first.Covers(first.Lower, expiry);
        var operation = new byte[32];
        try
        {
            do RandomNumberGenerator.Fill(operation); while (operation.AsSpan().IndexOfAnyExcept((byte)0) < 0);
            var encoded = Xiq1Codec.Encode(network.NetworkId.Span, operation, placement.ViewHash.Span,
                placement.PlacementHash.Span, first.Lower, expiry, resolution.LocatorHash.Span,
                0, Xiq1AntiSpamTokenType.None, [], ContactServicePaddingClass.Bytes16384);
            var final = await first.RecheckAsync(ct).ConfigureAwait(false); final.Covers(first.Lower, expiry);
            ct.ThrowIfCancellationRequested(); return Xiq1Codec.Decode(encoded);
        }
        finally { CryptographicOperations.ZeroMemory(operation); }
    }
}
