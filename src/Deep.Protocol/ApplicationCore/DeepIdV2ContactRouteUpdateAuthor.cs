using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.ApplicationCore;

/// <summary>Closed current-route author result. Not native/authored-counter
/// ownership, publication, peer consent, a committed event or dispatch permission.</summary>
public sealed class AuthoredVerifiedContactRouteUpdate
{
    internal AuthoredVerifiedContactRouteUpdate(ParsedDmc2 record)
    {
        Record = record;
        if (record.ParsedPayload is not ContactRouteUpdateDmc2Payload)
            throw new CryptographicException("The authored control is not ContactRouteUpdate.");
    }
    public ParsedDmc2 Record { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => Record.CanonicalBytes;
}

public static partial class ApplicationCoreCodec
{
    /// <summary>Frames the already signed current own publication route as one
    /// private successor control. Shared must independently supply the actual
    /// native-advertised predecessor, held account/counter and peer consent.
    /// Caller comparison selectors do not attest their origin.</summary>
    public static async ValueTask<AuthoredVerifiedContactRouteUpdate> AuthorVerifiedContactRouteUpdateAsync(
        VerifiedDeepIdV2ContactRouteClosure ownPublication,
        ParsedDeepIdV2ContactMailboxRoute originalOwnPackage,
        ReadOnlyMemory<byte> exactPreviousRoute, ReadOnlyMemory<byte> previousEventHash32,
        ReadOnlyMemory<byte> relationship32, ReadOnlyMemory<byte> conversation32,
        ReadOnlyMemory<byte> logicalMessage32, ulong senderClientSequence,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ownPublication); ArgumentNullException.ThrowIfNull(originalOwnPackage);
        ArgumentNullException.ThrowIfNull(trustedTime); cancellationToken.ThrowIfCancellationRequested();
        RequireNonzeroId(previousEventHash32.Span, "previous route event");
        RequireNonzeroId(relationship32.Span, "relationship");
        RequireNonzeroId(conversation32.Span, "conversation");
        RequireNonzeroId(logicalMessage32.Span, "logical message");
        if (senderClientSequence == 0 || senderClientSequence >= long.MaxValue ||
            exactPreviousRoute.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes)
            throw new ArgumentOutOfRangeException(nameof(senderClientSequence), "Private route control exceeds its closed counter/route bounds.");
        var previous = ContactRouteClosureCodec.Decode(exactPreviousRoute.Span);
        var predecessor = previousEventHash32.ToArray(); var relationship = relationship32.ToArray();
        var conversation = conversation32.ToArray(); var logical = logicalMessage32.ToArray();
        try
        {
            var first = await ownPublication.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
            var route = ownPublication.Route;
            var created = checked(first.UpperUnixSeconds * 1000);
            // DR-0122: the exact PMT snapshot authenticates assignment creation,
            // not the logical route's lifetime. ReadCurrentTimeAsync above and
            // the independent successor verifier below require current admitted
            // carriage/eligibility. Only the route's OWN signed windows bound
            // this control; an expired route itself still cannot be advertised.
            var routeEnd = new[] { (route.Reachability, 17), (route.Authorization, 13),
                (route.Route, 18), (route.Successor, 11), (route.Selection, 9) }
                .Min(part => BinaryPrimitives.ReadUInt64BigEndian(part.Item1.Field(part.Item2).Span));
            var expires = Math.Min(checked(routeEnd * 1000), checked(created + 7UL * 24 * 60 * 60 * 1000));
            if (expires <= created)
                throw new CryptographicException("Current publication has no private route-control lifetime.");
            var payload = CreateContactRouteUpdatePayloadCore(relationship,
                BinaryPrimitives.ReadUInt64BigEndian(route.Reachability.Field(3).Span), predecessor,
                route.Reachability, route.Authorization, route.Route, route.Successor, route.Projection, route.Selection);
            var recipient = ownPublication.Recipient;
            var record = AuthorDmc2Core(ownPublication.Network.NetworkId.Span, logical, conversation,
                recipient.Authorization.Binding.Record.DeepAccountId.Span, recipient.Authorization.Record.PublisherDeviceId.Span,
                senderClientSequence, created, expires, Dmc2Flags.None, [], payload);
            var verified = await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentSuccessorAsync(originalOwnPackage,
                recipient.Freshness, ownPublication.Network, ownPublication.NetworkAuthority, trustedTime,
                previous.ExactBytes, predecessor, relationship, conversation, record.CanonicalBytes, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(verified.ExactRouteClosure.Span, route.ExactBytes.Span))
                throw new CryptographicException("Private route control changed the exact adopted publication closure.");
            var final = await ownPublication.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
            if (final.MonotonicSample < first.MonotonicSample ||
                !CryptographicOperations.FixedTimeEquals(first.BootId.Span, final.BootId.Span))
                throw new CryptographicException("Private route-control author crossed protected clock continuity.");
            await verified.EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return new(record);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(predecessor); CryptographicOperations.ZeroMemory(relationship);
            CryptographicOperations.ZeroMemory(conversation); CryptographicOperations.ZeroMemory(logical);
        }
    }
}
