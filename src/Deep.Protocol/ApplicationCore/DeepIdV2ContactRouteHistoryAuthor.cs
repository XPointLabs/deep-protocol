using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ApplicationCore;

/// <summary>Closed count8 author result. Native identity/counters, consent,
/// original custody, durable adoption and dispatch remain separately owned.</summary>
public sealed class AuthoredVerifiedContactRouteHistoryControl
{
    internal AuthoredVerifiedContactRouteHistoryControl(ParsedDmc2 record) => Record = record;
    /// <summary>Exact immutable event to submit to the existing native authored owner.</summary>
    public ParsedDmc2 Record { get; }
    /// <summary>Canonical event bytes, with no implication of commitment.</summary>
    public ReadOnlyMemory<byte> CanonicalBytes => Record.CanonicalBytes;
}

public static partial class ApplicationCoreCodec
{
    /// <summary>Authors a private route announcement carrying the signed continuation of the original contact's XUR1.</summary>
    public static async ValueTask<AuthoredVerifiedContactRouteHistoryControl> AuthorVerifiedContactRouteHistoryRendezvousAnnouncementAsync(
        VerifiedDeepIdV2ContactRouteHistory endpoint, ReadOnlyMemory<byte> originalXur,
        IReadOnlyList<ReadOnlyMemory<byte>> successors, DeepIdV2CurrentContactAuthorization sender,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority, ReadOnlyMemory<byte> logicalMessage32,
        ulong senderClientSequence, OnionTrustedTimeAuthority time, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint); ArgumentNullException.ThrowIfNull(successors);
        ArgumentNullException.ThrowIfNull(sender);
        cancellationToken.ThrowIfCancellationRequested();
        int count = successors.Count;
        var anchor = endpoint.OriginalRendezvous;
        if (!CryptographicOperations.FixedTimeEquals(anchor.Span, originalXur.Span) ||
            count is < 1 or > DeepIdV2ContactRouteHistoryCodec.MaximumRendezvousSuccessors)
            throw new CryptographicException("Rendezvous announcement lost its native contact anchor or exceeds capacity.");
        var header = HistoryPayload(endpoint, endpoint, DeepIdV2ContactRouteHistoryMode.Announcement, new byte[32], []).Exact;
        var bytes = new byte[header.Length + 2 + count * 538];
        header.CopyTo(bytes, 0); bytes[72] = 9;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(header.Length), checked((ushort)count));
        var offset = header.Length + 2;
        for (var i = 0; i < count; i++, offset += 538)
        {
            var record = successors[i];
            if (record.Length != 538) throw new CryptographicException("Invalid rendezvous record size.");
            record.Span.CopyTo(bytes.AsSpan(offset, 538));
        }
        var payload = DeepIdV2ContactRouteHistoryCodec.Decode(bytes, endpoint.Original.NetworkId.Span);
        _ = await DeepIdV2ContactUpdateRendezvousVerifier.VerifySuccessorChainAsync(anchor, anchor,
            payload.RendezvousSuccessors, sender.Freshness, network, time, cancellationToken).ConfigureAwait(false);
        var message = await AuthorHistoryControlCoreAsync(payload, sender, network, authority, endpoint.Original.ConversationId,
            logicalMessage32, senderClientSequence, time, cancellationToken, endpoint).ConfigureAwait(false);
        _ = await DeepIdV2ContactRouteUpdateVerifier.VerifyHistoryPageAsync(endpoint, message.CanonicalBytes,
            sender.Freshness, network, authority, time, cancellationToken).ConfigureAwait(false);
        _ = await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentHistoryAnnouncementAsync(endpoint, message.CanonicalBytes,
            sender.Freshness, network, authority, time, cancellationToken).ConfigureAwait(false);
        return new(message);
    }
    /// <summary>Reads a prospective announcement expiry from the same current signed ceilings as the author. This planning scalar grants no authoring or delivery permission.</summary>
    /// <param name="endpoint">The independently verified exact endpoint to announce.</param>
    /// <param name="sender">Current sender authorization.</param>
    /// <param name="network">Current verified network.</param>
    /// <param name="authority">The network authority.</param>
    /// <param name="time">Independent trusted time.</param>
    /// <param name="cancellationToken">Cancellation for this read.</param>
    /// <returns>A prospective expiry in Unix milliseconds. Actual authoring must independently recheck it.</returns>
    public static async ValueTask<ulong> ReadVerifiedContactRouteHistoryAnnouncementExpiryAsync(
        VerifiedDeepIdV2ContactRouteHistory endpoint, DeepIdV2CurrentContactAuthorization sender,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority time, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint); ArgumentNullException.ThrowIfNull(sender);
        ArgumentNullException.ThrowIfNull(network); ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(time);
        var first = await DeepIdV2RouteContext.ReadAsync(sender, network, authority, time, cancellationToken).ConfigureAwait(false);
        var expires = HistoryControlExpiryMilliseconds(DeepIdV2ContactRouteHistoryMode.Announcement,
            first, sender, network, endpoint);
        var final = await first.RecheckAsync(cancellationToken).ConfigureAwait(false);
        DeepIdV2ContactRouteUpdateVerifier.RequireCurrentRoute(endpoint.Completed, final);
        if (checked(final.Upper * 1000) >= expires)
            throw new CryptographicException("History expiry planning lost its current control lifetime.");
        cancellationToken.ThrowIfCancellationRequested(); return expires;
    }

    /// <summary>Authors a bounded page or endpoint announcement exclusively from
    /// independently verified public originals. A request hash supplies correlation only.</summary>
    public static async ValueTask<AuthoredVerifiedContactRouteHistoryControl> AuthorVerifiedContactRouteHistoryPageAsync(
        VerifiedDeepIdV2ContactRouteHistory before, IReadOnlyList<VerifiedDeepIdV2ContactRouteHistoryStep> steps,
        bool announceEndpoint, ReadOnlyMemory<byte> requestEventHash32,
        DeepIdV2CurrentContactAuthorization sender, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ReadOnlyMemory<byte> logicalMessage32,
        ulong senderClientSequence, OnionTrustedTimeAuthority time, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(before); ArgumentNullException.ThrowIfNull(steps);
        var count = steps.Count;
        if (count < 0 || count > DeepIdV2ContactRouteHistoryCodec.MaximumAtoms || (!announceEndpoint && count == 0))
            throw new CryptographicException("History page needs one to three atoms or an endpoint announcement.");
        if (requestEventHash32.Length != 32) throw new CryptographicException("History correlation must be exactly32 bytes.");
        var ownedSteps = new VerifiedDeepIdV2ContactRouteHistoryStep[count];
        for (var index = 0; index < count; index++)
            ownedSteps[index] = steps[index] ?? throw new ArgumentException("History step cannot be null.", nameof(steps));
        var after = before;
        foreach (var step in ownedSteps)
        {
            if (!SameHistory(after, step.Before)) throw new CryptographicException("History page steps do not join exact authenticated originals.");
            after = step.After;
        }
        var mode = ownedSteps.Length == 0 ? DeepIdV2ContactRouteHistoryMode.Announcement :
            announceEndpoint ? DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement : DeepIdV2ContactRouteHistoryMode.Evidence;
        // The aggregate is closed before any clock/provider operation or event authoring.
        var payload = HistoryPayload(before, after, mode, requestEventHash32.Span, ownedSteps);
        var record = await AuthorHistoryControlCoreAsync(payload, sender, network, authority,
            before.Original.ConversationId, logicalMessage32, senderClientSequence, time, cancellationToken,
            announceEndpoint ? after : null).ConfigureAwait(false);
        var verified = await DeepIdV2ContactRouteUpdateVerifier.VerifyHistoryPageAsync(before, record.CanonicalBytes,
            sender.Freshness, network, authority, time, cancellationToken).ConfigureAwait(false);
        if (!SameHistory(after, verified)) throw new CryptographicException("Authored history changed its exact verified endpoint.");
        if (announceEndpoint)
            _ = await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentHistoryAnnouncementAsync(after, record.CanonicalBytes,
                sender.Freshness, network, authority, time, cancellationToken).ConfigureAwait(false);
        return new(record);
    }

    /// <summary>Authors mode4 from verified actual C/P selected by the native owner.
    /// Request lifetime derives from current sender authority, never the retained old route.</summary>
    public static async ValueTask<AuthoredVerifiedContactRouteHistoryControl> AuthorVerifiedContactRouteHistoryRequestAsync(
        VerifiedDeepIdV2ContactRouteHistory progress, DeepIdV2CurrentContactAuthorization sender,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> logicalMessage32, ulong senderClientSequence,
        OnionTrustedTimeAuthority time, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(progress);
        var payload = HistoryPayload(progress, progress, DeepIdV2ContactRouteHistoryMode.HistoryRequest, new byte[32], []);
        return new(await AuthorHistoryControlCoreAsync(payload, sender, network, authority,
            progress.Original.ConversationId, logicalMessage32, senderClientSequence, time, cancellationToken).ConfigureAwait(false));
    }

    private static async ValueTask<ParsedDmc2> AuthorHistoryControlCoreAsync(ContactRouteHistoryDmc2Payload payload,
        DeepIdV2CurrentContactAuthorization sender, VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> conversation32, ReadOnlyMemory<byte> logicalMessage32, ulong sequence,
        OnionTrustedTimeAuthority time, CancellationToken ct, VerifiedDeepIdV2ContactRouteHistory? announcement = null)
    {
        RequireNonzeroId(logicalMessage32.Span, "logical message");
        if (sequence == 0 || sequence >= long.MaxValue) throw new ArgumentOutOfRangeException(nameof(sequence));
        var logical = logicalMessage32.ToArray(); var conversation = conversation32.ToArray();
        var first = await DeepIdV2RouteContext.ReadAsync(sender, network, authority, time, ct).ConfigureAwait(false);
        var created = checked(first.Upper * 1000);
        var expires = HistoryControlExpiryMilliseconds(payload.Mode, first, sender, network, announcement);
        var result = AuthorDmc2Core(network.NetworkId.Span, logical, conversation,
            sender.Authorization.Binding.Record.DeepAccountId.Span, sender.Authorization.Record.PublisherDeviceId.Span,
            sequence, created, expires, Dmc2Flags.None, [], payload);
        var final = await first.RecheckAsync(ct).ConfigureAwait(false);
        if (checked(final.Upper * 1000) >= expires) throw new CryptographicException("History author lost current control lifetime.");
        if (announcement is not null) DeepIdV2ContactRouteUpdateVerifier.RequireCurrentRoute(announcement.Completed, final);
        ct.ThrowIfCancellationRequested(); return result;
    }

    private static ulong HistoryControlExpiryMilliseconds(DeepIdV2ContactRouteHistoryMode mode,
        DeepIdV2RouteContext first, DeepIdV2CurrentContactAuthorization sender,
        VerifiedOnionNetworkContext network, VerifiedDeepIdV2ContactRouteHistory? announcement)
    {
        var maximumLifetimeSeconds = mode is DeepIdV2ContactRouteHistoryMode.Announcement or
            DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement ? 3_600UL : 120UL;
        // The nonce-bound proof must be current for authoring and its final
        // recheck. Its deadline is not the retained control's event lifetime.
        var expiry = Math.Min(first.LogicalRecordExpiryCeiling, Math.Min(network.MaximumRecordExpiryUnixSeconds,
            Math.Min(network.Closure!.View.ExpiresAt, checked(first.Lower + maximumLifetimeSeconds))));
        expiry = Math.Min(expiry, sender.Freshness.NextProtectedLkg.Head.ValidUntil);
        if (announcement is not null)
        {
            DeepIdV2ContactRouteUpdateVerifier.RequireCurrentRoute(announcement.Completed, first);
            expiry = Math.Min(expiry, new[] { (announcement.Completed.Authorization, 13), (announcement.Completed.Reachability, 17),
                (announcement.Completed.Route, 18), (announcement.Completed.Successor, 11), (announcement.Completed.Selection, 9) }
                .Min(part => DeepIdV2RouteContext.U64(part.Item1.Field(part.Item2).Span)));
        }
        var expires = checked(expiry * 1000);
        if (expires <= checked(first.Upper * 1000)) throw new CryptographicException("Current authority cannot cover a fresh history control.");
        return expires;
    }

    private static bool SameHistory(VerifiedDeepIdV2ContactRouteHistory a, VerifiedDeepIdV2ContactRouteHistory b) =>
        a.OriginalAnchorHash.Span.SequenceEqual(b.OriginalAnchorHash.Span) && a.Cursor.Span.SequenceEqual(b.Cursor.Span) &&
        a.ExactCompletedXir1V2.Span.SequenceEqual(b.ExactCompletedXir1V2.Span) && a.ExactCompletedRoute.Span.SequenceEqual(b.ExactCompletedRoute.Span);

    private static ContactRouteHistoryDmc2Payload HistoryPayload(VerifiedDeepIdV2ContactRouteHistory before,
        VerifiedDeepIdV2ContactRouteHistory after, DeepIdV2ContactRouteHistoryMode mode, ReadOnlySpan<byte> correlation,
        IReadOnlyList<VerifiedDeepIdV2ContactRouteHistoryStep> steps)
    {
        var length = checked(1024 + steps.Sum(step => checked(4 + step.Atom.Exact.Length)));
        if (length > DeepIdV2ContactRouteHistoryCodec.MaximumPayloadBytes)
            throw new CryptographicException("History aggregate exceeds the unchanged payload capacity; pack fewer atoms.");
        var bytes = new byte[length]; before.Relationship.Span.CopyTo(bytes); after.Cursor.Span[..8].CopyTo(bytes.AsSpan(32));
        before.OriginalAnchorHash.Span.CopyTo(bytes.AsSpan(40)); bytes[72] = 8; bytes[73] = 1; bytes[74] = (byte)mode;
        bytes[75] = checked((byte)steps.Count); before.Cursor.Span.CopyTo(bytes.AsSpan(80)); after.Cursor.Span.CopyTo(bytes.AsSpan(192));
        before.Invite.CanonicalBytes.Span.CopyTo(bytes.AsSpan(304)); correlation.CopyTo(bytes.AsSpan(915)); var offset = 1024;
        foreach (var step in steps)
        {
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset), checked((uint)step.Atom.Exact.Length)); offset += 4;
            step.Atom.Exact.CopyTo(bytes, offset); offset += step.Atom.Exact.Length;
        }
        return DeepIdV2ContactRouteHistoryCodec.Decode(bytes, before.Original.NetworkId.Span);
    }
}
