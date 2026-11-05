using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

public static partial class DeepIdV2ContactUpdateRendezvousVerifier
{
    /// <summary>Authenticates a continuation against the original native contact and its independently retained head, then verifies the final record at current trusted time.</summary>
    public static async ValueTask<VerifiedDeepIdV2ContactUpdateRendezvous> VerifySuccessorChainAsync(
        ReadOnlyMemory<byte> originalXur, ReadOnlyMemory<byte> acceptedHead, IReadOnlyList<ReadOnlyMemory<byte>> successors,
        VerifiedDeepIdV2DirectoryFreshness freshness, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        var tip = await VerifyChainAsync(originalXur, acceptedHead, successors, freshness, network, authority,
            null, trustedTime, cancellationToken).ConfigureAwait(false);
        return new(tip, freshness);
    }

    /// <summary>Verifies an authenticated native event's chain at its creation time. Historical verification cannot provide a live capability.</summary>
    public static async ValueTask VerifyRecordedSuccessorChainAsync(ReadOnlyMemory<byte> originalXur,
        ReadOnlyMemory<byte> acceptedHead, IReadOnlyList<ReadOnlyMemory<byte>> successors,
        VerifiedDeepIdV2DirectoryFreshness freshness, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ulong eventCreatedAtUnixSeconds, OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        _ = await VerifyChainAsync(originalXur, acceptedHead, successors, freshness, network, authority,
            eventCreatedAtUnixSeconds, trustedTime, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<ContactRecord> VerifyChainAsync(ReadOnlyMemory<byte> genesisBytes,
        ReadOnlyMemory<byte> acceptedHead, IReadOnlyList<ReadOnlyMemory<byte>> successors,
        VerifiedDeepIdV2DirectoryFreshness freshness, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ulong? historicalTime, OnionTrustedTimeAuthority trustedTime, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(freshness); ArgumentNullException.ThrowIfNull(network); ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(trustedTime); ArgumentNullException.ThrowIfNull(successors);
        ct.ThrowIfCancellationRequested();
        int count = successors.Count;
        if (genesisBytes.Length != 538 || acceptedHead.Length != 538 ||
            count < 1 || count > DeepIdV2ContactRouteHistoryCodec.MaximumRendezvousSuccessors)
            throw new ArgumentException("Invalid rendezvous chain bounds.");
        var genesis = ContactCodec.Decode(ProtocolMagic.XUR1, genesisBytes.Span);
        var records = new ContactRecord[count];
        bool includesAcceptedHead = Fixed(genesis.CanonicalSpan, acceptedHead.Span);
        var previous = genesis;
        for (int index = 0; index < count; index++)
        {
            var bytes = successors[index];
            if (bytes.Length != 538) throw new CryptographicException("Invalid rendezvous successor size.");
            var record = ContactCodec.Decode(ProtocolMagic.XUR1, bytes.Span);
            RequireSuccessor(previous, record);
            includesAcceptedHead |= Fixed(record.CanonicalSpan, acceptedHead.Span);
            records[index] = previous = record;
        }
        if (!includesAcceptedHead)
            throw new CryptographicException("Rendezvous continuation diverges from its accepted head.");
        var first = await trustedTime.ReadCurrentAsync(ct).ConfigureAwait(false);
        var directory = AccountDirectoryAdh1Codec.Decode(freshness.ExactAdh1.Span);
        var witness = AccountDirectoryDtt1Codec.Decode(freshness.ExactDtt1.Span);
        var initialBounds = PeerWindow(first);
        RequireIssuerBinding(genesis, freshness, first);
        foreach (var record in records)
        {
            ct.ThrowIfCancellationRequested();
            RequireSignedDevice(record, freshness, first);
        }
        var final = await trustedTime.ReadCurrentAsync(ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        if (final.SampleSeconds < first.SampleSeconds || !Fixed(final.BootId.Span, first.BootId.Span))
            throw new CryptographicException("Rendezvous chain verification crossed a clock discontinuity.");
        var finalBounds = PeerWindow(final);
        if (historicalTime is { } at)
        {
            if (at > checked(freshness.TrustedUpperUnixSeconds + (final.SampleSeconds - freshness.MonotonicSample)) ||
                at < U64(previous.FieldSpan(11)) || at >= U64(previous.FieldSpan(12)))
                throw new CryptographicException("The rendezvous tip did not cover the native event.");
        }
        else
        {
            if (U64(previous.FieldSpan(11)) > initialBounds.Lower || U64(previous.FieldSpan(12)) <= finalBounds.Upper)
                throw new CryptographicException("The rendezvous tip does not cover the joined trusted-time interval.");
        }
        return previous;

        (ulong Lower, ulong Upper) PeerWindow(OnionMonotonicReading now)
        {
            network.EnsureCurrent();
            if (freshness.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue || freshness.CurrentCheckpoint is null ||
                !freshness.IsCurrentAtMonotonic(now.BootId.Span, now.SampleSeconds))
                throw new CryptographicException("Rendezvous continuation requires a current peer directory observation.");
            DeepIdV2RouteContext.RequireDirectoryBindings(freshness, network, authority, now, directory, witness);
            var closure = network.Closure!;
            var peerElapsed = checked(now.SampleSeconds - freshness.MonotonicSample);
            var networkElapsed = checked(now.SampleSeconds - closure.FreshnessMonotonicSample);
            var lower = Math.Min(checked(freshness.TrustedLowerUnixSeconds + peerElapsed), checked(closure.TrustedLowerUnixSeconds + networkElapsed));
            var upper = Math.Max(checked(freshness.TrustedUpperUnixSeconds + peerElapsed), checked(closure.TrustedUpperUnixSeconds + networkElapsed));
            DeepIdV2RouteTimeCoverage.Require(lower, upper, authority.NotBefore, authority.ExpiresAt, DeepIdV2RouteTimeArtifact.Xna1);
            DeepIdV2RouteTimeCoverage.Require(lower, upper, closure.View.NotBefore, closure.View.ExpiresAt, DeepIdV2RouteTimeArtifact.Xnv1);
            DeepIdV2RouteTimeCoverage.Require(lower, upper, closure.Head.ValidFrom, closure.Head.ValidUntil, DeepIdV2RouteTimeArtifact.Xnh1);
            DeepIdV2RouteTimeCoverage.Require(lower, upper, directory.ValidFrom, directory.ValidUntil, DeepIdV2RouteTimeArtifact.Adh1);
            var device = freshness.CurrentCheckpoint.Directory.Identity.ActiveDevices.SingleOrDefault(d =>
                Fixed(d.Certificate.DeviceId.Span, genesis.FieldSpan(13))) ??
                throw new CryptographicException("Rendezvous continuation issuer is no longer an active device.");
            DeepIdV2RouteTimeCoverage.Require(lower, upper, device.Certificate.IssuedAtUnixSeconds,
                device.Certificate.ExpiresAtUnixSeconds, DeepIdV2RouteTimeArtifact.DeviceCertificate);
            if (!Fixed(((IVerifiedDirectoryNetworkTime)freshness).ExactAdh1CoreReference.Span, closure.Adh1CoreReference))
                throw new DeepIdV2RouteContextException(DeepIdV2RouteContextCheck.DirectoryHead);
            return (lower, upper);
        }
    }

    internal static void RequireSuccessor(ContactRecord previous, ContactRecord next)
    {
        var generation = BinaryPrimitives.ReadUInt64BigEndian(previous.FieldSpan(4));
        if (generation == ulong.MaxValue || U64(next.FieldSpan(4)) != generation + 1 ||
            !Fixed(previous.ArtifactHash.Span, next.FieldSpan(5)) ||
            U64(next.FieldSpan(11)) < U64(previous.FieldSpan(11)) ||
            U64(next.FieldSpan(12)) <= U64(previous.FieldSpan(12)))
            throw new CryptographicException("Rendezvous generation, predecessor or validity does not extend its original.");
        // The current signed placement manifest may advance. Renewal keeps the
        // exact private direction, capabilities, metadata key and issuer.
        ReadOnlySpan<int> stableTags = [1, 2, 3, 7, 8, 9, 10, 13, 14];
        foreach (var tag in stableTags)
            if (!Fixed(previous.FieldSpan(tag), next.FieldSpan(tag)))
                throw new CryptographicException("Rendezvous renewal changed its direction or issuer.");
    }
}
