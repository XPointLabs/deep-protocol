using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.ContactV2;

public static partial class DeepIdV2ContactUpdateRendezvousVerifier
{
    /// <summary>Authenticates a continuation against the original native contact and its independently retained head, then verifies the final record at current trusted time.</summary>
    public static async ValueTask<VerifiedDeepIdV2ContactUpdateRendezvous> VerifySuccessorChainAsync(
        ReadOnlyMemory<byte> originalXur, ReadOnlyMemory<byte> acceptedHead, IReadOnlyList<ReadOnlyMemory<byte>> successors,
        VerifiedDeepIdV2DirectoryFreshness freshness, VerifiedOnionNetworkContext network,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        var tip = await VerifyChainAsync(originalXur, acceptedHead, successors, freshness, network,
            null, trustedTime, cancellationToken).ConfigureAwait(false);
        return new(tip, freshness);
    }

    /// <summary>Verifies an authenticated native event's chain at its creation time. Historical verification cannot provide a live capability.</summary>
    public static async ValueTask VerifyRecordedSuccessorChainAsync(ReadOnlyMemory<byte> originalXur,
        ReadOnlyMemory<byte> acceptedHead, IReadOnlyList<ReadOnlyMemory<byte>> successors,
        VerifiedDeepIdV2DirectoryFreshness freshness, VerifiedOnionNetworkContext network,
        ulong eventCreatedAtUnixSeconds, OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        _ = await VerifyChainAsync(originalXur, acceptedHead, successors, freshness, network,
            eventCreatedAtUnixSeconds, trustedTime, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<ContactRecord> VerifyChainAsync(ReadOnlyMemory<byte> genesisBytes,
        ReadOnlyMemory<byte> acceptedHead, IReadOnlyList<ReadOnlyMemory<byte>> successors,
        VerifiedDeepIdV2DirectoryFreshness freshness, VerifiedOnionNetworkContext network,
        ulong? historicalTime, OnionTrustedTimeAuthority trustedTime, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(freshness); ArgumentNullException.ThrowIfNull(network);
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
        DeepIdV2ContactUpdateRendezvousAuthor.RequireCurrent(freshness, network, first);
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
        DeepIdV2ContactUpdateRendezvousAuthor.RequireCurrent(freshness, network, final);
        if (historicalTime is { } at)
        {
            var elapsed = checked(final.SampleSeconds - freshness.MonotonicSample);
            if (at > checked(freshness.TrustedUpperUnixSeconds + elapsed) ||
                at < U64(previous.FieldSpan(11)) || at >= U64(previous.FieldSpan(12)))
                throw new CryptographicException("The rendezvous tip did not cover the native event.");
        }
        else
        {
            RequireLiveInterval(previous, freshness, first);
            RequireLiveInterval(previous, freshness, final);
        }
        return previous;
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
