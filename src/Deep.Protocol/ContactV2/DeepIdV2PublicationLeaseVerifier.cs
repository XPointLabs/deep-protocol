using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Independently current threshold/carriage permission for the exact
/// original reusable intent. Does not prove a replica commit or client adoption.</summary>
public static class DeepIdV2PublicationLeaseVerifier
{
    public static async ValueTask<VerifiedXpa1PublicationAuthorization> VerifyAsync(
        ParsedDeepIdV2PublicationLease candidate, VerifiedXPointNetworkAuthority authority,
        VerifiedDeepIdV2DirectoryFreshness freshness, VerifiedContactServicePlacement placement,
        OnionTrustedTimeAuthority trustedTime, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(candidate); ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(freshness); ArgumentNullException.ThrowIfNull(placement);
        ArgumentNullException.ThrowIfNull(trustedTime); ct.ThrowIfCancellationRequested();
        // Freeze/parsing precedes any external clock callback.
        var lease = DeepIdV2PublicationLeaseCodec.Decode(candidate.CanonicalBytes.Span);
        var first = await trustedTime.ReadCurrentAsync(ct).ConfigureAwait(false);
        RequireAtReading(lease, authority, freshness, placement, first);
        VerifyWitnesses(lease, authority);
        var final = await trustedTime.ReadCurrentAsync(ct).ConfigureAwait(false);
        if (!Fixed(first.BootId.Span, final.BootId.Span) || final.SampleSeconds < first.SampleSeconds)
            throw new CryptographicException("Publication lease crossed protected clock continuity.");
        RequireAtReading(lease, authority, freshness, placement, final);
        ct.ThrowIfCancellationRequested();
        return new(lease.OriginalRequest, ServiceWire.ParseValidatedXpa1(lease.OriginalRequest), authority,
            freshness, placement, trustedTime, final, lease);
    }

    private static void RequireAtReading(ParsedDeepIdV2PublicationLease lease, VerifiedXPointNetworkAuthority authority,
        VerifiedDeepIdV2DirectoryFreshness freshness, VerifiedContactServicePlacement placement, OnionMonotonicReading reading)
    {
        var network = placement.Network; network.EnsureCurrent();
        var closure = network.Closure ?? throw new CryptographicException("Publication lease needs complete verified network history.");
        var original = lease.OriginalRequest;
        if (!placement.Binds(ContactServiceRequestKind.PublishInvite, original.LocatorHash) ||
            placement.ServiceClass != ContactServiceClass.InviteResolver ||
            !Fixed(lease.NetworkId.Span, network.NetworkId.Span) || !Fixed(lease.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(lease.NetworkId.Span, freshness.NetworkId.Span) ||
            !Fixed(lease.ViewHash.Span, placement.ViewHash.Span) || !Fixed(lease.ViewHash.Span, closure.ViewCoreHash) ||
            !Fixed(lease.PlacementHash.Span, placement.PlacementHash.Span) ||
            !Fixed(lease.DirectoryHeadHash.Span, freshness.NextProtectedLkg.CoreHash.Span) ||
            !Fixed(closure.Adh1CoreReference, ((IVerifiedDirectoryNetworkTime)freshness).ExactAdh1CoreReference.Span) ||
            !Fixed(closure.View.FieldSpan(7), authority.AuthorityCoreReference.Span) ||
            !Fixed(closure.FreshnessBootId, reading.BootId.Span) ||
            reading.SampleSeconds < closure.FreshnessMonotonicSample ||
            reading.SampleSeconds >= closure.FreshnessDeadlineMonotonicSeconds ||
            !freshness.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds))
            throw new CryptographicException("Publication lease differs from exact current network/head/placement authority.");
        var head = AccountDirectoryAdh1Codec.Decode(freshness.ExactAdh1.Span);
        if (!Fixed(head.ExactXnaAuthorityCoreReference.Span, authority.AuthorityCoreReference.Span) ||
            !Fixed(head.WitnessPolicyHash.Span, authority.DirectoryWitnessPolicyHash.Span))
            throw new CryptographicException("Publication lease directory issuer is not current.");
        var proofElapsed = checked(reading.SampleSeconds - freshness.MonotonicSample);
        var networkElapsed = checked(reading.SampleSeconds - closure.FreshnessMonotonicSample);
        var lower = Math.Min(checked(freshness.TrustedLowerUnixSeconds + proofElapsed),
            checked(closure.TrustedLowerUnixSeconds + networkElapsed));
        var upper = Math.Max(checked(freshness.TrustedUpperUnixSeconds + proofElapsed),
            checked(closure.TrustedUpperUnixSeconds + networkElapsed));
        var records = ContactRouteClosureCodec.Decode(original.ExactRouteClosure.Span);
        var resourceExpiry = new[] { original.EffectiveExpiresAtUnixSeconds,
            U64(records.Authorization.Field(13).Span), U64(records.Selection.Field(9).Span),
            U64(records.Route.Field(18).Span), U64(records.Successor.Field(11).Span),
            U64(records.Reachability.Field(17).Span) }.Min();
        if (lease.IssuedAtUnixSeconds > lower || upper >= lease.ExpiresAtUnixSeconds ||
            lease.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds ||
            lease.ExpiresAtUnixSeconds > authority.ExpiresAt || lease.ExpiresAtUnixSeconds > head.ValidUntil ||
            lease.ExpiresAtUnixSeconds > resourceExpiry || lower < authority.NotBefore || lower < head.ValidFrom)
            throw new CryptographicException("Publication lease or inner resource does not cover the complete current interval.");
        // The old signed authorization proves original intent only. It never
        // becomes a current issuer/head/lease after expiry or key rotation.
        var oldPlacement = ContactServicePlacementFactory.RequireOriginalPublicationPlacement(network, authority, original);
        var parsed = DeepIdV2ContactPublicationCodec.DecodeXpu1(original.CanonicalBytes.Span);
        DeepIdV2Xpa1WitnessThresholdVerifier.RequireOriginalThreshold(parsed.Authorization, oldPlacement.Issuer);
        _ = VerifiedLogicalMailboxAssignment.Verify(network, authority, records.Projection);
        var currentPair = placement.RankedReplicaNodeIds;
        if (oldPlacement.Replicas.Count != 2 || currentPair.Count != 2 ||
            !Fixed(oldPlacement.Replicas[0].Span, currentPair[0].Span) || !Fixed(oldPlacement.Replicas[1].Span, currentPair[1].Span))
            throw new CryptographicException("Publication lease requires a separately authorized resolver-pair handover.");
        network.EnsureCurrent();
    }

    private static void VerifyWitnesses(ParsedDeepIdV2PublicationLease lease, VerifiedXPointNetworkAuthority authority)
    {
        if (lease.WitnessCount < authority.WitnessThreshold)
            throw new CryptographicException("Publication lease lacks current witness threshold.");
        var keys = authority.WitnessKeys.ToDictionary(value => Convert.ToHexString(value.Id.Span), StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        var rows = lease.SignatureRows;
        var signingInput = lease.SigningInput.ToArray();
        try
        {
            for (var offset = 0; offset < rows.Length; offset += 96)
            {
                if (!keys.TryGetValue(Convert.ToHexString(rows.Slice(offset, 32)), out var key) ||
                    !PublicKeyAuth.VerifyDetached(rows.Slice(offset + 32, 64).ToArray(), signingInput, key.Ed25519PublicKey.ToArray()))
                    throw new CryptographicException("Publication lease current witness signature is invalid.");
                domains.Add(Convert.ToHexString(key.FailureDomainHash.Span));
            }
            if (domains.Count < authority.WitnessThreshold)
                throw new CryptographicException("Publication lease lacks independent current witness domains.");
        }
        finally { CryptographicOperations.ZeroMemory(signingInput); }
    }
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
