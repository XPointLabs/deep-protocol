using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>Current mailbox policy derived only from the complete verified network.
/// It does not authorize holder requests, replay, local exit selection or delivery.</summary>
public sealed class VerifiedMailboxHostAuthorityV2
{
    private readonly VerifiedOnionNetworkContext network;
    private readonly VerifiedXPointNetworkAuthority root;
    private readonly ContactRecord pma;
    private readonly OnionTrustedTimeAuthority time;
    private readonly object clockGate = new();
    private ulong lastSample;

    internal VerifiedMailboxHostAuthorityV2(VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority root, ContactRecord pma,
        OnionTrustedTimeAuthority time, OnionMonotonicReading reading)
    {
        this.network = network; this.root = root; this.pma = pma; this.time = time;
        lastSample = reading.SampleSeconds;
    }

    public ReadOnlyMemory<byte> NetworkId => network.NetworkId.ToArray();
    public ReadOnlyMemory<byte> ProjectionReference => network.Closure!.PmtArtifactReference.ToArray();
    public ReadOnlyMemory<byte> MembershipCommitment => network.Closure!.Pmt.ArtifactHash.ToArray();
    public ulong SelectionEpoch => network.Closure!.SelectionEpoch;

    public async ValueTask EnsureCurrentAsync(CancellationToken cancellationToken = default) =>
        _ = await ReadAsync(cancellationToken).ConfigureAwait(false);

    /// <summary>Returns ranking facts, not route/grant or dispatch authority.</summary>
    public async ValueTask<IReadOnlyList<ReadOnlyMemory<byte>>> RankReplicasAsync(
        ReadOnlyMemory<byte> selectionInput32, CancellationToken cancellationToken = default)
    {
        if (selectionInput32.Length != 32 || selectionInput32.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Mailbox selection input must be nonzero 32 bytes.", nameof(selectionInput32));
        var input = selectionInput32.ToArray();
        await ReadAsync(cancellationToken).ConfigureAwait(false);
        var closure = network.Closure!;
        var ranked = ContactRouteThresholdAuthor.RankReplicas(network.NetworkId.Span,
            closure.PmtArtifactReference, closure.Pmt.FieldSpan(6), input,
            closure.Pmt.FieldSpan(9), closure.ReplicaCount);
        await ReadAsync(cancellationToken).ConfigureAwait(false);
        return Array.AsReadOnly(Enumerable.Range(0, ranked.Length / 32)
            .Select(index => (ReadOnlyMemory<byte>)ranked.AsSpan(index * 32, 32).ToArray()).ToArray());
    }

    public async ValueTask<VerifiedMailboxReplicaV2> ResolveReplicaAsync(
        ReadOnlyMemory<byte> nodeId32, CancellationToken cancellationToken = default)
    {
        if (nodeId32.Length != 32) throw new ArgumentException("Node ID must be 32 bytes.", nameof(nodeId32));
        var id = nodeId32.ToArray();
        await ReadAsync(cancellationToken).ConfigureAwait(false);
        if (!network.Closure!.PmtNodeIds.Any(candidate => Fixed(candidate, id)))
            throw new CryptographicException("The node is not in the current mailbox projection.");
        var node = network.ResolveNode(id);
        var key = network.ResolveNodeIdentityPublicKey(id);
        var result = new VerifiedMailboxReplicaV2(node.NodeId, key.Span,
            new VerifiedOnionNextHopTransport(network, node));
        await ReadAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    /// <summary>Checks issuer/grant currentness only. Holder, revocation, replay,
    /// placement-to-selection proof and durable mutation remain mandatory.</summary>
    public async ValueTask EnsureGrantCurrentAsync(ReadOnlyMemory<byte> exactMcg3,
        CancellationToken cancellationToken = default)
    {
        // Decoder bounds and captures bytes before the first callback.
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(exactMcg3.Span);
        var before = await ReadAsync(cancellationToken).ConfigureAwait(false);
        RequireGrant(grant, before);
        var after = await ReadAsync(cancellationToken).ConfigureAwait(false);
        RequireGrant(grant, after);
    }

    /// <summary>Issuer-authenticated selected replica facts for one captured grant.
    /// This is not holder, revocation, replay, dispatch or receipt authority.</summary>
    public async ValueTask<IReadOnlyList<VerifiedMailboxReplicaV2>> ResolveGrantReplicasAsync(
        ReadOnlyMemory<byte> exactMcg3, CancellationToken cancellationToken = default)
    {
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(exactMcg3.Span);
        var before = await ReadAsync(cancellationToken).ConfigureAwait(false);
        RequireGrant(grant, before);
        var closure = network.Closure!;
        if (closure.ReplicaCount != 2)
            throw new CryptographicException("The current mailbox quorum profile requires exactly two replicas.");
        var ranked = ContactRouteThresholdAuthor.RankReplicas(network.NetworkId.Span,
            closure.PmtArtifactReference, closure.Pmt.FieldSpan(6), grant.SelectionInput.Span,
            closure.Pmt.FieldSpan(9), closure.ReplicaCount);
        var replicas = Enumerable.Range(0, closure.ReplicaCount).Select(index =>
        {
            var id = ranked.AsSpan(index * 32, 32).ToArray();
            return new VerifiedMailboxReplicaV2(id, network.ResolveNodeIdentityPublicKey(id).Span,
                new VerifiedOnionNextHopTransport(network, network.ResolveNode(id)));
        }).ToArray();
        var after = await ReadAsync(cancellationToken).ConfigureAwait(false);
        RequireGrant(grant, after);
        cancellationToken.ThrowIfCancellationRequested();
        return Array.AsReadOnly(replicas);
    }

    internal async ValueTask<(VerifiedMailboxAuthorityV2 Policy, ulong Lower, ulong Upper)> ReadAsync(
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var reading = await time.ReadCurrentAsync(ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        var result = VerifyAtReading(network, root, pma, reading);
        lock (clockGate)
        {
            if (reading.SampleSeconds < lastSample)
                throw new CryptographicException("Mailbox authority crossed a protected clock rollback.");
            lastSample = reading.SampleSeconds;
        }
        return result;
    }

    internal static (VerifiedMailboxAuthorityV2 Policy, ulong Lower, ulong Upper) VerifyAtReading(
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority root,
        ContactRecord pma, OnionMonotonicReading reading)
    {
        network.EnsureCurrent();
        var closure = network.Closure!;
        if (!Fixed(network.NetworkId.Span, root.NetworkId.Span) ||
            !Fixed(closure.View.FieldSpan(7), root.AuthorityCoreReference.Span) ||
            !Fixed(closure.Head.FieldSpan(8), root.AuthorityCoreReference.Span) ||
            !Fixed(reading.BootId.Span, closure.FreshnessBootId) ||
            reading.SampleSeconds < closure.FreshnessMonotonicSample ||
            reading.SampleSeconds >= closure.FreshnessDeadlineMonotonicSeconds)
            throw new CryptographicException("Mailbox authority differs from current network/root/clock scope.");
        ulong lower, upper;
        try
        {
            var elapsed = checked(reading.SampleSeconds - closure.FreshnessMonotonicSample);
            lower = checked(closure.TrustedLowerUnixSeconds + elapsed);
            upper = checked(closure.TrustedUpperUnixSeconds + elapsed);
        }
        catch (OverflowException error)
        {
            throw new CryptographicException("Mailbox trusted-time projection overflowed.", error);
        }
        if (lower > upper || lower < root.NotBefore || upper >= root.ExpiresAt ||
            lower < closure.View.NotBefore || upper >= closure.View.ExpiresAt ||
            lower < closure.Head.ValidFrom || upper >= closure.Head.ValidUntil ||
            lower < BinaryPrimitives.ReadUInt64BigEndian(closure.Pmt.FieldSpan(11)) ||
            upper >= BinaryPrimitives.ReadUInt64BigEndian(closure.Pmt.FieldSpan(12)) ||
            upper >= closure.HardUpperUnixSeconds)
            throw new CryptographicException("Mailbox authority does not cover the full current proof interval.");
        var policy = MailboxAuthorityV2Verifier.Verify(root, pma.CanonicalBytes.Span, lower, upper);
        if (!policy.BindsProjection(closure.Pmt.CanonicalBytes.Span))
            throw new CryptographicException("Current PMT2 does not bind this mailbox issuer policy.");
        return (policy, lower, upper);
    }

    internal void RequireGrant(MailboxAuthenticatedGrant grant,
        (VerifiedMailboxAuthorityV2 Policy, ulong Lower, ulong Upper) current)
    {
        var issuer = current.Policy.ResolveIssuer(grant.Domain);
        if (grant.Lifecycle != MailboxCapabilityLifecycle.Active ||
            !Fixed(grant.NetworkId.Span, network.NetworkId.Span) ||
            !Fixed(grant.MembershipCommitment.Span, MembershipCommitment.Span) ||
            grant.Epoch != SelectionEpoch || grant.Generation < current.Policy.MinimumGrantGeneration ||
            !Fixed(grant.IssuerPublicKey.Span, issuer.PublicKey.Span) ||
            grant.NotBeforeUnixSeconds < issuer.ValidFromUnixSeconds ||
            grant.NotBeforeUnixSeconds > current.Lower || current.Upper >= grant.ExpiresAtUnixSeconds ||
            grant.ExpiresAtUnixSeconds > current.Policy.ExpiresAtUnixSeconds ||
            grant.ExpiresAtUnixSeconds > network.Closure!.HardUpperUnixSeconds ||
            grant.ExpiresAtUnixSeconds - grant.NotBeforeUnixSeconds > current.Policy.MaximumGrantLifetimeSeconds ||
            !PublicKeyAuth.VerifyDetached(grant.IssuerSignature.ToArray(),
                MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant), issuer.PublicKey.ToArray()))
            throw new CryptographicException("Mailbox grant is outside current issuer/network/time authority.");
    }

    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}

/// <summary>Copied mailbox node facts. Canonical node ID and identity/receipt key are separate fields.</summary>
public sealed class VerifiedMailboxReplicaV2
{
    private readonly byte[] nodeId, signingKey;
    internal VerifiedMailboxReplicaV2(ReadOnlySpan<byte> nodeId, ReadOnlySpan<byte> signingKey,
        VerifiedOnionNextHopTransport transport)
    { this.nodeId = nodeId.ToArray(); this.signingKey = signingKey.ToArray(); Transport = transport; }
    public ReadOnlyMemory<byte> NodeId => nodeId.ToArray();
    public ReadOnlyMemory<byte> SigningPublicKey => signingKey.ToArray();
    /// <summary>Origin address/port/current SPKI from the same admitted descriptor.
    /// Copied transport facts do not replace a live grant/revocation/operation check.</summary>
    public VerifiedOnionNextHopTransport Transport { get; }
}

public static class MailboxHostAuthorityV2Verifier
{
    public static async ValueTask<VerifiedMailboxHostAuthorityV2> VerifyAsync(
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority root,
        ReadOnlyMemory<byte> exactPma2, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(network); ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(trustedTime); cancellationToken.ThrowIfCancellationRequested();
        if (exactPma2.Length is < 497 or > 1_169)
            throw new CryptographicException("PMA2 is outside its exact bounded size.");
        var pma = ContactCodec.Decode(ProtocolMagic.PMA2, exactPma2.Span);
        var reading = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        VerifiedMailboxHostAuthorityV2.VerifyAtReading(network, root, pma, reading);
        var result = new VerifiedMailboxHostAuthorityV2(network, root, pma, trustedTime, reading);
        await result.EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }
}
