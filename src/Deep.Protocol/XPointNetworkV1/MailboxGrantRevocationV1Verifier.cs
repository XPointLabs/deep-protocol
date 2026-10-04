using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>Host-owned protected I/O, never a candidate cache or unsigned default.</summary>
public interface IMailboxGrantRevocationFloorReader
{
    ValueTask<ReadOnlyMemory<byte>> ReadCurrentCoreHashAsync(ReadOnlyMemory<byte> networkId16,
        ReadOnlyMemory<byte> pma2CoreReference38, MailboxCapabilityDomain domain,
        CancellationToken cancellationToken);
}

public enum MailboxGrantRevocationFloorError { Rollback, MissingSuccessor, SignedFork, RemovedSerial }

/// <summary>Only authenticated floor conflicts use this error; malformed or unsigned inputs cannot latch a scope.</summary>
public sealed class MailboxGrantRevocationFloorException(MailboxGrantRevocationFloorError error, string message)
    : CryptographicException(message)
{
    public MailboxGrantRevocationFloorError Error { get; } = error;
}

/// <summary>A verified write plan, not committed revocation or dispatch authority.</summary>
public sealed class VerifiedMailboxGrantRevocationPlan
{
    internal VerifiedMailboxGrantRevocationPlan(VerifiedMailboxHostAuthorityV2 host, ParsedMailboxGrantRevocationV1 snapshot)
    { Host = host; Snapshot = snapshot; }
    internal VerifiedMailboxHostAuthorityV2 Host { get; }
    internal ParsedMailboxGrantRevocationV1 Snapshot { get; }
    public ReadOnlyMemory<byte> ExactSnapshot => Snapshot.CanonicalBytes;
    public ReadOnlyMemory<byte> CoreHash => Snapshot.CoreHash;
    public ulong Generation => Snapshot.Generation;
    public MailboxCapabilityDomain Domain => Snapshot.Domain;
}

/// <summary>Current signed serial revocations after exact protected read-back.
/// Does not authorize holder, body, local exit, replay, mutation or receipt.</summary>
public sealed class VerifiedMailboxGrantRevocationV1
{
    private readonly VerifiedMailboxGrantRevocationPlan plan;
    private readonly IMailboxGrantRevocationFloorReader floors;
    internal VerifiedMailboxGrantRevocationV1(VerifiedMailboxGrantRevocationPlan plan, IMailboxGrantRevocationFloorReader floors)
    { this.plan = plan; this.floors = floors; }
    public ulong Generation => plan.Generation;
    public MailboxCapabilityDomain Domain => plan.Domain;
    public ReadOnlyMemory<byte> CoreHash => plan.CoreHash;

    public ValueTask EnsureCurrentAsync(CancellationToken cancellationToken = default) =>
        EnsureCurrentAsync(null, cancellationToken);

    private async ValueTask EnsureCurrentAsync(MailboxAuthenticatedGrant? grant, CancellationToken cancellationToken)
    {
        var host = plan.Host; var snapshot = plan.Snapshot;
        var before = await host.ReadAsync(cancellationToken).ConfigureAwait(false);
        MailboxGrantRevocationV1Verifier.RequireSnapshot(snapshot, host, before, false);
        if (grant is not null) host.RequireGrant(grant, before);
        var hash = await floors.ReadCurrentCoreHashAsync(host.NetworkId, snapshot.Field(2),
            snapshot.Domain, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (hash.Length != 32) throw new CryptographicException("The protected MGR1 floor is unavailable.");
        var ownedHash = hash.ToArray();
        var after = await host.ReadAsync(cancellationToken).ConfigureAwait(false);
        MailboxGrantRevocationV1Verifier.RequireSnapshot(snapshot, host, after, false);
        if (grant is not null) host.RequireGrant(grant, after);
        if (!CryptographicOperations.FixedTimeEquals(ownedHash, snapshot.CoreHash.Span))
            throw new CryptographicException("The MGR1 capability is not the current protected floor.");
    }

    public async ValueTask EnsureGrantNotRevokedAsync(ReadOnlyMemory<byte> exactMcg3,
        CancellationToken cancellationToken = default)
    {
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(exactMcg3.Span);
        var snapshot = plan.Snapshot;
        if (grant.Domain != snapshot.Domain || !Fixed(grant.IssuerPublicKey.Span, snapshot.FieldSpan(4)) ||
            !Fixed(grant.NetworkId.Span, snapshot.FieldSpan(1)))
            throw new CryptographicException("The grant differs from the MGR1 role/issuer/network scope.");
        await EnsureCurrentAsync(grant, cancellationToken).ConfigureAwait(false);
        if (snapshot.ContainsSerial(grant.Serial.Span)) throw new CryptographicException("The current MCG3 serial is revoked.");
        await EnsureCurrentAsync(grant, cancellationToken).ConfigureAwait(false);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public static class MailboxGrantRevocationV1Verifier
{
    public static bool RuntimeActivation => false;

    /// <summary>Pin a fresh signed snapshot for explicit genuinely new host-scope enrollment.
    /// The shared issuer chain may already have advanced; never use this as existing-floor recovery.</summary>
    public static async ValueTask<VerifiedMailboxGrantRevocationPlan> PlanInitialEnrollmentAsync(
        VerifiedMailboxHostAuthorityV2 host, ReadOnlyMemory<byte> exactSnapshot,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(host); cancellationToken.ThrowIfCancellationRequested();
        var snapshot = MailboxGrantRevocationV1Codec.Decode(exactSnapshot.Span);
        var before = await host.ReadAsync(cancellationToken).ConfigureAwait(false);
        RequireSnapshot(snapshot, host, before, false);
        var after = await host.ReadAsync(cancellationToken).ConfigureAwait(false);
        RequireSnapshot(snapshot, host, after, false);
        return new(host, snapshot);
    }

    public static async ValueTask<VerifiedMailboxGrantRevocationPlan> PlanAdvanceAsync(
        VerifiedMailboxHostAuthorityV2 host, ReadOnlyMemory<byte> exactProtectedPredecessor,
        ReadOnlyMemory<byte> exactCandidate, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(host); cancellationToken.ThrowIfCancellationRequested();
        var prior = MailboxGrantRevocationV1Codec.Decode(exactProtectedPredecessor.Span);
        var next = MailboxGrantRevocationV1Codec.Decode(exactCandidate.Span);
        var before = await host.ReadAsync(cancellationToken).ConfigureAwait(false);
        // Prior expiry does not erase a restored floor. It cannot authorize admission.
        RequireSnapshot(prior, host, before, true);
        RequireSnapshot(next, host, before, false);
        if (prior.Domain != next.Domain) throw new CryptographicException("MGR1 successor cannot change role.");
        if (next.Generation < prior.Generation)
            throw Floor(MailboxGrantRevocationFloorError.Rollback, "MGR1 candidate is below the protected floor.");
        if (next.Generation == prior.Generation)
        {
            if (!Fixed(prior.CoreHash.Span, next.CoreHash.Span))
                throw Floor(MailboxGrantRevocationFloorError.SignedFork, "MGR1 issuer signed two cores at one generation.");
        }
        else
        {
            if (prior.Generation == ulong.MaxValue || next.Generation != prior.Generation + 1)
                throw Floor(MailboxGrantRevocationFloorError.MissingSuccessor, "MGR1 successor history has a gap.");
            if (!Fixed(next.FieldSpan(6), prior.CoreHash.Span) || next.IssuedAt < prior.IssuedAt)
                throw Floor(MailboxGrantRevocationFloorError.SignedFork, "MGR1 successor differs from the protected predecessor.");
            var serials = prior.FieldSpan(11).ToArray();
            for (var index = 0; index < prior.SerialCount; index++)
                if (!next.ContainsSerial(serials.AsSpan(index * 16, 16)))
                    throw Floor(MailboxGrantRevocationFloorError.RemovedSerial, "MGR1 successor removed a retained revocation.");
        }
        var after = await host.ReadAsync(cancellationToken).ConfigureAwait(false);
        RequireSnapshot(prior, host, after, true);
        RequireSnapshot(next, host, after, false);
        return new(host, next);
    }

    /// <summary>Host must supply actual protected-store read-back and a reader bound to that same scoped store.</summary>
    public static async ValueTask<VerifiedMailboxGrantRevocationV1> VerifyCommittedAsync(
        VerifiedMailboxGrantRevocationPlan plan, ReadOnlyMemory<byte> exactProtectedReadBack,
        IMailboxGrantRevocationFloorReader floors, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan); ArgumentNullException.ThrowIfNull(floors);
        cancellationToken.ThrowIfCancellationRequested();
        var readBack = MailboxGrantRevocationV1Codec.Decode(exactProtectedReadBack.Span);
        if (!Fixed(readBack.CanonicalBytes.Span, plan.ExactSnapshot.Span))
            throw new CryptographicException("MGR1 durable read-back differs from its verified write plan.");
        var result = new VerifiedMailboxGrantRevocationV1(plan, floors);
        await result.EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    internal static void RequireSnapshot(ParsedMailboxGrantRevocationV1 snapshot,
        VerifiedMailboxHostAuthorityV2 host, (VerifiedMailboxAuthorityV2 Policy, ulong Lower, ulong Upper) current,
        bool protectedPredecessor)
    {
        var policy = current.Policy;
        var issuer = policy.ResolveIssuer(snapshot.Domain);
        var reference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.PMA2, policy.CoreHash.Span);
        if (!Fixed(snapshot.FieldSpan(1), host.NetworkId.Span) || !Fixed(snapshot.FieldSpan(2), reference) ||
            !Fixed(snapshot.FieldSpan(4), issuer.PublicKey.Span) || snapshot.NotBefore < policy.NotBeforeUnixSeconds ||
            snapshot.ExpiresAt > policy.ExpiresAtUnixSeconds || snapshot.IssuedAt < issuer.ValidFromUnixSeconds ||
            snapshot.IssuedAt > current.Lower ||
            (!protectedPredecessor && (snapshot.NotBefore > current.Lower || current.Upper >= snapshot.ExpiresAt)) ||
            !PublicKeyAuth.VerifyDetached(snapshot.FieldSpan(12).ToArray(), snapshot.SignatureInput.ToArray(), issuer.PublicKey.ToArray()))
            throw new CryptographicException("MGR1 is outside current PMA2 role/network/protected-time authority.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static MailboxGrantRevocationFloorException Floor(MailboxGrantRevocationFloorError error, string message) => new(error, message);
}
