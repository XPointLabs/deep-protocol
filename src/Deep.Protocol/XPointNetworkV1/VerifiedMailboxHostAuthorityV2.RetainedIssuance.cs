using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>Closed current two-store retained-read issuance only. Not native
/// replay, holder custody, installation, dispatch, Store or object availability.</summary>
public sealed class VerifiedMailboxRetainedReadIssuanceV2
{
    private readonly VerifiedMailboxHostAuthorityV2 host;
    private readonly ContactRecord request;
    private readonly ParsedContactRouteClosure route;
    private readonly DeepIdV2MailboxGrantReplicaEvidence[] evidence;
    private readonly ulong readUntil;

    internal VerifiedMailboxRetainedReadIssuanceV2(VerifiedMailboxHostAuthorityV2 host,
        ContactRecord request, ParsedContactRouteClosure route, ulong readUntil,
        DeepIdV2MailboxGrantReplicaEvidence[] evidence)
    { this.host = host; this.request = request; this.route = route; this.readUntil = readUntil; this.evidence = evidence; }

    public ReadOnlyMemory<byte> ExactXmg2 => request.CanonicalBytes.ToArray();
    public ReadOnlyMemory<byte> ExactRouteClosure => route.ExactBytes.ToArray();
    public ulong ReadUntilUnixSeconds => readUntil;

    public async ValueTask EnsureCurrentAsync(CancellationToken cancellationToken = default) =>
        _ = await host.ReadRetainedIssuanceAsync(request, route, readUntil, evidence, cancellationToken).ConfigureAwait(false);

    public async ValueTask<ReadOnlyMemory<byte>> AuthorSuccessAsync(IMailboxGrantIssuerSigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signer); cancellationToken.ThrowIfCancellationRequested();
        var exposed = signer.Ed25519PublicKey;
        if (exposed.Length != 32 || exposed.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException("Retained read issuer has no exact role key.");
        var publicKey = exposed.ToArray();
        var first = await host.ReadRetainedIssuanceAsync(request, route, readUntil, evidence, cancellationToken).ConfigureAwait(false);
        var issuer = first.Policy.ResolveIssuer(MailboxCapabilityDomain.Retrieve);
        if (!Equal(publicKey, issuer.PublicKey.Span))
            throw new CryptographicException("Retained read signer is not the actual current Retrieve issuer.");
        var expiry = host.MaximumRetainedGrantExpiry(first.Policy, first.Window.LowerUnixSeconds, readUntil);
        if (first.Window.UpperUnixSeconds >= expiry)
            throw new CryptographicException("Retained read issuer has no remaining complete grant interval.");
        var serial = new byte[16];
        do RandomNumberGenerator.Fill(serial); while (serial.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        var unsigned = new MailboxAuthenticatedGrant
        {
            Domain = MailboxCapabilityDomain.Retrieve, Lifecycle = MailboxCapabilityLifecycle.Active,
            NetworkId = host.NetworkId, Epoch = U64(route.Selection.Field(4).Span),
            Generation = Math.Max(1UL, first.Policy.MinimumGrantGeneration), Serial = serial,
            NotBeforeUnixSeconds = first.Window.LowerUnixSeconds, ExpiresAtUnixSeconds = expiry,
            OverlapUntilUnixSeconds = 0,
            PlacementCommitment = MailboxPlacementCommitment.Compute(new(route.Reachability.Field(10).Span)),
            MembershipCommitment = route.Projection.ArtifactHash.ToArray(),
            IssuerPublicKey = publicKey, HolderPublicKey = request.Field(5).ToArray(),
            SelectionInput = route.Selection.Field(3).ToArray(), IssuerSignature = new byte[64]
        };
        _ = await host.ReadRetainedIssuanceAsync(request, route, readUntil, evidence, cancellationToken).ConfigureAwait(false);
        var input = MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(unsigned);
        var returned = await signer.SignAsync(input.ToArray(), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (returned.Length != 64) throw new CryptographicException("Retained read signer returned an unbounded signature.");
        var signature = returned.ToArray();
        if (!PublicKeyAuth.VerifyDetached(signature, input, publicKey))
            throw new CryptographicException("Retained read signer returned an invalid signature.");
        var final = await host.ReadRetainedIssuanceAsync(request, route, readUntil, evidence, cancellationToken).ConfigureAwait(false);
        DeepIdV2MailboxGrantResultVerifier.RequireContinuous(first.Window, final.Window);
        var result = MailboxGrantResultAuthor.AuthorSuccess(request, route.ExactBytes.Span,
            unsigned with { IssuerSignature = signature }, final.Window.UpperUnixSeconds, U64(request.Field(10).Span));
        await host.RequireRetainedReadSuccessAsync(request, result, route, readUntil, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested(); return result.CanonicalBytes.ToArray();
    }

    public async ValueTask VerifySuccessAsync(ReadOnlyMemory<byte> exactXmc2, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (exactXmc2.Length != 510) throw new CryptographicException("Retained read winner requires an exact success.");
        var result = ContactCodec.Decode(ProtocolMagic.XMC2, exactXmc2.Span);
        _ = await host.ReadRetainedIssuanceAsync(request, route, readUntil, evidence, cancellationToken).ConfigureAwait(false);
        await host.RequireRetainedReadSuccessAsync(request, result, route, readUntil, cancellationToken).ConfigureAwait(false);
        _ = await host.ReadRetainedIssuanceAsync(request, route, readUntil, evidence, cancellationToken).ConfigureAwait(false);
    }

    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    private static bool Equal(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}

public sealed partial class VerifiedMailboxHostAuthorityV2
{
    internal const ulong MaximumRetainedObjectHorizonSeconds = 2_592_000;

    public async ValueTask<VerifiedMailboxRetainedReadIssuanceV2> VerifyRetainedReadIssuanceAsync(
        ReadOnlyMemory<byte> exactXmg2, ReadOnlyMemory<byte> exactOriginalRoute,
        ulong readUntilUnixSeconds, IReadOnlyList<DeepIdV2MailboxGrantReplicaEvidence> replicaEvidence,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(replicaEvidence); cancellationToken.ThrowIfCancellationRequested();
        if (exactXmg2.Length != 435 || exactOriginalRoute.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes ||
            replicaEvidence.Count != 2)
            throw new CryptographicException("Retained read issuance inputs exceed their exact bounds.");
        var request = ContactCodec.Decode(ProtocolMagic.XMG2, exactXmg2.Span);
        var route = ContactRouteClosureCodec.Decode(exactOriginalRoute.Span);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        var evidence = new DeepIdV2MailboxGrantReplicaEvidence[2];
        for (var i = 0; i < evidence.Length; i++)
        {
            var item = replicaEvidence[i] ?? throw new CryptographicException("Retained read evidence is absent.");
            evidence[i] = new(item.NodeId.Span, item.Signature.Span);
        }
        RequireRetainedRouteScope(request, route, readUntilUnixSeconds);
        _ = await ReadRetainedIssuanceAsync(request, route, readUntilUnixSeconds, evidence, cancellationToken).ConfigureAwait(false);
        return new(this, request, route, readUntilUnixSeconds, evidence);
    }

    internal async ValueTask<(VerifiedMailboxAuthorityV2 Policy, DeepIdV2ContactRouteTimeWindow Window)> ReadRetainedIssuanceAsync(
        ContactRecord request, ParsedContactRouteClosure route, ulong readUntil,
        DeepIdV2MailboxGrantReplicaEvidence[] evidence, CancellationToken ct)
    {
        RequireRetainedRouteScope(request, route, readUntil);
        RequireRetainedStoreEvidence(request, route, readUntil, evidence);
        var window = await ReadRetainedRequestTimeAsync(request, ct).ConfigureAwait(false);
        if (window.UpperUnixSeconds >= readUntil)
            throw new CryptographicException("Retained read custody no longer covers the complete current interval.");
        var current = MailboxAuthorityV2Verifier.Verify(root, pma.CanonicalBytes.Span, window.LowerUnixSeconds, window.UpperUnixSeconds);
        RequireRetainedStoreEvidence(request, route, readUntil, evidence);
        RequireOriginalMailboxNodes(route);
        ct.ThrowIfCancellationRequested(); return (current, window);
    }

    internal ulong MaximumRetainedGrantExpiry(VerifiedMailboxAuthorityV2 policy, ulong start, ulong readUntil) =>
        new[] { network.MaximumRecordExpiryUnixSeconds, network.Closure!.HardUpperUnixSeconds,
            policy.ExpiresAtUnixSeconds, checked(start + policy.MaximumGrantLifetimeSeconds), readUntil }.Min();

    private void RequireRetainedRouteScope(ContactRecord request, ParsedContactRouteClosure route, ulong readUntil)
    {
        RequireRetainedRequestSelection(request);
        var ceiling = new[] { U64Retained(route.Reachability.Field(17).Span), U64Retained(route.Authorization.Field(13).Span),
            U64Retained(route.Route.Field(18).Span), U64Retained(route.Successor.Field(11).Span),
            U64Retained(route.Projection.Field(12).Span), U64Retained(route.Selection.Field(9).Span) }.Min();
        if (readUntil == 0 || ceiling > ulong.MaxValue - MaximumRetainedObjectHorizonSeconds ||
            readUntil > ceiling + MaximumRetainedObjectHorizonSeconds ||
            !Fixed(route.Reachability.Field(1).Span, network.NetworkId.Span) ||
            !Fixed(request.Field(7).Span, ContactCodec.ArtifactReference(ProtocolMagic.PMT2, route.Projection).CanonicalBytes.Span) ||
            !Fixed(request.Field(8).Span, route.Selection.ArtifactHash.Span) ||
            !Fixed(request.Field(11).Span, route.ExactHash.Span) ||
            Fixed(request.Field(4).Span, route.Reachability.Field(10).Span))
            throw new CryptographicException("Retained read request/route/horizon/role differs from exact original custody.");
        var original = network.Closure!.RetainedPmts.Single(candidate => Fixed(
            ContactCodec.ArtifactReference(ProtocolMagic.PMT2, candidate).CanonicalBytes.Span, request.Field(7).Span));
        if (!Fixed(original.CanonicalBytes.Span, route.Projection.CanonicalBytes.Span) ||
            !Fixed(route.Route.Field(19).Span, route.Successor.Field(12).Span))
            throw new CryptographicException("Retained read route has no exact protected original projection/anchor.");
        RequireOriginalMailboxNodes(route);
    }

    private void RequireOriginalMailboxNodes(ParsedContactRouteClosure route)
    {
        var projection = route.Projection;
        if (projection.Field(7).Span[0] != 2) throw new CryptographicException("Retained read requires exactly two original Mailbox replicas.");
        var ranked = ContactRouteThresholdAuthor.RankReplicas(network.NetworkId.Span,
            ContactCodec.ArtifactReference(ProtocolMagic.PMT2, projection).CanonicalBytes.Span,
            projection.Field(6).Span, route.Selection.Field(3).Span, projection.Field(9).Span, 2);
        if (!Fixed(ranked, route.Selection.Field(6).Span))
            throw new CryptographicException("Retained read selection differs from the original signed selector.");
        for (var offset = 0; offset < ranked.Length; offset += 32)
        {
            var id = ranked.AsSpan(offset, 32).ToArray();
            if (!network.Closure!.PmtNodeIds.Any(current => Fixed(current, id)))
                throw new CryptographicException("An original retained replica is not currently admitted; reranking is forbidden.");
            _ = network.ResolveNode(id); _ = network.ResolveNodeIdentityPublicKey(id);
        }
    }

    private void RequireRetainedStoreEvidence(ContactRecord request, ParsedContactRouteClosure route,
        ulong readUntil, DeepIdV2MailboxGrantReplicaEvidence[] evidence)
    {
        var placement = ContactServicePlacementFactory.Create(network, ContactServiceRequestKind.ResolveInvite, request.Field(3));
        var stores = placement.RankedReplicaNodeIds;
        if (stores.Count != 2 || evidence.Length != 2 || Fixed(evidence[0].NodeId.Span, evidence[1].NodeId.Span))
            throw new CryptographicException("Retained read requires both independent current ContactResolve stores.");
        var tuple = MailboxRetainedReadEvidenceAuthentication.CreateTuple(SHA256.HashData(request.CanonicalBytes.Span),
            request.Field(3).Span, MailboxGrantCapabilityDigest.Compute(request.Field(4).Span, MailboxCapabilityDomain.Retrieve),
            route.ExactHash.Span, readUntil);
        var input = MailboxRetainedReadEvidenceAuthentication.GetSigningBytes(tuple);
        foreach (var item in evidence)
            if (!stores.Any(id => Fixed(id.Span, item.NodeId.Span)) ||
                !PublicKeyAuth.VerifyDetached(item.Signature.ToArray(), input, network.ResolveNodeIdentityPublicKey(item.NodeId).ToArray()))
                throw new CryptographicException("Retained read evidence has a missing, wrong or noncurrent store signature.");
    }

    internal async ValueTask RequireRetainedReadSuccessAsync(ContactRecord request, ContactRecord response,
        ParsedContactRouteClosure route, ulong readUntil, CancellationToken ct)
    {
        ContactCodec.ValidateMailboxGrantResultBinding(request, response);
        ContactCodec.ValidateMailboxGrantResultRouteBinding(response, route);
        RequireRetainedRouteScope(request, route, readUntil);
        var current = await ReadAsync(ct).ConfigureAwait(false);
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(response.Field(8).Span);
        _ = RequireRetainedReadGrant(grant, current);
        var requestStart = U64Retained(request.Field(9).Span);
        var requestExpiry = U64Retained(request.Field(10).Span);
        if (grant.ExpiresAtUnixSeconds > readUntil || grant.OverlapUntilUnixSeconds != 0 ||
            requestExpiry <= requestStart || requestExpiry - requestStart > 120 ||
            grant.NotBeforeUnixSeconds < requestStart ||
            U64Retained(response.Field(6).Span) != requestExpiry ||
            U64Retained(response.Field(4).Span) < requestStart ||
            U64Retained(response.Field(4).Span) >= requestExpiry ||
            U64Retained(response.Field(4).Span) > current.Upper)
            throw new CryptographicException("Retained read success exceeds its exact request/current issuer/horizon.");
        RequireOriginalMailboxNodes(route);
        var final = await ReadAsync(ct).ConfigureAwait(false);
        _ = RequireRetainedReadGrant(grant, final);
        if (final.Upper >= readUntil) throw new CryptographicException("Retained read horizon expired before result release.");
        ct.ThrowIfCancellationRequested();
    }

    private static ulong U64Retained(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
}
