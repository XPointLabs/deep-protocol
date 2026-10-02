using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Untrusted two-store evidence; construction grants no authority.</summary>
public sealed class DeepIdV2MailboxGrantReplicaEvidence
{
    private readonly byte[] nodeId, signature;
    public DeepIdV2MailboxGrantReplicaEvidence(ReadOnlySpan<byte> nodeId, ReadOnlySpan<byte> signature)
    {
        if (nodeId.Length != 32 || signature.Length != 64 ||
            nodeId.IndexOfAnyExcept((byte)0) < 0 || signature.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Mailbox evidence requires exact nonzero node/signature fields.");
        this.nodeId = nodeId.ToArray(); this.signature = signature.ToArray();
    }
    public ReadOnlyMemory<byte> NodeId => nodeId.ToArray();
    public ReadOnlyMemory<byte> Signature => signature.ToArray();
}

public interface IMailboxGrantIssuerSigner
{
    ReadOnlyMemory<byte> Ed25519PublicKey { get; }
    ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingBytes, CancellationToken cancellationToken);
}

/// <summary>Opaque two-store issuance authorization only, not recipient identity,
/// durable issuance, holder custody, dispatch permission or delivery.</summary>
public sealed class VerifiedDeepIdV2MailboxGrantIssuance
{
    private readonly VerifiedOnionNetworkContext network;
    private readonly VerifiedXPointNetworkAuthority root;
    private readonly OnionTrustedTimeAuthority time;
    private readonly ContactRecord pma, request;
    private readonly ParsedContactRouteClosure route;
    private readonly DeepIdV2MailboxGrantReplicaEvidence[] evidence;
    private readonly ulong effectiveExpiry;
    private readonly DeepIdV2ContactRouteTimeWindow verifiedAt;

    internal VerifiedDeepIdV2MailboxGrantIssuance(VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority root, OnionTrustedTimeAuthority time, ContactRecord pma,
        ContactRecord request, ParsedContactRouteClosure route, ulong effectiveExpiry,
        DeepIdV2MailboxGrantReplicaEvidence[] evidence, DeepIdV2ContactRouteTimeWindow verifiedAt)
    {
        this.network = network; this.root = root; this.time = time; this.pma = pma;
        this.request = request; this.route = route; this.effectiveExpiry = effectiveExpiry;
        this.evidence = evidence; this.verifiedAt = verifiedAt;
    }

    public MailboxCapabilityDomain Domain => (MailboxCapabilityDomain)request.Field(6).Span[0];
    public ReadOnlyMemory<byte> ExactXmg1 => request.CanonicalBytes.ToArray();

    public async ValueTask EnsureCurrentAsync(CancellationToken cancellationToken = default)
    { _ = await ReadAsync(cancellationToken).ConfigureAwait(false); }

    public async ValueTask VerifySuccessAsync(ReadOnlyMemory<byte> exactXmc1, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (exactXmc1.Length != 478) throw new CryptographicException("Mailbox winner must be an exact success.");
        var response = ContactCodec.Decode(ProtocolMagic.XMC1, exactXmc1.Span);
        ContactCodec.ValidateMailboxGrantResultBinding(request, response);
        ContactCodec.ValidateMailboxGrantResultRouteBinding(response, route);
        var first = await ReadAsync(cancellationToken).ConfigureAwait(false);
        RequireWinner(response, first.Window, first.Policy);
        var final = await ReadAsync(cancellationToken).ConfigureAwait(false);
        DeepIdV2MailboxGrantResultVerifier.RequireContinuous(first.Window, final.Window);
        RequireWinner(response, final.Window, final.Policy);
        cancellationToken.ThrowIfCancellationRequested();
    }

    private void RequireWinner(ContactRecord response, DeepIdV2ContactRouteTimeWindow window, VerifiedMailboxAuthorityV2 policy)
    {
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(response.Field(8).Span);
        var issuer = policy.ResolveIssuer(Domain);
        var start = DeepIdV2RouteContext.U64(request.Field(9).Span);
        var expiry = DeepIdV2RouteContext.U64(request.Field(10).Span);
        var serverTime = DeepIdV2RouteContext.U64(response.Field(4).Span);
        if (serverTime < start || serverTime >= expiry || serverTime > window.UpperUnixSeconds ||
            DeepIdV2RouteContext.U64(response.Field(6).Span) != expiry ||
            grant.Lifecycle != MailboxCapabilityLifecycle.Active ||
            !DeepIdV2RouteContext.Fixed(grant.MembershipCommitment.Span, route.Projection.ArtifactHash.Span) ||
            !DeepIdV2RouteContext.Fixed(grant.IssuerPublicKey.Span, issuer.PublicKey.Span) ||
            grant.Generation < Math.Max(1UL, policy.MinimumGrantGeneration) ||
            grant.NotBeforeUnixSeconds < issuer.ValidFromUnixSeconds ||
            grant.ExpiresAtUnixSeconds > policy.ExpiresAtUnixSeconds ||
            grant.ExpiresAtUnixSeconds > DeepIdV2MailboxGrantIssuanceVerifier.MaximumExpiry(network, route, effectiveExpiry) ||
            grant.ExpiresAtUnixSeconds - grant.NotBeforeUnixSeconds > policy.MaximumGrantLifetimeSeconds ||
            !PublicKeyAuth.VerifyDetached(grant.IssuerSignature.ToArray(),
                MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant), issuer.PublicKey.ToArray()))
            throw new CryptographicException("Mailbox winner is outside the original current issuance scope.");
        DeepIdV2MailboxGrantIssuanceVerifier.Covers(window, grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds);
    }

    private async ValueTask<(DeepIdV2ContactRouteTimeWindow Window, VerifiedMailboxAuthorityV2 Policy)> ReadAsync(CancellationToken ct)
    {
        var reading = await time.ReadCurrentAsync(ct).ConfigureAwait(false);
        var window = DeepIdV2MailboxGrantIssuanceVerifier.RequireAtReading(network, root,
            pma, request, route, effectiveExpiry, evidence, reading, ct);
        DeepIdV2MailboxGrantResultVerifier.RequireContinuous(verifiedAt, window);
        return (window, MailboxAuthorityV2Verifier.Verify(root, pma.CanonicalBytes.Span,
            window.LowerUnixSeconds, window.UpperUnixSeconds));
    }

    public async ValueTask<ReadOnlyMemory<byte>> AuthorSuccessAsync(IMailboxGrantIssuerSigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signer); cancellationToken.ThrowIfCancellationRequested();
        // Capture before an asynchronous callback; signer cannot substitute its identity.
        var exposedKey = signer.Ed25519PublicKey;
        if (exposedKey.Length != 32 || exposedKey.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException("Mailbox signer has no bounded role key.");
        var publicKey = exposedKey.ToArray();
        var first = await ReadAsync(cancellationToken).ConfigureAwait(false);
        var issuer = first.Policy.ResolveIssuer(Domain);
        if (!DeepIdV2RouteContext.Fixed(publicKey, issuer.PublicKey.Span))
            throw new CryptographicException("Mailbox signer is not the current PMA2 role issuer.");
        var start = first.Window.LowerUnixSeconds;
        var expiry = Math.Min(DeepIdV2MailboxGrantIssuanceVerifier.MaximumExpiry(network, route, effectiveExpiry),
            Math.Min(first.Policy.ExpiresAtUnixSeconds, checked(start + first.Policy.MaximumGrantLifetimeSeconds)));
        if (first.Window.UpperUnixSeconds >= expiry)
            throw new CryptographicException("Mailbox issuer has no remaining full grant interval.");
        var serial = new byte[16];
        do RandomNumberGenerator.Fill(serial); while (serial.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        var unsigned = new MailboxAuthenticatedGrant
        {
            Domain = Domain, Lifecycle = MailboxCapabilityLifecycle.Active,
            NetworkId = network.NetworkId, Epoch = DeepIdV2RouteContext.U64(route.Selection.Field(4).Span),
            Generation = Math.Max(1UL, first.Policy.MinimumGrantGeneration), Serial = serial,
            NotBeforeUnixSeconds = start, ExpiresAtUnixSeconds = expiry, OverlapUntilUnixSeconds = 0,
            PlacementCommitment = MailboxPlacementCommitment.Compute(new BlindedPlacementId(route.Reachability.Field(10).Span)),
            MembershipCommitment = route.Projection.ArtifactHash.ToArray(), IssuerPublicKey = publicKey,
            HolderPublicKey = request.Field(5).ToArray(), IssuerSignature = new byte[64],
        };
        _ = await ReadAsync(cancellationToken).ConfigureAwait(false);
        var signingBytes = MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(unsigned);
        var returnedSignature = await signer.SignAsync(signingBytes.ToArray(), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (returnedSignature.Length != 64) throw new CryptographicException("Mailbox issuer returned an unbounded detached signature.");
        var signature = returnedSignature.ToArray();
        if (!PublicKeyAuth.VerifyDetached(signature, signingBytes, publicKey))
            throw new CryptographicException("Mailbox issuer returned an invalid detached signature.");
        var final = await ReadAsync(cancellationToken).ConfigureAwait(false);
        DeepIdV2MailboxGrantResultVerifier.RequireContinuous(first.Window, final.Window);
        DeepIdV2MailboxGrantIssuanceVerifier.Covers(final.Window, start, expiry);
        var result = MailboxGrantResultAuthor.AuthorSuccess(request, route.ExactBytes.Span,
            unsigned with { IssuerSignature = signature }, final.Window.UpperUnixSeconds,
            DeepIdV2RouteContext.U64(request.Field(10).Span));
        cancellationToken.ThrowIfCancellationRequested(); return result.CanonicalBytes.ToArray();
    }
}

public static class DeepIdV2MailboxGrantIssuanceVerifier
{
    public static async ValueTask<VerifiedDeepIdV2MailboxGrantIssuance> VerifyAsync(
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority root,
        ReadOnlyMemory<byte> exactPma2, ReadOnlyMemory<byte> exactXmg1,
        ReadOnlyMemory<byte> exactRouteClosure, ulong effectiveExpiry,
        IReadOnlyList<DeepIdV2MailboxGrantReplicaEvidence> replicaEvidence,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(network); ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(replicaEvidence); ArgumentNullException.ThrowIfNull(trustedTime);
        cancellationToken.ThrowIfCancellationRequested();
        if (exactPma2.Length is < 12 or > 65_535 || exactXmg1.Length != 435 ||
            exactRouteClosure.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes ||
            replicaEvidence.Count != 2)
            throw new CryptographicException("Mailbox issuance inputs exceed their exact bounds.");
        var pma = ContactCodec.Decode(ProtocolMagic.PMA2, exactPma2.Span);
        var request = ContactCodec.Decode(ProtocolMagic.XMG1, exactXmg1.Span);
        var route = ContactRouteClosureCodec.Decode(exactRouteClosure.Span);
        var evidence = new DeepIdV2MailboxGrantReplicaEvidence[2];
        for (var index = 0; index < evidence.Length; index++)
        {
            var item = replicaEvidence[index] ?? throw new CryptographicException("Mailbox evidence is absent.");
            evidence[index] = new(item.NodeId.Span, item.Signature.Span);
        }
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        var first = RequireAtReading(network, root, pma, request, route, effectiveExpiry, evidence,
            await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false), cancellationToken);
        var final = RequireAtReading(network, root, pma, request, route, effectiveExpiry, evidence,
            await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false), cancellationToken);
        DeepIdV2MailboxGrantResultVerifier.RequireContinuous(first, final);
        cancellationToken.ThrowIfCancellationRequested();
        return new(network, root, trustedTime, pma, request, route, effectiveExpiry, evidence, final);
    }

    internal static DeepIdV2ContactRouteTimeWindow RequireAtReading(VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority root, ContactRecord pma, ContactRecord request,
        ParsedContactRouteClosure route, ulong effectiveExpiry, DeepIdV2MailboxGrantReplicaEvidence[] evidence,
        OnionMonotonicReading reading, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); network.EnsureCurrent(); var closure = network.Closure!;
        if (!Fixed(network.NetworkId.Span, root.NetworkId.Span) ||
            !Fixed(closure.View.FieldSpan(7), root.AuthorityCoreReference.Span) ||
            !Fixed(closure.Head.FieldSpan(8), root.AuthorityCoreReference.Span) ||
            !Fixed(reading.BootId.Span, closure.FreshnessBootId) ||
            reading.SampleSeconds < closure.FreshnessMonotonicSample ||
            reading.SampleSeconds >= closure.FreshnessDeadlineMonotonicSeconds)
            throw new CryptographicException("Mailbox issuer network/root/clock closure differs.");
        ulong lower, upper;
        try
        {
            var elapsed = checked(reading.SampleSeconds - closure.FreshnessMonotonicSample);
            lower = checked(closure.TrustedLowerUnixSeconds + elapsed);
            upper = checked(closure.TrustedUpperUnixSeconds + elapsed);
        }
        catch (OverflowException error) { throw new CryptographicException("Mailbox issuer time overflowed.", error); }
        var current = new DeepIdV2ContactRouteTimeWindow(lower, upper, reading);
        Covers(current, root.NotBefore, root.ExpiresAt);
        Covers(current, closure.View.NotBefore, closure.View.ExpiresAt);
        Covers(current, closure.Head.ValidFrom, closure.Head.ValidUntil);
        var policy = MailboxAuthorityV2Verifier.Verify(root, pma.CanonicalBytes.Span, lower, upper);
        if (!policy.BindsProjection(closure.Pmt.CanonicalBytes.Span) ||
            !Fixed(route.Projection.CanonicalBytes.Span, closure.Pmt.CanonicalBytes.Span) ||
            !Fixed(request.Field(1).Span, network.NetworkId.Span) ||
            !Fixed(route.Reachability.Field(1).Span, network.NetworkId.Span) ||
            !Fixed(request.Field(7).Span, closure.PmtArtifactReference) ||
            !Fixed(request.Field(8).Span, route.Selection.ArtifactHash.Span) ||
            !Fixed(route.Route.Field(8).Span, closure.ViewCoreReference) ||
            !Fixed(route.Route.Field(9).Span, XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNH1, closure.Head.CoreHash.Span)) ||
            !Fixed(route.Route.Field(19).Span, route.Successor.Field(12).Span) ||
            !Fixed(route.Successor.Field(8).Span, closure.ViewCoreReference))
            throw new CryptographicException("Mailbox issuance route is not the exact current root/projection/view/head.");
        ContactCodec.ValidateThresholdRouteGraph(route.Authorization, route.Route, route.Successor, route.Projection, route.Selection);
        foreach (var record in new[] { route.Reachability, route.Authorization, route.Route, route.Successor, route.Projection, route.Selection })
        {
            var tags = record.Magic switch
            {
                ProtocolMagic.XRR1 => (16, 17), ProtocolMagic.XRA1 => (12, 13),
                ProtocolMagic.XRC1 => (17, 18), ProtocolMagic.XSS1 => (10, 11),
                ProtocolMagic.PMT2 => (11, 12), _ => (8, 9),
            };
            Covers(current, U64(record.Field(tags.Item1).Span), U64(record.Field(tags.Item2).Span));
        }
        var selected = route.Selection.Field(6).Span;
        for (var offset = 0; offset < selected.Length; offset += 32)
            if (network.ResolveNode(selected.Slice(offset, 32)).KeyEpoch != U64(route.Route.Field(13).Span))
                throw new CryptographicException("Mailbox route traffic-key epoch differs from current nodes.");
        DeepIdV2RouteContext.VerifyWitnesses(route.Selection, 11, root);
        DeepIdV2RouteContext.VerifyWitnesses(route.Route, 21, root);
        DeepIdV2RouteContext.VerifyWitnesses(route.Successor, 14, root);
        var start = U64(request.Field(9).Span); var expiry = U64(request.Field(10).Span);
        var domain = (MailboxCapabilityDomain)request.Field(6).Span[0];
        var isDeposit = Fixed(request.Field(4).Span, route.Reachability.Field(10).Span);
        if (expiry <= start || expiry - start > 120 ||
            expiry > MaximumExpiry(network, route, effectiveExpiry) ||
            effectiveExpiry == 0 || effectiveExpiry > U64(route.Reachability.Field(17).Span) ||
            (domain == MailboxCapabilityDomain.Deposit ? !isDeposit : isDeposit) ||
            U64(route.Route.Field(18).Span) > closure.HardUpperUnixSeconds)
            throw new CryptographicException("Mailbox request exceeds its exact role/route/window scope.");
        Covers(current, start, expiry); Covers(current, 0, effectiveExpiry);
        var placement = ContactServicePlacementFactory.Create(network, ContactServiceRequestKind.ResolveInvite, request.Field(3));
        var stores = placement.RankedReplicaNodeIds;
        if (stores.Count != 2 || evidence.Length != 2 || Fixed(evidence[0].NodeId.Span, evidence[1].NodeId.Span))
            throw new CryptographicException("Mailbox issuance requires the two independent selected stores.");
        var tuple = MailboxGrantRouteEvidenceAuthentication.CreateTuple(SHA256.HashData(request.CanonicalBytes.Span),
            request.Field(3).Span, MailboxGrantCapabilityDigest.Compute(request.Field(4).Span, domain),
            (byte)domain, 1, route.ExactHash.Span, effectiveExpiry);
        var signing = MailboxGrantRouteEvidenceAuthentication.GetSigningBytes(tuple);
        foreach (var item in evidence)
            if (!stores.Any(store => Fixed(store.Span, item.NodeId.Span)) ||
                !PublicKeyAuth.VerifyDetached(item.Signature.ToArray(), signing,
                    network.ResolveNodeIdentityPublicKey(item.NodeId).ToArray()))
                throw new CryptographicException("Mailbox durable route evidence is not signed by both current selected stores.");
        ct.ThrowIfCancellationRequested(); return current;
    }

    internal static ulong MaximumExpiry(VerifiedOnionNetworkContext network, ParsedContactRouteClosure route, ulong effectiveExpiry) =>
        new[] { network.MaximumRecordExpiryUnixSeconds, effectiveExpiry,
            U64(route.Reachability.Field(17).Span), U64(route.Authorization.Field(13).Span),
            U64(route.Route.Field(18).Span), U64(route.Successor.Field(11).Span),
            U64(route.Projection.Field(12).Span), U64(route.Selection.Field(9).Span) }.Min();
    internal static void Covers(DeepIdV2ContactRouteTimeWindow current, ulong start, ulong expiry)
    {
        if (current.LowerUnixSeconds > current.UpperUnixSeconds || start > current.LowerUnixSeconds || current.UpperUnixSeconds >= expiry)
            throw new CryptographicException("Mailbox issuance does not cover the complete authenticated time interval.");
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => DeepIdV2RouteContext.Fixed(a, b);
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
}
