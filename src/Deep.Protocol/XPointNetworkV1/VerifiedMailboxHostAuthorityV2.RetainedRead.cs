using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.XPointNetworkV1;

public sealed partial class VerifiedMailboxHostAuthorityV2
{
    /// <summary>Authenticates the exact original PMA2/PMT2 namespace in this
    /// current verified history. No current issuer, expired grant, non-issuance,
    /// epoch-exclusion or deletion authority is returned.</summary>
    public async ValueTask RequireOriginalNamespaceAsync(ReadOnlyMemory<byte> exactPma2,
        ReadOnlyMemory<byte> exactPmt2, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var originalPolicy = ContactCodec.Decode(ProtocolMagic.PMA2, exactPma2.Span);
        var projection = ContactCodec.Decode(ProtocolMagic.PMT2, exactPmt2.Span);
        _ = await ReadAsync(cancellationToken).ConfigureAwait(false);
        Require();
        _ = await ReadAsync(cancellationToken).ConfigureAwait(false);
        Require();
        cancellationToken.ThrowIfCancellationRequested();

        void Require()
        {
            var ancestor = XPointOnionCapabilityProducer.RequireRetainedProjectionAuthority(network, root, projection);
            if (BinaryPrimitives.ReadUInt16BigEndian(originalPolicy.FieldSpan(9)) != 2 ||
                !Fixed(originalPolicy.FieldSpan(1), network.NetworkId.Span) ||
                !Fixed(projection.FieldSpan(4), XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.PMA2, originalPolicy.CoreHash.Span)) ||
                !Fixed(originalPolicy.FieldSpan(13), XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNA1, ancestor.CoreHash.Span)))
                throw new CryptographicException("The original mailbox namespace changes its verified projection or authority.");
            var issue = BinaryPrimitives.ReadUInt64BigEndian(originalPolicy.FieldSpan(11));
            MailboxAuthorityV2Verifier.VerifyHistoricalLineage(root, originalPolicy.CanonicalBytes.Span, issue, issue);
            XPointOnionCapabilityProducer.VerifyContactThreshold(projection, ancestor);
        }
    }

    /// <summary>Copied selected current-node facts for a still-current Retrieve
    /// grant naming a verified retained PMT2. Not holder, replay, revocation,
    /// object availability, mutation, dispatch or expired-grant authority.</summary>
    public async ValueTask<IReadOnlyList<VerifiedMailboxReplicaV2>> GetSelectedRetainedReadReplicasAsync(
        ReadOnlyMemory<byte> exactMcg3, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(exactMcg3.Span);
        if (grant.Domain != MailboxCapabilityDomain.Retrieve)
            throw new CryptographicException("Retained selection facts require a Retrieve grant.");
        var before = await ReadAsync(cancellationToken).ConfigureAwait(false);
        var projection = RequireRetainedReadGrant(grant, before);
        if (projection.FieldSpan(7)[0] != 2)
            throw new CryptographicException("Retained mailbox selection requires exactly two replicas.");
        var ranked = ContactRouteThresholdAuthor.RankReplicas(network.NetworkId.Span,
            ContactCodec.ArtifactReference(ProtocolMagic.PMT2, projection).CanonicalBytes.Span,
            projection.FieldSpan(6), grant.SelectionInput.Span, projection.FieldSpan(9), 2);
        var replicas = new VerifiedMailboxReplicaV2[2];
        for (var index = 0; index < replicas.Length; index++)
        {
            var id = ranked.AsSpan(index * 32, 32).ToArray();
            // Old rows select stable node IDs, not old origins, receipt keys or
            // transport authority. Removed/non-Mailbox nodes cannot be reranked.
            if (!network.Closure!.PmtNodeIds.Any(candidate => Fixed(candidate, id)))
                throw new CryptographicException("A retained replica is not a current admitted Mailbox node.");
            var node = network.ResolveNode(id);
            replicas[index] = new VerifiedMailboxReplicaV2(id, network.ResolveNodeIdentityPublicKey(id).Span,
                new VerifiedOnionNextHopTransport(network, node));
        }
        var after = await ReadAsync(cancellationToken).ConfigureAwait(false);
        _ = RequireRetainedReadGrant(grant, after);
        cancellationToken.ThrowIfCancellationRequested();
        return Array.AsReadOnly(replicas);
    }

    internal ContactRecord RequireRetainedReadGrant(MailboxAuthenticatedGrant grant,
        (VerifiedMailboxAuthorityV2 Policy, ulong Lower, ulong Upper) current)
    {
        if (grant.Domain != MailboxCapabilityDomain.Retrieve)
            throw new CryptographicException("Retained selection cannot authorize Store.");
        var projection = network.Closure!.RetainedPmts.SingleOrDefault(candidate =>
            Fixed(candidate.ArtifactHash.Span, grant.MembershipCommitment.Span) &&
            BinaryPrimitives.ReadUInt64BigEndian(candidate.FieldSpan(6)) == grant.Epoch);
        if (projection is null)
            throw new CryptographicException("The exact retained selection is absent from the verified network lineage.");
        RequireIssuerGrant(grant, current);
        return projection;
    }
}
