using Deep.Protocol.DeepExtension.MailboxCapabilities;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

public sealed partial class VerifiedMailboxHostAuthorityV2
{
    /// <summary>Authenticates a past exact two-node Store commitment. Returns no
    /// grant, replay reservation, mutation or dispatch authority (DR-0086).</summary>
    public async ValueTask VerifyStoreSettlementAsync(ReadOnlyMemory<byte> exactPrq2,
        ReadOnlyMemory<byte> exactMqr3, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Bound/capture both inputs before the first external clock callback.
        var request = MailboxPeerWireV2Codec.Decode(exactPrq2.Span);
        var ownedRequest = MailboxPeerWireV2Codec.Encode(request);
        if (request.Operation != MailboxPeerReplicationOperation.Store)
            throw new CryptographicException("Store settlement requires the exact Store operation.");
        _ = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Payload.Span);
        var expectedQuorumLength = MailboxReceiptV3Limits.QuorumFixedHeaderLength +
            2 * MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength + 64;
        if (exactMqr3.Length != expectedQuorumLength)
            throw new CryptographicException("Store settlement requires the exact Ed25519 quorum profile.");
        var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(exactMqr3.Span);
        var ownedQuorum = MailboxReceiptV3Codec.EncodeDurableQuorum(quorum);
        var proof = request.SenderMembershipProof.CanonicalInclusionProof;
        if (proof.Length != 342)
            throw new CryptographicException("Store settlement has a noncanonical membership proof.");
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(proof.Span[38..]);
        var assignment = VerifiedLogicalMailboxAssignment.FromMembership(network, root, grant.MembershipCommitment);
        if (!Fixed(proof.Span[..38], Deep.Protocol.ContactV1.ContactCodec.ArtifactReference(
            ProtocolMagic.PMT2, assignment.Projection).CanonicalBytes.Span))
            throw new CryptographicException("Store settlement differs from its authenticated logical assignment.");
        var current = await ReadAsync(cancellationToken).ConfigureAwait(false);
        var issuer = current.Policy.ResolveIssuer(MailboxCapabilityDomain.Deposit);
        // These are past signed facts, not a current grant/time authorization.
        // Missing issuer/descriptor history fails closed rather than installing
        // receipt time or bypassing the current host's protected clock.
        if (grant.Domain != MailboxCapabilityDomain.Deposit || grant.Epoch != SelectionEpoch ||
            !Fixed(grant.IssuerPublicKey.Span, issuer.PublicKey.Span) ||
            grant.NotBeforeUnixSeconds < issuer.ValidFromUnixSeconds ||
            grant.ExpiresAtUnixSeconds > issuer.ValidUntilUnixSeconds ||
            grant.ExpiresAtUnixSeconds - grant.NotBeforeUnixSeconds > current.Policy.MaximumGrantLifetimeSeconds ||
            !PublicKeyAuth.VerifyDetached(grant.IssuerSignature.ToArray(),
                MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant), issuer.PublicKey.ToArray()))
            throw new CryptographicException("Store settlement has no authenticated issuer scope.");
        var projection = assignment.Projection;
        var ranked = Deep.Protocol.ContactV1.ContactRouteThresholdAuthor.RankReplicas(NetworkId.Span,
            Deep.Protocol.ContactV1.ContactCodec.ArtifactReference(ProtocolMagic.PMT2, projection).CanonicalBytes.Span,
            projection.FieldSpan(6), grant.SelectionInput.Span, projection.FieldSpan(9), projection.FieldSpan(7)[0]);
        if (ranked.Length != 64 ||
            !((Fixed(ranked.AsSpan(0, 32), request.SenderRouterId.Span) && Fixed(ranked.AsSpan(32, 32), request.RecipientRouterId.Span)) ||
              (Fixed(ranked.AsSpan(32, 32), request.SenderRouterId.Span) && Fixed(ranked.AsSpan(0, 32), request.RecipientRouterId.Span))))
            throw new CryptographicException("Store settlement differs from the signed selected pair.");
        MailboxPeerWireV2Codec.VerifyStoreSettlement(ownedRequest, ownedQuorum, NetworkId.Span,
            network.ResolveNodeIdentityPublicKey(request.SenderRouterId).Span,
            network.ResolveNodeIdentityPublicKey(request.RecipientRouterId).Span);
        await ReadAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
    }
}
