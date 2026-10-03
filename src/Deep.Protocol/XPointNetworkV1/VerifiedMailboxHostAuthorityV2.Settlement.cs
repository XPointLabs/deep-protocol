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
        if (proof.Length != 342 || !Fixed(proof.Span[..38], ProjectionReference.Span))
            throw new CryptographicException("Store settlement is outside the exact current projection.");
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(proof.Span[38..]);
        var current = await ReadAsync(cancellationToken).ConfigureAwait(false);
        var issuer = current.Policy.ResolveIssuer(MailboxCapabilityDomain.Deposit);
        // These are past signed facts, not a current grant/time authorization.
        // Missing issuer/descriptor history fails closed rather than installing
        // receipt time or bypassing the current host's protected clock.
        if (grant.Domain != MailboxCapabilityDomain.Deposit || grant.Epoch != SelectionEpoch ||
            !Fixed(grant.MembershipCommitment.Span, MembershipCommitment.Span) ||
            !Fixed(grant.IssuerPublicKey.Span, issuer.PublicKey.Span) ||
            grant.NotBeforeUnixSeconds < issuer.ValidFromUnixSeconds ||
            grant.ExpiresAtUnixSeconds > issuer.ValidUntilUnixSeconds ||
            grant.ExpiresAtUnixSeconds - grant.NotBeforeUnixSeconds > current.Policy.MaximumGrantLifetimeSeconds ||
            !PublicKeyAuth.VerifyDetached(grant.IssuerSignature.ToArray(),
                MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant), issuer.PublicKey.ToArray()))
            throw new CryptographicException("Store settlement has no authenticated issuer scope.");
        var ranked = await RankReplicasAsync(grant.SelectionInput, cancellationToken).ConfigureAwait(false);
        if (ranked.Count != 2 ||
            !ranked.Any(id => Fixed(id.Span, request.SenderRouterId.Span)) ||
            !ranked.Any(id => Fixed(id.Span, request.RecipientRouterId.Span)))
            throw new CryptographicException("Store settlement differs from the signed selected pair.");
        MailboxPeerWireV2Codec.VerifyStoreSettlement(ownedRequest, ownedQuorum, NetworkId.Span,
            network.ResolveNodeIdentityPublicKey(request.SenderRouterId).Span,
            network.ResolveNodeIdentityPublicKey(request.RecipientRouterId).Span);
        await ReadAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
    }
}
