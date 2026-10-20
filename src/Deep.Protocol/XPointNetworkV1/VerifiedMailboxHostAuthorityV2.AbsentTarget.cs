using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.XPointNetworkV1;

public sealed partial class VerifiedMailboxHostAuthorityV2
{
    /// <summary>Verifies current Retrieve authority and exact source-durable
    /// PTR1 without inventing a placement preimage. The native owner must prove
    /// independently known pre-effect Store custody and actual target absence.</summary>
    public async ValueTask<PreparedMailboxPeerReservationV2> PrepareAbsentTargetTombstoneAsync(
        ReadOnlyMemory<byte> exactForwarding, IMailboxPeerReplayJournal replayJournal,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(replayJournal);
        var owned = exactForwarding.ToArray();
        var request = MailboxPeerWireV2Codec.Decode(MailboxPeerWireV2Codec.DecodeForwardedTombstoneRequest(owned));
        var proof = request.SenderMembershipProof.CanonicalInclusionProof.ToArray();
        if (request.Operation != MailboxPeerReplicationOperation.Tombstone || proof.Length != 342 ||
            !Fixed(proof, request.RecipientMembershipProof.CanonicalInclusionProof.Span))
            throw new CryptographicException("Absent target requires exact source-durable tombstone authority.");
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(proof.AsSpan(38));
        var replicas = await GetSelectedRetainedReadReplicasAsync(proof.AsMemory(38), cancellationToken).ConfigureAwait(false);
        var current = await ReadAsync(cancellationToken).ConfigureAwait(false);
        var projection = RequireRetainedReadGrant(grant, current);
        if (!Fixed(proof.AsSpan(0, 38), ContactCodec.ArtifactReference(ProtocolMagic.PMT2, projection).CanonicalBytes.Span) ||
            !replicas.Any(r => Fixed(r.NodeId.Span, request.SenderRouterId.Span)) ||
            !replicas.Any(r => Fixed(r.NodeId.Span, request.RecipientRouterId.Span)))
            throw new CryptographicException("Absent target changes its selected pair or exact projection.");
        var sender = replicas.Single(r => Fixed(r.NodeId.Span, request.SenderRouterId.Span));
        var recipient = replicas.Single(r => Fixed(r.NodeId.Span, request.RecipientRouterId.Span));
        var plan = MailboxPeerWireV2Codec.PrepareHostVerifiedTombstone(owned, new()
        {
            ExpectedOperation = MailboxPeerReplicationOperation.Tombstone, Epoch = grant.Epoch,
            OperationId = request.OperationId, SenderRouterId = sender.NodeId, RecipientRouterId = recipient.NodeId,
            MembershipCommitment = grant.MembershipCommitment, PlacementCommitment = grant.PlacementCommitment,
            // No preimage is synthesized. Only the private host-verified codec
            // path above uses the actual current grant's commitment instead.
            PlacementId = null!, NowUnixSeconds = current.Upper, EpochExpiresAtUnixSeconds = request.ExpiresAtUnixSeconds
        }, new SodiumMailboxPeerReplicationCrypto(), new HistoricalStoreProofs(sender, recipient, grant, proof), replayJournal);
        await EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
        return plan;
    }
}
