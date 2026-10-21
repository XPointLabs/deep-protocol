using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

public sealed partial class VerifiedMailboxHostAuthorityV2
{
    /// <summary>Historical first-replica preparation only. The native owner must
    /// independently join the original replay, completed Store and blob before
    /// exporting evidence. This does not authorize an expired-grant effect.</summary>
    public async ValueTask<PreparedMailboxPeerReservationV2> PrepareHistoricalStoreSourceAsync(
        ReadOnlyMemory<byte> exactRequest, IMailboxPeerReplayJournal replayJournal,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(replayJournal);
        var owned = exactRequest.ToArray();
        var facts = await HistoricalStoreFactsAsync(owned, cancellationToken).ConfigureAwait(false);
        var plan = MailboxPeerWireV2Codec.PrepareReplayReservation(owned, facts.Policy,
            new SodiumMailboxPeerReplicationCrypto(), facts.Proofs, replayJournal);
        RequireHistoricalStoreGrant(facts.Grant, plan.Snapshot.ReservedAtUnixSeconds);
        plan.RequireReservable();
        await EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
        return plan;
    }

    /// <summary>Authenticates historical PSR1 for metadata-only native repair.
    /// No current grant, mutation, dispatch, receipt or quorum authority is returned.</summary>
    public async ValueTask<PreparedMailboxPeerReservationV2> PrepareHistoricalStoreRecoveryAsync(
        ReadOnlyMemory<byte> exactForwarding, CancellationToken cancellationToken = default)
    {
        var owned = exactForwarding.ToArray();
        var original = MailboxPeerWireV2Codec.DecodeForwardedStoreRequest(owned);
        var facts = await HistoricalStoreFactsAsync(original, cancellationToken).ConfigureAwait(false);
        var plan = MailboxPeerWireV2Codec.PrepareForwardedStoreRecovery(owned, facts.Policy,
            new SodiumMailboxPeerReplicationCrypto(), facts.Proofs);
        RequireHistoricalStoreGrant(facts.Grant, plan.Snapshot.ReservedAtUnixSeconds);
        await EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
        return plan;
    }

    private async ValueTask<(MailboxPeerWireVerificationPolicyV2 Policy, HistoricalStoreProofs Proofs,
        MailboxAuthenticatedGrant Grant)> HistoricalStoreFactsAsync(byte[] exact, CancellationToken token)
    {
        var request = MailboxPeerWireV2Codec.Decode(exact);
        var proof = request.SenderMembershipProof.CanonicalInclusionProof.ToArray();
        if (request.Operation != MailboxPeerReplicationOperation.Store || proof.Length != 342 ||
            !Fixed(proof, request.RecipientMembershipProof.CanonicalInclusionProof.Span))
            throw new CryptographicException("Historical Store requires one exact current-format grant binding.");
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(proof.AsSpan(38));
        _ = await ReadAsync(token).ConfigureAwait(false);
        var projection = VerifiedLogicalMailboxAssignment.FromMembership(network, root, grant.MembershipCommitment).Projection;
        // Original issuer facts are bound to an exact authenticated retained
        // PMA/projection, never reinterpreted as today's grant authority.
        _ = RequireHistoricalStoreIssuer(grant);
        var reference = ContactCodec.ArtifactReference(ProtocolMagic.PMT2, projection).CanonicalBytes;
        var ranking = ContactRouteThresholdAuthor.RankReplicas(network.NetworkId.Span, reference.Span,
            projection.FieldSpan(6), grant.SelectionInput.Span, projection.FieldSpan(9), 2);
        if (grant.Domain != MailboxCapabilityDomain.Deposit ||
            !Fixed(grant.NetworkId.Span, network.NetworkId.Span) ||
            !Fixed(proof.AsSpan(0, 38), reference.Span) ||
            grant.Epoch != BinaryPrimitives.ReadUInt64BigEndian(projection.FieldSpan(6)) ||
            request.Epoch != grant.Epoch || !Fixed(request.MembershipCommitment.Span, grant.MembershipCommitment.Span) ||
            !Fixed(request.PlacementCommitment.Span, grant.PlacementCommitment.Span) ||
            !Fixed(request.SenderRouterId.Span, ranking.AsSpan(0, 32)) ||
            !Fixed(request.RecipientRouterId.Span, ranking.AsSpan(32, 32)))
            throw new CryptographicException("Historical Store changes its signed namespace or selected replica pair.");
        var sender = await ResolveReplicaAsync(request.SenderRouterId, token).ConfigureAwait(false);
        var recipient = await ResolveReplicaAsync(request.RecipientRouterId, token).ConfigureAwait(false);
        var current = await ReadAsync(token).ConfigureAwait(false);
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Payload.Span);
        return (new()
        {
            ExpectedOperation = MailboxPeerReplicationOperation.Store, Epoch = request.Epoch,
            OperationId = request.OperationId, SenderRouterId = sender.NodeId, RecipientRouterId = recipient.NodeId,
            MembershipCommitment = grant.MembershipCommitment, PlacementCommitment = grant.PlacementCommitment,
            PlacementId = envelope.PlacementId, NowUnixSeconds = current.Upper,
            EpochExpiresAtUnixSeconds = request.ExpiresAtUnixSeconds
        }, new(sender, recipient, grant, proof), grant);
    }

    private void RequireHistoricalStoreGrant(MailboxAuthenticatedGrant grant, ulong provenAdmission)
    {
        // Historical lineage verification is purpose-separated from ReadAsync's
        // ACTUAL current clock. Never call EnsureGrantCurrent with backdated time.
        _ = RequireHistoricalStoreIssuer(grant);
        if (provenAdmission < grant.NotBeforeUnixSeconds || provenAdmission >= grant.ExpiresAtUnixSeconds)
            throw new CryptographicException("Historical Store does not prove original issuer admission.");
    }

    private sealed class HistoricalStoreProofs(VerifiedMailboxReplicaV2 sender, VerifiedMailboxReplicaV2 recipient,
        MailboxAuthenticatedGrant grant, byte[] exact) : IMailboxReplicaMembershipProofVerifier
    {
        public bool VerifyStorageReplica(MailboxReplicaMembershipProof proof, ulong verificationTimeUnixSeconds) =>
            proof.Epoch == grant.Epoch && Fixed(proof.MembershipCommitment.Span, grant.MembershipCommitment.Span) &&
            Fixed(proof.CanonicalInclusionProof.Span, exact) &&
            (Fixed(proof.ReplicaId.Span, sender.NodeId.Span) && Fixed(proof.SigningPublicKey.Span, sender.SigningPublicKey.Span) ||
             Fixed(proof.ReplicaId.Span, recipient.NodeId.Span) && Fixed(proof.SigningPublicKey.Span, recipient.SigningPublicKey.Span));
    }
}
