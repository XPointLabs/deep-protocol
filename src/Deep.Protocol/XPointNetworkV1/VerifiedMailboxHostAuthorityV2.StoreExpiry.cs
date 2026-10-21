using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

public sealed partial class VerifiedMailboxHostAuthorityV2
{
    /// <summary>Authenticates permanent expiry of the exact original Store
    /// permission. Does not prove noncommit or return current authority (DR-0134).</summary>
    public async ValueTask VerifyStoreExpiryExclusionAsync(ReadOnlyMemory<byte> exactPrq2,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var request = MailboxPeerWireV2Codec.Decode(exactPrq2.Span);
        var owned = MailboxPeerWireV2Codec.Encode(request);
        if (request.Operation != MailboxPeerReplicationOperation.Store)
            throw new CryptographicException("Store exclusion requires the original Store operation.");
        _ = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Payload.Span);
        var proof = request.SenderMembershipProof.CanonicalInclusionProof;
        if (proof.Length != 342)
            throw new CryptographicException("Store exclusion has a noncanonical membership proof.");
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(proof.Span[38..]);
        var assignment = VerifiedLogicalMailboxAssignment.FromMembership(network, root, grant.MembershipCommitment);
        var projection = assignment.Projection;
        var reference = ContactCodec.ArtifactReference(ProtocolMagic.PMT2, projection).CanonicalBytes;
        if (!Fixed(proof.Span[..38], reference.Span) || grant.Epoch != SelectionEpoch ||
            grant.Epoch != BinaryPrimitives.ReadUInt64BigEndian(projection.FieldSpan(6)))
            throw new CryptographicException("Store exclusion differs from its authenticated logical assignment.");
        // These checks cannot be short-circuited by an untrusted expiry value.
        _ = MailboxPeerWireV2Codec.VerifyOriginalStoreRequest(owned, NetworkId.Span,
            network.ResolveNodeIdentityPublicKey(request.SenderRouterId).Span,
            network.ResolveNodeIdentityPublicKey(request.RecipientRouterId).Span);
        var ranked = ContactRouteThresholdAuthor.RankReplicas(NetworkId.Span, reference.Span,
            projection.FieldSpan(6), grant.SelectionInput.Span, projection.FieldSpan(9), projection.FieldSpan(7)[0]);
        if (ranked.Length != 64 || !Fixed(ranked.AsSpan(0, 32), request.SenderRouterId.Span) ||
            !Fixed(ranked.AsSpan(32, 32), request.RecipientRouterId.Span))
            throw new CryptographicException("Store exclusion differs from the signed writer order.");
        var current = await ReadAsync(cancellationToken).ConfigureAwait(false);
        _ = RequireHistoricalStoreIssuer(grant);
        if (current.Lower < grant.ExpiresAtUnixSeconds)
            throw new CryptographicException("Original Store permission has not permanently expired.");
        var final = await ReadAsync(cancellationToken).ConfigureAwait(false);
        if (final.Lower < grant.ExpiresAtUnixSeconds)
            throw new CryptographicException("Original Store exclusion lost current lower time.");
        cancellationToken.ThrowIfCancellationRequested();
    }
}
