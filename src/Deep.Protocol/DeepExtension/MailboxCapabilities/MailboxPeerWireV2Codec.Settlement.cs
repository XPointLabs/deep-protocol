using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static partial class MailboxPeerWireV2Codec
{
    // Only the closed host supplies descriptor keys. No admission policy/time,
    // replay owner or caller callback is accepted, and no request capability is
    // returned. The two signed commits attest past admission, not currentness.
    internal static void VerifyStoreSettlement(ReadOnlySpan<byte> exactRequest, ReadOnlySpan<byte> exactQuorum,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> senderKey, ReadOnlySpan<byte> recipientKey)
    {
        var request = Decode(exactRequest);
        if (request.Operation != MailboxPeerReplicationOperation.Store ||
            !FixedEquals(senderKey, request.SenderMembershipProof.SigningPublicKey.Span) ||
            !FixedEquals(recipientKey, request.RecipientMembershipProof.SigningPublicKey.Span))
            throw Error(MailboxPeerReplicationError.BindingMismatch, "Store settlement descriptor binding differs.");
        var first = request.SenderMembershipProof.CanonicalInclusionProof;
        var second = request.RecipientMembershipProof.CanonicalInclusionProof;
        if (first.Length != 342 || !FixedEquals(first.Span, second.Span) ||
            !first.Span[..4].SequenceEqual(ProtocolMagicBytes.PMT2) || first.Span[4] != 0 || first.Span[5] != 1)
            throw Error(MailboxPeerReplicationError.InvalidMembershipProof, "Store settlement proof differs.");
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(first.Span[38..]);
        if (grant.Domain != MailboxCapabilityDomain.Deposit || grant.Lifecycle != MailboxCapabilityLifecycle.Active ||
            !FixedEquals(grant.NetworkId.Span, network) || grant.Epoch != request.Epoch ||
            !FixedEquals(grant.MembershipCommitment.Span, first.Span.Slice(6, 32)) ||
            !FixedEquals(grant.MembershipCommitment.Span, request.MembershipCommitment.Span) ||
            !FixedEquals(grant.PlacementCommitment.Span, request.PlacementCommitment.Span) ||
            request.CreatedAtUnixSeconds < grant.NotBeforeUnixSeconds || request.CreatedAtUnixSeconds >= grant.ExpiresAtUnixSeconds)
            throw Error(MailboxPeerReplicationError.BindingMismatch, "Store settlement grant binding differs.");
        var envelope = DecodeCanonicalEnvelope(request.Payload.Span);
        if (!FixedEquals(SHA256.HashData(request.Payload.Span), request.PayloadDigest.Span) ||
            envelope.Epoch != request.Epoch || !FixedEquals(envelope.OperationId.Span, request.OperationId.Span) ||
            !FixedEquals(envelope.MailboxId.Bytes.Span, request.BlindedMailboxId.Span) ||
            !FixedEquals(MailboxPlacementCommitment.Compute(envelope.PlacementId), request.PlacementCommitment.Span) ||
            envelope.CreatedAtUnixSeconds > request.CreatedAtUnixSeconds || envelope.ExpiresAtUnixSeconds != request.ExpiresAtUnixSeconds)
            throw Error(MailboxPeerReplicationError.BindingMismatch, "Store settlement body differs.");
        var crypto = SettlementCrypto.Instance;
        if (!crypto.Verify(senderKey, GetSigningDigest(request), request.Signature.Span))
            throw Error(MailboxPeerReplicationError.InvalidSignature, "Store settlement sender signature differs.");
        var digest = DomainSeparatedHash("deep.mailbox.peer.request-identity.v2"u8, exactRequest);
        var verified = VerifyDurableQuorumCore(exactQuorum, request, envelope, digest, crypto);
        if (!FixedEquals(verified.CoordinatorReceipt.CoordinatorId.Span, request.SenderRouterId.Span) ||
            verified.ReplicaReceipts.Any(receipt => receipt.AcceptedAtUnixSeconds < grant.NotBeforeUnixSeconds ||
                receipt.AcceptedAtUnixSeconds >= grant.ExpiresAtUnixSeconds))
            throw Error(MailboxPeerReplicationError.InvalidReceipt, "Store settlement acceptance interval differs.");
    }

    private sealed class SettlementCrypto : IMailboxPeerReplicationCrypto
    {
        internal static readonly SettlementCrypto Instance = new();
        public byte[] Digest(ReadOnlySpan<byte> canonicalBytes) => SHA256.HashData(canonicalBytes);
        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature) =>
            publicKey.Length == 32 && signature.Length == 64 &&
            PublicKeyAuth.VerifyDetached(signature.ToArray(), signingBytes.ToArray(), publicKey.ToArray());
    }
}
