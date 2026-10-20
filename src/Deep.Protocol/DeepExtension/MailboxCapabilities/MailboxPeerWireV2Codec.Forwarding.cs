using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static partial class MailboxPeerWireV2Codec
{
    public const int TombstoneForwardingOverhead =
        8 + MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength + 64;

    /// <summary>Closed sender operation, only after its exact native durable mutation.</summary>
    public static byte[] CreateDurableTombstoneForwarding(
        VerifiedMailboxPeerWireRequestV2 original, ReadOnlySpan<byte> senderReceipt,
        ReadOnlySpan<byte> senderSeed)
    {
        ArgumentNullException.ThrowIfNull(original);
        var crypto = new SodiumMailboxPeerReplicationCrypto();
        var receipt = RequireForwardingReceipt(original.Request, senderReceipt, crypto,
            original.Request.ExpiresAtUnixSeconds - 1);
        if (senderSeed.Length != 32 ||
            !FixedEquals(crypto.GetPublicKey(senderSeed),
                original.Request.SenderMembershipProof.SigningPublicKey.Span) ||
            receipt.AcceptedAtUnixSeconds != original.ReplayClaim.ReservedAtUnixSeconds)
            throw Error(MailboxPeerReplicationError.InvalidReceipt, "PTR1 sender custody differs.");
        var request = Encode(original.Request);
        var result = new byte[checked(request.Length + TombstoneForwardingOverhead)];
        ProtocolMagicBytes.PTR1.CopyTo(result);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(4), checked((uint)request.Length));
        request.CopyTo(result, 8);
        senderReceipt.CopyTo(result.AsSpan(8 + request.Length));
        var privateKey = PublicKeyAuth.GenerateKeyPair(senderSeed.ToArray()).PrivateKey;
        try
        {
            PublicKeyAuth.SignDetached(ForwardingDigest(result.AsSpan(0, result.Length - 64)),
                privateKey).CopyTo(result, result.Length - 64);
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
        return result;
    }

    /// <summary>Canonical framing only; grants no replay/mutation authority.</summary>
    public static byte[] DecodeForwardedTombstoneRequest(ReadOnlySpan<byte> encoded)
    {
        var length = ForwardedRequestLength(encoded);
        var request = encoded.Slice(8, length);
        if (Decode(request).Operation != MailboxPeerReplicationOperation.Tombstone)
            throw Error(MailboxPeerReplicationError.InvalidPayload, "PTR1 requires Tombstone.");
        return request.ToArray();
    }

    public static VerifiedMailboxPeerWireRequestV2 VerifyAndReserveForwardedTombstone(
        ReadOnlySpan<byte> encoded, MailboxPeerWireVerificationPolicyV2 policy,
        IMailboxPeerReplicationCrypto crypto,
        IMailboxReplicaMembershipProofVerifier membershipVerifier,
        IMailboxPeerReplayJournal replayJournal)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(membershipVerifier);
        ArgumentNullException.ThrowIfNull(replayJournal);
        var length = ForwardedRequestLength(encoded);
        var (request, envelope, claim) = VerifyRequest(encoded.Slice(8, length),
            policy, crypto, membershipVerifier, enforceAdmissionFreshness: false);
        if (!crypto.Verify(request.SenderMembershipProof.SigningPublicKey.Span,
            ForwardingDigest(encoded[..^64]), encoded[^64..]))
            throw Error(MailboxPeerReplicationError.InvalidSignature, "PTR1 exact binding failed.");
        var receipt = RequireForwardingReceipt(request,
            encoded.Slice(8 + length, MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength),
            crypto, policy.NowUnixSeconds);

        // Existing local history is never rewritten by historical sender evidence.
        var existing = replayJournal.EvaluateExisting(claim);
        if (existing is not null)
            return FinishReplayVerification(request, envelope, claim, existing, false, crypto);
        var originalAdmission = claim with
        {
            ReservedAtUnixSeconds = receipt.AcceptedAtUnixSeconds
        };
        var evaluation = replayJournal.EvaluateAndReserve(originalAdmission);
        return FinishReplayVerification(request, envelope, originalAdmission, evaluation, true, crypto);
    }

    private static MailboxReplicaReceiptV2 RequireForwardingReceipt(
        MailboxPeerWireRequestV2 request, ReadOnlySpan<byte> encoded,
        IMailboxPeerReplicationCrypto crypto, ulong now,
        MailboxPeerReplicationOperation expectedOperation = MailboxPeerReplicationOperation.Tombstone)
    {
        if (request.Operation != expectedOperation)
            throw Error(MailboxPeerReplicationError.InvalidReceipt, "Peer forwarding operation differs.");
        var receipt = DecodeAndVerifySelectedReplica(encoded, request,
            request.Operation == MailboxPeerReplicationOperation.Store ? DecodeCanonicalEnvelope(request.Payload.Span) : null, crypto);
        var rejection = !FixedEquals(receipt.ReplicaId.Span, request.SenderRouterId.Span) ? "OriginRole" :
            receipt.AcceptedAtUnixSeconds - request.CreatedAtUnixSeconds >
                MailboxPeerWireV2Limits.MaximumPastAgeSeconds ? "OriginAdmission" :
            receipt.DurableAtUnixSeconds < receipt.AcceptedAtUnixSeconds ? "DurabilityOrder" :
            receipt.DurableAtUnixSeconds >= request.ExpiresAtUnixSeconds ? "ObjectExpiry" :
            receipt.DurableAtUnixSeconds > now ? "DurableFuture" : null;
        if (rejection is not null)
        {
            var error = Error(MailboxPeerReplicationError.InvalidReceipt, "PTR1 origin evidence is invalid.");
            error.Data["Deep.MailboxPeer.Forwarding.Check"] = rejection;
            if (rejection == "DurableFuture")
                error.Data["Deep.MailboxPeer.Forwarding.LeadSeconds"] = receipt.DurableAtUnixSeconds - now;
            throw error;
        }
        return receipt;
    }

    private static int ForwardedRequestLength(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < MailboxPeerWireV2Limits.MinimumTombstoneRequestLength + TombstoneForwardingOverhead ||
            encoded.Length > MailboxPeerWireV2Limits.MaximumTombstoneRequestLength + TombstoneForwardingOverhead ||
            !encoded[..4].SequenceEqual(ProtocolMagicBytes.PTR1))
            throw Error(MailboxPeerReplicationError.InvalidPayload, "PTR1 framing is invalid.");
        var length = BinaryPrimitives.ReadUInt32BigEndian(encoded[4..]);
        if (length < MailboxPeerWireV2Limits.MinimumTombstoneRequestLength ||
            length > MailboxPeerWireV2Limits.MaximumTombstoneRequestLength ||
            length + TombstoneForwardingOverhead != encoded.Length)
            throw Error(MailboxPeerReplicationError.InvalidPayload, "PTR1 length is invalid.");
        return checked((int)length);
    }

    private static byte[] ForwardingDigest(ReadOnlySpan<byte> unsigned)
    {
        ReadOnlySpan<byte> domain = "deep.mailbox.peer.tombstone-forwarding.v1"u8;
        var input = new byte[checked(domain.Length + 1 + unsigned.Length)];
        domain.CopyTo(input);
        unsigned.CopyTo(input.AsSpan(domain.Length + 1));
        return SHA256.HashData(input);
    }
}
