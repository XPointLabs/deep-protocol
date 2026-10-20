using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static partial class MailboxPeerWireV2Codec
{
    /// <summary>Fixed PSR1 overhead over the exact original Store PRQ2.</summary>
    public const int StoreForwardingOverhead = 8 + MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength + 64;

    /// <summary>Signs the exact Store and sender MRR2 only after actual native
    /// mutation/protected custody. Does not authorize recipient admission.</summary>
    public static byte[] CreateDurableStoreForwarding(VerifiedMailboxPeerWireRequestV2 original,
        ReadOnlySpan<byte> senderReceipt, ReadOnlySpan<byte> senderSeed)
    {
        ArgumentNullException.ThrowIfNull(original);
        var crypto = new SodiumMailboxPeerReplicationCrypto();
        var receipt = RequireForwardingReceipt(original.Request, senderReceipt, crypto,
            original.Request.ExpiresAtUnixSeconds - 1, MailboxPeerReplicationOperation.Store);
        if (senderSeed.Length != 32 || !FixedEquals(crypto.GetPublicKey(senderSeed),
            original.Request.SenderMembershipProof.SigningPublicKey.Span) ||
            receipt.AcceptedAtUnixSeconds != original.ReplayClaim.ReservedAtUnixSeconds)
            throw Error(MailboxPeerReplicationError.InvalidReceipt, "PSR1 sender custody differs.");
        var request = Encode(original.Request);
        var result = new byte[checked(request.Length + StoreForwardingOverhead)];
        ProtocolMagicBytes.PSR1.CopyTo(result);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(4), checked((uint)request.Length));
        request.CopyTo(result, 8); senderReceipt.CopyTo(result.AsSpan(8 + request.Length));
        var key = PublicKeyAuth.GenerateKeyPair(senderSeed.ToArray()).PrivateKey;
        try { PublicKeyAuth.SignDetached(StoreForwardingDigest(result.AsSpan(0, result.Length - 64)), key).CopyTo(result, result.Length - 64); }
        finally { CryptographicOperations.ZeroMemory(key); }
        return result;
    }

    /// <summary>Canonical PSR1 framing only; produces no admission authority.</summary>
    public static byte[] DecodeForwardedStoreRequest(ReadOnlySpan<byte> encoded)
    {
        var length = ForwardedStoreLength(encoded);
        var request = encoded.Slice(8, length);
        if (Decode(request).Operation != MailboxPeerReplicationOperation.Store)
            throw Error(MailboxPeerReplicationError.InvalidPayload, "PSR1 requires Store.");
        return request.ToArray();
    }

    /// <summary>Verifies first-replica evidence and reads existing native custody
    /// without reserving. Existing independent custody must be joined by the owner.</summary>
    public static PreparedMailboxPeerReservationV2 PrepareForwardedStoreReservation(ReadOnlySpan<byte> encoded,
        MailboxPeerWireVerificationPolicyV2 policy, IMailboxPeerReplicationCrypto crypto,
        IMailboxReplicaMembershipProofVerifier membershipVerifier, IMailboxPeerReplayJournal replayJournal)
    {
        ArgumentNullException.ThrowIfNull(replayJournal);
        var (request, envelope, claim) = VerifyStoreForwarding(encoded, policy, crypto, membershipVerifier);
        if (replayJournal.EvaluateExisting(claim) is null)
            return new(request, envelope, claim, null, true);
        // Existing reservation is checked against actual current time, not the
        // historical source admission. It may have a later recipient admission.
        return Prepare(request, envelope, claim with { ReservedAtUnixSeconds = policy.NowUnixSeconds }, replayJournal, crypto, true);
    }

    /// <summary>Returns only the source-proven, non-mutating original plan.
    /// The owner must authenticate selected-floor absence, complete other joins
    /// and prove native target absence before using it to reconcile an orphan.</summary>
    public static PreparedMailboxPeerReservationV2 PrepareForwardedStoreRecovery(ReadOnlySpan<byte> encoded,
        MailboxPeerWireVerificationPolicyV2 policy, IMailboxPeerReplicationCrypto crypto,
        IMailboxReplicaMembershipProofVerifier membershipVerifier)
    {
        var (request, envelope, claim) = VerifyStoreForwarding(encoded, policy, crypto, membershipVerifier);
        return new(request, envelope, claim, null, true);
    }

    private static (MailboxPeerWireRequestV2 Request, MailboxEncryptedEnvelope? Envelope, MailboxPeerReplayClaim Claim)
        VerifyStoreForwarding(ReadOnlySpan<byte> encoded, MailboxPeerWireVerificationPolicyV2 policy,
            IMailboxPeerReplicationCrypto crypto, IMailboxReplicaMembershipProofVerifier membershipVerifier)
    {
        ArgumentNullException.ThrowIfNull(policy); ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(membershipVerifier);
        var length = ForwardedStoreLength(encoded);
        var (request, envelope, claim) = VerifyRequest(encoded.Slice(8, length), policy, crypto,
            membershipVerifier, enforceAdmissionFreshness: false);
        if (!crypto.Verify(request.SenderMembershipProof.SigningPublicKey.Span,
            StoreForwardingDigest(encoded[..^64]), encoded[^64..]))
            throw Error(MailboxPeerReplicationError.InvalidSignature, "PSR1 exact binding failed.");
        var receipt = RequireForwardingReceipt(request,
            encoded.Slice(8 + length, MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength), crypto,
            policy.NowUnixSeconds, MailboxPeerReplicationOperation.Store);
        return (request, envelope, claim with { ReservedAtUnixSeconds = receipt.AcceptedAtUnixSeconds });
    }

    private static int ForwardedStoreLength(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < MailboxPeerWireV2Limits.MinimumStoreRequestLength + StoreForwardingOverhead ||
            encoded.Length > MailboxPeerWireV2Limits.MaximumRequestLength + StoreForwardingOverhead ||
            !encoded[..4].SequenceEqual(ProtocolMagicBytes.PSR1))
            throw Error(MailboxPeerReplicationError.InvalidPayload, "PSR1 framing is invalid.");
        var length = BinaryPrimitives.ReadUInt32BigEndian(encoded[4..]);
        if (length < MailboxPeerWireV2Limits.MinimumStoreRequestLength || length > MailboxPeerWireV2Limits.MaximumRequestLength ||
            length + StoreForwardingOverhead != encoded.Length)
            throw Error(MailboxPeerReplicationError.InvalidPayload, "PSR1 length is invalid.");
        return checked((int)length);
    }

    private static byte[] StoreForwardingDigest(ReadOnlySpan<byte> unsigned)
    {
        ReadOnlySpan<byte> domain = "deep.mailbox.peer.store-forwarding.v1"u8;
        var input = new byte[checked(domain.Length + 1 + unsigned.Length)];
        domain.CopyTo(input); unsigned.CopyTo(input.AsSpan(domain.Length + 1));
        return SHA256.HashData(input);
    }
}
