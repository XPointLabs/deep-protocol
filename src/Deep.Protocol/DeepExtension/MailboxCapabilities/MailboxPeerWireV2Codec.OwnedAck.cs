using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static partial class MailboxPeerWireV2Codec
{
    /// <summary>Only the native whole-ACK owner may invoke this signer after
    /// authenticating its exact persisted item and original AcceptedAt join.</summary>
    public static byte[] CreateOwnedAckAdmissionProof(ReadOnlySpan<byte> exactRequest, ReadOnlySpan<byte> senderSeed)
    {
        var request = Decode(exactRequest);
        var crypto = new SodiumMailboxPeerReplicationCrypto();
        if (request.Operation != MailboxPeerReplicationOperation.Tombstone || senderSeed.Length != 32 ||
            !FixedEquals(crypto.GetPublicKey(senderSeed), request.SenderMembershipProof.SigningPublicKey.Span) ||
            !crypto.Verify(request.SenderMembershipProof.SigningPublicKey.Span,
                GetSigningDigest(request), request.Signature.Span))
            throw Error(MailboxPeerReplicationError.InvalidSignature, "Owned ACK admission signing custody differs.");
        var privateKey = PublicKeyAuth.GenerateKeyPair(senderSeed.ToArray()).PrivateKey;
        try { return PublicKeyAuth.SignDetached(OwnedAckAdmissionDigest(exactRequest), privateKey); }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
    }

    public static VerifiedMailboxPeerWireRequestV2 VerifyAndReserveOwnedAckIntent(
        ReadOnlySpan<byte> exactRequest, ReadOnlySpan<byte> admissionProof,
        MailboxPeerWireVerificationPolicyV2 policy, IMailboxPeerReplicationCrypto crypto,
        IMailboxReplicaMembershipProofVerifier membershipVerifier, IMailboxPeerReplayJournal replayJournal)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(membershipVerifier);
        ArgumentNullException.ThrowIfNull(replayJournal);
        var (request, envelope, claim) = VerifyRequest(exactRequest, policy, crypto,
            membershipVerifier, enforceAdmissionFreshness: false);
        if (request.Operation != MailboxPeerReplicationOperation.Tombstone || admissionProof.Length != 64 ||
            !crypto.Verify(request.SenderMembershipProof.SigningPublicKey.Span,
                OwnedAckAdmissionDigest(exactRequest), admissionProof))
            throw Error(MailboxPeerReplicationError.InvalidSignature, "Owned ACK admission proof is invalid.");
        var existing = replayJournal.EvaluateExisting(claim);
        if (existing is not null)
            return FinishReplayVerification(request, envelope, claim, existing, false, crypto);
        var original = claim with { ReservedAtUnixSeconds = request.CreatedAtUnixSeconds };
        return FinishReplayVerification(request, envelope, original,
            replayJournal.EvaluateAndReserve(original), true, crypto);
    }

    private static byte[] OwnedAckAdmissionDigest(ReadOnlySpan<byte> exact)
    {
        ReadOnlySpan<byte> domain = "deep.mailbox.peer.owned-ack-admission.v1"u8;
        var input = new byte[checked(domain.Length + 1 + exact.Length)];
        domain.CopyTo(input);
        exact.CopyTo(input.AsSpan(domain.Length + 1));
        return SHA256.HashData(input);
    }
}
