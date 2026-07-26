using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxPeerReplayStateMachine
{
    private static ReadOnlySpan<byte> ScopeDomain =>
        "deep.mailbox.peer.replay-scope.v2"u8;

    public static byte[] ComputeScopeKey(
        ReadOnlySpan<byte> senderRouterId,
        ReadOnlySpan<byte> recipientRouterId,
        ReadOnlySpan<byte> replayNonce)
    {
        ValidateNonzero(senderRouterId, MailboxPeerWireV2Limits.RouterIdLength);
        ValidateNonzero(recipientRouterId, MailboxPeerWireV2Limits.RouterIdLength);
        ValidateNonzero(replayNonce, MailboxPeerWireV2Limits.ReplayNonceLength);
        var preimage = new byte[2 + ScopeDomain.Length + 96];
        BinaryPrimitives.WriteUInt16BigEndian(
            preimage,
            checked((ushort)ScopeDomain.Length));
        ScopeDomain.CopyTo(preimage.AsSpan(2));
        senderRouterId.CopyTo(preimage.AsSpan(2 + ScopeDomain.Length));
        recipientRouterId.CopyTo(preimage.AsSpan(2 + ScopeDomain.Length + 32));
        replayNonce.CopyTo(preimage.AsSpan(2 + ScopeDomain.Length + 64));
        return SHA256.HashData(preimage);
    }

    public static (
        MailboxPeerReplayEvaluation Evaluation,
        MailboxPeerReplaySnapshot NextSnapshot) EvaluateAndReserve(
        MailboxPeerReplaySnapshot? current,
        MailboxPeerReplayClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        ValidateClaim(claim);
        if (current is null)
        {
            return (
                Evaluation(MailboxPeerReplayState.NewReserved),
                new MailboxPeerReplaySnapshot
                {
                    RequestDigest = claim.RequestDigest.ToArray(),
                    Status = MailboxPeerReplayRecordStatus.Pending,
                    CanonicalResponse = ReadOnlyMemory<byte>.Empty
                });
        }

        ValidateSnapshot(current);
        if (!CryptographicOperations.FixedTimeEquals(
                current.RequestDigest.Span,
                claim.RequestDigest.Span))
            return (Evaluation(MailboxPeerReplayState.Conflict), current);

        return current.Status switch
        {
            MailboxPeerReplayRecordStatus.Pending =>
                (Evaluation(MailboxPeerReplayState.PendingSame), current),
            MailboxPeerReplayRecordStatus.Completed =>
                (new MailboxPeerReplayEvaluation
                {
                    State = MailboxPeerReplayState.CompletedSame,
                    CachedResponse = current.CanonicalResponse.ToArray()
                }, current),
            _ => throw Error("Persisted peer replay snapshot is inconsistent.")
        };
    }

    public static MailboxPeerReplaySnapshot Complete(
        MailboxPeerReplaySnapshot current,
        MailboxPeerReplayClaim claim,
        ReadOnlySpan<byte> canonicalMrr2Response)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(claim);
        ValidateClaim(claim);
        ValidateSnapshot(current);
        if (current.Status != MailboxPeerReplayRecordStatus.Pending ||
            !CryptographicOperations.FixedTimeEquals(
                current.RequestDigest.Span,
                claim.RequestDigest.Span) ||
            canonicalMrr2Response.Length !=
                MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength)
            throw Error("Only the exact pending peer request can complete with one bounded MRR2.");
        _ = MailboxReceiptV2Codec.DecodeReplica(canonicalMrr2Response);
        return current with
        {
            Status = MailboxPeerReplayRecordStatus.Completed,
            CanonicalResponse = canonicalMrr2Response.ToArray()
        };
    }

    private static MailboxPeerReplayEvaluation Evaluation(MailboxPeerReplayState state) =>
        new()
        {
            State = state,
            CachedResponse = ReadOnlyMemory<byte>.Empty
        };

    private static void ValidateClaim(MailboxPeerReplayClaim claim)
    {
        ValidateNonzero(claim.ScopeKey.Span, 32);
        ValidateNonzero(claim.RequestDigest.Span, 32);
        ValidateNonzero(claim.SenderRouterId.Span, 32);
        ValidateNonzero(claim.RecipientRouterId.Span, 32);
        ValidateNonzero(claim.ReplayNonce.Span, 32);
        ValidateNonzero(claim.OperationId.Span, 16);
        if (claim.Epoch == 0 ||
            claim.Operation is not (
                MailboxPeerReplicationOperation.Store or
                MailboxPeerReplicationOperation.Tombstone) ||
            !CryptographicOperations.FixedTimeEquals(
                claim.ScopeKey.Span,
                ComputeScopeKey(
                    claim.SenderRouterId.Span,
                    claim.RecipientRouterId.Span,
                    claim.ReplayNonce.Span)))
            throw Error("Peer replay claim is malformed.");
    }

    private static void ValidateSnapshot(MailboxPeerReplaySnapshot snapshot)
    {
        ValidateNonzero(snapshot.RequestDigest.Span, 32);
        if (snapshot.Status is not (
                MailboxPeerReplayRecordStatus.Pending or
                MailboxPeerReplayRecordStatus.Completed) ||
            snapshot.Status == MailboxPeerReplayRecordStatus.Pending &&
            !snapshot.CanonicalResponse.IsEmpty ||
            snapshot.Status == MailboxPeerReplayRecordStatus.Completed &&
            snapshot.CanonicalResponse.Length !=
                MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength)
            throw Error("Persisted peer replay snapshot is malformed.");
    }

    private static void ValidateNonzero(ReadOnlySpan<byte> value, int length)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw Error("Peer replay fixed field is malformed.");
    }

    private static MailboxPeerReplicationException Error(string message) =>
        new(MailboxPeerReplicationError.ReplayConflict, message);
}
