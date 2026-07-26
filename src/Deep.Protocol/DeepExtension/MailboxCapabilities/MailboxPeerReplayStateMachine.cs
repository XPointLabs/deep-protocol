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
        ulong epoch,
        ReadOnlySpan<byte> replayNonce)
    {
        ValidateNonzero(senderRouterId, MailboxPeerWireV2Limits.RouterIdLength);
        ValidateNonzero(recipientRouterId, MailboxPeerWireV2Limits.RouterIdLength);
        ValidateNonzero(replayNonce, MailboxPeerWireV2Limits.ReplayNonceLength);
        if (epoch == 0)
            throw Error("Peer replay epoch is malformed.");
        var preimage = new byte[2 + ScopeDomain.Length + 8 + 96];
        BinaryPrimitives.WriteUInt16BigEndian(
            preimage,
            checked((ushort)ScopeDomain.Length));
        ScopeDomain.CopyTo(preimage.AsSpan(2));
        var offset = 2 + ScopeDomain.Length;
        BinaryPrimitives.WriteUInt64BigEndian(preimage.AsSpan(offset), epoch);
        senderRouterId.CopyTo(preimage.AsSpan(offset + 8));
        recipientRouterId.CopyTo(preimage.AsSpan(offset + 40));
        replayNonce.CopyTo(preimage.AsSpan(offset + 72));
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
                    ScopeKey = claim.ScopeKey.ToArray(),
                    Epoch = claim.Epoch,
                    RequestDigest = claim.RequestDigest.ToArray(),
                    Status = MailboxPeerReplayRecordStatus.Pending,
                    CanonicalResponse = ReadOnlyMemory<byte>.Empty,
                    CreatedAtUnixSeconds = claim.CreatedAtUnixSeconds,
                    ExpiresAtUnixSeconds = claim.ExpiresAtUnixSeconds,
                    ReservedAtUnixSeconds = claim.ReservedAtUnixSeconds,
                    EpochExpiresAtUnixSeconds = claim.EpochExpiresAtUnixSeconds,
                    RetainUntilUnixSeconds = claim.RetainUntilUnixSeconds
                });
        }

        ValidateSnapshot(current);
        if (!CryptographicOperations.FixedTimeEquals(
                current.ScopeKey.Span,
                claim.ScopeKey.Span) ||
            current.Epoch != claim.Epoch ||
            current.CreatedAtUnixSeconds != claim.CreatedAtUnixSeconds ||
            current.ExpiresAtUnixSeconds != claim.ExpiresAtUnixSeconds ||
            current.EpochExpiresAtUnixSeconds != claim.EpochExpiresAtUnixSeconds ||
            current.RetainUntilUnixSeconds != claim.RetainUntilUnixSeconds ||
            claim.ReservedAtUnixSeconds < current.ReservedAtUnixSeconds)
            return (Evaluation(MailboxPeerReplayState.Conflict), current);
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
            !CryptographicOperations.FixedTimeEquals(
                current.ScopeKey.Span,
                claim.ScopeKey.Span) ||
            current.Epoch != claim.Epoch ||
            current.CreatedAtUnixSeconds != claim.CreatedAtUnixSeconds ||
            current.ExpiresAtUnixSeconds != claim.ExpiresAtUnixSeconds ||
            current.EpochExpiresAtUnixSeconds != claim.EpochExpiresAtUnixSeconds ||
            current.RetainUntilUnixSeconds != claim.RetainUntilUnixSeconds ||
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

    public static bool IsCollectable(
        MailboxPeerReplaySnapshot snapshot,
        ulong nowUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ValidateSnapshot(snapshot);
        return nowUnixSeconds >= snapshot.RetainUntilUnixSeconds;
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
                    claim.Epoch,
                    claim.ReplayNonce.Span)))
            throw Error("Peer replay claim is malformed.");
        if (claim.CreatedAtUnixSeconds == 0 ||
            claim.CreatedAtUnixSeconds > claim.ReservedAtUnixSeconds ||
            claim.ReservedAtUnixSeconds >= claim.ExpiresAtUnixSeconds ||
            claim.ExpiresAtUnixSeconds > claim.EpochExpiresAtUnixSeconds ||
            claim.EpochExpiresAtUnixSeconds - claim.CreatedAtUnixSeconds >
                MailboxPeerWireV2Limits.MaximumEpochLifetimeSeconds ||
            claim.EpochExpiresAtUnixSeconds >
                ulong.MaxValue - MailboxPeerWireV2Limits.ReplayRetentionSeconds ||
            claim.RetainUntilUnixSeconds !=
                claim.EpochExpiresAtUnixSeconds +
                MailboxPeerWireV2Limits.ReplayRetentionSeconds)
            throw Error("Peer replay claim retention fields are malformed.");
    }

    private static void ValidateSnapshot(MailboxPeerReplaySnapshot snapshot)
    {
        ValidateNonzero(snapshot.ScopeKey.Span, 32);
        ValidateNonzero(snapshot.RequestDigest.Span, 32);
        if (snapshot.Epoch == 0 ||
            snapshot.Status is not (
                MailboxPeerReplayRecordStatus.Pending or
                MailboxPeerReplayRecordStatus.Completed) ||
            snapshot.Status == MailboxPeerReplayRecordStatus.Pending &&
            !snapshot.CanonicalResponse.IsEmpty ||
            snapshot.Status == MailboxPeerReplayRecordStatus.Completed &&
            snapshot.CanonicalResponse.Length !=
                MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength ||
            snapshot.CreatedAtUnixSeconds == 0 ||
            snapshot.CreatedAtUnixSeconds > snapshot.ReservedAtUnixSeconds ||
            snapshot.ReservedAtUnixSeconds >= snapshot.ExpiresAtUnixSeconds ||
            snapshot.ExpiresAtUnixSeconds > snapshot.EpochExpiresAtUnixSeconds ||
            snapshot.EpochExpiresAtUnixSeconds - snapshot.CreatedAtUnixSeconds >
                MailboxPeerWireV2Limits.MaximumEpochLifetimeSeconds ||
            snapshot.EpochExpiresAtUnixSeconds >
                ulong.MaxValue - MailboxPeerWireV2Limits.ReplayRetentionSeconds ||
            snapshot.RetainUntilUnixSeconds !=
                snapshot.EpochExpiresAtUnixSeconds +
                MailboxPeerWireV2Limits.ReplayRetentionSeconds)
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
