namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

/// <summary>A verified, non-mutating replay plan. It is not a reservation,
/// mutation authority or durable receipt. Only the codec can construct it.</summary>
public sealed class PreparedMailboxPeerReservationV2
{
    internal PreparedMailboxPeerReservationV2(MailboxPeerWireRequestV2 request,
        MailboxEncryptedEnvelope? envelope, MailboxPeerReplayClaim claim,
        MailboxPeerReplayEvaluation? existing, bool mayCreate)
    {
        RequestValue = request; EnvelopeValue = envelope; ClaimValue = claim;
        Existing = existing; MayCreate = mayCreate;
    }

    internal MailboxPeerWireRequestV2 RequestValue { get; }
    internal MailboxEncryptedEnvelope? EnvelopeValue { get; }
    internal MailboxPeerReplayClaim ClaimValue { get; }
    internal MailboxPeerReplayEvaluation? Existing { get; }
    internal bool MayCreate { get; }

    /// <summary>Returns a defensive canonical request copy for the native owner.</summary>
    public MailboxPeerWireRequestV2 Request => MailboxPeerWireV2Codec.Decode(
        MailboxPeerWireV2Codec.Encode(RequestValue));

    /// <summary>Returns the exact prospective replay snapshot, not persisted history.</summary>
    public MailboxPeerReplaySnapshot Snapshot => new()
    {
        ScopeKey = ClaimValue.ScopeKey.ToArray(), Epoch = ClaimValue.Epoch,
        RequestDigest = ClaimValue.RequestDigest.ToArray(),
        Status = Existing?.State == MailboxPeerReplayState.CompletedSame
            ? MailboxPeerReplayRecordStatus.Completed : MailboxPeerReplayRecordStatus.Pending,
        CanonicalResponse = Existing?.CachedResponse.ToArray() ?? [],
        CreatedAtUnixSeconds = ClaimValue.CreatedAtUnixSeconds,
        ExpiresAtUnixSeconds = ClaimValue.ExpiresAtUnixSeconds,
        ReservedAtUnixSeconds = Existing?.EffectiveReservedAtUnixSeconds ?? ClaimValue.ReservedAtUnixSeconds,
        EpochExpiresAtUnixSeconds = ClaimValue.EpochExpiresAtUnixSeconds,
        RetainUntilUnixSeconds = ClaimValue.RetainUntilUnixSeconds
    };

    /// <summary>Rejects an unaided stale first reservation before any write-ahead intent.</summary>
    public void RequireReservable()
    {
        if (Existing is null && !MayCreate)
            throw new MailboxPeerReplicationException(MailboxPeerReplicationError.ExpiredOrStale,
                "A stale PRQ2 has no independently persisted reservation.");
        if (Existing?.State == MailboxPeerReplayState.Conflict)
            throw new MailboxPeerReplicationException(MailboxPeerReplicationError.ReplayConflict,
                "Prepared PRQ2 differs from existing replay custody.");
    }
}

public static partial class MailboxPeerWireV2Codec
{
    /// <summary>Authenticates a candidate and reads replay state without reserving it.
    /// The native owner must protect Snapshot before CommitPreparedReservation.</summary>
    public static PreparedMailboxPeerReservationV2 PrepareReplayReservation(
        ReadOnlySpan<byte> encoded, MailboxPeerWireVerificationPolicyV2 policy,
        IMailboxPeerReplicationCrypto crypto, IMailboxReplicaMembershipProofVerifier membershipVerifier,
        IMailboxPeerReplayJournal replayJournal)
    {
        ArgumentNullException.ThrowIfNull(replayJournal);
        ArgumentNullException.ThrowIfNull(policy); ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(membershipVerifier);
        var (request, envelope, claim) = VerifyRequest(encoded, policy, crypto, membershipVerifier,
            enforceAdmissionFreshness: false);
        return Prepare(request, envelope, claim, replayJournal, crypto,
            claim.ReservedAtUnixSeconds - claim.CreatedAtUnixSeconds <= MailboxPeerWireV2Limits.MaximumPastAgeSeconds);
    }

    private static PreparedMailboxPeerReservationV2 Prepare(MailboxPeerWireRequestV2 request,
        MailboxEncryptedEnvelope? envelope, MailboxPeerReplayClaim claim,
        IMailboxPeerReplayJournal journal, IMailboxPeerReplicationCrypto crypto, bool mayCreate)
    {
        var existing = journal.EvaluateExisting(claim);
        if (existing is not null)
            _ = FinishReplayVerification(request, envelope, claim, existing, false, crypto);
        return new(request, envelope, claim, existing, mayCreate);
    }

    /// <summary>Prepares only an original ACK authenticated by its actual native owner.</summary>
    public static PreparedMailboxPeerReservationV2 PrepareOwnedAckReservation(
        ReadOnlySpan<byte> exactRequest, ReadOnlySpan<byte> admissionProof,
        MailboxPeerWireVerificationPolicyV2 policy, IMailboxPeerReplicationCrypto crypto,
        IMailboxReplicaMembershipProofVerifier membershipVerifier, IMailboxPeerReplayJournal replayJournal)
    {
        ArgumentNullException.ThrowIfNull(replayJournal);
        ArgumentNullException.ThrowIfNull(policy); ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(membershipVerifier);
        var (request, envelope, claim) = VerifyRequest(exactRequest, policy, crypto, membershipVerifier,
            enforceAdmissionFreshness: false);
        if (request.Operation != MailboxPeerReplicationOperation.Tombstone || admissionProof.Length != 64 ||
            !crypto.Verify(request.SenderMembershipProof.SigningPublicKey.Span,
                OwnedAckAdmissionDigest(exactRequest), admissionProof))
            throw Error(MailboxPeerReplicationError.InvalidSignature, "Owned ACK admission proof is invalid.");
        var existing = replayJournal.EvaluateExisting(claim);
        if (existing is null) claim = claim with { ReservedAtUnixSeconds = request.CreatedAtUnixSeconds };
        return Prepare(request, envelope, claim, replayJournal, crypto, true);
    }

    /// <summary>Prepares PTR1 without mutating the recipient journal.</summary>
    public static PreparedMailboxPeerReservationV2 PrepareForwardedTombstoneReservation(
        ReadOnlySpan<byte> encoded, MailboxPeerWireVerificationPolicyV2 policy,
        IMailboxPeerReplicationCrypto crypto, IMailboxReplicaMembershipProofVerifier membershipVerifier,
        IMailboxPeerReplayJournal replayJournal)
        => PrepareForwardedTombstoneCore(encoded, policy, crypto, membershipVerifier, replayJournal, false);

    // Only the current verified-host factory may supply a commitment without a
    // placement preimage. This is still only preparation, never mutation authority.
    internal static PreparedMailboxPeerReservationV2 PrepareHostVerifiedTombstone(
        ReadOnlySpan<byte> encoded, MailboxPeerWireVerificationPolicyV2 policy,
        IMailboxPeerReplicationCrypto crypto, IMailboxReplicaMembershipProofVerifier membershipVerifier,
        IMailboxPeerReplayJournal replayJournal) =>
        PrepareForwardedTombstoneCore(encoded, policy, crypto, membershipVerifier, replayJournal, true);

    private static PreparedMailboxPeerReservationV2 PrepareForwardedTombstoneCore(
        ReadOnlySpan<byte> encoded, MailboxPeerWireVerificationPolicyV2 policy,
        IMailboxPeerReplicationCrypto crypto, IMailboxReplicaMembershipProofVerifier membershipVerifier,
        IMailboxPeerReplayJournal replayJournal, bool hostVerifiedCommitment)
    {
        ArgumentNullException.ThrowIfNull(replayJournal);
        ArgumentNullException.ThrowIfNull(policy); ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(membershipVerifier);
        var length = ForwardedRequestLength(encoded);
        var (request, envelope, claim) = VerifyRequest(encoded.Slice(8, length), policy, crypto,
            membershipVerifier, enforceAdmissionFreshness: false, hostVerifiedTombstoneCommitment: hostVerifiedCommitment);
        if (!crypto.Verify(request.SenderMembershipProof.SigningPublicKey.Span,
            ForwardingDigest(encoded[..^64]), encoded[^64..]))
            throw Error(MailboxPeerReplicationError.InvalidSignature, "PTR1 exact binding failed.");
        var receipt = RequireForwardingReceipt(request,
            encoded.Slice(8 + length, MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength), crypto, policy.NowUnixSeconds);
        if (replayJournal.EvaluateExisting(claim) is null)
            claim = claim with { ReservedAtUnixSeconds = receipt.AcceptedAtUnixSeconds };
        return Prepare(request, envelope, claim, replayJournal, crypto, true);
    }

    /// <summary>Performs the actual native reservation after the owning protected
    /// write-ahead intent and current lease check. No callback is invoked.</summary>
    public static VerifiedMailboxPeerWireRequestV2 CommitPreparedReservation(
        PreparedMailboxPeerReservationV2 prepared, IMailboxPeerReplayJournal replayJournal,
        IMailboxPeerReplicationCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(prepared); ArgumentNullException.ThrowIfNull(replayJournal);
        ArgumentNullException.ThrowIfNull(crypto); prepared.RequireReservable();
        var claim = prepared.ClaimValue;
        var expected = prepared.Snapshot;
        claim = claim with { ReservedAtUnixSeconds = expected.ReservedAtUnixSeconds };
        var evaluation = prepared.Existing is null ? replayJournal.EvaluateAndReserve(claim)
            : replayJournal.EvaluateExisting(claim) ?? throw Error(MailboxPeerReplicationError.ReplayConflict,
                "Existing prepared peer custody disappeared before commit.");
        if (evaluation.EffectiveReservedAtUnixSeconds != expected.ReservedAtUnixSeconds ||
            prepared.Existing?.State == MailboxPeerReplayState.CompletedSame &&
                (evaluation.State != MailboxPeerReplayState.CompletedSame ||
                 !FixedEquals(evaluation.CachedResponse.Span, expected.CanonicalResponse.Span)))
            throw Error(MailboxPeerReplicationError.ReplayConflict, "Prepared peer custody changed before commit.");
        return FinishReplayVerification(prepared.RequestValue, prepared.EnvelopeValue, claim,
            evaluation, prepared.MayCreate || prepared.Existing is not null, crypto);
    }
}
