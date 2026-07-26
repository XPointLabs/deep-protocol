namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxPeerReplicationLimits
{
    public const int ReplicaIdLength = 32;
    public const int PublicKeyLength = 32;
    public const int DigestLength = 32;
    public const int OperationIdLength = 16;
    public const int SignatureLength = 64;
    public const int MembershipProofFixedLength = 120;
    public const int MaximumInclusionProofLength = 4096;
    public const int RequestFixedLength = 256;
    public const int MaximumRequestLength =
        RequestFixedLength +
        MailboxClientLimits.MaximumEncryptedEnvelopeLength +
        (2 * (MembershipProofFixedLength + MaximumInclusionProofLength)) +
        SignatureLength;
    public const int AggregateAckHeaderLength = 40;
    public const int MaximumAggregateAckLength = MailboxClientLimits.MaximumPageBytes;
}

public enum MailboxPeerReplicationOperation : byte
{
    Store = 1,
    Tombstone = 2
}

public enum MailboxPeerResponseReplica : byte
{
    Source = 1,
    Target = 2
}

public enum MailboxPeerReplicationError
{
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    InvalidEnum,
    ReservedFieldNotZero,
    InvalidField,
    BindingMismatch,
    InvalidPayload,
    InvalidMembershipProof,
    InvalidSignature,
    InvalidReceipt
}

public sealed record MailboxReplicaMembershipProof
{
    public required ReadOnlyMemory<byte> ReplicaId { get; init; }
    public required ReadOnlyMemory<byte> SigningPublicKey { get; init; }
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> MembershipCommitment { get; init; }
    public required ReadOnlyMemory<byte> CanonicalInclusionProof { get; init; }
}

public sealed record MailboxPeerReplicationRequest
{
    public required MailboxPeerReplicationOperation Operation { get; init; }
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ReadOnlyMemory<byte> SourceReplicaId { get; init; }
    public required ReadOnlyMemory<byte> TargetReplicaId { get; init; }
    public required ReadOnlyMemory<byte> MembershipCommitment { get; init; }
    public required ReadOnlyMemory<byte> PlacementCommitment { get; init; }
    public required ReadOnlyMemory<byte> BlindedMailboxId { get; init; }
    public required ulong Cursor { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> PayloadDigest { get; init; }
    public required ReadOnlyMemory<byte> Payload { get; init; }
    public required MailboxReplicaMembershipProof SourceMembershipProof { get; init; }
    public required MailboxReplicaMembershipProof TargetMembershipProof { get; init; }
    public required ReadOnlyMemory<byte> Signature { get; init; }
}

public sealed record MailboxPeerReplicationVerificationPolicy
{
    public required MailboxPeerReplicationOperation ExpectedOperation { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> SourceReplicaId { get; init; }
    public required ReadOnlyMemory<byte> TargetReplicaId { get; init; }
    public required ReadOnlyMemory<byte> MembershipCommitment { get; init; }
    public required ReadOnlyMemory<byte> PlacementCommitment { get; init; }
    public required ulong NowUnixSeconds { get; init; }
}

public sealed record VerifiedMailboxPeerReplicationRequest
{
    public required MailboxPeerReplicationRequest Request { get; init; }
    public required MailboxEncryptedEnvelope? Envelope { get; init; }
}

public interface IMailboxReplicaMembershipProofVerifier
{
    /// <summary>
    /// Verifies the canonical inclusion proof, Storage role, signing key, epoch and exact membership
    /// commitment. Callers must use a P04/MRL1 verifier and fail closed on unknown proof versions.
    /// </summary>
    bool VerifyStorageReplica(
        MailboxReplicaMembershipProof proof,
        ulong verificationTimeUnixSeconds);
}

public interface IMailboxPeerReplicationCrypto
{
    bool Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature);

    byte[] Digest(ReadOnlySpan<byte> canonicalBytes);
}

public sealed record MailboxAggregateAckResponse
{
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required IReadOnlyList<ReadOnlyMemory<byte>> TombstoneQuorums { get; init; }
}

public sealed class MailboxPeerReplicationException(
    MailboxPeerReplicationError error,
    string message) : Exception(message)
{
    public MailboxPeerReplicationError Error { get; } = error;
}
