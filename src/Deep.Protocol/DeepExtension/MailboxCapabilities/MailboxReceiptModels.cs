namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxReceiptLimits
{
    public const int IdentifierLength = 16;
    public const int DigestLength = 32;
    public const int MinimumSignatureLength = 16;
    public const int MaximumSignatureLength = 512;
    public const int ReplicaSigningLength = 96;
    public const int ReplicaFixedHeaderLength = 100;
    public const int QuorumSigningLength = 100;
    public const int QuorumFixedHeaderLength = 104;
    public const int ErrorFixedHeaderLength = 24;
    public const int MaximumReplicaReceiptLength =
        ReplicaFixedHeaderLength + MaximumSignatureLength;
    public const int MaximumQuorumReceiptLength =
        QuorumFixedHeaderLength +
        MaximumReplicaReceiptLength * 2 +
        MaximumSignatureLength;
}

public enum MailboxReceiptStatus : byte
{
    Accepted = 1,
    Durable = 2
}

public enum MailboxReceiptStage : byte
{
    Accepted = 1,
    Durable = 2
}

public enum MailboxReceiptErrorClass : byte
{
    Capacity = 1,
    QuorumUnavailable = 2,
    Revoked = 3,
    Expired = 4,
    Replay = 5,
    InvalidCapability = 6
}

public enum MailboxReceiptError
{
    None = 0,
    EncodedLengthOutOfRange,
    InvalidMagic,
    UnsupportedVersion,
    InvalidEnumValue,
    ReservedFieldNotZero,
    MalformedLength,
    InvalidIdentifier,
    InvalidGeneration,
    InvalidCursor,
    InvalidTimestamp,
    InvalidDigest,
    InvalidSignature,
    InvalidReplicaSignature,
    InvalidCoordinatorSignature,
    DuplicateReplica,
    NotDurable,
    ReplicaDisagreement,
    UnexpectedStatement,
    InvalidErrorReceipt,
    NotEquivocation
}

public sealed record MailboxReplicaReceipt
{
    public required MailboxReceiptStatus Status { get; init; }
    public required ReadOnlyMemory<byte> ReplicaId { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ulong Generation { get; init; }
    public required ulong Cursor { get; init; }
    public required uint AcceptedAtBucket { get; init; }
    public required uint DurableAtBucket { get; init; }
    public required bool IsTombstone { get; init; }
    public required ReadOnlyMemory<byte> PayloadDigest { get; init; }
    public required ReadOnlyMemory<byte> Signature { get; init; }
}

public sealed record MailboxDurableQuorumReceipt
{
    public required ReadOnlyMemory<byte> CoordinatorId { get; init; }
    public required ulong CoordinatorSequence { get; init; }
    public required MailboxReplicaReceipt FirstReplica { get; init; }
    public required MailboxReplicaReceipt SecondReplica { get; init; }
    public required ReadOnlyMemory<byte> Signature { get; init; }
}

public sealed record MailboxDurableQuorumExpectation
{
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ulong Generation { get; init; }
    public required ReadOnlyMemory<byte> PayloadDigest { get; init; }
    public required bool IsTombstone { get; init; }
}

public sealed class MailboxErrorReceipt : IEquatable<MailboxErrorReceipt>
{
    public required MailboxReceiptStage Stage { get; init; }
    public required MailboxReceiptErrorClass ErrorClass { get; init; }
    public required bool Retryable { get; init; }
    public required ulong Generation { get; init; }
    public required uint RetryAfterBucket { get; init; }
    public required ReadOnlyMemory<byte> EvidenceDigest { get; init; }

    public bool Equals(MailboxErrorReceipt? other) =>
        other is not null &&
        Stage == other.Stage &&
        ErrorClass == other.ErrorClass &&
        Retryable == other.Retryable &&
        Generation == other.Generation &&
        RetryAfterBucket == other.RetryAfterBucket &&
        EvidenceDigest.Span.SequenceEqual(other.EvidenceDigest.Span);

    public override bool Equals(object? obj) => Equals(obj as MailboxErrorReceipt);

    public override int GetHashCode() =>
        HashCode.Combine(Stage, ErrorClass, Retryable, Generation, RetryAfterBucket);
}

public interface IMailboxReceiptCrypto
{
    byte[] Digest(ReadOnlySpan<byte> statement);

    bool VerifyReplica(
        ReadOnlySpan<byte> replicaId,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature);

    bool VerifyCoordinator(
        ReadOnlySpan<byte> coordinatorId,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature);
}

public sealed record VerifiedMailboxDurableQuorum(
    ulong Cursor,
    bool IsTombstone,
    IReadOnlyList<MailboxReplicaReceipt> ReplicaReceipts,
    MailboxDurableQuorumReceipt CoordinatorReceipt);

public sealed record MailboxCoordinatorEquivocationEvidence(
    ReadOnlyMemory<byte> CoordinatorId,
    ulong CoordinatorSequence,
    ReadOnlyMemory<byte> FirstStatement,
    ReadOnlyMemory<byte> SecondStatement);

public sealed class MailboxReceiptException(
    MailboxReceiptError error,
    string message)
    : Exception(message)
{
    public MailboxReceiptError Error { get; } = error;
}
