namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxClientLimits
{
    public const int BlindedIdentifierLength = 32;
    public const int OperationIdLength = 16;
    public const int DigestLength = 32;
    public const int MinimumCiphertextLength = 32;
    public const int MaximumCiphertextLength = 80 * 1024;
    public const int MaximumPageBytes = 1024 * 1024;
    public const int MaximumPageItems = 100;
    public const int MaximumContinuationTokenLength = 256;
    public const ulong MinimumTtlSeconds = 60;
    public const ulong MaximumTtlSeconds = 7 * 24 * 60 * 60;
    public const int EncryptedEnvelopeHeaderLength = 152;
}

public static class MailboxDomainSeparation
{
    public const string DepositCapability = "deep.mailbox.deposit-capability.v1";
    public const string RetrieveCapability = "deep.mailbox.retrieve-capability.v1";
    public const string BlindedMailboxId = "deep.mailbox.blinded-mailbox-id.v1";
    public const string PlacementId = "deep.mailbox.placement-id.v1";
    public const string EnvelopeDigest = "deep.mailbox.envelope-digest.v1";
    public const string ReplicaReceipt = "deep.mailbox.replica-receipt.v2";
    public const string CoordinatorReceipt = "deep.mailbox.coordinator-receipt.v2";
}

public abstract class MailboxBlindedIdentifier
{
    protected MailboxBlindedIdentifier(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != MailboxClientLimits.BlindedIdentifierLength ||
            bytes.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                $"Blinded mailbox identifiers must be exactly " +
                $"{MailboxClientLimits.BlindedIdentifierLength} nonzero bytes.",
                nameof(bytes));
        }

        Bytes = bytes.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes { get; }
}

public sealed class BlindedMailboxId(ReadOnlySpan<byte> bytes) : MailboxBlindedIdentifier(bytes);

public sealed class BlindedPlacementId(ReadOnlySpan<byte> bytes) : MailboxBlindedIdentifier(bytes);

public sealed record MailboxEpochWindow
{
    public required ulong CurrentEpoch { get; init; }
    public required ulong NextEpoch { get; init; }
    public required ulong CurrentNotBeforeUnixSeconds { get; init; }
    public required ulong NextNotBeforeUnixSeconds { get; init; }
    public required ulong CurrentExpiresAtUnixSeconds { get; init; }
    public required ulong NextExpiresAtUnixSeconds { get; init; }

    public bool Accepts(ulong epoch, ulong nowUnixSeconds)
    {
        Validate();
        return epoch == CurrentEpoch
            ? nowUnixSeconds >= CurrentNotBeforeUnixSeconds &&
              nowUnixSeconds <= CurrentExpiresAtUnixSeconds
            : epoch == NextEpoch &&
              nowUnixSeconds >= NextNotBeforeUnixSeconds &&
              nowUnixSeconds <= NextExpiresAtUnixSeconds;
    }

    public void Validate()
    {
        if (CurrentEpoch == 0 ||
            CurrentEpoch == ulong.MaxValue ||
            NextEpoch != CurrentEpoch + 1 ||
            CurrentNotBeforeUnixSeconds >= NextNotBeforeUnixSeconds ||
            NextNotBeforeUnixSeconds > CurrentExpiresAtUnixSeconds ||
            CurrentExpiresAtUnixSeconds >= NextExpiresAtUnixSeconds)
        {
            throw new MailboxClientException(
                MailboxClientError.InvalidEpochWindow,
                "Only the bounded overlapping E/E+1 epoch window is canonical.");
        }
    }
}

public sealed record MailboxEncryptedEnvelope
{
    public required ulong Epoch { get; init; }
    public required BlindedMailboxId MailboxId { get; init; }
    public required BlindedPlacementId PlacementId { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ReadOnlyMemory<byte> DeduplicationDigest { get; init; }
    public required ulong CreatedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> Ciphertext { get; init; }
}

public sealed record MailboxStoreRequest
{
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required MailboxMixedVersionMarker MixedVersion { get; init; }
    public required MailboxCapabilityPresentation DepositCapability { get; init; }
    public required MailboxEncryptedEnvelope Envelope { get; init; }
}

public sealed record MailboxRetrieveRequest
{
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required MailboxMixedVersionMarker MixedVersion { get; init; }
    public required MailboxCapabilityPresentation RetrieveCapability { get; init; }
    public required BlindedMailboxId MailboxId { get; init; }
    public required BlindedPlacementId PlacementId { get; init; }
    public required ulong AfterCursor { get; init; }
    public required ushort MaximumItems { get; init; }
    public required ReadOnlyMemory<byte> ContinuationToken { get; init; }
}

public sealed record MailboxRetrievePage
{
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ulong NextCursor { get; init; }
    public required bool HasMore { get; init; }
    public required ReadOnlyMemory<byte> ContinuationToken { get; init; }
    public required IReadOnlyList<MailboxEncryptedEnvelope> Envelopes { get; init; }
}

public sealed record MailboxAcknowledgement
{
    public required ulong Cursor { get; init; }
    public required ReadOnlyMemory<byte> EnvelopeDigest { get; init; }
}

public sealed record MailboxAckRequest
{
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required MailboxMixedVersionMarker MixedVersion { get; init; }
    public required MailboxCapabilityPresentation RetrieveCapability { get; init; }
    public required BlindedMailboxId MailboxId { get; init; }
    public required BlindedPlacementId PlacementId { get; init; }
    public required bool IsFinalPage { get; init; }
    public required ReadOnlyMemory<byte> ContinuationToken { get; init; }
    public required IReadOnlyList<MailboxAcknowledgement> Acknowledgements { get; init; }
}

public sealed record MailboxClientDecodePolicy
{
    public required ulong NowUnixSeconds { get; init; }
    public required MailboxEpochWindow EpochWindow { get; init; }
    public required MailboxCapabilityDecodePolicy CapabilityPolicy { get; init; }
    public bool AllowLegacyMirrorOverlap { get; init; }
}

public enum MailboxClientDeliveryStatus : byte
{
    Accepted = 1,
    Durable = 2,
    Delivered = 3
}

public sealed record MailboxDeliveryTransitionEvidence
{
    public bool DurableQuorumVerified { get; init; }
    public bool PayloadAuthenticatedAndDecrypted { get; init; }
    public bool DurableAckTombstoneVerified { get; init; }
}

public enum MailboxClientError
{
    None = 0,
    EncodedLengthOutOfRange,
    InvalidMagic,
    UnsupportedVersion,
    ReservedFieldNotZero,
    MalformedLength,
    InvalidIdentifier,
    InvalidOperationId,
    InvalidDigest,
    InvalidEpoch,
    InvalidEpochWindow,
    InvalidTtl,
    InvalidCiphertext,
    InvalidCapabilityDomain,
    CapabilityEnvelopeMismatch,
    PaginationOutOfRange,
    DowngradeRejected,
    InvalidDeliveryTransition
}

public sealed class MailboxClientException(
    MailboxClientError error,
    string message)
    : Exception(message)
{
    public MailboxClientError Error { get; } = error;
}
