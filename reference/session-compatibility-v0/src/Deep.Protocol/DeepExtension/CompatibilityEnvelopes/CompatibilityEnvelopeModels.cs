using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.DeepExtension.CompatibilityEnvelopes;

public static class CompatibilityEnvelopeDomains
{
    public const string HeaderV1 = "Deep/P03A/CompatibilityHeader/v1";
    public const string PayloadV1 = "Deep/P03A/CompatibilityPayload/v1";
}

public static class CompatibilityEnvelopeLimits
{
    public const int NonceContextLength = 32;
    public const int MinimumSenderAuthenticationLength = 1;
    public const int MaximumSenderAuthenticationLength = 512;
    public const int MaximumCryptoOverhead = 512;
    public const int HeaderPlaintextLength = 8;
    public const int MinimumLegacyDpe1Length = 4;
    public const int MaximumLegacyDpe1Length =
        OpaqueBundleLimits.MaximumEncryptedPayloadLength -
        NonceContextLength -
        MaximumCryptoOverhead;
}

public enum CompatibilityEnvelopePurpose : byte
{
    Header = 1,
    Payload = 2
}

public enum CompatibilityEnvelopeError
{
    None = 0,
    FeatureNotNegotiated,
    InvalidNonceContext,
    InvalidLegacyDpe1,
    InvalidOuterMetadata,
    InvalidCryptoResult,
    AuthenticationFailed,
    SenderAuthenticationMismatch,
    MalformedHeader,
    ReplayRejected
}

public sealed record CompatibilityEnvelopeSealRequest
{
    public required CompatibilityEnvelopePurpose Purpose { get; init; }
    public required string Domain { get; init; }
    public required ReadOnlyMemory<byte> RecipientKeyMaterial { get; init; }
    public required ReadOnlyMemory<byte> SenderAuthenticationSecret { get; init; }
    public required ReadOnlyMemory<byte> NonceContext { get; init; }
    public required ReadOnlyMemory<byte> AssociatedData { get; init; }
    public required ReadOnlyMemory<byte> Plaintext { get; init; }
}

public sealed record CompatibilityEnvelopeOpenRequest
{
    public required CompatibilityEnvelopePurpose Purpose { get; init; }
    public required string Domain { get; init; }
    public required ReadOnlyMemory<byte> RecipientKeyMaterial { get; init; }
    public required ReadOnlyMemory<byte> NonceContext { get; init; }
    public required ReadOnlyMemory<byte> AssociatedData { get; init; }
    public required ReadOnlyMemory<byte> Ciphertext { get; init; }
}

public sealed record CompatibilityEnvelopeSealedResult(ReadOnlyMemory<byte> Ciphertext);

public sealed record CompatibilityEnvelopeOpenedResult(
    ReadOnlyMemory<byte> Plaintext,
    ReadOnlyMemory<byte> SenderAuthenticationData);

/// <summary>
/// Production boundary for a future independently reviewed sender-authenticated
/// recipient-encryption construction. This package intentionally provides no implementation.
/// </summary>
public interface ICompatibilityEnvelopeCrypto
{
    CompatibilityEnvelopeSealedResult Seal(CompatibilityEnvelopeSealRequest request);

    CompatibilityEnvelopeOpenedResult Open(CompatibilityEnvelopeOpenRequest request);
}

public sealed record CompatibilityEnvelopeReplayScope(
    ReadOnlyMemory<byte> Capability,
    uint ExpiryBucket,
    ReadOnlyMemory<byte> ReplayMaterial);

public interface ICompatibilityEnvelopeReplayGuard
{
    bool TryAccept(CompatibilityEnvelopeReplayScope scope);
}

public sealed record CompatibilityEnvelopeWriteRequest
{
    public required OpaqueMailboxCapability Capability { get; init; }
    public required TransportAttemptId TransportAttemptId { get; init; }
    public required EndToEndDedupId EndToEndDedupId { get; init; }
    public required uint ExpiryBucket { get; init; }
    public required OpaqueBundlePaddingClass PaddingClass { get; init; }
    public required ReadOnlyMemory<byte> ReplayMaterial { get; init; }
    public required ReadOnlyMemory<byte> HeaderNonceContext { get; init; }
    public required ReadOnlyMemory<byte> PayloadNonceContext { get; init; }
    public required ReadOnlyMemory<byte> RecipientKeyMaterial { get; init; }
    public required ReadOnlyMemory<byte> SenderAuthenticationSecret { get; init; }
    public required ReadOnlyMemory<byte> LegacyDpe1 { get; init; }
}

public sealed record CompatibilityEnvelopeOpenResult(
    ReadOnlyMemory<byte> LegacyDpe1,
    ReadOnlyMemory<byte> SenderAuthenticationData,
    OpaqueBundle OuterBundle);

public sealed class CompatibilityEnvelopeException(
    CompatibilityEnvelopeError error,
    string message,
    Exception? innerException = null)
    : Exception(message, innerException)
{
    public CompatibilityEnvelopeError Error { get; } = error;
}
