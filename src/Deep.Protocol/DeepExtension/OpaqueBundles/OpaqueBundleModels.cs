namespace Deep.Protocol.DeepExtension.OpaqueBundles;

public static class OpaqueBundleLimits
{
    public const int FixedHeaderLength = 64;
    public const int MinimumCapabilityLength = 32;
    public const int MaximumCapabilityLength = 512;
    public const int MaximumEncryptedHeaderLength = 4096;
    public const int MaximumEncryptedPayloadLength = 1024 * 1024;
    public const int IdentifierLength = 16;
    public const int ReplayMaterialLength = 16;
    public const int MaximumEncodedLength = 1_064_960;
}

public enum OpaqueBundleWireVersion : byte
{
    V1 = 1
}

[Flags]
public enum OpaqueBundleFeatures : uint
{
    None = 0,
    SenderSealedHeader = 1 << 0,
    MailboxCapabilities = 1 << 1,
    TransportLocalCorrelation = 1 << 2,
    LegacyDpe1Compatibility = 1 << 3,
    V1Required = SenderSealedHeader | MailboxCapabilities | TransportLocalCorrelation
}

public enum OpaqueBundlePayloadKind : byte
{
    NativeOpaque = 1,
    LegacyDpe1 = 2
}

public enum OpaqueBundlePaddingClass : byte
{
    Bytes256 = 1,
    Bytes1024 = 2,
    Bytes4096 = 3,
    Bytes16384 = 4
}

public enum OpaqueBundleDecodeError
{
    None = 0,
    EncodedLengthOutOfRange,
    InvalidMagic,
    UnsupportedVersion,
    DowngradeRejected,
    UnknownCriticalFeature,
    MissingRequiredFeature,
    InvalidEnumValue,
    ReservedFieldNotZero,
    MalformedLength,
    NonCanonicalPadding,
    ExpiryOutsideWindow,
    LegacyPayloadNotAllowed,
    InvalidLegacyPayload,
    InvalidCapability,
    InvalidIdentifier,
    TransportAttemptEqualsDedup
}

public abstract class OpaqueMailboxCapability
{
    protected OpaqueMailboxCapability(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < OpaqueBundleLimits.MinimumCapabilityLength or > OpaqueBundleLimits.MaximumCapabilityLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(bytes),
                $"Opaque mailbox capabilities must be {OpaqueBundleLimits.MinimumCapabilityLength}..{OpaqueBundleLimits.MaximumCapabilityLength} bytes.");
        }

        Bytes = bytes.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes { get; }
}

public sealed class OpaqueDepositCapability(ReadOnlySpan<byte> bytes) : OpaqueMailboxCapability(bytes);

public sealed class OpaqueRetrieveCapability(ReadOnlySpan<byte> bytes) : OpaqueMailboxCapability(bytes);

public sealed class TransportAttemptId
{
    public TransportAttemptId(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != OpaqueBundleLimits.IdentifierLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(bytes),
                $"Transport attempt identifiers must be {OpaqueBundleLimits.IdentifierLength} bytes.");
        }

        Bytes = bytes.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes { get; }
}

public sealed class EndToEndDedupId
{
    public EndToEndDedupId(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != OpaqueBundleLimits.IdentifierLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(bytes),
                $"End-to-end dedup identifiers must be {OpaqueBundleLimits.IdentifierLength} bytes.");
        }

        Bytes = bytes.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes { get; }
}

public sealed record OpaqueBundleNegotiationOffer(
    OpaqueBundleWireVersion MinimumVersion,
    OpaqueBundleWireVersion MaximumVersion,
    OpaqueBundleFeatures SupportedCriticalFeatures);

public sealed record OpaqueBundleNegotiatedProfile(
    OpaqueBundleWireVersion WireVersion,
    OpaqueBundleFeatures SupportedCriticalFeatures,
    bool AllowLegacyDpe1);

public sealed record OpaqueBundleDecodePolicy
{
    public required OpaqueBundleWireVersion MinimumVersion { get; init; }
    public required OpaqueBundleWireVersion MaximumVersion { get; init; }
    public required OpaqueBundleFeatures SupportedCriticalFeatures { get; init; }
    public required uint MinimumExpiryBucket { get; init; }
    public required uint MaximumExpiryBucket { get; init; }
    public bool AllowLegacyDpe1 { get; init; }
}

public sealed record OpaqueBundleWriteRequest
{
    public required OpaqueMailboxCapability Capability { get; init; }
    public required TransportAttemptId TransportAttemptId { get; init; }
    public required EndToEndDedupId EndToEndDedupId { get; init; }
    public required uint ExpiryBucket { get; init; }
    public required OpaqueBundlePaddingClass PaddingClass { get; init; }
    public required ReadOnlyMemory<byte> ReplayMaterial { get; init; }
    public required ReadOnlyMemory<byte> EncryptedHeader { get; init; }
    public required ReadOnlyMemory<byte> EncryptedPayload { get; init; }
    public required OpaqueBundlePayloadKind PayloadKind { get; init; }
    public required OpaqueBundleFeatures CriticalFeatures { get; init; }
    public OpaqueBundleFeatures OptionalFeatures { get; init; }
}

public sealed record OpaqueBundle
{
    public required OpaqueBundleWireVersion WireVersion { get; init; }
    public required OpaqueMailboxCapability Capability { get; init; }
    public required TransportAttemptId TransportAttemptId { get; init; }
    public required uint ExpiryBucket { get; init; }
    public required OpaqueBundlePaddingClass PaddingClass { get; init; }
    public required ReadOnlyMemory<byte> ReplayMaterial { get; init; }
    public required ReadOnlyMemory<byte> EncryptedHeader { get; init; }
    public required ReadOnlyMemory<byte> EncryptedPayload { get; init; }
    public required OpaqueBundlePayloadKind PayloadKind { get; init; }
    public required OpaqueBundleFeatures CriticalFeatures { get; init; }
    public required OpaqueBundleFeatures OptionalFeatures { get; init; }
}

public abstract class OpaqueBundleException : Exception
{
    protected OpaqueBundleException(OpaqueBundleDecodeError error, string message)
        : base(message)
    {
        Error = error;
    }

    public OpaqueBundleDecodeError Error { get; }
}

public sealed class OpaqueBundleFormatException(OpaqueBundleDecodeError error, string message)
    : OpaqueBundleException(error, message);

public sealed class OpaqueBundlePolicyException(OpaqueBundleDecodeError error, string message)
    : OpaqueBundleException(error, message);

public sealed class OpaqueBundleNegotiationException(string message) : Exception(message);
