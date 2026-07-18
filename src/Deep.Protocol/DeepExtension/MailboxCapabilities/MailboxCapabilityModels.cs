namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxCapabilityLimits
{
    public const int FixedPresentationHeaderLength = 64;
    public const int MinimumDomainValueLength = 32;
    public const int MaximumDomainValueLength = 512;
    public const int IdempotencyKeyLength = 16;
    public const int AdmissionSlotIdLength = 16;
    public const int FixedAdmissionHeaderLength = 36;
    public const int MinimumAdmissionAuthorizationLength = 16;
    public const int MaximumAdmissionAuthorizationLength = 256;
    public const int MaximumPresentationLength =
        FixedPresentationHeaderLength +
        MaximumDomainValueLength +
        FixedAdmissionHeaderLength +
        MaximumAdmissionAuthorizationLength;
}

public enum MailboxCapabilityDomain : byte
{
    Deposit = 1,
    Retrieve = 2,
    Placement = 3
}

public enum MailboxCapabilityLifecycle : byte
{
    Active = 1,
    Overlap = 2,
    Revoked = 3,
    Recovery = 4
}

public enum MailboxMixedVersionMarker : byte
{
    StrictV1 = 1,
    LegacyMirrorOverlap = 2
}

public enum MailboxCapabilityError
{
    None = 0,
    EncodedLengthOutOfRange,
    InvalidMagic,
    UnsupportedVersion,
    InvalidEnumValue,
    CrossDomainPresentation,
    InvalidGeneration,
    InvalidValidityWindow,
    InvalidOverlap,
    LegacyOverlapNotAllowed,
    RevokedNotAllowed,
    RecoveryNotAllowed,
    ExpiredOrNotYetValid,
    InvalidReplayOrIdempotency,
    InvalidDomainValue,
    InvalidAdmission,
    ReservedFieldNotZero,
    MalformedLength,
    ReplayRejected
}

public abstract class MailboxDomainValue
{
    protected MailboxDomainValue(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is
            < MailboxCapabilityLimits.MinimumDomainValueLength or
            > MailboxCapabilityLimits.MaximumDomainValueLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(bytes),
                $"Mailbox domain values must be {MailboxCapabilityLimits.MinimumDomainValueLength}.." +
                $"{MailboxCapabilityLimits.MaximumDomainValueLength} bytes.");
        }

        Bytes = bytes.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes { get; }
}

public sealed class RotatingDepositCapability(ReadOnlySpan<byte> bytes) : MailboxDomainValue(bytes);

public sealed class RotatingRetrieveCapability(ReadOnlySpan<byte> bytes) : MailboxDomainValue(bytes);

public sealed class OpaquePlacementKey(ReadOnlySpan<byte> bytes) : MailboxDomainValue(bytes);

public sealed record MailboxFreeAdmissionSlot
{
    public required ReadOnlyMemory<byte> SlotId { get; init; }
    public required uint ValidFromBucket { get; init; }
    public required uint ValidUntilBucket { get; init; }
    public required ushort UseLimit { get; init; }
    public required ReadOnlyMemory<byte> Authorization { get; init; }
}

public sealed record MailboxCapabilityPresentation
{
    public required MailboxDomainValue DomainValue { get; init; }
    public required MailboxCapabilityLifecycle Lifecycle { get; init; }
    public required MailboxMixedVersionMarker MixedVersion { get; init; }
    public required ulong Generation { get; init; }
    public required uint NotBeforeBucket { get; init; }
    public required uint ExpiresAtBucket { get; init; }
    public required uint OverlapUntilBucket { get; init; }
    public required ulong ReplayCounter { get; init; }
    public required ReadOnlyMemory<byte> IdempotencyKey { get; init; }
    public MailboxFreeAdmissionSlot? FreeAdmission { get; init; }
}

public sealed record MailboxCapabilityDecodePolicy
{
    public required uint CurrentBucket { get; init; }
    public required ulong MinimumGeneration { get; init; }
    public bool AllowLegacyMirrorOverlap { get; init; }
    public bool AllowRevoked { get; init; }
    public bool AllowRecovery { get; init; }
}

public sealed record MailboxCapabilityReplayScope(
    MailboxCapabilityDomain Domain,
    ulong Generation,
    ulong ReplayCounter,
    ReadOnlyMemory<byte> IdempotencyKey);

public interface IMailboxCapabilityReplayGuard
{
    bool TryAccept(MailboxCapabilityReplayScope scope);
}

public sealed class MailboxCapabilityException(
    MailboxCapabilityError error,
    string message)
    : Exception(message)
{
    public MailboxCapabilityError Error { get; } = error;
}

