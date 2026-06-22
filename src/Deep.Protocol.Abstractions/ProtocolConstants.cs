namespace Deep.Protocol.Abstractions;

public static class ProtocolConstants
{
    public const int Ed25519PublicKeySize = 32;
    public const int Ed25519SeedSize = 32;
    public const int Ed25519SecretKeySize = 64;
    public const int X25519PublicKeySize = 32;
    public const int X25519SecretKeySize = 32;
    public const int SessionIdSize = 33;
    public const int SignatureSize = 64;
    public const int ProStandardCharacterLimit = 2000;
    public const int ProHigherCharacterLimit = 10000;
    public const int ProStandardPinnedConversationLimit = 5;
    public const int CommunityOrOneToOneMessagePadding = 160;

    public const string ProGenerateProofHashPersonalisation = "ProGenerateProof";
    public const string ProBuildProofHashPersonalisation = "ProProof________";
    public const string ProAddPaymentHashPersonalisation = "ProAddPayment___";
    public const string ProSetPaymentRefundRequestedHashPersonalisation = "ProSetRefundReq_";
    public const string ProGetDetailsHashPersonalisation = "ProGetProDetReq_";
}

public enum SessionIdPrefix : byte
{
    Standard = 0x05,
    Group = 0x03,
    Blind15 = 0x15,
    Blind25 = 0x25
}

public enum DestinationType
{
    SyncOrOneToOne = 0,
    Group = 1,
    CommunityInbox = 2,
    Community = 3
}

[Flags]
public enum EnvelopeFlags : uint
{
    None = 0,
    Source = 1 << 0,
    SourceDevice = 1 << 1,
    ServerTimestamp = 1 << 2,
    ProSignature = 1 << 3,
    Timestamp = 1 << 4
}

public enum ProStatus
{
    Nil = 0,
    InvalidProBackendSignature = 1,
    InvalidUserSignature = 2,
    Valid = 3,
    Expired = 4
}

public enum ProFeaturesForMessageStatus
{
    Success = 0,
    UtfDecodingError = 1,
    ExceedsCharacterLimit = 2
}

public enum ProProfileFeature
{
    ProBadge = 0,
    AnimatedAvatar = 1
}

public enum ProMessageFeature
{
    TenThousandCharacterLimit = 0
}
