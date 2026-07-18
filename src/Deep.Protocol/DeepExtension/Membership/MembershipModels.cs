namespace Deep.Protocol.DeepExtension.Membership;

public static class MembershipLimits
{
    public const int NetworkIdLength = 16;
    public const int SignerIdLength = 16;
    public const int HashLength = 32;
    public const int PublicKeyLength = 32;
    public const int MinimumSignatureLength = 16;
    public const int MaximumSignatureLength = 512;
    public const int MaximumSigners = 32;
    public const int MaximumBridgeContacts = 64;
    public const int MaximumContactLength = 512;
    public const int MaximumInclusionProofDepth = 64;
    public const int MaximumRevokedDelegationHashes = 64;
    public const uint MaximumClockSkewSeconds = 900;
}

public enum MembershipSignatureDomain : byte
{
    Update = 1,
    Membership = 2,
    Bridge = 3,
    Reward = 4,
    Billing = 5,
    OfflineDelegation = 6,
    OfflineRevocation = 7,
    Genesis = 8,
    ForkWitness = 9
}

public enum MembershipSignerRole : byte
{
    OfflineRoot = 1,
    Online = 2
}

public enum MembershipContractError
{
    InvalidField,
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    InvalidEnum,
    ReservedFieldNotZero,
    NonCanonicalOrder,
    DuplicateSigner,
    UnknownSigner,
    WrongSignerRole,
    WrongSignatureDomain,
    InvalidSignature,
    InsufficientQuorum,
    InvalidPolicy,
    NetworkMismatch,
    PolicyMismatch,
    ProtocolMismatch,
    InvalidValidityWindow,
    NotYetValid,
    Expired,
    ClockSkewOutOfRange,
    InvalidSequence,
    PreviousHashMismatch,
    RevokedDelegation,
    InvalidDelegation,
    ForkDetected,
    NotForkEvidence,
    AuthorityMismatch,
    SequenceOverflow
}

public sealed record MembershipPolicy
{
    public required uint Version { get; init; }
    public required ushort OfflineThreshold { get; init; }
    public required IReadOnlyList<ReadOnlyMemory<byte>> OfflineRootSignerIds { get; init; }
    public required ushort OnlineThreshold { get; init; }
    public required ushort OnlineSignerCount { get; init; }

    public static MembershipPolicy Beta(
        IReadOnlyList<ReadOnlyMemory<byte>> offlineRootSignerIds) =>
        new()
        {
            Version = 1,
            OfflineThreshold = 3,
            OfflineRootSignerIds = CopyIds(offlineRootSignerIds),
            OnlineThreshold = 2,
            OnlineSignerCount = 3
        };

    private static IReadOnlyList<ReadOnlyMemory<byte>> CopyIds(
        IReadOnlyList<ReadOnlyMemory<byte>> values) =>
        values.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
}

public static class MembershipContractVersion
{
    public const string Identifier = "Deep.Protocol/P04-canonical-v1";
}

public sealed record MembershipSignerDescriptor
{
    public required ReadOnlyMemory<byte> SignerId { get; init; }
    public required MembershipSignerRole Role { get; init; }
    public required ReadOnlyMemory<byte> PublicKey { get; init; }
}

public sealed record NetworkGenesis
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong GenesisSequence { get; init; }
    public required uint PolicyVersion { get; init; }
    public required ushort MinimumProtocol { get; init; }
    public required ushort MaximumProtocol { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required MembershipPolicy Policy { get; init; }
    public required IReadOnlyList<MembershipSignerDescriptor> OfflineRoots { get; init; }
}

public sealed record SignerDelegation
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong Sequence { get; init; }
    public required ReadOnlyMemory<byte> PreviousHash { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ValidFromUnixSeconds { get; init; }
    public required ulong ValidUntilUnixSeconds { get; init; }
    public required ushort MinimumProtocol { get; init; }
    public required ushort MaximumProtocol { get; init; }
    public required uint PolicyVersion { get; init; }
    public required IReadOnlyList<MembershipSignerDescriptor> OnlineSigners { get; init; }
    public required IReadOnlyList<MembershipSignature> Signatures { get; init; }
}

public sealed record SignerRevocation
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong Sequence { get; init; }
    public required ReadOnlyMemory<byte> PreviousHash { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ValidFromUnixSeconds { get; init; }
    public required ulong ValidUntilUnixSeconds { get; init; }
    public required ushort MinimumProtocol { get; init; }
    public required ushort MaximumProtocol { get; init; }
    public required uint PolicyVersion { get; init; }
    public required ReadOnlyMemory<byte> DelegationHash { get; init; }
    public required IReadOnlyList<MembershipSignature> Signatures { get; init; }
}

public sealed record BridgeEntryContact
{
    public required ReadOnlyMemory<byte> EntryId { get; init; }
    public required string Contact { get; init; }
}

public sealed record BridgeSnapshot
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong Sequence { get; init; }
    public required ReadOnlyMemory<byte> PreviousHash { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ValidFromUnixSeconds { get; init; }
    public required ulong ValidUntilUnixSeconds { get; init; }
    public required ushort MinimumProtocol { get; init; }
    public required ushort MaximumProtocol { get; init; }
    public required uint PolicyVersion { get; init; }
    public required IReadOnlyList<BridgeEntryContact> EntryContacts { get; init; }
    public required ForkWitnessRecord ForkWitness { get; init; }
}

public sealed record NodeMembershipCommitment
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong Sequence { get; init; }
    public required ReadOnlyMemory<byte> PreviousHash { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ValidFromUnixSeconds { get; init; }
    public required ulong ValidUntilUnixSeconds { get; init; }
    public required ushort MinimumProtocol { get; init; }
    public required ushort MaximumProtocol { get; init; }
    public required uint PolicyVersion { get; init; }
    public required uint MemberCount { get; init; }
    public required ReadOnlyMemory<byte> MerkleRoot { get; init; }
}

public sealed record MembershipInclusionProof
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong Sequence { get; init; }
    public required ReadOnlyMemory<byte> MemberCommitment { get; init; }
    public required uint LeafIndex { get; init; }
    public required IReadOnlyList<ReadOnlyMemory<byte>> SiblingHashes { get; init; }
}

public sealed record ForkWitnessRecord
{
    public required MembershipSignatureDomain CandidateDomain { get; init; }
    public required ulong Sequence { get; init; }
    public required ReadOnlyMemory<byte> PreviousHash { get; init; }
    public required ReadOnlyMemory<byte> CandidateHash { get; init; }
}

public sealed record MembershipSignature
{
    public required ReadOnlyMemory<byte> SignerId { get; init; }
    public required MembershipSignatureDomain Domain { get; init; }
    public required ReadOnlyMemory<byte> Signature { get; init; }
}

public sealed record SignedMembershipCommitment
{
    public required NodeMembershipCommitment Statement { get; init; }
    public required IReadOnlyList<MembershipSignature> Signatures { get; init; }
}

public sealed record SignedBridgeSnapshot
{
    public required BridgeSnapshot Statement { get; init; }
    public required IReadOnlyList<MembershipSignature> Signatures { get; init; }
}

public sealed record MembershipLastKnownGood
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required uint PolicyVersion { get; init; }
    public required ulong Sequence { get; init; }
    public required ReadOnlyMemory<byte> CanonicalHash { get; init; }
}

public sealed record MembershipVerificationContext
{
    public required NetworkGenesis Genesis { get; init; }
    public required SignerDelegation ActiveDelegation { get; init; }
    public required MembershipLastKnownGood AuthorityLastKnownGood { get; init; }
    public required IReadOnlyList<ReadOnlyMemory<byte>> RevokedDelegationHashes { get; init; }
    public required MembershipLastKnownGood LastKnownGood { get; init; }
    public required ulong VerificationTimeUnixSeconds { get; init; }
    public required uint AllowedClockSkewSeconds { get; init; }
    public required ushort ClientProtocol { get; init; }
}

public sealed record VerifiedMembershipCommitment
{
    public required NodeMembershipCommitment Statement { get; init; }
    public required ReadOnlyMemory<byte> CanonicalHash { get; init; }
    public required MembershipLastKnownGood NextLastKnownGood { get; init; }
}

public sealed record VerifiedBridgeSnapshot
{
    public required BridgeSnapshot Statement { get; init; }
    public required ReadOnlyMemory<byte> CanonicalHash { get; init; }
    public required MembershipLastKnownGood NextLastKnownGood { get; init; }
}

public sealed record MembershipForkEvidence
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required MembershipSignatureDomain Domain { get; init; }
    public required ulong Sequence { get; init; }
    public required ReadOnlyMemory<byte> PreviousHash { get; init; }
    public required ReadOnlyMemory<byte> FirstCanonicalStatement { get; init; }
    public required ReadOnlyMemory<byte> SecondCanonicalStatement { get; init; }
    public required ReadOnlyMemory<byte> FirstHash { get; init; }
    public required ReadOnlyMemory<byte> SecondHash { get; init; }
}

public sealed record VerifiedSignerDelegation
{
    public required SignerDelegation Statement { get; init; }
    public required ReadOnlyMemory<byte> CanonicalHash { get; init; }
    public required MembershipLastKnownGood NextAuthorityLastKnownGood { get; init; }
}

public sealed record VerifiedSignerRevocation
{
    public required SignerRevocation Statement { get; init; }
    public required ReadOnlyMemory<byte> CanonicalHash { get; init; }
    public required MembershipLastKnownGood NextAuthorityLastKnownGood { get; init; }
}

public interface IMembershipSignatureVerifier
{
    bool Verify(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature);
}

public sealed class MembershipContractException(
    MembershipContractError error,
    string message) : Exception(message)
{
    public MembershipContractError Error { get; } = error;
}
