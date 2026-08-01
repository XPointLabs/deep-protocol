using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxAuthority;

/// <summary>
/// Public, signed release authority for the managed mailbox lane.  It is a Deep extension;
/// it neither grants mailbox access nor contains a holder, session, recovery phrase, or private key.
/// </summary>
public static class ProductionMailboxAuthorityConstants
{
    public const string Schema = "production-mailbox-authority.v1";
    public const byte Version = 1;
    public const int HashLength = 32;
    public const int Ed25519PublicKeyLength = 32;
    public const int Ed25519SignatureLength = 64;
    public const int NetworkIdLength = 16;
    public const int MaximumEndpointLength = 512;
    public const int MaximumHashesPerPlatform = 8;
    public const int MaximumClockSkewSeconds = 300;
    public const ulong MaximumRevocationSnapshotLifetimeSeconds = 86_400;
}

public enum ProductionMailboxAuthorityEnvironment : byte
{
    Production = 1
}

public enum ProductionMailboxAuthorityTransport : byte
{
    AuthenticatedMau2 = 1
}

public enum ProductionMailboxAuthorityOwnership : byte
{
    OfficialManaged = 1,
    UserManaged = 2
}

/// <summary>
/// User-managed authorities may name an HTTPS endpoint on a private network (for example, a
/// self-operated LAN deployment). HTTP, development host names, and public official endpoints
/// without HTTPS are never permitted.
/// </summary>
public enum ProductionMailboxAuthorityEndpointPolicy : byte
{
    PublicHttpsOnly = 1,
    UserManagedPrivateHttps = 2
}

public enum ProductionMailboxAuthorityError
{
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    InvalidEnum,
    ReservedFieldNotZero,
    InvalidField,
    InvalidEndpoint,
    InvalidPinSet,
    InvalidEpochOrder,
    InvalidValidityWindow,
    InvalidApprovalBinding,
    InvalidSignature,
    UntrustedMrXKey,
    AuthorityRollback,
    PreviousHashMismatch,
    NotYetValid,
    Expired,
    NonCanonical
}

public sealed class ProductionMailboxAuthorityException(
    ProductionMailboxAuthorityError error,
    string message) : Exception(message)
{
    public ProductionMailboxAuthorityError Error { get; } = error;
}

public sealed record ProductionMailboxAuthorityEndpoint
{
    /// <summary>Absolute, canonical HTTPS URI. Coordinator and node ingress must be different origins.</summary>
    public required string Uri { get; init; }
    public required ReadOnlyMemory<byte> CurrentSpkiSha256 { get; init; }
    public required ReadOnlyMemory<byte> NextSpkiSha256 { get; init; }
}

public sealed record ProductionMailboxAuthorityEpoch
{
    public required ulong Epoch { get; init; }
    public required ulong Generation { get; init; }
    public required ReadOnlyMemory<byte> MembershipCommitment { get; init; }
    public required ReadOnlyMemory<byte> PlacementCommitment { get; init; }
    public required ulong NotBeforeUnixSeconds { get; init; }
    public required ulong NotAfterUnixSeconds { get; init; }
}

public sealed record ProductionMailboxAuthorityRevocation
{
    public required ReadOnlyMemory<byte> SnapshotHash { get; init; }
    public required ReadOnlyMemory<byte> HeadHash { get; init; }
    public required ReadOnlyMemory<byte> PreviousHeadHash { get; init; }
    public required ulong Generation { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
}

public sealed record ProductionMailboxAuthorityApproval
{
    /// <summary>SHA-256 of <see cref="ProductionMailboxAuthorityCodec.GetPayloadBytes"/>.</summary>
    public required ReadOnlyMemory<byte> AuthorityPayloadHash { get; init; }
    public required IReadOnlyList<ReadOnlyMemory<byte>> AllowedAndroidSigningCertificateSha256 { get; init; }
    public required IReadOnlyList<ReadOnlyMemory<byte>> AllowedWindowsSigningCertificateSha256 { get; init; }
    public required IReadOnlyList<ReadOnlyMemory<byte>> AndroidReleaseBuildArtifactSha256 { get; init; }
    public required IReadOnlyList<ReadOnlyMemory<byte>> WindowsReleaseBuildArtifactSha256 { get; init; }
    public required ulong RolloutNotBeforeUnixSeconds { get; init; }
    public required ulong RolloutNotAfterUnixSeconds { get; init; }
}

public sealed record ProductionMailboxAuthority
{
    /// <summary>Always <see cref="ProductionMailboxAuthorityConstants.Schema"/> encoded as PMA1/v1.</summary>
    public required bool DevelopmentOnly { get; init; }
    public required ProductionMailboxAuthorityEnvironment Environment { get; init; }
    public required ProductionMailboxAuthorityTransport Transport { get; init; }
    public required ProductionMailboxAuthorityOwnership Ownership { get; init; }
    public required ProductionMailboxAuthorityEndpointPolicy EndpointPolicy { get; init; }
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong AuthorityGeneration { get; init; }
    public required ReadOnlyMemory<byte> PreviousAuthorityHash { get; init; }
    /// <summary>Public mailbox capability issuer key; never private key material.</summary>
    public required ReadOnlyMemory<byte> MailboxIssuerEd25519PublicKey { get; init; }
    /// <summary>Public Mr. X approval key which signs this document.</summary>
    public required ReadOnlyMemory<byte> MrXApprovalEd25519PublicKey { get; init; }
    public required ProductionMailboxAuthorityEndpoint Coordinator { get; init; }
    public required ProductionMailboxAuthorityEndpoint NodeIngress { get; init; }
    public required ProductionMailboxAuthorityEpoch CurrentEpoch { get; init; }
    public required ProductionMailboxAuthorityEpoch NextEpoch { get; init; }
    public required ProductionMailboxAuthorityRevocation Revocation { get; init; }
    public required ProductionMailboxAuthorityApproval MrXApproval { get; init; }
    public required ReadOnlyMemory<byte> Signature { get; init; }
}

public interface IProductionMailboxAuthoritySignatureVerifier
{
    bool Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature);
}

/// <summary>
/// Durable last-known-good state is owned by the caller. A verifier accepts exactly the successor
/// of this state; it does not silently bootstrap a trust chain from a downloaded authority.
/// </summary>
public sealed record ProductionMailboxAuthorityVerificationContext
{
    public required ReadOnlyMemory<byte> PinnedMrXPublicKeySha256 { get; init; }
    public required ReadOnlyMemory<byte> ExpectedNetworkId { get; init; }
    public required ulong LastCommittedGeneration { get; init; }
    public required ReadOnlyMemory<byte> LastCommittedAuthorityHash { get; init; }
    public required ulong LastCommittedRevocationGeneration { get; init; }
    public required ReadOnlyMemory<byte> LastCommittedRevocationHeadHash { get; init; }
    public required ReadOnlyMemory<byte> LastCommittedRevocationSnapshotHash { get; init; }
    public required ulong NowUnixSeconds { get; init; }
    public uint ClockSkewSeconds { get; init; }
}

public sealed record VerifiedProductionMailboxAuthority
{
    public required ProductionMailboxAuthority Authority { get; init; }
    public required ReadOnlyMemory<byte> CanonicalAuthorityHash { get; init; }
    public required ulong NextCommittedGeneration { get; init; }
}
