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
    public const int MaximumArtifactBytes = 16_384;
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
    /// <summary>Global catalog/policy commitment. This is never a user's mailbox placement commitment.</summary>
    public required ReadOnlyMemory<byte> TopologyPlacementCommitment { get; init; }
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

/// <summary>
/// Explicit bounded-forward recovery context for a client that was offline across more than one
/// PMA1 rotation. The downloaded PMA1 is still authenticated by the caller-pinned Mr. X key and
/// must be live; only the exact previous-hash requirement is replaced by a bounded forward jump.
/// </summary>
internal sealed record ProductionMailboxAuthorityCheckpointVerificationContext
{
    public required ReadOnlyMemory<byte> PinnedMrXPublicKeySha256 { get; init; }
    public required ReadOnlyMemory<byte> ExpectedNetworkId { get; init; }
    public required ulong LastCommittedGeneration { get; init; }
    public required ulong LastCommittedRevocationGeneration { get; init; }
    public required ReadOnlyMemory<byte> LastCommittedRevocationHeadHash { get; init; }
    public required ReadOnlyMemory<byte> LastCommittedRevocationSnapshotHash { get; init; }
    public required ulong NowUnixSeconds { get; init; }
    public uint ClockSkewSeconds { get; init; }
}

/// <summary>
/// Unforgeable verified handle. The constructor and trusted snapshot are assembly-internal; public
/// access returns defensive copies so caller mutation cannot alter later trust decisions.
/// </summary>
public sealed class VerifiedProductionMailboxAuthority
{
    private readonly ProductionMailboxAuthority _authority;
    private readonly byte[] _canonicalAuthorityHash;

    internal VerifiedProductionMailboxAuthority(
        ProductionMailboxAuthority authority,
        ReadOnlySpan<byte> canonicalAuthorityHash,
        ulong nextCommittedGeneration)
    {
        _authority = ProductionMailboxAuthorityCopy.Clone(authority);
        _canonicalAuthorityHash = canonicalAuthorityHash.ToArray();
        NextCommittedGeneration = nextCommittedGeneration;
    }

    public ProductionMailboxAuthority Authority => ProductionMailboxAuthorityCopy.Clone(_authority);
    public ReadOnlyMemory<byte> CanonicalAuthorityHash => _canonicalAuthorityHash.ToArray();
    public ulong NextCommittedGeneration { get; }

    internal ProductionMailboxAuthority TrustedAuthority => _authority;
}

internal static class ProductionMailboxAuthorityCopy
{
    public static ProductionMailboxAuthority Clone(ProductionMailboxAuthority value) => new()
    {
        DevelopmentOnly = value.DevelopmentOnly,
        Environment = value.Environment,
        Transport = value.Transport,
        Ownership = value.Ownership,
        EndpointPolicy = value.EndpointPolicy,
        NetworkId = value.NetworkId.ToArray(),
        AuthorityGeneration = value.AuthorityGeneration,
        PreviousAuthorityHash = value.PreviousAuthorityHash.ToArray(),
        MailboxIssuerEd25519PublicKey = value.MailboxIssuerEd25519PublicKey.ToArray(),
        MrXApprovalEd25519PublicKey = value.MrXApprovalEd25519PublicKey.ToArray(),
        Coordinator = new ProductionMailboxAuthorityEndpoint
        {
            Uri = value.Coordinator.Uri,
            CurrentSpkiSha256 = value.Coordinator.CurrentSpkiSha256.ToArray(),
            NextSpkiSha256 = value.Coordinator.NextSpkiSha256.ToArray()
        },
        NodeIngress = new ProductionMailboxAuthorityEndpoint
        {
            Uri = value.NodeIngress.Uri,
            CurrentSpkiSha256 = value.NodeIngress.CurrentSpkiSha256.ToArray(),
            NextSpkiSha256 = value.NodeIngress.NextSpkiSha256.ToArray()
        },
        CurrentEpoch = Clone(value.CurrentEpoch),
        NextEpoch = Clone(value.NextEpoch),
        Revocation = new ProductionMailboxAuthorityRevocation
        {
            SnapshotHash = value.Revocation.SnapshotHash.ToArray(),
            HeadHash = value.Revocation.HeadHash.ToArray(),
            PreviousHeadHash = value.Revocation.PreviousHeadHash.ToArray(),
            Generation = value.Revocation.Generation,
            IssuedAtUnixSeconds = value.Revocation.IssuedAtUnixSeconds,
            ExpiresAtUnixSeconds = value.Revocation.ExpiresAtUnixSeconds
        },
        MrXApproval = new ProductionMailboxAuthorityApproval
        {
            AuthorityPayloadHash = value.MrXApproval.AuthorityPayloadHash.ToArray(),
            AllowedAndroidSigningCertificateSha256 = Clone(value.MrXApproval.AllowedAndroidSigningCertificateSha256),
            AllowedWindowsSigningCertificateSha256 = Clone(value.MrXApproval.AllowedWindowsSigningCertificateSha256),
            AndroidReleaseBuildArtifactSha256 = Clone(value.MrXApproval.AndroidReleaseBuildArtifactSha256),
            WindowsReleaseBuildArtifactSha256 = Clone(value.MrXApproval.WindowsReleaseBuildArtifactSha256),
            RolloutNotBeforeUnixSeconds = value.MrXApproval.RolloutNotBeforeUnixSeconds,
            RolloutNotAfterUnixSeconds = value.MrXApproval.RolloutNotAfterUnixSeconds
        },
        Signature = value.Signature.ToArray()
    };

    private static ProductionMailboxAuthorityEpoch Clone(ProductionMailboxAuthorityEpoch value) => new()
    {
        Epoch = value.Epoch,
        Generation = value.Generation,
        MembershipCommitment = value.MembershipCommitment.ToArray(),
        TopologyPlacementCommitment = value.TopologyPlacementCommitment.ToArray(),
        NotBeforeUnixSeconds = value.NotBeforeUnixSeconds,
        NotAfterUnixSeconds = value.NotAfterUnixSeconds
    };

    private static IReadOnlyList<ReadOnlyMemory<byte>> Clone(IReadOnlyList<ReadOnlyMemory<byte>> values) =>
        values.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
}
