using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

public static class ProductionMailboxRouteAdvertisementConstants
{
    public const string CertificateSchema = "production-mailbox-route-certificate.v1";
    public const string AdvertisementSchema = "production-mailbox-route-advertisement.v1";
    public const byte Version = 1;
    public const int NetworkIdLength = 16;
    public const int HashLength = 32;
    public const int Ed25519PublicKeyLength = 32;
    public const int Ed25519SignatureLength = 64;
    public const int CanonicalCertificateLength = 304;
    public const int CanonicalAdvertisementLength = 400;
    public const int MaximumClockSkewSeconds = 300;
    public const ulong MaximumLifetimeSeconds = 86_400;
}

public enum ProductionMailboxRouteAdvertisementError
{
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    ReservedFieldNotZero,
    InvalidField,
    InvalidRoute,
    InvalidValidityWindow,
    AuthorityMismatch,
    InvalidIssuerSignature,
    InvalidOwnerSignature,
    NotYetValid,
    Expired,
    AdvertisementRollback,
    AdvertisementConflict,
    NonCanonical
}

public sealed class ProductionMailboxRouteAdvertisementException(
    ProductionMailboxRouteAdvertisementError error,
    string message) : Exception(message)
{
    public ProductionMailboxRouteAdvertisementError Error { get; } = error;
}

/// <summary>
/// Issuer-certified mailbox route. It deliberately contains no active holder key, device identity,
/// account identity, subscription, or payment data, so holder rotation does not change the route.
/// </summary>
public sealed record ProductionMailboxRouteCertificate
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong AuthorityGeneration { get; init; }
    public required ReadOnlyMemory<byte> CanonicalAuthorityHash { get; init; }
    public required ReadOnlyMemory<byte> IssuerEd25519PublicKey { get; init; }
    public required ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey { get; init; }
    public required ReadOnlyMemory<byte> BlindedMailboxId { get; init; }
    public required ReadOnlyMemory<byte> BlindedPlacementId { get; init; }
    public required ReadOnlyMemory<byte> SelectionInputCommitment { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> IssuerSignature { get; init; }
}

/// <summary>
/// Contact-scoped owner authorization to use an exact issuer-certified route. Hosts must carry the
/// canonical bytes only inside an authenticated E2E contact channel; this type is not a directory.
/// </summary>
public sealed record ProductionMailboxRouteAdvertisement
{
    public required ProductionMailboxRouteCertificate Certificate { get; init; }
    public required ulong Sequence { get; init; }
    public required ulong PublishedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> OwnerSignature { get; init; }
}

public interface IProductionMailboxRouteSignatureVerifier
{
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature);
}

/// <summary>Verify-only adapter. No issuer or owner signing/private-key API is exposed.</summary>
public sealed class SodiumProductionMailboxRouteSignatureVerifier : IProductionMailboxRouteSignatureVerifier
{
    private readonly SodiumProductionMailboxAuthoritySignatureVerifier _inner = new();

    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature) =>
        _inner.Verify(publicKey, signingBytes, signature);
}

public sealed record ProductionMailboxRouteAdvertisementVerificationContext
{
    public required ulong NowUnixSeconds { get; init; }
    public uint ClockSkewSeconds { get; init; }
    /// <summary>
    /// Domain-separated hash of network, owner and route. It selects the durable sequence/hash state
    /// and prevents a host from accidentally applying another mailbox's replay state.
    /// </summary>
    public required ReadOnlyMemory<byte> ExpectedRouteDomainHash { get; init; }
    /// <summary>Zero only before the first accepted advertisement for this mailbox owner.</summary>
    public ulong LastAcceptedSequence { get; init; }
    /// <summary>All zero only when <see cref="LastAcceptedSequence"/> is zero.</summary>
    public required ReadOnlyMemory<byte> LastAcceptedAdvertisementHash { get; init; }
}

public sealed class VerifiedProductionMailboxRouteCertificate
{
    private readonly ProductionMailboxRouteCertificate _certificate;
    private readonly byte[] _canonicalHash;

    internal VerifiedProductionMailboxRouteCertificate(
        ProductionMailboxRouteCertificate certificate,
        ReadOnlySpan<byte> canonicalHash)
    {
        _certificate = ProductionMailboxRouteAdvertisementCopy.Clone(certificate);
        _canonicalHash = canonicalHash.ToArray();
    }

    public ProductionMailboxRouteCertificate Certificate =>
        ProductionMailboxRouteAdvertisementCopy.Clone(_certificate);
    public ReadOnlyMemory<byte> CanonicalCertificateHash => _canonicalHash.ToArray();
    internal ProductionMailboxRouteCertificate TrustedCertificate => _certificate;
}

public sealed class VerifiedProductionMailboxRouteAdvertisement
{
    private readonly ProductionMailboxRouteAdvertisement _advertisement;
    private readonly byte[] _canonicalHash;
    private readonly byte[] _routeDomainHash;

    internal VerifiedProductionMailboxRouteAdvertisement(
        ProductionMailboxRouteAdvertisement advertisement,
        ReadOnlySpan<byte> canonicalHash,
        ReadOnlySpan<byte> routeDomainHash)
    {
        _advertisement = ProductionMailboxRouteAdvertisementCopy.Clone(advertisement);
        _canonicalHash = canonicalHash.ToArray();
        _routeDomainHash = routeDomainHash.ToArray();
    }

    public ProductionMailboxRouteAdvertisement Advertisement =>
        ProductionMailboxRouteAdvertisementCopy.Clone(_advertisement);
    public ReadOnlyMemory<byte> CanonicalAdvertisementHash => _canonicalHash.ToArray();
    public ReadOnlyMemory<byte> RouteDomainHash => _routeDomainHash.ToArray();
    public ulong NextAcceptedSequence => _advertisement.Sequence;
}

internal static class ProductionMailboxRouteAdvertisementCopy
{
    public static ProductionMailboxRouteCertificate Clone(ProductionMailboxRouteCertificate value) => new()
    {
        NetworkId = value.NetworkId.ToArray(),
        AuthorityGeneration = value.AuthorityGeneration,
        CanonicalAuthorityHash = value.CanonicalAuthorityHash.ToArray(),
        IssuerEd25519PublicKey = value.IssuerEd25519PublicKey.ToArray(),
        MailboxOwnerEd25519PublicKey = value.MailboxOwnerEd25519PublicKey.ToArray(),
        BlindedMailboxId = value.BlindedMailboxId.ToArray(),
        BlindedPlacementId = value.BlindedPlacementId.ToArray(),
        SelectionInputCommitment = value.SelectionInputCommitment.ToArray(),
        IssuedAtUnixSeconds = value.IssuedAtUnixSeconds,
        ExpiresAtUnixSeconds = value.ExpiresAtUnixSeconds,
        IssuerSignature = value.IssuerSignature.ToArray()
    };

    public static ProductionMailboxRouteAdvertisement Clone(ProductionMailboxRouteAdvertisement value) => new()
    {
        Certificate = Clone(value.Certificate),
        Sequence = value.Sequence,
        PublishedAtUnixSeconds = value.PublishedAtUnixSeconds,
        ExpiresAtUnixSeconds = value.ExpiresAtUnixSeconds,
        OwnerSignature = value.OwnerSignature.ToArray()
    };
}
