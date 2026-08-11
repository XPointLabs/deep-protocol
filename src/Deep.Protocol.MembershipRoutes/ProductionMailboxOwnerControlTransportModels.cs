using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

public static class ProductionMailboxOwnerControlConstants
{
    public const byte Version = 1;
    public const int ResponderCertificateLength = 272;
    public const int RequestLength = 344;
    public const int ResponseHeaderLength = 384;
    public const int FinalActivationHeaderLength = 48;
    public const uint MaximumMessageLifetimeSeconds = 300;
    public const ulong MaximumResponderCertificateLifetimeSeconds =
        ProductionMailboxRouteContinuityConstants.MaximumDelegationLifetimeSeconds;
    public const int MaximumFinalActivationArtifactBytes = 8 * 1024 * 1024;
    public const int MaximumFinalActivationFrameBytes =
        FinalActivationHeaderLength + MaximumFinalActivationArtifactBytes;
    public const int MaximumHistoryBatchBytes = 8_394_304;
    public const int MaximumHistoryFrameBytes =
        MaximumHistoryBatchBytes +
        ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength;
}

public enum ProductionMailboxOwnerControlOperation : byte
{
    AdvanceOrFinalize = 1
}

public enum ProductionMailboxOwnerControlResponseKind : byte
{
    History = 1,
    FinalActivation = 2,
    NoChange = 3
}

/// <summary>
/// OCR1 is an anchor-issuer certificate for a dedicated, transport-only Registry responder key.
/// It grants no PMA, PRC, route, selection, persistence or publication authority.
/// </summary>
public sealed record ProductionMailboxOwnerControlResponderCertificate
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey { get; init; }
    public required ReadOnlyMemory<byte> RouteDomainHash { get; init; }
    public required ReadOnlyMemory<byte> AnchorCanonicalAuthorityHash { get; init; }
    public required ReadOnlyMemory<byte> ResponderEd25519PublicKey { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ulong KeyGeneration { get; init; }
    public required ReadOnlyMemory<byte> PreviousCanonicalCertificateHash { get; init; }
    public required ReadOnlyMemory<byte> AnchorIssuerSignature { get; init; }
}

public sealed record ProductionMailboxOwnerControlRequest
{
    public required ProductionMailboxOwnerControlOperation Operation { get; init; }
    public required ProductionMailboxSelectionSuccessorMode Mode { get; init; }
    public required ProductionMailboxRouteAuthorizationKind ExpectedAuthorizationKind { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> RequestId { get; init; }
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey { get; init; }
    public required ReadOnlyMemory<byte> RouteDomainHash { get; init; }
    public required ReadOnlyMemory<byte> SelectionInputCommitment { get; init; }
    public required ReadOnlyMemory<byte> PredecessorRouteOriginLkgHash { get; init; }
    public required ReadOnlyMemory<byte> CurrentRouteHistoryCheckpointHash { get; init; }
    public required ulong CurrentRouteHistoryBatchSequence { get; init; }
    public required ulong PredecessorAuthorizationSequence { get; init; }
    public required ReadOnlyMemory<byte> PredecessorAuthorizationHash { get; init; }
    public required ReadOnlyMemory<byte> OwnerSignature { get; init; }
}

public sealed record ProductionMailboxOwnerControlResponseHeader
{
    public required ProductionMailboxOwnerControlResponseKind Kind { get; init; }
    public required ProductionMailboxSelectionSuccessorMode Mode { get; init; }
    public required ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> CanonicalRequestHash { get; init; }
    public required ReadOnlyMemory<byte> RequestId { get; init; }
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ReadOnlyMemory<byte> RouteDomainHash { get; init; }
    public required ReadOnlyMemory<byte> PredecessorRouteOriginLkgHash { get; init; }
    public required ReadOnlyMemory<byte> CurrentRouteHistoryCheckpointHash { get; init; }
    public required ReadOnlyMemory<byte> NextRouteHistoryCheckpointHash { get; init; }
    public required ulong CurrentRouteHistoryBatchSequence { get; init; }
    public required ulong NextRouteHistoryBatchSequence { get; init; }
    public required ReadOnlyMemory<byte> PayloadSha256 { get; init; }
    public required uint PayloadLength { get; init; }
    public required ReadOnlyMemory<byte> ResponderEd25519PublicKey { get; init; }
    public required ReadOnlyMemory<byte> ResponderSignature { get; init; }
}

/// <summary>Inert carry-only PMFA1 aggregate. Decoding never creates an activation capability.</summary>
public sealed record ProductionMailboxFinalActivationFrame
{
    public required ProductionMailboxSelectionSuccessorMode Mode { get; init; }
    public required ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; init; }
    public required ProductionMailboxNodeCacheArtifacts Artifacts { get; init; }
}

/// <summary>Inert one-batch transport frame. Its RHC1 is untrusted until locally recomputed.</summary>
public sealed record ProductionMailboxOwnerControlHistoryFrame
{
    public required ReadOnlyMemory<byte> CanonicalRouteHistoryBatch { get; init; }
    public required ReadOnlyMemory<byte> UntrustedCanonicalRouteHistoryCheckpoint { get; init; }
}

/// <summary>Non-forgeable, exact owner-authenticated durable request observation.</summary>
public sealed class VerifiedProductionMailboxOwnerControlRequest
{
    private readonly byte[] _canonical;
    private readonly byte[] _hash;
    internal VerifiedProductionMailboxOwnerControlRequest(ProductionMailboxOwnerControlRequest request,
        ReadOnlySpan<byte> canonical, ReadOnlySpan<byte> hash)
    { Request = request; _canonical = canonical.ToArray(); _hash = hash.ToArray(); }
    internal ProductionMailboxOwnerControlRequest Request { get; }
    internal ReadOnlySpan<byte> TrustedCanonicalBytes => _canonical;
    internal ReadOnlySpan<byte> TrustedCanonicalHash => _hash;
    public ReadOnlyMemory<byte> CanonicalBytes => _canonical.ToArray();
    public ReadOnlyMemory<byte> CanonicalHash => _hash.ToArray();
    public ulong ExpiresAtUnixSeconds => Request.ExpiresAtUnixSeconds;
    public ProductionMailboxSelectionSuccessorMode Mode => Request.Mode;
    public ProductionMailboxRouteAuthorizationKind ExpectedAuthorizationKind => Request.ExpectedAuthorizationKind;
}

/// <summary>
/// Defensive, crypto-only authoring result for one exact PMCR1 History response. The RHB1 and
/// RHC1 remain separate; this type attests neither persistence nor delivery.
/// </summary>
public sealed class ProductionMailboxOwnerControlHistoryResponsePlan
{
    private readonly byte[] _canonicalHeader;
    private readonly byte[] _payloadHash;
    private readonly byte[] _responseHash;
    private readonly ProductionMailboxRouteHistoryBatchCommitPlan _history;

    internal ProductionMailboxOwnerControlHistoryResponsePlan(
        ReadOnlySpan<byte> canonicalHeader,
        uint payloadLength,
        ReadOnlySpan<byte> payloadHash,
        ReadOnlySpan<byte> responseHash,
        ProductionMailboxRouteHistoryBatchCommitPlan history)
    {
        if (canonicalHeader.Length != ProductionMailboxOwnerControlConstants.ResponseHeaderLength ||
            payloadLength == 0 ||
            payloadHash.Length != 32 || payloadHash.IndexOfAnyExcept((byte)0) < 0 ||
            responseHash.Length != 32 || responseHash.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("History response plan fields are invalid.");
        _canonicalHeader = canonicalHeader.ToArray();
        PayloadLength = payloadLength;
        _payloadHash = payloadHash.ToArray();
        _responseHash = responseHash.ToArray();
        _history = history ?? throw new ArgumentNullException(nameof(history));
    }

    public ReadOnlyMemory<byte> CanonicalHeader => _canonicalHeader.ToArray();
    public uint PayloadLength { get; }
    public ReadOnlyMemory<byte> PayloadSha256 => _payloadHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalResponseHash => _responseHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalRouteHistoryBatch => _history.CanonicalBatch;
    public ReadOnlyMemory<byte> CanonicalRouteHistoryBatchHash => _history.CanonicalBatchHash;
    public ReadOnlyMemory<byte> CanonicalRouteHistoryCheckpoint =>
        _history.TrustedNextCheckpoint.ToArray();
    public ReadOnlyMemory<byte> CanonicalRouteHistoryCheckpointHash =>
        _history.TrustedNextCheckpointHash.ToArray();
    public ulong NextRouteHistoryBatchSequence => _history.NextBatchSequence;
    public ReadOnlyMemory<byte> BatchCommitPlanHash => _history.PlanHash;
}

public sealed class VerifiedProductionMailboxOwnerControlResponderCertificate
{
    private readonly byte[] _canonical;
    private readonly byte[] _hash;
    internal VerifiedProductionMailboxOwnerControlResponderCertificate(
        ProductionMailboxOwnerControlResponderCertificate certificate,
        ReadOnlySpan<byte> canonical, ReadOnlySpan<byte> hash)
    { Certificate = certificate; _canonical = canonical.ToArray(); _hash = hash.ToArray(); }
    internal ProductionMailboxOwnerControlResponderCertificate Certificate { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => _canonical.ToArray();
    public ReadOnlyMemory<byte> CanonicalHash => _hash.ToArray();
    public ReadOnlyMemory<byte> ResponderEd25519PublicKey => Certificate.ResponderEd25519PublicKey.ToArray();
}

/// <summary>Non-forgeable exact OCR-bound responder-authenticated response observation.</summary>
public sealed class VerifiedProductionMailboxOwnerControlResponse
{
    private readonly byte[] _header;
    private readonly byte[] _payload;
    private readonly byte[] _hash;
    internal VerifiedProductionMailboxOwnerControlResponse(ProductionMailboxOwnerControlResponseHeader response,
        ReadOnlySpan<byte> header, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> hash)
    { Response = response; _header = header.ToArray(); _payload = payload.ToArray(); _hash = hash.ToArray(); }
    internal ProductionMailboxOwnerControlResponseHeader Response { get; }
    public ReadOnlyMemory<byte> CanonicalHeader => _header.ToArray();
    public ReadOnlyMemory<byte> CanonicalPayload => _payload.ToArray();
    public ReadOnlyMemory<byte> CanonicalResponseHash => _hash.ToArray();
    public ProductionMailboxOwnerControlResponseKind Kind => Response.Kind;
}

/// <summary>
/// Sealed fixed-header authority. Only after OCR/request/time/Ed25519 verification may a host rent
/// or read the bounded PMCR1 payload named here.
/// </summary>
public sealed class VerifiedProductionMailboxOwnerControlResponseHeader
{
    private readonly byte[] _canonical;
    internal VerifiedProductionMailboxOwnerControlResponseHeader(
        ProductionMailboxOwnerControlResponseHeader response, ReadOnlySpan<byte> canonical)
    { Response = response; _canonical = canonical.ToArray(); }
    internal ProductionMailboxOwnerControlResponseHeader Response { get; }
    internal ReadOnlyMemory<byte> CanonicalBytes => _canonical;
    public ProductionMailboxOwnerControlResponseKind Kind => Response.Kind;
    public uint PayloadLength => Response.PayloadLength;
}

public sealed class ProductionMailboxOcr1SigningRequest
{
    private readonly byte[] _signingBytes;
    private readonly byte[] _expectedIssuerPublicKey;

    internal ProductionMailboxOcr1SigningRequest(
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> expectedIssuerPublicKey)
    {
        _signingBytes = signingBytes.ToArray();
        _expectedIssuerPublicKey = expectedIssuerPublicKey.ToArray();
    }

    public ReadOnlyMemory<byte> SigningBytes => _signingBytes.ToArray();
    public ReadOnlyMemory<byte> ExpectedIssuerEd25519PublicKey =>
        _expectedIssuerPublicKey.ToArray();
    internal ReadOnlySpan<byte> TrustedSigningBytes => _signingBytes;
    internal ReadOnlySpan<byte> TrustedExpectedIssuerPublicKey => _expectedIssuerPublicKey;
    internal void Clear()
    {
        CryptographicOperations.ZeroMemory(_signingBytes);
        CryptographicOperations.ZeroMemory(_expectedIssuerPublicKey);
    }
}

public sealed class ProductionMailboxOwnerControlRequestSigningRequest
{
    private readonly byte[] _signingBytes;
    private readonly byte[] _expectedOwnerPublicKey;

    internal ProductionMailboxOwnerControlRequestSigningRequest(
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> expectedOwnerPublicKey)
    {
        _signingBytes = signingBytes.ToArray();
        _expectedOwnerPublicKey = expectedOwnerPublicKey.ToArray();
    }

    public ReadOnlyMemory<byte> SigningBytes => _signingBytes.ToArray();
    public ReadOnlyMemory<byte> ExpectedOwnerEd25519PublicKey =>
        _expectedOwnerPublicKey.ToArray();
    internal ReadOnlySpan<byte> TrustedSigningBytes => _signingBytes;
    internal ReadOnlySpan<byte> TrustedExpectedOwnerPublicKey => _expectedOwnerPublicKey;
    internal void Clear()
    {
        CryptographicOperations.ZeroMemory(_signingBytes);
        CryptographicOperations.ZeroMemory(_expectedOwnerPublicKey);
    }
}

public sealed class ProductionMailboxOwnerControlResponseSigningRequest
{
    private readonly byte[] _signingBytes;
    private readonly byte[] _expectedResponderPublicKey;

    internal ProductionMailboxOwnerControlResponseSigningRequest(
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> expectedResponderPublicKey)
    {
        _signingBytes = signingBytes.ToArray();
        _expectedResponderPublicKey = expectedResponderPublicKey.ToArray();
    }

    public ReadOnlyMemory<byte> SigningBytes => _signingBytes.ToArray();
    public ReadOnlyMemory<byte> ExpectedResponderEd25519PublicKey =>
        _expectedResponderPublicKey.ToArray();
    internal ReadOnlySpan<byte> TrustedSigningBytes => _signingBytes;
    internal ReadOnlySpan<byte> TrustedExpectedResponderPublicKey => _expectedResponderPublicKey;
    internal void Clear()
    {
        CryptographicOperations.ZeroMemory(_signingBytes);
        CryptographicOperations.ZeroMemory(_expectedResponderPublicKey);
    }
}

public delegate ValueTask<int> ProductionMailboxOcr1Signer(
    ProductionMailboxOcr1SigningRequest request,
    Memory<byte> signatureDestination,
    CancellationToken cancellationToken);

public delegate ValueTask<int> ProductionMailboxOwnerControlRequestSigner(
    ProductionMailboxOwnerControlRequestSigningRequest request,
    Memory<byte> signatureDestination,
    CancellationToken cancellationToken);

public delegate ValueTask<int> ProductionMailboxOwnerControlResponseSigner(
    ProductionMailboxOwnerControlResponseSigningRequest request,
    Memory<byte> signatureDestination,
    CancellationToken cancellationToken);
