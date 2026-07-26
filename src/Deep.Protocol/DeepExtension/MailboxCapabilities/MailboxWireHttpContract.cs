namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public enum MailboxWireFrame
{
    Mst1 = 1,
    Mrt1 = 2,
    Mrp1 = 3,
    Mak1 = 4,
    Mrr2 = 5,
    Mqr2 = 6,
    Mar1 = 7,
    Prq2 = 8,
    Mqr3 = 9
}

public sealed record MailboxHttpEndpointContract
{
    public required string Route { get; init; }
    public required string Method { get; init; }
    public required string RequestContentType { get; init; }
    public required MailboxWireFrame RequestFrame { get; init; }
    public required int MinimumRequestBytes { get; init; }
    public required int MaximumRequestBytes { get; init; }
    public required int SuccessStatusCode { get; init; }
    public required string ResponseContentType { get; init; }
    public required MailboxWireFrame ResponseFrame { get; init; }
    public required int MinimumResponseBytes { get; init; }
    public required int MaximumResponseBytes { get; init; }
    public required int RequestTimeoutSeconds { get; init; }
    public required int MaximumConcurrentRequests { get; init; }
    public required int RequestsPerMinute { get; init; }
    public required string RateLimitPartition { get; init; }
}

public enum MailboxHttpFailure
{
    MalformedCanonicalBody = 1,
    AuthenticationFailed = 2,
    AuthorizationFailed = 3,
    ReplayOrIdempotencyConflict = 4,
    ExpiredOrStale = 5,
    PayloadTooLarge = 6,
    UnsupportedContentTypeOrEncoding = 7,
    RateOrConcurrencyExceeded = 8,
    DependencyUnavailable = 9,
    DeadlineExceeded = 10,
    MethodNotAllowed = 11,
    MissingContentLength = 12
}

/// <summary>
/// Dormant transport metadata only. This type does not register routes or authorize activation.
/// Request bodies are the exact raw frame bytes: Content-Encoding is forbidden, Content-Length
/// must be within the endpoint bounds before allocation, and error responses have an empty body.
/// </summary>
public static class MailboxWireHttpContract
{
    public const string Method = "POST";
    public const bool RequiresContentLength = true;
    public const bool AllowsContentEncoding = false;
    public const int ErrorResponseBytes = 0;
    public const int RateWindowSeconds = 60;

    public const string Mst1ContentType = "application/vnd.deep.mailbox.mst1";
    public const string Mrt1ContentType = "application/vnd.deep.mailbox.mrt1";
    public const string Mrp1ContentType = "application/vnd.deep.mailbox.mrp1";
    public const string Mak1ContentType = "application/vnd.deep.mailbox.mak1";
    public const string Mrr2ContentType = "application/vnd.deep.mailbox.mrr2";
    public const string Mqr2ContentType = "application/vnd.deep.mailbox.mqr2";
    public const string Mqr3ContentType = "application/vnd.deep.mailbox.mqr3";
    public const string Mar1ContentType = "application/vnd.deep.mailbox.mar1";
    public const string Prq2ContentType = "application/vnd.deep.mailbox.prq2";

    public const string StoreRoute = "/api/client/mailbox/v1/store";
    public const string RetrieveRoute = "/api/client/mailbox/v1/retrieve";
    public const string AcknowledgeRoute = "/api/client/mailbox/v1/acknowledge";
    public const string PeerStoreRoute = "/api/peer/mailbox/v2/store";
    public const string PeerTombstoneRoute = "/api/peer/mailbox/v2/tombstone";

    public static MailboxHttpEndpointContract Store { get; } = new()
    {
        Route = StoreRoute,
        Method = Method,
        RequestContentType = Mst1ContentType,
        RequestFrame = MailboxWireFrame.Mst1,
        MinimumRequestBytes =
            48 +
            MailboxCapabilityLimits.FixedPresentationHeaderLength +
            MailboxCapabilityLimits.MinimumDomainValueLength +
            MailboxCapabilityLimits.FixedAdmissionHeaderLength +
            MailboxCapabilityLimits.MinimumAdmissionAuthorizationLength +
            MailboxClientLimits.EncryptedEnvelopeHeaderLength +
            MailboxClientLimits.MinimumCiphertextLength,
        MaximumRequestBytes =
            48 +
            MailboxCapabilityLimits.MaximumPresentationLength +
            MailboxClientLimits.MaximumEncryptedEnvelopeLength,
        SuccessStatusCode = 200,
        ResponseContentType = Mqr3ContentType,
        ResponseFrame = MailboxWireFrame.Mqr3,
        MinimumResponseBytes = Ed25519Mqr3Length,
        MaximumResponseBytes = Ed25519Mqr3Length,
        RequestTimeoutSeconds = 15,
        MaximumConcurrentRequests = 16,
        RequestsPerMinute = 60,
        RateLimitPartition = "authenticated capability scope"
    };

    public static MailboxHttpEndpointContract Retrieve { get; } = new()
    {
        Route = RetrieveRoute,
        Method = Method,
        RequestContentType = Mrt1ContentType,
        RequestFrame = MailboxWireFrame.Mrt1,
        MinimumRequestBytes =
            120 +
            MailboxCapabilityLimits.FixedPresentationHeaderLength +
            MailboxCapabilityLimits.MinimumDomainValueLength +
            MailboxCapabilityLimits.FixedAdmissionHeaderLength +
            MailboxCapabilityLimits.MinimumAdmissionAuthorizationLength,
        MaximumRequestBytes =
            120 +
            MailboxCapabilityLimits.MaximumPresentationLength +
            MailboxClientLimits.MaximumContinuationTokenLength,
        SuccessStatusCode = 200,
        ResponseContentType = Mrp1ContentType,
        ResponseFrame = MailboxWireFrame.Mrp1,
        MinimumResponseBytes = 48,
        MaximumResponseBytes = MailboxClientLimits.MaximumPageBytes,
        RequestTimeoutSeconds = 10,
        MaximumConcurrentRequests = 16,
        RequestsPerMinute = 120,
        RateLimitPartition = "authenticated capability scope"
    };

    public static MailboxHttpEndpointContract Acknowledge { get; } = new()
    {
        Route = AcknowledgeRoute,
        Method = Method,
        RequestContentType = Mak1ContentType,
        RequestFrame = MailboxWireFrame.Mak1,
        MinimumRequestBytes =
            120 +
            MailboxCapabilityLimits.FixedPresentationHeaderLength +
            MailboxCapabilityLimits.MinimumDomainValueLength +
            MailboxCapabilityLimits.FixedAdmissionHeaderLength +
            MailboxCapabilityLimits.MinimumAdmissionAuthorizationLength +
            40,
        MaximumRequestBytes =
            120 +
            MailboxCapabilityLimits.MaximumPresentationLength +
            MailboxClientLimits.MaximumContinuationTokenLength +
            (MailboxClientLimits.MaximumPageItems * 40),
        SuccessStatusCode = 200,
        ResponseContentType = Mar1ContentType,
        ResponseFrame = MailboxWireFrame.Mar1,
        MinimumResponseBytes =
            MailboxPeerReplicationLimits.AggregateAckHeaderLength +
            2 +
            Ed25519Mqr3Length,
        MaximumResponseBytes = MaximumEd25519Mar1Length,
        RequestTimeoutSeconds = 15,
        MaximumConcurrentRequests = 16,
        RequestsPerMinute = 60,
        RateLimitPartition = "authenticated capability scope"
    };

    public static MailboxHttpEndpointContract PeerStore { get; } =
        PeerEndpoint(
            PeerStoreRoute,
            MailboxPeerWireV2Limits.MinimumStoreRequestLength,
            MailboxPeerWireV2Limits.MaximumRequestLength);

    public static MailboxHttpEndpointContract PeerTombstone { get; } =
        PeerEndpoint(
            PeerTombstoneRoute,
            MailboxPeerWireV2Limits.MinimumTombstoneRequestLength,
            MailboxPeerWireV2Limits.MaximumTombstoneRequestLength);

    public static IReadOnlyList<MailboxHttpEndpointContract> ClientEndpoints { get; } =
        Array.AsReadOnly([Store, Retrieve, Acknowledge]);

    public static IReadOnlyList<MailboxHttpEndpointContract> PeerEndpoints { get; } =
        Array.AsReadOnly([PeerStore, PeerTombstone]);

    public static int StatusCode(MailboxHttpFailure failure) =>
        failure switch
        {
            MailboxHttpFailure.MalformedCanonicalBody => 400,
            MailboxHttpFailure.AuthenticationFailed => 401,
            MailboxHttpFailure.AuthorizationFailed => 403,
            MailboxHttpFailure.ReplayOrIdempotencyConflict => 409,
            MailboxHttpFailure.ExpiredOrStale => 409,
            MailboxHttpFailure.PayloadTooLarge => 413,
            MailboxHttpFailure.UnsupportedContentTypeOrEncoding => 415,
            MailboxHttpFailure.RateOrConcurrencyExceeded => 429,
            MailboxHttpFailure.DependencyUnavailable => 503,
            MailboxHttpFailure.DeadlineExceeded => 504,
            MailboxHttpFailure.MethodNotAllowed => 405,
            MailboxHttpFailure.MissingContentLength => 411,
            _ => throw new ArgumentOutOfRangeException(
                nameof(failure),
                failure,
                "Unknown mailbox HTTP failure.")
        };

    private const int Ed25519Mqr3Length =
        MailboxReceiptV3Limits.QuorumFixedHeaderLength +
        (2 * MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength) +
        MailboxPeerReplicationLimits.SignatureLength;
    private const int MaximumEd25519Mar1Length =
        MailboxPeerReplicationLimits.AggregateAckHeaderLength +
        (MailboxClientLimits.MaximumPageItems *
         (2 + Ed25519Mqr3Length));

    private static MailboxHttpEndpointContract PeerEndpoint(
        string route,
        int minimumRequestBytes,
        int maximumRequestBytes) =>
        new()
        {
            Route = route,
            Method = Method,
            RequestContentType = Prq2ContentType,
            RequestFrame = MailboxWireFrame.Prq2,
            MinimumRequestBytes = minimumRequestBytes,
            MaximumRequestBytes = maximumRequestBytes,
            SuccessStatusCode = 200,
            ResponseContentType = Mrr2ContentType,
            ResponseFrame = MailboxWireFrame.Mrr2,
            MinimumResponseBytes =
                MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength,
            MaximumResponseBytes =
                MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength,
            RequestTimeoutSeconds = 15,
            MaximumConcurrentRequests = 32,
            RequestsPerMinute = 120,
            RateLimitPartition = "verified sender router id"
        };
}
