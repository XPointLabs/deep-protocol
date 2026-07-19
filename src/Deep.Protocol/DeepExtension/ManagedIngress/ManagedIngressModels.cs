namespace Deep.Protocol.DeepExtension.ManagedIngress;

public static class ManagedIngressLimits
{
    public const int MinimumOpaqueFrameBytes = 64;
    public const int MaximumOpaqueFrameBytes = 1_572_864;
    public const int MaximumDecodedHeaderListBytes = 8_192;
    public const int MaximumHeaderFields = 32;
    public const int MaximumCapabilityDocumentBytes = 4_096;
    public const int ErrorFrameBytes = 64;
    public const int MinimumRetryAfterSeconds = 1;
    public const int MaximumRetryAfterSeconds = 60;
}

public enum ManagedIngressTransportResult
{
    TransitRequestValidated = 1,
    TransitCompleted = 2,
    CancelledBeforeForward = 3,
    OutcomeUnknown = 4,
    InvalidResponse = 5,
    RejectedBeforeForward = 6
}

public enum ManagedIngressOutcomeCertainty : byte
{
    BeforeForward = 1,
    UnknownAfterForward = 2
}

public enum ManagedIngressErrorClass : byte
{
    MalformedFrame = 1,
    UnsupportedResponseType = 2,
    FrameTooLarge = 3,
    UnsupportedMediaType = 4,
    WrongOrigin = 5,
    EarlyDataRejected = 6,
    Saturated = 7,
    InvalidUpstreamResponse = 8,
    Unavailable = 9,
    UpstreamOutcomeUnknown = 10
}

public enum ManagedIngressContractError
{
    None = 0,
    FrameLengthOutOfRange,
    WrongMethod,
    WrongPath,
    QueryForbidden,
    Http2Required,
    UnsupportedMediaType,
    UnsupportedResponseType,
    ContentCodingForbidden,
    ForbiddenHeader,
    HeaderCountExceeded,
    HeaderListTooLarge,
    MalformedHeader,
    EarlyDataRejected,
    MalformedErrorFrame,
    UnsupportedErrorVersion,
    InvalidErrorClass,
    InvalidOutcomeCertainty,
    InvalidRetryPolicy,
    ReservedFieldNotZero,
    CapabilityDocumentOutOfRange,
    MalformedCapabilityDocument,
    UnknownCriticalFeature,
    CapabilityPolicyMismatch
}

public sealed class ManagedIngressContractException : Exception
{
    public ManagedIngressContractException(
        ManagedIngressContractError error,
        string message,
        ManagedIngressOutcomeCertainty certainty = ManagedIngressOutcomeCertainty.BeforeForward)
        : base(message)
    {
        Error = error;
        Certainty = certainty;
    }

    public ManagedIngressContractError Error { get; }

    public ManagedIngressOutcomeCertainty Certainty { get; }
}

public sealed class ManagedIngressOpaqueFrame
{
    internal ManagedIngressOpaqueFrame(ReadOnlySpan<byte> bytes)
    {
        Bytes = bytes.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes { get; }
}

public sealed record ManagedIngressHeader(string Name, string Value);

public sealed record ManagedIngressRequestMetadata
{
    public ManagedIngressRequestMetadata(
        string method,
        string path,
        string query,
        Version httpVersion,
        string contentType,
        string accept,
        string? contentEncoding,
        long bodyLength,
        bool isEarlyData,
        IReadOnlyList<ManagedIngressHeader> headers,
        string scheme,
        string authority)
    {
        Method = method;
        Path = path;
        Query = query;
        HttpVersion = httpVersion;
        ContentType = contentType;
        Accept = accept;
        ContentEncoding = contentEncoding;
        BodyLength = bodyLength;
        IsEarlyData = isEarlyData;
        Headers = headers;
        Scheme = scheme;
        Authority = authority;
    }

    public string Method { get; init; }

    public string Path { get; init; }

    public string Query { get; init; }

    public Version HttpVersion { get; init; }

    public string ContentType { get; init; }

    public string Accept { get; init; }

    public string? ContentEncoding { get; init; }

    public long BodyLength { get; init; }

    public bool IsEarlyData { get; init; }

    public IReadOnlyList<ManagedIngressHeader> Headers { get; init; }

    public string Scheme { get; init; }

    public string Authority { get; init; }
}

public sealed record ManagedIngressResponseMetadata
{
    public ManagedIngressResponseMetadata(
        int statusCode,
        Version httpVersion,
        string? contentType,
        string? contentEncoding,
        long bodyLength,
        IReadOnlyList<ManagedIngressHeader> headers)
    {
        StatusCode = statusCode;
        HttpVersion = httpVersion;
        ContentType = contentType;
        ContentEncoding = contentEncoding;
        BodyLength = bodyLength;
        Headers = headers;
    }

    public int StatusCode { get; init; }

    public Version HttpVersion { get; init; }

    public string? ContentType { get; init; }

    public string? ContentEncoding { get; init; }

    public long BodyLength { get; init; }

    public IReadOnlyList<ManagedIngressHeader> Headers { get; init; }
}

public sealed record ManagedIngressErrorFrame
{
    public ManagedIngressErrorFrame(
        ManagedIngressErrorClass errorClass,
        ManagedIngressOutcomeCertainty certainty,
        bool retryable,
        int retryAfterSeconds)
    {
        ErrorClass = errorClass;
        Certainty = certainty;
        Retryable = retryable;
        RetryAfterSeconds = retryAfterSeconds;
    }

    public ManagedIngressErrorClass ErrorClass { get; init; }

    public ManagedIngressOutcomeCertainty Certainty { get; init; }

    public bool Retryable { get; init; }

    public int RetryAfterSeconds { get; init; }
}

public sealed record ManagedIngressErrorClassification(
    ManagedIngressTransportResult Result,
    ManagedIngressErrorFrame? Error);

public sealed class ManagedIngressStreamingAdmission
{
    private readonly long _declaredLength;
    private bool _completed;
    private bool _forwardStarted;
    private bool _cancelled;

    public ManagedIngressStreamingAdmission(long declaredLength)
    {
        if (declaredLength is
            < ManagedIngressLimits.MinimumOpaqueFrameBytes or
            > ManagedIngressLimits.MaximumOpaqueFrameBytes)
        {
            throw new ManagedIngressContractException(
                ManagedIngressContractError.FrameLengthOutOfRange,
                "The declared opaque frame length is outside strict bounds.");
        }

        _declaredLength = declaredLength;
    }

    public long ReceivedBytes { get; private set; }

    public void Append(ReadOnlySpan<byte> chunk)
    {
        EnsureReceiving();
        if (chunk.Length == 0)
        {
            return;
        }

        var next = checked(ReceivedBytes + chunk.Length);
        if (next > _declaredLength ||
            next > ManagedIngressLimits.MaximumOpaqueFrameBytes)
        {
            throw new ManagedIngressContractException(
                ManagedIngressContractError.FrameLengthOutOfRange,
                "The streamed opaque frame exceeds its declared or maximum length.");
        }

        ReceivedBytes = next;
    }

    public void Complete()
    {
        EnsureReceiving();
        if (ReceivedBytes != _declaredLength)
        {
            throw new ManagedIngressContractException(
                ManagedIngressContractError.FrameLengthOutOfRange,
                "The streamed opaque frame is truncated.");
        }

        _completed = true;
    }

    public void MarkForwardStarted()
    {
        if (!_completed || _cancelled || _forwardStarted)
        {
            throw new InvalidOperationException(
                "Forwarding may start exactly once after bounded admission completes.");
        }

        _forwardStarted = true;
    }

    public ManagedIngressTransportResult Cancel()
    {
        _cancelled = true;
        return _forwardStarted
            ? ManagedIngressTransportResult.OutcomeUnknown
            : ManagedIngressTransportResult.CancelledBeforeForward;
    }

    private void EnsureReceiving()
    {
        if (_completed || _cancelled || _forwardStarted)
        {
            throw new InvalidOperationException("The admission body is no longer writable.");
        }
    }
}

public static class ManagedIngressCapabilityFeatures
{
    public const string OpaqueFrameV1 = "opaque-frame-v1";

    public static IReadOnlySet<string> KnownCritical { get; } =
        new HashSet<string>(StringComparer.Ordinal)
        {
            OpaqueFrameV1
        };
}

public sealed record ManagedIngressCapabilityDocument
{
    public int SchemaVersion { get; init; } = 1;

    public string ContractId { get; init; } = ManagedIngressH2Contract.ContractId;

    public int MinimumVersion { get; init; } = 1;

    public int MaximumVersion { get; init; } = 1;

    public string RequestMediaType { get; init; } = ManagedIngressH2Contract.OpaqueMediaType;

    public string ResponseMediaType { get; init; } = ManagedIngressH2Contract.OpaqueMediaType;

    public string ErrorMediaType { get; init; } = ManagedIngressH2Contract.ErrorMediaType;

    public int MinimumFrameBytes { get; init; } = ManagedIngressLimits.MinimumOpaqueFrameBytes;

    public int MaximumFrameBytes { get; init; } = ManagedIngressLimits.MaximumOpaqueFrameBytes;

    public int MaximumHeaderListBytes { get; init; } =
        ManagedIngressLimits.MaximumDecodedHeaderListBytes;

    public int MaximumHeaderFields { get; init; } = ManagedIngressLimits.MaximumHeaderFields;

    public bool Ready { get; init; }

    public int RetryAfterSeconds { get; init; }

    public IReadOnlyList<string> HttpVersions { get; init; } = ["2"];

    public IReadOnlyList<string> CriticalFeatures { get; init; } =
        [ManagedIngressCapabilityFeatures.OpaqueFrameV1];

    public IReadOnlyList<string> OptionalFeatures { get; init; } = Array.Empty<string>();

    public static ManagedIngressCapabilityDocument V1Ready() => new()
    {
        Ready = true,
        RetryAfterSeconds = 0
    };
}
