using System.Text;
using System.Net;

namespace Deep.Protocol.DeepExtension.ManagedIngress;

public static class ManagedIngressH2Contract
{
    public const string ContractId = "Deep.Protocol/P10B-managed-ingress-h2-v1";
    public const string FramePath = "/api/ingress/v1/frame";
    public const string CapabilitiesPath = "/api/ingress/v1/capabilities";
    public const string OpaqueMediaType = "application/vnd.xpoint.deep.ingress-opaque-v1";
    public const string ErrorMediaType = "application/vnd.xpoint.deep.ingress-error-v1";
    public const string CapabilitiesMediaType =
        "application/vnd.xpoint.deep.ingress-capabilities-v1+json";

    private static readonly HashSet<string> ForbiddenHeaders =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "idempotency-key",
            "traceparent",
            "tracestate",
            "baggage",
            "content-encoding",
            "x-request-id",
            "x-correlation-id"
        };

    public static ManagedIngressOpaqueFrame ValidateOpaqueFrame(ReadOnlySpan<byte> bytes)
    {
        CheckFrameLength(bytes.Length);
        return new ManagedIngressOpaqueFrame(bytes);
    }

    public static ManagedIngressTransportResult ValidateFrameRequest(
        ManagedIngressRequestMetadata request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!StringComparer.Ordinal.Equals(request.Method, "POST"))
        {
            throw Error(ManagedIngressContractError.WrongMethod, "The frame method must be POST.");
        }

        if (!StringComparer.Ordinal.Equals(request.Path, FramePath))
        {
            throw Error(ManagedIngressContractError.WrongPath, "The frame path is not canonical.");
        }

        if (!string.IsNullOrEmpty(request.Query))
        {
            throw Error(ManagedIngressContractError.QueryForbidden, "Queries are forbidden.");
        }

        if (request.HttpVersion != HttpVersion.Version20)
        {
            throw Error(ManagedIngressContractError.Http2Required, "HTTP/2 is required.");
        }

        if (!MediaTypeEquals(request.ContentType, OpaqueMediaType))
        {
            throw Error(
                ManagedIngressContractError.UnsupportedMediaType,
                "The request media type is unsupported.");
        }

        if (!MediaTypeEquals(request.Accept, OpaqueMediaType))
        {
            throw Error(
                ManagedIngressContractError.UnsupportedResponseType,
                "The response media type is unsupported.");
        }

        if (!string.IsNullOrWhiteSpace(request.ContentEncoding))
        {
            throw Error(
                ManagedIngressContractError.ContentCodingForbidden,
                "Content coding is forbidden.");
        }

        if (request.IsEarlyData)
        {
            throw Error(
                ManagedIngressContractError.EarlyDataRejected,
                "TLS early data is forbidden.");
        }

        CheckFrameLength(request.BodyLength);
        ValidateHeaders(request.Headers);
        return ManagedIngressTransportResult.TransitRequestValidated;
    }

    public static ManagedIngressTransportResult ClassifyFrameResponse(
        ManagedIngressResponseMetadata response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.StatusCode != 200 ||
            response.HttpVersion != HttpVersion.Version20 ||
            !MediaTypeEquals(response.ContentType, OpaqueMediaType) ||
            !string.IsNullOrWhiteSpace(response.ContentEncoding) ||
            response.BodyLength is
                < ManagedIngressLimits.MinimumOpaqueFrameBytes or
                > ManagedIngressLimits.MaximumOpaqueFrameBytes)
        {
            return ManagedIngressTransportResult.InvalidResponse;
        }

        try
        {
            ValidateHeaders(response.Headers);
            return ManagedIngressTransportResult.TransitCompleted;
        }
        catch (ManagedIngressContractException)
        {
            return ManagedIngressTransportResult.InvalidResponse;
        }
    }

    public static ManagedIngressTransportResult ClassifyCancellation(bool forwardStarted) =>
        forwardStarted
            ? ManagedIngressTransportResult.OutcomeUnknown
            : ManagedIngressTransportResult.CancelledBeforeForward;

    public static void ValidateHeaders(IReadOnlyList<ManagedIngressHeader> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);
        if (headers.Count > ManagedIngressLimits.MaximumHeaderFields)
        {
            throw Error(
                ManagedIngressContractError.HeaderCountExceeded,
                "The decoded header count exceeds the contract limit.");
        }

        foreach (var header in headers)
        {
            if (header is null ||
                string.IsNullOrWhiteSpace(header.Name) ||
                header.Value is null ||
                header.Name.Any(character =>
                    character > 0x7f ||
                    char.IsUpper(character) ||
                    char.IsWhiteSpace(character)) ||
                header.Value.Contains('\r', StringComparison.Ordinal) ||
                header.Value.Contains('\n', StringComparison.Ordinal))
            {
                throw Error(
                    ManagedIngressContractError.MalformedHeader,
                    "A decoded header is malformed.");
            }

            if (ForbiddenHeaders.Contains(header.Name) ||
                header.Name.StartsWith("x-request-", StringComparison.OrdinalIgnoreCase) ||
                header.Name.StartsWith("x-correlation-", StringComparison.OrdinalIgnoreCase))
            {
                throw Error(
                    ManagedIngressContractError.ForbiddenHeader,
                    "A stable or reflective header is forbidden.");
            }
        }

        if (ComputeDecodedHeaderListBytes(headers) >
            ManagedIngressLimits.MaximumDecodedHeaderListBytes)
        {
            throw Error(
                ManagedIngressContractError.HeaderListTooLarge,
                "The decoded header list exceeds the contract limit.");
        }
    }

    public static int ComputeDecodedHeaderListBytes(IReadOnlyList<ManagedIngressHeader> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);
        var total = 0;
        foreach (var header in headers)
        {
            ArgumentNullException.ThrowIfNull(header);
            if (header.Name is null || header.Value is null)
            {
                throw Error(
                    ManagedIngressContractError.MalformedHeader,
                    "A decoded header is malformed.");
            }

            total = checked(
                total +
                Encoding.UTF8.GetByteCount(header.Name) +
                Encoding.UTF8.GetByteCount(header.Value) +
                32);
        }

        return total;
    }

    public static bool IsCanonicalErrorMapping(
        int httpStatus,
        ManagedIngressErrorFrame frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        var expected = httpStatus switch
        {
            400 => (ManagedIngressErrorClass.MalformedFrame,
                ManagedIngressOutcomeCertainty.BeforeForward, false),
            406 => (ManagedIngressErrorClass.UnsupportedResponseType,
                ManagedIngressOutcomeCertainty.BeforeForward, false),
            413 => (ManagedIngressErrorClass.FrameTooLarge,
                ManagedIngressOutcomeCertainty.BeforeForward, false),
            415 => (ManagedIngressErrorClass.UnsupportedMediaType,
                ManagedIngressOutcomeCertainty.BeforeForward, false),
            421 => (ManagedIngressErrorClass.WrongOrigin,
                ManagedIngressOutcomeCertainty.BeforeForward, true),
            425 => (ManagedIngressErrorClass.EarlyDataRejected,
                ManagedIngressOutcomeCertainty.BeforeForward, true),
            429 => (ManagedIngressErrorClass.Saturated,
                ManagedIngressOutcomeCertainty.BeforeForward, true),
            502 => (ManagedIngressErrorClass.InvalidUpstreamResponse,
                ManagedIngressOutcomeCertainty.UnknownAfterForward, true),
            503 => (ManagedIngressErrorClass.Unavailable,
                ManagedIngressOutcomeCertainty.BeforeForward, true),
            504 => (ManagedIngressErrorClass.UpstreamOutcomeUnknown,
                ManagedIngressOutcomeCertainty.UnknownAfterForward, true),
            _ => default
        };

        if (expected == default ||
            frame.ErrorClass != expected.Item1 ||
            frame.Certainty != expected.Item2 ||
            frame.Retryable != expected.Item3)
        {
            return false;
        }

        return httpStatus switch
        {
            429 or 503 => frame.RetryAfterSeconds is
                >= ManagedIngressLimits.MinimumRetryAfterSeconds and
                <= ManagedIngressLimits.MaximumRetryAfterSeconds,
            _ => frame.RetryAfterSeconds == 0
        };
    }

    private static bool MediaTypeEquals(string? actual, string expected) =>
        actual is not null &&
        StringComparer.OrdinalIgnoreCase.Equals(actual.Trim(), expected);

    private static void CheckFrameLength(long length)
    {
        if (length is
            < ManagedIngressLimits.MinimumOpaqueFrameBytes or
            > ManagedIngressLimits.MaximumOpaqueFrameBytes)
        {
            throw Error(
                ManagedIngressContractError.FrameLengthOutOfRange,
                "The opaque frame length is outside strict bounds.");
        }
    }

    private static ManagedIngressContractException Error(
        ManagedIngressContractError error,
        string message) => new(error, message);
}
