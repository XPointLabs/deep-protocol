using System.Text;
using System.Net;
using System.Globalization;

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
            "x-correlation-id",
            "x-account",
            "x-plan",
            "x-payer",
            "x-wallet",
            "x-operation-id",
            "x-attempt-id",
            "x-session-id",
            "x-capability",
            "x-receipt",
            "connection",
            "keep-alive",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "forwarded",
            "via",
            "user-agent",
            "referer",
            "origin"
        };

    private static readonly HashSet<string> FrameMetadataHeaders =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "content-type",
            "accept",
            "content-length",
            "host"
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

        ValidateRoutingMetadata(request);

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
        ValidateRequestHeaders(request, includeContentType: true);
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
            return ManagedIngressTransportResult.OutcomeUnknown;
        }

        try
        {
            ValidateResponseHeaders(response.Headers, allowRetryAfter: false);
            return ManagedIngressTransportResult.TransitCompleted;
        }
        catch (ManagedIngressContractException)
        {
            return ManagedIngressTransportResult.OutcomeUnknown;
        }
    }

    public static void ValidateCapabilityRequest(ManagedIngressRequestMetadata request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!StringComparer.Ordinal.Equals(request.Method, "GET"))
        {
            throw Error(ManagedIngressContractError.WrongMethod, "The capability method must be GET.");
        }

        if (!StringComparer.Ordinal.Equals(request.Path, CapabilitiesPath))
        {
            throw Error(ManagedIngressContractError.WrongPath, "The capability path is not canonical.");
        }

        if (!string.IsNullOrEmpty(request.Query))
        {
            throw Error(ManagedIngressContractError.QueryForbidden, "Queries are forbidden.");
        }

        if (request.HttpVersion != HttpVersion.Version20)
        {
            throw Error(ManagedIngressContractError.Http2Required, "HTTP/2 is required.");
        }

        ValidateRoutingMetadata(request);
        if (!string.IsNullOrEmpty(request.ContentType) ||
            !StringComparer.Ordinal.Equals(request.Accept, CapabilitiesMediaType))
        {
            throw Error(
                ManagedIngressContractError.UnsupportedMediaType,
                "The capability media contract is not canonical.");
        }

        if (!string.IsNullOrEmpty(request.ContentEncoding) ||
            request.BodyLength != 0 ||
            request.IsEarlyData)
        {
            throw Error(
                ManagedIngressContractError.ContentCodingForbidden,
                "Capability requests have no body, coding, or early data.");
        }

        ValidateRequestHeaders(request, includeContentType: false);
    }

    public static ManagedIngressCapabilityDocument ValidateCapabilityResponse(
        ManagedIngressResponseMetadata response,
        ReadOnlySpan<byte> body,
        IReadOnlySet<string> supportedCriticalFeatures)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(supportedCriticalFeatures);
        if (response.StatusCode != 200 ||
            response.HttpVersion != HttpVersion.Version20 ||
            !StringComparer.Ordinal.Equals(response.ContentType, CapabilitiesMediaType) ||
            !string.IsNullOrEmpty(response.ContentEncoding) ||
            response.BodyLength != body.Length ||
            body.IsEmpty ||
            body.Length > ManagedIngressLimits.MaximumCapabilityDocumentBytes)
        {
            throw Error(
                ManagedIngressContractError.MalformedCapabilityDocument,
                "The capability response is not canonical.");
        }

        ValidateResponseHeaders(response.Headers, allowRetryAfter: false);
        return ManagedIngressCapabilityDocumentCodec.Decode(body, supportedCriticalFeatures);
    }

    public static ManagedIngressErrorClassification ClassifyErrorResponse(
        ManagedIngressResponseMetadata response,
        ReadOnlySpan<byte> body)
    {
        ArgumentNullException.ThrowIfNull(response);
        try
        {
            if (response.HttpVersion != HttpVersion.Version20 ||
                !StringComparer.Ordinal.Equals(response.ContentType, ErrorMediaType) ||
                !string.IsNullOrEmpty(response.ContentEncoding) ||
                response.BodyLength != ManagedIngressLimits.ErrorFrameBytes ||
                body.Length != ManagedIngressLimits.ErrorFrameBytes)
            {
                return UnknownError();
            }

            ValidateResponseHeaders(response.Headers, allowRetryAfter: true);
            var retryHeaders = response.Headers
                .Where(header => StringComparer.OrdinalIgnoreCase.Equals(
                    header.Name,
                    "retry-after"))
                .ToArray();
            if (retryHeaders.Length > 1)
            {
                return UnknownError();
            }

            var frame = ManagedIngressErrorCodec.Decode(body);
            if (!IsCanonicalErrorMapping(response.StatusCode, frame))
            {
                return UnknownError();
            }

            if (frame.RetryAfterSeconds == 0)
            {
                if (retryHeaders.Length != 0)
                {
                    return UnknownError();
                }
            }
            else
            {
                if (retryHeaders.Length != 1 ||
                    !TryParseCanonicalRetryAfter(retryHeaders[0].Value, out var retryAfter) ||
                    retryAfter != frame.RetryAfterSeconds)
                {
                    return UnknownError();
                }
            }

            return new ManagedIngressErrorClassification(
                frame.Certainty == ManagedIngressOutcomeCertainty.BeforeForward
                    ? ManagedIngressTransportResult.RejectedBeforeForward
                    : ManagedIngressTransportResult.OutcomeUnknown,
                frame);
        }
        catch (Exception exception) when (
            exception is ManagedIngressContractException or
                ArgumentException or
                OverflowException)
        {
            return UnknownError();
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

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in headers)
        {
            if (header is null ||
                string.IsNullOrWhiteSpace(header.Name) ||
                header.Value is null ||
                header.Name.Any(character =>
                    character > 0x7f ||
                    char.IsUpper(character) ||
                    char.IsWhiteSpace(character)) ||
                header.Name[0] == ':' ||
                header.Value.Contains('\r', StringComparison.Ordinal) ||
                header.Value.Contains('\n', StringComparison.Ordinal))
            {
                throw Error(
                    ManagedIngressContractError.MalformedHeader,
                    "A decoded header is malformed.");
            }

            if (!names.Add(header.Name))
            {
                throw Error(
                    ManagedIngressContractError.MalformedHeader,
                    "Duplicate decoded header fields are forbidden.");
            }

            if (ForbiddenHeaders.Contains(header.Name) ||
                header.Name.StartsWith("x-", StringComparison.OrdinalIgnoreCase) ||
                header.Name.StartsWith("cf-", StringComparison.OrdinalIgnoreCase) ||
                header.Name.StartsWith("sec-", StringComparison.OrdinalIgnoreCase) ||
                header.Name.StartsWith("x-request-", StringComparison.OrdinalIgnoreCase) ||
                header.Name.StartsWith("x-correlation-", StringComparison.OrdinalIgnoreCase) ||
                header.Name.StartsWith("x-account-", StringComparison.OrdinalIgnoreCase) ||
                header.Name.StartsWith("x-plan-", StringComparison.OrdinalIgnoreCase) ||
                header.Name.StartsWith("x-payer-", StringComparison.OrdinalIgnoreCase) ||
                header.Name.StartsWith("x-wallet-", StringComparison.OrdinalIgnoreCase))
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

    public static int ComputeEffectiveFrameRequestHeaderBytes(
        ManagedIngressRequestMetadata request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var mandatory = EffectiveRequestHeaders(request, includeContentType: true);
        return ComputeDecodedHeaderListBytes(mandatory);
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
        StringComparer.Ordinal.Equals(actual, expected);

    private static void ValidateRoutingMetadata(ManagedIngressRequestMetadata request)
    {
        if (!StringComparer.Ordinal.Equals(request.Scheme, "https") ||
            string.IsNullOrEmpty(request.Authority) ||
            request.Authority.Length > 253 ||
            request.Authority.Any(character =>
                character > 0x7f ||
                char.IsUpper(character) ||
                char.IsWhiteSpace(character) ||
                character is '/' or '\\' or '@'))
        {
            throw Error(
                ManagedIngressContractError.MalformedHeader,
                "The HTTP/2 scheme or authority is not canonical.");
        }
    }

    private static void ValidateRequestHeaders(
        ManagedIngressRequestMetadata request,
        bool includeContentType)
    {
        ValidateHeaders(request.Headers);
        if (request.Headers.Any(header => FrameMetadataHeaders.Contains(header.Name)))
        {
            throw Error(
                ManagedIngressContractError.ForbiddenHeader,
                "Mandatory request metadata cannot be duplicated in the header collection.");
        }

        var effective = EffectiveRequestHeaders(request, includeContentType);
        if (effective.Count > ManagedIngressLimits.MaximumHeaderFields)
        {
            throw Error(
                ManagedIngressContractError.HeaderCountExceeded,
                "The effective decoded header count exceeds the contract limit.");
        }

        if (ComputeDecodedHeaderListBytes(effective) >
            ManagedIngressLimits.MaximumDecodedHeaderListBytes)
        {
            throw Error(
                ManagedIngressContractError.HeaderListTooLarge,
                "The effective decoded header list exceeds the contract limit.");
        }
    }

    private static void ValidateResponseHeaders(
        IReadOnlyList<ManagedIngressHeader> headers,
        bool allowRetryAfter)
    {
        ValidateHeaders(headers);
        if (headers.Any(header =>
                FrameMetadataHeaders.Contains(header.Name) ||
                (!allowRetryAfter &&
                 StringComparer.OrdinalIgnoreCase.Equals(header.Name, "retry-after"))))
        {
            throw Error(
                ManagedIngressContractError.ForbiddenHeader,
                "Response metadata cannot be duplicated in the header collection.");
        }
    }

    private static IReadOnlyList<ManagedIngressHeader> EffectiveRequestHeaders(
        ManagedIngressRequestMetadata request,
        bool includeContentType)
    {
        var headers = new List<ManagedIngressHeader>
        {
            new(":method", request.Method),
            new(":scheme", request.Scheme),
            new(":authority", request.Authority),
            new(":path", request.Path),
            new("accept", request.Accept),
            new("content-length", request.BodyLength.ToString(CultureInfo.InvariantCulture))
        };
        if (includeContentType)
        {
            headers.Add(new ManagedIngressHeader("content-type", request.ContentType));
        }

        headers.AddRange(request.Headers);
        return headers;
    }

    private static bool TryParseCanonicalRetryAfter(string value, out int seconds)
    {
        seconds = 0;
        return value.Length is >= 1 and <= 2 &&
               value.All(character => character is >= '0' and <= '9') &&
               value[0] != '0' &&
               int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out seconds) &&
               seconds is
                   >= ManagedIngressLimits.MinimumRetryAfterSeconds and
                   <= ManagedIngressLimits.MaximumRetryAfterSeconds;
    }

    private static ManagedIngressErrorClassification UnknownError() =>
        new(ManagedIngressTransportResult.OutcomeUnknown, null);

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
