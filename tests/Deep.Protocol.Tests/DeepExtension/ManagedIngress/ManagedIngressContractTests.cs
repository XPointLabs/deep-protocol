using System.Net;
using System.Text;
using Deep.Protocol.DeepExtension.ManagedIngress;
using Deep.Protocol.DeepExtension.OpaqueBundles;
using Deep.Protocol.GoldenVectors;
using Deep.Protocol.Abstractions.OnionRequests;
using Sodium;

namespace Deep.Protocol.Tests.DeepExtension.ManagedIngress;

public sealed class ManagedIngressContractTests
{
    [Fact]
    public void ContractConstants_AreExactAndTransportOnly()
    {
        Assert.Equal("Deep.Protocol/P10B-managed-ingress-h2-v1", ManagedIngressH2Contract.ContractId);
        Assert.Equal("/api/ingress/v1/frame", ManagedIngressH2Contract.FramePath);
        Assert.Equal("/api/ingress/v1/capabilities", ManagedIngressH2Contract.CapabilitiesPath);
        Assert.Equal(64, ManagedIngressLimits.MinimumOpaqueFrameBytes);
        Assert.Equal(1_572_864, ManagedIngressLimits.MaximumOpaqueFrameBytes);
        Assert.Equal(8_192, ManagedIngressLimits.MaximumDecodedHeaderListBytes);
        Assert.Equal(32, ManagedIngressLimits.MaximumHeaderFields);
        Assert.Equal(4_096, ManagedIngressLimits.MaximumCapabilityDocumentBytes);
        Assert.Equal(64, ManagedIngressLimits.ErrorFrameBytes);

        var publicNames = typeof(ManagedIngressH2Contract).Assembly
            .GetExportedTypes()
            .Where(type => type.Namespace == typeof(ManagedIngressH2Contract).Namespace)
            .SelectMany(type => new[] { type.Name }.Concat(type.GetMembers().Select(member => member.Name)))
            .ToArray();
        Assert.DoesNotContain(publicNames, name => name.Contains("Accepted", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(publicNames, name => name.Contains("Durable", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(publicNames, name => name.Contains("Delivered", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(64)]
    [InlineData(1_572_864)]
    public void OpaqueFrame_BoundsAreAcceptedAndBytesRemainOpaque(int length)
    {
        var input = new byte[length];
        input[0] = 0x44;
        input[^1] = 0xa5;

        var frame = ManagedIngressH2Contract.ValidateOpaqueFrame(input);

        Assert.Equal(input, frame.Bytes.ToArray());
        input[0] ^= 0xff;
        Assert.Equal(0x44, frame.Bytes.Span[0]);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(63)]
    [InlineData(1_572_865)]
    public void OpaqueFrame_OutOfBoundsFailsBeforeCopy(int length)
    {
        var input = new byte[length];
        var exception = Assert.Throws<ManagedIngressContractException>(
            () => ManagedIngressH2Contract.ValidateOpaqueFrame(input));
        Assert.Equal(ManagedIngressContractError.FrameLengthOutOfRange, exception.Error);
    }

    [Fact]
    public void CanonicalFrameRequest_IsAcceptedOnlyAsTransit()
    {
        var request = CanonicalRequest();

        var result = ManagedIngressH2Contract.ValidateFrameRequest(request);

        Assert.Equal(ManagedIngressTransportResult.TransitRequestValidated, result);
    }

    [Theory]
    [InlineData("GET", "/api/ingress/v1/frame", "", "2.0",
        "application/vnd.xpoint.deep.ingress-opaque-v1",
        "application/vnd.xpoint.deep.ingress-opaque-v1")]
    [InlineData("POST", "/api/ingress/v1/frame/", "", "2.0",
        "application/vnd.xpoint.deep.ingress-opaque-v1",
        "application/vnd.xpoint.deep.ingress-opaque-v1")]
    [InlineData("POST", "/api/ingress/v1/frame", "x=1", "2.0",
        "application/vnd.xpoint.deep.ingress-opaque-v1",
        "application/vnd.xpoint.deep.ingress-opaque-v1")]
    [InlineData("POST", "/api/ingress/v1/frame", "", "1.1",
        "application/vnd.xpoint.deep.ingress-opaque-v1",
        "application/vnd.xpoint.deep.ingress-opaque-v1")]
    [InlineData("POST", "/api/ingress/v1/frame", "", "3.0",
        "application/vnd.xpoint.deep.ingress-opaque-v1",
        "application/vnd.xpoint.deep.ingress-opaque-v1")]
    [InlineData("POST", "/api/ingress/v1/frame", "", "2.0",
        "application/json",
        "application/vnd.xpoint.deep.ingress-opaque-v1")]
    [InlineData("POST", "/api/ingress/v1/frame", "", "2.0",
        "application/vnd.xpoint.deep.ingress-opaque-v1",
        "application/json")]
    public void NonCanonicalFrameRequest_FailsClosed(
        string method,
        string path,
        string query,
        string version,
        string contentType,
        string accept)
    {
        var request = CanonicalRequest() with
        {
            Method = method,
            Path = path,
            Query = query,
            HttpVersion = Version.Parse(version),
            ContentType = contentType,
            Accept = accept
        };

        Assert.Throws<ManagedIngressContractException>(
            () => ManagedIngressH2Contract.ValidateFrameRequest(request));
    }

    [Theory]
    [InlineData("authorization")]
    [InlineData("cookie")]
    [InlineData("idempotency-key")]
    [InlineData("traceparent")]
    [InlineData("tracestate")]
    [InlineData("baggage")]
    [InlineData("content-encoding")]
    [InlineData("x-request-id")]
    [InlineData("x-correlation-id")]
    public void StableOrReflectiveHeaders_AreForbidden(string name)
    {
        var request = CanonicalRequest() with
        {
            Headers = [new ManagedIngressHeader(name, "forbidden")]
        };

        var exception = Assert.Throws<ManagedIngressContractException>(
            () => ManagedIngressH2Contract.ValidateFrameRequest(request));
        Assert.Equal(ManagedIngressContractError.ForbiddenHeader, exception.Error);
    }

    [Fact]
    public void EarlyData_IsRejectedBeforeForward()
    {
        var request = CanonicalRequest() with { IsEarlyData = true };

        var exception = Assert.Throws<ManagedIngressContractException>(
            () => ManagedIngressH2Contract.ValidateFrameRequest(request));

        Assert.Equal(ManagedIngressContractError.EarlyDataRejected, exception.Error);
        Assert.Equal(ManagedIngressOutcomeCertainty.BeforeForward, exception.Certainty);
    }

    [Theory]
    [InlineData(200, ManagedIngressTransportResult.TransitCompleted)]
    [InlineData(202, ManagedIngressTransportResult.OutcomeUnknown)]
    [InlineData(204, ManagedIngressTransportResult.OutcomeUnknown)]
    [InlineData(301, ManagedIngressTransportResult.OutcomeUnknown)]
    public void OuterSuccess_NeverCreatesMailboxAuthority(
        int statusCode,
        ManagedIngressTransportResult expected)
    {
        var response = new ManagedIngressResponseMetadata(
            statusCode,
            HttpVersion.Version20,
            ManagedIngressH2Contract.OpaqueMediaType,
            contentEncoding: null,
            bodyLength: 64,
            headers: Array.Empty<ManagedIngressHeader>());

        Assert.Equal(
            expected,
            ManagedIngressH2Contract.ClassifyFrameResponse(response, new byte[64]));
    }

    [Theory]
    [InlineData("MRR1")]
    [InlineData("MQR1")]
    [InlineData("DPB1")]
    [InlineData("MCP1")]
    public void InnerLookingBytes_RemainOpaqueAndUninterpreted(string prefix)
    {
        var bytes = new byte[ManagedIngressLimits.MinimumOpaqueFrameBytes];
        Encoding.ASCII.GetBytes(prefix).CopyTo(bytes, 0);

        var frame = ManagedIngressH2Contract.ValidateOpaqueFrame(bytes);

        Assert.Equal(bytes, frame.Bytes.ToArray());
    }

    [Theory]
    [InlineData(false, ManagedIngressTransportResult.CancelledBeforeForward)]
    [InlineData(true, ManagedIngressTransportResult.OutcomeUnknown)]
    public void Cancellation_IsClassifiedByForwardBoundary(
        bool forwardStarted,
        ManagedIngressTransportResult expected)
    {
        Assert.Equal(expected, ManagedIngressH2Contract.ClassifyCancellation(forwardStarted));
    }

    [Fact]
    public void StreamingAdmission_RejectsMismatchTruncationOverflowAndCancellationBeforeForward()
    {
        var mismatch = new ManagedIngressStreamingAdmission(declaredLength: 65);
        mismatch.Append(new byte[64]);
        Assert.Throws<ManagedIngressContractException>(() => mismatch.Complete());

        var overflow = new ManagedIngressStreamingAdmission(
            ManagedIngressLimits.MaximumOpaqueFrameBytes);
        overflow.Append(new byte[ManagedIngressLimits.MaximumOpaqueFrameBytes]);
        Assert.Throws<ManagedIngressContractException>(() => overflow.Append([0x01]));

        var cancelled = new ManagedIngressStreamingAdmission(64);
        cancelled.Append(new byte[32]);
        Assert.Equal(
            ManagedIngressTransportResult.CancelledBeforeForward,
            cancelled.Cancel());
        Assert.Throws<InvalidOperationException>(() => cancelled.MarkForwardStarted());
    }

    [Fact]
    public void StreamingAdmission_OnlyAllowsForwardAfterCompleteBoundedBody()
    {
        var admission = new ManagedIngressStreamingAdmission(64);
        admission.Append(new byte[17]);
        admission.Append(new byte[47]);

        admission.Complete();
        admission.MarkForwardStarted();

        Assert.Equal(64, admission.ReceivedBytes);
        Assert.Equal(
            ManagedIngressTransportResult.OutcomeUnknown,
            admission.Cancel());
    }

    [Fact]
    public void OverflowPermanentlyPoisonsAdmission()
    {
        var admission = new ManagedIngressStreamingAdmission(
            ManagedIngressLimits.MaximumOpaqueFrameBytes);
        admission.Append(new byte[ManagedIngressLimits.MaximumOpaqueFrameBytes]);

        Assert.Throws<ManagedIngressContractException>(() => admission.Append([0x01]));
        Assert.Throws<InvalidOperationException>(() => admission.Append(ReadOnlySpan<byte>.Empty));
        Assert.Throws<InvalidOperationException>(() => admission.Complete());
        Assert.Throws<InvalidOperationException>(() => admission.MarkForwardStarted());
    }

    [Fact]
    public void TruncatedCompletionPermanentlyPoisonsAdmission()
    {
        var admission = new ManagedIngressStreamingAdmission(65);
        admission.Append(new byte[64]);

        Assert.Throws<ManagedIngressContractException>(() => admission.Complete());
        Assert.Throws<InvalidOperationException>(() => admission.Append([0x01]));
        Assert.Throws<InvalidOperationException>(() => admission.Complete());
        Assert.Throws<InvalidOperationException>(() => admission.MarkForwardStarted());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(63)]
    [InlineData(65)]
    public void FrameResponse_RequiresActualCompleteBody(int actualLength)
    {
        var response = CanonicalFrameResponse(bodyLength: 64);

        Assert.Equal(
            ManagedIngressTransportResult.OutcomeUnknown,
            ManagedIngressH2Contract.ClassifyFrameResponse(
                response,
                new byte[actualLength]));
    }

    [Theory]
    [InlineData(64)]
    [InlineData(1_572_864)]
    public void FrameResponse_ActualBoundsAreAccepted(int length)
    {
        var response = CanonicalFrameResponse(length);
        Assert.Equal(
            ManagedIngressTransportResult.TransitCompleted,
            ManagedIngressH2Contract.ClassifyFrameResponse(response, new byte[length]));
    }

    [Fact]
    public void ResponseMandatoryFields_AreIncludedInLimits()
    {
        var response = CanonicalFrameResponse(64);
        Assert.True(
            ManagedIngressH2Contract.ComputeEffectiveResponseHeaderBytes(response) >
            ManagedIngressH2Contract.ComputeDecodedHeaderListBytes(response.Headers));

        var supplementalWithinStandaloneLimit = new[]
        {
            new ManagedIngressHeader(
                "cache-control",
                new string('a', ManagedIngressLimits.MaximumDecodedHeaderListBytes - 64))
        };
        Assert.True(
            ManagedIngressH2Contract.ComputeDecodedHeaderListBytes(
                supplementalWithinStandaloneLimit) <=
            ManagedIngressLimits.MaximumDecodedHeaderListBytes);
        Assert.Equal(
            ManagedIngressTransportResult.OutcomeUnknown,
            ManagedIngressH2Contract.ClassifyFrameResponse(
                response with { Headers = supplementalWithinStandaloneLimit },
                new byte[64]));
    }

    [Fact]
    public void MandatoryPseudoAndMediaHeaders_AreCountedAndCannotBeDuplicated()
    {
        var request = CanonicalRequest();
        Assert.True(
            ManagedIngressH2Contract.ComputeEffectiveFrameRequestHeaderBytes(request) >
            ManagedIngressH2Contract.ComputeDecodedHeaderListBytes(request.Headers));

        var duplicate = request with
        {
            Headers = [new ManagedIngressHeader("content-type", ManagedIngressH2Contract.OpaqueMediaType)]
        };
        Assert.Throws<ManagedIngressContractException>(
            () => ManagedIngressH2Contract.ValidateFrameRequest(duplicate));
    }

    [Theory]
    [InlineData("x-account")]
    [InlineData("x-plan")]
    [InlineData("x-payer")]
    [InlineData("x-wallet")]
    [InlineData("x-operation-id")]
    [InlineData("x-attempt-id")]
    [InlineData("account-id")]
    [InlineData("plan")]
    [InlineData("payer")]
    [InlineData("wallet")]
    [InlineData("operation-id")]
    [InlineData("bad/header")]
    [InlineData("connection")]
    [InlineData("transfer-encoding")]
    [InlineData(":path")]
    public void PrivacyBearingAndInvalidH2Headers_AreRejected(string name)
    {
        var request = CanonicalRequest() with
        {
            Headers = [new ManagedIngressHeader(name, "value")]
        };
        Assert.Throws<ManagedIngressContractException>(
            () => ManagedIngressH2Contract.ValidateFrameRequest(request));
    }

    [Theory]
    [InlineData("\0")]
    [InlineData("\u001f")]
    [InlineData("\u007f")]
    public void InvalidH2HeaderValues_AreRejected(string value)
    {
        Assert.Throws<ManagedIngressContractException>(() =>
            ManagedIngressH2Contract.ValidateHeaders(
                [new ManagedIngressHeader("cache-control", value)]));
    }

    [Fact]
    public void HeaderList_UsesRfc9113DecodedFormula()
    {
        var headers = new[]
        {
            new ManagedIngressHeader(":method", "POST"),
            new ManagedIngressHeader("content-type", ManagedIngressH2Contract.OpaqueMediaType)
        };

        var expected = headers.Sum(header =>
            Encoding.ASCII.GetByteCount(header.Name) +
            Encoding.ASCII.GetByteCount(header.Value) +
            32);
        Assert.Equal(expected, ManagedIngressH2Contract.ComputeDecodedHeaderListBytes(headers));
    }

    [Fact]
    public void ErrorVector_MatchesCanonicalBytes()
    {
        var error = new ManagedIngressErrorFrame(
            ManagedIngressErrorClass.Saturated,
            ManagedIngressOutcomeCertainty.BeforeForward,
            retryable: true,
            retryAfterSeconds: 17);

        var encoded = ManagedIngressErrorCodec.Encode(error);
        var vector = GoldenVectorLoader.Load("managed-ingress-h2-v1.json")
            .GetRequired("deep-extension/managed-ingress/v1/die1-saturated");

        VectorDiffs.AssertHex(vector.Id, vector.Hex!, Convert.ToHexString(encoded).ToLowerInvariant());
        Assert.Equal(error, ManagedIngressErrorCodec.Decode(encoded));
    }

    [Fact]
    public void CapabilityDocument_RoundTripsCanonicalBoundedJson()
    {
        var document = ManagedIngressCapabilityDocument.V1Ready();

        var encoded = ManagedIngressCapabilityDocumentCodec.Encode(document);
        var decoded = ManagedIngressCapabilityDocumentCodec.Decode(
            encoded,
            ManagedIngressCapabilityFeatures.KnownCritical);

        Assert.True(decoded.Ready);
        Assert.Equal(["2"], decoded.HttpVersions);
        Assert.True(encoded.Length <= ManagedIngressLimits.MaximumCapabilityDocumentBytes);
        Assert.Equal(encoded, ManagedIngressCapabilityDocumentCodec.Encode(decoded));
    }

    [Fact]
    public void CapabilityEndpoint_HasExactRequestAndResponseContract()
    {
        var request = CanonicalRequest() with
        {
            Method = "GET",
            Path = ManagedIngressH2Contract.CapabilitiesPath,
            ContentType = string.Empty,
            Accept = ManagedIngressH2Contract.CapabilitiesMediaType,
            BodyLength = 0
        };
        ManagedIngressH2Contract.ValidateCapabilityRequest(request);

        var body = ManagedIngressCapabilityDocumentCodec.Encode(
            ManagedIngressCapabilityDocument.V1Ready());
        var response = new ManagedIngressResponseMetadata(
            200,
            HttpVersion.Version20,
            ManagedIngressH2Contract.CapabilitiesMediaType,
            contentEncoding: null,
            body.Length,
            headers: Array.Empty<ManagedIngressHeader>());

        Assert.True(
            ManagedIngressH2Contract.ValidateCapabilityResponse(
                response,
                body,
                ManagedIngressCapabilityFeatures.KnownCritical).Ready);

        Assert.Throws<ManagedIngressContractException>(() =>
            ManagedIngressH2Contract.ValidateCapabilityRequest(request with { Query = "probe=1" }));
    }

    [Theory]
    [InlineData(421)]
    [InlineData(429)]
    [InlineData(503)]
    public void RetryAfterHeader_MustExactlyMatchCanonicalDie1(int status)
    {
        var errorClass = status switch
        {
            421 => ManagedIngressErrorClass.WrongOrigin,
            429 => ManagedIngressErrorClass.Saturated,
            _ => ManagedIngressErrorClass.Unavailable
        };
        var retryAfter = status is 429 or 503 ? 17 : 0;
        var frame = new ManagedIngressErrorFrame(
            errorClass,
            ManagedIngressOutcomeCertainty.BeforeForward,
            retryable: true,
            retryAfter);
        var body = ManagedIngressErrorCodec.Encode(frame);
        var headers = retryAfter == 0
            ? Array.Empty<ManagedIngressHeader>()
            : [new ManagedIngressHeader("retry-after", retryAfter.ToString())];
        var response = new ManagedIngressResponseMetadata(
            status,
            HttpVersion.Version20,
            ManagedIngressH2Contract.ErrorMediaType,
            contentEncoding: null,
            body.Length,
            headers);

        var classification = ManagedIngressH2Contract.ClassifyErrorResponse(response, body);

        Assert.Equal(
            frame.Certainty == ManagedIngressOutcomeCertainty.BeforeForward
                ? ManagedIngressTransportResult.RejectedBeforeForward
                : ManagedIngressTransportResult.OutcomeUnknown,
            classification.Result);

        var mismatch = response with
        {
            Headers = [new ManagedIngressHeader("retry-after", "60")]
        };
        Assert.Equal(
            ManagedIngressTransportResult.OutcomeUnknown,
            ManagedIngressH2Contract.ClassifyErrorResponse(mismatch, body).Result);
    }

    [Fact]
    public void MalformedOuterResponse_IsAlwaysOutcomeUnknown()
    {
        var response = new ManagedIngressResponseMetadata(
            503,
            HttpVersion.Version20,
            ManagedIngressH2Contract.ErrorMediaType,
            contentEncoding: null,
            ManagedIngressLimits.ErrorFrameBytes,
            headers: [new ManagedIngressHeader("retry-after", "17")]);

        Assert.Equal(
            ManagedIngressTransportResult.OutcomeUnknown,
            ManagedIngressH2Contract.ClassifyErrorResponse(
                response,
                new byte[ManagedIngressLimits.ErrorFrameBytes]).Result);
    }

    [Fact]
    public void MaximumSelectedThreeHopOnionProducerProfile_FitsOuterBound()
    {
        var destination = PublicKeyBox.GenerateKeyPair();
        var hops = Enumerable.Range(0, 3)
            .Select(index =>
            {
                var key = PublicKeyBox.GenerateKeyPair();
                return new OnionServiceNode($"hop-{index}", Array.Empty<byte>(), key.PublicKey);
            })
            .ToArray();
        var payload = new OnionRequestCodec().Build(
            new OnionRequestBuildOptions
            {
                EncryptionType = OnionEncryptionType.XChaCha20,
                Endpoint = "/api/ingress/internal/opaque-v1",
                DestinationX25519PublicKey = destination.PublicKey,
                Hops = hops
            },
            new byte[OpaqueBundleLimits.MaximumEncodedLength]);

        Assert.Equal(1_420_309, payload.Body.Length);
        var outer = ManagedIngressH2Contract.ValidateOpaqueFrame(payload.Body.Span);
        Assert.Equal(payload.Body.ToArray(), outer.Bytes.ToArray());
        var fixture = GoldenVectorLoader.Load("managed-ingress-h2-v1.json")
            .GetRequired("deep-extension/managed-ingress/v1/max-three-hop-producer");
        Assert.Equal((ulong)payload.Body.Length, fixture.TimestampMs);
        Assert.Equal(
            "DPB1-max=1064960;hops=3;endpoint=/api/ingress/internal/opaque-v1;xchacha20",
            fixture.Body);
    }

    [Fact]
    public void LanguageNeutralHttpFixtures_ArePresent()
    {
        var vectors = GoldenVectorLoader.Load("managed-ingress-h2-v1.json");
        Assert.Contains("\"method\":\"POST\"", vectors
            .GetRequired("deep-extension/managed-ingress/v1/frame-request").Body);
        Assert.Contains("\"status\":200", vectors
            .GetRequired("deep-extension/managed-ingress/v1/frame-success").Body);
        Assert.Contains("\"ready\":true", vectors
            .GetRequired("deep-extension/managed-ingress/v1/capability-ready").Body);
    }

    [Fact]
    public void ProductionSurface_HasNoInnerCodecTypes()
    {
        var managedTypes = typeof(ManagedIngressH2Contract).Assembly.GetExportedTypes()
            .Where(type => type.Namespace == typeof(ManagedIngressH2Contract).Namespace)
            .ToArray();
        var referencedTypeNames = managedTypes
            .SelectMany(type =>
                type.GetMethods().Select(method => method.ReturnType.FullName ?? string.Empty)
                    .Concat(type.GetMethods().SelectMany(method =>
                        method.GetParameters().Select(parameter =>
                            parameter.ParameterType.FullName ?? string.Empty)))
                    .Concat(type.GetProperties().Select(property =>
                        property.PropertyType.FullName ?? string.Empty)))
            .ToArray();

        Assert.DoesNotContain(referencedTypeNames, name =>
            name.Contains("OpaqueBundle", StringComparison.Ordinal) ||
            name.Contains("Mailbox", StringComparison.Ordinal));
    }

    [Fact]
    public void UnknownCriticalCapabilityFeature_FailsClosed()
    {
        var encoded = ManagedIngressCapabilityDocumentCodec.Encode(
            ManagedIngressCapabilityDocument.V1Ready() with
            {
                CriticalFeatures = ["opaque-frame-v1", "unknown-critical"]
            });

        var exception = Assert.Throws<ManagedIngressContractException>(
            () => ManagedIngressCapabilityDocumentCodec.Decode(
                encoded,
                ManagedIngressCapabilityFeatures.KnownCritical));
        Assert.Equal(ManagedIngressContractError.UnknownCriticalFeature, exception.Error);
    }

    private static ManagedIngressRequestMetadata CanonicalRequest() => new(
        "POST",
        ManagedIngressH2Contract.FramePath,
        query: string.Empty,
        HttpVersion.Version20,
        ManagedIngressH2Contract.OpaqueMediaType,
        ManagedIngressH2Contract.OpaqueMediaType,
        contentEncoding: null,
        bodyLength: 64,
        isEarlyData: false,
        headers: Array.Empty<ManagedIngressHeader>(),
        scheme: "https",
        authority: "bridge.example");

    private static ManagedIngressResponseMetadata CanonicalFrameResponse(long bodyLength) => new(
        200,
        HttpVersion.Version20,
        ManagedIngressH2Contract.OpaqueMediaType,
        contentEncoding: null,
        bodyLength,
        headers: Array.Empty<ManagedIngressHeader>());
}
