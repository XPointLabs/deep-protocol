using System.Net;
using System.Text;
using Deep.Protocol.DeepExtension.ManagedIngress;
using Deep.Protocol.GoldenVectors;

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
    [InlineData(202, ManagedIngressTransportResult.InvalidResponse)]
    [InlineData(204, ManagedIngressTransportResult.InvalidResponse)]
    [InlineData(301, ManagedIngressTransportResult.InvalidResponse)]
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

        Assert.Equal(expected, ManagedIngressH2Contract.ClassifyFrameResponse(response));
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
        headers: Array.Empty<ManagedIngressHeader>());
}
