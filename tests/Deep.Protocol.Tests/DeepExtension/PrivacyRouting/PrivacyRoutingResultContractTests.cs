using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.Tests.DeepExtension.PrivacyRouting;

public sealed class PrivacyRoutingResultContractTests
{
    [Theory]
    [InlineData(PrivacyRoutingOperation.Store)]
    [InlineData(PrivacyRoutingOperation.Retrieve)]
    [InlineData(PrivacyRoutingOperation.Acknowledge)]
    public void Success_ExactDpr1RoundTripsCanonicalBody(PrivacyRoutingOperation operation)
    {
        var encoded = PrivacyRoutingResultCodec.Encode(
            PrivacyRoutingTerminalResult.Success(operation, "canonical-inner-result"u8));

        Assert.Equal("DPR1"u8.ToArray(), encoded[..4]);
        Assert.Equal(1, encoded[4]);
        Assert.Equal(1, encoded[5]);
        Assert.Equal((byte)PrivacyRoutingResultKind.Success, encoded[6]);
        Assert.Equal((byte)operation, encoded[7]);
        Assert.Equal(22u, BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(12, 4)));
        var decoded = PrivacyRoutingResultCodec.Decode(encoded);
        Assert.Equal(PrivacyRoutingResultKind.Success, decoded.Kind);
        Assert.Equal(operation, decoded.Operation);
        Assert.Null(decoded.FailureCode);
        Assert.False(decoded.Retryable);
        Assert.Equal("canonical-inner-result"u8.ToArray(), decoded.Body.ToArray());
    }

    [Theory]
    [InlineData(PrivacyRoutingFailureCode.MalformedRequest, false)]
    [InlineData(PrivacyRoutingFailureCode.AuthenticationRejected, false)]
    [InlineData(PrivacyRoutingFailureCode.ReplayRejected, false)]
    [InlineData(PrivacyRoutingFailureCode.CapacityExceeded, true)]
    [InlineData(PrivacyRoutingFailureCode.Unavailable, true)]
    [InlineData(PrivacyRoutingFailureCode.OutcomeUnknown, true)]
    [InlineData(PrivacyRoutingFailureCode.InternalFailure, false)]
    public void Failure_ExactDpr1RoundTripsStablePolicy(
        PrivacyRoutingFailureCode code,
        bool retryable)
    {
        var encoded = PrivacyRoutingResultCodec.Encode(
            PrivacyRoutingTerminalResult.Failure(PrivacyRoutingOperation.Store, code));
        var decoded = PrivacyRoutingResultCodec.Decode(encoded);

        Assert.Equal(20, encoded.Length);
        Assert.Equal(PrivacyRoutingResultKind.Failure, decoded.Kind);
        Assert.Equal(code, decoded.FailureCode);
        Assert.Equal(retryable, decoded.Retryable);
        Assert.Empty(decoded.Body.ToArray());
    }

    [Fact]
    public void UnknownReservedLengthAndContradictoryRetryPolicy_Reject()
    {
        var canonical = PrivacyRoutingResultCodec.Encode(
            PrivacyRoutingTerminalResult.Failure(
                PrivacyRoutingOperation.Retrieve,
                PrivacyRoutingFailureCode.Unavailable));

        AssertError(canonical, 4, 2, PrivacyRoutingProtocolError.UnsupportedVersion);
        AssertError(canonical, 6, 3, PrivacyRoutingProtocolError.InvalidOperation);
        AssertError(canonical, 10, 0, PrivacyRoutingProtocolError.InvalidOperation);
        AssertError(canonical, 11, 1, PrivacyRoutingProtocolError.InvalidPadding);
        AssertError(canonical, 16, 1, PrivacyRoutingProtocolError.InvalidPadding);

        var wrongLength = canonical.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(wrongLength.AsSpan(12, 4), 1);
        Assert.Equal(
            PrivacyRoutingProtocolError.InvalidLength,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingResultCodec.Decode(wrongLength)).Error);
    }

    [Fact]
    public void SuccessBody_IsDefensivelyOwned()
    {
        var input = "mqr3"u8.ToArray();
        var result = PrivacyRoutingTerminalResult.Success(PrivacyRoutingOperation.Store, input);
        input[0] ^= 0xff;
        var copy = result.Body.ToArray();
        copy[0] ^= 0xff;

        Assert.Equal("mqr3"u8.ToArray(), result.Body.ToArray());
    }

    private static void AssertError(
        byte[] canonical,
        int offset,
        byte value,
        PrivacyRoutingProtocolError expected)
    {
        var malformed = canonical.ToArray();
        malformed[offset] = value;
        Assert.Equal(
            expected,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingResultCodec.Decode(malformed)).Error);
    }
}
