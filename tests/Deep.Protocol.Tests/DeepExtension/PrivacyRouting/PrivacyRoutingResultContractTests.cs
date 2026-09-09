using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.Tests.DeepExtension.PrivacyRouting;

public sealed class PrivacyRoutingResultContractTests
{
    [Fact]
    public void Xpr1_IsExactAndCanonical()
    {
        var result = PrivacyRoutingTerminalResult.Failure(PrivacyRoutingOperation.Retrieve, PrivacyRoutingFailureCode.OutcomeUnknown);
        var bytes = PrivacyRoutingResultCodec.Encode(result);
        Assert.Equal("XPR1", System.Text.Encoding.ASCII.GetString(bytes, 0, 4));
        Assert.Equal(result.FailureCode, PrivacyRoutingResultCodec.Decode(bytes).FailureCode);
        bytes[11] = 1;
        Assert.Throws<PrivacyRoutingProtocolException>(() => PrivacyRoutingResultCodec.Decode(bytes));
    }

    [Fact]
    public void ReplayWindow_IsBoundedAndDoesNotEvict()
    {
        var window = new PrivacyRoutingReplayWindow(1);
        Assert.Equal(PrivacyRoutingReplayResult.Accepted, window.TryAccept(Enumerable.Repeat((byte)1, 32).ToArray()));
        Assert.Equal(PrivacyRoutingReplayResult.Saturated, window.TryAccept(Enumerable.Repeat((byte)2, 32).ToArray()));
        Assert.Equal(PrivacyRoutingReplayResult.Replayed, window.TryAccept(Enumerable.Repeat((byte)1, 32).ToArray()));
    }

    [Fact]
    public void Xpr1_ContactResolveOperationIsExplicit()
    {
        var encoded = PrivacyRoutingResultCodec.Encode(
            PrivacyRoutingTerminalResult.Failure(
                PrivacyRoutingOperation.ContactResolve,
                PrivacyRoutingFailureCode.Unavailable));
        var decoded = PrivacyRoutingResultCodec.Decode(encoded);
        Assert.Equal(4, (byte)decoded.Operation);
        Assert.Equal(PrivacyRoutingOperation.ContactResolve, decoded.Operation);
    }

    [Fact]
    public void ContactResolveSuccessBodyRejectsMaxPlusOne()
    {
        var error = Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingTerminalResult.Success(
                PrivacyRoutingOperation.ContactResolve,
                new byte[PrivacyRoutingLimits.MaximumContactResolverResponseBytes + 1]));
        Assert.Equal(PrivacyRoutingProtocolError.InvalidLength, error.Error);
    }
}
