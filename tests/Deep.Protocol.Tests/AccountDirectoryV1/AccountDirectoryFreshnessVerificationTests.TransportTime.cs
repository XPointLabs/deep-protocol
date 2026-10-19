using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed partial class AccountDirectoryFreshnessVerificationTests
{
    [Theory]
    [InlineData(0UL)]
    [InlineData(1UL)]
    [InlineData(7UL)]
    [InlineData(30UL)]
    public void Did2TimeTransport_UpperAccountsForBoundedRoundTripWithoutAdvancingLower(ulong roundTrip)
    {
        var f = Did2EmptyFixture.Create(); var dtt = AccountDirectoryDtt1Codec.Decode(f.DttBytes);
        var result = f.Verify(window: new(Bytes(16, 0x44), 100, 100 + roundTrip, 102 + roundTrip));
        Assert.Equal(dtt.ObservedUnixTime - dtt.UncertaintySeconds + 2, result.TrustedLowerUnixSeconds);
        Assert.Equal(dtt.ObservedUnixTime + dtt.UncertaintySeconds + roundTrip + 2, result.TrustedUpperUnixSeconds);
        Assert.Equal(102 + roundTrip, result.MonotonicSample);
    }

    [Fact]
    public void Did2TimeTransport_LargeBootSampleUsesElapsedNotAbsoluteSample()
    {
        var f = Did2EmptyFixture.Create(); var dtt = AccountDirectoryDtt1Codec.Decode(f.DttBytes);
        var result = f.Verify(window: new(Bytes(16, 0x44), ulong.MaxValue - 10, ulong.MaxValue - 2, ulong.MaxValue - 2));
        Assert.Equal(dtt.ObservedUnixTime - dtt.UncertaintySeconds, result.TrustedLowerUnixSeconds);
        Assert.Equal(dtt.ObservedUnixTime + dtt.UncertaintySeconds + 8, result.TrustedUpperUnixSeconds);
    }

    [Fact]
    public void Did2TimeTransport_LatencyCannotHideSignedDttExpiry()
    {
        var f = Did2EmptyFixture.Create();
        Assert.Equal("DttExpired", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            f.Verify(window: new(Bytes(16, 0x44), 100, 130, 160))).Code);
    }

    [Fact]
    public void Did2TimeTransport_OriginalNonceDeadlineStillRejectsBeforeProofRelease()
    {
        var f = Did2EmptyFixture.Create();
        Assert.Equal("NonceWindowExpired", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            f.Verify(window: new(Bytes(16, 0x44), 100, 131, 131))).Code);
    }
}
