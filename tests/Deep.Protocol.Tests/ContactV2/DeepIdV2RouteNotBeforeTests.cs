using System.Security.Cryptography;
using Deep.Protocol.ContactV2;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2RouteNotBeforeTests
{
    public static IEnumerable<object[]> ThresholdArtifacts => new[]
    {
        DeepIdV2RouteTimeArtifact.Pms2, DeepIdV2RouteTimeArtifact.Xrc1, DeepIdV2RouteTimeArtifact.Xss1
    }.Select(value => new object[] { (int)value });

    [Theory]
    [MemberData(nameof(ThresholdArtifacts))]
    public void SchedulingOnlyCollectsFutureInsideWholeTrustedInterval(int value)
    {
        var artifact = (DeepIdV2RouteTimeArtifact)value;
        var window = new DeepIdV2RouteNotBeforeWindow(100, 105);
        window.Require(103, 200, artifact);
        var hint = Assert.Throws<DeepIdV2RouteNotBeforeException>(window.ThrowIfPending);
        Assert.Equal(3U, hint.RequiredDelaySeconds);
        Assert.IsType<CryptographicException>(Record.Exception(() =>
            DeepIdV2RouteTimeCoverage.Require(100, 105, 103, 200, artifact)));
        // A scheduling duration never admits the same record before its start.
        DeepIdV2RouteTimeCoverage.Require(103, 108, 103, 200, artifact);
    }

    [Theory]
    [MemberData(nameof(ThresholdArtifacts))]
    public void EarlierFutureCannotMaskAnotherThresholdExpiry(int value)
    {
        var window = new DeepIdV2RouteNotBeforeWindow(100, 105);
        window.Require(101, 200, DeepIdV2RouteTimeArtifact.Pms2);
        var error = Assert.Throws<CryptographicException>(() => window.Require(102, 105,
            (DeepIdV2RouteTimeArtifact)value));
        Assert.EndsWith("; Expiry).", error.Message);
    }

    [Theory]
    [MemberData(nameof(ThresholdArtifacts))]
    public void FutureBeyondTrustedUpperRejectsWithoutScheduling(int value)
    {
        var window = new DeepIdV2RouteNotBeforeWindow(100, 105);
        var error = Assert.Throws<CryptographicException>(() => window.Require(106, 200,
            (DeepIdV2RouteTimeArtifact)value));
        Assert.EndsWith("; NotBefore).", error.Message);
    }

    [Theory]
    [MemberData(nameof(ThresholdArtifacts))]
    public void InvertedTrustedIntervalRejectsWithoutScheduling(int value)
    {
        var window = new DeepIdV2RouteNotBeforeWindow(106, 105);
        var error = Assert.Throws<CryptographicException>(() => window.Require(107, 200,
            (DeepIdV2RouteTimeArtifact)value));
        Assert.EndsWith("; InvalidInterval).", error.Message);
    }

    [Fact]
    public void FinalWindowRecomputesMaximumDelayAndCanConvergeWithoutHint()
    {
        var first = new DeepIdV2RouteNotBeforeWindow(100, 105);
        first.Require(104, 200, DeepIdV2RouteTimeArtifact.Pms2);
        first.Require(102, 200, DeepIdV2RouteTimeArtifact.Xrc1);
        first.Require(103, 200, DeepIdV2RouteTimeArtifact.Xss1);
        Assert.Equal(4U, Assert.Throws<DeepIdV2RouteNotBeforeException>(first.ThrowIfPending).RequiredDelaySeconds);

        var final = new DeepIdV2RouteNotBeforeWindow(102, 107);
        final.Require(104, 200, DeepIdV2RouteTimeArtifact.Pms2);
        final.Require(102, 200, DeepIdV2RouteTimeArtifact.Xrc1);
        final.Require(103, 200, DeepIdV2RouteTimeArtifact.Xss1);
        Assert.Equal(2U, Assert.Throws<DeepIdV2RouteNotBeforeException>(final.ThrowIfPending).RequiredDelaySeconds);

        var converged = new DeepIdV2RouteNotBeforeWindow(104, 109);
        foreach (var artifact in new[] { DeepIdV2RouteTimeArtifact.Pms2, DeepIdV2RouteTimeArtifact.Xrc1, DeepIdV2RouteTimeArtifact.Xss1 })
            converged.Require(104, 200, artifact);
        Assert.Null(Record.Exception(converged.ThrowIfPending));
    }

    [Fact]
    public void CurrentAuthorityAndOtherArtifactsCannotOptIntoDeferredCoverage()
    {
        foreach (var artifact in Enum.GetValues<DeepIdV2RouteTimeArtifact>().Where(value =>
            value is not (DeepIdV2RouteTimeArtifact.Pms2 or DeepIdV2RouteTimeArtifact.Xrc1 or DeepIdV2RouteTimeArtifact.Xss1)))
            Assert.Throws<ArgumentOutOfRangeException>(() => new DeepIdV2RouteNotBeforeWindow(100, 105)
                .Require(101, 200, artifact));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DeepIdV2RouteNotBeforeWindow(100, 105)
            .Require(101, 200, (DeepIdV2RouteTimeArtifact)99));
    }

    [Fact]
    public void RelativeSecondsPreserveIntegerBoundsWithoutClockValuesInHint()
    {
        var window = new DeepIdV2RouteNotBeforeWindow(ulong.MaxValue - 6, ulong.MaxValue - 1);
        window.Require(ulong.MaxValue - 2, ulong.MaxValue, DeepIdV2RouteTimeArtifact.Pms2);
        var hint = Assert.Throws<DeepIdV2RouteNotBeforeException>(window.ThrowIfPending);
        Assert.Equal(4U, hint.RequiredDelaySeconds);
        Assert.DoesNotContain((ulong.MaxValue - 6).ToString(), hint.Message);
        Assert.Empty(hint.Data);
    }

    [Fact]
    public void UnrepresentableRelativeDurationFailsClosedInsteadOfTruncating()
    {
        var window = new DeepIdV2RouteNotBeforeWindow(1, (ulong)uint.MaxValue + 2);
        window.Require((ulong)uint.MaxValue + 2, (ulong)uint.MaxValue + 3, DeepIdV2RouteTimeArtifact.Pms2);
        Assert.Throws<CryptographicException>(window.ThrowIfPending);
    }

    [Fact]
    public void PublicHintHasNoConstructionOrAuthorityTimeOverrideSurface()
    {
        Assert.Empty(typeof(DeepIdV2RouteNotBeforeException).GetConstructors());
        var duration = typeof(DeepIdV2RouteNotBeforeException).GetProperty(nameof(DeepIdV2RouteNotBeforeException.RequiredDelaySeconds))!;
        Assert.Equal(typeof(uint), duration.PropertyType); Assert.False(duration.CanWrite);
        Assert.Null(typeof(DeepIdV2RouteNotBeforeException).GetProperty("TrustedLowerUnixSeconds"));
        Assert.Null(typeof(DeepIdV2RouteNotBeforeException).GetProperty("Threshold"));
        var method = Assert.Single(typeof(DeepIdV2ContactRouteVerifier).GetMethods(),
            candidate => candidate.Name == nameof(DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync));
        Assert.DoesNotContain(method.GetParameters(), parameter => parameter.ParameterType == typeof(bool));
    }
}
