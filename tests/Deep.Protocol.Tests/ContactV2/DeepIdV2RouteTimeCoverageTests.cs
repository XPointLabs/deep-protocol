using System.Security.Cryptography;
using Deep.Protocol.ContactV2;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2RouteTimeCoverageTests
{
    public static IEnumerable<object[]> Artifacts => Enum.GetValues<DeepIdV2RouteTimeArtifact>()
        .Select(value => new object[] { (int)value });

    [Theory]
    [MemberData(nameof(Artifacts))]
    public void Every_closed_label_preserves_complete_interval_check(int value)
    {
        var artifact = (DeepIdV2RouteTimeArtifact)value;
        DeepIdV2RouteTimeCoverage.Require(100, 105, 100, 106, artifact);
        var early = Assert.Throws<CryptographicException>(() =>
            DeepIdV2RouteTimeCoverage.Require(100, 105, 101, 106, artifact));
        var expired = Assert.Throws<CryptographicException>(() =>
            DeepIdV2RouteTimeCoverage.Require(100, 105, 100, 105, artifact));
        var inverted = Assert.Throws<CryptographicException>(() =>
            DeepIdV2RouteTimeCoverage.Require(106, 105, 100, 107, artifact));
        Assert.EndsWith("; NotBefore).", early.Message);
        Assert.EndsWith("; Expiry).", expired.Message);
        Assert.EndsWith("; InvalidInterval).", inverted.Message);
        foreach (var message in new[] { early.Message, expired.Message, inverted.Message })
        {
            Assert.StartsWith("DID2 route time coverage failed (", message);
            Assert.DoesNotContain("100", message);
            Assert.DoesNotContain("105", message);
            Assert.True(message.Length < 96);
        }
    }

    [Fact]
    public void Exclusive_expiry_and_maximum_integer_bounds_are_unchanged()
    {
        DeepIdV2RouteTimeCoverage.Require(ulong.MaxValue - 2, ulong.MaxValue - 1,
            ulong.MaxValue - 2, ulong.MaxValue, DeepIdV2RouteTimeArtifact.Xra1);
        var error = Assert.Throws<CryptographicException>(() =>
            DeepIdV2RouteTimeCoverage.Require(ulong.MaxValue, ulong.MaxValue,
                0, ulong.MaxValue, DeepIdV2RouteTimeArtifact.Xra1));
        Assert.Equal("DID2 route time coverage failed (XRA1; Expiry).", error.Message);
    }

    [Fact]
    public void Unknown_labels_reject_even_when_the_interval_would_pass() =>
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            DeepIdV2RouteTimeCoverage.Require(100, 105, 100, 106, (DeepIdV2RouteTimeArtifact)99));
}
