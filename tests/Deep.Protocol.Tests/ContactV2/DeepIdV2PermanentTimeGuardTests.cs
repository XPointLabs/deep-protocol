using System.Security.Cryptography;
using Deep.Protocol.ContactV2;

namespace Deep.Protocol.Tests.ContactV2;

// Pure predicate/error classification only: no synthetic verified handle,
// signature, current authority, native commit or delivery evidence.
public sealed class DeepIdV2PermanentTimeGuardTests
{
    [Theory]
    [InlineData(100UL, 220UL, 90UL, 230UL, 102UL, 101UL, "Permanent contact trusted interval is inverted.")]
    [InlineData(100UL, 220UL, 90UL, 230UL, 99UL, 101UL, "Permanent read issuance exceeds trusted lower time.")]
    [InlineData(100UL, 220UL, 90UL, 230UL, 100UL, 220UL, "Permanent read expiry does not cover trusted upper time.")]
    [InlineData(100UL, 221UL, 90UL, 230UL, 100UL, 101UL, "Permanent read lifetime exceeds 120 seconds.")]
    [InlineData(100UL, 220UL, 101UL, 230UL, 100UL, 101UL, "Permanent contact object begins after trusted lower time.")]
    [InlineData(100UL, 220UL, 90UL, 101UL, 100UL, 101UL, "Permanent contact object expiry does not cover trusted upper time.")]
    public void ClosedReasonsKeepTheSameRejectingBoundaries(ulong issued, ulong expires,
        ulong objectNotBefore, ulong objectExpires, ulong lower, ulong upper, string reason)
        => Assert.Equal(reason, Assert.Throws<CryptographicException>(() =>
            DeepIdV2PermanentContactResolveVerifier.RequireTimeBounds(
                issued, expires, objectNotBefore, objectExpires, lower, upper)).Message);

    [Fact]
    public void BoundaryGridMatchesTheCurrentPredicateIncludingUnsignedEdges()
    {
        ulong[] values = [0, 1, 119, 120, 121, ulong.MaxValue - 1, ulong.MaxValue];
        foreach (var issued in values)
        foreach (var expires in values)
        foreach (var lower in values)
        foreach (var upper in values)
        {
            // Check object equality on both sides without making object times
            // into caller-supplied verification authority.
            foreach (var objectWindow in new[] { (0UL, ulong.MaxValue), (lower, upper) })
            {
                var rejected = lower > upper || issued > lower || upper >= expires ||
                    expires - issued > 120 || objectWindow.Item1 > lower || upper >= objectWindow.Item2;
                var error = Record.Exception(() => DeepIdV2PermanentContactResolveVerifier.RequireTimeBounds(
                    issued, expires, objectWindow.Item1, objectWindow.Item2, lower, upper));
                if (rejected) Assert.IsType<CryptographicException>(error); else Assert.Null(error);
            }
        }
    }
}
