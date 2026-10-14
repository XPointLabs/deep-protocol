using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed partial class XPointNetworkAuthorityVerifierTests
{
    [Theory]
    [InlineData(1_000UL)] [InlineData(1_001UL)] [InlineData(2_000UL)]
    public void Verify_OfflineRootContinuityAfterExpiryKeepsPredecessorThresholdAndExactHistory(ulong issuedAt)
    {
        var fixture = AuthorityFixture.Create();
        var next = fixture.BuildPair(1, fixture.Genesis.CoreHash, 1, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Genesis.Roots,
            window: new(issuedAt, issuedAt, issuedAt + 1_000, issuedAt, issuedAt + 500));
        var verified = XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna, next.Xna], [fixture.Genesis.Dts, next.Dts]);
        Assert.Equal(issuedAt, verified.IssuedAt);
        Assert.Equal(issuedAt, verified.NotBefore);
        Assert.Equal(1UL, verified.AuthorityGeneration);
        Assert.Equal(1UL, verified.Dts1PolicyGeneration);
        Assert.Equal(fixture.Genesis.CoreHash, verified.AuthorityChain[0].CoreHash.ToArray());
        Assert.Equal(1_000UL, verified.AuthorityChain[0].ExpiresAt);
        Assert.Equal(fixture.Successor.Roots.Select(key => key.Key.PublicKey),
            verified.RootKeys.Select(key => key.Ed25519PublicKey.ToArray()));

        // The successor's root set cannot authorize its own transition, even
        // after predecessor expiry. DTS receipts alone do not grant continuity.
        var selfSigned = fixture.BuildPair(1, fixture.Genesis.CoreHash, 1, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Successor.Roots,
            window: new(issuedAt, issuedAt, issuedAt + 1_000, issuedAt, issuedAt + 500));
        Assert.Throws<XPointNetworkAuthorityVerificationException>(() =>
            XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
                [fixture.Genesis.Xna, selfSigned.Xna], [fixture.Genesis.Dts, selfSigned.Dts]));
        var corrupted = next.Xna.ToArray(); corrupted[^1] ^= 1;
        Assert.Throws<XPointNetworkAuthorityVerificationException>(() =>
            XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
                [fixture.Genesis.Xna, corrupted], [fixture.Genesis.Dts, next.Dts]));
        Assert.Throws<XPointNetworkAuthorityVerificationException>(() =>
            XPointNetworkAuthorityVerifier.Verify(fixture.Pin, [next.Xna], [next.Dts]));
    }

    [Fact]
    public void Verify_OfflineRootContinuityStillRejectsBackwardSignedTime()
    {
        var fixture = AuthorityFixture.Create();
        var backward = fixture.BuildPair(1, fixture.Genesis.CoreHash, 1, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Genesis.Roots,
            window: new(99, 100, 1_500, 100, 1_400));
        var error = Assert.Throws<XPointNetworkAuthorityVerificationException>(() =>
            XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
                [fixture.Genesis.Xna, backward.Xna], [fixture.Genesis.Dts, backward.Dts]));
        Assert.Equal("InvalidEffectiveTimeClosure", error.Code);
    }
}
