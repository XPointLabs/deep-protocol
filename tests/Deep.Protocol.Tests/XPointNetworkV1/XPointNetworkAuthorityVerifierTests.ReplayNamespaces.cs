using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed partial class XPointNetworkAuthorityVerifierTests
{
    [Fact]
    public void ReplayNamespaces_UseOnlyExactPairedAncestorsAndReturnDefensiveCopies()
    {
        var fixture = AuthorityFixture.Create();
        var genesis = XPointNetworkAuthorityVerifier.Verify(fixture.Pin, [fixture.Genesis.Xna], [fixture.Genesis.Dts]);
        var current = XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna, fixture.Successor.Xna], [fixture.Genesis.Dts, fixture.Successor.Dts]);
        var before = AccountDirectoryDtt1IssuanceEpoch.Derive(genesis, 300, 1);
        var after = AccountDirectoryDtt1IssuanceEpoch.Derive(current, 300, 1);
        Assert.Equal(new[] { before.Id.ToArray(), after.Id.ToArray() }, after.ReplayNamespaceIds.Select(b => b.ToArray()).ToArray());
        Assert.NotEqual(before.Id.ToArray(), after.Id.ToArray());
        foreach (var id in after.ReplayNamespaceIds) {
            Assert.True(MemoryMarshal.TryGetArray(id, out var segment)); segment.Array!.AsSpan().Fill(0);
        }
        Assert.Equal(before.Id.ToArray(), after.ReplayNamespaceIds[0].ToArray());
        Assert.Equal(after.Id.ToArray(), after.ReplayNamespaceIds[^1].ToArray());
        var fork = fixture.BuildPair(1, fixture.Genesis.CoreHash, 1, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Genesis.Roots, window: new(210, 210, 1_500, 210, 1_400));
        var sibling = XPointNetworkAuthorityVerifier.Verify(fixture.Pin, [fixture.Genesis.Xna, fork.Xna], [fixture.Genesis.Dts, fork.Dts]);
        var siblingEpoch = AccountDirectoryDtt1IssuanceEpoch.Derive(sibling, 300, 1);
        Assert.DoesNotContain(after.ReplayNamespaceIds, b => b.Span.SequenceEqual(siblingEpoch.Id.Span));
        Assert.Single(before.ReplayNamespaceIds); // Cannot explain a future/sibling successor.
    }

    [Fact]
    public void ReplayNamespaces_ExcludeOriginalPoliciesExpiredBeforeTheCurrentUtcDay()
    {
        var (fixture, first, second) = ObjectHorizonAuthorityChain();
        var current = XPointNetworkAuthorityVerifier.Verify(fixture.Pin,
            [fixture.Genesis.Xna, first.Xna, second.Xna], [fixture.Genesis.Dts, first.Dts, second.Dts]);
        var epoch = AccountDirectoryDtt1IssuanceEpoch.Derive(current, 2_680_000, 5);
        Assert.Single(epoch.ReplayNamespaceIds); Assert.Equal(epoch.Id.ToArray(), epoch.ReplayNamespaceIds[0].ToArray());
    }

    [Fact]
    public void ReplayNamespaces_RejectMoreThan64OverlappingSignedPairs()
    {
        var fixture = AuthorityFixture.Create(); var prior = fixture.Genesis;
        var xna = new List<ReadOnlyMemory<byte>> { prior.Xna }; var dts = new List<ReadOnlyMemory<byte>> { prior.Dts };
        for (ulong generation = 1; generation <= 64; generation++) {
            var next = fixture.BuildPair(generation, prior.CoreHash, generation, prior.PolicyHash,
                fixture.Genesis.Roots, fixture.Genesis.Roots, window: new(100 + generation, 100 + generation, 10_000, 100 + generation, 9_000), witnessPolicyGeneration: 0);
            xna.Add(next.Xna); dts.Add(next.Dts); prior = next;
        }
        var atLimit = XPointNetworkAuthorityVerifier.Verify(fixture.Pin, xna.Take(64).ToArray(), dts.Take(64).ToArray());
        Assert.Equal(64, AccountDirectoryDtt1IssuanceEpoch.Derive(atLimit, 500, 1).ReplayNamespaceIds.Count);
        var oversized = XPointNetworkAuthorityVerifier.Verify(fixture.Pin, xna, dts);
        Assert.Throws<CryptographicException>(() => AccountDirectoryDtt1IssuanceEpoch.Derive(oversized, 500, 1));
    }
}
