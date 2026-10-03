using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Fixture = Deep.Protocol.Tests.XPointNetworkV1.XPointOnionCapabilityProducerTests.Fixture;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class MailboxHostAuthorityV2VerifierTests
{
    [Fact]
    public async Task CurrentSignedNetwork_BindsExactPolicyEpochAndPmsRanking()
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync();
        var clock = new Clock(); var authority = await Verify(fixture, inputs, clock);
        var closure = inputs.Network.Closure!;
        Assert.Equal(closure.Pmt.ArtifactHash.ToArray(), authority.MembershipCommitment.ToArray());
        Assert.Equal(closure.SelectionEpoch, authority.SelectionEpoch);
        var input = Bytes(32, 0xa1);
        var expected = ContactRouteThresholdAuthor.RankReplicas(inputs.Network.NetworkId.Span,
            closure.PmtArtifactReference, closure.Pmt.FieldSpan(6), input,
            closure.Pmt.FieldSpan(9), closure.ReplicaCount);
        var actual = await authority.RankReplicasAsync(input);
        Assert.Equal(expected, actual.SelectMany(item => item.ToArray()).ToArray());
        var replica = await authority.ResolveReplicaAsync(actual[0]);
        Assert.Equal(actual[0].ToArray(), replica.NodeId.ToArray());
        Assert.NotEqual(replica.NodeId.ToArray(), replica.SigningPublicKey.ToArray());
        Assert.Equal(inputs.Network.ResolveNodeIdentityPublicKey(actual[0]).ToArray(), replica.SigningPublicKey.ToArray());
        MemoryMarshal.TryGetArray(replica.NodeId, out var array); array.Array![array.Offset] ^= 1;
        Assert.Equal(actual[0].ToArray(), replica.NodeId.ToArray());
        MemoryMarshal.TryGetArray(authority.MembershipCommitment, out var hash); hash.Array![hash.Offset] ^= 1;
        Assert.Equal(closure.Pmt.ArtifactHash.ToArray(), authority.MembershipCommitment.ToArray());
        Assert.Empty(typeof(VerifiedMailboxHostAuthorityV2).GetConstructors());
        Assert.Empty(typeof(VerifiedMailboxReplicaV2).GetConstructors());
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("foreign-root")]
    [InlineData("unbound-pma")]
    [InlineData("incomplete-network")]
    public async Task Factory_RejectsForeignInvalidOrUnboundAuthority(string mode)
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync();
        var root = fixture.Authority;
        if (mode == "signature") inputs.Pma[^1] ^= 1;
        if (mode == "foreign-root") root = Fixture.Create(networkMarker: 0x22).Authority;
        if (mode == "unbound-pma") inputs.Network = await fixture.VerifyAsync();
        if (mode == "incomplete-network") inputs.Network = new VerifiedOnionNetworkContext(root.NetworkId.Span);
        if (mode == "incomplete-network")
            await Assert.ThrowsAsync<OnionBoundaryException>(() => MailboxHostAuthorityV2Verifier.VerifyAsync(
                inputs.Network, root, inputs.Pma, new(new Clock())).AsTask());
        else
            await Assert.ThrowsAsync<CryptographicException>(() => MailboxHostAuthorityV2Verifier.VerifyAsync(
                inputs.Network, root, inputs.Pma, new(new Clock())).AsTask());
    }

    [Fact]
    public async Task Factory_CapturesPmaBeforeCallbackAndRejectsCancellation()
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync();
        var clock = new Clock { OnRead = () => inputs.Pma[^1] ^= 1 };
        await Verify(fixture, inputs, clock); // Owned before the callback mutates caller bytes.
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        clock.OnRead = null; var count = clock.Reads;
        await Assert.ThrowsAsync<OperationCanceledException>(() => MailboxHostAuthorityV2Verifier.VerifyAsync(
            inputs.Network, fixture.Authority, inputs.Pma, new(clock), cancellation.Token).AsTask());
        Assert.Equal(count, clock.Reads);
    }

    [Theory]
    [InlineData("foreign-boot")]
    [InlineData("rollback")]
    [InlineData("deadline")]
    [InlineData("within-proof-rollback")]
    public async Task LaterUse_RejectsClockDiscontinuityOrExpiry(string mode)
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync();
        var clock = new Clock(); var authority = await Verify(fixture, inputs, clock);
        if (mode == "foreign-boot") clock.Boot = Bytes(16, 0xd1);
        if (mode == "rollback") clock.Sample = 999;
        if (mode == "deadline") clock.Sample = 1_050;
        if (mode == "within-proof-rollback")
        {
            clock.Sample = 1_010; await authority.EnsureCurrentAsync(); clock.Sample = 1_009;
        }
        await Assert.ThrowsAsync<CryptographicException>(() => authority.EnsureCurrentAsync().AsTask());
    }

    [Theory]
    [InlineData("deposit")]
    [InlineData("retrieve")]
    public async Task Grant_VerifiesActualRoleSignatureAndCompleteProofInterval(string role)
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync();
        var clock = new Clock(); var authority = await Verify(fixture, inputs, clock);
        var grant = Grant(inputs.Network, role == "deposit" ? MailboxCapabilityDomain.Deposit : MailboxCapabilityDomain.Retrieve);
        await authority.EnsureGrantCurrentAsync(MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant));
        clock.Sample = 1_025; // upper 230 equals grant expiry; scalar lower would still look valid.
        await Assert.ThrowsAsync<CryptographicException>(() => authority.EnsureGrantCurrentAsync(
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)).AsTask());
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("membership")]
    [InlineData("epoch")]
    [InlineData("generation")]
    [InlineData("future-lower")]
    [InlineData("lifetime")]
    [InlineData("wrong-role-key")]
    [InlineData("overlap")]
    public async Task Grant_RejectsInvalidSignedScopeBeforeAnyConsumerMutation(string mode)
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync();
        var authority = await Verify(fixture, inputs, new Clock()); var grant = Grant(inputs.Network);
        grant = mode switch
        {
            "membership" => grant with { MembershipCommitment = Bytes(32, 0xff) },
            "epoch" => grant with { Epoch = grant.Epoch + 1 },
            "generation" => grant with { Generation = 4 },
            "future-lower" => grant with { NotBeforeUnixSeconds = 196 },
            "lifetime" => grant with { ExpiresAtUnixSeconds = 251 },
            "wrong-role-key" => grant with { Domain = MailboxCapabilityDomain.Retrieve },
            "overlap" => grant with { Lifecycle = MailboxCapabilityLifecycle.Overlap, OverlapUntilUnixSeconds = 220 },
            _ => grant,
        };
        grant = new SodiumMailboxCapabilityCrypto().SignGrant(grant, Bytes(32, 0xe1));
        if (mode == "signature")
        { var signature = grant.IssuerSignature.ToArray(); signature[^1] ^= 1; grant = grant with { IssuerSignature = signature }; }
        await Assert.ThrowsAsync<CryptographicException>(() => authority.EnsureGrantCurrentAsync(
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)).AsTask());
    }

    [Fact]
    public async Task Release_RechecksClockAndCopiedSelectionInput()
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync();
        var clock = new Clock(); var authority = await Verify(fixture, inputs, clock);
        var input = Bytes(32, 0xaa); var baseline = await authority.RankReplicasAsync(input);
        clock.OnRead = () => Array.Fill(input, (byte)0xbb);
        var actual = await authority.RankReplicasAsync(input);
        Assert.Equal(baseline.SelectMany(x => x.ToArray()), actual.SelectMany(x => x.ToArray()));
        clock.OnRead = () => { if (clock.Reads % 2 == 0) clock.Sample = 1_050; };
        await Assert.ThrowsAsync<CryptographicException>(() => authority.EnsureGrantCurrentAsync(
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(Grant(inputs.Network))).AsTask());
    }

    private static ValueTask<VerifiedMailboxHostAuthorityV2> Verify(Fixture fixture,
        (VerifiedOnionNetworkContext Network, byte[] Pma) inputs, Clock clock) =>
        MailboxHostAuthorityV2Verifier.VerifyAsync(inputs.Network, fixture.Authority, inputs.Pma, new(clock));

    [Fact]
    public async Task InvalidBoundsAndSelection_RejectBeforeClockCallback()
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync(); var clock = new Clock();
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxHostAuthorityV2Verifier.VerifyAsync(
            inputs.Network, fixture.Authority, new byte[1_170], new(clock)).AsTask());
        Assert.Equal(0, clock.Reads);
        var authority = await Verify(fixture, inputs, clock); var count = clock.Reads;
        await Assert.ThrowsAsync<ArgumentException>(() => authority.RankReplicasAsync(new byte[32]).AsTask());
        await Assert.ThrowsAsync<ArgumentException>(() => authority.ResolveReplicaAsync(new byte[33]).AsTask());
        await Assert.ThrowsAsync<MailboxAuthenticatedCapabilityException>(() => authority.EnsureGrantCurrentAsync(new byte[273]).AsTask());
        Assert.Equal(count, clock.Reads);
        await Assert.ThrowsAsync<CryptographicException>(() => authority.ResolveReplicaAsync(Bytes(32, 0xff)).AsTask());
    }

    [Fact]
    public async Task Factory_RejectsRollbackDuringFinalRelease()
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync();
        var clock = new Clock(); clock.OnRead = () => { if (clock.Reads == 2) clock.Sample = 999; };
        await Assert.ThrowsAsync<CryptographicException>(() => Verify(fixture, inputs, clock).AsTask());
    }

    [Fact]
    public async Task ClockCallbackCancellation_PreventsAuthorityRelease()
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync();
        using var cancellation = new CancellationTokenSource(); var clock = new Clock { OnRead = cancellation.Cancel };
        await Assert.ThrowsAsync<OperationCanceledException>(() => MailboxHostAuthorityV2Verifier.VerifyAsync(
            inputs.Network, fixture.Authority, inputs.Pma, new(clock), cancellation.Token).AsTask());
    }

    [Fact]
    public async Task Grant_CapturesExactBytesBeforeClockCallback()
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync(); var clock = new Clock();
        var authority = await Verify(fixture, inputs, clock);
        var exact = MailboxAuthenticatedCapabilityCodec.EncodeGrant(Grant(inputs.Network));
        clock.OnRead = () => exact[^1] ^= 1;
        await authority.EnsureGrantCurrentAsync(exact);
    }

    private static MailboxAuthenticatedGrant Grant(VerifiedOnionNetworkContext network,
        MailboxCapabilityDomain domain = MailboxCapabilityDomain.Deposit)
    {
        var seed = Bytes(32, domain == MailboxCapabilityDomain.Deposit ? (byte)0xe1 : (byte)0xe2);
        var grant = new MailboxAuthenticatedGrant
        {
            Domain = domain, Lifecycle = MailboxCapabilityLifecycle.Active,
            NetworkId = network.NetworkId, Epoch = network.Closure!.SelectionEpoch,
            Generation = 5, Serial = Bytes(16, 0x51), NotBeforeUnixSeconds = 190,
            ExpiresAtUnixSeconds = 230, OverlapUntilUnixSeconds = 0,
            PlacementCommitment = MailboxPlacementCommitment.Compute(new(Bytes(32, 0x52))),
            MembershipCommitment = network.Closure.Pmt.ArtifactHash,
            IssuerPublicKey = PublicKeyAuth.GenerateKeyPair(seed).PublicKey,
            HolderPublicKey = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x53)).PublicKey,
            IssuerSignature = new byte[64],
        };
        return new SodiumMailboxCapabilityCrypto().SignGrant(grant, seed);
    }
    private sealed class Clock : IOnionMonotonicClock
    {
        internal byte[] Boot = Bytes(16, 0xc1);
        internal ulong Sample = 1_000;
        internal int Reads;
        internal Action? OnRead;
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); Reads++; OnRead?.Invoke(); return ValueTask.FromResult(new OnionMonotonicReading(Boot, Sample)); }
    }
    private static byte[] Bytes(int length, byte marker) => Enumerable.Repeat(marker, length).ToArray();
}
