using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Fixture = Deep.Protocol.Tests.XPointNetworkV1.XPointOnionCapabilityProducerTests.Fixture;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed partial class MailboxHostAuthorityV2VerifierTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task RetainedRead_UsesActualSignedLineageAndCurrentDescriptorsAfterOldProjectionExpiry(
        bool cold, bool unchangedEpoch)
    {
        var fixture = Fixture.Create();
        var input = await fixture.VerifyMailboxHistoryAsync(cold, unchangedEpoch);
        var clock = new Clock { Sample = 1_025 };
        var host = await Verify(fixture, input, clock);
        var old = input.Network.Closure!.RetainedPmts[0];
        Assert.Equal(3, input.Network.Closure.RetainedPmts.Length);
        Assert.True(BinaryPrimitives.ReadUInt64BigEndian(old.FieldSpan(12)) < 220);
        var exact = MailboxAuthenticatedCapabilityCodec.EncodeGrant(RetainedReadGrant(input.Network));
        await Assert.ThrowsAsync<CryptographicException>(() => host.EnsureGrantCurrentAsync(exact).AsTask());
        await Assert.ThrowsAsync<CryptographicException>(() => host.ResolveGrantReplicasAsync(exact).AsTask());
        var result = await host.GetSelectedRetainedReadReplicasAsync(exact);
        var expected = ContactRouteThresholdAuthor.RankReplicas(input.Network.NetworkId.Span,
            ContactCodec.ArtifactReference("PMT2", old).CanonicalBytes.Span, old.FieldSpan(6),
            Bytes(32, 0x54), old.FieldSpan(9), 2);
        Assert.Equal(2, result.Count);
        Assert.Equal(expected, result.SelectMany(node => node.NodeId.ToArray()).ToArray());
        foreach (var replica in result)
            Assert.Equal(input.Network.ResolveNodeIdentityPublicKey(replica.NodeId).ToArray(), replica.SigningPublicKey.ToArray());
        // An expired original credential is not revived by retained selection.
        var expired = Resign(RetainedReadGrant(input.Network) with { NotBeforeUnixSeconds = 190, ExpiresAtUnixSeconds = 230 });
        await Assert.ThrowsAsync<CryptographicException>(() => host.GetSelectedRetainedReadReplicasAsync(
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(expired)).AsTask());
    }

    [Theory]
    [InlineData("deposit")]
    [InlineData("membership")]
    [InlineData("epoch")]
    [InlineData("network")]
    [InlineData("generation")]
    [InlineData("future-start")]
    [InlineData("expired")]
    [InlineData("issuer")]
    [InlineData("signature")]
    [InlineData("overlap")]
    [InlineData("lifetime")]
    [InlineData("network-expiry")]
    public async Task RetainedRead_RejectsInvalidGrantWithoutRelaxingIssuerTimeOrSelection(string defect)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var clock = new Clock { Sample = 1_025 }; var host = await Verify(fixture, input, clock);
        var grant = RetainedReadGrant(input.Network);
        grant = defect switch
        {
            "deposit" => grant with { Domain = MailboxCapabilityDomain.Deposit },
            "membership" => grant with { MembershipCommitment = Bytes(32, 0xff) },
            "epoch" => grant with { Epoch = grant.Epoch + 1 },
            "network" => grant with { NetworkId = Bytes(16, 0xff) },
            "generation" => grant with { Generation = 4 },
            "future-start" => grant with { NotBeforeUnixSeconds = 225 },
            "expired" => grant with { ExpiresAtUnixSeconds = 230 },
            "issuer" => grant with { IssuerPublicKey = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xe1)).PublicKey },
            "overlap" => grant with { Lifecycle = MailboxCapabilityLifecycle.Overlap, OverlapUntilUnixSeconds = 240 },
            "lifetime" => grant with { ExpiresAtUnixSeconds = 280 },
            "network-expiry" => grant with { ExpiresAtUnixSeconds = 301 },
            _ => grant,
        };
        grant = defect == "issuer"
            ? new SodiumMailboxCapabilityCrypto().SignGrant(grant, Bytes(32, 0xe1))
            : Resign(grant);
        if (defect == "signature")
        {
            var signature = grant.IssuerSignature.ToArray(); signature[0] ^= 1;
            grant = grant with { IssuerSignature = signature };
        }
        var before = clock.Reads;
        await Assert.ThrowsAsync<CryptographicException>(() => host.GetSelectedRetainedReadReplicasAsync(
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)).AsTask());
        if (defect == "deposit") Assert.Equal(before, clock.Reads);
    }

    [Fact]
    public async Task RetainedRead_CannotManufactureAbsentHistoryWithASignedGrant()
    {
        var fixture = Fixture.Create(); var history = await fixture.VerifyMailboxHistoryAsync();
        var omitted = await fixture.VerifyMailboxAsync();
        var host = await Verify(fixture, omitted, new Clock());
        var exact = MailboxAuthenticatedCapabilityCodec.EncodeGrant(RetainedReadGrant(history.Network));
        await Assert.ThrowsAsync<CryptographicException>(() => host.GetSelectedRetainedReadReplicasAsync(exact).AsTask());
        Assert.Single(omitted.Network.Closure!.RetainedPmts);
    }

    [Fact]
    public async Task RetainedRead_CapturesGrantBeforeClockCallback()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var clock = new Clock { Sample = 1_025 }; var host = await Verify(fixture, input, clock);
        var exact = MailboxAuthenticatedCapabilityCodec.EncodeGrant(RetainedReadGrant(input.Network));
        clock.OnRead = () => exact[^1] ^= 1;
        Assert.Equal(2, (await host.GetSelectedRetainedReadReplicasAsync(exact)).Count);
    }

    [Fact]
    public async Task RetainedRead_TerminalOnlyRehydrationDoesNotMintMissingEarlierSelection()
    {
        var fixture = Fixture.Create();
        // The complete producer rejects omitted signed history even earlier:
        // it never mints a current context from this terminal-only tuple.
        var failure = await Assert.ThrowsAsync<OnionBoundaryException>(() =>
            fixture.VerifyMailboxHistoryAsync(terminalOnly: true).AsTask());
        Assert.Equal("network-genesis-required", failure.Code);
    }

    [Fact]
    public async Task RetainedRead_CannotRerankAroundAnActuallyRemovedMailboxReplica()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync(removedMailboxNode: 0);
        var host = await Verify(fixture, input, new Clock { Sample = 1_025 });
        var old = input.Network.Closure!.RetainedPmts[0];
        var removedId = Bytes(32, 0x10); MailboxAuthenticatedGrant? selected = null;
        for (byte marker = 1; marker < 100; marker++)
        {
            var candidate = Resign(RetainedReadGrant(input.Network) with { SelectionInput = Bytes(32, marker) });
            var ranked = ContactRouteThresholdAuthor.RankReplicas(input.Network.NetworkId.Span,
                ContactCodec.ArtifactReference("PMT2", old).CanonicalBytes.Span, old.FieldSpan(6),
                candidate.SelectionInput.Span, old.FieldSpan(9), 2);
            if (ranked.AsSpan(0, 32).SequenceEqual(removedId) || ranked.AsSpan(32, 32).SequenceEqual(removedId))
            { selected = candidate; break; }
        }
        Assert.NotNull(selected);
        Assert.DoesNotContain(input.Network.Closure.PmtNodeIds, id => id.AsSpan().SequenceEqual(removedId));
        await Assert.ThrowsAsync<CryptographicException>(() => host.GetSelectedRetainedReadReplicasAsync(
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(selected)).AsTask());
        var current = Resign(Grant(input.Network, MailboxCapabilityDomain.Retrieve) with
            { NotBeforeUnixSeconds = 215, ExpiresAtUnixSeconds = 250 });
        Assert.Equal(2, (await host.ResolveGrantReplicasAsync(MailboxAuthenticatedCapabilityCodec.EncodeGrant(current))).Count);
    }

    [Theory]
    [InlineData("expiry")]
    [InlineData("rollback")]
    [InlineData("boot")]
    [InlineData("cancel")]
    public async Task RetainedRead_RechecksBeforeReleasingFacts(string defect)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var clock = new Clock { Sample = 1_025 }; var host = await Verify(fixture, input, clock);
        using var cancellation = new CancellationTokenSource();
        var reads = 0;
        clock.OnRead = () =>
        {
            if (++reads != 2) return;
            if (defect == "expiry") clock.Sample = 1_050;
            if (defect == "rollback") clock.Sample = 1_024;
            if (defect == "boot") clock.Boot = Bytes(16, 0xff);
            if (defect == "cancel") cancellation.Cancel();
        };
        var task = host.GetSelectedRetainedReadReplicasAsync(
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(RetainedReadGrant(input.Network)), cancellation.Token).AsTask();
        if (defect == "cancel") await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        else await Assert.ThrowsAsync<CryptographicException>(() => task);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(303)]
    [InlineData(305)]
    public async Task RetainedRead_RejectsHostileLengthBeforeClock(int length)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var clock = new Clock(); var host = await Verify(fixture, input, clock); var before = clock.Reads;
        await Assert.ThrowsAsync<MailboxAuthenticatedCapabilityException>(() => host.GetSelectedRetainedReadReplicasAsync(new byte[length]).AsTask());
        Assert.Equal(before, clock.Reads);
    }

    private static MailboxAuthenticatedGrant RetainedReadGrant(
        Deep.Protocol.DeepExtension.PrivacyRouting.VerifiedOnionNetworkContext network)
    {
        var old = network.Closure!.RetainedPmts[0];
        return Resign(Grant(network, MailboxCapabilityDomain.Retrieve) with
        {
            Epoch = BinaryPrimitives.ReadUInt64BigEndian(old.FieldSpan(6)),
            MembershipCommitment = old.ArtifactHash,
            NotBeforeUnixSeconds = 215, ExpiresAtUnixSeconds = 250,
        });
    }

    private static MailboxAuthenticatedGrant Resign(MailboxAuthenticatedGrant grant) =>
        new SodiumMailboxCapabilityCrypto().SignGrant(grant, Bytes(32, 0xe2));
}
