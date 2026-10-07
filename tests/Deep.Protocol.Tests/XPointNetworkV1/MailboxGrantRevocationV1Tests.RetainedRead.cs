using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Fixture = Deep.Protocol.Tests.XPointNetworkV1.XPointOnionCapabilityProducerTests.Fixture;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed partial class MailboxGrantRevocationV1Tests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RetainedReadRevocation_RequiresCurrentRetrieveIssuerAndExactProtectedFloor(bool cold)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync(cold);
        var host = await Host(fixture, input, new Clock { Sample = 1_025 });
        var snapshot = Snapshot(input.Pma, MailboxCapabilityDomain.Retrieve, issued: 215,
            expires: 260, serials: [Bytes(16, 0x51)]);
        var plan = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, snapshot);
        var floor = new Floor(plan, host.NetworkId);
        var committed = await MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, floor.Exact, floor);
        var exact = RetainedReadGrantBytes(input.Network, 0x52);
        await committed.EnsureRetainedReadGrantNotRevokedAsync(exact);
        await Assert.ThrowsAsync<CryptographicException>(() => committed.EnsureGrantNotRevokedAsync(exact).AsTask());
        await Assert.ThrowsAsync<CryptographicException>(() => committed.EnsureRetainedReadGrantNotRevokedAsync(
            RetainedReadGrantBytes(input.Network, 0x51)).AsTask());
    }

    [Theory]
    [InlineData("missing-floor")]
    [InlineData("changed-floor")]
    [InlineData("second-floor")]
    [InlineData("clock-rollback")]
    [InlineData("grant-expiry")]
    [InlineData("snapshot-expiry")]
    [InlineData("cancel")]
    public async Task RetainedReadRevocation_RechecksCurrentFloorAndClockAcrossCallback(string defect)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var clock = new Clock { Sample = 1_025 }; var host = await Host(fixture, input, clock);
        var snapshot = Snapshot(input.Pma, MailboxCapabilityDomain.Retrieve, issued: 215,
            expires: defect == "snapshot-expiry" ? 235UL : 260UL);
        var plan = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, snapshot);
        var floor = new Floor(plan, host.NetworkId);
        var committed = await MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, floor.Exact, floor);
        using var cancellation = new CancellationTokenSource(); var reads = 0;
        floor.OnRead = () =>
        {
            reads++;
            if (defect == "missing-floor") floor.Hash = ReadOnlyMemory<byte>.Empty;
            if (defect == "changed-floor" || defect == "second-floor" && reads == 2) floor.Hash = Bytes(32, 0xff);
            if (defect == "clock-rollback") clock.Sample = 1_024;
            if (defect == "grant-expiry") clock.Sample = 1_050;
            if (defect == "snapshot-expiry") clock.Sample = 1_030;
            if (defect == "cancel") cancellation.Cancel();
        };
        var task = committed.EnsureRetainedReadGrantNotRevokedAsync(RetainedReadGrantBytes(input.Network, 0x52),
            cancellation.Token).AsTask();
        if (defect == "cancel") await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        else await Assert.ThrowsAsync<CryptographicException>(() => task);
    }

    [Fact]
    public async Task RetainedReadRevocation_CapturesGrantBeforeProtectedFloorCallback()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var host = await Host(fixture, input, new Clock { Sample = 1_025 });
        var snapshot = Snapshot(input.Pma, MailboxCapabilityDomain.Retrieve, issued: 215, expires: 260);
        var plan = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, snapshot);
        var floor = new Floor(plan, host.NetworkId);
        var committed = await MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, floor.Exact, floor);
        var exact = RetainedReadGrantBytes(input.Network, 0x52);
        floor.OnRead = () => exact[^1] ^= 1;
        await committed.EnsureRetainedReadGrantNotRevokedAsync(exact);
    }

    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)]
    [InlineData(MailboxCapabilityDomain.Retrieve)]
    public async Task RetainedReadRevocation_CannotCrossFeedRoleOrInventOmittedHistory(MailboxCapabilityDomain role)
    {
        var fixture = Fixture.Create(); var retained = await fixture.VerifyMailboxHistoryAsync();
        var omitted = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, omitted, new Clock { Sample = 1_025 });
        var plan = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host,
            Snapshot(omitted.Pma, role, issued: 215, expires: 260));
        var floor = new Floor(plan, host.NetworkId);
        var committed = await MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, floor.Exact, floor);
        await Assert.ThrowsAsync<CryptographicException>(() => committed.EnsureRetainedReadGrantNotRevokedAsync(
            RetainedReadGrantBytes(retained.Network, 0x52)).AsTask());
    }

    private static byte[] RetainedReadGrantBytes(VerifiedOnionNetworkContext network, byte serial)
    {
        var original = MailboxAuthenticatedCapabilityCodec.DecodeGrant(Grant(network, MailboxCapabilityDomain.Retrieve, serial));
        var projection = network.Closure!.RetainedPmts[0];
        var grant = new SodiumMailboxCapabilityCrypto().SignGrant(original with
        {
            Epoch = BinaryPrimitives.ReadUInt64BigEndian(projection.FieldSpan(6)),
            MembershipCommitment = projection.ArtifactHash,
            NotBeforeUnixSeconds = 215, ExpiresAtUnixSeconds = 250,
        }, Bytes(32, 0xe2));
        return MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant);
    }
}
