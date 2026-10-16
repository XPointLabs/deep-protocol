using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Fixture = Deep.Protocol.Tests.XPointNetworkV1.XPointOnionCapabilityProducerTests.Fixture;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed partial class MailboxHostAuthorityV2VerifierTests
{
    [Theory]
    [InlineData(1024UL, false)]
    [InlineData(1025UL, false)] // upper equals expiry; lower is still below it.
    [InlineData(1034UL, false)]
    [InlineData(1035UL, true)]  // lower equals expiry.
    [InlineData(1036UL, true)]
    public async Task StoreExpiryRequiresAuthenticatedLowerNotUpper(ulong sample, bool excluded)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var clock = new Clock(); var host = await Verify(fixture, input, clock);
        var original = await OriginalExpiryStore(host, input.Network);
        clock.Sample = sample;
        if (excluded) await host.VerifyStoreExpiryExclusionAsync(original);
        else await Assert.ThrowsAsync<CryptographicException>(() => host.VerifyStoreExpiryExclusionAsync(original).AsTask());
        // Exclusion never restores the expired original permission.
        if (sample >= 1025) await Assert.ThrowsAsync<CryptographicException>(() => host.EnsureGrantCurrentAsync(
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(Grant(input.Network))).AsTask());
    }

    [Theory]
    [InlineData("sender-signature")]
    [InlineData("grant-signature")]
    [InlineData("forged-expiry")]
    [InlineData("writer-order")]
    [InlineData("payload")]
    [InlineData("network")]
    public async Task StoreExpiryCannotUseUnauthenticatedOriginal(string defect)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var clock = new Clock(); var host = await Verify(fixture, input, clock);
        var original = await OriginalExpiryStore(host, input.Network, defect);
        clock.Sample = 1035;
        Assert.NotNull(await Record.ExceptionAsync(() => host.VerifyStoreExpiryExclusionAsync(original).AsTask()));
    }

    [Fact]
    public async Task StoreExpiryCapturesInputBeforeClockAndHasNoTrustInputsOrResult()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var clock = new Clock(); var host = await Verify(fixture, input, clock);
        var original = await OriginalExpiryStore(host, input.Network); clock.Sample = 1035;
        clock.OnRead = () => Array.Fill(original, (byte)0);
        await host.VerifyStoreExpiryExclusionAsync(original);
        var api = typeof(VerifiedMailboxHostAuthorityV2).GetMethod(nameof(VerifiedMailboxHostAuthorityV2.VerifyStoreExpiryExclusionAsync))!;
        Assert.Equal(typeof(ValueTask), api.ReturnType);
        Assert.Equal(new[] { typeof(ReadOnlyMemory<byte>), typeof(CancellationToken) },
            api.GetParameters().Select(parameter => parameter.ParameterType));
    }

    [Theory]
    [InlineData("rollback")]
    [InlineData("boot")]
    [InlineData("host-expiry")]
    [InlineData("cancel")]
    public async Task StoreExpiryRechecksCurrentHostAfterAuthentication(string defect)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var clock = new Clock(); var host = await Verify(fixture, input, clock);
        var original = await OriginalExpiryStore(host, input.Network); clock.Sample = 1035;
        using var cancellation = new CancellationTokenSource(); var calls = 0;
        clock.OnRead = () =>
        {
            if (++calls != 2) return;
            if (defect == "rollback") clock.Sample--;
            if (defect == "boot") clock.Boot = Bytes(16, 0xff);
            if (defect == "host-expiry") clock.Sample = 1050;
            if (defect == "cancel") cancellation.Cancel();
        };
        if (defect == "cancel") await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            host.VerifyStoreExpiryExclusionAsync(original, cancellation.Token).AsTask());
        else await Assert.ThrowsAsync<CryptographicException>(() => host.VerifyStoreExpiryExclusionAsync(original).AsTask());
    }

    [Fact]
    public async Task StoreExpiryCannotManufactureMissingSignedHistory()
    {
        var fixture = Fixture.Create(); var history = await fixture.VerifyMailboxHistoryAsync(unchangedEpoch: true);
        var historyHost = await Verify(fixture, history, new Clock { Sample = 1025 });
        var original = await OriginalExpiryStore(historyHost, history.Network);
        var omitted = await fixture.VerifyMailboxAsync();
        var omittedHost = await Verify(fixture, omitted, new Clock { Sample = 1035 });
        await Assert.ThrowsAsync<CryptographicException>(() => omittedHost.VerifyStoreExpiryExclusionAsync(original).AsTask());
    }

    [Fact]
    public async Task StoreExpiryBoundsAndCancellationRejectBeforeClock()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var clock = new Clock(); var host = await Verify(fixture, input, clock); var reads = clock.Reads;
        await Assert.ThrowsAsync<MailboxPeerReplicationException>(() => host.VerifyStoreExpiryExclusionAsync(
            new byte[MailboxPeerWireV2Limits.MaximumRequestLength + 1]).AsTask());
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => host.VerifyStoreExpiryExclusionAsync(
            new byte[1], cancellation.Token).AsTask());
        Assert.Equal(reads, clock.Reads);
    }

    private static async Task<byte[]> OriginalExpiryStore(VerifiedMailboxHostAuthorityV2 host,
        VerifiedOnionNetworkContext network, string? defect = null)
    {
        var grant = Grant(network);
        if (defect == "forged-expiry") grant = grant with { ExpiresAtUnixSeconds = 225 };
        if (defect == "network") grant = grant with { NetworkId = Bytes(16, 0xff) };
        if (defect == "grant-signature") grant = grant with { IssuerSignature = Bytes(64, 0xff) };
        var ids = await host.RankReplicasAsync(grant.SelectionInput);
        var sender = defect == "writer-order" ? 1 : 0; var recipient = 1 - sender;
        byte[] proof = [.. host.ProjectionReference.Span, .. MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)];
        MailboxReplicaMembershipProof Proof(int index) => new()
        {
            ReplicaId = ids[index], SigningPublicKey = network.ResolveNodeIdentityPublicKey(ids[index]),
            Epoch = grant.Epoch, MembershipCommitment = grant.MembershipCommitment, CanonicalInclusionProof = proof
        };
        var envelope = new MailboxEncryptedEnvelope
        {
            Epoch = grant.Epoch, MailboxId = new(Bytes(32, 0x61)), PlacementId = new(Bytes(32, 0x52)),
            OperationId = Bytes(16, 0x62), DeduplicationDigest = Bytes(32, 0x63),
            CreatedAtUnixSeconds = 200, ExpiresAtUnixSeconds = 260, Ciphertext = Bytes(64, 0x64)
        };
        var payload = MailboxClientCodec.EncodeEncryptedEnvelope(envelope);
        var request = new MailboxPeerWireRequestV2
        {
            Operation = MailboxPeerReplicationOperation.Store, Epoch = grant.Epoch, OperationId = envelope.OperationId,
            SenderRouterId = ids[sender], RecipientRouterId = ids[recipient], MembershipCommitment = grant.MembershipCommitment,
            PlacementCommitment = grant.PlacementCommitment, BlindedMailboxId = envelope.MailboxId.Bytes, Cursor = 1,
            CreatedAtUnixSeconds = 200, ExpiresAtUnixSeconds = 260, ReplayNonce = Bytes(32, 0x65),
            Payload = payload, PayloadDigest = SHA256.HashData(payload), SenderMembershipProof = Proof(sender),
            RecipientMembershipProof = Proof(recipient), Signature = ReadOnlyMemory<byte>.Empty
        };
        var seed = Bytes(32, checked((byte)(0x90 + (ids[sender].Span[0] - 0x10) * 8)));
        request = new SodiumMailboxPeerReplicationCrypto().SignRequest(request, seed);
        if (defect == "sender-signature") request = request with { Signature = Bytes(64, 0xff) };
        if (defect == "payload") { payload[^1] ^= 1; request = request with { Payload = payload }; }
        return MailboxPeerWireV2Codec.Encode(request);
    }
}
