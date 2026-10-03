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
        var descriptor = inputs.Network.ResolveNode(actual[0].Span);
        Assert.Equal(replica.NodeId.ToArray(), replica.Transport.NodeId.ToArray());
        Assert.Equal(inputs.Network.NetworkId.ToArray(), replica.Transport.NetworkId.ToArray());
        Assert.Equal(descriptor.OriginAddress, replica.Transport.Address.ToArray());
        Assert.Equal(descriptor.OriginPort, replica.Transport.Port);
        Assert.Equal(descriptor.OriginSpki, replica.Transport.SpkiSha256.ToArray());
        MemoryMarshal.TryGetArray(replica.Transport.SpkiSha256, out var pin); pin.Array![pin.Offset] ^= 1;
        Assert.Equal(descriptor.OriginSpki, replica.Transport.SpkiSha256.ToArray());
        MemoryMarshal.TryGetArray(replica.NodeId, out var array); array.Array![array.Offset] ^= 1;
        Assert.Equal(actual[0].ToArray(), replica.NodeId.ToArray());
        MemoryMarshal.TryGetArray(authority.MembershipCommitment, out var hash); hash.Array![hash.Offset] ^= 1;
        Assert.Equal(closure.Pmt.ArtifactHash.ToArray(), authority.MembershipCommitment.ToArray());
        Assert.Empty(typeof(VerifiedMailboxHostAuthorityV2).GetConstructors());
        Assert.Empty(typeof(VerifiedMailboxReplicaV2).GetConstructors());
    }

    [Fact]
    public async Task SelectedGrant_UsesSignedSelectorAndActualDescriptorKeys()
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync();
        var clock = new Clock(); var authority = await Verify(fixture, inputs, clock);
        var grant = Grant(inputs.Network);
        var exact = MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant);
        var expected = await authority.RankReplicasAsync(grant.SelectionInput);
        clock.OnRead = () => Array.Fill(exact, (byte)0); // Decoder owns bytes before callbacks.
        var selected = await authority.ResolveGrantReplicasAsync(exact);
        Assert.Equal(2, selected.Count);
        Assert.Equal(expected.SelectMany(id => id.ToArray()), selected.SelectMany(replica => replica.NodeId.ToArray()));
        foreach (var replica in selected)
        {
            Assert.Equal(inputs.Network.ResolveNodeIdentityPublicKey(replica.NodeId).ToArray(), replica.SigningPublicKey.ToArray());
            Assert.Equal(replica.NodeId.ToArray(), replica.Transport.NodeId.ToArray());
            Assert.Equal(inputs.Network.ResolveNode(replica.NodeId.Span).OriginSpki, replica.Transport.SpkiSha256.ToArray());
        }
        clock.OnRead = null;
        var changed = grant with { SelectionInput = Bytes(32, 0xf1) };
        await Assert.ThrowsAsync<CryptographicException>(() => authority.ResolveGrantReplicasAsync(
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(changed)).AsTask());
    }

    [Fact]
    public async Task SelectedGrant_RechecksFullIntervalBeforeReleasingReplicas()
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync();
        var clock = new Clock(); var authority = await Verify(fixture, inputs, clock);
        var before = clock.Reads;
        clock.OnRead = () => { if (clock.Reads == before + 2) clock.Sample = 1_025; };
        await Assert.ThrowsAsync<CryptographicException>(() => authority.ResolveGrantReplicasAsync(
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(Grant(inputs.Network))).AsTask());
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
    public async Task StoreSettlementHasOnlyClosedInputsAndRejectsHostileSizeBeforeClock()
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync(); var clock = new Clock();
        var host = await Verify(fixture, inputs, clock); var count = clock.Reads;
        await Assert.ThrowsAsync<MailboxPeerReplicationException>(() => host.VerifyStoreSettlementAsync(
            new byte[MailboxPeerWireV2Limits.MaximumRequestLength + 1], new byte[1]).AsTask());
        Assert.Equal(count, clock.Reads);
        var api = typeof(VerifiedMailboxHostAuthorityV2).GetMethod(nameof(VerifiedMailboxHostAuthorityV2.VerifyStoreSettlementAsync))!;
        Assert.Equal(typeof(ValueTask), api.ReturnType);
        Assert.Equal(new[] { typeof(ReadOnlyMemory<byte>), typeof(ReadOnlyMemory<byte>), typeof(CancellationToken) },
            api.GetParameters().Select(parameter => parameter.ParameterType));
    }

    [Theory]
    [InlineData("body")]
    [InlineData("quorum-profile")]
    [InlineData("grant-version")]
    public async Task StoreSettlementRejectsMalformedInnerGrammarBeforeClock(string defect)
    {
        var fixture = Fixture.Create(); var inputs = await fixture.VerifyMailboxAsync(); var clock = new Clock();
        var host = await Verify(fixture, inputs, clock); var grant = Grant(inputs.Network);
        var ids = await host.RankReplicasAsync(grant.SelectionInput);
        var payload = MailboxClientCodec.EncodeEncryptedEnvelope(new()
        {
            Epoch = grant.Epoch, MailboxId = new(Bytes(32, 0x61)), PlacementId = new(Bytes(32, 0x52)),
            OperationId = Bytes(16, 0x62), DeduplicationDigest = Bytes(32, 0x63),
            CreatedAtUnixSeconds = 200, ExpiresAtUnixSeconds = 260, Ciphertext = Bytes(64, 0x64)
        });
        byte[] proof = [.. host.ProjectionReference.Span, .. MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)];
        if (defect == "body") payload[4] = 0xff;
        if (defect == "grant-version") proof[38 + 4] = 0xff;
        MailboxReplicaMembershipProof Membership(int index) => new()
        {
            ReplicaId = ids[index], SigningPublicKey = inputs.Network.ResolveNodeIdentityPublicKey(ids[index]),
            Epoch = grant.Epoch, MembershipCommitment = host.MembershipCommitment, CanonicalInclusionProof = proof
        };
        var request = MailboxPeerWireV2Codec.Encode(new()
        {
            Operation = MailboxPeerReplicationOperation.Store, Epoch = grant.Epoch, OperationId = Bytes(16, 0x62),
            SenderRouterId = ids[0], RecipientRouterId = ids[1], MembershipCommitment = host.MembershipCommitment,
            PlacementCommitment = grant.PlacementCommitment, BlindedMailboxId = Bytes(32, 0x61), Cursor = 1,
            CreatedAtUnixSeconds = 200, ExpiresAtUnixSeconds = 260, ReplayNonce = Bytes(32, 0x65),
            Payload = payload, PayloadDigest = SHA256.HashData(payload), SenderMembershipProof = Membership(0),
            RecipientMembershipProof = Membership(1), Signature = Bytes(64, 0x66)
        });
        // No positive crypto claim: grammar must reject before signature/time.
        // For the malformed grant case, provide an actual structurally valid
        // MQR3 so its decoder cannot mask the grant-version assertion.
        var quorum = new byte[1];
        if (defect is "grant-version" or "quorum-profile")
        {
            MailboxReplicaReceiptV2 Receipt(int index) => new()
            {
                OperationId = Bytes(16, 0x62), ReplicaId = ids[index], Epoch = grant.Epoch, Cursor = 1,
                BlindedMailboxId = Bytes(32, 0x61), PlacementCommitment = grant.PlacementCommitment,
                MembershipCommitment = host.MembershipCommitment, EnvelopeDigest = Bytes(32, 0x63),
                AcceptedAtUnixSeconds = 200, DurableAtUnixSeconds = 200, ExpiresAtUnixSeconds = 260,
                Status = MailboxReceiptStatus.Durable, Disposition = MailboxReplicaDisposition.Stored,
                Signature = Bytes(64, 0x66)
            };
            quorum = MailboxReceiptV3Codec.EncodeDurableQuorum(new()
            {
                CoordinatorId = ids[0], CoordinatorSequence = 1, FirstReplica = Receipt(0),
                SecondReplica = Receipt(1), Signature = Bytes(defect == "quorum-profile" ? 32 : 64, 0x66)
            });
        }
        var reads = clock.Reads;
        Assert.NotNull(await Record.ExceptionAsync(() => host.VerifyStoreSettlementAsync(request, quorum).AsTask()));
        Assert.Equal(reads, clock.Reads);
    }

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
            SelectionInput = Bytes(32, 0x54),
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
