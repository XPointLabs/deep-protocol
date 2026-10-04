using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Fixture = Deep.Protocol.Tests.XPointNetworkV1.XPointOnionCapabilityProducerTests.Fixture;

namespace Deep.Protocol.Tests.XPointNetworkV1;

/// <summary>Real signed network/role proofs; floor I/O is test-owned memory.
/// This is not native protected-store, node admission or physical delivery evidence.</summary>
public sealed class MailboxGrantRevocationV1Tests
{
    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)]
    [InlineData(MailboxCapabilityDomain.Retrieve)]
    public async Task NewHostCanPinFreshIssuerTailAfterGlobalGenesisExpired(MailboxCapabilityDomain role)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, input, new Clock());
        var expired = Snapshot(input.Pma, role, expires: 195);
        var predecessor = MailboxGrantRevocationV1Codec.Decode(expired);
        var tail = Snapshot(input.Pma, role, generation: 2, predecessor: predecessor.CoreHash.ToArray(),
            issued: 195, serials: [Bytes(16, 0x51)]);
        await Assert.ThrowsAsync<CryptographicException>(() =>
            MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, expired).AsTask());
        var plan = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, tail);
        var floor = new Floor(plan, host.NetworkId);
        var committed = await MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, floor.Exact, floor);
        Assert.Equal(2UL, committed.Generation);
        await Assert.ThrowsAsync<CryptographicException>(() => committed.EnsureGrantNotRevokedAsync(
            Grant(input.Network, role, serial: 0x51)).AsTask());
        await committed.EnsureGrantNotRevokedAsync(Grant(input.Network, role, serial: 0x52));
        await Assert.ThrowsAsync<MailboxGrantRevocationFloorException>(() =>
            MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(host, tail, Snapshot(input.Pma, role)).AsTask());
    }

    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)]
    [InlineData(MailboxCapabilityDomain.Retrieve)]
    public async Task SignedRoleAndCommittedFloor_RejectRevokedSerialAndAllowUnlistedCurrentGrant(MailboxCapabilityDomain role)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, input, new Clock());
        var snapshot = Snapshot(input.Pma, role, serials: [Bytes(16, 0x51)]);
        var plan = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, snapshot);
        var floor = new Floor(plan, host.NetworkId);
        var authority = await MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, floor.Exact, floor);
        await authority.EnsureGrantNotRevokedAsync(Grant(input.Network, role, 0x52));
        var rejected = await Assert.ThrowsAsync<CryptographicException>(() => authority.EnsureGrantNotRevokedAsync(
            Grant(input.Network, role, 0x51)).AsTask());
        Assert.Contains("serial is revoked", rejected.Message, StringComparison.Ordinal);
        Assert.Empty(typeof(VerifiedMailboxGrantRevocationPlan).GetConstructors());
        Assert.Empty(typeof(VerifiedMailboxGrantRevocationV1).GetConstructors());
        Assert.Equal(1UL, authority.Generation);
    }

    [Fact]
    public async Task SignedEmptySnapshot_IsExplicitEvidence_NotMissingFloorFallback()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, input, new Clock());
        var plan = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, Snapshot(input.Pma));
        var floor = new Floor(plan, host.NetworkId);
        var authority = await MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, floor.Exact, floor);
        await authority.EnsureGrantNotRevokedAsync(Grant(input.Network));
        floor.Hash = ReadOnlyMemory<byte>.Empty;
        await Assert.ThrowsAsync<CryptographicException>(() => authority.EnsureGrantNotRevokedAsync(Grant(input.Network)).AsTask());
        await Assert.ThrowsAsync<ApplicationCoreFormatException>(() => MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, ReadOnlyMemory<byte>.Empty).AsTask());
    }

    [Fact]
    public async Task ExpiredProtectedPredecessor_AllowsOnlyFreshExactSuccessorAndReplay()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, input, new Clock());
        var prior = Snapshot(input.Pma, expires: 195, serials: [Bytes(16, 0x51)]);
        var parsedPrior = MailboxGrantRevocationV1Codec.Decode(prior);
        var next = Snapshot(input.Pma, generation: 2, predecessor: parsedPrior.CoreHash.ToArray(),
            issued: 195, serials: [Bytes(16, 0x51), Bytes(16, 0x52)]);
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, prior).AsTask());
        var plan = await MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(host, prior, next);
        var floor = new Floor(plan, host.NetworkId);
        var authority = await MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, floor.Exact, floor);
        await Assert.ThrowsAsync<CryptographicException>(() => authority.EnsureGrantNotRevokedAsync(Grant(input.Network, serial: 0x51)).AsTask());
        var replay = await MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(host, floor.Exact, next);
        Assert.Equal(plan.ExactSnapshot.ToArray(), replay.ExactSnapshot.ToArray());
        await authority.EnsureGrantNotRevokedAsync(Grant(input.Network, serial: 0x53));
        floor.Hash = parsedPrior.CoreHash;
        await Assert.ThrowsAsync<CryptographicException>(() => authority.EnsureCurrentAsync().AsTask());
    }

    [Theory]
    [InlineData("rollback", MailboxGrantRevocationFloorError.Rollback)]
    [InlineData("gap", MailboxGrantRevocationFloorError.MissingSuccessor)]
    [InlineData("fork", MailboxGrantRevocationFloorError.SignedFork)]
    [InlineData("predecessor", MailboxGrantRevocationFloorError.SignedFork)]
    [InlineData("issued", MailboxGrantRevocationFloorError.SignedFork)]
    [InlineData("removed", MailboxGrantRevocationFloorError.RemovedSerial)]
    public async Task AuthenticatedFloorViolations_DoNotProduceWritePlan(string change, MailboxGrantRevocationFloorError error)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, input, new Clock());
        var genesis = MailboxGrantRevocationV1Codec.Decode(Snapshot(input.Pma));
        var prior = Snapshot(input.Pma, generation: 2, predecessor: genesis.CoreHash.ToArray(),
            issued: 195, serials: [Bytes(16, 0x51)]);
        var hash = MailboxGrantRevocationV1Codec.Decode(prior).CoreHash.ToArray();
        var candidate = change switch
        {
            "rollback" => genesis.CanonicalBytes.ToArray(),
            "gap" => Snapshot(input.Pma, generation: 4, predecessor: hash, issued: 195, serials: [Bytes(16, 0x51)]),
            "fork" => Snapshot(input.Pma, generation: 2, predecessor: genesis.CoreHash.ToArray(), issued: 195, serials: [Bytes(16, 0x52)]),
            "predecessor" => Snapshot(input.Pma, generation: 3, predecessor: Bytes(32, 0xff), issued: 195, serials: [Bytes(16, 0x51)]),
            "issued" => Snapshot(input.Pma, generation: 3, predecessor: hash, issued: 194, serials: [Bytes(16, 0x51)]),
            _ => Snapshot(input.Pma, generation: 3, predecessor: hash, issued: 195),
        };
        var rejected = await Assert.ThrowsAsync<MailboxGrantRevocationFloorException>(() =>
            MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(host, prior, candidate).AsTask());
        Assert.Equal(error, rejected.Error);
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("foreign-policy")]
    [InlineData("wrong-key")]
    [InlineData("role")]
    [InlineData("network")]
    [InlineData("before-issuer")]
    [InlineData("future-issuance")]
    [InlineData("policy-expiry")]
    public async Task InvalidSourceProof_CannotBecomeAuthenticatedForkOrFloor(string change)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, input, new Clock());
        var fields = Fields(input.Pma, MailboxCapabilityDomain.Deposit, 1, new byte[32], 190, 230, []);
        if (change == "foreign-policy") fields[1] = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.PMA2, Bytes(32, 0x99));
        if (change == "wrong-key") fields[3] = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xe2)).PublicKey;
        if (change == "role") fields[2] = new byte[] { 2 };
        if (change == "network") fields[0] = Bytes(16, 0x12);
        if (change == "before-issuer") fields[6] = U64(90);
        if (change == "future-issuance") { fields[6] = U64(196); fields[7] = U64(196); }
        if (change == "policy-expiry") fields[8] = U64(301);
        var exact = Sign(fields, MailboxCapabilityDomain.Deposit);
        if (change == "signature") exact[^1] ^= 1;
        var rejected = await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, exact).AsTask());
        Assert.IsNotType<MailboxGrantRevocationFloorException>(rejected);
    }

    [Fact]
    public async Task PlanAndCommit_OwnInputs_RequireExactReadBackAndCurrentFloorAfterCallback()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync(); var clock = new Clock();
        var host = await Host(fixture, input, clock);
        var exact = Snapshot(input.Pma); var original = exact.ToArray();
        clock.OnRead = () => Array.Fill(exact, (byte)0);
        var plan = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, exact);
        Assert.Equal(original, plan.ExactSnapshot.ToArray());
        clock.OnRead = null;
        var floor = new Floor(plan, host.NetworkId);
        var altered = Snapshot(input.Pma, serials: [Bytes(16, 0x51)]);
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, altered, floor).AsTask());
        floor.OnRead = () => floor.Hash = Bytes(32, 0x90);
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, original, floor).AsTask());
    }

    [Theory]
    [InlineData("expiry")]
    [InlineData("foreign-boot")]
    [InlineData("rollback")]
    [InlineData("cancel")]
    public async Task ProtectedFloorCallbackCannotReleaseAuthorityAcrossTimeOrCancellation(string change)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync(); var clock = new Clock();
        var host = await Host(fixture, input, clock);
        var plan = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, Snapshot(input.Pma));
        var floor = new Floor(plan, host.NetworkId);
        using var cancellation = new CancellationTokenSource();
        floor.OnRead = () =>
        {
            if (change == "expiry") clock.Sample = 1_025; // full upper == snapshot expiry, lower is still earlier
            if (change == "foreign-boot") clock.Boot = Bytes(16, 0xa1);
            if (change == "rollback") clock.Sample = 999;
            if (change == "cancel") cancellation.Cancel();
        };
        if (change == "cancel")
            await Assert.ThrowsAsync<OperationCanceledException>(() => MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, floor.Exact, floor, cancellation.Token).AsTask());
        else
            await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, floor.Exact, floor).AsTask());
    }

    [Fact]
    public async Task FloorCallbackCrossingGrantExpiry_RejectsEvenWhileSnapshotRemainsCurrent()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync(); var clock = new Clock();
        var host = await Host(fixture, input, clock);
        var plan = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, Snapshot(input.Pma));
        var floor = new Floor(plan, host.NetworkId);
        var authority = await MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, floor.Exact, floor);
        var exactGrant = Grant(input.Network, serial: 0x52, expires: 220);
        floor.OnRead = () => clock.Sample = 1_015; // upper == grant expiry, snapshot expires at 230
        await Assert.ThrowsAsync<CryptographicException>(() => authority.EnsureGrantNotRevokedAsync(exactGrant).AsTask());
        await authority.EnsureCurrentAsync(); // snapshot really is still current
    }

    [Fact]
    public async Task GrantBytesAreCapturedBeforeFloorCallback()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, input, new Clock());
        var plan = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, Snapshot(input.Pma));
        var floor = new Floor(plan, host.NetworkId);
        var authority = await MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, floor.Exact, floor);
        var exact = Grant(input.Network, serial: 0x52);
        floor.OnRead = () => Array.Fill(exact, (byte)0);
        await authority.EnsureGrantNotRevokedAsync(exact);
        Assert.All(exact, value => Assert.Equal((byte)0, value));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4096)]
    public void CanonicalSerialCapacityRoundTrips(int count)
    {
        var pmaReference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.PMA2, Bytes(32, 0x11));
        var serials = Enumerable.Range(1, count).Select(index =>
        {
            var serial = new byte[16]; BinaryPrimitives.WriteUInt32BigEndian(serial.AsSpan(12), (uint)index); return serial;
        }).ToArray();
        var fields = RawFields(pmaReference, MailboxCapabilityDomain.Deposit, 1, new byte[32], 190, 230, serials);
        var exact = Sign(fields, MailboxCapabilityDomain.Deposit);
        var parsed = MailboxGrantRevocationV1Codec.Decode(exact);
        Assert.Equal(327 + count * 16, exact.Length);
        Assert.Equal((uint)count, parsed.SerialCount);
        Assert.Equal(exact, MailboxGrantRevocationV1Codec.Encode(Enumerable.Range(1, 11).Select(parsed.Field).ToArray(), parsed.Field(12).Span));
    }

    [Theory]
    [InlineData("version")]
    [InlineData("suite")]
    [InlineData("reserved")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("count")]
    [InlineData("order")]
    [InlineData("duplicate")]
    [InlineData("zero")]
    public async Task HostileGrammarIsRejectedBeforeClock(string change)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync(); var clock = new Clock();
        var host = await Host(fixture, input, clock); var before = clock.Reads;
        var fields = Fields(input.Pma, MailboxCapabilityDomain.Deposit, 1, new byte[32], 190, 230, [Bytes(16, 1), Bytes(16, 2)]);
        if (change is "count" or "order" or "duplicate" or "zero")
        {
            if (change == "count") fields[9] = U32(uint.MaxValue);
            if (change == "order") fields[10] = Bytes(16, 2).Concat(Bytes(16, 1)).ToArray();
            if (change == "duplicate") fields[10] = Bytes(32, 1);
            if (change == "zero") fields[10] = new byte[32];
            Assert.Throws<ApplicationCoreFormatException>(() => Sign(fields, MailboxCapabilityDomain.Deposit));
        }
        else
        {
            var exact = Sign(fields, MailboxCapabilityDomain.Deposit);
            if (change == "version") exact[5] = 2;
            if (change == "suite") exact[7] ^= 1;
            if (change == "reserved") exact[11] = 1;
            if (change == "truncated") exact = exact[..^1];
            if (change == "trailing") exact = [.. exact, 0];
            await Assert.ThrowsAsync<ApplicationCoreFormatException>(() => MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, exact).AsTask());
        }
        Assert.Equal(before, clock.Reads);
    }

    private static ValueTask<VerifiedMailboxHostAuthorityV2> Host(Fixture fixture,
        (VerifiedOnionNetworkContext Network, byte[] Pma) input, Clock clock) =>
        MailboxHostAuthorityV2Verifier.VerifyAsync(input.Network, fixture.Authority, input.Pma, new(clock));
    private static byte[] Snapshot(byte[] pma, MailboxCapabilityDomain role = MailboxCapabilityDomain.Deposit,
        ulong generation = 1, byte[]? predecessor = null, ulong issued = 190, ulong expires = 230, byte[][]? serials = null) =>
        Sign(Fields(pma, role, generation, predecessor ?? new byte[32], issued, expires, serials ?? []), role);
    private static ReadOnlyMemory<byte>[] Fields(byte[] pma, MailboxCapabilityDomain role, ulong generation,
        byte[] predecessor, ulong issued, ulong expires, byte[][] serials) =>
        RawFields(XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.PMA2, ContactCodec.Decode(ProtocolMagic.PMA2, pma).CoreHash.Span),
            role, generation, predecessor, issued, expires, serials);
    private static ReadOnlyMemory<byte>[] RawFields(byte[] reference, MailboxCapabilityDomain role, ulong generation,
        byte[] predecessor, ulong issued, ulong expires, byte[][] serials) =>
        [Bytes(16, 0x11), reference, new byte[] { (byte)role },
            PublicKeyAuth.GenerateKeyPair(Bytes(32, role == MailboxCapabilityDomain.Deposit ? (byte)0xe1 : (byte)0xe2)).PublicKey,
            U64(generation), predecessor, U64(issued), U64(issued), U64(expires), U32((uint)serials.Length),
            serials.SelectMany(serial => serial).ToArray()];
    private static byte[] Sign(ReadOnlyMemory<byte>[] fields, MailboxCapabilityDomain role)
    {
        var key = PublicKeyAuth.GenerateKeyPair(Bytes(32, role == MailboxCapabilityDomain.Deposit ? (byte)0xe1 : (byte)0xe2));
        try { return MailboxGrantRevocationV1Codec.Encode(fields, PublicKeyAuth.SignDetached(MailboxGrantRevocationV1Codec.CreateSignatureInput(fields), key.PrivateKey)); }
        finally { CryptographicOperations.ZeroMemory(key.PrivateKey); }
    }
    private static byte[] Grant(VerifiedOnionNetworkContext network, MailboxCapabilityDomain role = MailboxCapabilityDomain.Deposit,
        byte serial = 0x51, ulong expires = 230)
    {
        var seed = Bytes(32, role == MailboxCapabilityDomain.Deposit ? (byte)0xe1 : (byte)0xe2);
        return MailboxAuthenticatedCapabilityCodec.EncodeGrant(new SodiumMailboxCapabilityCrypto().SignGrant(new()
        {
            Domain = role, Lifecycle = MailboxCapabilityLifecycle.Active, NetworkId = network.NetworkId,
            Epoch = network.Closure!.SelectionEpoch, Generation = 5, Serial = Bytes(16, serial),
            NotBeforeUnixSeconds = 190, ExpiresAtUnixSeconds = expires, OverlapUntilUnixSeconds = 0,
            PlacementCommitment = MailboxPlacementCommitment.Compute(new(Bytes(32, 0x52))),
            MembershipCommitment = network.Closure.Pmt.ArtifactHash,
            IssuerPublicKey = PublicKeyAuth.GenerateKeyPair(seed).PublicKey,
            HolderPublicKey = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x53)).PublicKey,
            SelectionInput = Bytes(32, 0x54), IssuerSignature = new byte[64]
        }, seed));
    }
    private sealed class Clock : IOnionMonotonicClock
    {
        internal byte[] Boot = Bytes(16, 0xc1); internal ulong Sample = 1_000;
        internal int Reads; internal Action? OnRead;
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken token)
        { token.ThrowIfCancellationRequested(); Reads++; OnRead?.Invoke(); return ValueTask.FromResult(new OnionMonotonicReading(Boot, Sample)); }
    }
    private sealed class Floor(VerifiedMailboxGrantRevocationPlan plan, ReadOnlyMemory<byte> network) : IMailboxGrantRevocationFloorReader
    {
        internal ReadOnlyMemory<byte> Exact = plan.ExactSnapshot;
        internal ReadOnlyMemory<byte> Hash = plan.CoreHash;
        internal Action? OnRead;
        public ValueTask<ReadOnlyMemory<byte>> ReadCurrentCoreHashAsync(ReadOnlyMemory<byte> actualNetwork,
            ReadOnlyMemory<byte> pma, MailboxCapabilityDomain role, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Assert.Equal(network.ToArray(), actualNetwork.ToArray());
            Assert.Equal(MailboxGrantRevocationV1Codec.Decode(Exact.Span).Field(2).ToArray(), pma.ToArray());
            Assert.Equal(plan.Domain, role); OnRead?.Invoke(); return ValueTask.FromResult(Hash);
        }
    }
    private static byte[] Bytes(int length, byte marker) => Enumerable.Repeat(marker, length).ToArray();
    private static byte[] U64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
    private static byte[] U32(uint value) { var result = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(result, value); return result; }
}
