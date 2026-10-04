using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Fixture = Deep.Protocol.Tests.XPointNetworkV1.XPointOnionCapabilityProducerTests.Fixture;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed partial class MailboxGrantRevocationV1Tests
{
    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit, 0)]
    [InlineData(MailboxCapabilityDomain.Retrieve, 0)]
    [InlineData(MailboxCapabilityDomain.Deposit, 4096)]
    [InlineData(MailboxCapabilityDomain.Retrieve, 4096)]
    public async Task AuthorUsesCanonicalRoleInputAndActualSignatureAtBothCapacityBounds(MailboxCapabilityDomain role, int count)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, input, new Clock());
        // Fixed-width serials with lexicographic order, not hashes sorted by accident.
        var serials = Enumerable.Range(1, count).Select(index => (ReadOnlyMemory<byte>)(byte[])[.. new byte[8], .. U64((ulong)index)]).ToArray();
        var prepared = await MailboxGrantRevocationV1Author.PrepareCurrentAsync(host, role, ReadOnlyMemory<byte>.Empty, serials);
        using var signer = new RoleSigner(role);
        var signed = await MailboxGrantRevocationV1Author.CompleteReservedAsync(prepared, signer);
        var snapshot = MailboxGrantRevocationV1Codec.Decode(signed.Span);
        Assert.Equal(1UL, snapshot.Generation); Assert.Equal(role, snapshot.Domain);
        Assert.Equal((uint)count, snapshot.SerialCount); Assert.Equal(300UL, snapshot.ExpiresAt);
        Assert.Equal(prepared.SigningInput.ToArray(), Assert.Single(signer.Inputs));
        Assert.Equal(snapshot.SignatureInput.ToArray(), prepared.SigningInput.ToArray());
        var restored = await MailboxGrantRevocationV1Author.RestoreReservedAsync(host, prepared.SigningInput);
        Assert.Equal(prepared.CoreHash.ToArray(), restored.CoreHash.ToArray());
        Assert.Equal(signed.ToArray(), (await MailboxGrantRevocationV1Author.CompleteReservedAsync(restored, signer)).ToArray());
        _ = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, signed);
        Assert.Empty(typeof(PreparedMailboxGrantRevocationV1).GetConstructors());
    }

    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)]
    [InlineData(MailboxCapabilityDomain.Retrieve)]
    public async Task AuthorPreservesExpiredSignedPredecessorAndCumulativeRevocations(MailboxCapabilityDomain role)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, input, new Clock());
        var prior = Snapshot(input.Pma, role, expires: 195, serials: [Bytes(16, 0x51)]);
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Author.PrepareCurrentAsync(
            host, role, prior, Array.Empty<ReadOnlyMemory<byte>>()).AsTask());
        var prepared = await MailboxGrantRevocationV1Author.PrepareCurrentAsync(host, role, prior,
            new ReadOnlyMemory<byte>[] { Bytes(16, 0x51), Bytes(16, 0x52) });
        using var signer = new RoleSigner(role);
        var exact = await MailboxGrantRevocationV1Author.CompleteReservedAsync(prepared, signer);
        var plan = await MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(host, prior, exact);
        Assert.Equal(2UL, plan.Generation);
        Assert.Equal(MailboxGrantRevocationV1Codec.Decode(prior).CoreHash.ToArray(),
            MailboxGrantRevocationV1Codec.Decode(exact.Span).Field(6).ToArray());
        var floor = new Floor(plan, host.NetworkId);
        var current = await MailboxGrantRevocationV1Verifier.VerifyCommittedAsync(plan, exact, floor);
        await Assert.ThrowsAsync<CryptographicException>(() => current.EnsureGrantNotRevokedAsync(Grant(input.Network, role, 0x51)).AsTask());
    }

    [Fact]
    public async Task InterruptedSignerRetriesIdenticalExpiredReservationNeverFreshensItsGeneration()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, input, new Clock());
        // Journal-owned bytes from a reservation whose signing never completed in its lifetime.
        var reservedInput = MailboxGrantRevocationV1Codec.Decode(Snapshot(input.Pma, expires: 195)).SignatureInput;
        var restored = await MailboxGrantRevocationV1Author.RestoreReservedAsync(host, reservedInput);
        using var signer = new RoleSigner(MailboxCapabilityDomain.Deposit) { BeforeSign = () => throw new IOException("Interrupted custody callback.") };
        await Assert.ThrowsAsync<IOException>(() => MailboxGrantRevocationV1Author.CompleteReservedAsync(restored, signer).AsTask());
        signer.BeforeSign = null;
        var retry = await MailboxGrantRevocationV1Author.RestoreReservedAsync(host, reservedInput);
        var historical = await MailboxGrantRevocationV1Author.CompleteReservedAsync(retry, signer);
        Assert.Equal(2, signer.Inputs.Count);
        Assert.All(signer.Inputs, bytes => Assert.Equal(reservedInput.ToArray(), bytes));
        Assert.Equal(195UL, MailboxGrantRevocationV1Codec.Decode(historical.Span).ExpiresAt);
        await MailboxGrantRevocationV1Author.VerifyReservedCompletionAsync(retry, historical);
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, historical).AsTask());
        var successor = await MailboxGrantRevocationV1Author.PrepareCurrentAsync(host, MailboxCapabilityDomain.Deposit,
            historical, Array.Empty<ReadOnlyMemory<byte>>());
        Assert.Equal(2UL, successor.Generation); Assert.Equal(300UL, successor.ExpiresAt);
        var fresh = await MailboxGrantRevocationV1Author.CompleteReservedAsync(successor, signer);
        _ = await MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(host, historical, fresh);
    }

    [Fact]
    public async Task ExactWinnerReadBackRejectsDifferentReservationAndInvalidActualSignature()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync(); var clock = new Clock();
        var host = await Host(fixture, input, clock);
        var reserved = await MailboxGrantRevocationV1Author.RestoreReservedAsync(host,
            MailboxGrantRevocationV1Codec.Decode(Snapshot(input.Pma, expires: 195)).SignatureInput);
        var reads = clock.Reads;
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Author.VerifyReservedCompletionAsync(
            reserved, Snapshot(input.Pma, serials: [Bytes(16, 0x51)])).AsTask());
        Assert.Equal(reads, clock.Reads);
        var bad = Snapshot(input.Pma, expires: 195); bad[^1] ^= 1;
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Author.VerifyReservedCompletionAsync(reserved, bad).AsTask());
        Assert.Equal(typeof(ValueTask), typeof(MailboxGrantRevocationV1Author).GetMethod(nameof(MailboxGrantRevocationV1Author.VerifyReservedCompletionAsync))!.ReturnType);
    }

    [Theory]
    [InlineData("predecessor")]
    [InlineData("gap")]
    [InlineData("removed")]
    [InlineData("missing-prior")]
    [InlineData("invalid-prior-signature")]
    public async Task ReservedIntentMustReconcileActualSignedPredecessorBeforeSigning(string change)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, input, new Clock());
        var prior = Snapshot(input.Pma, expires: 195, serials: [Bytes(16, 0x51)]);
        var core = MailboxGrantRevocationV1Codec.Decode(prior).CoreHash.ToArray();
        var next = Snapshot(input.Pma, generation: change == "gap" ? 3UL : 2UL,
            predecessor: change == "predecessor" ? Bytes(32, 0xf1) : core, issued: 195,
            serials: change == "removed" ? [] : [Bytes(16, 0x51)]);
        var reserved = await MailboxGrantRevocationV1Author.RestoreReservedAsync(host,
            MailboxGrantRevocationV1Codec.Decode(next).SignatureInput);
        if (change == "invalid-prior-signature") prior[^1] ^= 1;
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Author.VerifyReservedPredecessorAsync(
            reserved, change == "missing-prior" ? ReadOnlyMemory<byte>.Empty : prior).AsTask());
    }

    [Fact]
    public async Task ReservedExactGenesisAndSuccessorValidateWithoutReturningAdmissionAuthority()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, input, new Clock());
        var expired = Snapshot(input.Pma, expires: 195, serials: [Bytes(16, 0x51)]);
        var genesis = await MailboxGrantRevocationV1Author.RestoreReservedAsync(host,
            MailboxGrantRevocationV1Codec.Decode(expired).SignatureInput);
        await MailboxGrantRevocationV1Author.VerifyReservedPredecessorAsync(genesis, ReadOnlyMemory<byte>.Empty);
        var next = await MailboxGrantRevocationV1Author.PrepareCurrentAsync(host, MailboxCapabilityDomain.Deposit,
            expired, new ReadOnlyMemory<byte>[] { Bytes(16, 0x51) });
        await MailboxGrantRevocationV1Author.VerifyReservedPredecessorAsync(next, expired);
        Assert.Equal(typeof(ValueTask), typeof(MailboxGrantRevocationV1Author).GetMethod(nameof(MailboxGrantRevocationV1Author.VerifyReservedPredecessorAsync))!.ReturnType);
    }

    [Theory]
    [InlineData("wrong-role")]
    [InlineData("invalid-signature")]
    [InlineData("changed-key")]
    [InlineData("cancel")]
    [InlineData("foreign-boot")]
    public async Task SigningCallbackCannotReleaseForeignOrUnauthenticatedCompletion(string change)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync(); var clock = new Clock();
        var host = await Host(fixture, input, clock);
        var prepared = await MailboxGrantRevocationV1Author.PrepareCurrentAsync(host, MailboxCapabilityDomain.Deposit,
            ReadOnlyMemory<byte>.Empty, Array.Empty<ReadOnlyMemory<byte>>());
        using var signer = new RoleSigner(change == "wrong-role" ? MailboxCapabilityDomain.Retrieve : MailboxCapabilityDomain.Deposit);
        using var cancellation = new CancellationTokenSource();
        signer.BeforeSign = () =>
        {
            if (change == "cancel") cancellation.Cancel();
            if (change == "foreign-boot") clock.Boot = Bytes(16, 0xa1);
            if (change == "changed-key") signer.ChangedKey = true;
        };
        signer.InvalidSignature = change == "invalid-signature";
        if (change == "cancel")
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => MailboxGrantRevocationV1Author.CompleteReservedAsync(prepared, signer, cancellation.Token).AsTask());
        else
            await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Author.CompleteReservedAsync(prepared, signer).AsTask());
        Assert.Equal(change == "wrong-role" ? 0 : 1, signer.Inputs.Count);
    }

    [Theory]
    [InlineData("domain")]
    [InlineData("suite")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("count")]
    [InlineData("oversize")]
    public async Task MalformedReservationRejectsBeforeAuthorityCallbacks(string change)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync(); var clock = new Clock();
        var host = await Host(fixture, input, clock); var reads = clock.Reads;
        var exact = MailboxGrantRevocationV1Codec.Decode(Snapshot(input.Pma)).SignatureInput.ToArray();
        var prefix = ApplicationCoreFormat.SignatureInput("Deep/XPoint/V1/MGR1/issuer", []).Length;
        if (change == "domain") exact[1] ^= 1;
        if (change == "suite") exact[prefix + 7] ^= 1;
        if (change == "count") exact[prefix + 9] = 12;
        if (change == "truncated") exact = exact[..^1];
        if (change == "trailing") exact = [.. exact, 0];
        if (change == "oversize") exact = new byte[MailboxGrantRevocationV1Codec.MaximumBytes + prefix];
        await Assert.ThrowsAnyAsync<Exception>(() => MailboxGrantRevocationV1Author.RestoreReservedAsync(host, exact).AsTask());
        Assert.Equal(reads, clock.Reads);
    }

    [Fact]
    public async Task PreparationCapturesSerialsBeforeClockAndRejectsMalformedLedgerWithoutCallbacks()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync(); var clock = new Clock();
        var host = await Host(fixture, input, clock); var reads = clock.Reads;
        foreach (var invalid in new ReadOnlyMemory<byte>[][] { [new byte[16]], [Bytes(15, 1)],
            [Bytes(16, 2), Bytes(16, 1)], [Bytes(16, 1), Bytes(16, 1)] })
            await Assert.ThrowsAsync<ArgumentException>(() => MailboxGrantRevocationV1Author.PrepareCurrentAsync(host,
                MailboxCapabilityDomain.Deposit, ReadOnlyMemory<byte>.Empty, invalid).AsTask());
        Assert.Equal(reads, clock.Reads);
        var serial = Bytes(16, 0x51); clock.OnRead = () => Array.Clear(serial);
        var prepared = await MailboxGrantRevocationV1Author.PrepareCurrentAsync(host, MailboxCapabilityDomain.Deposit,
            ReadOnlyMemory<byte>.Empty, new ReadOnlyMemory<byte>[] { serial });
        clock.OnRead = null; using var signer = new RoleSigner(MailboxCapabilityDomain.Deposit);
        var signed = await MailboxGrantRevocationV1Author.CompleteReservedAsync(prepared, signer);
        Assert.Equal(Bytes(16, 0x51), MailboxGrantRevocationV1Codec.Decode(signed.Span).Field(11).ToArray());
        Assert.All(serial, value => Assert.Equal((byte)0, value));
    }

    [Fact]
    public async Task ExpiredHistoricalStepRequiresExactCommitAndCannotYieldAdmissionCapability()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxAsync();
        var host = await Host(fixture, input, new Clock());
        var prior = Snapshot(input.Pma, expires: 195, serials: [Bytes(16, 0x51)]);
        var historical = Snapshot(input.Pma, generation: 2, predecessor: MailboxGrantRevocationV1Codec.Decode(prior).CoreHash.ToArray(),
            issued: 195, expires: 199, serials: [Bytes(16, 0x51), Bytes(16, 0x52)]);
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(host, prior, historical).AsTask());
        var plan = await MailboxGrantRevocationV1Verifier.PlanCatchUpSuccessorAsync(host, prior, historical);
        var freshPlan = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, Snapshot(input.Pma));
        var floor = new Floor(freshPlan, host.NetworkId) { Exact = historical, Hash = plan.CoreHash };
        await MailboxGrantRevocationV1Verifier.VerifyHistoricalCommitAsync(plan, historical, floor);
        Assert.Empty(typeof(VerifiedMailboxGrantRevocationHistoryPlan).GetConstructors());
        Assert.Equal(typeof(ValueTask), typeof(MailboxGrantRevocationV1Verifier).GetMethod(nameof(MailboxGrantRevocationV1Verifier.VerifyHistoricalCommitAsync))!.ReturnType);
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Verifier.VerifyHistoricalCommitAsync(plan, prior, floor).AsTask());
        floor.Hash = ReadOnlyMemory<byte>.Empty;
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Verifier.VerifyHistoricalCommitAsync(plan, historical, floor).AsTask());
        floor.Hash = plan.CoreHash; floor.OnRead = () => floor.Hash = Bytes(32, 0x91);
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Verifier.VerifyHistoricalCommitAsync(plan, historical, floor).AsTask());
        floor.OnRead = null; floor.Hash = plan.CoreHash;
        var fresh = Snapshot(input.Pma, generation: 3, predecessor: plan.CoreHash.ToArray(), issued: 195,
            serials: [Bytes(16, 0x51), Bytes(16, 0x52)]);
        _ = await MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(host, historical, fresh);
    }

    private sealed class RoleSigner : IMailboxGrantIssuerSigner, IDisposable
    {
        private readonly byte[] publicKey, privateKey;
        internal readonly List<byte[]> Inputs = [];
        internal Action? BeforeSign; internal bool ChangedKey, InvalidSignature;
        internal RoleSigner(MailboxCapabilityDomain role)
        {
            var key = PublicKeyAuth.GenerateKeyPair(Bytes(32, role == MailboxCapabilityDomain.Deposit ? (byte)0xe1 : (byte)0xe2));
            publicKey = key.PublicKey; privateKey = key.PrivateKey;
        }
        public ReadOnlyMemory<byte> Ed25519PublicKey => ChangedKey ? Bytes(32, 0x91) : publicKey.ToArray();
        public ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> exactSigningInput, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Inputs.Add(exactSigningInput.ToArray()); BeforeSign?.Invoke();
            var signature = PublicKeyAuth.SignDetached(exactSigningInput.ToArray(), privateKey);
            if (InvalidSignature) signature[^1] ^= 1;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(signature);
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(privateKey);
    }
}
