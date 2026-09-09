using Deep.Protocol.MessagingCrypto;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class HybridOneTimePreKeyStateTests
{
    [Fact]
    public void FreshPlan_IsSingleConsumerAndCarriesExactStateCas()
    {
        using var source = CreateState(storageGeneration: 7);
        var predecessor = source.StateCommitment.ToArray();
        using var plan = source.PrepareConsume(Claim(10, 20, 30));

        Assert.False(source.IsConsumed);
        Assert.Equal(PreKeyConsumeOutcome.Fresh, plan.Outcome);
        Assert.Equal(7UL, plan.StateCas.ExpectedGeneration);
        Assert.Equal(predecessor, plan.StateCas.PredecessorCommitment.ToArray());
        Assert.Equal(2, plan.DeletionObligations.Count);
        var duplicateProof = DurableSuccess(plan);
        using var commit = plan.Commit(DurableSuccess(plan));
        Assert.Throws<MessagingCryptoException>(() => plan.Commit(duplicateProof));
        using var claimed = commit.TakeClaimedLease();
        using var claimedData = claimed.ConsumeForHandshake();
        Assert.Equal(Bytes(2), claimedData.X25519PrivateKey);
        Assert.Equal(1184, claimedData.MlKemDecapsulationKey.Length);
        using var next = commit.TakeNextState();
        Assert.True(next.IsConsumed);
        Assert.Equal(8UL, next.StorageGeneration);
        Assert.NotEqual(predecessor, next.StateCommitment.ToArray());
    }

    [Fact]
    public async Task ConcurrentPlanConsume_AllowsExactlyOneConsumer()
    {
        using var source = CreateState();
        using var plan = source.PrepareConsume(Claim(10, 20, 30));
        var proofs = Enumerable.Range(0, 16).Select(_ => DurableSuccess(plan)).ToArray();
        var results = await Task.WhenAll(Enumerable.Range(0, 16).Select(index => Task.Run(() =>
        {
            try
            {
                using var commit = plan.Commit(proofs[index]);
                return true;
            }
            catch (MessagingCryptoException exception) when (exception.Error == MessagingCryptoError.CapabilityConsumed)
            {
                return false;
            }
        })));
        Assert.Equal(1, results.Count(static value => value));
    }

    [Fact]
    public void ExactReplayHasNoSecretOrStateMutation()
    {
        using var source = CreateState();
        using var freshPlan = source.PrepareConsume(Claim(10, 20, 30));
        using var freshCommit = freshPlan.Commit(DurableSuccess(freshPlan));
        using var claimed = freshCommit.TakeClaimedLease();
        using var consumed = freshCommit.TakeNextState();

        using var replayPlan = consumed.PrepareConsume(Claim(10, 20, 30));
        Assert.Equal(PreKeyConsumeOutcome.ExactReplay, replayPlan.Outcome);
        using var replayCommit = replayPlan.ConsumeExactReplay();
        Assert.False(replayCommit.HasNextState);
        Assert.False(replayCommit.HasClaimedLease);
        Assert.Empty(replayCommit.DeletionObligations);
    }

    [Fact]
    public void ChangedReplayAndDifferentClaimReject()
    {
        using var source = CreateState();
        using var plan = source.PrepareConsume(Claim(10, 20, 30));
        using var commit = plan.Commit(DurableSuccess(plan));
        using var claimed = commit.TakeClaimedLease();
        using var consumed = commit.TakeNextState();

        var changed = Assert.Throws<MessagingCryptoException>(() =>
            consumed.PrepareConsume(Claim(10, 20, 31)));
        Assert.Equal(MessagingCryptoError.PreKeyConflict, changed.Error);
        var other = Assert.Throws<MessagingCryptoException>(() =>
            consumed.PrepareConsume(Claim(11, 21, 31)));
        Assert.Equal(MessagingCryptoError.PreKeyAlreadyConsumed, other.Error);
    }

    [Fact]
    public void CompetingFreshPlansSharePredecessorAndRequirePersistenceCas()
    {
        using var source = CreateState(storageGeneration: 12);
        using var first = source.PrepareConsume(Claim(10, 20, 30));
        using var second = source.PrepareConsume(Claim(11, 21, 31));
        Assert.Equal(first.StateCas.ExpectedGeneration, second.StateCas.ExpectedGeneration);
        Assert.Equal(
            first.StateCas.PredecessorCommitment.ToArray(),
            second.StateCas.PredecessorCommitment.ToArray());
    }

    [Fact]
    public void ClaimedLease_IsSingleUseAndDisposedStateRejects()
    {
        var source = CreateState();
        using var plan = source.PrepareConsume(Claim(10, 20, 30));
        using var commit = plan.Commit(DurableSuccess(plan));
        using var claimed = commit.TakeClaimedLease();
        using var data = claimed.ConsumeForHandshake();
        var consumed = Assert.Throws<MessagingCryptoException>(() => claimed.ConsumeForHandshake());
        Assert.Equal(MessagingCryptoError.CapabilityConsumed, consumed.Error);
        source.Dispose();
        var disposed = Assert.Throws<MessagingCryptoException>(() =>
            source.PrepareConsume(Claim(12, 22, 32)));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, disposed.Error);
    }

    [Fact]
    public void InvalidShapeRejectsBeforeOwnedStateExists()
    {
        var error = Assert.Throws<MessagingCryptoException>(() => HybridOneTimePreKeyState.Create(
            Bytes(1),
            new byte[31],
            Bytes(3),
            Enumerable.Repeat((byte)4, 1184).ToArray()));
        Assert.Equal(MessagingCryptoError.InvalidInput, error.Error);
    }

    [Fact]
    public void FailedOrStaleDurableCasCannotReleaseClaimedSecrets()
    {
        using var source = CreateState(storageGeneration: 9);
        using var failedPlan = source.PrepareConsume(Claim(10, 20, 30));
        Assert.Throws<MessagingCryptoException>(() =>
            DurableDatabaseCasSuccessCapability.CreateDarkForTests(
                failedPlan.StateCas,
                failedPlan.ProposedGeneration!.Value,
                failedPlan.ProposedStateCommitment.Span,
                durableDatabaseCasSucceeded: false));

        using var stalePlan = source.PrepareConsume(Claim(11, 21, 31));
        using var other = CreateState(storageGeneration: 10);
        using var otherPlan = other.PrepareConsume(Claim(12, 22, 32));
        var staleProof = DurableSuccess(otherPlan);
        Assert.Throws<MessagingCryptoException>(() => stalePlan.Commit(staleProof));
    }

    [Fact]
    public async Task DisposeAndPrepareHaveLinearLockOrdering()
    {
        var source = CreateState();
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        using var hook = MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            Point = name =>
            {
                if (name != "prekey.prepare-entered") return;
                entered.Set();
                Assert.True(release.Wait(TimeSpan.FromSeconds(5)));
            },
        });

        var prepare = Task.Run(() => source.PrepareConsume(Claim(10, 20, 30)));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        var dispose = Task.Run(source.Dispose);
        Assert.NotSame(dispose, await Task.WhenAny(dispose, Task.Delay(100)));
        release.Set();

        using var plan = await prepare;
        await dispose;
        var error = Assert.Throws<MessagingCryptoException>(() =>
            source.PrepareConsume(Claim(11, 21, 31)));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, error.Error);
    }

    [Theory]
    [InlineData("prekey.before-obligations-plan")]
    [InlineData("prekey.after-obligations-before-plan")]
    public void FaultDuringObligationsOrPlanDisposesNextClaimAndEverySecretOwner(string faultPoint)
    {
        using var source = CreateState();
        HybridOneTimePreKeyState? capturedNext = null;
        ClaimedHybridPreKeyLease? capturedClaimed = null;
        var capturedSecrets = new List<SecretBuffer>();
        using (MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            OwnedSecret = (name, owner) =>
            {
                if (name.StartsWith("prekey.claimed.", StringComparison.Ordinal))
                    capturedSecrets.Add(owner);
            },
            OwnedDisposable = (name, owner) =>
            {
                if (name == "prekey.next-state") capturedNext = Assert.IsType<HybridOneTimePreKeyState>(owner);
                if (name == "prekey.claimed-lease") capturedClaimed = Assert.IsType<ClaimedHybridPreKeyLease>(owner);
            },
            Point = name =>
            {
                if (name == faultPoint)
                    throw new InvalidOperationException("injected prekey plan construction fault");
            },
        }))
        {
            Assert.Throws<InvalidOperationException>(() => source.PrepareConsume(Claim(10, 20, 30)));
        }

        Assert.NotNull(capturedNext);
        Assert.NotNull(capturedClaimed);
        Assert.Equal(2, capturedSecrets.Count);
        Assert.Equal(MessagingCryptoError.ObjectDisposed, Assert.Throws<MessagingCryptoException>(() =>
            capturedNext!.PrepareConsume(Claim(11, 21, 31))).Error);
        Assert.Equal(MessagingCryptoError.CapabilityConsumed, Assert.Throws<MessagingCryptoException>(() =>
            capturedClaimed!.ConsumeForHandshake()).Error);
        Assert.All(capturedSecrets, owner =>
            Assert.Equal(MessagingCryptoError.ObjectDisposed,
                Assert.Throws<MessagingCryptoException>(() => owner.Copy()).Error));
    }

    private static HybridOneTimePreKeyState CreateState(ulong storageGeneration = 0) =>
        HybridOneTimePreKeyState.Create(
            Bytes(1), Bytes(2), Bytes(3),
            Enumerable.Repeat((byte)4, 1184).ToArray(),
            storageGeneration);

    private static VerifiedPreKeyClaimCapability Claim(byte claim, byte session, byte initiation) =>
        VerifiedPreKeyClaimCapability.CreateDarkForTests(
            Bytes(claim), Bytes(session), Bytes(initiation), Bytes(1), Bytes(3));

    private static DurableDatabaseCasSuccessCapability DurableSuccess(OneTimePreKeyConsumePlan plan) =>
        DurableDatabaseCasSuccessCapability.CreateDarkForTests(
            plan.StateCas,
            plan.ProposedGeneration ?? throw new InvalidOperationException("Fresh plan has no proposed generation."),
            plan.ProposedStateCommitment.Span,
            durableDatabaseCasSucceeded: true);

    private static byte[] Bytes(byte value) => Enumerable.Repeat(value, 32).ToArray();
}
