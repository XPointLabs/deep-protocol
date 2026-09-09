using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed partial class TripleRatchetTransactionsTests
{
    [Fact]
    public void IndependentCombinerVector_AndCasBoundPlanMatch()
    {
        using var state = CreateState();
        var target = new RatchetCounterTuple(0, 1, 1);
        var header = Bytes(3);
        var envelope = Bytes(4);
        using var plan = state.PrepareReceive(
            new ScriptedProvider(), Persistence(state),
            FreshDedup(state, target, header, envelope, 10, journalGeneration: 90_000),
            target, header, envelope);

        Assert.Equal(state.StorageGeneration, plan.DatabaseCas.ExpectedGeneration);
        Assert.Equal(state.StateCommitment.ToArray(), plan.DatabaseCas.PredecessorCommitment.ToArray());
        Assert.Equal(state.StorageGeneration, plan.CheckpointCas.ExpectedGeneration);
        Assert.NotNull(plan.DeduplicationMutation);
        Assert.Equal(90_000UL, plan.DeduplicationMutation!.ExpectedJournalGeneration);
        Assert.Single(plan.DeduplicationMutation.ConsumedPqTupleCommitments);
        using var commit = plan.Commit(DurableSuccess(plan));
        using var key = commit.TakeMessageKey();
        byte[]? actual = null;
        key.Use(value => actual = value.ToArray());
        try
        {
            // Independent Python hashlib/hmac RFC 5869 vector, including the
            // exact frozen Triple-Ratchet protocol-info component once in each CTX.
            Assert.Equal(
                "C553D6C92404501D5B90690B43D34B4581A4745880DD8B735AF73F8B5942A622",
                Convert.ToHexString(actual!));
            Assert.NotEqual(
                "F22F2605A8F927259EF0912E6D692ABC1B0875E11564BBB2517AD4943AFF057C",
                Convert.ToHexString(actual!));
        }
        finally { CryptographicOperations.ZeroMemory(actual!); }
        using var next = commit.TakeNextState();
        Assert.Equal(1UL, next.NextExpectedReceiveEcN);
        Assert.Equal(1UL, next.StorageGeneration);
    }

    [Fact]
    public void ReceiveGap_EnforcesPqContributionAtEveryStep()
    {
        using var state = CreateState(maximumWithoutFresh: 2);
        var target = new RatchetCounterTuple(2, 1, 3);
        var header = Bytes(4);
        var envelope = Bytes(5);
        var missing = new ScriptedProvider { FreshContribution = static _ => false };
        var error = Assert.Throws<MessagingCryptoException>(() => state.PrepareReceive(
            missing, Persistence(state), FreshDedup(state, target, header, envelope, 11),
            target, header, envelope));
        Assert.Equal(MessagingCryptoError.PqInjectionRequired, error.Error);

        var valid = new ScriptedProvider { FreshContribution = static ecN => ecN == 2 };
        using var plan = state.PrepareReceive(
            valid, Persistence(state), FreshDedup(state, target, header, envelope, 12),
            target, header, envelope);
        using var commit = plan.Commit(DurableSuccess(plan));
        using var key = commit.TakeMessageKey();
        using var next = commit.TakeNextState();
        Assert.Equal(0, next.ReceiveMessagesSincePqInjection);
        Assert.Equal(2, next.SkippedKeyCount);
    }

    [Fact]
    public void ReusedPqTupleAndBrokenStateEvidenceReject()
    {
        using var state = CreateState();
        var header = Bytes(5);
        var envelope = Bytes(6);
        var reusedTarget = new RatchetCounterTuple(1, 1, 1);
        var reused = Assert.Throws<MessagingCryptoException>(() => state.PrepareReceive(
            new ScriptedProvider { ReusePqTuple = true },
            Persistence(state), FreshDedup(state, reusedTarget, header, envelope, 20),
            reusedTarget, header, envelope));
        Assert.Equal(MessagingCryptoError.PqEvidenceRejected, reused.Error);

        var brokenTarget = new RatchetCounterTuple(0, 1, 1);
        var broken = Assert.Throws<MessagingCryptoException>(() => state.PrepareReceive(
            new ScriptedProvider { BreakFirstPredecessor = true },
            Persistence(state), FreshDedup(state, brokenTarget, header, envelope, 21),
            brokenTarget, header, envelope));
        Assert.Equal(MessagingCryptoError.PqEvidenceRejected, broken.Error);

        var reusedKeyTarget = new RatchetCounterTuple(1, 1, 2);
        var reusedKey = Assert.Throws<MessagingCryptoException>(() => state.PrepareReceive(
            new ScriptedProvider { ReusePqKey = true },
            Persistence(state), FreshDedup(state, reusedKeyTarget, header, envelope, 22),
            reusedKeyTarget, header, envelope));
        Assert.Equal(MessagingCryptoError.PqEvidenceRejected, reusedKey.Error);
    }

    [Fact]
    public void ZeroEcAndPqKeysRejectAtOwnedInputBoundary()
    {
        var evidence = new PqStepEvidence(Bytes(1), Bytes(2), false);
        var ec = Assert.Throws<MessagingCryptoException>(() => new RatchetComponentKeyMaterial(
            new RatchetCounterTuple(0, 1, 1), new byte[32], Bytes(3), evidence));
        Assert.Equal(MessagingCryptoError.InvalidInput, ec.Error);
        var pq = Assert.Throws<MessagingCryptoException>(() => new RatchetComponentKeyMaterial(
            new RatchetCounterTuple(0, 1, 1), Bytes(3), new byte[32], evidence));
        Assert.Equal(MessagingCryptoError.InvalidInput, pq.Error);
    }

    [Fact]
    public void CombinedMessageKeyIsZeroizedWhenFaultOccursAfterHkdfExpand()
    {
        byte[]? captured = null;
        using (MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            ManagedSecret = (name, value) =>
            {
                if (name != "message-kdf.output") return;
                captured = value;
                throw new InvalidOperationException("injected combined-key handoff fault");
            },
        }))
        {
            Assert.Throws<InvalidOperationException>(() => MessagingKdf.DeriveCombinedMessageKey(
                Bytes(1), 2, 3, 4, Bytes(5), Bytes(6), Bytes(7)));
        }

        Assert.NotNull(captured);
        Assert.True(MessagingCryptoValidation.IsZero(captured!));
    }

    [Fact]
    public void FreshReceiveFaultBeforeDedupDisposesOwnedNextState()
    {
        using var source = CreateState();
        TripleRatchetState? capturedNext = null;
        var target = new RatchetCounterTuple(0, 1, 1);
        var header = Bytes(22);
        var envelope = Bytes(23);
        using (MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            OwnedDisposable = (name, owner) =>
            {
                if (name == "ratchet.receive.next-state")
                    capturedNext = Assert.IsType<TripleRatchetState>(owner);
            },
            Point = name =>
            {
                if (name == "ratchet.receive.before-dedup-plan")
                    throw new InvalidOperationException("injected receive dedup construction fault");
            },
        }))
        {
            Assert.Throws<InvalidOperationException>(() => source.PrepareReceive(
                new ScriptedProvider(), Persistence(source),
                FreshDedup(source, target, header, envelope, 96),
                target, header, envelope));
        }

        Assert.NotNull(capturedNext);
        AssertStateDisposed(capturedNext!);
    }

    [Fact]
    public void SkippedReceiveFaultBeforeDedupDisposesOwnedNextState()
    {
        using var source = CreateState();
        var laterTarget = new RatchetCounterTuple(2, 1, 3);
        var laterHeader = Bytes(24);
        var laterEnvelope = Bytes(25);
        using var laterPlan = source.PrepareReceive(
            new ScriptedProvider(), Persistence(source),
            FreshDedup(source, laterTarget, laterHeader, laterEnvelope, 97),
            laterTarget, laterHeader, laterEnvelope);
        using var laterCommit = laterPlan.Commit(DurableSuccess(laterPlan));
        using var laterKey = laterCommit.TakeMessageKey();
        using var afterLater = laterCommit.TakeNextState();

        TripleRatchetState? capturedNext = null;
        var skippedTarget = new RatchetCounterTuple(0, 1, 1);
        var skippedHeader = Bytes(26);
        var skippedEnvelope = Bytes(27);
        using (MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            OwnedDisposable = (name, owner) =>
            {
                if (name == "ratchet.skipped.next-state")
                    capturedNext = Assert.IsType<TripleRatchetState>(owner);
            },
            Point = name =>
            {
                if (name == "ratchet.skipped.before-dedup-plan")
                    throw new InvalidOperationException("injected skipped dedup construction fault");
            },
        }))
        {
            Assert.Throws<InvalidOperationException>(() => afterLater.PrepareReceive(
                new ThrowingProvider(), Persistence(afterLater),
                FreshDedup(afterLater, skippedTarget, skippedHeader, skippedEnvelope, 98),
                skippedTarget, skippedHeader, skippedEnvelope));
        }

        Assert.NotNull(capturedNext);
        AssertStateDisposed(capturedNext!);
    }

    [Fact]
    public void PlanConstructorFaultDisposesMessageKeyAndNextStateOwners()
    {
        using var source = CreateState();
        MessageKeyLease? capturedKey = null;
        TripleRatchetState? capturedNext = null;
        using (MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            OwnedDisposable = (name, owner) =>
            {
                if (name == "ratchet.plan.message-key")
                    capturedKey = Assert.IsType<MessageKeyLease>(owner);
                if (name == "ratchet.plan.next-state")
                    capturedNext = Assert.IsType<TripleRatchetState>(owner);
            },
            Point = name =>
            {
                if (name == "ratchet.plan.after-owner-assignment")
                    throw new InvalidOperationException("injected plan constructor fault");
            },
        }))
        {
            Assert.Throws<InvalidOperationException>(() => source.PrepareSend(
                new ScriptedProvider(), Persistence(source), Bytes(80), Bytes(81), Bytes(28)));
        }

        Assert.NotNull(capturedKey);
        Assert.NotNull(capturedNext);
        Assert.Equal(MessagingCryptoError.ObjectDisposed,
            Assert.Throws<MessagingCryptoException>(() => capturedKey!.Use(static _ => { })).Error);
        AssertStateDisposed(capturedNext!);
    }

    [Fact]
    public void OversizedExactOwnedCollectionDisposesEveryPassedKey()
    {
        var keys = Enumerable.Range(0, MessagingCryptoConstants.MaximumForwardGap + 6)
            .Select(index => CreateOwnedKey((ulong)index))
            .ToArray();
        var error = Assert.Throws<MessagingCryptoException>(() =>
            new RatchetComponentTransition(Bytes(90), keys));
        Assert.Equal(MessagingCryptoError.TransitionRejected, error.Error);
        Assert.All(keys, key =>
            Assert.Throws<MessagingCryptoException>(() => key.Derive(Bytes(40), Bytes(41))));
    }

    [Fact]
    public void OutOfOrderSkippedKeys_AreBoundedAndDeletedOnCommit()
    {
        using var state = CreateState();
        var laterTarget = new RatchetCounterTuple(2, 1, 3);
        var laterHeader = Bytes(6);
        var laterEnvelope = Bytes(60);
        using var laterPlan = state.PrepareReceive(
            new ScriptedProvider(), Persistence(state),
            FreshDedup(state, laterTarget, laterHeader, laterEnvelope, 30),
            laterTarget, laterHeader, laterEnvelope);
        using var laterCommit = laterPlan.Commit(DurableSuccess(laterPlan));
        using var laterKey = laterCommit.TakeMessageKey();
        using var afterLater = laterCommit.TakeNextState();
        Assert.Equal(2, afterLater.SkippedKeyCount);

        var earlyTarget = new RatchetCounterTuple(0, 1, 1);
        var earlyHeader = Bytes(7);
        var earlyEnvelope = Bytes(61);
        using var earlyPlan = afterLater.PrepareReceive(
            new ScriptedProvider(), Persistence(afterLater),
            FreshDedup(afterLater, earlyTarget, earlyHeader, earlyEnvelope, 31),
            earlyTarget, earlyHeader, earlyEnvelope);
        Assert.Equal(RatchetPlanOutcome.OutOfOrderSkippedKey, earlyPlan.Outcome);
        using var earlyCommit = earlyPlan.Commit(DurableSuccess(earlyPlan));
        Assert.Contains(RatchetDeletionKind.ConsumedSkippedKeyAfterCommit, earlyCommit.DeletionObligations);
        using var earlyKey = earlyCommit.TakeMessageKey();
        using var afterEarly = earlyCommit.TakeNextState();
        Assert.Equal(1, afterEarly.SkippedKeyCount);
    }

    [Fact]
    public void SkippedLimitAndForwardGapRejectBeforeProvider()
    {
        using var state = CreateState();
        var provider = new ScriptedProvider();
        var farTarget = new RatchetCounterTuple(2049, 1, 2050);
        var header = Bytes(8);
        var envelope = Bytes(62);
        var tooFar = Assert.Throws<MessagingCryptoException>(() => state.PrepareReceive(
            provider, Persistence(state), FreshDedup(state, farTarget, header, envelope, 40),
            farTarget, header, envelope));
        Assert.Equal(MessagingCryptoError.ForwardGapExceeded, tooFar.Error);
        Assert.Equal(0, provider.ReceiveCalls);

        var boundaryProvider = new ScriptedProvider { FreshContribution = static _ => true };
        var boundaryTarget = new RatchetCounterTuple(2048, 1, 2049);
        using var boundaryPlan = state.PrepareReceive(
            boundaryProvider, Persistence(state),
            FreshDedup(state, boundaryTarget, header, envelope, 41),
            boundaryTarget, header, envelope);
        using var boundaryCommit = boundaryPlan.Commit(DurableSuccess(boundaryPlan));
        using var boundaryKey = boundaryCommit.TakeMessageKey();
        using var boundary = boundaryCommit.TakeNextState();
        Assert.Equal(2048, boundary.SkippedKeyCount);
    }

    [Fact]
    public void DurableDedupBoundaryHasNoSessionLifetime2048ReceiptCap()
    {
        using var state = CreateState();
        var target = new RatchetCounterTuple(0, 1, 1);
        var header = Bytes(9);
        var envelope = Bytes(63);
        using var plan = state.PrepareReceive(
            new ScriptedProvider(), Persistence(state),
            FreshDedup(state, target, header, envelope, 50, journalGeneration: 1_000_000),
            target, header, envelope);
        Assert.Equal(1_000_000UL, plan.DeduplicationMutation!.ExpectedJournalGeneration);
        Assert.DoesNotContain(
            typeof(TripleRatchetState).GetFields(System.Reflection.BindingFlags.Instance |
                                                 System.Reflection.BindingFlags.NonPublic),
            static field => field.Name.Contains("receipt", StringComparison.OrdinalIgnoreCase));

        using var replay = state.PrepareReceive(
            new ThrowingProvider(), Persistence(state),
            ExactReplayDedup(state, target, header, envelope, 51, 1_000_001),
            target, header, envelope);
        Assert.Equal(RatchetPlanOutcome.ExactReplay, replay.Outcome);
        using var replayCommit = replay.ConsumeExactReplay();
        Assert.False(replayCommit.HasNextState);
        Assert.False(replayCommit.HasMessageKey);
    }

    [Fact]
    public void RollbackRequiresTerminalLatchAndLatchedStateCannotResume()
    {
        using var state = CreateState(storageGeneration: 7);
        var rollback = Assert.Throws<MessagingCryptoException>(() => state.PrepareSend(
            new ScriptedProvider(), Persistence(state, latest: 8), Bytes(80), Bytes(81), Bytes(10)));
        Assert.Equal(MessagingCryptoError.RollbackDetected, rollback.Error);

        using var latchPlan = state.PrepareRollbackLatch(
            Persistence(state, latest: 8), Bytes(82), Bytes(83));
        Assert.Equal(RatchetPlanOutcome.RollbackLatched, latchPlan.Outcome);
        using var latchCommit = latchPlan.Commit(DurableSuccess(latchPlan));
        Assert.Contains(RatchetDeletionKind.AllSessionSecretsAfterRollbackLatch, latchCommit.DeletionObligations);
        using var latched = latchCommit.TakeNextState();
        Assert.True(latched.IsTerminallyLatched);
        Assert.Equal(9UL, latched.StorageGeneration);
        Assert.Equal(7UL, latchCommit.DatabaseCas.ExpectedGeneration);
        Assert.Equal(state.StateCommitment.ToArray(), latchCommit.DatabaseCas.PredecessorCommitment.ToArray());
        Assert.Equal(8UL, latchCommit.CheckpointCas.ExpectedGeneration);
        Assert.Equal(Bytes(88), latchCommit.CheckpointCas.PredecessorCommitment.ToArray());
        var terminal = Assert.Throws<MessagingCryptoException>(() => latched.PrepareSend(
            new ScriptedProvider(), Persistence(latched), Bytes(80), Bytes(81), Bytes(10)));
        Assert.Equal(MessagingCryptoError.TerminallyLatched, terminal.Error);
    }

    [Fact]
    public void FailedJournalOrUnifiedTransactionCannotReleaseTransition()
    {
        using var state = CreateState();
        using var plan = state.PrepareSend(
            new ScriptedProvider(), Persistence(state), Bytes(80), Bytes(81), Bytes(10));
        var generation = plan.ProposedGeneration!.Value;
        Assert.Throws<MessagingCryptoException>(() => ExactRatchetJournalReceipt.CreateDarkForTests(
            plan.OperationId.Span, plan.JournalPredecessor.Span,
            plan.DatabaseCas, plan.CheckpointCas, generation, plan.ProposedStateCommitment.Span,
            plan.TerminalStateCommitment.Span, plan.DeletionManifestCommitment.Span,
            plan.DeduplicationMutationCommitment.Span, plan.PqFenceMutationCommitment.Span,
            durablyCommitted: false));
        var receipt = ExactRatchetJournalReceipt.CreateDarkForTests(
            plan.OperationId.Span, plan.JournalPredecessor.Span,
            plan.DatabaseCas, plan.CheckpointCas, generation, plan.ProposedStateCommitment.Span,
            plan.TerminalStateCommitment.Span, plan.DeletionManifestCommitment.Span,
            plan.DeduplicationMutationCommitment.Span, plan.PqFenceMutationCommitment.Span,
            durablyCommitted: true);
        Assert.Throws<MessagingCryptoException>(() =>
            DurableRatchetTransactionSuccessCapability.CreateDarkForTests(
                receipt, atomicTransactionCommitted: false));
    }

    [Fact]
    public void DurableProofForDifferentStateCannotReleaseTransition()
    {
        using var firstState = CreateState(maximumWithoutFresh: 32);
        using var secondState = CreateState(maximumWithoutFresh: 31);
        using var firstPlan = firstState.PrepareSend(
            new ScriptedProvider(), Persistence(firstState), Bytes(80), Bytes(81), Bytes(10));
        using var secondPlan = secondState.PrepareSend(
            new ScriptedProvider(), Persistence(secondState), Bytes(80), Bytes(81), Bytes(10));
        var proofForFirst = DurableSuccess(firstPlan);

        var error = Assert.Throws<MessagingCryptoException>(() => secondPlan.Commit(proofForFirst));

        Assert.Equal(MessagingCryptoError.CasConflict, error.Error);
    }

    [Fact]
    public void RollbackProofForDifferentCheckpointCannotReleaseLatch()
    {
        using var state = CreateState(storageGeneration: 7);
        using var firstPlan = state.PrepareRollbackLatch(
            RatchetPersistenceLease.CreateDarkForTests(
                state.StorageGeneration, state.StateCommitment.Span, 8, Bytes(88)),
            Bytes(82), Bytes(83));
        using var secondPlan = state.PrepareRollbackLatch(
            RatchetPersistenceLease.CreateDarkForTests(
                state.StorageGeneration, state.StateCommitment.Span, 8, Bytes(89)),
            Bytes(82), Bytes(83));
        var proofForFirst = DurableSuccess(firstPlan);

        var error = Assert.Throws<MessagingCryptoException>(() => secondPlan.Commit(proofForFirst));

        Assert.Equal(MessagingCryptoError.CasConflict, error.Error);
    }

    [Fact]
    public async Task TransitionPlan_IsSingleConsumerUnderConcurrency()
    {
        using var state = CreateState();
        using var plan = state.PrepareSend(
            new ScriptedProvider(), Persistence(state), Bytes(80), Bytes(81), Bytes(11));
        var proofs = Enumerable.Range(0, 16).Select(_ => DurableSuccess(plan)).ToArray();
        var attempts = await Task.WhenAll(Enumerable.Range(0, 16).Select(index => Task.Run(() =>
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
        Assert.Equal(1, attempts.Count(static value => value));
    }

    [Fact]
    public void StateBindingAndPredecessorCommitmentCoverLineageAxes()
    {
        using var first = CreateState();
        var changedBinding = new RatchetStateBinding(
            MessagingCryptoConstants.Suite,
            Bytes(40), Bytes64(41), Bytes(42), 6, Bytes(43), Bytes(44), 9, Bytes(45));
        using var second = CreateState(binding: changedBinding);
        Assert.NotEqual(first.Binding.Commitment.ToArray(), second.Binding.Commitment.ToArray());
        Assert.NotEqual(first.StateCommitment.ToArray(), second.StateCommitment.ToArray());

        var wrong = RatchetPersistenceLease.CreateDarkForTests(
            first.StorageGeneration, second.StateCommitment.Span, first.StorageGeneration,
            second.StateCommitment.Span);
        var error = Assert.Throws<MessagingCryptoException>(() => first.PrepareSend(
            new ScriptedProvider(), wrong, Bytes(80), Bytes(81), Bytes(12)));
        Assert.Equal(MessagingCryptoError.CasConflict, error.Error);

        using var stricterPolicy = CreateState(maximumWithoutFresh: 31);
        Assert.NotEqual(first.StateCommitment.ToArray(), stricterPolicy.StateCommitment.ToArray());
    }

    [Fact]
    public void DedupLeaseRejectsCrossSessionCounterHeaderAndEnvelopeSubstitutionBeforeProvider()
    {
        using var first = CreateState();
        var otherBinding = new RatchetStateBinding(
            MessagingCryptoConstants.Suite,
            Bytes(90), Bytes64(41), Bytes(42), 5, Bytes(43), Bytes(44), 9, Bytes(45));
        using var second = CreateState(binding: otherBinding);
        var provider = new ScriptedProvider();
        var target = new RatchetCounterTuple(0, 1, 1);
        var header = Bytes(12);
        var envelope = Bytes(13);

        Assert.Equal(MessagingCryptoError.ReplayConflict, Assert.Throws<MessagingCryptoException>(() =>
            second.PrepareReceive(provider, Persistence(second),
                FreshDedup(first, target, header, envelope, 91),
                target, header, envelope)).Error);
        Assert.Equal(MessagingCryptoError.ReplayConflict, Assert.Throws<MessagingCryptoException>(() =>
            first.PrepareReceive(provider, Persistence(first),
                FreshDedup(first, new RatchetCounterTuple(1, 1, 2), header, envelope, 92),
                target, header, envelope)).Error);
        Assert.Equal(MessagingCryptoError.ReplayConflict, Assert.Throws<MessagingCryptoException>(() =>
            first.PrepareReceive(provider, Persistence(first),
                FreshDedup(first, target, Bytes(14), envelope, 93),
                target, header, envelope)).Error);
        Assert.Equal(MessagingCryptoError.ReplayConflict, Assert.Throws<MessagingCryptoException>(() =>
            first.PrepareReceive(provider, Persistence(first),
                FreshDedup(first, target, header, Bytes(15), 94),
                target, header, envelope)).Error);
        Assert.Equal(0, provider.ReceiveCalls);
    }

    [Fact]
    public void WrongExactJournalOperationDedupOrTerminalReceiptCannotReleaseSecrets()
    {
        using var state = CreateState();
        using (var send = state.PrepareSend(
                   new ScriptedProvider(), Persistence(state), Bytes(80), Bytes(81), Bytes(16)))
        {
            var error = Assert.Throws<MessagingCryptoException>(() =>
                send.Commit(DurableSuccess(send, operationId: Bytes(99))));
            Assert.Equal(MessagingCryptoError.CasConflict, error.Error);
        }

        var target = new RatchetCounterTuple(0, 1, 1);
        var header = Bytes(17);
        var envelope = Bytes(18);
        using (var receive = state.PrepareReceive(
                   new ScriptedProvider(), Persistence(state),
                   FreshDedup(state, target, header, envelope, 95),
                   target, header, envelope))
        {
            var error = Assert.Throws<MessagingCryptoException>(() =>
                receive.Commit(DurableSuccess(receive, dedupCommitment: Bytes(99))));
            Assert.Equal(MessagingCryptoError.CasConflict, error.Error);
        }

        using var rollbackState = CreateState(storageGeneration: 7);
        using var latch = rollbackState.PrepareRollbackLatch(
            Persistence(rollbackState, latest: 8), Bytes(82), Bytes(83));
        var terminal = Assert.Throws<MessagingCryptoException>(() =>
            latch.Commit(DurableSuccess(latch, terminalCommitment: Bytes(99))));
        Assert.Equal(MessagingCryptoError.CasConflict, terminal.Error);
    }

    [Fact]
    public async Task DisposeAndPrepareHaveLinearLockOrdering()
    {
        var state = CreateState();
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var provider = new BlockingProvider(entered, release);
        var prepare = Task.Run(() => state.PrepareSend(
            provider, Persistence(state), Bytes(80), Bytes(81), Bytes(19)));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        var dispose = Task.Run(state.Dispose);
        Assert.NotSame(dispose, await Task.WhenAny(dispose, Task.Delay(100)));
        release.Set();

        using var plan = await prepare;
        await dispose;
        var error = Assert.Throws<MessagingCryptoException>(() => state.PrepareSend(
            new ScriptedProvider(), Persistence(state), Bytes(80), Bytes(81), Bytes(20)));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, error.Error);
    }

    [Fact]
    public void ExactSerializedStateAccounting_IsClosedWithoutPublicSecretSurface()
    {
        Assert.Equal(2 * 1024 * 1024, MessagingCryptoConstants.MaximumDurableRatchetStateBytes);
        Assert.True(typeof(TripleRatchetDurableStateCodec).IsNotPublic);
        Assert.DoesNotContain(typeof(TripleRatchetState).GetProperties(), static property =>
            property.Name.Contains("SerializedSize", StringComparison.Ordinal));
    }

    private static TripleRatchetState CreateState(
        int maximumWithoutFresh = 32,
        ulong storageGeneration = 0,
        RatchetStateBinding? binding = null)
    {
        var receive = Bytes(60);
        var send = Bytes(61);
        var opaque = new byte[64];
        receive.CopyTo(opaque, 0);
        send.CopyTo(opaque, 32);
        return TripleRatchetState.Create(
            binding ?? CreateBinding(), opaque, receive, send,
            0, 0, storageGeneration, maximumWithoutFresh);
    }

    private static void AssertStateDisposed(TripleRatchetState state)
    {
        var error = Assert.Throws<MessagingCryptoException>(() => state.PrepareSend(
            new ScriptedProvider(), Persistence(state), Bytes(80), Bytes(81), Bytes(29)));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, error.Error);
    }

    private static RatchetStateBinding CreateBinding() => new(
        MessagingCryptoConstants.Suite,
        Bytes(40), Bytes64(41), Bytes(42), 5, Bytes(43), Bytes(44), 9, Bytes(45));

    private static RatchetPersistenceLease Persistence(TripleRatchetState state, ulong? latest = null)
    {
        var latestCommitment = latest.HasValue && latest.Value > state.StorageGeneration
            ? Bytes(88)
            : state.StateCommitment.ToArray();
        return RatchetPersistenceLease.CreateDarkForTests(
            state.StorageGeneration,
            state.StateCommitment.Span,
            latest ?? state.StorageGeneration,
            latestCommitment);
    }

    private static RatchetDeduplicationLease FreshDedup(
        TripleRatchetState state,
        RatchetCounterTuple target,
        ReadOnlySpan<byte> headerHash,
        ReadOnlySpan<byte> envelopeHash,
        byte value,
        ulong journalGeneration = 0) =>
        RatchetDeduplicationLease.CreateDarkForTests(
            RatchetDeduplicationOutcome.Fresh,
            state.Binding.Commitment.Span, state.Binding.SessionId.Span, target,
            Bytes(value), headerHash, envelopeHash, journalGeneration,
            Bytes(70), Bytes(71), true);

    private static RatchetDeduplicationLease ExactReplayDedup(
        TripleRatchetState state,
        RatchetCounterTuple target,
        ReadOnlySpan<byte> headerHash,
        ReadOnlySpan<byte> envelopeHash,
        byte value,
        ulong journalGeneration) =>
        RatchetDeduplicationLease.CreateDarkForTests(
            RatchetDeduplicationOutcome.ExactReplay,
            state.Binding.Commitment.Span, state.Binding.SessionId.Span, target,
            Bytes(value), headerHash, envelopeHash, journalGeneration,
            Bytes(70), Bytes(71), true);

    private static byte[] Bytes(byte value) => Enumerable.Repeat(value, 32).ToArray();
    private static byte[] Bytes64(byte value) => Enumerable.Repeat(value, 64).ToArray();

    private static DurableRatchetTransactionSuccessCapability DurableSuccess(
        TripleRatchetTransitionPlan plan,
        byte[]? operationId = null,
        byte[]? journalPredecessor = null,
        byte[]? deletionManifest = null,
        byte[]? terminalCommitment = null,
        byte[]? dedupCommitment = null,
        byte[]? pqFenceCommitment = null)
    {
        var generation = plan.ProposedGeneration ??
            throw new InvalidOperationException("Fresh ratchet plan has no proposed generation.");
        var receipt = ExactRatchetJournalReceipt.CreateDarkForTests(
            operationId ?? plan.OperationId.ToArray(),
            journalPredecessor ?? plan.JournalPredecessor.ToArray(),
            plan.DatabaseCas,
            plan.CheckpointCas,
            generation,
            plan.ProposedStateCommitment.Span,
            terminalCommitment ?? plan.TerminalStateCommitment.ToArray(),
            deletionManifest ?? plan.DeletionManifestCommitment.ToArray(),
            dedupCommitment ?? plan.DeduplicationMutationCommitment.ToArray(),
            pqFenceCommitment ?? plan.PqFenceMutationCommitment.ToArray(),
            durablyCommitted: true);
        return DurableRatchetTransactionSuccessCapability.CreateDarkForTests(
            receipt, atomicTransactionCommitted: true);
    }

    private static RatchetComponentKeyMaterial CreateOwnedKey(ulong ecN)
    {
        var prior = SHA256.HashData(Encoding.ASCII.GetBytes($"prior{ecN}"));
        var next = SHA256.HashData(Encoding.ASCII.GetBytes($"next{ecN}"));
        return new RatchetComponentKeyMaterial(
            new RatchetCounterTuple(ecN, 1, ecN + 1),
            SHA256.HashData(Encoding.ASCII.GetBytes($"ec-owned{ecN}")),
            SHA256.HashData(Encoding.ASCII.GetBytes($"pq-owned{ecN}")),
            new PqStepEvidence(prior, next, false));
    }

    private sealed class ScriptedProvider : ITripleRatchetComponentProvider
    {
        internal Func<ulong, bool> FreshContribution { get; init; } = static _ => false;
        internal bool ReusePqTuple { get; init; }
        internal bool ReusePqKey { get; init; }
        internal bool BreakFirstPredecessor { get; init; }
        internal byte[]? SendHeaderNetworkOverride { get; init; }
        internal RatchetCounterTuple? SendHeaderCounterOverride { get; init; }
        internal int SendCalls { get; private set; }
        internal int ReceiveCalls { get; private set; }
        internal int LastExactDtr2Length { get; private set; }

        public RatchetComponentTransition PrepareSend(
            ReadOnlySpan<byte> currentOpaqueState,
            RatchetEcChainCursor sendCursor,
            ReadOnlySpan<byte> networkId,
            PqInjectionSchedule pqSchedule)
        {
            SendCalls++;
            var receive = currentOpaqueState[..32].ToArray();
            var prior = currentOpaqueState[32..64].ToArray();
            var nextSendEcN = sendCursor.NextN;
            var key = Key(
                sendCursor.Chain,
                nextSendEcN,
                prior,
                FreshContribution(nextSendEcN),
                1,
                ReusePqTuple ? 1UL : nextSendEcN + 1);
            var next = new byte[64];
            receive.CopyTo(next, 0);
            key.PqEvidence.NextStateCommitment.CopyTo(next.AsSpan(32));
            byte[] exactDtr2 = [];
            if (!networkId.IsEmpty)
            {
                var counters = SendHeaderCounterOverride ?? key.Counters;
                exactDtr2 = Dtr2Codec.EncodeEmbedded(new Dtr2Record(
                    SendHeaderNetworkOverride ?? networkId.ToArray(),
                    counters.EcChain.ToArray(),
                    ecPreviousSendingChainLength: 0,
                    ecMessageNumber: counters.EcN,
                    sckaSendingEpoch: counters.SckaEpoch,
                    sckaPreviousSendingChainLength: 0,
                    sckaMessageNumber: counters.SckaN,
                    braidEpoch: 1,
                    braidMessage: Dtr2BraidMessage.None()));
            }
            return new RatchetComponentTransition(next, [key], exactDtr2);
        }

        public RatchetComponentTransition PrepareReceive(
            ReadOnlySpan<byte> currentOpaqueState,
            RatchetEcChainCursor receiveCursor,
            RatchetCounterTuple target,
            ReadOnlySpan<byte> exactDtr2,
            PqInjectionSchedule pqSchedule)
        {
            ReceiveCalls++;
            LastExactDtr2Length = exactDtr2.Length;
            var prior = currentOpaqueState[..32].ToArray();
            var send = currentOpaqueState[32..64].ToArray();
            var keys = new List<RatchetComponentKeyMaterial>();
            var changesChain = target.EcChain != receiveCursor.Chain;
            var previousSendingChainLength = receiveCursor.NextN;
            if (changesChain && !exactDtr2.IsEmpty)
                previousSendingChainLength = Dtr2Codec.DecodeEmbedded(exactDtr2).EcPreviousSendingChainLength;
            var oldGap = changesChain
                ? checked(previousSendingChainLength - receiveCursor.NextN)
                : 0;
            var totalGap = checked(oldGap + (changesChain ? target.EcN : target.EcN - receiveCursor.NextN));
            var nextSckaN = checked(target.SckaN - totalGap);
            for (var index = 0UL; index < oldGap; index++)
            {
                var ecN = checked(receiveCursor.NextN + index);
                var evidencePrior = prior;
                if (BreakFirstPredecessor && index == 0)
                    evidencePrior = Bytes(99);
                var sckaN = ReusePqTuple ? 1UL : nextSckaN++;
                var key = Key(
                    receiveCursor.Chain, ecN, evidencePrior,
                    FreshContribution(ecN), target.SckaEpoch, sckaN);
                keys.Add(key);
                prior = key.PqEvidence.NextStateCommitment.ToArray();
            }
            var firstNewN = changesChain ? 0UL : receiveCursor.NextN;
            for (var ecN = firstNewN; ecN <= target.EcN; ecN++)
            {
                var evidencePrior = prior;
                if (BreakFirstPredecessor && keys.Count == 0)
                    evidencePrior = Bytes(99);
                var sckaN = ReusePqTuple ? 1UL : nextSckaN++;
                var key = Key(
                    target.EcChain, ecN, evidencePrior,
                    FreshContribution(ecN), target.SckaEpoch, sckaN);
                keys.Add(key);
                prior = key.PqEvidence.NextStateCommitment.ToArray();
            }
            var next = new byte[64];
            prior.CopyTo(next, 0);
            send.CopyTo(next, 32);
            return new RatchetComponentTransition(next, keys.ToArray());
        }

        private RatchetComponentKeyMaterial Key(
            RatchetEcChainId ecChain,
            ulong ecN,
            ReadOnlySpan<byte> prior,
            bool fresh,
            ulong sckaEpoch,
            ulong sckaN)
        {
            Span<byte> evidenceInput = stackalloc byte[32 + 8 + 8 + 1];
            prior.CopyTo(evidenceInput);
            BinaryPrimitives.WriteUInt64BigEndian(evidenceInput[32..], ecN);
            BinaryPrimitives.WriteUInt64BigEndian(evidenceInput[40..], sckaN);
            evidenceInput[48] = fresh ? (byte)1 : (byte)0;
            var next = SHA256.HashData(evidenceInput);
            return new RatchetComponentKeyMaterial(
                new RatchetCounterTuple(ecChain, ecN, sckaEpoch, sckaN),
                SHA256.HashData(Encoding.ASCII.GetBytes($"ec{ecN}")),
                SHA256.HashData(Encoding.ASCII.GetBytes(ReusePqKey ? "pq-reused" : $"pq{ecN}")),
                new PqStepEvidence(prior, next, fresh));
        }
    }

    private sealed class BlockingProvider(
        ManualResetEventSlim entered,
        ManualResetEventSlim release) : ITripleRatchetComponentProvider
    {
        public RatchetComponentTransition PrepareSend(
            ReadOnlySpan<byte> currentOpaqueState,
            RatchetEcChainCursor sendCursor,
            ReadOnlySpan<byte> networkId,
            PqInjectionSchedule pqSchedule)
        {
            entered.Set();
            if (!release.Wait(TimeSpan.FromSeconds(5)))
                throw new TimeoutException("The concurrency test did not release the provider.");
            return new ScriptedProvider().PrepareSend(currentOpaqueState, sendCursor, networkId, pqSchedule);
        }

        public RatchetComponentTransition PrepareReceive(
            ReadOnlySpan<byte> currentOpaqueState,
            RatchetEcChainCursor receiveCursor,
            RatchetCounterTuple target,
            ReadOnlySpan<byte> exactDtr2,
            PqInjectionSchedule pqSchedule) =>
            throw new NotSupportedException();
    }

    private sealed class ThrowingProvider : ITripleRatchetComponentProvider
    {
        public RatchetComponentTransition PrepareSend(ReadOnlySpan<byte> currentOpaqueState, RatchetEcChainCursor sendCursor, ReadOnlySpan<byte> networkId, PqInjectionSchedule pqSchedule) =>
            throw new InvalidOperationException("Exact replay must not invoke provider.");
        public RatchetComponentTransition PrepareReceive(ReadOnlySpan<byte> currentOpaqueState, RatchetEcChainCursor receiveCursor, RatchetCounterTuple target, ReadOnlySpan<byte> exactDtr2, PqInjectionSchedule pqSchedule) =>
            throw new InvalidOperationException("Exact replay must not invoke provider.");
    }
}
