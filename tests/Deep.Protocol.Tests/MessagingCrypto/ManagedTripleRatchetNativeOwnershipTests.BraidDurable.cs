using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed partial class ManagedTripleRatchetNativeOwnershipTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task BraidDurableBoundary_FourFlightsResumeBothExhaustedSenders(bool deliverHeaderFirst)
    {
        using var pair = new RecoveryPair();
        var pending = new List<(bool Alice, byte Id, byte[] Cipher)>();
        try
        {
            for (byte id = 1; id <= 32; id++) pending.Add((true, id, await pair.Alice.Send(RecoveryMessage(true, id))));
            if (deliverHeaderFirst) await Verify(pair.Bob, pending[0].Cipher, RecoveryMessage(true, 1));
            for (byte id = 80; id < 112; id++) pending.Add((false, id, await pair.Bob.Send(RecoveryMessage(false, id))));
            await RequirePqBlocked(pair.Alice, true); await RequirePqBlocked(pair.Bob, false);
            foreach (var (sender, recipient, id) in new[] {
                         (pair.Alice, pair.Bob, (byte)200), (pair.Bob, pair.Alice, (byte)201),
                         (pair.Alice, pair.Bob, (byte)202), (pair.Bob, pair.Alice, (byte)203) })
            {
                var frame = await sender.SendDurableControl(Bytes(32, id));
                Assert.False(await recipient.ReceiveDurableControl(frame));
                var before = recipient.CommittedDigest();
                Assert.True(await recipient.ReceiveDurableControl(frame));
                Assert.Equal(before, recipient.CommittedDigest());
            }
            Assert.Equal(32, pair.Alice.SendMessagesSincePqInjection);
            Assert.Equal(32, pair.Bob.SendMessagesSincePqInjection);
            await ResumeBidirectionalFreshData(pair);
            for (var index = 0; index < pending.Count; index++)
            {
                if (deliverHeaderFirst && index == 0) continue;
                var entry = pending[index];
                await Verify(entry.Alice ? pair.Bob : pair.Alice, entry.Cipher, RecoveryMessage(entry.Alice, entry.Id));
            }
        }
        finally { foreach (var entry in pending) CryptographicOperations.ZeroMemory(entry.Cipher); }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task BraidDurableBoundary_UnknownCommitRetriesSamePreparedBytesWithoutNativeReauthor()
    {
        using var pair = new RecoveryPair();
        using var prepared = pair.Alice.PrepareDurableControl(Bytes(32, 200));
        byte[]? original = null;
        var calls = 0;
        var authority = new ControlCallback(async (plan, completion, ct) =>
        {
            calls++;
            if (original is null) original = plan.ExactControl.ToArray();
            else Assert.Equal(original, plan.ExactControl.ToArray());
            var receipt = await ((IExactBraidRecoveryDurableTransactionAuthority)pair.Alice).CommitAsync(plan, completion, ct);
            if (calls == 1) throw new IOException("Fixture lost callback after the atomic commit.");
            return receipt;
        });
        await Assert.ThrowsAsync<IOException>(() => prepared.CommitAsync(authority).AsTask());
        var committedDigest = pair.Alice.CommittedDigest();
        using var result = await prepared.CommitAsync(authority);
        Assert.True(result.IsExactReplay);
        Assert.Equal(original, result.TakeExactControl());
        Assert.Equal(committedDigest, pair.Alice.CommittedDigest());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => prepared.CommitAsync(authority).AsTask());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task BraidDurableBoundary_CancelledBeforeCallbackKeepsIdenticalCandidate()
    {
        using var pair = new RecoveryPair();
        using var prepared = pair.Alice.PrepareDurableControl(Bytes(32, 200));
        var called = false;
        var authority = new ControlCallback((plan, completion, ct) =>
        { called = true; return ((IExactBraidRecoveryDurableTransactionAuthority)pair.Alice).CommitAsync(plan, completion, ct); });
        var before = pair.Alice.CommittedDigest();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => prepared.CommitAsync(authority, new(true)).AsTask());
        Assert.False(called); Assert.Equal(before, pair.Alice.CommittedDigest());
        using var result = await prepared.CommitAsync(authority);
        Assert.Equal(Dbr2Codec.TotalBytes, result.TakeExactControl().Length);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task BraidDurableBoundary_ReceiptsFromAnotherPlanOrCallbackReject(bool otherPlan)
    {
        using var pair = new RecoveryPair();
        using var prepared = pair.Alice.PrepareDurableControl(Bytes(32, 200));
        ExactBraidRecoveryCommitReceipt? stolen = null;
        var capture = new ControlCallback((plan, completion, ct) =>
        { stolen = completion.Complete(ExactDpe2DurableCommitDisposition.Committed); throw new IOException("Fixture interrupted callback."); });
        await Assert.ThrowsAsync<IOException>(() => prepared.CommitAsync(capture).AsTask());
        using var different = otherPlan ? pair.Alice.PrepareDurableControl(Bytes(32, 201)) : null;
        var before = pair.Alice.CommittedDigest();
        await Assert.ThrowsAsync<CryptographicException>(() => (different ?? prepared).CommitAsync(
            new ControlCallback((plan, completion, ct) => ValueTask.FromResult(stolen!))).AsTask());
        Assert.Equal(before, pair.Alice.CommittedDigest());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task BraidDurableBoundary_DisposeDuringCallbackDefersWipeAndBlocksSecondFlight()
    {
        using var pair = new RecoveryPair();
        using var prepared = pair.Alice.PrepareDurableControl(Bytes(32, 200));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        ExactBraidRecoveryPersistencePlan? captured = null;
        var authority = new ControlCallback(async (plan, completion, ct) =>
        {
            captured = plan; entered.SetResult(); await release.Task;
            return await ((IExactBraidRecoveryDurableTransactionAuthority)pair.Alice).CommitAsync(plan, completion, ct);
        });
        var running = prepared.CommitAsync(authority).AsTask();
        await entered.Task;
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => prepared.CommitAsync(authority).AsTask());
            prepared.Dispose(); Assert.NotEmpty(captured!.NextTrs1.ToArray());
        }
        finally { release.TrySetResult(); }
        using var success = await running;
        Assert.Equal(Dbr2Codec.TotalBytes, success.TakeExactControl().Length);
        Assert.Throws<ObjectDisposedException>(() => captured!.NextTrs1);
    }

    [Theory]
    [InlineData(ExactDpe2DurableCommitDisposition.CasConflict)]
    [InlineData(ExactDpe2DurableCommitDisposition.ForkLatched)]
    [InlineData(ExactDpe2DurableCommitDisposition.RollbackLatched)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task BraidDurableBoundary_TerminalRejectionDestroysCandidate(ExactDpe2DurableCommitDisposition disposition)
    {
        using var pair = new RecoveryPair();
        using var prepared = pair.Alice.PrepareDurableControl(Bytes(32, 200));
        var reject = new ControlCallback((plan, completion, ct) => ValueTask.FromResult(completion.Complete(disposition)));
        var before = pair.Alice.CommittedDigest();
        await Assert.ThrowsAsync<CryptographicException>(() => prepared.CommitAsync(reject).AsTask());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => prepared.CommitAsync(reject).AsTask());
        Assert.Equal(before, pair.Alice.CommittedDigest());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task BraidDurableBoundary_NativeReplayWithoutDurableRowIsNotReceiptAuthority()
    {
        using var pair = new RecoveryPair();
        var frame = pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 200));
        Assert.False(pair.Bob.ReceiveControl(pair.BobProvider, frame));
        var before = pair.Bob.CommittedDigest();
        await Assert.ThrowsAsync<MessagingCryptoException>(() => pair.Bob.ReceiveDurableControl(frame));
        Assert.Equal(before, pair.Bob.CommittedDigest());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task BraidDurableBoundary_ClaimedReplayRequiresActualOriginalAuthenticatedHistory()
    {
        using var pair = new RecoveryPair();
        var frame = await pair.Alice.SendDurableControl(Bytes(32, 200));
        Assert.False(await pair.Bob.ReceiveDurableControl(frame));
        var changed = frame.ToArray(); changed[^1] ^= 1;
        using var prepared = pair.Bob.PrepareDurableReceive(changed, true);
        var before = pair.Bob.CommittedDigest();
        await Assert.ThrowsAsync<CryptographicException>(() => prepared.CommitAsync(pair.Bob).AsTask());
        Assert.Equal(before, pair.Bob.CommittedDigest());
    }

    [Theory]
    [InlineData("state")]
    [InlineData("checkpoint")]
    [InlineData("journal")]
    [InlineData("send-replay")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public void BraidDurableBoundary_InvalidPredecessorRejectsBeforeNativeCommit(string fault)
    {
        using var pair = new RecoveryPair();
        pair.Alice.RejectControlContext(fault);
    }

    private sealed class ControlCallback(
        Func<ExactBraidRecoveryPersistencePlan, ExactBraidRecoveryCommitCompletion, CancellationToken,
            ValueTask<ExactBraidRecoveryCommitReceipt>> callback) : IExactBraidRecoveryDurableTransactionAuthority
    {
        public ValueTask<ExactBraidRecoveryCommitReceipt> CommitAsync(ExactBraidRecoveryPersistencePlan plan,
            ExactBraidRecoveryCommitCompletion completion, CancellationToken cancellationToken = default) =>
            callback(plan, completion, cancellationToken);
    }

    // Trusted Protocol boundary fixture only, not the production SQL/floor owner.
    private sealed partial class IsolatedAtomicMemory : IExactBraidRecoveryDurableTransactionAuthority
    {
        private sealed record ControlRow(ExactBraidRecoveryDurableDirection Direction, byte[] Frame,
            byte[] PriorStateHash, byte[] NextStateHash);
        private readonly Dictionary<string, ControlRow> controls = [];
        internal ExactBraidRecoveryPreparedTransition PrepareDurableControl(byte[] operation) =>
            ExactBraidRecoveryDurableTransactionProducer.PrepareSend(state, Context(false), Bytes(16, 5), operation);
        internal ExactBraidRecoveryPreparedTransition PrepareDurableReceive(byte[] frame, bool replay) =>
            ExactBraidRecoveryDurableTransactionProducer.PrepareReceive(state, Context(replay), Bytes(16, 5), frame);
        internal async Task<byte[]> SendDurableControl(byte[] operation)
        {
            using var prepared = PrepareDurableControl(operation);
            using var success = await prepared.CommitAsync(this);
            var frame = success.TakeExactControl();
            Assert.Throws<InvalidOperationException>(() => success.TakeExactControl());
            return frame;
        }
        internal async Task<bool> ReceiveDurableControl(byte[] frame)
        {
            var operation = Convert.ToHexString(Dbr2Codec.Decode(frame).OperationId.Span);
            using var prepared = PrepareDurableReceive(frame, controls.ContainsKey(operation));
            using var success = await prepared.CommitAsync(this);
            Assert.Throws<InvalidOperationException>(() => success.TakeExactControl());
            return success.IsExactReplay;
        }
        public ValueTask<ExactBraidRecoveryCommitReceipt> CommitAsync(ExactBraidRecoveryPersistencePlan plan,
            ExactBraidRecoveryCommitCompletion completion, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var operation = Convert.ToHexString(plan.OperationId.Span);
            var frame = plan.ExactControl.ToArray();
            Assert.Equal(SHA256.HashData(frame), plan.ExactControlHash.ToArray());
            Assert.Equal(SHA256.HashData(Dbr2Codec.GetAuthenticationInput(Dbr2Codec.Decode(frame))), plan.ExactHeaderHash.ToArray());
            if (controls.TryGetValue(operation, out var retained))
            {
                if (plan.Direction != retained.Direction || !frame.AsSpan().SequenceEqual(retained.Frame))
                    throw new CryptographicException("Changed fixture control replay.");
                if (plan.HasStateMutation)
                {
                    var prior = plan.PriorTrs1.ToArray(); var next = plan.NextTrs1.ToArray();
                    try { Assert.Equal(retained.PriorStateHash, SHA256.HashData(prior)); Assert.Equal(retained.NextStateHash, SHA256.HashData(next)); }
                    finally { CryptographicOperations.ZeroMemory(prior); CryptographicOperations.ZeroMemory(next); }
                }
                return ValueTask.FromResult(completion.Complete(ExactDpe2DurableCommitDisposition.ExactReplay));
            }
            if (!plan.HasStateMutation) throw new CryptographicException("Claimed replay has no fixture history.");
            var priorBytes = plan.PriorTrs1.ToArray(); var nextBytes = plan.NextTrs1.ToArray();
            try
            {
                Assert.Equal(state, priorBytes); Assert.Equal(journal, plan.JournalPredecessor.ToArray());
                Assert.Equal(journalGeneration, plan.ExpectedJournalGeneration);
                Assert.Equal(Generation + 1, plan.NextStateGeneration);
                Assert.NotEmpty(plan.DeletionManifestCommitment.ToArray());
                using var prior = TripleRatchetDurableStateCodec.Decode(priorBytes);
                using var next = TripleRatchetDurableStateCodec.Decode(nextBytes);
                Assert.Equal(prior.SendMessagesSincePqInjection, next.SendMessagesSincePqInjection);
                Assert.Equal(prior.ReceiveMessagesSincePqInjection, next.ReceiveMessagesSincePqInjection);
                Assert.Equal(prior.SendEcChain, next.SendEcChain); Assert.Equal(prior.NextSendEcN, next.NextSendEcN);
                Assert.Equal(prior.ReceiveEcChain, next.ReceiveEcChain); Assert.Equal(prior.NextExpectedReceiveEcN, next.NextExpectedReceiveEcN);
                Assert.Equal(prior.SendPqFrontier, next.SendPqFrontier); Assert.Equal(prior.ReceivePqFrontier, next.ReceivePqFrontier);
                Assert.Equal(prior.SkippedKeyCount, next.SkippedKeyCount);
                controls.Add(operation, new(plan.Direction, frame, SHA256.HashData(priorBytes), SHA256.HashData(nextBytes)));
                CryptographicOperations.ZeroMemory(state); state = nextBytes; nextBytes = [];
                CryptographicOperations.ZeroMemory(journal); journal = SHA256.HashData(frame); journalGeneration++;
                return ValueTask.FromResult(completion.Complete(ExactDpe2DurableCommitDisposition.Committed));
            }
            finally { CryptographicOperations.ZeroMemory(priorBytes); CryptographicOperations.ZeroMemory(nextBytes); }
        }
        internal void RejectControlContext(string fault)
        {
            using var current = ReadCurrentState();
            var commitment = current.StateCommitment.ToArray();
            if (fault == "state") commitment[0] ^= 1;
            var context = new ExactDpe2DurableTransitionContext(current.StorageGeneration, commitment,
                current.StorageGeneration + (fault == "checkpoint" ? 1UL : 0UL), current.StateCommitment.Span,
                fault == "journal" ? (ulong)long.MaxValue : journalGeneration, journal, SHA256.HashData(journal),
                fault == "send-replay" ? ExactDpe2ReceiveReplayDisposition.ExactReplay : ExactDpe2ReceiveReplayDisposition.Fresh);
            var before = CommittedDigest();
            Assert.Throws<MessagingCryptoException>(() => ExactBraidRecoveryDurableTransactionProducer.PrepareSend(
                state, context, Bytes(16, 5), Bytes(32, 200)));
            Assert.Equal(before, CommittedDigest());
        }
    }
}
