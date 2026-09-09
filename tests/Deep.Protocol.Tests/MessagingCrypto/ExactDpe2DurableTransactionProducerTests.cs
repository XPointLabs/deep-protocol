using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed partial class TripleRatchetTransactionsTests
{
    [Fact]
    public async Task DurableProducer_Send_ReusesExactPlanAcrossLostCallbackAndReleasesOnlyAfterCommit()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var priorTrs1 = TripleRatchetDurableStateCodec.Encode(state);
        var dmc2 = CreateExactSendDmc2();
        var context = DurableContext(state);
        using var prepared = ExactDpe2DurableTransactionProducer.PrepareSendForTests(
            priorTrs1,
            state,
            new ScriptedProvider(),
            context,
            dmc2,
            Dpe2Network(),
            Bytes(54));
        var authority = new RecordingAuthority(
            new IOException("lost durable callback"),
            ExactDpe2DurableCommitDisposition.Committed);

        await Assert.ThrowsAsync<IOException>(async () =>
            await prepared.CommitAsync(authority));

        Assert.Equal(1, authority.Calls);
        Assert.NotNull(authority.FirstEnvelope);

        using var success = await prepared.CommitAsync(authority);
        var exactEnvelope = success.TakeExactEnvelope();
        try
        {
            Assert.Equal(2, authority.Calls);
            Assert.Equal(authority.FirstEnvelope, authority.SecondEnvelope);
            Assert.Equal(authority.FirstNextTrs1, authority.SecondNextTrs1);
            Assert.Equal(authority.SecondEnvelope, exactEnvelope);
            var decoded = Dpe2Codec.Decode(exactEnvelope);
            Assert.Equal(
                MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(decoded),
                success.ExactEnvelopeHash.ToArray());
            Assert.Equal(Bytes(54), success.OperationId.ToArray());

            using var next = TripleRatchetDurableStateCodec.Decode(authority.SecondNextTrs1!);
            Assert.Equal(1UL, next.StorageGeneration);
            Assert.Equal(1UL, next.NextSendEcN);
            Assert.Throws<InvalidOperationException>(() => _ = prepared.PersistencePlanForTests);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactEnvelope);
            CryptographicOperations.ZeroMemory(priorTrs1);
            CryptographicOperations.ZeroMemory(dmc2);
            authority.Dispose();
        }
    }

    [Fact]
    public async Task DurableProducer_Receive_BindsExactEnvelopeAndReleasesCanonicalDmc2AfterCommit()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var priorTrs1 = TripleRatchetDurableStateCodec.Encode(state);
        var exactDpe2 = CreateExactDpe2();
        var context = DurableContext(state);
        using var prepared = ExactDpe2DurableTransactionProducer.PrepareReceiveForTests(
            priorTrs1,
            state,
            new ScriptedProvider(),
            context,
            exactDpe2);
        var authority = new RecordingAuthority(ExactDpe2DurableCommitDisposition.Committed);

        Assert.True(prepared.PersistencePlanForTests.HasStateMutation);
        Assert.Equal(exactDpe2, prepared.PersistencePlanForTests.ExactEnvelope.ToArray());
        Assert.Equal(
            prepared.PersistencePlanForTests.DeletionManifestCommitment.ToArray(),
            prepared.PersistencePlanForTests.MessageKeyDeletionEvidence.ToArray());
        Assert.NotEmpty(prepared.PersistencePlanForTests.DeduplicationMutationCommitment.ToArray());

        using var success = await prepared.CommitAsync(authority);
        var exactDmc2 = success.TakeAuthenticatedDmc2();
        try
        {
            Assert.Equal(ExactDpe2ReceiveSuccessOutcome.Fresh, success.Outcome);
            var parsed = ApplicationCoreCodec.DecodeDmc2(exactDmc2);
            Assert.Equal(Dmc2ContentKind.MessageCreate, parsed.ContentKind);
            Assert.Equal(Dpe2Network(), parsed.NetworkId.ToArray());
            Assert.Equal(Bytes(34), parsed.SenderDeviceId.ToArray());
            Assert.Equal(exactDpe2, authority.FirstEnvelope);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactDmc2);
            CryptographicOperations.ZeroMemory(priorTrs1);
            CryptographicOperations.ZeroMemory(exactDpe2);
            authority.Dispose();
        }
    }

    [Fact]
    public async Task DurableProducer_ReceiveExactReplay_RequiresAuthorityReplayAndNeverReleasesPlaintext()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var priorTrs1 = TripleRatchetDurableStateCodec.Encode(state);
        var exactDpe2 = CreateExactDpe2();
        var context = DurableContext(
            state,
            ExactDpe2ReceiveReplayDisposition.ExactReplay,
            journalGeneration: 7);
        using var prepared = ExactDpe2DurableTransactionProducer.PrepareReceiveForTests(
            priorTrs1,
            state,
            new ThrowingProvider(),
            context,
            exactDpe2);
        var authority = new RecordingAuthority(ExactDpe2DurableCommitDisposition.ExactReplay);

        Assert.False(prepared.PersistencePlanForTests.HasStateMutation);
        Assert.Empty(prepared.PersistencePlanForTests.NextTrs1.ToArray());
        Assert.Empty(prepared.PersistencePlanForTests.MessageKeyDeletionEvidence.ToArray());

        using var success = await prepared.CommitAsync(authority);

        Assert.Equal(ExactDpe2ReceiveSuccessOutcome.ExactReplay, success.Outcome);
        Assert.False(success.HasAuthenticatedDmc2);
        Assert.Throws<InvalidOperationException>(() => success.TakeAuthenticatedDmc2());
        Assert.Equal(0UL, state.StorageGeneration);
        CryptographicOperations.ZeroMemory(priorTrs1);
        CryptographicOperations.ZeroMemory(exactDpe2);
        authority.Dispose();
    }

    [Theory]
    [InlineData(ExactDpe2DurableCommitDisposition.CasConflict)]
    [InlineData(ExactDpe2DurableCommitDisposition.ForkLatched)]
    [InlineData(ExactDpe2DurableCommitDisposition.RollbackLatched)]
    public async Task DurableProducer_TerminalAuthorityDispositionFailsClosed(
        ExactDpe2DurableCommitDisposition disposition)
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var priorTrs1 = TripleRatchetDurableStateCodec.Encode(state);
        var dmc2 = CreateExactSendDmc2();
        using var prepared = ExactDpe2DurableTransactionProducer.PrepareSendForTests(
            priorTrs1,
            state,
            new ScriptedProvider(),
            DurableContext(state),
            dmc2,
            Dpe2Network(),
            Bytes(54));
        using var authority = new RecordingAuthority(disposition);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await prepared.CommitAsync(authority));
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await prepared.CommitAsync(authority));
        Assert.Equal(0UL, state.StorageGeneration);

        CryptographicOperations.ZeroMemory(priorTrs1);
        CryptographicOperations.ZeroMemory(dmc2);
    }

    [Fact]
    public void DurableProducer_HostileSendSizeRejectsBeforeProviderOrPersistencePlan()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var priorTrs1 = TripleRatchetDurableStateCodec.Encode(state);
        var provider = new ScriptedProvider();

        Assert.Throws<MessagingCryptoException>(() =>
            ExactDpe2DurableTransactionProducer.PrepareSendForTests(
                priorTrs1,
                state,
                provider,
                DurableContext(state),
                new byte[281],
                Dpe2Network(),
                Bytes(54)));

        Assert.Equal(0, provider.SendCalls);
        Assert.Equal(0UL, state.StorageGeneration);
        CryptographicOperations.ZeroMemory(priorTrs1);
    }

    [Fact]
    public async Task DurableProducer_RejectsReceiptFromAnotherExactPlanOrCallbackAttempt()
    {
        using var firstState = CreateState(binding: CreateDpe2Binding());
        using var secondState = CreateState(binding: CreateDpe2Binding());
        var firstTrs1 = TripleRatchetDurableStateCodec.Encode(firstState);
        var secondTrs1 = TripleRatchetDurableStateCodec.Encode(secondState);
        var dmc2 = CreateExactSendDmc2();
        using var first = ExactDpe2DurableTransactionProducer.PrepareSendForTests(
            firstTrs1, firstState, new ScriptedProvider(), DurableContext(firstState),
            dmc2, Dpe2Network(), Bytes(54));
        using var second = ExactDpe2DurableTransactionProducer.PrepareSendForTests(
            secondTrs1, secondState, new ScriptedProvider(), DurableContext(secondState),
            dmc2, Dpe2Network(), Bytes(55));
        var foreignCompletion = new ExactDpe2DurableCommitCompletion(first.PersistencePlanForTests);
        var foreignReceipt = foreignCompletion.Complete(ExactDpe2DurableCommitDisposition.Committed);
        var authority = new ForeignReceiptAuthority(foreignReceipt);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await second.CommitAsync(authority));
        Assert.Equal(0UL, secondState.StorageGeneration);

        CryptographicOperations.ZeroMemory(firstTrs1);
        CryptographicOperations.ZeroMemory(secondTrs1);
        CryptographicOperations.ZeroMemory(dmc2);
    }

    [Fact]
    public void DurablePersistencePlan_HasNoPublicConstructorOrMutationSurface()
    {
        Assert.Empty(typeof(ExactDpe2DurablePersistencePlan).GetConstructors());
        Assert.All(
            typeof(ExactDpe2DurablePersistencePlan).GetProperties(BindingFlags.Public | BindingFlags.Instance),
            property => Assert.False(property.CanWrite));
        Assert.DoesNotContain(
            typeof(ExactDpe2DurablePersistencePlan).GetMethods(BindingFlags.Public | BindingFlags.Instance),
            method => method.Name.Contains("Create", StringComparison.Ordinal) ||
                      method.Name.Contains("Set", StringComparison.Ordinal));
    }

    private static ExactDpe2DurableTransitionContext DurableContext(
        TripleRatchetState state,
        ExactDpe2ReceiveReplayDisposition replay = ExactDpe2ReceiveReplayDisposition.Fresh,
        ulong journalGeneration = 0) =>
        new(
            state.StorageGeneration,
            state.StateCommitment.Span,
            state.StorageGeneration,
            state.StateCommitment.Span,
            journalGeneration,
            Bytes(70),
            Bytes(71),
            replay);

    private sealed class RecordingAuthority : IExactDpe2DurableTransactionAuthority, IDisposable
    {
        private readonly Queue<object> _outcomes;

        internal RecordingAuthority(params object[] outcomes) => _outcomes = new Queue<object>(outcomes);

        internal int Calls { get; private set; }
        internal byte[]? FirstEnvelope { get; private set; }
        internal byte[]? SecondEnvelope { get; private set; }
        internal byte[]? FirstNextTrs1 { get; private set; }
        internal byte[]? SecondNextTrs1 { get; private set; }

        public ValueTask<ExactDpe2DurableCommitReceipt> CommitAsync(
            ExactDpe2DurablePersistencePlan plan,
            ExactDpe2DurableCommitCompletion completion,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            if (Calls == 1)
            {
                FirstEnvelope = plan.ExactEnvelope.ToArray();
                FirstNextTrs1 = plan.NextTrs1.ToArray();
            }
            else
            {
                SecondEnvelope = plan.ExactEnvelope.ToArray();
                SecondNextTrs1 = plan.NextTrs1.ToArray();
            }
            var outcome = _outcomes.Dequeue();
            if (outcome is Exception exception) throw exception;
            return ValueTask.FromResult(
                completion.Complete((ExactDpe2DurableCommitDisposition)outcome));
        }

        public void Dispose()
        {
            Zero(FirstEnvelope); Zero(SecondEnvelope); Zero(FirstNextTrs1); Zero(SecondNextTrs1);
        }

        private static void Zero(byte[]? value)
        {
            if (value is not null) CryptographicOperations.ZeroMemory(value);
        }
    }

    private sealed class ForeignReceiptAuthority(ExactDpe2DurableCommitReceipt receipt) :
        IExactDpe2DurableTransactionAuthority
    {
        public ValueTask<ExactDpe2DurableCommitReceipt> CommitAsync(
            ExactDpe2DurablePersistencePlan plan,
            ExactDpe2DurableCommitCompletion completion,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(receipt);
    }
}
