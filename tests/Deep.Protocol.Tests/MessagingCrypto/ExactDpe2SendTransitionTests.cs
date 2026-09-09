using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed partial class TripleRatchetTransactionsTests
{
    [Fact]
    public void ExactDpe2Send_ReleasesExactEnvelopeAndNextStateOnlyAfterAtomicDurableCommit()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var exactDmc2 = CreateExactSendDmc2();
        MessageKeyLease? capturedMessageKey = null;
        using var faultProbe = MessagingCryptoFaultInjection.InstallDarkForTests(
            new MessagingCryptoFaultProbe
            {
                OwnedDisposable = (name, value) =>
                {
                    if (name == "ratchet.plan.message-key")
                        capturedMessageKey = Assert.IsType<MessageKeyLease>(value);
                },
            });
        var provider = new ScriptedProvider();
        using var plan = ExactDpe2SendTransitionPlan.Prepare(
            exactDmc2,
            Dpe2Network(),
            state,
            provider,
            Persistence(state),
            Bytes(54),
            Bytes(70));

        Assert.Equal(1, provider.SendCalls);
        Assert.Contains(RatchetDeletionKind.MessageKeyAfterUse, plan.DeletionObligations);
        Assert.Contains(RatchetDeletionKind.PreviousStateAfterCommit, plan.DeletionObligations);
        Assert.Contains(RatchetDeletionKind.ProviderTransitionSecrets, plan.DeletionObligations);
        Assert.NotNull(capturedMessageKey);
        var deletedBeforeCommit = Assert.Throws<MessagingCryptoException>(() =>
            capturedMessageKey!.Use(static _ => { }));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, deletedBeforeCommit.Error);
        Assert.DoesNotContain(
            typeof(ExactDpe2SendTransitionPlan).GetProperties(),
            static property => property.Name.Equals("ExactEnvelope", StringComparison.Ordinal) ||
                               property.Name.Contains("Ciphertext", StringComparison.Ordinal));
        Assert.DoesNotContain(
            typeof(ExactDpe2SendTransitionPlan).GetMethods(),
            static method => method.Name.Contains("TakeExactEnvelope", StringComparison.Ordinal));

        using var commit = plan.Commit(DurableSendSuccess(plan));

        var disposed = Assert.Throws<MessagingCryptoException>(() =>
            capturedMessageKey.Use(static _ => { }));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, disposed.Error);
        Assert.True(commit.HasExactEnvelope);
        Assert.True(commit.HasNextState);
        var exactEnvelope = commit.TakeExactEnvelope();
        try
        {
            var envelope = Dpe2Codec.Decode(exactEnvelope);
            Assert.Equal(4513, exactEnvelope.Length);
            Assert.Equal(Dpe2Network(), envelope.NetworkId.ToArray());
            Assert.Equal(Bytes(40), envelope.SessionId.ToArray());
            Assert.Equal(Bytes(44), envelope.SenderDeviceId.ToArray());
            Assert.Equal(Bytes(34), envelope.RecipientDeviceId.ToArray());
            Assert.Equal(Bytes(54), envelope.OperationId.ToArray());
            Assert.Equal(0UL, envelope.RatchetHeader.EcMessageNumber);
            Assert.Equal(1UL, envelope.RatchetHeader.SckaSendingEpoch);
            Assert.Equal(1UL, envelope.RatchetHeader.SckaMessageNumber);
            Assert.Equal(
                plan.ExactEnvelopeHash.ToArray(),
                MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(envelope));
            AssertExactEnvelopeDecryptsTo(envelope, exactDmc2);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactEnvelope);
            CryptographicOperations.ZeroMemory(exactDmc2);
        }

        using var next = commit.TakeNextState();
        Assert.Equal(1UL, next.NextSendEcN);
        Assert.Equal(1UL, next.StorageGeneration);
        Assert.Equal(0UL, state.NextSendEcN);
        Assert.Equal(0UL, state.StorageGeneration);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExactDpe2Send_ProviderHeaderNetworkOrCounterSubstitutionFailsClosed(bool changeNetwork)
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var provider = new ScriptedProvider
        {
            SendHeaderNetworkOverride = changeNetwork ? Network(99) : null,
            SendHeaderCounterOverride = changeNetwork ? null : new RatchetCounterTuple(7, 1, 8),
        };
        var exactDmc2 = CreateExactSendDmc2();
        try
        {
            var error = Assert.Throws<MessagingCryptoException>(() =>
                ExactDpe2SendTransitionPlan.Prepare(
                    exactDmc2,
                    Dpe2Network(),
                    state,
                    provider,
                    Persistence(state),
                    Bytes(54),
                    Bytes(70)));

            Assert.Equal(MessagingCryptoError.TransitionRejected, error.Error);
            Assert.Equal(1, provider.SendCalls);
            Assert.Equal(0UL, state.NextSendEcN);
            Assert.Equal(0UL, state.StorageGeneration);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactDmc2);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExactDpe2Send_Dmc2NetworkOrSenderSubstitutionRejectsBeforeProvider(bool changeNetwork)
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var provider = new ScriptedProvider();
        var exactDmc2 = CreateExactSendDmc2(
            networkId: changeNetwork ? Network(99) : null,
            senderDeviceId: changeNetwork ? null : Bytes(98));
        try
        {
            var error = Assert.Throws<MessagingCryptoException>(() =>
                ExactDpe2SendTransitionPlan.Prepare(
                    exactDmc2,
                    Dpe2Network(),
                    state,
                    provider,
                    Persistence(state),
                    Bytes(54),
                    Bytes(70)));

            Assert.Equal(MessagingCryptoError.ReplayConflict, error.Error);
            Assert.Equal(0, provider.SendCalls);
            Assert.Equal(0UL, state.NextSendEcN);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactDmc2);
        }
    }

    [Fact]
    public void ExactDpe2Send_WrongExactEnvelopeReceiptIsSingleConsumerAndDeletesKey()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var exactDmc2 = CreateExactSendDmc2();
        MessageKeyLease? capturedMessageKey = null;
        using var faultProbe = MessagingCryptoFaultInjection.InstallDarkForTests(
            new MessagingCryptoFaultProbe
            {
                OwnedDisposable = (name, value) =>
                {
                    if (name == "ratchet.plan.message-key")
                        capturedMessageKey = Assert.IsType<MessageKeyLease>(value);
                },
            });
        using var plan = ExactDpe2SendTransitionPlan.Prepare(
            exactDmc2,
            Dpe2Network(),
            state,
            new ScriptedProvider(),
            Persistence(state),
            Bytes(54),
            Bytes(70));
        var wrong = DurableExactDpe2SendSuccessCapability.CreateDarkForTests(
            DurableRatchetSuccess(plan),
            plan.OperationId.Span,
            Bytes(99),
            exactEnvelopeAndRatchetCommittedAtomically: true);

        var error = Assert.Throws<MessagingCryptoException>(() => plan.Commit(wrong));

        Assert.Equal(MessagingCryptoError.CasConflict, error.Error);
        Assert.Equal(0UL, state.NextSendEcN);
        Assert.Equal(0UL, state.StorageGeneration);
        var disposed = Assert.Throws<MessagingCryptoException>(() =>
            capturedMessageKey!.Use(static _ => { }));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, disposed.Error);
        var consumed = Assert.Throws<MessagingCryptoException>(() => plan.Commit(wrong));
        Assert.Equal(MessagingCryptoError.CapabilityConsumed, consumed.Error);
        CryptographicOperations.ZeroMemory(exactDmc2);
    }

    [Fact]
    public void ExactDpe2Send_CrashBeforeCommitDeletesKeyAndSameOperationCanBePreparedAgain()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var exactDmc2 = CreateExactSendDmc2();
        MessageKeyLease? firstMessageKey = null;
        using var faultProbe = MessagingCryptoFaultInjection.InstallDarkForTests(
            new MessagingCryptoFaultProbe
            {
                OwnedDisposable = (name, value) =>
                {
                    if (name == "ratchet.plan.message-key" && firstMessageKey is null)
                        firstMessageKey = Assert.IsType<MessageKeyLease>(value);
                },
            });
        var provider = new ScriptedProvider();
        using (var abandoned = ExactDpe2SendTransitionPlan.Prepare(
                   exactDmc2,
                   Dpe2Network(),
                   state,
                   provider,
                   Persistence(state),
                   Bytes(54),
                   Bytes(70)))
        {
        }

        var disposed = Assert.Throws<MessagingCryptoException>(() =>
            firstMessageKey!.Use(static _ => { }));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, disposed.Error);
        Assert.Equal(0UL, state.NextSendEcN);
        Assert.Equal(0UL, state.StorageGeneration);

        using var retry = ExactDpe2SendTransitionPlan.Prepare(
            exactDmc2,
            Dpe2Network(),
            state,
            provider,
            Persistence(state),
            Bytes(54),
            Bytes(70));
        using var commit = retry.Commit(DurableSendSuccess(retry));
        var exactEnvelope = commit.TakeExactEnvelope();
        try
        {
            var firstTransportAttempt = exactEnvelope.ToArray();
            var retryTransportAttempt = exactEnvelope.ToArray();
            Assert.Equal(firstTransportAttempt, retryTransportAttempt);
            CryptographicOperations.ZeroMemory(firstTransportAttempt);
            CryptographicOperations.ZeroMemory(retryTransportAttempt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactEnvelope);
            CryptographicOperations.ZeroMemory(exactDmc2);
        }
        using var next = commit.TakeNextState();
        Assert.Equal(2, provider.SendCalls);
        Assert.Equal(1UL, next.NextSendEcN);
    }

    [Fact]
    public void ExactDpe2Send_SessionSubstitutionCannotAuthenticateCommittedCiphertext()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var exactDmc2 = CreateExactSendDmc2();
        using var plan = ExactDpe2SendTransitionPlan.Prepare(
            exactDmc2,
            Dpe2Network(),
            state,
            new ScriptedProvider(),
            Persistence(state),
            Bytes(54),
            Bytes(70));
        using var commit = plan.Commit(DurableSendSuccess(plan));
        var exactEnvelope = commit.TakeExactEnvelope();
        try
        {
            var original = Dpe2Codec.Decode(exactEnvelope);
            var ciphertext = new byte[original.Ciphertext.Length];
            original.Ciphertext.CopyCiphertextTo(ciphertext);
            var substituted = new Dpe2Record(
                original.NetworkId.Span,
                Bytes(99),
                original.SenderDeviceId.Span,
                original.RecipientDeviceId.Span,
                original.OperationId.Span,
                original.RatchetHeader,
                Dpe2Ciphertext.Import(ciphertext));
            var headerHash = MessagingWireCryptographicInputs.ComputeDpe2HeaderHash(substituted);
            var ecKey = SHA256.HashData(Encoding.ASCII.GetBytes("ec0"));
            var pqKey = SHA256.HashData(Encoding.ASCII.GetBytes("pq0"));
            var messageKey = MessagingKdf.DeriveCombinedMessageKey(
                substituted.SessionId.Span,
                substituted.RatchetHeader.EcMessageNumber,
                substituted.RatchetHeader.SckaSendingEpoch,
                substituted.RatchetHeader.SckaMessageNumber,
                headerHash,
                ecKey,
                pqKey);
            try
            {
                Assert.Throws<CryptographicException>(() =>
                    SecretAeadXChaCha20Poly1305.Decrypt(
                        ciphertext,
                        MessagingWireCryptographicInputs.DeriveDpe2Nonce(substituted),
                        messageKey,
                        MessagingWireCryptographicInputs.GetDpe2AeadAssociatedData(substituted)));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ciphertext);
                CryptographicOperations.ZeroMemory(ecKey);
                CryptographicOperations.ZeroMemory(pqKey);
                CryptographicOperations.ZeroMemory(messageKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactEnvelope);
            CryptographicOperations.ZeroMemory(exactDmc2);
        }
        using var next = commit.TakeNextState();
    }

    [Theory]
    [InlineData(282, 4096)]
    [InlineData(4092, 4096)]
    [InlineData(4093, 16384)]
    [InlineData(16380, 16384)]
    [InlineData(16381, 32768)]
    [InlineData(32764, 32768)]
    [InlineData(32765, 49136)]
    [InlineData(33082, 49136)]
    public void ExactDpe2Padding_SelectsFrozenSmallestBucket(int dmc2Length, int expectedBucket) =>
        Assert.Equal(expectedBucket, ExactDpe2Padding.SelectSmallestBucket(dmc2Length));

    [Theory]
    [InlineData(281)]
    [InlineData(33083)]
    public void ExactDpe2Padding_RejectsLengthOutsideFrozenDmc2Bounds(int dmc2Length)
    {
        var error = Assert.Throws<MessagingCryptoException>(() =>
            ExactDpe2Padding.SelectSmallestBucket(dmc2Length));
        Assert.Equal(MessagingCryptoError.InvalidInput, error.Error);
    }

    [Fact]
    public void ExactDpe2Send_CannotMintSuccessWhenEnvelopeAndRatchetWereNotAtomic()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var exactDmc2 = CreateExactSendDmc2();
        using var plan = ExactDpe2SendTransitionPlan.Prepare(
            exactDmc2,
            Dpe2Network(),
            state,
            new ScriptedProvider(),
            Persistence(state),
            Bytes(54),
            Bytes(70));

        var error = Assert.Throws<MessagingCryptoException>(() =>
            DurableExactDpe2SendSuccessCapability.CreateDarkForTests(
                DurableRatchetSuccess(plan),
                plan.OperationId.Span,
                plan.ExactEnvelopeHash.Span,
                exactEnvelopeAndRatchetCommittedAtomically: false));

        Assert.Equal(MessagingCryptoError.CasConflict, error.Error);
        Assert.Equal(0UL, state.NextSendEcN);
        CryptographicOperations.ZeroMemory(exactDmc2);
    }

    private static byte[] CreateExactSendDmc2(byte[]? networkId = null, byte[]? senderDeviceId = null)
    {
        var message = ApplicationCoreCodec.AuthorDmc2ForValidation(
            networkId ?? Dpe2Network(),
            Bytes(21),
            Bytes(22),
            Bytes(23),
            senderDeviceId ?? Bytes(44),
            senderClientSequence: 1,
            createdAtUnixMilliseconds: 1,
            expiresAtUnixMilliseconds: 0,
            Dmc2Flags.None,
            [],
            ApplicationCoreCodec.CreateMessageCreatePayload("bounded E2EE-01B"));
        return message.CanonicalBytes.ToArray();
    }

    private static byte[] Network(byte value) => Enumerable.Repeat(value, 16).ToArray();

    private static DurableRatchetTransactionSuccessCapability DurableRatchetSuccess(
        ExactDpe2SendTransitionPlan plan)
    {
        var generation = plan.ProposedGeneration ??
            throw new InvalidOperationException("Fresh exact DPE2 send plan has no proposed generation.");
        var receipt = ExactRatchetJournalReceipt.CreateDarkForTests(
            plan.OperationId.Span,
            plan.JournalPredecessor.Span,
            plan.DatabaseCas,
            plan.CheckpointCas,
            generation,
            plan.ProposedStateCommitment.Span,
            [],
            plan.DeletionManifestCommitment.Span,
            [],
            plan.PqFenceMutationCommitment.Span,
            durablyCommitted: true);
        return DurableRatchetTransactionSuccessCapability.CreateDarkForTests(
            receipt,
            atomicTransactionCommitted: true);
    }

    private static DurableExactDpe2SendSuccessCapability DurableSendSuccess(
        ExactDpe2SendTransitionPlan plan) =>
        DurableExactDpe2SendSuccessCapability.CreateDarkForTests(
            DurableRatchetSuccess(plan),
            plan.OperationId.Span,
            plan.ExactEnvelopeHash.Span,
            exactEnvelopeAndRatchetCommittedAtomically: true);

    private static void AssertExactEnvelopeDecryptsTo(Dpe2Record envelope, ReadOnlySpan<byte> exactDmc2)
    {
        var ciphertext = new byte[envelope.Ciphertext.Length];
        envelope.Ciphertext.CopyCiphertextTo(ciphertext);
        var ecKey = SHA256.HashData(Encoding.ASCII.GetBytes("ec0"));
        var pqKey = SHA256.HashData(Encoding.ASCII.GetBytes("pq0"));
        var messageKey = MessagingKdf.DeriveCombinedMessageKey(
            envelope.SessionId.Span,
            envelope.RatchetHeader.EcMessageNumber,
            envelope.RatchetHeader.SckaSendingEpoch,
            envelope.RatchetHeader.SckaMessageNumber,
            MessagingWireCryptographicInputs.ComputeDpe2HeaderHash(envelope),
            ecKey,
            pqKey);
        byte[]? padded = null;
        try
        {
            padded = SecretAeadXChaCha20Poly1305.Decrypt(
                ciphertext,
                MessagingWireCryptographicInputs.DeriveDpe2Nonce(envelope),
                messageKey,
                MessagingWireCryptographicInputs.GetDpe2AeadAssociatedData(envelope));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(padded.AsSpan(^4)));
            Assert.Equal(exactDmc2.Length, length);
            Assert.Equal(exactDmc2.ToArray(), padded.AsSpan(0, length).ToArray());
            Assert.Equal(4096, ExactDpe2Padding.SelectSmallestBucket(length));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(ecKey);
            CryptographicOperations.ZeroMemory(pqKey);
            CryptographicOperations.ZeroMemory(messageKey);
            if (padded is not null) CryptographicOperations.ZeroMemory(padded);
        }
    }
}
