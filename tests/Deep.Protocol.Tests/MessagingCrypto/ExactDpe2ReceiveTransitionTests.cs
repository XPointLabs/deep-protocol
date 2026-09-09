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
    public void ExactDpe2Receive_ReleasesAuthenticatedDmc2OnlyAfterDurableCommitAndDeletesMessageKey()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var exactEnvelope = CreateExactDpe2();
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
        using var plan = ExactDpe2ReceiveTransitionPlan.Prepare(
            exactEnvelope,
            state,
            provider,
            Persistence(state),
            RatchetDeduplicationOutcome.Fresh,
            journalGeneration: 0,
            journalPredecessor: Bytes(70),
            retentionCommitment: Bytes(71));

        Assert.True(plan.HasAuthenticatedMessagePendingCommit);
        Assert.Contains(RatchetDeletionKind.MessageKeyAfterUse, plan.DeletionObligations);
        Assert.Contains(RatchetDeletionKind.PreviousStateAfterCommit, plan.DeletionObligations);
        Assert.Equal(Dtr2Codec.EmptyTotalBytes, provider.LastExactDtr2Length);
        Assert.NotNull(capturedMessageKey);
        var deletedBeforeCommit = Assert.Throws<MessagingCryptoException>(() =>
            capturedMessageKey!.Use(static _ => { }));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, deletedBeforeCommit.Error);

        using var commit = plan.Commit(DurableSuccess(plan));

        Assert.Equal(RatchetPlanOutcome.Fresh, commit.Outcome);
        Assert.True(commit.HasMessage);
        Assert.True(commit.HasNextState);
        var message = commit.TakeAuthenticatedMessage();
        Assert.Equal(Dmc2ContentKind.MessageCreate, message.ContentKind);
        Assert.Equal(Dpe2Network(), message.NetworkId.ToArray());
        Assert.Equal(Bytes(34), message.SenderDeviceId.ToArray());
        using var next = commit.TakeNextState();
        Assert.Equal(1UL, next.NextExpectedReceiveEcN);
        Assert.Equal(1UL, next.StorageGeneration);
        var remainsDeleted = Assert.Throws<MessagingCryptoException>(() =>
            capturedMessageKey.Use(static _ => { }));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, remainsDeleted.Error);
        Assert.DoesNotContain(
            typeof(ExactDpe2ReceiveTransitionPlan).GetMethods(),
            static method => method.Name.Contains("Plaintext", StringComparison.Ordinal));
    }

    [Fact]
    public void ExactDpe2Receive_TamperedCiphertextRejectsWithoutMutatingCommittedState()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var exact = CreateExactDpe2();
        var decoded = Dpe2Codec.Decode(exact);
        var ciphertext = new byte[decoded.Ciphertext.Length];
        decoded.Ciphertext.CopyCiphertextTo(ciphertext);
        ciphertext[^1] ^= 0x80;
        var tampered = Dpe2Codec.Encode(new Dpe2Record(
            decoded.NetworkId.Span,
            decoded.SessionId.Span,
            decoded.SenderDeviceId.Span,
            decoded.RecipientDeviceId.Span,
            decoded.OperationId.Span,
            decoded.RatchetHeader,
            Dpe2Ciphertext.Import(ciphertext)));
        var provider = new ScriptedProvider();

        var error = Assert.Throws<MessagingCryptoException>(() =>
            ExactDpe2ReceiveTransitionPlan.Prepare(
                tampered,
                state,
                provider,
                Persistence(state),
                RatchetDeduplicationOutcome.Fresh,
                0,
                Bytes(70),
                Bytes(71)));

        Assert.Equal(MessagingCryptoError.TransitionRejected, error.Error);
        Assert.Equal(1, provider.ReceiveCalls);
        Assert.Equal(0UL, state.StorageGeneration);
        Assert.Equal(0UL, state.NextExpectedReceiveEcN);
        using var retry = ExactDpe2ReceiveTransitionPlan.Prepare(
            exact,
            state,
            new ScriptedProvider(),
            Persistence(state),
            RatchetDeduplicationOutcome.Fresh,
            0,
            Bytes(70),
            Bytes(71));
        Assert.True(retry.HasAuthenticatedMessagePendingCommit);
    }

    [Fact]
    public void ExactDpe2Receive_WrongDurableReceiptCannotReleaseMessageOrStateAndDeletesKey()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
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
        using var plan = ExactDpe2ReceiveTransitionPlan.Prepare(
            CreateExactDpe2(),
            state,
            new ScriptedProvider(),
            Persistence(state),
            RatchetDeduplicationOutcome.Fresh,
            0,
            Bytes(70),
            Bytes(71));
        var receipt = ExactRatchetJournalReceipt.CreateDarkForTests(
            Bytes(99),
            plan.JournalPredecessor.Span,
            plan.DatabaseCas,
            plan.CheckpointCas,
            plan.ProposedGeneration!.Value,
            plan.ProposedStateCommitment.Span,
            [],
            plan.DeletionManifestCommitment.Span,
            plan.DeduplicationMutationCommitment.Span,
            plan.PqFenceMutationCommitment.Span,
            durablyCommitted: true);
        var wrongProof = DurableRatchetTransactionSuccessCapability.CreateDarkForTests(
            receipt,
            atomicTransactionCommitted: true);

        var error = Assert.Throws<MessagingCryptoException>(() => plan.Commit(wrongProof));

        Assert.Equal(MessagingCryptoError.CasConflict, error.Error);
        Assert.Equal(0UL, state.StorageGeneration);
        Assert.Equal(0UL, state.NextExpectedReceiveEcN);
        var disposed = Assert.Throws<MessagingCryptoException>(() =>
            capturedMessageKey!.Use(static _ => { }));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, disposed.Error);
    }

    [Fact]
    public void ExactDpe2Receive_CombinedKeyMatchesIndependentMessagingWireProjection()
    {
        var exact = CreateExactDpe2();
        var record = Dpe2Codec.Decode(exact);
        var headerHash = MessagingWireCryptographicInputs.ComputeDpe2HeaderHash(record);
        var ecKey = SHA256.HashData(Encoding.ASCII.GetBytes("ec0"));
        var pqKey = SHA256.HashData(Encoding.ASCII.GetBytes("pq0"));
        var local = MessagingKdf.DeriveCombinedMessageKey(
            record.SessionId.Span,
            record.RatchetHeader.EcMessageNumber,
            record.RatchetHeader.SckaSendingEpoch,
            record.RatchetHeader.SckaMessageNumber,
            headerHash,
            ecKey,
            pqKey);
        using var wire = Dpe2VerificationPlan.Create(
                record,
                new VerifiedDtr2Header(record.RatchetHeader, headerHash))
            .DeriveMessageKey(ecKey, pqKey);
        byte[]? independent = null;
        try
        {
            wire.Use(value => independent = value.ToArray());
            Assert.Equal(local, independent);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ecKey);
            CryptographicOperations.ZeroMemory(pqKey);
            CryptographicOperations.ZeroMemory(local);
            if (independent is not null) CryptographicOperations.ZeroMemory(independent);
        }
    }

    [Theory]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    public void ExactDpe2Receive_SessionAndDirectionalDeviceSubstitutionRejectBeforeProvider(
        bool changeSession,
        bool changeSender,
        bool changeRecipient)
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var exact = CreateExactDpe2(
            sessionId: changeSession ? Bytes(99) : null,
            senderDeviceId: changeSender ? Bytes(98) : null,
            recipientDeviceId: changeRecipient ? Bytes(97) : null,
            authenticate: false);
        var provider = new ScriptedProvider();

        var error = Assert.Throws<MessagingCryptoException>(() =>
            ExactDpe2ReceiveTransitionPlan.Prepare(
                exact,
                state,
                provider,
                Persistence(state),
                RatchetDeduplicationOutcome.Fresh,
                0,
                Bytes(70),
                Bytes(71)));

        Assert.Equal(MessagingCryptoError.ReplayConflict, error.Error);
        Assert.Equal(0, provider.ReceiveCalls);
        Assert.Equal(0UL, state.StorageGeneration);
    }

    [Fact]
    public void ExactDpe2Receive_AuthenticatedNonMinimalPaddingRejectsBeforeCommit()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var exact = CreateExactDpe2(plaintextBucket: 16384);
        var provider = new ScriptedProvider();

        var error = Assert.Throws<MessagingCryptoException>(() =>
            ExactDpe2ReceiveTransitionPlan.Prepare(
                exact,
                state,
                provider,
                Persistence(state),
                RatchetDeduplicationOutcome.Fresh,
                0,
                Bytes(70),
                Bytes(71)));

        Assert.Equal(MessagingCryptoError.InvalidInput, error.Error);
        Assert.Equal(1, provider.ReceiveCalls);
        Assert.Equal(0UL, state.StorageGeneration);
    }

    [Fact]
    public void ExactDpe2Receive_ExactReplayDoesNotInvokeProviderDecryptOrAdvanceState()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var exact = CreateExactDpe2();

        using var plan = ExactDpe2ReceiveTransitionPlan.Prepare(
            exact,
            state,
            new ThrowingProvider(),
            Persistence(state),
            RatchetDeduplicationOutcome.ExactReplay,
            journalGeneration: 7,
            journalPredecessor: Bytes(70),
            retentionCommitment: Bytes(71));

        Assert.Equal(RatchetPlanOutcome.ExactReplay, plan.Outcome);
        Assert.False(plan.HasAuthenticatedMessagePendingCommit);
        using var commit = plan.ConsumeExactReplay();
        Assert.Equal(RatchetPlanOutcome.ExactReplay, commit.Outcome);
        Assert.False(commit.HasMessage);
        Assert.False(commit.HasNextState);
        Assert.Equal(0UL, state.StorageGeneration);
        Assert.Equal(0UL, state.NextExpectedReceiveEcN);
    }

    [Fact]
    public void ExactDpe2Receive_AuthenticatedDmc2OuterIdentityMismatchRejectsBeforeCommit()
    {
        using var state = CreateState(binding: CreateDpe2Binding());
        var exact = CreateExactDpe2(dmc2SenderDeviceId: Bytes(96));

        var error = Assert.Throws<MessagingCryptoException>(() =>
            ExactDpe2ReceiveTransitionPlan.Prepare(
                exact,
                state,
                new ScriptedProvider(),
                Persistence(state),
                RatchetDeduplicationOutcome.Fresh,
                0,
                Bytes(70),
                Bytes(71)));

        Assert.Equal(MessagingCryptoError.ReplayConflict, error.Error);
        Assert.Equal(0UL, state.StorageGeneration);
    }

    private static RatchetStateBinding CreateDpe2Binding() => new(
        MessagingCryptoConstants.Suite,
        Bytes(40),
        Bytes64(41),
        Bytes(44),
        5,
        Bytes(43),
        Bytes(34),
        9,
        Bytes(45));

    private static byte[] CreateExactDpe2(
        byte[]? sessionId = null,
        byte[]? senderDeviceId = null,
        byte[]? recipientDeviceId = null,
        byte[]? dmc2SenderDeviceId = null,
        int plaintextBucket = 4096,
        bool authenticate = true)
    {
        var network = Dpe2Network();
        var session = sessionId ?? Bytes(40);
        var sender = senderDeviceId ?? Bytes(34);
        var recipient = recipientDeviceId ?? Bytes(44);
        var header = new Dtr2Record(
            network,
            Bytes(93),
            ecPreviousSendingChainLength: 0,
            ecMessageNumber: 0,
            sckaSendingEpoch: 1,
            sckaPreviousSendingChainLength: 0,
            sckaMessageNumber: 1,
            braidEpoch: 1,
            braidMessage: Dtr2BraidMessage.None());
        var placeholder = new Dpe2Record(
            network,
            session,
            sender,
            recipient,
            Bytes(54),
            header,
            Dpe2Ciphertext.Import(new byte[plaintextBucket + 16]));
        if (!authenticate)
            return Dpe2Codec.Encode(placeholder);

        var payload = ApplicationCoreCodec.CreateMessageCreatePayload("bounded E2EE-01");
        var dmc2 = ApplicationCoreCodec.AuthorDmc2ForValidation(
            network,
            Bytes(21),
            Bytes(22),
            Bytes(23),
            dmc2SenderDeviceId ?? sender,
            senderClientSequence: 1,
            createdAtUnixMilliseconds: 1,
            expiresAtUnixMilliseconds: 0,
            Dmc2Flags.None,
            [],
            payload);
        var padded = new byte[plaintextBucket];
        var canonical = dmc2.CanonicalBytes.ToArray();
        canonical.CopyTo(padded, 0);
        padded.AsSpan(canonical.Length, plaintextBucket - canonical.Length - 4).Fill(0xa5);
        BinaryPrimitives.WriteUInt32BigEndian(padded.AsSpan(plaintextBucket - 4), checked((uint)canonical.Length));
        var headerHash = MessagingWireCryptographicInputs.ComputeDpe2HeaderHash(placeholder);
        var ecKey = SHA256.HashData(Encoding.ASCII.GetBytes("ec0"));
        var pqKey = SHA256.HashData(Encoding.ASCII.GetBytes("pq0"));
        var messageKey = MessagingKdf.DeriveCombinedMessageKey(session, 0, 1, 1, headerHash, ecKey, pqKey);
        byte[]? ciphertext = null;
        try
        {
            ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(
                padded,
                MessagingWireCryptographicInputs.DeriveDpe2Nonce(placeholder),
                messageKey,
                MessagingWireCryptographicInputs.GetDpe2AeadAssociatedData(placeholder));
            return Dpe2Codec.Encode(new Dpe2Record(
                network,
                session,
                sender,
                recipient,
                Bytes(54),
                header,
                Dpe2Ciphertext.Import(ciphertext)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
            CryptographicOperations.ZeroMemory(padded);
            CryptographicOperations.ZeroMemory(ecKey);
            CryptographicOperations.ZeroMemory(pqKey);
            CryptographicOperations.ZeroMemory(messageKey);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private static byte[] Dpe2Network() => Enumerable.Repeat((byte)14, 16).ToArray();

    private static DurableRatchetTransactionSuccessCapability DurableSuccess(
        ExactDpe2ReceiveTransitionPlan plan)
    {
        var generation = plan.ProposedGeneration ??
            throw new InvalidOperationException("Fresh DPE2 receive plan has no proposed generation.");
        var receipt = ExactRatchetJournalReceipt.CreateDarkForTests(
            plan.OperationId.Span,
            plan.JournalPredecessor.Span,
            plan.DatabaseCas,
            plan.CheckpointCas,
            generation,
            plan.ProposedStateCommitment.Span,
            [],
            plan.DeletionManifestCommitment.Span,
            plan.DeduplicationMutationCommitment.Span,
            plan.PqFenceMutationCommitment.Span,
            durablyCommitted: true);
        return DurableRatchetTransactionSuccessCapability.CreateDarkForTests(
            receipt,
            atomicTransactionCommitted: true);
    }
}
