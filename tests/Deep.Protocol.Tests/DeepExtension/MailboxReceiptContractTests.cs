using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class MailboxReceiptContractTests
{
    private static readonly byte[] OperationId = Range(0x10, 16);
    private static readonly byte[] PayloadDigest = Range(0x40, 32);
    private static readonly byte[] ReplicaA = Range(0x70, 16);
    private static readonly byte[] ReplicaB = Range(0x80, 16);
    private static readonly byte[] Coordinator = Range(0x90, 16);

    [Fact]
    public void CanonicalReplicaAndQuorum_MatchGoldenVectors_AndVerify()
    {
        var crypto = new DeterministicTestReceiptCrypto();
        var first = SignReplica(CreateReplica(ReplicaA), crypto);
        var second = SignReplica(CreateReplica(ReplicaB), crypto);
        var quorum = SignQuorum(CreateQuorum(first, second), crypto);
        var vectors = GoldenVectorLoader.Load("mailbox-receipts-v1.json");

        Assert.Equal(
            vectors.GetRequired("deep-extension/mailbox-receipt/v1/replica-durable").Hex,
            Convert.ToHexString(MailboxReceiptCodec.EncodeReplica(first)).ToLowerInvariant());
        Assert.Equal(
            vectors.GetRequired("deep-extension/mailbox-receipt/v1/quorum-two-replicas").Hex,
            Convert.ToHexString(MailboxReceiptCodec.EncodeDurableQuorum(quorum)).ToLowerInvariant());

        var verified = MailboxReceiptVerifier.VerifyDurableQuorum(
            MailboxReceiptCodec.EncodeDurableQuorum(quorum),
            crypto,
            Expectation());

        Assert.Equal(2, verified.ReplicaReceipts.Count);
        Assert.Equal(42UL, verified.Cursor);
        Assert.False(verified.IsTombstone);
    }

    [Fact]
    public void QuorumRequiresTwoIndependentReplicaSignatures()
    {
        var crypto = new DeterministicTestReceiptCrypto();
        var first = SignReplica(CreateReplica(ReplicaA), crypto);
        var duplicate = SignReplica(CreateReplica(ReplicaA), crypto);
        var duplicateQuorum = SignQuorum(CreateQuorum(first, duplicate), crypto);

        var exception = Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptVerifier.VerifyDurableQuorum(
                MailboxReceiptCodec.EncodeDurableQuorum(duplicateQuorum),
                crypto,
                Expectation()));
        Assert.Equal(MailboxReceiptError.DuplicateReplica, exception.Error);

        var second = SignReplica(CreateReplica(ReplicaB), crypto);
        var quorum = SignQuorum(CreateQuorum(first, second), crypto);
        var encoded = MailboxReceiptCodec.EncodeDurableQuorum(quorum);
        encoded[^1] ^= 1;
        var invalid = Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptVerifier.VerifyDurableQuorum(encoded, crypto, Expectation()));
        Assert.Equal(MailboxReceiptError.InvalidCoordinatorSignature, invalid.Error);
    }

    [Fact]
    public void AcceptedReceipt_IsNotDurable()
    {
        var crypto = new DeterministicTestReceiptCrypto();
        var accepted = SignReplica(CreateReplica(ReplicaA) with
        {
            Status = MailboxReceiptStatus.Accepted,
            DurableAtBucket = 0
        }, crypto);
        var durable = SignReplica(CreateReplica(ReplicaB), crypto);
        var quorum = SignQuorum(CreateQuorum(accepted, durable), crypto);

        var exception = Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptVerifier.VerifyDurableQuorum(
                MailboxReceiptCodec.EncodeDurableQuorum(quorum),
                crypto,
                Expectation()));

        Assert.Equal(MailboxReceiptError.NotDurable, exception.Error);
    }

    [Fact]
    public void ReplicaStatementsMustAgreeOnCursorTombstoneAndPayload()
    {
        var crypto = new DeterministicTestReceiptCrypto();
        var first = SignReplica(CreateReplica(ReplicaA), crypto);
        var conflicting = SignReplica(CreateReplica(ReplicaB) with { Cursor = 43 }, crypto);
        var quorum = SignQuorum(CreateQuorum(first, conflicting), crypto);

        var exception = Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptVerifier.VerifyDurableQuorum(
                MailboxReceiptCodec.EncodeDurableQuorum(quorum),
                crypto,
                Expectation()));

        Assert.Equal(MailboxReceiptError.ReplicaDisagreement, exception.Error);
    }

    [Fact]
    public void VerificationRequiresExpectedOperationGenerationPayloadAndTombstone()
    {
        var crypto = new DeterministicTestReceiptCrypto();
        var quorum = CreateVerifiedQuorum(42, crypto);
        var encoded = MailboxReceiptCodec.EncodeDurableQuorum(quorum);

        foreach (var expectation in new[]
        {
            Expectation() with { OperationId = Range(0x20, 16) },
            Expectation() with { Generation = 8 },
            Expectation() with { PayloadDigest = Range(0x50, 32) },
            Expectation() with { IsTombstone = true }
        })
        {
            var exception = Assert.Throws<MailboxReceiptException>(() =>
                MailboxReceiptVerifier.VerifyDurableQuorum(encoded, crypto, expectation));
            Assert.Equal(MailboxReceiptError.UnexpectedStatement, exception.Error);
        }
    }

    [Fact]
    public void AlternateValidSignatureOfSameStatement_IsNotEquivocation()
    {
        var crypto = new AlternateCoordinatorSignatureCrypto();
        var first = SignReplica(CreateReplica(ReplicaA), crypto.Inner);
        var second = SignReplica(CreateReplica(ReplicaB), crypto.Inner);
        var quorum = SignQuorum(CreateQuorum(first, second), crypto.Inner);
        var alternativeSignature = quorum.Signature.ToArray();
        alternativeSignature[^1] ^= 1;
        var firstBytes = MailboxReceiptCodec.EncodeDurableQuorum(quorum);
        var secondBytes = MailboxReceiptCodec.EncodeDurableQuorum(
            quorum with { Signature = alternativeSignature });

        var exception = Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptVerifier.CreateCoordinatorEquivocationEvidence(
                firstBytes,
                secondBytes,
                crypto));
        Assert.Equal(MailboxReceiptError.NotEquivocation, exception.Error);
    }

    [Fact]
    public void CoordinatorEquivocationEvidence_PreservesTwoVerifiedStatements()
    {
        var crypto = new DeterministicTestReceiptCrypto();
        var firstQuorum = CreateVerifiedQuorum(42, crypto);
        var secondQuorum = CreateVerifiedQuorum(43, crypto);
        var firstBytes = MailboxReceiptCodec.EncodeDurableQuorum(firstQuorum);
        var secondBytes = MailboxReceiptCodec.EncodeDurableQuorum(secondQuorum);

        var evidence = MailboxReceiptVerifier.CreateCoordinatorEquivocationEvidence(
            firstBytes,
            secondBytes,
            crypto);

        Assert.Equal(Coordinator, evidence.CoordinatorId.ToArray());
        Assert.Equal(5UL, evidence.CoordinatorSequence);
        Assert.Equal(firstBytes, evidence.FirstStatement.ToArray());
        Assert.Equal(secondBytes, evidence.SecondStatement.ToArray());

        Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptVerifier.CreateCoordinatorEquivocationEvidence(
                firstBytes,
                firstBytes,
                crypto));
    }

    [Theory]
    [InlineData(MailboxReceiptStage.Accepted, MailboxReceiptErrorClass.Capacity, true)]
    [InlineData(MailboxReceiptStage.Durable, MailboxReceiptErrorClass.QuorumUnavailable, true)]
    [InlineData(MailboxReceiptStage.Durable, MailboxReceiptErrorClass.Revoked, false)]
    public void AcceptedAndDurableErrors_RoundTripCanonically(
        MailboxReceiptStage stage,
        MailboxReceiptErrorClass errorClass,
        bool retryable)
    {
        var receipt = new MailboxErrorReceipt
        {
            Stage = stage,
            ErrorClass = errorClass,
            Retryable = retryable,
            Generation = 7,
            RetryAfterBucket = retryable ? 1015u : 0u,
            EvidenceDigest = errorClass == MailboxReceiptErrorClass.QuorumUnavailable
                ? PayloadDigest
                : ReadOnlyMemory<byte>.Empty
        };

        var encoded = MailboxReceiptCodec.EncodeError(receipt);
        var decoded = MailboxReceiptCodec.DecodeError(encoded);

        Assert.Equal(receipt, decoded);
    }

    private static MailboxReplicaReceipt CreateReplica(byte[] replicaId, ulong cursor = 42) =>
        new()
        {
            Status = MailboxReceiptStatus.Durable,
            ReplicaId = replicaId,
            OperationId = OperationId,
            Generation = 7,
            Cursor = cursor,
            AcceptedAtBucket = 1001,
            DurableAtBucket = 1002,
            IsTombstone = false,
            PayloadDigest = PayloadDigest,
            Signature = ReadOnlyMemory<byte>.Empty
        };

    private static MailboxDurableQuorumReceipt CreateQuorum(
        MailboxReplicaReceipt first,
        MailboxReplicaReceipt second) =>
        new()
        {
            CoordinatorId = Coordinator,
            CoordinatorSequence = 5,
            FirstReplica = first,
            SecondReplica = second,
            Signature = ReadOnlyMemory<byte>.Empty
        };

    private static MailboxReplicaReceipt SignReplica(
        MailboxReplicaReceipt receipt,
        DeterministicTestReceiptCrypto crypto) =>
        receipt with
        {
            Signature = crypto.Sign(
                receipt.ReplicaId.Span,
                MailboxReceiptCodec.GetReplicaSigningBytes(receipt))
        };

    private static MailboxDurableQuorumReceipt SignQuorum(
        MailboxDurableQuorumReceipt receipt,
        DeterministicTestReceiptCrypto crypto) =>
        receipt with
        {
            Signature = crypto.Sign(
                receipt.CoordinatorId.Span,
                MailboxReceiptCodec.GetQuorumSigningBytes(receipt, crypto))
        };

    private static MailboxDurableQuorumReceipt CreateVerifiedQuorum(
        ulong cursor,
        DeterministicTestReceiptCrypto crypto)
    {
        var first = SignReplica(CreateReplica(ReplicaA, cursor), crypto);
        var second = SignReplica(CreateReplica(ReplicaB, cursor), crypto);
        return SignQuorum(CreateQuorum(first, second), crypto);
    }

    private static MailboxDurableQuorumExpectation Expectation() =>
        new()
        {
            OperationId = OperationId,
            Generation = 7,
            PayloadDigest = PayloadDigest,
            IsTombstone = false
        };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();

    private sealed class DeterministicTestReceiptCrypto : IMailboxReceiptCrypto
    {
        public byte[] Digest(ReadOnlySpan<byte> statement) => SHA256.HashData(statement);

        public bool VerifyReplica(
            ReadOnlySpan<byte> replicaId,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) =>
            CryptographicOperations.FixedTimeEquals(
                Sign(replicaId, signingBytes),
                signature);

        public bool VerifyCoordinator(
            ReadOnlySpan<byte> coordinatorId,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) =>
            CryptographicOperations.FixedTimeEquals(
                Sign(coordinatorId, signingBytes),
                signature);

        public byte[] Sign(ReadOnlySpan<byte> signerId, ReadOnlySpan<byte> statement)
        {
            var input = new byte[signerId.Length + statement.Length];
            signerId.CopyTo(input);
            statement.CopyTo(input.AsSpan(signerId.Length));
            return SHA256.HashData(input);
        }
    }

    private sealed class AlternateCoordinatorSignatureCrypto : IMailboxReceiptCrypto
    {
        public DeterministicTestReceiptCrypto Inner { get; } = new();

        public byte[] Digest(ReadOnlySpan<byte> statement) => Inner.Digest(statement);

        public bool VerifyReplica(
            ReadOnlySpan<byte> replicaId,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) =>
            Inner.VerifyReplica(replicaId, signingBytes, signature);

        public bool VerifyCoordinator(
            ReadOnlySpan<byte> coordinatorId,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            var expected = Inner.Sign(coordinatorId, signingBytes);
            if (CryptographicOperations.FixedTimeEquals(expected, signature))
            {
                return true;
            }

            expected[^1] ^= 1;
            return CryptographicOperations.FixedTimeEquals(expected, signature);
        }
    }
}
