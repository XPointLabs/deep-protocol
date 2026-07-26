using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class MailboxReceiptV2ContractTests
{
    private static readonly byte[] ReplicaA = Range(0x10, 32);
    private static readonly byte[] ReplicaB = Range(0x30, 32);
    private static readonly byte[] Coordinator = Range(0x50, 32);
    private static readonly byte[] OperationId = Range(0x70, 16);
    private static readonly byte[] MailboxId = Range(0x80, 32);
    private static readonly byte[] Placement = Range(0xa0, 32);
    private static readonly byte[] Membership = Range(0xc0, 32);
    private static readonly byte[] EnvelopeDigest = Range(0xe0, 32);

    [Fact]
    public void CanonicalReplicaTranscriptAndQuorum_MatchGoldenAndVerify()
    {
        var crypto = new DeterministicCrypto();
        var first = SignReplica(Replica(ReplicaA), crypto);
        var second = SignReplica(Replica(ReplicaB), crypto);
        var quorum = SignQuorum(Quorum(first, second), crypto);
        var vectors = GoldenVectorLoader.Load("mailbox-receipts-v2.json");

        Assert.Equal(
            vectors.GetRequired("deep-extension/mailbox-receipt/v2/replica-durable-stored").Hex,
            Convert.ToHexString(MailboxReceiptV2Codec.EncodeReplica(first)).ToLowerInvariant());
        Assert.Equal(
            vectors.GetRequired("deep-extension/mailbox-receipt/v2/quorum-two-replicas").Hex,
            Convert.ToHexString(MailboxReceiptV2Codec.EncodeDurableQuorum(quorum)).ToLowerInvariant());

        var verified = MailboxReceiptV2Codec.VerifyDurableQuorum(
            MailboxReceiptV2Codec.EncodeDurableQuorum(quorum),
            crypto,
            Expectation());
        Assert.Equal(42UL, verified.Cursor);
        Assert.Equal(MailboxReplicaDisposition.Stored, verified.Disposition);
        Assert.Equal(2, verified.ReplicaReceipts.Count);
    }

    [Fact]
    public void TranscriptMapsXnodeA193dccFieldsAndAddsRequiredBindings()
    {
        var receipt = Replica(ReplicaA);
        Assert.Equal(ReplicaA, receipt.ReplicaId.ToArray()); // storageRouterId
        Assert.Equal(MailboxId, receipt.BlindedMailboxId.ToArray()); // mailboxId, but blinded bytes
        Assert.Equal(EnvelopeDigest, receipt.EnvelopeDigest.ToArray()); // blobId digest
        Assert.Equal(1120UL, receipt.ExpiresAtUnixSeconds);
        Assert.Equal(1002UL, receipt.DurableAtUnixSeconds); // storedAt
        Assert.Equal(MailboxReplicaDisposition.Stored, receipt.Disposition);
        Assert.Equal(Placement, receipt.PlacementCommitment.ToArray());
        Assert.Equal(Membership, receipt.MembershipCommitment.ToArray());
    }

    [Fact]
    public void TamperPlacementMembershipEnvelopeOrSignature_FailsVerification()
    {
        var crypto = new DeterministicCrypto();
        var canonical = VerifiedQuorum(crypto);
        foreach (var mutate in new Func<MailboxReplicaReceiptV2, MailboxReplicaReceiptV2>[]
        {
            value => value with { PlacementCommitment = Range(0x01, 32) },
            value => value with { MembershipCommitment = Range(0x21, 32) },
            value => value with { EnvelopeDigest = Range(0x41, 32) }
        })
        {
            var changed = mutate(canonical.FirstReplica);
            var quorum = SignQuorum(canonical with
            {
                FirstReplica = changed
            }, crypto);
            Assert.Throws<MailboxReceiptException>(() =>
                MailboxReceiptV2Codec.VerifyDurableQuorum(
                    MailboxReceiptV2Codec.EncodeDurableQuorum(quorum),
                    crypto,
                    Expectation()));
        }

        var encoded = MailboxReceiptV2Codec.EncodeDurableQuorum(canonical);
        encoded[^1] ^= 1;
        Assert.Equal(
            MailboxReceiptError.InvalidCoordinatorSignature,
            Assert.Throws<MailboxReceiptException>(() =>
                MailboxReceiptV2Codec.VerifyDurableQuorum(encoded, crypto, Expectation())).Error);
    }

    [Fact]
    public void AcceptedOrDuplicateReplicaCannotSatisfyDurableQuorum()
    {
        var crypto = new DeterministicCrypto();
        var acceptedA = SignReplica(Replica(ReplicaA) with
        {
            Status = MailboxReceiptStatus.Accepted,
            DurableAtUnixSeconds = 0
        }, crypto);
        var acceptedB = SignReplica(Replica(ReplicaB) with
        {
            Status = MailboxReceiptStatus.Accepted,
            DurableAtUnixSeconds = 0
        }, crypto);
        var acceptedQuorum = SignQuorum(Quorum(acceptedA, acceptedB), crypto);
        Assert.Equal(
            MailboxReceiptError.NotDurable,
            Assert.Throws<MailboxReceiptException>(() =>
                MailboxReceiptV2Codec.VerifyDurableQuorum(
                    MailboxReceiptV2Codec.EncodeDurableQuorum(acceptedQuorum),
                    crypto,
                    Expectation())).Error);

        var duplicate = SignReplica(Replica(ReplicaA), crypto);
        var duplicateQuorum = SignQuorum(Quorum(duplicate, duplicate), crypto);
        Assert.Equal(
            MailboxReceiptError.DuplicateReplica,
            Assert.Throws<MailboxReceiptException>(() =>
                MailboxReceiptV2Codec.VerifyDurableQuorum(
                    MailboxReceiptV2Codec.EncodeDurableQuorum(duplicateQuorum),
                    crypto,
                    Expectation())).Error);
    }

    [Fact]
    public void V1AndV2ReceiptsCannotBeCrossDecodedOrDowngraded()
    {
        var crypto = new DeterministicCrypto();
        var v2 = MailboxReceiptV2Codec.EncodeReplica(SignReplica(Replica(ReplicaA), crypto));
        Assert.Equal(
            MailboxReceiptError.InvalidMagic,
            Assert.Throws<MailboxReceiptException>(() =>
                MailboxReceiptCodec.DecodeReplica(v2)).Error);

        var v1 = MailboxReceiptCodec.EncodeReplica(new MailboxReplicaReceipt
        {
            Status = MailboxReceiptStatus.Durable,
            ReplicaId = Range(0x10, 16),
            OperationId = OperationId,
            Generation = 7,
            Cursor = 42,
            AcceptedAtBucket = 1001,
            DurableAtBucket = 1002,
            IsTombstone = false,
            PayloadDigest = EnvelopeDigest,
            Signature = Range(0x40, 32)
        });
        Assert.Contains(
            Assert.Throws<MailboxReceiptException>(() =>
                MailboxReceiptV2Codec.DecodeReplica(v1)).Error,
            new[]
            {
                MailboxReceiptError.InvalidMagic,
                MailboxReceiptError.EncodedLengthOutOfRange
            });

        var tamperedVersion = v2.ToArray();
        tamperedVersion[4] = 1;
        Assert.Equal(
            MailboxReceiptError.UnsupportedVersion,
            Assert.Throws<MailboxReceiptException>(() =>
                MailboxReceiptV2Codec.DecodeReplica(tamperedVersion)).Error);
    }

    [Fact]
    public void ReplicaParserRejectsEveryTruncationAndReservedTamper()
    {
        var crypto = new DeterministicCrypto();
        var encoded = MailboxReceiptV2Codec.EncodeReplica(SignReplica(Replica(ReplicaA), crypto));
        for (var length = 0; length < encoded.Length; length++)
        {
            Assert.Throws<MailboxReceiptException>(() =>
                MailboxReceiptV2Codec.DecodeReplica(encoded.AsSpan(0, length)));
        }

        var reserved = encoded.ToArray();
        reserved[7] = 1;
        Assert.Equal(
            MailboxReceiptError.ReservedFieldNotZero,
            Assert.Throws<MailboxReceiptException>(() =>
                MailboxReceiptV2Codec.DecodeReplica(reserved)).Error);
        Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptV2Codec.DecodeReplica([.. encoded, (byte)0]));
    }

    [Fact]
    public void TombstoneReceiptRequiresExactAckExpectation()
    {
        var crypto = new DeterministicCrypto();
        var first = SignReplica(Replica(ReplicaA) with
        {
            Disposition = MailboxReplicaDisposition.Tombstone
        }, crypto);
        var second = SignReplica(Replica(ReplicaB) with
        {
            Disposition = MailboxReplicaDisposition.Tombstone
        }, crypto);
        var quorum = SignQuorum(Quorum(first, second), crypto);
        var verified = MailboxReceiptV2Codec.VerifyDurableQuorum(
            MailboxReceiptV2Codec.EncodeDurableQuorum(quorum),
            crypto,
            Expectation() with { Disposition = MailboxReplicaDisposition.Tombstone });
        Assert.Equal(MailboxReplicaDisposition.Tombstone, verified.Disposition);
        Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptV2Codec.VerifyDurableQuorum(
                MailboxReceiptV2Codec.EncodeDurableQuorum(quorum),
                crypto,
                Expectation()));
    }

    private static MailboxReplicaReceiptV2 Replica(byte[] replicaId) =>
        new()
        {
            Status = MailboxReceiptStatus.Durable,
            Disposition = MailboxReplicaDisposition.Stored,
            ReplicaId = replicaId,
            OperationId = OperationId,
            Epoch = 7,
            Cursor = 42,
            AcceptedAtUnixSeconds = 1001,
            DurableAtUnixSeconds = 1002,
            ExpiresAtUnixSeconds = 1120,
            BlindedMailboxId = MailboxId,
            PlacementCommitment = Placement,
            MembershipCommitment = Membership,
            EnvelopeDigest = EnvelopeDigest,
            Signature = ReadOnlyMemory<byte>.Empty
        };

    private static MailboxDurableQuorumReceiptV2 Quorum(
        MailboxReplicaReceiptV2 first,
        MailboxReplicaReceiptV2 second) =>
        new()
        {
            CoordinatorId = Coordinator,
            CoordinatorSequence = 5,
            FirstReplica = first,
            SecondReplica = second,
            Signature = ReadOnlyMemory<byte>.Empty
        };

    private static MailboxReplicaReceiptV2 SignReplica(
        MailboxReplicaReceiptV2 receipt,
        DeterministicCrypto crypto) =>
        receipt with
        {
            Signature = crypto.Sign(receipt.ReplicaId.Span, MailboxReceiptV2Codec.GetReplicaSigningBytes(receipt))
        };

    private static MailboxDurableQuorumReceiptV2 SignQuorum(
        MailboxDurableQuorumReceiptV2 receipt,
        DeterministicCrypto crypto) =>
        receipt with
        {
            Signature = crypto.Sign(
                receipt.CoordinatorId.Span,
                MailboxReceiptV2Codec.GetQuorumSigningBytes(receipt, crypto))
        };

    private static MailboxDurableQuorumReceiptV2 VerifiedQuorum(DeterministicCrypto crypto)
    {
        var first = SignReplica(Replica(ReplicaA), crypto);
        var second = SignReplica(Replica(ReplicaB), crypto);
        return SignQuorum(Quorum(first, second), crypto);
    }

    private static MailboxDurableQuorumExpectationV2 Expectation() =>
        new()
        {
            OperationId = OperationId,
            Epoch = 7,
            Cursor = 42,
            Disposition = MailboxReplicaDisposition.Stored,
            BlindedMailboxId = MailboxId,
            PlacementCommitment = Placement,
            MembershipCommitment = Membership,
            EnvelopeDigest = EnvelopeDigest,
            ExpiresAtUnixSeconds = 1120
        };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => unchecked((byte)value)).ToArray();

    private sealed class DeterministicCrypto : IMailboxReceiptCrypto
    {
        public byte[] Digest(ReadOnlySpan<byte> statement) => SHA256.HashData(statement);

        public bool VerifyReplica(
            ReadOnlySpan<byte> replicaId,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) =>
            CryptographicOperations.FixedTimeEquals(Sign(replicaId, signingBytes), signature);

        public bool VerifyCoordinator(
            ReadOnlySpan<byte> coordinatorId,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) =>
            CryptographicOperations.FixedTimeEquals(Sign(coordinatorId, signingBytes), signature);

        public byte[] Sign(ReadOnlySpan<byte> signerId, ReadOnlySpan<byte> statement)
        {
            var input = new byte[signerId.Length + statement.Length];
            signerId.CopyTo(input);
            statement.CopyTo(input.AsSpan(signerId.Length));
            return SHA256.HashData(input);
        }
    }
}
