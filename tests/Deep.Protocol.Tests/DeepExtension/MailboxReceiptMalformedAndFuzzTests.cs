using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class MailboxReceiptMalformedAndFuzzTests
{
    private static readonly TestCrypto Crypto = new();

    [Fact]
    public void EveryReplicaQuorumAndErrorTruncation_IsRejected()
    {
        var replica = SignedReplica(0x70);
        var quorum = SignedQuorum(replica, SignedReplica(0x80));
        var error = MailboxReceiptCodec.EncodeError(new MailboxErrorReceipt
        {
            Stage = MailboxReceiptStage.Durable,
            ErrorClass = MailboxReceiptErrorClass.QuorumUnavailable,
            Retryable = true,
            Generation = 7,
            RetryAfterBucket = 1015,
            EvidenceDigest = Range(0x40, 32)
        });

        AssertEveryTruncationRejected(
            MailboxReceiptCodec.EncodeReplica(replica),
            static bytes => MailboxReceiptCodec.DecodeReplica(bytes));
        AssertEveryTruncationRejected(
            MailboxReceiptCodec.EncodeDurableQuorum(quorum),
            bytes => MailboxReceiptCodec.DecodeDurableQuorum(bytes, Crypto));
        AssertEveryTruncationRejected(error, static bytes => MailboxReceiptCodec.DecodeError(bytes));
    }

    [Fact]
    public void StructuredReplicaMutations_AreRejected()
    {
        var canonical = MailboxReceiptCodec.EncodeReplica(SignedReplica(0x70));
        foreach (var offset in new[] { 4, 5, 6, 7, 98, 99 })
        {
            var mutated = canonical.ToArray();
            mutated[offset] = 0xff;
            Assert.Throws<MailboxReceiptException>(() =>
                MailboxReceiptCodec.DecodeReplica(mutated));
        }

        var badLength = canonical.ToArray();
        badLength[97]++;
        Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptCodec.DecodeReplica(badLength));
        Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptCodec.DecodeReplica(canonical.Concat(new byte[] { 0 }).ToArray()));
    }

    [Fact]
    public void StructuredQuorumMutations_AreRejected()
    {
        var quorum = MailboxReceiptCodec.EncodeDurableQuorum(
            SignedQuorum(SignedReplica(0x70), SignedReplica(0x80)));
        foreach (var offset in new[] { 4, 5, 36, 102 })
        {
            var mutated = quorum.ToArray();
            mutated[offset] ^= 1;
            Assert.Throws<MailboxReceiptException>(() =>
                MailboxReceiptCodec.DecodeDurableQuorum(mutated, Crypto));
        }

        var badNestedLength = quorum.ToArray();
        badNestedLength[33]++;
        Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptCodec.DecodeDurableQuorum(badNestedLength, Crypto));

        var badReplicaSignature = quorum.ToArray();
        badReplicaSignature[MailboxReceiptLimits.QuorumFixedHeaderLength +
                            MailboxReceiptLimits.ReplicaFixedHeaderLength] ^= 1;
        var exception = Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptVerifier.VerifyDurableQuorum(badReplicaSignature, Crypto));
        Assert.Equal(MailboxReceiptError.InvalidReplicaSignature, exception.Error);
    }

    [Fact]
    public void FixedSeedMalformedInputs_StayInsideExpectedExceptionSurface()
    {
        var random = new Random(0x503B);
        for (var iteration = 0; iteration < 2_000; iteration++)
        {
            var encoded = new byte[random.Next(0, MailboxReceiptLimits.MaximumQuorumReceiptLength + 32)];
            random.NextBytes(encoded);
            try
            {
                _ = MailboxReceiptCodec.DecodeDurableQuorum(encoded, Crypto);
            }
            catch (MailboxReceiptException)
            {
                continue;
            }

            Assert.Fail("Random malformed quorum unexpectedly decoded.");
        }
    }

    private static void AssertEveryTruncationRejected(
        byte[] canonical,
        Action<byte[]> decode)
    {
        for (var length = 0; length < canonical.Length; length++)
        {
            var truncated = canonical.AsSpan(0, length).ToArray();
            Assert.Throws<MailboxReceiptException>(() => decode(truncated));
        }
    }

    private static MailboxReplicaReceipt SignedReplica(int idStart)
    {
        var unsigned = new MailboxReplicaReceipt
        {
            Status = MailboxReceiptStatus.Durable,
            ReplicaId = Range(idStart, 16),
            OperationId = Range(0x10, 16),
            Generation = 7,
            Cursor = 42,
            AcceptedAtBucket = 1001,
            DurableAtBucket = 1002,
            IsTombstone = false,
            PayloadDigest = Range(0x40, 32),
            Signature = ReadOnlyMemory<byte>.Empty
        };
        return unsigned with
        {
            Signature = Crypto.Sign(
                unsigned.ReplicaId.Span,
                MailboxReceiptCodec.GetReplicaSigningBytes(unsigned))
        };
    }

    private static MailboxDurableQuorumReceipt SignedQuorum(
        MailboxReplicaReceipt first,
        MailboxReplicaReceipt second)
    {
        var unsigned = new MailboxDurableQuorumReceipt
        {
            CoordinatorId = Range(0x90, 16),
            CoordinatorSequence = 5,
            FirstReplica = first,
            SecondReplica = second,
            Signature = ReadOnlyMemory<byte>.Empty
        };
        return unsigned with
        {
            Signature = Crypto.Sign(
                unsigned.CoordinatorId.Span,
                MailboxReceiptCodec.GetQuorumSigningBytes(unsigned, Crypto))
        };
    }

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();

    private sealed class TestCrypto : IMailboxReceiptCrypto
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
