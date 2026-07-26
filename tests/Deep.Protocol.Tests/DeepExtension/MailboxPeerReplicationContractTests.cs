using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class MailboxPeerReplicationContractTests
{
    [Fact]
    public void StoreAndTombstone_AreCanonicalAuthenticatedAndMembershipBound()
    {
        var crypto = new SodiumMailboxPeerReplicationCrypto();
        var sourceSeed = Range(0x10, 32);
        var sourceKey = crypto.GetPublicKey(sourceSeed);
        var proof = Proof(Range(0x20, 32), sourceKey);
        var targetProof = Proof(Range(0x40, 32), Range(0x60, 32));
        var envelope = Envelope();
        var payload = MailboxClientCodec.EncodeEncryptedEnvelope(envelope);
        var unsigned = Request(MailboxPeerReplicationOperation.Store, proof, targetProof, payload) with
        {
            PayloadDigest = SHA256.HashData(payload)
        };
        var signed = crypto.SignRequest(unsigned, sourceSeed);
        var encoded = MailboxPeerReplicationCodec.Encode(signed);
        var verifier = new ExactProofVerifier();

        var verified = MailboxPeerReplicationCodec.Verify(
            encoded,
            Policy(signed),
            crypto,
            verifier);
        Assert.Equal(MailboxPeerReplicationOperation.Store, verified.Request.Operation);
        Assert.Equal(envelope.Ciphertext.ToArray(), verified.Envelope!.Ciphertext.ToArray());
        Assert.Equal(2, verifier.Calls);

        var tombstonePayload = envelope.DeduplicationDigest.ToArray();
        var tombstone = crypto.SignRequest(
            Request(MailboxPeerReplicationOperation.Tombstone, proof, targetProof, tombstonePayload),
            sourceSeed);
        Assert.Equal(
            MailboxPeerReplicationOperation.Tombstone,
            MailboxPeerReplicationCodec.Verify(
                MailboxPeerReplicationCodec.Encode(tombstone),
                Policy(tombstone),
                crypto,
                new ExactProofVerifier()).Request.Operation);
    }

    [Fact]
    public void WrongMembershipTargetSignatureOrLegacyJson_FailsClosed()
    {
        var crypto = new SodiumMailboxPeerReplicationCrypto();
        var seed = Range(0x10, 32);
        var proof = Proof(Range(0x20, 32), crypto.GetPublicKey(seed));
        var target = Proof(Range(0x40, 32), Range(0x60, 32));
        var payload = MailboxClientCodec.EncodeEncryptedEnvelope(Envelope());
        var request = crypto.SignRequest(
            Request(MailboxPeerReplicationOperation.Store, proof, target, payload) with
            {
                PayloadDigest = SHA256.HashData(payload)
            },
            seed);
        var encoded = MailboxPeerReplicationCodec.Encode(request);

        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerReplicationCodec.Verify(
                encoded,
                Policy(request) with { MembershipCommitment = Range(1, 32) },
                crypto,
                new ExactProofVerifier()));
        encoded[^1] ^= 1;
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerReplicationCodec.Verify(
                encoded,
                Policy(request),
                crypto,
                new ExactProofVerifier()));
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerReplicationCodec.Encode(request with
            {
                Payload = "{\"legacy\":true}"u8.ToArray(),
                PayloadDigest = SHA256.HashData("{\"legacy\":true}"u8)
            }));
    }

    [Fact]
    public void AggregateAck_RequiresOrderedExactTombstoneQuorums()
    {
        var receiptCrypto = new DeterministicReceiptCrypto();
        var expectations = new[] { Expectation(42), Expectation(43) };
        var receipts = expectations
            .Select(expectation => BuildTombstoneQuorum(expectation, receiptCrypto))
            .Select(MailboxReceiptV2Codec.EncodeDurableQuorum)
            .Select(static bytes => (ReadOnlyMemory<byte>)bytes)
            .ToArray();
        var response = new MailboxAggregateAckResponse
        {
            Epoch = 7,
            OperationId = Range(0x70, 16),
            TombstoneQuorums = receipts
        };
        var encoded = MailboxAggregateAckCodec.Encode(response);
        var verified = MailboxAggregateAckCodec.Verify(
            encoded,
            response.OperationId.Span,
            response.Epoch,
            expectations,
            receiptCrypto);
        Assert.Equal(2, verified.Count);

        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxAggregateAckCodec.Verify(
                encoded,
                response.OperationId.Span,
                response.Epoch,
                expectations.Reverse().ToArray(),
                receiptCrypto));
    }

    private static MailboxPeerReplicationRequest Request(
        MailboxPeerReplicationOperation operation,
        MailboxReplicaMembershipProof source,
        MailboxReplicaMembershipProof target,
        byte[] payload) =>
        new()
        {
            Operation = operation,
            Epoch = 7,
            OperationId = Range(0x70, 16),
            SourceReplicaId = source.ReplicaId,
            TargetReplicaId = target.ReplicaId,
            MembershipCommitment = Range(0x80, 32),
            PlacementCommitment = Range(0xa0, 32),
            BlindedMailboxId = Range(0xc0, 32),
            Cursor = operation == MailboxPeerReplicationOperation.Store ? 42UL : 43UL,
            ExpiresAtUnixSeconds = 1120,
            PayloadDigest = operation == MailboxPeerReplicationOperation.Tombstone
                ? payload
                : SHA256.HashData(payload),
            Payload = payload,
            SourceMembershipProof = source,
            TargetMembershipProof = target,
            Signature = ReadOnlyMemory<byte>.Empty
        };

    private static MailboxReplicaMembershipProof Proof(byte[] id, byte[] key) =>
        new()
        {
            ReplicaId = id,
            SigningPublicKey = key,
            Epoch = 7,
            MembershipCommitment = Range(0x80, 32),
            CanonicalInclusionProof = Range(0x01, 64)
        };

    private static MailboxPeerReplicationVerificationPolicy Policy(
        MailboxPeerReplicationRequest request) =>
        new()
        {
            ExpectedOperation = request.Operation,
            OperationId = request.OperationId,
            Epoch = request.Epoch,
            SourceReplicaId = request.SourceReplicaId,
            TargetReplicaId = request.TargetReplicaId,
            MembershipCommitment = request.MembershipCommitment,
            PlacementCommitment = request.PlacementCommitment,
            NowUnixSeconds = 1050
        };

    private static MailboxEncryptedEnvelope Envelope() =>
        new()
        {
            Epoch = 7,
            MailboxId = new BlindedMailboxId(Range(0xc0, 32)),
            PlacementId = new BlindedPlacementId(Range(0xa0, 32)),
            OperationId = Range(0x70, 16),
            DeduplicationDigest = Range(0xe0, 32),
            CreatedAtUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1120,
            Ciphertext = Range(1, 64)
        };

    private static MailboxDurableQuorumExpectationV2 Expectation(ulong cursor) =>
        new()
        {
            OperationId = Range(0x70, 16),
            Epoch = 7,
            Cursor = cursor,
            Disposition = MailboxReplicaDisposition.Tombstone,
            BlindedMailboxId = Range(0xc0, 32),
            PlacementCommitment = Range(0xa0, 32),
            MembershipCommitment = Range(0x80, 32),
            EnvelopeDigest = cursor == 42 ? Range(0xe0, 32) : Range(0x01, 32),
            ExpiresAtUnixSeconds = 1120
        };

    private static MailboxDurableQuorumReceiptV2 BuildTombstoneQuorum(
        MailboxDurableQuorumExpectationV2 expectation,
        DeterministicReceiptCrypto crypto)
    {
        MailboxReplicaReceiptV2 Replica(byte[] id)
        {
            var value = new MailboxReplicaReceiptV2
            {
                Status = MailboxReceiptStatus.Durable,
                Disposition = MailboxReplicaDisposition.Tombstone,
                ReplicaId = id,
                OperationId = expectation.OperationId,
                Epoch = expectation.Epoch,
                Cursor = expectation.Cursor,
                AcceptedAtUnixSeconds = 1001,
                DurableAtUnixSeconds = 1002,
                ExpiresAtUnixSeconds = expectation.ExpiresAtUnixSeconds,
                BlindedMailboxId = expectation.BlindedMailboxId,
                PlacementCommitment = expectation.PlacementCommitment,
                MembershipCommitment = expectation.MembershipCommitment,
                EnvelopeDigest = expectation.EnvelopeDigest,
                Signature = ReadOnlyMemory<byte>.Empty
            };
            return value with
            {
                Signature = crypto.Sign(id, MailboxReceiptV2Codec.GetReplicaSigningBytes(value))
            };
        }

        var quorum = new MailboxDurableQuorumReceiptV2
        {
            CoordinatorId = Range(0x50, 32),
            CoordinatorSequence = expectation.Cursor,
            FirstReplica = Replica(Range(0x10, 32)),
            SecondReplica = Replica(Range(0x30, 32)),
            Signature = ReadOnlyMemory<byte>.Empty
        };
        return quorum with
        {
            Signature = crypto.Sign(
                quorum.CoordinatorId.Span,
                MailboxReceiptV2Codec.GetQuorumSigningBytes(quorum, crypto))
        };
    }

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => unchecked((byte)value)).ToArray();

    private sealed class ExactProofVerifier : IMailboxReplicaMembershipProofVerifier
    {
        public int Calls { get; private set; }

        public bool VerifyStorageReplica(
            MailboxReplicaMembershipProof proof,
            ulong verificationTimeUnixSeconds)
        {
            Calls++;
            return proof.CanonicalInclusionProof.Length == 64;
        }
    }

    private sealed class DeterministicReceiptCrypto : IMailboxReceiptCrypto
    {
        public byte[] Digest(ReadOnlySpan<byte> statement) => SHA256.HashData(statement);
        public bool VerifyReplica(ReadOnlySpan<byte> replicaId, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature) =>
            CryptographicOperations.FixedTimeEquals(Sign(replicaId, signingBytes), signature);
        public bool VerifyCoordinator(ReadOnlySpan<byte> coordinatorId, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature) =>
            CryptographicOperations.FixedTimeEquals(Sign(coordinatorId, signingBytes), signature);
        public byte[] Sign(ReadOnlySpan<byte> id, ReadOnlySpan<byte> bytes) =>
            SHA256.HashData([.. id, .. bytes]);
    }
}
