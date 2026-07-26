using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class MailboxPeerReplicationContractTests
{
    [Fact]
    public void StoreAndTombstone_AreCanonicalAuthenticatedAndMembershipBound()
    {
        var crypto = new SodiumMailboxPeerReplicationCrypto();
        var sourceSeed = Range(0x10, 32);
        var targetSeed = Range(0x50, 32);
        var sourceKey = crypto.GetPublicKey(sourceSeed);
        var proof = Proof(Range(0x20, 32), sourceKey);
        var targetProof = Proof(Range(0x40, 32), crypto.GetPublicKey(targetSeed));
        var envelope = Envelope();
        var payload = MailboxClientCodec.EncodeEncryptedEnvelope(envelope);
        var unsigned = Request(MailboxPeerReplicationOperation.Store, proof, targetProof, payload) with
        {
            PayloadDigest = SHA256.HashData(payload)
        };
        var signed = crypto.SignRequest(unsigned, sourceSeed);
        var encoded = MailboxPeerReplicationCodec.Encode(signed);
        var mip1 = MailboxPeerReplicationCodec.EncodeMembershipProof(proof);
        Assert.Equal(184, mip1.Length);
        Assert.Equal(
            GoldenVectorLoader.Load("authenticated-mailbox-v2-identities.json")
                .GetRequired("deep-extension/mailbox-peer/v1/MIP1-length-184").Hex,
            Convert.ToHexString(SHA256.HashData(mip1)).ToLowerInvariant());
        Assert.Equal(904, encoded.Length);
        Assert.Equal(
            GoldenVectorLoader.Load("authenticated-mailbox-v2-identities.json")
                .GetRequired("deep-extension/mailbox-peer/v1/PRQ1-store-length-904").Hex,
            Convert.ToHexString(SHA256.HashData(encoded)).ToLowerInvariant());
        var verifier = new ExactProofVerifier();

        var verified = MailboxPeerReplicationCodec.Verify(
            encoded,
            Policy(signed),
            crypto,
            verifier);
        Assert.Equal(MailboxPeerReplicationOperation.Store, verified.Request.Operation);
        Assert.Equal(envelope.Ciphertext.ToArray(), verified.Envelope!.Ciphertext.ToArray());
        Assert.Equal(2, verifier.Calls);
        var rawPlacement = crypto.SignRequest(unsigned with
        {
            PlacementCommitment = envelope.PlacementId.Bytes.ToArray()
        }, sourceSeed);
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerReplicationCodec.Verify(
                MailboxPeerReplicationCodec.Encode(rawPlacement),
                Policy(rawPlacement),
                crypto,
                new ExactProofVerifier()));
        var unsignedReceipt = MailboxPeerReplicationCodec.CreateUnsignedReplicaResponse(
            verified,
            MailboxPeerResponseReplica.Target,
            MailboxReceiptStatus.Durable,
            MailboxReplicaDisposition.Stored,
            1001,
            1002);
        var receipt = crypto.SignReplicaResponse(unsignedReceipt, targetSeed);
        var verifiedReceipt = MailboxPeerReplicationCodec.VerifyReplicaResponse(
            MailboxReceiptV2Codec.EncodeReplica(receipt),
            verified,
            crypto);
        Assert.Equal(envelope.DeduplicationDigest.ToArray(), verifiedReceipt.EnvelopeDigest.ToArray());
        var duplicate = crypto.SignReplicaResponse(
            MailboxPeerReplicationCodec.CreateUnsignedReplicaResponse(
                verified,
                MailboxPeerResponseReplica.Target,
                MailboxReceiptStatus.Durable,
                MailboxReplicaDisposition.Duplicate,
                1001,
                1002),
            targetSeed);
        Assert.Equal(
            MailboxReplicaDisposition.Duplicate,
            MailboxPeerReplicationCodec.VerifyReplicaResponse(
                MailboxReceiptV2Codec.EncodeReplica(duplicate),
                verified,
                crypto).Disposition);
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerReplicationCodec.VerifyReplicaResponse(
                MailboxReceiptV2Codec.EncodeReplica(
                    crypto.SignReplicaResponse(unsignedReceipt, sourceSeed)),
                verified,
                crypto));
        foreach (var mutation in new Func<MailboxReplicaReceiptV2, MailboxReplicaReceiptV2>[]
        {
            value => value with { ReplicaId = Range(0x70, 32) },
            value => value with { OperationId = Range(1, 16) },
            value => value with { Epoch = 8 },
            value => value with { Cursor = 43 },
            value => value with { ExpiresAtUnixSeconds = 1121 },
            value => value with { BlindedMailboxId = Range(2, 32) },
            value => value with { PlacementCommitment = Range(3, 32) },
            value => value with { MembershipCommitment = Range(4, 32) },
            value => value with { EnvelopeDigest = SHA256.HashData(payload) },
            value => value with { Disposition = MailboxReplicaDisposition.Tombstone }
        })
        {
            var mutated = crypto.SignReplicaResponse(mutation(unsignedReceipt), targetSeed);
            Assert.Throws<MailboxPeerReplicationException>(() =>
                MailboxPeerReplicationCodec.VerifyReplicaResponse(
                    MailboxReceiptV2Codec.EncodeReplica(mutated),
                    verified,
                    crypto));
        }

        var tombstonePayload = envelope.DeduplicationDigest.ToArray();
        var tombstone = crypto.SignRequest(
            Request(MailboxPeerReplicationOperation.Tombstone, proof, targetProof, tombstonePayload),
            sourceSeed);
        var encodedTombstone = MailboxPeerReplicationCodec.Encode(tombstone);
        Assert.Equal(720, encodedTombstone.Length);
        Assert.Equal(
            GoldenVectorLoader.Load("authenticated-mailbox-v2-identities.json")
                .GetRequired("deep-extension/mailbox-peer/v1/PRQ1-tombstone-length-720").Hex,
            Convert.ToHexString(SHA256.HashData(encodedTombstone)).ToLowerInvariant());
        Assert.Equal(
            MailboxPeerReplicationOperation.Tombstone,
            MailboxPeerReplicationCodec.Verify(
                encodedTombstone,
                Policy(tombstone),
                crypto,
                new ExactProofVerifier()).Request.Operation);
        var rawTombstonePlacement = crypto.SignRequest(tombstone with
        {
            PlacementCommitment = Range(0xa0, 32)
        }, sourceSeed);
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerReplicationCodec.Verify(
                MailboxPeerReplicationCodec.Encode(rawTombstonePlacement),
                Policy(rawTombstonePlacement),
                crypto,
                new ExactProofVerifier()));
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
        var crypto = new SodiumMailboxPeerReplicationCrypto();
        var sourceSeed = Range(0x10, 32);
        var targetSeed = Range(0x40, 32);
        var source = Proof(Range(0x10, 32), crypto.GetPublicKey(sourceSeed));
        var target = Proof(Range(0x30, 32), crypto.GetPublicKey(targetSeed));
        var requests = new[]
        {
            VerifiedTombstone(42, Range(0xe0, 32)),
            VerifiedTombstone(43, Range(0x01, 32))
        };
        var receipts = requests
            .Select(BuildQuorum)
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
        Assert.Equal(1596, encoded.Length);
        Assert.Equal(
            GoldenVectorLoader.Load("authenticated-mailbox-v2-identities.json")
                .GetRequired("deep-extension/mailbox-peer/v1/MAR1-two-length-1596").Hex,
            Convert.ToHexString(SHA256.HashData(encoded)).ToLowerInvariant());
        var verified = MailboxAggregateAckCodec.Verify(
            encoded,
            requests,
            crypto);
        Assert.Equal(2, verified.Count);

        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxAggregateAckCodec.Verify(
                encoded,
                requests.Reverse().ToArray(),
                crypto));

        VerifiedMailboxPeerReplicationRequest VerifiedTombstone(ulong cursor, byte[] digest)
        {
            var request = Request(
                MailboxPeerReplicationOperation.Tombstone,
                source,
                target,
                digest) with
            { Cursor = cursor };
            var signed = crypto.SignRequest(request, sourceSeed);
            return MailboxPeerReplicationCodec.Verify(
                MailboxPeerReplicationCodec.Encode(signed),
                Policy(signed),
                crypto,
                new ExactProofVerifier());
        }

        MailboxDurableQuorumReceiptV2 BuildQuorum(
            VerifiedMailboxPeerReplicationRequest request)
        {
            var sourceReceipt = crypto.SignReplicaResponse(
                MailboxPeerReplicationCodec.CreateUnsignedReplicaResponse(
                    request,
                    MailboxPeerResponseReplica.Source,
                    MailboxReceiptStatus.Durable,
                    MailboxReplicaDisposition.Tombstone,
                    1001,
                    1002),
                sourceSeed);
            var targetReceipt = crypto.SignReplicaResponse(
                MailboxPeerReplicationCodec.CreateUnsignedReplicaResponse(
                    request,
                    MailboxPeerResponseReplica.Target,
                    MailboxReceiptStatus.Durable,
                    MailboxReplicaDisposition.Tombstone,
                    1001,
                    1002),
                targetSeed);
            return crypto.SignQuorumResponse(new MailboxDurableQuorumReceiptV2
            {
                CoordinatorId = request.Request.SourceReplicaId,
                CoordinatorSequence = request.Request.Cursor,
                FirstReplica = sourceReceipt,
                SecondReplica = targetReceipt,
                Signature = ReadOnlyMemory<byte>.Empty
            }, sourceSeed);
        }
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
            PlacementCommitment = MailboxPlacementCommitment.Compute(
                new BlindedPlacementId(Range(0xa0, 32))),
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
            PlacementId = new BlindedPlacementId(Range(0xa0, 32)),
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

}
