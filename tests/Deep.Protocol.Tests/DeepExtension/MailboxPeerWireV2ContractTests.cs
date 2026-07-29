using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class MailboxPeerWireV2ContractTests
{
    [Fact]
    public void Store_IsCanonicalFreshReplaySafeAndReturnsOnlyDurableMrr2()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Store);
        var request = fixture.Sign(fixture.Request);
        var encoded = MailboxPeerWireV2Codec.Encode(request);

        Assert.Equal(944, encoded.Length);
        Assert.Equal(encoded, MailboxPeerWireV2Codec.Encode(
            MailboxPeerWireV2Codec.Decode(encoded)));
        var vectors = GoldenVectorLoader.Load("mailbox-peer-wire-v2.json");
        Assert.Equal(
            vectors.GetRequired("deep-extension/mailbox-peer/v2/PRQ2-store").Hex,
            Convert.ToHexString(SHA256.HashData(encoded)).ToLowerInvariant());
        Assert.Equal(
            vectors.GetRequired("deep-extension/mailbox-peer/v2/PRQ2-store-signing-digest").Hex,
            Convert.ToHexString(
                MailboxPeerWireV2Codec.GetSigningDigest(request)).ToLowerInvariant());

        var verified = fixture.Verify(encoded);
        Assert.Equal(
            MailboxPeerReplayDisposition.NewReserved,
            verified.ReplayDisposition);
        Assert.Equal(
            fixture.Envelope.Ciphertext.ToArray(),
            verified.Envelope!.Ciphertext.ToArray());
        Assert.Equal(2, fixture.MembershipVerifier.Calls);

        var unsignedResponse =
            MailboxPeerWireV2Codec.CreateUnsignedDurableResponseAfterPersistence(
                verified,
                MailboxReplicaDisposition.Stored,
                1051,
                1052);
        var response = fixture.Crypto.SignReplicaResponse(
            unsignedResponse,
            fixture.RecipientSeed);
        var encodedResponse = MailboxReceiptV2Codec.EncodeReplica(response);
        Assert.Equal(
            MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength,
            encodedResponse.Length);
        Assert.Equal(
            MailboxReplicaDisposition.Stored,
            MailboxPeerWireV2Codec.VerifyReplicaResponse(
                encodedResponse,
                verified,
                fixture.Crypto).Disposition);

        MailboxPeerWireV2Codec.CompleteAtomically(
            verified,
            encodedResponse,
            fixture.Crypto,
            fixture.Journal);
        var retry = fixture.Verify(encoded);
        Assert.Equal(
            MailboxPeerReplayDisposition.IdempotentCompleted,
            retry.ReplayDisposition);
        Assert.Equal(encodedResponse, retry.CachedResponse.ToArray());

        var conflicting = fixture.Sign(request with { Cursor = 43 });
        var exception = Assert.Throws<MailboxPeerReplicationException>(() =>
            fixture.Verify(MailboxPeerWireV2Codec.Encode(conflicting)));
        Assert.Equal(MailboxPeerReplicationError.ReplayConflict, exception.Error);

        var acceptedOnly = fixture.Crypto.SignReplicaResponse(
            unsignedResponse with
            {
                Status = MailboxReceiptStatus.Accepted,
                DurableAtUnixSeconds = 0
            },
            fixture.RecipientSeed);
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.VerifyReplicaResponse(
                MailboxReceiptV2Codec.EncodeReplica(acceptedOnly),
                verified,
                fixture.Crypto));
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.VerifyReplicaResponse(
                encodedResponse.Concat(encodedResponse).ToArray(),
                verified,
                fixture.Crypto));
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.CreateUnsignedDurableResponseAfterPersistence(
                verified,
                MailboxReplicaDisposition.Stored,
                1049,
                1052));
    }

    [Fact]
    public void Tombstone_BindsDigestNonceRoutersAndTombstoneDisposition()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var request = fixture.Sign(fixture.Request);
        var encoded = MailboxPeerWireV2Codec.Encode(request);

        Assert.Equal(760, encoded.Length);
        var vectors = GoldenVectorLoader.Load("mailbox-peer-wire-v2.json");
        Assert.Equal(
            vectors.GetRequired("deep-extension/mailbox-peer/v2/PRQ2-tombstone").Hex,
            Convert.ToHexString(SHA256.HashData(encoded)).ToLowerInvariant());
        Assert.Equal(
            vectors.GetRequired("deep-extension/mailbox-peer/v2/PRQ2-tombstone-signing-digest").Hex,
            Convert.ToHexString(
                MailboxPeerWireV2Codec.GetSigningDigest(request)).ToLowerInvariant());

        var verified = fixture.Verify(encoded);
        Assert.Null(verified.Envelope);
        var response = fixture.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableResponseAfterPersistence(
                verified,
                MailboxReplicaDisposition.Tombstone,
                1051,
                1052),
            fixture.RecipientSeed);
        var encodedResponse = MailboxReceiptV2Codec.EncodeReplica(response);
        Assert.Equal(
            fixture.Envelope.DeduplicationDigest.ToArray(),
            MailboxPeerWireV2Codec.VerifyReplicaResponse(
                encodedResponse,
                verified,
                fixture.Crypto).EnvelopeDigest.ToArray());

        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.CreateUnsignedDurableResponseAfterPersistence(
                verified,
                MailboxReplicaDisposition.Stored,
                1051,
                1052));

        Assert.Throws<MailboxPeerReplicationException>(() =>
            fixture.Sign(request with
            {
                RecipientRouterId = fixture.SenderProof.ReplicaId
            }));
        var changedNonce = fixture.Sign(request with { ReplayNonce = Range(0x31, 32) });
        Assert.NotEqual(
            MailboxPeerWireV2Codec.GetSigningDigest(request),
            MailboxPeerWireV2Codec.GetSigningDigest(changedNonce));
    }

    [Fact]
    public void CanonicalLengthFreshnessDigestSignatureAndTamperFailures_AreClosed()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Store);
        var request = fixture.Sign(fixture.Request);
        var encoded = MailboxPeerWireV2Codec.Encode(request);

        foreach (var malformed in new[]
        {
            encoded[..^1],
            encoded.Concat([byte.MinValue]).ToArray(),
            Mutate(encoded, 4),
            Mutate(encoded, 290),
            Mutate(encoded, 280)
        })
        {
            Assert.Throws<MailboxPeerReplicationException>(() =>
                MailboxPeerWireV2Codec.Decode(malformed));
        }

        var badSignature = encoded.ToArray();
        badSignature[^1] ^= 1;
        Assert.Equal(
            MailboxPeerReplicationError.InvalidSignature,
            Assert.Throws<MailboxPeerReplicationException>(() =>
                fixture.Verify(badSignature)).Error);

        var staleEnvelope = fixture.Envelope with { CreatedAtUnixSeconds = 900 };
        var stalePayload = MailboxClientCodec.EncodeEncryptedEnvelope(staleEnvelope);
        var stale = fixture.Sign(request with
        {
            CreatedAtUnixSeconds = 929,
            Payload = stalePayload,
            PayloadDigest = SHA256.HashData(stalePayload)
        });
        Assert.Equal(
            MailboxPeerReplicationError.ExpiredOrStale,
            Assert.Throws<MailboxPeerReplicationException>(() =>
                fixture.Verify(MailboxPeerWireV2Codec.Encode(stale))).Error);
        Assert.Equal(0UL, MailboxPeerWireV2Limits.MaximumFutureSkewSeconds);
        foreach (var futureOffset in new ulong[] { 1, 30, 31 })
        {
            var future = fixture.Sign(request with
            {
                CreatedAtUnixSeconds = 1050 + futureOffset
            });
            Assert.Equal(
                MailboxPeerReplicationError.ExpiredOrStale,
                Assert.Throws<MailboxPeerReplicationException>(() =>
                    fixture.Verify(MailboxPeerWireV2Codec.Encode(future))).Error);
        }

        var badDigest = fixture.Sign(request with { PayloadDigest = Range(1, 32) });
        Assert.Equal(
            MailboxPeerReplicationError.InvalidPayload,
            Assert.Throws<MailboxPeerReplicationException>(() =>
                fixture.Verify(MailboxPeerWireV2Codec.Encode(badDigest))).Error);

        Assert.Throws<MailboxPeerReplicationException>(() =>
            fixture.Sign(request with
            {
                SenderRouterId = Range(0x60, 32)
            }));
        Assert.Throws<ArgumentException>(() =>
            fixture.Sign(request with
            {
                SenderMembershipProof = fixture.RecipientProof,
                RecipientMembershipProof = fixture.SenderProof
            }));
    }

    [Fact]
    public void SignedCreatedAtBoundary_IsZeroSkewForStoreAndTombstone()
    {
        foreach (var operation in new[]
        {
            MailboxPeerReplicationOperation.Store,
            MailboxPeerReplicationOperation.Tombstone
        })
        {
            var atNow = new Fixture(operation);
            var canonical = MailboxPeerWireV2Codec.Encode(
                atNow.Sign(atNow.Request with
                {
                    CreatedAtUnixSeconds = 1050
                }));
            var reserved = atNow.Verify(canonical);
            Assert.Equal(
                MailboxPeerReplayDisposition.NewReserved,
                reserved.ReplayDisposition);
            Assert.Equal(
                reserved.ReplayClaim.CreatedAtUnixSeconds,
                reserved.ReplayClaim.ReservedAtUnixSeconds);

            foreach (var futureOffset in new ulong[] { 1, 30, 31 })
            {
                var future = new Fixture(operation);
                var encoded = MailboxPeerWireV2Codec.Encode(
                    future.Sign(future.Request with
                    {
                        CreatedAtUnixSeconds = 1050 + futureOffset
                    }));
                Assert.Equal(
                    MailboxPeerReplicationError.ExpiredOrStale,
                    Assert.Throws<MailboxPeerReplicationException>(() =>
                        future.Verify(encoded)).Error);
            }
        }
    }

    [Fact]
    public void NegativeVectors_ReachTheirNamedFailClosedErrors()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Store);
        var canonical = MailboxPeerWireV2Codec.Encode(
            fixture.Sign(fixture.Request));
        var vectors = GoldenVectorLoader.Load(
            "mailbox-peer-wire-v2-negative.json");
        foreach (var vector in vectors.Vectors)
        {
            var mutated = canonical.ToArray();
            if (StringComparer.Ordinal.Equals(
                    vector.Kind,
                    "decode-append-zero"))
                mutated = mutated.Concat([byte.MinValue]).ToArray();
            else
                mutated[vector.MutationOffset!.Value] ^= 1;

            var exception = Assert.Throws<MailboxPeerReplicationException>(() =>
            {
                if (StringComparer.Ordinal.Equals(
                        vector.Kind,
                        "verify-xor-offset"))
                    _ = fixture.Verify(mutated);
                else
                    _ = MailboxPeerWireV2Codec.Decode(mutated);
            });
            Assert.Equal(vector.ExpectedError, exception.Error.ToString());
        }
    }

    [Fact]
    public void FullTruncationAndDeterministicMalformedSmoke_StayStructured()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Store);
        var canonical = MailboxPeerWireV2Codec.Encode(
            fixture.Sign(fixture.Request));
        for (var length = 0; length < canonical.Length; length++)
        {
            Assert.Throws<MailboxPeerReplicationException>(() =>
                MailboxPeerWireV2Codec.Decode(canonical.AsSpan(0, length)));
        }

        var random = new Random(0x10b);
        for (var iteration = 0; iteration < 500; iteration++)
        {
            var bytes = new byte[random.Next(0, 2048)];
            random.NextBytes(bytes);
            try
            {
                _ = MailboxPeerWireV2Codec.Decode(bytes);
            }
            catch (MailboxPeerReplicationException)
            {
                continue;
            }

            Assert.Fail("Random malformed PRQ2 unexpectedly decoded.");
        }
    }

    [Fact]
    public void ReplayStateMachine_RetainsPendingAcrossCrashAndRejectsEquivocation()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var encoded = MailboxPeerWireV2Codec.Encode(
            fixture.Sign(fixture.Request));
        var first = fixture.Verify(encoded);
        var pendingSnapshot = fixture.Journal.Snapshot(first.ReplayClaim);

        var recoveredJournal = new InMemoryReplayJournal(
            first.ReplayClaim.ScopeKey,
            pendingSnapshot);
        var recoveredFixture = fixture with { Journal = recoveredJournal };
        var recovered = recoveredFixture.Verify(encoded);
        Assert.Equal(
            MailboxPeerReplayDisposition.InFlight,
            recovered.ReplayDisposition);
        Assert.Empty(recovered.CachedResponse.ToArray());

        var changed = recoveredFixture.Sign(
            recovered.Request with { Cursor = recovered.Request.Cursor + 1 });
        Assert.Equal(
            MailboxPeerReplicationError.ReplayConflict,
            Assert.Throws<MailboxPeerReplicationException>(() =>
                recoveredFixture.Verify(
                    MailboxPeerWireV2Codec.Encode(changed))).Error);
    }

    [Fact]
    public void HttpMetadata_FreezesRawRoutesFramesBoundsAndEmptyErrorStatuses()
    {
        Assert.Collection(
            MailboxWireHttpContract.ClientEndpoints,
            endpoint =>
            {
                Assert.Equal("/api/client/mailbox/v1/store", endpoint.Route);
                Assert.Equal("POST", endpoint.Method);
                Assert.Equal(MailboxWireFrame.Mst1, endpoint.RequestFrame);
                Assert.Equal(MailboxWireFrame.Mqr3, endpoint.ResponseFrame);
                Assert.Equal(
                    "application/vnd.deep.mailbox.mqr3",
                    endpoint.ResponseContentType);
                Assert.Equal(82_836, endpoint.MaximumRequestBytes);
                Assert.Equal(776, endpoint.MaximumResponseBytes);
            },
            endpoint =>
            {
                Assert.Equal("/api/client/mailbox/v1/retrieve", endpoint.Route);
                Assert.Equal(MailboxWireFrame.Mrt1, endpoint.RequestFrame);
                Assert.Equal(MailboxWireFrame.Mrp1, endpoint.ResponseFrame);
                Assert.Equal(1_244, endpoint.MaximumRequestBytes);
                Assert.Equal(1_048_576, endpoint.MaximumResponseBytes);
            },
            endpoint =>
            {
                Assert.Equal(
                    "/api/client/mailbox/v1/acknowledge",
                    endpoint.Route);
                Assert.Equal(MailboxWireFrame.Mak1, endpoint.RequestFrame);
                Assert.Equal(MailboxWireFrame.Mar1, endpoint.ResponseFrame);
                Assert.Equal(5_244, endpoint.MaximumRequestBytes);
                Assert.Equal(77_840, endpoint.MaximumResponseBytes);
            });
        Assert.All(
            MailboxWireHttpContract.ClientEndpoints,
            endpoint => Assert.Equal(200, endpoint.SuccessStatusCode));
        Assert.Collection(
            MailboxWireHttpContract.PeerEndpoints,
            endpoint =>
            {
                Assert.Equal("/api/peer/mailbox/v2/store", endpoint.Route);
                Assert.Equal(
                    MailboxPeerWireV2Limits.MaximumRequestLength,
                    endpoint.MaximumRequestBytes);
                Assert.Equal(MailboxWireFrame.Mrr2, endpoint.ResponseFrame);
            },
            endpoint =>
            {
                Assert.Equal(
                    "/api/peer/mailbox/v2/tombstone",
                    endpoint.Route);
                Assert.Equal(8_824, endpoint.MaximumRequestBytes);
            });
        Assert.True(MailboxWireHttpContract.RequiresContentLength);
        Assert.False(MailboxWireHttpContract.AllowsContentEncoding);
        Assert.Equal(0, MailboxWireHttpContract.ErrorResponseBytes);
        Assert.Equal(60, MailboxWireHttpContract.RateWindowSeconds);
        Assert.Equal(
            "application/vnd.deep.mailbox.mar1",
            MailboxWireHttpContract.Acknowledge.ResponseContentType);
        Assert.Equal(
            400,
            MailboxWireHttpContract.StatusCode(
                MailboxHttpFailure.MalformedCanonicalBody));
        Assert.Equal(
            409,
            MailboxWireHttpContract.StatusCode(
                MailboxHttpFailure.ReplayOrIdempotencyConflict));
        Assert.Equal(
            413,
            MailboxWireHttpContract.StatusCode(
                MailboxHttpFailure.PayloadTooLarge));
        Assert.Equal(
            405,
            MailboxWireHttpContract.StatusCode(
                MailboxHttpFailure.MethodNotAllowed));
        Assert.Equal(
            411,
            MailboxWireHttpContract.StatusCode(
                MailboxHttpFailure.MissingContentLength));
        Assert.Equal(
            415,
            MailboxWireHttpContract.StatusCode(
                MailboxHttpFailure.UnsupportedContentTypeOrEncoding));
        Assert.Equal(
            503,
            MailboxWireHttpContract.StatusCode(
                MailboxHttpFailure.DependencyUnavailable));
    }

    [Fact]
    public void DurableQuorum_RequiresExactTwoAuthorizedCanonicalPrq2Replicas()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var verified = fixture.Verify(MailboxPeerWireV2Codec.Encode(
            fixture.Sign(fixture.Request)));
        var (sender, recipient, quorumBytes) = SignedQuorum(fixture, verified);
        var quorum = MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(
            quorumBytes,
            verified,
            fixture.Crypto);
        _ = MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(
            quorumBytes,
            verified,
            new WrongDigestCrypto(fixture.Crypto));
        Assert.Equal(
            GoldenVectorLoader.Load("mailbox-peer-wire-v2.json")
                .GetRequired(
                    "deep-extension/mailbox-peer/v2/MQR3-tombstone")
                .Hex,
            Convert.ToHexString(SHA256.HashData(quorumBytes))
                .ToLowerInvariant());
        Assert.Equal(2, quorum.ReplicaReceipts.Count);
        Assert.True(
            quorum.ReplicaReceipts[0].ReplicaId.Span.SequenceCompareTo(
                quorum.ReplicaReceipts[1].ReplicaId.Span) < 0);

        var duplicate = fixture.Crypto.SignQuorumResponse(
            new MailboxDurableQuorumReceiptV3
            {
                CoordinatorId = verified.Request.SenderRouterId,
                CoordinatorSequence = verified.Request.Cursor,
                FirstReplica = sender,
                SecondReplica = sender,
                Signature = ReadOnlyMemory<byte>.Empty
            },
            fixture.SenderSeed);
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(
                MailboxReceiptV3Codec.EncodeDurableQuorum(duplicate),
                verified,
                fixture.Crypto));

        foreach (var mutation in new Func<MailboxReplicaReceiptV2, MailboxReplicaReceiptV2>[]
        {
            value => value with { Cursor = value.Cursor + 1 },
            value => value with { EnvelopeDigest = Range(1, 32) },
            value => value with { ExpiresAtUnixSeconds = value.ExpiresAtUnixSeconds + 1 },
            value => value with { ReplicaId = Range(0x61, 32) }
        })
        {
            var changed = fixture.Crypto.SignReplicaResponse(
                mutation(recipient),
                fixture.RecipientSeed);
            Assert.Throws<MailboxPeerReplicationException>(() =>
                MailboxPeerWireV2Codec.CreateUnsignedDurableQuorumResponse(
                    verified,
                    MailboxReceiptV2Codec.EncodeReplica(sender),
                    MailboxReceiptV2Codec.EncodeReplica(changed),
                    verified.Request.SenderRouterId,
                    fixture.Crypto));
        }

        var wrongKey = fixture.Crypto.SignReplicaResponse(
            sender,
            fixture.RecipientSeed);
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.CreateUnsignedDurableQuorumResponse(
                verified,
                MailboxReceiptV2Codec.EncodeReplica(wrongKey),
                MailboxReceiptV2Codec.EncodeReplica(recipient),
                verified.Request.SenderRouterId,
                fixture.Crypto));

        var decoded = MailboxReceiptV3Codec.DecodeDurableQuorum(quorumBytes);
        var wrongCoordinator = fixture.Crypto.SignQuorumResponse(
            decoded with { CoordinatorId = verified.Request.RecipientRouterId },
            fixture.SenderSeed);
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(
                MailboxReceiptV3Codec.EncodeDurableQuorum(wrongCoordinator),
                verified,
                fixture.Crypto));

        var reordered = SwapMqr3Replicas(quorumBytes);
        Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptV3Codec.DecodeDurableQuorum(reordered));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(100)]
    public void AggregateAck_BindsOrderedMak1TombstonesAndMqr3AtBounds(int count)
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var (ack, tombstones, quorums) = AckBatch(fixture, count);
        var encoded = MailboxPeerWireV2AggregateAckCodec.Create(
            ack,
            tombstones,
            quorums,
            fixture.Crypto);
        var verified = MailboxPeerWireV2AggregateAckCodec.Verify(
            encoded,
            ack,
            tombstones,
            fixture.Crypto);
        Assert.Equal(count, verified.Count);
        Assert.Equal(
            count == 1 ? 818 : 77_840,
            encoded.Length);
        Assert.Equal(
            GoldenVectorLoader.Load("mailbox-peer-wire-v2.json")
                .GetRequired(count == 1
                    ? "deep-extension/mailbox-peer/v2/MAR1-ack-1"
                    : "deep-extension/mailbox-peer/v2/MAR1-ack-100")
                .Hex,
            Convert.ToHexString(SHA256.HashData(encoded)).ToLowerInvariant());
    }

    [Fact]
    public void AggregateAck_RejectsDuplicateReorderAndSubstitution()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var (ack, tombstones, quorums) = AckBatch(fixture, 3);
        var encoded = MailboxPeerWireV2AggregateAckCodec.Create(
            ack,
            tombstones,
            quorums,
            fixture.Crypto);

        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2AggregateAckCodec.Verify(
                encoded,
                ack,
                tombstones.Reverse().ToArray(),
                fixture.Crypto));
        Assert.Throws<MailboxClientException>(() =>
            MailboxPeerWireV2AggregateAckCodec.Create(
                ack with
                {
                    Acknowledgements =
                    [
                        ack.Acknowledgements[0],
                        ack.Acknowledgements[0],
                        ack.Acknowledgements[2]
                    ]
                },
                tombstones,
                quorums,
                fixture.Crypto));
        var substituted = quorums.ToArray();
        substituted[1] = quorums[0];
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2AggregateAckCodec.Create(
                ack,
                tombstones,
                substituted,
                fixture.Crypto));
        var digestChanged = ack with
        {
            Acknowledgements = ack.Acknowledgements
                .Select((value, index) => index == 1
                    ? value with { EnvelopeDigest = Range(3, 32) }
                    : value)
                .ToArray()
        };
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2AggregateAckCodec.Create(
                digestChanged,
                tombstones,
                quorums,
                fixture.Crypto));
        var cursorChanged = ack with
        {
            Acknowledgements = ack.Acknowledgements
                .Select((value, index) => index == 1
                    ? value with { Cursor = value.Cursor + 10 }
                    : value)
                .ToArray()
        };
        Assert.Throws<MailboxClientException>(() =>
            MailboxPeerWireV2AggregateAckCodec.Create(
                cursorChanged,
                tombstones,
                quorums,
                fixture.Crypto));
    }

    [Fact]
    public void MixedPrq1AndPrq2FramesOrReceipts_DoNotDowngrade()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var legacy = new MailboxPeerReplicationRequest
        {
            Operation = MailboxPeerReplicationOperation.Tombstone,
            Epoch = fixture.Request.Epoch,
            OperationId = fixture.Request.OperationId,
            SourceReplicaId = fixture.Request.SenderRouterId,
            TargetReplicaId = fixture.Request.RecipientRouterId,
            MembershipCommitment = fixture.Request.MembershipCommitment,
            PlacementCommitment = fixture.Request.PlacementCommitment,
            BlindedMailboxId = fixture.Request.BlindedMailboxId,
            Cursor = fixture.Request.Cursor,
            ExpiresAtUnixSeconds = fixture.Request.ExpiresAtUnixSeconds,
            PayloadDigest = fixture.Request.Payload,
            Payload = fixture.Request.Payload,
            SourceMembershipProof = fixture.SenderProof,
            TargetMembershipProof = fixture.RecipientProof,
            Signature = ReadOnlyMemory<byte>.Empty
        };
        legacy = fixture.Crypto.SignRequest(legacy, fixture.SenderSeed);
        var legacyVerified = new VerifiedMailboxPeerReplicationRequest
        {
            Request = legacy,
            Envelope = null
        };
        Assert.Equal(
            MailboxPeerReplicationError.InvalidMagic,
            Assert.Throws<MailboxPeerReplicationException>(() =>
                MailboxPeerWireV2Codec.Decode(
                    MailboxPeerReplicationCodec.Encode(legacy))).Error);

        var verified = fixture.Verify(MailboxPeerWireV2Codec.Encode(
            fixture.Sign(fixture.Request)));
        var forgedLegacyTime = fixture.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableReplicaResponseAfterPersistence(
                verified,
                MailboxPeerWireResponseReplicaV2.Sender,
                MailboxReplicaDisposition.Tombstone,
                1050,
                1051) with
            {
                AcceptedAtUnixSeconds = 1001,
                DurableAtUnixSeconds = 1002
            },
            fixture.SenderSeed);
        var recipient = fixture.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableReplicaResponseAfterPersistence(
                verified,
                MailboxPeerWireResponseReplicaV2.Recipient,
                MailboxReplicaDisposition.Tombstone,
                1050,
                1051),
            fixture.RecipientSeed);
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.CreateUnsignedDurableQuorumResponse(
                verified,
                MailboxReceiptV2Codec.EncodeReplica(forgedLegacyTime),
                MailboxReceiptV2Codec.EncodeReplica(recipient),
                verified.Request.SenderRouterId,
                fixture.Crypto));

        var prq2Quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(
            SignedQuorum(fixture, verified).EncodedQuorum);
        var changedSequence = fixture.Crypto.SignQuorumResponse(
            prq2Quorum with
            {
                CoordinatorSequence = verified.Request.Cursor,
                Signature = ReadOnlyMemory<byte>.Empty
            },
            fixture.SenderSeed);
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(
                MailboxReceiptV3Codec.EncodeDurableQuorum(changedSequence),
                verified,
                fixture.Crypto));

        var (quorumSender, quorumRecipient, mqr3Bytes) =
            SignedQuorum(fixture, verified);
        _ = MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(
            mqr3Bytes,
            verified,
            fixture.Crypto);
        Assert.Throws<MailboxReceiptException>(() =>
            MailboxPeerReplicationCodec.VerifyDurableQuorumResponse(
                mqr3Bytes,
                legacyVerified,
                fixture.Crypto));

        var mqr3 = MailboxReceiptV3Codec.DecodeDurableQuorum(mqr3Bytes);
        var mqr2 = fixture.Crypto.SignQuorumResponse(
            new MailboxDurableQuorumReceiptV2
            {
                CoordinatorId = mqr3.CoordinatorId,
                CoordinatorSequence = mqr3.CoordinatorSequence,
                FirstReplica = quorumSender,
                SecondReplica = quorumRecipient,
                Signature = ReadOnlyMemory<byte>.Empty
            },
            fixture.SenderSeed);
        var mqr2Bytes = MailboxReceiptV2Codec.EncodeDurableQuorum(mqr2);
        _ = MailboxPeerReplicationCodec.VerifyDurableQuorumResponse(
            mqr2Bytes,
            legacyVerified,
            fixture.Crypto);
        Assert.Throws<MailboxReceiptException>(() =>
            MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(
                mqr2Bytes,
                verified,
                fixture.Crypto));

        var recastAsMqr3 = mqr2Bytes.ToArray();
        "MQR3"u8.CopyTo(recastAsMqr3);
        recastAsMqr3[4] = 3;
        Assert.Equal(
            MailboxPeerReplicationError.InvalidReceipt,
            Assert.Throws<MailboxPeerReplicationException>(() =>
                MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(
                    recastAsMqr3,
                    verified,
                    fixture.Crypto)).Error);

        var recastAsMqr2 = mqr3Bytes.ToArray();
        "MQR2"u8.CopyTo(recastAsMqr2);
        recastAsMqr2[4] = 2;
        Assert.Equal(
            MailboxPeerReplicationError.InvalidReceipt,
            Assert.Throws<MailboxPeerReplicationException>(() =>
                MailboxPeerReplicationCodec.VerifyDurableQuorumResponse(
                    recastAsMqr2,
                    legacyVerified,
                    fixture.Crypto)).Error);

        var legacyMar1 = MailboxAggregateAckCodec.Encode(
            new MailboxAggregateAckResponse
            {
                Epoch = legacy.Epoch,
                OperationId = legacy.OperationId,
                TombstoneQuorums = [mqr2Bytes]
            });
        _ = MailboxAggregateAckCodec.Decode(legacyMar1);
        Assert.Throws<MailboxReceiptException>(() =>
            MailboxAggregateAckCodec.DecodeMqr3(legacyMar1));

        var prq2Mar1 = MailboxAggregateAckCodec.EncodeMqr3(
            new MailboxAggregateAckResponse
            {
                Epoch = verified.Request.Epoch,
                OperationId = verified.Request.OperationId,
                TombstoneQuorums = [mqr3Bytes]
            });
        _ = MailboxAggregateAckCodec.DecodeMqr3(prq2Mar1);
        Assert.Throws<MailboxReceiptException>(() =>
            MailboxAggregateAckCodec.Decode(prq2Mar1));
    }

    [Fact]
    public void ReplayRetention_IsEpochScopedFiniteCrashSafeAndBatchBounded()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var encoded = MailboxPeerWireV2Codec.Encode(fixture.Sign(fixture.Request));
        var verified = fixture.Verify(encoded);
        var snapshot = fixture.Journal.Snapshot(verified.ReplayClaim);
        Assert.Equal(1050UL, snapshot.ReservedAtUnixSeconds);
        Assert.Equal(1200UL, snapshot.EpochExpiresAtUnixSeconds);
        Assert.Equal(
            1200UL + MailboxPeerWireV2Limits.ReplayRetentionSeconds,
            snapshot.RetainUntilUnixSeconds);
        Assert.Equal(
            1_209_600,
            MailboxPeerWireV2Limits.MaximumReplayRecordsPerRouterPairPerEpoch);
        Assert.False(MailboxPeerReplayStateMachine.IsCollectable(
            snapshot,
            snapshot.RetainUntilUnixSeconds - 1));
        Assert.True(MailboxPeerReplayStateMachine.IsCollectable(
            snapshot,
            snapshot.RetainUntilUnixSeconds));

        var journal = new InMemoryReplayJournal();
        for (var index = 0; index < 1100; index++)
        {
            var nonce = SHA256.HashData(UInt64Bytes(checked((ulong)index + 1)));
            var claim = verified.ReplayClaim with
            {
                ReplayNonce = nonce,
                ScopeKey = MailboxPeerReplayStateMachine.ComputeScopeKey(
                    verified.Request.SenderRouterId.Span,
                    verified.Request.RecipientRouterId.Span,
                    verified.Request.Epoch,
                    nonce),
                RequestDigest = SHA256.HashData(nonce)
            };
            Assert.Equal(
                MailboxPeerReplayState.NewReserved,
                journal.EvaluateAndReserve(claim).State);
        }

        Assert.Equal(
            MailboxPeerWireV2Limits.MaximumReplayCollectionBatch,
            journal.CollectExpired(
                snapshot.RetainUntilUnixSeconds,
                MailboxPeerWireV2Limits.MaximumReplayCollectionBatch));
        Assert.Equal(
            76,
            journal.CollectExpired(
                snapshot.RetainUntilUnixSeconds,
                MailboxPeerWireV2Limits.MaximumReplayCollectionBatch));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            journal.CollectExpired(
                snapshot.RetainUntilUnixSeconds,
                MailboxPeerWireV2Limits.MaximumReplayCollectionBatch + 1));

        var nextEpochScope = MailboxPeerReplayStateMachine.ComputeScopeKey(
            verified.Request.SenderRouterId.Span,
            verified.Request.RecipientRouterId.Span,
            verified.Request.Epoch + 1,
            verified.Request.ReplayNonce.Span);
        Assert.NotEqual(
            verified.ReplayClaim.ScopeKey.ToArray(),
            nextEpochScope);
    }

    [Fact]
    public void ExactPendingAndCompletedRetries_UsePersistedReservationPastAdmissionFreshness()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Store);
        var envelope = fixture.Envelope with { ExpiresAtUnixSeconds = 1190 };
        var payload = MailboxClientCodec.EncodeEncryptedEnvelope(envelope);
        var request = fixture.Sign(fixture.Request with
        {
            ExpiresAtUnixSeconds = envelope.ExpiresAtUnixSeconds,
            Payload = payload,
            PayloadDigest = SHA256.HashData(payload)
        });
        var encoded = MailboxPeerWireV2Codec.Encode(request);
        var first = fixture.Verify(encoded);
        Assert.Equal(1050UL, first.ReplayClaim.ReservedAtUnixSeconds);

        var pendingRetry = fixture.VerifyAt(encoded, 1171, 1200);
        Assert.Equal(MailboxPeerReplayDisposition.InFlight, pendingRetry.ReplayDisposition);
        Assert.Equal(1050UL, pendingRetry.ReplayClaim.ReservedAtUnixSeconds);

        var response = fixture.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableResponseAfterPersistence(
                pendingRetry,
                MailboxReplicaDisposition.Stored,
                pendingRetry.ReplayClaim.ReservedAtUnixSeconds,
                pendingRetry.ReplayClaim.ReservedAtUnixSeconds),
            fixture.RecipientSeed);
        var canonicalResponse = MailboxReceiptV2Codec.EncodeReplica(response);
        fixture.Journal.CompleteAtomically(pendingRetry.ReplayClaim, canonicalResponse);

        var completedRetry = fixture.VerifyAt(encoded, 1172, 1200);
        Assert.Equal(
            MailboxPeerReplayDisposition.IdempotentCompleted,
            completedRetry.ReplayDisposition);
        Assert.Equal(1050UL, completedRetry.ReplayClaim.ReservedAtUnixSeconds);
        Assert.Equal(canonicalResponse, completedRetry.CachedResponse.ToArray());

        var unknown = new Fixture(MailboxPeerReplicationOperation.Store);
        var stale = Assert.Throws<MailboxPeerReplicationException>(() =>
            unknown.VerifyAt(encoded, 1172, 1200));
        Assert.Equal(MailboxPeerReplicationError.ExpiredOrStale, stale.Error);
        Assert.Equal(0, unknown.Journal.Count);
    }

    [Fact]
    public void ReplaySnapshotWithReservationOutsideOriginalFreshnessWindow_FailsClosed()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Store);
        var encoded = MailboxPeerWireV2Codec.Encode(fixture.Sign(fixture.Request));
        var verified = fixture.Verify(encoded);
        var snapshot = fixture.Journal.Snapshot(verified.ReplayClaim) with
        {
            ReservedAtUnixSeconds =
                verified.ReplayClaim.CreatedAtUnixSeconds +
                MailboxPeerWireV2Limits.MaximumPastAgeSeconds + 1
        };
        var retry = verified.ReplayClaim with
        {
            ReservedAtUnixSeconds = snapshot.ReservedAtUnixSeconds
        };

        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerReplayStateMachine.EvaluateAndReserve(snapshot, retry));
    }

    [Fact]
    public void PostRetentionOldExactAndConflictAreStaleBeforeJournal()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var encoded = MailboxPeerWireV2Codec.Encode(fixture.Sign(fixture.Request));
        var verified = fixture.Verify(encoded);
        Assert.Equal(
            1,
            fixture.Journal.CollectExpired(
                verified.ReplayClaim.RetainUntilUnixSeconds,
                1));
        var lateNow = verified.ReplayClaim.RetainUntilUnixSeconds;
        Assert.Equal(
            MailboxPeerReplicationError.ExpiredOrStale,
            Assert.Throws<MailboxPeerReplicationException>(() =>
                fixture.VerifyAt(encoded, lateNow, 1200)).Error);
        var conflicting = fixture.Sign(
            fixture.Request with { Cursor = fixture.Request.Cursor + 1 });
        Assert.Equal(
            MailboxPeerReplicationError.ExpiredOrStale,
            Assert.Throws<MailboxPeerReplicationException>(() =>
                fixture.VerifyAt(
                    MailboxPeerWireV2Codec.Encode(conflicting),
                    lateNow,
                    1200)).Error);
    }

    [Fact]
    public void TombstoneLifetimeAndForgedAcceptedAtCachedRetry_FailClosed()
    {
        var fixture = new Fixture(MailboxPeerReplicationOperation.Tombstone);
        var tooLong = fixture.Sign(fixture.Request with
        {
            ExpiresAtUnixSeconds =
                fixture.Request.CreatedAtUnixSeconds +
                MailboxPeerWireV2Limits.MaximumTombstoneLifetimeSeconds +
                1
        });
        Assert.Equal(
            MailboxPeerReplicationError.ExpiredOrStale,
            Assert.Throws<MailboxPeerReplicationException>(() =>
                fixture.VerifyAt(
                    MailboxPeerWireV2Codec.Encode(tooLong),
                    1050,
                    tooLong.ExpiresAtUnixSeconds)).Error);

        var encoded = MailboxPeerWireV2Codec.Encode(fixture.Sign(fixture.Request));
        var verified = fixture.Verify(encoded);
        var forged = fixture.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableResponseAfterPersistence(
                verified,
                MailboxReplicaDisposition.Tombstone,
                1050,
                1051) with
            {
                AcceptedAtUnixSeconds = 1049
            },
            fixture.RecipientSeed);
        var forgedBytes = MailboxReceiptV2Codec.EncodeReplica(forged);
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerWireV2Codec.VerifyReplicaResponse(
                forgedBytes,
                verified,
                fixture.Crypto));
        var forgedSnapshot = MailboxPeerReplayStateMachine.Complete(
            fixture.Journal.Snapshot(verified.ReplayClaim),
            verified.ReplayClaim,
            forgedBytes);
        var recovered = fixture with
        {
            Journal = new InMemoryReplayJournal(
                verified.ReplayClaim.ScopeKey,
                forgedSnapshot)
        };
        Assert.Throws<MailboxPeerReplicationException>(() =>
            recovered.Verify(encoded));
    }

    private static (
        MailboxReplicaReceiptV2 Sender,
        MailboxReplicaReceiptV2 Recipient,
        byte[] EncodedQuorum) SignedQuorum(
        Fixture fixture,
        VerifiedMailboxPeerWireRequestV2 verified)
    {
        var sender = fixture.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableReplicaResponseAfterPersistence(
                verified,
                MailboxPeerWireResponseReplicaV2.Sender,
                MailboxReplicaDisposition.Tombstone,
                1050,
                1051),
            fixture.SenderSeed);
        var recipient = fixture.Crypto.SignReplicaResponse(
            MailboxPeerWireV2Codec.CreateUnsignedDurableReplicaResponseAfterPersistence(
                verified,
                MailboxPeerWireResponseReplicaV2.Recipient,
                MailboxReplicaDisposition.Tombstone,
                1050,
                1051),
            fixture.RecipientSeed);
        var unsigned = MailboxPeerWireV2Codec.CreateUnsignedDurableQuorumResponse(
            verified,
            MailboxReceiptV2Codec.EncodeReplica(recipient),
            MailboxReceiptV2Codec.EncodeReplica(sender),
            verified.Request.SenderRouterId,
            fixture.Crypto);
        var signed = fixture.Crypto.SignQuorumResponse(
            unsigned,
            fixture.SenderSeed);
        return (
            sender,
            recipient,
            MailboxReceiptV3Codec.EncodeDurableQuorum(signed));
    }

    private static (
        MailboxAckRequest Ack,
        VerifiedMailboxPeerWireRequestV2[] Tombstones,
        ReadOnlyMemory<byte>[] Quorums) AckBatch(
        Fixture fixture,
        int count)
    {
        var acknowledgements = new MailboxAcknowledgement[count];
        var tombstones = new VerifiedMailboxPeerWireRequestV2[count];
        var quorums = new ReadOnlyMemory<byte>[count];
        for (var index = 0; index < count; index++)
        {
            var cursor = checked((ulong)index + 1);
            var digest = SHA256.HashData(UInt64Bytes(cursor));
            var nonce = SHA256.HashData([
                .. "p10b-ack-nonce"u8,
                .. UInt64Bytes(cursor)
            ]);
            var request = fixture.Sign(fixture.Request with
            {
                Cursor = cursor,
                ReplayNonce = nonce,
                Payload = digest,
                PayloadDigest = SHA256.HashData(digest)
            });
            var verified = fixture.Verify(
                MailboxPeerWireV2Codec.Encode(request));
            acknowledgements[index] = new MailboxAcknowledgement
            {
                Cursor = cursor,
                EnvelopeDigest = digest
            };
            tombstones[index] = verified;
            quorums[index] = SignedQuorum(fixture, verified).EncodedQuorum;
        }

        return (
            new MailboxAckRequest
            {
                Epoch = fixture.Request.Epoch,
                OperationId = fixture.Request.OperationId,
                MixedVersion = MailboxMixedVersionMarker.StrictV1,
                RetrieveCapability = RetrieveCapability(),
                MailboxId = fixture.Envelope.MailboxId,
                PlacementId = fixture.Envelope.PlacementId,
                IsFinalPage = true,
                ContinuationToken = ReadOnlyMemory<byte>.Empty,
                Acknowledgements = acknowledgements
            },
            tombstones,
            quorums);
    }

    private static MailboxCapabilityPresentation RetrieveCapability() =>
        new()
        {
            DomainValue = new RotatingRetrieveCapability(Range(0xb0, 32)),
            Lifecycle = MailboxCapabilityLifecycle.Active,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            Generation = 7,
            NotBeforeBucket = 1000,
            ExpiresAtBucket = 1100,
            OverlapUntilBucket = 0,
            ReplayCounter = 9,
            IdempotencyKey = Range(0x20, 16)
        };

    private static byte[] SwapMqr3Replicas(byte[] encoded)
    {
        var result = encoded.ToArray();
        const int firstOffset = MailboxReceiptV3Limits.QuorumFixedHeaderLength;
        const int replicaLength =
            MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength;
        var first = result.AsSpan(firstOffset, replicaLength).ToArray();
        result.AsSpan(firstOffset + replicaLength, replicaLength)
            .CopyTo(result.AsSpan(firstOffset, replicaLength));
        first.CopyTo(result, firstOffset + replicaLength);
        return result;
    }

    private static byte[] Mutate(byte[] value, int offset)
    {
        var result = value.ToArray();
        result[offset] ^= 1;
        return result;
    }

    private static byte[] UInt64Bytes(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length)
            .Select(static value => unchecked((byte)value))
            .ToArray();

    private sealed record Fixture
    {
        public Fixture(MailboxPeerReplicationOperation operation)
        {
            Operation = operation;
            Crypto = new SodiumMailboxPeerReplicationCrypto();
            SenderSeed = Range(0x10, 32);
            RecipientSeed = Range(0x50, 32);
            SenderProof = Proof(
                Range(0x20, 32),
                Crypto.GetPublicKey(SenderSeed));
            RecipientProof = Proof(
                Range(0x40, 32),
                Crypto.GetPublicKey(RecipientSeed));
            Envelope = new MailboxEncryptedEnvelope
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
            var payload = operation == MailboxPeerReplicationOperation.Store
                ? MailboxClientCodec.EncodeEncryptedEnvelope(Envelope)
                : Envelope.DeduplicationDigest.ToArray();
            Request = new MailboxPeerWireRequestV2
            {
                Operation = operation,
                Epoch = 7,
                OperationId = Envelope.OperationId,
                SenderRouterId = SenderProof.ReplicaId,
                RecipientRouterId = RecipientProof.ReplicaId,
                MembershipCommitment = Range(0x80, 32),
                PlacementCommitment = MailboxPlacementCommitment.Compute(
                    Envelope.PlacementId),
                BlindedMailboxId = Envelope.MailboxId.Bytes,
                Cursor = operation == MailboxPeerReplicationOperation.Store
                    ? 42UL
                    : 43UL,
                CreatedAtUnixSeconds = 1050,
                ExpiresAtUnixSeconds = Envelope.ExpiresAtUnixSeconds,
                ReplayNonce = Range(0x30, 32),
                PayloadDigest = SHA256.HashData(payload),
                Payload = payload,
                SenderMembershipProof = SenderProof,
                RecipientMembershipProof = RecipientProof,
                Signature = ReadOnlyMemory<byte>.Empty
            };
            Journal = new InMemoryReplayJournal();
            MembershipVerifier = new ExactProofVerifier();
        }

        public MailboxPeerReplicationOperation Operation { get; }
        public SodiumMailboxPeerReplicationCrypto Crypto { get; }
        public byte[] SenderSeed { get; }
        public byte[] RecipientSeed { get; }
        public MailboxReplicaMembershipProof SenderProof { get; }
        public MailboxReplicaMembershipProof RecipientProof { get; }
        public MailboxEncryptedEnvelope Envelope { get; }
        public MailboxPeerWireRequestV2 Request { get; }
        public InMemoryReplayJournal Journal { get; init; }
        public ExactProofVerifier MembershipVerifier { get; } = new();

        public MailboxPeerWireRequestV2 Sign(MailboxPeerWireRequestV2 request) =>
            Crypto.SignRequest(request with
            {
                Signature = ReadOnlyMemory<byte>.Empty
            }, SenderSeed);

        public VerifiedMailboxPeerWireRequestV2 Verify(ReadOnlySpan<byte> encoded) =>
            VerifyAt(encoded, 1050, 1200);

        public VerifiedMailboxPeerWireRequestV2 VerifyAt(
            ReadOnlySpan<byte> encoded,
            ulong nowUnixSeconds,
            ulong epochExpiresAtUnixSeconds) =>
            MailboxPeerWireV2Codec.VerifyAndReserve(
                encoded,
                new MailboxPeerWireVerificationPolicyV2
                {
                    ExpectedOperation = Operation,
                    Epoch = Request.Epoch,
                    OperationId = Request.OperationId,
                    SenderRouterId = Request.SenderRouterId,
                    RecipientRouterId = Request.RecipientRouterId,
                    MembershipCommitment = Request.MembershipCommitment,
                    PlacementCommitment = Request.PlacementCommitment,
                    PlacementId = Envelope.PlacementId,
                    NowUnixSeconds = nowUnixSeconds,
                    EpochExpiresAtUnixSeconds = epochExpiresAtUnixSeconds
                },
                Crypto,
                MembershipVerifier,
                Journal);

        private static MailboxReplicaMembershipProof Proof(
            byte[] routerId,
            byte[] signingPublicKey) =>
            new()
            {
                ReplicaId = routerId,
                SigningPublicKey = signingPublicKey,
                Epoch = 7,
                MembershipCommitment = Range(0x80, 32),
                CanonicalInclusionProof = Range(1, 64)
            };
    }

    private sealed class ExactProofVerifier :
        IMailboxReplicaMembershipProofVerifier
    {
        public int Calls { get; private set; }

        public bool VerifyStorageReplica(
            MailboxReplicaMembershipProof proof,
            ulong verificationTimeUnixSeconds)
        {
            Calls++;
            return verificationTimeUnixSeconds is >= 1050 and < 1200 &&
                   proof.CanonicalInclusionProof.Length == 64;
        }
    }

    private sealed class WrongDigestCrypto(
        SodiumMailboxPeerReplicationCrypto inner) : IMailboxPeerReplicationCrypto
    {
        public bool Verify(
            ReadOnlySpan<byte> publicKey,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) =>
            inner.Verify(publicKey, signingBytes, signature);

        public byte[] Digest(ReadOnlySpan<byte> canonicalBytes) =>
            Range(1, 32);
    }

    private sealed class InMemoryReplayJournal : IMailboxPeerReplayJournal
    {
        private readonly Dictionary<string, MailboxPeerReplaySnapshot> snapshots = [];

        public InMemoryReplayJournal()
        {
        }

        public InMemoryReplayJournal(
            ReadOnlyMemory<byte> scopeKey,
            MailboxPeerReplaySnapshot snapshot)
        {
            snapshots.Add(Convert.ToHexString(scopeKey.Span), snapshot);
        }

        public MailboxPeerReplayEvaluation EvaluateAndReserve(
            MailboxPeerReplayClaim claim)
        {
            var key = Convert.ToHexString(claim.ScopeKey.Span);
            snapshots.TryGetValue(key, out var current);
            var (evaluation, next) =
                MailboxPeerReplayStateMachine.EvaluateAndReserve(current, claim);
            snapshots[key] = next;
            return evaluation;
        }

        public MailboxPeerReplayEvaluation? EvaluateExisting(
            MailboxPeerReplayClaim claim)
        {
            var key = Convert.ToHexString(claim.ScopeKey.Span);
            if (!snapshots.TryGetValue(key, out var current))
            {
                return null;
            }

            return MailboxPeerReplayStateMachine.EvaluateAndReserve(current, claim)
                .Evaluation;
        }

        public int Count => snapshots.Count;

        public void CompleteAtomically(
            MailboxPeerReplayClaim claim,
            ReadOnlyMemory<byte> canonicalMrr2Response)
        {
            var key = Convert.ToHexString(claim.ScopeKey.Span);
            snapshots[key] = MailboxPeerReplayStateMachine.Complete(
                snapshots[key],
                claim,
                canonicalMrr2Response.Span);
        }

        public int CollectExpired(
            ulong nowUnixSeconds,
            int maximumRecords)
        {
            if (maximumRecords is
                    <= 0 or
                    > MailboxPeerWireV2Limits.MaximumReplayCollectionBatch)
                throw new ArgumentOutOfRangeException(nameof(maximumRecords));
            var keys = snapshots
                .Where(pair => MailboxPeerReplayStateMachine.IsCollectable(
                    pair.Value,
                    nowUnixSeconds))
                .Take(maximumRecords)
                .Select(static pair => pair.Key)
                .ToArray();
            foreach (var key in keys)
                _ = snapshots.Remove(key);
            return keys.Length;
        }

        public MailboxPeerReplaySnapshot Snapshot(
            MailboxPeerReplayClaim claim) =>
            snapshots[Convert.ToHexString(claim.ScopeKey.Span)];
    }
}
