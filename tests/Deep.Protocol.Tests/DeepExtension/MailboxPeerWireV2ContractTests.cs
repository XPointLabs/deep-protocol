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

        var stale = fixture.Sign(request with { CreatedAtUnixSeconds = 929 });
        Assert.Equal(
            MailboxPeerReplicationError.ExpiredOrStale,
            Assert.Throws<MailboxPeerReplicationException>(() =>
                fixture.Verify(MailboxPeerWireV2Codec.Encode(stale))).Error);
        var future = fixture.Sign(request with { CreatedAtUnixSeconds = 1081 });
        Assert.Equal(
            MailboxPeerReplicationError.ExpiredOrStale,
            Assert.Throws<MailboxPeerReplicationException>(() =>
                fixture.Verify(MailboxPeerWireV2Codec.Encode(future))).Error);

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
                Assert.Equal(MailboxWireFrame.Mqr2, endpoint.ResponseFrame);
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

    private static byte[] Mutate(byte[] value, int offset)
    {
        var result = value.ToArray();
        result[offset] ^= 1;
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
                    NowUnixSeconds = 1050
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
            return verificationTimeUnixSeconds == 1050 &&
                   proof.CanonicalInclusionProof.Length == 64;
        }
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

        public MailboxPeerReplaySnapshot Snapshot(
            MailboxPeerReplayClaim claim) =>
            snapshots[Convert.ToHexString(claim.ScopeKey.Span)];
    }
}
