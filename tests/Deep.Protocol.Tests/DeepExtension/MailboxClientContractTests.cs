using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class MailboxClientContractTests
{
    private static readonly byte[] OperationId = Range(0x10, 16);
    private static readonly byte[] MailboxId = Range(0x30, 32);
    private static readonly byte[] PlacementId = Range(0x50, 32);
    private static readonly byte[] EnvelopeDigest = Range(0x70, 32);

    [Fact]
    public void CanonicalClientFrames_MatchGoldenVectors_AndRoundTrip()
    {
        var vectors = GoldenVectorLoader.Load("mailbox-client-v1.json");
        var envelope = Envelope();
        var store = Store(envelope);
        var retrieve = Retrieve();
        var ack = Ack();

        AssertGolden(vectors, "deep-extension/mailbox-client/v1/envelope", MailboxClientCodec.EncodeEncryptedEnvelope(envelope));
        AssertGolden(vectors, "deep-extension/mailbox-client/v1/store", MailboxClientCodec.EncodeStore(store));
        AssertGolden(vectors, "deep-extension/mailbox-client/v1/retrieve", MailboxClientCodec.EncodeRetrieve(retrieve));
        AssertGolden(vectors, "deep-extension/mailbox-client/v1/ack", MailboxClientCodec.EncodeAck(ack));

        var decodedStore = MailboxClientCodec.DecodeStore(
            MailboxClientCodec.EncodeStore(store),
            Policy(),
            new AlwaysAcceptReplayGuard());
        Assert.IsType<RotatingDepositCapability>(decodedStore.DepositCapability.DomainValue);
        Assert.Equal(MailboxId, decodedStore.Envelope.MailboxId.Bytes.ToArray());

        var decodedRetrieve = MailboxClientCodec.DecodeRetrieve(
            MailboxClientCodec.EncodeRetrieve(retrieve),
            Policy(),
            new AlwaysAcceptReplayGuard());
        Assert.IsType<RotatingRetrieveCapability>(decodedRetrieve.RetrieveCapability.DomainValue);
        Assert.Equal(25, decodedRetrieve.MaximumItems);

        var decodedAck = MailboxClientCodec.DecodeAck(
            MailboxClientCodec.EncodeAck(ack),
            Policy(),
            new AlwaysAcceptReplayGuard());
        Assert.True(decodedAck.IsFinalPage);
        Assert.Equal(new ulong[] { 41, 42 }, decodedAck.Acknowledgements.Select(static item => item.Cursor));
    }

    [Fact]
    public void StoreSurface_NeverAcceptsRetrieveCapabilityOrMasterMaterial()
    {
        var envelope = Envelope();
        var retrieve = Store(envelope) with
        {
            DepositCapability = Capability(new RotatingRetrieveCapability(Range(0xb0, 32)))
        };
        var exception = Assert.Throws<MailboxClientException>(() => MailboxClientCodec.EncodeStore(retrieve));
        Assert.Equal(MailboxClientError.InvalidCapabilityDomain, exception.Error);

        var propertyNames = typeof(MailboxStoreRequest)
            .GetProperties()
            .Select(static property => property.Name)
            .ToArray();
        Assert.DoesNotContain(propertyNames, static name =>
            name.Contains("Retrieve", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("Master", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("SessionId", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("UserId", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void EpochWindow_AcceptsOnlyBoundedEAndEPlusOneOverlap()
    {
        var window = EpochWindow();
        Assert.True(window.Accepts(7, 1010));
        Assert.True(window.Accepts(8, 1010));
        Assert.False(window.Accepts(9, 1010));
        Assert.False(window.Accepts(7, 1101));

        Assert.Throws<MailboxClientException>(() =>
            (window with { NextEpoch = 9 }).Validate());
        Assert.Throws<MailboxClientException>(() =>
            (window with { NextNotBeforeUnixSeconds = 1101 }).Validate());

        var nextEnvelope = Envelope() with { Epoch = 8 };
        Assert.Equal(
            8UL,
            MailboxClientCodec.DecodeEncryptedEnvelope(
                MailboxClientCodec.EncodeEncryptedEnvelope(nextEnvelope),
                Policy()).Epoch);
    }

    [Fact]
    public void CiphertextAndTtlBounds_AreStrict()
    {
        _ = MailboxClientCodec.EncodeEncryptedEnvelope(Envelope() with
        {
            Ciphertext = Range(0, MailboxClientLimits.MinimumCiphertextLength),
            ExpiresAtUnixSeconds = 1060
        });
        _ = MailboxClientCodec.EncodeEncryptedEnvelope(Envelope() with
        {
            Ciphertext = Enumerable.Repeat((byte)0x5a, MailboxClientLimits.MaximumCiphertextLength).ToArray(),
            ExpiresAtUnixSeconds = 1000 + MailboxClientLimits.MaximumTtlSeconds
        });

        Assert.Equal(
            MailboxClientError.InvalidCiphertext,
            Assert.Throws<MailboxClientException>(() =>
                MailboxClientCodec.EncodeEncryptedEnvelope(Envelope() with
                {
                    Ciphertext = new byte[MailboxClientLimits.MinimumCiphertextLength - 1]
                })).Error);
        Assert.Equal(
            MailboxClientError.InvalidTtl,
            Assert.Throws<MailboxClientException>(() =>
                MailboxClientCodec.EncodeEncryptedEnvelope(Envelope() with
                {
                    ExpiresAtUnixSeconds = 1059
                })).Error);
        Assert.Equal(
            MailboxClientError.InvalidTtl,
            Assert.Throws<MailboxClientException>(() =>
                MailboxClientCodec.EncodeEncryptedEnvelope(Envelope() with
                {
                    ExpiresAtUnixSeconds = 1001 + MailboxClientLimits.MaximumTtlSeconds
                })).Error);
    }

    [Fact]
    public void TamperTrailingAndCrossVersionDowngrade_FailClosed()
    {
        var envelope = MailboxClientCodec.EncodeEncryptedEnvelope(Envelope());
        foreach (var mutation in new Action<byte[]>[]
        {
            bytes => bytes[4] = 0,
            bytes => bytes[4] = 2,
            bytes => bytes[5] = 1,
            bytes => bytes[148] = 1,
            bytes => bytes[144] = 0xff
        })
        {
            var tampered = envelope.ToArray();
            mutation(tampered);
            Assert.Throws<MailboxClientException>(() =>
                MailboxClientCodec.DecodeEncryptedEnvelope(tampered, Policy()));
        }

        Assert.Throws<MailboxClientException>(() =>
            MailboxClientCodec.DecodeEncryptedEnvelope([.. envelope, (byte)0], Policy()));

        var retrieve = MailboxClientCodec.EncodeRetrieve(Retrieve());
        retrieve[4] = 2;
        Assert.Equal(
            MailboxClientError.UnsupportedVersion,
            Assert.Throws<MailboxClientException>(() =>
                MailboxClientCodec.DecodeRetrieve(
                    retrieve,
                    Policy(),
                    new AlwaysAcceptReplayGuard())).Error);

        var legacy = Retrieve() with
        {
            MixedVersion = MailboxMixedVersionMarker.LegacyMirrorOverlap,
            RetrieveCapability = Capability(
                new RotatingRetrieveCapability(Range(0xb0, 32))) with
            {
                Lifecycle = MailboxCapabilityLifecycle.Overlap,
                MixedVersion = MailboxMixedVersionMarker.LegacyMirrorOverlap,
                OverlapUntilBucket = 1050
            }
        };
        Assert.Equal(
            MailboxClientError.DowngradeRejected,
            Assert.Throws<MailboxClientException>(() =>
                MailboxClientCodec.DecodeRetrieve(
                    MailboxClientCodec.EncodeRetrieve(legacy),
                    Policy(),
                    new AlwaysAcceptReplayGuard())).Error);
    }

    [Fact]
    public void RetrieveAndAckPagination_AreCanonicalAndBounded()
    {
        var page = new MailboxRetrievePage
        {
            Epoch = 7,
            OperationId = OperationId,
            NextCursor = 42,
            HasMore = true,
            ContinuationToken = Range(0xe0, 8),
            Envelopes = [Envelope()]
        };
        var encoded = MailboxClientCodec.EncodeRetrievePage(page);
        var decoded = MailboxClientCodec.DecodeRetrievePage(encoded, Policy());
        Assert.True(decoded.HasMore);
        Assert.Single(decoded.Envelopes);

        Assert.Throws<MailboxClientException>(() =>
            MailboxClientCodec.EncodeRetrieve(Retrieve() with { MaximumItems = 101 }));
        Assert.Throws<MailboxClientException>(() =>
            MailboxClientCodec.EncodeRetrievePage(page with
            {
                ContinuationToken = ReadOnlyMemory<byte>.Empty
            }));
        Assert.Throws<MailboxClientException>(() =>
            MailboxClientCodec.EncodeAck(Ack() with
            {
                Acknowledgements =
                [
                    new MailboxAcknowledgement { Cursor = 42, EnvelopeDigest = EnvelopeDigest },
                    new MailboxAcknowledgement { Cursor = 41, EnvelopeDigest = Range(0x90, 32) }
                ]
            }));
        Assert.Throws<MailboxClientException>(() =>
            MailboxClientCodec.DecodeRetrievePage([.. encoded, (byte)0], Policy()));
    }

    [Fact]
    public void Delivered_IsNeverSynthesizedFromAcceptanceOrDurabilityAlone()
    {
        Assert.Equal(
            MailboxClientDeliveryStatus.Durable,
            MailboxDeliveryStateMachine.Transition(
                MailboxClientDeliveryStatus.Accepted,
                MailboxClientDeliveryStatus.Durable,
                new MailboxDeliveryTransitionEvidence { DurableQuorumVerified = true }));
        Assert.Throws<MailboxClientException>(() =>
            MailboxDeliveryStateMachine.Transition(
                MailboxClientDeliveryStatus.Accepted,
                MailboxClientDeliveryStatus.Delivered,
                new MailboxDeliveryTransitionEvidence
                {
                    DurableQuorumVerified = true,
                    PayloadAuthenticatedAndDecrypted = true,
                    DurableAckTombstoneVerified = true
                }));
        Assert.Throws<MailboxClientException>(() =>
            MailboxDeliveryStateMachine.Transition(
                MailboxClientDeliveryStatus.Durable,
                MailboxClientDeliveryStatus.Delivered,
                new MailboxDeliveryTransitionEvidence
                {
                    PayloadAuthenticatedAndDecrypted = true,
                    DurableAckTombstoneVerified = false
                }));
        Assert.Equal(
            MailboxClientDeliveryStatus.Delivered,
            MailboxDeliveryStateMachine.Transition(
                MailboxClientDeliveryStatus.Durable,
                MailboxClientDeliveryStatus.Delivered,
                new MailboxDeliveryTransitionEvidence
                {
                    PayloadAuthenticatedAndDecrypted = true,
                    DurableAckTombstoneVerified = true
                }));
    }

    [Fact]
    public void DomainLabels_AreExplicitAndUnique()
    {
        var labels = new[]
        {
            MailboxDomainSeparation.DepositCapability,
            MailboxDomainSeparation.RetrieveCapability,
            MailboxDomainSeparation.BlindedMailboxId,
            MailboxDomainSeparation.PlacementId,
            MailboxDomainSeparation.EnvelopeDigest,
            MailboxDomainSeparation.ReplicaReceipt,
            MailboxDomainSeparation.CoordinatorReceipt
        };
        Assert.Equal(labels.Length, labels.Distinct(StringComparer.Ordinal).Count());
        Assert.All(labels, static label => Assert.StartsWith("deep.mailbox.", label, StringComparison.Ordinal));
    }

    [Fact]
    public void RandomMalformedClientFrames_NeverEscapeContractExceptions()
    {
        var random = new Random(0x9c51);
        for (var iteration = 0; iteration < 500; iteration++)
        {
            var bytes = new byte[random.Next(0, 2048)];
            random.NextBytes(bytes);
            AssertContractFailure(() =>
                MailboxClientCodec.DecodeEncryptedEnvelope(bytes, Policy()));
            AssertContractFailure(() =>
                MailboxClientCodec.DecodeRetrievePage(bytes, Policy()));
        }
    }

    private static MailboxEncryptedEnvelope Envelope() =>
        new()
        {
            Epoch = 7,
            MailboxId = new BlindedMailboxId(MailboxId),
            PlacementId = new BlindedPlacementId(PlacementId),
            OperationId = OperationId,
            DeduplicationDigest = EnvelopeDigest,
            CreatedAtUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1120,
            Ciphertext = Range(0xa0, 32)
        };

    private static MailboxStoreRequest Store(MailboxEncryptedEnvelope envelope) =>
        new()
        {
            Epoch = 7,
            OperationId = OperationId,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            DepositCapability = Capability(new RotatingDepositCapability(Range(0x90, 32))),
            Envelope = envelope
        };

    private static MailboxRetrieveRequest Retrieve() =>
        new()
        {
            Epoch = 7,
            OperationId = OperationId,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            RetrieveCapability = Capability(new RotatingRetrieveCapability(Range(0xb0, 32))),
            MailboxId = new BlindedMailboxId(MailboxId),
            PlacementId = new BlindedPlacementId(PlacementId),
            AfterCursor = 40,
            MaximumItems = 25,
            ContinuationToken = Range(0xd0, 8)
        };

    private static MailboxAckRequest Ack() =>
        new()
        {
            Epoch = 7,
            OperationId = OperationId,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            RetrieveCapability = Capability(new RotatingRetrieveCapability(Range(0xb0, 32))),
            MailboxId = new BlindedMailboxId(MailboxId),
            PlacementId = new BlindedPlacementId(PlacementId),
            IsFinalPage = true,
            ContinuationToken = ReadOnlyMemory<byte>.Empty,
            Acknowledgements =
            [
                new MailboxAcknowledgement { Cursor = 41, EnvelopeDigest = EnvelopeDigest },
                new MailboxAcknowledgement { Cursor = 42, EnvelopeDigest = Range(0x90, 32) }
            ]
        };

    private static MailboxCapabilityPresentation Capability(MailboxDomainValue value) =>
        new()
        {
            DomainValue = value,
            Lifecycle = MailboxCapabilityLifecycle.Active,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            Generation = 7,
            NotBeforeBucket = 1000,
            ExpiresAtBucket = 1100,
            OverlapUntilBucket = 0,
            ReplayCounter = 9,
            IdempotencyKey = Range(0x20, 16)
        };

    private static MailboxClientDecodePolicy Policy() =>
        new()
        {
            NowUnixSeconds = 1010,
            EpochWindow = EpochWindow(),
            CapabilityPolicy = new MailboxCapabilityDecodePolicy
            {
                CurrentBucket = 1010,
                MinimumGeneration = 7,
                AllowLegacyMirrorOverlap = false,
                AllowRevoked = false,
                AllowRecovery = false
            },
            AllowLegacyMirrorOverlap = false
        };

    private static MailboxEpochWindow EpochWindow() =>
        new()
        {
            CurrentEpoch = 7,
            NextEpoch = 8,
            CurrentNotBeforeUnixSeconds = 900,
            NextNotBeforeUnixSeconds = 950,
            CurrentExpiresAtUnixSeconds = 1100,
            NextExpiresAtUnixSeconds = 1200
        };

    private static void AssertGolden(GoldenVectorSet vectors, string id, byte[] encoded) =>
        Assert.Equal(
            vectors.GetRequired(id).Hex,
            Convert.ToHexString(encoded).ToLowerInvariant());

    private static void AssertContractFailure(Action decode)
    {
        try
        {
            decode();
        }
        catch (MailboxClientException)
        {
            return;
        }

        Assert.Fail("Random malformed bytes unexpectedly decoded as a canonical client mailbox frame.");
    }

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => unchecked((byte)value)).ToArray();

    private sealed class AlwaysAcceptReplayGuard : IMailboxCapabilityReplayGuard
    {
        public MailboxCapabilityReplayEvaluation Evaluate(MailboxCapabilityReplayScope scope) =>
            new()
            {
                Decision = MailboxCapabilityReplayDecision.AcceptedNew,
                CachedOutcome = ReadOnlyMemory<byte>.Empty
            };
    }
}
