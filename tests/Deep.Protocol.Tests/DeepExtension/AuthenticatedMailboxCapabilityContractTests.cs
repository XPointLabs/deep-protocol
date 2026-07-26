using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class AuthenticatedMailboxCapabilityContractTests
{
    [Fact]
    public void OfflineIssuerAndHolder_BindExactStoreRequest()
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuerSeed = Range(0x10, 32);
        var holderSeed = Range(0x40, 32);
        var grant = Grant(
            crypto.GetPublicKey(issuerSeed),
            crypto.GetPublicKey(holderSeed),
            MailboxCapabilityDomain.Deposit);
        var signedGrant = crypto.SignGrant(grant, issuerSeed);
        var binding = Binding(MailboxAuthenticatedOperation.Store);
        var presentation = crypto.SignPresentation(
            signedGrant,
            binding,
            replayCounter: 9,
            holderSeed);
        var encoded = MailboxAuthenticatedCapabilityCodec.EncodePresentation(presentation);
        var vector = GoldenVectorLoader.Load("authenticated-mailbox-v2.json")
            .GetRequired("deep-extension/mailbox-capability/v2/deposit-store");
        Assert.Equal(vector.Hex, Convert.ToHexString(encoded).ToLowerInvariant());

        var replay = new MemoryReplayJournal();
        var outer = MailboxAuthenticatedClientRequestCodec.Encode(
            new MailboxAuthenticatedClientRequest
            {
                Binding = binding,
                Presentation = presentation
            });
        var verifiedOuter = MailboxAuthenticatedClientRequestCodec.Verify(
            outer,
            Policy(grant),
            crypto,
            new NoRevocations(),
            replay);
        var verified = verifiedOuter.Capability;

        Assert.Equal(MailboxAuthenticatedReplayDisposition.NewReserved, verified.ReplayDisposition);
        Assert.Equal(grant.Serial.ToArray(), verified.Grant.Serial.ToArray());
        Assert.DoesNotContain(
            typeof(MailboxAuthenticatedGrant).GetProperties(),
            property => property.Name.Contains("Session", StringComparison.OrdinalIgnoreCase) ||
                        property.Name.Contains("Payment", StringComparison.OrdinalIgnoreCase) ||
                        property.Name.Contains("Wallet", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RequestOperationDomainAndSignatures_FailClosed()
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuerSeed = Range(0x10, 32);
        var holderSeed = Range(0x40, 32);
        var grant = crypto.SignGrant(
            Grant(
                crypto.GetPublicKey(issuerSeed),
                crypto.GetPublicKey(holderSeed),
                MailboxCapabilityDomain.Deposit),
            issuerSeed);
        var binding = Binding(MailboxAuthenticatedOperation.Store);
        var encoded = MailboxAuthenticatedCapabilityCodec.EncodePresentation(
            crypto.SignPresentation(grant, binding, 9, holderSeed));

        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.Verify(
                encoded,
                MailboxAuthenticatedRequestTranscript.ForStore(StoreEnvelope() with
                {
                    Ciphertext = Range(0x02, 64)
                }),
                Policy(grant),
                crypto,
                new NoRevocations(),
                new MemoryReplayJournal()));
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.Verify(
                encoded,
                Binding(MailboxAuthenticatedOperation.Retrieve),
                Policy(grant),
                crypto,
                new NoRevocations(),
                new MemoryReplayJournal()));

        encoded[^1] ^= 1;
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.Verify(
                encoded,
                binding,
                Policy(grant),
                crypto,
                new NoRevocations(),
                new MemoryReplayJournal()));
    }

    [Fact]
    public void RotationRevocationReplayAndMixedVersion_AreExplicit()
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuerSeed = Range(0x10, 32);
        var holderSeed = Range(0x40, 32);
        var grant = crypto.SignGrant(
            Grant(
                crypto.GetPublicKey(issuerSeed),
                crypto.GetPublicKey(holderSeed),
                MailboxCapabilityDomain.Retrieve),
            issuerSeed);
        var binding = Binding(MailboxAuthenticatedOperation.Ack);
        var encoded = MailboxAuthenticatedCapabilityCodec.EncodePresentation(
            crypto.SignPresentation(grant, binding, 9, holderSeed));
        var replay = new MemoryReplayJournal();

        _ = MailboxAuthenticatedCapabilityCodec.Verify(
            encoded, binding, Policy(grant), crypto, new NoRevocations(), replay);
        var second = MailboxAuthenticatedCapabilityCodec.Verify(
            encoded, binding, Policy(grant), crypto, new NoRevocations(), replay);
        Assert.Equal(MailboxAuthenticatedReplayDisposition.InFlight, second.ReplayDisposition);

        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.Verify(
                encoded,
                binding,
                Policy(grant) with { MinimumGeneration = grant.Generation + 1 },
                crypto,
                new NoRevocations(),
                new MemoryReplayJournal()));
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.Verify(
                encoded,
                binding,
                Policy(grant),
                crypto,
                new AllRevoked(),
                new MemoryReplayJournal()));

        var v1 = MailboxCapabilityCodec.Encode(new MailboxCapabilityPresentation
        {
            DomainValue = new RotatingRetrieveCapability(Range(1, 32)),
            Lifecycle = MailboxCapabilityLifecycle.Active,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            Generation = 1,
            NotBeforeBucket = 1,
            ExpiresAtBucket = 2,
            OverlapUntilBucket = 0,
            ReplayCounter = 1,
            IdempotencyKey = Range(2, 16)
        });
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.DecodePresentation(v1));
    }

    [Fact]
    public void TypedTranscripts_BindEveryCriticalStoreRetrieveAndAckField()
    {
        var store = StoreEnvelope();
        var storeDigest = MailboxAuthenticatedRequestTranscript.ForStore(store).RequestDigest;
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForStore(store with { Epoch = 12 }).RequestDigest, storeDigest);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForStore(store with { OperationId = Range(1, 16) }).RequestDigest, storeDigest);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForStore(store with { MailboxId = new BlindedMailboxId(Range(2, 32)) }).RequestDigest, storeDigest);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForStore(store with { PlacementId = new BlindedPlacementId(Range(3, 32)) }).RequestDigest, storeDigest);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForStore(store with { DeduplicationDigest = Range(4, 32) }).RequestDigest, storeDigest);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForStore(store with { CreatedAtUnixSeconds = 999 }).RequestDigest, storeDigest);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForStore(store with { ExpiresAtUnixSeconds = 1061 }).RequestDigest, storeDigest);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForStore(store with { Ciphertext = Range(5, 64) }).RequestDigest, storeDigest);

        var operationId = Range(0xd0, 16);
        var mailbox = new BlindedMailboxId(Range(0x20, 32));
        var placement = new BlindedPlacementId(Range(0x90, 32));
        var retrieve = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            11, operationId, mailbox, placement, 42, 10, Range(1, 8)).RequestDigest;
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForRetrieve(
            12, operationId, mailbox, placement, 42, 10, Range(1, 8)).RequestDigest, retrieve);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForRetrieve(
            11, Range(2, 16), mailbox, placement, 42, 10, Range(1, 8)).RequestDigest, retrieve);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForRetrieve(
            11, operationId, new BlindedMailboxId(Range(3, 32)), placement, 42, 10, Range(1, 8)).RequestDigest, retrieve);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForRetrieve(
            11, operationId, mailbox, new BlindedPlacementId(Range(4, 32)), 42, 10, Range(1, 8)).RequestDigest, retrieve);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForRetrieve(
            11, operationId, mailbox, placement, 43, 10, Range(1, 8)).RequestDigest, retrieve);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForRetrieve(
            11, operationId, mailbox, placement, 42, 11, Range(1, 8)).RequestDigest, retrieve);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForRetrieve(
            11, operationId, mailbox, placement, 42, 10, Range(2, 8)).RequestDigest, retrieve);

        var entries = new[]
        {
            new MailboxAcknowledgement { Cursor = 42, EnvelopeDigest = Range(0xe0, 32) },
            new MailboxAcknowledgement { Cursor = 43, EnvelopeDigest = Range(1, 32) }
        };
        var ack = MailboxAuthenticatedRequestTranscript.ForAck(
            11, operationId, mailbox, placement, false, Range(1, 8), entries).RequestDigest;
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForAck(
            11, operationId, mailbox, placement, true, [], entries).RequestDigest, ack);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForAck(
            11, operationId, mailbox, placement, false, Range(2, 8), entries).RequestDigest, ack);
        AssertChanged(MailboxAuthenticatedRequestTranscript.ForAck(
            11, operationId, mailbox, placement, false, Range(1, 8),
            [entries[0], entries[1] with { EnvelopeDigest = Range(2, 32) }]).RequestDigest, ack);
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedRequestTranscript.ForAck(
                11, operationId, mailbox, placement, true, Range(1, 8), entries));
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedRequestTranscript.ForAck(
                11, operationId, mailbox, placement, false, [], entries));
        Assert.NotEqual(storeDigest.ToArray(), retrieve.ToArray());
        Assert.NotEqual(retrieve.ToArray(), ack.ToArray());
    }

    [Fact]
    public void Mau2CarriesExactMcp2AndCanonicalBody_ForAllOperations()
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuerSeed = Range(0x10, 32);
        var holderSeed = Range(0x40, 32);
        var identities = new List<string>();
        foreach (var operation in new[]
        {
            MailboxAuthenticatedOperation.Store,
            MailboxAuthenticatedOperation.Retrieve,
            MailboxAuthenticatedOperation.Ack
        })
        {
            var domain = operation == MailboxAuthenticatedOperation.Store
                ? MailboxCapabilityDomain.Deposit
                : MailboxCapabilityDomain.Retrieve;
            var grant = crypto.SignGrant(
                Grant(
                    crypto.GetPublicKey(issuerSeed),
                    crypto.GetPublicKey(holderSeed),
                    domain),
                issuerSeed);
            var binding = Binding(operation);
            var presentation = crypto.SignPresentation(grant, binding, 9, holderSeed);
            var encoded = MailboxAuthenticatedClientRequestCodec.Encode(
                new MailboxAuthenticatedClientRequest
                {
                    Binding = binding,
                    Presentation = presentation
                });
            var decoded = MailboxAuthenticatedClientRequestCodec.Decode(encoded);
            identities.Add(
                $"{operation}:{encoded.Length}:" +
                Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(encoded)).ToLowerInvariant());
            Assert.Equal(operation, decoded.Binding.Operation);
            Assert.Equal(binding.CanonicalRequest.ToArray(), decoded.Binding.CanonicalRequest.ToArray());
            Assert.Equal(binding.RequestDigest.ToArray(), decoded.Presentation.RequestDigest.ToArray());
        }
        var vectors = GoldenVectorLoader.Load("authenticated-mailbox-v2-identities.json");
        Assert.Equal(
            $"Store:640:{vectors.GetRequired("deep-extension/mailbox-authenticated/v2/MAU2-store-length-640").Hex}",
            identities[0]);
        Assert.Equal(
            $"Retrieve:544:{vectors.GetRequired("deep-extension/mailbox-authenticated/v2/MAU2-retrieve-length-544").Hex}",
            identities[1]);
        Assert.Equal(
            $"Ack:576:{vectors.GetRequired("deep-extension/mailbox-authenticated/v2/MAU2-ack-length-576").Hex}",
            identities[2]);

        var legacy = MailboxClientCodec.EncodeEncryptedEnvelope(StoreEnvelope());
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedClientRequestCodec.Decode(legacy));
    }

    [Fact]
    public void IssuerAuthority_BindsDomainGenerationLifecycleAndHardWindow()
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuerSeed = Range(0x10, 32);
        var holderSeed = Range(0x40, 32);
        var grant = crypto.SignGrant(
            Grant(
                crypto.GetPublicKey(issuerSeed),
                crypto.GetPublicKey(holderSeed),
                MailboxCapabilityDomain.Deposit),
            issuerSeed);
        var binding = Binding(MailboxAuthenticatedOperation.Store);
        var encoded = MailboxAuthenticatedCapabilityCodec.EncodePresentation(
            crypto.SignPresentation(grant, binding, 9, holderSeed));
        var policy = Policy(grant);
        var authority = policy.TrustedIssuers.Single();
        foreach (var invalid in new[]
        {
            authority with { MaximumGeneration = grant.Generation - 1 },
            authority with { Domain = MailboxCapabilityDomain.Retrieve },
            authority with { AllowedLifecycle = MailboxCapabilityLifecycle.Overlap },
            authority with { ValidFromUnixSeconds = grant.NotBeforeUnixSeconds + 1 },
            authority with { ValidUntilUnixSeconds = grant.ExpiresAtUnixSeconds - 1 }
        })
        {
            Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
                MailboxAuthenticatedCapabilityCodec.Verify(
                    encoded,
                    binding,
                    policy with { TrustedIssuers = [invalid] },
                    crypto,
                    new NoRevocations(),
                    new MemoryReplayJournal()));
        }
    }

    [Fact]
    public void DirectVerifierRejectsRawPlacementAndUnauthenticatedInputsBeforeDurableLookups()
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuerSeed = Range(0x10, 32);
        var holderSeed = Range(0x40, 32);
        var canonicalGrant = Grant(
            crypto.GetPublicKey(issuerSeed),
            crypto.GetPublicKey(holderSeed),
            MailboxCapabilityDomain.Deposit);
        var binding = Binding(MailboxAuthenticatedOperation.Store);

        var rawGrant = crypto.SignGrant(canonicalGrant with
        {
            PlacementCommitment = new BlindedPlacementId(Range(0x90, 32)).Bytes.ToArray()
        }, issuerSeed);
        var rawEncoded = MailboxAuthenticatedCapabilityCodec.EncodePresentation(
            crypto.SignPresentation(rawGrant, binding, 9, holderSeed));
        var rawReplay = new MemoryReplayJournal();
        var rawRevocations = new CountingRevocations();
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.Verify(
                rawEncoded,
                binding,
                Policy(rawGrant),
                crypto,
                rawRevocations,
                rawReplay));
        Assert.Equal(0, rawReplay.Calls);
        Assert.Equal(0, rawRevocations.Calls);

        var signedGrant = crypto.SignGrant(canonicalGrant, issuerSeed);
        var encoded = MailboxAuthenticatedCapabilityCodec.EncodePresentation(
            crypto.SignPresentation(signedGrant, binding, 9, holderSeed));
        foreach (var offset in new[] { 72 + 208, encoded.Length - 1 })
        {
            var tampered = encoded.ToArray();
            tampered[offset] ^= 1;
            var replay = new MemoryReplayJournal();
            var revocations = new CountingRevocations();
            Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
                MailboxAuthenticatedCapabilityCodec.Verify(
                    tampered,
                    binding,
                    Policy(signedGrant),
                    crypto,
                    revocations,
                    replay));
            Assert.Equal(0, replay.Calls);
            Assert.Equal(0, revocations.Calls);
        }
    }

    [Fact]
    public void ReplayStateMachine_IsMonotonicCrashSafeAndConflictAware()
    {
        var claim = Claim(9, Range(1, 32));
        var reserved = MailboxCapabilityReplayStateMachine.EvaluateAndReserve(null, claim);
        Assert.Equal(MailboxCapabilityAtomicReplayState.NewReserved, reserved.Evaluation.State);
        var pendingAfterRestart = MailboxCapabilityReplayStateMachine.EvaluateAndReserve(
            reserved.NextSnapshot,
            claim);
        Assert.Equal(MailboxCapabilityAtomicReplayState.PendingSame, pendingAfterRestart.Evaluation.State);
        var higherWhilePending = MailboxCapabilityReplayStateMachine.EvaluateAndReserve(
            reserved.NextSnapshot,
            Claim(10, Range(5, 32)));
        Assert.Equal(MailboxCapabilityAtomicReplayState.PendingPrior, higherWhilePending.Evaluation.State);
        Assert.Same(reserved.NextSnapshot, higherWhilePending.NextSnapshot);
        var conflict = MailboxCapabilityReplayStateMachine.EvaluateAndReserve(
            reserved.NextSnapshot,
            Claim(9, Range(2, 32)));
        Assert.Equal(MailboxCapabilityAtomicReplayState.Conflict, conflict.Evaluation.State);
        var stale = MailboxCapabilityReplayStateMachine.EvaluateAndReserve(
            reserved.NextSnapshot,
            Claim(8, Range(3, 32)));
        Assert.Equal(MailboxCapabilityAtomicReplayState.StaleReplay, stale.Evaluation.State);
        var complete = MailboxCapabilityReplayStateMachine.Complete(
            reserved.NextSnapshot!,
            claim,
            Range(4, 32));
        var retry = MailboxCapabilityReplayStateMachine.EvaluateAndReserve(complete, claim);
        Assert.Equal(MailboxCapabilityAtomicReplayState.CompletedSame, retry.Evaluation.State);
        Assert.Equal(Range(4, 32), retry.Evaluation.CachedOutcome.ToArray());
        var next = MailboxCapabilityReplayStateMachine.EvaluateAndReserve(
            complete,
            Claim(10, Range(5, 32)));
        Assert.Equal(MailboxCapabilityAtomicReplayState.NewReserved, next.Evaluation.State);
        Assert.Equal(10UL, next.NextSnapshot?.HighestCounter);

        var journal = new AtomicReferenceReplayJournal();
        var decisions = new MailboxCapabilityAtomicReplayState[32];
        Parallel.For(0, decisions.Length, index =>
            decisions[index] = journal.EvaluateAndReserve(claim).State);
        Assert.Single(decisions, value => value == MailboxCapabilityAtomicReplayState.NewReserved);
        Assert.Equal(31, decisions.Count(value => value == MailboxCapabilityAtomicReplayState.PendingSame));
    }

    private static MailboxAuthenticatedGrant Grant(
        byte[] issuer,
        byte[] holder,
        MailboxCapabilityDomain domain) =>
        new()
        {
            Domain = domain,
            Lifecycle = MailboxCapabilityLifecycle.Active,
            Generation = 7,
            NetworkId = Range(0x70, 16),
            Epoch = 11,
            Serial = Range(0x80, 16),
            NotBeforeUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1100,
            OverlapUntilUnixSeconds = 0,
            PlacementCommitment = MailboxPlacementCommitment.Compute(
                new BlindedPlacementId(Range(0x90, 32))),
            MembershipCommitment = Range(0xb0, 32),
            IssuerPublicKey = issuer,
            HolderPublicKey = holder,
            IssuerSignature = ReadOnlyMemory<byte>.Empty
        };

    private static MailboxAuthenticatedRequestBinding Binding(
        MailboxAuthenticatedOperation operation) =>
        operation switch
        {
            MailboxAuthenticatedOperation.Store =>
                MailboxAuthenticatedRequestTranscript.ForStore(StoreEnvelope()),
            MailboxAuthenticatedOperation.Retrieve =>
                MailboxAuthenticatedRequestTranscript.ForRetrieve(
                    11,
                    Range(0xd0, 16),
                    new BlindedMailboxId(Range(0x20, 32)),
                    new BlindedPlacementId(Range(0x90, 32)),
                    42,
                    10,
                    Range(1, 8)),
            MailboxAuthenticatedOperation.Ack =>
                MailboxAuthenticatedRequestTranscript.ForAck(
                    11,
                    Range(0xd0, 16),
                    new BlindedMailboxId(Range(0x20, 32)),
                    new BlindedPlacementId(Range(0x90, 32)),
                    true,
                    [],
                    [
                        new MailboxAcknowledgement
                        {
                            Cursor = 42,
                            EnvelopeDigest = Range(0xe0, 32)
                        }
                    ]),
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };

    private static MailboxEncryptedEnvelope StoreEnvelope() =>
        new()
        {
            Epoch = 11,
            MailboxId = new BlindedMailboxId(Range(0x20, 32)),
            PlacementId = new BlindedPlacementId(Range(0x90, 32)),
            OperationId = Range(0xd0, 16),
            DeduplicationDigest = Range(0xe0, 32),
            CreatedAtUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1060,
            Ciphertext = Range(0x01, 64)
        };

    private static MailboxAuthenticatedVerificationPolicy Policy(MailboxAuthenticatedGrant grant) =>
        new()
        {
            NetworkId = grant.NetworkId,
            Epoch = grant.Epoch,
            PlacementCommitment = grant.PlacementCommitment,
            MembershipCommitment = grant.MembershipCommitment,
            NowUnixSeconds = 1050,
            MinimumGeneration = grant.Generation,
            TrustedIssuers =
            [
                new MailboxCapabilityIssuerAuthority
                {
                    PublicKey = grant.IssuerPublicKey,
                    Domain = grant.Domain,
                    AllowedLifecycle = grant.Lifecycle,
                    MinimumGeneration = grant.Generation,
                    MaximumGeneration = grant.Generation,
                    ValidFromUnixSeconds = grant.NotBeforeUnixSeconds,
                    ValidUntilUnixSeconds = grant.ExpiresAtUnixSeconds
                }
            ]
        };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => unchecked((byte)value)).ToArray();

    private static void AssertChanged(ReadOnlyMemory<byte> actual, ReadOnlyMemory<byte> expected) =>
        Assert.NotEqual(expected.ToArray(), actual.ToArray());

    private static MailboxCapabilityAtomicReplayClaim Claim(ulong counter, byte[] digest) =>
        new()
        {
            ClaimDigest = digest,
            IssuerPublicKey = Range(0x10, 32),
            Serial = Range(0x40, 16),
            Epoch = 11,
            Generation = 7,
            Operation = MailboxAuthenticatedOperation.Store,
            OperationId = Range(0x60, 16),
            ReplayCounter = counter,
            RequestDigest = Range(0x80, 32)
        };

    private sealed class NoRevocations : IMailboxCapabilityRevocationSource
    {
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => false;
    }

    private sealed class AllRevoked : IMailboxCapabilityRevocationSource
    {
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => true;
    }

    private sealed class CountingRevocations : IMailboxCapabilityRevocationSource
    {
        public int Calls { get; private set; }

        public bool IsRevoked(MailboxCapabilityRevocationQuery query)
        {
            Calls++;
            return false;
        }
    }

    private sealed class MemoryReplayJournal : IMailboxCapabilityReplayJournal
    {
        private readonly HashSet<string> _claims = new(StringComparer.Ordinal);

        public int Calls { get; private set; }

        public MailboxCapabilityAtomicReplayEvaluation EvaluateAndReserve(
            MailboxCapabilityAtomicReplayClaim claim)
        {
            Calls++;
            var key = Convert.ToHexString(claim.ClaimDigest.Span);
            return new()
            {
                State = _claims.Add(key)
                    ? MailboxCapabilityAtomicReplayState.NewReserved
                    : MailboxCapabilityAtomicReplayState.PendingSame,
                CachedOutcome = ReadOnlyMemory<byte>.Empty
            };
        }

        public void CompleteAtomically(
            MailboxCapabilityAtomicReplayClaim claim,
            ReadOnlyMemory<byte> canonicalOutcome) =>
            throw new NotSupportedException();
    }

    private sealed class AtomicReferenceReplayJournal : IMailboxCapabilityReplayJournal
    {
        private readonly object _gate = new();
        private MailboxCapabilityReplaySnapshot? _snapshot;

        public MailboxCapabilityAtomicReplayEvaluation EvaluateAndReserve(
            MailboxCapabilityAtomicReplayClaim claim)
        {
            lock (_gate)
            {
                var transition = MailboxCapabilityReplayStateMachine.EvaluateAndReserve(
                    _snapshot,
                    claim);
                _snapshot = transition.NextSnapshot;
                return transition.Evaluation;
            }
        }

        public void CompleteAtomically(
            MailboxCapabilityAtomicReplayClaim claim,
            ReadOnlyMemory<byte> canonicalOutcome)
        {
            lock (_gate)
                _snapshot = MailboxCapabilityReplayStateMachine.Complete(
                    _snapshot!,
                    claim,
                    canonicalOutcome.Span);
        }
    }
}
