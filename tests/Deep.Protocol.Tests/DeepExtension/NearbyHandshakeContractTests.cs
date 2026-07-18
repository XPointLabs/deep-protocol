using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.NearbyHandshakes;
using Deep.Protocol.DeepExtension.OpaqueBundles;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class NearbyHandshakeContractTests
{
    private static readonly byte[] ContactSecret = Range(0x10, 32);
    private static readonly byte[] Attempt = Range(0x40, 16);
    private static readonly byte[] Token = Range(0x50, 16);
    private static readonly byte[] Alice = Encoding.ASCII.GetBytes("alice-contact");
    private static readonly byte[] Bob = Encoding.ASCII.GetBytes("bob-contact");
    private static readonly TestSecretProvider SecretProvider = new(ContactSecret);

    [Fact]
    public void AdvertisementAndInitiator_MatchGoldenVectors()
    {
        var crypto = new TestAdapter(Alice, ContactSecret);
        var advertisement = NearbyHandshakeProtocol.CreateAdvertisement(
            Secret(), 100, 1, crypto);
        var binding = Binding();
        var initiator = NearbyHandshakeProtocol.CreateInitiator(binding, PeriodPolicy(), Bob, crypto);
        var vectors = GoldenVectorLoader.Load("nearby-handshake-v1.json");

        Assert.Equal(vectors.GetRequired("deep-extension/nearby/v1/advertisement").Hex,
            Convert.ToHexString(advertisement).ToLowerInvariant());
        Assert.Equal(vectors.GetRequired("deep-extension/nearby/v1/initiator").Hex,
            Convert.ToHexString(initiator).ToLowerInvariant());
        Assert.DoesNotContain(Convert.ToHexString(Alice), Convert.ToHexString(advertisement));
        Assert.DoesNotContain(Convert.ToHexString(Bob), Convert.ToHexString(advertisement));
    }

    [Fact]
    public void ContactScopedMatch_UsesBoundedCurrentPreviousAndFutureSkew()
    {
        var crypto = new TestAdapter(Alice, ContactSecret);
        var previous = NearbyHandshakeProtocol.CreateAdvertisement(
            Secret(), 99, 1, crypto);
        var match = NearbyHandshakeProtocol.MatchAdvertisement(
            previous, Secret(), 100,
            new NearbyRendezvousPolicy { PreviousPeriods = 1, FuturePeriods = 1 }, crypto);
        Assert.Equal(99UL, match.Period);

        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeProtocol.MatchAdvertisement(
                previous, new TestSecretProvider(Range(0x80, 32)).GetContactScopedSecret(), 100,
                new NearbyRendezvousPolicy { PreviousPeriods = 1, FuturePeriods = 1 }, crypto));
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeProtocol.MatchAdvertisement(
                NearbyHandshakeProtocol.CreateAdvertisement(Secret(), 98, 1, crypto),
                Secret(), 100,
                new NearbyRendezvousPolicy { PreviousPeriods = 1, FuturePeriods = 1 }, crypto));
    }

    [Fact]
    public void TranscriptWrongContactTamperAndReplay_FailClosed()
    {
        var alice = new TestAdapter(Alice, ContactSecret);
        var bob = new TestAdapter(Bob, ContactSecret);
        var responderReplay = new AcceptOnceReplayGuard();
        var initiatorReplay = new AcceptOnceReplayGuard();
        var initiator = NearbyHandshakeProtocol.CreateInitiator(Binding(), PeriodPolicy(), Bob, alice);
        var response = NearbyHandshakeProtocol.Respond(
            initiator, PeriodPolicy(), Alice, bob, responderReplay);
        var established = NearbyHandshakeProtocol.CompleteInitiator(
            initiator, response.Frame, PeriodPolicy(), Bob, alice, initiatorReplay);

        Assert.Equal(Bob, established.PeerIdentity.ToArray());
        Assert.Equal(32, established.SessionKey.Length);

        var tampered = response.Frame.ToArray();
        tampered[^1] ^= 1;
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeProtocol.CompleteInitiator(
                initiator, tampered, PeriodPolicy(), Bob, alice, new AcceptOnceReplayGuard()));
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeProtocol.CompleteInitiator(
                initiator, response.Frame, PeriodPolicy(), Alice, alice, new AcceptOnceReplayGuard()));
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeProtocol.CompleteInitiator(
                initiator, response.Frame, PeriodPolicy(), Bob, alice, initiatorReplay));
        Assert.Contains(responderReplay.Scopes, scope =>
            scope.CanonicalTranscript.Length == initiator.Length + response.Frame.Length);
        Assert.Contains(initiatorReplay.Scopes, scope =>
            scope.CanonicalTranscript.Length == initiator.Length + response.Frame.Length);
    }

    [Fact]
    public void StalePeriodAndNonAdvancingResumption_FailBeforeAdapter()
    {
        var alice = new TestAdapter(Alice, ContactSecret);
        var staleBinding = Binding() with { Period = 97 };
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeProtocol.CreateInitiator(
                staleBinding, PeriodPolicy(), Bob, alice));
        Assert.Equal(0, alice.InitiatorCalls);

        var binding = Binding() with
        {
            Mode = NearbyHandshakeMode.Resumption,
            ResumeCounter = 5
        };
        var initiator = NearbyHandshakeProtocol.CreateInitiator(
            binding, PeriodPolicy(), Bob, alice);
        var bob = new TestAdapter(Bob, ContactSecret);
        var guard = new MonotonicResumptionGuard();
        _ = NearbyHandshakeProtocol.Respond(
            initiator, PeriodPolicy(), Alice, bob, guard);
        var advanced = binding with { ResumeCounter = 6 };
        var advancedFrame = NearbyHandshakeProtocol.CreateInitiator(
            advanced, PeriodPolicy(), Bob, alice);
        _ = NearbyHandshakeProtocol.Respond(
            advancedFrame, PeriodPolicy(), Alice, bob, guard);
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeProtocol.Respond(
                initiator, PeriodPolicy(), Alice, bob, guard));
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeProtocol.Respond(
                advancedFrame, PeriodPolicy(), Alice, bob, guard));
    }

    [Fact]
    public void SimultaneousOpenAndLifecycle_AreDeterministicAndFailClosed()
    {
        Assert.Equal(NearbySimultaneousOpenRole.Initiator,
            NearbyHandshakeLifecycle.ResolveSimultaneousOpen(Range(0x10, 16), Range(0x20, 16)));
        Assert.Equal(NearbySimultaneousOpenRole.Responder,
            NearbyHandshakeLifecycle.ResolveSimultaneousOpen(Range(0x20, 16), Range(0x10, 16)));
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeLifecycle.ResolveSimultaneousOpen(Token, Token));

        Assert.Equal(NearbyHandshakeState.HintMatched,
            NearbyHandshakeLifecycle.Transition(NearbyHandshakeState.Idle, NearbyHandshakeEvent.HintMatched));
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeLifecycle.Transition(NearbyHandshakeState.Idle, NearbyHandshakeEvent.Established));
    }

    [Fact]
    public void NoProductionAdapterOrOpenDiscoveryDefault_IsRegistered()
    {
        var productionTypes = typeof(NearbyHandshakeProtocol).Assembly.GetTypes();
        Assert.DoesNotContain(productionTypes, type =>
            typeof(INearbyAuthenticatedKeyExchange).IsAssignableFrom(type) &&
            type is { IsInterface: false, IsAbstract: false });
        Assert.DoesNotContain(productionTypes, type =>
            type.Name.Contains("OpenDiscovery", StringComparison.OrdinalIgnoreCase));
    }

    private static NearbyHandshakeBinding Binding() =>
        new()
        {
            BundleVersion = 1,
            Period = 100,
            TransportAttemptId = new TransportAttemptId(Attempt),
            SimultaneousOpenToken = Token,
            Mode = NearbyHandshakeMode.Fresh,
            ResumeCounter = 0
        };

    private static ContactDiscoverySecret Secret() =>
        SecretProvider.GetContactScopedSecret();

    private static NearbyHandshakePeriodPolicy PeriodPolicy() =>
        new() { CurrentPeriod = 100, PreviousPeriods = 1, FuturePeriods = 1 };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();

    private sealed class AcceptOnceReplayGuard : INearbyHandshakeReplayGuard
    {
        private readonly HashSet<string> _seen = [];
        public List<NearbyHandshakeReplayScope> Scopes { get; } = [];

        public NearbyHandshakeReplayDecision Evaluate(NearbyHandshakeReplayScope scope)
        {
            Scopes.Add(scope);
            return _seen.Add(Convert.ToHexString(SHA256.HashData(scope.CanonicalTranscript.Span)))
                ? scope.Mode == NearbyHandshakeMode.Fresh
                    ? NearbyHandshakeReplayDecision.AcceptedFresh
                    : NearbyHandshakeReplayDecision.AcceptedResumption
                : NearbyHandshakeReplayDecision.Rejected;
        }
    }

    private sealed class MonotonicResumptionGuard : INearbyHandshakeReplayGuard
    {
        private ulong _last;
        public NearbyHandshakeReplayDecision Evaluate(NearbyHandshakeReplayScope scope)
        {
            if (scope.Mode != NearbyHandshakeMode.Resumption ||
                scope.ResumeCounter <= _last)
                return NearbyHandshakeReplayDecision.Rejected;
            _last = scope.ResumeCounter;
            return NearbyHandshakeReplayDecision.AcceptedResumption;
        }
    }

    private sealed class TestAdapter(byte[] localIdentity, byte[] sharedSecret)
        : INearbyAuthenticatedKeyExchange
    {
        public byte[] DeriveRendezvousHint(
            ReadOnlySpan<byte> domain,
            ContactDiscoverySecret contactSecret,
            ulong period,
            byte bundleVersion)
        {
            Assert.Equal(NearbyHandshakeDomains.RendezvousHint.ToArray(), domain.ToArray());
            var material = domain.ToArray().Concat(SecretProvider.Resolve(contactSecret))
                .Concat(BitConverter.GetBytes(period).Reverse())
                .Append(bundleVersion)
                .ToArray();
            return HMACSHA256.HashData(sharedSecret, material)[..16];
        }

        public byte[] CreateInitiatorPayload(
            ReadOnlySpan<byte> domain,
            NearbyHandshakeBinding binding,
            ReadOnlySpan<byte> expectedPeerIdentity) =>
            CreateInitiator(domain, binding, expectedPeerIdentity);

        public int InitiatorCalls { get; private set; }

        private byte[] CreateInitiator(
            ReadOnlySpan<byte> domain,
            NearbyHandshakeBinding binding,
            ReadOnlySpan<byte> expectedPeerIdentity)
        {
            Assert.Equal(NearbyHandshakeDomains.AuthenticatedKeyExchange.ToArray(), domain.ToArray());
            InitiatorCalls++;
            return Mac("I", domain.ToArray(), NearbyHandshakeCodec.GetBindingBytes(binding),
                localIdentity, expectedPeerIdentity.ToArray());
        }

        public byte[] CreateResponderPayload(
            ReadOnlySpan<byte> domain,
            NearbyHandshakeBinding binding,
            ReadOnlySpan<byte> canonicalInitiatorFrame,
            ReadOnlySpan<byte> expectedPeerIdentity)
        {
            var expected = Mac("I", domain.ToArray(), NearbyHandshakeCodec.GetBindingBytes(binding),
                expectedPeerIdentity.ToArray(), localIdentity);
            var decoded = NearbyHandshakeCodec.DecodeFrame(canonicalInitiatorFrame);
            if (!CryptographicOperations.FixedTimeEquals(expected, decoded.AdapterPayload.Span))
                throw new NearbyHandshakeException(NearbyHandshakeError.AuthenticationFailed, "wrong contact");
            return Mac("R", domain.ToArray(), canonicalInitiatorFrame.ToArray(), localIdentity,
                expectedPeerIdentity.ToArray());
        }

        public NearbyEstablishedSession CompleteResponder(
            ReadOnlySpan<byte> domain,
            NearbyHandshakeBinding binding,
            ReadOnlySpan<byte> canonicalInitiatorFrame,
            ReadOnlySpan<byte> canonicalResponderFrame,
            ReadOnlySpan<byte> expectedPeerIdentity)
        {
            var response = NearbyHandshakeCodec.DecodeFrame(canonicalResponderFrame);
            var expected = Mac("R", domain.ToArray(), canonicalInitiatorFrame.ToArray(), localIdentity,
                expectedPeerIdentity.ToArray());
            if (!CryptographicOperations.FixedTimeEquals(expected, response.AdapterPayload.Span))
                throw new NearbyHandshakeException(NearbyHandshakeError.AuthenticationFailed, "tamper");
            return new NearbyEstablishedSession(expectedPeerIdentity.ToArray(),
                SHA256.HashData(canonicalInitiatorFrame.ToArray()
                    .Concat(response.AdapterPayload.ToArray()).ToArray()));
        }

        public NearbyEstablishedSession CompleteInitiator(
            ReadOnlySpan<byte> domain,
            NearbyHandshakeBinding binding,
            ReadOnlySpan<byte> canonicalInitiatorFrame,
            ReadOnlySpan<byte> canonicalResponderFrame,
            ReadOnlySpan<byte> expectedPeerIdentity)
        {
            var response = NearbyHandshakeCodec.DecodeFrame(canonicalResponderFrame);
            var expected = Mac("R", domain.ToArray(), canonicalInitiatorFrame.ToArray(),
                expectedPeerIdentity.ToArray(), localIdentity);
            if (!CryptographicOperations.FixedTimeEquals(expected, response.AdapterPayload.Span))
                throw new NearbyHandshakeException(NearbyHandshakeError.AuthenticationFailed, "tamper");
            return new NearbyEstablishedSession(expectedPeerIdentity.ToArray(),
                SHA256.HashData(canonicalInitiatorFrame.ToArray()
                    .Concat(response.AdapterPayload.ToArray()).ToArray()));
        }

        private byte[] Mac(string label, params byte[][] values)
        {
            var bytes = Encoding.ASCII.GetBytes(label)
                .Concat(values.SelectMany(static value => value.ToArray()))
                .ToArray();
            return HMACSHA256.HashData(sharedSecret, bytes);
        }
    }

    private sealed class TestSecretProvider(byte[] secret) : ContactDiscoverySecretProviderBase
    {
        private readonly Dictionary<ContactDiscoverySecret, byte[]> _secrets = [];

        public override ContactDiscoverySecret GetContactScopedSecret()
        {
            var handle = CreateOpaqueSecretHandle();
            _secrets[handle] = secret.ToArray();
            return handle;
        }

        public byte[] Resolve(ContactDiscoverySecret handle) =>
            _secrets.TryGetValue(handle, out var bytes)
                ? bytes
                : throw new NearbyHandshakeException(
                    NearbyHandshakeError.InvalidIdentifier,
                    "Unknown test secret handle.");
    }
}
