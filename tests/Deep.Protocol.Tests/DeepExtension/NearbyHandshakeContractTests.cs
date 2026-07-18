using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.NearbyHandshakes;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class NearbyHandshakeContractTests
{
    private static readonly byte[] ContactSecret = Range(0x10, 32);
    private static readonly byte[] Attempt = Range(0x40, 16);
    private static readonly byte[] Token = Range(0x50, 16);
    private static readonly byte[] Alice = Encoding.ASCII.GetBytes("alice-contact");
    private static readonly byte[] Bob = Encoding.ASCII.GetBytes("bob-contact");

    [Fact]
    public void AdvertisementAndInitiator_MatchGoldenVectors()
    {
        var crypto = new TestAdapter(Alice, ContactSecret);
        var advertisement = NearbyHandshakeProtocol.CreateAdvertisement(
            ContactSecret, 100, 1, crypto);
        var binding = Binding();
        var initiator = NearbyHandshakeProtocol.CreateInitiator(binding, Bob, crypto);
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
            ContactSecret, 99, 1, crypto);
        var match = NearbyHandshakeProtocol.MatchAdvertisement(
            previous, ContactSecret, 100,
            new NearbyRendezvousPolicy { PreviousPeriods = 1, FuturePeriods = 1 }, crypto);
        Assert.Equal(99UL, match.Period);

        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeProtocol.MatchAdvertisement(
                previous, Range(0x80, 32), 100,
                new NearbyRendezvousPolicy { PreviousPeriods = 1, FuturePeriods = 1 }, crypto));
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeProtocol.MatchAdvertisement(
                NearbyHandshakeProtocol.CreateAdvertisement(ContactSecret, 98, 1, crypto),
                ContactSecret, 100,
                new NearbyRendezvousPolicy { PreviousPeriods = 1, FuturePeriods = 1 }, crypto));
    }

    [Fact]
    public void TranscriptWrongContactTamperAndReplay_FailClosed()
    {
        var alice = new TestAdapter(Alice, ContactSecret);
        var bob = new TestAdapter(Bob, ContactSecret);
        var replay = new AcceptOnceReplayGuard();
        var initiator = NearbyHandshakeProtocol.CreateInitiator(Binding(), Bob, alice);
        var response = NearbyHandshakeProtocol.Respond(initiator, Alice, bob, replay);
        var established = NearbyHandshakeProtocol.CompleteInitiator(
            initiator, response.Frame, Bob, alice, replay);

        Assert.Equal(Bob, established.PeerIdentity.ToArray());
        Assert.Equal(32, established.SessionKey.Length);

        var tampered = response.Frame.ToArray();
        tampered[^1] ^= 1;
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeProtocol.CompleteInitiator(
                initiator, tampered, Bob, alice, new AcceptOnceReplayGuard()));
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeProtocol.CompleteInitiator(
                initiator, response.Frame, Alice, alice, new AcceptOnceReplayGuard()));
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeProtocol.CompleteInitiator(
                initiator, response.Frame, Bob, alice, replay));
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
            TransportAttemptId = Attempt,
            SimultaneousOpenToken = Token,
            Mode = NearbyHandshakeMode.Fresh,
            ResumeCounter = 0
        };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();

    private sealed class AcceptOnceReplayGuard : INearbyHandshakeReplayGuard
    {
        private readonly HashSet<string> _seen = [];

        public bool TryAccept(NearbyHandshakeReplayScope scope) =>
            _seen.Add(Convert.ToHexString(SHA256.HashData(scope.CanonicalTranscript.Span)));
    }

    private sealed class TestAdapter(byte[] localIdentity, byte[] sharedSecret)
        : INearbyAuthenticatedKeyExchange
    {
        public byte[] DeriveRendezvousHint(
            ReadOnlySpan<byte> contactSecret,
            ulong period,
            byte bundleVersion)
        {
            var material = contactSecret.ToArray()
                .Concat(BitConverter.GetBytes(period).Reverse())
                .Append(bundleVersion)
                .ToArray();
            return HMACSHA256.HashData(sharedSecret, material)[..16];
        }

        public byte[] CreateInitiatorPayload(
            NearbyHandshakeBinding binding,
            ReadOnlySpan<byte> expectedPeerIdentity) =>
            Mac("I", NearbyHandshakeCodec.GetBindingBytes(binding), localIdentity,
                expectedPeerIdentity.ToArray());

        public NearbyResponderResult RespondAuthenticated(
            NearbyHandshakeBinding binding,
            ReadOnlySpan<byte> canonicalInitiatorFrame,
            ReadOnlySpan<byte> expectedPeerIdentity)
        {
            var expected = Mac("I", NearbyHandshakeCodec.GetBindingBytes(binding),
                expectedPeerIdentity.ToArray(), localIdentity);
            var decoded = NearbyHandshakeCodec.DecodeFrame(canonicalInitiatorFrame);
            if (!CryptographicOperations.FixedTimeEquals(expected, decoded.AdapterPayload.Span))
                throw new NearbyHandshakeException(NearbyHandshakeError.AuthenticationFailed, "wrong contact");
            var payload = Mac("R", canonicalInitiatorFrame.ToArray(), localIdentity,
                expectedPeerIdentity.ToArray());
            return new NearbyResponderResult(payload,
                new NearbyEstablishedSession(expectedPeerIdentity.ToArray(),
                    SHA256.HashData(canonicalInitiatorFrame.ToArray().Concat(payload).ToArray())));
        }

        public NearbyEstablishedSession CompleteInitiator(
            NearbyHandshakeBinding binding,
            ReadOnlySpan<byte> canonicalInitiatorFrame,
            ReadOnlySpan<byte> canonicalResponderFrame,
            ReadOnlySpan<byte> expectedPeerIdentity)
        {
            var response = NearbyHandshakeCodec.DecodeFrame(canonicalResponderFrame);
            var expected = Mac("R", canonicalInitiatorFrame.ToArray(),
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
}
