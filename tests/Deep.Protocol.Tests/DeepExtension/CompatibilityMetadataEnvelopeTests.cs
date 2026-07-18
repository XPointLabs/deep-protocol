using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.CompatibilityEnvelopes;
using Deep.Protocol.DeepExtension.OpaqueBundles;
using Deep.Protocol.GoldenVectors;
using Deep.Protocol.Tests.Fakes;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class CompatibilityMetadataEnvelopeTests
{
    private static readonly byte[] Capability = Range(0x40, 32);
    private static readonly byte[] AttemptId = Range(0x10, 16);
    private static readonly byte[] DedupId = Range(0x20, 16);
    private static readonly byte[] ReplayMaterial = Range(0x30, 16);
    private static readonly byte[] HeaderNonce = Range(0x60, 32);
    private static readonly byte[] PayloadNonce = Range(0x80, 32);
    private static readonly byte[] RecipientMaterial = Range(0xa0, 32);
    private static readonly byte[] SenderAuthentication = Range(0xc0, 32);
    private static readonly byte[] LegacyDpe1 = Encoding.ASCII.GetBytes("DPE1\0\0exact-legacy-payload");

    [Fact]
    public void CanonicalTestAdapterVector_HidesManagedMetadata_AndRecoversExactDpe1()
    {
        var crypto = new DeterministicTestCompatibilityEnvelopeCrypto();
        var encoded = CompatibilityMetadataEnvelopeCodec.Encode(
            CreateRequest(),
            StrictProfile(),
            crypto);
        var vector = GoldenVectorLoader.Load("compatibility-envelope-v1.json")
            .GetRequired("deep-extension/compatibility-envelope/v1/deposit-512");

        Assert.Equal(512, encoded.Length);
        Assert.Equal(vector.Hex, Convert.ToHexString(encoded).ToLowerInvariant());
        Assert.DoesNotContain(Convert.ToHexString(LegacyDpe1), Convert.ToHexString(encoded));
        Assert.DoesNotContain(Convert.ToHexString(SenderAuthentication), Convert.ToHexString(encoded));

        var replay = new RecordingReplayGuard();
        var opened = CompatibilityMetadataEnvelopeCodec.Decode(
            encoded,
            RecipientMaterial,
            StrictPolicy(),
            crypto,
            replay);

        Assert.Equal(LegacyDpe1, opened.LegacyDpe1.ToArray());
        Assert.Equal(SenderAuthentication, opened.SenderAuthenticationData.ToArray());
        Assert.Equal(ReplayMaterial, replay.Accepted.Single().ReplayMaterial.ToArray());
        Assert.Equal(
            [CompatibilityEnvelopeDomains.HeaderV1, CompatibilityEnvelopeDomains.PayloadV1],
            crypto.SealDomains);
        Assert.Equal(
            [CompatibilityEnvelopeDomains.HeaderV1, CompatibilityEnvelopeDomains.PayloadV1],
            crypto.OpenDomains);
    }

    [Fact]
    public void TamperAndWrongRecipient_FailWithoutReturningSenderOrDpe1()
    {
        var encoded = CompatibilityMetadataEnvelopeCodec.Encode(
            CreateRequest(),
            StrictProfile(),
            new DeterministicTestCompatibilityEnvelopeCrypto());
        encoded[OpaqueBundleLimits.FixedHeaderLength + Capability.Length + HeaderNonce.Length + 5] ^= 0x80;

        var tamper = Assert.Throws<CompatibilityEnvelopeException>(() =>
            CompatibilityMetadataEnvelopeCodec.Decode(
                encoded,
                RecipientMaterial,
                StrictPolicy(),
                new DeterministicTestCompatibilityEnvelopeCrypto(),
                new RecordingReplayGuard()));
        Assert.Equal(CompatibilityEnvelopeError.AuthenticationFailed, tamper.Error);

        encoded = CompatibilityMetadataEnvelopeCodec.Encode(
            CreateRequest(),
            StrictProfile(),
            new DeterministicTestCompatibilityEnvelopeCrypto());
        var wrongRecipient = Assert.Throws<CompatibilityEnvelopeException>(() =>
            CompatibilityMetadataEnvelopeCodec.Decode(
                encoded,
                Range(0xe0, 32),
                StrictPolicy(),
                new DeterministicTestCompatibilityEnvelopeCrypto(),
                new RecordingReplayGuard()));
        Assert.Equal(CompatibilityEnvelopeError.AuthenticationFailed, wrongRecipient.Error);
    }

    [Fact]
    public void Replay_IsRejectedAfterAuthenticatedDecrypt()
    {
        var crypto = new DeterministicTestCompatibilityEnvelopeCrypto();
        var encoded = CompatibilityMetadataEnvelopeCodec.Encode(CreateRequest(), StrictProfile(), crypto);
        var replay = new RecordingReplayGuard();

        _ = CompatibilityMetadataEnvelopeCodec.Decode(
            encoded,
            RecipientMaterial,
            StrictPolicy(),
            crypto,
            replay);
        var exception = Assert.Throws<CompatibilityEnvelopeException>(() =>
            CompatibilityMetadataEnvelopeCodec.Decode(
                encoded,
                RecipientMaterial,
                StrictPolicy(),
                crypto,
                replay));

        Assert.Equal(CompatibilityEnvelopeError.ReplayRejected, exception.Error);
        Assert.Equal(2, crypto.OpenDomains.Count(domain => domain == CompatibilityEnvelopeDomains.PayloadV1));
    }

    [Fact]
    public void DowngradeAndMissingAuthenticatedFeature_FailClosed()
    {
        var request = CreateRequest();
        var missingFeatureProfile = StrictProfile() with
        {
            SupportedCriticalFeatures =
                OpaqueBundleFeatures.V1Required |
                OpaqueBundleFeatures.LegacyDpe1Compatibility
        };

        var encode = Assert.Throws<CompatibilityEnvelopeException>(() =>
            CompatibilityMetadataEnvelopeCodec.Encode(
                request,
                missingFeatureProfile,
                new DeterministicTestCompatibilityEnvelopeCrypto()));
        Assert.Equal(CompatibilityEnvelopeError.FeatureNotNegotiated, encode.Error);

        var encoded = CompatibilityMetadataEnvelopeCodec.Encode(
            request,
            StrictProfile(),
            new DeterministicTestCompatibilityEnvelopeCrypto());
        var strictNativePolicy = StrictPolicy() with
        {
            SupportedCriticalFeatures =
                OpaqueBundleFeatures.V1Required |
                OpaqueBundleFeatures.LegacyDpe1Compatibility
        };
        Assert.Throws<OpaqueBundlePolicyException>(() =>
            CompatibilityMetadataEnvelopeCodec.Decode(
                encoded,
                RecipientMaterial,
                strictNativePolicy,
                new DeterministicTestCompatibilityEnvelopeCrypto(),
                new RecordingReplayGuard()));
    }

    [Fact]
    public void NonceContexts_MustDiffer_AndDomainsAreCodecOwned()
    {
        var request = CreateRequest() with { PayloadNonceContext = HeaderNonce };

        var exception = Assert.Throws<CompatibilityEnvelopeException>(() =>
            CompatibilityMetadataEnvelopeCodec.Encode(
                request,
                StrictProfile(),
                new DeterministicTestCompatibilityEnvelopeCrypto()));

        Assert.Equal(CompatibilityEnvelopeError.InvalidNonceContext, exception.Error);
        Assert.NotEqual(CompatibilityEnvelopeDomains.HeaderV1, CompatibilityEnvelopeDomains.PayloadV1);
    }

    [Fact]
    public void HopLocalAttemptAndNonceChanges_RemoveStableAttemptBytes()
    {
        var first = CompatibilityMetadataEnvelopeCodec.Encode(
            CreateRequest(),
            StrictProfile(),
            new DeterministicTestCompatibilityEnvelopeCrypto());
        var second = CompatibilityMetadataEnvelopeCodec.Encode(
            CreateRequest() with
            {
                TransportAttemptId = new TransportAttemptId(Range(0xd0, 16)),
                HeaderNonceContext = Range(0x01, 32),
                PayloadNonceContext = Range(0x21, 32)
            },
            StrictProfile(),
            new DeterministicTestCompatibilityEnvelopeCrypto());

        Assert.NotEqual(first, second);
        Assert.DoesNotContain(Convert.ToHexString(DedupId), Convert.ToHexString(first));
        Assert.DoesNotContain(Convert.ToHexString(DedupId), Convert.ToHexString(second));
    }

    [Fact]
    public void ProductionAssembly_ContainsNoCompatibilityCryptoImplementation()
    {
        var implementations = typeof(CompatibilityMetadataEnvelopeCodec).Assembly
            .GetTypes()
            .Where(type =>
                !type.IsAbstract &&
                !type.IsInterface &&
                typeof(ICompatibilityEnvelopeCrypto).IsAssignableFrom(type))
            .ToArray();

        Assert.Empty(implementations);
        Assert.False(typeof(ICompatibilityEnvelopeCrypto).IsAssignableFrom(typeof(SodiumSessionProtocolCrypto)));
        Assert.False(typeof(ICompatibilityEnvelopeCrypto).IsAssignableFrom(typeof(SodiumOnionRequestCrypto)));
    }

    private static CompatibilityEnvelopeWriteRequest CreateRequest() =>
        new()
        {
            Capability = new OpaqueDepositCapability(Capability),
            TransportAttemptId = new TransportAttemptId(AttemptId),
            EndToEndDedupId = new EndToEndDedupId(DedupId),
            ExpiryBucket = 123456,
            PaddingClass = OpaqueBundlePaddingClass.Bytes256,
            ReplayMaterial = ReplayMaterial,
            HeaderNonceContext = HeaderNonce,
            PayloadNonceContext = PayloadNonce,
            RecipientKeyMaterial = RecipientMaterial,
            SenderAuthenticationSecret = SenderAuthentication,
            LegacyDpe1 = LegacyDpe1
        };

    private static OpaqueBundleNegotiatedProfile StrictProfile() =>
        new(
            OpaqueBundleWireVersion.V1,
            OpaqueBundleFeatures.V1Required |
            OpaqueBundleFeatures.LegacyDpe1Compatibility |
            OpaqueBundleFeatures.AuthenticatedCompatibilityEnvelope,
            AllowLegacyDpe1: true);

    private static OpaqueBundleDecodePolicy StrictPolicy() =>
        new()
        {
            MinimumVersion = OpaqueBundleWireVersion.V1,
            MaximumVersion = OpaqueBundleWireVersion.V1,
            SupportedCriticalFeatures =
                OpaqueBundleFeatures.V1Required |
                OpaqueBundleFeatures.LegacyDpe1Compatibility |
                OpaqueBundleFeatures.AuthenticatedCompatibilityEnvelope,
            MinimumExpiryBucket = 123456,
            MaximumExpiryBucket = 123460,
            AllowLegacyDpe1 = true
        };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();

    private sealed class RecordingReplayGuard : ICompatibilityEnvelopeReplayGuard
    {
        private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

        public List<CompatibilityEnvelopeReplayScope> Accepted { get; } = [];

        public bool TryAccept(CompatibilityEnvelopeReplayScope scope)
        {
            Accepted.Add(scope);
            return _seen.Add(
                $"{Convert.ToHexString(scope.Capability.Span)}:" +
                $"{scope.ExpiryBucket}:" +
                $"{Convert.ToHexString(scope.ReplayMaterial.Span)}");
        }
    }
}
