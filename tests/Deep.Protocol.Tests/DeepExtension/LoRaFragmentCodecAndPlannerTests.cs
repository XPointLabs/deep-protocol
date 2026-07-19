using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.LoRaFragments;
using Deep.Protocol.DeepExtension.OpaqueBundles;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class LoRaFragmentCodecAndPlannerTests
{
    private static readonly byte[] MessageId = [1, 2, 3, 4, 5, 6, 7, 8];

    [Theory]
    [InlineData(LoRaFragmentFecMode.None, 0)]
    [InlineData(LoRaFragmentFecMode.Xor1, 1)]
    public void PlannerProducesCanonicalAuthenticatedFrames(
        LoRaFragmentFecMode fecMode,
        byte expectedParity)
    {
        var provider = new TestAuthenticationProvider();
        var handle = provider.Create(Range(0x90, 32));
        var authenticator = new TestAuthenticator(provider);
        var bundle = ValidOpaqueBundle();

        var plan = LoRaFragmentPlanner.Plan(
            new LoRaFragmentPlanRequest(
                bundle,
                MessageId,
                currentHop: 0,
                hopLimit: 3,
                shardSize: 64,
                fecMode,
                LoRaFragmentDirection.Forward,
                handle),
            Policy(),
            authenticator);

        Assert.Equal(5, plan.DataShardCount);
        Assert.Equal(expectedParity, plan.ParityShardCount);
        Assert.Equal(5 + expectedParity, plan.Frames.Count);
        Assert.Equal((ushort)bundle.Length, plan.Descriptor.BundleLength);
        Assert.Equal(100u, plan.Descriptor.ExpiryBucket);
        Assert.All(plan.Frames, encoded =>
        {
            Assert.Equal(96, encoded.Length);
            Assert.Equal((byte)'L', encoded.Span[0]);
            Assert.Equal((byte)'F', encoded.Span[1]);
            Assert.Equal(LoRaFragmentLimits.WireVersion, encoded.Span[2]);
            var decoded = LoRaFragmentCodec.Decode(
                encoded.Span,
                Policy(),
                handle,
                LoRaFragmentDirection.Forward,
                authenticator);
            Assert.Equal(64, decoded.Shard.Length);
            Assert.Equal(16, decoded.AuthenticationTag.Length);
        });
    }

    [Theory]
    [InlineData("deep-extension/lora-fragment/v1/none", LoRaFragmentFecMode.None)]
    [InlineData("deep-extension/lora-fragment/v1/xor1", LoRaFragmentFecMode.Xor1)]
    public void PlannerMatchesEveryFrameInGoldenVector(
        string vectorId,
        LoRaFragmentFecMode fecMode)
    {
        var provider = new TestAuthenticationProvider();
        var handle = provider.Create(Range(0x90, 32));
        var authenticator = new TestAuthenticator(provider);
        var bundle = ValidOpaqueBundle();
        var plan = LoRaFragmentPlanner.Plan(
            new LoRaFragmentPlanRequest(
                bundle,
                MessageId,
                0,
                3,
                64,
                fecMode,
                LoRaFragmentDirection.Forward,
                handle),
            Policy(),
            authenticator);
        var vector = GoldenVectorLoader.Load("lora-fragment-v1.json")
            .GetRequired(vectorId);

        Assert.NotNull(vector.FramesHex);
        Assert.Equal(
            vector.FramesHex,
            plan.Frames.Select(frame =>
                Convert.ToHexString(frame.Span).ToLowerInvariant()));
        Assert.Equal(
            vector.ReassembledBundleHex,
            Convert.ToHexString(bundle).ToLowerInvariant());
        Assert.Equal(vector.DataShardCount, plan.DataShardCount);
        Assert.Equal(vector.ParityShardCount, plan.ParityShardCount);
        Assert.Equal(vector.ShardSize, plan.Frames[0].Length - 32);
    }

    [Fact]
    public void CanonicalTranscriptIsDomainDirectionHeaderAndShard()
    {
        var header = new LoRaFragmentHeader(
            MessageId,
            ordinal: 0,
            dataShardCount: 3,
            parityShardCount: 0,
            shardSize: 32,
            LoRaFragmentFecMode.None);
        var shard = Range(0x20, 32);

        var transcript = LoRaFragmentCodec.BuildAuthenticatedTranscript(
            header,
            shard,
            LoRaFragmentDirection.Reverse);

        var domain = LoRaFragmentDomains.Authentication.ToArray();
        Assert.Equal(domain, transcript[..domain.Length]);
        Assert.Equal((byte)LoRaFragmentDirection.Reverse, transcript[domain.Length]);
        var headerOffset = domain.Length + 1;
        Assert.Equal((byte)'L', transcript[headerOffset]);
        Assert.Equal((byte)'F', transcript[headerOffset + 1]);
        Assert.Equal(MessageId, transcript[(headerOffset + 4)..(headerOffset + 12)]);
        Assert.Equal(shard, transcript[^shard.Length..]);
        Assert.Equal(
            domain.Length + 1 + LoRaFragmentLimits.HeaderLength + shard.Length,
            transcript.Length);
    }

    [Fact]
    public void WrongDirectionAndAuthenticationScopeFailClosed()
    {
        var provider = new TestAuthenticationProvider();
        var sender = provider.Create(Range(0x40, 32));
        var wrongScope = provider.Create(Range(0x60, 32));
        var authenticator = new TestAuthenticator(provider);
        var frame = new LoRaFragmentUnsignedFrame(
            new LoRaFragmentHeader(
                MessageId, 0, 2, 0, 64, LoRaFragmentFecMode.None),
            new byte[64]);
        var encoded = LoRaFragmentCodec.Encode(
            frame,
            sender,
            LoRaFragmentDirection.Forward,
            authenticator);

        Assert.Equal(
            LoRaFragmentError.AuthenticationFailed,
            Assert.Throws<LoRaFragmentException>(() =>
                LoRaFragmentCodec.Decode(
                    encoded,
                    Policy(),
                    sender,
                    LoRaFragmentDirection.Reverse,
                    authenticator)).Error);
        Assert.Equal(
            LoRaFragmentError.AuthenticationFailed,
            Assert.Throws<LoRaFragmentException>(() =>
                LoRaFragmentCodec.Decode(
                    encoded,
                    Policy(),
                    wrongScope,
                    LoRaFragmentDirection.Forward,
                    authenticator)).Error);
    }

    [Fact]
    public void EverySingleByteMutationFailsAuthenticationOrCanonicalParsing()
    {
        var provider = new TestAuthenticationProvider();
        var handle = provider.Create(Range(0x40, 32));
        var authenticator = new TestAuthenticator(provider);
        var frame = new LoRaFragmentUnsignedFrame(
            new LoRaFragmentHeader(
                MessageId, 0, 2, 0, 64, LoRaFragmentFecMode.None),
            Range(0x10, 64));
        var encoded = LoRaFragmentCodec.Encode(
            frame,
            handle,
            LoRaFragmentDirection.Forward,
            authenticator);

        for (var offset = 0; offset < encoded.Length; offset++)
        {
            var mutated = encoded.ToArray();
            mutated[offset] ^= 0x01;
            Assert.Throws<LoRaFragmentException>(() =>
                LoRaFragmentCodec.Decode(
                    mutated,
                    Policy(),
                    handle,
                    LoRaFragmentDirection.Forward,
                    authenticator));
        }
    }

    [Fact]
    public void ShardMutationAfterFirstVerificationCannotChangeRetainedBytes()
    {
        var provider = new TestAuthenticationProvider();
        var handle = provider.Create(Range(0x40, 32));
        var stable = new TestAuthenticator(provider);
        var encoded = LoRaFragmentCodec.Encode(
            new LoRaFragmentUnsignedFrame(
                new LoRaFragmentHeader(
                    MessageId, 0, 2, 0, 64, LoRaFragmentFecMode.None),
                Range(0x10, 64)),
            handle,
            LoRaFragmentDirection.Forward,
            stable);
        var mutating = new MutatingVerifier(
            stable,
            () => encoded[LoRaFragmentLimits.HeaderLength] ^= 1);

        var exception = Assert.Throws<LoRaFragmentException>(() =>
            LoRaFragmentCodec.Decode(
                encoded,
                Policy(),
                handle,
                LoRaFragmentDirection.Forward,
                mutating));

        Assert.Equal(LoRaFragmentError.AuthenticationFailed, exception.Error);
        Assert.Equal(2, mutating.VerifyCalls);
    }

    [Fact]
    public void EveryTruncationAndAnOverlongFrameFailBeforeAcceptance()
    {
        var provider = new TestAuthenticationProvider();
        var handle = provider.Create(Range(0x40, 32));
        var authenticator = new TestAuthenticator(provider);
        var encoded = LoRaFragmentCodec.Encode(
            new LoRaFragmentUnsignedFrame(
                new LoRaFragmentHeader(
                    MessageId, 0, 2, 0, 64, LoRaFragmentFecMode.None),
                new byte[64]),
            handle,
            LoRaFragmentDirection.Forward,
            authenticator);

        for (var length = 0; length < encoded.Length; length++)
        {
            Assert.Throws<LoRaFragmentException>(() =>
                LoRaFragmentCodec.Decode(
                    encoded.AsSpan(0, length),
                    Policy(),
                    handle,
                    LoRaFragmentDirection.Forward,
                    authenticator));
        }

        Assert.Throws<LoRaFragmentException>(() =>
            LoRaFragmentCodec.Decode(
                [.. encoded, 0],
                Policy(),
                handle,
                LoRaFragmentDirection.Forward,
                authenticator));
    }

    [Fact]
    public void InvalidSixtyFourByteDpb1AndRaisedPoliciesAreRejected()
    {
        var provider = new TestAuthenticationProvider();
        var handle = provider.Create(Range(0x40, 32));
        var authenticator = new TestAuthenticator(provider);

        var invalidBundle = Assert.Throws<LoRaFragmentException>(() =>
            LoRaFragmentPlanner.Plan(
                new LoRaFragmentPlanRequest(
                    new byte[LoRaFragmentLimits.MinimumBundleLength],
                    MessageId,
                    0,
                    1,
                    64,
                    LoRaFragmentFecMode.None,
                    LoRaFragmentDirection.Forward,
                    handle),
                Policy(),
                authenticator));
        Assert.Equal(LoRaFragmentError.OpaqueBundleRejected, invalidBundle.Error);
        Assert.IsAssignableFrom<OpaqueBundleException>(invalidBundle.InnerException);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new LoRaFragmentPolicy(
                OpaquePolicy(),
                maxBundleLength: LoRaFragmentLimits.MaximumBundleLength + 1));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new LoRaFragmentPolicy(
                OpaquePolicy(),
                maxShardSize: LoRaFragmentLimits.MaximumShardSize + 1));
    }

    [Fact]
    public void ProductionAssemblyContainsNoAuthenticatorOrCommercialDependency()
    {
        var assembly = typeof(LoRaFragmentCodec).Assembly;
        Assert.DoesNotContain(
            assembly.GetTypes(),
            type =>
                typeof(ILoRaFragmentAuthenticator).IsAssignableFrom(type) &&
                type is { IsInterface: false, IsAbstract: false });
        Assert.DoesNotContain(
            assembly.GetReferencedAssemblies(),
            reference =>
                ContainsCommercialName(reference.Name));
        Assert.DoesNotContain(
            assembly.GetTypes(),
            type =>
                ContainsCommercialName(type.FullName));
    }

    private static bool ContainsCommercialName(string? value) =>
        value?.Contains("wallet", StringComparison.OrdinalIgnoreCase) == true ||
        value?.Contains("billing", StringComparison.OrdinalIgnoreCase) == true ||
        value?.Contains("staking", StringComparison.OrdinalIgnoreCase) == true ||
        value?.Contains("reward", StringComparison.OrdinalIgnoreCase) == true ||
        value?.Contains("entitlement", StringComparison.OrdinalIgnoreCase) == true;

    private static byte[] ValidOpaqueBundle()
    {
        var request = new OpaqueBundleWriteRequest
        {
            Capability = new OpaqueDepositCapability(Range(0x10, 32)),
            TransportAttemptId = new TransportAttemptId(Range(0x30, 16)),
            EndToEndDedupId = new EndToEndDedupId(Range(0x50, 16)),
            ExpiryBucket = 100,
            PaddingClass = OpaqueBundlePaddingClass.Bytes256,
            ReplayMaterial = Range(0x70, 16),
            EncryptedHeader = new byte[] { 0xaa },
            EncryptedPayload = new byte[] { 0xbb },
            PayloadKind = OpaqueBundlePayloadKind.NativeOpaque,
            CriticalFeatures = OpaqueBundleFeatures.V1Required
        };
        return OpaqueBundleCodec.Encode(
            request,
            new OpaqueBundleNegotiatedProfile(
                OpaqueBundleWireVersion.V1,
                OpaqueBundleFeatures.V1Required,
                AllowLegacyDpe1: false));
    }

    private static LoRaFragmentPolicy Policy() =>
        new(OpaquePolicy());

    private static OpaqueBundleDecodePolicy OpaquePolicy() =>
        new()
        {
            MinimumVersion = OpaqueBundleWireVersion.V1,
            MaximumVersion = OpaqueBundleWireVersion.V1,
            SupportedCriticalFeatures = OpaqueBundleFeatures.V1Required,
            MinimumExpiryBucket = 99,
            MaximumExpiryBucket = 101
        };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();

    private sealed class TestAuthenticationProvider
        : LoRaFragmentAuthenticationHandleProviderBase
    {
        private readonly Dictionary<LoRaFragmentAuthenticationHandle, byte[]> _keys = [];

        public override LoRaFragmentAuthenticationHandle GetAuthenticationHandle() =>
            Create(Range(0x90, 32));

        public LoRaFragmentAuthenticationHandle Create(byte[] key)
        {
            var handle = CreateOpaqueAuthenticationHandle();
            _keys.Add(handle, key.ToArray());
            return handle;
        }

        public byte[] Resolve(LoRaFragmentAuthenticationHandle handle) =>
            _keys.TryGetValue(handle, out var key)
                ? key
                : throw new InvalidOperationException("Unknown test authentication handle.");
    }

    private sealed class TestAuthenticator(TestAuthenticationProvider provider)
        : ILoRaFragmentAuthenticator
    {
        public byte[] CreateTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript)
        {
            Assert.Equal(LoRaFragmentDomains.Authentication.ToArray(), domain.ToArray());
            Assert.Equal(domain.ToArray(), canonicalTranscript[..domain.Length].ToArray());
            Assert.Equal((byte)direction, canonicalTranscript[domain.Length]);
            return HMACSHA256.HashData(
                provider.Resolve(authenticationHandle),
                canonicalTranscript)[..LoRaFragmentLimits.AuthenticationTagLength];
        }

        public bool VerifyTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript,
            ReadOnlySpan<byte> authenticationTag)
        {
            var expected = CreateTag(
                domain,
                authenticationHandle,
                direction,
                canonicalTranscript);
            return authenticationTag.Length == expected.Length &&
                   CryptographicOperations.FixedTimeEquals(expected, authenticationTag);
        }
    }

    private sealed class MutatingVerifier(
        ILoRaFragmentAuthenticator inner,
        Action mutateOnce)
        : ILoRaFragmentAuthenticator
    {
        private bool _mutated;

        public int VerifyCalls { get; private set; }

        public byte[] CreateTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript) =>
            inner.CreateTag(
                domain,
                authenticationHandle,
                direction,
                canonicalTranscript);

        public bool VerifyTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript,
            ReadOnlySpan<byte> authenticationTag)
        {
            VerifyCalls++;
            var accepted = inner.VerifyTag(
                domain,
                authenticationHandle,
                direction,
                canonicalTranscript,
                authenticationTag);
            if (!_mutated)
            {
                _mutated = true;
                mutateOnce();
            }

            return accepted;
        }
    }
}
