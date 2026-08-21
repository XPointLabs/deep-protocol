using Deep.Protocol.DeepExtension.LoRaFragments;
using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class LoRaFragmentMalformedAndFuzzTests
{
    [Theory]
    [InlineData(0, 0)]
    [InlineData(2, 2)]
    [InlineData(3, 0x80)]
    [InlineData(4, 0)]
    [InlineData(13, 0)]
    [InlineData(13, 65)]
    [InlineData(14, 8)]
    [InlineData(12, 72)]
    public void StructuredHeaderMutationsUseBoundedProtocolErrors(
        int offset,
        byte value)
    {
        var fixture = new Fixture();
        var encoded = fixture.ValidFrame();
        encoded[offset] = value;

        Assert.Throws<LoRaFragmentException>(() =>
            LoRaFragmentCodec.Decode(
                encoded,
                fixture.Policy,
                fixture.Handle,
                LoRaFragmentDirection.Forward,
                fixture.Authenticator));
    }

    [Fact]
    public void ExactLengthMismatchAndAbsoluteShardBoundsFailClosed()
    {
        var fixture = new Fixture();
        var encoded = fixture.ValidFrame();

        var shortShard = encoded.ToArray();
        shortShard[15] = 7;
        Assert.Throws<LoRaFragmentException>(() =>
            LoRaFragmentCodec.Decode(
                shortShard,
                fixture.Policy,
                fixture.Handle,
                LoRaFragmentDirection.Forward,
                fixture.Authenticator));

        var overlongShard = new byte[LoRaFragmentLimits.MaximumEncodedFrameLength];
        encoded.AsSpan(0, LoRaFragmentLimits.HeaderLength).CopyTo(overlongShard);
        overlongShard[15] = 193;
        Assert.Throws<LoRaFragmentException>(() =>
            LoRaFragmentCodec.Decode(
                overlongShard,
                fixture.Policy,
                fixture.Handle,
                LoRaFragmentDirection.Forward,
                fixture.Authenticator));
    }

    [Fact]
    public void OversizedDeclaredDataReservationUsesBoundedProtocolError()
    {
        var fixture = new Fixture();
        var encoded = new byte[LoRaFragmentLimits.MaximumEncodedFrameLength];
        encoded[0] = (byte)'L';
        encoded[1] = (byte)'F';
        encoded[2] = LoRaFragmentLimits.WireVersion;
        new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }.CopyTo(encoded, 4);
        encoded[12] = 0;
        encoded[13] = LoRaFragmentLimits.MaximumDataShardCount;
        encoded[14] = 0;
        encoded[15] = LoRaFragmentLimits.MaximumShardSize;

        Assert.Throws<LoRaFragmentException>(() =>
            LoRaFragmentCodec.Decode(
                encoded,
                fixture.Policy,
                fixture.Handle,
                LoRaFragmentDirection.Forward,
                fixture.Authenticator));
    }

    [Fact]
    public void FixedSeedMalformedSmokeNeverLeaksFrameworkExceptions()
    {
        var fixture = new Fixture();
        var random = new Random(0x18A);
        for (var iteration = 0; iteration < 2_000; iteration++)
        {
            var shardSize = random.Next(
                LoRaFragmentLimits.MinimumShardSize,
                LoRaFragmentLimits.MaximumShardSize + 1);
            var encoded = new byte[
                LoRaFragmentLimits.HeaderLength +
                shardSize +
                LoRaFragmentLimits.AuthenticationTagLength];
            random.NextBytes(encoded);
            encoded[0] = (byte)'L';
            encoded[1] = (byte)'F';
            encoded[2] = LoRaFragmentLimits.WireVersion;
            encoded[15] = checked((byte)shardSize);

            try
            {
                _ = LoRaFragmentCodec.Decode(
                    encoded,
                    fixture.Policy,
                    fixture.Handle,
                    LoRaFragmentDirection.Forward,
                    fixture.Authenticator);
            }
            catch (LoRaFragmentException)
            {
                continue;
            }

            Assert.Fail("A random unauthenticated frame unexpectedly decoded.");
        }
    }

    [Fact]
    public void PlannerAcceptsAbsolute4096BoundaryAndHonorsLowerPolicy()
    {
        var fixture = new Fixture();
        var bundle = fixture.Bundle(OpaqueBundlePaddingClass.Bytes4096);
        Assert.Equal(4096, bundle.Length);

        var plan = LoRaFragmentPlanner.Plan(
            new LoRaFragmentPlanRequest(
                bundle,
                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                0,
                2,
                192,
                LoRaFragmentFecMode.Xor1,
                LoRaFragmentDirection.Forward,
                fixture.Handle),
            fixture.Policy,
            fixture.Authenticator);

        Assert.Equal(22, plan.DataShardCount);
        Assert.Equal(3, plan.ParityShardCount);
        Assert.Throws<LoRaFragmentException>(() =>
            LoRaFragmentPlanner.Plan(
                new LoRaFragmentPlanRequest(
                    bundle,
                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                    0,
                    2,
                    192,
                    LoRaFragmentFecMode.Xor1,
                    LoRaFragmentDirection.Forward,
                    fixture.Handle),
                new LoRaFragmentPolicy(
                    fixture.Policy.OpaqueBundleDecodePolicy,
                    maxBundleLength: 1024),
                fixture.Authenticator));
    }

    [Fact]
    public void AdapterReturningNoncanonicalTagLengthIsRejected()
    {
        var fixture = new Fixture();
        var header = new LoRaFragmentHeader(
            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
            0,
            2,
            0,
            64,
            LoRaFragmentFecMode.None);

        var exception = Assert.Throws<LoRaFragmentException>(() =>
            LoRaFragmentCodec.Encode(
                new LoRaFragmentUnsignedFrame(header, new byte[64]),
                fixture.Handle,
                LoRaFragmentDirection.Forward,
                new WrongLengthAuthenticator()));

        Assert.Equal(LoRaFragmentError.InvalidAuthenticationTag, exception.Error);
    }

    private sealed class Fixture
    {
        private readonly Provider _provider = new();

        public Fixture()
        {
            Handle = _provider.GetAuthenticationHandle();
            Authenticator = new RejectingAuthenticator();
            Policy = new LoRaFragmentPolicy(
                new OpaqueBundleDecodePolicy
                {
                    MinimumVersion = OpaqueBundleWireVersion.V1,
                    MaximumVersion = OpaqueBundleWireVersion.V1,
                    SupportedCriticalFeatures = OpaqueBundleFeatures.V1Required,
                    MinimumExpiryBucket = 100,
                    MaximumExpiryBucket = 100
                });
        }

        public LoRaFragmentAuthenticationHandle Handle { get; }
        public ILoRaFragmentAuthenticator Authenticator { get; }
        public LoRaFragmentPolicy Policy { get; }

        public byte[] ValidFrame()
        {
            var header = new LoRaFragmentHeader(
                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                0,
                2,
                0,
                64,
                LoRaFragmentFecMode.None);
            return LoRaFragmentCodec.Encode(
                new LoRaFragmentUnsignedFrame(header, new byte[64]),
                Handle,
                LoRaFragmentDirection.Forward,
                new ZeroAuthenticator());
        }

        public byte[] Bundle(OpaqueBundlePaddingClass paddingClass) =>
            OpaqueBundleCodec.Encode(
                new OpaqueBundleWriteRequest
                {
                    Capability = new OpaqueDepositCapability(
                        Enumerable.Range(0x20, 32).Select(static value => (byte)value).ToArray()),
                    TransportAttemptId = new TransportAttemptId(
                        Enumerable.Range(0x40, 16).Select(static value => (byte)value).ToArray()),
                    EndToEndDedupId = new EndToEndDedupId(
                        Enumerable.Range(0x60, 16).Select(static value => (byte)value).ToArray()),
                    ExpiryBucket = 100,
                    PaddingClass = paddingClass,
                    ReplayMaterial =
                        Enumerable.Range(0x80, 16).Select(static value => (byte)value).ToArray(),
                    EncryptedHeader = new byte[] { 0xaa },
                    EncryptedPayload = new byte[] { 0xbb },
                    PayloadKind = OpaqueBundlePayloadKind.NativeOpaque,
                    CriticalFeatures = OpaqueBundleFeatures.V1Required
                },
                new OpaqueBundleNegotiatedProfile(
                    OpaqueBundleWireVersion.V1,
                    OpaqueBundleFeatures.V1Required,
                    AllowLegacyDpe1: false));
    }

    private sealed class Provider : LoRaFragmentAuthenticationHandleProviderBase
    {
        public override LoRaFragmentAuthenticationHandle GetAuthenticationHandle() =>
            CreateOpaqueAuthenticationHandle();
    }

    private sealed class RejectingAuthenticator : ILoRaFragmentAuthenticator
    {
        public byte[] CreateTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript) =>
            new byte[LoRaFragmentLimits.AuthenticationTagLength];

        public bool VerifyTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript,
            ReadOnlySpan<byte> authenticationTag) =>
            false;
    }

    private sealed class ZeroAuthenticator : ILoRaFragmentAuthenticator
    {
        public byte[] CreateTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript) =>
            new byte[LoRaFragmentLimits.AuthenticationTagLength];

        public bool VerifyTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript,
            ReadOnlySpan<byte> authenticationTag) =>
            authenticationTag.IndexOfAnyExcept((byte)0) < 0;
    }

    private sealed class WrongLengthAuthenticator : ILoRaFragmentAuthenticator
    {
        public byte[] CreateTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript) =>
            new byte[LoRaFragmentLimits.AuthenticationTagLength - 1];

        public bool VerifyTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript,
            ReadOnlySpan<byte> authenticationTag) =>
            false;
    }
}
