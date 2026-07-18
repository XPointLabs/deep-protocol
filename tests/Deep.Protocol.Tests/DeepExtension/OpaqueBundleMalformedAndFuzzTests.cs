using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class OpaqueBundleMalformedAndFuzzTests
{
    [Fact]
    public void TryDecode_IsAllocationBoundedForDeclaredMaximums()
    {
        var input = new byte[OpaqueBundleLimits.MaximumEncodedLength + 1];

        var decoded = OpaqueBundleCodec.TryDecode(
            input,
            PermissivePolicy(),
            out _,
            out var error);

        Assert.False(decoded);
        Assert.Equal(OpaqueBundleDecodeError.EncodedLengthOutOfRange, error);
    }

    [Fact]
    public void EverySingleByteTruncation_FailsWithoutPartialResult()
    {
        var encoded = OpaqueBundleCodec.Encode(CreateRequest(), Profile());

        for (var length = 0; length < encoded.Length; length++)
        {
            var decoded = OpaqueBundleCodec.TryDecode(
                encoded.AsSpan(0, length),
                PermissivePolicy(),
                out var bundle,
                out var error);

            Assert.False(decoded);
            Assert.Null(bundle);
            Assert.NotEqual(OpaqueBundleDecodeError.None, error);
        }
    }

    [Fact]
    public void DeterministicMalformedFuzz_NeverEscapesExpectedResultSurface()
    {
        var random = new Random(0x503);

        for (var iteration = 0; iteration < 4096; iteration++)
        {
            var bytes = new byte[random.Next(0, 8193)];
            random.NextBytes(bytes);

            var success = OpaqueBundleCodec.TryDecode(
                bytes,
                PermissivePolicy(),
                out var bundle,
                out var error);

            Assert.Equal(success, bundle is not null);
            Assert.Equal(success, error == OpaqueBundleDecodeError.None);
        }
    }

    [Fact]
    public void ParserSurface_IsSynchronousAndCancellationIndependent()
    {
        var decode = typeof(OpaqueBundleCodec).GetMethod(
            nameof(OpaqueBundleCodec.Decode),
            [typeof(ReadOnlySpan<byte>), typeof(OpaqueBundleDecodePolicy)]);

        Assert.NotNull(decode);
        Assert.DoesNotContain(
            typeof(OpaqueBundleCodec).GetMethods().SelectMany(static method => method.GetParameters()),
            static parameter => parameter.ParameterType == typeof(CancellationToken));
    }

    private static OpaqueBundleWriteRequest CreateRequest() =>
        new()
        {
            Capability = new OpaqueDepositCapability(Enumerable.Repeat((byte)0x41, 32).ToArray()),
            TransportAttemptId = new TransportAttemptId(Enumerable.Range(0, 16).Select(static value => (byte)value).ToArray()),
            EndToEndDedupId = new EndToEndDedupId(Enumerable.Range(16, 16).Select(static value => (byte)value).ToArray()),
            ExpiryBucket = 10,
            PaddingClass = OpaqueBundlePaddingClass.Bytes256,
            ReplayMaterial = Enumerable.Repeat((byte)0x52, 16).ToArray(),
            EncryptedHeader = new byte[] { 0x01 },
            EncryptedPayload = new byte[] { 0x02 },
            CriticalFeatures = OpaqueBundleFeatures.V1Required,
            PayloadKind = OpaqueBundlePayloadKind.NativeOpaque
        };

    private static OpaqueBundleNegotiatedProfile Profile() =>
        new(OpaqueBundleWireVersion.V1, OpaqueBundleFeatures.V1Required, AllowLegacyDpe1: false);

    private static OpaqueBundleDecodePolicy PermissivePolicy() =>
        new()
        {
            MinimumVersion = OpaqueBundleWireVersion.V1,
            MaximumVersion = OpaqueBundleWireVersion.V1,
            SupportedCriticalFeatures =
                OpaqueBundleFeatures.V1Required | OpaqueBundleFeatures.LegacyDpe1Compatibility,
            MinimumExpiryBucket = 0,
            MaximumExpiryBucket = uint.MaxValue,
            AllowLegacyDpe1 = true
        };
}
