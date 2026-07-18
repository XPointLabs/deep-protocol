using System.Buffers.Binary;
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

    public static TheoryData<string, Func<byte[], byte[]>, OpaqueBundleDecodeError> StructuredMutations =>
        new()
        {
            {
                "declared-payload-length-over-maximum",
                bytes => Mutate(bytes, value =>
                    BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(58, 4), uint.MaxValue)),
                OpaqueBundleDecodeError.MalformedLength
            },
            {
                "trailing-byte-breaks-canonical-length",
                bytes => [.. bytes, (byte)0],
                OpaqueBundleDecodeError.MalformedLength
            },
            {
                "non-zero-padding",
                bytes => Mutate(bytes, value => value[^1] = 0x01),
                OpaqueBundleDecodeError.NonCanonicalPadding
            },
            {
                "unknown-critical-feature",
                bytes => Mutate(bytes, value =>
                    BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(10, 4), 0x8000_0007)),
                OpaqueBundleDecodeError.UnknownCriticalFeature
            },
            {
                "missing-required-feature",
                bytes => Mutate(bytes, value =>
                    BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(10, 4), 0x0000_0003)),
                OpaqueBundleDecodeError.MissingRequiredFeature
            },
            {
                "undefined-payload-kind",
                bytes => Mutate(bytes, value => value[6] = 0xff),
                OpaqueBundleDecodeError.InvalidEnumValue
            },
            {
                "legacy-kind-without-opt-in",
                bytes => Mutate(bytes, value =>
                    value[6] = (byte)OpaqueBundlePayloadKind.LegacyDpe1),
                OpaqueBundleDecodeError.LegacyPayloadNotAllowed
            }
        };

    [Theory]
    [MemberData(nameof(StructuredMutations))]
    public void DeterministicStructuredMutations_ReachNamedFailureBranches(
        string name,
        Func<byte[], byte[]> mutate,
        OpaqueBundleDecodeError expectedError)
    {
        var encoded = OpaqueBundleCodec.Encode(CreateRequest(), Profile());
        encoded = mutate(encoded);

        var success = OpaqueBundleCodec.TryDecode(
            encoded,
            PermissivePolicy() with { AllowLegacyDpe1 = false },
            out var bundle,
            out var error);

        Assert.False(success);
        Assert.Null(bundle);
        Assert.Equal(expectedError, error);
        Assert.False(string.IsNullOrWhiteSpace(name));
    }

    [Fact]
    public void DeterministicStructuredTruncations_ReachBodyAndHeaderBoundaries()
    {
        var encoded = OpaqueBundleCodec.Encode(CreateRequest(), Profile());
        var boundaries = new[]
        {
            OpaqueBundleLimits.FixedHeaderLength - 1,
            OpaqueBundleLimits.FixedHeaderLength,
            encoded.Length - 1
        };

        foreach (var length in boundaries)
        {
            var success = OpaqueBundleCodec.TryDecode(
                encoded.AsSpan(0, length),
                PermissivePolicy(),
                out var bundle,
                out var error);

            Assert.False(success);
            Assert.Null(bundle);
            Assert.NotEqual(OpaqueBundleDecodeError.None, error);
        }
    }

    [Fact]
    public void DeclaredPayloadLengthOverflow_ReachesParserOverflowGuard()
    {
        var encoded = OpaqueBundleCodec.Encode(CreateRequest(), Profile());
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(58, 4), uint.MaxValue);

        var exception = Assert.Throws<OpaqueBundleFormatException>(() =>
            OpaqueBundleCodec.Decode(encoded, PermissivePolicy()));

        Assert.Equal(OpaqueBundleDecodeError.MalformedLength, exception.Error);
        Assert.Contains("overflows the parser range", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EncoderStructuredMutation_SeparatesAttemptFromDedup()
    {
        var request = CreateRequest() with
        {
            EndToEndDedupId = new EndToEndDedupId(
                CreateRequest().TransportAttemptId.Bytes.Span)
        };

        var exception = Assert.Throws<OpaqueBundlePolicyException>(() =>
            OpaqueBundleCodec.Encode(request, Profile()));

        Assert.Equal(OpaqueBundleDecodeError.TransportAttemptEqualsDedup, exception.Error);
    }

    private static byte[] Mutate(byte[] bytes, Action<byte[]> mutation)
    {
        mutation(bytes);
        return bytes;
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
