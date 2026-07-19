using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.ManagedIngress;

namespace Deep.Protocol.Tests.DeepExtension.ManagedIngress;

public sealed class ManagedIngressMalformedAndFuzzTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(63)]
    [InlineData(65)]
    public void Die1_WrongLengthFailsClosed(int length)
    {
        var exception = Assert.Throws<ManagedIngressContractException>(
            () => ManagedIngressErrorCodec.Decode(new byte[length]));
        Assert.Equal(ManagedIngressContractError.MalformedErrorFrame, exception.Error);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(12)]
    [InlineData(63)]
    public void Die1_MutationsFailClosed(int offset)
    {
        var encoded = ManagedIngressErrorCodec.Encode(new ManagedIngressErrorFrame(
            ManagedIngressErrorClass.Unavailable,
            ManagedIngressOutcomeCertainty.BeforeForward,
            retryable: true,
            retryAfterSeconds: 5));
        encoded[offset] ^= 0x80;

        Assert.Throws<ManagedIngressContractException>(
            () => ManagedIngressErrorCodec.Decode(encoded));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(60)]
    [InlineData(61)]
    public void RetryAfter_IsStrictlyBounded(int seconds)
    {
        var error = new ManagedIngressErrorFrame(
            ManagedIngressErrorClass.Saturated,
            ManagedIngressOutcomeCertainty.BeforeForward,
            retryable: true,
            retryAfterSeconds: seconds);

        if (seconds is >= 1 and <= 60)
        {
            Assert.Equal(error, ManagedIngressErrorCodec.Decode(ManagedIngressErrorCodec.Encode(error)));
        }
        else
        {
            Assert.Throws<ManagedIngressContractException>(() => ManagedIngressErrorCodec.Encode(error));
        }
    }

    [Theory]
    [InlineData(400, ManagedIngressErrorClass.MalformedFrame, ManagedIngressOutcomeCertainty.BeforeForward)]
    [InlineData(406, ManagedIngressErrorClass.UnsupportedResponseType, ManagedIngressOutcomeCertainty.BeforeForward)]
    [InlineData(413, ManagedIngressErrorClass.FrameTooLarge, ManagedIngressOutcomeCertainty.BeforeForward)]
    [InlineData(415, ManagedIngressErrorClass.UnsupportedMediaType, ManagedIngressOutcomeCertainty.BeforeForward)]
    [InlineData(421, ManagedIngressErrorClass.WrongOrigin, ManagedIngressOutcomeCertainty.BeforeForward)]
    [InlineData(425, ManagedIngressErrorClass.EarlyDataRejected, ManagedIngressOutcomeCertainty.BeforeForward)]
    [InlineData(429, ManagedIngressErrorClass.Saturated, ManagedIngressOutcomeCertainty.BeforeForward)]
    [InlineData(502, ManagedIngressErrorClass.InvalidUpstreamResponse, ManagedIngressOutcomeCertainty.UnknownAfterForward)]
    [InlineData(503, ManagedIngressErrorClass.Unavailable, ManagedIngressOutcomeCertainty.BeforeForward)]
    [InlineData(504, ManagedIngressErrorClass.UpstreamOutcomeUnknown, ManagedIngressOutcomeCertainty.UnknownAfterForward)]
    public void HttpErrorMapping_IsExact(
        int status,
        ManagedIngressErrorClass errorClass,
        ManagedIngressOutcomeCertainty certainty)
    {
        var retryable = status is 421 or 425 or 429 or 502 or 503 or 504;
        var retryAfter = status is 429 or 503 ? 5 : 0;
        var frame = new ManagedIngressErrorFrame(errorClass, certainty, retryable, retryAfter);

        Assert.True(ManagedIngressH2Contract.IsCanonicalErrorMapping(status, frame));
    }

    [Fact]
    public void CrossMappedStatusAndFrame_Fails()
    {
        var frame = new ManagedIngressErrorFrame(
            ManagedIngressErrorClass.Unavailable,
            ManagedIngressOutcomeCertainty.UnknownAfterForward,
            retryable: true,
            retryAfterSeconds: 5);

        Assert.False(ManagedIngressH2Contract.IsCanonicalErrorMapping(503, frame));
        Assert.False(ManagedIngressH2Contract.IsCanonicalErrorMapping(504, frame));
    }

    [Fact]
    public void ErrorCodec_RejectsCrossClassCertaintyAndRetryPolicy()
    {
        Assert.Throws<ManagedIngressContractException>(() =>
            ManagedIngressErrorCodec.Encode(new ManagedIngressErrorFrame(
                ManagedIngressErrorClass.MalformedFrame,
                ManagedIngressOutcomeCertainty.UnknownAfterForward,
                retryable: true,
                retryAfterSeconds: 0)));
        Assert.Throws<ManagedIngressContractException>(() =>
            ManagedIngressErrorCodec.Encode(new ManagedIngressErrorFrame(
                ManagedIngressErrorClass.UpstreamOutcomeUnknown,
                ManagedIngressOutcomeCertainty.BeforeForward,
                retryable: false,
                retryAfterSeconds: 0)));
    }

    [Fact]
    public void HeaderListAndCountBounds_AreStrict()
    {
        var tooMany = Enumerable.Range(0, ManagedIngressLimits.MaximumHeaderFields + 1)
            .Select(index => new ManagedIngressHeader($"x-{index}", "v"))
            .ToArray();
        Assert.Throws<ManagedIngressContractException>(
            () => ManagedIngressH2Contract.ValidateHeaders(tooMany));

        var oversized = new[]
        {
            new ManagedIngressHeader("x-safe", new string('a', ManagedIngressLimits.MaximumDecodedHeaderListBytes))
        };
        Assert.Throws<ManagedIngressContractException>(
            () => ManagedIngressH2Contract.ValidateHeaders(oversized));
    }

    [Fact]
    public void FixedSeedMalformedSmoke_NeverAcceptsMutatedDie1()
    {
        var canonical = ManagedIngressErrorCodec.Encode(new ManagedIngressErrorFrame(
            ManagedIngressErrorClass.UpstreamOutcomeUnknown,
            ManagedIngressOutcomeCertainty.UnknownAfterForward,
            retryable: true,
            retryAfterSeconds: 0));
        var random = new Random(0x10b);
        var rejected = 0;

        for (var i = 0; i < 512; i++)
        {
            var candidate = canonical.ToArray();
            var mutations = 1 + random.Next(4);
            for (var mutation = 0; mutation < mutations; mutation++)
            {
                var index = random.Next(candidate.Length);
                candidate[index] ^= (byte)(1 << random.Next(8));
            }

            try
            {
                var decoded = ManagedIngressErrorCodec.Decode(candidate);
                var reencoded = ManagedIngressErrorCodec.Encode(decoded);
                Assert.Equal(candidate, reencoded);
            }
            catch (ManagedIngressContractException)
            {
                rejected++;
            }
        }

        Assert.True(rejected >= 450, $"Expected most malformed frames to be rejected, got {rejected}/512.");
    }

    [Fact]
    public void ReservedBytesAreAlwaysZero()
    {
        var encoded = ManagedIngressErrorCodec.Encode(new ManagedIngressErrorFrame(
            ManagedIngressErrorClass.MalformedFrame,
            ManagedIngressOutcomeCertainty.BeforeForward,
            retryable: false,
            retryAfterSeconds: 0));
        Assert.All(encoded.AsSpan(9, 1).ToArray(), value => Assert.Equal(0, value));
        Assert.All(encoded.AsSpan(12, 52).ToArray(), value => Assert.Equal(0, value));
        Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(10, 2)));
    }
}
