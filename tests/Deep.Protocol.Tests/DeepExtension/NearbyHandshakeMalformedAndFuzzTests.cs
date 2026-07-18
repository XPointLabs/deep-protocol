using Deep.Protocol.DeepExtension.NearbyHandshakes;
using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class NearbyHandshakeMalformedAndFuzzTests
{
    [Fact]
    public void EveryAdvertisementAndFrameTruncation_IsRejected()
    {
        var advertisement = NearbyHandshakeCodec.EncodeAdvertisement(1, Range(0x10, 16));
        var frame = CanonicalFrame();
        for (var length = 0; length < advertisement.Length; length++)
        {
            Assert.Throws<NearbyHandshakeException>(() =>
                NearbyHandshakeCodec.DecodeAdvertisement(advertisement.AsSpan(0, length)));
        }

        for (var length = 0; length < frame.Length; length++)
        {
            Assert.Throws<NearbyHandshakeException>(() =>
                NearbyHandshakeCodec.DecodeFrame(frame.AsSpan(0, length)));
        }
    }

    [Theory]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(7)]
    [InlineData(58)]
    [InlineData(63)]
    public void StructuredFrameMutations_AreRejected(int offset)
    {
        var frame = CanonicalFrame();
        frame[offset] = 0xff;
        Assert.Throws<NearbyHandshakeException>(() => NearbyHandshakeCodec.DecodeFrame(frame));
    }

    [Fact]
    public void LengthAndTrailingBytes_AreRejected()
    {
        var frame = CanonicalFrame();
        frame[57]++;
        Assert.Throws<NearbyHandshakeException>(() => NearbyHandshakeCodec.DecodeFrame(frame));
        Assert.Throws<NearbyHandshakeException>(() =>
            NearbyHandshakeCodec.DecodeFrame(CanonicalFrame().Concat(new byte[] { 0 }).ToArray()));
    }

    [Fact]
    public void FixedSeedMalformedFrames_StayInsideExpectedExceptionSurface()
    {
        var random = new Random(0x503C);
        for (var iteration = 0; iteration < 2_000; iteration++)
        {
            var encoded = new byte[random.Next(
                0,
                NearbyHandshakeLimits.FrameHeaderLength +
                NearbyHandshakeLimits.MaximumAdapterPayloadLength + 32)];
            random.NextBytes(encoded);
            try
            {
                _ = NearbyHandshakeCodec.DecodeFrame(encoded);
            }
            catch (NearbyHandshakeException)
            {
                continue;
            }

            Assert.Fail("Random malformed nearby frame unexpectedly decoded.");
        }
    }

    private static byte[] CanonicalFrame() =>
        NearbyHandshakeCodec.EncodeFrame(
            NearbyHandshakeMessageKind.InitiatorHello,
            new NearbyHandshakeBinding
            {
                BundleVersion = 1,
                Period = 100,
                TransportAttemptId = new TransportAttemptId(Range(0x40, 16)),
                SimultaneousOpenToken = Range(0x50, 16),
                Mode = NearbyHandshakeMode.Fresh,
                ResumeCounter = 0
            },
            Range(0x70, 32));

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();
}
