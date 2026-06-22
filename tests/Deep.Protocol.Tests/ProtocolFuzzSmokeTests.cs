using System.Security.Cryptography;

namespace Deep.Protocol.Tests;

public sealed class ProtocolFuzzSmokeTests
{
    [Fact]
    public void PadAndUnpadMessage_RoundTripsAcrossRandomPayloads()
    {
        var random = new Random(1337);
        for (var i = 0; i < 512; i++)
        {
            var size = random.Next(0, 4097);
            var payload = new byte[size];
            random.NextBytes(payload);

            var padded = SessionProtocolCodec.PadMessage(payload);
            var unpadded = SessionProtocolCodec.UnpadMessage(padded).ToArray();

            Assert.Equal(payload, unpadded);
            Assert.Equal(0, padded.Length % 160);
        }
    }

    [Fact]
    public void GroupUpdateParser_DoesNotThrowOnRandomPayloads()
    {
        for (var i = 0; i < 512; i++)
        {
            var payload = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(0, 512));
            _ = GroupUpdateParser.TryParseFromContent(payload);
        }
    }
}