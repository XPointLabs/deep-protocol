using System.Security.Cryptography;
using Deep.Protocol.Abstractions;

namespace Deep.Protocol.Tests;

public sealed class ProtocolParserCodecFuzzTests
{
    [Fact]
    public void DecodeEnvelope_DoesNotCrashOnRandomPayloads()
    {
        var codec = new SessionProtocolCodec();
        var random = new Random(424242);

        var decryptKey = new SodiumSessionProtocolCrypto().GenerateEd25519SecretKey();
        var keys = new DecodeEnvelopeKeys
        {
            DecryptKeys = new[] { (ReadOnlyMemory<byte>)decryptKey }
        };

        for (var i = 0; i < 512; i++)
        {
            var payload = new byte[random.Next(0, 1025)];
            random.NextBytes(payload);

            try
            {
                _ = codec.DecodeEnvelope(keys, payload);
            }
            catch
            {
            }
        }
    }

    [Fact]
    public void DecodeForCommunity_DoesNotCrashOnRandomPayloads()
    {
        var codec = new SessionProtocolCodec();

        for (var i = 0; i < 512; i++)
        {
            var payload = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(0, 1025));

            try
            {
                _ = codec.DecodeForCommunity(payload, DateTimeOffset.UtcNow);
            }
            catch
            {
            }
        }
    }

    [Fact]
    public void SharedConfigAndGroupParsers_DoNotCrashOnRandomPayloads()
    {
        for (var i = 0; i < 512; i++)
        {
            var payload = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(0, 1025));
            _ = SharedConfigParser.TryParseFromContent(payload);
            _ = GroupUpdateParser.TryParseFromContent(payload);
        }
    }

    [Fact]
    public void OnionEncryptionTypeParser_IsRobustToRandomStrings()
    {
        var random = new Random(5150);

        for (var i = 0; i < 512; i++)
        {
            var chars = new char[random.Next(0, 32)];
            for (var index = 0; index < chars.Length; index++)
            {
                chars[index] = (char)random.Next(32, 127);
            }

            var value = new string(chars);
            try
            {
                _ = OnionRequestCodec.ParseEncryptionType(value);
            }
            catch (ArgumentException)
            {
            }
        }
    }
}
