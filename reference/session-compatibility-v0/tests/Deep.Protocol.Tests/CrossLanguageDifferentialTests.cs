using System.Text;
using System.Text.Json;
using Deep.Protocol.Abstractions;
using Deep.Protocol.Abstractions.OnionRequests;
using Google.Protobuf;
using Sodium;

namespace Deep.Protocol.Tests;

public sealed class CrossLanguageDifferentialTests
{
    [Fact]
    public void OneToOneCodecCiphertextDecryptsWithDirectSodium()
    {
        var codec = new SessionProtocolCodec();
        var crypto = new SodiumSessionProtocolCrypto();

        var sender = crypto.GenerateEd25519SecretKey();
        var recipient = crypto.GenerateEd25519SecretKey();
        var recipientX25519Public = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(
            PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(recipient));
        var recipientSessionId = new byte[ProtocolConstants.SessionIdSize];
        recipientSessionId[0] = (byte)SessionIdPrefix.Standard;
        recipientX25519Public.CopyTo(recipientSessionId.AsSpan(1));

        var timestamp = DateTimeOffset.FromUnixTimeMilliseconds(1754971101000);
        var content = BuildContent("cross-language-1o1", timestamp);

        var encoded = codec.EncodeForOneToOne(content, sender, timestamp, recipientSessionId);

        var websocket = WebSocketProtos.WebSocketMessage.Parser.ParseFrom(encoded.Ciphertext.ToArray());
        var envelope = SessionProtos.Envelope.Parser.ParseFrom(websocket.Request.Body);

        var recipientX25519Secret = PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(recipient);
        var decryptedContent = SealedPublicKeyBox.Open(
            envelope.Content.ToByteArray(),
            recipientX25519Secret,
            recipientX25519Public);

        Assert.True(decryptedContent.Length > ProtocolConstants.SessionIdSize);
        var senderSessionId = decryptedContent[..ProtocolConstants.SessionIdSize];
        Assert.Equal((byte)SessionIdPrefix.Standard, senderSessionId[0]);

        var unpadded = SessionProtocolCodec.UnpadMessage(decryptedContent[ProtocolConstants.SessionIdSize..]).ToArray();
        var parsed = SessionProtos.Content.Parser.ParseFrom(unpadded);

        Assert.Equal("cross-language-1o1", parsed.DataMessage.Body);
        Assert.Equal((ulong)timestamp.ToUnixTimeMilliseconds(), parsed.SigTimestamp);
    }

    [Fact]
    public void GroupCodecCiphertextDecryptsWithDirectSodium()
    {
        var codec = new SessionProtocolCodec();
        var crypto = new SodiumSessionProtocolCrypto();

        var sender = crypto.GenerateEd25519SecretKey();
        var groupSecret = crypto.GenerateEd25519SecretKey();
        var groupEdPublic = PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(groupSecret);
        var groupCurvePublic = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(groupEdPublic);
        var groupCurveSecret = PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(groupSecret);

        var groupSessionId = new byte[ProtocolConstants.SessionIdSize];
        groupSessionId[0] = (byte)SessionIdPrefix.Group;
        groupEdPublic.CopyTo(groupSessionId.AsSpan(1));

        var timestamp = DateTimeOffset.FromUnixTimeMilliseconds(1754971101000);
        var content = BuildContent("cross-language-group", timestamp);

        var encoded = codec.EncodeForDestination(
            content,
            sender,
            new Destination
            {
                Type = DestinationType.Group,
                SentTimestamp = timestamp,
                GroupEd25519PublicKey = groupSessionId,
                GroupEncryptionKey = new byte[ProtocolConstants.X25519PublicKeySize]
            });

        var plaintext = SealedPublicKeyBox.Open(encoded.Ciphertext.ToArray(), groupCurveSecret, groupCurvePublic);
        Assert.True(plaintext.Length > ProtocolConstants.SessionIdSize);
        Assert.Equal((byte)SessionIdPrefix.Standard, plaintext[0]);

        var payload = plaintext[ProtocolConstants.SessionIdSize..];
        byte[] maybeDecompressed;
        try
        {
            using var input = new MemoryStream(payload);
            using var decompressor = new System.IO.Compression.BrotliStream(input, System.IO.Compression.CompressionMode.Decompress);
            using var output = new MemoryStream();
            decompressor.CopyTo(output);
            maybeDecompressed = output.ToArray();
        }
        catch
        {
            maybeDecompressed = payload;
        }

        var envelope = SessionProtos.Envelope.Parser.ParseFrom(StripPadding(maybeDecompressed));
        var parsed = SessionProtos.Content.Parser.ParseFrom(envelope.Content.ToByteArray());

        Assert.Equal("cross-language-group", parsed.DataMessage.Body);
        Assert.Equal((ulong)timestamp.ToUnixTimeMilliseconds(), envelope.Timestamp);
    }

    [Fact]
    public void OnionBuildLayeringAndResponseDecryptMatchDirectSodium()
    {
        var codec = new OnionRequestCodec();
        var destination = PublicKeyBox.GenerateKeyPair();
        var hop1 = PublicKeyBox.GenerateKeyPair();
        var hop2 = PublicKeyBox.GenerateKeyPair();

        var payload = codec.Build(
            new OnionRequestBuildOptions
            {
                EncryptionType = OnionEncryptionType.XChaCha20,
                Endpoint = "/loki/v3/lsrpc",
                DestinationX25519PublicKey = destination.PublicKey,
                Hops =
                [
                    new OnionServiceNode("hop-1", Array.Empty<byte>(), hop1.PublicKey),
                    new OnionServiceNode("hop-2", Array.Empty<byte>(), hop2.PublicKey)
                ]
            },
            "hello-onion"u8.ToArray());

        var layer1 = SealedPublicKeyBox.Open(payload.Body.ToArray(), hop1.PrivateKey, hop1.PublicKey);
        var layer2 = SealedPublicKeyBox.Open(layer1, hop2.PrivateKey, hop2.PublicKey);
        var destinationPlain = SealedPublicKeyBox.Open(layer2, destination.PrivateKey, destination.PublicKey);

        using var json = JsonDocument.Parse(destinationPlain);
        var root = json.RootElement;
        Assert.Equal("/loki/v3/lsrpc", root.GetProperty("Endpoint").GetString());
        Assert.Equal("xchacha20", root.GetProperty("EncryptionType").GetString());

        var body = Convert.FromBase64String(root.GetProperty("BodyBase64").GetString() ?? string.Empty);
        Assert.Equal("hello-onion", Encoding.UTF8.GetString(body));

        var responseEnvelope = JsonSerializer.SerializeToUtf8Bytes(new
        {
            statusCode = 200,
            headers = new { source = "router" },
            body = "ok"
        });
        var encryptedResponse = SealedPublicKeyBox.Create(responseEnvelope, payload.FinalHopX25519PublicKey.ToArray());

        var response = codec.DecryptResponse(
            OnionEncryptionType.XChaCha20,
            destination.PublicKey,
            payload.FinalHopX25519PublicKey.Span,
            payload.FinalHopX25519SecretKey.Span,
            encryptedResponse);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("ok", response.Body);
        Assert.Contains(response.Headers, pair => pair.Key == "source" && pair.Value == "router");
    }

    private static byte[] BuildContent(string body, DateTimeOffset timestamp) =>
        new SessionProtos.Content
        {
            SigTimestamp = (ulong)timestamp.ToUnixTimeMilliseconds(),
            DataMessage = new SessionProtos.DataMessage
            {
                Body = body
            }
        }.ToByteArray();

    private static byte[] StripPadding(byte[] payload)
    {
        var sizeWithoutPadding = payload.Length;
        while (sizeWithoutPadding > 0)
        {
            var value = payload[sizeWithoutPadding - 1];
            if (value != 0 && value != 0x80)
            {
                break;
            }

            sizeWithoutPadding--;
            if (value == 0x80)
            {
                return payload[..sizeWithoutPadding];
            }
        }

        return payload;
    }
}
