using Deep.Protocol.Abstractions.OnionRequests;
using System.Text;
using System.Text.Json;
using Sodium;

namespace Deep.Protocol.Tests;

public sealed class OnionRequestCodecTests
{
    [Theory]
    [InlineData("xchacha20", OnionEncryptionType.XChaCha20)]
    [InlineData("aes-gcm", OnionEncryptionType.AesGcm)]
    [InlineData("gcm", OnionEncryptionType.AesGcm)]
    public void OnionEncryptionNamesMatchLibsessionAliases(string wireName, OnionEncryptionType expected)
    {
        Assert.Equal(expected, OnionRequestCodec.ParseEncryptionType(wireName));
    }

    [Theory]
    [InlineData(OnionEncryptionType.XChaCha20, "xchacha20")]
    [InlineData(OnionEncryptionType.AesGcm, "aes-gcm")]
    public void OnionEncryptionTypesMapToWireNames(OnionEncryptionType type, string wireName)
    {
        Assert.Equal(wireName, OnionRequestCodec.ToWireString(type));
    }

    [Fact]
    public void OnionEncryptionTypeRejectsUnknownValue()
    {
        var ex = Assert.Throws<ArgumentException>(() => OnionRequestCodec.ParseEncryptionType("bogus"));

        Assert.Contains("Supported onion request encryption values", ex.Message);
    }

    [Fact]
    public void BuildReturnsEncryptedPayloadAndFinalHopKeyMaterial()
    {
        var codec = new OnionRequestCodec();
        var destination = PublicKeyBox.GenerateKeyPair();
        var hop = PublicKeyBox.GenerateKeyPair();

        var payload = codec.Build(
            new OnionRequestBuildOptions
            {
                EncryptionType = OnionEncryptionType.XChaCha20,
                Endpoint = "/loki/v3/lsrpc",
                DestinationX25519PublicKey = destination.PublicKey,
                Hops = [new OnionServiceNode("hop-1", Array.Empty<byte>(), hop.PublicKey)]
            },
            "hello"u8.ToArray());

        Assert.NotEmpty(payload.Body.ToArray());
        Assert.Equal(32, payload.FinalHopX25519PublicKey.Length);
        Assert.Equal(32, payload.FinalHopX25519SecretKey.Length);
    }

    [Fact]
    public void DecryptResponseParsesJsonEnvelopeFromSealedCiphertext()
    {
        var codec = new OnionRequestCodec();
        var destination = PublicKeyBox.GenerateKeyPair();
        var built = codec.Build(
            new OnionRequestBuildOptions
            {
                EncryptionType = OnionEncryptionType.XChaCha20,
                Endpoint = "/rpc",
                DestinationX25519PublicKey = destination.PublicKey
            },
            "ping"u8.ToArray());

        var responseEnvelope = JsonSerializer.SerializeToUtf8Bytes(new
        {
            statusCode = 202,
            headers = new { server = "router", trace = "abc" },
            body = "ok"
        });

        var encrypted = SealedPublicKeyBox.Create(responseEnvelope, built.FinalHopX25519PublicKey.ToArray());
        var response = codec.DecryptResponse(
            OnionEncryptionType.XChaCha20,
            destination.PublicKey,
            built.FinalHopX25519PublicKey.Span,
            built.FinalHopX25519SecretKey.Span,
            encrypted);

        Assert.Equal(202, response.StatusCode);
        Assert.Equal("ok", response.Body);
        Assert.Contains(response.Headers, pair => pair.Key == "server" && pair.Value == "router");
    }

    [Fact]
    public void DecryptResponseSupportsV4DataEnvelopeAndArrayHeaders()
    {
        var codec = new OnionRequestCodec();
        var destination = PublicKeyBox.GenerateKeyPair();
        var built = codec.Build(
            new OnionRequestBuildOptions
            {
                EncryptionType = OnionEncryptionType.AesGcm,
                Endpoint = "/rpc/v4",
                DestinationX25519PublicKey = destination.PublicKey
            },
            "ping"u8.ToArray());

        var responseEnvelope = JsonSerializer.SerializeToUtf8Bytes(new
        {
            code = 204,
            headers = new[]
            {
                new { key = "server", value = "router" },
                new { key = "trace", value = "trace-1" }
            },
            data = new { accepted = true }
        });

        var encrypted = SealedPublicKeyBox.Create(responseEnvelope, built.FinalHopX25519PublicKey.ToArray());
        var response = codec.DecryptResponse(
            OnionEncryptionType.AesGcm,
            destination.PublicKey,
            built.FinalHopX25519PublicKey.Span,
            built.FinalHopX25519SecretKey.Span,
            encrypted,
            v4Request: true);

        Assert.Equal(204, response.StatusCode);
        Assert.Equal("{\"accepted\":true}", response.Body);
        Assert.Contains(response.Headers, pair => pair.Key == "trace" && pair.Value == "trace-1");
    }

    [Fact]
    public void DecryptResponseFallsBackToPlaintextWhenEnvelopeIsNotJson()
    {
        var codec = new OnionRequestCodec();
        var destination = PublicKeyBox.GenerateKeyPair();
        var built = codec.Build(
            new OnionRequestBuildOptions
            {
                EncryptionType = OnionEncryptionType.XChaCha20,
                Endpoint = "/rpc",
                DestinationX25519PublicKey = destination.PublicKey
            },
            "ping"u8.ToArray());

        var plaintext = Encoding.UTF8.GetBytes("raw response");
        var encrypted = SealedPublicKeyBox.Create(plaintext, built.FinalHopX25519PublicKey.ToArray());

        var response = codec.DecryptResponse(
            OnionEncryptionType.XChaCha20,
            destination.PublicKey,
            built.FinalHopX25519PublicKey.Span,
            built.FinalHopX25519SecretKey.Span,
            encrypted);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("raw response", response.Body);
        Assert.Empty(response.Headers);
    }
}
