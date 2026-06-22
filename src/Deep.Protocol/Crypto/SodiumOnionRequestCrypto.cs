using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.Abstractions;
using Deep.Protocol.Abstractions.OnionRequests;
using Sodium;

namespace Deep.Protocol;

public sealed class SodiumOnionRequestCrypto : IOnionRequestCrypto
{
    public OnionRequestPayload Build(OnionRequestBuildOptions options, ReadOnlySpan<byte> plaintextBody)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.Endpoint))
        {
            throw new ArgumentException("Endpoint is required.", nameof(options));
        }

        var destinationPublicKey = RequireX25519PublicKey(options.DestinationX25519PublicKey, nameof(options.DestinationX25519PublicKey));
        var finalHop = GenerateX25519KeyPair();

        var request = new OnionBuiltRequest(
            options.Endpoint,
            OnionRequestCodec.ToWireString(options.EncryptionType),
            Convert.ToBase64String(plaintextBody.ToArray()),
            Convert.ToBase64String(finalHop.PublicKey));

        var layer = JsonSerializer.SerializeToUtf8Bytes(request);
        layer = SealedPublicKeyBox.Create(layer, destinationPublicKey);

        for (var i = options.Hops.Count - 1; i >= 0; i--)
        {
            var hopKey = RequireX25519PublicKey(options.Hops[i].X25519PublicKey, $"{nameof(options.Hops)}[{i}].X25519PublicKey");
            layer = SealedPublicKeyBox.Create(layer, hopKey);
        }

        return new OnionRequestPayload(layer, finalHop.PublicKey, finalHop.SecretKey);
    }

    public OnionResponse DecryptResponse(
        OnionEncryptionType encryptionType,
        ReadOnlySpan<byte> destinationX25519PublicKey,
        ReadOnlySpan<byte> finalHopX25519PublicKey,
        ReadOnlySpan<byte> finalHopX25519SecretKey,
        ReadOnlySpan<byte> encryptedResponse,
        bool v4Request)
    {
        if (encryptionType is not OnionEncryptionType.XChaCha20 and not OnionEncryptionType.AesGcm)
        {
            throw new ArgumentOutOfRangeException(nameof(encryptionType));
        }

        _ = RequireX25519PublicKey(destinationX25519PublicKey, nameof(destinationX25519PublicKey));
        var finalHopPublic = RequireX25519PublicKey(finalHopX25519PublicKey, nameof(finalHopX25519PublicKey));
        var finalHopSecret = RequireX25519SecretKey(finalHopX25519SecretKey, nameof(finalHopX25519SecretKey));

        var plaintext = SealedPublicKeyBox.Open(encryptedResponse.ToArray(), finalHopSecret, finalHopPublic);

        if (TryParseResponseEnvelope(plaintext, v4Request, out var parsed) && parsed is not null)
        {
            return parsed;
        }

        return new OnionResponse(200, Array.Empty<KeyValuePair<string, string>>(), Encoding.UTF8.GetString(plaintext));
    }

    private static bool TryParseResponseEnvelope(byte[] plaintext, bool v4Request, out OnionResponse? response)
    {
        response = null;
        try
        {
            using var json = JsonDocument.Parse(plaintext);
            var root = json.RootElement;

            var status = root.TryGetProperty("statusCode", out var statusCode)
                ? (short)statusCode.GetInt16()
                : root.TryGetProperty("code", out var code)
                    ? (short)code.GetInt16()
                    : (short)200;

            var headers = TryReadHeaders(root);
            string? body = null;
            if (root.TryGetProperty("body", out var bodyProperty))
            {
                body = bodyProperty.ValueKind == JsonValueKind.Null ? null : bodyProperty.GetString();
            }
            else if (v4Request && root.TryGetProperty("data", out var dataProperty))
            {
                body = dataProperty.GetRawText();
            }

            response = new OnionResponse(status, headers, body);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static IReadOnlyList<KeyValuePair<string, string>> TryReadHeaders(JsonElement root)
    {
        if (!root.TryGetProperty("headers", out var headersElement))
        {
            return Array.Empty<KeyValuePair<string, string>>();
        }

        if (headersElement.ValueKind == JsonValueKind.Object)
        {
            return headersElement.EnumerateObject()
                .Select(item => new KeyValuePair<string, string>(item.Name, item.Value.GetString() ?? string.Empty))
                .ToArray();
        }

        if (headersElement.ValueKind == JsonValueKind.Array)
        {
            var pairs = new List<KeyValuePair<string, string>>();
            foreach (var item in headersElement.EnumerateArray())
            {
                if (item.TryGetProperty("key", out var key) && item.TryGetProperty("value", out var value))
                {
                    pairs.Add(new KeyValuePair<string, string>(key.GetString() ?? string.Empty, value.GetString() ?? string.Empty));
                }
            }

            return pairs;
        }

        return Array.Empty<KeyValuePair<string, string>>();
    }

    private static byte[] RequireX25519PublicKey(ReadOnlyMemory<byte> key, string name) =>
        ByteHelpers.RequireSize(key, ProtocolConstants.X25519PublicKeySize, name);

    private static byte[] RequireX25519PublicKey(ReadOnlySpan<byte> key, string name) =>
        ByteHelpers.RequireSize(key, ProtocolConstants.X25519PublicKeySize, name);

    private static byte[] RequireX25519SecretKey(ReadOnlySpan<byte> key, string name) =>
        ByteHelpers.RequireSize(key, ProtocolConstants.X25519SecretKeySize, name);

    private static X25519KeyPair GenerateX25519KeyPair()
    {
        var seed = RandomNumberGenerator.GetBytes(ProtocolConstants.Ed25519SeedSize);
        var ed25519 = PublicKeyAuth.GenerateKeyPair(seed);
        return new X25519KeyPair(
            PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(ed25519.PublicKey),
            PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(ed25519.PrivateKey));
    }

    private sealed record OnionBuiltRequest(string Endpoint, string EncryptionType, string BodyBase64, string ReplyToX25519PublicKeyBase64);

    private sealed record X25519KeyPair(byte[] PublicKey, byte[] SecretKey);
}