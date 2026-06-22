using Google.Protobuf;
using Deep.Protocol.Abstractions;
using Deep.Protocol.GoldenVectors;
using Sodium;

namespace Deep.Protocol.Tests;

public sealed class GoldenVectorTests
{
    [Fact]
    public void PaddingMatchesLibsessionVectors()
    {
        var vectors = GoldenVectorLoader.Load("session-protocol.json");
        foreach (var vector in vectors.Vectors.Where(static vector =>
                     StringComparer.Ordinal.Equals(vector.Kind, "padding-160")))
        {
            var padded = SessionProtocolCodec.PadMessage(Convert.FromHexString(vector.PlaintextHex ?? string.Empty));

            VectorDiffs.AssertHex(vector.Id, vector.PaddedHex, Convert.ToHexString(padded).ToLowerInvariant());
            VectorDiffs.AssertHex(
                vector.Id + "/unpad",
                vector.PlaintextHex ?? string.Empty,
                Convert.ToHexString(SessionProtocolCodec.UnpadMessage(padded).ToArray()).ToLowerInvariant());
        }
    }

    [Fact]
    public void ContentProtobufSerializationMatchesGoldenVector()
    {
        var vectors = GoldenVectorLoader.Load("session-protocol.json");
        var vector = vectors.GetRequired("protobuf/content-data-message-hello-sigtimestamp");

        var content = new SessionProtos.Content
        {
            SigTimestamp = vector.TimestampMs!.Value,
            DataMessage = new SessionProtos.DataMessage
            {
                Body = vector.Body
            }
        };

        VectorDiffs.AssertHex(vector.Id, vector.Hex, Convert.ToHexString(content.ToByteArray()).ToLowerInvariant());
    }

    [Fact]
    public void SessionIdParsesKnownSourceTestVectors()
    {
        var vectors = GoldenVectorLoader.Load("session-protocol.json");
        var session0 = vectors.GetRequired("deterministic-test-key-0/session-id");
        var session1 = vectors.GetRequired("deterministic-test-key-1/session-id");

        VectorDiffs.AssertHex(session0.Id, session0.Hex, SessionId.ParseHex(session0.Hex!).ToString());
        VectorDiffs.AssertHex(session1.Id, session1.Hex, SessionId.ParseHex(session1.Hex!).ToString());
    }

    [Fact]
    public void DeterministicKeyExpansionMatchesUpstreamFixtures()
    {
        var vectors = GoldenVectorLoader.Load("session-protocol.json");

        foreach (var vector in vectors.Vectors.Where(static vector =>
                     StringComparer.Ordinal.Equals(vector.Kind, "identity-key-expansion")))
        {
            var seed = Convert.FromHexString(vector.SeedHex ?? string.Empty);
            var keyPair = PublicKeyAuth.GenerateKeyPair(seed);
            var curvePublic = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(keyPair.PublicKey);

            VectorDiffs.AssertHex(
                vector.Id + "/ed25519",
                vector.Ed25519PublicKeyHex,
                Convert.ToHexString(keyPair.PublicKey).ToLowerInvariant());
            VectorDiffs.AssertHex(
                vector.Id + "/x25519",
                vector.X25519PublicKeyHex,
                Convert.ToHexString(curvePublic).ToLowerInvariant());
        }
    }
}
