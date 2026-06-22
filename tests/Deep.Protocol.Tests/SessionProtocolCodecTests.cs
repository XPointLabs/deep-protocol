using Google.Protobuf;
using Deep.Protocol.Abstractions;
using Deep.Protocol.Tests.Fakes;
using System.Text;

namespace Deep.Protocol.Tests;

public sealed class SessionProtocolCodecTests
{
    private static readonly DateTimeOffset Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(1754971101000);
    private static readonly byte[] SenderSecret = Enumerable.Repeat((byte)0x11, ProtocolConstants.Ed25519SecretKeySize).ToArray();
    private static readonly byte[] RecipientSessionId = Convert.FromHexString("05aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74");

    [Fact]
    public void OneToOneEncodeBuildsWebsocketWrappedEnvelope()
    {
        var fake = new FakeSessionProtocolCrypto();
        var codec = new SessionProtocolCodec(fake, fake);
        var content = BuildContent("hello");

        var encoded = codec.EncodeForOneToOne(content, SenderSecret, Timestamp, RecipientSessionId);
        var websocket = WebSocketProtos.WebSocketMessage.Parser.ParseFrom(encoded.Ciphertext.ToArray());
        var envelope = SessionProtos.Envelope.Parser.ParseFrom(websocket.Request.Body);

        Assert.Equal(WebSocketProtos.WebSocketMessage.Types.Type.Request, websocket.Type);
        Assert.Equal(SessionProtos.Envelope.Types.Type.SessionMessage, envelope.Type);
        Assert.Equal((ulong)Timestamp.ToUnixTimeMilliseconds(), envelope.Timestamp);
        Assert.Equal((uint)1, envelope.SourceDevice);
        Assert.True(envelope.HasProSig);
        Assert.Equal(ProtocolConstants.SignatureSize, envelope.ProSig.Length);
        Assert.Equal(0xee, envelope.Content[0]);
    }

    [Fact]
    public void OneToOneDecodeUnwrapsAndUnpadsContent()
    {
        var fake = new FakeSessionProtocolCrypto();
        var codec = new SessionProtocolCodec(fake, fake);
        var content = BuildContent("hello");
        var encoded = codec.EncodeForOneToOne(content, SenderSecret, Timestamp, RecipientSessionId);

        var decoded = codec.DecodeEnvelope(
            new DecodeEnvelopeKeys { DecryptKeys = new[] { (ReadOnlyMemory<byte>)SenderSecret } },
            encoded.Ciphertext.Span);

        Assert.Equal(content, decoded.ContentPlaintext.ToArray());
        Assert.Equal(FakeSessionProtocolCrypto.SenderEd25519PublicKey, decoded.SenderEd25519PublicKey.ToArray());
        Assert.Equal(FakeSessionProtocolCrypto.SenderX25519PublicKey, decoded.SenderX25519PublicKey.ToArray());
        Assert.Null(decoded.Pro);
    }

    [Fact]
    public void CommunityContentRoundTripsWithoutCryptoAdapter()
    {
        var codec = new SessionProtocolCodec();
        var content = BuildContent("community");

        var encoded = codec.EncodeForCommunity(content);
        var decoded = codec.DecodeForCommunity(encoded.Ciphertext.Span, Timestamp);

        Assert.Null(decoded.Envelope);
        Assert.Equal(content, decoded.ContentPlaintext.ToArray());
        Assert.Null(decoded.Pro);
    }

    [Fact]
    public void CommunityEnvelopeDecodePrefersEnvelopeWhenRequiredFieldsExist()
    {
        var codec = new SessionProtocolCodec();
        var content = BuildContent("community");
        var envelope = new SessionProtos.Envelope
        {
            Type = SessionProtos.Envelope.Types.Type.SessionMessage,
            Timestamp = (ulong)Timestamp.ToUnixTimeMilliseconds(),
            Content = ByteString.CopyFrom(SessionProtocolCodec.PadMessage(content))
        };

        var decoded = codec.DecodeForCommunity(envelope.ToByteArray(), Timestamp);

        Assert.NotNull(decoded.Envelope);
        Assert.Equal(content, decoded.ContentPlaintext.ToArray());
    }

    [Fact]
    public void GroupEncodeAndDecodeRoundTripWithSodiumCrypto()
    {
        var codec = new SessionProtocolCodec();
        var sender = new SodiumSessionProtocolCrypto().GenerateEd25519SecretKey();
        var group = new SodiumSessionProtocolCrypto().GenerateEd25519SecretKey();
        var groupPublic = Sodium.PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(group);
        var groupSessionId = new byte[ProtocolConstants.SessionIdSize];
        groupSessionId[0] = (byte)SessionIdPrefix.Group;
        groupPublic.CopyTo(groupSessionId.AsSpan(1));
        var payload = BuildContent("group-message");

        var encoded = codec.EncodeForDestination(
            payload,
            sender,
            new Destination
            {
                Type = DestinationType.Group,
                SentTimestamp = Timestamp,
                GroupEd25519PublicKey = groupSessionId,
                GroupEncryptionKey = new byte[ProtocolConstants.X25519PublicKeySize]
            });

        var decoded = codec.DecodeEnvelope(
            new DecodeEnvelopeKeys
            {
                GroupEd25519PublicKey = groupPublic,
                DecryptKeys = new[] { (ReadOnlyMemory<byte>)group }
            },
            encoded.Ciphertext.Span);

        var content = SessionProtos.Content.Parser.ParseFrom(decoded.ContentPlaintext.ToArray());

        Assert.Equal(Timestamp, decoded.Envelope.Timestamp);
        Assert.Equal("group-message", content.DataMessage.Body);
        Assert.Equal(Sodium.PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(sender), decoded.SenderX25519PublicKey.ToArray());
        Assert.True(decoded.SenderEd25519PublicKey.IsEmpty);
    }

    [Fact]
    public void OneToOneEncodeAndDecodeRoundTripWithSodiumCrypto()
    {
        var codec = new SessionProtocolCodec();
        var crypto = new SodiumSessionProtocolCrypto();
        var sender = crypto.GenerateEd25519SecretKey();
        var recipient = crypto.GenerateEd25519SecretKey();
        var recipientX25519 = Sodium.PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(
            Sodium.PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(recipient));

        var recipientSessionId = new byte[ProtocolConstants.SessionIdSize];
        recipientSessionId[0] = (byte)SessionIdPrefix.Standard;
        recipientX25519.CopyTo(recipientSessionId.AsSpan(1));

        var payload = BuildContent("1o1-sodium");
        var encoded = codec.EncodeForOneToOne(payload, sender, Timestamp, recipientSessionId);

        var decoded = codec.DecodeEnvelope(
            new DecodeEnvelopeKeys
            {
                DecryptKeys = new[] { (ReadOnlyMemory<byte>)recipient }
            },
            encoded.Ciphertext.Span);

        var content = SessionProtos.Content.Parser.ParseFrom(decoded.ContentPlaintext.ToArray());
        Assert.Equal("1o1-sodium", content.DataMessage.Body);
    }

    [Fact]
    public void ProFeatureClassificationMatchesSessionLimits()
    {
        var standard = SessionProtocolCodec.GetProFeaturesForUtf8(Encoding.UTF8.GetBytes(new string('a', ProtocolConstants.ProStandardCharacterLimit)));
        var high = SessionProtocolCodec.GetProFeaturesForUtf8(Encoding.UTF8.GetBytes(new string('a', ProtocolConstants.ProStandardCharacterLimit + 1)));
        var tooHigh = SessionProtocolCodec.GetProFeaturesForUtf8(Encoding.UTF8.GetBytes(new string('a', ProtocolConstants.ProHigherCharacterLimit + 1)));
        var invalid = SessionProtocolCodec.GetProFeaturesForUtf8(new byte[] { 0xff });

        Assert.Equal(ProFeaturesForMessageStatus.Success, standard.Status);
        Assert.False(standard.Bitset.IsSet(ProMessageFeature.TenThousandCharacterLimit));
        Assert.True(high.Bitset.IsSet(ProMessageFeature.TenThousandCharacterLimit));
        Assert.Equal(ProFeaturesForMessageStatus.ExceedsCharacterLimit, tooHigh.Status);
        Assert.Equal(ProFeaturesForMessageStatus.UtfDecodingError, invalid.Status);
    }

    private static byte[] BuildContent(string body) =>
        new SessionProtos.Content
        {
            SigTimestamp = (ulong)Timestamp.ToUnixTimeMilliseconds(),
            DataMessage = new SessionProtos.DataMessage
            {
                Body = body
            }
        }.ToByteArray();
}
