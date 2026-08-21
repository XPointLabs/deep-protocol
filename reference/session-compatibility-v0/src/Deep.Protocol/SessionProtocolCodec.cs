using System.Text;
using Google.Protobuf;
using Deep.Protocol.Abstractions;
using Deep.Protocol.Abstractions.Crypto;
using Deep.Protocol.Internal;

namespace Deep.Protocol;

public sealed class SessionProtocolCodec
{
    private const byte PaddingTerminatingByte = 0x80;

    private readonly ISessionProtocolCrypto crypto;
    private readonly ProProofService proProofs;

    public SessionProtocolCodec(
        ISessionProtocolCrypto? crypto = null,
        IProtocolHashing? hashing = null)
    {
        var resolvedCrypto = crypto ?? hashing as ISessionProtocolCrypto ?? new SodiumSessionProtocolCrypto();
        this.crypto = resolvedCrypto;
        proProofs = new ProProofService(
            hashing ?? resolvedCrypto as IProtocolHashing ?? new SodiumSessionProtocolCrypto(),
            resolvedCrypto);
    }

    public static byte[] PadMessage(ReadOnlySpan<byte> payload)
    {
        var paddedContentSize = payload.Length + 1;
        var bytesForPadding = ProtocolConstants.CommunityOrOneToOneMessagePadding -
            (paddedContentSize % ProtocolConstants.CommunityOrOneToOneMessagePadding);
        paddedContentSize += bytesForPadding;

        var result = new byte[paddedContentSize];
        payload.CopyTo(result);
        result[payload.Length] = PaddingTerminatingByte;
        return result;
    }

    public static ReadOnlyMemory<byte> UnpadMessage(ReadOnlyMemory<byte> payload)
    {
        var span = payload.Span;
        var sizeWithoutPadding = span.Length;
        while (sizeWithoutPadding > 0)
        {
            var ch = span[sizeWithoutPadding - 1];
            if (ch != 0 && ch != PaddingTerminatingByte)
            {
                break;
            }

            sizeWithoutPadding--;
            if (ch == PaddingTerminatingByte)
            {
                break;
            }
        }

        return payload[..sizeWithoutPadding];
    }

    public static ProFeaturesForMessage GetProFeaturesForUtf8(ReadOnlySpan<byte> utf8)
    {
        string text;
        try
        {
            text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                .GetString(utf8);
        }
        catch (DecoderFallbackException ex)
        {
            return new ProFeaturesForMessage(
                ProFeaturesForMessageStatus.UtfDecodingError,
                ex.Message,
                new ProMessageBitset(0),
                0);
        }

        return ClassifyUnicodeMessage(text);
    }

    public static ProFeaturesForMessage GetProFeaturesForUtf16(ReadOnlySpan<char> utf16)
    {
        if (!IsWellFormedUtf16(utf16, out var codepointCount))
        {
            return new ProFeaturesForMessage(
                ProFeaturesForMessageStatus.UtfDecodingError,
                "Invalid UTF-16 sequence.",
                new ProMessageBitset(0),
                0);
        }

        return ClassifyCodepointCount(codepointCount);
    }

    public EncodedForDestination EncodeForOneToOne(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> ed25519PrivateKey,
        DateTimeOffset sentTimestamp,
        ReadOnlySpan<byte> recipientPublicKey,
        ReadOnlySpan<byte> proRotatingEd25519PrivateKey = default) =>
        EncodeForDestination(
            plaintext,
            ed25519PrivateKey,
            new Destination
            {
                Type = DestinationType.SyncOrOneToOne,
                SentTimestamp = sentTimestamp,
                RecipientPublicKey = recipientPublicKey.ToArray(),
                ProRotatingEd25519PrivateKey = proRotatingEd25519PrivateKey.ToArray()
            });

    public EncodedForDestination EncodeForCommunity(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> proRotatingEd25519PrivateKey = default) =>
        EncodeForDestination(
            plaintext,
            default,
            new Destination
            {
                Type = DestinationType.Community,
                ProRotatingEd25519PrivateKey = proRotatingEd25519PrivateKey.ToArray()
            });

    public EncodedForDestination EncodeForDestination(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> ed25519PrivateKey,
        Destination destination)
    {
        var proKey = NormalizeOptionalProKey(destination.ProRotatingEd25519PrivateKey.Span);
        var content = plaintext.ToArray();

        return destination.Type switch
        {
            DestinationType.SyncOrOneToOne => new EncodedForDestination(
                EncodeOneToOne(content, ed25519PrivateKey, destination, proKey)),
            DestinationType.Group => new EncodedForDestination(
                EncodeGroup(content, ed25519PrivateKey, destination, proKey)),
            DestinationType.Community => new EncodedForDestination(
                EncodeCommunity(content, proKey)),
            DestinationType.CommunityInbox => new EncodedForDestination(
                EncodeCommunityInbox(content, ed25519PrivateKey, destination, proKey)),
            _ => throw new ArgumentOutOfRangeException(nameof(destination.Type))
        };
    }

    public DecodedEnvelope DecodeEnvelope(
        DecodeEnvelopeKeys keys,
        ReadOnlySpan<byte> envelopePayload,
        ReadOnlySpan<byte> proBackendPublicKey = default)
    {
        ArgumentNullException.ThrowIfNull(keys);

        byte[] envelopePlaintext;
        byte[] senderX25519PublicKey = new byte[ProtocolConstants.X25519PublicKeySize];
        byte[] senderEd25519PublicKey = Array.Empty<byte>();

        if (keys.GroupEd25519PublicKey is { } groupKey)
        {
            var decrypt = crypto.DecryptGroupMessage(
                keys.DecryptKeys,
                groupKey.Span,
                envelopePayload);
            var senderId = SessionId.ParseHex(decrypt.SenderSessionIdHex);
            if (senderId.Prefix != SessionIdPrefix.Standard)
            {
                throw new InvalidOperationException("Group envelope sender id must use the 0x05 Session prefix.");
            }

            senderX25519PublicKey = senderId.PublicKey.ToArray();
            envelopePlaintext = decrypt.Plaintext.ToArray();
        }
        else
        {
            var websocket = WebSocketProtos.WebSocketMessage.Parser.ParseFrom(envelopePayload);
            if (websocket.Request is null || !websocket.Request.HasBody)
            {
                throw new InvalidOperationException("Parse websocket wrapped envelope failed, missing request body.");
            }

            envelopePlaintext = websocket.Request.Body.ToByteArray();
        }

        var envelope = SessionProtos.Envelope.Parser.ParseFrom(envelopePlaintext);
        var parsedEnvelope = ParseEnvelopeMetadata(envelope, sourceIsHex: true);

        if (!envelope.HasContent)
        {
            throw new InvalidOperationException("Parse decrypted message failed, missing content.");
        }

        byte[] contentPlaintext;
        if (keys.GroupEd25519PublicKey is not null)
        {
            contentPlaintext = envelope.Content.ToByteArray();
        }
        else
        {
            var decrypted = TryDecryptIncoming(keys.DecryptKeys, envelope.Content.ToByteArray());
            contentPlaintext = UnpadMessage(decrypted.Plaintext).ToArray();
            senderEd25519PublicKey = decrypted.SenderEd25519PublicKey.ToArray();
            senderX25519PublicKey = crypto.ConvertEd25519PublicKeyToX25519(senderEd25519PublicKey);
        }

        var content = SessionProtos.Content.Parser.ParseFrom(contentPlaintext);
        DecodedPro? pro = null;
        if (envelope.HasProSig)
        {
            var proSig = envelope.ProSig.ToByteArray();
            if (proSig.Length != ProtocolConstants.SignatureSize)
            {
                throw new InvalidOperationException("Parse envelope failed, pro signature has wrong size.");
            }

            parsedEnvelope = parsedEnvelope with { ProSignature = proSig };
            if (content.ProMessage is not null)
            {
                if (!content.HasSigTimestamp || content.SigTimestamp == 0)
                {
                    throw new InvalidOperationException(
                        "Content does not have signature timestamp set, pro proof expiry is unverifiable.");
                }

                parsedEnvelope = parsedEnvelope with { Flags = parsedEnvelope.Flags | EnvelopeFlags.ProSignature };
                pro = DecodePro(
                    content.ProMessage,
                    proBackendPublicKey,
                    DateTimeOffset.FromUnixTimeMilliseconds((long)content.SigTimestamp),
                    new ProSignedMessage(proSig, envelope.Content.ToByteArray()),
                    "Parse decrypted message failed");
            }
        }

        return new DecodedEnvelope
        {
            Envelope = parsedEnvelope,
            ContentPlaintext = contentPlaintext,
            SenderEd25519PublicKey = senderEd25519PublicKey,
            SenderX25519PublicKey = senderX25519PublicKey,
            Pro = pro
        };
    }

    public DecodedCommunityMessage DecodeForCommunity(
        ReadOnlySpan<byte> contentOrEnvelopePayload,
        DateTimeOffset unixTimestamp,
        ReadOnlySpan<byte> proBackendPublicKey = default)
    {
        ProtocolEnvelope? envelope = null;
        byte[] contentPlaintext;
        byte[]? proSignature = null;

        if (TryParseCommunityEnvelope(contentOrEnvelopePayload, out var pbEnvelope))
        {
            envelope = ParseEnvelopeMetadata(pbEnvelope, sourceIsHex: false);
            contentPlaintext = pbEnvelope.Content.ToByteArray();
            if (pbEnvelope.HasProSig)
            {
                proSignature = pbEnvelope.ProSig.ToByteArray();
                envelope = envelope with
                {
                    Flags = envelope.Flags | EnvelopeFlags.ProSignature,
                    ProSignature = proSignature
                };
            }
        }
        else
        {
            contentPlaintext = contentOrEnvelopePayload.ToArray();
        }

        var unpaddedContent = UnpadMessage(contentPlaintext).ToArray();
        var content = SessionProtos.Content.Parser.ParseFrom(unpaddedContent);

        if (content.HasProSigForCommunityMessageOnly)
        {
            if (proSignature is not null)
            {
                throw new InvalidOperationException(
                    "Decoding community message failed, envelope and content both had a pro signature specified.");
            }

            proSignature = content.ProSigForCommunityMessageOnly.ToByteArray();
        }

        if (proSignature is { Length: not ProtocolConstants.SignatureSize })
        {
            throw new InvalidOperationException("Decoding community message failed, pro signature has wrong size.");
        }

        DecodedPro? pro = null;
        if (proSignature is not null && content.ProMessage is not null)
        {
            ReadOnlyMemory<byte> signedMessage;
            if (envelope is not null)
            {
                signedMessage = contentPlaintext;
            }
            else
            {
                var unsignedContent = content.Clone();
                unsignedContent.ClearProSigForCommunityMessageOnly();
                signedMessage = PadMessage(unsignedContent.ToByteArray());
            }

            pro = DecodePro(
                content.ProMessage,
                proBackendPublicKey,
                unixTimestamp,
                new ProSignedMessage(proSignature, signedMessage),
                "Decoding community message failed");
        }

        return new DecodedCommunityMessage
        {
            Envelope = envelope,
            ContentPlaintext = unpaddedContent,
            ProSignature = proSignature,
            Pro = pro
        };
    }

    public byte[] ComputeProProofHash(ProProof proof) => proProofs.ComputeHash(proof);

    public ProStatus GetProProofStatus(
        ProProof proof,
        ReadOnlySpan<byte> proBackendPublicKey,
        DateTimeOffset unixTimestamp,
        ProSignedMessage? signedMessage = null) =>
        proProofs.GetStatus(proof, proBackendPublicKey, unixTimestamp, signedMessage);

    private byte[] EncodeOneToOne(
        byte[] plaintext,
        ReadOnlySpan<byte> ed25519PrivateKey,
        Destination destination,
        byte[] proKey)
    {
        var recipientSessionId = ByteHelpers.RequireSize(
            destination.RecipientPublicKey,
            ProtocolConstants.SessionIdSize,
            nameof(destination.RecipientPublicKey));
        if (recipientSessionId[0] != (byte)SessionIdPrefix.Standard)
        {
            throw new NotSupportedException("Unsupported recipient session id prefix for one-to-one destination.");
        }

        var padded = PadMessage(plaintext);
        var encryptedContent = crypto.EncryptForRecipient(
            ed25519PrivateKey,
            recipientSessionId.AsSpan(1),
            padded);

        var envelope = BuildEnvelope(
            SessionProtos.Envelope.Types.Type.SessionMessage,
            destination.SentTimestamp,
            encryptedContent,
            SignOrDummy(encryptedContent, proKey));

        var websocket = new WebSocketProtos.WebSocketMessage
        {
            Type = WebSocketProtos.WebSocketMessage.Types.Type.Request,
            Request = new WebSocketProtos.WebSocketRequestMessage
            {
                Verb = string.Empty,
                Path = string.Empty,
                RequestId = 0,
                Body = ByteString.CopyFrom(envelope.ToByteArray())
            }
        };

        return websocket.ToByteArray();
    }

    private byte[] EncodeGroup(
        byte[] plaintext,
        ReadOnlySpan<byte> ed25519PrivateKey,
        Destination destination,
        byte[] proKey)
    {
        var groupSessionId = ByteHelpers.RequireSize(
            destination.GroupEd25519PublicKey,
            ProtocolConstants.SessionIdSize,
            nameof(destination.GroupEd25519PublicKey));
        if (groupSessionId[0] != (byte)SessionIdPrefix.Group)
        {
            throw new NotSupportedException(
                "Unsupported configuration: encrypting for a legacy group (0x05 prefix) is not supported.");
        }

        var envelope = BuildEnvelope(
            SessionProtos.Envelope.Types.Type.ClosedGroupMessage,
            destination.SentTimestamp,
            plaintext,
            SignOrDummy(plaintext, proKey));

        return crypto.EncryptForGroup(
            ed25519PrivateKey,
            groupSessionId.AsSpan(1),
            destination.GroupEncryptionKey.Span,
            envelope.ToByteArray(),
            compress: true,
            padding: 256);
    }

    private byte[] EncodeCommunity(byte[] plaintext, byte[] proKey)
    {
        if (proKey.Length == 0)
        {
            return PadMessage(plaintext);
        }

        var content = SessionProtos.Content.Parser.ParseFrom(plaintext);
        if (content.HasProSigForCommunityMessageOnly)
        {
            throw new InvalidOperationException(
                "Pro signature for community message must not be set before encoding.");
        }

        var paddedContent = PadMessage(plaintext);
        var proSig = crypto.SignEd25519Detached(paddedContent, proKey);
        content.ProSigForCommunityMessageOnly = ByteString.CopyFrom(proSig);
        return PadMessage(content.ToByteArray());
    }

    private byte[] EncodeCommunityInbox(
        byte[] plaintext,
        ReadOnlySpan<byte> ed25519PrivateKey,
        Destination destination,
        byte[] proKey)
    {
        var communityPayload = EncodeCommunity(plaintext, proKey);
        return crypto.EncryptForBlindedRecipient(
            ed25519PrivateKey,
            destination.CommunityInboxServerPublicKey.Span,
            destination.RecipientPublicKey.Span,
            communityPayload);
    }

    private SessionProtos.Envelope BuildEnvelope(
        SessionProtos.Envelope.Types.Type type,
        DateTimeOffset timestamp,
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> proSignature) =>
        new()
        {
            Type = type,
            SourceDevice = 1,
            Timestamp = (ulong)timestamp.ToUnixTimeMilliseconds(),
            Content = ByteString.CopyFrom(content),
            ProSig = ByteString.CopyFrom(ByteHelpers.RequireSize(proSignature, ProtocolConstants.SignatureSize, nameof(proSignature)))
        };

    private byte[] NormalizeOptionalProKey(ReadOnlySpan<byte> proKey)
    {
        if (proKey.Length == 0)
        {
            return Array.Empty<byte>();
        }

        if (proKey.Length != ProtocolConstants.Ed25519SeedSize &&
            proKey.Length != ProtocolConstants.Ed25519SecretKeySize)
        {
            throw new ArgumentException(
                "Pro rotating Ed25519 private key must be 32-byte seed or 64-byte secret key.",
                nameof(proKey));
        }

        return crypto.NormalizeEd25519SecretKey(proKey);
    }

    private byte[] SignOrDummy(ReadOnlySpan<byte> message, ReadOnlySpan<byte> proKey)
    {
        var signingKey = proKey.Length == 0 ? crypto.GenerateEd25519SecretKey() : proKey.ToArray();
        return crypto.SignEd25519Detached(message, signingKey);
    }

    private RecipientDecryptionResult TryDecryptIncoming(
        IReadOnlyList<ReadOnlyMemory<byte>> keys,
        byte[] content)
    {
        foreach (var key in keys)
        {
            try
            {
                return crypto.DecryptIncoming(key.Span, content);
            }
            catch
            {
            }
        }

        throw new InvalidOperationException($"Envelope content decryption failed, tried {keys.Count} key(s).");
    }

    private static ProtocolEnvelope ParseEnvelopeMetadata(SessionProtos.Envelope envelope, bool sourceIsHex)
    {
        var flags = EnvelopeFlags.None;
        var timestamp = DateTimeOffset.UnixEpoch;
        ReadOnlyMemory<byte> source = ReadOnlyMemory<byte>.Empty;
        uint sourceDevice = 0;
        ulong serverTimestamp = 0;

        if (envelope.HasTimestamp)
        {
            timestamp = DateTimeOffset.FromUnixTimeMilliseconds((long)envelope.Timestamp);
            flags |= EnvelopeFlags.Timestamp;
        }

        if (envelope.HasSource)
        {
            if (envelope.Source.Length > 0)
            {
                source = sourceIsHex
                    ? ByteHelpers.HexToBytes(envelope.Source)
                    : ByteHelpers.Latin1Bytes(envelope.Source);

                if (source.Length != ProtocolConstants.SessionIdSize)
                {
                    throw new InvalidOperationException(
                        $"Parse envelope failed, source had unexpected size ({source.Length} bytes).");
                }

                flags |= EnvelopeFlags.Source;
            }
        }

        if (envelope.HasSourceDevice)
        {
            sourceDevice = envelope.SourceDevice;
            flags |= EnvelopeFlags.SourceDevice;
        }

        if (envelope.HasServerTimestamp)
        {
            serverTimestamp = envelope.ServerTimestamp;
            flags |= EnvelopeFlags.ServerTimestamp;
        }

        return new ProtocolEnvelope
        {
            Flags = flags,
            Timestamp = timestamp,
            Source = source,
            SourceDevice = sourceDevice,
            ServerTimestamp = serverTimestamp
        };
    }

    private DecodedPro DecodePro(
        SessionProtos.ProMessage proMessage,
        ReadOnlySpan<byte> proBackendPublicKey,
        DateTimeOffset unixTimestamp,
        ProSignedMessage signedMessage,
        string context)
    {
        if (proMessage.Proof is null)
        {
            throw new InvalidOperationException($"{context}, pro config missing proof.");
        }

        var proof = ParseProProof(proMessage.Proof, context);
        var status = proProofs.GetStatus(proof, proBackendPublicKey, unixTimestamp, signedMessage);
        return new DecodedPro
        {
            Status = status,
            Proof = proof,
            MessageBitset = new ProMessageBitset(proMessage.MsgBitset),
            ProfileBitset = new ProProfileBitset(proMessage.ProfileBitset)
        };
    }

    private static ProProof ParseProProof(SessionProtos.ProProof protoProof, string context)
    {
        var malformed =
            !protoProof.HasVersion ||
            protoProof.Version != 0 ||
            !protoProof.HasGenIndexHash ||
            protoProof.GenIndexHash.Length != ProtocolConstants.Ed25519PublicKeySize ||
            !protoProof.HasRotatingPublicKey ||
            protoProof.RotatingPublicKey.Length != ProtocolConstants.Ed25519PublicKeySize ||
            !protoProof.HasExpiryUnixTs ||
            !protoProof.HasSig ||
            protoProof.Sig.Length != ProtocolConstants.SignatureSize;

        if (malformed)
        {
            throw new InvalidOperationException($"{context}, pro metadata was malformed.");
        }

        return new ProProof
        {
            Version = (byte)protoProof.Version,
            GenerationIndexHash = protoProof.GenIndexHash.ToByteArray(),
            RotatingPublicKey = protoProof.RotatingPublicKey.ToByteArray(),
            ExpiryUnixTime = DateTimeOffset.FromUnixTimeMilliseconds((long)protoProof.ExpiryUnixTs),
            Signature = protoProof.Sig.ToByteArray()
        };
    }

    private static bool TryParseCommunityEnvelope(
        ReadOnlySpan<byte> payload,
        out SessionProtos.Envelope envelope)
    {
        try
        {
            envelope = SessionProtos.Envelope.Parser.ParseFrom(payload);
            return envelope.HasType && envelope.HasTimestamp && envelope.HasContent;
        }
        catch (InvalidProtocolBufferException)
        {
            envelope = new SessionProtos.Envelope();
            return false;
        }
    }

    private static ProFeaturesForMessage ClassifyUnicodeMessage(string text)
    {
        var codepointCount = text.EnumerateRunes().Count();
        return ClassifyCodepointCount(codepointCount);
    }

    private static ProFeaturesForMessage ClassifyCodepointCount(int codepointCount)
    {
        if (codepointCount > ProtocolConstants.ProStandardCharacterLimit)
        {
            if (codepointCount <= ProtocolConstants.ProHigherCharacterLimit)
            {
                return new ProFeaturesForMessage(
                    ProFeaturesForMessageStatus.Success,
                    null,
                    new ProMessageBitset(0).Set(ProMessageFeature.TenThousandCharacterLimit),
                    codepointCount);
            }

            return new ProFeaturesForMessage(
                ProFeaturesForMessageStatus.ExceedsCharacterLimit,
                "Message exceeds the maximum character limit allowed.",
                new ProMessageBitset(0),
                codepointCount);
        }

        return new ProFeaturesForMessage(
            ProFeaturesForMessageStatus.Success,
            null,
            new ProMessageBitset(0),
            codepointCount);
    }

    private static bool IsWellFormedUtf16(ReadOnlySpan<char> utf16, out int codepointCount)
    {
        codepointCount = 0;
        for (var i = 0; i < utf16.Length; i++)
        {
            var ch = utf16[i];
            if (char.IsHighSurrogate(ch))
            {
                if (i + 1 >= utf16.Length || !char.IsLowSurrogate(utf16[i + 1]))
                {
                    return false;
                }

                i++;
            }
            else if (char.IsLowSurrogate(ch))
            {
                return false;
            }

            codepointCount++;
        }

        return true;
    }
}
