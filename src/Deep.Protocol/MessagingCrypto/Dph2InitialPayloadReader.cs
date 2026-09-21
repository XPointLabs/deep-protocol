using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.MessagingCrypto;

internal static class Dph2InitialPayloadReader
{
    internal static (Xpk1Request Request, Xpc1Result Result) PreviewClaimTranscript(
        Dph2PreClaimHeader header,
        SecretBuffer initialAeadKey)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(initialAeadKey);
        var record = header.Record;
        byte[]? ciphertext = null;
        byte[]? key = null;
        byte[]? nonce = null;
        byte[]? aad = null;
        byte[]? plaintext = null;
        try
        {
            ciphertext = new byte[record.InitialCiphertext.Length];
            record.InitialCiphertext.CopyCiphertextTo(ciphertext);
            initialAeadKey.Use(secret => key = secret.ToArray());
            nonce = record.InitialPayloadNonce.ToArray();
            aad = MessagingWireCryptographicInputs.GetDph2InitialAeadAssociatedData(
                header.Offering.Record, record);
            plaintext = SecretAeadXChaCha20Poly1305.Decrypt(
                ciphertext, nonce, key!, aad);
            if (plaintext.Length is not (4096 or 16384 or 32768))
                throw new CryptographicException("The pre-claim DPH2 payload has an invalid bucket.");
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(plaintext.AsSpan()[^4..]));
            if (length is < 1 or > 32764 || length > plaintext.Length - 4)
                throw new CryptographicException("The pre-claim DPH2 payload length is invalid.");
            var parsed = Dph2InitialClaimTranscriptCodec.DecodePrefix(
                plaintext.AsSpan(0, length), record);
            return (parsed.Request, parsed.Result);
        }
        finally
        {
            Zero(ciphertext); Zero(key); Zero(nonce); Zero(aad); Zero(plaintext);
        }
    }

    internal static (byte[] SessionInit, byte[]? FirstApplication) Open(
        VerifiedDph2Initiation initiation,
        HybridHandshakeSecrets handshake)
    {
        var record = initiation.Record;
        byte[]? ciphertext = null;
        byte[]? key = null;
        byte[]? nonce = null;
        byte[]? aad = null;
        byte[]? plaintext = null;
        try
        {
            ciphertext = new byte[record.InitialCiphertext.Length];
            record.InitialCiphertext.CopyCiphertextTo(ciphertext);
            handshake.UseInitialAeadKey(secret => key = secret.ToArray());
            nonce = record.InitialPayloadNonce.ToArray();
            aad = MessagingWireCryptographicInputs.GetDph2InitialAeadAssociatedData(
                initiation.Offering.Record, record);
            plaintext = SecretAeadXChaCha20Poly1305.Decrypt(ciphertext, nonce, key!, aad);
            return Parse(plaintext, initiation);
        }
        finally
        {
            Zero(ciphertext); Zero(key); Zero(nonce); Zero(aad); Zero(plaintext);
        }
    }

    private static (byte[] SessionInit, byte[]? FirstApplication) Parse(
        ReadOnlySpan<byte> padded,
        VerifiedDph2Initiation initiation)
    {
        if (padded.Length is not (4096 or 16384 or 32768))
            throw new CryptographicException("The authenticated DPH2 payload has an invalid bucket.");
        var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(padded[^4..]));
        if (length is < 1 or > 32764 || length > padded.Length - 4)
            throw new CryptographicException("The authenticated DPH2 payload length is invalid.");
        var body = padded[..length];
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
        // Pre-cutover recovery fixtures use synthetic claims without an exact
        // signed XPC1 result. Only the test assembly recognizes that body.
        var offset = body[0] is 1 or 2
            ? 0
            : Dph2InitialClaimTranscriptCodec.DecodePrefix(body, initiation.Record).Consumed;
#else
        var offset = Dph2InitialClaimTranscriptCodec.DecodePrefix(body, initiation.Record).Consumed;
#endif
        var count = body[offset];
        if (count is not (1 or 2))
            throw new CryptographicException("The authenticated DPH2 event count is invalid.");
        offset++;
        var session = ReadEvent(body, ref offset);
        ValidateSession(session, initiation);
        ParsedDmc2? first = null;
        if (count == 2)
        {
            first = ReadEvent(body, ref offset);
            ValidateFirst(first, session);
        }
        if (offset != body.Length)
            throw new CryptographicException("The authenticated DPH2 payload has trailing event bytes.");
        return (session.CanonicalBytes.ToArray(), first?.CanonicalBytes.ToArray());
    }

    private static ParsedDmc2 ReadEvent(ReadOnlySpan<byte> body, ref int offset)
    {
        if (body.Length - offset < 4)
            throw new CryptographicException("The authenticated DPH2 LP32 event is truncated.");
        var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(body.Slice(offset, 4)));
        offset += 4;
        if (length is < 282 or > 33082 || body.Length - offset < length)
            throw new CryptographicException("The authenticated DPH2 event length is invalid.");
        var exact = body.Slice(offset, length);
        var parsed = ApplicationCoreCodec.DecodeDmc2(exact);
        if (!exact.SequenceEqual(parsed.CanonicalBytes.Span))
            throw new CryptographicException("The authenticated DPH2 event is noncanonical.");
        offset += length;
        return parsed;
    }

    private static void ValidateSession(ParsedDmc2 session, VerifiedDph2Initiation initiation)
    {
        var record = initiation.Record;
        if (session.ParsedPayload is not SessionInitDmc2Payload init ||
            !Fixed(session.NetworkId.Span, record.NetworkIdSpan) ||
            !Fixed(session.SenderAccountId.Span, record.InitiatorAccountIdSpan) ||
            !Fixed(session.SenderDeviceId.Span, record.InitiatorDeviceIdSpan) ||
            !Fixed(init.SenderDmd1Hash.Span, initiation.InitiatorDeviceDirectoryHeadHashSpan) ||
            !Fixed(init.SenderDirectory.NetworkId.Span, record.NetworkIdSpan) ||
            !Fixed(init.SenderDirectory.DeepAccountId.Span, record.InitiatorAccountIdSpan) ||
            !Fixed(init.SenderDirectory.RecordHash.Span, initiation.InitiatorDeviceDirectoryHeadHashSpan))
            throw new CryptographicException("The DPH2 SessionInit is outside the verified initiator scope.");
        var entry = init.SenderDirectory.ActiveDevices.SingleOrDefault(device =>
            Fixed(device.DeviceId.Span, record.InitiatorDeviceIdSpan));
        if (entry is null ||
            entry.Dpd1Reference.TypeCode != (ushort)Deep.Protocol.DeepNative.ArtifactType.Dpd1 ||
            !Fixed(entry.Dpd1Reference.CanonicalHash.Span, record.InitiatorDpd1RefSpan[6..]))
            throw new CryptographicException("The DPH2 SessionInit does not bind the verified initiator device.");
    }

    private static void ValidateFirst(ParsedDmc2 first, ParsedDmc2 session)
    {
        if (first.ContentKind == Dmc2ContentKind.SessionInit ||
            !Fixed(first.NetworkId.Span, session.NetworkId.Span) ||
            !Fixed(first.SenderAccountId.Span, session.SenderAccountId.Span) ||
            !Fixed(first.SenderDeviceId.Span, session.SenderDeviceId.Span) ||
            !Fixed(first.ConversationId.Span, session.ConversationId.Span) ||
            Fixed(first.LogicalMessageId.Span, session.LogicalMessageId.Span) ||
            first.SenderClientSequence <= session.SenderClientSequence ||
            first.CreatedAtUnixMilliseconds < session.CreatedAtUnixMilliseconds)
            throw new CryptographicException("The first DPH2 event is outside the initial conversation stream.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}
