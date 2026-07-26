using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxAuthenticatedRequestTranscript
{
    private static ReadOnlySpan<byte> StoreTag => "DEEP-MBND-STR-V2"u8;
    private static ReadOnlySpan<byte> RetrieveTag => "DEEP-MBND-GET-V2"u8;
    private static ReadOnlySpan<byte> AckTag => "DEEP-MBND-ACK-V2"u8;

    public static MailboxAuthenticatedRequestBinding ParseCanonical(
        MailboxAuthenticatedOperation operation,
        ReadOnlySpan<byte> canonical)
    {
        try
        {
            return operation switch
            {
                MailboxAuthenticatedOperation.Store => ForStore(ParseEnvelope(canonical)),
                MailboxAuthenticatedOperation.Retrieve => ParseRetrieve(canonical),
                MailboxAuthenticatedOperation.Ack => ParseAck(canonical),
                _ => throw Error("Authenticated request operation is unsupported.")
            };
        }
        catch (MailboxClientException exception)
        {
            throw new MailboxAuthenticatedCapabilityException(
                MailboxAuthenticatedCapabilityError.InvalidField,
                $"Canonical authenticated request is invalid: {exception.Error}.");
        }
        catch (ArgumentException exception)
        {
            throw new MailboxAuthenticatedCapabilityException(
                MailboxAuthenticatedCapabilityError.InvalidField,
                $"Canonical authenticated request field is invalid: {exception.ParamName}.");
        }
    }

    public static MailboxAuthenticatedRequestBinding ForStore(MailboxEncryptedEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var canonical = MailboxClientCodec.EncodeEncryptedEnvelope(envelope);
        return Create(
            MailboxAuthenticatedOperation.Store,
            envelope.OperationId.Span,
            StoreTag,
            canonical);
    }

    public static MailboxAuthenticatedRequestBinding ForRetrieve(
        ulong epoch,
        ReadOnlySpan<byte> operationId,
        BlindedMailboxId mailboxId,
        BlindedPlacementId placementId,
        ulong afterCursor,
        ushort maximumItems,
        ReadOnlySpan<byte> continuationToken)
    {
        ArgumentNullException.ThrowIfNull(mailboxId);
        ArgumentNullException.ThrowIfNull(placementId);
        ValidateCommon(epoch, operationId, continuationToken);
        if (maximumItems is 0 or > MailboxClientLimits.MaximumPageItems)
            throw Error("Retrieve maximum-items is outside strict bounds.");
        var canonical = new byte[112 + continuationToken.Length];
        "MBR2"u8.CopyTo(canonical);
        canonical[4] = 2;
        BinaryPrimitives.WriteUInt64BigEndian(canonical.AsSpan(8), epoch);
        operationId.CopyTo(canonical.AsSpan(16));
        mailboxId.Bytes.Span.CopyTo(canonical.AsSpan(32));
        placementId.Bytes.Span.CopyTo(canonical.AsSpan(64));
        BinaryPrimitives.WriteUInt64BigEndian(canonical.AsSpan(96), afterCursor);
        BinaryPrimitives.WriteUInt16BigEndian(canonical.AsSpan(104), maximumItems);
        BinaryPrimitives.WriteUInt16BigEndian(
            canonical.AsSpan(106),
            checked((ushort)continuationToken.Length));
        continuationToken.CopyTo(canonical.AsSpan(112));
        return Create(
            MailboxAuthenticatedOperation.Retrieve,
            operationId,
            RetrieveTag,
            canonical);
    }

    public static MailboxAuthenticatedRequestBinding ForAck(
        ulong epoch,
        ReadOnlySpan<byte> operationId,
        BlindedMailboxId mailboxId,
        BlindedPlacementId placementId,
        bool isFinalPage,
        ReadOnlySpan<byte> continuationToken,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements)
    {
        ArgumentNullException.ThrowIfNull(mailboxId);
        ArgumentNullException.ThrowIfNull(placementId);
        ArgumentNullException.ThrowIfNull(acknowledgements);
        ValidateCommon(epoch, operationId, continuationToken);
        if (acknowledgements.Count is 0 or > MailboxClientLimits.MaximumPageItems)
            throw Error("ACK entry count is outside strict bounds.");
        if (isFinalPage != continuationToken.IsEmpty)
            throw Error("Final ACK must have no continuation token; non-final ACK must have one.");
        var canonical = new byte[112 + continuationToken.Length + acknowledgements.Count * 40];
        "MBA2"u8.CopyTo(canonical);
        canonical[4] = 2;
        BinaryPrimitives.WriteUInt64BigEndian(canonical.AsSpan(8), epoch);
        operationId.CopyTo(canonical.AsSpan(16));
        mailboxId.Bytes.Span.CopyTo(canonical.AsSpan(32));
        placementId.Bytes.Span.CopyTo(canonical.AsSpan(64));
        canonical[96] = isFinalPage ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt16BigEndian(
            canonical.AsSpan(100),
            checked((ushort)acknowledgements.Count));
        BinaryPrimitives.WriteUInt16BigEndian(
            canonical.AsSpan(102),
            checked((ushort)continuationToken.Length));
        continuationToken.CopyTo(canonical.AsSpan(112));
        var offset = 112 + continuationToken.Length;
        ulong previousCursor = 0;
        foreach (var acknowledgement in acknowledgements)
        {
            ArgumentNullException.ThrowIfNull(acknowledgement);
            if (acknowledgement.Cursor <= previousCursor ||
                acknowledgement.EnvelopeDigest.Length != 32 ||
                acknowledgement.EnvelopeDigest.Span.IndexOfAnyExcept((byte)0) < 0)
                throw Error("ACK entries must be strictly ordered canonical cursor/digest pairs.");
            BinaryPrimitives.WriteUInt64BigEndian(canonical.AsSpan(offset), acknowledgement.Cursor);
            acknowledgement.EnvelopeDigest.Span.CopyTo(canonical.AsSpan(offset + 8));
            previousCursor = acknowledgement.Cursor;
            offset += 40;
        }
        return Create(MailboxAuthenticatedOperation.Ack, operationId, AckTag, canonical);
    }

    private static MailboxAuthenticatedRequestBinding Create(
        MailboxAuthenticatedOperation operation,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> canonical)
    {
        var framed = new byte[tag.Length + 4 + canonical.Length];
        tag.CopyTo(framed);
        BinaryPrimitives.WriteUInt32BigEndian(framed.AsSpan(tag.Length), checked((uint)canonical.Length));
        canonical.CopyTo(framed.AsSpan(tag.Length + 4));
        return new MailboxAuthenticatedRequestBinding(
            operation,
            operationId.ToArray(),
            SHA256.HashData(framed),
            canonical.ToArray());
    }

    private static MailboxAuthenticatedRequestBinding ParseRetrieve(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length < 112 ||
            !canonical[..4].SequenceEqual("MBR2"u8) ||
            canonical[4] != 2 ||
            canonical.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            canonical.Slice(108, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw Error("MBR2 header is invalid.");
        var tokenLength = BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(106, 2));
        if (canonical.Length != 112 + tokenLength)
            throw Error("MBR2 token length is invalid.");
        var binding = ForRetrieve(
            BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(8, 8)),
            canonical.Slice(16, 16),
            new BlindedMailboxId(canonical.Slice(32, 32)),
            new BlindedPlacementId(canonical.Slice(64, 32)),
            BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(96, 8)),
            BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(104, 2)),
            canonical[112..]);
        EnsureExact(binding, canonical);
        return binding;
    }

    private static MailboxAuthenticatedRequestBinding ParseAck(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length < 112 + 40 ||
            !canonical[..4].SequenceEqual("MBA2"u8) ||
            canonical[4] != 2 ||
            canonical.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            canonical[96] > 1 ||
            canonical.Slice(97, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            canonical.Slice(104, 8).IndexOfAnyExcept((byte)0) >= 0)
            throw Error("MBA2 header is invalid.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(100, 2));
        var tokenLength = BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(102, 2));
        if (count is 0 or > MailboxClientLimits.MaximumPageItems ||
            tokenLength > MailboxClientLimits.MaximumContinuationTokenLength ||
            canonical.Length != 112 + tokenLength + count * 40)
            throw Error("MBA2 nested lengths are invalid.");
        var acknowledgements = new MailboxAcknowledgement[count];
        var offset = 112 + tokenLength;
        for (var index = 0; index < count; index++)
        {
            acknowledgements[index] = new MailboxAcknowledgement
            {
                Cursor = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(offset, 8)),
                EnvelopeDigest = canonical.Slice(offset + 8, 32).ToArray()
            };
            offset += 40;
        }
        var binding = ForAck(
            BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(8, 8)),
            canonical.Slice(16, 16),
            new BlindedMailboxId(canonical.Slice(32, 32)),
            new BlindedPlacementId(canonical.Slice(64, 32)),
            canonical[96] == 1,
            canonical.Slice(112, tokenLength),
            acknowledgements);
        EnsureExact(binding, canonical);
        return binding;
    }

    private static MailboxEncryptedEnvelope ParseEnvelope(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length < MailboxClientLimits.EncryptedEnvelopeHeaderLength ||
            canonical.Length > MailboxClientLimits.MaximumEncryptedEnvelopeLength ||
            !canonical[..4].SequenceEqual("MEO1"u8) ||
            canonical[4] != 1 ||
            canonical.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            canonical.Slice(148, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw Error("MEO1 header is invalid.");
        var ciphertextLength = BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(144, 4));
        if (ciphertextLength is
                < MailboxClientLimits.MinimumCiphertextLength or
                > MailboxClientLimits.MaximumCiphertextLength ||
            canonical.Length != MailboxClientLimits.EncryptedEnvelopeHeaderLength + ciphertextLength)
            throw Error("MEO1 ciphertext length is invalid.");
        var envelope = new MailboxEncryptedEnvelope
        {
            Epoch = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(8, 8)),
            MailboxId = new BlindedMailboxId(canonical.Slice(16, 32)),
            PlacementId = new BlindedPlacementId(canonical.Slice(48, 32)),
            OperationId = canonical.Slice(80, 16).ToArray(),
            DeduplicationDigest = canonical.Slice(96, 32).ToArray(),
            CreatedAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(128, 8)),
            ExpiresAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(136, 8)),
            Ciphertext = canonical[152..].ToArray()
        };
        if (!MailboxClientCodec.EncodeEncryptedEnvelope(envelope).AsSpan().SequenceEqual(canonical))
            throw Error("MEO1 is not canonical.");
        return envelope;
    }

    private static void EnsureExact(
        MailboxAuthenticatedRequestBinding binding,
        ReadOnlySpan<byte> canonical)
    {
        if (!binding.CanonicalRequest.Span.SequenceEqual(canonical))
            throw Error("Authenticated request transcript is not canonical.");
    }

    private static void ValidateCommon(
        ulong epoch,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> continuationToken)
    {
        if (epoch == 0 ||
            operationId.Length != 16 ||
            operationId.IndexOfAnyExcept((byte)0) < 0 ||
            continuationToken.Length > MailboxClientLimits.MaximumContinuationTokenLength)
            throw Error("Authenticated request transcript fields are outside strict bounds.");
    }

    private static MailboxAuthenticatedCapabilityException Error(string message) =>
        new(MailboxAuthenticatedCapabilityError.InvalidField, message);
}
