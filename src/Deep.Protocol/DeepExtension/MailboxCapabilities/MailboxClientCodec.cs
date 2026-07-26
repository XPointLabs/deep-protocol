using System.Buffers.Binary;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxClientCodec
{
    private static ReadOnlySpan<byte> EnvelopeMagic => "MEO1"u8;
    private static ReadOnlySpan<byte> StoreMagic => "MST1"u8;
    private static ReadOnlySpan<byte> RetrieveMagic => "MRT1"u8;
    private static ReadOnlySpan<byte> PageMagic => "MRP1"u8;
    private static ReadOnlySpan<byte> AckMagic => "MAK1"u8;
    private const byte Version = 1;
    private const int StoreHeaderLength = 48;
    private const int RetrieveHeaderLength = 120;
    private const int PageHeaderLength = 48;
    private const int AckHeaderLength = 120;
    private const int AckEntryLength = 40;

    public static byte[] EncodeEncryptedEnvelope(MailboxEncryptedEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ValidateEnvelope(envelope, policy: null);
        var encoded = new byte[
            MailboxClientLimits.EncryptedEnvelopeHeaderLength + envelope.Ciphertext.Length];
        EnvelopeMagic.CopyTo(encoded);
        encoded[4] = Version;
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(8, 8), envelope.Epoch);
        envelope.MailboxId.Bytes.Span.CopyTo(
            encoded.AsSpan(16, MailboxClientLimits.BlindedIdentifierLength));
        envelope.PlacementId.Bytes.Span.CopyTo(
            encoded.AsSpan(48, MailboxClientLimits.BlindedIdentifierLength));
        envelope.OperationId.Span.CopyTo(
            encoded.AsSpan(80, MailboxClientLimits.OperationIdLength));
        envelope.DeduplicationDigest.Span.CopyTo(
            encoded.AsSpan(96, MailboxClientLimits.DigestLength));
        BinaryPrimitives.WriteUInt64BigEndian(
            encoded.AsSpan(128, 8),
            envelope.CreatedAtUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(
            encoded.AsSpan(136, 8),
            envelope.ExpiresAtUnixSeconds);
        BinaryPrimitives.WriteUInt32BigEndian(
            encoded.AsSpan(144, 4),
            checked((uint)envelope.Ciphertext.Length));
        envelope.Ciphertext.Span.CopyTo(
            encoded.AsSpan(MailboxClientLimits.EncryptedEnvelopeHeaderLength));
        return encoded;
    }

    public static MailboxEncryptedEnvelope DecodeEncryptedEnvelope(
        ReadOnlySpan<byte> encoded,
        MailboxClientDecodePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ValidateFrame(
            encoded,
            EnvelopeMagic,
            MailboxClientLimits.EncryptedEnvelopeHeaderLength,
            MailboxClientLimits.EncryptedEnvelopeHeaderLength +
            MailboxClientLimits.MaximumCiphertextLength);
        if (encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(148, 4).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw Error(MailboxClientError.ReservedFieldNotZero, "Reserved envelope fields must be zero.");
        }

        var ciphertextLength = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(144, 4));
        if (ciphertextLength is
                < MailboxClientLimits.MinimumCiphertextLength or
                > MailboxClientLimits.MaximumCiphertextLength ||
            encoded.Length != MailboxClientLimits.EncryptedEnvelopeHeaderLength + ciphertextLength)
        {
            throw Error(MailboxClientError.MalformedLength, "The encrypted envelope length is not canonical.");
        }

        ValidateBlindedIdentifier(encoded.Slice(16, MailboxClientLimits.BlindedIdentifierLength));
        ValidateBlindedIdentifier(encoded.Slice(48, MailboxClientLimits.BlindedIdentifierLength));
        var envelope = new MailboxEncryptedEnvelope
        {
            Epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8)),
            MailboxId = new BlindedMailboxId(
                encoded.Slice(16, MailboxClientLimits.BlindedIdentifierLength)),
            PlacementId = new BlindedPlacementId(
                encoded.Slice(48, MailboxClientLimits.BlindedIdentifierLength)),
            OperationId = encoded.Slice(80, MailboxClientLimits.OperationIdLength).ToArray(),
            DeduplicationDigest = encoded.Slice(96, MailboxClientLimits.DigestLength).ToArray(),
            CreatedAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(128, 8)),
            ExpiresAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(136, 8)),
            Ciphertext = encoded[MailboxClientLimits.EncryptedEnvelopeHeaderLength..].ToArray()
        };
        ValidateEnvelope(envelope, policy);
        return envelope;
    }

    public static byte[] EncodeStore(MailboxStoreRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateOperationId(request.OperationId.Span);
        ValidateMixedVersion(request.MixedVersion);
        EnsureDomain(request.DepositCapability, MailboxCapabilityDomain.Deposit);
        var capability = MailboxCapabilityCodec.Encode(request.DepositCapability);
        var envelope = EncodeEncryptedEnvelope(request.Envelope);
        if (request.Epoch != request.DepositCapability.Generation ||
            request.Epoch != request.Envelope.Epoch ||
            request.MixedVersion != request.DepositCapability.MixedVersion ||
            !request.OperationId.Span.SequenceEqual(request.Envelope.OperationId.Span))
        {
            throw Error(
                MailboxClientError.CapabilityEnvelopeMismatch,
                "The store operation, deposit capability and envelope must bind the same epoch and operation.");
        }

        var encoded = new byte[StoreHeaderLength + capability.Length + envelope.Length];
        StoreMagic.CopyTo(encoded);
        encoded[4] = Version;
        encoded[5] = (byte)request.MixedVersion;
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(8, 8), request.Epoch);
        request.OperationId.Span.CopyTo(encoded.AsSpan(16, MailboxClientLimits.OperationIdLength));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(32, 2), checked((ushort)capability.Length));
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(36, 4), checked((uint)envelope.Length));
        capability.CopyTo(encoded, StoreHeaderLength);
        envelope.CopyTo(encoded, StoreHeaderLength + capability.Length);
        return encoded;
    }

    public static MailboxStoreRequest DecodeStore(
        ReadOnlySpan<byte> encoded,
        MailboxClientDecodePolicy policy,
        IMailboxCapabilityReplayGuard replayGuard)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(replayGuard);
        ValidateFrame(
            encoded,
            StoreMagic,
            StoreHeaderLength +
            MailboxCapabilityLimits.FixedPresentationHeaderLength +
            MailboxClientLimits.EncryptedEnvelopeHeaderLength +
            MailboxClientLimits.MinimumCiphertextLength,
            StoreHeaderLength +
            MailboxCapabilityLimits.MaximumPresentationLength +
            MailboxClientLimits.EncryptedEnvelopeHeaderLength +
            MailboxClientLimits.MaximumCiphertextLength);
        if (encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(34, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(40, 8).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw Error(MailboxClientError.ReservedFieldNotZero, "Reserved store fields must be zero.");
        }

        var capabilityLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(32, 2));
        var envelopeLength = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(36, 4));
        if (capabilityLength is
                < MailboxCapabilityLimits.FixedPresentationHeaderLength or
                > MailboxCapabilityLimits.MaximumPresentationLength ||
            envelopeLength is
                < MailboxClientLimits.EncryptedEnvelopeHeaderLength +
                  MailboxClientLimits.MinimumCiphertextLength or
                > MailboxClientLimits.EncryptedEnvelopeHeaderLength +
                  MailboxClientLimits.MaximumCiphertextLength ||
            encoded.Length != StoreHeaderLength + capabilityLength + envelopeLength)
        {
            throw Error(MailboxClientError.MalformedLength, "Nested store lengths are not canonical.");
        }

        var epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8));
        ValidateEpoch(epoch, policy);
        var operationId = encoded.Slice(16, MailboxClientLimits.OperationIdLength).ToArray();
        ValidateOperationId(operationId);
        var mixedVersion = DecodeMixedVersion(encoded[5], policy);
        var capability = MailboxCapabilityCodec.Decode(
            encoded.Slice(StoreHeaderLength, capabilityLength),
            MailboxCapabilityDomain.Deposit,
            policy.CapabilityPolicy,
            replayGuard).Presentation;
        var envelope = DecodeEncryptedEnvelope(
            encoded.Slice(StoreHeaderLength + capabilityLength, checked((int)envelopeLength)),
            policy);
        if (epoch != capability.Generation ||
            epoch != envelope.Epoch ||
            mixedVersion != capability.MixedVersion ||
            !operationId.AsSpan().SequenceEqual(envelope.OperationId.Span))
        {
            throw Error(
                MailboxClientError.CapabilityEnvelopeMismatch,
                "The store frame has inconsistent epoch, version or operation bindings.");
        }

        return new MailboxStoreRequest
        {
            Epoch = epoch,
            OperationId = operationId,
            MixedVersion = mixedVersion,
            DepositCapability = capability,
            Envelope = envelope
        };
    }

    public static byte[] EncodeRetrieve(MailboxRetrieveRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateOperationId(request.OperationId.Span);
        ValidateMixedVersion(request.MixedVersion);
        ValidatePagination(request.MaximumItems, request.ContinuationToken.Span);
        EnsureDomain(request.RetrieveCapability, MailboxCapabilityDomain.Retrieve);
        if (request.Epoch != request.RetrieveCapability.Generation ||
            request.MixedVersion != request.RetrieveCapability.MixedVersion)
        {
            throw Error(MailboxClientError.InvalidEpoch, "Retrieve capability epoch/version binding is invalid.");
        }

        var capability = MailboxCapabilityCodec.Encode(request.RetrieveCapability);
        var encoded = new byte[
            RetrieveHeaderLength + capability.Length + request.ContinuationToken.Length];
        RetrieveMagic.CopyTo(encoded);
        encoded[4] = Version;
        encoded[5] = (byte)request.MixedVersion;
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(8, 8), request.Epoch);
        request.OperationId.Span.CopyTo(encoded.AsSpan(16, MailboxClientLimits.OperationIdLength));
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(32, 8), request.AfterCursor);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(40, 2), request.MaximumItems);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(42, 2), checked((ushort)capability.Length));
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(44, 2),
            checked((ushort)request.ContinuationToken.Length));
        request.MailboxId.Bytes.Span.CopyTo(encoded.AsSpan(48, MailboxClientLimits.BlindedIdentifierLength));
        request.PlacementId.Bytes.Span.CopyTo(encoded.AsSpan(80, MailboxClientLimits.BlindedIdentifierLength));
        capability.CopyTo(encoded, RetrieveHeaderLength);
        request.ContinuationToken.Span.CopyTo(encoded.AsSpan(RetrieveHeaderLength + capability.Length));
        return encoded;
    }

    public static MailboxRetrieveRequest DecodeRetrieve(
        ReadOnlySpan<byte> encoded,
        MailboxClientDecodePolicy policy,
        IMailboxCapabilityReplayGuard replayGuard)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(replayGuard);
        ValidateFrame(
            encoded,
            RetrieveMagic,
            RetrieveHeaderLength + MailboxCapabilityLimits.FixedPresentationHeaderLength,
            RetrieveHeaderLength +
            MailboxCapabilityLimits.MaximumPresentationLength +
            MailboxClientLimits.MaximumContinuationTokenLength);
        if (encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(46, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(112, 8).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw Error(MailboxClientError.ReservedFieldNotZero, "Reserved retrieve fields must be zero.");
        }

        var capabilityLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(42, 2));
        var tokenLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(44, 2));
        if (capabilityLength is
                < MailboxCapabilityLimits.FixedPresentationHeaderLength or
                > MailboxCapabilityLimits.MaximumPresentationLength ||
            tokenLength > MailboxClientLimits.MaximumContinuationTokenLength ||
            encoded.Length != RetrieveHeaderLength + capabilityLength + tokenLength)
        {
            throw Error(MailboxClientError.MalformedLength, "Nested retrieve lengths are not canonical.");
        }

        var epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8));
        ValidateEpoch(epoch, policy);
        var operationId = encoded.Slice(16, MailboxClientLimits.OperationIdLength).ToArray();
        ValidateOperationId(operationId);
        var maximumItems = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(40, 2));
        var token = encoded.Slice(RetrieveHeaderLength + capabilityLength, tokenLength).ToArray();
        ValidatePagination(maximumItems, token);
        var mixedVersion = DecodeMixedVersion(encoded[5], policy);
        var capability = MailboxCapabilityCodec.Decode(
            encoded.Slice(RetrieveHeaderLength, capabilityLength),
            MailboxCapabilityDomain.Retrieve,
            policy.CapabilityPolicy,
            replayGuard).Presentation;
        if (capability.Generation != epoch || capability.MixedVersion != mixedVersion)
        {
            throw Error(MailboxClientError.InvalidEpoch, "Retrieve capability epoch/version binding is invalid.");
        }

        ValidateBlindedIdentifier(encoded.Slice(48, MailboxClientLimits.BlindedIdentifierLength));
        ValidateBlindedIdentifier(encoded.Slice(80, MailboxClientLimits.BlindedIdentifierLength));
        return new MailboxRetrieveRequest
        {
            Epoch = epoch,
            OperationId = operationId,
            MixedVersion = mixedVersion,
            RetrieveCapability = capability,
            MailboxId = new BlindedMailboxId(
                encoded.Slice(48, MailboxClientLimits.BlindedIdentifierLength)),
            PlacementId = new BlindedPlacementId(
                encoded.Slice(80, MailboxClientLimits.BlindedIdentifierLength)),
            AfterCursor = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(32, 8)),
            MaximumItems = maximumItems,
            ContinuationToken = token
        };
    }

    public static byte[] EncodeRetrievePage(MailboxRetrievePage page)
    {
        ArgumentNullException.ThrowIfNull(page);
        ValidateOperationId(page.OperationId.Span);
        if (page.Epoch == 0 ||
            page.Envelopes.Count > MailboxClientLimits.MaximumPageItems ||
            page.ContinuationToken.Length > MailboxClientLimits.MaximumContinuationTokenLength ||
            page.HasMore != !page.ContinuationToken.IsEmpty ||
            page.HasMore && page.NextCursor == 0)
        {
            throw Error(MailboxClientError.PaginationOutOfRange, "Retrieve page metadata is not canonical.");
        }

        var envelopes = page.Envelopes.Select(EncodeEncryptedEnvelope).ToArray();
        var length = checked(
            PageHeaderLength +
            page.ContinuationToken.Length +
            envelopes.Sum(static value => 4 + value.Length));
        if (length > MailboxClientLimits.MaximumPageBytes)
        {
            throw Error(MailboxClientError.EncodedLengthOutOfRange, "Retrieve page exceeds its byte bound.");
        }

        var encoded = new byte[length];
        PageMagic.CopyTo(encoded);
        encoded[4] = Version;
        encoded[5] = page.HasMore ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(8, 8), page.Epoch);
        page.OperationId.Span.CopyTo(encoded.AsSpan(16, MailboxClientLimits.OperationIdLength));
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(32, 8), page.NextCursor);
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(40, 2),
            checked((ushort)page.ContinuationToken.Length));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(42, 2), checked((ushort)envelopes.Length));
        page.ContinuationToken.Span.CopyTo(encoded.AsSpan(PageHeaderLength));
        var offset = PageHeaderLength + page.ContinuationToken.Length;
        foreach (var envelope in envelopes)
        {
            BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(offset, 4), checked((uint)envelope.Length));
            offset += 4;
            envelope.CopyTo(encoded, offset);
            offset += envelope.Length;
        }

        return encoded;
    }

    public static MailboxRetrievePage DecodeRetrievePage(
        ReadOnlySpan<byte> encoded,
        MailboxClientDecodePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ValidateFrame(encoded, PageMagic, PageHeaderLength, MailboxClientLimits.MaximumPageBytes);
        if (encoded[5] > 1 ||
            encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(44, 4).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw Error(MailboxClientError.ReservedFieldNotZero, "Retrieve page flags/reserved fields are invalid.");
        }

        var epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8));
        ValidateEpoch(epoch, policy);
        var operationId = encoded.Slice(16, MailboxClientLimits.OperationIdLength).ToArray();
        ValidateOperationId(operationId);
        var nextCursor = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(32, 8));
        var tokenLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(40, 2));
        var count = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(42, 2));
        var hasMore = encoded[5] == 1;
        if (count > MailboxClientLimits.MaximumPageItems ||
            tokenLength > MailboxClientLimits.MaximumContinuationTokenLength ||
            PageHeaderLength + tokenLength > encoded.Length ||
            hasMore != (tokenLength != 0) ||
            hasMore && nextCursor == 0)
        {
            throw Error(MailboxClientError.PaginationOutOfRange, "Retrieve page bounds are invalid.");
        }

        var token = encoded.Slice(PageHeaderLength, tokenLength).ToArray();
        var offset = PageHeaderLength + tokenLength;
        var envelopes = new List<MailboxEncryptedEnvelope>(count);
        for (var index = 0; index < count; index++)
        {
            if (offset > encoded.Length - 4)
            {
                throw Error(MailboxClientError.MalformedLength, "A retrieve item length is truncated.");
            }

            var length = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(offset, 4));
            offset += 4;
            if (length >
                    MailboxClientLimits.EncryptedEnvelopeHeaderLength +
                    MailboxClientLimits.MaximumCiphertextLength ||
                length > encoded.Length - offset)
            {
                throw Error(MailboxClientError.MalformedLength, "A retrieve item length is invalid.");
            }

            var envelope = DecodeEncryptedEnvelope(encoded.Slice(offset, checked((int)length)), policy);
            if (envelope.Epoch != epoch)
            {
                throw Error(MailboxClientError.InvalidEpoch, "A page item belongs to another epoch.");
            }

            envelopes.Add(envelope);
            offset += checked((int)length);
        }

        if (offset != encoded.Length)
        {
            throw Error(MailboxClientError.MalformedLength, "The retrieve page has trailing bytes.");
        }

        return new MailboxRetrievePage
        {
            Epoch = epoch,
            OperationId = operationId,
            NextCursor = nextCursor,
            HasMore = hasMore,
            ContinuationToken = token,
            Envelopes = envelopes
        };
    }

    public static byte[] EncodeAck(MailboxAckRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateOperationId(request.OperationId.Span);
        ValidateMixedVersion(request.MixedVersion);
        EnsureDomain(request.RetrieveCapability, MailboxCapabilityDomain.Retrieve);
        ValidateAcknowledgements(request.Acknowledgements, request.ContinuationToken.Span, request.IsFinalPage);
        if (request.Epoch != request.RetrieveCapability.Generation ||
            request.MixedVersion != request.RetrieveCapability.MixedVersion)
        {
            throw Error(MailboxClientError.InvalidEpoch, "Ack capability epoch/version binding is invalid.");
        }

        var capability = MailboxCapabilityCodec.Encode(request.RetrieveCapability);
        var encoded = new byte[
            AckHeaderLength +
            capability.Length +
            request.ContinuationToken.Length +
            request.Acknowledgements.Count * AckEntryLength];
        AckMagic.CopyTo(encoded);
        encoded[4] = Version;
        encoded[5] = request.IsFinalPage ? (byte)1 : (byte)0;
        encoded[6] = (byte)request.MixedVersion;
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(8, 8), request.Epoch);
        request.OperationId.Span.CopyTo(encoded.AsSpan(16, MailboxClientLimits.OperationIdLength));
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(32, 2),
            checked((ushort)request.Acknowledgements.Count));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(34, 2), checked((ushort)capability.Length));
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(36, 2),
            checked((ushort)request.ContinuationToken.Length));
        request.MailboxId.Bytes.Span.CopyTo(encoded.AsSpan(40, MailboxClientLimits.BlindedIdentifierLength));
        request.PlacementId.Bytes.Span.CopyTo(encoded.AsSpan(72, MailboxClientLimits.BlindedIdentifierLength));
        capability.CopyTo(encoded, AckHeaderLength);
        request.ContinuationToken.Span.CopyTo(encoded.AsSpan(AckHeaderLength + capability.Length));
        var offset = AckHeaderLength + capability.Length + request.ContinuationToken.Length;
        foreach (var acknowledgement in request.Acknowledgements)
        {
            BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(offset, 8), acknowledgement.Cursor);
            acknowledgement.EnvelopeDigest.Span.CopyTo(encoded.AsSpan(offset + 8, MailboxClientLimits.DigestLength));
            offset += AckEntryLength;
        }

        return encoded;
    }

    public static MailboxAckRequest DecodeAck(
        ReadOnlySpan<byte> encoded,
        MailboxClientDecodePolicy policy,
        IMailboxCapabilityReplayGuard replayGuard)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(replayGuard);
        ValidateFrame(
            encoded,
            AckMagic,
            AckHeaderLength + MailboxCapabilityLimits.FixedPresentationHeaderLength + AckEntryLength,
            AckHeaderLength +
            MailboxCapabilityLimits.MaximumPresentationLength +
            MailboxClientLimits.MaximumContinuationTokenLength +
            MailboxClientLimits.MaximumPageItems * AckEntryLength);
        if (encoded[5] > 1 ||
            encoded[7] != 0 ||
            encoded.Slice(38, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(104, 16).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw Error(MailboxClientError.ReservedFieldNotZero, "Ack flags/reserved fields are invalid.");
        }

        var count = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(32, 2));
        var capabilityLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(34, 2));
        var tokenLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(36, 2));
        var expectedLength =
            AckHeaderLength + capabilityLength + tokenLength + count * AckEntryLength;
        if (count is 0 or > MailboxClientLimits.MaximumPageItems ||
            capabilityLength is
                < MailboxCapabilityLimits.FixedPresentationHeaderLength or
                > MailboxCapabilityLimits.MaximumPresentationLength ||
            tokenLength > MailboxClientLimits.MaximumContinuationTokenLength ||
            encoded.Length != expectedLength)
        {
            throw Error(MailboxClientError.MalformedLength, "Nested ack lengths are not canonical.");
        }

        var epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8));
        ValidateEpoch(epoch, policy);
        var operationId = encoded.Slice(16, MailboxClientLimits.OperationIdLength).ToArray();
        ValidateOperationId(operationId);
        var mixedVersion = DecodeMixedVersion(encoded[6], policy);
        var capability = MailboxCapabilityCodec.Decode(
            encoded.Slice(AckHeaderLength, capabilityLength),
            MailboxCapabilityDomain.Retrieve,
            policy.CapabilityPolicy,
            replayGuard).Presentation;
        if (capability.Generation != epoch || capability.MixedVersion != mixedVersion)
        {
            throw Error(MailboxClientError.InvalidEpoch, "Ack capability epoch/version binding is invalid.");
        }

        var tokenOffset = AckHeaderLength + capabilityLength;
        var token = encoded.Slice(tokenOffset, tokenLength).ToArray();
        var offset = tokenOffset + tokenLength;
        var acknowledgements = new List<MailboxAcknowledgement>(count);
        ulong priorCursor = 0;
        for (var index = 0; index < count; index++)
        {
            var cursor = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(offset, 8));
            var digest = encoded.Slice(offset + 8, MailboxClientLimits.DigestLength).ToArray();
            if (cursor == 0 || cursor <= priorCursor || digest.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            {
                throw Error(MailboxClientError.PaginationOutOfRange, "Ack entries must use increasing nonzero cursors.");
            }

            acknowledgements.Add(new MailboxAcknowledgement
            {
                Cursor = cursor,
                EnvelopeDigest = digest
            });
            priorCursor = cursor;
            offset += AckEntryLength;
        }

        var isFinalPage = encoded[5] == 1;
        ValidateAcknowledgements(acknowledgements, token, isFinalPage);
        ValidateBlindedIdentifier(encoded.Slice(40, MailboxClientLimits.BlindedIdentifierLength));
        ValidateBlindedIdentifier(encoded.Slice(72, MailboxClientLimits.BlindedIdentifierLength));
        return new MailboxAckRequest
        {
            Epoch = epoch,
            OperationId = operationId,
            MixedVersion = mixedVersion,
            RetrieveCapability = capability,
            MailboxId = new BlindedMailboxId(
                encoded.Slice(40, MailboxClientLimits.BlindedIdentifierLength)),
            PlacementId = new BlindedPlacementId(
                encoded.Slice(72, MailboxClientLimits.BlindedIdentifierLength)),
            IsFinalPage = isFinalPage,
            ContinuationToken = token,
            Acknowledgements = acknowledgements
        };
    }

    private static void ValidateEnvelope(
        MailboxEncryptedEnvelope envelope,
        MailboxClientDecodePolicy? policy)
    {
        ArgumentNullException.ThrowIfNull(envelope.MailboxId);
        ArgumentNullException.ThrowIfNull(envelope.PlacementId);
        ValidateOperationId(envelope.OperationId.Span);
        ValidateDigest(envelope.DeduplicationDigest.Span);
        if (envelope.Epoch == 0)
        {
            throw Error(MailboxClientError.InvalidEpoch, "Envelope epoch must be nonzero.");
        }

        if (envelope.Ciphertext.Length is
            < MailboxClientLimits.MinimumCiphertextLength or
            > MailboxClientLimits.MaximumCiphertextLength)
        {
            throw Error(MailboxClientError.InvalidCiphertext, "Ciphertext length is outside strict bounds.");
        }

        if (envelope.ExpiresAtUnixSeconds <= envelope.CreatedAtUnixSeconds ||
            envelope.ExpiresAtUnixSeconds - envelope.CreatedAtUnixSeconds is
                < MailboxClientLimits.MinimumTtlSeconds or
                > MailboxClientLimits.MaximumTtlSeconds)
        {
            throw Error(MailboxClientError.InvalidTtl, "Envelope TTL is outside the canonical 1 minute..7 day range.");
        }

        if (policy is null)
        {
            return;
        }

        ValidateEpoch(envelope.Epoch, policy);
        if (policy.NowUnixSeconds < envelope.CreatedAtUnixSeconds ||
            policy.NowUnixSeconds > envelope.ExpiresAtUnixSeconds)
        {
            throw Error(MailboxClientError.InvalidTtl, "Envelope is not currently valid.");
        }
    }

    private static void EnsureDomain(
        MailboxCapabilityPresentation presentation,
        MailboxCapabilityDomain expected)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        var actual = presentation.DomainValue switch
        {
            RotatingDepositCapability => MailboxCapabilityDomain.Deposit,
            RotatingRetrieveCapability => MailboxCapabilityDomain.Retrieve,
            OpaquePlacementKey => MailboxCapabilityDomain.Placement,
            _ => throw Error(MailboxClientError.InvalidCapabilityDomain, "Unknown mailbox capability domain.")
        };
        if (actual != expected)
        {
            throw Error(
                MailboxClientError.InvalidCapabilityDomain,
                "Deposit and retrieve capabilities are non-convertible domains.");
        }
    }

    private static void ValidateEpoch(ulong epoch, MailboxClientDecodePolicy policy)
    {
        policy.EpochWindow.Validate();
        if (!policy.EpochWindow.Accepts(epoch, policy.NowUnixSeconds))
        {
            throw Error(MailboxClientError.InvalidEpoch, "The epoch is outside the explicit E/E+1 overlap.");
        }
    }

    private static void ValidateOperationId(ReadOnlySpan<byte> operationId)
    {
        if (operationId.Length != MailboxClientLimits.OperationIdLength ||
            operationId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw Error(MailboxClientError.InvalidOperationId, "Operation IDs must be fixed length and nonzero.");
        }
    }

    private static void ValidateBlindedIdentifier(ReadOnlySpan<byte> identifier)
    {
        if (identifier.Length != MailboxClientLimits.BlindedIdentifierLength ||
            identifier.IndexOfAnyExcept((byte)0) < 0)
        {
            throw Error(
                MailboxClientError.InvalidIdentifier,
                "Blinded mailbox/placement identifiers must be fixed length and nonzero.");
        }
    }

    private static void ValidateDigest(ReadOnlySpan<byte> digest)
    {
        if (digest.Length != MailboxClientLimits.DigestLength ||
            digest.IndexOfAnyExcept((byte)0) < 0)
        {
            throw Error(MailboxClientError.InvalidDigest, "Mailbox digests must be fixed length and nonzero.");
        }
    }

    private static void ValidatePagination(ushort maximumItems, ReadOnlySpan<byte> token)
    {
        if (maximumItems is 0 or > MailboxClientLimits.MaximumPageItems ||
            token.Length > MailboxClientLimits.MaximumContinuationTokenLength)
        {
            throw Error(MailboxClientError.PaginationOutOfRange, "Pagination bounds are invalid.");
        }
    }

    private static void ValidateAcknowledgements(
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        ReadOnlySpan<byte> token,
        bool isFinalPage)
    {
        ArgumentNullException.ThrowIfNull(acknowledgements);
        if (acknowledgements.Count is 0 or > MailboxClientLimits.MaximumPageItems ||
            token.Length > MailboxClientLimits.MaximumContinuationTokenLength ||
            isFinalPage != token.IsEmpty)
        {
            throw Error(MailboxClientError.PaginationOutOfRange, "Ack pagination bounds are invalid.");
        }

        ulong priorCursor = 0;
        foreach (var acknowledgement in acknowledgements)
        {
            ArgumentNullException.ThrowIfNull(acknowledgement);
            ValidateDigest(acknowledgement.EnvelopeDigest.Span);
            if (acknowledgement.Cursor == 0 || acknowledgement.Cursor <= priorCursor)
            {
                throw Error(
                    MailboxClientError.PaginationOutOfRange,
                    "Ack entries must use increasing nonzero cursors.");
            }

            priorCursor = acknowledgement.Cursor;
        }
    }

    private static void ValidateMixedVersion(MailboxMixedVersionMarker marker)
    {
        if (marker is not (
            MailboxMixedVersionMarker.StrictV1 or
            MailboxMixedVersionMarker.LegacyMirrorOverlap))
        {
            throw Error(MailboxClientError.DowngradeRejected, "The mixed-version marker is invalid.");
        }
    }

    private static MailboxMixedVersionMarker DecodeMixedVersion(
        byte value,
        MailboxClientDecodePolicy policy)
    {
        var marker = (MailboxMixedVersionMarker)value;
        ValidateMixedVersion(marker);
        if (marker == MailboxMixedVersionMarker.LegacyMirrorOverlap &&
            !policy.AllowLegacyMirrorOverlap)
        {
            throw Error(MailboxClientError.DowngradeRejected, "Legacy mirror fallback was not explicitly enabled.");
        }

        return marker;
    }

    private static void ValidateFrame(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> magic,
        int minimumLength,
        int maximumLength)
    {
        if (encoded.Length < minimumLength || encoded.Length > maximumLength)
        {
            throw Error(MailboxClientError.EncodedLengthOutOfRange, "Mailbox frame length is outside strict bounds.");
        }

        if (!encoded[..4].SequenceEqual(magic))
        {
            throw Error(MailboxClientError.InvalidMagic, "Mailbox frame magic is invalid.");
        }

        if (encoded[4] != Version)
        {
            throw Error(MailboxClientError.UnsupportedVersion, "Mailbox frame version is unsupported.");
        }
    }

    private static MailboxClientException Error(MailboxClientError error, string message) =>
        new(error, message);
}
