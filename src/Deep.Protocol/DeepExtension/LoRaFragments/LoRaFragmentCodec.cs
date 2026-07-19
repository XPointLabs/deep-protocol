namespace Deep.Protocol.DeepExtension.LoRaFragments;

public static class LoRaFragmentCodec
{
    private static ReadOnlySpan<byte> Magic => "LF"u8;

    public static byte[] Encode(
        LoRaFragmentUnsignedFrame frame,
        LoRaFragmentAuthenticationHandle authenticationHandle,
        LoRaFragmentDirection direction,
        ILoRaFragmentAuthenticator authenticator)
    {
        ArgumentNullException.ThrowIfNull(frame);
        ArgumentNullException.ThrowIfNull(authenticationHandle);
        ArgumentNullException.ThrowIfNull(authenticator);
        ValidateDirection(direction);

        var header = EncodeHeader(frame.Header);
        var transcript = BuildAuthenticatedTranscript(frame.Header, frame.ShardSpan, direction);
        var authenticationTag = authenticator.CreateTag(
            LoRaFragmentDomains.Authentication,
            authenticationHandle,
            direction,
            transcript);
        if (authenticationTag is null ||
            authenticationTag.Length != LoRaFragmentLimits.AuthenticationTagLength)
        {
            throw Error(
                LoRaFragmentError.InvalidAuthenticationTag,
                "The authentication adapter must return exactly sixteen tag bytes.");
        }

        var encodedLength = checked(
            LoRaFragmentLimits.HeaderLength +
            frame.Header.ShardSize +
            LoRaFragmentLimits.AuthenticationTagLength);
        var encoded = new byte[encodedLength];
        header.CopyTo(encoded, 0);
        frame.ShardSpan.CopyTo(encoded.AsSpan(LoRaFragmentLimits.HeaderLength));
        authenticationTag.CopyTo(
            encoded,
            LoRaFragmentLimits.HeaderLength + frame.Header.ShardSize);
        return encoded;
    }

    public static LoRaFragmentFrame Decode(
        ReadOnlySpan<byte> encoded,
        LoRaFragmentPolicy policy,
        LoRaFragmentAuthenticationHandle authenticationHandle,
        LoRaFragmentDirection direction,
        ILoRaFragmentAuthenticator authenticator)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(authenticationHandle);
        ArgumentNullException.ThrowIfNull(authenticator);
        ValidateDirection(direction);

        if (encoded.Length is < LoRaFragmentLimits.MinimumEncodedFrameLength
            or > LoRaFragmentLimits.MaximumEncodedFrameLength)
        {
            throw Error(
                LoRaFragmentError.EncodedLengthOutOfRange,
                "The encoded frame is outside the absolute V1 length bounds.");
        }

        // Parse the complete fixed header and prove the exact frame length before
        // retaining any attacker-controlled shard bytes.
        if (!encoded[..Magic.Length].SequenceEqual(Magic))
        {
            throw Error(LoRaFragmentError.InvalidMagic, "The LoRa fragment magic is invalid.");
        }

        if (encoded[2] != LoRaFragmentLimits.WireVersion)
        {
            throw Error(
                LoRaFragmentError.UnsupportedVersion,
                "Only the canonical LoRa fragment V1 wire version is supported.");
        }

        var flags = encoded[3];
        if ((flags & 0xfe) != 0)
        {
            throw Error(
                LoRaFragmentError.UnknownFlags,
                "Unknown or reserved LoRa fragment flags are not canonical.");
        }

        var fecMode = (flags & 0x01) == 0
            ? LoRaFragmentFecMode.None
            : LoRaFragmentFecMode.Xor1;
        var messageId = encoded.Slice(4, LoRaFragmentLimits.MessageIdLength);
        if (messageId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw Error(
                LoRaFragmentError.InvalidMessageId,
                "The hop-local message ID must not be all zero.");
        }

        var ordinal = encoded[12];
        var dataShardCount = encoded[13];
        var parityShardCount = encoded[14];
        var shardSize = encoded[15];
        var expectedLength = checked(
            LoRaFragmentLimits.HeaderLength +
            shardSize +
            LoRaFragmentLimits.AuthenticationTagLength);
        if (encoded.Length != expectedLength)
        {
            throw Error(
                LoRaFragmentError.EncodedLengthOutOfRange,
                "The encoded frame length does not match its declared fixed shard size.");
        }

        ValidateDecodedCountsAndSize(
            dataShardCount,
            parityShardCount,
            shardSize,
            ordinal,
            fecMode,
            policy);

        var header = new LoRaFragmentHeader(
            messageId,
            ordinal,
            dataShardCount,
            parityShardCount,
            shardSize,
            fecMode);
        var shard = encoded.Slice(LoRaFragmentLimits.HeaderLength, shardSize);
        var authenticationTag = encoded.Slice(
            LoRaFragmentLimits.HeaderLength + shardSize,
            LoRaFragmentLimits.AuthenticationTagLength);
        var transcript = BuildAuthenticatedTranscript(header, shard, direction);
        if (!authenticator.VerifyTag(
                LoRaFragmentDomains.Authentication,
                authenticationHandle,
                direction,
                transcript,
                authenticationTag))
        {
            throw Error(
                LoRaFragmentError.AuthenticationFailed,
                "The LoRa fragment authentication tag was rejected.");
        }

        // The caller owns the input memory and could mutate it concurrently.
        // Retain only after the first verification, then authenticate the exact
        // retained snapshot once more to close the verify/copy TOCTOU window.
        var retainedShard = shard.ToArray();
        var retainedAuthenticationTag = authenticationTag.ToArray();
        var retainedTranscript = BuildAuthenticatedTranscript(
            header,
            retainedShard,
            direction);
        if (!authenticator.VerifyTag(
                LoRaFragmentDomains.Authentication,
                authenticationHandle,
                direction,
                retainedTranscript,
                retainedAuthenticationTag))
        {
            throw Error(
                LoRaFragmentError.AuthenticationFailed,
                "The retained LoRa fragment bytes changed after authentication.");
        }

        return new LoRaFragmentFrame(
            header,
            retainedShard,
            retainedAuthenticationTag);
    }

    public static byte[] BuildAuthenticatedTranscript(
        LoRaFragmentHeader header,
        ReadOnlySpan<byte> shard,
        LoRaFragmentDirection direction)
    {
        ArgumentNullException.ThrowIfNull(header);
        if (shard.Length != header.ShardSize)
        {
            throw new ArgumentException(
                "The shard must have the exact fixed size declared by the header.",
                nameof(shard));
        }

        ValidateDirection(direction);
        var encodedHeader = EncodeHeader(header);
        var domain = LoRaFragmentDomains.Authentication;
        var transcriptLength = checked(
            domain.Length +
            1 +
            LoRaFragmentLimits.HeaderLength +
            shard.Length);
        var transcript = new byte[transcriptLength];
        var offset = 0;
        domain.CopyTo(transcript);
        offset += domain.Length;
        transcript[offset++] = (byte)direction;
        encodedHeader.CopyTo(transcript, offset);
        offset += encodedHeader.Length;
        shard.CopyTo(transcript.AsSpan(offset));
        return transcript;
    }

    internal static byte[] EncodeHeader(LoRaFragmentHeader header)
    {
        ArgumentNullException.ThrowIfNull(header);

        var encoded = new byte[LoRaFragmentLimits.HeaderLength];
        Magic.CopyTo(encoded);
        encoded[2] = LoRaFragmentLimits.WireVersion;
        encoded[3] = header.FecMode switch
        {
            LoRaFragmentFecMode.None => 0,
            LoRaFragmentFecMode.Xor1 => 1,
            _ => throw new ArgumentOutOfRangeException(
                nameof(header),
                "The header declares an unsupported FEC mode.")
        };
        header.MessageIdSpan.CopyTo(encoded.AsSpan(4, LoRaFragmentLimits.MessageIdLength));
        encoded[12] = header.Ordinal;
        encoded[13] = header.DataShardCount;
        encoded[14] = header.ParityShardCount;
        encoded[15] = header.ShardSize;
        return encoded;
    }

    private static void ValidateDecodedCountsAndSize(
        byte dataShardCount,
        byte parityShardCount,
        byte shardSize,
        byte ordinal,
        LoRaFragmentFecMode fecMode,
        LoRaFragmentPolicy policy)
    {
        if (dataShardCount is < LoRaFragmentLimits.MinimumDataShardCount
            or > LoRaFragmentLimits.MaximumDataShardCount)
        {
            throw Error(
                LoRaFragmentError.InvalidDataShardCount,
                "The data-shard count is outside the absolute V1 bounds.");
        }

        if (dataShardCount > policy.MaxDataShards)
        {
            throw Error(
                LoRaFragmentError.PolicyRejected,
                "The data-shard count exceeds the caller's lower ceiling.");
        }

        if (shardSize is < LoRaFragmentLimits.MinimumShardSize
            or > LoRaFragmentLimits.MaximumShardSize)
        {
            throw Error(
                LoRaFragmentError.InvalidShardSize,
                "The shard size is outside the absolute V1 bounds.");
        }

        if (shardSize < policy.MinimumShardSize || shardSize > policy.MaxShardSize)
        {
            throw Error(
                LoRaFragmentError.PolicyRejected,
                "The shard size is outside the caller's narrowed range.");
        }

        var expectedParityCount = fecMode switch
        {
            LoRaFragmentFecMode.None => 0,
            LoRaFragmentFecMode.Xor1 =>
                (dataShardCount + LoRaFragmentLimits.XorDataShardsPerGroup - 1) /
                LoRaFragmentLimits.XorDataShardsPerGroup,
            _ => throw Error(
                LoRaFragmentError.InvalidFec,
                "The FEC mode is not implemented by V1.")
        };
        if (parityShardCount != expectedParityCount ||
            parityShardCount > LoRaFragmentLimits.MaximumParityShardCount)
        {
            throw Error(
                LoRaFragmentError.InvalidParityShardCount,
                "The parity-shard count is not canonical for the declared V1 FEC mode.");
        }

        if (parityShardCount > policy.MaxParityShards)
        {
            throw Error(
                LoRaFragmentError.PolicyRejected,
                "The parity-shard count exceeds the caller's lower ceiling.");
        }

        var totalFragmentCount = checked(dataShardCount + parityShardCount);
        if (totalFragmentCount > LoRaFragmentLimits.MaximumTotalFragmentCount ||
            ordinal >= totalFragmentCount)
        {
            throw Error(
                LoRaFragmentError.InvalidOrdinal,
                "The fragment ordinal is outside the canonical data/parity range.");
        }

        var dataCapacity = checked(dataShardCount * shardSize);
        if (dataCapacity > LoRaFragmentLimits.MaximumReservedDataShardBytes)
        {
            throw Error(
                LoRaFragmentError.PolicyRejected,
                "The declared data-shard reservation exceeds the absolute per-message ceiling.");
        }

        if (dataCapacity <
            LoRaFragmentLimits.DescriptorLength + LoRaFragmentLimits.MinimumBundleLength)
        {
            throw Error(
                LoRaFragmentError.InvalidDataShardCount,
                "The declared data shards cannot contain the descriptor and minimum V1 bundle.");
        }

    }

    private static void ValidateDirection(LoRaFragmentDirection direction)
    {
        if (direction is not LoRaFragmentDirection.Forward and not LoRaFragmentDirection.Reverse)
        {
            throw new ArgumentOutOfRangeException(nameof(direction));
        }
    }

    private static LoRaFragmentException Error(
        LoRaFragmentError error,
        string message) =>
        new(error, message);
}
