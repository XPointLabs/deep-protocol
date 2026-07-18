using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;

namespace Deep.Protocol.DeepExtension.OpaqueBundles;

public static class OpaqueBundleNegotiator
{
    public static OpaqueBundleNegotiatedProfile Negotiate(
        OpaqueBundleNegotiationOffer local,
        OpaqueBundleNegotiationOffer peer,
        OpaqueBundleWireVersion minimumSafeVersion,
        bool allowLegacyDpe1 = false)
    {
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(peer);

        ValidateOffer(local, nameof(local));
        ValidateOffer(peer, nameof(peer));

        var minimum = Math.Max((byte)local.MinimumVersion, (byte)peer.MinimumVersion);
        minimum = Math.Max(minimum, (byte)minimumSafeVersion);
        var maximum = Math.Min((byte)local.MaximumVersion, (byte)peer.MaximumVersion);
        if (minimum > maximum)
        {
            throw new OpaqueBundleNegotiationException("No wire version satisfies both offers and the minimum safe version.");
        }

        var selected = (OpaqueBundleWireVersion)maximum;
        if (selected != OpaqueBundleWireVersion.V1)
        {
            throw new OpaqueBundleNegotiationException($"Wire version {(byte)selected} is not implemented.");
        }

        var commonFeatures = local.SupportedCriticalFeatures & peer.SupportedCriticalFeatures;
        if ((commonFeatures & OpaqueBundleFeatures.V1Required) != OpaqueBundleFeatures.V1Required)
        {
            throw new OpaqueBundleNegotiationException("The peers do not share every critical V1 feature.");
        }

        return new OpaqueBundleNegotiatedProfile(selected, commonFeatures, allowLegacyDpe1);
    }

    private static void ValidateOffer(OpaqueBundleNegotiationOffer offer, string parameterName)
    {
        if ((byte)offer.MinimumVersion > (byte)offer.MaximumVersion)
        {
            throw new ArgumentException("Minimum version must not exceed maximum version.", parameterName);
        }

        if ((offer.SupportedCriticalFeatures & ~OpaqueBundleFeatureSet.KnownCriticalFeatures) !=
            OpaqueBundleFeatures.None)
        {
            throw new OpaqueBundleNegotiationException(
                $"{parameterName} declares a critical feature not implemented by this codec.");
        }
    }
}

public static class OpaqueBundleCodec
{
    private static ReadOnlySpan<byte> Magic => "DPB1"u8;
    private static ReadOnlySpan<byte> LegacyDpe1Magic => "DPE1"u8;

    public static byte[] Encode(
        OpaqueBundleWriteRequest request,
        OpaqueBundleNegotiatedProfile negotiatedProfile)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(negotiatedProfile);
        ValidateWriteRequest(request, negotiatedProfile);

        var capabilityLength = request.Capability.Bytes.Length;
        var encryptedHeaderLength = request.EncryptedHeader.Length;
        var encryptedPayloadLength = request.EncryptedPayload.Length;
        var unpaddedLength = checked(
            OpaqueBundleLimits.FixedHeaderLength +
            capabilityLength +
            encryptedHeaderLength +
            encryptedPayloadLength);
        var paddingBlock = GetPaddingBlock(request.PaddingClass);
        var encodedLength = RoundUp(unpaddedLength, paddingBlock);
        if (encodedLength > OpaqueBundleLimits.MaximumEncodedLength)
        {
            throw new OpaqueBundleFormatException(
                OpaqueBundleDecodeError.EncodedLengthOutOfRange,
                "The canonical padded bundle exceeds the maximum encoded length.");
        }

        var encoded = new byte[encodedLength];
        Magic.CopyTo(encoded);
        encoded[4] = (byte)negotiatedProfile.WireVersion;
        encoded[5] = (byte)negotiatedProfile.WireVersion;
        encoded[6] = (byte)request.PayloadKind;
        encoded[7] = request.Capability switch
        {
            OpaqueDepositCapability => 1,
            OpaqueRetrieveCapability => 2,
            _ => throw new OpaqueBundlePolicyException(
                OpaqueBundleDecodeError.InvalidCapability,
                "Only distinct opaque deposit and retrieve capability types are supported.")
        };
        encoded[8] = (byte)request.PaddingClass;
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(10, 4), (uint)request.CriticalFeatures);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(14, 4), (uint)request.OptionalFeatures);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(18, 4), request.ExpiryBucket);
        request.TransportAttemptId.Bytes.Span.CopyTo(encoded.AsSpan(22, OpaqueBundleLimits.IdentifierLength));
        request.ReplayMaterial.Span.CopyTo(encoded.AsSpan(38, OpaqueBundleLimits.ReplayMaterialLength));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(54, 2), checked((ushort)capabilityLength));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(56, 2), checked((ushort)encryptedHeaderLength));
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(58, 4), checked((uint)encryptedPayloadLength));

        var offset = OpaqueBundleLimits.FixedHeaderLength;
        request.Capability.Bytes.Span.CopyTo(encoded.AsSpan(offset, capabilityLength));
        offset += capabilityLength;
        request.EncryptedHeader.Span.CopyTo(encoded.AsSpan(offset, encryptedHeaderLength));
        offset += encryptedHeaderLength;
        request.EncryptedPayload.Span.CopyTo(encoded.AsSpan(offset, encryptedPayloadLength));
        return encoded;
    }

    public static OpaqueBundle Decode(
        ReadOnlySpan<byte> encoded,
        OpaqueBundleDecodePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        if (encoded.Length is < OpaqueBundleLimits.FixedHeaderLength or > OpaqueBundleLimits.MaximumEncodedLength)
        {
            throw Format(
                OpaqueBundleDecodeError.EncodedLengthOutOfRange,
                "The encoded bundle length is outside the bounded parser range.");
        }

        if (!encoded[..Magic.Length].SequenceEqual(Magic))
        {
            throw Format(OpaqueBundleDecodeError.InvalidMagic, "The Deep extension bundle magic is invalid.");
        }

        var version = (OpaqueBundleWireVersion)encoded[4];
        if (version != OpaqueBundleWireVersion.V1 || (byte)version > (byte)policy.MaximumVersion)
        {
            throw Policy(OpaqueBundleDecodeError.UnsupportedVersion, "The bundle wire version is not supported.");
        }

        if ((byte)version < (byte)policy.MinimumVersion)
        {
            throw Policy(OpaqueBundleDecodeError.DowngradeRejected, "The bundle wire version is below the strict minimum.");
        }

        var minimumReaderVersion = (OpaqueBundleWireVersion)encoded[5];
        if (minimumReaderVersion != OpaqueBundleWireVersion.V1 ||
            (byte)minimumReaderVersion > (byte)version)
        {
            throw Format(OpaqueBundleDecodeError.DowngradeRejected, "The minimum-reader version is not canonical for V1.");
        }

        if ((byte)minimumReaderVersion > (byte)policy.MaximumVersion)
        {
            throw Policy(OpaqueBundleDecodeError.UnsupportedVersion, "The reader does not support the bundle minimum-reader version.");
        }

        var payloadKind = (OpaqueBundlePayloadKind)encoded[6];
        if (payloadKind is not (OpaqueBundlePayloadKind.NativeOpaque or OpaqueBundlePayloadKind.LegacyDpe1))
        {
            throw Format(OpaqueBundleDecodeError.InvalidEnumValue, "The payload kind is invalid.");
        }

        var capabilityKind = encoded[7];
        if (capabilityKind is not (1 or 2))
        {
            throw Format(OpaqueBundleDecodeError.InvalidCapability, "The capability kind is invalid.");
        }

        var paddingClass = (OpaqueBundlePaddingClass)encoded[8];
        var paddingBlock = GetPaddingBlock(paddingClass);
        if (encoded[9] != 0 || encoded[62] != 0 || encoded[63] != 0)
        {
            throw Format(OpaqueBundleDecodeError.ReservedFieldNotZero, "Reserved header bytes must be zero.");
        }

        var criticalFeatures = (OpaqueBundleFeatures)BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(10, 4));
        if ((policy.SupportedCriticalFeatures & ~OpaqueBundleFeatureSet.KnownCriticalFeatures) !=
            OpaqueBundleFeatures.None)
        {
            throw Policy(
                OpaqueBundleDecodeError.UnknownCriticalFeature,
                "The decode policy attempts to extend the codec's implemented critical features.");
        }

        var acceptedCriticalFeatures =
            policy.SupportedCriticalFeatures & OpaqueBundleFeatureSet.KnownCriticalFeatures;
        var unknownCriticalFeatures = criticalFeatures & ~acceptedCriticalFeatures;
        if (unknownCriticalFeatures != OpaqueBundleFeatures.None)
        {
            throw Policy(OpaqueBundleDecodeError.UnknownCriticalFeature, "The bundle declares an unsupported critical feature.");
        }

        if ((criticalFeatures & OpaqueBundleFeatures.V1Required) != OpaqueBundleFeatures.V1Required)
        {
            throw Policy(OpaqueBundleDecodeError.MissingRequiredFeature, "The bundle omits a required V1 critical feature.");
        }

        var optionalFeatures = (OpaqueBundleFeatures)BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(14, 4));
        var expiryBucket = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(18, 4));
        if (expiryBucket < policy.MinimumExpiryBucket || expiryBucket > policy.MaximumExpiryBucket)
        {
            throw Policy(OpaqueBundleDecodeError.ExpiryOutsideWindow, "The expiry bucket is outside the accepted window.");
        }

        var capabilityLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(54, 2));
        var encryptedHeaderLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(56, 2));
        var encryptedPayloadLength = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(58, 4));
        var unpaddedLength64 =
            (long)OpaqueBundleLimits.FixedHeaderLength +
            capabilityLength +
            encryptedHeaderLength +
            encryptedPayloadLength;
        if (unpaddedLength64 > int.MaxValue)
        {
            throw Format(OpaqueBundleDecodeError.MalformedLength, "The declared body length overflows the parser range.");
        }

        ValidateDecodedLengths(capabilityLength, encryptedHeaderLength, encryptedPayloadLength);

        var unpaddedLength = (int)unpaddedLength64;
        var canonicalLength = RoundUp(unpaddedLength, paddingBlock);
        if (canonicalLength != encoded.Length)
        {
            throw Format(OpaqueBundleDecodeError.MalformedLength, "The encoded length does not match the canonical declared lengths.");
        }

        if (encoded[unpaddedLength..].IndexOfAnyExcept((byte)0) >= 0)
        {
            throw Format(OpaqueBundleDecodeError.NonCanonicalPadding, "Padding must contain only zero bytes.");
        }

        var offset = OpaqueBundleLimits.FixedHeaderLength;
        var capabilityBytes = encoded.Slice(offset, capabilityLength);
        var capability = capabilityKind == 1
            ? (OpaqueMailboxCapability)new OpaqueDepositCapability(capabilityBytes)
            : new OpaqueRetrieveCapability(capabilityBytes);
        offset += capabilityLength;
        var encryptedHeader = encoded.Slice(offset, encryptedHeaderLength).ToArray();
        offset += encryptedHeaderLength;
        var encryptedPayload = encoded.Slice(offset, checked((int)encryptedPayloadLength)).ToArray();

        ValidateLegacyPayload(payloadKind, criticalFeatures, encryptedPayload, policy.AllowLegacyDpe1);

        return new OpaqueBundle
        {
            WireVersion = version,
            Capability = capability,
            TransportAttemptId = new TransportAttemptId(encoded.Slice(22, OpaqueBundleLimits.IdentifierLength)),
            ExpiryBucket = expiryBucket,
            PaddingClass = paddingClass,
            ReplayMaterial = encoded.Slice(38, OpaqueBundleLimits.ReplayMaterialLength).ToArray(),
            EncryptedHeader = encryptedHeader,
            EncryptedPayload = encryptedPayload,
            PayloadKind = payloadKind,
            CriticalFeatures = criticalFeatures,
            OptionalFeatures = optionalFeatures
        };
    }

    public static bool TryDecode(
        ReadOnlySpan<byte> encoded,
        OpaqueBundleDecodePolicy policy,
        [NotNullWhen(true)] out OpaqueBundle? bundle,
        out OpaqueBundleDecodeError error)
    {
        try
        {
            bundle = Decode(encoded, policy);
            error = OpaqueBundleDecodeError.None;
            return true;
        }
        catch (OpaqueBundleException exception)
        {
            bundle = null;
            error = exception.Error;
            return false;
        }
    }

    private static void ValidateWriteRequest(
        OpaqueBundleWriteRequest request,
        OpaqueBundleNegotiatedProfile profile)
    {
        if (profile.WireVersion != OpaqueBundleWireVersion.V1)
        {
            throw Policy(OpaqueBundleDecodeError.UnsupportedVersion, "Only explicitly negotiated V1 encoding is implemented.");
        }

        if ((profile.SupportedCriticalFeatures & ~OpaqueBundleFeatureSet.KnownCriticalFeatures) !=
            OpaqueBundleFeatures.None)
        {
            throw Policy(
                OpaqueBundleDecodeError.UnknownCriticalFeature,
                "The negotiated profile attempts to extend the codec's implemented critical features.");
        }

        if ((request.CriticalFeatures & ~OpaqueBundleFeatureSet.KnownCriticalFeatures) !=
            OpaqueBundleFeatures.None)
        {
            throw Policy(
                OpaqueBundleDecodeError.UnknownCriticalFeature,
                "The request declares a critical feature not implemented by this codec.");
        }

        if ((request.CriticalFeatures & OpaqueBundleFeatures.V1Required) != OpaqueBundleFeatures.V1Required)
        {
            throw Policy(OpaqueBundleDecodeError.MissingRequiredFeature, "V1 encoding requires every V1 critical feature.");
        }

        if ((request.CriticalFeatures & ~profile.SupportedCriticalFeatures) != OpaqueBundleFeatures.None)
        {
            throw Policy(OpaqueBundleDecodeError.UnknownCriticalFeature, "The request uses a feature outside the negotiated profile.");
        }

        if (request.TransportAttemptId.Bytes.Span.SequenceEqual(request.EndToEndDedupId.Bytes.Span))
        {
            throw Policy(
                OpaqueBundleDecodeError.TransportAttemptEqualsDedup,
                "Transport-local attempt ID must differ from end-to-end dedup ID.");
        }

        if (request.ReplayMaterial.Length != OpaqueBundleLimits.ReplayMaterialLength)
        {
            throw Policy(OpaqueBundleDecodeError.InvalidIdentifier, "Replay material must be exactly 16 bytes.");
        }

        if (request.PayloadKind is not (OpaqueBundlePayloadKind.NativeOpaque or OpaqueBundlePayloadKind.LegacyDpe1))
        {
            throw Format(OpaqueBundleDecodeError.InvalidEnumValue, "The payload kind is invalid.");
        }

        ValidateLength(
            request.Capability.Bytes.Length,
            OpaqueBundleLimits.MinimumCapabilityLength,
            OpaqueBundleLimits.MaximumCapabilityLength,
            "capability");
        ValidateLength(request.EncryptedHeader.Length, 1, OpaqueBundleLimits.MaximumEncryptedHeaderLength, "encrypted header");
        ValidateLength(request.EncryptedPayload.Length, 1, OpaqueBundleLimits.MaximumEncryptedPayloadLength, "encrypted payload");
        _ = GetPaddingBlock(request.PaddingClass);
        ValidateLegacyPayload(request.PayloadKind, request.CriticalFeatures, request.EncryptedPayload.Span, profile.AllowLegacyDpe1);
    }

    private static void ValidateDecodedLengths(
        int capabilityLength,
        int encryptedHeaderLength,
        uint encryptedPayloadLength)
    {
        if (capabilityLength is < OpaqueBundleLimits.MinimumCapabilityLength or > OpaqueBundleLimits.MaximumCapabilityLength ||
            encryptedHeaderLength is < 1 or > OpaqueBundleLimits.MaximumEncryptedHeaderLength ||
            encryptedPayloadLength is < 1 or > OpaqueBundleLimits.MaximumEncryptedPayloadLength)
        {
            throw Format(OpaqueBundleDecodeError.MalformedLength, "One or more declared component lengths are outside strict bounds.");
        }
    }

    private static void ValidateLength(int value, int minimum, int maximum, string field)
    {
        if (value < minimum || value > maximum)
        {
            throw Format(OpaqueBundleDecodeError.MalformedLength, $"The {field} length is outside strict bounds.");
        }
    }

    private static void ValidateLegacyPayload(
        OpaqueBundlePayloadKind payloadKind,
        OpaqueBundleFeatures criticalFeatures,
        ReadOnlySpan<byte> encryptedPayload,
        bool allowLegacyDpe1)
    {
        if (payloadKind == OpaqueBundlePayloadKind.LegacyDpe1)
        {
            if (!allowLegacyDpe1)
            {
                throw Policy(OpaqueBundleDecodeError.LegacyPayloadNotAllowed, "Legacy DPE1 requires an explicit negotiated migration profile.");
            }

            if ((criticalFeatures & OpaqueBundleFeatures.LegacyDpe1Compatibility) == 0)
            {
                throw Policy(OpaqueBundleDecodeError.MissingRequiredFeature, "Legacy DPE1 payloads must declare the critical compatibility feature.");
            }

            if (!encryptedPayload.StartsWith(LegacyDpe1Magic))
            {
                throw Format(OpaqueBundleDecodeError.InvalidLegacyPayload, "Legacy compatibility payload must contain exact DPE1 bytes.");
            }
        }
        else if ((criticalFeatures & OpaqueBundleFeatures.LegacyDpe1Compatibility) != 0)
        {
            throw Policy(OpaqueBundleDecodeError.InvalidLegacyPayload, "Native opaque payloads must not declare legacy DPE1 compatibility.");
        }
    }

    private static int GetPaddingBlock(OpaqueBundlePaddingClass paddingClass) =>
        paddingClass switch
        {
            OpaqueBundlePaddingClass.Bytes256 => 256,
            OpaqueBundlePaddingClass.Bytes1024 => 1024,
            OpaqueBundlePaddingClass.Bytes4096 => 4096,
            OpaqueBundlePaddingClass.Bytes16384 => 16384,
            _ => throw Format(OpaqueBundleDecodeError.InvalidEnumValue, "The padding class is invalid.")
        };

    private static int RoundUp(int value, int block)
    {
        var remainder = value % block;
        return remainder == 0 ? value : checked(value + block - remainder);
    }

    private static OpaqueBundleFormatException Format(OpaqueBundleDecodeError error, string message) =>
        new(error, message);

    private static OpaqueBundlePolicyException Policy(OpaqueBundleDecodeError error, string message) =>
        new(error, message);
}
