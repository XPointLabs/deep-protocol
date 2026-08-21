using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.DeepExtension.CompatibilityEnvelopes;

public static class CompatibilityMetadataEnvelopeCodec
{
    private static ReadOnlySpan<byte> AssociatedDataMagic => "P3AD"u8;
    private static ReadOnlySpan<byte> HeaderPlaintextMagic => "P3A1"u8;

    private const OpaqueBundleFeatures RequiredCriticalFeatures =
        OpaqueBundleFeatures.V1Required |
        OpaqueBundleFeatures.LegacyDpe1Compatibility |
        OpaqueBundleFeatures.AuthenticatedCompatibilityEnvelope;

    public static byte[] Encode(
        CompatibilityEnvelopeWriteRequest request,
        OpaqueBundleNegotiatedProfile negotiatedProfile,
        ICompatibilityEnvelopeCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(negotiatedProfile);
        ArgumentNullException.ThrowIfNull(crypto);

        ValidateNegotiatedProfile(negotiatedProfile);
        ValidateWriteRequest(request);

        var associatedData = BuildAssociatedData(
            request.Capability,
            request.TransportAttemptId,
            request.ExpiryBucket,
            request.PaddingClass,
            request.ReplayMaterial.Span,
            request.HeaderNonceContext.Span,
            request.PayloadNonceContext.Span);
        var headerPlaintext = new byte[CompatibilityEnvelopeLimits.HeaderPlaintextLength];
        HeaderPlaintextMagic.CopyTo(headerPlaintext);
        BinaryPrimitives.WriteUInt32BigEndian(
            headerPlaintext.AsSpan(HeaderPlaintextMagic.Length),
            checked((uint)request.LegacyDpe1.Length));

        var sealedHeader = crypto.Seal(new CompatibilityEnvelopeSealRequest
        {
            Purpose = CompatibilityEnvelopePurpose.Header,
            Domain = CompatibilityEnvelopeDomains.HeaderV1,
            RecipientKeyMaterial = request.RecipientKeyMaterial,
            SenderAuthenticationSecret = request.SenderAuthenticationSecret,
            NonceContext = request.HeaderNonceContext,
            AssociatedData = associatedData,
            Plaintext = headerPlaintext
        });
        var sealedPayload = crypto.Seal(new CompatibilityEnvelopeSealRequest
        {
            Purpose = CompatibilityEnvelopePurpose.Payload,
            Domain = CompatibilityEnvelopeDomains.PayloadV1,
            RecipientKeyMaterial = request.RecipientKeyMaterial,
            SenderAuthenticationSecret = request.SenderAuthenticationSecret,
            NonceContext = request.PayloadNonceContext,
            AssociatedData = associatedData,
            Plaintext = request.LegacyDpe1
        });

        var encryptedHeader = FrameSealedPart(
            request.HeaderNonceContext.Span,
            sealedHeader,
            headerPlaintext.Length,
            OpaqueBundleLimits.MaximumEncryptedHeaderLength,
            "header");
        var encryptedPayload = FrameSealedPart(
            request.PayloadNonceContext.Span,
            sealedPayload,
            request.LegacyDpe1.Length,
            OpaqueBundleLimits.MaximumEncryptedPayloadLength,
            "payload");

        return OpaqueBundleCodec.Encode(
            new OpaqueBundleWriteRequest
            {
                Capability = request.Capability,
                TransportAttemptId = request.TransportAttemptId,
                EndToEndDedupId = request.EndToEndDedupId,
                ExpiryBucket = request.ExpiryBucket,
                PaddingClass = request.PaddingClass,
                ReplayMaterial = request.ReplayMaterial,
                EncryptedHeader = encryptedHeader,
                EncryptedPayload = encryptedPayload,
                PayloadKind = OpaqueBundlePayloadKind.AuthenticatedLegacyDpe1,
                CriticalFeatures = RequiredCriticalFeatures
            },
            negotiatedProfile);
    }

    public static CompatibilityEnvelopeOpenResult Decode(
        ReadOnlySpan<byte> encoded,
        ReadOnlyMemory<byte> recipientKeyMaterial,
        OpaqueBundleDecodePolicy policy,
        ICompatibilityEnvelopeCrypto crypto,
        ICompatibilityEnvelopeReplayGuard replayGuard)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(replayGuard);

        var outer = OpaqueBundleCodec.Decode(encoded, policy);
        if (outer.PayloadKind != OpaqueBundlePayloadKind.AuthenticatedLegacyDpe1 ||
            outer.CriticalFeatures != RequiredCriticalFeatures)
        {
            throw Error(
                CompatibilityEnvelopeError.FeatureNotNegotiated,
                "The bundle is not an explicitly negotiated authenticated compatibility envelope.");
        }

        if (outer.OptionalFeatures != OpaqueBundleFeatures.None)
        {
            throw Error(
                CompatibilityEnvelopeError.InvalidOuterMetadata,
                "P03A does not permit caller-defined optional outer metadata.");
        }

        var (headerNonce, headerCiphertext) = ParseSealedPart(outer.EncryptedHeader, "header");
        var (payloadNonce, payloadCiphertext) = ParseSealedPart(outer.EncryptedPayload, "payload");
        if (headerNonce.Span.SequenceEqual(payloadNonce.Span))
        {
            throw Error(
                CompatibilityEnvelopeError.InvalidNonceContext,
                "Header and payload nonce contexts must be distinct.");
        }

        var associatedData = BuildAssociatedData(
            outer.Capability,
            outer.TransportAttemptId,
            outer.ExpiryBucket,
            outer.PaddingClass,
            outer.ReplayMaterial.Span,
            headerNonce.Span,
            payloadNonce.Span);

        CompatibilityEnvelopeOpenedResult openedHeader;
        CompatibilityEnvelopeOpenedResult openedPayload;
        try
        {
            openedHeader = crypto.Open(new CompatibilityEnvelopeOpenRequest
            {
                Purpose = CompatibilityEnvelopePurpose.Header,
                Domain = CompatibilityEnvelopeDomains.HeaderV1,
                RecipientKeyMaterial = recipientKeyMaterial,
                NonceContext = headerNonce,
                AssociatedData = associatedData,
                Ciphertext = headerCiphertext
            });
            openedPayload = crypto.Open(new CompatibilityEnvelopeOpenRequest
            {
                Purpose = CompatibilityEnvelopePurpose.Payload,
                Domain = CompatibilityEnvelopeDomains.PayloadV1,
                RecipientKeyMaterial = recipientKeyMaterial,
                NonceContext = payloadNonce,
                AssociatedData = associatedData,
                Ciphertext = payloadCiphertext
            });
        }
        catch (CryptographicException exception)
        {
            throw Error(
                CompatibilityEnvelopeError.AuthenticationFailed,
                "Compatibility envelope authentication failed.",
                exception);
        }

        ValidateOpenedCiphertextOverhead(
            headerCiphertext.Length,
            openedHeader.Plaintext.Length,
            "header");
        ValidateOpenedCiphertextOverhead(
            payloadCiphertext.Length,
            openedPayload.Plaintext.Length,
            "payload");
        ValidateOpenedResults(openedHeader, openedPayload);

        var replayScope = new CompatibilityEnvelopeReplayScope(
            outer.Capability.Bytes.ToArray(),
            outer.ExpiryBucket,
            outer.ReplayMaterial.ToArray());
        if (!replayGuard.TryAccept(replayScope))
        {
            throw Error(
                CompatibilityEnvelopeError.ReplayRejected,
                "The authenticated compatibility envelope was already accepted.");
        }

        return new CompatibilityEnvelopeOpenResult(
            openedPayload.Plaintext.ToArray(),
            openedPayload.SenderAuthenticationData.ToArray(),
            outer);
    }

    private static void ValidateNegotiatedProfile(OpaqueBundleNegotiatedProfile profile)
    {
        if (profile.WireVersion != OpaqueBundleWireVersion.V1 ||
            !profile.AllowLegacyDpe1 ||
            (profile.SupportedCriticalFeatures & RequiredCriticalFeatures) != RequiredCriticalFeatures)
        {
            throw Error(
                CompatibilityEnvelopeError.FeatureNotNegotiated,
                "P03A requires explicit V1 authenticated-legacy compatibility negotiation.");
        }
    }

    private static void ValidateWriteRequest(CompatibilityEnvelopeWriteRequest request)
    {
        if (request.HeaderNonceContext.Length != CompatibilityEnvelopeLimits.NonceContextLength ||
            request.PayloadNonceContext.Length != CompatibilityEnvelopeLimits.NonceContextLength ||
            request.HeaderNonceContext.Span.SequenceEqual(request.PayloadNonceContext.Span))
        {
            throw Error(
                CompatibilityEnvelopeError.InvalidNonceContext,
                "Header and payload nonce contexts must be distinct 32-byte values.");
        }

        if (request.LegacyDpe1.Length is
            < CompatibilityEnvelopeLimits.MinimumLegacyDpe1Length or
            > CompatibilityEnvelopeLimits.MaximumLegacyDpe1Length ||
            !request.LegacyDpe1.Span.StartsWith("DPE1"u8))
        {
            throw Error(
                CompatibilityEnvelopeError.InvalidLegacyDpe1,
                "The compatibility plaintext must contain bounded exact DPE1 bytes.");
        }

        if (request.RecipientKeyMaterial.IsEmpty || request.SenderAuthenticationSecret.IsEmpty)
        {
            throw Error(
                CompatibilityEnvelopeError.InvalidCryptoResult,
                "Recipient and sender-authentication material must be provided to the crypto adapter.");
        }

        if (request.ReplayMaterial.Length != OpaqueBundleLimits.ReplayMaterialLength)
        {
            throw Error(
                CompatibilityEnvelopeError.InvalidCryptoResult,
                "Replay material must be exactly 16 bytes.");
        }
    }

    private static byte[] BuildAssociatedData(
        OpaqueMailboxCapability capability,
        TransportAttemptId transportAttemptId,
        uint expiryBucket,
        OpaqueBundlePaddingClass paddingClass,
        ReadOnlySpan<byte> replayMaterial,
        ReadOnlySpan<byte> headerNonce,
        ReadOnlySpan<byte> payloadNonce)
    {
        var capabilityKind = capability switch
        {
            OpaqueDepositCapability => (byte)1,
            OpaqueRetrieveCapability => (byte)2,
            _ => throw Error(
                CompatibilityEnvelopeError.InvalidCryptoResult,
                "Only distinct opaque deposit and retrieve capabilities are supported.")
        };
        var capabilityBytes = capability.Bytes.Span;
        var associatedData = new byte[
            AssociatedDataMagic.Length +
            4 +
            4 +
            4 +
            OpaqueBundleLimits.IdentifierLength +
            OpaqueBundleLimits.ReplayMaterialLength +
            2 +
            capabilityBytes.Length +
            CompatibilityEnvelopeLimits.NonceContextLength * 2];
        var offset = 0;
        AssociatedDataMagic.CopyTo(associatedData);
        offset += AssociatedDataMagic.Length;
        associatedData[offset++] = (byte)OpaqueBundleWireVersion.V1;
        associatedData[offset++] = (byte)OpaqueBundlePayloadKind.AuthenticatedLegacyDpe1;
        associatedData[offset++] = capabilityKind;
        associatedData[offset++] = (byte)paddingClass;
        BinaryPrimitives.WriteUInt32BigEndian(
            associatedData.AsSpan(offset, 4),
            (uint)RequiredCriticalFeatures);
        offset += 4;
        BinaryPrimitives.WriteUInt32BigEndian(associatedData.AsSpan(offset, 4), expiryBucket);
        offset += 4;
        transportAttemptId.Bytes.Span.CopyTo(
            associatedData.AsSpan(offset, OpaqueBundleLimits.IdentifierLength));
        offset += OpaqueBundleLimits.IdentifierLength;
        replayMaterial.CopyTo(
            associatedData.AsSpan(offset, OpaqueBundleLimits.ReplayMaterialLength));
        offset += OpaqueBundleLimits.ReplayMaterialLength;
        BinaryPrimitives.WriteUInt16BigEndian(
            associatedData.AsSpan(offset, 2),
            checked((ushort)capabilityBytes.Length));
        offset += 2;
        capabilityBytes.CopyTo(associatedData.AsSpan(offset));
        offset += capabilityBytes.Length;
        headerNonce.CopyTo(
            associatedData.AsSpan(offset, CompatibilityEnvelopeLimits.NonceContextLength));
        offset += CompatibilityEnvelopeLimits.NonceContextLength;
        payloadNonce.CopyTo(
            associatedData.AsSpan(offset, CompatibilityEnvelopeLimits.NonceContextLength));
        return associatedData;
    }

    private static byte[] FrameSealedPart(
        ReadOnlySpan<byte> nonce,
        CompatibilityEnvelopeSealedResult result,
        int plaintextLength,
        int maximumLength,
        string part)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (result.Ciphertext.Length <= plaintextLength ||
            result.Ciphertext.Length > plaintextLength + CompatibilityEnvelopeLimits.MaximumCryptoOverhead ||
            result.Ciphertext.Length > maximumLength - CompatibilityEnvelopeLimits.NonceContextLength)
        {
            throw Error(
                CompatibilityEnvelopeError.InvalidCryptoResult,
                $"The crypto adapter returned an invalid {part} ciphertext length.");
        }

        var framed = new byte[CompatibilityEnvelopeLimits.NonceContextLength + result.Ciphertext.Length];
        nonce.CopyTo(framed);
        result.Ciphertext.Span.CopyTo(framed.AsSpan(CompatibilityEnvelopeLimits.NonceContextLength));
        return framed;
    }

    private static (ReadOnlyMemory<byte> Nonce, ReadOnlyMemory<byte> Ciphertext) ParseSealedPart(
        ReadOnlyMemory<byte> framed,
        string part)
    {
        if (framed.Length <= CompatibilityEnvelopeLimits.NonceContextLength)
        {
            throw Error(
                CompatibilityEnvelopeError.InvalidCryptoResult,
                $"The framed {part} ciphertext is truncated.");
        }

        return (
            framed[..CompatibilityEnvelopeLimits.NonceContextLength].ToArray(),
            framed[CompatibilityEnvelopeLimits.NonceContextLength..].ToArray());
    }

    private static void ValidateOpenedResults(
        CompatibilityEnvelopeOpenedResult header,
        CompatibilityEnvelopeOpenedResult payload)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(payload);

        if (header.SenderAuthenticationData.Length is
                < CompatibilityEnvelopeLimits.MinimumSenderAuthenticationLength or
                > CompatibilityEnvelopeLimits.MaximumSenderAuthenticationLength ||
            payload.SenderAuthenticationData.Length != header.SenderAuthenticationData.Length ||
            !CryptographicOperations.FixedTimeEquals(
                header.SenderAuthenticationData.Span,
                payload.SenderAuthenticationData.Span))
        {
            throw Error(
                CompatibilityEnvelopeError.SenderAuthenticationMismatch,
                "Header and payload sender authentication results are invalid or do not match.");
        }

        if (header.Plaintext.Length != CompatibilityEnvelopeLimits.HeaderPlaintextLength ||
            !header.Plaintext.Span[..HeaderPlaintextMagic.Length].SequenceEqual(HeaderPlaintextMagic))
        {
            throw Error(
                CompatibilityEnvelopeError.MalformedHeader,
                "The decrypted compatibility header is malformed.");
        }

        var declaredPayloadLength = BinaryPrimitives.ReadUInt32BigEndian(
            header.Plaintext.Span[HeaderPlaintextMagic.Length..]);
        if (declaredPayloadLength != payload.Plaintext.Length)
        {
            throw Error(
                CompatibilityEnvelopeError.MalformedHeader,
                "The authenticated compatibility header does not match the payload length.");
        }

        if (payload.Plaintext.Length is
                < CompatibilityEnvelopeLimits.MinimumLegacyDpe1Length or
                > CompatibilityEnvelopeLimits.MaximumLegacyDpe1Length ||
            !payload.Plaintext.Span.StartsWith("DPE1"u8))
        {
            throw Error(
                CompatibilityEnvelopeError.InvalidLegacyDpe1,
                "The decrypted compatibility payload is not exact bounded DPE1 data.");
        }
    }

    private static void ValidateOpenedCiphertextOverhead(
        int ciphertextLength,
        int plaintextLength,
        string part)
    {
        var overhead = (long)ciphertextLength - plaintextLength;
        if (overhead is < 1 or > CompatibilityEnvelopeLimits.MaximumCryptoOverhead)
        {
            throw Error(
                CompatibilityEnvelopeError.InvalidCryptoResult,
                $"The authenticated {part} ciphertext overhead is outside strict bounds.");
        }
    }

    private static CompatibilityEnvelopeException Error(
        CompatibilityEnvelopeError error,
        string message,
        Exception? innerException = null) =>
        new(error, message, innerException);
}
