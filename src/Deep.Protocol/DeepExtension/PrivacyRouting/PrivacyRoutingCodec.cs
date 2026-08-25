using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepExtension.PrivacyRouting;

public static class PrivacyRoutingRequestBuilder
{
    private static readonly byte[] OperationIdDomain =
        "Deep/PrivacyRouting/V1/canonical-mailbox-operation-id"u8.ToArray();

    public static PrivacyRoutingBuiltRequest BuildForCanonicalMailboxRequest(
        IReadOnlyList<PrivacyRoutingHop> route,
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> canonicalMailboxRequest,
        int paddingBlockBytes = PrivacyRoutingLimits.DefaultPaddingBlockBytes)
    {
        if (canonicalMailboxRequest.Length > PrivacyRoutingLimits.MaximumApplicationPayloadBytes)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidLength, "The canonical mailbox request exceeds the privacy-routing limit.");
        }

        Span<byte> length = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(length, checked((ulong)canonicalMailboxRequest.Length));
        var operationIdInput = new byte[checked(OperationIdDomain.Length + length.Length + canonicalMailboxRequest.Length)];
        try
        {
            OperationIdDomain.CopyTo(operationIdInput, 0);
            length.CopyTo(operationIdInput.AsSpan(OperationIdDomain.Length));
            canonicalMailboxRequest.CopyTo(operationIdInput.AsSpan(OperationIdDomain.Length + length.Length));
            var operationId = SHA256.HashData(operationIdInput);
            var attemptId = RandomNonzero32();
            try
            {
                return Build(
                    route,
                    operation,
                    operationId,
                    attemptId,
                    canonicalMailboxRequest,
                    paddingBlockBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(operationId);
                CryptographicOperations.ZeroMemory(attemptId);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(operationIdInput);
        }
    }

    public static PrivacyRoutingBuiltRequest Build(
        IReadOnlyList<PrivacyRoutingHop> route,
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> attemptId,
        ReadOnlySpan<byte> payload,
        int paddingBlockBytes = PrivacyRoutingLimits.DefaultPaddingBlockBytes)
    {
        ValidateBuild(route, operation, operationId, attemptId, payload, paddingBlockBytes);

        using var replyKeyPair = PublicKeyBox.GenerateKeyPair();
        var replyPrivateKey = replyKeyPair.PrivateKey.ToArray();
        try
        {
            var exitReplayId = RandomNonzero32();
            var current = PrivacyRoutingRequestCodec.SealExit(
                route[2].X25519PublicKeySpan,
                exitReplayId,
                operation,
                operationId,
                attemptId,
                replyKeyPair.PublicKey,
                payload,
                paddingBlockBytes);

            for (var hop = 1; hop >= 0; hop--)
            {
                current = PrivacyRoutingRequestCodec.SealRelay(
                    route[hop].X25519PublicKeySpan,
                    RandomNonzero32(),
                    route[hop + 1].RouterIdSpan,
                    current,
                    paddingBlockBytes);
            }

            var context = new PrivacyRoutingReplyContext(
                operation,
                operationId,
                attemptId,
                replyPrivateKey);
            replyPrivateKey = Array.Empty<byte>();
            return new PrivacyRoutingBuiltRequest(current, context);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(replyPrivateKey);
        }
    }

    private static void ValidateBuild(
        IReadOnlyList<PrivacyRoutingHop> route,
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> attemptId,
        ReadOnlySpan<byte> payload,
        int paddingBlockBytes)
    {
        ArgumentNullException.ThrowIfNull(route);
        if (route.Count != PrivacyRoutingLimits.RouteHopCount || route.Any(static hop => hop is null))
        {
            throw Error(PrivacyRoutingProtocolError.InvalidRoute, "A privacy route must contain exactly three hops.");
        }

        for (var left = 0; left < route.Count; left++)
        {
            for (var right = left + 1; right < route.Count; right++)
            {
                if (CryptographicOperations.FixedTimeEquals(route[left].RouterIdSpan, route[right].RouterIdSpan))
                {
                    throw Error(PrivacyRoutingProtocolError.InvalidRoute, "A privacy route cannot repeat a router id.");
                }
            }
        }

        PrivacyRoutingWire.ValidateOperation(operation);
        PrivacyRoutingWire.ValidateId(operationId, PrivacyRoutingProtocolError.InvalidIdentifier, "operation id");
        PrivacyRoutingWire.ValidateId(attemptId, PrivacyRoutingProtocolError.InvalidIdentifier, "attempt id");
        if (payload.Length > PrivacyRoutingLimits.MaximumApplicationPayloadBytes)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidLength, "The application payload exceeds the privacy-routing limit.");
        }

        PrivacyRoutingWire.ValidatePaddingBlock(paddingBlockBytes);
    }

    private static byte[] RandomNonzero32()
    {
        var value = SodiumCore.GetRandomBytes(PrivacyRoutingLimits.HopReplayIdBytes);
        if (PrivacyRoutingWire.IsZero(value))
        {
            CryptographicOperations.ZeroMemory(value);
            throw Error(PrivacyRoutingProtocolError.InvalidIdentifier, "The CSPRNG produced an invalid replay id.");
        }

        return value;
    }

    private static PrivacyRoutingProtocolException Error(
        PrivacyRoutingProtocolError error,
        string message) => new(error, message);
}

public static class PrivacyRoutingRequestCodec
{
    private static readonly byte[] RelayMagic = "DRL1"u8.ToArray();
    private static readonly byte[] ExitMagic = "DRE1"u8.ToArray();
    private const int RelayFixedBytes = 80;
    private const int ExitFixedBytes = 144;

    public static PrivacyRoutingOpenedLayer Open(
        ReadOnlySpan<byte> frame,
        ReadOnlySpan<byte> recipientX25519PrivateKey)
    {
        var plaintext = PrivacyRoutingWire.OpenEnvelope(
            frame,
            recipientX25519PrivateKey,
            PrivacyRoutingWire.RequestPurpose);
        try
        {
            if (plaintext.AsSpan(0, 4).SequenceEqual(RelayMagic))
            {
                return DecodeRelay(plaintext);
            }

            if (plaintext.AsSpan(0, 4).SequenceEqual(ExitMagic))
            {
                return DecodeExit(plaintext);
            }

            throw Error(PrivacyRoutingProtocolError.UnsupportedVersion, "The opened request layer has an unknown magic value.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    internal static byte[] SealRelay(
        ReadOnlySpan<byte> recipientPublicKey,
        ReadOnlySpan<byte> replayId,
        ReadOnlySpan<byte> nextRouterId,
        ReadOnlySpan<byte> innerFrame,
        int paddingBlockBytes)
    {
        PrivacyRoutingWire.ValidateId(replayId, PrivacyRoutingProtocolError.InvalidIdentifier, "hop replay id");
        PrivacyRoutingWire.ValidateId(nextRouterId, PrivacyRoutingProtocolError.InvalidIdentifier, "next router id");
        PrivacyRoutingWire.ValidateInnerFrame(innerFrame);
        var padding = PrivacyRoutingWire.PaddingLength(RelayFixedBytes, innerFrame.Length, paddingBlockBytes);
        var plaintext = new byte[checked(RelayFixedBytes + innerFrame.Length + padding)];
        try
        {
            RelayMagic.CopyTo(plaintext, 0);
            plaintext[4] = 1;
            plaintext[5] = 1;
            plaintext[6] = 1;
            replayId.CopyTo(plaintext.AsSpan(8, 32));
            nextRouterId.CopyTo(plaintext.AsSpan(40, 32));
            BinaryPrimitives.WriteUInt32BigEndian(plaintext.AsSpan(72, 4), checked((uint)innerFrame.Length));
            BinaryPrimitives.WriteUInt32BigEndian(plaintext.AsSpan(76, 4), checked((uint)padding));
            innerFrame.CopyTo(plaintext.AsSpan(RelayFixedBytes));
            return PrivacyRoutingWire.SealEnvelope(plaintext, recipientPublicKey, PrivacyRoutingWire.RequestPurpose);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    internal static byte[] SealExit(
        ReadOnlySpan<byte> recipientPublicKey,
        ReadOnlySpan<byte> replayId,
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> attemptId,
        ReadOnlySpan<byte> replyPublicKey,
        ReadOnlySpan<byte> payload,
        int paddingBlockBytes)
    {
        PrivacyRoutingWire.ValidateId(replayId, PrivacyRoutingProtocolError.InvalidIdentifier, "exit replay id");
        PrivacyRoutingWire.ValidateOperation(operation);
        PrivacyRoutingWire.ValidateId(operationId, PrivacyRoutingProtocolError.InvalidIdentifier, "operation id");
        PrivacyRoutingWire.ValidateId(attemptId, PrivacyRoutingProtocolError.InvalidIdentifier, "attempt id");
        PrivacyRoutingWire.ValidatePublicKey(replyPublicKey);
        var padding = PrivacyRoutingWire.PaddingLength(ExitFixedBytes, payload.Length, paddingBlockBytes);
        var plaintext = new byte[checked(ExitFixedBytes + payload.Length + padding)];
        try
        {
            ExitMagic.CopyTo(plaintext, 0);
            plaintext[4] = 1;
            plaintext[5] = 1;
            plaintext[6] = 2;
            plaintext[7] = (byte)operation;
            replayId.CopyTo(plaintext.AsSpan(8, 32));
            operationId.CopyTo(plaintext.AsSpan(40, 32));
            attemptId.CopyTo(plaintext.AsSpan(72, 32));
            replyPublicKey.CopyTo(plaintext.AsSpan(104, 32));
            BinaryPrimitives.WriteUInt32BigEndian(plaintext.AsSpan(136, 4), checked((uint)payload.Length));
            BinaryPrimitives.WriteUInt32BigEndian(plaintext.AsSpan(140, 4), checked((uint)padding));
            payload.CopyTo(plaintext.AsSpan(ExitFixedBytes));
            return PrivacyRoutingWire.SealEnvelope(plaintext, recipientPublicKey, PrivacyRoutingWire.RequestPurpose);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static PrivacyRoutingRelayLayer DecodeRelay(ReadOnlySpan<byte> plaintext)
    {
        PrivacyRoutingWire.ValidateCommonPlaintext(plaintext, RelayFixedBytes, expectedKind: 1);
        var replayId = plaintext.Slice(8, 32);
        var nextRouterId = plaintext.Slice(40, 32);
        PrivacyRoutingWire.ValidateId(replayId, PrivacyRoutingProtocolError.InvalidIdentifier, "hop replay id");
        PrivacyRoutingWire.ValidateId(nextRouterId, PrivacyRoutingProtocolError.InvalidIdentifier, "next router id");
        var payload = PrivacyRoutingWire.ValidatePayloadAndPadding(plaintext, RelayFixedBytes, 72, 76);
        PrivacyRoutingWire.ValidateInnerFrame(payload);
        return new PrivacyRoutingRelayLayer(replayId, nextRouterId, payload);
    }

    private static PrivacyRoutingExitLayer DecodeExit(ReadOnlySpan<byte> plaintext)
    {
        PrivacyRoutingWire.ValidateCommonPlaintext(plaintext, ExitFixedBytes, expectedKind: 2);
        var operation = (PrivacyRoutingOperation)plaintext[7];
        PrivacyRoutingWire.ValidateOperation(operation);
        var replayId = plaintext.Slice(8, 32);
        var operationId = plaintext.Slice(40, 32);
        var attemptId = plaintext.Slice(72, 32);
        var replyPublicKey = plaintext.Slice(104, 32);
        PrivacyRoutingWire.ValidateId(replayId, PrivacyRoutingProtocolError.InvalidIdentifier, "exit replay id");
        PrivacyRoutingWire.ValidateId(operationId, PrivacyRoutingProtocolError.InvalidIdentifier, "operation id");
        PrivacyRoutingWire.ValidateId(attemptId, PrivacyRoutingProtocolError.InvalidIdentifier, "attempt id");
        PrivacyRoutingWire.ValidatePublicKey(replyPublicKey);
        var payload = PrivacyRoutingWire.ValidatePayloadAndPadding(plaintext, ExitFixedBytes, 136, 140);
        if (payload.Length > PrivacyRoutingLimits.MaximumApplicationPayloadBytes)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidLength, "The exit payload exceeds the application limit.");
        }

        return new PrivacyRoutingExitLayer(replayId, operation, operationId, attemptId, replyPublicKey, payload);
    }

    private static PrivacyRoutingProtocolException Error(
        PrivacyRoutingProtocolError error,
        string message) => new(error, message);
}

public static class PrivacyRoutingResponseCodec
{
    private static readonly byte[] Magic = "DRS1"u8.ToArray();
    private const int FixedBytes = 80;

    public static byte[] Seal(
        PrivacyRoutingExitLayer request,
        ReadOnlySpan<byte> payload,
        int paddingBlockBytes = PrivacyRoutingLimits.DefaultPaddingBlockBytes)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (payload.Length > PrivacyRoutingLimits.MaximumApplicationPayloadBytes)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidLength, "The response payload exceeds the application limit.");
        }

        PrivacyRoutingWire.ValidatePaddingBlock(paddingBlockBytes);
        var padding = PrivacyRoutingWire.PaddingLength(FixedBytes, payload.Length, paddingBlockBytes);
        var plaintext = new byte[checked(FixedBytes + payload.Length + padding)];
        try
        {
            Magic.CopyTo(plaintext, 0);
            plaintext[4] = 1;
            plaintext[5] = 1;
            plaintext[6] = (byte)request.Operation;
            request.OperationIdSpan.CopyTo(plaintext.AsSpan(8, 32));
            request.AttemptIdSpan.CopyTo(plaintext.AsSpan(40, 32));
            BinaryPrimitives.WriteUInt32BigEndian(plaintext.AsSpan(72, 4), checked((uint)payload.Length));
            BinaryPrimitives.WriteUInt32BigEndian(plaintext.AsSpan(76, 4), checked((uint)padding));
            payload.CopyTo(plaintext.AsSpan(FixedBytes));
            return PrivacyRoutingWire.SealEnvelope(
                plaintext,
                request.ReplyPublicKeySpan,
                PrivacyRoutingWire.ResponsePurpose);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public static PrivacyRoutingOpenedResponse Open(
        ReadOnlySpan<byte> frame,
        PrivacyRoutingReplyContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var plaintext = PrivacyRoutingWire.OpenEnvelope(
            frame,
            context.GetPrivateKey(),
            PrivacyRoutingWire.ResponsePurpose);
        try
        {
            PrivacyRoutingWire.ValidateCommonPlaintext(plaintext, FixedBytes, expectedKind: null);
            if (!plaintext.AsSpan(0, 4).SequenceEqual(Magic))
            {
                throw Error(PrivacyRoutingProtocolError.UnsupportedVersion, "The opened response has an unknown magic value.");
            }

            var operation = (PrivacyRoutingOperation)plaintext[6];
            PrivacyRoutingWire.ValidateOperation(operation);
            if (plaintext[7] != 0 ||
                operation != context.Operation ||
                !CryptographicOperations.FixedTimeEquals(plaintext.AsSpan(8, 32), context.OperationIdSpan) ||
                !CryptographicOperations.FixedTimeEquals(plaintext.AsSpan(40, 32), context.AttemptIdSpan))
            {
                throw Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "The response is not bound to this request context.");
            }

            var payload = PrivacyRoutingWire.ValidatePayloadAndPadding(plaintext, FixedBytes, 72, 76);
            if (payload.Length > PrivacyRoutingLimits.MaximumApplicationPayloadBytes)
            {
                throw Error(PrivacyRoutingProtocolError.InvalidLength, "The response payload exceeds the application limit.");
            }

            return new PrivacyRoutingOpenedResponse(operation, payload);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static PrivacyRoutingProtocolException Error(
        PrivacyRoutingProtocolError error,
        string message) => new(error, message);
}

internal static class PrivacyRoutingWire
{
    internal const byte RequestPurpose = 1;
    internal const byte ResponsePurpose = 2;
    private const byte Suite = 1;
    private const int EnvelopeFixedBytes = 68;
    private const int MacBytes = 16;
    private static readonly byte[] EnvelopeMagic = "DRF1"u8.ToArray();

    internal static byte[] SealEnvelope(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> recipientPublicKey,
        byte purpose)
    {
        ValidatePublicKey(recipientPublicKey);
        using var ephemeral = PublicKeyBox.GenerateKeyPair();
        var nonce = PublicKeyBox.GenerateNonce();
        byte[] ciphertext;
        var plaintextCopy = plaintext.ToArray();
        try
        {
            ciphertext = PublicKeyBox.Create(plaintextCopy, nonce, ephemeral.PrivateKey, recipientPublicKey.ToArray());
        }
        catch (Exception exception) when (exception is not PrivacyRoutingProtocolException)
        {
            throw Error(PrivacyRoutingProtocolError.AuthenticationFailed, "The privacy frame could not be sealed.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextCopy);
        }

        var frameLength = checked(EnvelopeFixedBytes + ciphertext.Length);
        if (frameLength is < ManagedIngress.ManagedIngressLimits.MinimumOpaqueFrameBytes or
            > ManagedIngress.ManagedIngressLimits.MaximumOpaqueFrameBytes)
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            throw Error(PrivacyRoutingProtocolError.FrameLengthOutOfRange, "The sealed privacy frame is outside managed-ingress bounds.");
        }

        var frame = new byte[frameLength];
        EnvelopeMagic.CopyTo(frame, 0);
        frame[4] = 1;
        frame[5] = 1;
        frame[6] = Suite;
        frame[7] = purpose;
        ephemeral.PublicKey.CopyTo(frame, 8);
        nonce.CopyTo(frame, 40);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(64, 4), checked((uint)ciphertext.Length));
        ciphertext.CopyTo(frame, EnvelopeFixedBytes);
        CryptographicOperations.ZeroMemory(ciphertext);
        return frame;
    }

    internal static byte[] OpenEnvelope(
        ReadOnlySpan<byte> frame,
        ReadOnlySpan<byte> recipientPrivateKey,
        byte expectedPurpose)
    {
        if (frame.Length is < EnvelopeFixedBytes + MacBytes or
            > ManagedIngress.ManagedIngressLimits.MaximumOpaqueFrameBytes)
        {
            throw Error(PrivacyRoutingProtocolError.FrameLengthOutOfRange, "The privacy frame is outside strict bounds.");
        }

        if (!frame[..4].SequenceEqual(EnvelopeMagic) || frame[4] != 1 || frame[5] != 1)
        {
            throw Error(PrivacyRoutingProtocolError.UnsupportedVersion, "The privacy frame version is unsupported.");
        }

        if (frame[6] != Suite)
        {
            throw Error(PrivacyRoutingProtocolError.UnsupportedSuite, "The privacy frame crypto suite is unsupported.");
        }

        if (frame[7] != expectedPurpose)
        {
            throw Error(PrivacyRoutingProtocolError.WrongFramePurpose, "The privacy frame purpose is invalid for this operation.");
        }

        if (recipientPrivateKey.Length != PrivacyRoutingLimits.X25519KeyBytes || IsZero(recipientPrivateKey))
        {
            throw Error(PrivacyRoutingProtocolError.InvalidKeyLength, "An independent X25519 private key must be a nonzero 32-byte value.");
        }

        var ciphertextLength = BinaryPrimitives.ReadUInt32BigEndian(frame.Slice(64, 4));
        if (ciphertextLength < MacBytes || ciphertextLength != frame.Length - EnvelopeFixedBytes)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidLength, "The privacy frame ciphertext length is non-canonical.");
        }

        var privateKeyCopy = recipientPrivateKey.ToArray();
        try
        {
            return PublicKeyBox.Open(
                frame[EnvelopeFixedBytes..].ToArray(),
                frame.Slice(40, 24).ToArray(),
                privateKeyCopy,
                frame.Slice(8, 32).ToArray());
        }
        catch (Exception exception)
        {
            throw Error(PrivacyRoutingProtocolError.AuthenticationFailed, "The privacy frame authentication failed.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKeyCopy);
        }
    }

    internal static void ValidateCommonPlaintext(
        ReadOnlySpan<byte> plaintext,
        int fixedBytes,
        byte? expectedKind)
    {
        if (plaintext.Length < fixedBytes)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidLength, "The opened privacy payload is truncated.");
        }

        if (plaintext[4] != 1 || plaintext[5] != 1)
        {
            throw Error(PrivacyRoutingProtocolError.UnsupportedVersion, "The opened privacy payload version is unsupported.");
        }

        if (expectedKind.HasValue && plaintext[6] != expectedKind.Value)
        {
            throw Error(PrivacyRoutingProtocolError.UnsupportedVersion, "The privacy layer kind is invalid.");
        }

        if (expectedKind == 1 && plaintext[7] != 0)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidPadding, "A reserved privacy layer field is nonzero.");
        }
    }

    internal static ReadOnlySpan<byte> ValidatePayloadAndPadding(
        ReadOnlySpan<byte> plaintext,
        int fixedBytes,
        int payloadLengthOffset,
        int paddingLengthOffset)
    {
        var payloadLength = BinaryPrimitives.ReadUInt32BigEndian(plaintext.Slice(payloadLengthOffset, 4));
        var paddingLength = BinaryPrimitives.ReadUInt32BigEndian(plaintext.Slice(paddingLengthOffset, 4));
        var expected = checked((ulong)fixedBytes + payloadLength + paddingLength);
        if (expected != (ulong)plaintext.Length)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidLength, "The opened privacy payload lengths are non-canonical.");
        }

        var payloadLengthInt = checked((int)payloadLength);
        var paddingLengthInt = checked((int)paddingLength);
        var canonicalPadding = false;
        for (var block = PrivacyRoutingLimits.MinimumPaddingBlockBytes;
             block <= PrivacyRoutingLimits.MaximumPaddingBlockBytes;
             block <<= 1)
        {
            if (PaddingLength(fixedBytes, payloadLengthInt, block) == paddingLengthInt)
            {
                canonicalPadding = true;
                break;
            }
        }

        if (!canonicalPadding)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidPadding, "The privacy padding length does not match an allowed block policy.");
        }

        if (!IsZero(plaintext.Slice(fixedBytes + payloadLengthInt, paddingLengthInt)))
        {
            throw Error(PrivacyRoutingProtocolError.InvalidPadding, "Privacy padding must contain only zero bytes.");
        }

        return plaintext.Slice(fixedBytes, payloadLengthInt);
    }

    internal static int PaddingLength(int fixedBytes, int payloadBytes, int paddingBlockBytes)
    {
        ValidatePaddingBlock(paddingBlockBytes);
        var unpaddedFrameLength = checked(EnvelopeFixedBytes + MacBytes + fixedBytes + payloadBytes);
        return (paddingBlockBytes - (unpaddedFrameLength % paddingBlockBytes)) % paddingBlockBytes;
    }

    internal static void ValidatePaddingBlock(int paddingBlockBytes)
    {
        if (paddingBlockBytes is < PrivacyRoutingLimits.MinimumPaddingBlockBytes or
            > PrivacyRoutingLimits.MaximumPaddingBlockBytes ||
            (paddingBlockBytes & (paddingBlockBytes - 1)) != 0)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidPadding, "The padding block must be a power of two from 256 through 65536 bytes.");
        }
    }

    internal static void ValidateInnerFrame(ReadOnlySpan<byte> frame)
    {
        if (frame.Length is < EnvelopeFixedBytes + MacBytes or
            > ManagedIngress.ManagedIngressLimits.MaximumOpaqueFrameBytes ||
            !frame[..4].SequenceEqual(EnvelopeMagic) ||
            frame[4] != 1 || frame[5] != 1 || frame[6] != Suite || frame[7] != RequestPurpose)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidLength, "A relay inner frame is not a bounded canonical request envelope.");
        }

        var ciphertextLength = BinaryPrimitives.ReadUInt32BigEndian(frame.Slice(64, 4));
        if (ciphertextLength < MacBytes || ciphertextLength != frame.Length - EnvelopeFixedBytes)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidLength, "A relay inner frame length is non-canonical.");
        }
    }

    internal static void ValidateOperation(PrivacyRoutingOperation operation)
    {
        if (operation is not (PrivacyRoutingOperation.Store or PrivacyRoutingOperation.Retrieve or PrivacyRoutingOperation.Acknowledge))
        {
            throw Error(PrivacyRoutingProtocolError.InvalidOperation, "The privacy-routing operation is unsupported.");
        }
    }

    internal static void ValidateId(
        ReadOnlySpan<byte> value,
        PrivacyRoutingProtocolError error,
        string field)
    {
        if (value.Length != 32 || IsZero(value))
        {
            throw Error(error, $"The {field} must be a nonzero 32-byte value.");
        }
    }

    internal static void ValidatePublicKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != PrivacyRoutingLimits.X25519KeyBytes || IsZero(key))
        {
            throw Error(PrivacyRoutingProtocolError.InvalidKeyLength, "An independent X25519 public key must be a nonzero 32-byte value.");
        }
    }

    internal static bool IsZero(ReadOnlySpan<byte> value)
    {
        var aggregate = 0;
        foreach (var item in value)
        {
            aggregate |= item;
        }

        return aggregate == 0;
    }

    private static PrivacyRoutingProtocolException Error(
        PrivacyRoutingProtocolError error,
        string message,
        Exception? exception = null) => new(error, message, exception);
}
