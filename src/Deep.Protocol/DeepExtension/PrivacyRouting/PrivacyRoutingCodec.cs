using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.GroupV1;
using Sodium;

namespace Deep.Protocol.DeepExtension.PrivacyRouting;

public sealed partial class PrivacyRoutingCodec
{
    public const bool RuntimeActivation = false;
}

internal static class PrivacyRoutingRequestBuilder
{
    public static PrivacyRoutingBuiltRequestCore BuildForCanonicalRequest(
        ReadOnlySpan<byte> networkId,
        IReadOnlyList<PrivacyRoutingHop> route,
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> canonicalRequest,
        int paddingBlockBytes = PrivacyRoutingLimits.DefaultPaddingBlockBytes)
    {
        using var entropy = PrivacyRoutingTestEntropy.CreateProductionRequest();
        return PrivacyRoutingValidationBuilder.BuildForCanonicalRequest(
            networkId, route, operation, canonicalRequest, entropy, paddingBlockBytes);
    }

}

internal static class PrivacyRoutingRequestCodec
{
    public static PrivacyRoutingOpenedLayer Open(
        ReadOnlySpan<byte> frame,
        PrivacyRoutingReceiveKey key,
        IPrivacyRoutingReplayStateStore replayStore)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(replayStore);
        return PrivacyRoutingValidationBuilder.OpenRequest(frame, key, replayStore);
    }
}

internal static class PrivacyRoutingResponseCodec
{
    public static byte[] Seal(
        PrivacyRoutingExitLayer request,
        PrivacyRoutingTerminalResult result,
        int paddingBlockBytes = PrivacyRoutingLimits.DefaultPaddingBlockBytes)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(result);
        using var entropy = PrivacyRoutingTestEntropy.CreateProductionResponse();
        return PrivacyRoutingValidationBuilder.SealResponse(request, result, entropy, paddingBlockBytes);
    }

    public static PrivacyRoutingOpenedResponseCore Open(ReadOnlySpan<byte> frame, PrivacyRoutingReplyContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return PrivacyRoutingValidationBuilder.OpenResponse(frame, context);
    }
}

/// <summary>Internal deterministic ONION-01 KAT seam. Production entrypoints never accept it.</summary>
internal static class PrivacyRoutingValidationBuilder
{
    internal static PrivacyRoutingBuiltRequestCore BuildForCanonicalRequest(ReadOnlySpan<byte> network, IReadOnlyList<PrivacyRoutingHop> route, PrivacyRoutingOperation operation, ReadOnlySpan<byte> request, PrivacyRoutingTestEntropy entropy, int block = PrivacyRoutingLimits.DefaultPaddingBlockBytes)
    {
        PrivacyRoutingWire.ValidateNetwork(network);
        PrivacyRoutingPayloadVerifier.ValidateRequest(network, operation, request);
        var operationId = PrivacyRoutingWire.HashCanonicalOperation(request);
        try { return Build(network, route, operation, operationId, entropy.AttemptId, request, entropy, block); }
        finally { CryptographicOperations.ZeroMemory(operationId); }
    }

    // The frozen framing KAT predates MAU2 and intentionally carries an empty Store payload.
    // This seam is internal and cannot be reached by the production builder/open entrypoints.
    internal static PrivacyRoutingBuiltRequestCore BuildFrozenKatVector(ReadOnlySpan<byte> network, IReadOnlyList<PrivacyRoutingHop> route, PrivacyRoutingOperation operation, ReadOnlySpan<byte> request, PrivacyRoutingTestEntropy entropy, int block = PrivacyRoutingLimits.DefaultPaddingBlockBytes)
    {
        PrivacyRoutingWire.ValidateNetwork(network);
        var operationId = PrivacyRoutingWire.HashCanonicalOperation(request);
        try { return Build(network, route, operation, operationId, entropy.AttemptId, request, entropy, block, validateCanonicalRequest: false); }
        finally { CryptographicOperations.ZeroMemory(operationId); }
    }

    internal static PrivacyRoutingBuiltRequestCore Build(ReadOnlySpan<byte> network, IReadOnlyList<PrivacyRoutingHop> route, PrivacyRoutingOperation operation, ReadOnlySpan<byte> operationId, ReadOnlySpan<byte> attemptId, ReadOnlySpan<byte> request, PrivacyRoutingTestEntropy entropy, int block = PrivacyRoutingLimits.DefaultPaddingBlockBytes, bool validateCanonicalRequest = true)
    {
        PrivacyRoutingWire.ValidateNetwork(network); ValidateRoute(route); PrivacyRoutingWire.ValidateOperation(operation); PrivacyRoutingWire.ValidateId(operationId, PrivacyRoutingProtocolError.InvalidIdentifier, "operation id"); PrivacyRoutingWire.ValidateId(attemptId, PrivacyRoutingProtocolError.InvalidIdentifier, "attempt id");
        if (validateCanonicalRequest) PrivacyRoutingPayloadVerifier.ValidateRequest(network, operation, request);
        PrivacyRoutingWire.ValidatePaddingBlock(block); entropy.Validate();
        var replyPrivate = entropy.ReplyPrivateScalar.ToArray(); var replyPublic = ScalarMult.Base(replyPrivate); PrivacyRoutingWire.ValidatePublicKey(replyPublic);
        var owner = PrivacyRoutingWire.Sha256Domain("Deep/XPoint/V1/reply-owner", replyPublic); var keyId = PrivacyRoutingWire.Sha256Domain("Deep/XPoint/V1/reply-key", replyPublic);
        try
        {
            // Frozen vector entropy is ordered by sealing order: exit, core, ingress.
            // Replay identifiers remain ordered by route hop: ingress, core, exit.
            var exitFrame = SealExit(network, route[2], entropy.ReplayIds[2], operation, operationId, attemptId, replyPublic, request, entropy.RequestEphemeralPrivateScalars[0], entropy.RequestNonces[0], block);
            try
            {
                var coreFrame = SealRelay(network, route[1], entropy.ReplayIds[1], route[2], exitFrame, entropy.RequestEphemeralPrivateScalars[1], entropy.RequestNonces[1], block);
                try
                {
                    var ingressFrame = SealRelay(network, route[0], entropy.ReplayIds[0], route[1], coreFrame, entropy.RequestEphemeralPrivateScalars[2], entropy.RequestNonces[2], block);
                    var context = new PrivacyRoutingReplyContext(operation, network, owner, keyId, replyPublic, operationId, attemptId, request, replyPrivate, entropy.TimeProvider, entropy.ReplyLifetime);
                    replyPrivate = Array.Empty<byte>();
                    return new PrivacyRoutingBuiltRequestCore(ingressFrame, context);
                }
                finally { CryptographicOperations.ZeroMemory(coreFrame); }
            }
            finally { CryptographicOperations.ZeroMemory(exitFrame); }
        }
        finally { CryptographicOperations.ZeroMemory(replyPrivate); CryptographicOperations.ZeroMemory(replyPublic); CryptographicOperations.ZeroMemory(owner); CryptographicOperations.ZeroMemory(keyId); }
    }

    internal static PrivacyRoutingOpenedLayer OpenRequest(ReadOnlySpan<byte> frame, PrivacyRoutingReceiveKey key, IPrivacyRoutingReplayStateStore? replay = null, bool allowFrozenKatMailboxPayload = false)
    {
        var plain = PrivacyRoutingWire.OpenRequestEnvelope(frame, key);
        try
        {
            PrivacyRoutingOpenedLayer layer = frame[8] switch
            {
                1 when key.Position is PrivacyRoutingReceivePosition.Ingress or PrivacyRoutingReceivePosition.Core => DecodeRelay(plain, key),
                2 when key.Position == PrivacyRoutingReceivePosition.Exit => DecodeExit(plain, key.NetworkIdSpan, allowFrozenKatMailboxPayload),
                _ => throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidKeyBinding, "Local receive position contradicts XRF1 layer kind.")
            };
            // Replay mutation is after all header, AEAD, plaintext, padding, and nesting checks.
            if (replay is not null)
            {
                PrivacyRoutingReplayResult replayResult;
                try
                {
                    replayResult = replay.TryAccept(
                        new PrivacyRoutingReplayScope(key.NetworkIdSpan, key.OwnerIdSpan, key.KeyIdSpan, key.Epoch, key.Position),
                        layer.ReplayIdSpan);
                }
                catch (Exception exception) when (exception is not PrivacyRoutingProtocolException)
                {
                    layer.Dispose();
                    throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplayRejected, "Replay state could not durably accept this layer.", exception);
                }
                if (replayResult != PrivacyRoutingReplayResult.Accepted)
                {
                    layer.Dispose();
                    throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplayRejected, "Replay state rejected this layer.");
                }
            }
            return layer;
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    internal static PrivacyRoutingOpenedLayer OpenRequestWithSharedSecret(
        ReadOnlySpan<byte> frame,
        VerifiedOnionReceiveContext receive,
        ReadOnlySpan<byte> sharedSecret)
    {
        var plain = PrivacyRoutingWire.OpenRequestEnvelopeWithSharedSecret(frame, receive, sharedSecret);
        try
        {
            return frame[8] switch
            {
                1 when receive.Position is OnionReceivePosition.Ingress or OnionReceivePosition.Core =>
                    DecodeVerifiedRelay(plain, receive),
                2 when receive.Position == OnionReceivePosition.Exit =>
                    DecodeVerifiedExit(plain, receive),
                _ => throw PrivacyRoutingWire.Error(
                    PrivacyRoutingProtocolError.InvalidKeyBinding,
                    "Verified receive position contradicts XRF1 layer kind.")
            };
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    private static PrivacyRoutingRelayLayer DecodeVerifiedRelay(
        ReadOnlySpan<byte> plain,
        VerifiedOnionReceiveContext receive)
    {
        if (plain.Length < 80 || !plain[..4].SequenceEqual(ProtocolMagicBytes.XRL1) ||
            plain[4] != 1 || plain[5] != 1 || plain[6] != 1 || plain[7] != 0)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "XRL1 grammar is invalid.");
        var replay = plain.Slice(8, 32);
        var next = plain.Slice(40, 32);
        PrivacyRoutingWire.ValidateId(replay, PrivacyRoutingProtocolError.InvalidIdentifier, "replay id");
        PrivacyRoutingWire.ValidateId(next, PrivacyRoutingProtocolError.InvalidIdentifier, "next router id");
        var expectedNext = receive.ResolveNextHop(next);
        var inner = PrivacyRoutingWire.ValidatePayloadAndPadding(plain, 80, 72, 76);
        PrivacyRoutingWire.ValidateInnerFrame(inner, expectedNext, receive.Network.NetworkIdSpan);
        return new PrivacyRoutingRelayLayer(replay, next, inner);
    }

    private static PrivacyRoutingExitLayer DecodeVerifiedExit(
        ReadOnlySpan<byte> plain,
        VerifiedOnionReceiveContext receive)
    {
        var exit = DecodeExit(plain, receive.Network.NetworkIdSpan, allowFrozenKatMailboxPayload: false);
        return exit;
    }

    internal static PrivacyRoutingExitLayer OpenExactRoute(ReadOnlySpan<byte> frame, IReadOnlyList<PrivacyRoutingReceiveKey> keys)
    {
        if (keys.Count != 3) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidRoute, "ONION-01 requires exactly three hops.");
        using var first = OpenRequest(frame, keys[0]) as PrivacyRoutingRelayLayer ?? throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidRoute, "Ingress must be relay.");
        using var second = OpenRequest(first.InnerFrame.Span, keys[1]) as PrivacyRoutingRelayLayer ?? throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidRoute, "Core must be relay.");
        return OpenRequest(second.InnerFrame.Span, keys[2], allowFrozenKatMailboxPayload: true) as PrivacyRoutingExitLayer ?? throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidRoute, "Third layer must be exit.");
    }

    internal static byte[] SealResponse(PrivacyRoutingExitLayer request, PrivacyRoutingTerminalResult result, PrivacyRoutingTestEntropy entropy, int block = PrivacyRoutingLimits.DefaultPaddingBlockBytes)
    {
        entropy.ValidateResponse();
        if (request.Operation != result.Operation)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "Terminal result operation is not bound to the request.");
        PrivacyRoutingPayloadVerifier.ValidateResult(request.Operation, request.PayloadSpan, result);
        request.BeginResponseSeal();
        var xpr = PrivacyRoutingResultCodec.Encode(result);
        var owner = PrivacyRoutingWire.Sha256Domain("Deep/XPoint/V1/reply-owner", request.ReplyPublicKeySpan.ToArray());
        var keyId = PrivacyRoutingWire.Sha256Domain("Deep/XPoint/V1/reply-key", request.ReplyPublicKeySpan.ToArray());
        try
        {
            var z = PrivacyRoutingWire.Padding(80, xpr.Length, block); var plain = new byte[80 + xpr.Length + z];
            try { ProtocolMagicBytes.XRS1.CopyTo(plain); plain[4] = plain[5] = 1; plain[6] = (byte)request.Operation; request.OperationIdSpan.CopyTo(plain.AsSpan(8)); request.AttemptIdSpan.CopyTo(plain.AsSpan(40)); BinaryPrimitives.WriteUInt32BigEndian(plain.AsSpan(72), (uint)xpr.Length); plain[76] = PrivacyRoutingWire.PaddingExponent(block); PrivacyRoutingWire.WriteU24(plain.AsSpan(77), z); xpr.CopyTo(plain, 80); return PrivacyRoutingWire.SealEnvelope(plain, request.NetworkIdSpan, owner, 0, keyId, 2, 3, request.ReplyPublicKeySpan, entropy.ResponseEphemeralPrivateScalar, entropy.ResponseNonce); }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        finally { CryptographicOperations.ZeroMemory(xpr); CryptographicOperations.ZeroMemory(owner); CryptographicOperations.ZeroMemory(keyId); }
    }

    internal static PrivacyRoutingOpenedResponseCore OpenResponse(ReadOnlySpan<byte> frame, PrivacyRoutingReplyContext context)
    {
        using var state = context.BeginOpen();
        var complete = false;
        byte[]? plain = null;
        try
        {
            plain = PrivacyRoutingWire.OpenResponseEnvelope(frame, state);
            if (plain.Length < 80 || !plain[..4].SequenceEqual(ProtocolMagicBytes.XRS1) || plain[4] != 1 || plain[5] != 1 || plain[7] != 0) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "XRS1 grammar is invalid.");
            var operation = (PrivacyRoutingOperation)plain[6]; PrivacyRoutingWire.ValidateOperation(operation);
            if (operation != state.Operation || !CryptographicOperations.FixedTimeEquals(plain.AsSpan(8, 32), state.OperationIdSpan) || !CryptographicOperations.FixedTimeEquals(plain.AsSpan(40, 32), state.AttemptIdSpan)) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "XRS1 context binding failed.");
            var xpr = PrivacyRoutingWire.ValidatePayloadAndPadding(plain, 80, 72, 76); var result = PrivacyRoutingResultCodec.Decode(xpr);
            if (result.Operation != operation) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "XPR1 operation mismatches XRS1.");
            PrivacyRoutingPayloadVerifier.ValidateResult(operation, state.CanonicalRequestSpan, result);
            complete = true;
            return new PrivacyRoutingOpenedResponseCore(result);
        }
        finally
        {
            context.CompleteOpen(complete);
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
        }
    }

    private static byte[] SealRelay(ReadOnlySpan<byte> network, PrivacyRoutingHop hop, ReadOnlySpan<byte> replay, PrivacyRoutingHop next, ReadOnlySpan<byte> inner, ReadOnlySpan<byte> ephemeral, ReadOnlySpan<byte> nonce, int block)
    {
        PrivacyRoutingWire.ValidateId(replay, PrivacyRoutingProtocolError.InvalidIdentifier, "replay id"); PrivacyRoutingWire.ValidateInnerFrame(inner, next, network);
        var z = PrivacyRoutingWire.Padding(80, inner.Length, block); var plain = new byte[80 + inner.Length + z];
        try { ProtocolMagicBytes.XRL1.CopyTo(plain); plain[4] = plain[5] = plain[6] = 1; replay.CopyTo(plain.AsSpan(8)); next.RouterOwnerIdSpan.CopyTo(plain.AsSpan(40)); BinaryPrimitives.WriteUInt32BigEndian(plain.AsSpan(72), (uint)inner.Length); plain[76] = PrivacyRoutingWire.PaddingExponent(block); PrivacyRoutingWire.WriteU24(plain.AsSpan(77), z); inner.CopyTo(plain.AsSpan(80)); return PrivacyRoutingWire.SealEnvelope(plain, network, hop.RouterOwnerIdSpan, hop.Epoch, hop.KeyIdSpan, 1, 1, hop.X25519PublicKeySpan, ephemeral, nonce); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }
    private static byte[] SealExit(ReadOnlySpan<byte> network, PrivacyRoutingHop hop, ReadOnlySpan<byte> replay, PrivacyRoutingOperation operation, ReadOnlySpan<byte> operationId, ReadOnlySpan<byte> attempt, ReadOnlySpan<byte> replyPublic, ReadOnlySpan<byte> request, ReadOnlySpan<byte> ephemeral, ReadOnlySpan<byte> nonce, int block)
    {
        PrivacyRoutingWire.ValidateId(replay, PrivacyRoutingProtocolError.InvalidIdentifier, "replay id"); PrivacyRoutingWire.ValidateOperation(operation); PrivacyRoutingWire.ValidateId(operationId, PrivacyRoutingProtocolError.InvalidIdentifier, "operation id"); PrivacyRoutingWire.ValidateId(attempt, PrivacyRoutingProtocolError.InvalidIdentifier, "attempt id"); PrivacyRoutingWire.ValidatePublicKey(replyPublic);
        var z = PrivacyRoutingWire.Padding(144, request.Length, block); var plain = new byte[144 + request.Length + z];
        try { ProtocolMagicBytes.XRE1.CopyTo(plain); plain[4] = plain[5] = 1; plain[6] = 2; plain[7] = (byte)operation; replay.CopyTo(plain.AsSpan(8)); operationId.CopyTo(plain.AsSpan(40)); attempt.CopyTo(plain.AsSpan(72)); replyPublic.CopyTo(plain.AsSpan(104)); BinaryPrimitives.WriteUInt32BigEndian(plain.AsSpan(136), (uint)request.Length); plain[140] = PrivacyRoutingWire.PaddingExponent(block); PrivacyRoutingWire.WriteU24(plain.AsSpan(141), z); request.CopyTo(plain.AsSpan(144)); return PrivacyRoutingWire.SealEnvelope(plain, network, hop.RouterOwnerIdSpan, hop.Epoch, hop.KeyIdSpan, 1, 2, hop.X25519PublicKeySpan, ephemeral, nonce); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }
    private static PrivacyRoutingRelayLayer DecodeRelay(ReadOnlySpan<byte> plain, PrivacyRoutingReceiveKey key)
        => DecodeRelay(plain, key.NextHop, key.NetworkIdSpan);
    private static PrivacyRoutingRelayLayer DecodeRelay(
        ReadOnlySpan<byte> plain,
        PrivacyRoutingHop? nextHop,
        ReadOnlySpan<byte> network)
    { if (plain.Length < 80 || !plain[..4].SequenceEqual(ProtocolMagicBytes.XRL1) || plain[4] != 1 || plain[5] != 1 || plain[6] != 1 || plain[7] != 0) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "XRL1 grammar is invalid."); var replay = plain.Slice(8, 32); var next = plain.Slice(40, 32); PrivacyRoutingWire.ValidateId(replay, PrivacyRoutingProtocolError.InvalidIdentifier, "replay id"); PrivacyRoutingWire.ValidateId(next, PrivacyRoutingProtocolError.InvalidIdentifier, "next router id"); var expectedNext = nextHop ?? throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidKeyBinding, "Relay receive context has no next-hop binding."); if (!CryptographicOperations.FixedTimeEquals(next, expectedNext.RouterOwnerIdSpan)) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidKeyBinding, "XRL1 next owner does not match the receive context."); var inner = PrivacyRoutingWire.ValidatePayloadAndPadding(plain, 80, 72, 76); PrivacyRoutingWire.ValidateInnerFrame(inner, expectedNext, network); return new PrivacyRoutingRelayLayer(replay, next, inner); }
    private static PrivacyRoutingExitLayer DecodeExit(ReadOnlySpan<byte> plain, ReadOnlySpan<byte> network, bool allowFrozenKatMailboxPayload)
    { if (plain.Length < 144 || !plain[..4].SequenceEqual(ProtocolMagicBytes.XRE1) || plain[4] != 1 || plain[5] != 1 || plain[6] != 2) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "XRE1 grammar is invalid."); var op = (PrivacyRoutingOperation)plain[7]; PrivacyRoutingWire.ValidateOperation(op); var replay = plain.Slice(8,32); var operation = plain.Slice(40,32); var attempt = plain.Slice(72,32); var reply = plain.Slice(104,32); PrivacyRoutingWire.ValidateId(replay,PrivacyRoutingProtocolError.InvalidIdentifier,"replay id"); PrivacyRoutingWire.ValidateId(operation,PrivacyRoutingProtocolError.InvalidIdentifier,"operation id"); PrivacyRoutingWire.ValidateId(attempt,PrivacyRoutingProtocolError.InvalidIdentifier,"attempt id"); PrivacyRoutingWire.ValidatePublicKey(reply); var request = PrivacyRoutingWire.ValidatePayloadAndPadding(plain,144,136,140); if (!allowFrozenKatMailboxPayload) PrivacyRoutingPayloadVerifier.ValidateRequest(network, op, request); var expected=PrivacyRoutingWire.HashCanonicalOperation(request); try { if(!CryptographicOperations.FixedTimeEquals(operation,expected)) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidIdentifier,"XRE1 operation id is not canonical."); } finally { CryptographicOperations.ZeroMemory(expected); } return new PrivacyRoutingExitLayer(network,replay,op,operation,attempt,reply,request); }
    private static void ValidateRoute(IReadOnlyList<PrivacyRoutingHop> route)
    { ArgumentNullException.ThrowIfNull(route); if (route.Count != 3 || route.Any(static x => x is null)) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidRoute,"Route must have three hops."); if(route[0].Role!=PrivacyRoutingKeyRole.Relay||route[1].Role!=PrivacyRoutingKeyRole.Relay||route[2].Role!=PrivacyRoutingKeyRole.Exit) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidRoute,"Route roles must be Relay, Relay, Exit."); for(var i=0;i<3;i++) for(var j=i+1;j<3;j++) if(CryptographicOperations.FixedTimeEquals(route[i].RouterOwnerIdSpan,route[j].RouterOwnerIdSpan)||CryptographicOperations.FixedTimeEquals(route[i].KeyIdSpan,route[j].KeyIdSpan)||CryptographicOperations.FixedTimeEquals(route[i].X25519PublicKeySpan,route[j].X25519PublicKeySpan)) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidRoute,"Router owners, key ids and public keys must be pairwise distinct."); }

    internal static void ValidateVerifiedRoute(IReadOnlyList<PrivacyRoutingHop> route) => ValidateRoute(route);
}

internal sealed class PrivacyRoutingTestEntropy : IDisposable
{
    internal required byte[] AttemptId { get; init; }
    internal required byte[][] ReplayIds { get; init; }
    internal required byte[] ReplyPrivateScalar { get; init; }
    internal required byte[][] RequestEphemeralPrivateScalars { get; init; }
    internal required byte[][] RequestNonces { get; init; }
    internal required byte[] ResponseEphemeralPrivateScalar { get; init; }
    internal required byte[] ResponseNonce { get; init; }
    internal TimeProvider TimeProvider { get; init; } = TimeProvider.System;
    internal TimeSpan ReplyLifetime { get; init; } = PrivacyRoutingLimits.ReplyContextLifetime;

    internal static PrivacyRoutingTestEntropy CreateProductionRequest() =>
        CreateProductionRequest(TimeProvider.System, PrivacyRoutingLimits.ReplyContextLifetime);

    internal static PrivacyRoutingTestEntropy CreateProductionRequest(TimeProvider timeProvider, TimeSpan replyLifetime) =>
        CreateProductionRequestCore(RandomNonZero(PrivacyRoutingLimits.AttemptIdBytes), timeProvider, replyLifetime);

    private static PrivacyRoutingTestEntropy CreateProductionRequestCore(
        byte[] attemptId,
        TimeProvider timeProvider,
        TimeSpan replyLifetime) => new()
    {
        AttemptId = attemptId,
        ReplayIds = DistinctRandomIds(PrivacyRoutingLimits.RouteHopCount),
        ReplyPrivateScalar = RandomPrivateScalar(),
        RequestEphemeralPrivateScalars = Enumerable.Range(0, PrivacyRoutingLimits.RouteHopCount).Select(_ => RandomPrivateScalar()).ToArray(),
        RequestNonces = Enumerable.Range(0, PrivacyRoutingLimits.RouteHopCount).Select(_ => RandomNonZero(24)).ToArray(),
        ResponseEphemeralPrivateScalar = Array.Empty<byte>(),
        ResponseNonce = Array.Empty<byte>(),
        TimeProvider = timeProvider,
        ReplyLifetime = replyLifetime
    };

    internal static PrivacyRoutingTestEntropy CreateProductionResponse() => new()
    {
        AttemptId = Array.Empty<byte>(),
        ReplayIds = [],
        ReplyPrivateScalar = Array.Empty<byte>(),
        RequestEphemeralPrivateScalars = [],
        RequestNonces = [],
        ResponseEphemeralPrivateScalar = RandomPrivateScalar(),
        ResponseNonce = RandomNonZero(24)
    };

    internal void Validate()
    {
        PrivacyRoutingWire.ValidateId(AttemptId, PrivacyRoutingProtocolError.InvalidIdentifier, "attempt id");
        if (ReplayIds.Length != 3 || RequestEphemeralPrivateScalars.Length != 3 || RequestNonces.Length != 3)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "Test entropy cardinality is invalid.");
        foreach (var id in ReplayIds) PrivacyRoutingWire.ValidateId(id, PrivacyRoutingProtocolError.InvalidIdentifier, "replay id");
        if (ReplayIds.Select(static value => Convert.ToHexString(value)).Distinct(StringComparer.Ordinal).Count() != 3)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidIdentifier, "Replay ids must be pairwise distinct.");
        PrivacyRoutingWire.ValidatePrivateKey(ReplyPrivateScalar);
        foreach (var scalar in RequestEphemeralPrivateScalars) PrivacyRoutingWire.ValidatePrivateKey(scalar);
        foreach (var nonce in RequestNonces) PrivacyRoutingWire.ValidateNonce(nonce);
        if (ReplyLifetime <= TimeSpan.Zero || ReplyLifetime > PrivacyRoutingLimits.ReplyContextLifetime)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "Reply context lifetime is invalid.");
    }

    internal void ValidateResponse()
    {
        PrivacyRoutingWire.ValidatePrivateKey(ResponseEphemeralPrivateScalar);
        PrivacyRoutingWire.ValidateNonce(ResponseNonce);
    }

    public void Dispose()
    {
        Zero(AttemptId);
        foreach (var value in ReplayIds) Zero(value);
        Zero(ReplyPrivateScalar);
        foreach (var value in RequestEphemeralPrivateScalars) Zero(value);
        foreach (var value in RequestNonces) Zero(value);
        Zero(ResponseEphemeralPrivateScalar);
        Zero(ResponseNonce);
    }

    private static byte[] RandomPrivateScalar()
    {
        while (true)
        {
            var scalar = RandomNonZero(PrivacyRoutingLimits.X25519KeyBytes);
            byte[]? publicKey = null;
            try
            {
                publicKey = ScalarMult.Base(scalar);
                if (!PrivacyRoutingWire.IsZero(publicKey)) return scalar;
            }
            catch (Exception)
            {
                // A rejected random scalar is burned and generation repeats.
            }
            finally
            {
                if (publicKey is not null) Zero(publicKey);
            }
            Zero(scalar);
        }
    }

    private static byte[] RandomNonZero(int length)
    {
        while (true)
        {
            var value = RandomNumberGenerator.GetBytes(length);
            if (!PrivacyRoutingWire.IsZero(value)) return value;
            Zero(value);
        }
    }

    private static byte[][] DistinctRandomIds(int count)
    {
        var values = new List<byte[]>(count);
        while (values.Count < count)
        {
            var candidate = RandomNonZero(PrivacyRoutingLimits.HopReplayIdBytes);
            if (values.Any(value => CryptographicOperations.FixedTimeEquals(value, candidate)))
            {
                Zero(candidate);
                continue;
            }
            values.Add(candidate);
        }
        return values.ToArray();
    }

    private static void Zero(byte[] value)
    {
        if (value.Length != 0) CryptographicOperations.ZeroMemory(value);
    }
}

internal static class PrivacyRoutingPayloadVerifier
{
    internal static void ValidateRequest(
        ReadOnlySpan<byte> networkId,
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> request)
    {
        PrivacyRoutingWire.ValidateOperation(operation);
        if (request.Length > PrivacyRoutingLimits.MaximumApplicationPayloadBytes)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "Request exceeds the ONION-01 limit.");

        if (operation == PrivacyRoutingOperation.GroupControl)
        {
            ValidateGroupControlRequest(networkId, request);
            return;
        }

        if (operation != PrivacyRoutingOperation.ContactResolve)
        {
            ValidateMailboxRequest(networkId, operation, request);
            return;
        }

        if (request.Length > PrivacyRoutingLimits.MaximumContactResolverRequestBytes)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "Contact Resolver request exceeds its ONION-01 limit.");

        try
        {
            if (ReadMagic(request) == ProtocolMagic.XPP1)
            {
                var publication = Xpp1BoundedCodec.Decode(request);
                if (!CryptographicOperations.FixedTimeEquals(publication.NetworkId.Span, networkId) ||
                    !publication.CanonicalBytes.Span.SequenceEqual(request))
                    throw PrivacyRoutingWire.Error(
                        PrivacyRoutingProtocolError.InvalidKeyBinding,
                        "Bounded XPP1 is not bound to the ONION-01 network or exact canonical bytes.");
                return;
            }

            ContactServiceRequestRecord decoded = ReadMagic(request) switch
            {
                ProtocolMagic.XPU1 => Xpu1Codec.Decode(request),
                ProtocolMagic.XIQ1 => Xiq1Codec.Decode(request),
                ProtocolMagic.XPK1 => Xpk1Codec.Decode(request),
                ProtocolMagic.XUW1 => Xuw1Codec.Decode(request),
                ProtocolMagic.XUQ1 => Xuq1Codec.Decode(request),
                _ => throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "ContactResolve accepts only current ContactV1 request records.")
            };
            if (!CryptographicOperations.FixedTimeEquals(decoded.NetworkId.Span, networkId) ||
                !decoded.CanonicalBytes.Span.SequenceEqual(request))
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidKeyBinding, "Contact Resolver request is not bound to the ONION-01 network or exact canonical bytes.");
        }
        catch (PrivacyRoutingProtocolException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "Contact Resolver request is not canonical.", exception);
        }
    }

    private static void ValidateGroupControlRequest(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> request)
    {
        if (request.Length > PrivacyRoutingLimits.MaximumGroupControlRequestBytes)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "Group Control request exceeds its ONION-01 limit.");
        try
        {
            var decoded = GroupCodec.Decode(request);
            if (decoded is not (GroupControlWriteRecord or GroupControlQueryRecord))
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "GroupControl accepts only exact GSW1 or GSQ1 request records.");
            if (!CryptographicOperations.FixedTimeEquals(decoded.Field(1).Span, networkId) ||
                !decoded.CanonicalBytes.Span.SequenceEqual(request))
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidKeyBinding, "Group Control request is not bound to the ONION-01 network or exact canonical bytes.");
        }
        catch (PrivacyRoutingProtocolException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "Group Control request is not canonical.", exception);
        }
    }

    private static void ValidateMailboxRequest(
        ReadOnlySpan<byte> networkId,
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> request)
    {
        try
        {
            var decoded = MailboxAuthenticatedClientRequestCodec.Decode(request);
            var expectedOperation = operation switch
            {
                PrivacyRoutingOperation.Store => MailboxAuthenticatedOperation.Store,
                PrivacyRoutingOperation.Retrieve => MailboxAuthenticatedOperation.Retrieve,
                PrivacyRoutingOperation.Acknowledge => MailboxAuthenticatedOperation.Ack,
                _ => throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "The ONION operation is not a mailbox operation.")
            };
            if (decoded.Binding.Operation != expectedOperation ||
                decoded.Presentation.Operation != expectedOperation)
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "MAU2 operation does not match the ONION terminal operation.");
            if (!CryptographicOperations.FixedTimeEquals(decoded.Presentation.Grant.NetworkId.Span, networkId))
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidKeyBinding, "MAU2 grant network does not match the ONION network.");
            var exact = MailboxAuthenticatedClientRequestCodec.Encode(decoded);
            try
            {
                if (!exact.AsSpan().SequenceEqual(request))
                    throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "MAU2 request bytes are not exact canonical bytes.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(exact);
            }
        }
        catch (PrivacyRoutingProtocolException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "Mailbox ONION operations accept only exact canonical MAU2 requests.", exception);
        }
    }

    internal static void ValidateResult(
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> exactRequest,
        PrivacyRoutingTerminalResult result)
    {
        if (result.Operation != operation)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "Result operation does not match the request.");
        if (result.Kind != PrivacyRoutingResultKind.Success) return;
        if (operation == PrivacyRoutingOperation.GroupControl)
        {
            ValidateGroupControlResult(exactRequest, result.Body.Span);
            return;
        }

        if (operation != PrivacyRoutingOperation.ContactResolve)
        {
            ValidateMailboxResult(operation, exactRequest, result.Body.Span);
            return;
        }
        var body = result.Body.Span;
        if (body.Length > PrivacyRoutingLimits.MaximumContactResolverResponseBytes)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "Contact Resolver response exceeds its ONION-01 limit.");

        try
        {
            if (ReadMagic(exactRequest) == ProtocolMagic.XPP1)
            {
                var request = Xpp1BoundedCodec.Decode(exactRequest);
                var receipt = Xic1BoundedCodec.Decode(body);
                Xic1BoundedCodec.ValidateFields(
                    Enumerable.Range(1, 14)
                        .Select(tag => receipt.FieldSpan(tag).ToArray())
                        .ToArray(),
                    request);
                if (!receipt.CanonicalBytes.Span.SequenceEqual(body))
                    throw PrivacyRoutingWire.Error(
                        PrivacyRoutingProtocolError.InvalidOperation,
                        "Bounded XIC1 response has non-canonical trailing bytes.");
                return;
            }

            ContactServiceResultRecord decoded = ReadMagic(exactRequest) switch
            {
                ProtocolMagic.XPU1 => Xpo1Codec.Decode(body, exactRequest),
                ProtocolMagic.XIQ1 => Xis1Codec.Decode(body, exactRequest),
                ProtocolMagic.XPK1 => Xpc1Codec.Decode(body, exactRequest),
                ProtocolMagic.XUW1 or ProtocolMagic.XUQ1 => Xus1Codec.Decode(body, exactRequest),
                _ => throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "ContactResolve request/result pairing is invalid.")
            };
            if (!decoded.WireBytes.Span.SequenceEqual(body))
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "Contact Resolver response has non-canonical trailing bytes.");
        }
        catch (PrivacyRoutingProtocolException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "Contact Resolver response is not canonical or bound to its exact request.", exception);
        }
    }

    private static void ValidateGroupControlResult(
        ReadOnlySpan<byte> exactRequest,
        ReadOnlySpan<byte> body)
    {
        if (body.Length > PrivacyRoutingLimits.MaximumGroupControlResponseBytes)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "Group Control response exceeds its ONION-01 limit.");
        try
        {
            var request = GroupCodec.Decode(exactRequest);
            if (request is not (GroupControlWriteRecord or GroupControlQueryRecord))
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "GroupControl request/result pairing is invalid.");
            var result = GroupCodec.Decode(body);
            if (result is not GroupControlResultRecord || !result.CanonicalBytes.Span.SequenceEqual(body))
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "GroupControl accepts only exact GSS1 result records.");

            if (!CryptographicOperations.FixedTimeEquals(result.Field(1).Span, request.Field(1).Span) ||
                !CryptographicOperations.FixedTimeEquals(result.Field(2).Span, request.Field(2).Span) ||
                !CryptographicOperations.FixedTimeEquals(
                    result.Field(3).Span,
                    ContactCodec.Sha256Domain("Deep/ContactResolver/V1/request", exactRequest)))
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "GSS1 is not bound to the exact Group Control request.");

            var isWrite = request is GroupControlWriteRecord;
            var operationKind = result.Field(16).Span[0];
            if ((operationKind == 1) != isWrite || operationKind is < 1 or > 2)
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "GSS1 operation kind does not match GSW1/GSQ1.");

            var status = BinaryPrimitives.ReadUInt16BigEndian(result.Field(4).Span);
            if (isWrite && status is (1 or 2) &&
                (!result.Field(17).Span.SequenceEqual(request.Field(18).Span) ||
                 !CryptographicOperations.FixedTimeEquals(result.Field(18).Span, request.Field(20).Span)))
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "GSS1 committed tuple does not match the exact GSW1 request.");

            if (!isWrite)
                ValidateGroupControlFetchResult(request, result, status);
        }
        catch (PrivacyRoutingProtocolException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "Group Control response is not canonical or bound to its exact request.", exception);
        }
    }

    private static void ValidateGroupControlFetchResult(GroupRecord request, GroupRecord result, ushort status)
    {
        var requestedPadding = BinaryPrimitives.ReadUInt16BigEndian(request.Field(20).Span);
        var actualPadding = BinaryPrimitives.ReadUInt16BigEndian(result.Field(8).Span);
        if (actualPadding != requestedPadding)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "GSS1 fetch padding class does not match GSQ1.");
        if (status == 11)
        {
            var required = BinaryPrimitives.ReadUInt16BigEndian(result.Field(17).Span);
            if (required <= requestedPadding || required > 4)
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "GSS1 required padding class is not a valid GSQ1 successor class.");
            return;
        }
        if (status != 3) return;

        var count = BinaryPrimitives.ReadUInt16BigEndian(result.Field(17).Span);
        var maximum = BinaryPrimitives.ReadUInt16BigEndian(request.Field(19).Span);
        if (count > maximum)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "GSS1 event count exceeds the exact GSQ1 maximum.");
        var after = BinaryPrimitives.ReadUInt64BigEndian(request.Field(18).Span);
        var rows = result.Field(18).Span;
        if (rows.Length < 8 || BinaryPrimitives.ReadUInt64BigEndian(rows) <= after)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "GSS1 events do not begin after the exact GSQ1 cursor.");
    }

    private static void ValidateMailboxResult(
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> exactRequest,
        ReadOnlySpan<byte> body)
    {
        try
        {
            var request = MailboxAuthenticatedClientRequestCodec.Decode(exactRequest);
            var operationId = request.Binding.OperationId.Span;
            var epoch = request.Presentation.Grant.Epoch;
            byte[] canonical;
            switch (operation)
            {
                case PrivacyRoutingOperation.Store:
                {
                    var storeRequest = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Binding.CanonicalRequest.Span);
                    var value = MailboxReceiptV3Codec.DecodeDurableQuorum(body);
                    ValidateReplicaBinding(value.FirstReplica, operationId, epoch,
                        storeRequest.MailboxId.Bytes.Span, request.Presentation.Grant.PlacementCommitment.Span,
                        request.Presentation.Grant.MembershipCommitment.Span, storeRequest.DeduplicationDigest.Span,
                        expectedCursor: null, MailboxReplicaDisposition.Stored, MailboxReplicaDisposition.Duplicate);
                    ValidateReplicaBinding(value.SecondReplica, operationId, epoch,
                        storeRequest.MailboxId.Bytes.Span, request.Presentation.Grant.PlacementCommitment.Span,
                        request.Presentation.Grant.MembershipCommitment.Span, storeRequest.DeduplicationDigest.Span,
                        expectedCursor: null, MailboxReplicaDisposition.Stored, MailboxReplicaDisposition.Duplicate);
                    canonical = MailboxReceiptV3Codec.EncodeDurableQuorum(value);
                    break;
                }
                case PrivacyRoutingOperation.Retrieve:
                    ValidateRetrievePage(body, request);
                    return;
                case PrivacyRoutingOperation.Acknowledge:
                {
                    var value = MailboxAggregateAckCodec.DecodeMqr3(body);
                    if (value.Epoch != epoch || !CryptographicOperations.FixedTimeEquals(value.OperationId.Span, operationId))
                        throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "MAR1 is not bound to the exact MAU2 operation.");
                    var ackRequest = MailboxAuthenticatedRequestTranscript.DecodeAckBody(request.Binding.CanonicalRequest.Span);
                    if (value.TombstoneQuorums.Count != ackRequest.Acknowledgements.Count)
                        throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "MAR1 quorum count does not match the exact MAU2 acknowledgement.");
                    for (var index = 0; index < value.TombstoneQuorums.Count; index++)
                    {
                        var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(value.TombstoneQuorums[index].Span);
                        var acknowledgement = ackRequest.Acknowledgements[index];
                        ValidateReplicaBinding(quorum.FirstReplica, operationId, epoch,
                            ackRequest.MailboxId.Bytes.Span, request.Presentation.Grant.PlacementCommitment.Span,
                            request.Presentation.Grant.MembershipCommitment.Span, acknowledgement.EnvelopeDigest.Span,
                            acknowledgement.Cursor, MailboxReplicaDisposition.Tombstone);
                        ValidateReplicaBinding(quorum.SecondReplica, operationId, epoch,
                            ackRequest.MailboxId.Bytes.Span, request.Presentation.Grant.PlacementCommitment.Span,
                            request.Presentation.Grant.MembershipCommitment.Span, acknowledgement.EnvelopeDigest.Span,
                            acknowledgement.Cursor, MailboxReplicaDisposition.Tombstone);
                    }
                    canonical = MailboxAggregateAckCodec.EncodeMqr3(value);
                    break;
                }
                default:
                    throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "The ONION operation is not a mailbox operation.");
            }

            try
            {
                if (!canonical.AsSpan().SequenceEqual(body))
                    throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "Mailbox terminal result bytes are not exact canonical bytes.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(canonical);
            }
        }
        catch (PrivacyRoutingProtocolException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "Mailbox terminal success is not the exact MQR3/MRP1/MAR1 result.", exception);
        }
    }

    private static void ValidateReplicaBinding(
        MailboxReplicaReceiptV2 receipt,
        ReadOnlySpan<byte> operationId,
        ulong epoch,
        ReadOnlySpan<byte> mailboxId,
        ReadOnlySpan<byte> placementCommitment,
        ReadOnlySpan<byte> membershipCommitment,
        ReadOnlySpan<byte> envelopeDigest,
        ulong? expectedCursor,
        params MailboxReplicaDisposition[] allowedDispositions)
    {
        if (receipt.Epoch != epoch ||
            !CryptographicOperations.FixedTimeEquals(receipt.OperationId.Span, operationId) ||
            !CryptographicOperations.FixedTimeEquals(receipt.BlindedMailboxId.Span, mailboxId) ||
            !CryptographicOperations.FixedTimeEquals(receipt.PlacementCommitment.Span, placementCommitment) ||
            !CryptographicOperations.FixedTimeEquals(receipt.MembershipCommitment.Span, membershipCommitment) ||
            !CryptographicOperations.FixedTimeEquals(receipt.EnvelopeDigest.Span, envelopeDigest) ||
            expectedCursor is not null && receipt.Cursor != expectedCursor.Value ||
            !allowedDispositions.Contains(receipt.Disposition))
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "Mailbox receipt is not bound to the exact MAU2 request.");
    }

    private static void ValidateRetrievePage(ReadOnlySpan<byte> body, MailboxAuthenticatedClientRequest request)
    {
        const int headerLength = 48;
        if (body.Length < headerLength || body.Length > MailboxClientLimits.MaximumPageBytes ||
            !body[..4].SequenceEqual(ProtocolMagicBytes.MRP1) || body[4] != 1 || body[5] > 1 ||
            body.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            body.Slice(44, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "MRP1 header is not canonical.");

        var epoch = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(8, 8));
        var operationId = body.Slice(16, MailboxClientLimits.OperationIdLength);
        var nextCursor = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(32, 8));
        var tokenLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(40, 2));
        var count = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(42, 2));
        var hasMore = body[5] == 1;
        var retrieveRequest = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(request.Binding.CanonicalRequest.Span);
        if (epoch != request.Presentation.Grant.Epoch || !CryptographicOperations.FixedTimeEquals(operationId, request.Binding.OperationId.Span))
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "MRP1 is not bound to the exact MAU2 operation.");
        if (operationId.IndexOfAnyExcept((byte)0) < 0 ||
            count > MailboxClientLimits.MaximumPageItems ||
            tokenLength > MailboxClientLimits.MaximumContinuationTokenLength ||
            headerLength + tokenLength > body.Length ||
            hasMore != (tokenLength != 0) ||
            hasMore && nextCursor == 0)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "MRP1 pagination fields are not canonical.");

        var offset = headerLength + tokenLength;
        ulong previousCursor = 0;
        for (var index = 0; index < count; index++)
        {
            if (offset > body.Length - 12)
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "MRP1 item header is truncated.");
            var cursor = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(offset, 8));
            var length = BinaryPrimitives.ReadUInt32BigEndian(body.Slice(offset + 8, 4));
            offset += 12;
            if (cursor == 0 || cursor <= previousCursor ||
                length > MailboxClientLimits.MaximumEncryptedEnvelopeLength ||
                length > body.Length - offset)
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "MRP1 item is not canonical.");
            var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(body.Slice(offset, checked((int)length)));
            if (envelope.Epoch != epoch ||
                !CryptographicOperations.FixedTimeEquals(envelope.MailboxId.Bytes.Span, retrieveRequest.MailboxId.Bytes.Span) ||
                !CryptographicOperations.FixedTimeEquals(envelope.PlacementId.Bytes.Span, retrieveRequest.PlacementId.Bytes.Span))
                throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.ReplyContextMismatch, "MRP1 item is not bound to the exact MAU2 retrieve request.");
            previousCursor = cursor;
            offset += checked((int)length);
        }

        if (offset != body.Length || (count == 0 ? nextCursor != 0 || hasMore : nextCursor != previousCursor))
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "MRP1 trailing bytes or next cursor are not canonical.");
    }

    private static string ReadMagic(ReadOnlySpan<byte> value)
    {
        if (value.Length < 4) return string.Empty;
        return System.Text.Encoding.ASCII.GetString(value[..4]);
    }
}

internal static class PrivacyRoutingWire
{
    private static readonly byte[] Magic = ProtocolMagicBytes.XRF1.ToArray();
    internal static PrivacyRoutingProtocolException Error(PrivacyRoutingProtocolError error, string message, Exception? inner = null) => new(error, message, inner);
    internal static void ValidateNetwork(ReadOnlySpan<byte> value) { if(value.Length!=16||IsZero(value)) throw Error(PrivacyRoutingProtocolError.InvalidIdentifier,"Network id must be nonzero 16 bytes."); }
    internal static void ValidateId(ReadOnlySpan<byte> value, PrivacyRoutingProtocolError error, string field) { if(value.Length!=32||IsZero(value)) throw Error(error,$"{field} must be nonzero 32 bytes."); }
    internal static void ValidatePublicKey(ReadOnlySpan<byte> value) => ValidateId(value,PrivacyRoutingProtocolError.InvalidKeyLength,"X25519 public key");
    internal static void ValidatePrivateKey(ReadOnlySpan<byte> value) => ValidateId(value,PrivacyRoutingProtocolError.InvalidKeyLength,"X25519 private key");
    internal static void ValidateNonce(ReadOnlySpan<byte> value) { if(value.Length!=24) throw Error(PrivacyRoutingProtocolError.InvalidKeyLength,"XChaCha20 nonce must be 24 bytes."); }
    internal static void ValidateEpoch(ulong epoch, bool response) { if((response&&epoch!=0)||(!response&&epoch==0)) throw Error(PrivacyRoutingProtocolError.InvalidKeyBinding,"Epoch contradicts frame purpose."); }
    internal static void ValidateRole(PrivacyRoutingKeyRole role) { if(role is not (PrivacyRoutingKeyRole.Relay or PrivacyRoutingKeyRole.Exit)) throw Error(PrivacyRoutingProtocolError.InvalidKeyBinding,"Traffic-key role is invalid."); }
    internal static void ValidateReceivePosition(PrivacyRoutingReceivePosition position) { if(position is not (PrivacyRoutingReceivePosition.Ingress or PrivacyRoutingReceivePosition.Core or PrivacyRoutingReceivePosition.Exit)) throw Error(PrivacyRoutingProtocolError.InvalidKeyBinding,"Receive position is invalid."); }
    internal static void ValidateOperation(PrivacyRoutingOperation op) { if(op is not (PrivacyRoutingOperation.Store or PrivacyRoutingOperation.Retrieve or PrivacyRoutingOperation.Acknowledge or PrivacyRoutingOperation.ContactResolve or PrivacyRoutingOperation.GroupControl)) throw Error(PrivacyRoutingProtocolError.InvalidOperation,"Operation is invalid."); }
    internal static bool IsZero(ReadOnlySpan<byte> value) { var aggregate=0; foreach(var b in value) aggregate|=b; return aggregate==0; }
    internal static byte PaddingExponent(int block) { ValidatePaddingBlock(block); return (byte)System.Numerics.BitOperations.Log2((uint)block); }
    internal static void ValidatePaddingBlock(int block) { if(block is < 256 or > 65536 || (block&(block-1))!=0) throw Error(PrivacyRoutingProtocolError.InvalidPadding,"Padding block must be a power of two from 256 to 65536."); }
    internal static int Padding(int prefix, int payload, int block) { ValidatePaddingBlock(block); return (block-((160+16+prefix+payload)%block))%block; }
    internal static void WriteU24(Span<byte> value, int input) { if(value.Length<3||input is <0 or >65535) throw Error(PrivacyRoutingProtocolError.InvalidPadding,"Padding length is invalid."); value[0]=(byte)(input>>16);value[1]=(byte)(input>>8);value[2]=(byte)input; }
    private static int ReadU24(ReadOnlySpan<byte> value) => (value[0]<<16)|(value[1]<<8)|value[2];
    internal static byte[] U64(ulong value) { var bytes=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(bytes,value);return bytes; }
    internal static byte[] HashCanonicalOperation(ReadOnlySpan<byte> request)
    {
        var length = U64((ulong)request.Length);
        var copy = request.ToArray();
        try { return Sha256Domain("Deep/XPoint/V1/canonical-mailbox-operation-id", length, copy); }
        finally { CryptographicOperations.ZeroMemory(length); CryptographicOperations.ZeroMemory(copy); }
    }
    internal static byte[] Sha256Domain(string label, params byte[][] parts) => DomainHash(label, SHA256.HashData, parts);
    private static byte[] Sha512Domain(string label, params byte[][] parts) => DomainHash(label, SHA512.HashData, parts);
    private static byte[] DomainHash(string label, Func<byte[],byte[]> hash, byte[][] parts) { var labelBytes=System.Text.Encoding.ASCII.GetBytes(label); var data=new byte[labelBytes.Length+1+parts.Sum(static p=>p.Length)]; labelBytes.CopyTo(data,0); var offset=labelBytes.Length+1; foreach(var part in parts) { part.CopyTo(data,offset);offset+=part.Length; } try{return hash(data);}finally{CryptographicOperations.ZeroMemory(data);} }
    internal static byte[] SealEnvelope(ReadOnlySpan<byte> plain, ReadOnlySpan<byte> network, ReadOnlySpan<byte> owner, ulong epoch, ReadOnlySpan<byte> keyId, byte purpose, byte layer, ReadOnlySpan<byte> recipientPublic, ReadOnlySpan<byte> ephemeralPrivate, ReadOnlySpan<byte> nonce)
    { ValidateNetwork(network);ValidateId(owner,PrivacyRoutingProtocolError.InvalidIdentifier,"key owner id");ValidateId(keyId,PrivacyRoutingProtocolError.InvalidIdentifier,"key id");ValidateEpoch(epoch,purpose==2);ValidatePublicKey(recipientPublic);ValidatePrivateKey(ephemeralPrivate);ValidateNonce(nonce);var privateCopy=ephemeralPrivate.ToArray();var ephemeralPublic=ScalarMult.Base(privateCopy);ValidatePublicKey(ephemeralPublic);var frame=new byte[160+plain.Length+16];try{Magic.CopyTo(frame);frame[4]=frame[5]=frame[6]=1;frame[7]=purpose;frame[8]=layer;network.CopyTo(frame.AsSpan(12));owner.CopyTo(frame.AsSpan(28));BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(60),epoch);keyId.CopyTo(frame.AsSpan(68));ephemeralPublic.CopyTo(frame.AsSpan(100));nonce.CopyTo(frame.AsSpan(132));BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(156),(uint)(plain.Length+16));var key=DeriveKey(network,owner,epoch,keyId,ephemeralPublic,purpose,layer,ephemeralPrivate,recipientPublic);var plainCopy=plain.ToArray();var nonceCopy=nonce.ToArray();var aad=frame.AsSpan(0,160).ToArray();try{var cipher=SecretAeadXChaCha20Poly1305.Encrypt(plainCopy,nonceCopy,key,aad);try{cipher.CopyTo(frame,160);}finally{CryptographicOperations.ZeroMemory(cipher);}}finally{CryptographicOperations.ZeroMemory(key);CryptographicOperations.ZeroMemory(plainCopy);CryptographicOperations.ZeroMemory(nonceCopy);CryptographicOperations.ZeroMemory(aad);}return frame;}finally{CryptographicOperations.ZeroMemory(privateCopy);CryptographicOperations.ZeroMemory(ephemeralPublic);} }
    internal static byte[] OpenRequestEnvelope(ReadOnlySpan<byte> frame, PrivacyRoutingReceiveKey key) { var header=ValidateHeader(frame,1);if(header.Layer!=(byte)key.Role||!CryptographicOperations.FixedTimeEquals(header.Network,key.NetworkIdSpan)||!CryptographicOperations.FixedTimeEquals(header.Owner,key.OwnerIdSpan)||!CryptographicOperations.FixedTimeEquals(header.KeyId,key.KeyIdSpan)||header.Epoch!=key.Epoch) throw Error(PrivacyRoutingProtocolError.InvalidKeyBinding,"Request header binding is invalid.");return Open(frame,key.PrivateKey,header); }
    internal static byte[] ReadBoundRequestEphemeral(ReadOnlySpan<byte> frame, VerifiedOnionReceiveContext receive)
    {
        var header = ValidateHeader(frame, 1);
        ValidateProductionReceiveHeader(header, receive);
        return header.Ephemeral.ToArray();
    }
    internal static byte[] OpenRequestEnvelopeWithSharedSecret(ReadOnlySpan<byte> frame, VerifiedOnionReceiveContext receive, ReadOnlySpan<byte> sharedSecret)
    {
        if (sharedSecret.Length != PrivacyRoutingLimits.X25519KeyBytes || IsZero(sharedSecret))
            throw Error(PrivacyRoutingProtocolError.AuthenticationFailed, "X25519 shared secret must be nonzero 32 bytes.");
        var header = ValidateHeader(frame, 1);
        ValidateProductionReceiveHeader(header, receive);
        return OpenWithSharedSecret(frame, sharedSecret, header);
    }
    private static void ValidateProductionReceiveHeader(Header header, VerifiedOnionReceiveContext receive)
    {
        var hop = receive.LocalHop;
        if (header.Layer != (byte)hop.Role ||
            !CryptographicOperations.FixedTimeEquals(header.Network, receive.Network.NetworkIdSpan) ||
            !CryptographicOperations.FixedTimeEquals(header.Owner, hop.RouterOwnerIdSpan) ||
            !CryptographicOperations.FixedTimeEquals(header.KeyId, hop.KeyIdSpan) ||
            header.Epoch != hop.Epoch)
            throw Error(PrivacyRoutingProtocolError.InvalidKeyBinding, "Verified request header binding is invalid.");
    }
    internal static byte[] OpenResponseEnvelope(ReadOnlySpan<byte> frame, PrivacyRoutingReplyOpenState state) { var header=ValidateHeader(frame,2);if(header.Layer!=3||header.Epoch!=0||!CryptographicOperations.FixedTimeEquals(header.Network,state.NetworkIdSpan)||!CryptographicOperations.FixedTimeEquals(header.Owner,state.OwnerIdSpan)||!CryptographicOperations.FixedTimeEquals(header.KeyId,state.KeyIdSpan)) throw Error(PrivacyRoutingProtocolError.ReplyContextMismatch,"Response header binding is invalid.");return Open(frame,state.PrivateKeySpan,header); }
    private static byte[] Open(ReadOnlySpan<byte> frame, ReadOnlySpan<byte> localPrivate, Header header) { var key=DeriveKey(header.Network,header.Owner,header.Epoch,header.KeyId,header.Ephemeral,header.Purpose,header.Layer,localPrivate,header.Ephemeral);var cipher=frame[160..].ToArray();var nonce=header.Nonce.ToArray();var aad=frame[..160].ToArray();try{try{return SecretAeadXChaCha20Poly1305.Decrypt(cipher,nonce,key,aad);}catch(Exception exception){throw Error(PrivacyRoutingProtocolError.AuthenticationFailed,"XRF1 authentication failed.",exception);}}finally{CryptographicOperations.ZeroMemory(key);CryptographicOperations.ZeroMemory(cipher);CryptographicOperations.ZeroMemory(nonce);CryptographicOperations.ZeroMemory(aad);} }
    private static byte[] OpenWithSharedSecret(ReadOnlySpan<byte> frame, ReadOnlySpan<byte> sharedSecret, Header header)
    {
        var key = DeriveKeyFromSharedSecret(
            header.Network, header.Owner, header.Epoch, header.KeyId, header.Ephemeral,
            header.Purpose, header.Layer, sharedSecret);
        var cipher = frame[160..].ToArray();
        var nonce = header.Nonce.ToArray();
        var aad = frame[..160].ToArray();
        try
        {
            try { return SecretAeadXChaCha20Poly1305.Decrypt(cipher, nonce, key, aad); }
            catch (Exception exception)
            {
                throw Error(PrivacyRoutingProtocolError.AuthenticationFailed, "XRF1 authentication failed.", exception);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(cipher);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(aad);
        }
    }
    private static byte[] DeriveKeyFromSharedSecret(ReadOnlySpan<byte> network, ReadOnlySpan<byte> owner, ulong epoch, ReadOnlySpan<byte> keyId, ReadOnlySpan<byte> ephemeral, byte purpose, byte layer, ReadOnlySpan<byte> sharedSecret)
    {
        if (sharedSecret.Length != PrivacyRoutingLimits.X25519KeyBytes || IsZero(sharedSecret))
            throw Error(PrivacyRoutingProtocolError.AuthenticationFailed, "X25519 shared secret must be nonzero 32 bytes.");
        var epochBytes = U64(epoch);
        var salt = Sha512Domain("Deep/XPoint/V1/frame-salt", network.ToArray(), owner.ToArray(), epochBytes, keyId.ToArray(), ephemeral.ToArray());
        try
        {
            var prk = HMACSHA512.HashData(salt, sharedSecret);
            try
            {
                var info = System.Text.Encoding.ASCII.GetBytes("Deep/XPoint/V1/frame-key\0").Concat(new[] { purpose, layer, (byte)1 }).ToArray();
                try
                {
                    var t = HMACSHA512.HashData(prk, info);
                    try { return t[..32]; }
                    finally { CryptographicOperations.ZeroMemory(t); }
                }
                finally { CryptographicOperations.ZeroMemory(info); }
            }
            finally { CryptographicOperations.ZeroMemory(prk); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(epochBytes);
        }
    }
    private static byte[] DeriveKey(ReadOnlySpan<byte> network,ReadOnlySpan<byte> owner,ulong epoch,ReadOnlySpan<byte> keyId,ReadOnlySpan<byte> ephemeral,byte purpose,byte layer,ReadOnlySpan<byte> localPrivate,ReadOnlySpan<byte> peerPublic)
    { ValidatePublicKey(peerPublic);byte[] shared;var privateCopy=localPrivate.ToArray();var publicCopy=peerPublic.ToArray();try{try{shared=ScalarMult.Mult(privateCopy,publicCopy);}catch(Exception exception){throw Error(PrivacyRoutingProtocolError.AuthenticationFailed,"X25519 scalar multiplication failed.",exception);}}finally{CryptographicOperations.ZeroMemory(privateCopy);CryptographicOperations.ZeroMemory(publicCopy);}try{if(IsZero(shared))throw Error(PrivacyRoutingProtocolError.AuthenticationFailed,"X25519 shared secret is all zero.");var epochBytes=U64(epoch);var salt=Sha512Domain("Deep/XPoint/V1/frame-salt",network.ToArray(),owner.ToArray(),epochBytes,keyId.ToArray(),ephemeral.ToArray());try{var prk=HMACSHA512.HashData(salt,shared);try{var info=System.Text.Encoding.ASCII.GetBytes("Deep/XPoint/V1/frame-key\0").Concat(new[]{purpose,layer,(byte)1}).ToArray();try{var t=HMACSHA512.HashData(prk,info);try{return t[..32];}finally{CryptographicOperations.ZeroMemory(t);}}finally{CryptographicOperations.ZeroMemory(info);}}finally{CryptographicOperations.ZeroMemory(prk);}}finally{CryptographicOperations.ZeroMemory(salt);CryptographicOperations.ZeroMemory(epochBytes);}}finally{CryptographicOperations.ZeroMemory(shared);} }
    private static Header ValidateHeader(ReadOnlySpan<byte> frame,byte purpose) { if(frame.Length is <176 or >1572864)throw Error(PrivacyRoutingProtocolError.FrameLengthOutOfRange,"XRF1 length is outside bounds.");if(!frame[..4].SequenceEqual(Magic))throw Error(PrivacyRoutingProtocolError.UnsupportedVersion,"XRF1 magic is required.");if(frame[4]!=1||frame[5]!=1||frame[6]!=1||!IsZero(frame.Slice(9,3)))throw Error(PrivacyRoutingProtocolError.UnsupportedVersion,"XRF1 header is invalid.");if(frame[7]!=purpose||(purpose==1&&frame[8]is not(1 or 2))||(purpose==2&&frame[8]!=3))throw Error(PrivacyRoutingProtocolError.WrongFramePurpose,"XRF1 purpose/layer is invalid.");if(BinaryPrimitives.ReadUInt32BigEndian(frame.Slice(156,4))!=frame.Length-160)throw Error(PrivacyRoutingProtocolError.InvalidLength,"XRF1 ciphertext length is invalid.");var header=new Header(frame);ValidateNetwork(header.Network);ValidateId(header.Owner,PrivacyRoutingProtocolError.InvalidIdentifier,"header owner id");ValidateId(header.KeyId,PrivacyRoutingProtocolError.InvalidIdentifier,"header key id");ValidateEpoch(header.Epoch,purpose==2);ValidatePublicKey(header.Ephemeral);ValidateNonce(header.Nonce);return header; }
    internal static ReadOnlySpan<byte> ValidatePayloadAndPadding(ReadOnlySpan<byte> plain,int prefix,int lengthOffset,int exponentOffset) { var payload=BinaryPrimitives.ReadUInt32BigEndian(plain.Slice(lengthOffset,4));var exponent=plain[exponentOffset];if(exponent is <8 or >16)throw Error(PrivacyRoutingProtocolError.InvalidPadding,"Padding exponent is invalid.");var z=ReadU24(plain.Slice(exponentOffset+1,3));var block=1<<exponent;if(payload>int.MaxValue||z>=block||z!=Padding(prefix,(int)payload,block)||(ulong)prefix+payload+(uint)z!=(ulong)plain.Length||!IsZero(plain.Slice(prefix+(int)payload,z)))throw Error(PrivacyRoutingProtocolError.InvalidPadding,"Padding is non-canonical.");return plain.Slice(prefix,(int)payload); }
    internal static void ValidateInnerFrame(ReadOnlySpan<byte> frame,PrivacyRoutingHop nextHop,ReadOnlySpan<byte> outerNetwork) { ValidateNetwork(outerNetwork);ArgumentNullException.ThrowIfNull(nextHop);var header=ValidateHeader(frame,1);if(!CryptographicOperations.FixedTimeEquals(header.Network,outerNetwork)||!CryptographicOperations.FixedTimeEquals(header.Owner,nextHop.RouterOwnerIdSpan)||!CryptographicOperations.FixedTimeEquals(header.KeyId,nextHop.KeyIdSpan)||header.Epoch!=nextHop.Epoch||header.Layer!=(byte)nextHop.Role)throw Error(PrivacyRoutingProtocolError.InvalidKeyBinding,"XRL1 inner network/owner/key/epoch/role binding is invalid."); }
    private readonly ref struct Header { private readonly ReadOnlySpan<byte> _frame;internal Header(ReadOnlySpan<byte> frame)=>_frame=frame;internal byte Purpose=>_frame[7];internal byte Layer=>_frame[8];internal ReadOnlySpan<byte> Network=>_frame.Slice(12,16);internal ReadOnlySpan<byte> Owner=>_frame.Slice(28,32);internal ulong Epoch=>BinaryPrimitives.ReadUInt64BigEndian(_frame.Slice(60,8));internal ReadOnlySpan<byte> KeyId=>_frame.Slice(68,32);internal ReadOnlySpan<byte> Ephemeral=>_frame.Slice(100,32);internal ReadOnlySpan<byte> Nonce=>_frame.Slice(132,24); }
}
