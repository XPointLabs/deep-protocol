using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxPeerWireV2AggregateAckCodec
{
    public static byte[] Create(
        MailboxAckRequest acknowledgementRequest,
        IReadOnlyList<VerifiedMailboxPeerWireRequestV2> orderedTombstones,
        IReadOnlyList<ReadOnlyMemory<byte>> orderedSignedMqr3,
        IMailboxPeerReplicationCrypto crypto)
    {
        ValidateInputs(
            acknowledgementRequest,
            orderedTombstones,
            orderedSignedMqr3,
            crypto);
        for (var index = 0; index < orderedTombstones.Count; index++)
        {
            _ = MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(
                orderedSignedMqr3[index].Span,
                orderedTombstones[index],
                crypto);
        }

        return MailboxAggregateAckCodec.EncodeMqr3(new MailboxAggregateAckResponse
        {
            Epoch = acknowledgementRequest.Epoch,
            OperationId = acknowledgementRequest.OperationId.ToArray(),
            TombstoneQuorums = orderedSignedMqr3
                .Select(static value => (ReadOnlyMemory<byte>)value.ToArray())
                .ToArray()
        });
    }

    public static IReadOnlyList<VerifiedMailboxDurableQuorumV3> Verify(
        ReadOnlySpan<byte> encodedMar1,
        MailboxAckRequest acknowledgementRequest,
        IReadOnlyList<VerifiedMailboxPeerWireRequestV2> orderedTombstones,
        IMailboxPeerReplicationCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(acknowledgementRequest);
        ArgumentNullException.ThrowIfNull(orderedTombstones);
        ArgumentNullException.ThrowIfNull(crypto);
        var response = MailboxAggregateAckCodec.DecodeMqr3(encodedMar1);
        ValidateInputs(
            acknowledgementRequest,
            orderedTombstones,
            response.TombstoneQuorums,
            crypto);
        if (response.Epoch != acknowledgementRequest.Epoch ||
            !FixedEquals(
                response.OperationId.Span,
                acknowledgementRequest.OperationId.Span))
            throw Error("MAR1 does not match the exact MAK1 operation.");

        var verified = new List<VerifiedMailboxDurableQuorumV3>(
            orderedTombstones.Count);
        for (var index = 0; index < orderedTombstones.Count; index++)
        {
            verified.Add(MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(
                response.TombstoneQuorums[index].Span,
                orderedTombstones[index],
                crypto));
        }

        return verified;
    }

    private static void ValidateInputs(
        MailboxAckRequest acknowledgementRequest,
        IReadOnlyList<VerifiedMailboxPeerWireRequestV2> orderedTombstones,
        IReadOnlyList<ReadOnlyMemory<byte>> orderedSignedMqr3,
        IMailboxPeerReplicationCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(acknowledgementRequest);
        ArgumentNullException.ThrowIfNull(orderedTombstones);
        ArgumentNullException.ThrowIfNull(orderedSignedMqr3);
        ArgumentNullException.ThrowIfNull(crypto);
        _ = MailboxClientCodec.EncodeAck(acknowledgementRequest);
        if (acknowledgementRequest.Acknowledgements.Count is
                0 or > MailboxClientLimits.MaximumPageItems ||
            orderedTombstones.Count !=
                acknowledgementRequest.Acknowledgements.Count ||
            orderedSignedMqr3.Count != orderedTombstones.Count)
            throw Error("MAK1, PRQ2 and MQR3 counts do not match.");

        var placementCommitment = MailboxPlacementCommitment.Compute(
            acknowledgementRequest.PlacementId);
        var firstRequest = orderedTombstones[0]?.Request ??
            throw Error("A verified PRQ2 Tombstone is missing.");
        for (var index = 0; index < orderedTombstones.Count; index++)
        {
            var verified = orderedTombstones[index] ??
                throw Error("A verified PRQ2 Tombstone is missing.");
            var request = verified.Request;
            var acknowledgement =
                acknowledgementRequest.Acknowledgements[index];
            if (request.Operation != MailboxPeerReplicationOperation.Tombstone ||
                request.Epoch != acknowledgementRequest.Epoch ||
                !FixedEquals(
                    request.OperationId.Span,
                    acknowledgementRequest.OperationId.Span) ||
                !FixedEquals(
                    request.BlindedMailboxId.Span,
                    acknowledgementRequest.MailboxId.Bytes.Span) ||
                !FixedEquals(
                    request.PlacementCommitment.Span,
                    placementCommitment) ||
                request.Cursor != acknowledgement.Cursor ||
                !FixedEquals(
                    request.Payload.Span,
                    acknowledgement.EnvelopeDigest.Span) ||
                !FixedEquals(
                    request.PayloadDigest.Span,
                    System.Security.Cryptography.SHA256.HashData(
                        acknowledgement.EnvelopeDigest.Span)) ||
                !SameFanout(request, firstRequest))
                throw Error(
                    $"PRQ2 Tombstone[{index}] does not match ordered MAK1 acknowledgement.");
        }
    }

    private static bool SameFanout(
        MailboxPeerWireRequestV2 request,
        MailboxPeerWireRequestV2 first) =>
        FixedEquals(request.SenderRouterId.Span, first.SenderRouterId.Span) &&
        FixedEquals(request.RecipientRouterId.Span, first.RecipientRouterId.Span) &&
        FixedEquals(
            request.MembershipCommitment.Span,
            first.MembershipCommitment.Span) &&
        FixedEquals(
            request.PlacementCommitment.Span,
            first.PlacementCommitment.Span);

    private static bool FixedEquals(
        ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static MailboxPeerReplicationException Error(string message) =>
        new(MailboxPeerReplicationError.BindingMismatch, message);
}
