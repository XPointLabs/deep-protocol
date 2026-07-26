using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxAggregateAckCodec
{
    private const byte Version = 1;
    private static ReadOnlySpan<byte> Magic => "MAR1"u8;

    public static byte[] Encode(MailboxAggregateAckResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        ValidateFixed(response.Epoch, response.OperationId.Span, response.TombstoneQuorums);
        var total = MailboxPeerReplicationLimits.AggregateAckHeaderLength +
                    response.TombstoneQuorums.Sum(static receipt => 2 + receipt.Length);
        if (total > MailboxPeerReplicationLimits.MaximumAggregateAckLength)
            throw Error(MailboxPeerReplicationError.InvalidLength, "MAR1 exceeds its total bound.");
        var output = new byte[total];
        Magic.CopyTo(output);
        output[4] = Version;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), response.Epoch);
        response.OperationId.Span.CopyTo(output.AsSpan(16));
        BinaryPrimitives.WriteUInt16BigEndian(
            output.AsSpan(32),
            checked((ushort)response.TombstoneQuorums.Count));
        var offset = MailboxPeerReplicationLimits.AggregateAckHeaderLength;
        foreach (var receipt in response.TombstoneQuorums)
        {
            _ = MailboxReceiptV2Codec.DecodeDurableQuorum(receipt.Span);
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)receipt.Length));
            offset += 2;
            receipt.Span.CopyTo(output.AsSpan(offset));
            offset += receipt.Length;
        }
        return output;
    }

    public static MailboxAggregateAckResponse Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < MailboxPeerReplicationLimits.AggregateAckHeaderLength ||
            encoded.Length > MailboxPeerReplicationLimits.MaximumAggregateAckLength)
            throw Error(MailboxPeerReplicationError.InvalidLength, "MAR1 length is outside strict bounds.");
        if (!encoded[..4].SequenceEqual(Magic))
            throw Error(MailboxPeerReplicationError.InvalidMagic, "MAR1 magic is invalid.");
        if (encoded[4] != Version)
            throw Error(MailboxPeerReplicationError.UnsupportedVersion, "MAR1 version is unsupported.");
        if (encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(34, 6).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(MailboxPeerReplicationError.ReservedFieldNotZero, "MAR1 reserved bytes must be zero.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(32, 2));
        if (count is 0 or > MailboxClientLimits.MaximumPageItems)
            throw Error(MailboxPeerReplicationError.InvalidLength, "MAR1 receipt count is invalid.");
        var receipts = new List<ReadOnlyMemory<byte>>(count);
        var offset = MailboxPeerReplicationLimits.AggregateAckHeaderLength;
        for (var index = 0; index < count; index++)
        {
            if (offset + 2 > encoded.Length)
                throw Error(MailboxPeerReplicationError.InvalidLength, "MAR1 is truncated before a receipt.");
            var length = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset, 2));
            offset += 2;
            if (length == 0 || offset + length > encoded.Length)
                throw Error(MailboxPeerReplicationError.InvalidLength, "MAR1 nested receipt length is invalid.");
            var receipt = encoded.Slice(offset, length).ToArray();
            _ = MailboxReceiptV2Codec.DecodeDurableQuorum(receipt);
            receipts.Add(receipt);
            offset += length;
        }
        if (offset != encoded.Length)
            throw Error(MailboxPeerReplicationError.InvalidLength, "MAR1 has trailing bytes.");
        var response = new MailboxAggregateAckResponse
        {
            Epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8)),
            OperationId = encoded.Slice(16, 16).ToArray(),
            TombstoneQuorums = receipts
        };
        ValidateFixed(response.Epoch, response.OperationId.Span, response.TombstoneQuorums);
        return response;
    }

    public static IReadOnlyList<VerifiedMailboxDurableQuorumV2> Verify(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> expectedOperationId,
        ulong expectedEpoch,
        IReadOnlyList<MailboxDurableQuorumExpectationV2> orderedExpectations,
        IMailboxReceiptCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(orderedExpectations);
        ArgumentNullException.ThrowIfNull(crypto);
        var response = Decode(encoded);
        if (response.Epoch != expectedEpoch ||
            expectedOperationId.Length != 16 ||
            !CryptographicOperations.FixedTimeEquals(response.OperationId.Span, expectedOperationId) ||
            response.TombstoneQuorums.Count != orderedExpectations.Count)
            throw Error(MailboxPeerReplicationError.BindingMismatch, "MAR1 does not match exact ACK operation.");
        var verified = new List<VerifiedMailboxDurableQuorumV2>(orderedExpectations.Count);
        for (var index = 0; index < orderedExpectations.Count; index++)
        {
            var expectation = orderedExpectations[index];
            if (expectation.Disposition != MailboxReplicaDisposition.Tombstone ||
                expectation.Epoch != expectedEpoch ||
                !CryptographicOperations.FixedTimeEquals(
                    expectation.OperationId.Span,
                    expectedOperationId))
                throw Error(MailboxPeerReplicationError.BindingMismatch, "MAR1 expectation is not an exact tombstone ACK.");
            try
            {
                verified.Add(MailboxReceiptV2Codec.VerifyDurableQuorum(
                    response.TombstoneQuorums[index].Span,
                    crypto,
                    expectation));
            }
            catch (MailboxReceiptException exception)
            {
                throw new MailboxPeerReplicationException(
                    MailboxPeerReplicationError.InvalidReceipt,
                    $"MAR1 nested MQR2[{index}] is invalid: {exception.Error}.");
            }
        }
        return verified;
    }

    private static void ValidateFixed(
        ulong epoch,
        ReadOnlySpan<byte> operationId,
        IReadOnlyList<ReadOnlyMemory<byte>> receipts)
    {
        if (epoch == 0 || operationId.Length != 16 ||
            operationId.IndexOfAnyExcept((byte)0) < 0 ||
            receipts is null || receipts.Count is 0 or > MailboxClientLimits.MaximumPageItems ||
            receipts.Any(static receipt => receipt.Length is 0 or > ushort.MaxValue))
            throw Error(MailboxPeerReplicationError.InvalidField, "MAR1 fixed fields are invalid.");
    }

    private static MailboxPeerReplicationException Error(
        MailboxPeerReplicationError error,
        string message) => new(error, message);
}
