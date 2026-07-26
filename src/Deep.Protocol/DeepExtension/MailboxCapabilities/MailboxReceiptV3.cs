using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxReceiptV3Limits
{
    public const int QuorumSigningLength = 116;
    public const int QuorumFixedHeaderLength = 120;
    public const int MaximumQuorumLength =
        QuorumFixedHeaderLength +
        (MailboxReceiptV2Limits.MaximumReplicaLength * 2) +
        MailboxReceiptLimits.MaximumSignatureLength;
}

/// <summary>
/// PRQ2-only durable quorum. Its MQR3 signing domain cannot be accepted as the
/// legacy PRQ1/MQR2 quorum even when both contain the same canonical MRR2 frames.
/// </summary>
public sealed record MailboxDurableQuorumReceiptV3
{
    public required ReadOnlyMemory<byte> CoordinatorId { get; init; }
    public required ulong CoordinatorSequence { get; init; }
    public required MailboxReplicaReceiptV2 FirstReplica { get; init; }
    public required MailboxReplicaReceiptV2 SecondReplica { get; init; }
    public required ReadOnlyMemory<byte> Signature { get; init; }
}

public sealed record VerifiedMailboxDurableQuorumV3(
    ulong Cursor,
    MailboxReplicaDisposition Disposition,
    IReadOnlyList<MailboxReplicaReceiptV2> ReplicaReceipts,
    MailboxDurableQuorumReceiptV3 CoordinatorReceipt);

public static class MailboxReceiptV3Codec
{
    private static ReadOnlySpan<byte> QuorumMagic => "MQR3"u8;
    private const byte Version = 3;

    public static byte[] GetQuorumSigningBytes(MailboxDurableQuorumReceiptV3 receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ValidateCoordinator(receipt);
        var (first, second) = CanonicalReplicas(receipt.FirstReplica, receipt.SecondReplica);
        var firstBytes = MailboxReceiptV2Codec.EncodeReplica(first);
        var secondBytes = MailboxReceiptV2Codec.EncodeReplica(second);
        var encoded = new byte[MailboxReceiptV3Limits.QuorumSigningLength];
        QuorumMagic.CopyTo(encoded);
        encoded[4] = Version;
        receipt.CoordinatorId.Span.CopyTo(
            encoded.AsSpan(8, MailboxReceiptV2Limits.ReplicaIdLength));
        BinaryPrimitives.WriteUInt64BigEndian(
            encoded.AsSpan(40, 8),
            receipt.CoordinatorSequence);
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(48, 2),
            checked((ushort)firstBytes.Length));
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(50, 2),
            checked((ushort)secondBytes.Length));
        SHA256.HashData(firstBytes).CopyTo(encoded, 52);
        SHA256.HashData(secondBytes).CopyTo(encoded, 84);
        return encoded;
    }

    public static byte[] EncodeDurableQuorum(MailboxDurableQuorumReceiptV3 receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ValidateCoordinator(receipt);
        ValidateSignature(receipt.Signature.Span);
        var (first, second) = CanonicalReplicas(receipt.FirstReplica, receipt.SecondReplica);
        var firstBytes = MailboxReceiptV2Codec.EncodeReplica(first);
        var secondBytes = MailboxReceiptV2Codec.EncodeReplica(second);
        var encoded = new byte[
            MailboxReceiptV3Limits.QuorumFixedHeaderLength +
            firstBytes.Length +
            secondBytes.Length +
            receipt.Signature.Length];
        QuorumMagic.CopyTo(encoded);
        encoded[4] = Version;
        receipt.CoordinatorId.Span.CopyTo(
            encoded.AsSpan(8, MailboxReceiptV2Limits.ReplicaIdLength));
        BinaryPrimitives.WriteUInt64BigEndian(
            encoded.AsSpan(40, 8),
            receipt.CoordinatorSequence);
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(48, 2),
            checked((ushort)firstBytes.Length));
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(50, 2),
            checked((ushort)secondBytes.Length));
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(116, 2),
            checked((ushort)receipt.Signature.Length));
        firstBytes.CopyTo(encoded, MailboxReceiptV3Limits.QuorumFixedHeaderLength);
        secondBytes.CopyTo(
            encoded,
            MailboxReceiptV3Limits.QuorumFixedHeaderLength + firstBytes.Length);
        receipt.Signature.Span.CopyTo(encoded.AsSpan(
            MailboxReceiptV3Limits.QuorumFixedHeaderLength +
            firstBytes.Length +
            secondBytes.Length));
        return encoded;
    }

    public static MailboxDurableQuorumReceiptV3 DecodeDurableQuorum(
        ReadOnlySpan<byte> encoded)
    {
        var minimum =
            MailboxReceiptV3Limits.QuorumFixedHeaderLength +
            (2 * (MailboxReceiptV2Limits.ReplicaFixedHeaderLength +
                  MailboxReceiptLimits.MinimumSignatureLength)) +
            MailboxReceiptLimits.MinimumSignatureLength;
        if (encoded.Length < minimum ||
            encoded.Length > MailboxReceiptV3Limits.MaximumQuorumLength)
            throw Error(
                MailboxReceiptError.EncodedLengthOutOfRange,
                "MQR3 length is outside strict bounds.");
        if (!encoded[..4].SequenceEqual(QuorumMagic))
            throw Error(MailboxReceiptError.InvalidMagic, "MQR3 magic is invalid.");
        if (encoded[4] != Version)
            throw Error(
                MailboxReceiptError.UnsupportedVersion,
                "MQR3 version is unsupported.");
        if (encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(52, 64).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(118, 2).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(
                MailboxReceiptError.ReservedFieldNotZero,
                "MQR3 reserved fields must be zero.");

        var firstLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(48, 2));
        var secondLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(50, 2));
        var signatureLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(116, 2));
        if (firstLength is
                < MailboxReceiptV2Limits.ReplicaFixedHeaderLength +
                  MailboxReceiptLimits.MinimumSignatureLength or
                > MailboxReceiptV2Limits.MaximumReplicaLength ||
            secondLength is
                < MailboxReceiptV2Limits.ReplicaFixedHeaderLength +
                  MailboxReceiptLimits.MinimumSignatureLength or
                > MailboxReceiptV2Limits.MaximumReplicaLength ||
            signatureLength is
                < MailboxReceiptLimits.MinimumSignatureLength or
                > MailboxReceiptLimits.MaximumSignatureLength ||
            encoded.Length !=
                MailboxReceiptV3Limits.QuorumFixedHeaderLength +
                firstLength +
                secondLength +
                signatureLength)
            throw Error(
                MailboxReceiptError.MalformedLength,
                "Nested MQR3 lengths are invalid.");

        var firstOffset = MailboxReceiptV3Limits.QuorumFixedHeaderLength;
        var secondOffset = firstOffset + firstLength;
        var signatureOffset = secondOffset + secondLength;
        var first = MailboxReceiptV2Codec.DecodeReplica(
            encoded.Slice(firstOffset, firstLength));
        var second = MailboxReceiptV2Codec.DecodeReplica(
            encoded.Slice(secondOffset, secondLength));
        if (first.ReplicaId.Span.SequenceCompareTo(second.ReplicaId.Span) > 0)
            throw Error(
                MailboxReceiptError.MalformedLength,
                "MQR3 replicas are not in canonical order.");

        var receipt = new MailboxDurableQuorumReceiptV3
        {
            CoordinatorId = encoded.Slice(
                8,
                MailboxReceiptV2Limits.ReplicaIdLength).ToArray(),
            CoordinatorSequence = BinaryPrimitives.ReadUInt64BigEndian(
                encoded.Slice(40, 8)),
            FirstReplica = first,
            SecondReplica = second,
            Signature = encoded.Slice(signatureOffset, signatureLength).ToArray()
        };
        ValidateCoordinator(receipt);
        return receipt;
    }

    private static (
        MailboxReplicaReceiptV2 First,
        MailboxReplicaReceiptV2 Second) CanonicalReplicas(
            MailboxReplicaReceiptV2 first,
            MailboxReplicaReceiptV2 second)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(second);
        return first.ReplicaId.Span.SequenceCompareTo(second.ReplicaId.Span) <= 0
            ? (first, second)
            : (second, first);
    }

    private static void ValidateCoordinator(MailboxDurableQuorumReceiptV3 receipt)
    {
        if (receipt.CoordinatorId.Length != MailboxReceiptV2Limits.ReplicaIdLength ||
            receipt.CoordinatorId.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Error(
                MailboxReceiptError.InvalidIdentifier,
                "MQR3 coordinator id is invalid.");
        if (receipt.CoordinatorSequence == 0)
            throw Error(
                MailboxReceiptError.InvalidCursor,
                "MQR3 coordinator sequence must be nonzero.");
    }

    private static void ValidateSignature(ReadOnlySpan<byte> signature)
    {
        if (signature.Length is
            < MailboxReceiptLimits.MinimumSignatureLength or
            > MailboxReceiptLimits.MaximumSignatureLength)
            throw Error(
                MailboxReceiptError.InvalidSignature,
                "MQR3 signature length is invalid.");
    }

    private static MailboxReceiptException Error(
        MailboxReceiptError error,
        string message) => new(error, message);
}
