using System.Buffers.Binary;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxReceiptCodec
{
    private static ReadOnlySpan<byte> ReplicaMagic => "MRR1"u8;
    private static ReadOnlySpan<byte> QuorumMagic => "MQR1"u8;
    private static ReadOnlySpan<byte> ErrorMagic => "MBE1"u8;
    private const byte Version = 1;

    public static byte[] GetReplicaSigningBytes(MailboxReplicaReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ValidateReplicaStatement(receipt);
        var encoded = new byte[MailboxReceiptLimits.ReplicaSigningLength];
        ReplicaMagic.CopyTo(encoded);
        encoded[4] = Version;
        encoded[5] = (byte)receipt.Status;
        encoded[6] = receipt.IsTombstone ? (byte)1 : (byte)0;
        receipt.ReplicaId.Span.CopyTo(encoded.AsSpan(8, MailboxReceiptLimits.IdentifierLength));
        receipt.OperationId.Span.CopyTo(encoded.AsSpan(24, MailboxReceiptLimits.IdentifierLength));
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(40, 8), receipt.Generation);
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(48, 8), receipt.Cursor);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(56, 4), receipt.AcceptedAtBucket);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(60, 4), receipt.DurableAtBucket);
        receipt.PayloadDigest.Span.CopyTo(encoded.AsSpan(64, MailboxReceiptLimits.DigestLength));
        return encoded;
    }

    public static byte[] EncodeReplica(MailboxReplicaReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ValidateSignature(receipt.Signature.Span);
        var signingBytes = GetReplicaSigningBytes(receipt);
        var encoded = new byte[
            MailboxReceiptLimits.ReplicaFixedHeaderLength + receipt.Signature.Length];
        signingBytes.CopyTo(encoded, 0);
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(96, 2),
            checked((ushort)receipt.Signature.Length));
        receipt.Signature.Span.CopyTo(
            encoded.AsSpan(MailboxReceiptLimits.ReplicaFixedHeaderLength));
        return encoded;
    }

    public static MailboxReplicaReceipt DecodeReplica(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is
            < MailboxReceiptLimits.ReplicaFixedHeaderLength +
              MailboxReceiptLimits.MinimumSignatureLength or
            > MailboxReceiptLimits.MaximumReplicaReceiptLength)
        {
            throw Error(
                MailboxReceiptError.EncodedLengthOutOfRange,
                "The replica receipt length is outside strict bounds.");
        }

        ValidateMagicAndVersion(encoded, ReplicaMagic);
        if (encoded[7] != 0 || encoded[98] != 0 || encoded[99] != 0)
        {
            throw Error(
                MailboxReceiptError.ReservedFieldNotZero,
                "Reserved replica receipt fields must be zero.");
        }

        var signatureLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(96, 2));
        if (signatureLength is
                < MailboxReceiptLimits.MinimumSignatureLength or
                > MailboxReceiptLimits.MaximumSignatureLength ||
            encoded.Length != MailboxReceiptLimits.ReplicaFixedHeaderLength + signatureLength)
        {
            throw Error(
                MailboxReceiptError.MalformedLength,
                "The replica signature length is not canonical.");
        }

        var status = (MailboxReceiptStatus)encoded[5];
        if (status is not (MailboxReceiptStatus.Accepted or MailboxReceiptStatus.Durable) ||
            encoded[6] > 1)
        {
            throw Error(MailboxReceiptError.InvalidEnumValue, "A replica receipt marker is invalid.");
        }

        var receipt = new MailboxReplicaReceipt
        {
            Status = status,
            IsTombstone = encoded[6] == 1,
            ReplicaId = encoded.Slice(8, MailboxReceiptLimits.IdentifierLength).ToArray(),
            OperationId = encoded.Slice(24, MailboxReceiptLimits.IdentifierLength).ToArray(),
            Generation = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(40, 8)),
            Cursor = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(48, 8)),
            AcceptedAtBucket = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(56, 4)),
            DurableAtBucket = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(60, 4)),
            PayloadDigest = encoded.Slice(64, MailboxReceiptLimits.DigestLength).ToArray(),
            Signature = encoded[MailboxReceiptLimits.ReplicaFixedHeaderLength..].ToArray()
        };
        ValidateReplicaStatement(receipt);
        return receipt;
    }

    public static byte[] GetQuorumSigningBytes(
        MailboxDurableQuorumReceipt receipt,
        IMailboxReceiptCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(crypto);
        ValidateIdentifier(receipt.CoordinatorId.Span);
        if (receipt.CoordinatorSequence == 0)
        {
            throw Error(
                MailboxReceiptError.InvalidCursor,
                "The coordinator sequence must be nonzero.");
        }

        var (first, second) = CanonicalReplicas(receipt.FirstReplica, receipt.SecondReplica);
        var firstBytes = EncodeReplica(first);
        var secondBytes = EncodeReplica(second);
        var firstDigest = crypto.Digest(firstBytes);
        var secondDigest = crypto.Digest(secondBytes);
        ValidateDigest(firstDigest);
        ValidateDigest(secondDigest);

        var encoded = new byte[MailboxReceiptLimits.QuorumSigningLength];
        QuorumMagic.CopyTo(encoded);
        encoded[4] = Version;
        receipt.CoordinatorId.Span.CopyTo(encoded.AsSpan(8, MailboxReceiptLimits.IdentifierLength));
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(24, 8), receipt.CoordinatorSequence);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(32, 2), checked((ushort)firstBytes.Length));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(34, 2), checked((ushort)secondBytes.Length));
        firstDigest.CopyTo(encoded, 36);
        secondDigest.CopyTo(encoded, 68);
        return encoded;
    }

    public static byte[] EncodeDurableQuorum(MailboxDurableQuorumReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ValidateIdentifier(receipt.CoordinatorId.Span);
        ValidateSignature(receipt.Signature.Span);
        if (receipt.CoordinatorSequence == 0)
        {
            throw Error(
                MailboxReceiptError.InvalidCursor,
                "The coordinator sequence must be nonzero.");
        }

        var (first, second) = CanonicalReplicas(receipt.FirstReplica, receipt.SecondReplica);
        var firstBytes = EncodeReplica(first);
        var secondBytes = EncodeReplica(second);
        var encoded = new byte[
            MailboxReceiptLimits.QuorumFixedHeaderLength +
            firstBytes.Length +
            secondBytes.Length +
            receipt.Signature.Length];

        QuorumMagic.CopyTo(encoded);
        encoded[4] = Version;
        receipt.CoordinatorId.Span.CopyTo(encoded.AsSpan(8, MailboxReceiptLimits.IdentifierLength));
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(24, 8), receipt.CoordinatorSequence);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(32, 2), checked((ushort)firstBytes.Length));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(34, 2), checked((ushort)secondBytes.Length));
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(100, 2),
            checked((ushort)receipt.Signature.Length));
        firstBytes.CopyTo(encoded, MailboxReceiptLimits.QuorumFixedHeaderLength);
        secondBytes.CopyTo(
            encoded,
            MailboxReceiptLimits.QuorumFixedHeaderLength + firstBytes.Length);
        receipt.Signature.Span.CopyTo(
            encoded.AsSpan(
                MailboxReceiptLimits.QuorumFixedHeaderLength +
                firstBytes.Length +
                secondBytes.Length));
        return encoded;
    }

    public static MailboxDurableQuorumReceipt DecodeDurableQuorum(
        ReadOnlySpan<byte> encoded,
        IMailboxReceiptCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(crypto);
        if (encoded.Length is
            < MailboxReceiptLimits.QuorumFixedHeaderLength +
              2 * (MailboxReceiptLimits.ReplicaFixedHeaderLength +
                   MailboxReceiptLimits.MinimumSignatureLength) +
              MailboxReceiptLimits.MinimumSignatureLength or
            > MailboxReceiptLimits.MaximumQuorumReceiptLength)
        {
            throw Error(
                MailboxReceiptError.EncodedLengthOutOfRange,
                "The quorum receipt length is outside strict bounds.");
        }

        ValidateMagicAndVersion(encoded, QuorumMagic);
        if (encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(36, 64).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded[102] != 0 ||
            encoded[103] != 0)
        {
            throw Error(
                MailboxReceiptError.ReservedFieldNotZero,
                "Reserved quorum receipt fields must be zero.");
        }

        var firstLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(32, 2));
        var secondLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(34, 2));
        var signatureLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(100, 2));
        if (firstLength is
                < MailboxReceiptLimits.ReplicaFixedHeaderLength +
                  MailboxReceiptLimits.MinimumSignatureLength or
                > MailboxReceiptLimits.MaximumReplicaReceiptLength ||
            secondLength is
                < MailboxReceiptLimits.ReplicaFixedHeaderLength +
                  MailboxReceiptLimits.MinimumSignatureLength or
                > MailboxReceiptLimits.MaximumReplicaReceiptLength ||
            signatureLength is
                < MailboxReceiptLimits.MinimumSignatureLength or
                > MailboxReceiptLimits.MaximumSignatureLength)
        {
            throw Error(MailboxReceiptError.MalformedLength, "A nested quorum length is invalid.");
        }

        var expectedLength =
            MailboxReceiptLimits.QuorumFixedHeaderLength +
            firstLength +
            secondLength +
            signatureLength;
        if (encoded.Length != expectedLength)
        {
            throw Error(
                MailboxReceiptError.MalformedLength,
                "The quorum receipt has trailing or truncated bytes.");
        }

        var firstOffset = MailboxReceiptLimits.QuorumFixedHeaderLength;
        var secondOffset = firstOffset + firstLength;
        var signatureOffset = secondOffset + secondLength;
        var first = DecodeReplica(encoded.Slice(firstOffset, firstLength));
        var second = DecodeReplica(encoded.Slice(secondOffset, secondLength));
        if (Compare(first.ReplicaId.Span, second.ReplicaId.Span) > 0)
        {
            throw Error(
                MailboxReceiptError.MalformedLength,
                "Nested replica receipts are not in canonical identifier order.");
        }

        var receipt = new MailboxDurableQuorumReceipt
        {
            CoordinatorId = encoded.Slice(8, MailboxReceiptLimits.IdentifierLength).ToArray(),
            CoordinatorSequence = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(24, 8)),
            FirstReplica = first,
            SecondReplica = second,
            Signature = encoded.Slice(signatureOffset, signatureLength).ToArray()
        };
        ValidateIdentifier(receipt.CoordinatorId.Span);
        if (receipt.CoordinatorSequence == 0)
        {
            throw Error(
                MailboxReceiptError.InvalidCursor,
                "The coordinator sequence must be nonzero.");
        }

        return receipt;
    }

    public static byte[] EncodeError(MailboxErrorReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ValidateError(receipt);
        var encoded = new byte[
            MailboxReceiptLimits.ErrorFixedHeaderLength + receipt.EvidenceDigest.Length];
        ErrorMagic.CopyTo(encoded);
        encoded[4] = Version;
        encoded[5] = (byte)receipt.Stage;
        encoded[6] = (byte)receipt.ErrorClass;
        encoded[7] = receipt.Retryable ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(8, 8), receipt.Generation);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(16, 4), receipt.RetryAfterBucket);
        encoded[20] = checked((byte)receipt.EvidenceDigest.Length);
        receipt.EvidenceDigest.Span.CopyTo(encoded.AsSpan(MailboxReceiptLimits.ErrorFixedHeaderLength));
        return encoded;
    }

    public static MailboxErrorReceipt DecodeError(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is not (
            MailboxReceiptLimits.ErrorFixedHeaderLength or
            MailboxReceiptLimits.ErrorFixedHeaderLength + MailboxReceiptLimits.DigestLength))
        {
            throw Error(
                MailboxReceiptError.EncodedLengthOutOfRange,
                "The error receipt length is not canonical.");
        }

        ValidateMagicAndVersion(encoded, ErrorMagic);
        if (encoded.Slice(21, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded[7] > 1 ||
            encoded[20] is not (0 or MailboxReceiptLimits.DigestLength) ||
            encoded.Length != MailboxReceiptLimits.ErrorFixedHeaderLength + encoded[20])
        {
            throw Error(
                MailboxReceiptError.InvalidErrorReceipt,
                "The error receipt framing is invalid.");
        }

        var receipt = new MailboxErrorReceipt
        {
            Stage = (MailboxReceiptStage)encoded[5],
            ErrorClass = (MailboxReceiptErrorClass)encoded[6],
            Retryable = encoded[7] == 1,
            Generation = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8)),
            RetryAfterBucket = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(16, 4)),
            EvidenceDigest = encoded[MailboxReceiptLimits.ErrorFixedHeaderLength..].ToArray()
        };
        ValidateError(receipt);
        return receipt;
    }

    private static void ValidateReplicaStatement(MailboxReplicaReceipt receipt)
    {
        if (receipt.Status is not (MailboxReceiptStatus.Accepted or MailboxReceiptStatus.Durable))
        {
            throw Error(MailboxReceiptError.InvalidEnumValue, "The receipt status is invalid.");
        }

        ValidateIdentifier(receipt.ReplicaId.Span);
        ValidateIdentifier(receipt.OperationId.Span);
        ValidateDigest(receipt.PayloadDigest.Span);
        if (receipt.Generation == 0)
        {
            throw Error(MailboxReceiptError.InvalidGeneration, "Generation must be nonzero.");
        }

        if (receipt.Cursor == 0)
        {
            throw Error(MailboxReceiptError.InvalidCursor, "Cursor must be nonzero.");
        }

        if (receipt.AcceptedAtBucket == 0 ||
            receipt.Status == MailboxReceiptStatus.Accepted && receipt.DurableAtBucket != 0 ||
            receipt.Status == MailboxReceiptStatus.Durable &&
            (receipt.DurableAtBucket < receipt.AcceptedAtBucket || receipt.DurableAtBucket == 0))
        {
            throw Error(
                MailboxReceiptError.InvalidTimestamp,
                "Accepted/durable time buckets are inconsistent.");
        }
    }

    private static void ValidateError(MailboxErrorReceipt receipt)
    {
        if (receipt.Stage is not (MailboxReceiptStage.Accepted or MailboxReceiptStage.Durable) ||
            receipt.ErrorClass is not (
                MailboxReceiptErrorClass.Capacity or
                MailboxReceiptErrorClass.QuorumUnavailable or
                MailboxReceiptErrorClass.Revoked or
                MailboxReceiptErrorClass.Expired or
                MailboxReceiptErrorClass.Replay or
                MailboxReceiptErrorClass.InvalidCapability) ||
            receipt.Generation == 0 ||
            receipt.Retryable != (receipt.RetryAfterBucket != 0) ||
            receipt.EvidenceDigest.Length is not (0 or MailboxReceiptLimits.DigestLength))
        {
            throw Error(
                MailboxReceiptError.InvalidErrorReceipt,
                "The error receipt is outside canonical bounds.");
        }
    }

    private static void ValidateMagicAndVersion(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> magic)
    {
        if (!encoded[..magic.Length].SequenceEqual(magic))
        {
            throw Error(MailboxReceiptError.InvalidMagic, "The mailbox receipt magic is invalid.");
        }

        if (encoded[4] != Version)
        {
            throw Error(
                MailboxReceiptError.UnsupportedVersion,
                "The mailbox receipt version is unsupported.");
        }
    }

    private static void ValidateIdentifier(ReadOnlySpan<byte> identifier)
    {
        if (identifier.Length != MailboxReceiptLimits.IdentifierLength ||
            identifier.IndexOfAnyExcept((byte)0) < 0)
        {
            throw Error(
                MailboxReceiptError.InvalidIdentifier,
                "Mailbox receipt identifiers must be fixed length and nonzero.");
        }
    }

    private static void ValidateDigest(ReadOnlySpan<byte> digest)
    {
        if (digest.Length != MailboxReceiptLimits.DigestLength)
        {
            throw Error(
                MailboxReceiptError.InvalidDigest,
                "Mailbox receipt digests must be fixed length.");
        }
    }

    private static void ValidateSignature(ReadOnlySpan<byte> signature)
    {
        if (signature.Length is
            < MailboxReceiptLimits.MinimumSignatureLength or
            > MailboxReceiptLimits.MaximumSignatureLength)
        {
            throw Error(
                MailboxReceiptError.InvalidSignature,
                "Mailbox receipt signatures are outside strict bounds.");
        }
    }

    private static (MailboxReplicaReceipt First, MailboxReplicaReceipt Second) CanonicalReplicas(
        MailboxReplicaReceipt first,
        MailboxReplicaReceipt second)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(second);
        return Compare(first.ReplicaId.Span, second.ReplicaId.Span) <= 0
            ? (first, second)
            : (second, first);
    }

    private static int Compare(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.SequenceCompareTo(right);

    private static MailboxReceiptException Error(
        MailboxReceiptError error,
        string message) =>
        new(error, message);
}
