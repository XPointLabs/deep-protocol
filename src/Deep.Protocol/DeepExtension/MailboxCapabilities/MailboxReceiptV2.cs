using System.Buffers.Binary;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxReceiptV2Limits
{
    public const int ReplicaIdLength = 32;
    public const int OperationIdLength = 16;
    public const int DigestLength = 32;
    public const int ReplicaSigningLength = 224;
    public const int ReplicaFixedHeaderLength = 232;
    public const int QuorumSigningLength = 116;
    public const int QuorumFixedHeaderLength = 120;
    public const int MaximumReplicaLength =
        ReplicaFixedHeaderLength + MailboxReceiptLimits.MaximumSignatureLength;
    public const int MaximumQuorumLength =
        QuorumFixedHeaderLength +
        MaximumReplicaLength * 2 +
        MailboxReceiptLimits.MaximumSignatureLength;
}

public enum MailboxReplicaDisposition : byte
{
    Stored = 1,
    Duplicate = 2,
    Tombstone = 3
}

public sealed record MailboxReplicaReceiptV2
{
    public required MailboxReceiptStatus Status { get; init; }
    public required MailboxReplicaDisposition Disposition { get; init; }
    public required ReadOnlyMemory<byte> ReplicaId { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ulong Epoch { get; init; }
    public required ulong Cursor { get; init; }
    public required ulong AcceptedAtUnixSeconds { get; init; }
    public required ulong DurableAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ReadOnlyMemory<byte> BlindedMailboxId { get; init; }
    public required ReadOnlyMemory<byte> PlacementCommitment { get; init; }
    public required ReadOnlyMemory<byte> MembershipCommitment { get; init; }
    public required ReadOnlyMemory<byte> EnvelopeDigest { get; init; }
    public required ReadOnlyMemory<byte> Signature { get; init; }
}

public sealed record MailboxDurableQuorumReceiptV2
{
    public required ReadOnlyMemory<byte> CoordinatorId { get; init; }
    public required ulong CoordinatorSequence { get; init; }
    public required MailboxReplicaReceiptV2 FirstReplica { get; init; }
    public required MailboxReplicaReceiptV2 SecondReplica { get; init; }
    public required ReadOnlyMemory<byte> Signature { get; init; }
}

public sealed record MailboxDurableQuorumExpectationV2
{
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required ulong Epoch { get; init; }
    public required ulong Cursor { get; init; }
    public required MailboxReplicaDisposition Disposition { get; init; }
    public required ReadOnlyMemory<byte> BlindedMailboxId { get; init; }
    public required ReadOnlyMemory<byte> PlacementCommitment { get; init; }
    public required ReadOnlyMemory<byte> MembershipCommitment { get; init; }
    public required ReadOnlyMemory<byte> EnvelopeDigest { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
}

public sealed record VerifiedMailboxDurableQuorumV2(
    ulong Cursor,
    MailboxReplicaDisposition Disposition,
    IReadOnlyList<MailboxReplicaReceiptV2> ReplicaReceipts,
    MailboxDurableQuorumReceiptV2 CoordinatorReceipt);

public static class MailboxReceiptV2Codec
{
    private static ReadOnlySpan<byte> ReplicaMagic => "MRR2"u8;
    private static ReadOnlySpan<byte> QuorumMagic => "MQR2"u8;
    private const byte Version = 2;

    public static byte[] GetReplicaSigningBytes(MailboxReplicaReceiptV2 receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ValidateReplica(receipt);
        var encoded = new byte[MailboxReceiptV2Limits.ReplicaSigningLength];
        ReplicaMagic.CopyTo(encoded);
        encoded[4] = Version;
        encoded[5] = (byte)receipt.Status;
        encoded[6] = (byte)receipt.Disposition;
        receipt.ReplicaId.Span.CopyTo(encoded.AsSpan(8, MailboxReceiptV2Limits.ReplicaIdLength));
        receipt.OperationId.Span.CopyTo(encoded.AsSpan(40, MailboxReceiptV2Limits.OperationIdLength));
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(56, 8), receipt.Epoch);
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(64, 8), receipt.Cursor);
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(72, 8), receipt.AcceptedAtUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(80, 8), receipt.DurableAtUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(88, 8), receipt.ExpiresAtUnixSeconds);
        receipt.BlindedMailboxId.Span.CopyTo(encoded.AsSpan(96, MailboxClientLimits.BlindedIdentifierLength));
        receipt.PlacementCommitment.Span.CopyTo(encoded.AsSpan(128, MailboxReceiptV2Limits.DigestLength));
        receipt.MembershipCommitment.Span.CopyTo(encoded.AsSpan(160, MailboxReceiptV2Limits.DigestLength));
        receipt.EnvelopeDigest.Span.CopyTo(encoded.AsSpan(192, MailboxReceiptV2Limits.DigestLength));
        return encoded;
    }

    public static byte[] EncodeReplica(MailboxReplicaReceiptV2 receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ValidateSignature(receipt.Signature.Span);
        var signingBytes = GetReplicaSigningBytes(receipt);
        var encoded = new byte[
            MailboxReceiptV2Limits.ReplicaFixedHeaderLength + receipt.Signature.Length];
        signingBytes.CopyTo(encoded, 0);
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(224, 2),
            checked((ushort)receipt.Signature.Length));
        receipt.Signature.Span.CopyTo(encoded.AsSpan(MailboxReceiptV2Limits.ReplicaFixedHeaderLength));
        return encoded;
    }

    public static MailboxReplicaReceiptV2 DecodeReplica(ReadOnlySpan<byte> encoded)
    {
        ValidateFrame(
            encoded,
            ReplicaMagic,
            MailboxReceiptV2Limits.ReplicaFixedHeaderLength +
            MailboxReceiptLimits.MinimumSignatureLength,
            MailboxReceiptV2Limits.MaximumReplicaLength);
        if (encoded[7] != 0 || encoded.Slice(226, 6).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw Error(MailboxReceiptError.ReservedFieldNotZero, "Reserved V2 replica fields must be zero.");
        }

        var signatureLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(224, 2));
        if (signatureLength is
                < MailboxReceiptLimits.MinimumSignatureLength or
                > MailboxReceiptLimits.MaximumSignatureLength ||
            encoded.Length != MailboxReceiptV2Limits.ReplicaFixedHeaderLength + signatureLength)
        {
            throw Error(MailboxReceiptError.MalformedLength, "The V2 replica signature length is invalid.");
        }

        var receipt = new MailboxReplicaReceiptV2
        {
            Status = (MailboxReceiptStatus)encoded[5],
            Disposition = (MailboxReplicaDisposition)encoded[6],
            ReplicaId = encoded.Slice(8, MailboxReceiptV2Limits.ReplicaIdLength).ToArray(),
            OperationId = encoded.Slice(40, MailboxReceiptV2Limits.OperationIdLength).ToArray(),
            Epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(56, 8)),
            Cursor = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(64, 8)),
            AcceptedAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(72, 8)),
            DurableAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(80, 8)),
            ExpiresAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(88, 8)),
            BlindedMailboxId = encoded.Slice(96, MailboxClientLimits.BlindedIdentifierLength).ToArray(),
            PlacementCommitment = encoded.Slice(128, MailboxReceiptV2Limits.DigestLength).ToArray(),
            MembershipCommitment = encoded.Slice(160, MailboxReceiptV2Limits.DigestLength).ToArray(),
            EnvelopeDigest = encoded.Slice(192, MailboxReceiptV2Limits.DigestLength).ToArray(),
            Signature = encoded[MailboxReceiptV2Limits.ReplicaFixedHeaderLength..].ToArray()
        };
        ValidateReplica(receipt);
        return receipt;
    }

    public static byte[] GetQuorumSigningBytes(
        MailboxDurableQuorumReceiptV2 receipt,
        IMailboxReceiptCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(crypto);
        ValidateFixedNonzero(receipt.CoordinatorId.Span, MailboxReceiptV2Limits.ReplicaIdLength);
        if (receipt.CoordinatorSequence == 0)
        {
            throw Error(MailboxReceiptError.InvalidCursor, "Coordinator sequence must be nonzero.");
        }

        var (first, second) = CanonicalReplicas(receipt.FirstReplica, receipt.SecondReplica);
        var firstBytes = EncodeReplica(first);
        var secondBytes = EncodeReplica(second);
        var firstDigest = crypto.Digest(firstBytes);
        var secondDigest = crypto.Digest(secondBytes);
        ValidateFixedNonzero(firstDigest, MailboxReceiptV2Limits.DigestLength);
        ValidateFixedNonzero(secondDigest, MailboxReceiptV2Limits.DigestLength);
        var encoded = new byte[MailboxReceiptV2Limits.QuorumSigningLength];
        QuorumMagic.CopyTo(encoded);
        encoded[4] = Version;
        receipt.CoordinatorId.Span.CopyTo(encoded.AsSpan(8, MailboxReceiptV2Limits.ReplicaIdLength));
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(40, 8), receipt.CoordinatorSequence);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(48, 2), checked((ushort)firstBytes.Length));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(50, 2), checked((ushort)secondBytes.Length));
        firstDigest.CopyTo(encoded, 52);
        secondDigest.CopyTo(encoded, 84);
        return encoded;
    }

    public static byte[] EncodeDurableQuorum(MailboxDurableQuorumReceiptV2 receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ValidateSignature(receipt.Signature.Span);
        ValidateFixedNonzero(receipt.CoordinatorId.Span, MailboxReceiptV2Limits.ReplicaIdLength);
        if (receipt.CoordinatorSequence == 0)
        {
            throw Error(MailboxReceiptError.InvalidCursor, "Coordinator sequence must be nonzero.");
        }

        var (first, second) = CanonicalReplicas(receipt.FirstReplica, receipt.SecondReplica);
        var firstBytes = EncodeReplica(first);
        var secondBytes = EncodeReplica(second);
        var encoded = new byte[
            MailboxReceiptV2Limits.QuorumFixedHeaderLength +
            firstBytes.Length +
            secondBytes.Length +
            receipt.Signature.Length];
        QuorumMagic.CopyTo(encoded);
        encoded[4] = Version;
        receipt.CoordinatorId.Span.CopyTo(encoded.AsSpan(8, MailboxReceiptV2Limits.ReplicaIdLength));
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(40, 8), receipt.CoordinatorSequence);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(48, 2), checked((ushort)firstBytes.Length));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(50, 2), checked((ushort)secondBytes.Length));
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(116, 2),
            checked((ushort)receipt.Signature.Length));
        firstBytes.CopyTo(encoded, MailboxReceiptV2Limits.QuorumFixedHeaderLength);
        secondBytes.CopyTo(encoded, MailboxReceiptV2Limits.QuorumFixedHeaderLength + firstBytes.Length);
        receipt.Signature.Span.CopyTo(encoded.AsSpan(
            MailboxReceiptV2Limits.QuorumFixedHeaderLength + firstBytes.Length + secondBytes.Length));
        return encoded;
    }

    public static MailboxDurableQuorumReceiptV2 DecodeDurableQuorum(ReadOnlySpan<byte> encoded)
    {
        ValidateFrame(
            encoded,
            QuorumMagic,
            MailboxReceiptV2Limits.QuorumFixedHeaderLength +
            2 * (MailboxReceiptV2Limits.ReplicaFixedHeaderLength +
                 MailboxReceiptLimits.MinimumSignatureLength) +
            MailboxReceiptLimits.MinimumSignatureLength,
            MailboxReceiptV2Limits.MaximumQuorumLength);
        if (encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(52, 64).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(118, 2).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw Error(MailboxReceiptError.ReservedFieldNotZero, "Reserved V2 quorum fields must be zero.");
        }

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
            encoded.Length != MailboxReceiptV2Limits.QuorumFixedHeaderLength +
                              firstLength + secondLength + signatureLength)
        {
            throw Error(MailboxReceiptError.MalformedLength, "Nested V2 quorum lengths are invalid.");
        }

        var firstOffset = MailboxReceiptV2Limits.QuorumFixedHeaderLength;
        var secondOffset = firstOffset + firstLength;
        var signatureOffset = secondOffset + secondLength;
        var first = DecodeReplica(encoded.Slice(firstOffset, firstLength));
        var second = DecodeReplica(encoded.Slice(secondOffset, secondLength));
        if (first.ReplicaId.Span.SequenceCompareTo(second.ReplicaId.Span) > 0)
        {
            throw Error(MailboxReceiptError.MalformedLength, "V2 replicas are not in canonical order.");
        }

        var receipt = new MailboxDurableQuorumReceiptV2
        {
            CoordinatorId = encoded.Slice(8, MailboxReceiptV2Limits.ReplicaIdLength).ToArray(),
            CoordinatorSequence = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(40, 8)),
            FirstReplica = first,
            SecondReplica = second,
            Signature = encoded.Slice(signatureOffset, signatureLength).ToArray()
        };
        ValidateFixedNonzero(receipt.CoordinatorId.Span, MailboxReceiptV2Limits.ReplicaIdLength);
        if (receipt.CoordinatorSequence == 0)
        {
            throw Error(MailboxReceiptError.InvalidCursor, "Coordinator sequence must be nonzero.");
        }

        return receipt;
    }

    public static VerifiedMailboxDurableQuorumV2 VerifyDurableQuorum(
        ReadOnlySpan<byte> encoded,
        IMailboxReceiptCrypto crypto,
        MailboxDurableQuorumExpectationV2 expectation)
    {
        ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(expectation);
        var receipt = DecodeDurableQuorum(encoded);
        var replicas = new[] { receipt.FirstReplica, receipt.SecondReplica };
        if (replicas[0].ReplicaId.Span.SequenceEqual(replicas[1].ReplicaId.Span))
        {
            throw Error(MailboxReceiptError.DuplicateReplica, "Durable quorum requires two distinct replicas.");
        }

        foreach (var replica in replicas)
        {
            if (!crypto.VerifyReplica(
                    replica.ReplicaId.Span,
                    GetReplicaSigningBytes(replica),
                    replica.Signature.Span))
            {
                throw Error(MailboxReceiptError.InvalidReplicaSignature, "A V2 replica signature is invalid.");
            }

            if (replica.Status != MailboxReceiptStatus.Durable)
            {
                throw Error(MailboxReceiptError.NotDurable, "Accepted does not satisfy durable quorum.");
            }
        }

        if (!StatementsAgree(replicas[0], replicas[1]))
        {
            throw Error(MailboxReceiptError.ReplicaDisagreement, "V2 replica statements disagree.");
        }

        if (!MatchesExpectation(replicas[0], expectation))
        {
            throw Error(MailboxReceiptError.UnexpectedStatement, "V2 receipt does not match caller context.");
        }

        if (!crypto.VerifyCoordinator(
                receipt.CoordinatorId.Span,
                GetQuorumSigningBytes(receipt, crypto),
                receipt.Signature.Span))
        {
            throw Error(MailboxReceiptError.InvalidCoordinatorSignature, "The V2 coordinator signature is invalid.");
        }

        return new VerifiedMailboxDurableQuorumV2(
            replicas[0].Cursor,
            replicas[0].Disposition,
            replicas,
            receipt);
    }

    private static void ValidateReplica(MailboxReplicaReceiptV2 receipt)
    {
        if (receipt.Status is not (MailboxReceiptStatus.Accepted or MailboxReceiptStatus.Durable) ||
            receipt.Disposition is not (
                MailboxReplicaDisposition.Stored or
                MailboxReplicaDisposition.Duplicate or
                MailboxReplicaDisposition.Tombstone))
        {
            throw Error(MailboxReceiptError.InvalidEnumValue, "V2 receipt status/disposition is invalid.");
        }

        ValidateFixedNonzero(receipt.ReplicaId.Span, MailboxReceiptV2Limits.ReplicaIdLength);
        ValidateFixedNonzero(receipt.OperationId.Span, MailboxReceiptV2Limits.OperationIdLength);
        ValidateFixedNonzero(receipt.BlindedMailboxId.Span, MailboxClientLimits.BlindedIdentifierLength);
        ValidateFixedNonzero(receipt.PlacementCommitment.Span, MailboxReceiptV2Limits.DigestLength);
        ValidateFixedNonzero(receipt.MembershipCommitment.Span, MailboxReceiptV2Limits.DigestLength);
        ValidateFixedNonzero(receipt.EnvelopeDigest.Span, MailboxReceiptV2Limits.DigestLength);
        if (receipt.Epoch == 0 || receipt.Cursor == 0)
        {
            throw Error(MailboxReceiptError.InvalidGeneration, "V2 epoch/cursor must be nonzero.");
        }

        if (receipt.AcceptedAtUnixSeconds == 0 ||
            receipt.ExpiresAtUnixSeconds <= receipt.AcceptedAtUnixSeconds ||
            receipt.Status == MailboxReceiptStatus.Accepted && receipt.DurableAtUnixSeconds != 0 ||
            receipt.Status == MailboxReceiptStatus.Durable &&
            (receipt.DurableAtUnixSeconds < receipt.AcceptedAtUnixSeconds ||
             receipt.DurableAtUnixSeconds >= receipt.ExpiresAtUnixSeconds))
        {
            throw Error(MailboxReceiptError.InvalidTimestamp, "V2 accepted/durable/expiry times are inconsistent.");
        }
    }

    private static bool StatementsAgree(MailboxReplicaReceiptV2 left, MailboxReplicaReceiptV2 right) =>
        left.OperationId.Span.SequenceEqual(right.OperationId.Span) &&
        left.Epoch == right.Epoch &&
        left.Cursor == right.Cursor &&
        left.Disposition == right.Disposition &&
        left.ExpiresAtUnixSeconds == right.ExpiresAtUnixSeconds &&
        left.BlindedMailboxId.Span.SequenceEqual(right.BlindedMailboxId.Span) &&
        left.PlacementCommitment.Span.SequenceEqual(right.PlacementCommitment.Span) &&
        left.MembershipCommitment.Span.SequenceEqual(right.MembershipCommitment.Span) &&
        left.EnvelopeDigest.Span.SequenceEqual(right.EnvelopeDigest.Span);

    private static bool MatchesExpectation(
        MailboxReplicaReceiptV2 receipt,
        MailboxDurableQuorumExpectationV2 expectation) =>
        receipt.OperationId.Span.SequenceEqual(expectation.OperationId.Span) &&
        receipt.Epoch == expectation.Epoch &&
        receipt.Cursor == expectation.Cursor &&
        receipt.Disposition == expectation.Disposition &&
        receipt.ExpiresAtUnixSeconds == expectation.ExpiresAtUnixSeconds &&
        receipt.BlindedMailboxId.Span.SequenceEqual(expectation.BlindedMailboxId.Span) &&
        receipt.PlacementCommitment.Span.SequenceEqual(expectation.PlacementCommitment.Span) &&
        receipt.MembershipCommitment.Span.SequenceEqual(expectation.MembershipCommitment.Span) &&
        receipt.EnvelopeDigest.Span.SequenceEqual(expectation.EnvelopeDigest.Span);

    private static (MailboxReplicaReceiptV2 First, MailboxReplicaReceiptV2 Second) CanonicalReplicas(
        MailboxReplicaReceiptV2 first,
        MailboxReplicaReceiptV2 second)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(second);
        return first.ReplicaId.Span.SequenceCompareTo(second.ReplicaId.Span) <= 0
            ? (first, second)
            : (second, first);
    }

    private static void ValidateFrame(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> magic,
        int minimum,
        int maximum)
    {
        if (encoded.Length < minimum || encoded.Length > maximum)
        {
            throw Error(MailboxReceiptError.EncodedLengthOutOfRange, "V2 receipt length is outside strict bounds.");
        }

        if (!encoded[..4].SequenceEqual(magic))
        {
            throw Error(MailboxReceiptError.InvalidMagic, "V2 receipt magic is invalid.");
        }

        if (encoded[4] != Version)
        {
            throw Error(MailboxReceiptError.UnsupportedVersion, "V2 receipt version is unsupported.");
        }
    }

    private static void ValidateFixedNonzero(ReadOnlySpan<byte> value, int length)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw Error(MailboxReceiptError.InvalidIdentifier, "A V2 receipt identifier/digest is invalid.");
        }
    }

    private static void ValidateSignature(ReadOnlySpan<byte> signature)
    {
        if (signature.Length is
            < MailboxReceiptLimits.MinimumSignatureLength or
            > MailboxReceiptLimits.MaximumSignatureLength)
        {
            throw Error(MailboxReceiptError.InvalidSignature, "V2 receipt signature length is invalid.");
        }
    }

    private static MailboxReceiptException Error(MailboxReceiptError error, string message) =>
        new(error, message);

}
