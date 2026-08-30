using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxPeerReplicationCodec
{
    private const byte Version = 1;
    private static ReadOnlySpan<byte> RequestMagic => ProtocolMagicBytes.PRQ1;
    private static ReadOnlySpan<byte> ProofMagic => ProtocolMagicBytes.MIP1;

    public static byte[] Encode(MailboxPeerReplicationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request, requireSignature: true);
        var unsigned = EncodeUnsigned(request);
        request.Signature.Span.CopyTo(unsigned.AsSpan(unsigned.Length - 64));
        return unsigned;
    }

    public static MailboxPeerReplicationRequest Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length <
                MailboxPeerReplicationLimits.RequestFixedLength +
                (2 * MailboxPeerReplicationLimits.MembershipProofFixedLength) +
                64 ||
            encoded.Length > MailboxPeerReplicationLimits.MaximumRequestLength)
            throw Error(MailboxPeerReplicationError.InvalidLength, "PRQ1 length is outside strict bounds.");
        if (!encoded[..4].SequenceEqual(RequestMagic))
            throw Error(MailboxPeerReplicationError.InvalidMagic, "PRQ1 magic is invalid.");
        if (encoded[4] != Version)
            throw Error(MailboxPeerReplicationError.UnsupportedVersion, "PRQ1 version is unsupported.");
        if (encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(250, 6).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(MailboxPeerReplicationError.ReservedFieldNotZero, "PRQ1 reserved bytes must be zero.");
        var rawPayloadLength = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(240, 4));
        if (rawPayloadLength > MailboxClientLimits.MaximumEncryptedEnvelopeLength)
            throw Error(MailboxPeerReplicationError.InvalidLength, "PRQ1 payload length exceeds its bound.");
        var payloadLength = (int)rawPayloadLength;
        var sourceProofLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(244, 2));
        var targetProofLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(246, 2));
        var signatureLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(248, 2));
        if (sourceProofLength < MailboxPeerReplicationLimits.MembershipProofFixedLength ||
            targetProofLength < MailboxPeerReplicationLimits.MembershipProofFixedLength ||
            sourceProofLength >
                MailboxPeerReplicationLimits.MembershipProofFixedLength +
                MailboxPeerReplicationLimits.MaximumInclusionProofLength ||
            targetProofLength >
                MailboxPeerReplicationLimits.MembershipProofFixedLength +
                MailboxPeerReplicationLimits.MaximumInclusionProofLength ||
            signatureLength != 64 ||
            encoded.Length != MailboxPeerReplicationLimits.RequestFixedLength +
                              payloadLength + sourceProofLength + targetProofLength + signatureLength)
            throw Error(MailboxPeerReplicationError.InvalidLength, "PRQ1 nested lengths are invalid.");
        var payloadOffset = MailboxPeerReplicationLimits.RequestFixedLength;
        var sourceOffset = payloadOffset + payloadLength;
        var targetOffset = sourceOffset + sourceProofLength;
        var signatureOffset = targetOffset + targetProofLength;
        var request = new MailboxPeerReplicationRequest
        {
            Operation = (MailboxPeerReplicationOperation)encoded[5],
            Epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8)),
            OperationId = encoded.Slice(16, 16).ToArray(),
            SourceReplicaId = encoded.Slice(32, 32).ToArray(),
            TargetReplicaId = encoded.Slice(64, 32).ToArray(),
            MembershipCommitment = encoded.Slice(96, 32).ToArray(),
            PlacementCommitment = encoded.Slice(128, 32).ToArray(),
            BlindedMailboxId = encoded.Slice(160, 32).ToArray(),
            Cursor = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(192, 8)),
            ExpiresAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(200, 8)),
            PayloadDigest = encoded.Slice(208, 32).ToArray(),
            Payload = encoded.Slice(payloadOffset, payloadLength).ToArray(),
            SourceMembershipProof = DecodeMembershipProof(encoded.Slice(sourceOffset, sourceProofLength)),
            TargetMembershipProof = DecodeMembershipProof(encoded.Slice(targetOffset, targetProofLength)),
            Signature = encoded.Slice(signatureOffset, 64).ToArray()
        };
        ValidateRequest(request, requireSignature: true);
        return request;
    }

    public static byte[] GetSigningBytes(MailboxPeerReplicationRequest request)
    {
        ValidateRequest(request, requireSignature: false);
        var unsigned = EncodeUnsigned(request);
        return [.. OperationTag(request.Operation), .. unsigned.AsSpan(0, unsigned.Length - 64)];
    }

    public static VerifiedMailboxPeerReplicationRequest Verify(
        ReadOnlySpan<byte> encoded,
        MailboxPeerReplicationVerificationPolicy policy,
        IMailboxPeerReplicationCrypto crypto,
        IMailboxReplicaMembershipProofVerifier membershipVerifier)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(membershipVerifier);
        var request = Decode(encoded);
        if (request.Operation != policy.ExpectedOperation ||
            request.Epoch != policy.Epoch ||
            !FixedEquals(request.OperationId.Span, policy.OperationId.Span) ||
            !FixedEquals(request.SourceReplicaId.Span, policy.SourceReplicaId.Span) ||
            !FixedEquals(request.TargetReplicaId.Span, policy.TargetReplicaId.Span) ||
            !FixedEquals(request.MembershipCommitment.Span, policy.MembershipCommitment.Span) ||
            !FixedEquals(request.PlacementCommitment.Span, policy.PlacementCommitment.Span) ||
            !FixedEquals(
                request.PlacementCommitment.Span,
                MailboxPlacementCommitment.Compute(policy.PlacementId)) ||
            request.ExpiresAtUnixSeconds <= policy.NowUnixSeconds)
            throw Error(MailboxPeerReplicationError.BindingMismatch, "PRQ1 does not match exact peer authority context.");
        if (!membershipVerifier.VerifyStorageReplica(
                request.SourceMembershipProof,
                policy.NowUnixSeconds) ||
            !membershipVerifier.VerifyStorageReplica(
                request.TargetMembershipProof,
                policy.NowUnixSeconds))
            throw Error(MailboxPeerReplicationError.InvalidMembershipProof, "A PRQ1 replica membership proof is invalid.");
        if (!crypto.Verify(
                request.SourceMembershipProof.SigningPublicKey.Span,
                GetSigningBytes(request),
                request.Signature.Span))
            throw Error(MailboxPeerReplicationError.InvalidSignature, "PRQ1 source signature is invalid.");

        MailboxEncryptedEnvelope? envelope = null;
        if (request.Operation == MailboxPeerReplicationOperation.Store)
        {
            if (!FixedEquals(crypto.Digest(request.Payload.Span), request.PayloadDigest.Span))
                throw Error(MailboxPeerReplicationError.InvalidPayload, "PRQ1 Store payload digest is invalid.");
            envelope = DecodeCanonicalEnvelope(request.Payload.Span);
            if (envelope.Epoch != request.Epoch ||
                !FixedEquals(envelope.OperationId.Span, request.OperationId.Span) ||
                !FixedEquals(envelope.MailboxId.Bytes.Span, request.BlindedMailboxId.Span) ||
                !FixedEquals(
                    MailboxPlacementCommitment.Compute(envelope.PlacementId),
                    request.PlacementCommitment.Span) ||
                envelope.ExpiresAtUnixSeconds != request.ExpiresAtUnixSeconds)
                throw Error(MailboxPeerReplicationError.BindingMismatch, "PRQ1 Store and exact MEO1 payload disagree.");
        }
        return new VerifiedMailboxPeerReplicationRequest
        {
            Request = request,
            Envelope = envelope
        };
    }

    public static MailboxReplicaReceiptV2 CreateUnsignedReplicaResponse(
        VerifiedMailboxPeerReplicationRequest verifiedRequest,
        MailboxPeerResponseReplica replica,
        MailboxReceiptStatus status,
        MailboxReplicaDisposition disposition,
        ulong acceptedAtUnixSeconds,
        ulong durableAtUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(verifiedRequest);
        var request = verifiedRequest.Request;
        if (replica is not (MailboxPeerResponseReplica.Source or MailboxPeerResponseReplica.Target) ||
            status is not (MailboxReceiptStatus.Accepted or MailboxReceiptStatus.Durable) ||
            !IsAllowedDisposition(request, disposition) ||
            acceptedAtUnixSeconds == 0 ||
            acceptedAtUnixSeconds >= request.ExpiresAtUnixSeconds ||
            status == MailboxReceiptStatus.Accepted && durableAtUnixSeconds != 0 ||
            status == MailboxReceiptStatus.Durable &&
            (durableAtUnixSeconds < acceptedAtUnixSeconds ||
             durableAtUnixSeconds >= request.ExpiresAtUnixSeconds))
            throw Error(MailboxPeerReplicationError.InvalidReceipt, "Peer receipt timestamps/status are invalid.");
        return new MailboxReplicaReceiptV2
        {
            Status = status,
            Disposition = disposition,
            ReplicaId = (replica == MailboxPeerResponseReplica.Source
                ? request.SourceReplicaId
                : request.TargetReplicaId).ToArray(),
            OperationId = request.OperationId.ToArray(),
            Epoch = request.Epoch,
            Cursor = request.Cursor,
            AcceptedAtUnixSeconds = acceptedAtUnixSeconds,
            DurableAtUnixSeconds = durableAtUnixSeconds,
            ExpiresAtUnixSeconds = request.ExpiresAtUnixSeconds,
            BlindedMailboxId = request.BlindedMailboxId.ToArray(),
            PlacementCommitment = request.PlacementCommitment.ToArray(),
            MembershipCommitment = request.MembershipCommitment.ToArray(),
            EnvelopeDigest = ExpectedEnvelopeDigest(verifiedRequest),
            Signature = ReadOnlyMemory<byte>.Empty
        };
    }

    public static MailboxReplicaReceiptV2 VerifyReplicaResponse(
        ReadOnlySpan<byte> encoded,
        VerifiedMailboxPeerReplicationRequest verifiedRequest,
        IMailboxPeerReplicationCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(verifiedRequest);
        ArgumentNullException.ThrowIfNull(crypto);
        var receipt = MailboxReceiptV2Codec.DecodeReplica(encoded);
        if (!MatchesRequest(receipt, verifiedRequest, allowSource: false) ||
            !crypto.Verify(
                verifiedRequest.Request.TargetMembershipProof.SigningPublicKey.Span,
                MailboxReceiptV2Codec.GetReplicaSigningBytes(receipt),
                receipt.Signature.Span))
            throw Error(MailboxPeerReplicationError.InvalidReceipt, "MRR2 is not the exact target response to PRQ1.");
        return receipt;
    }

    public static VerifiedMailboxDurableQuorumV2 VerifyDurableQuorumResponse(
        ReadOnlySpan<byte> encoded,
        VerifiedMailboxPeerReplicationRequest verifiedRequest,
        IMailboxPeerReplicationCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(verifiedRequest);
        ArgumentNullException.ThrowIfNull(crypto);
        var quorum = MailboxReceiptV2Codec.DecodeDurableQuorum(encoded);
        var request = verifiedRequest.Request;
        var replicas = new[] { quorum.FirstReplica, quorum.SecondReplica };
        if (replicas.Any(receipt =>
                receipt.Status != MailboxReceiptStatus.Durable ||
                !MatchesRequest(receipt, verifiedRequest, allowSource: true)) ||
            replicas[0].Disposition != replicas[1].Disposition ||
            !ContainsExactly(
                replicas.Select(static receipt => receipt.ReplicaId).ToArray(),
                request.SourceReplicaId,
                request.TargetReplicaId))
            throw Error(MailboxPeerReplicationError.InvalidReceipt, "MQR2 is not the exact selected replica set.");
        foreach (var receipt in replicas)
        {
            var key = FixedEquals(receipt.ReplicaId.Span, request.SourceReplicaId.Span)
                ? request.SourceMembershipProof.SigningPublicKey
                : request.TargetMembershipProof.SigningPublicKey;
            if (!crypto.Verify(
                    key.Span,
                    MailboxReceiptV2Codec.GetReplicaSigningBytes(receipt),
                    receipt.Signature.Span))
                throw Error(MailboxPeerReplicationError.InvalidReceipt, "MQR2 has an invalid selected-replica signature.");
        }
        ReadOnlyMemory<byte> coordinatorKey;
        if (FixedEquals(quorum.CoordinatorId.Span, request.SourceReplicaId.Span))
            coordinatorKey = request.SourceMembershipProof.SigningPublicKey;
        else if (FixedEquals(quorum.CoordinatorId.Span, request.TargetReplicaId.Span))
            coordinatorKey = request.TargetMembershipProof.SigningPublicKey;
        else
            throw Error(MailboxPeerReplicationError.InvalidReceipt, "MQR2 coordinator is not selected by PRQ1.");
        if (!crypto.Verify(
                coordinatorKey.Span,
                MailboxReceiptV2Codec.GetQuorumSigningBytes(
                    quorum,
                    new PeerReceiptDigestAdapter(crypto)),
                quorum.Signature.Span))
            throw Error(MailboxPeerReplicationError.InvalidReceipt, "MQR2 coordinator signature is invalid.");
        return new VerifiedMailboxDurableQuorumV2(
            request.Cursor,
            replicas[0].Disposition,
            replicas,
            quorum);
    }

    public static byte[] EncodeMembershipProof(MailboxReplicaMembershipProof proof)
    {
        ValidateProof(proof);
        var output = new byte[
            MailboxPeerReplicationLimits.MembershipProofFixedLength +
            proof.CanonicalInclusionProof.Length];
        ProofMagic.CopyTo(output);
        output[4] = Version;
        proof.ReplicaId.Span.CopyTo(output.AsSpan(8));
        proof.SigningPublicKey.Span.CopyTo(output.AsSpan(40));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(72), proof.Epoch);
        proof.MembershipCommitment.Span.CopyTo(output.AsSpan(80));
        BinaryPrimitives.WriteUInt16BigEndian(
            output.AsSpan(112),
            checked((ushort)proof.CanonicalInclusionProof.Length));
        proof.CanonicalInclusionProof.Span.CopyTo(
            output.AsSpan(MailboxPeerReplicationLimits.MembershipProofFixedLength));
        return output;
    }

    public static MailboxReplicaMembershipProof DecodeMembershipProof(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < MailboxPeerReplicationLimits.MembershipProofFixedLength ||
            encoded.Length >
                MailboxPeerReplicationLimits.MembershipProofFixedLength +
                MailboxPeerReplicationLimits.MaximumInclusionProofLength)
            throw Error(MailboxPeerReplicationError.InvalidLength, "MIP1 length is outside strict bounds.");
        if (!encoded[..4].SequenceEqual(ProofMagic))
            throw Error(MailboxPeerReplicationError.InvalidMagic, "MIP1 magic is invalid.");
        if (encoded[4] != Version)
            throw Error(MailboxPeerReplicationError.UnsupportedVersion, "MIP1 version is unsupported.");
        if (encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(114, 6).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(MailboxPeerReplicationError.ReservedFieldNotZero, "MIP1 reserved bytes must be zero.");
        var proofLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(112, 2));
        if (proofLength == 0 ||
            proofLength > MailboxPeerReplicationLimits.MaximumInclusionProofLength ||
            encoded.Length != MailboxPeerReplicationLimits.MembershipProofFixedLength + proofLength)
            throw Error(MailboxPeerReplicationError.InvalidLength, "MIP1 proof length is invalid.");
        var proof = new MailboxReplicaMembershipProof
        {
            ReplicaId = encoded.Slice(8, 32).ToArray(),
            SigningPublicKey = encoded.Slice(40, 32).ToArray(),
            Epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(72, 8)),
            MembershipCommitment = encoded.Slice(80, 32).ToArray(),
            CanonicalInclusionProof =
                encoded[MailboxPeerReplicationLimits.MembershipProofFixedLength..].ToArray()
        };
        ValidateProof(proof);
        return proof;
    }

    private static byte[] EncodeUnsigned(MailboxPeerReplicationRequest request)
    {
        var source = EncodeMembershipProof(request.SourceMembershipProof);
        var target = EncodeMembershipProof(request.TargetMembershipProof);
        var output = new byte[
            MailboxPeerReplicationLimits.RequestFixedLength +
            request.Payload.Length + source.Length + target.Length + 64];
        RequestMagic.CopyTo(output);
        output[4] = Version;
        output[5] = (byte)request.Operation;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), request.Epoch);
        request.OperationId.Span.CopyTo(output.AsSpan(16));
        request.SourceReplicaId.Span.CopyTo(output.AsSpan(32));
        request.TargetReplicaId.Span.CopyTo(output.AsSpan(64));
        request.MembershipCommitment.Span.CopyTo(output.AsSpan(96));
        request.PlacementCommitment.Span.CopyTo(output.AsSpan(128));
        request.BlindedMailboxId.Span.CopyTo(output.AsSpan(160));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(192), request.Cursor);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(200), request.ExpiresAtUnixSeconds);
        request.PayloadDigest.Span.CopyTo(output.AsSpan(208));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(240), checked((uint)request.Payload.Length));
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(244), checked((ushort)source.Length));
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(246), checked((ushort)target.Length));
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(248), 64);
        var offset = MailboxPeerReplicationLimits.RequestFixedLength;
        request.Payload.Span.CopyTo(output.AsSpan(offset));
        offset += request.Payload.Length;
        source.CopyTo(output, offset);
        offset += source.Length;
        target.CopyTo(output, offset);
        return output;
    }

    private static void ValidateRequest(MailboxPeerReplicationRequest request, bool requireSignature)
    {
        if (request.Operation is not (
                MailboxPeerReplicationOperation.Store or
                MailboxPeerReplicationOperation.Tombstone))
            throw Error(MailboxPeerReplicationError.InvalidEnum, "PRQ1 operation is invalid.");
        ValidateNonzero(request.OperationId.Span, 16);
        ValidateNonzero(request.SourceReplicaId.Span, 32);
        ValidateNonzero(request.TargetReplicaId.Span, 32);
        ValidateNonzero(request.MembershipCommitment.Span, 32);
        ValidateNonzero(request.PlacementCommitment.Span, 32);
        ValidateNonzero(request.BlindedMailboxId.Span, 32);
        ValidateNonzero(request.PayloadDigest.Span, 32);
        if (FixedEquals(request.SourceReplicaId.Span, request.TargetReplicaId.Span) ||
            request.Epoch == 0 || request.Cursor == 0 || request.ExpiresAtUnixSeconds == 0)
            throw Error(MailboxPeerReplicationError.InvalidField, "PRQ1 identity/cursor/epoch fields are invalid.");
        ValidateProof(request.SourceMembershipProof);
        ValidateProof(request.TargetMembershipProof);
        if (!FixedEquals(request.SourceReplicaId.Span, request.SourceMembershipProof.ReplicaId.Span) ||
            !FixedEquals(request.TargetReplicaId.Span, request.TargetMembershipProof.ReplicaId.Span) ||
            request.SourceMembershipProof.Epoch != request.Epoch ||
            request.TargetMembershipProof.Epoch != request.Epoch ||
            !FixedEquals(request.MembershipCommitment.Span, request.SourceMembershipProof.MembershipCommitment.Span) ||
            !FixedEquals(request.MembershipCommitment.Span, request.TargetMembershipProof.MembershipCommitment.Span))
            throw Error(MailboxPeerReplicationError.BindingMismatch, "PRQ1 proofs do not match request replicas.");
        if (request.Operation == MailboxPeerReplicationOperation.Store)
        {
            if (request.Payload.Length is
                    < MailboxClientLimits.EncryptedEnvelopeHeaderLength +
                      MailboxClientLimits.MinimumCiphertextLength or
                    > MailboxClientLimits.MaximumEncryptedEnvelopeLength ||
                !request.Payload.Span[..4].SequenceEqual(ProtocolMagicBytes.MEO1))
                throw Error(MailboxPeerReplicationError.InvalidPayload, "PRQ1 Store requires exact canonical MEO1 bytes.");
        }
        else if (request.Payload.Length != 32 ||
                 !FixedEquals(request.Payload.Span, request.PayloadDigest.Span))
            throw Error(MailboxPeerReplicationError.InvalidPayload, "PRQ1 Tombstone requires exactly one envelope digest.");
        if (requireSignature)
            ValidateNonzero(request.Signature.Span, 64);
        else if (!request.Signature.IsEmpty && request.Signature.Length != 64)
            throw Error(MailboxPeerReplicationError.InvalidField, "PRQ1 signature length is invalid.");
    }

    private static void ValidateProof(MailboxReplicaMembershipProof proof)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ValidateNonzero(proof.ReplicaId.Span, 32);
        ValidateNonzero(proof.SigningPublicKey.Span, 32);
        ValidateNonzero(proof.MembershipCommitment.Span, 32);
        if (proof.Epoch == 0 ||
            proof.CanonicalInclusionProof.Length is 0 or > MailboxPeerReplicationLimits.MaximumInclusionProofLength)
            throw Error(MailboxPeerReplicationError.InvalidMembershipProof, "MIP1 fields are invalid.");
    }

    private static MailboxEncryptedEnvelope DecodeCanonicalEnvelope(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < MailboxClientLimits.EncryptedEnvelopeHeaderLength ||
            !encoded[..4].SequenceEqual(ProtocolMagicBytes.MEO1) ||
            encoded[4] != 1 ||
            encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(148, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(MailboxPeerReplicationError.InvalidPayload, "Nested MEO1 header is invalid.");
        var ciphertextLength = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(144, 4));
        if (ciphertextLength is
                < MailboxClientLimits.MinimumCiphertextLength or
                > MailboxClientLimits.MaximumCiphertextLength ||
            encoded.Length != MailboxClientLimits.EncryptedEnvelopeHeaderLength + ciphertextLength)
            throw Error(MailboxPeerReplicationError.InvalidPayload, "Nested MEO1 length is invalid.");
        var envelope = new MailboxEncryptedEnvelope
        {
            Epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8)),
            MailboxId = new BlindedMailboxId(encoded.Slice(16, 32)),
            PlacementId = new BlindedPlacementId(encoded.Slice(48, 32)),
            OperationId = encoded.Slice(80, 16).ToArray(),
            DeduplicationDigest = encoded.Slice(96, 32).ToArray(),
            CreatedAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(128, 8)),
            ExpiresAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(136, 8)),
            Ciphertext = encoded[152..].ToArray()
        };
        if (!encoded.SequenceEqual(MailboxClientCodec.EncodeEncryptedEnvelope(envelope)))
            throw Error(MailboxPeerReplicationError.InvalidPayload, "Nested MEO1 is not canonical.");
        return envelope;
    }

    private static bool MatchesRequest(
        MailboxReplicaReceiptV2 receipt,
        VerifiedMailboxPeerReplicationRequest verifiedRequest,
        bool allowSource)
    {
        var request = verifiedRequest.Request;
        var selectedReplica =
            FixedEquals(receipt.ReplicaId.Span, request.TargetReplicaId.Span) ||
            allowSource && FixedEquals(receipt.ReplicaId.Span, request.SourceReplicaId.Span);
        return selectedReplica &&
               receipt.Status is (MailboxReceiptStatus.Accepted or MailboxReceiptStatus.Durable) &&
               IsAllowedDisposition(request, receipt.Disposition) &&
               receipt.OperationId.Span.SequenceEqual(request.OperationId.Span) &&
               receipt.Epoch == request.Epoch &&
               receipt.Cursor == request.Cursor &&
               receipt.ExpiresAtUnixSeconds == request.ExpiresAtUnixSeconds &&
               receipt.BlindedMailboxId.Span.SequenceEqual(request.BlindedMailboxId.Span) &&
               receipt.PlacementCommitment.Span.SequenceEqual(request.PlacementCommitment.Span) &&
               receipt.MembershipCommitment.Span.SequenceEqual(request.MembershipCommitment.Span) &&
               receipt.EnvelopeDigest.Span.SequenceEqual(ExpectedEnvelopeDigest(verifiedRequest).Span);
    }

    private static bool IsAllowedDisposition(
        MailboxPeerReplicationRequest request,
        MailboxReplicaDisposition disposition) =>
        request.Operation == MailboxPeerReplicationOperation.Store
            ? disposition is (
                MailboxReplicaDisposition.Stored or
                MailboxReplicaDisposition.Duplicate)
            : disposition == MailboxReplicaDisposition.Tombstone;

    private static ReadOnlyMemory<byte> ExpectedEnvelopeDigest(
        VerifiedMailboxPeerReplicationRequest verifiedRequest) =>
        verifiedRequest.Request.Operation == MailboxPeerReplicationOperation.Store
            ? verifiedRequest.Envelope?.DeduplicationDigest.ToArray() ??
              throw Error(MailboxPeerReplicationError.InvalidPayload, "Verified Store has no MEO1.")
            : verifiedRequest.Request.Payload.ToArray();

    private static bool ContainsExactly(
        IReadOnlyList<ReadOnlyMemory<byte>> actual,
        ReadOnlyMemory<byte> first,
        ReadOnlyMemory<byte> second) =>
        actual.Count == 2 &&
        !FixedEquals(actual[0].Span, actual[1].Span) &&
        actual.Any(value => FixedEquals(value.Span, first.Span)) &&
        actual.Any(value => FixedEquals(value.Span, second.Span));

    private static ReadOnlySpan<byte> OperationTag(MailboxPeerReplicationOperation operation) =>
        operation switch
        {
            MailboxPeerReplicationOperation.Store => "DEEP-PRQ1-STR\0\0\0"u8,
            MailboxPeerReplicationOperation.Tombstone => "DEEP-PRQ1-TMB\0\0\0"u8,
            _ => throw Error(MailboxPeerReplicationError.InvalidEnum, "PRQ1 operation has no signing tag.")
        };

    private static void ValidateNonzero(ReadOnlySpan<byte> value, int length)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw Error(MailboxPeerReplicationError.InvalidField, "A PRQ1 fixed field is invalid.");
    }

    private static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static MailboxPeerReplicationException Error(
        MailboxPeerReplicationError error,
        string message) => new(error, message);

    private sealed class PeerReceiptDigestAdapter(IMailboxPeerReplicationCrypto crypto)
        : IMailboxReceiptCrypto
    {
        public byte[] Digest(ReadOnlySpan<byte> statement) => crypto.Digest(statement);

        public bool VerifyReplica(
            ReadOnlySpan<byte> replicaId,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) => false;

        public bool VerifyCoordinator(
            ReadOnlySpan<byte> coordinatorId,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) => false;
    }
}
