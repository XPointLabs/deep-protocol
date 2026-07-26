using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxPeerWireV2Codec
{
    private const byte Version = 2;
    private static ReadOnlySpan<byte> Magic => "PRQ2"u8;

    public static byte[] Encode(MailboxPeerWireRequestV2 request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request, requireSignature: true);
        var encoded = EncodeUnsigned(request);
        request.Signature.Span.CopyTo(encoded.AsSpan(encoded.Length - 64));
        return encoded;
    }

    public static MailboxPeerWireRequestV2 Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length <
                MailboxPeerWireV2Limits.MinimumTombstoneRequestLength ||
            encoded.Length > MailboxPeerWireV2Limits.MaximumRequestLength)
            throw Error(
                MailboxPeerReplicationError.InvalidLength,
                "PRQ2 length is outside strict bounds.");
        if (!encoded[..4].SequenceEqual(Magic))
            throw Error(
                MailboxPeerReplicationError.InvalidMagic,
                "PRQ2 magic is invalid.");
        if (encoded[4] != Version)
            throw Error(
                MailboxPeerReplicationError.UnsupportedVersion,
                "PRQ2 version is unsupported.");
        if (encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(290, 6).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(
                MailboxPeerReplicationError.ReservedFieldNotZero,
                "PRQ2 reserved bytes must be zero.");

        var rawPayloadLength = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(280, 4));
        if (rawPayloadLength > MailboxClientLimits.MaximumEncryptedEnvelopeLength)
            throw Error(
                MailboxPeerReplicationError.InvalidLength,
                "PRQ2 payload length exceeds its bound.");
        var payloadLength = checked((int)rawPayloadLength);
        var senderProofLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(284, 2));
        var recipientProofLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(286, 2));
        var signatureLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(288, 2));
        if (senderProofLength is
                < MailboxPeerWireV2Limits.MinimumMembershipProofLength or
                > MailboxPeerWireV2Limits.MaximumMembershipProofLength ||
            recipientProofLength is
                < MailboxPeerWireV2Limits.MinimumMembershipProofLength or
                > MailboxPeerWireV2Limits.MaximumMembershipProofLength ||
            signatureLength != MailboxPeerReplicationLimits.SignatureLength ||
            encoded.Length !=
                MailboxPeerWireV2Limits.RequestHeaderLength +
                payloadLength +
                senderProofLength +
                recipientProofLength +
                signatureLength)
            throw Error(
                MailboxPeerReplicationError.InvalidLength,
                "PRQ2 nested lengths are invalid.");

        var payloadOffset = MailboxPeerWireV2Limits.RequestHeaderLength;
        var senderProofOffset = payloadOffset + payloadLength;
        var recipientProofOffset = senderProofOffset + senderProofLength;
        var signatureOffset = recipientProofOffset + recipientProofLength;
        var request = new MailboxPeerWireRequestV2
        {
            Operation = (MailboxPeerReplicationOperation)encoded[5],
            Epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8)),
            OperationId = encoded.Slice(16, 16).ToArray(),
            SenderRouterId = encoded.Slice(32, 32).ToArray(),
            RecipientRouterId = encoded.Slice(64, 32).ToArray(),
            MembershipCommitment = encoded.Slice(96, 32).ToArray(),
            PlacementCommitment = encoded.Slice(128, 32).ToArray(),
            BlindedMailboxId = encoded.Slice(160, 32).ToArray(),
            Cursor = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(192, 8)),
            CreatedAtUnixSeconds =
                BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(200, 8)),
            ExpiresAtUnixSeconds =
                BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(208, 8)),
            ReplayNonce = encoded.Slice(216, 32).ToArray(),
            PayloadDigest = encoded.Slice(248, 32).ToArray(),
            Payload = encoded.Slice(payloadOffset, payloadLength).ToArray(),
            SenderMembershipProof = MailboxPeerReplicationCodec.DecodeMembershipProof(
                encoded.Slice(senderProofOffset, senderProofLength)),
            RecipientMembershipProof = MailboxPeerReplicationCodec.DecodeMembershipProof(
                encoded.Slice(recipientProofOffset, recipientProofLength)),
            Signature = encoded.Slice(signatureOffset, signatureLength).ToArray()
        };
        ValidateRequest(request, requireSignature: true);
        return request;
    }

    /// <summary>
    /// Returns the SHA-256 digest signed directly by Ed25519. The digest preimage is
    /// U16BE(domain length) || ASCII domain || U32BE(unsigned PRQ2 length) || unsigned PRQ2.
    /// </summary>
    public static byte[] GetSigningDigest(MailboxPeerWireRequestV2 request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request, requireSignature: false);
        var encoded = EncodeUnsigned(request);
        return DomainSeparatedHash(
            SigningDomain(request.Operation),
            encoded.AsSpan(0, encoded.Length - 64));
    }

    public static VerifiedMailboxPeerWireRequestV2 VerifyAndReserve(
        ReadOnlySpan<byte> encoded,
        MailboxPeerWireVerificationPolicyV2 policy,
        IMailboxPeerReplicationCrypto crypto,
        IMailboxReplicaMembershipProofVerifier membershipVerifier,
        IMailboxPeerReplayJournal replayJournal)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(membershipVerifier);
        ArgumentNullException.ThrowIfNull(replayJournal);
        var (request, envelope, claim) = VerifyRequest(
            encoded,
            policy,
            crypto,
            membershipVerifier);
        var evaluation = replayJournal.EvaluateAndReserve(claim);
        var disposition = evaluation.State switch
        {
            MailboxPeerReplayState.NewReserved =>
                MailboxPeerReplayDisposition.NewReserved,
            MailboxPeerReplayState.PendingSame =>
                MailboxPeerReplayDisposition.InFlight,
            MailboxPeerReplayState.CompletedSame =>
                MailboxPeerReplayDisposition.IdempotentCompleted,
            MailboxPeerReplayState.Conflict =>
                throw Error(
                    MailboxPeerReplicationError.ReplayConflict,
                    "PRQ2 replay nonce was reused for different canonical bytes."),
            _ => throw Error(
                MailboxPeerReplicationError.ReplayConflict,
                "PRQ2 replay journal returned an invalid state.")
        };
        var verified = new VerifiedMailboxPeerWireRequestV2
        {
            Request = request,
            Envelope = envelope,
            ReplayClaim = claim,
            ReplayDisposition = disposition,
            CachedResponse = evaluation.CachedResponse.ToArray()
        };
        if (disposition == MailboxPeerReplayDisposition.IdempotentCompleted)
            _ = VerifyReplicaResponse(evaluation.CachedResponse.Span, verified, crypto);
        else if (!evaluation.CachedResponse.IsEmpty)
            throw Error(
                MailboxPeerReplicationError.ReplayConflict,
                "Only an exact completed retry may return a cached PRQ2 response.");
        return verified;
    }

    /// <summary>
    /// Creates the recipient's unsigned durable MRR2. The caller must invoke this method only
    /// after the exact Store or Tombstone mutation has been durably persisted.
    /// </summary>
    public static MailboxReplicaReceiptV2 CreateUnsignedDurableResponseAfterPersistence(
        VerifiedMailboxPeerWireRequestV2 verifiedRequest,
        MailboxReplicaDisposition disposition,
        ulong acceptedAtUnixSeconds,
        ulong durableAtUnixSeconds) =>
        CreateUnsignedDurableReplicaResponseAfterPersistence(
            verifiedRequest,
            MailboxPeerWireResponseReplicaV2.Recipient,
            disposition,
            acceptedAtUnixSeconds,
            durableAtUnixSeconds);

    public static MailboxReplicaReceiptV2 CreateUnsignedDurableReplicaResponseAfterPersistence(
        VerifiedMailboxPeerWireRequestV2 verifiedRequest,
        MailboxPeerWireResponseReplicaV2 replica,
        MailboxReplicaDisposition disposition,
        ulong acceptedAtUnixSeconds,
        ulong durableAtUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(verifiedRequest);
        var request = verifiedRequest.Request;
        if (replica is not (
                MailboxPeerWireResponseReplicaV2.Sender or
                MailboxPeerWireResponseReplicaV2.Recipient) ||
            !AllowedDisposition(request.Operation, disposition) ||
            acceptedAtUnixSeconds < request.CreatedAtUnixSeconds ||
            durableAtUnixSeconds < acceptedAtUnixSeconds ||
            durableAtUnixSeconds >= request.ExpiresAtUnixSeconds)
            throw Error(
                MailboxPeerReplicationError.InvalidReceipt,
                "PRQ2 durable response status, disposition or timestamps are invalid.");
        return new MailboxReplicaReceiptV2
        {
            Status = MailboxReceiptStatus.Durable,
            Disposition = disposition,
            ReplicaId = (replica == MailboxPeerWireResponseReplicaV2.Sender
                ? request.SenderRouterId
                : request.RecipientRouterId).ToArray(),
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
        VerifiedMailboxPeerWireRequestV2 verifiedRequest,
        IMailboxPeerReplicationCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(verifiedRequest);
        ArgumentNullException.ThrowIfNull(crypto);
        if (encoded.Length != MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength)
            throw Error(
                MailboxPeerReplicationError.InvalidReceipt,
                "PRQ2 response must be exactly one Ed25519 MRR2.");
        var receipt = MailboxReceiptV2Codec.DecodeReplica(encoded);
        var request = verifiedRequest.Request;
        if (!MatchesRequest(
                receipt,
                verifiedRequest,
                allowSender: false) ||
            !crypto.Verify(
                request.RecipientMembershipProof.SigningPublicKey.Span,
                MailboxReceiptV2Codec.GetReplicaSigningBytes(receipt),
                receipt.Signature.Span))
            throw Error(
                MailboxPeerReplicationError.InvalidReceipt,
                "MRR2 is not the exact durable recipient response to PRQ2.");
        return receipt;
    }

    public static MailboxDurableQuorumReceiptV3 CreateUnsignedDurableQuorumResponse(
        VerifiedMailboxPeerWireRequestV2 verifiedRequest,
        ReadOnlySpan<byte> firstMrr2,
        ReadOnlySpan<byte> secondMrr2,
        ReadOnlyMemory<byte> coordinatorRouterId,
        IMailboxPeerReplicationCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(verifiedRequest);
        ArgumentNullException.ThrowIfNull(crypto);
        var firstDecoded = DecodeAndVerifySelectedReplica(
            firstMrr2,
            verifiedRequest,
            crypto);
        var secondDecoded = DecodeAndVerifySelectedReplica(
            secondMrr2,
            verifiedRequest,
            crypto);
        var (first, second) =
            firstDecoded.ReplicaId.Span.SequenceCompareTo(
                secondDecoded.ReplicaId.Span) <= 0
                ? (firstDecoded, secondDecoded)
                : (secondDecoded, firstDecoded);
        ValidateReplicaPair(first, second, verifiedRequest);
        if (!IsSelectedRouter(coordinatorRouterId.Span, verifiedRequest.Request))
            throw Error(
                MailboxPeerReplicationError.InvalidReceipt,
                "MQR3 coordinator is not a selected PRQ2 router.");
        return new MailboxDurableQuorumReceiptV3
        {
            CoordinatorId = coordinatorRouterId.ToArray(),
            CoordinatorSequence = Prq2CoordinatorSequence(verifiedRequest),
            FirstReplica = first,
            SecondReplica = second,
            Signature = ReadOnlyMemory<byte>.Empty
        };
    }

    public static VerifiedMailboxDurableQuorumV3 VerifyDurableQuorumResponse(
        ReadOnlySpan<byte> encoded,
        VerifiedMailboxPeerWireRequestV2 verifiedRequest,
        IMailboxPeerReplicationCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(verifiedRequest);
        ArgumentNullException.ThrowIfNull(crypto);
        var expectedLength =
            MailboxReceiptV3Limits.QuorumFixedHeaderLength +
            (2 * MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength) +
            MailboxPeerReplicationLimits.SignatureLength;
        if (encoded.Length != expectedLength)
            throw Error(
                MailboxPeerReplicationError.InvalidReceipt,
                "PRQ2 durable quorum must be one exact Ed25519 MQR3.");
        var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(encoded);
        var first = quorum.FirstReplica;
        var second = quorum.SecondReplica;
        ValidateReplicaPair(first, second, verifiedRequest);
        _ = DecodeAndVerifySelectedReplica(
            MailboxReceiptV2Codec.EncodeReplica(first),
            verifiedRequest,
            crypto);
        _ = DecodeAndVerifySelectedReplica(
            MailboxReceiptV2Codec.EncodeReplica(second),
            verifiedRequest,
            crypto);
        var request = verifiedRequest.Request;
        if (quorum.CoordinatorSequence !=
                Prq2CoordinatorSequence(verifiedRequest) ||
            !IsSelectedRouter(quorum.CoordinatorId.Span, request))
            throw Error(
                MailboxPeerReplicationError.InvalidReceipt,
                "MQR3 coordinator context does not match PRQ2.");
        var coordinatorKey = FixedEquals(
                quorum.CoordinatorId.Span,
                request.SenderRouterId.Span)
            ? request.SenderMembershipProof.SigningPublicKey
            : request.RecipientMembershipProof.SigningPublicKey;
        if (!crypto.Verify(
                coordinatorKey.Span,
                MailboxReceiptV3Codec.GetQuorumSigningBytes(quorum),
                quorum.Signature.Span))
            throw Error(
                MailboxPeerReplicationError.InvalidReceipt,
                "MQR3 coordinator signature is invalid.");
        return new VerifiedMailboxDurableQuorumV3(
            request.Cursor,
            first.Disposition,
            [first, second],
            quorum);
    }

    public static void CompleteAtomically(
        VerifiedMailboxPeerWireRequestV2 verifiedRequest,
        ReadOnlyMemory<byte> canonicalMrr2Response,
        IMailboxPeerReplicationCrypto crypto,
        IMailboxPeerReplayJournal replayJournal)
    {
        ArgumentNullException.ThrowIfNull(verifiedRequest);
        ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(replayJournal);
        if (verifiedRequest.ReplayDisposition !=
            MailboxPeerReplayDisposition.NewReserved)
            throw Error(
                MailboxPeerReplicationError.ReplayConflict,
                "Only a newly reserved PRQ2 request can be completed.");
        _ = VerifyReplicaResponse(
            canonicalMrr2Response.Span,
            verifiedRequest,
            crypto);
        replayJournal.CompleteAtomically(
            verifiedRequest.ReplayClaim,
            canonicalMrr2Response);
    }

    private static (
        MailboxPeerWireRequestV2 Request,
        MailboxEncryptedEnvelope? Envelope,
        MailboxPeerReplayClaim Claim) VerifyRequest(
        ReadOnlySpan<byte> encoded,
        MailboxPeerWireVerificationPolicyV2 policy,
        IMailboxPeerReplicationCrypto crypto,
        IMailboxReplicaMembershipProofVerifier membershipVerifier)
    {
        var request = Decode(encoded);
        if (request.Operation != policy.ExpectedOperation ||
            request.Epoch != policy.Epoch ||
            !FixedEquals(request.OperationId.Span, policy.OperationId.Span) ||
            !FixedEquals(request.SenderRouterId.Span, policy.SenderRouterId.Span) ||
            !FixedEquals(
                request.RecipientRouterId.Span,
                policy.RecipientRouterId.Span) ||
            !FixedEquals(
                request.MembershipCommitment.Span,
                policy.MembershipCommitment.Span) ||
            !FixedEquals(
                request.PlacementCommitment.Span,
                policy.PlacementCommitment.Span) ||
            !FixedEquals(
                request.PlacementCommitment.Span,
                MailboxPlacementCommitment.Compute(policy.PlacementId)))
            throw Error(
                MailboxPeerReplicationError.BindingMismatch,
                "PRQ2 does not match exact peer routing authority.");
        if (request.CreatedAtUnixSeconds >= request.ExpiresAtUnixSeconds ||
            request.ExpiresAtUnixSeconds <= policy.NowUnixSeconds ||
            policy.EpochExpiresAtUnixSeconds <= policy.NowUnixSeconds ||
            request.ExpiresAtUnixSeconds > policy.EpochExpiresAtUnixSeconds ||
            policy.EpochExpiresAtUnixSeconds >
                ulong.MaxValue - MailboxPeerWireV2Limits.ReplayRetentionSeconds ||
            policy.EpochExpiresAtUnixSeconds - request.CreatedAtUnixSeconds >
                MailboxPeerWireV2Limits.MaximumEpochLifetimeSeconds ||
            request.Operation == MailboxPeerReplicationOperation.Tombstone &&
            request.ExpiresAtUnixSeconds - request.CreatedAtUnixSeconds >
                MailboxPeerWireV2Limits.MaximumTombstoneLifetimeSeconds ||
            request.CreatedAtUnixSeconds > policy.NowUnixSeconds ||
            policy.NowUnixSeconds > request.CreatedAtUnixSeconds &&
            policy.NowUnixSeconds - request.CreatedAtUnixSeconds >
                MailboxPeerWireV2Limits.MaximumPastAgeSeconds)
            throw Error(
                MailboxPeerReplicationError.ExpiredOrStale,
                "PRQ2 is expired or outside its fixed freshness window.");
        if (!crypto.Verify(
                request.SenderMembershipProof.SigningPublicKey.Span,
                GetSigningDigest(request),
                request.Signature.Span))
            throw Error(
                MailboxPeerReplicationError.InvalidSignature,
                "PRQ2 sender Ed25519 signature is invalid.");
        if (!membershipVerifier.VerifyStorageReplica(
                request.SenderMembershipProof,
                policy.NowUnixSeconds) ||
            !membershipVerifier.VerifyStorageReplica(
                request.RecipientMembershipProof,
                policy.NowUnixSeconds))
            throw Error(
                MailboxPeerReplicationError.InvalidMembershipProof,
                "A PRQ2 router membership proof is invalid.");
        if (!FixedEquals(
                SHA256.HashData(request.Payload.Span),
                request.PayloadDigest.Span))
            throw Error(
                MailboxPeerReplicationError.InvalidPayload,
                "PRQ2 SHA-256 payload digest is invalid.");

        MailboxEncryptedEnvelope? envelope = null;
        if (request.Operation == MailboxPeerReplicationOperation.Store)
        {
            envelope = DecodeCanonicalEnvelope(request.Payload.Span);
            if (envelope.Epoch != request.Epoch ||
                !FixedEquals(envelope.OperationId.Span, request.OperationId.Span) ||
                !FixedEquals(
                    envelope.MailboxId.Bytes.Span,
                    request.BlindedMailboxId.Span) ||
                !FixedEquals(
                    MailboxPlacementCommitment.Compute(envelope.PlacementId),
                    request.PlacementCommitment.Span) ||
                envelope.CreatedAtUnixSeconds > request.CreatedAtUnixSeconds ||
                envelope.ExpiresAtUnixSeconds != request.ExpiresAtUnixSeconds)
                throw Error(
                    MailboxPeerReplicationError.BindingMismatch,
                    "PRQ2 Store and exact canonical MEO1 disagree.");
        }

        var requestDigest = DomainSeparatedHash(
            "deep.mailbox.peer.request-identity.v2"u8,
            encoded);
        var scopeKey = MailboxPeerReplayStateMachine.ComputeScopeKey(
            request.SenderRouterId.Span,
            request.RecipientRouterId.Span,
            request.Epoch,
            request.ReplayNonce.Span);
        var retainUntil = checked(
            policy.EpochExpiresAtUnixSeconds +
            MailboxPeerWireV2Limits.ReplayRetentionSeconds);
        return (
            request,
            envelope,
            new MailboxPeerReplayClaim
            {
                ScopeKey = scopeKey,
                RequestDigest = requestDigest,
                SenderRouterId = request.SenderRouterId.ToArray(),
                RecipientRouterId = request.RecipientRouterId.ToArray(),
                ReplayNonce = request.ReplayNonce.ToArray(),
                OperationId = request.OperationId.ToArray(),
                Operation = request.Operation,
                Epoch = request.Epoch,
                CreatedAtUnixSeconds = request.CreatedAtUnixSeconds,
                ExpiresAtUnixSeconds = request.ExpiresAtUnixSeconds,
                ReservedAtUnixSeconds = policy.NowUnixSeconds,
                EpochExpiresAtUnixSeconds = policy.EpochExpiresAtUnixSeconds,
                RetainUntilUnixSeconds = retainUntil
            });
    }

    private static byte[] EncodeUnsigned(MailboxPeerWireRequestV2 request)
    {
        var senderProof =
            MailboxPeerReplicationCodec.EncodeMembershipProof(
                request.SenderMembershipProof);
        var recipientProof =
            MailboxPeerReplicationCodec.EncodeMembershipProof(
                request.RecipientMembershipProof);
        var output = new byte[
            MailboxPeerWireV2Limits.RequestHeaderLength +
            request.Payload.Length +
            senderProof.Length +
            recipientProof.Length +
            MailboxPeerReplicationLimits.SignatureLength];
        Magic.CopyTo(output);
        output[4] = Version;
        output[5] = (byte)request.Operation;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), request.Epoch);
        request.OperationId.Span.CopyTo(output.AsSpan(16));
        request.SenderRouterId.Span.CopyTo(output.AsSpan(32));
        request.RecipientRouterId.Span.CopyTo(output.AsSpan(64));
        request.MembershipCommitment.Span.CopyTo(output.AsSpan(96));
        request.PlacementCommitment.Span.CopyTo(output.AsSpan(128));
        request.BlindedMailboxId.Span.CopyTo(output.AsSpan(160));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(192), request.Cursor);
        BinaryPrimitives.WriteUInt64BigEndian(
            output.AsSpan(200),
            request.CreatedAtUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(
            output.AsSpan(208),
            request.ExpiresAtUnixSeconds);
        request.ReplayNonce.Span.CopyTo(output.AsSpan(216));
        request.PayloadDigest.Span.CopyTo(output.AsSpan(248));
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(280),
            checked((uint)request.Payload.Length));
        BinaryPrimitives.WriteUInt16BigEndian(
            output.AsSpan(284),
            checked((ushort)senderProof.Length));
        BinaryPrimitives.WriteUInt16BigEndian(
            output.AsSpan(286),
            checked((ushort)recipientProof.Length));
        BinaryPrimitives.WriteUInt16BigEndian(
            output.AsSpan(288),
            MailboxPeerReplicationLimits.SignatureLength);
        var offset = MailboxPeerWireV2Limits.RequestHeaderLength;
        request.Payload.Span.CopyTo(output.AsSpan(offset));
        offset += request.Payload.Length;
        senderProof.CopyTo(output, offset);
        offset += senderProof.Length;
        recipientProof.CopyTo(output, offset);
        return output;
    }

    private static void ValidateRequest(
        MailboxPeerWireRequestV2 request,
        bool requireSignature)
    {
        if (request.Operation is not (
                MailboxPeerReplicationOperation.Store or
                MailboxPeerReplicationOperation.Tombstone))
            throw Error(
                MailboxPeerReplicationError.InvalidEnum,
                "PRQ2 operation is invalid.");
        ValidateNonzero(request.OperationId.Span, 16);
        ValidateNonzero(request.SenderRouterId.Span, 32);
        ValidateNonzero(request.RecipientRouterId.Span, 32);
        ValidateNonzero(request.MembershipCommitment.Span, 32);
        ValidateNonzero(request.PlacementCommitment.Span, 32);
        ValidateNonzero(request.BlindedMailboxId.Span, 32);
        ValidateNonzero(request.ReplayNonce.Span, 32);
        ValidateNonzero(request.PayloadDigest.Span, 32);
        if (request.Epoch == 0 ||
            request.Cursor == 0 ||
            request.CreatedAtUnixSeconds == 0 ||
            request.CreatedAtUnixSeconds >= request.ExpiresAtUnixSeconds ||
            FixedEquals(
                request.SenderRouterId.Span,
                request.RecipientRouterId.Span) ||
            request.SenderMembershipProof is null ||
            request.RecipientMembershipProof is null ||
            !FixedEquals(
                request.SenderRouterId.Span,
                request.SenderMembershipProof.ReplicaId.Span) ||
            !FixedEquals(
                request.RecipientRouterId.Span,
                request.RecipientMembershipProof.ReplicaId.Span) ||
            request.SenderMembershipProof.Epoch != request.Epoch ||
            request.RecipientMembershipProof.Epoch != request.Epoch ||
            !FixedEquals(
                request.SenderMembershipProof.MembershipCommitment.Span,
                request.MembershipCommitment.Span) ||
            !FixedEquals(
                request.RecipientMembershipProof.MembershipCommitment.Span,
                request.MembershipCommitment.Span))
            throw Error(
                MailboxPeerReplicationError.InvalidField,
                "PRQ2 fixed routing or membership fields are invalid.");
        if (request.Operation == MailboxPeerReplicationOperation.Store)
        {
            if (request.Payload.Length is
                    < MailboxClientLimits.EncryptedEnvelopeHeaderLength +
                      MailboxClientLimits.MinimumCiphertextLength or
                    > MailboxClientLimits.MaximumEncryptedEnvelopeLength)
                throw Error(
                    MailboxPeerReplicationError.InvalidPayload,
                    "PRQ2 Store requires one bounded canonical MEO1.");
        }
        else if (request.Payload.Length != MailboxClientLimits.DigestLength)
            throw Error(
                MailboxPeerReplicationError.InvalidPayload,
                "PRQ2 Tombstone requires exactly one envelope digest.");
        if (requireSignature)
            ValidateNonzero(
                request.Signature.Span,
                MailboxPeerReplicationLimits.SignatureLength);
        else if (!request.Signature.IsEmpty &&
                 request.Signature.Length !=
                    MailboxPeerReplicationLimits.SignatureLength)
            throw Error(
                MailboxPeerReplicationError.InvalidSignature,
                "PRQ2 signature is not empty or exactly 64 bytes.");
    }

    private static MailboxEncryptedEnvelope DecodeCanonicalEnvelope(
        ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < MailboxClientLimits.EncryptedEnvelopeHeaderLength ||
            !encoded[..4].SequenceEqual("MEO1"u8) ||
            encoded[4] != 1 ||
            encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(148, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(
                MailboxPeerReplicationError.InvalidPayload,
                "Nested MEO1 header is invalid.");
        var ciphertextLength =
            BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(144, 4));
        if (ciphertextLength is
                < MailboxClientLimits.MinimumCiphertextLength or
                > MailboxClientLimits.MaximumCiphertextLength ||
            encoded.Length !=
                MailboxClientLimits.EncryptedEnvelopeHeaderLength +
                ciphertextLength)
            throw Error(
                MailboxPeerReplicationError.InvalidPayload,
                "Nested MEO1 length is invalid.");
        var envelope = new MailboxEncryptedEnvelope
        {
            Epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8)),
            MailboxId = new BlindedMailboxId(encoded.Slice(16, 32)),
            PlacementId = new BlindedPlacementId(encoded.Slice(48, 32)),
            OperationId = encoded.Slice(80, 16).ToArray(),
            DeduplicationDigest = encoded.Slice(96, 32).ToArray(),
            CreatedAtUnixSeconds =
                BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(128, 8)),
            ExpiresAtUnixSeconds =
                BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(136, 8)),
            Ciphertext = encoded[152..].ToArray()
        };
        if (!encoded.SequenceEqual(MailboxClientCodec.EncodeEncryptedEnvelope(envelope)))
            throw Error(
                MailboxPeerReplicationError.InvalidPayload,
                "Nested MEO1 is not canonical.");
        return envelope;
    }

    private static ReadOnlyMemory<byte> ExpectedEnvelopeDigest(
        VerifiedMailboxPeerWireRequestV2 verifiedRequest) =>
        verifiedRequest.Request.Operation == MailboxPeerReplicationOperation.Store
            ? verifiedRequest.Envelope?.DeduplicationDigest.ToArray() ??
              throw Error(
                  MailboxPeerReplicationError.InvalidPayload,
                  "Verified PRQ2 Store has no MEO1.")
            : verifiedRequest.Request.Payload.ToArray();

    private static MailboxReplicaReceiptV2 DecodeAndVerifySelectedReplica(
        ReadOnlySpan<byte> encoded,
        VerifiedMailboxPeerWireRequestV2 verifiedRequest,
        IMailboxPeerReplicationCrypto crypto)
    {
        if (encoded.Length != MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength)
            throw Error(
                MailboxPeerReplicationError.InvalidReceipt,
                "PRQ2 quorum requires exact Ed25519 MRR2 inputs.");
        var receipt = MailboxReceiptV2Codec.DecodeReplica(encoded);
        if (!MatchesRequest(receipt, verifiedRequest, allowSender: true))
            throw Error(
                MailboxPeerReplicationError.InvalidReceipt,
                "MRR2 does not match the exact PRQ2 quorum context.");
        var request = verifiedRequest.Request;
        var key = FixedEquals(receipt.ReplicaId.Span, request.SenderRouterId.Span)
            ? request.SenderMembershipProof.SigningPublicKey
            : request.RecipientMembershipProof.SigningPublicKey;
        if (!crypto.Verify(
                key.Span,
                MailboxReceiptV2Codec.GetReplicaSigningBytes(receipt),
                receipt.Signature.Span))
            throw Error(
                MailboxPeerReplicationError.InvalidReceipt,
                "A selected PRQ2 MRR2 signature is invalid.");
        return receipt;
    }

    private static void ValidateReplicaPair(
        MailboxReplicaReceiptV2 first,
        MailboxReplicaReceiptV2 second,
        VerifiedMailboxPeerWireRequestV2 verifiedRequest)
    {
        if (first.ReplicaId.Span.SequenceCompareTo(second.ReplicaId.Span) >= 0 ||
            first.Disposition != second.Disposition ||
            !ContainsExactlySelectedRouters(
                first.ReplicaId.Span,
                second.ReplicaId.Span,
                verifiedRequest.Request))
            throw Error(
                MailboxPeerReplicationError.InvalidReceipt,
                "MQR3 must contain the two distinct PRQ2 routers in canonical order.");
    }

    private static bool MatchesRequest(
        MailboxReplicaReceiptV2 receipt,
        VerifiedMailboxPeerWireRequestV2 verifiedRequest,
        bool allowSender)
    {
        var request = verifiedRequest.Request;
        var selected =
            FixedEquals(receipt.ReplicaId.Span, request.RecipientRouterId.Span) ||
            allowSender &&
            FixedEquals(receipt.ReplicaId.Span, request.SenderRouterId.Span);
        return selected &&
               receipt.Status == MailboxReceiptStatus.Durable &&
               AllowedDisposition(request.Operation, receipt.Disposition) &&
               FixedEquals(receipt.OperationId.Span, request.OperationId.Span) &&
               receipt.Epoch == request.Epoch &&
               receipt.Cursor == request.Cursor &&
               receipt.AcceptedAtUnixSeconds >= request.CreatedAtUnixSeconds &&
               receipt.ExpiresAtUnixSeconds == request.ExpiresAtUnixSeconds &&
               FixedEquals(
                   receipt.BlindedMailboxId.Span,
                   request.BlindedMailboxId.Span) &&
               FixedEquals(
                   receipt.PlacementCommitment.Span,
                   request.PlacementCommitment.Span) &&
               FixedEquals(
                   receipt.MembershipCommitment.Span,
                   request.MembershipCommitment.Span) &&
               FixedEquals(
                   receipt.EnvelopeDigest.Span,
                   ExpectedEnvelopeDigest(verifiedRequest).Span);
    }

    private static bool ContainsExactlySelectedRouters(
        ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second,
        MailboxPeerWireRequestV2 request) =>
        !FixedEquals(first, second) &&
        (FixedEquals(first, request.SenderRouterId.Span) &&
         FixedEquals(second, request.RecipientRouterId.Span) ||
         FixedEquals(first, request.RecipientRouterId.Span) &&
         FixedEquals(second, request.SenderRouterId.Span));

    private static bool IsSelectedRouter(
        ReadOnlySpan<byte> routerId,
        MailboxPeerWireRequestV2 request) =>
        FixedEquals(routerId, request.SenderRouterId.Span) ||
        FixedEquals(routerId, request.RecipientRouterId.Span);

    private static ulong Prq2CoordinatorSequence(
        VerifiedMailboxPeerWireRequestV2 verifiedRequest) =>
        BinaryPrimitives.ReadUInt64BigEndian(
            verifiedRequest.ReplayClaim.RequestDigest.Span) |
        0x8000_0000_0000_0000UL;

    private static bool AllowedDisposition(
        MailboxPeerReplicationOperation operation,
        MailboxReplicaDisposition disposition) =>
        operation == MailboxPeerReplicationOperation.Store
            ? disposition is (
                MailboxReplicaDisposition.Stored or
                MailboxReplicaDisposition.Duplicate)
            : disposition == MailboxReplicaDisposition.Tombstone;

    private static ReadOnlySpan<byte> SigningDomain(
        MailboxPeerReplicationOperation operation) =>
        operation switch
        {
            MailboxPeerReplicationOperation.Store =>
                "deep.mailbox.peer.store-request.v2"u8,
            MailboxPeerReplicationOperation.Tombstone =>
                "deep.mailbox.peer.tombstone-request.v2"u8,
            _ => throw Error(
                MailboxPeerReplicationError.InvalidEnum,
                "PRQ2 operation has no signing domain.")
        };

    private static byte[] DomainSeparatedHash(
        ReadOnlySpan<byte> domain,
        ReadOnlySpan<byte> value)
    {
        var preimage = new byte[2 + domain.Length + 4 + value.Length];
        BinaryPrimitives.WriteUInt16BigEndian(
            preimage,
            checked((ushort)domain.Length));
        domain.CopyTo(preimage.AsSpan(2));
        BinaryPrimitives.WriteUInt32BigEndian(
            preimage.AsSpan(2 + domain.Length),
            checked((uint)value.Length));
        value.CopyTo(preimage.AsSpan(2 + domain.Length + 4));
        return SHA256.HashData(preimage);
    }

    private static void ValidateNonzero(ReadOnlySpan<byte> value, int length)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw Error(
                MailboxPeerReplicationError.InvalidField,
                "A PRQ2 fixed field is invalid.");
    }

    private static bool FixedEquals(
        ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static MailboxPeerReplicationException Error(
        MailboxPeerReplicationError error,
        string message) => new(error, message);

}
