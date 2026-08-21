using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// A sealed, defensively owned DPR1 + PRQ2 verification fact. It is an authenticated request
/// fact only; it carries no replay reservation, mutation, delivery, or durability authority.
/// </summary>
public sealed class VerifiedNativePeerRequest
{
    private readonly byte[] _dpr;
    private readonly byte[] _prq;
    private readonly byte[] _requestId;
    private readonly byte[] _senderKey;
    private readonly byte[] _recipientKey;
    private readonly MailboxPeerWireRequestV2 _request;

    internal VerifiedNativePeerRequest(
        OwnedRecord dpr,
        ReadOnlySpan<byte> prq,
        MailboxPeerWireRequestV2 request,
        ReadOnlySpan<byte> senderKey,
        ReadOnlySpan<byte> recipientKey)
    {
        _dpr = dpr.CanonicalCopy();
        _prq = prq.ToArray();
        _requestId = dpr.FieldCopy(6);
        _senderKey = senderKey.ToArray();
        _recipientKey = recipientKey.ToArray();
        _request = request;
        Operation = request.Operation;
        Epoch = request.Epoch;
        IssuedAtUnixSeconds = Scalars.UInt64(dpr.FieldSpan(7));
        ExpiresAtUnixSeconds = Scalars.UInt64(dpr.FieldSpan(8));
    }

    public ReadOnlyMemory<byte> CanonicalDpr1 => _dpr.ToArray();
    public ReadOnlyMemory<byte> CanonicalPrq2 => _prq.ToArray();
    public ReadOnlyMemory<byte> RequestId => _requestId.ToArray();
    public MailboxPeerReplicationOperation Operation { get; }
    public ulong Epoch { get; }
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public bool NoMutationOrDurabilityClaim => true;

    internal ReadOnlySpan<byte> TrustedDpr => _dpr;
    internal ReadOnlySpan<byte> TrustedPrq => _prq;
    internal ReadOnlySpan<byte> TrustedSenderKey => _senderKey;
    internal ReadOnlySpan<byte> TrustedRecipientKey => _recipientKey;
    internal MailboxPeerWireRequestV2 TrustedRequest => _request;
}

/// <summary>A sealed exact DPS1 + MRR2 authentication fact with no delivery authority.</summary>
public sealed class VerifiedNativePeerResponse
{
    private readonly byte[] _dps;
    private readonly byte[] _mrr;

    internal VerifiedNativePeerResponse(OwnedRecord dps, ReadOnlySpan<byte> mrr)
    {
        _dps = dps.CanonicalCopy();
        _mrr = mrr.ToArray();
        IssuedAtUnixSeconds = Scalars.UInt64(dps.FieldSpan(9));
        ExpiresAtUnixSeconds = Scalars.UInt64(dps.FieldSpan(10));
    }

    public ReadOnlyMemory<byte> CanonicalDps1 => _dps.ToArray();
    public ReadOnlyMemory<byte> CanonicalMrr2 => _mrr.ToArray();
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public bool NoDeliveryOrDurabilityClaim => true;
}

/// <summary>Verifies the exact one-frame native peer request without accepting caller authority.</summary>
public static class NativePeerVerifier
{
    public const int DprLength = 408;
    public const int RequestFramePrefixLength = 4;
    public const int RequestFixedOverhead = 4 + DprLength + 4;
    public const int DpsLength = 444;
    public const int MrrLength = 296;
    public const int ResponseLength = 4 + DpsLength + 4 + MrrLength;
    private const string RequestDomain = "Deep/NativeRouting/V1/request";
    private const string ResponseDomain = "Deep/NativeRouting/V1/response";

    public static VerifiedNativePeerRequest VerifyRequest(
        ReadOnlySpan<byte> canonicalFrame,
        VerifiedMembershipRoutingLkg membership,
        VerifiedRouterContact senderContact,
        VerifiedRouterContact recipientContact,
        BlindedPlacementId expectedPlacementId,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(membership);
        ArgumentNullException.ThrowIfNull(senderContact);
        ArgumentNullException.ThrowIfNull(recipientContact);
        ArgumentNullException.ThrowIfNull(expectedPlacementId);

        // All outer and nested lengths are checked before the first copy or signature operation.
        if (canonicalFrame.Length < RequestFixedOverhead +
                MailboxPeerWireV2Limits.MinimumTombstoneRequestLength ||
            canonicalFrame.Length > RequestFixedOverhead +
                MailboxPeerWireV2Limits.MaximumRequestLength ||
            BinaryPrimitives.ReadUInt32BigEndian(canonicalFrame) != DprLength)
            Invalid(RecordError.InvalidLength, "The native peer request frame length is invalid.");
        var rawPrqLength = BinaryPrimitives.ReadUInt32BigEndian(
            canonicalFrame.Slice(4 + DprLength, 4));
        if (rawPrqLength > int.MaxValue ||
            rawPrqLength < MailboxPeerWireV2Limits.MinimumTombstoneRequestLength ||
            rawPrqLength > MailboxPeerWireV2Limits.MaximumRequestLength ||
            canonicalFrame.Length != RequestFixedOverhead + checked((int)rawPrqLength))
            Invalid(RecordError.InvalidLength, "The native peer PRQ2 frame is malformed.");

        var canonicalDpr = canonicalFrame.Slice(4, DprLength);
        var prq = canonicalFrame[RequestFixedOverhead..];
        CanonicalGrammar.Preflight(canonicalDpr, RecordDefinitions.Dpr1);
        PreflightPrq(prq);
        var dpr = CanonicalGrammar.DecodeOwned(
            canonicalDpr,
            RecordDefinitions.Dpr1);
        Equal(dpr.FieldSpan(1), membership.TrustedNetworkId, "DPR1 network mismatch.");
        Equal(dpr.FieldSpan(2), senderContact.RouterId.Span, "DPR1 sender mismatch.");
        Equal(dpr.FieldSpan(3), recipientContact.RouterId.Span, "DPR1 recipient mismatch.");
        if (CanonicalGrammar.FixedEquals(dpr.FieldSpan(2), dpr.FieldSpan(3)))
            Invalid(RecordError.InvalidField, "DPR1 sender and recipient are equal.");
        Equal(dpr.FieldSpan(4), senderContact.ArtifactReference.Span,
            "DPR1 sender contact mismatch.");
        Equal(dpr.FieldSpan(5), recipientContact.ArtifactReference.Span,
            "DPR1 recipient contact mismatch.");
        if (CanonicalGrammar.IsZero(dpr.FieldSpan(6)))
            Invalid(RecordError.InvalidField, "DPR1 request ID is zero.");
        var issuedAt = Scalars.UInt64(dpr.FieldSpan(7));
        var expiresAt = Scalars.UInt64(dpr.FieldSpan(8));
        if (issuedAt == 0 || issuedAt >= expiresAt ||
            transactionTimeUnixSeconds < issuedAt || transactionTimeUnixSeconds >= expiresAt ||
            issuedAt < senderContact.IssuedAtUnixSeconds ||
            issuedAt < recipientContact.IssuedAtUnixSeconds ||
            expiresAt > senderContact.ExpiresAtUnixSeconds ||
            expiresAt > recipientContact.ExpiresAtUnixSeconds ||
            expiresAt > membership.EpochExpiresAtUnixSeconds)
            Invalid(RecordError.Expired, "DPR1 is outside its exact contact and epoch window.");

        var sender = FindRouter(membership, dpr.FieldSpan(2), senderContact);
        var recipient = FindRouter(membership, dpr.FieldSpan(3), recipientContact);

        var prqReference = new ArtifactReference(
            ArtifactType.Prq2,
            rawPrqLength,
            SHA256.HashData(prq));
        Equal(dpr.FieldSpan(10), CanonicalGrammar.EncodeReference(prqReference),
            "DPR1 PRQ2 reference mismatch.");
        Equal(prq.Slice(32, 32), dpr.FieldSpan(2), "DPR1/PRQ2 sender mismatch.");
        Equal(prq.Slice(64, 32), dpr.FieldSpan(3), "DPR1/PRQ2 recipient mismatch.");
        Equal(prq.Slice(96, 32), membership.MembershipRoot.Span,
            "PRQ2 membership root mismatch.");
        Equal(prq.Slice(128, 32), MailboxPlacementCommitment.Compute(expectedPlacementId),
            "PRQ2 placement commitment mismatch.");
        Equal(prq.Slice(216, 32), dpr.FieldSpan(6), "DPR1/PRQ2 request ID mismatch.");
        if (BinaryPrimitives.ReadUInt64BigEndian(prq.Slice(8, 8)) != membership.Epoch ||
            BinaryPrimitives.ReadUInt64BigEndian(prq.Slice(200, 8)) != issuedAt ||
            BinaryPrimitives.ReadUInt64BigEndian(prq.Slice(208, 8)) != expiresAt)
            Invalid(RecordError.InvalidField,
                "DPR1 and PRQ2 epoch or time-window fields differ.");

        VerifyDetached(
            dpr.FieldSpan(11),
            CanonicalGrammar.GetSigningBytes(dpr, RequestDomain),
            sender.RouterEd25519PublicKey);

        MailboxPeerWireRequestV2 request;
        try
        {
            request = MailboxPeerWireV2Codec.VerifyReplayCandidate(
                prq,
                new MailboxPeerWireVerificationPolicyV2
                {
                    ExpectedOperation = (MailboxPeerReplicationOperation)prq[5],
                    Epoch = membership.Epoch,
                    OperationId = prq.Slice(16, 16).ToArray(),
                    SenderRouterId = senderContact.RouterId,
                    RecipientRouterId = recipientContact.RouterId,
                    MembershipCommitment = membership.MembershipRoot,
                    PlacementCommitment = MailboxPlacementCommitment.Compute(expectedPlacementId),
                    PlacementId = expectedPlacementId,
                    NowUnixSeconds = transactionTimeUnixSeconds,
                    EpochExpiresAtUnixSeconds = membership.EpochExpiresAtUnixSeconds
                },
                SodiumPeerCrypto.Instance,
                new NativeMembershipAdapter(membership));
        }
        catch (MailboxPeerReplicationException)
        {
            throw new RecordException(RecordError.InvalidField,
                "The nested PRQ2 is invalid.");
        }

        if (request.CreatedAtUnixSeconds != issuedAt || request.ExpiresAtUnixSeconds != expiresAt ||
            !CanonicalGrammar.FixedEquals(request.ReplayNonce.Span, dpr.FieldSpan(6)))
            Invalid(RecordError.InvalidField, "DPR1 and PRQ2 time or request-ID fields differ.");
        return new VerifiedNativePeerRequest(
            dpr, prq, request, sender.RouterEd25519PublicKey, recipient.RouterEd25519PublicKey);
    }

    public static VerifiedNativePeerResponse VerifyResponse(
        ReadOnlySpan<byte> canonicalFrame,
        VerifiedNativePeerRequest request,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (canonicalFrame.Length != ResponseLength ||
            BinaryPrimitives.ReadUInt32BigEndian(canonicalFrame) != DpsLength ||
            BinaryPrimitives.ReadUInt32BigEndian(canonicalFrame.Slice(4 + DpsLength, 4)) != MrrLength)
            Invalid(RecordError.InvalidLength, "The native peer response frame length is invalid.");

        var dps = CanonicalGrammar.DecodeOwned(
            canonicalFrame.Slice(4, DpsLength), RecordDefinitions.Dps1);
        var mrrBytes = canonicalFrame.Slice(8 + DpsLength, MrrLength);
        var dpr = CanonicalGrammar.DecodeOwned(request.TrustedDpr, RecordDefinitions.Dpr1);
        Equal(dps.FieldSpan(1), dpr.FieldSpan(1), "DPS1 network mismatch.");
        Equal(dps.FieldSpan(2), dpr.FieldSpan(2), "DPS1 sender mismatch.");
        Equal(dps.FieldSpan(3), dpr.FieldSpan(3), "DPS1 recipient mismatch.");
        Equal(dps.FieldSpan(4), dpr.FieldSpan(4), "DPS1 sender contact mismatch.");
        Equal(dps.FieldSpan(5), dpr.FieldSpan(5), "DPS1 recipient contact mismatch.");
        Equal(dps.FieldSpan(6), dpr.FieldSpan(6), "DPS1 request ID mismatch.");
        var dprReference = CanonicalGrammar.ComputeReference(
            ArtifactType.Dpr1, dpr.CanonicalSpan);
        Equal(dps.FieldSpan(7), CanonicalGrammar.EncodeReference(dprReference),
            "DPS1 DPR1 reference mismatch.");
        var mrrReference = new ArtifactReference(
            ArtifactType.Mrr2, MrrLength, SHA256.HashData(mrrBytes));
        Equal(dps.FieldSpan(8), CanonicalGrammar.EncodeReference(mrrReference),
            "DPS1 MRR2 reference mismatch.");
        var issuedAt = Scalars.UInt64(dps.FieldSpan(9));
        var expiresAt = Scalars.UInt64(dps.FieldSpan(10));
        if (issuedAt < request.IssuedAtUnixSeconds || issuedAt >= expiresAt ||
            expiresAt > request.ExpiresAtUnixSeconds ||
            transactionTimeUnixSeconds < issuedAt || transactionTimeUnixSeconds >= expiresAt)
            Invalid(RecordError.Expired, "DPS1 is outside the exact DPR1 window.");
        VerifyDetached(
            dps.FieldSpan(11),
            CanonicalGrammar.GetSigningBytes(dps, ResponseDomain),
            request.TrustedRecipientKey);

        MailboxReplicaReceiptV2 receipt;
        try
        {
            receipt = MailboxReceiptV2Codec.DecodeReplica(mrrBytes);
        }
        catch (MailboxReceiptException)
        {
            throw new RecordException(RecordError.InvalidField,
                "The nested MRR2 is invalid.");
        }
        var inner = request.TrustedRequest;
        var expectedDigest = inner.Operation == MailboxPeerReplicationOperation.Store
            ? inner.Payload.Span.Slice(96, 32)
            : inner.Payload.Span;
        var allowedDisposition = inner.Operation == MailboxPeerReplicationOperation.Store
            ? receipt.Disposition is MailboxReplicaDisposition.Stored or MailboxReplicaDisposition.Duplicate
            : receipt.Disposition == MailboxReplicaDisposition.Tombstone;
        if (receipt.Status != MailboxReceiptStatus.Durable || !allowedDisposition ||
            !CanonicalGrammar.FixedEquals(receipt.ReplicaId.Span, inner.RecipientRouterId.Span) ||
            !CanonicalGrammar.FixedEquals(receipt.OperationId.Span, inner.OperationId.Span) ||
            receipt.Epoch != inner.Epoch || receipt.Cursor != inner.Cursor ||
            receipt.AcceptedAtUnixSeconds < inner.CreatedAtUnixSeconds ||
            receipt.DurableAtUnixSeconds < receipt.AcceptedAtUnixSeconds ||
            receipt.DurableAtUnixSeconds > issuedAt ||
            receipt.ExpiresAtUnixSeconds != inner.ExpiresAtUnixSeconds ||
            !CanonicalGrammar.FixedEquals(receipt.BlindedMailboxId.Span, inner.BlindedMailboxId.Span) ||
            !CanonicalGrammar.FixedEquals(receipt.PlacementCommitment.Span, inner.PlacementCommitment.Span) ||
            !CanonicalGrammar.FixedEquals(receipt.MembershipCommitment.Span, inner.MembershipCommitment.Span) ||
            !CanonicalGrammar.FixedEquals(receipt.EnvelopeDigest.Span, expectedDigest))
            Invalid(RecordError.InvalidField, "MRR2 does not match the exact native request.");
        VerifyDetached(
            receipt.Signature.Span,
            MailboxReceiptV2Codec.GetReplicaSigningBytes(receipt),
            request.TrustedRecipientKey);
        return new VerifiedNativePeerResponse(dps, mrrBytes);
    }

    private static VerifiedRouterEntry FindRouter(
        VerifiedMembershipRoutingLkg membership,
        ReadOnlySpan<byte> routerId,
        VerifiedRouterContact contact)
    {
        VerifiedRouterEntry? router = null;
        foreach (var candidate in membership.TrustedRouters)
        {
            if (!CanonicalGrammar.FixedEquals(candidate.RouterId, routerId)) continue;
            if (router is not null)
                Invalid(RecordError.ForkDetected, "The sealed router table contains a duplicate ID.");
            router = candidate;
        }
        if (router is null ||
            (router.Capabilities & RouterCapabilities.NativePeerMailboxV2) == 0)
            Invalid(RecordError.Revoked, "The DPR1 router lacks native-peer authority.");
        var contactRecord = CanonicalGrammar.DecodeOwned(
            contact.TrustedCanonical,
            RecordDefinitions.Dpc1);
        Equal(contactRecord.FieldSpan(3), router!.DnrReference,
            "The DPR1 contact belongs to another router certificate.");
        var mrl = CanonicalGrammar.DecodeOwned(router.Mrl2, RecordDefinitions.Mrl2);
        if (contact.AnchorGeneration != Scalars.UInt64(mrl.FieldSpan(8)))
            Invalid(RecordError.InvalidTransition,
                "The DPR1 contact anchor generation belongs to another MRL2 row.");
        Equal(contact.TrustedAnchorReference, mrl.FieldSpan(9),
            "The DPR1 contact chain belongs to another MRL2 anchor.");
        return router;
    }

    private sealed class NativeMembershipAdapter(VerifiedMembershipRoutingLkg membership)
        : IMailboxReplicaMembershipProofVerifier
    {
        public bool VerifyStorageReplica(
            MailboxReplicaMembershipProof proof,
            ulong verificationTimeUnixSeconds)
        {
            try
            {
                var canonical = MailboxPeerReplicationCodec.EncodeMembershipProof(proof);
                var result = NativeMembershipVerifier.VerifyMailboxMembership(canonical, membership);
                return (result.Roles & RouterRoles.MailboxReplica) != 0 &&
                       (result.Capabilities & RouterCapabilities.NativePeerMailboxV2) != 0;
            }
            catch (RecordException)
            {
                return false;
            }
            catch (MailboxPeerReplicationException)
            {
                return false;
            }
        }
    }

    private sealed class SodiumPeerCrypto : IMailboxPeerReplicationCrypto
    {
        internal static SodiumPeerCrypto Instance { get; } = new();

        public bool Verify(
            ReadOnlySpan<byte> publicKey,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            try
            {
                return PublicKeyAuth.VerifyDetached(
                    signature.ToArray(), signingBytes.ToArray(), publicKey.ToArray());
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        public byte[] Digest(ReadOnlySpan<byte> canonicalBytes) => SHA256.HashData(canonicalBytes);
    }

    private static void VerifyDetached(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> publicKey)
    {
        if (!SodiumPeerCrypto.Instance.Verify(publicKey, signingBytes, signature))
            Invalid(RecordError.InvalidSignature, "The DPR1 router signature is invalid.");
    }

    private static void PreflightPrq(ReadOnlySpan<byte> canonicalPrq)
    {
        try
        {
            _ = MailboxPeerWireV2Codec.PreflightCanonical(canonicalPrq);
        }
        catch (MailboxPeerReplicationException)
        {
            throw new RecordException(RecordError.InvalidField,
                "The nested PRQ2 framing is invalid.");
        }
    }

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string message)
    {
        if (!CanonicalGrammar.FixedEquals(actual, expected))
            Invalid(RecordError.InvalidField, message);
    }

    private static void Invalid(RecordError error, string message) =>
        throw new RecordException(error, message);
}
