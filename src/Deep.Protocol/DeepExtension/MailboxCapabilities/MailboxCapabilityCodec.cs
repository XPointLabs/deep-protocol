using System.Buffers.Binary;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxCapabilityCodec
{
    private static ReadOnlySpan<byte> Magic => "MCP1"u8;
    private static ReadOnlySpan<byte> AdmissionMagic => "MFA1"u8;
    private const byte Version = 1;

    public static byte[] Encode(MailboxCapabilityPresentation presentation)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        var domain = GetDomain(presentation.DomainValue);
        ValidatePresentation(presentation, policy: null);
        var admission = presentation.FreeAdmission is null
            ? Array.Empty<byte>()
            : EncodeAdmission(presentation.FreeAdmission);
        var value = presentation.DomainValue.Bytes.Span;
        var encoded = new byte[
            MailboxCapabilityLimits.FixedPresentationHeaderLength +
            value.Length +
            admission.Length];

        Magic.CopyTo(encoded);
        encoded[4] = Version;
        encoded[5] = (byte)domain;
        encoded[6] = (byte)presentation.Lifecycle;
        encoded[7] = (byte)presentation.MixedVersion;
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(8, 8), presentation.Generation);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(16, 4), presentation.NotBeforeBucket);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(20, 4), presentation.ExpiresAtBucket);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(24, 4), presentation.OverlapUntilBucket);
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(32, 8), presentation.ReplayCounter);
        presentation.IdempotencyKey.Span.CopyTo(
            encoded.AsSpan(40, MailboxCapabilityLimits.IdempotencyKeyLength));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(56, 2), checked((ushort)value.Length));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(58, 2), checked((ushort)admission.Length));
        value.CopyTo(encoded.AsSpan(MailboxCapabilityLimits.FixedPresentationHeaderLength));
        admission.CopyTo(
            encoded,
            MailboxCapabilityLimits.FixedPresentationHeaderLength + value.Length);
        return encoded;
    }

    public static MailboxCapabilityDecodeResult Decode(
        ReadOnlySpan<byte> encoded,
        MailboxCapabilityDomain expectedDomain,
        MailboxCapabilityDecodePolicy policy,
        IMailboxCapabilityReplayGuard replayGuard)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(replayGuard);
        if (encoded.Length is
            < MailboxCapabilityLimits.FixedPresentationHeaderLength or
            > MailboxCapabilityLimits.MaximumPresentationLength)
        {
            throw Error(
                MailboxCapabilityError.EncodedLengthOutOfRange,
                "The mailbox capability presentation length is outside strict bounds.");
        }

        if (!encoded[..Magic.Length].SequenceEqual(Magic))
        {
            throw Error(MailboxCapabilityError.InvalidMagic, "The mailbox capability magic is invalid.");
        }

        if (encoded[4] != Version)
        {
            throw Error(MailboxCapabilityError.UnsupportedVersion, "The mailbox capability version is unsupported.");
        }

        var domain = (MailboxCapabilityDomain)encoded[5];
        if (domain is not (
            MailboxCapabilityDomain.Deposit or
            MailboxCapabilityDomain.Retrieve or
            MailboxCapabilityDomain.Placement))
        {
            throw Error(MailboxCapabilityError.InvalidEnumValue, "The mailbox capability domain is invalid.");
        }

        if (domain != expectedDomain)
        {
            throw Error(
                MailboxCapabilityError.CrossDomainPresentation,
                "A mailbox capability cannot be decoded through a different domain.");
        }

        var lifecycle = (MailboxCapabilityLifecycle)encoded[6];
        var mixedVersion = (MailboxMixedVersionMarker)encoded[7];
        if (lifecycle is not (
                MailboxCapabilityLifecycle.Active or
                MailboxCapabilityLifecycle.Overlap or
                MailboxCapabilityLifecycle.Revoked or
                MailboxCapabilityLifecycle.Recovery) ||
            mixedVersion is not (
                MailboxMixedVersionMarker.StrictV1 or
                MailboxMixedVersionMarker.LegacyMirrorOverlap))
        {
            throw Error(MailboxCapabilityError.InvalidEnumValue, "A lifecycle marker is invalid.");
        }

        if (encoded.Slice(28, 4).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(60, 4).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw Error(
                MailboxCapabilityError.ReservedFieldNotZero,
                "Reserved capability fields must be zero.");
        }

        var valueLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(56, 2));
        var admissionLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(58, 2));
        if (valueLength is
                < MailboxCapabilityLimits.MinimumDomainValueLength or
                > MailboxCapabilityLimits.MaximumDomainValueLength ||
            admissionLength != 0 &&
            admissionLength is
                < MailboxCapabilityLimits.FixedAdmissionHeaderLength +
                  MailboxCapabilityLimits.MinimumAdmissionAuthorizationLength or
                > MailboxCapabilityLimits.FixedAdmissionHeaderLength +
                  MailboxCapabilityLimits.MaximumAdmissionAuthorizationLength)
        {
            throw Error(MailboxCapabilityError.MalformedLength, "A capability body length is invalid.");
        }

        var expectedLength =
            MailboxCapabilityLimits.FixedPresentationHeaderLength +
            valueLength +
            admissionLength;
        if (expectedLength != encoded.Length)
        {
            throw Error(
                MailboxCapabilityError.MalformedLength,
                "The capability presentation has trailing or truncated bytes.");
        }

        var offset = MailboxCapabilityLimits.FixedPresentationHeaderLength;
        var domainBytes = encoded.Slice(offset, valueLength);
        var domainValue = domain switch
        {
            MailboxCapabilityDomain.Deposit =>
                (MailboxDomainValue)new RotatingDepositCapability(domainBytes),
            MailboxCapabilityDomain.Retrieve =>
                new RotatingRetrieveCapability(domainBytes),
            MailboxCapabilityDomain.Placement =>
                new OpaquePlacementKey(domainBytes),
            _ => throw Error(
                MailboxCapabilityError.InvalidEnumValue,
                "The mailbox capability domain is invalid.")
        };
        offset += valueLength;
        var admission = admissionLength == 0
            ? null
            : DecodeAdmission(encoded.Slice(offset, admissionLength));
        var presentation = new MailboxCapabilityPresentation
        {
            DomainValue = domainValue,
            Lifecycle = lifecycle,
            MixedVersion = mixedVersion,
            Generation = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8)),
            NotBeforeBucket = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(16, 4)),
            ExpiresAtBucket = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(20, 4)),
            OverlapUntilBucket = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(24, 4)),
            ReplayCounter = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(32, 8)),
            IdempotencyKey = encoded.Slice(40, MailboxCapabilityLimits.IdempotencyKeyLength).ToArray(),
            FreeAdmission = admission
        };
        ValidatePresentation(presentation, policy);

        var scope = new MailboxCapabilityReplayScope(
            domain,
            presentation.Generation,
            presentation.ReplayCounter,
            presentation.IdempotencyKey.ToArray(),
            encoded.ToArray());
        var evaluation = replayGuard.Evaluate(scope);
        if (evaluation is null)
        {
            throw Error(
                MailboxCapabilityError.InvalidReplayEvaluation,
                "The replay guard returned no evaluation.");
        }

        return evaluation.Decision switch
        {
            MailboxCapabilityReplayDecision.AcceptedNew
                when evaluation.CachedOutcome.IsEmpty =>
                new MailboxCapabilityDecodeResult
                {
                    Presentation = presentation,
                    ReplayDisposition = MailboxCapabilityReplayDisposition.New,
                    CachedOutcome = ReadOnlyMemory<byte>.Empty
                },
            MailboxCapabilityReplayDecision.IdempotentReplay
                when evaluation.CachedOutcome.Length is
                    > 0 and <= MailboxCapabilityLimits.MaximumCachedOutcomeLength =>
                new MailboxCapabilityDecodeResult
                {
                    Presentation = presentation,
                    ReplayDisposition = MailboxCapabilityReplayDisposition.IdempotentReplay,
                    CachedOutcome = evaluation.CachedOutcome.ToArray()
                },
            MailboxCapabilityReplayDecision.ReplayRejected
                when evaluation.CachedOutcome.IsEmpty =>
                throw Error(
                    MailboxCapabilityError.ReplayRejected,
                    "The capability presentation is a rejected replay."),
            MailboxCapabilityReplayDecision.IdempotencyConflict
                when evaluation.CachedOutcome.IsEmpty =>
                throw Error(
                    MailboxCapabilityError.IdempotencyConflict,
                    "The idempotency key conflicts with a different canonical presentation."),
            _ => throw Error(
                MailboxCapabilityError.InvalidReplayEvaluation,
                "The replay evaluation decision and cached outcome are inconsistent.")
        };
    }

    private static void ValidatePresentation(
        MailboxCapabilityPresentation presentation,
        MailboxCapabilityDecodePolicy? policy)
    {
        _ = GetDomain(presentation.DomainValue);
        if (presentation.Generation == 0)
        {
            throw Error(MailboxCapabilityError.InvalidGeneration, "Generation must be nonzero.");
        }

        if (presentation.NotBeforeBucket >= presentation.ExpiresAtBucket)
        {
            throw Error(
                MailboxCapabilityError.InvalidValidityWindow,
                "The validity window is empty or reversed.");
        }

        if (presentation.IdempotencyKey.Length != MailboxCapabilityLimits.IdempotencyKeyLength ||
            presentation.ReplayCounter == 0)
        {
            throw Error(
                MailboxCapabilityError.InvalidReplayOrIdempotency,
                "Replay and idempotency fields are outside strict bounds.");
        }

        if (presentation.Lifecycle == MailboxCapabilityLifecycle.Overlap)
        {
            if (presentation.OverlapUntilBucket <= presentation.NotBeforeBucket ||
                presentation.OverlapUntilBucket > presentation.ExpiresAtBucket)
            {
                throw Error(
                    MailboxCapabilityError.InvalidOverlap,
                    "An overlap presentation requires a finite bounded overlap window.");
            }
        }
        else if (presentation.OverlapUntilBucket != 0)
        {
            throw Error(
                MailboxCapabilityError.InvalidOverlap,
                "Only overlap presentations may carry overlap-until.");
        }

        if (presentation.MixedVersion == MailboxMixedVersionMarker.LegacyMirrorOverlap &&
            presentation.Lifecycle != MailboxCapabilityLifecycle.Overlap)
        {
            throw Error(
                MailboxCapabilityError.InvalidOverlap,
                "Legacy mirror overlap requires the explicit overlap lifecycle.");
        }

        if (presentation.FreeAdmission is not null)
        {
            ValidateAdmission(presentation.FreeAdmission);
            if (presentation.FreeAdmission.ValidFromBucket < presentation.NotBeforeBucket ||
                presentation.FreeAdmission.ValidUntilBucket > presentation.ExpiresAtBucket)
            {
                throw Error(
                    MailboxCapabilityError.InvalidAdmission,
                    "The free-admission window must be nested in the capability window.");
            }
        }

        if (policy is null)
        {
            return;
        }

        if (presentation.Generation < policy.MinimumGeneration)
        {
            throw Error(MailboxCapabilityError.InvalidGeneration, "The generation is below the strict floor.");
        }

        if (policy.CurrentBucket < presentation.NotBeforeBucket ||
            policy.CurrentBucket > presentation.ExpiresAtBucket ||
            presentation.Lifecycle == MailboxCapabilityLifecycle.Overlap &&
            policy.CurrentBucket > presentation.OverlapUntilBucket)
        {
            throw Error(
                MailboxCapabilityError.ExpiredOrNotYetValid,
                "The capability is outside its accepted validity window.");
        }

        if (presentation.MixedVersion == MailboxMixedVersionMarker.LegacyMirrorOverlap &&
            !policy.AllowLegacyMirrorOverlap)
        {
            throw Error(
                MailboxCapabilityError.LegacyOverlapNotAllowed,
                "Legacy mirror overlap is not explicitly allowed.");
        }

        if (presentation.Lifecycle == MailboxCapabilityLifecycle.Revoked && !policy.AllowRevoked)
        {
            throw Error(MailboxCapabilityError.RevokedNotAllowed, "Revoked capability use is not allowed.");
        }

        if (presentation.Lifecycle == MailboxCapabilityLifecycle.Recovery && !policy.AllowRecovery)
        {
            throw Error(MailboxCapabilityError.RecoveryNotAllowed, "Recovery capability use is not allowed.");
        }

        if (presentation.FreeAdmission is not null &&
            (policy.CurrentBucket < presentation.FreeAdmission.ValidFromBucket ||
             policy.CurrentBucket > presentation.FreeAdmission.ValidUntilBucket))
        {
            throw Error(
                MailboxCapabilityError.InvalidAdmission,
                "The free-admission slot is outside its accepted validity window.");
        }
    }

    private static byte[] EncodeAdmission(MailboxFreeAdmissionSlot admission)
    {
        ValidateAdmission(admission);
        var encoded = new byte[
            MailboxCapabilityLimits.FixedAdmissionHeaderLength +
            admission.Authorization.Length];
        AdmissionMagic.CopyTo(encoded);
        encoded[4] = Version;
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(6, 2), admission.UseLimit);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(8, 4), admission.ValidFromBucket);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(12, 4), admission.ValidUntilBucket);
        admission.SlotId.Span.CopyTo(
            encoded.AsSpan(16, MailboxCapabilityLimits.AdmissionSlotIdLength));
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(32, 2),
            checked((ushort)admission.Authorization.Length));
        admission.Authorization.Span.CopyTo(
            encoded.AsSpan(MailboxCapabilityLimits.FixedAdmissionHeaderLength));
        return encoded;
    }

    private static MailboxFreeAdmissionSlot DecodeAdmission(ReadOnlySpan<byte> encoded)
    {
        if (!encoded[..AdmissionMagic.Length].SequenceEqual(AdmissionMagic) ||
            encoded[4] != Version ||
            encoded[5] != 0 ||
            encoded[34] != 0 ||
            encoded[35] != 0)
        {
            throw Error(MailboxCapabilityError.InvalidAdmission, "The free-admission framing is invalid.");
        }

        var authorizationLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(32, 2));
        if (authorizationLength is
                < MailboxCapabilityLimits.MinimumAdmissionAuthorizationLength or
                > MailboxCapabilityLimits.MaximumAdmissionAuthorizationLength ||
            encoded.Length != MailboxCapabilityLimits.FixedAdmissionHeaderLength + authorizationLength)
        {
            throw Error(MailboxCapabilityError.InvalidAdmission, "The free-admission length is invalid.");
        }

        var admission = new MailboxFreeAdmissionSlot
        {
            SlotId = encoded.Slice(16, MailboxCapabilityLimits.AdmissionSlotIdLength).ToArray(),
            ValidFromBucket = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(8, 4)),
            ValidUntilBucket = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(12, 4)),
            UseLimit = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(6, 2)),
            Authorization = encoded[MailboxCapabilityLimits.FixedAdmissionHeaderLength..].ToArray()
        };
        ValidateAdmission(admission);
        return admission;
    }

    private static void ValidateAdmission(MailboxFreeAdmissionSlot admission)
    {
        if (admission.SlotId.Length != MailboxCapabilityLimits.AdmissionSlotIdLength ||
            admission.UseLimit == 0 ||
            admission.ValidFromBucket >= admission.ValidUntilBucket ||
            admission.Authorization.Length is
                < MailboxCapabilityLimits.MinimumAdmissionAuthorizationLength or
                > MailboxCapabilityLimits.MaximumAdmissionAuthorizationLength)
        {
            throw Error(
                MailboxCapabilityError.InvalidAdmission,
                "The free-admission slot is outside canonical bounds.");
        }
    }

    private static MailboxCapabilityDomain GetDomain(MailboxDomainValue value) =>
        value switch
        {
            RotatingDepositCapability => MailboxCapabilityDomain.Deposit,
            RotatingRetrieveCapability => MailboxCapabilityDomain.Retrieve,
            OpaquePlacementKey => MailboxCapabilityDomain.Placement,
            _ => throw Error(
                MailboxCapabilityError.InvalidDomainValue,
                "The mailbox domain value runtime type is unsupported.")
        };

    private static MailboxCapabilityException Error(
        MailboxCapabilityError error,
        string message) =>
        new(error, message);
}
