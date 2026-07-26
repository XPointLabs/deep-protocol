using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxAuthenticatedCapabilityCodec
{
    private const byte Version = 2;
    private const int GrantUnsignedLength = 208;
    private const int PresentationUnsignedLength = 344;
    private static ReadOnlySpan<byte> GrantMagic => "MCG2"u8;
    private static ReadOnlySpan<byte> PresentationMagic => "MCP2"u8;

    public static byte[] EncodeGrant(MailboxAuthenticatedGrant grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        ValidateGrant(grant, requireSignature: true);
        var output = EncodeUnsignedGrant(grant);
        grant.IssuerSignature.Span.CopyTo(output.AsSpan(GrantUnsignedLength));
        return output;
    }

    public static MailboxAuthenticatedGrant DecodeGrant(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != MailboxAuthenticatedCapabilityLimits.GrantLength)
            throw Error(MailboxAuthenticatedCapabilityError.InvalidLength, "MCG2 must have its exact fixed length.");
        if (!encoded[..4].SequenceEqual(GrantMagic))
            throw Error(MailboxAuthenticatedCapabilityError.InvalidMagic, "MCG2 magic is invalid.");
        if (encoded[4] != Version)
            throw Error(MailboxAuthenticatedCapabilityError.UnsupportedVersion, "MCG2 version is unsupported.");
        if (encoded[7] != 0)
            throw Error(MailboxAuthenticatedCapabilityError.ReservedFieldNotZero, "MCG2 reserved byte must be zero.");

        var grant = new MailboxAuthenticatedGrant
        {
            Domain = (MailboxCapabilityDomain)encoded[5],
            Lifecycle = (MailboxCapabilityLifecycle)encoded[6],
            NetworkId = encoded.Slice(8, 16).ToArray(),
            Epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(24, 8)),
            Generation = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(32, 8)),
            Serial = encoded.Slice(40, 16).ToArray(),
            NotBeforeUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(56, 8)),
            ExpiresAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(64, 8)),
            OverlapUntilUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(72, 8)),
            PlacementCommitment = encoded.Slice(80, 32).ToArray(),
            MembershipCommitment = encoded.Slice(112, 32).ToArray(),
            IssuerPublicKey = encoded.Slice(144, 32).ToArray(),
            HolderPublicKey = encoded.Slice(176, 32).ToArray(),
            IssuerSignature = encoded.Slice(208, 64).ToArray()
        };
        ValidateGrant(grant, requireSignature: true);
        return grant;
    }

    public static byte[] EncodePresentation(MailboxAuthenticatedPresentation presentation)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        ValidateBinding(new MailboxAuthenticatedRequestBinding(
            presentation.Operation,
            presentation.OperationId,
            presentation.RequestDigest));
        if (presentation.ReplayCounter == 0 ||
            presentation.HolderSignature.Length != MailboxAuthenticatedCapabilityLimits.SignatureLength)
            throw Error(MailboxAuthenticatedCapabilityError.InvalidField, "MCP2 replay/signature fields are invalid.");
        var grant = EncodeGrant(presentation.Grant);
        var output = EncodeUnsignedPresentation(presentation, grant);
        presentation.HolderSignature.Span.CopyTo(output.AsSpan(PresentationUnsignedLength));
        return output;
    }

    public static MailboxAuthenticatedPresentation DecodePresentation(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != MailboxAuthenticatedCapabilityLimits.PresentationLength)
            throw Error(MailboxAuthenticatedCapabilityError.InvalidLength, "MCP2 must have its exact fixed length.");
        if (!encoded[..4].SequenceEqual(PresentationMagic))
            throw Error(MailboxAuthenticatedCapabilityError.InvalidMagic, "MCP2 magic is invalid.");
        if (encoded[4] != Version)
            throw Error(MailboxAuthenticatedCapabilityError.UnsupportedVersion, "MCP2 version is unsupported.");
        if (encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(66, 6).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(MailboxAuthenticatedCapabilityError.ReservedFieldNotZero, "MCP2 reserved bytes must be zero.");
        if (BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(64, 2)) !=
            MailboxAuthenticatedCapabilityLimits.GrantLength)
            throw Error(MailboxAuthenticatedCapabilityError.InvalidLength, "MCP2 embedded grant length is invalid.");

        var presentation = new MailboxAuthenticatedPresentation
        {
            Operation = (MailboxAuthenticatedOperation)encoded[5],
            OperationId = encoded.Slice(8, 16).ToArray(),
            ReplayCounter = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(24, 8)),
            RequestDigest = encoded.Slice(32, 32).ToArray(),
            Grant = DecodeGrant(encoded.Slice(72, MailboxAuthenticatedCapabilityLimits.GrantLength)),
            HolderSignature = encoded.Slice(PresentationUnsignedLength, 64).ToArray()
        };
        ValidateBinding(new MailboxAuthenticatedRequestBinding(
            presentation.Operation,
            presentation.OperationId,
            presentation.RequestDigest));
        if (presentation.ReplayCounter == 0 || IsAllZero(presentation.HolderSignature.Span))
            throw Error(MailboxAuthenticatedCapabilityError.InvalidField, "MCP2 replay/signature fields are invalid.");
        ValidateOperationDomain(presentation.Operation, presentation.Grant.Domain);
        return presentation;
    }

    public static byte[] GetGrantSigningBytes(MailboxAuthenticatedGrant grant)
    {
        ValidateGrant(grant, requireSignature: false);
        var tag = GrantTag(grant.Domain);
        return [.. tag, .. EncodeUnsignedGrant(grant).AsSpan(0, GrantUnsignedLength)];
    }

    public static byte[] GetPresentationSigningBytes(MailboxAuthenticatedPresentation presentation)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        var grant = EncodeGrant(presentation.Grant);
        var unsigned = EncodeUnsignedPresentation(presentation, grant);
        return [.. OperationTag(presentation.Operation), .. unsigned.AsSpan(0, PresentationUnsignedLength)];
    }

    public static VerifiedMailboxAuthenticatedCapability Verify(
        ReadOnlySpan<byte> encoded,
        MailboxAuthenticatedRequestBinding expectedBinding,
        MailboxAuthenticatedVerificationPolicy policy,
        IMailboxAuthenticatedCapabilityCrypto crypto,
        IMailboxCapabilityRevocationSource revocations,
        IMailboxCapabilityReplayJournal replayJournal)
    {
        ArgumentNullException.ThrowIfNull(expectedBinding);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(crypto);
        ArgumentNullException.ThrowIfNull(revocations);
        ArgumentNullException.ThrowIfNull(replayJournal);
        ValidateBinding(expectedBinding);
        ValidatePolicy(policy);
        var presentation = DecodePresentation(encoded);
        var grant = presentation.Grant;

        if (presentation.Operation != expectedBinding.Operation ||
            !FixedEquals(presentation.OperationId.Span, expectedBinding.OperationId.Span) ||
            !FixedEquals(presentation.RequestDigest.Span, expectedBinding.RequestDigest.Span))
            throw Error(MailboxAuthenticatedCapabilityError.BindingMismatch, "MCP2 does not match the exact outer request.");
        if (!FixedEquals(grant.NetworkId.Span, policy.NetworkId.Span) ||
            grant.Epoch != policy.Epoch ||
            !FixedEquals(grant.PlacementCommitment.Span, policy.PlacementCommitment.Span) ||
            !FixedEquals(grant.MembershipCommitment.Span, policy.MembershipCommitment.Span))
            throw Error(MailboxAuthenticatedCapabilityError.BindingMismatch, "MCG2 authority context does not match.");
        if (grant.Generation < policy.MinimumGeneration)
            throw Error(MailboxAuthenticatedCapabilityError.GenerationRejected, "MCG2 generation is below the floor.");
        if (policy.NowUnixSeconds < grant.NotBeforeUnixSeconds ||
            policy.NowUnixSeconds > grant.ExpiresAtUnixSeconds ||
            grant.Lifecycle == MailboxCapabilityLifecycle.Overlap &&
            policy.NowUnixSeconds > grant.OverlapUntilUnixSeconds)
            throw Error(MailboxAuthenticatedCapabilityError.OutsideValidityWindow, "MCG2 is outside its validity window.");
        var authority = policy.TrustedIssuers.FirstOrDefault(candidate =>
            candidate.PublicKey.Length == 32 &&
            FixedEquals(candidate.PublicKey.Span, grant.IssuerPublicKey.Span) &&
            candidate.Domain == grant.Domain);
        if (authority is null)
            throw Error(MailboxAuthenticatedCapabilityError.UntrustedIssuer, "MCG2 issuer is not trusted for this mailbox.");
        if (authority.AllowedLifecycle != grant.Lifecycle ||
            grant.Generation < authority.MinimumGeneration ||
            grant.Generation > authority.MaximumGeneration ||
            grant.NotBeforeUnixSeconds < authority.ValidFromUnixSeconds ||
            grant.ExpiresAtUnixSeconds > authority.ValidUntilUnixSeconds)
            throw Error(MailboxAuthenticatedCapabilityError.UntrustedIssuer, "MCG2 exceeds issuer rotation authority.");
        if (revocations.IsRevoked(new MailboxCapabilityRevocationQuery
        {
            IssuerPublicKey = grant.IssuerPublicKey.ToArray(),
            Serial = grant.Serial.ToArray(),
            Domain = grant.Domain,
            Generation = grant.Generation,
            Epoch = grant.Epoch,
            MembershipCommitment = grant.MembershipCommitment.ToArray()
        }))
            throw Error(MailboxAuthenticatedCapabilityError.Revoked, "MCG2 has been revoked.");
        if (!crypto.VerifyIssuer(
                grant.IssuerPublicKey.Span,
                GetGrantSigningBytes(grant),
                grant.IssuerSignature.Span))
            throw Error(MailboxAuthenticatedCapabilityError.InvalidIssuerSignature, "MCG2 issuer signature is invalid.");
        if (!crypto.VerifyHolder(
                grant.HolderPublicKey.Span,
                GetPresentationSigningBytes(presentation),
                presentation.HolderSignature.Span))
            throw Error(MailboxAuthenticatedCapabilityError.InvalidHolderSignature, "MCP2 holder signature is invalid.");

        var claim = new MailboxCapabilityAtomicReplayClaim
        {
            ClaimDigest = crypto.Digest(encoded).ToArray(),
            IssuerPublicKey = grant.IssuerPublicKey.ToArray(),
            Serial = grant.Serial.ToArray(),
            Epoch = grant.Epoch,
            Generation = grant.Generation,
            Operation = presentation.Operation,
            OperationId = presentation.OperationId.ToArray(),
            ReplayCounter = presentation.ReplayCounter,
            RequestDigest = presentation.RequestDigest.ToArray()
        };
        var evaluation = replayJournal.EvaluateAndReserve(claim) ??
            throw Error(MailboxAuthenticatedCapabilityError.InvalidReplayEvaluation, "Replay journal returned null.");
        if (evaluation.CachedOutcome.Length > MailboxAuthenticatedCapabilityLimits.MaximumCachedOutcomeLength)
            throw Error(MailboxAuthenticatedCapabilityError.InvalidReplayEvaluation, "Cached replay outcome is too large.");

        var disposition = evaluation.State switch
        {
            MailboxCapabilityAtomicReplayState.NewReserved when evaluation.CachedOutcome.IsEmpty =>
                MailboxAuthenticatedReplayDisposition.NewReserved,
            MailboxCapabilityAtomicReplayState.PendingSame when evaluation.CachedOutcome.IsEmpty =>
                MailboxAuthenticatedReplayDisposition.InFlight,
            MailboxCapabilityAtomicReplayState.CompletedSame when !evaluation.CachedOutcome.IsEmpty =>
                MailboxAuthenticatedReplayDisposition.IdempotentCompleted,
            MailboxCapabilityAtomicReplayState.StaleReplay when evaluation.CachedOutcome.IsEmpty =>
                throw Error(MailboxAuthenticatedCapabilityError.ReplayRejected, "MCP2 replay is stale."),
            MailboxCapabilityAtomicReplayState.Conflict when evaluation.CachedOutcome.IsEmpty =>
                throw Error(MailboxAuthenticatedCapabilityError.ReplayConflict, "MCP2 replay tuple conflicts."),
            _ => throw Error(
                MailboxAuthenticatedCapabilityError.InvalidReplayEvaluation,
                "Replay state and cached outcome are inconsistent.")
        };
        return new VerifiedMailboxAuthenticatedCapability
        {
            Grant = grant,
            Binding = new MailboxAuthenticatedRequestBinding(
                expectedBinding.Operation,
                expectedBinding.OperationId,
                expectedBinding.RequestDigest,
                expectedBinding.CanonicalRequest),
            ReplayDisposition = disposition,
            ReplayClaim = claim,
            CachedOutcome = evaluation.CachedOutcome.ToArray()
        };
    }

    private static byte[] EncodeUnsignedGrant(MailboxAuthenticatedGrant grant)
    {
        var output = new byte[MailboxAuthenticatedCapabilityLimits.GrantLength];
        GrantMagic.CopyTo(output);
        output[4] = Version;
        output[5] = (byte)grant.Domain;
        output[6] = (byte)grant.Lifecycle;
        grant.NetworkId.Span.CopyTo(output.AsSpan(8));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(24), grant.Epoch);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(32), grant.Generation);
        grant.Serial.Span.CopyTo(output.AsSpan(40));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(56), grant.NotBeforeUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(64), grant.ExpiresAtUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(72), grant.OverlapUntilUnixSeconds);
        grant.PlacementCommitment.Span.CopyTo(output.AsSpan(80));
        grant.MembershipCommitment.Span.CopyTo(output.AsSpan(112));
        grant.IssuerPublicKey.Span.CopyTo(output.AsSpan(144));
        grant.HolderPublicKey.Span.CopyTo(output.AsSpan(176));
        return output;
    }

    private static byte[] EncodeUnsignedPresentation(
        MailboxAuthenticatedPresentation presentation,
        ReadOnlySpan<byte> grant)
    {
        var output = new byte[MailboxAuthenticatedCapabilityLimits.PresentationLength];
        PresentationMagic.CopyTo(output);
        output[4] = Version;
        output[5] = (byte)presentation.Operation;
        presentation.OperationId.Span.CopyTo(output.AsSpan(8));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(24), presentation.ReplayCounter);
        presentation.RequestDigest.Span.CopyTo(output.AsSpan(32));
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(64), MailboxAuthenticatedCapabilityLimits.GrantLength);
        grant.CopyTo(output.AsSpan(72));
        return output;
    }

    private static void ValidateGrant(MailboxAuthenticatedGrant grant, bool requireSignature)
    {
        ArgumentNullException.ThrowIfNull(grant);
        if (grant.Domain is not (MailboxCapabilityDomain.Deposit or MailboxCapabilityDomain.Retrieve) ||
            grant.Lifecycle is not (MailboxCapabilityLifecycle.Active or MailboxCapabilityLifecycle.Overlap))
            throw Error(MailboxAuthenticatedCapabilityError.InvalidEnum, "MCG2 domain/lifecycle is invalid.");
        ValidateNonzero(grant.NetworkId.Span, 16);
        ValidateNonzero(grant.Serial.Span, 16);
        ValidateNonzero(grant.PlacementCommitment.Span, 32);
        ValidateNonzero(grant.MembershipCommitment.Span, 32);
        ValidateNonzero(grant.IssuerPublicKey.Span, 32);
        ValidateNonzero(grant.HolderPublicKey.Span, 32);
        if (grant.Epoch == 0 || grant.Generation == 0 ||
            grant.NotBeforeUnixSeconds >= grant.ExpiresAtUnixSeconds)
            throw Error(MailboxAuthenticatedCapabilityError.InvalidField, "MCG2 epoch/generation/window is invalid.");
        if (grant.Lifecycle == MailboxCapabilityLifecycle.Overlap)
        {
            if (grant.OverlapUntilUnixSeconds <= grant.NotBeforeUnixSeconds ||
                grant.OverlapUntilUnixSeconds > grant.ExpiresAtUnixSeconds)
                throw Error(MailboxAuthenticatedCapabilityError.InvalidField, "MCG2 overlap is invalid.");
        }
        else if (grant.OverlapUntilUnixSeconds != 0)
            throw Error(MailboxAuthenticatedCapabilityError.InvalidField, "Active MCG2 cannot carry overlap.");
        if (requireSignature)
            ValidateNonzero(grant.IssuerSignature.Span, 64);
        else if (!grant.IssuerSignature.IsEmpty && grant.IssuerSignature.Length != 64)
            throw Error(MailboxAuthenticatedCapabilityError.InvalidField, "MCG2 signature length is invalid.");
    }

    private static void ValidateBinding(MailboxAuthenticatedRequestBinding binding)
    {
        if (binding.Operation is not (
                MailboxAuthenticatedOperation.Store or
                MailboxAuthenticatedOperation.Retrieve or
                MailboxAuthenticatedOperation.Ack))
            throw Error(MailboxAuthenticatedCapabilityError.InvalidEnum, "MCP2 operation is invalid.");
        ValidateNonzero(binding.OperationId.Span, 16);
        ValidateNonzero(binding.RequestDigest.Span, 32);
    }

    private static void ValidatePolicy(MailboxAuthenticatedVerificationPolicy policy)
    {
        ValidateNonzero(policy.NetworkId.Span, 16);
        ValidateNonzero(policy.PlacementCommitment.Span, 32);
        ValidateNonzero(policy.MembershipCommitment.Span, 32);
        if (policy.Epoch == 0 || policy.MinimumGeneration == 0 ||
            policy.TrustedIssuers is null or { Count: 0 } or { Count: > 8 })
            throw Error(MailboxAuthenticatedCapabilityError.InvalidField, "MCP2 verification policy is invalid.");
        foreach (var issuer in policy.TrustedIssuers)
        {
            if (issuer is null ||
                issuer.PublicKey.Length != 32 ||
                issuer.PublicKey.Span.IndexOfAnyExcept((byte)0) < 0 ||
                issuer.Domain is not (MailboxCapabilityDomain.Deposit or MailboxCapabilityDomain.Retrieve) ||
                issuer.AllowedLifecycle is not (
                    MailboxCapabilityLifecycle.Active or MailboxCapabilityLifecycle.Overlap) ||
                issuer.MinimumGeneration == 0 ||
                issuer.MinimumGeneration > issuer.MaximumGeneration ||
                issuer.ValidFromUnixSeconds >= issuer.ValidUntilUnixSeconds)
                throw Error(MailboxAuthenticatedCapabilityError.InvalidField, "Issuer authority is invalid.");
        }
        if (policy.TrustedIssuers
            .GroupBy(static issuer =>
                $"{(byte)issuer.Domain}:{Convert.ToHexString(issuer.PublicKey.Span)}",
                StringComparer.Ordinal)
            .Any(static group => group.Count() != 1))
            throw Error(MailboxAuthenticatedCapabilityError.InvalidField, "Issuer authorities are duplicated.");
    }

    private static void ValidateOperationDomain(
        MailboxAuthenticatedOperation operation,
        MailboxCapabilityDomain domain)
    {
        if (operation == MailboxAuthenticatedOperation.Store
                ? domain != MailboxCapabilityDomain.Deposit
                : domain != MailboxCapabilityDomain.Retrieve)
            throw Error(MailboxAuthenticatedCapabilityError.InvalidDomainForOperation, "Capability domain cannot authorize this operation.");
    }

    private static ReadOnlySpan<byte> GrantTag(MailboxCapabilityDomain domain) =>
        domain switch
        {
            MailboxCapabilityDomain.Deposit => "DEEP-MCG2-DEP\0\0\0"u8,
            MailboxCapabilityDomain.Retrieve => "DEEP-MCG2-RET\0\0\0"u8,
            _ => throw Error(MailboxAuthenticatedCapabilityError.InvalidEnum, "MCG2 has no signing tag.")
        };

    private static ReadOnlySpan<byte> OperationTag(MailboxAuthenticatedOperation operation) =>
        operation switch
        {
            MailboxAuthenticatedOperation.Store => "DEEP-MCP2-STR\0\0\0"u8,
            MailboxAuthenticatedOperation.Retrieve => "DEEP-MCP2-GET\0\0\0"u8,
            MailboxAuthenticatedOperation.Ack => "DEEP-MCP2-ACK\0\0\0"u8,
            _ => throw Error(MailboxAuthenticatedCapabilityError.InvalidEnum, "MCP2 has no signing tag.")
        };

    private static void ValidateNonzero(ReadOnlySpan<byte> value, int length)
    {
        if (value.Length != length || IsAllZero(value))
            throw Error(MailboxAuthenticatedCapabilityError.InvalidField, "A fixed field is invalid.");
    }

    private static bool IsAllZero(ReadOnlySpan<byte> value) =>
        value.IndexOfAnyExcept((byte)0) < 0;

    private static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static MailboxAuthenticatedCapabilityException Error(
        MailboxAuthenticatedCapabilityError error,
        string message) => new(error, message);
}
