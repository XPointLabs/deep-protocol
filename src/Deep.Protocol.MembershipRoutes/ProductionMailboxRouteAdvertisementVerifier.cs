using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

public static class ProductionMailboxRouteCertificateVerifier
{
    public static VerifiedProductionMailboxRouteCertificate Verify(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority verifiedAuthority,
        ulong nowUnixSeconds,
        uint clockSkewSeconds,
        IProductionMailboxRouteSignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(verifiedAuthority);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (encoded.Length != ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidLength,
                "PRC1 canonical length is invalid.");
        ValidateClock(nowUnixSeconds, clockSkewSeconds);
        var frozenBytes = encoded.ToArray();
        var certificate = ProductionMailboxRouteAdvertisementCodec.DecodeCertificate(frozenBytes);
        var authority = verifiedAuthority.Authority;
        var authorityHash = verifiedAuthority.CanonicalAuthorityHash.ToArray();
        VerifyLiveAuthority(authority, nowUnixSeconds, clockSkewSeconds);
        Equal(certificate.NetworkId.Span, authority.NetworkId.Span,
            ProductionMailboxRouteAdvertisementError.AuthorityMismatch, "PRC1 network mismatch.");
        Equal(certificate.CanonicalAuthorityHash.Span, authorityHash,
            ProductionMailboxRouteAdvertisementError.AuthorityMismatch, "PRC1 authority hash mismatch.");
        Equal(certificate.IssuerEd25519PublicKey.Span, authority.MailboxIssuerEd25519PublicKey.Span,
            ProductionMailboxRouteAdvertisementError.AuthorityMismatch, "PRC1 issuer key mismatch.");
        if (certificate.AuthorityGeneration != authority.AuthorityGeneration)
            throw Error(ProductionMailboxRouteAdvertisementError.AuthorityMismatch,
                "PRC1 authority generation mismatch.");
        VerifyWindow(certificate.IssuedAtUnixSeconds, certificate.ExpiresAtUnixSeconds,
            nowUnixSeconds, clockSkewSeconds, ProtocolMagic.PRC1);
        if (certificate.IssuedAtUnixSeconds < authority.CurrentEpoch.NotBeforeUnixSeconds ||
            certificate.ExpiresAtUnixSeconds > authority.CurrentEpoch.NotAfterUnixSeconds ||
            certificate.IssuedAtUnixSeconds < authority.MrXApproval.RolloutNotBeforeUnixSeconds ||
            certificate.ExpiresAtUnixSeconds > authority.MrXApproval.RolloutNotAfterUnixSeconds ||
            certificate.IssuedAtUnixSeconds < authority.Revocation.IssuedAtUnixSeconds ||
            certificate.ExpiresAtUnixSeconds > authority.Revocation.ExpiresAtUnixSeconds)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidValidityWindow,
                "PRC1 lifetime exceeds the verified authority envelope.");
        var expectedSelectionInput = ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(
            new BlindedPlacementId(certificate.BlindedPlacementId.Span));
        Equal(certificate.SelectionInputCommitment.Span, expectedSelectionInput,
            ProductionMailboxRouteAdvertisementError.InvalidRoute,
            "PRC1 selection input does not match its blinded placement ID.");
        var frozenPublicKey = certificate.IssuerEd25519PublicKey.ToArray();
        var frozenSignature = certificate.IssuerSignature.ToArray();
        var signingBytes = ProductionMailboxRouteAdvertisementCodec.GetCertificateSigningBytes(certificate);
        if (!signatureVerifier.Verify(frozenPublicKey, signingBytes, frozenSignature))
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidIssuerSignature,
                "PRC1 issuer signature is invalid.");
        return new VerifiedProductionMailboxRouteCertificate(certificate, SHA256.HashData(frozenBytes));
    }

    internal static void ValidateClock(ulong now, uint skew)
    {
        if (now == 0 || skew > ProductionMailboxRouteAdvertisementConstants.MaximumClockSkewSeconds)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidField,
                "Route verification time is incomplete or unsafe.");
    }

    internal static void VerifyLiveAuthority(ProductionMailboxAuthority authority, ulong now, uint skew)
    {
        if (authority.DevelopmentOnly || authority.Environment != ProductionMailboxAuthorityEnvironment.Production)
            throw Error(ProductionMailboxRouteAdvertisementError.AuthorityMismatch,
                "Development mailbox authority is forbidden.");
        VerifyWindow(authority.CurrentEpoch.NotBeforeUnixSeconds, authority.CurrentEpoch.NotAfterUnixSeconds,
            now, skew, "authority current epoch");
        VerifyWindow(authority.MrXApproval.RolloutNotBeforeUnixSeconds,
            authority.MrXApproval.RolloutNotAfterUnixSeconds, now, skew, "Mr. X rollout");
        VerifyWindow(authority.Revocation.IssuedAtUnixSeconds, authority.Revocation.ExpiresAtUnixSeconds,
            now, skew, "authority revocation snapshot");
    }

    internal static void VerifyWindow(ulong from, ulong until, ulong now, uint skew, string name)
    {
        if (now < from && from - now > skew)
            throw Error(ProductionMailboxRouteAdvertisementError.NotYetValid, $"{name} is not yet valid.");
        if (now > until && now - until > skew)
            throw Error(ProductionMailboxRouteAdvertisementError.Expired, $"{name} has expired.");
    }

    internal static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected,
        ProductionMailboxRouteAdvertisementError error, string message)
    {
        if (actual.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw Error(error, message);
    }

    internal static ProductionMailboxRouteAdvertisementException Error(
        ProductionMailboxRouteAdvertisementError error,
        string message) => new(error, message);
}

public static class ProductionMailboxRouteAdvertisementVerifier
{
    public static VerifiedProductionMailboxRouteAdvertisement Verify(
        ReadOnlySpan<byte> encoded,
        VerifiedProductionMailboxAuthority verifiedAuthority,
        ProductionMailboxRouteAdvertisementVerificationContext context,
        IProductionMailboxRouteSignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(verifiedAuthority);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (encoded.Length != ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength)
            throw ProductionMailboxRouteCertificateVerifier.Error(
                ProductionMailboxRouteAdvertisementError.InvalidLength,
                "PRA1 canonical length is invalid.");
        if (context.ExpectedRouteDomainHash.Length
                != ProductionMailboxRouteAdvertisementConstants.HashLength
            || context.LastAcceptedAdvertisementHash.Length
                != ProductionMailboxRouteAdvertisementConstants.HashLength)
            throw ProductionMailboxRouteCertificateVerifier.Error(
                ProductionMailboxRouteAdvertisementError.InvalidField,
                "PRA1 verification context hash length is invalid.");
        var frozenRouteDomainHash = context.ExpectedRouteDomainHash.ToArray();
        var frozenLastHash = context.LastAcceptedAdvertisementHash.ToArray();
        ValidateContext(context.LastAcceptedSequence, frozenLastHash,
            frozenRouteDomainHash, context.NowUnixSeconds, context.ClockSkewSeconds);
        var frozenBytes = encoded.ToArray();
        var advertisement = ProductionMailboxRouteAdvertisementCodec.DecodeAdvertisement(frozenBytes);
        _ = ProductionMailboxRouteCertificateVerifier.Verify(
            ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(advertisement.Certificate),
            verifiedAuthority, context.NowUnixSeconds, context.ClockSkewSeconds, signatureVerifier);
        ProductionMailboxRouteCertificateVerifier.VerifyWindow(
            advertisement.PublishedAtUnixSeconds, advertisement.ExpiresAtUnixSeconds,
            context.NowUnixSeconds, context.ClockSkewSeconds, ProtocolMagic.PRA1);
        var routeDomainHash = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(
            advertisement.Certificate);
        ProductionMailboxRouteCertificateVerifier.Equal(
            routeDomainHash, frozenRouteDomainHash,
            ProductionMailboxRouteAdvertisementError.InvalidRoute,
            "PRA1 does not match the caller-selected durable route domain.");
        var canonicalHash = SHA256.HashData(frozenBytes);
        var frozenOwnerKey = advertisement.Certificate.MailboxOwnerEd25519PublicKey.ToArray();
        var frozenOwnerSignature = advertisement.OwnerSignature.ToArray();
        var signingBytes = ProductionMailboxRouteAdvertisementCodec.GetAdvertisementSigningBytes(advertisement);
        if (!signatureVerifier.Verify(frozenOwnerKey, signingBytes, frozenOwnerSignature))
            throw ProductionMailboxRouteCertificateVerifier.Error(
                ProductionMailboxRouteAdvertisementError.InvalidOwnerSignature,
                "PRA1 owner signature is invalid.");
        if (advertisement.Sequence < context.LastAcceptedSequence)
            throw ProductionMailboxRouteCertificateVerifier.Error(
                ProductionMailboxRouteAdvertisementError.AdvertisementRollback,
                "PRA1 sequence rolled back.");
        if (advertisement.Sequence == context.LastAcceptedSequence &&
            !CryptographicOperations.FixedTimeEquals(canonicalHash, frozenLastHash))
            throw ProductionMailboxRouteCertificateVerifier.Error(
                ProductionMailboxRouteAdvertisementError.AdvertisementConflict,
                "PRA1 sequence conflicts with the durably accepted advertisement.");
        return new VerifiedProductionMailboxRouteAdvertisement(advertisement, canonicalHash, routeDomainHash);
    }

    private static void ValidateContext(ulong lastSequence, ReadOnlySpan<byte> lastHash,
        ReadOnlySpan<byte> routeDomainHash, ulong now, uint skew)
    {
        ProductionMailboxRouteCertificateVerifier.ValidateClock(now, skew);
        if (routeDomainHash.Length != ProductionMailboxRouteAdvertisementConstants.HashLength ||
            routeDomainHash.IndexOfAnyExcept((byte)0) < 0)
            throw ProductionMailboxRouteCertificateVerifier.Error(
                ProductionMailboxRouteAdvertisementError.InvalidField,
                "Expected PRA1 route-domain hash is invalid.");
        if (lastHash.Length != ProductionMailboxRouteAdvertisementConstants.HashLength)
            throw ProductionMailboxRouteCertificateVerifier.Error(
                ProductionMailboxRouteAdvertisementError.InvalidField,
                "Last accepted PRA1 hash length is invalid.");
        var hashIsZero = lastHash.IndexOfAnyExcept((byte)0) < 0;
        if ((lastSequence == 0) != hashIsZero)
            throw ProductionMailboxRouteCertificateVerifier.Error(
                ProductionMailboxRouteAdvertisementError.InvalidField,
                "Initial PRA1 state requires sequence zero and an all-zero hash; committed state requires both non-zero.");
    }
}
