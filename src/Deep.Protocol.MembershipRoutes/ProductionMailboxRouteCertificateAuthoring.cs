using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

/// <summary>
/// Capability-scoped fresh PRC1 authoring. A caller supplies no unsigned certificate or signing
/// transcript: both are derived from a sealed enrollment identity and verified live control plane.
/// </summary>
public static class ProductionMailboxRouteCertificateAuthoring
{
    public static VerifiedProductionMailboxRouteCertificateIntent CreateIntent(
        VerifiedProductionMailboxHistoricalRouteAnchor historicalAnchor,
        VerifiedProductionMailboxRouteHistoryCursor currentRoute,
        VerifiedProductionMailboxAuthority currentAuthority,
        VerifiedProductionMailboxRevocationSnapshot currentRevocations,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        ulong nowUnixSeconds,
        uint clockSkewSeconds)
    {
        ArgumentNullException.ThrowIfNull(historicalAnchor);
        ArgumentNullException.ThrowIfNull(currentRoute);
        ArgumentNullException.ThrowIfNull(currentAuthority);
        ArgumentNullException.ThrowIfNull(currentRevocations);
        ProductionMailboxRouteCertificateVerifier.ValidateClock(nowUnixSeconds, clockSkewSeconds);
        var delegation = historicalAnchor.EnrollmentState.Enrollment.Delegation;
        var authority = currentAuthority.Authority;
        var revocations = currentRevocations.Snapshot;
        var anchorCertificate = historicalAnchor.AnchorCertificate.Certificate;
        var checkpoint = currentRoute.Checkpoint.TrustedCheckpoint;
        var currentRol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(
            currentRoute.CanonicalCurrentRouteOriginLkg());
        if (authority.AuthorityGeneration > delegation.MaximumAuthorityGeneration ||
            authority.AuthorityGeneration != revocations.AuthorityGeneration ||
            revocations.RevocationGeneration != authority.Revocation.Generation ||
            !Fixed(authority.NetworkId.Span, delegation.NetworkId.Span) ||
            !Fixed(revocations.NetworkId.Span, delegation.NetworkId.Span) ||
            !Fixed(SHA256.HashData(authority.MrXApprovalEd25519PublicKey.Span),
                delegation.PinnedMrXPublicKeySha256.Span) ||
            !Fixed(currentRevocations.CanonicalSnapshotHash.Span, authority.Revocation.SnapshotHash.Span) ||
            !Fixed(revocations.RevocationHeadHash.Span, authority.Revocation.HeadHash.Span) ||
            !Fixed(currentRoute.Enrollment.CanonicalDelegationHash.Span,
                historicalAnchor.EnrollmentState.Enrollment.CanonicalDelegationHash.Span) ||
            checkpoint.CurrentAuthorityGeneration != authority.AuthorityGeneration ||
            !Fixed(checkpoint.CurrentCanonicalAuthorityHash.Span,
                currentAuthority.CanonicalAuthorityHash.Span) ||
            checkpoint.CurrentRevocationGeneration != revocations.RevocationGeneration ||
            !Fixed(checkpoint.CurrentRevocationHeadHash.Span, revocations.RevocationHeadHash.Span) ||
            !Fixed(checkpoint.CurrentRevocationSnapshotHash.Span,
                currentRevocations.CanonicalSnapshotHash.Span) ||
            !Fixed(checkpoint.CurrentRouteOriginLkgHash.Span,
                ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(currentRol)) ||
            !Fixed(currentRol.NetworkId.Span, delegation.NetworkId.Span) ||
            !Fixed(currentRol.RouteDomainHash.Span, delegation.RouteDomainHash.Span) ||
            !Fixed(anchorCertificate.SelectionInputCommitment.Span,
                delegation.SelectionInputCommitment.Span) ||
            !Fixed(ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(anchorCertificate),
                delegation.RouteDomainHash.Span))
            throw new FormatException("PRC1 intent control plane differs from the sealed enrollment.");
        if (issuedAtUnixSeconds == 0 || expiresAtUnixSeconds <= issuedAtUnixSeconds ||
            expiresAtUnixSeconds - issuedAtUnixSeconds >
                ProductionMailboxRouteAdvertisementConstants.MaximumLifetimeSeconds ||
            issuedAtUnixSeconds < authority.CurrentEpoch.NotBeforeUnixSeconds ||
            expiresAtUnixSeconds > authority.CurrentEpoch.NotAfterUnixSeconds ||
            issuedAtUnixSeconds < authority.MrXApproval.RolloutNotBeforeUnixSeconds ||
            expiresAtUnixSeconds > authority.MrXApproval.RolloutNotAfterUnixSeconds ||
            issuedAtUnixSeconds < revocations.IssuedAtUnixSeconds ||
            expiresAtUnixSeconds > revocations.ExpiresAtUnixSeconds)
            throw new FormatException("PRC1 intent validity is outside the verified control plane.");
        ProductionMailboxRouteCertificateVerifier.VerifyWindow(issuedAtUnixSeconds,
            expiresAtUnixSeconds, nowUnixSeconds, clockSkewSeconds, "PRC1 intent");
        return new(historicalAnchor, currentRoute, currentAuthority, currentRevocations,
            issuedAtUnixSeconds, expiresAtUnixSeconds);
    }

    public static async ValueTask<VerifiedProductionMailboxRouteCertificate> AuthorAsync(
        VerifiedProductionMailboxRouteCertificateIntent intent,
        ProductionMailboxPrc1Signer signer,
        ulong nowUnixSeconds,
        uint clockSkewSeconds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(signer);
        // Rebuild the intent to revalidate its owned sealed sources immediately before callback.
        var checkedIntent = CreateIntent(intent.Anchor, intent.CurrentRoute, intent.Authority, intent.Revocations,
            intent.IssuedAt, intent.ExpiresAt, nowUnixSeconds, clockSkewSeconds);
        var delegation = checkedIntent.Anchor.EnrollmentState.Enrollment.Delegation;
        var authority = checkedIntent.Authority.Authority;
        var certificate = new ProductionMailboxRouteCertificate
        {
            NetworkId = delegation.NetworkId.ToArray(),
            AuthorityGeneration = authority.AuthorityGeneration,
            CanonicalAuthorityHash = checkedIntent.Authority.CanonicalAuthorityHash.ToArray(),
            IssuerEd25519PublicKey = authority.MailboxIssuerEd25519PublicKey.ToArray(),
            MailboxOwnerEd25519PublicKey = delegation.MailboxOwnerEd25519PublicKey.ToArray(),
            BlindedMailboxId = delegation.BlindedMailboxId.ToArray(),
            BlindedPlacementId = delegation.BlindedPlacementId.ToArray(),
            SelectionInputCommitment = delegation.SelectionInputCommitment.ToArray(),
            IssuedAtUnixSeconds = checkedIntent.IssuedAt,
            ExpiresAtUnixSeconds = checkedIntent.ExpiresAt,
            IssuerSignature = new byte[64]
        };
        var signingBytes = ProductionMailboxRouteAdvertisementCodec.GetCertificateSigningBytes(certificate);
        var signature = new byte[64];
        var request = new ProductionMailboxPrc1SigningRequest(signingBytes,
            authority.MailboxIssuerEd25519PublicKey.Span);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var written = await signer(request, signature, cancellationToken).ConfigureAwait(false);
            if (written != 64) throw new FormatException("PRC1 signer must write exactly 64 bytes.");
            var canonical = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
                certificate with { IssuerSignature = signature.ToArray() });
            return ProductionMailboxRouteCertificateVerifier.Verify(canonical,
                checkedIntent.Authority, nowUnixSeconds, clockSkewSeconds,
                new SodiumProductionMailboxRouteSignatureVerifier());
        }
        finally
        {
            request.Clear(); CryptographicOperations.ZeroMemory(signingBytes);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second) =>
        first.Length == second.Length && CryptographicOperations.FixedTimeEquals(first, second);
}
