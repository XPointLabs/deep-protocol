namespace Deep.Protocol.DeepExtension.MailboxAuthority;

/// <summary>
/// Narrow, verify-only bridge used by the production membership-routes package.
/// It exposes no authoring, signing, recovery, entropy, or secret-key operations.
/// </summary>
public sealed class ProductionMailboxRoutesVerificationFacade
{
    private ProductionMailboxRoutesVerificationFacade()
    {
    }

    public static VerifiedProductionMailboxAuthority VerifyForwardCheckpoint(
        ReadOnlySpan<byte> canonicalAuthority,
        ProductionMailboxAuthorityCheckpointVerificationContext context,
        IProductionMailboxAuthoritySignatureVerifier signatureVerifier) =>
        ProductionMailboxAuthorityVerifier.VerifyForwardCheckpoint(
            canonicalAuthority,
            context,
            signatureVerifier);

    public static void PreflightCanonicalRevocationSnapshot(ReadOnlySpan<byte> canonical) =>
        ProductionMailboxRevocationSnapshotCodec.PreflightCanonical(canonical);
}
