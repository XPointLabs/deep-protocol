using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Reconstructs a non-forgeable rollback-floor capability only after the persisted
/// ADH1 is re-authenticated against an already verified XPoint authority lineage.
/// Current wall time is intentionally not an input: expiry cannot erase a floor.
/// </summary>
public static class AccountDirectoryProtectedLkgFactory
{
    public static AccountDirectoryProtectedLkg Restore(
        VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> exactPersistedAdh1,
        ReadOnlySpan<byte> expectedAdh1CoreHash) =>
        AccountDirectoryCurrentProofVerifier.RestoreProtectedLkg(
            authority, exactPersistedAdh1, expectedAdh1CoreHash);
}
