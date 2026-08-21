namespace Deep.Protocol.DeepNative;

internal static class RecoveryTestAccess
{
    internal static ValueTask<RecoveryCandidatePlan> OpenUnverifiedCandidateAsync(
        ReadOnlyMemory<byte> canonicalDrc1,
        RecoveryProtectorProvider provider,
        RecoveryNonceLatch nonceLatch,
        CancellationToken cancellationToken) =>
        RecoveryEngine.OpenUnverifiedCandidateForTestsAsync(
            canonicalDrc1, provider, nonceLatch, cancellationToken);
}
