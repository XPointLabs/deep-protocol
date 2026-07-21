using Deep.Protocol.DeepExtension.Membership;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.SelfHostedProfiles;

public enum ProfileCarrierTransitionDecision
{
    Idempotent = 1,
    EquivalentSameState = 2,
    ForwardSameGenesis = 3,
    ExplicitNetworkSwitchCandidate = 4,
    RollbackRejected = 5,
    ForkRejected = 6,
    TrustRejected = 7
}

public static class ProfileCarrierTransitionVerifier
{
    public static ProfileCarrierTransitionDecision VerifyExact(
        ReadOnlySpan<byte> previousFilePayload,
        ProfileCarrierVerificationOptions previousOptions,
        ReadOnlySpan<byte> candidateFilePayload,
        ProfileCarrierVerificationOptions candidateOptions,
        IMembershipSignatureVerifier verifier) =>
        VerifyCore(
            previousFilePayload,
            previousOptions,
            candidateFilePayload,
            candidateOptions,
            verifier,
            continuityDisposed: null);

    internal static ProfileCarrierTransitionDecision VerifyExact(
        ReadOnlySpan<byte> previousFilePayload,
        ProfileCarrierVerificationOptions previousOptions,
        ReadOnlySpan<byte> candidateFilePayload,
        ProfileCarrierVerificationOptions candidateOptions,
        IMembershipSignatureVerifier verifier,
        Action<bool> continuityDisposed) =>
        VerifyCore(
            previousFilePayload,
            previousOptions,
            candidateFilePayload,
            candidateOptions,
            verifier,
            continuityDisposed);

    private static ProfileCarrierTransitionDecision VerifyCore(
        ReadOnlySpan<byte> previousFilePayload,
        ProfileCarrierVerificationOptions previousOptions,
        ReadOnlySpan<byte> candidateFilePayload,
        ProfileCarrierVerificationOptions candidateOptions,
        IMembershipSignatureVerifier verifier,
        Action<bool>? continuityDisposed)
    {
        if (previousOptions is null || candidateOptions is null || verifier is null)
        {
            return ProfileCarrierTransitionDecision.TrustRejected;
        }

        ProfileCarrierContinuity? previous = null;
        ProfileCarrierContinuity? candidate = null;
        try
        {
            previous = ProfileCarrierVerifier.VerifyContinuityExact(
                previousFilePayload,
                previousOptions,
                verifier,
                continuityDisposed);
            candidate = ProfileCarrierVerifier.VerifyContinuityExact(
                candidateFilePayload,
                candidateOptions,
                verifier,
                continuityDisposed);

            if (previousFilePayload.SequenceEqual(candidateFilePayload))
            {
                return ProfileCarrierTransitionDecision.Idempotent;
            }

            if (!string.Equals(
                    previous.GenesisFingerprint,
                    candidate.GenesisFingerprint,
                    StringComparison.Ordinal))
            {
                return ProfileCarrierTransitionDecision.ExplicitNetworkSwitchCandidate;
            }

            if (candidate.DelegationSequence != previous.DelegationSequence)
            {
                // DPF1 v1 P04 verification admits only the represented
                // genesis-rooted delegation step. This branch is defensive for
                // a future parser and is not a rotation policy.
                return candidate.DelegationSequence < previous.DelegationSequence
                    ? ProfileCarrierTransitionDecision.RollbackRejected
                    : ProfileCarrierTransitionDecision.ForkRejected;
            }
            if (!previous.DelegationCommitment.AsSpan()
                    .SequenceEqual(candidate.DelegationCommitment))
            {
                return ProfileCarrierTransitionDecision.ForkRejected;
            }

            var sharedCount = Math.Min(
                previous.Bridges.Length,
                candidate.Bridges.Length);
            for (var index = 0; index < sharedCount; index++)
            {
                if (previous.Bridges[index].Sequence != candidate.Bridges[index].Sequence ||
                    !previous.Bridges[index].Commitment.AsSpan()
                        .SequenceEqual(candidate.Bridges[index].Commitment))
                {
                    return ProfileCarrierTransitionDecision.ForkRejected;
                }
            }

            if (candidate.Bridges.Length < previous.Bridges.Length)
            {
                return ProfileCarrierTransitionDecision.RollbackRejected;
            }
            if (candidate.Bridges.Length > previous.Bridges.Length)
            {
                return ProfileCarrierTransitionDecision.ForwardSameGenesis;
            }

            return ProfileCarrierTransitionDecision.EquivalentSameState;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return ProfileCarrierTransitionDecision.TrustRejected;
        }
        finally
        {
            candidate?.Dispose();
            previous?.Dispose();
        }
    }
}

internal sealed class ProfileCarrierContinuity : IDisposable
{
    private ulong delegationSequence;
    private int disposed;
    private readonly Action<bool>? continuityDisposed;

    public ProfileCarrierContinuity(
        string genesisFingerprint,
        ulong delegationSequence,
        byte[] delegationCommitment,
        ProfileCarrierBridgeContinuity[] bridges,
        Action<bool>? continuityDisposed)
    {
        GenesisFingerprint = genesisFingerprint;
        this.delegationSequence = delegationSequence;
        DelegationCommitment = delegationCommitment;
        Bridges = bridges;
        this.continuityDisposed = continuityDisposed;
    }

    public string GenesisFingerprint { get; }

    public ulong DelegationSequence => delegationSequence;

    public byte[] DelegationCommitment { get; }

    public ProfileCarrierBridgeContinuity[] Bridges { get; }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        delegationSequence = 0;
        CryptographicOperations.ZeroMemory(DelegationCommitment);
        foreach (var bridge in Bridges)
        {
            bridge.Clear();
        }

        continuityDisposed?.Invoke(
            DelegationSequence == 0 &&
            DelegationCommitment.All(static value => value == 0) &&
            Bridges.All(static value => value.IsCleared));
    }
}

internal sealed class ProfileCarrierBridgeContinuity
{
    private ulong sequence;

    public ProfileCarrierBridgeContinuity(ulong sequence, byte[] commitment)
    {
        this.sequence = sequence;
        Commitment = commitment;
    }

    public ulong Sequence => sequence;

    public byte[] Commitment { get; }

    public bool IsCleared =>
        sequence == 0 && Commitment.All(static value => value == 0);

    public void Clear()
    {
        sequence = 0;
        CryptographicOperations.ZeroMemory(Commitment);
    }
}
