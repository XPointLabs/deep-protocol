using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.MessagingCrypto;

// Internal prospective state only. Never a durable receipt, dispatch or ACK grant.
internal sealed class TripleRatchetBraidRecoveryCandidate : IDisposable
{
    private TripleRatchetState? next;
    internal TripleRatchetBraidRecoveryCandidate(TripleRatchetState? successor, UnverifiedDbr2Record control, bool replay)
    { next = successor; Control = control; IsExactReplay = replay; }
    internal UnverifiedDbr2Record Control { get; }
    internal bool IsExactReplay { get; }
    internal TripleRatchetState TakeNextState() => Interlocked.Exchange(ref next, null) ??
        throw new MessagingCryptoException(MessagingCryptoError.CapabilityConsumed, "Control successor is absent or consumed.");
    public void Dispose() => Interlocked.Exchange(ref next, null)?.Dispose();
}

internal sealed partial class TripleRatchetState
{
    internal bool TryVerifyObsoleteBraidRecoveryControl(ManagedTripleRatchetComponentProvider provider,
        ReadOnlySpan<byte> network, UnverifiedDbr2Record frame)
    {
        ArgumentNullException.ThrowIfNull(provider);
        var ownedNetwork = network.ToArray();
        try
        {
            lock (_lifecycleSync)
            {
                ThrowIfUnavailable();
                return _componentState!.Use(value => provider.TryVerifyObsoleteBraidControl(value, Binding, ownedNetwork, frame));
            }
        }
        finally { CryptographicOperations.ZeroMemory(ownedNetwork); }
    }

    internal TripleRatchetBraidRecoveryCandidate PrepareBraidRecoverySend(
        ManagedTripleRatchetComponentProvider provider, ReadOnlySpan<byte> network, ReadOnlySpan<byte> operation)
    {
        ArgumentNullException.ThrowIfNull(provider);
        var ownedNetwork = network.ToArray(); var ownedOperation = operation.ToArray();
        try
        {
            lock (_lifecycleSync)
            {
                ThrowIfUnavailable();
                using var transition = _componentState!.Use(value =>
                    provider.PrepareBraidControlSend(value, Binding, ownedNetwork, ownedOperation));
                return CopyBraidControlCandidate(transition);
            }
        }
        finally { CryptographicOperations.ZeroMemory(ownedNetwork); CryptographicOperations.ZeroMemory(ownedOperation); }
    }

    internal TripleRatchetBraidRecoveryCandidate PrepareBraidRecoveryReceive(
        ManagedTripleRatchetComponentProvider provider, ReadOnlySpan<byte> network, ReadOnlySpan<byte> exactControl)
    {
        ArgumentNullException.ThrowIfNull(provider);
        var frame = Dbr2Codec.Decode(exactControl);
        var ownedNetwork = network.ToArray();
        try
        {
            lock (_lifecycleSync)
            {
                ThrowIfUnavailable();
                using var transition = _componentState!.Use(value =>
                    provider.PrepareBraidControlReceive(value, Binding, ownedNetwork, frame));
                return CopyBraidControlCandidate(transition);
            }
        }
        finally { CryptographicOperations.ZeroMemory(ownedNetwork); }
    }

    private TripleRatchetBraidRecoveryCandidate CopyBraidControlCandidate(BraidRecoveryComponentTransition transition)
    {
        if (transition.IsExactReplay) return new(null, transition.Control, true);
        SecretBuffer? component = null;
        Dictionary<RatchetCounterTuple, SkippedComponentKey>? skipped = null;
        try
        {
            component = transition.TakeNextState(); skipped = CloneSkipped();
            var successor = new TripleRatchetState(Binding, component,
                ReceiveEcChain, NextExpectedReceiveEcN, SendEcChain, NextSendEcN,
                checked(StorageGeneration + 1), ReceiveMessagesSincePqInjection, SendMessagesSincePqInjection,
                ReceivePqFrontier, SendPqFrontier, _receivePqStateCommitment.ToArray(), _sendPqStateCommitment.ToArray(),
                _maximumMessagesWithoutPqInjection, skipped, false);
            component = null; skipped = null;
            return new(successor, transition.Control, false);
        }
        finally { component?.Dispose(); DisposeSkipped(skipped); }
    }
}
