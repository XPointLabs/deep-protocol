using Deep.Protocol.Abstractions.State;

namespace Deep.Protocol;

public static class SharedConfigNamespaceStateMachine
{
    public static SharedConfigNamespaceMergeResult Apply(
        SharedConfigNamespaceState state,
        int kind,
        long seqNo,
        ReadOnlySpan<byte> data,
        DateTimeOffset updatedAt)
    {
        if (state is null)
        {
            throw new ArgumentNullException(nameof(state));
        }

        if (kind <= 0 || seqNo < 0)
        {
            return new SharedConfigNamespaceMergeResult(state, SharedConfigMergeOutcome.Invalid);
        }

        var current = state.Namespaces.TryGetValue(kind, out var existing) ? existing : null;

        if (current is not null)
        {
            if (seqNo < current.SeqNo)
            {
                return new SharedConfigNamespaceMergeResult(state, SharedConfigMergeOutcome.Stale);
            }

            if (seqNo == current.SeqNo)
            {
                var incoming = data.ToArray();
                if (incoming.AsSpan().SequenceEqual(current.Data.Span))
                {
                    return new SharedConfigNamespaceMergeResult(state, SharedConfigMergeOutcome.Duplicate, current);
                }

                return new SharedConfigNamespaceMergeResult(state, SharedConfigMergeOutcome.Stale);
            }
        }

        var applied = new SharedConfigNamespaceEntry(kind, seqNo, data.ToArray(), updatedAt);
        var map = new Dictionary<int, SharedConfigNamespaceEntry>(state.Namespaces)
        {
            [kind] = applied
        };

        return new SharedConfigNamespaceMergeResult(
            new SharedConfigNamespaceState { Namespaces = map },
            SharedConfigMergeOutcome.Applied,
            applied);
    }
}
