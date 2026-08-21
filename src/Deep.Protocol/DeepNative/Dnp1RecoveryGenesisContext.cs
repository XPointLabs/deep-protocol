using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// Cryptographically relative ReleaseRoot genesis context. It is derived only from verified
/// nonterminal ReleaseRoot, DWD and protected WHL facts and cannot authorize persistence,
/// publication, or the required consumer-owned zero-to-one CAS.
/// </summary>
public sealed class GenesisReleaseContext
{
    private readonly byte[] _fingerprint;
    private readonly byte[] _authorityHead;
    private readonly byte[] _protectedStateKeyId;
    private readonly byte[] _network;
    private readonly byte[] _resetId;
    private readonly byte[] _latestDwdReference;
    private readonly byte[] _currentReleaseTransitionReference;
    private readonly ulong _latestWitnessEpoch;
    private readonly (ArtifactType Type, byte[] Canonical)[] _recoveryRows;
    private readonly byte[] _witnessHeadHistoryLkg;
    private readonly byte[][] _latestWitnessIds;
    private readonly ReleaseRootRelativeFact _currentRoot;
    private readonly WitnessDelegationRelativeFact _latestDelegation;
    private readonly VerifiedGenesisBaseIdentityContext _baseIdentity;
    private readonly WitnessDelegationRelativeFact[] _orderedDwdAncestry;
    private readonly byte[] _releaseRootLkg;

    internal GenesisReleaseContext(
        VerifiedGenesisBaseIdentityContext baseIdentity,
        VerifiedGenesisReleaseHead verifiedHead)
    {
        ArgumentNullException.ThrowIfNull(baseIdentity);
        ArgumentNullException.ThrowIfNull(verifiedHead);
        if (!ReferenceEquals(verifiedHead.BaseIdentity, baseIdentity))
            Invalid("Genesis release head belongs to another sealed base identity.");
        var currentRoot = verifiedHead.CurrentRoot;
        var orderedDwdAncestry = verifiedHead.OrderedDwdAncestry;
        var headHistory = verifiedHead.HeadHistory;
        ArgumentNullException.ThrowIfNull(currentRoot);
        ArgumentNullException.ThrowIfNull(orderedDwdAncestry);
        ArgumentNullException.ThrowIfNull(headHistory);
        if (currentRoot.IsTerminalCandidate || orderedDwdAncestry.Count is < 1 or > 65 ||
            currentRoot.Transitions.Count > 64 ||
            currentRoot.Transitions.Any(static value => value.Type != ArtifactType.Krt1) ||
            !CanonicalGrammar.FixedEquals(baseIdentity.Network,
                currentRoot.Manifest.NetworkId.Span))
            Invalid("Genesis release context requires a complete nonterminal ReleaseRoot chain.");
        if (headHistory.EntryCount != orderedDwdAncestry.Count - 1)
            Invalid("Genesis release context WHL count differs from DWD ancestry.");

        var transitionIndex = 0;
        ArtifactReference? observedRoot = null;
        for (var index = 0; index < orderedDwdAncestry.Count; index++)
        {
            var fact = orderedDwdAncestry[index] ?? throw new RecordException(
                RecordError.InvalidField, "Genesis release context contains a null DWD fact.");
            var rootReference = fact.ReleaseRoot.CurrentTransitionReference;
            if (observedRoot is null || !Same(observedRoot.Value, rootReference))
            {
                if (index == 0)
                {
                    if (!Same(rootReference, CanonicalGrammar.ComputeReference(
                            ArtifactType.Rrm1, currentRoot.Manifest.CanonicalBytes.Span)))
                        Invalid("Genesis DWD1 is not rooted in the immutable RRM1.");
                }
                else
                {
                    if (transitionIndex >= currentRoot.Transitions.Count ||
                        !Same(rootReference, currentRoot.Transitions[transitionIndex]))
                        Invalid("A genesis ReleaseRoot transition lacks its exact successor DWD1.");
                    transitionIndex++;
                }
                observedRoot = rootReference;
            }
        }
        if (transitionIndex != currentRoot.Transitions.Count || observedRoot is null ||
            !Same(observedRoot.Value, currentRoot.CurrentTransitionReference))
            Invalid("Genesis ReleaseRoot transition ancestry is incomplete or has a tail.");

        var latest = orderedDwdAncestry[^1];
        _baseIdentity = baseIdentity;
        _orderedDwdAncestry = orderedDwdAncestry.ToArray();
        _releaseRootLkg = verifiedHead.ReleaseRootLkg.ToArray();
        _currentRoot = currentRoot;
        _latestDelegation = latest;
        _authorityHead = ComputeAuthorityHead(currentRoot, latest);
        if (!CanonicalGrammar.FixedEquals(
                _authorityHead, headHistory.CurrentReleaseRootAuthorityHead.Span) ||
            !CanonicalGrammar.FixedEquals(
                headHistory.CurrentDwdReference.Span,
                Reference(ArtifactType.Dwd1, latest.Delegation.CanonicalBytes.Span)))
            Invalid("Genesis WHL1 current head differs from verified ReleaseRoot ancestry.");
        _protectedStateKeyId = headHistory.TrustedProtectedStateKeyId.ToArray();
        _network = currentRoot.Manifest.NetworkId.ToArray();
        _resetId = baseIdentity.ResetId.ToArray();
        _latestDwdReference = Reference(ArtifactType.Dwd1, latest.Delegation.CanonicalBytes.Span);
        _currentReleaseTransitionReference =
            CanonicalGrammar.EncodeReference(currentRoot.CurrentTransitionReference);
        _latestWitnessEpoch = latest.Delegation.WitnessEpoch;
        _latestWitnessIds = latest.Descriptors
            .Select(static value => value.WitnessId.ToArray())
            .OrderBy(static value => value, ByteArrayComparer.Instance)
            .ToArray();
        if (_latestWitnessIds.Length != 4)
            Invalid("Genesis release context requires exactly four current witnesses.");
        _witnessHeadHistoryLkg = headHistory.TrustedCanonical.ToArray();
        _recoveryRows =
        [
            (ArtifactType.Rrm1, currentRoot.Manifest.CanonicalBytes.ToArray()),
            .. currentRoot.TransitionCanonicals.Select(static canonical =>
            {
                var bytes = canonical.ToArray();
                return (bytes.Length == 412 ? ArtifactType.Krt1 : ArtifactType.Krf1, bytes);
            }),
            .. orderedDwdAncestry.Select(static fact =>
                (ArtifactType.Dwd1, fact.Delegation.CanonicalBytes.ToArray()))
        ];

        var whl = headHistory.TrustedCanonical;
        var historyCount = BinaryPrimitives.ReadUInt16BigEndian(whl.Slice(156, 2));
        _fingerprint = ComputeFingerprint(baseIdentity.ResetId,
            currentRoot, orderedDwdAncestry,
            whl.Slice(158, checked(historyCount * 342)), historyCount,
            _protectedStateKeyId, _authorityHead);
    }

    public ReadOnlyMemory<byte> Fingerprint => _fingerprint.ToArray();
    public ReadOnlyMemory<byte> CurrentReleaseRootAuthorityHead => _authorityHead.ToArray();
    public ReadOnlyMemory<byte> ProtectedStateHmacKeyId => _protectedStateKeyId.ToArray();
    public bool NoAuthorityClaim => true;
    internal ReadOnlySpan<byte> Network => _network;
    internal ReadOnlySpan<byte> ResetId => _resetId;
    internal ReadOnlySpan<byte> LatestDwdReference => _latestDwdReference;
    internal ReadOnlySpan<byte> CurrentReleaseTransitionReference =>
        _currentReleaseTransitionReference;
    internal ulong LatestWitnessEpoch => _latestWitnessEpoch;
    internal ReadOnlySpan<byte> WitnessHeadHistoryLkg => _witnessHeadHistoryLkg;
    internal IReadOnlyList<ReadOnlyMemory<byte>> LatestWitnessIds =>
        _latestWitnessIds.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
    internal ReleaseRootRelativeFact CurrentRoot => _currentRoot;
    internal WitnessDelegationRelativeFact LatestDelegation => _latestDelegation;
    internal VerifiedGenesisBaseIdentityContext BaseIdentity => _baseIdentity;
    internal IReadOnlyList<WitnessDelegationRelativeFact> OrderedDwdAncestry =>
        _orderedDwdAncestry.ToArray();
    internal ReadOnlySpan<byte> ReleaseRootLkg => _releaseRootLkg;
    internal IReadOnlyList<(ArtifactType Type, ReadOnlyMemory<byte> Canonical)> RecoveryRows =>
        _recoveryRows.Select(static row =>
            (row.Type, (ReadOnlyMemory<byte>)row.Canonical.ToArray())).ToArray();

    internal static byte[] ComputeFingerprint(
        ReadOnlySpan<byte> resetId32,
        ReleaseRootRelativeFact currentRoot,
        IReadOnlyList<WitnessDelegationRelativeFact> orderedDwdAncestry,
        ReadOnlySpan<byte> orderedHeadHistoryEntries,
        ushort historyCount,
        ReadOnlySpan<byte> protectedStateKeyId32,
        ReadOnlySpan<byte> authorityHead32)
    {
        ArgumentNullException.ThrowIfNull(currentRoot);
        ArgumentNullException.ThrowIfNull(orderedDwdAncestry);
        if (resetId32.Length != 32 || protectedStateKeyId32.Length != 32 ||
            authorityHead32.Length != 32 || orderedDwdAncestry.Count is < 1 or > 65 ||
            orderedHeadHistoryEntries.Length != checked(historyCount * 342) ||
            historyCount != orderedDwdAncestry.Count - 1)
            Invalid("Genesis release context inputs have invalid fixed widths or counts.");
        var latest = orderedDwdAncestry[^1];
        var payload = new byte[
            16 + 32 + 38 + 8 + 32 + 38 + 38 + 1 + 1 + 8 + 38 + 8 + 32 +
            2 + 38 * currentRoot.Transitions.Count +
            2 + 38 * orderedDwdAncestry.Count +
            2 + orderedHeadHistoryEntries.Length + 32];
        var offset = 0;
        Append(currentRoot.Manifest.NetworkId.Span);
        Append(resetId32);
        Append(Reference(ArtifactType.Rrm1, currentRoot.Manifest.CanonicalBytes.Span));
        U64(currentRoot.CurrentGeneration);
        Append(currentRoot.CurrentEd25519PublicKey.Span);
        Append(CanonicalGrammar.EncodeReference(currentRoot.CurrentTransitionReference));
        Append(new byte[38]);
        payload[offset++] = 0;
        payload[offset++] = 0;
        U64(latest.Delegation.DelegationGeneration);
        Append(Reference(ArtifactType.Dwd1, latest.Delegation.CanonicalBytes.Span));
        U64(latest.Delegation.WitnessEpoch);
        Append(authorityHead32);
        U16(checked((ushort)currentRoot.Transitions.Count));
        foreach (var transition in currentRoot.Transitions)
            Append(CanonicalGrammar.EncodeReference(transition));
        U16(checked((ushort)orderedDwdAncestry.Count));
        foreach (var fact in orderedDwdAncestry)
            Append(Reference(ArtifactType.Dwd1, fact.Delegation.CanonicalBytes.Span));
        U16(historyCount);
        Append(orderedHeadHistoryEntries);
        Append(protectedStateKeyId32);
        if (offset != payload.Length)
            Invalid("Genesis release context transcript width drifted.");
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V3/recovery-genesis-release-context", payload);

        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(payload.AsSpan(offset));
            offset += value.Length;
        }
        void U64(ulong value)
        {
            BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(offset, 8), value);
            offset += 8;
        }
        void U16(ushort value)
        {
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(offset, 2), value);
            offset += 2;
        }
    }

    internal static byte[] ComputeAuthorityHead(
        ReleaseRootRelativeFact currentRoot,
        WitnessDelegationRelativeFact latest)
    {
        var rrmReference = CanonicalGrammar.ComputeReference(
            ArtifactType.Rrm1, currentRoot.Manifest.CanonicalBytes.Span);
        var latestReference = CanonicalGrammar.ComputeReference(
            ArtifactType.Dwd1, latest.Delegation.CanonicalBytes.Span);
        var chain = new byte[38 + 2 + 38 * currentRoot.Transitions.Count + 38];
        var chainOffset = 0;
        CanonicalGrammar.EncodeReference(rrmReference).CopyTo(chain, chainOffset);
        chainOffset += 38;
        BinaryPrimitives.WriteUInt16BigEndian(
            chain.AsSpan(chainOffset, 2), checked((ushort)currentRoot.Transitions.Count));
        chainOffset += 2;
        foreach (var transition in currentRoot.Transitions)
        {
            CanonicalGrammar.EncodeReference(transition).CopyTo(chain, chainOffset);
            chainOffset += 38;
        }
        CanonicalGrammar.EncodeReference(latestReference).CopyTo(chain, chainOffset);
        var checkpoint = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/release-root-chain", chain);

        var tuple = new byte[282];
        var offset = 0;
        Append(CanonicalGrammar.EncodeReference(rrmReference));
        U64(currentRoot.CurrentGeneration);
        Append(currentRoot.CurrentEd25519PublicKey.Span);
        Append(CanonicalGrammar.EncodeReference(currentRoot.CurrentTransitionReference));
        Append(new byte[38]);
        tuple[offset++] = 0;
        tuple[offset++] = 0;
        U64(latest.Delegation.DelegationGeneration);
        Append(CanonicalGrammar.EncodeReference(latestReference));
        U64(latest.Delegation.WitnessEpoch);
        U16(checked((ushort)currentRoot.Transitions.Count));
        Append(checkpoint);
        Append(new byte[38]);
        if (offset != tuple.Length) Invalid("Genesis ReleaseRoot authority tuple width drifted.");
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/release-root-authority-head", tuple);

        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(tuple.AsSpan(offset));
            offset += value.Length;
        }
        void U64(ulong value)
        {
            BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(offset, 8), value);
            offset += 8;
        }
        void U16(ushort value)
        {
            BinaryPrimitives.WriteUInt16BigEndian(tuple.AsSpan(offset, 2), value);
            offset += 2;
        }
    }

    private static bool Same(ArtifactReference left, ArtifactReference right) =>
        left.Type == right.Type && left.CanonicalLength == right.CanonicalLength &&
        CanonicalGrammar.FixedEquals(left.CanonicalHash.Span, right.CanonicalHash.Span);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static ByteArrayComparer Instance { get; } = new();
        public int Compare(byte[]? left, byte[]? right) => left is null ? -1 : right is null ? 1 :
            left.AsSpan().SequenceCompareTo(right);
    }

    private static byte[] Reference(ArtifactType type, ReadOnlySpan<byte> canonical) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, canonical));

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static GenesisReleaseContext CreateGenesisReleaseContext(
        VerifiedGenesisBaseIdentityContext baseIdentity,
        VerifiedGenesisReleaseHead verifiedHead) =>
        new(baseIdentity, verifiedHead);
}

internal static class WitnessAuthorityBinding
{
    internal static void Verify(
        ReadOnlySpan<byte> observedDwdReference38,
        ulong observedRootGeneration,
        ReadOnlySpan<byte> observedRootTransition38,
        ReadOnlySpan<byte> observedTerminalKrf38,
        byte observedTerminalState,
        ReadOnlySpan<byte> observedAuthorityHead32,
        ReadOnlySpan<byte> expectedDwdReference38,
        ulong expectedRootGeneration,
        ReadOnlySpan<byte> expectedRootTransition38,
        ReadOnlySpan<byte> expectedTerminalKrf38,
        bool expectedTerminalState,
        ReadOnlySpan<byte> expectedAuthorityHead32)
    {
        if (observedDwdReference38.Length != 38 || observedRootTransition38.Length != 38 ||
            observedTerminalKrf38.Length != 38 || observedAuthorityHead32.Length != 32 ||
            expectedDwdReference38.Length != 38 || expectedRootTransition38.Length != 38 ||
            expectedTerminalKrf38.Length != 38 || expectedAuthorityHead32.Length != 32 ||
            observedTerminalState > 1)
            Invalid("The witness authority binding has an invalid shape.");
        if (!CanonicalGrammar.FixedEquals(observedDwdReference38, expectedDwdReference38) ||
            observedRootGeneration != expectedRootGeneration ||
            !CanonicalGrammar.FixedEquals(observedRootTransition38, expectedRootTransition38) ||
            !CanonicalGrammar.FixedEquals(observedTerminalKrf38, expectedTerminalKrf38) ||
            observedTerminalState != (expectedTerminalState ? (byte)1 : (byte)0) ||
            !CanonicalGrammar.FixedEquals(observedAuthorityHead32, expectedAuthorityHead32))
            Invalid("The witness receipt authority tuple is cross-fed.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
