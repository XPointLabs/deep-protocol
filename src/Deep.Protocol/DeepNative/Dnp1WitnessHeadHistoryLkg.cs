using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// Exact protected WHL1 bytes carried from a consumer-owned store. This input is untrusted,
/// defensively owned, and conveys neither storage nor ReleaseRoot authority.
/// </summary>
public sealed class WitnessHeadHistoryLkgInput
{
    private readonly byte[] _canonical;

    public WitnessHeadHistoryLkgInput(ReadOnlySpan<byte> exactWhl1)
    {
        Preflight(exactWhl1);
        _canonical = exactWhl1.ToArray();
        Preflight(_canonical);
    }

    internal ReadOnlyMemory<byte> Canonical => _canonical;
    public bool NoAuthorityClaim => true;

    internal static void Preflight(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length < 222 || !canonical[..4].SequenceEqual("WHL1"u8) ||
            canonical[4] != 1 || canonical[5] != 0)
            Invalid(RecordError.InvalidField, "The WHL1 fixed header is invalid.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(canonical[156..158]);
        if (count > 64 || canonical.Length != checked(222 + 342 * count))
            Invalid(RecordError.InvalidLength, "The WHL1 entry count or length is invalid.");
        if (CanonicalGrammar.IsZero(canonical.Slice(canonical.Length - 64, 32)))
            Invalid(RecordError.InvalidField, "The WHL1 protected-state key ID is zero.");
    }

    private static void Invalid(RecordError error, string message) =>
        throw new RecordException(error, message);
}

/// <summary>
/// Cryptographically verified WHL1 relative to exact sealed cutover and ReleaseRoot facts.
/// It is data-only and cannot authorize a consumer CAS, publication, or activation.
/// </summary>
public sealed class VerifiedWitnessHeadHistoryLkg
{
    private readonly byte[] _canonical;
    private readonly byte[] _currentDwdReference;
    private readonly byte[] _authorityHead;

    internal VerifiedWitnessHeadHistoryLkg(
        ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> currentDwdReference,
        ReadOnlySpan<byte> authorityHead,
        ushort entryCount)
    {
        _canonical = canonical.ToArray();
        _currentDwdReference = currentDwdReference.ToArray();
        _authorityHead = authorityHead.ToArray();
        EntryCount = entryCount;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => _canonical.ToArray();
    public ReadOnlyMemory<byte> CurrentDwdReference => _currentDwdReference.ToArray();
    public ReadOnlyMemory<byte> CurrentReleaseRootAuthorityHead => _authorityHead.ToArray();
    public ushort EntryCount { get; }
    public bool NoAuthorityClaim => true;
    internal ReadOnlySpan<byte> TrustedCanonical => _canonical;
    internal ReadOnlySpan<byte> TrustedProtectedStateKeyId =>
        _canonical.AsSpan(_canonical.Length - 64, 32);
}

/// <summary>
/// HMAC-verified, nonterminal RRL1/WHL1 head joined to one exact genesis identity and
/// ReleaseRoot ancestry. It is relative data only and cannot authorize persistence.
/// </summary>
public sealed class VerifiedGenesisReleaseHead
{
    private readonly byte[] _releaseRootLkg;

    internal VerifiedGenesisReleaseHead(
        VerifiedGenesisBaseIdentityContext baseIdentity,
        ReleaseRootRelativeFact currentRoot,
        IReadOnlyList<WitnessDelegationRelativeFact> orderedDwdAncestry,
        VerifiedWitnessHeadHistoryLkg headHistory,
        ReadOnlySpan<byte> exactReleaseRootLkg)
    {
        BaseIdentity = baseIdentity;
        CurrentRoot = currentRoot;
        OrderedDwdAncestry = orderedDwdAncestry.ToArray();
        HeadHistory = headHistory;
        _releaseRootLkg = exactReleaseRootLkg.ToArray();
    }

    public bool NoAuthorityClaim => true;
    internal VerifiedGenesisBaseIdentityContext BaseIdentity { get; }
    internal ReleaseRootRelativeFact CurrentRoot { get; }
    internal IReadOnlyList<WitnessDelegationRelativeFact> OrderedDwdAncestry { get; }
    internal VerifiedWitnessHeadHistoryLkg HeadHistory { get; }
    internal ReadOnlySpan<byte> ReleaseRootLkg => _releaseRootLkg;
}

/// <summary>Package-owned WHL1 verification only; durable mutation remains consumer-owned.</summary>
public sealed class WitnessHeadHistoryLkgVerifier
{
    public async ValueTask<VerifiedGenesisReleaseHead> VerifyGenesisAsync(
        WitnessHeadHistoryLkgInput input,
        ReadOnlyMemory<byte> exactReleaseRootLkg,
        ReleaseRootRelativeFact currentRoot,
        IReadOnlyList<WitnessDelegationRelativeFact> orderedDwdAncestry,
        VerifiedGenesisBaseIdentityContext baseIdentity,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(currentRoot);
        ArgumentNullException.ThrowIfNull(orderedDwdAncestry);
        ArgumentNullException.ThrowIfNull(baseIdentity);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        var identity = baseIdentity.Identity;
        if (orderedDwdAncestry.Count is < 1 or > 65 ||
            currentRoot.IsTerminalCandidate || identity.IsTerminal || identity.ForkLatched)
            Invalid("Genesis WHL1 requires bounded nonterminal ReleaseRoot and identity facts.");

        var canonical = input.Canonical.ToArray();
        WitnessHeadHistoryLkgInput.Preflight(canonical);
        var count = BinaryPrimitives.ReadUInt16BigEndian(canonical.AsSpan(156, 2));
        var keyId = canonical.AsMemory(canonical.Length - 64, 32);
        var rootLkgBytes = exactReleaseRootLkg.ToArray();
        var rootVerifier = new ReleaseRootRelativeVerifier();
        var rootMatch = await rootVerifier.VerifyLkgHmacAsync(
            rootLkgBytes, hmacProvider, cancellationToken).ConfigureAwait(false);
        var rootLkg = ProtectedStateCodec.DecodeReleaseRootLastKnownGood(rootLkgBytes);
        var rootAuthority = rootVerifier.CreateAuthorityTuple(rootLkgBytes, rootMatch);
        if (rootLkg.Terminal || rootLkg.ForkLatched ||
            !CanonicalGrammar.FixedEquals(rootLkg.Record.FieldSpan(1),
                currentRoot.Manifest.NetworkId.Span) ||
            !CanonicalGrammar.FixedEquals(rootLkg.Record.FieldSpan(15), keyId.Span))
            Invalid("Genesis RRL1 is terminal, forked, cross-network, or uses another key.");
        var returned = await hmacProvider.ComputeTagAsync(new ProtectedHmacRequest(
            "Deep/ProtectedState/V1/WHL1", ArtifactRegistry.ProtectedHmacSha256,
            keyId.Span, canonical.AsSpan(0, canonical.Length - 32)), cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var tag = returned.ToArray();
        if (tag.Length != 32 || !CanonicalGrammar.FixedEquals(
                tag, canonical.AsSpan(canonical.Length - 32, 32)))
            throw new RecordException(RecordError.InvalidSignature,
                "The genesis WHL1 protected-state HMAC is invalid.");

        var network = currentRoot.Manifest.NetworkId.Span;
        if (!CanonicalGrammar.FixedEquals(network, identity.Account.Certificate.NetworkId.Span) ||
            !CanonicalGrammar.FixedEquals(network, baseIdentity.Network) ||
            !CanonicalGrammar.FixedEquals(network, canonical.AsSpan(6, 16)) ||
            !CanonicalGrammar.FixedEquals(canonical.AsSpan(22, 32), baseIdentity.ResetId) ||
            count != orderedDwdAncestry.Count - 1)
            Invalid("Genesis WHL1 network, reset, or ancestry count differs from sealed facts.");
        Span<byte> deploymentInput = stackalloc byte[80];
        network.CopyTo(deploymentInput[..16]);
        identity.Account.DeepAccountIdHash.Span.CopyTo(deploymentInput[16..48]);
        baseIdentity.ResetId.CopyTo(deploymentInput[48..]);
        var deploymentSubject = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/deployment-subject", deploymentInput);
        if (!CanonicalGrammar.FixedEquals(canonical.AsSpan(54, 32), deploymentSubject))
            Invalid("Genesis WHL1 deployment subject differs from the sealed identity.");

        var previousReference = default(ArtifactReference);
        for (var index = 0; index < orderedDwdAncestry.Count; index++)
        {
            var fact = orderedDwdAncestry[index] ?? throw new RecordException(
                RecordError.InvalidField, "Genesis DWD ancestry contains a null fact.");
            var delegation = fact.Delegation;
            if (delegation.DelegationGeneration != (ulong)index ||
                delegation.WitnessEpoch != checked((ulong)index + 1) ||
                !CanonicalGrammar.FixedEquals(delegation.NetworkId.Span, network))
                Invalid("Genesis DWD ancestry is skipped, reordered, or cross-network.");
            var reference = CanonicalGrammar.ComputeReference(
                ArtifactType.Dwd1, delegation.CanonicalBytes.Span);
            if (index == 0)
            {
                if (!CanonicalGrammar.DecodeReference(
                        delegation.Record.FieldSpan(3), allowZero: true).IsZero)
                    Invalid("Genesis DWD1 has a nonzero predecessor.");
            }
            else
            {
                var encodedPrevious = CanonicalGrammar.EncodeReference(previousReference);
                if (!CanonicalGrammar.FixedEquals(delegation.Record.FieldSpan(3), encodedPrevious))
                    Invalid("Genesis DWD ancestry has a wrong predecessor.");
                var entry = canonical.AsSpan(158 + (index - 1) * 342, 342);
                var previous = orderedDwdAncestry[index - 1].Delegation;
                if (!CanonicalGrammar.FixedEquals(entry[..38],
                        CanonicalGrammar.EncodeReference(reference)) ||
                    BinaryPrimitives.ReadUInt64BigEndian(entry[38..46]) !=
                        delegation.DelegationGeneration ||
                    BinaryPrimitives.ReadUInt64BigEndian(entry[46..54]) !=
                        previous.WitnessEpoch)
                    Invalid("Genesis WHL1 entry differs from the DWD ancestry.");
                RecoveryCandidatePlan.VerifyDwhHeads(previous, delegation, entry[54..342]);
            }
            previousReference = reference;
        }
        var latest = orderedDwdAncestry[^1];
        var latestReference = CanonicalGrammar.EncodeReference(previousReference);
        var authorityHead = GenesisReleaseContext.ComputeAuthorityHead(currentRoot, latest);
        if (!CanonicalGrammar.FixedEquals(canonical.AsSpan(86, 38), latestReference) ||
            !CanonicalGrammar.FixedEquals(canonical.AsSpan(124, 32), authorityHead) ||
            !CanonicalGrammar.FixedEquals(CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/release-root-authority-head",
                rootAuthority.CanonicalTuple.Span), authorityHead))
            Invalid("Genesis WHL1 current DWD or ReleaseRoot head is stale.");
        var history = new VerifiedWitnessHeadHistoryLkg(
            canonical, latestReference, authorityHead, count);
        return new VerifiedGenesisReleaseHead(baseIdentity, currentRoot,
            orderedDwdAncestry, history, rootLkgBytes);
    }

    public async ValueTask<VerifiedWitnessHeadHistoryLkg> VerifyCurrentAsync(
        WitnessHeadHistoryLkgInput input,
        CurrentCutoverRelative currentCutover,
        ReleaseRootRestoreRelative releaseRoot,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(currentCutover);
        ArgumentNullException.ThrowIfNull(releaseRoot);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();

        var canonical = input.Canonical.ToArray();
        WitnessHeadHistoryLkgInput.Preflight(canonical);
        var count = BinaryPrimitives.ReadUInt16BigEndian(canonical.AsSpan(156, 2));
        var keyId = canonical.AsMemory(canonical.Length - 64, 32);
        if (!CanonicalGrammar.FixedEquals(keyId.Span, currentCutover.TrustedDplKeyId))
            Invalid("WHL1 does not use the sealed current ProtectedStateHmac key ID.");
        var storedTag = canonical.AsMemory(canonical.Length - 32, 32);
        var returned = await hmacProvider.ComputeTagAsync(new ProtectedHmacRequest(
            "Deep/ProtectedState/V1/WHL1", ArtifactRegistry.ProtectedHmacSha256,
            keyId.Span, canonical.AsSpan(0, canonical.Length - 32)), cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var tag = returned.ToArray();
        if (tag.Length != 32 || !CanonicalGrammar.FixedEquals(tag, storedTag.Span))
            throw new RecordException(RecordError.InvalidSignature,
                "The WHL1 protected-state HMAC is invalid.");

        // Only the public shape and exact sealed key selector are trusted before the HMAC.
        // All ancestry/source semantics below operate on the authenticated frozen bytes.
        var dwdCanonicals = releaseRoot.OrderedDwdCanonicals;
        var predecessorHeads = releaseRoot.OrderedPredecessorHeads;
        if (dwdCanonicals.Count is < 1 or > 65 || predecessorHeads.Count != dwdCanonicals.Count ||
            count != dwdCanonicals.Count - 1)
            Invalid("WHL1 count differs from the sealed ReleaseRoot ancestry.");

        var latestDwd = dwdCanonicals[^1];
        var currentDwdReference = Reference(ArtifactType.Dwd1, latestDwd);
        var authorityHead = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/release-root-authority-head",
            releaseRoot.AuthorityTuple.CanonicalTuple.Span);
        Span<byte> deploymentInput = stackalloc byte[80];
        currentCutover.TrustedNetwork.CopyTo(deploymentInput[..16]);
        currentCutover.TrustedAccountHash.CopyTo(deploymentInput[16..48]);
        currentCutover.TrustedResetId.CopyTo(deploymentInput[48..]);
        var deploymentSubject = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/deployment-subject", deploymentInput);
        if (!CanonicalGrammar.FixedEquals(canonical.AsSpan(6, 16), currentCutover.TrustedNetwork) ||
            !CanonicalGrammar.FixedEquals(canonical.AsSpan(22, 32), currentCutover.TrustedResetId) ||
            !CanonicalGrammar.FixedEquals(canonical.AsSpan(54, 32), deploymentSubject) ||
            !CanonicalGrammar.FixedEquals(canonical.AsSpan(86, 38), currentDwdReference) ||
            !CanonicalGrammar.FixedEquals(canonical.AsSpan(124, 32), authorityHead) ||
            !CanonicalGrammar.FixedEquals(currentCutover.TrustedReleaseRootAuthorityHead, authorityHead))
            Invalid("WHL1 current source differs from the sealed cutover/ReleaseRoot facts.");

        for (var index = 1; index < dwdCanonicals.Count; index++)
        {
            var entry = canonical.AsSpan(158 + (index - 1) * 342, 342);
            var current = CutoverCodec.DecodeWitnessDelegation(dwdCanonicals[index]);
            var previous = CutoverCodec.DecodeWitnessDelegation(dwdCanonicals[index - 1]);
            if (!CanonicalGrammar.FixedEquals(entry[..38],
                    Reference(ArtifactType.Dwd1, dwdCanonicals[index])) ||
                BinaryPrimitives.ReadUInt64BigEndian(entry[38..46]) != current.DelegationGeneration ||
                BinaryPrimitives.ReadUInt64BigEndian(entry[46..54]) != previous.WitnessEpoch ||
                !CanonicalGrammar.FixedEquals(entry[54..342], predecessorHeads[index]))
                Invalid("A WHL1 entry differs from the exact sealed DWD ancestry evidence.");
            RecoveryCandidatePlan.VerifyDwhHeads(
                previous, current, entry[54..342]);
        }

        return new VerifiedWitnessHeadHistoryLkg(
            canonical, currentDwdReference, authorityHead, count);
    }

    private static byte[] Reference(ArtifactType type, ReadOnlySpan<byte> canonical) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, canonical));

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
