using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Authority-private DID2 directory mutation input. Current checkpoints must
/// describe the complete protected map, not merely the leaves in this batch.
/// </summary>
public sealed class DeepIdV2DirectoryHeadMutationRequest
{
    private readonly ReadOnlyMemory<byte>[] priorTransitions;
    private readonly VerifiedAdc1V2[] current;
    private readonly VerifiedAdc1V2[] successors;

    public DeepIdV2DirectoryHeadMutationRequest(
        IReadOnlyList<ReadOnlyMemory<byte>> exactPriorTransitions,
        IReadOnlyList<VerifiedAdc1V2> currentCheckpoints,
        IReadOnlyList<VerifiedAdc1V2> successors,
        ulong validFromUnixSeconds, ulong validUntilUnixSeconds,
        ushort minimumReader)
    {
        ArgumentNullException.ThrowIfNull(exactPriorTransitions);
        ArgumentNullException.ThrowIfNull(currentCheckpoints);
        ArgumentNullException.ThrowIfNull(successors);
        if (exactPriorTransitions.Count > 1_000_000 ||
            currentCheckpoints.Count > 1_000_000 || successors.Count > 4096)
            throw new ArgumentOutOfRangeException(nameof(successors));
        if (validUntilUnixSeconds <= validFromUnixSeconds ||
            validUntilUnixSeconds - validFromUnixSeconds > 86_400)
            throw new ArgumentOutOfRangeException(nameof(validUntilUnixSeconds));
        if (minimumReader < 2)
            throw new ArgumentOutOfRangeException(nameof(minimumReader));
        priorTransitions = exactPriorTransitions.Select(value =>
        {
            if (value.Length != DeepIdV2DirectoryTransitionCodec.CanonicalLength)
                throw new ArgumentException("Every prior V2 transition must have its exact canonical length.",
                    nameof(exactPriorTransitions));
            return (ReadOnlyMemory<byte>)value.ToArray();
        }).ToArray();
        current = currentCheckpoints.Select(value => value ??
            throw new ArgumentException("A current V2 checkpoint is null.",
                nameof(currentCheckpoints))).ToArray();
        this.successors = successors.Select(value => value ??
            throw new ArgumentException("A successor V2 checkpoint is null.",
                nameof(successors))).ToArray();
        ValidFromUnixSeconds = validFromUnixSeconds;
        ValidUntilUnixSeconds = validUntilUnixSeconds;
        MinimumReader = minimumReader;
    }

    public IReadOnlyList<ReadOnlyMemory<byte>> ExactPriorTransitions =>
        priorTransitions.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
    public IReadOnlyList<VerifiedAdc1V2> CurrentCheckpoints => current.ToArray();
    public IReadOnlyList<VerifiedAdc1V2> Successors => successors.ToArray();
    public ulong ValidFromUnixSeconds { get; }
    public ulong ValidUntilUnixSeconds { get; }
    public ushort MinimumReader { get; }
}

/// <summary>
/// Authors an ADH1 carrying only V2 directory roots. The signed ADH1 envelope
/// remains version one, but reader floor two and complete private V2 replay are
/// mandatory. No DID1 transition or ADC1 V1 capability enters this path.
/// </summary>
public static class DeepIdV2DirectoryHeadAuthor
{
    /// <summary>
    /// Authors the separately pinned, empty reader-V2 genesis ADH1 from the
    /// current XNA1 witness threshold. The result has no transitions and must
    /// be pinned independently before an ADA2 store is provisioned.
    /// </summary>
    public static async ValueTask<AuthoredAccountDirectoryHeadMutation>
        AuthorGenesisAsync(VerifiedXPointNetworkAuthority authority,
            ulong validFromUnixSeconds, ulong validUntilUnixSeconds,
            IReadOnlyList<IAccountDirectoryAdh1WitnessSigner> witnessSigners,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(witnessSigners);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            if (validFromUnixSeconds < authority.NotBefore ||
                validUntilUnixSeconds > authority.ExpiresAt ||
                validUntilUnixSeconds <= validFromUnixSeconds ||
                validUntilUnixSeconds - validFromUnixSeconds > 86_400)
                Fail("TimeOutsideAuthority",
                    "The DID2 genesis head interval is outside the XPoint authority.");
            var signers = ValidateSigners(authority, witnessSigners);
            AccountDirectoryAdh1 Head(
                IReadOnlyList<AccountDirectoryAdh1WitnessEntry> receipts) =>
                new(authority.NetworkId.Span, 0, new byte[32], 0,
                    AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
                    DeepIdV2DirectorySparseMap.EmptyMapRoot.Span,
                    authority.AuthorityCoreReference.Span,
                    authority.DirectoryWitnessPolicyHash.Span,
                    validFromUnixSeconds, validUntilUnixSeconds, 2, receipts);
            var unsigned = Head(signers.Select(static signer =>
                new AccountDirectoryAdh1WitnessEntry(signer.Id,
                    Enumerable.Repeat((byte)1, 64).ToArray())).ToArray());
            var signingInput = AccountDirectoryCrypto.ComputeAdh1SigningInput(
                unsigned);
            var receipts = new List<AccountDirectoryAdh1WitnessEntry>(
                signers.Length);
            try
            {
                foreach (var signer in signers)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var signature = (await signer.Signer.SignAdh1Async(
                        signingInput.ToArray(), cancellationToken)
                        .ConfigureAwait(false)).ToArray();
                    try
                    {
                        if (signature.Length != 64 ||
                            signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                            !PublicKeyAuth.VerifyDetached(signature, signingInput,
                                signer.PublicKey))
                            Fail("InvalidSignerResult",
                                "A DID2 genesis witness returned an invalid ADH1 signature.");
                        receipts.Add(new AccountDirectoryAdh1WitnessEntry(
                            signer.Id, signature));
                    }
                    finally { CryptographicOperations.ZeroMemory(signature); }
                }
            }
            finally { CryptographicOperations.ZeroMemory(signingInput); }
            var head = Head(receipts);
            var exact = AccountDirectoryAdh1Codec.Encode(head);
            var coreHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            var protectedHead = DeepIdV2DirectoryBootstrapVerifier
                .RestoreGenesis(authority, exact, coreHash);
            return new AuthoredAccountDirectoryHeadMutation(exact, coreHash,
                [], [], protectedHead);
        }
        catch (OperationCanceledException) { throw; }
        catch (AccountDirectoryHeadAuthoringException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or
            FormatException or CryptographicException or OverflowException)
        {
            throw new AccountDirectoryHeadAuthoringException("AuthoringRejected",
                "The DID2 genesis head authoring failed closed.", exception);
        }
    }

    public static async ValueTask<AuthoredAccountDirectoryHeadMutation> AdvanceAsync(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProtectedLkg predecessor,
        DeepIdV2DirectoryHeadMutationRequest request,
        IReadOnlyList<IAccountDirectoryAdh1WitnessSigner> witnessSigners,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(predecessor);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(witnessSigners);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            ValidateAuthority(authority, predecessor, request);
            var signers = ValidateSigners(authority, witnessSigners);
            var journal = request.ExactPriorTransitions.ToList();
            var map = DeepIdV2DirectoryJournal.ReplayAndVerify(predecessor, journal)
                .ToDictionary(static entry => entry.Key,
                    static entry => entry.Value, StringComparer.Ordinal);
            var current = ValidateCurrent(authority, request.CurrentCheckpoints, map);
            var ordered = ValidateSuccessors(authority, request.Successors, current);
            var authored = new List<ReadOnlyMemory<byte>>(ordered.Length);

            foreach (var capability in ordered)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var checkpoint = capability.Checkpoint;
                var leaf = checkpoint.DirectoryLeafKey.ToArray();
                var key = Convert.ToHexString(leaf);
                var previous = map.TryGetValue(key, out var value) ? value : new byte[38];
                var before = DeepIdV2DirectorySparseMap.ComputeFullMapRoot(map);
                map[key] = checkpoint.ArtifactReference.ToArray();
                var after = DeepIdV2DirectorySparseMap.ComputeFullMapRoot(map);
                var transition = DeepIdV2DirectoryTransitionCodec.Author(
                    checked((ulong)journal.Count), leaf, previous,
                    checkpoint.ArtifactReference.Span, before, after);
                journal.Add(transition.CanonicalBytes);
                authored.Add(transition.CanonicalBytes);
            }

            var appendRoot = DeepIdV2DirectoryJournal.ComputeAppendRoot(journal);
            var mapRoot = DeepIdV2DirectorySparseMap.ComputeFullMapRoot(map);
            var unsigned = new AccountDirectoryAdh1(authority.NetworkId.Span,
                checked(predecessor.LogGeneration + 1), predecessor.CoreHash.Span,
                checked((ulong)journal.Count), appendRoot, mapRoot,
                authority.AuthorityCoreReference.Span,
                authority.DirectoryWitnessPolicyHash.Span,
                request.ValidFromUnixSeconds, request.ValidUntilUnixSeconds,
                request.MinimumReader,
                signers.Select(static signer => new AccountDirectoryAdh1WitnessEntry(
                    signer.Id, Enumerable.Repeat((byte)1, 64).ToArray())).ToArray());
            var signingInput = AccountDirectoryCrypto.ComputeAdh1SigningInput(unsigned);
            var receipts = new List<AccountDirectoryAdh1WitnessEntry>(signers.Length);
            try
            {
                foreach (var signer in signers)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var signature = (await signer.Signer.SignAdh1Async(
                        signingInput.ToArray(), cancellationToken).ConfigureAwait(false)).ToArray();
                    try
                    {
                        if (signature.Length != 64 ||
                            signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                            !PublicKeyAuth.VerifyDetached(signature, signingInput,
                                signer.PublicKey))
                            Fail("InvalidSignerResult", "A V2 directory witness returned an invalid ADH1 signature.");
                        receipts.Add(new AccountDirectoryAdh1WitnessEntry(signer.Id, signature));
                    }
                    finally { CryptographicOperations.ZeroMemory(signature); }
                }
            }
            finally { CryptographicOperations.ZeroMemory(signingInput); }

            var head = new AccountDirectoryAdh1(authority.NetworkId.Span,
                unsigned.LogGeneration, predecessor.CoreHash.Span,
                unsigned.TreeSize, appendRoot, mapRoot,
                authority.AuthorityCoreReference.Span,
                authority.DirectoryWitnessPolicyHash.Span,
                request.ValidFromUnixSeconds, request.ValidUntilUnixSeconds,
                request.MinimumReader, receipts);
            var exact = AccountDirectoryAdh1Codec.Encode(head);
            var coreHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            var protectedHead = AccountDirectoryProtectedLkgFactory.Restore(
                authority, exact, coreHash);
            _ = DeepIdV2DirectoryJournal.ReplayAndVerify(protectedHead, journal);
            return new AuthoredAccountDirectoryHeadMutation(exact, coreHash,
                authored, journal, protectedHead);
        }
        catch (OperationCanceledException) { throw; }
        catch (AccountDirectoryHeadAuthoringException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or
            FormatException or CryptographicException or OverflowException)
        {
            throw new AccountDirectoryHeadAuthoringException("AuthoringRejected",
                "The DID2 directory head mutation failed closed.", exception);
        }
    }

    private static void ValidateAuthority(VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProtectedLkg predecessor,
        DeepIdV2DirectoryHeadMutationRequest request)
    {
        var head = predecessor.Head;
        if (head.MinimumReader < 2 || request.MinimumReader < head.MinimumReader)
            Fail("ReaderRollback", "The DID2 directory requires a protected reader floor of at least two.");
        if (!Fixed(authority.NetworkId.Span, head.NetworkId.Span) ||
            !Fixed(authority.AuthorityCoreReference.Span,
                head.ExactXnaAuthorityCoreReference.Span) ||
            !Fixed(authority.DirectoryWitnessPolicyHash.Span,
                head.WitnessPolicyHash.Span))
            Fail("AuthorityMismatch", "The protected head is outside the exact current XPoint authority.");
        if (request.ValidFromUnixSeconds < authority.NotBefore ||
            request.ValidUntilUnixSeconds > authority.ExpiresAt)
            Fail("TimeOutsideAuthority", "The candidate ADH1 interval is outside the current authority.");
        if ((ulong)request.ExactPriorTransitions.Count != predecessor.TreeSize)
            Fail("JournalLengthMismatch", "The complete V2 journal does not match the protected tree size.");
    }

    private static Dictionary<string, VerifiedAdc1V2> ValidateCurrent(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<VerifiedAdc1V2> capabilities,
        IReadOnlyDictionary<string, byte[]> map)
    {
        var current = new Dictionary<string, VerifiedAdc1V2>(StringComparer.Ordinal);
        foreach (var capability in capabilities)
        {
            var checkpoint = capability.Checkpoint;
            var key = Convert.ToHexString(checkpoint.DirectoryLeafKey.Span);
            if (!Fixed(checkpoint.NetworkId.Span, authority.NetworkId.Span) ||
                !current.TryAdd(key, capability) ||
                !map.TryGetValue(key, out var reference) ||
                !Fixed(reference, checkpoint.ArtifactReference.Span))
                Fail("CurrentCheckpointMismatch", "Current V2 capabilities do not exactly close the protected map.");
        }
        if (current.Count != map.Count)
            Fail("CurrentCheckpointIncomplete", "The authority omitted a current V2 checkpoint.");
        return current;
    }

    private static VerifiedAdc1V2[] ValidateSuccessors(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<VerifiedAdc1V2> successors,
        IReadOnlyDictionary<string, VerifiedAdc1V2> current)
    {
        var ordered = successors.OrderBy(static value =>
                value.Checkpoint.DirectoryLeafKey.ToArray(), ByteArrayComparer.Instance)
            .ThenBy(static value => value.Checkpoint.CheckpointGeneration)
            .ThenBy(static value => value.Checkpoint.ArtifactReference.ToArray(),
                ByteArrayComparer.Instance).ToArray();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var capability in ordered)
        {
            var checkpoint = capability.Checkpoint;
            var key = Convert.ToHexString(checkpoint.DirectoryLeafKey.Span);
            if (!Fixed(checkpoint.NetworkId.Span, authority.NetworkId.Span))
                Fail("NetworkMismatch", "A successor V2 checkpoint belongs to another network.");
            if (!seen.Add(key))
                Fail("DuplicateLeafMutation", "One DID2 head batch may advance a leaf only once.");
            if (!current.TryGetValue(key, out var prior))
            {
                if (checkpoint.CheckpointGeneration != 0 ||
                    checkpoint.PredecessorCheckpointHash.Span.IndexOfAnyExcept((byte)0) >= 0)
                    Fail("InvalidFirstAdmission", "A new DID2 leaf must start at ADC1 V2 generation zero.");
            }
            else
            {
                var previous = prior.Checkpoint;
                if (checkpoint.CheckpointGeneration != checked(previous.CheckpointGeneration + 1) ||
                    !Fixed(checkpoint.PredecessorCheckpointHash.Span,
                        previous.ArtifactHash.Span) ||
                    checkpoint.AccountGeneration != previous.AccountGeneration)
                    Fail("InvalidCheckpointSuccessor", "ADC1 V2 does not exactly advance its current predecessor.");
            }
        }
        return ordered;
    }

    private static SignerBinding[] ValidateSigners(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<IAccountDirectoryAdh1WitnessSigner> signers)
    {
        if (signers.Count is < 1 or > 32)
            Fail("InsufficientSigners", "ADH1 requires one to 32 witnesses.");
        var result = new SignerBinding[signers.Count];
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < signers.Count; index++)
        {
            var signer = signers[index] ?? throw new AccountDirectoryHeadAuthoringException(
                "UnknownSigner", "A configured ADH1 witness is null.");
            var id = signer.WitnessId.ToArray();
            if (id.Length != 32 || id.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !ids.Add(Convert.ToHexString(id)))
                Fail("DuplicateOrInvalidSigner", "ADH1 witness IDs must be exact, nonzero and unique.");
            var key = authority.WitnessKeys.SingleOrDefault(candidate =>
                Fixed(candidate.Id.Span, id));
            if (key is null)
                Fail("UnknownSigner", "An ADH1 witness is outside the current witness set.");
            domains.Add(Convert.ToHexString(key.FailureDomainHash.Span));
            result[index] = new SignerBinding(signer, id,
                key.Ed25519PublicKey.ToArray());
        }
        if (result.Length < authority.WitnessThreshold ||
            domains.Count < authority.WitnessThreshold)
            Fail("InsufficientSigners", "ADH1 witnesses do not meet the failure-domain threshold.");
        Array.Sort(result, static (left, right) =>
            left.Id.AsSpan().SequenceCompareTo(right.Id));
        return result;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new AccountDirectoryHeadAuthoringException(code, message);

    private sealed record SignerBinding(IAccountDirectoryAdh1WitnessSigner Signer,
        byte[] Id, byte[] PublicKey);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) =>
            left.AsSpan().SequenceCompareTo(right);
    }
}
