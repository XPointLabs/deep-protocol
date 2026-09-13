using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryHeadAuthoringException : CryptographicException
{
    internal AccountDirectoryHeadAuthoringException(
        string code,
        string message,
        Exception? inner = null) : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Custody boundary for one ADH1 witness. The implementation owns its private
/// key; the protocol author supplies and subsequently verifies only the exact
/// canonical ADH1 signing input.
/// </summary>
public interface IAccountDirectoryAdh1WitnessSigner
{
    ReadOnlyMemory<byte> WitnessId { get; }

    ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(
        ReadOnlyMemory<byte> signingInput,
        CancellationToken cancellationToken);
}

/// <summary>
/// Complete authority-held state required to advance one directory head. The
/// transition preimages are deliberately authority-private and are never a
/// public directory index.
/// </summary>
public sealed class AccountDirectoryHeadMutationRequest
{
    private readonly ReadOnlyMemory<byte>[] priorTransitions;
    private readonly VerifiedAccountDirectoryCheckpoint[] currentCheckpoints;
    private readonly VerifiedAccountDirectoryCheckpoint[] successors;

    public AccountDirectoryHeadMutationRequest(
        IReadOnlyList<ReadOnlyMemory<byte>> exactPriorTransitions,
        IReadOnlyList<VerifiedAccountDirectoryCheckpoint> currentCheckpoints,
        IReadOnlyList<VerifiedAccountDirectoryCheckpoint> successors,
        ulong validFromUnixSeconds,
        ulong validUntilUnixSeconds,
        ushort minimumReader)
    {
        ArgumentNullException.ThrowIfNull(exactPriorTransitions);
        ArgumentNullException.ThrowIfNull(currentCheckpoints);
        ArgumentNullException.ThrowIfNull(successors);
        if (successors.Count > 4096)
            throw new ArgumentOutOfRangeException(nameof(successors));
        if (validUntilUnixSeconds <= validFromUnixSeconds ||
            validUntilUnixSeconds - validFromUnixSeconds > 86_400)
            throw new ArgumentOutOfRangeException(nameof(validUntilUnixSeconds));
        if (minimumReader == 0)
            throw new ArgumentOutOfRangeException(nameof(minimumReader));

        priorTransitions = CopyTransitions(exactPriorTransitions);
        this.currentCheckpoints = CopyCapabilities(currentCheckpoints, nameof(currentCheckpoints));
        this.successors = CopyCapabilities(successors, nameof(successors));
        ValidFromUnixSeconds = validFromUnixSeconds;
        ValidUntilUnixSeconds = validUntilUnixSeconds;
        MinimumReader = minimumReader;
    }

    public IReadOnlyList<ReadOnlyMemory<byte>> ExactPriorTransitions =>
        priorTransitions.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
    public IReadOnlyList<VerifiedAccountDirectoryCheckpoint> CurrentCheckpoints =>
        currentCheckpoints.ToArray();
    public IReadOnlyList<VerifiedAccountDirectoryCheckpoint> Successors => successors.ToArray();
    public ulong ValidFromUnixSeconds { get; }
    public ulong ValidUntilUnixSeconds { get; }
    public ushort MinimumReader { get; }

    private static ReadOnlyMemory<byte>[] CopyTransitions(
        IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        if (values.Count > 1_000_000)
            throw new ArgumentOutOfRangeException(nameof(values));
        var result = new ReadOnlyMemory<byte>[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            if (values[index].Length != AccountDirectoryTransitionCodec.CanonicalLength)
                throw new ArgumentException("Every prior transition must be exact canonical ADT1 bytes.", nameof(values));
            result[index] = values[index].ToArray();
        }
        return result;
    }

    private static VerifiedAccountDirectoryCheckpoint[] CopyCapabilities(
        IReadOnlyList<VerifiedAccountDirectoryCheckpoint> values,
        string name)
    {
        if (values.Count > 1_000_000)
            throw new ArgumentOutOfRangeException(name);
        var result = new VerifiedAccountDirectoryCheckpoint[values.Count];
        for (var index = 0; index < values.Count; index++)
            result[index] = values[index] ?? throw new ArgumentException("Directory checkpoint capability is null.", name);
        return result;
    }
}

public sealed class AuthoredAccountDirectoryHeadMutation
{
    private readonly byte[] exactAdh1;
    private readonly byte[] coreHash;
    private readonly ReadOnlyMemory<byte>[] exactTransitions;
    private readonly ReadOnlyMemory<byte>[] exactAllTransitions;

    internal AuthoredAccountDirectoryHeadMutation(
        ReadOnlySpan<byte> exactAdh1,
        ReadOnlySpan<byte> coreHash,
        IReadOnlyList<ReadOnlyMemory<byte>> exactTransitions,
        IReadOnlyList<ReadOnlyMemory<byte>> exactAllTransitions,
        AccountDirectoryProtectedLkg protectedHead)
    {
        this.exactAdh1 = exactAdh1.ToArray();
        this.coreHash = coreHash.ToArray();
        this.exactTransitions = Copy(exactTransitions);
        this.exactAllTransitions = Copy(exactAllTransitions);
        ProtectedHead = protectedHead;
    }

    public ReadOnlyMemory<byte> ExactAdh1 => exactAdh1.ToArray();
    public ReadOnlyMemory<byte> CoreHash => coreHash.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactTransitions => Copy(exactTransitions);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactAllTransitions => Copy(exactAllTransitions);
    public AccountDirectoryProtectedLkg ProtectedHead { get; }

    private static ReadOnlyMemory<byte>[] Copy(IEnumerable<ReadOnlyMemory<byte>> values) =>
        values.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
}

/// <summary>
/// Replays the complete private transition journal, applies a bounded canonical
/// batch, obtains the current XNA witness threshold, and returns only after the
/// resulting ADH1 has been independently verified back into a protected LKG.
/// </summary>
public static class AccountDirectoryHeadAuthor
{
    private const string TransitionDomain = "Deep/AccountDirectory/V1/transition";
    private static readonly byte[][] SparseEmpty = BuildSparseEmpty();

    public static async ValueTask<AuthoredAccountDirectoryHeadMutation> AdvanceAsync(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProtectedLkg predecessor,
        AccountDirectoryHeadMutationRequest request,
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
            var journal = request.ExactPriorTransitions.Select(static value => value.ToArray()).ToList();
            var map = ReplayAndValidatePredecessor(predecessor, journal);
            var current = ValidateCurrentCapabilities(authority, request.CurrentCheckpoints, map);
            var ordered = ValidateAndOrderSuccessors(authority, request.Successors, current);
            var authored = new List<ReadOnlyMemory<byte>>(ordered.Length);

            foreach (var successor in ordered)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var checkpoint = successor.Checkpoint;
                var leaf = checkpoint.DirectoryLeafKey.ToArray();
                var leafKey = Convert.ToHexString(leaf);
                var previousReference = map.TryGetValue(leafKey, out var previous)
                    ? previous
                    : new byte[38];
                var previousRoot = ComputeSparseRoot(map);
                var nextReference = CheckpointReference(checkpoint);
                map[leafKey] = nextReference;
                var nextRoot = ComputeSparseRoot(map);
                var transition = new AccountDirectoryTransition(
                    checked((ulong)journal.Count),
                    leaf,
                    previousReference,
                    nextReference,
                    previousRoot,
                    nextRoot);
                var exact = AccountDirectoryTransitionCodec.Encode(transition);
                journal.Add(exact);
                authored.Add(exact);
            }

            var appendRoot = ComputeAppendRoot(journal);
            var mapRoot = ComputeSparseRoot(map);
            var unsigned = new AccountDirectoryAdh1(
                authority.NetworkId.Span,
                checked(predecessor.LogGeneration + 1),
                predecessor.CoreHash.Span,
                checked((ulong)journal.Count),
                appendRoot,
                mapRoot,
                authority.AuthorityCoreReference.Span,
                authority.DirectoryWitnessPolicyHash.Span,
                request.ValidFromUnixSeconds,
                request.ValidUntilUnixSeconds,
                request.MinimumReader,
                signers.Select(static signer => new AccountDirectoryAdh1WitnessEntry(
                    signer.Id, Enumerable.Repeat((byte)1, 64).ToArray())).ToArray());
            var signingInput = AccountDirectoryCrypto.ComputeAdh1SigningInput(unsigned);
            var receipts = new List<AccountDirectoryAdh1WitnessEntry>(signers.Length);
            try
            {
                foreach (var signer in signers)
                {
                    var returned = await signer.Signer.SignAdh1Async(
                        signingInput.ToArray(), cancellationToken).ConfigureAwait(false);
                    var signature = returned.ToArray();
                    try
                    {
                        if (signature.Length != 64 || signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                            !PublicKeyAuth.VerifyDetached(signature, signingInput, signer.PublicKey))
                            Fail("InvalidSignerResult", "A configured witness returned an invalid ADH1 signature.");
                        receipts.Add(new AccountDirectoryAdh1WitnessEntry(signer.Id, signature));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(signature);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signingInput);
            }

            var head = new AccountDirectoryAdh1(
                authority.NetworkId.Span,
                unsigned.LogGeneration,
                predecessor.CoreHash.Span,
                unsigned.TreeSize,
                appendRoot,
                mapRoot,
                authority.AuthorityCoreReference.Span,
                authority.DirectoryWitnessPolicyHash.Span,
                request.ValidFromUnixSeconds,
                request.ValidUntilUnixSeconds,
                request.MinimumReader,
                receipts);
            var exactAdh1 = AccountDirectoryAdh1Codec.Encode(head);
            var coreHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            var protectedHead = AccountDirectoryProtectedLkgFactory.Restore(
                authority, exactAdh1, coreHash);
            return new AuthoredAccountDirectoryHeadMutation(
                exactAdh1,
                coreHash,
                authored,
                journal.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
                protectedHead);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (AccountDirectoryHeadAuthoringException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or
            CryptographicException or OverflowException)
        {
            throw new AccountDirectoryHeadAuthoringException(
                "AuthoringRejected",
                "The account-directory head mutation failed closed.",
                exception);
        }
    }

    private static void ValidateAuthority(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProtectedLkg predecessor,
        AccountDirectoryHeadMutationRequest request)
    {
        var head = predecessor.Head;
        if (!Fixed(authority.NetworkId.Span, head.NetworkId.Span) ||
            !Fixed(authority.AuthorityCoreReference.Span, head.ExactXnaAuthorityCoreReference.Span) ||
            !Fixed(authority.DirectoryWitnessPolicyHash.Span, head.WitnessPolicyHash.Span))
            Fail("AuthorityMismatch", "The predecessor head is outside the exact current XPoint authority.");
        if (request.ValidFromUnixSeconds < authority.NotBefore ||
            request.ValidUntilUnixSeconds > authority.ExpiresAt)
            Fail("TimeOutsideAuthority", "The candidate ADH1 interval is outside the current XPoint authority.");
        if (request.MinimumReader < head.MinimumReader)
            Fail("ReaderRollback", "The candidate ADH1 reader floor rolls back its predecessor.");
        if ((ulong)request.ExactPriorTransitions.Count != head.TreeSize)
            Fail("JournalLengthMismatch", "The private transition journal does not match the predecessor tree size.");
    }

    private static Dictionary<string, byte[]> ReplayAndValidatePredecessor(
        AccountDirectoryProtectedLkg predecessor,
        IReadOnlyList<byte[]> journal)
    {
        var map = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        for (var index = 0; index < journal.Count; index++)
        {
            var transition = AccountDirectoryTransitionCodec.Decode(journal[index]);
            if (transition.LogIndex != (ulong)index)
                Fail("JournalIndexMismatch", "The private transition journal has a non-contiguous log index.");
            var key = Convert.ToHexString(transition.DirectoryLeafKey.Span);
            var actualPrevious = map.TryGetValue(key, out var value) ? value : new byte[38];
            if (!Fixed(actualPrevious, transition.PreviousAdc1Reference.Span) ||
                !Fixed(ComputeSparseRoot(map), transition.PreviousMapRoot.Span))
                Fail("JournalPredecessorMismatch", "A private directory transition does not consume the current map state.");
            map[key] = transition.NextAdc1Reference.ToArray();
            if (!Fixed(ComputeSparseRoot(map), transition.NextMapRoot.Span))
                Fail("JournalSuccessorMismatch", "A private directory transition does not produce its committed map root.");
        }
        if (!Fixed(ComputeAppendRoot(journal), predecessor.AppendLogMerkleRoot.Span) ||
            !Fixed(ComputeSparseRoot(map), predecessor.CurrentValueMapRoot.Span))
            Fail("JournalRootMismatch", "The private transition journal does not reconstruct the predecessor ADH1 roots.");
        return map;
    }

    private static Dictionary<string, VerifiedAccountDirectoryCheckpoint> ValidateCurrentCapabilities(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<VerifiedAccountDirectoryCheckpoint> current,
        IReadOnlyDictionary<string, byte[]> map)
    {
        var result = new Dictionary<string, VerifiedAccountDirectoryCheckpoint>(StringComparer.Ordinal);
        foreach (var capability in current)
        {
            var checkpoint = capability.Checkpoint;
            if (!Fixed(checkpoint.NetworkId.Span, authority.NetworkId.Span))
                Fail("NetworkMismatch", "A current ADC1 capability belongs to another network.");
            var key = Convert.ToHexString(checkpoint.DirectoryLeafKey.Span);
            if (!result.TryAdd(key, capability) || !map.TryGetValue(key, out var reference) ||
                !Fixed(reference, CheckpointReference(checkpoint)))
                Fail("CurrentCheckpointMismatch", "Current ADC1 capabilities do not exactly close the predecessor map.");
        }
        if (result.Count != map.Count)
            Fail("CurrentCheckpointIncomplete", "The authority omitted a current ADC1 capability from its private map state.");
        return result;
    }

    private static VerifiedAccountDirectoryCheckpoint[] ValidateAndOrderSuccessors(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<VerifiedAccountDirectoryCheckpoint> successors,
        IReadOnlyDictionary<string, VerifiedAccountDirectoryCheckpoint> current)
    {
        var ordered = successors.OrderBy(static value => value.Checkpoint.DirectoryLeafKey.ToArray(), ByteArrayComparer.Instance)
            .ThenBy(static value => value.Checkpoint.CheckpointGeneration)
            .ThenBy(static value => CheckpointReference(value.Checkpoint), ByteArrayComparer.Instance)
            .ToArray();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var capability in ordered)
        {
            var checkpoint = capability.Checkpoint;
            if (!Fixed(checkpoint.NetworkId.Span, authority.NetworkId.Span))
                Fail("NetworkMismatch", "A successor ADC1 capability belongs to another network.");
            var key = Convert.ToHexString(checkpoint.DirectoryLeafKey.Span);
            if (!seen.Add(key))
                Fail("DuplicateLeafMutation", "One ADH1 batch may advance a directory leaf only once.");
            if (!current.TryGetValue(key, out var predecessor))
            {
                if (checkpoint.CheckpointGeneration != 0 ||
                    checkpoint.PredecessorCheckpointHash.Span.IndexOfAnyExcept((byte)0) >= 0)
                    Fail("InvalidFirstAdmission", "A new directory leaf must start at ADC1 generation zero.");
            }
            else
            {
                var previous = predecessor.Checkpoint;
                var previousHash = SHA256.HashData(AccountDirectoryAdc1Codec.Encode(previous));
                if (checkpoint.CheckpointGeneration != checked(previous.CheckpointGeneration + 1) ||
                    !Fixed(checkpoint.PredecessorCheckpointHash.Span, previousHash) ||
                    checkpoint.AccountGeneration != previous.AccountGeneration)
                    Fail("InvalidCheckpointSuccessor", "ADC1 does not exactly advance its current predecessor.");
            }
        }
        return ordered;
    }

    private static SignerBinding[] ValidateSigners(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<IAccountDirectoryAdh1WitnessSigner> signers)
    {
        if (signers.Count is < 1 or > 32)
            Fail("InsufficientSigners", "ADH1 requires between one and 32 configured witnesses.");
        var result = new SignerBinding[signers.Count];
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < signers.Count; index++)
        {
            var signer = signers[index] ?? throw new AccountDirectoryHeadAuthoringException(
                "UnknownSigner", "A configured ADH1 signer is null.");
            var id = signer.WitnessId.ToArray();
            if (id.Length != 32 || id.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !ids.Add(Convert.ToHexString(id)))
                Fail("DuplicateOrInvalidSigner", "ADH1 signer IDs must be exact, nonzero, and unique.");
            var key = authority.WitnessKeys.SingleOrDefault(candidate => Fixed(candidate.Id.Span, id));
            if (key is null)
                Fail("UnknownSigner", "An ADH1 signer is outside the exact current witness set.");
            domains.Add(Convert.ToHexString(key.FailureDomainHash.Span));
            result[index] = new SignerBinding(signer, id, key.Ed25519PublicKey.ToArray());
        }
        if (result.Length < authority.WitnessThreshold || domains.Count < authority.WitnessThreshold)
            Fail("InsufficientSigners", "Configured ADH1 witnesses do not meet the exact failure-domain threshold.");
        Array.Sort(result, static (left, right) => left.Id.AsSpan().SequenceCompareTo(right.Id));
        return result;
    }

    private static byte[] CheckpointReference(AccountDirectoryAdc1 checkpoint) =>
        AccountDirectoryCrypto.CreateReference(
            "ADC1"u8,
            1,
            SHA256.HashData(AccountDirectoryAdc1Codec.Encode(checkpoint)));

    private static byte[] ComputeAppendRoot(IReadOnlyList<byte[]> transitions)
    {
        if (transitions.Count == 0)
            return AccountDirectoryRfc6962.ComputeEmptyTreeHash();
        var leaves = transitions.Select(static transition =>
            AccountDirectoryRfc6962.ComputeLeafHash(
                AccountDirectoryCrypto.Sha256Domain(TransitionDomain, transition))).ToArray();
        return MerkleTreeHash(leaves, 0, leaves.Length);
    }

    private static byte[] MerkleTreeHash(IReadOnlyList<byte[]> leaves, int offset, int count)
    {
        if (count == 1)
            return leaves[offset].ToArray();
        var split = LargestPowerOfTwoLessThan(count);
        return AccountDirectoryRfc6962.ComputeNodeHash(
            MerkleTreeHash(leaves, offset, split),
            MerkleTreeHash(leaves, offset + split, count - split));
    }

    private static int LargestPowerOfTwoLessThan(int value)
    {
        var result = 1;
        while (checked(result * 2) < value)
            result *= 2;
        return result;
    }

    private static byte[] ComputeSparseRoot(IReadOnlyDictionary<string, byte[]> entries)
    {
        if (entries.Count == 0)
            return AccountDirectorySparseMap.EmptyMapRoot.ToArray();
        var nodes = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            var key = Convert.FromHexString(entry.Key);
            nodes[entry.Key] = PresentLeaf(key, entry.Value);
        }

        for (var level = 0; level < 256; level++)
        {
            var next = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            var consumed = new HashSet<string>(StringComparer.Ordinal);
            foreach (var entry in nodes)
            {
                if (!consumed.Add(entry.Key))
                    continue;
                var position = Convert.FromHexString(entry.Key);
                ToggleBit(position, 255 - level);
                var siblingKey = Convert.ToHexString(position);
                var sibling = nodes.TryGetValue(siblingKey, out var present)
                    ? present
                    : SparseEmpty[level];
                consumed.Add(siblingKey);
                ToggleBit(position, 255 - level);
                var isRight = Bit(position, 255 - level);
                var parent = isRight
                    ? SparseNode(sibling, entry.Value)
                    : SparseNode(entry.Value, sibling);
                ClearBit(position, 255 - level);
                next[Convert.ToHexString(position)] = parent;
            }
            nodes = next;
        }
        return nodes.Single().Value;
    }

    private static byte[] PresentLeaf(ReadOnlySpan<byte> key, ReadOnlySpan<byte> reference)
    {
        var payload = new byte[70];
        key.CopyTo(payload);
        reference.CopyTo(payload.AsSpan(32));
        return AccountDirectoryCrypto.Sha256Domain(
            "Deep/AccountDirectory/V1/map-present", payload);
    }

    private static byte[] SparseNode(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        Span<byte> pair = stackalloc byte[64];
        left.CopyTo(pair);
        right.CopyTo(pair[32..]);
        return AccountDirectoryCrypto.Sha256Domain(
            "Deep/AccountDirectory/V1/map-node", pair);
    }

    private static byte[][] BuildSparseEmpty()
    {
        var result = new byte[257][];
        result[0] = AccountDirectoryCrypto.Sha256Domain(
            "Deep/AccountDirectory/V1/map-empty-leaf", []);
        Span<byte> pair = stackalloc byte[64];
        for (var index = 0; index < 256; index++)
        {
            result[index].CopyTo(pair);
            result[index].CopyTo(pair[32..]);
            result[index + 1] = AccountDirectoryCrypto.Sha256Domain(
                "Deep/AccountDirectory/V1/map-node", pair);
        }
        return result;
    }

    private static bool Bit(ReadOnlySpan<byte> value, int bit) =>
        (value[bit / 8] & (0x80 >> (bit % 8))) != 0;

    private static void ToggleBit(Span<byte> value, int bit) =>
        value[bit / 8] ^= checked((byte)(0x80 >> (bit % 8)));

    private static void ClearBit(Span<byte> value, int bit) =>
        value[bit / 8] &= unchecked((byte)~(0x80 >> (bit % 8)));

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new AccountDirectoryHeadAuthoringException(code, message);

    private sealed record SignerBinding(
        IAccountDirectoryAdh1WitnessSigner Signer,
        byte[] Id,
        byte[] PublicKey);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
