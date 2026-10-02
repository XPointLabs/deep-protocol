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
            ProtocolMagicBytes.ADC1,
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
