using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class DeepIdV2DirectoryJournalTests
{
    [Fact]
    public void ReplayV2_ClosesTwoAdmissionsOverExactHeadRoots()
    {
        var (journal, head, map) = Fixture();
        var replayed = DeepIdV2DirectoryJournal.ReplayAndVerify(head, journal);

        Assert.Equal(map.Count, replayed.Count);
        foreach (var entry in map)
            Assert.Equal(entry.Value, replayed[entry.Key]);
        Assert.Equal(head.AppendLogMerkleRoot.ToArray(),
            DeepIdV2DirectoryJournal.ComputeAppendRoot(journal));
    }

    [Fact]
    public void ReplayV2_RejectsGapWrongRootAndLegacyReference()
    {
        var (journal, head, _) = Fixture();
        var wrongIndex = journal.Select(static value => value.ToArray()).ToArray();
        BinaryPrimitives.WriteUInt64BigEndian(wrongIndex[1].AsSpan(2), 3);
        Assert.Throws<CryptographicException>(() =>
            DeepIdV2DirectoryJournal.ReplayAndVerify(head,
                wrongIndex.Select(static bytes => (ReadOnlyMemory<byte>)bytes).ToArray()));

        var wrongRoot = journal.Select(static value => value.ToArray()).ToArray();
        wrongRoot[1][150] ^= 1;
        Assert.Throws<CryptographicException>(() =>
            DeepIdV2DirectoryJournal.ReplayAndVerify(head,
                wrongRoot.Select(static bytes => (ReadOnlyMemory<byte>)bytes).ToArray()));

        var oldReference = journal.Select(static value => value.ToArray()).ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(oldReference[1].AsSpan(84), 1);
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            DeepIdV2DirectoryJournal.ReplayAndVerify(head,
                oldReference.Select(static bytes => (ReadOnlyMemory<byte>)bytes).ToArray()));

        var wrongHead = Head(2, Bytes(32, 0x7a), head.CurrentValueMapRoot.Span,
            minimumReader: 2);
        Assert.Throws<CryptographicException>(() =>
            DeepIdV2DirectoryJournal.ReplayAndVerify(wrongHead, journal));
        var oldReader = Head(2, head.AppendLogMerkleRoot.Span,
            head.CurrentValueMapRoot.Span, minimumReader: 1);
        Assert.Throws<CryptographicException>(() =>
            DeepIdV2DirectoryJournal.ReplayAndVerify(oldReader, journal));
    }

    private static (ReadOnlyMemory<byte>[] Journal,
        AccountDirectoryProtectedLkg Head,
        Dictionary<string, byte[]> Map) Fixture()
    {
        var first = Bytes(32, 0x10);
        var second = first.ToArray();
        second[^1] ^= 1;
        var firstRef = Reference(Bytes(32, 0x40));
        var secondRef = Reference(Bytes(32, 0x50));
        var map = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var initialRoot = DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray();
        map[Convert.ToHexString(first)] = firstRef;
        var firstRoot = DeepIdV2DirectorySparseMap.ComputeFullMapRoot(map);
        var firstTransition = DeepIdV2DirectoryTransitionCodec.Author(0,
            first, new byte[38], firstRef, initialRoot, firstRoot);
        map[Convert.ToHexString(second)] = secondRef;
        var secondRoot = DeepIdV2DirectorySparseMap.ComputeFullMapRoot(map);
        var secondTransition = DeepIdV2DirectoryTransitionCodec.Author(1,
            second, new byte[38], secondRef, firstRoot, secondRoot);
        ReadOnlyMemory<byte>[] journal =
        [firstTransition.CanonicalBytes, secondTransition.CanonicalBytes];
        var appendRoot = DeepIdV2DirectoryJournal.ComputeAppendRoot(journal);
        return (journal, Head(2, appendRoot, secondRoot,
            minimumReader: 2), map);
    }

    private static AccountDirectoryProtectedLkg Head(ulong treeSize,
        ReadOnlySpan<byte> appendRoot32, ReadOnlySpan<byte> mapRoot32,
        ushort minimumReader)
    {
        var authorityReference = new byte[38];
        "XNA1"u8.CopyTo(authorityReference);
        BinaryPrimitives.WriteUInt16BigEndian(authorityReference.AsSpan(4), 1);
        Bytes(32, 9).CopyTo(authorityReference, 6);
        var head = new AccountDirectoryAdh1(Bytes(16, 1), 0,
            new byte[32], treeSize, appendRoot32, mapRoot32,
            authorityReference, Bytes(32, 8), 1, 3601, minimumReader,
            [new AccountDirectoryAdh1WitnessEntry(Bytes(32, 10), Bytes(64, 11))]);
        return new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(head));
    }

    private static byte[] Reference(byte[] hash)
    {
        var reference = new byte[38];
        "ADC1"u8.CopyTo(reference);
        BinaryPrimitives.WriteUInt16BigEndian(reference.AsSpan(4), 2);
        hash.CopyTo(reference, 6);
        return reference;
    }

    private static byte[] Bytes(int length, byte first) =>
        Enumerable.Range(0, length).Select(index =>
            unchecked((byte)(first + index))).ToArray();
}
