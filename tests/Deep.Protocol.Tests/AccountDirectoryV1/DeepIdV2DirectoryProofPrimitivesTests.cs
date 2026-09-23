using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class DeepIdV2DirectoryProofPrimitivesTests
{
    [Fact]
    public void TransitionV2_RoundTripsAndCommitsExactV2Bytes()
    {
        var leaf = Bytes(32, 0x10);
        var next = AdcReference(2, Bytes(32, 0x20));
        var transition = DeepIdV2DirectoryTransitionCodec.Author(7, leaf,
            new byte[38], next, Bytes(32, 0x30), Bytes(32, 0x40));
        var canonical = transition.CanonicalBytes.ToArray();
        var parsed = DeepIdV2DirectoryTransitionCodec.Decode(canonical);

        Assert.Equal(182, canonical.Length);
        Assert.Equal((ushort)2, BinaryPrimitives.ReadUInt16BigEndian(canonical));
        Assert.Equal(7UL, parsed.LogIndex);
        Assert.Equal(DomainHash("Deep/AccountDirectory/V2/transition", canonical),
            parsed.Commitment.ToArray());
        Assert.Equal(AccountDirectoryRfc6962.ComputeLeafHash(parsed.Commitment.Span),
            parsed.AppendLogLeafHash.ToArray());
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            AccountDirectoryTransitionCodec.Decode(canonical));
        var owned = parsed.CanonicalBytes.ToArray();
        owned[10] ^= 1;
        Assert.NotEqual(owned, parsed.CanonicalBytes.ToArray());
    }

    [Fact]
    public void TransitionV2_RejectsOldReferencesAndMalformedFields()
    {
        var valid = DeepIdV2DirectoryTransitionCodec.Author(0, Bytes(32, 1),
            new byte[38], AdcReference(2, Bytes(32, 2)), Bytes(32, 3),
            Bytes(32, 4)).CanonicalBytes.ToArray();
        Action<byte[]>[] mutations =
        [
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes, 1),
            bytes => Array.Clear(bytes, 10, 32),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(84), 1),
            bytes => Array.Clear(bytes, 80, 38),
            bytes => Array.Clear(bytes, 118, 32),
            bytes => Array.Clear(bytes, 150, 32)
        ];
        foreach (var mutate in mutations)
        {
            var bytes = valid.ToArray();
            mutate(bytes);
            Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
                DeepIdV2DirectoryTransitionCodec.Decode(bytes));
        }
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            DeepIdV2DirectoryTransitionCodec.Decode(valid[..^1]));
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            DeepIdV2DirectoryTransitionCodec.Decode([.. valid, 0]));
        var oldPredecessor = valid.ToArray();
        AdcReference(1, Bytes(32, 5)).CopyTo(oldPredecessor, 42);
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            DeepIdV2DirectoryTransitionCodec.Decode(oldPredecessor));
    }

    [Fact]
    public void SparseMapV2_HasIndependentEmptyAndPresentRoots()
    {
        var leaf = Bytes(32, 0x10);
        var reference = AdcReference(2, Bytes(32, 0x20));
        var bitmap = new byte[32];
        var expectedEmpty = IndependentEmpty();
        Assert.Equal(expectedEmpty[256], DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray());
        Assert.Equal(expectedEmpty[256],
            DeepIdV2DirectorySparseMap.ComputeNonMembershipRoot(leaf, bitmap, []));
        Assert.NotEqual(AccountDirectorySparseMap.EmptyMapRoot.ToArray(),
            expectedEmpty[256]);

        Span<byte> presentPreimage = stackalloc byte[70];
        leaf.CopyTo(presentPreimage);
        reference.CopyTo(presentPreimage[32..]);
        var current = DomainHash("Deep/AccountDirectory/V2/map-present",
            presentPreimage);
        Span<byte> pair = stackalloc byte[64];
        for (var level = 0; level < 256; level++)
        {
            var keyIndex = 255 - level;
            var right = (leaf[keyIndex / 8] & (0x80 >> (keyIndex % 8))) != 0;
            if (right)
            {
                expectedEmpty[level].CopyTo(pair);
                current.CopyTo(pair[32..]);
            }
            else
            {
                current.CopyTo(pair);
                expectedEmpty[level].CopyTo(pair[32..]);
            }
            current = DomainHash("Deep/AccountDirectory/V2/map-node", pair);
        }
        Assert.Equal(current, DeepIdV2DirectorySparseMap.ComputePresentRoot(
            leaf, reference, bitmap, []));
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            DeepIdV2DirectorySparseMap.ComputePresentRoot(leaf,
                AdcReference(1, Bytes(32, 0x20)), bitmap, []));
    }

    [Fact]
    public void SparseMapV2_RejectsMalformedAndExplicitDefaultSibling()
    {
        var leaf = Bytes(32, 0x10);
        var bitmap = new byte[32];
        bitmap[0] = 0x80;
        Assert.Throws<ArgumentException>(() =>
            DeepIdV2DirectorySparseMap.ComputeNonMembershipRoot(leaf, bitmap, []));
        var defaultSibling = IndependentEmpty()[0];
        Assert.Throws<ArgumentException>(() =>
            DeepIdV2DirectorySparseMap.ComputeNonMembershipRoot(leaf, bitmap,
                defaultSibling));
        var nonDefaultSibling = Bytes(32, 0x50);
        var root = DeepIdV2DirectorySparseMap.ComputeNonMembershipRoot(
            leaf, bitmap, nonDefaultSibling);
        nonDefaultSibling[0] ^= 1;
        Assert.NotEqual(root, DeepIdV2DirectorySparseMap.ComputeNonMembershipRoot(
            leaf, bitmap, nonDefaultSibling));
        Assert.Throws<ArgumentException>(() =>
            DeepIdV2DirectorySparseMap.ComputeNonMembershipRoot(
                new byte[32], new byte[32], []));
    }

    private static byte[][] IndependentEmpty()
    {
        var empty = new byte[257][];
        empty[0] = DomainHash("Deep/AccountDirectory/V2/map-empty-leaf", []);
        for (var level = 0; level < 256; level++)
            empty[level + 1] = DomainHash("Deep/AccountDirectory/V2/map-node",
                [.. empty[level], .. empty[level]]);
        return empty;
    }

    private static byte[] DomainHash(string domain, ReadOnlySpan<byte> payload)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var input = new byte[label.Length + 5 + payload.Length];
        label.CopyTo(input, 0);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(label.Length + 1),
            (uint)payload.Length);
        payload.CopyTo(input.AsSpan(label.Length + 5));
        return SHA256.HashData(input);
    }

    private static byte[] AdcReference(ushort version, byte[] hash)
    {
        var reference = new byte[38];
        "ADC1"u8.CopyTo(reference);
        BinaryPrimitives.WriteUInt16BigEndian(reference.AsSpan(4), version);
        hash.CopyTo(reference, 6);
        return reference;
    }

    private static byte[] Bytes(int length, byte first) =>
        Enumerable.Range(0, length).Select(index =>
            unchecked((byte)(first + index))).ToArray();
}
