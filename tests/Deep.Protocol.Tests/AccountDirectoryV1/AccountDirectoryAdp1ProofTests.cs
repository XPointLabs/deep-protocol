using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryAdp1ProofTests
{
    [Fact]
    public void SparseMap_EmptyAndPresentRootsMatchIndependentLiteralComputation()
    {
        var key = Bytes(32, 0x21);
        var reference = Reference("ADC1", Bytes(32, 0x31));
        var bitmap = new byte[32];

        Assert.Equal(IndependentEmptyHashes()[256], AccountDirectorySparseMap.EmptyMapRoot.ToArray());
        Assert.Equal(IndependentSparseRoot(key, null, bitmap, []),
            AccountDirectorySparseMap.ComputeNonMembershipRoot(key, bitmap, []));
        Assert.Equal(IndependentSparseRoot(key, reference, bitmap, []),
            AccountDirectorySparseMap.ComputePresentRoot(key, reference, bitmap, []));
    }

    [Fact]
    public void SparseMap_BitmapOrderAndKeyBitPlacementAreExactAndTamperEvident()
    {
        var key = Bytes(32, 0x41);
        key[^1] |= 1; // level zero selects the right-hand child.
        var sibling = Bytes(32, 0x51);
        var bitmap = new byte[32];
        bitmap[0] = 0x80; // level zero, MSB first.

        var expected = IndependentSparseRoot(key, null, bitmap, sibling);
        var actual = AccountDirectorySparseMap.ComputeNonMembershipRoot(key, bitmap, sibling);
        Assert.Equal(expected, actual);

        var changed = sibling.ToArray();
        changed[0] ^= 1;
        Assert.NotEqual(actual, AccountDirectorySparseMap.ComputeNonMembershipRoot(key, bitmap, changed));

        var oppositeKey = key.ToArray();
        oppositeKey[^1] &= 0xfe;
        Assert.NotEqual(actual, AccountDirectorySparseMap.ComputeNonMembershipRoot(oppositeKey, bitmap, sibling));
    }

    [Fact]
    public void SparseMap_RejectsWrongShapesAndExplicitDefaultSibling()
    {
        var key = Bytes(32, 0x61);
        var bitmap = new byte[32];
        bitmap[0] = 0x80;

        Assert.Throws<ArgumentException>(() => AccountDirectorySparseMap.ComputeNonMembershipRoot(key[..31], new byte[32], []));
        Assert.Throws<ArgumentException>(() => AccountDirectorySparseMap.ComputeNonMembershipRoot(key, new byte[31], []));
        Assert.Throws<ArgumentException>(() => AccountDirectorySparseMap.ComputeNonMembershipRoot(key, bitmap, []));
        Assert.Throws<ArgumentException>(() => AccountDirectorySparseMap.ComputeNonMembershipRoot(
            key, bitmap, IndependentEmptyHashes()[0]));
        Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectorySparseMap.ComputePresentRoot(
            key, new byte[38], new byte[32], []));
    }

    [Fact]
    public void SparseMap_AcceptsAll256ExplicitNonDefaultLevels()
    {
        var key = Bytes(32, 0x62);
        var bitmap = Enumerable.Repeat((byte)0xff, 32).ToArray();
        var siblings = new byte[256 * 32];
        for (var level = 0; level < 256; level++)
            Bytes(32, unchecked((byte)(level + 1))).CopyTo(siblings, level * 32);

        var expected = IndependentSparseRoot(key, null, bitmap, siblings);
        Assert.Equal(expected, AccountDirectorySparseMap.ComputeNonMembershipRoot(key, bitmap, siblings));
    }

    [Fact]
    public void Rfc6962_InclusionAcceptsCanonicalPathsAndRejectsTamperingOrNonminimalNodes()
    {
        var leaves = Enumerable.Range(1, 3)
            .Select(index => IndependentLeafHash(Bytes(32, checked((byte)index))))
            .ToArray();
        var left = IndependentNodeHash(leaves[0], leaves[1]);
        var root = IndependentNodeHash(left, leaves[2]);

        Assert.Equal(leaves[0], AccountDirectoryRfc6962.ComputeLeafHash(Bytes(32, 1)));
        Assert.Equal(left, AccountDirectoryRfc6962.ComputeNodeHash(leaves[0], leaves[1]));
        Assert.True(AccountDirectoryRfc6962.VerifyInclusion(leaves[0], 0, 3,
            Join(leaves[1], leaves[2]), root));
        Assert.True(AccountDirectoryRfc6962.VerifyInclusion(leaves[2], 2, 3, left, root));

        var tampered = Join(leaves[1], leaves[2]);
        tampered[0] ^= 1;
        Assert.False(AccountDirectoryRfc6962.VerifyInclusion(leaves[0], 0, 3, tampered, root));
        Assert.False(AccountDirectoryRfc6962.VerifyInclusion(leaves[0], 3, 3, Join(leaves[1], leaves[2]), root));
        Assert.False(AccountDirectoryRfc6962.VerifyInclusion(leaves[0], 0, 3,
            Join(leaves[1], leaves[2], leaves[2]), root));
        Assert.Throws<ArgumentException>(() => AccountDirectoryRfc6962.VerifyInclusion(
            leaves[0], 0, 3, new byte[65 * 32], root));
    }

    [Fact]
    public void Rfc6962_ConsistencyHandlesEmptyEqualAndGrowingTreesWithCheckedBounds()
    {
        var leaves = Enumerable.Range(1, 3)
            .Select(index => IndependentLeafHash(Bytes(32, checked((byte)index))))
            .ToArray();
        var root2 = IndependentNodeHash(leaves[0], leaves[1]);
        var root3 = IndependentNodeHash(root2, leaves[2]);
        var empty = SHA256.HashData([]);

        Assert.True(AccountDirectoryRfc6962.VerifyConsistency(0, 3, empty, root3, []));
        Assert.True(AccountDirectoryRfc6962.VerifyConsistency(0, 0, empty, empty, []));
        Assert.True(AccountDirectoryRfc6962.VerifyConsistency(3, 3, root3, root3, []));
        Assert.True(AccountDirectoryRfc6962.VerifyConsistency(1, 3, leaves[0], root3,
            Join(leaves[1], leaves[2])));
        Assert.True(AccountDirectoryRfc6962.VerifyConsistency(2, 3, root2, root3, leaves[2]));

        var changed = leaves[2].ToArray();
        changed[0] ^= 1;
        Assert.False(AccountDirectoryRfc6962.VerifyConsistency(2, 3, root2, root3, changed));
        Assert.False(AccountDirectoryRfc6962.VerifyConsistency(4, 3, root3, root3, []));
        Assert.False(AccountDirectoryRfc6962.VerifyConsistency(0, 0, empty, root3, []));
        Assert.False(AccountDirectoryRfc6962.VerifyConsistency(3, 3, root3, root3, leaves[0]));
        Assert.Throws<ArgumentException>(() => AccountDirectoryRfc6962.VerifyConsistency(
            1, 2, leaves[0], root2, new byte[31]));
    }

    [Fact]
    public void TransitionCodec_EnforcesExact182ByteTypedShape()
    {
        var canonical = Transition(
            7, Bytes(32, 0x71), Reference("ADC1", Bytes(32, 0x72)),
            Reference("ADC1", Bytes(32, 0x73)), Bytes(32, 0x74), Bytes(32, 0x75));
        var decoded = AccountDirectoryTransitionCodec.Decode(canonical);

        Assert.Equal(182, canonical.Length);
        Assert.Equal(7UL, decoded.LogIndex);
        Assert.Equal(canonical, AccountDirectoryTransitionCodec.Encode(decoded));

        foreach (var mutation in new Action<byte[]>[]
        {
            value => BinaryPrimitives.WriteUInt16BigEndian(value, 2),
            value => value[42] = (byte)'X',
            value => value[80] = (byte)'X',
            value => Array.Clear(value, 10, 32),
            value => Array.Clear(value, 118, 32),
            value => Array.Clear(value, 150, 32),
        })
        {
            var candidate = canonical.ToArray();
            mutation(candidate);
            Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryTransitionCodec.Decode(candidate));
        }
        Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryTransitionCodec.Decode(canonical[..^1]));
        Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryTransitionCodec.Decode(canonical.Concat([byte.MinValue]).ToArray()));
    }

    private static byte[] IndependentSparseRoot(
        ReadOnlySpan<byte> key,
        byte[]? presentReference,
        ReadOnlySpan<byte> bitmap,
        ReadOnlySpan<byte> siblings)
    {
        var empty = IndependentEmptyHashes();
        byte[] current;
        if (presentReference is null)
        {
            current = empty[0];
        }
        else
        {
            current = DomainHash("Deep/AccountDirectory/V1/map-present", Join(key.ToArray(), presentReference));
        }
        var offset = 0;
        for (var level = 0; level < 256; level++)
        {
            var supplied = (bitmap[level / 8] & (0x80 >> (level % 8))) != 0;
            var sibling = supplied ? siblings.Slice(offset, 32).ToArray() : empty[level];
            if (supplied) offset += 32;
            var keyBit = 255 - level;
            var right = (key[keyBit / 8] & (0x80 >> (keyBit % 8))) != 0;
            current = right
                ? DomainHash("Deep/AccountDirectory/V1/map-node", Join(sibling, current))
                : DomainHash("Deep/AccountDirectory/V1/map-node", Join(current, sibling));
        }
        return current;
    }

    private static byte[][] IndependentEmptyHashes()
    {
        var result = new byte[257][];
        result[0] = DomainHash("Deep/AccountDirectory/V1/map-empty-leaf", []);
        for (var level = 0; level < 256; level++)
            result[level + 1] = DomainHash("Deep/AccountDirectory/V1/map-node", Join(result[level], result[level]));
        return result;
    }

    private static byte[] DomainHash(string domain, ReadOnlySpan<byte> payload)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var preimage = new byte[label.Length + 5 + payload.Length];
        label.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(preimage.AsSpan(label.Length + 1), checked((uint)payload.Length));
        payload.CopyTo(preimage.AsSpan(label.Length + 5));
        return SHA256.HashData(preimage);
    }

    private static byte[] IndependentLeafHash(ReadOnlySpan<byte> commitment)
    {
        var input = new byte[33];
        input[0] = 0;
        commitment.CopyTo(input.AsSpan(1));
        return SHA256.HashData(input);
    }

    private static byte[] IndependentNodeHash(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var input = new byte[65];
        input[0] = 1;
        left.CopyTo(input.AsSpan(1));
        right.CopyTo(input.AsSpan(33));
        return SHA256.HashData(input);
    }

    private static byte[] Transition(ulong index, byte[] key, byte[] previous, byte[] next, byte[] oldRoot, byte[] newRoot) =>
        Join(U16(1), U64(index), key, previous, next, oldRoot, newRoot);

    private static byte[] Reference(string magic, byte[] hash) =>
        Join(Encoding.ASCII.GetBytes(magic), U16(1), hash);

    private static byte[] U16(ushort value) { var result = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(result, value); return result; }
    private static byte[] U64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
    private static byte[] Bytes(int length, byte seed) { var result = new byte[length]; for (var i = 0; i < length; i++) result[i] = unchecked((byte)(seed + i)); return result; }
    private static byte[] Join(params byte[][] values) { var result = new byte[values.Sum(static x => x.Length)]; var offset = 0; foreach (var value in values) { value.CopyTo(result, offset); offset += value.Length; } return result; }
}
