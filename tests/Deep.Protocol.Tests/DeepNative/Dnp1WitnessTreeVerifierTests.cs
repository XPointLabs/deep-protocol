using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

public sealed class WitnessTreeVerifierTests
{
    [Fact]
    public void Inclusion_TwoLeaves_UsesExactLevelAndNodeIndex()
    {
        var left=WitnessTreeVerifier.Leaf(Bytes(0x11,116));
        var right=WitnessTreeVerifier.Leaf(Bytes(0x22,116));
        var root=Node(0,0,left,right);

        WitnessTreeVerifier.VerifyInclusion(left,0,2,right,root);
        WitnessTreeVerifier.VerifyInclusion(right,1,2,left,root);
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.VerifyInclusion(left,0,2,left,root));
    }

    [Fact]
    public void Consistency_OneToTwo_UsesOldRootAsImplicitFirstNode()
    {
        var oldRoot=WitnessTreeVerifier.Leaf(Bytes(0x31,116));
        var sibling=WitnessTreeVerifier.Leaf(Bytes(0x32,116));
        var newRoot=Node(0,0,oldRoot,sibling);

        WitnessTreeVerifier.VerifyConsistency(1,oldRoot,2,newRoot,sibling,Bytes(0x7a,32));
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.VerifyConsistency(1,oldRoot,2,newRoot,Bytes(0x41,32),Bytes(0x7a,32)));
    }

    [Fact]
    public void InclusionAndConsistency_UnbalancedThreeLeafTree_AreExact()
    {
        var first=WitnessTreeVerifier.Leaf(Bytes(0x61,116));
        var second=WitnessTreeVerifier.Leaf(Bytes(0x62,116));
        var third=WitnessTreeVerifier.Leaf(Bytes(0x63,116));
        var firstPair=Node(0,0,first,second);
        var root=Node(1,0,firstPair,third);

        var firstProof=second.Concat(third).ToArray();
        WitnessTreeVerifier.VerifyInclusion(first,0,3,firstProof,root);
        WitnessTreeVerifier.VerifyInclusion(third,2,3,firstPair,root);
        WitnessTreeVerifier.VerifyConsistency(
            2,firstPair,3,root,third,Bytes(0x7b,32));
    }

    [Fact]
    public void Consistency_EmptyAndSameSize_AreCanonicalOnly()
    {
        var empty=WitnessTreeVerifier.EmptyRoot(1,Bytes(0x50,32),1024);
        var root=WitnessTreeVerifier.Leaf(Bytes(0x51,116));
        WitnessTreeVerifier.VerifyConsistency(0,empty,1,root,[],empty);
        WitnessTreeVerifier.VerifyConsistency(1,root,1,root,[],empty);

        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.VerifyConsistency(0,Bytes(0x52,32),1,root,[],empty));
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.VerifyConsistency(1,root,1,root,Bytes(0x53,32),empty));
    }

    [Fact]
    public void ProofAndEmptyRootBounds_RejectBeforeTreeWork()
    {
        var leaf=WitnessTreeVerifier.Leaf(Bytes(0x71,116));
        var empty=WitnessTreeVerifier.EmptyRoot(1,Bytes(0x72,32),1);

        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.VerifyInclusion(leaf,0,0,[],leaf));
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.VerifyInclusion(leaf,1,1,[],leaf));
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.VerifyInclusion(leaf,0,1,Bytes(0x73,31),leaf));
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.VerifyConsistency(2,leaf,1,leaf,[],empty));
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.VerifyConsistency(0,empty,1,leaf,Bytes(0x74,1056),empty));
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.EmptyRoot(0,Bytes(0x75,32),1));
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.EmptyRoot(1,new byte[32],1));
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.EmptyRoot(1,Bytes(0x76,32),0));
    }

    [Fact]
    public void CorruptInclusionConsistencyPriorHeadAndDurabilityRejectWithoutCallbacks()
    {
        var oldRoot = WitnessTreeVerifier.Leaf(Bytes(0x41, 116));
        var sibling = WitnessTreeVerifier.Leaf(Bytes(0x42, 116));
        var newRoot = Node(0, 0, oldRoot, sibling);

        WitnessTreeVerifier.VerifyInclusion(oldRoot, 0, 2, sibling, newRoot);
        WitnessTreeVerifier.VerifyConsistency(
            1, oldRoot, 2, newRoot, sibling, Bytes(0x43, 32));
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.VerifyInclusion(oldRoot, 0, 2, oldRoot, newRoot));
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.VerifyConsistency(
                1, oldRoot, 2, newRoot, Bytes(0x44, 32), Bytes(0x43, 32)));
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.VerifyConsistency(
                1, Bytes(0x45, 32), 2, newRoot, sibling, Bytes(0x43, 32)));

        var fields = RecordDefinitions.Dcn1.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength])
            .ToArray();
        fields[25] = new byte[] { (byte)DurabilityClass.FsyncReplicated };
        var canonical = CanonicalGrammar.Encode(RecordDefinitions.Dcn1, fields);
        canonical[FieldOffset(canonical, 26)] = 2;
        Assert.Throws<RecordException>(() =>
            CanonicalGrammar.Preflight(canonical, RecordDefinitions.Dcn1));
    }

    private static byte[] Node(ushort level,ulong index,ReadOnlySpan<byte> left,ReadOnlySpan<byte> right)
    {
        Span<byte> payload=stackalloc byte[74];
        BinaryPrimitives.WriteUInt16BigEndian(payload,level);
        BinaryPrimitives.WriteUInt64BigEndian(payload[2..],index);
        left.CopyTo(payload[10..42]);right.CopyTo(payload[42..]);
        return CanonicalGrammar.Sha256Domain("Deep/Cutover/V1/witness-log-node",payload);
    }

    private static byte[] Bytes(byte value,int length)=>Enumerable.Repeat(value,length).ToArray();

    private static int FieldOffset(ReadOnlySpan<byte> encoded, int tag)
    {
        var offset = 12;
        for (var current = 1; current <= tag; current++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                encoded.Slice(offset + 4, 4)));
            offset += 8;
            if (current == tag) return offset;
            offset += length;
        }
        throw new ArgumentOutOfRangeException(nameof(tag));
    }
}
