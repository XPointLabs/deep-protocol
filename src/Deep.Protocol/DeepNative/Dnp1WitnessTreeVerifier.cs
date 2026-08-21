using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

internal static class WitnessTreeVerifier
{
    private const string LeafDomain="Deep/Cutover/V1/witness-log-leaf";
    private const string NodeDomain="Deep/Cutover/V1/witness-log-node";
    private const string EmptyDomain="Deep/Cutover/V1/witness-empty-root";

    internal static byte[] Leaf(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 116)
            Invalid("The witness leaf transcript is not exact116.");
        return CanonicalGrammar.Sha256Domain(LeafDomain,payload);
    }

    internal static void VerifyInclusion(
        ReadOnlySpan<byte> leaf,ulong leafIndex,ulong treeSize,
        ReadOnlySpan<byte> proof,ReadOnlySpan<byte> expectedRoot)
    {
        if(treeSize==0 || leafIndex>=treeSize || proof.Length%32!=0 || proof.Length>1024)
            Invalid("The witness inclusion proof bounds are invalid.");
        var running=leaf.ToArray();var fn=leafIndex;var sn=treeSize-1;ushort level=0;var cursor=0;
        while(sn!=0)
        {
            if((fn&1)==1)
            {
                var sibling=Next(proof,ref cursor,"inclusion");
                running=Node(level,fn>>1,sibling,running);
            }
            else if(fn<sn)
            {
                var sibling=Next(proof,ref cursor,"inclusion");
                running=Node(level,fn>>1,running,sibling);
            }
            fn>>=1;sn>>=1;level++;
        }
        if(cursor!=proof.Length || !CanonicalGrammar.FixedEquals(running,expectedRoot))
            Invalid("The witness inclusion proof does not produce the signed tree root.");
    }

    internal static void VerifyConsistency(
        ulong previousSize,ReadOnlySpan<byte> previousRoot,
        ulong treeSize,ReadOnlySpan<byte> treeRoot,
        ReadOnlySpan<byte> proof,ReadOnlySpan<byte> authorizedEmptyRoot)
    {
        if(previousSize>treeSize || proof.Length%32!=0 || proof.Length>1024)
            Invalid("The witness consistency proof bounds are invalid.");
        if(previousSize==0)
        {
            if(authorizedEmptyRoot.Length!=32 || proof.Length!=0 ||
               !CanonicalGrammar.FixedEquals(previousRoot,authorizedEmptyRoot))
                Invalid("The empty witness predecessor has a nonempty proof or wrong root.");
            if(treeSize==0 && !CanonicalGrammar.FixedEquals(treeRoot,authorizedEmptyRoot))
                Invalid("The empty witness tree root is invalid.");
            return;
        }
        if(previousSize==treeSize)
        {
            if(proof.Length!=0 || !CanonicalGrammar.FixedEquals(previousRoot,treeRoot))
                Invalid("An unchanged witness tree has inconsistent roots or proof bytes.");
            return;
        }
        if(proof.Length==0) Invalid("A growing witness tree omits its consistency proof.");

        var fn=previousSize-1;var sn=treeSize-1;ushort level=0;
        while((fn&1)==1){fn>>=1;sn>>=1;level++;}
        var cursor=0;byte[] oldRunning,newRunning;
        if(fn==0){oldRunning=previousRoot.ToArray();newRunning=previousRoot.ToArray();}
        else {oldRunning=Next(proof,ref cursor,"consistency").ToArray();newRunning=oldRunning.ToArray();}
        while(cursor<proof.Length)
        {
            if(sn==0) Invalid("The witness consistency proof has trailing hashes.");
            var sibling=Next(proof,ref cursor,"consistency");
            if((fn&1)==1 || fn==sn)
            {
                oldRunning=Node(level,fn>>1,sibling,oldRunning);
                newRunning=Node(level,fn>>1,sibling,newRunning);
                while((fn&1)==0 && fn!=0){fn>>=1;sn>>=1;level++;}
            }
            else newRunning=Node(level,fn>>1,newRunning,sibling);
            fn>>=1;sn>>=1;level++;
        }
        if(sn!=0 || !CanonicalGrammar.FixedEquals(oldRunning,previousRoot) ||
           !CanonicalGrammar.FixedEquals(newRunning,treeRoot))
            Invalid("The witness consistency proof does not produce both signed roots.");
    }

    internal static byte[] EmptyRoot(
        ulong witnessEpoch,ReadOnlySpan<byte> witnessId,ulong maximumTreeSize)
    {
        if(witnessEpoch==0 || witnessId.Length!=32 || CanonicalGrammar.IsZero(witnessId) ||
           maximumTreeSize==0)
            Invalid("The authorized witness empty-root tuple is invalid.");
        Span<byte> payload=stackalloc byte[56];
        BinaryPrimitives.WriteUInt64BigEndian(payload,witnessEpoch);
        witnessId.CopyTo(payload[8..40]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[40..48],maximumTreeSize);
        BinaryPrimitives.WriteUInt64BigEndian(payload[48..],0);
        return CanonicalGrammar.Sha256Domain(EmptyDomain,payload);
    }

    private static ReadOnlySpan<byte> Next(ReadOnlySpan<byte> proof,ref int cursor,string kind)
    {
        if(cursor>proof.Length-32) Invalid($"The witness {kind} proof is truncated.");
        var value=proof.Slice(cursor,32);cursor+=32;return value;
    }

    private static byte[] Node(
        ushort level,ulong nodeIndex,ReadOnlySpan<byte> left,ReadOnlySpan<byte> right)
    {
        Span<byte> payload=stackalloc byte[74];
        BinaryPrimitives.WriteUInt16BigEndian(payload,level);
        BinaryPrimitives.WriteUInt64BigEndian(payload[2..],nodeIndex);
        left.CopyTo(payload[10..42]);right.CopyTo(payload[42..]);
        return CanonicalGrammar.Sha256Domain(NodeDomain,payload);
    }

    private static void Invalid(string message)=>
        throw new RecordException(RecordError.InvalidField,message);
}
