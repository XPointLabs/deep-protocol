using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.XPointNetworkV1;

internal static class XPointNetworkTestRecords
{
    internal delegate void SpanMutation(Span<byte> value);
    internal static byte[] Create(XPointRecordDefinition d)
    {
        var fields = d.Fields.Select(CreateDefault).ToArray();
        SetGenerationPredecessor(d, fields, 0, default);
        switch (d.Kind)
        {
            case XPointRecordKind.Xna1: PopulateXna(fields,1,1,3,2,1); break;
            case XPointRecordKind.Xvp1: PopulateXvp(fields); break;
            case XPointRecordKind.Xnd1: PopulateXnd(fields, Id(2), Id(40), Id(50)); break;
            case XPointRecordKind.Xnv1: PopulateXnv(fields); break;
            case XPointRecordKind.Xnh1: PopulateXnh(fields); break;
            case XPointRecordKind.Xnp1: PopulateXnp(fields); break;
            case XPointRecordKind.Xnf1: PopulateXnf(fields); break;
            case XPointRecordKind.Nfp1: PopulateNfp(fields); break;
            case XPointRecordKind.Xcd1: PopulateXcd(fields, Id(2), Id(40), [(Id(3),Id(41),Id(51)),(Id(4),Id(42),Id(52))]); break;
        }
        return XPointNetworkCodec.Write(d, fields);
    }

    internal static byte[] CreateXna(int rootCount, int rootThreshold, int signatureCount, ulong generation = 0, XPointBytes predecessor = default)
    {
        var f = XPointNetworkRegistry.Xna1.Fields.Select(CreateDefault).ToArray();
        PopulateXna(f,rootCount,rootThreshold,3,2,signatureCount);
        SetGenerationPredecessor(XPointNetworkRegistry.Xna1,f,generation,predecessor);
        if (generation != 0)
        {
            f[4]=RootEntries(rootCount,generation);
            f[9]=WitnessEntries(3,generation);
        }
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1,f);
    }

    internal static byte[] CreateCallRelayXnd(byte nodeSeed, byte keySeed, byte domainSeed)
    {
        var f=XPointNetworkRegistry.Xnd1.Fields.Select(CreateDefault).ToArray();
        PopulateXnd(f,Id(nodeSeed),Id(keySeed),Id(domainSeed));
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xnd1,f);
    }

    internal static byte[] CreateXcd(byte targetNodeSeed, byte targetKeySeed,
        (byte node,byte key,byte domain) replica1, (byte node,byte key,byte domain) replica2)
    {
        var f=XPointNetworkRegistry.Xcd1.Fields.Select(CreateDefault).ToArray();
        PopulateXcd(f,Id(targetNodeSeed),Id(targetKeySeed),
            [(Id(replica1.node),Id(replica1.key),Id(replica1.domain)),(Id(replica2.node),Id(replica2.key),Id(replica2.domain))]);
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xcd1,f);
    }

    internal static byte[] CreateXcdBound(Xnd1Record target, Xnd1Record first, Xnd1Record second)
    {
        var f=XPointNetworkRegistry.Xcd1.Fields.Select(CreateDefault).ToArray();
        PopulateXcd(f,target.NodeId.ToArray(),target.FindRole(4)!.PublicKey.ToArray(),
            [(first.NodeId.ToArray(),first.FindRole(4)!.PublicKey.ToArray(),first.FailureDomainHash.ToArray()),
             (second.NodeId.ToArray(),second.FindRole(4)!.PublicKey.ToArray(),second.FailureDomainHash.ToArray())]);
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xcd1,f);
    }

    internal static byte[] MutateField(byte[] canonical, int tag, SpanMutation mutation)
    {
        var copy=canonical.ToArray();
        var offset=12;
        for(var current=1;current<=tag;current++)
        {
            var length=checked((int)BinaryPrimitives.ReadUInt32BigEndian(copy.AsSpan(offset+4,4)));
            offset+=8;
            if(current==tag){ mutation(copy.AsSpan(offset,length)); return copy; }
            offset+=length;
        }
        throw new ArgumentOutOfRangeException(nameof(tag));
    }

    internal static byte[] Id(byte seed, int length=32)
    {
        var value=new byte[length];
        value[0]=seed;
        value[^1]=(byte)(seed^0x5a);
        return value;
    }

    private static ReadOnlyMemory<byte> CreateDefault(XPointFieldDefinition f)
    {
        var value=new byte[f.MinimumLength];
        if (f.Kind is XPointFieldKind.UInt8 or XPointFieldKind.UInt16 or XPointFieldKind.UInt32 or XPointFieldKind.UInt64)
        {
            var scalar=f.AllowedValues is {Length:>0}?f.AllowedValues[0]:f.MinimumValue;
            WriteScalar(value,scalar);
        }
        else if (f.Kind is XPointFieldKind.CoreReference or XPointFieldKind.ArtifactReference)
            value=XPointNetworkCodec.EncodeCoreReference(f.ReferenceMagic!,Id((byte)f.Tag));
        else if (f.NonZero && value.Length>0) value[0]=(byte)(f.Tag+1);
        return value;
    }

    private static void PopulateXna(ReadOnlyMemory<byte>[] f,int roots,int rootThreshold,int witnesses,int witnessThreshold,int signatures)
    {
        f[0]=Id(1,16); f[3]=Scalar((ulong)roots,1); f[4]=RootEntries(roots); f[5]=Scalar((ulong)rootThreshold,1);
        f[7]=Scalar(1,2); f[8]=Scalar((ulong)witnesses,1); f[9]=WitnessEntries(witnesses); f[10]=Scalar((ulong)witnessThreshold,1);
        f[11]=XPointNetworkCodec.EncodeCoreReference("DTS1",Id(12)); f[12]=Id(13); f[13]=Scalar(10,4); f[14]=Scalar(1,8);
        f[15]=Scalar(100,8); f[16]=Scalar(100,8); f[17]=Scalar(200,8); f[18]=Scalar((ulong)signatures,1); f[19]=SignatureEntries(signatures);
    }

    private static void PopulateXvp(ReadOnlyMemory<byte>[] f)
    {
        f[0]=Id(1,16); f[3]=Scalar(31,2); f[4]=Scalar(3,1); f[5]=Scalar(2,1); f[6]=Scalar(15,2);
        f[7]=Scalar(3,1); f[8]=Scalar(2_592_000,4); f[9]=Scalar(60,2); f[10]=Scalar(1,2);
        f[12]=XPointNetworkCodec.EncodeCoreReference("XCC1",Id(13)); f[13]=Scalar(1,2); f[14]=Scalar(100,8);
        f[15]=Scalar(100,8); f[16]=Scalar(200,8); f[17]=XPointNetworkCodec.EncodeCoreReference("XNA1",Id(18));
        f[18]=Scalar(1,1); f[19]=SignatureEntries(1);
    }

    private static void PopulateXnd(ReadOnlyMemory<byte>[] f,byte[] node,byte[] roleKey,byte[] failureDomain)
    {
        f[0]=Id(1,16); f[1]=node; f[4]=Id(5); f[5]=Id(6); f[6]=failureDomain; f[7]=Id(8); f[8]=Id(9);
        f[9]=Scalar(64500,4); f[10]=Scalar(643,2);
        Span<byte> projection=stackalloc byte[118]; var p=0;
        foreach(var x in new[]{f[0],f[6],f[7],f[8],f[9],f[10]}){x.Span.CopyTo(projection[p..]);p+=x.Length;}
        f[11]=XPointNetworkCrypto.Sha256Domain(XPointNetworkRegistry.FailureDomainDomain,projection);
        f[12]=Scalar(16,2); f[13]=Scalar(0,4); f[14]=Scalar(0,8); f[15]=Scalar(0,8); f[16]=Scalar(0,8); f[17]=Scalar(100,4);
        f[18]=Scalar(1,1); f[19]=OriginEntries(); f[20]=Scalar(1,8); f[21]=Id(22); f[22]=Scalar(100,8); f[23]=Scalar(200,8);
        f[24]=Scalar(2,8); f[25]=Id(26); f[26]=Scalar(190,8); f[27]=Scalar(290,8); f[28]=Scalar(1,2); f[29]=Scalar(1,2);
        f[30]=Scalar(1,1); f[31]=RoleEntries([(4,0UL,roleKey)]); f[32]=Scalar(100,8); f[33]=Scalar(100,8); f[34]=Scalar(200,8);
        f[35]=Scalar(1,2); f[36]=Id(37,64);
    }

    private static void PopulateXnv(ReadOnlyMemory<byte>[] f)
    {
        f[0]=Id(1,16); f[3]=Id(4); f[5]=Id(6); f[6]=XPointNetworkCodec.EncodeCoreReference("XNA1",Id(7)); f[7]=Id(8);
        f[8]=XPointNetworkCodec.EncodeCoreReference("XVP1",Id(9)); f[9]=Scalar(1,2); f[10]=Scalar(3,2);
        f[11]=Refs("XND1",3); f[12]=Scalar(0,2); f[13]=Array.Empty<byte>(); f[14]=Scalar(0,2); f[15]=Array.Empty<byte>();
        f[16]=Scalar(1,2); f[17]=Refs("XCB1",1); f[18]=Scalar(100,8); f[19]=Scalar(100,8); f[20]=Scalar(200,8);
        f[21]=Scalar(1,2); f[22]=Scalar(2,1); f[23]=SignatureEntries(2);
    }

    private static void PopulateXnh(ReadOnlyMemory<byte>[] f)
    {
        f[0]=Id(1,16); f[3]=Scalar(1,8); f[4]=Id(5); f[5]=XPointNetworkCodec.EncodeCoreReference("XNV1",Id(6));
        f[7]=XPointNetworkCodec.EncodeCoreReference("XNA1",Id(8)); f[8]=Id(9); f[9]=Scalar(100,8); f[10]=Scalar(200,8);
        f[11]=Scalar(1,2); f[12]=Scalar(0,1); f[13]=Array.Empty<byte>(); f[14]=Scalar(2,1); f[15]=SignatureEntries(2);
    }

    private static void PopulateXnp(ReadOnlyMemory<byte>[] f)
    {
        f[0]=Id(1,16); f[1]=XPointNetworkCodec.EncodeCoreReference("XNH1",Id(2)); f[2]=Scalar(1,8); f[3]=Id(4);
        f[4]=XPointNetworkCodec.EncodeCoreReference("XNV1",Id(5)); f[6]=f[1]; f[7]=f[2]; f[8]=f[3]; f[9]=f[4];
        f[11]=Scalar(1,2); f[12]=Scalar(0,8); f[13]=Scalar(0,1); f[14]=Array.Empty<byte>(); f[15]=Scalar(0,1); f[16]=Array.Empty<byte>();
    }

    private static void PopulateXnf(ReadOnlyMemory<byte>[] f)
    {
        f[0]=Id(1,16); var range=new byte[16]; BinaryPrimitives.WriteUInt64BigEndian(range,0); BinaryPrimitives.WriteUInt64BigEndian(range.AsSpan(8),0); f[3]=range;
        f[4]=Scalar(1,8); f[5]=Id(6); f[6]=XPointNetworkCodec.EncodeCoreReference("XNV1",Id(7));
        var vh=new byte[40]; Id(7).CopyTo(vh,8); f[7]=vh; f[8]=XPointNetworkCodec.EncodeCoreReference("XNH1",Id(9));
        var th=new byte[40]; BinaryPrimitives.WriteUInt64BigEndian(th,1); Id(10).CopyTo(th,8); f[9]=th;
        f[10]=XPointNetworkCodec.EncodeCoreReference("XNA1",Id(11)); f[11]=Scalar(100,8); f[12]=Scalar(1,2); f[13]=Scalar(1,1); f[14]=SignatureEntries(1);
    }

    private static void PopulateNfp(ReadOnlyMemory<byte>[] f)
    {
        f[0]=Id(1,16); f[2]=XPointNetworkCodec.EncodeCoreReference("XNV1",Id(3)); f[3]=Scalar(1,8); f[4]=Id(5);
        f[6]=XPointNetworkCodec.EncodeCoreReference("XNV1",Id(7)); f[7]=XPointNetworkCodec.EncodeCoreReference("XNH1",Id(8));
        f[8]=Scalar(1,1); f[9]=Refs("XNA1",1); f[10]=Scalar(1,1); f[11]=Refs("XNF1",1); f[12]=Scalar(0,1); f[13]=Array.Empty<byte>();
        f[14]=XPointNetworkCodec.EncodeCoreReference("DTT1",Id(15)); f[15]=Scalar(1,2);
    }

    private static void PopulateXcd(ReadOnlyMemory<byte>[] f,byte[] targetNode,byte[] targetKey,(byte[] node,byte[] key,byte[] domain)[] replicas)
    {
        f[0]=Id(1,16); f[1]=targetNode; f[4]=targetKey; f[5]=Scalar(0,8); f[6]=Scalar((ulong)replicas.Length,1);
        var entries=new byte[replicas.Length*200];
        for(var i=0;i<replicas.Length;i++)
        {
            var e=entries.AsSpan(i*200,200); Id((byte)(10+i)).CopyTo(e); BinaryPrimitives.WriteUInt64BigEndian(e[32..40],0);
            replicas[i].key.CopyTo(e[40..72]); replicas[i].node.CopyTo(e[72..104]); replicas[i].domain.CopyTo(e[104..136]); Id((byte)(60+i),64).CopyTo(e[136..]);
        }
        f[7]=entries; f[8]=Scalar(2,1); f[9]=Scalar(1,2); f[10]=Scalar(1,2); f[11]=Scalar(1,2); f[12]=Scalar(1200,2);
        f[13]=Scalar(64000,4); f[14]=Scalar(100,4); f[15]=Scalar(60,2); f[16]=Scalar(3,2); f[17]=Scalar(100,8);
        f[18]=Scalar(100,8); f[19]=Scalar(200,8); f[20]=Id(21,64);
    }

    private static void SetGenerationPredecessor(XPointRecordDefinition d,ReadOnlyMemory<byte>[] f,ulong generation,XPointBytes predecessor)
    {
        if(d.GenerationTag==0)return;
        f[d.GenerationTag-1]=Scalar(generation,8);
        f[d.PredecessorHashTag-1]=generation==0?new byte[32]:predecessor.ToArray();
    }

    private static byte[] RootEntries(int count,ulong generation=0){var x=new byte[count*72];for(var i=0;i<count;i++){Id((byte)(10+i)).CopyTo(x,i*72);BinaryPrimitives.WriteUInt64BigEndian(x.AsSpan(i*72+32),generation);Id((byte)(30+i)).CopyTo(x,i*72+40);}return x;}
    private static byte[] WitnessEntries(int count,ulong generation=0){var x=new byte[count*104];for(var i=0;i<count;i++){Id((byte)(10+i)).CopyTo(x,i*104);BinaryPrimitives.WriteUInt64BigEndian(x.AsSpan(i*104+32),generation);Id((byte)(40+i)).CopyTo(x,i*104+40);Id((byte)(70+i)).CopyTo(x,i*104+72);}return x;}
    private static byte[] SignatureEntries(int count){var x=new byte[count*96];for(var i=0;i<count;i++){Id((byte)(10+i)).CopyTo(x,i*96);Id((byte)(90+i),64).CopyTo(x,i*96+32);}return x;}
    private static byte[] RoleEntries((byte role,ulong generation,byte[] key)[] values){var x=new byte[values.Length*41];for(var i=0;i<values.Length;i++){x[i*41]=values[i].role;BinaryPrimitives.WriteUInt64BigEndian(x.AsSpan(i*41+1),values[i].generation);values[i].key.CopyTo(x,i*41+9);}return x;}
    private static byte[] OriginEntries(){var x=new byte[148];Id(1).CopyTo(x);x[32]=1;x[33]=4;x[34]=127;x[35]=0;x[36]=0;x[37]=1;BinaryPrimitives.WriteUInt16BigEndian(x.AsSpan(50),443);Id(2).CopyTo(x,52);BinaryPrimitives.WriteUInt64BigEndian(x.AsSpan(84),100);BinaryPrimitives.WriteUInt64BigEndian(x.AsSpan(92),200);Id(3).CopyTo(x,100);BinaryPrimitives.WriteUInt64BigEndian(x.AsSpan(132),190);BinaryPrimitives.WriteUInt64BigEndian(x.AsSpan(140),290);return x;}
    private static byte[] Refs(string magic,int count){var x=new byte[count*38];for(var i=0;i<count;i++)XPointNetworkCodec.EncodeCoreReference(magic,Id((byte)(20+i))).CopyTo(x,i*38);return x;}
    private static byte[] Scalar(ulong value,int width){var x=new byte[width];WriteScalar(x,value);return x;}
    private static void WriteScalar(Span<byte> output,ulong value){switch(output.Length){case 1:output[0]=checked((byte)value);break;case 2:BinaryPrimitives.WriteUInt16BigEndian(output,checked((ushort)value));break;case 4:BinaryPrimitives.WriteUInt32BigEndian(output,checked((uint)value));break;case 8:BinaryPrimitives.WriteUInt64BigEndian(output,value);break;default:throw new ArgumentOutOfRangeException(nameof(output));}}
}
