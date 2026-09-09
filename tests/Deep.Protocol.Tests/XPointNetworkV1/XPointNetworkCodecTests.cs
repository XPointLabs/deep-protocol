using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class XPointNetworkCodecTests
{
    public static IEnumerable<object[]> Definitions() =>
        XPointNetworkRegistry.All.Select(value => new object[] { value.Magic });

    [Theory]
    [MemberData(nameof(Definitions))]
    public void AllNineRecordsRoundTripAsStrongTypes(string magic)
    {
        var definition=XPointNetworkRegistry.Get(magic);
        var bytes=XPointNetworkTestRecords.Create(definition);
        var parsed=XPointNetworkCodec.Parse(bytes);
        Assert.Equal(definition.Kind,parsed.Kind);
        Assert.Equal(bytes,parsed.CanonicalCopy());
        Assert.Equal(definition.MinimumBytes,bytes.Length);
    }

    [Fact]
    public void RegistryRemainsDarkAndContainsExactNineRecords()
    {
        Assert.False(XPointNetworkRegistry.RuntimeActivation);
        Assert.Equal(1,XPointNetworkRegistry.RegistryGeneration);
        Assert.Equal(9,XPointNetworkRegistry.All.Count);
        Assert.Equal(new[]{"XNA1","XVP1","XND1","XNV1","XNH1","XNP1","XNF1","NFP1","XCD1"},
            XPointNetworkRegistry.All.Select(x=>x.Magic));
    }

    [Fact]
    public void HeaderAndTrailingBytesRejectBeforeAnyVerifierExists()
    {
        var valid=XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xna1);
        foreach(var mutation in new Action<byte[]>[]
        {
            x=>x[0]=(byte)'?', x=>x[5]=2, x=>x[7]=2, x=>x[9]=19, x=>x[11]=1,
            x=>x[13]=2, x=>x[14]=1,
        })
        {
            var copy=valid.ToArray(); mutation(copy);
            Assert.Throws<XPointValidationException>(()=>XPointNetworkCodec.Parse(copy));
        }
        Assert.Throws<XPointValidationException>(()=>XPointNetworkCodec.Parse(valid.Concat(new byte[]{0}).ToArray()));
    }

    [Fact]
    public void HostileDeclaredLengthsAndCountsRejectWithoutLargeAllocation()
    {
        var valid=XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xnv1);
        var listLengthOffset=FindFieldHeader(valid,12)+4;
        foreach(var length in new uint[]{0,37,39,uint.MaxValue})
        {
            var copy=valid.ToArray(); BinaryPrimitives.WriteUInt32BigEndian(copy.AsSpan(listLengthOffset),length);
            Assert.Throws<XPointValidationException>(()=>XPointNetworkCodec.Parse(copy));
        }
        for(var i=0;i<512;i++)
        {
            var size=RandomNumberGenerator.GetInt32(0,70_000);
            var hostile=new byte[size]; RandomNumberGenerator.Fill(hostile);
            try { _=XPointNetworkCodec.Parse(hostile); }
            catch(XPointValidationException) { }
        }
    }

    [Fact]
    public void CanonicalTagMutationAndDuplicateListEntriesReject()
    {
        var valid=XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xcd1);
        var tag=valid.ToArray(); BinaryPrimitives.WriteUInt16BigEndian(tag.AsSpan(FindFieldHeader(tag,8)),9);
        Assert.Equal("NonCanonicalTag",Assert.Throws<XPointValidationException>(()=>XPointNetworkCodec.Parse(tag)).Error);
        var duplicate=XPointNetworkTestRecords.MutateField(valid,8,value=>value[..200].CopyTo(value[200..400]));
        Assert.Equal("NonCanonicalList",Assert.Throws<XPointValidationException>(()=>XPointNetworkCodec.Parse(duplicate)).Error);
    }

    private static int FindFieldHeader(byte[] canonical,int tag)
    {
        var offset=12;
        for(var current=1;current<tag;current++) offset+=8+checked((int)BinaryPrimitives.ReadUInt32BigEndian(canonical.AsSpan(offset+4,4)));
        return offset;
    }
}
