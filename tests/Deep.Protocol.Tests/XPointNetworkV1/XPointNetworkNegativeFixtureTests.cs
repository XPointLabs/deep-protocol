using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class XPointNetworkNegativeFixtureTests
{
    public static IEnumerable<object[]> FrozenNegativeCases()
    {
        foreach (var vector in XPointNetworkFrozenVectorManifest.NegativeVectors)
            yield return C(vector.Id, vector.ExpectedStage, vector.ExpectedError);
    }

    [Theory]
    [MemberData(nameof(FrozenNegativeCases))]
    public void ExactFrozenNegativeFixtureIsRepresented(string id,string stage,string error)
    {
        Assert.StartsWith("negative-",id,StringComparison.Ordinal);
        Assert.True(Enum.TryParse<XPointValidationStage>(stage,out _));
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void FrozenNegativeCatalogContainsExactlyThirtyUniqueCases()
    {
        var cases=FrozenNegativeCases().ToArray();
        Assert.Equal(30,cases.Length);
        Assert.Equal(30,cases.Select(x=>(string)x[0]).Distinct(StringComparer.Ordinal).Count());
    }

    public static IEnumerable<object[]> FrozenNegativeInputs() =>
        XPointNetworkFrozenVectorManifest.NegativeVectors.Where(vector => vector.InputHex is not null)
            .Select(vector => new object[] { vector });

    [Theory]
    [MemberData(nameof(FrozenNegativeInputs))]
    public void FrozenNegativeInputBytesExecuteWithExactManifestError(XPointNegativeVector vector)
    {
        var header = Convert.FromHexString(vector.InputHex!);
        var definition = XPointNetworkRegistry.Get(System.Text.Encoding.ASCII.GetString(header, 0, 4));
        var canonical = XPointNetworkTestRecords.Create(definition);
        header.CopyTo(canonical, 0);
        var actual = Assert.Throws<XPointValidationException>(() => XPointNetworkCodec.Parse(canonical));
        Assert.Equal(vector.ExpectedStage, actual.Stage.ToString());
        Assert.Equal(vector.ExpectedError, actual.Error);
    }

    [Fact]
    public void FrozenNegativeManifestIsUntampered() => XPointNetworkFrozenVectorManifest.AssertUntampered();

    [Fact]
    public void FrozenStructuralAndLocalSemanticFixturesReturnExactStageAndError()
    {
        var xna=XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xna1);
        Check(Mutate(xna,x=>x[10]=1),XPointValidationStage.Header,"NonCanonicalReserved");
        var xnd=XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xnd1);
        Check(Mutate(xnd,x=>x[7]=0),XPointValidationStage.Header,"UnknownSuite");
        var xnp=XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xnp1);
        Check(Mutate(xnp,x=>x[9]=16),XPointValidationStage.Header,"WrongFieldCount");
        Check(xna[..^1],XPointValidationStage.Length,"RecordLengthOutOfRange");
        var tooLarge=new byte[65_536]; "XNA1"u8.CopyTo(tooLarge);
        Check(tooLarge,XPointValidationStage.Length,"RecordLengthOutOfRange");
        Check(XPointNetworkTestRecords.MutateField(xna,1,v=>v.Clear()),XPointValidationStage.Scalar,"ZeroForbidden");
        Check(XPointNetworkTestRecords.MutateField(xna,4,v=>v[0]=2),XPointValidationStage.ListArithmetic,"CountLengthMismatch");
        var twoRootXna=XPointNetworkTestRecords.CreateXna(2,1,1);
        Check(XPointNetworkTestRecords.MutateField(twoRootXna,5,v=>v[..72].CopyTo(v[72..144])),XPointValidationStage.CanonicalList,"NonCanonicalList");
        var xvp=XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xvp1);
        Check(XPointNetworkTestRecords.MutateField(xvp,13,v=>"XND1"u8.CopyTo(v)),XPointValidationStage.Reference,"ReferenceTypeMismatch");
        Check(XPointNetworkTestRecords.MutateField(xna,19,v=>v[0]=0),XPointValidationStage.Scalar,"RootSignatureCountOutOfRange");
        Check(XPointNetworkTestRecords.MutateField(xnd,12,v=>v[0]^=1),XPointValidationStage.DerivedValue,"FailureDomainMismatch");
        Check(XPointNetworkTestRecords.MutateField(xnd,18,v=>v.Clear()),XPointValidationStage.CrossField,"RoleProjectionMismatch");
        Check(XPointNetworkTestRecords.MutateField(xnd,25,v=>System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(v,3)),XPointValidationStage.CrossField,"InvalidKeyEpoch");
        Check(XPointNetworkTestRecords.MutateField(xnp,9,v=>v[0]^=1),XPointValidationStage.Proof,"NonCanonicalProof");
    }

    private static object[] C(string id,string stage,string error)=>[id,stage,error];

    private static byte[] Mutate(byte[] value,Action<byte[]> mutation){var copy=value.ToArray();mutation(copy);return copy;}
    private static void Check(byte[] value,XPointValidationStage stage,string error)
    {
        var actual=Assert.Throws<XPointValidationException>(()=>XPointNetworkCodec.Parse(value));
        Assert.Equal(stage,actual.Stage);
        Assert.Equal(error,actual.Error);
    }
}
