using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.Tests.MessagingWire;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class ContactServiceWireCodecTests
{
    [Fact]
    public void RequestCodecsProduceStableCanonicalGoldenRecords()
    {
        var xiq=Xiq();var xpk=Xpk();var xuw=Xuw();var xuq=Xuq();var xpu=Xpu();

        Assert.Equal("DAF740B32F04F6535450225F202A18BF4536C61C8354ADC902C3B854C44B11A0",HexHash(xiq));
        Assert.Equal("57BD87E718469C2E743F55C6CD858B1A9CE9E6B6ADC3F8F742E5B180A71D75B1",HexHash(xpk));
        Assert.Equal("2D075C84CA1989F078B2774AC34A18CA22CBA012FE29AA7DB8E893DAC5F79EA0",HexHash(xuw));
        Assert.Equal("0AF80D459A450D2813812C87A84819C9B7034FF09C1DEA019A0A83E7CA2E9B4C",HexHash(xuq));
        Assert.Equal("843E2FD6ABE1B6328EB5E0C44023CE48A167E50E4D2882BA5BD3B625B0E20E54",HexHash(xpu));
        Assert.True(new ushort[]{1,2,3,4,5,6,16,17,18,19,20,21}.SequenceEqual(Tags(xiq)));
        Assert.True(new ushort[]{1,2,3,4,5,6,16,17,18,19,20,21,22}.SequenceEqual(Tags(xuw)));
    }

    [Fact]
    public void TypedRequestModelsOwnInputAndValidateDerivedHashes()
    {
        var bytes=Xuw();var decoded=Xuw1Codec.Decode(bytes);var canonical=decoded.CanonicalBytes.ToArray();var field=decoded.Field(21).ToArray();
        bytes[0]^=0xff;canonical[0]^=0xff;field[^1]^=0xff;
        Assert.Equal("XUW1",decoded.Magic);
        Assert.Equal(B(9,70),decoded.SealedUpdate.ToArray());
        Assert.Equal(SHA256.HashData(B(9,70)),decoded.EventCiphertextHash.ToArray());

        var bad=Xuw();bad[FieldOffset(bad,20)]^=1;
        Assert.Equal("EventCiphertextHashMismatch",Assert.Throws<ContactFormatException>(()=>Xuw1Codec.Decode(bad)).Code);
    }

    [Fact]
    public void XpuClosesAuthorizationProjectionAndCiphertextHash()
    {
        var decoded=Xpu1Codec.Decode(Xpu());
        Assert.Equal(decoded.AuthorizedBodyHash.ToArray(),Field(decoded.ExactXpa1.Span,19));
        Assert.Equal(SHA256.HashData(decoded.ObjectCiphertext.Span),decoded.ObjectCiphertextHash.ToArray());
        Assert.Equal(decoded.AuthorizedBodyHash.ToArray(),Xpu1Codec.ComputeAuthorizedBodyHash(
            decoded.NetworkId.Span,decoded.OperationId.Span,decoded.ViewHash.Span,decoded.PlacementHash.Span,
            decoded.IssuedAtUnixSeconds,decoded.ExpiresAtUnixSeconds,decoded.LocatorHash.Span,decoded.Xir1Hash.Span,
            decoded.Generation,decoded.PredecessorObjectHash.Span,decoded.ObjectCiphertext.Span,
            decoded.UsageLimit,decoded.EffectiveExpiresAtUnixSeconds,
            decoded.ExactRouteClosure.Span));
        Assert.Equal(SHA256.HashData(decoded.ExactRouteClosure.Span),decoded.RouteClosureHash.ToArray());

        var changed=Xpu();changed[FieldOffset(changed,21)+3]^=1;
        Assert.Equal("ObjectCiphertextHashMismatch",Assert.Throws<ContactFormatException>(()=>Xpu1Codec.Decode(changed)).Code);
    }

    [Fact]
    public void ResultCodecsEnforceClosedMatricesAndExactPadding()
    {
        var xpu=Xpu();var receipts=Receipts();
        var xpo=Xpo1Codec.Encode(xpu,Xpo1Status.Committed,ContactServiceMutationOutcome.DurablyCommitted,60,0,ContactServicePaddingClass.Bytes1024,[U64(0),SHA256.HashData(B(40,31)),U64(7),receipts]);
        Assert.Equal(1024,xpo.Length);Assert.Equal(Xpo1Status.Committed,Xpo1Codec.Decode(xpo,xpu).Status);

        var xiq=Xiq();var cipher=B(40,80);var route=RouteClosure();
        var xis=Xis1Codec.Encode(xiq,Xis1Status.Success,ContactServiceMutationOutcome.None,60,0,ContactServicePaddingClass.Bytes16384,[U64(0),U64(80),SHA256.HashData(cipher),cipher,SHA256.HashData(route),route,receipts]);
        Assert.Equal(Xis1Status.Success,Xis1Codec.Decode(xis,xiq).Status);

        var xpk=Xpk();var xpc=Xpc1Codec.Encode(xpk,Xpc1Status.StaleBundle,ContactServiceMutationOutcome.None,60,0,ContactServicePaddingClass.Bytes1024,[B(32,101),B(32,102),B(32,103)]);
        Assert.Equal(1024,xpc.Length);Assert.Equal(Xpc1Status.StaleBundle,Xpc1Codec.Decode(xpc,xpk).Status);

        var wrong=Xpo1Codec.Encode(xpu,Xpo1Status.Expired,ContactServiceMutationOutcome.None,60,0,ContactServicePaddingClass.Bytes256,[]);
        WriteU16(wrong,FieldOffset(wrong,4),99);
        Assert.Equal("UnknownStatus",Assert.Throws<ContactFormatException>(()=>Xpo1Codec.Decode(wrong,xpu)).Code);
        wrong=Xpo1Codec.Encode(xpu,Xpo1Status.Expired,ContactServiceMutationOutcome.None,60,0,ContactServicePaddingClass.Bytes256,[]);wrong[^1]=1;
        Assert.Equal("NonZeroPadding",Assert.Throws<ContactFormatException>(()=>Xpo1Codec.Decode(wrong,xpu)).Code);
        Assert.Throws<ContactFormatException>(()=>Xpo1Codec.Encode(xpu,Xpo1Status.Committed,ContactServiceMutationOutcome.None,60,0,ContactServicePaddingClass.Bytes1024,[U64(0),B(32,1),U64(1),receipts]));
    }

    [Fact]
    public void UpdateResultsCloseWriteFetchAndPaginationShapes()
    {
        var write=Xuw();var receipts=Receipts();var writeEventHash=Xuw1Codec.Decode(write).EventHash;
        var committed=Xus1Codec.Encode(write,Xus1OperationKind.Write,Xus1Status.WriteCommitted,ContactServiceMutationOutcome.DurablyCommitted,50,0,ContactServicePaddingClass.Bytes1024,[U64(0),writeEventHash,U64(4),receipts]);
        Assert.Equal(Xus1OperationKind.Write,Xus1Codec.Decode(committed,write).OperationKind);

        var query=Xuq();var eventBytes=Event(6,B(32,112),B(20,113),80);
        var events=Xus1Codec.Encode(query,Xus1OperationKind.Fetch,Xus1Status.Events,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes4096,[U16(1),eventBytes,U64(6),new byte[]{0}]);
        var decoded=Xus1Codec.Decode(events,query);Assert.Equal(4096,decoded.WireBytes.Length);Assert.Equal(Xus1Status.Events,decoded.Status);

        var changedCursor=Xuq(after:6);Assert.Equal("RequestHashMismatch",Assert.Throws<ContactFormatException>(()=>Xus1Codec.Decode(events,changedCursor)).Code);
        Assert.Throws<ContactFormatException>(()=>Xus1Codec.Encode(query,Xus1OperationKind.Fetch,Xus1Status.NoChange,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes1024,[]));
        Assert.Throws<ContactFormatException>(()=>Xus1Codec.Encode(write,Xus1OperationKind.Fetch,Xus1Status.NoChange,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes256,[]));
    }

    [Theory]
    [InlineData(8)]
    [InlineData(10)]
    [InlineData(12)]
    public void RequestGrammarRejectsReservedAndTrailingBytes(int offset)
    {
        var bytes=Xuq();var changed=bytes.ToArray();changed[offset]=1;
        Assert.Throws<ContactFormatException>(()=>Xuq1Codec.Decode(changed));
        Assert.Throws<ContactFormatException>(()=>Xuq1Codec.Decode(bytes.Concat(new byte[]{0}).ToArray()));
    }

    [Fact]
    public void RequestGrammarRejectsUnknownTagsLengthsScalarsAndCaps()
    {
        var bytes=Xuq();WriteU16(bytes,FieldHeaderOffset(bytes,16),15);
        Assert.Equal("UnknownOrMissingTag",Assert.Throws<ContactFormatException>(()=>Xuq1Codec.Decode(bytes)).Code);

        bytes=Xuq();WriteU32(bytes,FieldHeaderOffset(bytes,19)+4,3);
        Assert.Throws<ContactFormatException>(()=>Xuq1Codec.Decode(bytes));

        bytes=Xpk();WriteU16(bytes,FieldOffset(bytes,20),0x0202);
        Assert.Equal("UnknownRequestedSuite",Assert.Throws<ContactFormatException>(()=>Xpk1Codec.Decode(bytes)).Code);

        Assert.Throws<ContactFormatException>(()=>Xuw1Codec.Encode(B(16,1),B(32,2),B(32,3),B(32,4),10,100,B(32,5),B(32,6),0,new byte[32],new byte[32769],80));
        Assert.Throws<ContactFormatException>(()=>Xpu1Codec.Encode(B(16,1),B(32,2),B(32,3),B(32,4),10,100,B(32,5),B(32,6),0,new byte[32],B(65500,7),0,80,RouteClosure(),B(12,8)));
    }

    [Fact]
    public void ResultRequestBindingUsesExactCanonicalBytes()
    {
        var request=Xiq();var result=Xis1Codec.Encode(request,Xis1Status.NotFound,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes256,[]);
        var changed=request.ToArray();changed[FieldOffset(changed,17)+7]=1;
        Assert.Equal("RequestHashMismatch",Assert.Throws<ContactFormatException>(()=>Xis1Codec.Decode(result,changed)).Code);
    }

    [Fact]
    public void ClosedFailureStatusMatricesAcceptTheirOnlyPayloadShapes()
    {
        var xpu=Xpu();
        foreach(var status in new[]{Xpo1Status.Expired,Xpo1Status.Unauthorized,Xpo1Status.TemporarilyUnavailable})
            Assert.Equal(status,Xpo1Codec.Decode(Xpo1Codec.Encode(xpu,status,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes256,[]),xpu).Status);
        foreach(var status in new[]{Xpo1Status.StaleView,Xpo1Status.Conflict})
            Assert.Equal(status,Xpo1Codec.Decode(Xpo1Codec.Encode(xpu,status,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes256,[B(32,150)]),xpu).Status);
        Assert.Equal(Xpo1Status.RateLimited,Xpo1Codec.Decode(Xpo1Codec.Encode(xpu,Xpo1Status.RateLimited,ContactServiceMutationOutcome.None,50,3,ContactServicePaddingClass.Bytes256,[]),xpu).Status);
        Assert.Equal(Xpo1Status.OutcomeUnknown,Xpo1Codec.Decode(Xpo1Codec.Encode(xpu,Xpo1Status.OutcomeUnknown,ContactServiceMutationOutcome.OutcomeUnknown,50,3,ContactServicePaddingClass.Bytes256,[]),xpu).Status);

        var xiq=Xiq();
        foreach(var status in new[]{Xis1Status.Expired,Xis1Status.AlreadyClaimed,Xis1Status.NotFound,Xis1Status.TemporarilyUnavailable})
            Assert.Equal(status,Xis1Codec.Decode(Xis1Codec.Encode(xiq,status,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes256,[]),xiq).Status);
        foreach(var status in new[]{Xis1Status.StaleView,Xis1Status.Conflict})
            Assert.Equal(status,Xis1Codec.Decode(Xis1Codec.Encode(xiq,status,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes256,[B(32,151)]),xiq).Status);
        Assert.Equal(Xis1Status.RateLimited,Xis1Codec.Decode(Xis1Codec.Encode(xiq,Xis1Status.RateLimited,ContactServiceMutationOutcome.None,50,3,ContactServicePaddingClass.Bytes256,[]),xiq).Status);
        Assert.Equal(Xis1Status.OutcomeUnknown,Xis1Codec.Decode(Xis1Codec.Encode(xiq,Xis1Status.OutcomeUnknown,ContactServiceMutationOutcome.OutcomeUnknown,50,3,ContactServicePaddingClass.Bytes256,[]),xiq).Status);

        var xpk=Xpk();
        foreach(var status in new[]{Xpc1Status.PreKeysUnavailable,Xpc1Status.Expired})
            Assert.Equal(status,Xpc1Codec.Decode(Xpc1Codec.Encode(xpk,status,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes256,[]),xpk).Status);
        Assert.Equal(Xpc1Status.Conflict,Xpc1Codec.Decode(Xpc1Codec.Encode(xpk,Xpc1Status.Conflict,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes256,[B(32,152)]),xpk).Status);
        Assert.Equal(Xpc1Status.RateLimited,Xpc1Codec.Decode(Xpc1Codec.Encode(xpk,Xpc1Status.RateLimited,ContactServiceMutationOutcome.None,50,3,ContactServicePaddingClass.Bytes256,[]),xpk).Status);
        Assert.Equal(Xpc1Status.OutcomeUnknown,Xpc1Codec.Decode(Xpc1Codec.Encode(xpk,Xpc1Status.OutcomeUnknown,ContactServiceMutationOutcome.OutcomeUnknown,50,3,ContactServicePaddingClass.Bytes256,[]),xpk).Status);

        Assert.Throws<ContactFormatException>(()=>Xis1Codec.Encode(xiq,Xis1Status.NotFound,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes256,[B(32,1)]));
        Assert.Throws<ContactFormatException>(()=>Xpc1Codec.Encode(xpk,Xpc1Status.StaleBundle,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes256,[B(32,1)]));
        Assert.Throws<ContactFormatException>(()=>Xpo1Codec.Encode(xpu,Xpo1Status.OutcomeUnknown,ContactServiceMutationOutcome.OutcomeUnknown,50,0,ContactServicePaddingClass.Bytes256,[]));
        Assert.Throws<ContactFormatException>(()=>Xis1Codec.Encode(xiq,Xis1Status.OutcomeUnknown,ContactServiceMutationOutcome.OutcomeUnknown,50,0,ContactServicePaddingClass.Bytes256,[]));
        Assert.Throws<ContactFormatException>(()=>Xpc1Codec.Encode(xpk,Xpc1Status.OutcomeUnknown,ContactServiceMutationOutcome.OutcomeUnknown,50,0,ContactServicePaddingClass.Bytes256,[]));
        Assert.Throws<ContactFormatException>(()=>Xpo1Codec.Encode(xpu,Xpo1Status.RateLimited,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes256,[]));
        Assert.Throws<ContactFormatException>(()=>Xis1Codec.Encode(xiq,Xis1Status.RateLimited,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes256,[]));
        Assert.Throws<ContactFormatException>(()=>Xpc1Codec.Encode(xpk,Xpc1Status.RateLimited,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes256,[]));
    }

    [Fact]
    public void XiqClosesAntiSpamRegistryAtNoneWithEmptyToken()
    {
        var decoded=Xiq1Codec.Decode(Xiq());
        Assert.Equal(Xiq1AntiSpamTokenType.None,decoded.AntiSpamTokenType);
        Assert.Empty(decoded.AntiSpamToken.ToArray());
        Assert.Throws<ContactFormatException>(()=>Xiq1Codec.Encode(B(16,1),B(32,2),B(32,3),B(32,4),10,100,B(32,5),0,(Xiq1AntiSpamTokenType)1,[],ContactServicePaddingClass.Bytes1024));
        Assert.Throws<ContactFormatException>(()=>Xiq1Codec.Encode(B(16,1),B(32,2),B(32,3),B(32,4),10,100,B(32,5),0,Xiq1AntiSpamTokenType.None,B(1,6),ContactServicePaddingClass.Bytes1024));
    }

    [Fact]
    public void XpuAndXisAcceptOnlyTheirExactExpandedBounds()
    {
        var maximumXpu=Xpu(65_575,32,maximumRoute:true);
        Assert.Equal(92_992,maximumXpu.Length);
        Assert.Equal(3_666,Xpu1Codec.Decode(maximumXpu).ExactXpa1.Length);
        Assert.Equal("RecordLengthOutOfRange",Assert.Throws<ContactFormatException>(()=>Xpu1Codec.Decode(Xpu(65_576,32,maximumRoute:true))).Code);

        var route=RouteClosure(maximum:true);var cipher=B(65_575,80);var request=Xiq();
        Assert.Equal(23_295,route.Length);
        var result=Xis1Codec.Encode(request,Xis1Status.Success,ContactServiceMutationOutcome.DurablyCommitted,60,0,ContactServicePaddingClass.Bytes131072,[U64(0),U64(80),SHA256.HashData(cipher),cipher,SHA256.HashData(route),route,U64(7),Receipts()]);
        Assert.Equal(131_072,result.Length);
        Assert.Equal(89_388,Xis1Codec.Decode(result,request).CanonicalBytes.Length);
        Assert.Throws<ContactFormatException>(()=>Xis1Codec.Encode(request,Xis1Status.Success,ContactServiceMutationOutcome.None,60,0,ContactServicePaddingClass.Bytes65536,[U64(0),U64(80),SHA256.HashData(cipher),cipher,SHA256.HashData(route),route,Receipts()]));
        var mediumCipher=B(20_000,80);var minimumRoute=RouteClosure();
        Assert.Throws<ContactFormatException>(()=>Xis1Codec.Encode(request,Xis1Status.Success,ContactServiceMutationOutcome.None,60,0,ContactServicePaddingClass.Bytes65536,[U64(0),U64(80),SHA256.HashData(mediumCipher),mediumCipher,SHA256.HashData(minimumRoute),minimumRoute,Receipts()]));
        Assert.Throws<ContactFormatException>(()=>Xis1Codec.Encode(request,Xis1Status.Success,ContactServiceMutationOutcome.None,60,0,ContactServicePaddingClass.Bytes131072,[U64(0),U64(80),SHA256.HashData(B(40,80)),B(40,80),SHA256.HashData(RouteClosure()),RouteClosure(),Receipts()]));
        Assert.Throws<ContactFormatException>(()=>Xis1Codec.Encode(request,Xis1Status.Success,ContactServiceMutationOutcome.None,60,0,ContactServicePaddingClass.Bytes16384,[U64(0),U64(80),SHA256.HashData(B(40,80)),B(40,80),SHA256.HashData(RouteClosure()),RouteClosure()]));
        Assert.Throws<ContactFormatException>(()=>Xis1Codec.Encode(request,Xis1Status.NotFound,ContactServiceMutationOutcome.None,60,0,ContactServicePaddingClass.Bytes131072,[]));
    }

    [Fact]
    public void ClaimReceiptHashBindsExactDpkAndCompleteUnsignedTuple()
    {
        var request=Xpk();var requestHash=Xpk1Codec.Decode(request).RequestHash;var dpk=WithDpd1Reference(MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime),PreKeyInventoryTestData.Reference("DPD1",B(32,13)));var exactDpk=Dpk2Codec.Encode(dpk);const ulong commitGeneration=17;
        var manifest=PreKeyInventoryTestData.CreateClaimManifest(
            dpk,B(32,5),PreKeyInventoryTestData.Reference("XPS1",B(32,11)),
            PreKeyInventoryTestData.Reference("DRS1",B(32,12)));
        var receiptHash=Xpc1Codec.ComputeClaimReceiptHash(requestHash.Span,exactDpk,manifest.ExactXpi1,dpk.OneTimeX25519PrekeyId.Span,commitGeneration,0);
        var result=Xpc1Codec.Encode(request,Xpc1Status.Claimed,ContactServiceMutationOutcome.DurablyCommitted,60,0,ContactServicePaddingClass.Bytes4096,[exactDpk,dpk.OneTimeX25519PrekeyId,receiptHash,B(32,9),B(38,10),U64(dpk.PrekeyServiceGeneration),U64(dpk.ExpiresAt),U16(0),U64(commitGeneration),Receipts(),manifest.ExactXpi1,U16(manifest.InventoryIndex),manifest.InclusionProof]);
        Assert.Equal(Xpc1Status.Claimed,Xpc1Codec.Decode(result,request).Status);

        var changedProof=result.ToArray();changedProof[FieldOffset(changedProof,28)]^=1;
        Assert.Equal("InvalidXpi1InventoryMembership",Assert.Throws<ContactFormatException>(()=>Xpc1Codec.Decode(changedProof,request)).Code);
        var changedIndex=result.ToArray();WriteU16(changedIndex,FieldOffset(changedIndex,27),1);
        Assert.Equal("InvalidXpi1InventoryMembership",Assert.Throws<ContactFormatException>(()=>Xpc1Codec.Decode(changedIndex,request)).Code);

        var changed=result.ToArray();changed[FieldOffset(changed,18)]^=1;
        Assert.Equal("ClaimReceiptHashMismatch",Assert.Throws<ContactFormatException>(()=>Xpc1Codec.Decode(changed,request)).Code);
        Assert.NotEqual(receiptHash,Xpc1Codec.ComputeClaimReceiptHash(requestHash.Span,exactDpk,manifest.ExactXpi1,dpk.OneTimeX25519PrekeyId.Span,commitGeneration+1,0));
        var changedXpi1=manifest.ExactXpi1.ToArray();changedXpi1[^1]^=1;
        Assert.NotEqual(receiptHash,Xpc1Codec.ComputeClaimReceiptHash(requestHash.Span,exactDpk,changedXpi1,dpk.OneTimeX25519PrekeyId.Span,commitGeneration,0));
    }

    [Fact]
    public void UpdateEventHashBindsWriteAndSubsequentChainLinks()
    {
        var write=Xuw();var decodedWrite=Xuw1Codec.Decode(write);
        Assert.Equal(decodedWrite.EventHash.ToArray(),Xuw1Codec.ComputeEventHash(decodedWrite.EventGeneration,decodedWrite.PredecessorEventHash.Span,decodedWrite.EventCiphertextHash.Span,decodedWrite.EffectiveExpiresAtUnixSeconds,decodedWrite.SealedUpdate.Span));

        var query=Xuq();var first=Event(6,B(32,112),B(20,113),80);var firstHash=EventHash(first);var second=Event(7,firstHash,B(21,114),81);var data=first.Concat(second).ToArray();
        var result=Xus1Codec.Encode(query,Xus1OperationKind.Fetch,Xus1Status.Events,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes4096,[U16(2),data,U64(7),new byte[]{0}]);
        Assert.Equal(Xus1Status.Events,Xus1Codec.Decode(result,query).Status);
        data[84+20+8]^=1;
        Assert.Throws<ContactFormatException>(()=>Xus1Codec.Encode(query,Xus1OperationKind.Fetch,Xus1Status.Events,ContactServiceMutationOutcome.None,50,0,ContactServicePaddingClass.Bytes4096,[U16(2),data,U64(7),new byte[]{0}]));
    }

    private static byte[] Xiq()=>Xiq1Codec.Encode(B(16,1),B(32,2),B(32,3),B(32,4),10,100,B(32,5),0,Xiq1AntiSpamTokenType.None,[],ContactServicePaddingClass.Bytes1024);
    private static byte[] Xpk()=>Xpk1Codec.Encode(B(16,1),B(32,2),B(32,3),B(32,4),10,100,B(32,5),B(32,6),B(32,7),B(32,8),B(32,9));
    private static byte[] Xuw()=>Xuw1Codec.Encode(B(16,1),B(32,2),B(32,3),B(32,4),10,100,B(32,5),B(32,6),0,new byte[32],B(9,70),80);
    private static byte[] Xuq(ulong after=5)=>Xuq1Codec.Encode(B(16,1),B(32,2),B(32,3),B(32,4),10,100,B(32,5),B(32,6),after,4,ContactServicePaddingClass.Bytes4096);

    private static byte[] Xpu(int cipherLength=40,int witnessCount=2,bool maximumRoute=false)
    {
        var common=new (ushort,byte[])[]{(1,B(16,1)),(2,B(32,2)),(3,B(32,3)),(4,B(32,4)),(5,U64(10)),(6,U64(100))};var cipher=B(cipherLength,31);var route=RouteClosure(maximumRoute);
        var body=common.Concat(new (ushort,byte[])[]{(16,B(32,5)),(17,B(32,6)),(18,U64(0)),(19,new byte[32]),(20,SHA256.HashData(cipher)),(21,cipher),(22,U32(0)),(23,U64(80)),(24,SHA256.HashData(route)),(25,route)}).ToArray();
        var bodyHash=ContactCodec.Sha256Domain("Deep/ContactResolver/V1/XPU-authorized-body",Write("XPU1",body));
        var witnesses=Witnesses(witnessCount);
        var xpa=Write("XPA1",[(1,B(16,1)),(2,B(32,40)),(3,B(32,2)),(4,B(32,5)),(5,new byte[]{1}),(6,B(32,41)),(7,B(32,42)),(8,B(32,6)),(9,U64(0)),(10,new byte[32]),(11,SHA256.HashData(cipher)),(12,U32(0)),(13,U64(80)),(14,B(32,43)),(15,U64(5)),(16,U64(10)),(17,U64(90)),(18,B(32,44)),(19,bodyHash),(20,new byte[]{checked((byte)witnessCount)}),(21,witnesses)]);
        return Write("XPU1",body.Append(((ushort)26,xpa)).ToArray());
    }

    private static byte[] Event(ulong generation,byte[] predecessor,byte[] cipher,ulong expires){var b=new byte[84+cipher.Length];BinaryPrimitives.WriteUInt64BigEndian(b,generation);predecessor.CopyTo(b,8);SHA256.HashData(cipher).CopyTo(b,40);BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(72),expires);BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(80),checked((uint)cipher.Length));cipher.CopyTo(b,84);return b;}
    private static byte[] EventHash(byte[] exactEvent)=>Xuw1Codec.ComputeEventHash(BinaryPrimitives.ReadUInt64BigEndian(exactEvent),exactEvent.AsSpan(8,32),exactEvent.AsSpan(40,32),BinaryPrimitives.ReadUInt64BigEndian(exactEvent.AsSpan(72)),exactEvent.AsSpan(84));
    private static Dpk2Record WithDpd1Reference(Dpk2Record value,byte[] reference)=>new(
        value.NetworkId.Span,value.ResponderAccountId.Span,value.ResponderDeviceId.Span,value.ResponderDeviceGeneration,
        reference,value.DeviceDirectoryGeneration,value.DeviceDirectoryHeadHash.Span,value.PrekeyServiceGeneration,
        1,value.BundleId.Span,value.PolicyGeneration,value.NotBefore,value.IssuedAt,value.ExpiresAt,
        value.DeviceAgreementPublicKey.Span,value.SignedX25519PrekeyId.Span,value.SignedX25519PrekeyPublic.Span,
        value.SignedX25519PrekeySignature.Span,value.OneTimeX25519PrekeyId.Span,value.OneTimeX25519PrekeyPublic.Span,
        value.MlKemPrekeyId.Span,value.MlKem768EncapsulationKey.Span,value.MlKemKind,value.ReuseLimit,
        value.MlKemPrekeySignature.Span,value.BundleSignature.Span);
    private static byte[] RouteClosure(bool maximum=false){var c=maximum?ContactCodecTests.Records.MaximumRouteClosure:ContactCodecTests.Records.RouteClosure;var records=new[]{c.Xrr,c.Xra,c.Xrc,c.Xss,c.Pmt,c.Pms};var size=1+records.Sum(r=>4+r.CanonicalBytes.Length);var b=new byte[size];b[0]=6;var o=1;foreach(var record in records){BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(o),checked((uint)record.CanonicalBytes.Length));o+=4;record.CanonicalBytes.Span.CopyTo(b.AsSpan(o));o+=record.CanonicalBytes.Length;}return b;}
    private static byte[] Receipts(){var b=new byte[193];b[0]=2;B(32,1).CopyTo(b,1);B(64,10).CopyTo(b,33);B(32,2).CopyTo(b,97);B(64,11).CopyTo(b,129);return b;}
    private static byte[] Witnesses(int count){var b=new byte[checked(count*96)];for(var i=0;i<count;i++){B(32,checked((byte)(1+i))).CopyTo(b,i*96);B(64,checked((byte)(10+i))).CopyTo(b,i*96+32);}return b;}
    private static byte[] B(int n,byte seed){var b=new byte[n];for(var i=0;i<n;i++)b[i]=(byte)(seed+i%17);return b;}
    private static byte[] U16(ushort v){var b=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(b,v);return b;}
    private static byte[] U32(uint v){var b=new byte[4];BinaryPrimitives.WriteUInt32BigEndian(b,v);return b;}
    private static byte[] U64(ulong v){var b=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(b,v);return b;}
    private static string HexHash(byte[] b)=>Convert.ToHexString(SHA256.HashData(b));
    private static void WriteU16(byte[] b,int o,ushort v)=>BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o,2),v);
    private static void WriteU32(byte[] b,int o,uint v)=>BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(o,4),v);
    private static ushort[] Tags(byte[] b){var n=BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(8,2));var result=new ushort[n];var o=12;for(var i=0;i<n;i++){result[i]=BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(o,2));o+=8+checked((int)BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(o+4,4)));}return result;}
    private static int FieldHeaderOffset(byte[] b,ushort wanted){var n=BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(8,2));var o=12;for(var i=0;i<n;i++){var t=BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(o,2));if(t==wanted)return o;o+=8+checked((int)BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(o+4,4)));}throw new InvalidOperationException();}
    private static int FieldOffset(byte[] b,ushort tag)=>FieldHeaderOffset(b,tag)+8;
    private static byte[] Field(ReadOnlySpan<byte> b,ushort wanted){var n=BinaryPrimitives.ReadUInt16BigEndian(b.Slice(8,2));var o=12;for(var i=0;i<n;i++){var t=BinaryPrimitives.ReadUInt16BigEndian(b.Slice(o,2));var size=checked((int)BinaryPrimitives.ReadUInt32BigEndian(b.Slice(o+4,4)));o+=8;if(t==wanted)return b.Slice(o,size).ToArray();o+=size;}throw new InvalidOperationException();}
    private static byte[] Write(string magic,IReadOnlyList<(ushort Tag,byte[] Value)> fields){var size=12+fields.Sum(f=>8+f.Value.Length);var b=new byte[size];Encoding.ASCII.GetBytes(magic).CopyTo(b,0);WriteU16(b,4,1);WriteU16(b,6,0x0201);WriteU16(b,8,checked((ushort)fields.Count));var o=12;foreach(var f in fields){WriteU16(b,o,f.Tag);WriteU32(b,o+4,checked((uint)f.Value.Length));o+=8;f.Value.CopyTo(b,o);o+=f.Value.Length;}return b;}
}
