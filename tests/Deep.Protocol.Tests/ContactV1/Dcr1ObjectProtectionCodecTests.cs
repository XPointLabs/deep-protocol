using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class Dcr1ObjectProtectionCodecTests
{
    [Fact]
    public void PermanentProtectionHasDeterministicGoldenAndExactRoundTrip()
    {
        var dcr=ContactCodecTests.Records.Dcr;var network=dcr.Field(1).ToArray();
        var did=ApplicationCoreCodec.AuthorDid1(B(32,10),B(16,20));
        using var resolution=PermanentContactResolutionDerivation.Derive(network,did);
        var protectedBytes=ContactCodecValidation.SealPermanentDcr1(dcr,network,did,resolution,B(24,30));

        Assert.Equal("B38990FFF5CF6812B4EBDF46A076DE0FC931C58708BAFFB9D6C1684B1365C6A3",Convert.ToHexString(SHA256.HashData(protectedBytes)));
        Assert.Equal(B(24,30),protectedBytes[..24]);
        var opened=Dcr1ObjectProtectionCodec.OpenPermanent(protectedBytes,network,did,resolution);
        Assert.Equal(dcr.CanonicalBytes.ToArray(),opened.CanonicalBytes.ToArray());
    }

    [Fact]
    public void OneTimeProtectionUsesZeroKeyProjectionAadAndRoundTrips()
    {
        var dcr=ContactCodecTests.Records.Dcr;var dia=Dia(dcr,B(32,40),B(32,50));
        var protectedBytes=ContactCodecValidation.SealOneTimeDcr1(dcr,dia,B(24,60));
        Assert.Equal("E06F00E86CB85E4420B4A763FE75BF9375820459FFD913D5E59A31C1171AE095",Convert.ToHexString(SHA256.HashData(protectedBytes)));
        Assert.Equal(dcr.CanonicalBytes.ToArray(),Dcr1ObjectProtectionCodec.OpenOneTime(protectedBytes,dia).CanonicalBytes.ToArray());

        var sameKeyDifferentInvitation=Dia(dcr,B(32,41),dia.Field(6).ToArray());
        Assert.Equal("Dcr1ObjectAuthenticationFailed",Assert.Throws<ContactFormatException>(()=>Dcr1ObjectProtectionCodec.OpenOneTime(protectedBytes,sameKeyDifferentInvitation)).Code);
    }

    [Fact]
    public void PermanentOpenRejectsWrongNetworkDidAndTampering()
    {
        var dcr=ContactCodecTests.Records.Dcr;var network=dcr.Field(1).ToArray();var did=ApplicationCoreCodec.AuthorDid1(B(32,70),B(16,80));
        using var resolution=PermanentContactResolutionDerivation.Derive(network,did);
        var protectedBytes=ContactCodecValidation.SealPermanentDcr1(dcr,network,did,resolution,B(24,90));

        var wrongNetwork=network.ToArray();wrongNetwork[^1]^=1;
        Assert.Equal("Dcr1ObjectAuthenticationFailed",Assert.Throws<ContactFormatException>(()=>Dcr1ObjectProtectionCodec.OpenPermanent(protectedBytes,wrongNetwork,did,resolution)).Code);
        var wrongDid=ApplicationCoreCodec.AuthorDid1(B(32,71),B(16,80));
        Assert.Equal("Dcr1ObjectAuthenticationFailed",Assert.Throws<ContactFormatException>(()=>Dcr1ObjectProtectionCodec.OpenPermanent(protectedBytes,network,wrongDid,resolution)).Code);
        var tampered=protectedBytes.ToArray();tampered[^1]^=1;
        Assert.Equal("Dcr1ObjectAuthenticationFailed",Assert.Throws<ContactFormatException>(()=>Dcr1ObjectProtectionCodec.OpenPermanent(tampered,network,did,resolution)).Code);
    }

    [Fact]
    public void OneTimeOpenRejectsWrongDiaKeyAadAndTampering()
    {
        var dcr=ContactCodecTests.Records.Dcr;var dia=Dia(dcr,B(32,100),B(32,110));var protectedBytes=ContactCodecValidation.SealOneTimeDcr1(dcr,dia,B(24,120));
        var wrongKey=Dia(dcr,dia.Field(2).ToArray(),B(32,111));
        Assert.Equal("Dcr1ObjectAuthenticationFailed",Assert.Throws<ContactFormatException>(()=>Dcr1ObjectProtectionCodec.OpenOneTime(protectedBytes,wrongKey)).Code);
        var changed=protectedBytes.ToArray();changed[24]^=1;
        Assert.Equal("Dcr1ObjectAuthenticationFailed",Assert.Throws<ContactFormatException>(()=>Dcr1ObjectProtectionCodec.OpenOneTime(changed,dia)).Code);
        Assert.Equal("ProtectedDcr1LengthOutOfRange",Assert.Throws<ContactFormatException>(()=>Dcr1ObjectProtectionCodec.OpenOneTime(new byte[39],dia)).Code);
    }

    [Fact]
    public void ProductionSealUsesFreshCspNonceAndHasNoPublicEntropyInjection()
    {
        var dcr=ContactCodecTests.Records.Dcr;var dia=Dia(dcr,B(32,130),B(32,140));
        var first=Dcr1ObjectProtectionCodec.SealOneTime(dcr,dia);var second=Dcr1ObjectProtectionCodec.SealOneTime(dcr,dia);
        Assert.False(first.AsSpan(0,24).SequenceEqual(second.AsSpan(0,24)));
        Assert.DoesNotContain(typeof(Dcr1ObjectProtectionCodec).GetMethods(),method=>method.IsPublic&&method.GetParameters().Any(parameter=>parameter.ParameterType.Name.Contains("Entropy",StringComparison.Ordinal)));
    }

    [Fact]
    public void SealRejectsCrossNetworkDcrBeforeEncryption()
    {
        var dcr=ContactCodecTests.Records.Dcr;var dia=ContactCodecTests.Records.Dia;
        Assert.Equal("Dcr1NetworkMismatch",Assert.Throws<ContactFormatException>(()=>Dcr1ObjectProtectionCodec.SealOneTime(dcr,dia)).Code);
    }

    private static ContactRecord Dia(ContactRecord dcr,byte[] invitationId,byte[] key)
    {
        var expectedDcbHash=SHA256.HashData(dcr.Field(2).Span);
        return ContactCodecValidation.AuthorRecord("DIA1",[dcr.Field(1),invitationId,new byte[]{2},U16(1),B(16,1),key,expectedDcbHash,U64(500),U16(1)]);
    }

    private static byte[] B(int length,byte seed){var b=new byte[length];for(var i=0;i<length;i++)b[i]=(byte)(seed+i%13);return b;}
    private static byte[] U16(ushort value){var b=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(b,value);return b;}
    private static byte[] U64(ulong value){var b=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(b,value);return b;}
}
