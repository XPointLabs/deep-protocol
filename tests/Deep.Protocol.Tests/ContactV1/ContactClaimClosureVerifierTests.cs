using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class ContactClaimClosureVerifierTests
{
    [Fact]
    public void ExactVerifiedXisClaimRestoresAuthoritativeDcaAndPublisherDevice()
    {
        var fixture = ContactCodecSecurityTests.CryptoDcrFixture.Create(
            networkId: ContactCodecTests.Records.RouteClosure.Xrr.Field(1).ToArray());
        var dia1 = Dia(fixture.Dcr, Bytes(32, 0x41), Bytes(32, 0x51), 90);
        var protectedDcr1 = Dcr1ObjectProtectionCodec.SealOneTime(fixture.Dcr, dia1);
        var claim = Xis1InviteClaimReceiptVerifierTests.CreateVerifiedOneTimeClaim(
            fixture.Dcr.Field(1).Span, protectedDcr1);

        var closure = ContactClaimClosureVerifier.VerifyOneTimeClaim(
            claim, dia1, fixture.Freshness, fixture.BootId, fixture.CurrentMonotonicSample);

        Assert.Equal(fixture.Dcr.CanonicalBytes.ToArray(), closure.ExactDcr1.ToArray());
        Assert.Same(closure.Contact.Authorization, closure.Authorization);
        Assert.Equal((ulong)30, closure.Authorization.TrustedUnixSeconds);
        Assert.Equal(closure.Contact.Bundle.Field(10).ToArray(),
            closure.PublisherDevice.Certificate.DeviceId.ToArray());
        Assert.Contains(closure.PublisherDevice, closure.Contact.Directory.Identity.ActiveDevices);
        Assert.Equal(claim.ExactXis1.ToArray(), closure.Claim.ExactXis1.ToArray());
    }

    [Fact]
    public void WrongKeyBundleFreshnessAndInvitationTimeFailClosed()
    {
        var network = ContactCodecTests.Records.RouteClosure.Xrr.Field(1).ToArray();
        var fixture = ContactCodecSecurityTests.CryptoDcrFixture.Create(networkId: network);
        var dia1 = Dia(fixture.Dcr, Bytes(32, 0x41), Bytes(32, 0x51), 90);
        var protectedDcr1 = Dcr1ObjectProtectionCodec.SealOneTime(fixture.Dcr, dia1);
        var claim = Xis1InviteClaimReceiptVerifierTests.CreateVerifiedOneTimeClaim(
            fixture.Dcr.Field(1).Span, protectedDcr1);

        AssertCode("ClaimClosureRejected", () => ContactClaimClosureVerifier.VerifyOneTimeClaim(
            claim, Dia(fixture.Dcr, dia1.Field(2).ToArray(), Bytes(32, 0x52), 90),
            fixture.Freshness, fixture.BootId, fixture.CurrentMonotonicSample));
        AssertCode("DirectoryFreshnessExpired", () => ContactClaimClosureVerifier.VerifyOneTimeClaim(
            claim, dia1, fixture.Freshness, Bytes(16, 0x91), fixture.CurrentMonotonicSample));
        AssertCode("InvitationExpired", () => ContactClaimClosureVerifier.VerifyOneTimeClaim(
            claim, Dia(fixture.Dcr, Bytes(32, 0x41), Bytes(32, 0x51), 30),
            fixture.Freshness, fixture.BootId, fixture.CurrentMonotonicSample));

        var foreign = ContactCodecSecurityTests.CryptoDcrFixture.Create(1, networkId: network);
        AssertCode("ClaimClosureRejected", () => ContactClaimClosureVerifier.VerifyOneTimeClaim(
            claim, dia1, foreign.Freshness, foreign.BootId, foreign.CurrentMonotonicSample));

        var otherDcr = foreign.Dcr;
        var mismatchedCiphertext = Dcr1ObjectProtectionCodec.SealOneTime(otherDcr, dia1);
        var mismatchedClaim = Xis1InviteClaimReceiptVerifierTests.CreateVerifiedOneTimeClaim(
            fixture.Dcr.Field(1).Span, mismatchedCiphertext);
        AssertCode("InvitationBundleMismatch", () => ContactClaimClosureVerifier.VerifyOneTimeClaim(
            mismatchedClaim, dia1, fixture.Freshness, fixture.BootId,
            fixture.CurrentMonotonicSample));
    }

    [Fact]
    public void PublicFacadeHasNoRawReceiptKeyBoolOrForgeableOutputPath()
    {
        Assert.Empty(typeof(VerifiedContactClaimClosure).GetConstructors());
        var method = Assert.Single(typeof(ContactClaimClosureVerifier).GetMethods(),
            static candidate => candidate.IsPublic && candidate.DeclaringType == typeof(ContactClaimClosureVerifier));
        Assert.Equal(nameof(ContactClaimClosureVerifier.VerifyOneTimeClaim), method.Name);
        Assert.DoesNotContain(method.GetParameters(), parameter =>
            parameter.ParameterType == typeof(bool) ||
            parameter.ParameterType.Name.Contains("DxpReceiptRelative", StringComparison.Ordinal) ||
            parameter.Name?.Contains("key", StringComparison.OrdinalIgnoreCase) == true);
    }

    private static ContactRecord Dia(
        ContactRecord dcr1, byte[] invitationId, byte[] objectKey, ulong expiresAt)
    {
        var expectedBundleHash = SHA256.HashData(dcr1.Field(2).Span);
        return ContactCodecValidation.AuthorRecord("DIA1",
            [dcr1.Field(1),invitationId,new byte[]{2},U16(1),Bytes(16,0x31),objectKey,
             expectedBundleHash,U64(expiresAt),U16(1)]);
    }

    private static void AssertCode(string code, Action action) =>
        Assert.Equal(code, Assert.Throws<ContactClaimClosureException>(action).Code);
    private static byte[] Bytes(int length, byte seed) =>
        Enumerable.Range(0, length).Select(index => unchecked((byte)(seed + index))).ToArray();
    private static byte[] U16(ushort value){var output=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(output,value);return output;}
    private static byte[] U64(ulong value){var output=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(output,value);return output;}
}
