using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class ApplicationCoreNegativeTests
{
    [Theory]
    [InlineData(0, 0x58, ApplicationCoreValidationStage.FixedHeader, ApplicationCoreRejection.WrongMagic)]
    [InlineData(5, 0x02, ApplicationCoreValidationStage.FixedHeader, ApplicationCoreRejection.WrongVersion)]
    [InlineData(7, 0x02, ApplicationCoreValidationStage.FixedHeader, ApplicationCoreRejection.WrongSuite)]
    [InlineData(9, 0x03, ApplicationCoreValidationStage.FixedHeader, ApplicationCoreRejection.WrongFieldCount)]
    [InlineData(11, 0x01, ApplicationCoreValidationStage.FixedHeader, ApplicationCoreRejection.ReservedNotZero)]
    [InlineData(13, 0x02, ApplicationCoreValidationStage.FieldHeaders, ApplicationCoreRejection.OutOfOrderTag)]
    [InlineData(15, 0x01, ApplicationCoreValidationStage.FieldHeaders, ApplicationCoreRejection.ReservedNotZero)]
    [InlineData(53, 0x01, ApplicationCoreValidationStage.FieldHeaders, ApplicationCoreRejection.DuplicateTag)]
    public void SharedHeaderAndFieldGrammar_RejectsExactly(
        int offset,
        byte value,
        ApplicationCoreValidationStage stage,
        ApplicationCoreRejection rejection)
    {
        var canonical = ApplicationCoreCodec.AuthorDid1(
            ApplicationCoreFixture.Bytes(32, 0x11), ApplicationCoreFixture.Bytes(16, 0x22))
            .CanonicalBytes.ToArray();
        canonical[offset] = value;

        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDid1(canonical));
        Assert.Equal(stage, exception.Stage);
        Assert.Equal(rejection, exception.Rejection);
    }

    [Fact]
    public void Did1_ZeroFieldAndNonCanonicalTextReject()
    {
        var zero = Assert.Throws<ApplicationCoreFormatException>(() =>
            ApplicationCoreCodec.AuthorDid1(new byte[32], ApplicationCoreFixture.Bytes(16, 0x22)));
        Assert.Equal(ApplicationCoreRejection.ZeroForbidden, zero.Rejection);

        var text = ApplicationCoreCodec.AuthorDid1(
            ApplicationCoreFixture.Bytes(32, 0x11), ApplicationCoreFixture.Bytes(16, 0x22)).Text;
        var upper = Assert.Throws<ApplicationCoreFormatException>(() =>
            ApplicationCoreCodec.DecodeDeepIdText(text.ToUpperInvariant()));
        Assert.Equal(ApplicationCoreRejection.NonCanonicalText, upper.Rejection);

        var damaged = text[..^1] + (text[^1] == 'q' ? 'p' : 'q');
        Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDeepIdText(damaged));
    }

    [Theory]
    [InlineData(0UL, 0x01, 1UL, ApplicationCoreRejection.InvalidLineage)]
    [InlineData(1UL, 0x00, 1UL, ApplicationCoreRejection.InvalidLineage)]
    [InlineData(0UL, 0x00, 0UL, ApplicationCoreRejection.InvalidGeneration)]
    public void Dab1_LineageAndAccountGenerationReject(
        ulong bindingGeneration,
        byte predecessor,
        ulong accountGeneration,
        ApplicationCoreRejection rejection)
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.AuthorDab1(
            ApplicationCoreFixture.Bytes(32, 0x11), ApplicationCoreFixture.Bytes(32, 0x12),
            bindingGeneration, ApplicationCoreFixture.Bytes(32, predecessor),
            ApplicationCoreFixture.Bytes(32, 0x13), accountGeneration,
            ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x14),
            ApplicationCoreFixture.Bytes(64, 0x15), ApplicationCoreFixture.Bytes(64, 0x16)));
        Assert.Equal(rejection, exception.Rejection);
    }

    [Fact]
    public void Dmd1_SuccessorRequiresNonzeroPredecessor()
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreFixture.Directory(
            ApplicationCoreFixture.Bytes(16, 0x21), ApplicationCoreFixture.Bytes(32, 0x22),
            ApplicationCoreFixture.Bytes(32, 0x31), generation: 2));
        Assert.Equal(ApplicationCoreRejection.InvalidLineage, exception.Rejection);
    }

    [Theory]
    [InlineData(0, 10UL, 20UL, ApplicationCoreRejection.InvalidFlags)]
    [InlineData(4, 10UL, 20UL, ApplicationCoreRejection.InvalidFlags)]
    [InlineData(1, 20UL, 20UL, ApplicationCoreRejection.InvalidTimeRange)]
    public void Dca1_ClosedMaskAndTimeRangeReject(
        byte mask,
        ulong notBefore,
        ulong expiresAt,
        ApplicationCoreRejection rejection)
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.AuthorDca1(
            ApplicationCoreFixture.Bytes(16, 0x11), ApplicationCoreFixture.Bytes(32, 0x12),
            ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x13), 1,
            ApplicationCoreFixture.Bytes(32, 0x14), ApplicationCoreFixture.Bytes(32, 0x15),
            ApplicationCoreFixture.Bytes(32, 0x16), mask, 100, notBefore, expiresAt,
            ApplicationCoreFixture.Bytes(64, 0x17), ApplicationCoreFixture.Bytes(32, 0x18),
            ApplicationCoreFixture.Reference(ApplicationCoreCodec.Dab1ArtifactTypeCode, 394, 0x19)));
        Assert.Equal(rejection, exception.Rejection);
    }

    [Theory]
    [InlineData(4725)]
    [InlineData(4821)]
    [InlineData(4885)]
    [InlineData(5685)]
    [InlineData(5877)]
    [InlineData(6129)]
    [InlineData(17013)]
    [InlineData(17109)]
    [InlineData(17173)]
    [InlineData(17973)]
    [InlineData(18165)]
    [InlineData(18417)]
    [InlineData(33397)]
    [InlineData(33493)]
    [InlineData(33557)]
    [InlineData(34357)]
    [InlineData(34549)]
    [InlineData(34801)]
    [InlineData(49765)]
    [InlineData(49861)]
    [InlineData(49925)]
    [InlineData(50725)]
    [InlineData(50917)]
    public void Dao1_EveryAndOnlyFrozenTotalAuthors(int total)
    {
        var record = ApplicationCoreCodec.AuthorDao1(
            ApplicationCoreFixture.Bytes(16, 0x11), ApplicationCoreFixture.Bytes(32, 0x12),
            ApplicationCoreFixture.Bytes(32, 0x13), ApplicationCoreFixture.Bytes(32, 0x14),
            ApplicationCoreFixture.Bytes(24, 0x15), ApplicationCoreFixture.Bytes(total - 196, 0x16));
        Assert.Equal(total, record.CanonicalBytes.Length);
    }

    [Fact]
    public void Dmc2_CommonZerosAndTimeRangeReject()
    {
        var payload = ApplicationCoreCodec.CreateMessageCreatePayload("x");
        var zeroSequence = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.AuthorDmc2(
            ApplicationCoreFixture.Bytes(16, 0x11), ApplicationCoreFixture.Bytes(32, 0x12),
            ApplicationCoreFixture.Bytes(32, 0x13), ApplicationCoreFixture.Bytes(32, 0x14),
            ApplicationCoreFixture.Bytes(32, 0x15), 0, 1000, 0, Dmc2Flags.None, [], payload));
        Assert.Equal(ApplicationCoreRejection.InvalidGeneration, zeroSequence.Rejection);

        var zeroLogicalId = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.AuthorDmc2(
            ApplicationCoreFixture.Bytes(16, 0x11), new byte[32],
            ApplicationCoreFixture.Bytes(32, 0x13), ApplicationCoreFixture.Bytes(32, 0x14),
            ApplicationCoreFixture.Bytes(32, 0x15), 1, 1000, 0, Dmc2Flags.None, [], payload));
        Assert.Equal(ApplicationCoreRejection.ZeroForbidden, zeroLogicalId.Rejection);

        var badExpiry = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.AuthorDmc2(
            ApplicationCoreFixture.Bytes(16, 0x11), ApplicationCoreFixture.Bytes(32, 0x12),
            ApplicationCoreFixture.Bytes(32, 0x13), ApplicationCoreFixture.Bytes(32, 0x14),
            ApplicationCoreFixture.Bytes(32, 0x15), 1, 1000, 1000, Dmc2Flags.None, [], payload));
        Assert.Equal(ApplicationCoreRejection.InvalidTimeRange, badExpiry.Rejection);
    }

    [Fact]
    public void Dmc2_InvalidUtf8NulAndInvalidUtf16Reject()
    {
        var canonical = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateMessageCreatePayload("x")).CanonicalBytes.ToArray();
        canonical[ApplicationCoreFixture.FieldOffset(canonical, 12) + 2] = 0xc0;
        var invalidUtf8 = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDmc2(canonical));
        Assert.Equal(ApplicationCoreRejection.NonCanonicalText, invalidUtf8.Rejection);

        Assert.Equal(ApplicationCoreRejection.NonCanonicalText,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                ApplicationCoreCodec.CreateMessageCreatePayload("x\0y")).Rejection);
        Assert.Equal(ApplicationCoreRejection.NonCanonicalText,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                ApplicationCoreCodec.CreateMessageCreatePayload("\ud800")).Rejection);
    }

    [Fact]
    public void DecodersOwnCanonicalBytesBeforeDerivedHashes()
    {
        var input = ApplicationCoreCodec.AuthorDab1(
            ApplicationCoreFixture.Bytes(32, 0x11), ApplicationCoreFixture.Bytes(32, 0x12),
            0, new byte[32], ApplicationCoreFixture.Bytes(32, 0x13), 1,
            ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x14),
            ApplicationCoreFixture.Bytes(64, 0x15), ApplicationCoreFixture.Bytes(64, 0x16))
            .CanonicalBytes.ToArray();
        var decoded = ApplicationCoreCodec.DecodeDab1(input);
        var canonical = decoded.CanonicalBytes.ToArray();
        var hash = decoded.RecordHash.ToArray();

        input.AsSpan().Fill(0xff);

        Assert.Equal(canonical, decoded.CanonicalBytes.ToArray());
        Assert.Equal(hash, decoded.RecordHash.ToArray());
        Assert.Equal("AB7E5646D100E52914A9FCD0AFA01B8FFC1684EFADFB89F75AFC446122DCA1CA",
            Convert.ToHexString(decoded.RecordHash.Span));
    }

    [Fact]
    public void Dmc2_TrailingBytesRejectAsNoncanonicalGrammar()
    {
        var canonical = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateMessageCreatePayload("x")).CanonicalBytes.ToArray();
        Array.Resize(ref canonical, canonical.Length + 1);

        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDmc2(canonical));
        Assert.Equal(ApplicationCoreRejection.TrailingBytes, exception.Rejection);
    }
}
