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
    [InlineData(37, 0x01, ApplicationCoreValidationStage.FieldHeaders, ApplicationCoreRejection.DuplicateTag)]
    public void SharedHeaderAndFieldGrammar_RejectsExactly(
        int offset, byte value, ApplicationCoreValidationStage stage,
        ApplicationCoreRejection rejection)
    {
        var canonical = ApplicationCoreFixture.Directory(
            ApplicationCoreFixture.Bytes(16, 0x21), ApplicationCoreFixture.Bytes(32, 0x22),
            ApplicationCoreFixture.Bytes(32, 0x31)).CanonicalBytes.ToArray();
        canonical[offset] = value;
        var error = Assert.Throws<ApplicationCoreFormatException>(() =>
            ApplicationCoreCodec.DecodeDmd1(canonical));
        Assert.Equal(stage, error.Stage);
        Assert.Equal(rejection, error.Rejection);
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
    [InlineData(4725)]
    [InlineData(4821)]
    [InlineData(4885)]
    [InlineData(5685)]
    [InlineData(5877)]
    [InlineData(8189)]
    [InlineData(17013)]
    [InlineData(17109)]
    [InlineData(17173)]
    [InlineData(17973)]
    [InlineData(18165)]
    [InlineData(20477)]
    [InlineData(33397)]
    [InlineData(33493)]
    [InlineData(33557)]
    [InlineData(34357)]
    [InlineData(34549)]
    [InlineData(36861)]
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

    [Theory]
    [InlineData(6129)]
    [InlineData(18417)]
    [InlineData(34801)]
    public void Dao1_RetiredDph2TotalsReject(int total)
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(() =>
            ApplicationCoreCodec.AuthorDao1(
                ApplicationCoreFixture.Bytes(16, 0x11), ApplicationCoreFixture.Bytes(32, 0x12),
                ApplicationCoreFixture.Bytes(32, 0x13), ApplicationCoreFixture.Bytes(32, 0x14),
                ApplicationCoreFixture.Bytes(24, 0x15), ApplicationCoreFixture.Bytes(total - 196, 0x16)));
        Assert.Equal(ApplicationCoreRejection.InvalidTotalSize, exception.Rejection);
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
    public void Dmc2_TrailingBytesRejectAsNoncanonicalGrammar()
    {
        var canonical = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateMessageCreatePayload("x")).CanonicalBytes.ToArray();
        Array.Resize(ref canonical, canonical.Length + 1);

        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDmc2(canonical));
        Assert.Equal(ApplicationCoreRejection.TrailingBytes, exception.Rejection);
    }
}
