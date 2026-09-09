using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class ApplicationCoreGoldenTests
{
    [Fact]
    public void Did1_MatchesIndependentCanonicalAndTextGolden()
    {
        var record = ApplicationCoreCodec.AuthorDid1(
            ApplicationCoreFixture.Bytes(32, 0x11), ApplicationCoreFixture.Bytes(16, 0x22));

        Assert.Equal(
            "4449443100010201000200000001000000000020" + new string('1', 64) +
            "0002000000000010" + new string('2', 32),
            Convert.ToHexString(record.CanonicalBytes.Span));
        Assert.Equal(
            "deep1qyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zg3zyg3zyg3zyg3zyg3zyg3zygshqyzd0",
            record.Text);
        Assert.Equal("81C4C3A115E513AF83CA9343E4AD4A29557427C1EC9726EF01B9F4238FD3AB58",
            Convert.ToHexString(record.RecordHash.Span));
    }

    [Fact]
    public void Dab1_MatchesIndependentRecordAndProjectionGoldens()
    {
        var record = ApplicationCoreCodec.AuthorDab1(
            ApplicationCoreFixture.Bytes(32, 0x11), ApplicationCoreFixture.Bytes(32, 0x12),
            0, new byte[32], ApplicationCoreFixture.Bytes(32, 0x13), 1,
            ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x14),
            ApplicationCoreFixture.Bytes(64, 0x15), ApplicationCoreFixture.Bytes(64, 0x16));

        AssertGolden(record, "AB7E5646D100E52914A9FCD0AFA01B8FFC1684EFADFB89F75AFC446122DCA1CA");
        Assert.Equal("945815952BA32ED68AF407E8FB85BD909B22429551DD09CBD68D0740C93A00A1",
            RawHash(record.UnsignedCanonicalBytes.Span));
    }

    [Fact]
    public void Dmd1_MatchesIndependentRecordAndProjectionGoldens()
    {
        var entries = new[]
        {
            new DeviceDirectoryEntry(ApplicationCoreFixture.Bytes(32, 0x31),
                ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpd1, 776, 0x41)),
            new DeviceDirectoryEntry(ApplicationCoreFixture.Bytes(32, 0x32),
                ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpd1, 776, 0x42)),
        };
        var record = ApplicationCoreCodec.AuthorDmd1(
            ApplicationCoreFixture.Bytes(16, 0x21), ApplicationCoreFixture.Bytes(32, 0x22), 1,
            ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x43),
            ApplicationCoreFixture.Reference((ushort)ArtifactType.Drs1, 356, 0x44),
            1, new byte[32], entries, 100, ApplicationCoreFixture.Bytes(64, 0x45));

        AssertGolden(record, "CA1D55C805F4FD3D48B0745BA2366A1378EF934AD6B29386C203F65B4A48CDD1");
        Assert.Equal("43AD9F83DC255E90EC6928229DCBBF7F2209009F26F54494822F8EAC76E73D44",
            RawHash(record.UnsignedCanonicalBytes.Span));
    }

    [Fact]
    public void Dca1_MatchesIndependentRecordAndProjectionGoldens()
    {
        var record = ApplicationCoreCodec.AuthorDca1(
            ApplicationCoreFixture.Bytes(16, 0x11), ApplicationCoreFixture.Bytes(32, 0x12),
            ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x13), 1,
            ApplicationCoreFixture.Bytes(32, 0x14), ApplicationCoreFixture.Bytes(32, 0x15),
            ApplicationCoreFixture.Bytes(32, 0x16), 3, 100, 10, 20,
            ApplicationCoreFixture.Bytes(64, 0x17), ApplicationCoreFixture.Bytes(32, 0x18),
            ApplicationCoreFixture.Reference(ApplicationCoreCodec.Dab1ArtifactTypeCode, 394, 0x19));

        AssertGolden(record, "020F3006D97556822CDE1ED6DB8D16F9F5A2D4725074B59111D365DB70999036");
        Assert.Equal("319290CE33A4409F6C270686C94C5DDF4AF270B5EB92DD4BF76AF9CFA6ACE8DE",
            RawHash(record.SigningProjection.Span));
    }

    [Fact]
    public void Dao1_MatchesIndependentRecordAndHeaderGoldens()
    {
        var record = ApplicationCoreCodec.AuthorDao1(
            ApplicationCoreFixture.Bytes(16, 0x11), ApplicationCoreFixture.Bytes(32, 0x12),
            ApplicationCoreFixture.Bytes(32, 0x13), ApplicationCoreFixture.Bytes(32, 0x14),
            ApplicationCoreFixture.Bytes(24, 0x15), ApplicationCoreFixture.Bytes(4529, 0x16));

        AssertGolden(record, "14FB227A3C7345F05756F7C401F8D64C83D2AB42E5E678B54E89E78235F379D6");
        Assert.Equal("E84E2447456AFD016C57E98F9A80CFDC6B86CD826E6E20BB91D918B5699E51BF",
            RawHash(record.AeadHeader.Span));
    }

    [Fact]
    public void Dmc2MessageCreate_MatchesIndependentRecordGolden()
    {
        var record = ApplicationCoreCodec.AuthorDmc2(
            ApplicationCoreFixture.Bytes(16, 0x11), ApplicationCoreFixture.Bytes(32, 0x12),
            ApplicationCoreFixture.Bytes(32, 0x13), ApplicationCoreFixture.Bytes(32, 0x14),
            ApplicationCoreFixture.Bytes(32, 0x15), 1, 1000, 0, Dmc2Flags.None, [],
            ApplicationCoreCodec.CreateMessageCreatePayload("hello"));

        Assert.Equal(289, record.CanonicalBytes.Length);
        AssertGolden(record, "0299214154290C05C74C442E90BE2A25FD192BB461494A9A38930D67A5E5C9C6");
    }

    private static void AssertGolden(ParsedApplicationCoreRecord record, string expectedRecordHash) =>
        Assert.Equal(expectedRecordHash, Convert.ToHexString(record.RecordHash.Span));

    private static string RawHash(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(SHA256.HashData(value));
}
