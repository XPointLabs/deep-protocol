using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class ApplicationCoreGoldenTests
{

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
