using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class ApplicationCoreRecordTests
{

    [Fact]
    public void Dmd1_RoundTripsSortedDirectoryAndProjection()
    {
        var network = ApplicationCoreFixture.Bytes(16, 0x21);
        var account = ApplicationCoreFixture.Bytes(32, 0x22);
        var revocations = ApplicationCoreFixture.Revocations(network, account);
        var drsReference = ApplicationCoreCodec.CreateArtifactReference((ushort)ArtifactType.Drs1,
            checked((uint)revocations.CanonicalBytes.Length), revocations.CanonicalHash.Span);
        var devices = new[]
        {
            new DeviceDirectoryEntry(ApplicationCoreFixture.Bytes(32, 0x31),
                ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpd1, 776, 0x41)),
            new DeviceDirectoryEntry(ApplicationCoreFixture.Bytes(32, 0x32),
                ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpd1, 776, 0x42)),
        };
        var record = ApplicationCoreCodec.AuthorDmd1(network, account, 1,
            ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x43), drsReference,
            1, new byte[32], devices, 100, ApplicationCoreFixture.Bytes(64, 0x44));

        Assert.Equal(496, record.CanonicalBytes.Length);
        Assert.Equal(424, record.UnsignedCanonicalBytes.Length);
        Assert.Equal(2, record.ActiveDevices.Count);
        Assert.Equal(record.CanonicalBytes.ToArray(),
            ApplicationCoreCodec.DecodeDmd1(record.CanonicalBytes.Span).CanonicalBytes.ToArray());
    }

    [Fact]
    public void Dmd1_UnsortedDevicesReject()
    {
        var network = ApplicationCoreFixture.Bytes(16, 0x21);
        var account = ApplicationCoreFixture.Bytes(32, 0x22);
        var revocations = ApplicationCoreFixture.Revocations(network, account);
        var devices = new[]
        {
            new DeviceDirectoryEntry(ApplicationCoreFixture.Bytes(32, 0x32),
                ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpd1, 776, 0x41)),
            new DeviceDirectoryEntry(ApplicationCoreFixture.Bytes(32, 0x31),
                ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpd1, 776, 0x42)),
        };

        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.AuthorDmd1(
            network, account, 1,
            ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x43),
            ApplicationCoreCodec.CreateArtifactReference((ushort)ArtifactType.Drs1,
                checked((uint)revocations.CanonicalBytes.Length), revocations.CanonicalHash.Span),
            1, new byte[32], devices, 100, ApplicationCoreFixture.Bytes(64, 0x44)));
        Assert.Equal(ApplicationCoreRejection.InvalidOrdering, exception.Rejection);
    }

    [Fact]
    public void Dao1_RoundTripsOnlyFrozenTotal()
    {
        var record = ApplicationCoreCodec.AuthorDao1(
            ApplicationCoreFixture.Bytes(16, 0x11),
            ApplicationCoreFixture.Bytes(32, 0x12),
            ApplicationCoreFixture.Bytes(32, 0x13),
            ApplicationCoreFixture.Bytes(32, 0x14),
            ApplicationCoreFixture.Bytes(24, 0x15),
            ApplicationCoreFixture.Bytes(4529, 0x16));

        Assert.Equal(4725, record.CanonicalBytes.Length);
        Assert.Equal(188, record.AeadHeader.Length);
        Assert.Equal(record.CanonicalBytes.ToArray(),
            ApplicationCoreCodec.DecodeDao1(record.CanonicalBytes.Span).CanonicalBytes.ToArray());
    }

    [Fact]
    public void Dao1_NonFrozenTotalRejectsBeforeOwnership()
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.AuthorDao1(
            ApplicationCoreFixture.Bytes(16, 0x11),
            ApplicationCoreFixture.Bytes(32, 0x12),
            ApplicationCoreFixture.Bytes(32, 0x13),
            ApplicationCoreFixture.Bytes(32, 0x14),
            ApplicationCoreFixture.Bytes(24, 0x15),
            ApplicationCoreFixture.Bytes(4528, 0x16)));
        Assert.Equal(ApplicationCoreValidationStage.ExactTotalSize, exception.Stage);

        exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.AuthorDao1(
            ApplicationCoreFixture.Bytes(16, 0x11),
            ApplicationCoreFixture.Bytes(32, 0x12),
            ApplicationCoreFixture.Bytes(32, 0x13),
            ApplicationCoreFixture.Bytes(32, 0x14),
            ApplicationCoreFixture.Bytes(24, 0x15),
            ApplicationCoreFixture.Bytes(4530, 0x16)));
        Assert.Equal(ApplicationCoreValidationStage.ExactTotalSize, exception.Stage);

        exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.AuthorDao1(
            ApplicationCoreFixture.Bytes(16, 0x11),
            ApplicationCoreFixture.Bytes(32, 0x12),
            ApplicationCoreFixture.Bytes(32, 0x13),
            ApplicationCoreFixture.Bytes(32, 0x14),
            ApplicationCoreFixture.Bytes(24, 0x15),
            ApplicationCoreFixture.Bytes(4505, 0x16)));
        Assert.Equal(ApplicationCoreValidationStage.ExactTotalSize, exception.Stage);
    }

    [Fact]
    public void IdentityRealm_IsDeterministicAndProfileSeparated()
    {
        var network = ApplicationCoreFixture.Bytes(16, 0x11);
        var first = ApplicationCoreCodec.DeriveIdentityRealmId(network, 1);
        var repeat = ApplicationCoreCodec.DeriveIdentityRealmId(network, 1);
        var second = ApplicationCoreCodec.DeriveIdentityRealmId(network, 2);

        Assert.Equal(first.ToArray(), repeat.ToArray());
        Assert.NotEqual(first.ToArray(), second.ToArray());
    }
}
