using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class ApplicationCoreRecordTests
{
    [Fact]
    public void Did1_RoundTripsPermanentTextAndOwnsInputs()
    {
        var key = ApplicationCoreFixture.Bytes(32, 0x11);
        var capability = ApplicationCoreFixture.Bytes(16, 0x22);
        var record = ApplicationCoreCodec.AuthorDid1(key, capability);
        var canonical = record.CanonicalBytes.ToArray();

        key[0] ^= 0xff;
        capability[0] ^= 0xff;
        canonical[0] ^= 0xff;

        Assert.Equal(76, record.CanonicalBytes.Length);
        Assert.Equal(90, record.Text.Length);
        Assert.True(record.IsPermanent);
        Assert.False(record.HasExpiry);
        Assert.Equal(record.CanonicalBytes.ToArray(), ApplicationCoreCodec.DecodeDeepIdText(record.Text).CanonicalBytes.ToArray());
        Assert.Equal("DID1", System.Text.Encoding.ASCII.GetString(record.CanonicalBytes.Span[..4]));
    }

    [Fact]
    public void Dab1_RoundTripsExactUnsignedProjection()
    {
        var record = ApplicationCoreCodec.AuthorDab1(
            ApplicationCoreFixture.Bytes(32, 0x11),
            ApplicationCoreFixture.Bytes(32, 0x12),
            0,
            new byte[32],
            ApplicationCoreFixture.Bytes(32, 0x13),
            1,
            ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x14),
            ApplicationCoreFixture.Bytes(64, 0x15),
            ApplicationCoreFixture.Bytes(64, 0x16));

        Assert.Equal(394, record.CanonicalBytes.Length);
        Assert.Equal(250, record.UnsignedCanonicalBytes.Length);
        Assert.Equal(250 + "Deep/Application/V1/address-binding/address".Length + 7,
            record.AddressSignatureInput.Length);
        Assert.Equal(record.CanonicalBytes.ToArray(),
            ApplicationCoreCodec.DecodeDab1(record.CanonicalBytes.Span).CanonicalBytes.ToArray());
    }

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
    public void Dca1_RoundTripsExactSigningProjection()
    {
        var record = ApplicationCoreCodec.AuthorDca1(
            ApplicationCoreFixture.Bytes(16, 0x11),
            ApplicationCoreFixture.Bytes(32, 0x12),
            ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x13),
            1,
            ApplicationCoreFixture.Bytes(32, 0x14),
            ApplicationCoreFixture.Bytes(32, 0x15),
            ApplicationCoreFixture.Bytes(32, 0x16),
            3,
            100,
            10,
            20,
            ApplicationCoreFixture.Bytes(64, 0x17),
            ApplicationCoreFixture.Bytes(32, 0x18),
            ApplicationCoreFixture.Reference(ApplicationCoreCodec.Dab1ArtifactTypeCode, 394, 0x19));

        Assert.Equal(473, record.CanonicalBytes.Length);
        Assert.Equal(401, record.SigningProjection.Length);
        Assert.Equal(record.CanonicalBytes.ToArray(),
            ApplicationCoreCodec.DecodeDca1(record.CanonicalBytes.Span).CanonicalBytes.ToArray());
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
