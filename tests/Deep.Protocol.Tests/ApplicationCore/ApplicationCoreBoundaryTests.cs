using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class ApplicationCoreBoundaryTests
{
    [Fact]
    public void Dmd1_DeviceCountAcceptsSixteenAndRejectsSeventeen()
    {
        var network = ApplicationCoreFixture.Bytes(16, 0x11);
        var account = ApplicationCoreFixture.Bytes(32, 0x12);
        var revocations = ApplicationCoreFixture.Revocations(network, account);
        var devices = Enumerable.Range(1, 17)
            .Select(index => new DeviceDirectoryEntry(
                OrderedId(index),
                ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpd1, 776, checked((byte)index))))
            .ToArray();

        var accepted = AuthorDirectory(network, account, revocations, devices[..16]);
        Assert.Equal(16, accepted.ActiveDevices.Count);
        Assert.Equal(1476, accepted.CanonicalBytes.Length);

        var rejected = Assert.Throws<ApplicationCoreFormatException>(() =>
            AuthorDirectory(network, account, revocations, devices));
        Assert.Equal(ApplicationCoreRejection.InvalidFieldLength, rejected.Rejection);
    }

    [Fact]
    public void TextUtf8Accepts16384AndRejects16385Bytes()
    {
        var maximum = new string('x', 16384);
        var accepted = ApplicationCoreCodec.CreateMessageCreatePayload(maximum);
        Assert.Equal(16386, accepted.CanonicalBytes.Length);
        Assert.Equal(maximum, accepted.Text);

        var rejected = Assert.Throws<ApplicationCoreFormatException>(() =>
            ApplicationCoreCodec.CreateMessageCreatePayload(maximum + "x"));
        Assert.Equal(ApplicationCoreRejection.InvalidFieldLength, rejected.Rejection);
    }

    [Fact]
    public void ReactionUtf8Accepts32AndRejects33Bytes()
    {
        var maximum = "\U0001F600" + string.Concat(Enumerable.Repeat("\u034F", 14));
        var overMaximum = "a" + string.Concat(Enumerable.Repeat("\u034F", 16));
        Assert.Equal(32, Encoding.UTF8.GetByteCount(maximum));
        Assert.Equal(33, Encoding.UTF8.GetByteCount(overMaximum));

        var accepted = ApplicationCoreCodec.CreateReactionSetPayload(
            OrderedId(1), ReactionOperation.Add, maximum);
        Assert.Equal(maximum, accepted.Reaction);
        var rejected = Assert.Throws<ApplicationCoreFormatException>(() =>
            ApplicationCoreCodec.CreateReactionSetPayload(
                OrderedId(1), ReactionOperation.Add, overMaximum));
        Assert.Equal(ApplicationCoreRejection.InvalidFieldLength, rejected.Rejection);
    }

    [Fact]
    public void ReceiptCountsAccept128AndReject129()
    {
        var read = Enumerable.Range(1, 129)
            .Select(index => new Dmc2LogicalMessageReference(OrderedId(index)))
            .ToArray();
        var delivered = Enumerable.Range(1, 129)
            .Select(index => new Dmc2DeliveryReceiptEntry(
                OrderedId(index), DeliveryReceiptStatus.Materialized))
            .ToArray();

        Assert.Equal(128, ApplicationCoreCodec.CreateReceiptReadPayload(read[..128]).Messages.Count);
        Assert.Equal(128, ApplicationCoreCodec.CreateReceiptDeliveredPayload(delivered[..128]).Entries.Count);
        Assert.Equal(ApplicationCoreRejection.InvalidFieldLength,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                ApplicationCoreCodec.CreateReceiptReadPayload(read)).Rejection);
        Assert.Equal(ApplicationCoreRejection.InvalidFieldLength,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                ApplicationCoreCodec.CreateReceiptDeliveredPayload(delivered)).Rejection);
    }

    [Fact]
    public void Dmc2OuterPayloadAccepts32768ForTypedInspectionAndRejects32769AtBound()
    {
        var canonical = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateMessageCreatePayload("x")).CanonicalBytes.ToArray();
        var atMaximum = ReplaceLastField(canonical, new byte[32768]);
        var overMaximum = ReplaceLastField(canonical, new byte[32769]);

        var typed = Assert.Throws<ApplicationCoreFormatException>(() =>
            ApplicationCoreCodec.DecodeDmc2(atMaximum));
        Assert.Equal(ApplicationCoreValidationStage.TypedPayload, typed.Stage);
        Assert.Equal(ApplicationCoreRejection.InvalidFieldLength, typed.Rejection);

        var outer = Assert.Throws<ApplicationCoreFormatException>(() =>
            ApplicationCoreCodec.DecodeDmc2(overMaximum));
        Assert.Equal(ApplicationCoreValidationStage.TypedPayload, outer.Stage);
        Assert.Equal(ApplicationCoreRejection.InvalidFieldLength, outer.Rejection);
    }

    [Fact]
    public void AllApplicationNetworkIdsRejectZero16()
    {
        var zero = new byte[16];
        var account = ApplicationCoreFixture.Bytes(32, 0x12);
        var payload = ApplicationCoreCodec.CreateMessageCreatePayload("x");

        AssertZero(() => ApplicationCoreCodec.DeriveIdentityRealmId(zero, 1));
        AssertZero(() => ApplicationCoreFixture.Directory(zero, account, OrderedId(1)));
        AssertZero(() => ApplicationCoreCodec.AuthorDca1(
            zero, account,
            ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x13),
            1, OrderedId(2), OrderedId(3), OrderedId(4), 1, 1, 10, 20,
            ApplicationCoreFixture.Bytes(64, 0x15), OrderedId(5),
            ApplicationCoreFixture.Reference(ApplicationCoreCodec.Dab1ArtifactTypeCode, 394, 0x16)));
        AssertZero(() => ApplicationCoreCodec.AuthorDao1(
            zero, OrderedId(1), OrderedId(2), OrderedId(3),
            ApplicationCoreFixture.Bytes(24, 0x17), ApplicationCoreFixture.Bytes(4529, 0x18)));
        AssertZero(() => ApplicationCoreCodec.AuthorDmc2(
            zero, OrderedId(1), OrderedId(2), OrderedId(3), OrderedId(4),
            1, 1, 0, Dmc2Flags.None, [], payload));
    }

    [Fact]
    public void Dca1RejectsUnallocatedDab1ArtifactTypeBeforeVerification()
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(() =>
            ApplicationCoreCodec.AuthorDca1(
                ApplicationCoreFixture.Bytes(16, 0x11),
                ApplicationCoreFixture.Bytes(32, 0x12),
                ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x13),
                1,
                OrderedId(2),
                OrderedId(3),
                OrderedId(4),
                1,
                1,
                10,
                20,
                ApplicationCoreFixture.Bytes(64, 0x15),
                OrderedId(5),
                ApplicationCoreFixture.Reference(0x1002, 394, 0x16)));

        Assert.Equal(ApplicationCoreRejection.InvalidReference, exception.Rejection);
    }

    private static ParsedDmd1 AuthorDirectory(
        byte[] network,
        byte[] account,
        RevocationSnapshot revocations,
        IReadOnlyList<DeviceDirectoryEntry> devices) => ApplicationCoreCodec.AuthorDmd1(
            network,
            account,
            1,
            ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x21),
            ApplicationCoreCodec.CreateArtifactReference(
                (ushort)ArtifactType.Drs1,
                checked((uint)revocations.CanonicalBytes.Length),
                revocations.CanonicalHash.Span),
            1,
            new byte[32],
            devices,
            100,
            ApplicationCoreFixture.Bytes(64, 0x22));

    private static byte[] OrderedId(int value)
    {
        var id = new byte[32];
        BinaryPrimitives.WriteInt32BigEndian(id.AsSpan(28), value);
        return id;
    }

    private static byte[] ReplaceLastField(byte[] canonical, byte[] replacement)
    {
        var valueOffset = ApplicationCoreFixture.FieldOffset(canonical, 12);
        var fieldHeaderOffset = valueOffset - 8;
        var output = new byte[fieldHeaderOffset + 8 + replacement.Length];
        canonical.AsSpan(0, fieldHeaderOffset + 8).CopyTo(output);
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(fieldHeaderOffset + 4, 4), checked((uint)replacement.Length));
        replacement.CopyTo(output, valueOffset);
        return output;
    }

    private static void AssertZero(Action action)
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(action);
        Assert.Equal(ApplicationCoreRejection.ZeroForbidden, exception.Rejection);
    }
}
