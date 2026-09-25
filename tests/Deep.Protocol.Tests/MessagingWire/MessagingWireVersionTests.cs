using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.MessagingWire;

public sealed class MessagingWireVersionTests
{
    [Fact]
    public void VersionIsSelectedPerCodecAndOldDefaultDoesNotReadVersionTwo()
    {
        var versionTwo = new byte[21];
        var writer = new MessagingWireWriter(versionTwo, "DPH2"u8, 1,
            version: 2);
        writer.Write(1, [0x41]);
        writer.Complete();

        Assert.Equal((byte)2, versionTwo[5]);
        var oldReader = Assert.Throws<MessagingWireFormatException>(() =>
            Read(versionTwo, expectedVersion: 1));
        Assert.Equal(MessagingWirePrevalidationStage.FixedHeader,
            oldReader.Stage);
        Assert.Equal(MessagingWireRejection.WrongVersion,
            oldReader.Rejection);
        Read(versionTwo, expectedVersion: 2);

        var versionOne = new byte[21];
        var oldWriter = new MessagingWireWriter(versionOne, "DPH2"u8, 1);
        oldWriter.Write(1, [0x41]);
        oldWriter.Complete();
        var newReader = Assert.Throws<MessagingWireFormatException>(() =>
            Read(versionOne, expectedVersion: 2));
        Assert.Equal(MessagingWireRejection.WrongVersion,
            newReader.Rejection);
        Read(versionOne, expectedVersion: 1);
    }

    private static void Read(byte[] record, ushort expectedVersion)
    {
        Span<MessagingWireFieldSlice> fields =
            stackalloc MessagingWireFieldSlice[1];
        MessagingWireFraming.Preflight(record, "DPH2"u8, 1, [21], fields,
            expectedVersion);
        Assert.Equal(1, fields[0].Length);
    }
}
