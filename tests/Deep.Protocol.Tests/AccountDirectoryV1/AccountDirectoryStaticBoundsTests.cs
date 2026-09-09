using System.Buffers.Binary;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryStaticBoundsTests
{
    [Fact]
    public void ReceiptCounts_CannotExceedFrozenXnaKeySetBounds()
    {
        var witnesses = Enumerable.Range(1, 33)
            .Select(index => new AccountDirectoryAdh1WitnessEntry(Id(index), Fill(64, 1)))
            .ToArray();
        Assert.Throws<ArgumentException>(() => new AccountDirectoryAdh1(
            Fill(16, 1), 1, Fill(32, 2), 1, Fill(32, 3), Fill(32, 4), Ref("XNA1", 5),
            Fill(32, 6), 10, 20, 1, witnesses));

        var timeWitnesses = Enumerable.Range(1, 33)
            .Select(index => new AccountDirectoryDtt1WitnessReceipt(Id(index), Fill(64, 1)))
            .ToArray();
        Assert.Throws<ArgumentException>(() => new AccountDirectoryDtt1(
            Fill(16, 1), Fill(32, 2), 100, 1, Fill(32, 3), 1, Fill(32, 4), 1,
            Ref("XNA1", 5), Fill(32, 6), 100, 101, Fill(32, 7), timeWitnesses));

        var roots = Enumerable.Range(1, 9)
            .Select(index => new AccountDirectoryAdf1RootReceipt(Id(index), Fill(64, 1)))
            .ToArray();
        Assert.Throws<ArgumentException>(() => new AccountDirectoryAdf1(
            Fill(16, 1), 1, Fill(32, 2), 1, 2, 1, Fill(32, 3), Ref("ADH1", 4), 1,
            Fill(32, 5), Fill(32, 6), Ref("XNA1", 7), 100, 1, roots));

        var dtsRoots = Enumerable.Range(1, 9)
            .Select(index => new AccountDirectoryDts1RootReceipt(Id(index), Fill(64, 1)))
            .ToArray();
        var sources = new[]
        {
            new AccountDirectoryDts1Source(Id(1), Id(11), 1, "time-a.example", 123, Fill(32, 7), 5),
            new AccountDirectoryDts1Source(Id(2), Id(12), 1, "time-b.example", 123, Fill(32, 8), 5)
        };
        Assert.Throws<ArgumentException>(() => new AccountDirectoryDts1(
            Fill(16, 1), 1, Fill(32, 2), sources, 2, 2, 30, 15, 100, 200, 1, 1, dtsRoots));
    }

    private static byte[] Id(int value)
    {
        var result = new byte[32];
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(28), value);
        return result;
    }

    private static byte[] Ref(string magic, byte seed)
    {
        var result = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        Fill(32, seed).CopyTo(result, 6);
        return result;
    }

    private static byte[] Fill(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
}
