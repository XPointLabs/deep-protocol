using Deep.Protocol.XPointNetworkV1;
using Xunit;

namespace Deep.Protocol.Tests;

public sealed class MailboxStoreReplicaEvidenceTests
{
    [Theory]
    [InlineData(0, 0)] [InlineData(1, 0)] [InlineData(2, 0)]
    [InlineData(0, 65_536)] [InlineData(1, 65_536)] [InlineData(2, 65_536)]
    public void AllRecordSizesAreCheckedBeforeParsingOrOwnedCopies(int index, int length)
    {
        ReadOnlyMemory<byte>[] records = [new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }];
        records[index] = new byte[length];
        Assert.Throws<ArgumentException>(() => new MailboxStoreReplicaEvidence(records[0], records[1], records[2]));
    }
}
