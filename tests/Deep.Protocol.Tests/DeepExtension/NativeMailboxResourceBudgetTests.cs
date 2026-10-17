using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class NativeMailboxResourceBudgetTests
{
    [Fact]
    public void CompositeMutationBudgetsContainLeafWorkAndStayBelowPublicOnion()
    {
        Assert.Equal(25, MailboxWireHttpContract.Store.RequestTimeoutSeconds);
        Assert.Equal(25, MailboxWireHttpContract.Acknowledge.RequestTimeoutSeconds);
        Assert.Equal(15, MailboxWireHttpContract.PeerStore.RequestTimeoutSeconds);
        Assert.Equal(15, MailboxWireHttpContract.PeerTombstone.RequestTimeoutSeconds);
        Assert.Equal(10, MailboxWireHttpContract.Retrieve.RequestTimeoutSeconds);
        Assert.True(MailboxWireHttpContract.PeerStore.RequestTimeoutSeconds < MailboxWireHttpContract.Store.RequestTimeoutSeconds);
        Assert.True(MailboxWireHttpContract.PeerTombstone.RequestTimeoutSeconds < MailboxWireHttpContract.Acknowledge.RequestTimeoutSeconds);
        Assert.True(MailboxWireHttpContract.Store.RequestTimeoutSeconds < 30);
        Assert.True(MailboxWireHttpContract.Acknowledge.RequestTimeoutSeconds < 30);
        Assert.Equal(16, MailboxWireHttpContract.Store.MaximumConcurrentRequests);
        Assert.Equal(32, MailboxWireHttpContract.PeerStore.MaximumConcurrentRequests);
    }
}
