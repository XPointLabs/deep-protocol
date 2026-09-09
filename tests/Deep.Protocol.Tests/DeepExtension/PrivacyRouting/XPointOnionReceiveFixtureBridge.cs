using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.Tests.XPointNetworkV1;

// The XPoint fixture is owned by a concurrent package. Keep its pre-clean-break helper out of
// the production assembly while allowing the repository test project to compile during repin.
internal static class OnionReceiveContextFactory
{
    internal static VerifiedOnionReceiveContext Create(
        VerifiedOnionNetworkContext network,
        OnionOperation operation,
        OnionReceivePosition position,
        ReadOnlyMemory<byte> localNodeId,
        OnionKeyHandle keyHandle,
        ReadOnlyMemory<byte> nextNodeId)
    {
        if (operation is < OnionOperation.Store or > OnionOperation.ContactResolve ||
            (position == OnionReceivePosition.Exit ? !nextNodeId.IsEmpty : nextNodeId.IsEmpty))
            throw new ArgumentException("The transitional test fixture arguments are invalid.");
        return new VerifiedOnionReceiveContext(
            OnionLocalNodeKeyFactory.Bind(network, position, localNodeId, keyHandle));
    }
}
