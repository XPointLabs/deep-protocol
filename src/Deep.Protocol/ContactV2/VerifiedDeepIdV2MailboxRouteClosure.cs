using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Closed independently current mailbox-delivery route. Not event
/// authentication, consent, publication, a holder/grant or dispatch authority.
/// Only Protocol can construct or implement this boundary.</summary>
public abstract class VerifiedDeepIdV2MailboxRouteClosure
{
    internal VerifiedDeepIdV2MailboxRouteClosure() { }
    public abstract ParsedContactRouteClosure Route { get; }
    public abstract DeepIdV2CurrentContactAuthorization Recipient { get; }
    public abstract VerifiedOnionNetworkContext Network { get; }
    public abstract VerifiedXPointNetworkAuthority NetworkAuthority { get; }
    public ReadOnlyMemory<byte> ExactRouteClosure => Route.ExactBytes;
    /// <summary>Public routing selector derived from the independently verified
    /// DID2 and network; never the private resolver capability or read key.</summary>
    public ReadOnlyMemory<byte> LocatorHash => DeepIdV2PermanentContactResolutionDerivation.ComputeLocator(
        Network.NetworkId.Span, Recipient.Authorization.Binding.DeepId.RecordHash.Span);
    public abstract ValueTask<DeepIdV2ContactRouteTimeWindow> ReadCurrentTimeAsync(
        CancellationToken cancellationToken = default);
    public async ValueTask EnsureCurrentAsync(CancellationToken cancellationToken = default)
    { _ = await ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false); }
}
