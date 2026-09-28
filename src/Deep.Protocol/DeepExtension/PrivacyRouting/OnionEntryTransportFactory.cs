using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.PrivacyRouting;

/// <summary>Selected-entry TLS facts from one exact live path, never a caller
/// URL or a permission to change the path. No receive private key is released.</summary>
public sealed class VerifiedOnionEntryTransport
{
    private readonly VerifiedOnionPathContext path;
    internal VerifiedOnionEntryTransport(VerifiedOnionPathContext path,
        VerifiedOnionNextHopTransport peer)
    {
        this.path = path;
        Peer = peer;
    }

    public VerifiedOnionNextHopTransport Peer { get; }

    public void EnsureCurrent()
    {
        path.Network.EnsureCurrent();
        path.TrustedTime.EnsureLive();
    }
}

public static class OnionEntryTransportFactory
{
    public static VerifiedOnionEntryTransport Create(VerifiedOnionPathContext path)
    {
        ArgumentNullException.ThrowIfNull(path);
        path.Network.EnsureCurrent();
        path.TrustedTime.EnsureLive();
        var hop = path.Route[0];
        var node = path.Network.CandidateNodes.SingleOrDefault(candidate =>
            CryptographicOperations.FixedTimeEquals(candidate.RouterOwnerId,
                path.EntryRouterId.Span)) ?? throw new OnionBoundaryException(
                    "entry-not-in-view", "The selected entry is absent from this exact network closure.");
        if (hop.Epoch != node.KeyEpoch ||
            !CryptographicOperations.FixedTimeEquals(hop.KeyIdSpan, node.KeyId) ||
            !CryptographicOperations.FixedTimeEquals(hop.X25519PublicKeySpan, node.OnionPublicKey))
            throw new OnionBoundaryException("entry-path-mismatch",
                "The selected entry differs from its verified traffic-key binding.");
        return new(path, new VerifiedOnionNextHopTransport(path.Network, node));
    }
}
