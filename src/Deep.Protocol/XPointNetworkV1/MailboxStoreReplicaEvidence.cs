using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>Bounded untrusted public records, not current or historical authority.</summary>
public sealed class MailboxStoreReplicaEvidence
{
    private readonly byte[] view, first, second;
    public MailboxStoreReplicaEvidence(ReadOnlyMemory<byte> exactXnv1,
        ReadOnlyMemory<byte> exactFirstXnd1, ReadOnlyMemory<byte> exactSecondXnd1)
    {
        foreach (var bytes in new[] { exactXnv1, exactFirstXnd1, exactSecondXnd1 })
            if (bytes.Length is < 1 or > 65_535) throw new ArgumentException("Store replica evidence exceeds canonical record bounds.");
        view = exactXnv1.ToArray(); first = exactFirstXnd1.ToArray(); second = exactSecondXnd1.ToArray();
        _ = XPointNetworkCodec.Parse<Xnv1Record>(view);
        _ = XPointNetworkCodec.Parse<Xnd1Record>(first); _ = XPointNetworkCodec.Parse<Xnd1Record>(second);
    }
    public ReadOnlyMemory<byte> ExactXnv1 => view.ToArray();
    public ReadOnlyMemory<byte> ExactFirstXnd1 => first.ToArray();
    public ReadOnlyMemory<byte> ExactSecondXnd1 => second.ToArray();
}

/// <summary>Original signed receipt-key facts only. Not a current route or grant.</summary>
public sealed class VerifiedMailboxStoreReplicaEvidence
{
    private readonly byte[] firstId, firstKey, secondId, secondKey;
    internal VerifiedMailboxStoreReplicaEvidence(Xnv1Record view, Xnd1Record first, Xnd1Record second)
    {
        firstId = first.NodeId.ToArray(); firstKey = first.IdentityPublicKey.ToArray();
        secondId = second.NodeId.ToArray(); secondKey = second.IdentityPublicKey.ToArray();
        OriginalViewNotBefore = view.NotBefore; OriginalViewExpiresAt = view.ExpiresAt;
    }
    public ReadOnlyMemory<byte> FirstNodeId => firstId.ToArray();
    public ReadOnlyMemory<byte> FirstReceiptPublicKey => firstKey.ToArray();
    public ReadOnlyMemory<byte> SecondNodeId => secondId.ToArray();
    public ReadOnlyMemory<byte> SecondReceiptPublicKey => secondKey.ToArray();
    public ulong OriginalViewNotBefore { get; }
    public ulong OriginalViewExpiresAt { get; }
}

/// <summary>DR-0106 closed original Store-key evidence; never admission or retirement permission.</summary>
public static class MailboxStoreReplicaEvidenceVerifier
{
    public static async ValueTask<MailboxStoreReplicaEvidence> CaptureAsync(
        VerifiedDeepIdV2ContactRouteClosure route, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(route);
        await route.EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
        var closure = route.Network.Closure ?? throw new CryptographicException("Store evidence requires the actual verified network closure.");
        if (!Fixed(route.Route.Projection.CanonicalBytes.Span, closure.Pmt.CanonicalBytes.Span))
            throw new CryptographicException("Original Store evidence must be captured in its current exact projection.");
        var ids = route.Route.Selection.Field(6);
        if (ids.Length != 64) throw new CryptographicException("Store evidence requires the distinct selected replica pair.");
        var first = closure.Descriptors.Single(node => Fixed(node.NodeId.Span, ids.Span[..32]));
        var second = closure.Descriptors.Single(node => Fixed(node.NodeId.Span, ids.Span[32..]));
        var result = new MailboxStoreReplicaEvidence(closure.View.CanonicalCopy(), first.CanonicalCopy(), second.CanonicalCopy());
        _ = Verify(route.Network, route.NetworkAuthority, route.Route, result);
        await route.EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    public static VerifiedMailboxStoreReplicaEvidence Verify(VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ParsedContactRouteClosure originalRoute,
        MailboxStoreReplicaEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(network); ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(originalRoute); ArgumentNullException.ThrowIfNull(evidence);
        network.EnsureCurrent();
        var closure = network.Closure ?? throw new CryptographicException("Store evidence requires the actual verified network closure.");
        if (network.ProtectedLkg is not { } lkg || !Fixed(lkg.AuthorityCoreReference.Span, authority.AuthorityCoreReference.Span) ||
            !Fixed(network.NetworkId.Span, authority.NetworkId.Span))
            throw new CryptographicException("Original Store evidence is outside the exact authority lineage.");
        var original = ContactRouteClosureCodec.Decode(originalRoute.ExactBytes.Span);
        if (!closure.RetainedPmts.Any(pmt => Fixed(pmt.CanonicalBytes.Span, original.Projection.CanonicalBytes.Span)))
            throw new CryptographicException("Original Store projection is absent from the independently verified retained lineage.");
        ContactCodec.ValidatePmsSelection(original.Selection, original.Projection);
        try { XPointOnionCapabilityProducer.VerifyContactThreshold(original.Projection, authority); }
        catch (OnionBoundaryException error) { throw new CryptographicException("Original Store projection threshold is invalid.", error); }
        DeepIdV2RouteContext.VerifyWitnesses(original.Selection, 11, authority);
        DeepIdV2RouteContext.VerifyWitnesses(original.Route, 21, authority);
        DeepIdV2RouteContext.VerifyWitnesses(original.Successor, 14, authority);
        var ids = original.Selection.Field(6);
        if (ids.Length != 64 || Fixed(ids.Span[..32], ids.Span[32..]))
            throw new CryptographicException("Original Store evidence requires two distinct selected nodes.");
        var view = XPointNetworkCodec.Parse<Xnv1Record>(evidence.ExactXnv1.Span);
        if (!Fixed(view.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNA1, view.AuthorizingXna.Hash.Span), authority.AuthorityCoreReference.Span) ||
            !Fixed(view.DirectoryWitnessPolicyHash.Span, authority.DirectoryWitnessPolicyHash.Span) ||
            !Fixed(XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, view.CoreHash.Span), original.Projection.Field(5).Span) ||
            view.NotBefore < authority.NotBefore || view.ExpiresAt > authority.ExpiresAt)
            throw new CryptographicException("Original Store view is not bound to its signed original projection/authority.");
        try
        {
            XPointOnionCapabilityProducer.VerifyThreshold(view.WitnessSignatures, authority,
                XPointNetworkCrypto.ComputeSigningInput(view), "store-view-threshold-invalid");
        }
        catch (OnionBoundaryException error) { throw new CryptographicException("Original Store view threshold is invalid.", error); }
        var first = XPointNetworkCodec.Parse<Xnd1Record>(evidence.ExactFirstXnd1.Span);
        var second = XPointNetworkCodec.Parse<Xnd1Record>(evidence.ExactSecondXnd1.Span);
        RequireDescriptor(first, ids.Span[..32]); RequireDescriptor(second, ids.Span[32..]);
        network.EnsureCurrent();
        return new(view, first, second);

        void RequireDescriptor(Xnd1Record node, ReadOnlySpan<byte> selectedId)
        {
            var refs = view.FieldSpan(12);
            var found = false;
            for (var offset = 0; offset < refs.Length; offset += 38)
            {
                var reference = XPointNetworkCodec.DecodeArtifactReference(refs.Slice(offset, 38));
                if (reference.Magic == ProtocolMagic.XND1 && Fixed(reference.Hash.Span, XPointNetworkCrypto.ComputeArtifactHash(node))) found = true;
            }
            var revoked = view.FieldSpan(14);
            for (var offset = 0; offset < revoked.Length; offset += 32)
                if (Fixed(revoked.Slice(offset, 32), node.NodeId.Span)) throw new CryptographicException("Original Store node was revoked in its signed view.");
            if (!found || !Fixed(node.NodeId.Span, selectedId) || !Fixed(node.NetworkId.Span, authority.NetworkId.Span) ||
                (node.RoleMask & (1 << 2)) == 0 || node.NotBefore > view.NotBefore || node.ExpiresAt < view.ExpiresAt ||
                !PublicKeyAuth.VerifyDetached(node.Signature.ToArray(), XPointNetworkCrypto.ComputeSigningInput(node), node.IdentityPublicKey.ToArray()))
                throw new CryptographicException("Original Store descriptor/key is absent, reordered or unauthenticated.");
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
