using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>
/// Authenticates a complete retained signed closure at its original artifact
/// intervals. This returns no current network, time, issuer or operation authority.
/// </summary>
public static class XPointNetworkHistoricalClosureVerifier
{
    /// <summary>
    /// Verifies retained signatures, exact predecessor chains and original
    /// interval bindings without establishing currentness or returning authority.
    /// </summary>
    /// <param name="genesisPin">The independently retained network and generation-zero authority pin.</param>
    /// <param name="closure">The complete canonical signed distribution history to authenticate.</param>
    public static void Verify(XPointNetworkGenesisPin genesisPin, XPointNetworkClosureWireArtifacts closure)
    {
        ArgumentNullException.ThrowIfNull(genesisPin);
        ArgumentNullException.ThrowIfNull(closure);
        if (!closure.NetworkId.Span.SequenceEqual(genesisPin.NetworkId.Span))
            throw new CryptographicException("Historical closure network differs from the pinned genesis.");
        var authority = XPointNetworkAuthorityVerifier.Verify(genesisPin,
            closure.ExactAuthorityChain, closure.ExactTimePolicyChain);
        XPointOnionCapabilityProducer.VerifyHistoricalClosure(authority, closure);
    }
}

internal static partial class XPointOnionCapabilityProducer
{
    // Reuses the exact signed-history, descriptor and projection checks from
    // current admission. No freshness object, clock or capability is constructed.
    internal static void VerifyHistoricalClosure(VerifiedXPointNetworkAuthority authority,
        XPointNetworkClosureWireArtifacts closure)
    {
        var policyBytes = OwnChain(closure.ExactNetworkPolicyChain, ProtocolMagic.XVP1);
        var viewBytes = OwnChain(closure.ExactViewChain, ProtocolMagic.XNV1);
        var headBytes = OwnChain(closure.ExactHeadChain, ProtocolMagic.XNH1);
        var pmtBytes = OwnChain(closure.ExactPlacementTopologyChain, ProtocolMagic.PMT2);
        var nodeBytes = closure.ExactActiveNodeDescriptors.Select(value => Own(value, ProtocolMagic.XND1)).ToArray();
        var pmaBytes = closure.ExactMailboxAuthorityChain;
        if (viewBytes.Length != headBytes.Length ||
            policyBytes.Sum(static value => (long)value.Length) + viewBytes.Sum(static value => (long)value.Length) +
            headBytes.Sum(static value => (long)value.Length) + pmtBytes.Sum(static value => (long)value.Length) +
            nodeBytes.Sum(static value => (long)value.Length) > MaximumSuccessorChainBytes)
            throw new CryptographicException("Historical signed closure exceeds its complete paired-chain bound.");
        var policies = policyBytes.Select(static value => XPointNetworkCodec.Parse<Xvp1Record>(value)).ToArray();
        var views = viewBytes.Select(static value => XPointNetworkCodec.Parse<Xnv1Record>(value)).ToArray();
        var heads = headBytes.Select(static value => XPointNetworkCodec.Parse<Xnh1Record>(value)).ToArray();
        var pmts = pmtBytes.Select(static value => ContactCodec.Decode(ProtocolMagic.PMT2, value)).ToArray();
        var nodes = nodeBytes.Select(static value => XPointNetworkCodec.Parse<Xnd1Record>(value)).ToArray();
        _ = VerifySignedHistory(authority, policies, views, heads, pmts, null, false);

        var pmas = new ContactRecord[pmaBytes.Count];
        for (var i = 0; i < pmas.Length; i++)
        {
            var pma = ContactCodec.Decode(ProtocolMagic.PMA2, pmaBytes[i].Span);
            var issue = BinaryPrimitives.ReadUInt64BigEndian(pma.FieldSpan(11));
            MailboxAuthorityV2Verifier.VerifyHistoricalLineage(authority, pma.CanonicalBytes.Span, issue, issue);
            var generation = BinaryPrimitives.ReadUInt64BigEndian(pma.FieldSpan(2));
            if (BinaryPrimitives.ReadUInt16BigEndian(pma.FieldSpan(9)) != 2 ||
                (i == 0 ? generation != 0 || pma.FieldSpan(3).IndexOfAnyExcept((byte)0) >= 0 :
                    generation != checked(BinaryPrimitives.ReadUInt64BigEndian(pmas[i - 1].FieldSpan(2)) + 1) ||
                    !Fixed(pma.FieldSpan(3), pmas[i - 1].CoreHash.Span)))
                throw new CryptographicException("Historical mailbox policy lineage is incomplete or changes its algorithm.");
            pmas[i] = pma;
        }
        var byReference = pmas.ToDictionary(static value =>
            Convert.ToHexString(XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.PMA2, value.CoreHash.Span)), StringComparer.Ordinal);
        var viewsByReference = views.ToDictionary(static value => Convert.ToHexString(value.CoreReferenceValue.Encode()), StringComparer.Ordinal);
        foreach (var pmt in pmts)
        {
            if (!byReference.TryGetValue(Convert.ToHexString(pmt.FieldSpan(4)), out var pma))
                throw new CryptographicException("Historical projection omits its exact signed mailbox policy.");
            var view = viewsByReference[Convert.ToHexString(pmt.FieldSpan(5))];
            var original = RequireHistoricalAuthority(authority, view.FieldSpan(7));
            var issue = BinaryPrimitives.ReadUInt64BigEndian(pmt.FieldSpan(10));
            var notBefore = BinaryPrimitives.ReadUInt64BigEndian(pmt.FieldSpan(11));
            var expires = BinaryPrimitives.ReadUInt64BigEndian(pmt.FieldSpan(12));
            if (!Fixed(pma.FieldSpan(13), view.FieldSpan(7)) || original.NotBefore > issue ||
                original.NotBefore > notBefore || expires > original.ExpiresAt ||
                BinaryPrimitives.ReadUInt64BigEndian(pma.FieldSpan(11)) > notBefore ||
                expires > BinaryPrimitives.ReadUInt64BigEndian(pma.FieldSpan(12)))
                throw new CryptographicException("Historical projection is outside its original signed authority and mailbox policy.");
        }
        var policy = policies[^1]; var terminalView = views[^1]; var head = heads[^1]; var terminalPmt = pmts[^1];
        if (!Fixed(policy.FieldSpan(18), authority.AuthorityCoreReference.Span) ||
            !Fixed(terminalView.FieldSpan(7), authority.AuthorityCoreReference.Span) ||
            !Fixed(head.FieldSpan(8), authority.AuthorityCoreReference.Span) ||
            !Fixed(terminalView.ActivePolicy.Hash.Span, policy.CoreHash.Span) ||
            !Fixed(terminalPmt.FieldSpan(5), terminalView.CoreReferenceValue.Encode()) ||
            !Fixed(terminalPmt.FieldSpan(4), XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.PMA2, pmas[^1].CoreHash.Span)))
            throw new CryptographicException("Historical terminal records do not form one exact signed closure.");
        VerifyNodeHistory(authority, policy, terminalView, nodes);
        VerifyPmtNodeProjection(terminalPmt, nodes);
    }
}
