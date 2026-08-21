using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepNative;

/// <summary>High-level verifier for the exact mailbox MIP1/RIP2/MRL2 proof path.</summary>
public static class NativeMembershipVerifier
{
    public static VerifiedMrl2Membership VerifyMailboxMembership(
        ReadOnlySpan<byte> canonicalMailboxMip1,
        VerifiedMembershipRoutingLkg lastKnownGood)
    {
        ArgumentNullException.ThrowIfNull(lastKnownGood);

        // This walk is allocation-free and includes the complete RIP2 nested framing.
        MailboxMembershipCarrier.Preflight(canonicalMailboxMip1);
        var owned = canonicalMailboxMip1.ToArray();
        MailboxMembershipCarrier.Preflight(owned);

        var replicaId = owned.AsSpan(8, 32);
        var signingKey = owned.AsSpan(40, 32);
        var outerEpoch = BinaryPrimitives.ReadUInt64BigEndian(owned.AsSpan(72, 8));
        var outerRoot = owned.AsSpan(80, 32);
        var inner = owned.AsSpan(MailboxMembershipCarrier.FixedOuterLength);
        var rip = CanonicalGrammar.DecodeOwned(inner, RecordDefinitions.Rip2);
        var mrlBytes = rip.FieldSpan(12);
        var mrl = CanonicalGrammar.DecodeOwned(mrlBytes, RecordDefinitions.Mrl2);

        var members = BinaryPrimitives.ReadUInt32BigEndian(rip.FieldSpan(7));
        var padded = BinaryPrimitives.ReadUInt32BigEndian(rip.FieldSpan(8));
        var leafIndex = BinaryPrimitives.ReadUInt32BigEndian(rip.FieldSpan(9));
        var siblingCount = rip.FieldSpan(13)[0];
        if (!Fixed(rip.FieldSpan(1), lastKnownGood.TrustedNetworkId) ||
            !Fixed(rip.FieldSpan(2), lastKnownGood.TrustedResetId) ||
            BinaryPrimitives.ReadUInt64BigEndian(rip.FieldSpan(3)) != lastKnownGood.MembershipSequence ||
            BinaryPrimitives.ReadUInt64BigEndian(rip.FieldSpan(4)) != lastKnownGood.Epoch ||
            members != lastKnownGood.MemberCount ||
            !Fixed(rip.FieldSpan(10), lastKnownGood.TrustedMembershipRoot) ||
            outerEpoch != lastKnownGood.Epoch ||
            !Fixed(outerRoot, lastKnownGood.TrustedMembershipRoot))
            Invalid("The RIP2 proof is for another sealed membership closure.");

        if (leafIndex >= lastKnownGood.TrustedRouters.Count)
            Invalid("The RIP2 leaf index is outside the sealed router table.");
        var router = lastKnownGood.TrustedRouters[checked((int)leafIndex)];
        var descriptorGeneration = BinaryPrimitives.ReadUInt64BigEndian(mrl.FieldSpan(3));
        var proofDescriptorGeneration = BinaryPrimitives.ReadUInt64BigEndian(rip.FieldSpan(6));
        var roles = (RouterRoles)BinaryPrimitives.ReadUInt64BigEndian(mrl.FieldSpan(6));
        var capabilities = (RouterCapabilities)BinaryPrimitives.ReadUInt64BigEndian(mrl.FieldSpan(7));
        var fullMrlReference = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Mrl2, mrlBytes));
        if (!Fixed(replicaId, router.RouterId) ||
            !Fixed(signingKey, router.RouterEd25519PublicKey) ||
            !Fixed(mrl.FieldSpan(1), lastKnownGood.TrustedNetworkId) ||
            BinaryPrimitives.ReadUInt64BigEndian(mrl.FieldSpan(2)) != lastKnownGood.Epoch ||
            proofDescriptorGeneration != descriptorGeneration ||
            descriptorGeneration != router.DescriptorGeneration ||
            !Fixed(mrl.FieldSpan(4), router.RouterId) ||
            !Fixed(mrl.FieldSpan(5), router.DnrReference) ||
            !Fixed(fullMrlReference, router.FullMrlReference) ||
            !Fixed(mrl.FieldSpan(9), router.AnchorDpcReference) ||
            roles != router.Roles || capabilities != router.Capabilities ||
            !Fixed(mrlBytes, router.Mrl2))
            Invalid("The embedded MRL2 row does not match the sealed router tuple.");

        var running = RealLeaf(
            lastKnownGood.TrustedResetId,
            lastKnownGood.Epoch,
            descriptorGeneration,
            leafIndex,
            mrlBytes);
        var siblings = rip.FieldSpan(14);
        for (var level = 0; level < siblingCount; level++)
        {
            var sibling = siblings.Slice(level * 32, 32);
            var nodeIndex = leafIndex >> (level + 1);
            running = (leafIndex & (1u << level)) == 0
                ? Node(checked((ushort)level), nodeIndex, running, sibling)
                : Node(checked((ushort)level), nodeIndex, sibling, running);
        }
        var root = Root(lastKnownGood.TrustedResetId, lastKnownGood.Epoch, members, padded, running);
        if (!Fixed(root, lastKnownGood.TrustedMembershipRoot))
            Invalid("The RIP2 Merkle root is invalid.");

        return new VerifiedMrl2Membership(
            owned, mrlBytes, router.RouterId, router.RouterEd25519PublicKey,
            RealLeaf(lastKnownGood.TrustedResetId, lastKnownGood.Epoch,
                descriptorGeneration, leafIndex, mrlBytes),
            router.FullMrlReference,
            lastKnownGood.Epoch, descriptorGeneration, roles, capabilities);
    }

    internal static byte[] RealLeaf(
        ReadOnlySpan<byte> resetId,
        ulong epoch,
        ulong descriptorGeneration,
        uint index,
        ReadOnlySpan<byte> canonicalMrl2)
    {
        if (resetId.Length != 32 || canonicalMrl2.Length != Mrl2Projection.Length)
            Invalid("The MRL2 leaf input is malformed.");
        Span<byte> projection = stackalloc byte[Mrl2Projection.Length];
        Mrl2Projection.WriteFromFull(canonicalMrl2, projection);
        Span<byte> prefix = stackalloc byte[1 + 32 + 8 + 8 + 4 + 4];
        prefix[0] = 0;
        resetId.CopyTo(prefix[1..33]);
        BinaryPrimitives.WriteUInt64BigEndian(prefix[33..41], epoch);
        BinaryPrimitives.WriteUInt64BigEndian(prefix[41..49], descriptorGeneration);
        BinaryPrimitives.WriteUInt32BigEndian(prefix[49..53], index);
        BinaryPrimitives.WriteUInt32BigEndian(prefix[53..57], Mrl2Projection.Length);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendDomain(hash, "Deep/NativeRouting/V2/mrl-leaf", checked((uint)(prefix.Length + canonicalMrl2.Length)));
        hash.AppendData(prefix);
        hash.AppendData(projection);
        return hash.GetHashAndReset();
    }

    internal static byte[] EmptyLeaf(ReadOnlySpan<byte> resetId, ulong epoch, uint index)
    {
        if (resetId.Length != 32) Invalid("The MRL2 empty leaf input is malformed.");
        Span<byte> payload = stackalloc byte[1 + 32 + 8 + 4];
        payload[0] = 1;
        resetId.CopyTo(payload[1..33]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[33..41], epoch);
        BinaryPrimitives.WriteUInt32BigEndian(payload[41..45], index);
        return CanonicalGrammar.Sha256Domain("Deep/NativeRouting/V2/mrl-leaf", payload);
    }

    internal static byte[] Node(
        ushort level,
        uint nodeIndex,
        ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right)
    {
        if (left.Length != 32 || right.Length != 32) Invalid("The MRL2 node input is malformed.");
        Span<byte> payload = stackalloc byte[70];
        BinaryPrimitives.WriteUInt16BigEndian(payload[..2], level);
        BinaryPrimitives.WriteUInt32BigEndian(payload[2..6], nodeIndex);
        left.CopyTo(payload[6..38]);
        right.CopyTo(payload[38..70]);
        return CanonicalGrammar.Sha256Domain("Deep/NativeRouting/V2/mrl-node", payload);
    }

    internal static byte[] Root(
        ReadOnlySpan<byte> resetId,
        ulong epoch,
        uint memberCount,
        uint paddedLeafCount,
        ReadOnlySpan<byte> nodeRoot)
    {
        if (resetId.Length != 32 || nodeRoot.Length != 32)
            Invalid("The MRL2 root input is malformed.");
        Span<byte> payload = stackalloc byte[82];
        resetId.CopyTo(payload[..32]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[32..40], epoch);
        BinaryPrimitives.WriteUInt16BigEndian(payload[40..42], 2);
        BinaryPrimitives.WriteUInt32BigEndian(payload[42..46], memberCount);
        BinaryPrimitives.WriteUInt32BigEndian(payload[46..50], paddedLeafCount);
        nodeRoot.CopyTo(payload[50..82]);
        return CanonicalGrammar.Sha256Domain("Deep/NativeRouting/V2/mrl-root", payload);
    }

    private static void AppendDomain(IncrementalHash hash, string domain, uint payloadLength)
    {
        var domainBytes = System.Text.Encoding.ASCII.GetBytes(domain);
        Span<byte> scalar = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(scalar[..2], checked((ushort)domainBytes.Length));
        hash.AppendData(scalar[..2]);
        hash.AppendData(domainBytes);
        BinaryPrimitives.WriteUInt32BigEndian(scalar, payloadLength);
        hash.AppendData(scalar);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
