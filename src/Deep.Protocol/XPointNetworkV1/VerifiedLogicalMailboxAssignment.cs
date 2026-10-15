using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.XPointNetworkV1;

// DR-0122: a closed current-eligibility fact for exact assignment metadata.
// It is not a grant, a live route, a transport origin or expired-route permission.
// No public constructor, caller clock, historical-currentness switch or key input.
internal sealed class VerifiedLogicalMailboxAssignment
{
    private readonly VerifiedOnionNetworkContext network;
    private readonly VerifiedXPointNetworkAuthority authority;

    private VerifiedLogicalMailboxAssignment(VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ContactRecord projection)
    { this.network = network; this.authority = authority; Projection = projection; }

    internal ContactRecord Projection { get; }

    internal static VerifiedLogicalMailboxAssignment FromReference(VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ReadOnlyMemory<byte> exactReference)
    {
        if (exactReference.Length != 38)
            throw new CryptographicException("Logical assignment reference has a noncanonical size.");
        network.EnsureCurrent();
        var projection = network.Closure!.RetainedPmts.SingleOrDefault(candidate => Fixed(
            ContactCodec.ArtifactReference(ProtocolMagic.PMT2, candidate).CanonicalBytes.Span,
            exactReference.Span));
        if (projection is null)
        {
            var error = new CryptographicException("Logical assignment is absent from verified retained history.");
            error.Data["Deep.ContactRoute.Scope"] = "pmt-reference";
            throw error;
        }
        return Verify(network, authority, projection);
    }

    internal static VerifiedLogicalMailboxAssignment FromMembership(VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ReadOnlyMemory<byte> exactCommitment)
    {
        if (exactCommitment.Length != 32)
            throw new CryptographicException("Logical assignment commitment has a noncanonical size.");
        network.EnsureCurrent();
        var projection = network.Closure!.RetainedPmts.SingleOrDefault(candidate =>
            Fixed(candidate.ArtifactHash.Span, exactCommitment.Span)) ??
            throw new CryptographicException("Logical assignment commitment is absent from verified retained history.");
        return Verify(network, authority, projection);
    }

    internal static VerifiedLogicalMailboxAssignment Verify(VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ContactRecord exactProjection)
    {
        ArgumentNullException.ThrowIfNull(network); ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(exactProjection);
        if (exactProjection.Magic != ProtocolMagic.PMT2)
            throw new CryptographicException("Logical assignment requires an exact PMT2 snapshot.");
        var owned = ContactCodec.Decode(ProtocolMagic.PMT2, exactProjection.CanonicalBytes.Span);
        var result = new VerifiedLogicalMailboxAssignment(network, authority, owned);
        result.VerifyScope();
        result.EnsureCurrent();
        return result;
    }

    // Eligibility was verified against this exact immutable network capability.
    // Rechecks enforce its live lease, not repeated history walks/signatures.
    internal void EnsureCurrent() => network.EnsureCurrent();

    // Authenticated original Store-time cohort only; no current assignment fact
    // is released. Later epoch/cohort transitions do not rewrite past receipts.
    internal static void RequireHistoricalCohort(VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ContactRecord original, ContactRecord atStore)
    {
        network.EnsureCurrent();
        foreach (var projection in new[] { original, atStore })
        {
            var issuer = XPointOnionCapabilityProducer.RequireRetainedProjectionAuthority(network, authority, projection);
            XPointOnionCapabilityProducer.VerifyContactThreshold(projection, issuer);
        }
        new VerifiedLogicalMailboxAssignment(network, authority, original).RequireContinuousCohort(atStore);
        network.EnsureCurrent();
    }

    private void VerifyScope()
    {
        network.EnsureCurrent();
        var closure = network.Closure!;
        if (!Fixed(network.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(Projection.Field(1).Span, network.NetworkId.Span) ||
            network.ProtectedLkg is not { } floor ||
            !Fixed(floor.AuthorityCoreReference.Span, authority.AuthorityCoreReference.Span))
            throw new CryptographicException("Logical assignment differs from current protected network authority.");

        // Exact membership in independently verified history is mandatory.
        // A terminal-only forward checkpoint cannot resurrect an omitted snapshot.
        var originalAuthority = XPointOnionCapabilityProducer.RequireRetainedProjectionAuthority(
            network, authority, Projection);
        try { XPointOnionCapabilityProducer.VerifyContactThreshold(Projection, originalAuthority); }
        catch (OnionBoundaryException error)
        { throw new CryptographicException("Logical assignment snapshot threshold is invalid.", error); }

        RequireContinuousCohort(closure.Pmt);
        // Snapshot origin/SPKI/capacity fields are not transport or current-role
        // authority. Resolve every member through today's admitted descriptor.
        var expectedIds = NodeIds(Projection);
        for (var offset = 0; offset < expectedIds.Length; offset += 32)
        {
            var node = network.ResolveNode(expectedIds.AsSpan(offset, 32));
            if ((node.RoleMask & (1 << 2)) == 0 || node.MailboxCapacity == 0)
                throw new CryptographicException("Logical assignment member lacks current mailbox admission.");
        }
        network.EnsureCurrent();
    }

    private void RequireContinuousCohort(ContactRecord terminal)
    {
        var closure = network.Closure!;
        var firstGeneration = U64(Projection.Field(2).Span);
        var lastGeneration = U64(terminal.Field(2).Span);
        if (firstGeneration > lastGeneration ||
            lastGeneration - firstGeneration >= XPointNetworkClosureWireCodec.MaximumChainCount)
            throw new CryptographicException("Logical assignment is outside the bounded current projection lineage.");
        var expectedGeneration = firstGeneration;
        var count = 0;
        foreach (var step in closure.RetainedPmts)
        {
            var generation = U64(step.Field(2).Span);
            if (generation < firstGeneration || generation > lastGeneration) continue;
            if (generation != expectedGeneration ||
                !Fixed(step.Field(1).Span, Projection.Field(1).Span) ||
                !Fixed(step.Field(6).Span, Projection.Field(6).Span) ||
                !Fixed(step.Field(7).Span, Projection.Field(7).Span) ||
                !SameNodeIds(Projection, step))
                throw new CryptographicException("Logical assignment lost continuous current epoch/cohort eligibility.");
            count++;
            if (generation != lastGeneration) expectedGeneration = checked(generation + 1);
        }
        if ((ulong)count != lastGeneration - firstGeneration + 1)
            throw new CryptographicException("Logical assignment retained projection history is incomplete.");
    }

    private static byte[] NodeIds(ContactRecord projection)
    {
        var rows = projection.Field(9).Span;
        var ids = new byte[checked(rows.Length / 136 * 32)];
        for (var offset = 0; offset < rows.Length; offset += 136)
            rows.Slice(offset, 32).CopyTo(ids.AsSpan(offset / 136 * 32, 32));
        return ids;
    }

    private static bool SameNodeIds(ContactRecord left, ContactRecord right)
    {
        var before = left.FieldSpan(9); var after = right.FieldSpan(9);
        if (before.Length != after.Length) return false;
        for (var offset = 0; offset < before.Length; offset += 136)
            if (!Fixed(before.Slice(offset, 32), after.Slice(offset, 32))) return false;
        return true;
    }

    private static ulong U64(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt64BigEndian(bytes);
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
