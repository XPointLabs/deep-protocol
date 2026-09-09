using System.Buffers.Binary;

namespace Deep.Protocol.XPointNetworkV1;

internal static class XPointNetworkSemantics
{
    internal static void Validate(XPointParsedRecord record)
    {
        switch (record)
        {
            case Xna1Record value: ValidateXna(value); break;
            case Xvp1Record value: ValidateXvp(value); break;
            case Xnd1Record value: ValidateXnd(value); break;
            case Xnv1Record value: ValidateXnv(value); break;
            case Xnh1Record value: ValidateXnh(value); break;
            case Xnp1Record value: ValidateXnp(value); break;
            case Xnf1Record value: ValidateXnf(value); break;
            case Nfp1Record value: ValidateNfp(value); break;
            case Xcd1Record value: ValidateXcd(value); break;
            default: throw new InvalidOperationException();
        }
    }

    private static void ValidateXna(Xna1Record r)
    {
        if (r.RootThreshold > r.RootKeys.Count || r.WitnessThreshold > r.Witnesses.Count)
            Fail(XPointValidationStage.CrossField, "ThresholdExceedsCount", "A threshold exceeds its key count.");
        ValidateSortedUnique(r.FieldSpan(5), 72, 0, 32, [40], [32]);
        ValidateSortedUnique(r.FieldSpan(10), 104, 0, 32, [40,72], [32,32]);
        ValidateSortedUnique(r.FieldSpan(20), 96, 0, 32, [32], [64]);
        if (r.AuthorityGeneration == 0 && (r.RootKeys.Any(x => x.Generation != 0) || r.Witnesses.Any(x => x.Generation != 0)))
            Fail(XPointValidationStage.CrossField, "InvalidGenesisKeyGeneration", "Genesis key generations must be zero.");
        ValidateInterval(r.IssuedAt, r.NotBefore, r.ExpiresAt, 34_560_000);
        if (r.AuthorityGeneration == 0 && r.Signatures.Count < r.RootThreshold)
            Fail(XPointValidationStage.CrossField, "WrongAuthorizingThreshold", "Genesis signatures do not meet the current threshold.");
    }

    private static void ValidateXvp(Xvp1Record r)
    {
        var constraints = r.UInt16(7);
        if ((constraints & 0x000f) != 0x000f || (constraints & ~0x007f) != 0)
            Fail(XPointValidationStage.CrossField, "InvalidRouteConstraintMask", "Required route constraints are absent or unknown bits are set.");
        if (r.MailboxReplicaCount != 2)
            Fail(XPointValidationStage.CrossField, "InactiveMaturityValue", "D0 requires exactly two mailbox replicas.");
        ValidateInterval(r.IssuedAt, r.NotBefore, r.ExpiresAt, 2_592_000);
        ValidateSortedUnique(r.FieldSpan(20), 96, 0, 32, [32], [64]);
    }

    private static void ValidateXnd(Xnd1Record r)
    {
        Span<byte> failureProjection = stackalloc byte[150];
        var offset = 0;
        foreach (var tag in new[] { 1,7,8,9,10,11 })
        {
            r.FieldSpan(tag).CopyTo(failureProjection[offset..]);
            offset += r.FieldSpan(tag).Length;
        }
        if (!XPointNetworkCrypto.Sha256Domain(XPointNetworkRegistry.FailureDomainDomain, failureProjection[..offset]).AsSpan().SequenceEqual(r.FieldSpan(12)))
            Fail(XPointValidationStage.DerivedValue, "FailureDomainMismatch", "The failure-domain projection hash is invalid.");

        var roles = r.RoleMask;
        if (roles == 0 || (roles & ~0x001f) != 0)
            Fail(XPointValidationStage.CrossField, "UnknownRoleBit", "The role mask is invalid.");
        for (var role = 0; role < 5; role++)
        {
            var hasRole = (roles & (1 << role)) != 0;
            ulong capacity = role switch
            {
                0 => r.UInt32(14), 1 => r.UInt64(15), 2 => r.UInt64(16),
                3 => r.UInt64(17), 4 => r.UInt32(18), _ => 0UL,
            };
            if (hasRole != (capacity != 0))
                Fail(XPointValidationStage.CrossField, "RoleProjectionMismatch", "Role capacity does not match the role mask.");
        }

        ValidateSortedUnique(r.FieldSpan(20), 148, 0, 32);
        var originEndpoints = new HashSet<string>(StringComparer.Ordinal);
        foreach (var origin in r.Origins)
        {
            if (origin.Transport is not (1 or 2) || origin.AddressFamily is not (4 or 6) ||
                origin.Port == 0 || XPointNetworkCodec.IsZero(origin.Address.Span) ||
                XPointNetworkCodec.IsZero(origin.CurrentSpki.Span) || XPointNetworkCodec.IsZero(origin.NextSpki.Span) ||
                origin.CurrentSpki.Equals(origin.NextSpki) ||
                origin.CurrentNotBefore >= origin.CurrentExpiresAt || origin.NextNotBefore >= origin.NextExpiresAt ||
                origin.NextNotBefore > origin.CurrentExpiresAt ||
                origin.AddressFamily == 4 && !XPointNetworkCodec.IsZero(origin.Address.Span[4..]))
                Fail(XPointValidationStage.CrossField, "InvalidPeerOrigin", "A peer origin violates its exact grammar.");
            var endpoint = $"{origin.Transport}:{origin.AddressFamily}:{Convert.ToHexString(origin.Address.Span)}:{origin.Port}";
            if (!originEndpoints.Add(endpoint))
                Fail(XPointValidationStage.CanonicalList, "NonCanonicalList", "Peer origin endpoints must be unique.");
        }

        var currentEpoch = r.UInt64(21);
        if (currentEpoch == ulong.MaxValue || r.UInt64(25) != currentEpoch + 1 || r.FieldSpan(22).SequenceEqual(r.FieldSpan(26)))
            Fail(XPointValidationStage.CrossField, "InvalidKeyEpoch", "Onion key epochs or keys are invalid.");
        ValidateSimpleInterval(r.UInt64(23), r.UInt64(24), 86_400, "InvalidKeyEpoch");
        ValidateSimpleInterval(r.UInt64(27), r.UInt64(28), 86_400, "InvalidKeyEpoch");
        if (r.UInt64(27) > r.UInt64(24))
            Fail(XPointValidationStage.CrossField, "InvalidKeyEpoch", "Onion key intervals contain a gap.");
        if (r.UInt16(29) > r.UInt16(30))
            Fail(XPointValidationStage.CrossField, "InvalidProtocolRange", "The protocol generation range is reversed.");
        ValidateInterval(r.UInt64(33), r.NotBefore, r.ExpiresAt, 604_800);

        // Role id zero is the canonical Entry role. Unlike identifier fields, the
        // sort key for this list is therefore allowed to be zero.
        ValidateSortedUnique(r.FieldSpan(32), 41, 0, 1, [9], [32], allowZeroSortKey: true);
        if (r.RoleKeys.Count != PopCount(roles) || r.RoleKeys.Any(k => k.RoleId > 4 || (roles & (1 << k.RoleId)) == 0))
            Fail(XPointValidationStage.CrossField, "RoleProjectionMismatch", "Role-key entries are not the exact role projection.");
    }

    private static void ValidateXnv(Xnv1Record r)
    {
        ValidateReferenceList(r.FieldSpan(12), ProtocolMagic.XND1, artifact: true, sorted: false);
        ValidateSortedUnique(r.FieldSpan(14), 32, 0, 32);
        ValidateServiceReferences(r.FieldSpan(16));
        ValidateReferenceList(r.FieldSpan(18), ProtocolMagic.XCB1, artifact: true, sorted: true);
        ValidateSortedUnique(r.FieldSpan(24), 96, 0, 32, [32], [64]);
        ValidateInterval(r.UInt64(19), r.NotBefore, r.ExpiresAt, 86_400);
    }

    private static void ValidateXnh(Xnh1Record r)
    {
        ValidateNodeList(r.FieldSpan(14));
        ValidateSortedUnique(r.FieldSpan(16), 96, 0, 32, [32], [64]);
        ValidateSimpleInterval(r.ValidFrom, r.ValidUntil, 86_400, "InvalidEffectiveTimeClosure");
        if (r.LogGeneration == 0 && (r.TreeSize != 1 || r.LatestViewGeneration != 0 || r.UInt8(13) != 0))
            Fail(XPointValidationStage.CrossField, "InvalidGenesisHead", "A genesis head must contain exactly one generation-zero leaf and no consistency proof.");
    }

    private static void ValidateXnp(Xnp1Record r)
    {
        ValidateNodeList(r.FieldSpan(15));
        ValidateNodeList(r.FieldSpan(17));
        if (r.TargetTreeSize < r.SourceTreeSize || r.TargetViewGeneration < r.SourceViewGeneration ||
            r.UInt64(13) != r.TargetTreeSize - 1)
            Fail(XPointValidationStage.CrossField, "InvalidProofTuple", "The ordinary proof tuple is invalid.");
        var identical = r.TargetTreeSize == r.SourceTreeSize && r.TargetViewGeneration == r.SourceViewGeneration &&
            r.FieldSpan(4).SequenceEqual(r.FieldSpan(9)) && r.FieldSpan(5).SequenceEqual(r.FieldSpan(10));
        if (identical != (r.UInt8(14) == 0 && r.UInt8(16) == 0))
            Fail(XPointValidationStage.Proof, "NonCanonicalProof", "Identical tuples require zero proofs and changed tuples require proof nodes.");
    }

    private static void ValidateXnf(Xnf1Record r)
    {
        ulong expected;
        try { expected = checked(r.LastCoveredGeneration - r.FirstCoveredGeneration + 1); }
        catch (OverflowException) { Fail(XPointValidationStage.ListArithmetic, "ArithmeticOverflow", "The covered range overflows."); return; }
        if (r.LastCoveredGeneration < r.FirstCoveredGeneration || expected != r.CoveredHeadCount)
            Fail(XPointValidationStage.CrossField, "InvalidForwardCheckpoint", "The covered range/count is inconsistent.");
        var targetGeneration = BinaryPrimitives.ReadUInt64BigEndian(r.FieldSpan(8));
        if (targetGeneration != r.LastCoveredGeneration || !r.TargetView.Hash.Span.SequenceEqual(r.FieldSpan(8)[8..]))
            Fail(XPointValidationStage.CrossField, "InvalidForwardCheckpoint", "The target view projection is inconsistent.");
        ValidateSortedUnique(r.FieldSpan(15), 96, 0, 32, [32], [64]);
    }

    private static void ValidateNfp(Nfp1Record r)
    {
        ValidateReferenceList(r.FieldSpan(10), ProtocolMagic.XNA1, artifact: false, sorted: false);
        ValidateReferenceList(r.FieldSpan(12), ProtocolMagic.XNF1, artifact: false, sorted: false);
        ValidateNodeList(r.FieldSpan(14));
    }

    private static void ValidateXcd(Xcd1Record r)
    {
        ValidateSortedUnique(r.FieldSpan(8), 200, 0, 32, [40,72,104], [32,32,32]);
        var nodes = new HashSet<string>(StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        var keys = new HashSet<string>(StringComparer.Ordinal) { Convert.ToHexString(r.TargetRolePublicKey.Span) };
        foreach (var entry in r.Replicas)
        {
            if (entry.NodeId.Span.SequenceEqual(r.CallRelayNodeId.Span) ||
                !nodes.Add(Convert.ToHexString(entry.NodeId.Span)) ||
                !domains.Add(Convert.ToHexString(entry.FailureDomainHash.Span)) ||
                !keys.Add(Convert.ToHexString(entry.RolePublicKey.Span)) ||
                XPointNetworkCodec.IsZero(entry.ProofOfPossession.Span))
                Fail(XPointValidationStage.CanonicalList, "NonCanonicalList", "Call relay replica identities, nodes, keys, and domains must be distinct.");
        }
        ValidateInterval(r.UInt64(18), r.NotBefore, r.ExpiresAt, 604_800);
    }

    private static void ValidateInterval(ulong issuedAt, ulong notBefore, ulong expiresAt, ulong maximumLifetime)
    {
        if (issuedAt > notBefore || notBefore >= expiresAt || expiresAt - notBefore > maximumLifetime)
            Fail(XPointValidationStage.CrossField, "InvalidEffectiveTimeClosure", "The validity interval is invalid.");
    }

    private static void ValidateSimpleInterval(ulong from, ulong until, ulong maximum, string error)
    {
        if (from >= until || until - from > maximum)
            Fail(XPointValidationStage.CrossField, error, "A validity interval is invalid.");
    }

    private static void ValidateNodeList(ReadOnlySpan<byte> list)
    {
        for (var offset = 0; offset < list.Length; offset += 32)
            if (XPointNetworkCodec.IsZero(list.Slice(offset, 32)))
                Fail(XPointValidationStage.CanonicalList, "NonCanonicalList", "Merkle nodes must be nonzero.");
    }

    private static void ValidateReferenceList(ReadOnlySpan<byte> list, string magic, bool artifact, bool sorted)
    {
        ReadOnlySpan<byte> previous = default;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var offset = 0; offset < list.Length; offset += 38)
        {
            var value = list.Slice(offset, 38);
            if (!value[..4].SequenceEqual(System.Text.Encoding.ASCII.GetBytes(magic)) ||
                BinaryPrimitives.ReadUInt16BigEndian(value[4..6]) != 1 || XPointNetworkCodec.IsZero(value[6..]))
                Fail(XPointValidationStage.Reference, "ReferenceTypeMismatch", $"Expected a {magic} {(artifact ? "artifact" : "core")} reference.");
            if (!seen.Add(Convert.ToHexString(value)))
                Fail(XPointValidationStage.CanonicalList, "NonCanonicalList", "Reference list entries must be unique.");
            if (sorted && !previous.IsEmpty && previous.SequenceCompareTo(value) >= 0)
                Fail(XPointValidationStage.CanonicalList, "NonCanonicalList", "Reference list entries are not sorted.");
            previous = value;
        }
    }

    private static void ValidateServiceReferences(ReadOnlySpan<byte> list)
    {
        ReadOnlySpan<byte> previous = default;
        for (var offset = 0; offset < list.Length; offset += 38)
        {
            var value = list.Slice(offset, 38);
            var magic = System.Text.Encoding.ASCII.GetString(value[..4]);
            if (magic is not (ProtocolMagic.XCD1 or ProtocolMagic.XOD1) || BinaryPrimitives.ReadUInt16BigEndian(value[4..6]) != 1 ||
                XPointNetworkCodec.IsZero(value[6..]) || !previous.IsEmpty && previous.SequenceCompareTo(value) >= 0)
                Fail(XPointValidationStage.CanonicalList, "NonCanonicalList", "Service core references are invalid, duplicated, or unsorted.");
            previous = value;
        }
    }

    private static void ValidateSortedUnique(
        ReadOnlySpan<byte> list, int width, int sortOffset, int sortLength,
        int[]? uniqueOffsets = null, int[]? uniqueLengths = null,
        bool allowZeroSortKey = false)
    {
        ReadOnlySpan<byte> previous = default;
        var additional = uniqueOffsets is null ? null : uniqueOffsets.Select(_ => new HashSet<string>(StringComparer.Ordinal)).ToArray();
        for (var offset = 0; offset < list.Length; offset += width)
        {
            var entry = list.Slice(offset, width);
            var key = entry.Slice(sortOffset, sortLength);
            if (!allowZeroSortKey && XPointNetworkCodec.IsZero(key) ||
                !previous.IsEmpty && previous.SequenceCompareTo(key) >= 0)
                Fail(XPointValidationStage.CanonicalList, "NonCanonicalList", "A list is unsorted, duplicated, or contains a zero ID.");
            previous = key;
            if (additional is null) continue;
            for (var index = 0; index < additional.Length; index++)
            {
                var value = entry.Slice(uniqueOffsets![index], uniqueLengths![index]);
                if (XPointNetworkCodec.IsZero(value) || !additional[index].Add(Convert.ToHexString(value)))
                    Fail(XPointValidationStage.CanonicalList, "NonCanonicalList", "A unique list component is zero or duplicated.");
            }
        }
    }

    private static int PopCount(ushort value)
    {
        var count = 0;
        while (value != 0) { count += value & 1; value >>= 1; }
        return count;
    }

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(XPointValidationStage stage, string error, string message) =>
        throw XPointNetworkCodec.Error(stage, error, message);
}
