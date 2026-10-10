using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.DeepExtension.PrivacyRouting;

/// <summary>
/// Non-secret local custody bytes, not network authority. The host must
/// authenticate/protect these bytes before supplying them to the verifier.
/// </summary>
public static class OnionNetworkProtectedHistoryCodec
{
    private const int HeaderBytes = 16;
    private const int LkgBytes = 225;
    private const int MaximumRecordBytes = 65_535;

    public static byte[] Encode(VerifiedOnionNetworkContext network)
    {
        ArgumentNullException.ThrowIfNull(network);
        network.EnsureCurrent();
        var closure = network.Closure ?? throw new OnionBoundaryException(
            "network-context-incomplete", "Protected history requires a complete network closure.");
        var lkg = network.ProtectedLkg ?? throw new OnionBoundaryException(
            "network-context-incomplete", "Protected history requires a verified LKG.");
        return EncodeCore(lkg, closure.Policy.CanonicalCopy(), closure.Pmt.CanonicalBytes.Span);
    }

    /// <summary>Checks the entire verified predecessor, including policy/PMT bytes, for a host floor CAS.</summary>
    public static bool BindsPredecessor(VerifiedOnionNetworkContext network, ReadOnlyMemory<byte> exactProtectedHistory)
    {
        ArgumentNullException.ThrowIfNull(network);
        network.EnsureCurrent();
        if (exactProtectedHistory.Length < HeaderBytes + LkgBytes ||
            exactProtectedHistory.Length > HeaderBytes + LkgBytes + 2 * MaximumRecordBytes) return false;
        return network.BindsProtectedPredecessor(SHA256.HashData(exactProtectedHistory.Span));
    }

    internal static (XPointNetworkProtectedLkg Lkg, Xvp1Record Policy, ContactRecord Pmt) Decode(
        ReadOnlySpan<byte> capsule)
    {
        if (capsule.Length < HeaderBytes + LkgBytes ||
            capsule.Length > HeaderBytes + LkgBytes + 2 * MaximumRecordBytes ||
            !capsule[..4].SequenceEqual("DNH2"u8) ||
            BinaryPrimitives.ReadUInt16BigEndian(capsule[4..6]) != 2 ||
            BinaryPrimitives.ReadUInt16BigEndian(capsule[6..8]) != 0)
            throw Invalid();
        var policyLength = BinaryPrimitives.ReadUInt32BigEndian(capsule[8..12]);
        var pmtLength = BinaryPrimitives.ReadUInt32BigEndian(capsule[12..16]);
        if (policyLength is < 1 or > MaximumRecordBytes || pmtLength is < 1 or > MaximumRecordBytes ||
            (ulong)capsule.Length != HeaderBytes + LkgBytes + (ulong)policyLength + pmtLength)
            throw Invalid();
        var body = capsule.Slice(HeaderBytes, LkgBytes);
        var checkpointPresent = body[178];
        if (checkpointPresent > 1 || (checkpointPresent == 0 && body[179..].IndexOfAnyExcept((byte)0) >= 0))
            throw Invalid();
        try
        {
            var lkg = new XPointNetworkProtectedLkg(body[..16].ToArray(), body.Slice(16, 38).ToArray(),
                BinaryPrimitives.ReadUInt64BigEndian(body[54..62]), body.Slice(62, 32).ToArray(),
                body.Slice(94, 38).ToArray(), BinaryPrimitives.ReadUInt64BigEndian(body[132..140]),
                body.Slice(140, 38).ToArray(),
                checkpointPresent == 1 ? body.Slice(179, 38).ToArray() : default,
                checkpointPresent == 1 ? BinaryPrimitives.ReadUInt64BigEndian(body[217..225]) : null);
            var policy = XPointNetworkCodec.Parse<Xvp1Record>(capsule.Slice(HeaderBytes + LkgBytes, (int)policyLength));
            var pmt = ContactCodec.Decode(ProtocolMagic.PMT2, capsule[(HeaderBytes + LkgBytes + (int)policyLength)..]);
            if (!Fixed(policy.NetworkId.Span, lkg.NetworkId.Span) || !Fixed(pmt.Field(1).Span, lkg.NetworkId.Span) ||
                !Fixed(pmt.Field(5).Span, lkg.ViewCoreReference.Span) ||
                BinaryPrimitives.ReadUInt64BigEndian(pmt.Field(2).Span) < policy.UInt64(12))
                throw Invalid();
            return (lkg, policy, pmt);
        }
        catch (OnionBoundaryException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or FormatException or OverflowException)
        {
            throw new OnionBoundaryException("network-history-invalid", "The protected network history is not canonical.", exception);
        }
    }

    internal static VerifiedOnionNetworkContext BindVerifiedHistory(
        VerifiedXPointNetworkAuthority authority, VerifiedOnionNetworkContext candidate, ReadOnlySpan<byte> capsule,
        IReadOnlyList<ReadOnlyMemory<byte>> policies, IReadOnlyList<ReadOnlyMemory<byte>> views,
        IReadOnlyList<ReadOnlyMemory<byte>> heads, IReadOnlyList<ReadOnlyMemory<byte>> pmts)
    {
        var (prior, policy, pmt) = Decode(capsule);
        var next = candidate.ProtectedLkg ?? throw Invalid();
        _ = XPointOnionCapabilityProducer.RequireHistoricalAuthority(authority, prior.AuthorityCoreReference.Span);
        if (!Fixed(prior.NetworkId.Span, next.NetworkId.Span) ||
            !Fixed(next.AuthorityCoreReference.Span, authority.AuthorityCoreReference.Span) ||
            prior.ViewGeneration > next.ViewGeneration || prior.HeadTreeSize > next.HeadTreeSize)
            throw Mismatch();
        var index = -1;
        for (var i = 0; i < views.Count; i++)
        {
            var view = XPointNetworkCodec.Parse<Xnv1Record>(views[i].Span);
            if (view.ViewGeneration != prior.ViewGeneration) continue;
            var head = XPointNetworkCodec.Parse<Xnh1Record>(heads[i].Span);
            if (!Fixed(XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, view.CoreHash.Span), prior.ViewCoreReference.Span) ||
                !Fixed(XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNH1, head.CoreHash.Span), prior.HeadCoreReference.Span) ||
                !Fixed(view.FieldSpan(7), prior.AuthorityCoreReference.Span) ||
                !Fixed(head.FieldSpan(8), prior.AuthorityCoreReference.Span) ||
                !Fixed(policy.FieldSpan(18), prior.AuthorityCoreReference.Span) ||
                head.TreeSize != prior.HeadTreeSize || !Fixed(head.Root.Span, prior.HeadRoot.Span) ||
                !Fixed(view.ActivePolicy.Hash.Span, policy.CoreHash.Span))
                throw Mismatch();
            index = i;
            break;
        }
        if (index < 0 ||
            !policies.Any(bytes => Fixed(bytes.Span, policy.CanonicalCopy())) ||
            !pmts.Any(bytes => Fixed(bytes.Span, pmt.CanonicalBytes.Span)))
            throw Mismatch();
        var retained = new XPointNetworkProtectedLkg(next.NetworkId, next.HeadCoreReference, next.HeadTreeSize,
            next.HeadRoot, next.ViewCoreReference, next.ViewGeneration, next.AuthorityCoreReference,
            prior.LastForwardCheckpointCoreReference, prior.LastForwardCheckpointGeneration);
        candidate.EnsureCurrent();
        return new VerifiedOnionNetworkContext(candidate.NetworkId.Span, candidate.TrustedTime!,
            candidate.CandidateNodes, candidate.Closure!, retained, prior, SHA256.HashData(capsule));
    }

    internal static IReadOnlyList<ReadOnlyMemory<byte>>[] OwnChains(
        params IReadOnlyList<ReadOnlyMemory<byte>>[] chains)
    {
        long total = 0;
        foreach (var chain in chains)
        {
            ArgumentNullException.ThrowIfNull(chain);
            if (chain.Count is < 1 or > 4_096) throw Invalid();
            foreach (var record in chain)
            {
                if (record.Length is < 1 or > MaximumRecordBytes) throw Invalid();
                total += record.Length;
                if (total > 64L * 1024 * 1024) throw Invalid();
            }
        }
        return chains.Select(chain => (IReadOnlyList<ReadOnlyMemory<byte>>)
            chain.Select(bytes => (ReadOnlyMemory<byte>)bytes.ToArray()).ToArray()).ToArray();
    }

    private static byte[] EncodeCore(XPointNetworkProtectedLkg lkg, ReadOnlySpan<byte> policy, ReadOnlySpan<byte> pmt)
    {
        if (policy.Length is < 1 or > MaximumRecordBytes || pmt.Length is < 1 or > MaximumRecordBytes)
            throw Invalid();
        var bytes = new byte[HeaderBytes + LkgBytes + policy.Length + pmt.Length];
        "DNH2"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 2);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), checked((uint)policy.Length));
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(12), checked((uint)pmt.Length));
        var body = bytes.AsSpan(HeaderBytes, LkgBytes);
        lkg.NetworkId.Span.CopyTo(body);
        lkg.HeadCoreReference.Span.CopyTo(body[16..]);
        BinaryPrimitives.WriteUInt64BigEndian(body[54..], lkg.HeadTreeSize);
        lkg.HeadRoot.Span.CopyTo(body[62..]);
        lkg.ViewCoreReference.Span.CopyTo(body[94..]);
        BinaryPrimitives.WriteUInt64BigEndian(body[132..], lkg.ViewGeneration);
        lkg.AuthorityCoreReference.Span.CopyTo(body[140..]);
        if (lkg.LastForwardCheckpointGeneration.HasValue)
        {
            body[178] = 1;
            lkg.LastForwardCheckpointCoreReference.Span.CopyTo(body[179..]);
            BinaryPrimitives.WriteUInt64BigEndian(body[217..], lkg.LastForwardCheckpointGeneration.Value);
        }
        policy.CopyTo(bytes.AsSpan(HeaderBytes + LkgBytes));
        pmt.CopyTo(bytes.AsSpan(HeaderBytes + LkgBytes + policy.Length));
        return bytes;
    }

    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static OnionBoundaryException Invalid() => new("network-history-invalid", "Protected history is not canonical.");
    private static OnionBoundaryException Mismatch() => new("network-history-mismatch", "The current signed chains do not preserve the protected predecessor.");
}
