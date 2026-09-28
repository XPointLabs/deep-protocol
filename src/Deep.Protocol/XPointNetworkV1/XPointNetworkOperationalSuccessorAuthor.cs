using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

public sealed class XPointNetworkOperationalNodeRollover
{
    private readonly byte[] currentOriginSpkiSha256;
    private readonly byte[] nextOriginSpkiSha256;
    private readonly byte[] currentOnionX25519PublicKey;
    private readonly byte[] nextOnionX25519PublicKey;

    public XPointNetworkOperationalNodeRollover(
        IXPointNetworkOperationalSigner identitySigner,
        ReadOnlySpan<byte> currentOriginSpkiSha256,
        ReadOnlySpan<byte> nextOriginSpkiSha256,
        ReadOnlySpan<byte> currentOnionX25519PublicKey,
        ReadOnlySpan<byte> nextOnionX25519PublicKey)
    {
        IdentitySigner = identitySigner ?? throw new ArgumentNullException(nameof(identitySigner));
        this.currentOriginSpkiSha256 = Required(currentOriginSpkiSha256, nameof(currentOriginSpkiSha256));
        this.nextOriginSpkiSha256 = Required(nextOriginSpkiSha256, nameof(nextOriginSpkiSha256));
        this.currentOnionX25519PublicKey = Required(currentOnionX25519PublicKey, nameof(currentOnionX25519PublicKey));
        this.nextOnionX25519PublicKey = Required(nextOnionX25519PublicKey, nameof(nextOnionX25519PublicKey));
        if (this.currentOriginSpkiSha256.AsSpan().SequenceEqual(this.nextOriginSpkiSha256) ||
            this.currentOnionX25519PublicKey.AsSpan().SequenceEqual(this.nextOnionX25519PublicKey))
            throw new ArgumentException("Current and next operational keys must be distinct.");
    }

    public IXPointNetworkOperationalSigner IdentitySigner { get; }
    public ReadOnlyMemory<byte> CurrentOriginSpkiSha256 => currentOriginSpkiSha256.ToArray();
    public ReadOnlyMemory<byte> NextOriginSpkiSha256 => nextOriginSpkiSha256.ToArray();
    public ReadOnlyMemory<byte> CurrentOnionX25519PublicKey => currentOnionX25519PublicKey.ToArray();
    public ReadOnlyMemory<byte> NextOnionX25519PublicKey => nextOnionX25519PublicKey.ToArray();

    private static byte[] Required(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be a nonzero 32-byte key or pin.", name);
        return value.ToArray();
    }
}

/// <summary>
/// Exact, protected predecessor and signer inputs for a one-generation operational
/// renewal. The release-pinned XNA1/DTS1 are reused; no genesis record is authored.
/// </summary>
public sealed class XPointNetworkOperationalSuccessorRequest
{
    private readonly byte[] ceremonyId;
    private readonly byte[] protectedHeadCoreHash;
    private readonly byte[] protectedPmtArtifactHash;
    private readonly byte[] currentAdh1CoreReference;

    public XPointNetworkOperationalSuccessorRequest(
        ReadOnlySpan<byte> ceremonyId,
        VerifiedXPointNetworkBootstrap bootstrap,
        IReadOnlyList<IXPointNetworkBootstrapRootSigner> rootSigners,
        IReadOnlyList<IXPointNetworkWitnessSigner> witnessSigners,
        IReadOnlyList<XPointNetworkOperationalNodeRollover> nodeRollovers,
        ReadOnlyMemory<byte> exactPreviousXvp1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactPreviousXnd1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnv1History,
        ReadOnlyMemory<byte> exactProtectedXnh1,
        ReadOnlyMemory<byte> exactPreviousPma2,
        ReadOnlyMemory<byte> exactProtectedPmt2,
        ReadOnlySpan<byte> protectedHeadCoreHash,
        ReadOnlySpan<byte> protectedPmtArtifactHash,
        ReadOnlySpan<byte> currentAdh1CoreReference,
        ulong issuedAtUnixSeconds,
        ulong notBeforeUnixSeconds,
        ulong expiresAtUnixSeconds)
    {
        this.ceremonyId = Required(ceremonyId, 32, nameof(ceremonyId));
        Bootstrap = bootstrap ?? throw new ArgumentNullException(nameof(bootstrap));
        RootSigners = Copy(rootSigners, nameof(rootSigners));
        WitnessSigners = Copy(witnessSigners, nameof(witnessSigners));
        NodeRollovers = Copy(nodeRollovers, nameof(nodeRollovers));
        ExactPreviousXvp1 = Required(exactPreviousXvp1.Span, nameof(exactPreviousXvp1));
        ExactPreviousXnd1 = CopyBytes(exactPreviousXnd1, nameof(exactPreviousXnd1));
        ExactOrderedXnv1History = CopyBytes(exactOrderedXnv1History, nameof(exactOrderedXnv1History));
        ExactProtectedXnh1 = Required(exactProtectedXnh1.Span, nameof(exactProtectedXnh1));
        ExactPreviousPma2 = Required(exactPreviousPma2.Span, nameof(exactPreviousPma2));
        ExactProtectedPmt2 = Required(exactProtectedPmt2.Span, nameof(exactProtectedPmt2));
        this.protectedHeadCoreHash = Required(protectedHeadCoreHash, 32, nameof(protectedHeadCoreHash));
        this.protectedPmtArtifactHash = Required(protectedPmtArtifactHash, 32, nameof(protectedPmtArtifactHash));
        this.currentAdh1CoreReference = Required(currentAdh1CoreReference, 38, nameof(currentAdh1CoreReference));
        if (!this.currentAdh1CoreReference.AsSpan(0, 4).SequenceEqual("ADH1"u8) ||
            !this.currentAdh1CoreReference.AsSpan(4, 2).SequenceEqual(new byte[] { 0, 1 }))
            throw new ArgumentException("The current directory anchor must be an ADH1 core reference.", nameof(currentAdh1CoreReference));
        if (RootSigners.Count == 0 || WitnessSigners.Count is < 2 or > 32 ||
            NodeRollovers.Count is < 3 or > 512 ||
            ExactPreviousXnd1.Count != NodeRollovers.Count ||
            ExactOrderedXnv1History.Count is < 1 or > 4_096)
            throw new ArgumentException("The operational predecessor/signer set is incomplete or unbounded.");
        if (issuedAtUnixSeconds == 0 || issuedAtUnixSeconds > notBeforeUnixSeconds ||
            notBeforeUnixSeconds >= expiresAtUnixSeconds ||
            expiresAtUnixSeconds - notBeforeUnixSeconds > 86_400 ||
            Bootstrap.Authority.NotBefore > issuedAtUnixSeconds ||
            expiresAtUnixSeconds > Bootstrap.Authority.ExpiresAt)
            throw new ArgumentException("The successor interval is outside the live authority or 24-hour profile.");
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        NotBeforeUnixSeconds = notBeforeUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }

    public ReadOnlyMemory<byte> CeremonyId => ceremonyId.ToArray();
    public VerifiedXPointNetworkBootstrap Bootstrap { get; }
    public IReadOnlyList<IXPointNetworkBootstrapRootSigner> RootSigners { get; }
    public IReadOnlyList<IXPointNetworkWitnessSigner> WitnessSigners { get; }
    public IReadOnlyList<XPointNetworkOperationalNodeRollover> NodeRollovers { get; }
    public ReadOnlyMemory<byte> ExactPreviousXvp1 { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactPreviousXnd1 { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnv1History { get; }
    public ReadOnlyMemory<byte> ExactProtectedXnh1 { get; }
    public ReadOnlyMemory<byte> ExactPreviousPma2 { get; }
    public ReadOnlyMemory<byte> ExactProtectedPmt2 { get; }
    public ReadOnlyMemory<byte> ProtectedHeadCoreHash => protectedHeadCoreHash.ToArray();
    public ReadOnlyMemory<byte> ProtectedPmtArtifactHash => protectedPmtArtifactHash.ToArray();
    public ReadOnlyMemory<byte> CurrentAdh1CoreReference => currentAdh1CoreReference.ToArray();
    public ulong IssuedAtUnixSeconds { get; }
    public ulong NotBeforeUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }

    private static byte[] Required(ReadOnlySpan<byte> value, int size, string name)
    {
        if (value.Length != size || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {size} nonzero bytes.", name);
        return value.ToArray();
    }

    private static byte[] Required(ReadOnlySpan<byte> value, string name)
    {
        if (value.IsEmpty) throw new ArgumentException($"{name} is empty.", name);
        return value.ToArray();
    }

    private static IReadOnlyList<T> Copy<T>(IReadOnlyList<T> values, string name) where T : class
    {
        ArgumentNullException.ThrowIfNull(values, name);
        if (values.Any(static value => value is null))
            throw new ArgumentException($"{name} contains a null signer.", name);
        return Array.AsReadOnly(values.ToArray());
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> CopyBytes(
        IReadOnlyList<ReadOnlyMemory<byte>> values, string name)
    {
        ArgumentNullException.ThrowIfNull(values, name);
        if (values.Any(static value => value.IsEmpty))
            throw new ArgumentException($"{name} contains an empty artifact.", name);
        return Array.AsReadOnly(values.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    }
}

public sealed class AuthoredXPointNetworkOperationalSuccessor
{
    internal AuthoredXPointNetworkOperationalSuccessor(
        byte[] xvp1, byte[][] xnd1, byte[] xnv1, byte[] xnh1, byte[] pma2, byte[] pmt2)
    {
        ExactXvp1 = xvp1.ToArray();
        ExactXnd1 = Array.AsReadOnly(xnd1.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
        ExactXnv1 = xnv1.ToArray();
        ExactXnh1 = xnh1.ToArray();
        ExactPma2 = pma2.ToArray();
        ExactPmt2 = pmt2.ToArray();
    }

    public ReadOnlyMemory<byte> ExactXvp1 { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactXnd1 { get; }
    public ReadOnlyMemory<byte> ExactXnv1 { get; }
    public ReadOnlyMemory<byte> ExactXnh1 { get; }
    public ReadOnlyMemory<byte> ExactPma2 { get; }
    public ReadOnlyMemory<byte> ExactPmt2 { get; }
}

/// <summary>
/// Authors one exact XVP1/XND1/XNV1/XNH1/PMA2/PMT2 successor closure. It cannot
/// publish or replace the caller's independently protected network/directory floors.
/// </summary>
public static class XPointNetworkOperationalSuccessorAuthor
{
    public static byte[] ComputeAdh1CoreHash(ReadOnlySpan<byte> exactAdh1) =>
        AccountDirectoryCrypto.ComputeAdh1CoreHash(AccountDirectoryAdh1Codec.Decode(exactAdh1));

    public static byte[] ComputeXnh1CoreHash(ReadOnlySpan<byte> exactXnh1) =>
        XPointNetworkCodec.Parse<Xnh1Record>(exactXnh1).CoreHash.ToArray();

    public static async ValueTask<AuthoredXPointNetworkOperationalSuccessor> AuthorAsync(
        XPointNetworkOperationalSuccessorRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var authority = request.Bootstrap.Authority;
        var roots = ValidateRoots(authority, request.RootSigners);
        var witnesses = ValidateWitnesses(authority, request.WitnessSigners);
        var priorPolicy = XPointNetworkCodec.Parse<Xvp1Record>(request.ExactPreviousXvp1.Span);
        var priorNodes = request.ExactPreviousXnd1
            .Select(static value => XPointNetworkCodec.Parse<Xnd1Record>(value.Span))
            .OrderBy(static value => value.NodeId.ToArray(), ByteArrayComparer.Instance).ToArray();
        var priorView = XPointNetworkCodec.Parse<Xnv1Record>(request.ExactOrderedXnv1History[^1].Span);
        var priorHead = XPointNetworkCodec.Parse<Xnh1Record>(request.ExactProtectedXnh1.Span);
        var priorPma = ContactCodec.Decode(ProtocolMagic.PMA2, request.ExactPreviousPma2.Span);
        var priorPmt = ContactCodec.Decode(ProtocolMagic.PMT2, request.ExactProtectedPmt2.Span);
        ValidateProtectedPredecessor(request, authority, priorPolicy, priorNodes, priorView, priorHead, priorPma, priorPmt);
        var nodeRollovers = ValidateNodeRollovers(priorNodes, request.NodeRollovers);

        var nextPmtGeneration = checked(BinaryPrimitives.ReadUInt64BigEndian(priorPmt.FieldSpan(2)) + 1);
        var policy = await AuthorPolicyAsync(request, priorPolicy, nextPmtGeneration, roots, cancellationToken)
            .ConfigureAwait(false);
        var nodeBytes = new byte[priorNodes.Length][];
        for (var index = 0; index < priorNodes.Length; index++)
            nodeBytes[index] = await AuthorNodeAsync(
                request, priorNodes[index], nodeRollovers[index], cancellationToken).ConfigureAwait(false);
        var nodes = nodeBytes.Select(static value => XPointNetworkCodec.Parse<Xnd1Record>(value)).ToArray();
        var view = await AuthorViewAsync(request, priorView, policy, nodes, witnesses, cancellationToken)
            .ConfigureAwait(false);
        var proof = XPointNetworkViewLogAuthor.BuildAppendProof(
            request.ExactOrderedXnv1History, request.ExactProtectedXnh1.Span, view);
        var head = await AuthorHeadAsync(request, priorHead, view, proof, witnesses, cancellationToken)
            .ConfigureAwait(false);
        var pma = await AuthorPmaAsync(request, priorPma, roots, cancellationToken)
            .ConfigureAwait(false);
        var pmt = await AuthorPmtAsync(request, priorPmt, pma, view, nodes, witnesses, cancellationToken)
            .ConfigureAwait(false);

        XPointNetworkVerifier.RequireSuccessor(priorPolicy, XPointNetworkCodec.Parse<Xvp1Record>(policy));
        XPointNetworkVerifier.RequireSuccessor(priorView, XPointNetworkCodec.Parse<Xnv1Record>(view));
        XPointNetworkVerifier.RequireSuccessor(priorHead, XPointNetworkCodec.Parse<Xnh1Record>(head));
        for (var index = 0; index < priorNodes.Length; index++)
            XPointNetworkVerifier.RequireSuccessor(priorNodes[index], nodes[index]);
        _ = MailboxAuthorityV2Verifier.Verify(
            authority, pma, request.NotBeforeUnixSeconds, request.ExpiresAtUnixSeconds - 1);
        return new AuthoredXPointNetworkOperationalSuccessor(policy, nodeBytes, view, head, pma, pmt);
    }

    private static void ValidateProtectedPredecessor(
        XPointNetworkOperationalSuccessorRequest request,
        VerifiedXPointNetworkAuthority authority,
        Xvp1Record policy,
        IReadOnlyList<Xnd1Record> nodes,
        Xnv1Record view,
        Xnh1Record head,
        ContactRecord pma,
        ContactRecord pmt)
    {
        if (!Fixed(head.CoreHash.Span, request.ProtectedHeadCoreHash.Span) ||
            !Fixed(pmt.ArtifactHash.Span, request.ProtectedPmtArtifactHash.Span) ||
            !Fixed(view.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(head.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(policy.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(policy.FieldSpan(18), authority.AuthorityCoreReference.Span) ||
            !Fixed(view.FieldSpan(7), authority.AuthorityCoreReference.Span) ||
            !Fixed(head.FieldSpan(8), authority.AuthorityCoreReference.Span) ||
            !Fixed(view.FieldSpan(8), authority.DirectoryWitnessPolicyHash.Span) ||
            !Fixed(head.FieldSpan(9), authority.DirectoryWitnessPolicyHash.Span) ||
            !Fixed(view.FieldSpan(9), XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XVP1, policy.CoreHash.Span)) ||
            !head.LatestView.Equals(view.CoreReferenceValue) ||
            head.LatestViewGeneration != view.ViewGeneration ||
            head.TreeSize != checked(view.ViewGeneration + 1) ||
            !Fixed(pma.FieldSpan(1), authority.NetworkId.Span) ||
            !Fixed(pmt.FieldSpan(1), authority.NetworkId.Span) ||
            !Fixed(pmt.FieldSpan(4), XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.PMA2, pma.CoreHash.Span)) ||
            !Fixed(pmt.FieldSpan(5), XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, view.CoreHash.Span)) ||
            BinaryPrimitives.ReadUInt64BigEndian(pmt.FieldSpan(2)) != policy.UInt64(12) ||
            nodes.Count != view.UInt16(11) ||
            nodes.Select(static node => Convert.ToHexString(node.NodeId.Span)).Distinct(StringComparer.Ordinal).Count() != nodes.Count)
            throw new CryptographicException("The exact protected operational predecessor is incomplete or cross-bound.");
        var references = nodes.Select(static node => ArtifactReference(
            ProtocolMagic.XND1, XPointNetworkCrypto.ComputeArtifactHash(node))).SelectMany(static value => value).ToArray();
        if (!Fixed(references, view.FieldSpan(12)))
            throw new CryptographicException("The protected view does not commit the exact node descriptor set.");
        var validHistoricalTime = BinaryPrimitives.ReadUInt64BigEndian(pma.FieldSpan(11));
        _ = MailboxAuthorityV2Verifier.Verify(authority, pma.CanonicalBytes.Span,
            validHistoricalTime, validHistoricalTime);
    }

    private static async ValueTask<byte[]> AuthorPolicyAsync(
        XPointNetworkOperationalSuccessorRequest request,
        Xvp1Record previous,
        ulong requiredPmtGeneration,
        IXPointNetworkBootstrapRootSigner[] roots,
        CancellationToken cancellationToken)
    {
        var fields = Fields(previous, 20);
        fields[1] = U64(checked(previous.Generation + 1));
        fields[2] = previous.CoreHash.ToArray();
        fields[11] = U64(requiredPmtGeneration);
        fields[14] = U64(request.IssuedAtUnixSeconds);
        fields[15] = U64(request.NotBeforeUnixSeconds);
        fields[16] = U64(request.ExpiresAtUnixSeconds);
        fields[18] = new[] { checked((byte)roots.Length) };
        fields[19] = SignatureRows(roots.Select(static signer =>
            (signer.RootKeyId.ToArray(), Placeholder64())).ToArray());
        var provisional = XPointNetworkCodec.Parse<Xvp1Record>(
            XPointNetworkCodec.Write(XPointNetworkRegistry.Xvp1, fields));
        var input = XPointNetworkCrypto.ComputeSigningInput(provisional);
        fields[19] = SignatureRows(await SignRootsAsync(
            request, roots, XPointNetworkRootSignaturePurpose.NetworkPolicy,
            previous.Generation + 1, input, cancellationToken).ConfigureAwait(false));
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xvp1, fields);
    }

    private static async ValueTask<byte[]> AuthorNodeAsync(
        XPointNetworkOperationalSuccessorRequest request,
        Xnd1Record previous,
        XPointNetworkOperationalNodeRollover rollover,
        CancellationToken cancellationToken)
    {
        var signer = rollover.IdentitySigner;
        var fields = Fields(previous, 37);
        fields[2] = U64(checked(previous.Generation + 1));
        fields[3] = previous.CoreHash.ToArray();
        var origins = fields[19].ToArray();
        for (var offset = 0; offset < origins.Length; offset += 148)
        {
            rollover.CurrentOriginSpkiSha256.Span.CopyTo(origins.AsSpan(offset + 52, 32));
            U64(request.NotBeforeUnixSeconds).CopyTo(origins, offset + 84);
            U64(request.ExpiresAtUnixSeconds).CopyTo(origins, offset + 92);
            rollover.NextOriginSpkiSha256.Span.CopyTo(origins.AsSpan(offset + 100, 32));
            U64(request.NotBeforeUnixSeconds).CopyTo(origins, offset + 132);
            U64(request.ExpiresAtUnixSeconds).CopyTo(origins, offset + 140);
        }
        fields[19] = origins;
        var currentEpoch = checked(previous.UInt64(25) + 1);
        fields[20] = U64(currentEpoch);
        fields[21] = rollover.CurrentOnionX25519PublicKey;
        fields[22] = U64(request.NotBeforeUnixSeconds);
        fields[23] = U64(request.ExpiresAtUnixSeconds);
        fields[24] = U64(checked(currentEpoch + 1));
        fields[25] = rollover.NextOnionX25519PublicKey;
        fields[26] = U64(request.NotBeforeUnixSeconds);
        fields[27] = U64(request.ExpiresAtUnixSeconds);
        fields[32] = U64(request.IssuedAtUnixSeconds);
        fields[33] = U64(request.NotBeforeUnixSeconds);
        fields[34] = U64(request.ExpiresAtUnixSeconds);
        fields[36] = Placeholder64();
        var provisional = XPointNetworkCodec.Parse<Xnd1Record>(
            XPointNetworkCodec.Write(XPointNetworkRegistry.Xnd1, fields));
        var input = XPointNetworkCrypto.ComputeSigningInput(provisional);
        fields[36] = await SignOperationalAsync(
            request, signer, XPointNetworkOperationalSignaturePurpose.NodeDescriptor,
            previous.Generation + 1, input, cancellationToken).ConfigureAwait(false);
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xnd1, fields);
    }

    private static async ValueTask<byte[]> AuthorViewAsync(
        XPointNetworkOperationalSuccessorRequest request,
        Xnv1Record previous,
        byte[] exactPolicy,
        IReadOnlyList<Xnd1Record> nodes,
        IXPointNetworkWitnessSigner[] witnesses,
        CancellationToken cancellationToken)
    {
        var policy = XPointNetworkCodec.Parse<Xvp1Record>(exactPolicy);
        var fields = Fields(previous, 24);
        fields[1] = U64(checked(previous.Generation + 1));
        fields[2] = previous.CoreHash.ToArray();
        fields[8] = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XVP1, policy.CoreHash.Span);
        fields[10] = U16(checked((ushort)nodes.Count));
        fields[11] = nodes.Select(static node => ArtifactReference(
            ProtocolMagic.XND1, XPointNetworkCrypto.ComputeArtifactHash(node)))
            .SelectMany(static value => value).ToArray();
        fields[18] = U64(request.IssuedAtUnixSeconds);
        fields[19] = U64(request.NotBeforeUnixSeconds);
        fields[20] = U64(request.ExpiresAtUnixSeconds);
        fields[22] = new[] { checked((byte)witnesses.Length) };
        fields[23] = SignatureRows(witnesses.Select(static (signer, index) =>
            (signer.SignerId.ToArray(), Placeholder64(checked((byte)(index + 1))))).ToArray());
        return await SignWitnessRecordAsync(
            request, XPointNetworkRegistry.Xnv1, fields, 23, witnesses,
            XPointNetworkOperationalSignaturePurpose.NetworkView,
            previous.Generation + 1, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<byte[]> AuthorHeadAsync(
        XPointNetworkOperationalSuccessorRequest request,
        Xnh1Record previous,
        byte[] exactView,
        XPointNetworkViewAppendProof proof,
        IXPointNetworkWitnessSigner[] witnesses,
        CancellationToken cancellationToken)
    {
        var view = XPointNetworkCodec.Parse<Xnv1Record>(exactView);
        var fields = Fields(previous, 16);
        fields[1] = U64(checked(previous.Generation + 1));
        fields[2] = previous.CoreHash.ToArray();
        fields[3] = U64(checked(previous.TreeSize + 1));
        fields[4] = proof.Root;
        fields[5] = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, view.CoreHash.Span);
        fields[6] = U64(view.ViewGeneration);
        fields[9] = U64(request.NotBeforeUnixSeconds);
        fields[10] = U64(request.ExpiresAtUnixSeconds);
        fields[12] = new[] { checked((byte)proof.ConsistencyNodes.Count) };
        fields[13] = proof.ConsistencyNodes.SelectMany(static value => value).ToArray();
        fields[14] = new[] { checked((byte)witnesses.Length) };
        fields[15] = SignatureRows(witnesses.Select(static (signer, index) =>
            (signer.SignerId.ToArray(), Placeholder64(checked((byte)(index + 1))))).ToArray());
        return await SignWitnessRecordAsync(
            request, XPointNetworkRegistry.Xnh1, fields, 15, witnesses,
            XPointNetworkOperationalSignaturePurpose.NetworkHead,
            previous.Generation + 1, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<byte[]> AuthorPmaAsync(
        XPointNetworkOperationalSuccessorRequest request,
        ContactRecord previous,
        IXPointNetworkBootstrapRootSigner[] roots,
        CancellationToken cancellationToken)
    {
        var fields = Fields(previous, 16);
        var generation = checked(BinaryPrimitives.ReadUInt64BigEndian(previous.FieldSpan(2)) + 1);
        fields[1] = U64(generation);
        fields[2] = previous.CoreHash.ToArray();
        fields[9] = U64(request.IssuedAtUnixSeconds);
        fields[10] = U64(request.NotBeforeUnixSeconds);
        fields[11] = U64(request.ExpiresAtUnixSeconds);
        fields[14] = new[] { checked((byte)roots.Length) };
        fields[15] = SignatureRows(roots.Select(static signer =>
            (signer.RootKeyId.ToArray(), Placeholder64())).ToArray());
        var provisional = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.PMA2, fields);
        fields[15] = SignatureRows(await SignRootsAsync(
            request, roots, XPointNetworkRootSignaturePurpose.MailboxAuthority,
            generation, provisional.SignatureInput.ToArray(), cancellationToken).ConfigureAwait(false));
        return ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.PMA2, fields).CanonicalBytes.ToArray();
    }

    private static async ValueTask<byte[]> AuthorPmtAsync(
        XPointNetworkOperationalSuccessorRequest request,
        ContactRecord previous,
        byte[] exactPma,
        byte[] exactView,
        IReadOnlyList<Xnd1Record> nodes,
        IXPointNetworkWitnessSigner[] witnesses,
        CancellationToken cancellationToken)
    {
        var pma = ContactCodec.Decode(ProtocolMagic.PMA2, exactPma);
        var view = XPointNetworkCodec.Parse<Xnv1Record>(exactView);
        var generation = checked(BinaryPrimitives.ReadUInt64BigEndian(previous.FieldSpan(2)) + 1);
        var mailboxNodes = nodes.Where(static node => (node.RoleMask & (1 << 2)) != 0).ToArray();
        var fields = Fields(previous, 16);
        fields[1] = U64(generation);
        fields[2] = previous.CoreHash.ToArray();
        fields[3] = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.PMA2, pma.CoreHash.Span);
        fields[4] = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, view.CoreHash.Span);
        // Operational freshness does not itself rotate the seven-day mailbox
        // placement epoch; that is a separate storage-handover ceremony.
        fields[7] = U16(checked((ushort)mailboxNodes.Length));
        fields[8] = mailboxNodes.Select(static node =>
        {
            var origin = node.Origins[0];
            return Join(node.NodeId.ToArray(), U64(node.UInt64(16)), origin.Id.ToArray(),
                origin.CurrentSpki.ToArray(), origin.NextSpki.ToArray());
        }).SelectMany(static value => value).ToArray();
        fields[9] = U64(request.IssuedAtUnixSeconds);
        fields[10] = U64(request.NotBeforeUnixSeconds);
        fields[11] = U64(request.ExpiresAtUnixSeconds);
        fields[12] = new byte[32];
        fields[13] = request.CurrentAdh1CoreReference;
        fields[14] = new[] { checked((byte)witnesses.Length) };
        fields[15] = SignatureRows(witnesses.Select(static (signer, index) =>
            (signer.SignerId.ToArray(), Placeholder64(checked((byte)(index + 1))))).ToArray());
        var provisional = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.PMT2, fields);
        var input = provisional.SignatureInput.ToArray();
        var receipts = new List<(byte[] Id, byte[] Signature)>();
        foreach (var signer in witnesses)
            receipts.Add((signer.SignerId.ToArray(), await SignOperationalAsync(
                request, signer, XPointNetworkOperationalSignaturePurpose.MailboxTopology,
                generation, input, cancellationToken).ConfigureAwait(false)));
        fields[15] = SignatureRows(receipts);
        var authored = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.PMT2, fields);
        if (previous.FieldSpan(13).IndexOfAnyExcept((byte)0) >= 0 &&
            !Fixed(previous.FieldSpan(13), authored.CoreHash.Span))
            throw new CryptographicException("The protected PMT2 forward commitment names a different successor.");
        return authored.CanonicalBytes.ToArray();
    }

    private static async ValueTask<byte[]> SignWitnessRecordAsync(
        XPointNetworkOperationalSuccessorRequest request,
        XPointRecordDefinition definition,
        ReadOnlyMemory<byte>[] fields,
        int signatureIndex,
        IXPointNetworkWitnessSigner[] witnesses,
        XPointNetworkOperationalSignaturePurpose purpose,
        ulong generation,
        CancellationToken cancellationToken)
    {
        var provisional = XPointNetworkCodec.Parse(XPointNetworkCodec.Write(definition, fields));
        var input = XPointNetworkCrypto.ComputeSigningInput(provisional);
        var receipts = new List<(byte[] Id, byte[] Signature)>();
        foreach (var signer in witnesses)
            receipts.Add((signer.SignerId.ToArray(), await SignOperationalAsync(
                request, signer, purpose, generation, input, cancellationToken).ConfigureAwait(false)));
        fields[signatureIndex] = SignatureRows(receipts);
        return XPointNetworkCodec.Write(definition, fields);
    }

    private static async ValueTask<(byte[] Id, byte[] Signature)[]> SignRootsAsync(
        XPointNetworkOperationalSuccessorRequest request,
        IXPointNetworkBootstrapRootSigner[] roots,
        XPointNetworkRootSignaturePurpose purpose,
        ulong generation,
        byte[] input,
        CancellationToken cancellationToken)
    {
        var receipts = new List<(byte[] Id, byte[] Signature)>();
        foreach (var signer in roots)
        {
            var signature = new byte[64];
            var signingRequest = new XPointNetworkRootSigningRequest(
                request.CeremonyId.Span, purpose, request.Bootstrap.Authority.NetworkId.Span,
                generation, signer.RootKeyId.Span, signer.KeyGeneration,
                signer.Ed25519PublicKey.Span, signer.CustodyDomainHash.Span, input);
            try
            {
                var written = await signer.SignAsync(signingRequest, signature, cancellationToken).ConfigureAwait(false);
                ValidateSignature(written, signature, input, signer.Ed25519PublicKey.Span);
                receipts.Add((signer.RootKeyId.ToArray(), signature.ToArray()));
            }
            finally
            {
                signingRequest.Clear();
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        CryptographicOperations.ZeroMemory(input);
        return receipts.ToArray();
    }

    private static async ValueTask<byte[]> SignOperationalAsync(
        XPointNetworkOperationalSuccessorRequest request,
        IXPointNetworkOperationalSigner signer,
        XPointNetworkOperationalSignaturePurpose purpose,
        ulong generation,
        byte[] input,
        CancellationToken cancellationToken)
    {
        var signature = new byte[64];
        var signingRequest = new XPointNetworkOperationalSigningRequest(
            request.CeremonyId.Span, purpose, request.Bootstrap.Authority.NetworkId.Span,
            generation, signer.SignerId.Span, signer.KeyGeneration,
            signer.Ed25519PublicKey.Span, input);
        try
        {
            var written = await signer.SignAsync(signingRequest, signature, cancellationToken).ConfigureAwait(false);
            ValidateSignature(written, signature, input, signer.Ed25519PublicKey.Span);
            return signature.ToArray();
        }
        finally
        {
            signingRequest.Clear();
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static IXPointNetworkBootstrapRootSigner[] ValidateRoots(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<IXPointNetworkBootstrapRootSigner> signers)
    {
        var known = authority.RootKeys.ToDictionary(static value => Convert.ToHexString(value.Id.Span), StringComparer.Ordinal);
        var ordered = signers.OrderBy(static value => value.RootKeyId.ToArray(), ByteArrayComparer.Instance).ToArray();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var signer in ordered)
        {
            var id = Convert.ToHexString(signer.RootKeyId.Span);
            if (!seen.Add(id) || !known.TryGetValue(id, out var key) ||
                signer.KeyGeneration != key.Generation ||
                !Fixed(signer.Ed25519PublicKey.Span, key.Ed25519PublicKey.Span))
                throw new CryptographicException("A renewal root signer is unknown or duplicated.");
        }
        if (ordered.Length < authority.RootThreshold)
            throw new CryptographicException("The renewal root signer threshold is incomplete.");
        return ordered;
    }

    private static IXPointNetworkWitnessSigner[] ValidateWitnesses(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<IXPointNetworkWitnessSigner> signers)
    {
        var known = authority.WitnessKeys.ToDictionary(static value => Convert.ToHexString(value.Id.Span), StringComparer.Ordinal);
        var ordered = signers.OrderBy(static value => value.SignerId.ToArray(), ByteArrayComparer.Instance).ToArray();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        foreach (var signer in ordered)
        {
            var id = Convert.ToHexString(signer.SignerId.Span);
            if (!ids.Add(id) || !known.TryGetValue(id, out var key) ||
                signer.KeyGeneration != key.Generation ||
                !Fixed(signer.Ed25519PublicKey.Span, key.Ed25519PublicKey.Span) ||
                !Fixed(signer.FailureDomainHash.Span, key.FailureDomainHash.Span) ||
                !domains.Add(Convert.ToHexString(signer.FailureDomainHash.Span)))
                throw new CryptographicException("A renewal witness is unknown, duplicated, or shares a failure domain.");
        }
        if (ordered.Length < authority.WitnessThreshold)
            throw new CryptographicException("The renewal witness threshold is incomplete.");
        return ordered;
    }

    private static XPointNetworkOperationalNodeRollover[] ValidateNodeRollovers(
        IReadOnlyList<Xnd1Record> nodes,
        IReadOnlyList<XPointNetworkOperationalNodeRollover> rollovers)
    {
        var byId = new Dictionary<string, XPointNetworkOperationalNodeRollover>(StringComparer.Ordinal);
        foreach (var rollover in rollovers)
            if (!byId.TryAdd(Convert.ToHexString(rollover.IdentitySigner.SignerId.Span), rollover))
                throw new CryptographicException("The renewal node identity signer set is duplicated.");
        if (byId.Count != nodes.Count)
            throw new CryptographicException("The renewal node identity signer set is incomplete.");
        var trafficKeys = new HashSet<string>(StringComparer.Ordinal);
        var originPins = new HashSet<string>(StringComparer.Ordinal);
        return nodes.Select(node =>
        {
            if (!byId.TryGetValue(Convert.ToHexString(node.NodeId.Span), out var rollover) ||
                !Fixed(rollover.IdentitySigner.Ed25519PublicKey.Span, node.IdentityPublicKey.Span))
                throw new CryptographicException("A renewal node signer changes a registered node identity.");
            var currentOnion = rollover.CurrentOnionX25519PublicKey.Span;
            var nextOnion = rollover.NextOnionX25519PublicKey.Span;
            if (Fixed(currentOnion, node.FieldSpan(22)) || Fixed(currentOnion, node.FieldSpan(26)) ||
                Fixed(nextOnion, node.FieldSpan(22)) || Fixed(nextOnion, node.FieldSpan(26)) ||
                !trafficKeys.Add(Convert.ToHexString(currentOnion)) ||
                !trafficKeys.Add(Convert.ToHexString(nextOnion)))
                throw new CryptographicException("Renewal onion traffic keys must be fresh and unique across nodes.");
            var currentSpki = rollover.CurrentOriginSpkiSha256.ToArray();
            var nextSpki = rollover.NextOriginSpkiSha256.ToArray();
            if (node.Origins.Any(origin =>
                    Fixed(currentSpki, origin.CurrentSpki.Span) || Fixed(currentSpki, origin.NextSpki.Span) ||
                    Fixed(nextSpki, origin.CurrentSpki.Span) || Fixed(nextSpki, origin.NextSpki.Span)) ||
                !originPins.Add(Convert.ToHexString(currentSpki)) ||
                !originPins.Add(Convert.ToHexString(nextSpki)))
                throw new CryptographicException("Renewal origin SPKI pins must be fresh and unique across nodes.");
            return rollover;
        }).ToArray();
    }

    private static ReadOnlyMemory<byte>[] Fields(XPointParsedRecord record, int count) =>
        Enumerable.Range(1, count).Select(tag => (ReadOnlyMemory<byte>)record.FieldSpan(tag).ToArray()).ToArray();

    private static ReadOnlyMemory<byte>[] Fields(ContactRecord record, int count) =>
        Enumerable.Range(1, count).Select(tag => (ReadOnlyMemory<byte>)record.FieldSpan(tag).ToArray()).ToArray();

    private static void ValidateSignature(int written, ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> input, ReadOnlySpan<byte> publicKey)
    {
        if (written != 64 || signature.IndexOfAnyExcept((byte)0) < 0 ||
            !PublicKeyAuth.VerifyDetached(signature.ToArray(), input.ToArray(), publicKey.ToArray()))
            throw new CryptographicException("An operational successor signer returned an invalid signature.");
    }

    private static byte[] SignatureRows(IReadOnlyList<(byte[] Id, byte[] Signature)> rows) =>
        Join(rows.OrderBy(static value => value.Id, ByteArrayComparer.Instance)
            .Select(static value => Join(value.Id, value.Signature)).ToArray());

    private static byte[] ArtifactReference(string magic, ReadOnlySpan<byte> hash)
    {
        var bytes = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        hash.CopyTo(bytes.AsSpan(6));
        return bytes;
    }

    private static byte[] Placeholder64(byte discriminator = 1)
    {
        var value = new byte[64];
        value[0] = discriminator;
        return value;
    }

    private static byte[] Join(params byte[][] values)
    {
        var result = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(result, offset);
            offset += value.Length;
        }
        return result;
    }

    private static byte[] U16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
