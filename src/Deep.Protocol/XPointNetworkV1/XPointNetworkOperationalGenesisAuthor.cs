using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

public enum XPointNetworkOperationalSignaturePurpose : byte
{
    NodeDescriptor = 1,
    NetworkView = 2,
    NetworkHead = 3,
    DirectoryHead = 4,
    MailboxTopology = 5,
}

/// <summary>
/// Short-lived, purpose-bound signing request for an online XPoint witness or an
/// existing node identity. The author validates the returned signature against
/// the public key named by the immutable request.
/// </summary>
public sealed class XPointNetworkOperationalSigningRequest
{
    private readonly byte[] ceremonyId;
    private readonly byte[] networkId;
    private readonly byte[] signerId;
    private readonly byte[] expectedPublicKey;
    private readonly byte[] signingInput;
    private readonly byte[] signingInputHash;

    internal XPointNetworkOperationalSigningRequest(
        ReadOnlySpan<byte> ceremonyId,
        XPointNetworkOperationalSignaturePurpose purpose,
        ReadOnlySpan<byte> networkId,
        ulong generation,
        ReadOnlySpan<byte> signerId,
        ulong keyGeneration,
        ReadOnlySpan<byte> expectedPublicKey,
        ReadOnlySpan<byte> signingInput)
    {
        this.ceremonyId = ceremonyId.ToArray();
        Purpose = purpose;
        this.networkId = networkId.ToArray();
        Generation = generation;
        this.signerId = signerId.ToArray();
        KeyGeneration = keyGeneration;
        this.expectedPublicKey = expectedPublicKey.ToArray();
        this.signingInput = signingInput.ToArray();
        signingInputHash = SHA256.HashData(signingInput);
    }

    public ReadOnlyMemory<byte> CeremonyId => ceremonyId.ToArray();
    public XPointNetworkOperationalSignaturePurpose Purpose { get; }
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong Generation { get; }
    public ReadOnlyMemory<byte> SignerId => signerId.ToArray();
    public ulong KeyGeneration { get; }
    public ReadOnlyMemory<byte> ExpectedEd25519PublicKey => expectedPublicKey.ToArray();
    public ReadOnlyMemory<byte> SigningInput => signingInput;
    public ReadOnlyMemory<byte> SigningInputSha256 => signingInputHash;

    internal void Clear()
    {
        CryptographicOperations.ZeroMemory(signingInput);
        CryptographicOperations.ZeroMemory(signingInputHash);
    }
}

public interface IXPointNetworkOperationalSigner
{
    ReadOnlyMemory<byte> SignerId { get; }
    ulong KeyGeneration { get; }
    ReadOnlyMemory<byte> Ed25519PublicKey { get; }

    ValueTask<int> SignAsync(
        XPointNetworkOperationalSigningRequest request,
        Memory<byte> signature64,
        CancellationToken cancellationToken);
}

public interface IXPointNetworkWitnessSigner :
    IXPointNetworkOperationalSigner,
    IAccountDirectoryDtt1WitnessSigner
{
    ReadOnlyMemory<byte> FailureDomainHash { get; }
}

public sealed class XPointNetworkOperationalNode
{
    private readonly byte[] stakingIdentityHash;
    private readonly byte[] operatorId;
    private readonly byte[] hostId;
    private readonly byte[] providerId;
    private readonly byte[] originId;
    private readonly byte[] originAddress;
    private readonly byte[] currentOriginSpkiSha256;
    private readonly byte[] nextOriginSpkiSha256;
    private readonly byte[] currentOnionX25519PublicKey;
    private readonly byte[] nextOnionX25519PublicKey;
    private readonly byte[][] roleEd25519PublicKeys;

    public XPointNetworkOperationalNode(
        IXPointNetworkOperationalSigner identitySigner,
        ReadOnlySpan<byte> stakingIdentityHash,
        ReadOnlySpan<byte> operatorId,
        ReadOnlySpan<byte> hostId,
        ReadOnlySpan<byte> providerId,
        uint asn,
        ushort jurisdiction,
        ReadOnlySpan<byte> originId,
        IPAddress originAddress,
        ushort originPort,
        ReadOnlySpan<byte> currentOriginSpkiSha256,
        ReadOnlySpan<byte> nextOriginSpkiSha256,
        ReadOnlySpan<byte> currentOnionX25519PublicKey,
        ReadOnlySpan<byte> nextOnionX25519PublicKey,
        IReadOnlyList<ReadOnlyMemory<byte>> roleEd25519PublicKeys,
        ushort roleMask = 0x001f)
    {
        IdentitySigner = identitySigner ?? throw new ArgumentNullException(nameof(identitySigner));
        this.stakingIdentityHash = Required(stakingIdentityHash, 32, nameof(stakingIdentityHash));
        this.operatorId = Required(operatorId, 32, nameof(operatorId));
        this.hostId = Required(hostId, 32, nameof(hostId));
        this.providerId = Required(providerId, 32, nameof(providerId));
        Asn = asn;
        Jurisdiction = jurisdiction;
        this.originId = Required(originId, 32, nameof(originId));
        ArgumentNullException.ThrowIfNull(originAddress);
        OriginAddressFamily = originAddress.AddressFamily switch
        {
            System.Net.Sockets.AddressFamily.InterNetwork => (byte)4,
            System.Net.Sockets.AddressFamily.InterNetworkV6 => (byte)6,
            _ => throw new ArgumentException("The node origin must be IPv4 or IPv6.", nameof(originAddress)),
        };
        var addressBytes = originAddress.GetAddressBytes();
        this.originAddress = new byte[16];
        addressBytes.CopyTo(this.originAddress, 0);
        if (originPort == 0) throw new ArgumentOutOfRangeException(nameof(originPort));
        OriginPort = originPort;
        this.currentOriginSpkiSha256 = Required(currentOriginSpkiSha256, 32, nameof(currentOriginSpkiSha256));
        this.nextOriginSpkiSha256 = Required(nextOriginSpkiSha256, 32, nameof(nextOriginSpkiSha256));
        if (this.currentOriginSpkiSha256.AsSpan().SequenceEqual(this.nextOriginSpkiSha256))
            throw new ArgumentException("Current and next origin SPKI pins must differ.");
        this.currentOnionX25519PublicKey = Required(currentOnionX25519PublicKey, 32, nameof(currentOnionX25519PublicKey));
        this.nextOnionX25519PublicKey = Required(nextOnionX25519PublicKey, 32, nameof(nextOnionX25519PublicKey));
        if (this.currentOnionX25519PublicKey.AsSpan().SequenceEqual(this.nextOnionX25519PublicKey))
            throw new ArgumentException("Current and next onion public keys must differ.");
        if (roleMask != 0x001f)
            throw new ArgumentOutOfRangeException(nameof(roleMask), "The first-release profile requires every frozen role.");
        ArgumentNullException.ThrowIfNull(roleEd25519PublicKeys);
        if (roleEd25519PublicKeys.Count != 5)
            throw new ArgumentException("The first-release profile requires five role public keys.", nameof(roleEd25519PublicKeys));
        this.roleEd25519PublicKeys = roleEd25519PublicKeys
            .Select((value, index) => Required(value.Span, 32, $"{nameof(roleEd25519PublicKeys)}[{index}]"))
            .ToArray();
        if (this.roleEd25519PublicKeys.Select(Convert.ToHexString).Distinct(StringComparer.Ordinal).Count() != 5)
            throw new ArgumentException("Node role public keys must be distinct.", nameof(roleEd25519PublicKeys));
        RoleMask = roleMask;
    }

    public IXPointNetworkOperationalSigner IdentitySigner { get; }
    public ReadOnlyMemory<byte> StakingIdentityHash => stakingIdentityHash.ToArray();
    public ReadOnlyMemory<byte> OperatorId => operatorId.ToArray();
    public ReadOnlyMemory<byte> HostId => hostId.ToArray();
    public ReadOnlyMemory<byte> ProviderId => providerId.ToArray();
    public uint Asn { get; }
    public ushort Jurisdiction { get; }
    public ReadOnlyMemory<byte> OriginId => originId.ToArray();
    public byte OriginAddressFamily { get; }
    public ReadOnlyMemory<byte> OriginAddress => originAddress.ToArray();
    public ushort OriginPort { get; }
    public ReadOnlyMemory<byte> CurrentOriginSpkiSha256 => currentOriginSpkiSha256.ToArray();
    public ReadOnlyMemory<byte> NextOriginSpkiSha256 => nextOriginSpkiSha256.ToArray();
    public ReadOnlyMemory<byte> CurrentOnionX25519PublicKey => currentOnionX25519PublicKey.ToArray();
    public ReadOnlyMemory<byte> NextOnionX25519PublicKey => nextOnionX25519PublicKey.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> RoleEd25519PublicKeys =>
        Array.AsReadOnly(roleEd25519PublicKeys.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    public ushort RoleMask { get; }

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }
}

public sealed class XPointNetworkOperationalGenesisRequest
{
    private readonly byte[] ceremonyId;
    private readonly byte[] directoryQueryLeafKey;
    private readonly byte[] xcc1CoreCommitment;
    private readonly byte[] xcb1ArtifactCommitment;
    private readonly byte[] pma2ArtifactCommitment;

    public XPointNetworkOperationalGenesisRequest(
        ReadOnlySpan<byte> ceremonyId,
        VerifiedXPointNetworkBootstrap bootstrap,
        IReadOnlyList<IXPointNetworkBootstrapRootSigner> rootSigners,
        IReadOnlyList<IXPointNetworkWitnessSigner> witnessSigners,
        IReadOnlyList<XPointNetworkOperationalNode> nodes,
        ReadOnlySpan<byte> directoryQueryLeafKey,
        ReadOnlySpan<byte> xcc1CoreCommitment,
        ReadOnlySpan<byte> xcb1ArtifactCommitment,
        ReadOnlySpan<byte> pma2ArtifactCommitment,
        ulong issuedAtUnixSeconds,
        ulong notBeforeUnixSeconds,
        ulong expiresAtUnixSeconds,
        ReadOnlySpan<byte> snapshotNonce,
        ReadOnlySpan<byte> snapshotBootId,
        ulong snapshotNonceCreatedAtMonotonicSeconds,
        ulong snapshotResponseReceivedAtMonotonicSeconds,
        ulong snapshotCurrentMonotonicSeconds,
        ulong observedUnixTime,
        uint uncertaintySeconds,
        ushort minimumReader = 1)
    {
        this.ceremonyId = Required(ceremonyId, 32, nameof(ceremonyId));
        Bootstrap = bootstrap ?? throw new ArgumentNullException(nameof(bootstrap));
        ArgumentNullException.ThrowIfNull(rootSigners);
        RootSigners = rootSigners.ToArray();
        ArgumentNullException.ThrowIfNull(witnessSigners);
        WitnessSigners = witnessSigners.ToArray();
        ArgumentNullException.ThrowIfNull(nodes);
        Nodes = nodes.ToArray();
        this.directoryQueryLeafKey = Required(directoryQueryLeafKey, 32, nameof(directoryQueryLeafKey));
        this.xcc1CoreCommitment = Required(xcc1CoreCommitment, 32, nameof(xcc1CoreCommitment));
        this.xcb1ArtifactCommitment = Required(xcb1ArtifactCommitment, 32, nameof(xcb1ArtifactCommitment));
        this.pma2ArtifactCommitment = Required(pma2ArtifactCommitment, 32, nameof(pma2ArtifactCommitment));
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        NotBeforeUnixSeconds = notBeforeUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
        SnapshotNonce = Required(snapshotNonce, 32, nameof(snapshotNonce));
        SnapshotBootId = Required(snapshotBootId, 16, nameof(snapshotBootId));
        SnapshotNonceCreatedAtMonotonicSeconds = snapshotNonceCreatedAtMonotonicSeconds;
        SnapshotResponseReceivedAtMonotonicSeconds = snapshotResponseReceivedAtMonotonicSeconds;
        SnapshotCurrentMonotonicSeconds = snapshotCurrentMonotonicSeconds;
        ObservedUnixTime = observedUnixTime;
        UncertaintySeconds = uncertaintySeconds;
        MinimumReader = minimumReader;

        if (RootSigners.Count == 0 || WitnessSigners.Count is < 2 or > 32 || Nodes.Count is < 3 or > 512)
            throw new ArgumentException("The operational genesis signer or node set is outside its frozen bounds.");
        if (issuedAtUnixSeconds == 0 || issuedAtUnixSeconds > notBeforeUnixSeconds ||
            notBeforeUnixSeconds >= expiresAtUnixSeconds || expiresAtUnixSeconds - notBeforeUnixSeconds > 86_400)
            throw new ArgumentException("The operational genesis interval must be non-empty and at most 24 hours.");
        if (uncertaintySeconds is < 1 or > 30 || observedUnixTime <= uncertaintySeconds ||
            observedUnixTime + uncertaintySeconds >= expiresAtUnixSeconds ||
            observedUnixTime - uncertaintySeconds < notBeforeUnixSeconds)
            throw new ArgumentException("The authenticated time interval is outside the operational genesis interval.");
        if (snapshotNonceCreatedAtMonotonicSeconds > snapshotResponseReceivedAtMonotonicSeconds ||
            snapshotResponseReceivedAtMonotonicSeconds > snapshotCurrentMonotonicSeconds ||
            snapshotResponseReceivedAtMonotonicSeconds - snapshotNonceCreatedAtMonotonicSeconds >
            AccountDirectoryCurrentProofVerifier.MaximumNonceRoundTripSeconds)
            throw new ArgumentException("The snapshot monotonic window is invalid.");
        if (minimumReader == 0) throw new ArgumentOutOfRangeException(nameof(minimumReader));
    }

    public ReadOnlyMemory<byte> CeremonyId => ceremonyId.ToArray();
    public VerifiedXPointNetworkBootstrap Bootstrap { get; }
    public IReadOnlyList<IXPointNetworkBootstrapRootSigner> RootSigners { get; }
    public IReadOnlyList<IXPointNetworkWitnessSigner> WitnessSigners { get; }
    public IReadOnlyList<XPointNetworkOperationalNode> Nodes { get; }
    public ReadOnlyMemory<byte> DirectoryQueryLeafKey => directoryQueryLeafKey.ToArray();
    public ReadOnlyMemory<byte> Xcc1CoreCommitment => xcc1CoreCommitment.ToArray();
    public ReadOnlyMemory<byte> Xcb1ArtifactCommitment => xcb1ArtifactCommitment.ToArray();
    public ReadOnlyMemory<byte> Pma2ArtifactCommitment => pma2ArtifactCommitment.ToArray();
    public ulong IssuedAtUnixSeconds { get; }
    public ulong NotBeforeUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> SnapshotNonce { get; }
    public ReadOnlyMemory<byte> SnapshotBootId { get; }
    public ulong SnapshotNonceCreatedAtMonotonicSeconds { get; }
    public ulong SnapshotResponseReceivedAtMonotonicSeconds { get; }
    public ulong SnapshotCurrentMonotonicSeconds { get; }
    public ulong ObservedUnixTime { get; }
    public uint UncertaintySeconds { get; }
    public ushort MinimumReader { get; }

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }
}

public sealed class AuthoredXPointNetworkOperationalGenesis
{
    internal AuthoredXPointNetworkOperationalGenesis(
        XPointNetworkOperationalGenesisRequest request,
        byte[] xvp1,
        byte[][] xnd1,
        byte[] xnv1,
        byte[] xnh1,
        byte[] adh1,
        byte[] dtt1,
        byte[] adp1,
        byte[] pmt2,
        VerifiedOnionNetworkContext verifiedNetwork)
    {
        Request = request;
        ExactXvp1 = xvp1.ToArray();
        ExactXnd1 = Array.AsReadOnly(xnd1.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
        ExactXnv1 = xnv1.ToArray();
        ExactXnh1 = xnh1.ToArray();
        ExactAdh1 = adh1.ToArray();
        ExactDtt1 = dtt1.ToArray();
        ExactAdp1 = adp1.ToArray();
        ExactPmt2 = pmt2.ToArray();
        VerifiedNetwork = verifiedNetwork;
    }

    public XPointNetworkOperationalGenesisRequest Request { get; }
    public ReadOnlyMemory<byte> ExactXna1 => Request.Bootstrap.ExactXna1;
    public ReadOnlyMemory<byte> ExactDts1 => Request.Bootstrap.ExactDts1;
    public ReadOnlyMemory<byte> ExactXvp1 { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactXnd1 { get; }
    public ReadOnlyMemory<byte> ExactXnv1 { get; }
    public ReadOnlyMemory<byte> ExactXnh1 { get; }
    public ReadOnlyMemory<byte> ExactAdh1 { get; }
    public ReadOnlyMemory<byte> ExactDtt1 { get; }
    public ReadOnlyMemory<byte> ExactAdp1 { get; }
    public ReadOnlyMemory<byte> ExactPmt2 { get; }
    public VerifiedOnionNetworkContext VerifiedNetwork { get; }
}

/// <summary>
/// Authors and immediately verifies the complete first-release generation-zero
/// XPoint/directory closure. It accepts no raw signatures and never owns private
/// key material.
/// </summary>
public static class XPointNetworkOperationalGenesisAuthor
{
    public static async ValueTask<AuthoredXPointNetworkOperationalGenesis> AuthorAsync(
        XPointNetworkOperationalGenesisRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var authority = request.Bootstrap.Authority;
        var network = authority.NetworkId.ToArray();
        var witnesses = ValidateWitnesses(authority, request.WitnessSigners);
        var nodes = ValidateNodes(network, request.Nodes);

        var xvp = await AuthorPolicyAsync(request, authority, cancellationToken).ConfigureAwait(false);
        var xnd = new byte[nodes.Length][];
        for (var index = 0; index < nodes.Length; index++)
            xnd[index] = await AuthorNodeAsync(request, nodes[index], cancellationToken).ConfigureAwait(false);
        Array.Sort(xnd, static (left, right) =>
            XPointNetworkCodec.Parse<Xnd1Record>(left).NodeId.Span.SequenceCompareTo(
                XPointNetworkCodec.Parse<Xnd1Record>(right).NodeId.Span));

        var xnv = await AuthorViewAsync(request, authority, xvp, xnd, witnesses, cancellationToken)
            .ConfigureAwait(false);
        var xnh = await AuthorHeadAsync(request, authority, xnv, witnesses, cancellationToken)
            .ConfigureAwait(false);
        var adh = await AuthorDirectoryHeadAsync(request, authority, witnesses, cancellationToken)
            .ConfigureAwait(false);

        var adhRecord = AccountDirectoryAdh1Codec.Decode(adh);
        var adhHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(adhRecord);
        var protectedHead = AccountDirectoryProtectedLkgFactory.Restore(authority, adh, adhHash);
        var proof = AccountDirectoryAdp1ProofMaterial.NonMembership(
            request.DirectoryQueryLeafKey.Span,
            callerProtectedLkg: null,
            consistencyProofNodes: [],
            exactAfp1: ReadOnlyMemory<byte>.Empty,
            sparseMapBitmap: new byte[32],
            sparseMapSiblings: []);
        var issuanceEpoch = AccountDirectoryDtt1IssuanceEpoch.Derive(
            authority, request.ObservedUnixTime, request.UncertaintySeconds);
        var proofRequest = new AccountDirectoryProofAuthoringRequest(
            network,
            request.SnapshotNonce.Span,
            request.SnapshotBootId.Span,
            request.SnapshotNonceCreatedAtMonotonicSeconds,
            adh,
            xnv,
            request.ObservedUnixTime,
            request.UncertaintySeconds,
            request.ObservedUnixTime - request.UncertaintySeconds,
            checked(request.ObservedUnixTime + request.UncertaintySeconds +
                AccountDirectoryCurrentProofVerifier.MaximumNonceRoundTripSeconds),
            issuanceEpoch,
            request.MinimumReader);
        var authoredProof = await AccountDirectoryProofAuthor.IssueAsync(
            authority,
            protectedHead,
            proofRequest,
            proof,
            witnesses.Cast<IAccountDirectoryDtt1WitnessSigner>().ToArray(),
            cancellationToken).ConfigureAwait(false);
        var monotonic = new AccountDirectoryMonotonicRequestWindow(
            request.SnapshotBootId.Span,
            request.SnapshotNonceCreatedAtMonotonicSeconds,
            request.SnapshotResponseReceivedAtMonotonicSeconds,
            request.SnapshotCurrentMonotonicSeconds);
        var freshness = AccountDirectoryCurrentProofVerifier.Verify(
            authority,
            adh,
            authoredProof.ExactDtt1,
            authoredProof.ExactAdp1,
            request.SnapshotNonce.Span,
            request.DirectoryQueryLeafKey.Span,
            monotonic,
            protectedLkg: null,
            currentCheckpoint: null,
            request.MinimumReader);
        var pmt = await AuthorMailboxTopologyAsync(
            request, authority, xnv, xnd, freshness, witnesses, cancellationToken)
            .ConfigureAwait(false);
        var verified = await OnionNetworkContextVerifier.VerifyAsync(
            authority,
            freshness,
            [xvp],
            [xnv],
            [xnh],
            xnd.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
            [pmt],
            protectedPrevious: null,
            new OnionTrustedTimeAuthority(new FixedMonotonicClock(
                request.SnapshotBootId.Span,
                request.SnapshotCurrentMonotonicSeconds)),
            cancellationToken).ConfigureAwait(false);
        verified.EnsureCurrent();
        return new AuthoredXPointNetworkOperationalGenesis(
            request,
            xvp,
            xnd,
            xnv,
            xnh,
            adh,
            authoredProof.ExactDtt1.ToArray(),
            authoredProof.ExactAdp1.ToArray(),
            pmt,
            verified);
    }

    private static async ValueTask<byte[]> AuthorPolicyAsync(
        XPointNetworkOperationalGenesisRequest request,
        VerifiedXPointNetworkAuthority authority,
        CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte>[] fields =
        [
            authority.NetworkId.ToArray(), U64(0), new byte[32], U16(0x001f),
            new byte[] { 3 }, new byte[] { 2 }, U16(0x000f), new byte[] { 3 },
            U32(2_592_000), U16(600), U16(1), U64(0),
            XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XCC1, request.Xcc1CoreCommitment.Span),
            U16(1), U64(request.IssuedAtUnixSeconds), U64(request.NotBeforeUnixSeconds),
            U64(request.ExpiresAtUnixSeconds), authority.AuthorityCoreReference,
            new byte[] { checked((byte)request.RootSigners.Count) },
            SignatureRows(request.RootSigners.Select(static signer =>
                (signer.RootKeyId.ToArray(), Placeholder64())).ToArray()),
        ];
        var provisional = XPointNetworkCodec.Parse<Xvp1Record>(
            XPointNetworkCodec.Write(XPointNetworkRegistry.Xvp1, fields));
        var input = XPointNetworkCrypto.ComputeSigningInput(provisional);
        var receipts = new List<(byte[] Id, byte[] Signature)>();
        foreach (var signer in request.RootSigners)
        {
            var signature = new byte[64];
            var signingRequest = new XPointNetworkRootSigningRequest(
                request.CeremonyId.Span,
                XPointNetworkRootSignaturePurpose.NetworkPolicy,
                authority.NetworkId.Span,
                0,
                signer.RootKeyId.Span,
                signer.KeyGeneration,
                signer.Ed25519PublicKey.Span,
                signer.CustodyDomainHash.Span,
                input);
            try
            {
                var written = await signer.SignAsync(signingRequest, signature, cancellationToken)
                    .ConfigureAwait(false);
                ValidateSignature(written, signature, input, signer.Ed25519PublicKey.Span);
                receipts.Add((signer.RootKeyId.ToArray(), signature.ToArray()));
            }
            finally
            {
                signingRequest.Clear();
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        fields[19] = SignatureRows(receipts.ToArray());
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xvp1, fields);
    }

    private static async ValueTask<byte[]> AuthorNodeAsync(
        XPointNetworkOperationalGenesisRequest request,
        XPointNetworkOperationalNode node,
        CancellationToken cancellationToken)
    {
        var signer = node.IdentitySigner;
        var nodeId = signer.SignerId.ToArray();
        var publicKey = signer.Ed25519PublicKey.ToArray();
        if (!nodeId.AsSpan().SequenceEqual(publicKey) || signer.KeyGeneration != 0)
            throw new CryptographicException("A genesis node ID must equal its generation-zero Ed25519 identity key.");
        var failureDomain = XPointNetworkCrypto.Sha256Domain(
            XPointNetworkRegistry.FailureDomainDomain,
            Join(request.Bootstrap.Authority.NetworkId.ToArray(), node.OperatorId.ToArray(),
                node.HostId.ToArray(), node.ProviderId.ToArray(), U32(node.Asn), U16(node.Jurisdiction)));
        var origin = Join(
            node.OriginId.ToArray(), [1], [node.OriginAddressFamily], node.OriginAddress.ToArray(), U16(node.OriginPort),
            node.CurrentOriginSpkiSha256.ToArray(), U64(request.NotBeforeUnixSeconds), U64(request.ExpiresAtUnixSeconds),
            node.NextOriginSpkiSha256.ToArray(), U64(request.NotBeforeUnixSeconds), U64(request.ExpiresAtUnixSeconds));
        var roleRows = Join(Enumerable.Range(0, 5).Select(role =>
            Join([checked((byte)role)], U64(0), node.RoleEd25519PublicKeys[role].ToArray())).ToArray());
        ReadOnlyMemory<byte>[] fields = new ReadOnlyMemory<byte>[37];
        fields[0] = request.Bootstrap.Authority.NetworkId.ToArray();
        fields[1] = nodeId;
        fields[2] = U64(0);
        fields[3] = new byte[32];
        fields[4] = publicKey;
        fields[5] = node.StakingIdentityHash;
        fields[6] = node.OperatorId;
        fields[7] = node.HostId;
        fields[8] = node.ProviderId;
        fields[9] = U32(node.Asn);
        fields[10] = U16(node.Jurisdiction);
        fields[11] = failureDomain;
        fields[12] = U16(node.RoleMask);
        fields[13] = U32(100_000);
        fields[14] = U64(1_000_000_000);
        fields[15] = U64(100UL * 1024 * 1024 * 1024);
        fields[16] = U64(100UL * 1024 * 1024 * 1024);
        fields[17] = U32(10_000);
        fields[18] = new byte[] { 1 };
        fields[19] = origin;
        fields[20] = U64(1);
        fields[21] = node.CurrentOnionX25519PublicKey;
        fields[22] = U64(request.NotBeforeUnixSeconds);
        fields[23] = U64(request.ExpiresAtUnixSeconds);
        fields[24] = U64(2);
        fields[25] = node.NextOnionX25519PublicKey;
        fields[26] = U64(request.NotBeforeUnixSeconds);
        fields[27] = U64(request.ExpiresAtUnixSeconds);
        fields[28] = U16(1);
        fields[29] = U16(1);
        fields[30] = new byte[] { 5 };
        fields[31] = roleRows;
        fields[32] = U64(request.IssuedAtUnixSeconds);
        fields[33] = U64(request.NotBeforeUnixSeconds);
        fields[34] = U64(request.ExpiresAtUnixSeconds);
        fields[35] = U16(request.MinimumReader);
        fields[36] = Placeholder64();
        return await SignOperationalRecordAsync(
            request,
            XPointNetworkRegistry.Xnd1,
            fields,
            36,
            signer,
            XPointNetworkOperationalSignaturePurpose.NodeDescriptor,
            generation: 0,
            cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<byte[]> AuthorViewAsync(
        XPointNetworkOperationalGenesisRequest request,
        VerifiedXPointNetworkAuthority authority,
        byte[] exactXvp1,
        byte[][] exactXnd1,
        IXPointNetworkWitnessSigner[] witnesses,
        CancellationToken cancellationToken)
    {
        var policy = XPointNetworkCodec.Parse<Xvp1Record>(exactXvp1);
        var nodes = exactXnd1.Select(static value => XPointNetworkCodec.Parse<Xnd1Record>(value))
            .OrderBy(static value => value.NodeId.ToArray(), ByteArrayComparer.Instance).ToArray();
        ReadOnlyMemory<byte>[] fields =
        [
            authority.NetworkId.ToArray(), U64(0), new byte[32],
            HashDomain("Deep/XPoint/V1/first-release/finalized-chain", authority.NetworkId.Span),
            U64(1), HashDomain("Deep/XPoint/V1/first-release/finalized-block", authority.NetworkId.Span),
            authority.AuthorityCoreReference, authority.DirectoryWitnessPolicyHash,
            XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XVP1, policy.CoreHash.Span),
            U16(1), U16(checked((ushort)nodes.Length)),
            Join(nodes.Select(static value => ArtifactReference(
                ProtocolMagic.XND1, XPointNetworkCrypto.ComputeArtifactHash(value))).ToArray()),
            U16(0), Array.Empty<byte>(), U16(0), Array.Empty<byte>(), U16(1),
            ArtifactReference(ProtocolMagic.XCB1, request.Xcb1ArtifactCommitment.Span),
            U64(request.IssuedAtUnixSeconds), U64(request.NotBeforeUnixSeconds), U64(request.ExpiresAtUnixSeconds),
            U16(request.MinimumReader), new byte[] { checked((byte)witnesses.Length) },
            SignatureRows(witnesses.Select(static (signer, index) =>
                (signer.SignerId.ToArray(), Placeholder64(checked((byte)(index + 1))))).ToArray()),
        ];
        return await SignWitnessRecordAsync(
            request, XPointNetworkRegistry.Xnv1, fields, 23, witnesses,
            XPointNetworkOperationalSignaturePurpose.NetworkView, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<byte[]> AuthorHeadAsync(
        XPointNetworkOperationalGenesisRequest request,
        VerifiedXPointNetworkAuthority authority,
        byte[] exactXnv1,
        IXPointNetworkWitnessSigner[] witnesses,
        CancellationToken cancellationToken)
    {
        var view = XPointNetworkCodec.Parse<Xnv1Record>(exactXnv1);
        Span<byte> leafPayload = stackalloc byte[72];
        BinaryPrimitives.WriteUInt64BigEndian(leafPayload, view.ViewGeneration);
        view.FieldSpan(3).CopyTo(leafPayload[8..40]);
        view.CoreHash.Span.CopyTo(leafPayload[40..]);
        var root = XPointNetworkCrypto.Rfc6962Leaf(leafPayload);
        ReadOnlyMemory<byte>[] fields =
        [
            authority.NetworkId.ToArray(), U64(0), new byte[32], U64(1), root,
            XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, view.CoreHash.Span), U64(0),
            authority.AuthorityCoreReference, authority.DirectoryWitnessPolicyHash,
            U64(request.NotBeforeUnixSeconds), U64(request.ExpiresAtUnixSeconds), U16(request.MinimumReader),
            new byte[] { 0 }, Array.Empty<byte>(),
            new byte[] { checked((byte)witnesses.Length) },
            SignatureRows(witnesses.Select(static (signer, index) =>
                (signer.SignerId.ToArray(), Placeholder64(checked((byte)(index + 1))))).ToArray()),
        ];
        return await SignWitnessRecordAsync(
            request, XPointNetworkRegistry.Xnh1, fields, 15, witnesses,
            XPointNetworkOperationalSignaturePurpose.NetworkHead, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<byte[]> AuthorDirectoryHeadAsync(
        XPointNetworkOperationalGenesisRequest request,
        VerifiedXPointNetworkAuthority authority,
        IXPointNetworkWitnessSigner[] witnesses,
        CancellationToken cancellationToken)
    {
        var placeholder = witnesses.Select(static (signer, index) => new AccountDirectoryAdh1WitnessEntry(
            signer.SignerId.Span, Placeholder64(checked((byte)(index + 1)))))
            .ToArray();
        var unsigned = new AccountDirectoryAdh1(
            authority.NetworkId.Span, 0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.Span,
            authority.AuthorityCoreReference.Span, authority.DirectoryWitnessPolicyHash.Span,
            request.NotBeforeUnixSeconds, request.ExpiresAtUnixSeconds, request.MinimumReader, placeholder);
        var input = AccountDirectoryCrypto.ComputeAdh1SigningInput(unsigned);
        var receipts = new List<AccountDirectoryAdh1WitnessEntry>();
        foreach (var signer in witnesses)
        {
            var signature = await SignOperationalAsync(
                request, signer, XPointNetworkOperationalSignaturePurpose.DirectoryHead,
                0, input, cancellationToken).ConfigureAwait(false);
            receipts.Add(new AccountDirectoryAdh1WitnessEntry(signer.SignerId.Span, signature));
            CryptographicOperations.ZeroMemory(signature);
        }
        receipts.Sort(static (left, right) => left.WitnessId.Span.SequenceCompareTo(right.WitnessId.Span));
        return AccountDirectoryAdh1Codec.Encode(new AccountDirectoryAdh1(
            authority.NetworkId.Span, 0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.Span,
            authority.AuthorityCoreReference.Span, authority.DirectoryWitnessPolicyHash.Span,
            request.NotBeforeUnixSeconds, request.ExpiresAtUnixSeconds, request.MinimumReader, receipts));
    }

    private static async ValueTask<byte[]> AuthorMailboxTopologyAsync(
        XPointNetworkOperationalGenesisRequest request,
        VerifiedXPointNetworkAuthority authority,
        byte[] exactXnv1,
        byte[][] exactXnd1,
        VerifiedAccountDirectoryFreshness freshness,
        IXPointNetworkWitnessSigner[] witnesses,
        CancellationToken cancellationToken)
    {
        var view = XPointNetworkCodec.Parse<Xnv1Record>(exactXnv1);
        var nodes = exactXnd1.Select(static value => XPointNetworkCodec.Parse<Xnd1Record>(value))
            .OrderBy(static value => value.NodeId.ToArray(), ByteArrayComparer.Instance).ToArray();
        var rows = nodes.Select(static node =>
        {
            var origin = node.Origins[0];
            return Join(node.NodeId.ToArray(), U64(node.UInt64(16)), origin.Id.ToArray(),
                origin.CurrentSpki.ToArray(), origin.NextSpki.ToArray());
        }).ToArray();
        ReadOnlyMemory<byte>[] fields =
        [
            authority.NetworkId.ToArray(), U64(0), new byte[32],
            ArtifactReference(ProtocolMagic.PMA2, request.Pma2ArtifactCommitment.Span),
            XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, view.CoreHash.Span),
            U64(1), new byte[] { 2 }, U16(checked((ushort)nodes.Length)), Join(rows),
            U64(request.IssuedAtUnixSeconds), U64(request.NotBeforeUnixSeconds), U64(request.ExpiresAtUnixSeconds),
            new byte[32], freshness.ExactAdh1CoreReference,
            new byte[] { checked((byte)witnesses.Length) },
            SignatureRows(witnesses.Select(static (signer, index) =>
                (signer.SignerId.ToArray(), Placeholder64(checked((byte)(index + 1))))).ToArray()),
        ];
        var provisional = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.PMT2, fields);
        var input = provisional.SignatureInput.ToArray();
        var receipts = new List<(byte[] Id, byte[] Signature)>();
        foreach (var signer in witnesses)
        {
            var signature = await SignOperationalAsync(
                request, signer, XPointNetworkOperationalSignaturePurpose.MailboxTopology,
                0, input, cancellationToken).ConfigureAwait(false);
            receipts.Add((signer.SignerId.ToArray(), signature));
        }
        fields[15] = SignatureRows(receipts.ToArray());
        return ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.PMT2, fields).CanonicalBytes.ToArray();
    }

    private static async ValueTask<byte[]> SignWitnessRecordAsync(
        XPointNetworkOperationalGenesisRequest request,
        XPointRecordDefinition definition,
        ReadOnlyMemory<byte>[] fields,
        int signatureFieldIndex,
        IXPointNetworkWitnessSigner[] signers,
        XPointNetworkOperationalSignaturePurpose purpose,
        CancellationToken cancellationToken)
    {
        var provisional = XPointNetworkCodec.Parse(XPointNetworkCodec.Write(definition, fields));
        var input = XPointNetworkCrypto.ComputeSigningInput(provisional);
        var receipts = new List<(byte[] Id, byte[] Signature)>();
        foreach (var signer in signers)
        {
            var signature = await SignOperationalAsync(
                request, signer, purpose, 0, input, cancellationToken).ConfigureAwait(false);
            receipts.Add((signer.SignerId.ToArray(), signature));
        }
        fields[signatureFieldIndex] = SignatureRows(receipts.ToArray());
        return XPointNetworkCodec.Write(definition, fields);
    }

    private static async ValueTask<byte[]> SignOperationalRecordAsync(
        XPointNetworkOperationalGenesisRequest request,
        XPointRecordDefinition definition,
        ReadOnlyMemory<byte>[] fields,
        int signatureFieldIndex,
        IXPointNetworkOperationalSigner signer,
        XPointNetworkOperationalSignaturePurpose purpose,
        ulong generation,
        CancellationToken cancellationToken)
    {
        var provisional = XPointNetworkCodec.Parse(XPointNetworkCodec.Write(definition, fields));
        var input = XPointNetworkCrypto.ComputeSigningInput(provisional);
        fields[signatureFieldIndex] = await SignOperationalAsync(
            request, signer, purpose, generation, input, cancellationToken).ConfigureAwait(false);
        return XPointNetworkCodec.Write(definition, fields);
    }

    private static async ValueTask<byte[]> SignOperationalAsync(
        XPointNetworkOperationalGenesisRequest request,
        IXPointNetworkOperationalSigner signer,
        XPointNetworkOperationalSignaturePurpose purpose,
        ulong generation,
        byte[] signingInput,
        CancellationToken cancellationToken)
    {
        var signature = new byte[64];
        var signingRequest = new XPointNetworkOperationalSigningRequest(
            request.CeremonyId.Span,
            purpose,
            request.Bootstrap.Authority.NetworkId.Span,
            generation,
            signer.SignerId.Span,
            signer.KeyGeneration,
            signer.Ed25519PublicKey.Span,
            signingInput);
        try
        {
            var written = await signer.SignAsync(signingRequest, signature, cancellationToken)
                .ConfigureAwait(false);
            ValidateSignature(written, signature, signingInput, signer.Ed25519PublicKey.Span);
            return signature.ToArray();
        }
        finally
        {
            signingRequest.Clear();
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static IXPointNetworkWitnessSigner[] ValidateWitnesses(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<IXPointNetworkWitnessSigner> signers)
    {
        var known = authority.WitnessKeys.ToDictionary(
            static value => Convert.ToHexString(value.Id.Span), StringComparer.Ordinal);
        var result = signers.OrderBy(static value => value.SignerId.ToArray(), ByteArrayComparer.Instance).ToArray();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        foreach (var signer in result)
        {
            var id = Convert.ToHexString(signer.SignerId.Span);
            if (!ids.Add(id) || !known.TryGetValue(id, out var binding) ||
                signer.KeyGeneration != binding.Generation ||
                !Fixed(signer.Ed25519PublicKey.Span, binding.Ed25519PublicKey.Span) ||
                !Fixed(signer.FailureDomainHash.Span, binding.FailureDomainHash.Span) ||
                !domains.Add(Convert.ToHexString(signer.FailureDomainHash.Span)))
                throw new CryptographicException("An operational witness is unknown, duplicated, or outside its exact XNA1 binding.");
        }
        if (result.Length < authority.WitnessThreshold || domains.Count < authority.WitnessThreshold)
            throw new CryptographicException("The operational witnesses do not meet the exact XNA1 threshold.");
        return result;
    }

    private static XPointNetworkOperationalNode[] ValidateNodes(
        ReadOnlySpan<byte> network,
        IReadOnlyList<XPointNetworkOperationalNode> nodes)
    {
        var result = nodes.ToArray();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var hosts = new HashSet<string>(StringComparer.Ordinal);
        var origins = new HashSet<string>(StringComparer.Ordinal);
        foreach (var node in result)
        {
            ArgumentNullException.ThrowIfNull(node);
            var id = node.IdentitySigner.SignerId.Span;
            if (id.Length != 32 || id.IndexOfAnyExcept((byte)0) < 0 ||
                !ids.Add(Convert.ToHexString(id)) ||
                !hosts.Add(Convert.ToHexString(node.HostId.Span)) ||
                !origins.Add($"{node.OriginAddressFamily}:{Convert.ToHexString(node.OriginAddress.Span)}:{node.OriginPort}"))
                throw new CryptographicException("Operational nodes must have distinct exact identities, hosts, and endpoints.");
        }
        _ = network;
        return result;
    }

    private static void ValidateSignature(
        int written,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> signingInput,
        ReadOnlySpan<byte> publicKey)
    {
        if (written != 64 || signature.IndexOfAnyExcept((byte)0) < 0 ||
            !PublicKeyAuth.VerifyDetached(signature.ToArray(), signingInput.ToArray(), publicKey.ToArray()))
            throw new CryptographicException("An operational signer returned an invalid Ed25519 signature.");
    }

    private static byte[] SignatureRows(IReadOnlyList<(byte[] Id, byte[] Signature)> rows) =>
        Join(rows.OrderBy(static value => value.Id, ByteArrayComparer.Instance)
            .Select(static value => Join(value.Id, value.Signature)).ToArray());

    private static byte[] ArtifactReference(string magic, ReadOnlySpan<byte> hash)
    {
        var result = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }

    private static byte[] HashDomain(string domain, ReadOnlySpan<byte> value) =>
        XPointNetworkCrypto.Sha256Domain(domain, value.ToArray());

    private static byte[] Placeholder64(byte discriminator = 1)
    {
        var result = new byte[64];
        result[0] = discriminator;
        return result;
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

    private static byte[] U32(uint value)
    {
        var result = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(result, value);
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

    private sealed class FixedMonotonicClock(byte[] bootId, ulong sample) : IOnionMonotonicClock
    {
        private readonly byte[] boot = bootId.ToArray();

        internal FixedMonotonicClock(ReadOnlySpan<byte> bootId, ulong sample)
            : this(bootId.ToArray(), sample)
        {
        }

        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(boot, sample));
        }
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
