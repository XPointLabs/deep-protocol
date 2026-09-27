using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

public sealed class XPointNetworkOperationalGenesisAuthorTests
{
    [Fact]
    public async Task AuthorAsync_ProducesIndependentlyVerifiedCompleteGenesis()
    {
        var network = Bytes(16, 0x11);
        var ceremony = Bytes(32, 0x12);
        var root = new RootSigner(Bytes(32, 0x20), Bytes(32, 0x21), Bytes(32, 0x22));
        var witnesses = Enumerable.Range(0, 3).Select(index => new WitnessSigner(
            Bytes(32, checked((byte)(0x30 + index))),
            Bytes(32, checked((byte)(0x40 + index))),
            Bytes(32, checked((byte)(0x50 + index))))).ToArray();
        var sources = new[]
        {
            new AccountDirectoryDts1Source(
                Bytes(32, 0x60), Bytes(32, 0x61), 1,
                "time.cloudflare.com", 4460, Bytes(32, 0x62), 5),
            new AccountDirectoryDts1Source(
                Bytes(32, 0x63), Bytes(32, 0x64), 1,
                "nts.netnod.se", 4460, Bytes(32, 0x65), 5),
        }.OrderBy(static value => value.SourceId.ToArray(), ByteArrayComparer.Instance).ToArray();
        var bootstrapRequest = new XPointNetworkGenesisAuthoringRequest(
            ceremony,
            network,
            [new XPointNetworkBootstrapRootKey(
                root.RootKeyId.Span, 0, root.Ed25519PublicKey.Span, root.CustodyDomainHash.Span)],
            1,
            witnesses.Select(static value => new XPointNetworkBootstrapWitnessKey(
                value.SignerId.Span, 0, value.Ed25519PublicKey.Span,
                value.FailureDomainHash.Span)).ToArray(),
            2,
            sources,
            5,
            10,
            900,
            900,
            10_000,
            900,
            9_000,
            1,
            1);
        var bootstrap = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
            bootstrapRequest, [root]);

        var nodes = Enumerable.Range(0, 3).Select(index =>
        {
            var signer = new OperationalSigner(
                Bytes(32, checked((byte)(0x70 + index))),
                idEqualsPublicKey: true);
            return new XPointNetworkOperationalNode(
                signer,
                Bytes(32, checked((byte)(0x80 + index))),
                Bytes(32, checked((byte)(0x90 + index))),
                Bytes(32, checked((byte)(0xa0 + index))),
                Bytes(32, checked((byte)(0xb0 + index))),
                checked((uint)(64_500 + index)),
                840,
                Bytes(32, checked((byte)(0xc0 + index))),
                IPAddress.Parse($"192.0.2.{index + 1}"),
                443,
                Bytes(32, checked((byte)(0xd0 + index))),
                Bytes(32, checked((byte)(0xd8 + index))),
                ScalarMult.Base(Bytes(32, checked((byte)(0xe0 + index)))),
                ScalarMult.Base(Bytes(32, checked((byte)(0xe8 + index)))),
                Enumerable.Range(0, 5).Select(role => (ReadOnlyMemory<byte>)
                    PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(0x10 + index * 5 + role)))).PublicKey)
                    .ToArray());
        }).ToArray();
        var request = new XPointNetworkOperationalGenesisRequest(
            ceremony,
            bootstrap,
            [root],
            witnesses,
            nodes,
            Bytes(32, 0xf1),
            Hash("xcc"),
            Hash("xcb"),
            Hash("pma"),
            PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x31)).PublicKey,
            PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x32)).PublicKey,
            990,
            1_000,
            1_500,
            Bytes(32, 0xf2),
            Bytes(16, 0xf3),
            100,
            101,
            102,
            1_100,
            5);

        var authored = await XPointNetworkOperationalGenesisAuthor.AuthorAsync(request);

        Assert.Equal("XVP1", ContactMagic(authored.ExactXvp1.Span));
        Assert.Equal(3, authored.ExactXnd1.Count);
        Assert.Equal("XNV1", ContactMagic(authored.ExactXnv1.Span));
        Assert.Equal("XNH1", ContactMagic(authored.ExactXnh1.Span));
        Assert.Equal("ADH1", ContactMagic(authored.ExactAdh1.Span));
        Assert.Equal("DTT1", ContactMagic(authored.ExactDtt1.Span));
        Assert.Equal("ADP1", ContactMagic(authored.ExactAdp1.Span));
        Assert.Equal("PMA2", ContactCodec.Decode("PMA2", authored.ExactPma2.Span).Magic);
        Assert.Equal("PMT2", ContactCodec.Decode("PMT2", authored.ExactPmt2.Span).Magic);
        var mailboxAuthority = MailboxAuthorityV2Verifier.Verify(
            bootstrap.Authority, authored.ExactPma2.Span, 1_095, 1_105);
        Assert.True(mailboxAuthority.BindsProjection(authored.ExactPmt2.Span));
        authored.VerifiedNetwork.EnsureCurrent();

        var priorHead = XPointNetworkCodec.Parse<Xnh1Record>(authored.ExactXnh1.Span);
        var priorPmt = ContactCodec.Decode("PMT2", authored.ExactPmt2.Span);
        var adh = AccountDirectoryAdh1Codec.Decode(authored.ExactAdh1.Span);
        var firstRollovers = Rollovers(nodes, 0x30, 0x80);
        var successorRequest = new XPointNetworkOperationalSuccessorRequest(
            Hash("successor-ceremony"), bootstrap, [root], witnesses,
            firstRollovers,
            authored.ExactXvp1, authored.ExactXnd1, [authored.ExactXnv1],
            authored.ExactXnh1, authored.ExactPma2, authored.ExactPmt2,
            priorHead.CoreHash.Span, priorPmt.ArtifactHash.Span,
            XPointNetworkCodec.EncodeCoreReference("ADH1", AccountDirectoryCrypto.ComputeAdh1CoreHash(adh)),
            1_200, 1_210, 1_400);
        var successor = await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(successorRequest);
        Assert.Equal(1UL, XPointNetworkCodec.Parse<Xvp1Record>(successor.ExactXvp1.Span).Generation);
        Assert.Equal(1UL, XPointNetworkCodec.Parse<Xnv1Record>(successor.ExactXnv1.Span).ViewGeneration);
        Assert.Equal(2UL, XPointNetworkCodec.Parse<Xnh1Record>(successor.ExactXnh1.Span).TreeSize);
        Assert.Equal(3, successor.ExactXnd1.Count);
        Assert.All(successor.ExactXnd1, bytes =>
            Assert.Equal(1UL, XPointNetworkCodec.Parse<Xnd1Record>(bytes.Span).Generation));
        Assert.Equal(1UL, System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(
            ContactCodec.Decode("PMT2", successor.ExactPmt2.Span).FieldSpan(2)));
        Assert.True(priorPmt.FieldSpan(6).SequenceEqual(
            ContactCodec.Decode("PMT2", successor.ExactPmt2.Span).FieldSpan(6)));

        var reusedTrafficKeys = nodes.Select(static node => new XPointNetworkOperationalNodeRollover(
            node.IdentitySigner, node.CurrentOriginSpkiSha256.Span, node.NextOriginSpkiSha256.Span,
            node.CurrentOnionX25519PublicKey.Span, node.NextOnionX25519PublicKey.Span)).ToArray();
        var reusedKeyRequest = new XPointNetworkOperationalSuccessorRequest(
            Hash("reused-traffic-key-ceremony"), bootstrap, [root], witnesses,
            reusedTrafficKeys, authored.ExactXvp1, authored.ExactXnd1,
            [authored.ExactXnv1], authored.ExactXnh1, authored.ExactPma2, authored.ExactPmt2,
            priorHead.CoreHash.Span, priorPmt.ArtifactHash.Span,
            XPointNetworkCodec.EncodeCoreReference("ADH1", AccountDirectoryCrypto.ComputeAdh1CoreHash(adh)),
            1_200, 1_210, 1_400);
        await Assert.ThrowsAsync<CryptographicException>(() =>
            XPointNetworkOperationalSuccessorAuthor.AuthorAsync(reusedKeyRequest).AsTask());

        var currentNonce = Bytes(32, 0xf5);
        var currentBoot = Bytes(16, 0xf6);
        var protectedDirectoryHead = AccountDirectoryProtectedLkgFactory.Restore(
            bootstrap.Authority, authored.ExactAdh1,
            AccountDirectoryCrypto.ComputeAdh1CoreHash(adh));
        var proofMaterial = AccountDirectoryAdp1ProofMaterial.NonMembership(
            Bytes(32, 0xf1), callerProtectedLkg: null, consistencyProofNodes: [],
            exactAfp1: ReadOnlyMemory<byte>.Empty, sparseMapBitmap: new byte[32], sparseMapSiblings: []);
        var proofRequest = new AccountDirectoryProofAuthoringRequest(
            network, currentNonce, currentBoot, 200,
            authored.ExactAdh1.Span, successor.ExactXnv1.Span,
            1_300, 5, 1_295,
            checked(1_305UL + AccountDirectoryCurrentProofVerifier.MaximumNonceRoundTripSeconds),
            AccountDirectoryDtt1IssuanceEpoch.Derive(bootstrap.Authority, 1_300, 5), 1);
        var currentProof = await AccountDirectoryProofAuthor.IssueAsync(
            bootstrap.Authority, protectedDirectoryHead, proofRequest, proofMaterial,
            witnesses.Cast<IAccountDirectoryDtt1WitnessSigner>().ToArray());
        var freshness = AccountDirectoryCurrentProofVerifier.Verify(
            bootstrap.Authority, authored.ExactAdh1,
            currentProof.ExactDtt1, currentProof.ExactAdp1,
            currentNonce, Bytes(32, 0xf1),
            new AccountDirectoryMonotonicRequestWindow(currentBoot, 200, 201, 202),
            protectedLkg: null, currentCheckpoint: null, supportedReader: 1);
        var verifiedSuccessor = await OnionNetworkContextVerifier.VerifyAsync(
            bootstrap.Authority, freshness,
            [successor.ExactXvp1], [successor.ExactXnv1], [successor.ExactXnh1],
            successor.ExactXnd1, [successor.ExactPmt2],
            protectedPrevious: authored.VerifiedNetwork,
            new OnionTrustedTimeAuthority(new FixedClock(currentBoot, 202)),
            CancellationToken.None);
        verifiedSuccessor.EnsureCurrent();

        var secondHead = XPointNetworkCodec.Parse<Xnh1Record>(successor.ExactXnh1.Span);
        var secondPmt = ContactCodec.Decode("PMT2", successor.ExactPmt2.Span);
        var secondRollovers = Rollovers(nodes, 0x60, 0xa0);
        var secondRequest = new XPointNetworkOperationalSuccessorRequest(
            Hash("second-successor-ceremony"), bootstrap, [root], witnesses,
            secondRollovers,
            successor.ExactXvp1, successor.ExactXnd1,
            [authored.ExactXnv1, successor.ExactXnv1],
            successor.ExactXnh1, successor.ExactPma2, successor.ExactPmt2,
            secondHead.CoreHash.Span, secondPmt.ArtifactHash.Span,
            XPointNetworkCodec.EncodeCoreReference("ADH1", AccountDirectoryCrypto.ComputeAdh1CoreHash(adh)),
            1_330, 1_340, 1_480);
        var second = await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(secondRequest);
        Assert.Equal(2UL, XPointNetworkCodec.Parse<Xnv1Record>(second.ExactXnv1.Span).ViewGeneration);
        Assert.Equal(3UL, XPointNetworkCodec.Parse<Xnh1Record>(second.ExactXnh1.Span).TreeSize);
        Assert.True(priorPmt.FieldSpan(6).SequenceEqual(
            ContactCodec.Decode("PMT2", second.ExactPmt2.Span).FieldSpan(6)));

        var wrongHeadPin = new XPointNetworkOperationalSuccessorRequest(
            Hash("wrong-head-pin-ceremony"), bootstrap, [root], witnesses,
            secondRollovers,
            successor.ExactXvp1, successor.ExactXnd1,
            [authored.ExactXnv1, successor.ExactXnv1],
            successor.ExactXnh1, successor.ExactPma2, successor.ExactPmt2,
            Bytes(32, 0x7a), secondPmt.ArtifactHash.Span,
            XPointNetworkCodec.EncodeCoreReference("ADH1", AccountDirectoryCrypto.ComputeAdh1CoreHash(adh)),
            1_330, 1_340, 1_480);
        await Assert.ThrowsAsync<CryptographicException>(() =>
            XPointNetworkOperationalSuccessorAuthor.AuthorAsync(wrongHeadPin).AsTask());
    }

    private static string ContactMagic(ReadOnlySpan<byte> bytes) =>
        System.Text.Encoding.ASCII.GetString(bytes[..4]);

    private static byte[] Hash(string value) => SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(value));
    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();

    private static XPointNetworkOperationalNodeRollover[] Rollovers(
        IReadOnlyList<XPointNetworkOperationalNode> nodes, byte spkiMarker, byte onionMarker) =>
        nodes.Select((node, index) => new XPointNetworkOperationalNodeRollover(
            node.IdentitySigner,
            Bytes(32, checked((byte)(spkiMarker + index * 2))),
            Bytes(32, checked((byte)(spkiMarker + index * 2 + 1))),
            ScalarMult.Base(Bytes(32, checked((byte)(onionMarker + index * 2)))),
            ScalarMult.Base(Bytes(32, checked((byte)(onionMarker + index * 2 + 1)))))).ToArray();

    private sealed class FixedClock(byte[] boot, ulong sample) : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(boot, sample));
        }
    }

    private class OperationalSigner : IXPointNetworkOperationalSigner
    {
        private readonly byte[] id;
        private readonly KeyPair pair;

        internal OperationalSigner(byte[] seed, bool idEqualsPublicKey = false)
        {
            pair = PublicKeyAuth.GenerateKeyPair(seed);
            id = idEqualsPublicKey ? pair.PublicKey.ToArray() : SHA256.HashData(pair.PublicKey);
        }

        public ReadOnlyMemory<byte> SignerId => id.ToArray();
        public ulong KeyGeneration => 0;
        public ReadOnlyMemory<byte> Ed25519PublicKey => pair.PublicKey.ToArray();

        public ValueTask<int> SignAsync(
            XPointNetworkOperationalSigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var signature = PublicKeyAuth.SignDetached(request.SigningInput.ToArray(), pair.PrivateKey);
            signature.CopyTo(signature64);
            return ValueTask.FromResult(signature.Length);
        }

        protected byte[] Sign(ReadOnlyMemory<byte> input) =>
            PublicKeyAuth.SignDetached(input.ToArray(), pair.PrivateKey);
    }

    private sealed class WitnessSigner : OperationalSigner, IXPointNetworkWitnessSigner
    {
        private readonly byte[] failureDomain;

        internal WitnessSigner(byte[] idSeed, byte[] keySeed, byte[] failureDomain)
            : base(keySeed)
        {
            this.failureDomain = failureDomain.ToArray();
            ForcedId = idSeed.ToArray();
        }

        private byte[] ForcedId { get; }
        public new ReadOnlyMemory<byte> SignerId => ForcedId.ToArray();
        ReadOnlyMemory<byte> IXPointNetworkOperationalSigner.SignerId => ForcedId.ToArray();
        public ReadOnlyMemory<byte> WitnessId => ForcedId.ToArray();
        public ReadOnlyMemory<byte> FailureDomainHash => failureDomain.ToArray();

        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(Sign(signingInput));
        }
    }

    private sealed class RootSigner : IXPointNetworkBootstrapRootSigner
    {
        private readonly byte[] id;
        private readonly byte[] custody;
        private readonly KeyPair pair;

        internal RootSigner(byte[] id, byte[] seed, byte[] custody)
        {
            this.id = id.ToArray();
            this.custody = custody.ToArray();
            pair = PublicKeyAuth.GenerateKeyPair(seed);
        }

        public ReadOnlyMemory<byte> RootKeyId => id.ToArray();
        public ulong KeyGeneration => 0;
        public ReadOnlyMemory<byte> Ed25519PublicKey => pair.PublicKey.ToArray();
        public ReadOnlyMemory<byte> CustodyDomainHash => custody.ToArray();

        public ValueTask<int> SignAsync(
            XPointNetworkRootSigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var signature = PublicKeyAuth.SignDetached(request.SigningInput.ToArray(), pair.PrivateKey);
            signature.CopyTo(signature64);
            return ValueTask.FromResult(signature.Length);
        }
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
