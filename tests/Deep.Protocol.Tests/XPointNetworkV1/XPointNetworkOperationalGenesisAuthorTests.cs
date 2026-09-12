using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
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
        Assert.Equal("PMT2", ContactCodec.Decode("PMT2", authored.ExactPmt2.Span).Magic);
        authored.VerifiedNetwork.EnsureCurrent();
    }

    private static string ContactMagic(ReadOnlySpan<byte> bytes) =>
        System.Text.Encoding.ASCII.GetString(bytes[..4]);

    private static byte[] Hash(string value) => SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(value));
    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();

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
