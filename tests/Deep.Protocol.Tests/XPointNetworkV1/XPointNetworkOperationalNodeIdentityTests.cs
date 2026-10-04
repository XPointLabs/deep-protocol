using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.XPointNetworkV1;

/// <summary>Genesis candidate authoring, not DID2 completion or dispatch authority.</summary>
public sealed class XPointNetworkOperationalNodeIdentityTests
{
    [Fact]
    public async Task CandidateCommitsIndependentNodeIdAndIdentityKeyWithGenuineDescriptorSignature()
    {
        using var f = await Fixture.CreateAsync();
        var candidate = await XPointNetworkOperationalGenesisAuthor.AuthorNetworkCandidateAsync(f.Request);
        Assert.Equal(3, candidate.ExactXnd1.Count);
        foreach (var exact in candidate.ExactXnd1)
        {
            var node = XPointNetworkCodec.Parse<Xnd1Record>(exact.Span);
            var signer = Assert.Single(f.Nodes, s => s.SignerId.Span.SequenceEqual(node.FieldSpan(2)));
            Assert.False(node.FieldSpan(2).SequenceEqual(node.FieldSpan(5)));
            Assert.Equal(signer.Ed25519PublicKey.ToArray(), node.FieldSpan(5).ToArray());
            var input = XPointNetworkCrypto.ComputeSigningInput(node);
            Assert.True(PublicKeyAuth.VerifyDetached(node.FieldSpan(37).ToArray(), input, signer.Ed25519PublicKey.ToArray()));
            Assert.False(PublicKeyAuth.VerifyDetached(node.FieldSpan(37).ToArray(), input, signer.SignerId.ToArray()));
        }
    }

    [Theory]
    [InlineData("zero-id")]
    [InlineData("short-id")]
    [InlineData("duplicate-id")]
    [InlineData("zero-key")]
    [InlineData("short-key")]
    [InlineData("generation")]
    public async Task InvalidIndependentIdentityRejectsBeforeAnyOperationalSignerCallback(string defect)
    {
        using var f = await Fixture.CreateAsync();
        var node = f.Nodes[0];
        if (defect == "zero-id") node.Id = new byte[32];
        if (defect == "short-id") node.Id = B(31, 0x81);
        if (defect == "duplicate-id") node.Id = f.Nodes[1].SignerId.ToArray();
        if (defect == "zero-key") node.PublicKey = new byte[32];
        if (defect == "short-key") node.PublicKey = B(31, 0x82);
        if (defect == "generation") node.Generation = 1;
        await Assert.ThrowsAsync<CryptographicException>(() =>
            XPointNetworkOperationalGenesisAuthor.AuthorNetworkCandidateAsync(f.Request).AsTask());
        Assert.All(f.Signers, signer => Assert.Equal(0, signer.OperationalCalls));
        Assert.Equal(0, f.Root.RootCalls);
    }

    [Fact]
    public async Task SignatureFromNodeIdDerivedKeyCannotSatisfyCommittedDescriptorIdentityKey()
    {
        using var f = await Fixture.CreateAsync(); f.Nodes[0].UseIdAsSeed = true;
        await Assert.ThrowsAsync<CryptographicException>(() =>
            XPointNetworkOperationalGenesisAuthor.AuthorNetworkCandidateAsync(f.Request).AsTask());
        Assert.Equal(1, f.Nodes[0].OperationalCalls);
        Assert.All(f.Nodes.Skip(1), signer => Assert.Equal(0, signer.OperationalCalls));
        Assert.All(f.Witnesses, signer => Assert.Equal(0, signer.OperationalCalls));
    }

    private sealed class Fixture : IDisposable
    {
        internal Signer Root = new(0x20);
        internal Signer[] Witnesses = [new(0x30), new(0x31), new(0x32)];
        internal Signer[] Nodes = [new(0x70), new(0x71), new(0x72)];
        internal IEnumerable<Signer> Signers => new[] { Root }.Concat(Witnesses).Concat(Nodes);
        internal XPointNetworkOperationalGenesisRequest Request = null!;
        internal static async Task<Fixture> CreateAsync()
        {
            var f = new Fixture();
            try
            {
                var bootstrap = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(new(
                    B(32, 0x12), B(16, 0x11), [new(f.Root.RootKeyId.Span, 0, f.Root.Ed25519PublicKey.Span, f.Root.CustodyDomainHash.Span)], 1,
                    f.Witnesses.Select(w => new XPointNetworkBootstrapWitnessKey(w.SignerId.Span, 0, w.Ed25519PublicKey.Span, w.FailureDomainHash.Span)).ToArray(), 2,
                    [new(B(32, 0x60), B(32, 0x61), 1, "time1.invalid", 4460, B(32, 0x62), 5),
                     new(B(32, 0x63), B(32, 0x64), 1, "time2.invalid", 4460, B(32, 0x65), 5)],
                    5, 10, 900, 900, 10_000, 900, 9_000, 1, 1), [f.Root]);
                var nodes = f.Nodes.Select((signer, i) => new XPointNetworkOperationalNode(signer,
                    B(32, (byte)(0x80 + i)), B(32, (byte)(0x90 + i)), B(32, (byte)(0xa0 + i)), B(32, (byte)(0xb0 + i)),
                    (uint)(64_500 + i), 840, B(32, (byte)(0xc0 + i)), IPAddress.Parse($"192.0.2.{i + 1}"), 443,
                    B(32, (byte)(0xd0 + i)), B(32, (byte)(0xd8 + i)), ScalarMult.Base(B(32, (byte)(0xe0 + i))),
                    ScalarMult.Base(B(32, (byte)(0xe8 + i))), Enumerable.Range(0, 5).Select(role =>
                        (ReadOnlyMemory<byte>)B(32, (byte)(0x10 + i * 5 + role))).ToArray())).ToArray();
                f.Request = new(B(32, 0x12), bootstrap, [f.Root], f.Witnesses, nodes,
                    B(32, 0x41), B(32, 0x42), B(32, 0x43), B(32, 0x44), B(32, 0x45), 990, 1_000, 1_500);
                f.Root.RootCalls = 0;
                return f;
            }
            catch { f.Dispose(); throw; }
        }
        public void Dispose() { foreach (var signer in Signers) signer.Dispose(); }
    }

    private sealed class Signer : IXPointNetworkBootstrapRootSigner, IXPointNetworkWitnessSigner, IDisposable
    {
        private readonly KeyPair key;
        internal byte[] Id, PublicKey;
        internal ulong Generation;
        internal int OperationalCalls, RootCalls;
        internal bool UseIdAsSeed;
        internal Signer(byte marker)
        { Id = SHA256.HashData(B(32, marker)); key = PublicKeyAuth.GenerateKeyPair(B(32, marker)); PublicKey = key.PublicKey; }
        public ReadOnlyMemory<byte> RootKeyId => Id;
        public ReadOnlyMemory<byte> SignerId => Id;
        public ReadOnlyMemory<byte> WitnessId => Id;
        public ulong KeyGeneration => Generation;
        public ReadOnlyMemory<byte> Ed25519PublicKey => PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => SHA256.HashData(Id);
        public ReadOnlyMemory<byte> FailureDomainHash => CustodyDomainHash;
        public ValueTask<int> SignAsync(XPointNetworkRootSigningRequest request, Memory<byte> signature, CancellationToken token)
        { token.ThrowIfCancellationRequested(); RootCalls++; PublicKeyAuth.SignDetached(request.SigningInput.ToArray(), key.PrivateKey).CopyTo(signature); return ValueTask.FromResult(64); }
        public ValueTask<int> SignAsync(XPointNetworkOperationalSigningRequest request, Memory<byte> signature, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); OperationalCalls++;
            var signingKey = UseIdAsSeed ? PublicKeyAuth.GenerateKeyPair(Id).PrivateKey : key.PrivateKey;
            try { PublicKeyAuth.SignDetached(request.SigningInput.ToArray(), signingKey).CopyTo(signature); return ValueTask.FromResult(64); }
            finally { if (UseIdAsSeed) CryptographicOperations.ZeroMemory(signingKey); }
        }
        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(ReadOnlyMemory<byte> input, CancellationToken token)
        { token.ThrowIfCancellationRequested(); return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey)); }
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
    private static byte[] B(int count, byte marker) => Enumerable.Repeat(marker, count).ToArray();
}
