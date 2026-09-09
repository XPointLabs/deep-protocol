using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class XPointNetworkBootstrapAuthorTests
{
    [Fact]
    public async Task AuthorGenesis_ProducesCanonicalVerifierAcceptedXnaAndDts()
    {
        var fixture = Fixture.Create();

        var result = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
            fixture.Request,
            fixture.Signers.Take(2).Reverse().ToArray());

        var exactXna = result.ExactXna1.ToArray();
        var exactDts = result.ExactDts1.ToArray();
        var xna = XPointNetworkCodec.Parse<Xna1Record>(exactXna);
        var dts = AccountDirectoryDts1Codec.Decode(exactDts);
        var independentlyVerified = XPointNetworkAuthorityVerifier.Verify(
            result.GenesisPin,
            new ReadOnlyMemory<byte>[] { exactXna },
            new ReadOnlyMemory<byte>[] { exactDts });

        Assert.Equal((ulong)0, result.Authority.AuthorityGeneration);
        Assert.Equal(result.Authority.AuthorityCoreHash.ToArray(), independentlyVerified.AuthorityCoreHash.ToArray());
        Assert.Equal(xna.CoreHash.ToArray(), result.GenesisPin.AuthorityCoreHash.ToArray());
        Assert.Equal(AccountDirectoryCrypto.ComputeDts1PolicyHash(dts), result.Authority.TimeSourcePolicyHash.ToArray());
        Assert.Equal(result.Authority.Dts1PolicyCoreReference.ToArray(), xna.FieldSpan(12).ToArray());
        Assert.Equal(fixture.Roots.Select(static root => root.RootKeyId.ToArray()).Order(ByteArrays.Instance),
            xna.RootKeys.Select(static root => root.Id.ToArray()));
        Assert.Equal(fixture.Witnesses.Select(static witness => witness.WitnessId.ToArray()).Order(ByteArrays.Instance),
            xna.Witnesses.Select(static witness => witness.Id.ToArray()));
        Assert.Equal(new[] { "time-a.example", "time-b.example" }, dts.Sources.Select(static source => source.HostAscii));
        Assert.Equal(2, xna.Signatures.Count);
        Assert.Equal(2, dts.RootReceipts.Count);
    }

    [Fact]
    public async Task AuthorGenesis_SuppliesExactPurposeSeparatedSigningInputsAndClearsRequests()
    {
        var fixture = Fixture.Create();

        var result = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
            fixture.Request,
            fixture.Signers.Take(2).ToArray());

        var xna = XPointNetworkCodec.Parse<Xna1Record>(result.ExactXna1.Span);
        var dts = AccountDirectoryDts1Codec.Decode(result.ExactDts1.Span);
        var expectedXna = XPointNetworkCrypto.ComputeSigningInput(xna);
        var expectedDts = AccountDirectoryCrypto.ComputeDts1SigningInput(dts);
        try
        {
            foreach (var signer in fixture.Signers.Take(2))
            {
                Assert.Collection(signer.Captured,
                    first =>
                    {
                        Assert.Equal(XPointNetworkRootSignaturePurpose.GenesisAuthority, first.Purpose);
                        Assert.Equal(expectedXna, first.SigningInput);
                    },
                    second =>
                    {
                        Assert.Equal(XPointNetworkRootSignaturePurpose.DirectoryTimeSourcePolicy, second.Purpose);
                        Assert.Equal(expectedDts, second.SigningInput);
                    });
                Assert.All(signer.Requests, request =>
                {
                    Assert.All(request.SigningInput.ToArray(), static value => Assert.Equal(0, value));
                    Assert.All(request.SigningInputSha256.ToArray(), static value => Assert.Equal(0, value));
                    Assert.Equal(fixture.CeremonyId, request.CeremonyId.ToArray());
                    Assert.Equal((ulong)0, request.AuthorityGeneration);
                    Assert.Equal((ulong)0, request.KeyGeneration);
                    Assert.Equal(signer.CustodyDomainHash.ToArray(), request.CustodyDomainHash.ToArray());
                });
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedXna);
            CryptographicOperations.ZeroMemory(expectedDts);
        }
    }

    [Fact]
    public async Task AuthorGenesis_IsDeterministicAcrossInputOrdering()
    {
        var first = Fixture.Create(reverseInputs: false);
        var second = Fixture.Create(reverseInputs: true);

        var firstResult = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
            first.Request, first.Signers.Take(2).ToArray());
        var secondResult = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
            second.Request, second.Signers.Take(2).Reverse().ToArray());

        Assert.Equal(firstResult.ExactXna1.ToArray(), secondResult.ExactXna1.ToArray());
        Assert.Equal(firstResult.ExactDts1.ToArray(), secondResult.ExactDts1.ToArray());
        Assert.Equal(firstResult.GenesisPin.AuthorityCoreHash.ToArray(), secondResult.GenesisPin.AuthorityCoreHash.ToArray());
    }

    [Fact]
    public async Task AuthorGenesis_ReturnsDefensiveNonForgeableVerifiedOutput()
    {
        var fixture = Fixture.Create();
        var result = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
            fixture.Request, fixture.Signers.Take(2).ToArray());
        var expectedXna = result.ExactXna1.ToArray();
        var expectedDts = result.ExactDts1.ToArray();
        var expectedCore = result.Authority.AuthorityCoreHash.ToArray();

        var changedXna = result.ExactXna1.ToArray();
        var changedDts = result.ExactDts1.ToArray();
        changedXna.AsSpan().Clear();
        changedDts.AsSpan().Clear();
        var changedPin = result.GenesisPin.AuthorityCoreHash.ToArray();
        changedPin.AsSpan().Clear();

        Assert.Equal(expectedXna, result.ExactXna1.ToArray());
        Assert.Equal(expectedDts, result.ExactDts1.ToArray());
        Assert.Equal(expectedCore, result.Authority.AuthorityCoreHash.ToArray());
        Assert.Empty(typeof(VerifiedXPointNetworkBootstrap).GetConstructors());
        Assert.Empty(typeof(XPointNetworkRootSigningRequest).GetConstructors());
    }

    [Fact]
    public async Task AuthorGenesis_RejectsInsufficientDuplicateAndUnknownSignersBeforeSigning()
    {
        var fixture = Fixture.Create();
        await RejectAsync("InsufficientRootSigners", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(fixture.Request, fixture.Signers.Take(1).ToArray()));
        Assert.All(fixture.Signers, static signer => Assert.Equal(0, signer.CallCount));

        var duplicate = new IXPointNetworkBootstrapRootSigner[] { fixture.Signers[0], fixture.Signers[0] };
        await RejectAsync("DuplicateOrInvalidRootSigner", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(fixture.Request, duplicate));
        Assert.Equal(0, fixture.Signers[0].CallCount);

        var attacker = new CustodySigner(Bytes(32, 0xf0), KeyPair(0xf1), 0, Bytes(32, 0xf2));
        await RejectAsync("UnknownRootSigner", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                fixture.Request,
                new IXPointNetworkBootstrapRootSigner[] { fixture.Signers[0], attacker }));
        Assert.Equal(0, fixture.Signers[0].CallCount);
        Assert.Equal(0, attacker.CallCount);

        var wrongCustody = new CustodySigner(
            fixture.Signers[0].RootKeyId.Span,
            fixture.Signers[0].Keys,
            0,
            Bytes(32, 0xf3));
        await RejectAsync("UnknownRootSigner", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                fixture.Request,
                new IXPointNetworkBootstrapRootSigner[] { wrongCustody, fixture.Signers[1] }));
        Assert.Equal(0, wrongCustody.CallCount);
    }

    [Fact]
    public async Task AuthorGenesis_RejectsInvalidSignatureAndClearsCallbackBuffer()
    {
        var fixture = Fixture.Create();
        fixture.Signers[0].Mode = SignerMode.InvalidSignature;

        await RejectAsync("InvalidRootSignerResult", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                fixture.Request, fixture.Signers.Take(2).ToArray()));

        var request = Assert.Single(fixture.Signers[0].Requests);
        Assert.All(request.SigningInput.ToArray(), static value => Assert.Equal(0, value));
        Assert.All(fixture.Signers[0].LastOutputBuffer.ToArray(), static value => Assert.Equal(0, value));
        Assert.Equal(0, fixture.Signers[1].CallCount);
    }

    [Fact]
    public async Task AuthorGenesis_WrapsSignerFailureAndClearsRequest()
    {
        var fixture = Fixture.Create();
        fixture.Signers[0].Mode = SignerMode.Throw;

        var error = await RejectAsync("RootSignerFailed", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                fixture.Request, fixture.Signers.Take(2).ToArray()));

        Assert.IsType<InvalidOperationException>(error.InnerException);
        var request = Assert.Single(fixture.Signers[0].Requests);
        Assert.All(request.SigningInput.ToArray(), static value => Assert.Equal(0, value));
    }

    [Fact]
    public async Task AuthorGenesis_RejectsWrongSignatureLengthAndPropagatesCancellation()
    {
        var wrongLength = Fixture.Create();
        wrongLength.Signers[0].Mode = SignerMode.WrongLength;
        await RejectAsync("InvalidRootSignerResult", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                wrongLength.Request, wrongLength.Signers.Take(2).ToArray()));
        Assert.All(wrongLength.Signers[0].Requests.Single().SigningInput.ToArray(),
            static value => Assert.Equal(0, value));

        var cancelled = Fixture.Create();
        cancelled.Signers[0].Mode = SignerMode.Cancel;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                cancelled.Request, cancelled.Signers.Take(2).ToArray()));
        Assert.All(cancelled.Signers[0].Requests.Single().SigningInput.ToArray(),
            static value => Assert.Equal(0, value));
        Assert.Equal(0, cancelled.Signers[1].CallCount);
    }

    [Fact]
    public async Task AuthorGenesis_RejectsKeyAndFailureDomainCollisionsBeforeSignerCallbacks()
    {
        var fixture = Fixture.Create();
        var duplicateRoot = fixture.Roots.ToArray();
        duplicateRoot[2] = new XPointNetworkBootstrapRootKey(
            fixture.Roots[0].RootKeyId.Span, 0, fixture.Roots[2].Ed25519PublicKey.Span,
            fixture.Roots[2].CustodyDomainHash.Span);
        await RejectAsync("DuplicateRootBoundary", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                fixture.Rebuild(roots: duplicateRoot), fixture.Signers.Take(2).ToArray()));

        var duplicateDomain = fixture.Witnesses.ToArray();
        duplicateDomain[2] = new XPointNetworkBootstrapWitnessKey(
            duplicateDomain[2].WitnessId.Span, 0, duplicateDomain[2].Ed25519PublicKey.Span,
            duplicateDomain[0].FailureDomainHash.Span);
        await RejectAsync("DuplicateWitnessBoundary", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                fixture.Rebuild(witnesses: duplicateDomain), fixture.Signers.Take(2).ToArray()));

        Assert.All(fixture.Signers, static signer => Assert.Equal(0, signer.CallCount));
    }

    [Fact]
    public async Task AuthorGenesis_RejectsUncoveredOrOversizedTimePolicyBeforeSignerCallbacks()
    {
        var fixture = Fixture.Create();

        await RejectAsync("InvalidTimePolicyInterval", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                fixture.Rebuild(timePolicyNotBefore: 99), fixture.Signers.Take(2).ToArray()));
        await RejectAsync("InvalidTimePolicyInterval", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                fixture.Rebuild(timePolicyExpires: 2_592_101), fixture.Signers.Take(2).ToArray()));

        Assert.All(fixture.Signers, static signer => Assert.Equal(0, signer.CallCount));
    }

    [Fact]
    public async Task AuthorGenesis_RejectsNonGenesisKeyGenerationsAndInvalidSourceClosureBeforeSigning()
    {
        var fixture = Fixture.Create();
        var badRoots = fixture.Roots.ToArray();
        badRoots[0] = new XPointNetworkBootstrapRootKey(
            badRoots[0].RootKeyId.Span, 1, badRoots[0].Ed25519PublicKey.Span,
            badRoots[0].CustodyDomainHash.Span);
        await RejectAsync("InvalidGenesisKeyGeneration", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                fixture.Rebuild(roots: badRoots), fixture.Signers.Take(2).ToArray()));

        var badWitnesses = fixture.Witnesses.ToArray();
        badWitnesses[0] = new XPointNetworkBootstrapWitnessKey(
            badWitnesses[0].WitnessId.Span, 1, badWitnesses[0].Ed25519PublicKey.Span,
            badWitnesses[0].FailureDomainHash.Span);
        await RejectAsync("InvalidGenesisKeyGeneration", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                fixture.Rebuild(witnesses: badWitnesses), fixture.Signers.Take(2).ToArray()));

        var duplicateEndpoint = new[]
        {
            fixture.Sources[0],
            new AccountDirectoryDts1Source(
                fixture.Sources[1].SourceId.Span,
                fixture.Sources[1].FailureFamilyHash.Span,
                fixture.Sources[0].Protocol,
                fixture.Sources[0].HostAscii,
                fixture.Sources[0].Port,
                fixture.Sources[0].TlsSpkiSha256.Span,
                fixture.Sources[0].MaximumRadiusSeconds),
        };
        await RejectAsync("InvalidBootstrapInput", () =>
            XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                fixture.Rebuild(sources: duplicateEndpoint), fixture.Signers.Take(2).ToArray()));

        Assert.All(fixture.Signers, static signer => Assert.Equal(0, signer.CallCount));
    }

    private static async Task<XPointNetworkBootstrapAuthoringException> RejectAsync(
        string code,
        Func<ValueTask<VerifiedXPointNetworkBootstrap>> action)
    {
        var error = await Assert.ThrowsAsync<XPointNetworkBootstrapAuthoringException>(
            async () => await action());
        Assert.Equal(code, error.Code);
        return error;
    }

    private sealed class Fixture
    {
        private Fixture(
            byte[] ceremonyId,
            byte[] networkId,
            XPointNetworkBootstrapRootKey[] roots,
            XPointNetworkBootstrapWitnessKey[] witnesses,
            AccountDirectoryDts1Source[] sources,
            CustodySigner[] signers,
            XPointNetworkGenesisAuthoringRequest request)
        {
            CeremonyId = ceremonyId;
            NetworkId = networkId;
            Roots = roots;
            Witnesses = witnesses;
            Sources = sources;
            Signers = signers;
            Request = request;
        }

        internal byte[] CeremonyId { get; }
        internal byte[] NetworkId { get; }
        internal XPointNetworkBootstrapRootKey[] Roots { get; }
        internal XPointNetworkBootstrapWitnessKey[] Witnesses { get; }
        internal AccountDirectoryDts1Source[] Sources { get; }
        internal CustodySigner[] Signers { get; }
        internal XPointNetworkGenesisAuthoringRequest Request { get; }

        internal static Fixture Create(bool reverseInputs = false)
        {
            var ceremony = Bytes(32, 0x01);
            var network = Bytes(16, 0x20);
            var rootPairs = new[] { KeyPair(0x30), KeyPair(0x31), KeyPair(0x32) };
            var roots = rootPairs.Select((pair, index) => new XPointNetworkBootstrapRootKey(
                Bytes(32, checked((byte)(0x40 + index))), 0, pair.PublicKey,
                Bytes(32, checked((byte)(0xb0 + index))))).ToArray();
            var witnesses = Enumerable.Range(0, 3).Select(index =>
            {
                var pair = KeyPair(checked((byte)(0x50 + index)));
                return new XPointNetworkBootstrapWitnessKey(
                    Bytes(32, checked((byte)(0x60 + index))), 0, pair.PublicKey,
                    Bytes(32, checked((byte)(0x70 + index))));
            }).ToArray();
            var sources = new[]
            {
                new AccountDirectoryDts1Source(Bytes(32, 0x81), Bytes(32, 0x91), 1,
                    "time-b.example", 4460, Bytes(32, 0xa1), 5),
                new AccountDirectoryDts1Source(Bytes(32, 0x80), Bytes(32, 0x90), 1,
                    "time-a.example", 4460, Bytes(32, 0xa0), 5),
            };
            var signers = roots.Select((root, index) => new CustodySigner(
                root.RootKeyId.Span, rootPairs[index], root.KeyGeneration,
                root.CustodyDomainHash.Span)).ToArray();
            var selectedRoots = reverseInputs ? roots.Reverse().ToArray() : roots;
            var selectedWitnesses = reverseInputs ? witnesses.Reverse().ToArray() : witnesses;
            var selectedSources = reverseInputs ? sources.Reverse().ToArray() : sources;
            var request = NewRequest(ceremony, network, selectedRoots, selectedWitnesses, selectedSources,
                100, 100, 34_000_000, 100, 2_592_000);
            return new Fixture(ceremony, network, roots, witnesses, sources, signers, request);
        }

        internal XPointNetworkGenesisAuthoringRequest Rebuild(
            IReadOnlyList<XPointNetworkBootstrapRootKey>? roots = null,
            IReadOnlyList<XPointNetworkBootstrapWitnessKey>? witnesses = null,
            IReadOnlyList<AccountDirectoryDts1Source>? sources = null,
            ulong? timePolicyNotBefore = null,
            ulong? timePolicyExpires = null) =>
            NewRequest(CeremonyId, NetworkId, roots ?? Roots, witnesses ?? Witnesses, sources ?? Sources,
                100, 100, 34_000_000, timePolicyNotBefore ?? 100, timePolicyExpires ?? 2_592_000);

        private static XPointNetworkGenesisAuthoringRequest NewRequest(
            byte[] ceremony,
            byte[] network,
            IReadOnlyList<XPointNetworkBootstrapRootKey> roots,
            IReadOnlyList<XPointNetworkBootstrapWitnessKey> witnesses,
            IReadOnlyList<AccountDirectoryDts1Source> sources,
            ulong issuedAt,
            ulong authorityNotBefore,
            ulong authorityExpires,
            ulong timePolicyNotBefore,
            ulong timePolicyExpires) =>
            new(
                ceremony,
                network,
                roots,
                2,
                witnesses,
                2,
                sources,
                10,
                10,
                issuedAt,
                authorityNotBefore,
                authorityExpires,
                timePolicyNotBefore,
                timePolicyExpires,
                1,
                1);
    }

    private enum SignerMode
    {
        Valid,
        InvalidSignature,
        Throw,
        WrongLength,
        Cancel,
    }

    private sealed record CapturedSigning(
        XPointNetworkRootSignaturePurpose Purpose,
        byte[] SigningInput);

    private sealed class CustodySigner : IXPointNetworkBootstrapRootSigner
    {
        private readonly byte[] id;
        private readonly KeyPair keyPair;
        private readonly byte[] custodyDomainHash;

        internal CustodySigner(
            ReadOnlySpan<byte> id,
            KeyPair keyPair,
            ulong generation,
            ReadOnlySpan<byte> custodyDomainHash)
        {
            this.id = id.ToArray();
            this.keyPair = keyPair;
            KeyGeneration = generation;
            this.custodyDomainHash = custodyDomainHash.ToArray();
        }

        public ReadOnlyMemory<byte> RootKeyId => id.ToArray();
        public ulong KeyGeneration { get; }
        public ReadOnlyMemory<byte> Ed25519PublicKey => keyPair.PublicKey.ToArray();
        public ReadOnlyMemory<byte> CustodyDomainHash => custodyDomainHash.ToArray();
        internal KeyPair Keys => keyPair;
        internal SignerMode Mode { get; set; }
        internal int CallCount { get; private set; }
        internal List<XPointNetworkRootSigningRequest> Requests { get; } = [];
        internal List<CapturedSigning> Captured { get; } = [];
        internal Memory<byte> LastOutputBuffer { get; private set; }

        public ValueTask<int> SignAsync(
            XPointNetworkRootSigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            Requests.Add(request);
            var input = request.SigningInput.ToArray();
            Captured.Add(new CapturedSigning(request.Purpose, input));
            if (Mode == SignerMode.Throw)
                throw new InvalidOperationException("custody unavailable");
            if (Mode == SignerMode.Cancel)
                throw new OperationCanceledException(cancellationToken);
            var signature = Mode == SignerMode.InvalidSignature
                ? PublicKeyAuth.SignDetached(input, KeyPair(0xee).PrivateKey)
                : PublicKeyAuth.SignDetached(input, keyPair.PrivateKey);
            signature.CopyTo(signature64);
            LastOutputBuffer = signature64;
            return ValueTask.FromResult(Mode == SignerMode.WrongLength ? 63 : 64);
        }
    }

    private sealed class ByteArrays : IComparer<byte[]>
    {
        internal static readonly ByteArrays Instance = new();
        public int Compare(byte[]? left, byte[]? right) =>
            left is null ? right is null ? 0 : -1 : right is null ? 1 : left.AsSpan().SequenceCompareTo(right);
    }

    private static KeyPair KeyPair(byte seed) => PublicKeyAuth.GenerateKeyPair(Bytes(32, seed));

    private static byte[] Bytes(int length, byte seed)
    {
        var value = new byte[length];
        for (var index = 0; index < value.Length; index++)
            value[index] = unchecked((byte)(seed + index));
        return value;
    }
}
