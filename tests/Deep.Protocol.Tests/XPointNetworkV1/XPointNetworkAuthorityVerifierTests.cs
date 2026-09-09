using System.Buffers.Binary;
using System.Collections;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.XPointNetworkV1;

[Collection("Production artifact build")]
public sealed class XPointNetworkAuthorityVerifierTests
{
    [Fact]
    public void Verify_CreatesDefensiveCapabilityFromCompleteCryptoValidChains()
    {
        var fixture = AuthorityFixture.Create();
        var genesisBytes = fixture.Genesis.Xna.ToArray();
        var successorBytes = fixture.Successor.Xna.ToArray();
        var genesisDtsBytes = fixture.Genesis.Dts.ToArray();
        var successorDtsBytes = fixture.Successor.Dts.ToArray();

        var verified = XPointNetworkAuthorityVerifier.Verify(
            fixture.Pin,
            new ReadOnlyMemory<byte>[] { genesisBytes, successorBytes },
            new ReadOnlyMemory<byte>[] { genesisDtsBytes, successorDtsBytes });

        Assert.Equal((ulong)1, verified.AuthorityGeneration);
        Assert.Equal((ulong)1, verified.Dts1PolicyGeneration);
        Assert.Equal(fixture.Network, verified.NetworkId.ToArray());
        Assert.Equal(fixture.Successor.CoreHash, verified.AuthorityCoreHash.ToArray());
        Assert.Equal(fixture.Successor.PolicyHash, verified.TimeSourcePolicyHash.ToArray());
        Assert.Equal(2, verified.RootThreshold);
        Assert.Equal(2, verified.RootKeys.Count);
        Assert.Equal(2, verified.WitnessThreshold);
        Assert.Equal(3, verified.WitnessKeys.Count);

        genesisBytes.AsSpan().Fill(0);
        successorBytes.AsSpan().Fill(0);
        genesisDtsBytes.AsSpan().Fill(0);
        successorDtsBytes.AsSpan().Fill(0);
        var networkCopy = verified.NetworkId.ToArray();
        var rootIdCopy = verified.RootKeys[0].Id.ToArray();
        networkCopy.AsSpan().Fill(0);
        rootIdCopy.AsSpan().Fill(0);

        Assert.Equal(fixture.Network, verified.NetworkId.ToArray());
        Assert.Equal(fixture.Successor.Roots[0].Id, verified.RootKeys[0].Id.ToArray());
    }

    [Fact]
    public void Verify_RejectsPinSubstitutionAndIncompletePositionalClosure()
    {
        var fixture = AuthorityFixture.Create();
        Reject("GenesisPinMismatch", fixture, new XPointNetworkGenesisPin(fixture.Network, Bytes(32, 0xee)));
        Reject("NetworkMismatch", fixture, new XPointNetworkGenesisPin(Bytes(16, 0xee), fixture.Genesis.CoreHash));

        var error = Assert.Throws<XPointNetworkAuthorityVerificationException>(() =>
            XPointNetworkAuthorityVerifier.Verify(
                fixture.Pin,
                new ReadOnlyMemory<byte>[] { fixture.Genesis.Xna, fixture.Successor.Xna },
                new ReadOnlyMemory<byte>[] { fixture.Genesis.Dts }));
        Assert.Equal("IncompleteAuthorityClosure", error.Code);
    }

    [Fact]
    public void Verify_RejectsSameGenerationChangedAuthorityAndSkippedAuthorityGeneration()
    {
        var fixture = AuthorityFixture.Create();
        var sameGeneration = fixture.BuildPair(
            authorityGeneration: 0,
            authorityPredecessor: new byte[32],
            policyGeneration: 1,
            policyPredecessor: fixture.Genesis.PolicyHash,
            currentRoots: fixture.Genesis.Roots,
            xnaSigners: fixture.Genesis.Roots,
            rootAuthorityGeneration: 0);
        RejectSecond(fixture, sameGeneration, "GenesisReleasePinMismatch");

        var generationTwoRoots = fixture.CreateRoots(0x70, 0x90, 2);
        var skipped = fixture.BuildPair(
            authorityGeneration: 2,
            authorityPredecessor: fixture.Genesis.CoreHash,
            policyGeneration: 1,
            policyPredecessor: fixture.Genesis.PolicyHash,
            currentRoots: generationTwoRoots,
            xnaSigners: fixture.Genesis.Roots,
            rootAuthorityGeneration: 2);
        RejectSecond(fixture, skipped, "GenerationGap");
    }

    [Fact]
    public void Verify_RejectsWrongAuthorityPredecessorSignerAndThreshold()
    {
        var fixture = AuthorityFixture.Create();
        var wrongPredecessor = fixture.BuildPair(
            1, Bytes(32, 0xe1), 1, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Genesis.Roots, rootAuthorityGeneration: 1);
        RejectSecond(fixture, wrongPredecessor, "PredecessorMismatch");

        var attackers = fixture.CreateRoots(0xa0, 0xb0, 9);
        var wrongSignerRows = fixture.Genesis.Roots
            .Select((root, index) => new ReceiptSigner(root.Id, attackers[index].Key.PrivateKey))
            .ToArray();
        var wrongSigner = fixture.BuildPair(
            1, fixture.Genesis.CoreHash, 1, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Genesis.Roots,
            xnaReceiptSigners: wrongSignerRows, rootAuthorityGeneration: 1);
        RejectSecond(fixture, wrongSigner, "InvalidSignature");

        var oneSignature = fixture.BuildPair(
            1, fixture.Genesis.CoreHash, 1, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Genesis.Roots,
            xnaReceiptSigners: [ReceiptSigner.Valid(fixture.Genesis.Roots[0])],
            rootAuthorityGeneration: 1);
        RejectSecond(fixture, oneSignature, "WrongAuthorizingThreshold");
    }

    [Fact]
    public void Verify_RejectsSkippedOrMismatchedDtsPolicyPredecessor()
    {
        var fixture = AuthorityFixture.Create();
        var skipped = fixture.BuildPair(
            1, fixture.Genesis.CoreHash, 2, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Genesis.Roots, rootAuthorityGeneration: 1);
        RejectSecond(fixture, skipped, "DtsPredecessorMismatch");

        var wrongPredecessor = fixture.BuildPair(
            1, fixture.Genesis.CoreHash, 1, Bytes(32, 0xd2),
            fixture.Successor.Roots, fixture.Genesis.Roots, rootAuthorityGeneration: 1);
        RejectSecond(fixture, wrongPredecessor, "DtsPredecessorMismatch");
    }

    [Fact]
    public void Verify_RejectsDtsWrongSignerGenerationThresholdNetworkAndHash()
    {
        var fixture = AuthorityFixture.Create();
        var attacker = fixture.CreateRoots(0xa0, 0xb0, 9)[0];
        var wrongDtsSigners = fixture.Successor.Roots
            .Select(root => new ReceiptSigner(root.Id, attacker.Key.PrivateKey))
            .ToArray();
        var wrongSigner = fixture.BuildPair(
            1, fixture.Genesis.CoreHash, 1, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Genesis.Roots,
            dtsReceiptSigners: wrongDtsSigners, rootAuthorityGeneration: 1);
        RejectSecond(fixture, wrongSigner, "InvalidDtsSignature");

        var wrongGeneration = fixture.BuildPair(
            1, fixture.Genesis.CoreHash, 1, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Genesis.Roots, rootAuthorityGeneration: 7);
        RejectSecond(fixture, wrongGeneration, "DtsAuthorityGenerationMismatch");

        var belowThreshold = fixture.BuildPair(
            1, fixture.Genesis.CoreHash, 1, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Genesis.Roots,
            dtsReceiptSigners: [ReceiptSigner.Valid(fixture.Successor.Roots[0])],
            rootAuthorityGeneration: 1);
        RejectSecond(fixture, belowThreshold, "WrongDtsThreshold");

        var otherNetwork = Bytes(16, 0xc3);
        var wrongNetwork = fixture.BuildPair(
            1, fixture.Genesis.CoreHash, 1, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Genesis.Roots,
            rootAuthorityGeneration: 1, network: otherNetwork);
        RejectSecond(fixture, wrongNetwork, "NetworkMismatch");

        var wrongHash = fixture.BuildPair(
            1, fixture.Genesis.CoreHash, 1, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Genesis.Roots,
            rootAuthorityGeneration: 1, xnaPolicyHash: Bytes(32, 0xc4));
        RejectSecond(fixture, wrongHash, "InvalidTimeSourcePolicy");

        var wrongReference = fixture.BuildPair(
            1, fixture.Genesis.CoreHash, 1, fixture.Genesis.PolicyHash,
            fixture.Successor.Roots, fixture.Genesis.Roots,
            rootAuthorityGeneration: 1, xnaReferenceHash: Bytes(32, 0xc5));
        RejectSecond(fixture, wrongReference, "DtsPolicyReferenceMismatch");
    }

    [Fact]
    public void Verify_OwnsAllInputsBeforeParsingThem()
    {
        var fixture = AuthorityFixture.Create();
        var first = fixture.Genesis.Xna.ToArray();
        var second = fixture.Successor.Xna.ToArray();
        var mutating = new MutatingReadOnlyList(first, second);

        var verified = XPointNetworkAuthorityVerifier.Verify(
            fixture.Pin,
            mutating,
            new ReadOnlyMemory<byte>[] { fixture.Genesis.Dts, fixture.Successor.Dts });

        Assert.Equal((ulong)1, verified.AuthorityGeneration);
        Assert.All(first, value => Assert.Equal(0, value));
    }

    [Fact]
    public void CapabilityAndKeyFactsHaveNoPublicConstructionPath()
    {
        Assert.True(typeof(VerifiedXPointNetworkAuthority).IsSealed);
        Assert.Empty(typeof(VerifiedXPointNetworkAuthority).GetConstructors());
        Assert.Empty(typeof(XPointNetworkRootKey).GetConstructors());
        Assert.Empty(typeof(XPointNetworkWitnessKey).GetConstructors());

        var method = Assert.Single(typeof(XPointNetworkAuthorityVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Equal("Verify", method.Name);
        Assert.DoesNotContain(method.GetParameters(), parameter =>
            typeof(Delegate).IsAssignableFrom(parameter.ParameterType) ||
            parameter.ParameterType.Name.Contains("Verifier", StringComparison.Ordinal) ||
            parameter.ParameterType.Name.Contains("Resolver", StringComparison.Ordinal) ||
            parameter.ParameterType.Name.Contains("KeyMap", StringComparison.Ordinal));
    }

    [Fact]
    public void ProductionArtifactHasNoFriendAssemblySeam()
    {
        var root = FindRepositoryRoot();
        var output = Path.Combine(Path.GetTempPath(), "deep-xna-production-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(output);
        try
        {
            var start = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            foreach (var argument in new[]
            {
                "build", Path.Combine(root, "src", "Deep.Protocol", "Deep.Protocol.csproj"),
                "-c", "Release", "--no-restore", "-p:RecoveryTestSeam=false", "-o", output,
            }) start.ArgumentList.Add(argument);
            using var process = Process.Start(start) ?? throw new InvalidOperationException("dotnet build did not start.");
            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert.True(process.ExitCode == 0, stdout + Environment.NewLine + stderr);

            using var stream = File.OpenRead(Path.Combine(output, "Deep.Protocol.dll"));
            using var pe = new PEReader(stream);
            var metadata = pe.GetMetadataReader();
            Assert.DoesNotContain(metadata.GetAssemblyDefinition().GetCustomAttributes(), handle =>
                AttributeTypeName(metadata, handle) == "System.Runtime.CompilerServices.InternalsVisibleToAttribute");
        }
        finally
        {
            Directory.Delete(output, recursive: true);
        }
    }

    private static void Reject(string code, AuthorityFixture fixture, XPointNetworkGenesisPin pin)
    {
        var error = Assert.Throws<XPointNetworkAuthorityVerificationException>(() =>
            XPointNetworkAuthorityVerifier.Verify(
                pin,
                new ReadOnlyMemory<byte>[] { fixture.Genesis.Xna, fixture.Successor.Xna },
                new ReadOnlyMemory<byte>[] { fixture.Genesis.Dts, fixture.Successor.Dts }));
        Assert.Equal(code, error.Code);
    }

    private static void RejectSecond(AuthorityFixture fixture, AuthorityPair successor, string code)
    {
        var error = Assert.Throws<XPointNetworkAuthorityVerificationException>(() =>
            XPointNetworkAuthorityVerifier.Verify(
                fixture.Pin,
                new ReadOnlyMemory<byte>[] { fixture.Genesis.Xna, successor.Xna },
                new ReadOnlyMemory<byte>[] { fixture.Genesis.Dts, successor.Dts }));
        Assert.Equal(code, error.Code);
    }

    private static string AttributeTypeName(MetadataReader metadata, CustomAttributeHandle handle)
    {
        var attribute = metadata.GetCustomAttribute(handle);
        if (attribute.Constructor.Kind != HandleKind.MemberReference) return string.Empty;
        var member = metadata.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
        if (member.Parent.Kind != HandleKind.TypeReference) return string.Empty;
        var type = metadata.GetTypeReference((TypeReferenceHandle)member.Parent);
        return metadata.GetString(type.Namespace) + "." + metadata.GetString(type.Name);
    }

    private static string FindRepositoryRoot()
    {
        for (var path = Directory.GetCurrentDirectory(); path is not null; path = Directory.GetParent(path)?.FullName)
            if (File.Exists(Path.Combine(path, "Deep.Protocol.slnx"))) return path;
        throw new DirectoryNotFoundException("Deep.Protocol.slnx");
    }

    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();

    private sealed class MutatingReadOnlyList(byte[] first, byte[] second) : IReadOnlyList<ReadOnlyMemory<byte>>
    {
        public int Count => 2;
        public ReadOnlyMemory<byte> this[int index]
        {
            get
            {
                if (index == 1) first.AsSpan().Fill(0);
                return index switch { 0 => first, 1 => second, _ => throw new ArgumentOutOfRangeException(nameof(index)) };
            }
        }

        public IEnumerator<ReadOnlyMemory<byte>> GetEnumerator() => throw new NotSupportedException();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed record SigningRoot(byte[] Id, KeyPair Key, ulong Generation);
    private sealed record ReceiptSigner(byte[] Id, byte[] PrivateKey)
    {
        internal static ReceiptSigner Valid(SigningRoot root) => new(root.Id, root.Key.PrivateKey);
    }

    private sealed record AuthorityPair(
        byte[] Xna,
        byte[] Dts,
        byte[] CoreHash,
        byte[] PolicyHash,
        SigningRoot[] Roots);

    private sealed class AuthorityFixture
    {
        private AuthorityFixture(byte[] network, SigningRoot[] genesisRoots, SigningRoot[] successorRoots)
        {
            Network = network;
            Genesis = BuildPair(0, new byte[32], 0, new byte[32], genesisRoots, genesisRoots, rootAuthorityGeneration: 0);
            Successor = BuildPair(1, Genesis.CoreHash, 1, Genesis.PolicyHash, successorRoots, genesisRoots, rootAuthorityGeneration: 1);
            Pin = new XPointNetworkGenesisPin(Network, Genesis.CoreHash);
        }

        internal byte[] Network { get; }
        internal AuthorityPair Genesis { get; }
        internal AuthorityPair Successor { get; }
        internal XPointNetworkGenesisPin Pin { get; }

        internal static AuthorityFixture Create()
        {
            var fixtureNetwork = Bytes(16, 0x11);
            var fixture = new AuthorityFixture(
                fixtureNetwork,
                CreateRootSet(0x10, 0x30, 0),
                CreateRootSet(0x50, 0x60, 1));
            return fixture;
        }

        internal SigningRoot[] CreateRoots(byte idSeed, byte keySeed, ulong generation) =>
            CreateRootSet(idSeed, keySeed, generation);

        internal AuthorityPair BuildPair(
            ulong authorityGeneration,
            byte[] authorityPredecessor,
            ulong policyGeneration,
            byte[] policyPredecessor,
            SigningRoot[] currentRoots,
            SigningRoot[] xnaSigners,
            IReadOnlyList<ReceiptSigner>? xnaReceiptSigners = null,
            IReadOnlyList<ReceiptSigner>? dtsReceiptSigners = null,
            ulong? rootAuthorityGeneration = null,
            byte[]? network = null,
            byte[]? xnaPolicyHash = null,
            byte[]? xnaReferenceHash = null)
        {
            var selectedNetwork = network ?? Network;
            var dts = BuildDts(
                selectedNetwork,
                policyGeneration,
                policyPredecessor,
                rootAuthorityGeneration ?? authorityGeneration,
                dtsReceiptSigners ?? currentRoots.Select(ReceiptSigner.Valid).ToArray());
            var dtsRecord = AccountDirectoryDts1Codec.Decode(dts);
            var policyHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(dtsRecord);
            var xna = BuildXna(
                selectedNetwork,
                authorityGeneration,
                authorityPredecessor,
                currentRoots,
                rootThreshold: 2,
                xnaReferenceHash ?? policyHash,
                xnaPolicyHash ?? policyHash,
                xnaReceiptSigners ?? xnaSigners.Select(ReceiptSigner.Valid).ToArray());
            var xnaRecord = XPointNetworkCodec.Parse<Xna1Record>(xna);
            return new AuthorityPair(xna, dts, xnaRecord.CoreHash.ToArray(), policyHash, currentRoots);
        }

        private static byte[] BuildDts(
            byte[] network,
            ulong policyGeneration,
            byte[] predecessorPolicyHash,
            ulong rootAuthorityGeneration,
            IReadOnlyList<ReceiptSigner> signers)
        {
            var sources = new[]
            {
                new AccountDirectoryDts1Source(Bytes(32, 0x10), Bytes(32, 0x20), 1,
                    "time-a.example", 443, Bytes(32, 0x30), 5),
                new AccountDirectoryDts1Source(Bytes(32, 0x11), Bytes(32, 0x21), 1,
                    "time-b.example", 443, Bytes(32, 0x31), 5),
            };
            var placeholders = signers
                .OrderBy(static signer => signer.Id, ByteArrayComparer.Instance)
                .Select(static signer => new AccountDirectoryDts1RootReceipt(signer.Id, Bytes(64, 0xaa)))
                .ToArray();
            var unsigned = new AccountDirectoryDts1(
                network, policyGeneration, predecessorPolicyHash, sources,
                2, 2, 30, 5, 100, 900, 1, rootAuthorityGeneration, placeholders);
            var signingInput = AccountDirectoryCrypto.ComputeDts1SigningInput(unsigned);
            var receipts = signers
                .OrderBy(static signer => signer.Id, ByteArrayComparer.Instance)
                .Select(signer => new AccountDirectoryDts1RootReceipt(
                    signer.Id, PublicKeyAuth.SignDetached(signingInput, signer.PrivateKey)))
                .ToArray();
            return AccountDirectoryDts1Codec.Encode(new AccountDirectoryDts1(
                network, policyGeneration, predecessorPolicyHash, sources,
                2, 2, 30, 5, 100, 900, 1, rootAuthorityGeneration, receipts));
        }

        private static byte[] BuildXna(
            byte[] network,
            ulong generation,
            byte[] predecessor,
            SigningRoot[] currentRoots,
            byte rootThreshold,
            byte[] dtsReferenceHash,
            byte[] policyHash,
            IReadOnlyList<ReceiptSigner> signers)
        {
            ReadOnlyMemory<byte>[] fields = new ReadOnlyMemory<byte>[20];
            fields[0] = network;
            fields[1] = U64(generation);
            fields[2] = predecessor;
            fields[3] = new byte[] { checked((byte)currentRoots.Length) };
            fields[4] = RootEntries(currentRoots);
            fields[5] = new byte[] { rootThreshold };
            fields[6] = U64(generation);
            fields[7] = U16(1);
            fields[8] = new byte[] { 3 };
            fields[9] = WitnessEntries(generation);
            fields[10] = new byte[] { 2 };
            fields[11] = XPointNetworkCodec.EncodeCoreReference("DTS1", dtsReferenceHash);
            fields[12] = policyHash;
            fields[13] = U32(10);
            fields[14] = U64(1);
            fields[15] = U64(generation == 0 ? 100UL : 200UL);
            fields[16] = U64(generation == 0 ? 100UL : 200UL);
            fields[17] = U64(generation == 0 ? 1_000UL : 900UL);
            var orderedSigners = signers.OrderBy(static signer => signer.Id, ByteArrayComparer.Instance).ToArray();
            fields[18] = new byte[] { checked((byte)orderedSigners.Length) };
            fields[19] = SignatureEntries(orderedSigners.Select(static (signer, index) =>
                (signer.Id, Bytes(64, checked((byte)(0xbb + index))))).ToArray());
            var provisional = XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
            var signingInput = XPointNetworkCrypto.ComputeSigningInput(provisional);
            fields[19] = SignatureEntries(orderedSigners.Select(signer =>
                (signer.Id, PublicKeyAuth.SignDetached(signingInput, signer.PrivateKey))).ToArray());
            return XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields);
        }

        private static SigningRoot[] CreateRootSet(byte idSeed, byte keySeed, ulong generation) =>
        [
            new SigningRoot(Bytes(32, idSeed), PublicKeyAuth.GenerateKeyPair(Bytes(32, keySeed)), generation),
            new SigningRoot(Bytes(32, checked((byte)(idSeed + 1))), PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(keySeed + 1)))), generation),
        ];

        private static byte[] RootEntries(IEnumerable<SigningRoot> roots)
        {
            var ordered = roots.OrderBy(static root => root.Id, ByteArrayComparer.Instance).ToArray();
            var output = new byte[ordered.Length * 72];
            for (var index = 0; index < ordered.Length; index++)
            {
                ordered[index].Id.CopyTo(output, index * 72);
                BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(index * 72 + 32), ordered[index].Generation);
                ordered[index].Key.PublicKey.CopyTo(output, index * 72 + 40);
            }
            return output;
        }

        private static byte[] WitnessEntries(ulong generation)
        {
            var output = new byte[3 * 104];
            for (var index = 0; index < 3; index++)
            {
                Bytes(32, checked((byte)(0x80 + index))).CopyTo(output, index * 104);
                BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(index * 104 + 32), generation);
                PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(0xc0 + index)))).PublicKey.CopyTo(output, index * 104 + 40);
                Bytes(32, checked((byte)(0xe0 + index))).CopyTo(output, index * 104 + 72);
            }
            return output;
        }

        private static byte[] SignatureEntries(IReadOnlyList<(byte[] Id, byte[] Signature)> values)
        {
            var output = new byte[values.Count * 96];
            for (var index = 0; index < values.Count; index++)
            {
                values[index].Id.CopyTo(output, index * 96);
                values[index].Signature.CopyTo(output, index * 96 + 32);
            }
            return output;
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
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
