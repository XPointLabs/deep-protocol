using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class Xpa1PublicationAuthorizationVerifierTests
{
    [Fact]
    public void ValidThresholdAuthorization_MintsBoundDefensiveCapability()
    {
        var fixture = Fixture.Create();
        var request = fixture.CreateRequest();

        var capability = fixture.Verify(request);

        Assert.Equal(fixture.Network, capability.NetworkId.ToArray());
        Assert.Equal(request.RequestHash.ToArray(), capability.RequestHash.ToArray());
        Assert.Equal(request.OperationId.ToArray(), capability.OperationId.ToArray());
        Assert.Equal(request.LocatorHash.ToArray(), capability.LocatorHash.ToArray());
        Assert.Equal(request.ViewHash.ToArray(), capability.ViewHash.ToArray());
        Assert.Equal(request.PlacementHash.ToArray(), capability.PlacementHash.ToArray());
        Assert.Equal(fixture.Authority.AuthorityCoreReference.ToArray(), capability.AuthorityCoreReference.ToArray());
        Assert.Equal(fixture.Authority.DirectoryWitnessPolicyHash.ToArray(), capability.WitnessPolicyHash.ToArray());
        Assert.Equal(Xpa1PublicationKind.PermanentAddress, capability.PublicationKind);
        Assert.Equal(1_000UL, capability.VerifiedAtMonotonicSeconds);

        var networkCopy = capability.NetworkId;
        MemoryMarshal.AsMemory(networkCopy).Span.Fill(0);
        var xpaCopy = capability.ExactXpa1;
        MemoryMarshal.AsMemory(xpaCopy).Span.Fill(0);
        Assert.Equal(fixture.Network, capability.NetworkId.ToArray());
        Assert.NotEqual(new byte[capability.ExactXpa1.Length], capability.ExactXpa1.ToArray());
    }

    [Fact]
    public void PublicSurface_IsNonForgeableAndAcceptsNoCallerAuthoredTrustSet()
    {
        Assert.Empty(typeof(VerifiedXpa1PublicationAuthorization).GetConstructors());
        var verify = Assert.Single(typeof(Xpa1PublicationAuthorizationVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Equal("VerifyAsync", verify.Name);
        Assert.Equal(
            [typeof(Xpu1Request), typeof(VerifiedXPointNetworkAuthority),
             typeof(VerifiedAccountDirectoryFreshness), typeof(VerifiedContactServicePlacement),
             typeof(OnionTrustedTimeAuthority), typeof(CancellationToken)],
            verify.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.DoesNotContain(verify.GetParameters(), static parameter =>
            parameter.ParameterType == typeof(byte[]) ||
            typeof(Delegate).IsAssignableFrom(parameter.ParameterType) ||
            parameter.Name?.Contains("threshold", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("signer", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("key", StringComparison.OrdinalIgnoreCase) == true);
    }

    [Fact]
    public void UnknownWitness_IsRejected()
    {
        var fixture = Fixture.Create();
        var unknown = new Signer(
            Bytes(32, 0xe0), PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xe1)), Bytes(32, 0xe2));
        var request = fixture.CreateRequest(signers: [fixture.Signers[0], fixture.Signers[1], unknown]);

        AssertCode("UnknownWitness", () => fixture.Verify(request));
    }

    [Fact]
    public void BelowThreshold_IsRejected()
    {
        var fixture = Fixture.Create(witnessThreshold: 3);
        var request = fixture.CreateRequest(signers: fixture.Signers.Take(2).ToArray());

        AssertCode("WitnessThresholdNotMet", () => fixture.Verify(request));
    }

    [Fact]
    public void BadWitnessSignature_IsRejected()
    {
        var fixture = Fixture.Create();
        var request = fixture.CreateRequest(tamperSignature: true);

        AssertCode("InvalidWitnessSignature", () => fixture.Verify(request));
    }

    [Fact]
    public void StaleOrDifferentBootMonotonicReading_IsRejected()
    {
        var fixture = Fixture.Create();
        var request = fixture.CreateRequest();

        AssertCode("FreshnessExpired", () => fixture.Verify(
            request, new OnionMonotonicReading(fixture.BootId, 1_050)));
        AssertCode("MonotonicBootMismatch", () => fixture.Verify(
            request, new OnionMonotonicReading(Bytes(16, 0xd0), 1_000)));
    }

    [Fact]
    public void WrongPlacementOrView_IsRejected()
    {
        var fixture = Fixture.Create();

        var wrongPlacement = fixture.CreateRequest(placementHash: Bytes(32, 0xd1));
        AssertCode("PlacementMismatch", () => fixture.Verify(wrongPlacement));

        var wrongView = fixture.CreateRequest(viewHash: Bytes(32, 0xd2));
        AssertCode("FreshnessBindingMismatch", () => fixture.Verify(wrongView));
    }

    [Fact]
    public void WrongNetworkOrAuthorityPolicy_IsRejected()
    {
        var fixture = Fixture.Create();
        var wrongNetwork = fixture.CreateRequest(network: Bytes(16, 0xd3));
        AssertCode("NetworkMismatch", () => fixture.Verify(wrongNetwork));

        var wrongPolicyFreshness = fixture.CreateFreshness(Bytes(32, 0xd4));
        AssertCode("AuthorityBindingMismatch", () => fixture.Verify(
            fixture.CreateRequest(), freshness: wrongPolicyFreshness));
    }

    [Fact]
    public void AuthorizationFromAnotherDirectoryHead_IsRejected()
    {
        var fixture = Fixture.Create();
        var request = fixture.CreateRequest(directoryHeadHash: Bytes(32, 0xd5));

        AssertCode("FreshnessBindingMismatch", () => fixture.Verify(request));
    }

    [Fact]
    public void TamperedBodyWithRecomputedCiphertextHash_IsRejectedBeforeCapability()
    {
        var fixture = Fixture.Create();
        var exact = fixture.CreateRequest().CanonicalBytes.ToArray();
        var ciphertext = Field(exact, 21).ToArray();
        ciphertext[^1] ^= 1;
        exact = ReplaceSameLengthField(exact, 21, ciphertext);
        exact = ReplaceSameLengthField(exact, 20, SHA256.HashData(ciphertext));

        var error = Assert.Throws<ContactFormatException>(() => Xpu1Codec.Decode(exact));
        Assert.Equal("XpaAuthorizationMismatch", error.Code);
    }

    private static void AssertCode(string code, Action action)
    {
        var error = Assert.Throws<Xpa1PublicationAuthorizationException>(action);
        Assert.Equal(code, error.Code);
    }

    private sealed class Fixture
    {
        private Fixture(byte[] network, byte witnessThreshold)
        {
            Network = network;
            WitnessThreshold = witnessThreshold;
        }

        internal byte[] Network { get; }
        internal byte WitnessThreshold { get; }
        internal byte[] BootId { get; } = Bytes(16, 0xb0);
        internal byte[] ViewHash { get; } = Bytes(32, 0xb1);
        internal byte[] PlacementHash { get; } = Bytes(32, 0xb2);
        internal byte[] LocatorHash { get; } = Bytes(32, 0xb3);
        internal Signer[] Signers { get; private set; } = null!;
        internal VerifiedXPointNetworkAuthority Authority { get; private set; } = null!;
        internal VerifiedAccountDirectoryFreshness Freshness { get; private set; } = null!;
        internal VerifiedContactServicePlacement Placement { get; private set; } = null!;
        internal OnionMonotonicReading CurrentReading => new(BootId, 1_000);

        internal static Fixture Create(byte networkMarker = 0x11, byte witnessThreshold = 2)
        {
            var fixture = new Fixture(Bytes(16, networkMarker), witnessThreshold);
            fixture.Build();
            return fixture;
        }

        internal VerifiedXpa1PublicationAuthorization Verify(
            Xpu1Request request,
            OnionMonotonicReading? reading = null,
            VerifiedAccountDirectoryFreshness? freshness = null) =>
            Xpa1PublicationAuthorizationVerifier.VerifyAsync(
                request, Authority, freshness ?? Freshness, Placement,
                new OnionTrustedTimeAuthority(new FixedClock(reading ?? CurrentReading)), default)
                .AsTask().GetAwaiter().GetResult();

        internal Xpu1Request CreateRequest(
            byte[]? network = null,
            byte[]? viewHash = null,
            byte[]? placementHash = null,
            byte[]? directoryHeadHash = null,
            IReadOnlyList<Signer>? signers = null,
            bool tamperSignature = false)
        {
            network ??= Network;
            viewHash ??= ViewHash;
            placementHash ??= PlacementHash;
            signers ??= Signers;
            var operation = Bytes(32, 0xc0);
            var xir = Bytes(32, 0xc1);
            var predecessor = new byte[32];
            var ciphertext = Bytes(64, 0xc2);
            var route = RouteClosure();
            var bodyHash = Xpu1Codec.ComputeAuthorizedBodyHash(
                network, operation, viewHash, placementHash, 195, 240,
                LocatorHash, xir, 0, predecessor, ciphertext, 0, 250, route);
            var xpa = CreateXpa1(
                network, operation, LocatorHash, xir, predecessor,
                SHA256.HashData(ciphertext), bodyHash,
                directoryHeadHash ?? Freshness.ExactAdh1CoreHash.ToArray(),
                signers, tamperSignature);
            return Xpu1Codec.Decode(Xpu1Codec.Encode(
                network, operation, viewHash, placementHash, 195, 240,
                LocatorHash, xir, 0, predecessor, ciphertext, 0, 250, route, xpa));
        }

        private static byte[] RouteClosure()
        {
            var closure = ContactCodecTests.Records.RouteClosure;
            var records = new[]
            {
                closure.Xrr, closure.Xra, closure.Xrc,
                closure.Xss, closure.Pmt, closure.Pms,
            };
            var result = new byte[1 + records.Sum(record => 4 + record.CanonicalBytes.Length)];
            result[0] = 6;
            var offset = 1;
            foreach (var record in records)
            {
                BinaryPrimitives.WriteUInt32BigEndian(
                    result.AsSpan(offset), checked((uint)record.CanonicalBytes.Length));
                offset += 4;
                record.CanonicalBytes.Span.CopyTo(result.AsSpan(offset));
                offset += record.CanonicalBytes.Length;
            }
            return result;
        }

        internal VerifiedAccountDirectoryFreshness CreateFreshness(byte[]? policyOverride = null)
        {
            var policy = policyOverride ?? Authority.DirectoryWitnessPolicyHash.ToArray();
            var witnesses = Signers.Take(WitnessThreshold).Select((signer, index) =>
                new AccountDirectoryAdh1WitnessEntry(
                    signer.Id, Bytes(64, checked((byte)(0x70 + index))))).ToArray();
            var head = new AccountDirectoryAdh1(
                Network, 1, Bytes(32, 0x60), 1, Bytes(32, 0x61), Bytes(32, 0x62),
                Authority.AuthorityCoreReference.Span, policy, 100, 500, 1, witnesses);
            var exactHead = AccountDirectoryAdh1Codec.Encode(head);
            var headHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            var nonce = Bytes(32, 0x63);
            var dttReceipts = Signers.Take(WitnessThreshold).Select((signer, index) =>
                new AccountDirectoryDtt1WitnessReceipt(
                    signer.Id, Bytes(64, checked((byte)(0x80 + index))))).ToArray();
            var issuanceEpoch = AccountDirectoryDtt1IssuanceEpoch.Derive(Authority, 200, 5);
            var dtt = new AccountDirectoryDtt1(
                Network, nonce, 200, 5, headHash, head.LogGeneration,
                ViewHash, 7, Authority.AuthorityCoreReference.Span, policy,
                195, 250, issuanceEpoch.Id.Span, dttReceipts);
            var exactDtt = AccountDirectoryDtt1Codec.Encode(dtt);
            var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);
            var query = Bytes(32, 0x64);
            var proof = new AccountDirectoryAdp1(
                [1], Network, AccountDirectoryAdp1ResultKind.NonMembership, query, head,
                0, new byte[32], [], new byte[32], [], false,
                AccountDirectoryAdp1HistoryMode.ConsistencyOrGenesis, [], dttHash, null);
            var monotonic = new AccountDirectoryMonotonicRequestWindow(BootId, 990, 995, 1_000);
            return new VerifiedAccountDirectoryFreshness(
                exactHead, head, headHash, exactDtt, dttHash, [1], Bytes(32, 0x65), proof, [],
                195, 205, monotonic, 1_050, null);
        }

        private void Build()
        {
            Signers = Enumerable.Range(0, 3).Select(index => new Signer(
                Bytes(32, checked((byte)(0x40 + index))),
                PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(0x50 + index)))),
                Bytes(32, checked((byte)(0x60 + index))))).ToArray();
            Authority = CreateAuthority(Network, Signers, WitnessThreshold);
            Freshness = CreateFreshness();
            var leaseBoot = PrivacyRoutingWire.Sha256Domain(
                "Deep/XPoint/V1/monotonic-boot-id", BootId);
            var lease = new OnionTrustedTimeLease(TimeProvider.System, TimeSpan.FromMinutes(1), leaseBoot);
            var context = new VerifiedOnionNetworkContext(Network, lease, []);
            Placement = new VerifiedContactServicePlacement(
                context, ContactServiceRequestKind.PublishInvite, ContactServiceClass.InviteResolver,
                ViewHash, PlacementHash, LocatorHash, 7, 300,
                [Bytes(32, 0x91), Bytes(32, 0x92)]);
        }

        private byte[] CreateXpa1(
            byte[] network,
            byte[] operation,
            byte[] locator,
            byte[] xir,
            byte[] predecessor,
            byte[] ciphertextHash,
            byte[] bodyHash,
            byte[] directoryHeadHash,
            IReadOnlyList<Signer> signers,
            bool tamperSignature)
        {
            var fields = new List<ReadOnlyMemory<byte>>
            {
                network, Bytes(32, 0xc3), operation, locator, new byte[] { 1 },
                Bytes(32, 0xc4), Bytes(32, 0xc5), xir, U64(0), predecessor,
                ciphertextHash, U32(0), U64(250), Bytes(32, 0xc6),
                U64(190), U64(194), U64(250), directoryHeadHash,
                bodyHash, new byte[] { checked((byte)signers.Count) },
            };
            var unsigned = Write("XPA1", fields);
            var input = ContactCodec.SignatureInput(
                "Deep/ContactResolver/V1/publication-authorization", unsigned);
            var rows = signers.Select(signer =>
                (signer.Id, Signature: PublicKeyAuth.SignDetached(input, signer.Key.PrivateKey)))
                .OrderBy(static row => row.Id, ByteArrayComparer.Instance)
                .Select(static row => Join(row.Id, row.Signature)).ToArray();
            if (tamperSignature) rows[0][^1] ^= 1;
            fields.Add(Join(rows));
            return Write("XPA1", fields);
        }
    }

    private static VerifiedXPointNetworkAuthority CreateAuthority(
        byte[] network, Signer[] witnesses, byte witnessThreshold)
    {
        var root = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x20));
        var rootId = Bytes(32, 0x21);
        var sources = new[]
        {
            new AccountDirectoryDts1Source(
                Bytes(32, 0x22), Bytes(32, 0x23), 1,
                "time-a.example", 443, Bytes(32, 0x24), 1),
            new AccountDirectoryDts1Source(
                Bytes(32, 0x25), Bytes(32, 0x26), 1,
                "time-b.example", 443, Bytes(32, 0x27), 1),
        };
        var dts = new AccountDirectoryDts1(
            network, 0, new byte[32], sources, 2, 2, 30, 1,
            1, 1_000, 1, 0,
            [new AccountDirectoryDts1RootReceipt(rootId, Bytes(64, 0x28))]);
        var dtsHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(dts);
        ReadOnlyMemory<byte>[] fields = new ReadOnlyMemory<byte>[20];
        fields[0] = network;
        fields[1] = U64(0);
        fields[2] = new byte[32];
        fields[3] = new byte[] { 1 };
        fields[4] = Join(rootId, U64(0), root.PublicKey);
        fields[5] = new byte[] { 1 };
        fields[6] = U64(0);
        fields[7] = U16(1);
        fields[8] = new byte[] { checked((byte)witnesses.Length) };
        fields[9] = Join(witnesses.OrderBy(static witness => witness.Id, ByteArrayComparer.Instance)
            .Select(static witness => Join(witness.Id, U64(0), witness.Key.PublicKey, witness.FailureDomain)).ToArray());
        fields[10] = new byte[] { witnessThreshold };
        fields[11] = Reference("DTS1", dtsHash);
        fields[12] = dtsHash;
        fields[13] = U32(30);
        fields[14] = U64(1);
        fields[15] = U64(1);
        fields[16] = U64(1);
        fields[17] = U64(1_000);
        fields[18] = new byte[] { 1 };
        fields[19] = Join(rootId, Bytes(64, 0x29));
        var unsigned = XPointNetworkCodec.Parse<Xna1Record>(
            XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
        fields[19] = Join(rootId, PublicKeyAuth.SignDetached(
            XPointNetworkCrypto.ComputeSigningInput(unsigned), root.PrivateKey));
        var xna = XPointNetworkCodec.Parse<Xna1Record>(
            XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
        return new VerifiedXPointNetworkAuthority(xna, dts, [xna]);
    }

    private sealed record Signer(byte[] Id, KeyPair Key, byte[] FailureDomain);

    private sealed class FixedClock(OnionMonotonicReading reading) : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(
                reading.BootId.Span, reading.SampleSeconds));
        }
    }

    private static byte[] Write(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        var bytes = new byte[12 + fields.Sum(static field => 8 + field.Length)];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].Span.CopyTo(bytes.AsSpan(offset));
            offset += fields[index].Length;
        }
        return bytes;
    }

    private static ReadOnlySpan<byte> Field(ReadOnlySpan<byte> bytes, ushort wanted)
    {
        var count = BinaryPrimitives.ReadUInt16BigEndian(bytes[8..10]);
        var offset = 12;
        for (var index = 0; index < count; index++)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(offset, 2));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset + 4, 4)));
            offset += 8;
            if (tag == wanted) return bytes.Slice(offset, length);
            offset += length;
        }
        throw new InvalidOperationException();
    }

    private static byte[] ReplaceSameLengthField(byte[] bytes, ushort tag, byte[] replacement)
    {
        var output = bytes.ToArray();
        var offset = FieldOffset(output, tag, out var length);
        if (length != replacement.Length) throw new ArgumentException("Replacement length differs.");
        replacement.CopyTo(output, offset);
        return output;
    }

    private static int FieldOffset(ReadOnlySpan<byte> bytes, ushort wanted, out int fieldLength)
    {
        var count = BinaryPrimitives.ReadUInt16BigEndian(bytes[8..10]);
        var offset = 12;
        for (var index = 0; index < count; index++)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(offset, 2));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset + 4, 4)));
            offset += 8;
            if (tag == wanted)
            {
                fieldLength = length;
                return offset;
            }
            offset += length;
        }
        throw new InvalidOperationException();
    }

    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        var output = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        hash.CopyTo(output.AsSpan(6));
        return output;
    }

    private static byte[] Join(params byte[][] values)
    {
        var output = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }
        return output;
    }

    private static byte[] Bytes(int length, byte seed) =>
        Enumerable.Range(0, length).Select(index => unchecked((byte)(seed + index))).ToArray();
    private static byte[] U16(ushort value) { var output = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(output, value); return output; }
    private static byte[] U32(uint value) { var output = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(output, value); return output; }
    private static byte[] U64(ulong value) { var output = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(output, value); return output; }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
