using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Tests.XPointNetworkV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class ContactNetworkAuthorityVerifierTests
{
    [Fact]
    public async Task ProposalAuthority_DoesNotTrustSelectionUntilThresholdPmsIsBound()
    {
        var fixture = Fixture.Create();

        var proposal = await fixture.VerifyProposalAsync();
        var bound = await ContactNetworkAuthorityVerifier.BindSelectionAsync(
            proposal, fixture.Pms.CanonicalBytes, default);

        Assert.Equal(fixture.Network, proposal.NetworkId.ToArray());
        Assert.Equal(ContactCodec.ArtifactReference("PMT2", fixture.Pmt).CanonicalBytes.ToArray(),
            proposal.Pmt2ArtifactReference.ToArray());
        Assert.Equal(fixture.Identity.VerifiedRecipient.Certificate.DeviceId.ToArray(),
            proposal.RecipientDeviceId.ToArray());
        Assert.Equal(fixture.Pms.ArtifactHash.ToArray(), bound.Pms2ArtifactHash.ToArray());
    }

    [Fact]
    public async Task ProposalAuthority_ExpiredFreshnessFailsBeforeRouteProposal()
    {
        var fixture = Fixture.Create();
        var clock = new CountingClock(new OnionMonotonicReading(
            fixture.BootId, fixture.Freshness.FreshnessDeadlineMonotonicSeconds));

        var error = await Assert.ThrowsAsync<ContactNetworkAuthorityVerificationException>(() =>
            fixture.VerifyProposalAsync(clock: clock).AsTask());

        Assert.Equal("FreshnessExpired", error.Code);
    }

    [Fact]
    public async Task ExactVerifiedClosure_MintsDefensivePublicCapability()
    {
        var fixture = Fixture.Create();

        var capability = await fixture.VerifyAsync();

        Assert.Equal(fixture.Network, capability.NetworkId.ToArray());
        Assert.Equal(fixture.Authority.AuthorityCoreReference.ToArray(), capability.AuthorityCoreReference.ToArray());
        Assert.Equal(fixture.XnvReference, capability.Xnv1CoreReference.ToArray());
        Assert.Equal(fixture.XnhReference, capability.Xnh1CoreReference.ToArray());
        Assert.Equal(fixture.Freshness.ExactAdh1CoreReference.ToArray(), capability.Adh1CoreReference.ToArray());
        Assert.Equal(ContactCodec.ArtifactReference("PMT2", fixture.Pmt).CanonicalBytes.ToArray(),
            capability.Pmt2ArtifactReference.ToArray());
        Assert.Equal(fixture.Pms.ArtifactHash.ToArray(), capability.Pms2ArtifactHash.ToArray());
        Assert.Equal(fixture.Identity.VerifiedRecipient.Certificate.DeviceId.ToArray(), capability.RecipientDeviceId.ToArray());
        Assert.Equal(29UL, capability.TrustedLowerUnixSeconds);
        Assert.Equal(30UL, capability.TrustedUpperUnixSeconds);

        var copy = capability.Pms2ArtifactHash;
        MemoryMarshal.AsMemory(copy).Span.Fill(0);
        Assert.Equal(fixture.Pms.ArtifactHash.ToArray(), capability.Pms2ArtifactHash.ToArray());
    }

    [Fact]
    public void PublicSurface_HasStagedSafeProducersAndNoForgeableConstructor()
    {
        Assert.Empty(typeof(VerifiedContactNetworkAuthority).GetConstructors());
        Assert.Empty(typeof(VerifiedContactRouteProposalAuthority).GetConstructors());
        var methods = typeof(ContactNetworkAuthorityVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly);
        Assert.Equal(
            [nameof(ContactNetworkAuthorityVerifier.BindSelectionAsync),
             nameof(ContactNetworkAuthorityVerifier.VerifyAsync),
             nameof(ContactNetworkAuthorityVerifier.VerifyProposalAsync)],
            methods.Select(static method => method.Name)
                .OrderBy(static name => name, StringComparer.Ordinal).ToArray());
        var method = Assert.Single(methods,
            static candidate => candidate.Name == nameof(ContactNetworkAuthorityVerifier.VerifyAsync));
        Assert.Equal(
            [typeof(VerifiedXPointNetworkAuthority), typeof(VerifiedOnionNetworkContext),
             typeof(VerifiedAccountDirectoryFreshness), typeof(VerifiedDevice),
             typeof(CurrentlyAuthoritativeDca1), typeof(ReadOnlyMemory<byte>),
             typeof(ReadOnlyMemory<byte>), typeof(ReadOnlyMemory<byte>),
             typeof(ReadOnlyMemory<byte>), typeof(ReadOnlyMemory<byte>),
             typeof(OnionTrustedTimeAuthority), typeof(CancellationToken)],
            method.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        foreach (var candidate in methods)
        {
            Assert.DoesNotContain(candidate.GetParameters(), static parameter =>
                parameter.Name?.Contains("key", StringComparison.OrdinalIgnoreCase) == true ||
                parameter.Name?.Contains("threshold", StringComparison.OrdinalIgnoreCase) == true ||
                parameter.ParameterType == typeof(bool) ||
                typeof(Delegate).IsAssignableFrom(parameter.ParameterType));
        }
    }

    [Fact]
    public async Task MalformedPms_IsRejectedBeforeClockCallback()
    {
        var fixture = Fixture.Create();
        var clock = new CountingClock(new OnionMonotonicReading(fixture.BootId, 1_003));

        var error = await Assert.ThrowsAsync<ContactNetworkAuthorityVerificationException>(() =>
            fixture.VerifyAsync(exactPms2: new byte[499], clock: clock).AsTask());

        Assert.Equal("ArtifactSizeInvalid", error.Code);
        Assert.Equal(0, clock.ReadCount);
    }

    [Fact]
    public async Task CrossNetworkPms_IsRejected()
    {
        var fixture = Fixture.Create();
        var changed = fixture.BuildPms(network: Bytes(16, 0xe1));

        await AssertCodeAsync("PmsBindingMismatch", () => fixture.VerifyAsync(exactPms2: changed.CanonicalBytes));
    }

    [Fact]
    public async Task ChangedExactViewAtSameProtectedHead_IsRejectedAsForkInput()
    {
        var fixture = Fixture.Create();
        var fork = fixture.ExactXnv.ToArray();
        fork[^1] ^= 1;

        await AssertCodeAsync("ExactClosureMismatch", () => fixture.VerifyAsync(exactXnv1: fork));
    }

    [Fact]
    public async Task WrongPmtReference_IsRejected()
    {
        var fixture = Fixture.Create();
        var changed = fixture.BuildPms(pmtReference: Reference("PMT2", Bytes(32, 0xe2)));

        await AssertCodeAsync("PmsBindingMismatch", () => fixture.VerifyAsync(exactPms2: changed.CanonicalBytes));
    }

    [Fact]
    public async Task PartialTrustedIntervalCoverage_IsRejected()
    {
        var fixture = Fixture.Create();
        var changed = fixture.BuildPms(notBefore: 30);

        await AssertCodeAsync("TrustedTimeIntervalNotCovered", () =>
            fixture.VerifyAsync(exactPms2: changed.CanonicalBytes));
    }

    [Fact]
    public async Task ReceiptOutsideExactWitnessSet_CannotMeetThreshold()
    {
        var fixture = Fixture.Create();
        var unknown = new ContactCodecSecurityTests.CryptoDcrFixture.Witness(
            Bytes(32, 0xe3), PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xe4)), Bytes(32, 0xe5));
        var changed = fixture.BuildPms(signers: [fixture.Witnesses[0], unknown]);

        await AssertCodeAsync("UnknownWitness", () => fixture.VerifyAsync(exactPms2: changed.CanonicalBytes));
    }

    [Fact]
    public async Task BelowExactWitnessThreshold_IsRejected()
    {
        var fixture = Fixture.Create(witnessThreshold: 3);

        await AssertCodeAsync("WitnessThresholdNotMet", () => fixture.VerifyAsync());
    }

    [Fact]
    public async Task RepeatedWitnessFailureDomain_IsRejected()
    {
        var fixture = Fixture.Create(repeatWitnessFailureDomain: true);

        await AssertCodeAsync("WitnessFailureDomainRepeated", () => fixture.VerifyAsync());
    }

    [Fact]
    public async Task ExpiredOrWrongBootFreshness_IsRejected()
    {
        var fixture = Fixture.Create();
        await AssertCodeAsync("FreshnessExpired", () => fixture.VerifyAsync(
            clock: new CountingClock(new OnionMonotonicReading(fixture.BootId, fixture.Freshness.FreshnessDeadlineMonotonicSeconds))));
        await AssertCodeAsync("FreshnessExpired", () => fixture.VerifyAsync(
            clock: new CountingClock(new OnionMonotonicReading(Bytes(16, 0xe6), 1_003))));
    }

    private static async Task AssertCodeAsync(
        string code,
        Func<ValueTask<VerifiedContactNetworkAuthority>> action)
    {
        var error = await Assert.ThrowsAsync<ContactNetworkAuthorityVerificationException>(() => action().AsTask());
        Assert.Equal(code, error.Code);
    }

    internal sealed class Fixture
    {
        private Fixture(
            ContactCodecSecurityTests.CryptoDcrFixture identity,
            byte witnessThreshold,
            bool repeatWitnessFailureDomain,
            bool repeatReplicaFailureDomain)
        {
            Identity = identity;
            Witnesses = identity.NetworkWitnesses.ToArray();
            Network = identity.NetworkAuthority.NetworkId.ToArray();
            Authority = witnessThreshold == identity.NetworkAuthority.WitnessThreshold && !repeatWitnessFailureDomain
                ? identity.NetworkAuthority
                : BuildAuthority(Network, Witnesses, witnessThreshold, repeatWitnessFailureDomain);
            BootId = Bytes(16, 0xa1);

            ExactXnv = BuildXnv();
            var view = XPointNetworkCodec.Parse<Xnv1Record>(ExactXnv);
            XnvReference = XPointNetworkCodec.EncodeCoreReference("XNV1", view.CoreHash.Span);
            ExactXnh = BuildXnh(view);
            var head = XPointNetworkCodec.Parse<Xnh1Record>(ExactXnh);
            XnhReference = XPointNetworkCodec.EncodeCoreReference("XNH1", head.CoreHash.Span);

            Freshness = BuildFreshness(view);
            Pmt = BuildPmt(view);
            Pms = BuildPms();
            ReplicaIdentities = Rows(Pmt.Field(9).Span, 136)
                .Select((row, index) => new ReplicaIdentity(
                    row[..32],
                    PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(0xb0 + index)))),
                    repeatReplicaFailureDomain && index == 1
                        ? Bytes(32, 0xc0)
                        : Bytes(32, checked((byte)(0xc0 + index)))))
                .ToArray();
            CurrentNetwork = BuildCurrentNetwork(view, head);
        }

        internal ContactCodecSecurityTests.CryptoDcrFixture Identity { get; }
        internal VerifiedXPointNetworkAuthority Authority { get; }
        internal ContactCodecSecurityTests.CryptoDcrFixture.Witness[] Witnesses { get; }
        internal byte[] Network { get; }
        internal byte[] BootId { get; }
        internal byte[] ExactXnv { get; }
        internal byte[] ExactXnh { get; }
        internal byte[] XnvReference { get; }
        internal byte[] XnhReference { get; }
        internal VerifiedAccountDirectoryFreshness Freshness { get; }
        internal ContactRecord Pmt { get; }
        internal ContactRecord Pms { get; }
        internal ReplicaIdentity[] ReplicaIdentities { get; }
        internal VerifiedOnionNetworkContext CurrentNetwork { get; }

        internal static Fixture Create(
            byte witnessThreshold = 2,
            bool repeatWitnessFailureDomain = false,
            bool repeatReplicaFailureDomain = false) =>
            new(ContactCodecSecurityTests.CryptoDcrFixture.Create(), witnessThreshold,
                repeatWitnessFailureDomain, repeatReplicaFailureDomain);

        internal ValueTask<VerifiedContactNetworkAuthority> VerifyAsync(
            ReadOnlyMemory<byte>? exactXnv1 = null,
            ReadOnlyMemory<byte>? exactPms2 = null,
            CountingClock? clock = null) =>
            ContactNetworkAuthorityVerifier.VerifyAsync(
                Authority, CurrentNetwork, Freshness, Identity.VerifiedRecipient, Identity.Authorization,
                exactXnv1 ?? ExactXnv, ExactXnh, Freshness.ExactAdh1, Pmt.CanonicalBytes,
                exactPms2 ?? Pms.CanonicalBytes,
                new OnionTrustedTimeAuthority(clock ?? new CountingClock(
                    new OnionMonotonicReading(BootId, 1_003))), default);

        internal ValueTask<VerifiedContactRouteProposalAuthority> VerifyProposalAsync(
            ReadOnlyMemory<byte>? exactXnv1 = null,
            ReadOnlyMemory<byte>? exactPmt2 = null,
            CountingClock? clock = null) =>
            ContactNetworkAuthorityVerifier.VerifyProposalAsync(
                Authority, CurrentNetwork, Freshness, Identity.VerifiedRecipient,
                Identity.Authorization, exactXnv1 ?? ExactXnv, ExactXnh,
                Freshness.ExactAdh1, exactPmt2 ?? Pmt.CanonicalBytes,
                new OnionTrustedTimeAuthority(clock ?? new CountingClock(
                    new OnionMonotonicReading(BootId, 1_003))), default);

        internal ContactRecord BuildPms(
            byte[]? network = null,
            byte[]? pmtReference = null,
            ulong notBefore = 20,
            IReadOnlyList<ContactCodecSecurityTests.CryptoDcrFixture.Witness>? signers = null)
        {
            network ??= Network;
            pmtReference ??= ContactCodec.ArtifactReference("PMT2", Pmt).CanonicalBytes.ToArray();
            signers ??= Witnesses.Take(2).ToArray();
            var placementInput = Bytes(32, 0xb1);
            var epoch = U64(40);
            var ranked = Rows(Pmt.Field(9).Span, 136)
                .Select(static row => row[..32].ToArray())
                .Select(node => (Node: node, Score: Rendezvous(network, pmtReference, epoch, placementInput, node)))
                .OrderBy(static value => value.Score, ByteArrayComparer.Instance)
                .ThenBy(static value => value.Node, ByteArrayComparer.Instance)
                .Select(static value => value.Node).ToArray();
            ReadOnlyMemory<byte>[] fields =
            [
                network, pmtReference, placementInput, epoch, new byte[] { 2 }, Join(ranked),
                new byte[32], U64(notBefore), U64(80), new byte[] { checked((byte)signers.Count) },
                Join(signers.Select(static signer => Join(signer.Id, Bytes(64, 0xc1))).ToArray()),
            ];
            var unsignedSelection = Write("PMS2", fields);
            fields[6] = ContactCodec.Sha256Domain(
                "Deep/XPoint/V1/PMS2/selection", ProjectRaw(unsignedSelection, 6));
            return SignWitnessRecord("PMS2", fields, 11, signers);
        }

        private byte[] BuildXnv()
        {
            var value = XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xnv1);
            value = Set(value, 1, Network);
            value = Set(value, 7, Authority.AuthorityCoreReference);
            value = Set(value, 8, Authority.DirectoryWitnessPolicyHash);
            value = Set(value, 19, U64(20));
            value = Set(value, 20, U64(20));
            value = Set(value, 21, U64(80));
            return value;
        }

        private static VerifiedXPointNetworkAuthority BuildAuthority(
            byte[] network,
            IReadOnlyList<ContactCodecSecurityTests.CryptoDcrFixture.Witness> witnesses,
            byte witnessThreshold,
            bool repeatFailureDomain)
        {
            var template = XPointNetworkCodec.Parse<Xna1Record>(
                XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xna1));
            var fields = Enumerable.Range(1, 20)
                .Select(tag => template.FieldSpan(tag).ToArray()).ToArray();
            fields[0] = network.ToArray();
            fields[8] = new byte[] { checked((byte)witnesses.Count) };
            fields[9] = Join(witnesses.Select((witness, index) => Join(
                witness.Id, U64(0), witness.Key.PublicKey,
                repeatFailureDomain && index == 1 ? witnesses[0].FailureDomain : witness.FailureDomain)).ToArray());
            fields[10] = new byte[] { witnessThreshold };
            var canonical = WriteUnchecked(XPointNetworkRegistry.Xna1, fields);
            var xna = new Xna1Record(XPointNetworkRegistry.Xna1, canonical, fields);
            var sources = new[]
            {
                new AccountDirectoryDts1Source(
                    Bytes(32, 0xf1), Bytes(32, 0xf2), 1,
                    "time-a.example", 443, Bytes(32, 0xf3), 1),
                new AccountDirectoryDts1Source(
                    Bytes(32, 0xf4), Bytes(32, 0xf5), 1,
                    "time-b.example", 443, Bytes(32, 0xf6), 1),
            };
            var dts = new AccountDirectoryDts1(
                network, 0, new byte[32], sources, 2, 2, 30, 1,
                1, 1_000, 1, 0,
                [new AccountDirectoryDts1RootReceipt(Bytes(32, 0xf7), Bytes(64, 0xf8))]);
            return new VerifiedXPointNetworkAuthority(xna, dts, [xna]);
        }

        private byte[] BuildXnh(Xnv1Record view)
        {
            var value = XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xnh1);
            value = Set(value, 1, Network);
            value = Set(value, 6, XPointNetworkCodec.EncodeCoreReference("XNV1", view.CoreHash.Span));
            value = Set(value, 7, U64(view.ViewGeneration));
            value = Set(value, 8, Authority.AuthorityCoreReference);
            value = Set(value, 9, Authority.DirectoryWitnessPolicyHash);
            value = Set(value, 10, U64(20));
            value = Set(value, 11, U64(80));
            return value;
        }

        private VerifiedAccountDirectoryFreshness BuildFreshness(Xnv1Record view)
        {
            var head = new AccountDirectoryAdh1(
                Network, 1, Bytes(32, 0xd1), 1, Bytes(32, 0xd2), Bytes(32, 0xd3),
                Authority.AuthorityCoreReference.Span, Authority.DirectoryWitnessPolicyHash.Span,
                20, 80, 1,
                Witnesses.Take(2).Select(static witness =>
                    new AccountDirectoryAdh1WitnessEntry(witness.Id, Bytes(64, 0xd4))).ToArray());
            var exactAdh = AccountDirectoryAdh1Codec.Encode(head);
            var adhHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            var nonce = Bytes(32, 0xd5);
            var issuanceEpoch = AccountDirectoryDtt1IssuanceEpoch.Derive(Authority, 30, 1);
            var dtt = new AccountDirectoryDtt1(
                Network, nonce, 30, 1, adhHash, 1, view.CoreHash.Span, view.ViewGeneration,
                Authority.AuthorityCoreReference.Span, Authority.DirectoryWitnessPolicyHash.Span,
                29, 31, issuanceEpoch.Id.Span,
                Witnesses.Take(2).Select(static witness =>
                    new AccountDirectoryDtt1WitnessReceipt(witness.Id, Bytes(64, 0xd6))).ToArray());
            var exactDtt = AccountDirectoryDtt1Codec.Encode(dtt);
            var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);
            var query = Bytes(32, 0xd7);
            var proof = new AccountDirectoryAdp1(
                [1], Network, AccountDirectoryAdp1ResultKind.NonMembership, query, head,
                0, new byte[32], [], new byte[32], [], false,
                AccountDirectoryAdp1HistoryMode.ConsistencyOrGenesis, [], dttHash, null);
            var monotonic = new AccountDirectoryMonotonicRequestWindow(BootId, 1_000, 1_002, 1_003);
            return new VerifiedAccountDirectoryFreshness(
                exactAdh, head, adhHash, exactDtt, dttHash, [1], Bytes(32, 0xd8), proof, [],
                29, 30, monotonic, 1_050, null);
        }

        private ContactRecord BuildPmt(Xnv1Record view)
        {
            var rows = new[] { Bytes(136, 0x20), Bytes(136, 0x40) }
                .OrderBy(static row => row, ByteArrayComparer.Instance).ToArray();
            ReadOnlyMemory<byte>[] fields =
            [
                Network, U64(0), new byte[32], Reference("PMA2", Bytes(32, 0xa2)),
                XPointNetworkCodec.EncodeCoreReference("XNV1", view.CoreHash.Span), U64(40),
                new byte[] { 2 }, U16(2), Join(rows), U64(20), U64(20), U64(80),
                new byte[32], Freshness.ExactAdh1CoreReference, new byte[] { 2 },
                Join(Witnesses.Take(2).Select(static witness => Join(witness.Id, Bytes(64, 0xa3))).ToArray()),
            ];
            return SignWitnessRecord("PMT2", fields, 16, Witnesses.Take(2).ToArray());
        }

        private VerifiedOnionNetworkContext BuildCurrentNetwork(Xnv1Record view, Xnh1Record head)
        {
            var policy = XPointNetworkCodec.Parse<Xvp1Record>(
                XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xvp1));
            var nodes = Rows(Pmt.Field(9).Span, 136).Select(static row => row[..32].ToArray()).ToArray();
            var closure = new VerifiedOnionNetworkClosure
            {
                NetworkId = Network.ToArray(),
                Policy = policy,
                View = view,
                Head = head,
                Pmt = Pmt,
                ViewCoreHash = view.CoreHash.ToArray(),
                ViewCoreReference = XnvReference.ToArray(),
                PmtArtifactReference = ContactCodec.ArtifactReference("PMT2", Pmt).CanonicalBytes.ToArray(),
                PmtNodeIds = nodes,
                SelectionEpoch = 40,
                ReplicaCount = 2,
                HardUpperUnixSeconds = 80,
                Adh1CoreReference = Freshness.ExactAdh1CoreReference.ToArray(),
                Dtt1CoreHash = Freshness.ExactDtt1CoreHash.ToArray(),
                FreshnessBootId = Freshness.BootId.ToArray(),
                TrustedLowerUnixSeconds = Freshness.TrustedLowerUnixSeconds,
                TrustedUpperUnixSeconds = Freshness.TrustedUpperUnixSeconds,
                FreshnessMonotonicSample = Freshness.MonotonicSample,
                FreshnessDeadlineMonotonicSeconds = Freshness.FreshnessDeadlineMonotonicSeconds,
            };
            var lkg = new XPointNetworkProtectedLkg(
                Network, XnhReference, head.TreeSize, head.Root.ToArray(), XnvReference,
                view.ViewGeneration, Authority.AuthorityCoreReference);
            var leaseBoot = PrivacyRoutingWire.Sha256Domain("Deep/XPoint/V1/monotonic-boot-id", BootId);
            var nodesById = ReplicaIdentities.ToDictionary(
                static replica => Convert.ToHexString(replica.NodeId), StringComparer.Ordinal);
            var verifiedNodes = closure.PmtNodeIds.Select((nodeId, index) =>
            {
                var replica = nodesById[Convert.ToHexString(nodeId)];
                return new VerifiedNetworkNode(
                    nodeId.ToArray(), Bytes(32, checked((byte)(0xd0 + index))),
                    Bytes(32, checked((byte)(0xd2 + index))), replica.FailureDomain,
                    Bytes(32, checked((byte)(0xd4 + index))), 1, 4,
                    [127, 0, 0, checked((byte)(1 + index))], checked((ushort)(4400 + index)),
                    Bytes(32, checked((byte)(0xd6 + index))), 7, 1, 1, 1, 1,
                    Bytes(32, checked((byte)(0xd8 + index))),
                    Bytes(32, checked((byte)(0xda + index))), replica.Key.PublicKey);
            }).ToArray();
            return new VerifiedOnionNetworkContext(
                Network, new OnionTrustedTimeLease(TimeProvider.System, TimeSpan.FromMinutes(1), leaseBoot),
                verifiedNodes, closure, lkg, null);
        }

        private ContactRecord SignWitnessRecord(
            string magic,
            ReadOnlyMemory<byte>[] fields,
            int signatureTag,
            IReadOnlyList<ContactCodecSecurityTests.CryptoDcrFixture.Witness> signers)
        {
            var unsigned = ContactCodec.Decode(magic, Write(magic, fields));
            fields[signatureTag - 1] = Join(signers
                .OrderBy(static signer => signer.Id, ByteArrayComparer.Instance)
                .Select(signer => Join(
                    signer.Id, PublicKeyAuth.SignDetached(unsigned.SignatureInput.ToArray(), signer.Key.PrivateKey)))
                .ToArray());
            return ContactCodec.Decode(magic, Write(magic, fields));
        }

        internal sealed record ReplicaIdentity(byte[] NodeId, KeyPair Key, byte[] FailureDomain);
    }

    internal sealed class CountingClock(OnionMonotonicReading reading) : IOnionMonotonicClock
    {
        internal int ReadCount { get; private set; }
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReadCount++;
            return ValueTask.FromResult(new OnionMonotonicReading(reading.BootId.Span, reading.SampleSeconds));
        }
    }

    private static byte[] Set(byte[] source, int tag, ReadOnlyMemory<byte> value) =>
        XPointNetworkTestRecords.MutateField(source, tag, destination => value.Span.CopyTo(destination));

    private static byte[] Rendezvous(
        byte[] network, byte[] pmtReference, byte[] epoch, byte[] placementInput, byte[] node)
    {
        var label = Encoding.ASCII.GetBytes("Deep/XPoint/V1/PMS2/rendezvous-sha256/v2");
        return SHA256.HashData(Join(label, [0], network, pmtReference, epoch, placementInput, node));
    }

    private static byte[][] Rows(ReadOnlySpan<byte> source, int width)
    {
        var rows = new byte[source.Length / width][];
        for (var offset = 0; offset < source.Length; offset += width)
            rows[offset / width] = source.Slice(offset, width).ToArray();
        return rows;
    }

    private static byte[] Write(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        var output = new byte[12 + fields.Sum(static field => 8 + field.Length)];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].Span.CopyTo(output.AsSpan(offset));
            offset += fields[index].Length;
        }
        return output;
    }

    private static byte[] WriteUnchecked(XPointRecordDefinition definition, IReadOnlyList<byte[]> fields)
    {
        var output = new byte[12 + fields.Sum(static field => 8 + field.Length)];
        Encoding.ASCII.GetBytes(definition.Magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), definition.Version);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), definition.Suite);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].CopyTo(output, offset);
            offset += fields[index].Length;
        }
        return output;
    }

    private static byte[] ProjectRaw(ReadOnlySpan<byte> canonical, int fieldCount)
    {
        var end = 12;
        for (var index = 0; index < fieldCount; index++)
            end += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(end + 4, 4)));
        var output = canonical[..end].ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fieldCount));
        return output;
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
    private static byte[] U64(ulong value) { var output = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(output, value); return output; }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
