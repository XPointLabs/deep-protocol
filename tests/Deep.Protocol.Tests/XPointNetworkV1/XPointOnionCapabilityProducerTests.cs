using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.GroupV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class XPointOnionCapabilityProducerTests
{
    [Fact]
    public async Task ExactClosure_MintsPlacementPathAndReceiveCapabilities()
    {
        var fixture = Fixture.Create();
        var context = await fixture.VerifyAsync();
        context.EnsureCurrent();
        Assert.Null(context.PriorProtectedLkg);
        Assert.NotNull(context.ProtectedLkg);
        Assert.Equal(0UL, context.ProtectedLkg!.ViewGeneration);
        Assert.Equal(1UL, context.ProtectedLkg.HeadTreeSize);
        Assert.Equal(fixture.ViewCoreHash,
            context.ProtectedLkg.ViewCoreReference.Slice(6).ToArray());
        var shard = Bytes(32, 0xa1);
        var publish = ContactServicePlacementFactory.Create(
            context, ContactServiceRequestKind.PublishInvite, shard);
        var resolve = ContactServicePlacementFactory.Create(
            context, ContactServiceRequestKind.ResolveInvite, shard);

        Assert.Equal(fixture.ViewCoreHash, resolve.ViewHash.ToArray());
        Assert.Equal(publish.PlacementHash.ToArray(), resolve.PlacementHash.ToArray());
        Assert.Equal(
            publish.RankedReplicaNodeIds.Select(static value => value.ToArray()),
            resolve.RankedReplicaNodeIds.Select(static value => value.ToArray()));
        Assert.Equal(ContactServiceClass.InviteResolver, resolve.ServiceClass);
        Assert.True(resolve.Binds(ContactServiceRequestKind.ResolveInvite, shard));
        Assert.False(resolve.Binds(ContactServiceRequestKind.PublishInvite, shard));
        Assert.False(resolve.Binds(ContactServiceRequestKind.ResolveInvite, Bytes(32, 0xa2)));
        Assert.Equal(300UL, resolve.ValidUntilUnixSeconds);

        var candidates = OnionPathCandidateSnapshotFactory.Create(context);
        Assert.Equal(context.NetworkId.ToArray(), candidates.NetworkId.ToArray());
        Assert.Equal(0UL, candidates.ViewGeneration);
        Assert.Equal(fixture.ViewCoreHash, candidates.ViewHash.ToArray());
        Assert.Equal(fixture.NodeIds.Count, candidates.Candidates.Count);
        Assert.All(candidates.Candidates, candidate =>
        {
            Assert.Equal(32, candidate.NodeId.Length);
            Assert.Equal(32, candidate.RouterOwnerId.Length);
            Assert.Equal(32, candidate.PhysicalHostId.Length);
            Assert.Equal(32, candidate.FailureDomainId.Length);
            Assert.Equal(32, candidate.OriginId.Length);
            Assert.NotEqual(0, candidate.VerifiedRoleMask);
            if ((candidate.VerifiedRoleMask & 0x0001) != 0)
                Assert.NotEqual(OnionCandidateCapacityClass.None, candidate.EntryCapacityClass);
            if ((candidate.VerifiedRoleMask & 0x0002) != 0)
                Assert.NotEqual(OnionCandidateCapacityClass.None, candidate.RelayCapacityClass);
            if ((candidate.VerifiedRoleMask & 0x0004) != 0)
                Assert.NotEqual(OnionCandidateCapacityClass.None, candidate.MailboxCapacityClass);
        });
        var candidateIdCopy = candidates.Candidates[0].NodeId;
        MemoryMarshal.AsMemory(candidateIdCopy).Span.Fill(0);
        Assert.NotEqual(new byte[32], candidates.Candidates[0].NodeId.ToArray());

        var exit = resolve.RankedReplicaNodeIds[0].ToArray();
        var others = fixture.NodeIds.Where(value => !value.AsSpan().SequenceEqual(exit)).ToArray();
        var path = OnionPathContextFactory.CreateContactResolver(
            context, resolve, others[0], others[1], exit);
        Assert.Equal(others[0], path.EntryRouterId.ToArray());
        var copy = path.EntryRouterId;
        MemoryMarshal.AsMemory(copy).Span.Fill(0);
        Assert.Equal(others[0], path.EntryRouterId.ToArray());

        var keys = new OnionKeyAgreementAuthority(new RejectingVault());
        var handle = keys.BindKeyHandle(Bytes(32, 0xd1));
        var receive = OnionReceiveContextFactory.Create(
            context, OnionOperation.ContactResolve, OnionReceivePosition.Ingress,
            others[0], handle, others[1]);
        Assert.Equal(OnionReceivePosition.Ingress, receive.Position);
        Assert.Equal(handle.Id.ToArray(), receive.KeyHandle.Id.ToArray());
    }

    [Fact]
    public async Task PlacementManifestDirectoryAnchor_DoesNotHaveToEqualTheLatestDirectoryHead()
    {
        var fixture = Fixture.Create();

        var context = await fixture.VerifyWithPmtDirectoryAnchorAsync(0xde);

        context.EnsureCurrent();
        Assert.NotNull(context.Closure);
    }

    [Fact]
    public async Task ExactGenesisHead_RehydratesOnlyAnIdenticalProtectedLkg()
    {
        var fixture = Fixture.Create();
        var original = await fixture.VerifyAsync();

        var rehydrated = await fixture.RehydrateAsync(original.ProtectedLkg!);

        Assert.Equal(original.ProtectedLkg!.NetworkId.ToArray(), rehydrated.ProtectedLkg!.NetworkId.ToArray());
        Assert.Equal(original.ProtectedLkg.HeadCoreReference.ToArray(), rehydrated.ProtectedLkg.HeadCoreReference.ToArray());
        Assert.Equal(original.ProtectedLkg.ViewCoreReference.ToArray(), rehydrated.ProtectedLkg.ViewCoreReference.ToArray());

        var foreign = await Fixture.Create(networkMarker: 0x21).VerifyAsync();
        var mismatch = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fixture.RehydrateAsync(foreign.ProtectedLkg!));
        Assert.Equal("network-rehydration-mismatch", mismatch.Code);
    }

    [Fact]
    public async Task ExactClosure_RejectsBadThresholdForkAndStaleMonotonicTime()
    {
        var fixture = Fixture.Create();
        var badThreshold = fixture.WithArtifacts(viewMarker: 0x71, witnessCount: 1);
        var threshold = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await badThreshold.VerifyAsync());
        Assert.Equal("view-threshold-invalid", threshold.Code);

        var current = await fixture.VerifyAsync();
        var fork = fixture.WithArtifacts(viewMarker: 0x72);
        var forkError = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fork.VerifyAsync(current));
        Assert.Equal("network-stale-or-fork", forkError.Code);

        var stale = fixture.WithClockSample(fixture.FreshnessDeadline);
        var staleError = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await stale.VerifyAsync());
        Assert.Equal("trusted-time-invalid", staleError.Code);
    }

    [Fact]
    public async Task OrderedSuccessorChain_AllowsMultiGenerationCatchup_AndRejectsMissingOrTamperedIntermediate()
    {
        var genesis = Fixture.Create();
        var protectedLkg = await genesis.VerifyAsync();
        var successors = genesis.BuildSuccessorChain();

        var current = await successors.VerifyAsync(protectedLkg);
        Assert.Equal(2UL, current.Closure!.View.ViewGeneration);
        Assert.NotNull(current.PriorProtectedLkg);
        Assert.NotNull(current.ProtectedLkg);
        Assert.Equal(protectedLkg.ProtectedLkg!.ViewCoreReference.ToArray(),
            current.PriorProtectedLkg!.ViewCoreReference.ToArray());
        Assert.Equal(2UL, current.ProtectedLkg!.ViewGeneration);

        var missing = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await successors.WithoutFirstIntermediate().VerifyAsync(protectedLkg));
        Assert.Equal("network-stale-or-fork", missing.Code);

        var tampered = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await successors.WithTamperedIntermediateHeadProof().VerifyAsync(protectedLkg));
        Assert.Equal("head-threshold-invalid", tampered.Code);
    }

    [Fact]
    public async Task Path_RejectsMissingRoleDuplicateHostAndForeignPlacement()
    {
        var roleFixture = Fixture.Create().WithNodeRole(1, 0x001d);
        var roleContext = await roleFixture.VerifyAsync();
        var placement = ContactServicePlacementFactory.Create(
            roleContext, ContactServiceRequestKind.ResolveInvite, Bytes(32, 0x91));
        var exit = placement.RankedReplicaNodeIds.First(value => !value.Span.SequenceEqual(roleFixture.NodeIds[1])).ToArray();
        var ingress = roleFixture.NodeIds.First(value => !value.AsSpan().SequenceEqual(exit) && !value.AsSpan().SequenceEqual(roleFixture.NodeIds[1]));
        var roleError = Assert.Throws<OnionBoundaryException>(() => OnionPathContextFactory.CreateContactResolver(
            roleContext, placement, ingress, roleFixture.NodeIds[1], exit));
        Assert.Equal("path-role-invalid", roleError.Code);

        var hostFixture = Fixture.Create().WithDuplicateHost(0, 1);
        var hostContext = await hostFixture.VerifyAsync();
        var hostPlacement = ContactServicePlacementFactory.Create(
            hostContext, ContactServiceRequestKind.ResolveInvite, Bytes(32, 0x92));
        var hostExit = hostPlacement.RankedReplicaNodeIds[0].ToArray();
        var hostOthers = hostFixture.NodeIds.Where(value => !value.AsSpan().SequenceEqual(hostExit)).ToArray();
        var hostError = Assert.Throws<OnionBoundaryException>(() => OnionPathContextFactory.CreateContactResolver(
            hostContext, hostPlacement, hostOthers[0], hostOthers[1], hostExit));
        Assert.Equal("path-host-duplicate", hostError.Code);

        var other = await Fixture.Create(networkMarker: 0x21).VerifyAsync();
        var foreign = ContactServicePlacementFactory.Create(
            other, ContactServiceRequestKind.ResolveInvite, Bytes(32, 0x92));
        var foreignError = Assert.Throws<OnionBoundaryException>(() => OnionPathContextFactory.CreateContactResolver(
            hostContext, foreign, hostOthers[0], hostOthers[1], hostExit));
        Assert.Equal("placement-context-mismatch", foreignError.Code);
    }

    [Fact]
    public async Task Placement_UsesExactFormula_IsStableWithinEpoch_AndEpochChangesRanking()
    {
        var fixture = Fixture.Create(selectionEpoch: 7);
        var context = await fixture.VerifyAsync();
        var shard = Bytes(32, 0xb1);
        var first = ContactServicePlacementFactory.Create(
            context, ContactServiceRequestKind.ClaimPreKey, shard);
        var second = ContactServicePlacementFactory.Create(
            context, ContactServiceRequestKind.ClaimPreKey, shard);
        Assert.Equal(
            first.RankedReplicaNodeIds.Select(static value => value.ToArray()),
            second.RankedReplicaNodeIds.Select(static value => value.ToArray()));
        Assert.Equal(first.PlacementHash.ToArray(), second.PlacementHash.ToArray());
        Assert.Equal(fixture.ExpectedPlacementHash(ContactServiceClass.PreKeyClaim, shard), first.PlacementHash.ToArray());

        VerifiedContactServicePlacement? remapped = null;
        for (ulong epoch = 8; epoch < 64; epoch++)
        {
            var changedFixture = Fixture.Create(selectionEpoch: epoch);
            var changedContext = await changedFixture.VerifyAsync();
            var candidate = ContactServicePlacementFactory.Create(
                changedContext, ContactServiceRequestKind.ClaimPreKey, shard);
            if (!candidate.RankedReplicaNodeIds.Select(static value => Convert.ToHexString(value.Span))
                    .SequenceEqual(first.RankedReplicaNodeIds.Select(static value => Convert.ToHexString(value.Span))))
            {
                remapped = candidate;
                break;
            }
        }
        Assert.NotNull(remapped);
    }

    [Fact]
    public void PublicSurface_HasNoStaticHashXirPmsOrRawHopAuthority()
    {
        Assert.False(PrivacyRoutingCodec.RuntimeActivation);
        Assert.Empty(typeof(VerifiedOnionNetworkContext).GetConstructors());
        Assert.Empty(typeof(VerifiedContactServicePlacement).GetConstructors());
        Assert.Empty(typeof(VerifiedOnionPathContext).GetConstructors());
        Assert.Empty(typeof(VerifiedOnionReceiveContext).GetConstructors());
        Assert.Empty(typeof(VerifiedOnionPathCandidateSnapshot).GetConstructors());
        Assert.Empty(typeof(VerifiedOnionPathCandidate).GetConstructors());
        Assert.Empty(typeof(VerifiedGroupControlPlacement).GetConstructors());

        var candidateCreate = Assert.Single(typeof(OnionPathCandidateSnapshotFactory).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Equal("Create", candidateCreate.Name);
        Assert.Equal(typeof(VerifiedOnionNetworkContext), Assert.Single(candidateCreate.GetParameters()).ParameterType);
        Assert.DoesNotContain(typeof(VerifiedOnionPathCandidate).GetProperties(), property =>
            property.Name.Contains("Key", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("Trust", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("Address", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("Endpoint", StringComparison.OrdinalIgnoreCase));

        var verifyMethods = typeof(OnionNetworkContextVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly);
        Assert.Equal(["VerifyAsync", "VerifyFromForwardCheckpointAsync", "VerifyRehydratedCurrentAsync"],
            verifyMethods.Select(static method => method.Name).Order(StringComparer.Ordinal).ToArray());
        Assert.All(verifyMethods, verify => Assert.DoesNotContain(verify.GetParameters(), parameter =>
            typeof(Delegate).IsAssignableFrom(parameter.ParameterType) ||
            parameter.ParameterType == typeof(bool) ||
            parameter.Name?.Contains("hash", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("xir", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("pms", StringComparison.OrdinalIgnoreCase) == true));

        var creates = typeof(OnionPathContextFactory).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly);
        Assert.Equal(["CreateContactResolver", "CreateGroupControl", "CreateMailbox"],
            creates.Select(static method => method.Name).Order(StringComparer.Ordinal).ToArray());
        Assert.All(creates, create => Assert.DoesNotContain(create.GetParameters(), parameter =>
            parameter.Name?.Contains("hop", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("key", StringComparison.OrdinalIgnoreCase) == true));
        var groupPlacementVerify = Assert.Single(typeof(GroupControlPlacementVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Equal([typeof(VerifiedOnionNetworkContext), typeof(VerifiedGroupControlRendezvous)],
            groupPlacementVerify.GetParameters().Select(static parameter => parameter.ParameterType));
        Assert.Equal(["EntryRouterId"], typeof(VerifiedOnionPathContext).GetProperties(
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly).Select(static value => value.Name));

        var placementCreate = Assert.Single(typeof(ContactServicePlacementFactory).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.DoesNotContain(placementCreate.GetParameters(), parameter =>
            parameter.Name?.Contains("view", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("placement", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("xir", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("pms", StringComparison.OrdinalIgnoreCase) == true);
    }

    [Fact]
    public async Task ForwardCheckpoint_AdvancesProtectedLkgWithoutGenerationZeroHistory()
    {
        var package = Fixture.Create().BuildForwardPackage();

        var verified = await package.VerifyAsync();

        Assert.Equal(1UL, package.Lkg.ViewGeneration);
        Assert.Equal(2UL, verified.TargetViewGeneration);
        Assert.Equal(3UL, verified.TargetHeadTreeSize);
        Assert.Equal(0UL, verified.TerminalCheckpointGeneration);
        Assert.Equal(2UL, verified.NextProtectedLkg.ViewGeneration);
        Assert.Equal(verified.TargetViewCoreReference.ToArray(), verified.NextProtectedLkg.ViewCoreReference.ToArray());
        Assert.Equal(verified.TargetHeadCoreReference.ToArray(), verified.NextProtectedLkg.HeadCoreReference.ToArray());
        Assert.Equal(verified.TerminalCheckpointCoreReference.ToArray(),
            verified.NextProtectedLkg.LastForwardCheckpointCoreReference.ToArray());
        Assert.Equal(package.Lkg.ViewCoreReference.ToArray(),
            verified.PriorProtectedLkg.ViewCoreReference.ToArray());

        var context = await package.VerifyContextAsync(verified);
        Assert.Equal(2UL, context.Closure!.View.ViewGeneration);
        Assert.Equal(2UL, BinaryPrimitives.ReadUInt64BigEndian(context.Closure.Pmt.FieldSpan(2)));
        Assert.Equal(package.Lkg.ViewCoreReference.ToArray(),
            context.PriorProtectedLkg!.ViewCoreReference.ToArray());
        Assert.Equal(verified.NextProtectedLkg.LastForwardCheckpointCoreReference.ToArray(),
            context.ProtectedLkg!.LastForwardCheckpointCoreReference.ToArray());

        var nfpCopy = verified.ExactNfp1;
        var viewCopy = verified.ExactTargetXnv1;
        var rootCopy = verified.TargetHeadRoot;
        MemoryMarshal.AsMemory(nfpCopy).Span.Fill(0);
        MemoryMarshal.AsMemory(viewCopy).Span.Fill(0);
        MemoryMarshal.AsMemory(rootCopy).Span.Fill(0);
        Assert.Equal("NFP1"u8.ToArray(), verified.ExactNfp1.Span[..4].ToArray());
        Assert.Equal("XNV1"u8.ToArray(), verified.ExactTargetXnv1.Span[..4].ToArray());
        Assert.Contains(verified.TargetHeadRoot.ToArray(), static value => value != 0);
    }

    [Fact]
    public async Task ForwardCheckpoint_RejectsHostileSourceCheckpointDttAndTarget()
    {
        var package = Fixture.Create().BuildForwardPackage();

        Assert.Equal("InvalidSourceLkg", (await Assert.ThrowsAsync<XPointNetworkForwardCheckpointVerificationException>(
            async () => await package.WithSourceRoot(Bytes(32, 0xee)).VerifyAsync())).Code);
        Assert.Equal("InvalidSignature", (await Assert.ThrowsAsync<XPointNetworkForwardCheckpointVerificationException>(
            async () => await package.WithTamperedXnfSignature().VerifyAsync())).Code);
        Assert.Equal("dtt-target-mismatch", (await Assert.ThrowsAsync<XPointNetworkForwardCheckpointVerificationException>(
            async () => await package.WithWrongDttReference().VerifyAsync())).Code);
        Assert.Equal("InvalidInclusionProof", (await Assert.ThrowsAsync<XPointNetworkForwardCheckpointVerificationException>(
            async () => await package.WithTamperedMembershipProof().VerifyAsync())).Code);
        Assert.Equal("authority-chain-mismatch", (await Assert.ThrowsAsync<XPointNetworkForwardCheckpointVerificationException>(
            async () => await package.WithTamperedAuthorityReceipt().VerifyAsync())).Code);
        Assert.Equal("InvalidSignature", (await Assert.ThrowsAsync<XPointNetworkForwardCheckpointVerificationException>(
            async () => await package.WithTamperedTargetViewSignature().VerifyAsync())).Code);
        Assert.Equal("InvalidSignature", (await Assert.ThrowsAsync<XPointNetworkForwardCheckpointVerificationException>(
            async () => await package.WithTamperedTargetHeadSignature().VerifyAsync())).Code);
        Assert.Equal("checkpoint-lineage-mismatch", (await Assert.ThrowsAsync<XPointNetworkForwardCheckpointVerificationException>(
            async () => await package.WithProtectedCheckpoint(Bytes(32, 0xef), 0).VerifyAsync())).Code);
    }

    [Fact]
    public async Task ForwardCheckpoint_RejectsExpiredMonotonicLeaseAndOwnsCallerBuffers()
    {
        var package = Fixture.Create().BuildForwardPackage();
        var nfp = package.Nfp.ToArray();
        var xnf = package.Xnf.ToArray();
        var view = package.TargetView.ToArray();
        var head = package.TargetHead.ToArray();
        var ownedPackage = package with { Nfp = nfp, Xnf = xnf, TargetView = view, TargetHead = head };

        var verified = await ownedPackage.VerifyAsync();
        nfp.AsSpan().Fill(0);
        xnf.AsSpan().Fill(0);
        view.AsSpan().Fill(0);
        head.AsSpan().Fill(0);
        Assert.Equal("NFP1"u8.ToArray(), verified.ExactNfp1.Span[..4].ToArray());
        Assert.Equal("XNF1"u8.ToArray(), verified.ExactOrderedXnf1Chain[0].Span[..4].ToArray());

        var expired = await Assert.ThrowsAsync<XPointNetworkForwardCheckpointVerificationException>(
            async () => await package.WithClockSample(package.Freshness.FreshnessDeadlineMonotonicSeconds).VerifyAsync());
        Assert.Equal("trusted-time-invalid", expired.Code);
    }

    [Fact]
    public async Task ForwardCheckpoint_TerminalCompositionRejectsUnsignedPolicyPmtAndForeignCapability()
    {
        var package = Fixture.Create().BuildForwardPackage();
        var checkpoint = await package.VerifyAsync();

        var policy = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await package.WithTamperedCurrentPolicySignature().VerifyContextAsync(checkpoint));
        Assert.Equal("policy-threshold-invalid", policy.Code);

        var pmt = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await package.WithTamperedCurrentPmtSignature().VerifyContextAsync(checkpoint));
        Assert.Equal("pmt-threshold-invalid", pmt.Code);

        var foreignPackage = Fixture.Create(networkMarker: 0x21).BuildForwardPackage();
        var foreignCheckpoint = await foreignPackage.VerifyAsync();
        var foreign = await Assert.ThrowsAsync<XPointNetworkForwardCheckpointVerificationException>(async () =>
            await package.VerifyContextAsync(foreignCheckpoint));
        Assert.Equal("forward-capability-mismatch", foreign.Code);
    }

    [Fact]
    public async Task ForwardCheckpoint_PublicCapabilityHasNoForgeryOrCallbackSeam()
    {
        Assert.Empty(typeof(VerifiedXPointNetworkForwardCheckpoint).GetConstructors());
        var method = Assert.Single(typeof(XPointNetworkForwardCheckpointVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Equal("VerifyAsync", method.Name);
        Assert.DoesNotContain(method.GetParameters(), parameter =>
            typeof(Delegate).IsAssignableFrom(parameter.ParameterType) ||
            parameter.ParameterType.Name.Contains("Resolver", StringComparison.Ordinal) ||
            parameter.ParameterType.Name.Contains("Signature", StringComparison.Ordinal));

        var tooMany = Enumerable.Repeat<ReadOnlyMemory<byte>>(new byte[545], 65).ToArray();
        var package = Fixture.Create().BuildForwardPackage();
        var error = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await XPointNetworkForwardCheckpointVerifier.VerifyAsync(
                package.Authority, package.Freshness, package.Lkg, package.AuthorityChain,
                tooMany, package.Nfp, package.TargetView, package.TargetHead,
                new OnionTrustedTimeAuthority(new FixedClock(Bytes(16, 0xc1), package.ClockSample)), default));
        Assert.Contains("1..64", error.Message, StringComparison.Ordinal);
    }

    private sealed class RejectingVault : IOnionKeyAgreementVault
    {
        public ValueTask<byte[]> DeriveX25519SharedSecretAsync(
            OnionKeyHandle keyHandle,
            ReadOnlyMemory<byte> peerPublicKey,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class FixedClock(byte[] bootId, ulong sample) : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(bootId, sample));
        }
    }

    private sealed record SigningKey(byte[] Id, KeyPair Pair, byte[] FailureDomain);

    private sealed class Fixture
    {
        private readonly byte _networkMarker;
        private readonly ulong _selectionEpoch;
        private readonly ulong _clockSample;
        private readonly byte _viewMarker;
        private readonly int _witnessCount;
        private readonly ushort[] _roles;
        private readonly byte[][] _hosts;
        private readonly SigningKey _root;
        private readonly SigningKey[] _witnesses;
        private readonly byte[] _xna;
        private readonly byte[] _dts;
        private readonly byte[] _xvp;
        private readonly byte[][] _nodes;
        private readonly byte[] _xnv;
        private readonly byte[] _xnh;
        private readonly byte[] _pmt;
        private readonly VerifiedXPointNetworkAuthority _authority;
        private readonly VerifiedAccountDirectoryFreshness _freshness;

        private Fixture(
            byte networkMarker,
            ulong selectionEpoch,
            ulong clockSample,
            byte viewMarker,
            int witnessCount,
            ushort[] roles,
            byte[][] hosts,
            SigningKey root,
            SigningKey[] witnesses,
            byte[] xna,
            byte[] dts)
        {
            _networkMarker = networkMarker;
            _selectionEpoch = selectionEpoch;
            _clockSample = clockSample;
            _viewMarker = viewMarker;
            _witnessCount = witnessCount;
            _roles = roles.ToArray();
            _hosts = hosts.Select(static value => value.ToArray()).ToArray();
            _root = root;
            _witnesses = witnesses;
            _xna = xna;
            _dts = dts;
            var network = Bytes(16, networkMarker);
            var xnaRecord = XPointNetworkCodec.Parse<Xna1Record>(xna);
            _authority = XPointNetworkAuthorityVerifier.Verify(
                new XPointNetworkGenesisPin(network, xnaRecord.CoreHash.Span), [xna], [dts]);
            _xvp = BuildXvp(network, _authority, root);
            var policy = XPointNetworkCodec.Parse<Xvp1Record>(_xvp);
            _nodes = Enumerable.Range(0, 3)
                .Select(index => BuildXnd(network, index, _roles[index], _hosts[index]))
                .ToArray();
            _xnv = BuildXnv(network, _authority, policy, _nodes, witnesses, viewMarker, witnessCount);
            var view = XPointNetworkCodec.Parse<Xnv1Record>(_xnv);
            _xnh = BuildXnh(network, _authority, view, witnesses);
            _freshness = BuildFreshness(network, _authority, view, witnesses);
            _pmt = BuildPmt(network, view, _freshness, _nodes, witnesses, selectionEpoch);
        }

        internal IReadOnlyList<byte[]> NodeIds => _nodes
            .Select(static value => XPointNetworkCodec.Parse<Xnd1Record>(value).NodeId.ToArray()).ToArray();
        internal byte[] ViewCoreHash => XPointNetworkCodec.Parse<Xnv1Record>(_xnv).CoreHash.ToArray();
        internal ulong FreshnessDeadline => _freshness.FreshnessDeadlineMonotonicSeconds;

        internal static Fixture Create(byte networkMarker = 0x11, ulong selectionEpoch = 7)
        {
            var root = new SigningKey(Bytes(32, 0x20), PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x21)), Bytes(32, 0x22));
            var witnesses = Enumerable.Range(0, 3).Select(index => new SigningKey(
                Bytes(32, checked((byte)(0x40 + index))),
                PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(0x50 + index)))),
                Bytes(32, checked((byte)(0x60 + index))))).ToArray();
            var network = Bytes(16, networkMarker);
            var dts = BuildDts(network, root);
            var policyHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(AccountDirectoryDts1Codec.Decode(dts));
            var xna = BuildXna(network, root, witnesses, policyHash);
            return new Fixture(networkMarker, selectionEpoch, 1_000, 0x70, 2,
                [0x001f, 0x001f, 0x001f],
                [Bytes(32, 0x81), Bytes(32, 0x82), Bytes(32, 0x83)],
                root, witnesses, xna, dts);
        }

        internal Fixture WithArtifacts(byte viewMarker, int witnessCount = 2) =>
            new(_networkMarker, _selectionEpoch, _clockSample, viewMarker, witnessCount,
                _roles, _hosts, _root, _witnesses, _xna, _dts);

        internal Fixture WithClockSample(ulong value) =>
            new(_networkMarker, _selectionEpoch, value, _viewMarker, _witnessCount,
                _roles, _hosts, _root, _witnesses, _xna, _dts);

        internal Fixture WithNodeRole(int index, ushort role)
        {
            var roles = _roles.ToArray();
            roles[index] = role;
            return new Fixture(_networkMarker, _selectionEpoch, _clockSample, _viewMarker, _witnessCount,
                roles, _hosts, _root, _witnesses, _xna, _dts);
        }

        internal Fixture WithDuplicateHost(int source, int target)
        {
            var hosts = _hosts.Select(static value => value.ToArray()).ToArray();
            hosts[target] = hosts[source].ToArray();
            return new Fixture(_networkMarker, _selectionEpoch, _clockSample, _viewMarker, _witnessCount,
                _roles, hosts, _root, _witnesses, _xna, _dts);
        }

        internal ValueTask<VerifiedOnionNetworkContext> VerifyAsync(VerifiedOnionNetworkContext? previous = null) =>
            OnionNetworkContextVerifier.VerifyAsync(
                _authority, _freshness, new ReadOnlyMemory<byte>[] { _xvp },
                new ReadOnlyMemory<byte>[] { _xnv }, new ReadOnlyMemory<byte>[] { _xnh },
                _nodes.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
                new ReadOnlyMemory<byte>[] { _pmt }, previous,
                new OnionTrustedTimeAuthority(new FixedClock(Bytes(16, 0xc1), _clockSample)), default);

        internal ValueTask<VerifiedOnionNetworkContext> VerifyWithPmtDirectoryAnchorAsync(byte marker)
        {
            var pmt = ContactCodec.Decode("PMT2", _pmt);
            var fields = Enumerable.Range(1, 16)
                .Select(tag => (ReadOnlyMemory<byte>)pmt.FieldSpan(tag).ToArray()).ToArray();
            fields[13] = XPointNetworkCodec.EncodeCoreReference("ADH1", Bytes(32, marker));
            var provisional = ContactCodec.AuthorForValidation("PMT2", fields);
            var input = provisional.SignatureInput.ToArray();
            fields[15] = SignatureRows(_witnesses.Take(2).Select(value =>
                (value.Id, PublicKeyAuth.SignDetached(input, value.Pair.PrivateKey))).ToArray());
            var anchoredPmt = ContactCodec.AuthorForValidation("PMT2", fields).CanonicalBytes.ToArray();
            return OnionNetworkContextVerifier.VerifyAsync(
                _authority, _freshness, new ReadOnlyMemory<byte>[] { _xvp },
                new ReadOnlyMemory<byte>[] { _xnv }, new ReadOnlyMemory<byte>[] { _xnh },
                _nodes.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
                new ReadOnlyMemory<byte>[] { anchoredPmt }, null,
                new OnionTrustedTimeAuthority(new FixedClock(Bytes(16, 0xc1), _clockSample)), default);
        }

        internal ValueTask<VerifiedOnionNetworkContext> RehydrateAsync(XPointNetworkProtectedLkg protectedCurrent) =>
            OnionNetworkContextVerifier.VerifyRehydratedCurrentAsync(
                _authority, _freshness, new ReadOnlyMemory<byte>[] { _xvp },
                new ReadOnlyMemory<byte>[] { _xnv }, new ReadOnlyMemory<byte>[] { _xnh },
                _nodes.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
                new ReadOnlyMemory<byte>[] { _pmt }, protectedCurrent,
                new OnionTrustedTimeAuthority(new FixedClock(Bytes(16, 0xc1), _clockSample)), default);

        internal SuccessorFixture BuildSuccessorChain()
        {
            var network = Bytes(16, _networkMarker);
            var policies = new List<byte[]>();
            var views = new List<byte[]>();
            var heads = new List<byte[]>();
            var nodeSets = new List<byte[][]>();
            var priorPolicy = XPointNetworkCodec.Parse<Xvp1Record>(_xvp);
            var priorView = XPointNetworkCodec.Parse<Xnv1Record>(_xnv);
            var priorHead = XPointNetworkCodec.Parse<Xnh1Record>(_xnh);
            var priorNodes = _nodes.Select(static value => XPointNetworkCodec.Parse<Xnd1Record>(value)).ToArray();

            for (ulong generation = 1; generation <= 2; generation++)
            {
                var policyBytes = BuildXvp(network, _authority, _root, generation, priorPolicy.CoreHash.ToArray());
                var policy = XPointNetworkCodec.Parse<Xvp1Record>(policyBytes);
                var nodes = Enumerable.Range(0, 3).Select(index => BuildXnd(
                    network, index, _roles[index], _hosts[index], generation, priorNodes[index].CoreHash.ToArray())).ToArray();
                var viewBytes = BuildXnv(network, _authority, policy, nodes, _witnesses,
                    checked((byte)(0x70 + generation)), 2, generation, priorView.CoreHash.ToArray());
                var view = XPointNetworkCodec.Parse<Xnv1Record>(viewBytes);
                var headBytes = BuildXnh(network, _authority, view, _witnesses, priorHead);
                var head = XPointNetworkCodec.Parse<Xnh1Record>(headBytes);
                policies.Add(policyBytes);
                views.Add(viewBytes);
                heads.Add(headBytes);
                nodeSets.Add(nodes);
                priorPolicy = policy;
                priorView = view;
                priorHead = head;
                priorNodes = nodes.Select(static value => XPointNetworkCodec.Parse<Xnd1Record>(value)).ToArray();
            }

            var freshness = BuildFreshness(network, _authority, priorView, _witnesses);
            var pmts = new List<byte[]>();
            var priorPmt = ContactCodec.Decode("PMT2", _pmt);
            for (var index = 0; index < views.Count; index++)
            {
                var generation = checked((ulong)(index + 1));
                var pmt = BuildPmt(network, XPointNetworkCodec.Parse<Xnv1Record>(views[index]), freshness,
                    nodeSets[index], _witnesses, _selectionEpoch + generation, generation,
                    priorPmt.CoreHash.ToArray());
                pmts.Add(pmt);
                priorPmt = ContactCodec.Decode("PMT2", pmt);
            }

            return new SuccessorFixture(_authority, freshness, policies.ToArray(), views.ToArray(),
                heads.ToArray(), nodeSets[^1], pmts.ToArray(), _clockSample);
        }

        internal ForwardPackage BuildForwardPackage()
        {
            var successors = BuildSuccessorChain();
            var sourceView = XPointNetworkCodec.Parse<Xnv1Record>(successors.Views[0]);
            var sourceHead = XPointNetworkCodec.Parse<Xnh1Record>(successors.Heads[0]);
            var targetView = XPointNetworkCodec.Parse<Xnv1Record>(successors.Views[^1]);
            var targetHead = XPointNetworkCodec.Parse<Xnh1Record>(successors.Heads[^1]);
            var leaves = new[]
            {
                CoveredHeadLeaf(sourceView, sourceHead),
                CoveredHeadLeaf(targetView, targetHead),
            };
            var coveredRoot = XPointNetworkCrypto.Rfc6962Inner(leaves[0], leaves[1]);
            ReadOnlyMemory<byte>[] xnfFields =
            [
                sourceView.NetworkId.ToArray(), U64(0), new byte[32], Join(U64(1), U64(2)), U64(2), coveredRoot,
                XPointNetworkCodec.EncodeCoreReference("XNV1", targetView.CoreHash.Span),
                Join(U64(targetView.ViewGeneration), targetView.CoreHash.ToArray()),
                XPointNetworkCodec.EncodeCoreReference("XNH1", targetHead.CoreHash.Span),
                Join(U64(targetHead.TreeSize), targetHead.Root.ToArray()),
                _authority.AuthorityCoreReference, U64(200), U16(1), new byte[] { 1 },
                SignatureRows([(_root.Id, Bytes(64, 0xda))]),
            ];
            var xnf = SignXPoint(XPointNetworkRegistry.Xnf1, xnfFields, 14,
                [(_root.Id, _root.Pair.PrivateKey)]);
            var xnfRecord = XPointNetworkCodec.Parse<Xnf1Record>(xnf);
            ReadOnlyMemory<byte>[] nfpFields =
            [
                sourceView.NetworkId.ToArray(), U64(sourceView.ViewGeneration),
                XPointNetworkCodec.EncodeCoreReference("XNV1", sourceView.CoreHash.Span),
                U64(sourceHead.TreeSize), sourceHead.Root.ToArray(), U64(0),
                XPointNetworkCodec.EncodeCoreReference("XNV1", targetView.CoreHash.Span),
                XPointNetworkCodec.EncodeCoreReference("XNH1", targetHead.CoreHash.Span),
                new byte[] { 1 }, _authority.AuthorityCoreReference,
                new byte[] { 1 }, XPointNetworkCodec.EncodeCoreReference("XNF1", xnfRecord.CoreHash.Span),
                new byte[] { 1 }, leaves[1],
                XPointNetworkCodec.EncodeCoreReference("DTT1", successors.Freshness.ExactDtt1CoreHash.Span), U16(1),
            ];
            var nfp = XPointNetworkCodec.Write(XPointNetworkRegistry.Nfp1, nfpFields);
            var lkg = new XPointNetworkProtectedLkg(
                sourceView.NetworkId.ToArray(),
                XPointNetworkCodec.EncodeCoreReference("XNH1", sourceHead.CoreHash.Span),
                sourceHead.TreeSize,
                sourceHead.Root.ToArray(),
                XPointNetworkCodec.EncodeCoreReference("XNV1", sourceView.CoreHash.Span),
                sourceView.ViewGeneration,
                _authority.AuthorityCoreReference);
            return new ForwardPackage(
                _authority, successors.Freshness, lkg, [_xna], xnf, nfp,
                successors.Policies[^1], successors.Views[^1], successors.Heads[^1],
                successors.Nodes, successors.Pmts[^1], _clockSample);
        }

        internal byte[] ExpectedPlacementHash(ContactServiceClass serviceClass, byte[] shard)
        {
            var network = Bytes(16, _networkMarker);
            var view = XPointNetworkCodec.Parse<Xnv1Record>(_xnv);
            var pmt = ContactCodec.Decode("PMT2", _pmt);
            var input = XPointNetworkCrypto.Sha256Domain(
                "Deep/ContactResolver/V1/service-placement-input", Join(network, [(byte)serviceClass], shard));
            var ranked = Rows(pmt.FieldSpan(9), 136).Select(static row => row[..32].ToArray())
                .Select(node => (Node: node, Rank: ServiceRank(network, _selectionEpoch, input, node)))
                .OrderBy(static value => value.Rank, ByteArrayComparer.Instance)
                .ThenBy(static value => value.Node, ByteArrayComparer.Instance)
                .Take(2).Select(static value => value.Node).ToArray();
            return XPointNetworkCrypto.Sha256Domain(
                "Deep/ContactResolver/V1/service-placement",
                Join(network, XPointNetworkCodec.EncodeCoreReference("XNV1", view.CoreHash.Span),
                    ArtifactReference("PMT2", pmt.ArtifactHash.Span), U64(_selectionEpoch),
                    [(byte)serviceClass], shard, input, [2], Join(ranked)));
        }

        private static byte[] BuildDts(byte[] network, SigningKey root)
        {
            var sources = new[]
            {
                new AccountDirectoryDts1Source(Bytes(32, 0x10), Bytes(32, 0x11), 1, "a.example", 443, Bytes(32, 0x12), 5),
                new AccountDirectoryDts1Source(Bytes(32, 0x13), Bytes(32, 0x14), 1, "b.example", 443, Bytes(32, 0x15), 5),
            };
            var placeholder = new[] { new AccountDirectoryDts1RootReceipt(root.Id, Bytes(64, 0xa1)) };
            var unsigned = new AccountDirectoryDts1(network, 0, new byte[32], sources, 2, 2, 30, 5, 100, 900, 1, 0, placeholder);
            var signature = PublicKeyAuth.SignDetached(AccountDirectoryCrypto.ComputeDts1SigningInput(unsigned), root.Pair.PrivateKey);
            return AccountDirectoryDts1Codec.Encode(new AccountDirectoryDts1(
                network, 0, new byte[32], sources, 2, 2, 30, 5, 100, 900, 1, 0,
                [new AccountDirectoryDts1RootReceipt(root.Id, signature)]));
        }

        private static byte[] BuildXna(byte[] network, SigningKey root, SigningKey[] witnesses, byte[] policyHash)
        {
            ReadOnlyMemory<byte>[] fields =
            [
                network, U64(0), new byte[32], new byte[] { 1 }, RootRows([root]), new byte[] { 1 }, U64(0), U16(1), new byte[] { 3 },
                WitnessRows(witnesses), new byte[] { 2 }, XPointNetworkCodec.EncodeCoreReference("DTS1", policyHash),
                policyHash, U32(10), U64(1), U64(100), U64(100), U64(1_000), new byte[] { 1 },
                SignatureRows([(root.Id, Bytes(64, 0xa2))]),
            ];
            var provisional = XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
            fields[19] = SignatureRows([(root.Id, PublicKeyAuth.SignDetached(
                XPointNetworkCrypto.ComputeSigningInput(provisional), root.Pair.PrivateKey))]);
            return XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields);
        }

        private static byte[] BuildXvp(
            byte[] network,
            VerifiedXPointNetworkAuthority authority,
            SigningKey root,
            ulong generation = 0,
            byte[]? predecessorCoreHash = null)
        {
            ReadOnlyMemory<byte>[] fields =
            [
                network, U64(generation), predecessorCoreHash ?? new byte[32], U16(0x001f), new byte[] { 3 }, new byte[] { 2 }, U16(0x000f), new byte[] { 3 },
                U32(2_592_000), U16(600), U16(1), U64(generation), XPointNetworkCodec.EncodeCoreReference("XCC1", Bytes(32, 0x31)),
                U16(1), U64(100), U64(100), U64(900), authority.AuthorityCoreReference,
                new byte[] { 1 }, SignatureRows([(root.Id, Bytes(64, 0xa3))]),
            ];
            return SignXPoint(XPointNetworkRegistry.Xvp1, fields, 19, [(root.Id, root.Pair.PrivateKey)]);
        }

        private static byte[] BuildXnd(
            byte[] network,
            int index,
            ushort roles,
            byte[] host,
            ulong generation = 0,
            byte[]? predecessorCoreHash = null)
        {
            var seed = checked((byte)(0x90 + index * 8));
            var identity = PublicKeyAuth.GenerateKeyPair(Bytes(32, seed));
            var nodeId = Bytes(32, checked((byte)(0x10 + index)));
            var originId = Bytes(32, checked((byte)(0x30 + index)));
            var currentSpki = Bytes(32, checked((byte)(0x50 + index)));
            var nextSpki = Bytes(32, checked((byte)(0x58 + index)));
            ReadOnlyMemory<byte>[] fields = new ReadOnlyMemory<byte>[37];
            fields[0] = network; fields[1] = nodeId; fields[2] = U64(generation); fields[3] = predecessorCoreHash ?? new byte[32];
            fields[4] = identity.PublicKey; fields[5] = Bytes(32, checked((byte)(0x20 + index)));
            fields[6] = Bytes(32, checked((byte)(0x70 + index))); fields[7] = host;
            fields[8] = Bytes(32, checked((byte)(0x78 + index))); fields[9] = U32(64_500u + (uint)index);
            fields[10] = U16(840); fields[11] = FailureDomain(network, fields[6].Span, host, fields[8].Span, fields[9].Span, fields[10].Span);
            fields[12] = U16(roles);
            fields[13] = U32((roles & 1) != 0 ? 100u : 0u);
            fields[14] = U64((roles & 2) != 0 ? 100UL : 0UL);
            fields[15] = U64((roles & 4) != 0 ? 100UL : 0UL);
            fields[16] = U64((roles & 8) != 0 ? 100UL : 0UL);
            fields[17] = U32((roles & 16) != 0 ? 100u : 0u);
            fields[18] = new byte[] { 1 }; fields[19] = OriginRow(originId, index, currentSpki, nextSpki);
            fields[20] = U64(1); fields[21] = ScalarMult.Base(Bytes(32, checked((byte)(0xa0 + index))));
            fields[22] = U64(100); fields[23] = U64(400); fields[24] = U64(2);
            fields[25] = ScalarMult.Base(Bytes(32, checked((byte)(0xb0 + index))));
            fields[26] = U64(350); fields[27] = U64(800); fields[28] = U16(1); fields[29] = U16(1);
            var roleRows = RoleRows(roles, index); fields[30] = new byte[] { checked((byte)(roleRows.Length / 41)) }; fields[31] = roleRows;
            fields[32] = U64(100); fields[33] = U64(100); fields[34] = U64(400); fields[35] = U16(1);
            fields[36] = Bytes(64, 0xa4);
            var provisional = XPointNetworkCodec.Parse<Xnd1Record>(XPointNetworkCodec.Write(XPointNetworkRegistry.Xnd1, fields));
            fields[36] = PublicKeyAuth.SignDetached(XPointNetworkCrypto.ComputeSigningInput(provisional), identity.PrivateKey);
            return XPointNetworkCodec.Write(XPointNetworkRegistry.Xnd1, fields);
        }

        private static byte[] BuildXnv(
            byte[] network,
            VerifiedXPointNetworkAuthority authority,
            Xvp1Record policy,
            byte[][] nodes,
            SigningKey[] witnesses,
            byte viewMarker,
            int witnessCount,
            ulong generation = 0,
            byte[]? predecessorCoreHash = null)
        {
            var parsed = nodes.Select(static value => XPointNetworkCodec.Parse<Xnd1Record>(value))
                .OrderBy(static value => value.NodeId.ToArray(), ByteArrayComparer.Instance).ToArray();
            ReadOnlyMemory<byte>[] fields =
            [
                network, U64(generation), predecessorCoreHash ?? new byte[32], Bytes(32, 0x61), U64(generation + 1), Bytes(32, viewMarker),
                authority.AuthorityCoreReference, authority.DirectoryWitnessPolicyHash,
                XPointNetworkCodec.EncodeCoreReference("XVP1", policy.CoreHash.Span), U16(1), U16(3),
                Join(parsed.Select(static value => ArtifactReference("XND1", XPointNetworkCrypto.ComputeArtifactHash(value))).ToArray()),
                U16(0), Array.Empty<byte>(), U16(0), Array.Empty<byte>(), U16(1), ArtifactReference("XCB1", Bytes(32, 0x62)),
                U64(100), U64(100), U64(300), U16(1), new byte[] { 2 },
                SignatureRows(witnesses.Take(2).Select(static (value, index) =>
                    (value.Id, Bytes(64, checked((byte)(0xa5 + index))))).ToArray()),
            ];
            var provisional = XPointNetworkCodec.Parse<Xnv1Record>(
                XPointNetworkCodec.Write(XPointNetworkRegistry.Xnv1, fields));
            var input = XPointNetworkCrypto.ComputeSigningInput(provisional);
            fields[23] = SignatureRows(witnesses.Take(2).Select((value, index) =>
                (value.Id, index < witnessCount
                    ? PublicKeyAuth.SignDetached(input, value.Pair.PrivateKey)
                    : Bytes(64, checked((byte)(0xb5 + index))))).ToArray());
            return XPointNetworkCodec.Write(XPointNetworkRegistry.Xnv1, fields);
        }

        private static byte[] BuildXnh(
            byte[] network,
            VerifiedXPointNetworkAuthority authority,
            Xnv1Record view,
            SigningKey[] witnesses,
            Xnh1Record? predecessor = null)
        {
            var leaf = ViewLeaf(view);
            var generation = predecessor is null ? 0UL : predecessor.LogGeneration + 1;
            var root = predecessor is null ? leaf : XPointNetworkCrypto.Rfc6962Inner(predecessor.Root.Span, leaf);
            ReadOnlyMemory<byte>[] fields =
            [
                network, U64(generation), predecessor?.CoreHash.ToArray() ?? new byte[32], U64(generation + 1), root,
                XPointNetworkCodec.EncodeCoreReference("XNV1", view.CoreHash.Span), U64(view.ViewGeneration),
                authority.AuthorityCoreReference, authority.DirectoryWitnessPolicyHash,
                U64(100), U64(300), U16(1), new byte[] { predecessor is null ? (byte)0 : (byte)1 },
                predecessor is null ? Array.Empty<byte>() : leaf, new byte[] { 2 },
                SignatureRows(witnesses.Take(2).Select(static (value, index) =>
                    (value.Id, Bytes(64, checked((byte)(0xa6 + index))))).ToArray()),
            ];
            return SignXPoint(XPointNetworkRegistry.Xnh1, fields, 15,
                witnesses.Take(2).Select(static value => (value.Id, value.Pair.PrivateKey)).ToArray());
        }

        private static VerifiedAccountDirectoryFreshness BuildFreshness(
            byte[] network,
            VerifiedXPointNetworkAuthority authority,
            Xnv1Record view,
            SigningKey[] witnesses)
        {
            var adh = new AccountDirectoryAdh1(
                network, 0, new byte[32], 0, Bytes(32, 0x72), Bytes(32, 0x73),
                authority.AuthorityCoreReference.Span, authority.DirectoryWitnessPolicyHash.Span,
                100, 300, 1,
                witnesses.Take(2).Select(static value => new AccountDirectoryAdh1WitnessEntry(value.Id, Bytes(64, 0xa7))).ToArray());
            var exactAdh = AccountDirectoryAdh1Codec.Encode(adh);
            var adhHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(adh);
            var nonce = Bytes(32, 0x74);
            var placeholders = witnesses.Take(2).Select(static value => new AccountDirectoryDtt1WitnessReceipt(value.Id, Bytes(64, 0xa8))).ToArray();
            var issuanceEpoch = AccountDirectoryDtt1IssuanceEpoch.Derive(authority, 200, 5);
            var unsigned = new AccountDirectoryDtt1(
                network, nonce, 200, 5, adhHash, 0, view.CoreHash.Span, view.ViewGeneration,
                authority.AuthorityCoreReference.Span, authority.DirectoryWitnessPolicyHash.Span, 200, 260,
                issuanceEpoch.Id.Span, placeholders);
            var input = AccountDirectoryCrypto.ComputeDtt1SigningInput(unsigned);
            var receipts = witnesses.Take(2).Select(value => new AccountDirectoryDtt1WitnessReceipt(
                value.Id, PublicKeyAuth.SignDetached(input, value.Pair.PrivateKey))).ToArray();
            var dtt = new AccountDirectoryDtt1(
                network, nonce, 200, 5, adhHash, 0, view.CoreHash.Span, view.ViewGeneration,
                authority.AuthorityCoreReference.Span, authority.DirectoryWitnessPolicyHash.Span, 200, 260,
                issuanceEpoch.Id.Span, receipts);
            var exactDtt = AccountDirectoryDtt1Codec.Encode(dtt);
            var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);
            var query = Bytes(32, 0x75);
            var proof = new AccountDirectoryAdp1(
                [1], network, AccountDirectoryAdp1ResultKind.NonMembership, query, adh, 0, new byte[32],
                [], new byte[32], [], false, AccountDirectoryAdp1HistoryMode.ConsistencyOrGenesis, [], dttHash, null);
            var monotonic = new AccountDirectoryMonotonicRequestWindow(Bytes(16, 0xc1), 990, 995, 1_000);
            return new VerifiedAccountDirectoryFreshness(
                exactAdh, adh, adhHash, exactDtt, dttHash, [1], Bytes(32, 0x76), proof, [],
                195, 205, monotonic, 1_050, null);
        }

        private static byte[] BuildPmt(
            byte[] network,
            Xnv1Record view,
            VerifiedAccountDirectoryFreshness freshness,
            byte[][] nodes,
            SigningKey[] witnesses,
            ulong selectionEpoch,
            ulong generation = 0,
            byte[]? predecessorCoreHash = null)
        {
            var parsed = nodes.Select(static value => XPointNetworkCodec.Parse<Xnd1Record>(value))
                .OrderBy(static value => value.NodeId.ToArray(), ByteArrayComparer.Instance).ToArray();
            var rows = parsed.Select(static node =>
            {
                var origin = node.Origins[0];
                return Join(node.NodeId.ToArray(), U64(node.UInt64(16)), origin.Id.ToArray(),
                    origin.CurrentSpki.ToArray(), origin.NextSpki.ToArray());
            }).ToArray();
            ReadOnlyMemory<byte>[] fields =
            [
                network, U64(generation), predecessorCoreHash ?? new byte[32], ArtifactReference("PMA2", Bytes(32, 0x77)),
                XPointNetworkCodec.EncodeCoreReference("XNV1", view.CoreHash.Span), U64(selectionEpoch),
                new byte[] { 2 }, U16(3), Join(rows), U64(100), U64(100), U64(300), new byte[32],
                freshness.ExactAdh1CoreReference, new byte[] { 2 },
                SignatureRows(witnesses.Take(2).Select(static (value, index) =>
                    (value.Id, Bytes(64, checked((byte)(0xa9 + index))))).ToArray()),
            ];
            var provisional = ContactCodec.AuthorForValidation("PMT2", fields);
            var input = provisional.SignatureInput.ToArray();
            fields[15] = SignatureRows(witnesses.Take(2).Select(value =>
                (value.Id, PublicKeyAuth.SignDetached(input, value.Pair.PrivateKey))).ToArray());
            return ContactCodec.AuthorForValidation("PMT2", fields).CanonicalBytes.ToArray();
        }
    }

    private sealed class SuccessorFixture(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness freshness,
        byte[][] policies,
        byte[][] views,
        byte[][] heads,
        byte[][] nodes,
        byte[][] pmts,
        ulong clockSample)
    {
        internal byte[][] Views => views.Select(static value => value.ToArray()).ToArray();
        internal byte[][] Heads => heads.Select(static value => value.ToArray()).ToArray();
        internal byte[][] Policies => policies.Select(static value => value.ToArray()).ToArray();
        internal byte[][] Nodes => nodes.Select(static value => value.ToArray()).ToArray();
        internal byte[][] Pmts => pmts.Select(static value => value.ToArray()).ToArray();
        internal VerifiedAccountDirectoryFreshness Freshness => freshness;

        internal ValueTask<VerifiedOnionNetworkContext> VerifyAsync(VerifiedOnionNetworkContext previous) =>
            OnionNetworkContextVerifier.VerifyAsync(
                authority, freshness, Memories(policies), Memories(views), Memories(heads), Memories(nodes),
                Memories(pmts), previous,
                new OnionTrustedTimeAuthority(new FixedClock(Bytes(16, 0xc1), clockSample)), default);

        internal SuccessorFixture WithoutFirstIntermediate() => new(
            authority, freshness, policies[1..], views[1..], heads[1..], nodes, pmts[1..], clockSample);

        internal SuccessorFixture WithTamperedIntermediateHeadProof()
        {
            var changed = heads.Select(static value => value.ToArray()).ToArray();
            var parsed = XPointNetworkCodec.Parse<Xnh1Record>(changed[0]);
            var fields = Enumerable.Range(1, parsed.Definition.Fields.Count)
                .Select(tag => (ReadOnlyMemory<byte>)parsed.FieldSpan(tag).ToArray()).ToArray();
            var proof = fields[13].ToArray();
            proof[0] ^= 1;
            fields[13] = proof;
            changed[0] = XPointNetworkCodec.Write(XPointNetworkRegistry.Xnh1, fields);
            return new SuccessorFixture(authority, freshness, policies, views, changed, nodes, pmts, clockSample);
        }

        private static ReadOnlyMemory<byte>[] Memories(byte[][] values) =>
            values.Select(static value => (ReadOnlyMemory<byte>)value).ToArray();
    }

    private sealed record ForwardPackage(
        VerifiedXPointNetworkAuthority Authority,
        VerifiedAccountDirectoryFreshness Freshness,
        XPointNetworkProtectedLkg Lkg,
        ReadOnlyMemory<byte>[] AuthorityChain,
        byte[] Xnf,
        byte[] Nfp,
        byte[] CurrentPolicy,
        byte[] TargetView,
        byte[] TargetHead,
        byte[][] CurrentNodes,
        byte[] CurrentPmt,
        ulong ClockSample)
    {
        internal ValueTask<VerifiedXPointNetworkForwardCheckpoint> VerifyAsync() =>
            XPointNetworkForwardCheckpointVerifier.VerifyAsync(
                Authority, Freshness, Lkg, AuthorityChain, new ReadOnlyMemory<byte>[] { Xnf },
                Nfp, TargetView, TargetHead,
                new OnionTrustedTimeAuthority(new FixedClock(Bytes(16, 0xc1), ClockSample)), default);

        internal ValueTask<VerifiedOnionNetworkContext> VerifyContextAsync(
            VerifiedXPointNetworkForwardCheckpoint checkpoint) =>
            OnionNetworkContextVerifier.VerifyFromForwardCheckpointAsync(
                Authority, Freshness, checkpoint, CurrentPolicy,
                CurrentNodes.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(), CurrentPmt,
                new OnionTrustedTimeAuthority(new FixedClock(Bytes(16, 0xc1), ClockSample)), default);

        internal ForwardPackage WithSourceRoot(byte[] root) => this with
        {
            Lkg = new XPointNetworkProtectedLkg(
                Lkg.NetworkId, Lkg.HeadCoreReference, Lkg.HeadTreeSize, root,
                Lkg.ViewCoreReference, Lkg.ViewGeneration, Lkg.AuthorityCoreReference),
        };

        internal ForwardPackage WithProtectedCheckpoint(byte[] checkpointHash, ulong generation) => this with
        {
            Lkg = new XPointNetworkProtectedLkg(
                Lkg.NetworkId, Lkg.HeadCoreReference, Lkg.HeadTreeSize, Lkg.HeadRoot,
                Lkg.ViewCoreReference, Lkg.ViewGeneration, Lkg.AuthorityCoreReference,
                XPointNetworkCodec.EncodeCoreReference("XNF1", checkpointHash), generation),
        };

        internal ForwardPackage WithTamperedXnfSignature() => this with
        {
            Xnf = XPointNetworkTestRecords.MutateField(Xnf, 15, static value => value[^1] ^= 1),
        };

        internal ForwardPackage WithWrongDttReference() => this with
        {
            Nfp = XPointNetworkTestRecords.MutateField(Nfp, 15, static value => value[^1] ^= 1),
        };

        internal ForwardPackage WithTamperedMembershipProof() => this with
        {
            Nfp = XPointNetworkTestRecords.MutateField(Nfp, 14, static value => value[0] ^= 1),
        };

        internal ForwardPackage WithTamperedAuthorityReceipt() => this with
        {
            AuthorityChain =
            [
                XPointNetworkTestRecords.MutateField(AuthorityChain[0].ToArray(), 20, static value => value[^1] ^= 1),
            ],
        };

        internal ForwardPackage WithTamperedTargetViewSignature() => this with
        {
            TargetView = XPointNetworkTestRecords.MutateField(TargetView, 24, static value => value[^1] ^= 1),
        };

        internal ForwardPackage WithTamperedTargetHeadSignature() => this with
        {
            TargetHead = XPointNetworkTestRecords.MutateField(TargetHead, 16, static value => value[^1] ^= 1),
        };

        internal ForwardPackage WithTamperedCurrentPolicySignature() => this with
        {
            CurrentPolicy = XPointNetworkTestRecords.MutateField(CurrentPolicy, 20, static value => value[^1] ^= 1),
        };

        internal ForwardPackage WithTamperedCurrentPmtSignature() => this with
        {
            CurrentPmt = XPointNetworkTestRecords.MutateField(CurrentPmt, 16, static value => value[^1] ^= 1),
        };

        internal ForwardPackage WithClockSample(ulong sample) => this with { ClockSample = sample };
    }

    private static byte[] SignXPoint(
        XPointRecordDefinition definition,
        ReadOnlyMemory<byte>[] fields,
        int signatureFieldIndex,
        IReadOnlyList<(byte[] Id, byte[] PrivateKey)> signers)
    {
        var provisional = XPointNetworkCodec.Parse(XPointNetworkCodec.Write(definition, fields));
        var input = XPointNetworkCrypto.ComputeSigningInput(provisional);
        fields[signatureFieldIndex] = SignatureRows(signers.Select(value =>
            (value.Id, PublicKeyAuth.SignDetached(input, value.PrivateKey))).ToArray());
        return XPointNetworkCodec.Write(definition, fields);
    }

    private static byte[] RootRows(IReadOnlyList<SigningKey> roots) => Join(roots.Select(value =>
        Join(value.Id, U64(0), value.Pair.PublicKey)).ToArray());

    private static byte[] WitnessRows(IReadOnlyList<SigningKey> witnesses) => Join(witnesses.Select(value =>
        Join(value.Id, U64(0), value.Pair.PublicKey, value.FailureDomain)).ToArray());

    private static byte[] SignatureRows(IReadOnlyList<(byte[] Id, byte[] Signature)> rows) =>
        Join(rows.OrderBy(static value => value.Id, ByteArrayComparer.Instance)
            .Select(static value => Join(value.Id, value.Signature)).ToArray());

    private static byte[] OriginRow(byte[] id, int index, byte[] currentSpki, byte[] nextSpki)
    {
        var address = new byte[16];
        address[0] = 10; address[1] = 0; address[2] = 0; address[3] = checked((byte)(index + 1));
        return Join(id, [1], [4], address, U16(checked((ushort)(4_000 + index))), currentSpki,
            U64(100), U64(400), nextSpki, U64(350), U64(800));
    }

    private static byte[] RoleRows(ushort roles, int nodeIndex)
    {
        var rows = new List<byte[]>();
        for (byte role = 0; role < 5; role++)
        {
            if ((roles & (1 << role)) == 0) continue;
            var pair = PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(0xc0 + nodeIndex * 5 + role))));
            rows.Add(Join([role], U64(0), pair.PublicKey));
        }
        return Join(rows.ToArray());
    }

    private static byte[] FailureDomain(
        byte[] network,
        ReadOnlySpan<byte> operatorId,
        byte[] host,
        ReadOnlySpan<byte> provider,
        ReadOnlySpan<byte> asn,
        ReadOnlySpan<byte> jurisdiction) => XPointNetworkCrypto.Sha256Domain(
            XPointNetworkRegistry.FailureDomainDomain,
            Join(network, operatorId.ToArray(), host, provider.ToArray(), asn.ToArray(), jurisdiction.ToArray()));

    private static byte[] ViewLeaf(Xnv1Record view)
    {
        Span<byte> payload = stackalloc byte[72];
        BinaryPrimitives.WriteUInt64BigEndian(payload, view.ViewGeneration);
        view.FieldSpan(3).CopyTo(payload[8..40]);
        view.CoreHash.Span.CopyTo(payload[40..]);
        return XPointNetworkCrypto.Rfc6962Leaf(payload);
    }

    private static byte[] CoveredHeadLeaf(Xnv1Record view, Xnh1Record head)
    {
        Span<byte> payload = stackalloc byte[80];
        BinaryPrimitives.WriteUInt64BigEndian(payload, view.ViewGeneration);
        view.CoreHash.Span.CopyTo(payload[8..40]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[40..48], head.TreeSize);
        head.Root.Span.CopyTo(payload[48..]);
        return XPointNetworkCrypto.Rfc6962Leaf(payload);
    }

    private static byte[] ServiceRank(byte[] network, ulong epoch, byte[] input, byte[] node)
    {
        var label = Encoding.ASCII.GetBytes("Deep/ContactResolver/V1/service-rendezvous-sha256/v1");
        return SHA256.HashData(Join(label, [0], network, U64(epoch), input, node));
    }

    private static IEnumerable<byte[]> Rows(ReadOnlySpan<byte> source, int width)
    {
        var rows = new List<byte[]>(source.Length / width);
        for (var offset = 0; offset < source.Length; offset += width)
            rows.Add(source.Slice(offset, width).ToArray());
        return rows;
    }

    private static byte[] ArtifactReference(string magic, ReadOnlySpan<byte> hash)
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
        foreach (var value in values) { value.CopyTo(output, offset); offset += value.Length; }
        return output;
    }

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] U32(uint value)
    {
        var output = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(output, value);
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
