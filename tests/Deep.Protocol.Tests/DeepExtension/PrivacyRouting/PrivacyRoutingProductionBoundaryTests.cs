using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.DeepExtension.PrivacyRouting;

public sealed class PrivacyRoutingProductionBoundaryTests
{
    [Fact]
    public async Task ProductionBoundary_RoundTripsContactResolve_WithDurableCommitBeforeRelease()
    {
        using var fixture = new ProductionFixture();
        var ledger = new FakeEntropyLedger();
        var replayStore = new FakeReplayStore();
        var codec = fixture.Codec(ledger);
        var request = OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Network, OnionOperation.ContactResolve, ContactQuery(fixture.Network.NetworkId.Span));

        using var built = await codec.BuildAsync(fixture.Path(OnionOperation.ContactResolve), request, default);
        Assert.NotEqual(new byte[32], built.AttemptId.ToArray());
        Assert.Equal(8, ledger.Batches.Single().Commitments.Count);

        using var ingress = Assert.IsType<OpenedOnionRelay>(
            await Open(codec, fixture.Receive(0, built.Frame), built.Frame, replayStore));
        Assert.Equal(1, replayStore.CommitCount);
        Assert.Equal(fixture.Nodes[1].NodeId, ingress.NextHop.NodeId.ToArray());
        Assert.Equal(OnionNextHopTransport.TcpTls, ingress.NextHop.Transport);
        Assert.Equal(OnionNextHopAddressFamily.IPv4, ingress.NextHop.AddressFamily);
        Assert.Equal(fixture.Nodes[1].OriginAddress, ingress.NextHop.Address.ToArray());
        Assert.Equal(fixture.Nodes[1].OriginPort, ingress.NextHop.Port);
        Assert.Equal(fixture.Nodes[1].OriginSpki, ingress.NextHop.SpkiSha256.ToArray());
        using var core = Assert.IsType<OpenedOnionRelay>(
            await Open(codec, fixture.Receive(1, ingress.InnerFrame), ingress.InnerFrame, replayStore));
        Assert.Equal(2, replayStore.CommitCount);
        using var exit = Assert.IsType<OpenedOnionExit>(
            await Open(codec, fixture.Receive(2, core.InnerFrame), core.InnerFrame, replayStore));
        Assert.Equal(3, replayStore.CommitCount);
        Assert.Equal(request.CanonicalBytes.ToArray(), exit.Request.CanonicalBytes.ToArray());

        var resultBytes = Xis1Codec.Encode(
            request.CanonicalBytes.Span, Xis1Status.NotFound, ContactServiceMutationOutcome.None,
            50, 0, ContactServicePaddingClass.Bytes256, []);
        var result = OnionTerminalPayloadVerifierV1.VerifySuccess(exit.Request, resultBytes);
        var response = await codec.SealAsync(exit.ReplyContext, result, default);
        Assert.Equal(2, ledger.Batches.Count);
        Assert.True(ledger.Batches[1].IsResponse);
        var opened = await codec.OpenResponseAsync(response, built.ReplyContext, default);
        Assert.Equal(resultBytes, opened.Result.Body.ToArray());
        Assert.Equal(OnionOperation.ContactResolve, opened.Result.Operation);
    }

    [Fact]
    public async Task OpenAsync_AmbiguousOrCancelledCommit_ReleasesNoCapabilityAndBurnsLease()
    {
        using var fixture = new ProductionFixture();
        var codec = fixture.Codec(new FakeEntropyLedger());
        var request = OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Network, OnionOperation.ContactResolve, ContactQuery(fixture.Network.NetworkId.Span));
        using var built = await codec.BuildAsync(fixture.Path(OnionOperation.ContactResolve), request, default);

        var ambiguousStore = new FakeReplayStore { Outcome = OnionReplayCommitOutcome.Ambiguous };
        var receive = fixture.Receive(0, built.Frame);
        await using var ambiguousLease = await new OnionReplayAuthority(ambiguousStore)
            .BeginOpenAsync(receive, built.Frame, default);
        var ambiguous = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await codec.OpenAsync(built.Frame, receive, ambiguousLease, default));
        Assert.Equal("replay-commit-ambiguous", ambiguous.Code);
        Assert.True(ambiguousStore.Disposed);
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await codec.OpenAsync(built.Frame, receive, ambiguousLease, default));

        var cancelledStore = new FakeReplayStore { CancelAfterMayHaveCommitted = true };
        await using var cancelledLease = await new OnionReplayAuthority(cancelledStore)
            .BeginOpenAsync(receive, built.Frame, default);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await codec.OpenAsync(built.Frame, receive, cancelledLease, default));
        Assert.True(cancelledStore.MayHaveCommitted);
        Assert.True(cancelledStore.Disposed);
    }

    [Theory]
    [InlineData(OnionEntropyCommitOutcome.Duplicate, "entropy-duplicate")]
    [InlineData(OnionEntropyCommitOutcome.Ambiguous, "entropy-commit-ambiguous")]
    [InlineData(OnionEntropyCommitOutcome.Rejected, "entropy-commit-rejected")]
    public async Task BuildAsync_EntropyDuplicatePartialOrRejected_EmitsNoFrame(
        OnionEntropyCommitOutcome outcome,
        string expectedCode)
    {
        using var fixture = new ProductionFixture();
        var ledger = new FakeEntropyLedger { Outcome = outcome };
        var codec = fixture.Codec(ledger);
        var request = OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Network, OnionOperation.ContactResolve, ContactQuery(fixture.Network.NetworkId.Span));

        var error = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await codec.BuildAsync(fixture.Path(OnionOperation.ContactResolve), request, default));
        Assert.Equal(expectedCode, error.Code);
        Assert.Single(ledger.Batches);
    }

    [Fact]
    public void Capabilities_AreNonForgeable_AndCodecHasOnlyFourAsyncRuntimeMethods()
    {
        Assert.False(PrivacyRoutingCodec.RuntimeActivation);
        foreach (var type in new[]
                 {
                     typeof(VerifiedOnionNetworkContext), typeof(OnionTrustedTimeLease),
                     typeof(VerifiedOnionPathContext), typeof(VerifiedOnionLocalNodeKey),
                     typeof(VerifiedOnionReceiveContext), typeof(VerifiedOnionNextHopTransport),
                     typeof(VerifiedGroupControlPlacement),
                     typeof(VerifiedCanonicalOnionRequest), typeof(VerifiedOnionTerminalResult),
                     typeof(OnionReplayOpenLease), typeof(OnionReplyContext), typeof(OnionExitReplyContext)
                 })
        {
            Assert.True(type.IsSealed);
            Assert.Empty(type.GetConstructors());
        }

        var methods = typeof(PrivacyRoutingCodec).GetMethods(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .OrderBy(static method => method.Name)
            .ToArray();
        Assert.Equal(["BuildAsync", "OpenAsync", "OpenResponseAsync", "SealAsync"],
            methods.Select(static method => method.Name).ToArray());
        Assert.DoesNotContain(methods.SelectMany(static method => method.GetParameters()), parameter =>
            parameter.Name?.Contains("attempt", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("private", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("entropy", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.IsOptional);

        Assert.Equal(
            ["VerifyFailure", "VerifyRequest", "VerifySuccess"],
            typeof(OnionTerminalPayloadVerifierV1).GetMethods(
                    BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Select(static method => method.Name).Order().ToArray());
        Assert.Equal("BeginOpenAsync", Assert.Single(typeof(OnionReplayAuthority).GetMethods(
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)).Name);
        Assert.Equal(
            ["VerifyAsync", "VerifyFromForwardCheckpointAsync", "VerifyRehydratedCurrentAsync"],
            typeof(OnionNetworkContextVerifier).GetMethods(
                    BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Select(static method => method.Name).Order().ToArray());
        Assert.Equal(["CreateContactResolver", "CreateGroupControl", "CreateMailbox"],
            typeof(OnionPathContextFactory).GetMethods(
                    BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Select(static method => method.Name).Order(StringComparer.Ordinal).ToArray());
        var bind = Assert.Single(typeof(OnionLocalNodeKeyFactory).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Equal("Bind", bind.Name);
        Assert.Equal(
            [typeof(VerifiedOnionNetworkContext), typeof(OnionReceivePosition),
             typeof(ReadOnlyMemory<byte>), typeof(OnionKeyHandle)],
            bind.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        var select = Assert.Single(typeof(OnionReceiveContextSelector).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Equal("Select", select.Name);
        Assert.Equal(
            [typeof(ReadOnlyMemory<byte>), typeof(VerifiedOnionLocalNodeKey)],
            select.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.Null(typeof(OpenedOnionRelay).GetProperty("NextRouterId"));
        Assert.Equal(typeof(VerifiedOnionNextHopTransport),
            typeof(OpenedOnionRelay).GetProperty("NextHop")?.PropertyType);
        Assert.Equal(typeof(ReadOnlyMemory<byte>),
            typeof(OnionReplayScope).GetProperty("BootId")?.PropertyType);
    }

    [Fact]
    public void PublicPathAndReceiveFactories_SelectOnlyNodesSealedIntoVerifiedNetworkContext()
    {
        var time = new OnionTrustedTimeLease(TimeProvider.System, TimeSpan.FromMinutes(5), Fill(0xf1, 32));
        var nodes = new[]
        {
            Node(0x11, 0xa1, 0x31, roleMask: 1 << 0, failure: 0xd1),
            Node(0x22, 0xa2, 0x32, roleMask: 1 << 1, failure: 0xd2),
            Node(0x33, 0xa3, 0x33, roleMask: 1 << 2, failure: 0xd3)
        };
        var network = new VerifiedOnionNetworkContext(
            Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), time, nodes);
        var placement = new VerifiedContactServicePlacement(
            network, ContactServiceRequestKind.ResolveInvite, ContactServiceClass.InviteResolver,
            Fill(0xc1, 32), Fill(0xc2, 32), Fill(0xc3, 32), 7, 300,
            [nodes[2].NodeId, Fill(0x44, 32)]);

        var path = OnionPathContextFactory.CreateContactResolver(
            network, placement, nodes[0].NodeId, nodes[1].NodeId, nodes[2].NodeId);
        Assert.Equal(nodes[0].NodeId, path.EntryRouterId.ToArray());
        var entryCopy = path.EntryRouterId;
        MemoryMarshal.AsMemory(entryCopy).Span.Fill(0);
        Assert.Equal(nodes[0].NodeId, path.EntryRouterId.ToArray());
        var ingress = OnionLocalNodeKeyFactory.Bind(
            network, OnionReceivePosition.Ingress, nodes[0].NodeId, new OnionKeyHandle(Fill(0xe1, 32)));
        var exit = OnionLocalNodeKeyFactory.Bind(
            network, OnionReceivePosition.Exit, nodes[2].NodeId, new OnionKeyHandle(Fill(0xe3, 32)));
        Assert.Equal(OnionReceivePosition.Ingress, ingress.Position);
        Assert.Equal(OnionReceivePosition.Exit, exit.Position);
        Assert.Throws<OnionBoundaryException>(() => OnionPathContextFactory.CreateContactResolver(
            network, placement, nodes[0].NodeId, nodes[1].NodeId, Fill(0xff, 32)));
    }

    [Fact]
    public void MailboxPathFactory_BindsClosedOperationAndExactVerifiedReplicaPair()
    {
        var time = new OnionTrustedTimeLease(
            TimeProvider.System,
            TimeSpan.FromMinutes(5),
            Fill(0xf2, 32));
        var nodes = new[]
        {
            Node(0x11, 0xa1, 0x31, roleMask: 1 << 0, failure: 0xd1),
            Node(0x22, 0xa2, 0x32, roleMask: 1 << 1, failure: 0xd2),
            Node(0x33, 0xa3, 0x33, roleMask: 1 << 2, failure: 0xd3),
            Node(0x44, 0xa4, 0x34, roleMask: 1 << 2, failure: 0xd4)
        };
        var network = new VerifiedOnionNetworkContext(
            Convert.FromHexString("00112233445566778899AABBCCDDEEFF"),
            time,
            nodes);

        var path = OnionPathContextFactory.CreateMailbox(
            network,
            OnionOperation.Store,
            nodes[2].NodeId,
            nodes[3].NodeId,
            nodes[0].NodeId,
            nodes[1].NodeId,
            nodes[2].NodeId);

        Assert.Equal(nodes[0].NodeId, path.EntryRouterId.ToArray());
        Assert.Equal(OnionOperation.Store, path.Operation);
        var wrongExit = Assert.Throws<OnionBoundaryException>(() =>
            OnionPathContextFactory.CreateMailbox(
                network,
                OnionOperation.Retrieve,
                nodes[2].NodeId,
                nodes[3].NodeId,
                nodes[0].NodeId,
                nodes[1].NodeId,
                nodes[1].NodeId));
        Assert.Equal("path-role-invalid", wrongExit.Code);
        var wrongOperation = Assert.Throws<OnionBoundaryException>(() =>
            OnionPathContextFactory.CreateMailbox(
                network,
                OnionOperation.ContactResolve,
                nodes[2].NodeId,
                nodes[3].NodeId,
                nodes[0].NodeId,
                nodes[1].NodeId,
                nodes[2].NodeId));
        Assert.Equal("mailbox-operation-invalid", wrongOperation.Code);
        var duplicate = Assert.Throws<OnionBoundaryException>(() =>
            OnionPathContextFactory.CreateMailbox(
                network,
                OnionOperation.Acknowledge,
                nodes[2].NodeId,
                nodes[2].NodeId,
                nodes[0].NodeId,
                nodes[1].NodeId,
                nodes[2].NodeId));
        Assert.Equal("mailbox-replica-duplicate", duplicate.Code);
    }

    [Fact]
    public void VerifiedPathAndReceive_RejectWrongCardinalityRolesAndNextHop()
    {
        using var fixture = new ProductionFixture();
        Assert.Throws<PrivacyRoutingProtocolException>(() => new VerifiedOnionPathContext(
            fixture.Network, fixture.Time, OnionOperation.ContactResolve, fixture.Route[..2]));
        var wrongRoles = fixture.Route.ToArray();
        wrongRoles[2] = new PrivacyRoutingHop(
            Fill(0x70, 32), Fill(0x71, 32), 7, PrivacyRoutingKeyRole.Relay, ScalarMult.Base(Fill(0x72, 32)));
        Assert.Throws<PrivacyRoutingProtocolException>(() => new VerifiedOnionPathContext(
            fixture.Network, fixture.Time, OnionOperation.ContactResolve, wrongRoles));
        Assert.Throws<OnionBoundaryException>(() => new VerifiedOnionLocalNodeKey(
            fixture.Network, OnionReceivePosition.Core, fixture.Nodes[2],
            new OnionKeyHandle(Fill(0x90, 32))));
    }

    [Fact]
    public async Task ReceiveSelector_DerivesNextHopFromAuthenticatedLayer_AndRejectsUnknownNodeBeforeReplay()
    {
        using var fixture = new ProductionFixture();
        var codec = fixture.Codec(new FakeEntropyLedger());
        var request = OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Network, OnionOperation.ContactResolve, ContactQuery(fixture.Network.NetworkId.Span));
        var rogueRoute = fixture.Route.ToArray();
        rogueRoute[1] = new PrivacyRoutingHop(
            Fill(0x66, 32), Fill(0xa6, 32), 7, PrivacyRoutingKeyRole.Relay,
            ScalarMult.Base(Fill(0x36, 32)));
        var roguePath = new VerifiedOnionPathContext(
            fixture.Network, fixture.Time, OnionOperation.ContactResolve, rogueRoute);
        using var built = await codec.BuildAsync(roguePath, request, default);
        var receive = fixture.Receive(0, built.Frame);
        var store = new FakeReplayStore();

        var error = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await Open(codec, receive, built.Frame, store));

        Assert.Equal("node-not-in-view", error.Code);
        Assert.Equal(0, store.CommitCount);
    }

    [Fact]
    public async Task ReceiveSelector_RejectsHostileHeader_AndNextHopCapabilityDefensivelyCopies()
    {
        using var fixture = new ProductionFixture();
        var codec = fixture.Codec(new FakeEntropyLedger());
        var request = OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Network, OnionOperation.ContactResolve, ContactQuery(fixture.Network.NetworkId.Span));
        using var built = await codec.BuildAsync(fixture.Path(OnionOperation.ContactResolve), request, default);
        var hostile = built.Frame.ToArray();
        hostile[28] ^= 0x01;

        var error = Assert.Throws<OnionBoundaryException>(() =>
            OnionReceiveContextSelector.Select(hostile, fixture.LocalKeys[0]));
        Assert.Equal("receive-frame-invalid", error.Code);

        var store = new FakeReplayStore();
        using var opened = Assert.IsType<OpenedOnionRelay>(
            await Open(codec, fixture.Receive(0, built.Frame), built.Frame, store));
        var address = opened.NextHop.Address;
        var spki = opened.NextHop.SpkiSha256;
        MemoryMarshal.AsMemory(address).Span.Fill(0);
        MemoryMarshal.AsMemory(spki).Span.Fill(0);
        Assert.Equal(fixture.Nodes[1].OriginAddress, opened.NextHop.Address.ToArray());
        Assert.Equal(fixture.Nodes[1].OriginSpki, opened.NextHop.SpkiSha256.ToArray());
    }

    [Fact]
    public async Task ReplayScope_ExposesDefensiveBootId_AndLeaseRejectsAnotherBoot()
    {
        using var fixture = new ProductionFixture();
        var codec = fixture.Codec(new FakeEntropyLedger());
        var request = OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Network, OnionOperation.ContactResolve, ContactQuery(fixture.Network.NetworkId.Span));
        using var built = await codec.BuildAsync(fixture.Path(OnionOperation.ContactResolve), request, default);
        var store = new FakeReplayStore();
        var receive = fixture.Receive(0, built.Frame);
        await using var lease = await new OnionReplayAuthority(store).BeginOpenAsync(receive, built.Frame, default);
        var scope = Assert.IsType<OnionReplayScope>(store.Scope);
        Assert.Equal(Fill(0xf0, 32), scope.BootId.ToArray());
        var bootCopy = scope.BootId;
        MemoryMarshal.AsMemory(bootCopy).Span.Fill(0);
        Assert.Equal(Fill(0xf0, 32), scope.BootId.ToArray());

        var otherTime = new OnionTrustedTimeLease(TimeProvider.System, TimeSpan.FromMinutes(5), Fill(0xf1, 32));
        var otherNetwork = new VerifiedOnionNetworkContext(
            fixture.Network.NetworkId.Span, otherTime, fixture.Nodes);
        var otherLocal = OnionLocalNodeKeyFactory.Bind(
            otherNetwork, OnionReceivePosition.Ingress, fixture.Nodes[0].NodeId, fixture.Handles[0]);
        var otherReceive = OnionReceiveContextSelector.Select(built.Frame, otherLocal);

        var error = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await codec.OpenAsync(built.Frame, otherReceive, lease, default));
        Assert.Equal("replay-lease-mismatch", error.Code);
        Assert.Equal(0, store.CommitCount);
    }

    [Fact]
    public async Task NextHopTransport_InvalidVerifiedOriginFailsBeforeReplayCommit()
    {
        using var fixture = new ProductionFixture();
        var nodes = fixture.Nodes.ToArray();
        nodes[1] = nodes[1] with { OriginTransport = 3 };
        var network = new VerifiedOnionNetworkContext(
            fixture.Network.NetworkId.Span, fixture.Time, nodes);
        var route = new[]
        {
            OnionPathContextFactory.Hop(nodes[0], PrivacyRoutingKeyRole.Relay),
            OnionPathContextFactory.Hop(nodes[1], PrivacyRoutingKeyRole.Relay),
            OnionPathContextFactory.Hop(nodes[2], PrivacyRoutingKeyRole.Exit)
        };
        var request = OnionTerminalPayloadVerifierV1.VerifyRequest(
            network, OnionOperation.ContactResolve, ContactQuery(network.NetworkId.Span));
        var path = new VerifiedOnionPathContext(
            network, fixture.Time, OnionOperation.ContactResolve, route);
        var codec = fixture.Codec(new FakeEntropyLedger());
        using var built = await codec.BuildAsync(path, request, default);
        var local = OnionLocalNodeKeyFactory.Bind(
            network, OnionReceivePosition.Ingress, nodes[0].NodeId, fixture.Handles[0]);
        var receive = OnionReceiveContextSelector.Select(built.Frame, local);
        var store = new FakeReplayStore();

        var error = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await Open(codec, receive, built.Frame, store));

        Assert.Equal("next-hop-origin-invalid", error.Code);
        Assert.Equal(0, store.CommitCount);
    }

    private static async ValueTask<OpenedOnionLayer> Open(
        PrivacyRoutingCodec codec,
        VerifiedOnionReceiveContext receive,
        ReadOnlyMemory<byte> frame,
        FakeReplayStore store)
    {
        await using var lease = await new OnionReplayAuthority(store).BeginOpenAsync(receive, frame, default);
        return await codec.OpenAsync(frame, receive, lease, default);
    }

    private static byte[] ContactQuery(ReadOnlySpan<byte> network) => Xiq1Codec.Encode(
        network, Fill(0x21, 32), Fill(0x41, 32), Fill(0x61, 32), 10, 100,
        Fill(0x81, 32), 0, Xiq1AntiSpamTokenType.None, [], ContactServicePaddingClass.Bytes256);

    private static byte[] Fill(byte value, int length) => Enumerable.Repeat(value, length).ToArray();

    private static byte[] IPv4(byte value)
    {
        var address = new byte[16];
        address.AsSpan(0, 4).Fill(value);
        return address;
    }

    private static VerifiedNetworkNode Node(byte node, byte keyId, byte scalar, ushort roleMask, byte failure) =>
        new(Fill(node, 32), Fill(node, 32), Fill((byte)(node + 1), 32), Fill(failure, 32),
            Fill((byte)(node + 2), 32), 1, 4, IPv4((byte)(node + 3)), 443,
            Fill((byte)(node + 4), 32), roleMask,
            (roleMask & 0x0001) != 0 ? 1U : 0U,
            (roleMask & 0x0002) != 0 ? 1UL : 0UL,
            (roleMask & 0x0004) != 0 ? 1UL : 0UL,
            7, Fill(keyId, 32), ScalarMult.Base(Fill(scalar, 32)));

    private sealed class FakeEntropyLedger : IOnionEntropyUniquenessLedger
    {
        public OnionEntropyCommitOutcome Outcome { get; init; } = OnionEntropyCommitOutcome.Committed;
        public List<OnionEntropyCommitmentBatch> Batches { get; } = [];
        public ValueTask<OnionEntropyCommitOutcome> CommitAsync(
            OnionEntropyCommitmentBatch batch,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Batches.Add(batch);
            return ValueTask.FromResult(Outcome);
        }
    }

    private sealed class FakeReplayStore : IOnionDurableReplayStore
    {
        public OnionReplayCommitOutcome Outcome { get; init; } = OnionReplayCommitOutcome.Committed;
        public bool CancelAfterMayHaveCommitted { get; init; }
        public bool MayHaveCommitted { get; private set; }
        public bool Disposed { get; private set; }
        public int CommitCount { get; private set; }
        public OnionReplayScope? Scope { get; private set; }

        public ValueTask<IOnionDurableReplayTransaction> BeginAsync(
            OnionReplayScope scope,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Scope = scope;
            return ValueTask.FromResult<IOnionDurableReplayTransaction>(new Transaction(this));
        }

        private sealed class Transaction(FakeReplayStore owner) : IOnionDurableReplayTransaction
        {
            public ValueTask<OnionReplayCommitOutcome> CommitAsync(
                ReadOnlyMemory<byte> replayId,
                CancellationToken cancellationToken)
            {
                Assert.NotEqual(new byte[32], replayId.ToArray());
                owner.CommitCount++;
                if (owner.CancelAfterMayHaveCommitted)
                {
                    owner.MayHaveCommitted = true;
                    throw new OperationCanceledException(cancellationToken);
                }
                return ValueTask.FromResult(owner.Outcome);
            }
            public ValueTask DisposeAsync()
            {
                owner.Disposed = true;
                return ValueTask.CompletedTask;
            }
        }
    }

    private sealed class FakeKeyVault(IReadOnlyDictionary<string, byte[]> scalars) : IOnionKeyAgreementVault
    {
        public ValueTask<byte[]> DeriveX25519SharedSecretAsync(
            OnionKeyHandle keyHandle,
            ReadOnlyMemory<byte> peerPublicKey,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var scalar = scalars[Convert.ToHexString(keyHandle.Id.Span)];
            return ValueTask.FromResult(ScalarMult.Mult(scalar, peerPublicKey.ToArray()));
        }
    }

    private sealed class ProductionFixture : IDisposable
    {
        private readonly byte[][] _scalars;
        private readonly IReadOnlyDictionary<string, byte[]> _keyMap;

        internal ProductionFixture()
        {
            Time = new OnionTrustedTimeLease(TimeProvider.System, TimeSpan.FromMinutes(5), Fill(0xf0, 32));
            _scalars = [Fill(0x31, 32), Fill(0x32, 32), Fill(0x33, 32)];
            Nodes = [
                Node(0x11, 0xa1, 0x31, roleMask: 1 << 0, failure: 0xd1),
                Node(0x22, 0xa2, 0x32, roleMask: 1 << 1, failure: 0xd2),
                Node(0x33, 0xa3, 0x33, roleMask: 1 << 2, failure: 0xd3)
            ];
            Network = new VerifiedOnionNetworkContext(
                Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), Time, Nodes);
            Route = [
                OnionPathContextFactory.Hop(Nodes[0], PrivacyRoutingKeyRole.Relay),
                OnionPathContextFactory.Hop(Nodes[1], PrivacyRoutingKeyRole.Relay),
                OnionPathContextFactory.Hop(Nodes[2], PrivacyRoutingKeyRole.Exit)
            ];
            Handles = [new OnionKeyHandle(Fill(0xb1, 32)), new OnionKeyHandle(Fill(0xb2, 32)), new OnionKeyHandle(Fill(0xb3, 32))];
            LocalKeys = [
                OnionLocalNodeKeyFactory.Bind(Network, OnionReceivePosition.Ingress, Nodes[0].NodeId, Handles[0]),
                OnionLocalNodeKeyFactory.Bind(Network, OnionReceivePosition.Core, Nodes[1].NodeId, Handles[1]),
                OnionLocalNodeKeyFactory.Bind(Network, OnionReceivePosition.Exit, Nodes[2].NodeId, Handles[2])
            ];
            _keyMap = Handles.Select((handle, index) => (handle, index)).ToDictionary(
                static item => Convert.ToHexString(item.handle.Id.Span), item => _scalars[item.index]);
        }

        internal VerifiedOnionNetworkContext Network { get; }
        internal OnionTrustedTimeLease Time { get; }
        internal VerifiedNetworkNode[] Nodes { get; }
        internal PrivacyRoutingHop[] Route { get; }
        internal OnionKeyHandle[] Handles { get; }
        internal VerifiedOnionLocalNodeKey[] LocalKeys { get; }
        internal PrivacyRoutingCodec Codec(IOnionEntropyUniquenessLedger ledger) =>
            new(new OnionEntropyAuthority(ledger), new OnionKeyAgreementAuthority(new FakeKeyVault(_keyMap)));
        internal VerifiedOnionPathContext Path(OnionOperation operation) => new(Network, Time, operation, Route);
        internal VerifiedOnionReceiveContext Receive(int index, ReadOnlyMemory<byte> frame) =>
            OnionReceiveContextSelector.Select(frame, LocalKeys[index]);
        public void Dispose()
        {
            foreach (var scalar in _scalars) CryptographicOperations.ZeroMemory(scalar);
        }
    }
}
