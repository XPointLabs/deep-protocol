using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.GroupV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class XPointOnionCapabilityProducerTests
{
    [Fact]
    public async Task TrustedTimeLeaseSubtractsElapsedTimeFromNetworkHardExpiry()
    {
        var freshness = Fixture.Create().Did2TimeEvidence();
        var networkTime = (IVerifiedDirectoryNetworkTime)freshness;
        var later = checked(freshness.MonotonicSample + 1);
        var expired = checked(freshness.MonotonicSample + 2);
        Assert.True(expired < freshness.FreshnessDeadlineMonotonicSeconds);
        var hardUpper = checked(freshness.TrustedUpperUnixSeconds + 2);
        var current = new OnionTrustedTimeAuthority(new FixedClock(networkTime.BootId.ToArray(), later));
        var lease = await current.MintAsync(freshness, hardUpper, default);
        Assert.InRange(lease.Remaining, TimeSpan.Zero, TimeSpan.FromSeconds(1));
        var tooLate = new OnionTrustedTimeAuthority(new FixedClock(networkTime.BootId.ToArray(), expired));
        var error = await Assert.ThrowsAsync<OnionBoundaryException>(() => tooLate.MintAsync(freshness, hardUpper, default).AsTask());
        Assert.Equal("trusted-time-invalid", error.Code);
    }

    [Fact]
    public async Task ProtectedHistory_EqualTipRetainsActualPredecessor()
    {
        var fixture = Fixture.Create();
        var previous = await fixture.VerifyDid2Async();
        var history = OnionNetworkProtectedHistoryCodec.Encode(previous);
        var current = await fixture.VerifyHistoryAsync(history);
        Assert.Equal(history, OnionNetworkProtectedHistoryCodec.Encode(current));
        Assert.True(OnionNetworkProtectedHistoryCodec.BindsPredecessor(current, history));
        Assert.False(OnionNetworkProtectedHistoryCodec.BindsPredecessor(previous, history));
        var fork = await Fixture.Create(selectionEpoch: 8).VerifyDid2Async();
        Assert.Equal(previous.ProtectedLkg!.ViewCoreReference.ToArray(), fork.ProtectedLkg!.ViewCoreReference.ToArray());
        Assert.False(OnionNetworkProtectedHistoryCodec.BindsPredecessor(current, OnionNetworkProtectedHistoryCodec.Encode(fork)));
        Assert.Equal(previous.ProtectedLkg!.HeadCoreReference.ToArray(), current.PriorProtectedLkg!.HeadCoreReference.ToArray());
        var copy = OnionNetworkProtectedHistoryCodec.Encode(current); copy.AsSpan().Fill(0);
        Assert.Equal(history, OnionNetworkProtectedHistoryCodec.Encode(current));
    }

    [Fact]
    public async Task ProtectedHistory_FullSuccessorDoesNotReviveExpiredPriorLease()
    {
        var fixture = Fixture.Create();
        var previous = await fixture.WithClockSample(fixture.FreshnessDeadline - 1).VerifyDid2Async();
        var history = OnionNetworkProtectedHistoryCodec.Encode(previous);
        await Task.Delay(TimeSpan.FromMilliseconds(1_100));
        Assert.Equal("trusted-time-expired", Assert.Throws<OnionBoundaryException>(previous.EnsureCurrent).Code);
        var current = await fixture.VerifyHistoryAsync(history, fixture.BuildSuccessorChain());
        current.EnsureCurrent();
        Assert.Equal(2UL, current.ProtectedLkg!.ViewGeneration);
        Assert.Equal(0UL, current.PriorProtectedLkg!.ViewGeneration);
        Assert.Equal(previous.ProtectedLkg!.HeadRoot.ToArray(), current.PriorProtectedLkg.HeadRoot.ToArray());
        Assert.Equal("trusted-time-expired", Assert.Throws<OnionBoundaryException>(previous.EnsureCurrent).Code);
    }

    [Theory]
    [InlineData("magic")]
    [InlineData("version")]
    [InlineData("reserved")]
    [InlineData("length")]
    [InlineData("checkpoint")]
    [InlineData("trailing")]
    [InlineData("max+1")]
    [InlineData("root")]
    [InlineData("policy-signature")]
    [InlineData("pmt-signature")]
    public async Task ProtectedHistory_RejectsMalformedOrForgedCapsule(string fault)
    {
        var fixture = Fixture.Create();
        var history = OnionNetworkProtectedHistoryCodec.Encode(await fixture.VerifyDid2Async());
        switch (fault)
        {
            case "magic": history[0] ^= 1; break;
            case "version": history[5] = 1; break;
            case "reserved": history[7] = 1; break;
            case "length": history[11] ^= 1; break;
            case "checkpoint": history[16 + 178] = 2; break;
            case "root": history[16 + 62] ^= 1; break;
            case "trailing": history = [.. history, 0]; break;
            case "max+1": history = new byte[16 + 225 + 2 * 65_535 + 1]; break;
            case "policy-signature":
                var length = BinaryPrimitives.ReadUInt32BigEndian(history.AsSpan(8));
                history[16 + 225 + (int)length - 1] ^= 1; break;
            default: history[^1] ^= 1; break;
        }
        var failure = await Assert.ThrowsAsync<OnionBoundaryException>(async () => await fixture.VerifyHistoryAsync(history));
        Assert.Contains(failure.Code, new[] { "network-history-invalid", "network-history-mismatch" });
    }

    [Fact]
    public async Task ProtectedHistory_RejectsCrossNetworkForkOmissionAndRollback()
    {
        var fixture = Fixture.Create();
        var history = OnionNetworkProtectedHistoryCodec.Encode(await fixture.VerifyDid2Async());
        await Assert.ThrowsAsync<OnionBoundaryException>(async () => await Fixture.Create(0x12).VerifyHistoryAsync(history));
        await Assert.ThrowsAsync<OnionBoundaryException>(async () => await fixture.WithArtifacts(0x71).VerifyHistoryAsync(history));
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fixture.VerifyHistoryAsync(history, fixture.BuildSuccessorChain().WithoutFirstIntermediate()));
        var latest = await fixture.VerifyHistoryAsync(history, fixture.BuildSuccessorChain());
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fixture.VerifyHistoryAsync(OnionNetworkProtectedHistoryCodec.Encode(latest)));
    }

    [Fact]
    public async Task InstalledPublicKey_UsesOnlyVerifiedActiveDescriptor()
    {
        var fixture = Fixture.Create();
        var network = await fixture.VerifyDid2Async();
        OnionLocalNodeKeyFactory.EnsureInstalledPublicKey(network, fixture.NodeIds[0], ScalarMult.Base(Bytes(32, 0xa0)));
        Assert.Equal("local-node-key-mismatch", Assert.Throws<OnionBoundaryException>(() =>
            OnionLocalNodeKeyFactory.EnsureInstalledPublicKey(network, fixture.NodeIds[0], ScalarMult.Base(Bytes(32, 0xb0)))).Code);
        Assert.Equal("local-node-key-mismatch", Assert.Throws<OnionBoundaryException>(() =>
            OnionLocalNodeKeyFactory.EnsureInstalledPublicKey(network, fixture.NodeIds[0], new byte[31])).Code);
        Assert.Equal("node-not-in-view", Assert.Throws<OnionBoundaryException>(() =>
            OnionLocalNodeKeyFactory.EnsureInstalledPublicKey(network, Bytes(32, 0xdf), ScalarMult.Base(Bytes(32, 0xa0)))).Code);
    }

    [Theory]
    [InlineData(0, 1, 2)]
    [InlineData(0, 2, 1)]
    [InlineData(1, 0, 2)]
    [InlineData(1, 2, 0)]
    [InlineData(2, 0, 1)]
    [InlineData(2, 1, 0)]
    public async Task SignedMultiRoleReceive_AllSixPermutationsDisambiguateOnlyAfterAuthentication(
        int ingressIndex, int coreIndex, int exitIndex)
    {
        var network = await Fixture.Create().VerifyDid2Async();
        var (path, request) = MultiRoleRequest(network, ingressIndex, coreIndex, exitIndex);
        var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(new ReceiveEntropyLedger()),
            new OnionKeyAgreementAuthority(new ReceiveVault()));
        using var built = await codec.BuildAsync(path, request, default);
        var store = new ReceiveReplayStore();
        using var ingress = Assert.IsType<OpenedOnionRelay>(await OpenSignedRelay(
            network, codec, store, built.Frame, ingressIndex, OnionReceivePosition.Ingress));
        using var core = Assert.IsType<OpenedOnionRelay>(await OpenSignedRelay(
            network, codec, store, ingress.InnerFrame, coreIndex, OnionReceivePosition.Core));
        var exitReceive = SignedReceive(network, core.InnerFrame, exitIndex, OnionReceivePosition.Exit);
        await using var exitLease = await new OnionReplayAuthority(store)
            .BeginOpenAsync(exitReceive, core.InnerFrame, default);
        using var exit = Assert.IsType<OpenedOnionExit>(
            await codec.OpenAsync(core.InnerFrame, exitReceive, exitLease, default));
        Assert.Equal(request.CanonicalBytes.ToArray(), exit.Request.CanonicalBytes.ToArray());
        Assert.Equal(3, store.CommitCount);
        Assert.Equal(5, store.DisposalCount);
        Assert.Equal(new[] { OnionReceivePosition.Core, OnionReceivePosition.Ingress,
            OnionReceivePosition.Ingress, OnionReceivePosition.Core, OnionReceivePosition.Exit },
            store.Positions);
        var failure = OnionTerminalPayloadVerifierV1.VerifyFailure(exit.Request, OnionFailureCode.Unavailable);
        var response = await codec.SealAsync(exit.ReplyContext, failure, default);
        var openedResponse = await codec.OpenResponseAsync(response, built.ReplyContext, default);
        Assert.Equal(OnionFailureCode.Unavailable, openedResponse.Result.FailureCode);
    }

    [Theory]
    [InlineData("authentication")]
    [InlineData("padding")]
    [InlineData("inner-key")]
    [InlineData("inner-network")]
    [InlineData("inner-version")]
    [InlineData("unknown-next")]
    public async Task SignedMultiRoleReceive_InvalidFrameNeverEmitsPositionRetry(string fault)
    {
        var network = await Fixture.Create().VerifyDid2Async();
        var (path, request) = MultiRoleRequest(network, 0, 1, 2);
        var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(new ReceiveEntropyLedger()),
            new OnionKeyAgreementAuthority(new ReceiveVault()));
        using var built = await codec.BuildAsync(path, request, default);
        var frame = MutateSignedRelay(network, built.Frame, fault);
        var wrongReceive = SignedReceive(network, frame, 0, OnionReceivePosition.Core);
        var store = new ReceiveReplayStore();
        await using var lease = await new OnionReplayAuthority(store).BeginOpenAsync(wrongReceive, frame, default);
        var error = await Assert.ThrowsAnyAsync<Exception>(async () =>
            await codec.OpenAsync(frame, wrongReceive, lease, default));
        Assert.False(error is OnionBoundaryException { Code: "receive-position-mismatch" });
        if (fault == "unknown-next")
            Assert.Equal("node-not-in-view", Assert.IsType<OnionBoundaryException>(error).Code);
        else
            Assert.Equal(fault switch
            {
                "authentication" => PrivacyRoutingProtocolError.AuthenticationFailed,
                "padding" => PrivacyRoutingProtocolError.InvalidPadding,
                "inner-version" => PrivacyRoutingProtocolError.UnsupportedVersion,
                _ => PrivacyRoutingProtocolError.InvalidKeyBinding
            }, Assert.IsType<PrivacyRoutingProtocolException>(
                Assert.IsType<OnionBoundaryException>(error).InnerException).Error);
        Assert.Equal(0, store.CommitCount);
        Assert.Equal(1, store.DisposalCount);
        Assert.Single(store.Positions);
    }

    [Fact]
    public async Task SignedMultiRoleReceive_DisallowedLocalRoleDoesNotAuthorizePositionRetry()
    {
        var fixture = Fixture.Create();
        var network = await fixture.VerifyDid2Async();
        var (path, request) = MultiRoleRequest(network, 0, 1, 2);
        var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(new ReceiveEntropyLedger()),
            new OnionKeyAgreementAuthority(new ReceiveVault()));
        using var built = await codec.BuildAsync(path, request, default);
        var removed = await fixture.WithNodeRole(0, 0x001e).VerifyDid2Async();
        var receive = SignedReceive(removed, built.Frame, 0, OnionReceivePosition.Core);
        var store = new ReceiveReplayStore();
        await using var lease = await new OnionReplayAuthority(store).BeginOpenAsync(receive, built.Frame, default);
        var error = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await codec.OpenAsync(built.Frame, receive, lease, default));
        Assert.Equal("path-role-invalid", error.Code);
        Assert.Equal(0, store.CommitCount);
    }

    [Fact]
    public async Task SignedMultiRoleReceive_FailedDisposalReplacesRetryError()
    {
        var network = await Fixture.Create().VerifyDid2Async();
        var (path, request) = MultiRoleRequest(network, 0, 1, 2);
        var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(new ReceiveEntropyLedger()),
            new OnionKeyAgreementAuthority(new ReceiveVault()));
        using var built = await codec.BuildAsync(path, request, default);
        var receive = SignedReceive(network, built.Frame, 0, OnionReceivePosition.Core);
        var store = new ReceiveReplayStore { FailDispose = true };
        await using var lease = await new OnionReplayAuthority(store).BeginOpenAsync(receive, built.Frame, default);
        await Assert.ThrowsAsync<IOException>(async () =>
            await codec.OpenAsync(built.Frame, receive, lease, default));
        Assert.Equal(0, store.CommitCount);
        Assert.Equal(1, store.DisposalCount);
    }

    [Fact]
    public async Task SignedMultiRoleReceive_VaultFailureNeverEmitsPositionRetry()
    {
        var network = await Fixture.Create().VerifyDid2Async();
        var (path, request) = MultiRoleRequest(network, 0, 1, 2);
        var entropy = new OnionEntropyAuthority(new ReceiveEntropyLedger());
        var builder = new PrivacyRoutingCodec(entropy, new OnionKeyAgreementAuthority(new ReceiveVault()));
        using var built = await builder.BuildAsync(path, request, default);
        var codec = new PrivacyRoutingCodec(entropy, new OnionKeyAgreementAuthority(new RejectingVault()));
        var receive = SignedReceive(network, built.Frame, 0, OnionReceivePosition.Core);
        var store = new ReceiveReplayStore();
        await using var lease = await new OnionReplayAuthority(store).BeginOpenAsync(receive, built.Frame, default);
        await Assert.ThrowsAsync<NotSupportedException>(async () =>
            await codec.OpenAsync(built.Frame, receive, lease, default));
        Assert.Equal(0, store.CommitCount);
        Assert.Single(store.Positions);
    }

    [Theory]
    [InlineData(OnionReplayCommitOutcome.Replayed, "replay-rejected")]
    [InlineData(OnionReplayCommitOutcome.Saturated, "replay-rejected")]
    [InlineData(OnionReplayCommitOutcome.Ambiguous, "replay-commit-ambiguous")]
    public async Task SignedMultiRoleReceive_CommitFailureNeverEmitsPositionRetry(
        OnionReplayCommitOutcome outcome, string code)
    {
        var network = await Fixture.Create().VerifyDid2Async();
        var (path, request) = MultiRoleRequest(network, 0, 1, 2);
        var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(new ReceiveEntropyLedger()),
            new OnionKeyAgreementAuthority(new ReceiveVault()));
        using var built = await codec.BuildAsync(path, request, default);
        var receive = SignedReceive(network, built.Frame, 0, OnionReceivePosition.Ingress);
        var store = new ReceiveReplayStore { Outcome = outcome };
        await using var lease = await new OnionReplayAuthority(store).BeginOpenAsync(receive, built.Frame, default);
        var error = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await codec.OpenAsync(built.Frame, receive, lease, default));
        Assert.Equal(code, error.Code);
        Assert.Equal(1, store.CommitCount);
        Assert.Single(store.Positions);
    }

    [Fact]
    public async Task SelectedEntryTransport_BindsBothExitPermutationsWithoutCallerOrigin()
    {
        var fixture = Fixture.Create();
        var network = await fixture.VerifyDid2Async();
        var placement = ContactServicePlacementFactory.Create(network,
            ContactServiceRequestKind.PublishPreKeyInventory, Bytes(32, 0x91));
        foreach (var exit in placement.RankedReplicaNodeIds)
        {
            var others = fixture.NodeIds.Where(id => !id.AsSpan().SequenceEqual(exit.Span)).ToArray();
            var path = OnionPathContextFactory.CreateContactResolver(network, placement,
                others[0], others[1], exit);
            var transport = OnionEntryTransportFactory.Create(path);
            transport.EnsureCurrent();
            Assert.Equal(path.EntryRouterId.ToArray(),
                network.ResolveNode(transport.Peer.NodeId.Span).RouterOwnerId);
            var expected = network.ResolveNode(others[0]);
            Assert.Equal(expected.OriginAddress, transport.Peer.Address.ToArray());
            Assert.Equal(expected.OriginSpki, transport.Peer.SpkiSha256.ToArray());
            Assert.Equal(expected.OriginPort, transport.Peer.Port);
            MemoryMarshal.AsMemory(transport.Peer.Address).Span.Fill(0);
            Assert.Equal(expected.OriginAddress, transport.Peer.Address.ToArray());
        }
        Assert.Throws<ArgumentNullException>(() => OnionEntryTransportFactory.Create(null!));
    }

    [Fact]
    public async Task SelectedEntryTransport_RejectsExpiredLeaseAndChangedTrafficKey()
    {
        var fixture = Fixture.Create();
        var network = await fixture.VerifyDid2Async();
        var placement = ContactServicePlacementFactory.Create(network,
            ContactServiceRequestKind.PublishPreKeyInventory, Bytes(32, 0x91));
        var exit = placement.RankedReplicaNodeIds[0];
        var others = fixture.NodeIds.Where(id => !id.AsSpan().SequenceEqual(exit.Span)).ToArray();
        var path = OnionPathContextFactory.CreateContactResolver(network, placement, others[0], others[1], exit);
        var clock = new AdvancingTimestampProvider();
        var lease = new OnionTrustedTimeLease(clock, TimeSpan.FromSeconds(1), Bytes(32, 0x92));
        var expiring = new VerifiedOnionPathContext(network, lease, OnionOperation.ContactResolve, path.Route);
        var transport = OnionEntryTransportFactory.Create(expiring);
        clock.Timestamp = 1;
        Assert.Equal("trusted-time-expired", Assert.Throws<OnionBoundaryException>(transport.EnsureCurrent).Code);
        Assert.Equal("trusted-time-expired",
            Assert.Throws<OnionBoundaryException>(() => OnionEntryTransportFactory.Create(expiring)).Code);
        var changed = path.Route.ToArray();
        var first = changed[0];
        changed[0] = new PrivacyRoutingHop(first.RouterOwnerId.Span, first.KeyId.Span, first.Epoch,
            first.Role, ScalarMult.Base(Bytes(32, 0x93)));
        var mismatched = new VerifiedOnionPathContext(network, path.TrustedTime,
            OnionOperation.ContactResolve, changed);
        Assert.Equal("entry-path-mismatch",
            Assert.Throws<OnionBoundaryException>(() => OnionEntryTransportFactory.Create(mismatched)).Code);
    }

    private sealed class AdvancingTimestampProvider : TimeProvider
    {
        internal long Timestamp { get; set; }
        public override long TimestampFrequency => 1;
        public override long GetTimestamp() => Timestamp;
    }

    [Fact]
    public async Task Did2Xpc1Claim_RequiresBothCurrentSelectedReplicaSignatures()
    {
        var context = await Fixture.Create(networkMarker: 0x01).VerifyAsync();
        var fixture = Deep.Protocol.Tests.ContactV2
            .DeepIdV2PreKeyClaimCommitmentTests.Build(Dpk2PrekeyKind.LastResort);
        var original = DeepIdV2PreKeyClaimRequestCodec.Decode(fixture.Request);
        var sourceOffering = DeepIdV2Dpk2Codec.Decode(fixture.Offering).Record;
        // This test owns selected-replica signatures, not DPK2 issuer authority.
        var scopedOffering = new Dpk2Record(context.NetworkId.Span,
            sourceOffering.ResponderAccountId.Span,
            sourceOffering.ResponderDeviceId.Span,
            sourceOffering.ResponderDeviceGeneration,
            sourceOffering.ResponderDpd1Ref.Span,
            sourceOffering.DeviceDirectoryGeneration,
            sourceOffering.DeviceDirectoryHeadHash.Span,
            sourceOffering.PrekeyServiceGeneration,
            sourceOffering.InventoryEpoch, sourceOffering.BundleId.Span,
            sourceOffering.PolicyGeneration, sourceOffering.NotBefore,
            sourceOffering.IssuedAt, sourceOffering.ExpiresAt,
            sourceOffering.DeviceAgreementPublicKey.Span,
            sourceOffering.SignedX25519PrekeyId.Span,
            sourceOffering.SignedX25519PrekeyPublic.Span,
            sourceOffering.SignedX25519PrekeySignature.Span,
            sourceOffering.OneTimeX25519PrekeyId.Span,
            sourceOffering.OneTimeX25519PrekeyPublic.Span,
            sourceOffering.MlKemPrekeyId.Span,
            sourceOffering.MlKem768EncapsulationKey.Span,
            sourceOffering.MlKemKind, sourceOffering.ReuseLimit,
            sourceOffering.MlKemPrekeySignature.Span,
            sourceOffering.BundleSignature.Span);
        var offeringBytes = DeepIdV2Dpk2Codec.Encode(scopedOffering);
        var sourceManifest = DeepIdV2PreKeyManifestCodec.Decode(fixture.Manifest);
        var manifestFields = Enumerable.Range(1, 15)
            .Select(sourceManifest.Field).ToArray();
        manifestFields[0] = context.NetworkId;
        manifestFields[10] = DeepIdV2Dpk2Codec.Decode(offeringBytes).ExactHash;
        var manifestBytes = DeepIdV2PreKeyManifestCodec.Encode(manifestFields,
            sourceManifest.Field(16).Span);
        var manifest = DeepIdV2PreKeyManifestCodec.Decode(manifestBytes);
        var placement = ContactServicePlacementFactory.Create(context,
            ContactServiceRequestKind.ClaimPreKey, manifest.Field(2));
        var requestBytes = DeepIdV2PreKeyClaimRequestCodec.Encode(
            context.NetworkId.Span, original.Field(2).Span,
            placement.ViewHash.Span, placement.PlacementHash.Span,
            BinaryPrimitives.ReadUInt64BigEndian(original.Field(5).Span),
            BinaryPrimitives.ReadUInt64BigEndian(original.Field(6).Span),
            original.Field(16).Span, original.Field(17).Span,
            original.Field(18).Span, original.Field(19).Span,
            original.Field(21).Span);
        var request = DeepIdV2PreKeyClaimRequestCodec.Decode(requestBytes);
        foreach (var tag in new[] { 2, 5, 6, 16, 17, 18, 19, 20, 21, 22 })
            Assert.Equal(original.Field(tag).ToArray(), request.Field(tag).ToArray());
        Assert.Equal(DeepIdV2PreKeyClaimCommitment.TupleLength,
            DeepIdV2PreKeyClaimCommitment.CreateTuple(requestBytes,
                offeringBytes, manifestBytes, 3, 1).Length);
        var payload = Deep.Protocol.Tests.ContactV2
            .DeepIdV2PreKeyClaimResultCodecTests.SuccessPayload(
                (requestBytes, offeringBytes, manifestBytes));
        var rows = new byte[193];
        rows[0] = 2;
        var input = DeepIdV2PreKeyClaimCommitment.CreateReplicaSignatureInput(
            requestBytes, offeringBytes, manifestBytes, 3, 1);
        try
        {
            var ordered = placement.RankedReplicaNodeIds
                .OrderBy(static id => Convert.ToHexString(id.Span))
                .ToArray();
            for (var index = 0; index < ordered.Length; index++)
            {
                var nodeId = ordered[index];
                var offset = 1 + index * 96;
                nodeId.Span.CopyTo(rows.AsSpan(offset, 32));
                var nodeIndex = nodeId.Span[0] - 0x10;
                var pair = PublicKeyAuth.GenerateKeyPair(Bytes(32,
                    checked((byte)(0x90 + nodeIndex * 8))));
                try
                {
                    PublicKeyAuth.SignDetached(input, pair.PrivateKey)
                        .CopyTo(rows, offset + 32);
                }
                finally { CryptographicOperations.ZeroMemory(pair.PrivateKey); }
            }
        }
        finally { CryptographicOperations.ZeroMemory(input); }
        payload[9] = rows;
        ParsedXpc1V2 Result() => DeepIdV2PreKeyClaimResultCodec.Decode(
            DeepIdV2PreKeyClaimResultCodec.Encode(requestBytes,
                Xpc1V2Status.Claimed,
                Xpc1V2MutationOutcome.DurablyCommitted,
                1_700_000_123, 0, payload),
            requestBytes);
        var result = Result();
        var verified = DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(
            request, result, placement);
        Assert.False(DeepIdV2PreKeyClaimReplicaSignatureVerifier.RuntimeActivation);
        Assert.Equal(requestBytes, verified.ExactRequest.ToArray());
        Assert.Equal(result.WireBytes.ToArray(), verified.ExactResult.ToArray());
        Assert.Empty(typeof(VerifiedXpc1V2ReplicaSignatures).GetConstructors());

        var oldDomainRows = rows.ToArray();
        var oldDomainInput = Deep.Protocol.ApplicationCore.ApplicationCoreFormat
            .SignatureInput("Deep/ContactResolver/V1/prekey-claim-commit",
                DeepIdV2PreKeyClaimCommitment.CreateTuple(requestBytes,
                    offeringBytes, manifestBytes, 3, 1), 0x0201);
        try
        {
            for (var index = 0; index < 2; index++)
            {
                var offset = 1 + index * 96;
                var nodeIndex = oldDomainRows[offset] - 0x10;
                var pair = PublicKeyAuth.GenerateKeyPair(Bytes(32,
                    checked((byte)(0x90 + nodeIndex * 8))));
                try
                {
                    PublicKeyAuth.SignDetached(oldDomainInput, pair.PrivateKey)
                        .CopyTo(oldDomainRows, offset + 32);
                }
                finally { CryptographicOperations.ZeroMemory(pair.PrivateKey); }
            }
        }
        finally { CryptographicOperations.ZeroMemory(oldDomainInput); }
        payload[9] = oldDomainRows;
        Assert.Throws<Deep.Protocol.ApplicationCore.ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(
                request, Result(), placement));

        var changed = rows.ToArray();
        changed[^1] ^= 1;
        payload[9] = changed;
        Assert.Throws<Deep.Protocol.ApplicationCore.ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(
                request, Result(), placement));
        var failure = DeepIdV2PreKeyClaimResultCodec.Decode(
            DeepIdV2PreKeyClaimResultCodec.Encode(requestBytes,
                Xpc1V2Status.PreKeysUnavailable,
                Xpc1V2MutationOutcome.None, 123, 0, []), requestBytes);
        Assert.Throws<Deep.Protocol.ApplicationCore.ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(
                request, failure, placement));
        Assert.Throws<Deep.Protocol.ApplicationCore.ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(
                request, result, new VerifiedContactServicePlacement(context,
                    placement.RequestKind, placement.ServiceClass,
                    placement.ViewHash.Span, Bytes(32, 0xe1),
                    manifest.Field(2).Span, placement.SelectionEpoch,
                    placement.ValidUntilUnixSeconds,
                    placement.RankedReplicaNodeIds.Select(static id =>
                        id.ToArray()), placement.PolicyGeneration)));
    }

    [Fact]
    public async Task Did2Xic1Pair_RequiresBothCurrentSelectedReplicaSignatures()
    {
        var fixture = Fixture.Create(networkMarker: 0x01);
        var context = await fixture.VerifyAsync();
        var oneTime = Deep.Protocol.Tests.ContactV2
            .DeepIdV2PreKeyClaimCommitmentTests.Build(Dpk2PrekeyKind.OneTime);
        var lastResort = Deep.Protocol.Tests.ContactV2
            .DeepIdV2PreKeyClaimCommitmentTests.Build(Dpk2PrekeyKind.LastResort);
        ParsedDpk2V2 OnNetwork(byte[] exact)
        {
            var record = DeepIdV2Dpk2Codec.Decode(exact).Record;
            var scoped = new Dpk2Record(context.NetworkId.Span,
                record.ResponderAccountId.Span, record.ResponderDeviceId.Span,
                record.ResponderDeviceGeneration, record.ResponderDpd1Ref.Span,
                record.DeviceDirectoryGeneration,
                record.DeviceDirectoryHeadHash.Span,
                record.PrekeyServiceGeneration, record.InventoryEpoch,
                record.BundleId.Span, record.PolicyGeneration, record.NotBefore,
                record.IssuedAt, record.ExpiresAt,
                record.DeviceAgreementPublicKey.Span,
                record.SignedX25519PrekeyId.Span,
                record.SignedX25519PrekeyPublic.Span,
                record.SignedX25519PrekeySignature.Span,
                record.OneTimeX25519PrekeyId.Span,
                record.OneTimeX25519PrekeyPublic.Span,
                record.MlKemPrekeyId.Span,
                record.MlKem768EncapsulationKey.Span,
                record.MlKemKind, record.ReuseLimit,
                record.MlKemPrekeySignature.Span,
                record.BundleSignature.Span);
            return DeepIdV2Dpk2Codec.Decode(DeepIdV2Dpk2Codec.Encode(scoped));
        }
        var member = OnNetwork(oneTime.Offering);
        var last = OnNetwork(lastResort.Offering);
        var sourceManifest = DeepIdV2PreKeyManifestCodec.Decode(oneTime.Manifest);
        var manifestFields = Enumerable.Range(1, 15)
            .Select(sourceManifest.Field).ToArray();
        manifestFields[0] = context.NetworkId;
        manifestFields[10] = last.ExactHash;
        // This structural inventory fixture is intentionally not an authorized
        // inventory; this test owns only the signed two-replica receipt gate.
        manifestFields[13] = U64(100);
        manifestFields[14] = U64(300);
        var manifest = DeepIdV2PreKeyManifestCodec.Decode(
            DeepIdV2PreKeyManifestCodec.Encode(manifestFields,
                sourceManifest.Field(16).Span));
        var placement = ContactServicePlacementFactory.Create(context,
            ContactServiceRequestKind.PublishPreKeyInventory, manifest.Field(2));
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(
            DeepIdV2PreKeyPublicationCodec.Encode(context.NetworkId.Span,
                Bytes(32, 0xd1), placement.PlacementHash.Span, manifest,
                Enumerable.Repeat(member, 32).ToArray(), last));

        ParsedXic1V2 Receipt(ReadOnlyMemory<byte> nodeId, ulong time)
        {
            ReadOnlyMemory<byte>[] fields =
            [
                publication.NetworkId, publication.PublicationOperationId,
                publication.Manifest.ExactHash, publication.PlacementHash,
                nodeId, U64(time)
            ];
            var index = nodeId.Span[0] - 0x10;
            var pair = PublicKeyAuth.GenerateKeyPair(Bytes(32,
                checked((byte)(0x90 + index * 8))));
            try
            {
                var signature = PublicKeyAuth.SignDetached(
                    DeepIdV2PreKeyCommitReceiptCodec.CreateSignatureInput(fields),
                    pair.PrivateKey);
                return DeepIdV2PreKeyCommitReceiptCodec.Decode(
                    DeepIdV2PreKeyCommitReceiptCodec.Encode(fields, signature));
            }
            finally { CryptographicOperations.ZeroMemory(pair.PrivateKey); }
        }

        var replicas = placement.RankedReplicaNodeIds;
        var first = Receipt(replicas[0], 200);
        var second = Receipt(replicas[1], 201);
        Assert.False(DeepIdV2PreKeyCommitReceiptVerifier.RuntimeActivation);
        DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(
            publication, placement, first, second);
        DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(
            publication, placement, second, first);
        Assert.Throws<Deep.Protocol.ApplicationCore.ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(
                publication, placement, first, first));
        Assert.Throws<Deep.Protocol.ApplicationCore.ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(
                publication, placement, first,
                Receipt(replicas[1], 99)));
        var substituted = second.CanonicalBytes.ToArray();
        substituted[^1] ^= 1;
        Assert.Throws<Deep.Protocol.ApplicationCore.ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(
                publication, placement, first,
                DeepIdV2PreKeyCommitReceiptCodec.Decode(substituted)));
        var wrongPlacement = new VerifiedContactServicePlacement(context,
            placement.RequestKind, placement.ServiceClass, placement.ViewHash.Span,
            Bytes(32, 0xe1), manifest.Field(2).Span,
            placement.SelectionEpoch, placement.ValidUntilUnixSeconds,
            replicas.Select(static id => id.ToArray()), placement.PolicyGeneration);
        Assert.Throws<Deep.Protocol.ApplicationCore.ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(
                publication, wrongPlacement, first, second));
    }

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
        var grant = ContactServicePlacementFactory.Create(
            context, ContactServiceRequestKind.AcquireMailboxGrant, shard);

        Assert.Equal(fixture.ViewCoreHash, resolve.ViewHash.ToArray());
        Assert.Equal(publish.PlacementHash.ToArray(), resolve.PlacementHash.ToArray());
        Assert.Equal(resolve.PlacementHash.ToArray(), grant.PlacementHash.ToArray());
        Assert.Equal(
            publish.RankedReplicaNodeIds.Select(static value => value.ToArray()),
            resolve.RankedReplicaNodeIds.Select(static value => value.ToArray()));
        Assert.Equal(ContactServiceClass.InviteResolver, resolve.ServiceClass);
        Assert.Equal(ContactServiceClass.InviteResolver, grant.ServiceClass);
        Assert.True(grant.Binds(ContactServiceRequestKind.AcquireMailboxGrant, shard));
        var pmt = ContactCodec.Decode("PMT2", fixture.Pmt);
        Assert.True(context.BindsProjection(
            ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes));
        Assert.False(context.BindsProjection(Bytes(38, 0xa3)));
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
        var local = OnionLocalNodeKeyFactory.Bind(
            context, OnionReceivePosition.Ingress, others[0], handle);
        Assert.Equal(OnionReceivePosition.Ingress, local.Position);
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
    public async Task Did2DirectoryTime_VerifiesAndRehydratesNetworkWithoutV1AccountProof()
    {
        var fixture = Fixture.Create();
        var context = await fixture.VerifyDid2Async();
        context.EnsureCurrent();
        Assert.NotNull(context.ProtectedLkg);

        var rehydrated = await fixture.RehydrateDid2Async(context.ProtectedLkg!);
        Assert.Equal(context.ProtectedLkg!.HeadCoreReference.ToArray(),
            rehydrated.ProtectedLkg!.HeadCoreReference.ToArray());

        var foreign = Fixture.Create(networkMarker: 0x21).Did2TimeEvidence();
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fixture.VerifyDid2Async(foreign));

        var stale = fixture.WithClockSample(fixture.FreshnessDeadline);
        var staleError = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await stale.VerifyDid2Async());
        Assert.Equal("trusted-time-invalid", staleError.Code);
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
        Assert.Null(typeof(PrivacyRoutingCodec).Assembly.GetType(
            "Deep.Protocol.DeepExtension.PrivacyRouting.VerifiedGroupControlPlacement"));

        var historyMethods = typeof(OnionNetworkProtectedHistoryCodec).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly);
        Assert.Equal(["BindsPredecessor", "Encode"], historyMethods.Select(method => method.Name).Order().ToArray());
        var historyBinding = Assert.Single(historyMethods, method => method.Name == "BindsPredecessor");
        Assert.Equal(typeof(bool), historyBinding.ReturnType);
        Assert.Equal([typeof(VerifiedOnionNetworkContext), typeof(ReadOnlyMemory<byte>)],
            historyBinding.GetParameters().Select(parameter => parameter.ParameterType).ToArray());

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
        Assert.Equal(["VerifyAsync", "VerifyFromForwardCheckpointAsync",
                "VerifyFromProtectedHistoryAsync",
                "VerifyRehydratedCurrentAsync"],
            verifyMethods.Select(static method => method.Name).Order(StringComparer.Ordinal).ToArray());
        Assert.All(verifyMethods, verify => Assert.DoesNotContain(verify.GetParameters(), parameter =>
            typeof(Delegate).IsAssignableFrom(parameter.ParameterType) ||
            parameter.ParameterType == typeof(bool) ||
            parameter.Name?.Contains("hash", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("xir", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("pms", StringComparison.OrdinalIgnoreCase) == true));

        var creates = typeof(OnionPathContextFactory).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly);
        Assert.Equal(["CreateContactResolver", "CreateMailbox"],
            creates.Select(static method => method.Name).Order(StringComparer.Ordinal).ToArray());
        Assert.All(creates, create => Assert.DoesNotContain(create.GetParameters(), parameter =>
            parameter.Name?.Contains("hop", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("key", StringComparison.OrdinalIgnoreCase) == true));
        Assert.Empty(typeof(GroupControlPlacementVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
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

    private static (VerifiedOnionPathContext Path, VerifiedCanonicalOnionRequest Request) MultiRoleRequest(
        VerifiedOnionNetworkContext network, int ingress, int core, int exit)
    {
        var nodes = OnionPathCandidateSnapshotFactory.Create(network).Candidates;
        for (byte marker = 1; marker < 65; marker++)
        {
            var capability = Bytes(32, marker);
            var placement = ContactServicePlacementFactory.Create(network,
                ContactServiceRequestKind.PublishPreKeyInventory, capability);
            if (!placement.RankedReplicaNodeIds.Any(id => id.Span.SequenceEqual(nodes[exit].NodeId.Span))) continue;
            var path = OnionPathContextFactory.CreateContactResolver(network, placement,
                nodes[ingress].NodeId, nodes[core].NodeId, nodes[exit].NodeId);
            // Canonical V2 commit carriage only: this does not claim the staged
            // aggregate, publisher proof or final XIC1 publication exists.
            var exact = new byte[325];
            var writer = new ApplicationRecordWriter(exact, "XPP1"u8, 12, 2, DeepIdV2Codec.Suite);
            writer.Write(1, [(byte)Xpp1V2FragmentPhase.Commit]);
            writer.Write(2, network.NetworkId.Span);
            writer.Write(3, Bytes(32, 0x11));
            writer.Write(4, placement.ViewHash.Span);
            writer.Write(5, placement.PlacementHash.Span);
            writer.Write(6, Bytes(32, 0x12));
            writer.Write(7, U32(DeepIdV2PreKeyPublicationCodec.MinimumTotalBytes));
            writer.Write(8, U16(2));
            writer.Write(9, U16(DeepIdV2BoundedPreKeyPublicationCodec.NonChunkIndex));
            writer.Write(10, new byte[32]);
            writer.Write(11, Bytes(32, 0x13));
            writer.Write(12, []);
            writer.Complete();
            _ = DeepIdV2BoundedPreKeyPublicationCodec.Decode(exact);
            return (path, OnionTerminalPayloadVerifierV1.VerifyRequest(network, OnionOperation.ContactResolve, exact));
        }
        throw new InvalidOperationException("The bounded test capability search found no selected exit.");
    }

    private static VerifiedOnionReceiveContext SignedReceive(VerifiedOnionNetworkContext network,
        ReadOnlyMemory<byte> frame, int index, OnionReceivePosition position) =>
        OnionReceiveContextSelector.Select(frame, OnionLocalNodeKeyFactory.Bind(network, position,
            OnionPathCandidateSnapshotFactory.Create(network).Candidates[index].NodeId,
            new OnionKeyHandle(Bytes(32, checked((byte)(0xd0 + index))))));

    private static async ValueTask<OpenedOnionLayer> OpenSignedRelay(VerifiedOnionNetworkContext network,
        PrivacyRoutingCodec codec, ReceiveReplayStore store, ReadOnlyMemory<byte> frame,
        int index, OnionReceivePosition position)
    {
        var opposite = position == OnionReceivePosition.Ingress ? OnionReceivePosition.Core : OnionReceivePosition.Ingress;
        var wrong = SignedReceive(network, frame, index, opposite);
        var previousCommits = store.CommitCount;
        await using var wrongLease = await new OnionReplayAuthority(store).BeginOpenAsync(wrong, frame, default);
        var mismatch = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await codec.OpenAsync(frame, wrong, wrongLease, default));
        Assert.Equal("receive-position-mismatch", mismatch.Code);
        Assert.Equal(previousCommits, store.CommitCount);
        var right = SignedReceive(network, frame, index, position);
        await using var rightLease = await new OnionReplayAuthority(store).BeginOpenAsync(right, frame, default);
        return await codec.OpenAsync(frame, right, rightLease, default);
    }

    private static byte[] MutateSignedRelay(VerifiedOnionNetworkContext network,
        ReadOnlyMemory<byte> original, string fault)
    {
        if (fault == "authentication")
        {
            var corrupt = original.ToArray(); corrupt[^1] ^= 1; return corrupt;
        }
        var receive = SignedReceive(network, original, 0, OnionReceivePosition.Ingress);
        var scalar = Bytes(32, 0xa0);
        var shared = ScalarMult.Mult(scalar, original.Span.Slice(100, 32).ToArray());
        var plain = PrivacyRoutingWire.OpenRequestEnvelopeWithSharedSecret(original.Span, receive, shared);
        try
        {
            switch (fault)
            {
                case "padding": plain[^1] = 1; break;
                case "inner-key": plain[80 + 68] ^= 1; break;
                case "inner-network": plain[80 + 12] ^= 1; break;
                case "inner-version": plain[80 + 4] = 2; break;
                case "unknown-next": plain.AsSpan(40, 32).Fill(0xf8); break;
                default: throw new ArgumentOutOfRangeException(nameof(fault));
            }
            var local = receive.LocalHop;
            return PrivacyRoutingWire.SealEnvelope(plain, network.NetworkId.Span,
                local.RouterOwnerId.Span, local.Epoch, local.KeyId.Span, 1, 1,
                local.X25519PublicKey.Span, Bytes(32, 0xe5), Bytes(24, 0xe6));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scalar);
            CryptographicOperations.ZeroMemory(shared);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    private sealed class ReceiveVault : IOnionKeyAgreementVault
    {
        public ValueTask<byte[]> DeriveX25519SharedSecretAsync(OnionKeyHandle handle,
            ReadOnlyMemory<byte> peer, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var index = handle.Id.Span[0] - 0xd0;
            Assert.InRange(index, 0, 2);
            var scalar = Bytes(32, checked((byte)(0xa0 + index)));
            try { return ValueTask.FromResult(ScalarMult.Mult(scalar, peer.ToArray())); }
            finally { CryptographicOperations.ZeroMemory(scalar); }
        }
    }

    private sealed class ReceiveEntropyLedger : IOnionEntropyUniquenessLedger
    {
        public ValueTask<OnionEntropyCommitOutcome> CommitAsync(OnionEntropyCommitmentBatch batch,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(OnionEntropyCommitOutcome.Committed);
        }
    }

    private sealed class ReceiveReplayStore : IOnionDurableReplayStore
    {
        internal List<OnionReceivePosition> Positions { get; } = [];
        internal int CommitCount { get; private set; }
        internal int DisposalCount { get; private set; }
        internal bool FailDispose { get; init; }
        internal OnionReplayCommitOutcome Outcome { get; init; } = OnionReplayCommitOutcome.Committed;
        public ValueTask<IOnionDurableReplayTransaction> BeginAsync(OnionReplayScope scope,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Positions.Add(scope.Position);
            return ValueTask.FromResult<IOnionDurableReplayTransaction>(new Transaction(this));
        }
        private sealed class Transaction(ReceiveReplayStore store) : IOnionDurableReplayTransaction
        {
            public ValueTask<OnionReplayCommitOutcome> CommitAsync(ReadOnlyMemory<byte> replayId,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                store.CommitCount++;
                return ValueTask.FromResult(store.Outcome);
            }
            public ValueTask DisposeAsync()
            {
                store.DisposalCount++;
                if (store.FailDispose) throw new IOException("Injected replay disposal failure.");
                return ValueTask.CompletedTask;
            }
        }
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

    internal sealed class Fixture
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

        internal byte[] Pmt => _pmt.ToArray();
        private readonly VerifiedXPointNetworkAuthority _authority;
        private readonly VerifiedDeepIdV2DirectoryFreshness _freshness;

        internal VerifiedXPointNetworkAuthority Authority => _authority;

        internal async ValueTask<(VerifiedOnionNetworkContext Network, byte[] Pma)> VerifyMailboxAsync()
        {
            ReadOnlyMemory<byte>[] fields =
            [
                _authority.NetworkId, U64(0), new byte[32], Bytes(32, 0xe0),
                PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xe1)).PublicKey,
                PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xe2)).PublicKey,
                U64(5), U32(60), U16(2), U64(100), U64(100), U64(300),
                _authority.AuthorityCoreReference, _authority.DirectoryWitnessPolicyHash,
                new byte[] { 1 }, SignatureRows([(_root.Id, Bytes(64, 0xe3))]),
            ];
            var unsigned = ContactCodec.AuthorForOperationalAuthority("PMA2", fields);
            fields[15] = SignatureRows([(_root.Id,
                PublicKeyAuth.SignDetached(unsigned.SignatureInput.ToArray(), _root.Pair.PrivateKey))]);
            var pma = ContactCodec.AuthorForOperationalAuthority("PMA2", fields);
            var pmt = ContactCodec.Decode("PMT2", _pmt);
            var projection = Enumerable.Range(1, 16)
                .Select(tag => pmt.Field(tag)).ToArray();
            projection[3] = XPointNetworkCodec.EncodeCoreReference("PMA2", pma.CoreHash.Span);
            var candidate = ContactCodec.AuthorForOperationalAuthority("PMT2", projection);
            projection[15] = SignatureRows(_witnesses.Take(2).Select(key =>
                (key.Id, PublicKeyAuth.SignDetached(candidate.SignatureInput.ToArray(), key.Pair.PrivateKey))).ToArray());
            var exactPmt = ContactCodec.AuthorForOperationalAuthority("PMT2", projection).CanonicalBytes;
            var network = await OnionNetworkContextVerifier.VerifyAsync(_authority, _freshness,
                new ReadOnlyMemory<byte>[] { _xvp }, new ReadOnlyMemory<byte>[] { _xnv },
                new ReadOnlyMemory<byte>[] { _xnh },
                _nodes.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
                new ReadOnlyMemory<byte>[] { exactPmt }, null,
                new OnionTrustedTimeAuthority(new FixedClock(Bytes(16, 0xc1), _clockSample)), default);
            return (network, pma.CanonicalBytes.ToArray());
        }

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

        internal VerifiedDeepIdV2DirectoryFreshness Did2TimeEvidence() =>
            new(_freshness.ExactAdh1.Span, _freshness.ExactDtt1.Span, [],
                _authority.NetworkId.Span, Bytes(32, 0x75),
                new AccountDirectoryMonotonicRequestWindow(Bytes(16, 0xc1), 990, 995, 1_000),
                _freshness.FreshnessDeadlineMonotonicSeconds,
                _freshness.TrustedLowerUnixSeconds, _freshness.TrustedUpperUnixSeconds,
                AccountDirectoryAdp1ResultKind.NonMembership, null, false, null);

        internal ValueTask<VerifiedOnionNetworkContext> VerifyDid2Async(
            VerifiedDeepIdV2DirectoryFreshness? evidence = null) =>
            OnionNetworkContextVerifier.VerifyAsync(
                _authority, evidence ?? Did2TimeEvidence(), new ReadOnlyMemory<byte>[] { _xvp },
                new ReadOnlyMemory<byte>[] { _xnv }, new ReadOnlyMemory<byte>[] { _xnh },
                _nodes.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
                new ReadOnlyMemory<byte>[] { _pmt }, null,
                new OnionTrustedTimeAuthority(new FixedClock(Bytes(16, 0xc1), _clockSample)), default);

        internal ValueTask<VerifiedOnionNetworkContext> VerifyHistoryAsync(byte[] history, SuccessorFixture? successors = null)
        {
            var freshness = successors?.Freshness ?? _freshness;
            var evidence = new VerifiedDeepIdV2DirectoryFreshness(freshness.ExactAdh1.Span, freshness.ExactDtt1.Span, [],
                _authority.NetworkId.Span, Bytes(32, 0x75),
                new AccountDirectoryMonotonicRequestWindow(Bytes(16, 0xc1), 990, 995, 1_000),
                freshness.FreshnessDeadlineMonotonicSeconds, freshness.TrustedLowerUnixSeconds, freshness.TrustedUpperUnixSeconds,
                AccountDirectoryAdp1ResultKind.NonMembership, null, false, null);
            return OnionNetworkContextVerifier.VerifyFromProtectedHistoryAsync(_authority, evidence,
                new ReadOnlyMemory<byte>[] { _xvp }.Concat((successors?.Policies ?? []).Select(bytes => (ReadOnlyMemory<byte>)bytes)).ToArray(),
                new ReadOnlyMemory<byte>[] { _xnv }.Concat((successors?.Views ?? []).Select(bytes => (ReadOnlyMemory<byte>)bytes)).ToArray(),
                new ReadOnlyMemory<byte>[] { _xnh }.Concat((successors?.Heads ?? []).Select(bytes => (ReadOnlyMemory<byte>)bytes)).ToArray(),
                (successors?.Nodes ?? _nodes).Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray(),
                new ReadOnlyMemory<byte>[] { _pmt }.Concat((successors?.Pmts ?? []).Select(bytes => (ReadOnlyMemory<byte>)bytes)).ToArray(),
                history, new(new FixedClock(Bytes(16, 0xc1), _clockSample)), default);
        }

        internal ValueTask<VerifiedOnionNetworkContext> RehydrateDid2Async(
            XPointNetworkProtectedLkg protectedCurrent) =>
            OnionNetworkContextVerifier.VerifyRehydratedCurrentAsync(
                _authority, Did2TimeEvidence(), new ReadOnlyMemory<byte>[] { _xvp },
                new ReadOnlyMemory<byte>[] { _xnv }, new ReadOnlyMemory<byte>[] { _xnh },
                _nodes.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
                new ReadOnlyMemory<byte>[] { _pmt }, protectedCurrent,
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
                XPointNetworkCodec.EncodeCoreReference("DTT1", ((IVerifiedDirectoryNetworkTime)successors.Freshness).ExactDtt1CoreHash.Span), U16(1),
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

        private static VerifiedDeepIdV2DirectoryFreshness BuildFreshness(
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
            var monotonic = new AccountDirectoryMonotonicRequestWindow(Bytes(16, 0xc1), 990, 995, 1_000);
            return new VerifiedDeepIdV2DirectoryFreshness(
                exactAdh, exactDtt, [], network, query, monotonic, 1_050,
                195, 205, AccountDirectoryAdp1ResultKind.NonMembership, null, false, null);
        }

        private static byte[] BuildPmt(
            byte[] network,
            Xnv1Record view,
            VerifiedDeepIdV2DirectoryFreshness freshness,
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
                ((IVerifiedDirectoryNetworkTime)freshness).ExactAdh1CoreReference, new byte[] { 2 },
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

    internal sealed class SuccessorFixture(
        VerifiedXPointNetworkAuthority authority,
        VerifiedDeepIdV2DirectoryFreshness freshness,
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
        internal VerifiedDeepIdV2DirectoryFreshness Freshness => freshness;

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

    internal sealed record ForwardPackage(
        VerifiedXPointNetworkAuthority Authority,
        VerifiedDeepIdV2DirectoryFreshness Freshness,
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
