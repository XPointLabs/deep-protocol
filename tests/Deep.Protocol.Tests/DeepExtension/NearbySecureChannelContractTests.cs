using System.Buffers;
using System.Reflection;
using System.Runtime.InteropServices;
using Deep.Protocol.DeepExtension.NearbyHandshakes;
using Deep.Protocol.DeepExtension.NearbySecureChannels;
using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class NearbySecureChannelContractTests
{
    private static readonly DateTimeOffset ValidFrom = DateTimeOffset.UnixEpoch;
    private static readonly DateTimeOffset ValidUntil = DateTimeOffset.UnixEpoch.AddDays(2);
    private static readonly DateTimeOffset ValidationTime = DateTimeOffset.UnixEpoch.AddDays(1);

    [Fact]
    public void Topology_HasOwnedReplayCommitWithoutReusableAcceptance()
    {
        var assembly = typeof(NearbyAkeContext).Assembly;
        Assert.Null(assembly.GetType(
            "Deep.Protocol.DeepExtension.NearbySecureChannels.NearbyReplayAcceptance"));
        Assert.Null(assembly.GetType(
            "Deep.Protocol.DeepExtension.NearbySecureChannels.NearbyReplayCommitterBase"));

        var activation = typeof(INearbyPendingSession).GetMethod("ActivateAsync");
        Assert.NotNull(activation);
        Assert.Equal(typeof(ValueTask<INearbySecureSession>), activation.ReturnType);
        Assert.Equal(
            [typeof(INearbyReplayCommitter), typeof(CancellationToken)],
            activation.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.DoesNotContain(
            activation.GetParameters(),
            parameter => parameter.ParameterType.Name.Contains(
                "Acceptance",
                StringComparison.OrdinalIgnoreCase));

        Assert.Equal(
            typeof(NearbyFreshReplayClaim),
            typeof(INearbyPendingSession).GetProperty("ReplayClaim")!.PropertyType);

        var outcomeProperties = typeof(NearbyReplayCommitOutcome).GetProperties();
        Assert.Single(outcomeProperties);
        Assert.Equal("Classification", outcomeProperties[0].Name);
    }

    [Fact]
    public void OpaqueValues_HaveValueEqualityStableHashesCopyingAndRedaction()
    {
        AssertOpaqueValueEquality(
            bytes => new NearbyAccountIdentity(bytes),
            minimumLength: 1,
            maximumLength: 512);
        AssertOpaqueValueEquality(
            bytes => new NearbyDeviceKeyId(bytes),
            minimumLength: 16,
            maximumLength: 64);
        AssertOpaqueValueEquality(
            bytes => new NearbyTranscriptDigest(bytes),
            minimumLength: 32,
            maximumLength: 64);
        AssertOpaqueValueEquality(
            bytes => new NearbyLocalKeyReference(bytes),
            minimumLength: 16,
            maximumLength: 64);
    }

    [Fact]
    public async Task VerifiedCredential_IsOpaqueVerifierIssuedAndReadOnly()
    {
        Assert.Empty(typeof(NearbyVerifiedDeviceCredential).GetConstructors());
        Assert.Empty(typeof(NearbyAuthenticatedPeer).GetConstructors());

        var descriptor = Descriptor(
            Account(0x10),
            Device(0x20),
            epoch: 7,
            NearbyDeviceCredentialStatus.Active,
            ValidFrom,
            ValidUntil);
        var expectation = Expectation(
            Account(0x10),
            Device(0x20),
            epoch: 7,
            ValidationTime);

        var verified = await new TestCredentialVerifier()
            .VerifyAsync(descriptor, expectation);

        Assert.Equal(descriptor.AccountIdentity, verified.AccountIdentity);
        Assert.Equal(descriptor.DeviceKeyId, verified.DeviceKeyId);
        Assert.Equal(7UL, verified.RosterEpoch);
        Assert.Equal(ValidFrom, verified.ValidFrom);
        Assert.Equal(ValidUntil, verified.ValidUntil);
        Assert.Equal(NearbyDeviceCredentialStatus.Active, verified.Status);
        Assert.Contains("redacted", verified.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("wrong-account", NearbySecureChannelError.InvalidCredential)]
    [InlineData("same-account-wrong-device", NearbySecureChannelError.InvalidCredential)]
    [InlineData("revoked", NearbySecureChannelError.CredentialRevoked)]
    [InlineData("not-yet-valid", NearbySecureChannelError.CredentialNotYetValid)]
    [InlineData("expired", NearbySecureChannelError.CredentialExpired)]
    [InlineData("roster-rollback", NearbySecureChannelError.RosterRollback)]
    public async Task CredentialVerification_FailsClosed(
        string scenario,
        NearbySecureChannelError expectedError)
    {
        var account = Account(0x10);
        var device = Device(0x20);
        var descriptor = Descriptor(
            account,
            device,
            epoch: scenario == "roster-rollback" ? 6UL : 7UL,
            scenario == "revoked"
                ? NearbyDeviceCredentialStatus.Revoked
                : NearbyDeviceCredentialStatus.Active,
            scenario == "not-yet-valid" ? ValidationTime.AddMinutes(1) : ValidFrom,
            scenario == "expired" ? ValidationTime : ValidUntil);
        var expectedAccount = scenario == "wrong-account" ? Account(0x30) : account;
        var expectedDevice = scenario == "same-account-wrong-device" ? Device(0x40) : device;
        var expectation = Expectation(expectedAccount, expectedDevice, 7, ValidationTime);

        var exception = await Assert.ThrowsAsync<NearbySecureChannelException>(
            async () => await new TestCredentialVerifier()
                .VerifyAsync(descriptor, expectation));
        Assert.Equal(expectedError, exception.Error);
    }

    [Fact]
    public async Task Context_BindsProviderIssuedLocalKeyAndVerifiedCredentials()
    {
        var verifier = new TestCredentialVerifier();
        var localDescriptor = Descriptor(
            Account(0x10),
            Device(0x20),
            7,
            NearbyDeviceCredentialStatus.Active,
            ValidFrom,
            ValidUntil);
        var peerDescriptor = Descriptor(
            Account(0x30),
            Device(0x40),
            7,
            NearbyDeviceCredentialStatus.Active,
            ValidFrom,
            ValidUntil);
        var local = await verifier.VerifyAsync(
            localDescriptor,
            Expectation(localDescriptor.AccountIdentity, localDescriptor.DeviceKeyId, 7, ValidationTime));
        var peer = await verifier.VerifyAsync(
            peerDescriptor,
            Expectation(peerDescriptor.AccountIdentity, peerDescriptor.DeviceKeyId, 7, ValidationTime));
        var keyReference = new NearbyLocalKeyReference(Range(0x70, 16));
        var handle = await new TestLocalKeyProvider(keyReference)
            .GetLocalKeyAsync(local);
        var binding = Binding();

        var context = new NearbyAkeContext(
            NearbySecureChannelProfileId.UnassignedPendingExternalCryptoReview,
            binding,
            NearbySessionRole.Initiator,
            local,
            handle,
            peer,
            rosterEpoch: 7,
            ValidationTime);

        Assert.Same(handle, context.LocalKeyHandle);
        Assert.Same(local, context.LocalCredential);
        Assert.Equal(local.AccountIdentity, context.LocalCredential.AccountIdentity);
        Assert.Equal(local.DeviceKeyId, context.LocalCredential.DeviceKeyId);
        Assert.Equal(keyReference, context.LocalKeyHandle.KeyReference);
        Assert.Same(peer, context.ExpectedPeerCredential);
        Assert.Equal(NearbySessionRole.Initiator, context.LocalRole);

        var token = binding.SimultaneousOpenToken.ToArray();
        Assert.True(MemoryMarshal.TryGetArray(binding.SimultaneousOpenToken, out var segment));
        segment.Array![segment.Offset] ^= 0xff;
        Assert.Equal(token, context.Binding.SimultaneousOpenToken.ToArray());

        Assert.Empty(typeof(NearbyLocalDeviceKeyHandle).GetConstructors());
    }

    [Fact]
    public async Task Context_RejectsResumptionEvenWithVerifiedCapabilities()
    {
        var (local, peer, handle) = await Capabilities();
        var exception = Assert.Throws<NearbySecureChannelException>(() =>
            new NearbyAkeContext(
                NearbySecureChannelProfileId.UnassignedPendingExternalCryptoReview,
                Binding(NearbyHandshakeMode.Resumption, 1),
                NearbySessionRole.Initiator,
                local,
                handle,
                peer,
                rosterEpoch: 7,
                ValidationTime));

        Assert.Equal(NearbySecureChannelError.ResumptionNotSupported, exception.Error);
        Assert.Same(local, handle.Credential);
    }

    [Fact]
    public void ReplayClaim_HasExactValueEqualityAndHashing()
    {
        var left = Claim();
        var same = Claim();
        Assert.Equal(left, same);
        Assert.Equal(left.GetHashCode(), same.GetHashCode());

        Assert.NotEqual(left, Claim(local: Device(0x21)));
        Assert.NotEqual(left, Claim(peer: Device(0x41)));
        Assert.NotEqual(left, Claim(attemptStart: 0x91));
        Assert.NotEqual(left, Claim(digest: new NearbyTranscriptDigest(Range(0xb1, 32))));
        Assert.NotEqual(left, Claim(rosterEpoch: 8));
        Assert.Contains("redacted", left.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PendingSession_RejectsHandshakeHashDifferentFromReplayTranscript()
    {
        var (_, peer, handle) = await Capabilities();
        var exception = Assert.Throws<NearbySecureChannelException>(() =>
            new TestPendingSession(
                Context(NearbySessionRole.Initiator, handle, peer),
                ValidationTime,
                Claim(peer: peer.DeviceKeyId),
                new TestSecureSession(NearbySessionRole.Initiator, peer, ValidationTime),
                new NearbyTranscriptDigest(Range(0xd0, 32))));

        Assert.Equal(NearbySecureChannelError.InvalidCredential, exception.Error);
    }

    [Fact]
    public async Task PendingSession_CommitsItsOwnedClaimAndActivatesOnlyOnce()
    {
        var (_, peer, handle) = await Capabilities();
        var claim = Claim(peer: peer.DeviceKeyId);
        var channel = new TestSecureSession(
            NearbySessionRole.Initiator,
            peer,
            ValidationTime);
        var pending = new TestPendingSession(
            Context(NearbySessionRole.Initiator, handle, peer),
            ValidationTime,
            claim,
            channel);
        var committer = TestReplayCommitter.Immediate(
            NearbyReplayClaimClassification.AcceptedFresh);

        var activated = await pending.ActivateAsync(committer);

        Assert.Same(channel, activated);
        Assert.Equal(1, committer.CallCount);
        Assert.Equal(claim, committer.Claims.Single());
        Assert.Equal(1, pending.ActivationCount);
        Assert.Equal(0, pending.PendingDisposeCount);

        var reuse = await Assert.ThrowsAsync<NearbySecureChannelException>(
            async () => await pending.ActivateAsync(committer));
        Assert.Equal(NearbySecureChannelError.InvalidState, reuse.Error);
        Assert.Equal(1, committer.CallCount);
    }

    [Fact]
    public async Task PendingSession_RejectsConcurrentDoubleActivationBeforeSecondCommit()
    {
        var (_, peer, handle) = await Capabilities();
        var claim = Claim(peer: peer.DeviceKeyId);
        var committer = TestReplayCommitter.Blocked();
        var pending = new TestPendingSession(
            Context(NearbySessionRole.Responder, handle, peer),
            ValidationTime,
            claim,
            new TestSecureSession(NearbySessionRole.Responder, peer, ValidationTime));

        var first = pending.ActivateAsync(committer).AsTask();
        await committer.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));

        var concurrent = await Assert.ThrowsAsync<NearbySecureChannelException>(
            async () => await pending.ActivateAsync(committer));
        Assert.Equal(NearbySecureChannelError.InvalidState, concurrent.Error);
        Assert.Equal(1, committer.CallCount);

        committer.Release.TrySetResult(
            new NearbyReplayCommitOutcome(NearbyReplayClaimClassification.AcceptedFresh));
        _ = await first;
        Assert.Equal(claim, committer.Claims.Single());
    }

    [Fact]
    public async Task PendingSession_DisposeDuringCommitAbandonsStateAndNeverTransfers()
    {
        var (_, peer, handle) = await Capabilities();
        var committer = TestReplayCommitter.Blocked();
        var pending = new TestPendingSession(
            Context(NearbySessionRole.Initiator, handle, peer),
            ValidationTime,
            Claim(peer: peer.DeviceKeyId),
            new TestSecureSession(NearbySessionRole.Initiator, peer, ValidationTime));

        var activation = pending.ActivateAsync(committer).AsTask();
        await committer.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        pending.Dispose();
        pending.Dispose();
        Assert.Equal(1, pending.PendingDisposeCount);

        committer.Release.TrySetResult(
            new NearbyReplayCommitOutcome(NearbyReplayClaimClassification.AcceptedFresh));
        var disposed = await Assert.ThrowsAsync<NearbySecureChannelException>(
            async () => await activation);
        Assert.Equal(NearbySecureChannelError.InvalidState, disposed.Error);
        Assert.Equal(0, pending.ActivationCount);
        Assert.Equal(1, pending.PendingDisposeCount);
    }

    [Theory]
    [InlineData(
        NearbyReplayClaimClassification.DuplicateSameTranscript,
        NearbySecureChannelError.ReplayRejected)]
    [InlineData(
        NearbyReplayClaimClassification.CollisionDifferentTranscript,
        NearbySecureChannelError.ReplayCollision)]
    [InlineData(
        NearbyReplayClaimClassification.Rejected,
        NearbySecureChannelError.ReplayRejected)]
    public async Task PendingSession_NonFreshOutcomeConsumesAndDisposes(
        NearbyReplayClaimClassification classification,
        NearbySecureChannelError expectedError)
    {
        var (_, peer, handle) = await Capabilities();
        var pending = new TestPendingSession(
            Context(NearbySessionRole.Initiator, handle, peer),
            ValidationTime,
            Claim(peer: peer.DeviceKeyId),
            new TestSecureSession(NearbySessionRole.Initiator, peer, ValidationTime));
        var committer = TestReplayCommitter.Immediate(classification);

        var rejected = await Assert.ThrowsAsync<NearbySecureChannelException>(
            async () => await pending.ActivateAsync(committer));
        Assert.Equal(expectedError, rejected.Error);
        Assert.Equal(0, pending.ActivationCount);
        Assert.Equal(1, pending.PendingDisposeCount);

        var retry = await Assert.ThrowsAsync<NearbySecureChannelException>(
            async () => await pending.ActivateAsync(committer));
        Assert.Equal(NearbySecureChannelError.InvalidState, retry.Error);
        Assert.Equal(1, committer.CallCount);
    }

    [Fact]
    public async Task PendingSession_RejectsAnyReplayClaimScopeMismatch()
    {
        var (_, peer, handle) = await Capabilities();
        var context = Context(NearbySessionRole.Initiator, handle, peer);
        var channel = new TestSecureSession(
            NearbySessionRole.Initiator,
            peer,
            ValidationTime);

        foreach (var mismatch in new[]
                 {
                     Claim(local: Device(0x21), peer: peer.DeviceKeyId),
                     Claim(peer: Device(0x41)),
                     Claim(peer: peer.DeviceKeyId, attemptStart: 0x91),
                     Claim(peer: peer.DeviceKeyId, rosterEpoch: 8)
                 })
        {
            var exception = Assert.Throws<NearbySecureChannelException>(() =>
                new TestPendingSession(
                    context,
                    ValidationTime,
                    mismatch,
                    channel));
            Assert.Equal(NearbySecureChannelError.InvalidCredential, exception.Error);
        }
    }

    [Fact]
    public async Task PendingSession_RejectsActivatedChannelWithSameDeviceButDifferentAccount()
    {
        var (_, peer, handle) = await Capabilities();
        var alternatePeer = await new TestCredentialVerifier().VerifyAsync(
            Descriptor(
                Account(0x50),
                peer.DeviceKeyId,
                7,
                NearbyDeviceCredentialStatus.Active,
                ValidFrom,
                ValidUntil),
            Expectation(Account(0x50), peer.DeviceKeyId, 7, ValidationTime));
        var channel = new TestSecureSession(NearbySessionRole.Initiator, alternatePeer, ValidationTime);
        var pending = new TestPendingSession(
            Context(NearbySessionRole.Initiator, handle, peer),
            ValidationTime,
            Claim(peer: peer.DeviceKeyId),
            channel);

        var exception = await Assert.ThrowsAsync<NearbySecureChannelException>(
            async () => await pending.ActivateAsync(TestReplayCommitter.Immediate(
                NearbyReplayClaimClassification.AcceptedFresh)));

        Assert.Equal(NearbySecureChannelError.InvalidCredential, exception.Error);
        Assert.Equal(1, channel.DisposeCount);
        Assert.Equal(1, pending.PendingDisposeCount);
    }

    [Fact]
    public async Task PendingSession_RejectsActivatedChannelWithSameDeviceButDifferentRosterEpoch()
    {
        var (_, peer, handle) = await Capabilities();
        var alternatePeer = await new TestCredentialVerifier().VerifyAsync(
            Descriptor(
                peer.AccountIdentity,
                peer.DeviceKeyId,
                8,
                NearbyDeviceCredentialStatus.Active,
                ValidFrom,
                ValidUntil),
            Expectation(peer.AccountIdentity, peer.DeviceKeyId, 8, ValidationTime));
        var channel = new TestSecureSession(NearbySessionRole.Initiator, alternatePeer, ValidationTime);
        var pending = new TestPendingSession(
            Context(NearbySessionRole.Initiator, handle, peer),
            ValidationTime,
            Claim(peer: peer.DeviceKeyId),
            channel);

        var exception = await Assert.ThrowsAsync<NearbySecureChannelException>(
            async () => await pending.ActivateAsync(TestReplayCommitter.Immediate(
                NearbyReplayClaimClassification.AcceptedFresh)));

        Assert.Equal(NearbySecureChannelError.InvalidCredential, exception.Error);
        Assert.Equal(1, channel.DisposeCount);
        Assert.Equal(1, pending.PendingDisposeCount);
    }

    [Fact]
    public async Task PendingSession_RejectsActivatedChannelWithDifferentAuthenticationContext()
    {
        var (_, peer, handle) = await Capabilities();
        var channel = new TestSecureSession(
            NearbySessionRole.Initiator,
            peer,
            ValidationTime.AddMinutes(-1));
        var pending = new TestPendingSession(
            Context(NearbySessionRole.Initiator, handle, peer),
            ValidationTime,
            Claim(peer: peer.DeviceKeyId),
            channel);

        var exception = await Assert.ThrowsAsync<NearbySecureChannelException>(
            async () => await pending.ActivateAsync(TestReplayCommitter.Immediate(
                NearbyReplayClaimClassification.AcceptedFresh)));

        Assert.Equal(NearbySecureChannelError.AuthenticationFailed, exception.Error);
        Assert.Equal(1, channel.DisposeCount);
        Assert.Equal(1, pending.PendingDisposeCount);
    }

    [Fact]
    public async Task PendingSession_NullPostCommitChannelDisposesPendingState()
    {
        var (_, peer, handle) = await Capabilities();
        var pending = new NullPendingSession(
            Context(NearbySessionRole.Initiator, handle, peer),
            ValidationTime,
            Claim(peer: peer.DeviceKeyId));

        var exception = await Assert.ThrowsAsync<NearbySecureChannelException>(
            async () => await pending.ActivateAsync(TestReplayCommitter.Immediate(
                NearbyReplayClaimClassification.AcceptedFresh)));
        Assert.Equal(NearbySecureChannelError.InvalidState, exception.Error);
        Assert.Equal(1, pending.PendingDisposeCount);
    }

    [Fact]
    public async Task LocalKeyProvider_RejectsMismatchedReturnedCredential()
    {
        var (local, peer, _) = await Capabilities();
        var exception = await Assert.ThrowsAsync<NearbySecureChannelException>(
            async () => await new MismatchedLocalKeyProvider(
                new NearbyLocalKeyReference(Range(0x71, 16)),
                peer).GetLocalKeyAsync(local));

        Assert.Equal(NearbySecureChannelError.InvalidCredential, exception.Error);
    }

    [Fact]
    public async Task Context_RechecksIndependentLocalCredentialAgainstKeyHandle()
    {
        var (local, peer, _) = await Capabilities();
        var provider = new MismatchedLocalKeyProvider(
            new NearbyLocalKeyReference(Range(0x72, 16)),
            peer);

        var exception = Assert.Throws<NearbySecureChannelException>(() =>
            new NearbyAkeContext(
                NearbySecureChannelProfileId.UnassignedPendingExternalCryptoReview,
                Binding(),
                NearbySessionRole.Initiator,
                local,
                provider.IssueUncheckedHandle(),
                peer,
                7,
                ValidationTime));

        Assert.Equal(NearbySecureChannelError.InvalidCredential, exception.Error);
    }

    [Fact]
    public async Task FlightWrappers_TransferOrDisposeOwnedStateExactlyOnce()
    {
        var payload = new NearbyHandshakePayload(Range(0x10, 16));
        var (_, peer, handle) = await Capabilities();
        var context = Context(NearbySessionRole.Initiator, handle, peer);
        var initiatorHello = new NearbyInitiatorHelloFrame(
            context,
            NearbyHandshakeCodec.EncodeFrame(
                NearbyHandshakeMessageKind.InitiatorHello,
                Binding(),
                payload.Bytes.Span));
        var responderResponse = new NearbyResponderResponseFrame(
            context,
            initiatorHello,
            NearbyHandshakeCodec.EncodeFrame(
                NearbyHandshakeMessageKind.ResponderResponse,
                Binding(),
                Range(0x20, 16)));
        var factory = new TestFreshAkeFactory();
        var transferredPending = Pending(handle, peer);
        var transferredState = new TestInitiatorState(transferredPending);
        var initiator = factory.IssueInitiatorFlight(
            context,
            payload,
            transferredState);
        var responseFlight = initiator.BindResponse(
            initiatorHello,
            responderResponse);

        Assert.Same(transferredPending, factory.AcceptResponder(responseFlight));
        Assert.Equal(1, transferredState.AcceptCount);
        Assert.Throws<NearbySecureChannelException>(() =>
            factory.AcceptResponder(responseFlight));
        Assert.Throws<NearbySecureChannelException>(() =>
            initiator.BindResponse(initiatorHello, responderResponse));
        initiator.Dispose();
        responseFlight.Dispose();
        initiator.Dispose();
        Assert.Equal(0, transferredState.DisposeCount);
        transferredPending.Dispose();

        var abandonedState = new TestInitiatorState();
        var abandonedInitiator = factory.IssueInitiatorFlight(
            context,
            payload,
            abandonedState);
        abandonedInitiator.Dispose();
        abandonedInitiator.Dispose();
        Assert.Equal(1, abandonedState.DisposeCount);
        Assert.Throws<NearbySecureChannelException>(() =>
            abandonedInitiator.BindResponse(initiatorHello, responderResponse));

        var abandonedResponseState = new TestInitiatorState();
        var abandonedResponse = factory.IssueInitiatorFlight(
                context,
                payload,
                abandonedResponseState)
            .BindResponse(initiatorHello, responderResponse);
        abandonedResponse.Dispose();
        abandonedResponse.Dispose();
        Assert.Equal(1, abandonedResponseState.DisposeCount);
        Assert.Throws<NearbySecureChannelException>(() =>
            factory.AcceptResponder(abandonedResponse));

        var responderPending = Pending(handle, peer);
        var responder = factory.IssueResponderFlight(
            initiatorHello,
            payload,
            responderPending);
        Assert.Same(responderPending, responder.TakePendingSession());
        Assert.Throws<NearbySecureChannelException>(() => responder.TakePendingSession());
        responder.Dispose();
        Assert.Equal(0, responderPending.PendingDisposeCount);
        responderPending.Dispose();
        Assert.Equal(1, responderPending.PendingDisposeCount);

        var abandonedPending = Pending(handle, peer);
        var abandonedResponder = factory.IssueResponderFlight(
            initiatorHello,
            payload,
            abandonedPending);
        abandonedResponder.Dispose();
        abandonedResponder.Dispose();
        Assert.Equal(1, abandonedPending.PendingDisposeCount);
        Assert.Throws<NearbySecureChannelException>(() => abandonedResponder.TakePendingSession());
    }

    [Fact]
    public async Task InitiatorStateBinding_RejectsDifferentContextOrFramePayload()
    {
        var (_, peer, handle) = await Capabilities();
        var context = Context(NearbySessionRole.Initiator, handle, peer);
        var sameValuesDifferentCapability = Context(
            NearbySessionRole.Initiator,
            handle,
            peer);
        var payload = new NearbyHandshakePayload(Range(0x31, 16));
        var otherHello = new NearbyInitiatorHelloFrame(
            sameValuesDifferentCapability,
            NearbyHandshakeCodec.EncodeFrame(
                NearbyHandshakeMessageKind.InitiatorHello,
                Binding(),
                payload.Bytes.Span));
        var otherResponse = new NearbyResponderResponseFrame(
            sameValuesDifferentCapability,
            otherHello,
            NearbyHandshakeCodec.EncodeFrame(
                NearbyHandshakeMessageKind.ResponderResponse,
                Binding(),
                Range(0x41, 16)));
        var factory = new TestFreshAkeFactory();
        var crossContextState = new TestInitiatorState();
        var crossContextFlight = factory.IssueInitiatorFlight(
            context,
            payload,
            crossContextState);

        var crossContext = Assert.Throws<NearbySecureChannelException>(() =>
            crossContextFlight.BindResponse(otherHello, otherResponse));
        Assert.Equal(NearbySecureChannelError.InvalidCredential, crossContext.Error);
        crossContextFlight.Dispose();
        Assert.Equal(1, crossContextState.DisposeCount);

        var matchingHello = new NearbyInitiatorHelloFrame(
            context,
            NearbyHandshakeCodec.EncodeFrame(
                NearbyHandshakeMessageKind.InitiatorHello,
                Binding(),
                payload.Bytes.Span));
        var matchingResponse = new NearbyResponderResponseFrame(
            context,
            matchingHello,
            NearbyHandshakeCodec.EncodeFrame(
                NearbyHandshakeMessageKind.ResponderResponse,
                Binding(),
                Range(0x51, 16)));
        var payloadMismatchState = new TestInitiatorState();
        var payloadMismatchFlight = factory.IssueInitiatorFlight(
            context,
            new NearbyHandshakePayload(Range(0x32, 16)),
            payloadMismatchState);

        var payloadMismatch = Assert.Throws<NearbySecureChannelException>(() =>
            payloadMismatchFlight.BindResponse(matchingHello, matchingResponse));
        Assert.Equal(NearbySecureChannelError.InvalidState, payloadMismatch.Error);
        payloadMismatchFlight.Dispose();
        Assert.Equal(1, payloadMismatchState.DisposeCount);

        var mismatchedFactoryState = new TestInitiatorState();
        var mismatchedFactory = new MismatchedFreshAkeFactory(
            sameValuesDifferentCapability,
            payload,
            mismatchedFactoryState);
        var mismatchedFactoryResult = Assert.Throws<NearbySecureChannelException>(() =>
            mismatchedFactory.BeginInitiator(context));
        Assert.Equal(
            NearbySecureChannelError.InvalidCredential,
            mismatchedFactoryResult.Error);
        Assert.Equal(1, mismatchedFactoryState.DisposeCount);
    }

    [Fact]
    public async Task RecordDirection_IsRoleBoundAndCannotBeSelectedBySealCaller()
    {
        var seal = typeof(INearbySecureSession).GetMethod("Seal")!;
        Assert.Equal(
            [typeof(NearbyRecordKind), typeof(ReadOnlySpan<byte>)],
            seal.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.DoesNotContain(
            seal.GetParameters(),
            parameter => parameter.ParameterType == typeof(NearbyRecordDirection));

        var (_, peer, _) = await Capabilities();
        using var initiator = new TestSecureSession(
            NearbySessionRole.Initiator,
            peer,
            ValidationTime);
        Assert.Equal(
            NearbyRecordDirection.InitiatorToResponder,
            initiator.SendDirection);
        Assert.Equal(
            NearbyRecordDirection.ResponderToInitiator,
            initiator.ReceiveDirection);

        _ = initiator.Seal(NearbyRecordKind.Control, Range(1, 16));
        var opened = initiator.Open(Range(2, 16));
        Assert.Equal(initiator.ReceiveDirection, opened.Direction);
        Assert.Equal(1UL, opened.Counter);

        using var reflected = new ReflectedSecureSession(
            NearbySessionRole.Initiator,
            peer,
            ValidationTime);
        var reflection = Assert.Throws<NearbySecureChannelException>(() =>
            reflected.Open(Range(3, 16)));
        Assert.Equal(NearbySecureChannelError.DirectionReflection, reflection.Error);

        Assert.Equal(
            NearbyRecordDirection.ResponderToInitiator,
            NearbyRecordDirectionPolicy.SendFor(NearbySessionRole.Responder));
        Assert.Equal(
            NearbyRecordDirection.InitiatorToResponder,
            NearbyRecordDirectionPolicy.ReceiveFor(NearbySessionRole.Responder));
    }

    [Fact]
    public async Task Records_RejectOversizedEncodedInputAndAdapterOutput()
    {
        var (_, peer, _) = await Capabilities();
        using var oversizedOpen = new OversizedRecordSession(peer);
        var oversized = new byte[NearbySecureChannelLimits.MaximumEncodedRecordLength + 1];

        var open = Assert.Throws<NearbySecureChannelException>(() => oversizedOpen.Open(oversized));
        Assert.Equal(NearbySecureChannelError.InvalidRecord, open.Error);
        Assert.Equal(0, oversizedOpen.OpenCoreCount);

        using var oversizedSeal = new OversizedRecordSession(peer);
        var seal = Assert.Throws<NearbySecureChannelException>(() =>
            oversizedSeal.Seal(NearbyRecordKind.Control, Range(1, 16)));
        Assert.Equal(NearbySecureChannelError.InvalidRecord, seal.Error);
    }

    [Fact]
    public async Task Records_RejectEmptyAdapterOutput()
    {
        var (_, peer, _) = await Capabilities();
        using var session = new EmptyRecordSession(peer);

        var exception = Assert.Throws<NearbySecureChannelException>(() =>
            session.Seal(NearbyRecordKind.Control, Range(1, 16)));

        Assert.Equal(NearbySecureChannelError.InvalidRecord, exception.Error);
    }

    [Fact]
    public async Task PendingSession_DisposeReentrancyCannotResurrectOrEscapeChannel()
    {
        var (_, peer, handle) = await Capabilities();
        var channel = new TestSecureSession(
            NearbySessionRole.Initiator,
            peer,
            ValidationTime);
        TestPendingSession? pending = null;
        pending = new TestPendingSession(
            Context(NearbySessionRole.Initiator, handle, peer),
            ValidationTime,
            Claim(peer: peer.DeviceKeyId),
            channel,
            beforeReturn: () => pending!.Dispose());

        var exception = await Assert.ThrowsAsync<NearbySecureChannelException>(
            async () => await pending.ActivateAsync(TestReplayCommitter.Immediate(
                NearbyReplayClaimClassification.AcceptedFresh)));

        Assert.Equal(NearbySecureChannelError.InvalidState, exception.Error);
        Assert.Equal(1, channel.DisposeCount);
        Assert.Equal(1, pending.PendingDisposeCount);
    }

    [Fact]
    public async Task PendingSession_ReentrantActivationCannotCommitOrTransferTwice()
    {
        var (_, peer, handle) = await Capabilities();
        var channel = new TestSecureSession(
            NearbySessionRole.Initiator,
            peer,
            ValidationTime);
        var committer = TestReplayCommitter.Immediate(
            NearbyReplayClaimClassification.AcceptedFresh);
        NearbySecureChannelException? nestedFailure = null;
        TestPendingSession? pending = null;
        pending = new TestPendingSession(
            Context(NearbySessionRole.Initiator, handle, peer),
            ValidationTime,
            Claim(peer: peer.DeviceKeyId),
            channel,
            beforeReturn: () =>
            {
                try
                {
                    _ = pending!.ActivateAsync(committer).AsTask().GetAwaiter().GetResult();
                }
                catch (NearbySecureChannelException exception)
                {
                    nestedFailure = exception;
                }
            });

        var activated = await pending.ActivateAsync(committer);

        Assert.Same(channel, activated);
        Assert.Equal(NearbySecureChannelError.InvalidState, nestedFailure?.Error);
        Assert.Equal(1, committer.CallCount);
        Assert.Equal(1, pending.ActivationCount);
        Assert.Equal(0, channel.DisposeCount);
    }

    [Theory]
    [InlineData(ThrowingInspectionProperty.Role)]
    [InlineData(ThrowingInspectionProperty.Peer)]
    [InlineData(ThrowingInspectionProperty.SendDirection)]
    [InlineData(ThrowingInspectionProperty.ReceiveDirection)]
    public async Task PendingSession_DisposesReturnedChannelWhenInspectionThrows(
        ThrowingInspectionProperty throwingProperty)
    {
        var (_, peer, handle) = await Capabilities();
        var channel = new ThrowingInspectionSession(peer, throwingProperty);
        var pending = new TestPendingSession(
            Context(NearbySessionRole.Initiator, handle, peer),
            ValidationTime,
            Claim(peer: peer.DeviceKeyId),
            channel);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await pending.ActivateAsync(TestReplayCommitter.Immediate(
                NearbyReplayClaimClassification.AcceptedFresh)));
        Assert.Equal(1, channel.DisposeCount);
        Assert.Equal(1, pending.PendingDisposeCount);
    }

    [Fact]
    public async Task PendingSession_CancellationBeforeCommitNeverActivates()
    {
        var (_, peer, handle) = await Capabilities();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var pending = new TestPendingSession(
            Context(NearbySessionRole.Initiator, handle, peer),
            ValidationTime,
            Claim(peer: peer.DeviceKeyId),
            new TestSecureSession(NearbySessionRole.Initiator, peer, ValidationTime));
        var committer = TestReplayCommitter.Immediate(NearbyReplayClaimClassification.AcceptedFresh);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await pending.ActivateAsync(committer, cancellation.Token));
        Assert.Equal(0, committer.CallCount);
        Assert.Equal(0, pending.ActivationCount);
        Assert.Equal(1, pending.PendingDisposeCount);
    }

    [Fact]
    public async Task PendingSession_DurableAcceptanceWinsCancellationAfterCommit()
    {
        var (_, peer, handle) = await Capabilities();
        using var cancellation = new CancellationTokenSource();
        var channel = new TestSecureSession(NearbySessionRole.Initiator, peer, ValidationTime);
        var pending = new TestPendingSession(
            Context(NearbySessionRole.Initiator, handle, peer),
            ValidationTime,
            Claim(peer: peer.DeviceKeyId),
            channel);
        var committer = new CommitWinsAfterCancellation(cancellation);

        var activated = await pending.ActivateAsync(committer, cancellation.Token);
        Assert.Same(channel, activated);
        Assert.True(cancellation.IsCancellationRequested);
        Assert.Equal(1, committer.CallCount);
        Assert.Equal(1, pending.ActivationCount);
    }

    [Fact]
    public async Task CanonicalAkeFrames_AreRoleSpecificFreshBoundedAndContextBound()
    {
        var (_, peer, handle) = await Capabilities();
        var context = Context(NearbySessionRole.Responder, handle, peer);
        var initiatorBytes = NearbyHandshakeCodec.EncodeFrame(
            NearbyHandshakeMessageKind.InitiatorHello,
            Binding(),
            Range(0x10, NearbyHandshakeLimits.MinimumAdapterPayloadLength));
        var responderBytes = NearbyHandshakeCodec.EncodeFrame(
            NearbyHandshakeMessageKind.ResponderResponse,
            Binding(),
            Range(0x20, NearbyHandshakeLimits.MinimumAdapterPayloadLength));
        var initiator = new NearbyInitiatorHelloFrame(context, initiatorBytes);
        var responder = new NearbyResponderResponseFrame(
            context,
            initiator,
            responderBytes);
        Assert.Equal(initiatorBytes, initiator.Bytes.ToArray());
        Assert.Equal(responderBytes, responder.Bytes.ToArray());
        Assert.Same(context, initiator.Context);
        Assert.Same(context, responder.Context);
        Assert.Same(initiator, responder.InitiatorHello);
        Assert.Equal(
            context.Binding.TransportAttemptId.Bytes.ToArray(),
            initiator.Binding.TransportAttemptId.Bytes.ToArray());
        Assert.Throws<NearbySecureChannelException>(() =>
            new NearbyInitiatorHelloFrame(
                context,
                new byte[NearbySecureChannelLimits.MaximumCanonicalAkeFrameLength + 1]));

        Assert.Equal(
            [typeof(NearbyInitiatorHelloFrame)],
            typeof(INearbyFreshAke).GetMethod("AcceptInitiator")!
                .GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.Equal(
            [typeof(NearbyInitiatorResponseFlight)],
            typeof(INearbyFreshAke).GetMethod("AcceptResponder")!
                .GetParameters().Select(static parameter => parameter.ParameterType).ToArray());

        var reflected = Assert.Throws<NearbySecureChannelException>(() =>
            new NearbyInitiatorHelloFrame(context, responderBytes));
        Assert.Equal(NearbySecureChannelError.DirectionReflection, reflected.Error);
        var reflectedResponse = Assert.Throws<NearbySecureChannelException>(() =>
            new NearbyResponderResponseFrame(context, initiator, initiatorBytes));
        Assert.Equal(
            NearbySecureChannelError.DirectionReflection,
            reflectedResponse.Error);

        var resumptionBytes = NearbyHandshakeCodec.EncodeFrame(
            NearbyHandshakeMessageKind.InitiatorHello,
            Binding(NearbyHandshakeMode.Resumption, 1),
            Range(0x30, NearbyHandshakeLimits.MinimumAdapterPayloadLength));
        var resumption = Assert.Throws<NearbySecureChannelException>(() =>
            new NearbyInitiatorHelloFrame(context, resumptionBytes));
        Assert.Equal(NearbySecureChannelError.ResumptionNotSupported, resumption.Error);

        var differentAttempt = NearbyHandshakeCodec.EncodeFrame(
            NearbyHandshakeMessageKind.InitiatorHello,
            Binding(attemptStart: 0x91),
            Range(0x40, NearbyHandshakeLimits.MinimumAdapterPayloadLength));
        var mismatch = Assert.Throws<NearbySecureChannelException>(() =>
            new NearbyInitiatorHelloFrame(context, differentAttempt));
        Assert.Equal(NearbySecureChannelError.InvalidHandshakePayload, mismatch.Error);

        var differentContext = new NearbyAkeContext(
            NearbySecureChannelProfileId.UnassignedPendingExternalCryptoReview,
            Binding(attemptStart: 0x91),
            NearbySessionRole.Responder,
            handle.Credential,
            handle,
            peer,
            7,
            ValidationTime);
        var otherInitiator = new NearbyInitiatorHelloFrame(
            differentContext,
            differentAttempt);
        var crossedExchange = Assert.Throws<NearbySecureChannelException>(() =>
            new NearbyResponderResponseFrame(context, otherInitiator, responderBytes));
        Assert.Equal(NearbySecureChannelError.InvalidCredential, crossedExchange.Error);
    }

    [Fact]
    public async Task CanonicalAkeFrame_SnapshotsCallerMemoryBeforeValidation()
    {
        var (_, peer, handle) = await Capabilities();
        var context = Context(NearbySessionRole.Responder, handle, peer);
        var encoded = NearbyHandshakeCodec.EncodeFrame(
            NearbyHandshakeMessageKind.InitiatorHello,
            Binding(),
            Range(0x20, NearbyHandshakeLimits.MinimumAdapterPayloadLength));
        using var memory = new MutatingMemoryManager(encoded);

        var frame = new NearbyInitiatorHelloFrame(context, memory.Memory);

        _ = NearbyHandshakeCodec.DecodeFrame(frame.Bytes.Span);
        Assert.Equal(encoded, frame.Bytes.ToArray());
    }

    [Fact]
    public void AkeBoundary_RequiresRoleSpecificFrameTypes()
    {
        var assembly = typeof(NearbyAkeContext).Assembly;
        var initiator = assembly.GetType(
            "Deep.Protocol.DeepExtension.NearbySecureChannels.NearbyInitiatorHelloFrame");
        var responder = assembly.GetType(
            "Deep.Protocol.DeepExtension.NearbySecureChannels.NearbyResponderResponseFrame");

        Assert.NotNull(initiator);
        Assert.NotNull(responder);
        Assert.Null(assembly.GetType(
            "Deep.Protocol.DeepExtension.NearbySecureChannels.NearbyCanonicalAkeFrame"));
        Assert.Equal(
            [initiator],
            typeof(INearbyFreshAke).GetMethod("AcceptInitiator")!
                .GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.Equal(
            [typeof(NearbyInitiatorResponseFlight)],
            typeof(INearbyFreshAke).GetMethod("AcceptResponder")!
                .GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
    }

    [Fact]
    public async Task ResponderFrame_RejectsSameBindingFromDifferentContextCapability()
    {
        var (local, peer, handle) = await Capabilities();
        var context = Context(NearbySessionRole.Responder, handle, peer);
        var initiatorBytes = NearbyHandshakeCodec.EncodeFrame(
            NearbyHandshakeMessageKind.InitiatorHello,
            Binding(),
            Range(0x51, NearbyHandshakeLimits.MinimumAdapterPayloadLength));
        var responderBytes = NearbyHandshakeCodec.EncodeFrame(
            NearbyHandshakeMessageKind.ResponderResponse,
            Binding(),
            Range(0x61, NearbyHandshakeLimits.MinimumAdapterPayloadLength));
        var initiator = new NearbyInitiatorHelloFrame(context, initiatorBytes);
        var verifier = new TestCredentialVerifier();
        var otherPeer = await verifier.VerifyAsync(
            Descriptor(
                Account(0x51),
                Device(0x61),
                7,
                NearbyDeviceCredentialStatus.Active,
                ValidFrom,
                ValidUntil),
            Expectation(Account(0x51), Device(0x61), 7, ValidationTime));
        var otherLocal = await verifier.VerifyAsync(
            Descriptor(
                Account(0x11),
                Device(0x21),
                7,
                NearbyDeviceCredentialStatus.Active,
                ValidFrom,
                ValidUntil),
            Expectation(Account(0x11), Device(0x21), 7, ValidationTime));
        var otherHandle = await new TestLocalKeyProvider(
            new NearbyLocalKeyReference(Range(0x71, 16)))
            .GetLocalKeyAsync(otherLocal);
        var epochEightLocal = await verifier.VerifyAsync(
            Descriptor(
                local.AccountIdentity,
                local.DeviceKeyId,
                8,
                NearbyDeviceCredentialStatus.Active,
                ValidFrom,
                ValidUntil),
            Expectation(local.AccountIdentity, local.DeviceKeyId, 8, ValidationTime));
        var epochEightPeer = await verifier.VerifyAsync(
            Descriptor(
                peer.AccountIdentity,
                peer.DeviceKeyId,
                8,
                NearbyDeviceCredentialStatus.Active,
                ValidFrom,
                ValidUntil),
            Expectation(peer.AccountIdentity, peer.DeviceKeyId, 8, ValidationTime));
        var epochEightHandle = await new TestLocalKeyProvider(
            new NearbyLocalKeyReference(Range(0x72, 16)))
            .GetLocalKeyAsync(epochEightLocal);

        foreach (var differentContext in new[]
                 {
                     AkeContext(
                         NearbySessionRole.Responder,
                         local,
                         handle,
                         otherPeer,
                         7,
                         ValidationTime),
                     AkeContext(
                         NearbySessionRole.Responder,
                         otherLocal,
                         otherHandle,
                         peer,
                         7,
                         ValidationTime),
                     AkeContext(
                         NearbySessionRole.Initiator,
                         local,
                         handle,
                         peer,
                         7,
                         ValidationTime),
                     AkeContext(
                         NearbySessionRole.Responder,
                         epochEightLocal,
                         epochEightHandle,
                         epochEightPeer,
                         8,
                         ValidationTime),
                     AkeContext(
                         NearbySessionRole.Responder,
                         local,
                         handle,
                         peer,
                         7,
                         ValidationTime.AddMinutes(-1))
                 })
        {
            var exception = Assert.Throws<NearbySecureChannelException>(() =>
                new NearbyResponderResponseFrame(
                    differentContext,
                    initiator,
                    responderBytes));
            Assert.Equal(NearbySecureChannelError.InvalidCredential, exception.Error);
        }
    }

    [Fact]
    public void InitiatorStateBoundary_IsOwnedAndCannotAcceptRawState()
    {
        var assembly = typeof(NearbyAkeContext).Assembly;
        var ownedResponse = assembly.GetType(
            "Deep.Protocol.DeepExtension.NearbySecureChannels.NearbyInitiatorResponseFlight");
        var acceptResponder = typeof(INearbyFreshAke).GetMethod("AcceptResponder")!;

        Assert.NotNull(ownedResponse);
        Assert.Equal(
            [ownedResponse],
            acceptResponder.GetParameters()
                .Select(static parameter => parameter.ParameterType)
                .ToArray());
        Assert.DoesNotContain(
            acceptResponder.GetParameters(),
            parameter => parameter.ParameterType.Name.Contains(
                "InitiatorState",
                StringComparison.Ordinal));
        Assert.Empty(typeof(NearbyInitiatorFlight).GetConstructors());
        Assert.Empty(ownedResponse!.GetConstructors());
        Assert.Equal(
            ownedResponse,
            typeof(NearbyInitiatorFlight).GetMethod("BindResponse")?.ReturnType);
    }

    [Fact]
    public void InitiatorFactory_IsInstanceBoundAndCannotReExportRawState()
    {
        var factory = typeof(NearbyFreshAkeBase).GetMethod(
            "CreateInitiatorFlight",
            BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);

        Assert.NotNull(factory);
        Assert.False(factory.IsStatic);
        Assert.Null(typeof(NearbyInitiatorResponseFlight).GetMethod("TakeState"));
        Assert.DoesNotContain(
            typeof(NearbyFreshAkeBase).GetMethods(
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance),
            method => method.ReturnType.Name.Contains(
                "InitiatorState",
                StringComparison.Ordinal) ||
                method.GetParameters().Any(parameter =>
                    parameter.ParameterType.Name.Contains(
                        "InitiatorState",
                        StringComparison.Ordinal)));
        Assert.DoesNotContain(
            typeof(NearbyFreshAkeBase).GetMethods(
                BindingFlags.NonPublic | BindingFlags.Static),
            method => method.ReturnType == typeof(NearbyInitiatorFlight));
        Assert.Null(typeof(NearbyFreshAkeBase).Assembly.GetType(
            "Deep.Protocol.DeepExtension.NearbySecureChannels.INearbyInitiatorState"));
    }

    [Fact]
    public void ResponderFlight_IsIssuerCapabilityNotCallerConstructible()
    {
        Assert.Empty(typeof(NearbyResponderFlight).GetConstructors());
        Assert.NotNull(typeof(NearbyResponderFlight).GetProperty("Context"));
        Assert.NotNull(typeof(NearbyResponderFlight).GetProperty("InitiatorHello"));
    }

    [Fact]
    public async Task InitiatorResponse_IsInstanceBoundAndWrongIssuerRetainsOwnership()
    {
        var (_, peer, handle) = await Capabilities();
        var context = Context(NearbySessionRole.Initiator, handle, peer);
        var payload = new NearbyHandshakePayload(Range(0x73, 16));
        var initiatorHello = new NearbyInitiatorHelloFrame(
            context,
            NearbyHandshakeCodec.EncodeFrame(
                NearbyHandshakeMessageKind.InitiatorHello,
                Binding(),
                payload.Bytes.Span));
        var responderResponse = new NearbyResponderResponseFrame(
            context,
            initiatorHello,
            NearbyHandshakeCodec.EncodeFrame(
                NearbyHandshakeMessageKind.ResponderResponse,
                Binding(),
                Range(0x83, 16)));
        var owner = new TestFreshAkeFactory();
        var sameSubclassThief = new TestFreshAkeFactory();
        var otherSubclassThief = new OtherFreshAkeFactory();

        var sameSubclassBeginState = new TestInitiatorState();
        var sameSubclassBegin = owner.IssueInitiatorFlight(
            context,
            payload,
            sameSubclassBeginState);
        sameSubclassThief.ReturnInitiatorFlight(_ => sameSubclassBegin);
        Assert.Throws<NearbySecureChannelException>(() =>
            sameSubclassThief.BeginInitiator(context));
        Assert.Equal(1, sameSubclassBeginState.DisposeCount);

        var otherSubclassBeginState = new TestInitiatorState();
        var otherSubclassBegin = owner.IssueInitiatorFlight(
            context,
            payload,
            otherSubclassBeginState);
        otherSubclassThief.ReturnInitiatorFlight(_ => otherSubclassBegin);
        Assert.Throws<NearbySecureChannelException>(() =>
            otherSubclassThief.BeginInitiator(context));
        Assert.Equal(1, otherSubclassBeginState.DisposeCount);

        var pending = Pending(handle, peer);
        var state = new TestInitiatorState(pending);
        var responseFlight = owner.IssueInitiatorFlight(
                context,
                payload,
                state)
            .BindResponse(initiatorHello, responderResponse);

        foreach (var thief in new NearbyFreshAkeBase[]
                 {
                     sameSubclassThief,
                     otherSubclassThief
                 })
        {
            var rejected = Assert.Throws<NearbySecureChannelException>(() =>
                thief.AcceptResponder(responseFlight));
            Assert.Equal(
                NearbySecureChannelError.InvalidCredential,
                rejected.Error);
            Assert.Equal(0, state.AcceptCount);
            Assert.Equal(0, state.DisposeCount);
        }

        Assert.Same(pending, owner.AcceptResponder(responseFlight));
        Assert.Equal(1, state.AcceptCount);
        Assert.Equal(0, state.DisposeCount);
        responseFlight.Dispose();
        pending.Dispose();

        var abandonedState = new TestInitiatorState();
        var abandoned = owner.IssueInitiatorFlight(
                context,
                payload,
                abandonedState)
            .BindResponse(initiatorHello, responderResponse);
        Assert.Throws<NearbySecureChannelException>(() =>
            sameSubclassThief.AcceptResponder(abandoned));
        abandoned.Dispose();
        abandoned.Dispose();
        Assert.Equal(0, abandonedState.AcceptCount);
        Assert.Equal(1, abandonedState.DisposeCount);

        var failingState = new TestInitiatorState();
        var failing = owner.IssueInitiatorFlight(
                context,
                payload,
                failingState)
            .BindResponse(initiatorHello, responderResponse);
        Assert.Throws<NotSupportedException>(() =>
            owner.AcceptResponder(failing));
        Assert.Equal(1, failingState.AcceptCount);
        Assert.Equal(1, failingState.DisposeCount);
        Assert.Throws<NearbySecureChannelException>(() =>
            owner.AcceptResponder(failing));
    }

    [Fact]
    public async Task ResponderFlight_RejectsStolenIssuerAndMismatchedInputFrame()
    {
        var (_, peer, handle) = await Capabilities();
        var context = Context(NearbySessionRole.Responder, handle, peer);
        var payload = new NearbyHandshakePayload(Range(0x93, 16));
        var initiatorHello = new NearbyInitiatorHelloFrame(
            context,
            NearbyHandshakeCodec.EncodeFrame(
                NearbyHandshakeMessageKind.InitiatorHello,
                Binding(),
                payload.Bytes.Span));
        var sameValuesDifferentFrame = new NearbyInitiatorHelloFrame(
            context,
            initiatorHello.Bytes);
        var owner = new TestFreshAkeFactory();
        var sameSubclassThief = new TestFreshAkeFactory();
        var otherSubclassThief = new OtherFreshAkeFactory();

        var sameSubclassPending = Pending(handle, peer);
        var sameSubclassStolen = owner.IssueResponderFlight(
            initiatorHello,
            payload,
            sameSubclassPending);
        sameSubclassThief.ReturnResponderFlight(_ => sameSubclassStolen);
        var sameSubclassRejected =
            Assert.Throws<NearbySecureChannelException>(() =>
                sameSubclassThief.AcceptInitiator(initiatorHello));
        Assert.Equal(
            NearbySecureChannelError.InvalidCredential,
            sameSubclassRejected.Error);
        Assert.Equal(1, sameSubclassPending.PendingDisposeCount);

        var otherSubclassPending = Pending(handle, peer);
        var otherSubclassStolen = owner.IssueResponderFlight(
            initiatorHello,
            payload,
            otherSubclassPending);
        otherSubclassThief.ReturnResponderFlight(_ => otherSubclassStolen);
        var otherSubclassRejected =
            Assert.Throws<NearbySecureChannelException>(() =>
                otherSubclassThief.AcceptInitiator(initiatorHello));
        Assert.Equal(
            NearbySecureChannelError.InvalidCredential,
            otherSubclassRejected.Error);
        Assert.Equal(1, otherSubclassPending.PendingDisposeCount);

        var wrongFramePending = Pending(handle, peer);
        var wrongFrame = owner.IssueResponderFlight(
            initiatorHello,
            payload,
            wrongFramePending);
        owner.ReturnResponderFlight(_ => wrongFrame);
        var wrongFrameRejected =
            Assert.Throws<NearbySecureChannelException>(() =>
                owner.AcceptInitiator(sameValuesDifferentFrame));
        Assert.Equal(
            NearbySecureChannelError.InvalidCredential,
            wrongFrameRejected.Error);
        Assert.Equal(1, wrongFramePending.PendingDisposeCount);

        var acceptedPending = Pending(handle, peer);
        owner.ReturnResponderFlight(input =>
            owner.IssueResponderFlight(input, payload, acceptedPending));
        var accepted = owner.AcceptInitiator(initiatorHello);
        Assert.Same(context, accepted.Context);
        Assert.Same(initiatorHello, accepted.InitiatorHello);
        Assert.Same(acceptedPending, accepted.TakePendingSession());
        accepted.Dispose();
        Assert.Equal(0, acceptedPending.PendingDisposeCount);
        acceptedPending.Dispose();
    }

    [Fact]
    public void ContractAssembly_HasNoRawKeyCryptoOrRuntimeImplementation()
    {
        var contractTypes = typeof(NearbyAkeContext).Assembly.GetTypes()
            .Where(type => type.Namespace ==
                "Deep.Protocol.DeepExtension.NearbySecureChannels")
            .ToArray();
        var forbiddenNames = new[]
        {
            "Noise", "Hmac", "Aes", "ChaCha", "Scalar", "Prf",
            "PrivateKey", "SecretKey", "TrafficKey", "SessionKey", "RawKey"
        };

        foreach (var type in contractTypes)
        {
            var surface = type.GetMembers(BindingFlags.Instance | BindingFlags.Public)
                .Select(static member => member.Name)
                .Concat(type.GetMethods().Select(static method => method.ReturnType.Name))
                .Concat(type.GetMethods()
                    .SelectMany(static method => method.GetParameters())
                    .Select(static parameter => parameter.ParameterType.Name));
            Assert.DoesNotContain(surface, name =>
                forbiddenNames.Any(forbidden =>
                    name.Contains(forbidden, StringComparison.OrdinalIgnoreCase)));
        }

        foreach (var contract in new[]
                 {
                     typeof(INearbyFreshAke),
                     typeof(INearbyPendingSession),
                     typeof(INearbySecureSession),
                     typeof(INearbyReplayCommitter),
                     typeof(INearbyDeviceCredentialVerifier),
                     typeof(INearbyLocalDeviceKeyProvider)
                 })
        {
            Assert.DoesNotContain(contractTypes, type =>
                type is { IsInterface: false, IsAbstract: false } &&
                contract.IsAssignableFrom(type));
        }
    }

    private static async ValueTask<(
        NearbyVerifiedDeviceCredential Local,
        NearbyVerifiedDeviceCredential Peer,
        NearbyLocalDeviceKeyHandle Handle)> Capabilities()
    {
        var verifier = new TestCredentialVerifier();
        var localDescriptor = Descriptor(
            Account(0x10),
            Device(0x20),
            7,
            NearbyDeviceCredentialStatus.Active,
            ValidFrom,
            ValidUntil);
        var peerDescriptor = Descriptor(
            Account(0x30),
            Device(0x40),
            7,
            NearbyDeviceCredentialStatus.Active,
            ValidFrom,
            ValidUntil);
        var local = await verifier.VerifyAsync(
            localDescriptor,
            Expectation(localDescriptor.AccountIdentity, localDescriptor.DeviceKeyId, 7, ValidationTime));
        var peer = await verifier.VerifyAsync(
            peerDescriptor,
            Expectation(peerDescriptor.AccountIdentity, peerDescriptor.DeviceKeyId, 7, ValidationTime));
        var handle = await new TestLocalKeyProvider(
            new NearbyLocalKeyReference(Range(0x70, 16)))
            .GetLocalKeyAsync(local);
        return (local, peer, handle);
    }

    private static TestPendingSession Pending(
        NearbyLocalDeviceKeyHandle handle,
        NearbyVerifiedDeviceCredential peer) =>
        new(
            Context(NearbySessionRole.Initiator, handle, peer),
            ValidationTime,
            Claim(peer: peer.DeviceKeyId),
            new TestSecureSession(NearbySessionRole.Initiator, peer, ValidationTime));

    private static NearbyAkeContext Context(
        NearbySessionRole localRole,
        NearbyLocalDeviceKeyHandle handle,
        NearbyVerifiedDeviceCredential peer) =>
        AkeContext(
            localRole,
            handle.Credential,
            handle,
            peer,
            7,
            ValidationTime);

    private static NearbyAkeContext AkeContext(
        NearbySessionRole localRole,
        NearbyVerifiedDeviceCredential local,
        NearbyLocalDeviceKeyHandle handle,
        NearbyVerifiedDeviceCredential peer,
        ulong rosterEpoch,
        DateTimeOffset validationTime) =>
        new(
            NearbySecureChannelProfileId.UnassignedPendingExternalCryptoReview,
            Binding(),
            localRole,
            local,
            handle,
            peer,
            rosterEpoch,
            validationTime);

    private static NearbyDeviceCredentialDescriptor Descriptor(
        NearbyAccountIdentity account,
        NearbyDeviceKeyId device,
        ulong epoch,
        NearbyDeviceCredentialStatus status,
        DateTimeOffset validFrom,
        DateTimeOffset validUntil) =>
        new(account, device, epoch, validFrom, validUntil, status);

    private static NearbyCredentialVerificationExpectation Expectation(
        NearbyAccountIdentity account,
        NearbyDeviceKeyId device,
        ulong epoch,
        DateTimeOffset validationTime) =>
        new(account, device, epoch, validationTime);

    private static NearbyFreshReplayClaim Claim(
        NearbyDeviceKeyId? local = null,
        NearbyDeviceKeyId? peer = null,
        int attemptStart = 0x80,
        NearbyTranscriptDigest? digest = null,
        ulong rosterEpoch = 7) =>
        new(
            local ?? Device(0x20),
            peer ?? Device(0x40),
            new TransportAttemptId(Range(attemptStart, 16)),
            digest ?? new NearbyTranscriptDigest(Range(0xb0, 32)),
            rosterEpoch);

    private static NearbyHandshakeBinding Binding(
        NearbyHandshakeMode mode = NearbyHandshakeMode.Fresh,
        ulong resumeCounter = 0,
        int attemptStart = 0x80) =>
        new()
        {
            BundleVersion = 1,
            Period = 100,
            TransportAttemptId = new TransportAttemptId(Range(attemptStart, 16)),
            SimultaneousOpenToken = Range(0xa0, 16),
            Mode = mode,
            ResumeCounter = resumeCounter
        };

    private static NearbyAccountIdentity Account(int start) =>
        new(Range(start, 33));

    private static NearbyDeviceKeyId Device(int start) =>
        new(Range(start, 32));

    private static void AssertOpaqueValueEquality<T>(
        Func<ReadOnlyMemory<byte>, T> create,
        int minimumLength,
        int maximumLength)
        where T : notnull
    {
        Assert.ThrowsAny<Exception>(() => create(ReadOnlyMemory<byte>.Empty));
        Assert.ThrowsAny<Exception>(() => create(new byte[minimumLength - 1]));
        Assert.ThrowsAny<Exception>(() => create(new byte[maximumLength + 1]));
        Assert.ThrowsAny<Exception>(() => create(new byte[minimumLength]));

        var input = Range(1, minimumLength);
        var left = create(input);
        var same = create(Range(1, minimumLength));
        var different = create(Range(2, minimumLength));
        input[0] ^= 0xff;

        Assert.Equal(left, same);
        Assert.Equal(left.GetHashCode(), same.GetHashCode());
        Assert.NotEqual(left, different);
        Assert.Contains("redacted", left.ToString(), StringComparison.OrdinalIgnoreCase);

        var bytes = (ReadOnlyMemory<byte>)left.GetType().GetProperty("Bytes")!.GetValue(left)!;
        Assert.True(MemoryMarshal.TryGetArray(bytes, out var segment));
        segment.Array![segment.Offset] ^= 0xff;
        var reread = (ReadOnlyMemory<byte>)left.GetType().GetProperty("Bytes")!.GetValue(left)!;
        Assert.Equal(1, reread.Span[0]);
    }

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();

    private sealed class TestCredentialVerifier : NearbyDeviceCredentialVerifierBase
    {
        public override ValueTask<NearbyVerifiedDeviceCredential> VerifyAsync(
            NearbyDeviceCredentialDescriptor descriptor,
            NearbyCredentialVerificationExpectation expectation,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(
                CreateVerifiedCredential(descriptor, expectation));
        }
    }

    private sealed class TestLocalKeyProvider(NearbyLocalKeyReference keyReference)
        : NearbyLocalDeviceKeyProviderBase
    {
        protected override ValueTask<NearbyLocalDeviceKeyHandle> GetLocalKeyCoreAsync(
            NearbyVerifiedDeviceCredential credential,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(
                CreateOpaqueLocalKeyHandle(credential, keyReference));
        }
    }

    private sealed class MismatchedLocalKeyProvider(
        NearbyLocalKeyReference keyReference,
        NearbyVerifiedDeviceCredential returnedCredential)
        : NearbyLocalDeviceKeyProviderBase
    {
        protected override ValueTask<NearbyLocalDeviceKeyHandle> GetLocalKeyCoreAsync(
            NearbyVerifiedDeviceCredential credential,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(
                CreateOpaqueLocalKeyHandle(returnedCredential, keyReference));
        }

        public NearbyLocalDeviceKeyHandle IssueUncheckedHandle() =>
            CreateOpaqueLocalKeyHandle(returnedCredential, keyReference);
    }

    private sealed class TestInitiatorState(
        INearbyPendingSession? pendingSession = null)
    {
        private int accepted;
        private int disposed;

        public int AcceptCount => Volatile.Read(ref accepted);

        public int DisposeCount => Volatile.Read(ref disposed);

        public INearbyPendingSession Accept(
            NearbyResponderResponseFrame responderResponse)
        {
            ArgumentNullException.ThrowIfNull(responderResponse);
            Interlocked.Increment(ref accepted);
            return pendingSession ?? throw new NotSupportedException();
        }

        public void Dispose() => Interlocked.CompareExchange(ref disposed, 1, 0);
    }

    private sealed class TestFreshAkeFactory : NearbyFreshAkeBase
    {
        private Func<
            NearbyAkeContext,
            NearbyInitiatorFlight>? beginInitiator;
        private Func<
            NearbyInitiatorHelloFrame,
            NearbyResponderFlight>? acceptInitiator;

        public NearbyInitiatorFlight IssueInitiatorFlight(
            NearbyAkeContext context,
            NearbyHandshakePayload handshakePayload,
            TestInitiatorState state) =>
            CreateInitiatorFlight(
                context,
                handshakePayload,
                state.Accept,
                state.Dispose);

        public NearbyResponderFlight IssueResponderFlight(
            NearbyInitiatorHelloFrame initiatorHello,
            NearbyHandshakePayload handshakePayload,
            INearbyPendingSession pendingSession) =>
            CreateResponderFlight(
                initiatorHello,
                handshakePayload,
                pendingSession);

        public void ReturnInitiatorFlight(
            Func<NearbyAkeContext, NearbyInitiatorFlight> value) =>
            beginInitiator = value;

        public void ReturnResponderFlight(
            Func<NearbyInitiatorHelloFrame, NearbyResponderFlight> value) =>
            acceptInitiator = value;

        protected override NearbyInitiatorFlight BeginInitiatorCore(
            NearbyAkeContext context) =>
            beginInitiator?.Invoke(context) ??
            throw new NotSupportedException();

        protected override NearbyResponderFlight AcceptInitiatorCore(
            NearbyInitiatorHelloFrame canonicalInitiatorFrame) =>
            acceptInitiator?.Invoke(canonicalInitiatorFrame) ??
            throw new NotSupportedException();
    }

    private sealed class MismatchedFreshAkeFactory(
        NearbyAkeContext issuedContext,
        NearbyHandshakePayload payload,
        TestInitiatorState state)
        : NearbyFreshAkeBase
    {
        protected override NearbyInitiatorFlight BeginInitiatorCore(
            NearbyAkeContext context)
        {
            _ = context;
            return CreateInitiatorFlight(
                issuedContext,
                payload,
                state.Accept,
                state.Dispose);
        }

        protected override NearbyResponderFlight AcceptInitiatorCore(
            NearbyInitiatorHelloFrame canonicalInitiatorFrame) =>
            throw new NotSupportedException();
    }

    private sealed class OtherFreshAkeFactory : NearbyFreshAkeBase
    {
        private Func<
            NearbyAkeContext,
            NearbyInitiatorFlight>? beginInitiator;
        private Func<
            NearbyInitiatorHelloFrame,
            NearbyResponderFlight>? acceptInitiator;

        public void ReturnInitiatorFlight(
            Func<NearbyAkeContext, NearbyInitiatorFlight> value) =>
            beginInitiator = value;

        public void ReturnResponderFlight(
            Func<NearbyInitiatorHelloFrame, NearbyResponderFlight> value) =>
            acceptInitiator = value;

        protected override NearbyInitiatorFlight BeginInitiatorCore(
            NearbyAkeContext context) =>
            beginInitiator?.Invoke(context) ??
            throw new NotSupportedException();

        protected override NearbyResponderFlight AcceptInitiatorCore(
            NearbyInitiatorHelloFrame canonicalInitiatorFrame) =>
            acceptInitiator?.Invoke(canonicalInitiatorFrame) ??
            throw new NotSupportedException();
    }

    private sealed class TestPendingSession : NearbyPendingSessionBase
    {
        private readonly INearbySecureSession channel;
        private readonly Action? beforeReturn;
        private int activationCount;
        private int pendingDisposeCount;

        public TestPendingSession(
            NearbyAkeContext context,
            DateTimeOffset authenticatedAt,
            NearbyFreshReplayClaim replayClaim,
            INearbySecureSession channel,
            NearbyTranscriptDigest? handshakeHash = null,
            Action? beforeReturn = null)
            : base(
                context,
                authenticatedAt,
                handshakeHash ?? replayClaim.TranscriptDigest,
                replayClaim)
        {
            this.channel = channel;
            this.beforeReturn = beforeReturn;
        }

        public int ActivationCount => Volatile.Read(ref activationCount);

        public int PendingDisposeCount => Volatile.Read(ref pendingDisposeCount);

        protected override INearbySecureSession ActivateAfterReplayCommit()
        {
            Interlocked.Increment(ref activationCount);
            beforeReturn?.Invoke();
            return channel;
        }

        protected override void DisposePendingState() =>
            Interlocked.Increment(ref pendingDisposeCount);
    }

    private sealed class NullPendingSession : NearbyPendingSessionBase
    {
        private int pendingDisposeCount;

        public NullPendingSession(
            NearbyAkeContext context,
            DateTimeOffset authenticatedAt,
            NearbyFreshReplayClaim replayClaim)
            : base(context, authenticatedAt, replayClaim.TranscriptDigest, replayClaim)
        {
        }

        public int PendingDisposeCount => Volatile.Read(ref pendingDisposeCount);

        protected override INearbySecureSession ActivateAfterReplayCommit() => null!;

        protected override void DisposePendingState() =>
            Interlocked.Increment(ref pendingDisposeCount);
    }

    private sealed class TestReplayCommitter : INearbyReplayCommitter
    {
        private readonly NearbyReplayClaimClassification? immediate;
        private int callCount;

        private TestReplayCommitter(NearbyReplayClaimClassification? immediate)
        {
            this.immediate = immediate;
        }

        public List<NearbyFreshReplayClaim> Claims { get; } = [];

        public int CallCount => Volatile.Read(ref callCount);

        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<NearbyReplayCommitOutcome> Release { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public static TestReplayCommitter Immediate(
            NearbyReplayClaimClassification classification) =>
            new(classification);

        public static TestReplayCommitter Blocked() => new(null);

        public async ValueTask<NearbyReplayCommitOutcome> CommitFreshAsync(
            NearbyFreshReplayClaim claim,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref callCount);
            lock (Claims)
            {
                Claims.Add(claim);
            }

            Started.TrySetResult();
            if (immediate is { } classification)
            {
                return new NearbyReplayCommitOutcome(classification);
            }

            return await Release.Task.WaitAsync(cancellationToken);
        }
    }

    private sealed class CommitWinsAfterCancellation(CancellationTokenSource cancellation)
        : INearbyReplayCommitter
    {
        private int callCount;

        public int CallCount => Volatile.Read(ref callCount);

        public ValueTask<NearbyReplayCommitOutcome> CommitFreshAsync(
            NearbyFreshReplayClaim claim,
            CancellationToken cancellationToken = default)
        {
            _ = claim;
            _ = cancellationToken;
            Interlocked.Increment(ref callCount);
            cancellation.Cancel();
            return ValueTask.FromResult(new NearbyReplayCommitOutcome(
                NearbyReplayClaimClassification.AcceptedFresh));
        }
    }

    private class TestSecureSession : NearbySecureSessionBase
    {
        private ulong sendCounter;
        private ulong receiveCounter;
        private int disposeCount;

        public TestSecureSession(
            NearbySessionRole localRole,
            NearbyVerifiedDeviceCredential peerCredential,
            DateTimeOffset authenticatedAt)
            : base(
                localRole,
                peerCredential,
                peerCredential.RosterEpoch,
                authenticatedAt)
        {
        }

        protected override byte[] SealCore(
            NearbyRecordDirection direction,
            NearbyRecordKind kind,
            ReadOnlySpan<byte> plaintext)
        {
            Assert.Equal(SendDirection, direction);
            _ = kind;
            _ = checked(++sendCounter);
            return plaintext.ToArray();
        }

        protected override NearbyOpenedRecord OpenCore(
            NearbyRecordDirection expectedDirection,
            ReadOnlySpan<byte> record) =>
            new(
                expectedDirection,
                NearbyRecordKind.Control,
                checked(++receiveCounter),
                record.ToArray());

        public int DisposeCount => Volatile.Read(ref disposeCount);

        public override void Dispose() => Interlocked.Increment(ref disposeCount);
    }

    private sealed class ReflectedSecureSession(
        NearbySessionRole localRole,
        NearbyVerifiedDeviceCredential peerCredential,
        DateTimeOffset authenticatedAt)
        : TestSecureSession(localRole, peerCredential, authenticatedAt)
    {
        protected override NearbyOpenedRecord OpenCore(
            NearbyRecordDirection expectedDirection,
            ReadOnlySpan<byte> record) =>
            new(
                SendDirection,
                NearbyRecordKind.Control,
                1,
                record.ToArray());
    }

    private sealed class OversizedRecordSession(NearbyVerifiedDeviceCredential peer)
        : TestSecureSession(NearbySessionRole.Initiator, peer, ValidationTime)
    {
        public int OpenCoreCount { get; private set; }

        protected override byte[] SealCore(
            NearbyRecordDirection direction,
            NearbyRecordKind kind,
            ReadOnlySpan<byte> plaintext)
        {
            _ = direction;
            _ = kind;
            _ = plaintext;
            return new byte[NearbySecureChannelLimits.MaximumEncodedRecordLength + 1];
        }

        protected override NearbyOpenedRecord OpenCore(
            NearbyRecordDirection expectedDirection,
            ReadOnlySpan<byte> record)
        {
            OpenCoreCount++;
            _ = record;
            return new NearbyOpenedRecord(
                expectedDirection,
                NearbyRecordKind.Control,
                1,
                Range(1, 16));
        }
    }

    private sealed class EmptyRecordSession(NearbyVerifiedDeviceCredential peer)
        : TestSecureSession(NearbySessionRole.Initiator, peer, ValidationTime)
    {
        protected override byte[] SealCore(
            NearbyRecordDirection direction,
            NearbyRecordKind kind,
            ReadOnlySpan<byte> plaintext)
        {
            _ = direction;
            _ = kind;
            _ = plaintext;
            return [];
        }
    }

    private sealed class MutatingMemoryManager(byte[] initial) : MemoryManager<byte>
    {
        private readonly byte[] bytes = initial.ToArray();
        private int spanReads;

        public override Span<byte> GetSpan()
        {
            // MemoryManager.Memory observes the span once while creating Memory.
            // The second observation must be snapshotted; any later caller read mutates.
            if (Interlocked.Increment(ref spanReads) > 2)
            {
                bytes[0] ^= 0xff;
            }

            return bytes;
        }

        public override MemoryHandle Pin(int elementIndex = 0) =>
            throw new NotSupportedException();

        public override void Unpin()
        {
        }

        protected override void Dispose(bool disposing)
        {
        }
    }

    public enum ThrowingInspectionProperty
    {
        Role,
        Peer,
        SendDirection,
        ReceiveDirection
    }

    private sealed class ThrowingInspectionSession(
        NearbyVerifiedDeviceCredential peer,
        ThrowingInspectionProperty throwingProperty)
        : INearbySecureSession
    {
        private readonly NearbyAuthenticatedPeer authenticatedPeer = new TestSecureSession(
            NearbySessionRole.Initiator,
            peer,
            ValidationTime).Peer;
        private int disposeCount;

        public int DisposeCount => Volatile.Read(ref disposeCount);

        public NearbyAuthenticatedPeer Peer => throwingProperty == ThrowingInspectionProperty.Peer
            ? throw new InvalidOperationException("test inspection failure")
            : authenticatedPeer;

        public NearbySessionRole LocalRole => throwingProperty == ThrowingInspectionProperty.Role
            ? throw new InvalidOperationException("test inspection failure")
            : NearbySessionRole.Initiator;

        public NearbyRecordDirection SendDirection =>
            throwingProperty == ThrowingInspectionProperty.SendDirection
                ? throw new InvalidOperationException("test inspection failure")
                : NearbyRecordDirection.InitiatorToResponder;

        public NearbyRecordDirection ReceiveDirection =>
            throwingProperty == ThrowingInspectionProperty.ReceiveDirection
                ? throw new InvalidOperationException("test inspection failure")
                : NearbyRecordDirection.ResponderToInitiator;

        public byte[] Seal(NearbyRecordKind kind, ReadOnlySpan<byte> plaintext) =>
            throw new NotSupportedException();

        public NearbyOpenedRecord Open(ReadOnlySpan<byte> record) =>
            throw new NotSupportedException();

        public void Dispose() => Interlocked.Increment(ref disposeCount);
    }
}
