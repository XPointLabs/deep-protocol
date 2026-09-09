using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.GroupV1;
using Sodium;

namespace Deep.Protocol.Tests.DeepExtension.PrivacyRouting;

public sealed class PrivacyRoutingContractTests
{
    [Fact]
    public void FrozenPositiveVector_ProducesExactXrf1Frames()
    {
        using var fixture = new OnionFixture();
        using var built = PrivacyRoutingValidationBuilder.BuildFrozenKatVector(fixture.Network, fixture.Route, PrivacyRoutingOperation.Store, Array.Empty<byte>(), fixture.Entropy, 256);
        using var vectorExit = PrivacyRoutingValidationBuilder.OpenExactRoute(built.Frame.Span, fixture.ReceiveKeys);
        Assert.Equal("FFC951AA6F2FA03096D1D1B579735B2F6F84019FE2F617AA65FF3D68705F2527", Convert.ToHexString(vectorExit.ReplyPublicKey.Span));
        Assert.Equal("XRF1", System.Text.Encoding.ASCII.GetString(built.Frame.Span[..4]));
        Assert.Equal("D173EACEBB01753F3B19D6CF1A5C6046B9449ED17FBAA9889766D9ED83B7D30F", Convert.ToHexString(vectorExit.OperationId.Span));
        Assert.Equal(1024, built.Frame.Length);
        using var ingress = Assert.IsType<PrivacyRoutingRelayLayer>(PrivacyRoutingValidationBuilder.OpenRequest(built.Frame.Span, fixture.ReceiveKeys[0]));
        Assert.Equal(768, ingress.InnerFrame.Length);
        using var core = Assert.IsType<PrivacyRoutingRelayLayer>(PrivacyRoutingValidationBuilder.OpenRequest(ingress.InnerFrame.Span, fixture.ReceiveKeys[1]));
        Assert.Equal(512, core.InnerFrame.Length);
        Assert.Equal("24787A0697601F4F449E0BFEF3C377A9D2FA2690BA6C2459E3C5C4C4E8F52686", Convert.ToHexString(SHA256.HashData(core.InnerFrame.Span)));
        Assert.Equal("9A18E3EEA0C86428B8F39DE4FD5C00F094FCF718E40DABC817E0595AF13A7C84", Convert.ToHexString(SHA256.HashData(ingress.InnerFrame.Span)));
        Assert.Equal("EDC09617CF81F4B21F9119D4D0EB91FF2316E6AD33C727C028617025E9241C96", Convert.ToHexString(SHA256.HashData(built.Frame.Span)));
        using var exit = Assert.IsType<PrivacyRoutingExitLayer>(PrivacyRoutingValidationBuilder.OpenRequest(core.InnerFrame.Span, fixture.ReceiveKeys[2], allowFrozenKatMailboxPayload: true));
        var response = PrivacyRoutingValidationBuilder.SealResponse(exit, PrivacyRoutingTerminalResult.Failure(PrivacyRoutingOperation.Store, PrivacyRoutingFailureCode.Unavailable), fixture.Entropy, 256);
        Assert.Equal(512, response.Length);
        Assert.Equal("2ED416644EF1B390482C4466C720CAFDACFE551CCBA8670A7B1884EFF5964199", Convert.ToHexString(SHA256.HashData(response)));
        var opened = PrivacyRoutingValidationBuilder.OpenResponse(response, built.ReplyContext);
        Assert.Equal(PrivacyRoutingFailureCode.Unavailable, opened.Result.FailureCode);
        Assert.Throws<PrivacyRoutingProtocolException>(() => PrivacyRoutingValidationBuilder.OpenResponse(response, built.ReplyContext));
    }

    [Theory]
    [MemberData(nameof(HostileIds))]
    public void AllFrozenHostileClasses_RejectWithoutReplayMutation(string id)
    {
        using var fixture = new OnionFixture();
        using var built = PrivacyRoutingValidationBuilder.BuildFrozenKatVector(fixture.Network, fixture.Route, PrivacyRoutingOperation.Store, Array.Empty<byte>(), fixture.Entropy, 256);
        var store = new CountingReplayStore();
        var frame = built.Frame.ToArray();
        if (id.StartsWith("legacy-", StringComparison.Ordinal)) frame.AsSpan(0, 4).Fill((byte)'D');
        else if (id == "xrf1-zero-public-or-shared-secret") frame.AsSpan(100, 32).Clear();
        else if (id == "xrf1-associated-data-tamper") frame[132] ^= 1;
        else if (id == "xrf1-header-version-suite-reserved") frame[9] = 1;
        else if (id == "xrf1-purpose-layer-combination") frame[8] = 3;
        else if (id == "xrf1-ciphertext-length-trailing") BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(156), 16);
        else if (id == "xrf1-network-owner-epoch-key-substitution") frame[68] ^= 1;
        else if (id == "trusted-time-overlap-expiry-retirement") { fixture.ReceiveKeys[0].Dispose(); }
        else if (id == "replay-before-forward-or-eviction") { Assert.IsType<PrivacyRoutingRelayLayer>(PrivacyRoutingValidationBuilder.OpenRequest(frame, fixture.ReceiveKeys[0], store)); }
        else if (id == "fourth-nested-request-frame") frame = FourthHopFrame(fixture, frame);
        else if (id is "xrl1-noncanonical-inner-owner" or "xre1-operation-domain-attempt-substitution" or "padding-exponent-length-or-nonzero" or "reply-owner-key-operation-attempt-mismatch") frame[^1] ^= 0x80;

        if (id == "fourth-nested-request-frame")
            Assert.Throws<PrivacyRoutingProtocolException>(() => PrivacyRoutingValidationBuilder.OpenExactRoute(frame, fixture.ReceiveKeys));
        else
            Assert.Throws<PrivacyRoutingProtocolException>(() => PrivacyRoutingValidationBuilder.OpenRequest(frame, fixture.ReceiveKeys[0], store));
        Assert.Equal(id == "replay-before-forward-or-eviction" ? 1 : 0, store.Count);
    }

    [Fact]
    public void InternalPreproductionCodec_UsesCSPRNG_RequiredReplay_AndSingleUseReplyState()
    {
        using var fixture = new OnionFixture();
        Assert.False(PrivacyRoutingCodec.RuntimeActivation);
        var mau2 = MailboxRequest(MailboxAuthenticatedOperation.Retrieve, fixture.Network);
        using var firstBuilt = PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route, PrivacyRoutingOperation.Retrieve, mau2, 256);
        using var secondBuilt = PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route, PrivacyRoutingOperation.Retrieve, mau2, 256);
        Assert.NotEqual(Convert.ToHexString(firstBuilt.Frame.Span), Convert.ToHexString(secondBuilt.Frame.Span));

        var replay = new CountingReplayStore();
        using var ingress = Assert.IsType<PrivacyRoutingRelayLayer>(PrivacyRoutingRequestCodec.Open(firstBuilt.Frame.Span, fixture.ReceiveKeys[0], replay));
        using var core = Assert.IsType<PrivacyRoutingRelayLayer>(PrivacyRoutingRequestCodec.Open(ingress.InnerFrame.Span, fixture.ReceiveKeys[1], replay));
        using var exit = Assert.IsType<PrivacyRoutingExitLayer>(PrivacyRoutingRequestCodec.Open(core.InnerFrame.Span, fixture.ReceiveKeys[2], replay));
        Assert.Equal(3, replay.Count);
        Assert.Equal(
            [PrivacyRoutingReceivePosition.Ingress, PrivacyRoutingReceivePosition.Core, PrivacyRoutingReceivePosition.Exit],
            replay.Scopes.Select(static scope => scope.Position).ToArray());
        for (var index = 0; index < replay.Scopes.Count; index++)
        {
            Assert.Equal(fixture.Network, replay.Scopes[index].NetworkId.ToArray());
            Assert.Equal(fixture.Route[index].RouterOwnerId.ToArray(), replay.Scopes[index].OwnerId.ToArray());
            Assert.Equal(fixture.Route[index].KeyId.ToArray(), replay.Scopes[index].KeyId.ToArray());
            Assert.Equal(fixture.Route[index].Epoch, replay.Scopes[index].Epoch);
        }
        Assert.Equal(PrivacyRoutingProtocolError.ReplayRejected, Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingRequestCodec.Open(firstBuilt.Frame.Span, fixture.ReceiveKeys[0], replay)).Error);
        Assert.Equal(3, replay.Count);

        var response = PrivacyRoutingResponseCodec.Seal(exit, PrivacyRoutingTerminalResult.Failure(PrivacyRoutingOperation.Retrieve, PrivacyRoutingFailureCode.Unavailable), 256);
        var opened = PrivacyRoutingResponseCodec.Open(response, firstBuilt.ReplyContext);
        Assert.Equal(PrivacyRoutingFailureCode.Unavailable, opened.Result.FailureCode);
        Assert.Equal(PrivacyRoutingProtocolError.ReplyContextDisposed, Assert.Throws<PrivacyRoutingProtocolException>(() => PrivacyRoutingResponseCodec.Open(response, firstBuilt.ReplyContext)).Error);
        Assert.Equal(PrivacyRoutingProtocolError.ReplyContextDisposed, Assert.Throws<PrivacyRoutingProtocolException>(() => PrivacyRoutingResponseCodec.Seal(exit, PrivacyRoutingTerminalResult.Failure(PrivacyRoutingOperation.Retrieve, PrivacyRoutingFailureCode.Unavailable), 256)).Error);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void InternalBuilder_RejectsNonMau2MailboxPayload(int operationValue)
    {
        using var fixture = new OnionFixture();
        var operation = (PrivacyRoutingOperation)operationValue;
        var error = Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route, operation, Array.Empty<byte>(), 256));
        Assert.Equal(PrivacyRoutingProtocolError.InvalidOperation, error.Error);
    }

    [Fact]
    public void InternalBuilder_RejectsMau2OperationAndNetworkSubstitution()
    {
        using var fixture = new OnionFixture();
        var store = MailboxRequest(MailboxAuthenticatedOperation.Store, fixture.Network);
        Assert.Equal(
            PrivacyRoutingProtocolError.InvalidOperation,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route, PrivacyRoutingOperation.Retrieve, store, 256)).Error);

        var otherNetwork = fixture.Network.ToArray();
        otherNetwork[0] ^= 0x80;
        var crossNetwork = MailboxRequest(MailboxAuthenticatedOperation.Store, otherNetwork);
        Assert.Equal(
            PrivacyRoutingProtocolError.InvalidKeyBinding,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route, PrivacyRoutingOperation.Store, crossNetwork, 256)).Error);
    }

    [Theory]
    [InlineData(MailboxAuthenticatedOperation.Store, 1)]
    [InlineData(MailboxAuthenticatedOperation.Retrieve, 2)]
    [InlineData(MailboxAuthenticatedOperation.Ack, 3)]
    public void InternalResponseSeal_RejectsArbitraryMailboxSuccess(
        MailboxAuthenticatedOperation mailboxOperation,
        int onionOperationValue)
    {
        using var fixture = new OnionFixture();
        var onionOperation = (PrivacyRoutingOperation)onionOperationValue;
        var mau2 = MailboxRequest(mailboxOperation, fixture.Network);
        using var built = PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route, onionOperation, mau2, 256);
        var replay = new CountingReplayStore();
        using var exit = OpenPublicExit(built.Frame.Span, fixture.ReceiveKeys, replay);

        var error = Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingResponseCodec.Seal(exit, PrivacyRoutingTerminalResult.Success(onionOperation, "not-a-canonical-result"u8), 256));
        Assert.Equal(PrivacyRoutingProtocolError.InvalidOperation, error.Error);
    }

    [Fact]
    public void RetrieveResponse_IsExactBoundMrp1_AndInvalidAttemptDoesNotConsumeExitState()
    {
        using var fixture = new OnionFixture();
        var mau2 = MailboxRequest(MailboxAuthenticatedOperation.Retrieve, fixture.Network);
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(mau2);
        using var built = PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route, PrivacyRoutingOperation.Retrieve, mau2, 256);
        using var exit = OpenPublicExit(built.Frame.Span, fixture.ReceiveKeys, new CountingReplayStore());

        Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingResponseCodec.Seal(exit, PrivacyRoutingTerminalResult.Success(PrivacyRoutingOperation.Retrieve, "MRP1"u8), 256));
        var wrongMrp1 = MailboxClientCodec.EncodeRetrievePage(new MailboxRetrievePage
        {
            Epoch = decoded.Presentation.Grant.Epoch,
            OperationId = Range(0x41, 16),
            NextCursor = 0,
            HasMore = false,
            ContinuationToken = ReadOnlyMemory<byte>.Empty,
            Items = []
        });
        Assert.Equal(PrivacyRoutingProtocolError.ReplyContextMismatch, Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingResponseCodec.Seal(exit, PrivacyRoutingTerminalResult.Success(PrivacyRoutingOperation.Retrieve, wrongMrp1), 256)).Error);
        var mrp1 = MailboxClientCodec.EncodeRetrievePage(new MailboxRetrievePage
        {
            Epoch = decoded.Presentation.Grant.Epoch,
            OperationId = decoded.Binding.OperationId,
            NextCursor = 0,
            HasMore = false,
            ContinuationToken = ReadOnlyMemory<byte>.Empty,
            Items = []
        });
        var response = PrivacyRoutingResponseCodec.Seal(exit, PrivacyRoutingTerminalResult.Success(PrivacyRoutingOperation.Retrieve, mrp1), 256);
        var opened = PrivacyRoutingResponseCodec.Open(response, built.ReplyContext);
        Assert.Equal(mrp1, opened.Payload.ToArray());
    }

    [Theory]
    [InlineData(MailboxAuthenticatedOperation.Store, 1)]
    [InlineData(MailboxAuthenticatedOperation.Ack, 3)]
    public void StoreAndAcknowledgeSuccess_AreExactAndRequestBound(
        MailboxAuthenticatedOperation mailboxOperation,
        int onionOperationValue)
    {
        using var fixture = new OnionFixture();
        var onionOperation = (PrivacyRoutingOperation)onionOperationValue;
        var mau2 = MailboxRequest(mailboxOperation, fixture.Network);
        using var built = PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route, onionOperation, mau2, 256);
        using var exit = OpenPublicExit(built.Frame.Span, fixture.ReceiveKeys, new CountingReplayStore());

        var wrong = MailboxQuorumResult(mau2, mailboxOperation, wrongOperationId: true);
        Assert.Equal(PrivacyRoutingProtocolError.ReplyContextMismatch, Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingResponseCodec.Seal(exit, PrivacyRoutingTerminalResult.Success(onionOperation, wrong), 256)).Error);
        var exact = MailboxQuorumResult(mau2, mailboxOperation, wrongOperationId: false);
        var response = PrivacyRoutingResponseCodec.Seal(exit, PrivacyRoutingTerminalResult.Success(onionOperation, exact), 256);
        Assert.Equal(exact, PrivacyRoutingResponseCodec.Open(response, built.ReplyContext).Payload.ToArray());
    }

    [Fact]
    public void ContactResolve_IsExplicitBoundedTerminalOperation()
    {
        using var fixture = new OnionFixture();
        var request = ContactQuery(fixture.Network);
        using var built = PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route, PrivacyRoutingOperation.ContactResolve, request, 256);
        using var exit = OpenPublicExit(built.Frame.Span, fixture.ReceiveKeys, new CountingReplayStore());
        Assert.Equal(PrivacyRoutingOperation.ContactResolve, exit.Operation);
        Assert.Equal(request, exit.Payload.ToArray());

        var result = Xis1Codec.Encode(request, Xis1Status.NotFound, ContactServiceMutationOutcome.None, 50, 0, ContactServicePaddingClass.Bytes256, []);
        var response = PrivacyRoutingResponseCodec.Seal(exit, PrivacyRoutingTerminalResult.Success(PrivacyRoutingOperation.ContactResolve, result), 256);
        var opened = PrivacyRoutingResponseCodec.Open(response, built.ReplyContext);
        Assert.Equal(PrivacyRoutingOperation.ContactResolve, opened.Operation);
        Assert.Equal(result, opened.Payload.ToArray());
    }

    [Fact]
    public void ContactResolve_RejectsWrongNetworkUnknownRequestAndMismatchedResult()
    {
        using var fixture = new OnionFixture();
        var otherNetwork = fixture.Network.ToArray();
        otherNetwork[0] ^= 0x80;
        var crossNetwork = ContactQuery(otherNetwork);
        Assert.Equal(PrivacyRoutingProtocolError.InvalidKeyBinding, Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route, PrivacyRoutingOperation.ContactResolve, crossNetwork, 256)).Error);
        Assert.Equal(PrivacyRoutingProtocolError.InvalidOperation, Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route, PrivacyRoutingOperation.ContactResolve, "HTTP"u8, 256)).Error);

        var request = ContactQuery(fixture.Network);
        using var built = PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route, PrivacyRoutingOperation.ContactResolve, request, 256);
        using var exit = OpenPublicExit(built.Frame.Span, fixture.ReceiveKeys, new CountingReplayStore());
        var differentRequest = Xiq1Codec.Encode(fixture.Network, Range(0x31, 32), Range(0x32, 32), Range(0x33, 32), 10, 100, Range(0x34, 32), 0, Xiq1AntiSpamTokenType.None, [], ContactServicePaddingClass.Bytes256);
        var wrongResult = Xis1Codec.Encode(differentRequest, Xis1Status.NotFound, ContactServiceMutationOutcome.None, 50, 0, ContactServicePaddingClass.Bytes256, []);
        Assert.Equal(PrivacyRoutingProtocolError.InvalidOperation, Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingResponseCodec.Seal(exit, PrivacyRoutingTerminalResult.Success(PrivacyRoutingOperation.ContactResolve, wrongResult), 256)).Error);
        var exactResult = Xis1Codec.Encode(request, Xis1Status.NotFound, ContactServiceMutationOutcome.None, 50, 0, ContactServicePaddingClass.Bytes256, []);
        var response = PrivacyRoutingResponseCodec.Seal(exit, PrivacyRoutingTerminalResult.Success(PrivacyRoutingOperation.ContactResolve, exactResult), 256);
        Assert.Equal(exactResult, PrivacyRoutingResponseCodec.Open(response, built.ReplyContext).Payload.ToArray());
    }

    [Fact]
    public void GroupControl_IsDistinctExactBoundOnionOperation()
    {
        using var fixture = new OnionFixture();
        var request = GroupWrite(fixture.Network);
        using var built = PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(
            fixture.Network, fixture.Route, PrivacyRoutingOperation.GroupControl, request, 256);
        using var exit = OpenPublicExit(built.Frame.Span, fixture.ReceiveKeys, new CountingReplayStore());
        Assert.Equal(5, (byte)exit.Operation);
        Assert.Equal(request, exit.Payload.ToArray());

        var exact = GroupWriteResult(request);
        var response = PrivacyRoutingResponseCodec.Seal(exit,
            PrivacyRoutingTerminalResult.Success(PrivacyRoutingOperation.GroupControl, exact), 256);
        var opened = PrivacyRoutingResponseCodec.Open(response, built.ReplyContext);
        Assert.Equal(PrivacyRoutingOperation.GroupControl, opened.Operation);
        Assert.Equal(exact, opened.Payload.ToArray());
    }

    [Fact]
    public void GroupControl_RejectsOperationSmugglingAndRequestResultSubstitution()
    {
        using var fixture = new OnionFixture();
        var write = GroupWrite(fixture.Network);
        Assert.Equal(PrivacyRoutingProtocolError.InvalidOperation, Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route,
                PrivacyRoutingOperation.ContactResolve, write, 256)).Error);
        Assert.Equal(PrivacyRoutingProtocolError.InvalidOperation, Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(fixture.Network, fixture.Route,
                PrivacyRoutingOperation.GroupControl, ContactQuery(fixture.Network), 256)).Error);

        using var built = PrivacyRoutingRequestBuilder.BuildForCanonicalRequest(
            fixture.Network, fixture.Route, PrivacyRoutingOperation.GroupControl, write, 256);
        using var exit = OpenPublicExit(built.Frame.Span, fixture.ReceiveKeys, new CountingReplayStore());
        var result = GroupWriteResult(write);
        result[GroupFieldOffset(result, 3)] ^= 0x80;
        Assert.Equal(PrivacyRoutingProtocolError.ReplyContextMismatch, Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingResponseCodec.Seal(exit,
                PrivacyRoutingTerminalResult.Success(PrivacyRoutingOperation.GroupControl, result), 256)).Error);
    }

    [Fact]
    public void PublicSurface_HasNoRuntimeRawKeyReplayOrEntropyBypass()
    {
        Assert.False(PrivacyRoutingCodec.RuntimeActivation);
        var exported = typeof(PrivacyRoutingCodec).Assembly.GetExportedTypes()
            .Where(type => type.Namespace == typeof(PrivacyRoutingCodec).Namespace)
            .ToArray();
        Assert.DoesNotContain(exported, type => type.Name is
            nameof(PrivacyRoutingHop) or
            nameof(PrivacyRoutingReceiveKey) or
            nameof(PrivacyRoutingTestEntropy) or
            nameof(IPrivacyRoutingReplayStateStore));
        Assert.DoesNotContain(typeof(PrivacyRoutingCodec).GetMethods(
                System.Reflection.BindingFlags.Public |
                System.Reflection.BindingFlags.Instance |
                System.Reflection.BindingFlags.DeclaredOnly)
            .SelectMany(static method => method.GetParameters()), parameter =>
            parameter.ParameterType.Name.Contains("Hop", StringComparison.Ordinal) ||
            parameter.ParameterType.Name.Contains("Private", StringComparison.Ordinal) ||
            parameter.IsOptional);
    }

    [Fact]
    public void Relay_RejectsCrossNetworkInnerFrameBeforeReplayMutation()
    {
        using var fixture = new OnionFixture();
        var store = new CountingReplayStore();
        var frame = CrossNetworkSpliceFrame(fixture);

        var error = Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingValidationBuilder.OpenRequest(frame, fixture.ReceiveKeys[0], store));

        Assert.Equal(PrivacyRoutingProtocolError.InvalidKeyBinding, error.Error);
        Assert.Equal(0, store.Count);
    }

    public static IEnumerable<object[]> HostileIds => new[]
    {
        "legacy-drf1","legacy-drl1","legacy-dre1","legacy-dpr1","legacy-drs1","xrf1-header-version-suite-reserved","xrf1-purpose-layer-combination","xrf1-ciphertext-length-trailing","xrf1-network-owner-epoch-key-substitution","xrf1-zero-public-or-shared-secret","xrf1-associated-data-tamper","xrl1-noncanonical-inner-owner","xre1-operation-domain-attempt-substitution","padding-exponent-length-or-nonzero","fourth-nested-request-frame","replay-before-forward-or-eviction","reply-owner-key-operation-attempt-mismatch","trusted-time-overlap-expiry-retirement"
    }.Select(static id => new object[] { id });

    private static byte[] FourthHopFrame(OnionFixture fixture, ReadOnlySpan<byte> inner)
    {
        var plain = new byte[80 + inner.Length];
        "XRL1"u8.CopyTo(plain); plain[4] = plain[5] = plain[6] = 1; Enumerable.Repeat((byte)0x90, 32).ToArray().CopyTo(plain, 8); fixture.Route[0].RouterOwnerId.Span.CopyTo(plain.AsSpan(40)); BinaryPrimitives.WriteUInt32BigEndian(plain.AsSpan(72), (uint)inner.Length); plain[76] = 8; inner.CopyTo(plain.AsSpan(80));
        try { return PrivacyRoutingWire.SealEnvelope(plain, fixture.Network, fixture.Route[0].RouterOwnerId.Span, 7, fixture.Route[0].KeyId.Span, 1, 1, fixture.Route[0].X25519PublicKey.Span, Enumerable.Repeat((byte)0x75, 32).ToArray(), Enumerable.Repeat((byte)0x85, 24).ToArray()); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    private static byte[] CrossNetworkSpliceFrame(OnionFixture fixture)
    {
        var otherNetwork = fixture.Network.ToArray();
        otherNetwork[0] ^= 0x80;
        var innerPlain = new byte[144];
        var innerEphemeral = Enumerable.Repeat((byte)0x76, 32).ToArray();
        var innerNonce = Enumerable.Repeat((byte)0x86, 24).ToArray();
        var outerEphemeral = Enumerable.Repeat((byte)0x77, 32).ToArray();
        var outerNonce = Enumerable.Repeat((byte)0x87, 24).ToArray();
        byte[]? inner = null;
        byte[]? outerPlain = null;
        try
        {
            inner = PrivacyRoutingWire.SealEnvelope(innerPlain, otherNetwork, fixture.Route[1].RouterOwnerId.Span, fixture.Route[1].Epoch, fixture.Route[1].KeyId.Span, 1, 2, fixture.Route[1].X25519PublicKey.Span, innerEphemeral, innerNonce);
            var padding = PrivacyRoutingWire.Padding(80, inner.Length, 256);
            outerPlain = new byte[80 + inner.Length + padding];
            "XRL1"u8.CopyTo(outerPlain);
            outerPlain[4] = outerPlain[5] = outerPlain[6] = 1;
            Enumerable.Repeat((byte)0x91, 32).ToArray().CopyTo(outerPlain, 8);
            fixture.Route[1].RouterOwnerId.Span.CopyTo(outerPlain.AsSpan(40));
            BinaryPrimitives.WriteUInt32BigEndian(outerPlain.AsSpan(72), (uint)inner.Length);
            outerPlain[76] = PrivacyRoutingWire.PaddingExponent(256);
            PrivacyRoutingWire.WriteU24(outerPlain.AsSpan(77), padding);
            inner.CopyTo(outerPlain, 80);
            return PrivacyRoutingWire.SealEnvelope(outerPlain, fixture.Network, fixture.Route[0].RouterOwnerId.Span, fixture.Route[0].Epoch, fixture.Route[0].KeyId.Span, 1, 1, fixture.Route[0].X25519PublicKey.Span, outerEphemeral, outerNonce);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(otherNetwork);
            CryptographicOperations.ZeroMemory(innerPlain);
            CryptographicOperations.ZeroMemory(innerEphemeral);
            CryptographicOperations.ZeroMemory(innerNonce);
            CryptographicOperations.ZeroMemory(outerEphemeral);
            CryptographicOperations.ZeroMemory(outerNonce);
            if (inner is not null) CryptographicOperations.ZeroMemory(inner);
            if (outerPlain is not null) CryptographicOperations.ZeroMemory(outerPlain);
        }
    }

    private static PrivacyRoutingExitLayer OpenPublicExit(
        ReadOnlySpan<byte> frame,
        IReadOnlyList<PrivacyRoutingReceiveKey> keys,
        IPrivacyRoutingReplayStateStore replay)
    {
        using var ingress = Assert.IsType<PrivacyRoutingRelayLayer>(PrivacyRoutingRequestCodec.Open(frame, keys[0], replay));
        using var core = Assert.IsType<PrivacyRoutingRelayLayer>(PrivacyRoutingRequestCodec.Open(ingress.InnerFrame.Span, keys[1], replay));
        return Assert.IsType<PrivacyRoutingExitLayer>(PrivacyRoutingRequestCodec.Open(core.InnerFrame.Span, keys[2], replay));
    }

    private static byte[] ContactQuery(ReadOnlySpan<byte> network) =>
        Xiq1Codec.Encode(
            network,
            Range(0x21, 32),
            Range(0x41, 32),
            Range(0x61, 32),
            10,
            100,
            Range(0x81, 32),
            0,
            Xiq1AntiSpamTokenType.None,
            [],
            ContactServicePaddingClass.Bytes256);

    private static byte[] GroupWrite(ReadOnlySpan<byte> network)
    {
        var sealedRecord = Range(0x11, 64);
        return GroupRecord("GSW1", [1,2,3,4,5,6,16,17,18,19,20,21,22],
            [network.ToArray(), Range(0x21,32), Range(0x41,32), Range(0x61,32), U64(10), U64(20),
             Range(0x81,32), Range(0xa1,32), U64(1), new byte[32], SHA256.HashData(sealedRecord),
             Lp32(sealedRecord), U64(30)]);
    }

    private static byte[] GroupWriteResult(ReadOnlySpan<byte> request)
    {
        var decoded = Assert.IsType<GroupControlWriteRecord>(GroupCodec.Decode(request));
        return GroupRecord("GSS1", [1,2,3,4,5,6,7,8,16,17,18,19,20],
            [decoded.Field(1).ToArray(), decoded.Field(2).ToArray(),
             ContactCodec.Sha256Domain("Deep/ContactResolver/V1/request", request), U16(1), new byte[]{1},
             U64(15), U32(0), U16(4), new byte[]{1}, decoded.Field(18).ToArray(),
             decoded.Field(20).ToArray(), U64(1), Range(0xc0,96)]);
    }

    private static byte[] GroupRecord(string magic, IReadOnlyList<int> tags, IReadOnlyList<byte[]> fields)
    {
        var bytes = new byte[checked(12 + fields.Sum(field => 8 + field.Length))];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count));
        var at = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(at), checked((ushort)tags[index]));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(at + 4), checked((uint)fields[index].Length));
            at += 8; fields[index].CopyTo(bytes, at); at += fields[index].Length;
        }
        return GroupCodec.Decode(magic, bytes).CanonicalBytes.ToArray();
    }

    private static int GroupFieldOffset(ReadOnlySpan<byte> record, int wantedTag)
    {
        var at = 12; var count = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(8, 2));
        for (var index = 0; index < count; index++)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(at, 2));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(record.Slice(at + 4, 4)));
            at += 8; if (tag == wantedTag) return at; at += length;
        }
        throw new ArgumentOutOfRangeException(nameof(wantedTag));
    }

    private static byte[] U16(ushort value) { var result = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(result, value); return result; }
    private static byte[] U32(uint value) { var result = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(result, value); return result; }
    private static byte[] U64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
    private static byte[] Lp32(ReadOnlySpan<byte> value) { var result = new byte[value.Length + 4]; BinaryPrimitives.WriteUInt32BigEndian(result, checked((uint)value.Length)); value.CopyTo(result.AsSpan(4)); return result; }

    private static byte[] MailboxRequest(MailboxAuthenticatedOperation operation, ReadOnlySpan<byte> network)
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuerSeed = Range(0x10, 32);
        var holderSeed = Range(0x40, 32);
        var domain = operation == MailboxAuthenticatedOperation.Store
            ? MailboxCapabilityDomain.Deposit
            : MailboxCapabilityDomain.Retrieve;
        var grant = crypto.SignGrant(new MailboxAuthenticatedGrant
        {
            Domain = domain,
            Lifecycle = MailboxCapabilityLifecycle.Active,
            NetworkId = network.ToArray(),
            Epoch = 11,
            Generation = 7,
            Serial = Range(0x80, 16),
            NotBeforeUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1100,
            OverlapUntilUnixSeconds = 0,
            PlacementCommitment = MailboxPlacementCommitment.Compute(new BlindedPlacementId(Range(0x90, 32))),
            MembershipCommitment = Range(0xb0, 32),
            IssuerPublicKey = crypto.GetPublicKey(issuerSeed),
            HolderPublicKey = crypto.GetPublicKey(holderSeed),
            IssuerSignature = ReadOnlyMemory<byte>.Empty
        }, issuerSeed);
        var binding = operation switch
        {
            MailboxAuthenticatedOperation.Store => MailboxAuthenticatedRequestTranscript.ForStore(new MailboxEncryptedEnvelope
            {
                Epoch = 11,
                MailboxId = new BlindedMailboxId(Range(0x20, 32)),
                PlacementId = new BlindedPlacementId(Range(0x90, 32)),
                OperationId = Range(0xd0, 16),
                DeduplicationDigest = Range(0xe0, 32),
                CreatedAtUnixSeconds = 1000,
                ExpiresAtUnixSeconds = 1060,
                Ciphertext = Range(0x01, 64)
            }),
            MailboxAuthenticatedOperation.Retrieve => MailboxAuthenticatedRequestTranscript.ForRetrieve(
                11, Range(0xd0, 16), new BlindedMailboxId(Range(0x20, 32)), new BlindedPlacementId(Range(0x90, 32)), 42, 10, Range(1, 8)),
            MailboxAuthenticatedOperation.Ack => MailboxAuthenticatedRequestTranscript.ForAck(
                11, Range(0xd0, 16), new BlindedMailboxId(Range(0x20, 32)), new BlindedPlacementId(Range(0x90, 32)), true, [],
                [new MailboxAcknowledgement { Cursor = 42, EnvelopeDigest = Range(0xe0, 32) }]),
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };
        return MailboxAuthenticatedClientRequestCodec.Encode(new MailboxAuthenticatedClientRequest
        {
            Binding = binding,
            Presentation = crypto.SignPresentation(grant, binding, 9, holderSeed)
        });
    }

    private static byte[] MailboxQuorumResult(
        ReadOnlySpan<byte> exactMau2,
        MailboxAuthenticatedOperation operation,
        bool wrongOperationId)
    {
        var request = MailboxAuthenticatedClientRequestCodec.Decode(exactMau2);
        var operationId = wrongOperationId ? Range(0x31, 16) : request.Binding.OperationId.ToArray();
        ReadOnlyMemory<byte> mailboxId;
        ReadOnlyMemory<byte> envelopeDigest;
        ulong cursor;
        MailboxReplicaDisposition disposition;
        if (operation == MailboxAuthenticatedOperation.Store)
        {
            var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Binding.CanonicalRequest.Span);
            mailboxId = body.MailboxId.Bytes;
            envelopeDigest = body.DeduplicationDigest;
            cursor = 42;
            disposition = MailboxReplicaDisposition.Stored;
        }
        else
        {
            var body = MailboxAuthenticatedRequestTranscript.DecodeAckBody(request.Binding.CanonicalRequest.Span);
            mailboxId = body.MailboxId.Bytes;
            envelopeDigest = body.Acknowledgements[0].EnvelopeDigest;
            cursor = body.Acknowledgements[0].Cursor;
            disposition = MailboxReplicaDisposition.Tombstone;
        }

        MailboxReplicaReceiptV2 Replica(byte id) => new()
        {
            Status = MailboxReceiptStatus.Durable,
            Disposition = disposition,
            ReplicaId = Enumerable.Repeat(id, 32).ToArray(),
            OperationId = operationId,
            Epoch = request.Presentation.Grant.Epoch,
            Cursor = cursor,
            AcceptedAtUnixSeconds = 1001,
            DurableAtUnixSeconds = 1002,
            ExpiresAtUnixSeconds = 1060,
            BlindedMailboxId = mailboxId,
            PlacementCommitment = request.Presentation.Grant.PlacementCommitment,
            MembershipCommitment = request.Presentation.Grant.MembershipCommitment,
            EnvelopeDigest = envelopeDigest,
            Signature = Range(id, 64)
        };

        var quorum = MailboxReceiptV3Codec.EncodeDurableQuorum(new MailboxDurableQuorumReceiptV3
        {
            CoordinatorId = Range(0x51, 32),
            CoordinatorSequence = 1,
            FirstReplica = Replica(0x11),
            SecondReplica = Replica(0x22),
            Signature = Range(0x71, 64)
        });
        if (operation == MailboxAuthenticatedOperation.Store) return quorum;
        return MailboxAggregateAckCodec.EncodeMqr3(new MailboxAggregateAckResponse
        {
            Epoch = request.Presentation.Grant.Epoch,
            OperationId = operationId,
            TombstoneQuorums = [quorum]
        });
    }

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => unchecked((byte)value)).ToArray();

    private sealed class CountingReplayStore : IPrivacyRoutingReplayStateStore
    {
        private readonly PrivacyRoutingReplayWindow _window = new(8);
        public int Count { get; private set; }
        public List<PrivacyRoutingReplayScope> Scopes { get; } = [];
        public PrivacyRoutingReplayResult TryAccept(PrivacyRoutingReplayScope scope, ReadOnlySpan<byte> replayId)
        {
            var result = _window.TryAccept(replayId);
            if (result == PrivacyRoutingReplayResult.Accepted)
            {
                Count++;
                Scopes.Add(scope);
            }
            return result;
        }
    }

    private sealed class OnionFixture : IDisposable
    {
        internal OnionFixture()
        {
            Network = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
            var scalars = new[] { 0x31, 0x32, 0x33 }.Select(x => Enumerable.Repeat((byte)x, 32).ToArray()).ToArray();
            Route = new[] { 0x11, 0x22, 0x33 }.Select((x, i) => new PrivacyRoutingHop(Enumerable.Repeat((byte)x, 32).ToArray(), Enumerable.Repeat((byte)(0xa1 + i), 32).ToArray(), 7, i == 2 ? PrivacyRoutingKeyRole.Exit : PrivacyRoutingKeyRole.Relay, ScalarMult.Base(scalars[i]))).ToArray();
            ReceiveKeys = Route.Select((hop, i) => new PrivacyRoutingReceiveKey(Network, hop.RouterOwnerId.Span, hop.KeyId.Span, hop.Epoch, (PrivacyRoutingReceivePosition)(i + 1), scalars[i], i < 2 ? Route[i + 1] : null)).ToArray();
            Entropy = new PrivacyRoutingTestEntropy { AttemptId = Enumerable.Repeat((byte)0x55, 32).ToArray(), ReplayIds = new[] { 0x63, 0x62, 0x61 }.Select(x => Enumerable.Repeat((byte)x, 32).ToArray()).ToArray(), ReplyPrivateScalar = Enumerable.Repeat((byte)0x34, 32).ToArray(), RequestEphemeralPrivateScalars = new[] { 0x71, 0x72, 0x73 }.Select(x => Enumerable.Repeat((byte)x, 32).ToArray()).ToArray(), RequestNonces = new[] { 0x81, 0x82, 0x83 }.Select(x => Enumerable.Repeat((byte)x, 24).ToArray()).ToArray(), ResponseEphemeralPrivateScalar = Enumerable.Repeat((byte)0x74, 32).ToArray(), ResponseNonce = Enumerable.Repeat((byte)0x84, 24).ToArray() };
        }
        internal byte[] Network { get; } internal PrivacyRoutingHop[] Route { get; } internal PrivacyRoutingReceiveKey[] ReceiveKeys { get; } internal PrivacyRoutingTestEntropy Entropy { get; }
        public void Dispose() { foreach (var key in ReceiveKeys) key.Dispose(); Entropy.Dispose(); }
    }
}
