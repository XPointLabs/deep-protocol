using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.ManagedIngress;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;

namespace Deep.Protocol.Tests.DeepExtension.PrivacyRouting;

public sealed class PrivacyRoutingContractTests
{
    [Fact]
    public void ThreeHopRequest_OpensOneLayerPerIndependentKey_AndReplyIsEndToEndBound()
    {
        using var fixture = new RouteFixture();
        var operationId = Bytes(0x31, 32);
        var attemptId = Bytes(0x52, 32);
        var payload = Encoding.UTF8.GetBytes("canonical-mau2");

        using var built = PrivacyRoutingRequestBuilder.Build(
            fixture.Route,
            PrivacyRoutingOperation.Store,
            operationId,
            attemptId,
            payload);

        var firstFrame = built.Frame.ToArray();
        Assert.Equal(0, firstFrame.Length % PrivacyRoutingLimits.DefaultPaddingBlockBytes);
        ManagedIngressH2Contract.ValidateOpaqueFrame(firstFrame);

        var first = Assert.IsType<PrivacyRoutingRelayLayer>(
            PrivacyRoutingRequestCodec.Open(firstFrame, fixture.Keys[0].PrivateKey));
        Assert.Equal(fixture.Route[1].RouterId.ToArray(), first.NextRouterId.ToArray());
        Assert.Equal(0, first.InnerFrame.Length % PrivacyRoutingLimits.DefaultPaddingBlockBytes);

        var second = Assert.IsType<PrivacyRoutingRelayLayer>(
            PrivacyRoutingRequestCodec.Open(first.InnerFrame.Span, fixture.Keys[1].PrivateKey));
        Assert.Equal(fixture.Route[2].RouterId.ToArray(), second.NextRouterId.ToArray());

        var exit = Assert.IsType<PrivacyRoutingExitLayer>(
            PrivacyRoutingRequestCodec.Open(second.InnerFrame.Span, fixture.Keys[2].PrivateKey));
        Assert.Equal(PrivacyRoutingOperation.Store, exit.Operation);
        Assert.Equal(operationId, exit.OperationId.ToArray());
        Assert.Equal(attemptId, exit.AttemptId.ToArray());
        Assert.Equal(payload, exit.Payload.ToArray());
        Assert.NotEqual(first.ReplayId.ToArray(), second.ReplayId.ToArray());
        Assert.NotEqual(second.ReplayId.ToArray(), exit.ReplayId.ToArray());

        var sealedReply = PrivacyRoutingResponseCodec.Seal(exit, "mqr3"u8);
        Assert.Equal(0, sealedReply.Length % PrivacyRoutingLimits.DefaultPaddingBlockBytes);
        var openedReply = PrivacyRoutingResponseCodec.Open(sealedReply, built.ReplyContext);
        Assert.Equal(PrivacyRoutingOperation.Store, openedReply.Operation);
        Assert.Equal("mqr3"u8.ToArray(), openedReply.Payload.ToArray());
    }

    [Fact]
    public void CanonicalMailboxBuilder_DerivesStableOperationId_AndFreshAttemptId()
    {
        using var fixture = new RouteFixture();
        var mau2 = Bytes(0xa5, 511);
        using var first = PrivacyRoutingRequestBuilder.BuildForCanonicalMailboxRequest(
            fixture.Route,
            PrivacyRoutingOperation.Store,
            mau2);
        using var second = PrivacyRoutingRequestBuilder.BuildForCanonicalMailboxRequest(
            fixture.Route,
            PrivacyRoutingOperation.Store,
            mau2);

        var firstExit = OpenExit(first.Frame.Span, fixture.Keys);
        var secondExit = OpenExit(second.Frame.Span, fixture.Keys);
        var expectedInput = "Deep/PrivacyRouting/V1/canonical-mailbox-operation-id"u8
            .ToArray()
            .Concat(U64((ulong)mau2.Length))
            .Concat(mau2)
            .ToArray();
        var expectedOperationId = SHA256.HashData(expectedInput);

        Assert.Equal(expectedOperationId, firstExit.OperationId.ToArray());
        Assert.Equal(expectedOperationId, secondExit.OperationId.ToArray());
        Assert.NotEqual(firstExit.AttemptId.ToArray(), secondExit.AttemptId.ToArray());
        Assert.Equal(mau2, firstExit.Payload.ToArray());
    }

    [Fact]
    public void RequestAndOpenedModels_DefensivelyOwnAllPublicBytes()
    {
        using var fixture = new RouteFixture();
        using var built = PrivacyRoutingRequestBuilder.BuildForCanonicalMailboxRequest(
            fixture.Route,
            PrivacyRoutingOperation.Store,
            "mau2"u8);

        var frameCopy = built.Frame.ToArray();
        frameCopy[0] ^= 0xff;
        Assert.Equal((byte)'D', built.Frame.Span[0]);

        var first = Assert.IsType<PrivacyRoutingRelayLayer>(
            PrivacyRoutingRequestCodec.Open(built.Frame.Span, fixture.Keys[0].PrivateKey));
        var nextCopy = first.NextRouterId.ToArray();
        nextCopy[0] ^= 0xff;
        Assert.Equal(fixture.Route[1].RouterId.Span[0], first.NextRouterId.Span[0]);

        var innerCopy = first.InnerFrame.ToArray();
        innerCopy[0] ^= 0xff;
        Assert.Equal((byte)'D', first.InnerFrame.Span[0]);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(4)]
    public void RouteCount_OtherThanExactlyThreeRejects(int count)
    {
        using var fixture = new RouteFixture();
        var route = fixture.Route.Take(Math.Min(count, 3)).ToList();
        if (count == 4)
        {
            using var extra = PublicKeyBox.GenerateKeyPair();
            route.Add(new PrivacyRoutingHop(Bytes(0x7f, 32), extra.PublicKey));
        }

        var error = Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingRequestBuilder.BuildForCanonicalMailboxRequest(
                route,
                PrivacyRoutingOperation.Store,
                "mau2"u8));
        Assert.Equal(PrivacyRoutingProtocolError.InvalidRoute, error.Error);
    }

    [Fact]
    public void RepeatedRouter_RejectsBeforeEncryption()
    {
        using var fixture = new RouteFixture();
        var repeated = new[] { fixture.Route[0], fixture.Route[1], fixture.Route[0] };

        var error = Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingRequestBuilder.BuildForCanonicalMailboxRequest(
                repeated,
                PrivacyRoutingOperation.Store,
                "mau2"u8));
        Assert.Equal(PrivacyRoutingProtocolError.InvalidRoute, error.Error);
    }

    [Fact]
    public void TamperAndWrongHopKey_FailAuthentication()
    {
        using var fixture = new RouteFixture();
        using var built = PrivacyRoutingRequestBuilder.BuildForCanonicalMailboxRequest(
            fixture.Route,
            PrivacyRoutingOperation.Store,
            "mau2"u8);
        var tampered = built.Frame.ToArray();
        tampered[^1] ^= 0x80;

        Assert.Equal(
            PrivacyRoutingProtocolError.AuthenticationFailed,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingRequestCodec.Open(tampered, fixture.Keys[0].PrivateKey)).Error);
        Assert.Equal(
            PrivacyRoutingProtocolError.AuthenticationFailed,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingRequestCodec.Open(built.Frame.Span, fixture.Keys[1].PrivateKey)).Error);
    }

    [Fact]
    public void NonCanonicalEnvelopeFields_RejectBeforeOpen()
    {
        using var fixture = new RouteFixture();
        using var built = PrivacyRoutingRequestBuilder.BuildForCanonicalMailboxRequest(
            fixture.Route,
            PrivacyRoutingOperation.Store,
            "mau2"u8);

        var suite = built.Frame.ToArray();
        suite[6] = 2;
        Assert.Equal(
            PrivacyRoutingProtocolError.UnsupportedSuite,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingRequestCodec.Open(suite, fixture.Keys[0].PrivateKey)).Error);

        var length = built.Frame.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(length.AsSpan(64, 4), 16);
        Assert.Equal(
            PrivacyRoutingProtocolError.InvalidLength,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingRequestCodec.Open(length, fixture.Keys[0].PrivateKey)).Error);

        Assert.Equal(
            PrivacyRoutingProtocolError.FrameLengthOutOfRange,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingRequestCodec.Open(new byte[83], fixture.Keys[0].PrivateKey)).Error);
    }

    [Fact]
    public void Response_ContextMismatchAndDisposedContext_FailClosed()
    {
        using var fixture = new RouteFixture();
        using var built = PrivacyRoutingRequestBuilder.BuildForCanonicalMailboxRequest(
            fixture.Route,
            PrivacyRoutingOperation.Store,
            "mau2"u8);
        var exit = OpenExit(built.Frame.Span, fixture.Keys);
        var changedOperationId = exit.OperationId.ToArray();
        changedOperationId[0] ^= 0x80;
        var forgedContext = new PrivacyRoutingExitLayer(
            exit.ReplayId.Span,
            exit.Operation,
            changedOperationId,
            exit.AttemptId.Span,
            exit.ReplyPublicKey.Span,
            exit.Payload.Span);
        var response = PrivacyRoutingResponseCodec.Seal(forgedContext, "mqr3"u8);

        Assert.Equal(
            PrivacyRoutingProtocolError.ReplyContextMismatch,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingResponseCodec.Open(response, built.ReplyContext)).Error);

        built.ReplyContext.Dispose();
        Assert.Equal(
            PrivacyRoutingProtocolError.ReplyContextDisposed,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingResponseCodec.Open(response, built.ReplyContext)).Error);
    }

    [Fact]
    public void ReplayWindow_IsBoundedAndNeverEvictsAcceptedIds()
    {
        var window = new PrivacyRoutingReplayWindow(2);
        var first = Bytes(0x11, 32);
        var second = Bytes(0x22, 32);
        var third = Bytes(0x33, 32);

        Assert.Equal(PrivacyRoutingReplayResult.Accepted, window.TryAccept(first));
        Assert.Equal(PrivacyRoutingReplayResult.Replayed, window.TryAccept(first));
        Assert.Equal(PrivacyRoutingReplayResult.Accepted, window.TryAccept(second));
        Assert.Equal(PrivacyRoutingReplayResult.Saturated, window.TryAccept(third));
        Assert.Equal(PrivacyRoutingReplayResult.Replayed, window.TryAccept(first));
        Assert.Equal(2, window.Count);
    }

    [Fact]
    public void PayloadAndPaddingBoundaries_RejectHostileValues()
    {
        using var fixture = new RouteFixture();
        Assert.Equal(
            PrivacyRoutingProtocolError.InvalidLength,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingRequestBuilder.BuildForCanonicalMailboxRequest(
                    fixture.Route,
                    PrivacyRoutingOperation.Store,
                    new byte[PrivacyRoutingLimits.MaximumApplicationPayloadBytes + 1])).Error);

        Assert.Equal(
            PrivacyRoutingProtocolError.InvalidPadding,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingRequestBuilder.BuildForCanonicalMailboxRequest(
                    fixture.Route,
                    PrivacyRoutingOperation.Store,
                    "mau2"u8,
                    paddingBlockBytes: 1_000)).Error);

        using var maximum = PrivacyRoutingRequestBuilder.BuildForCanonicalMailboxRequest(
            fixture.Route,
            PrivacyRoutingOperation.Store,
            new byte[PrivacyRoutingLimits.MaximumApplicationPayloadBytes]);
        Assert.InRange(
            maximum.Frame.Length,
            ManagedIngressLimits.MinimumOpaqueFrameBytes,
            ManagedIngressLimits.MaximumOpaqueFrameBytes);
    }

    [Fact]
    public void AuthenticatedButNonCanonicalPaddingLength_RejectsBeforeForward()
    {
        using var fixture = new RouteFixture();
        using var built = PrivacyRoutingRequestBuilder.BuildForCanonicalMailboxRequest(
            fixture.Route,
            PrivacyRoutingOperation.Store,
            "mau2"u8);
        var first = Assert.IsType<PrivacyRoutingRelayLayer>(
            PrivacyRoutingRequestCodec.Open(built.Frame.Span, fixture.Keys[0].PrivateKey));
        var inner = first.InnerFrame.ToArray();
        var plaintext = new byte[80 + inner.Length + 1];
        "DRL1"u8.CopyTo(plaintext);
        plaintext[4] = 1;
        plaintext[5] = 1;
        plaintext[6] = 1;
        Bytes(0x51, 32).CopyTo(plaintext, 8);
        fixture.Route[1].RouterId.Span.CopyTo(plaintext.AsSpan(40, 32));
        BinaryPrimitives.WriteUInt32BigEndian(plaintext.AsSpan(72, 4), (uint)inner.Length);
        BinaryPrimitives.WriteUInt32BigEndian(plaintext.AsSpan(76, 4), 1);
        inner.CopyTo(plaintext, 80);
        var sealedMalformed = PrivacyRoutingWire.SealEnvelope(
            plaintext,
            fixture.Route[0].X25519PublicKey.Span,
            PrivacyRoutingWire.RequestPurpose);

        Assert.Equal(
            PrivacyRoutingProtocolError.InvalidPadding,
            Assert.Throws<PrivacyRoutingProtocolException>(() =>
                PrivacyRoutingRequestCodec.Open(sealedMalformed, fixture.Keys[0].PrivateKey)).Error);
    }

    private static PrivacyRoutingExitLayer OpenExit(
        ReadOnlySpan<byte> frame,
        IReadOnlyList<KeyPair> keys)
    {
        var first = Assert.IsType<PrivacyRoutingRelayLayer>(
            PrivacyRoutingRequestCodec.Open(frame, keys[0].PrivateKey));
        var second = Assert.IsType<PrivacyRoutingRelayLayer>(
            PrivacyRoutingRequestCodec.Open(first.InnerFrame.Span, keys[1].PrivateKey));
        return Assert.IsType<PrivacyRoutingExitLayer>(
            PrivacyRoutingRequestCodec.Open(second.InnerFrame.Span, keys[2].PrivateKey));
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed class RouteFixture : IDisposable
    {
        internal RouteFixture()
        {
            Keys = Enumerable.Range(0, 3)
                .Select(_ => PublicKeyBox.GenerateKeyPair())
                .ToArray();
            Route = Keys.Select((key, index) =>
                    new PrivacyRoutingHop(Bytes((byte)(0x41 + index), 32), key.PublicKey))
                .ToArray();
        }

        internal KeyPair[] Keys { get; }

        internal PrivacyRoutingHop[] Route { get; }

        public void Dispose()
        {
            foreach (var key in Keys)
            {
                key.Dispose();
            }
        }
    }
}
