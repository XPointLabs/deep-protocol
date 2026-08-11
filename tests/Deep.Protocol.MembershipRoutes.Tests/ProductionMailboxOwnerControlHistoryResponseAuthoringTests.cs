using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed partial class ProductionMailboxSliceDApiTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HistoryResponsePlanHashesSeparateCanonicalBatchThenCheckpointAndRoundTrips(
        bool delegated)
    {
        var fixture = await CreateHistoryFixtureAsync(delegated: delegated);
        var plan = await AuthorHistoryAsync(fixture,
            (request, destination, _) =>
            {
                PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(),
                    fixture.Live.ResponderKey).CopyTo(destination.Span);
                return ValueTask.FromResult(64);
            });

        var batch = plan.CanonicalRouteHistoryBatch.ToArray();
        var checkpoint = plan.CanonicalRouteHistoryCheckpoint.ToArray();
        Assert.Equal(fixture.History.CanonicalBatchHash.ToArray(),
            plan.CanonicalRouteHistoryBatchHash.ToArray());
        Assert.Equal(fixture.History.NextCursor.CanonicalCheckpointHash.ToArray(),
            plan.CanonicalRouteHistoryCheckpointHash.ToArray());
        Assert.Equal(fixture.History.NextCursor.LastCommittedBatchSequence,
            plan.NextRouteHistoryBatchSequence);
        Assert.Equal(fixture.History.PlanHash.ToArray(), plan.BatchCommitPlanHash.ToArray());
        Assert.Equal(checked((uint)(batch.Length + checkpoint.Length)), plan.PayloadLength);

        using var payloadHasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        payloadHasher.AppendData(batch); payloadHasher.AppendData(checkpoint);
        Assert.Equal(payloadHasher.GetHashAndReset(), plan.PayloadSha256.ToArray());
        using var responseHasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        responseHasher.AppendData(
            "Deep/production-mailbox/owner-control-response-hash/v1"u8);
        responseHasher.AppendData(plan.CanonicalHeader.Span);
        responseHasher.AppendData(batch); responseHasher.AppendData(checkpoint);
        Assert.Equal(responseHasher.GetHashAndReset(), plan.CanonicalResponseHash.ToArray());

        var header = ProductionMailboxOwnerControlTransportCodec.VerifyResponseHeader(
            plan.CanonicalHeader.Span, fixture.Request, fixture.Live.Anchor, Now, 0);
        var segmented = ProductionMailboxOwnerControlTransportCodec
            .VerifyHistoryResponseSegments(header, fixture.History,
                plan.CanonicalResponseHash);
        Assert.Equal(plan.CanonicalResponseHash.ToArray(),
            segmented.CanonicalResponseHash.ToArray());
        var wrongResponseHash = plan.CanonicalResponseHash.ToArray();
        wrongResponseHash[^1] ^= 1;
        Assert.Throws<FormatException>(() => ProductionMailboxOwnerControlTransportCodec
            .VerifyHistoryResponseSegments(header, fixture.History, wrongResponseHash));
        await using var stream = new SegmentedReadStream(batch, checkpoint);
        var verified = await ProductionMailboxOwnerControlTransportCodec
            .ReadVerifiedResponsePayloadAsync(stream, header);
        Assert.Equal(plan.CanonicalResponseHash.ToArray(),
            verified.CanonicalResponseHash.ToArray());

        batch.AsSpan().Clear(); checkpoint.AsSpan().Clear();
        var headerCopy = plan.CanonicalHeader.ToArray(); headerCopy.AsSpan().Clear();
        Assert.NotEqual(new byte[32], plan.PayloadSha256.ToArray());
        Assert.Equal("PMCR"u8.ToArray(), plan.CanonicalHeader.Span[..4].ToArray());
        Assert.Equal("RHB1"u8.ToArray(),
            plan.CanonicalRouteHistoryBatch.Span[..4].ToArray());
        Assert.Equal("RHC1"u8.ToArray(),
            plan.CanonicalRouteHistoryCheckpoint.Span[..4].ToArray());

        var replay = await AuthorHistoryAsync(fixture,
            (request, destination, _) =>
            {
                PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(),
                    fixture.Live.ResponderKey).CopyTo(destination.Span);
                return ValueTask.FromResult(64);
            });
        Assert.Equal(plan.CanonicalHeader.ToArray(), replay.CanonicalHeader.ToArray());
        Assert.Equal(plan.CanonicalResponseHash.ToArray(),
            replay.CanonicalResponseHash.ToArray());
    }

    [Fact]
    public async Task HistoryResponseRejectsAnchorPlanWindowAndSignerFailuresWithoutCapability()
    {
        var fixture = await CreateHistoryFixtureAsync();
        var other = await CreateHistoryFixtureAsync(offline: true);
        var callbacks = 0;
        ValueTask<int> Count(ProductionMailboxOwnerControlResponseSigningRequest _,
            Memory<byte> __, CancellationToken ___)
        { callbacks++; return ValueTask.FromResult(64); }

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.AuthorHistoryResponseHeaderAsync(
                fixture.Request, other.Live.Anchor, fixture.History, Now, Now + 50, Count));
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.AuthorHistoryResponseHeaderAsync(
                fixture.Request, fixture.Live.Anchor, other.History, Now, Now + 50, Count));
        await Assert.ThrowsAsync<FormatException>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.AuthorHistoryResponseHeaderAsync(
                fixture.Request, fixture.Live.Anchor, fixture.History, Now + 50, Now + 50, Count));
        Assert.Equal(0, callbacks);

        await Assert.ThrowsAsync<FormatException>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.AuthorHistoryResponseHeaderAsync(
                fixture.Request, fixture.Live.Anchor, fixture.History, Now, Now + 50,
                (_, _, _) => ValueTask.FromResult(63)));
        await Assert.ThrowsAsync<FormatException>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.AuthorHistoryResponseHeaderAsync(
                fixture.Request, fixture.Live.Anchor, fixture.History, Now, Now + 50,
                (_, destination, _) =>
                {
                    destination.Span.Fill(1);
                    return ValueTask.FromResult(64);
                }));
    }

    [Fact]
    public async Task HistoryResponseFreezesSignerViewsAndCancellationNeverReturnsAPlan()
    {
        var fixture = await CreateHistoryFixtureAsync();
        Memory<byte> retainedDestination = default;
        var plan = await AuthorHistoryAsync(fixture, (request, destination, _) =>
        {
            var signingBytes = request.SigningBytes.ToArray();
            PublicKeyAuth.SignDetached(signingBytes, fixture.Live.ResponderKey)
                .CopyTo(destination.Span);
            signingBytes.AsSpan().Clear();
            var key = request.ExpectedResponderEd25519PublicKey.ToArray(); key.AsSpan().Clear();
            retainedDestination = destination;
            return ValueTask.FromResult(64);
        });
        var stableHeader = plan.CanonicalHeader.ToArray();
        retainedDestination.Span.Fill(0x5a);
        Assert.Equal(stableHeader, plan.CanonicalHeader.ToArray());

        var callbacks = 0;
        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await ProductionMailboxOwnerControlTransportCodec.AuthorHistoryResponseHeaderAsync(
                    fixture.Request, fixture.Live.Anchor, fixture.History, Now, Now + 50,
                    (_, _, _) => { callbacks++; return ValueTask.FromResult(64); },
                    cancelled.Token));
        }
        Assert.Equal(0, callbacks);

        using var duringSigner = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.AuthorHistoryResponseHeaderAsync(
                fixture.Request, fixture.Live.Anchor, fixture.History, Now, Now + 50,
                (request, destination, _) =>
                {
                    callbacks++;
                    PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(),
                        fixture.Live.ResponderKey).CopyTo(destination.Span);
                    duringSigner.Cancel();
                    return ValueTask.FromResult(64);
                }, duringSigner.Token));
        Assert.Equal(1, callbacks);

        var hostile = await CreateHistoryFixtureAsync();
        var batchField = typeof(ProductionMailboxRouteHistoryBatchCommitPlan).GetField(
            "_canonicalBatch", BindingFlags.Instance | BindingFlags.NonPublic)!;
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.AuthorHistoryResponseHeaderAsync(
                hostile.Request, hostile.Live.Anchor, hostile.History, Now, Now + 50,
                (request, destination, _) =>
                {
                    PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(),
                        hostile.Live.ResponderKey).CopyTo(destination.Span);
                    var changed = hostile.History.CanonicalBatch.ToArray();
                    changed[^1] ^= 1;
                    batchField.SetValue(hostile.History, changed);
                    return ValueTask.FromResult(64);
                }));
    }

    [Fact]
    public async Task HistoryResponseOuterValidMaximumMutationRejectsBeforeSignerWithoutLargeClone()
    {
        var fixture = await CreateHistoryFixtureAsync();
        var field = typeof(ProductionMailboxRouteHistoryBatchCommitPlan).GetField(
            "_canonicalBatch", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var malformed = new byte[ProductionMailboxRouteHistoryConstants.MaximumEncodedBytes];
        "RHB1"u8.CopyTo(malformed); malformed[4] = 1;
        field.SetValue(fixture.History, malformed);
        var callbacks = 0;
        var allocated = GC.GetAllocatedBytesForCurrentThread();

        await Assert.ThrowsAsync<FormatException>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.AuthorHistoryResponseHeaderAsync(
                fixture.Request, fixture.Live.Anchor, fixture.History, Now, Now + 50,
                (_, _, _) => { callbacks++; return ValueTask.FromResult(64); }));

        Assert.Equal(0, callbacks);
        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - allocated, 0, 512 * 1024);
    }

    [Fact]
    public async Task RequestHistoryKindsAndOcrLowerBoundRejectBeforeSignerAtExactBoundary()
    {
        var owner = await CreateHistoryFixtureAsync();
        var delegated = await CreateHistoryFixtureAsync(delegated: true);
        var callbacks = 0;
        ValueTask<int> Count(ProductionMailboxOwnerControlRequestSigningRequest _,
            Memory<byte> __, CancellationToken ___)
        { callbacks++; return ValueTask.FromResult(64); }

        await Assert.ThrowsAsync<FormatException>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.AuthorDelegatedDirectRequestAsync(
                owner.Live.Anchor, owner.CurrentCursor, Enumerable.Repeat((byte)101, 32).ToArray(),
                Now, Now + 50, Count));
        await Assert.ThrowsAsync<FormatException>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.AuthorOwnerDirectRequestAsync(
                delegated.Live.Anchor, delegated.CurrentCursor,
                Enumerable.Repeat((byte)102, 32).ToArray(), Now, Now + 50, Count));
        await Assert.ThrowsAsync<FormatException>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.AuthorOwnerDirectRequestAsync(
                owner.Live.Anchor, owner.CurrentCursor, Enumerable.Repeat((byte)103, 32).ToArray(),
                Now - 1, Now + 50, Count));
        Assert.Equal(0, callbacks);

        var wrongHistoryRequest = ForgeRequest(owner,
            ProductionMailboxRouteAuthorizationKind.DelegatedRCA1, Now);
        var historyCallbacks = 0;
        await Assert.ThrowsAsync<FormatException>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.AuthorHistoryResponseHeaderAsync(
                wrongHistoryRequest, owner.Live.Anchor, owner.History, Now, Now + 50,
                (_, _, _) => { historyCallbacks++; return ValueTask.FromResult(64); }));
        Assert.Equal(0, historyCallbacks);

        var equality = await ProductionMailboxOwnerControlTransportCodec.AuthorNoChangeResponseAsync(
            owner.Request, owner.Live.Anchor, Now, Now + 50,
            (request, destination, _) =>
            {
                PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(),
                    owner.Live.ResponderKey).CopyTo(destination.Span);
                return ValueTask.FromResult(64);
            });
        Assert.NotEmpty(equality.CanonicalHeader.ToArray());

        var preOcrRequest = ForgeRequest(owner,
            ProductionMailboxRouteAuthorizationKind.OwnerPRA2, Now - 1);
        var responseCallbacks = 0;
        await Assert.ThrowsAsync<FormatException>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.AuthorNoChangeResponseAsync(
                preOcrRequest, owner.Live.Anchor, Now - 1, Now + 40,
                (_, _, _) => { responseCallbacks++; return ValueTask.FromResult(64); }));
        Assert.Equal(0, responseCallbacks);

        var validHeader = ProductionMailboxOwnerControlTransportCodec.DecodeResponseHeader(
            equality.CanonicalHeader.Span);
        var preOcrHeader = validHeader with
        {
            IssuedAtUnixSeconds = Now - 1,
            CanonicalRequestHash = preOcrRequest.CanonicalHash,
            RequestId = ProductionMailboxOwnerControlTransportCodec.DecodeRequest(
                preOcrRequest.CanonicalBytes.Span).RequestId,
            ResponderSignature = new byte[64]
        };
        preOcrHeader = preOcrHeader with
        {
            ResponderSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxOwnerControlTransportCodec.GetResponseSigningBytes(preOcrHeader),
                owner.Live.ResponderKey)
        };
        var preOcrHeaderBytes = ProductionMailboxOwnerControlTransportCodec
            .EncodeResponseHeader(preOcrHeader);
        Assert.Throws<FormatException>(() =>
            ProductionMailboxOwnerControlTransportCodec.VerifyResponseHeader(
                preOcrHeaderBytes, preOcrRequest, owner.Live.Anchor, Now - 1, 0));
    }

    private static VerifiedProductionMailboxOwnerControlRequest ForgeRequest(
        HistoryFixture fixture, ProductionMailboxRouteAuthorizationKind kind, ulong issuedAt)
    {
        var request = ProductionMailboxOwnerControlTransportCodec.DecodeRequest(
            fixture.Request.CanonicalBytes.Span) with
        {
            ExpectedAuthorizationKind = kind,
            IssuedAtUnixSeconds = issuedAt,
            OwnerSignature = new byte[64]
        };
        var ocrHash = fixture.Live.Anchor.CanonicalOwnerControlResponderCertificateHash.ToArray();
        request = request with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxOwnerControlTransportCodec.GetRequestSigningBytes(request, ocrHash),
                fixture.Live.OwnerKey)
        };
        var canonical = ProductionMailboxOwnerControlTransportCodec.EncodeRequest(request);
        return new(request, canonical,
            ProductionMailboxOwnerControlTransportCodec.ComputeRequestHash(request, ocrHash));
    }

    private static async Task<HistoryFixture> CreateHistoryFixtureAsync(bool offline = false,
        bool delegated = false)
    {
        var live = await CreateLiveFixtureAsync(offline);
        var window = new ProductionMailboxLiveTransitionWindow
        {
            RouteNotBeforeUnixSeconds = Now, RouteExpiresAtUnixSeconds = Now + 80,
            CheckpointIssuedAtUnixSeconds = Now, CheckpointExpiresAtUnixSeconds = Now + 80,
            AuthorizationIssuedAtUnixSeconds = Now, AuthorizationExpiresAtUnixSeconds = Now + 80,
            NowUnixSeconds = Now, ClockSkewSeconds = 0
        };
        VerifiedProductionMailboxRouteHistoryCursor currentCursor = live.Cursor;
        VerifiedProductionMailboxSelectionTransitionIntent intent = live.Intent;
        VerifiedProductionMailboxLiveTransition transition = null!;
        if (!delegated && !offline)
            transition = await ProductionMailboxLiveTransitionAuthoring.AuthorOwnerDirectAsync(
                live.Anchor, live.Cursor, live.Intent, window,
                (r,d,_) => Sign64(r.SigningBytes, d, live.OwnerKey),
                (r,d,_) =>
                {
                    PublicKeyAuth.SignDetached(r.SigningBytes.ToArray(), live.OldIssuerKey)
                        .CopyTo(d.Span); return ValueTask.CompletedTask;
                },
                (r,d,_) =>
                {
                    PublicKeyAuth.SignDetached(r.SigningBytes.ToArray(), live.CurrentIssuerKey)
                        .CopyTo(d.Span); return ValueTask.CompletedTask;
                });
        else if (!delegated)
            transition = await ProductionMailboxLiveTransitionAuthoring.AuthorOwnerOfflineAsync(
                live.Anchor, live.Cursor, live.Intent, window,
                (r,d,_) => Sign64(r.SigningBytes, d, live.OwnerKey),
                (r,d,_) =>
                {
                    PublicKeyAuth.SignDetached(r.SigningBytes.ToArray(), live.CurrentIssuerKey)
                        .CopyTo(d.Span); return ValueTask.CompletedTask;
                });
        else
        {
            var first = !offline
                ? await ProductionMailboxLiveTransitionAuthoring.AuthorDelegatedDirectAsync(
                    live.Anchor, live.Cursor, live.Intent, window,
                    (r,d,_) => Sign64(r.SigningBytes, d, live.CurrentIssuerKey),
                    (r,d,_) => Sign64(r.SigningBytes, d, live.CurrentIssuerKey),
                    (r,d,_) =>
                    {
                        PublicKeyAuth.SignDetached(r.SigningBytes.ToArray(), live.OldIssuerKey)
                            .CopyTo(d.Span); return ValueTask.CompletedTask;
                    },
                    (r,d,_) =>
                    {
                        PublicKeyAuth.SignDetached(r.SigningBytes.ToArray(), live.CurrentIssuerKey)
                            .CopyTo(d.Span); return ValueTask.CompletedTask;
                    })
                : await ProductionMailboxLiveTransitionAuthoring.AuthorDelegatedOfflineAsync(
                    live.Anchor, live.Cursor, live.Intent, window,
                    (r,d,_) => Sign64(r.SigningBytes, d, live.CurrentIssuerKey),
                    (r,d,_) => Sign64(r.SigningBytes, d, live.CurrentIssuerKey),
                    (r,d,_) =>
                    {
                        PublicKeyAuth.SignDetached(r.SigningBytes.ToArray(), live.CurrentIssuerKey)
                            .CopyTo(d.Span); return ValueTask.CompletedTask;
                    });
            currentCursor = ProductionMailboxRouteHistoryAuthoring.VerifyNextBatchForCommit(
                live.Cursor, first.CommitPlan.CanonicalRouteHistoryBatch.Span).NextCursor;
            intent = !offline
                ? ProductionMailboxRouteIssuerAuthoring.CreateDirectSelectionTransitionIntent(
                    currentCursor, live.Intent.OldAuthority, live.Intent.OldTopology,
                    live.Intent.OldSelection, live.Intent.CurrentAuthority,
                    live.Intent.CurrentRevocations, live.Intent.CurrentTopology,
                    live.Intent.CurrentSelection, live.Intent.NextSelection!,
                    live.Intent.RouteCertificate, Now, 0)
                : ProductionMailboxRouteIssuerAuthoring.CreateOfflineSelectionTransitionIntent(
                    currentCursor, live.Intent.OldAuthority, live.Intent.OldTopology,
                    live.Intent.OldSelection, live.Intent.CurrentAuthority,
                    live.Intent.CurrentRevocations, live.Intent.CurrentTopology,
                    live.Intent.CurrentSelection, live.Intent.NextSelection!,
                    live.Intent.RouteCertificate, Now, 0);
        }
        if (delegated && !offline)
            transition = await ProductionMailboxLiveTransitionAuthoring.AuthorDelegatedDirectAsync(
                live.Anchor, currentCursor, intent, window,
                (r,d,_) => Sign64(r.SigningBytes, d, live.CurrentIssuerKey),
                (r,d,_) => Sign64(r.SigningBytes, d, live.CurrentIssuerKey),
                (r,d,_) =>
                {
                    PublicKeyAuth.SignDetached(r.SigningBytes.ToArray(), live.OldIssuerKey)
                        .CopyTo(d.Span); return ValueTask.CompletedTask;
                },
                (r,d,_) =>
                {
                    PublicKeyAuth.SignDetached(r.SigningBytes.ToArray(), live.CurrentIssuerKey)
                        .CopyTo(d.Span); return ValueTask.CompletedTask;
                });
        else if (delegated)
            transition = await ProductionMailboxLiveTransitionAuthoring.AuthorDelegatedOfflineAsync(
                live.Anchor, currentCursor, intent, window,
                (r,d,_) => Sign64(r.SigningBytes, d, live.CurrentIssuerKey),
                (r,d,_) => Sign64(r.SigningBytes, d, live.CurrentIssuerKey),
                (r,d,_) =>
                {
                    PublicKeyAuth.SignDetached(r.SigningBytes.ToArray(), live.CurrentIssuerKey)
                        .CopyTo(d.Span); return ValueTask.CompletedTask;
                });
        var history = ProductionMailboxRouteHistoryAuthoring.VerifyNextBatchForCommit(
            currentCursor, transition.CommitPlan.CanonicalRouteHistoryBatch.Span);
        ValueTask<VerifiedProductionMailboxOwnerControlRequest> requestTask = (delegated, offline) switch
        {
            (false, true) => ProductionMailboxOwnerControlTransportCodec.AuthorOwnerOfflineRequestAsync(
                live.Anchor, currentCursor, Enumerable.Repeat((byte)92, 32).ToArray(),
                Now, Now + 60, (r,d,_) => Sign64(r.SigningBytes, d, live.OwnerKey)),
            (false, false) => ProductionMailboxOwnerControlTransportCodec.AuthorOwnerDirectRequestAsync(
                live.Anchor, currentCursor, Enumerable.Repeat((byte)91, 32).ToArray(),
                Now, Now + 60, (r,d,_) => Sign64(r.SigningBytes, d, live.OwnerKey)),
            (true, true) => ProductionMailboxOwnerControlTransportCodec.AuthorDelegatedOfflineRequestAsync(
                live.Anchor, currentCursor, Enumerable.Repeat((byte)94, 32).ToArray(),
                Now, Now + 60, (r,d,_) => Sign64(r.SigningBytes, d, live.OwnerKey)),
            _ => ProductionMailboxOwnerControlTransportCodec.AuthorDelegatedDirectRequestAsync(
                live.Anchor, currentCursor, Enumerable.Repeat((byte)93, 32).ToArray(),
                Now, Now + 60, (r,d,_) => Sign64(r.SigningBytes, d, live.OwnerKey))
        };
        var request = await requestTask;
        return new(live, currentCursor, request, history);
    }

    private static ValueTask<ProductionMailboxOwnerControlHistoryResponsePlan> AuthorHistoryAsync(
        HistoryFixture fixture, ProductionMailboxOwnerControlResponseSigner signer) =>
        ProductionMailboxOwnerControlTransportCodec.AuthorHistoryResponseHeaderAsync(
            fixture.Request, fixture.Live.Anchor, fixture.History, Now, Now + 50, signer);

    private sealed record HistoryFixture(LiveFixture Live,
        VerifiedProductionMailboxRouteHistoryCursor CurrentCursor,
        VerifiedProductionMailboxOwnerControlRequest Request,
        ProductionMailboxRouteHistoryBatchCommitPlan History);

    private sealed class SegmentedReadStream(params byte[][] segments) : Stream
    {
        private int _segment;
        private int _offset;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => segments.Sum(static value => (long)value.Length);
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            if (_segment == segments.Length) return 0;
            var source = segments[_segment].AsSpan(_offset);
            var length = Math.Min(buffer.Length, source.Length);
            source[..length].CopyTo(buffer);
            _offset += length;
            if (_offset == segments[_segment].Length) { _segment++; _offset = 0; }
            return length;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Read(buffer.Span));
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
