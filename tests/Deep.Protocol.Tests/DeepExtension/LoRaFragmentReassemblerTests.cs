using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.LoRaFragments;
using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class LoRaFragmentReassemblerTests
{
    [Fact]
    public async Task ArbitraryReorderCompletesExactBundleAndPersistsReplayTombstone()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore();
        var reassembler = fixture.Reassembler(store);
        LoRaFragmentReassemblyResult? result = null;

        foreach (var encoded in fixture.Plan.Frames.Reverse())
        {
            result = await reassembler.ProcessAsync(fixture.Request(encoded));
        }

        Assert.NotNull(result);
        Assert.Equal(LoRaFragmentReassemblyOutcome.Completed, result.Outcome);
        Assert.Equal(fixture.Bundle, result.EncodedOpaqueBundle!.Value.ToArray());
        Assert.Equal(1, store.CompletedCount);

        var restarted = fixture.Reassembler(store);
        var replay = await restarted.ProcessAsync(fixture.Request(fixture.Plan.Frames[0]));
        Assert.Equal(LoRaFragmentReassemblyOutcome.Rejected, replay.Outcome);
        Assert.Null(replay.EncodedOpaqueBundle);
    }

    [Fact]
    public async Task ExactDuplicateIsIdempotentButAuthenticatedConflictPoisonsAcrossRestart()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore();
        var reassembler = fixture.Reassembler(store);
        var first = fixture.Plan.Frames[0];

        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Incomplete,
            (await reassembler.ProcessAsync(fixture.Request(first))).Outcome);
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Incomplete,
            (await reassembler.ProcessAsync(fixture.Request(first))).Outcome);

        var decoded = LoRaFragmentCodec.Decode(
            first.Span,
            fixture.FragmentPolicy,
            fixture.AuthenticationHandle,
            LoRaFragmentDirection.Forward,
            fixture.Authenticator);
        var differentShard = decoded.Shard.ToArray();
        differentShard[^1] ^= 1;
        var conflict = LoRaFragmentCodec.Encode(
            new LoRaFragmentUnsignedFrame(decoded.Header, differentShard),
            fixture.AuthenticationHandle,
            LoRaFragmentDirection.Forward,
            fixture.Authenticator);

        var poisoned = await reassembler.ProcessAsync(fixture.Request(conflict));
        Assert.Equal(LoRaFragmentReassemblyOutcome.Rejected, poisoned.Outcome);
        Assert.Equal(1, store.PoisonedCount);

        var restarted = fixture.Reassembler(store);
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Rejected,
            (await restarted.ProcessAsync(fixture.Request(first))).Outcome);
    }

    [Fact]
    public async Task Xor1RecoversOneLossPerGroupButNeverTwoLosses()
    {
        var oneLoss = new Fixture(LoRaFragmentFecMode.Xor1);
        var oneLossStore = new MemoryReplayStore();
        var oneLossReassembler = oneLoss.Reassembler(oneLossStore);
        LoRaFragmentReassemblyResult? recovered = null;
        foreach (var encoded in oneLoss.Plan.Frames.Where((_, index) => index != 2))
        {
            recovered = await oneLossReassembler.ProcessAsync(oneLoss.Request(encoded));
        }

        Assert.NotNull(recovered);
        Assert.Equal(LoRaFragmentReassemblyOutcome.Completed, recovered.Outcome);
        Assert.Equal(oneLoss.Bundle, recovered.EncodedOpaqueBundle!.Value.ToArray());

        var twoLoss = new Fixture(LoRaFragmentFecMode.Xor1);
        var twoLossReassembler = twoLoss.Reassembler(new MemoryReplayStore());
        LoRaFragmentReassemblyResult? incomplete = null;
        foreach (var encoded in twoLoss.Plan.Frames.Where((_, index) => index is not 1 and not 2))
        {
            incomplete = await twoLossReassembler.ProcessAsync(twoLoss.Request(encoded));
        }

        Assert.NotNull(incomplete);
        Assert.Equal(LoRaFragmentReassemblyOutcome.Incomplete, incomplete.Outcome);
        Assert.Null(incomplete.EncodedOpaqueBundle);
    }

    [Fact]
    public async Task AuthenticatedMalformedParityPoisonsAndRejectsAfterRestart()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.Xor1);
        var store = new MemoryReplayStore();
        var reassembler = fixture.Reassembler(store);
        var parityIndex = fixture.Plan.DataShardCount;
        var parity = LoRaFragmentCodec.Decode(
            fixture.Plan.Frames[parityIndex].Span,
            fixture.FragmentPolicy,
            fixture.AuthenticationHandle,
            LoRaFragmentDirection.Forward,
            fixture.Authenticator);
        var malformedShard = parity.Shard.ToArray();
        malformedShard[^1] ^= 1;
        var malformedParity = LoRaFragmentCodec.Encode(
            new LoRaFragmentUnsignedFrame(parity.Header, malformedShard),
            fixture.AuthenticationHandle,
            LoRaFragmentDirection.Forward,
            fixture.Authenticator);

        LoRaFragmentReassemblyResult? result = null;
        foreach (var frame in fixture.Plan.Frames
                     .Take(fixture.Plan.DataShardCount)
                     .Where((_, index) => index != 1)
                     .Append(malformedParity))
        {
            result = await reassembler.ProcessAsync(fixture.Request(frame));
        }

        Assert.NotNull(result);
        Assert.Equal(LoRaFragmentReassemblyOutcome.Rejected, result.Outcome);
        Assert.Equal(1, store.PoisonedCount);
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Rejected,
            (await fixture.Reassembler(store).ProcessAsync(
                fixture.Request(fixture.Plan.Frames[0]))).Outcome);
    }

    [Fact]
    public async Task AuthenticatedMalformedParityCannotBeIgnoredWhenAllDataArrives()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.Xor1);
        var store = new MemoryReplayStore
        {
            RequireAllDataForReady = true
        };
        var reassembler = fixture.Reassembler(store);
        var parityIndex = fixture.Plan.DataShardCount;
        var parity = LoRaFragmentCodec.Decode(
            fixture.Plan.Frames[parityIndex].Span,
            fixture.FragmentPolicy,
            fixture.AuthenticationHandle,
            LoRaFragmentDirection.Forward,
            fixture.Authenticator);
        var malformedShard = parity.Shard.ToArray();
        malformedShard[0] ^= 1;
        var malformedParity = LoRaFragmentCodec.Encode(
            new LoRaFragmentUnsignedFrame(parity.Header, malformedShard),
            fixture.AuthenticationHandle,
            LoRaFragmentDirection.Forward,
            fixture.Authenticator);

        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Incomplete,
            (await reassembler.ProcessAsync(fixture.Request(malformedParity))).Outcome);

        LoRaFragmentReassemblyResult? result = null;
        foreach (var frame in fixture.Plan.Frames.Take(fixture.Plan.DataShardCount))
        {
            result = await reassembler.ProcessAsync(fixture.Request(frame));
        }

        Assert.NotNull(result);
        Assert.Equal(LoRaFragmentReassemblyOutcome.Rejected, result.Outcome);
        Assert.Null(result.EncodedOpaqueBundle);
        Assert.Equal(1, store.PoisonedCount);
    }

    [Theory]
    [InlineData(3, 0x11)]
    [InlineData(6, 101)]
    public async Task AuthenticatedDescriptorBoundaryViolationPoisons(
        int descriptorOffset,
        byte replacement)
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore();
        var reassembler = fixture.Reassembler(store);
        var first = LoRaFragmentCodec.Decode(
            fixture.Plan.Frames[0].Span,
            fixture.FragmentPolicy,
            fixture.AuthenticationHandle,
            LoRaFragmentDirection.Forward,
            fixture.Authenticator);
        var changedShard = first.Shard.ToArray();
        if (descriptorOffset == 6)
        {
            BinaryPrimitives.WriteUInt32BigEndian(
                changedShard.AsSpan(descriptorOffset, sizeof(uint)),
                replacement);
        }
        else
        {
            changedShard[descriptorOffset] = replacement;
        }

        var changedFirst = LoRaFragmentCodec.Encode(
            new LoRaFragmentUnsignedFrame(first.Header, changedShard),
            fixture.AuthenticationHandle,
            LoRaFragmentDirection.Forward,
            fixture.Authenticator);
        LoRaFragmentReassemblyResult? result = null;
        foreach (var frame in fixture.Plan.Frames.Skip(1).Prepend(changedFirst))
        {
            result = await reassembler.ProcessAsync(fixture.Request(frame));
        }

        Assert.NotNull(result);
        Assert.Equal(LoRaFragmentReassemblyOutcome.Rejected, result.Outcome);
        Assert.Equal(1, store.PoisonedCount);
    }

    [Fact]
    public async Task DirectionAndReplayScopeNeverMix()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore();
        var reassembler = fixture.Reassembler(store);
        var alternateScope = fixture.ReplayProvider.Create();

        foreach (var encoded in fixture.Plan.Frames.Take(fixture.Plan.Frames.Count - 1))
        {
            Assert.Equal(
                LoRaFragmentReassemblyOutcome.Incomplete,
                (await reassembler.ProcessAsync(fixture.Request(encoded))).Outcome);
        }

        var wrongScope = await reassembler.ProcessAsync(
            fixture.Request(fixture.Plan.Frames[^1], alternateScope));
        Assert.Equal(LoRaFragmentReassemblyOutcome.Incomplete, wrongScope.Outcome);

        var reverse = await reassembler.ProcessAsync(
            fixture.Request(
                fixture.Plan.Frames[^1],
                fixture.ReplayScope,
                LoRaFragmentDirection.Reverse));
        Assert.Equal(LoRaFragmentReassemblyOutcome.Rejected, reverse.Outcome);
        Assert.Equal(0, store.CompletedCount);
    }

    [Fact]
    public async Task StoreSnapshotFromAnotherReplayScopeNeverEmitsBundle()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore
        {
            SnapshotReplayScopeOverride = fixture.ReplayProvider.Create()
        };
        var reassembler = fixture.Reassembler(store);
        LoRaFragmentReassemblyResult? result = null;

        foreach (var encoded in fixture.Plan.Frames)
        {
            result = await reassembler.ProcessAsync(fixture.Request(encoded));
        }

        Assert.NotNull(result);
        Assert.NotEqual(LoRaFragmentReassemblyOutcome.Completed, result.Outcome);
        Assert.Null(result.EncodedOpaqueBundle);
        Assert.Equal(0, store.CompletedCount);
    }

    [Fact]
    public async Task CallerMutationBeforeProcessingIsAuthenticatedBeforeStoreCopy()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore();
        var reassembler = fixture.Reassembler(store);
        var encoded = fixture.Plan.Frames[0].ToArray();
        var request = fixture.Request(encoded);
        encoded[^1] ^= 1;

        var result = await reassembler.ProcessAsync(request);

        Assert.Equal(LoRaFragmentReassemblyOutcome.Rejected, result.Outcome);
        Assert.Equal(0, store.ApplyCalls);
    }

    [Fact]
    public async Task FatalAuthenticatorFailureIsNotReducedToOrdinaryFrameRejection()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var fatal = new OutOfMemoryException("fragment auth fatal canary");
        var reassembler = new LoRaFragmentReassembler(
            new MemoryReplayStore(),
            fixture.ReassemblyPolicy,
            new ThrowingAuthenticator(fatal));

        var thrown = await Assert.ThrowsAsync<OutOfMemoryException>(
            async () => await reassembler.ProcessAsync(
                fixture.Request(fixture.Plan.Frames[0])));

        Assert.Same(fatal, thrown);
    }

    [Fact]
    public async Task UnknownTerminalOutcomeNeverEmitsBundle()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore
        {
            CommitStatus = LoRaFragmentStoreCommitStatus.OutcomeUnknown
        };
        var reassembler = fixture.Reassembler(store);
        LoRaFragmentReassemblyResult? result = null;
        foreach (var encoded in fixture.Plan.Frames)
        {
            result = await reassembler.ProcessAsync(fixture.Request(encoded));
        }

        Assert.NotNull(result);
        Assert.Equal(LoRaFragmentReassemblyOutcome.OutcomeUnknown, result.Outcome);
        Assert.Null(result.EncodedOpaqueBundle);
    }

    [Fact]
    public async Task LoweredGlobalAdmissionLimitRejectsWithoutEvictingLiveState()
    {
        var fixture = new Fixture(
            LoRaFragmentFecMode.None,
            maximumIncompleteMessagesGlobal: 1);
        var store = new MemoryReplayStore();
        var reassembler = fixture.Reassembler(store);

        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Incomplete,
            (await reassembler.ProcessAsync(
                fixture.Request(fixture.Plan.Frames[0]))).Outcome);

        var secondPlan = fixture.CreatePlan(
            new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 });
        var rejected = await reassembler.ProcessAsync(
            fixture.Request(secondPlan.Frames[0]));

        Assert.Equal(LoRaFragmentReassemblyOutcome.Rejected, rejected.Outcome);
        Assert.Equal(1, store.IncompleteCount);
    }

    [Fact]
    public async Task LoweredPerScopeAdmissionLimitRejectsOnlyThatScope()
    {
        var fixture = new Fixture(
            LoRaFragmentFecMode.None,
            maximumIncompleteMessagesPerReplayScope: 1);
        var store = new MemoryReplayStore();
        var reassembler = fixture.Reassembler(store);

        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Incomplete,
            (await reassembler.ProcessAsync(
                fixture.Request(fixture.Plan.Frames[0]))).Outcome);

        var secondPlan = fixture.CreatePlan(
            new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 });
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Rejected,
            (await reassembler.ProcessAsync(
                fixture.Request(secondPlan.Frames[0]))).Outcome);

        var alternateScope = fixture.ReplayProvider.Create();
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Incomplete,
            (await reassembler.ProcessAsync(
                fixture.Request(secondPlan.Frames[0], alternateScope))).Outcome);
        Assert.Equal(2, store.IncompleteCount);
    }

    [Fact]
    public void CompletedTerminalRequiresCanonicalSha256Digest()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var key = new LoRaFragmentReplayKey(
            fixture.ReplayScope,
            LoRaFragmentDirection.Forward,
            fixture.Plan.Frames[0].Span.Slice(4, LoRaFragmentLimits.MessageIdLength));

        Assert.Throws<ArgumentException>(() =>
            new LoRaFragmentTerminalCommit(
                key,
                generation: 1,
                LoRaFragmentTerminalStatus.Completed,
                expiryBucket: 100,
                retentionExpiryBucket: 101,
                bundleDigest: new byte[31]));
    }

    [Fact]
    public void TerminalRetentionCannotPrecedeExpiry()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var key = new LoRaFragmentReplayKey(
            fixture.ReplayScope,
            LoRaFragmentDirection.Forward,
            fixture.Plan.Frames[0].Span.Slice(4, LoRaFragmentLimits.MessageIdLength));

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new LoRaFragmentTerminalCommit(
                key,
                generation: 1,
                LoRaFragmentTerminalStatus.Poisoned,
                expiryBucket: 100,
                retentionExpiryBucket: 99));
    }

    private sealed class Fixture
    {
        private static readonly byte[] MessageId = [1, 2, 3, 4, 5, 6, 7, 8];
        private readonly AuthenticationProvider _authenticationProvider = new();

        public Fixture(
            LoRaFragmentFecMode fecMode,
            int maximumIncompleteMessagesPerReplayScope =
                LoRaFragmentReassemblyLimits.MaximumIncompleteMessagesPerReplayScope,
            int maximumIncompleteMessagesGlobal =
                LoRaFragmentReassemblyLimits.MaximumIncompleteMessagesGlobal)
        {
            AuthenticationHandle = _authenticationProvider.Create(
                Enumerable.Range(0x90, 32).Select(static value => (byte)value).ToArray());
            Authenticator = new HmacTestAuthenticator(_authenticationProvider);
            ReplayProvider = new ReplayProvider();
            ReplayScope = ReplayProvider.Create();
            FragmentPolicy = new LoRaFragmentPolicy(
                new OpaqueBundleDecodePolicy
                {
                    MinimumVersion = OpaqueBundleWireVersion.V1,
                    MaximumVersion = OpaqueBundleWireVersion.V1,
                    SupportedCriticalFeatures = OpaqueBundleFeatures.V1Required,
                    MinimumExpiryBucket = 99,
                    MaximumExpiryBucket = 101
                });
            ReassemblyPolicy = new LoRaFragmentReassemblyPolicy(
                FragmentPolicy,
                currentExpiryBucket: 99,
                provisionalExpiryBucket: 101,
                acceptedExpirySkewBuckets: 1,
                maximumIncompleteMessagesPerReplayScope:
                    maximumIncompleteMessagesPerReplayScope,
                maximumIncompleteMessagesGlobal: maximumIncompleteMessagesGlobal);
            Bundle = CreateBundle();
            FecMode = fecMode;
            Plan = CreatePlan(MessageId);
        }

        public LoRaFragmentAuthenticationHandle AuthenticationHandle { get; }
        public ILoRaFragmentAuthenticator Authenticator { get; }
        public ReplayProvider ReplayProvider { get; }
        public LoRaFragmentReplayScopeHandle ReplayScope { get; }
        public LoRaFragmentPolicy FragmentPolicy { get; }
        public LoRaFragmentReassemblyPolicy ReassemblyPolicy { get; }
        public byte[] Bundle { get; }
        public LoRaFragmentFecMode FecMode { get; }
        public LoRaFragmentPlan Plan { get; }

        public LoRaFragmentPlan CreatePlan(byte[] messageId) =>
            LoRaFragmentPlanner.Plan(
                new LoRaFragmentPlanRequest(
                    Bundle,
                    messageId,
                    currentHop: 0,
                    hopLimit: 3,
                    shardSize: 64,
                    FecMode,
                    LoRaFragmentDirection.Forward,
                    AuthenticationHandle),
                FragmentPolicy,
                Authenticator);

        public LoRaFragmentReassembler Reassembler(ILoRaFragmentReplayStore store) =>
            new(store, ReassemblyPolicy, Authenticator);

        public LoRaFragmentReassemblyRequest Request(
            ReadOnlyMemory<byte> encoded,
            LoRaFragmentReplayScopeHandle? replayScope = null,
            LoRaFragmentDirection direction = LoRaFragmentDirection.Forward) =>
            new(
                encoded,
                AuthenticationHandle,
                replayScope ?? ReplayScope,
                direction);

        private static byte[] CreateBundle() =>
            OpaqueBundleCodec.Encode(
                new OpaqueBundleWriteRequest
                {
                    Capability = new OpaqueDepositCapability(
                        Enumerable.Range(0x10, 32).Select(static value => (byte)value).ToArray()),
                    TransportAttemptId = new TransportAttemptId(
                        Enumerable.Range(0x30, 16).Select(static value => (byte)value).ToArray()),
                    EndToEndDedupId = new EndToEndDedupId(
                        Enumerable.Range(0x50, 16).Select(static value => (byte)value).ToArray()),
                    ExpiryBucket = 100,
                    PaddingClass = OpaqueBundlePaddingClass.Bytes256,
                    ReplayMaterial =
                        Enumerable.Range(0x70, 16).Select(static value => (byte)value).ToArray(),
                    EncryptedHeader = new byte[] { 0xaa },
                    EncryptedPayload = new byte[] { 0xbb },
                    PayloadKind = OpaqueBundlePayloadKind.NativeOpaque,
                    CriticalFeatures = OpaqueBundleFeatures.V1Required
                },
                new OpaqueBundleNegotiatedProfile(
                    OpaqueBundleWireVersion.V1,
                    OpaqueBundleFeatures.V1Required,
                    AllowLegacyDpe1: false));
    }

    private sealed class MemoryReplayStore : ILoRaFragmentReplayStore
    {
        private readonly object _gate = new();
        private readonly Dictionary<Key, State> _states = [];

        public LoRaFragmentStoreCommitStatus CommitStatus { get; set; } =
            LoRaFragmentStoreCommitStatus.Committed;
        public LoRaFragmentReplayScopeHandle? SnapshotReplayScopeOverride { get; set; }
        public bool RequireAllDataForReady { get; set; }
        public int ApplyCalls { get; private set; }
        public int CompletedCount
        {
            get
            {
                lock (_gate)
                    return _states.Values.Count(state =>
                        state.Terminal == LoRaFragmentTerminalStatus.Completed);
            }
        }
        public int PoisonedCount
        {
            get
            {
                lock (_gate)
                    return _states.Values.Count(state =>
                        state.Terminal == LoRaFragmentTerminalStatus.Poisoned);
            }
        }
        public int IncompleteCount
        {
            get
            {
                lock (_gate)
                    return _states.Values.Count(state => state.Terminal is null);
            }
        }

        public ValueTask<LoRaFragmentStoreApplyResult> ApplyAuthenticatedFragmentAsync(
            LoRaFragmentAuthenticatedFragment fragment,
            LoRaFragmentReassemblyPolicy policy,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                ApplyCalls++;
                var key = Key.From(fragment.Key);
                if (_states.TryGetValue(key, out var state))
                {
                    if (state.Terminal is not null)
                        return ValueTask.FromResult(
                            new LoRaFragmentStoreApplyResult(
                                LoRaFragmentStoreApplyStatus.Rejected));
                    if (!state.Matches(fragment.Frame.Header))
                    {
                        state.Terminal = LoRaFragmentTerminalStatus.Poisoned;
                        return ValueTask.FromResult(
                            new LoRaFragmentStoreApplyResult(
                                LoRaFragmentStoreApplyStatus.Rejected));
                    }
                }
                else
                {
                    if (IncompleteCountNoLock() >= policy.MaximumIncompleteMessagesGlobal ||
                        IncompleteCountForScopeNoLock(fragment.Key.ReplayScope) >=
                        policy.MaximumIncompleteMessagesPerReplayScope ||
                        ReservedBytesNoLock() + fragment.ReservationCharge >
                        policy.MaximumReservedBytesGlobal)
                    {
                        return ValueTask.FromResult(
                            new LoRaFragmentStoreApplyResult(
                                LoRaFragmentStoreApplyStatus.Rejected));
                    }

                    state = new State(
                        fragment.Key,
                        fragment.Frame.Header,
                        policy.ProvisionalExpiryBucket,
                        fragment.ReservationCharge);
                    _states.Add(key, state);
                }

                var ordinal = fragment.Frame.Header.Ordinal;
                var canonical = fragment.CanonicalHeaderAndShard.ToArray();
                if (state.CanonicalByOrdinal[ordinal] is { } previous)
                {
                    if (!previous.AsSpan().SequenceEqual(canonical))
                    {
                        state.Terminal = LoRaFragmentTerminalStatus.Poisoned;
                        return ValueTask.FromResult(
                            new LoRaFragmentStoreApplyResult(
                                LoRaFragmentStoreApplyStatus.Rejected));
                    }
                }
                else
                {
                    state.CanonicalByOrdinal[ordinal] = canonical;
                    if (ordinal < state.Shape.DataShardCount)
                        state.Data[ordinal] = fragment.Frame.Shard.ToArray();
                    else
                        state.Parity[ordinal - state.Shape.DataShardCount] =
                            fragment.Frame.Shard.ToArray();
                    if (ordinal == 0)
                    {
                        var expiry = BinaryPrimitives.ReadUInt32BigEndian(
                            fragment.Frame.Shard.Span.Slice(6, 4));
                        if (expiry >= policy.CurrentExpiryBucket &&
                            expiry <= state.ExpiryBucket)
                            state.ExpiryBucket = expiry;
                    }
                    state.Generation++;
                }

                if (!state.IsReady(RequireAllDataForReady))
                    return ValueTask.FromResult(
                        new LoRaFragmentStoreApplyResult(
                            LoRaFragmentStoreApplyStatus.Incomplete));

                return ValueTask.FromResult(
                    new LoRaFragmentStoreApplyResult(
                        LoRaFragmentStoreApplyStatus.Ready,
                        state.Snapshot(SnapshotReplayScopeOverride)));
            }
        }

        public ValueTask<LoRaFragmentStoreCommitResult> TryCommitTerminalAsync(
            LoRaFragmentTerminalCommit terminal,
            LoRaFragmentReassemblyPolicy policy,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                var key = Key.From(terminal.Key);
                if (!_states.TryGetValue(key, out var state) ||
                    state.Generation != terminal.Generation ||
                    state.Terminal is not null)
                {
                    return ValueTask.FromResult(
                        new LoRaFragmentStoreCommitResult(
                            LoRaFragmentStoreCommitStatus.GenerationMismatch));
                }

                if (CommitStatus == LoRaFragmentStoreCommitStatus.Committed)
                    state.Terminal = terminal.Status;
                return ValueTask.FromResult(
                    new LoRaFragmentStoreCommitResult(CommitStatus));
            }
        }

        public ValueTask<LoRaFragmentReassemblySnapshot?> ReadAsync(
            LoRaFragmentReplayKey key,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                return ValueTask.FromResult(
                    _states.TryGetValue(Key.From(key), out var state) &&
                    state.Terminal is null
                        ? state.Snapshot()
                        : null);
            }
        }

        private int IncompleteCountNoLock() =>
            _states.Values.Count(state => state.Terminal is null);

        private int IncompleteCountForScopeNoLock(LoRaFragmentReplayScopeHandle scope) =>
            _states.Values.Count(state =>
                state.Terminal is null &&
                ReferenceEquals(state.Key.ReplayScope, scope));

        private int ReservedBytesNoLock() =>
            _states.Values.Where(state => state.Terminal is null)
                .Sum(state => state.ReservationCharge);

        private sealed class State
        {
            public State(
                LoRaFragmentReplayKey key,
                LoRaFragmentHeader shape,
                uint expiryBucket,
                int reservationCharge)
            {
                Key = key;
                Shape = shape;
                ExpiryBucket = expiryBucket;
                ReservationCharge = reservationCharge;
                CanonicalByOrdinal = new byte[shape.TotalFragmentCount][];
                Data = new byte[shape.DataShardCount][];
                Parity = new byte[shape.ParityShardCount][];
            }

            public LoRaFragmentReplayKey Key { get; }
            public LoRaFragmentHeader Shape { get; }
            public uint ExpiryBucket { get; set; }
            public int ReservationCharge { get; }
            public long Generation { get; set; }
            public LoRaFragmentTerminalStatus? Terminal { get; set; }
            public byte[]?[] CanonicalByOrdinal { get; }
            public byte[]?[] Data { get; }
            public byte[]?[] Parity { get; }

            public bool Matches(LoRaFragmentHeader header) =>
                Shape.MessageId.Span.SequenceEqual(header.MessageId.Span) &&
                Shape.DataShardCount == header.DataShardCount &&
                Shape.ParityShardCount == header.ParityShardCount &&
                Shape.ShardSize == header.ShardSize &&
                Shape.FecMode == header.FecMode;

            public bool IsReady(bool requireAllData)
            {
                if (Data.All(static shard => shard is not null))
                    return true;
                if (requireAllData)
                    return false;
                if (Shape.FecMode != LoRaFragmentFecMode.Xor1)
                    return false;
                for (var group = 0; group < Shape.ParityShardCount; group++)
                {
                    var first = group * LoRaFragmentLimits.XorDataShardsPerGroup;
                    var end = Math.Min(
                        Shape.DataShardCount,
                        first + LoRaFragmentLimits.XorDataShardsPerGroup);
                    var missing = 0;
                    for (var index = first; index < end; index++)
                        if (Data[index] is null)
                            missing++;
                    if (missing > 1 || missing == 1 && Parity[group] is null)
                        return false;
                }

                return true;
            }

            public LoRaFragmentReassemblySnapshot Snapshot(
                LoRaFragmentReplayScopeHandle? replayScopeOverride = null) =>
                new(
                    replayScopeOverride is null
                        ? Key
                        : new LoRaFragmentReplayKey(
                            replayScopeOverride,
                            Key.Direction,
                            Key.MessageId.Span),
                    Shape,
                    Generation,
                    ExpiryBucket,
                    Data.Select(static shard =>
                        shard is null ? null : (ReadOnlyMemory<byte>?)shard),
                    Parity.Select(static shard =>
                        shard is null ? null : (ReadOnlyMemory<byte>?)shard));
        }

        private sealed record Key(
            LoRaFragmentReplayScopeHandle Scope,
            LoRaFragmentDirection Direction,
            string MessageId)
        {
            public static Key From(LoRaFragmentReplayKey key) =>
                new(
                    key.ReplayScope,
                    key.Direction,
                    Convert.ToHexString(key.MessageId.Span));
        }
    }

    private sealed class AuthenticationProvider
        : LoRaFragmentAuthenticationHandleProviderBase
    {
        private readonly Dictionary<LoRaFragmentAuthenticationHandle, byte[]> _keys = [];

        public override LoRaFragmentAuthenticationHandle GetAuthenticationHandle() =>
            Create(
                Enumerable.Range(0x90, 32).Select(static value => (byte)value).ToArray());

        public LoRaFragmentAuthenticationHandle Create(byte[] key)
        {
            var handle = CreateOpaqueAuthenticationHandle();
            _keys.Add(handle, key.ToArray());
            return handle;
        }

        public byte[] Resolve(LoRaFragmentAuthenticationHandle handle) =>
            _keys.TryGetValue(handle, out var key)
                ? key
                : throw new InvalidOperationException("Unknown test authentication handle.");
    }

    private sealed class ReplayProvider : LoRaFragmentReplayScopeHandleProviderBase
    {
        public override LoRaFragmentReplayScopeHandle GetReplayScopeHandle() =>
            Create();

        public LoRaFragmentReplayScopeHandle Create() =>
            CreateOpaqueReplayScopeHandle();
    }

    private sealed class HmacTestAuthenticator(AuthenticationProvider provider)
        : ILoRaFragmentAuthenticator
    {
        public byte[] CreateTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript) =>
            HMACSHA256.HashData(
                provider.Resolve(authenticationHandle),
                canonicalTranscript)[..LoRaFragmentLimits.AuthenticationTagLength];

        public bool VerifyTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript,
            ReadOnlySpan<byte> authenticationTag)
        {
            var expected = CreateTag(
                domain,
                authenticationHandle,
                direction,
                canonicalTranscript);
            return authenticationTag.Length == expected.Length &&
                   CryptographicOperations.FixedTimeEquals(expected, authenticationTag);
        }
    }

    private sealed class ThrowingAuthenticator(Exception exception)
        : ILoRaFragmentAuthenticator
    {
        public byte[] CreateTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript) =>
            throw exception;

        public bool VerifyTag(
            ReadOnlySpan<byte> domain,
            LoRaFragmentAuthenticationHandle authenticationHandle,
            LoRaFragmentDirection direction,
            ReadOnlySpan<byte> canonicalTranscript,
            ReadOnlySpan<byte> authenticationTag) =>
            throw exception;
    }
}
