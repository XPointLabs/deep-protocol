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

    [Theory]
    [InlineData(17)]
    [InlineData(41)]
    [InlineData(73)]
    public async Task FixedSeedPermutationsReassembleExactly(int seed)
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var random = new Random(seed);
        var order = fixture.Plan.Frames
            .Select(frame => (Frame: frame, Rank: random.Next()))
            .OrderBy(static item => item.Rank)
            .Select(static item => item.Frame)
            .ToArray();
        var reassembler = fixture.Reassembler(new MemoryReplayStore());
        LoRaFragmentReassemblyResult? result = null;

        foreach (var frame in order)
        {
            result = await reassembler.ProcessAsync(fixture.Request(frame));
            if (result.Outcome == LoRaFragmentReassemblyOutcome.Completed)
            {
                break;
            }
        }

        Assert.NotNull(result);
        Assert.Equal(LoRaFragmentReassemblyOutcome.Completed, result.Outcome);
        Assert.Equal(fixture.Bundle, result.EncodedOpaqueBundle!.Value.ToArray());
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
    public async Task Xor1RecoversOneLossInEachOfMultipleGroups()
    {
        var recoverable = new Fixture(LoRaFragmentFecMode.Xor1, shardSize: 32);
        Assert.True(recoverable.Plan.DataShardCount > LoRaFragmentLimits.XorDataShardsPerGroup);
        var reassembler = recoverable.Reassembler(new MemoryReplayStore());
        LoRaFragmentReassemblyResult? recovered = null;
        foreach (var frame in recoverable.Plan.Frames.Where(
                     (_, index) => index is not 1 and not 8))
        {
            recovered = await reassembler.ProcessAsync(recoverable.Request(frame));
        }

        Assert.NotNull(recovered);
        Assert.Equal(LoRaFragmentReassemblyOutcome.Completed, recovered.Outcome);
        Assert.Equal(recoverable.Bundle, recovered.EncodedOpaqueBundle!.Value.ToArray());

        var unrecoverable = new Fixture(LoRaFragmentFecMode.Xor1, shardSize: 32);
        var second = unrecoverable.Reassembler(new MemoryReplayStore());
        LoRaFragmentReassemblyResult? incomplete = null;
        foreach (var frame in unrecoverable.Plan.Frames.Where(
                     (_, index) => index is not 1 and not 2))
        {
            incomplete = await second.ProcessAsync(unrecoverable.Request(frame));
        }

        Assert.NotNull(incomplete);
        Assert.Equal(LoRaFragmentReassemblyOutcome.Incomplete, incomplete.Outcome);
    }

    [Fact]
    public async Task Xor1RecoveredOrdinalZeroTightensExpiryAndCompletesAcrossRestart()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.Xor1);
        var store = new MemoryReplayStore();
        var reassembler = fixture.Reassembler(store);
        LoRaFragmentReassemblyResult? result = null;

        foreach (var ordinal in new[] { 3, 4, 1, 5, 2 })
        {
            result = await reassembler.ProcessAsync(
                fixture.Request(fixture.Plan.Frames[ordinal]));
        }

        Assert.NotNull(result);
        Assert.Equal(LoRaFragmentReassemblyOutcome.Completed, result.Outcome);
        Assert.Equal(fixture.Bundle, result.EncodedOpaqueBundle!.Value.ToArray());
        Assert.Equal(100u, store.CompletedExpiryBucket);

        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Rejected,
            (await reassembler.ProcessAsync(
                fixture.Request(fixture.Plan.Frames[0]))).Outcome);
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Rejected,
            (await fixture.Reassembler(store).ProcessAsync(
                fixture.Request(fixture.Plan.Frames[0]))).Outcome);
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
    [InlineData(0, 0x02)]
    [InlineData(1, 0x02)]
    [InlineData(2, 0x02)]
    [InlineData(3, 0x11)]
    [InlineData(4, 0x00)]
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
    public async Task AuthenticatedNoncanonicalPaddingPoisons()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore();
        var reassembler = fixture.Reassembler(store);
        var lastIndex = fixture.Plan.DataShardCount - 1;
        var last = LoRaFragmentCodec.Decode(
            fixture.Plan.Frames[lastIndex].Span,
            fixture.FragmentPolicy,
            fixture.AuthenticationHandle,
            LoRaFragmentDirection.Forward,
            fixture.Authenticator);
        var changedShard = last.Shard.ToArray();
        changedShard[^1] = 1;
        var changedLast = LoRaFragmentCodec.Encode(
            new LoRaFragmentUnsignedFrame(last.Header, changedShard),
            fixture.AuthenticationHandle,
            LoRaFragmentDirection.Forward,
            fixture.Authenticator);

        LoRaFragmentReassemblyResult? result = null;
        foreach (var frame in fixture.Plan.Frames
                     .Take(lastIndex)
                     .Append(changedLast))
        {
            result = await reassembler.ProcessAsync(fixture.Request(frame));
        }

        Assert.NotNull(result);
        Assert.Equal(LoRaFragmentReassemblyOutcome.Rejected, result.Outcome);
        Assert.Equal(1, store.PoisonedCount);
    }

    [Fact]
    public async Task AuthenticatedNoncanonicalDataCountPoisons()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore();
        var reassembler = fixture.Reassembler(store);
        var expandedFrames = new List<byte[]>();
        foreach (var encoded in fixture.Plan.Frames)
        {
            var decoded = LoRaFragmentCodec.Decode(
                encoded.Span,
                fixture.FragmentPolicy,
                fixture.AuthenticationHandle,
                LoRaFragmentDirection.Forward,
                fixture.Authenticator);
            var expandedHeader = new LoRaFragmentHeader(
                decoded.Header.MessageId.Span,
                decoded.Header.Ordinal,
                checked((byte)(fixture.Plan.DataShardCount + 1)),
                parityShardCount: 0,
                fixture.ShardSize,
                LoRaFragmentFecMode.None);
            expandedFrames.Add(LoRaFragmentCodec.Encode(
                new LoRaFragmentUnsignedFrame(expandedHeader, decoded.Shard.Span),
                fixture.AuthenticationHandle,
                LoRaFragmentDirection.Forward,
                fixture.Authenticator));
        }

        var finalHeader = new LoRaFragmentHeader(
            fixture.Plan.Frames[0].Span.Slice(4, LoRaFragmentLimits.MessageIdLength),
            checked((byte)fixture.Plan.DataShardCount),
            checked((byte)(fixture.Plan.DataShardCount + 1)),
            parityShardCount: 0,
            fixture.ShardSize,
            LoRaFragmentFecMode.None);
        expandedFrames.Add(LoRaFragmentCodec.Encode(
            new LoRaFragmentUnsignedFrame(finalHeader, new byte[fixture.ShardSize]),
            fixture.AuthenticationHandle,
            LoRaFragmentDirection.Forward,
            fixture.Authenticator));

        LoRaFragmentReassemblyResult? result = null;
        foreach (var frame in expandedFrames)
        {
            result = await reassembler.ProcessAsync(fixture.Request(frame));
        }

        Assert.NotNull(result);
        Assert.Equal(LoRaFragmentReassemblyOutcome.Rejected, result.Outcome);
        Assert.Equal(1, store.PoisonedCount);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(14, 15)]
    public void PlannerAcceptsExactHopBoundaries(byte currentHop, byte hopLimit)
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var plan = fixture.CreatePlan(
            new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 },
            currentHop,
            hopLimit);

        Assert.Equal(currentHop, plan.Descriptor.CurrentHop);
        Assert.Equal(hopLimit, plan.Descriptor.HopLimit);
    }

    [Fact]
    public void PlannerRejectsEqualMaximumHopAndLimit()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            fixture.CreatePlan(
                new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 },
                currentHop: 15,
                hopLimit: 15));
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
    public async Task ForeignScopeSnapshotNeverPoisonsThatScope()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore();
        var alternateScope = fixture.ReplayProvider.Create();
        var reassembler = fixture.Reassembler(store);
        foreach (var frame in fixture.Plan.Frames.Take(4))
        {
            Assert.Equal(
                LoRaFragmentReassemblyOutcome.Incomplete,
                (await reassembler.ProcessAsync(
                    fixture.Request(frame, alternateScope))).Outcome);
        }

        store.SnapshotReplayScopeOverride = alternateScope;
        store.SnapshotGenerationOverride = 4;
        LoRaFragmentReassemblyResult? foreign = null;
        foreach (var frame in fixture.Plan.Frames)
        {
            foreign = await reassembler.ProcessAsync(fixture.Request(frame));
        }

        Assert.NotNull(foreign);
        Assert.Equal(LoRaFragmentReassemblyOutcome.OutcomeUnknown, foreign.Outcome);
        Assert.Equal(0, store.PoisonedCount);

        store.SnapshotReplayScopeOverride = null;
        store.SnapshotGenerationOverride = null;
        var completed = await reassembler.ProcessAsync(
            fixture.Request(fixture.Plan.Frames[4], alternateScope));
        Assert.Equal(LoRaFragmentReassemblyOutcome.Completed, completed.Outcome);
        Assert.Equal(fixture.Bundle, completed.EncodedOpaqueBundle!.Value.ToArray());
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
    public async Task CompletedResultCarriesDescriptorForRelayRefragmentation()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var reassembler = fixture.Reassembler(new MemoryReplayStore());
        LoRaFragmentReassemblyResult? completed = null;
        foreach (var frame in fixture.Plan.Frames)
        {
            completed = await reassembler.ProcessAsync(fixture.Request(frame));
        }

        Assert.NotNull(completed);
        Assert.Equal(LoRaFragmentReassemblyOutcome.Completed, completed.Outcome);
        var descriptorProperty = typeof(LoRaFragmentReassemblyResult)
            .GetProperty("Descriptor");
        Assert.NotNull(descriptorProperty);
        var descriptor = Assert.IsType<LoRaFragmentDescriptor>(
            descriptorProperty.GetValue(completed));
        Assert.Equal((byte)0, descriptor.CurrentHop);
        Assert.Equal((byte)3, descriptor.HopLimit);
        Assert.Equal(100u, descriptor.ExpiryBucket);

        var relayPlan = LoRaFragmentPlanner.Plan(
            new LoRaFragmentPlanRequest(
                completed.EncodedOpaqueBundle!.Value.Span,
                new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 },
                checked((byte)(descriptor.CurrentHop + 1)),
                descriptor.HopLimit,
                fixture.ShardSize,
                LoRaFragmentFecMode.None,
                LoRaFragmentDirection.Forward,
                fixture.AuthenticationHandle),
            fixture.FragmentPolicy,
            fixture.Authenticator);
        Assert.Equal((byte)1, relayPlan.Descriptor.CurrentHop);
        Assert.Equal(fixture.Bundle, completed.EncodedOpaqueBundle.Value.ToArray());
    }

    [Fact]
    public void ReplayStoreReadContractRepresentsTerminalRecords()
    {
        var read = typeof(ILoRaFragmentReplayStore).GetMethod("ReadAsync");

        Assert.NotNull(read);
        Assert.Contains(
            "LoRaFragmentReplayRecord",
            read.ReturnType.FullName,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task PostCommitExceptionPerformsBoundedReconciliationWithoutPayload()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore
        {
            ThrowAfterCommit = true
        };
        var reassembler = fixture.Reassembler(store);
        LoRaFragmentReassemblyResult? result = null;
        foreach (var frame in fixture.Plan.Frames)
        {
            result = await reassembler.ProcessAsync(fixture.Request(frame));
        }

        Assert.NotNull(result);
        Assert.Equal(LoRaFragmentReassemblyOutcome.OutcomeUnknown, result.Outcome);
        Assert.Null(result.EncodedOpaqueBundle);
        Assert.Equal(1, store.CompletedCount);
        Assert.Equal(1, store.ReadCalls);
        Assert.True(store.LastReadTokenCanBeCanceled);
    }

    [Fact]
    public async Task ReconciliationTimeoutBoundsStoreThatIgnoresCancellation()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore
        {
            CommitStatus = LoRaFragmentStoreCommitStatus.OutcomeUnknown,
            NeverCompleteRead = true
        };
        var policy = fixture.CreateReassemblyPolicy(
            reconciliationTimeout: TimeSpan.FromMilliseconds(50));
        var reassembler = fixture.Reassembler(store, policy);
        LoRaFragmentReassemblyResult? result = null;
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        foreach (var frame in fixture.Plan.Frames)
        {
            result = await reassembler.ProcessAsync(fixture.Request(frame))
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(2));
        }

        stopwatch.Stop();
        Assert.NotNull(result);
        Assert.Equal(LoRaFragmentReassemblyOutcome.OutcomeUnknown, result.Outcome);
        Assert.Null(result.EncodedOpaqueBundle);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task WrappedFatalCancellationIsNeverNormalized()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var fatal = new OutOfMemoryException("wrapped fragment fatal canary");
        var wrapped = new OperationCanceledException("wrapper", fatal);
        var authentication = new LoRaFragmentReassembler(
            new MemoryReplayStore(),
            fixture.ReassemblyPolicy,
            new ThrowingAuthenticator(wrapped));

        var authThrown = await Assert.ThrowsAsync<OperationCanceledException>(
            async () => await authentication.ProcessAsync(
                fixture.Request(fixture.Plan.Frames[0])));
        Assert.Same(fatal, authThrown.InnerException);

        var applyStore = new MemoryReplayStore
        {
            ApplyException = wrapped
        };
        var applyThrown = await Assert.ThrowsAsync<OperationCanceledException>(
            async () => await fixture.Reassembler(applyStore).ProcessAsync(
                fixture.Request(fixture.Plan.Frames[0])));
        Assert.Same(fatal, applyThrown.InnerException);

        var commitStore = new MemoryReplayStore
        {
            CommitException = wrapped
        };
        var terminal = fixture.Reassembler(commitStore);
        OperationCanceledException? commitThrown = null;
        foreach (var frame in fixture.Plan.Frames)
        {
            try
            {
                _ = await terminal.ProcessAsync(fixture.Request(frame));
            }
            catch (OperationCanceledException exception)
            {
                commitThrown = exception;
                break;
            }
        }

        Assert.NotNull(commitThrown);
        Assert.Same(fatal, commitThrown.InnerException);
    }

    [Fact]
    public async Task CallerCancellationBeforeAuthenticationNeverMutatesStore()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await fixture.Reassembler(store).ProcessAsync(
                fixture.Request(fixture.Plan.Frames[0]),
                cancellation.Token));
        Assert.Equal(0, store.ApplyCalls);
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
    public async Task ReservationChargeBoundaryIsExactAndAdmissionIsAtomic()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.Xor1);
        var charge = checked(
            fixture.Plan.Frames.Count * fixture.ShardSize +
            LoRaFragmentReassemblyLimits.ReservationMetadataBytes);
        var rejectedStore = new MemoryReplayStore();
        var rejectedPolicy = fixture.CreateReassemblyPolicy(
            maximumReservedBytesGlobal: charge - 1);

        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Rejected,
            (await fixture.Reassembler(rejectedStore, rejectedPolicy).ProcessAsync(
                fixture.Request(fixture.Plan.Frames[0]))).Outcome);
        Assert.Equal(0, rejectedStore.IncompleteCount);

        var admittedStore = new MemoryReplayStore();
        var admittedPolicy = fixture.CreateReassemblyPolicy(
            maximumReservedBytesGlobal: charge);
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Incomplete,
            (await fixture.Reassembler(admittedStore, admittedPolicy).ProcessAsync(
                fixture.Request(fixture.Plan.Frames[0]))).Outcome);
        Assert.Equal(1, admittedStore.IncompleteCount);
    }

    [Fact]
    public async Task AbsoluteGlobalCountPressureRejectsSeventeenthLiveId()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var store = new MemoryReplayStore();
        var reassembler = fixture.Reassembler(store);
        for (var index = 1;
             index <= LoRaFragmentReassemblyLimits.MaximumIncompleteMessagesGlobal;
             index++)
        {
            var plan = fixture.CreatePlan(Enumerable.Repeat((byte)index, 8).ToArray());
            Assert.Equal(
                LoRaFragmentReassemblyOutcome.Incomplete,
                (await reassembler.ProcessAsync(
                    fixture.Request(
                        plan.Frames[0],
                        fixture.ReplayProvider.Create()))).Outcome);
        }

        var overflowPlan = fixture.CreatePlan(
            Enumerable.Repeat(
                (byte)(LoRaFragmentReassemblyLimits.MaximumIncompleteMessagesGlobal + 1),
                8).ToArray());
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Rejected,
            (await reassembler.ProcessAsync(
                fixture.Request(
                    overflowPlan.Frames[0],
                    fixture.ReplayProvider.Create()))).Outcome);
        Assert.Equal(
            LoRaFragmentReassemblyLimits.MaximumIncompleteMessagesGlobal,
            store.IncompleteCount);
    }

    [Fact]
    public async Task ExpiredStateRejectsReplayAcrossRestartThenPurgesBeforeAdmission()
    {
        var fixture = new Fixture(
            LoRaFragmentFecMode.None,
            maximumIncompleteMessagesGlobal: 1);
        var store = new MemoryReplayStore();
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Incomplete,
            (await fixture.Reassembler(store).ProcessAsync(
                fixture.Request(fixture.Plan.Frames[0]))).Outcome);

        var atRetention = fixture.CreateReassemblyPolicy(
            currentExpiryBucket: 101,
            provisionalExpiryBucket: 101,
            maximumIncompleteMessagesGlobal: 1,
            maximumTombstonesGlobal: 1);
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Rejected,
            (await fixture.Reassembler(store, atRetention).ProcessAsync(
                fixture.Request(fixture.Plan.Frames[0]))).Outcome);

        var afterRetention = fixture.CreateReassemblyPolicy(
            currentExpiryBucket: 102,
            provisionalExpiryBucket: 102,
            maximumIncompleteMessagesGlobal: 1,
            maximumTombstonesGlobal: 1);
        var replacement = fixture.CreatePlan(
            new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 });
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Incomplete,
            (await fixture.Reassembler(store, afterRetention).ProcessAsync(
                fixture.Request(replacement.Frames[1]))).Outcome);
        Assert.Equal(1, store.IncompleteCount);
    }

    [Fact]
    public async Task TombstoneScopeAndByteCeilingsBlockNewAdmission()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var scopeStore = new MemoryReplayStore();
        var scopePolicy = fixture.CreateReassemblyPolicy(
            maximumTombstonesPerReplayScope: 1);
        LoRaFragmentReassemblyResult? completed = null;
        foreach (var frame in fixture.Plan.Frames)
        {
            completed = await fixture.Reassembler(scopeStore, scopePolicy)
                .ProcessAsync(fixture.Request(frame));
        }

        Assert.Equal(LoRaFragmentReassemblyOutcome.Completed, completed!.Outcome);
        var next = fixture.CreatePlan(new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 });
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Rejected,
            (await fixture.Reassembler(scopeStore, scopePolicy).ProcessAsync(
                fixture.Request(next.Frames[0]))).Outcome);
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Incomplete,
            (await fixture.Reassembler(scopeStore, scopePolicy).ProcessAsync(
                fixture.Request(
                    next.Frames[0],
                    fixture.ReplayProvider.Create()))).Outcome);

        var bytesStore = new MemoryReplayStore();
        var bytesPolicy = fixture.CreateReassemblyPolicy(
            maximumTombstoneBytesGlobal: 64);
        foreach (var frame in fixture.Plan.Frames)
        {
            completed = await fixture.Reassembler(bytesStore, bytesPolicy)
                .ProcessAsync(fixture.Request(frame));
        }

        Assert.Equal(LoRaFragmentReassemblyOutcome.Completed, completed!.Outcome);
        Assert.Equal(
            LoRaFragmentReassemblyOutcome.Rejected,
            (await fixture.Reassembler(bytesStore, bytesPolicy).ProcessAsync(
                fixture.Request(
                    next.Frames[0],
                    fixture.ReplayProvider.Create()))).Outcome);
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

    [Fact]
    public void SnapshotRejectsOverlongShardEnumerableAtAuthenticatedBound()
    {
        var fixture = new Fixture(LoRaFragmentFecMode.None);
        var header = LoRaFragmentCodec.Decode(
            fixture.Plan.Frames[0].Span,
            fixture.FragmentPolicy,
            fixture.AuthenticationHandle,
            LoRaFragmentDirection.Forward,
            fixture.Authenticator).Header;
        var key = new LoRaFragmentReplayKey(
            fixture.ReplayScope,
            LoRaFragmentDirection.Forward,
            header.MessageId.Span);
        var overlong = new OverlongShardEnumerable(
            new byte[header.ShardSize],
            throwAfter: 100);

        Assert.Throws<ArgumentException>(() =>
            new LoRaFragmentReassemblySnapshot(
                key,
                header,
                generation: 1,
                expiryBucket: 100,
                overlong,
                Array.Empty<ReadOnlyMemory<byte>?>()));
        Assert.True(
            overlong.MoveNextCalls <= header.DataShardCount + 1,
            $"The constructor consumed {overlong.MoveNextCalls} elements.");
    }

    private sealed class OverlongShardEnumerable(
        ReadOnlyMemory<byte> shard,
        int throwAfter)
        : IEnumerable<ReadOnlyMemory<byte>?>
    {
        public int MoveNextCalls { get; private set; }

        public IEnumerator<ReadOnlyMemory<byte>?> GetEnumerator()
        {
            while (true)
            {
                MoveNextCalls++;
                if (MoveNextCalls > throwAfter)
                {
                    throw new InvalidOperationException(
                        "The bounded consumer read a pathological tail.");
                }

                yield return shard;
            }
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() =>
            GetEnumerator();
    }

    private sealed class Fixture
    {
        private static readonly byte[] MessageId = [1, 2, 3, 4, 5, 6, 7, 8];
        private readonly AuthenticationProvider _authenticationProvider = new();

        public Fixture(
            LoRaFragmentFecMode fecMode,
            byte shardSize = 64,
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
                    MaximumExpiryBucket = 105
                });
            ReassemblyPolicy = CreateReassemblyPolicy(
                maximumIncompleteMessagesPerReplayScope:
                    maximumIncompleteMessagesPerReplayScope,
                maximumIncompleteMessagesGlobal: maximumIncompleteMessagesGlobal);
            Bundle = CreateBundle();
            FecMode = fecMode;
            ShardSize = shardSize;
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
        public byte ShardSize { get; }
        public LoRaFragmentPlan Plan { get; }

        public LoRaFragmentPlan CreatePlan(
            byte[] messageId,
            byte currentHop = 0,
            byte hopLimit = 3) =>
            LoRaFragmentPlanner.Plan(
                new LoRaFragmentPlanRequest(
                    Bundle,
                    messageId,
                    currentHop,
                    hopLimit,
                    ShardSize,
                    FecMode,
                    LoRaFragmentDirection.Forward,
                    AuthenticationHandle),
                FragmentPolicy,
                Authenticator);

        public LoRaFragmentReassemblyPolicy CreateReassemblyPolicy(
            uint currentExpiryBucket = 99,
            uint provisionalExpiryBucket = 101,
            uint acceptedExpirySkewBuckets = 1,
            int maximumIncompleteMessagesPerReplayScope =
                LoRaFragmentReassemblyLimits.MaximumIncompleteMessagesPerReplayScope,
            int maximumIncompleteMessagesGlobal =
                LoRaFragmentReassemblyLimits.MaximumIncompleteMessagesGlobal,
            int maximumReservedBytesGlobal =
                LoRaFragmentReassemblyLimits.MaximumReservedBytesGlobal,
            int maximumTombstonesPerReplayScope =
                LoRaFragmentReassemblyLimits.MaximumTombstonesPerReplayScope,
            int maximumTombstonesGlobal =
                LoRaFragmentReassemblyLimits.MaximumTombstonesGlobal,
            int maximumTombstoneBytesGlobal =
                LoRaFragmentReassemblyLimits.MaximumTombstoneBytesGlobal,
            TimeSpan reconciliationTimeout = default) =>
            new(
                FragmentPolicy,
                currentExpiryBucket,
                provisionalExpiryBucket,
                acceptedExpirySkewBuckets,
                maximumIncompleteMessagesPerReplayScope,
                maximumIncompleteMessagesGlobal,
                maximumReservedBytesGlobal,
                maximumTombstonesPerReplayScope,
                maximumTombstonesGlobal,
                maximumTombstoneBytesGlobal,
                reconciliationTimeout);

        public LoRaFragmentReassembler Reassembler(
            ILoRaFragmentReplayStore store,
            LoRaFragmentReassemblyPolicy? policy = null) =>
            new(store, policy ?? ReassemblyPolicy, Authenticator);

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
        private const int TombstoneCharge = 64;
        private readonly object _gate = new();
        private readonly Dictionary<Key, State> _states = [];

        public LoRaFragmentStoreCommitStatus CommitStatus { get; set; } =
            LoRaFragmentStoreCommitStatus.Committed;
        public LoRaFragmentReplayScopeHandle? SnapshotReplayScopeOverride { get; set; }
        public long? SnapshotGenerationOverride { get; set; }
        public bool RequireAllDataForReady { get; set; }
        public bool ThrowAfterCommit { get; set; }
        public bool NeverCompleteRead { get; set; }
        public Exception? ApplyException { get; set; }
        public Exception? CommitException { get; set; }
        public int ApplyCalls { get; private set; }
        public int ReadCalls { get; private set; }
        public bool LastReadTokenCanBeCanceled { get; private set; }
        public int CompletedCount
        {
            get
            {
                lock (_gate)
                    return _states.Values.Count(state =>
                        state.Terminal == LoRaFragmentTerminalStatus.Completed &&
                        !state.Expired);
            }
        }
        public int PoisonedCount
        {
            get
            {
                lock (_gate)
                    return _states.Values.Count(state =>
                        state.Terminal == LoRaFragmentTerminalStatus.Poisoned &&
                        !state.Expired);
            }
        }
        public int IncompleteCount
        {
            get
            {
                lock (_gate)
                    return _states.Values.Count(state =>
                        state.Terminal is null && !state.Expired);
            }
        }
        public uint? CompletedExpiryBucket
        {
            get
            {
                lock (_gate)
                    return _states.Values.SingleOrDefault(state =>
                        state.Terminal == LoRaFragmentTerminalStatus.Completed)
                        ?.ExpiryBucket;
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
                if (ApplyException is not null)
                    throw ApplyException;
                EvictExpiredNoLock(policy);
                var key = Key.From(fragment.Key);
                if (_states.TryGetValue(key, out var state))
                {
                    if (state.Terminal is not null || state.Expired)
                        return ValueTask.FromResult(
                            new LoRaFragmentStoreApplyResult(
                                LoRaFragmentStoreApplyStatus.Rejected));
                    if (!state.Matches(fragment.Frame.Header))
                    {
                        state.Terminal = LoRaFragmentTerminalStatus.Poisoned;
                        state.RetentionExpiryBucket =
                            policy.GetRetentionExpiryBucket(state.ExpiryBucket);
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
                        policy.MaximumReservedBytesGlobal ||
                        TombstoneCountForScopeNoLock(fragment.Key.ReplayScope) >=
                        policy.MaximumTombstonesPerReplayScope ||
                        TombstoneCountNoLock() >= policy.MaximumTombstonesGlobal ||
                        checked(TombstoneCountNoLock() * TombstoneCharge) >=
                        policy.MaximumTombstoneBytesGlobal)
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
                        state.RetentionExpiryBucket =
                            policy.GetRetentionExpiryBucket(state.ExpiryBucket);
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
                        if (expiry < policy.CurrentExpiryBucket ||
                            expiry > state.ExpiryBucket)
                        {
                            state.Expired = true;
                            state.RetentionExpiryBucket = expiry > uint.MaxValue -
                                policy.AcceptedExpirySkewBuckets
                                    ? uint.MaxValue
                                    : expiry + policy.AcceptedExpirySkewBuckets;
                            return ValueTask.FromResult(
                                new LoRaFragmentStoreApplyResult(
                                    LoRaFragmentStoreApplyStatus.Rejected));
                        }

                        if (expiry <= state.ExpiryBucket)
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
                        state.Snapshot(
                            SnapshotReplayScopeOverride,
                            SnapshotGenerationOverride)));
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
                if (CommitException is not null)
                    throw CommitException;
                EvictExpiredNoLock(policy);
                var key = Key.From(terminal.Key);
                if (!_states.TryGetValue(key, out var state) ||
                    state.Generation != terminal.Generation ||
                    state.Terminal is not null ||
                    state.Expired ||
                    terminal.ExpiryBucket > state.ExpiryBucket ||
                    terminal.RetentionExpiryBucket !=
                    policy.GetRetentionExpiryBucket(terminal.ExpiryBucket))
                {
                    return ValueTask.FromResult(
                        new LoRaFragmentStoreCommitResult(
                            LoRaFragmentStoreCommitStatus.GenerationMismatch));
                }

                if (CommitStatus == LoRaFragmentStoreCommitStatus.Committed)
                {
                    state.Terminal = terminal.Status;
                    state.ExpiryBucket = terminal.ExpiryBucket;
                    state.RetentionExpiryBucket = terminal.RetentionExpiryBucket;
                    state.BundleDigest = terminal.BundleDigest?.ToArray();
                    if (ThrowAfterCommit)
                    {
                        throw new IOException(
                            "Simulated unknown result after durable terminal commit.");
                    }
                }
                return ValueTask.FromResult(
                    new LoRaFragmentStoreCommitResult(CommitStatus));
            }
        }

        public ValueTask<LoRaFragmentReplayRecord> ReadAsync(
            LoRaFragmentReplayKey key,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (NeverCompleteRead)
            {
                var pending =
                    new TaskCompletionSource<LoRaFragmentReplayRecord>(
                        TaskCreationOptions.RunContinuationsAsynchronously);
                return new ValueTask<LoRaFragmentReplayRecord>(pending.Task);
            }

            lock (_gate)
            {
                ReadCalls++;
                LastReadTokenCanBeCanceled = cancellationToken.CanBeCanceled;
                if (!_states.TryGetValue(Key.From(key), out var state))
                {
                    return ValueTask.FromResult(
                        new LoRaFragmentReplayRecord(
                            key,
                            LoRaFragmentReplayRecordStatus.Absent,
                            generation: 0,
                            expiryBucket: 0,
                            retentionExpiryBucket: 0));
                }

                if (state.Terminal is null && !state.Expired)
                {
                    var snapshot = state.Snapshot();
                    return ValueTask.FromResult(
                        new LoRaFragmentReplayRecord(
                            state.Key,
                            LoRaFragmentReplayRecordStatus.Incomplete,
                            state.Generation,
                            state.ExpiryBucket,
                            retentionExpiryBucket: 0,
                            snapshot));
                }

                var status = state.Expired
                    ? LoRaFragmentReplayRecordStatus.Expired
                    : state.Terminal == LoRaFragmentTerminalStatus.Completed
                        ? LoRaFragmentReplayRecordStatus.Completed
                        : LoRaFragmentReplayRecordStatus.Poisoned;
                return ValueTask.FromResult(
                    new LoRaFragmentReplayRecord(
                        state.Key,
                        status,
                        state.Generation,
                        state.ExpiryBucket,
                        state.RetentionExpiryBucket,
                        bundleDigest: state.BundleDigest ?? []));
            }
        }

        private int IncompleteCountNoLock() =>
            _states.Values.Count(state =>
                state.Terminal is null && !state.Expired);

        private int IncompleteCountForScopeNoLock(LoRaFragmentReplayScopeHandle scope) =>
            _states.Values.Count(state =>
                state.Terminal is null &&
                !state.Expired &&
                ReferenceEquals(state.Key.ReplayScope, scope));

        private int ReservedBytesNoLock() =>
            _states.Values.Where(state =>
                    state.Terminal is null && !state.Expired)
                .Sum(state => state.ReservationCharge);

        private int TombstoneCountNoLock() =>
            _states.Values.Count(state =>
                state.Terminal is not null || state.Expired);

        private int TombstoneCountForScopeNoLock(
            LoRaFragmentReplayScopeHandle scope) =>
            _states.Values.Count(state =>
                (state.Terminal is not null || state.Expired) &&
                ReferenceEquals(state.Key.ReplayScope, scope));

        private void EvictExpiredNoLock(LoRaFragmentReassemblyPolicy policy)
        {
            foreach (var state in _states.Values)
            {
                if (state.Terminal is null &&
                    !state.Expired &&
                    state.ExpiryBucket < policy.CurrentExpiryBucket)
                {
                    state.Expired = true;
                    state.RetentionExpiryBucket =
                        checked(
                            state.ExpiryBucket +
                            policy.AcceptedExpirySkewBuckets);
                }
            }

            foreach (var key in _states
                         .Where(pair =>
                             (pair.Value.Terminal is not null ||
                              pair.Value.Expired) &&
                             pair.Value.RetentionExpiryBucket <
                             policy.CurrentExpiryBucket)
                         .Select(static pair => pair.Key)
                         .ToArray())
            {
                _states.Remove(key);
            }
        }

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
            public bool Expired { get; set; }
            public uint RetentionExpiryBucket { get; set; }
            public byte[]? BundleDigest { get; set; }
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
                LoRaFragmentReplayScopeHandle? replayScopeOverride = null,
                long? generationOverride = null) =>
                new(
                    replayScopeOverride is null
                        ? Key
                        : new LoRaFragmentReplayKey(
                            replayScopeOverride,
                            Key.Direction,
                            Key.MessageId.Span),
                    Shape,
                    generationOverride ?? Generation,
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
