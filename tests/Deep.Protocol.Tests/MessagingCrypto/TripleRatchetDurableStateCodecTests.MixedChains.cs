using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed partial class TripleRatchetTransactionsTests
{
    [Fact]
    public void DurableCodec_MixedChainSkippedKeysColdRoundTripAndConsumeWithoutProvider()
    {
        using var source = CreateMixedChainSkippedState();
        Assert.Equal(5, source.SkippedKeyCount);
        Assert.Equal(7UL, source.ReceivePqFrontier.SckaN);
        var exact = TripleRatchetDurableStateCodec.Encode(source);
        try
        {
            using var cold = TripleRatchetDurableStateCodec.Decode(exact);
            Assert.Equal(source.StateCommitment.ToArray(), cold.StateCommitment.ToArray());
            AssertExactDurableRoundTrip(cold, exact);
            var oldTarget = new RatchetCounterTuple(RatchetEcChainId.DarkDefaultForTests, 0, 1, 1);
            using var oldPlan = cold.PrepareReceive(new ThrowingProvider(), Persistence(cold),
                FreshDedup(cold, oldTarget, Bytes(131), Bytes(132), 133), oldTarget, Bytes(131), Bytes(132));
            Assert.Equal(RatchetPlanOutcome.OutOfOrderSkippedKey, oldPlan.Outcome);
            using var oldCommit = oldPlan.Commit(DurableSuccess(oldPlan));
            using var oldKey = oldCommit.TakeMessageKey();
            using var afterOld = oldCommit.TakeNextState();
            var nextExact = TripleRatchetDurableStateCodec.Encode(afterOld);
            try
            {
                using var nextCold = TripleRatchetDurableStateCodec.Decode(nextExact);
                AssertExactDurableRoundTrip(nextCold, nextExact);
                var newTarget = new RatchetCounterTuple(nextCold.ReceiveEcChain, 0, 1, 5);
                using var newPlan = nextCold.PrepareReceive(new ThrowingProvider(), Persistence(nextCold),
                    FreshDedup(nextCold, newTarget, Bytes(134), Bytes(135), 136), newTarget, Bytes(134), Bytes(135));
                Assert.Equal(RatchetPlanOutcome.OutOfOrderSkippedKey, newPlan.Outcome);
                using var newCommit = newPlan.Commit(DurableSuccess(newPlan));
                using var newKey = newCommit.TakeMessageKey();
                using var afterBoth = newCommit.TakeNextState();
                Assert.Equal(3, afterBoth.SkippedKeyCount);
                Assert.Equal(source.ReceivePqFrontier, afterBoth.ReceivePqFrontier);
            }
            finally { CryptographicOperations.ZeroMemory(nextExact); }
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    [Theory]
    [InlineData("reordered")]
    [InlineData("duplicate")]
    [InlineData("numeric-tie")]
    [InlineData("frontier")]
    public void DurableCodec_MixedChainHostileSkippedRecordsRejectBeforeAllocation(string defect)
    {
        using var source = CreateMixedChainSkippedState();
        var exact = TripleRatchetDurableStateCodec.Encode(source);
        var offset = DurableFixedPrefixBeforeComponent + checked((int)BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(528)));
        Assert.Equal(5U, BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(532)));
        // The first two canonical records have EcN=0 in different chains and distinct PQ counters.
        Assert.False(exact.AsSpan(offset, 32).SequenceEqual(exact.AsSpan(offset + DurableSkippedEntrySize, 32)));
        switch (defect)
        {
            case "reordered":
                var first = exact.AsSpan(offset, DurableSkippedEntrySize).ToArray();
                try
                {
                    exact.AsSpan(offset + DurableSkippedEntrySize, DurableSkippedEntrySize).CopyTo(exact.AsSpan(offset));
                    first.CopyTo(exact.AsSpan(offset + DurableSkippedEntrySize));
                }
                finally { CryptographicOperations.ZeroMemory(first); }
                break;
            case "duplicate":
                exact.AsSpan(offset, DurableSkippedEntrySize).CopyTo(exact.AsSpan(offset + DurableSkippedEntrySize));
                break;
            case "numeric-tie":
                exact.AsSpan(offset + 32, 24).CopyTo(exact.AsSpan(offset + DurableSkippedEntrySize + 32));
                break;
            case "frontier":
                BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(offset + DurableSkippedEntrySize + 32), source.NextExpectedReceiveEcN);
                break;
            default: throw new InvalidOperationException();
        }
        RewriteChecksum(exact);
        AssertPreAllocationRejection(exact, MessagingCryptoError.InvalidInput);
    }

    private static TripleRatchetState CreateMixedChainSkippedState()
    {
        using var source = CreateState();
        var oldChain = RatchetEcChainId.DarkDefaultForTests;
        var firstTarget = new RatchetCounterTuple(oldChain, 2, 1, 3);
        var firstHeader = EncodeDtr2(oldChain, 0, firstTarget);
        var newChain = RatchetEcChainId.FromPublicKey(Enumerable.Repeat((byte)0x6A, 32).ToArray());
        var secondTarget = new RatchetCounterTuple(newChain, 2, 1, 7);
        var secondHeader = EncodeDtr2(newChain, 4, secondTarget);
        try
        {
            using var firstPlan = source.PrepareReceive(new ScriptedProvider { BindPqKeyToChainAndCounter = true },
                Persistence(source), FreshDedup(source, firstTarget, Bytes(137), Bytes(138), 139),
                firstTarget, firstHeader, Bytes(137), Bytes(138));
            using var firstCommit = firstPlan.Commit(DurableSuccess(firstPlan));
            using var firstKey = firstCommit.TakeMessageKey();
            using var advanced = firstCommit.TakeNextState();
            using var secondPlan = advanced.PrepareReceive(new ScriptedProvider { BindPqKeyToChainAndCounter = true },
                Persistence(advanced), FreshDedup(advanced, secondTarget, Bytes(140), Bytes(141), 142),
                secondTarget, secondHeader, Bytes(140), Bytes(141));
            using var secondCommit = secondPlan.Commit(DurableSuccess(secondPlan));
            using var secondKey = secondCommit.TakeMessageKey();
            return secondCommit.TakeNextState();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstHeader);
            CryptographicOperations.ZeroMemory(secondHeader);
        }
    }

    private static void AssertExactDurableRoundTrip(TripleRatchetState state, byte[] expected)
    {
        var exact = TripleRatchetDurableStateCodec.Encode(state);
        try { Assert.Equal(expected, exact); }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }
}
