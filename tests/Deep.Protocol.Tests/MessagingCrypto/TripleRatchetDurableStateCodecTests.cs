using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed partial class TripleRatchetTransactionsTests
{
    private const int DurableFixedPrefixBeforeComponent = 536;
    private const int DurableSkippedEntrySize = 185;
    private const int DurableTrailerSize = 64;
    private const string DurableChecksumDomain = "Deep/LocalState/V1/triple-ratchet-state-checksum";

    [Fact]
    public void DurableCodec_InitialStateIsExactCanonicalAndRoundTripsLosslessly()
    {
        using var source = CreateState(maximumWithoutFresh: 37, storageGeneration: 12);
        var first = TripleRatchetDurableStateCodec.Encode(source);
        var second = TripleRatchetDurableStateCodec.Encode(source);
        try
        {
            Assert.Equal(664, first.Length);
            Assert.Equal(first, second);
            Assert.Equal("TRS1", System.Text.Encoding.ASCII.GetString(first, 0, 4));
            Assert.Equal(1, first[4]);
            Assert.Equal(MessagingCryptoConstants.Suite, BinaryPrimitives.ReadUInt16BigEndian(first.AsSpan(5)));
            Assert.Equal((uint)first.Length, BinaryPrimitives.ReadUInt32BigEndian(first.AsSpan(8)));
            Assert.Equal(
                "665C3F4BD8C183FE3B4A169CAC400E82500F95329D4F5EC035F9D554A6466A10",
                Convert.ToHexString(SHA256.HashData(first)));

            using var restored = TripleRatchetDurableStateCodec.Decode(first);
            var reencoded = TripleRatchetDurableStateCodec.Encode(restored);
            try
            {
                Assert.Equal(first, reencoded);
                Assert.Equal(source.StateCommitment.ToArray(), restored.StateCommitment.ToArray());
                Assert.Equal(source.Binding.Commitment.ToArray(), restored.Binding.Commitment.ToArray());
                Assert.Equal(12UL, restored.StorageGeneration);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(reencoded);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
        }
    }

    [Fact]
    public void DurableCodec_PreservesSkippedComponentKeysAndProviderStateAcrossRestart()
    {
        using var source = CreateState(maximumWithoutFresh: 3);
        var target = new RatchetCounterTuple(2, 1, 3);
        var header = Bytes(23);
        var envelope = Bytes(24);
        using var plan = source.PrepareReceive(
            new ScriptedProvider { FreshContribution = static ecN => ecN == 2 },
            Persistence(source),
            FreshDedup(source, target, header, envelope, 101),
            target,
            header,
            envelope);
        using var commit = plan.Commit(DurableSuccess(plan));
        using var messageKey = commit.TakeMessageKey();
        using var advanced = commit.TakeNextState();
        Assert.Equal(2, advanced.SkippedKeyCount);

        var encoded = TripleRatchetDurableStateCodec.Encode(advanced);
        try
        {
            using var restored = TripleRatchetDurableStateCodec.Decode(encoded);
            Assert.Equal(2, restored.SkippedKeyCount);
            Assert.Equal(advanced.StateCommitment.ToArray(), restored.StateCommitment.ToArray());
            var reencoded = TripleRatchetDurableStateCodec.Encode(restored);
            try
            {
                Assert.Equal(encoded, reencoded);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(reencoded);
            }

            using var liveSendPlan = advanced.PrepareSend(
                new ScriptedProvider(), Persistence(advanced), Bytes(104), Bytes(105), Bytes(106));
            using var restoredSendPlan = restored.PrepareSend(
                new ScriptedProvider(), Persistence(restored), Bytes(104), Bytes(105), Bytes(106));
            using var liveSendCommit = liveSendPlan.Commit(DurableSuccess(liveSendPlan));
            using var restoredSendCommit = restoredSendPlan.Commit(DurableSuccess(restoredSendPlan));
            using var liveMessageKey = liveSendCommit.TakeMessageKey();
            using var restoredMessageKey = restoredSendCommit.TakeMessageKey();
            var liveKeyHash = liveMessageKey.Use(static key => SHA256.HashData(key));
            var restoredKeyHash = restoredMessageKey.Use(static key => SHA256.HashData(key));
            try
            {
                Assert.Equal(liveKeyHash, restoredKeyHash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(liveKeyHash);
                CryptographicOperations.ZeroMemory(restoredKeyHash);
            }
            using var liveNext = liveSendCommit.TakeNextState();
            using var restoredNext = restoredSendCommit.TakeNextState();
            var liveNextBytes = TripleRatchetDurableStateCodec.Encode(liveNext);
            var restoredNextBytes = TripleRatchetDurableStateCodec.Encode(restoredNext);
            try
            {
                Assert.Equal(liveNextBytes, restoredNextBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(liveNextBytes);
                CryptographicOperations.ZeroMemory(restoredNextBytes);
            }

            var skippedTarget = new RatchetCounterTuple(0, 1, 1);
            var skippedHeader = Bytes(25);
            var skippedEnvelope = Bytes(26);
            using var skippedPlan = restored.PrepareReceive(
                new ThrowingProvider(),
                Persistence(restored),
                FreshDedup(restored, skippedTarget, skippedHeader, skippedEnvelope, 102),
                skippedTarget,
                skippedHeader,
                skippedEnvelope);
            Assert.Equal(RatchetPlanOutcome.OutOfOrderSkippedKey, skippedPlan.Outcome);
            using var skippedCommit = skippedPlan.Commit(DurableSuccess(skippedPlan));
            using var skippedMessageKey = skippedCommit.TakeMessageKey();
            using var afterSkipped = skippedCommit.TakeNextState();
            Assert.Equal(1, afterSkipped.SkippedKeyCount);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    [Fact]
    public void DurableCodec_PreservesTerminalLatchWithoutRetainingSecrets()
    {
        using var source = CreateState(storageGeneration: 7);
        using var latchPlan = source.PrepareRollbackLatch(
            Persistence(source, latest: 8), Bytes(82), Bytes(83));
        using var latchCommit = latchPlan.Commit(DurableSuccess(latchPlan));
        using var terminal = latchCommit.TakeNextState();

        var encoded = TripleRatchetDurableStateCodec.Encode(terminal);
        try
        {
            Assert.Equal(600, encoded.Length);
            Assert.Equal(1, encoded[7]);
            Assert.Equal(0U, BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(528)));
            Assert.Equal(0U, BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(532)));
            using var restored = TripleRatchetDurableStateCodec.Decode(encoded);
            Assert.True(restored.IsTerminallyLatched);
            Assert.Equal(terminal.StateCommitment.ToArray(), restored.StateCommitment.ToArray());
            var error = Assert.Throws<MessagingCryptoException>(() => restored.PrepareSend(
                new ScriptedProvider(), Persistence(restored), Bytes(80), Bytes(81), Bytes(84)));
            Assert.Equal(MessagingCryptoError.TerminallyLatched, error.Error);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    [Fact]
    public void DurableCodec_PreservesOldChainSkippedKeysAcrossDhRatchetAndRestart()
    {
        using var initial = CreateState();
        var oldChain = RatchetEcChainId.DarkDefaultForTests;
        var firstTarget = new RatchetCounterTuple(oldChain, 0, 1, 1);
        var firstDtr2 = EncodeDtr2(oldChain, previousChainLength: 0, firstTarget);
        using var firstPlan = initial.PrepareReceive(
            new ScriptedProvider(),
            Persistence(initial),
            FreshDedup(initial, firstTarget, Bytes(111), Bytes(112), 113),
            firstTarget,
            firstDtr2,
            Bytes(111),
            Bytes(112));
        using var firstCommit = firstPlan.Commit(DurableSuccess(firstPlan));
        using var firstKey = firstCommit.TakeMessageKey();
        using var afterFirst = firstCommit.TakeNextState();

        var newChainBytes = Enumerable.Repeat((byte)0x6A, 32).ToArray();
        var newChain = RatchetEcChainId.FromPublicKey(newChainBytes);
        var newTarget = new RatchetCounterTuple(newChain, 0, 1, 4);
        var newDtr2 = EncodeDtr2(newChain, previousChainLength: 3, newTarget);
        var provider = new ScriptedProvider();
        using var newPlan = afterFirst.PrepareReceive(
            provider,
            Persistence(afterFirst),
            FreshDedup(afterFirst, newTarget, Bytes(114), Bytes(115), 116),
            newTarget,
            newDtr2,
            Bytes(114),
            Bytes(115));
        using var newCommit = newPlan.Commit(DurableSuccess(newPlan));
        using var newKey = newCommit.TakeMessageKey();
        using var afterDhRatchet = newCommit.TakeNextState();
        Assert.Equal(2, afterDhRatchet.SkippedKeyCount);

        var encoded = TripleRatchetDurableStateCodec.Encode(afterDhRatchet);
        try
        {
            using var restored = TripleRatchetDurableStateCodec.Decode(encoded);
            var oldSkippedTarget = new RatchetCounterTuple(oldChain, 1, 1, 2);
            using var skippedPlan = restored.PrepareReceive(
                new ThrowingProvider(),
                Persistence(restored),
                FreshDedup(restored, oldSkippedTarget, Bytes(117), Bytes(118), 119),
                oldSkippedTarget,
                Bytes(117),
                Bytes(118));
            Assert.Equal(RatchetPlanOutcome.OutOfOrderSkippedKey, skippedPlan.Outcome);
            using var skippedCommit = skippedPlan.Commit(DurableSuccess(skippedPlan));
            using var skippedKey = skippedCommit.TakeMessageKey();
            using var afterSkipped = skippedCommit.TakeNextState();
            Assert.Equal(1, afterSkipped.SkippedKeyCount);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
            CryptographicOperations.ZeroMemory(newChainBytes);
            CryptographicOperations.ZeroMemory(firstDtr2);
            CryptographicOperations.ZeroMemory(newDtr2);
        }
    }

    [Fact]
    public void ReceiveRejectsNewDhChainWhosePnIsBehindCommittedOldChainCursor()
    {
        using var state = CreateState();
        var oldTarget = new RatchetCounterTuple(RatchetEcChainId.DarkDefaultForTests, 0, 1, 1);
        var oldDtr2 = EncodeDtr2(oldTarget.EcChain, 0, oldTarget);
        using var oldPlan = state.PrepareReceive(
            new ScriptedProvider(), Persistence(state),
            FreshDedup(state, oldTarget, Bytes(120), Bytes(121), 122),
            oldTarget, oldDtr2, Bytes(120), Bytes(121));
        using var oldCommit = oldPlan.Commit(DurableSuccess(oldPlan));
        using var oldKey = oldCommit.TakeMessageKey();
        using var advanced = oldCommit.TakeNextState();

        var newChainBytes = Enumerable.Repeat((byte)0x6B, 32).ToArray();
        var newTarget = new RatchetCounterTuple(
            RatchetEcChainId.FromPublicKey(newChainBytes), 0, 1, 2);
        var stalePnDtr2 = EncodeDtr2(newTarget.EcChain, 0, newTarget);
        var provider = new ScriptedProvider();
        try
        {
            var error = Assert.Throws<MessagingCryptoException>(() => advanced.PrepareReceive(
                provider, Persistence(advanced),
                FreshDedup(advanced, newTarget, Bytes(123), Bytes(124), 125),
                newTarget, stalePnDtr2, Bytes(123), Bytes(124)));
            Assert.Equal(MessagingCryptoError.ReplayConflict, error.Error);
            Assert.Equal(0, provider.ReceiveCalls);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(newChainBytes);
            CryptographicOperations.ZeroMemory(oldDtr2);
            CryptographicOperations.ZeroMemory(stalePnDtr2);
        }
    }

    [Fact]
    public void DurableCodec_RejectsHostileLengthsCountsVersionsAndFlagsBeforeSecretAllocation()
    {
        using var source = CreateState();
        var canonical = TripleRatchetDurableStateCodec.Encode(source);
        try
        {
            var oversized = new byte[MessagingCryptoConstants.MaximumDurableRatchetStateBytes + 1];
            AssertPreAllocationRejection(oversized, MessagingCryptoError.StateLimitExceeded);
            AssertPreAllocationRejection(canonical.AsSpan(0, canonical.Length - 1).ToArray(), MessagingCryptoError.InvalidInput);

            var wrongVersion = canonical.ToArray();
            wrongVersion[4] = 2;
            AssertPreAllocationRejection(wrongVersion, MessagingCryptoError.InvalidInput);

            var wrongSuite = canonical.ToArray();
            BinaryPrimitives.WriteUInt16BigEndian(wrongSuite.AsSpan(5), 0x0202);
            AssertPreAllocationRejection(wrongSuite, MessagingCryptoError.InvalidInput);

            var wrongFlags = canonical.ToArray();
            wrongFlags[7] = 0x80;
            AssertPreAllocationRejection(wrongFlags, MessagingCryptoError.InvalidInput);

            var hostileProviderLength = canonical.ToArray();
            BinaryPrimitives.WriteUInt32BigEndian(hostileProviderLength.AsSpan(528), uint.MaxValue);
            RewriteChecksum(hostileProviderLength);
            AssertPreAllocationRejection(hostileProviderLength, MessagingCryptoError.StateLimitExceeded);

            var hostileCount = canonical.ToArray();
            BinaryPrimitives.WriteUInt32BigEndian(hostileCount.AsSpan(532), 2049);
            RewriteChecksum(hostileCount);
            AssertPreAllocationRejection(hostileCount, MessagingCryptoError.StateLimitExceeded);

            var negativePqCounter = canonical.ToArray();
            BinaryPrimitives.WriteInt32BigEndian(negativePqCounter.AsSpan(340), -1);
            RewriteChecksum(negativePqCounter);
            AssertPreAllocationRejection(negativePqCounter, MessagingCryptoError.StateLimitExceeded);

            var zeroBinding = canonical.ToArray();
            zeroBinding.AsSpan(12, 32).Clear();
            RewriteChecksum(zeroBinding);
            AssertPreAllocationRejection(zeroBinding, MessagingCryptoError.InvalidInput);

            var terminalWithSecrets = canonical.ToArray();
            terminalWithSecrets[7] = 1;
            RewriteChecksum(terminalWithSecrets);
            AssertPreAllocationRejection(terminalWithSecrets, MessagingCryptoError.InvalidInput);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    [Fact]
    public void DurableCodec_RejectsNonCanonicalSkippedOrderingAndDuplicates()
    {
        using var state = CreateStateWithTwoSkippedKeys();
        var canonical = TripleRatchetDurableStateCodec.Encode(state);
        try
        {
            var componentLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(canonical.AsSpan(528)));
            var skippedOffset = DurableFixedPrefixBeforeComponent + componentLength;

            var reversed = canonical.ToArray();
            var firstEntry = reversed.AsSpan(skippedOffset, DurableSkippedEntrySize).ToArray();
            reversed.AsSpan(skippedOffset + DurableSkippedEntrySize, DurableSkippedEntrySize)
                .CopyTo(reversed.AsSpan(skippedOffset, DurableSkippedEntrySize));
            firstEntry.CopyTo(reversed.AsSpan(skippedOffset + DurableSkippedEntrySize));
            CryptographicOperations.ZeroMemory(firstEntry);
            RewriteChecksum(reversed);
            AssertPreAllocationRejection(reversed, MessagingCryptoError.InvalidInput);

            var duplicate = canonical.ToArray();
            duplicate.AsSpan(skippedOffset, DurableSkippedEntrySize)
                .CopyTo(duplicate.AsSpan(skippedOffset + DurableSkippedEntrySize, DurableSkippedEntrySize));
            RewriteChecksum(duplicate);
            AssertPreAllocationRejection(duplicate, MessagingCryptoError.InvalidInput);

            var invalidBoolean = canonical.ToArray();
            invalidBoolean[skippedOffset + 184] = 2;
            RewriteChecksum(invalidBoolean);
            AssertPreAllocationRejection(invalidBoolean, MessagingCryptoError.InvalidInput);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    [Fact]
    public void DurableCodec_RejectsTamperAndDisposesImportedSecretsOnSemanticMismatch()
    {
        using var source = CreateState();
        var canonical = TripleRatchetDurableStateCodec.Encode(source);
        try
        {
            var checksumTamper = canonical.ToArray();
            checksumTamper[DurableFixedPrefixBeforeComponent] ^= 0x40;
            Assert.Equal(MessagingCryptoError.CasConflict,
                Assert.Throws<MessagingCryptoException>(() =>
                    TripleRatchetDurableStateCodec.Decode(checksumTamper)).Error);

            var semanticTamper = canonical.ToArray();
            semanticTamper[DurableFixedPrefixBeforeComponent] ^= 0x20;
            RewriteChecksum(semanticTamper);
            SecretBuffer? capturedComponent = null;
            using (MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
            {
                OwnedSecret = (name, owner) =>
                {
                    if (name == "ratchet-state-codec.component") capturedComponent = owner;
                },
            }))
            {
                Assert.Equal(MessagingCryptoError.CasConflict,
                    Assert.Throws<MessagingCryptoException>(() =>
                        TripleRatchetDurableStateCodec.Decode(semanticTamper)).Error);
            }
            Assert.NotNull(capturedComponent);
            Assert.Equal(MessagingCryptoError.ObjectDisposed,
                Assert.Throws<MessagingCryptoException>(() => capturedComponent!.Copy()).Error);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    [Fact]
    public void DurableCodec_ZeroizesFailedEncodeAndFailedImportOwners()
    {
        using var source = CreateState();
        byte[]? capturedEncoding = null;
        using (MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            ManagedSecret = (name, value) =>
            {
                if (name != "ratchet-state-codec.output") return;
                capturedEncoding = value;
                throw new InvalidOperationException("injected durable encode handoff fault");
            },
        }))
        {
            Assert.Throws<InvalidOperationException>(() => TripleRatchetDurableStateCodec.Encode(source));
        }
        Assert.NotNull(capturedEncoding);
        Assert.True(MessagingCryptoValidation.IsZero(capturedEncoding!));

        var encoded = TripleRatchetDurableStateCodec.Encode(source);
        TripleRatchetState? capturedState = null;
        try
        {
            using (MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
            {
                OwnedDisposable = (name, owner) =>
                {
                    if (name == "ratchet-state-codec.imported-state")
                        capturedState = Assert.IsType<TripleRatchetState>(owner);
                },
                Point = name =>
                {
                    if (name == "ratchet-state-codec.before-import-release")
                        throw new InvalidOperationException("injected durable import handoff fault");
                },
            }))
            {
                Assert.Throws<InvalidOperationException>(() => TripleRatchetDurableStateCodec.Decode(encoded));
            }
            Assert.NotNull(capturedState);
            AssertStateDisposed(capturedState!);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    [Fact]
    public void DurableCodec_EnforcesExactAggregateTwoMiBBoundBeforeOutputAllocation()
    {
        const int nonProviderBytes = 600;
        var exactProviderLength = MessagingCryptoConstants.MaximumDurableRatchetStateBytes - nonProviderBytes;
        var exactProvider = Enumerable.Repeat((byte)0x5A, exactProviderLength).ToArray();
        try
        {
            using var exact = TripleRatchetState.Create(
                CreateBinding(), exactProvider, Bytes(60), Bytes(61), 0, 0, 0, 32);
            var encoded = TripleRatchetDurableStateCodec.Encode(exact);
            try
            {
                Assert.Equal(MessagingCryptoConstants.MaximumDurableRatchetStateBytes, encoded.Length);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }

            var overProvider = new byte[exactProviderLength + 1];
            overProvider.AsSpan().Fill(0x5B);
            try
            {
                var error = Assert.Throws<MessagingCryptoException>(() => TripleRatchetState.Create(
                    CreateBinding(), overProvider, Bytes(60), Bytes(61), 0, 0, 0, 32));
                Assert.Equal(MessagingCryptoError.StateLimitExceeded, error.Error);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(overProvider);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactProvider);
        }
    }

    private static TripleRatchetState CreateStateWithTwoSkippedKeys()
    {
        using var source = CreateState(maximumWithoutFresh: 3);
        var target = new RatchetCounterTuple(2, 1, 3);
        var header = Bytes(31);
        var envelope = Bytes(32);
        using var plan = source.PrepareReceive(
            new ScriptedProvider { FreshContribution = static ecN => ecN == 2 },
            Persistence(source),
            FreshDedup(source, target, header, envelope, 103),
            target,
            header,
            envelope);
        using var commit = plan.Commit(DurableSuccess(plan));
        using var key = commit.TakeMessageKey();
        return commit.TakeNextState();
    }

    private static byte[] EncodeDtr2(
        RatchetEcChainId chain,
        ulong previousChainLength,
        RatchetCounterTuple target) =>
        Dtr2Codec.EncodeEmbedded(new Dtr2Record(
            Enumerable.Repeat((byte)0x4F, 16).ToArray(),
            chain.ToArray(),
            previousChainLength,
            target.EcN,
            target.SckaEpoch,
            0,
            target.SckaN,
            1,
            Dtr2BraidMessage.None()));

    private static void AssertPreAllocationRejection(byte[] encoded, MessagingCryptoError expected)
    {
        var reachedAllocationBoundary = false;
        try
        {
            using (MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
            {
                Point = name =>
                {
                    if (name == "ratchet-state-codec.validated-before-allocation")
                        reachedAllocationBoundary = true;
                },
            }))
            {
                var error = Assert.Throws<MessagingCryptoException>(() =>
                    TripleRatchetDurableStateCodec.Decode(encoded));
                Assert.Equal(expected, error.Error);
            }
            Assert.False(reachedAllocationBoundary);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static void RewriteChecksum(byte[] encoded)
    {
        var checksumOffset = encoded.Length - 32;
        var checksum = MessagingKdf.Sha256Domain(DurableChecksumDomain, encoded.AsSpan(0, checksumOffset));
        try
        {
            checksum.CopyTo(encoded, checksumOffset);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(checksum);
        }
    }
}
