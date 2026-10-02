using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.ApplicationCore;
using Sodium;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class ManagedTripleRatchetNativeOwnershipTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task NativeDpe2_BidirectionalOutOfOrderReplayAuthenticationAndPqRollover()
    {
        // Fixed-root component integration, not identity/durable/network E2E.
        using var aliceProvider = ManagedTripleRatchetComponentProvider.CreateApproved(
            DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess());
        using var bobProvider = ManagedTripleRatchetComponentProvider.CreateApproved(
            DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess());
        using var ec = SecretBuffer.ImportExact(Bytes(32, 1), 32, "fixture EC root");
        using var pq = SecretBuffer.ImportExact(Bytes(32, 2), 32, "fixture PQ root");
        var alicePrivate = Bytes(32, 3); var bobPrivate = Bytes(32, 4);
        using var aliceSeed = VerifiedTripleRatchetSeedCapability.CreateFromVerifiedRoots(Binding(true), ec, pq);
        using var bobSeed = VerifiedTripleRatchetSeedCapability.CreateFromVerifiedRoots(Binding(false), ec, pq);
        try
        {
            using var aliceState = aliceProvider.InitializeAlice(aliceSeed, alicePrivate, ScalarMult.Base(alicePrivate),
                ScalarMult.Base(bobPrivate), 1, 32);
            using var bobState = bobProvider.InitializeBob(bobSeed, bobPrivate, ScalarMult.Base(bobPrivate),
                ScalarMult.Base(alicePrivate), 1, 32);
            using var alice = new IsolatedAtomicMemory(aliceState);
            using var bob = new IsolatedAtomicMemory(bobState);
            ParsedDmc2 Message(bool fromAlice, byte id) => ApplicationCoreCodec.AuthorDmc2(Bytes(16, 5),
                Bytes(32, id), Bytes(32, 25), Bytes(32, fromAlice ? (byte)22 : (byte)23),
                Bytes(32, fromAlice ? (byte)8 : (byte)9), id, 1_100_000UL + id, 0, Dmc2Flags.None, [],
                ApplicationCoreCodec.CreateMessageCreatePayload($"native message {id}: Привет 📨"));
            var first = Message(true, 31); var second = Message(true, 32);
            var firstCipher = await alice.Send(first); var secondCipher = await alice.Send(second);
            var corrupt = secondCipher.ToArray(); corrupt[^1] ^= 1;
            await Assert.ThrowsAnyAsync<CryptographicException>(() => bob.Receive(corrupt));
            Assert.Equal(1UL, bob.Generation);
            await Verify(bob, secondCipher, second);
            using (var opened = await bob.Receive(firstCipher))
            {
                Assert.Equal(ExactDpe2ReceiveSuccessOutcome.OutOfOrderSkippedKey, opened.Outcome);
                var exact = opened.TakeAuthenticatedDmc2();
                try { Assert.Equal(first.CanonicalBytes.ToArray(), exact); }
                finally { CryptographicOperations.ZeroMemory(exact); }
            }
            var generation = bob.Generation;
            using (var replay = await bob.Receive(firstCipher))
            {
                Assert.Equal(ExactDpe2ReceiveSuccessOutcome.ExactReplay, replay.Outcome);
                Assert.False(replay.HasAuthenticatedDmc2); Assert.Equal(generation, bob.Generation);
            }
            for (byte id = 40; id < 120; id++)
            {
                var fromAlice = id % 2 != 0;
                var message = Message(fromAlice, id);
                var sender = fromAlice ? alice : bob; var receiver = fromAlice ? bob : alice;
                var cipher = await sender.Send(message);
                try { await Verify(receiver, cipher, message); }
                catch (CryptographicException exception) { throw new InvalidOperationException($"Native component rejected fixture step {id}.", exception); }
                if (Dpe2Codec.Decode(cipher).RatchetHeader.SckaSendingEpoch == 0)
                    Assert.True(receiver.ReceiveMessagesSincePqInjection > 0); // Old key is never fresh.
                else if (Dpe2Codec.Decode(cipher).RatchetHeader.SckaMessageNumber == 1)
                    Assert.Equal(0, receiver.ReceiveMessagesSincePqInjection);
                if (id == 41)
                    bob.RejectUnrelatedSameEpochBraid(bobProvider, bobState);
            }
            // Both sides send beyond the fixed 32-message no-PQ contribution
            // limit. Success requires the actual native Braid/EC/PQ rollover.
            Assert.Equal(83UL, alice.Generation); Assert.Equal(83UL, bob.Generation);
        }
        finally { CryptographicOperations.ZeroMemory(alicePrivate); CryptographicOperations.ZeroMemory(bobPrivate); }
    }

    private static async Task Verify(IsolatedAtomicMemory receiver, byte[] cipher, ParsedDmc2 message)
    {
        using var opened = await receiver.Receive(cipher);
        var exact = opened.TakeAuthenticatedDmc2();
        try { Assert.Equal(message.CanonicalBytes.ToArray(), exact); }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public void EvidenceSuccessorsRemainOwnedAcrossSendAndGappedReceive()
    {
        // Crypto-component fixture only: fixed roots are NOT handshake/account
        // authority or durable/device delivery evidence. Actual approved native
        // Braid and production managed component, no scripted provider.
        using var aliceProvider = ManagedTripleRatchetComponentProvider.CreateApproved(
            DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess());
        using var bobProvider = ManagedTripleRatchetComponentProvider.CreateApproved(
            DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess());
        using var ec = SecretBuffer.ImportExact(Bytes(32, 1), 32, "fixture EC root");
        using var pq = SecretBuffer.ImportExact(Bytes(32, 2), 32, "fixture PQ root");
        var alicePrivate = Bytes(32, 3); var bobPrivate = Bytes(32, 4);
        var alicePublic = ScalarMult.Base(alicePrivate); var bobPublic = ScalarMult.Base(bobPrivate);
        using var aliceSeed = VerifiedTripleRatchetSeedCapability.CreateFromVerifiedRoots(Binding(true), ec, pq);
        using var bobSeed = VerifiedTripleRatchetSeedCapability.CreateFromVerifiedRoots(Binding(false), ec, pq);
        using var alice = aliceProvider.InitializeAlice(aliceSeed, alicePrivate, alicePublic, bobPublic, 1, 32);
        using var bob = bobProvider.InitializeBob(bobSeed, bobPrivate, bobPublic, alicePublic, 1, 32);
        var aliceComponent = Component(alice); var bobComponent = Component(bob);
        byte[]? successor = null, received = null;
        try
        {
            var cursor = new RatchetEcChainCursor(alice.SendEcChain, alice.NextSendEcN);
            using var first = aliceProvider.PrepareSend(aliceComponent, cursor, Bytes(16, 5), new(0, 32));
            using var firstState = first.TakeNextState(); successor = firstState.Copy();
            var firstKeys = first.TakeMessageKeys();
            try
            {
                Assert.Single(firstKeys);
                RequireEvidence(successor);
                cursor = new(firstKeys[0].Counters.EcChain, firstKeys[0].Counters.EcN + 1);
            }
            finally { foreach (var key in firstKeys) key.Dispose(); }
            using var second = aliceProvider.PrepareSend(successor, cursor, Bytes(16, 5), new(1, 32));
            using var secondState = second.TakeNextState();
            var secondBytes = secondState.Copy();
            try { RequireEvidence(secondBytes); }
            finally { CryptographicOperations.ZeroMemory(secondBytes); }
            var headerBytes = second.TakeExactSendDtr2();
            var header = Dtr2Codec.DecodeEmbedded(headerBytes);
            var target = new RatchetCounterTuple(RatchetEcChainId.FromPublicKey(header.EcRatchetPublicKey.Span),
                header.EcMessageNumber, header.SckaSendingEpoch, header.SckaMessageNumber);
            using var incoming = bobProvider.PrepareReceive(bobComponent,
                new(bob.ReceiveEcChain, bob.NextExpectedReceiveEcN), target, headerBytes, new(0, 32));
            var incomingKeys = incoming.TakeMessageKeys();
            var secondKeys = second.TakeMessageKeys();
            try
            {
                Assert.Equal(2, incomingKeys.Count); Assert.Single(secondKeys);
                Assert.Equal(secondKeys[0].Counters, incomingKeys[1].Counters);
                Assert.Equal(incomingKeys[0].PqEvidence.NextStateCommitment.ToArray(),
                    incomingKeys[1].PqEvidence.PriorStateCommitment.ToArray());
                using var incomingState = incoming.TakeNextState(); received = incomingState.Copy();
                RequireEvidence(received);
            }
            finally
            {
                foreach (var key in incomingKeys) key.Dispose();
                foreach (var key in secondKeys) key.Dispose();
            }
        }
        finally
        {
            foreach (var buffer in new[] { alicePrivate, bobPrivate, aliceComponent, bobComponent, successor, received })
                if (buffer is not null) CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static void RequireEvidence(byte[] component)
    {
        Assert.True(component.AsSpan(240, 32).IndexOfAnyExcept((byte)0) >= 0);
        Assert.True(component.AsSpan(272, 32).IndexOfAnyExcept((byte)0) >= 0);
    }

    private static byte[] Component(TripleRatchetState state)
    {
        var exact = TripleRatchetDurableStateCodec.Encode(state);
        try { return exact.AsSpan(536, checked((int)BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(528)))).ToArray(); }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    private static RatchetStateBinding Binding(bool alice) => new(MessagingCryptoConstants.Suite,
        Bytes(32, 6), Bytes(64, 7), Bytes(32, alice ? (byte)8 : (byte)9), 1,
        Bytes(32, alice ? (byte)10 : (byte)11), Bytes(32, alice ? (byte)9 : (byte)8), 1,
        Bytes(32, alice ? (byte)11 : (byte)10));

    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();

    // Trusted authority implementation only for this in-memory component test.
    // Production still requires SQLCipher, independent floor, retirement/inbox.
    private sealed class IsolatedAtomicMemory : IExactDpe2DurableTransactionAuthority, IDisposable
    {
        private byte[] state, journal;
        private ulong journalGeneration;
        private readonly Dictionary<string, byte[]> receives = [];
        internal IsolatedAtomicMemory(TripleRatchetState initial)
        { state = TripleRatchetDurableStateCodec.Encode(initial); journal = SHA256.HashData(state); }
        internal ulong Generation { get { using var current = TripleRatchetDurableStateCodec.Decode(state); return current.StorageGeneration; } }
        internal int ReceiveMessagesSincePqInjection { get { using var current = TripleRatchetDurableStateCodec.Decode(state); return current.ReceiveMessagesSincePqInjection; } }
        internal void RejectUnrelatedSameEpochBraid(ManagedTripleRatchetComponentProvider provider, TripleRatchetState initial)
        {
            using var current = TripleRatchetDurableStateCodec.Decode(state);
            var malformed = Component(current); var old = Component(initial);
            try
            {
                // At this fixture step Bob has installed output1 in Ct2Sampled.
                Assert.Equal(1UL, BinaryPrimitives.ReadUInt64BigEndian(malformed.AsSpan(360)));
                Assert.Equal((byte)ManagedMlKemBraidState.Ct2Sampled, malformed[596 + 7]);
                // A valid but unrelated NoHeaderReceived epoch1 is not an
                // allowed exception to the epoch relation.
                old.AsSpan(596).CopyTo(malformed.AsSpan(596));
                var error = Assert.Throws<MessagingCryptoException>(() =>
                    provider.PrepareSend(malformed, new(current.SendEcChain, current.NextSendEcN), Bytes(16, 5), new(0, 32)));
                Assert.Equal(MessagingCryptoError.InvalidInput, error.Error);
            }
            finally { CryptographicOperations.ZeroMemory(malformed); CryptographicOperations.ZeroMemory(old); }
        }
        private ExactDpe2DurableTransitionContext Context(bool replay)
        {
            using var current = TripleRatchetDurableStateCodec.Decode(state);
            return new(current.StorageGeneration, current.StateCommitment.Span, current.StorageGeneration,
                current.StateCommitment.Span, journalGeneration, journal, SHA256.HashData(journal),
                replay ? ExactDpe2ReceiveReplayDisposition.ExactReplay : ExactDpe2ReceiveReplayDisposition.Fresh);
        }
        internal async Task<byte[]> Send(ParsedDmc2 message)
        {
            using var prepared = ExactDpe2DurableTransactionProducer.PrepareSend(state, Context(false),
                message.CanonicalBytes.Span, message.NetworkId.Span, message.LogicalMessageId.Span);
            using var committed = await prepared.CommitAsync(this);
            return committed.TakeExactEnvelope();
        }
        internal async Task<ExactDpe2ReceiveSuccessCapability> Receive(byte[] cipher)
        {
            var envelope = Dpe2Codec.Decode(cipher);
            var replay = receives.TryGetValue(Convert.ToHexString(envelope.OperationId.Span), out var prior);
            if (replay && !prior!.AsSpan().SequenceEqual(MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(envelope)))
                throw new CryptographicException("Changed fixture replay.");
            using var prepared = ExactDpe2DurableTransactionProducer.PrepareReceive(state, Context(replay), cipher);
            return await prepared.CommitAsync(this);
        }
        public ValueTask<ExactDpe2DurableCommitReceipt> CommitAsync(ExactDpe2DurablePersistencePlan plan,
            ExactDpe2DurableCommitCompletion completion, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var prior = plan.PriorTrs1.ToArray();
            try { Assert.Equal(state, prior); }
            finally { CryptographicOperations.ZeroMemory(prior); }
            Assert.Equal(journal, plan.JournalPredecessor.ToArray());
            Assert.Equal(journalGeneration, plan.ExpectedJournalGeneration);
            var operation = Convert.ToHexString(plan.OperationId.Span);
            if (!plan.HasStateMutation)
            {
                Assert.Equal(receives[operation], plan.ExactEnvelopeHash.ToArray());
                return ValueTask.FromResult(completion.Complete(ExactDpe2DurableCommitDisposition.ExactReplay));
            }
            Assert.True(plan.MessageKeyDeletedAfterAuthenticatedEnvelopeOperation);
            Assert.Equal(Generation + 1, plan.NextStateGeneration);
            var next = plan.NextTrs1.ToArray();
            CryptographicOperations.ZeroMemory(state); state = next;
            journal = SHA256.HashData(plan.ExactEnvelopeHash.Span); journalGeneration++;
            if (plan.Direction == ExactDpe2DurableDirection.Receive) receives.Add(operation, plan.ExactEnvelopeHash.ToArray());
            return ValueTask.FromResult(completion.Complete(ExactDpe2DurableCommitDisposition.Committed));
        }
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(state); CryptographicOperations.ZeroMemory(journal);
            foreach (var hash in receives.Values) CryptographicOperations.ZeroMemory(hash);
            receives.Clear();
        }
    }
}
