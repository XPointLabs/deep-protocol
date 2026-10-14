using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed partial class ManagedTripleRatchetNativeOwnershipTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task BraidObsoleteBoundary_InstalledOutputAuthenticatesOnlyUnconsumedControlWithoutMutation(bool nativeRecorded)
    {
        using var pair = new RecoveryPair();
        var original = pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 200));
        try
        {
            var initial = pair.Bob.CommittedDigest();
            Assert.Null(pair.Bob.VerifyObsoleteControl(original)); // No installed output yet.
            Assert.Equal(initial, pair.Bob.CommittedDigest());
            if (nativeRecorded) Assert.False(pair.Bob.ReceiveControl(pair.BobProvider, original));
            // Complete the actual Braid using ordinary data, not the old DBR2
            // operation. This must not invent a control receive/receipt.
            foreach (var (sender, receiver, alice, id) in new[] {
                         (pair.Alice, pair.Bob, true, (byte)1), (pair.Bob, pair.Alice, false, (byte)80),
                         (pair.Alice, pair.Bob, true, (byte)2), (pair.Bob, pair.Alice, false, (byte)81) })
            {
                var message = RecoveryMessage(alice, id); var data = await sender.Send(message);
                try { await Verify(receiver, data, message); }
                finally { CryptographicOperations.ZeroMemory(data); }
            }
            var before = pair.Bob.CommittedDigest();
            if (nativeRecorded)
                Assert.Throws<MessagingCryptoException>(() => pair.Bob.VerifyObsoleteControl(original));
            else
            {
                var proof = Assert.IsType<VerifiedBraidRecoveryObsoleteControl>(pair.Bob.VerifyObsoleteControl(original));
                Assert.Equal(1UL, proof.BraidEpoch); Assert.Equal(pair.Bob.Generation, proof.StateGeneration);
                Assert.Equal(SHA256.HashData(original), proof.ExactControlHash.ToArray());
                Assert.Empty(typeof(VerifiedBraidRecoveryObsoleteControl).GetConstructors());
                var copy = proof.ExactControlHash.ToArray(); copy.AsSpan().Clear();
                Assert.Equal(SHA256.HashData(original), proof.ExactControlHash.ToArray());
                Assert.NotNull(pair.Bob.VerifyObsoleteControl(original)); // Proof does not consume a native slot.
                var changed = original.ToArray(); changed[^1] ^= 1;
                Assert.Throws<CryptographicException>(() => pair.Bob.VerifyObsoleteControl(changed));
                Assert.Throws<MessagingCryptoException>(() => pair.Alice.VerifyObsoleteControl(original));
                pair.Bob.RejectObsoleteContext(original, replay: true, wrongCheckpoint: false);
                pair.Bob.RejectObsoleteContext(original, replay: false, wrongCheckpoint: true);
            }
            Assert.Equal(before, pair.Bob.CommittedDigest());
            // The read-only proof neither repairs nor breaks ordinary data.
            await ResumeBidirectionalFreshData(pair);
        }
        finally { CryptographicOperations.ZeroMemory(original); }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task BraidObsoleteBoundary_RetiredOriginalRootCannotMintReadOnlyProof()
    {
        using var pair = new RecoveryPair();
        var original = pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 200));
        try
        {
            foreach (var (sender, receiver, alice, id) in new[] {
                         (pair.Alice, pair.Bob, true, (byte)1), (pair.Bob, pair.Alice, false, (byte)80),
                         (pair.Alice, pair.Bob, true, (byte)2), (pair.Bob, pair.Alice, false, (byte)81) })
            {
                var message = RecoveryMessage(alice, id); var data = await sender.Send(message);
                try { await Verify(receiver, data, message); }
                finally { CryptographicOperations.ZeroMemory(data); }
            }
            Assert.NotNull(pair.Bob.VerifyObsoleteControl(original));
            await ResumeBidirectionalFreshData(pair); // Both actual data frontiers now1.
            foreach (var (sender, receiver, id) in new[] {
                         (pair.Bob, pair.Alice, (byte)201), (pair.Alice, pair.Bob, (byte)202),
                         (pair.Bob, pair.Alice, (byte)203), (pair.Alice, pair.Bob, (byte)204) })
                receiver.ReceiveControl(receiver == pair.Alice ? pair.AliceProvider : pair.BobProvider,
                    sender.SendControl(sender == pair.Alice ? pair.AliceProvider : pair.BobProvider, Bytes(32, id)));
            var before = pair.Bob.CommittedDigest();
            Assert.Null(pair.Bob.VerifyObsoleteControl(original)); // No reconstruction/fallback root.
            Assert.Equal(before, pair.Bob.CommittedDigest());
        }
        finally { CryptographicOperations.ZeroMemory(original); }
    }

    private sealed partial class IsolatedAtomicMemory
    {
        internal VerifiedBraidRecoveryObsoleteControl? VerifyObsoleteControl(byte[] exact) =>
            ExactBraidRecoveryDurableTransactionProducer.TryVerifyObsoleteControl(state, Context(false), Bytes(16, 5), exact);
        internal void RejectObsoleteContext(byte[] exact, bool replay, bool wrongCheckpoint)
        {
            using var current = TripleRatchetDurableStateCodec.Decode(state);
            var context = new ExactDpe2DurableTransitionContext(current.StorageGeneration, current.StateCommitment.Span,
                current.StorageGeneration + (wrongCheckpoint ? 1UL : 0UL), current.StateCommitment.Span,
                journalGeneration, journal, SHA256.HashData(journal),
                replay ? ExactDpe2ReceiveReplayDisposition.ExactReplay : ExactDpe2ReceiveReplayDisposition.Fresh);
            Assert.Throws<MessagingCryptoException>(() =>
                ExactBraidRecoveryDurableTransactionProducer.TryVerifyObsoleteControl(state, context, Bytes(16, 5), exact));
        }
    }
}
