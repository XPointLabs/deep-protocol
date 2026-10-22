using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Xunit.Abstractions;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class ExactEd25519VerificationMemoTests(ITestOutputHelper output)
{
    [Fact]
    public void ExactRepeatUsesArithmeticOnlyAndOwnsInputs()
    {
        using var key = PublicKeyAuth.GenerateKeyPair();
        var message = "public signed protocol input"u8.ToArray();
        var signature = PublicKeyAuth.SignDetached(message, key.PrivateKey);
        var exact = message.ToArray(); var memo = new ExactEd25519VerificationMemo();
        Assert.True(memo.Verify(key.PublicKey, message, signature));
        message[0] ^= 1;
        Assert.True(memo.Verify(key.PublicKey, exact, signature));
        Assert.Equal(1, memo.Snapshot().NativeVerifications);
        Assert.False(memo.Verify(key.PublicKey, message, signature));
        signature[0] ^= 1;
        Assert.False(memo.Verify(key.PublicKey, exact, signature));
        Assert.Equal(1, memo.Snapshot().Entries);
    }

    [Fact]
    public void DifferentKeyAndNegativeResultsNeverBecomePositiveHits()
    {
        using var key = PublicKeyAuth.GenerateKeyPair(); using var other = PublicKeyAuth.GenerateKeyPair();
        var message = "public signed protocol input"u8.ToArray();
        var signature = PublicKeyAuth.SignDetached(message, key.PrivateKey); var memo = new ExactEd25519VerificationMemo();
        Assert.True(memo.Verify(key.PublicKey, message, signature));
        Assert.False(memo.Verify(other.PublicKey, message, signature));
        Assert.False(memo.Verify(other.PublicKey, message, signature));
        Assert.Equal(3, memo.Snapshot().NativeVerifications);
        Assert.False(memo.Verify(new byte[31], message, signature));
        Assert.False(memo.Verify(key.PublicKey, message, new byte[63]));
    }

    [Fact]
    public void ByteAndEntryCapacityEvictsWithoutChangingVerification()
    {
        using var key = PublicKeyAuth.GenerateKeyPair(); var memo = new ExactEd25519VerificationMemo(2, 200, new Random(0));
        for (byte i = 0; i < 8; i++)
        {
            byte[] message = [i]; var signature = PublicKeyAuth.SignDetached(message, key.PrivateKey);
            Assert.True(memo.Verify(key.PublicKey, message, signature));
            Assert.InRange(memo.Snapshot().Entries, 0, 2); Assert.InRange(memo.Snapshot().Bytes, 0, 200);
        }
        byte[] first = [0]; Assert.True(memo.Verify(key.PublicKey, first, PublicKeyAuth.SignDetached(first, key.PrivateKey)));
        Assert.Equal(9, memo.Snapshot().NativeVerifications);
        var large = new byte[65_537]; var signed = PublicKeyAuth.SignDetached(large, key.PrivateKey);
        Assert.True(memo.Verify(key.PublicKey, large, signed)); Assert.True(memo.Verify(key.PublicKey, large, signed));
        Assert.Equal(11, memo.Snapshot().NativeVerifications);
    }

    [Fact]
    public async Task ConcurrentExactHitsStayBounded()
    {
        using var key = PublicKeyAuth.GenerateKeyPair(); var memo = new ExactEd25519VerificationMemo(2, 1024);
        byte[] message = [1, 2, 3]; var signature = PublicKeyAuth.SignDetached(message, key.PrivateKey);
        await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(() => Assert.True(memo.Verify(key.PublicKey, message, signature)))));
        Assert.Equal(1, memo.Snapshot().Entries); Assert.Equal(99, memo.Snapshot().Bytes);
    }

    [Theory]
    [InlineData(4, 6, 16)]
    [InlineData(24, 32, 12)]
    [InlineData(64, 80, 8)]
    public void RepeatedOversizedPublicHistoryDoesNotThrashEveryExactTuple(int capacity, int history, int rounds)
    {
        using var key = PublicKeyAuth.GenerateKeyPair();
        var memo = new ExactEd25519VerificationMemo(capacity, 65_536, new Random(0));
        var messages = Enumerable.Range(0, history).Select(index => BitConverter.GetBytes(index)).ToArray();
        var signatures = messages.Select(message => PublicKeyAuth.SignDetached(message, key.PrivateKey)).ToArray();
        for (var pass = 0; pass < rounds; pass++)
            for (var index = 0; index < history; index++)
            {
                Assert.True(memo.Verify(key.PublicKey, messages[index], signatures[index]));
                Assert.InRange(memo.Snapshot().Entries, 1, capacity);
                Assert.InRange(memo.Snapshot().Bytes, 1, 65_536);
            }
        // FIFO misses every tuple on every sequential pass when history >
        // capacity. Fixed-seed replacement makes this regression deterministic,
        // independent of generated keys/signatures or wall-clock measurements.
        Assert.InRange(memo.Snapshot().NativeVerifications, history, history * rounds - history);
        output.WriteLine("capacity={0}; history={1}; passes={2}; native={3}; naiveSequentialMisses={4}",
            capacity, history, rounds, memo.Snapshot().NativeVerifications, history * rounds);
        var before = memo.Snapshot().NativeVerifications;
        var changed = messages[0].ToArray(); changed[0] ^= 0x80;
        Assert.False(memo.Verify(key.PublicKey, changed, signatures[0]));
        Assert.False(memo.Verify(key.PublicKey, changed, signatures[0]));
        Assert.Equal(before + 2, memo.Snapshot().NativeVerifications);
    }
}
