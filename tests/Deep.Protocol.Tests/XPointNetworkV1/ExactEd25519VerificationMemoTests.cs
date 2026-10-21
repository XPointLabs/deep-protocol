using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class ExactEd25519VerificationMemoTests
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
        using var key = PublicKeyAuth.GenerateKeyPair(); var memo = new ExactEd25519VerificationMemo(2, 200);
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
}
