using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class ManagedMlKemBraidProfileTests
{
    [Fact]
    public void FrozenProfile_MatchesIndependentDeterministicKdfHashAndHmacVectors()
    {
        using var authenticator = ManagedMlKemBraidAuthenticator.Initialize(Fill(0x11, 32));
        var seed = Fill(0x44, 32);
        var vector = Fill(0x55, 1152);

        var header = authenticator.CreateHeaderMessage(seed, vector);
        Span<byte> actualSeed = stackalloc byte[32];
        Span<byte> actualHash = stackalloc byte[32];
        Span<byte> actualHeaderMac = stackalloc byte[32];
        header.CopyHeaderTo(actualSeed, actualHash, actualHeaderMac);

        Assert.Equal(seed, actualSeed.ToArray());
        Assert.Equal(
            "3285022D074CA044A2C459D6501BF642A71347C342A60C6D9F9C306B7A8AB325",
            Convert.ToHexString(actualHash));
        Assert.Equal(
            "64EA785C0ED297850F726B3E0EF502A474D68B62DBA6546C65A3E88459FEE495",
            Convert.ToHexString(actualHeaderMac));

        var ciphertext1 = Fill(0x66, 960);
        var ciphertext2 = Fill(0x77, 128);
        var ciphertextMessage = authenticator.CreateCiphertext2Message(ciphertext1, ciphertext2);
        Span<byte> actualCiphertext2 = stackalloc byte[128];
        Span<byte> actualCiphertextMac = stackalloc byte[32];
        ciphertextMessage.CopyCiphertext2To(actualCiphertext2, actualCiphertextMac);
        Assert.Equal(ciphertext2, actualCiphertext2.ToArray());
        Assert.Equal(
            "62DA0915996692FD1BC0E4FC9BCA281CF4BD2167EFD192BF57E66AC871F47920",
            Convert.ToHexString(actualCiphertextMac));

        using var outputKey = authenticator.DeriveOutputKey(Fill(0x33, 32), 7);
        byte[]? actualOutputKey = null;
        try
        {
            outputKey.Use(value => actualOutputKey = value.ToArray());
            Assert.Equal(
                "64DB290DDD92AD7144378C9F4E6E26E70E28520DBD8D4090EB382651A96B5CEF",
                Convert.ToHexString(actualOutputKey!));
        }
        finally
        {
            if (actualOutputKey is not null)
                CryptographicOperations.ZeroMemory(actualOutputKey);
        }
    }

    [Fact]
    public void ExactDtr2Header_RoundTripsAndAuthenticatesAgainstFrozenProfile()
    {
        using var authenticator = ManagedMlKemBraidAuthenticator.Initialize(Fill(0x11, 32));
        var vector = Fill(0x55, 1152);
        var record = new Dtr2Record(
            Fill(0x14, 16),
            Fill(0x93, 32),
            ecPreviousSendingChainLength: 0,
            ecMessageNumber: 9,
            sckaSendingEpoch: 1,
            sckaPreviousSendingChainLength: 0,
            sckaMessageNumber: 4,
            braidEpoch: 1,
            authenticator.CreateHeaderMessage(Fill(0x44, 32), vector));

        var exact = Dtr2Codec.EncodeEmbedded(record);
        var decoded = Dtr2Codec.DecodeEmbedded(exact);

        Assert.Equal(Dtr2Codec.HeaderTotalBytes, exact.Length);
        Assert.Equal(Dtr2BraidMessageKind.Header, decoded.BraidMessage.Kind);
        authenticator.VerifyHeaderMessage(decoded.BraidMessage, vector, decoded.BraidEpoch);
    }

    [Fact]
    public void HeaderAndCiphertextSubstitutionRejectConstantTimeWithoutPoisoningState()
    {
        using var authenticator = ManagedMlKemBraidAuthenticator.Initialize(Fill(0x11, 32));
        var seed = Fill(0x44, 32);
        var vector = Fill(0x55, 1152);
        var validHeader = authenticator.CreateHeaderMessage(seed, vector);
        Span<byte> copiedSeed = stackalloc byte[32];
        Span<byte> copiedHash = stackalloc byte[32];
        Span<byte> copiedMac = stackalloc byte[32];
        validHeader.CopyHeaderTo(copiedSeed, copiedHash, copiedMac);
        copiedMac[0] ^= 0x80;
        var changedMac = Dtr2BraidMessage.Header(copiedSeed, copiedHash, copiedMac);
        var headerError = Assert.Throws<MessagingCryptoException>(() =>
            authenticator.VerifyHeaderMessage(changedMac, vector, 1));
        Assert.Equal(MessagingCryptoError.TransitionRejected, headerError.Error);

        var changedVector = vector.ToArray();
        changedVector[^1] ^= 0x01;
        var hashError = Assert.Throws<MessagingCryptoException>(() =>
            authenticator.VerifyHeaderMessage(validHeader, changedVector, 1));
        Assert.Equal(MessagingCryptoError.TransitionRejected, hashError.Error);

        var ciphertext1 = Fill(0x66, 960);
        var ciphertext2 = Fill(0x77, 128);
        var validCiphertext = authenticator.CreateCiphertext2Message(ciphertext1, ciphertext2);
        Span<byte> copiedCiphertext2 = stackalloc byte[128];
        Span<byte> copiedCiphertextMac = stackalloc byte[32];
        validCiphertext.CopyCiphertext2To(copiedCiphertext2, copiedCiphertextMac);
        copiedCiphertextMac[^1] ^= 0x01;
        var changedCiphertextMac = Dtr2BraidMessage.Ciphertext2(
            copiedCiphertext2,
            copiedCiphertextMac);
        var ciphertextError = Assert.Throws<MessagingCryptoException>(() =>
            authenticator.VerifyCiphertext2Message(changedCiphertextMac, ciphertext1, 1));
        Assert.Equal(MessagingCryptoError.TransitionRejected, ciphertextError.Error);

        authenticator.VerifyHeaderMessage(validHeader, vector, 1);
        authenticator.VerifyCiphertext2Message(validCiphertext, ciphertext1, 1);
    }

    [Fact]
    public void AuthenticatorUpdate_ProvidesPcsContributionAndRejectsEpochGapOrOldReplay()
    {
        using var first = ManagedMlKemBraidAuthenticator.Initialize(Fill(0x11, 32));
        var seed = Fill(0x44, 32);
        var vector = Fill(0x55, 1152);
        var oldHeader = first.CreateHeaderMessage(seed, vector);
        using var updated = first.PrepareUpdate(Fill(0x22, 32), 2);
        var newHeader = updated.CreateHeaderMessage(seed, vector);
        Span<byte> ignoredSeed = stackalloc byte[32];
        Span<byte> ignoredHash = stackalloc byte[32];
        Span<byte> newMac = stackalloc byte[32];
        newHeader.CopyHeaderTo(ignoredSeed, ignoredHash, newMac);

        Assert.Equal(
            "9FB4D541B30BDC3542DBA180769B7375D24D102514920B7BC31CDBDA6C8E6570",
            Convert.ToHexString(newMac));
        var replay = Assert.Throws<MessagingCryptoException>(() =>
            updated.VerifyHeaderMessage(oldHeader, vector, 1));
        Assert.Equal(MessagingCryptoError.TransitionRejected, replay.Error);
        var gap = Assert.Throws<MessagingCryptoException>(() =>
            updated.PrepareUpdate(Fill(0x33, 32), 4));
        Assert.Equal(MessagingCryptoError.TransitionRejected, gap.Error);

        first.VerifyHeaderMessage(oldHeader, vector, 1);
        updated.VerifyHeaderMessage(newHeader, vector, 2);
    }

    [Fact]
    public void SealedState_RoundTripsWithoutPlaintextSecretSurfaceAndBindsExactSessionState()
    {
        var wrappingKey = Fill(0x88, 32);
        var stateBinding = Fill(0x99, 32);
        var nonce = Enumerable.Range(1, 24).Select(static value => checked((byte)value)).ToArray();
        using var original = ManagedMlKemBraidAuthenticator.Initialize(Fill(0x11, 32));

        var first = original.ExportSealedForTests(wrappingKey, stateBinding, nonce);
        var second = original.ExportSealedForTests(wrappingKey, stateBinding, nonce);

        Assert.Equal(first, second);
        Assert.Equal(115, first.Length);
        Assert.DoesNotContain(
            typeof(ManagedMlKemBraidAuthenticator).GetProperties(),
            static property => property.Name.Contains("Root", StringComparison.Ordinal) ||
                               property.Name.Contains("MacKey", StringComparison.Ordinal));
        Assert.DoesNotContain(
            typeof(ManagedMlKemBraidAuthenticator).GetMethods(),
            static method => method.Name.StartsWith("Copy", StringComparison.Ordinal));

        using var restored = ManagedMlKemBraidAuthenticator.ImportSealed(
            first,
            wrappingKey,
            stateBinding);
        var seed = Fill(0x44, 32);
        var vector = Fill(0x55, 1152);
        AssertHeaderEqual(
            original.CreateHeaderMessage(seed, vector),
            restored.CreateHeaderMessage(seed, vector));

        var wrongBinding = Assert.Throws<MessagingCryptoException>(() =>
            ManagedMlKemBraidAuthenticator.ImportSealed(first, wrappingKey, Fill(0x98, 32)));
        Assert.Equal(MessagingCryptoError.TransitionRejected, wrongBinding.Error);
        var wrongKey = Assert.Throws<MessagingCryptoException>(() =>
            ManagedMlKemBraidAuthenticator.ImportSealed(first, Fill(0x87, 32), stateBinding));
        Assert.Equal(MessagingCryptoError.TransitionRejected, wrongKey.Error);
        var changed = first.ToArray();
        changed[^1] ^= 0x01;
        var tampered = Assert.Throws<MessagingCryptoException>(() =>
            ManagedMlKemBraidAuthenticator.ImportSealed(changed, wrappingKey, stateBinding));
        Assert.Equal(MessagingCryptoError.TransitionRejected, tampered.Error);
    }

    [Fact]
    public void LocalPlaintextSubstate_RoundTripsExactlyAndRejectsHostileShape()
    {
        using var original = ManagedMlKemBraidAuthenticator.Initialize(Fill(0x11, 32));
        var encoded = original.ExportLocalPlaintextState();
        try
        {
            Assert.Equal(79, encoded.Length);
            using var restored = ManagedMlKemBraidAuthenticator.ImportLocalPlaintextState(encoded);
            AssertHeaderEqual(
                original.CreateHeaderMessage(Fill(0x44, 32), Fill(0x55, 1152)),
                restored.CreateHeaderMessage(Fill(0x44, 32), Fill(0x55, 1152)));

            Assert.Equal(MessagingCryptoError.InvalidInput,
                Assert.Throws<MessagingCryptoException>(() =>
                    ManagedMlKemBraidAuthenticator.ImportLocalPlaintextState(encoded[..^1])).Error);
            var wrongVersion = encoded.ToArray();
            try
            {
                wrongVersion[4] = 2;
                Assert.Equal(MessagingCryptoError.InvalidInput,
                    Assert.Throws<MessagingCryptoException>(() =>
                        ManagedMlKemBraidAuthenticator.ImportLocalPlaintextState(wrongVersion)).Error);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(wrongVersion);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    [Fact]
    public void InitializationAbortAndDisposeZeroOwnedSecrets()
    {
        SecretBuffer? capturedRoot = null;
        using (MessagingCryptoFaultInjection.InstallDarkForTests(
                   new MessagingCryptoFaultProbe
                   {
                       OwnedSecret = (name, value) =>
                       {
                           if (name == "braid.auth.root") capturedRoot = value;
                       },
                       Point = name =>
                       {
                           if (name == "braid.auth.after-root")
                               throw new InvalidOperationException("injected abort");
                       },
                   }))
        {
            Assert.Throws<InvalidOperationException>(() =>
                ManagedMlKemBraidAuthenticator.Initialize(Fill(0x11, 32)));
        }
        Assert.NotNull(capturedRoot);
        var aborted = Assert.Throws<MessagingCryptoException>(() =>
            capturedRoot!.Use(static _ => { }));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, aborted.Error);

        var live = ManagedMlKemBraidAuthenticator.Initialize(Fill(0x11, 32));
        live.Dispose();
        live.Dispose();
        var disposed = Assert.Throws<MessagingCryptoException>(() =>
            live.CreateHeaderMessage(Fill(0x44, 32), Fill(0x55, 1152)));
        Assert.Equal(MessagingCryptoError.ObjectDisposed, disposed.Error);
    }

    private static void AssertHeaderEqual(Dtr2BraidMessage expected, Dtr2BraidMessage actual)
    {
        Span<byte> expectedSeed = stackalloc byte[32];
        Span<byte> expectedHash = stackalloc byte[32];
        Span<byte> expectedMac = stackalloc byte[32];
        Span<byte> actualSeed = stackalloc byte[32];
        Span<byte> actualHash = stackalloc byte[32];
        Span<byte> actualMac = stackalloc byte[32];
        expected.CopyHeaderTo(expectedSeed, expectedHash, expectedMac);
        actual.CopyHeaderTo(actualSeed, actualHash, actualMac);
        Assert.Equal(expectedSeed.ToArray(), actualSeed.ToArray());
        Assert.Equal(expectedHash.ToArray(), actualHash.ToArray());
        Assert.Equal(expectedMac.ToArray(), actualMac.ToArray());
    }

    private static byte[] Fill(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();
}
