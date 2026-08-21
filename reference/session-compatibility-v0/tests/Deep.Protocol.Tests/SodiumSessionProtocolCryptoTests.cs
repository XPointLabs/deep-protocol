using Deep.Protocol.Abstractions;

namespace Deep.Protocol.Tests;

public sealed class SodiumSessionProtocolCryptoTests
{
    private static readonly DateTimeOffset Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(1754971101000);

    [Fact]
    public void SignAndVerifyDetachedRoundTrip()
    {
        var crypto = new SodiumSessionProtocolCrypto();
        var secret = crypto.GenerateEd25519SecretKey();
        var publicKey = crypto.ConvertEd25519PublicKeyToX25519(
            Sodium.PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(secret));

        var message = "session-proof"u8.ToArray();
        var signature = crypto.SignEd25519Detached(message, secret);

        Assert.True(crypto.VerifyEd25519Detached(signature, message, Sodium.PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(secret)));
        Assert.Equal(ProtocolConstants.SignatureSize, signature.Length);
        Assert.Equal(ProtocolConstants.X25519PublicKeySize, publicKey.Length);
    }

    [Fact]
    public void Blake2b256Personalized_IsStableForSameInputs()
    {
        var crypto = new SodiumSessionProtocolCrypto();

        var hash1 = crypto.Blake2b256Personalized(
            ProtocolConstants.ProBuildProofHashPersonalisation,
            new ReadOnlyMemory<byte>[]
            {
                new byte[] { 0x01 },
                BitConverter.GetBytes((ulong)Timestamp.ToUnixTimeMilliseconds())
            });

        var hash2 = crypto.Blake2b256Personalized(
            ProtocolConstants.ProBuildProofHashPersonalisation,
            new ReadOnlyMemory<byte>[]
            {
                new byte[] { 0x01 },
                BitConverter.GetBytes((ulong)Timestamp.ToUnixTimeMilliseconds())
            });

        Assert.Equal(hash1, hash2);
        Assert.Equal(32, hash1.Length);
    }

    [Fact]
    public void OneToOneEncryptionRoundTrip_PreservesSenderAndMessage()
    {
        var crypto = new SodiumSessionProtocolCrypto();
        var sender = crypto.GenerateEd25519SecretKey();
        var recipient = crypto.GenerateEd25519SecretKey();

        var recipientPublic = Sodium.PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(
            Sodium.PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(recipient));

        var plaintext = "hello-session"u8.ToArray();
        var ciphertext = crypto.EncryptForRecipient(sender, recipientPublic, plaintext);
        var decrypted = crypto.DecryptIncoming(recipient, ciphertext);

        Assert.Equal(plaintext, decrypted.Plaintext.ToArray());
        Assert.Equal(
            Sodium.PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(sender),
            decrypted.SenderEd25519PublicKey.ToArray());
    }

    [Fact]
    public void EncryptForBlindedRecipient_ValidatesInputShapes()
    {
        var crypto = new SodiumSessionProtocolCrypto();
        var sender = crypto.GenerateEd25519SecretKey();

        var exServer = Assert.Throws<ArgumentException>(() =>
            crypto.EncryptForBlindedRecipient(sender, new byte[ProtocolConstants.X25519PublicKeySize - 1], new byte[ProtocolConstants.X25519PublicKeySize], "x"u8.ToArray()));
        Assert.Equal("serverPublicKey", exServer.ParamName);

        var exRecipient = Assert.Throws<ArgumentException>(() =>
            crypto.EncryptForBlindedRecipient(sender, new byte[ProtocolConstants.X25519PublicKeySize], new byte[31], "x"u8.ToArray()));
        Assert.Equal("recipientBlindedId", exRecipient.ParamName);
    }

    [Fact]
    public void GroupEncryptionRoundTrip_RestoresPayloadWithCompressionAndPadding()
    {
        var crypto = new SodiumSessionProtocolCrypto();
        var senderSecret = crypto.GenerateEd25519SecretKey();
        var groupSecret = crypto.GenerateEd25519SecretKey();
        var groupPublic = Sodium.PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(groupSecret);

        var payload = "group-message-with-padding"u8.ToArray();
        var encrypted = crypto.EncryptForGroup(
            senderSecret,
            groupPublic,
            new byte[ProtocolConstants.X25519PublicKeySize],
            payload,
            compress: true,
            padding: 160);

        var decrypted = crypto.DecryptGroupMessage([groupSecret], groupPublic, encrypted);

        Assert.Equal(payload, decrypted.Plaintext.ToArray());
        Assert.Equal(0, decrypted.KeyIndex);
        Assert.StartsWith("05", decrypted.SenderSessionIdHex, StringComparison.Ordinal);
    }

    [Fact]
    public void EncryptForGroup_RejectsInvalidEncryptionKeySize()
    {
        var crypto = new SodiumSessionProtocolCrypto();
        var senderSecret = crypto.GenerateEd25519SecretKey();
        var groupSecret = crypto.GenerateEd25519SecretKey();
        var groupPublic = Sodium.PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(groupSecret);

        var ex = Assert.Throws<ArgumentException>(() =>
            crypto.EncryptForGroup(
                senderSecret,
                groupPublic,
                new byte[ProtocolConstants.X25519PublicKeySize - 1],
                "x"u8.ToArray(),
                compress: false,
                padding: 0));

        Assert.Equal("groupEncryptionKey", ex.ParamName);
    }
}