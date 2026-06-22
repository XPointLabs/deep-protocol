using Deep.Protocol.Abstractions;
using Sodium;
using System.Text;

namespace Deep.Protocol.Tests;

public sealed class SodiumDifferentialTests
{
    [Fact]
    public void NormalizeSeedMatchesDirectSodiumKeypairExpansion()
    {
        var crypto = new SodiumSessionProtocolCrypto();
        var seed = Enumerable.Range(0, ProtocolConstants.Ed25519SeedSize).Select(i => (byte)i).ToArray();

        var adapter = crypto.NormalizeEd25519SecretKey(seed);
        var direct = PublicKeyAuth.GenerateKeyPair(seed).PrivateKey;

        Assert.Equal(direct, adapter);
    }

    [Fact]
    public void SignDetachedMatchesDirectSodiumForSameInputs()
    {
        var crypto = new SodiumSessionProtocolCrypto();
        var seed = Enumerable.Range(0, ProtocolConstants.Ed25519SeedSize).Select(i => (byte)(255 - i)).ToArray();
        var secret = PublicKeyAuth.GenerateKeyPair(seed).PrivateKey;
        var message = "differential-signature"u8.ToArray();

        var adapter = crypto.SignEd25519Detached(message, secret);
        var direct = PublicKeyAuth.SignDetached(message, secret);

        Assert.Equal(direct, adapter);
        Assert.True(crypto.VerifyEd25519Detached(adapter, message, PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(secret)));
    }

    [Fact]
    public void RecipientEncryptionPayloadIsDirectlyDecryptableBySodium()
    {
        var crypto = new SodiumSessionProtocolCrypto();
        var senderSeed = Enumerable.Range(0, ProtocolConstants.Ed25519SeedSize).Select(i => (byte)(i + 1)).ToArray();
        var recipientSeed = Enumerable.Range(0, ProtocolConstants.Ed25519SeedSize).Select(i => (byte)(i + 33)).ToArray();
        var senderSecret = PublicKeyAuth.GenerateKeyPair(senderSeed).PrivateKey;
        var recipientSecret = PublicKeyAuth.GenerateKeyPair(recipientSeed).PrivateKey;
        var recipientPublic = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(
            PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(recipientSecret));

        var ciphertext = crypto.EncryptForRecipient(senderSecret, recipientPublic, "hello-onion"u8.ToArray());

        var recipientX25519Secret = PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(recipientSecret);
        var recipientX25519Public = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(
            PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(recipientSecret));
        var plaintext = SealedPublicKeyBox.Open(ciphertext, recipientX25519Secret, recipientX25519Public);

        Assert.True(plaintext.Length > ProtocolConstants.SessionIdSize);
        Assert.Equal((byte)SessionIdPrefix.Standard, plaintext[0]);

        var senderPublic = PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(senderSecret);
        Assert.Equal(senderPublic, plaintext[1..(1 + ProtocolConstants.Ed25519PublicKeySize)]);
    }

    [Fact]
    public void ConvertEd25519PublicKeyToX25519_MatchesDirectSodiumConversion()
    {
        var crypto = new SodiumSessionProtocolCrypto();
        var seed = Enumerable.Range(0, ProtocolConstants.Ed25519SeedSize).Select(i => (byte)(i + 17)).ToArray();
        var keyPair = PublicKeyAuth.GenerateKeyPair(seed);

        var adapter = crypto.ConvertEd25519PublicKeyToX25519(keyPair.PublicKey);
        var direct = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(keyPair.PublicKey);

        Assert.Equal(direct, adapter);
    }

    [Fact]
    public void Blake2b256Personalized_MatchesDirectSodiumGenericHash()
    {
        var crypto = new SodiumSessionProtocolCrypto();
        var parts = new ReadOnlyMemory<byte>[]
        {
            new byte[] { 0x01, 0x02, 0x03 },
            Encoding.ASCII.GetBytes("deep")
        };

        var adapter = crypto.Blake2b256Personalized(ProtocolConstants.ProBuildProofHashPersonalisation, parts);
        var direct = GenericHash.HashSaltPersonal(
            parts.SelectMany(static p => p.ToArray()).ToArray(),
            key: null,
            salt: new byte[16],
            personal: Encoding.ASCII.GetBytes(ProtocolConstants.ProBuildProofHashPersonalisation),
            bytes: 32);

        Assert.Equal(direct, adapter);
    }

    [Fact]
    public void BlindedRecipientEncryption_SupportsBlind15AndBlind25SessionPrefixes()
    {
        var crypto = new SodiumSessionProtocolCrypto();
        var sender = PublicKeyAuth.GenerateKeyPair(Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray()).PrivateKey;
        var recipient = PublicKeyAuth.GenerateKeyPair(Enumerable.Range(0, 32).Select(i => (byte)(i + 101)).ToArray()).PrivateKey;
        var recipientX25519Public = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(
            PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(recipient));
        var recipientX25519Secret = PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(recipient);
        var senderPublic = PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(sender);
        var serverPublicKey = Enumerable.Repeat((byte)0x77, ProtocolConstants.X25519PublicKeySize).ToArray();
        var body = "blinded-payload"u8.ToArray();

        var blind15Recipient = new byte[ProtocolConstants.SessionIdSize];
        blind15Recipient[0] = (byte)SessionIdPrefix.Blind15;
        recipientX25519Public.CopyTo(blind15Recipient.AsSpan(1));

        var blind25Recipient = new byte[ProtocolConstants.SessionIdSize];
        blind25Recipient[0] = (byte)SessionIdPrefix.Blind25;
        recipientX25519Public.CopyTo(blind25Recipient.AsSpan(1));

        var encrypted15 = crypto.EncryptForBlindedRecipient(sender, serverPublicKey, blind15Recipient, body);
        var encrypted25 = crypto.EncryptForBlindedRecipient(sender, serverPublicKey, blind25Recipient, body);

        var decrypted15 = SealedPublicKeyBox.Open(encrypted15, recipientX25519Secret, recipientX25519Public);
        var decrypted25 = SealedPublicKeyBox.Open(encrypted25, recipientX25519Secret, recipientX25519Public);

        Assert.Equal((byte)SessionIdPrefix.Blind15, decrypted15[0]);
        Assert.Equal((byte)SessionIdPrefix.Blind25, decrypted25[0]);
        Assert.Equal(senderPublic, decrypted15[1..(1 + ProtocolConstants.Ed25519PublicKeySize)]);
        Assert.Equal(senderPublic, decrypted25[1..(1 + ProtocolConstants.Ed25519PublicKeySize)]);
        Assert.Equal(body, decrypted15[ProtocolConstants.SessionIdSize..]);
        Assert.Equal(body, decrypted25[ProtocolConstants.SessionIdSize..]);
    }
}