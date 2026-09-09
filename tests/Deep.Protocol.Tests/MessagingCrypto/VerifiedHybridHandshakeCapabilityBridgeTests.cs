using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.Tests.MessagingWire;
using Sodium;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class VerifiedHybridHandshakeCapabilityBridgeTests
{
    [Fact]
    public void VerifiedWireInitiationMintsDirectionalTranscriptCapabilities()
    {
        var (offering, initiation, verified) = VerifyOneTimeInitiation();

        var aliceBinding = Binding(offering, initiation, localIsInitiator: true);
        var aliceCapability = VerifiedHybridTranscriptCapability.FromVerifiedInitiation(
            verified, aliceBinding, localIsInitiator: true);
        var alice = aliceCapability.Consume(initiation.ActualMlKem768Ciphertext.Span);
        try
        {
            Assert.Equal(verified.TranscriptHash.ToArray(), alice.TranscriptHash);
            Assert.Null(alice.FullDph2ReplayHash);
            Assert.Equal(offering.OneTimeX25519PrekeyId.ToArray(), alice.X25519PreKeyId);
            Assert.Equal(offering.MlKemPrekeyId.ToArray(), alice.MlKemPreKeyId);
        }
        finally
        {
            Zero(alice);
        }

        var bobBinding = Binding(offering, initiation, localIsInitiator: false);
        var bobCapability = VerifiedHybridTranscriptCapability.FromVerifiedInitiation(
            verified, bobBinding, localIsInitiator: false);
        var bob = bobCapability.ConsumeBoundForResponder();
        try
        {
            Assert.Equal(verified.TranscriptHash.ToArray(), bob.TranscriptHash);
            Assert.Equal(verified.FullReplayHash.ToArray(), bob.FullDph2ReplayHash);
            Assert.Equal(offering.OneTimeX25519PrekeyId.ToArray(), bob.X25519PreKeyId);
        }
        finally
        {
            Zero(bob);
        }
    }

    [Fact]
    public void BridgeRejectsTranscriptDeviceDirectionAndResponderHeadSubstitution()
    {
        var (offering, initiation, verified) = VerifyOneTimeInitiation();

        Assert.Equal(
            MessagingCryptoError.InvalidInput,
            Assert.Throws<MessagingCryptoException>(() =>
                VerifiedHybridTranscriptCapability.FromVerifiedInitiation(
                    verified,
                    Binding(offering, initiation, true, transcript: Bytes(64, 0xe1)),
                    true)).Error);

        Assert.Equal(
            MessagingCryptoError.InvalidInput,
            Assert.Throws<MessagingCryptoException>(() =>
                VerifiedHybridTranscriptCapability.FromVerifiedInitiation(
                    verified,
                    Binding(offering, initiation, true, localDevice: Bytes(32, 0xe2)),
                    true)).Error);

        Assert.Equal(
            MessagingCryptoError.InvalidInput,
            Assert.Throws<MessagingCryptoException>(() =>
                VerifiedHybridTranscriptCapability.FromVerifiedInitiation(
                    verified,
                    Binding(offering, initiation, true, responderHead: Bytes(32, 0xe3)),
                    true)).Error);

        Assert.Equal(
            MessagingCryptoError.InvalidInput,
            Assert.Throws<MessagingCryptoException>(() =>
                VerifiedHybridTranscriptCapability.FromVerifiedInitiation(
                    verified,
                    Binding(offering, initiation, true),
                    false)).Error);
    }

    [Fact]
    public void BridgeCapabilityIsSingleUseAndRejectsCiphertextSubstitution()
    {
        var (offering, initiation, verified) = VerifyOneTimeInitiation();
        var substituted = initiation.ActualMlKem768Ciphertext.ToArray();
        substituted[^1] ^= 1;
        var rejected = VerifiedHybridTranscriptCapability.FromVerifiedInitiation(
            verified, Binding(offering, initiation, true), true);
        Assert.Equal(
            MessagingCryptoError.PreKeyConflict,
            Assert.Throws<MessagingCryptoException>(() => rejected.Consume(substituted)).Error);
        Assert.Equal(
            MessagingCryptoError.CapabilityConsumed,
            Assert.Throws<MessagingCryptoException>(() =>
                rejected.Consume(initiation.ActualMlKem768Ciphertext.Span)).Error);

        var consumed = VerifiedHybridTranscriptCapability.FromVerifiedInitiation(
            verified, Binding(offering, initiation, false), false);
        var data = consumed.ConsumeBoundForResponder();
        Zero(data);
        Assert.Equal(
            MessagingCryptoError.CapabilityConsumed,
            Assert.Throws<MessagingCryptoException>(consumed.ConsumeBoundForResponder).Error);
    }

    private static (Dpk2Record Offering, Dph2Record Initiation, VerifiedDph2Initiation Verified)
        VerifyOneTimeInitiation()
    {
        var offering = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var verifiedOffering = MessagingWireVerification.VerifyDpk2(
            Dpk2Codec.Encode(offering), new DpkCallbacks(offering));
        var initiation = MessagingWireFixtures.Dph2(offering, 4112);
        var verified = MessagingWireVerification.VerifyDph2(
            Dph2Codec.Encode(initiation), verifiedOffering, new DphCallbacks(initiation));
        return (offering, initiation, verified);
    }

    private static RatchetStateBinding Binding(
        Dpk2Record offering,
        Dph2Record initiation,
        bool localIsInitiator,
        byte[]? transcript = null,
        byte[]? localDevice = null,
        byte[]? responderHead = null)
    {
        var initiatorHead = Bytes(32, 0xd1);
        var actualResponderHead = responderHead ?? offering.DeviceDirectoryHeadHash.ToArray();
        return localIsInitiator
            ? new RatchetStateBinding(
                MessagingCryptoConstants.Suite,
                initiation.SessionId.Span,
                transcript ?? MessagingWireCryptographicInputs.ComputeDph2TranscriptHash(offering, initiation),
                localDevice ?? initiation.InitiatorDeviceId.ToArray(),
                initiation.InitiatorDeviceGeneration,
                initiatorHead,
                initiation.ResponderDeviceId.Span,
                initiation.ResponderDeviceGeneration,
                actualResponderHead)
            : new RatchetStateBinding(
                MessagingCryptoConstants.Suite,
                initiation.SessionId.Span,
                transcript ?? MessagingWireCryptographicInputs.ComputeDph2TranscriptHash(offering, initiation),
                localDevice ?? initiation.ResponderDeviceId.ToArray(),
                initiation.ResponderDeviceGeneration,
                actualResponderHead,
                initiation.InitiatorDeviceId.Span,
                initiation.InitiatorDeviceGeneration,
                initiatorHead);
    }

    private static byte[] Bytes(int length, byte seed) =>
        MessagingWireFixtures.Bytes(length, seed);

    private static void Zero(VerifiedHybridTranscriptData data)
    {
        CryptographicOperations.ZeroMemory(data.TranscriptHash);
        CryptographicOperations.ZeroMemory(data.MlKemCiphertext);
        if (data.FullDph2ReplayHash is not null)
            CryptographicOperations.ZeroMemory(data.FullDph2ReplayHash);
        if (data.X25519PreKeyId is not null)
            CryptographicOperations.ZeroMemory(data.X25519PreKeyId);
        CryptographicOperations.ZeroMemory(data.MlKemPreKeyId);
    }

    private sealed class DpkCallbacks(Dpk2Record expected) : IDpk2VerificationCallbacks
    {
        public Dpk2ResolvedDevice ResolveActiveDevice(Dpk2Record offering)
        {
            Assert.Equal(Dpk2Codec.Encode(expected), Dpk2Codec.Encode(offering));
            return new Dpk2ResolvedDevice(
                MessagingWireFixtures.Dpk2SigningPublicKey(),
                offering.DeviceAgreementPublicKey.Span);
        }

        public bool VerifyEd25519(
            ReadOnlyMemory<byte> publicKey,
            ReadOnlyMemory<byte> signatureInput,
            ReadOnlyMemory<byte> signature) =>
            PublicKeyAuth.VerifyDetached(
                signature.ToArray(), signatureInput.ToArray(), publicKey.ToArray());
    }

    private sealed class DphCallbacks(Dph2Record expected) : IDph2VerificationCallbacks
    {
        public Dph2ResolvedInitiator ResolveInitiator(Dph2Record initiation)
        {
            Assert.Equal(Dph2Codec.Encode(expected), Dph2Codec.Encode(initiation));
            return new Dph2ResolvedInitiator(
                initiation.InitiatorDeviceAgreementPublicKey.Span,
                Bytes(32, 0xd8));
        }

        public bool VerifyExactClaim(Dph2ClaimVerification claim) =>
            claim.OperationId.Span.SequenceEqual(expected.ClaimOperationId.Span) &&
            claim.ReceiptHash.Span.SequenceEqual(expected.ClaimReceiptHash.Span) &&
            claim.SessionId.Span.SequenceEqual(expected.SessionId.Span);
    }
}
