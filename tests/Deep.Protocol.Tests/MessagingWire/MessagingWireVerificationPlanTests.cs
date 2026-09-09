using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.Tests.MessagingWire;

public sealed class MessagingWireVerificationPlanTests
{
    [Fact]
    public void PublicFacadeMintsDistinctVerifiedCapabilities()
    {
        var offering = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var verifiedOffering = MessagingWireVerification.VerifyDpk2(
            Dpk2Codec.Encode(offering),
            new DpkCallbacks(offering));
        Assert.Equal(Dpk2Codec.Encode(offering), verifiedOffering.ExactBytes.ToArray());

        var initiation = MessagingWireFixtures.Dph2(offering, 4112);
        var verifiedInitiation = MessagingWireVerification.VerifyDph2(
            Dph2Codec.Encode(initiation),
            verifiedOffering,
            new DphCallbacks(initiation));
        Assert.Equal(Dph2Codec.Encode(initiation), verifiedInitiation.ExactBytes.ToArray());
        Assert.Equal(
            MessagingWireFixtures.Bytes(32, 0xd7),
            verifiedInitiation.InitiatorDeviceDirectoryHeadHashSpan.ToArray());

        var dtr = MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.Header).Record;
        var verifiedHeader = MessagingWireVerification.VerifyEmbeddedDtr2(
            Dtr2Codec.EncodeEmbedded(dtr),
            new DtrCallbacks());
        Assert.Equal(Dtr2Codec.EncodeEmbedded(dtr), verifiedHeader.ExactBytes.ToArray());

        var envelope = MessagingWireFixtures.Dpe2(dtr, 4112);
        using var verifiedEnvelope = MessagingWireVerification.VerifyDpe2(
            Dpe2Codec.Encode(envelope),
            new DtrCallbacks(),
            new DpeCallbacks());
        Assert.Equal(Dpe2Codec.Encode(envelope), verifiedEnvelope.ExactBytes.ToArray());
    }

    [Fact]
    public void CrossNetworkDph2CannotSelectOtherwiseExactOffering()
    {
        var offering = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var verifiedOffering = MessagingWireVerification.VerifyDpk2(
            Dpk2Codec.Encode(offering),
            new DpkCallbacks(offering));
        var crossNetwork = CloneDph2(
            MessagingWireFixtures.Dph2(offering, 4112),
            networkId: MessagingWireFixtures.Bytes(16, 0xe7));
        var crossNetworkBytes = Dph2Codec.Encode(crossNetwork);

        var codecException = Assert.Throws<MessagingWireFormatException>(() =>
            Dph2Codec.Decode(crossNetworkBytes, offering));
        Assert.Equal(MessagingWirePrevalidationStage.HashProjection, codecException.Stage);
        Assert.Equal(MessagingWireRejection.CrossFieldMismatch, codecException.Rejection);

        var exception = Assert.Throws<MessagingWireFormatException>(() =>
            MessagingWireVerification.VerifyDph2(
                crossNetworkBytes,
                verifiedOffering,
                new DphCallbacks(crossNetwork)));
        Assert.Equal(MessagingWirePrevalidationStage.HashProjection, exception.Stage);
        Assert.Equal(MessagingWireRejection.CrossFieldMismatch, exception.Rejection);
    }

    [Fact]
    public void ChangedDph2PayloadUnderSameClaimAndSessionTripsReplayFence()
    {
        var offering = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var verifiedOffering = MessagingWireVerification.VerifyDpk2(
            Dpk2Codec.Encode(offering),
            new DpkCallbacks(offering));
        var retainedRecord = MessagingWireFixtures.Dph2(offering, 4112);
        var changedRecord = CloneDph2(
            retainedRecord,
            ciphertext: Dph2InitialCiphertext.Import(MessagingWireFixtures.Bytes(4112, 0xc9)));
        var retained = MessagingWireVerification.VerifyDph2(
            Dph2Codec.Encode(retainedRecord), verifiedOffering, new DphCallbacks(retainedRecord));
        var changed = MessagingWireVerification.VerifyDph2(
            Dph2Codec.Encode(changedRecord), verifiedOffering, new DphCallbacks(changedRecord));

        Assert.Equal(retained.ClaimOperationId.ToArray(), changed.ClaimOperationId.ToArray());
        Assert.Equal(retained.SessionId.ToArray(), changed.SessionId.ToArray());
        Assert.NotEqual(retained.FullReplayHash.ToArray(), changed.FullReplayHash.ToArray());
        var exception = Assert.Throws<MessagingWireFormatException>(() =>
            MessagingWireVerification.RequireExactDph2Replay(retained, changed));
        Assert.Equal(MessagingWireRejection.CrossFieldMismatch, exception.Rejection);
    }

    [Fact]
    public void ChangedDpe2UnderSameOperationTripsReplayFence()
    {
        var dtr = MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.Ciphertext2).Record;
        var retainedRecord = MessagingWireFixtures.Dpe2(dtr, 4112);
        var changedRecord = new Dpe2Record(
            retainedRecord.NetworkId.Span,
            retainedRecord.SessionId.Span,
            retainedRecord.SenderDeviceId.Span,
            retainedRecord.RecipientDeviceId.Span,
            retainedRecord.OperationId.Span,
            retainedRecord.RatchetHeader,
            Dpe2Ciphertext.Import(MessagingWireFixtures.Bytes(4112, 0xd9)));
        using var retained = MessagingWireVerification.VerifyDpe2(
            Dpe2Codec.Encode(retainedRecord), new DtrCallbacks(), new DpeCallbacks());
        using var changed = MessagingWireVerification.VerifyDpe2(
            Dpe2Codec.Encode(changedRecord), new DtrCallbacks(), new DpeCallbacks());

        Assert.Equal(retained.OperationId.ToArray(), changed.OperationId.ToArray());
        Assert.NotEqual(retained.FullReplayHash.ToArray(), changed.FullReplayHash.ToArray());
        var exception = Assert.Throws<MessagingWireFormatException>(() =>
            MessagingWireVerification.RequireExactDpe2Replay(retained, changed));
        Assert.Equal(MessagingWireRejection.CrossFieldMismatch, exception.Rejection);
    }

    [Fact]
    public void Dpe2VerificationRejectsMissingOrEnvelopeSubstitutedAuthenticatedFacts()
    {
        var dtr = MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.None).Record;
        var envelope = MessagingWireFixtures.Dpe2(dtr, 4112);
        var exact = Dpe2Codec.Encode(envelope);

        var missing = Assert.Throws<MessagingWireFormatException>(() =>
            MessagingWireVerification.VerifyDpe2(
                exact, new DtrCallbacks(), new MissingDpeOutput()));
        Assert.Equal(MessagingWirePrevalidationStage.CryptographicVerification, missing.Stage);
        Assert.Equal(MessagingWireRejection.CallbackRejected, missing.Rejection);

        var substitutedCallback = new CapturingDpeOutput(substituteSession: true);
        var substituted = Assert.Throws<MessagingWireFormatException>(() =>
            MessagingWireVerification.VerifyDpe2(
                exact, new DtrCallbacks(), substitutedCallback));
        Assert.Equal(MessagingWirePrevalidationStage.CryptographicVerification, substituted.Stage);
        Assert.Equal(MessagingWireRejection.CallbackRejected, substituted.Rejection);
        Assert.All(substitutedCallback.CapturedBuffers, AssertZeroed);
    }

    [Fact]
    public void Dpe2AuthenticatedBuffersTransferOnceAndZeroizeOnDisposeAndFailures()
    {
        var dtr = MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.None).Record;
        var envelope = MessagingWireFixtures.Dpe2(dtr, 4112);
        var exact = Dpe2Codec.Encode(envelope);
        var callback = new CapturingDpeOutput();
        var verified = MessagingWireVerification.VerifyDpe2(
            exact, new DtrCallbacks(), callback);
        var factBuffers = CaptureFactBuffers(verified);

        Assert.Same(callback.CapturedBuffers[0], factBuffers[0]);
        Assert.Same(callback.CapturedBuffers[3], factBuffers[1]);
        Assert.Same(callback.CapturedBuffers[4], factBuffers[2]);
        Assert.Same(callback.CapturedBuffers[5], factBuffers[3]);
        AssertZeroed(callback.CapturedBuffers[1]);
        AssertZeroed(callback.CapturedBuffers[2]);

        verified.Dispose();
        Assert.All(callback.CapturedBuffers, AssertZeroed);
        Assert.Throws<ObjectDisposedException>(() => verified.NetworkId.ToArray());
        Assert.Throws<ObjectDisposedException>(() => verified.SessionId.ToArray());
        Assert.Throws<ObjectDisposedException>(() => verified.SenderAccountId.ToArray());
        Assert.Throws<ObjectDisposedException>(() => verified.ExactBytes.ToArray());
        Assert.Throws<ObjectDisposedException>(() =>
            verified.UseAuthenticatedPlaintext(static plaintext => plaintext.Length));

        var throwing = new CapturingDpeOutput(throwAfterAccept: true);
        Assert.Throws<InvalidOperationException>(() =>
            MessagingWireVerification.VerifyDpe2(
                exact, new DtrCallbacks(), throwing));
        Assert.All(throwing.CapturedBuffers, AssertZeroed);
    }

    [Theory]
    [InlineData(17)]
    [InlineData(22)]
    public void Dpk2SignedProjectionSubstitutionsFailFacadeVerification(int tag)
    {
        var fields = ManualMessagingWire.Dpk2Fields(MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime));
        fields[tag - 1].Value[0] ^= 0x40;
        var substitutedBytes = ManualMessagingWire.Record("DPK2", fields);
        var substituted = Dpk2Codec.Decode(substitutedBytes);

        var exception = Assert.Throws<MessagingWireFormatException>(() =>
            MessagingWireVerification.VerifyDpk2(substitutedBytes, new DpkCallbacks(substituted)));
        Assert.Equal(MessagingWirePrevalidationStage.CryptographicVerification, exception.Stage);
        Assert.Equal(MessagingWireRejection.CallbackRejected, exception.Rejection);
    }

    [Fact]
    public void PlansUseNarrowCountableCallbacksAndBindExactRecords()
    {
        var offering = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var dpkCallbacks = new DpkCallbacks(offering);
        var verifiedOffering = Dpk2VerificationPlan.Create(offering).Verify(dpkCallbacks);
        Assert.Equal(1, dpkCallbacks.ResolveCount);
        Assert.Equal(3, dpkCallbacks.SignatureCount);

        var initiation = MessagingWireFixtures.Dph2(offering, 4112);
        var dphCallbacks = new DphCallbacks(initiation);
        var verifiedInitiation = Dph2VerificationPlan
            .Create(initiation, verifiedOffering)
            .Verify(dphCallbacks);
        Assert.Equal(1, dphCallbacks.ResolveCount);
        Assert.Equal(1, dphCallbacks.ClaimCount);
        Assert.Equal(
            MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(initiation),
            verifiedInitiation.FullReplayHash.ToArray());

        var dtr = MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.Header).Record;
        var dtrCallbacks = new DtrCallbacks();
        var verifiedHeader = Dtr2VerificationPlan.Create(dtr).Verify(dtrCallbacks);
        Assert.Equal(1, dtrCallbacks.Count);

        var envelope = MessagingWireFixtures.Dpe2(dtr, 4112);
        var dpeCallbacks = new DpeCallbacks();
        Dpe2VerificationPlan.Create(envelope, verifiedHeader).Verify(dpeCallbacks);
        Assert.Equal(1, dpeCallbacks.Count);
    }

    [Fact]
    public void RejectedCallbacksStopAtTheExactBoundary()
    {
        var offering = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var callbacks = new DpkCallbacks(offering) { AcceptSignatures = false };
        var exception = Assert.Throws<MessagingWireFormatException>(
            () => Dpk2VerificationPlan.Create(offering).Verify(callbacks));
        Assert.Equal(MessagingWirePrevalidationStage.CryptographicVerification, exception.Stage);
        Assert.Equal(1, callbacks.ResolveCount);
        Assert.Equal(1, callbacks.SignatureCount);
    }

    [Fact]
    public void Dpe2MessageKeyMatchesIndependentFrozenConstruction()
    {
        var dtr = MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.Ciphertext2).Record;
        var envelope = MessagingWireFixtures.Dpe2(dtr, 4112);
        var verifiedHeader = Dtr2VerificationPlan.Create(dtr).Verify(new DtrCallbacks());
        var plan = Dpe2VerificationPlan.Create(envelope, verifiedHeader);
        var ecKey = MessagingWireFixtures.Bytes(32, 0xa1);
        var pqKey = MessagingWireFixtures.Bytes(32, 0xc1);

        using var actualOwner = plan.DeriveMessageKey(ecKey, pqKey);
        var actual = actualOwner.Copy();
        var expected = IndependentMessageKey(envelope, ecKey, pqKey);
        try
        {
            Assert.Equal(expected, actual);
            Assert.Equal(
                "ed82c766fadc5f9f247118e9b0f06a7637cadae79becd54b2cd7e2086e1d869a",
                Convert.ToHexString(actual).ToLowerInvariant());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(ecKey);
            CryptographicOperations.ZeroMemory(pqKey);
        }
    }

    private static byte[] IndependentMessageKey(
        Dpe2Record record,
        ReadOnlySpan<byte> ecKey,
        ReadOnlySpan<byte> pqKey)
    {
        var sessionId = record.SessionId.ToArray();
        var headerHash = SHA256.HashData(DomainHashInput(
            "Deep/Messaging/V2/ratchet-header",
            Dtr2Codec.EncodeEmbedded(record.RatchetHeader)));
        var salt = SHA512.HashData(DomainHashInput(
            "Deep/Messaging/V2/triple-ratchet-salt",
            sessionId));
        var ecOwned = ecKey.ToArray();
        var pqOwned = pqKey.ToArray();
        var protocolInfo = Encoding.ASCII.GetBytes(
            "DeepTripleRatchetV1_X25519_MLKEM768_XCHACHA20");
        var hybridIkm = Context(
            "Deep/Messaging/V2/hybrid-message-ikm",
            protocolInfo,
            ecOwned,
            pqOwned);
        var info = Context(
            "Deep/Messaging/V2/message-key",
            protocolInfo,
            sessionId,
            U64(record.RatchetHeader.EcMessageNumber),
            U64(record.RatchetHeader.SckaSendingEpoch),
            U64(record.RatchetHeader.SckaMessageNumber),
            headerHash);
        var prk = new byte[64];
        var output = new byte[32];
        try
        {
            Assert.Equal(64, HKDF.Extract(HashAlgorithmName.SHA512, hybridIkm, salt, prk));
            HKDF.Expand(HashAlgorithmName.SHA512, prk, output, info);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sessionId);
            CryptographicOperations.ZeroMemory(headerHash);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(ecOwned);
            CryptographicOperations.ZeroMemory(pqOwned);
            CryptographicOperations.ZeroMemory(protocolInfo);
            CryptographicOperations.ZeroMemory(hybridIkm);
            CryptographicOperations.ZeroMemory(info);
            CryptographicOperations.ZeroMemory(prk);
        }
    }

    private static byte[] DomainHashInput(string label, ReadOnlySpan<byte> value)
    {
        var labelBytes = Encoding.ASCII.GetBytes(label);
        var output = new byte[labelBytes.Length + 5 + value.Length];
        labelBytes.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(labelBytes.Length + 1), checked((uint)value.Length));
        value.CopyTo(output.AsSpan(labelBytes.Length + 5));
        return output;
    }

    private static byte[] Context(string label, params byte[][] parts)
    {
        var labelBytes = Encoding.ASCII.GetBytes(label);
        var length = labelBytes.Length + 5 + parts.Sum(static part => 4 + part.Length);
        var output = new byte[length];
        labelBytes.CopyTo(output, 0);
        var offset = labelBytes.Length + 1;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset + 2), checked((ushort)parts.Length));
        offset += 4;
        foreach (var part in parts)
        {
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset), checked((uint)part.Length));
            part.CopyTo(output, offset + 4);
            offset += 4 + part.Length;
        }
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private sealed class DpkCallbacks(Dpk2Record record) : IDpk2VerificationCallbacks
    {
        internal int ResolveCount { get; private set; }
        internal int SignatureCount { get; private set; }
        internal bool AcceptSignatures { get; init; } = true;

        public Dpk2ResolvedDevice ResolveActiveDevice(Dpk2Record offering)
        {
            Assert.Equal(Dpk2Codec.Encode(record), Dpk2Codec.Encode(offering));
            ResolveCount++;
            return new Dpk2ResolvedDevice(
                MessagingWireFixtures.Dpk2SigningPublicKey(),
                offering.DeviceAgreementPublicKey.Span);
        }

        public bool VerifyEd25519(
            ReadOnlyMemory<byte> publicKey,
            ReadOnlyMemory<byte> signatureInput,
            ReadOnlyMemory<byte> signature)
        {
            Assert.Equal(32, publicKey.Length);
            Assert.NotEmpty(signatureInput.ToArray());
            Assert.Equal(64, signature.Length);
            SignatureCount++;
            return AcceptSignatures && PublicKeyAuth.VerifyDetached(
                signature.ToArray(), signatureInput.ToArray(), publicKey.ToArray());
        }
    }

    private sealed class DphCallbacks(Dph2Record record) : IDph2VerificationCallbacks
    {
        internal int ResolveCount { get; private set; }
        internal int ClaimCount { get; private set; }

        public Dph2ResolvedInitiator ResolveInitiator(Dph2Record initiation)
        {
            Assert.Equal(Dph2Codec.Encode(record), Dph2Codec.Encode(initiation));
            ResolveCount++;
            return new Dph2ResolvedInitiator(
                initiation.InitiatorDeviceAgreementPublicKey.Span,
                MessagingWireFixtures.Bytes(32, 0xd7));
        }

        public bool VerifyExactClaim(Dph2ClaimVerification claim)
        {
            Assert.Equal(record.ClaimOperationId.ToArray(), claim.OperationId.ToArray());
            Assert.Equal(record.SessionId.ToArray(), claim.SessionId.ToArray());
            ClaimCount++;
            return true;
        }
    }

    private sealed class DtrCallbacks : IDtr2VerificationCallbacks
    {
        internal int Count { get; private set; }
        public bool VerifyBraidMessage(Dtr2Record header)
        {
            Assert.NotNull(header);
            Count++;
            return true;
        }
    }

    private sealed class DpeCallbacks : IDpe2VerificationCallbacks
    {
        internal int Count { get; private set; }
        public void AuthenticateExactEnvelope(
            Dpe2AuthenticationVerification verification,
            Dpe2AuthenticationOutput output)
        {
            Assert.Equal(24, verification.Nonce.Length);
            Assert.True(verification.Ciphertext.Length is 4112 or 16400 or 32784 or 49152);
            Assert.NotEmpty(verification.AssociatedData.ToArray());
            Assert.Equal(32, verification.ExactEnvelopeHash.Length);
            Count++;
            output.AcceptAuthenticatedPlaintext(
                new byte[282],
                verification.NetworkId.Span,
                verification.SessionId.Span,
                MessagingWireFixtures.Bytes(32, 0x23),
                verification.SenderDeviceId.Span,
                MessagingWireFixtures.Bytes(32, 0x24));
        }
    }

    private sealed class MissingDpeOutput : IDpe2VerificationCallbacks
    {
        public void AuthenticateExactEnvelope(
            Dpe2AuthenticationVerification verification,
            Dpe2AuthenticationOutput output)
        {
        }
    }

    private sealed class CapturingDpeOutput(
        bool substituteSession = false,
        bool throwAfterAccept = false) : IDpe2VerificationCallbacks
    {
        internal IReadOnlyList<byte[]> CapturedBuffers { get; private set; } = [];

        public void AuthenticateExactEnvelope(
            Dpe2AuthenticationVerification verification,
            Dpe2AuthenticationOutput output)
        {
            output.AcceptAuthenticatedPlaintext(
                MessagingWireFixtures.Bytes(282, 0x71),
                verification.NetworkId.Span,
                substituteSession
                    ? MessagingWireFixtures.Bytes(32, 0xee)
                    : verification.SessionId.Span,
                MessagingWireFixtures.Bytes(32, 0x23),
                verification.SenderDeviceId.Span,
                MessagingWireFixtures.Bytes(32, 0x24));
            CapturedBuffers = CapturePrivateBuffers(output,
                "_plaintext", "_networkId", "_sessionId", "_senderAccountId", "_senderDeviceId", "_conversationId");
            if (throwAfterAccept)
                throw new InvalidOperationException("Synthetic callback failure after accepting plaintext.");
        }
    }

    private static IReadOnlyList<byte[]> CaptureFactBuffers(VerifiedDpe2Envelope envelope)
    {
        var facts = typeof(VerifiedDpe2Envelope)
            .GetField("_authenticated", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(envelope)!;
        return CapturePrivateBuffers(facts,
            "_plaintext", "_senderAccountId", "_senderDeviceId", "_conversationId");
    }

    private static IReadOnlyList<byte[]> CapturePrivateBuffers(object owner, params string[] names) =>
        names.Select(name => Assert.IsType<byte[]>(owner.GetType()
            .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(owner))).ToArray();

    private static void AssertZeroed(byte[] value) => Assert.All(value, item => Assert.Equal(0, item));

    private static Dph2Record CloneDph2(
        Dph2Record source,
        byte[]? networkId = null,
        Dph2InitialCiphertext? ciphertext = null)
    {
        if (ciphertext is null)
        {
            var copy = new byte[source.InitialCiphertext.Length];
            source.InitialCiphertext.CopyCiphertextTo(copy);
            ciphertext = Dph2InitialCiphertext.Import(copy);
        }

        return new Dph2Record(
            networkId ?? source.NetworkId.ToArray(),
            source.InitiatorAccountId.Span,
            source.InitiatorDeviceId.Span,
            source.InitiatorDeviceGeneration,
            source.InitiatorDpd1Ref.Span,
            source.ResponderAccountId.Span,
            source.ResponderDeviceId.Span,
            source.ResponderDeviceGeneration,
            source.ExactDpk2Hash.Span,
            source.ClaimOperationId.Span,
            source.ClaimReceiptHash.Span,
            source.LastResortUseCounter,
            source.InitiatorDeviceAgreementPublicKey.Span,
            source.InitiatorEphemeralX25519PublicKey.Span,
            source.SelectedPrekey,
            source.ActualMlKem768Ciphertext.Span,
            source.InitiatorInitialRatchetX25519PublicKey.Span,
            source.InitialPayloadNonce.Span,
            ciphertext);
    }
}
