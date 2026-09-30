using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.ContactV2;

public sealed partial class DeepIdV2PreKeyClaimReceiptVerifierTests
{
    [Fact]
    public void PromotionSurfaceHasNoV1OrCallerTrustBoundary()
    {
        var method = Assert.Single(typeof(Dph2InitialClaimPreview).GetMethods(),
            candidate => candidate.Name == "VerifyCurrentAsync");
        Assert.Equal(new[] { typeof(VerifiedContactServicePlacement),
            typeof(DeepIdV2CurrentContactAuthorization), typeof(ParsedDcr1V2),
            typeof(VerifiedDeepIdV2DirectoryFreshness), typeof(OnionTrustedTimeAuthority),
            typeof(CancellationToken) }, method.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.Equal(typeof(ParsedXpk1V2), typeof(Dph2InitialClaimPreview).GetProperty("Request")!.PropertyType);
        Assert.Equal(typeof(ParsedXpc1V2), typeof(Dph2InitialClaimPreview).GetProperty("Result")!.PropertyType);
        Assert.Empty(typeof(Dph2InitialClaimPreview).GetConstructors());
        Assert.Empty(typeof(VerifiedDph2InitialClaim).GetConstructors());
        Assert.Equal(typeof(ParsedDcr1V2), typeof(VerifiedDph2InitialClaim).GetProperty("RecipientClosure")!.PropertyType);
        Assert.Equal("Deep.Protocol.MessagingCrypto", typeof(VerifiedInitialSessionPreKeyClaim).Namespace);
        Assert.Equal("Deep.Protocol.MessagingCrypto", typeof(VerifiedDevicePreKeyClaimReservation).Namespace);
    }

    // Actual V2 signed recipient/replica records and real XChaCha20 AEAD.
    // The existing directory/network/PQ output seams are explicitly bounded;
    // this does not claim approved-provider hybrid AKE or physical delivery.
    private static async Task AssertV2EncryptedPrefixAsync(ParsedXpk1V2 request,
        ParsedXpc1V2 result, Dph2Record header, VerifiedXpc1V2PreKeyClaimReceipt receipt,
        VerifiedContactServicePlacement placement, DeepIdV2CurrentContactAuthorization contact,
        ParsedDcr1V2 closure, byte[] boot)
    {
        var prefix = Dph2InitialClaimTranscriptCodec.Encode(request.CanonicalBytes.Span,
            result.WireBytes.Span, header);
        Assert.Equal(8 + request.CanonicalBytes.Length + result.WireBytes.Length, prefix.Length);
        Assert.True(prefix.Length >= 4542);
        Assert.True(prefix.Length + 4 > 4096);
        var body = prefix.Concat(new byte[] { 1 }).ToArray();
        var decoded = Dph2InitialClaimTranscriptCodec.DecodePrefix(body, header);
        Assert.Equal(prefix.Length, decoded.Consumed);
        Assert.Equal(request.CanonicalBytes.ToArray(), decoded.Request.CanonicalBytes.ToArray());
        Assert.Equal(result.WireBytes.ToArray(), decoded.Result.WireBytes.ToArray());
        Assert.Throws<CryptographicException>(() => Dph2InitialClaimTranscriptCodec.DecodePrefix(prefix, header));
        Assert.Throws<CryptographicException>(() => Dph2InitialClaimTranscriptCodec.DecodePrefix(body[..^2], header));
        Assert.Throws<CryptographicException>(() => Dph2InitialClaimTranscriptCodec.DecodePrefix(
            new byte[Dph2InitialClaimTranscriptCodec.MaximumUnpaddedPayloadBytes + 1], header));
        foreach (var length in new uint[] { 0, uint.MaxValue, 32765 })
        {
            var oversized = body.ToArray();
            BinaryPrimitives.WriteUInt32BigEndian(oversized, length);
            Assert.Throws<CryptographicException>(() => Dph2InitialClaimTranscriptCodec.DecodePrefix(oversized, header));
        }
        var v1Request = request.CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(v1Request.AsSpan(4), 1);
        Assert.Throws<ApplicationCoreFormatException>(() => Dph2InitialClaimTranscriptCodec.Encode(
            v1Request, result.WireBytes.Span, header));
        var v1Result = result.WireBytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(v1Result.AsSpan(4), 1);
        Assert.Throws<ApplicationCoreFormatException>(() => Dph2InitialClaimTranscriptCodec.Encode(
            request.CanonicalBytes.Span, v1Result, header));
        var malformedPadding = result.WireBytes.ToArray(); malformedPadding[^1] ^= 1;
        Assert.Throws<ApplicationCoreFormatException>(() => Dph2InitialClaimTranscriptCodec.Encode(
            request.CanonicalBytes.Span, malformedPadding, header));
        var failure = DeepIdV2PreKeyClaimResultCodec.Encode(request.CanonicalBytes.Span,
            Xpc1V2Status.PreKeysUnavailable, Xpc1V2MutationOutcome.None, 15, 0, []);
        Assert.Throws<CryptographicException>(() => Dph2InitialClaimTranscriptCodec.Encode(
            request.CanonicalBytes.Span, failure, header));
        var wrongReceiptHeader = CopyWithCiphertext(header, new byte[16400], changedReceipt: Bytes(32, 0x7f));
        Assert.Throws<CryptographicException>(() => Dph2InitialClaimTranscriptCodec.Encode(
            request.CanonicalBytes.Span, result.WireBytes.Span, wrongReceiptHeader));

        var current = contact.Freshness.CurrentCheckpoint!;
        var session = ApplicationCoreCodec.AuthorDmc2(header.NetworkId.Span,
            Bytes(32, 0x81), Bytes(32, 0x82), header.InitiatorAccountId.Span,
            header.InitiatorDeviceId.Span, 1, 15000, 20000, Dmc2Flags.None, [],
            ApplicationCoreCodec.CreateSessionInitPayload(Bytes(32, 0x83),
                current.Directory.Record, SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl));
        var key = Bytes(32, 0x84);
        byte[]? aad = null;
        try
        {
            using var previewKey = SecretBuffer.ImportExact(key, 32, nameof(key));
            foreach (var bucket in new[] { 16384, 32768 })
            {
                var padded = Bytes(bucket, 0x85);
                prefix.CopyTo(padded, 0); padded[prefix.Length] = 1;
                BinaryPrimitives.WriteUInt32BigEndian(padded.AsSpan(prefix.Length + 1),
                    checked((uint)session.CanonicalBytes.Length));
                session.CanonicalBytes.Span.CopyTo(padded.AsSpan(prefix.Length + 5));
                BinaryPrimitives.WriteUInt32BigEndian(padded.AsSpan(bucket - 4),
                    checked((uint)(prefix.Length + 5 + session.CanonicalBytes.Length)));
                var provisional = CopyWithCiphertext(header, new byte[bucket + 16]);
                aad = MessagingWireCryptographicInputs.GetDph2InitialAeadAssociatedData(
                    receipt.Offering.ExactBytes.Span, provisional);
                var ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(padded,
                    header.InitialPayloadNonce.ToArray(), key, aad);
                try
                {
                    var sealedRecord = CopyWithCiphertext(header, ciphertext);
                    Dph2PreClaimHeader Prevalidate(Dph2Record record) =>
                        Dph2VerificationPlan.Create(record, receipt.Offering).Prevalidate(
                            new Dph2ResolvedInitiator(record.InitiatorDeviceAgreementPublicKey.Span,
                                current.Directory.Record.RecordHash.Span));
                    Dph2InitialClaimPreview Preview()
                    {
                        var prevalidated = Prevalidate(sealedRecord);
                        var pair = Dph2InitialPayloadReader.PreviewClaimTranscript(prevalidated, previewKey);
                        Assert.Equal(request.CanonicalBytes.ToArray(), pair.Request.CanonicalBytes.ToArray());
                        Assert.Equal(result.WireBytes.ToArray(), pair.Result.WireBytes.ToArray());
                        return new Dph2InitialClaimPreview(prevalidated, pair.Request, pair.Result);
                    }
                    var preview = Preview();
                    var verified = await preview.VerifyCurrentAsync(placement, contact, closure,
                        contact.Freshness, new(new Clock(boot)));
                    Assert.Same(current, verified.InitiatorCheckpoint);
                    Assert.Same(closure, verified.RecipientClosure);
                    Assert.Equal(sealedRecord.SessionId.ToArray(), verified.Initiation.SessionId.ToArray());
                    Assert.Equal(receipt.ExactReplayHash.ToArray(), verified.Claim.ExactReplayHash.ToArray());
                    await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                        await preview.VerifyCurrentAsync(placement, contact, closure, contact.Freshness,
                            new(new Clock(boot))));
                    using var lanes = verified.BindForInitialSession();
                    using var device = lanes.ConsumeForDevicePreKeyOwner();
                    using var protocol = lanes.ConsumeForProtocolHandshake();
                    Assert.Equal(sealedRecord.SessionId.ToArray(), device.SessionId.ToArray());
                    Assert.Equal(device.OperationId.ToArray(), protocol.OperationId);
                    Assert.Equal(receipt.ExactReplayHash.ToArray(), device.Xpc1FullReplayHash.ToArray());
                    Assert.Throws<InvalidOperationException>(() => verified.BindForInitialSession());
                    Assert.Throws<InvalidOperationException>(() => lanes.ConsumeForDevicePreKeyOwner());
                    Assert.Throws<InvalidOperationException>(() => lanes.ConsumeForProtocolHandshake());
                    // Final recheck must not leave the recipient interval at its
                    // earlier receipt sample while the initiator is still fresh.
                    await Assert.ThrowsAsync<AccountDirectoryFreshnessVerificationException>(async () =>
                        await Preview().VerifyCurrentAsync(placement, contact, closure, contact.Freshness,
                            new(new Clock(boot, [3, 3, 3, 7]))));
                    using var canceled = new CancellationTokenSource(); canceled.Cancel();
                    var noRead = new Clock(boot);
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                        await Preview().VerifyCurrentAsync(placement, contact, closure, contact.Freshness,
                            new(noRead), canceled.Token));
                    Assert.Equal(0, noRead.Reads);
                    using var lateCancellation = new CancellationTokenSource();
                    var lateClock = new Clock(boot, cancel: lateCancellation, cancelAtRead: 4);
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                        await Preview().VerifyCurrentAsync(placement, contact, closure, contact.Freshness,
                            new(lateClock), lateCancellation.Token));
                    Assert.Equal(4, lateClock.Reads);
                    await Assert.ThrowsAsync<CryptographicException>(async () =>
                        await Preview().VerifyCurrentAsync(placement, contact, closure, contact.Freshness,
                            new(new Clock(Bytes(16, 0x7e)))));
                    var changed = ciphertext.ToArray(); changed[^1] ^= 1;
                    Assert.ThrowsAny<CryptographicException>(() => Dph2InitialPayloadReader.PreviewClaimTranscript(
                        Prevalidate(CopyWithCiphertext(header, changed)), previewKey));
                    CryptographicOperations.ZeroMemory(changed);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(ciphertext);
                    CryptographicOperations.ZeroMemory(padded);
                    CryptographicOperations.ZeroMemory(aad); aad = null;
                }
            }
            var eventOnly = new byte[4096]; eventOnly[0] = 1;
            BinaryPrimitives.WriteUInt32BigEndian(eventOnly.AsSpan(4092), 1);
            var oldRecord = CopyWithCiphertext(header, new byte[4112]);
            aad = MessagingWireCryptographicInputs.GetDph2InitialAeadAssociatedData(receipt.Offering.ExactBytes.Span, oldRecord);
            var oldCiphertext = SecretAeadXChaCha20Poly1305.Encrypt(eventOnly,
                header.InitialPayloadNonce.ToArray(), key, aad);
            try
            {
                var oldHeader = Dph2VerificationPlan.Create(CopyWithCiphertext(header, oldCiphertext), receipt.Offering)
                    .Prevalidate(new Dph2ResolvedInitiator(header.InitiatorDeviceAgreementPublicKey.Span,
                        current.Directory.Record.RecordHash.Span));
                Assert.Throws<CryptographicException>(() => Dph2InitialPayloadReader.PreviewClaimTranscript(oldHeader, previewKey));
            }
            finally { CryptographicOperations.ZeroMemory(oldCiphertext); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(prefix);
            CryptographicOperations.ZeroMemory(body); if (aad is not null) CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static Dph2Record CopyWithCiphertext(Dph2Record record, byte[] ciphertext,
        byte[]? changedReceipt = null) => new(record.NetworkId.Span,
        record.InitiatorAccountId.Span, record.InitiatorDeviceId.Span, record.InitiatorDeviceGeneration,
        record.InitiatorDpd1Ref.Span, record.InitiatorDid2.Span, record.ResponderAccountId.Span,
        record.ResponderDeviceId.Span, record.ResponderDeviceGeneration, record.ExactDpk2Hash.Span,
        record.ClaimOperationId.Span, changedReceipt ?? record.ClaimReceiptHash.ToArray(),
        record.LastResortUseCounter, record.InitiatorDeviceAgreementPublicKey.Span,
        record.InitiatorEphemeralX25519PublicKey.Span, record.SelectedPrekey,
        record.ActualMlKem768Ciphertext.Span, record.InitiatorInitialRatchetX25519PublicKey.Span,
        record.InitialPayloadNonce.Span, Dph2InitialCiphertext.Import(ciphertext));
}
