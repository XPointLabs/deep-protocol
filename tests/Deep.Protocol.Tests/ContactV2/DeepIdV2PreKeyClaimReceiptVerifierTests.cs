using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.Tests.XPointNetworkV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.ContactV2;

public sealed partial class DeepIdV2PreKeyClaimReceiptVerifierTests
{
    [Fact]
    public void SurfaceIsClosedAndCannotGrantSessionOrAck()
    {
        Assert.Empty(typeof(VerifiedXpc1V2PreKeyClaimReceipt).GetConstructors());
        Assert.False(DeepIdV2PreKeyClaimReceiptVerifier.RuntimeActivation);
        var method = Assert.Single(typeof(DeepIdV2PreKeyClaimReceiptVerifier)
            .GetMethods(), candidate => candidate.Name == "VerifyAsync");
        Assert.Equal(new[] { typeof(ParsedXpk1V2), typeof(ParsedXpc1V2),
            typeof(VerifiedContactServicePlacement), typeof(DeepIdV2CurrentContactAuthorization),
            typeof(ParsedDcr1V2), typeof(OnionTrustedTimeAuthority), typeof(CancellationToken) },
            method.GetParameters().Select(parameter => parameter.ParameterType));
        var recipient = Assert.Single(typeof(DeepIdV2PreKeyClaimReceiptVerifier).GetMethods(),
            candidate => candidate.Name == "VerifyCommittedForRecipientAsync");
        Assert.Equal(method.GetParameters().Select(parameter => parameter.ParameterType),
            recipient.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.DoesNotContain(typeof(VerifiedXpc1V2PreKeyClaimReceipt).GetMethods(),
            candidate => candidate.Name is "BindForInitialSession" or "ConsumeForHandshake");
    }

    // Reuses the current V2 identity/closure fixture, not a V1 claim receipt.
    // The network capability below is a bounded test seam; its producer and
    // real nonce proofs have independent gates. This is not physical evidence.
    internal static async Task AssertCurrentRecipientClaimsAsync(ParsedDcr1V2 closure,
        DeepIdV2CurrentContactAuthorization contact, ParsedXpi1V2 manifest,
        IReadOnlyList<ParsedDpk2V2> oneTime, ParsedDpk2V2 lastResort,
        ParsedXpi1V2 higherReuseManifest, ParsedDpk2V2 higherReuseMember, byte[] boot)
    {
        var keys = new[] { PublicKeyAuth.GenerateKeyPair(), PublicKeyAuth.GenerateKeyPair() };
        var placement = Placement(contact, boot, manifest.Field(2).ToArray(), keys);
        var keyByNode = Enumerable.Range(0, 2).ToDictionary(
            index => Convert.ToHexString(Bytes(32, checked((byte)(0x31 + index)))),
            index => keys[index]);
        Dph2Record Header(ParsedDpk2V2 selected, byte[] receiptHash,
            int ciphertextLength = 4112, HeaderChanges? changes = null)
        {
            var checkpoint = contact.Freshness.CurrentCheckpoint!;
            var directory = checkpoint.Directory.Record;
            var device = checkpoint.Binding.Identity.ActiveDevices.Single().Certificate;
            var member = selected.Record;
            return new Dph2Record(
                changes?.Network ?? contact.Freshness.NetworkId.ToArray(),
                changes?.InitiatorAccount ?? directory.DeepAccountId.ToArray(),
                changes?.InitiatorDevice ?? device.DeviceId.ToArray(),
                changes?.InitiatorGeneration ?? device.DeviceGeneration,
                changes?.DpdRef ?? directory.ActiveDevices[0].Dpd1Reference.CanonicalBytes.ToArray(),
                changes?.Did ?? checkpoint.Binding.DeepId.CanonicalBytes.ToArray(),
                changes?.RecipientAccount ?? member.ResponderAccountId.ToArray(),
                changes?.RecipientDevice ?? member.ResponderDeviceId.ToArray(),
                changes?.RecipientGeneration ?? member.ResponderDeviceGeneration,
                changes?.DpkHash ?? selected.ExactHash.ToArray(),
                changes?.Operation ?? Bytes(32, 0x61), receiptHash,
                changes?.Counter ?? (selected.Kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : (ushort)1),
                changes?.Agreement ?? device.DeviceX25519PublicKey.ToArray(),
                changes?.Ephemeral ?? Bytes(32, 0x65),
                changes?.Selection ?? (selected.Kind == Dpk2PrekeyKind.OneTime
                    ? Dph2SelectedPrekey.OneTime(member.SignedX25519PrekeyId.Span,
                        member.OneTimeX25519PrekeyId.Span, member.MlKemPrekeyId.Span)
                    : Dph2SelectedPrekey.LastResort(member.SignedX25519PrekeyId.Span,
                        member.MlKemPrekeyId.Span)),
                Bytes(1088, 0x66), changes?.Ratchet ?? Bytes(32, 0x67), Bytes(24, 0x68),
                Dph2InitialCiphertext.Import(Bytes(ciphertextLength, 0x69)));
        }
        var senderCommitment = MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(
            Header(oneTime[0], Bytes(32, 0x64)));
        ParsedXpk1V2 Request(byte[]? bundleHash = null, ulong expiry = 20,
            byte[]? operation = null, byte[]? commitment = null) =>
            DeepIdV2PreKeyClaimRequestCodec.Decode(DeepIdV2PreKeyClaimRequestCodec.Encode(
                contact.Freshness.NetworkId.Span, operation ?? Bytes(32, 0x61), placement.ViewHash.Span,
                placement.PlacementHash.Span, 10, expiry, manifest.Field(2).Span,
                bundleHash ?? closure.Bundle.ObjectHash.ToArray(), manifest.Field(6).Span[6..],
                manifest.Field(3).Span, commitment ?? senderCommitment));
        ParsedXpc1V2 Result(ParsedXpk1V2 request, ParsedDpk2V2 selected,
            ParsedXpi1V2 inventory, ushort counter = 0,
            Xpc1V2Status status = Xpc1V2Status.Claimed, ulong serverTime = 15,
            bool damageSignature = false)
        {
            var input = DeepIdV2PreKeyClaimCommitment.CreateReplicaSignatureInput(
                request.CanonicalBytes.Span, selected.CanonicalBytes.Span,
                inventory.CanonicalBytes.Span, 1, counter);
            var rows = new byte[193]; rows[0] = 2;
            var replicas = placement.RankedReplicaNodeIds.OrderBy(id => Convert.ToHexString(id.Span),
                StringComparer.Ordinal).ToArray();
            for (var index = 0; index < 2; index++)
            {
                replicas[index].Span.CopyTo(rows.AsSpan(1 + index * 96, 32));
                PublicKeyAuth.SignDetached(input, keyByNode[Convert.ToHexString(replicas[index].Span)]
                    .PrivateKey).CopyTo(rows, 33 + index * 96);
            }
            if (damageSignature) rows[33] ^= 1;
            ReadOnlyMemory<byte>[] payload =
            [
                selected.CanonicalBytes,
                selected.Kind == Dpk2PrekeyKind.OneTime ? selected.OneTimePrekeyId : new byte[32],
                DeepIdV2PreKeyClaimCommitment.ComputeReceiptHash(request.CanonicalBytes.Span,
                    selected.CanonicalBytes.Span, inventory.CanonicalBytes.Span, 1, counter),
                selected.DeviceDirectoryHeadHash, inventory.Field(13), U64(selected.PrekeyServiceGeneration),
                U64(selected.ExpiresAt), U16(counter), U64(1), rows, inventory.CanonicalBytes,
                U16(selected.Kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : ushort.MaxValue),
                selected.Kind == Dpk2PrekeyKind.OneTime ? IndexZeroProof(oneTime) : ReadOnlyMemory<byte>.Empty
            ];
            return DeepIdV2PreKeyClaimResultCodec.Decode(DeepIdV2PreKeyClaimResultCodec.Encode(
                request.CanonicalBytes.Span, status, Xpc1V2MutationOutcome.DurablyCommitted,
                serverTime, 0, payload), request.CanonicalBytes.Span);
        }
        ValueTask<VerifiedXpc1V2PreKeyClaimReceipt> Verify(ParsedXpk1V2 request,
            ParsedXpc1V2 result, Clock? clock = null, CancellationToken cancellation = default,
            VerifiedContactServicePlacement? operationPlacement = null) =>
            DeepIdV2PreKeyClaimReceiptVerifier.VerifyAsync(request, result, operationPlacement ?? placement,
                contact, closure, new OnionTrustedTimeAuthority(clock ?? new Clock(boot)), cancellation);
        var request = Request();
        await MessagingCrypto.ManagedInitiatorInitialSessionFactoryTests.AssertV2RecoveryAsync(
            contact, closure, placement, oneTime[0], lastResort, boot,
            async (offering, operation, commitment) =>
            {
                var selected = offering.Record.MlKemKind == Dpk2PrekeyKind.OneTime
                    ? oneTime[0] : lastResort;
                var currentRequest = Request(operation: operation, commitment: commitment);
                return await Verify(currentRequest, Result(currentRequest, selected, manifest,
                    selected.Kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : (ushort)1));
            });
        var oneTimeResult = Result(request, oneTime[0], manifest);
        var receipt = await Verify(request, oneTimeResult);
        // Independent domain/length framing oracle; do not derive this expected
        // commitment through the implementation's helper.
        using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            hash.AppendData(System.Text.Encoding.ASCII.GetBytes(
                "Deep/ContactResolver/V2/exact-prekey-claim-replay"));
            hash.AppendData([0]);
            hash.AppendData(U32(checked((uint)(8 + request.CanonicalBytes.Length + oneTimeResult.WireBytes.Length))));
            hash.AppendData(U32(checked((uint)request.CanonicalBytes.Length)));
            hash.AppendData(request.CanonicalBytes.Span);
            hash.AppendData(U32(checked((uint)oneTimeResult.WireBytes.Length)));
            hash.AppendData(oneTimeResult.WireBytes.Span);
            Assert.Equal(hash.GetHashAndReset(), receipt.ExactReplayHash.ToArray());
        }
        Assert.Equal(oneTime[0].ExactHash.ToArray(), receipt.Offering.ExactHash.ToArray());
        Assert.Equal(request.RequestHash.ToArray(), receipt.RequestHash.ToArray());
        Assert.Equal(oneTimeResult.Field(18).ToArray(), receipt.ClaimReceiptHash.ToArray());
        Assert.Equal(placement.PlacementHash.ToArray(), receipt.PlacementHash.ToArray());
        Assert.Equal(2, receipt.ReplicaNodeIds.Count);
        var exact = await Verify(request, oneTimeResult);
        VerifiedXpc1V2PreKeyClaimReceipt.RequireExactReplay(receipt, exact);
        var header = Header(oneTime[0], receipt.ClaimReceiptHash.ToArray());
        var transcript = receipt.CopyEncryptedInitialClaimTranscript(header);
        Assert.Equal(request.CanonicalBytes.ToArray(), transcript.Xpk1);
        Assert.Equal(oneTimeResult.WireBytes.ToArray(), transcript.Xpc1Wire);
        transcript.Xpk1[0] ^= 1; transcript.Xpc1Wire[0] ^= 1;
        Assert.Equal(request.CanonicalBytes.ToArray(), receipt.CopyEncryptedInitialClaimTranscript(header).Xpk1);
        // Correlation alone grants no initiator proof, AEAD, handshake or ACK.
        // The selected offering must retain its exact V2 hash, not a V1
        // re-encoding of the identity-neutral projected record.
        foreach (var selected in new[] { oneTime[0], lastResort })
        {
            var candidateResult = Result(request, selected, manifest,
                selected.Kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : (ushort)1);
            var candidate = await Verify(request, candidateResult);
            foreach (var bucket in new[] { 4112, 16400, 32784 })
            {
                var bound = Header(selected, candidate.ClaimReceiptHash.ToArray(), bucket);
                candidate.RequireMatchesDph2Header(Dph2Codec.Decode(Dph2Codec.Encode(bound)));
                var pair = candidate.CopyEncryptedInitialClaimTranscript(bound);
                Assert.Equal(request.CanonicalBytes.ToArray(), pair.Xpk1);
                Assert.Equal(candidate.ClaimReceiptHash.ToArray(), bound.ClaimReceiptHash.ToArray());
                Assert.Equal(selected.ExactHash.ToArray(), bound.ExactDpk2Hash.ToArray());
            }
            await AssertV2EncryptedPrefixAsync(request, candidateResult,
                Header(selected, candidate.ClaimReceiptHash.ToArray(), 16400),
                candidate, placement, contact, closure, boot);
        }
        foreach (var change in new[]
        {
            new HeaderChanges(Operation: Bytes(32, 0x70)),
            new HeaderChanges(InitiatorAccount: Bytes(32, 0x70)),
            new HeaderChanges(InitiatorDevice: Bytes(32, 0x70)),
            new HeaderChanges(DpdRef: Ref("DPD1", Bytes(32, 0x70))),
            new HeaderChanges(Did: DeepIdV2Codec.AuthorDid2(Bytes(32, 0x70),
                Bytes(1952, 0x71), Bytes(16, 0x72)).CanonicalBytes.ToArray()),
            new HeaderChanges(Agreement: Bytes(32, 0x70)),
            new HeaderChanges(Ephemeral: Bytes(32, 0x70)),
            new HeaderChanges(Ratchet: Bytes(32, 0x70))
        })
            Assert.Throws<CryptographicException>(() => receipt.CopyEncryptedInitialClaimTranscript(
                Header(oneTime[0], receipt.ClaimReceiptHash.ToArray(), changes: change)));
        Assert.Throws<CryptographicException>(() => receipt.RequireMatchesDph2Header(
            Header(oneTime[0], Bytes(32, 0x70))));
        foreach (var change in new[]
        {
            new HeaderChanges(Network: Bytes(16, 0x70)),
            new HeaderChanges(RecipientAccount: Bytes(32, 0x70)),
            new HeaderChanges(RecipientDevice: Bytes(32, 0x70)),
            new HeaderChanges(RecipientGeneration: header.ResponderDeviceGeneration + 1),
            new HeaderChanges(DpkHash: Bytes(32, 0x70)),
            new HeaderChanges(DpkHash: MessagingWireCryptographicInputs.ComputeExactDpk2Hash(oneTime[0].Record)),
            new HeaderChanges(Selection: Dph2SelectedPrekey.OneTime(Bytes(32, 0x70),
                header.SelectedPrekey.OneTimeX25519PrekeyIdOrZero.Span,
                header.SelectedPrekey.MlKemPrekeyId.Span)),
            new HeaderChanges(Selection: Dph2SelectedPrekey.OneTime(
                header.SelectedPrekey.SignedX25519PrekeyId.Span, Bytes(32, 0x70),
                header.SelectedPrekey.MlKemPrekeyId.Span)),
            new HeaderChanges(Selection: Dph2SelectedPrekey.OneTime(
                header.SelectedPrekey.SignedX25519PrekeyId.Span,
                header.SelectedPrekey.OneTimeX25519PrekeyIdOrZero.Span, Bytes(32, 0x70)))
        })
            Assert.Throws<MessagingWireFormatException>(() => receipt.CopyEncryptedInitialClaimTranscript(
                Header(oneTime[0], receipt.ClaimReceiptHash.ToArray(), changes: change)));
        var lastResortReceipt = await Verify(request, Result(request, lastResort, manifest, 1));
        // Counter 2 is structurally valid, but cannot replace the signed claim's counter 1.
        // The fixture's signed last-resort reuse limit is 1, so selection also rejects it.
        Assert.Throws<MessagingWireFormatException>(() => lastResortReceipt.RequireMatchesDph2Header(
            Header(lastResort, lastResortReceipt.ClaimReceiptHash.ToArray(), changes: new(Counter: 2))));
        Assert.Throws<ArgumentNullException>(() => receipt.CopyEncryptedInitialClaimTranscript(null!));
        var currentCheckpoint = contact.Freshness.CurrentCheckpoint!;
        var currentHead = currentCheckpoint.Directory.Record.RecordHash.ToArray();
        VerifiedAdc1V2 Initiator(Dph2Record candidate,
            VerifiedDeepIdV2DirectoryFreshness? freshness = null, ulong sample = 3,
            byte[]? operationBoot = null, byte[]? head = null) =>
            Dph2InitialClaimPreview.RequireCurrentInitiator(candidate, head ?? currentHead,
                freshness ?? contact.Freshness, operationBoot ?? boot, sample);
        Assert.Same(currentCheckpoint, Initiator(header));
        var changedGeneration = Header(oneTime[0], receipt.ClaimReceiptHash.ToArray(),
            changes: new(InitiatorGeneration: header.InitiatorDeviceGeneration + 1));
        // Sender commitment intentionally excludes device generation. The
        // independent current-device check must reject this otherwise matching claim.
        receipt.RequireMatchesDph2Header(changedGeneration);
        Assert.Throws<CryptographicException>(() => Initiator(changedGeneration));
        foreach (var change in new[]
        {
            new HeaderChanges(InitiatorDevice: Bytes(32, 0x70)),
            new HeaderChanges(InitiatorGeneration: header.InitiatorDeviceGeneration + 1),
            new HeaderChanges(DpdRef: Ref("DPD1", Bytes(32, 0x70))),
            new HeaderChanges(Agreement: Bytes(32, 0x70))
        })
            Assert.Throws<CryptographicException>(() => Initiator(Header(oneTime[0],
                receipt.ClaimReceiptHash.ToArray(), changes: change)));
        Assert.Throws<CryptographicException>(() => Initiator(header, head: Bytes(32, 0x70)));
        Assert.Throws<CryptographicException>(() => Initiator(header, operationBoot: Bytes(16, 0x70)));
        Assert.Throws<CryptographicException>(() => Initiator(header, sample: 2));
        Assert.Throws<CryptographicException>(() => Initiator(header,
            sample: contact.Freshness.FreshnessDeadlineMonotonicSeconds));
        // Narrow time-bound output seam, retaining the actual V2 checkpoint.
        // These checks do not claim that a native/physical directory issued
        // the altered interval; the public proof verifier has separate gates.
        VerifiedDeepIdV2DirectoryFreshness TimeBounds(ulong lower, ulong upper) => new(
            contact.Freshness.ExactAdh1.Span, contact.Freshness.ExactDtt1.Span,
            contact.Freshness.ExactAdp1V2.Span, contact.Freshness.NetworkId.Span,
            contact.Freshness.QueriedDirectoryLeafKey.Span,
            new AccountDirectoryMonotonicRequestWindow(boot, 3, 3, 3),
            contact.Freshness.FreshnessDeadlineMonotonicSeconds, lower, upper,
            AccountDirectoryAdp1ResultKind.CurrentValue, currentCheckpoint,
            contact.Freshness.HasRootAuthorizedForwardLineage, null);
        var certificate = currentCheckpoint.Binding.Identity.ActiveDevices.Single().Certificate;
        Assert.Throws<CryptographicException>(() => Initiator(header,
            TimeBounds(certificate.IssuedAtUnixSeconds - 1, contact.TrustedUpperUnixSeconds)));
        Assert.Throws<CryptographicException>(() => Initiator(header,
            TimeBounds(contact.TrustedLowerUnixSeconds, certificate.ExpiresAtUnixSeconds)));
        Assert.Throws<CryptographicException>(() => Initiator(header,
            TimeBounds(contact.TrustedLowerUnixSeconds, certificate.ExpiresAtUnixSeconds - 1), sample: 4));
        Assert.Throws<CryptographicException>(() => Initiator(header,
            TimeBounds(contact.TrustedLowerUnixSeconds, ulong.MaxValue), sample: 4));
        var replayHash = receipt.ExactReplayHash.ToArray(); replayHash[0] ^= 1;
        Assert.NotEqual(replayHash, receipt.ExactReplayHash.ToArray());
        Assert.Equal((ushort)1, (await Verify(request, Result(request, lastResort, manifest, 1)))
            .LastResortUseCounter);
        var alteredProjection = await Verify(request, Result(request, oneTime[0], manifest, serverTime: 16));
        Assert.Equal(receipt.ClaimReceiptHash.ToArray(), alteredProjection.ClaimReceiptHash.ToArray());
        Assert.Throws<CryptographicException>(() =>
            VerifiedXpc1V2PreKeyClaimReceipt.RequireExactReplay(receipt, alteredProjection));
        var projectedReplay = await Verify(request,
            Result(request, oneTime[0], manifest, status: Xpc1V2Status.Replay));
        Assert.Throws<CryptographicException>(() =>
            VerifiedXpc1V2PreKeyClaimReceipt.RequireExactReplay(receipt, projectedReplay));
        var wrongBundle = Request(Bytes(32, 0x63));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await Verify(wrongBundle, Result(wrongBundle, oneTime[0], manifest)));
        await Assert.ThrowsAsync<ApplicationCoreFormatException>(async () =>
            await Verify(request, Result(request, oneTime[0], manifest, damageSignature: true)));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await Verify(request, Result(request, higherReuseMember, higherReuseManifest, 2)));
        var shortRequest = Request(expiry: 17);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await Verify(request, oneTimeResult, new Clock(boot, [4, 3])));
        var observedLater = await Verify(request, oneTimeResult, new Clock(boot, [4, 4]));
        Assert.Throws<CryptographicException>(() => observedLater.RequireCurrentAt(new(boot, 3)));
        Assert.Throws<CryptographicException>(() => observedLater.RequireCurrentAt(new(Bytes(16, 0x74), 4)));
        observedLater.RequireCurrentAt(new(boot, 4));
        var mixedHead = Placement(contact, boot, manifest.Field(2).ToArray(), keys, mismatchedDirectory: true);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await Verify(request, oneTimeResult, operationPlacement: mixedHead));
        await Assert.ThrowsAsync<CryptographicException>(async () => await Verify(shortRequest,
            Result(shortRequest, oneTime[0], manifest), new Clock(boot, [3, 4])));
        ValueTask<VerifiedXpc1V2PreKeyClaimReceipt> VerifyRecipient(ParsedXpk1V2 pending,
            ParsedXpc1V2 committed, Clock? clock = null, VerifiedContactServicePlacement? currentPlacement = null) =>
            DeepIdV2PreKeyClaimReceiptVerifier.VerifyCommittedForRecipientAsync(pending, committed,
                currentPlacement ?? placement, contact, closure, new(clock ?? new Clock(boot, [3, 4])));
        var committedShort = Result(shortRequest, oneTime[0], manifest);
        var delayedRecipient = await VerifyRecipient(shortRequest, committedShort);
        Assert.Equal(committedShort.Field(18).ToArray(), delayedRecipient.ClaimReceiptHash.ToArray());
        delayedRecipient.RequireCurrentAt(new(boot, 4));
        Assert.Throws<CryptographicException>(() => delayedRecipient.ConsumeForInitiator(
            Header(oneTime[0], delayedRecipient.ClaimReceiptHash.ToArray())));
        Assert.Throws<CryptographicException>(() => delayedRecipient.RequireCurrentAt(new(boot, 3)));
        await Assert.ThrowsAsync<CryptographicException>(async () => await VerifyRecipient(shortRequest,
            committedShort, currentPlacement: Placement(contact, boot, manifest.Field(2).ToArray(), keys, 9, 16)));
        await Assert.ThrowsAsync<CryptographicException>(async () => await VerifyRecipient(shortRequest,
            committedShort, currentPlacement: Placement(contact, boot, manifest.Field(2).ToArray(), keys, 15, 20)));
        await Assert.ThrowsAsync<ApplicationCoreFormatException>(async () => await VerifyRecipient(shortRequest,
            Result(shortRequest, oneTime[0], manifest, damageSignature: true)));
        await Assert.ThrowsAsync<CryptographicException>(async () => await VerifyRecipient(shortRequest,
            committedShort, new Clock(boot, [4, 3])));
        await Assert.ThrowsAsync<Deep.Protocol.AccountDirectoryV1.AccountDirectoryFreshnessVerificationException>(
            async () => await Verify(request, oneTimeResult, new Clock(boot, [3, 7])));
        await Assert.ThrowsAsync<Deep.Protocol.AccountDirectoryV1.AccountDirectoryFreshnessVerificationException>(
            async () => await Verify(request, oneTimeResult, new Clock(Bytes(16, 0x74))));
        // The two authenticated intervals are conservatively unioned, never
        // intersected to hide an early or expired network bound.
        foreach (var bounds in new[] { (Lower: 9UL, Upper: 16UL), (Lower: 15UL, Upper: 20UL),
                     (Lower: 15UL, Upper: ulong.MaxValue) })
        {
            var wider = Placement(contact, boot, manifest.Field(2).ToArray(), keys,
                bounds.Lower, bounds.Upper);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await Verify(request, oneTimeResult, new Clock(boot, [3, 4]),
                    operationPlacement: wider));
        }
        var expiredNetwork = Placement(contact, boot, manifest.Field(2).ToArray(), keys,
            deadline: 3);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await Verify(request, oneTimeResult, operationPlacement: expiredNetwork));
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        var neverRead = new Clock(boot);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await Verify(request, oneTimeResult, neverRead, cancellation.Token));
        Assert.Equal(0, neverRead.Reads);
        using var lateCancellation = new CancellationTokenSource();
        var lateClock = new Clock(boot, cancel: lateCancellation);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await Verify(request, oneTimeResult, lateClock, lateCancellation.Token));
        Assert.Equal(2, lateClock.Reads);
    }

    private static VerifiedContactServicePlacement Placement(
        DeepIdV2CurrentContactAuthorization contact, byte[] boot, byte[] capability, KeyPair[] keys,
        ulong lower = 15, ulong upper = 16, ulong deadline = 60, bool mismatchedDirectory = false)
    {
        var network = contact.Freshness.NetworkId.ToArray();
        var directoryHead = AccountDirectoryAdh1Codec.Decode(contact.Freshness.ExactAdh1.Span);
        var authorityReference = directoryHead.ExactXnaAuthorityCoreReference.ToArray();
        var view = SyntheticView(network, authorityReference);
        var policy = XPointNetworkCodec.Parse<Xvp1Record>(XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xvp1));
        var headWire = XPointNetworkTestRecords.MutateField(XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xnh1),
            8, field => authorityReference.CopyTo(field));
        var head = XPointNetworkCodec.Parse<Xnh1Record>(headWire);
        var viewRef = XPointNetworkCodec.EncodeCoreReference("XNV1", view.CoreHash.Span);
        var nodeIds = new[] { Bytes(32, 0x31), Bytes(32, 0x32) };
        var rows = new byte[272];
        for (var index = 0; index < 2; index++)
        {
            rows.AsSpan(index * 136, 136).Fill(checked((byte)(0x31 + index)));
            nodeIds[index].CopyTo(rows, index * 136);
        }
        var witnessRows = Bytes(192, 0x35);
        witnessRows.AsSpan(96, 96).Fill(0x36);
        ReadOnlyMemory<byte>[] pmtFields =
        [network, U64(0), new byte[32], Ref("PMA2", Bytes(32, 0x33)), viewRef,
            U64(1), new byte[] { 2 }, U16(2), rows, U64(10), U64(10), U64(20),
            Bytes(32, 0x34), Ref("ADH1", contact.Freshness.NextProtectedLkg.CoreHash.Span),
            new byte[] { 2 }, witnessRows];
        var wire = new byte[12 + pmtFields.Length * 8 + pmtFields.Sum(field => field.Length)];
        var writer = new ApplicationRecordWriter(wire, "PMT2"u8, 16, 1, 0x0201);
        for (var tag = 1; tag <= 16; tag++) writer.Write((ushort)tag, pmtFields[tag - 1].Span);
        writer.Complete();
        var pmt = ContactCodec.Decode(wire);
        var closure = new VerifiedOnionNetworkClosure
        {
            NetworkId = network, Policy = policy, View = view, Head = head, Pmt = pmt, RetainedPmts = [pmt],
            ViewCoreHash = view.CoreHash.ToArray(), ViewCoreReference = viewRef,
            PmtArtifactReference = ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes.ToArray(),
            PmtNodeIds = nodeIds, SelectionEpoch = 1, ReplicaCount = 2, HardUpperUnixSeconds = 20,
            Adh1CoreReference = mismatchedDirectory ? Ref("ADH1", Bytes(32, 0x70)) : pmtFields[13].ToArray(),
            Dtt1CoreHash = Bytes(32, 0x36),
            FreshnessBootId = boot, TrustedLowerUnixSeconds = lower, TrustedUpperUnixSeconds = upper,
            FreshnessMonotonicSample = 3, FreshnessDeadlineMonotonicSeconds = deadline
        };
        var headRef = XPointNetworkCodec.EncodeCoreReference("XNH1", head.CoreHash.Span);
        var nodes = Enumerable.Range(0, 2).Select(index => new VerifiedNetworkNode(
            nodeIds[index], Bytes(32, 0x41), Bytes(32, 0x42), Bytes(32, checked((byte)(0x43 + index))),
            Bytes(32, 0x45), 1, 4, [127, 0, 0, checked((byte)(1 + index))], 443,
            Bytes(32, 0x46), 7, 1, 1, 1, 1, Bytes(32, 0x47), Bytes(32, 0x48), keys[index].PublicKey));
        var context = new VerifiedOnionNetworkContext(network,
            new OnionTrustedTimeLease(TimeProvider.System, TimeSpan.FromMinutes(1), Bytes(32, 0x49)),
            nodes, closure, new XPointNetworkProtectedLkg(network, headRef, head.TreeSize,
                head.Root.ToArray(), viewRef, view.ViewGeneration, Ref("XNA1", Bytes(32, 0x50))), null);
        return ContactServicePlacementFactory.Create(context, ContactServiceRequestKind.ClaimPreKey, capability);
    }

    // Explicit internal verifier-output seam for binding/time unit coverage,
    // NOT a signed directory/network producer or native/physical evidence.
    internal static byte[] SyntheticClaimDtt(byte[] network, byte[] exactHead)
    {
        var head = AccountDirectoryAdh1Codec.Decode(exactHead);
        var view = SyntheticView(network, head.ExactXnaAuthorityCoreReference.ToArray());
        return AccountDirectoryDtt1Codec.Encode(new AccountDirectoryDtt1(network, Bytes(32, 0x51), 15, 1,
            AccountDirectoryCrypto.ComputeAdh1CoreHash(head), head.LogGeneration, view.CoreHash.Span,
            view.ViewGeneration, head.ExactXnaAuthorityCoreReference.Span, head.WitnessPolicyHash.Span,
            15, 20, Bytes(32, 0x52), [new AccountDirectoryDtt1WitnessReceipt(Bytes(32, 0x53), Bytes(64, 0x54))]));
    }

    private static Xnv1Record SyntheticView(byte[] network, byte[] authorityReference)
    {
        var wire = XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xnv1);
        wire = XPointNetworkTestRecords.MutateField(wire, 1, field => network.CopyTo(field));
        wire = XPointNetworkTestRecords.MutateField(wire, 7, field => authorityReference.CopyTo(field));
        foreach (var tag in new[] { 19, 20 })
            wire = XPointNetworkTestRecords.MutateField(wire, tag, field => U64(10).CopyTo(field));
        wire = XPointNetworkTestRecords.MutateField(wire, 21, field => U64(80).CopyTo(field));
        return XPointNetworkCodec.Parse<Xnv1Record>(wire);
    }

    private static byte[] IndexZeroProof(IReadOnlyList<ParsedDpk2V2> members)
    {
        var level = members.Select((member, index) => ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V2/prekey-inventory-leaf", U16((ushort)index)
                .Concat(member.ExactHash.ToArray()).ToArray())).ToArray();
        var proof = new List<byte>();
        while (level.Length > 1)
        {
            proof.AddRange(level[1]);
            level = Enumerable.Range(0, level.Length / 2).Select(index => ApplicationCoreFormat
                .Sha256Domain("Deep/ContactResolver/V2/prekey-inventory-node",
                    level[index * 2].Concat(level[index * 2 + 1]).ToArray())).ToArray();
        }
        return proof.ToArray();
    }

    private sealed class Clock(byte[] boot, ulong[]? samples = null,
        CancellationTokenSource? cancel = null, int cancelAtRead = 2) : IOnionMonotonicClock
    {
        internal int Reads { get; private set; }
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            var index = Reads++;
            if (Reads == cancelAtRead) cancel?.Cancel();
            return ValueTask.FromResult(new OnionMonotonicReading(boot,
                samples?[Math.Min(index, samples.Length - 1)] ?? 3));
        }
    }
    private sealed record HeaderChanges(byte[]? Network = null,
        byte[]? InitiatorAccount = null, byte[]? InitiatorDevice = null,
        ulong? InitiatorGeneration = null,
        byte[]? DpdRef = null, byte[]? Did = null, byte[]? RecipientAccount = null,
        byte[]? RecipientDevice = null, ulong? RecipientGeneration = null,
        byte[]? DpkHash = null, byte[]? Operation = null, ushort? Counter = null,
        byte[]? Agreement = null, byte[]? Ephemeral = null, byte[]? Ratchet = null,
        Dph2SelectedPrekey? Selection = null);
    private static byte[] Bytes(int length, byte value) { var bytes = new byte[length]; bytes.AsSpan().Fill(value); return bytes; }
    private static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static byte[] U32(uint value) { var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes; }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] Ref(string magic, ReadOnlySpan<byte> hash)
    {
        var bytes = new byte[38]; System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1); hash.CopyTo(bytes.AsSpan(6)); return bytes;
    }
}
