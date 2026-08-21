using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class NativePeerVerifierTests
{
    [Fact]
    public void ExactDprPrqFrame_VerifiesAgainstSealedMrl2AndContacts()
    {
        var fixture = Fixture.Create();

        var verified = NativePeerVerifier.VerifyRequest(
            fixture.Frame,
            fixture.Lkg,
            fixture.SenderContact,
            fixture.RecipientContact,
            fixture.PlacementId,
            1050);
        fixture.Frame.AsSpan().Fill(0xff);

        Assert.Equal(MailboxPeerReplicationOperation.Tombstone, verified.Operation);
        Assert.Equal(7UL, verified.Epoch);
        Assert.Equal(fixture.RequestId, verified.RequestId.ToArray());
        Assert.Equal("DPR1", System.Text.Encoding.ASCII.GetString(
            verified.CanonicalDpr1.Span[..4]));
        Assert.Equal("PRQ2", System.Text.Encoding.ASCII.GetString(
            verified.CanonicalPrq2.Span[..4]));
        Assert.True(verified.NoMutationOrDurabilityClaim);
    }

    [Fact]
    public void SignatureReferenceOrNativeCapabilityMix_Rejects()
    {
        var fixture = Fixture.Create();
        var badSignature = fixture.Frame.ToArray();
        badSignature[4 + NativePeerVerifier.DprLength - 1] ^= 1;
        Assert.Equal(RecordError.InvalidSignature,
            Assert.Throws<RecordException>(() => NativePeerVerifier.VerifyRequest(
                badSignature, fixture.Lkg, fixture.SenderContact, fixture.RecipientContact,
                fixture.PlacementId, 1050)).Error);

        var badNested = fixture.Frame.ToArray();
        badNested[^1] ^= 1;
        Assert.Throws<RecordException>(() => NativePeerVerifier.VerifyRequest(
            badNested, fixture.Lkg, fixture.SenderContact, fixture.RecipientContact,
            fixture.PlacementId, 1050));

        var unauthenticatedMalformedNested = fixture.Frame.ToArray();
        unauthenticatedMalformedNested[4 + NativePeerVerifier.DprLength - 1] ^= 1;
        unauthenticatedMalformedNested[^1] ^= 1;
        Assert.Equal(RecordError.InvalidField,
            Assert.Throws<RecordException>(() => NativePeerVerifier.VerifyRequest(
                unauthenticatedMalformedNested, fixture.Lkg, fixture.SenderContact,
                fixture.RecipientContact, fixture.PlacementId, 1050)).Error);
    }

    [Fact]
    public void OuterInnerRequestBindings_RejectBeforeInvalidOuterSignature()
    {
        var fixture = Fixture.Create();
        var prqOffset = NativePeerVerifier.RequestFixedOverhead;

        foreach (var mutation in new Action<byte[]>[]
        {
            frame => frame[prqOffset + 216] ^= 1,
            frame => frame[prqOffset + 32] ^= 1,
            frame => BinaryPrimitives.WriteUInt64BigEndian(
                frame.AsSpan(prqOffset + 208, 8), 1099),
        })
        {
            var frame = fixture.Frame.ToArray();
            mutation(frame);
            RebindPrqReferenceWithoutResigning(frame);
            Assert.Equal(RecordError.InvalidField,
                Assert.Throws<RecordException>(() => NativePeerVerifier.VerifyRequest(
                    frame, fixture.Lkg, fixture.SenderContact, fixture.RecipientContact,
                    fixture.PlacementId, 1050)).Error);
        }

        var referenceMismatch = fixture.Frame.ToArray();
        referenceMismatch[^1] ^= 1;
        Assert.Equal(RecordError.InvalidField,
            Assert.Throws<RecordException>(() => NativePeerVerifier.VerifyRequest(
                referenceMismatch, fixture.Lkg, fixture.SenderContact,
                fixture.RecipientContact, fixture.PlacementId, 1050)).Error);

    }

    [Fact]
    public void OuterInnerOperationDiscriminators_RejectBeforeParsingOrSignature()
    {
        var fixture = Fixture.Create();
        var prqOffset = NativePeerVerifier.RequestFixedOverhead;

        var invalidInnerOperation = fixture.Frame.ToArray();
        invalidInnerOperation[prqOffset + 5] = 3;
        invalidInnerOperation[4 + NativePeerVerifier.DprLength - 1] ^= 1;
        Assert.Equal(RecordError.InvalidField,
            Assert.Throws<RecordException>(() => NativePeerVerifier.VerifyRequest(
                invalidInnerOperation, fixture.Lkg, fixture.SenderContact,
                fixture.RecipientContact, fixture.PlacementId, 1050)).Error);

        var invalidOuterOperation = fixture.Frame.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(invalidOuterOperation.AsSpan(4 + 288, 2), 2);
        Assert.Equal(RecordError.InvalidField,
            Assert.Throws<RecordException>(() => NativePeerVerifier.VerifyRequest(
                invalidOuterOperation, fixture.Lkg, fixture.SenderContact,
                fixture.RecipientContact, fixture.PlacementId, 1050)).Error);

        var maximumMalformed = new byte[
            NativePeerVerifier.RequestFixedOverhead +
            MailboxPeerWireV2Limits.MaximumRequestLength];
        BinaryPrimitives.WriteUInt32BigEndian(maximumMalformed, NativePeerVerifier.DprLength);
        fixture.Frame.AsSpan(4, NativePeerVerifier.DprLength)
            .CopyTo(maximumMalformed.AsSpan(4));
        BinaryPrimitives.WriteUInt32BigEndian(
            maximumMalformed.AsSpan(4 + NativePeerVerifier.DprLength),
            MailboxPeerWireV2Limits.MaximumRequestLength);
        var maximumPrq = maximumMalformed.AsSpan(NativePeerVerifier.RequestFixedOverhead);
        "PRQ2"u8.CopyTo(maximumPrq);
        maximumPrq[4] = 2;
        maximumPrq[5] = 3;
        BinaryPrimitives.WriteUInt32BigEndian(
            maximumPrq.Slice(280, 4), MailboxClientLimits.MaximumEncryptedEnvelopeLength);
        BinaryPrimitives.WriteUInt16BigEndian(
            maximumPrq.Slice(284, 2), MailboxPeerWireV2Limits.MaximumMembershipProofLength);
        BinaryPrimitives.WriteUInt16BigEndian(
            maximumPrq.Slice(286, 2), MailboxPeerWireV2Limits.MaximumMembershipProofLength);
        BinaryPrimitives.WriteUInt16BigEndian(
            maximumPrq.Slice(288, 2), MailboxPeerReplicationLimits.SignatureLength);

        _ = Record.Exception(() => NativePeerVerifier.VerifyRequest(
            maximumMalformed, fixture.Lkg, fixture.SenderContact,
            fixture.RecipientContact, fixture.PlacementId, 1050));
        var before = GC.GetAllocatedBytesForCurrentThread();
        var maximumError = Assert.Throws<RecordException>(() =>
            NativePeerVerifier.VerifyRequest(
                maximumMalformed, fixture.Lkg, fixture.SenderContact,
                fixture.RecipientContact, fixture.PlacementId, 1050));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal(RecordError.InvalidField, maximumError.Error);
        Assert.InRange(allocated, 0, 128 * 1024);
    }

    [Fact]
    public void ExactDpsMrrFrame_VerifiesOnlyAgainstSealedRequest()
    {
        var fixture = Fixture.Create();
        var request = NativePeerVerifier.VerifyRequest(
            fixture.Frame, fixture.Lkg, fixture.SenderContact, fixture.RecipientContact,
            fixture.PlacementId, 1050);
        var unsignedReceipt = new MailboxReplicaReceiptV2
        {
            Status = MailboxReceiptStatus.Durable,
            Disposition = MailboxReplicaDisposition.Tombstone,
            ReplicaId = fixture.RecipientId,
            OperationId = fixture.OperationId,
            Epoch = 7,
            Cursor = 1,
            AcceptedAtUnixSeconds = 1041,
            DurableAtUnixSeconds = 1042,
            ExpiresAtUnixSeconds = 1100,
            BlindedMailboxId = fixture.BlindedMailboxId,
            PlacementCommitment = MailboxPlacementCommitment.Compute(fixture.PlacementId),
            MembershipCommitment = fixture.Lkg.MembershipRoot,
            EnvelopeDigest = fixture.TombstoneDigest,
            Signature = ReadOnlyMemory<byte>.Empty
        };
        var mrr = MailboxReceiptV2Codec.EncodeReplica(
            new SodiumMailboxPeerReplicationCrypto().SignReplicaResponse(
                unsignedReceipt, fixture.RecipientSeed));
        var dps = Dps(request, mrr, fixture.RecipientPrivateKey);
        var frame = new byte[NativePeerVerifier.ResponseLength];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)dps.Length);
        dps.CopyTo(frame, 4);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(4 + dps.Length), (uint)mrr.Length);
        mrr.CopyTo(frame, 8 + dps.Length);

        var verified = NativePeerVerifier.VerifyResponse(frame, request, 1050);
        frame.AsSpan().Fill(0xff);

        Assert.Equal(1043UL, verified.IssuedAtUnixSeconds);
        Assert.Equal("DPS1", System.Text.Encoding.ASCII.GetString(verified.CanonicalDps1.Span[..4]));
        Assert.Equal("MRR2", System.Text.Encoding.ASCII.GetString(verified.CanonicalMrr2.Span[..4]));
        Assert.True(verified.NoDeliveryOrDurabilityClaim);
    }

    private sealed class Fixture
    {
        private Fixture() { }
        internal required byte[] Frame { get; init; }
        internal required VerifiedMembershipRoutingLkg Lkg { get; init; }
        internal required VerifiedRouterContact SenderContact { get; init; }
        internal required VerifiedRouterContact RecipientContact { get; init; }
        internal required BlindedPlacementId PlacementId { get; init; }
        internal required byte[] RequestId { get; init; }
        internal required byte[] RecipientId { get; init; }
        internal required byte[] RecipientSeed { get; init; }
        internal required byte[] RecipientPrivateKey { get; init; }
        internal required byte[] OperationId { get; init; }
        internal required byte[] BlindedMailboxId { get; init; }
        internal required byte[] TombstoneDigest { get; init; }

        internal static Fixture Create()
        {
            var network = Bytes(1, 16);
            var reset = Bytes(2, 32);
            var senderKeys = PublicKeyAuth.GenerateKeyPair(Bytes(3, 32));
            var recipientKeys = PublicKeyAuth.GenerateKeyPair(Bytes(4, 32));
            var senderId = Bytes(5, 32);
            var recipientId = Bytes(6, 32);
            var senderDnr = Ref(ArtifactType.Dnr1, 756, 7);
            var recipientDnr = Ref(ArtifactType.Dnr1, 756, 8);
            var senderContactBytes = Contact(network, senderId, senderDnr, senderKeys);
            var recipientContactBytes = Contact(network, recipientId, recipientDnr, recipientKeys);
            var senderContactReference = CanonicalGrammar.EncodeReference(
                CanonicalGrammar.ComputeReference(ArtifactType.Dpc1, senderContactBytes));
            var recipientContactReference = CanonicalGrammar.EncodeReference(
                CanonicalGrammar.ComputeReference(ArtifactType.Dpc1, recipientContactBytes));
            var senderContact = new VerifiedRouterContact(CanonicalGrammar.DecodeOwned(
                senderContactBytes, RecordDefinitions.Dpc1), senderContactReference, 1);
            var recipientContact = new VerifiedRouterContact(CanonicalGrammar.DecodeOwned(
                recipientContactBytes, RecordDefinitions.Dpc1), recipientContactReference, 1);
            var senderMrl = Mrl2(network, senderId, senderDnr,
                senderContact.ArtifactReference.Span);
            var recipientMrl = Mrl2(network, recipientId, recipientDnr,
                recipientContact.ArtifactReference.Span);
            var senderLeaf = NativeMembershipVerifier.RealLeaf(reset, 7, 9, 0, senderMrl);
            var recipientLeaf = NativeMembershipVerifier.RealLeaf(reset, 7, 10, 1, recipientMrl);
            var node = NativeMembershipVerifier.Node(0, 0, senderLeaf, recipientLeaf);
            var root = NativeMembershipVerifier.Root(reset, 7, 2, 2, node);
            var lkg = new VerifiedMembershipRoutingLkg(
                network, reset, 11, 7, 1200, root, Bytes(9, 32),
                [
                    new VerifiedRouterEntry(senderId, senderKeys.PublicKey, senderDnr,
                        senderMrl, 9, RouterRoles.MailboxReplica,
                        RouterCapabilities.NativePeerMailboxV2),
                    new VerifiedRouterEntry(recipientId, recipientKeys.PublicKey, recipientDnr,
                        recipientMrl, 10, RouterRoles.MailboxReplica,
                        RouterCapabilities.NativePeerMailboxV2)
                ]);
            var senderProof = Proof(network, reset, root, senderMrl, senderId,
                senderKeys.PublicKey, 0, recipientLeaf, 9);
            var recipientProof = Proof(network, reset, root, recipientMrl, recipientId,
                recipientKeys.PublicKey, 1, senderLeaf, 10);
            var placement = new BlindedPlacementId(Bytes(10, 32));
            var requestId = Bytes(11, 32);
            var payload = Bytes(12, 32);
            var operationId = Bytes(13, 16);
            var blindedMailboxId = Bytes(14, 32);
            var request = new MailboxPeerWireRequestV2
            {
                Operation = MailboxPeerReplicationOperation.Tombstone,
                Epoch = 7,
                OperationId = operationId,
                SenderRouterId = senderId,
                RecipientRouterId = recipientId,
                MembershipCommitment = root,
                PlacementCommitment = MailboxPlacementCommitment.Compute(placement),
                BlindedMailboxId = blindedMailboxId,
                Cursor = 1,
                CreatedAtUnixSeconds = 1040,
                ExpiresAtUnixSeconds = 1100,
                ReplayNonce = requestId,
                PayloadDigest = SHA256.HashData(payload),
                Payload = payload,
                SenderMembershipProof = senderProof,
                RecipientMembershipProof = recipientProof,
                Signature = ReadOnlyMemory<byte>.Empty
            };
            var crypto = new SodiumMailboxPeerReplicationCrypto();
            var signedRequest = crypto.SignRequest(request, Bytes(3, 32));
            var prq = MailboxPeerWireV2Codec.Encode(signedRequest);
            var dpr = Dpr(network, senderId, recipientId, senderContact, recipientContact,
                requestId, prq, senderKeys.PrivateKey);
            var frame = new byte[4 + dpr.Length + 4 + prq.Length];
            BinaryPrimitives.WriteUInt32BigEndian(frame, checked((uint)dpr.Length));
            dpr.CopyTo(frame, 4);
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(4 + dpr.Length), checked((uint)prq.Length));
            prq.CopyTo(frame, 8 + dpr.Length);
            return new Fixture
            {
                Frame = frame,
                Lkg = lkg,
                SenderContact = senderContact,
                RecipientContact = recipientContact,
                PlacementId = placement,
                RequestId = requestId,
                RecipientId = recipientId,
                RecipientSeed = Bytes(4, 32),
                RecipientPrivateKey = recipientKeys.PrivateKey,
                OperationId = operationId,
                BlindedMailboxId = blindedMailboxId,
                TombstoneDigest = payload
            };
        }
    }

    private static byte[] Dps(
        VerifiedNativePeerRequest request,
        byte[] mrr,
        byte[] recipientPrivateKey)
    {
        var dpr = CanonicalGrammar.DecodeOwned(
            request.CanonicalDpr1.Span, RecordDefinitions.Dpr1);
        var fields = RecordDefinitions.Dps1.Fields
            .Select(static value => (ReadOnlyMemory<byte>)new byte[value.MinimumLength]).ToArray();
        for (var tag = 1; tag <= 6; tag++) fields[tag - 1] = dpr.FieldCopy(tag);
        fields[6] = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Dpr1, dpr.CanonicalSpan));
        fields[7] = CanonicalGrammar.EncodeReference(new ArtifactReference(
            ArtifactType.Mrr2, checked((uint)mrr.Length), SHA256.HashData(mrr)));
        fields[8] = U64(1043); fields[9] = U64(1100); fields[10] = new byte[64];
        var unsigned = CanonicalGrammar.Encode(RecordDefinitions.Dps1, fields);
        fields[10] = PublicKeyAuth.SignDetached(CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(unsigned, RecordDefinitions.Dps1),
            "Deep/NativeRouting/V1/response"), recipientPrivateKey);
        return CanonicalGrammar.Encode(RecordDefinitions.Dps1, fields);
    }

    private static void RebindPrqReferenceWithoutResigning(byte[] frame)
    {
        var dpr = CanonicalGrammar.DecodeOwned(
            frame.AsSpan(4, NativePeerVerifier.DprLength),
            RecordDefinitions.Dpr1);
        var fields = RecordDefinitions.Dpr1.Fields
            .Select(static value => (ReadOnlyMemory<byte>)new byte[value.MinimumLength]).ToArray();
        for (var tag = 1; tag <= fields.Length; tag++) fields[tag - 1] = dpr.FieldCopy(tag);
        var prq = frame.AsSpan(NativePeerVerifier.RequestFixedOverhead);
        fields[9] = CanonicalGrammar.EncodeReference(new ArtifactReference(
            ArtifactType.Prq2, checked((uint)prq.Length), SHA256.HashData(prq)));
        CanonicalGrammar.Encode(RecordDefinitions.Dpr1, fields).CopyTo(frame, 4);
    }

    private static MailboxReplicaMembershipProof Proof(
        byte[] network, byte[] reset, byte[] root, byte[] mrl, byte[] router,
        byte[] key, uint index, byte[] sibling, ulong generation)
    {
        var fields = RecordDefinitions.Rip2.Fields
            .Select(static value => (ReadOnlyMemory<byte>)new byte[value.MinimumLength]).ToArray();
        fields[0] = network; fields[1] = reset; fields[2] = U64(11); fields[3] = U64(7);
        fields[4] = U16(2); fields[5] = U64(generation); fields[6] = U32(2); fields[7] = U32(2);
        fields[8] = U32(index); fields[9] = root; fields[10] = U32(326); fields[11] = mrl;
        fields[12] = new byte[] { 1 }; fields[13] = sibling;
        return new MailboxReplicaMembershipProof
        {
            ReplicaId = router,
            SigningPublicKey = key,
            Epoch = 7,
            MembershipCommitment = root,
            CanonicalInclusionProof = CanonicalGrammar.Encode(RecordDefinitions.Rip2, fields)
        };
    }

    private static byte[] Dpr(
        byte[] network, byte[] sender, byte[] recipient,
        VerifiedRouterContact senderContact, VerifiedRouterContact recipientContact,
        byte[] requestId, byte[] prq, byte[] senderPrivateKey)
    {
        var fields = RecordDefinitions.Dpr1.Fields
            .Select(static value => (ReadOnlyMemory<byte>)new byte[value.MinimumLength]).ToArray();
        fields[0] = network; fields[1] = sender; fields[2] = recipient;
        fields[3] = senderContact.ArtifactReference; fields[4] = recipientContact.ArtifactReference;
        fields[5] = requestId; fields[6] = U64(1040); fields[7] = U64(1100); fields[8] = U16(1);
        fields[9] = CanonicalGrammar.EncodeReference(new ArtifactReference(
            ArtifactType.Prq2, checked((uint)prq.Length), SHA256.HashData(prq)));
        fields[10] = new byte[64];
        var unsigned = CanonicalGrammar.Encode(RecordDefinitions.Dpr1, fields);
        fields[10] = PublicKeyAuth.SignDetached(CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(unsigned, RecordDefinitions.Dpr1),
            "Deep/NativeRouting/V1/request"), senderPrivateKey);
        return CanonicalGrammar.Encode(RecordDefinitions.Dpr1, fields);
    }

    private static byte[] Contact(byte[] network, byte[] router, byte[] dnr, KeyPair keys)
    {
        var fields = RecordDefinitions.Dpc1.Fields
            .Select(static value => (ReadOnlyMemory<byte>)new byte[value.MinimumLength]).ToArray();
        fields[0] = network; fields[1] = router; fields[2] = dnr; fields[3] = U64(1);
        fields[4] = new byte[38]; fields[5] = U64(1000); fields[6] = U64(1200);
        fields[7] = U64((ulong)RouterCapabilities.NativePeerMailboxV2);
        fields[8] = new byte[] { (byte)EndpointKind.Ipv4 }; fields[9] = new byte[] { 1, 1, 1, 1 };
        fields[10] = U16(443); fields[11] = Bytes(15, 32); fields[12] = new byte[32];
        fields[13] = U64(1); fields[14] = new byte[64];
        var unsigned = CanonicalGrammar.Encode(RecordDefinitions.Dpc1, fields);
        fields[14] = PublicKeyAuth.SignDetached(CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(unsigned, RecordDefinitions.Dpc1),
            "Deep/NativeRouting/V1/contact"), keys.PrivateKey);
        return CanonicalGrammar.Encode(RecordDefinitions.Dpc1, fields);
    }

    private static byte[] Mrl2(byte[] network, byte[] router, byte[] dnr, ReadOnlySpan<byte> contact)
    {
        var fields = RecordDefinitions.Mrl2.Fields
            .Select(static value => (ReadOnlyMemory<byte>)new byte[value.MinimumLength]).ToArray();
        fields[0] = network; fields[1] = U64(7); fields[2] = U64(router[0] == 5 ? 9UL : 10UL);
        fields[3] = router; fields[4] = dnr; fields[5] = U64((ulong)RouterRoles.MailboxReplica);
        fields[6] = U64((ulong)RouterCapabilities.NativePeerMailboxV2);
        fields[7] = U64(1); fields[8] = contact.ToArray(); fields[9] = U64(1000);
        fields[10] = U64(1200); fields[11] = new byte[38];
        return CanonicalGrammar.Encode(RecordDefinitions.Mrl2, fields);
    }

    private static byte[] Ref(ArtifactType type, uint length, byte marker)
    {
        var value = new byte[38];
        BinaryPrimitives.WriteUInt16BigEndian(value, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(2), length);
        value[6] = marker;
        return value;
    }

    private static byte[] Bytes(byte value, int length) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] U16(ushort value) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    private static byte[] U32(uint value) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
}
