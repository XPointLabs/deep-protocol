using System.Buffers.Binary;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.MessagingWire;

public sealed class MessagingWireNegativeTests
{
    [Fact]
    public void TruncatedAndTrailingRecordsRejectAtExactSizeStage()
    {
        var valid = Dpk2Codec.Encode(MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime));
        AssertReject(
            () => Dpk2Codec.Decode(valid[..^1]),
            MessagingWirePrevalidationStage.ExactTotalSize,
            MessagingWireRejection.InvalidTotalSize);
        AssertReject(
            () => Dpk2Codec.Decode(valid.Concat([(byte)0x00]).ToArray()),
            MessagingWirePrevalidationStage.ExactTotalSize,
            MessagingWireRejection.InvalidTotalSize);
    }

    [Fact]
    public void ExactTotalSizeRejectsMaxPlusOneBeforeHeaderRead()
    {
        var valid = Dpe2Codec.Encode(MessagingWireFixtures.Dpe2(
            MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.EncapsulationKey).Record,
            49152));
        var invalid = new byte[valid.Length + 1];
        valid.CopyTo(invalid, 0);

        AssertReject(
            () => Dpe2Codec.Decode(invalid),
            MessagingWirePrevalidationStage.ExactTotalSize,
            MessagingWireRejection.InvalidTotalSize);
    }

    [Fact]
    public void BoundedOwnedPayloadsRejectMaximumPlusOne()
    {
        Assert.Throws<ArgumentException>(() =>
            Dph2InitialCiphertext.Import(new byte[32785]));
        Assert.Throws<ArgumentException>(() =>
            Dpe2Ciphertext.Import(new byte[49153]));
        Assert.Throws<ArgumentException>(() =>
            Dtr2BraidMessage.EncapsulationKey(new byte[1153]));
        Assert.Throws<ArgumentException>(() =>
            Dtr2BraidMessage.Ciphertext1(new byte[961]));
        Assert.Throws<ArgumentException>(() =>
            Dtr2BraidMessage.Ciphertext2(new byte[129], new byte[32]));
    }

    [Theory]
    [InlineData("DPAC")]
    [InlineData("DPDC")]
    [InlineData("DPKB")]
    [InlineData("DPHI")]
    [InlineData("DPE1")]
    public void RetiredMagicsAreNeverAliases(string retiredMagic)
    {
        var encoded = Dpk2Codec.Encode(MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime));
        System.Text.Encoding.ASCII.GetBytes(retiredMagic).CopyTo(encoded, 0);

        AssertReject(
            () => Dpk2Codec.Decode(encoded),
            MessagingWirePrevalidationStage.FixedHeader,
            MessagingWireRejection.WrongMagic);
    }

    [Theory]
    [InlineData(0x0101)]
    [InlineData(0x0102)]
    [InlineData(0x0202)]
    public void RetiredAndReservedSuitesReject(ushort suite)
    {
        var encoded = Dpk2Codec.Encode(MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(6, 2), suite);

        AssertReject(
            () => Dpk2Codec.Decode(encoded),
            MessagingWirePrevalidationStage.FixedHeader,
            MessagingWireRejection.WrongSuite);
    }

    [Fact]
    public void FixedHeaderVersionCountAndReservedRejectExactly()
    {
        var valid = Dpk2Codec.Encode(MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime));
        var version = valid.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(version.AsSpan(4, 2), 2);
        AssertReject(() => Dpk2Codec.Decode(version), MessagingWirePrevalidationStage.FixedHeader, MessagingWireRejection.WrongVersion);

        var count = valid.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(count.AsSpan(8, 2), 25);
        AssertReject(() => Dpk2Codec.Decode(count), MessagingWirePrevalidationStage.FixedHeader, MessagingWireRejection.WrongFieldCount);

        var reserved = valid.ToArray();
        reserved[11] = 1;
        AssertReject(() => Dpk2Codec.Decode(reserved), MessagingWirePrevalidationStage.FixedHeader, MessagingWireRejection.ReservedNotZero);
    }

    [Fact]
    public void UnknownDuplicateOutOfOrderAndFieldReservedTagsReject()
    {
        var valid = Dpk2Codec.Encode(MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime));
        var unknown = valid.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(unknown.AsSpan(12, 2), 27);
        AssertReject(() => Dpk2Codec.Decode(unknown), MessagingWirePrevalidationStage.FieldHeaders, MessagingWireRejection.UnknownTag);

        var duplicate = valid.ToArray();
        var secondHeader = LocateHeader(duplicate, 2);
        BinaryPrimitives.WriteUInt16BigEndian(duplicate.AsSpan(secondHeader, 2), 1);
        AssertReject(() => Dpk2Codec.Decode(duplicate), MessagingWirePrevalidationStage.FieldHeaders, MessagingWireRejection.DuplicateTag);

        var outOfOrder = valid.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(outOfOrder.AsSpan(12, 2), 2);
        AssertReject(() => Dpk2Codec.Decode(outOfOrder), MessagingWirePrevalidationStage.FieldHeaders, MessagingWireRejection.OutOfOrderTag);

        var fieldReserved = valid.ToArray();
        fieldReserved[15] = 1;
        AssertReject(() => Dpk2Codec.Decode(fieldReserved), MessagingWirePrevalidationStage.FieldHeaders, MessagingWireRejection.ReservedNotZero);
    }

    [Fact]
    public void HostileLengthAndExactFieldLengthRejectBeforeOwnedCopy()
    {
        var valid = Dpk2Codec.Encode(MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime));
        var hostile = valid.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(16, 4), uint.MaxValue);
        AssertReject(() => Dpk2Codec.Decode(hostile), MessagingWirePrevalidationStage.FieldHeaders, MessagingWireRejection.InvalidFieldLength);

        var fields = ManualMessagingWire.Dpk2Fields(MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime));
        fields[0].Value = fields[0].Value.Concat([(byte)0x7f]).ToArray();
        fields[1].Value = fields[1].Value[..^1];
        var wrongExactLengths = ManualMessagingWire.Record("DPK2", fields);
        AssertReject(() => Dpk2Codec.Decode(wrongExactLengths), MessagingWirePrevalidationStage.FieldLengths, MessagingWireRejection.InvalidFieldLength);
    }

    [Fact]
    public void Zero16NetworkIdRejectsAcrossEveryNetworkBoundE2eeRecord()
    {
        var offering = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var dpk2 = Dpk2Codec.Encode(offering);
        var dph2 = Dph2Codec.Encode(MessagingWireFixtures.Dph2(offering, 4112));
        var dtr2 = Dtr2Codec.EncodeEmbedded(MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.None).Record);
        var dpe2 = Dpe2Codec.Encode(MessagingWireFixtures.Dpe2(
            MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.None).Record,
            4112));

        foreach (var (encoded, decode) in new (byte[] Encoded, Action<byte[]> Decode)[]
                 {
                     (dpk2, value => Dpk2Codec.Decode(value)),
                     (dph2, value => Dph2Codec.Decode(value)),
                     (dtr2, value => Dtr2Codec.DecodeEmbedded(value)),
                     (dpe2, value => Dpe2Codec.Decode(value)),
                 })
        {
            var zeroNetwork = encoded.ToArray();
            var field = LocateValue(zeroNetwork, 1);
            zeroNetwork.AsSpan(field.Offset, field.Length).Clear();
            AssertReject(
                () => decode(zeroNetwork),
                MessagingWirePrevalidationStage.SemanticFields,
                MessagingWireRejection.ZeroForbidden);
        }

        Assert.Throws<ArgumentException>(() => new Dpk2Record(
            new byte[16], offering.ResponderAccountId.Span, offering.ResponderDeviceId.Span,
            offering.ResponderDeviceGeneration, offering.ResponderDpd1Ref.Span,
            offering.DeviceDirectoryGeneration, offering.DeviceDirectoryHeadHash.Span,
            offering.PrekeyServiceGeneration, offering.InventoryEpoch, offering.BundleId.Span,
            offering.PolicyGeneration, offering.NotBefore, offering.IssuedAt, offering.ExpiresAt,
            offering.DeviceAgreementPublicKey.Span, offering.SignedX25519PrekeyId.Span,
            offering.SignedX25519PrekeyPublic.Span, offering.SignedX25519PrekeySignature.Span,
            offering.OneTimeX25519PrekeyId.Span, offering.OneTimeX25519PrekeyPublic.Span,
            offering.MlKemPrekeyId.Span, offering.MlKem768EncapsulationKey.Span,
            offering.MlKemKind, offering.ReuseLimit, offering.MlKemPrekeySignature.Span,
            offering.BundleSignature.Span));
    }

    [Fact]
    public void Dpk2KindPresenceAndReuseCrossSubstitutionRejects()
    {
        var fields = ManualMessagingWire.Dpk2Fields(MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime));
        fields[22].Value[0] = (byte)Dpk2PrekeyKind.LastResort;
        var substituted = ManualMessagingWire.Record("DPK2", fields);

        AssertReject(
            () => Dpk2Codec.Decode(substituted),
            MessagingWirePrevalidationStage.SemanticFields,
            MessagingWireRejection.CrossFieldMismatch);
    }

    [Fact]
    public void Dph2CrossKindRejectsBeforeCiphertextOwnership()
    {
        var offering = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var record = MessagingWireFixtures.Dph2(offering, 32784);
        var fields = ManualMessagingWire.Dph2Fields(record);
        fields[15].Value[96] = (byte)Dpk2PrekeyKind.LastResort;
        var substituted = ManualMessagingWire.Record("DPH2", fields);

        AssertReject(
            () => Dph2Codec.Decode(substituted),
            MessagingWirePrevalidationStage.SemanticFields,
            MessagingWireRejection.CrossFieldMismatch);
    }

    [Fact]
    public void Dph2ChangedDerivedSessionAndOfferingSubstitutionReject()
    {
        var offering = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var record = MessagingWireFixtures.Dph2(offering, 4112);
        var fields = ManualMessagingWire.Dph2Fields(record);
        fields[12].Value[0] ^= 0x80;
        var changedSession = ManualMessagingWire.Record("DPH2", fields);
        AssertReject(
            () => Dph2Codec.Decode(changedSession),
            MessagingWirePrevalidationStage.HashProjection,
            MessagingWireRejection.DerivedValueMismatch);

        var otherOfferingBytes = Dpk2Codec.Encode(offering);
        var bundleId = LocateValue(otherOfferingBytes, 10);
        otherOfferingBytes[bundleId.Offset] ^= 0x40;
        var otherOffering = Dpk2Codec.Decode(otherOfferingBytes);
        AssertReject(
            () => Dph2Codec.ValidateSelection(record, otherOffering),
            MessagingWirePrevalidationStage.HashProjection,
            MessagingWireRejection.CrossFieldMismatch);
    }

    [Fact]
    public async Task Dph2DerivedSessionValidationUsesOnlyTheOwnedSnapshot()
    {
        var offering = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var encoded = Dph2Codec.Encode(MessagingWireFixtures.Dph2(offering, 4112));
        var session = LocateValue(encoded, 13);
        var expectedSession = encoded.AsSpan(session.Offset, session.Length).ToArray();
        Assert.Equal(expectedSession, Dph2Codec.Decode(encoded).SessionId.ToArray());

        using var stop = new CancellationTokenSource();
        var mutator = Task.Run(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                encoded[session.Offset] ^= 0x80;
                Thread.Yield();
                encoded[session.Offset] ^= 0x80;
            }
        });

        try
        {
            for (var attempt = 0; attempt < 500; attempt++)
            {
                try
                {
                    var decoded = Dph2Codec.Decode(encoded);
                    Assert.Equal(expectedSession, decoded.SessionId.ToArray());
                }
                catch (MessagingWireFormatException exception)
                {
                    Assert.Equal(MessagingWirePrevalidationStage.HashProjection, exception.Stage);
                    Assert.Equal(MessagingWireRejection.DerivedValueMismatch, exception.Rejection);
                }
            }
        }
        finally
        {
            stop.Cancel();
            await mutator.WaitAsync(TimeSpan.FromSeconds(5));
            encoded[session.Offset] = expectedSession[0];
        }
    }

    [Fact]
    public void Dtr2KindPayloadAndTotalSubstitutionRejects()
    {
        var fixture = MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.Header);
        var fields = ManualMessagingWire.Dtr2Fields(fixture);
        fields[8].Value[0] = (byte)Dtr2BraidMessageKind.Ciphertext2;
        var substituted = ManualMessagingWire.Record("DTR2", fields);

        AssertReject(
            () => Dtr2Codec.DecodeEmbedded(substituted),
            MessagingWirePrevalidationStage.SemanticFields,
            MessagingWireRejection.CrossFieldMismatch);
    }

    [Fact]
    public void Dpe2RejectsEmbeddedSubstitutionBeforeLargeCiphertextCopy()
    {
        var dtr = MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.EncapsulationKey);
        var record = MessagingWireFixtures.Dpe2(dtr.Record, 49152);
        var encoded = Dpe2Codec.Encode(record);
        var nested = LocateValue(encoded, 6);
        System.Text.Encoding.ASCII.GetBytes("DPHI").CopyTo(encoded, nested.Offset);

        AssertReject(
            () => Dpe2Codec.Decode(encoded),
            MessagingWirePrevalidationStage.OwnedCopy,
            MessagingWireRejection.EmbeddedRecordRejected);

        try { Dpe2Codec.Decode(encoded); } catch (MessagingWireFormatException) { }
        var before = GC.GetAllocatedBytesForCurrentThread();
        try { Dpe2Codec.Decode(encoded); } catch (MessagingWireFormatException) { }
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(allocated < 32_768, $"Rejected embedded DTR2 allocated {allocated} bytes before rejection.");
    }

    [Fact]
    public void Dpe2RejectsCrossNetworkEmbeddedDtr2()
    {
        var encoded = Dpe2Codec.Encode(MessagingWireFixtures.Dpe2(
            MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.None).Record,
            4112));
        var network = LocateValue(encoded, 1);
        encoded[network.Offset] ^= 0x40;

        AssertReject(
            () => Dpe2Codec.Decode(encoded),
            MessagingWirePrevalidationStage.OwnedCopy,
            MessagingWireRejection.CrossFieldMismatch);
    }

    private static void AssertReject(
        Action action,
        MessagingWirePrevalidationStage stage,
        MessagingWireRejection rejection)
    {
        var exception = Assert.Throws<MessagingWireFormatException>(action);
        Assert.Equal(stage, exception.Stage);
        Assert.Equal(rejection, exception.Rejection);
    }

    private static int LocateHeader(ReadOnlySpan<byte> encoded, int targetTag)
    {
        var offset = 12;
        var count = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(8, 2));
        for (var index = 0; index < count; index++)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset, 2));
            if (tag == targetTag)
                return offset;
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(offset + 4, 4)));
            offset += 8 + length;
        }

        throw new InvalidOperationException("The requested test field was not found.");
    }

    private static (int Offset, int Length) LocateValue(ReadOnlySpan<byte> encoded, int targetTag)
    {
        var header = LocateHeader(encoded, targetTag);
        return (
            header + 8,
            checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(header + 4, 4))));
    }
}
