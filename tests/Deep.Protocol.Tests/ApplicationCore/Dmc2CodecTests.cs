using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class Dmc2CodecTests
{
    [Fact]
    public void EveryFrozenCoreKind_RoundTripsTypedPayload()
    {
        var network = ApplicationCoreFixture.Bytes(16, 0x11);
        var account = ApplicationCoreFixture.Bytes(32, 0x14);
        var device = ApplicationCoreFixture.Bytes(32, 0x15);
        var revocations = ApplicationCoreFixture.Revocations(network, account);
        var directory = ApplicationCoreFixture.Directory(network, account, device, revocations);
        var id1 = new Dmc2LogicalMessageReference(ApplicationCoreFixture.Bytes(32, 0x31));
        var id2 = new Dmc2LogicalMessageReference(ApplicationCoreFixture.Bytes(32, 0x32));
        Dmc2Payload[] payloads =
        [
            ApplicationCoreCodec.CreateSessionInitPayload(ApplicationCoreFixture.Bytes(32, 0x41), directory,
                SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl),
            ApplicationCoreCodec.CreateMessageCreatePayload("hello"),
            ApplicationCoreCodec.CreateMessageEditPayload(ApplicationCoreFixture.Bytes(32, 0x42), "edited"),
            ApplicationCoreCodec.CreateMessageDeletePayload(ApplicationCoreFixture.Bytes(32, 0x43),
                MessageDeleteScope.LocalRequest),
            ApplicationCoreCodec.CreateReactionSetPayload(ApplicationCoreFixture.Bytes(32, 0x44),
                ReactionOperation.Add, "👍"),
            ApplicationCoreCodec.CreateReceiptDeliveredPayload(
            [
                new Dmc2DeliveryReceiptEntry(id1.LogicalMessageId.Span, DeliveryReceiptStatus.StoreAccepted),
                new Dmc2DeliveryReceiptEntry(id2.LogicalMessageId.Span, DeliveryReceiptStatus.Materialized),
            ]),
            ApplicationCoreCodec.CreateReceiptReadPayload([id1, id2]),
            ApplicationCoreCodec.CreateTypingPayload(TypingOperation.Start, ApplicationCoreFixture.Bytes(32, 0x45)),
            ApplicationCoreCodec.CreateDeviceListUpdatePayload(directory),
            ApplicationCoreCodec.CreateDeviceRevocationPayload(revocations, directory),
        ];

        foreach (var payload in payloads)
        {
            var authored = ApplicationCoreFixture.Message(payload, network, account, device);
            var decoded = ApplicationCoreCodec.DecodeDmc2(authored.CanonicalBytes.Span);
            Assert.Equal(payload.Kind, decoded.ContentKind);
            Assert.Equal(authored.CanonicalBytes.ToArray(), decoded.CanonicalBytes.ToArray());
            Assert.Equal(282 + decoded.ReplyToLogicalMessageId.Length + payload.CanonicalBytes.Length,
                decoded.CanonicalBytes.Length);
        }
    }

    [Fact]
    public void MessageCreate_ReplyAndFlagsRoundTrip()
    {
        var reply = ApplicationCoreFixture.Bytes(32, 0x55);
        var record = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateMessageCreatePayload("reply"),
            flags: Dmc2Flags.Silent | Dmc2Flags.HighPriority,
            reply: reply);

        Assert.Equal(reply, record.ReplyToLogicalMessageId.ToArray());
        Assert.Equal(Dmc2Flags.Silent | Dmc2Flags.HighPriority, record.Flags);
        using var envelope = ApplicationCoreFixture.VerifiedEnvelope(record);
        var verified = ApplicationCoreVerifier.VerifyDmc2(envelope);
        Assert.Equal("reply", Assert.IsType<MessageCreateDmc2Payload>(verified.Payload).Text);
    }

    [Theory]
    [InlineData(30)]
    [InlineData(65535)]
    public void ReservedKind_RejectsBeforePayload(int kind)
    {
        var canonical = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateMessageCreatePayload("hello")).CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(
            canonical.AsSpan(ApplicationCoreFixture.FieldOffset(canonical, 9), 2), checked((ushort)kind));

        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDmc2(canonical));
        Assert.Equal(ApplicationCoreValidationStage.TypedPayload, exception.Stage);
        Assert.Equal(ApplicationCoreRejection.ReservedContentKind, exception.Rejection);
    }

    [Fact]
    public void UnknownFlagRejects()
    {
        var canonical = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateMessageCreatePayload("hello")).CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(
            canonical.AsSpan(ApplicationCoreFixture.FieldOffset(canonical, 10), 4), 1u << 31);

        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDmc2(canonical));
        Assert.Equal(ApplicationCoreRejection.InvalidFlags, exception.Rejection);
    }

    [Fact]
    public void ReplyOnEditRejects()
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateMessageEditPayload(ApplicationCoreFixture.Bytes(32, 0x21), "x"),
            reply: ApplicationCoreFixture.Bytes(32, 0x22)));
        Assert.Equal(ApplicationCoreRejection.InvalidFlags, exception.Rejection);
    }

    [Theory]
    [InlineData(86_400_001)]
    [InlineData(0)]
    public void SessionInit_InvalidExpiryRejects(ulong expiryDelta)
    {
        var network = ApplicationCoreFixture.Bytes(16, 0x11);
        var account = ApplicationCoreFixture.Bytes(32, 0x14);
        var device = ApplicationCoreFixture.Bytes(32, 0x15);
        var directory = ApplicationCoreFixture.Directory(network, account, device);
        var payload = ApplicationCoreCodec.CreateSessionInitPayload(ApplicationCoreFixture.Bytes(32, 0x31), directory,
            SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl);
        var expiresAt = expiryDelta == 0 ? 0UL : 1_000UL + expiryDelta;

        Assert.Throws<ApplicationCoreFormatException>(() =>
            ApplicationCoreFixture.Message(payload, network, account, device, expiresAt: expiresAt));
    }

    [Fact]
    public void SessionInit_EmbeddedHashSubstitutionRejects()
    {
        var network = ApplicationCoreFixture.Bytes(16, 0x11);
        var account = ApplicationCoreFixture.Bytes(32, 0x14);
        var device = ApplicationCoreFixture.Bytes(32, 0x15);
        var directory = ApplicationCoreFixture.Directory(network, account, device);
        var canonical = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateSessionInitPayload(ApplicationCoreFixture.Bytes(32, 0x31), directory,
                SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl),
            network, account, device).CanonicalBytes.ToArray();
        var payloadOffset = ApplicationCoreFixture.FieldOffset(canonical, 12);
        canonical[payloadOffset + 32] ^= 0x01;

        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDmc2(canonical));
        Assert.Equal(ApplicationCoreRejection.CrossFieldMismatch, exception.Rejection);
    }

    [Fact]
    public void SessionInit_MalformedEmbeddedDirectoryUsesEmbeddedStage()
    {
        var network = ApplicationCoreFixture.Bytes(16, 0x11);
        var account = ApplicationCoreFixture.Bytes(32, 0x14);
        var device = ApplicationCoreFixture.Bytes(32, 0x15);
        var directory = ApplicationCoreFixture.Directory(network, account, device);
        var canonical = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateSessionInitPayload(ApplicationCoreFixture.Bytes(32, 0x31), directory,
                SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl),
            network, account, device).CanonicalBytes.ToArray();
        var payloadOffset = ApplicationCoreFixture.FieldOffset(canonical, 12);
        canonical[payloadOffset + 68] ^= 0xff;

        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDmc2(canonical));
        Assert.Equal(ApplicationCoreValidationStage.EmbeddedRecord, exception.Stage);
        Assert.Equal(ApplicationCoreRejection.EmbeddedRecordRejected, exception.Rejection);
    }

    [Fact]
    public void SessionInit_SenderIdentitySubstitutionRejects()
    {
        var network = ApplicationCoreFixture.Bytes(16, 0x11);
        var account = ApplicationCoreFixture.Bytes(32, 0x14);
        var device = ApplicationCoreFixture.Bytes(32, 0x15);
        var directory = ApplicationCoreFixture.Directory(network, account, device);
        var payload = ApplicationCoreCodec.CreateSessionInitPayload(ApplicationCoreFixture.Bytes(32, 0x31), directory,
            SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl);

        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreFixture.Message(
            payload, network, ApplicationCoreFixture.Bytes(32, 0x61), device));
        Assert.Equal(ApplicationCoreRejection.CrossFieldMismatch, exception.Rejection);
    }

    [Fact]
    public void ReceiptIds_MustBeStrictlySortedAndUnique()
    {
        var high = new Dmc2LogicalMessageReference(ApplicationCoreFixture.Bytes(32, 0x32));
        var low = new Dmc2LogicalMessageReference(ApplicationCoreFixture.Bytes(32, 0x31));
        var exception = Assert.Throws<ApplicationCoreFormatException>(() =>
            ApplicationCoreCodec.CreateReceiptReadPayload([high, low]));
        Assert.Equal(ApplicationCoreRejection.InvalidOrdering, exception.Rejection);
    }

    [Fact]
    public void NonCanonicalTextRejectsWithoutNormalization()
    {
        var decomposed = "e\u0301";
        Assert.False(decomposed.IsNormalized(NormalizationForm.FormC));
        var exception = Assert.Throws<ApplicationCoreFormatException>(() =>
            ApplicationCoreCodec.CreateMessageCreatePayload(decomposed));
        Assert.Equal(ApplicationCoreRejection.NonCanonicalText, exception.Rejection);
    }

    [Fact]
    public void ReactionRequiresExactlyOneGrapheme()
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(() =>
            ApplicationCoreCodec.CreateReactionSetPayload(ApplicationCoreFixture.Bytes(32, 0x22),
                ReactionOperation.Add, "👍👍"));
        Assert.Equal(ApplicationCoreRejection.NonCanonicalText, exception.Rejection);
    }

    [Fact]
    public void MalformedLp16RejectsBeforeApplicationCallback()
    {
        var canonical = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateMessageCreatePayload("hello")).CanonicalBytes.ToArray();
        var payloadOffset = ApplicationCoreFixture.FieldOffset(canonical, 12);
        BinaryPrimitives.WriteUInt16BigEndian(canonical.AsSpan(payloadOffset, 2), 4);

        var exception = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDmc2(canonical));
        Assert.Equal(ApplicationCoreValidationStage.TypedPayload, exception.Stage);
        Assert.Equal(ApplicationCoreRejection.InvalidFieldLength, exception.Rejection);
    }

    [Fact]
    public void ReturnedCanonicalCopiesCannotMutateRecord()
    {
        var record = ApplicationCoreFixture.Message(ApplicationCoreCodec.CreateMessageCreatePayload("owned"));
        var first = record.CanonicalBytes.ToArray();
        first[0] ^= 0xff;
        var second = record.CanonicalBytes.ToArray();

        Assert.Equal("DMC2", Encoding.ASCII.GetString(second.AsSpan(0, 4)));
        Assert.NotEqual(first, second);
    }
}
