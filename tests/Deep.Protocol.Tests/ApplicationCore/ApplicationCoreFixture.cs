using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.ApplicationCore;

internal static class ApplicationCoreFixture
{
    internal static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();

    internal static ApplicationArtifactReference Reference(ushort type, uint length, byte value) =>
        ApplicationCoreCodec.CreateArtifactReference(type, length, Bytes(32, value));

    internal static RevocationSnapshot Revocations(byte[] network, byte[] account)
    {
        var fields = RecordDefinitions.Drs1.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength])
            .ToArray();
        fields[0] = network;
        fields[1] = account;
        fields[2] = U64(1);
        fields[3] = U64(1);
        fields[4] = U64(100);
        fields[7] = Bytes(32, 0x77);
        return IdentityCodec.DecodeRevocationSnapshot(CanonicalGrammar.Encode(RecordDefinitions.Drs1, fields));
    }

    internal static ParsedDmd1 Directory(
        byte[] network,
        byte[] account,
        byte[] device,
        RevocationSnapshot? revocations = null,
        ulong generation = 1,
        byte predecessorValue = 0)
    {
        revocations ??= Revocations(network, account);
        var drsReference = ApplicationCoreCodec.CreateArtifactReference(
            (ushort)ArtifactType.Drs1,
            checked((uint)revocations.CanonicalBytes.Length),
            revocations.CanonicalHash.Span);
        var devices = new[]
        {
            new DeviceDirectoryEntry(device, Reference((ushort)ArtifactType.Dpd1, 776, 0x31)),
        };
        return ApplicationCoreCodec.AuthorDmd1(
            network,
            account,
            1,
            Reference((ushort)ArtifactType.Dpa1, 644, 0x21),
            drsReference,
            generation,
            Bytes(32, predecessorValue),
            devices,
            100,
            Bytes(64, 0x41));
    }

    internal static ParsedDmc2 Message(
        Dmc2Payload payload,
        byte[]? network = null,
        byte[]? account = null,
        byte[]? device = null,
        Dmc2Flags? flags = null,
        ulong? expiresAt = null,
        byte[]? reply = null)
    {
        network ??= Bytes(16, 0x11);
        account ??= Bytes(32, 0x14);
        device ??= Bytes(32, 0x15);
        var createdAt = 1_000UL;
        var effectiveFlags = flags ?? payload.Kind switch
        {
            Dmc2ContentKind.Typing => Dmc2Flags.Silent,
            Dmc2ContentKind.AttachmentCancel => Dmc2Flags.Silent,
            _ => Dmc2Flags.None,
        };
        var effectiveExpiry = expiresAt ?? payload.Kind switch
        {
            Dmc2ContentKind.SessionInit => createdAt + 10_000,
            Dmc2ContentKind.Typing => createdAt + 10_000,
            _ => 0UL,
        };
        return ApplicationCoreCodec.AuthorDmc2(
            network,
            Bytes(32, 0x12),
            Bytes(32, 0x13),
            account,
            device,
            1,
            createdAt,
            effectiveExpiry,
            effectiveFlags,
            reply ?? [],
            payload);
    }

    internal static VerifiedDpe2Envelope VerifiedEnvelope(
        ParsedDmc2 plaintext,
        byte[]? authenticatedNetwork = null,
        byte[]? authenticatedAccount = null,
        byte[]? authenticatedDevice = null,
        byte[]? authenticatedConversation = null,
        byte[]? envelopeNetwork = null,
        byte[]? envelopeDevice = null,
        byte[]? authenticatedSession = null)
    {
        var network = envelopeNetwork ?? plaintext.NetworkId.ToArray();
        var session = Bytes(32, 0xb1);
        var senderDevice = envelopeDevice ?? plaintext.SenderDeviceId.ToArray();
        var header = new Dtr2Record(
            network,
            Bytes(32, 0x91),
            0,
            1,
            1,
            0,
            1,
            1,
            Dtr2BraidMessage.None());
        var envelope = new Dpe2Record(
            network,
            session,
            senderDevice,
            Bytes(32, 0x92),
            Bytes(32, 0x93),
            header,
            Dpe2Ciphertext.Import(Bytes(4112, 0x94)));
        return MessagingWireVerification.VerifyDpe2(
            Dpe2Codec.Encode(envelope),
            new AcceptRatchet(),
            new AuthenticatedPlaintext(
                plaintext.CanonicalBytes.ToArray(),
                authenticatedNetwork ?? plaintext.NetworkId.ToArray(),
                authenticatedSession ?? session,
                authenticatedAccount ?? plaintext.SenderAccountId.ToArray(),
                authenticatedDevice ?? plaintext.SenderDeviceId.ToArray(),
                authenticatedConversation ?? plaintext.ConversationId.ToArray()));
    }

    internal static int FieldOffset(ReadOnlySpan<byte> canonical, int soughtTag)
    {
        var fieldCount = BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(8, 2));
        var offset = 12;
        for (var index = 0; index < fieldCount; index++)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(canonical.Slice(offset, 2));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(offset + 4, 4)));
            offset += 8;
            if (tag == soughtTag)
                return offset;
            offset += length;
        }
        throw new InvalidOperationException("The fixture tag was not found.");
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private sealed class AcceptRatchet : IDtr2VerificationCallbacks
    {
        public bool VerifyBraidMessage(Dtr2Record header) => true;
    }

    private sealed class AuthenticatedPlaintext(
        byte[] plaintext,
        byte[] network,
        byte[] session,
        byte[] account,
        byte[] device,
        byte[] conversation) : IDpe2VerificationCallbacks
    {
        public void AuthenticateExactEnvelope(
            Dpe2AuthenticationVerification verification,
            Dpe2AuthenticationOutput output) => output.AcceptAuthenticatedPlaintext(
                plaintext,
                network,
                session,
                account,
                device,
                conversation);
    }
}
