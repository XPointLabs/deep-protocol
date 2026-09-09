using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Protocol.MessagingWire;

public static class MessagingWireCryptographicInputs
{
    public const string X25519SignedPrekeyDomain = "Deep/Messaging/V2/x25519-signed-prekey";
    public const string MlKemPrekeyDomain = "Deep/Messaging/V2/mlkem-prekey";
    public const string PrekeyBundleDomain = "Deep/Messaging/V2/prekey-bundle";
    public const string ExactDpk2Domain = "Deep/Messaging/V2/exact-dpk2";
    public const string SenderEphemeralDomain = "Deep/ContactResolver/V1/sender-ephemeral";
    public const string SessionIdDomain = "Deep/Messaging/V2/session-id";
    public const string HandshakeTranscriptDomain = "Deep/Messaging/V2/handshake-transcript";
    public const string Dph2HeaderDomain = "Deep/Messaging/V2/dph2-header";
    public const string Dph2InitialAadDomain = "Deep/Messaging/V2/dph2-initial-aead-ad";
    public const string ExactDph2ReplayDomain = "Deep/Messaging/V2/exact-dph2-replay";
    public const string PrekeyClaimBindingDomain = "Deep/Messaging/V2/prekey-claim-binding";
    public const string RatchetHeaderDomain = "Deep/Messaging/V2/ratchet-header";
    public const string Dpe2NonceDomain = "Deep/Messaging/V2/dpe2-nonce";
    public const string Dpe2AadDomain = "Deep/Messaging/V2/dpe2-aead-ad";
    public const string ExactDpe2ReplayDomain = "Deep/Messaging/V2/exact-dpe2-replay";

    public static byte[] GetX25519SignedPrekeySignatureInput(Dpk2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return SignatureInput(X25519SignedPrekeyDomain, Dpk2Codec.GetX25519SignedPrekeyProjection(record));
    }

    public static byte[] GetMlKemPrekeySignatureInput(Dpk2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return SignatureInput(MlKemPrekeyDomain, Dpk2Codec.GetMlKemPrekeyProjection(record));
    }

    public static byte[] GetPrekeyBundleSignatureInput(Dpk2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return SignatureInput(PrekeyBundleDomain, Dpk2Codec.GetUnsignedBundleProjection(record));
    }

    public static byte[] ComputeExactDpk2Hash(Dpk2Record record)
        => SHA256.HashData(GetExactDpk2HashInput(record));

    public static byte[] GetExactDpk2HashInput(Dpk2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return DomainHashInput(ExactDpk2Domain, Dpk2Codec.Encode(record));
    }

    public static byte[] ComputeSenderEphemeralCommitment(Dph2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return ComputeSenderEphemeralCommitment(
            record.NetworkIdSpan,
            record.InitiatorAccountIdSpan,
            record.InitiatorDeviceIdSpan,
            record.InitiatorDpd1RefSpan,
            record.InitiatorDeviceAgreementPublicKeySpan,
            record.InitiatorEphemeralX25519PublicKeySpan,
            record.InitiatorInitialRatchetX25519PublicKeySpan);
    }

    internal static byte[] ComputeSenderEphemeralCommitment(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> initiatorAccountId,
        ReadOnlySpan<byte> initiatorDeviceId,
        ReadOnlySpan<byte> initiatorDpd1Reference,
        ReadOnlySpan<byte> initiatorDeviceAgreementPublicKey,
        ReadOnlySpan<byte> initiatorEphemeralPublicKey,
        ReadOnlySpan<byte> initiatorInitialRatchetPublicKey) =>
        ComputeSenderEphemeralCommitmentCore(
            networkId,
            initiatorAccountId,
            initiatorDeviceId,
            initiatorDpd1Reference,
            initiatorDeviceAgreementPublicKey,
            initiatorEphemeralPublicKey,
            initiatorInitialRatchetPublicKey);

    private static byte[] ComputeSenderEphemeralCommitmentCore(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> initiatorAccountId,
        ReadOnlySpan<byte> initiatorDeviceId,
        ReadOnlySpan<byte> initiatorDpd1Reference,
        ReadOnlySpan<byte> initiatorDeviceAgreementPublicKey,
        ReadOnlySpan<byte> initiatorEphemeralPublicKey,
        ReadOnlySpan<byte> initiatorInitialRatchetPublicKey)
    {
        var value = new byte[16 + 32 + 32 + 38 + 32 + 32 + 32];
        var offset = 0;
        networkId.CopyTo(value.AsSpan(offset)); offset += 16;
        initiatorAccountId.CopyTo(value.AsSpan(offset)); offset += 32;
        initiatorDeviceId.CopyTo(value.AsSpan(offset)); offset += 32;
        initiatorDpd1Reference.CopyTo(value.AsSpan(offset)); offset += 38;
        initiatorDeviceAgreementPublicKey.CopyTo(value.AsSpan(offset)); offset += 32;
        initiatorEphemeralPublicKey.CopyTo(value.AsSpan(offset)); offset += 32;
        initiatorInitialRatchetPublicKey.CopyTo(value.AsSpan(offset));
        try
        {
            return Sha256Domain(SenderEphemeralDomain, value);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    public static byte[] ComputeDph2SessionId(Dph2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return Sha256Domain(SessionIdDomain, record.BuildSessionIdValue());
    }

    public static byte[] GetDph2HandshakeHeader(Dph2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return Dph2Codec.GetHandshakeHeader(record);
    }

    public static byte[] GetDph2TranscriptHashInput(Dpk2Record exactOffering, Dph2Record record)
    {
        ArgumentNullException.ThrowIfNull(exactOffering);
        ArgumentNullException.ThrowIfNull(record);
        var exactDpk2 = Dpk2Codec.Encode(exactOffering);
        var header = Dph2Codec.GetHandshakeHeader(record);
        var value = Concat(LengthPrefix32(exactDpk2), LengthPrefix32(header));
        return DomainHashInput(HandshakeTranscriptDomain, value);
    }

    public static byte[] ComputeDph2TranscriptHash(Dpk2Record exactOffering, Dph2Record record) =>
        SHA512.HashData(GetDph2TranscriptHashInput(exactOffering, record));

    public static byte[] ComputeDph2HeaderHash(Dph2Record record)
        => SHA256.HashData(GetDph2HeaderHashInput(record));

    public static byte[] GetDph2HeaderHashInput(Dph2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return DomainHashInput(Dph2HeaderDomain, Dph2Codec.GetHandshakeHeader(record));
    }

    public static byte[] GetDph2InitialAeadAssociatedData(
        Dpk2Record exactOffering,
        Dph2Record record)
    {
        ArgumentNullException.ThrowIfNull(exactOffering);
        ArgumentNullException.ThrowIfNull(record);
        var header = Dph2Codec.GetHandshakeHeader(record);
        var transcriptHash = ComputeDph2TranscriptHash(exactOffering, record);
        return Context(Dph2InitialAadDomain, header, transcriptHash);
    }

    public static byte[] GetDph2FullReplayHashInput(Dph2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return DomainHashInput(ExactDph2ReplayDomain, Dph2Codec.Encode(record));
    }

    public static byte[] ComputeDph2FullReplayHash(Dph2Record record) =>
        SHA256.HashData(GetDph2FullReplayHashInput(record));

    public static byte[] ComputeDph2ClaimBinding(Dph2Record record)
        => SHA256.HashData(GetDph2ClaimBindingHashInput(record));

    public static byte[] GetDph2ClaimBindingHashInput(Dph2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var replayHash = ComputeDph2FullReplayHash(record);
        return DomainHashInput(
            PrekeyClaimBindingDomain,
            Concat(
                record.ClaimOperationIdMemory,
                record.SessionIdMemory,
                record.ExactDpk2HashMemory,
                record.ClaimReceiptHashMemory,
                replayHash));
    }

    public static byte[] GetDpe2Header(Dpe2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return Dpe2Codec.GetHeader(record);
    }

    public static byte[] ComputeDpe2HeaderHash(Dpe2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return ComputeDtr2HeaderHash(record.RatchetHeader);
    }

    public static byte[] GetDtr2HeaderHashInput(Dtr2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return DomainHashInput(RatchetHeaderDomain, Dtr2Codec.EncodeEmbedded(record));
    }

    public static byte[] ComputeDtr2HeaderHash(Dtr2Record record) =>
        SHA256.HashData(GetDtr2HeaderHashInput(record));

    public static byte[] DeriveDpe2Nonce(Dpe2Record record)
        => SHA256.HashData(GetDpe2NonceHashInput(record))[..24];

    public static byte[] GetDpe2NonceHashInput(Dpe2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var headerHash = ComputeDpe2HeaderHash(record);
        return DomainHashInput(
            Dpe2NonceDomain,
            Concat(record.SessionIdMemory, record.OperationIdMemory, headerHash));
    }

    public static byte[] GetDpe2AeadAssociatedData(Dpe2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return Context(Dpe2AadDomain, Dpe2Codec.GetHeader(record), ComputeDpe2HeaderHash(record));
    }

    public static byte[] GetDpe2FullReplayHashInput(Dpe2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return DomainHashInput(ExactDpe2ReplayDomain, Dpe2Codec.Encode(record));
    }

    public static byte[] ComputeDpe2FullReplayHash(Dpe2Record record) =>
        SHA256.HashData(GetDpe2FullReplayHashInput(record));

    internal static byte[] ComputeDph2SessionId(ReadOnlySpan<byte> value) =>
        Sha256Domain(SessionIdDomain, value);

    internal static byte[] Sha256Domain(string label, ReadOnlySpan<byte> value) =>
        SHA256.HashData(DomainHashInput(label, value));

    internal static byte[] Sha512Domain(string label, ReadOnlySpan<byte> value) =>
        SHA512.HashData(DomainHashInput(label, value));

    internal static byte[] DomainHashInput(string label, ReadOnlySpan<byte> value)
    {
        var labelBytes = Ascii(label);
        var output = new byte[labelBytes.Length + 1 + 4 + value.Length];
        labelBytes.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(labelBytes.Length + 1, 4),
            checked((uint)value.Length));
        value.CopyTo(output.AsSpan(labelBytes.Length + 5));
        return output;
    }

    internal static byte[] SignatureInput(string label, ReadOnlySpan<byte> record)
    {
        var labelBytes = Ascii(label);
        var output = new byte[labelBytes.Length + 1 + 2 + 4 + record.Length];
        labelBytes.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(
            output.AsSpan(labelBytes.Length + 1, 2),
            MessagingWireFraming.Suite);
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(labelBytes.Length + 3, 4),
            checked((uint)record.Length));
        record.CopyTo(output.AsSpan(labelBytes.Length + 7));
        return output;
    }

    internal static byte[] Context(string label, params ReadOnlyMemory<byte>[] parts)
    {
        var labelBytes = Ascii(label);
        var length = labelBytes.Length + 1 + 2 + 2;
        foreach (var part in parts)
            length = checked(length + 4 + part.Length);

        var output = new byte[length];
        labelBytes.CopyTo(output, 0);
        var offset = labelBytes.Length + 1;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset, 2), MessagingWireFraming.Suite);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset + 2, 2), checked((ushort)parts.Length));
        offset += 4;
        foreach (var part in parts)
        {
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset, 4), checked((uint)part.Length));
            offset += 4;
            part.Span.CopyTo(output.AsSpan(offset));
            offset += part.Length;
        }

        return output;
    }

    internal static byte[] LengthPrefix32(ReadOnlySpan<byte> value)
    {
        var output = new byte[4 + value.Length];
        BinaryPrimitives.WriteUInt32BigEndian(output, checked((uint)value.Length));
        value.CopyTo(output.AsSpan(4));
        return output;
    }

    internal static byte[] Concat(params ReadOnlyMemory<byte>[] values)
    {
        var length = 0;
        foreach (var value in values)
            length = checked(length + value.Length);
        var output = new byte[length];
        var offset = 0;
        foreach (var value in values)
        {
            value.Span.CopyTo(output.AsSpan(offset));
            offset += value.Length;
        }

        return output;
    }

    private static byte[] Ascii(string label)
    {
        ArgumentException.ThrowIfNullOrEmpty(label);
        if (label.Any(static value => value is < (char)0x20 or > (char)0x7e))
            throw new ArgumentException("A messaging-wire domain must be printable ASCII.", nameof(label));
        return Encoding.ASCII.GetBytes(label);
    }
}
