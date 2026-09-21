using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.MessagingCrypto;

/// <summary>
/// Structural codec for the mandatory encrypted XPK1/XPC1 prefix of the
/// pending DPH2 initial-payload clean break. Parsing proves exact correlation,
/// not threshold signatures, trusted time or recipient publication authority.
/// No verified handshake capability may be minted from this result alone.
/// </summary>
internal static class Dph2InitialClaimTranscriptCodec
{
    internal const int MaximumUnpaddedPayloadBytes = 32_764;

    internal static byte[] Encode(
        ReadOnlySpan<byte> exactXpk1,
        ReadOnlySpan<byte> exactXpc1Wire,
        Dph2Record dph2)
    {
        ArgumentNullException.ThrowIfNull(dph2);
        _ = DecodeRecords(exactXpk1, exactXpc1Wire, dph2);
        var length = checked(8 + exactXpk1.Length + exactXpc1Wire.Length);
        if (length >= MaximumUnpaddedPayloadBytes)
            throw new CryptographicException("The exact DPH2 claim transcript leaves no room for initial events.");
        var prefix = new byte[length];
        BinaryPrimitives.WriteUInt32BigEndian(prefix, checked((uint)exactXpk1.Length));
        exactXpk1.CopyTo(prefix.AsSpan(4));
        var offset = 4 + exactXpk1.Length;
        BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(offset), checked((uint)exactXpc1Wire.Length));
        exactXpc1Wire.CopyTo(prefix.AsSpan(offset + 4));
        return prefix;
    }

    internal static (Xpk1Request Request, Xpc1Result Result, int Consumed) DecodePrefix(
        ReadOnlySpan<byte> unpaddedBody,
        Dph2Record dph2)
    {
        ArgumentNullException.ThrowIfNull(dph2);
        if (unpaddedBody.Length > MaximumUnpaddedPayloadBytes)
            throw new CryptographicException("The DPH2 initial payload exceeds its largest bucket.");
        var offset = 0;
        var requestBytes = ReadLp32(unpaddedBody, ref offset);
        var resultBytes = ReadLp32(unpaddedBody, ref offset);
        var (request, result) = DecodeRecords(requestBytes, resultBytes, dph2);
        if (offset >= unpaddedBody.Length)
            throw new CryptographicException("The DPH2 claim transcript has no initial event sequence.");
        return (request, result, offset);
    }

    private static (Xpk1Request Request, Xpc1Result Result) DecodeRecords(
        ReadOnlySpan<byte> exactXpk1,
        ReadOnlySpan<byte> exactXpc1Wire,
        Dph2Record dph2)
    {
        if (exactXpk1.IsEmpty || exactXpc1Wire.IsEmpty ||
            exactXpk1.Length > MaximumUnpaddedPayloadBytes - 8 ||
            exactXpc1Wire.Length > MaximumUnpaddedPayloadBytes - 8)
            throw new CryptographicException("The DPH2 claim transcript has invalid record bounds.");
        var request = Xpk1Codec.Decode(exactXpk1);
        var result = Xpc1Codec.Decode(exactXpc1Wire, exactXpk1);
        if (result.Status is not (Xpc1Status.Claimed or Xpc1Status.Replay) ||
            result.MutationOutcome != ContactServiceMutationOutcome.DurablyCommitted)
            throw new CryptographicException("The DPH2 claim transcript is not a durable claim.");
        var dpk2 = Dpk2Codec.Decode(result.Field(16).Span);
        Dph2Codec.ValidateSelection(dph2, dpk2);
        var dpk2Hash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(dpk2);
        var commitment = MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(dph2);
        try
        {
            if (!Fixed(request.NetworkId.Span, dph2.NetworkId.Span) ||
                !Fixed(request.OperationId.Span, dph2.ClaimOperationId.Span) ||
                !Fixed(request.ClaimOperationId.Span, dph2.ClaimOperationId.Span) ||
                !Fixed(request.ResponderDeviceId.Span, dph2.ResponderDeviceId.Span) ||
                !Fixed(request.SenderEphemeralCommitment.Span, commitment) ||
                !Fixed(result.Field(18).Span, dph2.ClaimReceiptHash.Span) ||
                !Fixed(result.Field(17).Span,
                    dph2.SelectedPrekey.OneTimeX25519PrekeyIdOrZero.Span) ||
                !Fixed(dpk2Hash, dph2.ExactDpk2Hash.Span))
                throw new CryptographicException(
                    "The encrypted claim transcript differs from the exact DPH2 header.");
            return (request, result);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dpk2Hash);
            CryptographicOperations.ZeroMemory(commitment);
        }
    }

    private static ReadOnlySpan<byte> ReadLp32(ReadOnlySpan<byte> body, ref int offset)
    {
        if (body.Length - offset < 4)
            throw new CryptographicException("The DPH2 claim transcript is truncated.");
        var length = BinaryPrimitives.ReadUInt32BigEndian(body[offset..]);
        offset += 4;
        if (length is 0 or > MaximumUnpaddedPayloadBytes || length > body.Length - offset)
            throw new CryptographicException("The DPH2 claim transcript has an invalid LP32 length.");
        var record = body.Slice(offset, checked((int)length));
        offset += checked((int)length);
        return record;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
