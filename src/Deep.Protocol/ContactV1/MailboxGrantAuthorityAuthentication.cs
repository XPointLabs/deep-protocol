using System.Buffers.Binary;
using System.Text;

namespace Deep.Protocol.ContactV1;

/// <summary>
/// Canonical authentication transcript for the private XNode-to-mailbox-authority
/// hop. The HTTP representation is deliberately excluded from the signature so
/// transports cannot reinterpret or normalize security-relevant values.
/// </summary>
public static class MailboxGrantAuthorityAuthentication
{
    private static readonly byte[] Domain =
        Encoding.ASCII.GetBytes("Deep/Registry/Internal/V1/mailbox-grant-authority");

    public static byte[] GetSigningBytes(
        ReadOnlySpan<byte> exactXmg1,
        MailboxGrantAcquisitionResultCode resultCode,
        ReadOnlySpan<byte> exactRouteClosure,
        ulong resultExpiresAtUnixSeconds,
        ReadOnlySpan<byte> nodeId,
        ulong issuedAtUnixSeconds,
        ReadOnlySpan<byte> nonce)
    {
        _ = ContactCodec.Decode(ProtocolMagic.XMG1, exactXmg1);
        if (!Enum.IsDefined(resultCode))
            throw new ArgumentOutOfRangeException(nameof(resultCode));
        if (resultCode == MailboxGrantAcquisitionResultCode.Success)
            _ = ContactRouteClosureCodec.Decode(exactRouteClosure);
        else if (!exactRouteClosure.IsEmpty)
            throw new ArgumentException(
                "A failed mailbox grant request must not disclose route bytes.",
                nameof(exactRouteClosure));
        if (resultExpiresAtUnixSeconds == 0 || issuedAtUnixSeconds == 0)
            throw new ArgumentOutOfRangeException(nameof(resultExpiresAtUnixSeconds));
        if (nodeId.Length != 32 || nodeId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The XNode ID must be 32 non-zero bytes.", nameof(nodeId));
        if (nonce.Length != 32 || nonce.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The authentication nonce must be 32 non-zero bytes.", nameof(nonce));

        var size = checked(Domain.Length + 1 + 2 + 4 + exactXmg1.Length + 2
            + 4 + exactRouteClosure.Length + 8 + 32 + 8 + 32);
        var output = new byte[size];
        var offset = 0;
        Domain.CopyTo(output, offset);
        offset += Domain.Length + 1;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), 0x0201);
        offset += 2;
        WriteLp32(output, ref offset, exactXmg1);
        BinaryPrimitives.WriteUInt16BigEndian(
            output.AsSpan(offset), checked((ushort)resultCode));
        offset += 2;
        WriteLp32(output, ref offset, exactRouteClosure);
        BinaryPrimitives.WriteUInt64BigEndian(
            output.AsSpan(offset), resultExpiresAtUnixSeconds);
        offset += 8;
        nodeId.CopyTo(output.AsSpan(offset));
        offset += 32;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset), issuedAtUnixSeconds);
        offset += 8;
        nonce.CopyTo(output.AsSpan(offset));
        return output;
    }

    private static void WriteLp32(byte[] output, ref int offset, ReadOnlySpan<byte> value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(offset), checked((uint)value.Length));
        offset += 4;
        value.CopyTo(output.AsSpan(offset));
        offset += value.Length;
    }
}
