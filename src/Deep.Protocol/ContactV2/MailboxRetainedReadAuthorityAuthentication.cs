using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Private forwarding transcript only; not proof of two protected
/// stores, original admission, current issuer authority or durable replay.</summary>
public static class MailboxRetainedReadAuthorityAuthentication
{
    public const string SigningDomain = "Deep/Registry/Internal/V2/mailbox-retained-read-authority";

    public static byte[] GetSigningBytes(ReadOnlySpan<byte> exactXmg2, ReadOnlySpan<byte> exactRoute,
        ulong readUntilUnixSeconds, ulong resultExpiresAtUnixSeconds, ReadOnlySpan<byte> nodeId,
        ulong issuedAtUnixSeconds, ReadOnlySpan<byte> nonce)
    {
        var request = ContactCodec.Decode(ProtocolMagic.XMG2, exactXmg2);
        var route = ContactRouteClosureCodec.Decode(exactRoute);
        if (request.Field(6).Span[0] != 2 || !request.Field(11).Span.SequenceEqual(route.ExactHash.Span) ||
            readUntilUnixSeconds == 0 || issuedAtUnixSeconds == 0 ||
            resultExpiresAtUnixSeconds != BinaryPrimitives.ReadUInt64BigEndian(request.Field(10).Span) ||
            nodeId.Length != 32 || nodeId.IndexOfAnyExcept((byte)0) < 0 ||
            nonce.Length != 32 || nonce.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Retained forwarding requires exact Retrieve/request/route/deadline/node/nonce fields.");
        var domain = Encoding.ASCII.GetBytes(SigningDomain);
        var result = new byte[checked(domain.Length + 7 + exactXmg2.Length + 4 + exactRoute.Length + 8 + 8 + 32 + 8 + 32)];
        domain.CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(domain.Length + 1), 0x0201);
        var offset = domain.Length + 3;
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset), checked((uint)exactXmg2.Length)); offset += 4;
        exactXmg2.CopyTo(result.AsSpan(offset)); offset += exactXmg2.Length;
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset), checked((uint)exactRoute.Length)); offset += 4;
        exactRoute.CopyTo(result.AsSpan(offset)); offset += exactRoute.Length;
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(offset), readUntilUnixSeconds); offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(offset), resultExpiresAtUnixSeconds); offset += 8;
        nodeId.CopyTo(result.AsSpan(offset)); offset += 32;
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(offset), issuedAtUnixSeconds); offset += 8;
        nonce.CopyTo(result.AsSpan(offset));
        return result;
    }
}
