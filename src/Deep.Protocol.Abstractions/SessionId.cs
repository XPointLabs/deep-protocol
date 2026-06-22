using System.Buffers.Text;

namespace Deep.Protocol.Abstractions;

public readonly record struct SessionId
{
    public SessionIdPrefix Prefix { get; }
    public ReadOnlyMemory<byte> PublicKey { get; }

    public SessionId(SessionIdPrefix prefix, ReadOnlyMemory<byte> publicKey)
    {
        if (publicKey.Length != ProtocolConstants.X25519PublicKeySize &&
            publicKey.Length != ProtocolConstants.Ed25519PublicKeySize)
        {
            throw new ArgumentException("Session id public key must be 32 bytes.", nameof(publicKey));
        }

        Prefix = prefix;
        PublicKey = publicKey.ToArray();
    }

    public byte[] ToBytes()
    {
        var result = new byte[ProtocolConstants.SessionIdSize];
        result[0] = (byte)Prefix;
        PublicKey.Span.CopyTo(result.AsSpan(1));
        return result;
    }

    public override string ToString() => Convert.ToHexString(ToBytes()).ToLowerInvariant();

    public static SessionId ParseHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        if (hex.Length != ProtocolConstants.SessionIdSize * 2)
        {
            throw new FormatException("Session id hex must contain 33 bytes.");
        }

        var bytes = Convert.FromHexString(hex);
        return Parse(bytes);
    }

    public static SessionId Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ProtocolConstants.SessionIdSize)
        {
            throw new FormatException("Session id must contain 33 bytes.");
        }

        if (!Enum.IsDefined(typeof(SessionIdPrefix), bytes[0]))
        {
            throw new FormatException($"Unknown Session id prefix 0x{bytes[0]:x2}.");
        }

        return new SessionId((SessionIdPrefix)bytes[0], bytes[1..].ToArray());
    }
}
