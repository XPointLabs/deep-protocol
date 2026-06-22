using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.Abstractions;

namespace Deep.Protocol;

public static class ByteHelpers
{
    public static byte[] RequireSize(ReadOnlySpan<byte> value, int size, string name)
    {
        if (value.Length != size)
        {
            throw new ArgumentException($"{name} must be {size} bytes (was {value.Length}).", name);
        }

        return value.ToArray();
    }

    public static byte[] RequireSize(ReadOnlyMemory<byte> value, int size, string name) =>
        RequireSize(value.Span, size, name);

    public static byte[] RequireSize(ReadOnlySpan<byte> value, int sizeA, int sizeB, string name)
    {
        if (value.Length != sizeA && value.Length != sizeB)
        {
            throw new ArgumentException($"{name} must be {sizeA} or {sizeB} bytes (was {value.Length}).", name);
        }

        return value.ToArray();
    }

    public static byte[] UInt64LittleEndian(ulong value)
    {
        var bytes = new byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, value);
        return bytes;
    }

    public static byte[] UnixMillisecondsLittleEndian(DateTimeOffset value) =>
        UInt64LittleEndian((ulong)value.ToUnixTimeMilliseconds());

    public static byte[] HexToBytes(string hex) => Convert.FromHexString(hex);

    public static string ToLowerHex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    public static byte[] Latin1Bytes(string value) => Encoding.Latin1.GetBytes(value);
}
