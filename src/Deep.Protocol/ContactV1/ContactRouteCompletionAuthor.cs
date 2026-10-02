using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.ContactV1;

/// <summary>
/// Completes a threshold-authored route using only the same active device that
/// signed XRA1, then invokes the full route-closure verifier before returning.
/// </summary>
public static class ContactRouteCompletionAuthor
{

    private static byte[] RandomNonZero32()
    {
        var result = new byte[32];
        do RandomNumberGenerator.Fill(result);
        while (result.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return result;
    }

    private static byte[] PlaceholderSignature()
    {
        var result = new byte[64];
        result[^1] = 1;
        return result;
    }

    private static byte[] U16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    private static byte[] U32(uint value)
    {
        var result = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
