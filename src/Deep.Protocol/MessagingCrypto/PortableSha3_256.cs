using System.Numerics;
using System.Security.Cryptography;

namespace Deep.Protocol.MessagingCrypto;

/// <summary>
/// Portable SHA3-256 for protocol inputs on runtimes whose platform crypto
/// provider does not expose SHA-3 (notably older Android releases).
/// </summary>
internal static class PortableSha3_256
{
    private const int RateBytes = 136;

    private static ReadOnlySpan<ulong> RoundConstants =>
    [
        0x0000000000000001UL, 0x0000000000008082UL,
        0x800000000000808aUL, 0x8000000080008000UL,
        0x000000000000808bUL, 0x0000000080000001UL,
        0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008aUL, 0x0000000000000088UL,
        0x0000000080008009UL, 0x000000008000000aUL,
        0x000000008000808bUL, 0x800000000000008bUL,
        0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL,
        0x000000000000800aUL, 0x800000008000000aUL,
        0x8000000080008081UL, 0x8000000000008080UL,
        0x0000000080000001UL, 0x8000000080008008UL,
    ];

    private static ReadOnlySpan<byte> RotationOffsets =>
    [
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    ];

    internal static byte[] HashConcat(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        Span<ulong> state = stackalloc ulong[25];
        var position = 0;
        try
        {
            Absorb(first, state, ref position);
            Absorb(second, state, ref position);
            XorByte(state, position, 0x06);
            XorByte(state, RateBytes - 1, 0x80);
            Permute(state);

            var output = new byte[32];
            for (var index = 0; index < output.Length; index++)
                output[index] = (byte)(state[index >> 3] >> ((index & 7) * 8));
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(state));
        }
    }

    private static void Absorb(ReadOnlySpan<byte> input, Span<ulong> state, ref int position)
    {
        foreach (var value in input)
        {
            XorByte(state, position, value);
            position++;
            if (position != RateBytes) continue;
            Permute(state);
            position = 0;
        }
    }

    private static void XorByte(Span<ulong> state, int position, byte value) =>
        state[position >> 3] ^= (ulong)value << ((position & 7) * 8);

    private static void Permute(Span<ulong> state)
    {
        Span<ulong> columns = stackalloc ulong[5];
        Span<ulong> deltas = stackalloc ulong[5];
        Span<ulong> moved = stackalloc ulong[25];
        try
        {
            foreach (var roundConstant in RoundConstants)
            {
                for (var x = 0; x < 5; x++)
                    columns[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^
                                 state[x + 15] ^ state[x + 20];
                for (var x = 0; x < 5; x++)
                    deltas[x] = columns[(x + 4) % 5] ^
                                BitOperations.RotateLeft(columns[(x + 1) % 5], 1);
                for (var y = 0; y < 5; y++)
                for (var x = 0; x < 5; x++)
                    state[x + 5 * y] ^= deltas[x];

                for (var y = 0; y < 5; y++)
                for (var x = 0; x < 5; x++)
                {
                    var source = x + 5 * y;
                    var destination = y + 5 * ((2 * x + 3 * y) % 5);
                    moved[destination] = BitOperations.RotateLeft(
                        state[source], RotationOffsets[source]);
                }

                for (var y = 0; y < 5; y++)
                for (var x = 0; x < 5; x++)
                    state[x + 5 * y] = moved[x + 5 * y] ^
                        (~moved[(x + 1) % 5 + 5 * y] & moved[(x + 2) % 5 + 5 * y]);
                state[0] ^= roundConstant;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(columns));
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(deltas));
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(moved));
        }
    }
}
