using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;

namespace Deep.Protocol.AccountDirectoryV1;

public static class AccountDirectoryCurrentValueClosureVerifier
{

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private sealed class LexicographicByteArrayComparer : IComparer<byte[]>
    {
        internal static LexicographicByteArrayComparer Instance { get; } = new();
        public int Compare(byte[]? x, byte[]? y) => x.AsSpan().SequenceCompareTo(y);
    }
}
