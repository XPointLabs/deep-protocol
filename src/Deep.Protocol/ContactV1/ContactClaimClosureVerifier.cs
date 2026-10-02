using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.ContactV1;

public sealed class ContactClaimClosureException : CryptographicException
{
    internal ContactClaimClosureException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Production bridge from an exact XIS1 one-time claim to application-owned
/// identity capabilities. No caller-authored DXP receipt or raw key can enter
/// this promotion path.
/// </summary>
public static class ContactClaimClosureVerifier
{

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new ContactClaimClosureException(code, message);
}
