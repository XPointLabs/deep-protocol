using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.DeepNative;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV1;

public sealed class ContactNetworkAuthorityVerificationException : CryptographicException
{
    internal ContactNetworkAuthorityVerificationException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Mints the Contact route-authority capability only from already verified
/// Protocol capabilities and their exact current XPoint/directory bytes.
/// </summary>
public static class ContactNetworkAuthorityVerifier
{
}
