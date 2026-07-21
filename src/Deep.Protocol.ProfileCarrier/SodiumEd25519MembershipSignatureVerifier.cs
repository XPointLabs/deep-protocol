using Deep.Protocol.DeepExtension.Membership;
using Sodium;

namespace Deep.Protocol.DeepExtension.SelfHostedProfiles;

/// <summary>
/// Verifies P04 detached Ed25519 signatures without exposing signing or key
/// management capabilities.
/// </summary>
public sealed class SodiumEd25519MembershipSignatureVerifier
    : IMembershipSignatureVerifier
{
    private const int Ed25519PublicKeyLength = 32;
    private const int Ed25519SignatureLength = 64;

    private readonly IEd25519DetachedVerificationProvider provider;

    public SodiumEd25519MembershipSignatureVerifier()
        : this(SodiumEd25519DetachedVerificationProvider.Instance)
    {
    }

    internal SodiumEd25519MembershipSignatureVerifier(
        IEd25519DetachedVerificationProvider provider)
    {
        this.provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    public bool Verify(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature)
    {
        if (signerId.Length != MembershipLimits.SignerIdLength ||
            publicKey.Length != Ed25519PublicKeyLength ||
            signature.Length != Ed25519SignatureLength ||
            signingBytes.Length < MembershipSigningDomains.FixedTagLength)
        {
            return false;
        }

        try
        {
            var expectedTag = MembershipSigningDomains.GetFixedTag(domain);
            if (!signingBytes[..MembershipSigningDomains.FixedTagLength]
                    .SequenceEqual(expectedTag.Span))
            {
                return false;
            }

            return provider.VerifyDetached(
                signature.ToArray(),
                signingBytes.ToArray(),
                publicKey.ToArray());
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return false;
        }
    }
}

internal interface IEd25519DetachedVerificationProvider
{
    bool VerifyDetached(byte[] signature, byte[] message, byte[] publicKey);
}

internal sealed class SodiumEd25519DetachedVerificationProvider
    : IEd25519DetachedVerificationProvider
{
    public static SodiumEd25519DetachedVerificationProvider Instance { get; } = new();

    private SodiumEd25519DetachedVerificationProvider()
    {
    }

    public bool VerifyDetached(byte[] signature, byte[] message, byte[] publicKey) =>
        PublicKeyAuth.VerifyDetached(signature, message, publicKey);
}
