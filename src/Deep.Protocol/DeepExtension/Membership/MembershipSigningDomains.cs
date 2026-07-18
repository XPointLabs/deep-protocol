using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.Membership;

public static class MembershipContractHash
{
    public const int Sha256Length = 32;

    public static byte[] Sha256(ReadOnlySpan<byte> canonicalBytes) =>
        SHA256.HashData(canonicalBytes);
}

public static class MembershipSigningDomains
{
    public const int FixedTagLength = 16;

    public static ReadOnlyMemory<byte> GetFixedTag(MembershipSignatureDomain domain) =>
        domain switch
        {
            MembershipSignatureDomain.Update => "DEEP-UPD-V1\0\0\0\0\0"u8.ToArray(),
            MembershipSignatureDomain.Membership => "DEEP-MEM-V1\0\0\0\0\0"u8.ToArray(),
            MembershipSignatureDomain.Bridge => "DEEP-BRG-V1\0\0\0\0\0"u8.ToArray(),
            MembershipSignatureDomain.Reward => "DEEP-RWD-V1\0\0\0\0\0"u8.ToArray(),
            MembershipSignatureDomain.Billing => "DEEP-BIL-V1\0\0\0\0\0"u8.ToArray(),
            MembershipSignatureDomain.OfflineDelegation => "DEEP-DEL-V1\0\0\0\0\0"u8.ToArray(),
            MembershipSignatureDomain.OfflineRevocation => "DEEP-REV-V1\0\0\0\0\0"u8.ToArray(),
            MembershipSignatureDomain.Genesis => "DEEP-GEN-V1\0\0\0\0\0"u8.ToArray(),
            MembershipSignatureDomain.ForkWitness => "DEEP-FRK-V1\0\0\0\0\0"u8.ToArray(),
            _ => throw new MembershipContractException(
                MembershipContractError.InvalidEnum,
                "The signing domain has no approved fixed tag.")
        };

    public static byte[] Frame(
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> canonicalStatement)
    {
        var tag = GetFixedTag(domain);
        var framed = new byte[tag.Length + canonicalStatement.Length];
        tag.Span.CopyTo(framed);
        canonicalStatement.CopyTo(framed.AsSpan(tag.Length));
        return framed;
    }
}
