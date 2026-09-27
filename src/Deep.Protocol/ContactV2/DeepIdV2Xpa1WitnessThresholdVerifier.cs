using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Witness-threshold evidence for one exact XPA1 V2. This is not a current
/// directory, placement, publisher or durable publication capability.
/// </summary>
internal sealed class VerifiedXpa1V2WitnessThreshold
{
    private readonly byte[] exactXpa1;
    private readonly byte[] authorityCoreReference;
    private readonly byte[] witnessPolicyHash;

    internal VerifiedXpa1V2WitnessThreshold(ParsedXpa1V2 xpa1,
        VerifiedXPointNetworkAuthority authority)
    {
        exactXpa1 = xpa1.CanonicalBytes.ToArray();
        authorityCoreReference = authority.AuthorityCoreReference.ToArray();
        witnessPolicyHash = authority.DirectoryWitnessPolicyHash.ToArray();
    }

    public ReadOnlyMemory<byte> ExactXpa1 => exactXpa1.ToArray();
    public ReadOnlyMemory<byte> AuthorityCoreReference =>
        authorityCoreReference.ToArray();
    public ReadOnlyMemory<byte> WitnessPolicyHash => witnessPolicyHash.ToArray();
}

internal static class DeepIdV2Xpa1WitnessThresholdVerifier
{
    public static bool RuntimeActivation => false;

    public static VerifiedXpa1V2WitnessThreshold Verify(ParsedXpa1V2 xpa1,
        VerifiedXPointNetworkAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(xpa1);
        ArgumentNullException.ThrowIfNull(authority);
        if (!Fixed(xpa1.Field(1).Span, authority.NetworkId.Span) ||
            xpa1.Field(20).Span[0] < authority.WitnessThreshold)
            throw new CryptographicException(
                "XPA1 V2 network or witness threshold differs from current XNA1.");

        var keys = authority.WitnessKeys.ToDictionary(
            static key => Convert.ToHexString(key.Id.Span),
            StringComparer.Ordinal);
        var rows = xpa1.Field(21).ToArray();
        var signingInput = xpa1.WitnessSigningInput.ToArray();
        var failureDomains = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            for (var offset = 0; offset < rows.Length; offset += 96)
            {
                var row = rows.AsSpan(offset, 96);
                if (!keys.TryGetValue(Convert.ToHexString(row[..32]), out var key))
                    throw new CryptographicException(
                        "XPA1 V2 names an unknown directory witness.");
                bool verified;
                try
                {
                    verified = PublicKeyAuth.VerifyDetached(
                        row[32..].ToArray(), signingInput,
                        key.Ed25519PublicKey.ToArray());
                }
                catch (Exception exception) when (exception is ArgumentException or
                    CryptographicException)
                {
                    throw new CryptographicException(
                        "XPA1 V2 witness signature is invalid.", exception);
                }
                if (!verified)
                    throw new CryptographicException(
                        "XPA1 V2 witness signature is invalid.");
                failureDomains.Add(Convert.ToHexString(
                    key.FailureDomainHash.Span));
            }
            if (failureDomains.Count < authority.WitnessThreshold)
                throw new CryptographicException(
                    "XPA1 V2 lacks distinct witness failure domains.");
            return new VerifiedXpa1V2WitnessThreshold(xpa1, authority);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rows);
            CryptographicOperations.ZeroMemory(signingInput);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
