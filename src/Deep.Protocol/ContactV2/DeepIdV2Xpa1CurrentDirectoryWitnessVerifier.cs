using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// The exact V2 witness threshold bound to a live DID2 directory head and
/// nonce-bound trusted interval. This is not publication/placement authority.
/// </summary>
internal sealed class VerifiedXpa1V2CurrentDirectoryWitness
{
    private readonly byte[] exactXpu1;
    private readonly byte[] exactXpa1;
    private readonly byte[] directoryHeadHash;

    internal VerifiedXpa1V2CurrentDirectoryWitness(ParsedXpu1V2 request,
        VerifiedDeepIdV2DirectoryFreshness freshness)
    {
        exactXpu1 = request.CanonicalBytes.ToArray();
        exactXpa1 = request.Authorization.CanonicalBytes.ToArray();
        directoryHeadHash = freshness.NextProtectedLkg.CoreHash.ToArray();
    }

    public ReadOnlyMemory<byte> ExactXpu1 => exactXpu1.ToArray();
    public ReadOnlyMemory<byte> ExactXpa1 => exactXpa1.ToArray();
    public ReadOnlyMemory<byte> DirectoryHeadHash => directoryHeadHash.ToArray();
}

internal static class DeepIdV2Xpa1CurrentDirectoryWitnessVerifier
{
    private const ulong MaximumAuthorizationLifetimeSeconds = 86_400;
    public static bool RuntimeActivation => false;

    public static VerifiedXpa1V2CurrentDirectoryWitness Verify(
        ParsedXpu1V2 request, VerifiedXPointNetworkAuthority authority,
        VerifiedDeepIdV2DirectoryFreshness freshness,
        ReadOnlySpan<byte> currentBootId, ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(freshness);
        var xpa = request.Authorization;
        if (!Fixed(request.Field(1).Span, authority.NetworkId.Span) ||
            !Fixed(request.Field(1).Span, freshness.NetworkId.Span) ||
            !Fixed(xpa.Field(1).Span, freshness.NetworkId.Span) ||
            !freshness.IsCurrentAtMonotonic(currentBootId,
                currentMonotonicSample))
            Fail("XPA1 V2 network or DID2 freshness is not current.");

        var head = AccountDirectoryAdh1Codec.Decode(freshness.ExactAdh1.Span);
        var dtt = AccountDirectoryDtt1Codec.Decode(freshness.ExactDtt1.Span);
        var headHash = freshness.NextProtectedLkg.CoreHash.Span;
        if (!Fixed(head.NetworkId.Span, freshness.NetworkId.Span) ||
            !Fixed(dtt.NetworkId.Span, freshness.NetworkId.Span) ||
            !Fixed(head.ExactXnaAuthorityCoreReference.Span,
                authority.AuthorityCoreReference.Span) ||
            !Fixed(dtt.AuthorizingXna1CoreReference.Span,
                authority.AuthorityCoreReference.Span) ||
            !Fixed(head.WitnessPolicyHash.Span,
                authority.DirectoryWitnessPolicyHash.Span) ||
            !Fixed(dtt.WitnessPolicyHash.Span,
                authority.DirectoryWitnessPolicyHash.Span) ||
            !Fixed(dtt.CurrentAdh1CoreHash.Span, headHash) ||
            dtt.CurrentAdh1Generation != head.LogGeneration ||
            !Fixed(xpa.Field(18).Span, headHash) ||
            !Fixed(dtt.CurrentXnv1CoreHash.Span, request.Field(3).Span))
            Fail("XPA1 V2 is not bound to the exact current XNA1/ADH1/DTT1 view.");

        ulong lower, upper;
        try
        {
            var elapsed = checked(currentMonotonicSample - freshness.MonotonicSample);
            lower = checked(freshness.TrustedLowerUnixSeconds + elapsed);
            upper = checked(freshness.TrustedUpperUnixSeconds + elapsed);
        }
        catch (OverflowException exception)
        {
            throw new CryptographicException(
                "XPA1 V2 trusted-time projection overflowed.", exception);
        }
        var issued = U64(xpa.Field(15).Span);
        var notBefore = U64(xpa.Field(16).Span);
        var expires = U64(xpa.Field(17).Span);
        var effectiveExpires = U64(xpa.Field(13).Span);
        var requestIssued = U64(request.Field(5).Span);
        var requestExpires = U64(request.Field(6).Span);
        if (expires - issued > MaximumAuthorizationLifetimeSeconds ||
            issued > lower || notBefore > lower || upper >= expires ||
            requestIssued < issued || requestIssued > lower ||
            upper >= requestExpires || requestExpires > expires ||
            expires > effectiveExpires ||
            head.ValidFrom > lower || upper >= head.ValidUntil ||
            expires > head.ValidUntil ||
            authority.NotBefore > lower || upper >= authority.ExpiresAt ||
            expires > authority.ExpiresAt)
            Fail("XPA1 V2 does not cover the complete current trusted interval.");

        DeepIdV2Xpa1WitnessThresholdVerifier.Verify(xpa, authority);
        return new VerifiedXpa1V2CurrentDirectoryWitness(request, freshness);
    }

    private static ulong U64(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt64BigEndian(value);
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
    private static void Fail(string message) =>
        throw new CryptographicException(message);
}
