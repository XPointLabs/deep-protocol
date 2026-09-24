using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// A DCA1 V2 delegation promoted only by the exact current DID2 directory
/// checkpoint and its nonce-bound trusted-time interval. This does not by
/// itself authorize contact publication or a pre-key claim.
/// </summary>
public sealed class DeepIdV2CurrentContactAuthorization
{
    internal DeepIdV2CurrentContactAuthorization(VerifiedDca1V2 authorization,
        VerifiedDeepIdV2DirectoryFreshness freshness, ulong trustedLower,
        ulong trustedUpper)
    {
        Authorization = authorization;
        Freshness = freshness;
        TrustedLowerUnixSeconds = trustedLower;
        TrustedUpperUnixSeconds = trustedUpper;
    }

    public VerifiedDca1V2 Authorization { get; }
    public VerifiedDeepIdV2DirectoryFreshness Freshness { get; }
    public ulong TrustedLowerUnixSeconds { get; }
    public ulong TrustedUpperUnixSeconds { get; }
}

public static class DeepIdV2CurrentContactAuthorizationVerifier
{
    public static DeepIdV2CurrentContactAuthorization Verify(
        VerifiedDeepIdV2DirectoryFreshness freshness,
        VerifiedDca1V2 authorization, ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(freshness);
        ArgumentNullException.ThrowIfNull(authorization);
        if (freshness.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue)
            Fail("CurrentCheckpointRequired", "A current DID2 checkpoint is required.");
        var checkpoint = freshness.CurrentCheckpoint ??
            throw new AccountDirectoryFreshnessVerificationException(
                "CurrentCheckpointRequired", "A current DID2 checkpoint is required.");
        if (!freshness.IsCurrentAtMonotonic(currentBootId, currentMonotonicSample))
            Fail("DirectoryFreshnessExpired", "The DID2 directory proof is no longer current.");
        if (!CryptographicOperations.FixedTimeEquals(
                checkpoint.Binding.Record.CanonicalBytes.Span,
                authorization.Binding.Record.CanonicalBytes.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                checkpoint.Directory.Record.CanonicalBytes.Span,
                authorization.Directory.Record.CanonicalBytes.Span) ||
            !CryptographicOperations.FixedTimeEquals(freshness.NetworkId.Span,
                authorization.Record.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                freshness.QueriedDirectoryLeafKey.Span,
                checkpoint.Checkpoint.DirectoryLeafKey.Span))
            Fail("AuthorizationIdentityMismatch",
                "DCA1 V2 is not bound to the exact current DID2 directory identity.");
        if (checkpoint.IsDcaAuthorizationRevoked(
                authorization.Record.AuthorizationId.Span))
            Fail("AuthorizationRevoked", "DCA1 V2 is revoked in the current checkpoint.");

        ulong lower, upper;
        try
        {
            var elapsed = checked(currentMonotonicSample - freshness.MonotonicSample);
            lower = checked(freshness.TrustedLowerUnixSeconds + elapsed);
            upper = checked(freshness.TrustedUpperUnixSeconds + elapsed);
        }
        catch (OverflowException)
        {
            Fail("TrustedTimeInvalid", "The DID2 trusted-time interval overflowed.");
            throw;
        }
        if (authorization.Record.NotBeforeUnixSeconds > lower ||
            authorization.Record.ExpiresAtUnixSeconds <= upper)
            Fail("AuthorizationNotCurrent",
                "DCA1 V2 does not cover the complete authenticated time interval.");
        return new DeepIdV2CurrentContactAuthorization(
            authorization, freshness, lower, upper);
    }

    [DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new AccountDirectoryFreshnessVerificationException(code, message);
}
