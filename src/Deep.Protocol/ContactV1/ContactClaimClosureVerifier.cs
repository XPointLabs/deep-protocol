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
/// Non-forgeable result that closes one exact, replica-authenticated XIS1
/// one-time claim over its authenticated DIA1 ciphertext, current directory
/// checkpoint, DCA1 authority and DCR1 publisher device.
/// </summary>
public sealed class VerifiedContactClaimClosure
{
    internal VerifiedContactClaimClosure(
        VerifiedXis1InviteClaimReceipt claim,
        VerifiedContactBundleClosure contact,
        VerifiedDevice publisherDevice)
    {
        Claim = claim;
        Contact = contact;
        PublisherDevice = publisherDevice;
    }

    public VerifiedXis1InviteClaimReceipt Claim { get; }
    public VerifiedContactBundleClosure Contact { get; }
    public CurrentlyAuthoritativeDca1 Authorization => Contact.Authorization;
    public VerifiedDevice PublisherDevice { get; }
    public ReadOnlyMemory<byte> ExactDcr1 => Contact.ResolverResponse.CanonicalBytes;
}

/// <summary>
/// Production bridge from an exact XIS1 one-time claim to application-owned
/// identity capabilities. No caller-authored DXP receipt or raw key can enter
/// this promotion path.
/// </summary>
public static class ContactClaimClosureVerifier
{
    public static VerifiedContactClaimClosure VerifyOneTimeClaim(
        VerifiedXis1InviteClaimReceipt claim,
        ContactRecord exactDia1,
        VerifiedAccountDirectoryFreshness freshness,
        ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(claim);
        ArgumentNullException.ThrowIfNull(exactDia1);
        ArgumentNullException.ThrowIfNull(freshness);

        try
        {
            if (!StringComparer.Ordinal.Equals(exactDia1.Magic, ProtocolMagic.DIA1))
                Fail("ExactDia1Required", "The claim closure requires one exact canonical DIA1 record.");
            if (!Fixed(claim.NetworkId.Span, exactDia1.Field(1).Span) ||
                !Fixed(claim.NetworkId.Span, freshness.NetworkId.Span))
                Fail("NetworkMismatch", "XIS1, DIA1 and directory freshness do not bind the same network.");
            if (!freshness.IsCurrentAtMonotonic(currentBootId, currentMonotonicSample))
                Fail("DirectoryFreshnessExpired", "The account-directory proof is not current at the supplied monotonic sample.");
            if (claim.ServerTimeUnixSeconds < freshness.TrustedLowerUnixSeconds ||
                claim.ServerTimeUnixSeconds > freshness.TrustedUpperUnixSeconds)
                Fail("ClaimTimeOutsideDirectoryProof", "The signed XIS1 server time is outside the account-directory trusted interval.");
            if (BinaryPrimitives.ReadUInt64BigEndian(exactDia1.Field(8).Span) <= claim.ServerTimeUnixSeconds)
                Fail("InvitationExpired", "DIA1 was expired at the signed XIS1 claim instant.");

            var checkpoint = freshness.CurrentCheckpoint;
            if (freshness.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue || checkpoint is null)
                Fail("CurrentDirectoryCheckpointRequired", "The claim requires an exact current ADC1 checkpoint.");

            var dcr1 = Dcr1ObjectProtectionCodec.OpenOneTime(claim.ObjectCiphertext.Span, exactDia1);
            var bundleHash = SHA256.HashData(dcr1.Field(2).Span);
            try
            {
                if (!Fixed(bundleHash, exactDia1.Field(7).Span))
                    Fail("InvitationBundleMismatch", "The authenticated DCR1 bundle is not the bundle committed by DIA1.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bundleHash);
            }

            var bundle = ContactCodec.Decode(ProtocolMagic.DCB1, dcr1.Field(2).Span);
            var dca1 = ApplicationCoreCodec.DecodeDca1(bundle.Field(6).Span);
            var verifiedDca1 = ApplicationCoreVerifier.VerifyDca1(
                dca1, checkpoint.Binding, checkpoint.Directory);
            var authorization = ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(
                verifiedDca1, claim.ServerTimeUnixSeconds);
            var contact = ContactCodec.VerifyDcr1Closure(
                dcr1, authorization, freshness, currentBootId, currentMonotonicSample);

            var publisherId = contact.Bundle.Field(10);
            var publisher = contact.Directory.Identity.ActiveDevices.SingleOrDefault(device =>
                Fixed(device.Certificate.DeviceId.Span, publisherId.Span));
            if (publisher is null)
                Fail("PublisherDeviceMissing", "The exact DCR1 publisher is not an active verified directory device.");

            return new VerifiedContactClaimClosure(claim, contact, publisher);
        }
        catch (ContactClaimClosureException)
        {
            throw;
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or CryptographicException)
        {
            throw new ContactClaimClosureException(
                "ClaimClosureRejected", "The exact XIS1/DIA1/DCR1 identity closure was rejected.", exception);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new ContactClaimClosureException(code, message);
}
