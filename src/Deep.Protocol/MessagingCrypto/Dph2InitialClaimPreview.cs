using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.MessagingCrypto;

/// <summary>
/// AEAD-opened but not yet threshold-verified initial claim evidence. This is
/// not a handshake/session capability and cannot authorize persistence or ACK.
/// </summary>
public sealed class Dph2InitialClaimPreview
{
    private readonly Dph2PreClaimHeader _header;
    private readonly Xpk1Request _request;
    private readonly Xpc1Result _result;
    private int _promoted;

    internal Dph2InitialClaimPreview(
        Dph2PreClaimHeader header,
        Xpk1Request request,
        Xpc1Result result)
    {
        _header = header;
        _request = request;
        _result = result;
    }

    public Xpk1Request Request => _request;
    public Xpc1Result Result => _result;

    /// <summary>
    /// Verifies the exact AEAD-opened claim with current two-replica placement,
    /// recipient publication and trusted time before promoting DPH2. Neither
    /// this result nor the preview commits local state or authorizes an ACK.
    /// </summary>
    public async ValueTask<VerifiedDph2InitialClaim> VerifyCurrentAsync(
        VerifiedAccountDirectoryFreshness initiatorFreshness,
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority recipientAuthority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(initiatorFreshness);
        var claim = await Xpc1PreKeyClaimReceiptVerifier.VerifyAsync(
            _request, _result, placement, recipientAuthority, recipientBundle,
            trustedTimeAuthority, cancellationToken).ConfigureAwait(false);
        var reading = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken)
            .ConfigureAwait(false);
        var current = initiatorFreshness.CurrentCheckpoint;
        if (initiatorFreshness.ResultKind !=
                AccountDirectoryAdp1ResultKind.CurrentValue ||
            current is null ||
            !initiatorFreshness.IsCurrentAtMonotonic(
                reading.BootId.Span, reading.SampleSeconds) ||
            !Fixed(initiatorFreshness.NetworkId.Span,
                _header.Record.NetworkId.Span) ||
            !Fixed(current.Directory.Record.DeepAccountId.Span,
                _header.Record.InitiatorAccountId.Span) ||
            !Fixed(current.Directory.Record.RecordHash.Span,
                _header.InitiatorDirectoryHeadHash))
            throw new CryptographicException(
                "The DPH2 initiator directory is not the current verified account-directory value.");
        return new VerifiedDph2InitialClaim(
            claim, Promote(claim), current, recipientBundle);
    }

    // Narrow protocol tests may independently exercise the threshold verifier
    // with synthetic initiator directories. Production uses VerifyCurrentAsync.
#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal async ValueTask<VerifiedDph2InitialClaim> VerifyClaimForTestsAsync(
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority recipientAuthority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken = default)
    {
        var claim = await Xpc1PreKeyClaimReceiptVerifier.VerifyAsync(
            _request, _result, placement, recipientAuthority, recipientBundle,
            trustedTimeAuthority, cancellationToken).ConfigureAwait(false);
        return new VerifiedDph2InitialClaim(claim, Promote(claim), null, null);
    }
#endif

    /// <summary>
    /// Allows one promotion only after an independent authority verifies the
    /// exact decrypted XPK1/XPC1 pair. A receipt for a different padded wire
    /// result, even with matching projected fields, cannot be substituted.
    /// </summary>
    internal VerifiedDph2Initiation Promote(VerifiedXpc1PreKeyClaimReceipt verifiedClaim)
    {
        ArgumentNullException.ThrowIfNull(verifiedClaim);
        if (Interlocked.CompareExchange(ref _promoted, 1, 0) != 0)
            throw new InvalidOperationException("The initial claim preview is single-use.");
        var (xpk1, xpc1Wire) = verifiedClaim.CopyEncryptedInitialClaimTranscript();
        try
        {
            if (!Fixed(xpk1, _request.CanonicalBytes.Span) ||
                !Fixed(xpc1Wire, _result.WireBytes.Span))
                throw new CryptographicException(
                    "The verified XPC1 claim differs from the AEAD-opened DPH2 transcript.");
            return _header.Promote(verifiedClaim);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(xpk1);
            CryptographicOperations.ZeroMemory(xpc1Wire);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// Two mutually bound verifier-minted capabilities for the normal responder
/// reservation/handshake saga. A durable session and semantic inbox commit are
/// still required before any transport acknowledgement.
/// </summary>
public sealed class VerifiedDph2InitialClaim
{
    internal VerifiedDph2InitialClaim(
        VerifiedXpc1PreKeyClaimReceipt claim,
        VerifiedDph2Initiation initiation,
        VerifiedAccountDirectoryCheckpoint? initiatorCheckpoint,
        VerifiedContactBundleClosure? recipientBundle)
    {
        Claim = claim;
        Initiation = initiation;
        InitiatorCheckpoint = initiatorCheckpoint;
        RecipientBundle = recipientBundle;
    }

    public VerifiedXpc1PreKeyClaimReceipt Claim { get; }
    public VerifiedDph2Initiation Initiation { get; }
    /// <summary>The current initiator DAB1/DMD1 closure used at promotion.</summary>
    public VerifiedAccountDirectoryCheckpoint? InitiatorCheckpoint { get; }
    /// <summary>The exact recipient publication verified with XPC1.</summary>
    public VerifiedContactBundleClosure? RecipientBundle { get; }
}
