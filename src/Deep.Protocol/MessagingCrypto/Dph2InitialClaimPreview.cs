using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV2;
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
    private readonly ParsedXpk1V2 _request;
    private readonly ParsedXpc1V2 _result;
    private int _promoted;

    internal Dph2InitialClaimPreview(
        Dph2PreClaimHeader header,
        ParsedXpk1V2 request,
        ParsedXpc1V2 result)
    {
        _header = header;
        _request = request;
        _result = result;
    }

    public ParsedXpk1V2 Request => _request;
    public ParsedXpc1V2 Result => _result;

    /// <summary>Promotes only the exact AEAD-opened V2 claim after current
    /// initiator/device and recipient verification. This does not commit
    /// prekeys, ratchet state, semantic inbox or transport acknowledgement.</summary>
    public async ValueTask<VerifiedDph2InitialClaim> VerifyCurrentAsync(
        VerifiedContactServicePlacement placement,
        DeepIdV2CurrentContactAuthorization recipientAuthorization,
        ParsedDcr1V2 recipientClosure,
        VerifiedDeepIdV2DirectoryFreshness initiatorFreshness,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(placement);
        ArgumentNullException.ThrowIfNull(recipientAuthorization);
        ArgumentNullException.ThrowIfNull(recipientClosure);
        ArgumentNullException.ThrowIfNull(initiatorFreshness);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        cancellationToken.ThrowIfCancellationRequested();
        _ = await VerifyCurrentInitiatorAsync(initiatorFreshness,
            trustedTimeAuthority, cancellationToken).ConfigureAwait(false);
        var claim = await DeepIdV2PreKeyClaimReceiptVerifier.VerifyAsync(
            _request, _result, placement, recipientAuthorization, recipientClosure,
            trustedTimeAuthority, cancellationToken).ConfigureAwait(false);
        var reading = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var checkpoint = RequireCurrentInitiator(_header.Record,
            _header.InitiatorDirectoryHeadHash, initiatorFreshness,
            reading.BootId.Span, reading.SampleSeconds);
        claim.RequireCurrentAt(reading);
        placement.Network.EnsureCurrent();
        cancellationToken.ThrowIfCancellationRequested();
        return new VerifiedDph2InitialClaim(claim, Promote(claim), checkpoint,
            recipientClosure);
    }

    /// <summary>
    /// Checks only the DID2 initiator side of an initial claim against a
    /// current, nonce-bound V2 directory proof. This deliberately cannot
    /// promote a session: current-recipient and exact V2 receipt verification
    /// are independent requirements of VerifyCurrentAsync.
    /// </summary>
    internal async ValueTask<VerifiedAdc1V2> VerifyCurrentInitiatorAsync(
        VerifiedDeepIdV2DirectoryFreshness initiatorFreshness,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(initiatorFreshness);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        var reading = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return RequireCurrentInitiator(_header.Record, _header.InitiatorDirectoryHeadHash,
            initiatorFreshness, reading.BootId.Span, reading.SampleSeconds);
    }

    // This DID2-only check can be shared with the V2 promotion cutover. It
    // grants no session and takes no V1 recipient/request/result or callback.
    internal static VerifiedAdc1V2 RequireCurrentInitiator(Dph2Record record,
        ReadOnlySpan<byte> initiatorDirectoryHeadHash,
        VerifiedDeepIdV2DirectoryFreshness initiatorFreshness,
        ReadOnlySpan<byte> currentBootId, ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(record);
        return RequireCurrentInitiatorCore(record.NetworkId.Span, record.InitiatorAccountId.Span,
            record.InitiatorDeviceId.Span, record.InitiatorDeviceGeneration, record.InitiatorDpd1Ref.Span,
            record.InitiatorDid2.Span, record.InitiatorDeviceAgreementPublicKey.Span,
            initiatorDirectoryHeadHash, initiatorFreshness, currentBootId, currentMonotonicSample);
    }

    internal static VerifiedAdc1V2 RequireCurrentInitiatorCore(ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId, ReadOnlySpan<byte> deviceId, ulong deviceGeneration,
        ReadOnlySpan<byte> dpdReference, ReadOnlySpan<byte> exactDid2, ReadOnlySpan<byte> agreementPublic,
        ReadOnlySpan<byte> initiatorDirectoryHeadHash, VerifiedDeepIdV2DirectoryFreshness initiatorFreshness,
        ReadOnlySpan<byte> currentBootId, ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(initiatorFreshness);
        var current = initiatorFreshness.CurrentCheckpoint;
        if (initiatorFreshness.ResultKind !=
                AccountDirectoryAdp1ResultKind.CurrentValue ||
            current is null ||
            !initiatorFreshness.IsCurrentAtMonotonic(
                currentBootId, currentMonotonicSample) ||
            !Fixed(initiatorFreshness.NetworkId.Span,
                networkId) ||
            !Fixed(current.Directory.Record.DeepAccountId.Span,
                accountId) ||
            !Fixed(current.Directory.Record.RecordHash.Span,
                initiatorDirectoryHeadHash) ||
            !Fixed(current.Binding.DeepId.CanonicalBytes.Span,
                exactDid2))
            throw new CryptographicException(
                "The DPH2 initiator directory is not the current verified account-directory value.");
        ulong lower, upper;
        try
        {
            var elapsed = checked(currentMonotonicSample - initiatorFreshness.MonotonicSample);
            lower = checked(initiatorFreshness.TrustedLowerUnixSeconds + elapsed);
            upper = checked(initiatorFreshness.TrustedUpperUnixSeconds + elapsed);
        }
        catch (OverflowException exception)
        {
            throw new CryptographicException("The DPH2 initiator time interval overflowed.", exception);
        }
        var selectedDeviceId = deviceId.ToArray();
        var entry = current.Directory.Record.ActiveDevices.SingleOrDefault(device =>
            Fixed(device.DeviceId.Span, selectedDeviceId));
        var device = current.Binding.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.Certificate.DeviceId.Span, selectedDeviceId));
        if (entry is null || device is null || lower > upper ||
            device.Certificate.DeviceGeneration != deviceGeneration ||
            device.Certificate.IssuedAtUnixSeconds > lower ||
            device.Certificate.ExpiresAtUnixSeconds <= upper ||
            !Fixed(entry.Dpd1Reference.CanonicalBytes.Span, dpdReference) ||
            !Fixed(entry.Dpd1Reference.CanonicalHash.Span, device.Certificate.CanonicalHash.Span) ||
            !Fixed(device.Certificate.DeviceX25519PublicKey.Span,
                agreementPublic))
            throw new CryptographicException(
                "The DPH2 initiator is not the exact current DID2 device for the complete time interval.");
        return current;
    }

    /// <summary>
    /// Allows one promotion only after an independent authority verifies the
    /// exact decrypted XPK1/XPC1 pair. A receipt for a different padded wire
    /// result, even with matching projected fields, cannot be substituted.
    /// </summary>
    private VerifiedDph2Initiation Promote(VerifiedXpc1V2PreKeyClaimReceipt verifiedClaim)
    {
        ArgumentNullException.ThrowIfNull(verifiedClaim);
        if (Interlocked.CompareExchange(ref _promoted, 1, 0) != 0)
            throw new InvalidOperationException("The initial claim preview is single-use.");
        var (xpk1, xpc1Wire) = verifiedClaim.CopyEncryptedInitialClaimTranscript(_header.Record);
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
    private int _bound;

    internal VerifiedDph2InitialClaim(
        VerifiedXpc1V2PreKeyClaimReceipt claim,
        VerifiedDph2Initiation initiation,
        VerifiedAdc1V2 initiatorCheckpoint,
        ParsedDcr1V2 recipientClosure)
    {
        Claim = claim ?? throw new ArgumentNullException(nameof(claim));
        Initiation = initiation ?? throw new ArgumentNullException(nameof(initiation));
        InitiatorCheckpoint = initiatorCheckpoint ?? throw new ArgumentNullException(nameof(initiatorCheckpoint));
        RecipientClosure = recipientClosure ?? throw new ArgumentNullException(nameof(recipientClosure));
    }

    public VerifiedXpc1V2PreKeyClaimReceipt Claim { get; }
    public VerifiedDph2Initiation Initiation { get; }
    /// <summary>The current initiator DID2/DAB2/ADC1 V2/DMD1 closure used at promotion.</summary>
    public VerifiedAdc1V2 InitiatorCheckpoint { get; }
    /// <summary>The exact recipient publication verified with XPC1.</summary>
    public ParsedDcr1V2 RecipientClosure { get; }

    /// <summary>Transfers two independent, single-use claim lanes only after
    /// current V2 promotion. This still grants no durable session or ACK.</summary>
    public VerifiedInitialSessionPreKeyClaim BindForInitialSession()
    {
        if (Interlocked.CompareExchange(ref _bound, 1, 0) != 0)
            throw new InvalidOperationException("The verified initial claim is single-use.");
        Claim.RequireMatchesDph2Header(Initiation.Record);
        var offering = Claim.Offering.Record;
        return new VerifiedInitialSessionPreKeyClaim(offering.MlKemKind,
            Claim.LastResortUseCounter, Claim.OperationId.Span,
            Initiation.SessionId.Span, Claim.ExactDpk2Hash.Span,
            Claim.ExactReplayHash.Span, Initiation.FullReplayHash.Span,
            offering.MlKemKind == Dpk2PrekeyKind.OneTime
                ? offering.OneTimeX25519PrekeyId.Span : [],
            offering.MlKemPrekeyId.Span, Initiation);
    }
}
