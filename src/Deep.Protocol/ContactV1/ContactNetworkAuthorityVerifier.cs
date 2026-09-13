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
    public static ValueTask<VerifiedContactRouteProposalAuthority> VerifyProposalAsync(
        VerifiedXPointNetworkAuthority authority,
        VerifiedOnionNetworkContext currentNetwork,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedDevice recipientDevice,
        CurrentlyAuthoritativeDca1 recipientAuthorization,
        ReadOnlyMemory<byte> exactXnv1,
        ReadOnlyMemory<byte> exactXnh1,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactPmt2,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken) =>
        VerifiedContactNetworkAuthority.VerifyProposalAsync(
            authority, currentNetwork, freshness, recipientDevice, recipientAuthorization,
            exactXnv1, exactXnh1, exactAdh1, exactPmt2,
            trustedTimeAuthority, cancellationToken);

    public static ValueTask<VerifiedContactNetworkAuthority> BindSelectionAsync(
        VerifiedContactRouteProposalAuthority proposal,
        ReadOnlyMemory<byte> exactPms2,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proposal);
        return proposal.BindSelectionAsync(exactPms2, cancellationToken);
    }

    public static ValueTask<VerifiedContactNetworkAuthority> VerifyAsync(
        VerifiedXPointNetworkAuthority authority,
        VerifiedOnionNetworkContext currentNetwork,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedDevice recipientDevice,
        CurrentlyAuthoritativeDca1 recipientAuthorization,
        ReadOnlyMemory<byte> exactXnv1,
        ReadOnlyMemory<byte> exactXnh1,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactPmt2,
        ReadOnlyMemory<byte> exactPms2,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken) =>
        VerifiedContactNetworkAuthority.VerifyAsync(
            authority, currentNetwork, freshness, recipientDevice, recipientAuthorization,
            exactXnv1, exactXnh1, exactAdh1, exactPmt2, exactPms2,
            trustedTimeAuthority, cancellationToken);
}

/// <summary>
/// Non-forgeable current account/device/network capability used only to author
/// the device-signed XRA1 proposal. It contains no route selection or replica
/// authority; exact PMS2 must subsequently be threshold-bound.
/// </summary>
public sealed class VerifiedContactRouteProposalAuthority
{
    private readonly byte[] networkId;
    private readonly byte[] pmt2ArtifactReference;
    private readonly byte[] xnv1CoreReference;
    private readonly byte[] xnh1CoreReference;
    private readonly byte[] adh1CoreReference;
    private readonly byte[] recipientDeviceId;
    private readonly byte[] recipientDevicePublicKey;
    private readonly byte[] recipientAccountId;
    private readonly byte[] recipientDpd1Reference;
    private readonly byte[] dca1Reference;
    private readonly VerifiedXPointNetworkAuthority authority;
    private readonly VerifiedOnionNetworkContext currentNetwork;
    private readonly VerifiedAccountDirectoryFreshness freshness;
    private readonly VerifiedDevice recipientDevice;
    private readonly CurrentlyAuthoritativeDca1 recipientAuthorization;
    private readonly byte[] exactXnv1;
    private readonly byte[] exactXnh1;
    private readonly byte[] exactAdh1;
    private readonly byte[] exactPmt2;
    private readonly OnionTrustedTimeAuthority trustedTimeAuthority;

    internal VerifiedContactRouteProposalAuthority(
        VerifiedXPointNetworkAuthority authority,
        VerifiedOnionNetworkContext currentNetwork,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedDevice recipientDevice,
        CurrentlyAuthoritativeDca1 recipientAuthorization,
        ReadOnlySpan<byte> exactXnv1,
        ReadOnlySpan<byte> exactXnh1,
        ReadOnlySpan<byte> exactAdh1,
        ReadOnlySpan<byte> exactPmt2,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        ReadOnlySpan<byte> pmt2ArtifactReference,
        ReadOnlySpan<byte> xnv1CoreReference,
        ReadOnlySpan<byte> xnh1CoreReference,
        ReadOnlySpan<byte> adh1CoreReference,
        ReadOnlySpan<byte> recipientDpd1Reference,
        ReadOnlySpan<byte> dca1Reference,
        ulong trustedLowerUnixSeconds,
        ulong trustedUpperUnixSeconds,
        ulong notBeforeUnixSeconds,
        ulong expiresAtUnixSeconds)
    {
        this.authority = authority;
        this.currentNetwork = currentNetwork;
        this.freshness = freshness;
        this.recipientDevice = recipientDevice;
        this.recipientAuthorization = recipientAuthorization;
        this.exactXnv1 = exactXnv1.ToArray();
        this.exactXnh1 = exactXnh1.ToArray();
        this.exactAdh1 = exactAdh1.ToArray();
        this.exactPmt2 = exactPmt2.ToArray();
        this.trustedTimeAuthority = trustedTimeAuthority;
        networkId = authority.NetworkId.ToArray();
        this.pmt2ArtifactReference = pmt2ArtifactReference.ToArray();
        this.xnv1CoreReference = xnv1CoreReference.ToArray();
        this.xnh1CoreReference = xnh1CoreReference.ToArray();
        this.adh1CoreReference = adh1CoreReference.ToArray();
        recipientDeviceId = recipientDevice.Certificate.DeviceId.ToArray();
        recipientDevicePublicKey = recipientDevice.Certificate.DeviceEd25519PublicKey.ToArray();
        recipientAccountId = recipientDevice.Certificate.AccountHash.ToArray();
        this.recipientDpd1Reference = recipientDpd1Reference.ToArray();
        this.dca1Reference = dca1Reference.ToArray();
        TrustedLowerUnixSeconds = trustedLowerUnixSeconds;
        TrustedUpperUnixSeconds = trustedUpperUnixSeconds;
        NotBeforeUnixSeconds = notBeforeUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> Pmt2ArtifactReference => pmt2ArtifactReference.ToArray();
    public ReadOnlyMemory<byte> Xnv1CoreReference => xnv1CoreReference.ToArray();
    public ReadOnlyMemory<byte> Xnh1CoreReference => xnh1CoreReference.ToArray();
    public ReadOnlyMemory<byte> Adh1CoreReference => adh1CoreReference.ToArray();
    public ReadOnlyMemory<byte> RecipientDeviceId => recipientDeviceId.ToArray();
    public ReadOnlyMemory<byte> RecipientDevicePublicKey => recipientDevicePublicKey.ToArray();
    public ReadOnlyMemory<byte> RecipientDpd1Reference => recipientDpd1Reference.ToArray();
    public ReadOnlyMemory<byte> Dca1Reference => dca1Reference.ToArray();
    public ulong TrustedLowerUnixSeconds { get; }
    public ulong TrustedUpperUnixSeconds { get; }
    public ulong NotBeforeUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }

    internal ReadOnlySpan<byte> RecipientAccountIdSpan => recipientAccountId;
    internal VerifiedXPointNetworkAuthority NetworkAuthority => authority;
    internal ReadOnlySpan<byte> ExactPmt2Span => exactPmt2;

    internal ValueTask<VerifiedContactNetworkAuthority> BindSelectionAsync(
        ReadOnlyMemory<byte> exactPms2,
        CancellationToken cancellationToken) =>
        VerifiedContactNetworkAuthority.VerifyAsync(
            authority, currentNetwork, freshness, recipientDevice, recipientAuthorization,
            exactXnv1, exactXnh1, exactAdh1, exactPmt2, exactPms2,
            trustedTimeAuthority, cancellationToken);
}

public sealed partial class VerifiedContactNetworkAuthority
{
    private const int MaximumRecordBytes = 65_535;
    private readonly byte[] networkId;
    private readonly byte[] authorityCoreReference;
    private readonly byte[] witnessPolicyHash;
    private readonly byte[] xnv1CoreReference;
    private readonly byte[] xnh1CoreReference;
    private readonly byte[] adh1CoreReference;
    private readonly byte[] pmt2ArtifactReference;
    private readonly byte[] pms2ArtifactHash;
    private readonly byte[] recipientDeviceId;
    private readonly byte[] recipientAccountId;
    private readonly byte[] recipientDpd1Reference;
    private readonly byte[] recipientDevicePublicKey;
    private readonly byte[] recipientDeviceAgreementPublicKey;
    private readonly byte[] recipientDmd1Hash;
    private readonly byte[] recipientDrs1Reference;
    private readonly byte[] dca1Reference;
    private readonly byte[] monotonicBootId;
    private readonly Dictionary<string, WitnessMaterial> witnessKeys;

    private VerifiedContactNetworkAuthority(
        VerifiedXPointNetworkAuthority authority,
        ReadOnlySpan<byte> xnv1Reference,
        ReadOnlySpan<byte> xnh1Reference,
        ReadOnlySpan<byte> adh1Reference,
        ReadOnlySpan<byte> pmt2Reference,
        ReadOnlySpan<byte> pms2Hash,
        DeviceCertificate recipient,
        CurrentlyAuthoritativeDca1 recipientAuthorization,
        ReadOnlySpan<byte> dpd1Reference,
        ReadOnlySpan<byte> dca1Reference,
        ulong trustedLowerUnixSeconds,
        ulong trustedUpperUnixSeconds,
        ulong notBeforeUnixSeconds,
        ulong expiresAtUnixSeconds,
        OnionMonotonicReading monotonic,
        ulong freshnessDeadlineMonotonicSeconds)
    {
        networkId = authority.NetworkId.ToArray();
        authorityCoreReference = authority.AuthorityCoreReference.ToArray();
        witnessPolicyHash = authority.DirectoryWitnessPolicyHash.ToArray();
        AuthorityGeneration = authority.AuthorityGeneration;
        xnv1CoreReference = xnv1Reference.ToArray();
        xnh1CoreReference = xnh1Reference.ToArray();
        adh1CoreReference = adh1Reference.ToArray();
        pmt2ArtifactReference = pmt2Reference.ToArray();
        pms2ArtifactHash = pms2Hash.ToArray();
        recipientDeviceId = recipient.DeviceId.ToArray();
        recipientAccountId = recipient.AccountHash.ToArray();
        RecipientDeviceGeneration = recipient.DeviceGeneration;
        recipientDpd1Reference = dpd1Reference.ToArray();
        recipientDevicePublicKey = recipient.DeviceEd25519PublicKey.ToArray();
        recipientDeviceAgreementPublicKey = recipient.DeviceX25519PublicKey.ToArray();
        RecipientDmd1Generation = recipientAuthorization.Verified.Directory.Record.DirectoryGeneration;
        recipientDmd1Hash = recipientAuthorization.Verified.Directory.Record.RecordHash.ToArray();
        recipientDrs1Reference = recipientAuthorization.Verified.Directory.Record.Drs1Reference.CanonicalBytes.ToArray();
        this.dca1Reference = dca1Reference.ToArray();
        monotonicBootId = monotonic.BootId.ToArray();
        VerifiedAtMonotonicSeconds = monotonic.SampleSeconds;
        FreshnessDeadlineMonotonicSeconds = freshnessDeadlineMonotonicSeconds;
        witnessKeys = authority.WitnessKeys.ToDictionary(
            static witness => Convert.ToHexString(witness.Id.Span),
            static witness => new WitnessMaterial(
                witness.Ed25519PublicKey.ToArray(), witness.FailureDomainHash.ToArray()),
            StringComparer.Ordinal);
        WitnessThreshold = authority.WitnessThreshold;
        TrustedLowerUnixSeconds = trustedLowerUnixSeconds;
        TrustedUpperUnixSeconds = trustedUpperUnixSeconds;
        NotBeforeUnixSeconds = notBeforeUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong AuthorityGeneration { get; }
    public ReadOnlyMemory<byte> AuthorityCoreReference => authorityCoreReference.ToArray();
    public ReadOnlyMemory<byte> WitnessPolicyHash => witnessPolicyHash.ToArray();
    public ReadOnlyMemory<byte> Xnv1CoreReference => xnv1CoreReference.ToArray();
    public ReadOnlyMemory<byte> Xnh1CoreReference => xnh1CoreReference.ToArray();
    public ReadOnlyMemory<byte> Adh1CoreReference => adh1CoreReference.ToArray();
    public ReadOnlyMemory<byte> Pmt2ArtifactReference => pmt2ArtifactReference.ToArray();
    public ReadOnlyMemory<byte> Pms2ArtifactHash => pms2ArtifactHash.ToArray();
    public ReadOnlyMemory<byte> RecipientDeviceId => recipientDeviceId.ToArray();
    public ulong RecipientDeviceGeneration { get; }
    public ReadOnlyMemory<byte> RecipientDpd1Reference => recipientDpd1Reference.ToArray();
    public ReadOnlyMemory<byte> RecipientDevicePublicKey => recipientDevicePublicKey.ToArray();
    public ReadOnlyMemory<byte> Dca1Reference => dca1Reference.ToArray();
    public int WitnessThreshold { get; }
    public ulong TrustedLowerUnixSeconds { get; }
    public ulong TrustedUpperUnixSeconds { get; }
    public ulong NotBeforeUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ulong TrustedUnixSeconds => TrustedUpperUnixSeconds;

    internal ReadOnlySpan<byte> RecipientAccountIdSpan => recipientAccountId;
    internal ReadOnlySpan<byte> RecipientDeviceSigningPublicKeySpan => recipientDevicePublicKey;
    internal ReadOnlySpan<byte> RecipientDeviceAgreementPublicKeySpan => recipientDeviceAgreementPublicKey;
    internal ulong RecipientDmd1Generation { get; }
    internal ReadOnlySpan<byte> RecipientDmd1HashSpan => recipientDmd1Hash;
    internal ReadOnlySpan<byte> RecipientDrs1ReferenceSpan => recipientDrs1Reference;
    internal ReadOnlySpan<byte> MonotonicBootIdSpan => monotonicBootId;
    internal ulong VerifiedAtMonotonicSeconds { get; }
    internal ulong FreshnessDeadlineMonotonicSeconds { get; }

    internal static async ValueTask<VerifiedContactNetworkAuthority> VerifyAsync(
        VerifiedXPointNetworkAuthority authority,
        VerifiedOnionNetworkContext currentNetwork,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedDevice recipientDevice,
        CurrentlyAuthoritativeDca1 recipientAuthorization,
        ReadOnlyMemory<byte> exactXnv1,
        ReadOnlyMemory<byte> exactXnh1,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactPmt2,
        ReadOnlyMemory<byte> exactPms2,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(currentNetwork);
        ArgumentNullException.ThrowIfNull(freshness);
        ArgumentNullException.ThrowIfNull(recipientDevice);
        ArgumentNullException.ThrowIfNull(recipientAuthorization);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        cancellationToken.ThrowIfCancellationRequested();

        var xnvBytes = Own(exactXnv1, XPointNetworkRegistry.Xnv1.MinimumBytes, XPointNetworkRegistry.Xnv1.MaximumBytes, ProtocolMagic.XNV1);
        var xnhBytes = Own(exactXnh1, XPointNetworkRegistry.Xnh1.MinimumBytes, XPointNetworkRegistry.Xnh1.MaximumBytes, ProtocolMagic.XNH1);
        var adhBytes = Own(exactAdh1, 1, MaximumRecordBytes, ProtocolMagic.ADH1);
        var pmtBytes = Own(exactPmt2, 842, 11_066, ProtocolMagic.PMT2);
        var pmsBytes = Own(exactPms2, 500, 3_476, ProtocolMagic.PMS2);

        try
        {
            currentNetwork.EnsureCurrent();
            var closure = currentNetwork.Closure ??
                throw Error("NetworkContextIncomplete", "The current network context has no verified XPoint closure.");
            var protectedLkg = currentNetwork.ProtectedLkg ??
                throw Error("NetworkContextIncomplete", "The current network context has no protected XPoint tuple.");

            VerifyExactContext(authority, currentNetwork, freshness, closure, protectedLkg,
                xnvBytes, xnhBytes, adhBytes, pmtBytes);

            var monotonic = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(monotonic.BootId.Span, closure.FreshnessBootId) ||
                !freshness.IsCurrentAtMonotonic(monotonic.BootId.Span, monotonic.SampleSeconds))
                throw Error("FreshnessExpired", "The protected monotonic reading no longer keeps the exact directory closure current.");

            var pms = ContactCodec.Decode(ProtocolMagic.PMS2, pmsBytes);
            VerifyPms(authority, closure.Pmt, pms);
            VerifyRecipient(authority, freshness, recipientDevice, recipientAuthorization);

            var low = freshness.TrustedLowerUnixSeconds;
            var high = freshness.TrustedUpperUnixSeconds;
            VerifyCompleteTimeInterval(authority, closure, freshness, recipientDevice.Certificate,
                recipientAuthorization.Verified.Record, pms, low, high);

            var xnvReference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, closure.View.CoreHash.Span);
            var xnhReference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNH1, closure.Head.CoreHash.Span);
            var pmtReference = ContactCodec.ArtifactReference(ProtocolMagic.PMT2, closure.Pmt).CanonicalBytes.ToArray();
            var dpdReference = ArtifactReference(
                ProtocolMagic.DPD1, recipientDevice.Certificate.CanonicalHash.Span);
            var dcaReference = ArtifactReference(
                ProtocolMagic.DCA1, recipientAuthorization.Verified.Record.RecordHash.Span);
            var notBefore = new[]
            {
                authority.NotBefore, closure.View.NotBefore, closure.Head.ValidFrom,
                freshness.ValidFromUnixSeconds,
                BinaryPrimitives.ReadUInt64BigEndian(closure.Pmt.FieldSpan(11)),
                BinaryPrimitives.ReadUInt64BigEndian(pms.FieldSpan(8)),
                recipientDevice.Certificate.IssuedAtUnixSeconds,
                recipientAuthorization.Verified.Record.NotBeforeUnixSeconds,
            }.Max();
            var expiresAt = new[]
            {
                authority.ExpiresAt, closure.View.ExpiresAt, closure.Head.ValidUntil,
                freshness.ExpiresAtUnixSeconds,
                BinaryPrimitives.ReadUInt64BigEndian(closure.Pmt.FieldSpan(12)),
                BinaryPrimitives.ReadUInt64BigEndian(pms.FieldSpan(9)),
                recipientDevice.Certificate.ExpiresAtUnixSeconds,
                recipientAuthorization.Verified.Record.ExpiresAtUnixSeconds,
            }.Min();

            return new VerifiedContactNetworkAuthority(
                authority, xnvReference, xnhReference, freshness.ExactAdh1CoreReference.Span,
                pmtReference, pms.ArtifactHash.Span, recipientDevice.Certificate,
                recipientAuthorization, dpdReference, dcaReference, low, high, notBefore, expiresAt,
                monotonic, freshness.FreshnessDeadlineMonotonicSeconds);
        }
        catch (ContactNetworkAuthorityVerificationException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (OnionBoundaryException exception)
        {
            throw Error("NetworkContextInvalid", "The verified XPoint network context is no longer usable.", exception);
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or CryptographicException or OverflowException)
        {
            throw Error("MalformedClosure", "The exact Contact network-authority closure is malformed.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(xnvBytes);
            CryptographicOperations.ZeroMemory(xnhBytes);
            CryptographicOperations.ZeroMemory(adhBytes);
            CryptographicOperations.ZeroMemory(pmtBytes);
            CryptographicOperations.ZeroMemory(pmsBytes);
        }
    }

    internal static async ValueTask<VerifiedContactRouteProposalAuthority> VerifyProposalAsync(
        VerifiedXPointNetworkAuthority authority,
        VerifiedOnionNetworkContext currentNetwork,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedDevice recipientDevice,
        CurrentlyAuthoritativeDca1 recipientAuthorization,
        ReadOnlyMemory<byte> exactXnv1,
        ReadOnlyMemory<byte> exactXnh1,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactPmt2,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(currentNetwork);
        ArgumentNullException.ThrowIfNull(freshness);
        ArgumentNullException.ThrowIfNull(recipientDevice);
        ArgumentNullException.ThrowIfNull(recipientAuthorization);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        cancellationToken.ThrowIfCancellationRequested();

        var xnvBytes = Own(exactXnv1, XPointNetworkRegistry.Xnv1.MinimumBytes,
            XPointNetworkRegistry.Xnv1.MaximumBytes, ProtocolMagic.XNV1);
        var xnhBytes = Own(exactXnh1, XPointNetworkRegistry.Xnh1.MinimumBytes,
            XPointNetworkRegistry.Xnh1.MaximumBytes, ProtocolMagic.XNH1);
        var adhBytes = Own(exactAdh1, 1, MaximumRecordBytes, ProtocolMagic.ADH1);
        var pmtBytes = Own(exactPmt2, 842, 11_066, ProtocolMagic.PMT2);
        try
        {
            currentNetwork.EnsureCurrent();
            var closure = currentNetwork.Closure ??
                throw Error("NetworkContextIncomplete",
                    "The current network context has no verified XPoint closure.");
            var protectedLkg = currentNetwork.ProtectedLkg ??
                throw Error("NetworkContextIncomplete",
                    "The current network context has no protected XPoint tuple.");
            VerifyExactContext(authority, currentNetwork, freshness, closure, protectedLkg,
                xnvBytes, xnhBytes, adhBytes, pmtBytes);

            var monotonic = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(
                    monotonic.BootId.Span, closure.FreshnessBootId) ||
                !freshness.IsCurrentAtMonotonic(
                    monotonic.BootId.Span, monotonic.SampleSeconds))
                throw Error("FreshnessExpired",
                    "The protected monotonic reading no longer keeps the exact directory closure current.");

            VerifyRecipient(authority, freshness, recipientDevice, recipientAuthorization);
            var low = freshness.TrustedLowerUnixSeconds;
            var high = freshness.TrustedUpperUnixSeconds;
            var recipient = recipientDevice.Certificate;
            var dca = recipientAuthorization.Verified.Record;
            if (low > high ||
                !Covers(authority.NotBefore, authority.ExpiresAt, low, high) ||
                !Covers(closure.View.NotBefore, closure.View.ExpiresAt, low, high) ||
                !Covers(closure.Head.ValidFrom, closure.Head.ValidUntil, low, high) ||
                !Covers(freshness.ValidFromUnixSeconds, freshness.ExpiresAtUnixSeconds, low, high) ||
                !Covers(BinaryPrimitives.ReadUInt64BigEndian(closure.Pmt.FieldSpan(11)),
                    BinaryPrimitives.ReadUInt64BigEndian(closure.Pmt.FieldSpan(12)), low, high) ||
                !Covers(recipient.IssuedAtUnixSeconds, recipient.ExpiresAtUnixSeconds, low, high) ||
                !Covers(dca.NotBeforeUnixSeconds, dca.ExpiresAtUnixSeconds, low, high))
                throw Error("TrustedTimeIntervalNotCovered",
                    "The authenticated trusted-time interval is not covered by the route-proposal authority.");

            var pmtReference = ContactCodec.ArtifactReference(
                ProtocolMagic.PMT2, closure.Pmt).CanonicalBytes.ToArray();
            var xnvReference = XPointNetworkCodec.EncodeCoreReference(
                ProtocolMagic.XNV1, closure.View.CoreHash.Span);
            var xnhReference = XPointNetworkCodec.EncodeCoreReference(
                ProtocolMagic.XNH1, closure.Head.CoreHash.Span);
            var dpdReference = ArtifactReference(
                ProtocolMagic.DPD1, recipient.CanonicalHash.Span);
            var dcaReference = ArtifactReference(
                ProtocolMagic.DCA1, dca.RecordHash.Span);
            var notBefore = new[]
            {
                authority.NotBefore, closure.View.NotBefore, closure.Head.ValidFrom,
                freshness.ValidFromUnixSeconds,
                BinaryPrimitives.ReadUInt64BigEndian(closure.Pmt.FieldSpan(11)),
                recipient.IssuedAtUnixSeconds, dca.NotBeforeUnixSeconds,
            }.Max();
            var expiresAt = new[]
            {
                authority.ExpiresAt, closure.View.ExpiresAt, closure.Head.ValidUntil,
                freshness.ExpiresAtUnixSeconds,
                BinaryPrimitives.ReadUInt64BigEndian(closure.Pmt.FieldSpan(12)),
                recipient.ExpiresAtUnixSeconds, dca.ExpiresAtUnixSeconds,
            }.Min();
            return new VerifiedContactRouteProposalAuthority(
                authority, currentNetwork, freshness, recipientDevice, recipientAuthorization,
                xnvBytes, xnhBytes, adhBytes, pmtBytes, trustedTimeAuthority,
                pmtReference, xnvReference, xnhReference,
                freshness.ExactAdh1CoreReference.Span,
                dpdReference, dcaReference, low, high, notBefore, expiresAt);
        }
        catch (ContactNetworkAuthorityVerificationException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (OnionBoundaryException exception)
        {
            throw Error("NetworkContextInvalid",
                "The verified XPoint network context is no longer usable.", exception);
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or
            CryptographicException or OverflowException)
        {
            throw Error("MalformedClosure",
                "The exact Contact route-proposal authority closure is malformed.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(xnvBytes);
            CryptographicOperations.ZeroMemory(xnhBytes);
            CryptographicOperations.ZeroMemory(adhBytes);
            CryptographicOperations.ZeroMemory(pmtBytes);
        }
    }

    internal bool IsCurrentAt(ulong trusted) =>
        trusted >= NotBeforeUnixSeconds && trusted < ExpiresAtUnixSeconds;

    internal void VerifyWitnessThreshold(ContactRecord record, int receiptTag)
    {
        var receipts = record.FieldSpan(receiptTag);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        var valid = 0;
        for (var offset = 0; offset < receipts.Length; offset += 96)
        {
            var id = receipts.Slice(offset, 32);
            if (!witnessKeys.TryGetValue(Convert.ToHexString(id), out var witness) ||
                !VerifyEd25519(witness.PublicKey, record.SignatureInput.Span, receipts.Slice(offset + 32, 64)))
                throw new ContactFormatException(ContactValidationStage.Signature, "DirectoryWitnessSignatureFailed");
            if (!domains.Add(Convert.ToHexString(witness.FailureDomain)))
                throw new ContactFormatException(ContactValidationStage.Signature, "DirectoryWitnessFailureDomainRepeated");
            valid++;
        }
        if (valid < WitnessThreshold)
            throw new ContactFormatException(ContactValidationStage.Closure, "DirectoryWitnessThresholdNotMet");
    }

    private static void VerifyExactContext(
        VerifiedXPointNetworkAuthority authority,
        VerifiedOnionNetworkContext currentNetwork,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedOnionNetworkClosure closure,
        XPointNetworkProtectedLkg protectedLkg,
        ReadOnlySpan<byte> exactXnv1,
        ReadOnlySpan<byte> exactXnh1,
        ReadOnlySpan<byte> exactAdh1,
        ReadOnlySpan<byte> exactPmt2)
    {
        var xnvReference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, closure.View.CoreHash.Span);
        var xnhReference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNH1, closure.Head.CoreHash.Span);
        var directoryHead = AccountDirectoryAdh1Codec.Decode(exactAdh1);
        var trustedTime = AccountDirectoryDtt1Codec.Decode(freshness.ExactDtt1.Span);
        if (!Fixed(exactXnv1, closure.View.CanonicalSpan) ||
            !Fixed(exactXnh1, closure.Head.CanonicalSpan) ||
            !Fixed(exactAdh1, freshness.ExactAdh1.Span) ||
            !Fixed(exactPmt2, closure.Pmt.CanonicalBytes.Span))
            throw Error("ExactClosureMismatch", "An exact supplied artifact differs from the verified current capability closure.");

        if (!Fixed(authority.NetworkId.Span, currentNetwork.NetworkId.Span) ||
            !Fixed(authority.NetworkId.Span, freshness.NetworkId.Span) ||
            !Fixed(authority.NetworkId.Span, closure.NetworkId) ||
            !Fixed(authority.NetworkId.Span, closure.View.NetworkId.Span) ||
            !Fixed(authority.NetworkId.Span, closure.Head.NetworkId.Span) ||
            !Fixed(authority.NetworkId.Span, closure.Pmt.FieldSpan(1)))
            throw Error("NetworkMismatch", "The authority, network context, directory and placement artifacts do not name one network.");

        if (!Fixed(authority.AuthorityCoreReference.Span, closure.View.FieldSpan(7)) ||
            !Fixed(authority.AuthorityCoreReference.Span, closure.Head.FieldSpan(8)) ||
            !Fixed(authority.AuthorityCoreReference.Span, protectedLkg.AuthorityCoreReference.Span) ||
            !Fixed(authority.AuthorityCoreReference.Span, directoryHead.ExactXnaAuthorityCoreReference.Span) ||
            !Fixed(authority.AuthorityCoreReference.Span, trustedTime.AuthorizingXna1CoreReference.Span) ||
            !Fixed(authority.DirectoryWitnessPolicyHash.Span, closure.View.FieldSpan(8)) ||
            !Fixed(authority.DirectoryWitnessPolicyHash.Span, closure.Head.FieldSpan(9)) ||
            !Fixed(authority.DirectoryWitnessPolicyHash.Span, directoryHead.WitnessPolicyHash.Span) ||
            !Fixed(authority.DirectoryWitnessPolicyHash.Span, trustedTime.WitnessPolicyHash.Span) ||
            !Fixed(xnvReference, closure.Head.LatestView.Encode()) ||
            !Fixed(closure.View.CoreHash.Span, trustedTime.CurrentXnv1CoreHash.Span) ||
            closure.View.ViewGeneration != trustedTime.CurrentXnv1Generation ||
            closure.Head.LatestViewGeneration != closure.View.ViewGeneration ||
            !Fixed(xnvReference, protectedLkg.ViewCoreReference.Span) ||
            !Fixed(xnhReference, protectedLkg.HeadCoreReference.Span) ||
            !Fixed(closure.Pmt.FieldSpan(5), xnvReference))
            throw Error("CoreReferenceMismatch", "The verified XNV1/XNH1/PMT2 network references are not exact.");

        // PMT2 tag 14 remains its issuance-time audit anchor. Current directory
        // freshness is authenticated by the exact ADH1/DTT1 closure below.
        if (!Fixed(closure.Adh1CoreReference, freshness.ExactAdh1CoreReference.Span) ||
            !Fixed(closure.Dtt1CoreHash, freshness.ExactDtt1CoreHash.Span) ||
            !Fixed(closure.FreshnessBootId, freshness.BootId.Span) ||
            closure.TrustedLowerUnixSeconds != freshness.TrustedLowerUnixSeconds ||
            closure.TrustedUpperUnixSeconds != freshness.TrustedUpperUnixSeconds ||
            closure.FreshnessMonotonicSample != freshness.MonotonicSample ||
            closure.FreshnessDeadlineMonotonicSeconds != freshness.FreshnessDeadlineMonotonicSeconds)
            throw Error("FreshnessMismatch", "The supplied directory freshness is not the exact freshness used to mint the current network context.");
    }

    private static void VerifyPms(
        VerifiedXPointNetworkAuthority authority,
        ContactRecord pmt,
        ContactRecord pms)
    {
        if (!Fixed(pms.FieldSpan(1), authority.NetworkId.Span) ||
            !Fixed(pms.FieldSpan(2), ContactCodec.ArtifactReference(ProtocolMagic.PMT2, pmt).CanonicalBytes.Span) ||
            !Fixed(pms.FieldSpan(4), pmt.FieldSpan(6)) ||
            pms.FieldSpan(5)[0] != pmt.FieldSpan(7)[0])
            throw Error("PmsBindingMismatch", "PMS2 does not bind the exact current PMT2/network/epoch/replica count.");
        ContactCodec.ValidatePmsSelection(pms, pmt);
        VerifyWitnessThreshold(pms, 11, authority);
    }

    private static void VerifyRecipient(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedDevice recipientDevice,
        CurrentlyAuthoritativeDca1 recipientAuthorization)
    {
        var certificate = recipientDevice.Certificate;
        var authorization = recipientAuthorization.Verified;
        if (!Fixed(authority.NetworkId.Span, certificate.NetworkId.Span) ||
            !Fixed(authority.NetworkId.Span, authorization.Record.NetworkId.Span) ||
            !Fixed(authority.NetworkId.Span, authorization.Directory.Record.NetworkId.Span) ||
            !Fixed(authorization.Record.PublisherDeviceId.Span, certificate.DeviceId.Span) ||
            recipientAuthorization.TrustedUnixSeconds != freshness.TrustedUpperUnixSeconds)
            throw Error("RecipientMismatch", "DCA1, DPD1 and trusted freshness do not identify one exact current recipient device.");

        var exactDevice = authorization.Directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.Certificate.DeviceId.Span, certificate.DeviceId.Span));
        if (exactDevice is null ||
            exactDevice.Certificate.CanonicalBytes.Length != certificate.CanonicalBytes.Length ||
            !Fixed(exactDevice.Certificate.CanonicalHash.Span, certificate.CanonicalHash.Span))
            throw Error("RecipientMismatch", "The recipient DPD1 is not the exact active device authorized by DCA1/DMD1.");
    }

    private static void VerifyCompleteTimeInterval(
        VerifiedXPointNetworkAuthority authority,
        VerifiedOnionNetworkClosure closure,
        VerifiedAccountDirectoryFreshness freshness,
        DeviceCertificate recipient,
        ParsedDca1 dca,
        ContactRecord pms,
        ulong low,
        ulong high)
    {
        if (low > high ||
            !Covers(authority.NotBefore, authority.ExpiresAt, low, high) ||
            !Covers(closure.View.NotBefore, closure.View.ExpiresAt, low, high) ||
            !Covers(closure.Head.ValidFrom, closure.Head.ValidUntil, low, high) ||
            !Covers(freshness.ValidFromUnixSeconds, freshness.ExpiresAtUnixSeconds, low, high) ||
            !Covers(BinaryPrimitives.ReadUInt64BigEndian(closure.Pmt.FieldSpan(11)),
                BinaryPrimitives.ReadUInt64BigEndian(closure.Pmt.FieldSpan(12)), low, high) ||
            !Covers(BinaryPrimitives.ReadUInt64BigEndian(pms.FieldSpan(8)),
                BinaryPrimitives.ReadUInt64BigEndian(pms.FieldSpan(9)), low, high) ||
            !Covers(recipient.IssuedAtUnixSeconds, recipient.ExpiresAtUnixSeconds, low, high) ||
            !Covers(dca.NotBeforeUnixSeconds, dca.ExpiresAtUnixSeconds, low, high))
            throw Error("TrustedTimeIntervalNotCovered", "The complete authenticated trusted-time interval is not covered by every authority artifact.");
    }

    private static void VerifyWitnessThreshold(
        ContactRecord record,
        int receiptTag,
        VerifiedXPointNetworkAuthority authority)
    {
        var witnesses = authority.WitnessKeys.ToDictionary(
            static witness => Convert.ToHexString(witness.Id.Span), StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        var valid = 0;
        var receipts = record.FieldSpan(receiptTag);
        for (var offset = 0; offset < receipts.Length; offset += 96)
        {
            var id = receipts.Slice(offset, 32);
            if (!witnesses.TryGetValue(Convert.ToHexString(id), out var witness))
                throw Error("UnknownWitness", "A PMS2 witness is absent from the exact XNA1 authority.");
            if (!domains.Add(Convert.ToHexString(witness.FailureDomainHash.Span)))
                throw Error("WitnessFailureDomainRepeated", "PMS2 repeats a physical witness failure domain.");
            if (!VerifyEd25519(witness.Ed25519PublicKey.Span, record.SignatureInput.Span, receipts.Slice(offset + 32, 64)))
                throw Error("InvalidWitnessSignature", "A PMS2 witness signature is invalid.");
            valid++;
        }
        if (valid < authority.WitnessThreshold)
            throw Error("WitnessThresholdNotMet", "PMS2 does not meet the exact XNA1 witness threshold.");
    }

    private static bool Covers(ulong notBefore, ulong expiresAt, ulong low, ulong high) =>
        notBefore <= low && high < expiresAt;

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static bool VerifyEd25519(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64) return false;
        try { return PublicKeyAuth.VerifyDetached(signature.ToArray(), message.ToArray(), publicKey.ToArray()); }
        catch (Exception) { return false; }
    }

    private static byte[] Own(ReadOnlyMemory<byte> value, int minimum, int maximum, string name)
    {
        if (value.Length < minimum || value.Length > maximum)
            throw Error("ArtifactSizeInvalid", $"The exact {name} length is outside its frozen bounds.");
        return value.ToArray();
    }

    private static byte[] ArtifactReference(string magic, ReadOnlySpan<byte> hash) =>
        new ContactArtifactReference(magic, 1, hash).CanonicalBytes.ToArray();

    private sealed record WitnessMaterial(byte[] PublicKey, byte[] FailureDomain);

    private static ContactNetworkAuthorityVerificationException Error(
        string code,
        string message,
        Exception? inner = null) => new(code, message, inner);
}
