using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV1;

public enum Xpa1PublicationKind : byte
{
    PermanentAddress = 1,
    OneTimeInvite = 2,
}

public sealed class Xpa1PublicationAuthorizationException : CryptographicException
{
    internal Xpa1PublicationAuthorizationException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Non-serializable proof that one exact XPU1 is authorized by the current
/// account-directory witness threshold and the exact verified resolver placement.
/// The host must obtain this capability immediately before reserving or mutating state.
/// </summary>
public sealed class VerifiedXpa1PublicationAuthorization
{
    private readonly byte[] _exactXpa1;
    private readonly byte[] _networkId;
    private readonly byte[] _authorizationId;
    private readonly byte[] _operationId;
    private readonly byte[] _locatorHash;
    private readonly byte[] _dcr1Hash;
    private readonly byte[] _dcb1Hash;
    private readonly byte[] _xir1Hash;
    private readonly byte[] _predecessorObjectHash;
    private readonly byte[] _objectCiphertextHash;
    private readonly byte[] _policyHash;
    private readonly byte[] _directoryHeadHash;
    private readonly byte[] _authorizedBodyHash;
    private readonly byte[] _requestHash;
    private readonly byte[] _viewHash;
    private readonly byte[] _placementHash;
    private readonly byte[] _authorityCoreReference;
    private readonly byte[] _witnessPolicyHash;
    private readonly byte[] _bootId;

    internal VerifiedXpa1PublicationAuthorization(
        Xpu1Request request,
        ServiceRecord xpa1,
        VerifiedXPointNetworkAuthority authority,
        OnionMonotonicReading currentMonotonic)
    {
        _exactXpa1 = xpa1.Canonical.ToArray();
        _networkId = xpa1[1].ToArray();
        _authorizationId = xpa1[2].ToArray();
        _operationId = xpa1[3].ToArray();
        _locatorHash = xpa1[4].ToArray();
        PublicationKind = (Xpa1PublicationKind)xpa1[5][0];
        _dcr1Hash = xpa1[6].ToArray();
        _dcb1Hash = xpa1[7].ToArray();
        _xir1Hash = xpa1[8].ToArray();
        Generation = ServiceWire.U64(xpa1[9]);
        _predecessorObjectHash = xpa1[10].ToArray();
        _objectCiphertextHash = xpa1[11].ToArray();
        UsageLimit = ServiceWire.U32(xpa1[12]);
        EffectiveExpiresAtUnixSeconds = ServiceWire.U64(xpa1[13]);
        _policyHash = xpa1[14].ToArray();
        IssuedAtUnixSeconds = ServiceWire.U64(xpa1[15]);
        NotBeforeUnixSeconds = ServiceWire.U64(xpa1[16]);
        AuthorizationExpiresAtUnixSeconds = ServiceWire.U64(xpa1[17]);
        _directoryHeadHash = xpa1[18].ToArray();
        _authorizedBodyHash = xpa1[19].ToArray();
        _requestHash = request.RequestHash.ToArray();
        _viewHash = request.ViewHash.ToArray();
        _placementHash = request.PlacementHash.ToArray();
        _authorityCoreReference = authority.AuthorityCoreReference.ToArray();
        AuthorityGeneration = authority.AuthorityGeneration;
        _witnessPolicyHash = authority.DirectoryWitnessPolicyHash.ToArray();
        _bootId = currentMonotonic.BootId.ToArray();
        VerifiedAtMonotonicSeconds = currentMonotonic.SampleSeconds;
    }

    public ReadOnlyMemory<byte> ExactXpa1 => _exactXpa1.ToArray();
    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> AuthorizationId => _authorizationId.ToArray();
    public ReadOnlyMemory<byte> OperationId => _operationId.ToArray();
    public ReadOnlyMemory<byte> LocatorHash => _locatorHash.ToArray();
    public Xpa1PublicationKind PublicationKind { get; }
    public ReadOnlyMemory<byte> Dcr1Hash => _dcr1Hash.ToArray();
    public ReadOnlyMemory<byte> Dcb1Hash => _dcb1Hash.ToArray();
    public ReadOnlyMemory<byte> Xir1Hash => _xir1Hash.ToArray();
    public ulong Generation { get; }
    public ReadOnlyMemory<byte> PredecessorObjectHash => _predecessorObjectHash.ToArray();
    public ReadOnlyMemory<byte> ObjectCiphertextHash => _objectCiphertextHash.ToArray();
    public uint UsageLimit { get; }
    public ulong EffectiveExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> PolicyHash => _policyHash.ToArray();
    public ulong IssuedAtUnixSeconds { get; }
    public ulong NotBeforeUnixSeconds { get; }
    public ulong AuthorizationExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> DirectoryHeadHash => _directoryHeadHash.ToArray();
    public ReadOnlyMemory<byte> AuthorizedBodyHash => _authorizedBodyHash.ToArray();
    public ReadOnlyMemory<byte> RequestHash => _requestHash.ToArray();
    public ReadOnlyMemory<byte> ViewHash => _viewHash.ToArray();
    public ReadOnlyMemory<byte> PlacementHash => _placementHash.ToArray();
    public ReadOnlyMemory<byte> AuthorityCoreReference => _authorityCoreReference.ToArray();
    public ulong AuthorityGeneration { get; }
    public ReadOnlyMemory<byte> WitnessPolicyHash => _witnessPolicyHash.ToArray();
    public ReadOnlyMemory<byte> BootId => _bootId.ToArray();
    public ulong VerifiedAtMonotonicSeconds { get; }
}

public static class Xpa1PublicationAuthorizationVerifier
{
    private const string SignatureDomain = "Deep/ContactResolver/V1/publication-authorization";
    private const ulong MaximumAuthorizationLifetimeSeconds = 86_400;

    public static async ValueTask<VerifiedXpa1PublicationAuthorization> VerifyAsync(
        Xpu1Request request,
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedContactServicePlacement placement,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(freshness);
        ArgumentNullException.ThrowIfNull(placement);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var currentMonotonic = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
            var xpa1 = ServiceWire.ParseValidatedXpa1(request);
            VerifyAuthorityAndFreshness(request, authority, freshness, placement, xpa1);
            VerifyMonotonicAndTime(request, authority, freshness, placement, currentMonotonic, xpa1);
            VerifyPlacement(request, placement);
            VerifyWitnessThreshold(authority, xpa1);
            return new VerifiedXpa1PublicationAuthorization(request, xpa1, authority, currentMonotonic);
        }
        catch (Xpa1PublicationAuthorizationException)
        {
            throw;
        }
        catch (OnionBoundaryException exception)
        {
            throw new Xpa1PublicationAuthorizationException(
                "TrustedTimeInvalid", "The protected monotonic clock is unavailable or invalid.", exception);
        }
        catch (Exception exception) when (exception is ContactFormatException or FormatException or ArgumentException or CryptographicException)
        {
            throw new Xpa1PublicationAuthorizationException(
                "InvalidPublicationAuthorization",
                "The exact XPA1 publication authorization closure is invalid.",
                exception);
        }
    }

    private static void VerifyAuthorityAndFreshness(
        Xpu1Request request,
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedContactServicePlacement placement,
        ServiceRecord xpa1)
    {
        if (!Fixed(request.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(request.NetworkId.Span, freshness.NetworkId.Span) ||
            !Fixed(request.NetworkId.Span, placement.Network.NetworkId.Span))
            Fail("NetworkMismatch", "XPU1, XPA1, authority, freshness and placement must name one exact network.");

        var head = AccountDirectoryAdh1Codec.Decode(freshness.ExactAdh1.Span);
        var dtt = AccountDirectoryDtt1Codec.Decode(freshness.ExactDtt1.Span);
        if (!Fixed(head.ExactXnaAuthorityCoreReference.Span, authority.AuthorityCoreReference.Span) ||
            !Fixed(dtt.AuthorizingXna1CoreReference.Span, authority.AuthorityCoreReference.Span) ||
            !Fixed(head.WitnessPolicyHash.Span, authority.DirectoryWitnessPolicyHash.Span) ||
            !Fixed(dtt.WitnessPolicyHash.Span, authority.DirectoryWitnessPolicyHash.Span))
            Fail("AuthorityBindingMismatch", "The current ADH1/DTT1 does not bind the exact current XNA1 authority and witness policy.");
        if (!Fixed(dtt.CurrentAdh1CoreHash.Span, freshness.ExactAdh1CoreHash.Span) ||
            dtt.CurrentAdh1Generation != freshness.AdhGeneration ||
            !Fixed(xpa1[18], freshness.ExactAdh1CoreHash.Span) ||
            !Fixed(dtt.CurrentXnv1CoreHash.Span, placement.ViewHash.Span) ||
            !Fixed(request.ViewHash.Span, placement.ViewHash.Span))
            Fail("FreshnessBindingMismatch", "The current ADH1/DTT1 does not bind the exact verified resolver view.");
    }

    private static void VerifyMonotonicAndTime(
        Xpu1Request request,
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedContactServicePlacement placement,
        OnionMonotonicReading currentMonotonic,
        ServiceRecord xpa1)
    {
        var lease = placement.Network.TrustedTime ??
            throw new Xpa1PublicationAuthorizationException(
                "PlacementTimeMissing", "The verified resolver placement has no production trusted-time lease.");
        try
        {
            lease.EnsureLive();
        }
        catch (OnionBoundaryException exception)
        {
            throw new Xpa1PublicationAuthorizationException(
                "PlacementTimeExpired", "The verified resolver placement trusted-time lease has expired.", exception);
        }
        var expectedLeaseBoot = PrivacyRoutingWire.Sha256Domain(
            "Deep/XPoint/V1/monotonic-boot-id", freshness.BootId.ToArray());
        try
        {
            if (!Fixed(currentMonotonic.BootId.Span, freshness.BootId.Span) ||
                !Fixed(expectedLeaseBoot, lease.BootIdSpan))
                Fail("MonotonicBootMismatch", "Freshness, current monotonic reading and placement lease belong to different boots.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedLeaseBoot);
        }

        if (!freshness.IsCurrentAtMonotonic(currentMonotonic.BootId.Span, currentMonotonic.SampleSeconds))
            Fail("FreshnessExpired", "The account-directory freshness capability is no longer current.");

        var elapsed = currentMonotonic.SampleSeconds - freshness.MonotonicSample;
        ulong lower;
        ulong upper;
        try
        {
            lower = checked(freshness.TrustedLowerUnixSeconds + elapsed);
            upper = checked(freshness.TrustedUpperUnixSeconds + elapsed);
        }
        catch (OverflowException exception)
        {
            throw new Xpa1PublicationAuthorizationException(
                "TrustedTimeOverflow", "The monotonic-to-trusted-time projection overflowed.", exception);
        }

        var issuedAt = ServiceWire.U64(xpa1[15]);
        var notBefore = ServiceWire.U64(xpa1[16]);
        var authorizationExpiresAt = ServiceWire.U64(xpa1[17]);
        if (authorizationExpiresAt - issuedAt > MaximumAuthorizationLifetimeSeconds ||
            notBefore > lower || upper >= authorizationExpiresAt ||
            authority.NotBefore > lower || upper >= authority.ExpiresAt ||
            freshness.ValidFromUnixSeconds > lower || upper >= freshness.ExpiresAtUnixSeconds ||
            upper >= placement.ValidUntilUnixSeconds ||
            request.IssuedAtUnixSeconds < issuedAt || request.IssuedAtUnixSeconds > lower ||
            request.ExpiresAtUnixSeconds > authorizationExpiresAt || upper >= request.ExpiresAtUnixSeconds ||
            authorizationExpiresAt > placement.ValidUntilUnixSeconds ||
            authorizationExpiresAt > freshness.ExpiresAtUnixSeconds ||
            authorizationExpiresAt > authority.ExpiresAt ||
            authorizationExpiresAt > ServiceWire.U64(xpa1[13]))
            Fail("AuthorizationTimeInvalid", "The complete trusted interval or XPA1/XPU1 lifetime lies outside its verified closure.");
    }

    private static void VerifyPlacement(Xpu1Request request, VerifiedContactServicePlacement placement)
    {
        if (!placement.Binds(ContactServiceRequestKind.PublishInvite, request.LocatorHash) ||
            placement.RequestKind != ContactServiceRequestKind.PublishInvite ||
            placement.ServiceClass != ContactServiceClass.InviteResolver ||
            !Fixed(request.ViewHash.Span, placement.ViewHash.Span) ||
            !Fixed(request.PlacementHash.Span, placement.PlacementHash.Span))
            Fail("PlacementMismatch", "XPU1 is not bound to the exact verified PublishInvite placement and shard.");
    }

    private static void VerifyWitnessThreshold(
        VerifiedXPointNetworkAuthority authority,
        ServiceRecord xpa1)
    {
        var count = xpa1[20][0];
        if (count < authority.WitnessThreshold)
            Fail("WitnessThresholdNotMet", "XPA1 contains fewer witness receipts than the exact XNA1 threshold.");

        var keys = authority.WitnessKeys.ToDictionary(
            static key => Convert.ToHexString(key.Id.Span), StringComparer.Ordinal);
        var projection = ServiceWire.Project(ProtocolMagic.XPA1, Enumerable.Range(1, 20)
            .Select(tag => (checked((ushort)tag), xpa1[(ushort)tag].ToArray())).ToArray());
        var signingInput = ContactCodec.SignatureInput(SignatureDomain, projection);
        var failureDomains = new HashSet<string>(StringComparer.Ordinal);
        var valid = 0;
        try
        {
            for (var index = 0; index < count; index++)
            {
                var row = xpa1[21].Slice(index * 96, 96);
                if (!keys.TryGetValue(Convert.ToHexString(row[..32]), out var key) || key is null)
                    Fail("UnknownWitness", "XPA1 contains a signer absent from the exact current XNA1 witness set.");

                bool verified;
                try
                {
                    verified = PublicKeyAuth.VerifyDetached(
                        row[32..].ToArray(), signingInput, key.Ed25519PublicKey.ToArray());
                }
                catch (Exception exception) when (exception is CryptographicException or ArgumentException)
                {
                    throw new Xpa1PublicationAuthorizationException(
                        "InvalidWitnessSignature", "An XPA1 Ed25519 witness signature is invalid.", exception);
                }
                if (!verified)
                    Fail("InvalidWitnessSignature", "An XPA1 Ed25519 witness signature is invalid.");
                failureDomains.Add(Convert.ToHexString(key.FailureDomainHash.Span));
                valid++;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(projection);
            CryptographicOperations.ZeroMemory(signingInput);
        }

        if (valid < authority.WitnessThreshold || failureDomains.Count < authority.WitnessThreshold)
            Fail("WitnessThresholdNotMet", "XPA1 does not meet the exact XNA1 witness and failure-domain threshold.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new Xpa1PublicationAuthorizationException(code, message);
}
