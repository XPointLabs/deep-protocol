using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.ContactV2;

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
    private readonly Xpu1Request _request;
    private readonly VerifiedXPointNetworkAuthority _authority;
    private readonly VerifiedDeepIdV2DirectoryFreshness _freshness;
    private readonly VerifiedContactServicePlacement _placement;
    private readonly OnionTrustedTimeAuthority _time;

    internal VerifiedXpa1PublicationAuthorization(
        Xpu1Request request,
        ServiceRecord xpa1,
        VerifiedXPointNetworkAuthority authority,
        VerifiedDeepIdV2DirectoryFreshness freshness,
        VerifiedContactServicePlacement placement,
        OnionTrustedTimeAuthority time,
        OnionMonotonicReading currentMonotonic)
    {
        _request = request; _authority = authority; _freshness = freshness;
        _placement = placement; _time = time;
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

    public async ValueTask EnsureCurrentAsync(CancellationToken cancellationToken = default)
    {
        var current = await Xpa1PublicationAuthorizationVerifier.VerifyAsync(_request,
            _authority, _freshness, _placement, _time, cancellationToken).ConfigureAwait(false);
        if (current.VerifiedAtMonotonicSeconds < VerifiedAtMonotonicSeconds ||
            !CryptographicOperations.FixedTimeEquals(current.BootId.Span, _bootId))
            throw new Xpa1PublicationAuthorizationException("TrustedTimeInvalid",
                "Publication release crossed its original protected clock sample.");
        cancellationToken.ThrowIfCancellationRequested();
    }
}

public static class Xpa1PublicationAuthorizationVerifier
{
    public static async ValueTask<VerifiedXpa1PublicationAuthorization> VerifyAsync(
        Xpu1Request request, VerifiedXPointNetworkAuthority authority,
        VerifiedDeepIdV2DirectoryFreshness freshness, VerifiedContactServicePlacement placement,
        OnionTrustedTimeAuthority trustedTimeAuthority, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(freshness); ArgumentNullException.ThrowIfNull(placement);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority); cancellationToken.ThrowIfCancellationRequested();
        try
        {
            // Reparse exact V2 bytes before any clock/source callback.
            request = Xpu1Codec.Decode(request.CanonicalBytes.Span);
            var parsed = DeepIdV2ContactPublicationCodec.DecodeXpu1(request.CanonicalBytes.Span);
            if (request.Generation != 0 || request.UsageLimit != 0 ||
                parsed.Authorization.Field(5).Span[0] != (byte)Xpa1PublicationKind.PermanentAddress)
                Fail("UnsupportedPublicationKind", "Only current DID2 reusable genesis publication is admitted.");
            if (request.ExpiresAtUnixSeconds <= request.IssuedAtUnixSeconds ||
                request.ExpiresAtUnixSeconds - request.IssuedAtUnixSeconds > 120 ||
                ServiceWire.U64(parsed.Authorization.Field(15).Span) != request.IssuedAtUnixSeconds ||
                ServiceWire.U64(parsed.Authorization.Field(16).Span) != request.IssuedAtUnixSeconds ||
                ServiceWire.U64(parsed.Authorization.Field(17).Span) != request.ExpiresAtUnixSeconds)
                Fail("AuthorizationTimeInvalid", "DID2 genesis authorization must bind the exact bounded request lifetime.");
            var first = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
            RequireCurrent(request, parsed, authority, freshness, placement, first);
            var final = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
            if (!Fixed(first.BootId.Span, final.BootId.Span) || final.SampleSeconds < first.SampleSeconds)
                Fail("TrustedTimeInvalid", "Publication verification crossed a protected clock discontinuity.");
            RequireCurrent(request, parsed, authority, freshness, placement, final);
            cancellationToken.ThrowIfCancellationRequested();
            return new(request, ServiceWire.ParseValidatedXpa1(request), authority,
                freshness, placement, trustedTimeAuthority, final);
        }
        catch (Xpa1PublicationAuthorizationException) { throw; }
        catch (Exception error) when (error is ArgumentException or FormatException or
            CryptographicException or OverflowException or OnionBoundaryException)
        {
            throw new Xpa1PublicationAuthorizationException("InvalidPublicationAuthorization",
                "The exact DID2 publication authorization failed closed.", error);
        }
    }

    private static void RequireCurrent(Xpu1Request request, ParsedXpu1V2 parsed,
        VerifiedXPointNetworkAuthority authority, VerifiedDeepIdV2DirectoryFreshness freshness,
        VerifiedContactServicePlacement placement, OnionMonotonicReading reading)
    {
        placement.Network.EnsureCurrent();
        var closure = placement.Network.Closure ??
            throw new Xpa1PublicationAuthorizationException("PlacementMissing", "Complete NETCODEC placement is required.");
        if (!placement.Binds(ContactServiceRequestKind.PublishInvite, request.LocatorHash) ||
            placement.RequestKind != ContactServiceRequestKind.PublishInvite ||
            placement.ServiceClass != ContactServiceClass.InviteResolver ||
            !Fixed(request.NetworkId.Span, placement.Network.NetworkId.Span) ||
            !Fixed(request.ViewHash.Span, placement.ViewHash.Span) ||
            !Fixed(request.PlacementHash.Span, placement.PlacementHash.Span) ||
            !Fixed(closure.View.CoreHash.Span, request.ViewHash.Span) ||
            !Fixed(closure.Adh1CoreReference, ((IVerifiedDirectoryNetworkTime)freshness).ExactAdh1CoreReference.Span) ||
            !Fixed(closure.FreshnessBootId, reading.BootId.Span) ||
            !Fixed(closure.View.FieldSpan(7), authority.AuthorityCoreReference.Span) ||
            reading.SampleSeconds < closure.FreshnessMonotonicSample ||
            reading.SampleSeconds >= closure.FreshnessDeadlineMonotonicSeconds ||
            request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds)
            Fail("PlacementMismatch", "Publication is not bound to the exact current DID2 network/head/placement.");
        // The account-independent observer proof and independently obtained
        // network context may use different nonce-bound DTT1 intervals.
        var elapsed = checked(reading.SampleSeconds - closure.FreshnessMonotonicSample);
        var networkLower = checked(closure.TrustedLowerUnixSeconds + elapsed);
        var networkUpper = checked(closure.TrustedUpperUnixSeconds + elapsed);
        if (request.IssuedAtUnixSeconds > networkLower || networkUpper >= request.ExpiresAtUnixSeconds ||
            networkUpper >= placement.ValidUntilUnixSeconds)
            Fail("AuthorizationTimeInvalid", "The full network trusted interval is not covered.");
        _ = DeepIdV2Xpa1CurrentDirectoryWitnessVerifier.Verify(parsed, authority, freshness,
            reading.BootId.Span, reading.SampleSeconds);
        if (!Fixed(parsed.Field(25).Span, request.ExactRouteClosure.Span) ||
            !Fixed(ContactRouteClosureCodec.Decode(request.ExactRouteClosure.Span).Projection.CanonicalBytes.Span,
                closure.Pmt.CanonicalBytes.Span))
            Fail("RouteProjectionMismatch", "Publication uses another exact verified PMT2 projection.");
    }

    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    [DoesNotReturn]
    private static void Fail(string code, string message) => throw new Xpa1PublicationAuthorizationException(code, message);
}
