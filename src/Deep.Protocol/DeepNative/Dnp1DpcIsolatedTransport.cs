using System.Diagnostics.CodeAnalysis;

namespace Deep.Protocol.DeepNative;

public enum CanonicalAddressFamily : byte
{
    Ipv4 = 1,
    Ipv6 = 2
}

/// <summary>A canonical binary IP value. Construction does not imply that it is publicly routable.</summary>
public sealed class CanonicalIpAddress : IEquatable<CanonicalIpAddress>
{
    private readonly byte[] _bytes;

    public CanonicalIpAddress(ReadOnlySpan<byte> address)
    {
        if (address.Length == 16 && IsIpv4Mapped(address))
        {
            Family = CanonicalAddressFamily.Ipv4;
            _bytes = address[12..].ToArray();
        }
        else if (address.Length == 4)
        {
            Family = CanonicalAddressFamily.Ipv4;
            _bytes = address.ToArray();
        }
        else if (address.Length == 16)
        {
            Family = CanonicalAddressFamily.Ipv6;
            _bytes = address.ToArray();
        }
        else
        {
            throw new RecordException(
                RecordError.InvalidLength,
                "A canonical IP address must contain 4 or 16 bytes.");
        }
    }

    public CanonicalAddressFamily Family { get; }
    public ReadOnlyMemory<byte> Bytes => _bytes.ToArray();

    public bool Equals(CanonicalIpAddress? other) =>
        other is not null && Family == other.Family &&
        CanonicalGrammar.FixedEquals(_bytes, other._bytes);

    public override bool Equals(object? obj) => Equals(obj as CanonicalIpAddress);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add((byte)Family);
        foreach (var value in _bytes) hash.Add(value);
        return hash.ToHashCode();
    }

    internal ReadOnlySpan<byte> TrustedBytes => _bytes;

    private static bool IsIpv4Mapped(ReadOnlySpan<byte> address) =>
        address[..10].IndexOfAnyExcept((byte)0) < 0 && address[10] == 0xff && address[11] == 0xff;
}

public sealed class DnsResolutionRequest
{
    private readonly byte[] _canonicalName;

    internal DnsResolutionRequest(ReadOnlySpan<byte> canonicalName) =>
        _canonicalName = canonicalName.ToArray();

    public ReadOnlyMemory<byte> CanonicalAsciiName => _canonicalName.ToArray();
    public int MaximumResults => 16;
    public bool ResolveExactlyOnce => true;
}

public interface ITypedDnsResolver
{
    ValueTask<IReadOnlyList<CanonicalIpAddress>> ResolveOnceAsync(
        DnsResolutionRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>Closed transport options passed to the trusted platform connector.</summary>
public sealed class IsolatedConnectionRequest
{
    private readonly CanonicalIpAddress[] _addresses;
    private readonly byte[] _serverName;

    internal IsolatedConnectionRequest(
        IReadOnlyList<CanonicalIpAddress> addresses,
        ReadOnlySpan<byte> serverName,
        ushort port)
    {
        _addresses = addresses.Select(static address =>
            new CanonicalIpAddress(address.TrustedBytes)).ToArray();
        _serverName = serverName.ToArray();
        Port = port;
    }

    public IReadOnlyList<CanonicalIpAddress> Addresses =>
        Array.AsReadOnly(_addresses.Select(static address =>
            new CanonicalIpAddress(address.TrustedBytes)).ToArray());
    public ReadOnlyMemory<byte> CanonicalAsciiSni => _serverName.ToArray();
    public ushort Port { get; }
    public bool SystemProxyDisabled => true;
    public bool UserProxyDisabled => true;
    public bool RedirectsDisabled => true;
    public bool AltSvcDisabled => true;
    public bool OriginCoalescingDisabled => true;
    public bool PoolingDisabled => true;
    public bool ConnectionReuseDisabled => true;
    public bool FreshConnectionRequired => true;
}

public sealed class IsolatedPeerResponse
{
    private readonly byte[] _body;

    public IsolatedPeerResponse(
        ushort statusCode,
        ReadOnlySpan<byte> body,
        bool isRedirect = false,
        bool isCompressed = false)
    {
        StatusCode = statusCode;
        _body = body.ToArray();
        IsRedirect = isRedirect;
        IsCompressed = isCompressed;
    }

    public ushort StatusCode { get; }
    public ReadOnlyMemory<byte> Body => _body.ToArray();
    public bool IsRedirect { get; }
    public bool IsCompressed { get; }
}

public interface IFreshPeerTransport : IAsyncDisposable
{
    CanonicalIpAddress RemoteAddress { get; }
    ReadOnlyMemory<byte> TlsSpkiSha256 { get; }

    ValueTask<IsolatedPeerResponse> SendNativeMailboxAsync(
        ReadOnlyMemory<byte> exactRequestBody,
        CancellationToken cancellationToken = default);

    ValueTask CloseAsync(CancellationToken cancellationToken = default);
}

public interface ITypedPeerConnector
{
    ValueTask<IFreshPeerTransport> ConnectTlsAsync(
        IsolatedConnectionRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>Exact immutable headers/path owned by the DNP boundary, never by its caller.</summary>
public static class NativePeerHttpContract
{
    public const string Method = "POST";
    public const string Path = "/api/peer/native/v1/mailbox";
    public const string RequestMediaType = "application/vnd.deep.peer.dpr1+prq2";
    public const string ResponseMediaType = "application/vnd.deep.peer.dps1+mrr2";
    public const string CacheControl = "no-store, no-transform";
    public const string ContentTypeOptions = "nosniff";
}

/// <summary>
/// One authoritative-read observation assembled only from sealed relative facts. Its internal
/// constructor prevents raw bytes or caller strings from minting a transport authorization.
/// </summary>
public sealed class DpcTransportAuthoritySnapshot
{
    private readonly byte[] _cutoverSource;
    private readonly byte[] _drsReference;
    private readonly byte[] _drsHead;
    private readonly byte[] _witnessLkgReference;
    private readonly byte[] _dnrcSource;
    private readonly byte[] _dnrReference;
    private readonly byte[] _membershipRoot;
    private readonly byte[] _placementCommitment;
    private readonly byte[] _dpcReference;

    internal DpcTransportAuthoritySnapshot(
        CurrentCutoverRelative cutover,
        CurrentDnrcRelative dnrc,
        VerifiedMembershipRoutingLkg membership,
        VerifiedRouterContact contact,
        ulong authoritativeReadGeneration,
        ulong transactionTimeUnixSeconds,
        bool protectedKeysHealthy)
    {
        ArgumentNullException.ThrowIfNull(cutover);
        ArgumentNullException.ThrowIfNull(dnrc);
        ArgumentNullException.ThrowIfNull(membership);
        ArgumentNullException.ThrowIfNull(contact);
        if (authoritativeReadGeneration == 0)
            Invalid("The transport authority read generation is zero.");
        if (!CanonicalGrammar.FixedEquals(cutover.TrustedNetwork, membership.TrustedNetworkId) ||
            !CanonicalGrammar.FixedEquals(cutover.TrustedResetId, membership.TrustedResetId) ||
            !CanonicalGrammar.FixedEquals(dnrc.RouterId.Span, contact.RouterId.Span))
            Invalid("The transport authority facts belong to different scopes.");
        var contactRecord = CanonicalGrammar.DecodeOwned(
            contact.TrustedCanonical, RecordDefinitions.Dpc1);
        if (!CanonicalGrammar.FixedEquals(contactRecord.FieldSpan(3), dnrc.DnrArtifactReference.Span))
            Invalid("The transport DPC1 does not belong to the current DNRC.");
        VerifiedRouterEntry? router = null;
        foreach (var candidate in membership.TrustedRouters)
        {
            if (!CanonicalGrammar.FixedEquals(candidate.RouterId, dnrc.RouterId.Span)) continue;
            if (router is not null) Invalid("The transport MRLC has a duplicate router ID.");
            router = candidate;
        }
        if (router is null ||
            !CanonicalGrammar.FixedEquals(router.DnrReference, dnrc.DnrArtifactReference.Span) ||
            !CanonicalGrammar.FixedEquals(router.AnchorDpcReference, contact.TrustedAnchorReference))
            Invalid("The transport DNRC/DPC1 facts are absent from the exact MRLC tuple.");

        Cutover = cutover;
        Dnrc = dnrc;
        Membership = membership;
        Contact = contact;
        AuthoritativeReadGeneration = authoritativeReadGeneration;
        TransactionTimeUnixSeconds = transactionTimeUnixSeconds;
        ProtectedKeysHealthy = protectedKeysHealthy;
        _cutoverSource = cutover.SourceFingerprint.ToArray();
        _drsReference = cutover.TrustedDrsRef.ToArray();
        _drsHead = cutover.TrustedDrsHead.ToArray();
        _witnessLkgReference = cutover.TrustedDwlRef.ToArray();
        _dnrcSource = dnrc.SourceFingerprint.ToArray();
        _dnrReference = dnrc.DnrArtifactReference.ToArray();
        _membershipRoot = membership.MembershipRoot.ToArray();
        _placementCommitment = membership.PlacementCommitment.ToArray();
        _dpcReference = contact.ArtifactReference.ToArray();
    }

    internal CurrentCutoverRelative Cutover { get; }
    internal CurrentDnrcRelative Dnrc { get; }
    internal VerifiedMembershipRoutingLkg Membership { get; }
    internal VerifiedRouterContact Contact { get; }
    public ulong AuthoritativeReadGeneration { get; }
    public ulong TransactionTimeUnixSeconds { get; }
    public bool ProtectedKeysHealthy { get; }
    public bool NoAuthorityClaim => true;

    internal void EnsureUsable()
    {
        var now = TransactionTimeUnixSeconds;
        if (!ProtectedKeysHealthy || now >= Cutover.LeaseExpiresAtUnixSeconds ||
            now >= Membership.EpochExpiresAtUnixSeconds ||
            now < Dnrc.Certificate.IssuedAtUnixSeconds ||
            now >= Dnrc.Certificate.ExpiresAtUnixSeconds ||
            now < Contact.IssuedAtUnixSeconds || now >= Contact.ExpiresAtUnixSeconds)
            throw new RecordException(
                RecordError.Expired,
                "The transport authority or protected key health is not current.");
    }

    internal bool SameAuthority(DpcTransportAuthoritySnapshot other) =>
        other is not null &&
        AuthoritativeReadGeneration == other.AuthoritativeReadGeneration &&
        CanonicalGrammar.FixedEquals(_cutoverSource, other._cutoverSource) &&
        CanonicalGrammar.FixedEquals(_drsReference, other._drsReference) &&
        CanonicalGrammar.FixedEquals(_drsHead, other._drsHead) &&
        CanonicalGrammar.FixedEquals(_witnessLkgReference, other._witnessLkgReference) &&
        CanonicalGrammar.FixedEquals(_dnrcSource, other._dnrcSource) &&
        CanonicalGrammar.FixedEquals(_dnrReference, other._dnrReference) &&
        CanonicalGrammar.FixedEquals(_membershipRoot, other._membershipRoot) &&
        CanonicalGrammar.FixedEquals(_placementCommitment, other._placementCommitment) &&
        CanonicalGrammar.FixedEquals(_dpcReference, other._dpcReference);

    [DoesNotReturn]
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class DpcTransportAuthorityReadRequest
{
    private readonly byte[] _routerId;

    internal DpcTransportAuthorityReadRequest(ReadOnlySpan<byte> routerId) =>
        _routerId = routerId.ToArray();

    public ReadOnlyMemory<byte> RouterId => _routerId.ToArray();
    public bool RequireCurrentDpcDnrMrlcDrsWitnessAndKeyHealth => true;
}

public interface IDpcTransportAuthorityReader
{
    ValueTask<DpcTransportAuthoritySnapshot> ReadCurrentAsync(
        DpcTransportAuthorityReadRequest request,
        CancellationToken cancellationToken = default);
}

public sealed class DpcTransportResult
{
    private readonly byte[] _responseFrame;

    internal DpcTransportResult(
        VerifiedNativePeerResponse verifiedResponse,
        ReadOnlySpan<byte> responseFrame)
    {
        VerifiedResponse = verifiedResponse;
        _responseFrame = responseFrame.ToArray();
    }

    public VerifiedNativePeerResponse VerifiedResponse { get; }
    public ReadOnlyMemory<byte> ExactResponseFrame => _responseFrame.ToArray();
    public bool NoDeliveryOrDurabilityClaim => true;
}

/// <summary>
/// One-shot resolve/connect/TLS/send boundary with an authoritative zero-byte final gate.
/// Construction is internal so a request caller cannot inject a resolver, connector or policy.
/// </summary>
public sealed class DpcIsolatedPeerClient
{
    private readonly TimeSpan _operationTimeout;
    private readonly IDpcTransportAuthorityReader _authorityReader;
    private readonly ITypedDnsResolver _resolver;
    private readonly ITypedPeerConnector _connector;

    internal DpcIsolatedPeerClient(
        TimeSpan operationTimeout,
        IDpcTransportAuthorityReader authorityReader,
        ITypedDnsResolver resolver,
        ITypedPeerConnector connector)
    {
        ArgumentNullException.ThrowIfNull(authorityReader);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(connector);
        if (operationTimeout <= TimeSpan.Zero || operationTimeout.TotalMilliseconds > int.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(operationTimeout));
        _operationTimeout = operationTimeout;
        _authorityReader = authorityReader;
        _resolver = resolver;
        _connector = connector;
    }

    public async ValueTask<DpcTransportResult> SendAsync(
        VerifiedNativePeerRequest request,
        DpcTransportAuthoritySnapshot initialAuthority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(initialAuthority);
        initialAuthority.EnsureUsable();
        BindRequestDestination(request, initialAuthority);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(_operationTimeout);
        var token = deadline.Token;
        var readRequest = new DpcTransportAuthorityReadRequest(
            initialAuthority.Contact.RouterId.Span);
        var beforeResolve = await _authorityReader.ReadCurrentAsync(readRequest, token)
            .ConfigureAwait(false);
        RequireUnchanged(initialAuthority, beforeResolve);

        IReadOnlyList<CanonicalIpAddress> addresses;
        byte[] sni;
        var contact = initialAuthority.Contact;
        switch (contact.EndpointKind)
        {
            case EndpointKind.Ipv4:
            case EndpointKind.Ipv6:
                var direct = new CanonicalIpAddress(contact.Address.Span);
                if ((contact.EndpointKind == EndpointKind.Ipv4) !=
                    (direct.Family == CanonicalAddressFamily.Ipv4))
                    Invalid("The DPC1 direct endpoint kind and address differ.");
                DpcAddressPolicy.EnsurePublicUnicast(direct);
                addresses = new[] { direct };
                sni = [];
                break;
            case EndpointKind.Dns:
                DpcAddressPolicy.ValidateDnsName(contact.Address.Span);
                var resolved = await _resolver.ResolveOnceAsync(
                    new DnsResolutionRequest(contact.Address.Span), token).ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                addresses = DpcAddressPolicy.FreezeAndValidate(resolved);
                sni = contact.Address.ToArray();
                break;
            default:
                Invalid("The DPC1 endpoint kind is unknown.");
                throw new InvalidOperationException();
        }

        var beforeConnect = await _authorityReader.ReadCurrentAsync(readRequest, token)
            .ConfigureAwait(false);
        RequireUnchanged(initialAuthority, beforeConnect);
        token.ThrowIfCancellationRequested();

        IFreshPeerTransport? transport = null;
        try
        {
            transport = await _connector.ConnectTlsAsync(
                new IsolatedConnectionRequest(addresses, sni, contact.Port), token)
                .ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (transport is null || !DpcAddressPolicy.Contains(addresses, transport.RemoteAddress))
                Invalid("The connected remote IP is outside the frozen DPC1 address set.");
            var spki = transport.TlsSpkiSha256.ToArray();
            var pinMatches = spki.Length == 32 &&
                (CanonicalGrammar.FixedEquals(spki, contact.CurrentTlsSpkiSha256.Span) ||
                 (!CanonicalGrammar.IsZero(contact.NextTlsSpkiSha256.Span) &&
                  CanonicalGrammar.FixedEquals(spki, contact.NextTlsSpkiSha256.Span)));
            if (!pinMatches) Invalid("The TLS SPKI does not match the exact DPC1 pins.");

            // No callback or await is permitted between this authoritative read and Send.
            var final = await _authorityReader.ReadCurrentAsync(readRequest, token).ConfigureAwait(false);
            RequireUnchanged(initialAuthority, final);
            BindRequestDestination(request, final);
            token.ThrowIfCancellationRequested();
            var body = CreateRequestFrame(request);
            var response = await transport.SendNativeMailboxAsync(body, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (response.IsRedirect || response.IsCompressed || response.StatusCode != 200 ||
                response.Body.Length != NativePeerVerifier.ResponseLength)
                Invalid("The native peer HTTP response failed its closed transport contract.");
            var responseBytes = response.Body.ToArray();
            var verified = NativePeerVerifier.VerifyResponse(
                responseBytes, request, final.TransactionTimeUnixSeconds);
            return new DpcTransportResult(verified, responseBytes);
        }
        finally
        {
            if (transport is not null)
            {
                try { await transport.CloseAsync(CancellationToken.None).ConfigureAwait(false); }
                finally { await transport.DisposeAsync().ConfigureAwait(false); }
            }
        }
    }

    private static void RequireUnchanged(
        DpcTransportAuthoritySnapshot expected,
        DpcTransportAuthoritySnapshot observed)
    {
        if (observed is null || !expected.SameAuthority(observed))
            Invalid("The DPC/DNR/MRLC/DRS/witness authority changed during transport.");
        observed.EnsureUsable();
    }

    private static void BindRequestDestination(
        VerifiedNativePeerRequest request,
        DpcTransportAuthoritySnapshot authority)
    {
        var dpr = CanonicalGrammar.DecodeOwned(request.TrustedDpr, RecordDefinitions.Dpr1);
        if (!CanonicalGrammar.FixedEquals(dpr.FieldSpan(3), authority.Contact.RouterId.Span) ||
            !CanonicalGrammar.FixedEquals(dpr.FieldSpan(5), authority.Contact.ArtifactReference.Span) ||
            !CanonicalGrammar.FixedEquals(dpr.FieldSpan(1), authority.Membership.TrustedNetworkId))
            Invalid("The native request destination differs from current transport authority.");
    }

    private static byte[] CreateRequestFrame(VerifiedNativePeerRequest request)
    {
        var dpr = request.TrustedDpr;
        var prq = request.TrustedPrq;
        var frame = new byte[8 + dpr.Length + prq.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)dpr.Length);
        dpr.CopyTo(frame.AsSpan(4));
        var offset = 4 + dpr.Length;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(
            frame.AsSpan(offset), (uint)prq.Length);
        prq.CopyTo(frame.AsSpan(offset + 4));
        return frame;
    }

    [DoesNotReturn]
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidTransition, message);
}

internal static class DpcAddressPolicy
{
    internal static IReadOnlyList<CanonicalIpAddress> FreezeAndValidate(
        IReadOnlyList<CanonicalIpAddress>? returned)
    {
        if (returned is null || returned.Count is < 1 or > 16)
            Invalid("DNS must return between one and sixteen addresses.");
        var owned = new List<CanonicalIpAddress>(returned.Count);
        foreach (var candidate in returned)
        {
            if (candidate is null) Invalid("DNS returned a null address.");
            var copy = new CanonicalIpAddress(candidate!.TrustedBytes);
            EnsurePublicUnicast(copy);
            if (owned.Any(existing => existing.Equals(copy)))
                Invalid("DNS returned a duplicate canonical address.");
            owned.Add(copy);
        }
        owned.Sort(Compare);
        return owned.AsReadOnly();
    }

    internal static void ValidateDnsName(ReadOnlySpan<byte> name)
    {
        if (name.Length is < 3 or > 253 || name.IndexOf((byte)'.') < 1)
            Invalid("The DPC1 DNS name length or label count is invalid.");
        var labelLength = 0;
        var labelStart = 0;
        for (var index = 0; index <= name.Length; index++)
        {
            if (index < name.Length && name[index] != (byte)'.')
            {
                var value = name[index];
                var allowed = value is >= (byte)'a' and <= (byte)'z' or
                    >= (byte)'0' and <= (byte)'9' or (byte)'-';
                if (!allowed) Invalid("The DPC1 DNS name is not canonical lower-case LDH ASCII.");
                labelLength++;
                continue;
            }
            if (labelLength is < 1 or > 63 || name[labelStart] == (byte)'-' ||
                name[index - 1] == (byte)'-')
                Invalid("The DPC1 DNS label is invalid.");
            labelStart = index + 1;
            labelLength = 0;
        }
    }

    internal static void EnsurePublicUnicast(CanonicalIpAddress address)
    {
        var bytes = address.TrustedBytes;
        if (address.Family == CanonicalAddressFamily.Ipv4)
        {
            if (Prefix(bytes, [0], 8) || Prefix(bytes, [10], 8) ||
                Prefix(bytes, [100, 64], 10) || Prefix(bytes, [127], 8) ||
                Prefix(bytes, [169, 254], 16) || Prefix(bytes, [172, 16], 12) ||
                Prefix(bytes, [192, 0, 0], 24) || Prefix(bytes, [192, 0, 2], 24) ||
                Prefix(bytes, [192, 88, 99], 24) || Prefix(bytes, [192, 168], 16) ||
                Prefix(bytes, [198, 18], 15) || Prefix(bytes, [198, 51, 100], 24) ||
                Prefix(bytes, [203, 0, 113], 24) || Prefix(bytes, [224], 4) ||
                Prefix(bytes, [240], 4))
                Invalid("The DPC1 IPv4 address is not public unicast.");
            return;
        }
        if (!Prefix(bytes, [0x20], 3) || Prefix(bytes, [0x20, 0x01, 0x00], 23) ||
            Prefix(bytes, [0x20, 0x01, 0x0d, 0xb8], 32) ||
            Prefix(bytes, [0x3f, 0xff, 0x00], 20))
            Invalid("The DPC1 IPv6 address is not public unicast.");
    }

    internal static bool Contains(
        IReadOnlyList<CanonicalIpAddress> set,
        CanonicalIpAddress candidate) => set.Any(candidate.Equals);

    private static int Compare(CanonicalIpAddress left, CanonicalIpAddress right)
    {
        var family = ((byte)left.Family).CompareTo((byte)right.Family);
        return family != 0 ? family : left.TrustedBytes.SequenceCompareTo(right.TrustedBytes);
    }

    private static bool Prefix(ReadOnlySpan<byte> address, ReadOnlySpan<byte> prefix, int bits)
    {
        var whole = bits / 8;
        if (!address[..whole].SequenceEqual(prefix[..whole])) return false;
        var remainder = bits % 8;
        if (remainder == 0) return true;
        var mask = (byte)(0xff << (8 - remainder));
        return (address[whole] & mask) == (prefix[whole] & mask);
    }

    [DoesNotReturn]
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
