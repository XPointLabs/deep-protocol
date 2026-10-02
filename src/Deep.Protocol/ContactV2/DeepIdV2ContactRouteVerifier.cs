using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.DeepNative;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Bounded threshold records only. Parsing does not authenticate a
/// witness, recipient, network or publication.</summary>
public sealed class ParsedDeepIdV2RouteThreshold
{
    public ParsedDeepIdV2RouteThreshold(ReadOnlySpan<byte> exactPms2,
        ReadOnlySpan<byte> exactXrc1, ReadOnlySpan<byte> exactXss1)
    {
        Selection = ContactCodec.Decode(ProtocolMagic.PMS2, exactPms2);
        LiveRoute = ContactCodec.Decode(ProtocolMagic.XRC1, exactXrc1);
        Successor = ContactCodec.Decode(ProtocolMagic.XSS1, exactXss1);
    }
    public ContactRecord Selection { get; }
    public ContactRecord LiveRoute { get; }
    public ContactRecord Successor { get; }
}

/// <summary>Read-only authenticated route time; not a caller clock or signing capability.</summary>
public sealed class DeepIdV2ContactRouteTimeWindow
{
    private readonly byte[] bootId;
    internal DeepIdV2ContactRouteTimeWindow(ulong lower, ulong upper, OnionMonotonicReading reading)
    { LowerUnixSeconds = lower; UpperUnixSeconds = upper; bootId = reading.BootId.ToArray(); MonotonicSample = reading.SampleSeconds; }
    public ulong LowerUnixSeconds { get; }
    public ulong UpperUnixSeconds { get; }
    public ReadOnlyMemory<byte> BootId => bootId.ToArray();
    public ulong MonotonicSample { get; }
}

/// <summary>DID2-only exact current route, not publication, consent, a grant,
/// semantic ACK or delivery. No public/caller-key construction path.</summary>
public sealed class VerifiedDeepIdV2ContactRouteClosure
{
    private readonly OnionTrustedTimeAuthority time;
    internal VerifiedDeepIdV2ContactRouteClosure(ParsedXir1V2 invite,
        ParsedContactRouteClosure route, DeepIdV2CurrentContactAuthorization recipient,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority time)
    { Invite = invite; Route = route; Recipient = recipient; Network = network; NetworkAuthority = authority; this.time = time; }

    public ParsedXir1V2 Invite { get; }
    public ParsedContactRouteClosure Route { get; }
    public DeepIdV2CurrentContactAuthorization Recipient { get; }
    public VerifiedOnionNetworkContext Network { get; }
    public VerifiedXPointNetworkAuthority NetworkAuthority { get; }
    public ReadOnlyMemory<byte> ExactXir1V2 => Invite.CanonicalBytes;
    public ReadOnlyMemory<byte> ExactRouteClosure => Route.ExactBytes;

    internal ValueTask<OnionMonotonicReading> ReadPublicationClockAsync(CancellationToken ct) =>
        time.ReadCurrentAsync(ct);

    internal DeepIdV2ContactRouteTimeWindow VerifyAtReading(OnionMonotonicReading reading, CancellationToken ct)
    {
        var current = DeepIdV2RouteContext.VerifyAtReading(Recipient, Network, NetworkAuthority, time, reading, ct);
        DeepIdV2ContactRouteVerifier.RequireBindings(Invite, Route, current);
        return new(current.Lower, current.Upper, current.Reading);
    }

    public async ValueTask EnsureCurrentAsync(CancellationToken cancellationToken = default)
    { _ = await ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false); }

    public async ValueTask<DeepIdV2ContactRouteTimeWindow> ReadCurrentTimeAsync(
        CancellationToken cancellationToken = default)
    {
        var current = await DeepIdV2RouteContext.ReadAsync(Recipient, Network,
            NetworkAuthority, time, cancellationToken).ConfigureAwait(false);
        DeepIdV2ContactRouteVerifier.RequireBindings(Invite, Route, current);
        return new(current.Lower, current.Upper, current.Reading);
    }
}

public static class DeepIdV2ContactRouteVerifier
{
    /// <summary>Validates an exact DID2 device proposal before contacting an
    /// authority. This does not mint signing, publication or route authority.</summary>
    public static async ValueTask VerifyAdvertisementAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ReadOnlyMemory<byte> exactXra1,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (exactXra1.Length != 550) throw new CryptographicException("XRA1 must have its exact bounded size.");
        var xra = ContactCodec.Decode(ProtocolMagic.XRA1, exactXra1.Span);
        var first = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, trustedTime,
            cancellationToken).ConfigureAwait(false);
        first.RequireAdvertisement(xra);
        var final = await first.RecheckAsync(cancellationToken).ConfigureAwait(false);
        final.RequireAdvertisement(xra);
    }

    /// <summary>Validates an untrusted threshold before durable adoption.
    /// This grants no route, publication, signing, mutation or dispatch capability.</summary>
    public static async ValueTask VerifyThresholdAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ReadOnlyMemory<byte> exactXra1,
        ParsedDeepIdV2RouteThreshold threshold, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(threshold);
        cancellationToken.ThrowIfCancellationRequested();
        if (exactXra1.Length != 550) throw new CryptographicException("XRA1 must have its exact bounded size.");
        var xra = ContactCodec.Decode(ProtocolMagic.XRA1, exactXra1.Span);
        var first = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority,
            trustedTime, cancellationToken).ConfigureAwait(false);
        first.RequireAdvertisement(xra);
        first.RequireThreshold(xra, threshold.Selection, threshold.LiveRoute, threshold.Successor);
        var final = await first.RecheckAsync(cancellationToken).ConfigureAwait(false);
        final.RequireAdvertisement(xra);
        final.RequireThreshold(xra, threshold.Selection, threshold.LiveRoute, threshold.Successor);
    }

    public static async ValueTask<VerifiedDeepIdV2ContactRouteClosure> VerifyAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ReadOnlyMemory<byte> exactXir1V2,
        ReadOnlyMemory<byte> exactSixRecordClosure, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (exactXir1V2.Length != DeepIdV2InviteRendezvousCodec.CanonicalLength ||
            exactSixRecordClosure.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes)
            throw new CryptographicException("The DID2 invite/route sizes are outside their exact bounds.");
        // Codecs own all inputs before the first await. No V1 invite fallback.
        var invite = DeepIdV2InviteRendezvousCodec.Decode(exactXir1V2.Span);
        var route = ContactRouteClosureCodec.Decode(exactSixRecordClosure.Span);
        var first = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority,
            trustedTime, cancellationToken).ConfigureAwait(false);
        RequireBindings(invite, route, first);
        ContactCodec.VerifyDeviceSignature(route.Reachability, first.Device.Certificate.DeviceEd25519PublicKey.Span);
        var final = await first.RecheckAsync(cancellationToken).ConfigureAwait(false);
        RequireBindings(invite, route, final);
        return new(invite, route, recipient, network, authority, trustedTime);
    }

    internal static void RequireBindings(ParsedXir1V2 invite,
        ParsedContactRouteClosure route, DeepIdV2RouteContext current)
    {
        var xra = route.Authorization; var xrr = route.Reachability;
        if (!DeepIdV2RouteContext.Fixed(route.Projection.CanonicalBytes.Span, current.Pmt.CanonicalBytes.Span))
            throw new CryptographicException("The route PMT2 differs from the exact verified network projection.");
        current.RequireAdvertisement(xra);
        current.RequireThreshold(xra, route.Selection, route.Route, route.Successor, requireCurrentDirectory: false);
        if (!DeepIdV2RouteContext.Fixed(invite.FieldSpan(1), current.Network.NetworkId.Span) ||
            !DeepIdV2RouteContext.Fixed(invite.FieldSpan(5), current.PmtReference.Span) ||
            !DeepIdV2RouteContext.Fixed(invite.FieldSpan(18), ContactCodec.ArtifactReference(ProtocolMagic.XRA1, xra).CanonicalBytes.Span) ||
            !DeepIdV2RouteContext.Fixed(invite.FieldSpan(6), xra.FieldSpan(6)) ||
            !DeepIdV2RouteContext.Fixed(invite.FieldSpan(7), xra.FieldSpan(10)) ||
            !DeepIdV2RouteContext.Fixed(invite.FieldSpan(8), xra.FieldSpan(11)) ||
            !DeepIdV2RouteContext.Fixed(invite.FieldSpan(12), xra.FieldSpan(9)) ||
            !DeepIdV2RouteContext.Fixed(invite.FieldSpan(13), xra.FieldSpan(12)) ||
            !DeepIdV2RouteContext.Fixed(invite.FieldSpan(14), xra.FieldSpan(13)) ||
            !DeepIdV2RouteContext.Fixed(invite.FieldSpan(15), current.DeviceReference.Span) ||
            !DeepIdV2RouteContext.Fixed(invite.FieldSpan(16), current.DcaReference.Span) ||
            !DeepIdV2RouteContext.Fixed(xrr.FieldSpan(18), current.DeviceReference.Span) ||
            !DeepIdV2RouteContext.Fixed(xrr.FieldSpan(10), route.Route.FieldSpan(10)) ||
            !DeepIdV2RouteContext.Fixed(xrr.FieldSpan(11), xra.FieldSpan(9)) ||
            !DeepIdV2RouteContext.Fixed(xrr.FieldSpan(13), xra.FieldSpan(8)))
            throw new CryptographicException("The DID2 invite/reachability differs from its exact device, delegation or route scope.");
        current.Covers(DeepIdV2RouteContext.U64(invite.FieldSpan(13)), DeepIdV2RouteContext.U64(invite.FieldSpan(14)), DeepIdV2RouteTimeArtifact.Xir1V2);
        current.Covers(DeepIdV2RouteContext.U64(xrr.FieldSpan(16)), DeepIdV2RouteContext.U64(xrr.FieldSpan(17)), DeepIdV2RouteTimeArtifact.Xrr1);
        // Structural framing already validates every exact route graph reference.
        DeepIdV2InviteRendezvousCodec.VerifyIssuerAndDca1(invite, current.Recipient.Authorization, current.Upper);
    }
    internal static void RequireBundleIssuanceAnchor(VerifiedDeepIdV2ContactRouteClosure route, ParsedDcb1V2 bundle)
    {
        var minimum = bundle.Field(21).Span;
        var current = route.Recipient.Freshness.NextProtectedLkg;
        var generation = DeepIdV2RouteContext.U64(minimum);
        if (!DeepIdV2RouteContext.Fixed(minimum[8..], route.Route.Route.FieldSpan(19)[6..]) ||
            generation > current.LogGeneration ||
            (generation == current.LogGeneration && !DeepIdV2RouteContext.Fixed(minimum[8..], current.CoreHash.Span)))
            throw new CryptographicException("Contact minimum checkpoint differs from its signed route issuance anchor or current verified floor.");
    }
}

internal sealed class DeepIdV2RouteContext
{
    private readonly OnionTrustedTimeAuthority time;
    private readonly OnionMonotonicReading reading;
    private DeepIdV2RouteContext(DeepIdV2CurrentContactAuthorization recipient,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority time, OnionMonotonicReading reading, VerifiedDevice device,
        ulong lower, ulong upper)
    {
        Recipient = recipient; Network = network; Authority = authority; this.time = time;
        this.reading = reading; Device = device; Lower = lower; Upper = upper;
    }
    internal DeepIdV2CurrentContactAuthorization Recipient { get; }
    internal VerifiedOnionNetworkContext Network { get; }
    internal VerifiedXPointNetworkAuthority Authority { get; }
    internal VerifiedDevice Device { get; }
    internal OnionMonotonicReading Reading => reading;
    internal ulong Lower { get; }
    internal ulong Upper { get; }
    internal ContactRecord Pmt => Network.Closure!.Pmt;
    internal ReadOnlyMemory<byte> PmtReference => Network.Closure!.PmtArtifactReference.ToArray();
    internal ReadOnlyMemory<byte> DeviceReference => new ContactArtifactReference(ProtocolMagic.DPD1, 1,
        Device.Certificate.CanonicalHash.Span).CanonicalBytes;
    internal ReadOnlyMemory<byte> DcaReference => new ContactArtifactReference(ProtocolMagic.DCA1, 2,
        Recipient.Authorization.Record.RecordHash.Span).CanonicalBytes;
    internal ReadOnlyMemory<byte> ViewReference => Network.Closure!.ViewCoreReference.ToArray();
    internal ReadOnlyMemory<byte> HeadReference => XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNH1, Network.Closure!.Head.CoreHash.Span);
    internal ReadOnlyMemory<byte> DirectoryReference => Network.Closure!.Adh1CoreReference.ToArray();

    internal static async ValueTask<DeepIdV2RouteContext> ReadAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, OnionTrustedTimeAuthority time, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(recipient); ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(authority); ArgumentNullException.ThrowIfNull(time);
        ct.ThrowIfCancellationRequested();
        var reading = await time.ReadCurrentAsync(ct).ConfigureAwait(false);
        return VerifyAtReading(recipient, network, authority, time, reading, ct);
    }

    // Pure release-time verification of the already captured clock sample:
    // no extra clock callback can move expiry past our final validation.
    internal static DeepIdV2RouteContext VerifyAtReading(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, OnionTrustedTimeAuthority time,
        OnionMonotonicReading reading, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); network.EnsureCurrent();
        var closure = network.Closure!;
        var fresh = recipient.Freshness;
        var current = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh,
            recipient.Authorization, reading.BootId.Span, reading.SampleSeconds);
        var dtt = AccountDirectoryDtt1Codec.Decode(fresh.ExactDtt1.Span);
        var head = AccountDirectoryAdh1Codec.Decode(fresh.ExactAdh1.Span);
        if (!Fixed(network.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(network.NetworkId.Span, fresh.NetworkId.Span) ||
            !Fixed(closure.View.FieldSpan(7), authority.AuthorityCoreReference.Span) ||
            !Fixed(closure.Head.FieldSpan(8), authority.AuthorityCoreReference.Span) ||
            !Fixed(head.ExactXnaAuthorityCoreReference.Span, authority.AuthorityCoreReference.Span) ||
            !Fixed(dtt.AuthorizingXna1CoreReference.Span, authority.AuthorityCoreReference.Span) ||
            !Fixed(head.WitnessPolicyHash.Span, authority.DirectoryWitnessPolicyHash.Span) ||
            !Fixed(dtt.WitnessPolicyHash.Span, authority.DirectoryWitnessPolicyHash.Span) ||
            !Fixed(((IVerifiedDirectoryNetworkTime)fresh).ExactAdh1CoreReference.Span, closure.Adh1CoreReference) ||
            !Fixed(dtt.CurrentXnv1CoreHash.Span, closure.View.CoreHash.Span) ||
            dtt.CurrentXnv1Generation != closure.View.ViewGeneration ||
            !Fixed(reading.BootId.Span, closure.FreshnessBootId) ||
            reading.SampleSeconds < closure.FreshnessMonotonicSample ||
            reading.SampleSeconds >= closure.FreshnessDeadlineMonotonicSeconds)
            throw new CryptographicException("The current DID2 recipient and network do not share exact directory/view authority.");
        ulong lower, upper;
        try
        {
            var elapsed = checked(reading.SampleSeconds - closure.FreshnessMonotonicSample);
            lower = Math.Min(current.TrustedLowerUnixSeconds, checked(closure.TrustedLowerUnixSeconds + elapsed));
            upper = Math.Max(current.TrustedUpperUnixSeconds, checked(closure.TrustedUpperUnixSeconds + elapsed));
        }
        catch (OverflowException error) { throw new CryptographicException("The route trusted-time projection overflowed.", error); }
        var device = recipient.Authorization.Binding.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.Certificate.DeviceId.Span, recipient.Authorization.Record.PublisherDeviceId.Span)) ??
            throw new CryptographicException("The route publisher is not an active DID2 device.");
        var result = new DeepIdV2RouteContext(recipient, network, authority, time, reading, device, lower, upper);
        result.Covers(authority.NotBefore, authority.ExpiresAt, DeepIdV2RouteTimeArtifact.Xna1);
        result.Covers(closure.View.NotBefore, closure.View.ExpiresAt, DeepIdV2RouteTimeArtifact.Xnv1);
        result.Covers(closure.Head.ValidFrom, closure.Head.ValidUntil, DeepIdV2RouteTimeArtifact.Xnh1);
        result.Covers(head.ValidFrom, head.ValidUntil, DeepIdV2RouteTimeArtifact.Adh1);
        result.Covers(device.Certificate.IssuedAtUnixSeconds, device.Certificate.ExpiresAtUnixSeconds, DeepIdV2RouteTimeArtifact.DeviceCertificate);
        result.Covers(recipient.Authorization.Record.NotBeforeUnixSeconds, recipient.Authorization.Record.ExpiresAtUnixSeconds, DeepIdV2RouteTimeArtifact.Dca1);
        result.Covers(U64(closure.Pmt.FieldSpan(11)), U64(closure.Pmt.FieldSpan(12)), DeepIdV2RouteTimeArtifact.Pmt2);
        return result;
    }

    internal async ValueTask<DeepIdV2RouteContext> RecheckAsync(CancellationToken ct)
    {
        var next = await ReadAsync(Recipient, Network, Authority, time, ct).ConfigureAwait(false);
        if (next.reading.SampleSeconds < reading.SampleSeconds ||
            !Fixed(next.reading.BootId.Span, reading.BootId.Span))
            throw new CryptographicException("Route authoring crossed a protected clock discontinuity.");
        return next;
    }
    internal void Covers(ulong start, ulong expiry, DeepIdV2RouteTimeArtifact artifact) =>
        DeepIdV2RouteTimeCoverage.Require(Lower, Upper, start, expiry, artifact);
    internal void RequireAdvertisement(ContactRecord xra)
    {
        if (xra.Magic != ProtocolMagic.XRA1 || !Fixed(xra.FieldSpan(1), Network.NetworkId.Span) ||
            !Fixed(xra.FieldSpan(5), PmtReference.Span) ||
            !Fixed(xra.FieldSpan(14), Device.Certificate.DeviceId.Span) ||
            !Fixed(xra.FieldSpan(15), DeviceReference.Span) ||
            Fixed(xra.FieldSpan(11), Device.Certificate.DeviceX25519PublicKey.Span) ||
            U64(xra.FieldSpan(12)) < Device.Certificate.IssuedAtUnixSeconds ||
            U64(xra.FieldSpan(12)) < Recipient.Authorization.Record.NotBeforeUnixSeconds ||
            U64(xra.FieldSpan(13)) > Device.Certificate.ExpiresAtUnixSeconds ||
            U64(xra.FieldSpan(13)) > Recipient.Authorization.Record.ExpiresAtUnixSeconds)
            throw new CryptographicException("The XRA1 proposal differs from current DID2 device/delegation scope.");
        Covers(U64(xra.FieldSpan(12)), U64(xra.FieldSpan(13)), DeepIdV2RouteTimeArtifact.Xra1);
        DeepIdV2ContactUpdateRendezvousAuthor.RequireAgreementKey(xra.FieldSpan(11));
        ContactCodec.VerifyDeviceSignature(xra, Device.Certificate.DeviceEd25519PublicKey.Span);
    }
    internal void RequireThreshold(ContactRecord xra, ContactRecord pms, ContactRecord xrc, ContactRecord xss,
        bool requireCurrentDirectory = true)
    {
        ContactCodec.ValidateThresholdRouteGraph(xra, xrc, xss, Pmt, pms);
        if (!Fixed(xrc.FieldSpan(8), ViewReference.Span) || !Fixed(xrc.FieldSpan(9), HeadReference.Span) ||
            !Fixed(xrc.FieldSpan(19), xss.FieldSpan(12)) ||
            (requireCurrentDirectory && !Fixed(xrc.FieldSpan(19), DirectoryReference.Span)) ||
            !Fixed(xss.FieldSpan(8), ViewReference.Span))
            throw new CryptographicException("The threshold route has stale or substituted current directory/network references.");
        for (var offset = 0; offset < pms.FieldSpan(6).Length; offset += 32)
            if (Network.ResolveNode(pms.FieldSpan(6).Slice(offset, 32)).KeyEpoch != U64(xrc.FieldSpan(13)))
                throw new CryptographicException("The live route names a different current node traffic-key epoch.");
        Covers(U64(pms.FieldSpan(8)), U64(pms.FieldSpan(9)), DeepIdV2RouteTimeArtifact.Pms2);
        Covers(U64(xrc.FieldSpan(17)), U64(xrc.FieldSpan(18)), DeepIdV2RouteTimeArtifact.Xrc1);
        Covers(U64(xss.FieldSpan(10)), U64(xss.FieldSpan(11)), DeepIdV2RouteTimeArtifact.Xss1);
        if (U64(xrc.FieldSpan(18)) > Network.Closure!.HardUpperUnixSeconds)
            throw new CryptographicException("The live route outlives its verified network/key closure.");
        VerifyWitnesses(pms, 11, Authority); VerifyWitnesses(xrc, 21, Authority); VerifyWitnesses(xss, 14, Authority);
    }
    internal static void VerifyWitnesses(ContactRecord record, int tag, VerifiedXPointNetworkAuthority authority)
    {
        var receipts = record.FieldSpan(tag);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        var ids = new HashSet<string>(StringComparer.Ordinal);
        for (var offset = 0; offset < receipts.Length; offset += 96)
        {
            var row = receipts.Slice(offset, 96);
            var id = row[..32].ToArray();
            var key = authority.WitnessKeys.SingleOrDefault(candidate => Fixed(candidate.Id.Span, id));
            if (key is null || !ids.Add(Convert.ToHexString(row[..32])) ||
                !domains.Add(Convert.ToHexString(key.FailureDomainHash.Span)) ||
                !PublicKeyAuth.VerifyDetached(row[32..].ToArray(), record.SignatureInput.ToArray(), key.Ed25519PublicKey.ToArray()))
                throw new CryptographicException("The route witness signature, identity or failure domain is invalid.");
        }
        if (ids.Count < authority.WitnessThreshold)
            throw new CryptographicException("The route has fewer current witnesses than the required threshold.");
    }
    internal static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    internal static ulong U64(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt64BigEndian(bytes);
}
