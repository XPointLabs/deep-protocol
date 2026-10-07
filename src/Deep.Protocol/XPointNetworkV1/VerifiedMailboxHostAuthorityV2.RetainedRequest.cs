using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>Captured current Retrieve request/time context for a retained
/// selection lookup. Not capability ownership, route provenance, issuance,
/// holder custody, replay, dispatch, object availability or deletion authority.</summary>
public sealed class VerifiedMailboxRetainedReadRequestV2
{
    private readonly VerifiedMailboxHostAuthorityV2 host;
    private readonly ContactRecord request;

    internal VerifiedMailboxRetainedReadRequestV2(VerifiedMailboxHostAuthorityV2 host,
        ContactRecord request)
    { this.host = host; this.request = request; }

    public ReadOnlyMemory<byte> ExactXmg2 => request.CanonicalBytes.ToArray();
    public ReadOnlyMemory<byte> ProjectionReference => request.Field(7).ToArray();
    public ReadOnlyMemory<byte> SelectionHash => request.Field(8).ToArray();
    public ReadOnlyMemory<byte> ExactRouteHash => request.Field(11).ToArray();

    /// <summary>Authenticated time from this original request's current host.
    /// No historical clock, route or caller time can replace it. Copied bounds
    /// alone cannot authorize a storage mutation or expiry deletion.</summary>
    public ValueTask<DeepIdV2ContactRouteTimeWindow> ReadCurrentTimeAsync(
        CancellationToken cancellationToken = default) =>
        host.ReadRetainedRequestTimeAsync(request, cancellationToken);

    public async ValueTask EnsureCurrentAsync(CancellationToken cancellationToken = default) =>
        _ = await ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
}

public sealed partial class VerifiedMailboxHostAuthorityV2
{
    /// <summary>Checks holder proof, current request window and an exact PMT2
    /// already in verified protected lineage before a retained route lookup.
    /// The PMS2 hash/capability are still unverified lookup inputs, not route
    /// or issuance authority. Deposit and expired requests are never accepted.</summary>
    public async ValueTask<VerifiedMailboxRetainedReadRequestV2> VerifyRetainedReadRequestAsync(
        ReadOnlyMemory<byte> exactXmg2, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (exactXmg2.Length != 435)
            throw new CryptographicException("A retained read requires an exact bounded XMG2.");
        var request = ContactCodec.Decode(ProtocolMagic.XMG2, exactXmg2.Span);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        RequireRetainedRequestSelection(request);
        _ = await ReadRetainedRequestTimeAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return new(this, request);
    }

    internal async ValueTask<DeepIdV2ContactRouteTimeWindow> ReadRetainedRequestTimeAsync(
        ContactRecord request, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        RequireRetainedRequestSelection(request);
        var firstReading = await time.ReadCurrentAsync(ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        RequireRetainedRequestWindow(request, ReadAtReading(firstReading));
        var finalReading = await time.ReadCurrentAsync(ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        var final = ReadAtReading(finalReading);
        RequireRetainedRequestWindow(request, final);
        return new(final.Lower, final.Upper, finalReading);
    }

    private void RequireRetainedRequestSelection(ContactRecord request)
    {
        network.EnsureCurrent();
        if (request.Field(6).Span[0] != (byte)MailboxCapabilityDomain.Retrieve ||
            !Fixed(request.Field(1).Span, network.NetworkId.Span))
            throw new CryptographicException("Retained read request is outside its current network/Retrieve role.");
        var matches = network.Closure!.RetainedPmts.Count(candidate => Fixed(
            ContactCodec.ArtifactReference(ProtocolMagic.PMT2, candidate).CanonicalBytes.Span,
            request.Field(7).Span));
        if (matches != 1)
            throw new CryptographicException("The request's exact projection is absent from verified protected lineage.");
    }

    private void RequireRetainedRequestWindow(ContactRecord request,
        (VerifiedMailboxAuthorityV2 Policy, ulong Lower, ulong Upper) current)
    {
        var start = BinaryPrimitives.ReadUInt64BigEndian(request.Field(9).Span);
        var expiry = BinaryPrimitives.ReadUInt64BigEndian(request.Field(10).Span);
        if (expiry <= start || expiry - start > 120 ||
            expiry > current.Policy.ExpiresAtUnixSeconds ||
            expiry > network.MaximumRecordExpiryUnixSeconds ||
            start > current.Lower || current.Upper >= expiry)
            throw new CryptographicException("Retained read request does not cover the full current authority/time interval.");
    }
}
