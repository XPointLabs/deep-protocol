using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>Real current Retrieve issuer signature bound to the captured original
/// path and holder request. Not owner custody, installation, dispatch or ACK.</summary>
public sealed class VerifiedMailboxRetainedReadGrantV2
{
    private readonly VerifiedMailboxHostAuthorityV2 host;
    private readonly ContactRecord request, response;
    private readonly ParsedContactRouteClosure route;
    private readonly ulong horizonCeiling;

    internal VerifiedMailboxRetainedReadGrantV2(VerifiedMailboxHostAuthorityV2 host,
        ContactRecord request, ContactRecord response, ParsedContactRouteClosure route, ulong horizonCeiling)
    { this.host = host; this.request = request; this.response = response; this.route = route; this.horizonCeiling = horizonCeiling; }

    public ReadOnlyMemory<byte> ExactXmg2 => request.CanonicalBytes.ToArray();
    public ReadOnlyMemory<byte> ExactXmc2 => response.CanonicalBytes.ToArray();
    public ReadOnlyMemory<byte> ExactGrant => response.Field(8).ToArray();
    public ReadOnlyMemory<byte> ExactPma2 => host.RetainedReadPolicyBytes;
    public ReadOnlyMemory<byte> MembershipCommitment => route.Projection.ArtifactHash.ToArray();
    public MailboxCapabilityDomain Domain => MailboxCapabilityDomain.Retrieve;

    public ValueTask EnsureCurrentAsync(CancellationToken cancellationToken = default) =>
        host.RequireRetainedReadSuccessAsync(request, response, route, horizonCeiling, cancellationToken);
}

public sealed partial class VerifiedMailboxHostAuthorityV2
{
    internal ReadOnlyMemory<byte> RetainedReadPolicyBytes => pma.CanonicalBytes.ToArray();

    /// <summary>Signs only an untrusted bounded Retrieve request. Original owner
    /// route/capability/holder custody remains mandatory in the account operation;
    /// this does not verify historical admission or authorize issuance/Store.</summary>
    public async ValueTask<AuthoredMailboxGrantRequest> AuthorRetainedReadRequestAsync(
        ReadOnlyMemory<byte> exactOriginalRoute, ReadOnlyMemory<byte> locatorHash,
        ReadOnlyMemory<byte> ownerRetrieveCapability, IReachabilityMailboxHolderSigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signer); cancellationToken.ThrowIfCancellationRequested();
        var route = CaptureRetainedRoute(exactOriginalRoute);
        RequireClient32(locatorHash.Span); RequireClient32(ownerRetrieveCapability.Span);
        if (Fixed(ownerRetrieveCapability.Span, route.Reachability.Field(10).Span))
            throw new CryptographicException("A public Deposit capability cannot authorize retained Retrieve.");
        var exposed = signer.Ed25519PublicKey; RequireClient32(exposed.Span);
        var locator = locatorHash.ToArray(); var capability = ownerRetrieveCapability.ToArray(); var holder = exposed.ToArray();
        var signature = new byte[64];
        try
        {
            var first = await ReadAsync(cancellationToken).ConfigureAwait(false);
            var start = first.Lower;
            var horizonCeiling = RetainedRouteHorizonCeiling(route);
            var expiry = new[] { checked(start + 120), first.Policy.ExpiresAtUnixSeconds,
                network.MaximumRecordExpiryUnixSeconds, network.Closure!.HardUpperUnixSeconds, horizonCeiling }.Min();
            if (first.Upper >= expiry) throw new CryptographicException("Retained request has no complete current window.");
            var operation = new byte[32];
            do RandomNumberGenerator.Fill(operation); while (operation.AsSpan().IndexOfAnyExcept((byte)0) < 0);
            var placeholder = new byte[64]; placeholder[^1] = 1;
            ReadOnlyMemory<byte>[] fields = [network.NetworkId, operation, locator, capability, holder,
                new byte[] { (byte)MailboxCapabilityDomain.Retrieve },
                ContactCodec.ArtifactReference(ProtocolMagic.PMT2, route.Projection).CanonicalBytes,
                route.Selection.ArtifactHash, RetainedU64Bytes(start), RetainedU64Bytes(expiry), route.ExactHash, placeholder];
            var unsigned = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XMG2, fields);
            RequireRetainedRouteScope(unsigned, route, RetainedRouteHorizonCeiling(route));
            _ = await ReadRetainedRequestTimeAsync(unsigned, cancellationToken).ConfigureAwait(false);
            var written = await signer.SignMailboxGrantRequestAsync(unsigned.SignatureInput.ToArray(), signature, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (written != 64 || !PublicKeyAuth.VerifyDetached(signature, unsigned.SignatureInput.ToArray(), holder))
                throw new CryptographicException("Retained holder returned an invalid proof of possession.");
            fields[11] = signature;
            var exact = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XMG2, fields);
            ContactCodec.VerifyMailboxGrantHolderSignature(exact);
            _ = await ReadRetainedRequestTimeAsync(exact, cancellationToken).ConfigureAwait(false);
            RequireRetainedRouteScope(exact, route, RetainedRouteHorizonCeiling(route));
            cancellationToken.ThrowIfCancellationRequested(); return new(exact);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(locator); CryptographicOperations.ZeroMemory(capability);
            CryptographicOperations.ZeroMemory(holder); CryptographicOperations.ZeroMemory(signature);
        }
    }

    /// <summary>Restores the same still-current signed pending request. Never
    /// reauthors its operation/window or creates protected owner custody.</summary>
    public async ValueTask<AuthoredMailboxGrantRequest> RestoreRetainedReadRequestAsync(
        ReadOnlyMemory<byte> exactOriginalRoute, ReadOnlyMemory<byte> locatorHash,
        ReadOnlyMemory<byte> ownerRetrieveCapability, ReadOnlyMemory<byte> holderPublicKey,
        ReadOnlyMemory<byte> exactXmg2, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var route = CaptureRetainedRoute(exactOriginalRoute);
        RequireClient32(locatorHash.Span); RequireClient32(ownerRetrieveCapability.Span); RequireClient32(holderPublicKey.Span);
        if (exactXmg2.Length != 435) throw new CryptographicException("Retained pending request exceeds its exact bound.");
        var request = ContactCodec.Decode(ProtocolMagic.XMG2, exactXmg2.Span);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        if (!Fixed(request.Field(3).Span, locatorHash.Span) || !Fixed(request.Field(4).Span, ownerRetrieveCapability.Span) ||
            !Fixed(request.Field(5).Span, holderPublicKey.Span))
            throw new CryptographicException("Retained pending request differs from protected owner/holder scope.");
        RequireRetainedRouteScope(request, route, RetainedRouteHorizonCeiling(route));
        _ = await ReadRetainedRequestTimeAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested(); return new(request);
    }

    /// <summary>Verifies only a real still-current Retrieve grant under this
    /// current host. Historical request-envelope expiry never renews a grant.
    /// Actual owner installation must remain inside its protected holder lease.</summary>
    public async ValueTask<VerifiedMailboxRetainedReadGrantV2> VerifyRetainedReadSuccessAsync(
        ReadOnlyMemory<byte> exactOriginalRoute, ReadOnlyMemory<byte> exactXmg2,
        ReadOnlyMemory<byte> exactXmc2, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var route = CaptureRetainedRoute(exactOriginalRoute);
        if (exactXmg2.Length != 435 || exactXmc2.Length != 510)
            throw new CryptographicException("Retained success requires bounded exact request/result records.");
        var request = ContactCodec.Decode(ProtocolMagic.XMG2, exactXmg2.Span);
        var response = ContactCodec.Decode(ProtocolMagic.XMC2, exactXmc2.Span);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        var ceiling = RetainedRouteHorizonCeiling(route);
        await RequireRetainedReadSuccessAsync(request, response, route, ceiling, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested(); return new(this, request, response, route, ceiling);
    }

    private static ParsedContactRouteClosure CaptureRetainedRoute(ReadOnlyMemory<byte> exact)
    {
        if (exact.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes)
            throw new CryptographicException("Retained route exceeds its closed exact bound.");
        return ContactRouteClosureCodec.Decode(exact.Span);
    }

    private static ulong RetainedRouteHorizonCeiling(ParsedContactRouteClosure route)
    {
        var admission = new[] { U64Retained(route.Reachability.Field(17).Span), U64Retained(route.Authorization.Field(13).Span),
            U64Retained(route.Route.Field(18).Span), U64Retained(route.Successor.Field(11).Span),
            U64Retained(route.Projection.Field(12).Span), U64Retained(route.Selection.Field(9).Span) }.Min();
        if (admission > ulong.MaxValue - MaximumRetainedObjectHorizonSeconds)
            throw new CryptographicException("Retained route horizon overflows.");
        return admission + MaximumRetainedObjectHorizonSeconds;
    }
    private static byte[] RetainedU64Bytes(ulong value)
    { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
    private static void RequireClient32(ReadOnlySpan<byte> value)
    { if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("Retained request requires exact nonzero 32-byte owner fields."); }
}
