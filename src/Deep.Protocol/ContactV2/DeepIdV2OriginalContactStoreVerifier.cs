using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Authenticates original initial-Store recipient facts only. Returns
/// parsed public records, never freshness, a route/holder capability, a replay
/// reservation, a directory-floor update or deletion permission.</summary>
public static class DeepIdV2OriginalContactStoreVerifier
{
    public static ParsedContactRouteClosure Verify(
        VerifiedXPointNetworkAuthority authority, ParsedDid2 protectedPeerCredential,
        ReadOnlySpan<byte> exactPeerAdp1, ReadOnlySpan<byte> exactDcr1,
        ReadOnlySpan<byte> exactRoute, ulong originalUnixSeconds,
        ushort deploymentProfileId, ushort supportedReader, IDeepMlDsa65Verifier verifier)
    {
        // All untrusted framing bounds precede identity/PQ callbacks.
        if (exactPeerAdp1.Length is < 1 or > DeepIdV2Adp1Codec.MaximumLength ||
            exactDcr1.Length is < 1 or > DeepIdV2ResolverClosureCodec.MaximumLength ||
            exactRoute.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes)
            throw new ArgumentOutOfRangeException(nameof(exactDcr1), "Original recipient records exceed their existing codec bounds.");
        var checkpoint = DeepIdV2DirectoryCurrentProofVerifier.VerifyOriginalCheckpoint(
            authority, exactPeerAdp1, protectedPeerCredential, originalUnixSeconds,
            deploymentProfileId, supportedReader, verifier);
        var contact = DeepIdV2ResolverClosureCodec.Decode(exactDcr1);
        var bundle = contact.Bundle;
        if (!Fixed(bundle.Field(23).Span, checkpoint.Binding.DeepId.CanonicalBytes.Span) ||
            !Fixed(bundle.Field(24).Span, checkpoint.Binding.Record.CanonicalBytes.Span) ||
            !Fixed(bundle.Field(5).Span, checkpoint.Directory.Record.CanonicalBytes.Span))
            throw new CryptographicException("Original contact differs from its authenticated peer checkpoint.");
        var authorization = DeepIdV2ContactAuthorizationCodec.Verify(
            DeepIdV2ContactAuthorizationCodec.Decode(bundle.Field(6).Span), checkpoint.Binding, checkpoint.Directory);
        if (checkpoint.IsDcaAuthorizationRevoked(authorization.Record.AuthorizationId.Span))
            throw new CryptographicException("Original contact delegation was revoked in its original checkpoint.");
        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(contact, authorization, originalUnixSeconds);
        var route = ContactRouteClosureCodec.Decode(exactRoute);
        // Bundle's XIR entry is an exact LP record (40-byte slot framing).
        var invite = DeepIdV2InviteRendezvousCodec.Decode(bundle.Field(14).Span[40..]);
        DeepIdV2InviteRendezvousCodec.VerifyIssuerAndDca1(invite, authorization, originalUnixSeconds);
        var device = authorization.Binding.Identity.ActiveDevices.Single(item =>
            Fixed(item.Certificate.DeviceId.Span, authorization.Record.PublisherDeviceId.Span)).Certificate;
        var deviceRef = new ContactArtifactReference(ProtocolMagic.DPD1, 1, device.CanonicalHash.Span).CanonicalBytes;
        var dcaRef = new ContactArtifactReference(ProtocolMagic.DCA1, 2, authorization.Record.RecordHash.Span).CanonicalBytes;
        var xra = route.Authorization;
        DeepIdV2ContactRouteVerifier.RequireIdentityBindings(invite, route, authority.NetworkId.Span,
            ContactCodec.ArtifactReference(ProtocolMagic.PMT2, route.Projection).CanonicalBytes.Span,
            deviceRef.Span, dcaRef.Span);
        if (!Fixed(xra.Field(14).Span, device.DeviceId.Span) ||
            !Fixed(xra.Field(15).Span, deviceRef.Span) ||
            Fixed(xra.Field(11).Span, device.DeviceX25519PublicKey.Span) ||
            U64(xra.Field(12).Span) < device.IssuedAtUnixSeconds ||
            U64(xra.Field(12).Span) < authorization.Record.NotBeforeUnixSeconds ||
            U64(xra.Field(13).Span) > device.ExpiresAtUnixSeconds ||
            U64(xra.Field(13).Span) > authorization.Record.ExpiresAtUnixSeconds)
            throw new CryptographicException("Original route differs from its signed device/delegation scope.");
        DeepIdV2ContactUpdateRendezvousAuthor.RequireAgreementKey(xra.Field(11).Span);
        ContactCodec.VerifyDeviceSignature(xra, device.DeviceEd25519PublicKey.Span);
        ContactCodec.VerifyDeviceSignature(route.Reachability, device.DeviceEd25519PublicKey.Span);
        var minimum = bundle.Field(21).Span;
        var proof = DeepIdV2Adp1Codec.Decode(exactPeerAdp1);
        if (!Fixed(minimum[8..], route.Route.Field(19).Span[6..]) ||
            U64(minimum) > proof.Head.LogGeneration ||
            U64(minimum) == proof.Head.LogGeneration && !Fixed(minimum[8..], AccountDirectoryCrypto.ComputeAdh1CoreHash(proof.Head)))
            throw new CryptographicException("Original contact issuance anchor differs from its signed directory/route.");
        foreach (var (record, start, end) in new[] {
            (xra, 12, 13), (route.Reachability, 16, 17), (route.Selection, 8, 9),
            (route.Route, 17, 18), (route.Successor, 10, 11) })
            if (originalUnixSeconds < U64(record.Field(start).Span) || originalUnixSeconds >= U64(record.Field(end).Span))
                throw new CryptographicException("Original Store lies outside its signed recipient-route interval.");
        // PMT/PMS/XRC/XSS and original receipt keys are independently verified
        // by MailboxStoreReplicaEvidenceVerifier; neither entry admits a send.
        return route;
    }

    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static ulong U64(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt64BigEndian(bytes);
}
