using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Direct current DID2 XMG2 authoring. Not issuance, holder custody,
/// durable retry, installation or dispatch. No retired identity route overload.</summary>
public static class DeepIdV2MailboxGrantRequestAuthor
{
    /// <summary>Restores only an exact still-current pending request. Never
    /// signs, changes its operation/route/window or establishes protected custody.</summary>
    public static ValueTask<AuthoredMailboxGrantRequest> RestoreDepositAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ReadOnlyMemory<byte> locatorHash,
        ReadOnlyMemory<byte> holderPublicKey, ReadOnlyMemory<byte> exactXmg2,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(route);
        return RestoreAsync(route, locatorHash, route.Route.Reachability.Field(10),
            holderPublicKey, MailboxCapabilityDomain.Deposit, exactXmg2, cancellationToken);
    }

    public static ValueTask<AuthoredMailboxGrantRequest> RestoreRetrieveAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ReadOnlyMemory<byte> locatorHash,
        ReadOnlyMemory<byte> ownerRetrieveCapability, ReadOnlyMemory<byte> holderPublicKey,
        ReadOnlyMemory<byte> exactXmg2, CancellationToken cancellationToken = default) =>
        RestoreAsync(route, locatorHash, ownerRetrieveCapability, holderPublicKey,
            MailboxCapabilityDomain.Retrieve, exactXmg2, cancellationToken);

    private static async ValueTask<AuthoredMailboxGrantRequest> RestoreAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ReadOnlyMemory<byte> locatorHash,
        ReadOnlyMemory<byte> capability, ReadOnlyMemory<byte> holderPublicKey,
        MailboxCapabilityDomain domain, ReadOnlyMemory<byte> exactXmg2, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(route); ct.ThrowIfCancellationRequested();
        Required32(locatorHash.Span); Required32(capability.Span); Required32(holderPublicKey.Span);
        if (exactXmg2.Length != 435)
            throw new CryptographicException("An exact bounded retained XMG2 is required.");
        var request = ContactCodec.Decode(ProtocolMagic.XMG2, exactXmg2.Span);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        DeepIdV2MailboxGrantResultVerifier.RequireRequestScope(route, request);
        if (request.Field(6).Span[0] != (byte)domain ||
            !CryptographicOperations.FixedTimeEquals(request.Field(3).Span, locatorHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(request.Field(4).Span, capability.Span) ||
            !CryptographicOperations.FixedTimeEquals(request.Field(5).Span, holderPublicKey.Span))
            throw new CryptographicException("Retained mailbox request differs from protected holder scope.");
        var start = U64(request.Field(9).Span); var expiry = U64(request.Field(10).Span);
        var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequireWindow(first, start, expiry);
        var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        DeepIdV2MailboxGrantResultVerifier.RequireContinuous(first, final);
        RequireWindow(final, start, expiry);
        ct.ThrowIfCancellationRequested(); return new(request);
    }

    public static ValueTask<AuthoredMailboxGrantRequest> AuthorDepositAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ReadOnlyMemory<byte> locatorHash,
        IReachabilityMailboxHolderSigner signer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(route);
        return AuthorAsync(route, locatorHash, route.Route.Reachability.Field(10),
            MailboxCapabilityDomain.Deposit, signer, cancellationToken);
    }

    public static ValueTask<AuthoredMailboxGrantRequest> AuthorRetrieveAsync(
        VerifiedDeepIdV2ContactRouteClosure ownedRoute, ReadOnlyMemory<byte> locatorHash,
        ReadOnlyMemory<byte> ownerRetrieveCapability, IReachabilityMailboxHolderSigner signer,
        CancellationToken cancellationToken = default) =>
        AuthorAsync(ownedRoute, locatorHash, ownerRetrieveCapability,
            MailboxCapabilityDomain.Retrieve, signer, cancellationToken);

    private static async ValueTask<AuthoredMailboxGrantRequest> AuthorAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ReadOnlyMemory<byte> locatorHash,
        ReadOnlyMemory<byte> capability, MailboxCapabilityDomain domain,
        IReachabilityMailboxHolderSigner signer, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(signer);
        ct.ThrowIfCancellationRequested();
        Required32(locatorHash.Span); Required32(capability.Span);
        if (domain == MailboxCapabilityDomain.Retrieve &&
            CryptographicOperations.FixedTimeEquals(capability.Span, route.Route.Reachability.Field(10).Span))
            throw new CryptographicException("A public deposit capability cannot authorize owner retrieval.");
        var locator = locatorHash.ToArray(); var secret = capability.ToArray();
        // A mutable signer cannot substitute the key during an asynchronous callback.
        byte[]? holder = null, operation = null;
        var signature = new byte[64];
        try
        {
            var key = signer.Ed25519PublicKey; Required32(key.Span); holder = key.ToArray();
            var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
            var records = route.Route;
            var start = first.LowerUnixSeconds;
            var expiry = new[] { checked(start + 120), route.Network.MaximumRecordExpiryUnixSeconds,
                U64(records.Reachability.Field(17).Span), U64(records.Authorization.Field(13).Span),
                U64(records.Route.Field(18).Span), U64(records.Successor.Field(11).Span),
                U64(records.Projection.Field(12).Span), U64(records.Selection.Field(9).Span) }.Min();
            RequireWindow(first, start, expiry);
            operation = Random32();
            var placeholder = new byte[64]; placeholder[^1] = 1;
            ReadOnlyMemory<byte>[] fields = [records.Reachability.Field(1), operation,
                locator, secret, holder, new byte[] { (byte)domain },
                ContactCodec.ArtifactReference(ProtocolMagic.PMT2, records.Projection).CanonicalBytes,
                records.Selection.ArtifactHash, EncodeU64(start), EncodeU64(expiry), records.ExactHash, placeholder];
            var unsigned = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XMG2, fields);
            RequireWindow(await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false), start, expiry);
            var written = await signer.SignMailboxGrantRequestAsync(unsigned.SignatureInput, signature, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            RequireWindow(await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false), start, expiry);
            if (written != 64 || signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !PublicKeyAuth.VerifyDetached(signature, unsigned.SignatureInput.ToArray(), holder))
                throw new CryptographicException("The DID2 mailbox holder returned an invalid proof of possession.");
            fields[11] = signature;
            var exact = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XMG2, fields);
            ContactCodec.VerifyMailboxGrantHolderSignature(exact);
            return new(exact);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(locator); CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(signature);
            if (holder is not null) CryptographicOperations.ZeroMemory(holder);
            if (operation is not null) CryptographicOperations.ZeroMemory(operation);
        }
    }
    private static void Required32(ReadOnlySpan<byte> value)
    { if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("An exact nonzero 32-byte mailbox request field is required."); }
    private static void RequireWindow(DeepIdV2ContactRouteTimeWindow current, ulong start, ulong expiry)
    { if (current.LowerUnixSeconds > current.UpperUnixSeconds || start > current.LowerUnixSeconds || current.UpperUnixSeconds >= expiry) throw new CryptographicException("The mailbox request does not cover authenticated route time."); }
    private static byte[] Random32()
    { var result = new byte[32]; do RandomNumberGenerator.Fill(result); while (result.AsSpan().IndexOfAnyExcept((byte)0) < 0); return result; }
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    private static byte[] EncodeU64(ulong value)
    { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
}
