using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

public sealed partial class VerifiedMailboxHostAuthorityV2
{
    // Past Store signature facts only. Never called by RequireGrant/current
    // admission, nor a replacement for two actual signed durable receipts.
    internal VerifiedMailboxAuthorityV2 RequireHistoricalStoreIssuer(MailboxAuthenticatedGrant grant)
    {
        // All callers bracket this synchronous fact check with actual current
        // host reads. No effect/await/caller callback occurs inside this helper.
        foreach (var record in issuerHistory)
        {
            if (BinaryPrimitives.ReadUInt16BigEndian(record.Field(9).Span) != 2 ||
                !Fixed(grant.NetworkId.Span, NetworkId.Span) || grant.Domain != MailboxCapabilityDomain.Deposit ||
                grant.Lifecycle != MailboxCapabilityLifecycle.Active || !Fixed(record.Field(5).Span, grant.IssuerPublicKey.Span)) continue;
            var policy = new VerifiedMailboxAuthorityV2(record);
            if (grant.Generation < policy.MinimumGrantGeneration || grant.NotBeforeUnixSeconds < policy.NotBeforeUnixSeconds ||
                grant.ExpiresAtUnixSeconds > policy.ExpiresAtUnixSeconds ||
                grant.ExpiresAtUnixSeconds - grant.NotBeforeUnixSeconds > policy.MaximumGrantLifetimeSeconds) continue;
            var reference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.PMA2, record.CoreHash.Span);
            var projection = network.Closure!.RetainedPmts.FirstOrDefault(value => Fixed(value.Field(4).Span, reference) &&
                BinaryPrimitives.ReadUInt64BigEndian(value.Field(6).Span) == grant.Epoch);
            if (projection is null) continue;
            var ancestor = XPointOnionCapabilityProducer.RequireRetainedProjectionAuthorityFact(network.Closure!, root, projection);
            if (!Fixed(record.Field(13).Span, XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNA1, ancestor.CoreHash.Span))) continue;
            MailboxAuthorityV2Verifier.VerifyHistoricalLineage(root, record.CanonicalBytes.Span, grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds - 1);
            if (!PublicKeyAuth.VerifyDetached(grant.IssuerSignature.ToArray(),
                MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant), grant.IssuerPublicKey.ToArray()))
                throw new CryptographicException("Historical Store issuer signature differs.");
            return policy;
        }
        throw new CryptographicException("Historical Store issuer is absent from exact authenticated policy/projection history.");
    }
}
