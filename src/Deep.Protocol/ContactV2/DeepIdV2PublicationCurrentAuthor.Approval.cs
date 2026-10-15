using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

public static partial class DeepIdV2PublicationCurrentAuthor
{
    /// <summary>Authors a parsed original XPU with an actual current XPA.
    /// The result is not current reusable mutation or durable winner authority.</summary>
    public static async ValueTask<Xpu1Request> AuthorApprovalAsync(
        VerifiedDeepIdV2PublicationSubmission submission,
        IReadOnlyList<IXpa1PublicationAuthorizationWitnessSigner> witnesses, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(submission); ArgumentNullException.ThrowIfNull(witnesses); ct.ThrowIfCancellationRequested();
        var route = submission.Route; var original = submission.Request.OriginalRequest;
        var count = witnesses.Count;
        if (count is < 2 or > 32) throw new CryptographicException("Current publication witness count is invalid.");
        var captured = new (IXpa1PublicationAuthorizationWitnessSigner Signer, byte[] Id, byte[] Key)[count];
        var identities = new HashSet<string>(StringComparer.Ordinal); var domains = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < count; index++)
        {
            var signer = witnesses[index] ?? throw new CryptographicException("Current publication witness is absent.");
            var id = signer.WitnessId.ToArray();
            if (id.Length != 32 || !identities.Add(Convert.ToHexString(id)))
                throw new CryptographicException("Current publication witness is invalid or duplicated.");
            var key = route.NetworkAuthority.WitnessKeys.SingleOrDefault(value => Fixed(value.Id.Span, id)) ??
                throw new CryptographicException("Current publication witness is not currently authorized.");
            domains.Add(Convert.ToHexString(key.FailureDomainHash.Span));
            captured[index] = (signer, id, key.Ed25519PublicKey.ToArray());
        }
        if (count < route.NetworkAuthority.WitnessThreshold || domains.Count < route.NetworkAuthority.WitnessThreshold)
            throw new CryptographicException("Current publication lacks independent witness threshold.");
        Array.Sort(captured, (left, right) => left.Id.AsSpan().SequenceCompareTo(right.Id));
        await RecheckIssuerSubmissionAsync(submission, ct).ConfigureAwait(false);
        var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequireCurrentScope(route, submission.Request, first);
        var issued = first.LowerUnixSeconds;
        var expires = submission.Request.ExpiresAtUnixSeconds;
        if (issued < route.Recipient.Freshness.NextProtectedLkg.Head.ValidFrom || issued < route.NetworkAuthority.NotBefore ||
            expires <= first.UpperUnixSeconds || expires - issued > 120)
            throw new CryptographicException("Actual publication approval is outside current issuer time.");
        var closure = DeepIdV2ResolverClosureCodec.Decode(original.ExactDcr1.Span);
        var bundle = closure.Bundle;
        var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite, original.LocatorHash);
        ReadOnlyMemory<byte>[] body = [original.NetworkId, original.OperationId, placement.ViewHash, placement.PlacementHash,
            CurrentU64(original.IssuedAtUnixSeconds), CurrentU64(original.ExpiresAtUnixSeconds), original.LocatorHash,
            SHA256.HashData(bundle.Field(14).Span[40..]), CurrentU64(original.Generation), original.PredecessorObjectHash,
            SHA256.HashData(original.ObjectCiphertext.Span), original.ObjectCiphertext, new byte[4],
            CurrentU64(original.EffectiveExpiresAtUnixSeconds), SHA256.HashData(original.ExactRouteClosure.Span),
            original.ExactRouteClosure, new byte[594 + count * 96], original.OwnerRetrieveCapability];
        var bodyHash = DeepIdV2ContactPublicationCodec.ComputeAuthorizedBodyHash(CurrentRecord(ProtocolMagicBytes.XPU1,
            DeepIdV2ContactPublicationCodec.XpuTags, body));
        var head = route.Recipient.Freshness.NextProtectedLkg.CoreHash;
        var identity = new byte[96]; original.OperationId.Span.CopyTo(identity); bodyHash.CopyTo(identity, 32); head.Span.CopyTo(identity.AsSpan(64));
        byte[][] xpa = [original.NetworkId.ToArray(), ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V2/publication-authorization-id", identity), original.OperationId.ToArray(), original.LocatorHash.ToArray(),
            [1], SHA256.HashData(closure.CanonicalBytes.Span), SHA256.HashData(bundle.CanonicalBytes.Span), body[7].ToArray(),
            CurrentU64(original.Generation), original.PredecessorObjectHash.ToArray(), body[10].ToArray(), new byte[4],
            CurrentU64(original.EffectiveExpiresAtUnixSeconds), ApplicationCoreFormat.Sha256Domain(
                "Deep/ContactResolver/V2/publication-policy", original.ExactDca1.Span),
            CurrentU64(issued), CurrentU64(issued), CurrentU64(expires), head.ToArray(), bodyHash,
            [checked((byte)count)], new byte[count * 96]];
        var input = DeepIdV2ContactPublicationCodec.CreateWitnessSigningInput(xpa);
        try
        {
            for (var index = 0; index < captured.Length; index++)
            {
                await RecheckIssuerSubmissionAsync(submission, ct).ConfigureAwait(false);
                var signer = captured[index];
                if (!Fixed(signer.Signer.WitnessId.Span, signer.Id))
                    throw new CryptographicException("Current publication witness changed identity before signing.");
                var signature = (await signer.Signer.SignXpa1Async(input.ToArray(), ct).ConfigureAwait(false)).ToArray();
                try
                {
                    ct.ThrowIfCancellationRequested();
                    var after = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false); RequireContinuous(first, after);
                    RequireCurrentScope(route, submission.Request, after);
                    if (!Fixed(signer.Signer.WitnessId.Span, signer.Id) || signature.Length != 64 ||
                        !PublicKeyAuth.VerifyDetached(signature, input, signer.Key))
                        throw new CryptographicException("Current publication witness signature or identity is invalid.");
                    signer.Id.CopyTo(xpa[20], index * 96); signature.CopyTo(xpa[20], index * 96 + 32);
                }
                finally { CryptographicOperations.ZeroMemory(signature); }
            }
            body[16] = CurrentRecord(ProtocolMagicBytes.XPA1, DeepIdV2ContactPublicationCodec.XpaTags,
                xpa.Select(value => (ReadOnlyMemory<byte>)value).ToArray());
            var request = Xpu1Codec.Decode(CurrentRecord(ProtocolMagicBytes.XPU1, DeepIdV2ContactPublicationCodec.XpuTags, body));
            _ = await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(route, original, request.CanonicalBytes, ct).ConfigureAwait(false);
            await RecheckIssuerSubmissionAsync(submission, ct).ConfigureAwait(false);
            var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false); RequireContinuous(first, final);
            RequireCurrentScope(route, submission.Request, final); ct.ThrowIfCancellationRequested(); return request;
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    private static byte[] CurrentRecord(ReadOnlySpan<byte> magic, ReadOnlySpan<ushort> tags, ReadOnlyMemory<byte>[] fields)
    {
        var length = checked(12 + fields.Sum(value => checked(8 + value.Length)));
        var bytes = new byte[length];
        var writer = new ApplicationRecordWriter(bytes, magic, checked((ushort)tags.Length), 2, DeepIdV2Codec.Suite);
        for (var index = 0; index < tags.Length; index++) writer.Write(tags[index], fields[index].Span);
        writer.Complete(); return bytes;
    }
    private static byte[] CurrentU64(ulong value)
    { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
}
