using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

public static partial class DeepIdV2PublicationCurrentAuthor
{
    /// <summary>Current lease over the independently verified permanent
    /// original winner. Never a second original-XPA or a replica commitment.</summary>
    public static async ValueTask<ParsedDeepIdV2PublicationLease> AuthorLeaseAsync(
        VerifiedDeepIdV2PublicationSubmission submission, VerifiedDeepIdV2IssuerPublicationIntent intent,
        IReadOnlyList<IDeepIdV2PublicationLeaseWitnessSigner> witnesses, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(submission); ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(witnesses); ct.ThrowIfCancellationRequested();
        if (!ReferenceEquals(submission.Route, intent.Route))
            throw new CryptographicException("Current publication and original intent require the same independently verified route.");
        RequireSameOriginal(submission.Request.OriginalRequest, intent.OwnedRequest);
        var request = submission.Request; var route = submission.Route; var authority = route.NetworkAuthority;
        var count = witnesses.Count;
        if (count is < 2 or > 32) throw new CryptographicException("Current publication lease witness count is invalid.");
        var captured = new (IDeepIdV2PublicationLeaseWitnessSigner Signer, byte[] Id, byte[] Key)[count];
        var identities = new HashSet<string>(StringComparer.Ordinal); var domains = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < count; index++)
        {
            var signer = witnesses[index] ?? throw new CryptographicException("Current publication lease witness is absent.");
            var id = signer.WitnessId.ToArray();
            if (id.Length != 32 || !identities.Add(Convert.ToHexString(id)))
                throw new CryptographicException("Current publication lease witness is invalid or duplicated.");
            var key = authority.WitnessKeys.SingleOrDefault(value => Fixed(value.Id.Span, id)) ??
                throw new CryptographicException("Current publication lease witness is not currently authorized.");
            domains.Add(Convert.ToHexString(key.FailureDomainHash.Span));
            captured[index] = (signer, id, key.Ed25519PublicKey.ToArray());
        }
        if (count < authority.WitnessThreshold || domains.Count < authority.WitnessThreshold)
            throw new CryptographicException("Current publication lease lacks independent witness threshold.");
        Array.Sort(captured, (left, right) => left.Id.AsSpan().SequenceCompareTo(right.Id));
        await RecheckOriginalAsync().ConfigureAwait(false);
        var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite, intent.Request.LocatorHash);
        ReadOnlyMemory<byte>[] fields = [request.NetworkId, intent.Request.RequestHash, placement.ViewHash, placement.PlacementHash,
            CurrentU64(request.IssuedAtUnixSeconds), CurrentU64(request.ExpiresAtUnixSeconds),
            route.Recipient.Freshness.NextProtectedLkg.CoreHash, request.RequestNonce, intent.Request.CanonicalBytes, new byte[] { (byte)count }];
        var input = DeepIdV2PublicationLeaseCodec.UnsignedSigningInput(fields);
        var signing = new PublicationLeaseSigningRequest(request.NetworkId.Span, intent.RequestHash.Span, input);
        var rows = new byte[count * 96];
        try
        {
            var first = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
            for (var index = 0; index < captured.Length; index++)
            {
                await RecheckOriginalAsync().ConfigureAwait(false);
                var signer = captured[index];
                if (!Fixed(signer.Signer.WitnessId.Span, signer.Id))
                    throw new CryptographicException("Current publication lease witness changed identity before signing.");
                var signature = (await signer.Signer.SignPublicationLeaseAsync(signing, ct).ConfigureAwait(false)).ToArray();
                try
                {
                    ct.ThrowIfCancellationRequested();
                    if (!Fixed(signer.Signer.WitnessId.Span, signer.Id) || signature.Length != 64 ||
                        !PublicKeyAuth.VerifyDetached(signature, input, signer.Key))
                        throw new CryptographicException("Current publication lease custody returned an invalid signature or identity.");
                    signer.Id.CopyTo(rows, index * 96); signature.CopyTo(rows, index * 96 + 32);
                }
                finally { CryptographicOperations.ZeroMemory(signature); }
                await RecheckOriginalAsync().ConfigureAwait(false);
            }
            var lease = DeepIdV2PublicationLeaseCodec.Decode(DeepIdV2PublicationLeaseCodec.Encode([..fields, rows]));
            var final = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false); RequireContinuous(first, final);
            await RecheckOriginalAsync().ConfigureAwait(false);
            _ = await DeepIdV2PublicationLeaseVerifier.VerifyAsync(lease, authority, route.Recipient.Freshness,
                placement, route.TrustedPublicationTime, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); return lease;
        }
        finally { CryptographicOperations.ZeroMemory(input); CryptographicOperations.ZeroMemory(rows); }

        async ValueTask RecheckOriginalAsync()
        {
            await RecheckIssuerSubmissionAsync(submission, ct).ConfigureAwait(false);
            _ = await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(route, intent.OwnedRequest,
                intent.Request.CanonicalBytes, ct).ConfigureAwait(false);
        }
    }
}
