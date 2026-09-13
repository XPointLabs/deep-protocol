using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.ContactV1;

public sealed class ContactRouteCompletionAuthoringRequest
{
    public ContactRouteCompletionAuthoringRequest(
        VerifiedContactRouteProposalAuthority proposalAuthority,
        AuthoredContactRouteAdvertisement advertisement,
        AuthoredContactRouteThresholdClosure thresholdClosure,
        ushort minimumReader = 1)
    {
        ProposalAuthority = proposalAuthority ??
            throw new ArgumentNullException(nameof(proposalAuthority));
        Advertisement = advertisement ?? throw new ArgumentNullException(nameof(advertisement));
        ThresholdClosure = thresholdClosure ??
            throw new ArgumentNullException(nameof(thresholdClosure));
        if (minimumReader is < 1 or > 256)
            throw new ArgumentOutOfRangeException(nameof(minimumReader));
        MinimumReader = minimumReader;
    }

    public VerifiedContactRouteProposalAuthority ProposalAuthority { get; }
    public AuthoredContactRouteAdvertisement Advertisement { get; }
    public AuthoredContactRouteThresholdClosure ThresholdClosure { get; }
    public ushort MinimumReader { get; }
}

public sealed class AuthoredPermanentContactRoute
{
    private readonly byte[] exactXrr1;
    private readonly byte[] exactXir1;
    private readonly byte[] exactRouteClosure;

    internal AuthoredPermanentContactRoute(
        VerifiedContactRouteClosure verified,
        ContactRecord reachability,
        ContactRecord invite)
    {
        Verified = verified;
        Reachability = reachability;
        Invite = invite;
        exactXrr1 = reachability.CanonicalBytes.ToArray();
        exactXir1 = invite.CanonicalBytes.ToArray();
        exactRouteClosure = ContactRouteClosureCodec.Encode(verified);
    }

    public VerifiedContactRouteClosure Verified { get; }
    public ContactRecord Reachability { get; }
    public ContactRecord Invite { get; }
    public ReadOnlyMemory<byte> ExactXrr1 => exactXrr1.ToArray();
    public ReadOnlyMemory<byte> ExactXir1 => exactXir1.ToArray();
    public ReadOnlyMemory<byte> ExactRouteClosure => exactRouteClosure.ToArray();
}

/// <summary>
/// Completes a threshold-authored route using only the same active device that
/// signed XRA1, then invokes the full route-closure verifier before returning.
/// </summary>
public static class ContactRouteCompletionAuthor
{
    public static async ValueTask<AuthoredPermanentContactRoute> AuthorAsync(
        ContactRouteCompletionAuthoringRequest request,
        IContactDeviceCustodySigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(signer);
        cancellationToken.ThrowIfCancellationRequested();
        var proposal = request.ProposalAuthority;
        var xra = request.Advertisement.Record;
        var threshold = request.ThresholdClosure;
        try
        {
            if (!Fixed(threshold.Authority.NetworkId.Span, proposal.NetworkId.Span) ||
                !Fixed(threshold.Authority.RecipientDeviceId.Span,
                    proposal.RecipientDeviceId.Span) ||
                !Fixed(threshold.Selection.Field(3).Span, xra.Field(6).Span) ||
                !Fixed(threshold.LiveRoute.Field(5).Span,
                    ContactCodec.ArtifactReference(ProtocolMagic.XRA1, xra)
                        .CanonicalBytes.Span) ||
                !Fixed(signer.DeviceId.Span, proposal.RecipientDeviceId.Span) ||
                !Fixed(signer.Ed25519PublicKey.Span,
                    proposal.RecipientDevicePublicKey.Span) ||
                signer.CustodyDomainHash.Length != 32 ||
                signer.CustodyDomainHash.Span.IndexOfAnyExcept((byte)0) < 0)
                throw new ContactPublicationAuthoringException(
                    "RouteCompletionAuthorityMismatch",
                    "The route completion inputs do not share one verified device and threshold closure.");

            var xrr = await AuthorReachabilityAsync(
                proposal, xra, threshold, request.MinimumReader, signer, cancellationToken)
                .ConfigureAwait(false);
            var xir = await AuthorInviteAsync(
                proposal, xra, request.MinimumReader, signer, cancellationToken)
                .ConfigureAwait(false);
            var pmt = ContactCodec.Decode(ProtocolMagic.PMT2, proposal.ExactPmt2Span);
            var verified = ContactCodec.VerifyRouteUpdateClosure(
                xir, xrr, xra, threshold.LiveRoute, threshold.SuccessorCheckpoint,
                pmt, threshold.Selection, threshold.Authority);
            return new AuthoredPermanentContactRoute(verified, xrr, xir);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ContactPublicationAuthoringException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or
            CryptographicException or OverflowException or InvalidOperationException)
        {
            throw new ContactPublicationAuthoringException(
                "InvalidRouteCompletionInput",
                "The exact XRR1/XIR1 authoring inputs are invalid.", exception);
        }
    }

    private static async ValueTask<ContactRecord> AuthorReachabilityAsync(
        VerifiedContactRouteProposalAuthority proposal,
        ContactRecord xra,
        AuthoredContactRouteThresholdClosure threshold,
        ushort minimumReader,
        IContactDeviceCustodySigner signer,
        CancellationToken cancellationToken)
    {
        var xrc = threshold.LiveRoute;
        var xss = threshold.SuccessorCheckpoint;
        var fields = new ReadOnlyMemory<byte>[]
        {
            proposal.NetworkId,
            RandomNonZero32(),
            U64(0),
            new byte[32],
            ContactCodec.ArtifactReference(ProtocolMagic.XRA1, xra).CanonicalBytes,
            ContactCodec.ArtifactReference(ProtocolMagic.XRC1, xrc).CanonicalBytes,
            ContactCodec.ArtifactReference(ProtocolMagic.XSS1, xss).CanonicalBytes,
            proposal.Pmt2ArtifactReference,
            threshold.Selection.ArtifactHash,
            xrc.Field(10),
            xra.Field(9),
            new byte[] { 3 },
            xra.Field(8),
            U16(minimumReader),
            xrc.Field(16),
            xrc.Field(17),
            xrc.Field(18),
            proposal.RecipientDpd1Reference,
            PlaceholderSignature(),
            new byte[2],
        };
        return await SignAsync(
            ProtocolMagic.XRR1, fields, 18,
            ContactDeviceSignaturePurpose.RouteReachability,
            proposal, signer, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<ContactRecord> AuthorInviteAsync(
        VerifiedContactRouteProposalAuthority proposal,
        ContactRecord xra,
        ushort minimumReader,
        IContactDeviceCustodySigner signer,
        CancellationToken cancellationToken)
    {
        var fields = new ReadOnlyMemory<byte>[]
        {
            proposal.NetworkId,
            RandomNonZero32(),
            U64(0),
            new byte[32],
            proposal.Pmt2ArtifactReference,
            xra.Field(6),
            xra.Field(10),
            xra.Field(11),
            new byte[] { 1 },
            U32(0),
            U16(minimumReader),
            xra.Field(9),
            xra.Field(12),
            xra.Field(13),
            proposal.RecipientDpd1Reference,
            proposal.Dca1Reference,
            PlaceholderSignature(),
            ContactCodec.ArtifactReference(ProtocolMagic.XRA1, xra).CanonicalBytes,
        };
        return await SignAsync(
            ProtocolMagic.XIR1, fields, 16,
            ContactDeviceSignaturePurpose.InviteRoute,
            proposal, signer, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<ContactRecord> SignAsync(
        string magic,
        ReadOnlyMemory<byte>[] fields,
        int signatureIndex,
        ContactDeviceSignaturePurpose purpose,
        VerifiedContactRouteProposalAuthority proposal,
        IContactDeviceCustodySigner signer,
        CancellationToken cancellationToken)
    {
        var provisional = ContactCodec.AuthorForOperationalAuthority(magic, fields);
        var request = new ContactDeviceSigningRequest(
            purpose, proposal.NetworkId.Span, proposal.RecipientAccountIdSpan,
            proposal.RecipientDeviceId.Span, signer.CustodyDomainHash.Span,
            provisional.SignatureInput.Span);
        var signature = new byte[64];
        try
        {
            var written = await signer.SignAsync(
                request, signature, cancellationToken).ConfigureAwait(false);
            if (written != 64 || signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !PublicKeyAuth.VerifyDetached(
                    signature, provisional.SignatureInput.ToArray(),
                    proposal.RecipientDevicePublicKey.ToArray()))
                throw new ContactPublicationAuthoringException(
                    "InvalidCustodySignature",
                    $"The {magic} custody signer returned an invalid signature.");
            fields[signatureIndex] = signature.ToArray();
            return ContactCodec.AuthorForOperationalAuthority(magic, fields);
        }
        finally
        {
            request.Clear();
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static byte[] RandomNonZero32()
    {
        var result = new byte[32];
        do RandomNumberGenerator.Fill(result);
        while (result.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return result;
    }

    private static byte[] PlaceholderSignature()
    {
        var result = new byte[64];
        result[^1] = 1;
        return result;
    }

    private static byte[] U16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    private static byte[] U32(uint value)
    {
        var result = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
