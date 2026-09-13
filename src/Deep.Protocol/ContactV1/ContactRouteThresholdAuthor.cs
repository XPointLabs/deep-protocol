using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV1;

public enum ContactRouteAuthoritySignaturePurpose : byte
{
    Selection = 1,
    LiveRoute = 2,
    SuccessorCheckpoint = 3,
}

public sealed class ContactRouteAuthoritySigningRequest
{
    private readonly byte[] networkId;
    private readonly byte[] signingInput;
    private readonly byte[] signingInputHash;

    internal ContactRouteAuthoritySigningRequest(
        ContactRouteAuthoritySignaturePurpose purpose,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> signingInput)
    {
        Purpose = purpose;
        this.networkId = networkId.ToArray();
        this.signingInput = signingInput.ToArray();
        signingInputHash = SHA256.HashData(signingInput);
    }

    public ContactRouteAuthoritySignaturePurpose Purpose { get; }
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> SigningInput => signingInput;
    public ReadOnlyMemory<byte> SigningInputSha256 => signingInputHash;

    internal void Clear()
    {
        CryptographicOperations.ZeroMemory(signingInput);
        CryptographicOperations.ZeroMemory(signingInputHash);
    }
}

public interface IContactRouteAuthorityWitnessSigner
{
    ReadOnlyMemory<byte> WitnessId { get; }

    ValueTask<int> SignAsync(
        ContactRouteAuthoritySigningRequest request,
        Memory<byte> signature64,
        CancellationToken cancellationToken);
}

public sealed class ContactRouteThresholdAuthoringRequest
{
    public ContactRouteThresholdAuthoringRequest(
        VerifiedContactRouteProposalAuthority proposalAuthority,
        AuthoredContactRouteAdvertisement advertisement,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds)
    {
        ProposalAuthority = proposalAuthority ??
            throw new ArgumentNullException(nameof(proposalAuthority));
        Advertisement = advertisement ?? throw new ArgumentNullException(nameof(advertisement));
        var xra = advertisement.Record;
        if (issuedAtUnixSeconds == 0 || issuedAtUnixSeconds >= expiresAtUnixSeconds ||
            expiresAtUnixSeconds - issuedAtUnixSeconds > 86_400 ||
            issuedAtUnixSeconds > proposalAuthority.TrustedLowerUnixSeconds ||
            expiresAtUnixSeconds <= proposalAuthority.TrustedUpperUnixSeconds ||
            issuedAtUnixSeconds < proposalAuthority.NotBeforeUnixSeconds ||
            expiresAtUnixSeconds > proposalAuthority.ExpiresAtUnixSeconds ||
            issuedAtUnixSeconds < BinaryPrimitives.ReadUInt64BigEndian(xra.Field(12).Span) ||
            expiresAtUnixSeconds > BinaryPrimitives.ReadUInt64BigEndian(xra.Field(13).Span))
            throw new ArgumentOutOfRangeException(nameof(expiresAtUnixSeconds));
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }

    public VerifiedContactRouteProposalAuthority ProposalAuthority { get; }
    public AuthoredContactRouteAdvertisement Advertisement { get; }
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
}

public sealed class AuthoredContactRouteThresholdClosure
{
    private readonly byte[] exactPms2;
    private readonly byte[] exactXrc1;
    private readonly byte[] exactXss1;

    internal AuthoredContactRouteThresholdClosure(
        VerifiedContactNetworkAuthority authority,
        ContactRecord selection,
        ContactRecord liveRoute,
        ContactRecord successorCheckpoint)
    {
        Authority = authority;
        Selection = selection;
        LiveRoute = liveRoute;
        SuccessorCheckpoint = successorCheckpoint;
        exactPms2 = selection.CanonicalBytes.ToArray();
        exactXrc1 = liveRoute.CanonicalBytes.ToArray();
        exactXss1 = successorCheckpoint.CanonicalBytes.ToArray();
    }

    public VerifiedContactNetworkAuthority Authority { get; }
    public ContactRecord Selection { get; }
    public ContactRecord LiveRoute { get; }
    public ContactRecord SuccessorCheckpoint { get; }
    public ReadOnlyMemory<byte> ExactPms2 => exactPms2.ToArray();
    public ReadOnlyMemory<byte> ExactXrc1 => exactXrc1.ToArray();
    public ReadOnlyMemory<byte> ExactXss1 => exactXss1.ToArray();
}

/// <summary>
/// Rehydrates a remote threshold-authority response only after all exact
/// PMS2/XRC1/XSS1 bindings, validity windows and witness thresholds verify.
/// No device-custody callback is required by this verifier.
/// </summary>
public static class ContactRouteThresholdVerifier
{
    public static async ValueTask<AuthoredContactRouteThresholdClosure> VerifyExactAsync(
        VerifiedContactRouteProposalAuthority proposal,
        AuthoredContactRouteAdvertisement advertisement,
        ReadOnlyMemory<byte> exactPms2,
        ReadOnlyMemory<byte> exactXrc1,
        ReadOnlyMemory<byte> exactXss1,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proposal);
        ArgumentNullException.ThrowIfNull(advertisement);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            ContactRouteAdvertisementVerifier.Validate(proposal, advertisement.Record);
            var pmt = ContactCodec.Decode(ProtocolMagic.PMT2, proposal.ExactPmt2Span);
            var pms = ContactCodec.Decode(ProtocolMagic.PMS2, exactPms2.Span);
            var xrc = ContactCodec.Decode(ProtocolMagic.XRC1, exactXrc1.Span);
            var xss = ContactCodec.Decode(ProtocolMagic.XSS1, exactXss1.Span);
            var authority = await ContactNetworkAuthorityVerifier.BindSelectionAsync(
                proposal, exactPms2, cancellationToken).ConfigureAwait(false);
            ContactCodec.ValidateThresholdRouteGraph(advertisement.Record, xrc, xss, pmt, pms);

            if (!Fixed(pmt.Field(5).Span, authority.Xnv1CoreReference.Span) ||
                !Fixed(pmt.Field(14).Span, authority.Adh1CoreReference.Span) ||
                !Fixed(pms.ArtifactHash.Span, authority.Pms2ArtifactHash.Span) ||
                !Fixed(xrc.Field(8).Span, authority.Xnv1CoreReference.Span) ||
                !Fixed(xrc.Field(9).Span, authority.Xnh1CoreReference.Span) ||
                !Fixed(xrc.Field(19).Span, authority.Adh1CoreReference.Span) ||
                !Fixed(xss.Field(8).Span, authority.Xnv1CoreReference.Span) ||
                !Fixed(xss.Field(12).Span, authority.Adh1CoreReference.Span))
                throw new ContactPublicationAuthoringException(
                    "RouteThresholdAuthorityMismatch",
                    "The threshold route records do not bind the verified network/directory authority.");

            var trusted = authority.TrustedUnixSeconds;
            if (!authority.IsCurrentAt(trusted) ||
                !CurrentAt(advertisement.Record, 12, 13, trusted) ||
                !CurrentAt(pmt, 11, 12, trusted) ||
                !CurrentAt(pms, 8, 9, trusted) ||
                !CurrentAt(xrc, 17, 18, trusted) ||
                !CurrentAt(xss, 10, 11, trusted))
                throw new ContactPublicationAuthoringException(
                    "RouteThresholdExpired",
                    "The threshold route response is not current at the authenticated instant.");

            authority.VerifyWitnessThreshold(pmt, 16);
            authority.VerifyWitnessThreshold(pms, 11);
            authority.VerifyWitnessThreshold(xrc, 21);
            authority.VerifyWitnessThreshold(xss, 14);
            return new AuthoredContactRouteThresholdClosure(authority, pms, xrc, xss);
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
                "InvalidRouteThresholdResponse",
                "The exact PMS2/XRC1/XSS1 response failed closed.", exception);
        }
    }

    private static bool CurrentAt(ContactRecord record, int fromTag, int untilTag, ulong trusted) =>
        BinaryPrimitives.ReadUInt64BigEndian(record.Field(fromTag).Span) <= trusted &&
        trusted < BinaryPrimitives.ReadUInt64BigEndian(record.Field(untilTag).Span);

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// Authors the threshold-owned PMS2/XRC1/XSS1 half only after verifying the
/// exact active-device XRA1 proposal and current proposal authority.
/// </summary>
public static class ContactRouteThresholdAuthor
{
    public static async ValueTask<AuthoredContactRouteThresholdClosure> AuthorAsync(
        ContactRouteThresholdAuthoringRequest request,
        IReadOnlyList<IContactRouteAuthorityWitnessSigner> witnessSigners,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(witnessSigners);
        cancellationToken.ThrowIfCancellationRequested();
        var proposal = request.ProposalAuthority;
        var xra = request.Advertisement.Record;
        try
        {
            ValidateAdvertisement(proposal, xra);
            var pmt = ContactCodec.Decode(ProtocolMagic.PMT2, proposal.ExactPmt2Span);
            var signers = ValidateSigners(proposal.NetworkAuthority, witnessSigners);
            var pms = await AuthorSelectionAsync(
                proposal, pmt, xra, request, signers, cancellationToken).ConfigureAwait(false);
            var authority = await ContactNetworkAuthorityVerifier.BindSelectionAsync(
                proposal, pms.CanonicalBytes, cancellationToken).ConfigureAwait(false);
            var xrc = await AuthorLiveRouteAsync(
                proposal, pmt, pms, xra, request, signers, cancellationToken).ConfigureAwait(false);
            var xss = await AuthorSuccessorAsync(
                proposal, pmt, pms, xrc, request, signers, cancellationToken).ConfigureAwait(false);
            authority.VerifyWitnessThreshold(pms, 11);
            authority.VerifyWitnessThreshold(xrc, 21);
            authority.VerifyWitnessThreshold(xss, 14);
            return new AuthoredContactRouteThresholdClosure(authority, pms, xrc, xss);
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
                "InvalidRouteThresholdInput",
                "The exact PMS2/XRC1/XSS1 authoring inputs are invalid.", exception);
        }
    }

    private static async ValueTask<ContactRecord> AuthorSelectionAsync(
        VerifiedContactRouteProposalAuthority proposal,
        ContactRecord pmt,
        ContactRecord xra,
        ContactRouteThresholdAuthoringRequest request,
        SignerBinding[] signers,
        CancellationToken cancellationToken)
    {
        var ranked = RankReplicas(
            proposal.NetworkId.Span,
            proposal.Pmt2ArtifactReference.Span,
            pmt.Field(6).Span,
            xra.Field(6).Span,
            pmt.Field(9).Span,
            pmt.Field(7).Span[0]);
        var fields = new ReadOnlyMemory<byte>[]
        {
            proposal.NetworkId,
            proposal.Pmt2ArtifactReference,
            xra.Field(6),
            pmt.Field(6),
            new byte[] { pmt.Field(7).Span[0] },
            ranked,
            Array.Empty<byte>(),
            U64(request.IssuedAtUnixSeconds),
            U64(request.ExpiresAtUnixSeconds),
            new byte[] { checked((byte)signers.Length) },
            PlaceholderReceipts(signers),
        };
        var projection = EncodeProjection(ProtocolMagic.PMS2, fields, 6);
        fields[6] = ContactCodec.Sha256Domain(
            "Deep/XPoint/V1/PMS2/selection", projection);
        return await SignRecordAsync(
            ProtocolMagic.PMS2, fields, 10,
            ContactRouteAuthoritySignaturePurpose.Selection,
            signers, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<ContactRecord> AuthorLiveRouteAsync(
        VerifiedContactRouteProposalAuthority proposal,
        ContactRecord pmt,
        ContactRecord pms,
        ContactRecord xra,
        ContactRouteThresholdAuthoringRequest request,
        SignerBinding[] signers,
        CancellationToken cancellationToken)
    {
        var replicaCount = pms.Field(5).Span[0];
        var replicaEntries = new byte[replicaCount * 64];
        for (var index = 0; index < replicaCount; index++)
        {
            pms.Field(6).Span.Slice(index * 32, 32)
                .CopyTo(replicaEntries.AsSpan(index * 64, 32));
            RandomNonZero32().CopyTo(replicaEntries, index * 64 + 32);
        }
        var fields = new ReadOnlyMemory<byte>[]
        {
            proposal.NetworkId,
            RandomNonZero32(),
            U64(0),
            new byte[32],
            ContactCodec.ArtifactReference(ProtocolMagic.XRA1, xra).CanonicalBytes,
            proposal.Pmt2ArtifactReference,
            pms.ArtifactHash,
            proposal.Xnv1CoreReference,
            proposal.Xnh1CoreReference,
            RandomNonZero32(),
            xra.Field(10),
            xra.Field(11),
            pmt.Field(6),
            new byte[] { replicaCount },
            replicaEntries,
            U64(request.IssuedAtUnixSeconds),
            U64(request.IssuedAtUnixSeconds),
            U64(request.ExpiresAtUnixSeconds),
            proposal.Adh1CoreReference,
            new byte[] { checked((byte)signers.Length) },
            PlaceholderReceipts(signers),
        };
        return await SignRecordAsync(
            ProtocolMagic.XRC1, fields, 20,
            ContactRouteAuthoritySignaturePurpose.LiveRoute,
            signers, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<ContactRecord> AuthorSuccessorAsync(
        VerifiedContactRouteProposalAuthority proposal,
        ContactRecord pmt,
        ContactRecord pms,
        ContactRecord xrc,
        ContactRouteThresholdAuthoringRequest request,
        SignerBinding[] signers,
        CancellationToken cancellationToken)
    {
        var xrcReference = ContactCodec.ArtifactReference(
            ProtocolMagic.XRC1, xrc).CanonicalBytes;
        var fields = new ReadOnlyMemory<byte>[]
        {
            proposal.NetworkId,
            xrc.Field(2),
            U64(1),
            xrc.CoreHash,
            xrcReference,
            xrcReference,
            ContactCodec.ArtifactReference(ProtocolMagic.PMT2, pmt).CanonicalBytes,
            proposal.Xnv1CoreReference,
            pms.ArtifactHash,
            U64(request.IssuedAtUnixSeconds),
            U64(request.ExpiresAtUnixSeconds),
            proposal.Adh1CoreReference,
            new byte[] { checked((byte)signers.Length) },
            PlaceholderReceipts(signers),
        };
        return await SignRecordAsync(
            ProtocolMagic.XSS1, fields, 13,
            ContactRouteAuthoritySignaturePurpose.SuccessorCheckpoint,
            signers, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<ContactRecord> SignRecordAsync(
        string magic,
        ReadOnlyMemory<byte>[] fields,
        int receiptIndex,
        ContactRouteAuthoritySignaturePurpose purpose,
        SignerBinding[] signers,
        CancellationToken cancellationToken)
    {
        var provisional = ContactCodec.AuthorForOperationalAuthority(magic, fields);
        var rows = new byte[signers.Length * 96];
        for (var index = 0; index < signers.Length; index++)
        {
            var signer = signers[index];
            signer.Id.CopyTo(rows, index * 96);
            var request = new ContactRouteAuthoritySigningRequest(
                purpose, provisional.Field(1).Span, provisional.SignatureInput.Span);
            var signature = rows.AsMemory(index * 96 + 32, 64);
            try
            {
                var written = await signer.Signer.SignAsync(
                    request, signature, cancellationToken).ConfigureAwait(false);
                if (written != 64 || signature.Span.IndexOfAnyExcept((byte)0) < 0 ||
                    !PublicKeyAuth.VerifyDetached(
                        signature.ToArray(), provisional.SignatureInput.ToArray(), signer.PublicKey))
                    throw new ContactPublicationAuthoringException(
                        "InvalidRouteWitnessSignature",
                        "A route-authority witness returned an invalid signature.");
            }
            finally
            {
                request.Clear();
            }
        }
        fields[receiptIndex] = rows;
        return ContactCodec.AuthorForOperationalAuthority(magic, fields);
    }

    private static void ValidateAdvertisement(
        VerifiedContactRouteProposalAuthority proposal,
        ContactRecord xra) => ContactRouteAdvertisementVerifier.Validate(proposal, xra);

    private static SignerBinding[] ValidateSigners(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<IContactRouteAuthorityWitnessSigner> signers)
    {
        if (signers.Count is < 1 or > 32)
            throw new ContactPublicationAuthoringException(
                "InsufficientRouteWitnesses", "Route authoring requires 1..32 witnesses.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        var result = new SignerBinding[signers.Count];
        for (var index = 0; index < signers.Count; index++)
        {
            var signer = signers[index] ?? throw new ContactPublicationAuthoringException(
                "UnknownRouteWitness", "A configured route witness is null.");
            var id = signer.WitnessId.ToArray();
            if (id.Length != 32 || id.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !ids.Add(Convert.ToHexString(id)))
                throw new ContactPublicationAuthoringException(
                    "DuplicateOrInvalidRouteWitness",
                    "Route witness IDs must be exact, non-zero and unique.");
            var witness = authority.WitnessKeys.SingleOrDefault(candidate =>
                Fixed(candidate.Id.Span, id)) ?? throw new ContactPublicationAuthoringException(
                    "UnknownRouteWitness", "A route witness is outside the current XNA1 set.");
            domains.Add(Convert.ToHexString(witness.FailureDomainHash.Span));
            result[index] = new SignerBinding(
                signer, id, witness.Ed25519PublicKey.ToArray());
        }
        if (result.Length < authority.WitnessThreshold ||
            domains.Count < authority.WitnessThreshold)
            throw new ContactPublicationAuthoringException(
                "InsufficientRouteWitnesses",
                "Route witnesses do not satisfy the current threshold and failure domains.");
        Array.Sort(result, static (left, right) =>
            left.Id.AsSpan().SequenceCompareTo(right.Id));
        return result;
    }

    private static byte[] RankReplicas(
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> pmtReference,
        ReadOnlySpan<byte> selectionEpoch,
        ReadOnlySpan<byte> placementInput,
        ReadOnlySpan<byte> candidates,
        byte replicaCount)
    {
        var ranked = new List<(byte[] NodeId, byte[] Score)>();
        for (var offset = 0; offset < candidates.Length; offset += 136)
        {
            var nodeId = candidates.Slice(offset, 32).ToArray();
            ranked.Add((nodeId, RendezvousScore(
                network, pmtReference, selectionEpoch, placementInput, nodeId)));
        }
        ranked.Sort(static (left, right) =>
        {
            var score = left.Score.AsSpan().SequenceCompareTo(right.Score);
            return score != 0 ? score : left.NodeId.AsSpan().SequenceCompareTo(right.NodeId);
        });
        if (replicaCount is < 2 or > 5 || ranked.Count < replicaCount)
            throw new ContactPublicationAuthoringException(
                "RouteReplicaSetUnavailable",
                "The current PMT2 cannot satisfy its route replication factor.");
        var result = new byte[replicaCount * 32];
        for (var index = 0; index < replicaCount; index++)
            ranked[index].NodeId.CopyTo(result, index * 32);
        return result;
    }

    private static byte[] RendezvousScore(
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> pmtReference,
        ReadOnlySpan<byte> selectionEpoch,
        ReadOnlySpan<byte> placementInput,
        ReadOnlySpan<byte> nodeId)
    {
        var label = Encoding.ASCII.GetBytes("Deep/XPoint/V1/PMS2/rendezvous-sha256/v2");
        var input = new byte[label.Length + 1 + network.Length + pmtReference.Length +
            selectionEpoch.Length + placementInput.Length + nodeId.Length];
        var offset = 0;
        label.CopyTo(input, offset); offset += label.Length;
        input[offset++] = 0;
        network.CopyTo(input.AsSpan(offset)); offset += network.Length;
        pmtReference.CopyTo(input.AsSpan(offset)); offset += pmtReference.Length;
        selectionEpoch.CopyTo(input.AsSpan(offset)); offset += selectionEpoch.Length;
        placementInput.CopyTo(input.AsSpan(offset)); offset += placementInput.Length;
        nodeId.CopyTo(input.AsSpan(offset));
        try { return SHA256.HashData(input); }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    private static byte[] PlaceholderReceipts(SignerBinding[] signers)
    {
        var rows = new byte[signers.Length * 96];
        for (var index = 0; index < signers.Length; index++)
        {
            signers[index].Id.CopyTo(rows, index * 96);
            rows[index * 96 + 32] = 1;
        }
        return rows;
    }

    private static byte[] EncodeProjection(
        string magic,
        IReadOnlyList<ReadOnlyMemory<byte>> fields,
        int count)
    {
        var length = checked(12 + fields.Take(count).Sum(field => 8 + field.Length));
        var result = new byte[length];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8), checked((ushort)count));
        var offset = 12;
        for (var index = 0; index < count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(
                result.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(
                result.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].Span.CopyTo(result.AsSpan(offset));
            offset += fields[index].Length;
        }
        return result;
    }

    private static byte[] RandomNonZero32()
    {
        var result = new byte[32];
        do RandomNumberGenerator.Fill(result);
        while (result.AsSpan().IndexOfAnyExcept((byte)0) < 0);
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

    private sealed record SignerBinding(
        IContactRouteAuthorityWitnessSigner Signer,
        byte[] Id,
        byte[] PublicKey);
}
