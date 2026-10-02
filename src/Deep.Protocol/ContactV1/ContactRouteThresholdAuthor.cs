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

/// <summary>
/// Rehydrates a remote threshold-authority response only after all exact
/// PMS2/XRC1/XSS1 bindings, validity windows and witness thresholds verify.
/// No device-custody callback is required by this verifier.
/// </summary>
public static class ContactRouteThresholdVerifier
{

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

    internal static byte[] RankReplicas(
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

    internal static byte[] EncodeProjection(
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
