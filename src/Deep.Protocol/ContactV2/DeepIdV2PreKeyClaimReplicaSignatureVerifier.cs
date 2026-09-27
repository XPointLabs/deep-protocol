using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Two selected replica signatures over one exact XPC1 V2 claim tuple.
/// This is not inventory publication, durable CAS or message authority.
/// </summary>
public sealed class VerifiedXpc1V2ReplicaSignatures
{
    private readonly byte[] exactRequest;
    private readonly byte[] exactResult;
    private readonly byte[] placementHash;

    internal VerifiedXpc1V2ReplicaSignatures(ParsedXpk1V2 request,
        ParsedXpc1V2 result, VerifiedContactServicePlacement placement)
    {
        exactRequest = request.CanonicalBytes.ToArray();
        exactResult = result.WireBytes.ToArray();
        placementHash = placement.PlacementHash.ToArray();
    }

    public ReadOnlyMemory<byte> ExactRequest => exactRequest.ToArray();
    public ReadOnlyMemory<byte> ExactResult => exactResult.ToArray();
    public ReadOnlyMemory<byte> PlacementHash => placementHash.ToArray();
}

public static class DeepIdV2PreKeyClaimReplicaSignatureVerifier
{
    public static bool RuntimeActivation => false;

    public static VerifiedXpc1V2ReplicaSignatures Verify(
        ParsedXpk1V2 request, ParsedXpc1V2 result,
        VerifiedContactServicePlacement placement)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(placement);
        placement.Network.EnsureCurrent();
        _ = DeepIdV2PreKeyClaimResultCodec.Decode(
            result.WireBytes.Span, request.CanonicalBytes.Span);
        if (result.Status is not (Xpc1V2Status.Claimed or Xpc1V2Status.Replay) ||
            result.MutationOutcome != Xpc1V2MutationOutcome.DurablyCommitted ||
            placement.RequestKind != ContactServiceRequestKind.ClaimPreKey ||
            placement.ServiceClass != ContactServiceClass.PreKeyClaim ||
            !placement.Binds(ContactServiceRequestKind.ClaimPreKey,
                request.Field(16)) ||
            !Fixed(request.Field(1).Span, placement.Network.NetworkId.Span) ||
            !Fixed(request.Field(3).Span, placement.ViewHash.Span) ||
            !Fixed(request.Field(4).Span, placement.PlacementHash.Span))
            Reject("XPC1 V2 claim is outside the current selected placement.");

        var replicas = placement.RankedReplicaNodeIds;
        var rows = result.Field(25).Span;
        if (replicas.Count != 2 || rows.Length != 193 || rows[0] != 2 ||
            Fixed(replicas[0].Span, replicas[1].Span))
            Reject("XPC1 V2 has no exact two-replica placement.");
        var first = rows.Slice(1, 96);
        var second = rows.Slice(97, 96);
        if (!(Fixed(first[..32], replicas[0].Span) &&
              Fixed(second[..32], replicas[1].Span) ||
              Fixed(first[..32], replicas[1].Span) &&
              Fixed(second[..32], replicas[0].Span)))
            Reject("XPC1 V2 receipts are not from both selected replicas.");

        var generation = BinaryPrimitives.ReadUInt64BigEndian(result.Field(24).Span);
        var counter = BinaryPrimitives.ReadUInt16BigEndian(result.Field(23).Span);
        var input = DeepIdV2PreKeyClaimCommitment.CreateReplicaSignatureInput(
            request.CanonicalBytes.Span, result.Field(16).Span,
            result.Field(26).Span, generation, counter);
        try
        {
            VerifyOne(first, input, placement);
            VerifyOne(second, input, placement);
        }
        finally { CryptographicOperations.ZeroMemory(input); }
        return new VerifiedXpc1V2ReplicaSignatures(request, result, placement);
    }

    private static void VerifyOne(ReadOnlySpan<byte> row,
        ReadOnlySpan<byte> input, VerifiedContactServicePlacement placement)
    {
        var key = placement.Network.ResolveNodeIdentityPublicKey(
            row[..32].ToArray());
        if (!PublicKeyAuth.VerifyDetached(row[32..].ToArray(),
                input.ToArray(), key.ToArray()))
            Reject("XPC1 V2 selected replica signature is invalid.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static void Reject(string message) => throw ApplicationCoreFormat.Error(
        ApplicationCoreValidationStage.CryptographicVerification,
        ApplicationCoreRejection.VerificationFailed, message);
}
