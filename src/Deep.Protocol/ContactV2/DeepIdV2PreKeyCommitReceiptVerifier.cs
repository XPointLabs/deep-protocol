using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Closes the two selected XIC1 signatures against one exact XPP1 and current
/// NETCODEC placement. Inventory authorization, durable replica state and a
/// subsequent XPK1 claim remain independent requirements.
/// </summary>
public static class DeepIdV2PreKeyCommitReceiptVerifier
{
    public static bool RuntimeActivation => false;

    public static void VerifyPair(ParsedXpp1V2 publication,
        VerifiedContactServicePlacement placement,
        ParsedXic1V2 first, ParsedXic1V2 second)
    {
        ArgumentNullException.ThrowIfNull(publication);
        ArgumentNullException.ThrowIfNull(placement);
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(second);
        placement.Network.EnsureCurrent();
        var replicas = placement.RankedReplicaNodeIds;
        if (replicas.Count != 2 ||
            placement.RequestKind != ContactServiceRequestKind.PublishPreKeyInventory ||
            !placement.Binds(ContactServiceRequestKind.PublishPreKeyInventory,
                publication.Manifest.Field(2)) ||
            !Fixed(placement.Network.NetworkId.Span, publication.NetworkId.Span) ||
            !Fixed(placement.PlacementHash.Span, publication.PlacementHash.Span) ||
            Fixed(replicas[0].Span, replicas[1].Span))
            Reject("XIC1 pair is outside the current publication placement.");

        var firstId = first.Field(5);
        var secondId = second.Field(5);
        if (Fixed(firstId.Span, secondId.Span) ||
            !(Fixed(firstId.Span, replicas[0].Span) &&
                Fixed(secondId.Span, replicas[1].Span) ||
              Fixed(firstId.Span, replicas[1].Span) &&
                Fixed(secondId.Span, replicas[0].Span)))
            Reject("XIC1 receipts are not from both selected replicas.");

        VerifyOne(publication, placement, first);
        VerifyOne(publication, placement, second);
    }

    private static void VerifyOne(ParsedXpp1V2 publication,
        VerifiedContactServicePlacement placement, ParsedXic1V2 receipt)
    {
        var committedAt = BinaryPrimitives.ReadUInt64BigEndian(receipt.Field(6).Span);
        var notBefore = BinaryPrimitives.ReadUInt64BigEndian(
            publication.Manifest.Field(14).Span);
        var expiresAt = BinaryPrimitives.ReadUInt64BigEndian(
            publication.Manifest.Field(15).Span);
        if (!Fixed(receipt.Field(1).Span, publication.NetworkId.Span) ||
            !Fixed(receipt.Field(2).Span, publication.PublicationOperationId.Span) ||
            !Fixed(receipt.Field(3).Span, publication.Manifest.ExactHash.Span) ||
            !Fixed(receipt.Field(4).Span, publication.PlacementHash.Span) ||
            committedAt < notBefore || committedAt >= expiresAt ||
            committedAt > placement.ValidUntilUnixSeconds)
            Reject("XIC1 receipt differs from the exact publication or its validity window.");
        var publicKey = placement.Network.ResolveNodeIdentityPublicKey(receipt.Field(5));
        if (!PublicKeyAuth.VerifyDetached(receipt.Field(7).ToArray(),
                receipt.SignatureInput.ToArray(), publicKey.ToArray()))
            Reject("XIC1 selected replica signature is invalid.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void Reject(string message) => throw ApplicationCoreFormat.Error(
        ApplicationCoreValidationStage.CryptographicVerification,
        ApplicationCoreRejection.VerificationFailed, message);
}
