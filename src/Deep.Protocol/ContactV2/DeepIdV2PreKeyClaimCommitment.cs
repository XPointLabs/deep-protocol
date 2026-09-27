using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Non-authoritative XPC1 V2 commitment inputs. These functions only derive
/// bytes; they do not prove publication, placement, replica signatures or a
/// durable claim. The caller must verify those separately.
/// </summary>
public static class DeepIdV2PreKeyClaimCommitment
{
    public const int TupleLength = 138;
    public static bool RuntimeActivation => false;

    public static byte[] CreateReplicaSignatureInput(
        ReadOnlySpan<byte> exactXpk1, ReadOnlySpan<byte> exactDpk2,
        ReadOnlySpan<byte> exactXpi1, ulong claimCommitGeneration,
        ushort lastResortUseCounter) =>
        ApplicationCoreFormat.SignatureInput(
            "Deep/ContactResolver/V2/prekey-claim-commit",
            CreateTuple(exactXpk1, exactDpk2, exactXpi1,
                claimCommitGeneration, lastResortUseCounter),
            DeepIdV2Codec.Suite);

    public static byte[] ComputeReceiptHash(
        ReadOnlySpan<byte> exactXpk1, ReadOnlySpan<byte> exactDpk2,
        ReadOnlySpan<byte> exactXpi1, ulong claimCommitGeneration,
        ushort lastResortUseCounter) =>
        ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V2/prekey-claim-receipt",
            CreateTuple(exactXpk1, exactDpk2, exactXpi1,
                claimCommitGeneration, lastResortUseCounter));

    public static byte[] CreateTuple(ReadOnlySpan<byte> exactXpk1,
        ReadOnlySpan<byte> exactDpk2, ReadOnlySpan<byte> exactXpi1,
        ulong claimCommitGeneration, ushort lastResortUseCounter)
    {
        var request = DeepIdV2PreKeyClaimRequestCodec.Decode(exactXpk1);
        var offering = DeepIdV2Dpk2Codec.Decode(exactDpk2);
        var manifest = DeepIdV2PreKeyManifestCodec.Decode(exactXpi1);
        if (claimCommitGeneration == 0 ||
            !Fixed(request.Field(1).Span, offering.NetworkId.Span) ||
            !Fixed(request.Field(1).Span, manifest.Field(1).Span) ||
            !Fixed(request.Field(16).Span, manifest.Field(2).Span) ||
            !Fixed(request.Field(18).Span, manifest.Field(6).Span[6..]) ||
            !Fixed(request.Field(19).Span, offering.ResponderDeviceId.Span) ||
            !Fixed(request.Field(19).Span, manifest.Field(3).Span) ||
            !Fixed(offering.ResponderDpd1Reference.Span,
                manifest.Field(4).Span) ||
            !Fixed(offering.DeviceDirectoryHeadHash.Span,
                manifest.Field(12).Span) ||
            offering.PrekeyServiceGeneration != BinaryPrimitives
                .ReadUInt64BigEndian(manifest.Field(5).Span) ||
            offering.InventoryEpoch != BinaryPrimitives
                .ReadUInt64BigEndian(manifest.Field(7).Span) ||
            offering.NotBefore != BinaryPrimitives
                .ReadUInt64BigEndian(manifest.Field(14).Span) ||
            offering.ExpiresAt != BinaryPrimitives
                .ReadUInt64BigEndian(manifest.Field(15).Span) ||
            offering.IssuedAt > offering.NotBefore)
            throw new CryptographicException(
                "XPC1 V2 tuple inputs are not the same request, device and inventory epoch.");

        var oneTimePrekeyId = new byte[32];
        if (offering.Kind == Dpk2PrekeyKind.OneTime)
        {
            if (lastResortUseCounter != 0)
                throw new CryptographicException(
                    "One-time XPC1 V2 claim has a last-resort counter.");
            offering.OneTimePrekeyId.Span.CopyTo(oneTimePrekeyId);
        }
        else if (offering.Kind != Dpk2PrekeyKind.LastResort ||
            lastResortUseCounter is < 1 or > 64 ||
            lastResortUseCounter > offering.Record.ReuseLimit)
            throw new CryptographicException(
                "Last-resort XPC1 V2 counter is outside the exact DPK2 limit.");

        var tuple = new byte[TupleLength];
        request.RequestHash.Span.CopyTo(tuple);
        offering.ExactHash.Span.CopyTo(tuple.AsSpan(32));
        manifest.ExactHash.Span.CopyTo(tuple.AsSpan(64));
        oneTimePrekeyId.CopyTo(tuple, 96);
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(128, 8),
            claimCommitGeneration);
        BinaryPrimitives.WriteUInt16BigEndian(tuple.AsSpan(136, 2),
            lastResortUseCounter);
        return tuple;
    }

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
