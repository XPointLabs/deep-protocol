using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxPlacementCommitment
{
    private static ReadOnlySpan<byte> Domain => "deep.mailbox.placement-commitment.v2"u8;

    public static byte[] Compute(BlindedPlacementId placementId)
    {
        ArgumentNullException.ThrowIfNull(placementId);
        var input = new byte[4 + Domain.Length + 4 + placementId.Bytes.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, checked((uint)Domain.Length));
        Domain.CopyTo(input.AsSpan(4));
        var offset = 4 + Domain.Length;
        BinaryPrimitives.WriteUInt32BigEndian(
            input.AsSpan(offset),
            checked((uint)placementId.Bytes.Length));
        placementId.Bytes.Span.CopyTo(input.AsSpan(offset + 4));
        return SHA256.HashData(input);
    }
}
