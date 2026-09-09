using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

internal static class PreKeyInventoryTestData
{
    internal sealed record ClaimManifest(
        Xpi1Record Manifest,
        byte[] ExactXpi1,
        ushort InventoryIndex,
        byte[] InclusionProof,
        IReadOnlyList<byte[]> OrderedHashes);

    internal static ClaimManifest CreateClaimManifest(
        Dpk2Record selected,
        ReadOnlySpan<byte> serviceCapability32,
        ReadOnlySpan<byte> xps1Reference38,
        ReadOnlySpan<byte> currentDrs1Reference38,
        ReadOnlySpan<byte> devicePrivateKey = default,
        ushort inventoryIndex = 0,
        ushort count = 32,
        ulong inventoryEpoch = 1,
        ReadOnlySpan<byte> predecessorXpi1Hash32 = default,
        ReadOnlySpan<byte> lastResortDpk2Hash32 = default)
    {
        if (count is < 32 or > 4096 || inventoryIndex >= count)
            throw new ArgumentOutOfRangeException(nameof(count));

        var exactSelected = Dpk2Codec.Encode(selected);
        var selectedHash = ContactCodec.Sha256Domain("Deep/Messaging/V2/exact-dpk2", exactSelected);
        var hashes = Enumerable.Range(0, count)
            .Select(index => SHA256.HashData(Encoding.ASCII.GetBytes($"inventory-member-{index}")))
            .ToArray();
        hashes[inventoryIndex] = selectedHash;
        var root = PreKeyInventoryPublicationVerifier.ComputeMerkleRoot(hashes);
        var predecessor = predecessorXpi1Hash32.IsEmpty ? new byte[32] : predecessorXpi1Hash32.ToArray();
        var lastHash = lastResortDpk2Hash32.IsEmpty
            ? SHA256.HashData("last-resort-member"u8)
            : lastResortDpk2Hash32.ToArray();
        var fields = new Xpi1UnsignedFields(
            selected.NetworkId.Span,
            serviceCapability32,
            selected.ResponderDeviceId.Span,
            selected.ResponderDpd1Ref.Span,
            selected.PrekeyServiceGeneration,
            xps1Reference38,
            inventoryEpoch,
            predecessor,
            count,
            root,
            lastHash,
            selected.DeviceDirectoryHeadHash.Span,
            currentDrs1Reference38,
            selected.NotBefore,
            selected.ExpiresAt);
        var signatureInput = Xpi1Codec.CreateSignatureInput(fields);
        var signature = devicePrivateKey.IsEmpty
            ? Enumerable.Repeat((byte)0xa5, 64).ToArray()
            : PublicKeyAuth.SignDetached(signatureInput, devicePrivateKey.ToArray());
        var exactXpi1 = Xpi1Codec.Encode(fields, signature);
        return new ClaimManifest(
            Xpi1Codec.Decode(exactXpi1), exactXpi1, inventoryIndex,
            BuildProof(hashes, inventoryIndex), hashes);
    }

    internal static byte[] BuildProof(IReadOnlyList<byte[]> exactDpk2Hashes, ushort inventoryIndex)
    {
        var width = 1;
        while (width < exactDpk2Hashes.Count) width <<= 1;
        var level = new byte[width][];
        for (var index = 0; index < width; index++)
        {
            var position = U16(checked((ushort)index));
            level[index] = index < exactDpk2Hashes.Count
                ? ContactCodec.Sha256Domain(
                    "Deep/ContactResolver/V1/prekey-inventory-leaf",
                    Join(position, exactDpk2Hashes[index]))
                : ContactCodec.Sha256Domain(
                    "Deep/ContactResolver/V1/prekey-inventory-empty", position);
        }

        var siblings = new List<byte[]>();
        var current = inventoryIndex;
        while (level.Length > 1)
        {
            siblings.Add(level[current ^ 1].ToArray());
            var next = new byte[level.Length / 2][];
            for (var index = 0; index < next.Length; index++)
                next[index] = ContactCodec.Sha256Domain(
                    "Deep/ContactResolver/V1/prekey-inventory-node",
                    Join(level[index * 2], level[(index * 2) + 1]));
            level = next;
            current >>= 1;
        }
        return Join(siblings.ToArray());
    }

    internal static byte[] Reference(string magic, ReadOnlySpan<byte> hash32)
    {
        var result = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash32.CopyTo(result.AsSpan(6));
        return result;
    }

    internal static byte[] U16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    internal static byte[] Join(params byte[][] values)
    {
        var result = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(result, offset);
            offset += value.Length;
        }
        return result;
    }
}
