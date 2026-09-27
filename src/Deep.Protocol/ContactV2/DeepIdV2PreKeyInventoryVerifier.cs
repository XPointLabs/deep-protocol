using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Verifies the exact complete DID2 XPI1/DPK2 inventory commitment. It does
/// not verify XPP1, replica receipts, predecessor custody, or a live claim.
/// </summary>
public static class DeepIdV2PreKeyInventoryVerifier
{
    public static bool RuntimeActivation => false;

    public static void VerifyComplete(ParsedDcr1V2 closure,
        DeepIdV2CurrentContactAuthorization currentAuthorization,
        ParsedXpi1V2 manifest,
        IReadOnlyList<ParsedDpk2V2> oneTimeMembers,
        ParsedDpk2V2 lastResortMember,
        ReadOnlySpan<byte> currentBootId, ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(closure);
        ArgumentNullException.ThrowIfNull(currentAuthorization);
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(oneTimeMembers);
        ArgumentNullException.ThrowIfNull(lastResortMember);
        if (oneTimeMembers.Count is < 32 or > 4096)
            Reject("XPI1 one-time DPK2 count is outside its closed bound.");
        var members = oneTimeMembers.ToArray();
        var declared = BinaryPrimitives.ReadUInt16BigEndian(manifest.FieldSpan(9));
        if (members.Length != declared || members.Length is < 32 or > 4096)
            Reject("XPI1 does not commit the exact complete one-time DPK2 count.");

        DeepIdV2PreKeyManifestBinding.Verify(closure, currentAuthorization,
            manifest, currentBootId, currentMonotonicSample);
        var hashes = new byte[members.Length][];
        var seenHashes = new HashSet<string>(StringComparer.Ordinal);
        ReadOnlyMemory<byte> previousId = default;
        for (var index = 0; index < members.Length; index++)
        {
            var member = members[index] ?? throw new ArgumentException(
                "A one-time DPK2 member is missing.", nameof(oneTimeMembers));
            if (member.Kind != Dpk2PrekeyKind.OneTime)
                Reject("The one-time XPI1 inventory contains a last-resort DPK2.");
            DeepIdV2Dpk2MemberBinding.VerifyAfterManifest(closure,
                currentAuthorization, manifest, member);
            var id = member.OneTimePrekeyId;
            if (!previousId.IsEmpty &&
                previousId.Span.SequenceCompareTo(id.Span) >= 0)
                Reject("One-time DPK2 members are not strictly ordered by pre-key ID.");
            previousId = id;
            hashes[index] = member.ExactHash.ToArray();
            if (!seenHashes.Add(Convert.ToHexString(hashes[index])))
                Reject("The XPI1 inventory repeats an exact DPK2 hash.");
        }

        if (lastResortMember.Kind != Dpk2PrekeyKind.LastResort)
            Reject("XPI1 has no exact last-resort DPK2 member.");
        DeepIdV2Dpk2MemberBinding.VerifyAfterManifest(closure,
            currentAuthorization, manifest, lastResortMember);
        if (lastResortMember.Record.ReuseLimit > GetLastResortReuseLimit(
                closure, currentAuthorization, manifest))
            Reject("Last-resort DPK2 exceeds its exact XPS1 reuse limit.");

        var root = ComputeRoot(hashes);
        if (!CryptographicOperations.FixedTimeEquals(root,
                manifest.FieldSpan(10)) ||
            !CryptographicOperations.FixedTimeEquals(
                lastResortMember.ExactHash.Span, manifest.FieldSpan(11)))
            Reject("XPI1 does not commit the exact ordered DPK2 inventory.");
    }

    internal static byte[] ComputeRoot(IReadOnlyList<byte[]> exactHashes)
    {
        ArgumentNullException.ThrowIfNull(exactHashes);
        if (exactHashes.Count is < 32 or > 4096)
            throw new ArgumentOutOfRangeException(nameof(exactHashes));
        var width = 1;
        while (width < exactHashes.Count) width <<= 1;
        var level = new byte[width][];
        Span<byte> position = stackalloc byte[2];
        Span<byte> leafInput = stackalloc byte[34];
        for (var index = 0; index < width; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(position,
                checked((ushort)index));
            if (index < exactHashes.Count)
            {
                var hash = exactHashes[index];
                if (hash is null || hash.Length != 32)
                    throw new ArgumentException(
                        "Every exact DPK2 hash must be 32 bytes.",
                        nameof(exactHashes));
                position.CopyTo(leafInput);
                hash.CopyTo(leafInput[2..]);
                level[index] = ApplicationCoreFormat.Sha256Domain(
                    "Deep/ContactResolver/V2/prekey-inventory-leaf",
                    leafInput);
            }
            else
            {
                level[index] = ApplicationCoreFormat.Sha256Domain(
                    "Deep/ContactResolver/V2/prekey-inventory-empty",
                    position);
            }
        }
        Span<byte> input = stackalloc byte[64];
        while (level.Length > 1)
        {
            var next = new byte[level.Length / 2][];
            for (var index = 0; index < next.Length; index++)
            {
                level[index * 2].CopyTo(input);
                level[index * 2 + 1].CopyTo(input[32..]);
                next[index] = ApplicationCoreFormat.Sha256Domain(
                    "Deep/ContactResolver/V2/prekey-inventory-node",
                    input);
            }
            level = next;
        }
        return level[0];
    }

    private static ushort GetLastResortReuseLimit(ParsedDcr1V2 closure,
        DeepIdV2CurrentContactAuthorization currentAuthorization,
        ParsedXpi1V2 manifest)
    {
        var devices = currentAuthorization.Authorization.Directory.Record
            .ActiveDevices;
        var index = -1;
        for (var current = 0; current < devices.Count; current++)
            if (devices[current].DeviceId.Span.SequenceEqual(manifest.FieldSpan(3)))
            {
                index = current;
                break;
            }
        if (index < 0)
            Reject("XPI1 responder has no current XPS1 descriptor.");
        var list = closure.Bundle.FieldSpan(12);
        var xps = list.Slice(1 + index * 356 + 4, 352);
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[12];
        ApplicationCoreFormat.Preflight(xps, ProtocolMagicBytes.XPS1, 12,
            352, 352, fields, 1, 0x0201);
        return BinaryPrimitives.ReadUInt16BigEndian(
            ApplicationCoreFormat.Field(xps, fields, 9));
    }

    private static void Reject(string message) => throw ApplicationCoreFormat.Error(
        ApplicationCoreValidationStage.CryptographicVerification,
        ApplicationCoreRejection.VerificationFailed, message);
}
