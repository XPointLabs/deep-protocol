using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2PreKeyClaimResultCodecTests
{
    [Theory]
    [InlineData((ushort)1)]
    [InlineData((ushort)2)]
    public void LastResortResult_BindsExactDID2ClaimButDoesNotMintAuthority(
        ushort statusValue)
    {
        var status = (Xpc1V2Status)statusValue;
        var fixture = DeepIdV2PreKeyClaimCommitmentTests.Build(
            Dpk2PrekeyKind.LastResort);
        var payload = SuccessPayload(fixture);
        var wire = DeepIdV2PreKeyClaimResultCodec.Encode(fixture.Request,
            status, Xpc1V2MutationOutcome.DurablyCommitted,
            1_700_000_123, 0, payload);
        var result = DeepIdV2PreKeyClaimResultCodec.Decode(wire,
            fixture.Request);

        Assert.False(DeepIdV2PreKeyClaimResultCodec.RuntimeActivation);
        Assert.Equal(4096, wire.Length);
        Assert.Equal(status, result.Status);
        Assert.Equal(Xpc1V2MutationOutcome.DurablyCommitted,
            result.MutationOutcome);
        Assert.Equal(fixture.Offering, result.Field(16).ToArray());
        Assert.Equal(fixture.Manifest, result.Field(26).ToArray());
        Assert.Empty(result.Field(28).ToArray());

        var wrongReceipt = wire.ToArray();
        wrongReceipt[FieldOffset(wrongReceipt, 18)] ^= 1;
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyClaimResultCodec.Decode(wrongReceipt,
                fixture.Request));

        var wrongCounter = wire.ToArray();
        wrongCounter[FieldOffset(wrongCounter, 23) + 1] = 0;
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyClaimResultCodec.Decode(wrongCounter,
                fixture.Request));

        var oldEnvelope = wire.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(oldEnvelope.AsSpan(4), 1);
        Assert.Equal(ApplicationCoreRejection.WrongVersion,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                DeepIdV2PreKeyClaimResultCodec.Decode(oldEnvelope,
                    fixture.Request)).Rejection);

        var nonZeroPadding = wire.ToArray();
        nonZeroPadding[^1] = 1;
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyClaimResultCodec.Decode(nonZeroPadding,
                fixture.Request));

        var wrongRequest = fixture.Request.ToArray();
        wrongRequest[FieldOffset(wrongRequest, 2)] ^= 1;
        wrongRequest[FieldOffset(wrongRequest, 22)] ^= 1;
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyClaimResultCodec.Decode(wire, wrongRequest));

        foreach (var outside in new[] { 1_700_000_099UL, 1_700_100_000UL })
        {
            Assert.Equal(ApplicationCoreRejection.InvalidTimeRange,
                Assert.Throws<ApplicationCoreFormatException>(() =>
                    DeepIdV2PreKeyClaimResultCodec.Encode(fixture.Request,
                        status, Xpc1V2MutationOutcome.DurablyCommitted,
                        outside, 0, payload)).Rejection);
        }
    }

    [Fact]
    public void FailureResult_UsesClosedStatusAndRetryMatrix()
    {
        var fixture = DeepIdV2PreKeyClaimCommitmentTests.Build(
            Dpk2PrekeyKind.LastResort);
        var wire = DeepIdV2PreKeyClaimResultCodec.Encode(fixture.Request,
            Xpc1V2Status.PreKeysUnavailable, Xpc1V2MutationOutcome.None,
            123, 0, []);
        Assert.Equal(256, wire.Length);
        Assert.Equal(Xpc1V2Status.PreKeysUnavailable,
            DeepIdV2PreKeyClaimResultCodec.Decode(wire, fixture.Request).Status);
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyClaimResultCodec.Encode(fixture.Request,
                Xpc1V2Status.PreKeysUnavailable,
                Xpc1V2MutationOutcome.DurablyCommitted, 123, 0, []));
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyClaimResultCodec.Encode(fixture.Request,
                Xpc1V2Status.RateLimited, Xpc1V2MutationOutcome.None,
                123, 0, []));
    }

    [Fact]
    public void OneTimeResult_RequiresExactMerkleMembership()
    {
        var original = DeepIdV2PreKeyClaimCommitmentTests.Build(
            Dpk2PrekeyKind.OneTime);
        var offering = DeepIdV2Dpk2Codec.Decode(original.Offering);
        var leaves = new byte[32][];
        leaves[0] = offering.ExactHash.ToArray();
        for (var index = 1; index < leaves.Length; index++)
        {
            leaves[index] = new byte[32];
            leaves[index].AsSpan().Fill(checked((byte)index));
        }
        var (root, proof) = RootAndIndexZeroProof(leaves);
        var originalManifest = DeepIdV2PreKeyManifestCodec.Decode(
            original.Manifest);
        var manifestFields = Enumerable.Range(1, 15)
            .Select(originalManifest.Field).ToArray();
        manifestFields[9] = root;
        var exactManifest = DeepIdV2PreKeyManifestCodec.Encode(
            manifestFields, originalManifest.Field(16).Span);
        var fixture = (original.Request, original.Offering, exactManifest);
        var payload = SuccessPayload(fixture, 0);
        payload[11] = Be16(0);
        payload[12] = proof;

        var wire = DeepIdV2PreKeyClaimResultCodec.Encode(fixture.Request,
            Xpc1V2Status.Claimed, Xpc1V2MutationOutcome.DurablyCommitted,
            1_700_000_123, 0, payload);
        Assert.Equal(4096, wire.Length);
        Assert.Equal(Xpc1V2Status.Claimed,
            DeepIdV2PreKeyClaimResultCodec.Decode(wire, fixture.Request).Status);

        var wrongProof = wire.ToArray();
        wrongProof[FieldOffset(wrongProof, 28)] ^= 1;
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyClaimResultCodec.Decode(wrongProof,
                fixture.Request));
    }

    internal static ReadOnlyMemory<byte>[] SuccessPayload(
        (byte[] Request, byte[] Offering, byte[] Manifest) fixture,
        ushort counter = 1)
    {
        var offering = DeepIdV2Dpk2Codec.Decode(fixture.Offering);
        var manifest = DeepIdV2PreKeyManifestCodec.Decode(fixture.Manifest);
        var replicaRows = new byte[193];
        replicaRows[0] = 2;
        replicaRows.AsSpan(1, 32).Fill(0x11);
        replicaRows.AsSpan(33, 64).Fill(0x21);
        replicaRows.AsSpan(97, 32).Fill(0x12);
        replicaRows.AsSpan(129, 64).Fill(0x22);
        return
        [
            fixture.Offering,
            offering.Kind == Dpk2PrekeyKind.OneTime
                ? offering.OneTimePrekeyId : new byte[32],
            DeepIdV2PreKeyClaimCommitment.ComputeReceiptHash(
                fixture.Request, fixture.Offering, fixture.Manifest, 3, counter),
            offering.DeviceDirectoryHeadHash,
            manifest.Field(13),
            Be64(offering.PrekeyServiceGeneration),
            Be64(offering.ExpiresAt),
            Be16(counter),
            Be64(3),
            replicaRows,
            fixture.Manifest,
            Be16(ushort.MaxValue),
            ReadOnlyMemory<byte>.Empty
        ];
    }

    private static (byte[] Root, byte[] Proof) RootAndIndexZeroProof(
        IReadOnlyList<byte[]> exactHashes)
    {
        var level = new byte[exactHashes.Count][];
        for (var index = 0; index < level.Length; index++)
        {
            var leafInput = new byte[34];
            BinaryPrimitives.WriteUInt16BigEndian(leafInput, checked((ushort)index));
            exactHashes[index].CopyTo(leafInput, 2);
            level[index] = ApplicationCoreFormat.Sha256Domain(
                "Deep/ContactResolver/V2/prekey-inventory-leaf", leafInput);
        }
        var proof = new byte[160];
        for (var depth = 0; depth < 5; depth++)
        {
            level[1].CopyTo(proof, depth * 32);
            var next = new byte[level.Length / 2][];
            for (var index = 0; index < next.Length; index++)
            {
                var pair = new byte[64];
                level[index * 2].CopyTo(pair, 0);
                level[index * 2 + 1].CopyTo(pair, 32);
                next[index] = ApplicationCoreFormat.Sha256Domain(
                    "Deep/ContactResolver/V2/prekey-inventory-node", pair);
            }
            level = next;
        }
        return (level[0], proof);
    }

    private static int FieldOffset(ReadOnlySpan<byte> wire, int soughtTag)
    {
        var count = BinaryPrimitives.ReadUInt16BigEndian(wire[8..10]);
        var offset = 12;
        for (var index = 0; index < count; index++)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(wire.Slice(offset, 2));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                wire.Slice(offset + 4, 4)));
            offset += 8;
            if (tag == soughtTag) return offset;
            offset += length;
        }
        throw new ArgumentOutOfRangeException(nameof(soughtTag));
    }

    private static byte[] Be16(ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] Be64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }
}
