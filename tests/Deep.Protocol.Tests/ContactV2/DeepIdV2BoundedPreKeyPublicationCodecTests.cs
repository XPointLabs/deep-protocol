using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2BoundedPreKeyPublicationCodecTests
{
    [Fact]
    public void ExactV2Aggregate_RoundTripsThroughBoundedManifestChunksAndCommit()
    {
        var aggregate = Aggregate();
        var sequence = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
            aggregate, Bytes(32, 0x31), Did2(), Dca1(), Xps1());
        Assert.False(DeepIdV2BoundedPreKeyPublicationCodec.RuntimeActivation);
        Assert.Equal(4, sequence.Count);
        var manifest = DeepIdV2BoundedPreKeyPublicationCodec.Decode(sequence[0]);
        var first = DeepIdV2BoundedPreKeyPublicationCodec.Decode(sequence[1]);
        var second = DeepIdV2BoundedPreKeyPublicationCodec.Decode(sequence[2]);
        var commit = DeepIdV2BoundedPreKeyPublicationCodec.Decode(sequence[3]);
        Assert.Equal(Xpp1V2FragmentPhase.Manifest, manifest.Phase);
        Assert.Equal(Did2(), manifest.PublisherDid2.ToArray());
        Assert.Equal(Dca1(), manifest.PublisherDca1.ToArray());
        Assert.Equal(Xps1(), manifest.PublisherXps1.ToArray());
        Assert.Empty(first.PublisherDid2.ToArray());
        Assert.Empty(first.PublisherDca1.ToArray());
        Assert.Empty(first.PublisherXps1.ToArray());
        Assert.Equal(Xpp1V2FragmentPhase.Chunk, first.Phase);
        Assert.Equal(Xpp1V2FragmentPhase.Commit, commit.Phase);
        Assert.Equal((ushort)2, manifest.ChunkCount);
        Assert.Equal(DeepIdV2BoundedPreKeyPublicationCodec.MaximumCanonicalBytes,
            sequence[1].Length);
        Assert.Equal(aggregate.Length, (int)manifest.AggregateLength);
        Assert.Equal(aggregate, first.Body.ToArray().Concat(second.Body.ToArray()));
        Assert.Equal(DeepIdV2BoundedPreKeyPublicationCodec.ComputeAggregateHash(
            aggregate), manifest.ExactAggregateHash.ToArray());
        Assert.Equal(ApplicationCoreFormat.Sha256Domain(
                DeepIdV2BoundedPreKeyPublicationCodec.RequestHashDomain,
                sequence[0]), manifest.RequestHash.ToArray());
        Assert.Equal(manifest.PublisherDescriptorCommitment.ToArray(),
            commit.PublisherDescriptorCommitment.ToArray());
        Assert.Equal(sequence.SelectMany(static fragment => fragment),
            DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(aggregate,
                Bytes(32, 0x31), Did2(), Dca1(), Xps1())
                .SelectMany(static fragment => fragment));

        var changedPublicSupport = sequence[0].ToArray();
        changedPublicSupport[FieldOffset(changedPublicSupport, 12) +
            DeepIdV2Codec.Did2Length +
            DeepIdV2ContactAuthorizationCodec.CanonicalLength] ^= 1;
        Assert.Equal(ApplicationCoreRejection.CrossFieldMismatch,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                DeepIdV2BoundedPreKeyPublicationCodec.Decode(changedPublicSupport))
                .Rejection);

        var retiredPublisher = sequence[0].ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(
            retiredPublisher.AsSpan(FieldOffset(retiredPublisher, 12) + 4), 1);
        Assert.Equal(ApplicationCoreRejection.EmbeddedRecordRejected,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                DeepIdV2BoundedPreKeyPublicationCodec.Decode(retiredPublisher))
                .Rejection);

        var changedPublisher = sequence[0].ToArray();
        changedPublisher[FieldOffset(changedPublisher, 12) +
            FieldOffset(Did2(), 1)] ^= 1;
        Assert.Equal(ApplicationCoreRejection.CrossFieldMismatch,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                DeepIdV2BoundedPreKeyPublicationCodec.Decode(changedPublisher))
                .Rejection);

        var changedChunk = sequence[1].ToArray();
        changedChunk[^1] ^= 1;
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2BoundedPreKeyPublicationCodec.Decode(changedChunk));

        var changedDescriptor = sequence[0].ToArray();
        changedDescriptor[^1] ^= 1;
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2BoundedPreKeyPublicationCodec.Decode(changedDescriptor));

        var wrongPhase = sequence[0].ToArray();
        wrongPhase[FieldOffset(wrongPhase, 1)] = 4;
        Assert.Equal(ApplicationCoreRejection.InvalidEnum,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                DeepIdV2BoundedPreKeyPublicationCodec.Decode(wrongPhase))
                .Rejection);

        var wrongIndex = sequence[1].ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(
            wrongIndex.AsSpan(FieldOffset(wrongIndex, 9)), ushort.MaxValue);
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2BoundedPreKeyPublicationCodec.Decode(wrongIndex));

        var oldEnvelope = sequence[0].ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(oldEnvelope.AsSpan(4), 1);
        Assert.Equal(ApplicationCoreRejection.WrongVersion,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                DeepIdV2BoundedPreKeyPublicationCodec.Decode(oldEnvelope))
                .Rejection);

        var tooLarge = sequence[1].ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(
            tooLarge.AsSpan(FieldOffset(tooLarge, 7)),
            DeepIdV2PreKeyPublicationCodec.MaximumTotalBytes + 1u);
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2BoundedPreKeyPublicationCodec.Decode(tooLarge));

        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2BoundedPreKeyPublicationCodec.Decode(aggregate));
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyPublicationCodec.Decode(sequence[0]));
    }

    private static byte[] Aggregate()
    {
        var oneTime = DeepIdV2PreKeyClaimCommitmentTests.Build(
            Dpk2PrekeyKind.OneTime);
        var lastResort = DeepIdV2PreKeyClaimCommitmentTests.Build(
            Dpk2PrekeyKind.LastResort);
        var manifest = DeepIdV2PreKeyManifestCodec.Decode(oneTime.Manifest);
        var member = DeepIdV2Dpk2Codec.Decode(oneTime.Offering);
        var last = DeepIdV2Dpk2Codec.Decode(lastResort.Offering);
        return DeepIdV2PreKeyPublicationCodec.Encode(member.NetworkId.Span,
            Bytes(32, 0x41), Bytes(32, 0x51), manifest,
            Enumerable.Repeat(member, 32).ToArray(), last);
    }

    private static byte[] Did2() => DeepIdV2Codec.AuthorDid2(
        Bytes(32, 0xa1), Bytes(1952, 0xa2), Bytes(16, 0xa3))
        .CanonicalBytes.ToArray();

    private static byte[] Dca1() => Bytes(
        DeepIdV2ContactAuthorizationCodec.CanonicalLength, 0xd1);

    private static byte[] Xps1() => Bytes(
        DeepIdV2BoundedPreKeyPublicationCodec.Xps1Length, 0xe1);

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

    private static byte[] Bytes(int length, byte value)
    {
        var bytes = new byte[length];
        bytes.AsSpan().Fill(value);
        return bytes;
    }
}
