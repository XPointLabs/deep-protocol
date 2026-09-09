using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class AttachmentManifestCodecTests
{
    [Theory]
    [InlineData(1UL, 1, 1)]
    [InlineData(262144UL, 1, 1)]
    [InlineData(262145UL, 2, 2)]
    [InlineData(1048577UL, 5, 3)]
    [InlineData(26214400UL, 100, 5)]
    public void Dam1_RoundTripsExactArithmeticAndHash(ulong total, int count, ushort bucket)
    {
        var manifest = Manifest(total, count, "файл.txt", "application/octet-stream");
        var decoded = ApplicationCoreCodec.DecodeDam1(manifest.CanonicalBytes.Span);

        Assert.Equal(270 + 40 * count + Encoding.UTF8.GetByteCount("файл.txt") + 24,
            decoded.CanonicalBytes.Length);
        Assert.Equal((uint)count, decoded.ChunkCount);
        Assert.Equal(bucket, decoded.CiphertextCapacityBucketId);
        Assert.Equal(DomainHash("Deep/Attachment/V1/manifest", decoded.CanonicalBytes.Span),
            decoded.ManifestHash.ToArray());
        Assert.Equal(manifest.CanonicalBytes.ToArray(), decoded.CanonicalBytes.ToArray());
    }

    [Fact]
    public void AttachmentDmc2Kinds_AreTypedButDoNotActivateBlobRuntime()
    {
        var manifest = Manifest(17, 1, "", "image/png");
        var offer = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateAttachmentOfferPayload(manifest),
            flags: Dmc2Flags.Disappearing | Dmc2Flags.HighPriority,
            reply: ApplicationCoreFixture.Bytes(32, 0x44));
        var parsedOffer = Assert.IsType<AttachmentOfferDmc2Payload>(
            ApplicationCoreCodec.DecodeDmc2(offer.CanonicalBytes.Span).ParsedPayload);
        Assert.Equal(manifest.ManifestHash.ToArray(), parsedOffer.Manifest.ManifestHash.ToArray());

        var cancel = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateAttachmentCancelPayload(
                manifest.ObjectId.Span, AttachmentCancelReason.Superseded));
        var parsedCancel = Assert.IsType<AttachmentCancelDmc2Payload>(
            ApplicationCoreCodec.DecodeDmc2(cancel.CanonicalBytes.Span).ParsedPayload);
        Assert.Equal(AttachmentCancelReason.Superseded, parsedCancel.Reason);
        Assert.Equal(manifest.ObjectId.ToArray(), parsedCancel.ObjectId.ToArray());
    }

    [Theory]
    [InlineData("../secret", "image/png")]
    [InlineData("   ", "image/png")]
    [InlineData("ok", "Image/PNG")]
    [InlineData("ok", "image/png; charset=utf-8")]
    [InlineData("ok", "image")]
    public void Dam1_NoncanonicalMetadataRejects(string filename, string mediaType)
    {
        Assert.Throws<ApplicationCoreFormatException>(() => Manifest(1, 1, filename, mediaType));
    }

    [Fact]
    public void Dam1_NonminimalBucketAndChangedCiphertextLengthRejectBeforeUse()
    {
        var canonical = Manifest(1, 1, "a", "x/y").CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(canonical.AsSpan(FieldOffset(canonical, 11), 2), 2);
        var bucket = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDam1(canonical));
        Assert.Equal(ApplicationCoreRejection.InvalidEnum, bucket.Rejection);

        canonical = Manifest(1, 1, "a", "x/y").CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(canonical.AsSpan(FieldOffset(canonical, 10) + 4, 4), 18);
        var length = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDam1(canonical));
        Assert.Equal(ApplicationCoreRejection.CrossFieldMismatch, length.Rejection);
    }

    [Fact]
    public void AttachmentOffer_RejectsCrossNetworkAndCancelRequiresSilent()
    {
        var manifest = Manifest(1, 1, "", "");
        Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateAttachmentOfferPayload(manifest),
            network: ApplicationCoreFixture.Bytes(16, 0x55)));
        Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateAttachmentCancelPayload(
                manifest.ObjectId.Span, AttachmentCancelReason.LocalPolicy),
            flags: Dmc2Flags.None));
    }

    private static ParsedDam1 Manifest(
        ulong total,
        int count,
        string filename,
        string mediaType)
    {
        var final = checked((uint)(total - 262144UL * (ulong)(count - 1)));
        var entries = Enumerable.Range(0, count)
            .Select(index => new Dam1ChunkEntry(
                (uint)index,
                checked((index == count - 1 ? final : 262144U) + 16),
                ApplicationCoreFixture.Bytes(32, checked((byte)(0x60 + index % 20)))))
            .ToArray();
        return ApplicationCoreCodec.AuthorDam1(
            ApplicationCoreFixture.Bytes(16, 0x11),
            ApplicationCoreFixture.Bytes(32, 0x21),
            ApplicationCoreFixture.Bytes(32, 0x22),
            ApplicationCoreFixture.Bytes(32, 0x23),
            total,
            entries,
            123456,
            filename,
            mediaType);
    }

    private static int FieldOffset(byte[] canonical, ushort requestedTag)
    {
        var offset = 12;
        for (ushort tag = 1; tag <= 14; tag++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(canonical.AsSpan(offset + 4, 4)));
            offset += 8;
            if (tag == requestedTag)
                return offset;
            offset += length;
        }
        throw new InvalidOperationException();
    }

    private static byte[] DomainHash(string label, ReadOnlySpan<byte> value)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.ASCII.GetBytes(label));
        hash.AppendData([0]);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length);
        hash.AppendData(value);
        return hash.GetHashAndReset();
    }
}
