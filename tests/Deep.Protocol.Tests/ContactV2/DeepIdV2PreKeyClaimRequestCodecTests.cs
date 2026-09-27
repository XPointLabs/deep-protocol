using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2PreKeyClaimRequestCodecTests
{
    [Fact]
    public void Did2ClaimRequest_HasOneV2EnvelopeAndRequestDomain()
    {
        var network = Bytes(16, 0x11);
        var operation = Bytes(32, 0x21);
        var view = Bytes(32, 0x31);
        var placement = Bytes(32, 0x41);
        var capability = Bytes(32, 0x51);
        var dcb = Bytes(32, 0x61);
        var xps = Bytes(32, 0x71);
        var device = Bytes(32, 0x81);
        var commitment = Bytes(32, 0x91);

        var exact = DeepIdV2PreKeyClaimRequestCodec.Encode(network, operation,
            view, placement, 10, 20, capability, dcb, xps, device,
            commitment);
        var parsed = DeepIdV2PreKeyClaimRequestCodec.Decode(exact);
        Assert.False(DeepIdV2PreKeyClaimRequestCodec.RuntimeActivation);
        Assert.Equal(DeepIdV2PreKeyClaimRequestCodec.CanonicalLength, exact.Length);
        Assert.Equal(operation, parsed.Field(2).ToArray());
        Assert.Equal(operation, parsed.Field(22).ToArray());
        Assert.Equal(ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V2/request", exact),
            parsed.RequestHash.ToArray());
        Assert.NotEqual(ApplicationCoreFormat.Sha256Domain(
            "Deep/ContactResolver/V1/request", exact),
            parsed.RequestHash.ToArray());

        var oldRequest = Xpk1Codec.Encode(network, operation, view, placement,
            10, 20, capability, dcb, xps, device, commitment);
        Assert.Equal(ApplicationCoreRejection.WrongVersion,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                DeepIdV2PreKeyClaimRequestCodec.Decode(oldRequest)).Rejection);
        var wrongSuite = exact.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(wrongSuite.AsSpan(6, 2), 0x0201);
        Assert.Equal(ApplicationCoreRejection.WrongSuite,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                DeepIdV2PreKeyClaimRequestCodec.Decode(wrongSuite)).Rejection);
        var wrongClaimOperation = exact.ToArray();
        wrongClaimOperation[^1] ^= 1;
        Assert.Equal(ApplicationCoreRejection.CrossFieldMismatch,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                DeepIdV2PreKeyClaimRequestCodec.Decode(wrongClaimOperation)).Rejection);
        var wrongRequestedSuite = exact.ToArray();
        var tag20 = FindValueOffset(wrongRequestedSuite, 20);
        BinaryPrimitives.WriteUInt16BigEndian(
            wrongRequestedSuite.AsSpan(tag20, 2), 0x0201);
        Assert.Equal(ApplicationCoreRejection.InvalidEnum,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                DeepIdV2PreKeyClaimRequestCodec.Decode(wrongRequestedSuite)).Rejection);
    }

    private static int FindValueOffset(ReadOnlySpan<byte> canonical,
        ushort wantedTag)
    {
        var offset = 12;
        while (offset < canonical.Length)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(
                canonical.Slice(offset, 2));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                canonical.Slice(offset + 4, 4)));
            offset += 8;
            if (tag == wantedTag)
                return offset;
            offset += length;
        }
        throw new InvalidOperationException("The expected fixture tag is absent.");
    }

    private static byte[] Bytes(int length, byte value)
    {
        var bytes = new byte[length];
        bytes.AsSpan().Fill(value);
        return bytes;
    }
}
