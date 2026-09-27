using System.Buffers.Binary;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.Tests.MessagingWire;
using Sodium;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2Dpk2CodecTests
{
    [Theory]
    [InlineData(Dpk2PrekeyKind.OneTime, Dpk2Codec.OneTimeTotalBytes)]
    [InlineData(Dpk2PrekeyKind.LastResort, Dpk2Codec.LastResortTotalBytes)]
    public void Did2EnvelopeIsCanonicalAndRejectsOldWire(
        Dpk2PrekeyKind kind, int expectedLength)
    {
        var record = MessagingWireFixtures.Dpk2(kind);
        var oldBytes = Dpk2Codec.Encode(record);
        var did2Bytes = DeepIdV2Dpk2Codec.Encode(record);
        var parsed = DeepIdV2Dpk2Codec.Decode(did2Bytes);

        Assert.False(DeepIdV2Dpk2Codec.RuntimeActivation);
        Assert.Equal(expectedLength, did2Bytes.Length);
        Assert.Equal((ushort)2,
            BinaryPrimitives.ReadUInt16BigEndian(did2Bytes.AsSpan(4)));
        Assert.Equal((ushort)0x0301,
            BinaryPrimitives.ReadUInt16BigEndian(did2Bytes.AsSpan(6)));
        Assert.Equal(did2Bytes, parsed.CanonicalBytes.ToArray());
        Assert.Equal(did2Bytes,
            DeepIdV2Dpk2Codec.Encode(parsed.Record));
        Assert.NotEqual(oldBytes, did2Bytes);
        var independentShape = oldBytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(independentShape.AsSpan(4), 2);
        BinaryPrimitives.WriteUInt16BigEndian(independentShape.AsSpan(6), 0x0301);
        Assert.Equal(independentShape, did2Bytes);
        Assert.Throws<MessagingWireFormatException>(() =>
            DeepIdV2Dpk2Codec.Decode(oldBytes));
        Assert.Throws<MessagingWireFormatException>(() =>
            Dpk2Codec.Decode(did2Bytes));

        var wrongSuite = did2Bytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(wrongSuite.AsSpan(6), 0x0201);
        var error = Assert.Throws<MessagingWireFormatException>(() =>
            DeepIdV2Dpk2Codec.Decode(wrongSuite));
        Assert.Equal(MessagingWireRejection.WrongSuite, error.Rejection);
    }

    [Fact]
    public void OldPrekeySignaturesCannotAuthorizeDid2Envelope()
    {
        var oldRecord = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var publicKey = MessagingWireFixtures.Dpk2SigningPublicKey();
        Assert.True(PublicKeyAuth.VerifyDetached(
            oldRecord.SignedX25519PrekeySignature.ToArray(),
            MessagingWireCryptographicInputs
                .GetX25519SignedPrekeySignatureInput(oldRecord), publicKey));
        Assert.False(PublicKeyAuth.VerifyDetached(
            oldRecord.SignedX25519PrekeySignature.ToArray(),
            DeepIdV2Dpk2Codec.GetX25519SignedPrekeySignatureInput(oldRecord),
            publicKey));
        Assert.False(PublicKeyAuth.VerifyDetached(
            oldRecord.MlKemPrekeySignature.ToArray(),
            DeepIdV2Dpk2Codec.GetMlKemPrekeySignatureInput(oldRecord),
            publicKey));
        Assert.False(PublicKeyAuth.VerifyDetached(
            oldRecord.BundleSignature.ToArray(),
            DeepIdV2Dpk2Codec.GetPrekeyBundleSignatureInput(oldRecord),
            publicKey));
    }
}
