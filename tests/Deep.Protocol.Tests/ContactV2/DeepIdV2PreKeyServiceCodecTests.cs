using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Sodium;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2PreKeyServiceCodecTests
{
    [Fact]
    public void ExactDID2Service_IsV2SignedAndRejectsV1OrWrongLineage()
    {
        var seed = Bytes(32, 0x91);
        var keys = PublicKeyAuth.GenerateKeyPair(seed);
        var dpd = new byte[38];
        "DPD1"u8.CopyTo(dpd);
        BinaryPrimitives.WriteUInt16BigEndian(dpd.AsSpan(4), 1);
        Bytes(32, 0x35).CopyTo(dpd, 6);
        ReadOnlyMemory<byte>[] fields =
        [
            Bytes(16, 0x11), Bytes(32, 0x12), Bytes(32, 0x13),
            dpd, Be64(1), new byte[32], Be16(DeepIdV2Codec.Suite),
            Be16(32), Be16(9), Be64(100), Be64(200)
        ];
        var signature = PublicKeyAuth.SignDetached(
            DeepIdV2PreKeyServiceCodec.CreateSignatureInput(fields),
            keys.PrivateKey);
        var exact = DeepIdV2PreKeyServiceCodec.Encode(fields, signature);
        Assert.Equal(DeepIdV2PreKeyServiceCodec.CanonicalLength,
            exact.Length);
        var parsed = DeepIdV2PreKeyServiceCodec.Decode(exact);
        DeepIdV2PreKeyServiceCodec.VerifyDeviceSignature(parsed,
            keys.PublicKey);
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyServiceCodec.VerifyDeviceSignature(parsed,
                Bytes(32, 0x55)));

        var old = exact.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(old.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(old.AsSpan(6), 0x0201);
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyServiceCodec.Decode(old));
        var wrongPredecessor = fields.ToArray();
        wrongPredecessor[5] = Bytes(32, 0x99);
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyServiceCodec.Encode(wrongPredecessor,
                signature));
        var zeroGeneration = fields.ToArray();
        zeroGeneration[4] = Be64(0);
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2PreKeyServiceCodec.Encode(zeroGeneration, signature));

        var successor = fields.ToArray();
        successor[4] = Be64(2);
        successor[5] = SHA256.HashData(exact);
        var successorSignature = PublicKeyAuth.SignDetached(
            DeepIdV2PreKeyServiceCodec.CreateSignatureInput(successor),
            keys.PrivateKey);
        DeepIdV2PreKeyServiceCodec.VerifyDeviceSignature(
            DeepIdV2PreKeyServiceCodec.Decode(
                DeepIdV2PreKeyServiceCodec.Encode(successor,
                    successorSignature)), keys.PublicKey);
    }

    private static byte[] Bytes(int count, byte value) =>
        Enumerable.Repeat(value, count).ToArray();

    private static byte[] Be64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static byte[] Be16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }
}
