using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.Tests.MessagingWire;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2PreKeyClaimCommitmentTests
{
    [Theory]
    [InlineData(Dpk2PrekeyKind.OneTime, (ushort)0)]
    [InlineData(Dpk2PrekeyKind.LastResort, (ushort)1)]
    public void ExactV2ClaimInputs_DeriveOneNonCircularReceiptTuple(
        Dpk2PrekeyKind kind, ushort counter)
    {
        var fixture = Build(kind);
        var tuple = DeepIdV2PreKeyClaimCommitment.CreateTuple(
            fixture.Request, fixture.Offering, fixture.Manifest, 3, counter);
        Assert.False(DeepIdV2PreKeyClaimCommitment.RuntimeActivation);
        Assert.Equal(DeepIdV2PreKeyClaimCommitment.TupleLength, tuple.Length);
        Assert.Equal(DeepIdV2PreKeyClaimRequestCodec.Decode(fixture.Request)
            .RequestHash.ToArray(), tuple[..32]);
        Assert.Equal(DeepIdV2Dpk2Codec.Decode(fixture.Offering)
            .ExactHash.ToArray(), tuple[32..64]);
        Assert.Equal(DeepIdV2PreKeyManifestCodec.Decode(fixture.Manifest)
            .ExactHash.ToArray(), tuple[64..96]);
        Assert.Equal(kind == Dpk2PrekeyKind.OneTime
                ? DeepIdV2Dpk2Codec.Decode(fixture.Offering)
                    .OneTimePrekeyId.ToArray()
                : new byte[32], tuple[96..128]);
        Assert.Equal((ulong)3,
            BinaryPrimitives.ReadUInt64BigEndian(tuple.AsSpan(128, 8)));
        Assert.Equal(counter,
            BinaryPrimitives.ReadUInt16BigEndian(tuple.AsSpan(136, 2)));
        Assert.Equal(ApplicationCoreFormat.Sha256Domain(
                "Deep/ContactResolver/V2/prekey-claim-receipt", tuple),
            DeepIdV2PreKeyClaimCommitment.ComputeReceiptHash(
                fixture.Request, fixture.Offering, fixture.Manifest, 3,
                counter));
        Assert.Equal(ApplicationCoreFormat.SignatureInput(
                "Deep/ContactResolver/V2/prekey-claim-commit", tuple,
                DeepIdV2Codec.Suite),
            DeepIdV2PreKeyClaimCommitment.CreateReplicaSignatureInput(
                fixture.Request, fixture.Offering, fixture.Manifest, 3,
                counter));
        Assert.NotEqual(ApplicationCoreFormat.Sha256Domain(
                "Deep/ContactResolver/V1/prekey-claim-receipt", tuple),
            DeepIdV2PreKeyClaimCommitment.ComputeReceiptHash(
                fixture.Request, fixture.Offering, fixture.Manifest, 3,
                counter));

        Assert.Throws<CryptographicException>(() =>
            DeepIdV2PreKeyClaimCommitment.CreateTuple(fixture.Request,
                fixture.Offering, fixture.Manifest, 0, counter));
        Assert.Throws<CryptographicException>(() =>
            DeepIdV2PreKeyClaimCommitment.CreateTuple(fixture.Request,
                fixture.Offering, fixture.Manifest, 3,
                kind == Dpk2PrekeyKind.OneTime ? (ushort)1 : (ushort)0));
        var oldOffering = Dpk2Codec.Encode(
            DeepIdV2Dpk2Codec.Decode(fixture.Offering).Record);
        Assert.Throws<MessagingWireFormatException>(() =>
            DeepIdV2PreKeyClaimCommitment.CreateTuple(fixture.Request,
                oldOffering, fixture.Manifest, 3, counter));
    }

    internal static (byte[] Request, byte[] Offering, byte[] Manifest) Build(
        Dpk2PrekeyKind kind)
    {
        var source = MessagingWireFixtures.Dpk2V2(kind);
        var dpdReference = Reference("DPD1", Bytes(32, 0x25));
        var record = new Dpk2Record(source.NetworkId.Span,
            source.ResponderAccountId.Span, source.ResponderDeviceId.Span,
            source.ResponderDeviceGeneration, dpdReference,
            source.DeviceDirectoryGeneration,
            source.DeviceDirectoryHeadHash.Span,
            source.PrekeyServiceGeneration, source.InventoryEpoch,
            source.BundleId.Span, source.PolicyGeneration, source.NotBefore,
            source.IssuedAt, source.ExpiresAt,
            source.DeviceAgreementPublicKey.Span,
            source.SignedX25519PrekeyId.Span,
            source.SignedX25519PrekeyPublic.Span,
            source.SignedX25519PrekeySignature.Span,
            source.OneTimeX25519PrekeyId.Span,
            source.OneTimeX25519PrekeyPublic.Span,
            source.MlKemPrekeyId.Span,
            source.MlKem768EncapsulationKey.Span, source.MlKemKind,
            source.ReuseLimit, source.MlKemPrekeySignature.Span,
            source.BundleSignature.Span);
        var offering = DeepIdV2Dpk2Codec.Encode(record);
        var capability = Bytes(32, 0x35);
        var xpsHash = Bytes(32, 0x45);
        var xpsReference = Reference("XPS1", xpsHash);
        var epoch = Be64(record.InventoryEpoch);
        ReadOnlyMemory<byte>[] manifestFields =
        [
            record.NetworkId, capability, record.ResponderDeviceId,
            dpdReference, Be64(record.PrekeyServiceGeneration), xpsReference,
            epoch, Bytes(32, 0x55), Be16(32), Bytes(32, 0x65),
            kind == Dpk2PrekeyKind.LastResort
                ? DeepIdV2Dpk2Codec.Decode(offering).ExactHash
                : Bytes(32, 0x75), record.DeviceDirectoryHeadHash,
            Reference("DRS1", Bytes(32, 0x85)), Be64(record.NotBefore),
            Be64(record.ExpiresAt)
        ];
        var manifest = DeepIdV2PreKeyManifestCodec.Encode(manifestFields,
            Bytes(64, 0x95));
        var request = DeepIdV2PreKeyClaimRequestCodec.Encode(
            record.NetworkId.Span, Bytes(32, 0xa5), Bytes(32, 0xb5),
            Bytes(32, 0xc5), record.NotBefore, record.ExpiresAt,
            capability, Bytes(32, 0xd5), xpsHash,
            record.ResponderDeviceId.Span, Bytes(32, 0xe5));
        return (request, offering, manifest);
    }

    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        var bytes = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4, 2), 1);
        hash.CopyTo(bytes.AsSpan(6));
        return bytes;
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

    private static byte[] Bytes(int length, byte value)
    {
        var bytes = new byte[length];
        bytes.AsSpan().Fill(value);
        return bytes;
    }
}
