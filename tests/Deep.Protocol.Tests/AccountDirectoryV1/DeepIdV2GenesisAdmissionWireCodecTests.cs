using System.Buffers.Binary;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class DeepIdV2GenesisAdmissionWireCodecTests
{
    [Fact]
    public void RequestV2_RoundTripsExactBoundedArtifactsAndRejectsV1()
    {
        var request = new DeepIdV2GenesisAdmissionWireRequest(Bytes(32, 1),
            new DeepIdV2GenesisAdmissionRequest(Bytes(644, 2), Bytes(356, 3),
                [Bytes(776, 4)], Bytes(DeepIdV2Codec.Did2Length, 5), Bytes(3711, 6),
                Bytes(426, 7), Bytes(458, 8), []));
        var encoded = DeepIdV2GenesisAdmissionWireCodec.EncodeRequest(request);
        var decoded = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(encoded);

        Assert.Equal((ushort)2, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(4)));
        Assert.Equal((uint)encoded.Length,
            BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(8)));
        Assert.Equal(request.OperationId.ToArray(), decoded.OperationId.ToArray());
        Assert.Equal(request.Admission.ExactDid2.ToArray(),
            decoded.Admission.ExactDid2.ToArray());
        Assert.Equal(request.Admission.ExactDab2.ToArray(),
            decoded.Admission.ExactDab2.ToArray());
        Assert.Throws<FormatException>(() =>
            AccountDirectoryGenesisAdmissionWireCodec.DecodeRequest(encoded));
        var oldVersion = encoded.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(oldVersion.AsSpan(4), 1);
        Assert.Throws<FormatException>(() =>
            DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(oldVersion));
    }

    [Fact]
    public void RequestV2_RejectsLengthsCountsAndTrailingBytesBeforeAdmission()
    {
        var encoded = DeepIdV2GenesisAdmissionWireCodec.EncodeRequest(
            new DeepIdV2GenesisAdmissionWireRequest(Bytes(32, 1),
                new DeepIdV2GenesisAdmissionRequest(Bytes(644, 2),
                    Bytes(356, 3), [Bytes(776, 4)], Bytes(DeepIdV2Codec.Did2Length, 5),
                    Bytes(3711, 6), Bytes(426, 7), Bytes(458, 8), [])));
        var mutations = new Action<byte[]>[]
        {
            bytes => bytes[0] = (byte)'X',
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 1),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), 0),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(44), 645),
            bytes => Array.Clear(bytes, 12, 32)
        };
        foreach (var mutate in mutations)
        {
            var candidate = encoded.ToArray();
            mutate(candidate);
            Assert.Throws<FormatException>(() =>
                DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(candidate));
        }
        Assert.Throws<FormatException>(() =>
            DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(encoded[..^1]));
        Assert.Throws<FormatException>(() =>
            DeepIdV2GenesisAdmissionWireCodec.DecodeRequest([.. encoded, 0]));
    }

    [Fact]
    public void RequestV2_FullRevocationBoundFitsItsActualEnvelopeLimit()
    {
        var revoked = Enumerable.Range(1, 4096).Select(index =>
        {
            var id = new byte[32];
            BinaryPrimitives.WriteUInt32BigEndian(id.AsSpan(28), (uint)index);
            return (ReadOnlyMemory<byte>)id;
        }).ToArray();
        var request = new DeepIdV2GenesisAdmissionWireRequest(Bytes(32, 1),
            new DeepIdV2GenesisAdmissionRequest(Bytes(644, 2), Bytes(356, 3),
                [Bytes(776, 4)], Bytes(DeepIdV2Codec.Did2Length, 5), Bytes(3711, 6),
                Bytes(426, 7), Bytes(458, 8), revoked));
        var encoded = DeepIdV2GenesisAdmissionWireCodec.EncodeRequest(request);

        Assert.True(encoded.Length > 128 * 1024);
        Assert.True(encoded.Length <= DeepIdV2GenesisAdmissionWireCodec.MaximumRequestLength);
        Assert.Equal(4096,
            DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(encoded)
                .Admission.RevokedDcaAuthorizationIds.Count);
    }

    [Fact]
    public void ReceiptV2_RequiresReaderFloorAndRejectsV1()
    {
        var head = Head(minimumReader: 2);
        var receipt = new DeepIdV2GenesisAdmissionReceipt(Bytes(32, 1),
            Bytes(32, 2), head);
        var encoded = DeepIdV2GenesisAdmissionWireCodec.EncodeReceipt(receipt);
        var decoded = DeepIdV2GenesisAdmissionWireCodec.DecodeReceipt(encoded);

        Assert.Equal(head, decoded.ExactAdh1.ToArray());
        Assert.Throws<FormatException>(() =>
            AccountDirectoryGenesisAdmissionWireCodec.DecodeReceipt(encoded));
        Assert.Throws<ArgumentException>(() =>
            new DeepIdV2GenesisAdmissionReceipt(Bytes(32, 1), Bytes(32, 2),
                Head(minimumReader: 1)));
        var wrongVersion = encoded.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(wrongVersion.AsSpan(4), 1);
        Assert.Throws<FormatException>(() =>
            DeepIdV2GenesisAdmissionWireCodec.DecodeReceipt(wrongVersion));
    }

    private static byte[] Head(ushort minimumReader)
    {
        var authorityReference = new byte[38];
        "XNA1"u8.CopyTo(authorityReference);
        BinaryPrimitives.WriteUInt16BigEndian(authorityReference.AsSpan(4), 1);
        Bytes(32, 9).CopyTo(authorityReference, 6);
        return AccountDirectoryAdh1Codec.Encode(new AccountDirectoryAdh1(
            Bytes(16, 1), 0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
            DeepIdV2DirectorySparseMap.EmptyMapRoot.Span,
            authorityReference, Bytes(32, 8), 1, 3601, minimumReader,
            [new AccountDirectoryAdh1WitnessEntry(Bytes(32, 10),
                Bytes(64, 11))]));
    }

    private static byte[] Bytes(int length, byte first) =>
        Enumerable.Range(0, length).Select(index =>
            unchecked((byte)(first + index))).ToArray();
}
