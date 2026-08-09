using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class ProductionMailboxOwnerControlRequestResponseTests
{
    [Fact]
    public void Pmcq1_Exact344_OcrHashIsContextOnlyAndChangesBothTranscripts()
    {
        var value = Request(); var ocrA = Bytes(20, 32); var ocrB = Bytes(21, 32);
        var encoded = ProductionMailboxOwnerControlTransportCodec.EncodeRequest(value);
        Assert.Equal(344, encoded.Length); Assert.Equal("PMCQ"u8.ToArray(), encoded[..4]);
        Assert.Equal((byte)1, encoded[5]); Assert.Equal((byte)1, encoded[6]); Assert.Equal((byte)1, encoded[7]);
        Assert.Equal(10UL, BinaryPrimitives.ReadUInt64BigEndian(encoded[8..16]));
        Assert.Equal(20UL, BinaryPrimitives.ReadUInt64BigEndian(encoded[16..24]));
        Assert.Equal(value.RequestId.ToArray(), encoded[24..56]);
        Assert.DoesNotContain(ocrA, encoded.AsMemory().ToArray().Chunk(32).Select(static x => x.ToArray()));
        Assert.NotEqual(
            ProductionMailboxOwnerControlTransportCodec.GetRequestSigningBytes(value, ocrA),
            ProductionMailboxOwnerControlTransportCodec.GetRequestSigningBytes(value, ocrB));
        Assert.NotEqual(
            ProductionMailboxOwnerControlTransportCodec.ComputeRequestHash(value, ocrA),
            ProductionMailboxOwnerControlTransportCodec.ComputeRequestHash(value, ocrB));
        Assert.Equal(encoded, ProductionMailboxOwnerControlTransportCodec.EncodeRequest(
            ProductionMailboxOwnerControlTransportCodec.DecodeRequest(encoded)));
    }

    [Fact]
    public void Pmcr1_Exact384_GoldenResponderAndStaleEquality()
    {
        var value = new ProductionMailboxOwnerControlResponseHeader
        {
            Kind = ProductionMailboxOwnerControlResponseKind.NoChange,
            Mode = ProductionMailboxSelectionSuccessorMode.DirectPromotion,
            AuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            IssuedAtUnixSeconds = 10, ExpiresAtUnixSeconds = 20,
            CanonicalRequestHash = Bytes(1, 32), RequestId = Bytes(2, 32), NetworkId = Bytes(3, 16),
            RouteDomainHash = Bytes(4, 32), PredecessorRouteOriginLkgHash = Bytes(5, 32),
            CurrentRouteHistoryCheckpointHash = Bytes(6, 32), NextRouteHistoryCheckpointHash = Bytes(6, 32),
            CurrentRouteHistoryBatchSequence = 3, NextRouteHistoryBatchSequence = 3,
            PayloadSha256 = System.Security.Cryptography.SHA256.HashData([]), PayloadLength = 0,
            ResponderEd25519PublicKey = Bytes(7, 32), ResponderSignature = Bytes(8, 64)
        };
        var encoded = ProductionMailboxOwnerControlTransportCodec.EncodeResponseHeader(value);
        Assert.Equal(384, encoded.Length); Assert.Equal(value.ResponderEd25519PublicKey.ToArray(), encoded[288..320]);
        Assert.Equal(value.ResponderSignature.ToArray(), encoded[320..384]);
        Assert.Throws<FormatException>(() => ProductionMailboxOwnerControlTransportCodec.ValidateMessageWindow(
            10, 20, 20, 0, "PMCR1"));
        ProductionMailboxOwnerControlTransportCodec.ValidateMessageWindow(10, 20, 19, 0, "PMCR1");
    }

    private static ProductionMailboxOwnerControlRequest Request() => new()
    {
        Operation = ProductionMailboxOwnerControlOperation.AdvanceOrFinalize,
        Mode = ProductionMailboxSelectionSuccessorMode.DirectPromotion,
        ExpectedAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
        IssuedAtUnixSeconds = 10, ExpiresAtUnixSeconds = 20, RequestId = Bytes(1, 32),
        NetworkId = Bytes(2, 16), MailboxOwnerEd25519PublicKey = Bytes(3, 32),
        RouteDomainHash = Bytes(4, 32), SelectionInputCommitment = Bytes(5, 32),
        PredecessorRouteOriginLkgHash = Bytes(6, 32), CurrentRouteHistoryCheckpointHash = Bytes(7, 32),
        CurrentRouteHistoryBatchSequence = 3, PredecessorAuthorizationSequence = 4,
        PredecessorAuthorizationHash = Bytes(8, 32), OwnerSignature = Bytes(9, 64)
    };
    private static byte[] Bytes(byte value, int count) => Enumerable.Repeat(value, count).ToArray();
}
