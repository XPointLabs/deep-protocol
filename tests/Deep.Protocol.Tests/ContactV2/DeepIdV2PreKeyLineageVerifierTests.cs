using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2PreKeyLineageVerifierTests
{
    [Fact]
    public void FirstEpoch_RequiresEmptyDurableService()
    {
        Assert.False(DeepIdV2PreKeyLineageVerifier.RuntimeActivation);
        var first = Manifest(1);
        DeepIdV2PreKeyLineageVerifier.VerifySuccessor(first, null);
        Reject(() => DeepIdV2PreKeyLineageVerifier.VerifySuccessor(
            Manifest(2, Bytes(32, 0x35)), null));
    }

    [Fact]
    public void Successor_BindsExactAcceptedPredecessorAndService()
    {
        var first = Manifest(1);
        var second = Manifest(2, first.ExactHash.Span);
        DeepIdV2PreKeyLineageVerifier.VerifySuccessor(second, first);

        Reject(() => DeepIdV2PreKeyLineageVerifier.VerifySuccessor(first, first));
        Reject(() => DeepIdV2PreKeyLineageVerifier.VerifySuccessor(
            Manifest(3, first.ExactHash.Span), first));
        Reject(() => DeepIdV2PreKeyLineageVerifier.VerifySuccessor(
            Manifest(2, Bytes(32, 0x49)), first));
        Reject(() => DeepIdV2PreKeyLineageVerifier.VerifySuccessor(
            Manifest(2, first.ExactHash.Span, capability: 0x76), first));
        Reject(() => DeepIdV2PreKeyLineageVerifier.VerifySuccessor(
            Manifest(2, first.ExactHash.Span, device: 0x77), first));
    }

    [Fact]
    public void FourteenthEpoch_HasNoSuccessor()
    {
        var previous = Manifest(14, Bytes(32, 0x51));
        Reject(() => DeepIdV2PreKeyLineageVerifier.VerifySuccessor(
            Manifest(14, previous.ExactHash.Span), previous));
    }

    [Fact]
    public void ServiceSuccessor_StructuralEpochNamespaceIsSeparate_NotSignatureAuthority()
    {
        var previous = Manifest(14, Bytes(32, 0x51));
        DeepIdV2PreKeyLineageVerifier.VerifySuccessor(
            Manifest(1, serviceGeneration: 2, serviceReference: 0x48), previous);
        Reject(() => DeepIdV2PreKeyLineageVerifier.VerifySuccessor(
            Manifest(1, serviceGeneration: 3, serviceReference: 0x48), previous));
        Reject(() => DeepIdV2PreKeyLineageVerifier.VerifySuccessor(
            Manifest(1, serviceGeneration: 2), previous));
        Reject(() => DeepIdV2PreKeyLineageVerifier.VerifySuccessor(
            Manifest(2, previous.ExactHash.Span, serviceGeneration: 2, serviceReference: 0x48), previous));
        // Epoch1 with a nonzero predecessor cannot reach lineage: the closed
        // manifest codec rejects it first. Keep that earlier boundary explicit.
        var malformed = Assert.Throws<ApplicationCoreFormatException>(() =>
            Manifest(1, Bytes(32, 0x52), serviceGeneration: 2, serviceReference: 0x48));
        Assert.Equal(ApplicationCoreValidationStage.SemanticFields, malformed.Stage);
        Reject(() => DeepIdV2PreKeyLineageVerifier.VerifySuccessor(
            Manifest(1, device: 0x77, serviceGeneration: 2, serviceReference: 0x48), previous));
        Reject(() => DeepIdV2PreKeyLineageVerifier.VerifySuccessor(
            Manifest(1, serviceGeneration: 1, serviceReference: 0x48),
            Manifest(1, serviceGeneration: ulong.MaxValue)));
    }

    private static ParsedXpi1V2 Manifest(ulong epoch,
        ReadOnlySpan<byte> predecessor = default, byte capability = 0x25,
        byte device = 0x26, ulong serviceGeneration = 1, byte serviceReference = 0x28)
    {
        ReadOnlyMemory<byte>[] fields =
        [
            Bytes(16, 0x21), Bytes(32, capability), Bytes(32, device),
            Reference("DPD1", 0x27), U64(serviceGeneration), Reference("XPS1", serviceReference),
            U64(epoch), predecessor.IsEmpty ? new byte[32] : predecessor.ToArray(),
            U16(32), Bytes(32, 0x29), Bytes(32, 0x2a),
            Bytes(32, 0x2b), Reference("DRS1", 0x2c), U64(10), U64(20)
        ];
        return DeepIdV2PreKeyManifestCodec.Decode(
            DeepIdV2PreKeyManifestCodec.Encode(fields, Bytes(64, 0x2d)));
    }

    private static byte[] Reference(string magic, byte hash)
    {
        var bytes = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4, 2),
            magic == "XPS1" ? (ushort)2 : (ushort)1);
        Bytes(32, hash).CopyTo(bytes, 6);
        return bytes;
    }

    private static byte[] U16(ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] Bytes(int count, byte value) =>
        Enumerable.Repeat(value, count).ToArray();

    private static void Reject(Action action)
    {
        var error = Assert.Throws<ApplicationCoreFormatException>(action);
        Assert.Equal(ApplicationCoreValidationStage.CryptographicVerification,
            error.Stage);
        Assert.Equal(ApplicationCoreRejection.InvalidLineage, error.Rejection);
    }
}
