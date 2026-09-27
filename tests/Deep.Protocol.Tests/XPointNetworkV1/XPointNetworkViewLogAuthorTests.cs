using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class XPointNetworkViewLogAuthorTests
{
    [Fact]
    public void BuildAppendProof_AdvancesProtectedHistoryAcrossPowerOfTwoBoundaries()
    {
        var genesis = GenesisView();
        var history = new List<ReadOnlyMemory<byte>> { genesis };
        var head = GenesisHead(genesis);

        for (var generation = 1UL; generation <= 9; generation++)
        {
            var successor = SuccessorView(history[^1].Span, generation);
            var prior = XPointNetworkCodec.Parse<Xnh1Record>(head);
            var material = XPointNetworkViewLogAuthor.BuildAppendProof(history, head, successor);
            Assert.Contains(material.ConsistencyNodes, node =>
                node.AsSpan().SequenceEqual(ViewLeaf(XPointNetworkCodec.Parse<Xnv1Record>(successor))));
            XPointMerkleProofs.VerifyConsistency(
                prior.TreeSize, prior.TreeSize + 1, prior.Root.Span, material.Root,
                material.ConsistencyNodes.SelectMany(static node => node).ToArray(),
                material.ConsistencyNodes.Count);
            head = SuccessorHead(head, successor, material);
            history.Add(successor);
            Assert.Equal(generation + 1, XPointNetworkCodec.Parse<Xnh1Record>(head).TreeSize);
        }
    }

    [Fact]
    public void BuildAppendProof_RejectsHistoryThatDiffersFromProtectedHead()
    {
        var genesis = GenesisView();
        var head = GenesisHead(genesis);
        var differentGenesis = XPointNetworkTestRecords.MutateField(
            genesis, 6, span => span[0] ^= 0x40);
        var successor = SuccessorView(differentGenesis, 1);

        Assert.Throws<CryptographicException>(() =>
            XPointNetworkViewLogAuthor.BuildAppendProof([differentGenesis], head, successor));
    }

    [Fact]
    public void BuildAppendProof_RejectsGapAndFork()
    {
        var genesis = GenesisView();
        var head = GenesisHead(genesis);
        var gap = SuccessorView(genesis, 2);
        var fork = XPointNetworkTestRecords.MutateField(
            SuccessorView(genesis, 1), 3, span => span[0] ^= 0x40);

        Assert.Throws<XPointValidationException>(() =>
            XPointNetworkViewLogAuthor.BuildAppendProof([genesis], head, gap));
        Assert.Throws<XPointValidationException>(() =>
            XPointNetworkViewLogAuthor.BuildAppendProof([genesis], head, fork));
    }

    [Fact]
    public void BuildAppendProof_RejectsProtectedHeadGenerationMismatch()
    {
        var genesis = GenesisView();
        var head = XPointNetworkTestRecords.MutateField(
            XPointNetworkTestRecords.MutateField(
                GenesisHead(genesis), 2, span => span[^1] = 1),
            3, span => span[0] = 1);
        var successor = SuccessorView(genesis, 1);

        Assert.Throws<CryptographicException>(() =>
            XPointNetworkViewLogAuthor.BuildAppendProof([genesis], head, successor));
    }

    private static byte[] GenesisView() => XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xnv1);

    private static byte[] SuccessorView(ReadOnlySpan<byte> previousBytes, ulong generation)
    {
        var previous = XPointNetworkCodec.Parse<Xnv1Record>(previousBytes);
        var fields = Enumerable.Range(1, 24)
            .Select(tag => (ReadOnlyMemory<byte>)previous.FieldSpan(tag).ToArray()).ToArray();
        fields[1] = U64(generation);
        fields[2] = previous.CoreHash.ToArray();
        var blockHash = fields[5].ToArray();
        blockHash[0] ^= checked((byte)generation);
        fields[5] = blockHash;
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xnv1, fields);
    }

    private static byte[] GenesisHead(ReadOnlySpan<byte> genesisBytes)
    {
        var view = XPointNetworkCodec.Parse<Xnv1Record>(genesisBytes);
        var template = XPointNetworkCodec.Parse<Xnh1Record>(
            XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xnh1));
        var fields = Enumerable.Range(1, 16)
            .Select(tag => (ReadOnlyMemory<byte>)template.FieldSpan(tag).ToArray()).ToArray();
        fields[4] = ViewLeaf(view);
        fields[5] = XPointNetworkCodec.EncodeCoreReference("XNV1", view.CoreHash.Span);
        fields[6] = U64(0);
        fields[7] = view.FieldSpan(7).ToArray();
        fields[8] = view.FieldSpan(8).ToArray();
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xnh1, fields);
    }

    private static byte[] SuccessorHead(
        ReadOnlySpan<byte> priorHeadBytes,
        ReadOnlySpan<byte> viewBytes,
        XPointNetworkViewAppendProof material)
    {
        var prior = XPointNetworkCodec.Parse<Xnh1Record>(priorHeadBytes);
        var view = XPointNetworkCodec.Parse<Xnv1Record>(viewBytes);
        var fields = Enumerable.Range(1, 16)
            .Select(tag => (ReadOnlyMemory<byte>)prior.FieldSpan(tag).ToArray()).ToArray();
        fields[1] = U64(prior.LogGeneration + 1);
        fields[2] = prior.CoreHash.ToArray();
        fields[3] = U64(prior.TreeSize + 1);
        fields[4] = material.Root;
        fields[5] = XPointNetworkCodec.EncodeCoreReference("XNV1", view.CoreHash.Span);
        fields[6] = U64(view.ViewGeneration);
        fields[12] = new[] { checked((byte)material.ConsistencyNodes.Count) };
        fields[13] = material.ConsistencyNodes.SelectMany(static node => node).ToArray();
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xnh1, fields);
    }

    private static byte[] ViewLeaf(Xnv1Record view)
    {
        Span<byte> payload = stackalloc byte[72];
        BinaryPrimitives.WriteUInt64BigEndian(payload, view.ViewGeneration);
        view.FieldSpan(3).CopyTo(payload[8..40]);
        view.CoreHash.Span.CopyTo(payload[40..]);
        return XPointNetworkCrypto.Rfc6962Leaf(payload);
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }
}
