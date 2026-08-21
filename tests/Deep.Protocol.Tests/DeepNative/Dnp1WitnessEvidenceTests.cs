namespace Deep.Protocol.DeepNative;

public sealed class WitnessEvidenceTests
{
    [Fact]
    public void ReplacementWitnessEmptyRoot_BindsEpochIdAndMaximumTreeSize()
    {
        var witnessId = Enumerable.Repeat((byte)0x51, 32).ToArray();
        var root = WitnessTreeVerifier.EmptyRoot(7, witnessId, 1024);

        Assert.NotEqual(root, WitnessTreeVerifier.EmptyRoot(8, witnessId, 1024));
        var changedId = witnessId.ToArray(); changedId[0] ^= 1;
        Assert.NotEqual(root, WitnessTreeVerifier.EmptyRoot(7, changedId, 1024));
        Assert.NotEqual(root, WitnessTreeVerifier.EmptyRoot(7, witnessId, 1023));

        var firstLeaf = WitnessTreeVerifier.Leaf(
            Enumerable.Repeat((byte)0x52, 116).ToArray());
        WitnessTreeVerifier.VerifyConsistency(0, root, 1, firstLeaf, [], root);
        Assert.Throws<RecordException>(() =>
            WitnessTreeVerifier.VerifyConsistency(0,
                WitnessTreeVerifier.EmptyRoot(7, witnessId, 1023),
                1, firstLeaf, [], root));
    }
}
