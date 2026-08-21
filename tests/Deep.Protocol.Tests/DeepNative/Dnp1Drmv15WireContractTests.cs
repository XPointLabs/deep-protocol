using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class Drmv20WireContractTests
{
    [Fact]
    public async Task UnsupportedPairOrClosedScalar_RejectsAfterExactlyOneAeadOpen()
    {
        var cases = new Action<byte[]>[]
        {
            bytes => bytes[4] = 19,
            bytes =>
            {
                "DRM9"u8.CopyTo(bytes);
                bytes[4] = 20;
            },
            bytes => bytes[4] = 21,
            bytes => bytes[5] = 2,
            bytes => bytes[8] = 0
        };

        foreach (var mutate in cases)
        {
            var canonical = CanonicalDrmv20();
            var plaintext = canonical.ToArray();
            mutate(plaintext);
            var nonce = Enumerable.Repeat((byte)0x71, 24).ToArray();
            var provider = new CountingPlaintextProvider(nonce, plaintext);

            await Assert.ThrowsAsync<RecordException>(() =>
                RecoveryTestAccess.OpenUnverifiedCandidateAsync(
                    Drm3Fixture.CreateCapsule(canonical, nonce),
                    provider,
                    new StoredLatch(),
                    default).AsTask());

            Assert.Equal(1, provider.DeriveCalls);
            Assert.Equal(1, provider.OpenCalls);
        }
    }

    [Fact]
    public void ExactPrefix_DecodesOnlyDrmvVersion20Profile1Pin274()
    {
        var canonical = CanonicalDrmv20();

        using var manifest = RecoveryManifestParser.DecodeOwned(canonical, 6);

        Assert.Equal(284, RecoveryManifestParser.PrefixLength);
        Assert.Equal("DRMV"u8.ToArray(), manifest.CanonicalSpan[..4].ToArray());
        Assert.Equal((byte)20, manifest.CanonicalSpan[4]);
        Assert.Equal((byte)1, manifest.CanonicalSpan[5]);
        Assert.Equal((ushort)6, ReadU16(manifest.CanonicalSpan.Slice(6, 2)));
        Assert.Equal((ushort)274, ReadU16(manifest.CanonicalSpan.Slice(8, 2)));
        Assert.Equal(274, manifest.PinCoreProjection.Length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    [InlineData(11)]
    [InlineData(12)]
    [InlineData(13)]
    [InlineData(14)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(18)]
    [InlineData(19)]
    [InlineData(21)]
    [InlineData(255)]
    public void UnsupportedDrmvVersion_RejectsWithoutReinterpretation(byte version)
    {
        var canonical = CanonicalDrmv20();
        canonical[4] = version;

        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(canonical, 6));
    }

    [Theory]
    [InlineData("DRM1", 1)]
    [InlineData("DRM2", 2)]
    [InlineData("DRM3", 3)]
    [InlineData("DRM4", 4)]
    [InlineData("DRM5", 5)]
    [InlineData("DRM1", 20)]
    [InlineData("DRM5", 20)]
    public void LegacyOrMixedMagicVersionPair_RejectsWithoutReinterpretation(
        string magic,
        byte version)
    {
        var canonical = CanonicalDrmv20();
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(canonical, 0);
        canonical[4] = version;

        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(canonical, 6));
    }

    [Theory]
    [InlineData(5, 0)]
    [InlineData(5, 2)]
    [InlineData(8, 0)]
    [InlineData(9, 0)]
    public void ClosedProfileAndPinLength_RejectBeforeContainerDecode(
        int offset,
        byte value)
    {
        var canonical = CanonicalDrmv20();
        canonical[offset] = value;

        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(canonical, 6));
    }

    private static byte[] CanonicalDrmv20()
    {
        var canonical = Drm3Fixture.Create();
        "DRMV"u8.CopyTo(canonical);
        canonical[4] = 20;
        return canonical;
    }

    private static ushort ReadU16(ReadOnlySpan<byte> bytes) =>
        System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(bytes);

    private sealed class CountingPlaintextProvider(byte[] nonce, byte[] plaintext)
        : RecoveryProtectorProvider
    {
        public int DeriveCalls { get; private set; }

        public int OpenCalls { get; private set; }

        public override ValueTask DeriveNonceAsync(
            RecoveryProviderRequest request,
            Memory<byte> derivedNonce24,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DeriveCalls++;
            nonce.CopyTo(derivedNonce24);
            return ValueTask.CompletedTask;
        }

        public override ValueTask OpenAsync(
            RecoveryProviderRequest request,
            Memory<byte> plaintextDestination,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            OpenCalls++;
            plaintext.CopyTo(plaintextDestination);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class StoredLatch : RecoveryNonceLatch
    {
        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(RecoveryNonceLatchDecision.Stored);
        }
    }
}
