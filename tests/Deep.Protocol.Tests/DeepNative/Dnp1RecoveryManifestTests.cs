using System.Buffers.Binary;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class RecoveryManifestTests
{
    [Fact]
    public void SortedRows_VerifyReferencesAndOwnedPlaintextIsZeroedOnDispose()
    {
        var plaintext = CanonicalDrm5();

        using var manifest = RecoveryManifestParser.DecodeOwned(plaintext, 6);
        plaintext.AsSpan().Fill(0xff);

        Assert.Equal(6, manifest.Rows.Count);
        Assert.Contains(manifest.Rows.Select((_, index) =>
            System.Text.Encoding.ASCII.GetString(manifest.RowBytes(index)[..4])),
            static magic => magic == "DPA1");
    }

    [Fact]
    public void ReversedOrDuplicateRows_RejectBeforeOwnedSnapshot()
    {
        var reversed = CanonicalDrm5();
        var rows = RecoveryManifestParser.Preflight(reversed, 6).RowsOffset;
        var firstLength = 38 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(reversed.AsSpan(rows + 2, 4)));
        var second = rows + firstLength;
        var secondLength = 38 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(reversed.AsSpan(second + 2, 4)));
        var pair = reversed.AsSpan(rows, firstLength + secondLength).ToArray();
        pair.AsSpan(firstLength, secondLength).CopyTo(reversed.AsSpan(rows));
        pair.AsSpan(0, firstLength).CopyTo(reversed.AsSpan(rows + secondLength));
        var duplicate = CanonicalDrm5();
        duplicate.AsSpan(rows, 38).CopyTo(duplicate.AsSpan(second, 38));

        Assert.Throws<RecordException>(() => RecoveryManifestParser.DecodeOwned(reversed, 6));
        Assert.Throws<RecordException>(() => RecoveryManifestParser.DecodeOwned(duplicate, 6));
    }

    [Fact]
    public void LateTruncationAtMaximumCount_IsBoundedAndRejects()
    {
        var plaintext = CanonicalDrm5();
        BinaryPrimitives.WriteUInt16BigEndian(plaintext.AsSpan(6, 2),
            RecoveryManifestParser.MaximumArtifactCount);

        var before = GC.GetAllocatedBytesForCurrentThread();
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(
                plaintext,
                RecoveryManifestParser.MaximumArtifactCount));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(allocated < 256 * 1024, $"Unexpected allocation: {allocated}");
    }

    [Fact]
    public void HostileIntMaxRowLength_IsNormalizedBeforeOwnership()
    {
        var plaintext = CanonicalDrm5();
        var rows = RecoveryManifestParser.Preflight(plaintext, 6).RowsOffset;
        BinaryPrimitives.WriteUInt32BigEndian(plaintext.AsSpan(rows + 2, 4), int.MaxValue);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var exception = Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(plaintext, 6));

        Assert.Equal(RecordError.InvalidLength, exception.Error);
        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - before, 0, 64 * 1024);
    }

    [Fact]
    public void MissingLateClosedAdjacency_RejectsBeforeOwnedSnapshot()
    {
        var plaintext = CanonicalDrm5();
        var rows = RecoveryManifestParser.Preflight(plaintext, 6).RowsOffset;
        var dcm = FindRow(plaintext, rows, ArtifactType.Dcm1);
        var dcmBytes = dcm + ArtifactReference.Length;
        MutableField(plaintext, dcmBytes, 5).Fill(0x7f);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var exception = Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(plaintext, 6));

        Assert.Equal(RecordError.InvalidArtifactReference, exception.Error);
        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - before, 0, 64 * 1024);
    }

    [Fact]
    public void DrsDtcCountMismatch_RejectsBeforeOwnedSnapshot()
    {
        var plaintext = CanonicalDrm5();
        var rows = RecoveryManifestParser.Preflight(plaintext, 6).RowsOffset;
        var drs = FindRow(plaintext, rows, ArtifactType.Drs1);
        var drsBytes = drs + ArtifactReference.Length;
        BinaryPrimitives.WriteUInt16BigEndian(
            MutableField(plaintext, drsBytes, 9), 1);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var exception = Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(plaintext, 6));

        Assert.Equal(RecordError.InvalidField, exception.Error);
        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - before, 0, 64 * 1024);
    }

    [Theory]
    [InlineData("DRM1", 1)]
    [InlineData("DRM2", 2)]
    [InlineData("DRM3", 3)]
    [InlineData("DRM4", 4)]
    [InlineData("DRM5", 5)]
    [InlineData("DRM6", 6)]
    [InlineData("DRM7", 7)]
    [InlineData("DRM8", 8)]
    [InlineData("DRM9", 9)]
    [InlineData("DRM1", 10)]
    [InlineData("DRM1", 11)]
    [InlineData("DRM1", 12)]
    [InlineData("DRM1", 13)]
    [InlineData("DRM1", 14)]
    public void LegacyDrmVersions_RejectWithoutReinterpretation(string magic, byte version)
    {
        var plaintext = CanonicalDrm5();
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(plaintext, 0);
        plaintext[4] = version;

        var exception = Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(plaintext, 6));

        Assert.Equal(RecordError.InvalidHeader, exception.Error);
    }

    private static byte[] CanonicalDrm5()
    {
        var plaintext = Drm3Fixture.Create();
        "DRMV"u8.CopyTo(plaintext);
        plaintext[4] = 20;
        return plaintext;
    }

    private static int FindRow(byte[] plaintext, int offset, ArtifactType type)
    {
        var count = BinaryPrimitives.ReadUInt16BigEndian(plaintext.AsSpan(6, 2));
        for (var index = 0; index < count; index++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                plaintext.AsSpan(offset + 2, 4)));
            if (BinaryPrimitives.ReadUInt16BigEndian(plaintext.AsSpan(offset, 2)) == (ushort)type)
                return offset;
            offset += ArtifactReference.Length + length;
        }
        throw new InvalidOperationException("The fixture row is absent.");
    }

    private static Span<byte> MutableField(byte[] encoded, int recordOffset, int oneBasedTag)
    {
        var offset = recordOffset + CanonicalGrammar.HeaderLength;
        for (var tag = 1; tag <= oneBasedTag; tag++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                encoded.AsSpan(offset + 4, 4)));
            offset += CanonicalGrammar.FieldHeaderLength;
            if (tag == oneBasedTag) return encoded.AsSpan(offset, length);
            offset += length;
        }
        throw new ArgumentOutOfRangeException(nameof(oneBasedTag));
    }

}
