using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class DeepIdV2CodecTests
{
    [Fact]
    public void Did2_RoundTripsCompactCommitment_WithoutFabricatingCredential()
    {
        var capability = Enumerable.Repeat((byte)0xa5, 16).ToArray();
        var did = DeepIdV2Codec.AuthorDid2(Pattern(32, 1), Pattern(1952, 2), capability);
        Assert.Equal(2052, did.CanonicalBytes.Length);
        var descriptor = DeepPermanentIdV2.FromCredential(did, capability);
        Assert.Equal(90, descriptor.CanonicalText.Length);
        Assert.Equal("DID2", did.Magic);
        Assert.Equal(-1, did.CanonicalBytes.Span.IndexOf(capability));
        Assert.True(did.MatchesResolverReadCapability(capability));
        var compact = DeepIdV2Codec.DecodeDeepIdText(descriptor.CanonicalText);
        Assert.Equal(did.RecordHash.ToArray(), compact.Did2Hash);
        Assert.Equal(capability, compact.ReadCapability);

        var reparsed = DeepIdV2Codec.DecodeDid2(did.CanonicalBytes.Span);
        Assert.True(reparsed.MatchesResolverReadCapability(capability));
        Assert.Equal(did.RecordHash.ToArray(), reparsed.RecordHash.ToArray());
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2Codec.DecodeDeepIdText(descriptor.CanonicalText.ToUpperInvariant()));
        var text = descriptor.CanonicalText;
        var mutatedText = text[..^1] + (text[^1] == 'q' ? 'p' : 'q');
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2Codec.DecodeDeepIdText(mutatedText));

        Assert.True(descriptor.MatchesExactCredential(did));
        Assert.True(DeepPermanentIdV2.ParseCanonical(text).MatchesExactCredential(did));
        Assert.Throws<ArgumentException>(() => DeepPermanentIdV2.FromCredential(
            did, Pattern(16, 4)));
        var substituted = DeepIdV2Codec.AuthorDid2(
            Pattern(32, 1), Pattern(1952, 4), Pattern(16, 3));
        Assert.False(descriptor.MatchesExactCredential(substituted));
        var legacyText = DeepPermanentIdV1.Create(Pattern(32, 1), Pattern(16, 3)).CanonicalText;
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepPermanentIdV2.ParseCanonical(legacyText));
    }

    [Fact]
    public void Did2_RejectsOldVersionSuiteLengthsAndTags()
    {
        var did = DeepIdV2Codec.AuthorDid2(Pattern(32, 1), Pattern(1952, 2), Pattern(16, 3));
        var canonical = did.CanonicalBytes.ToArray();
        canonical[5] = 1;
        AssertRejects(ApplicationCoreRejection.WrongVersion, () => DeepIdV2Codec.DecodeDid2(canonical));
        canonical = did.CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(canonical.AsSpan(6, 2), 0x0201);
        AssertRejects(ApplicationCoreRejection.WrongSuite, () => DeepIdV2Codec.DecodeDid2(canonical));
        canonical = did.CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(canonical.AsSpan(12, 2), 2);
        AssertRejects(ApplicationCoreRejection.OutOfOrderTag, () => DeepIdV2Codec.DecodeDid2(canonical));
        canonical = did.CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(canonical.AsSpan(16, 4), 31);
        AssertRejects(ApplicationCoreRejection.UnknownTag, () => DeepIdV2Codec.DecodeDid2(canonical));
        // The retired raw-capability candidate was 16 bytes shorter.
        var retired = did.CanonicalBytes.Span[..2036].ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(retired.AsSpan(8), 2036);
        BinaryPrimitives.WriteUInt32BigEndian(retired.AsSpan(2016), 16);
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2Codec.DecodeDid2(retired));
    }

    [Fact]
    public void Dab2_HasExactHybridProjectionAndClosedPredecessor()
    {
        var did = DeepIdV2Codec.AuthorDid2(Pattern(32, 1), Pattern(1952, 2), Pattern(16, 3));
        var reference = new ApplicationArtifactReference(1, 644, Pattern(32, 4));
        var dab = DeepIdV2Codec.AuthorDab2(
            did.RecordHash.Span, Pattern(32, 5), 0, new byte[32],
            Pattern(32, 6), 1, reference,
            Pattern(64, 7), Pattern(3309, 8), Pattern(64, 9));
        Assert.Equal(3711, dab.CanonicalBytes.Length);
        Assert.Equal(250, dab.UnsignedCanonicalBytes.Length);
        Assert.Equal(0x0301,
            BinaryPrimitives.ReadUInt16BigEndian(dab.UnsignedCanonicalBytes.Span[6..8]));
        Assert.Equal(0x1002, DeepIdV2Codec.Dab2ArtifactType);
        var reparsed = DeepIdV2Codec.DecodeDab2(dab.CanonicalBytes.Span);
        Assert.Equal(dab.RecordHash.ToArray(), reparsed.RecordHash.ToArray());

        var invalid = dab.CanonicalBytes.ToArray();
        invalid[12 + 3 * 8 + 32 + 32 + 8 + 8] = 1;
        AssertRejects(ApplicationCoreRejection.InvalidGeneration, () => DeepIdV2Codec.DecodeDab2(invalid));
    }

    private static byte[] Pattern(int length, byte start) =>
        Enumerable.Range(0, length).Select(index => unchecked((byte)(start + index))).ToArray();

    private static void AssertRejects(ApplicationCoreRejection rejection, Action action)
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(action);
        Assert.Equal(rejection, exception.Rejection);
    }
}
