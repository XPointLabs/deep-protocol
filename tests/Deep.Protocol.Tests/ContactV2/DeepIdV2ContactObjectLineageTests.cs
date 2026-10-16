using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV2;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2ContactObjectLineageTests
{
    [Theory]
    [InlineData(100UL, 200UL)]
    [InlineData(110UL, 200UL)]
    [InlineData(110UL, 210UL)]
    public void ChainAllowsNondecreasingSignedWindowWithoutExtendingAnyService(ulong issued, ulong expiry)
    {
        var prior = Bundle(7, 100, 200, new byte[32]);
        DeepIdV2ContactObjectLineage.RequireSuccessorChain(prior, Bundle(8, issued, expiry, prior.ObjectHash.ToArray()));
    }

    [Theory]
    [InlineData(7UL, 8UL, 99UL, 200UL, false)]
    [InlineData(7UL, 8UL, 110UL, 199UL, false)]
    [InlineData(7UL, 8UL, 110UL, 200UL, true)]
    [InlineData(7UL, 7UL, 110UL, 200UL, false)]
    [InlineData(7UL, 9UL, 110UL, 200UL, false)]
    [InlineData(ulong.MaxValue, 0UL, 110UL, 200UL, false)]
    public void ChainRejectsRollbackSubstitutionReplayGapAndOverflow(
        ulong priorGeneration, ulong generation, ulong issued, ulong expiry, bool wrongHash)
    {
        var prior = Bundle(priorGeneration, 100, 200, new byte[32]);
        var hash = prior.ObjectHash.ToArray();
        if (wrongHash) hash[0] ^= 1;
        Assert.Throws<CryptographicException>(() => DeepIdV2ContactObjectLineage.RequireSuccessorChain(
            prior, Bundle(generation, issued, expiry, hash)));
    }

    // Predicate-only parsed facts, not signature/currentness fixtures. The
    // signed owner/issuer/cold-replay case lives in Shared's renewal tests.
    private static ParsedDcb1V2 Bundle(ulong generation, ulong issued, ulong expiry, byte[] predecessor)
    {
        var fields = Enumerable.Range(0, 24).Select(_ => Array.Empty<byte>()).ToArray();
        fields[7] = U64(generation); fields[8] = predecessor;
        fields[16] = U64(issued); fields[17] = U64(expiry);
        return new ParsedDcb1V2(U64(generation), fields, []);
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes;
    }
}
