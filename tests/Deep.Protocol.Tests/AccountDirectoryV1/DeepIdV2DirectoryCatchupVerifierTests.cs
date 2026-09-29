using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed partial class AccountDirectoryFreshnessVerificationTests
{
    [Fact]
    public void Did2Catchup_ExactEmptyPageShapeVectorHasNoFreshnessAuthority()
    {
        var request = Convert.FromHexString("444851320002000000000044000102030405060708090a0b0c0d0e0f00000000000000000101010101010101010101010101010101010101010101010101010101010101");
        var response = Convert.FromHexString("444852320002000000000047000102030405060708090a0b0c0d0e0f00000000000000000101010101010101010101010101010101010101010101010101010101010101000000");
        DeepIdV2DirectoryHistoryWireCodec.ValidateRequest(request);
        var page = DeepIdV2DirectoryHistoryWireCodec.DecodeResponse(response,request);
        Assert.Empty(page.ExactSuccessors); Assert.Empty(page.ConsistencyNodes.ToArray());
        foreach (var offset in new[] {0,4,6,8,12,28,36,68,70}) {
            var bad = response.ToArray(); bad[offset] ^= 0x80;
            Assert.ThrowsAny<Exception>(() => DeepIdV2DirectoryHistoryWireCodec.DecodeResponse(bad,request));
        }
        foreach (var length in Enumerable.Range(0,response.Length))
            Assert.Throws<FormatException>(() => DeepIdV2DirectoryHistoryWireCodec.DecodeResponse(response.AsSpan(0,length),request));
    }

    [Fact]
    public void Did2Catchup_WirePagesAreSourceBoundCanonicalAndBounded()
    {
        var fixture = AuthorityFixture.Create();
        var root = AccountDirectoryRfc6962.ComputeEmptyTreeHash();
        var map = DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray();
        var source = new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(
            fixture.Head(0, new byte[32], 0, root, map, minimumReader: 2)));
        var history = new List<AccountDirectoryProtectedLkg> { source };
        for (var i = 0; i < 130; i++)
            history.Add(new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(fixture.Head(
                history[^1].LogGeneration + 1, history[^1].CoreHash.ToArray(), 0, root, map, minimumReader: 2))));
        var floor = source;
        foreach (var count in new[] { 64, 64, 2, 0 })
        {
            var request = DeepIdV2DirectoryHistoryWireCodec.EncodeRequest(floor);
            Assert.Equal(68, request.Length);
            Assert.Equal("444851320002000000000044", Convert.ToHexString(request[..12]));
            var response = DeepIdV2DirectoryHistoryWireCodec.AuthorResponse(fixture.Verified, request, history, []);
            var page = DeepIdV2DirectoryHistoryWireCodec.DecodeResponse(response, request);
            Assert.Equal(count, page.ExactSuccessors.Count);
            if (count > 0) floor = DeepIdV2DirectoryCatchupVerifier.Verify(fixture.Verified,
                floor, page.ExactSuccessors, page.ConsistencyNodes).ProtectedLkg;
            for (var length = 0; length < response.Length; length += Math.Max(1, response.Length / 32))
                Assert.ThrowsAny<Exception>(() => DeepIdV2DirectoryHistoryWireCodec.DecodeResponse(response.AsSpan(0, length), request));
            foreach (var offset in new[] { 0, 4, 6, 8, 12, 28, 36, 68 })
            {
                var bad = response.ToArray(); bad[offset] ^= 0x80;
                Assert.ThrowsAny<Exception>(() => DeepIdV2DirectoryHistoryWireCodec.DecodeResponse(bad, request));
            }
            var extra = response.Concat(new byte[1]).ToArray();
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(extra.AsSpan(8), (uint)extra.Length);
            Assert.Throws<FormatException>(() => DeepIdV2DirectoryHistoryWireCodec.DecodeResponse(extra, request));
        }
        Assert.Equal(130UL, floor.LogGeneration);
    }

    [Fact]
    public void Did2Catchup_ResumesMoreThan64HeadsWithoutRootOrFreshness()
    {
        var fixture = AuthorityFixture.Create();
        var root = AccountDirectoryRfc6962.ComputeEmptyTreeHash();
        var map = DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray();
        var prior = new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(
            fixture.Head(0, new byte[32], 0, root, map, minimumReader: 2)));
        var initial = prior;
        for (var page = 0; page < 3; page++)
        {
            var chain = new List<ReadOnlyMemory<byte>>();
            var last = prior;
            for (var index = 0; index < 64; index++)
            {
                var next = AccountDirectoryAdh1Codec.Encode(fixture.Head(last.LogGeneration + 1,
                    last.CoreHash.ToArray(), 0, root, map, minimumReader: 2));
                chain.Add(next);
                last = new AccountDirectoryProtectedLkg(next);
            }
            var verified = DeepIdV2DirectoryCatchupVerifier.Verify(fixture.Verified, prior, chain, default);
            Assert.Equal(prior.ExactAdh1.ToArray(), verified.PriorProtectedLkg.ExactAdh1.ToArray());
            Assert.Equal(last.ExactAdh1.ToArray(), verified.ProtectedLkg.ExactAdh1.ToArray());
            if (page != 0)
                Assert.Throws<CryptographicException>(() => DeepIdV2DirectoryCatchupVerifier.Verify(
                    fixture.Verified, initial, chain, default));
            prior = AccountDirectoryProtectedLkgFactory.Restore(fixture.Verified,
                verified.ProtectedLkg.ExactAdh1, verified.ProtectedLkg.CoreHash.Span);
        }
        Assert.Equal(192UL, prior.LogGeneration);
    }

    [Fact]
    public void Did2Catchup_RejectsForkReaderDowngradeRootChangeAndBadShapes()
    {
        var fixture = AuthorityFixture.Create();
        var root = AccountDirectoryRfc6962.ComputeEmptyTreeHash();
        var map = DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray();
        var source = new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(
            fixture.Head(0, new byte[32], 0, root, map, minimumReader: 2)));
        var valid = AccountDirectoryAdh1Codec.Encode(fixture.Head(1,
            source.CoreHash.ToArray(), 0, root, map, minimumReader: 2));
        foreach (var wrong in new[]
        {
            fixture.Head(1, Bytes(32, 0x42), 0, root, map, minimumReader: 2),
            fixture.Head(2, source.CoreHash.ToArray(), 0, root, map, minimumReader: 2),
            fixture.Head(1, source.CoreHash.ToArray(), 0, root, map, minimumReader: 1),
            fixture.Head(1, source.CoreHash.ToArray(), 0, root, Bytes(32, 0x42), minimumReader: 2),
        })
            Assert.ThrowsAny<CryptographicException>(() => DeepIdV2DirectoryCatchupVerifier.Verify(
                fixture.Verified, source, [AccountDirectoryAdh1Codec.Encode(wrong)], default));
        var tampered = valid.ToArray();
        tampered[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => DeepIdV2DirectoryCatchupVerifier.Verify(
            fixture.Verified, source, [tampered], default));
        Assert.Throws<ArgumentException>(() => DeepIdV2DirectoryCatchupVerifier.Verify(
            fixture.Verified, source, [], default));
        Assert.Throws<ArgumentException>(() => DeepIdV2DirectoryCatchupVerifier.Verify(
            fixture.Verified, source, Enumerable.Repeat((ReadOnlyMemory<byte>)valid, 65).ToArray(), default));
        Assert.Throws<ArgumentException>(() => DeepIdV2DirectoryCatchupVerifier.Verify(
            fixture.Verified, source, [valid], new byte[33]));
        var nonempty = new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(
            fixture.Head(0, new byte[32], 2, Bytes(32, 0x51), map, minimumReader: 2)));
        var inconsistent = AccountDirectoryAdh1Codec.Encode(fixture.Head(1,
            nonempty.CoreHash.ToArray(), 3, Bytes(32, 0x52), map, minimumReader: 2));
        Assert.Throws<CryptographicException>(() => DeepIdV2DirectoryCatchupVerifier.Verify(
            fixture.Verified, nonempty, [inconsistent], default));
    }
}
