using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class XPointNetworkPrimitiveVectorTests
{
    public static IEnumerable<object[]> FrozenPrimitiveVectors() =>
        XPointNetworkFrozenVectorManifest.PrimitiveVectors.Select(vector => new object[] { vector });

    [Theory]
    [MemberData(nameof(FrozenPrimitiveVectors))]
    public void FrozenPrimitiveVectorExecutesWithExactPreimageAndOutput(XPointPrimitiveVector vector)
    {
        var input = Convert.FromHexString(vector.InputHex);
        var expectedPreimage = Convert.FromHexString(vector.PreimageHex);
        var expected = Convert.FromHexString(vector.ExpectedHex);
        byte[] actualPreimage;
        byte[] actual;

        switch (vector.Operation)
        {
            case "SHA256-D":
                actualPreimage = DomainPreimage(vector.Domain, input);
                actual = XPointNetworkCrypto.Sha256Domain(vector.Domain, input);
                break;
            case "SIGINPUT":
                actualPreimage = XPointNetworkCrypto.SignatureInput(vector.Domain, 0x0201, input);
                actual = SHA256.HashData(actualPreimage);
                break;
            case "ArtifactRef38":
                actualPreimage = input;
                actual = new byte[38];
                "XND1"u8.CopyTo(actual);
                BinaryPrimitives.WriteUInt16BigEndian(actual.AsSpan(4), 1);
                SHA256.HashData(input).CopyTo(actual.AsSpan(6));
                break;
            case "SHA256":
                actualPreimage = input;
                actual = SHA256.HashData(input);
                break;
            default:
                throw new InvalidOperationException($"Unknown frozen primitive operation: {vector.Operation}.");
        }

        Assert.Equal(expectedPreimage, actualPreimage);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void FrozenPrimitiveManifestIsUntampered() => XPointNetworkFrozenVectorManifest.AssertUntampered();

    [Fact]
    public void ExactOneLeafAppendConsistencyAndInclusionProofsVerify()
    {
        var first = XPointNetworkCrypto.Rfc6962Leaf(new byte[] { 1 });
        var second = XPointNetworkCrypto.Rfc6962Leaf(new byte[] { 2 });
        var root = XPointNetworkCrypto.Rfc6962Inner(first, second);
        XPointMerkleProofs.VerifyConsistency(1, 2, first, root, second, 1);
        XPointMerkleProofs.VerifyInclusion(second, 1, 2, first, 1, root);
    }

    [Fact]
    public void ExtraOrChangedMerkleNodesRejectAsNoncanonicalProofs()
    {
        var first = XPointNetworkCrypto.Rfc6962Leaf(new byte[] { 1 });
        var second = XPointNetworkCrypto.Rfc6962Leaf(new byte[] { 2 });
        var root = XPointNetworkCrypto.Rfc6962Inner(first, second);
        var extra = second.Concat(second).ToArray();
        Assert.Throws<XPointValidationException>(() => XPointMerkleProofs.VerifyConsistency(1, 2, first, root, extra, 2));
        second[0] ^= 1;
        Assert.Throws<XPointValidationException>(() => XPointMerkleProofs.VerifyConsistency(1, 2, first, root, second, 1));
    }

    private static byte[] DomainPreimage(string domain, ReadOnlySpan<byte> payload)
    {
        var domainBytes = Encoding.ASCII.GetBytes(domain);
        var output = new byte[domainBytes.Length + 5 + payload.Length];
        domainBytes.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(domainBytes.Length + 1), checked((uint)payload.Length));
        payload.CopyTo(output.AsSpan(domainBytes.Length + 5));
        return output;
    }
}
