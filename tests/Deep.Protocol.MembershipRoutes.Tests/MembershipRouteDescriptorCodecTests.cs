using Deep.Protocol.DeepExtension.MembershipRoutes;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class MembershipRouteDescriptorCodecTests
{
    [Fact]
    public void CanonicalRoundTrip_IsStable()
    {
        var descriptor = Member(1);
        var encoded = MembershipRouteDescriptorCodec.Encode(descriptor);
        var decoded = MembershipRouteDescriptorCodec.Decode(encoded);

        Assert.Equal(encoded, MembershipRouteDescriptorCodec.Encode(decoded));
        Assert.Equal(descriptor.RpcEndpoint, decoded.RpcEndpoint);
        Assert.Equal(descriptor.RouterId.ToArray(), decoded.RouterId.ToArray());
    }

    [Fact]
    public void SixMemberProofs_VerifyAndRejectTampering()
    {
        var members = Enumerable.Range(1, 6).Select(Member).ToArray();
        var root = MembershipRouteDescriptorCodec.ComputeRoot(members);
        var proofs = MembershipRouteDescriptorCodec.BuildProofs(members);

        Assert.All(
            members.Select((member, index) => (member, index)),
            item => Assert.True(MembershipRouteDescriptorCodec.VerifyInclusion(
                item.member, proofs[item.index], root)));

        var tampered = members[2] with { RpcEndpoint = "https://attacker.invalid/" };
        Assert.False(MembershipRouteDescriptorCodec.VerifyInclusion(tampered, proofs[2], root));
        Assert.False(MembershipRouteDescriptorCodec.VerifyInclusion(
            members[2],
            proofs[2] with { MemberCount = 5 },
            root));
    }

    [Theory]
    [InlineData("https://user:secret@example.test/")]
    [InlineData("https://example.test/path")]
    [InlineData("ftp://example.test/")]
    public void Endpoint_IsAuthorityOnly(string endpoint)
    {
        var descriptor = Member(1) with { RpcEndpoint = endpoint };
        var exception = Assert.Throws<MembershipRouteDescriptorException>(
            () => MembershipRouteDescriptorCodec.Encode(descriptor));
        Assert.Equal(MembershipRouteDescriptorError.InvalidEndpoint, exception.Error);
    }

    private static MembershipRouteDescriptor Member(int value) => new()
    {
        RouterId = Bytes(value),
        Ed25519PublicKey = Bytes(value + 20),
        X25519PublicKey = Bytes(value + 40),
        RpcEndpoint = $"https://node-{value}.example.test/",
        Roles = MembershipRouteRole.Ingress | MembershipRouteRole.Core | MembershipRouteRole.Storage,
        Capabilities = MembershipRouteCapability.SessionRpc |
                       MembershipRouteCapability.OnionV1 |
                       MembershipRouteCapability.Storage,
        Epoch = 7,
        ValidFromUnixSeconds = 1_700_000_000,
        ValidUntilUnixSeconds = 1_800_000_000
    };

    private static byte[] Bytes(int start) =>
        Enumerable.Range(start, MembershipRouteDescriptorCodec.KeyLength)
            .Select(static value => checked((byte)value))
            .ToArray();
}
