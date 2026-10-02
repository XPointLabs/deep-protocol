using System.Reflection;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.Identity;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class PublicationStoreAuthoritySurfaceTests
{
    [Fact]
    public void PermanentResolveCannotMintTrustFromParsedBytesOrCallerKeys()
    {
        Assert.Empty(typeof(ParsedDeepIdV2PermanentContactCandidate).GetConstructors());
        Assert.Empty(typeof(VerifiedDeepIdV2PermanentContactResolveClosure).GetConstructors());
        Assert.Empty(typeof(DeepIdV2ContactRouteTimeWindow).GetConstructors());
        Assert.All(typeof(DeepIdV2ContactRouteTimeWindow).GetProperties(), property => Assert.False(property.CanWrite));
        var methods = typeof(DeepIdV2PermanentContactResolveVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly);
        var open = Assert.Single(methods, method => method.Name == "OpenCandidate");
        Assert.Equal([typeof(DeepPermanentIdV2), typeof(ReadOnlyMemory<byte>), typeof(ReadOnlyMemory<byte>)],
            open.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        var verify = Assert.Single(methods, method => method.Name == "VerifyAsync");
        Assert.Equal([typeof(ParsedDeepIdV2PermanentContactCandidate), typeof(VerifiedDeepIdV2DirectoryFreshness),
            typeof(VerifiedOnionNetworkContext), typeof(VerifiedXPointNetworkAuthority),
            typeof(OnionTrustedTimeAuthority), typeof(CancellationToken)],
            verify.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        Assert.Equal(312, DeepIdV2PermanentContactResolveVerifier.ExactRequestBytes);
        Assert.Equal(131_072, DeepIdV2PermanentContactResolveVerifier.MaximumResultBytes);
    }

    [Fact]
    public void OwnedPublicationCommitRequiresClosedDid2InputsAndCannotBeManufactured()
    {
        Assert.Empty(typeof(VerifiedDeepIdV2PublicationCommit).GetConstructors());
        var method = Assert.Single(typeof(DeepIdV2PublicationCommitVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Equal("VerifyCommittedAsync", method.Name);
        Assert.Equal([typeof(VerifiedDeepIdV2ContactRouteClosure), typeof(AuthoredDeepIdV2ContactObject),
            typeof(ContactPublicationAuthorityWireRequest), typeof(ReadOnlyMemory<byte>),
            typeof(ReadOnlyMemory<byte>), typeof(CancellationToken)],
            method.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        Assert.All(typeof(VerifiedDeepIdV2PublicationCommit).GetProperties(), property => Assert.False(property.CanWrite));
        Assert.Equal(16_384, DeepIdV2PublicationCommitVerifier.MaximumResultBytes);
    }

    [Fact]
    public void PublicStoreAuthorityRequiresDirectDid2AndClosedVerifiedInputs()
    {
        Assert.Empty(typeof(VerifiedXpa1PublicationAuthorization).GetConstructors());
        var verify = Assert.Single(typeof(Xpa1PublicationAuthorizationVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Equal("VerifyAsync", verify.Name);
        Assert.Equal(
            [typeof(Xpu1Request), typeof(VerifiedXPointNetworkAuthority),
             typeof(VerifiedDeepIdV2DirectoryFreshness), typeof(VerifiedContactServicePlacement),
             typeof(OnionTrustedTimeAuthority), typeof(CancellationToken)],
            verify.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        Assert.DoesNotContain(verify.GetParameters(), parameter =>
            parameter.ParameterType == typeof(byte[]) ||
            typeof(Delegate).IsAssignableFrom(parameter.ParameterType));
        var recheck = typeof(VerifiedXpa1PublicationAuthorization).GetMethod("EnsureCurrentAsync")!;
        Assert.Equal([typeof(CancellationToken)],
            recheck.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
    }
}
