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
    public void SuccessorCoordinationHasOnlyBoundedParsedBytesAndClosedReadOnlyVerification()
    {
        Assert.Equal(3, ContactRouteAuthorityWireCodec.RequestVersion);
        Assert.Equal(3, ContactRouteAuthorityWireCodec.ResponseVersion);
        Assert.Equal(1_159, ContactRouteAuthorityWireCodec.MinimumRequestBytes);
        Assert.Equal(25_065, ContactRouteAuthorityWireCodec.MaximumRequestBytes);
        Assert.All(typeof(ContactRouteAuthorityWireRequest).GetProperties(), property => Assert.False(property.CanWrite));
        Assert.Null(typeof(ContactRouteAuthorityWireCodec).GetField("RequestBytes"));
        Assert.Empty(typeof(VerifiedDeepIdV2ContactRoutePredecessor).GetConstructors());
        var verify = Assert.Single(typeof(DeepIdV2ContactRouteVerifier).GetMethods(),
            method => method.Name == "VerifyAdvertisementSuccessorAsync");
        Assert.Equal([typeof(DeepIdV2CurrentContactAuthorization), typeof(VerifiedOnionNetworkContext),
            typeof(VerifiedXPointNetworkAuthority), typeof(VerifiedDeepIdV2ContactRoutePredecessor),
            typeof(ReadOnlyMemory<byte>), typeof(OnionTrustedTimeAuthority), typeof(CancellationToken)],
            verify.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        Assert.Equal(typeof(ValueTask), verify.ReturnType);
        Assert.False(verify.GetParameters()[3].IsOptional);
        Assert.DoesNotContain(verify.GetParameters(), parameter => typeof(Delegate).IsAssignableFrom(parameter.ParameterType));
    }

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
        var methods = typeof(DeepIdV2PublicationCommitVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly);
        Assert.Equal(["VerifyCommittedAsync", "VerifyIssuerPredecessorAsync", "VerifyOneTimeCommittedAsync", "VerifyPredecessorAsync"], methods.Select(value => value.Name).Order().ToArray());
        var method = Assert.Single(methods, value => value.Name == "VerifyCommittedAsync");
        Assert.Equal("VerifyCommittedAsync", method.Name);
        Assert.Equal([typeof(VerifiedDeepIdV2ContactRouteClosure), typeof(AuthoredDeepIdV2ContactObject),
            typeof(ContactPublicationAuthorityWireRequest), typeof(ReadOnlyMemory<byte>),
            typeof(ReadOnlyMemory<byte>), typeof(CancellationToken)],
            method.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        var oneTime = Assert.Single(methods, value => value.Name == "VerifyOneTimeCommittedAsync");
        Assert.Equal([typeof(VerifiedDeepIdV2ContactRouteClosure), typeof(AuthoredDeepIdV2OneTimeContactObject),
            typeof(ContactPublicationAuthorityWireRequest), typeof(ReadOnlyMemory<byte>),
            typeof(ReadOnlyMemory<byte>), typeof(CancellationToken)],
            oneTime.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        Assert.Equal(typeof(ValueTask<VerifiedDeepIdV2PublicationCommit>), oneTime.ReturnType);
        Assert.DoesNotContain(oneTime.GetParameters(), parameter =>
            typeof(Delegate).IsAssignableFrom(parameter.ParameterType) || parameter.ParameterType == typeof(bool));
        Assert.All(typeof(VerifiedDeepIdV2PublicationCommit).GetProperties(), property => Assert.False(property.CanWrite));
        Assert.Equal(16_384, DeepIdV2PublicationCommitVerifier.MaximumResultBytes);
    }

    [Fact]
    public void IssuerHistoryIsSeparateClosedSignedEvidenceWithoutClientDecryptionOrDispatch()
    {
        var type = typeof(VerifiedDeepIdV2PublicationIssuerPredecessor);
        Assert.Empty(type.GetConstructors());
        Assert.Equal(["Generation"], type.GetProperties().Select(property => property.Name).ToArray());
        Assert.DoesNotContain(type.GetMethods(), method => method.Name is "SignAsync" or "DispatchAsync" or "EnsureCurrentAsync");
        var verify = Assert.Single(typeof(DeepIdV2PublicationCommitVerifier).GetMethods(), method => method.Name == "VerifyIssuerPredecessorAsync");
        Assert.Equal([typeof(DeepIdV2CurrentContactAuthorization), typeof(VerifiedOnionNetworkContext), typeof(VerifiedXPointNetworkAuthority),
            typeof(ContactPublicationAuthorityWireRequest), typeof(ReadOnlyMemory<byte>), typeof(ReadOnlyMemory<byte>),
            typeof(OnionTrustedTimeAuthority), typeof(CancellationToken)], verify.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        foreach (var name in new[] { "VerifyIssuerSuccessorRequestAsync", "AuthorIssuerThresholdSuccessorAsync", "VerifyIssuerSuccessorResponseAsync" })
        {
            var method = Assert.Single(typeof(DeepIdV2PublicationAuthorityAuthor).GetMethods(), value => value.Name == name);
            Assert.False(Assert.Single(method.GetParameters(), parameter => parameter.ParameterType == type).IsOptional);
        }
        Assert.Equal(4, ContactPublicationAuthorityWireCodec.Version);
        Assert.Equal(23_322, ContactPublicationAuthorityWireCodec.MinimumRequestBytes);
        Assert.Equal(171_614, ContactPublicationAuthorityWireCodec.MaximumRequestBytes);
        Assert.Equal(171_626, ContactCoordinationOnionCodec.MaximumRequestBytes);
    }

    [Fact]
    public void SuccessorsRequireClosedHistoryAndCannotMintDispatchFromParsedHashes()
    {
        foreach (var type in new[] { typeof(VerifiedDeepIdV2ContactObjectPredecessor), typeof(VerifiedDeepIdV2PublicationPredecessor) })
        {
            Assert.Empty(type.GetConstructors());
            Assert.All(type.GetProperties(), property => Assert.False(property.CanWrite));
            Assert.DoesNotContain(type.GetMethods(), method => method.Name is "EnsureCurrentAsync" or "SignAsync" or "DispatchAsync");
        }
        var verify = Assert.Single(typeof(DeepIdV2PublicationCommitVerifier).GetMethods(), method => method.Name == "VerifyPredecessorAsync");
        Assert.Equal([typeof(DeepIdV2CurrentContactAuthorization), typeof(VerifiedOnionNetworkContext), typeof(VerifiedXPointNetworkAuthority),
            typeof(VerifiedDeepIdV2ContactObjectPredecessor), typeof(ContactPublicationAuthorityWireRequest),
            typeof(ReadOnlyMemory<byte>), typeof(ReadOnlyMemory<byte>), typeof(OnionTrustedTimeAuthority), typeof(CancellationToken)],
            verify.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        var objectAuthor = Assert.Single(typeof(DeepIdV2ContactObjectAuthor).GetMethods(), method => method.Name == "AuthorRetainedSuccessorAsync");
        Assert.Equal([typeof(VerifiedDeepIdV2ContactRouteClosure), typeof(VerifiedDeepIdV2ContactRouteIssuance),
            typeof(VerifiedDeepIdV2ContactObjectPredecessor), typeof(OwnedGenesisDeviceSecrets), typeof(IReadOnlyList<ParsedXps1V2>),
            typeof(string), typeof(ReadOnlyMemory<byte>), typeof(CancellationToken)],
            objectAuthor.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        foreach (var name in new[] { "AuthorSuccessorRequestAsync", "VerifySuccessorRequestAsync", "AuthorThresholdSuccessorAsync", "VerifySuccessorResponseAsync" })
        {
            var method = Assert.Single(typeof(DeepIdV2PublicationAuthorityAuthor).GetMethods(), value => value.Name == name);
            var predecessor = Assert.Single(method.GetParameters(), value => value.ParameterType == typeof(VerifiedDeepIdV2PublicationPredecessor));
            Assert.False(predecessor.IsOptional);
            Assert.DoesNotContain(method.GetParameters(), parameter => typeof(Delegate).IsAssignableFrom(parameter.ParameterType));
        }
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
