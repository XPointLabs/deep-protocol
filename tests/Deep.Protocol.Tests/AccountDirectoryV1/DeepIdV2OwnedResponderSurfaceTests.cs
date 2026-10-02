using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class DeepIdV2OwnedResponderSurfaceTests
{
    [Fact]
    public void Did2OwnedResponderSurface_ClosedCurrentProofInputsAndSingleAtomicHandoff()
    {
        Assert.Empty(typeof(ResponderInitialSessionCommitCapability).GetConstructors());
        Assert.Empty(typeof(ResponderInitialSessionAtomicStorePayload).GetConstructors());
        var prepare = typeof(OwnedGenesisDeviceSecrets).GetMethod(nameof(OwnedGenesisDeviceSecrets.PrepareInitialSessionAsync))!;
        Assert.Equal(new[] { typeof(VerifiedDph2InitialClaim), typeof(VerifiedDeepIdV2DirectoryFreshness),
            typeof(VerifiedDeepIdV2DirectoryFreshness), typeof(RestoredDpk2PreKeySecretCapability),
            typeof(OnionTrustedTimeAuthority), typeof(int), typeof(CancellationToken) },
            prepare.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.Equal(typeof(ValueTask<ResponderInitialSessionCommitCapability>), prepare.ReturnType);
        var preview = typeof(OwnedGenesisDeviceSecrets).GetMethod(nameof(OwnedGenesisDeviceSecrets.PreviewInitialClaimAsync))!;
        Assert.Equal(typeof(ValueTask<Dph2InitialClaimPreview>), preview.ReturnType);
        Assert.Equal(new[] { typeof(Dph2Record), typeof(VerifiedDeepIdV2DirectoryFreshness),
            typeof(VerifiedDeepIdV2DirectoryFreshness), typeof(VerifiedDpk2Offering),
            typeof(RestoredDpk2PreKeySecretCapability), typeof(OnionTrustedTimeAuthority), typeof(int), typeof(CancellationToken) },
            preview.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.Equal(new[] { "ClaimOperationId", "SessionId" },
            typeof(ResponderInitialSessionCommitCapability).GetProperties().Select(property => property.Name).Order());
        Assert.DoesNotContain(typeof(ResponderInitialSessionCommitCapability).GetMethods(),
            method => method.Name is "Acknowledge" or "Reserve" or "Commit" or "Publish" or "Dispatch");
    }
}
