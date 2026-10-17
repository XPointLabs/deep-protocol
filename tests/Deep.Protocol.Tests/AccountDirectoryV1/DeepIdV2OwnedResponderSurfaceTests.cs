using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class DeepIdV2OwnedResponderSurfaceTests
{
    [Fact]
    public void Did2ExpiredInitialSurface_HasNoPublicFactoryRatchetKeysOrLiveConversion()
    {
        var prepare = typeof(OwnedGenesisDeviceSecrets).GetMethod(nameof(OwnedGenesisDeviceSecrets.PrepareInitialMailboxSessionAsync))!;
        var strict = typeof(OwnedGenesisDeviceSecrets).GetMethod(nameof(OwnedGenesisDeviceSecrets.PrepareInitialSessionAsync))!;
        Assert.Equal(strict.GetParameters().Select(value => value.ParameterType), prepare.GetParameters().Select(value => value.ParameterType));
        Assert.Equal(typeof(ValueTask<ResponderInitialMailboxPreparation>), prepare.ReturnType);
        foreach (var type in new[] { typeof(ResponderInitialMailboxPreparation), typeof(ResponderExpiredInitialAtomicStorePayload) })
        {
            Assert.True(type.IsSealed); Assert.Empty(type.GetConstructors());
            Assert.True(typeof(IDisposable).IsAssignableFrom(type));
            Assert.All(type.GetProperties(), property => Assert.Null(property.SetMethod));
        }
        Assert.Equal(new[] { "DiscardedStateHash", "FirstApplicationDmc2", "ProvenLowerUnixSeconds", "Reservation", "SessionInitDmc2" },
            typeof(ResponderExpiredInitialAtomicStorePayload).GetProperties().Select(value => value.Name).Order());
        Assert.DoesNotContain(typeof(ResponderExpiredInitialAtomicStorePayload).GetMethods(),
            method => method.Name.Contains("Live", StringComparison.Ordinal) || method.Name.Contains("Trs", StringComparison.Ordinal));
        Assert.Equal(typeof(ResponderInitialSessionCommitCapability), typeof(ResponderInitialMailboxPreparation)
            .GetMethod(nameof(ResponderInitialMailboxPreparation.ConsumeLive))!.ReturnType);
        Assert.Equal(typeof(ResponderExpiredInitialAtomicStorePayload), typeof(ResponderInitialMailboxPreparation)
            .GetMethod(nameof(ResponderInitialMailboxPreparation.ConsumeExpiredForAtomicStore))!.ReturnType);
    }

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
