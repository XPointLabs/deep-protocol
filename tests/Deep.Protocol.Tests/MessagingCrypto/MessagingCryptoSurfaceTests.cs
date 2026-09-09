using System.Reflection;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class MessagingCryptoSurfaceTests
{
    [Fact]
    public void OnlyReviewedReadinessAndOpaqueDurableDpe2SurfaceIsExported()
    {
        var assembly = typeof(Deep.Protocol.Identity.DeepRecoveryV1).Assembly;
        var exported = assembly.GetExportedTypes()
            .Where(static type => type.Namespace == "Deep.Protocol.MessagingCrypto")
            .Select(static type => type.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(
            new[]
            {
                nameof(ExactDpe2DurableCommitDisposition),
                nameof(ExactDpe2DurableCommitCompletion),
                nameof(ExactDpe2DurableCommitReceipt),
                nameof(ExactDpe2DurableDirection),
                nameof(ExactDpe2DurablePersistencePlan),
                nameof(ExactDpe2DurableTransactionProducer),
                nameof(ExactDpe2DurableTransitionContext),
                nameof(ExactDpe2PreparedReceive),
                nameof(ExactDpe2PreparedSend),
                nameof(ExactDpe2ReceiveReplayDisposition),
                nameof(ExactDpe2ReceiveSuccessCapability),
                nameof(ExactDpe2ReceiveSuccessOutcome),
                nameof(ExactDpe2SendSuccessCapability),
                nameof(AuthoredDpk2Offering),
                nameof(Dpk2AuthoringAuthority),
                nameof(Dpk2AuthoringContext),
                nameof(Dpk2PreKeyPersistenceBlob),
                nameof(Dpk2PreKeyPersistenceProtector),
                nameof(Dpk2PreKeyPersistenceScope),
                nameof(Dpk2PreKeySecretCapability),
                nameof(IExactDpe2DurableTransactionAuthority),
                nameof(InitiatorDph2ClaimPreparation),
                nameof(InitiatorInitialSessionAtomicStorePayload),
                nameof(InitiatorInitialSessionCommitCapability),
                nameof(ManagedInitiatorInitialSessionFactory),
                nameof(ManagedResponderInitialSessionFactory),
                nameof(MessagingE2eeActivationBlocker),
                nameof(MessagingE2eeActivationReport),
                nameof(MessagingE2eeActivationUnavailableException),
                nameof(MessagingE2eeApprovedMlKemPrerequisiteLease),
                nameof(MessagingE2eeProductionReadiness),
                nameof(RestoredDpk2PreKeySecretCapability),
            }.Order(StringComparer.Ordinal),
            exported);
        Assert.False(typeof(IMlKem768Provider).IsPublic);
        Assert.False(typeof(DeepMlKemProductionRuntime).IsPublic);
        Assert.True(typeof(DeepMlKemProductionRuntime).IsSealed);
        Assert.DoesNotContain(
            typeof(DeepMlKemProductionRuntime).GetMethods(BindingFlags.Static | BindingFlags.Instance | BindingFlags.NonPublic),
            static method => method.GetParameters().Any(parameter =>
                parameter.ParameterType == typeof(IMlKem768Provider)));
        Assert.False(typeof(HybridPreKeyHandshake).IsPublic);
        Assert.False(typeof(VerifiedHybridTranscriptCapability).IsPublic);
        Assert.False(typeof(DurableDatabaseCasSuccessCapability).IsPublic);
        Assert.False(typeof(ExactRatchetJournalReceipt).IsPublic);
        Assert.False(typeof(DurableRatchetTransactionSuccessCapability).IsPublic);
        Assert.All(typeof(HybridPreKeyHandshake).GetMethods(BindingFlags.Static | BindingFlags.NonPublic),
            static method => Assert.False(method.IsPublic));
        Assert.DoesNotContain(
            assembly.GetExportedTypes()
                .SelectMany(static type => type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance)),
            static method => method.GetParameters().Any(static parameter =>
                parameter.ParameterType == typeof(IMlKem768Provider) ||
                parameter.ParameterType == typeof(HybridInitiatorKeyMaterial) ||
                parameter.ParameterType == typeof(HybridResponderStaticKeyMaterial) ||
                parameter.ParameterType == typeof(ClaimedHybridPreKeyLease) ||
                parameter.ParameterType == typeof(VerifiedHybridTranscriptCapability)));
        Assert.Empty(typeof(MessagingE2eeActivationReport).GetConstructors());
        Assert.Empty(typeof(MessagingE2eeActivationUnavailableException).GetConstructors());
        Assert.Empty(typeof(MessagingE2eeApprovedMlKemPrerequisiteLease).GetConstructors());
        Assert.Empty(typeof(ExactDpe2DurablePersistencePlan).GetConstructors());
        Assert.Empty(typeof(ExactDpe2DurableCommitCompletion).GetConstructors());
        Assert.Empty(typeof(ExactDpe2DurableCommitReceipt).GetConstructors());
        Assert.Empty(typeof(ExactDpe2PreparedSend).GetConstructors());
        Assert.Empty(typeof(ExactDpe2PreparedReceive).GetConstructors());
        Assert.Empty(typeof(ExactDpe2SendSuccessCapability).GetConstructors());
        Assert.Empty(typeof(ExactDpe2ReceiveSuccessCapability).GetConstructors());
        Assert.Empty(typeof(AuthoredDpk2Offering).GetConstructors());
        Assert.Empty(typeof(Dpk2AuthoringAuthority).GetConstructors());
        Assert.Empty(typeof(Dpk2PreKeySecretCapability).GetConstructors());
        Assert.Empty(typeof(Dpk2PreKeyPersistenceBlob).GetConstructors());
        Assert.Empty(typeof(RestoredDpk2PreKeySecretCapability).GetConstructors());
        Assert.Empty(typeof(InitiatorDph2ClaimPreparation).GetConstructors());
        Assert.Empty(typeof(InitiatorInitialSessionAtomicStorePayload).GetConstructors());
        Assert.Empty(typeof(InitiatorInitialSessionCommitCapability).GetConstructors());
        Assert.DoesNotContain(
            typeof(Dpk2AuthoringAuthority).GetMethods(BindingFlags.Public | BindingFlags.Instance),
            static method => method.GetParameters().Any(parameter =>
                parameter.ParameterType == typeof(byte[]) ||
                parameter.ParameterType == typeof(ReadOnlyMemory<byte>) ||
                parameter.ParameterType.Name.Contains("Provider", StringComparison.OrdinalIgnoreCase) ||
                typeof(Delegate).IsAssignableFrom(parameter.ParameterType)));
        Assert.DoesNotContain(
            typeof(Dpk2PreKeySecretCapability).GetProperties(BindingFlags.Public | BindingFlags.Instance),
            static property => property.Name.Contains("Private", StringComparison.OrdinalIgnoreCase) ||
                property.Name.Contains("Secret", StringComparison.OrdinalIgnoreCase) ||
                property.PropertyType == typeof(byte[]));
        Assert.DoesNotContain(
            typeof(RestoredDpk2PreKeySecretCapability).GetProperties(BindingFlags.Public | BindingFlags.Instance),
            static property => property.Name.Contains("Private", StringComparison.OrdinalIgnoreCase) ||
                property.Name.Contains("Secret", StringComparison.OrdinalIgnoreCase) ||
                property.PropertyType == typeof(byte[]));
        Assert.DoesNotContain(
            new[] { typeof(Dpk2PreKeyPersistenceProtector), typeof(RestoredDpk2PreKeySecretCapability) }
                .SelectMany(static type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance)),
            static method => method.ReturnType == typeof(byte[]) ||
                method.GetParameters().Any(static parameter =>
                    typeof(Delegate).IsAssignableFrom(parameter.ParameterType) ||
                    parameter.ParameterType.Name.Contains("Provider", StringComparison.OrdinalIgnoreCase)));
        Assert.DoesNotContain(
            typeof(ExactDpe2PreparedSend).GetProperties(BindingFlags.Public | BindingFlags.Instance),
            static property => property.PropertyType == typeof(ExactDpe2DurablePersistencePlan));
        Assert.DoesNotContain(
            typeof(ExactDpe2PreparedReceive).GetProperties(BindingFlags.Public | BindingFlags.Instance),
            static property => property.PropertyType == typeof(ExactDpe2DurablePersistencePlan));
        Assert.DoesNotContain(
            typeof(MessagingE2eeApprovedMlKemPrerequisiteLease).GetMethods(BindingFlags.Public | BindingFlags.Instance),
            static method => method.ReturnType == typeof(byte[]) ||
                             method.ReturnType == typeof(ReadOnlyMemory<byte>) ||
                             method.GetParameters().Any(static parameter =>
                                 parameter.ParameterType == typeof(byte[]) ||
                                 parameter.ParameterType == typeof(ReadOnlyMemory<byte>)));
    }

    [Fact]
    public void Dpk2Dph2Dpe2Codecs_RemainAbsentUntilFrozenGrammar()
    {
        var types = typeof(IMlKem768Provider).Assembly.GetTypes()
            .Where(static type => type.Namespace == "Deep.Protocol.MessagingCrypto")
            .ToArray();
        Assert.DoesNotContain(types, static type =>
            type.Name is "Dpk2Codec" or "Dph2Codec" or "Dpe2Codec" ||
            type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance)
                .Any(static method => method.Name is
                    "EncodeDpk2" or "DecodeDpk2" or
                    "EncodeDph2" or "DecodeDph2" or
                    "EncodeDpe2" or "DecodeDpe2"));
    }

    [Fact]
    public void NoSessionFallbackAndOnlyReviewedDarkRuntimeMlKemImplementationExists()
    {
        var types = typeof(IMlKem768Provider).Assembly.GetTypes()
            .Where(static type => type.Namespace == "Deep.Protocol.MessagingCrypto")
            .ToArray();
        Assert.DoesNotContain(types, static type =>
            type.Name.StartsWith("Session", StringComparison.OrdinalIgnoreCase) ||
            type.Namespace?.Contains("SessionCompatibility", StringComparison.OrdinalIgnoreCase) == true);
        var providers = types.Where(static type =>
            type.IsClass && !type.IsAbstract && typeof(IMlKem768Provider).IsAssignableFrom(type)).ToArray();
        Assert.Single(providers);
        Assert.Equal(typeof(DeepMlKemNativeProvider), providers[0]);
        Assert.False(providers[0].IsPublic);
        Assert.Equal("mlkem-native/v2.0.0/portable-c/deep-abi-v1", DeepMlKemNativeProvider.Identifier);
    }
}
