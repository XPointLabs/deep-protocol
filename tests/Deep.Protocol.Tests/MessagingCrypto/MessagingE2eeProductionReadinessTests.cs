using System.Collections;
using System.Runtime.InteropServices;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class MessagingE2eeProductionReadinessTests
{
    [Fact]
    public void FullEngineIsExplicitlyBlockedWithoutFallbackOrMutableReport()
    {
        var report = MessagingE2eeProductionReadiness.InspectCurrentProcess();

        Assert.Equal(0x0201, report.Suite);
        Assert.False(report.CanActivate);
        var approvedWindowsRuntime = OperatingSystem.IsWindows() &&
            RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.Arm64;
        if (approvedWindowsRuntime)
            Assert.DoesNotContain(
                MessagingE2eeActivationBlocker.ApprovedMlKemAssetUnavailableForRuntime,
                report.Blockers);
        else
            Assert.Contains(
                MessagingE2eeActivationBlocker.ApprovedMlKemAssetUnavailableForRuntime,
                report.Blockers);
        Assert.DoesNotContain(
            MessagingE2eeActivationBlocker.TripleRatchetComponentProviderUnavailable,
            report.Blockers);
        Assert.DoesNotContain(
            MessagingE2eeActivationBlocker.DurableRatchetStateCodecUnavailable,
            report.Blockers);
        Assert.Contains(
            MessagingE2eeActivationBlocker.ProductionRatchetPersistenceAuthorityUnavailable,
            report.Blockers);
        Assert.DoesNotContain(
            report.Blockers,
            blocker => (int)blocker == 5);
        Assert.Contains(
            MessagingE2eeActivationBlocker.IssuedDeviceAgreementAuthorityUnavailable,
            report.Blockers);
        Assert.Contains(
            MessagingE2eeActivationBlocker.DurableHybridPreKeySecretAuthorityUnavailable,
            report.Blockers);
        Assert.Contains(
            MessagingE2eeActivationBlocker.AtomicInitialSessionPersistenceAuthorityUnavailable,
            report.Blockers);
        Assert.Throws<NotSupportedException>(() =>
            ((IList)report.Blockers).Add(
                MessagingE2eeActivationBlocker.ApprovedMlKemAssetUnavailableForRuntime));

        var exception = Assert.Throws<MessagingE2eeActivationUnavailableException>(
            MessagingE2eeProductionReadiness.EnsureFullEngineAvailable);
        Assert.Equal(
            MessagingE2eeActivationUnavailableException.ProductionEngineUnavailable,
            exception.Code);
        Assert.Same(exception.Report.Blockers, exception.Report.Blockers);
        Assert.DoesNotContain("DPE1", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("fallback", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RuntimeRequiresBothWholeKemAndIncrementalBraidApproval()
    {
        Assert.True(MessagingE2eeProductionReadiness.IsApprovedRuntime(true, Architecture.X64));
        Assert.True(MessagingE2eeProductionReadiness.IsApprovedRuntime(true, Architecture.Arm64));
        Assert.False(MessagingE2eeProductionReadiness.IsApprovedRuntime(false, Architecture.X64));
        Assert.False(MessagingE2eeProductionReadiness.IsApprovedRuntime(false, Architecture.Arm64));
        Assert.DoesNotContain(
            typeof(MessagingE2eeProductionReadiness).GetMethods(),
            static method => method.IsPublic && method.GetParameters().Any(static parameter =>
                parameter.ParameterType == typeof(Architecture) ||
                parameter.ParameterType == typeof(string)));
    }

    [Fact]
    public void ApprovedWindowsRuntimeCanOpenOpaquePrerequisiteOnly()
    {
        if (!OperatingSystem.IsWindows() ||
            RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
            return;

        using var lease = MessagingE2eeProductionReadiness.OpenApprovedMlKemPrerequisite();
        Assert.Equal("mlkem-native/v2.0.0/portable-c/deep-abi-v1", lease.ProviderIdentifier);
        Assert.False(lease.Report.CanActivate);
        Assert.DoesNotContain(
            MessagingE2eeActivationBlocker.ApprovedMlKemAssetUnavailableForRuntime,
            lease.Report.Blockers);
    }
}
