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
        Assert.False(MessagingE2eeProductionReadiness.IsApprovedRuntime(true, Architecture.X64));
        Assert.False(MessagingE2eeProductionReadiness.IsApprovedRuntime(true, Architecture.Arm64));
        Assert.False(MessagingE2eeProductionReadiness.IsApprovedRuntime(false, Architecture.X64));
        Assert.False(MessagingE2eeProductionReadiness.IsApprovedRuntime(false, Architecture.Arm64));
        Assert.DoesNotContain(
            typeof(MessagingE2eeProductionReadiness).GetMethods(),
            static method => method.IsPublic && method.GetParameters().Any(static parameter =>
                parameter.ParameterType == typeof(Architecture) ||
                parameter.ParameterType == typeof(string)));
    }

    [Fact]
    public void WholeKemAssetAloneCannotOpenProductionPrerequisite()
    {
        var exception = Assert.Throws<MessagingE2eeActivationUnavailableException>(
            MessagingE2eeProductionReadiness.OpenApprovedMlKemPrerequisite);
        Assert.Contains(
            MessagingE2eeActivationBlocker.ApprovedMlKemAssetUnavailableForRuntime,
            exception.Report.Blockers);
    }
}
