using System.Collections.ObjectModel;
using System.Runtime.InteropServices;

namespace Deep.Protocol.MessagingCrypto;

/// <summary>
/// Closed reasons why suite 0x0201 cannot yet be activated as a production
/// messaging engine. These are implementation ownership gates, not negotiable
/// wire fallbacks.
/// </summary>
public enum MessagingE2eeActivationBlocker
{
    ApprovedMlKemAssetUnavailableForRuntime = 1,
    TripleRatchetComponentProviderUnavailable = 2,
    DurableRatchetStateCodecUnavailable = 3,
    ProductionRatchetPersistenceAuthorityUnavailable = 4,
    IssuedDeviceAgreementAuthorityUnavailable = 6,
    DurableHybridPreKeySecretAuthorityUnavailable = 7,
    AtomicInitialSessionPersistenceAuthorityUnavailable = 8,
}

/// <summary>
/// Immutable, non-authoritative readiness information for the production
/// E2EE-01 composition. It contains no key material and cannot authenticate a
/// message or authorize persistence.
/// </summary>
public sealed class MessagingE2eeActivationReport
{
    private readonly ReadOnlyCollection<MessagingE2eeActivationBlocker> _blockers;

    internal MessagingE2eeActivationReport(
        string runtimeIdentifier,
        bool approvedMlKemAssetDeclared,
        IEnumerable<MessagingE2eeActivationBlocker> blockers)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeIdentifier);
        ArgumentNullException.ThrowIfNull(blockers);
        RuntimeIdentifier = runtimeIdentifier;
        ApprovedMlKemAssetDeclared = approvedMlKemAssetDeclared;
        var owned = blockers.Distinct().Order().ToArray();
        if (owned.Length == 0)
            throw new InvalidOperationException(
                "E2EE-01 cannot report production readiness before a complete owned engine exists.");
        _blockers = Array.AsReadOnly(owned);
    }

    public ushort Suite => 0x0201;
    public string RuntimeIdentifier { get; }
    public bool ApprovedMlKemAssetDeclared { get; }
    public bool CanActivate => false;
    public IReadOnlyList<MessagingE2eeActivationBlocker> Blockers => _blockers;
}

/// <summary>
/// Stable fail-closed signal for callers that attempted to activate E2EE-01
/// before every production ownership gate was implemented.
/// </summary>
public sealed class MessagingE2eeActivationUnavailableException : InvalidOperationException
{
    public const string ProductionEngineUnavailable =
        "E2EE01_PRODUCTION_ENGINE_UNAVAILABLE";

    internal MessagingE2eeActivationUnavailableException(MessagingE2eeActivationReport report)
        : base(BuildMessage(report))
    {
        Report = report;
    }

    public string Code => ProductionEngineUnavailable;
    public MessagingE2eeActivationReport Report { get; }

    private static string BuildMessage(MessagingE2eeActivationReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return "Suite 0x0201 is not production-active. Missing owned components: " +
               string.Join(", ", report.Blockers) + ".";
    }
}

/// <summary>
/// Opaque owner for the release-approved ML-KEM prerequisite. It intentionally
/// exposes no KEM operation, key, handshake, ratchet, ciphertext or capability.
/// Possessing this lease does not mean that the full E2EE engine is active.
/// </summary>
public sealed class MessagingE2eeApprovedMlKemPrerequisiteLease : IDisposable
{
    private readonly object _gate = new();
    private DeepMlKemProductionRuntime? _runtime;

    internal MessagingE2eeApprovedMlKemPrerequisiteLease(
        DeepMlKemProductionRuntime runtime,
        MessagingE2eeActivationReport report)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        Report = report ?? throw new ArgumentNullException(nameof(report));
    }

    public string ProviderIdentifier
    {
        get
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                return DeepMlKemNativeProvider.Identifier;
            }
        }
    }

    public MessagingE2eeActivationReport Report { get; }

    public void Dispose()
    {
        DeepMlKemProductionRuntime? runtime;
        lock (_gate)
        {
            runtime = _runtime;
            _runtime = null;
        }
        runtime?.Dispose();
    }

    private void ThrowIfDisposed()
    {
        if (_runtime is null)
            throw new ObjectDisposedException(nameof(MessagingE2eeApprovedMlKemPrerequisiteLease));
    }
}

/// <summary>
/// Production prerequisite boundary for E2EE-01. The only resource it can open
/// is the generated-manifest-approved ML-KEM runtime. Full session activation
/// remains unavailable until all blockers in the report are removed by owned
/// protocol implementations.
/// </summary>
public static class MessagingE2eeProductionReadiness
{
    public static MessagingE2eeActivationReport InspectCurrentProcess()
    {
        var approvedAsset = IsApprovedRuntime(
            OperatingSystem.IsWindows(),
            RuntimeInformation.ProcessArchitecture);
        var blockers = new List<MessagingE2eeActivationBlocker>();
        if (!approvedAsset)
            blockers.Add(MessagingE2eeActivationBlocker.ApprovedMlKemAssetUnavailableForRuntime);
        blockers.Add(MessagingE2eeActivationBlocker.ProductionRatchetPersistenceAuthorityUnavailable);
        blockers.Add(MessagingE2eeActivationBlocker.IssuedDeviceAgreementAuthorityUnavailable);
        blockers.Add(MessagingE2eeActivationBlocker.DurableHybridPreKeySecretAuthorityUnavailable);
        blockers.Add(MessagingE2eeActivationBlocker.AtomicInitialSessionPersistenceAuthorityUnavailable);
        return new MessagingE2eeActivationReport(
            RuntimeInformation.RuntimeIdentifier,
            approvedAsset,
            blockers);
    }

    public static MessagingE2eeApprovedMlKemPrerequisiteLease OpenApprovedMlKemPrerequisite()
    {
        var report = InspectCurrentProcess();
        if (!report.ApprovedMlKemAssetDeclared)
            throw new MessagingE2eeActivationUnavailableException(report);
        var runtime = DeepMlKemProductionRuntime.CreateApprovedForCurrentProcess();
        try
        {
            return new MessagingE2eeApprovedMlKemPrerequisiteLease(runtime, report);
        }
        catch
        {
            runtime.Dispose();
            throw;
        }
    }

    public static void EnsureFullEngineAvailable() =>
        throw new MessagingE2eeActivationUnavailableException(InspectCurrentProcess());

    internal static bool IsApprovedRuntime(bool isWindows, Architecture architecture) =>
        IsWholeKemApprovedRuntime(isWindows, architecture) &&
        HasApprovedIncrementalBraidRuntime(isWindows, architecture);

    private static bool IsWholeKemApprovedRuntime(bool isWindows, Architecture architecture) =>
        isWindows && architecture == Architecture.X64;

    // The whole-KEM handshake library and the incremental Braid library are
    // both required by suite 0x0201. Candidate-only Braid assets must never
    // clear the shared provider blocker merely because the whole-KEM asset is
    // approved for the same RID.
    private static bool HasApprovedIncrementalBraidRuntime(bool isWindows, Architecture architecture)
    {
        _ = isWindows;
        _ = architecture;
        return false;
    }
}
