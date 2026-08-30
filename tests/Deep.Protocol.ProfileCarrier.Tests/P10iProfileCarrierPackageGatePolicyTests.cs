using System.Diagnostics;

namespace Deep.Protocol.ProfileCarrier.Tests;

public sealed class P10iProfileCarrierPackageGatePolicyTests
{
    private const string AcceptedSource =
        "a9b7a10a555758d4b2e30707a70d271f010b6c30";
    private const string AlternateAncestor =
        "60ce2e3a5140f245d6bcfecf60fa456c26ffe730";

    [Fact]
    public void GatePinsAcceptedSourceAndValidatesBeforePublishing()
    {
        var script = File.ReadAllText(ScriptPath());

        Assert.Contains(
            $"$carrierSourceCommit = \"{AcceptedSource}\"",
            script,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "[string]$CarrierSourceCommit",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"archive\", \"--format=zip\"",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "$carrierSourceCommit HEAD",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "ProvenancePath is required",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "accepted P10I carrier provenance",
            script,
            StringComparison.Ordinal);

        var packageValidation = script.IndexOf(
            "Assert-CarrierProvenancePackage $carrierProvenance $a.Package",
            StringComparison.Ordinal);
        var identityValidation = script.IndexOf(
            "Invoke-Checked \"dotnet\" (@($identityDll) + $identityArguments)",
            StringComparison.Ordinal);
        var publication = script.IndexOf(
            "$publishedPackage = Join-Path $PublishedRoot",
            StringComparison.Ordinal);
        Assert.True(packageValidation >= 0);
        Assert.True(identityValidation > packageValidation);
        Assert.True(publication > identityValidation);
    }

    [Fact]
    public void PolicySelfTestRejectsTamperedSourceHashVersionAndDependency()
    {
        var result = RunGate(
            "-ProvenancePath",
            ProvenancePath(),
            "-PolicySelfTest");

        Assert.Equal(0, result.ExitCode);
        foreach (var label in new[]
                 {
                     "alternate-ancestor-source-rejection=PASS",
                     "alternate-descendant-source-rejection=PASS",
                     "tampered-carrier-source-rejection=PASS",
                     "tampered-carrier-version-rejection=PASS",
                     "tampered-protocol-dependency-rejection=PASS",
                     "tampered-package-hash-rejection=PASS",
                     "P10I carrier package policy self-test PASS"
                 })
        {
            Assert.Contains(label, result.Output, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void OmittedProvenanceIsRejectedBeforeAnyBuildOrPublish()
    {
        var result = RunGate("-PolicySelfTest");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains(
            "ProvenancePath is required",
            result.Output,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "external-work-root-a=",
            result.Output,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "package=",
            result.Output,
            StringComparison.Ordinal);
    }

    [Fact]
    public void CallerCannotSupplyAlternateAncestorOrDescendantSource()
    {
        var head = Git("rev-parse", "HEAD").Trim();
        Assert.NotEqual(AcceptedSource, head);
        Assert.Equal(
            0,
            GitExitCode("merge-base", "--is-ancestor", AcceptedSource, head));

        foreach (var candidate in new[] { AlternateAncestor, head })
        {
            var result = RunGate(
                "-ProvenancePath",
                ProvenancePath(),
                "-PolicySelfTest",
                "-CarrierSourceCommit",
                candidate);

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains(
                "CarrierSourceCommit",
                result.Output,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                "P10I carrier package policy self-test PASS",
                result.Output,
                StringComparison.Ordinal);
        }
    }

    private static GateResult RunGate(params string[] arguments)
    {
        var start = new ProcessStartInfo("powershell")
        {
            WorkingDirectory = RepositoryRoot(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        start.Environment["PSModulePath"] = WindowsPowerShellModulePath();
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(ScriptPath());
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ??
            throw new InvalidOperationException("PowerShell gate process did not start.");
        var standardOutput = process.StandardOutput.ReadToEnd();
        var standardError = process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(30_000), "PowerShell gate process timed out.");
        return new GateResult(
            process.ExitCode,
            standardOutput + Environment.NewLine + standardError);
    }

    private static string WindowsPowerShellModulePath() => string.Join(
        Path.PathSeparator,
        (Environment.GetEnvironmentVariable("PSModulePath") ?? string.Empty)
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Where(static path => path.Contains("WindowsPowerShell", StringComparison.OrdinalIgnoreCase)));

    private static string Git(params string[] arguments)
    {
        var result = RunGit(arguments);
        Assert.Equal(0, result.ExitCode);
        return result.Output;
    }

    private static int GitExitCode(params string[] arguments) =>
        RunGit(arguments).ExitCode;

    private static GateResult RunGit(IEnumerable<string> arguments)
    {
        var start = new ProcessStartInfo("git")
        {
            WorkingDirectory = RepositoryRoot(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }
        using var process = Process.Start(start) ??
            throw new InvalidOperationException("Git process did not start.");
        var standardOutput = process.StandardOutput.ReadToEnd();
        var standardError = process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(10_000), "Git process timed out.");
        return new GateResult(
            process.ExitCode,
            standardOutput + Environment.NewLine + standardError);
    }

    private static string ScriptPath() => Path.Combine(
        RepositoryRoot(),
        "eng",
        "verify-p10i-profile-carrier-package.ps1");

    private static string ProvenancePath() => Path.Combine(
        RepositoryRoot(),
        "eng",
        "p10i-profile-carrier-package-provenance.json");

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "Deep.Protocol.slnx")))
        {
            directory = directory.Parent;
        }
        return directory?.FullName ??
            throw new InvalidOperationException("Repository root was not found.");
    }

    private sealed record GateResult(int ExitCode, string Output);
}
